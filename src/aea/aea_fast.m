//
//  aea_fast.m
//  libgrabkernel2
//
//  Two-phase fast kernelcache extraction over AEA-encrypted YAA streams.
//
//  Phase A — BuildManifest discovery.
//    Walk the first couple of chunks linearly, capped at 32 frames each,
//    looking for `AssetData/boot/BuildManifest.plist`. Decode the plist
//    and pin the board-specific kernelcache filename.
//    Failure is fatal; we don't speculatively scan downstream chunks.
//
//  Phase B — Linear scan with lex-stop and body-skip.
//    Walk every chunk large enough to plausibly contain a kernelcache
//    (>= 8 MB) frame-by-frame. The rolling window only fetches frame
//    headers and small bodies; large bodies are skipped without I/O
//    (yaaSkip merely advances the logical cursor). When a frame's path
//    sorts past `AssetData/boot/`, we stop early in that chunk.
//
//    NOTE: an earlier revision tried stride jumps with strong-magic
//    probes; in practice every probe at an 8 MB stride landed inside
//    a >256 KB body and produced a probe-miss, so each "jump" cost a
//    wasted 256 KB request before falling back to linear scan. Linear
//    walk_range is already near-optimal because body skips don't fetch.
//

#import <Foundation/Foundation.h>
#import "aea_fast.h"
#import "aea_internal.h"
#import "utils.h"

#define BOOT_PREFIX           @"AssetData/boot/"
#define BUILD_MANIFEST_PATH   @"AssetData/boot/BuildManifest.plist"

#define WINDOW_CHUNK_SIZE     (2 * 1024 * 1024)   // 2 MB rolling window
#define MIN_KC_CHUNK_BYTES    (8 * 1024 * 1024) // skip chunks too small to host kc
#define PHASE_A_MAX_CHUNKS    4
#define PHASE_A_MAX_FRAMES    32

// =================================================================
// Rolling window over the AEA plaintext stream.
// =================================================================
typedef struct {
    AEAFClusterIndex *idx;
    AEAFRangeOpener *opener;
    int64_t cur;          // next plaintext offset to fetch
    int64_t end;          // exclusive end
    NSMutableData *buf;
    NSUInteger pos;
} YAAWindow;

static int64_t yaaTell(YAAWindow *w) {
    return w->cur - (int64_t)(w->buf.length - w->pos);
}

static BOOL yaaEnsure(YAAWindow *w, NSUInteger n, NSError **outError) {
    while ((NSInteger)w->buf.length - (NSInteger)w->pos < (NSInteger)n) {
        if (w->cur >= w->end) {
            if (outError) *outError = AEAFMakeError(AEAFErrorTruncated, @"YAA window exhausted");
            return NO;
        }
        if (w->pos > 0) {
            NSUInteger keep = w->buf.length - w->pos;
            memmove(w->buf.mutableBytes, (uint8_t *)w->buf.mutableBytes + w->pos, keep);
            [w->buf setLength:keep];
            w->pos = 0;
        }
        int64_t fetch = WINDOW_CHUNK_SIZE;
        if (w->cur + fetch > w->end) fetch = w->end - w->cur;
        NSData *data = [w->idx readPlaintextAtOffset:w->cur length:fetch opener:w->opener error:outError];
        if (!data || data.length == 0) {
            if (!data && outError && !*outError) *outError = AEAFMakeError(AEAFErrorTruncated, @"window: read failed");
            return NO;
        }
        [w->buf appendData:data];
        w->cur += data.length;
    }
    return YES;
}

static const uint8_t *yaaRead(YAAWindow *w, NSUInteger n, NSError **outError) {
    if (!yaaEnsure(w, n, outError)) return NULL;
    const uint8_t *out = (const uint8_t *)w->buf.bytes + w->pos;
    w->pos += n;
    return out;
}

static void yaaSkip(YAAWindow *w, int64_t n) {
    int64_t avail = (int64_t)w->buf.length - (int64_t)w->pos;
    if (n <= avail) { w->pos += (NSUInteger)n; return; }
    n -= avail;
    [w->buf setLength:0];
    w->pos = 0;
    w->cur += n;
    if (w->cur > w->end) w->cur = w->end;
}

// =================================================================
// Frame hit metadata.
// =================================================================
typedef struct {
    int64_t   frameStart;
    int64_t   headerSize;
    int64_t   bodySize;
    char      type;
    NSString *path;
} AEAFFrameHit;

// =================================================================
// Resolve a chunk's inner range and pbzx flag.
// =================================================================
typedef struct {
    int64_t innerStart;
    int64_t innerEnd;
    BOOL    pbzx;
} AEAFInnerRange;

static BOOL aeaf_resolve_inner_range(AEAFClusterIndex *idx,
                                     AEAFRangeOpener *opener,
                                     AEAFManifestEntry *entry,
                                     int64_t manifestFrameSize,
                                     AEAFInnerRange *out,
                                     NSError **outError) {
    int64_t chunkPlain = manifestFrameSize + entry.plainIdx;
    NSData *outerHdr = [idx readPlaintextAtOffset:chunkPlain length:256
                                            opener:opener error:outError];
    if (!outerHdr || outerHdr.length < 6) return NO;
    NSUInteger headerSize = 0, cursor = 0;
    AEAFYAAEntry *outer = AEAFParseYAAFrameHeader(outerHdr, &cursor, &headerSize, outError);
    if (!outer) {
        uint16_t hsz = (uint16_t)((const uint8_t *)outerHdr.bytes)[4]
                     | ((uint16_t)((const uint8_t *)outerHdr.bytes)[5] << 8);
        if (hsz > outerHdr.length) {
            outerHdr = [idx readPlaintextAtOffset:chunkPlain length:hsz
                                            opener:opener error:outError];
            if (!outerHdr) return NO;
            cursor = 0;
            outer = AEAFParseYAAFrameHeader(outerHdr, &cursor, &headerSize, outError);
        }
        if (!outer) return NO;
    }
    out->innerStart = chunkPlain + (int64_t)headerSize;
    out->innerEnd   = out->innerStart + (int64_t)outer.size;

    NSData *peek = [idx readPlaintextAtOffset:out->innerStart length:4
                                        opener:opener error:outError];
    if (!peek || peek.length < 4) return NO;
    out->pbzx = (memcmp(peek.bytes, "pbzx", 4) == 0);
    return YES;
}

// =================================================================
// Linearly scan [start, end) for a frame whose path matches.
// `targetExact` (if non-nil) wins; otherwise substring match against
// `needleSubstr`. `wantBuildManifest` mode looks for BuildManifest
// path equality. Returns YES on hit, NO on clean exhaustion.
//
// `outBMHit` receives BuildManifest body location when matched; the
// caller decides whether to fetch+parse it.
// =================================================================
typedef enum {
    AEAFScanModeBuildManifest = 0,
    AEAFScanModeKernelcache   = 1,
} AEAFScanMode;

static BOOL aeaf_walk_range(AEAFClusterIndex *idx,
                            AEAFRangeOpener *opener,
                            int64_t startOff,
                            int64_t endOff,
                            AEAFScanMode mode,
                            NSString *targetExact,
                            int maxFrames,
                            AEAFFrameHit *outHit,
                            int *outFramesScanned,
                            NSError **outError) {
    YAAWindow win = {0};
    win.idx = idx;
    win.opener = opener;
    win.cur = startOff;
    win.end = endOff;
    win.buf = [NSMutableData dataWithCapacity:WINDOW_CHUNK_SIZE * 2];
    win.pos = 0;

    int frames = 0;
    while (1) {
        int64_t frameStart = yaaTell(&win);
        if (frameStart >= endOff) break;
        if (maxFrames > 0 && frames >= maxFrames) {
            DBGLOG("walk_range: hit maxFrames=%d at offset %lld\n", maxFrames, frameStart);
            break;
        }
        const uint8_t *head = yaaRead(&win, 6, outError);
        if (!head) return NO;
        if (memcmp(head, "AA01", 4) != 0 && memcmp(head, "YAA1", 4) != 0) {
            if (outError) *outError = AEAFMakeError(AEAFErrorBadFormat, @"bad YAA magic at %lld", frameStart);
            return NO;
        }
        uint16_t hdrSize = (uint16_t)head[4] | ((uint16_t)head[5] << 8);
        if (hdrSize <= 6) {
            if (outError) *outError = AEAFMakeError(AEAFErrorBadFormat, @"hdrSize too small at %lld", frameStart);
            return NO;
        }
        const uint8_t *rest = yaaRead(&win, hdrSize - 6, outError);
        if (!rest) return NO;
        NSData *bodyView = [NSData dataWithBytesNoCopy:(void *)rest
                                                length:(NSUInteger)hdrSize - 6
                                          freeWhenDone:NO];
        NSMutableData *synth = [NSMutableData dataWithCapacity:hdrSize];
        const uint8_t magic[6] = {'A','A','0','1', (uint8_t)(hdrSize & 0xff), (uint8_t)(hdrSize >> 8)};
        [synth appendBytes:magic length:6];
        [synth appendData:bodyView];
        NSUInteger c2 = 0, h2 = 0;
        AEAFYAAEntry *ent = AEAFParseYAAFrameHeader(synth, &c2, &h2, outError);
        if (!ent) return NO;
        frames++;

        BOOL match = NO;
        if (mode == AEAFScanModeBuildManifest) {
            match = (ent.type == 'F' && [ent.path isEqualToString:BUILD_MANIFEST_PATH]);
        } else {
            match = (ent.type == 'F' && targetExact && [ent.path isEqualToString:targetExact]);
        }
        if (match) {
            outHit->frameStart = frameStart;
            outHit->headerSize = (int64_t)hdrSize;
            outHit->bodySize   = (int64_t)ent.size;
            outHit->type       = ent.type;
            outHit->path       = ent.path;
            if (outFramesScanned) *outFramesScanned = frames;
            return YES;
        }

        // Lex-stop within this chunk: every chunk's inner stream is
        // path-sorted, so once we cross past AssetData/boot/ on a non-D
        // entry we can stop (boot dir entries themselves are 'D' which
        // sort before files).
        if (mode == AEAFScanModeKernelcache && ent.type == 'F'
            && ent.path && [ent.path compare:BOOT_PREFIX] == NSOrderedDescending
            && ![ent.path hasPrefix:BOOT_PREFIX]) {
            DBGLOG("walk_range: '%s' past boot/, stopping\n", ent.path.UTF8String);
            break;
        }
        if (mode == AEAFScanModeBuildManifest && ent.type == 'F'
            && ent.path && [ent.path compare:BUILD_MANIFEST_PATH] == NSOrderedDescending) {
            DBGLOG("walk_range: BuildManifest mode, '%s' past target, stopping\n", ent.path.UTF8String);
            break;
        }

        yaaSkip(&win, (int64_t)ent.size);
    }
    if (outFramesScanned) *outFramesScanned = frames;
    return NO;
}

// =================================================================
// Decode BuildManifest.plist body and pull the board-specific kernelcache path.
// =================================================================
static NSString *aeaf_extract_kernelcache_name(AEAFClusterIndex *idx,
                                               AEAFRangeOpener *opener,
                                               int64_t bodyStart,
                                               int64_t bodyLen,
                                               NSString *boardconfig) {
    if (bodyLen <= 0 || bodyLen > 16 * 1024 * 1024) return nil;
    NSError *err = nil;
    NSData *data = [idx readPlaintextAtOffset:bodyStart length:bodyLen
                                        opener:opener error:&err];
    if (!data || data.length == 0) return nil;
    NSDictionary *plist = [NSPropertyListSerialization propertyListWithData:data
                                                                    options:0
                                                                     format:NULL
                                                                      error:&err];
    if (![plist isKindOfClass:[NSDictionary class]]) return nil;
    NSArray *identities = plist[@"BuildIdentities"];
    if (![identities isKindOfClass:[NSArray class]]) return nil;
    NSString *wantedDeviceClass = boardconfig.length ? boardconfig.lowercaseString : nil;
    NSString *kernelCachePath = nil;
    for (NSDictionary *identity in identities) {
        if (![identity isKindOfClass:[NSDictionary class]]) continue;
        NSDictionary *info = identity[@"Info"];
        if (![info isKindOfClass:[NSDictionary class]]) continue;
        NSString *variant = info[@"Variant"];
        if ([variant isKindOfClass:[NSString class]] && [variant hasPrefix:@"Research"]) {
            continue;
        }
        NSString *deviceClass = info[@"DeviceClass"];
        if (wantedDeviceClass.length) {
            if (![deviceClass isKindOfClass:[NSString class]] ||
                ![deviceClass isEqualToString:wantedDeviceClass]) {
                continue;
            }
        }
        NSString *kp = identity[@"Manifest"][@"KernelCache"][@"Info"][@"Path"];
        if ([kp isKindOfClass:[NSString class]] && [kp containsString:@"kernelcache.release."]) {
            kernelCachePath = kp;
        }
    }
    return kernelCachePath;
}

// =================================================================
BOOL aea_fast_extract_kernelcache(NSString *aeaURL,
                                  NSString *decryptionKeyB64,
                                  NSString *outPath,
                                  NSString *boardconfig,
                                  NSInteger chunkIndex,
                                  NSString *kernelPathSubstring,
                                  AEAFFastStats *outStats) {
    (void)kernelPathSubstring; // honored only as a fallback; not used now.
    if (!aeaURL.length || !decryptionKeyB64.length || !outPath.length) {
        ERRLOG("aea_fast: missing required argument\n");
        return NO;
    }

    AEAFRangeOpener *opener = [[AEAFRangeOpener alloc] initWithURL:aeaURL];
    NSError *err = nil;
    AEAFClusterIndex *idx = [AEAFClusterIndex indexWithOpener:opener
                                                    symKeyB64:decryptionKeyB64
                                                        error:&err];
    if (!idx) {
        ERRLOG("aea_fast: prepare prefix failed: %s\n", err.localizedDescription.UTF8String);
        return NO;
    }
    NSData *mfData = [idx readPlaintextAtOffset:0 length:16 * 1024
                                          opener:opener error:&err];
    if (!mfData) {
        ERRLOG("aea_fast: read manifest slice: %s\n", err.localizedDescription.UTF8String);
        return NO;
    }
    int64_t manifestFrameSize = 0;
    NSArray<AEAFManifestEntry *> *manifest = AEAFReadYOPManifest(mfData, &manifestFrameSize, &err);
    if (!manifest) {
        ERRLOG("aea_fast: parse YOP_MANIFEST: %s\n", err.localizedDescription.UTF8String);
        return NO;
    }
    LOG("aea_fast: %lu manifest entries\n", (unsigned long)manifest.count);

    // ---- Phase A: BuildManifest discovery ----
    NSString *targetPath = nil;
    NSInteger phaseAChunks = MIN((NSInteger)manifest.count, (NSInteger)PHASE_A_MAX_CHUNKS);
    for (NSInteger ci = 0; ci < phaseAChunks; ci++) {
        AEAFInnerRange r = {0};
        if (!aeaf_resolve_inner_range(idx, opener, manifest[ci], manifestFrameSize, &r, &err)) {
            LOG("aea_fast: phase A chunk %ld outer header unreadable\n", (long)ci);
            continue;
        }
        if (r.pbzx) {
            LOG("aea_fast: phase A chunk %ld pbzx-wrapped, skipping\n", (long)ci);
            continue;
        }
        LOG("aea_fast: phase A scanning chunk %ld inner=[%lld..%lld) %lld B\n",
            (long)ci, r.innerStart, r.innerEnd, r.innerEnd - r.innerStart);
        AEAFFrameHit bm = {0};
        int frames = 0;
        NSError *werr = nil;
        BOOL hit = aeaf_walk_range(idx, opener, r.innerStart, r.innerEnd,
                                   AEAFScanModeBuildManifest, nil,
                                   PHASE_A_MAX_FRAMES, &bm, &frames, &werr);
        if (!hit) {
            LOG("aea_fast: phase A chunk %ld no BuildManifest in first %d frames\n",
                (long)ci, frames);
            continue;
        }
        LOG("aea_fast: phase A chunk %ld BuildManifest.plist @%lld (size=%lld)\n",
            (long)ci, bm.frameStart, bm.bodySize);
        NSString *kcName = aeaf_extract_kernelcache_name(idx, opener,
                                                          bm.frameStart + bm.headerSize,
                                                          bm.bodySize,
                                                          boardconfig);
        if (kcName.length) {
            targetPath = [BOOT_PREFIX stringByAppendingString:kcName];
            LOG("aea_fast: pinned target -> %s\n", targetPath.UTF8String);
            break;
        }
        ERRLOG("aea_fast: BuildManifest yielded no kernelcache path for board=%s\n",
               boardconfig.length ? boardconfig.UTF8String : "(any)");
        return NO;
    }
    if (!targetPath) {
        ERRLOG("aea_fast: BuildManifest discovery failed in first %ld chunk(s)\n",
               (long)phaseAChunks);
        return NO;
    }

    // ---- Phase B: jump search for the pinned kernelcache path ----
    NSMutableArray<NSNumber *> *order = [NSMutableArray array];
    if (chunkIndex > 0) {
        [order addObject:@(chunkIndex)];
    } else {
        for (NSInteger ci = 0; ci < (NSInteger)manifest.count; ci++) {
            if (manifest[ci].size < MIN_KC_CHUNK_BYTES) continue;
            [order addObject:@(ci)];
        }
    }

    int64_t kcStart = -1, kcSize = 0;
    NSString *kcPath = nil;
    NSInteger usedChunk = -1;
    for (NSNumber *n in order) {
        NSInteger ci = n.integerValue;
        AEAFInnerRange r = {0};
        if (!aeaf_resolve_inner_range(idx, opener, manifest[ci], manifestFrameSize, &r, &err)) {
            LOG("aea_fast: phase B chunk %ld unreadable, skipping\n", (long)ci);
            continue;
        }
        if (r.pbzx) {
            LOG("aea_fast: phase B chunk %ld pbzx-wrapped, skipping\n", (long)ci);
            continue;
        }
        LOG("aea_fast: phase B chunk %ld inner=[%lld..%lld) %lld B\n",
            (long)ci, r.innerStart, r.innerEnd, r.innerEnd - r.innerStart);
        AEAFFrameHit hit = {0};
        int frames = 0;
        NSError *werr = nil;
        if (aeaf_walk_range(idx, opener, r.innerStart, r.innerEnd,
                            AEAFScanModeKernelcache, targetPath, 0,
                            &hit, &frames, &werr)) {
            kcStart   = hit.frameStart;
            kcSize    = hit.headerSize + hit.bodySize;
            kcPath    = hit.path;
            usedChunk = ci;
            break;
        }
        LOG("aea_fast: phase B chunk %ld scanned %d frames, no match\n", (long)ci, frames);
    }
    if (usedChunk < 0) {
        ERRLOG("aea_fast: kernelcache '%s' not found in any chunk\n", targetPath.UTF8String);
        return NO;
    }
    LOG("aea_fast: located %s in chunk %ld @%lld (size=%lld)\n",
        kcPath.UTF8String, (long)usedChunk, kcStart, kcSize);

    NSInteger probeCalls = opener.requestCount;
    int64_t   probeBytes = opener.bytesTransferred;

    NSData *kcFrame = [idx readPlaintextAtOffset:kcStart length:kcSize
                                          opener:opener error:&err];
    if (!kcFrame || kcFrame.length < 6) {
        ERRLOG("aea_fast: fetch kc frame: %s\n", err.localizedDescription.UTF8String);
        return NO;
    }
    const uint8_t *kfp = kcFrame.bytes;
    uint16_t kHdrSize = (uint16_t)kfp[4] | ((uint16_t)kfp[5] << 8);
    if (kHdrSize > kcFrame.length) {
        ERRLOG("aea_fast: kc frame header span %u > %lu\n", kHdrSize, (unsigned long)kcFrame.length);
        return NO;
    }
    NSData *im4p = [kcFrame subdataWithRange:NSMakeRange(kHdrSize, kcFrame.length - kHdrSize)];
    NSData *payload = AEAFExtractIM4PPayload(im4p, &err);
    if (!payload) {
        ERRLOG("aea_fast: parse IM4P: %s\n", err.localizedDescription.UTF8String);
        return NO;
    }
    NSData *kcDec = AEAFDecompressKernelcache(payload, &err);
    if (!kcDec) {
        ERRLOG("aea_fast: decompress kernelcache: %s\n", err.localizedDescription.UTF8String);
        return NO;
    }
    NSError *werr = nil;
    if (![kcDec writeToFile:outPath options:NSDataWritingAtomic error:&werr]) {
        ERRLOG("aea_fast: write %s: %s\n", outPath.UTF8String, werr.localizedDescription.UTF8String);
        return NO;
    }

    int64_t   fetchBytes = opener.bytesTransferred - probeBytes;
    NSInteger fetchCalls = opener.requestCount - probeCalls;
    LOG("Fast AEA kernelcache: %s written (%lu bytes; %lld B / %ld reqs total; probe=%lld fetch=%lld)\n",
        outPath.UTF8String, (unsigned long)kcDec.length,
        opener.bytesTransferred, (long)opener.requestCount,
        probeBytes, fetchBytes);
    (void)fetchCalls;

    if (outStats) {
        outStats->requestCount     = opener.requestCount;
        outStats->bytesTransferred = opener.bytesTransferred;
        outStats->chunkIndexUsed   = usedChunk;
    }
    return YES;
}
