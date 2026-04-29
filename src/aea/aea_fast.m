//
//  aea_fast.m
//  libgrabkernel2
//
//  Top-level: AEA prefix + YOP_MANIFEST + outer YAA + rolling-window inner
//  YAA scan + targeted slice fetch + IM4P/LZFSE decompression -> output.
//

#import <Foundation/Foundation.h>
#import "aea_fast.h"
#import "aea_internal.h"
#import "utils.h"

#define DEFAULT_KERNEL_CHUNK 4
#define DEFAULT_KERNEL_PATH @"kernelcache.release."
#define WINDOW_CHUNK_SIZE   (256 * 1024)

// yaaWindowReader: buffers AEA plaintext fetched in WINDOW_CHUNK_SIZE
// chunks so the caller can read+skip across YAA frame boundaries while only
// paying for the segment bands that overlap the window. Skipping a large
// body advances the cursor without fetching cipher.
typedef struct {
    AEAFClusterIndex *idx;
    AEAFRangeOpener *opener;
    int64_t cur;          // next plaintext offset to fetch
    int64_t end;          // exclusive end
    NSMutableData *buf;
    NSUInteger pos;
    int64_t opens;
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
            // Compact buffer.
            NSUInteger keep = w->buf.length - w->pos;
            memmove(w->buf.mutableBytes, (uint8_t *)w->buf.mutableBytes + w->pos, keep);
            [w->buf setLength:keep];
            w->pos = 0;
        }
        int64_t fetch = WINDOW_CHUNK_SIZE;
        if (w->cur + fetch > w->end) {
            fetch = w->end - w->cur;
        }
        NSData *data = [w->idx readPlaintextAtOffset:w->cur length:fetch opener:w->opener error:outError];
        if (!data) return NO;
        if (data.length == 0) {
            if (outError) *outError = AEAFMakeError(AEAFErrorTruncated, @"YAA window: zero-length read");
            return NO;
        }
        w->opens++;
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
    if (n <= avail) {
        w->pos += (NSUInteger)n;
        return;
    }
    n -= avail;
    [w->buf setLength:0];
    w->pos = 0;
    w->cur += n;
    if (w->cur > w->end) w->cur = w->end;
}

BOOL aea_fast_extract_kernelcache(NSString *aeaURL,
                                  NSString *decryptionKeyB64,
                                  NSString *outPath,
                                  NSInteger chunkIndex,
                                  NSString *kernelPathSubstring) {
    if (!aeaURL.length || !decryptionKeyB64.length || !outPath.length) {
        ERRLOG("aea_fast: missing required argument\n");
        return NO;
    }
    if (chunkIndex <= 0) chunkIndex = DEFAULT_KERNEL_CHUNK;
    NSString *needle = kernelPathSubstring.length > 0 ? kernelPathSubstring : DEFAULT_KERNEL_PATH;

    LOG("Fast AEA kernelcache: %s (chunk %ld)\n", aeaURL.UTF8String, (long)chunkIndex);

    AEAFRangeOpener *opener = [[AEAFRangeOpener alloc] initWithURL:aeaURL];
    NSError *err = nil;
    AEAFClusterIndex *idx = [AEAFClusterIndex indexWithOpener:opener
                                                    symKeyB64:decryptionKeyB64
                                                        error:&err];
    if (!idx) {
        ERRLOG("aea_fast: prepare prefix failed: %s\n", err.localizedDescription.UTF8String);
        return NO;
    }
    NSInteger prefixCalls = opener.requestCount;
    int64_t prefixBytes = opener.bytesTransferred;

    // Manifest sits at plaintext offset 0.
    NSData *mfData = [idx readPlaintextAtOffset:0 length:16 * 1024 opener:opener error:&err];
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
    if (chunkIndex >= (NSInteger)manifest.count) {
        ERRLOG("aea_fast: chunk %ld out of range (manifest has %lu)\n",
               (long)chunkIndex, (unsigned long)manifest.count);
        return NO;
    }
    NSInteger manifestCalls = opener.requestCount - prefixCalls;
    int64_t manifestBytes = opener.bytesTransferred - prefixBytes;
    (void)manifestCalls; (void)manifestBytes;
    DBGLOG("Stage 2 manifest: requests=%ld bytes=%lld entries=%lu\n",
           (long)manifestCalls, manifestBytes, (unsigned long)manifest.count);

    AEAFManifestEntry *targetChunk = manifest[chunkIndex];
    int64_t chunkPlain = manifestFrameSize + targetChunk.plainIdx;
    int64_t chunkPlainSize = targetChunk.size + 34; // include outer YAA frame header
    (void)chunkPlainSize;
    DBGLOG("Target chunk %ld: plain_start=%lld plain_size=%lld label=%s\n",
           (long)chunkIndex, chunkPlain, chunkPlainSize, targetChunk.label.UTF8String);

    // Read outer YAA header.
    NSData *outerHdr = [idx readPlaintextAtOffset:chunkPlain length:256 opener:opener error:&err];
    if (!outerHdr || outerHdr.length < 6) {
        ERRLOG("aea_fast: read outer header: %s\n", err.localizedDescription.UTF8String);
        return NO;
    }
    NSUInteger headerSize = 0, cursor = 0;
    AEAFYAAEntry *outer = AEAFParseYAAFrameHeader(outerHdr, &cursor, &headerSize, &err);
    if (!outer) {
        // Maybe outer header > 256 bytes; refetch.
        if (outerHdr.length >= 6) {
            uint16_t hsz = (uint16_t)((const uint8_t *)outerHdr.bytes)[4]
                         | ((uint16_t)((const uint8_t *)outerHdr.bytes)[5] << 8);
            if (hsz > outerHdr.length) {
                outerHdr = [idx readPlaintextAtOffset:chunkPlain length:hsz opener:opener error:&err];
                if (!outerHdr) {
                    ERRLOG("aea_fast: re-read outer header: %s\n", err.localizedDescription.UTF8String);
                    return NO;
                }
                cursor = 0;
                outer = AEAFParseYAAFrameHeader(outerHdr, &cursor, &headerSize, &err);
            }
        }
        if (!outer) {
            ERRLOG("aea_fast: decode outer entry: %s\n", err.localizedDescription.UTF8String);
            return NO;
        }
    }
    int64_t innerStart = chunkPlain + (int64_t)headerSize;
    int64_t innerEnd = innerStart + (int64_t)outer.size;
    DBGLOG("Stage 3 outer: hdr_size=%zu body_size=%llu inner_start=%lld inner_end=%lld\n",
           (size_t)headerSize, (unsigned long long)outer.size, innerStart, innerEnd);

    // Detect pbzx wrapper.
    NSData *peek = [idx readPlaintextAtOffset:innerStart length:4 opener:opener error:&err];
    if (!peek || peek.length < 4) {
        ERRLOG("aea_fast: peek inner: %s\n", err.localizedDescription.UTF8String);
        return NO;
    }
    if (memcmp(peek.bytes, "pbzx", 4) == 0) {
        ERRLOG("aea_fast: chunk %ld body is pbzx-wrapped (not supported)\n", (long)chunkIndex);
        return NO;
    }

    // Walk inner YAA frames in a rolling window.
    YAAWindow win = {0};
    win.idx = idx;
    win.opener = opener;
    win.cur = innerStart;
    win.end = innerEnd;
    win.buf = [NSMutableData dataWithCapacity:WINDOW_CHUNK_SIZE * 2];
    win.pos = 0;

    int64_t kcStart = -1;
    int64_t kcSize = 0;
    NSString *kcPath = nil;
    int framesSeen = 0;
    NSInteger probeStartC = opener.requestCount;
    int64_t probeStartB = opener.bytesTransferred;

    while (1) {
        int64_t frameStart = yaaTell(&win);
        if (frameStart >= innerEnd) break;
        const uint8_t *head = yaaRead(&win, 6, &err);
        if (!head) {
            ERRLOG("aea_fast: read inner frame head at %lld: %s\n", frameStart, err.localizedDescription.UTF8String);
            return NO;
        }
        if (memcmp(head, "AA01", 4) != 0 && memcmp(head, "YAA1", 4) != 0) {
            ERRLOG("aea_fast: bad inner YAA magic at %lld\n", frameStart);
            return NO;
        }
        uint16_t hdrSize = (uint16_t)head[4] | ((uint16_t)head[5] << 8);
        if (hdrSize <= 6) {
            ERRLOG("aea_fast: bad inner hdr size %u at %lld\n", hdrSize, frameStart);
            return NO;
        }
        const uint8_t *rest = yaaRead(&win, hdrSize - 6, &err);
        if (!rest) {
            ERRLOG("aea_fast: read inner frame body at %lld: %s\n", frameStart, err.localizedDescription.UTF8String);
            return NO;
        }
        AEAFYAAEntry *ent = [[AEAFYAAEntry alloc] init];
        NSData *bodyView = [NSData dataWithBytesNoCopy:(void *)rest length:(NSUInteger)hdrSize - 6 freeWhenDone:NO];
        // decodeYAAEntryBody is private to aea_yop.m; reuse via parsing one
        // synthetic frame from a small NSData blob.
        NSMutableData *synth = [NSMutableData dataWithCapacity:hdrSize];
        const uint8_t magic[6] = {'A','A','0','1', (uint8_t)(hdrSize & 0xff), (uint8_t)(hdrSize >> 8)};
        [synth appendBytes:magic length:6];
        [synth appendData:bodyView];
        NSUInteger c2 = 0, h2 = 0;
        ent = AEAFParseYAAFrameHeader(synth, &c2, &h2, &err);
        if (!ent) {
            ERRLOG("aea_fast: decode inner entry at %lld: %s\n", frameStart, err.localizedDescription.UTF8String);
            return NO;
        }
        framesSeen++;
        DBGLOG("YAA frame #%d offset=%lld path=%s size=%llu type=%c\n",
               framesSeen, frameStart, ent.path.UTF8String ?: "(nil)",
               (unsigned long long)ent.size, ent.type);

        if (ent.type == 'F' && ent.path && [ent.path containsString:needle]) {
            kcStart = frameStart;
            kcSize = (int64_t)hdrSize + (int64_t)ent.size;
            kcPath = ent.path;
            break;
        }
        yaaSkip(&win, (int64_t)ent.size);
    }
    if (kcStart < 0) {
        ERRLOG("aea_fast: kernelcache not found in chunk %ld (scanned %d frames)\n",
               (long)chunkIndex, framesSeen);
        return NO;
    }
    NSInteger probeCalls = opener.requestCount - probeStartC;
    int64_t probeBytes = opener.bytesTransferred - probeStartB;
    (void)probeCalls;
    DBGLOG("Stage 4 probe: frames=%d windows=%lld requests=%ld bytes=%lld\n",
           framesSeen, win.opens, (long)probeCalls, probeBytes);
    LOG("Located kernelcache: %s (size=%lld at +%lld)\n",
        kcPath.UTF8String, kcSize, kcStart);

    // Fetch the kernelcache YAA frame.
    NSData *kcFrame = [idx readPlaintextAtOffset:kcStart length:kcSize opener:opener error:&err];
    if (!kcFrame) {
        ERRLOG("aea_fast: fetch kc frame: %s\n", err.localizedDescription.UTF8String);
        return NO;
    }
    if (kcFrame.length < 6) {
        ERRLOG("aea_fast: kc frame too short\n");
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

    LOG("Fast AEA kernelcache: %s written (%lu bytes; transferred=%lld over %ld requests; probe=%lld fetch=%lld)\n",
        outPath.UTF8String, (unsigned long)kcDec.length,
        opener.bytesTransferred, (long)opener.requestCount,
        probeBytes, opener.bytesTransferred - probeStartB - probeBytes);
    return YES;
}
