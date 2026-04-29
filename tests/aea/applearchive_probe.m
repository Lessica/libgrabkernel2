//
//  applearchive_probe.m
//  libgrabkernel2
//
//  Validation harness for Apple's public AppleArchive framework.
//
//  This intentionally does not exercise libgrabkernel2's AEA fast path. It
//  wraps a remote .aea URL in an AACustomByteStream, lets AppleArchive perform
//  random-access AEA decryption, then uses Apple's archive decoder inside each
//  YOP chunk to locate:
//
//    1. AssetData/boot/BuildManifest.plist
//    2. the kernelcache.release.* path named by that plist
//
//  The reported HTTP request and byte counters quantify whether the official
//  framework is a viable replacement for the hand-rolled fast path.
//

#import <AppleArchive/AppleArchive.h>
#import <Foundation/Foundation.h>
#import "src/aea/aea_internal.h"

#define PROBE_MANIFEST_PREFIX_BYTES (16 * 1024)
#define PROBE_MAX_ATTEMPTS 3
#define PROBE_MAX_PHASE_A_CHUNKS 4
#define PROBE_MIN_KC_CHUNK_BYTES (8 * 1024 * 1024)
#define PROBE_BOOT_PREFIX @"AssetData/boot/"
#define PROBE_BUILD_MANIFEST @"AssetData/boot/BuildManifest.plist"

extern NSArray<AEAFManifestEntry *> *AEAFReadYOPManifest(NSData *data,
                                                         int64_t *outFrameSize,
                                                         NSError **outError);

static AAFieldKey probeKey(const char *s) {
    AAFieldKey k = {0};
    k.skey[0] = s[0];
    k.skey[1] = s[1];
    k.skey[2] = s[2];
    return k;
}

// ============================================================
// HTTP Range-backed AppleArchive byte stream
// ============================================================

@interface AEAHTTPRangeByteSource : NSObject
@property(nonatomic, readonly) NSInteger requestCount;
@property(nonatomic, readonly) int64_t bytesTransferred;
- (instancetype)initWithURL:(NSString *)url;
- (BOOL)prepareContentLength;
- (ssize_t)readInto:(void *)buf length:(size_t)nbyte;
- (ssize_t)preadInto:(void *)buf length:(size_t)nbyte offset:(off_t)offset;
- (off_t)seekTo:(off_t)offset whence:(int)whence;
- (void)cancel;
@end

@implementation AEAHTTPRangeByteSource {
    NSString *_url;
    NSURLSession *_session;
    off_t _cursor;
    off_t _contentLength;
    BOOL _cancelled;
}

- (instancetype)initWithURL:(NSString *)url {
    if ((self = [super init])) {
        _url = [url copy];
        _contentLength = -1;
        NSURLSessionConfiguration *cfg = [NSURLSessionConfiguration defaultSessionConfiguration];
        cfg.timeoutIntervalForRequest = 30;
        cfg.timeoutIntervalForResource = 300;
        cfg.HTTPMaximumConnectionsPerHost = 4;
        _session = [NSURLSession sessionWithConfiguration:cfg];
    }
    return self;
}

- (void)dealloc {
    [_session finishTasksAndInvalidate];
}

- (BOOL)prepareContentLength {
    NSURL *u = [NSURL URLWithString:_url];
    if (!u) return NO;

    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:u];
    req.HTTPMethod = @"HEAD";

    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    __block NSURLResponse *resp = nil;
    __block NSError *err = nil;
    NSURLSessionDataTask *task = [_session dataTaskWithRequest:req
                                             completionHandler:^(NSData *_Nullable d, NSURLResponse *_Nullable r, NSError *_Nullable e) {
        (void)d;
        resp = r;
        err = e;
        dispatch_semaphore_signal(sem);
    }];
    [task resume];
    dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);

    if (err) return NO;
    NSHTTPURLResponse *http = (NSHTTPURLResponse *)resp;
    if (![http isKindOfClass:[NSHTTPURLResponse class]] || http.statusCode < 200 || http.statusCode >= 300) {
        return NO;
    }

    @synchronized (self) {
        _contentLength = (off_t)http.expectedContentLength;
    }
    return _contentLength > 0;
}

- (NSData *)fetchRangeAtOffset:(off_t)offset length:(size_t)nbyte {
    if (offset < 0 || nbyte == 0) return [NSData data];

    NSURL *u = [NSURL URLWithString:_url];
    if (!u) return nil;

    NSError *lastErr = nil;
    for (int attempt = 1; attempt <= PROBE_MAX_ATTEMPTS; attempt++) {
        NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:u];
        req.HTTPMethod = @"GET";
        [req setValue:[NSString stringWithFormat:@"bytes=%lld-%lld",
                       (long long)offset,
                       (long long)offset + (long long)nbyte - 1]
   forHTTPHeaderField:@"Range"];

        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        __block NSData *body = nil;
        __block NSURLResponse *resp = nil;
        __block NSError *err = nil;
        NSURLSessionDataTask *task = [_session dataTaskWithRequest:req
                                                 completionHandler:^(NSData *_Nullable d, NSURLResponse *_Nullable r, NSError *_Nullable e) {
            body = d;
            resp = r;
            err = e;
            dispatch_semaphore_signal(sem);
        }];
        [task resume];
        dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);

        if (err) {
            lastErr = err;
            continue;
        }

        NSHTTPURLResponse *http = (NSHTTPURLResponse *)resp;
        if (![http isKindOfClass:[NSHTTPURLResponse class]]) continue;
        if (http.statusCode != 206 && http.statusCode != 200) continue;

        @synchronized (self) {
            _requestCount++;
            _bytesTransferred += (int64_t)body.length;
        }
        return body;
    }

    if (lastErr) {
        fprintf(stderr, "HTTP Range failed: %s\n", lastErr.localizedDescription.UTF8String);
    }
    return nil;
}

- (ssize_t)readInto:(void *)buf length:(size_t)nbyte {
    off_t off = 0;
    @synchronized (self) {
        if (_cancelled) return -1;
        off = _cursor;
    }

    ssize_t got = [self preadInto:buf length:nbyte offset:off];
    if (got > 0) {
        @synchronized (self) {
            _cursor += got;
        }
    }
    return got;
}

- (ssize_t)preadInto:(void *)buf length:(size_t)nbyte offset:(off_t)offset {
    @synchronized (self) {
        if (_cancelled) return -1;
        if (_contentLength >= 0 && offset >= _contentLength) return 0;
    }

    NSData *data = [self fetchRangeAtOffset:offset length:nbyte];
    if (!data || data.length > nbyte) return -1;
    memcpy(buf, data.bytes, data.length);
    return (ssize_t)data.length;
}

- (off_t)seekTo:(off_t)offset whence:(int)whence {
    @synchronized (self) {
        if (_cancelled) return -1;
        off_t base = 0;
        if (whence == SEEK_SET) {
            base = 0;
        } else if (whence == SEEK_CUR) {
            base = _cursor;
        } else if (whence == SEEK_END) {
            if (_contentLength < 0) return -1;
            base = _contentLength;
        } else {
            return -1;
        }

        off_t next = base + offset;
        if (next < 0) return -1;
        _cursor = next;
        return _cursor;
    }
}

- (void)cancel {
    @synchronized (self) {
        _cancelled = YES;
    }
}

@end

static ssize_t remoteRead(void *arg, void *buf, size_t nbyte) {
    return [(__bridge AEAHTTPRangeByteSource *)arg readInto:buf length:nbyte];
}

static ssize_t remotePRead(void *arg, void *buf, size_t nbyte, off_t offset) {
    return [(__bridge AEAHTTPRangeByteSource *)arg preadInto:buf length:nbyte offset:offset];
}

static off_t remoteSeek(void *arg, off_t offset, int whence) {
    return [(__bridge AEAHTTPRangeByteSource *)arg seekTo:offset whence:whence];
}

static void remoteCancel(void *arg) {
    [(__bridge AEAHTTPRangeByteSource *)arg cancel];
}

static int remoteClose(void *arg) {
    if (arg) CFBridgingRelease(arg);
    return 0;
}

static AAByteStream openRemoteEncryptedStream(AEAHTTPRangeByteSource *source) {
    AAByteStream stream = AACustomByteStreamOpen();
    if (!stream) return NULL;
    AACustomByteStreamSetData(stream, (void *)CFBridgingRetain(source));
    AACustomByteStreamSetReadProc(stream, remoteRead);
    AACustomByteStreamSetPReadProc(stream, remotePRead);
    AACustomByteStreamSetSeekProc(stream, remoteSeek);
    AACustomByteStreamSetCancelProc(stream, remoteCancel);
    AACustomByteStreamSetCloseProc(stream, remoteClose);
    return stream;
}

// ============================================================
// Plaintext slice stream for decoding one YOP chunk
// ============================================================

@interface AEAPlainSliceByteSource : NSObject
- (instancetype)initWithPlainStream:(AAByteStream)plain
                              start:(off_t)start
                             length:(off_t)length;
- (ssize_t)readInto:(void *)buf length:(size_t)nbyte;
- (ssize_t)preadInto:(void *)buf length:(size_t)nbyte offset:(off_t)offset;
- (off_t)seekTo:(off_t)offset whence:(int)whence;
- (void)cancel;
@end

@implementation AEAPlainSliceByteSource {
    AAByteStream _plain;
    off_t _start;
    off_t _length;
    off_t _cursor;
    BOOL _cancelled;
}

- (instancetype)initWithPlainStream:(AAByteStream)plain
                              start:(off_t)start
                             length:(off_t)length {
    if ((self = [super init])) {
        _plain = plain;
        _start = start;
        _length = length;
    }
    return self;
}

- (ssize_t)readInto:(void *)buf length:(size_t)nbyte {
    off_t off = 0;
    @synchronized (self) {
        if (_cancelled) return -1;
        off = _cursor;
    }
    ssize_t got = [self preadInto:buf length:nbyte offset:off];
    if (got > 0) {
        @synchronized (self) {
            _cursor += got;
        }
    }
    return got;
}

- (ssize_t)preadInto:(void *)buf length:(size_t)nbyte offset:(off_t)offset {
    @synchronized (self) {
        if (_cancelled) return -1;
    }
    if (offset < 0 || offset >= _length) return 0;
    off_t avail = _length - offset;
    if ((off_t)nbyte > avail) nbyte = (size_t)avail;
    return AAByteStreamPRead(_plain, buf, nbyte, _start + offset);
}

- (off_t)seekTo:(off_t)offset whence:(int)whence {
    @synchronized (self) {
        if (_cancelled) return -1;
        off_t base = 0;
        if (whence == SEEK_SET) {
            base = 0;
        } else if (whence == SEEK_CUR) {
            base = _cursor;
        } else if (whence == SEEK_END) {
            base = _length;
        } else {
            return -1;
        }
        off_t next = base + offset;
        if (next < 0) return -1;
        _cursor = next;
        return _cursor;
    }
}

- (void)cancel {
    @synchronized (self) {
        _cancelled = YES;
    }
}

@end

static ssize_t sliceRead(void *arg, void *buf, size_t nbyte) {
    return [(__bridge AEAPlainSliceByteSource *)arg readInto:buf length:nbyte];
}

static ssize_t slicePRead(void *arg, void *buf, size_t nbyte, off_t offset) {
    return [(__bridge AEAPlainSliceByteSource *)arg preadInto:buf length:nbyte offset:offset];
}

static off_t sliceSeek(void *arg, off_t offset, int whence) {
    return [(__bridge AEAPlainSliceByteSource *)arg seekTo:offset whence:whence];
}

static void sliceCancel(void *arg) {
    [(__bridge AEAPlainSliceByteSource *)arg cancel];
}

static int sliceClose(void *arg) {
    if (arg) CFBridgingRelease(arg);
    return 0;
}

static AAByteStream openPlainSliceStream(AAByteStream plain, off_t start, off_t length) {
    AEAPlainSliceByteSource *slice = [[AEAPlainSliceByteSource alloc] initWithPlainStream:plain
                                                                                    start:start
                                                                                   length:length];
    AAByteStream stream = AACustomByteStreamOpen();
    if (!stream) return NULL;
    AACustomByteStreamSetData(stream, (void *)CFBridgingRetain(slice));
    AACustomByteStreamSetReadProc(stream, sliceRead);
    AACustomByteStreamSetPReadProc(stream, slicePRead);
    AACustomByteStreamSetSeekProc(stream, sliceSeek);
    AACustomByteStreamSetCancelProc(stream, sliceCancel);
    AACustomByteStreamSetCloseProc(stream, sliceClose);
    return stream;
}

// ============================================================
// Official decode helpers
// ============================================================

static NSString *headerPath(AAHeader header) {
    size_t len = 0;
    int s = AAHeaderGetFieldStringWithKey(header, probeKey("PAT"), 0, NULL, &len);
    if (s <= 0 || len == 0 || len > 4096) return nil;
    NSMutableData *buf = [NSMutableData dataWithLength:len + 1];
    s = AAHeaderGetFieldStringWithKey(header, probeKey("PAT"), buf.length, buf.mutableBytes, &len);
    if (s <= 0) return nil;
    return [[NSString alloc] initWithBytes:buf.bytes length:len encoding:NSUTF8StringEncoding];
}

static BOOL headerDataBlobSize(AAHeader header, uint64_t *outSize) {
    uint64_t size = 0, off = 0;
    int s = AAHeaderGetFieldBlobWithKey(header, probeKey("DAT"), &size, &off);
    if (s <= 0) return NO;
    if (outSize) *outSize = size;
    return YES;
}

static NSData *readPlain(AAByteStream plain, int64_t offset, int64_t length) {
    if (length <= 0 || length > NSUIntegerMax) return nil;
    NSMutableData *data = [NSMutableData dataWithLength:(NSUInteger)length];
    ssize_t got = AAByteStreamPRead(plain, data.mutableBytes, data.length, offset);
    if (got <= 0) return nil;
    [data setLength:(NSUInteger)got];
    return data;
}

static BOOL resolveChunkInnerRange(AAByteStream plain,
                                   AEAFManifestEntry *entry,
                                   int64_t manifestFrameSize,
                                   int64_t *outStart,
                                   int64_t *outLength) {
    int64_t chunkPlain = manifestFrameSize + entry.plainIdx;
    NSData *hdr = readPlain(plain, chunkPlain, 256);
    if (!hdr || hdr.length < 6) return NO;

    NSUInteger cursor = 0, headerSize = 0;
    NSError *err = nil;
    AEAFYAAEntry *outer = AEAFParseYAAFrameHeader(hdr, &cursor, &headerSize, &err);
    if (!outer) {
        const uint8_t *b = hdr.bytes;
        uint16_t hsz = (uint16_t)b[4] | ((uint16_t)b[5] << 8);
        hdr = readPlain(plain, chunkPlain, hsz);
        if (!hdr) return NO;
        cursor = 0;
        outer = AEAFParseYAAFrameHeader(hdr, &cursor, &headerSize, &err);
    }
    if (!outer) return NO;

    int64_t innerStart = chunkPlain + (int64_t)headerSize;
    NSData *peek = readPlain(plain, innerStart, 4);
    if (peek && peek.length == 4 && memcmp(peek.bytes, "pbzx", 4) == 0) {
        return NO;
    }

    if (outStart) *outStart = innerStart;
    if (outLength) *outLength = (int64_t)outer.size;
    return YES;
}

static NSData *findAndReadPathInChunk(AAByteStream plain,
                                      AEAFManifestEntry *entry,
                                      int64_t manifestFrameSize,
                                      NSString *targetPath,
                                      BOOL bootLexStop,
                                      NSInteger *outHeadersRead) {
    int64_t innerStart = 0, innerLength = 0;
    if (!resolveChunkInnerRange(plain, entry, manifestFrameSize, &innerStart, &innerLength)) {
        return nil;
    }

    AAByteStream slice = openPlainSliceStream(plain, innerStart, innerLength);
    if (!slice) return nil;

    AAArchiveStream decode = AADecodeArchiveInputStreamOpen(slice, NULL, NULL, 0, 0);
    if (!decode) {
        AAByteStreamClose(slice);
        return nil;
    }

    NSData *result = nil;
    AAHeader header = NULL;
    NSInteger headers = 0;
    while (1) {
        int status = AAArchiveStreamReadHeader(decode, &header);
        if (status <= 0) break;
        headers++;

        NSString *path = headerPath(header);
        uint64_t blobSize = 0;
        BOOL hasBlob = headerDataBlobSize(header, &blobSize);
        if ([path isEqualToString:targetPath] && hasBlob) {
            if (blobSize <= NSUIntegerMax) {
                NSMutableData *buf = [NSMutableData dataWithLength:(NSUInteger)blobSize];
                int s = AAArchiveStreamReadBlob(decode, probeKey("DAT"), buf.mutableBytes, buf.length);
                if (s == 0) result = buf;
            }
            break;
        }

        if (bootLexStop && path && [path compare:PROBE_BOOT_PREFIX] == NSOrderedDescending
            && ![path hasPrefix:PROBE_BOOT_PREFIX]) {
            break;
        }
    }

    if (outHeadersRead) *outHeadersRead = headers;
    if (header) AAHeaderDestroy(header);
    AAArchiveStreamClose(decode);
    AAByteStreamClose(slice);
    return result;
}

static NSString *kernelcacheNameFromBuildManifest(NSData *data) {
    NSError *err = nil;
    NSDictionary *plist = [NSPropertyListSerialization propertyListWithData:data
                                                                    options:0
                                                                     format:NULL
                                                                      error:&err];
    if (![plist isKindOfClass:[NSDictionary class]]) return nil;
    NSArray *identities = plist[@"BuildIdentities"];
    if (![identities isKindOfClass:[NSArray class]]) return nil;
    for (NSDictionary *identity in identities) {
        NSString *kp = identity[@"Manifest"][@"KernelCache"][@"Info"][@"Path"];
        if ([kp isKindOfClass:[NSString class]] && [kp containsString:@"kernelcache.release."]) {
            return kp;
        }
    }
    return nil;
}

static void printStats(NSString *label, AEAHTTPRangeByteSource *source) {
    printf("%s: %ld reqs / %.2f MiB\n",
           label.UTF8String,
           (long)source.requestCount,
           (double)source.bytesTransferred / (1024.0 * 1024.0));
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc != 3) {
            fprintf(stderr, "usage: %s <aea-url> <base64-symmetric-key>\n", argv[0]);
            return 2;
        }

        NSString *url = [NSString stringWithUTF8String:argv[1]];
        NSData *key = [[NSData alloc] initWithBase64EncodedString:[NSString stringWithUTF8String:argv[2]]
                                                          options:0];
        if (key.length != 32) {
            fprintf(stderr, "bad key length: %lu\n", (unsigned long)key.length);
            return 2;
        }

        AEAHTTPRangeByteSource *source = [[AEAHTTPRangeByteSource alloc] initWithURL:url];
        if (![source prepareContentLength]) {
            fprintf(stderr, "failed to determine remote Content-Length\n");
            return 1;
        }

        AAByteStream encrypted = openRemoteEncryptedStream(source);
        if (!encrypted) {
            fprintf(stderr, "AACustomByteStreamOpen failed\n");
            return 1;
        }

        AEAContext context = AEAContextCreateWithEncryptedStream(encrypted);
        if (!context) {
            fprintf(stderr, "AEAContextCreateWithEncryptedStream failed\n");
            AAByteStreamClose(encrypted);
            return 1;
        }

        if (AEAContextSetSymmetricKey(context, key.bytes, key.length) < 0) {
            fprintf(stderr, "AEAContextSetSymmetricKey failed\n");
            AEAContextDestroy(context);
            AAByteStreamClose(encrypted);
            return 1;
        }

        AAByteStream plain = AEADecryptionRandomAccessInputStreamOpen(encrypted, context,
                                                                      16 * 1024 * 1024,
                                                                      0, 0);
        if (!plain) {
            fprintf(stderr, "AEADecryptionRandomAccessInputStreamOpen failed\n");
            AEAContextDestroy(context);
            AAByteStreamClose(encrypted);
            return 1;
        }

        NSData *manifestHead = readPlain(plain, 0, PROBE_MANIFEST_PREFIX_BYTES);
        if (!manifestHead) {
            fprintf(stderr, "failed to read plaintext manifest prefix\n");
            AAByteStreamClose(plain);
            AEAContextDestroy(context);
            AAByteStreamClose(encrypted);
            return 1;
        }

        int64_t manifestFrameSize = 0;
        NSError *err = nil;
        NSArray<AEAFManifestEntry *> *manifest = AEAFReadYOPManifest(manifestHead, &manifestFrameSize, &err);
        if (!manifest) {
            fprintf(stderr, "YOP manifest parse failed: %s\n", err.localizedDescription.UTF8String);
            AAByteStreamClose(plain);
            AEAContextDestroy(context);
            AAByteStreamClose(encrypted);
            return 1;
        }

        printf("top manifest: %lu entries, frame=%lld\n",
               (unsigned long)manifest.count,
               manifestFrameSize);
        printStats(@"after top manifest", source);
        fflush(stdout);

        NSData *buildManifest = nil;
        NSInteger bmChunk = -1, bmHeaders = 0;
        NSInteger phaseAChunks = MIN((NSInteger)manifest.count, (NSInteger)PROBE_MAX_PHASE_A_CHUNKS);
        for (NSInteger i = 0; i < phaseAChunks; i++) {
            NSInteger headers = 0;
            buildManifest = findAndReadPathInChunk(plain, manifest[i], manifestFrameSize,
                                                   PROBE_BUILD_MANIFEST, NO, &headers);
            printf("BuildManifest chunk %ld: headers=%ld %s\n",
                   (long)i, (long)headers, buildManifest ? "hit" : "miss");
            printStats(@"  cumulative", source);
            fflush(stdout);
            if (buildManifest) {
                bmChunk = i;
                bmHeaders = headers;
                break;
            }
        }

        if (!buildManifest) {
            fprintf(stderr, "BuildManifest.plist not found\n");
            AAByteStreamClose(plain);
            AEAContextDestroy(context);
            AAByteStreamClose(encrypted);
            return 1;
        }

        NSString *kcName = kernelcacheNameFromBuildManifest(buildManifest);
        if (!kcName.length) {
            fprintf(stderr, "BuildManifest.plist contains no kernelcache.release.* path\n");
            AAByteStreamClose(plain);
            AEAContextDestroy(context);
            AAByteStreamClose(encrypted);
            return 1;
        }

        NSString *targetPath = [PROBE_BOOT_PREFIX stringByAppendingString:kcName];
        NSData *kernelcache = nil;
        NSInteger kcChunk = -1, kcHeaders = 0;
        for (NSInteger i = 0; i < (NSInteger)manifest.count; i++) {
            if (manifest[i].size < PROBE_MIN_KC_CHUNK_BYTES) continue;
            NSInteger headers = 0;
            kernelcache = findAndReadPathInChunk(plain, manifest[i], manifestFrameSize,
                                                 targetPath, YES, &headers);
            printf("kernelcache chunk %ld: headers=%ld %s\n",
                   (long)i, (long)headers, kernelcache ? "hit" : "miss");
            printStats(@"  cumulative", source);
            fflush(stdout);
            if (kernelcache) {
                kcChunk = i;
                kcHeaders = headers;
                break;
            }
        }

        AAByteStreamClose(plain);

        if (!kernelcache) {
            fprintf(stderr, "kernelcache not found: %s\n", targetPath.UTF8String);
            AEAContextDestroy(context);
            AAByteStreamClose(encrypted);
            return 1;
        }

        printf("official AppleArchive result:\n");
        printf("  BuildManifest: chunk=%ld headers=%ld size=%lu\n",
               (long)bmChunk, (long)bmHeaders, (unsigned long)buildManifest.length);
        printf("  Kernelcache: chunk=%ld headers=%ld path=%s size=%lu\n",
               (long)kcChunk, (long)kcHeaders, targetPath.UTF8String,
               (unsigned long)kernelcache.length);
        printStats(@"  total", source);

        AEAContextDestroy(context);
        AAByteStreamClose(encrypted);
        return 0;
    }
}
