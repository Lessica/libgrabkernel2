//
//  aea_index.m
//  libgrabkernel2
//
//  AEA prefix loading, cluster header walking, and segment-band-driven
//  plaintext slicing.
//

#import <Foundation/Foundation.h>
#import "aea_internal.h"
#import "utils.h"

#define AEAF_MAGIC "AEA1"
#define AEAF_PROFILE_SYMMETRIC 1

#pragma pack(push, 1)
typedef struct {
    char     magic[4];                  // "AEA1"
    uint32_t profile_and_scrypt;
    uint32_t auth_data_length;
} AEAFFileHeader;

typedef struct {
    uint8_t  hmac[32];
    uint8_t  data[48];
    uint8_t  cluster_hmac[32];
} AEAFEncRootHeader;

typedef struct {
    uint64_t file_size;
    uint64_t encrypted_size;
    uint32_t segment_size;
    uint32_t segs_per_cluster;
    uint8_t  compression;
    uint8_t  checksum;
    uint8_t  pad[22];
} AEAFRootHeaderOnDisk;

typedef struct {
    uint8_t mac[32];
    uint8_t key[32];
    uint8_t iv[16];
} AEAFHeaderKey;
#pragma pack(pop)

static NSData *base64Decode(NSString *b64) {
    return [[NSData alloc] initWithBase64EncodedString:b64
                                                options:NSDataBase64DecodingIgnoreUnknownCharacters];
}

@implementation AEAFClusterIndex {
    NSData *_mainKey;
    NSMutableArray<NSValue *> *_clusterValues; // each holds an AEAFCluster *
    AEAFRangeOpener *_opener;
    AEAFRootHeader _rootHeader;
    int64_t _prefixLen;
    int64_t _headerSecSize;
    int64_t _plainEnd;
    // LRU cache of decrypted+decompressed segment plaintexts.
    // Key: NSNumber boxing (uint64_t)((cluster.index << 32) | segIdx)
    // _segCacheOrder is MRU-first.
    NSMutableDictionary<NSNumber *, NSData *> *_segCache;
    NSMutableArray<NSNumber *> *_segCacheOrder;
}

#define AEAF_SEG_CACHE_MAX 8

- (AEAFRootHeader)rootHeader { return _rootHeader; }
- (int64_t)prefixLen { return _prefixLen; }
- (int64_t)headerSecSize { return _headerSecSize; }
- (int64_t)plainEnd { return _plainEnd; }

- (instancetype)init {
    if ((self = [super init])) {
        _clusterValues = [NSMutableArray array];
        _segCache = [NSMutableDictionary dictionaryWithCapacity:AEAF_SEG_CACHE_MAX];
        _segCacheOrder = [NSMutableArray arrayWithCapacity:AEAF_SEG_CACHE_MAX];
    }
    return self;
}

- (NSData *)cachedSegmentForKey:(NSNumber *)key {
    NSData *d = _segCache[key];
    if (!d) return nil;
    [_segCacheOrder removeObject:key];
    [_segCacheOrder insertObject:key atIndex:0];
    return d;
}

- (void)cacheSegment:(NSData *)plain forKey:(NSNumber *)key {
    if (!plain || plain.length == 0) return;
    if (!_segCache[key]) {
        if (_segCacheOrder.count >= AEAF_SEG_CACHE_MAX) {
            NSNumber *evict = _segCacheOrder.lastObject;
            [_segCacheOrder removeLastObject];
            [_segCache removeObjectForKey:evict];
        }
        [_segCacheOrder insertObject:key atIndex:0];
    } else {
        [_segCacheOrder removeObject:key];
        [_segCacheOrder insertObject:key atIndex:0];
    }
    _segCache[key] = plain;
}

- (void)dealloc {
    for (NSValue *v in _clusterValues) {
        AEAFCluster *c = (AEAFCluster *)v.pointerValue;
        if (c) {
            free(c->segments);
            free(c->segment_macs);
            free(c);
        }
    }
}

+ (nullable instancetype)indexWithOpener:(AEAFRangeOpener *)opener
                              symKeyB64:(NSString *)b64key
                                   error:(NSError **)outError {
    NSData *symKey = base64Decode(b64key);
    if (!symKey || symKey.length != 32) {
        if (outError) *outError = AEAFMakeError(AEAFErrorBadArguments, @"bad base64 sym key (got %zu bytes)", (size_t)symKey.length);
        return nil;
    }

    NSData *prefix = [opener readRangeAtOffset:0 length:64 * 1024 error:outError];
    if (!prefix) return nil;
    const uint8_t *bytes = prefix.bytes;
    NSUInteger total = prefix.length;
    if (total < sizeof(AEAFFileHeader)) {
        if (outError) *outError = AEAFMakeError(AEAFErrorTruncated, @"prefix too short for header");
        return nil;
    }
    AEAFFileHeader fh;
    memcpy(&fh, bytes, sizeof(fh));
    if (memcmp(fh.magic, AEAF_MAGIC, 4) != 0) {
        if (outError) *outError = AEAFMakeError(AEAFErrorBadFormat, @"bad AEA magic");
        return nil;
    }
    uint32_t profile = fh.profile_and_scrypt & 0xffffff;
    if (profile != AEAF_PROFILE_SYMMETRIC) {
        if (outError) *outError = AEAFMakeError(AEAFErrorUnsupported, @"profile %u not supported", profile);
        return nil;
    }
    uint32_t authLen = fh.auth_data_length;
    int64_t cursor = sizeof(fh);
    if ((NSUInteger)cursor + authLen + 32 + sizeof(AEAFEncRootHeader) > total) {
        if (outError) *outError = AEAFMakeError(AEAFErrorTruncated, @"prefix incomplete");
        return nil;
    }
    const uint8_t *authData = bytes + cursor;
    cursor += authLen;
    const uint8_t *mainSalt = bytes + cursor;
    cursor += 32;
    AEAFEncRootHeader encRoot;
    memcpy(&encRoot, bytes + cursor, sizeof(encRoot));
    cursor += sizeof(encRoot);

    // Derive main key: HKDF(symKey, mainSalt, "AEA_AMK" || u32_le(profile_and_scrypt))
    uint8_t mainKeyInfo[7 + 4];
    memcpy(mainKeyInfo, "AEA_AMK", 7);
    uint32_t pas = fh.profile_and_scrypt;
    for (int i = 0; i < 4; i++) mainKeyInfo[7 + i] = (uint8_t)(pas >> (i * 8));
    uint8_t mainKey[32];
    if (!AEAFHKDFSHA256(symKey.bytes, symKey.length, mainSalt, 32, mainKeyInfo, sizeof(mainKeyInfo), mainKey, 32)) {
        if (outError) *outError = AEAFMakeError(AEAFErrorDecrypt, @"derive main key");
        return nil;
    }

    // Derive root header key: HKDF(mainKey, "", "AEA_RHEK") -> 80 bytes
    AEAFHeaderKey rhk;
    if (!AEAFHKDFSHA256(mainKey, 32, NULL, 0, (const uint8_t *)"AEA_RHEK", 8, (uint8_t *)&rhk, sizeof(rhk))) {
        if (outError) *outError = AEAFMakeError(AEAFErrorDecrypt, @"derive root header key");
        return nil;
    }

    // Authenticate root header. Salt = clusterHmac || authData; data = encRoot.data.
    NSMutableData *salt = [NSMutableData dataWithCapacity:32 + authLen];
    [salt appendBytes:encRoot.cluster_hmac length:32];
    [salt appendBytes:authData length:authLen];
    uint8_t calcMac[32];
    if (!AEAFHMACVariant(rhk.mac, 32, salt.bytes, salt.length, encRoot.data, sizeof(encRoot.data), calcMac)) {
        if (outError) *outError = AEAFMakeError(AEAFErrorDecrypt, @"root header HMAC failed");
        return nil;
    }
    if (memcmp(calcMac, encRoot.hmac, 32) != 0) {
        if (outError) *outError = AEAFMakeError(AEAFErrorHMACMismatch, @"root header HMAC mismatch");
        return nil;
    }
    // Decrypt encRoot.data || authData (CTR — encrypts only first len(data) bytes).
    NSMutableData *cipherBlob = [NSMutableData dataWithCapacity:sizeof(encRoot.data) + authLen];
    [cipherBlob appendBytes:encRoot.data length:sizeof(encRoot.data)];
    [cipherBlob appendBytes:authData length:authLen];
    NSMutableData *plainBlob = [NSMutableData dataWithLength:cipherBlob.length];
    if (!AEAFAES256CTR(rhk.key, rhk.iv, cipherBlob.bytes, cipherBlob.length, plainBlob.mutableBytes)) {
        if (outError) *outError = AEAFMakeError(AEAFErrorDecrypt, @"root header CTR decrypt");
        return nil;
    }
    if (plainBlob.length < sizeof(AEAFRootHeaderOnDisk)) {
        if (outError) *outError = AEAFMakeError(AEAFErrorBadFormat, @"root header too short");
        return nil;
    }
    AEAFRootHeaderOnDisk rh;
    memcpy(&rh, plainBlob.bytes, sizeof(rh));

    AEAFClusterIndex *idx = [[self alloc] init];
    idx->_opener = opener;
    idx->_mainKey = [NSData dataWithBytes:mainKey length:32];
    idx->_rootHeader.file_size = rh.file_size;
    idx->_rootHeader.encrypted_size = rh.encrypted_size;
    idx->_rootHeader.segment_size = rh.segment_size;
    idx->_rootHeader.segs_per_cluster = rh.segs_per_cluster;
    idx->_rootHeader.compression = rh.compression;
    idx->_rootHeader.checksum = rh.checksum;
    if (rh.checksum != 2 /* Sha256 */) {
        if (outError) *outError = AEAFMakeError(AEAFErrorUnsupported, @"checksum type %u not supported (only SHA256)", rh.checksum);
        return nil;
    }
    idx->_prefixLen = (int64_t)sizeof(fh) + (int64_t)authLen + 32 + (int64_t)sizeof(encRoot);
    idx->_headerSecSize = (int64_t)AEAF_SEG_HDR_SIZE * (int64_t)rh.segs_per_cluster
                          + 32 + 32 * (int64_t)rh.segs_per_cluster;
    AEAFCluster *c0 = calloc(1, sizeof(AEAFCluster));
    c0->index = 0;
    c0->cipher_header_start = idx->_prefixLen;
    memcpy(c0->incoming_mac, encRoot.cluster_hmac, 32);
    [idx->_clusterValues addObject:[NSValue valueWithPointer:c0]];
    DBGLOG("AEA prefix loaded: file_size=%llu, segment_size=%u, segs_per_cluster=%u, compression=%u, prefix_len=%lld, header_sec_size=%lld\n",
           rh.file_size, rh.segment_size, rh.segs_per_cluster, rh.compression,
           idx->_prefixLen, idx->_headerSecSize);
    return idx;
}

- (AEAFCluster *)clusterAt:(NSUInteger)i {
    return (AEAFCluster *)[_clusterValues[i] pointerValue];
}

// Reads + authenticates + decrypts the header section of cluster c.
- (BOOL)readClusterHeader:(AEAFCluster *)c
                   opener:(AEAFRangeOpener *)opener
              plainCursor:(int64_t)plainCursor
                    error:(NSError **)outError {
    NSData *hdrData = [opener readRangeAtOffset:c->cipher_header_start
                                          length:_headerSecSize
                                           error:outError];
    if (!hdrData) return NO;
    if ((int64_t)hdrData.length < _headerSecSize) {
        if (outError) *outError = AEAFMakeError(AEAFErrorTruncated, @"cluster %u header short read", c->index);
        return NO;
    }
    const uint8_t *p = hdrData.bytes;
    uint32_t segPer = _rootHeader.segs_per_cluster;
    int64_t encSegBytes = (int64_t)AEAF_SEG_HDR_SIZE * segPer;
    const uint8_t *encSegHdrs = p;
    p += encSegBytes;
    uint8_t nextClusterMac[32];
    memcpy(nextClusterMac, p, 32);
    p += 32;
    const uint8_t *segMacBytes = p;
    int64_t segMacBytesLen = 32 * (int64_t)segPer;

    // Derive cluster key: HKDF(mainKey, "", "AEA_CK" || u32_le(index)).
    uint8_t ckInfo[6 + 4];
    memcpy(ckInfo, "AEA_CK", 6);
    for (int i = 0; i < 4; i++) ckInfo[6 + i] = (uint8_t)(c->index >> (i * 8));
    uint8_t clusterKey[32];
    if (!AEAFHKDFSHA256(_mainKey.bytes, 32, NULL, 0, ckInfo, sizeof(ckInfo), clusterKey, 32)) {
        if (outError) *outError = AEAFMakeError(AEAFErrorDecrypt, @"derive cluster %u key", c->index);
        return NO;
    }
    AEAFHeaderKey chk;
    if (!AEAFHKDFSHA256(clusterKey, 32, NULL, 0, (const uint8_t *)"AEA_CHEK", 8, (uint8_t *)&chk, sizeof(chk))) {
        if (outError) *outError = AEAFMakeError(AEAFErrorDecrypt, @"derive cluster %u header key", c->index);
        return NO;
    }
    NSMutableData *salt = [NSMutableData dataWithCapacity:32 + segMacBytesLen];
    [salt appendBytes:nextClusterMac length:32];
    [salt appendBytes:segMacBytes length:segMacBytesLen];
    uint8_t calcMac[32];
    if (!AEAFHMACVariant(chk.mac, 32, salt.bytes, salt.length, encSegHdrs, encSegBytes, calcMac)) {
        if (outError) *outError = AEAFMakeError(AEAFErrorDecrypt, @"cluster %u HMAC", c->index);
        return NO;
    }
    if (memcmp(calcMac, c->incoming_mac, 32) != 0) {
        if (outError) *outError = AEAFMakeError(AEAFErrorHMACMismatch, @"cluster %u header HMAC mismatch", c->index);
        return NO;
    }
    // Decrypt segment headers in place.
    NSMutableData *segHdrPlain = [NSMutableData dataWithLength:encSegBytes];
    if (!AEAFAES256CTR(chk.key, chk.iv, encSegHdrs, encSegBytes, segHdrPlain.mutableBytes)) {
        if (outError) *outError = AEAFMakeError(AEAFErrorDecrypt, @"cluster %u CTR decrypt", c->index);
        return NO;
    }
    AEAFSegmentHeader *segs = calloc(segPer, sizeof(AEAFSegmentHeader));
    memcpy(segs, segHdrPlain.bytes, encSegBytes);
    uint8_t (*segMacs)[32] = calloc(segPer, 32);
    memcpy(segMacs, segMacBytes, segMacBytesLen);

    int64_t plainSz = 0, bodyLen = 0;
    for (uint32_t i = 0; i < segPer; i++) {
        plainSz += segs[i].decompressed_size;
        bodyLen += segs[i].compressed_size;
    }

    memcpy(c->outgoing_mac, nextClusterMac, 32);
    c->segments = segs;
    c->segment_macs = segMacs;
    c->cipher_body_start = c->cipher_header_start + _headerSecSize;
    c->cipher_body_end = c->cipher_body_start + bodyLen;
    c->plain_start = plainCursor;
    c->plain_size = plainSz;
    return YES;
}

// Walks cluster headers until plainOffset is covered. Returns the cluster
// array index that contains plainOffset, or -1 on failure.
- (NSInteger)indexUntilPlainOffset:(int64_t)plainOffset
                            opener:(AEAFRangeOpener *)opener
                             error:(NSError **)outError {
    if (plainOffset < 0) {
        if (outError) *outError = AEAFMakeError(AEAFErrorBadArguments, @"negative plainOffset");
        return -1;
    }
    while (1) {
        NSInteger idx = (NSInteger)_clusterValues.count - 1;
        AEAFCluster *cur = [self clusterAt:idx];
        if (cur->segments == NULL) {
            if (![self readClusterHeader:cur opener:opener plainCursor:_plainEnd error:outError]) {
                return -1;
            }
            _plainEnd = cur->plain_start + cur->plain_size;
        }
        if (plainOffset < cur->plain_start + cur->plain_size) {
            return idx;
        }
        if ((uint64_t)_plainEnd >= _rootHeader.file_size) {
            if (outError) *outError = AEAFMakeError(AEAFErrorBadArguments, @"plainOffset %lld past file size %llu",
                                                    plainOffset, _rootHeader.file_size);
            return -1;
        }
        AEAFCluster *next = calloc(1, sizeof(AEAFCluster));
        next->index = cur->index + 1;
        next->cipher_header_start = cur->cipher_body_end;
        memcpy(next->incoming_mac, cur->outgoing_mac, 32);
        [_clusterValues addObject:[NSValue valueWithPointer:next]];
    }
}

// segRange: returns range of segment indices [firstSeg..lastSeg] in cluster c
// whose plaintext spans overlap [wantStart, wantEnd). segSkip = bytes to drop
// from start of firstSeg's plaintext. segCap = clamp on lastSeg's plaintext.
static BOOL segRange(AEAFCluster *c, int64_t wantStart, int64_t wantEnd,
                     uint32_t segPer,
                     int *outFirst, int *outLast, int64_t *outSkip, int64_t *outCap) {
    int firstSeg = -1, lastSeg = -1;
    int64_t segSkip = 0, segCap = 0;
    int64_t plainPos = c->plain_start;
    for (uint32_t i = 0; i < segPer; i++) {
        AEAFSegmentHeader *s = &c->segments[i];
        int64_t segPlainEnd = plainPos + s->decompressed_size;
        if (firstSeg == -1 && segPlainEnd > wantStart && s->decompressed_size > 0) {
            firstSeg = (int)i;
            segSkip = wantStart - plainPos;
            if (segSkip < 0) segSkip = 0;
        }
        if (firstSeg != -1 && plainPos < wantEnd) {
            lastSeg = (int)i;
            segCap = wantEnd - plainPos;
            if (segCap > (int64_t)s->decompressed_size) {
                segCap = s->decompressed_size;
            }
        }
        plainPos = segPlainEnd;
    }
    if (firstSeg < 0) return NO;
    *outFirst = firstSeg;
    *outLast = lastSeg;
    *outSkip = segSkip;
    *outCap = segCap;
    return YES;
}

- (NSData *)readPlaintextAtOffset:(int64_t)plainOffset
                           length:(int64_t)length
                           opener:(AEAFRangeOpener *)opener
                            error:(NSError **)outError {
    NSInteger startIdx = [self indexUntilPlainOffset:plainOffset opener:opener error:outError];
    if (startIdx < 0) return nil;
    int64_t wantStart = plainOffset;
    int64_t wantEnd = (int64_t)_rootHeader.file_size;
    if (length > 0) {
        wantEnd = plainOffset + length;
        if ((uint64_t)wantEnd > _rootHeader.file_size) {
            wantEnd = (int64_t)_rootHeader.file_size;
        }
    }
    NSInteger endIdx = startIdx;
    if (wantEnd > 0) {
        endIdx = [self indexUntilPlainOffset:wantEnd - 1 opener:opener error:outError];
        if (endIdx < 0) return nil;
    }
    uint32_t segPer = _rootHeader.segs_per_cluster;
    NSMutableData *out = [NSMutableData dataWithCapacity:(NSUInteger)(wantEnd - wantStart)];

    for (NSInteger ci = startIdx; ci <= endIdx; ci++) {
        AEAFCluster *cluster = [self clusterAt:ci];
        if (cluster->segments == NULL) {
            if (outError) *outError = AEAFMakeError(AEAFErrorBadArguments, @"cluster %u not indexed", cluster->index);
            return nil;
        }
        int firstSeg = 0, lastSeg = 0;
        int64_t segSkip = 0, segCap = 0;
        if (!segRange(cluster, wantStart, wantEnd, segPer, &firstSeg, &lastSeg, &segSkip, &segCap)) {
            continue;
        }

        // Identify which segments in [firstSeg..lastSeg] are NOT cached.
        // Fetch + decrypt only the contiguous run(s) of missing segments.
        // To keep things simple, we fetch one tight range covering all
        // missing segments in this band; cached ones are reused as-is.
        int missLo = -1, missHi = -1;
        for (int seg = firstSeg; seg <= lastSeg; seg++) {
            uint64_t k = ((uint64_t)cluster->index << 32) | (uint32_t)seg;
            NSNumber *key = @(k);
            if (_segCache[key] == nil) {
                if (missLo < 0) missLo = seg;
                missHi = seg;
            }
        }

        NSData *bodyBlob = nil;
        int64_t missBodyStart = 0;
        if (missLo >= 0) {
            int64_t preBytes = 0, spanBytes = 0;
            for (int i = 0; i < (int)segPer; i++) {
                AEAFSegmentHeader *s = &cluster->segments[i];
                if (i < missLo) {
                    preBytes += s->compressed_size;
                    continue;
                }
                if (i > missHi) break;
                spanBytes += s->compressed_size;
            }
            int64_t rangeStart = cluster->cipher_body_start + preBytes;
            bodyBlob = [opener readRangeAtOffset:rangeStart length:spanBytes error:outError];
            if (!bodyBlob) return nil;
            if ((int64_t)bodyBlob.length < spanBytes) {
                if (outError) *outError = AEAFMakeError(AEAFErrorTruncated, @"cluster %u body short read", cluster->index);
                return nil;
            }
            missBodyStart = preBytes;
        }

        // Derive cluster key once per cluster (cheap but skip when no misses).
        uint8_t clusterKey[32];
        BOOL clusterKeyReady = NO;
        if (missLo >= 0) {
            uint8_t ckInfo[6 + 4];
            memcpy(ckInfo, "AEA_CK", 6);
            for (int j = 0; j < 4; j++) ckInfo[6 + j] = (uint8_t)(cluster->index >> (j * 8));
            if (!AEAFHKDFSHA256(_mainKey.bytes, 32, NULL, 0, ckInfo, sizeof(ckInfo), clusterKey, 32)) {
                if (outError) *outError = AEAFMakeError(AEAFErrorDecrypt, @"derive cluster %u key", cluster->index);
                return nil;
            }
            clusterKeyReady = YES;
        }

        // Walk band segments; pull from cache or decrypt+cache.
        int64_t bodyOff = 0;
        for (int seg = firstSeg; seg <= lastSeg; seg++) {
            AEAFSegmentHeader *sh = &cluster->segments[seg];
            uint32_t cSize = sh->compressed_size;
            uint32_t dSize = sh->decompressed_size;
            if (cSize == 0 || dSize == 0) continue;

            uint64_t k = ((uint64_t)cluster->index << 32) | (uint32_t)seg;
            NSNumber *cacheKey = @(k);
            NSData *segOut = [self cachedSegmentForKey:cacheKey];

            if (!segOut) {
                // Locate this segment's cipher within bodyBlob.
                int64_t segPre = 0;
                for (int i = missLo; i < seg; i++) {
                    segPre += cluster->segments[i].compressed_size;
                }
                const uint8_t *segCipher = (const uint8_t *)bodyBlob.bytes + segPre;
                (void)bodyOff;

                uint8_t skInfo[6 + 4];
                memcpy(skInfo, "AEA_SK", 6);
                for (int j = 0; j < 4; j++) skInfo[6 + j] = (uint8_t)((uint32_t)seg >> (j * 8));
                AEAFHeaderKey segKey;
                if (!clusterKeyReady ||
                    !AEAFHKDFSHA256(clusterKey, 32, NULL, 0, skInfo, sizeof(skInfo),
                                    (uint8_t *)&segKey, sizeof(segKey))) {
                    if (outError) *outError = AEAFMakeError(AEAFErrorDecrypt, @"derive seg key");
                    return nil;
                }
                uint8_t calcMac[32];
                if (!AEAFHMACVariant(segKey.mac, 32, NULL, 0, segCipher, cSize, calcMac)) {
                    if (outError) *outError = AEAFMakeError(AEAFErrorDecrypt, @"seg HMAC");
                    return nil;
                }
                if (memcmp(calcMac, cluster->segment_macs[seg], 32) != 0) {
                    if (outError) *outError = AEAFMakeError(AEAFErrorHMACMismatch, @"seg %d HMAC mismatch", seg);
                    return nil;
                }
                NSMutableData *segPlain = [NSMutableData dataWithLength:cSize];
                if (!AEAFAES256CTR(segKey.key, segKey.iv, segCipher, cSize, segPlain.mutableBytes)) {
                    if (outError) *outError = AEAFMakeError(AEAFErrorDecrypt, @"seg CTR decrypt");
                    return nil;
                }
                if (cSize == dSize) {
                    segOut = segPlain;
                } else {
                    NSMutableData *dec = [NSMutableData dataWithLength:dSize];
                    size_t written = 0;
                    if (!AEAFDecompressSegment(_rootHeader.compression,
                                               segPlain.bytes, cSize,
                                               dec.mutableBytes, dSize,
                                               &written, outError)) {
                        return nil;
                    }
                    if (written != dSize) {
                        if (outError) *outError = AEAFMakeError(AEAFErrorDecompress, @"seg decompress short: %zu vs %u", written, dSize);
                        return nil;
                    }
                    segOut = dec;
                }
                [self cacheSegment:segOut forKey:cacheKey];
            }

            const uint8_t *segBytes = segOut.bytes;
            int64_t outStart = 0;
            int64_t outLen = (int64_t)segOut.length;
            if (seg == firstSeg && segSkip > 0) {
                outStart = segSkip;
                if (outStart >= outLen) continue;
                outLen -= outStart;
            }
            if (seg == lastSeg) {
                int64_t cap = segCap;
                if (seg == firstSeg) cap -= segSkip;
                if (cap > 0 && cap < outLen) {
                    outLen = cap;
                }
            }
            if (outLen > 0) {
                [out appendBytes:segBytes + outStart length:(NSUInteger)outLen];
            }
        }
        (void)missBodyStart;
    }
    return out;
}

@end
