//
//  aea_internal.h
//  libgrabkernel2
//
//  Private types and helpers used across the aea_fast/ source files.
//

#ifndef aea_internal_h
#define aea_internal_h

#import <Foundation/Foundation.h>
#import <stdint.h>

NS_ASSUME_NONNULL_BEGIN

// HKDF info strings — must match Apple's AEA constants (see AEA spec).
extern NSString *const AEAFInfoMainKey;            // "AEA_AMK"
extern NSString *const AEAFInfoRootHeaderKey;      // "AEA_RHEK"
extern NSString *const AEAFInfoClusterKey;         // "AEA_CK"
extern NSString *const AEAFInfoClusterMaterialKey; // "AEA_CHEK"
extern NSString *const AEAFInfoSegmentKey;         // "AEA_SK"

extern NSErrorDomain const AEAFErrorDomain;

typedef NS_ENUM(NSInteger, AEAFErrorCode) {
    AEAFErrorBadArguments = 1,
    AEAFErrorHTTP,
    AEAFErrorTruncated,
    AEAFErrorBadFormat,
    AEAFErrorUnsupported,
    AEAFErrorHMACMismatch,
    AEAFErrorDecrypt,
    AEAFErrorDecompress,
    AEAFErrorIO,
};

static inline NSError *AEAFMakeError(AEAFErrorCode code, NSString *fmt, ...) NS_FORMAT_FUNCTION(2, 3);
static inline NSError *AEAFMakeError(AEAFErrorCode code, NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    return [NSError errorWithDomain:AEAFErrorDomain code:code userInfo:@{NSLocalizedDescriptionKey: msg ?: @""}];
}

// ============================================================
// crypto primitives (aea_crypto.m)
// ============================================================

// HKDF-SHA256: out = HKDF(salt, ikm, info). salt may be NULL when salt_len==0.
BOOL AEAFHKDFSHA256(const uint8_t *ikm, size_t ikm_len,
                    const uint8_t * _Nullable salt, size_t salt_len,
                    const uint8_t *info, size_t info_len,
                    uint8_t *out, size_t out_len);

// AEA's quirky HMAC: HMAC-SHA256(key, salt || data || u64_le(salt_len)).
// salt may be NULL when salt_len==0. Output is exactly 32 bytes.
BOOL AEAFHMACVariant(const uint8_t *key, size_t key_len,
                     const uint8_t * _Nullable salt, size_t salt_len,
                     const uint8_t *data, size_t data_len,
                     uint8_t *out);

// AES-256 CTR. iv is 16 bytes (full counter block). Result has same length as
// input. Decrypts in place when in == out.
BOOL AEAFAES256CTR(const uint8_t *key,
                   const uint8_t *iv,
                   const uint8_t *in, size_t in_len,
                   uint8_t *out);

// ============================================================
// HTTP Range opener (aea_range.m)
// ============================================================

@interface AEAFRangeOpener : NSObject

@property(nonatomic, readonly) NSInteger requestCount;
@property(nonatomic, readonly) int64_t bytesTransferred;

- (instancetype)initWithURL:(NSString *)url;

// Synchronously fetches [offset, offset+length) from the URL. If length<=0
// the request is open-ended. Up to 3 attempts are made on transient errors.
// Returns nil and fills *outError on failure.
- (nullable NSData *)readRangeAtOffset:(int64_t)offset
                                length:(int64_t)length
                                 error:(NSError **)outError;

@end

// ============================================================
// AEA cluster index (aea_index.m)
// ============================================================

#define AEAF_HMAC_LEN 32
#define AEAF_SEG_HDR_SIZE 40 // DecompressedSize(4) + CompressedSize(4) + Sha256(32)

typedef struct {
    uint32_t decompressed_size;
    uint32_t compressed_size;
    uint8_t  checksum[32];
} AEAFSegmentHeader;

typedef struct {
    uint32_t index;
    int64_t  cipher_header_start;
    int64_t  cipher_body_start;
    int64_t  cipher_body_end;
    int64_t  plain_start;
    int64_t  plain_size;
    uint8_t  incoming_mac[AEAF_HMAC_LEN];
    uint8_t  outgoing_mac[AEAF_HMAC_LEN];
    AEAFSegmentHeader *segments;       // segs_per_cluster, owned
    uint8_t (*segment_macs)[AEAF_HMAC_LEN]; // segs_per_cluster, owned
} AEAFCluster;

typedef struct {
    uint64_t file_size;
    uint64_t encrypted_size;
    uint32_t segment_size;
    uint32_t segs_per_cluster;
    uint8_t  compression;
    uint8_t  checksum;
} AEAFRootHeader;

@interface AEAFClusterIndex : NSObject

@property(nonatomic, readonly) AEAFRootHeader rootHeader;
@property(nonatomic, readonly) int64_t prefixLen;
@property(nonatomic, readonly) int64_t headerSecSize;
@property(nonatomic, readonly) int64_t plainEnd;

// Parses prefix (header + authData + salt + encRootHdr) using one Range read.
+ (nullable instancetype)indexWithOpener:(AEAFRangeOpener *)opener
                              symKeyB64:(NSString *)b64key
                                   error:(NSError **)outError;

// Reads a slice of plaintext [plainOffset, plainOffset+length) into an
// NSMutableData. Walks cluster headers as needed via Range reads, then
// fetches the minimal segment band per cluster. length<=0 means "to end".
- (nullable NSData *)readPlaintextAtOffset:(int64_t)plainOffset
                                    length:(int64_t)length
                                  opener:(AEAFRangeOpener *)opener
                                     error:(NSError **)outError;

@end

// ============================================================
// YOP_MANIFEST + YAA frame parsing (aea_yop.m)
// ============================================================

typedef struct {
    int      index;
    NSString *_Nullable __unsafe_unretained label; // owned by caller's manifest array
    int64_t  size;       // SIZ
    int64_t  plain_idx;  // IDX (running plaintext index, relative to end of manifest entry)
    int64_t  input_size; // IDZ
} AEAFManifestChunk;

@interface AEAFManifestEntry : NSObject
@property(nonatomic, assign) int       index;
@property(nonatomic, copy)   NSString *label;
@property(nonatomic, assign) int64_t   size;
@property(nonatomic, assign) int64_t   plainIdx;
@property(nonatomic, assign) int64_t   inputSize;
@end

@interface AEAFYAAEntry : NSObject
@property(nonatomic, assign) uint8_t  type;       // 'F','M','D','L', etc.
@property(nonatomic, copy, nullable) NSString *path;
@property(nonatomic, copy, nullable) NSString *label;
@property(nonatomic, assign) uint64_t size;
@property(nonatomic, assign) uint64_t entrySize; // ESize / IDZ
@property(nonatomic, assign) uint64_t entryIdx;  // IDX
@property(nonatomic, assign) uint8_t  yop;
@property(nonatomic, assign) uint32_t xat;
@property(nonatomic, assign) uint32_t yec;
@end

// Reads [magic(4) + headerSize(2) + headerBody] from data starting at *cursor
// and returns the decoded YAA entry. Advances *cursor to end of header. Does
// NOT consume any body. Returns nil on parse error.
AEAFYAAEntry *_Nullable AEAFParseYAAFrameHeader(NSData *data,
                                                NSUInteger *cursor,
                                                NSUInteger *outHeaderSize,
                                                NSError **outError);

// Decodes YOP_MANIFEST entry sitting at the very start of the AEA plaintext
// (cursor 0) and returns the chunk list. *outManifestFrameSize gets the
// running plaintext consumption (header_size + manifest payload size).
NSArray<AEAFManifestEntry *> *_Nullable AEAFReadYOPManifest(NSData *data,
                                                            int64_t *outManifestFrameSize,
                                                            NSError **outError);

// ============================================================
// Im4p + decompress (aea_im4p.m)
// ============================================================

// Decodes an IM4P ASN.1 blob and returns the inner Data (the compressed
// kernelcache payload). Returns nil on parse error.
NSData *_Nullable AEAFExtractIM4PPayload(NSData *im4p, NSError **outError);

// Decompresses a kernelcache payload (LZFSE for modern OTAs; bare Mach-O is
// also accepted). Returns the decompressed bytes.
NSData *_Nullable AEAFDecompressKernelcache(NSData *payload, NSError **outError);

// Decompresses a single AEA segment payload according to the root header's
// compression byte. The output buffer is the full DecompressedSize.
BOOL AEAFDecompressSegment(uint8_t compression,
                           const uint8_t *src, size_t src_len,
                           uint8_t *dst, size_t dst_len,
                           size_t *out_written,
                           NSError **outError);

NS_ASSUME_NONNULL_END

#endif /* aea_internal_h */
