//
//  aea_fast.h
//  libgrabkernel2
//
//  HTTP-Range driven kernelcache extraction for AEA-encrypted OTAs.
//

#ifndef aea_fast_h
#define aea_fast_h

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// Stats filled by a successful aea_fast_extract_kernelcache call.
typedef struct {
    NSInteger requestCount;    // total HTTP Range requests made
    int64_t   bytesTransferred; // total bytes fetched over the network
    NSInteger chunkIndexUsed;  // YOP_MANIFEST chunk that contained the kernelcache
} AEAFFastStats;

// aea_fast_extract_kernelcache pulls just enough of an AEA OTA over
// HTTP-Range to locate, decrypt and decompress the kernelcache, then writes
// it to outPath.
//
// `aeaURL` must be the .aea OTA URL.
// `decryptionKeyB64` is the base64-encoded AEA symmetric key (AppleDB ships
//   this in `links[].decryptionKey` for iOS 18+ OTAs).
// `outPath` is the file to write the decompressed kernelcache to.
// `chunkIndex` controls chunk selection:
//   0  = auto-scan (scans YOP_MANIFEST chunks for the kernelcache needle,
//        falls back to chunk 4 if the scan finds nothing).
//   >0 = use that specific chunk index directly.
// `kernelPathSubstring` filters which YAA frame counts as the kernelcache.
//   Pass nil for the default ("kernelcache.release.").
// `outStats` receives request/byte/chunk metrics if non-NULL.
//
// Returns YES on success, NO and logs an error on failure.
BOOL aea_fast_extract_kernelcache(NSString *aeaURL,
                                  NSString *decryptionKeyB64,
                                  NSString *outPath,
                                  NSInteger chunkIndex,
                                  NSString *_Nullable kernelPathSubstring,
                                  AEAFFastStats *_Nullable outStats);

NS_ASSUME_NONNULL_END

#endif /* aea_fast_h */
