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

// aea_fast_extract_kernelcache pulls just enough of an AEA OTA over
// HTTP-Range to locate, decrypt and decompress the kernelcache, then writes
// it to outPath.
//
// `aeaURL` must be the .aea OTA URL.
// `decryptionKeyB64` is the base64-encoded AEA symmetric key (AppleDB ships
//   this in `links[].decryptionKey` for iOS 18+ OTAs).
// `outPath` is the file to write the decompressed kernelcache to.
// `chunkIndex` is the YOP_MANIFEST chunk that holds the kernelcache; pass 0
//   to use the default of 4 (which is correct for current iOS 18+ OTAs).
// `kernelPathSubstring` filters which YAA frame counts as the kernelcache.
//   Pass nil for the default ("kernelcache.release.").
//
// Returns YES on success, NO and logs an error on failure.
BOOL aea_fast_extract_kernelcache(NSString *aeaURL,
                                  NSString *decryptionKeyB64,
                                  NSString *outPath,
                                  NSInteger chunkIndex,
                                  NSString *_Nullable kernelPathSubstring);

NS_ASSUME_NONNULL_END

#endif /* aea_fast_h */
