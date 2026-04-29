//
//  appledb_internal.h
//  libgrabkernel2
//
//  Library-private extensions to the AppleDB resolver. Exposes the full
//  FirmwareLink record (including the AEA decryption key) so the dispatch
//  layer in grabkernel.m can pick the right download path. Not part of the
//  public ABI.
//

#ifndef appledb_internal_h
#define appledb_internal_h

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// FirmwareLink describes a chosen firmware download endpoint.
//
// `decryptionKey` (when non-nil) is the base64-encoded AEA symmetric key for
// encrypted OTA assets (.aea). It is required to extract any payload from an
// AEA-wrapped OTA. AppleDB ships this key alongside iOS 18+ OTA links.
@interface FirmwareLink : NSObject
@property(nonatomic, copy) NSString *url;
@property(nonatomic, copy, nullable) NSString *decryptionKey; // base64 AEA AMK, nil for non-AEA
@property(nonatomic, assign) BOOL isOTA;
@property(nonatomic, assign) BOOL isAEA;
@end

FirmwareLink *_Nullable getFirmwareLinkFor(NSString *osStr, NSString *build, NSString *modelIdentifier);
FirmwareLink *_Nullable getFirmwareLink(void);

NS_ASSUME_NONNULL_END

#endif /* appledb_internal_h */
