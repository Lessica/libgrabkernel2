//
//  aea_crypto.m
//  libgrabkernel2
//
//  HKDF-SHA256, AEA's HMAC variant, and AES-256 CTR built atop CommonCrypto.
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCrypto.h>
#import <string.h>
#import "aea_internal.h"

NSString *const AEAFInfoMainKey            = @"AEA_AMK";
NSString *const AEAFInfoRootHeaderKey      = @"AEA_RHEK";
NSString *const AEAFInfoClusterKey         = @"AEA_CK";
NSString *const AEAFInfoClusterMaterialKey = @"AEA_CHEK";
NSString *const AEAFInfoSegmentKey         = @"AEA_SK";

NSErrorDomain const AEAFErrorDomain = @"AEAFastErrorDomain";

#define HASH_LEN 32

static void hmac_sha256(const uint8_t *key, size_t key_len,
                        const uint8_t *data, size_t data_len,
                        uint8_t out[HASH_LEN]) {
    CCHmac(kCCHmacAlgSHA256, key, key_len, data, data_len, out);
}

BOOL AEAFHKDFSHA256(const uint8_t *ikm, size_t ikm_len,
                    const uint8_t *salt, size_t salt_len,
                    const uint8_t *info, size_t info_len,
                    uint8_t *out, size_t out_len) {
    // HKDF-Extract: PRK = HMAC-SHA256(salt, ikm). If salt is empty, salt is
    // a zero-filled HASH_LEN buffer.
    uint8_t prk[HASH_LEN];
    uint8_t zero_salt[HASH_LEN] = {0};
    const uint8_t *hkdf_salt = (salt_len > 0) ? salt : zero_salt;
    size_t hkdf_salt_len = (salt_len > 0) ? salt_len : HASH_LEN;
    hmac_sha256(hkdf_salt, hkdf_salt_len, ikm, ikm_len, prk);

    // HKDF-Expand: T(0) = empty;
    //              T(i) = HMAC(PRK, T(i-1) || info || i)
    if (out_len > 255 * HASH_LEN) {
        return NO;
    }
    uint8_t t[HASH_LEN];
    size_t t_len = 0;
    size_t produced = 0;
    uint8_t counter = 0;

    // Buffer for HMAC input: previous T || info || counter byte.
    NSMutableData *buf = [NSMutableData dataWithCapacity:HASH_LEN + info_len + 1];
    while (produced < out_len) {
        counter++;
        [buf setLength:0];
        if (t_len > 0) {
            [buf appendBytes:t length:t_len];
        }
        if (info_len > 0) {
            [buf appendBytes:info length:info_len];
        }
        [buf appendBytes:&counter length:1];
        hmac_sha256(prk, HASH_LEN, buf.bytes, buf.length, t);
        t_len = HASH_LEN;
        size_t copy_len = MIN((size_t)HASH_LEN, out_len - produced);
        memcpy(out + produced, t, copy_len);
        produced += copy_len;
    }
    return YES;
}

BOOL AEAFHMACVariant(const uint8_t *key, size_t key_len,
                     const uint8_t *salt, size_t salt_len,
                     const uint8_t *data, size_t data_len,
                     uint8_t out[32]) {
    CCHmacContext ctx;
    CCHmacInit(&ctx, kCCHmacAlgSHA256, key, key_len);
    if (salt_len > 0 && salt != NULL) {
        CCHmacUpdate(&ctx, salt, salt_len);
    }
    if (data_len > 0 && data != NULL) {
        CCHmacUpdate(&ctx, data, data_len);
    }
    uint8_t lenBuf[8];
    uint64_t le = (uint64_t)salt_len;
    for (int i = 0; i < 8; i++) {
        lenBuf[i] = (uint8_t)(le >> (i * 8));
    }
    CCHmacUpdate(&ctx, lenBuf, 8);
    CCHmacFinal(&ctx, out);
    return YES;
}

BOOL AEAFAES256CTR(const uint8_t *key,
                   const uint8_t iv[16],
                   const uint8_t *in, size_t in_len,
                   uint8_t *out) {
    CCCryptorRef cryptor = NULL;
    CCCryptorStatus st = CCCryptorCreateWithMode(kCCEncrypt, kCCModeCTR, kCCAlgorithmAES,
                                                 ccNoPadding,
                                                 iv, key, kCCKeySizeAES256,
                                                 NULL, 0, 0,
                                                 kCCModeOptionCTR_BE,
                                                 &cryptor);
    if (st != kCCSuccess || cryptor == NULL) {
        return NO;
    }
    size_t moved = 0;
    st = CCCryptorUpdate(cryptor, in, in_len, out, in_len, &moved);
    if (st != kCCSuccess) {
        CCCryptorRelease(cryptor);
        return NO;
    }
    size_t finalMoved = 0;
    st = CCCryptorFinal(cryptor, out + moved, in_len - moved, &finalMoved);
    CCCryptorRelease(cryptor);
    return st == kCCSuccess;
}
