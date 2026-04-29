//
//  aea_im4p.m
//  libgrabkernel2
//
//  Minimal BER walker that pulls the OCTET STRING data field out of an IM4P
//  payload, plus LZFSE / segment decompression via Compression.framework.
//

#import <Foundation/Foundation.h>
#import <compression.h>
#import "aea_internal.h"
#import "utils.h"

// LZBITMAP is publicly available since iOS 14.5 / macOS 11.4. Define the
// constant defensively so we still compile against older SDKs.
#ifndef COMPRESSION_LZBITMAP
#define COMPRESSION_LZBITMAP ((compression_algorithm)0x702)
#endif

#define IM4P_BER_TAG_OCTET_STRING 0x04
#define IM4P_BER_TAG_IA5STRING    0x16
#define IM4P_BER_TAG_SEQUENCE     0x30

// Reads a BER length starting at *pos. Advances *pos past the length bytes.
static BOOL berReadLen(const uint8_t *buf, NSUInteger len, NSUInteger *pos, NSUInteger *outLen, NSError **outError) {
    if (*pos >= len) {
        if (outError) *outError = AEAFMakeError(AEAFErrorBadFormat, @"BER length truncated");
        return NO;
    }
    uint8_t b = buf[*pos];
    (*pos)++;
    if ((b & 0x80) == 0) {
        *outLen = b;
        return YES;
    }
    int n = b & 0x7f;
    if (n == 0 || n > 8) {
        if (outError) *outError = AEAFMakeError(AEAFErrorBadFormat, @"BER length form %d unsupported", n);
        return NO;
    }
    if (*pos + n > len) {
        if (outError) *outError = AEAFMakeError(AEAFErrorBadFormat, @"BER long length truncated");
        return NO;
    }
    NSUInteger v = 0;
    for (int i = 0; i < n; i++) {
        v = (v << 8) | buf[*pos + i];
    }
    *pos += n;
    *outLen = v;
    return YES;
}

NSData *AEAFExtractIM4PPayload(NSData *im4p, NSError **outError) {
    const uint8_t *buf = im4p.bytes;
    NSUInteger len = im4p.length;
    NSUInteger pos = 0;
    if (len < 2 || buf[pos] != IM4P_BER_TAG_SEQUENCE) {
        if (outError) *outError = AEAFMakeError(AEAFErrorBadFormat, @"IM4P: not a SEQUENCE (got %#x)", len > 0 ? buf[0] : 0);
        return nil;
    }
    pos++;
    NSUInteger seqLen = 0;
    if (!berReadLen(buf, len, &pos, &seqLen, outError)) return nil;
    NSUInteger seqEnd = pos + seqLen;
    if (seqEnd > len) {
        if (outError) *outError = AEAFMakeError(AEAFErrorBadFormat, @"IM4P SEQUENCE length overflows");
        return nil;
    }

    // Walk children. Expect: IA5String("IM4P"), IA5String(type), IA5String(version), OCTET STRING(data).
    int field = 0;
    while (pos < seqEnd) {
        uint8_t tag = buf[pos++];
        NSUInteger fieldLen = 0;
        if (!berReadLen(buf, len, &pos, &fieldLen, outError)) return nil;
        if (pos + fieldLen > seqEnd) {
            if (outError) *outError = AEAFMakeError(AEAFErrorBadFormat, @"IM4P field overflows SEQUENCE");
            return nil;
        }
        if (field == 0) {
            if (tag != IM4P_BER_TAG_IA5STRING || fieldLen != 4 || memcmp(buf + pos, "IM4P", 4) != 0) {
                if (outError) *outError = AEAFMakeError(AEAFErrorBadFormat, @"IM4P: first field not 'IM4P'");
                return nil;
            }
        } else if (field == 3) {
            if (tag != IM4P_BER_TAG_OCTET_STRING) {
                if (outError) *outError = AEAFMakeError(AEAFErrorBadFormat, @"IM4P: 4th field not OCTET STRING (tag=%#x)", tag);
                return nil;
            }
            return [im4p subdataWithRange:NSMakeRange(pos, fieldLen)];
        }
        pos += fieldLen;
        field++;
    }
    if (outError) *outError = AEAFMakeError(AEAFErrorBadFormat, @"IM4P: payload field not found (only %d fields)", field);
    return nil;
}

// Detects if data is bare Mach-O 64-bit (universal handling intentionally
// skipped — kernelcaches embedded in modern AEA OTAs are LZFSE).
static inline uint32_t rd_u32le_for_macho(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static BOOL isMacho64(const uint8_t *p, NSUInteger len) {
    if (len < 4) return NO;
    uint32_t m = rd_u32le_for_macho(p);
    return m == 0xfeedfacf || m == 0xcffaedfe;
}

NSData *AEAFDecompressKernelcache(NSData *payload, NSError **outError) {
    const uint8_t *p = payload.bytes;
    NSUInteger len = payload.length;
    if (len < 4) {
        if (outError) *outError = AEAFMakeError(AEAFErrorBadFormat, @"kernelcache payload too short");
        return nil;
    }
    // LZFSE: starts with "bvx2" (block) or "bvxn"/"bvx-".
    if (p[0] == 'b' && p[1] == 'v' && p[2] == 'x') {
        // Compression.framework decompresses LZFSE in one shot. We don't
        // know the decompressed size up-front; iterate until success.
        size_t bufSize = MAX((size_t)len * 4, (size_t)16 * 1024 * 1024);
        for (int attempt = 0; attempt < 6; attempt++) {
            NSMutableData *out = [NSMutableData dataWithLength:bufSize];
            size_t written = compression_decode_buffer(out.mutableBytes, bufSize,
                                                        p, len,
                                                        NULL, COMPRESSION_LZFSE);
            if (written == 0) {
                if (outError) *outError = AEAFMakeError(AEAFErrorDecompress, @"LZFSE kernelcache decompress failed");
                return nil;
            }
            if (written < bufSize) {
                [out setLength:written];
                return out;
            }
            // Buffer too small; double and retry.
            bufSize *= 2;
        }
        if (outError) *outError = AEAFMakeError(AEAFErrorDecompress, @"LZFSE output unexpectedly large");
        return nil;
    }
    // Already a Mach-O.
    if (isMacho64(p, len)) {
        return payload;
    }
    if (outError) *outError = AEAFMakeError(AEAFErrorUnsupported, @"unsupported kernelcache magic %02x%02x%02x%02x",
                                            p[0], p[1], p[2], p[3]);
    return nil;
}

BOOL AEAFDecompressSegment(uint8_t compression,
                           const uint8_t *src, size_t src_len,
                           uint8_t *dst, size_t dst_len,
                           size_t *out_written,
                           NSError **outError) {
    compression_algorithm algo;
    switch (compression) {
        case '-': // NONE — caller should not have called us
            if (src_len > dst_len) {
                if (outError) *outError = AEAFMakeError(AEAFErrorDecompress, @"NONE: src %zu > dst %zu", src_len, dst_len);
                return NO;
            }
            memcpy(dst, src, src_len);
            *out_written = src_len;
            return YES;
        case 'b': algo = COMPRESSION_LZBITMAP; break;
        case 'e': algo = COMPRESSION_LZFSE; break;
        case 'z': algo = COMPRESSION_ZLIB; break;
        case 'x': algo = COMPRESSION_LZMA; break;
        case '4': algo = COMPRESSION_LZ4; break;
        default:
            if (outError) *outError = AEAFMakeError(AEAFErrorUnsupported, @"unsupported segment compression %#x ('%c')",
                                                    compression, compression);
            return NO;
    }
    size_t written = compression_decode_buffer(dst, dst_len, src, src_len, NULL, algo);
    if (written == 0) {
        if (outError) *outError = AEAFMakeError(AEAFErrorDecompress, @"compression_decode_buffer failed (algo=%d)", (int)algo);
        return NO;
    }
    *out_written = written;
    return YES;
}
