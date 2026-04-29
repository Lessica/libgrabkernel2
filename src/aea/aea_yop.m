//
//  aea_yop.m
//  libgrabkernel2
//
//  Minimal YAA frame parser + YOP_MANIFEST decoder. Only the fields needed
//  for kernelcache extraction are honored; unrecognized fields trigger a
//  parse error so we can surface unexpected formats early.
//

#import <Foundation/Foundation.h>
#import "aea_internal.h"

#define YAA_MAGIC1 0x31414159 // "YAA1"
#define YAA_MAGIC2 0x31304141 // "AA01"

@implementation AEAFManifestEntry
@end

@implementation AEAFYAAEntry
@end

static inline uint16_t rd_u16le(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}
static inline uint32_t rd_u32le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static inline uint64_t rd_u64le(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= ((uint64_t)p[i]) << (i * 8);
    return v;
}

// Decodes a YAA header body (the bytes after magic+headerSize) into entry.
// Returns YES on success.
static BOOL decodeYAAEntryBody(const uint8_t *body, NSUInteger len, AEAFYAAEntry *entry, NSError **outError) {
    NSUInteger i = 0;
    while (i + 4 <= len) {
        const uint8_t *field = body + i;
        i += 4;
        char tag[4] = {(char)field[0], (char)field[1], (char)field[2], (char)field[3]};
        // 3-letter group + 1-letter variant
#define NEED(n) do { if (i + (n) > len) { \
            if (outError) *outError = AEAFMakeError(AEAFErrorBadFormat, @"YAA field %.4s truncated", tag); \
            return NO; \
        } } while (0)

        if (memcmp(tag, "TYP", 3) == 0) {
            switch (tag[3]) {
                case '1': NEED(1); entry.type = body[i]; i += 1; break;
                default:
                    if (outError) *outError = AEAFMakeError(AEAFErrorBadFormat, @"unknown TYP variant '%c'", tag[3]);
                    return NO;
            }
        } else if (memcmp(tag, "PAT", 3) == 0) {
            switch (tag[3]) {
                case 'P': {
                    NEED(2);
                    uint16_t plen = rd_u16le(body + i);
                    i += 2;
                    NEED(plen);
                    entry.path = [[NSString alloc] initWithBytes:body + i length:plen encoding:NSUTF8StringEncoding];
                    i += plen;
                    break;
                }
                default:
                    if (outError) *outError = AEAFMakeError(AEAFErrorBadFormat, @"unknown PAT variant '%c'", tag[3]);
                    return NO;
            }
        } else if (memcmp(tag, "LNK", 3) == 0) {
            switch (tag[3]) {
                case 'P': {
                    NEED(2);
                    uint16_t plen = rd_u16le(body + i);
                    i += 2 + plen;
                    if (i > len) { if (outError) *outError = AEAFMakeError(AEAFErrorBadFormat, @"LNKP truncated"); return NO; }
                    break;
                }
                default:
                    if (outError) *outError = AEAFMakeError(AEAFErrorBadFormat, @"unknown LNK variant '%c'", tag[3]);
                    return NO;
            }
        } else if (memcmp(tag, "UID", 3) == 0 || memcmp(tag, "GID", 3) == 0) {
            switch (tag[3]) {
                case '1': NEED(1); i += 1; break;
                case '2': NEED(2); i += 2; break;
                default:
                    if (outError) *outError = AEAFMakeError(AEAFErrorBadFormat, @"unknown UID/GID variant '%c'", tag[3]);
                    return NO;
            }
        } else if (memcmp(tag, "MOD", 3) == 0) {
            switch (tag[3]) {
                case '2': NEED(2); i += 2; break;
                default:
                    if (outError) *outError = AEAFMakeError(AEAFErrorBadFormat, @"unknown MOD variant '%c'", tag[3]);
                    return NO;
            }
        } else if (memcmp(tag, "FLG", 3) == 0) {
            switch (tag[3]) {
                case '1': NEED(1); i += 1; break;
                case '2': NEED(2); i += 2; break;
                case '4': NEED(4); i += 4; break;
                default:
                    if (outError) *outError = AEAFMakeError(AEAFErrorBadFormat, @"unknown FLG variant '%c'", tag[3]);
                    return NO;
            }
        } else if (memcmp(tag, "MTM", 3) == 0 || memcmp(tag, "BTM", 3) == 0 || memcmp(tag, "CTM", 3) == 0) {
            switch (tag[3]) {
                case 'T': NEED(8 + 4); i += 8 + 4; break;
                case 'S': NEED(8); i += 8; break;
                default:
                    if (outError) *outError = AEAFMakeError(AEAFErrorBadFormat, @"unknown time variant '%c'", tag[3]);
                    return NO;
            }
        } else if (memcmp(tag, "DAT", 3) == 0) {
            switch (tag[3]) {
                case 'A': NEED(2); entry.size = rd_u16le(body + i); i += 2; break;
                case 'B': NEED(4); entry.size = rd_u32le(body + i); i += 4; break;
                case 'C': NEED(8); entry.size = rd_u64le(body + i); i += 8; break;
                default:
                    if (outError) *outError = AEAFMakeError(AEAFErrorBadFormat, @"unknown DAT variant '%c'", tag[3]);
                    return NO;
            }
        } else if (memcmp(tag, "XAT", 3) == 0) {
            switch (tag[3]) {
                case 'A': NEED(2); entry.xat = rd_u16le(body + i); i += 2; break;
                case 'B': NEED(4); entry.xat = rd_u32le(body + i); i += 4; break;
                default:
                    if (outError) *outError = AEAFMakeError(AEAFErrorBadFormat, @"unknown XAT variant '%c'", tag[3]);
                    return NO;
            }
        } else if (memcmp(tag, "IDX", 3) == 0) {
            // IDX uses Index (running plain offset) per ipsw's mapping (LE
            // sizes 1/2/4); '8' is overloaded with ESize in ipsw and we
            // treat it the same way to stay consistent.
            switch (tag[3]) {
                case '1': NEED(1); entry.entryIdx = body[i]; i += 1; break;
                case '2': NEED(2); entry.entryIdx = rd_u16le(body + i); i += 2; break;
                case '4': NEED(4); entry.entryIdx = rd_u32le(body + i); i += 4; break;
                case '8': NEED(8); entry.entrySize = rd_u64le(body + i); i += 8; break;
                default:
                    if (outError) *outError = AEAFMakeError(AEAFErrorBadFormat, @"unknown IDX variant '%c'", tag[3]);
                    return NO;
            }
        } else if (memcmp(tag, "IDZ", 3) == 0) {
            switch (tag[3]) {
                case '1': NEED(1); entry.entrySize = body[i]; i += 1; break;
                case '2': NEED(2); entry.entrySize = rd_u16le(body + i); i += 2; break;
                case '4': NEED(4); entry.entrySize = rd_u32le(body + i); i += 4; break;
                case '8': NEED(8); entry.entrySize = rd_u64le(body + i); i += 8; break;
                default:
                    if (outError) *outError = AEAFMakeError(AEAFErrorBadFormat, @"unknown IDZ variant '%c'", tag[3]);
                    return NO;
            }
        } else if (memcmp(tag, "SIZ", 3) == 0) {
            switch (tag[3]) {
                case '1': NEED(1); entry.size = body[i]; i += 1; break;
                case '2': NEED(2); entry.size = rd_u16le(body + i); i += 2; break;
                case '4': NEED(4); entry.size = rd_u32le(body + i); i += 4; break;
                case '8': NEED(8); entry.size = rd_u64le(body + i); i += 8; break;
                default:
                    if (outError) *outError = AEAFMakeError(AEAFErrorBadFormat, @"unknown SIZ variant '%c'", tag[3]);
                    return NO;
            }
        } else if (memcmp(tag, "AFR", 3) == 0 || memcmp(tag, "AFT", 3) == 0
                   || memcmp(tag, "HLC", 3) == 0 || memcmp(tag, "HLO", 3) == 0) {
            switch (tag[3]) {
                case '1': NEED(1); i += 1; break;
                case '2': NEED(2); i += 2; break;
                case '4': NEED(4); i += 4; break;
                default:
                    if (outError) *outError = AEAFMakeError(AEAFErrorBadFormat, @"unknown numeric variant '%c'", tag[3]);
                    return NO;
            }
        } else if (memcmp(tag, "FLI", 3) == 0) {
            NEED(4); i += 4;
        } else if (memcmp(tag, "YOP", 3) == 0) {
            switch (tag[3]) {
                case '1': NEED(1); entry.yop = body[i]; i += 1; break;
                default:
                    if (outError) *outError = AEAFMakeError(AEAFErrorBadFormat, @"unknown YOP variant '%c'", tag[3]);
                    return NO;
            }
        } else if (memcmp(tag, "YEC", 3) == 0) {
            switch (tag[3]) {
                case 'A': NEED(2); entry.yec = rd_u16le(body + i); i += 2; break;
                case 'B': NEED(4); entry.yec = rd_u32le(body + i); i += 4; break;
                default:
                    if (outError) *outError = AEAFMakeError(AEAFErrorBadFormat, @"unknown YEC variant '%c'", tag[3]);
                    return NO;
            }
        } else if (memcmp(tag, "SH2", 3) == 0) {
            NEED(32); i += 32;
        } else if (memcmp(tag, "LBL", 3) == 0) {
            switch (tag[3]) {
                case 'P': {
                    NEED(2);
                    uint16_t llen = rd_u16le(body + i);
                    i += 2;
                    NEED(llen);
                    entry.label = [[NSString alloc] initWithBytes:body + i length:llen encoding:NSUTF8StringEncoding];
                    i += llen;
                    break;
                }
                default:
                    if (outError) *outError = AEAFMakeError(AEAFErrorBadFormat, @"unknown LBL variant '%c'", tag[3]);
                    return NO;
            }
        } else {
            if (outError) *outError = AEAFMakeError(AEAFErrorBadFormat, @"unknown YAA tag %c%c%c%c", tag[0], tag[1], tag[2], tag[3]);
            return NO;
        }
#undef NEED
    }
    return YES;
}

AEAFYAAEntry *AEAFParseYAAFrameHeader(NSData *data,
                                      NSUInteger *cursor,
                                      NSUInteger *outHeaderSize,
                                      NSError **outError) {
    NSUInteger pos = cursor ? *cursor : 0;
    const uint8_t *bytes = data.bytes;
    NSUInteger len = data.length;
    if (pos + 6 > len) {
        if (outError) *outError = AEAFMakeError(AEAFErrorTruncated, @"YAA frame header truncated at %zu", (size_t)pos);
        return nil;
    }
    uint32_t magic = rd_u32le(bytes + pos);
    if (magic != YAA_MAGIC1 && magic != YAA_MAGIC2) {
        if (outError) *outError = AEAFMakeError(AEAFErrorBadFormat, @"bad YAA magic %#x at %zu", magic, (size_t)pos);
        return nil;
    }
    uint16_t hdrSize = rd_u16le(bytes + pos + 4);
    if (hdrSize <= 6) {
        if (outError) *outError = AEAFMakeError(AEAFErrorBadFormat, @"bad YAA hdr size %u", hdrSize);
        return nil;
    }
    if (pos + hdrSize > len) {
        if (outError) *outError = AEAFMakeError(AEAFErrorTruncated, @"YAA frame header span %u > available", hdrSize);
        return nil;
    }
    AEAFYAAEntry *entry = [[AEAFYAAEntry alloc] init];
    if (!decodeYAAEntryBody(bytes + pos + 6, hdrSize - 6, entry, outError)) {
        return nil;
    }
    if (cursor) *cursor = pos + hdrSize;
    if (outHeaderSize) *outHeaderSize = hdrSize;
    return entry;
}

NSArray<AEAFManifestEntry *> *AEAFReadYOPManifest(NSData *data,
                                                  int64_t *outManifestFrameSize,
                                                  NSError **outError) {
    NSUInteger cursor = 0;
    NSUInteger headerSize = 0;
    AEAFYAAEntry *first = AEAFParseYAAFrameHeader(data, &cursor, &headerSize, outError);
    if (!first) return nil;
    if (first.type != 'M' || first.yop != 'M') {
        if (outError) *outError = AEAFMakeError(AEAFErrorBadFormat, @"expected Metadata/YOP_MANIFEST first; got type=%c yop=%c", first.type, first.yop);
        return nil;
    }
    if (first.size == 0) {
        if (outManifestFrameSize) *outManifestFrameSize = (int64_t)headerSize;
        return @[];
    }
    if (cursor + first.size > data.length) {
        if (outError) *outError = AEAFMakeError(AEAFErrorTruncated, @"manifest body span %llu > available %zu",
                                                first.size, (size_t)(data.length - cursor));
        return nil;
    }
    const uint8_t *bytes = data.bytes;
    NSUInteger bodyStart = cursor;
    NSUInteger bodyEnd = cursor + first.size;
    NSMutableArray<AEAFManifestEntry *> *out = [NSMutableArray array];

    NSUInteger inner = bodyStart;
    while (inner < bodyEnd) {
        if (bodyEnd - inner < 6) break;
        uint32_t magic = rd_u32le(bytes + inner);
        if (magic != YAA_MAGIC1 && magic != YAA_MAGIC2) {
            if (outError) *outError = AEAFMakeError(AEAFErrorBadFormat, @"bad inner magic at %zu", (size_t)inner);
            return nil;
        }
        uint16_t hdrSize = rd_u16le(bytes + inner + 4);
        if (hdrSize <= 6 || inner + hdrSize > bodyEnd) {
            if (outError) *outError = AEAFMakeError(AEAFErrorBadFormat, @"bad inner hdr size %u", hdrSize);
            return nil;
        }
        AEAFYAAEntry *ent = [[AEAFYAAEntry alloc] init];
        if (!decodeYAAEntryBody(bytes + inner + 6, hdrSize - 6, ent, outError)) {
            return nil;
        }
        inner += hdrSize;
        if (ent.type == 'M' && ent.yop == 'E') {
            AEAFManifestEntry *m = [[AEAFManifestEntry alloc] init];
            m.index = (int)out.count;
            m.label = ent.label ?: @"";
            m.size = (int64_t)ent.size;
            m.plainIdx = (int64_t)ent.entryIdx;
            m.inputSize = (int64_t)ent.entrySize;
            [out addObject:m];
        }
    }
    if (outManifestFrameSize) *outManifestFrameSize = (int64_t)(bodyEnd);
    return out;
}
