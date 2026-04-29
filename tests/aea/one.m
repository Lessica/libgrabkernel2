#import <Foundation/Foundation.h>
#import "aea_fast.h"

// Single-build harness: usage: ./aea_one <build> <url> <key> [boardconfig]
int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc < 4) {
            fprintf(stderr, "usage: %s <build> <url> <key> [boardconfig]\n", argv[0]);
            return 2;
        }
        NSString *build = [NSString stringWithUTF8String:argv[1]];
        NSString *url   = [NSString stringWithUTF8String:argv[2]];
        NSString *key   = [NSString stringWithUTF8String:argv[3]];
        NSString *board = argc > 4 ? [NSString stringWithUTF8String:argv[4]] : nil;
        NSString *out = [NSTemporaryDirectory() stringByAppendingPathComponent:
                         [NSString stringWithFormat:@"kc_aea_%@", build]];

        AEAFFastStats stats = {0};
        BOOL ok = aea_fast_extract_kernelcache(url, key, out, board, 0, nil, &stats);
        printf("\nRESULT %s %s chunk=%ld reqs=%ld bytes=%lld\n",
               build.UTF8String,
               ok ? "PASS" : "FAIL",
               (long)stats.chunkIndexUsed,
               (long)stats.requestCount,
               stats.bytesTransferred);
        return ok ? 0 : 1;
    }
}
