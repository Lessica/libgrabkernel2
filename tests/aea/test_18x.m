#import <Foundation/Foundation.h>
#import "grabkernel.h"
#import "aea_fast.h"

// ---------------------------------------------------------------------------
// Multi-build AEA fast-path stress test.
//
// Each row is a real iOS 18 Full OTA with an AppleDB-supplied AEA decryption
// key. We call aea_fast_extract_kernelcache directly (bypassing AppleDB)
// so we can test many builds without extra network lookups.
//
// The test validates:
//  - Successful extraction for every build
//  - Reports request count and bytes transferred per build
//  - Verifies that auto-scan (chunkIndex=0) finds the correct chunk
// ---------------------------------------------------------------------------

typedef struct {
    const char *build;
    const char *model;
    const char *key;   // base64 AEA AMK from AppleDB
    const char *url;
} TestCase;

static TestCase kCases[] = {
    { "22A3351", "iPhone17,1",
      "hEOJElfZ36KloAo2VjC+8eZ/hYuT3/V+09Cg+1waAnA=",
      "https://updates.cdn-apple.com/2024FallFCS/mobileassets/032-87820/49E96347-486E-47BD-858A-202BD5A90E0B/com_apple_MobileAsset_SoftwareUpdate/d9faf503145b73e746c27e075c48af44bfa02f15731649242930e38c98c5fe39.aea" },
    { "22B82", "iPhone14,7",
      "b+9l0LC1Pdr7JxBq2CecnTZ/yIEH4oaWKjbDEtzFmn0=",
      "https://updates.cdn-apple.com/2024FallFCS/mobileassets/062-24410/F9936F79-3FB2-42BA-9D15-E37165F87C37/com_apple_MobileAsset_SoftwareUpdate/8e95e93ae4df9b73ecc64d723b84bdbdb098a707d50f9ca43accfea8c52e4682.aea" },
    { "22C150", "iPhone14,7",
      "M4g7NHWMF4cAUM/KAqqQyslbojbgIHTZr3mnEilJrag=",
      "https://updates.cdn-apple.com/2024FallFCS/mobileassets/052-83879/B1C21480-00B6-4C20-B535-3F8E6359E083/com_apple_MobileAsset_SoftwareUpdate/594adfc17993f5c8f7ff65485f51d65ca192655eb14b1857373ffd5b7eee6f58.aea" },
    { "22D82", "iPhone14,7",
      "MJXOiNZGO9iF2P8P8y9WrgSW7ZkC55XKmuSlgf+aS70=",
      "https://updates.cdn-apple.com/2025WinterFCS/mobileassets/082-03090/D74BB61B-6C86-46F0-9435-A171618EBEF1/com_apple_MobileAsset_SoftwareUpdate/deec2f3e1ef7a74ebcb810afcd09c917cebf54ca1a03736f63dcae6acf3e1dff.aea" },
    { "22E252", "iPhone14,7",
      "Ry69DNpILd4lIvzsHLFYHRIVBmfcTrsU/4R4WunOISA=",
      "https://updates.cdn-apple.com/2025SpringFCS/mobileassets/082-30759/4145E635-9373-431A-AAC2-ED59D20EE36C/com_apple_MobileAsset_SoftwareUpdate/ccb7e6a17cca0195ca7cdba445dfaaed035c8e900625ae87f1877b23333a92b2.aea" },
    { "22F76", "iPhone14,7",
      "zEnJdeWwBxN9rdO4S4TDG9/Q9avClSBU3Ot9GOzaQxA=",
      "https://updates.cdn-apple.com/2025SpringFCS/mobileassets/082-46058/642342D4-C12A-40C4-BBC3-09760D6B707B/com_apple_MobileAsset_SoftwareUpdate/1f6306ba34943cd79dd3191b2c18c4892616164375189a037c15b5ade7e6185a.aea" },
    { "22G100", "iPhone14,7",
      "ndNxtDzY4Wkkt4VYSKl6KmwBiaqtb6YcMqeSpWcMACI=",
      "https://updates.cdn-apple.com/2025SummerFCS/mobileassets/093-21279/E41BD396-3DA3-40B6-93B0-13BB95D46C18/com_apple_MobileAsset_SoftwareUpdate/1316d76b9a2381b67c9512cd7949a4bcc2a62f81295d81916cdef4d7d07b68fc.aea" },
    { "22H124", "iPhone14,7",
      "rnnYn1+STJ0PD0KgDFZmezUGqLH+rE/KAw0K4wVJxjM=",
      "https://updates.cdn-apple.com/2025FallFCS/mobileassets/089-20430/42EC8E9E-6A56-4271-8880-1476E1D79E56/com_apple_MobileAsset_SoftwareUpdate/e33520b3a66af9a0a6f2c7ae175e24514105e9064dde466fca5faf0b234d9690.aea" },
    { "22H352", "iPhone14,7",
      "8Gnb7BZaSRl+lKifU5BzyvP/ZriYHVozHj25ggLF0wY=",
      "https://updates.cdn-apple.com/2026WinterFCS/mobileassets/122-58401/4E536902-586D-4813-ABFA-40C6AE770D9F/com_apple_MobileAsset_SoftwareUpdate/255df022b520f2d68e8aad300e07815f7734d4a712f1895f0eedebab7ebb3711.aea" },
};

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        NSUInteger total = sizeof(kCases) / sizeof(kCases[0]);

        // Header
        printf("\n%-10s  %-12s  %-6s  %5s  %10s  %s\n",
               "Build", "Model", "Chunk", "Reqs", "Bytes(MB)", "Result");
        printf("%-10s  %-12s  %-6s  %5s  %10s  %s\n",
               "----------", "------------", "------", "-----", "----------", "------");

        NSUInteger passed = 0;
        for (NSUInteger i = 0; i < total; i++) {
            TestCase *tc = &kCases[i];
            NSString *outPath = [NSTemporaryDirectory()
                                 stringByAppendingPathComponent:
                                 [NSString stringWithFormat:@"kc_aea_%s", tc->build]];

            AEAFFastStats stats = {0};
            BOOL ok = aea_fast_extract_kernelcache(
                [NSString stringWithUTF8String:tc->url],
                [NSString stringWithUTF8String:tc->key],
                outPath,
                0,   // auto-scan
                nil,
                &stats);

            if (ok) passed++;
            printf("%-10s  %-12s  %-6ld  %5ld  %10.2f  %s\n",
                   tc->build,
                   tc->model,
                   (long)stats.chunkIndexUsed,
                   (long)stats.requestCount,
                   (double)stats.bytesTransferred / (1024.0 * 1024.0),
                   ok ? "PASS" : "FAIL");
            fflush(stdout);
        }

        printf("\n%lu/%lu passed\n\n", (unsigned long)passed, (unsigned long)total);
        return passed == total ? 0 : 1;
    }
}

