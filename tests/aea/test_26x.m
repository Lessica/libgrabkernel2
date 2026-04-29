#import <Foundation/Foundation.h>
#import "grabkernel.h"
#import "aea_fast.h"

// ---------------------------------------------------------------------------
// Multi-build AEA fast-path stress test (iOS 26.x).
//
// Each row is a real iOS 26 Full OTA with an AppleDB-supplied AEA decryption
// key. Covers every released 26.x build for two devices: iPhone14,7
// (A15, no Apple Intelligence) and iPhone17,1 (A18 Pro).
//
// Expected: 20/20 PASS.
// ---------------------------------------------------------------------------

typedef struct {
    const char *build;
    const char *model;
    const char *board;
    const char *key;
    const char *url;
} TestCase;

static TestCase kCases[] = {
    // 26.0
    { "23A341", "iPhone14,7", "D27AP",
      "feY8+Ogygsf+7q9ig/4EAjXZsTHKSe80yfguEGC1KqU=",
      "https://updates.cdn-apple.com/2025FallFCS/mobileassets/093-40362/76DEFB05-E268-4F9B-B6B8-32C03CED3199/com_apple_MobileAsset_SoftwareUpdate/7341339d7a706af7904f5e1ee71aa46d07ca943af77de91ca6a3750553b80983.aea" },
    { "23A341", "iPhone17,1", "D93AP",
      "sefY6ymzlA7H8EKg0bjluS31MQkIId1FjD9V3W4ybbc=",
      "https://updates.cdn-apple.com/2025FallFCS/mobileassets/093-41925/14346E35-5DF1-4DE5-92FD-C449F86FE5F3/com_apple_MobileAsset_SoftwareUpdate/e444bedcb0aee642d91491cf02436f039af7da1e7b3f11bdee0e8826a4e9f935.aea" },

    // 26.0.1
    { "23A355", "iPhone14,7", "D27AP",
      "HbYkSyY/YW6GYu6CvuyqUfzrzCceSWTb7Sg8iPxnRbQ=",
      "https://updates.cdn-apple.com/2025FallFCS/mobileassets/093-44578/1FD74663-8E44-4B89-80DA-A4328A6B6255/com_apple_MobileAsset_SoftwareUpdate/f891234d122a0c2af7495b222e3cb753d3e0880259fe45ba72f5e0608a21c6fe.aea" },
    { "23A355", "iPhone17,1", "D93AP",
      "0oZ3+ZZdLCllJI9/Jwror/5t95EGnw66IZIBp/fWR20=",
      "https://updates.cdn-apple.com/2025FallFCS/mobileassets/093-44475/0CB456A9-11A4-412F-B57E-3454AC9545A9/com_apple_MobileAsset_SoftwareUpdate/c92e8d6dc99b37d2efa8d19ea60b4d3264b043ec739901038b2299d366c741eb.aea" },

    // 26.1
    { "23B85", "iPhone14,7", "D27AP",
      "4fR+wllnofZDWc8GLIIK6kQKbc+bxyUoUESfSVDKtps=",
      "https://updates.cdn-apple.com/2025FallFCS/mobileassets/089-14083/18F4C7B2-CAED-40FC-B5A7-D00A5C0A379A/com_apple_MobileAsset_SoftwareUpdate/e03ec0da93ee761b391f6db023af62a10c6cf6dd4df5d60be7b85d080664f5f9.aea" },
    { "23B85", "iPhone17,1", "D93AP",
      "0beWMht3auVfeo0q8ynwDOdgsWAjR3kYNVPiNU1owVo=",
      "https://updates.cdn-apple.com/2025FallFCS/mobileassets/089-13012/9B7F70F4-4E15-42B9-92EE-68EB565DC766/com_apple_MobileAsset_SoftwareUpdate/fa5752208e0ea297bc65639b843066bc16f15b23304c9aa843d4ee8820e24fca.aea" },

    // 26.2
    { "23C55", "iPhone14,7", "D27AP",
      "VPFp0IMalyEUOJ80yPDVA+ICNPZimBskpCwmILp/iFk=",
      "https://updates.cdn-apple.com/2025FallFCS/mobileassets/089-91082/D1E6A72B-9BE8-4217-AFB0-53CC3FEF218E/com_apple_MobileAsset_SoftwareUpdate/87a21f96e0125cff0a6022d8a94420a3314e721f03fc42808d5e2e3f8103046d.aea" },
    { "23C55", "iPhone17,1", "D93AP",
      "Df+NoKJXGrbYZUgbIiHO+MbiHRGx4MafvD8hfS13Qy0=",
      "https://updates.cdn-apple.com/2025FallFCS/mobileassets/089-91631/CAE6FEDF-CD10-4605-A1C7-A1756BFE0D7D/com_apple_MobileAsset_SoftwareUpdate/6d4e1c96d29c5066d642112fe38db07346e4c346a26f227ea3cea3970cf57cca.aea" },

    // 26.2.1
    { "23C71", "iPhone14,7", "D27AP",
      "rEgtAI3ZF3N0A5K3PY5Yd3EURdHugC+F7Xvmrtnmnp0=",
      "https://updates.cdn-apple.com/2025FallFCS/mobileassets/047-34149/E2E27B48-8206-4C75-BA17-961C2BCBDAA9/com_apple_MobileAsset_SoftwareUpdate/5c183195c2f098958be2d5bc31491cdfd1469b9b75a16e29016703ffd23953ae.aea" },
    { "23C71", "iPhone17,1", "D93AP",
      "S7yzmaoq6WWGMjADIs9yitIZS70bmOgwyv+yIu/2FeM=",
      "https://updates.cdn-apple.com/2025FallFCS/mobileassets/047-34173/461D7EC5-FAB6-40D7-9023-E825FED363E2/com_apple_MobileAsset_SoftwareUpdate/2c0774954f3ce8a9fb4399d01f986f22ae474acbd16d52859b16ec3e98a3b64e.aea" },

    // 26.3
    { "23D127", "iPhone14,7", "D27AP",
      "fBiuK9uU2KmddeJwzqrmeG+/8nqB5MbQRXc1cYCYGLg=",
      "https://updates.cdn-apple.com/2026WinterFCS/mobileassets/047-54425/BFC4299E-FE61-4443-BA18-C3F56C837EB3/com_apple_MobileAsset_SoftwareUpdate/1605c3732f1a1f64cb7ac2e1004c63875d648b7a39cd027d1295727a6d765060.aea" },
    { "23D127", "iPhone17,1", "D93AP",
      "DUO0qpnbf0qs4IUZeHM6kfuW2+/ol5I2OdNtQtySISY=",
      "https://updates.cdn-apple.com/2026WinterFCS/mobileassets/047-60015/7285CC6A-2496-4709-B41D-EA597E9B2CAF/com_apple_MobileAsset_SoftwareUpdate/7370f12de2ed2d5536d59006ab24b8c23c167d1ec68374d809d4b8ae2948cdca.aea" },

    // 26.3.1
    { "23D8133", "iPhone14,7", "D27AP",
      "PgNprOrLOsIrVlNGyWjd1ACl9FjCEFLA65DEF+x5zGY=",
      "https://updates.cdn-apple.com/2026WinterFCS/mobileassets/047-91001/0C221EDA-425F-49C3-A77A-B90B42361E14/com_apple_MobileAsset_SoftwareUpdate/617b068bcc55ff2772ad89023d8bd716a06c19e6c56445f080476aea1ebb29a1.aea" },
    { "23D8133", "iPhone17,1", "D93AP",
      "P1OahXDSqR+X5Lc63VFT9JDZFtR6cHtIc+ryyJ9kuLs=",
      "https://updates.cdn-apple.com/2026WinterFCS/mobileassets/047-91006/A0A6DB3B-FA96-4914-9329-92C319E4C662/com_apple_MobileAsset_SoftwareUpdate/911b7260ab45d8dd465f252d04d815d24f2258f160fd267e3f1b13db01d7963f.aea" },

    // 26.4
    { "23E246", "iPhone14,7", "D27AP",
      "nFX+e/ow8YH96yQioyNcdBUX6LziUd4Tnsg9YD64dbU=",
      "https://updates.cdn-apple.com/2026SpringFCS/mobileassets/122-03456/1F93D35D-1BF0-492C-89A0-45CB12511056/com_apple_MobileAsset_SoftwareUpdate/65aa53ff5a89d14b70a8f5138d755b12817c3d140b8db04e80c4f7970ff7d542.aea" },
    { "23E246", "iPhone17,1", "D93AP",
      "JLreKKk4eeNQGgJpBm+HxtzWw5l6FHqB38hAaZMi1Rw=",
      "https://updates.cdn-apple.com/2026SpringFCS/mobileassets/122-07875/7F554311-F17F-4070-979E-1B33530D1040/com_apple_MobileAsset_SoftwareUpdate/15fe4a1c411d53edbb3d40de8d186a69ce7284794d46ae8785200579e9c31d6d.aea" },

    // 26.4.1
    { "23E254", "iPhone14,7", "D27AP",
      "AvG+DT+Q/7Mu2dkfEujyTPxRSURh8yJt60dVMc+M3Zs=",
      "https://updates.cdn-apple.com/2026SpringFCS/mobileassets/122-28477/C3F3CE4F-C864-496B-90F0-02D7373478C9/com_apple_MobileAsset_SoftwareUpdate/8987e74c5df1e94284eb1200a73756c2678847ecde90041d654c4afcc3fd635c.aea" },
    { "23E254", "iPhone17,1", "D93AP",
      "lgdBR13zUcKNfBgW9B5r3PO9L48e2PDg0gUjRPmAGHs=",
      "https://updates.cdn-apple.com/2026SpringFCS/mobileassets/122-28538/49998DB2-CCE7-4D43-944C-557CD27BC982/com_apple_MobileAsset_SoftwareUpdate/d1373165e56ec4e4fb23868770f73ed2b41acc6f7e586864ba69920797ef0f89.aea" },

    // 26.4.2
    { "23E261", "iPhone14,7", "D27AP",
      "7euXwu0+mMxuR4nvtxpZwMRkSvKog394xCkrhVOQLWw=",
      "https://updates.cdn-apple.com/2026SpringFCS/mobileassets/122-60814/02FF580F-8B76-422C-A88E-DB5033953440/com_apple_MobileAsset_SoftwareUpdate/89aa419355fef19c3e06923d28163d3a7e835bd34e3eee1eef5d0ebbbefcd322.aea" },
    { "23E261", "iPhone17,1", "D93AP",
      "9/cY+jui1eVLupfa/OYmu1RkhVCLMejwagfcyXRPqdI=",
      "https://updates.cdn-apple.com/2026SpringFCS/mobileassets/122-60856/A8CBEC86-158C-4745-ACC3-2B2CABA00AA0/com_apple_MobileAsset_SoftwareUpdate/c4f8725d25ce08029121570c9139474103232f7bb58ec86573af650c31229ae4.aea" },
};

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        NSUInteger total = sizeof(kCases) / sizeof(kCases[0]);

        printf("\n%-10s  %-12s  %-6s  %5s  %10s  %s\n",
               "Build", "Model", "Chunk", "Reqs", "Bytes(MB)", "Result");
        printf("%-10s  %-12s  %-6s  %5s  %10s  %s\n",
               "----------", "------------", "------", "-----", "----------", "------");

        NSUInteger passed = 0;
        for (NSUInteger i = 0; i < total; i++) {
            TestCase *tc = &kCases[i];
            NSString *outPath = [NSTemporaryDirectory()
                                 stringByAppendingPathComponent:
                                 [NSString stringWithFormat:@"kc_aea_%s_%s",
                                  tc->build, tc->model]];

            AEAFFastStats stats = {0};
            BOOL ok = aea_fast_extract_kernelcache(
                [NSString stringWithUTF8String:tc->url],
                [NSString stringWithUTF8String:tc->key],
                outPath,
                [NSString stringWithUTF8String:tc->board],
                0,
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
