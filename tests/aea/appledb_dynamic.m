#import <Foundation/Foundation.h>
#import "grabkernel.h"

// End-to-end public API integration test for AEA OTAs.
//
// Unlike the matrix tests, this harness does not hardcode the OTA URL or AEA
// decryption key. It calls the public grabkernel.h entry point, which must
// resolve AppleDB's FirmwareLink internally and dispatch AEA links to the fast
// path with the AppleDB-supplied decryptionKey.
//
// This exercises the same public boardconfig contract as the legacy IPSW/ZIP
// path: BuildManifest.plist must be resolved and the matching DeviceClass
// identity must select the kernelcache path.

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        NSString *osStr = argc > 1 ? [NSString stringWithUTF8String:argv[1]] : @"iOS";
        NSString *build = argc > 2 ? [NSString stringWithUTF8String:argv[2]] : @"22A3351";
        NSString *model = argc > 3 ? [NSString stringWithUTF8String:argv[3]] : @"iPhone17,1";
        NSString *boardconfig = argc > 4 ? [NSString stringWithUTF8String:argv[4]] : @"D93AP";
        if (!osStr.length || !build.length || !model.length || !boardconfig.length) {
            fprintf(stderr, "usage: %s [osStr build model boardconfig]\n", argv[0]);
            return 2;
        }

        NSString *outPath = [NSTemporaryDirectory()
                             stringByAppendingPathComponent:
                             [NSString stringWithFormat:@"kc_aea_public_%@", build]];
        BOOL ok = grab_kernelcache_for(osStr, build, model, boardconfig, outPath);
        if (!ok) {
            fprintf(stderr, "public grab_kernelcache_for failed for %s %s %s\n",
                    osStr.UTF8String, build.UTF8String, model.UTF8String);
            return 1;
        }

        printf("Public AEA AppleDB PASS: os=%s build=%s model=%s out=%s\n",
               osStr.UTF8String,
               build.UTF8String,
               model.UTF8String,
               outPath.UTF8String);
        return 0;
    }
}
