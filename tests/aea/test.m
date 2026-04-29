#import <Foundation/Foundation.h>
#import "grabkernel.h"

// Live AEA fast-path test: pulls the kernelcache out of an iOS 18+ AEA OTA
// using HTTP-Range + AppleDB-supplied decryption key.
int main(int argc, const char *argv[]) {
    @autoreleasepool {
        NSString *osStr = @"iOS";
        NSString *build = @"22A3351";
        NSString *model = @"iPhone17,1";
        NSString *board = @"D93AP";
        if (argc >= 5) {
            osStr = [NSString stringWithUTF8String:argv[1]];
            build = [NSString stringWithUTF8String:argv[2]];
            model = [NSString stringWithUTF8String:argv[3]];
            board = [NSString stringWithUTF8String:argv[4]];
        }
        NSString *out = [NSTemporaryDirectory() stringByAppendingPathComponent:@"kc_aea"];
        NSLog(@"AEA fast test: os=%@ build=%@ model=%@ board=%@ -> %@",
              osStr, build, model, board, out);
        bool ok = grab_kernelcache_for(osStr, build, model, board, out);
        NSLog(@"AEA fast test: %@", ok ? @"PASS" : @"FAIL");
        return ok ? 0 : 1;
    }
}
