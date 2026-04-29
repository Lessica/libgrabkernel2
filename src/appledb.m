//
//  appledb.m
//  libgrabkernel2
//
//  Created by Dhinak G on 3/4/24.
//

#import <Foundation/Foundation.h>
#import <sys/utsname.h>
#if !TARGET_OS_OSX
#import <UIKit/UIKit.h>
#endif
#import <sys/sysctl.h>
#import "appledb.h"
#import "appledb_internal.h"
#import "utils.h"

#define BASE_URL @"https://api.appledb.dev/ios/"
#define ALL_VERSIONS BASE_URL @"main.json.xz"

NSArray *hostsNeedingAuth = @[@"adcdownload.apple.com", @"download.developer.apple.com", @"developer.apple.com"];

@implementation FirmwareLink
@end

static inline NSString *apiURLForBuild(NSString *osStr, NSString *build) {
    return [NSString stringWithFormat:@"https://api.appledb.dev/ios/%@;%@.json", osStr, build];
}

static NSData *makeSynchronousRequest(NSString *url, NSError **error) {
    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
    __block NSData *data = nil;
    __block NSError *taskError = nil;
    NSURLSession *session = [NSURLSession sharedSession];

    NSURLSessionDataTask *task = [session dataTaskWithURL:[NSURL URLWithString:url]
                                        completionHandler:^(NSData *taskData, NSURLResponse *response, NSError *error) {
                                            data = taskData;
                                            taskError = error;
                                            dispatch_semaphore_signal(semaphore);
                                        }];
    [task resume];

    dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);

    if (error) {
        *error = taskError;
    }

    return data;
}

static FirmwareLink *bestLinkFromSources(NSArray<NSDictionary<NSString *, id> *> *sources, NSString *modelIdentifier) {
    // Priority buckets: 0 = IPSW, 1 = plain OTA, 2 = AEA OTA (fallback)
    FirmwareLink *candidates[3] = {nil, nil, nil};

    for (NSDictionary<NSString *, id> *source in sources) {
        if (![source[@"deviceMap"] containsObject:modelIdentifier]) {
            DBGLOG("Skipping source that does not include device: %s\n", [source[@"deviceMap"] componentsJoinedByString:@", "].UTF8String);
            continue;
        }

        if (![@[@"ota", @"ipsw"] containsObject:source[@"type"]]) {
            DBGLOG("Skipping source type: %s\n", [source[@"type"] UTF8String]);
            continue;
        }

        BOOL isOTA = [source[@"type"] isEqualToString:@"ota"];

        if (isOTA && source[@"prerequisiteBuild"]) {
            // ignore deltas
            DBGLOG("Skipping OTA source with prerequisite build: %s\n", [source[@"prerequisiteBuild"] UTF8String]);
            continue;
        }

        for (NSDictionary<NSString *, id> *link in source[@"links"]) {
            NSURL *url = [NSURL URLWithString:link[@"url"]];
            if ([hostsNeedingAuth containsObject:url.host]) {
                DBGLOG("Skipping link that needs authentication: %s\n", url.absoluteString.UTF8String);
                continue;
            }

            if (!link[@"active"]) {
                DBGLOG("Skipping inactive link: %s\n", url.absoluteString.UTF8String);
                continue;
            }

            FirmwareLink *fl = [[FirmwareLink alloc] init];
            fl.url = link[@"url"];
            fl.isOTA = isOTA;
            fl.isAEA = [url.pathExtension.lowercaseString isEqualToString:@"aea"];
            id key = link[@"decryptionKey"];
            if ([key isKindOfClass:[NSString class]]) {
                fl.decryptionKey = key;
            }

            int bucket = !isOTA ? 0 : (!fl.isAEA ? 1 : 2);
            if (!candidates[bucket]) {
                DBGLOG("Candidate (priority %d): %s (OTA: %s, AEA: %s, key: %s)\n",
                    bucket,
                    fl.url.UTF8String,
                    fl.isOTA ? "yes" : "no",
                    fl.isAEA ? "yes" : "no",
                    fl.decryptionKey ? "yes" : "no");
                candidates[bucket] = fl;
            }
        }
    }

    for (int i = 0; i < 3; i++) {
        if (candidates[i]) {
            LOG("Found firmware URL: %s (OTA: %s, AEA: %s, key: %s)\n",
                candidates[i].url.UTF8String,
                candidates[i].isOTA ? "yes" : "no",
                candidates[i].isAEA ? "yes" : "no",
                candidates[i].decryptionKey ? "yes" : "no");
            return candidates[i];
        }
    }

    return nil;
}

static FirmwareLink *getFirmwareLinkFromAll(NSString *osStr, NSString *build, NSString *modelIdentifier) {
    NSError *error = nil;
    NSData *compressed = makeSynchronousRequest(ALL_VERSIONS, &error);
    if (error) {
        ERRLOG("Failed to fetch API data: %s\n", error.localizedDescription.UTF8String);
        return nil;
    }

    NSData *decompressed = [compressed decompressedDataUsingAlgorithm:NSDataCompressionAlgorithmLZMA error:&error];
    if (error) {
        ERRLOG("Failed to decompress API data: %s\n", error.localizedDescription.UTF8String);
        return nil;
    }

    NSArray *json = [NSJSONSerialization JSONObjectWithData:decompressed options:0 error:&error];
    if (error) {
        ERRLOG("Failed to parse API data: %s\n", error.localizedDescription.UTF8String);
        return nil;
    }

    for (NSDictionary<NSString *, id> *firmware in json) {
        if ([firmware[@"osStr"] isEqualToString:osStr] && [firmware[@"build"] isEqualToString:build]) {
            FirmwareLink *fl = bestLinkFromSources(firmware[@"sources"], modelIdentifier);
            if (!fl) {
                DBGLOG("No suitable links found for firmware: %s\n", [firmware[@"key"] UTF8String]);
            } else {
                return fl;
            }
        }
    }

    return nil;
}

static FirmwareLink *getFirmwareLinkFromDirect(NSString *osStr, NSString *build, NSString *modelIdentifier) {
    NSString *apiURL = apiURLForBuild(osStr, build);
    if (!apiURL) {
        ERRLOG("Failed to get API URL!\n");
        return nil;
    }

    NSError *error = nil;
    NSData *data = makeSynchronousRequest(apiURL, &error);
    if (error) {
        ERRLOG("Failed to fetch API data: %s\n", error.localizedDescription.UTF8String);
        return nil;
    }

    NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
    if (error) {
        ERRLOG("Failed to parse API data: %s\n", error.localizedDescription.UTF8String);
        return nil;
    }

    return bestLinkFromSources(json[@"sources"], modelIdentifier);
}

FirmwareLink *getFirmwareLinkFor(NSString *osStr, NSString *build, NSString *modelIdentifier) {
    FirmwareLink *fl = getFirmwareLinkFromDirect(osStr, build, modelIdentifier);
    if (!fl) {
        DBGLOG("Failed to get firmware URL from direct API, checking all versions...\n");
        fl = getFirmwareLinkFromAll(osStr, build, modelIdentifier);
    }

    if (!fl) {
        ERRLOG("Failed to find a firmware URL!\n");
        return nil;
    }

    return fl;
}

FirmwareLink *getFirmwareLink(void) {
    NSString *osStr = getOsStr();
    NSString *build = getBuild();
    NSString *modelIdentifier = getModelIdentifier();

    if (!osStr || !build || !modelIdentifier) {
        return nil;
    }

    return getFirmwareLinkFor(osStr, build, modelIdentifier);
}

// Legacy shims preserved for ABI compatibility.
NSString *getFirmwareURLFor(NSString *osStr, NSString *build, NSString *modelIdentifier, bool *isOTA) {
    FirmwareLink *fl = getFirmwareLinkFor(osStr, build, modelIdentifier);
    if (!fl) {
        return nil;
    }
    if (isOTA) {
        *isOTA = fl.isOTA;
    }
    return fl.url;
}

NSString *getFirmwareURL(bool *isOTA) {
    FirmwareLink *fl = getFirmwareLink();
    if (!fl) {
        return nil;
    }
    if (isOTA) {
        *isOTA = fl.isOTA;
    }
    return fl.url;
}