//
//  aea_range.m
//  libgrabkernel2
//
//  Synchronous HTTP-Range opener built on NSURLSession. Provides up to 3
//  attempts on transient errors and tracks request/byte counters for
//  diagnostics.
//

#import <Foundation/Foundation.h>
#import "aea_internal.h"
#import "utils.h"

#define AEAF_MAX_ATTEMPTS 3

@implementation AEAFRangeOpener {
    NSString *_url;
    NSURLSession *_session;
}

- (instancetype)initWithURL:(NSString *)url {
    if ((self = [super init])) {
        _url = [url copy];
        NSURLSessionConfiguration *cfg = [NSURLSessionConfiguration defaultSessionConfiguration];
        cfg.timeoutIntervalForRequest = 30;
        cfg.timeoutIntervalForResource = 300;
        cfg.HTTPMaximumConnectionsPerHost = 4;
        _session = [NSURLSession sessionWithConfiguration:cfg];
    }
    return self;
}

- (void)dealloc {
    [_session finishTasksAndInvalidate];
}

- (NSData *)readRangeAtOffset:(int64_t)offset
                       length:(int64_t)length
                        error:(NSError **)outError {
    if (offset < 0) {
        if (outError) *outError = AEAFMakeError(AEAFErrorBadArguments, @"negative offset %lld", offset);
        return nil;
    }
    NSURL *u = [NSURL URLWithString:_url];
    if (!u) {
        if (outError) *outError = AEAFMakeError(AEAFErrorBadArguments, @"bad URL: %@", _url);
        return nil;
    }

    NSError *lastErr = nil;
    for (int attempt = 1; attempt <= AEAF_MAX_ATTEMPTS; attempt++) {
        NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:u];
        req.HTTPMethod = @"GET";
        if (length > 0) {
            [req setValue:[NSString stringWithFormat:@"bytes=%lld-%lld", offset, offset + length - 1]
       forHTTPHeaderField:@"Range"];
        } else {
            [req setValue:[NSString stringWithFormat:@"bytes=%lld-", offset]
       forHTTPHeaderField:@"Range"];
        }

        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        __block NSData *body = nil;
        __block NSURLResponse *resp = nil;
        __block NSError *err = nil;
        NSURLSessionDataTask *task = [_session dataTaskWithRequest:req
                                                 completionHandler:^(NSData *_Nullable d, NSURLResponse *_Nullable r, NSError *_Nullable e) {
            body = d;
            resp = r;
            err = e;
            dispatch_semaphore_signal(sem);
        }];
        [task resume];
        dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);

        if (err) {
            lastErr = err;
            DBGLOG("Range attempt %d failed: %s\n", attempt, err.localizedDescription.UTF8String);
            continue;
        }
        NSHTTPURLResponse *http = (NSHTTPURLResponse *)resp;
        if (![http isKindOfClass:[NSHTTPURLResponse class]]) {
            lastErr = AEAFMakeError(AEAFErrorHTTP, @"non-HTTP response");
            continue;
        }
        if (http.statusCode != 200 && http.statusCode != 206) {
            lastErr = AEAFMakeError(AEAFErrorHTTP, @"unexpected status %ld for offset=%lld length=%lld",
                                    (long)http.statusCode, offset, length);
            DBGLOG("Range HTTP %ld at offset=%lld length=%lld\n", (long)http.statusCode, offset, length);
            continue;
        }
        _requestCount++;
        _bytesTransferred += (int64_t)body.length;
        DBGLOG("Range #%ld: offset=%lld length=%lld got=%zu\n",
               (long)_requestCount, offset, length, (size_t)body.length);
        return body;
    }
    if (outError) *outError = lastErr ?: AEAFMakeError(AEAFErrorHTTP, @"range request failed");
    return nil;
}

@end
