#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#include <errno.h>
#include <fcntl.h>
#include <mach/mach_time.h>
#include <objc/runtime.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#define IPC_DIRECTORY "/var/mobile/Library/IPADDecrypt"
#define IPC_SOCKET_PATH IPC_DIRECTORY "/companion.sock"
#define MAX_MESSAGE 512
#define MIN_LEASE_TTL 15
#define MAX_LEASE_TTL 300
#define CLIENT_IO_TIMEOUT_SECONDS 10
#define MAX_CONCURRENT_CLIENTS 8

static NSString *const IdleReason = @"me.sixfalls.ipadecrypt";

@interface UIApplication (IPADDecryptPrivate)
- (void)_setIdleTimerDisabled:(BOOL)disabled forReason:(NSString *)reason;
- (void)resetIdleTimerAndUndim;
@end

@interface SBLockScreenManager : NSObject
+ (instancetype)sharedInstance;
- (BOOL)isUILocked;
- (BOOL)attemptUnlockWithPasscode:(NSString *)passcode;
@end

static NSMutableDictionary<NSString *, NSNumber *> *leases;
static dispatch_source_t leaseTimer;
static dispatch_semaphore_t clientSlots;
static dispatch_semaphore_t unlockSlot;
static BOOL ownsIdleOverride;
static BOOL priorIdleDisabled;
static BOOL usesReasonedIdleOverride;

static NSTimeInterval continuousTime(void) {
    static mach_timebase_info_data_t timebase;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        (void)mach_timebase_info(&timebase);
    });
    return ((NSTimeInterval)mach_continuous_time() * timebase.numer /
            timebase.denom) / NSEC_PER_SEC;
}

static void runOnMainSync(dispatch_block_t block) {
    if ([NSThread isMainThread]) block();
    else dispatch_sync(dispatch_get_main_queue(), block);
}

static NSInteger lockState(void) {
    __block NSInteger state = -1;
    runOnMainSync(^{
        Class cls = objc_getClass("SBLockScreenManager");
        id manager = cls ? [cls sharedInstance] : nil;
        if (manager && [manager respondsToSelector:@selector(isUILocked)]) {
            state = [manager isUILocked] ? 1 : 0;
        }
    });
    return state;
}

static void stopLeaseTimer(void) {
    if (leaseTimer) {
        dispatch_source_cancel(leaseTimer);
        leaseTimer = nil;
    }
}

static void restoreIdleTimerIfUnleased(void) {
    NSCAssert([NSThread isMainThread], @"idle state must be changed on main");
    if (leases.count != 0 || !ownsIdleOverride) return;

    UIApplication *application = [UIApplication sharedApplication];
    if (usesReasonedIdleOverride) {
        [application _setIdleTimerDisabled:NO forReason:IdleReason];
    } else {
        application.idleTimerDisabled = priorIdleDisabled;
    }

    ownsIdleOverride = NO;
    usesReasonedIdleOverride = NO;
    stopLeaseTimer();
}

static void expireLeases(void) {
    NSCAssert([NSThread isMainThread], @"lease expiry must run on main");
    NSTimeInterval now = continuousTime();
    NSArray<NSString *> *tokens = [leases allKeys];
    for (NSString *token in tokens) {
        if (leases[token].doubleValue <= now) {
            [leases removeObjectForKey:token];
        }
    }
    restoreIdleTimerIfUnleased();
}

static void ensureLeaseTimer(void) {
    NSCAssert([NSThread isMainThread], @"lease timer must run on main");
    if (leaseTimer) return;
    leaseTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
                                        dispatch_get_main_queue());
    dispatch_source_set_timer(leaseTimer,
                              dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC),
                              NSEC_PER_SEC, NSEC_PER_SEC / 10);
    dispatch_source_set_event_handler(leaseTimer, ^{ expireLeases(); });
    dispatch_resume(leaseTimer);
}

static NSString *acquireIdleLease(NSTimeInterval ttl) {
    __block NSString *token = nil;
    runOnMainSync(^{
        expireLeases();
        UIApplication *application = [UIApplication sharedApplication];

        if (leases.count == 0) {
            priorIdleDisabled = application.idleTimerDisabled;
            usesReasonedIdleOverride =
                [application respondsToSelector:@selector(_setIdleTimerDisabled:forReason:)];
            if (usesReasonedIdleOverride) {
                [application _setIdleTimerDisabled:YES forReason:IdleReason];
            } else if (!priorIdleDisabled) {
                application.idleTimerDisabled = YES;
            }
            ownsIdleOverride = YES;
        }

        if (!application.idleTimerDisabled) {
            leases = leases ?: [NSMutableDictionary dictionary];
            [leases removeAllObjects];
            restoreIdleTimerIfUnleased();
            return;
        }

        token = [[NSUUID UUID].UUIDString lowercaseString];
        leases[token] = @(continuousTime() + ttl);
        ensureLeaseTimer();
    });
    return token;
}

static BOOL renewIdleLease(NSString *token, NSTimeInterval ttl) {
    __block BOOL renewed = NO;
    runOnMainSync(^{
        expireLeases();
        if (leases[token]) {
            leases[token] = @(continuousTime() + ttl);
            renewed = YES;
        }
    });
    return renewed;
}

static BOOL releaseIdleLease(NSString *token) {
    __block BOOL released = NO;
    runOnMainSync(^{
        expireLeases();
        if (leases[token]) {
            [leases removeObjectForKey:token];
            released = YES;
        }
        restoreIdleTimerIfUnleased();
    });
    return released;
}

static BOOL validPIN(NSString *pin) {
    if (pin.length < 4 || pin.length > 16) return NO;
    for (NSUInteger index = 0; index < pin.length; index++) {
        unichar character = [pin characterAtIndex:index];
        if (character < '0' || character > '9') return NO;
    }
    return YES;
}

static NSString *unlockDeviceExclusive(NSString *pin) {
    NSInteger initial = lockState();
    if (initial < 0) return @"ERR\tunsupported\n";
    if (initial == 0) return @"OK\talready-unlocked\n";

    __block BOOL attempted = NO;
    runOnMainSync(^{
        UIApplication *application = [UIApplication sharedApplication];
        if ([application respondsToSelector:@selector(resetIdleTimerAndUndim)]) {
            [application resetIdleTimerAndUndim];
        }
    });

    // Give SpringBoard a moment to finish its undim/wake transition before
    // making the one and only passcode attempt. Sleeping here is safe because
    // each socket request is handled on a worker queue.
    usleep(300 * 1000);

    runOnMainSync(^{
        Class cls = objc_getClass("SBLockScreenManager");
        id manager = cls ? [cls sharedInstance] : nil;
        if (manager && [manager respondsToSelector:@selector(attemptUnlockWithPasscode:)]) {
            attempted = YES;
            (void)[manager attemptUnlockWithPasscode:pin];
        }
    });
    if (!attempted) return @"ERR\tunsupported\n";

    for (NSUInteger attempt = 0; attempt < 50; attempt++) {
        if (lockState() == 0) return @"OK\tunlocked\n";
        usleep(100 * 1000);
    }
    return @"ERR\trejected-or-timeout\n";
}

static NSString *unlockDevice(NSString *pin) {
    if (dispatch_semaphore_wait(unlockSlot, DISPATCH_TIME_NOW) != 0) {
        return @"ERR\tunlock-in-progress\n";
    }

    NSString *response;
    @try {
        response = unlockDeviceExclusive(pin);
    } @finally {
        dispatch_semaphore_signal(unlockSlot);
    }
    return response;
}

static NSTimeInterval leaseTTL(NSString *value) {
    NSInteger ttl = value.integerValue;
    if (ttl < MIN_LEASE_TTL || ttl > MAX_LEASE_TTL) return 0;
    return (NSTimeInterval)ttl;
}

static NSString *handleRequest(NSString *request) {
    NSString *line = [request stringByTrimmingCharactersInSet:
                      [NSCharacterSet newlineCharacterSet]];
    NSArray<NSString *> *parts = [line componentsSeparatedByString:@"\t"];
    NSString *command = parts.firstObject;

    if ([command isEqualToString:@"status"] && parts.count == 1) {
        NSInteger state = lockState();
        if (state < 0) return @"ERR\tunsupported\n";
        return state ? @"OK\tlocked\n" : @"OK\tunlocked\n";
    }
    if ([command isEqualToString:@"unlock"] && parts.count == 2) {
        if (!validPIN(parts[1])) return @"ERR\tinvalid-pin\n";
        return unlockDevice(parts[1]);
    }
    if ([command isEqualToString:@"idle-acquire"] && parts.count == 2) {
        NSTimeInterval ttl = leaseTTL(parts[1]);
        if (ttl == 0) return @"ERR\tinvalid-ttl\n";
        NSString *token = acquireIdleLease(ttl);
        return token ? [NSString stringWithFormat:@"OK\t%@\n", token]
                     : @"ERR\tidle-timer-not-disabled\n";
    }
    if ([command isEqualToString:@"idle-renew"] && parts.count == 3) {
        NSTimeInterval ttl = leaseTTL(parts[2]);
        if (ttl == 0) return @"ERR\tinvalid-ttl\n";
        return renewIdleLease(parts[1], ttl) ? @"OK\trenewed\n"
                                             : @"ERR\tunknown-lease\n";
    }
    if ([command isEqualToString:@"idle-release"] && parts.count == 2) {
        return releaseIdleLease(parts[1]) ? @"OK\treleased\n"
                                          : @"ERR\tunknown-lease\n";
    }
    return @"ERR\tinvalid-request\n";
}

static void writeAll(int fd, NSData *data) {
    const uint8_t *bytes = (const uint8_t *)data.bytes;
    size_t remaining = data.length;
    while (remaining > 0) {
        ssize_t written = write(fd, bytes, remaining);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) return;
        bytes += written;
        remaining -= (size_t)written;
    }
}

static void serveClient(int fd) {
    @autoreleasepool {
        char buffer[MAX_MESSAGE] = {0};
        size_t used = 0;
        while (used + 1 < sizeof(buffer)) {
            ssize_t length = read(fd, buffer + used, sizeof(buffer) - used - 1);
            if (length < 0 && errno == EINTR) continue;
            if (length <= 0) break;
            used += (size_t)length;
            if (memchr(buffer, '\n', used)) break;
        }

        NSString *response = @"ERR\tinvalid-request\n";
        if (used > 0) {
            NSString *request = [[NSString alloc] initWithBytes:buffer
                                                         length:used
                                                       encoding:NSUTF8StringEncoding];
            if (request) response = handleRequest(request);
        }
        writeAll(fd, [response dataUsingEncoding:NSUTF8StringEncoding]);
        close(fd);
    }
}

static void startServer(void) {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        mkdir(IPC_DIRECTORY, 0700);
        unlink(IPC_SOCKET_PATH);

        int server = socket(AF_UNIX, SOCK_STREAM, 0);
        if (server < 0) return;
        fcntl(server, F_SETFD, FD_CLOEXEC);

        struct sockaddr_un address;
        memset(&address, 0, sizeof(address));
        address.sun_family = AF_UNIX;
        strlcpy(address.sun_path, IPC_SOCKET_PATH, sizeof(address.sun_path));

        if (bind(server, (struct sockaddr *)&address, sizeof(address)) != 0 ||
            chmod(IPC_SOCKET_PATH, 0600) != 0 || listen(server, 4) != 0) {
            close(server);
            unlink(IPC_SOCKET_PATH);
            return;
        }

        for (;;) {
            int client;
            do {
                client = accept(server, NULL, NULL);
            } while (client < 0 && errno == EINTR);
            if (client < 0) {
                if (errno == EBADF || errno == EINVAL) break;
                usleep(100 * 1000);
                continue;
            }
            fcntl(client, F_SETFD, FD_CLOEXEC);
            int noSigPipe = 1;
            struct timeval timeout = {
                .tv_sec = CLIENT_IO_TIMEOUT_SECONDS,
                .tv_usec = 0,
            };
            if (setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE,
                           &noSigPipe, sizeof(noSigPipe)) != 0 ||
                setsockopt(client, SOL_SOCKET, SO_RCVTIMEO,
                           &timeout, sizeof(timeout)) != 0 ||
                setsockopt(client, SOL_SOCKET, SO_SNDTIMEO,
                           &timeout, sizeof(timeout)) != 0) {
                close(client);
                continue;
            }
            dispatch_semaphore_wait(clientSlots, DISPATCH_TIME_FOREVER);
            dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
                serveClient(client);
                dispatch_semaphore_signal(clientSlots);
            });
        }
    });
}

%ctor {
    @autoreleasepool {
        leases = [NSMutableDictionary dictionary];
        clientSlots = dispatch_semaphore_create(MAX_CONCURRENT_CLIENTS);
        unlockSlot = dispatch_semaphore_create(1);
        startServer();
    }
}
