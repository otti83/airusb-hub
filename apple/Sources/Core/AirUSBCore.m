#import "AirUSBCore.h"

#import <DiskArbitration/DiskArbitration.h>
#import <IOKit/IOKitLib.h>
#import <IOKit/usb/IOUSBHostFamilyDefinitions.h>
#import <IOUSBHost/IOUSBHostControllerInterface.h>
#import <IOUSBHost/IOUSBHostDefinitions.h>
#import <IOKit/IOReturn.h>

#include <sys/mount.h>
#include <sys/param.h>

#pragma mark - small IORegistry helpers

static NSNumber *propNum(io_service_t s, CFStringRef key)
{
    CFTypeRef v = IORegistryEntryCreateCFProperty(s, key, kCFAllocatorDefault, 0);
    if (!v) return nil;
    if (CFGetTypeID(v) != CFNumberGetTypeID()) { CFRelease(v); return nil; }
    return (__bridge_transfer NSNumber *)v;
}

static NSString *propStr(io_service_t s, CFStringRef key)
{
    CFTypeRef v = IORegistryEntryCreateCFProperty(s, key, kCFAllocatorDefault, 0);
    if (!v) return nil;
    if (CFGetTypeID(v) != CFStringGetTypeID()) { CFRelease(v); return nil; }
    return (__bridge_transfer NSString *)v;
}

static void collectBsdNames(io_service_t node, NSMutableArray<NSString *> *out)
{
    NSString *bsd = propStr(node, CFSTR("BSD Name"));
    if (bsd && ![out containsObject:bsd]) [out addObject:bsd];

    io_iterator_t it = IO_OBJECT_NULL;
    if (IORegistryEntryGetChildIterator(node, kIOServicePlane, &it) != KERN_SUCCESS) return;
    io_service_t child;
    while ((child = IOIteratorNext(it))) {
        collectBsdNames(child, out);
        IOObjectRelease(child);
    }
    IOObjectRelease(it);
}

/// Mount points currently backed by any of `bsdNames`, read from the kernel's
/// own mount table rather than from a guess about where volumes appear.
static NSArray<NSString *> *mountPointsFor(NSArray<NSString *> *bsdNames)
{
    NSMutableArray<NSString *> *out = [NSMutableArray array];
    if (bsdNames.count == 0) return out;

    struct statfs *mnts = NULL;
    const int n = getmntinfo(&mnts, MNT_NOWAIT);
    for (int i = 0; i < n; ++i) {
        NSString *from = @(mnts[i].f_mntfromname);      // e.g. /dev/disk4s1
        for (NSString *bsd in bsdNames) {
            if ([from isEqualToString:[@"/dev/" stringByAppendingString:bsd]]) {
                [out addObject:@(mnts[i].f_mntonname)];
                break;
            }
        }
    }
    return out;
}

static BOOL looksLikeBootDisk(NSArray<NSString *> *bsdNames)
{
    // disk0 is the internal boot media on every Mac this targets. Checked by
    // name as well as by the mount table, because a device with no mounted
    // volume can still be the boot disk mid-unmount.
    for (NSString *b in bsdNames) {
        if ([b isEqualToString:@"disk0"] || [b hasPrefix:@"disk0s"]) return YES;
    }
    struct statfs root;
    if (statfs("/", &root) == 0) {
        NSString *rootDev = @(root.f_mntfromname);
        for (NSString *b in bsdNames) {
            if ([rootDev hasPrefix:[@"/dev/" stringByAppendingString:b]]) return YES;
        }
    }
    return NO;
}

#pragma mark - AirUSBDeviceInfo

@implementation AirUSBDeviceInfo

- (BOOL)hasStorage { return self.bsdNames.count > 0; }

- (NSString *)identifierText
{
    return [NSString stringWithFormat:@"%04x:%04x", self.vendorId, self.productId];
}

- (NSString *)stableId
{
    // locationID is unique per physical port and survives a refresh, which
    // VID:PID does not when two identical sticks are plugged in.
    return [NSString stringWithFormat:@"%08x-%04x-%04x",
            self.locationId, self.vendorId, self.productId];
}

@end

#pragma mark - AirUSBDeviceWatcher

@implementation AirUSBDeviceWatcher {
    IONotificationPortRef _port;
    io_iterator_t _addedIter;
    io_iterator_t _removedIter;
}

static void deviceEvent(void *refcon, io_iterator_t iterator)
{
    // Drain the iterator or the notification never fires again.
    io_service_t s;
    while ((s = IOIteratorNext(iterator))) IOObjectRelease(s);

    AirUSBDeviceWatcher *self_ = (__bridge AirUSBDeviceWatcher *)refcon;
    dispatch_async(dispatch_get_main_queue(), ^{
        if (self_.onChange) self_.onChange();
    });
}

- (void)start
{
    if (_port) return;

    _port = IONotificationPortCreate(kIOMainPortDefault);
    IONotificationPortSetDispatchQueue(_port, dispatch_get_main_queue());

    // Two matching dictionaries: IOServiceAddMatchingNotification consumes a
    // reference to the one it is given, so they cannot be shared.
    IOServiceAddMatchingNotification(_port, kIOMatchedNotification,
                                     IOServiceMatching(kIOUSBHostDeviceClassName),
                                     deviceEvent, (__bridge void *)self, &_addedIter);
    IOServiceAddMatchingNotification(_port, kIOTerminatedNotification,
                                     IOServiceMatching(kIOUSBHostDeviceClassName),
                                     deviceEvent, (__bridge void *)self, &_removedIter);

    // Arm both by draining the initial contents.
    deviceEvent((__bridge void *)self, _addedIter);
    deviceEvent((__bridge void *)self, _removedIter);
}

- (void)stop
{
    if (_addedIter)   { IOObjectRelease(_addedIter);   _addedIter = 0; }
    if (_removedIter) { IOObjectRelease(_removedIter); _removedIter = 0; }
    if (_port)        { IONotificationPortDestroy(_port); _port = NULL; }
}

- (void)dealloc { [self stop]; }

- (NSArray<AirUSBDeviceInfo *> *)currentDevices
{
    NSMutableArray<AirUSBDeviceInfo *> *out = [NSMutableArray array];

    io_iterator_t it = IO_OBJECT_NULL;
    if (IOServiceGetMatchingServices(kIOMainPortDefault,
                                     IOServiceMatching(kIOUSBHostDeviceClassName),
                                     &it) != KERN_SUCCESS) return out;

    static NSString *const kSpeedNames[] = {
        @"—", @"Full (12 Mb/s)", @"Low (1.5 Mb/s)", @"High (480 Mb/s)",
        @"SuperSpeed (5 Gb/s)", @"SuperSpeed+ (10 Gb/s)", @"SuperSpeed+ (20 Gb/s)", @"other"
    };

    io_service_t dev;
    while ((dev = IOIteratorNext(it))) {
        AirUSBDeviceInfo *d = [AirUSBDeviceInfo new];
        d.productName = propStr(dev, CFSTR("USB Product Name")) ?: @"Unknown device";
        d.vendorName  = propStr(dev, CFSTR("USB Vendor Name")) ?: @"";
        d.vendorId    = (uint16_t)propNum(dev, CFSTR("idVendor")).unsignedIntValue;
        d.productId   = (uint16_t)propNum(dev, CFSTR("idProduct")).unsignedIntValue;
        d.locationId  = (uint32_t)propNum(dev, CFSTR("locationID")).unsignedIntValue;

        NSNumber *speed = propNum(dev, CFSTR("USBSpeed"));
        NSNumber *link  = propNum(dev, CFSTR("UsbLinkSpeed"));
        const NSUInteger raw = speed ? speed.unsignedIntegerValue : 0;
        d.speedText = raw < (sizeof kSpeedNames / sizeof kSpeedNames[0])
                        ? kSpeedNames[raw] : @"unknown";
        d.linkSpeedBitsPerSecond = link ? link.doubleValue : 0;

        // Surface a disagreement rather than silently trusting one property.
        const BOOL superish = (raw >= kIOUSBHostConnectionSpeedSuper);
        d.speedPropertiesDisagree =
            link && ((superish && link.doubleValue < 4.0e9) ||
                     (!superish && link.doubleValue >= 4.0e9));

        NSMutableArray<NSString *> *bsd = [NSMutableArray array];
        collectBsdNames(dev, bsd);
        d.bsdNames    = bsd;
        d.mountPoints = mountPointsFor(bsd);
        d.isBootDisk  = looksLikeBootDisk(bsd);

        [out addObject:d];
        IOObjectRelease(dev);
    }
    IOObjectRelease(it);

    [out sortUsingComparator:^NSComparisonResult(AirUSBDeviceInfo *a, AirUSBDeviceInfo *b) {
        return [a.productName localizedCaseInsensitiveCompare:b.productName];
    }];
    return out;
}

@end

#pragma mark - AirUSBEntitlementProbe

@implementation AirUSBEntitlementReport
@end

// Apple's example capabilities from IOUSBHostControllerInterface.h, verbatim, so
// a failure is attributable to authorisation rather than to a malformed payload
// (which would raise IOUSBHostCIExceptionTypeCapabilitiesInvalid and look like a
// completely different problem).
static const IOUSBHostCIMessage kControllerCapabilities = {
    .control = (IOUSBHostCIMessageTypeControllerCapabilities << IOUSBHostCIMessageControlTypePhase)
             | IOUSBHostCIMessageControlNoResponse
             | IOUSBHostCIMessageControlValid
             | (1 << IOUSBHostCICapabilitiesMessageControlPortCountPhase),
    .data0   = (1 << IOUSBHostCICapabilitiesMessageData0CommandTimeoutThresholdPhase)
             | (2 << IOUSBHostCICapabilitiesMessageData0ConnectionLatencyPhase),
    .data1   = 0
};

static const IOUSBHostCIMessage kPortCapabilities = {
    .control = (IOUSBHostCIMessageTypePortCapabilities << IOUSBHostCIMessageControlTypePhase)
             | IOUSBHostCIMessageControlNoResponse
             | IOUSBHostCIMessageControlValid
             | (1 << IOUSBHostCIPortCapabilitiesMessageControlPortNumberPhase)
             | (0 << IOUSBHostCIPortCapabilitiesMessageControlConnectorTypePhase),
    .data0   = ((907 / 8) << IOUSBHostCIPortCapabilitiesMessageData0MaxPowerPhase),
    .data1   = 0
};

@implementation AirUSBEntitlementProbe

+ (AirUSBEntitlementReport *)run
{
    AirUSBEntitlementReport *r = [AirUSBEntitlementReport new];

    // The profile lives at Contents/embedded.provisionprofile, NOT in Resources —
    // -pathForResource: would report ABSENT for a bundle that has one.
    NSString *profilePath = [NSBundle.mainBundle.bundlePath
        stringByAppendingPathComponent:@"Contents/embedded.provisionprofile"];
    NSData *profile = [NSData dataWithContentsOfFile:profilePath];
    r.profilePresent = profile != nil;
    if (profile) {
        NSData *needle = [@"com.apple.developer.usb.host-controller-interface"
                             dataUsingEncoding:NSUTF8StringEncoding];
        r.profileAuthorisesEntitlement =
            [profile rangeOfData:needle options:0
                           range:NSMakeRange(0, profile.length)].location != NSNotFound;
    }

    NSMutableData *caps = [NSMutableData dataWithBytes:&kControllerCapabilities
                                                length:sizeof(IOUSBHostCIMessage)];
    [caps appendBytes:&kPortCapabilities length:sizeof(IOUSBHostCIMessage)];

    NSError *err = nil;
    IOUSBHostControllerInterface *controller = nil;

    // Wrapped for the reason every IOUSBHost call in this project is: Apple's
    // error path can raise NSInvalidArgumentException instead of returning an
    // NSError. Measured twice — on openWithOptions: and on descriptorWithType:.
    @try {
        controller = [[IOUSBHostControllerInterface alloc]
                         initWithCapabilities:caps
                                        queue:nil
                              interruptRateHz:1000
                                        error:&err
                               commandHandler:^(IOUSBHostControllerInterface *ci,
                                                IOUSBHostCIMessage command) {
                                   (void)ci; (void)command;
                               }
                              doorbellHandler:^(IOUSBHostControllerInterface *ci,
                                                IOUSBHostCIDoorbell *doorbells,
                                                uint32_t count) {
                                   (void)ci; (void)doorbells; (void)count;
                               }
                              interestHandler:nil];
    } @catch (NSException *ex) {
        r.state   = AirUSBEntitlementStateThrew;
        r.summary = @"The system raised an exception";
        r.detail  = [NSString stringWithFormat:@"%@: %@", ex.name, ex.reason];
        return r;
    }

    if (controller) {
        [controller destroy];
        r.state    = AirUSBEntitlementStateGranted;
        r.ioReturn = 0;
        r.summary  = @"Ready to receive devices";
        r.detail   = @"A virtual USB controller was created successfully. This Mac "
                      "can import devices shared by another machine.";
        return r;
    }

    r.state    = AirUSBEntitlementStateRefused;
    r.ioReturn = (unsigned)(err ? err.code : 0);
    r.summary  = @"Cannot receive devices yet";

    if (r.ioReturn == (unsigned)kIOReturnNotOpen) {
        r.detail = @"macOS refused to create a virtual USB controller "
                    "(0xE00002CD kIOReturnNotOpen).\n\nThis is expected: Apple has "
                    "not yet granted this build the entitlement that allows it. "
                    "Sharing devices FROM this Mac is unaffected and works today.";
    } else {
        r.detail = [NSString stringWithFormat:
            @"macOS refused to create a virtual USB controller (0x%08X).\n\n"
             "Sharing devices FROM this Mac is unaffected.", r.ioReturn];
    }
    return r;
}

@end

#pragma mark - AirUSBEjector

/// DiskArbitration takes a C function pointer, not a block, so the completion
/// and the outstanding count live in a context object that is handed across as
/// `void *`. It is retained for the duration and released when the last callback
/// lands — that is what keeps the DASession alive long enough to deliver them.
@interface AirUSBEjectContext : NSObject
@property(nonatomic, copy)   void (^completion)(NSError *_Nullable);
@property(nonatomic, assign) NSInteger pending;
@property(nonatomic, strong, nullable) NSError *firstError;
@property(nonatomic, assign) DASessionRef session;
@property(nonatomic, strong) dispatch_queue_t queue;
@end

@implementation AirUSBEjectContext
@end

static void ejectFinishOne(AirUSBEjectContext *ctx, NSError *_Nullable e)
{
    if (e && !ctx.firstError) ctx.firstError = e;
    if (--ctx.pending > 0) return;

    DASessionSetDispatchQueue(ctx.session, NULL);
    CFRelease(ctx.session);
    ctx.session = NULL;

    NSError *err = ctx.firstError;
    void (^done)(NSError *) = ctx.completion;
    dispatch_async(dispatch_get_main_queue(), ^{ done(err); });

    // Balances the CFBridgingRetain taken before the first DADiskUnmount.
    CFRelease((__bridge CFTypeRef)ctx);
}

static void ejectUnmountCallback(DADiskRef disk, DADissenterRef dissenter, void *context)
{
    AirUSBEjectContext *ctx = (__bridge AirUSBEjectContext *)context;
    const char *bsd = DADiskGetBSDName(disk);

    if (!dissenter) {
        ejectFinishOne(ctx, nil);
        return;
    }

    // DiskArbitration names the process holding the volume when it can, which is
    // the only part of this a user can actually act on.
    CFStringRef reason = DADissenterGetStatusString(dissenter);
    NSString *why = reason ? (__bridge NSString *)reason
                           : @"Something is still using it.";
    ejectFinishOne(ctx, [NSError errorWithDomain:@"AirUSB"
                                            code:(NSInteger)DADissenterGetStatus(dissenter)
                                        userInfo:@{
        NSLocalizedDescriptionKey:
            [NSString stringWithFormat:@"\u201c%s\u201d is in use.", bsd ?: "?"],
        NSLocalizedRecoverySuggestionErrorKey: why
    }]);
}

@implementation AirUSBEjector

+ (void)ejectDevice:(AirUSBDeviceInfo *)device
         completion:(void (^)(NSError *_Nullable))completion
{
    if (device.mountPoints.count == 0) { completion(nil); return; }

    if (device.isBootDisk) {
        completion([NSError errorWithDomain:@"AirUSB" code:1 userInfo:@{
            NSLocalizedDescriptionKey: @"That is the startup disk.",
            NSLocalizedRecoverySuggestionErrorKey:
                @"AirUSB Hub will not unmount the disk macOS is running from."
        }]);
        return;
    }

    // Whole disks only. kDADiskUnmountOptionWhole takes the slices with it, and
    // unmounting slices individually races the whole-disk unmount.
    NSMutableArray<NSString *> *wholeDisks = [NSMutableArray array];
    for (NSString *b in device.bsdNames) {
        if (b.length <= 4 || ![b hasPrefix:@"disk"]) continue;
        if ([b rangeOfString:@"s" options:0 range:NSMakeRange(4, b.length - 4)].location
                != NSNotFound) continue;
        [wholeDisks addObject:b];
    }
    if (wholeDisks.count == 0) { completion(nil); return; }

    DASessionRef session = DASessionCreate(kCFAllocatorDefault);
    if (!session) {
        completion([NSError errorWithDomain:@"AirUSB" code:2 userInfo:@{
            NSLocalizedDescriptionKey: @"Could not talk to Disk Arbitration."
        }]);
        return;
    }

    // A dispatch queue rather than a run loop: this is called from SwiftUI, and
    // a run-loop-scheduled session would only be pumped if the caller happened
    // to be spinning one.
    AirUSBEjectContext *ctx = [AirUSBEjectContext new];
    ctx.completion = completion;
    ctx.pending    = (NSInteger)wholeDisks.count;
    ctx.session    = session;
    ctx.queue      = dispatch_queue_create("com.airusb.eject", DISPATCH_QUEUE_SERIAL);
    DASessionSetDispatchQueue(session, ctx.queue);

    // Kept alive across the callbacks; released by the last ejectFinishOne.
    CFBridgingRetain(ctx);

    for (NSString *bsd in wholeDisks) {
        DADiskRef disk = DADiskCreateFromBSDName(kCFAllocatorDefault, session, bsd.UTF8String);
        if (!disk) {
            ejectFinishOne(ctx, [NSError errorWithDomain:@"AirUSB" code:3 userInfo:@{
                NSLocalizedDescriptionKey:
                    [NSString stringWithFormat:@"Could not find /dev/%@.", bsd]
            }]);
            continue;
        }
        DADiskUnmount(disk, kDADiskUnmountOptionWhole,
                      ejectUnmountCallback, (__bridge void *)ctx);
        CFRelease(disk);
    }
}

@end
