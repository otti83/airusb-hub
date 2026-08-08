//
//  The Objective-C layer the SwiftUI app sits on.
//
//  IOKit is a C API with manual retain/release and CF bridging; doing it from
//  Swift means a lot of `Unmanaged` and `takeRetainedValue` at every call. It is
//  written once here instead, and Swift sees plain objects.
//
//  Everything in this file is READ-ONLY with respect to the USB device. Nothing
//  here captures, unmounts, or claims anything — the enumeration is the same
//  information `system_profiler SPUSBDataType` shows, and ejecting goes through
//  DiskArbitration exactly as Finder's eject does.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// One USB device as the IORegistry describes it, plus whatever block media sits
/// beneath it.
@interface AirUSBDeviceInfo : NSObject

@property(nonatomic, copy)   NSString *productName;
@property(nonatomic, copy)   NSString *vendorName;
@property(nonatomic, assign) uint16_t  vendorId;
@property(nonatomic, assign) uint16_t  productId;
@property(nonatomic, assign) uint32_t  locationId;

/// From `USBSpeed`, cross-checked against `UsbLinkSpeed`.
///
/// The IORegistry publishes TWO speed properties with DIFFERENT enumerations, in
/// which the same integer 3 means High in one and Super in the other. Reading the
/// wrong one silently reports a USB 3 device as USB 2, so the link rate is kept
/// alongside and a disagreement is surfaced rather than hidden.
@property(nonatomic, copy)   NSString *speedText;
@property(nonatomic, assign) double    linkSpeedBitsPerSecond;
@property(nonatomic, assign) BOOL      speedPropertiesDisagree;

/// Whole disks and slices beneath this device, e.g. `disk4`, `disk4s1`.
@property(nonatomic, copy)   NSArray<NSString *> *bsdNames;

/// Currently mounted volumes backed by this device.
@property(nonatomic, copy)   NSArray<NSString *> *mountPoints;

/// True if any BSD name looks like the boot disk. Such a device is never
/// offered for sharing, and the UI says why rather than just disabling a button.
@property(nonatomic, assign) BOOL isBootDisk;

/// A device with no block media — a keyboard, a hub, a serial adapter. It can
/// still be shared; there is simply nothing to unmount first.
@property(nonatomic, readonly) BOOL hasStorage;

/// `058f:6387`
@property(nonatomic, readonly) NSString *identifierText;

/// Stable across a refresh, so SwiftUI's diffing does not rebuild every row.
@property(nonatomic, readonly) NSString *stableId;

@end


/// Enumerates USB devices and watches for hotplug.
@interface AirUSBDeviceWatcher : NSObject

/// Called on the main queue whenever a device is attached or detached.
@property(nonatomic, copy, nullable) void (^onChange)(void);

- (NSArray<AirUSBDeviceInfo *> *)currentDevices;

- (void)start;
- (void)stop;

@end


/// The result of asking whether this build may create a virtual USB controller.
typedef NS_ENUM(NSInteger, AirUSBEntitlementState) {
    AirUSBEntitlementStateGranted,      ///< a controller was created; the importer can be built
    AirUSBEntitlementStateRefused,      ///< ran and was refused — the expected state before the grant
    AirUSBEntitlementStateThrew,        ///< Apple's error path raised instead of returning
};

@interface AirUSBEntitlementReport : NSObject
@property(nonatomic, assign) AirUSBEntitlementState state;
@property(nonatomic, assign) unsigned ioReturn;
@property(nonatomic, copy)   NSString *summary;
@property(nonatomic, copy)   NSString *detail;
@property(nonatomic, assign) BOOL profilePresent;
@property(nonatomic, assign) BOOL profileAuthorisesEntitlement;
@end

@interface AirUSBEntitlementProbe : NSObject
/// Attempts to instantiate IOUSBHostControllerInterface and reports what happened.
/// Safe: one unpowered root port, destroyed immediately.
+ (AirUSBEntitlementReport *)run;
@end


/// Unmounts the volumes backed by a device, the same way Finder's eject does.
@interface AirUSBEjector : NSObject
/// Unmounts every mounted volume of `device`. `completion` runs on the main queue.
/// `error` is nil on success; on failure it names the volume and, when
/// DiskArbitration supplies it, the process holding it.
+ (void)ejectDevice:(AirUSBDeviceInfo *)device
         completion:(void (^)(NSError *_Nullable error))completion;
@end

NS_ASSUME_NONNULL_END
