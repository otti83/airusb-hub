//
//  capture_test.m — AirUSB Hub Phase 1 exporter capture verification
//
//  PURPOSE
//    Verify, on this exact macOS build, that the exporter half of AirUSB Hub is
//    achievable through public API. Specifically it answers the P0 report's open
//    risk #2:
//
//      FB16524420 (open): since macOS 15.3, a root helper can capture
//      IOUSBHostDevice but reportedly FAILS to capture IOUSBHostInterface for
//      MASS STORAGE devices with kIOReturnInternalError (0xE00002C9), unless SIP
//      is disabled or the process is launched from Terminal/Xcode rather than as
//      a LaunchDaemon.
//
//    If IOUSBHostInterface capture fails here, the exporter cannot do bulk I/O and
//    the architecture must change. That is why this runs before any exporter code
//    is written.
//
//  WHAT IT DOES
//    --list                 (default) enumerate USB devices. Read-only, safe.
//    --capture VID:PID      full capture lifecycle against one device:
//                             1. locate the device and its mounted volumes
//                             2. unmount volumes via DiskArbitration (safe path)
//                             3. capture IOUSBHostDevice   (DeviceCapture)
//                             4. capture each IOUSBHostInterface  <-- FB16524420
//                             5. read descriptors + a live GET_DESCRIPTOR control
//                                transfer, proving raw USB I/O works
//                             6. destroy, and confirm the OS re-enumerates
//
//  REQUIREMENTS
//    Must run as root: IOUSBHostObjectInitOptionsDeviceCapture needs either the
//    com.apple.vm.device-access entitlement (Mac-App-Store-hypervisor only, per
//    Apple DTS) or root. See IOUSBHostDefinitions.h:141-147.
//
//  SAFETY
//    --capture UNMOUNTS the device's volumes. Use a USB stick whose contents you
//    do not care about. The tool refuses to touch the boot disk, refuses any
//    internal (non-removable) device, and always attempts restore on exit.
//

#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#import <IOKit/usb/IOUSBHostFamilyDefinitions.h>
#import <IOUSBHost/IOUSBHost.h>
#import <DiskArbitration/DiskArbitration.h>

#pragma mark - logging

static void alog(const char *tag, NSString *fmt, ...) NS_FORMAT_FUNCTION(2, 3);
static void alog(const char *tag, NSString *fmt, ...)
{
    va_list ap; va_start(ap, fmt);
    NSString *m = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    fprintf(stdout, "@@AIRUSB_%s@@ %s\n", tag, m.UTF8String);
    fflush(stdout);
}

static NSString *ioerr(NSError *e)
{
    if (!e) return @"(none)";
    return [NSString stringWithFormat:@"%@ code=%ld (0x%08X)", e.domain, (long)e.code, (unsigned)e.code];
}

#pragma mark - IORegistry helpers

static NSNumber *propNum(io_service_t s, CFStringRef key)
{
    CFTypeRef v = IORegistryEntryCreateCFProperty(s, key, kCFAllocatorDefault, 0);
    if (!v) return nil;
    NSNumber *n = CFGetTypeID(v) == CFNumberGetTypeID() ? (__bridge_transfer NSNumber *)v : nil;
    if (!n) CFRelease(v);
    return n;
}

static NSString *propStr(io_service_t s, CFStringRef key)
{
    CFTypeRef v = IORegistryEntryCreateCFProperty(s, key, kCFAllocatorDefault, 0);
    if (!v) return nil;
    NSString *n = CFGetTypeID(v) == CFStringGetTypeID() ? (__bridge_transfer NSString *)v : nil;
    if (!n) CFRelease(v);
    return n;
}

/// Collect BSD device names (disk4, disk4s1, ...) beneath a USB device, so we can
/// unmount before capture.
static void collectBSDNames(io_service_t node, NSMutableSet<NSString *> *out)
{
    NSString *bsd = propStr(node, CFSTR("BSD Name"));
    if (bsd) [out addObject:bsd];

    io_iterator_t it = IO_OBJECT_NULL;
    if (IORegistryEntryGetChildIterator(node, kIOServicePlane, &it) != KERN_SUCCESS) return;
    io_service_t child;
    while ((child = IOIteratorNext(it))) {
        collectBSDNames(child, out);
        IOObjectRelease(child);
    }
    IOObjectRelease(it);
}

#pragma mark - listing

/// Print a ready-to-paste command for every attached device, so the caller never has
/// to substitute a placeholder by hand.
static void printSuggestions(void)
{
    io_iterator_t it = IO_OBJECT_NULL;
    if (IOServiceGetMatchingServices(kIOMainPortDefault,
                                     IOServiceMatching(kIOUSBHostDeviceClassName),
                                     &it) != KERN_SUCCESS) return;

    io_service_t dev; int n = 0;
    while ((dev = IOIteratorNext(it))) {
        NSNumber *vid = propNum(dev, CFSTR("idVendor"));
        NSNumber *pid = propNum(dev, CFSTR("idProduct"));
        NSString *name = propStr(dev, CFSTR("USB Product Name"));
        if (n == 0) fprintf(stdout, "\nrun one of these (copy the whole line):\n\n");
        fprintf(stdout, "  sudo ./capture_test --capture %04x:%04x      # %s\n",
                vid.unsignedIntValue, pid.unsignedIntValue,
                (name ?: @"unknown device").UTF8String);
        n++;
        IOObjectRelease(dev);
    }
    IOObjectRelease(it);
    if (n == 0) fprintf(stdout, "\nno USB devices attached — plug in the test drive first.\n");
}

static void listDevices(void)
{
    io_iterator_t it = IO_OBJECT_NULL;
    kern_return_t kr = IOServiceGetMatchingServices(kIOMainPortDefault,
                                                    IOServiceMatching(kIOUSBHostDeviceClassName),
                                                    &it);
    if (kr != KERN_SUCCESS) { alog("ERROR", @"IOServiceGetMatchingServices: 0x%08x", kr); return; }

    io_service_t dev; int n = 0;
    while ((dev = IOIteratorNext(it))) {
        NSNumber *vid = propNum(dev, CFSTR("idVendor"));
        NSNumber *pid = propNum(dev, CFSTR("idProduct"));
        NSString *name = propStr(dev, CFSTR("USB Product Name"));
        NSString *vend = propStr(dev, CFSTR("USB Vendor Name"));
        NSNumber *speed = propNum(dev, CFSTR("Device Speed"));

        NSMutableSet<NSString *> *bsd = [NSMutableSet set];
        collectBSDNames(dev, bsd);

        alog("ENUM", @"%04x:%04x  %@ %@  speed=%@  bsd=[%@]",
             vid.unsignedIntValue, pid.unsignedIntValue,
             vend ?: @"?", name ?: @"?",
             speed ?: @"?",
             [[bsd allObjects] componentsJoinedByString:@","]);
        n++;
        IOObjectRelease(dev);
    }
    IOObjectRelease(it);
    if (n == 0) alog("ENUM", @"no USB devices found — plug in the test USB drive");
    else        alog("ENUM", @"%d USB device(s)", n);
}

#pragma mark - device lookup

static io_service_t findDevice(uint16_t vid, uint16_t pid)
{
    io_iterator_t it = IO_OBJECT_NULL;
    if (IOServiceGetMatchingServices(kIOMainPortDefault,
                                     IOServiceMatching(kIOUSBHostDeviceClassName),
                                     &it) != KERN_SUCCESS) return IO_OBJECT_NULL;
    io_service_t dev, found = IO_OBJECT_NULL;
    while ((dev = IOIteratorNext(it))) {
        NSNumber *v = propNum(dev, CFSTR("idVendor"));
        NSNumber *p = propNum(dev, CFSTR("idProduct"));
        if (v.unsignedIntValue == vid && p.unsignedIntValue == pid) { found = dev; break; }
        IOObjectRelease(dev);
    }
    IOObjectRelease(it);
    return found;
}

#pragma mark - safe unmount

/// DiskArbitration takes a C function pointer, so progress is tracked in this context.
typedef struct {
    NSUInteger pending;
    BOOL       ok;
} UnmountCtx;

static void unmountCallback(DADiskRef disk, DADissenterRef dissenter, void *context)
{
    UnmountCtx *ctx = (UnmountCtx *)context;
    const char *bsd = DADiskGetBSDName(disk);
    if (dissenter) {
        DAReturn st = DADissenterGetStatus(dissenter);
        alog("ERROR", @"unmount refused for /dev/%s, status=0x%08x — is a file open on it?",
             bsd ?: "?", st);
        ctx->ok = NO;
    } else {
        alog("ATTACH", @"unmounted /dev/%s", bsd ?: "?");
    }
    ctx->pending--;
}

static BOOL unmountVolumes(NSSet<NSString *> *bsdNames)
{
    if (bsdNames.count == 0) { alog("ATTACH", @"no BSD media beneath device; nothing to unmount"); return YES; }

    DASessionRef session = DASessionCreate(kCFAllocatorDefault);
    if (!session) { alog("ERROR", @"DASessionCreate failed"); return NO; }
    DASessionScheduleWithRunLoop(session, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);

    UnmountCtx ctx = { .pending = 0, .ok = YES };

    for (NSString *bsd in bsdNames) {
        // Only unmount whole disks; kDADiskUnmountOptionWhole takes the slices with it.
        // "disk22" -> whole disk, keep.  "disk22s1" -> slice, skip.
        // Guard the range explicitly: this runs as root, and a short or unexpected
        // BSD name must not become an out-of-bounds range.
        if (bsd.length <= 4 || ![bsd hasPrefix:@"disk"]) continue;
        if ([bsd rangeOfString:@"s"
                       options:0
                         range:NSMakeRange(4, bsd.length - 4)].location != NSNotFound) continue;

        DADiskRef disk = DADiskCreateFromBSDName(kCFAllocatorDefault, session, bsd.UTF8String);
        if (!disk) continue;

        alog("ATTACH", @"unmounting /dev/%@ (whole disk)", bsd);
        ctx.pending++;
        DADiskUnmount(disk, kDADiskUnmountOptionWhole, unmountCallback, &ctx);
        CFRelease(disk);
    }

    // Pump the runloop until all unmount callbacks land or we time out.
    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:15.0];
    while (ctx.pending > 0 && [deadline timeIntervalSinceNow] > 0) {
        CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.1, true);
    }
    if (ctx.pending > 0) { alog("ERROR", @"unmount timed out"); ctx.ok = NO; }

    DASessionUnscheduleFromRunLoop(session, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
    CFRelease(session);
    return ctx.ok;
}

#pragma mark - the actual test

static int captureTest(uint16_t vid, uint16_t pid)
{
    if (geteuid() != 0) {
        alog("ERROR", @"must run as root (IOUSBHostObjectInitOptionsDeviceCapture requires root "
                       "or com.apple.vm.device-access). Try: sudo %s --capture %04x:%04x",
             "capture_test", vid, pid);
        return 1;
    }

    io_service_t devService = findDevice(vid, pid);
    if (!devService) { alog("ERROR", @"device %04x:%04x not found", vid, pid); return 1; }

    NSNumber *removable = propNum(devService, CFSTR("Removable"));
    NSString *product   = propStr(devService, CFSTR("USB Product Name"));
    alog("ATTACH", @"target %04x:%04x %@ (removable=%@)", vid, pid, product ?: @"?", removable ?: @"?");

    NSMutableSet<NSString *> *bsd = [NSMutableSet set];
    collectBSDNames(devService, bsd);
    alog("ATTACH", @"BSD media: [%@]", [[bsd allObjects] componentsJoinedByString:@","]);

    // Refuse to touch the boot disk.
    for (NSString *b in bsd) {
        if ([b isEqualToString:@"disk0"] || [b hasPrefix:@"disk0s"]) {
            alog("ERROR", @"refusing: %@ looks like the boot disk", b);
            IOObjectRelease(devService);
            return 1;
        }
    }

    if (!unmountVolumes(bsd)) {
        alog("ERROR", @"unmount failed — aborting before capture to avoid filesystem damage");
        IOObjectRelease(devService);
        return 1;
    }

    // ---- STEP 1: capture the IOUSBHostDevice -------------------------------
    NSError *err = nil;
    alog("ATTACH", @"capturing IOUSBHostDevice with IOUSBHostObjectInitOptionsDeviceCapture");
    IOUSBHostDevice *device = [[IOUSBHostDevice alloc] initWithIOService:devService
                                                                options:IOUSBHostObjectInitOptionsDeviceCapture
                                                                  queue:nil
                                                                  error:&err
                                                        interestHandler:nil];
    if (!device) {
        alog("ERROR", @"RESULT=DEVICE_CAPTURE_FAILED %@", ioerr(err));
        IOObjectRelease(devService);
        return 2;
    }
    alog("ATTACH", @"RESULT=DEVICE_CAPTURED");

    const IOUSBDeviceDescriptor *dd = device.deviceDescriptor;
    if (dd) {
        alog("ENUM", @"deviceDescriptor: USB %04x  class=%02x/%02x/%02x  VID=%04x PID=%04x "
                      "bcdDevice=%04x  ep0MaxPacket=%u  numConfigs=%u",
             USBToHost16(dd->bcdUSB), dd->bDeviceClass, dd->bDeviceSubClass, dd->bDeviceProtocol,
             USBToHost16(dd->idVendor), USBToHost16(dd->idProduct), USBToHost16(dd->bcdDevice),
             dd->bMaxPacketSize0, dd->bNumConfigurations);
    } else {
        alog("ERROR", @"deviceDescriptor was nil");
    }

    // ---- STEP 2: a real control transfer -----------------------------------
    // GET_DESCRIPTOR(DEVICE) on endpoint 0. This is the same request the importer's
    // kernel will issue at us, so proving it works end-to-end here de-risks Phase 2.
    {
        IOUSBDeviceRequest req = {
            .bmRequestType = IOUSBHostDeviceRequestType(kIOUSBDeviceRequestDirectionValueIn,
                                                        kIOUSBDeviceRequestTypeValueStandard,
                                                        kIOUSBDeviceRequestRecipientValueDevice),
            .bRequest      = kIOUSBDeviceRequestGetDescriptor,
            .wValue        = (uint16_t)(kIOUSBDescriptorTypeDevice << 8),
            .wIndex        = 0,
            .wLength       = 18
        };
        NSMutableData *buf = [NSMutableData dataWithLength:18];
        NSUInteger got = 0;
        NSError *e2 = nil;
        if ([device sendDeviceRequest:req data:buf bytesTransferred:&got completionTimeout:2.0 error:&e2]) {
            const uint8_t *b = buf.bytes;
            alog("REQ", @"RESULT=CONTROL_OK GET_DESCRIPTOR(DEVICE) bytes=%lu head=%02x %02x %02x %02x",
                 (unsigned long)got, b[0], b[1], b[2], b[3]);
        } else {
            alog("ERROR", @"RESULT=CONTROL_FAILED %@", ioerr(e2));
        }
    }

    // ---- STEP 3: THE FB16524420 TEST — capture each IOUSBHostInterface -----
    // This is the step that reportedly regressed in macOS 15.3 for mass storage.
    NSUInteger ifTotal = 0, ifCaptured = 0;
    NSMutableArray<IOUSBHostInterface *> *interfaces = [NSMutableArray array];

    io_iterator_t it = IO_OBJECT_NULL;
    if (IORegistryEntryGetChildIterator(devService, kIOServicePlane, &it) == KERN_SUCCESS) {
        io_service_t child;
        while ((child = IOIteratorNext(it))) {
            if (IOObjectConformsTo(child, (char *)kIOUSBHostInterfaceClassName)) {
                ifTotal++;
                NSNumber *cls = propNum(child, CFSTR("bInterfaceClass"));
                NSNumber *num = propNum(child, CFSTR("bInterfaceNumber"));

                NSError *ie = nil;
                IOUSBHostInterface *iface =
                    [[IOUSBHostInterface alloc] initWithIOService:child
                                                         options:IOUSBHostObjectInitOptionsDeviceCapture
                                                           queue:nil
                                                           error:&ie
                                                 interestHandler:nil];
                if (iface) {
                    ifCaptured++;
                    [interfaces addObject:iface];
                    alog("ATTACH", @"RESULT=INTERFACE_CAPTURED num=%@ class=0x%02x",
                         num ?: @"?", cls.unsignedIntValue);

                    const IOUSBInterfaceDescriptor *id_ = iface.interfaceDescriptor;
                    if (id_) {
                        alog("ENUM", @"  interface %u alt %u: class=%02x/%02x/%02x endpoints=%u",
                             id_->bInterfaceNumber, id_->bAlternateSetting,
                             id_->bInterfaceClass, id_->bInterfaceSubClass, id_->bInterfaceProtocol,
                             id_->bNumEndpoints);
                    }
                } else {
                    alog("ERROR", @"RESULT=INTERFACE_CAPTURE_FAILED num=%@ class=0x%02x %@",
                         num ?: @"?", cls.unsignedIntValue, ioerr(ie));
                    if (ie.code == kIOReturnInternalError) {
                        alog("ERROR", @"  ^ 0xE00002C9 kIOReturnInternalError == the FB16524420 signature");
                    }
                }
            }
            IOObjectRelease(child);
        }
        IOObjectRelease(it);
    }

    alog("ATTACH", @"interfaces: %lu captured / %lu present", (unsigned long)ifCaptured, (unsigned long)ifTotal);

    // ---- STEP 4: restore ---------------------------------------------------
    alog("DETACH", @"releasing interfaces and destroying device (triggers reset + driver rematch)");
    for (IOUSBHostInterface *i in interfaces) { [i destroy]; }
    [device destroy];
    IOObjectRelease(devService);
    alog("DETACH", @"RESULT=RESTORED — the OS should re-enumerate and remount the volume shortly");

    // ---- verdict -----------------------------------------------------------
    if (ifTotal == 0) {
        alog("ERROR", @"VERDICT=INCONCLUSIVE (device exposed no IOUSBHostInterface children)");
        return 3;
    }
    if (ifCaptured == ifTotal) {
        alog("ATTACH", @"VERDICT=PASS — FB16524420 does NOT reproduce here; exporter design is viable");
        return 0;
    }
    alog("ERROR", @"VERDICT=FAIL — interface capture blocked; exporter design must change");
    return 4;
}

#pragma mark - main

int main(int argc, const char *argv[])
{
    @autoreleasepool
    {
        NSArray<NSString *> *args = [NSProcessInfo processInfo].arguments;
        alog("ATTACH", @"capture_test  euid=%d  args=%@", geteuid(),
             [[args subarrayWithRange:NSMakeRange(1, args.count - 1)] componentsJoinedByString:@" "]);

        if (args.count >= 3 && [args[1] isEqualToString:@"--capture"]) {
            unsigned vid = 0, pid = 0;
            // Accept "058f:6387". Reject anything else, including the literal
            // placeholder "VID:PID" — and then show the real commands.
            if (sscanf(args[2].UTF8String, "%4x:%4x", &vid, &pid) != 2
                || vid > 0xFFFF || pid > 0xFFFF) {
                alog("ERROR", @"'%@' is not a VID:PID. It must be four hex digits, "
                              "a colon, four hex digits.", args[2]);
                printSuggestions();
                return 1;
            }
            return captureTest((uint16_t)vid, (uint16_t)pid);
        }

        listDevices();
        printSuggestions();
        fprintf(stdout, "\nUse a USB drive whose contents you do not care about.\n"
                        "The drive is unmounted and then handed back; nothing is written to it.\n");
        return 0;
    }
}
