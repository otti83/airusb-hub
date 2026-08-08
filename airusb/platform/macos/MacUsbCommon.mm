#include "MacUsbCommon.h"
#include "StatusMapMacos.h"

#import <IOKit/IOReturn.h>
#import <IOKit/usb/IOUSBHostFamilyDefinitions.h>

#include <cstdio>

namespace airusb::macos {

// ---------------------------------------------------------------------------
// The status table is written in pure C++ so it can be reviewed and tested off
// this machine. These assertions are what make that safe: every constant in
// StatusMapMacos.h is checked against the SDK it claims to have come from, so a
// transcription error or an SDK change breaks the build here rather than
// mistranslating a USB error at runtime.
// ---------------------------------------------------------------------------

static_assert(kIORetSuccess         == static_cast<std::uint32_t>(kIOReturnSuccess));
static_assert(kIORetError           == static_cast<std::uint32_t>(kIOReturnError));
static_assert(kIORetNoMemory        == static_cast<std::uint32_t>(kIOReturnNoMemory));
static_assert(kIORetNoResources     == static_cast<std::uint32_t>(kIOReturnNoResources));
static_assert(kIORetNoDevice        == static_cast<std::uint32_t>(kIOReturnNoDevice));
static_assert(kIORetNotPrivileged   == static_cast<std::uint32_t>(kIOReturnNotPrivileged));
static_assert(kIORetBadArgument     == static_cast<std::uint32_t>(kIOReturnBadArgument));
static_assert(kIORetExclusiveAccess == static_cast<std::uint32_t>(kIOReturnExclusiveAccess));
static_assert(kIORetBadMessageID    == static_cast<std::uint32_t>(kIOReturnBadMessageID));
static_assert(kIORetUnsupported     == static_cast<std::uint32_t>(kIOReturnUnsupported));
static_assert(kIORetInternalError   == static_cast<std::uint32_t>(kIOReturnInternalError));
static_assert(kIORetIOError         == static_cast<std::uint32_t>(kIOReturnIOError));
static_assert(kIORetNotOpen         == static_cast<std::uint32_t>(kIOReturnNotOpen));
static_assert(kIORetBusy            == static_cast<std::uint32_t>(kIOReturnBusy));
static_assert(kIORetTimeout         == static_cast<std::uint32_t>(kIOReturnTimeout));
static_assert(kIORetOffline         == static_cast<std::uint32_t>(kIOReturnOffline));
static_assert(kIORetNotReady        == static_cast<std::uint32_t>(kIOReturnNotReady));
static_assert(kIORetNotAttached     == static_cast<std::uint32_t>(kIOReturnNotAttached));
static_assert(kIORetNoSpace         == static_cast<std::uint32_t>(kIOReturnNoSpace));
static_assert(kIORetUnderrun        == static_cast<std::uint32_t>(kIOReturnUnderrun));
static_assert(kIORetOverrun         == static_cast<std::uint32_t>(kIOReturnOverrun));
static_assert(kIORetDeviceError     == static_cast<std::uint32_t>(kIOReturnDeviceError));
static_assert(kIORetAborted         == static_cast<std::uint32_t>(kIOReturnAborted));
static_assert(kIORetNotResponding   == static_cast<std::uint32_t>(kIOReturnNotResponding));
static_assert(kIORetNotPermitted    == static_cast<std::uint32_t>(kIOReturnNotPermitted));
static_assert(kIORetNotFound        == static_cast<std::uint32_t>(kIOReturnNotFound));
static_assert(kUsbRetPipeStalled    == static_cast<std::uint32_t>(kUSBHostReturnPipeStalled));
static_assert(kUsbRetNoPower        == static_cast<std::uint32_t>(kUSBHostReturnNoPower));
static_assert(kUsbRetRedundant      == static_cast<std::uint32_t>(kUSBHostReturnRedundant));

// airusb::Speed is declared to mirror tIOUSBHostConnectionSpeed exactly, so that
// a speed can cross the manifest boundary without a translation table that could
// itself be wrong. Pinned here so the two cannot drift apart silently.
static_assert(static_cast<int>(Speed::None)         == kIOUSBHostConnectionSpeedNone);
static_assert(static_cast<int>(Speed::Full)         == kIOUSBHostConnectionSpeedFull);
static_assert(static_cast<int>(Speed::Low)          == kIOUSBHostConnectionSpeedLow);
static_assert(static_cast<int>(Speed::High)         == kIOUSBHostConnectionSpeedHigh);
static_assert(static_cast<int>(Speed::Super)        == kIOUSBHostConnectionSpeedSuper);
static_assert(static_cast<int>(Speed::SuperPlus)    == kIOUSBHostConnectionSpeedSuperPlus);
static_assert(static_cast<int>(Speed::SuperPlusBy2) == kIOUSBHostConnectionSpeedSuperPlusBy2);
static_assert(static_cast<int>(Speed::Other)        == kIOUSBHostConnectionSpeedOther);

// ---------------------------------------------------------------------------
// logging
// ---------------------------------------------------------------------------

namespace {
const char* g_prefix = "airusb";
}

void setLogPrefix(const char* prefix) { if (prefix) g_prefix = prefix; }

void logLine(const char* tag, NSString* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    NSString* m = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    std::fprintf(stdout, "@@AIRUSB_%s@@ [%s] %s\n", tag, g_prefix, m.UTF8String);
    std::fflush(stdout);
}

std::string describeError(NSError* e)
{
    if (!e) return "(none)";
    const std::uint32_t code = static_cast<std::uint32_t>(e.code);
    NSString* s = [NSString stringWithFormat:@"%@ %ld (0x%08X %s)",
                   e.domain, (long)e.code, code, ioReturnName(code)];
    return std::string(s.UTF8String);
}

// ---------------------------------------------------------------------------
// IORegistry
// ---------------------------------------------------------------------------

NSNumber* propNum(io_service_t s, CFStringRef key)
{
    CFTypeRef v = IORegistryEntryCreateCFProperty(s, key, kCFAllocatorDefault, 0);
    if (!v) return nil;
    if (CFGetTypeID(v) != CFNumberGetTypeID()) { CFRelease(v); return nil; }
    return (__bridge_transfer NSNumber*)v;
}

NSString* propStr(io_service_t s, CFStringRef key)
{
    CFTypeRef v = IORegistryEntryCreateCFProperty(s, key, kCFAllocatorDefault, 0);
    if (!v) return nil;
    if (CFGetTypeID(v) != CFStringGetTypeID()) { CFRelease(v); return nil; }
    return (__bridge_transfer NSString*)v;
}

void collectBsdNames(io_service_t node, std::set<std::string>& out)
{
    if (NSString* bsd = propStr(node, CFSTR("BSD Name")); bsd)
        out.insert(std::string(bsd.UTF8String));

    io_iterator_t it = IO_OBJECT_NULL;
    if (IORegistryEntryGetChildIterator(node, kIOServicePlane, &it) != KERN_SUCCESS) return;
    io_service_t child;
    while ((child = IOIteratorNext(it))) {
        collectBsdNames(child, out);
        IOObjectRelease(child);
    }
    IOObjectRelease(it);
}

io_service_t findDeviceByVidPid(std::uint16_t vid, std::uint16_t pid)
{
    io_iterator_t it = IO_OBJECT_NULL;
    if (IOServiceGetMatchingServices(kIOMainPortDefault,
                                     IOServiceMatching(kIOUSBHostDeviceClassName),
                                     &it) != KERN_SUCCESS) return IO_OBJECT_NULL;
    io_service_t dev, found = IO_OBJECT_NULL;
    while ((dev = IOIteratorNext(it))) {
        NSNumber* v = propNum(dev, CFSTR("idVendor"));
        NSNumber* p = propNum(dev, CFSTR("idProduct"));
        if (v.unsignedIntValue == vid && p.unsignedIntValue == pid) { found = dev; break; }
        IOObjectRelease(dev);
    }
    IOObjectRelease(it);
    return found;
}

io_service_t findDeviceByLocationId(std::uint32_t locationId)
{
    io_iterator_t it = IO_OBJECT_NULL;
    if (IOServiceGetMatchingServices(kIOMainPortDefault,
                                     IOServiceMatching(kIOUSBHostDeviceClassName),
                                     &it) != KERN_SUCCESS) return IO_OBJECT_NULL;
    io_service_t dev, found = IO_OBJECT_NULL;
    while ((dev = IOIteratorNext(it))) {
        if (locationIdOf(dev) == locationId) { found = dev; break; }
        IOObjectRelease(dev);
    }
    IOObjectRelease(it);
    return found;
}

std::uint32_t locationIdOf(io_service_t device)
{
    NSNumber* n = propNum(device, CFSTR("locationID"));
    return n ? static_cast<std::uint32_t>(n.unsignedIntValue) : 0u;
}

Speed readSpeed(io_service_t device)
{
    NSNumber* modern = propNum(device, CFSTR("USBSpeed"));
    NSNumber* link   = propNum(device, CFSTR("UsbLinkSpeed"));
    if (!modern) return Speed::None;

    const unsigned raw = modern.unsignedIntValue;
    if (raw > static_cast<unsigned>(Speed::Other)) return Speed::Other;
    const Speed s = static_cast<Speed>(raw);

    // Cross-check against the measured link rate. The two properties use
    // different enumerations and the same integer 3 means High in the legacy one
    // and Super in this one; a mismatch here means we are reading the wrong
    // property and about to declare a USB 3 device as USB 2.
    if (link) {
        const double bps = link.doubleValue;
        const bool superish = (s == Speed::Super || s == Speed::SuperPlus ||
                               s == Speed::SuperPlusBy2);
        if (superish && bps < 4.0e9)
            logLine("ERROR", @"speed mismatch: USBSpeed=%u says SuperSpeed but "
                             "UsbLinkSpeed=%.0f is below 5 Gb/s", raw, bps);
        if (!superish && bps >= 4.0e9)
            logLine("ERROR", @"speed mismatch: USBSpeed=%u but UsbLinkSpeed=%.0f "
                             "is SuperSpeed or faster", raw, bps);
    }
    return s;
}

std::string describeSpeed(io_service_t device)
{
    const Speed s = readSpeed(device);
    NSNumber* link = propNum(device, CFSTR("UsbLinkSpeed"));
    NSString* out = link
        ? [NSString stringWithFormat:@"%s (%.1f Gb/s link)", speedName(s), link.doubleValue / 1e9]
        : [NSString stringWithFormat:@"%s", speedName(s)];
    return std::string(out.UTF8String);
}

// ---------------------------------------------------------------------------
// safe construction
// ---------------------------------------------------------------------------

std::uint32_t probeServiceOpen(io_service_t service)
{
    io_connect_t c = IO_OBJECT_NULL;
    const kern_return_t kr = IOServiceOpen(service, mach_task_self(), 0, &c);
    if (kr == KERN_SUCCESS) IOServiceClose(c);
    return static_cast<std::uint32_t>(kr);
}

namespace {

/// The shared body of safeInitDevice/safeInitInterface. `make` performs the
/// actual allocation; everything around it exists because Apple's failure path
/// can raise.
template <typename T, typename MakeFn>
T* safeInitImpl(io_service_t service,
                const char* what,
                std::uint32_t* ioReturn,
                std::string* why,
                MakeFn make)
{
    if (ioReturn) *ioReturn = kIORetSuccess;

    NSError* err = nil;
    T* obj = nil;
    @try {
        obj = make(&err);
    } @catch (NSException* ex) {
        // Documented Apple behaviour on this path, not a hypothetical. See the
        // file header. Turning it into a return value is the whole point of this
        // wrapper: a root daemon must not die here.
        if (why) {
            NSString* s = [NSString stringWithFormat:@"%s init raised %@: %@",
                           what, ex.name, ex.reason];
            *why = std::string(s.UTF8String);
        }
        logLine("ERROR", @"%@ init raised %@: %@ — Apple's error path raised "
                          "instead of returning NSError", @(what), ex.name, ex.reason);
        obj = nil;
    }

    if (obj) return obj;

    // The framework destroys its own NSError on this path, so ask the kernel
    // directly for the code that actually caused the failure.
    const std::uint32_t direct = probeServiceOpen(service);
    if (ioReturn) *ioReturn = (direct != kIORetSuccess)
                                ? direct
                                : static_cast<std::uint32_t>(err ? err.code : kIORetError);
    if (why && why->empty()) {
        NSString* s = [NSString stringWithFormat:@"%s init failed: %s (direct open 0x%08X %s)",
                       what, describeError(err).c_str(), direct, ioReturnName(direct)];
        *why = std::string(s.UTF8String);
    }
    return nil;
}

} // namespace

IOUSBHostDevice* safeInitDevice(io_service_t service,
                                IOUSBHostObjectInitOptions options,
                                std::uint32_t* ioReturn,
                                std::string* why)
{
    return safeInitImpl<IOUSBHostDevice>(
        service, "IOUSBHostDevice", ioReturn, why,
        [&](NSError** e) {
            return [[IOUSBHostDevice alloc] initWithIOService:service
                                                      options:options
                                                        queue:nil
                                                        error:e
                                              interestHandler:nil];
        });
}

IOUSBHostInterface* safeInitInterface(io_service_t service,
                                      IOUSBHostObjectInitOptions options,
                                      std::uint32_t* ioReturn,
                                      std::string* why)
{
    return safeInitImpl<IOUSBHostInterface>(
        service, "IOUSBHostInterface", ioReturn, why,
        [&](NSError** e) {
            return [[IOUSBHostInterface alloc] initWithIOService:service
                                                         options:options
                                                           queue:nil
                                                           error:e
                                                 interestHandler:nil];
        });
}

void safeDestroy(IOUSBHostObject* obj, bool surrender)
{
    if (!obj) return;
    @try {
        if (surrender) [obj destroyWithOptions:IOUSBHostObjectDestroyOptionsDeviceSurrender];
        else           [obj destroy];
    } @catch (NSException* ex) {
        logLine("ERROR", @"destroy raised %@: %@", ex.name, ex.reason);
    }
}

bool canOpenInterfaces(io_service_t device, std::uint32_t* lastIoReturn)
{
    io_iterator_t it = IO_OBJECT_NULL;
    if (IORegistryEntryGetChildIterator(device, kIOServicePlane, &it) != KERN_SUCCESS)
        return false;

    int present = 0, opened = 0;
    std::uint32_t last = kIORetSuccess;
    io_service_t child;
    while ((child = IOIteratorNext(it))) {
        if (IOObjectConformsTo(child, (char*)kIOUSBHostInterfaceClassName)) {
            ++present;
            const std::uint32_t kr = probeServiceOpen(child);
            last = kr;
            // kIOReturnExclusiveAccess means the POLICY allowed the open and
            // something else currently holds the interface. That is a yes to the
            // question being asked here: the System Policy check runs first.
            if (kr == kIORetSuccess || kr == kIORetExclusiveAccess) ++opened;
        }
        IOObjectRelease(child);
    }
    IOObjectRelease(it);

    if (lastIoReturn) *lastIoReturn = last;
    return present > 0 && opened == present;
}

} // namespace airusb::macos
