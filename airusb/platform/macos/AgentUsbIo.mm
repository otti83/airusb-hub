#include "AgentUsbIo.h"
#include "MacUsbCommon.h"
#include "StatusMapMacos.h"

#import <IOKit/IOKitLib.h>
#import <IOKit/usb/IOUSBHostFamilyDefinitions.h>
#import <IOUSBHost/AppleUSBDescriptorParsing.h>

#include "../../core/Watchdog.h"

namespace airusb::macos {

namespace {

/// How long to wait for the interface nubs to reappear after the daemon's
/// configureWithValue:. IOUSBHostDevice.h is explicit that "after the completion
/// of this call, the interfaces are not guaranteed to be immediately available",
/// and under launchd the wait is genuinely needed — from a terminal enough time
/// had usually elapsed to hide it.
constexpr double kNubWaitSeconds = 5.0;

XferType xferTypeOf(const IOUSBEndpointDescriptor* ep)
{
    switch (IOUSBGetEndpointType(ep)) {
        case kIOUSBEndpointTypeControl:     return XferType::Control;
        case kIOUSBEndpointTypeIsochronous: return XferType::Isochronous;
        case kIOUSBEndpointTypeInterrupt:   return XferType::Interrupt;
        case kIOUSBEndpointTypeBulk:
        default:                            return XferType::Bulk;
    }
}

/// Seconds for IOUSBHostPipe.completionTimeout.
///
/// MUST be 0 for interrupt pipes and streams: an interrupt IN may legitimately
/// idle forever, and IOUSBHostPipe.h states the requirement outright. The
/// exporter therefore cannot delegate interrupt timeouts to IOKit — they are
/// aborted only on cancel, endpoint destroy, lease loss, or detach.
NSTimeInterval timeoutFor(XferType type, std::uint32_t requestedMs)
{
    if (type == XferType::Interrupt) return 0.0;
    const std::uint32_t ms = requestedMs != 0 ? requestedMs
                                              : static_cast<std::uint32_t>(watchdog::kUrbCeilingBulk);
    return static_cast<NSTimeInterval>(ms) / 1000.0;
}

/// An NSMutableData suitable for a USB transfer.
///
/// -ioDataWithCapacity: lives on IOUSBHostObject, which is the INTERFACE, not the
/// pipe — IOUSBHostPipe descends from IOUSBHostIOSource instead. It hands back a
/// buffer the framework can hand to the controller without bouncing it, so it is
/// worth reaching through the pipe's owning interface for. A plain NSMutableData
/// still works when the interface is unavailable, just with one more copy.
NSMutableData* ioBuffer(IOUSBHostPipe* pipe, std::size_t bytes)
{
    if (bytes == 0) return nil;

    if (IOUSBHostInterface* owner = pipe.hostInterface; owner) {
        NSError* e = nil;
        // Allocated at exactly the transfer size and then left alone.
        // IOUSBHostObject.h: "Because the NSMutableData is backed by kernel
        // memory, the length and capacity are not mutable. Any changes to the
        // length or capacity will cause an exception to be thrown." So the size
        // is decided here and never adjusted afterwards.
        NSMutableData* d = [owner ioDataWithCapacity:bytes error:&e];
        if (d && d.length == bytes) return d;
        if (d) {
            // A buffer whose length is not what was asked for cannot be used:
            // the framework takes the transfer length from data.length, so a
            // mismatch would silently move the wrong number of bytes.
            logLine("ERROR", @"ioDataWithCapacity:%zu returned a %lu byte buffer — "
                              "falling back to an ordinary allocation",
                    bytes, (unsigned long)d.length);
        }
    }
    return [NSMutableData dataWithLength:bytes];
}

} // namespace

// ---------------------------------------------------------------------------

AgentUsbIo::~AgentUsbIo() { closeAll(); }

Status AgentUsbIo::checkGeneration(std::uint32_t generation) const
{
    if (generation == _generation) return Status::Ok;
    logLine("ERROR", @"transfer carries pipe table generation %u but the current "
                      "table is generation %u — refusing", generation, _generation);
    return Status::XferEpStopped;
}

AgentUsbIo::PipeRow* AgentUsbIo::find(std::uint8_t epAddr)
{
    for (PipeRow& r : _pipes)
        if (r.address == epAddr) return &r;
    return nullptr;
}

// ---------------------------------------------------------------------------

Status AgentUsbIo::openInterfaces(std::uint32_t locationId,
                                  std::uint8_t configValue,
                                  ipc::PipeTable& out,
                                  std::string* why)
{
    closeAll();
    _locationId  = locationId;
    _configValue = configValue;
    return buildTable(out, why);
}

Status AgentUsbIo::rebuildPipeTable(ipc::PipeTable& out, std::string* why)
{
    if (_locationId == 0) {
        if (why) *why = "rebuildPipeTable before openInterfaces";
        return Status::BadArgument;
    }
    logLine("ATTACH", @"rebuilding the pipe table (generation %u -> %u)",
            _generation, _generation + 1);
    closeAll();
    return buildTable(out, why);
}

Status AgentUsbIo::buildTable(ipc::PipeTable& out, std::string* why)
{
    io_service_t device = findDeviceByLocationId(_locationId);
    if (!device) {
        if (why) *why = "device not present in the IORegistry";
        return Status::DeviceGone;
    }

    _interfaces = [NSMutableArray array];
    _pipes.clear();
    ++_generation;

    // Poll for the republished interface nubs rather than assuming they are
    // already there. The daemon's configureWithValue:matchInterfaces:NO tore the
    // old ones down and the new ones arrive asynchronously.
    NSDate* deadline = [NSDate dateWithTimeIntervalSinceNow:kNubWaitSeconds];
    NSUInteger present = 0;
    do {
        present = 0;
        io_iterator_t it = IO_OBJECT_NULL;
        if (IORegistryEntryGetChildIterator(device, kIOServicePlane, &it) == KERN_SUCCESS) {
            io_service_t c;
            while ((c = IOIteratorNext(it))) {
                if (IOObjectConformsTo(c, (char*)kIOUSBHostInterfaceClassName)) ++present;
                IOObjectRelease(c);
            }
            IOObjectRelease(it);
        }
        if (present > 0) break;
        CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.1, true);
    } while ([deadline timeIntervalSinceNow] > 0);

    if (present == 0) {
        IOObjectRelease(device);
        if (why) *why = "no IOUSBHostInterface nubs appeared within 5 s — did the "
                        "daemon call configureWithValue:matchInterfaces:NO?";
        return Status::CaptureFailed;
    }
    logLine("ATTACH", @"%lu interface nub(s) present", (unsigned long)present);

    // ---- open each interface ------------------------------------------------
    io_iterator_t it = IO_OBJECT_NULL;
    if (IORegistryEntryGetChildIterator(device, kIOServicePlane, &it) != KERN_SUCCESS) {
        IOObjectRelease(device);
        if (why) *why = "IORegistryEntryGetChildIterator failed";
        return Status::Internal;
    }

    Status result = Status::Ok;
    io_service_t child;
    while ((child = IOIteratorNext(it))) {
        if (!IOObjectConformsTo(child, (char*)kIOUSBHostInterfaceClassName)) {
            IOObjectRelease(child);
            continue;
        }

        NSNumber* num = propNum(child, CFSTR("bInterfaceNumber"));

        // A PLAIN open first, with no capture option. The daemon has already
        // captured the DEVICE, which terminated every driver of it, so by the
        // time we get here nothing should hold the interface.
        std::uint32_t ior = 0;
        std::string   iwhy;
        IOUSBHostInterface* iface =
            safeInitInterface(child, IOUSBHostObjectInitOptionsNone, &ior, &iwhy);

        if (!iface) {
            // Fall back to an explicit interface capture. The P1 probe found the
            // plain open sufficient once the device is captured, but it was
            // measured with a raw type-0 IOServiceOpen rather than through the
            // framework, and the framework opens a different user client type.
            // Trying both here costs one call and removes the difference between
            // "the design is wrong" and "the option was missing".
            std::uint32_t ior2 = 0;
            std::string   iwhy2;
            iface = safeInitInterface(child, IOUSBHostObjectInitOptionsDeviceCapture,
                                      &ior2, &iwhy2);
            if (iface) {
                logLine("ATTACH", @"interface %@ needed IOUSBHostObjectInitOptions"
                                   "DeviceCapture (plain open gave 0x%08X %s)",
                        (num ? num : @"?"), ior, ioReturnName(ior));
            } else {
                ior  = ior2 != kIORetSuccess ? ior2 : ior;
                iwhy = iwhy2.empty() ? iwhy : iwhy2;
            }
        }

        if (!iface) {
            logLine("ERROR", @"interface %@ open failed: 0x%08X %s — %s",
                    (num ? num : @"?"), ior, ioReturnName(ior), iwhy.c_str());

            // Separate the two failures that look alike but mean opposite things.
            const std::uint32_t policy = probeServiceOpen(child);
            if (ior == kIORetNotPermitted || policy == kIORetNotPermitted) {
                logLine("ERROR", @"  ^ System Policy denied iokit-open-service "
                                  "IOUSBHostInterface. This process is not in the "
                                  "console security session — that is the gate the "
                                  "two-process design exists for, and it has failed.");
            } else if (policy == kIORetSuccess || policy == kIORetExclusiveAccess) {
                // The policy check PASSED. The framework's own open is what
                // failed, and the usual reason is that a driver still owns the
                // interface because nothing captured the device first.
                logLine("ERROR", @"  ^ the security session is FINE (a raw open of "
                                  "this service returns 0x%08X %s). The framework's "
                                  "open is what failed — the usual cause is that a "
                                  "driver still holds the interface because no "
                                  "capture is in effect.",
                        policy, ioReturnName(policy));
            }

            if (result == Status::Ok) result = fromIOReturn(ior, false);
            if (why && why->empty()) *why = iwhy;
            IOObjectRelease(child);
            continue;
        }

        [_interfaces addObject:iface];

        const IOUSBInterfaceDescriptor* id_ = iface.interfaceDescriptor;
        const IOUSBConfigurationDescriptor* cd = iface.configurationDescriptor;
        if (!id_ || !cd) {
            logLine("ERROR", @"interface %@ opened but has no descriptors", (num ? num : @"?"));
            IOObjectRelease(child);
            continue;
        }

        if (cd->bConfigurationValue != _configValue) {
            // The daemon and the agent disagree about the active configuration.
            // Moving data now would use pipes from the wrong configuration.
            logLine("ERROR", @"interface %@ reports configuration %u but the daemon "
                              "selected %u — refusing to build a pipe table",
                    (num ? num : @"?"), cd->bConfigurationValue, _configValue);
            IOObjectRelease(child);
            IOObjectRelease(it);
            IOObjectRelease(device);
            closeAll();
            if (why) *why = "configuration mismatch between daemon and agent";
            return Status::Internal;
        }

        logLine("ENUM", @"interface %u alt %u: class=%02x/%02x/%02x endpoints=%u",
                id_->bInterfaceNumber, id_->bAlternateSetting,
                id_->bInterfaceClass, id_->bInterfaceSubClass, id_->bInterfaceProtocol,
                id_->bNumEndpoints);

        // ---- copy a pipe for every endpoint of the ACTIVE alt setting -------
        const IOUSBEndpointDescriptor* ep = nullptr;
        while ((ep = IOUSBGetNextEndpointDescriptor(cd, id_,
                        reinterpret_cast<const IOUSBDescriptorHeader*>(ep))) != nullptr) {
            const std::uint8_t addr = IOUSBGetEndpointAddress(ep);

            NSError* pe = nil;
            IOUSBHostPipe* pipe = nil;
            @try {
                pipe = [iface copyPipeWithAddress:addr error:&pe];
            } @catch (NSException* ex) {
                logLine("ERROR", @"copyPipeWithAddress:0x%02x raised %@: %@",
                        addr, ex.name, ex.reason);
                pipe = nil;
            }

            if (!pipe) {
                logLine("ERROR", @"no pipe for endpoint 0x%02x: %s",
                        addr, describeError(pe).c_str());
                if (result == Status::Ok) result = Status::CaptureFailed;
                continue;
            }

            PipeRow row;
            row.address = addr;
            row.type    = xferTypeOf(ep);
            row.pipe    = pipe;
            _pipes.push_back(row);

            const IOUSBSuperSpeedEndpointCompanionDescriptor* comp =
                reinterpret_cast<const IOUSBSuperSpeedEndpointCompanionDescriptor*>(
                    IOUSBGetNextAssociatedDescriptorWithType(
                        cd, reinterpret_cast<const IOUSBDescriptorHeader*>(ep), nullptr,
                        kIOUSBDescriptorTypeSuperSpeedUSBEndpointCompanion));

            ipc::EpEntry e;
            e.address         = addr;
            e.type            = static_cast<std::uint8_t>(row.type);
            e.maxPacketSize   = ep->wMaxPacketSize;
            e.interval        = ep->bInterval;
            e.maxBurst        = comp ? comp->bMaxBurst : 0;
            e.interfaceNumber = id_->bInterfaceNumber;
            e.altSetting      = id_->bAlternateSetting;
            out.endpoints.push_back(e);

            logLine("ENUM", @"  endpoint 0x%02x type=%u maxPacket=%u burst=%u",
                    addr, static_cast<unsigned>(row.type), ep->wMaxPacketSize,
                    comp ? comp->bMaxBurst : 0);
        }

        IOObjectRelease(child);
    }
    IOObjectRelease(it);
    IOObjectRelease(device);

    out.generation = _generation;

    if (_pipes.empty()) {
        if (why && why->empty()) *why = "no pipes could be opened";
        return result != Status::Ok ? result : Status::CaptureFailed;
    }

    logLine("ATTACH", @"pipe table generation %u: %zu endpoint(s) across %lu interface(s)",
            _generation, _pipes.size(), (unsigned long)_interfaces.count);
    return Status::Ok;
}

// ---------------------------------------------------------------------------
// transfers
// ---------------------------------------------------------------------------

Status AgentUsbIo::bulkOut(std::uint32_t generation, std::uint8_t epAddr,
                           std::span<const std::uint8_t> data, std::uint32_t timeoutMs,
                           std::uint32_t* actualLen)
{
    if (actualLen) *actualLen = 0;
    if (const Status g = checkGeneration(generation); g != Status::Ok) return g;

    PipeRow* row = find(epAddr);
    if (!row) return Status::NotFound;
    if (epAddr & 0x80u) return Status::BadArgument;      // that is an IN endpoint

    NSMutableData* buf = ioBuffer(row->pipe, data.size());
    if (!data.empty()) std::memcpy(buf.mutableBytes, data.data(), data.size());

    NSUInteger moved = 0;
    NSError* err = nil;
    BOOL ok = NO;
    @try {
        ok = [row->pipe sendIORequestWithData:buf
                             bytesTransferred:&moved
                            completionTimeout:timeoutFor(row->type, timeoutMs)
                                        error:&err];
    } @catch (NSException* ex) {
        logLine("ERROR", @"bulkOut 0x%02x raised %@: %@", epAddr, ex.name, ex.reason);
        return Status::Internal;
    }

    if (!ok) {
        const std::uint32_t ior = static_cast<std::uint32_t>(err ? err.code : kIORetError);
        const Status s = fromIOReturn(ior, true);
        logLine("XFER", @"OUT 0x%02x %zu bytes -> 0x%08X %s (%s)",
                epAddr, data.size(), ior, ioReturnName(ior), statusName(s));
        return s;
    }

    if (actualLen) *actualLen = static_cast<std::uint32_t>(moved);
    return Status::Ok;
}

Status AgentUsbIo::bulkIn(std::uint32_t generation, std::uint8_t epAddr,
                          std::uint32_t maxLen, std::uint32_t timeoutMs,
                          std::vector<std::uint8_t>& out)
{
    out.clear();
    if (const Status g = checkGeneration(generation); g != Status::Ok) return g;

    PipeRow* row = find(epAddr);
    if (!row) return Status::NotFound;
    if ((epAddr & 0x80u) == 0) return Status::BadArgument;   // that is an OUT endpoint
    if (maxLen == 0 || maxLen > ipc::kMaxTransferBytes) return Status::BadArgument;

    NSMutableData* buf = ioBuffer(row->pipe, maxLen);

    NSUInteger moved = 0;
    NSError* err = nil;
    BOOL ok = NO;
    @try {
        ok = [row->pipe sendIORequestWithData:buf
                             bytesTransferred:&moved
                            completionTimeout:timeoutFor(row->type, timeoutMs)
                                        error:&err];
    } @catch (NSException* ex) {
        logLine("ERROR", @"bulkIn 0x%02x raised %@: %@", epAddr, ex.name, ex.reason);
        return Status::Internal;
    }

    if (!ok) {
        const std::uint32_t ior = static_cast<std::uint32_t>(err ? err.code : kIORetError);
        const Status s = fromIOReturn(ior, true);
        logLine("XFER", @"IN  0x%02x offered %u -> 0x%08X %s (%s)",
                epAddr, maxLen, ior, ioReturnName(ior), statusName(s));

        // An IOKit "underrun" is a short read, which is ordinary USB and carries
        // the bytes that DID arrive. Dropping them would turn every legitimate
        // short transfer into data loss.
        if (s == Status::XferShort && moved > 0 && moved <= maxLen) {
            const std::uint8_t* p = static_cast<const std::uint8_t*>(buf.bytes);
            out.assign(p, p + moved);
            return Status::Ok;
        }
        return s;
    }

    // Trust the kernel's byte count, never the buffer we offered. Copying maxLen
    // here would hand the caller uninitialised bytes on every short read — the
    // exact defect diag/BotProbe's short-read case exists to catch.
    if (moved > maxLen) {
        logLine("ERROR", @"kernel reported %lu bytes for a %u byte buffer — refusing",
                (unsigned long)moved, maxLen);
        return Status::XferOverrun;
    }
    const std::uint8_t* p = static_cast<const std::uint8_t*>(buf.bytes);
    out.assign(p, p + moved);
    return Status::Ok;
}

Status AgentUsbIo::clearHalt(std::uint32_t generation, std::uint8_t epAddr)
{
    if (const Status g = checkGeneration(generation); g != Status::Ok) return g;

    PipeRow* row = find(epAddr);
    if (!row) return Status::NotFound;

    NSError* err = nil;
    BOOL ok = NO;
    @try {
        ok = [row->pipe clearStallWithError:&err];
    } @catch (NSException* ex) {
        logLine("ERROR", @"clearStall 0x%02x raised %@: %@", epAddr, ex.name, ex.reason);
        return Status::Internal;
    }

    if (!ok) {
        const std::uint32_t ior = static_cast<std::uint32_t>(err ? err.code : kIORetError);
        logLine("ERROR", @"clearStall 0x%02x -> 0x%08X %s", epAddr, ior, ioReturnName(ior));
        return fromIOReturn(ior, false);
    }
    logLine("XFER", @"CLEAR_HALT 0x%02x (stall and data toggle both cleared)", epAddr);
    return Status::Ok;
}

Status AgentUsbIo::abortEndpoint(std::uint32_t generation, std::uint8_t epAddr)
{
    if (const Status g = checkGeneration(generation); g != Status::Ok) return g;

    PipeRow* row = find(epAddr);
    if (!row) return Status::NotFound;

    NSError* err = nil;
    BOOL ok = NO;
    @try {
        // Synchronous: on return the pipe is genuinely quiet, which is what the
        // release path needs before it destroys anything.
        ok = [row->pipe abortWithOption:IOUSBHostAbortOptionSynchronous error:&err];
    } @catch (NSException* ex) {
        logLine("ERROR", @"abort 0x%02x raised %@: %@", epAddr, ex.name, ex.reason);
        return Status::Internal;
    }
    if (!ok) {
        const std::uint32_t ior = static_cast<std::uint32_t>(err ? err.code : kIORetError);
        return fromIOReturn(ior, false);
    }
    return Status::Ok;
}

void AgentUsbIo::closeAll()
{
    if (_pipes.empty() && _interfaces.count == 0) return;

    // Abort every pipe before releasing anything. An in-flight transfer on a pipe
    // whose interface has just been destroyed is how a driver ends up completing
    // into freed memory.
    for (PipeRow& r : _pipes) {
        if (!r.pipe) continue;
        NSError* err = nil;
        @try {
            (void)[r.pipe abortWithOption:IOUSBHostAbortOptionSynchronous error:&err];
        } @catch (NSException* ex) {
            logLine("ERROR", @"abort during close raised %@: %@", ex.name, ex.reason);
        }
        r.pipe = nil;
    }
    _pipes.clear();

    for (IOUSBHostInterface* i in _interfaces) safeDestroy(i, /*surrender=*/false);
    [_interfaces removeAllObjects];
    _interfaces = nil;
}

} // namespace airusb::macos
