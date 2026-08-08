#include "HostDeviceExporter.h"
#include "MacUsbCommon.h"
#include "StatusMapMacos.h"

#import <IOKit/IOKitLib.h>
#import <IOKit/usb/IOUSBHostFamilyDefinitions.h>

#include "../../core/Watchdog.h"

#include <sys/stat.h>
#include <unistd.h>

namespace airusb::macos {

namespace {

/// The daemon's IPC deadline. It must EXCEED the agent's own transfer ceiling,
/// or the daemon gives up on a transfer the agent is still legitimately running
/// and the two disagree about whether it happened. Same ordering rule as
/// T_urb_ceiling_bulk < T_urb_watchdog_importer, one layer down.
constexpr std::uint32_t kIpcCallTimeoutMs =
    static_cast<std::uint32_t>(watchdog::kUrbCeilingBulk) + 5000u;

static_assert(kIpcCallTimeoutMs > watchdog::kUrbCeilingBulk,
              "the daemon must not time out before the agent's transfer ceiling");

constexpr std::uint32_t kControlTimeoutMs = static_cast<std::uint32_t>(watchdog::kNetCtrl);

/// Enough for any configuration or BOS descriptor a real device publishes, and
/// bounded so a malfunctioning device cannot make us ask for an absurd length.
constexpr std::size_t kDescriptorFetchMax = 4096;

std::uint16_t rd16le(const std::uint8_t* p) noexcept
{
    return static_cast<std::uint16_t>(p[0] | (static_cast<std::uint16_t>(p[1]) << 8));
}

} // namespace

std::uint32_t consoleUid() noexcept
{
    struct stat st {};
    if (::stat("/dev/console", &st) == 0) return static_cast<std::uint32_t>(st.st_uid);
    return 0xFFFFFFFFu;
}

// ---------------------------------------------------------------------------

HostDeviceExporter::~HostDeviceExporter() { release(); }

// ---------------------------------------------------------------------------
// attach
// ---------------------------------------------------------------------------

Status HostDeviceExporter::attach(const ExporterConfig& cfg, std::string* whyNot)
{
    const auto fail = [&](Status s, const std::string& msg) {
        if (whyNot) *whyNot = msg;
        logLine("ERROR", @"attach failed: %s", msg.c_str());
        release();
        return s;
    };

    if (geteuid() != 0)
        return fail(Status::NotPermitted,
                    "the exporter daemon must run as root: DeviceCapture and "
                    "whole-disk unmount both require it");

    // ---- 1. locate ---------------------------------------------------------
    _service = findDeviceByVidPid(cfg.vendorId, cfg.productId);
    if (!_service)
        return fail(Status::NotFound, "device not found in the IORegistry");

    _locationId = locationIdOf(_service);
    NSString* product = propStr(_service, CFSTR("USB Product Name"));
    logLine("ATTACH", @"target %04x:%04x '%@' locationID=0x%08X speed=%s",
            cfg.vendorId, cfg.productId, (product ? product : @"?"), _locationId,
            describeSpeed(_service).c_str());

    // ---- 2+3. claim and unmount, before anything is captured ---------------
    //
    // Order matters: we never capture a mounted device. Capturing one evicts
    // IOUSBMassStorageDriver out from under a filesystem holding dirty buffers.
    std::string diskWhy;
    if (const Status s = _disks.claimAndUnmount(_service, &diskWhy); s != Status::Ok)
        return fail(s, diskWhy.empty() ? "claim/unmount failed" : diskWhy);

    // ---- 4. capture ---------------------------------------------------------
    logLine("ATTACH", @"capturing with IOUSBHostObjectInitOptionsDeviceCapture");
    std::uint32_t ior = 0;
    std::string   why;
    _device = safeInitDevice(_service, IOUSBHostObjectInitOptionsDeviceCapture, &ior, &why);
    if (!_device) {
        // Protocol-visible handling per §7.4: ATTACH_OK{status = CAPTURE_FAILED}
        // plus TLV NATIVE_STATUS carrying this IOReturn. Nothing has been
        // announced yet, so the unwind below simply hands the drive back.
        NSString* m = [NSString stringWithFormat:@"device capture failed: 0x%08X %s — %s",
                       ior, ioReturnName(ior), why.c_str()];
        return fail(Status::CaptureFailed, std::string(m.UTF8String));
    }
    logLine("ATTACH", @"RESULT=DEVICE_CAPTURED");

    // ---- 5. configure with matchInterfaces:NO ------------------------------
    //
    // The capture terminated every driver and client of this device, including
    // the IOUSBHostInterface nubs, so they must be republished. matchInterfaces
    // is ALWAYS NO: passing YES invites IOUSBMassStorageDriver to match and mount
    // the drive locally while it is leased out, which is a direct two-mount
    // corruption path.
    {
        NSError* de = nil;
        const IOUSBConfigurationDescriptor* cd =
            [_device configurationDescriptorWithIndex:0 error:&de];
        if (!cd)
            return fail(Status::ManifestInvalid,
                        "configurationDescriptorWithIndex:0 failed: " + describeError(de));

        _configValue = cd->bConfigurationValue;
        logLine("ENUM", @"config[0]: bConfigurationValue=%u wTotalLength=%u interfaces=%u",
                cd->bConfigurationValue, rd16le(reinterpret_cast<const std::uint8_t*>(cd) + 2),
                cd->bNumInterfaces);

        // Unconfigure first so the re-select is a real configuration change even
        // if the device already reports this value. Failure is tolerated and
        // logged: some devices refuse configuration 0, and the select below is
        // what actually matters.
        NSError* ze = nil;
        if (![_device configureWithValue:0 matchInterfaces:NO error:&ze])
            logLine("ATTACH", @"configureWithValue:0 declined (%s) — continuing",
                    describeError(ze).c_str());

        NSError* ce = nil;
        logLine("ATTACH", @"configureWithValue:%u matchInterfaces:NO", _configValue);
        if (![_device configureWithValue:_configValue matchInterfaces:NO error:&ce])
            return fail(fromIOReturn(static_cast<std::uint32_t>(ce ? ce.code : kIORetError), false),
                        "configureWithValue failed: " + describeError(ce));
    }

    // ---- 8. manifest --------------------------------------------------------
    if (const Status s = buildManifest(whyNot); s != Status::Ok) {
        release();
        return s;
    }

    // ---- 6+7. the agent opens the interfaces and builds the pipe table ------
    if (const Status s = waitForAgent(cfg, whyNot); s != Status::Ok) {
        release();
        return s;
    }

    _leaseStartNs = Clock::system().nowNs();
    logLine("ATTACH", @"RESULT=ATTACHED locationID=0x%08X config=%u endpoints=%zu "
                       "generation=%u",
            _locationId, _configValue, _pipes.endpoints.size(), _pipes.generation);
    return Status::Ok;
}

// ---------------------------------------------------------------------------
// manifest
// ---------------------------------------------------------------------------

Status HostDeviceExporter::fetchDescriptor(std::uint8_t type, std::uint8_t index,
                                           std::uint16_t langId, std::size_t hint,
                                           std::vector<std::uint8_t>& out)
{
    out.clear();
    NSUInteger length = hint ? hint : kDescriptorFetchMax;
    NSError* err = nil;

    const IOUSBDescriptor* d = nil;
    @try {
        d = [_device descriptorWithType:static_cast<tIOUSBDescriptorType>(type)
                                 length:&length
                                  index:index
                             languageID:langId
                                  error:&err];
    } @catch (NSException* ex) {
        // MEASURED ON REAL HARDWARE, 2026-08-08, during the P2.8 gate run:
        //
        //   descriptorWithType:6 raised NSInvalidArgumentException:
        //   -[__NSPlaceholderDictionary initWithObjects:forKeys:count:]:
        //   attempt to insert nil object from objects[0]
        //
        // This is the SAME Apple defect P1_CAPTURE_VERIFICATION.md diagnosed on
        // -[IOUSBHostObject openWithOptions:error:], and it is therefore not
        // specific to the open path: when the device STALLs a descriptor request,
        // the framework builds an NSError userInfo from -[NSBundle
        // localizedStringForKey:] results and raises because the first is nil.
        //
        // Without this @catch a root daemon would die here holding a captured,
        // unmounted drive. That is why every call into IOUSBHost is wrapped, and
        // this log line is the evidence that the rule earns its keep.
        logLine("ERROR", @"descriptorWithType:%u raised %@: %@ — Apple's error path "
                          "raised instead of returning NSError (the same defect as "
                          "openWithOptions:). Caught; the daemon continues.",
                type, ex.name, ex.reason);
        return Status::Internal;
    }
    if (!d) return fromIOReturn(static_cast<std::uint32_t>(err ? err.code : kIORetError), false);

    const std::uint8_t* p = reinterpret_cast<const std::uint8_t*>(d);

    // Take the length from the descriptor itself, cross-checked against what the
    // framework reported. A descriptor blob travels verbatim to the importer, so
    // copying more than the device published would put uninitialised bytes on the
    // wire, and copying less would truncate a configuration.
    std::size_t total = p[0];
    if (type == kIOUSBDescriptorTypeConfiguration ||
        type == kIOUSBDescriptorTypeOtherSpeedConfiguration ||
        type == kIOUSBDescriptorTypeBOS) {
        total = rd16le(p + 2);
    }
    if (total == 0 || total > kDescriptorFetchMax) {
        logLine("ERROR", @"descriptor type %u index %u declares an implausible "
                          "length %zu", type, index, total);
        return Status::ManifestInvalid;
    }
    if (total > length) {
        logLine("ERROR", @"descriptor type %u index %u declares %zu bytes but the "
                          "framework returned %lu", type, index, total,
                (unsigned long)length);
        return Status::ManifestInvalid;
    }

    out.assign(p, p + total);
    return Status::Ok;
}

Status HostDeviceExporter::buildManifest(std::string* whyNot)
{
    const auto fail = [&](const std::string& msg) {
        if (whyNot) *whyNot = msg;
        logLine("ERROR", @"manifest: %s", msg.c_str());
        return Status::ManifestInvalid;
    };

    _manifest = DeviceManifest{};
    _manifest.setSpeed(readSpeed(_service));

    // ---- device descriptor --------------------------------------------------
    const IOUSBDeviceDescriptor* dd = _device.deviceDescriptor;
    if (!dd) return fail("the device returned no device descriptor");

    const std::uint8_t* ddp = reinterpret_cast<const std::uint8_t*>(dd);
    if (ddp[0] < 18) return fail("device descriptor shorter than 18 bytes");
    _manifest.setDeviceDescriptor(std::span<const std::uint8_t>(ddp, 18));

    logLine("ENUM", @"deviceDescriptor: USB %04x class=%02x/%02x/%02x VID=%04x "
                     "PID=%04x bcdDevice=%04x ep0MaxPacket=%u configs=%u",
            rd16le(ddp + 2), ddp[4], ddp[5], ddp[6], rd16le(ddp + 8), rd16le(ddp + 10),
            rd16le(ddp + 12), ddp[7], ddp[17]);

    const std::uint8_t numConfigs = ddp[17];
    if (numConfigs == 0) return fail("the device declares zero configurations");

    // ---- every configuration, verbatim and complete -------------------------
    std::vector<std::uint8_t> blob;
    for (std::uint8_t i = 0; i < numConfigs; ++i) {
        if (const Status s = fetchDescriptor(kIOUSBDescriptorTypeConfiguration, i, 0,
                                             kDescriptorFetchMax, blob); s != Status::Ok)
            return fail("could not read configuration descriptor " + std::to_string(i));
        _manifest.addConfiguration(blob);
        logLine("ENUM", @"config[%u]: %zu bytes verbatim", i, blob.size());
    }

    // ---- BOS, if the device has one ----------------------------------------
    //
    // A SuperSpeed device must have one; a USB 2 device legitimately stalls the
    // request. Absence is a fact to record, not a failure.
    if (const IOUSBBOSDescriptor* bos = _device.capabilityDescriptors; bos) {
        const std::uint8_t* bp = reinterpret_cast<const std::uint8_t*>(bos);
        const std::size_t total = rd16le(bp + 2);
        if (total >= 5 && total <= kDescriptorFetchMax) {
            _manifest.setBos(std::span<const std::uint8_t>(bp, total));
            logLine("ENUM", @"BOS: %zu bytes, %u capabilities", total, bp[4]);
        } else {
            logLine("ERROR", @"BOS declares an implausible length %zu — omitted", total);
        }
    } else {
        logLine("ENUM", @"no BOS descriptor (expected on USB 2 devices)");
    }

    // ---- device qualifier: high-speed-capable USB 2.0 devices only ----------
    //
    // USB 2.0 §9.6.2 defines this descriptor only for devices capable of
    // high-speed operation, and USB 3.2 does not define it for SuperSpeed at all.
    // Asking a SuperSpeed device for it earns a STALL — and on macOS 26.5.1 that
    // STALL makes descriptorWithType: RAISE rather than return an error (see
    // fetchDescriptor). The exception is caught, but there is no reason to
    // provoke a known-buggy Apple path to ask a question the specification has
    // already answered.
    const Speed sp = _manifest.speed();
    if (sp == Speed::Full || sp == Speed::High) {
        if (fetchDescriptor(kIOUSBDescriptorTypeDeviceQualifier, 0, 0, 10, blob) == Status::Ok)
            _manifest.setDeviceQualifier(blob);
        else
            logLine("ENUM", @"no device qualifier descriptor (the device does not "
                             "publish one)");
    } else {
        logLine("ENUM", @"device qualifier not requested: undefined at %s",
                speedName(sp));
    }

    // ---- strings ------------------------------------------------------------
    //
    // Index 0 is the LANGID table, not a string. Conflating the two is a classic
    // enumeration bug and produces a manifest whose "manufacturer" is a list of
    // language codes.
    std::vector<std::uint16_t> langIds;
    if (fetchDescriptor(kIOUSBDescriptorTypeString, 0, 0, 256, blob) == Status::Ok &&
        blob.size() >= 4) {
        _manifest.setLangIds({});                       // set below, after parsing
        for (std::size_t at = 2; at + 1 < blob.size(); at += 2)
            langIds.push_back(rd16le(blob.data() + at));
        _manifest.setLangIds(langIds);
        logLine("ENUM", @"LANGID table: %zu entries, first 0x%04x",
                langIds.size(), langIds.empty() ? 0 : langIds[0]);
    } else {
        logLine("ENUM", @"no string descriptors (the device publishes none)");
    }

    if (!langIds.empty()) {
        const std::uint16_t lang = langIds[0];

        // Collect every string index the descriptors actually reference, rather
        // than probing 1..255 and provoking a stall for each absent one.
        std::vector<std::uint8_t> wanted;
        const auto want = [&](std::uint8_t idx) {
            if (idx == 0) return;
            for (std::uint8_t v : wanted) if (v == idx) return;
            wanted.push_back(idx);
        };
        want(ddp[14]);   // iManufacturer
        want(ddp[15]);   // iProduct
        want(ddp[16]);   // iSerialNumber

        for (std::size_t ci = 0; ci < _manifest.configurationCount(); ++ci) {
            const auto cfg = _manifest.configurationByIndex(static_cast<std::uint8_t>(ci));
            forEachDescriptor(cfg, [&](std::uint8_t type, std::span<const std::uint8_t> d) {
                if (type == kDescConfiguration && d.size() >= 9) want(d[6]);   // iConfiguration
                else if (type == kDescInterface && d.size() >= 9) want(d[8]);  // iInterface
                return true;
            });
        }

        for (std::uint8_t idx : wanted) {
            if (fetchDescriptor(kIOUSBDescriptorTypeString, idx, lang, 256, blob) == Status::Ok)
                _manifest.addString(idx, lang, blob);
        }
        logLine("ENUM", @"string descriptors: %zu referenced index(es) fetched",
                wanted.size());
    }

    // ---- validate -----------------------------------------------------------
    //
    // Every bLength/wTotalLength walk is re-validated here, and the descriptors
    // are cross-checked against the declared speed. This is what turns the
    // USBSpeed/Device Speed enumeration trap into a hard failure rather than a
    // silent USB 2 downgrade of a SuperSpeed device.
    std::string mwhy;
    if (const Status v = _manifest.validate(&mwhy); v != Status::Ok)
        return fail("manifest validation failed: " + mwhy);

    logLine("ATTACH", @"RESULT=MANIFEST_OK speed=%s configs=%zu bytes=%zu",
            speedName(_manifest.speed()), _manifest.configurationCount(),
            _manifest.byteSize());
    return Status::Ok;
}

// ---------------------------------------------------------------------------
// the agent
// ---------------------------------------------------------------------------

Status HostDeviceExporter::waitForAgent(const ExporterConfig& cfg, std::string* whyNot)
{
    const auto fail = [&](Status s, const std::string& msg) {
        if (whyNot) *whyNot = msg;
        logLine("ERROR", @"agent: %s", msg.c_str());
        return s;
    };

    _socketPath = cfg.socketPath;

    Status st = Status::Ok;
    // 0666 on the socket, with the real access decision made by uid check below.
    // A permissive mode plus a kernel-verified peer uid is strictly safer than a
    // restrictive mode plus a trusted self-reported identity.
    _listenFd = ipc::listenOnUnixSocket(_socketPath, 0666, st);
    if (_listenFd < 0)
        return fail(st, "could not listen on " + _socketPath);
    logLine("ATTACH", @"listening on %s, waiting up to %u ms for the agent",
            _socketPath.c_str(), cfg.agentWaitMs);

    const std::uint32_t expectUid = (cfg.allowedUid == 0xFFFFFFFFu) ? consoleUid()
                                                                    : cfg.allowedUid;

    for (;;) {
        std::uint32_t peerUid = 0xFFFFFFFFu, peerPid = 0;
        const int fd = ipc::acceptOne(_listenFd, cfg.agentWaitMs, &peerUid, &peerPid, st);
        if (fd < 0) return fail(st, "no agent connected");

        // The uid comes from getpeereid(2) — the kernel's own record — not from
        // anything the peer said. The daemon runs as root; believing a
        // self-reported identity would make this check decorative.
        if (expectUid != 0xFFFFFFFFu && peerUid != expectUid) {
            logLine("ERROR", @"rejecting a connection from uid %u pid %u; only the "
                              "console user (uid %u) may drive this daemon",
                    peerUid, peerPid, expectUid);
            ::close(fd);
            continue;
        }

        logLine("ATTACH", @"agent connected: uid=%u pid=%u", peerUid, peerPid);
        _link = ipc::AgentLink(fd);
        _agentLost = false;
        break;
    }

    // ---- handshake ----------------------------------------------------------
    {
        ipc::HelloBody mine;
        mine.protocolVersion = ipc::kProtocolVersion;
        mine.pid  = static_cast<std::uint32_t>(::getpid());
        mine.euid = static_cast<std::uint32_t>(::geteuid());

        std::vector<std::uint8_t> body;
        ipc::encodeHello(mine, body);

        ipc::Frame rep;
        if (const Status s = _link.call(ipc::Op::Hello, body, 5000, rep); s != Status::Ok)
            return fail(s, "the agent did not answer HELLO");

        ipc::HelloBody theirs;
        if (!ipc::decodeHello(rep.body, theirs))
            return fail(Status::MalformedFrame, "the agent's HELLO was malformed");

        if (theirs.protocolVersion != ipc::kProtocolVersion) {
            // Both halves ship together, so a version skew means a botched
            // install rather than a peer to be accommodated.
            NSString* m = [NSString stringWithFormat:@"agent speaks IPC version %u, "
                           "this daemon speaks %u — the two halves are from "
                           "different builds", theirs.protocolVersion, ipc::kProtocolVersion];
            return fail(Status::UnsupportedVersion, std::string(m.UTF8String));
        }
        logLine("ATTACH", @"agent handshake ok: pid=%u euid=%u", theirs.pid, theirs.euid);
    }

    // ---- open the interfaces --------------------------------------------------
    {
        ipc::OpenBody ob;
        ob.locationId  = _locationId;
        ob.configValue = _configValue;

        std::vector<std::uint8_t> body;
        ipc::encodeOpen(ob, body);

        ipc::Frame rep;
        if (const Status s = _link.call(ipc::Op::OpenInterfaces, body, 20000, rep);
            s != Status::Ok)
            return fail(s, "OPEN_INTERFACES did not complete");

        if (rep.status != Status::Ok) {
            NSString* m = [NSString stringWithFormat:@"the agent could not open the "
                           "interfaces: %s", statusName(rep.status)];
            return fail(rep.status, std::string(m.UTF8String));
        }
        if (!ipc::decodePipeTable(rep.body, _pipes))
            return fail(Status::MalformedFrame, "the agent's pipe table was malformed");
        if (_pipes.endpoints.empty())
            return fail(Status::CaptureFailed, "the agent opened no endpoints");

        logLine("ATTACH", @"pipe table generation %u with %zu endpoint(s)",
                _pipes.generation, _pipes.endpoints.size());
    }

    return Status::Ok;
}

Status HostDeviceExporter::rebuildPipeTable(std::string* whyNot)
{
    if (!agentAlive()) {
        if (whyNot) *whyNot = "the agent is gone";
        return Status::TransportLost;
    }

    ipc::Frame rep;
    const Status s = _link.call(ipc::Op::RebuildPipes, {}, 20000, rep);
    if (s != Status::Ok) { noteAgentLost("rebuildPipeTable"); return s; }
    if (rep.status != Status::Ok) {
        if (whyNot) *whyNot = statusName(rep.status);
        return rep.status;
    }
    if (!ipc::decodePipeTable(rep.body, _pipes)) return Status::MalformedFrame;

    logLine("ATTACH", @"adopted pipe table generation %u", _pipes.generation);
    return Status::Ok;
}

void HostDeviceExporter::noteAgentLost(const char* where)
{
    if (_agentLost) return;
    _agentLost = true;
    logLine("ERROR", @"the agent died during %@ — the capture will be released and "
                      "the drive handed back", @(where));
}

bool HostDeviceExporter::waitWhileAgentAlive(std::uint32_t ms)
{
    if (!agentAlive()) return false;

    // The agent has nothing to say unprompted, so any readable byte is either a
    // protocol violation or, far more likely, EOF because it exited.
    ipc::Frame f;
    const Status s = _link.receive(f, ms);
    if (s == Status::XferTimeout) return true;
    noteAgentLost("idle wait");
    return false;
}

// ---------------------------------------------------------------------------
// IUsbDevicePort
// ---------------------------------------------------------------------------

Status HostDeviceExporter::controlTransfer(const SetupPacket& setup,
                                           std::span<const std::uint8_t> dataOut,
                                           std::vector<std::uint8_t>& dataIn)
{
    dataIn.clear();
    if (!_device) return Status::DeviceGone;

    IOUSBDeviceRequest req {};
    req.bmRequestType = setup.bmRequestType;
    req.bRequest      = setup.bRequest;
    req.wValue        = setup.wValue;
    req.wIndex        = setup.wIndex;
    req.wLength       = setup.wLength;

    const bool in = setup.direction() == Dir::In;
    NSMutableData* buf = nil;
    if (setup.wLength > 0) {
        buf = [NSMutableData dataWithLength:setup.wLength];
        if (!in) {
            if (dataOut.size() < setup.wLength) return Status::BadArgument;
            std::memcpy(buf.mutableBytes, dataOut.data(), setup.wLength);
        }
    }

    NSUInteger moved = 0;
    NSError* err = nil;
    BOOL ok = NO;
    @try {
        ok = [_device sendDeviceRequest:req
                                   data:buf
                       bytesTransferred:&moved
                      completionTimeout:static_cast<NSTimeInterval>(kControlTimeoutMs) / 1000.0
                                  error:&err];
    } @catch (NSException* ex) {
        logLine("ERROR", @"control transfer raised %@: %@", ex.name, ex.reason);
        return Status::Internal;
    }

    if (!ok) {
        const std::uint32_t ior = static_cast<std::uint32_t>(err ? err.code : kIORetError);
        const Status s = fromIOReturn(ior, true);
        logLine("XFER", @"CTRL %02x %02x wValue=%04x wIndex=%04x wLength=%u -> "
                         "0x%08X %s (%s)",
                setup.bmRequestType, setup.bRequest, setup.wValue, setup.wIndex,
                setup.wLength, ior, ioReturnName(ior), statusName(s));
        return s;
    }

    if (in && buf) {
        // Rule A-4 and R5: a response never exceeds wLength, and the length is
        // taken from what the device actually sent.
        if (moved > setup.wLength) return Status::XferOverrun;
        const std::uint8_t* p = static_cast<const std::uint8_t*>(buf.bytes);
        dataIn.assign(p, p + moved);
    }
    return Status::Ok;
}

Status HostDeviceExporter::bulkOut(std::uint8_t epAddr,
                                   std::span<const std::uint8_t> data,
                                   std::uint32_t* actualLen)
{
    if (actualLen) *actualLen = 0;
    if (!agentAlive()) return Status::DeviceGone;
    if (data.size() > ipc::kMaxTransferBytes) return Status::LimitExceeded;

    ipc::XferReq req;
    req.generation = _pipes.generation;
    req.epAddr     = epAddr;
    req.timeoutMs  = static_cast<std::uint32_t>(watchdog::kUrbCeilingBulk);
    req.length     = static_cast<std::uint32_t>(data.size());

    std::vector<std::uint8_t> body;
    body.reserve(ipc::kXferReqSize + data.size());
    ipc::encodeXferReq(req, data, body);

    ipc::Frame rep;
    const Status s = _link.call(ipc::Op::BulkOut, body, kIpcCallTimeoutMs, rep);
    if (s != Status::Ok) { noteAgentLost("bulkOut"); return Status::DeviceGone; }
    if (rep.status != Status::Ok) return rep.status;

    std::uint32_t moved = 0;
    if (!ipc::decodeActualLen(rep.body, moved)) return Status::MalformedFrame;

    // R5, re-asserted at the copy site rather than only at the decoder: the
    // device cannot have accepted more than was offered to it.
    if (moved > data.size()) return Status::XferOverrun;
    if (actualLen) *actualLen = moved;
    return Status::Ok;
}

Status HostDeviceExporter::bulkIn(std::uint8_t epAddr, std::uint32_t maxLen,
                                  std::vector<std::uint8_t>& out)
{
    out.clear();
    if (!agentAlive()) return Status::DeviceGone;
    if (maxLen == 0 || maxLen > ipc::kMaxTransferBytes) return Status::BadArgument;

    ipc::XferReq req;
    req.generation = _pipes.generation;
    req.epAddr     = epAddr;
    req.timeoutMs  = static_cast<std::uint32_t>(watchdog::kUrbCeilingBulk);
    req.length     = maxLen;

    std::vector<std::uint8_t> body;
    ipc::encodeXferReq(req, {}, body);

    ipc::Frame rep;
    const Status s = _link.call(ipc::Op::BulkIn, body, kIpcCallTimeoutMs, rep);
    if (s != Status::Ok) { noteAgentLost("bulkIn"); return Status::DeviceGone; }
    if (rep.status != Status::Ok) return rep.status;

    // R5 again. The agent is trusted no further than the LAN peer is: a reply
    // longer than the buffer the caller offered is refused, not truncated, so a
    // caller that sized a kernel buffer from maxLen cannot be overrun.
    if (rep.body.size() > maxLen) return Status::XferOverrun;

    out = std::move(rep.body);
    return Status::Ok;
}

Status HostDeviceExporter::clearHalt(std::uint8_t epAddr)
{
    // Endpoint 0 does not hold a persistent halt: a control STALL is per-transfer.
    // Answering locally keeps a stalled class request (GET_MAX_LUN on a
    // single-LUN device is the common one) from becoming an IPC round trip.
    if ((epAddr & 0x7Fu) == 0) return Status::Ok;

    if (!agentAlive()) return Status::DeviceGone;

    ipc::EpRef ref;
    ref.generation = _pipes.generation;
    ref.epAddr     = epAddr;

    std::vector<std::uint8_t> body;
    ipc::encodeEpRef(ref, body);

    ipc::Frame rep;
    const Status s = _link.call(ipc::Op::ClearHalt, body, 10000, rep);
    if (s != Status::Ok) { noteAgentLost("clearHalt"); return Status::DeviceGone; }
    return rep.status;
}

// ---------------------------------------------------------------------------
// release
// ---------------------------------------------------------------------------

void HostDeviceExporter::release()
{
    // ---- 1. the agent lets go of the pipes and interfaces ------------------
    if (_link.valid()) {
        if (!_agentLost) {
            ipc::Frame rep;
            const Status s = _link.call(ipc::Op::Close, {},
                                        static_cast<std::uint32_t>(watchdog::kDrainGraceful) + 3000,
                                        rep);
            if (s != Status::Ok)
                logLine("ERROR", @"the agent did not acknowledge CLOSE (%s); "
                                  "releasing anyway", statusName(s));
        }
        _link.close();
    }
    if (_listenFd >= 0) {
        ::close(_listenFd);
        _listenFd = -1;
        if (!_socketPath.empty()) (void)::unlink(_socketPath.c_str());
    }
    _pipes = ipc::PipeTable{};

    // ---- 2. plain destroy, NOT surrender -----------------------------------
    //
    // Plain destroy resets the device and re-registers its drivers for matching,
    // which is exactly what makes the local OS remount the stick.
    // DestroyOptionsDeviceSurrender does the opposite and is correct only when
    // honouring kUSBHostMessageDeviceIsRequestingClose.
    if (_device) {
        logLine("DETACH", @"destroying the captured device (reset + driver rematch)");
        safeDestroy(_device, /*surrender=*/false);
        _device = nil;
    }

    // ---- 3. only now unclaim ------------------------------------------------
    //
    // Unclaiming before the destroy would reopen the automount window while the
    // device is still captured.
    _disks.release();

    if (_service) {
        IOObjectRelease(_service);
        _service = 0;
    }

    if (_leaseStartNs != 0) {
        const ContinuousNs held = Clock::system().nowNs() - _leaseStartNs;
        logLine("DETACH", @"RESULT=RESTORED lease held %.1f s — the OS should "
                           "re-enumerate and remount shortly",
                static_cast<double>(held) / 1e9);
        _leaseStartNs = 0;
    }
}

} // namespace airusb::macos
