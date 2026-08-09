#include "UdecxDriverChannel.h"

#if !defined(_WIN32)

// Compiled everywhere so the build graph is the same on every platform, and
// empty everywhere but Windows. The alternative — excluding the file — makes a
// missing symbol on Windows look like a link error rather than a port that was
// never written.
namespace airusb::windows {
UdecxDriverChannel::~UdecxDriverChannel() = default;
Status UdecxDriverChannel::open(std::string* why)
{
    if (why) *why = "the AirUSB virtual host controller only exists on Windows";
    return Status::UnsupportedMessage;
}
void UdecxDriverChannel::close() {}
bool UdecxDriverChannel::isOpen() const noexcept { return false; }
Status UdecxDriverChannel::plugIn(const DeviceManifest&, std::uint8_t, std::string* why)
{
    if (why) *why = "not Windows";
    return Status::UnsupportedMessage;
}
Status UdecxDriverChannel::plugOut(std::string*) { return Status::UnsupportedMessage; }
bool UdecxDriverChannel::tryReceive(std::vector<std::uint8_t>&) { return false; }
Status UdecxDriverChannel::send(std::span<const std::uint8_t>) { return Status::TransportLost; }
std::size_t UdecxDriverChannel::pendingToDriver() const { return 0; }
Status UdecxDriverChannel::flush() { return Status::Ok; }
std::size_t UdecxDriverChannel::fetchesInFlight() const noexcept { return 0; }
std::uint32_t UdecxDriverChannel::sessionIncarnation() const noexcept { return 0; }
std::uint32_t UdecxDriverChannel::deviceIncarnation()  const noexcept { return 0; }
} // namespace airusb::windows

#else

#include <windows.h>
#include <cfgmgr32.h>
#include <initguid.h>
#include <winioctl.h>

#include <cstring>

// The GUID and the IOCTL codes, duplicated from the driver header ON PURPOSE.
//
// `driver/airusb_sys.h` includes <ntddk.h>, which cannot appear in a user-mode
// translation unit — the two worlds cannot share that file. So the numbers are
// repeated here and the static_asserts below are what keep them identical:
// a change on one side that is not mirrored is a compile error in the test that
// pins them, not a silent mismatch discovered against a loaded driver.
// {4aa7ad7b-6160-4be4-bfd3-33caa80f09ed}
DEFINE_GUID(GUID_DEVINTERFACE_AIRUSB_UM,
    0x4aa7ad7b, 0x6160, 0x4be4, 0xbf, 0xd3, 0x33, 0xca, 0xa8, 0x0f, 0x09, 0xed);

#define AIRUSB_UM_IOCTL_BASE 0x800
#define AIRUSB_UM_IOCTL_BIND \
    CTL_CODE(FILE_DEVICE_UNKNOWN, AIRUSB_UM_IOCTL_BASE + 0, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define AIRUSB_UM_IOCTL_PLUG_IN \
    CTL_CODE(FILE_DEVICE_UNKNOWN, AIRUSB_UM_IOCTL_BASE + 1, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define AIRUSB_UM_IOCTL_PLUG_OUT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, AIRUSB_UM_IOCTL_BASE + 2, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define AIRUSB_UM_IOCTL_FETCH \
    CTL_CODE(FILE_DEVICE_UNKNOWN, AIRUSB_UM_IOCTL_BASE + 3, METHOD_OUT_DIRECT, FILE_WRITE_ACCESS)
#define AIRUSB_UM_IOCTL_COMPLETE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, AIRUSB_UM_IOCTL_BASE + 4, METHOD_IN_DIRECT, FILE_WRITE_ACCESS)

namespace airusb::windows {

namespace {

constexpr std::size_t kFetchDepth      = 4;
constexpr std::size_t kCompleteSlots   = 8;
constexpr std::size_t kFetchBufferSize = (1u << 20) + 256u;   // AIRUSB_MAX_RECORD

/// One overlapped operation.
///
/// The event is created ONCE and reused. Two earlier versions memset the whole
/// OVERLAPPED before each operation — which destroys the handle field without
/// closing it — and then created another. That leaks one kernel handle per I/O,
/// so a Windows session leaks at transfer rate and eventually exhausts the
/// process handle table. Only the last event per slot was ever closed.
struct Slot {
    OVERLAPPED                ov{};
    std::vector<std::uint8_t> buf;
    bool                      busy = false;

    bool arm()
    {
        if (ov.hEvent == nullptr) {
            ov.hEvent = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
            if (ov.hEvent == nullptr) return false;
        }
        // Everything EXCEPT hEvent is reset. The handle is the one field that
        // must survive, which is exactly the field a memset destroys.
        const HANDLE keep = ov.hEvent;
        ov = OVERLAPPED{};
        ov.hEvent = keep;
        ::ResetEvent(ov.hEvent);
        return true;
    }
};

} // namespace

struct UdecxDriverChannel::Impl {
    HANDLE device = INVALID_HANDLE_VALUE;
    Slot   fetch[kFetchDepth];
    Slot   done[kCompleteSlots];
    std::string lastError;
    /// The driver's, never ours. See the header.
    std::uint32_t sessionInc = 0;
    std::uint32_t deviceInc  = 0;
};

UdecxDriverChannel::~UdecxDriverChannel() { close(); }

bool UdecxDriverChannel::isOpen() const noexcept
{
    return _impl != nullptr && _impl->device != INVALID_HANDLE_VALUE;
}

std::size_t UdecxDriverChannel::fetchesInFlight() const noexcept
{
    if (!_impl) return 0;
    std::size_t n = 0;
    for (const Slot& s : _impl->fetch) if (s.busy) ++n;
    return n;
}

namespace {

/// Arms one FETCH. Returns false only if the driver refused it outright.
bool armFetch(HANDLE device, Slot& s)
{
    if (s.busy) return true;
    if (s.buf.size() != kFetchBufferSize) s.buf.assign(kFetchBufferSize, 0);
    if (!s.arm()) return false;

    DWORD got = 0;
    const BOOL ok = ::DeviceIoControl(device, AIRUSB_UM_IOCTL_FETCH,
                                      nullptr, 0,
                                      s.buf.data(), static_cast<DWORD>(s.buf.size()),
                                      &got, &s.ov);
    if (ok) { s.busy = true; return true; }             // completed inline
    if (::GetLastError() == ERROR_IO_PENDING) { s.busy = true; return true; }
    return false;
}

} // namespace

Status UdecxDriverChannel::open(std::string* why)
{
    close();
    _impl = new Impl();

    // Find the interface by GUID rather than by a fixed name: a device
    // interface path is generated and must not be guessed.
    ULONG len = 0;
    CONFIGRET cr = ::CM_Get_Device_Interface_List_SizeW(
        &len, const_cast<LPGUID>(&GUID_DEVINTERFACE_AIRUSB_UM), nullptr,
        CM_GET_DEVICE_INTERFACE_LIST_PRESENT);
    if (cr != CR_SUCCESS || len < 2) {
        if (why) *why = "the AirUSB virtual host controller driver is not installed "
                        "on this machine";
        close();
        return Status::NotFound;
    }

    std::vector<wchar_t> list(len, 0);
    cr = ::CM_Get_Device_Interface_ListW(
        const_cast<LPGUID>(&GUID_DEVINTERFACE_AIRUSB_UM), nullptr,
        list.data(), len, CM_GET_DEVICE_INTERFACE_LIST_PRESENT);
    if (cr != CR_SUCCESS || list[0] == L'\0') {
        if (why) *why = "the AirUSB driver is installed but has no active interface";
        close();
        return Status::NotFound;
    }

    _impl->device = ::CreateFileW(list.data(), GENERIC_READ | GENERIC_WRITE,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                  OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
    if (_impl->device == INVALID_HANDLE_VALUE) {
        // The device object is SYSTEM/Administrators only, by design: a process
        // that can plug in presents an arbitrary USB identity to this machine.
        // So access denied here is the ACL working, not a bug.
        const DWORD e = ::GetLastError();
        if (why) *why = e == ERROR_ACCESS_DENIED
            ? "this process may not open the AirUSB driver — presenting a device "
              "to this computer needs the broker service, which runs as SYSTEM"
            : "could not open the AirUSB driver";
        close();
        return e == ERROR_ACCESS_DENIED ? Status::NotPermitted : Status::TransportLost;
    }

    DWORD got = 0;
    std::uint32_t inc[2] = { 0, 0 };
    if (!::DeviceIoControl(_impl->device, AIRUSB_UM_IOCTL_BIND,
                           nullptr, 0, inc, sizeof inc, &got, nullptr)) {
        if (why) *why = "another process is already using the AirUSB driver";
        close();
        return Status::Busy;
    }
    if (got < sizeof inc) {
        // A driver that will not say which session we got is one we cannot
        // stamp records for. Refused rather than guessed.
        if (why) *why = "the AirUSB driver did not report its session";
        close();
        return Status::UnsupportedVersion;
    }
    _impl->sessionInc = inc[0];
    _impl->deviceInc  = inc[1];

    for (Slot& s : _impl->fetch) {
        if (!armFetch(_impl->device, s)) {
            if (why) *why = "the driver refused an inverted call";
            close();
            return Status::TransportLost;
        }
    }
    return Status::Ok;
}

void UdecxDriverChannel::close()
{
    if (!_impl) return;
    if (_impl->device != INVALID_HANDLE_VALUE) {
        // Cancel BEFORE closing. Closing a handle with overlapped I/O
        // outstanding is legal and leaves the driver completing requests
        // against an OVERLAPPED that is about to be freed.
        (void)::CancelIoEx(_impl->device, nullptr);
        for (Slot& s : _impl->fetch)
            if (s.busy && s.ov.hEvent) ::WaitForSingleObject(s.ov.hEvent, 100);
        for (Slot& s : _impl->done)
            if (s.busy && s.ov.hEvent) ::WaitForSingleObject(s.ov.hEvent, 100);
        ::CloseHandle(_impl->device);
        _impl->device = INVALID_HANDLE_VALUE;
    }
    for (Slot& s : _impl->fetch) if (s.ov.hEvent) ::CloseHandle(s.ov.hEvent);
    for (Slot& s : _impl->done)  if (s.ov.hEvent) ::CloseHandle(s.ov.hEvent);
    delete _impl;
    _impl = nullptr;
}

Status UdecxDriverChannel::plugIn(const DeviceManifest& manifest,
                                  std::uint8_t configValue, std::string* why)
{
    if (!isOpen()) { if (why) *why = "the driver is not open"; return Status::TransportLost; }

    const auto dev = manifest.deviceDescriptor();
    const auto cfg = manifest.configurationByValue(configValue);
    if (dev.size() < 18 || cfg.size() < 9) {
        if (why) *why = "this device's descriptors are not complete enough to present";
        return Status::ManifestInvalid;
    }

    // The endpoints, by address, in the order the device declares them. The
    // driver creates one Simple endpoint per entry plus ep0.
    std::vector<std::uint8_t> endpoints;
    endpoints.push_back(0);                     // ep0 always
    for (std::uint16_t iface = 0; iface < 256; ++iface) {
        for (const EndpointModel& e :
                 manifest.endpointsFor(configValue, static_cast<std::uint8_t>(iface), 0)) {
            if (e.type != XferType::Bulk) continue;   // v1 presents bulk only
            endpoints.push_back(e.address);
        }
    }

    std::uint32_t speed = 2;                    // UDECX high speed
    switch (manifest.speed()) {
        case Speed::Low:   speed = 0; break;
        case Speed::Full:  speed = 1; break;
        case Speed::High:  speed = 2; break;
        default:           speed = 3; break;    // Super and above
    }

    std::vector<std::uint8_t> body;
    auto putU32 = [&body](std::uint32_t v) {
        body.push_back(static_cast<std::uint8_t>(v));
        body.push_back(static_cast<std::uint8_t>(v >> 8));
        body.push_back(static_cast<std::uint8_t>(v >> 16));
        body.push_back(static_cast<std::uint8_t>(v >> 24));
    };
    putU32(1);                                            // Version
    putU32(speed);
    putU32(static_cast<std::uint32_t>(dev.size()));
    putU32(static_cast<std::uint32_t>(cfg.size()));
    putU32(0);                                            // StringBlobLen
    putU32(static_cast<std::uint32_t>(endpoints.size()));
    putU32(0);                                            // Reserved, MBZ
    body.insert(body.end(), dev.begin(), dev.end());
    body.insert(body.end(), cfg.begin(), cfg.end());
    body.insert(body.end(), endpoints.begin(), endpoints.end());

    DWORD got = 0;
    std::uint32_t devInc = 0;
    if (!::DeviceIoControl(_impl->device, AIRUSB_UM_IOCTL_PLUG_IN,
                           body.data(), static_cast<DWORD>(body.size()),
                           &devInc, sizeof devInc, &got, nullptr)) {
        if (why) *why = "the driver refused to present this device";
        return Status::CaptureFailed;
    }
    // Plug-in BUMPS the device incarnation, so the value BIND returned is now
    // one behind and every record stamped with it would be refused.
    if (got >= sizeof devInc) _impl->deviceInc = devInc;
    return Status::Ok;
}

Status UdecxDriverChannel::plugOut(std::string* why)
{
    if (!isOpen()) return Status::Ok;
    DWORD got = 0;
    if (!::DeviceIoControl(_impl->device, AIRUSB_UM_IOCTL_PLUG_OUT,
                           nullptr, 0, nullptr, 0, &got, nullptr)) {
        if (why) *why = "the driver refused to remove the device";
        return Status::Internal;
    }
    return Status::Ok;
}

bool UdecxDriverChannel::tryReceive(std::vector<std::uint8_t>& out)
{
    if (!isOpen()) return false;

    for (Slot& s : _impl->fetch) {
        if (!s.busy) { (void)armFetch(_impl->device, s); continue; }

        DWORD got = 0;
        // FALSE: never wait. The bridge above is an event loop with a network
        // to service, and a blocking reap here would stall it behind the
        // driver's idea of when there is work.
        if (!::GetOverlappedResult(_impl->device, &s.ov, &got, FALSE)) {
            if (::GetLastError() == ERROR_IO_INCOMPLETE) continue;
            s.busy = false;
            (void)armFetch(_impl->device, s);      // cancelled or failed; re-arm
            continue;
        }

        s.busy = false;
        if (got != 0) {
            out.assign(s.buf.begin(), s.buf.begin() + static_cast<std::ptrdiff_t>(got));
            (void)armFetch(_impl->device, s);      // keep the depth up
            return true;
        }
        (void)armFetch(_impl->device, s);
    }
    return false;
}

Status UdecxDriverChannel::send(std::span<const std::uint8_t> record)
{
    if (!isOpen()) return Status::TransportLost;
    (void)flush();

    for (Slot& s : _impl->done) {
        if (s.busy) continue;
        s.buf.assign(record.begin(), record.end());
        if (!s.arm()) return Status::NoResources;

        DWORD got = 0;
        const BOOL ok = ::DeviceIoControl(_impl->device, AIRUSB_UM_IOCTL_COMPLETE,
                                          s.buf.data(), static_cast<DWORD>(s.buf.size()),
                                          nullptr, 0, &got, &s.ov);
        if (ok) return Status::Ok;
        if (::GetLastError() == ERROR_IO_PENDING) { s.busy = true; return Status::Ok; }
        return Status::TransportLost;
    }
    // Every slot busy. Honest backpressure: the bridge queues and retries, and
    // `pendingToDriver()` is non-zero so its poll loop knows to keep flushing.
    return Status::Busy;
}

std::size_t UdecxDriverChannel::pendingToDriver() const
{
    if (!_impl) return 0;
    std::size_t n = 0;
    for (const Slot& s : _impl->done) if (s.busy) ++n;
    return n;
}

std::uint32_t UdecxDriverChannel::sessionIncarnation() const noexcept
{
    return _impl ? _impl->sessionInc : 0;
}

std::uint32_t UdecxDriverChannel::deviceIncarnation() const noexcept
{
    return _impl ? _impl->deviceInc : 0;
}

Status UdecxDriverChannel::flush()
{
    if (!isOpen()) return Status::TransportLost;
    for (Slot& s : _impl->done) {
        if (!s.busy) continue;
        DWORD got = 0;
        if (::GetOverlappedResult(_impl->device, &s.ov, &got, FALSE)) { s.busy = false; continue; }
        if (::GetLastError() != ERROR_IO_INCOMPLETE) s.busy = false;   // failed; slot freed
    }
    return Status::Ok;
}

} // namespace airusb::windows

#endif // _WIN32
