#include "VhciPresenter.h"

#include "LinuxUsb.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>

#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

namespace airusb::linuxvhci {

namespace {

constexpr const char* kVhciDir = "/sys/devices/platform/vhci_hcd.0";

bool readWhole(const std::string& path, std::string& out)
{
    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return false;
    char buf[8192];
    const std::size_t n = std::fread(buf, 1, sizeof buf, f);
    std::fclose(f);
    out.assign(buf, n);
    return true;
}

/// vhci-hcd splits its ports by speed: the first half is USB2, the second USB3.
/// Choosing from the wrong half is ACCEPTED by the kernel and then the kernel
/// disagrees with itself about where the device is.
int pickPort(KernelSpeed speed, std::string& why)
{
    std::string status;
    if (!readWhole(std::string(kVhciDir) + "/status", status)) {
        why = "cannot read vhci-hcd's status — is the module loaded? "
              "(sudo modprobe vhci-hcd)";
        return -1;
    }
    const bool wantSs = isSuperSpeedHalf(speed);

    std::size_t pos = status.find('\n');
    if (pos == std::string::npos) { why = "vhci-hcd's status has no rows"; return -1; }
    ++pos;

    while (pos < status.size()) {
        const std::size_t eol = status.find('\n', pos);
        const std::string row = status.substr(pos, eol == std::string::npos
                                                   ? std::string::npos : eol - pos);
        pos = (eol == std::string::npos) ? status.size() : eol + 1;

        char hub[8] = {};
        int port = -1, sta = -1;
        if (std::sscanf(row.c_str(), "%7s %d %d", hub, &port, &sta) != 3) continue;
        if ((std::strcmp(hub, "ss") == 0) != wantSs) continue;
        if (sta != 4) continue;                       // 4 == free
        return port;
    }
    why = wantSs ? "every SuperSpeed port on the virtual hub is in use"
                 : "every high-speed port on the virtual hub is in use";
    return -1;
}

bool writeAttach(int port, int sockfd, unsigned devid, KernelSpeed speed, std::string& why)
{
    char line[128];
    const int n = std::snprintf(line, sizeof line, "%d %d %u %d",
                                port, sockfd, devid, static_cast<int>(speed));
    const int fd = ::open((std::string(kVhciDir) + "/attach").c_str(), O_WRONLY);
    if (fd < 0) {
        why = std::string("cannot open vhci-hcd's attach file: ") + std::strerror(errno) +
              " — this needs to run as root";
        return false;
    }
    const ssize_t w = ::write(fd, line, static_cast<std::size_t>(n));
    const int err = errno;
    ::close(fd);
    if (w != n) {
        why = std::string("the kernel refused the attach: ") + std::strerror(err);
        if (err == EBUSY) why += " — that port was taken between choosing it and using it";
        return false;
    }
    return true;
}

} // namespace

VhciPresenter::~VhciPresenter() { withdraw(); }

bool VhciPresenter::canPresent() const noexcept
{
    // Looked at, not assumed. A hub started by an ordinary user, or one running
    // on a kernel built without CONFIG_USB_SUPPORT, has to say so BEFORE
    // somebody clicks Attach — the window renders `whyNot()` and the person
    // gets a sentence instead of a failure.
    std::string status;
    if (!readWhole(std::string(kVhciDir) + "/status", status)) return false;
    return ::access((std::string(kVhciDir) + "/attach").c_str(), W_OK) == 0;
}

std::string VhciPresenter::whyNot() const
{
    std::string status;
    if (!readWhole(std::string(kVhciDir) + "/status", status))
        return "The virtual USB host controller is not available on this kernel. "
               "Load it with `sudo modprobe vhci-hcd`; on Ubuntu 24.04 it is in "
               "the linux-modules-extra package.";
    if (::access((std::string(kVhciDir) + "/attach").c_str(), W_OK) != 0)
        return "This process cannot write to the virtual USB host controller. "
               "Presenting a device to this computer needs root.";
    return {};
}

Status VhciPresenter::present(session::ImporterClient& client,
                              session::ImporterClient::BridgeAttach& attached,
                              std::string* why)
{
    auto fail = [&](Status s, std::string m) {
        _last = std::move(m);
        if (why) *why = _last;
        withdraw();
        return s;
    };

    (void)client;
    if (_bridge) return fail(Status::Busy, "a device is already presented");
    if (!attached.link) return fail(Status::TransportLost, "the session has no link");

    // NOT a cast. airusb::Speed and usb_device_speed agree on High and disagree
    // on everything else; see LinuxUsb.h and the table test that asserts the
    // disagreement.
    const KernelSpeed kspeed = toKernelSpeed(attached.speed);
    if (kspeed == KernelSpeed::Unknown)
        return fail(Status::SpeedUnsupported,
                    "this device's link speed cannot be expressed to Linux");

    int sv[2] = { -1, -1 };
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
        return fail(Status::NoResources,
                    std::string("socketpair: ") + std::strerror(errno));

    std::string pw;
    const int vport = pickPort(kspeed, pw);
    if (vport < 0) {
        ::close(sv[0]); ::close(sv[1]);
        return fail(Status::NoResources, pw);
    }

    if (!writeAttach(vport, sv[1], 0x00020002u, kspeed, pw)) {
        ::close(sv[0]); ::close(sv[1]);
        return fail(Status::CaptureFailed, pw);
    }
    // The kernel holds its own reference now. Ours has to go, or the socket
    // never sees EOF and the port is left attached to nothing.
    ::close(sv[1]);

    // OUR end must be non-blocking, or FdStream's read/write would block the
    // broker's single loop and re-open the deadlock the whole design closes:
    // vhci-hcd drives one socket with two kthreads, and a bridge that blocks on
    // the network while the kernel's send window fills wedges both sides into
    // an unkillable D-state and a reboot.
    const int fl = ::fcntl(sv[0], F_GETFL, 0);
    (void)::fcntl(sv[0], F_SETFL, (fl < 0 ? 0 : fl) | O_NONBLOCK);

    _sock   = sv[0];
    _port   = vport;
    _stream = std::make_unique<FdStream>(_sock);

    session::ImporterDataPlane::Config pc;
    pc.attachId         = attached.attachId;
    pc.attachSlot       = attached.slot;
    pc.maxInFlight      = 1;              // usb-storage is can_queue = 1
    pc.maxTransferBytes = attached.maxTransferBytes;
    _plane = std::make_unique<session::ImporterDataPlane>(attached.link, &_clock, pc);

    VhciNetBridge::Config bc;
    bc.capturedConfig = attached.capturedConfig;
    _bridge = std::make_unique<VhciNetBridge>(*_stream, *_plane, attached.manifest,
                                              _clock, bc);

    _last = "Presented to this computer on virtual port " + std::to_string(_port) +
            ". It should appear in `lsusb` and `lsblk`.";
    if (why) *why = _last;
    return Status::Ok;
}

Status VhciPresenter::pump()
{
    if (!_bridge) return Status::Ok;
    const Status s = _bridge->poll();
    if (s != Status::Ok && s != Status::Busy) _last = _bridge->lastError();
    return s;
}

void VhciPresenter::withdraw()
{
    // Order matters. The bridge is dropped first so nothing tries to write to a
    // socket that is about to close; closing the socket is what gives vhci-hcd
    // its EOF, which is what returns the port to `sta 004` instead of leaving
    // it attached to nothing.
    _bridge.reset();
    _plane.reset();
    _stream.reset();          // FdStream's destructor closes _sock
    _sock = -1;
    _port = -1;
}

std::string VhciPresenter::statusText() const
{
    if (!_bridge) return "Nothing is presented to this computer.";
    return _last;
}

} // namespace airusb::linuxvhci
