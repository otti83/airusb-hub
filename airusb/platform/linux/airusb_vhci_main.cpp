// L4 — make Linux enumerate a device that is not there.
//
// This is the gate the whole project has been walking toward. Everything before
// it proved that a USB device could be FORWARDED; this is the first time an
// operating system TAKES one — enumerates it, reads its descriptors, binds its
// own real class driver and creates its own device node. macOS cannot do this
// yet because Apple has not granted an entitlement, and Windows cannot because
// its driver is unwritten. Linux can, today, with nobody's permission.
//
// It serves a simulated device, so no hardware and no network are involved and
// the only variable under test is the kernel path. Pointing the same bridge at a
// RemoteDevicePort instead of a ScriptedDevice is L6.
//
//     sudo ./airusb-vhci
//
// Then, in another shell:
//     dmesg | tail
//     lsusb
//     lsblk

#include "FdStream.h"
#include "LinuxUsb.h"
#include "VhciBridge.h"

#include "../../tests/fakes/ScriptedDevice.h"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace airusb;
using namespace airusb::linuxvhci;

namespace {

constexpr const char* kVhciDir = "/sys/devices/platform/vhci_hcd.0";

void logLine(const char* tag, const std::string& msg)
{
    std::printf("@@AIRUSB_%s@@ %s\n", tag, msg.c_str());
    std::fflush(stdout);
}

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
/// Choosing from the wrong half is accepted by the kernel and then the kernel
/// disagrees with itself about where the device is.
int pickPort(KernelSpeed speed, std::string& why)
{
    std::string status;
    if (!readWhole(std::string(kVhciDir) + "/status", status)) {
        why = "cannot read status — is vhci-hcd loaded? (sudo modprobe vhci-hcd)";
        return -1;
    }
    const bool wantSs = isSuperSpeedHalf(speed);

    std::size_t pos = status.find('\n');
    if (pos == std::string::npos) { why = "status has no rows"; return -1; }
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
    why = wantSs ? "no free SuperSpeed port" : "no free high-speed port";
    return -1;
}

bool attach(int port, int sockfd, unsigned devid, KernelSpeed speed, std::string& why)
{
    char line[128];
    const int n = std::snprintf(line, sizeof line, "%d %d %u %d",
                                port, sockfd, devid, static_cast<int>(speed));
    const int fd = ::open((std::string(kVhciDir) + "/attach").c_str(), O_WRONLY);
    if (fd < 0) {
        why = std::string("open(attach): ") + std::strerror(errno) + " — run as root";
        return false;
    }
    const ssize_t w = ::write(fd, line, static_cast<std::size_t>(n));
    const int err = errno;
    ::close(fd);
    if (w != n) {
        why = std::string("write(attach): ") + std::strerror(err);
        if (err == EBUSY) why += " — the port is taken";
        return false;
    }
    return true;
}

} // namespace

int main(int argc, char** argv)
{
    if (argc > 1) {
        std::fprintf(stderr,
            "usage: %s\n\n"
            "  The attach speed is NOT an option. It is read from the device's own\n"
            "  manifest, because it is a fact about the device and not a preference.\n",
            argv[0]);
        return 64;
    }

    fakes::ScriptedDevice device{61440, 512};   // 31.5 MB RAM disk, SuperSpeed manifest

    // The speed comes from the MANIFEST, and there is deliberately no flag to
    // override it. This was a real defect in the first version of this tool: it
    // took --speed from the command line, and attaching a SuperSpeed manifest at
    // high speed produced
    //
    //     usb 3-1: Invalid ep0 maxpacket: 9
    //     usb usb3-port1: unable to enumerate USB device
    //
    // because bMaxPacketSize0 is a power-of-two EXPONENT at SuperSpeed (9 = 512)
    // and a literal byte count at high speed, where only 8/16/32/64 are legal.
    // The descriptors were correct; the speed we claimed for them was not. A tool
    // that can express that contradiction will eventually be asked to.
    const Speed devSpeed = device.manifest().speed();

    // NOT a cast. airusb::Speed and usb_device_speed agree on High and disagree
    // on everything else; see LinuxUsb.h.
    const KernelSpeed kspeed = toKernelSpeed(devSpeed);
    if (kspeed == KernelSpeed::Unknown) {
        logLine("ERROR", "the manifest declares a speed Linux cannot express");
        return 1;
    }

    int sv[2] = { -1, -1 };
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        logLine("ERROR", std::string("socketpair: ") + std::strerror(errno));
        return 1;
    }

    std::string why;
    const int port = pickPort(kspeed, why);
    if (port < 0) { logLine("ERROR", why); return 1; }

    logLine("ATTACH", "port " + std::to_string(port) +
                      ", speed " + std::to_string(static_cast<int>(kspeed)) +
                      " (" + (isSuperSpeedHalf(kspeed) ? "ss" : "hs") + " half)");

    if (!attach(port, sv[1], 0x00020002u, kspeed, why)) {
        logLine("ERROR", why);
        return 1;
    }
    // The kernel holds its own reference now. Ours must go or the socket never
    // sees EOF and the port is left attached to nothing.
    ::close(sv[1]);

    logLine("ATTACH", "attached; the kernel is enumerating. Try `dmesg | tail` and `lsblk`.");

    FdStream stream(sv[0]);
    VhciBridge bridge(stream, device);
    bridge.setTrace([](const std::string& l) { logLine("XFER", l); });

    const Status s = bridge.run();

    const VhciBridgeStats& st = bridge.stats();
    std::printf("\n--- vhci bridge ---\n"
                "  submits=%u unlinks=%u answeredLocally=%u forwarded=%u stalled=%u\n"
                "  bytes to kernel=%llu, from kernel=%llu\n",
                st.submitsHandled, st.unlinksHandled, st.answeredLocally,
                st.forwardedToDevice, st.stalled,
                static_cast<unsigned long long>(st.bytesToKernel),
                static_cast<unsigned long long>(st.bytesFromKernel));
    std::fflush(stdout);

    if (s != Status::Ok) {
        logLine("ERROR", std::string("RESULT=FAIL — ") + statusName(s) + " — " + bridge.lastError());
        return 2;
    }
    logLine("XFER", "RESULT=PASS — the kernel enumerated the device and then detached");
    return 0;
}
