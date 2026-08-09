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
#include "VhciNetBridge.h"

#include "../../core/Clock.h"
#include "../../crypto/Identity.h"
#include "../../session/ImporterClient.h"
#include "../../session/ImporterDataPlane.h"
#include "../../session/PeerStore.h"
#include "../../transport/TcpTransport.h"
#include "../../tests/fakes/ScriptedDevice.h"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <csignal>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace airusb;
using namespace airusb::crypto;
using namespace airusb::protocol;
using namespace airusb::session;
using namespace airusb::transport;
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

// ---------------------------------------------------------------------------
// --host: a REAL device (well, a simulated one served by `airusb-net serve`, or a
// real drive captured by the macOS exporter) mounted on THIS Linux kernel, over an
// encrypted network session. This is the whole importer stack against a real
// kernel: ImporterClient (handshake/attach) -> ImporterDataPlane (non-blocking) ->
// VhciNetBridge (non-blocking) -> the vhci-hcd socketpair, behind one poll(2) loop.
// ---------------------------------------------------------------------------

LocalIdentity loadOrCreateIdentity(const std::string& path)
{
    Seed seed{};
    if (FILE* f = std::fopen(path.c_str(), "rb"); f) {
        const std::size_t got = std::fread(seed.data(), 1, seed.size(), f);
        std::fclose(f);
        if (got == seed.size()) return LocalIdentity::fromSeed(seed);
    }
    randomBytes(std::span<std::uint8_t>(seed.data(), seed.size()));
    if (FILE* f = std::fopen(path.c_str(), "wb"); f) {
        (void)std::fwrite(seed.data(), 1, seed.size(), f);
        std::fclose(f);
    }
    return LocalIdentity::fromSeed(seed);
}

int runHost(const std::string& host, std::uint16_t port,
            const std::string& idPath, const std::string& peersPath)
{
    // A kernel detach closes the socket under us; a write to it must become
    // TransportLost, never SIGPIPE-kills the process mid-transfer.
    ::signal(SIGPIPE, SIG_IGN);

    LocalIdentity identity = loadOrCreateIdentity(idPath);
    PeerStore peers;
    (void)peers.load(peersPath);

    Status st = Status::Ok;
    auto conn = TcpStream::connect(host, port, &st);
    if (!conn) {
        logLine("ERROR", "connect failed to " + host + ":" + std::to_string(port));
        return 1;
    }
    const int tcpFd = static_cast<int>(conn->fd());

    ImporterClient client;
    ImporterClient::Config cc;
    cc.identity = &identity;
    cc.peers    = &peers;
    if (const Status s = client.connect(std::move(conn), cc); s != Status::Ok) {
        logLine("ERROR", std::string("handshake failed: ") + statusName(s) + " — " +
                         client.failureReason());
        return 2;
    }
    logLine("ATTACH", "connected; SAS " + sasText(client.sas()));
    if (client.trust() != Trust::Paired) {
        // Trust on first use, for a test tool, said out loud. The exporter pins the
        // first unpaired peer and drops the session, so the first run pairs and the
        // second run mounts — the caller retries.
        logLine("ATTACH", "peer not pinned — trusting on first use (test tool)");
        (void)client.trustPeerWithoutConfirmation("test peer");
        (void)peers.save(peersPath);
    }

    std::vector<DeviceRecord> devices;
    if (const Status s = client.listDevices(devices); s != Status::Ok) {
        logLine("ERROR", std::string("LIST_DEVICES: ") + statusName(s) + " — " +
                         client.failureReason());
        return 3;
    }
    if (devices.empty()) { logLine("ERROR", "the exporter offered no devices"); return 3; }
    logLine("ENUM", std::to_string(devices.size()) + " device(s); attaching \"" +
                    devices[0].name + "\"");

    ImporterClient::BridgeAttach ba;
    std::string why;
    if (const Status s = client.attachForBridge(devices[0].uid, 1, ba, &why); s != Status::Ok) {
        logLine("ERROR", std::string("ATTACH: ") + statusName(s) + " — " + why);
        return 4;
    }
    logLine("ATTACH", std::string("attached; speed ") + speedName(ba.speed) +
                      ", captured configuration " + std::to_string(ba.capturedConfig));

    const KernelSpeed kspeed = toKernelSpeed(ba.speed);
    if (kspeed == KernelSpeed::Unknown) {
        logLine("ERROR", "the device's speed cannot be expressed to Linux");
        return 5;
    }

    int sv[2] = { -1, -1 };
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        logLine("ERROR", std::string("socketpair: ") + std::strerror(errno));
        return 6;
    }

    std::string pw;
    const int vport = pickPort(kspeed, pw);
    if (vport < 0) { logLine("ERROR", pw); ::close(sv[0]); ::close(sv[1]); return 7; }
    logLine("ATTACH", "vhci port " + std::to_string(vport) + " (" +
                      (isSuperSpeedHalf(kspeed) ? "ss" : "hs") + " half)");

    if (!attach(vport, sv[1], 0x00020002u, kspeed, pw)) {
        logLine("ERROR", pw); ::close(sv[0]); ::close(sv[1]); return 8;
    }
    ::close(sv[1]);   // the kernel holds its own reference now

    // OUR end must be non-blocking, or FdStream's read/write would block the loop
    // and re-open the §4.2 deadlock the whole design closes.
    const int fl = ::fcntl(sv[0], F_GETFL, 0);
    (void)::fcntl(sv[0], F_SETFL, (fl < 0 ? 0 : fl) | O_NONBLOCK);

    logLine("ATTACH", "attached to vhci; the kernel is enumerating. Try `dmesg | tail`, `lsblk`.");

    FdStream kstream(sv[0]);

    ImporterDataPlane::Config pc;
    pc.attachId         = ba.attachId;
    pc.attachSlot       = ba.slot;
    pc.maxInFlight      = 1;
    pc.maxTransferBytes = ba.maxTransferBytes;
    ImporterDataPlane plane(ba.link, &Clock::system(), pc);

    VhciNetBridge::Config bc;
    bc.capturedConfig = ba.capturedConfig;
    VhciNetBridge bridge(kstream, plane, ba.manifest, Clock::system(), bc);
    bridge.setTrace([](const std::string& l) { logLine("XFER", l); });

    // R-A/R-B/R-C in one loop: POLLIN on both fds, POLLOUT only while a tx buffer is
    // non-empty (so a full socket parks instead of spinning), a 250 ms cap so the
    // deadline sweep runs even when both fds are quiet, and bridge.poll() — which
    // drains the kernel FIRST — after every wake.
    Status result = Status::Ok;
    for (;;) {
        struct pollfd fds[2];
        fds[0].fd = tcpFd; fds[0].events = POLLIN; fds[0].revents = 0;
        fds[1].fd = sv[0]; fds[1].events = POLLIN; fds[1].revents = 0;
        if (ba.link->pendingTxBytes() > 0) fds[0].events |= POLLOUT;
        if (bridge.pendingKernelTx() > 0)  fds[1].events |= POLLOUT;

        const int pr = ::poll(fds, 2, 250);
        if (pr < 0) {
            if (errno == EINTR) continue;
            logLine("ERROR", std::string("poll: ") + std::strerror(errno));
            result = Status::Internal;
            break;
        }

        const Status s = bridge.poll();
        if (s == Status::TransportLost) { logLine("DETACH", "the session ended"); break; }
        if (s != Status::Ok) {
            logLine("ERROR", std::string("bridge: ") + statusName(s) + " — " + bridge.lastError());
            result = s;
            break;
        }
    }

    const VhciBridgeStats& bs = bridge.stats();
    std::printf("\n--- vhci net bridge ---\n"
                "  submits=%u unlinks=%u answeredLocally=%u forwarded=%u stalled=%u\n"
                "  bytes to kernel=%llu, from kernel=%llu\n",
                bs.submitsHandled, bs.unlinksHandled, bs.answeredLocally,
                bs.forwardedToDevice, bs.stalled,
                static_cast<unsigned long long>(bs.bytesToKernel),
                static_cast<unsigned long long>(bs.bytesFromKernel));
    std::fflush(stdout);

    ::close(sv[0]);          // EOF -> vhci teardown, port back to free
    (void)client.detach();
    return result == Status::Ok ? 0 : 9;
}

} // namespace

// The original L4 path: a local simulated device, no network. Reached by running
// `airusb-vhci` with no arguments.
int runLocal()
{
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

int main(int argc, char** argv)
{
    // No arguments: the local simulated-device path (L4). `--host H` mounts a device
    // served over the network — `airusb-net serve`, or the macOS exporter — onto
    // THIS Linux kernel (L6).
    std::string host, idPath = "airusb-vhci.id", peersPath = "airusb-vhci.peers";
    std::uint16_t port = 7714;
    bool wantHost = false;

    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--host" && i + 1 < argc)       { host = argv[++i]; wantHost = true; }
        else if (a == "--port" && i + 1 < argc)  port = static_cast<std::uint16_t>(std::atoi(argv[++i]));
        else if (a == "--id" && i + 1 < argc)    idPath = argv[++i];
        else if (a == "--peers" && i + 1 < argc) peersPath = argv[++i];
        else {
            std::fprintf(stderr,
                "usage:\n"
                "  %s                       local simulated device (L4)\n"
                "  %s --host H [--port N]   mount a network-served device on this kernel (L6)\n"
                "                           [--id PATH] [--peers PATH]\n\n"
                "  The attach speed is NOT an option. It is read from the device's own\n"
                "  manifest, because it is a fact about the device and not a preference.\n",
                argv[0], argv[0]);
            return 64;
        }
    }

    return wantHost ? runHost(host, port, idPath, peersPath) : runLocal();
}
