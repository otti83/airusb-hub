// L1 — the first real gate: does vhci-hcd talk to us at all?
//
// No AirUSB, no network, no manifest, no device. This opens a socketpair, hands
// one end to the kernel through vhci-hcd's sysfs `attach`, and reads whatever the
// kernel says first. If a kernel that has just been told a device exists starts
// enumerating it by asking for its device descriptor, then every assumption the
// Linux importer rests on is sound and the rest is work. If it does not, nothing
// downstream is worth writing.
//
// It is a probe, not a product: it answers one question and exits.
//
// WHY A SOCKETPAIR AND NOT A TCP CONNECTION
//
// The P1 plan assumed vhci-hcd needed a real network socket, which would have
// meant a loopback TCP connection carrying plaintext USB/IP that anything on the
// machine could reach. It does not. `attach_store` checks exactly two things:
// that `sockfd_lookup()` resolves the number, and that `socket->type` is
// SOCK_STREAM. There is no address-family test anywhere in drivers/usb/usbip/.
// So an AF_UNIX socketpair works, and no plaintext USB/IP ever exists on a socket
// a third party can open.
//
// Run it as root inside a Linux VM:
//     sudo ./vhci_probe [--speed high|super]

#include "UsbipCodec.h"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace airusb::linuxvhci;

namespace {

constexpr const char* kVhciDir = "/sys/devices/platform/vhci_hcd.0";

/// Linux's enum usb_device_speed. NOT airusb::Speed — the two disagree on every
/// value except HIGH, which is the one anyone would test with first, so the
/// mapping is written out rather than cast.
enum KernelSpeed : int {
    kSpeedUnknown   = 0,
    kSpeedLow       = 1,
    kSpeedFull      = 2,
    kSpeedHigh      = 3,
    kSpeedWireless  = 4,
    kSpeedSuper     = 5,
    kSpeedSuperPlus = 6,
};

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

/// vhci-hcd splits its ports by speed: the first half are USB2 ("hs"), the second
/// half USB3 ("ss"). Attaching a SuperSpeed device to a low-numbered port is
/// accepted and then the kernel disagrees with itself about where the device is.
/// So the port is chosen from the correct half, and the half is derived from
/// `status` rather than from an assumption about how many ports exist.
int pickPort(int speed, std::string& why)
{
    std::string status;
    if (!readWhole(std::string(kVhciDir) + "/status", status)) {
        why = "cannot read status — is vhci-hcd loaded?";
        return -1;
    }

    const bool wantSs = (speed == kSpeedSuper || speed == kSpeedSuperPlus);

    // Skip the header line, then take the first free port ("sta 004") whose hub
    // column matches the speed we are about to claim.
    std::size_t pos = status.find('\n');
    if (pos == std::string::npos) { why = "status has no rows"; return -1; }
    ++pos;

    while (pos < status.size()) {
        const std::size_t eol = status.find('\n', pos);
        const std::string row = status.substr(pos, eol == std::string::npos ? std::string::npos : eol - pos);
        pos = (eol == std::string::npos) ? status.size() : eol + 1;
        if (row.size() < 12) continue;

        char hub[8] = {};
        int port = -1, sta = -1;
        if (std::sscanf(row.c_str(), "%7s %d %d", hub, &port, &sta) != 3) continue;

        const bool isSs = (std::strcmp(hub, "ss") == 0);
        if (isSs != wantSs) continue;
        if (sta != 4) continue;               // 4 == VDEV_ST_NULL, free
        return port;
    }
    why = wantSs ? "no free SuperSpeed port" : "no free high-speed port";
    return -1;
}

bool writeAttach(int port, int sockfd, unsigned devid, int speed, std::string& why)
{
    char line[128];
    const int n = std::snprintf(line, sizeof line, "%d %d %u %d", port, sockfd, devid, speed);
    if (n <= 0) { why = "could not format the attach line"; return false; }

    const std::string path = std::string(kVhciDir) + "/attach";
    const int fd = ::open(path.c_str(), O_WRONLY);
    if (fd < 0) {
        why = std::string("open(attach): ") + std::strerror(errno) + " — run as root";
        return false;
    }
    const ssize_t w = ::write(fd, line, static_cast<std::size_t>(n));
    const int err = errno;
    ::close(fd);
    if (w != n) {
        why = std::string("write(attach): ") + std::strerror(err);
        if (err == EBUSY) why += " — that port is taken, try another";
        return false;
    }
    return true;
}

void hexdump(const std::uint8_t* p, std::size_t n)
{
    for (std::size_t i = 0; i < n; ++i) {
        if (i % 16 == 0) std::printf("  %04zx  ", i);
        std::printf("%02x ", p[i]);
        if (i % 16 == 15) std::printf("\n");
    }
    if (n % 16) std::printf("\n");
}

} // namespace

int main(int argc, char** argv)
{
    int speed = kSpeedHigh;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--speed" && i + 1 < argc) {
            const std::string s = argv[++i];
            if      (s == "high")  speed = kSpeedHigh;
            else if (s == "super") speed = kSpeedSuper;
            else if (s == "full")  speed = kSpeedFull;
            else { std::fprintf(stderr, "unknown speed %s\n", s.c_str()); return 64; }
        } else {
            std::fprintf(stderr, "usage: %s [--speed high|super|full]\n", argv[0]);
            return 64;
        }
    }

    int sv[2] = { -1, -1 };
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        std::fprintf(stderr, "socketpair: %s\n", std::strerror(errno));
        return 1;
    }

    std::string why;
    const int port = pickPort(speed, why);
    if (port < 0) { std::fprintf(stderr, "%s\n", why.c_str()); return 1; }

    const unsigned devid = 0x00020002u;   // (busnum << 16) | devnum, nominal
    std::printf("@@VHCI@@ attaching: port=%d sockfd=%d devid=0x%08x speed=%d\n",
                port, sv[1], devid, speed);

    if (!writeAttach(port, sv[1], devid, speed, why)) {
        std::fprintf(stderr, "%s\n", why.c_str());
        return 1;
    }

    // The kernel holds its own reference now. Ours must go, or the socket never
    // sees EOF when we exit and the port is left attached to nothing.
    ::close(sv[1]);
    sv[1] = -1;

    std::printf("@@VHCI@@ attached; waiting for the kernel to say something\n");
    std::fflush(stdout);

    std::uint8_t pdu[kPduBytes] = {};
    std::size_t got = 0;
    while (got < sizeof pdu) {
        const ssize_t r = ::read(sv[0], pdu + got, sizeof pdu - got);
        if (r == 0)  { std::fprintf(stderr, "kernel closed the socket after %zu bytes\n", got); return 2; }
        if (r < 0)   { if (errno == EINTR) continue;
                       std::fprintf(stderr, "read: %s\n", std::strerror(errno)); return 2; }
        got += static_cast<std::size_t>(r);
    }

    std::printf("@@VHCI@@ first PDU, %zu bytes:\n", got);
    hexdump(pdu, got);

    UsbipPdu p;
    bool clamped = false;
    if (!decodePdu(std::span<const std::uint8_t>(pdu, got), p, &clamped)) {
        std::fprintf(stderr, "@@VHCI@@ RESULT=FAIL — the PDU did not decode\n");
        return 3;
    }

    std::printf("@@VHCI@@ command=%u seqnum=%u devid=0x%08x direction=%s ep=%u\n",
                p.command, p.seqnum, p.devid, p.direction == kDirIn ? "IN" : "OUT", p.ep);
    std::printf("@@VHCI@@ flags=0x%08x buflen=%d start_frame=%d packets=%d interval=%d\n",
                p.transferFlags, p.transferBufferLength, p.startFrame,
                p.numberOfPackets, p.interval);
    std::printf("@@VHCI@@ setup = %02x %02x %02x %02x %02x %02x %02x %02x\n",
                p.setup[0], p.setup[1], p.setup[2], p.setup[3],
                p.setup[4], p.setup[5], p.setup[6], p.setup[7]);

    // Read the setup packet the way USB reads it: little-endian, inside a
    // big-endian header.
    const unsigned wValue  = static_cast<unsigned>(p.setup[2]) | (static_cast<unsigned>(p.setup[3]) << 8);
    const unsigned wLength = static_cast<unsigned>(p.setup[6]) | (static_cast<unsigned>(p.setup[7]) << 8);
    std::printf("@@VHCI@@ decoded: bmRequestType=0x%02x bRequest=%u wValue=0x%04x wLength=%u\n",
                p.setup[0], p.setup[1], wValue, wLength);

    // The gate: a kernel that has just been told a device exists must begin by
    // asking that device what it is.
    const bool isSubmit  = (p.command == kCmdSubmit);
    const bool isEp0In   = (p.ep == 0 && p.direction == kDirIn);
    const bool isGetDesc = (p.setup[0] == 0x80 && p.setup[1] == 0x06 && wValue == 0x0100);
    const bool devidOk   = (p.devid == devid);

    std::printf("@@VHCI@@ CMD_SUBMIT=%s ep0-IN=%s GET_DESCRIPTOR(DEVICE)=%s devid-echoed=%s\n",
                isSubmit ? "yes" : "NO", isEp0In ? "yes" : "NO",
                isGetDesc ? "yes" : "NO", devidOk ? "yes" : "NO");

    ::close(sv[0]);

    if (isSubmit && isEp0In && isGetDesc && devidOk) {
        std::printf("@@VHCI@@ RESULT=PASS — the kernel is enumerating a device that "
                    "does not exist, over a socketpair, and asked us what it is\n");
        return 0;
    }
    std::printf("@@VHCI@@ RESULT=FAIL\n");
    return 4;
}
