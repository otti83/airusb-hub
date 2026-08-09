// airusb-exportd — the root half of the macOS exporter, plus the P2.8 gate.
//
// P2.8's gate is one sentence: prove a real CBW -> data -> CSW exchange through
// pipes the AGENT obtained while the DAEMON holds the capture. --selftest-bot
// does exactly that and prints the evidence, using diag/BotProbe, which is
// validated against a RAM-disk device in CI on every commit.
//
// SAFETY
//   The probe is read-only: GET_MAX_LUN, TEST UNIT READY, INQUIRY,
//   READ CAPACITY(10), READ(10). It never writes a byte to the medium. The drive
//   is still unmounted first — a captured device must not have a live filesystem
//   on it — and handed back on the way out.
//
//   The tool refuses the boot disk, refuses to run without root, and aborts
//   before capture if any unmount is dissented.

#include "HostDeviceExporter.h"
#include "MacUsbCommon.h"
#include "../../core/Clock.h"
#include "../../core/Platform.h"
#include "../../core/Watchdog.h"
#include "../../crypto/Identity.h"
#include "../../diag/BotProbe.h"
#include "../../session/ExporterSession.h"
#include "../../session/PeerStore.h"
#include "../../session/SecureSession.h"
#include "../../transport/TcpTransport.h"

#import <Foundation/Foundation.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unistd.h>

using namespace airusb;
using namespace airusb::macos;

namespace {

void usage(const char* argv0)
{
    std::fprintf(stderr,
        "usage: sudo %s --device VID:PID [options]\n"
        "\n"
        "  --device VID:PID     e.g. 058f:6387 (four hex digits, colon, four hex digits)\n"
        "  --socket PATH        where the agent connects (default /var/run/airusb-exportd.sock)\n"
        "  --agent-wait MS      how long to wait for the agent (default 30000)\n"
        "  --selftest-bot       run the read-only Bulk-Only Transport probe and exit\n"
        "  --serve [--port N]   after capture, serve the drive over TCP (default 7714)\n"
        "                       to a remote importer (e.g. Linux airusb-vhci --host)\n"
        "  --hold MS            after the probe, keep the lease this long\n"
        "  --list               enumerate USB devices and exit (read-only, no root needed)\n"
        "\n"
        "  Must run as root: DeviceCapture and whole-disk unmount both require it.\n"
        "  Use a USB drive whose contents you do not care about.\n", argv0);
}

void listDevices()
{
    io_iterator_t it = IO_OBJECT_NULL;
    if (IOServiceGetMatchingServices(kIOMainPortDefault,
                                     IOServiceMatching(kIOUSBHostDeviceClassName),
                                     &it) != KERN_SUCCESS) {
        logLine("ERROR", @"IOServiceGetMatchingServices failed");
        return;
    }

    io_service_t dev;
    int n = 0;
    while ((dev = IOIteratorNext(it))) {
        NSNumber* vid = propNum(dev, CFSTR("idVendor"));
        NSNumber* pid = propNum(dev, CFSTR("idProduct"));
        NSString* name = propStr(dev, CFSTR("USB Product Name"));

        std::set<std::string> bsd;
        collectBsdNames(dev, bsd);
        std::string joined;
        for (const std::string& b : bsd) { if (!joined.empty()) joined += ","; joined += b; }

        logLine("ENUM", @"%04x:%04x  %@  locationID=0x%08X  speed=%s  bsd=[%s]",
                vid.unsignedIntValue, pid.unsignedIntValue, (name ? name : @"?"),
                locationIdOf(dev), describeSpeed(dev).c_str(), joined.c_str());
        ++n;
        IOObjectRelease(dev);
    }
    IOObjectRelease(it);
    if (n == 0) logLine("ENUM", @"no USB devices found — plug in the test drive");
}

/// The P2.8 gate. Returns true on PASS.
bool runBotSelfTest(HostDeviceExporter& ex)
{
    logLine("XFER", @"=== P2.8 gate: real CBW -> data -> CSW through the agent's pipes ===");

    diag::BotEndpoints eps;
    if (!diag::findBotInterface(ex.manifest(), ex.configValue(), eps)) {
        logLine("ERROR", @"RESULT=SELFTEST_SKIPPED — this device has no Bulk-Only "
                          "Transport interface (08/06/50). The probe only applies "
                          "to mass storage.");
        return false;
    }

    // Cross-check the manifest against what the agent actually opened. The
    // manifest says which endpoints SHOULD exist; the pipe table says which ones
    // the agent HAS. A disagreement means the probe would submit to a pipe that
    // does not exist, and diagnosing that as a USB failure would be wrong.
    bool haveIn = false, haveOut = false;
    for (const ipc::EpEntry& e : ex.pipeTable().endpoints) {
        if (e.address == eps.bulkIn)  haveIn  = true;
        if (e.address == eps.bulkOut) haveOut = true;
    }
    if (!haveIn || !haveOut) {
        logLine("ERROR", @"RESULT=SELFTEST_FAILED — the manifest names endpoints "
                          "0x%02x/0x%02x but the agent's pipe table does not have "
                          "them (in=%s out=%s)",
                eps.bulkIn, eps.bulkOut, haveIn ? "yes" : "no", haveOut ? "yes" : "no");
        return false;
    }

    diag::BotProbe probe(ex, eps);
    probe.setTrace([](const std::string& line) {
        logLine("XFER", @"%s", line.c_str());
    });

    const diag::BotProbeResult r = probe.run();

    std::fprintf(stdout, "\n--- BOT probe result ---\n%s", r.summary().c_str());
    if (!r.vendor.empty())
        std::fprintf(stdout, "  device: '%s' '%s' rev '%s'\n",
                     r.vendor.c_str(), r.product.c_str(), r.revision.c_str());
    if (r.blockSize)
        std::fprintf(stdout, "  medium: %llu blocks x %u bytes = %.2f GB\n",
                     static_cast<unsigned long long>(r.blockCount()), r.blockSize,
                     static_cast<double>(r.blockCount()) *
                     static_cast<double>(r.blockSize) / 1e9);
    if (!r.sector0.empty()) {
        std::fprintf(stdout, "  sector 0 (first 32 bytes, read-only):\n    ");
        for (std::size_t i = 0; i < 32 && i < r.sector0.size(); ++i)
            std::fprintf(stdout, "%02x ", r.sector0[i]);
        std::fprintf(stdout, "\n  boot signature 55AA: %s\n",
                     r.sector0HasBootSignature ? "present" : "absent");
    }
    std::fflush(stdout);

    if (r.passed) {
        logLine("XFER", @"RESULT=SELFTEST_PASS — bulk I/O works through pipes the "
                         "agent obtained while the daemon holds the capture. The "
                         "split exporter is proven end to end.");
        // OQ-1 is settled only if the boundaries survived, which is a separate
        // claim from "the transfers succeeded".
        logLine("XFER", @"OQ-1: transfer boundaries %@ — one NormalTransfer is one "
                         "logical URB on this path",
                r.transferBoundariesIntact ? @"INTACT" : @"VIOLATED");
    } else {
        logLine("ERROR", @"RESULT=SELFTEST_FAIL — %s", r.failure.c_str());
    }
    return r.passed;
}

// ---------------------------------------------------------------------------
// --serve: the captured drive, over TCP, to a remote importer (e.g. the Linux
// airusb-vhci --host). The capture and the network are the same two-process split
// as everywhere else — the daemon owns the IUsbDevicePort, this just runs an
// ExporterSession over a socket instead of a local BotProbe.
// ---------------------------------------------------------------------------

crypto::LocalIdentity loadOrCreateIdentity(const std::string& path)
{
    crypto::Seed seed{};
    if (FILE* f = std::fopen(path.c_str(), "rb"); f) {
        const std::size_t got = std::fread(seed.data(), 1, seed.size(), f);
        std::fclose(f);
        if (got == seed.size()) return crypto::LocalIdentity::fromSeed(seed);
    }
    crypto::randomBytes(std::span<std::uint8_t>(seed.data(), seed.size()));
    if (FILE* f = std::fopen(path.c_str(), "wb"); f) {
        (void)std::fwrite(seed.data(), 1, seed.size(), f);
        std::fclose(f);
    }
    return crypto::LocalIdentity::fromSeed(seed);
}

/// Presents the ALREADY-captured device (an IUsbDevicePort) to ExporterSession.
/// release() is a no-op: unclaiming the drive is the daemon's job, in the
/// documented order (§7.6), not a network session's.
class CapturedDeviceSource final : public session::IDeviceSource {
public:
    explicit CapturedDeviceSource(HostDeviceExporter& ex) : _ex(ex) {}

    std::vector<protocol::DeviceRecord> list() override
    {
        protocol::DeviceRecord r;
        r.uid = uid();
        const auto dd = _ex.manifest().deviceDescriptor();
        r.vendorId  = dd.size() >= 10 ? static_cast<std::uint16_t>(dd[8]  | (dd[9]  << 8)) : 0;
        r.productId = dd.size() >= 12 ? static_cast<std::uint16_t>(dd[10] | (dd[11] << 8)) : 0;
        r.speed = static_cast<std::uint8_t>(_ex.manifest().speed());
        r.flags = protocol::kDevHasStorage | protocol::kDevShareable;
        r.name  = "Captured USB drive";
        return { r };
    }

    Status claim(const protocol::DeviceUid& u, IUsbDevicePort** portOut,
                 DeviceManifest& m, std::uint8_t* cfg, std::string* whyNot) override
    {
        if (!(u == uid())) { if (whyNot) *whyNot = "No such device on this Mac."; return Status::NotFound; }
        if (!_ex.attached()) { if (whyNot) *whyNot = "The drive is no longer captured."; return Status::DeviceGone; }
        *portOut = &_ex;
        m        = _ex.manifest();
        if (cfg) *cfg = _ex.configValue();
        return Status::Ok;
    }

    void release(const protocol::DeviceUid&) override {}

    static protocol::DeviceUid uid()
    {
        protocol::DeviceUid u{};
        for (std::size_t i = 0; i < u.size(); ++i) u[i] = static_cast<std::uint8_t>(0xB0 + i);
        return u;
    }

private:
    HostDeviceExporter& _ex;
};

int runServe(HostDeviceExporter& exporter, std::uint16_t port,
             const std::string& idPath, const std::string& peersPath)
{
    crypto::LocalIdentity identity = loadOrCreateIdentity(idPath);
    session::PeerStore peers;
    (void)peers.load(peersPath);
    logLine("ATTACH", @"exporter identity %s",
            crypto::fingerprintText(crypto::fingerprint(identity.identityKey())).c_str());

    Status st = Status::Ok;
    const platform::SocketHandle listenFd = transport::TcpStream::listen(port, &st);
    if (!platform::isValid(listenFd)) {
        logLine("ERROR", @"could not listen on TCP port %u", port);
        return 1;
    }
    logLine("ATTACH", @"serving the captured drive on TCP port %u", port);

    CapturedDeviceSource source(exporter);

    while (exporter.attached() && exporter.agentAlive()) {
        std::unique_ptr<transport::TcpStream> conn;
        for (int i = 0; i < 3000 && !conn; ++i) {          // wait for the next importer
            conn = transport::TcpStream::accept(listenFd, &st);
            if (!conn) {
                if (!exporter.agentAlive()) break;
                platform::sleepMs(20);
            }
        }
        if (!conn) continue;
        logLine("ATTACH", @"importer connected");

        session::SecureSession secure;
        session::SecureSession::Config sc;
        sc.initiator = false;
        sc.identity  = &identity;
        sc.peers     = &peers;
        (void)secure.begin(std::move(conn), sc);

        for (int i = 0; i < 15000 && !secure.established(); ++i) {
            const Status s = secure.pump();
            if (secure.state() == session::SecureSession::State::Failed) {
                logLine("ERROR", @"handshake failed: %s", secure.failureReason().c_str());
                break;
            }
            if (s != Status::Ok && s != Status::Busy) break;
            platform::sleepMs(1);
        }
        if (!secure.established()) continue;

        if (secure.trust() != session::Trust::Paired) {
            // TOFU for a test tool, said out loud: pin and drop, so the importer
            // reconnects with the grants applied.
            logLine("ATTACH", @"importer not paired — pinning (test tool). SAS %s",
                    crypto::sasText(secure.sas()).c_str());
            (void)peers.pin(secure.peerIdentity(), "importer", session::kDefaultGrants, 0);
            (void)peers.save(peersPath);
            logLine("ATTACH", @"pinned; the importer must reconnect");
            continue;
        }
        logLine("ATTACH", @"importer paired, SAS %s", crypto::sasText(secure.sas()).c_str());

        session::ExporterSession expSess;
        session::ExporterSession::Config ec;
        ec.devices = &source;
        ec.clock   = &Clock::system();
        if (expSess.begin(&secure, ec) != Status::Ok) continue;

        for (;;) {
            const Status s = expSess.pump();
            if (s == Status::TransportLost) { logLine("DETACH", @"importer disconnected"); break; }
            if (isFatal(s)) {
                logLine("ERROR", @"session closed: %s — %s", statusName(s), expSess.lastError().c_str());
                break;
            }
            if (!exporter.agentAlive()) { logLine("ERROR", @"the agent is gone — ending the session"); break; }
            platform::sleepMs(1);
        }
        logLine("ATTACH", @"served %llu transfer(s)",
                static_cast<unsigned long long>(expSess.transfersServed()));
        expSess.close();
    }
    return 0;
}

} // namespace

int main(int argc, const char* argv[])
{
    @autoreleasepool {
        setLogPrefix("exportd");
        ipc::ignoreSigpipe();

        // The timeout table's ordering relationships are static_asserted, but a
        // build that somehow relaxed one must be caught at launch rather than in
        // the field with a drive captured.
        if (!watchdog::assertConsistent()) {
            logLine("ERROR", @"the timeout table is inconsistent — refusing to start");
            return 70;
        }

        ExporterConfig cfg;
        bool selftest = false, list = false, serve = false;
        std::uint16_t servePort = 7714;
        std::uint32_t holdMs = 0;
        bool haveDevice = false;

        for (int i = 1; i < argc; ++i) {
            const std::string a = argv[i];
            if (a == "--device" && i + 1 < argc) {
                unsigned vid = 0, pid = 0;
                if (std::sscanf(argv[++i], "%4x:%4x", &vid, &pid) != 2 ||
                    vid > 0xFFFF || pid > 0xFFFF) {
                    logLine("ERROR", @"'%s' is not a VID:PID", argv[i]);
                    usage(argv[0]);
                    return 64;
                }
                cfg.vendorId  = static_cast<std::uint16_t>(vid);
                cfg.productId = static_cast<std::uint16_t>(pid);
                haveDevice = true;
            }
            else if (a == "--socket" && i + 1 < argc)     cfg.socketPath  = argv[++i];
            else if (a == "--agent-wait" && i + 1 < argc) cfg.agentWaitMs = static_cast<std::uint32_t>(std::atoi(argv[++i]));
            else if (a == "--hold" && i + 1 < argc)       holdMs = static_cast<std::uint32_t>(std::atoi(argv[++i]));
            else if (a == "--selftest-bot")               selftest = true;
            else if (a == "--serve")                      serve = true;
            else if (a == "--port" && i + 1 < argc)       servePort = static_cast<std::uint16_t>(std::atoi(argv[++i]));
            else if (a == "--list")                       list = true;
            else { usage(argv[0]); return 64; }
        }

        if (list) { listDevices(); return 0; }

        if (!haveDevice) {
            usage(argv[0]);
            std::fprintf(stderr, "\nAttached devices:\n");
            listDevices();
            return 64;
        }

        logLine("ATTACH", @"airusb-exportd starting: pid=%d euid=%d ppid=%d %s",
                ::getpid(), ::geteuid(), ::getppid(),
                ::getppid() == 1 ? "(launchd)" : (isatty(STDIN_FILENO) ? "(tty)" : "(no tty)"));

        HostDeviceExporter exporter;
        std::string why;

        const Status st = exporter.attach(cfg, &why);
        if (st != Status::Ok) {
            // User-facing wording per §7.4: never a bare error code in the primary
            // text. The code is on the line above, for the log.
            logLine("ERROR", @"RESULT=ATTACH_FAILED %s: %s", statusName(st), why.c_str());
            std::fprintf(stderr,
                "\nCould not take control of the drive. It has been returned to this Mac.\n"
                "  reason: %s\n", why.c_str());
            return 2;
        }

        int rc = 0;
        if (selftest)
            rc = runBotSelfTest(exporter) ? 0 : 3;

        if (serve) {
            // Serve until the importer is done and the agent is still alive. The
            // release below hands the drive back to this Mac in the documented order.
            rc = runServe(exporter, servePort, "airusb-exportd.id", "airusb-exportd.peers");
        }
        else if (holdMs > 0) {
            logLine("ATTACH", @"holding the lease for %u ms", holdMs);
            // The agent dying is the event that must release the capture and hand
            // the drive back, so the hold watches for exactly that rather than
            // just sleeping.
            const std::uint64_t step = 1000;
            std::uint64_t waited = 0;
            while (waited < holdMs) {
                const std::uint32_t slice =
                    static_cast<std::uint32_t>(holdMs - waited < step ? holdMs - waited : step);
                if (!exporter.waitWhileAgentAlive(slice)) {
                    logLine("ERROR", @"the agent is gone — releasing the capture early "
                                      "so the drive comes back to this Mac");
                    break;
                }
                waited += slice;
            }
        }

        exporter.release();
        return rc;
    }
}
