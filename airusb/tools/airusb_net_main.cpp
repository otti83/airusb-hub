// airusb-net — the two halves of a session, over a real socket.
//
//   airusb-net serve   --port 7714 [--fake]
//   airusb-net connect --host H --port 7714 [--probe]
//
// Portable C++: no IOKit, no platform USB API. That is what lets the client run
// on Windows and Linux against a macOS exporter — proving the protocol, the
// crypto and the LAN path long before any of those platforms has a driver.
//
// --fake serves a RAM-disk Bulk-Only Transport device instead of real hardware,
// so the whole path can be exercised with no root, no capture and no risk to
// anybody's drive. The real device source is the macOS exporter daemon; this
// tool is the network, not the hardware.

#include "../core/Clock.h"
#include "../core/Platform.h"
#include "../crypto/Identity.h"
#include "../diag/BotProbe.h"
#include "../session/ExporterSession.h"
#include "../session/ImporterClient.h"
#include "../session/PeerStore.h"
#include "../session/SecureSession.h"
#include "../tests/fakes/ScriptedDevice.h"
#include "../transport/TcpTransport.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

using namespace airusb;
using namespace airusb::crypto;
using namespace airusb::protocol;
using namespace airusb::session;
using namespace airusb::transport;

namespace {

void logLine(const char* tag, const std::string& msg)
{
    std::printf("@@AIRUSB_%s@@ %s\n", tag, msg.c_str());
    std::fflush(stdout);
}

std::string hex(std::span<const std::uint8_t> b) { return toHex(b); }

// ---------------------------------------------------------------------------
// A device source backed by a RAM disk, for proving the network without hardware
// ---------------------------------------------------------------------------

class FakeDeviceSource final : public IDeviceSource {
public:
    fakes::ScriptedDevice device{61440, 512};   // 31.5 MB of RAM disk

    std::vector<DeviceRecord> list() override
    {
        DeviceRecord r;
        r.uid       = uid();
        r.vendorId  = 0x058f;
        r.productId = 0x6387;
        r.speed     = static_cast<std::uint8_t>(Speed::Super);
        r.flags     = kDevHasStorage | kDevShareable;
        r.name      = "Simulated Flash Disk";
        return { r };
    }

    Status claim(const DeviceUid& u, IUsbDevicePort** portOut,
                 DeviceManifest& manifestOut, std::uint8_t* cfgOut,
                 std::string* whyNot) override
    {
        if (!(u == uid())) {
            if (whyNot) *whyNot = "No such device on this Mac.";
            return Status::NotFound;
        }
        *portOut    = &device;
        manifestOut = device.manifest();
        *cfgOut     = 1;
        logLine("ATTACH", "claimed the simulated device");
        return Status::Ok;
    }

    void release(const DeviceUid&) override { logLine("DETACH", "released"); }

    static DeviceUid uid()
    {
        DeviceUid u{};
        for (std::size_t i = 0; i < u.size(); ++i)
            u[i] = static_cast<std::uint8_t>(0xA0 + i);
        return u;
    }
};

// ---------------------------------------------------------------------------

LocalIdentity loadOrCreateIdentity(const std::string& path)
{
    // A real daemon stores this at 0600 under /Library/Application Support.
    // Here it is a file beside the working directory so a test run is
    // self-contained and obviously throwaway.
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

int runServe(std::uint16_t port, const std::string& idPath, const std::string& peersPath)
{
    LocalIdentity identity = loadOrCreateIdentity(idPath);
    PeerStore peers;
    (void)peers.load(peersPath);

    logLine("ATTACH", "fingerprint " + fingerprintText(fingerprint(identity.identityKey())));
    logLine("ATTACH", "pinned peers: " + std::to_string(peers.size()));

    Status st = Status::Ok;
    const int listenFd = TcpStream::listen(port, &st);
    if (listenFd < 0) {
        logLine("ERROR", "could not listen on port " + std::to_string(port));
        return 1;
    }
    logLine("ATTACH", "listening on port " + std::to_string(port));

    FakeDeviceSource source;

    for (;;) {
        std::unique_ptr<TcpStream> conn;
        while (!conn) {
            conn = TcpStream::accept(listenFd, &st);
            if (!conn) platform::sleepMs(20);
        }
        logLine("ATTACH", "peer connected");

        SecureSession secure;
        SecureSession::Config sc;
        sc.initiator = false;
        sc.identity  = &identity;
        sc.peers     = &peers;

        (void)secure.begin(std::move(conn), sc);

        bool failed = false;
        for (int i = 0; i < 15000 && !secure.established(); ++i) {
            const Status s = secure.pump();
            if (secure.state() == SecureSession::State::Failed) {
                logLine("ERROR", "handshake failed: " + secure.failureReason());
                failed = true;
                break;
            }
            if (s != Status::Ok && s != Status::Busy) { failed = true; break; }
            platform::sleepMs(1);
        }
        if (failed || !secure.established()) continue;

        logLine("ATTACH", std::string("handshake ok, peer ") +
                fingerprintText(fingerprint(secure.peerIdentity().identityKey)));
        logLine("ATTACH", std::string("trust: ") +
                (secure.trust() == Trust::Paired ? "paired" : "UNPAIRED"));

        if (secure.trust() != Trust::Paired) {
            // Trust on first use, for a test tool, said out loud. The product
            // shows the SAS and waits for a person; nothing here should be
            // mistaken for that.
            logLine("ERROR", "peer is not paired — pinning it because this is a "
                             "test tool. SAS would be " + sasText(secure.sas()));
            (void)peers.pin(secure.peerIdentity(), "test peer", kDefaultGrants, 0);
            (void)peers.save(peersPath);
            // The grants were read at handshake time, so the session has to be
            // remade for them to take effect. Ask the peer to reconnect rather
            // than pretending they applied.
            logLine("ERROR", "pinned; reconnect to use it");
            continue;
        }

        ExporterSession exporter;
        ExporterSession::Config ec;
        ec.devices = &source;
        ec.clock   = &Clock::system();
        if (exporter.begin(&secure, ec) != Status::Ok) continue;

        for (;;) {
            const Status s = exporter.pump();
            if (s == Status::TransportLost) { logLine("DETACH", "peer disconnected"); break; }
            if (isFatal(s)) {
                logLine("ERROR", std::string("session closed: ") + statusName(s) +
                                 " — " + exporter.lastError());
                break;
            }
            platform::sleepMs(1);
        }
        logLine("ATTACH", "served " + std::to_string(exporter.transfersServed()) +
                          " transfer(s), " + std::to_string(exporter.messagesHandled()) +
                          " message(s)");
        exporter.close();
    }
}

int runConnect(const std::string& host, std::uint16_t port, bool probe,
               const std::string& idPath, const std::string& peersPath)
{
    LocalIdentity identity = loadOrCreateIdentity(idPath);
    PeerStore peers;
    (void)peers.load(peersPath);

    logLine("ATTACH", "fingerprint " + fingerprintText(fingerprint(identity.identityKey())));

    Status st = Status::Ok;
    auto conn = TcpStream::connect(host, port, &st);
    if (!conn) {
        logLine("ERROR", "could not connect to " + host + ":" + std::to_string(port));
        return 1;
    }

    ImporterClient client;
    ImporterClient::Config cc;
    cc.identity = &identity;
    cc.peers    = &peers;

    if (const Status s = client.connect(std::move(conn), cc); s != Status::Ok) {
        logLine("ERROR", std::string("handshake failed: ") + statusName(s) + " — " +
                         client.failureReason());
        return 2;
    }

    logLine("ATTACH", std::string("connected to ") +
            fingerprintText(fingerprint(client.peerIdentity().identityKey)));
    logLine("ATTACH", "SAS " + sasText(client.sas()));

    if (client.trust() != Trust::Paired) {
        logLine("ERROR", "peer not pinned — trusting on first use (test tool). "
                         "Compare SAS " + sasText(client.sas()) + " with the other side.");
        (void)client.trustPeerWithoutConfirmation("test peer");
        (void)peers.save(peersPath);
    }

    std::vector<DeviceRecord> devices;
    if (const Status s = client.listDevices(devices); s != Status::Ok) {
        logLine("ERROR", std::string("LIST_DEVICES: ") + statusName(s) + " — " +
                         client.failureReason());
        return 3;
    }

    logLine("ENUM", std::to_string(devices.size()) + " device(s) offered");
    for (const DeviceRecord& d : devices) {
        char line[256];
        std::snprintf(line, sizeof line, "%04x:%04x  %-24s speed=%s  uid=%s",
                      d.vendorId, d.productId, d.name.c_str(),
                      speedName(static_cast<Speed>(d.speed)),
                      hex(std::span<const std::uint8_t>(d.uid.data(), 8)).c_str());
        logLine("ENUM", line);
    }
    if (devices.empty() || !probe) return 0;

    std::unique_ptr<RemoteDevicePort> devicePort;
    std::string why;
    if (const Status s = client.attach(devices[0].uid, 1, devicePort, &why); s != Status::Ok) {
        logLine("ERROR", std::string("ATTACH: ") + statusName(s) + " — " + why);
        return 4;
    }
    logLine("ATTACH", "attached; manifest validated");

    diag::BotEndpoints eps;
    if (!diag::findBotInterface(devicePort->manifest(), 1, eps)) {
        logLine("ERROR", "the attached device is not Bulk-Only Transport storage");
        (void)client.detach();
        return 5;
    }

    diag::BotProbe bot(*devicePort, eps);
    bot.setTrace([](const std::string& l) { logLine("XFER", l); });
    const diag::BotProbeResult r = bot.run();

    std::printf("\n--- BOT probe over the network ---\n%s", r.summary().c_str());
    if (r.blockSize)
        std::printf("  medium: %llu blocks x %u bytes = %.2f MB\n",
                    static_cast<unsigned long long>(r.blockCount()), r.blockSize,
                    static_cast<double>(r.blockCount()) *
                    static_cast<double>(r.blockSize) / 1e6);
    if (!r.sector0.empty()) {
        std::printf("  sector 0: ");
        for (std::size_t i = 0; i < 16 && i < r.sector0.size(); ++i)
            std::printf("%02x ", r.sector0[i]);
        std::printf("\n");
    }
    std::fflush(stdout);

    (void)client.detach();

    if (r.passed) {
        logLine("XFER", "RESULT=PASS — a USB Mass Storage exchange completed over "
                        "an encrypted, authenticated network session");
        return 0;
    }
    logLine("ERROR", "RESULT=FAIL — " + r.failure);
    return 6;
}

void usage(const char* argv0)
{
    std::fprintf(stderr,
        "usage:\n"
        "  %s serve   [--port N] [--id PATH] [--peers PATH]\n"
        "  %s connect --host H [--port N] [--probe] [--id PATH] [--peers PATH]\n"
        "\n"
        "  serve     offer a simulated USB drive over the network\n"
        "  connect   attach to one, and with --probe read from it\n"
        "\n"
        "  Portable: the client builds and runs on macOS, Linux and Windows.\n", argv0, argv0);
}

} // namespace

int main(int argc, const char* argv[])
{
    if (argc < 2) { usage(argv[0]); return 64; }

    const std::string mode = argv[1];
    std::uint16_t port = 7714;
    std::string host   = "127.0.0.1";
    std::string idPath = mode == "serve" ? "airusb-serve.id" : "airusb-connect.id";
    std::string peersPath = mode == "serve" ? "airusb-serve.peers" : "airusb-connect.peers";
    bool probe = false;

    for (int i = 2; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--port" && i + 1 < argc)
            port = static_cast<std::uint16_t>(std::atoi(argv[++i]));
        else if (a == "--host" && i + 1 < argc)  host = argv[++i];
        else if (a == "--id" && i + 1 < argc)    idPath = argv[++i];
        else if (a == "--peers" && i + 1 < argc) peersPath = argv[++i];
        else if (a == "--probe")                 probe = true;
        else { usage(argv[0]); return 64; }
    }

    if (mode == "serve")   return runServe(port, idPath, peersPath);
    if (mode == "connect") return runConnect(host, port, probe, idPath, peersPath);

    usage(argv[0]);
    return 64;
}
