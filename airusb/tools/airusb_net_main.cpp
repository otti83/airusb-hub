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
#include "../diag/WriteProbe.h"
#include "../session/ExporterSession.h"
#include "../session/InlineAsyncPort.h"
#include "../session/LeaseAuthority.h"
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
    /// The RAM disk always returns, so an inline adapter is honest here.
    InlineAsyncPort async{device};

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

    Status claim(const DeviceUid& u, IAsyncUsbDevicePort** portOut,
                 DeviceManifest& manifestOut, std::uint8_t* cfgOut,
                 std::string* whyNot) override
    {
        if (!(u == uid())) {
            if (whyNot) *whyNot = "No such device on this Mac.";
            return Status::NotFound;
        }
        *portOut    = &async;
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
    // 0600, not whatever the umask says. This file is the private key: whoever
    // reads it can be this machine to every peer that has pinned it. The bare
    // fopen("wb") that used to be here produced 0644, and the same mistake in
    // airusb-exportd — which runs as root — put a world-readable Ed25519 seed
    // on disk. Found on a real machine, not in review.
    Seed seed{};
    std::string blob;
    if (platform::readWholeFile(path, blob, seed.size()) && blob.size() == seed.size()) {
        std::memcpy(seed.data(), blob.data(), seed.size());
        (void)platform::restrictToOwnerIfLoose(path);
        return LocalIdentity::fromSeed(seed);
    }

    randomBytes(std::span<std::uint8_t>(seed.data(), seed.size()));
    (void)platform::writeFileAtomically(
        path, std::string(reinterpret_cast<const char*>(seed.data()), seed.size()),
        /*privateToOwner=*/true);
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
    // Not `int`. A socket handle is a signed int on POSIX but an unsigned
    // UINT_PTR on Windows, so storing one in an int truncates it on 64-bit
    // Windows and then sign-extends the wreckage when it is passed to accept().
    // The error test has to be platform::isValid() for the same reason:
    // INVALID_SOCKET is (SOCKET)~0, which is not "< 0" in an unsigned type.
    // MSVC would have warned C4244 here, but /wd4244 is on for the narrowings
    // the shim handles deliberately, so this one would have passed in silence.
    const platform::SocketHandle listenFd = TcpStream::listen(port, &st);
    if (!platform::isValid(listenFd)) {
        logLine("ERROR", "could not listen on port " + std::to_string(port));
        return 1;
    }
    logLine("ATTACH", "listening on port " + std::to_string(port));

    FakeDeviceSource source;
    // ONE authority for the whole life of the process, deliberately outside the
    // accept loop. Inside it, an ownership record would die with each session —
    // which is exactly the bug that let a disconnected importer's drive be
    // handed to the next peer that connected.
    LeaseAuthority leases(Clock::system());

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
        ec.leases  = &leases;
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

int runConnect(const std::string& host, std::uint16_t port, bool probe, bool writeTest,
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

    // The write half, only when asked for in so many words. Everything above this
    // point is read-only and safe to point at anything; everything below it is
    // not, which is why it is a separate instrument behind a separate flag.
    bool writeOk = true;
    if (writeTest && r.passed) {
        diag::WriteProbe wp(*devicePort, eps);
        wp.setTrace([](const std::string& l) { logLine("XFER", l); });

        diag::WriteProbe::Options wopt;
        wopt.blockSize = r.blockSize ? r.blockSize : 512;
        // LBA 1024 clears the partition TABLE and nothing else. This used to
        // claim it was "well past" anything structural, so an accident would
        // "damage free space rather than the map of where everything is" —
        // measured against a real 32 GB stick on 2026-08-09, that is false. Its
        // partition begins at LBA 128, so LBA 1024 is 896 sectors INSIDE the
        // filesystem, where exFAT keeps its allocation bitmap and FAT.
        //
        // The number is not raised, because there is no offset that is safe on
        // an unknown medium: past the metadata is user data, and a bigger
        // number only changes whose bytes are lost. The guard is the flag and
        // the fact that this instrument is a separate type with a method called
        // runDestructiveWriteTest — not a hopeful choice of sector.
        wopt.startLba  = 1024;

        const diag::WriteProbeResult wr = wp.runDestructiveWriteTest(wopt);
        std::printf("\n--- BOT write probe over the network ---\n%s", wr.summary().c_str());
        std::fflush(stdout);
        writeOk = wr.passed;
        if (!wr.passed) logLine("ERROR", "WRITE=FAIL — " + wr.failure);

        // Segmentation, said out loud rather than assumed.
        //
        // The write probe's largest run is 128 KiB, which exceeds 65 519 — the
        // largest record this protocol can ever negotiate — so a correct
        // implementation MUST have split it, in both directions: the OUT payload
        // going down, and the read-back coming up. Until this line existed the
        // largest transfer any end-to-end run had ever carried was 16 384 bytes,
        // which fits inside the default 16 640-byte record and therefore proved
        // the unsegmented path twice while appearing to prove both.
        //
        // It is a hard gate, not a note. A run where segmentation did not fire
        // did not test what this flag claims to test, and reporting PASS for it
        // is how the Windows path came to look verified when it was not.
        char seg[256];
        std::snprintf(seg, sizeof seg,
                      "SEGMENTATION out=%llu in=%llu contRecords=%llu "
                      "maxSegment=%u largestOut=%u fired=%s",
                      static_cast<unsigned long long>(devicePort->segmentedOutTransfers()),
                      static_cast<unsigned long long>(devicePort->segmentedInTransfers()),
                      static_cast<unsigned long long>(devicePort->inContinuationRecords()),
                      devicePort->maxSegmentBytes(), wr.largestOutBytes,
                      (devicePort->segmentedOutTransfers() > 0 &&
                       devicePort->segmentedInTransfers()  > 0) ? "yes" : "NO");
        logLine("XFER", seg);

        if (wr.passed && (devicePort->segmentedOutTransfers() == 0 ||
                          devicePort->segmentedInTransfers()  == 0)) {
            logLine("ERROR", "SEGMENTATION=FAIL — a 128 KiB transfer crossed the "
                             "session without being split, which cannot happen "
                             "under a legal record size");
            writeOk = false;
        }
    }

    (void)client.detach();

    if (r.passed && writeOk) {
        logLine("XFER", "RESULT=PASS — a USB Mass Storage exchange completed over "
                        "an encrypted, authenticated network session");
        return 0;
    }
    if (!r.passed) logLine("ERROR", "RESULT=FAIL — " + r.failure);
    return 6;
}

void usage(const char* argv0)
{
    std::fprintf(stderr,
        "usage:\n"
        "  %s serve   [--port N] [--id PATH] [--peers PATH]\n"
        "  %s connect --host H [--port N] [--probe] [--write-test]\n"
        "                    [--id PATH] [--peers PATH]\n"
        "\n"
        "  serve       offer a simulated USB drive over the network\n"
        "  connect     attach to one, and with --probe read from it\n"
        "  --write-test  ALSO WRITE TO THE DEVICE, to exercise the host->device\n"
        "                path. DESTROYS DATA from LBA 1024 onward. It restores\n"
        "                what it overwrote if it completes, and cannot if it is\n"
        "                interrupted. Never point this at a disk you care about.\n"
        "\n"
        "  Portable: the client builds and runs on macOS, Linux and Windows.\n", argv0, argv0);
}

} // namespace

// `char*`, not `const char*`. The standard names exactly two forms of main, and
// GCC and Clang accept the const variant silently even under -pedantic-errors,
// so nothing on this side of the fence would ever have said so. Conforming to
// the spelled form costs nothing here — every use immediately becomes a
// std::string or is passed as a const char* — and removes a question that would
// otherwise be answered for the first time by a compiler nobody has run yet.
int main(int argc, char* argv[])
{
    // First, before anything prints. The SAS line a user has to read is one of
    // the strings this protects.
    const platform::ConsoleUtf8 utf8Console;

    if (argc < 2) { usage(argv[0]); return 64; }

    const std::string mode = argv[1];
    std::uint16_t port = 7714;
    std::string host   = "127.0.0.1";
    std::string idPath = mode == "serve" ? "airusb-serve.id" : "airusb-connect.id";
    std::string peersPath = mode == "serve" ? "airusb-serve.peers" : "airusb-connect.peers";
    bool probe = false;
    bool writeTest = false;

    for (int i = 2; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--port" && i + 1 < argc)
            port = static_cast<std::uint16_t>(std::atoi(argv[++i]));
        else if (a == "--host" && i + 1 < argc)  host = argv[++i];
        else if (a == "--id" && i + 1 < argc)    idPath = argv[++i];
        else if (a == "--peers" && i + 1 < argc) peersPath = argv[++i];
        else if (a == "--probe")                 probe = true;
        else if (a == "--write-test")          { probe = true; writeTest = true; }
        else { usage(argv[0]); return 64; }
    }

    if (mode == "serve")   return runServe(port, idPath, peersPath);
    if (mode == "connect") return runConnect(host, port, probe, writeTest, idPath, peersPath);

    usage(argv[0]);
    return 64;
}
