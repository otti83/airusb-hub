// airusb-brokerd — the one process on this machine that owns its USB identity.
//
//   airusb-brokerd [--socket PATH] [--share] [--share-port N] [--name TEXT]
//                  [--id PATH] [--peers PATH] [--allow-uid N] [--simulated]
//
// WHAT IT OWNS, AND WHY IT IS ONE PROCESS
//
//   * the machine's Noise identity and its pinned-peer store,
//   * every network session, in both directions,
//   * the lease: who has a device from here, and whether it may be reassigned,
//   * the PRESENTER: the thing that hands a remote device to this computer's
//     operating system.
//
// Those four used to be spread across three programs with three identities.
// `airusb-hubd` had one and showed a person six digits; `airusb-exportd` and
// `airusb-vhci` had another and paired without asking anybody. So the ceremony
// protected a diagnostic connection while a different key authorised the one
// that moved a filesystem. Merging them is not tidiness — it is the only way
// the number on the screen can be the number that matters.
//
// WHY IT IS PRIVILEGED, WHICH IS NOT A CHOICE
//
// Linux tells vhci-hcd about a socket by writing a FILE DESCRIPTOR NUMBER into
// sysfs, and a descriptor number is only meaningful in the process that writes
// it. So the process holding the socket is the process writing sysfs, writing
// there needs root, the network session is on the other end of that same
// socket, and therefore the identity that authenticates the session is in the
// root process too. The chain has no seam to put a boundary in.
//
// THE WINDOW IS NOT THIS PROCESS
//
// `airusb-hubd` connects to the socket below and can only PROPOSE. It never
// receives a key, never forwards a protocol record, and cannot pin a peer the
// broker did not itself put a question about — see BrokerProtocol.h. What the
// local channel establishes is WHICH USER is at the keyboard (getpeereid on
// POSIX, the pipe's ACL on Windows); what it does not establish is which
// program, and LocalEndpoint.h says so plainly rather than implying more.

#include "../control/BrokerServer.h"
#include "../session/DevicePresenter.h"
#include "../control/HubState.h"
#include "../control/LocalEndpoint.h"
#include "../control/SimulatedDeviceSource.h"
#include "../core/Platform.h"
#include "../crypto/Identity.h"
#include "../crypto/Primitives.h"
#include "../session/PeerStore.h"

#if defined(__linux__)
#  include "../platform/linux/VhciPresenter.h"
#elif defined(_WIN32)
#  include "../platform/windows/UdecxPresenter.h"
#endif

#include <atomic>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>

#if !defined(_WIN32)
#  include <unistd.h>
#endif

using namespace airusb;
using namespace airusb::control;
using namespace airusb::crypto;
using namespace airusb::session;

namespace {

std::atomic<bool> gStop{false};
extern "C" void onSignal(int) { gStop.store(true); }

LocalIdentity loadOrCreateIdentity(const std::string& path)
{
    Seed seed{};
    std::string blob;
    if (platform::readWholeFile(path, blob, seed.size()) && blob.size() == seed.size()) {
        std::memcpy(seed.data(), blob.data(), seed.size());
        // A seed that was written loose by an older build is tightened on the
        // way in. This process is privileged, so a world-readable private key
        // here is worse than anywhere else in the project — and that exact
        // mistake was found on a real machine once already.
        (void)platform::restrictToOwnerIfLoose(path);
        return LocalIdentity::fromSeed(seed);
    }
    randomBytes(std::span<std::uint8_t>(seed.data(), seed.size()));
    (void)platform::writeFileAtomically(
        path, std::string(reinterpret_cast<const char*>(seed.data()), seed.size()),
        /*privateToOwner=*/true);
    return LocalIdentity::fromSeed(seed);
}

std::string machineName()
{
    if (const char* h = std::getenv("HOSTNAME"); h && *h) return h;
    if (const char* h = std::getenv("COMPUTERNAME"); h && *h) return h;
#if !defined(_WIN32)
    char buf[128] = {};
    if (::gethostname(buf, sizeof buf - 1) == 0 && buf[0]) return buf;
#endif
    return "this machine";
}

/// The presenter for THIS build, chosen by what the platform can actually do
/// rather than by what it is called.
std::unique_ptr<session::IDevicePresenter> makePresenter()
{
#if defined(__linux__)
    return std::make_unique<linuxvhci::VhciPresenter>(Clock::system());
#elif defined(__APPLE__)
    // The one thing Apple gates. Everything else in this project works on a
    // Mac; this does not, and will not until FB24214361 is granted. Saying so
    // in the window beats a button that quietly does something smaller.
    return std::make_unique<session::UnavailablePresenter>(
        "unavailable-macos",
        "macOS cannot present a remote device as a real USB device yet. It needs "
        "the com.apple.developer.usb.host-controller-interface entitlement from "
        "Apple, requested as FB24214361 and not yet granted. This Mac can still "
        "SHARE its own devices, and can read a remote one for diagnostics.");
#elif defined(_WIN32)
    // W5. It reports canPresent() == false — with the reason — on every machine
    // where airusb.sys is not installed, which today is every machine: the
    // driver compiles, passes Code Analysis clean, and has never been loaded.
    return std::make_unique<windows::UdecxPresenter>(Clock::system());
#else
    return std::make_unique<session::UnavailablePresenter>(
        "unavailable", "This platform has no USB importer.");
#endif
}

void usage(const char* argv0)
{
    std::fprintf(stderr,
        "usage: %s [options]\n"
        "\n"
        "  --socket PATH    where the window connects   (default %s)\n"
        "  --share          start sharing immediately\n"
        "  --share-port N   the LAN port devices are offered on (default 7714)\n"
        "  --name TEXT      how this machine introduces itself\n"
        "  --id PATH        identity seed          (default airusb.id)\n"
        "  --peers PATH     pinned peers           (default airusb.peers)\n"
        "  --allow-uid N    only this uid may drive the broker\n"
        "  --simulated      offer a RAM-backed device instead of real hardware\n"
        "\n"
        "This process owns the machine's USB identity, its pinned peers, its\n"
        "leases and its importer. The window (airusb-hubd) connects to the\n"
        "socket above and can only propose; it never holds a key.\n",
        argv0, defaultBrokerPath().c_str());
}

} // namespace

int main(int argc, char* argv[])
{
    const platform::ConsoleUtf8 utf8Console;

    std::string   sockPath  = defaultBrokerPath();
    std::string   idPath    = "airusb.id";
    std::string   peersPath = "airusb.peers";
    std::string   name      = machineName();
    std::uint16_t sharePort = 7714;
    bool          shareNow  = false;
    bool          simulated = false;
    std::uint32_t allowUid  = 0xFFFFFFFFu;
    bool          enforceUid = false;

    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if      (a == "--socket"     && i + 1 < argc) sockPath  = argv[++i];
        else if (a == "--id"         && i + 1 < argc) idPath    = argv[++i];
        else if (a == "--peers"      && i + 1 < argc) peersPath = argv[++i];
        else if (a == "--name"       && i + 1 < argc) name      = argv[++i];
        else if (a == "--share-port" && i + 1 < argc)
            sharePort = static_cast<std::uint16_t>(std::atoi(argv[++i]));
        else if (a == "--allow-uid"  && i + 1 < argc) {
            allowUid = static_cast<std::uint32_t>(std::strtoul(argv[++i], nullptr, 10));
            enforceUid = true;
        }
        else if (a == "--share")     shareNow  = true;
        else if (a == "--simulated") simulated = true;
        else { usage(argv[0]); return 64; }
    }

    std::signal(SIGINT, onSignal);
#if defined(SIGTERM)
    std::signal(SIGTERM, onSignal);
#endif
#if defined(SIGPIPE)
    // A window that exits mid-write must become a closed connection, never a
    // signal that kills the daemon holding somebody's drive.
    std::signal(SIGPIPE, SIG_IGN);
#endif

    LocalIdentity identity = loadOrCreateIdentity(idPath);
    PeerStore peers;
    (void)peers.load(peersPath);

    std::unique_ptr<session::IDevicePresenter> presenter = makePresenter();

    // The exporter half. `--simulated` is the RAM-backed device; the real
    // capture backends live in the platform daemons and are wired in as they
    // gain an IDeviceSource that this process can hold.
    std::unique_ptr<SimulatedDeviceSource> sim;
    if (simulated) sim = std::make_unique<SimulatedDeviceSource>();

    HubState hub;
    HubState::Config hc;
    hc.devices     = sim.get();
    hc.identity    = &identity;
    hc.peers       = &peers;
    hc.peersPath   = peersPath;
    hc.machineName = name;
    hc.presenter   = presenter.get();
    if (hub.begin(hc) != Status::Ok) {
        std::fprintf(stderr, "airusb-brokerd: could not start\n");
        return 1;
    }

    LocalListener listener;
    std::string why;
    // 0600 on POSIX. The broker runs as root and the window does not, so a
    // deployment that wants the console user to reach it relaxes this to 0660
    // with a group — deliberately not the default, because a socket that grants
    // control of this machine's USB devices should widen only on purpose.
    if (listener.open(sockPath, 0600, &why) != Status::Ok) {
        std::fprintf(stderr, "airusb-brokerd: %s\n", why.c_str());
        return 1;
    }

    BrokerServer::Config bc;
    bc.allowedUid = allowUid;
    bc.enforceUid = enforceUid;
    BrokerServer server(hub, listener, bc);
    server.setMachineName(name);
    server.setFingerprint(fingerprintText(fingerprint(identity.identityKey())));

    std::printf("@@AIRUSB_BROKER@@ identity %s\n",
                fingerprintText(fingerprint(identity.identityKey())).c_str());
    std::printf("@@AIRUSB_BROKER@@ socket %s\n", sockPath.c_str());
    std::printf("@@AIRUSB_BROKER@@ presenter %s canPresent=%s\n",
                presenter->name(), presenter->canPresent() ? "yes" : "no");
    if (!presenter->canPresent())
        std::printf("@@AIRUSB_BROKER@@ %s\n", presenter->whyNot().c_str());
    std::fflush(stdout);

    if (shareNow) {
        std::string sw;
        if (hub.shareStart(sharePort, &sw) != Status::Ok)
            std::fprintf(stderr, "airusb-brokerd: could not start sharing: %s\n", sw.c_str());
        else
            std::printf("@@AIRUSB_BROKER@@ sharing on port %u\n",
                        static_cast<unsigned>(sharePort));
        std::fflush(stdout);
    }

    while (!gStop.load()) {
        int did = server.poll();
        did += hub.pump();
        platform::sleepMs(did > 0 ? 2 : 15);
    }

    std::printf("\n@@AIRUSB_BROKER@@ stopping — releasing anything held\n");
    hub.importDisconnect();
    hub.shareStop();
    listener.close();
    return 0;
}
