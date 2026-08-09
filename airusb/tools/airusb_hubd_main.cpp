// airusb-hubd — the window.
//
//   airusb-hubd [--ui-port N] [--broker PATH] [--standalone]
//               [--share-port N] [--share] [--open|--no-open]
//               [--id PATH] [--peers PATH] [--token PATH] [--name TEXT]
//
// Runs an HTTP control plane on 127.0.0.1 and prints a URL. Opening that URL
// gives the product's interface on macOS, Linux and Windows, from one binary,
// with no toolkit and no installed dependency.
//
// TWO MODES, AND THE DIFFERENCE IS NOT COSMETIC
//
// **Attached to a broker** (the default). `airusb-brokerd` owns the machine's
// identity, its pinned peers, its leases and its importer; this process holds
// none of those and can only propose. The six digits a person compares belong
// to the session that really moves a filesystem, because there is only one
// session.
//
// **Standalone** (`--standalone`, or no broker running). This process runs the
// same state machine in-process with the DIAGNOSTIC presenter: it can pair,
// list, and read a remote device, and it cannot add one to this computer. That
// is genuinely useful on a machine with no driver, and it is a different thing
// from the product — so it says so, in the window, in its own words rather
// than by omission.
//
// The distinction used to be invisible, and that was the defect: the window
// had its OWN identity and pin store, so a person compared six digits
// belonging to a diagnostic connection while `airusb-exportd` and
// `airusb-vhci` paired with a different key and never showed anybody anything.
//
// WHAT IT DOES NOT NEED
//
// Root, in either mode. Presenting a device to an operating system is the
// broker's job and is privileged for reasons recorded in its own file.
//
// THE TOKEN, AND WHY IT IS IN THE FRAGMENT
//
// Loopback is not an authorisation boundary: on a shared machine every local
// account can open a socket to 127.0.0.1. So the API requires a bearer token
// that lives in a file only this user can read. The URL carries it after a `#`,
// because a browser never sends a fragment to a server — it stays out of the
// access log, out of Referer, and out of anything else that records URLs. The
// page lifts it out of `location.hash` and puts it in a header.

#include "../control/BrokerClient.h"
#include "../control/BrokerFacade.h"
#include "../control/ControlApi.h"
#include "../control/HubState.h"
#include "../control/LocalEndpoint.h"
#include "../control/HttpServer.h"
#include "../control/SimulatedDeviceSource.h"
#include "../core/Platform.h"
#include "../crypto/Identity.h"
#include "../crypto/Primitives.h"
#include "../session/PeerStore.h"

#include <atomic>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

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
        return LocalIdentity::fromSeed(seed);
    }
    randomBytes(std::span<std::uint8_t>(seed.data(), seed.size()));
    (void)platform::writeFileAtomically(
        path, std::string(reinterpret_cast<const char*>(seed.data()), seed.size()),
        /*privateToOwner=*/true);
    return LocalIdentity::fromSeed(seed);
}

/// 256 bits from the same CSPRNG the identity seed comes from. Not a password,
/// not derived from anything, and never reused: a fresh one every start, so a
/// token that leaks into somebody's shell history stops working when the daemon
/// is restarted.
std::string freshToken()
{
    std::uint8_t raw[32];
    randomBytes(std::span<std::uint8_t>(raw, sizeof raw));
    return toHex(std::span<const std::uint8_t>(raw, sizeof raw));
}

std::string machineName()
{
    // Display only. It rides beside the peer's pin so a person can tell two
    // paired machines apart; nothing authenticates on it, and the fingerprint
    // beneath it is what actually identifies the peer.
    if (const char* h = std::getenv("HOSTNAME"); h && *h) return h;
    if (const char* h = std::getenv("COMPUTERNAME"); h && *h) return h;
#if !defined(_WIN32)
    char buf[128] = {};
    if (::gethostname(buf, sizeof buf - 1) == 0 && buf[0]) return buf;
#endif
    return "this machine";
}

void openInBrowser(const std::string& url)
{
    // The URL is built here out of a port number and hex, so there is nothing
    // in it a shell could take as syntax. It is still quoted, because that
    // reasoning is a property of today's code and the quoting is a property of
    // the command.
#if defined(_WIN32)
    const std::string cmd = "start \"\" \"" + url + "\"";
#elif defined(__APPLE__)
    const std::string cmd = "open \"" + url + "\"";
#else
    const std::string cmd = "xdg-open \"" + url + "\" >/dev/null 2>&1";
#endif
    // Assigned rather than cast to void: glibc marks system() warn_unused_result
    // and a (void) cast does not satisfy GCC's version of that attribute. The
    // result really is ignored on purpose — a browser that fails to open is not
    // a reason to refuse to run, and the URL has already been printed.
    const int rc = std::system(cmd.c_str());
    if (rc != 0)
        std::fprintf(stderr, "airusb-hubd: could not open a browser; use the "
                             "address above.\n");
}

void usage(const char* argv0)
{
    std::fprintf(stderr,
        "usage: %s [options]\n"
        "\n"
        "  --ui-port N     the loopback port for the window   (default 0 = pick one)\n"
        "  --broker PATH   the privileged broker's socket     (default %s)\n"
        "  --standalone    do not use a broker: run the read-only diagnostic\n"
        "                  half in this process, and say so in the window\n"
        "  --share-port N  the LAN port devices are offered on (default 7714)\n"
        "  --share         start sharing immediately, without waiting for a click\n"
        "  --no-open       print the URL instead of opening a browser\n"
        "  --open          open a browser (the default when a console is attached)\n"
        "  --name TEXT     how this machine introduces itself\n"
        "  --id PATH       identity seed          (default airusb-hub.id)\n"
        "  --peers PATH    pinned peers           (default airusb-hub.peers)\n"
        "  --token PATH    control token          (default airusb-hub.token)\n"
        "\n"
        "The window is served on 127.0.0.1 only. It needs the token printed at\n"
        "startup, which is why the URL has to be used as printed.\n",
        argv0, defaultBrokerPath().c_str());
}

} // namespace

int main(int argc, char* argv[])
{
    const platform::ConsoleUtf8 utf8Console;

    std::uint16_t uiPort    = 0;
    std::uint16_t sharePort = 7714;
    bool          shareNow  = false;
    bool          openUi    = true;
    std::string   idPath    = "airusb-hub.id";
    std::string   peersPath = "airusb-hub.peers";
    std::string   tokenPath = "airusb-hub.token";
    std::string   name      = machineName();
    std::string   brokerPath = defaultBrokerPath();
    bool          standalone = false;

    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--ui-port" && i + 1 < argc)
            uiPort = static_cast<std::uint16_t>(std::atoi(argv[++i]));
        else if (a == "--share-port" && i + 1 < argc)
            sharePort = static_cast<std::uint16_t>(std::atoi(argv[++i]));
        else if (a == "--share")    shareNow = true;
        else if (a == "--no-open")  openUi = false;
        else if (a == "--open")     openUi = true;
        else if (a == "--name"  && i + 1 < argc) name      = argv[++i];
        else if (a == "--id"    && i + 1 < argc) idPath    = argv[++i];
        else if (a == "--peers" && i + 1 < argc) peersPath = argv[++i];
        else if (a == "--token" && i + 1 < argc) tokenPath = argv[++i];
        else if (a == "--broker" && i + 1 < argc) brokerPath = argv[++i];
        else if (a == "--standalone") standalone = true;
        else { usage(argv[0]); return 64; }
    }

    std::signal(SIGINT, onSignal);
#if defined(SIGTERM)
    std::signal(SIGTERM, onSignal);
#endif

    // Which half is behind the window, decided by looking rather than by a flag
    // alone: `--standalone` forces the diagnostic mode, and otherwise the broker
    // is used if one is actually listening.
    BrokerClient broker;
    std::string brokerWhy;
    bool attached = false;
    if (!standalone) {
        attached = broker.open(brokerPath, &brokerWhy) == Status::Ok;
        if (!attached)
            std::fprintf(stderr,
                "airusb-hubd: no broker at %s (%s)\n"
                "airusb-hubd: falling back to the read-only diagnostic half. This "
                "window can pair with another machine and READ a device from it; "
                "it cannot add one to this computer. Start airusb-brokerd for that.\n",
                brokerPath.c_str(), brokerWhy.c_str());
    }

    // The standalone half. Its identity is SEPARATE from the machine's on
    // purpose and is named so: it authorises a diagnostic session and nothing
    // that touches an operating system, and conflating the two is the defect
    // this whole change exists to remove.
    LocalIdentity identity = loadOrCreateIdentity(idPath);
    PeerStore peers;
    (void)peers.load(peersPath);
    SimulatedDeviceSource devices;

    HubState hub;
    if (!attached) {
        HubState::Config hc;
        hc.devices     = &devices;
        hc.identity    = &identity;
        hc.peers       = &peers;
        hc.peersPath   = peersPath;
        hc.machineName = name;
        hc.presenter   = nullptr;      // the diagnostic probe, which says so
        if (hub.begin(hc) != Status::Ok) {
            std::fprintf(stderr, "airusb-hubd: could not start\n");
            return 1;
        }
    }

    BrokerFacade viaBroker(broker);
    IHubFacade& facade = attached ? static_cast<IHubFacade&>(viaBroker)
                                  : static_cast<IHubFacade&>(hub);

    const std::string token = freshToken();
    // 0600 where the OS has such a thing. On Windows `privateToOwner` is a
    // no-op and the file inherits the directory ACL — the same exposure the
    // identity seed already has, and documented rather than papered over.
    if (!platform::writeFileAtomically(tokenPath, token, /*privateToOwner=*/true))
        std::fprintf(stderr, "airusb-hubd: warning — could not write %s\n", tokenPath.c_str());

    HttpServer server;
    if (const Status s = server.start(uiPort); s != Status::Ok) {
        std::fprintf(stderr, "airusb-hubd: could not listen on 127.0.0.1:%u (%s)\n",
                     static_cast<unsigned>(uiPort), statusName(s));
        return 1;
    }

    GuardConfig guard;
    guard.token = token;
    guard.port  = server.port();
    ControlApi api(facade, guard);

    const std::string url = "http://127.0.0.1:" + std::to_string(server.port()) +
                            "/#t=" + token;

    // The MACHINE's identity when there is a broker, this window's diagnostic
    // one when there is not — and the line says which, because a fingerprint
    // with no owner named is the ambiguity that started all of this.
    if (attached) {
        std::printf("@@AIRUSB_HUB@@ broker %s\n", brokerPath.c_str());
        std::printf("@@AIRUSB_HUB@@ identity %s (this machine's, held by the broker)\n",
                    broker.hello().fingerprint.c_str());
        std::printf("@@AIRUSB_HUB@@ presenter %s canPresent=%s\n",
                    broker.hello().presenter.c_str(),
                    broker.hello().canPresent ? "yes" : "no");
    } else {
        std::printf("@@AIRUSB_HUB@@ standalone — DIAGNOSTIC ONLY, no device is added "
                    "to this computer\n");
        std::printf("@@AIRUSB_HUB@@ identity %s (this window's, not this machine's)\n",
                    fingerprintText(fingerprint(identity.identityKey())).c_str());
    }
    std::printf("@@AIRUSB_HUB@@ ui http://127.0.0.1:%u/\n",
                static_cast<unsigned>(server.port()));
    std::printf("@@AIRUSB_HUB@@ token-file %s\n", tokenPath.c_str());
    std::printf("\n  AirUSB Hub is running. Open this address:\n\n    %s\n\n", url.c_str());
    std::fflush(stdout);

    if (shareNow) {
        std::string why;
        if (facade.shareStart(sharePort, &why) != Status::Ok)
            std::fprintf(stderr, "airusb-hubd: could not start sharing: %s\n", why.c_str());
        else
            std::printf("@@AIRUSB_HUB@@ sharing on port %u\n",
                        static_cast<unsigned>(sharePort));
        std::fflush(stdout);
    }

    if (openUi) openInBrowser(url);

    while (!gStop.load()) {
        int did = server.poll([&api](const HttpRequest& r) { return api.handle(r); });
        // Only the standalone half has a state machine to pump. With a broker,
        // the broker pumps its own — and that is the point: the sessions, the
        // leases and the device live over there.
        if (!attached) did += hub.pump();
        // 5 ms when something is happening, 20 when nothing is. A USB session
        // that is actively moving data is driven inside its own request, so this
        // interval bounds the window's responsiveness rather than throughput.
        platform::sleepMs(did > 0 ? 5 : 20);
    }

    std::printf("\n@@AIRUSB_HUB@@ stopping — releasing anything held\n");
    if (!attached) {
        hub.importDisconnect();
        hub.shareStop();
    } else {
        // The broker keeps running and keeps its leases. Closing the window
        // must NOT hand somebody's drive back: that decision belongs to the
        // person, not to whether a browser tab is open.
        broker.close();
    }
    server.stop();
    return 0;
}
