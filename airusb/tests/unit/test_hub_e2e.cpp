// Two machines, one process: the pairing dance, both ways round.
//
// WHY THIS TEST EXISTS AT ALL
//
// The short authentication string is derived from the handshake hash, so it is
// different in every session. Both people therefore have to be looking at the
// SAME session's number — and the exporter is obliged to end that session the
// instant it pins a peer, because its grants were read at handshake time and
// carrying on would make its own record of what it authorised untrue.
//
// Those two facts guarantee the connection is torn down in the middle of every
// first pairing. Whether the product survives that depends on which side
// pressed first, and "it worked when I tried it" is not an answer, because the
// order is decided by two people in different rooms.
//
// So this runs the whole thing twice: importer-first and exporter-first. Both
// must end with a device attached and a USB Mass Storage exchange completed.
//
// WHY IT USES A THREAD
//
// Because two machines are two machines. Each HubState is touched by exactly
// one thread and they communicate only through a TCP socket, which is the same
// arrangement the real deployment has — the thread is standing in for the other
// computer, not for concurrency inside the hub. Nothing here shares a HubState
// across threads, and nothing in HubState would be safe if it did.

#include "../TestHarness.h"
#include "../../control/HubState.h"
#include "../../control/Json.h"
#include "../../control/SimulatedDeviceSource.h"
#include "../../core/Platform.h"

#include <atomic>
#include <string>
#include <thread>

using namespace airusb;
using namespace airusb::control;

namespace {

crypto::LocalIdentity identityFrom(std::uint8_t fill)
{
    crypto::Seed seed{};
    for (std::size_t i = 0; i < seed.size(); ++i)
        seed[i] = static_cast<std::uint8_t>(fill + i);
    return crypto::LocalIdentity::fromSeed(seed);
}

/// The sharing machine, on its own thread, driven by two flags. Everything it
/// touches belongs to it.
class SharerThread {
public:
    SharerThread()
        : _identity(identityFrom(0x10))
    {
        HubState::Config c;
        c.devices     = &_devices;
        c.identity    = &_identity;
        c.peers       = &_peers;
        c.machineName = "the machine with the drive";
        (void)_hub.begin(c);
    }

    Status start()
    {
        std::string why;
        const Status s = _hub.shareStart(0, &why);
        if (s != Status::Ok) return s;
        _port.store(_hub.sharePort());
        _thread = std::thread([this] { run(); });
        return Status::Ok;
    }

    ~SharerThread()
    {
        _stop.store(true);
        if (_thread.joinable()) _thread.join();
    }

    std::uint16_t port() const noexcept { return _port.load(); }
    ShareState    state() const noexcept { return static_cast<ShareState>(_state.load()); }
    std::uint32_t sas()   const noexcept { return _sas.load(); }
    void approve()        { _approve.store(true); }
    /// Blocks until the worker has carried the approval out, so a test never
    /// races its own instruction.
    bool approveAndWait(int ms = 3000)
    {
        approve();
        for (int i = 0; i < ms; ++i) {
            if (!_approve.load()) return true;
            platform::sleepMs(1);
        }
        return false;
    }

private:
    void run()
    {
        while (!_stop.load()) {
            if (_approve.load()) {
                std::string why;
                // The ticket is read from the SAME state the window would
                // render, which is the whole point of it: an approval that does
                // not name the question it is answering is refused now.
                (void)_hub.shareApprove(_hub.shareNonce(), _hub.sharePeerFingerprint(),
                                        _hub.shareSas(), true, &why);
                _approve.store(false);
            }
            const int did = _hub.pump();
            _state.store(static_cast<int>(_hub.shareState()));
            _sas.store(_hub.shareSas());
            platform::sleepMs(did > 0 ? 1 : 3);
        }
    }

    SimulatedDeviceSource  _devices;
    crypto::LocalIdentity  _identity;
    session::PeerStore     _peers;
    HubState               _hub;
    std::thread            _thread;
    std::atomic<bool>      _stop{false};
    std::atomic<bool>      _approve{false};
    std::atomic<int>       _state{0};
    std::atomic<unsigned>  _sas{0};
    std::atomic<std::uint16_t> _port{0};
};

/// Spins the importer's own pump until `pred` holds, so the test waits on the
/// thing it cares about rather than on a sleep long enough to usually work.
template <typename Pred>
bool waitFor(HubState& hub, Pred pred, int ms = 15000)
{
    for (int i = 0; i < ms; ++i) {
        if (pred()) return true;
        hub.pump();
        platform::sleepMs(1);
    }
    return pred();
}

bool waitForShare(const SharerThread& s, ShareState want, int ms = 15000)
{
    for (int i = 0; i < ms; ++i) {
        if (s.state() == want) return true;
        platform::sleepMs(1);
    }
    return s.state() == want;
}

/// The importer, on the main thread. Returns false if anything went wrong.
struct Importer {
    crypto::LocalIdentity identity = identityFrom(0x90);
    session::PeerStore    peers;
    HubState              hub;

    Importer()
    {
        HubState::Config c;
        c.identity    = &identity;
        c.peers       = &peers;
        c.machineName = "the machine that wants it";
        (void)hub.begin(c);
    }
};

/// Attach the offered device and run the read-only Bulk-Only Transport probe.
/// This is the line that makes the test about the product rather than about a
/// state machine: bytes have to cross the session and come back right.
void attachAndVerify(HubState& hub)
{
    JsonOut before;
    hub.writeStateJson(before);
    CHECK(before.str().find("Simulated Flash Disk") != std::string::npos);

    // The uid is not guessed; it is read out of what the peer offered.
    const std::string blob = before.str();
    const std::size_t at = blob.find("\"uid\":\"");
    CHECK(at != std::string::npos);
    const std::size_t start = at + 7;
    const std::string uid = blob.substr(start, blob.find('"', start) - start);
    CHECK_EQ(static_cast<int>(uid.size()), 32);

    std::string why;
    CHECK(hub.importAttach(uid, &why) == Status::Ok);
    CHECK(hub.importState() == ImportState::Attached);

    CHECK(hub.importPing(&why) == Status::Ok);
    CHECK(hub.importVerify(&why) == Status::Ok);

    JsonOut after;
    hub.writeStateJson(after);
    CHECK(after.str().find("\"passed\":true") != std::string::npos);
    CHECK(after.str().find("Scripted Device") != std::string::npos);

    CHECK(hub.importDetach(&why) == Status::Ok);
    CHECK(hub.importState() == ImportState::Connected);
}

// ---------------------------------------------------------------------------

void testImporterApprovesFirst()
{
    std::printf("pairing, importer first\n");

    TEST_CASE("both sides show the same number, and the drive ends up attached") {
        SharerThread sharer;
        CHECK(sharer.start() == Status::Ok);
        CHECK(waitForShare(sharer, ShareState::Listening));

        Importer imp;
        std::string why;
        CHECK(imp.hub.importConnect("127.0.0.1", sharer.port(), &why) == Status::Ok);
        CHECK(imp.hub.importState() == ImportState::AwaitingApproval);
        CHECK(waitForShare(sharer, ShareState::AwaitingApproval));

        // The property the whole ceremony rests on. If these ever differ, the
        // six digits a person is asked to compare mean nothing.
        CHECK_EQ(imp.hub.importSas(), sharer.sas());
        CHECK(imp.hub.importSas() != 0u);

        CHECK(imp.hub.importApprove(imp.hub.importNonce(), imp.hub.importPeerFingerprint(),
                                    imp.hub.importSas(), true, &why) == Status::Ok);
        CHECK(imp.hub.importState() == ImportState::WaitingForPeer);

        // Still connected, deliberately: the other person is still looking at
        // this session's number.
        CHECK(waitForShare(sharer, ShareState::AwaitingApproval));
        CHECK(sharer.approveAndWait());

        CHECK(waitFor(imp.hub, [&] { return imp.hub.importState() == ImportState::Connected; }));
        attachAndVerify(imp.hub);
    }
}

void testExporterApprovesFirst()
{
    std::printf("pairing, exporter first\n");

    TEST_CASE("the importer loses its session mid-decision and recovers") {
        // This is the order that breaks a naive implementation. The exporter
        // pins and drops while the importer is still deciding, so the number
        // the importer was looking at belongs to a session that no longer
        // exists — and the number it gets on reconnect is a different one.
        SharerThread sharer;
        CHECK(sharer.start() == Status::Ok);
        CHECK(waitForShare(sharer, ShareState::Listening));

        Importer imp;
        std::string why;
        CHECK(imp.hub.importConnect("127.0.0.1", sharer.port(), &why) == Status::Ok);
        CHECK(imp.hub.importState() == ImportState::AwaitingApproval);
        CHECK(waitForShare(sharer, ShareState::AwaitingApproval));

        const std::uint32_t firstSas = imp.hub.importSas();
        CHECK_EQ(firstSas, sharer.sas());

        CHECK(sharer.approveAndWait());

        // The importer must reconnect on its own and offer a NEW number, which
        // the sharer — now paired — shows as its session number rather than as
        // a question. Nobody is left comparing a number to nothing.
        //
        // Sampled rather than merely awaited, because the defect this catches
        // is a state that exists for about a second and then repairs itself:
        // the session dies, taking the SAS with it, and the window goes on
        // asking "do these six digits match?" above a blank space. Observed
        // against `airusb-net serve`, which pins and drops on the spot.
        bool everAskedWithoutANumber = false;
        const bool reconnected = waitFor(imp.hub, [&] {
            if (imp.hub.importState() == ImportState::AwaitingApproval &&
                imp.hub.importSas() == 0)
                everAskedWithoutANumber = true;
            return imp.hub.importState() == ImportState::AwaitingApproval &&
                   imp.hub.importSas() != 0 && imp.hub.importSas() != firstSas;
        });
        CHECK(reconnected);
        CHECK(!everAskedWithoutANumber);
        CHECK(waitForShare(sharer, ShareState::Serving));
        CHECK_EQ(imp.hub.importSas(), sharer.sas());

        CHECK(imp.hub.importApprove(imp.hub.importNonce(), imp.hub.importPeerFingerprint(),
                                    imp.hub.importSas(), true, &why) == Status::Ok);
        CHECK(waitFor(imp.hub, [&] { return imp.hub.importState() == ImportState::Connected; }));
        attachAndVerify(imp.hub);
    }
}

void testRefusalIsFinal()
{
    std::printf("refusing\n");

    TEST_CASE("a refusal pins nothing and does not quietly redial") {
        SharerThread sharer;
        CHECK(sharer.start() == Status::Ok);
        CHECK(waitForShare(sharer, ShareState::Listening));

        Importer imp;
        std::string why;
        CHECK(imp.hub.importConnect("127.0.0.1", sharer.port(), &why) == Status::Ok);
        CHECK(imp.hub.importState() == ImportState::AwaitingApproval);

        CHECK(imp.hub.importApprove(imp.hub.importNonce(), imp.hub.importPeerFingerprint(),
                                    imp.hub.importSas(), false, &why) == Status::Ok);
        CHECK(imp.hub.importState() == ImportState::Off);
        CHECK_EQ(static_cast<int>(imp.peers.size()), 0);

        // The reconnect logic is the one thing that could undo a refusal, so
        // give it plenty of chances to misbehave.
        for (int i = 0; i < 3000; ++i) { imp.hub.pump(); platform::sleepMs(1); }
        CHECK(imp.hub.importState() == ImportState::Off);
        CHECK_EQ(static_cast<int>(imp.peers.size()), 0);
    }
}

void testUnpairedPeerGetsNothing()
{
    std::printf("the trust gate, from the outside\n");

    TEST_CASE("an unpaired importer is answered, and refused") {
        // §3.14: PING is allowed, LIST_DEVICES is not. Both halves matter — a
        // machine that answered nothing would be indistinguishable from one
        // that had gone away, which is exactly what the pairing heartbeat has
        // to tell apart.
        SharerThread sharer;
        CHECK(sharer.start() == Status::Ok);
        CHECK(waitForShare(sharer, ShareState::Listening));

        Importer imp;
        std::string why;
        CHECK(imp.hub.importConnect("127.0.0.1", sharer.port(), &why) == Status::Ok);
        CHECK(imp.hub.importState() == ImportState::AwaitingApproval);

        CHECK(imp.hub.importPing(&why) == Status::Ok);

        const Status listed = imp.hub.importRefresh(&why);
        CHECK(listed == Status::NotPaired || listed == Status::NotPermitted);

        // And nothing can be attached through the refusal.
        CHECK(imp.hub.importAttach(std::string(32, 'a'), &why) != Status::Ok);
        imp.hub.importDisconnect();
    }
}

} // namespace

int main()
{
    std::printf("test_hub_e2e\n");
    testImporterApprovesFirst();
    testExporterApprovesFirst();
    testRefusalIsFinal();
    testUnpairedPeerGetsNothing();
    TEST_MAIN_END();
}
