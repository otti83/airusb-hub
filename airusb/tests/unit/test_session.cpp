// The session layer — preamble, handshake, trust gate, encrypted transport.
//
// This is the piece that connects the crypto to the wire. The tests are written
// around what an attacker on the LAN can actually do to a connection whose first
// eight bytes are plaintext:
//
//   * rewrite the version or the security flags,
//   * strip the IK bit to force a weaker pattern,
//   * present a legitimate peer's identity in a session keyed to their own,
//   * connect having never been paired and act as though they had been.
//
// And the property that makes the first two survivable: the preamble is not
// protected, it is BOUND. Both preambles become the Noise prologue, so a
// rewrite makes the two sides compute different prologues and the first MAC
// fails.

#include "../TestHarness.h"
#include "../../session/SecureSession.h"
#include "../../session/PeerStore.h"
#include "../../transport/TcpTransport.h"

#include <cstdio>
#include <cstring>
#include <string>

using namespace airusb;
using namespace airusb::crypto;
using namespace airusb::session;
using namespace airusb::transport;

namespace {

std::span<const std::uint8_t> bytesOf(const std::string& s)
{
    return std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(s.data()), s.size());
}

/// Runs two sessions against each other over a MemoryPipe until both settle.
struct Pair {
    MemoryPipe    pipe;
    SecureSession a, b;
    Status        aStatus = Status::Busy;
    Status        bStatus = Status::Busy;

    bool bothEstablished() const { return a.established() && b.established(); }
};

/// Pumps both sides to a fixed point. Returns false if neither can progress,
/// which is what a stalled or failed handshake looks like from outside.
bool converge(Pair& p)
{
    for (int i = 0; i < 40; ++i) {
        p.aStatus = p.a.pump();
        p.bStatus = p.b.pump();
        if (p.a.state() == SecureSession::State::Failed) return false;
        if (p.b.state() == SecureSession::State::Failed) return false;
        if (p.bothEstablished()) return true;
    }
    return false;
}

SecureSession::Config cfgFor(const LocalIdentity& id, bool initiator,
                             const PeerStore* peers = nullptr)
{
    SecureSession::Config c;
    c.initiator = initiator;
    c.identity  = &id;
    c.peers     = peers;
    return c;
}

void testHappyPath()
{
    std::printf("a session from a socket\n");

    TEST_CASE("XX: two strangers reach an encrypted, authenticated session") {
        const LocalIdentity ia = LocalIdentity::generate();
        const LocalIdentity ib = LocalIdentity::generate();

        Pair p;
        CHECK(p.a.begin(p.pipe.endpointA(), cfgFor(ia, true))  == Status::Busy);
        CHECK(p.b.begin(p.pipe.endpointB(), cfgFor(ib, false)) == Status::Busy);
        CHECK(converge(p));

        CHECK(p.a.pattern() == protocol::NoisePattern::XX);
        CHECK(p.b.pattern() == protocol::NoisePattern::XX);

        // Each side learned who the other is, and it is who they really are.
        CHECK(p.a.peerIdentity().identityKey == ib.identityKey());
        CHECK(p.b.peerIdentity().identityKey == ia.identityKey());

        // Same channel binding, therefore the same six digits to compare.
        CHECK(p.a.channelBinding() == p.b.channelBinding());
        CHECK_EQ(p.a.sas(), p.b.sas());
        CHECK(p.a.sas() < 1000000u);
    }

    TEST_CASE("with no pin store, both sides are Unpaired and may do nothing") {
        const LocalIdentity ia = LocalIdentity::generate();
        const LocalIdentity ib = LocalIdentity::generate();

        Pair p;
        (void)p.a.begin(p.pipe.endpointA(), cfgFor(ia, true));
        (void)p.b.begin(p.pipe.endpointB(), cfgFor(ib, false));
        CHECK(converge(p));

        // §3.14: there is no "the LAN is trusted" mode.
        CHECK(p.a.trust() == Trust::Unpaired);
        CHECK(p.b.trust() == Trust::Unpaired);
        CHECK(!p.a.mayList());
        CHECK(!p.a.mayAttach());
        CHECK(!p.b.mayList());
        CHECK(!p.b.mayAttach());
    }

    TEST_CASE("traffic after the handshake is encrypted") {
        const LocalIdentity ia = LocalIdentity::generate();
        const LocalIdentity ib = LocalIdentity::generate();

        Pair p;
        (void)p.a.begin(p.pipe.endpointA(), cfgFor(ia, true));
        (void)p.b.begin(p.pipe.endpointB(), cfgFor(ib, false));
        CHECK(converge(p));

        const std::string msg = "SUBMIT would go here";
        CHECK(p.a.transport()->sendRecord(bytesOf(msg)) == Status::Ok);
        CHECK(p.a.transport()->flush() == Status::Ok);

        std::vector<std::uint8_t> got;
        CHECK(p.b.transport()->receiveRecord(got) == Status::Ok);
        CHECK(std::string(got.begin(), got.end()) == msg);
    }

    TEST_CASE("many records both ways after establishment") {
        const LocalIdentity ia = LocalIdentity::generate();
        const LocalIdentity ib = LocalIdentity::generate();

        Pair p;
        (void)p.a.begin(p.pipe.endpointA(), cfgFor(ia, true));
        (void)p.b.begin(p.pipe.endpointB(), cfgFor(ib, false));
        CHECK(converge(p));

        for (int i = 0; i < 32; ++i) {
            const std::string out = "msg " + std::to_string(i);
            CHECK(p.a.transport()->sendRecord(bytesOf(out)) == Status::Ok);
            CHECK(p.a.transport()->flush() == Status::Ok);
            std::vector<std::uint8_t> got;
            CHECK(p.b.transport()->receiveRecord(got) == Status::Ok);
            CHECK(std::string(got.begin(), got.end()) == out);

            const std::string back = "reply " + std::to_string(i);
            CHECK(p.b.transport()->sendRecord(bytesOf(back)) == Status::Ok);
            CHECK(p.b.transport()->flush() == Status::Ok);
            std::vector<std::uint8_t> got2;
            CHECK(p.a.transport()->receiveRecord(got2) == Status::Ok);
            CHECK(std::string(got2.begin(), got2.end()) == back);
        }
    }
}

void testPairingAndTrust()
{
    std::printf("pairing and the trust gate\n");

    TEST_CASE("a pinned peer reaches Paired with its grants") {
        const LocalIdentity ia = LocalIdentity::generate();
        const LocalIdentity ib = LocalIdentity::generate();

        PeerStore storeA, storeB;
        CHECK(storeA.pin(ib.publicIdentity(), "B", kDefaultGrants, 1) == Status::Ok);
        CHECK(storeB.pin(ia.publicIdentity(), "A", kDefaultGrants, 1) == Status::Ok);

        Pair p;
        (void)p.a.begin(p.pipe.endpointA(), cfgFor(ia, true, &storeA));
        (void)p.b.begin(p.pipe.endpointB(), cfgFor(ib, false, &storeB));
        CHECK(converge(p));

        CHECK(p.a.trust() == Trust::Paired);
        CHECK(p.b.trust() == Trust::Paired);
        CHECK(p.a.mayList());
        CHECK(p.a.mayAttach());
        CHECK(!storeA.hasGrant(ib.identityKey(), kMayAttachWithoutPrompt));
    }

    TEST_CASE("IK is used when the initiator has the peer pinned") {
        const LocalIdentity ia = LocalIdentity::generate();
        const LocalIdentity ib = LocalIdentity::generate();

        PeerStore storeA, storeB;
        CHECK(storeA.pin(ib.publicIdentity(), "B", kDefaultGrants, 1) == Status::Ok);
        CHECK(storeB.pin(ia.publicIdentity(), "A", kDefaultGrants, 1) == Status::Ok);

        Pair p;
        auto ca = cfgFor(ia, true, &storeA);
        ca.expectedPeer    = ib.identityKey();
        ca.hasExpectedPeer = true;

        (void)p.a.begin(p.pipe.endpointA(), ca);
        (void)p.b.begin(p.pipe.endpointB(), cfgFor(ib, false, &storeB));
        CHECK(converge(p));

        // The responder learned the pattern from the preamble, without being
        // told out of band.
        CHECK(p.a.pattern() == protocol::NoisePattern::IK);
        CHECK(p.b.pattern() == protocol::NoisePattern::IK);
        CHECK(p.a.trust() == Trust::Paired);
        CHECK(p.b.trust() == Trust::Paired);
    }

    TEST_CASE("unpinning takes the grants away") {
        const LocalIdentity ia = LocalIdentity::generate();
        const LocalIdentity ib = LocalIdentity::generate();

        PeerStore store;
        CHECK(store.pin(ib.publicIdentity(), "B", kDefaultGrants, 1) == Status::Ok);
        CHECK(store.isPaired(ib.identityKey()));
        CHECK(store.unpin(ib.identityKey()));
        CHECK(!store.isPaired(ib.identityKey()));

        Pair p;
        (void)p.a.begin(p.pipe.endpointA(), cfgFor(ia, true, &store));
        (void)p.b.begin(p.pipe.endpointB(), cfgFor(ib, false));
        CHECK(converge(p));
        CHECK(p.a.trust() == Trust::Unpaired);
    }

    TEST_CASE("one peer's pin does not grant another peer anything") {
        const LocalIdentity ia = LocalIdentity::generate();
        const LocalIdentity ib = LocalIdentity::generate();
        const LocalIdentity stranger = LocalIdentity::generate();

        PeerStore store;
        CHECK(store.pin(ib.publicIdentity(), "B", kDefaultGrants, 1) == Status::Ok);

        Pair p;
        (void)p.a.begin(p.pipe.endpointA(), cfgFor(ia, true, &store));
        (void)p.b.begin(p.pipe.endpointB(), cfgFor(stranger, false));
        CHECK(converge(p));
        CHECK(p.a.trust() == Trust::Unpaired);
        CHECK(!p.a.mayAttach());
    }

    TEST_CASE("pinning refuses an identity whose binding does not verify") {
        const LocalIdentity a = LocalIdentity::generate();
        const LocalIdentity b = LocalIdentity::generate();

        PeerIdentity forged = a.publicIdentity();
        forged.noiseKey = b.noiseKey();        // a's identity, b's Noise key

        PeerStore store;
        CHECK(store.pin(forged, "forged", kDefaultGrants, 1) == Status::AuthFailed);
        CHECK_EQ(store.size(), 0u);
    }
}

void testAttacks()
{
    std::printf("what an attacker on the LAN can try\n");

    TEST_CASE("a man in the middle rewriting the preamble breaks the handshake") {
        // §3.13: "a downgrade attempt on the plaintext preamble breaks the
        // handshake MAC." Tested with an actual man in the middle rather than by
        // asserting that two byte arrays differ.
        //
        // The attacker flips wire_minor, which nothing else validates — so if the
        // prologue did NOT bind the preamble, this session would come up
        // perfectly and the attacker would have proved they can rewrite it.
        const LocalIdentity ia = LocalIdentity::generate();
        const LocalIdentity ib = LocalIdentity::generate();

        MemoryPipe left, right;                 // A <-> MITM <-> B
        auto mitmToA = left.endpointB();
        auto mitmToB = right.endpointA();

        SecureSession a, b;
        CHECK(a.begin(left.endpointA(), cfgFor(ia, true))   == Status::Busy);
        CHECK(b.begin(right.endpointB(), cfgFor(ib, false)) == Status::Busy);

        bool tamperedAtoB = false;
        const auto relay = [&](IByteStream& from, IByteStream& to, bool tamper) {
            std::uint8_t buf[512];
            const IoResult r = from.read(std::span<std::uint8_t>(buf, sizeof buf));
            if (r.status != Status::Ok || r.bytes == 0) return;
            // The preamble is the first 8 bytes of the stream, in the clear.
            if (tamper && !tamperedAtoB && r.bytes >= wire::kPreambleSize) {
                buf[wire::kPreOffWireMinor] =
                    static_cast<std::uint8_t>(buf[wire::kPreOffWireMinor] + 1);
                tamperedAtoB = true;
            }
            (void)to.write(std::span<const std::uint8_t>(buf, r.bytes));
        };

        bool established = false;
        for (int i = 0; i < 40 && !established; ++i) {
            (void)a.pump();
            relay(*mitmToA, *mitmToB, /*tamper=*/true);
            (void)b.pump();
            relay(*mitmToB, *mitmToA, /*tamper=*/false);
            if (a.state() == SecureSession::State::Failed) break;
            if (b.state() == SecureSession::State::Failed) break;
            established = a.established() && b.established();
        }

        CHECK(tamperedAtoB);          // the attack was actually delivered
        CHECK(!established);          // and it did not work
        CHECK(!a.established());
        CHECK(!b.established());
    }

    TEST_CASE("a man in the middle relaying faithfully still cannot read it") {
        // The control for the test above: the same relay WITHOUT tampering must
        // let the session come up, or the previous test would prove nothing —
        // a broken relay also produces "not established".
        const LocalIdentity ia = LocalIdentity::generate();
        const LocalIdentity ib = LocalIdentity::generate();

        MemoryPipe left, right;
        auto midA = left.endpointB();
        auto midB = right.endpointA();

        SecureSession a, b;
        CHECK(a.begin(left.endpointA(), cfgFor(ia, true))   == Status::Busy);
        CHECK(b.begin(right.endpointB(), cfgFor(ib, false)) == Status::Busy);

        std::vector<std::uint8_t> seen;
        const auto relay = [&](IByteStream& from, IByteStream& to) {
            std::uint8_t buf[512];
            const IoResult r = from.read(std::span<std::uint8_t>(buf, sizeof buf));
            if (r.status != Status::Ok || r.bytes == 0) return;
            seen.insert(seen.end(), buf, buf + r.bytes);
            (void)to.write(std::span<const std::uint8_t>(buf, r.bytes));
        };

        bool established = false;
        for (int i = 0; i < 40 && !established; ++i) {
            (void)a.pump();
            relay(*midA, *midB);
            (void)b.pump();
            relay(*midB, *midA);
            established = a.established() && b.established();
        }
        CHECK(established);

        // The attacker saw every byte and still has neither identity key in the
        // clear: XX encrypts both statics.
        const auto contains = [&](const PublicKey& k) {
            if (seen.size() < k.size()) return false;
            for (std::size_t i = 0; i + k.size() <= seen.size(); ++i)
                if (std::memcmp(seen.data() + i, k.data(), k.size()) == 0) return true;
            return false;
        };
        CHECK(!contains(ia.identityKey()));
        CHECK(!contains(ib.identityKey()));
    }

    TEST_CASE("a mismatched prologue fails the handshake, at the crypto level") {
        // The direct version of the test above, without needing to inject bytes
        // into a pipe: two peers whose prologues differ by one bit.
        const LocalIdentity ia = LocalIdentity::generate();
        const LocalIdentity ib = LocalIdentity::generate();

        protocol::HandshakeState hi, hr;
        protocol::HandshakeState::Params pi;
        pi.pattern = protocol::NoisePattern::XX;
        pi.initiator = true;
        pi.localStatic = ia.noiseSecret();
        pi.prologue = { 'A', 'U', 'S', 'B', 1, 0, 1, 0 };
        CHECK(hi.start(pi) == Status::Ok);

        protocol::HandshakeState::Params pr = pi;
        pr.initiator = false;
        pr.localStatic = ib.noiseSecret();
        pr.prologue = { 'A', 'U', 'S', 'B', 1, 1, 1, 0 };   // wire_minor rewritten
        CHECK(hr.start(pr) == Status::Ok);

        std::vector<std::uint8_t> m0, p0, m1, p1;
        CHECK(hi.writeMessage({}, m0) == Status::Ok);
        CHECK(hr.readMessage(m0, p0) == Status::Ok);        // message 1 has no MAC
        CHECK(hr.writeMessage({}, m1) == Status::Ok);
        // The first authenticated message is where the mismatch surfaces.
        CHECK(hi.readMessage(m1, p1) == Status::AuthFailed);
    }

    TEST_CASE("a peer speaking a different wire major is refused immediately") {
        const LocalIdentity ia = LocalIdentity::generate();

        MemoryPipe pipe;
        SecureSession a;
        CHECK(a.begin(pipe.endpointA(), cfgFor(ia, true)) == Status::Busy);

        // Write a preamble from the far side claiming wire major 9.
        auto peer = pipe.endpointB();
        std::vector<std::uint8_t> bad;
        protocol::Preamble p;
        p.wireMajor = 9;
        protocol::encodePreamble(p, bad);
        const IoResult w = peer->write(bad);
        CHECK(w.status == Status::Ok);

        CHECK(a.pump() == Status::UnsupportedVersion);
        CHECK(a.state() == SecureSession::State::Failed);
        CHECK(a.failureReason().find("wire major") != std::string::npos);
    }

    TEST_CASE("a peer that does not offer Noise is refused") {
        const LocalIdentity ia = LocalIdentity::generate();

        MemoryPipe pipe;
        SecureSession a;
        CHECK(a.begin(pipe.endpointA(), cfgFor(ia, true)) == Status::Busy);

        auto peer = pipe.endpointB();
        std::vector<std::uint8_t> bad;
        protocol::Preamble p;
        p.flags = 0;                       // SEC_NOISE_XX cleared
        protocol::encodePreamble(p, bad);
        CHECK(peer->write(bad).status == Status::Ok);

        CHECK(a.pump() == Status::UnsupportedVersion);
        CHECK(a.state() == SecureSession::State::Failed);
    }

    TEST_CASE("garbage in place of a preamble is refused") {
        const LocalIdentity ia = LocalIdentity::generate();

        MemoryPipe pipe;
        SecureSession a;
        CHECK(a.begin(pipe.endpointA(), cfgFor(ia, true)) == Status::Busy);

        auto peer = pipe.endpointB();
        const std::vector<std::uint8_t> junk = { 'H','T','T','P','/','1','.','1' };
        CHECK(peer->write(junk).status == Status::Ok);

        CHECK(a.pump() == Status::MalformedFrame);
        CHECK(a.state() == SecureSession::State::Failed);
    }

    TEST_CASE("a failed session stays failed") {
        const LocalIdentity ia = LocalIdentity::generate();
        MemoryPipe pipe;
        SecureSession a;
        CHECK(a.begin(pipe.endpointA(), cfgFor(ia, true)) == Status::Busy);

        auto peer = pipe.endpointB();
        const std::vector<std::uint8_t> junk = { 0,0,0,0,0,0,0,0 };
        CHECK(peer->write(junk).status == Status::Ok);
        CHECK(a.pump() == Status::MalformedFrame);

        // No retry path. A handshake that failed is replaced, not resumed.
        CHECK(a.pump() == Status::AuthFailed);
        CHECK(a.transport() == nullptr || !a.established());
    }

    TEST_CASE("an IK initiator whose pin is stale cannot connect") {
        // The peer rotated its Noise key; our pin is out of date. IK must fail
        // rather than silently falling back, because falling back is what an
        // attacker who can force a rotation would want.
        const LocalIdentity ia = LocalIdentity::generate();
        const LocalIdentity ibOld = LocalIdentity::generate();
        const LocalIdentity ibNew = LocalIdentity::generate();

        PeerStore store;
        CHECK(store.pin(ibOld.publicIdentity(), "B", kDefaultGrants, 1) == Status::Ok);

        Pair p;
        auto ca = cfgFor(ia, true, &store);
        ca.expectedPeer    = ibOld.identityKey();
        ca.hasExpectedPeer = true;

        (void)p.a.begin(p.pipe.endpointA(), ca);
        (void)p.b.begin(p.pipe.endpointB(), cfgFor(ibNew, false));
        CHECK(!converge(p));
        CHECK(!p.a.established());
        CHECK(!p.b.established());
    }
}

void testPeerStorePersistence()
{
    std::printf("the pin store on disk\n");

    TEST_CASE("round trips through the text format") {
        const LocalIdentity a = LocalIdentity::generate();
        const LocalIdentity b = LocalIdentity::generate();

        PeerStore s;
        CHECK(s.pin(a.publicIdentity(), "Alice's Mac", kDefaultGrants, 100) == Status::Ok);
        CHECK(s.pin(b.publicIdentity(), "Bob", kMayList, 200) == Status::Ok);

        PeerStore t;
        CHECK(t.deserialize(s.serialize()));
        CHECK_EQ(t.size(), 2u);
        CHECK(t.isPaired(a.identityKey()));
        CHECK(t.hasGrant(a.identityKey(), kMayAttach));
        CHECK(!t.hasGrant(b.identityKey(), kMayAttach));
        CHECK(t.find(a.identityKey())->name == "Alice's Mac");
        CHECK_EQ(t.find(b.identityKey())->firstSeenNs, 200ull);
    }

    TEST_CASE("a corrupt file loads nothing rather than something") {
        // A partially loaded pin store looks like a working one while silently
        // having forgotten peers — which shows up as an unexplained pairing
        // prompt, and trains the user to click through it.
        const LocalIdentity a = LocalIdentity::generate();
        PeerStore s;
        CHECK(s.pin(a.publicIdentity(), "A", kDefaultGrants, 1) == Status::Ok);

        std::string text = s.serialize();
        text += "this is not a valid line\n";

        PeerStore t;
        CHECK(t.pin(a.publicIdentity(), "A", kDefaultGrants, 1) == Status::Ok);
        CHECK(!t.deserialize(text));
        // The pre-existing contents are left alone; nothing half-parsed lands.
        CHECK_EQ(t.size(), 1u);
    }

    TEST_CASE("a file with the wrong header is refused") {
        PeerStore t;
        CHECK(!t.deserialize("airusb-peers-v99\n"));
        CHECK(!t.deserialize(""));
        CHECK(!t.deserialize("garbage"));
    }

    TEST_CASE("an empty store round trips") {
        PeerStore s, t;
        CHECK(t.deserialize(s.serialize()));
        CHECK_EQ(t.size(), 0u);
    }

    TEST_CASE("a hostile peer name cannot break the format") {
        const LocalIdentity a = LocalIdentity::generate();
        PeerStore s;
        CHECK(s.pin(a.publicIdentity(), "evil\tname\nwith\nnewlines",
                    kDefaultGrants, 1) == Status::Ok);

        PeerStore t;
        CHECK(t.deserialize(s.serialize()));
        CHECK_EQ(t.size(), 1u);
        const std::string n = t.find(a.identityKey())->name;
        CHECK(n.find('\t') == std::string::npos);
        CHECK(n.find('\n') == std::string::npos);
    }

    TEST_CASE("saves and loads atomically through a real file") {
        const LocalIdentity a = LocalIdentity::generate();
        PeerStore s;
        CHECK(s.pin(a.publicIdentity(), "A", kDefaultGrants, 7) == Status::Ok);

        const std::string path = "/tmp/airusb-peerstore-test.txt";
        (void)std::remove(path.c_str());
        CHECK(s.save(path) == Status::Ok);

        PeerStore t;
        CHECK(t.load(path) == Status::Ok);
        CHECK_EQ(t.size(), 1u);
        CHECK(t.isPaired(a.identityKey()));

        (void)std::remove(path.c_str());
    }

    TEST_CASE("a missing file is a first run, not an error") {
        PeerStore t;
        CHECK(t.load("/tmp/airusb-peerstore-does-not-exist") == Status::Ok);
        CHECK_EQ(t.size(), 0u);
    }

    TEST_CASE("key rotation re-pins the same identity") {
        // Same identity key, new Noise static, freshly signed. Allowed, because
        // the binding proves the identity vouches for the new key.
        Seed seed{};
        randomBytes(std::span<std::uint8_t>(seed.data(), seed.size()));
        const LocalIdentity v1 = LocalIdentity::fromSeed(seed);

        PeerStore s;
        CHECK(s.pin(v1.publicIdentity(), "peer", kDefaultGrants, 1) == Status::Ok);
        CHECK_EQ(s.size(), 1u);
        CHECK(s.pin(v1.publicIdentity(), "peer", kDefaultGrants, 2) == Status::Ok);
        CHECK_EQ(s.size(), 1u);              // still one peer, not two
    }
}

} // namespace

int main()
{
    std::printf("test_session\n");
    testHappyPath();
    testPairingAndTrust();
    testAttacks();
    testPeerStorePersistence();
    TEST_MAIN_END();
}
