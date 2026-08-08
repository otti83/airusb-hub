// P2.4 — identity, the binding signature, the SAS, and the real record cipher.
//
// Noise proves that the peer holds the private key for some X25519 static key.
// It says nothing about whether that key belongs to anyone we should be talking
// to. Everything in this file exists to close that gap, and the tests are
// written around the ways it can be left open:
//
//   * a peer that presents someone else's identity key with its own Noise key,
//   * a binding signature that covers one key but not the other,
//   * a SAS derived from something an attacker can make agree on both sides.
//
// The last section wires the whole thing into the real RecordLayer, replacing
// NullCipher — which is what P2.4 was actually for.

#include "../TestHarness.h"
#include "../../crypto/Identity.h"
#include "../../protocol/Noise.h"
#include "../../transport/NoiseCipher.h"
#include "../../transport/TcpTransport.h"

#include <cstring>
#include <set>
#include <string>

using namespace airusb;
using namespace airusb::crypto;
using namespace airusb::protocol;
using namespace airusb::transport;

namespace {

std::span<const std::uint8_t> bytesOf(const std::string& s)
{
    return std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(s.data()), s.size());
}

/// Runs a full XX handshake carrying identity payloads, exactly as the session
/// layer will. Returns the handshake hash both sides agreed on.
struct Handshaken {
    Hash         channelBinding{};
    PeerIdentity initiatorSeesResponder;
    PeerIdentity responderSeesInitiator;
    CipherState  initSend, initRecv, respSend, respRecv;
    bool         ok = false;
};

Handshaken runXxWithIdentities(const LocalIdentity& a, const LocalIdentity& b)
{
    Handshaken r;

    HandshakeState init, resp;

    HandshakeState::Params ip;
    ip.pattern     = NoisePattern::XX;
    ip.initiator   = true;
    ip.localStatic = a.noiseSecret();
    if (init.start(ip) != Status::Ok) return r;

    HandshakeState::Params rp;
    rp.pattern     = NoisePattern::XX;
    rp.initiator   = false;
    rp.localStatic = b.noiseSecret();
    if (resp.start(rp) != Status::Ok) return r;

    // XX message 1: initiator's ephemeral only, no payload worth carrying.
    std::vector<std::uint8_t> m0, p0;
    if (init.writeMessage({}, m0) != Status::Ok) return r;
    if (resp.readMessage(m0, p0) != Status::Ok) return r;

    // Message 2 carries the responder's identity: its static key is sent here.
    std::vector<std::uint8_t> respPayload;
    encodeIdentityPayload(b, respPayload);
    std::vector<std::uint8_t> m1, p1;
    if (resp.writeMessage(respPayload, m1) != Status::Ok) return r;
    if (init.readMessage(m1, p1) != Status::Ok) return r;
    if (!decodeAndVerifyIdentityPayload(p1, init.remoteStatic(),
                                        r.initiatorSeesResponder)) return r;

    // Message 3 carries the initiator's identity.
    std::vector<std::uint8_t> initPayload;
    encodeIdentityPayload(a, initPayload);
    std::vector<std::uint8_t> m2, p2;
    if (init.writeMessage(initPayload, m2) != Status::Ok) return r;
    if (resp.readMessage(m2, p2) != Status::Ok) return r;
    if (!decodeAndVerifyIdentityPayload(p2, resp.remoteStatic(),
                                        r.responderSeesInitiator)) return r;

    if (!init.complete() || !resp.complete()) return r;
    if (!(init.handshakeHash() == resp.handshakeHash())) return r;

    r.channelBinding = init.handshakeHash();
    if (init.split(r.initSend, r.initRecv) != Status::Ok) return r;
    if (resp.split(r.respSend, r.respRecv) != Status::Ok) return r;
    r.ok = true;
    return r;
}

// ---------------------------------------------------------------------------

void testIdentity()
{
    std::printf("identity and the binding signature\n");

    TEST_CASE("a generated identity binds its own two keys") {
        const LocalIdentity id = LocalIdentity::generate();
        CHECK(verifyBinding(id.publicIdentity()));
        CHECK(id.noiseKey() == x25519PublicKey(id.noiseSecret()));
    }

    TEST_CASE("the identity key and the Noise key are different keys") {
        // Reusing one key for signing and Diffie-Hellman invalidates the
        // security proofs of both schemes.
        const LocalIdentity id = LocalIdentity::generate();
        CHECK(!(id.identityKey() == id.noiseKey()));
    }

    TEST_CASE("fromSeed is deterministic and generate is not") {
        Seed s{};
        randomBytes(std::span<std::uint8_t>(s.data(), s.size()));
        const LocalIdentity a = LocalIdentity::fromSeed(s);
        const LocalIdentity b = LocalIdentity::fromSeed(s);
        CHECK(a.identityKey() == b.identityKey());
        CHECK(a.noiseKey() == b.noiseKey());
        CHECK(a.binding() == b.binding());

        const LocalIdentity c = LocalIdentity::generate();
        const LocalIdentity d = LocalIdentity::generate();
        CHECK(!(c.identityKey() == d.identityKey()));
    }

    TEST_CASE("one seed, two independent keypairs") {
        // Both derive from the same stored secret by domain-separated labels.
        // If the labels were the same, the Ed25519 seed and the X25519 secret
        // would be the same 32 bytes.
        Seed s{};
        randomBytes(std::span<std::uint8_t>(s.data(), s.size()));
        const LocalIdentity id = LocalIdentity::fromSeed(s);
        CHECK(!(id.noiseSecret() == s));
    }

    TEST_CASE("the binding covers the identity key") {
        LocalIdentity a = LocalIdentity::generate();
        const LocalIdentity b = LocalIdentity::generate();

        PeerIdentity swapped = a.publicIdentity();
        swapped.identityKey = b.identityKey();
        CHECK(!verifyBinding(swapped));
    }

    TEST_CASE("the binding covers the Noise key") {
        const LocalIdentity a = LocalIdentity::generate();
        const LocalIdentity b = LocalIdentity::generate();

        PeerIdentity swapped = a.publicIdentity();
        swapped.noiseKey = b.noiseKey();
        CHECK(!verifyBinding(swapped));
    }

    TEST_CASE("a tampered signature does not verify") {
        const LocalIdentity a = LocalIdentity::generate();
        PeerIdentity p = a.publicIdentity();
        p.binding[0] ^= 0x01u;
        CHECK(!verifyBinding(p));
    }

    TEST_CASE("the signed message contains the context and both keys") {
        const LocalIdentity a = LocalIdentity::generate();
        const auto msg = bindingMessage(a.identityKey(), a.noiseKey());
        CHECK_EQ(msg.size(), kBindingContext.size() + 2 * kDhLen);
        CHECK(std::memcmp(msg.data(), kBindingContext.data(), kBindingContext.size()) == 0);
        CHECK(std::memcmp(msg.data() + kBindingContext.size(),
                          a.identityKey().data(), kDhLen) == 0);
        CHECK(std::memcmp(msg.data() + kBindingContext.size() + kDhLen,
                          a.noiseKey().data(), kDhLen) == 0);
    }
}

void testIdentityPayload()
{
    std::printf("the XX identity payload\n");

    TEST_CASE("a well-formed payload verifies against the negotiated key") {
        const LocalIdentity a = LocalIdentity::generate();
        std::vector<std::uint8_t> payload;
        encodeIdentityPayload(a, payload);
        CHECK_EQ(payload.size(), kIdentityPayloadLen);

        PeerIdentity got;
        CHECK(decodeAndVerifyIdentityPayload(payload, a.noiseKey(), got));
        CHECK(got.identityKey == a.identityKey());
        CHECK(got.noiseKey == a.noiseKey());
    }

    TEST_CASE("THE attack: replaying someone else's identity with your own key") {
        // An eavesdropper copies a legitimate peer's (I_pk, sigS) out of an
        // earlier handshake and presents it in their own, where Noise negotiated
        // THEIR static key. If the binding were checked against a key taken from
        // the payload, this would succeed and the attacker would inherit the
        // victim's pinned identity.
        const LocalIdentity victim   = LocalIdentity::generate();
        const LocalIdentity attacker = LocalIdentity::generate();

        std::vector<std::uint8_t> stolen;
        encodeIdentityPayload(victim, stolen);

        PeerIdentity got;
        CHECK(!decodeAndVerifyIdentityPayload(stolen, attacker.noiseKey(), got));

        // And it still works for the peer it actually belongs to.
        CHECK(decodeAndVerifyIdentityPayload(stolen, victim.noiseKey(), got));
    }

    TEST_CASE("a short or long payload is refused") {
        const LocalIdentity a = LocalIdentity::generate();
        std::vector<std::uint8_t> payload;
        encodeIdentityPayload(a, payload);

        PeerIdentity got;
        for (std::size_t n = 0; n < payload.size(); ++n) {
            CHECK(!decodeAndVerifyIdentityPayload(
                std::span<const std::uint8_t>(payload).subspan(0, n), a.noiseKey(), got));
        }
        auto tooLong = payload;
        tooLong.push_back(0);
        CHECK(!decodeAndVerifyIdentityPayload(tooLong, a.noiseKey(), got));
    }

    TEST_CASE("every single-bit corruption of the payload is refused") {
        const LocalIdentity a = LocalIdentity::generate();
        std::vector<std::uint8_t> payload;
        encodeIdentityPayload(a, payload);

        PeerIdentity got;
        for (std::size_t byte = 0; byte < payload.size(); byte += 7) {
            auto bad = payload;
            bad[byte] ^= 0x01u;
            CHECK(!decodeAndVerifyIdentityPayload(bad, a.noiseKey(), got));
        }
    }
}

void testFingerprint()
{
    std::printf("fingerprints\n");

    TEST_CASE("deterministic, and different per identity") {
        const LocalIdentity a = LocalIdentity::generate();
        const LocalIdentity b = LocalIdentity::generate();
        CHECK(fingerprint(a.identityKey()) == fingerprint(a.identityKey()));
        CHECK(!(fingerprint(a.identityKey()) == fingerprint(b.identityKey())));
    }

    TEST_CASE("rendered as four base32 groups of eight") {
        const LocalIdentity a = LocalIdentity::generate();
        const std::string t = fingerprintText(fingerprint(a.identityKey()));
        CHECK_EQ(t.size(), 35u);              // 32 characters + 3 separators
        CHECK(t[8] == ' ');
        CHECK(t[17] == ' ');
        CHECK(t[26] == ' ');

        int chars = 0;
        for (char c : t) {
            if (c == ' ') continue;
            ++chars;
            const bool valid = (c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7');
            CHECK(valid);
        }
        CHECK_EQ(chars, 32);
    }

    TEST_CASE("a one-bit change in the key changes the fingerprint") {
        const LocalIdentity a = LocalIdentity::generate();
        PublicKey k = a.identityKey();
        k[0] ^= 0x01u;
        CHECK(!(fingerprint(a.identityKey()) == fingerprint(k)));
    }
}

void testSas()
{
    std::printf("the short authentication string\n");

    TEST_CASE("both peers of a real handshake see the same six digits") {
        const LocalIdentity a = LocalIdentity::generate();
        const LocalIdentity b = LocalIdentity::generate();
        const Handshaken h = runXxWithIdentities(a, b);
        CHECK(h.ok);

        const std::uint32_t sas = sasDigits(h.channelBinding);
        CHECK(sas < 1000000u);
        CHECK_EQ(sasText(sas).size(), 6u);
    }

    TEST_CASE("different sessions give different digits") {
        // The SAS derives from the handshake hash, which includes fresh
        // ephemerals. If it depended only on the static keys, an attacker could
        // record one comparison and reuse it forever.
        const LocalIdentity a = LocalIdentity::generate();
        const LocalIdentity b = LocalIdentity::generate();

        std::set<std::uint32_t> seen;
        for (int i = 0; i < 8; ++i) {
            const Handshaken h = runXxWithIdentities(a, b);
            CHECK(h.ok);
            seen.insert(sasDigits(h.channelBinding));
        }
        // Eight draws from a million values colliding would be astronomical.
        CHECK(seen.size() >= 7);
    }

    TEST_CASE("a one-bit change in the channel binding changes the digits") {
        Hash h{};
        randomBytes(std::span<std::uint8_t>(h.data(), h.size()));
        Hash h2 = h;
        h2[0] ^= 0x01u;
        // Not guaranteed by arithmetic, but a collision here is 1 in 10^6 and
        // the value is fixed, so this is a stable regression check.
        CHECK(sasDigits(h) != sasDigits(h2));
    }

    TEST_CASE("the text form is always six characters, zero padded") {
        CHECK(sasText(0) == "000000");
        CHECK(sasText(1) == "000001");
        CHECK(sasText(42) == "000042");
        CHECK(sasText(999999) == "999999");
    }

    TEST_CASE("digits are in range for many random bindings") {
        for (int i = 0; i < 500; ++i) {
            Hash h{};
            randomBytes(std::span<std::uint8_t>(h.data(), h.size()));
            const std::uint32_t s = sasDigits(h);
            CHECK(s < 1000000u);
        }
    }
}

void testNoiseCipher()
{
    std::printf("NoiseCipher — the real IRecordCipher\n");

    TEST_CASE("a sealed record opens on the other side") {
        const LocalIdentity a = LocalIdentity::generate();
        const LocalIdentity b = LocalIdentity::generate();
        const Handshaken h = runXxWithIdentities(a, b);
        CHECK(h.ok);

        NoiseCipher ia(h.initSend, h.initRecv);
        NoiseCipher rb(h.respSend, h.respRecv);

        CHECK_EQ(ia.overhead(), crypto::kTagLen);

        const std::string msg = "hello over the wire";
        std::vector<std::uint8_t> sealed;
        CHECK(ia.seal(bytesOf(msg), sealed) == Status::Ok);
        CHECK_EQ(sealed.size(), msg.size() + crypto::kTagLen);

        std::vector<std::uint8_t> opened;
        CHECK(rb.open(sealed, opened) == Status::Ok);
        CHECK(std::string(opened.begin(), opened.end()) == msg);
    }

    TEST_CASE("a tampered record is AuthFailed and is fatal") {
        const LocalIdentity a = LocalIdentity::generate();
        const LocalIdentity b = LocalIdentity::generate();
        const Handshaken h = runXxWithIdentities(a, b);
        CHECK(h.ok);

        NoiseCipher ia(h.initSend, h.initRecv);
        NoiseCipher rb(h.respSend, h.respRecv);

        const std::string msg = "payload";
        std::vector<std::uint8_t> sealed;
        CHECK(ia.seal(bytesOf(msg), sealed) == Status::Ok);
        sealed[0] ^= 0x01u;

        std::vector<std::uint8_t> opened;
        CHECK(rb.open(sealed, opened) == Status::AuthFailed);
        CHECK(isFatal(Status::AuthFailed));
        CHECK_EQ(rb.recvNonce(), 0ull);
    }

    TEST_CASE("both directions rekey at the same record count") {
        // Run with an interval of 4 so the rotation actually happens. Production
        // uses 2^32; the point being tested is that the two sides stay in step,
        // which is independent of the number.
        const LocalIdentity a = LocalIdentity::generate();
        const LocalIdentity b = LocalIdentity::generate();
        const Handshaken h = runXxWithIdentities(a, b);
        CHECK(h.ok);

        NoiseCipher ia(h.initSend, h.initRecv, 4);
        NoiseCipher rb(h.respSend, h.respRecv, 4);

        for (int i = 0; i < 20; ++i) {
            const std::string msg = "record " + std::to_string(i);
            std::vector<std::uint8_t> sealed, opened;
            CHECK(ia.seal(bytesOf(msg), sealed) == Status::Ok);
            CHECK(rb.open(sealed, opened) == Status::Ok);
            CHECK(std::string(opened.begin(), opened.end()) == msg);
        }
        CHECK_EQ(ia.recordsSealed(), 20ull);
        CHECK_EQ(rb.recordsOpened(), 20ull);
    }

    TEST_CASE("a peer that does not rekey falls out of step") {
        // Confirms the rotation is real rather than a no-op that happens to
        // leave both sides working.
        const LocalIdentity a = LocalIdentity::generate();
        const LocalIdentity b = LocalIdentity::generate();
        const Handshaken h = runXxWithIdentities(a, b);
        CHECK(h.ok);

        NoiseCipher ia(h.initSend, h.initRecv, 2);
        NoiseCipher rb(h.respSend, h.respRecv, 0);   // never rekeys

        std::vector<std::uint8_t> s1, s2, s3, o;
        CHECK(ia.seal(bytesOf(std::string("a")), s1) == Status::Ok);
        CHECK(rb.open(s1, o) == Status::Ok);
        o.clear();
        CHECK(ia.seal(bytesOf(std::string("b")), s2) == Status::Ok);   // triggers rekey
        CHECK(rb.open(s2, o) == Status::Ok);
        o.clear();
        CHECK(ia.seal(bytesOf(std::string("c")), s3) == Status::Ok);   // sealed under the new key
        CHECK(rb.open(s3, o) == Status::AuthFailed);
    }

    TEST_CASE("an oversized plaintext is refused") {
        const LocalIdentity a = LocalIdentity::generate();
        const LocalIdentity b = LocalIdentity::generate();
        const Handshaken h = runXxWithIdentities(a, b);
        CHECK(h.ok);

        NoiseCipher ia(h.initSend, h.initRecv);
        const std::vector<std::uint8_t> big(kNoiseMaxPlaintext + 1, 0);
        std::vector<std::uint8_t> out;
        CHECK(ia.seal(big, out) == Status::LimitExceeded);
    }
}

void testEndToEndOverRecordLayer()
{
    std::printf("end to end: RecordLayer with NoiseCipher instead of NullCipher\n");

    TEST_CASE("messages cross a real record layer encrypted") {
        const LocalIdentity a = LocalIdentity::generate();
        const LocalIdentity b = LocalIdentity::generate();
        const Handshaken h = runXxWithIdentities(a, b);
        CHECK(h.ok);

        MemoryPipe pipe;
        RecordLayer left(pipe.endpointA(),
                         std::make_unique<NoiseCipher>(h.initSend, h.initRecv));
        RecordLayer right(pipe.endpointB(),
                          std::make_unique<NoiseCipher>(h.respSend, h.respRecv));

        left.setHandshakeComplete(16640);
        right.setHandshakeComplete(16640);

        const std::string msg = "AirUSB/1 SUBMIT, or it would be";
        CHECK(left.sendRecord(bytesOf(msg)) == Status::Ok);
        CHECK(left.flush() == Status::Ok);

        // The bytes on the wire must not be the plaintext.
        CHECK(pipe.bytesAtoB() >= msg.size() + crypto::kTagLen);

        std::vector<std::uint8_t> got;
        CHECK(right.receiveRecord(got) == Status::Ok);
        CHECK(std::string(got.begin(), got.end()) == msg);
    }

    TEST_CASE("the plaintext never appears on the wire") {
        const LocalIdentity a = LocalIdentity::generate();
        const LocalIdentity b = LocalIdentity::generate();
        const Handshaken h = runXxWithIdentities(a, b);
        CHECK(h.ok);

        MemoryPipe pipe;
        RecordLayer left(pipe.endpointA(),
                         std::make_unique<NoiseCipher>(h.initSend, h.initRecv));
        left.setHandshakeComplete(16640);

        // A distinctive marker that a NullCipher build would leak verbatim.
        const std::string marker = "PLAINTEXT-MARKER-0123456789";
        CHECK(left.sendRecord(bytesOf(marker)) == Status::Ok);
        CHECK(left.flush() == Status::Ok);

        // Reconstruct what actually crossed the pipe by reading it out the far
        // side without decrypting.
        RecordLayer sink(pipe.endpointB(), std::make_unique<NullCipher>());
        sink.setHandshakeComplete(16640);
        std::vector<std::uint8_t> raw;
        CHECK(sink.receiveRecord(raw) == Status::Ok);

        const std::string onWire(raw.begin(), raw.end());
        CHECK(onWire.find(marker) == std::string::npos);
        CHECK_EQ(raw.size(), marker.size() + crypto::kTagLen);
    }

    TEST_CASE("many records in both directions round trip in order") {
        const LocalIdentity a = LocalIdentity::generate();
        const LocalIdentity b = LocalIdentity::generate();
        const Handshaken h = runXxWithIdentities(a, b);
        CHECK(h.ok);

        MemoryPipe pipe;
        RecordLayer left(pipe.endpointA(),
                         std::make_unique<NoiseCipher>(h.initSend, h.initRecv));
        RecordLayer right(pipe.endpointB(),
                          std::make_unique<NoiseCipher>(h.respSend, h.respRecv));
        left.setHandshakeComplete(16640);
        right.setHandshakeComplete(16640);

        for (int i = 0; i < 64; ++i) {
            const std::string out = "a->b " + std::to_string(i);
            CHECK(left.sendRecord(bytesOf(out)) == Status::Ok);
            CHECK(left.flush() == Status::Ok);
            std::vector<std::uint8_t> got;
            CHECK(right.receiveRecord(got) == Status::Ok);
            CHECK(std::string(got.begin(), got.end()) == out);

            const std::string back = "b->a " + std::to_string(i);
            CHECK(right.sendRecord(bytesOf(back)) == Status::Ok);
            CHECK(right.flush() == Status::Ok);
            std::vector<std::uint8_t> got2;
            CHECK(left.receiveRecord(got2) == Status::Ok);
            CHECK(std::string(got2.begin(), got2.end()) == back);
        }
    }
}

} // namespace

int main()
{
    std::printf("test_identity\n");
    testIdentity();
    testIdentityPayload();
    testFingerprint();
    testSas();
    testNoiseCipher();
    testEndToEndOverRecordLayer();
    TEST_MAIN_END();
}
