// Fuzz target for the Noise handshake parser and the identity payload.
//
// HandshakeState::readMessage is the first code in the whole system to touch
// bytes from an unauthenticated peer. Before it returns, nothing has been
// verified: not the version, not the identity, not even that the sender is
// speaking Noise. Every length in it is peer-controlled.
//
// The contract, for ANY byte string:
//   * no read outside the buffer,
//   * no allocation sized from an unchecked peer-supplied length,
//   * a failure is a Status, never a crash and never a partially-updated state
//     that a caller could mistake for success,
//   * a handshake that reports complete() really is complete — a malformed
//     message must never advance the state machine.
//
// The identity payload decoder is fuzzed alongside it because it runs on the
// decrypted payload, which is authenticated but still attacker-chosen: a peer
// with a valid key can put anything it likes in there.

#include "../../protocol/Noise.h"
#include "../../crypto/Identity.h"

#include <cassert>
#include <cstdint>
#include <cstring>
#include <vector>

using namespace airusb;
using namespace airusb::crypto;
using namespace airusb::protocol;

namespace {

/// Fixed keys. Generating them per input would make findings unreproducible and
/// would spend the whole fuzzing budget on X25519.
const SecretKey& localStatic()
{
    static const SecretKey k = [] {
        SecretKey s{};
        for (std::size_t i = 0; i < s.size(); ++i) s[i] = static_cast<std::uint8_t>(i + 1);
        return s;
    }();
    return k;
}

const PublicKey& remoteStatic()
{
    static const PublicKey k = [] {
        SecretKey s{};
        for (std::size_t i = 0; i < s.size(); ++i) s[i] = static_cast<std::uint8_t>(0x40 + i);
        return x25519PublicKey(s);
    }();
    return k;
}

/// Feeds `data` to a responder in the given pattern, as message 0, then keeps
/// feeding whatever is left as subsequent messages.
void driveResponder(NoisePattern pattern, std::span<const std::uint8_t> data)
{
    HandshakeState h;
    HandshakeState::Params p;
    p.pattern     = pattern;
    p.initiator   = false;
    p.localStatic = localStatic();
    if (h.start(p) != Status::Ok) return;

    std::size_t at = 0;
    for (int msg = 0; msg < 4 && at < data.size(); ++msg) {
        // Split the input into chunks with a peer-chosen length, so both very
        // short and very long messages are exercised.
        const std::size_t remaining = data.size() - at;
        const std::size_t take = (data[at] % 200u) + 1u;
        const std::size_t len = take < remaining ? take : remaining;

        std::vector<std::uint8_t> payload;
        const Status s = h.readMessage(data.subspan(at, len), payload);
        at += len;

        if (s != Status::Ok) {
            // A rejected message must not have advanced the handshake. If it
            // had, a peer could skip straight past authentication by sending
            // garbage that "failed".
            assert(!h.complete());
            return;
        }
        if (h.complete()) {
            CipherState tx, rx;
            const Status sp = h.split(tx, rx);
            assert(sp == Status::Ok);
            return;
        }
        // Between messages the responder writes; without doing so the state
        // machine would refuse the next read as out of turn.
        std::vector<std::uint8_t> out;
        if (h.writeMessage({}, out) != Status::Ok) return;
        if (h.complete()) return;
    }
}

/// The initiator side of IK, which is the only role that reads with a
/// pre-shared remote static and therefore takes a different path.
void driveIkInitiator(std::span<const std::uint8_t> data)
{
    HandshakeState h;
    HandshakeState::Params p;
    p.pattern         = NoisePattern::IK;
    p.initiator       = true;
    p.localStatic     = localStatic();
    p.remoteStatic    = remoteStatic();
    p.hasRemoteStatic = true;
    if (h.start(p) != Status::Ok) return;

    std::vector<std::uint8_t> m0;
    if (h.writeMessage({}, m0) != Status::Ok) return;

    std::vector<std::uint8_t> payload;
    const Status s = h.readMessage(data, payload);
    if (s != Status::Ok) {
        assert(!h.complete());
        return;
    }
    assert(h.complete());
    CipherState tx, rx;
    assert(h.split(tx, rx) == Status::Ok);
}

void exerciseIdentityPayload(std::span<const std::uint8_t> data)
{
    PeerIdentity out;
    const bool ok = decodeAndVerifyIdentityPayload(data, remoteStatic(), out);
    if (ok) {
        // Success must mean the length was exact and the binding verified
        // against the key we passed in, not one taken from the payload.
        assert(data.size() == kIdentityPayloadLen);
        assert(out.noiseKey == remoteStatic());
        assert(verifyBinding(out));
    }

    // The transport cipher's decrypt path is reachable with attacker bytes too.
    CipherState cs;
    Key k{};
    std::memcpy(k.data(), remoteStatic().data(), k.size());
    cs.initializeKey(k);
    std::vector<std::uint8_t> pt;
    const Status ds = cs.decryptWithAd({}, data, pt);
    if (ds != Status::Ok) {
        // Noise §5.1: a failed decrypt must not advance the nonce.
        assert(cs.nonce() == 0);
        assert(pt.empty());
    }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    if (size < 1) return 0;

    const std::span<const std::uint8_t> all(data, size);

    // The first byte selects the target so one corpus covers every entry point.
    switch (data[0] & 0x03u) {
        case 0: driveResponder(NoisePattern::XX, all.subspan(1)); break;
        case 1: driveResponder(NoisePattern::IK, all.subspan(1)); break;
        case 2: driveIkInitiator(all.subspan(1)); break;
        default: exerciseIdentityPayload(all.subspan(1)); break;
    }
    return 0;
}
