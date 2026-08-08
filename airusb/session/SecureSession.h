// AirUSB Hub — the thing that turns a socket into an authenticated session.
//
// This is the piece that was missing between P2.4 and a working product: the
// crypto worked and the exporter worked, and nothing connected the two.
//
//     L0 preamble (8 plaintext bytes, both directions)
//         |
//         v
//     Noise handshake, carried as pre-handshake records (<= 8 KiB, R1)
//         |
//         v
//     identity payload verified against the NEGOTIATED static key
//         |
//         v
//     trust gate — paired, or Unpaired with only PAIR_*/PING/GOODBYE allowed
//         |
//         v
//     NoiseCipher adopted, RecordLayer switched to the negotiated record size
//
// WHY THE PREAMBLE IS SAFE IN THE CLEAR
//
// It is not protected, it is *bound*. Both preambles — ours as sent, the peer's
// as received — become the Noise prologue. An attacker who rewrites the version
// or clears a security flag makes the two sides compute different prologues, and
// the first MAC fails. §3.13: "a downgrade attempt on the plaintext preamble
// breaks the handshake MAC."
//
// WHICH PATTERN, AND WHO DECIDES
//
// The responder cannot guess whether the initiator has it pinned, so the
// initiator says so in the preamble with SEC_NOISE_IK. Flipping that bit makes
// the two sides run different patterns and the handshake fails — fail-closed,
// not a downgrade.

#ifndef AIRUSB_SESSION_SECURESESSION_H
#define AIRUSB_SESSION_SECURESESSION_H

#include "PeerStore.h"
#include "../core/Status.h"
#include "../crypto/Identity.h"
#include "../protocol/Codec.h"
#include "../protocol/Noise.h"
#include "../transport/RecordLayer.h"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace airusb::session {

/// What the peer is allowed to ask for once the handshake is done.
enum class Trust : std::uint8_t {
    Unknown,     ///< handshake not finished
    Unpaired,    ///< authenticated, but never confirmed by a human
    Paired,      ///< pinned, with grants
};

class SecureSession {
public:
    struct Config {
        bool initiator = true;

        /// Must outlive the session. Not copied: it holds secrets, and copies of
        /// secrets are copies to wipe.
        const crypto::LocalIdentity* identity = nullptr;

        /// Consulted for the trust gate and to decide whether IK is available.
        /// May be null, which means every peer is Unpaired.
        const PeerStore* peers = nullptr;

        /// The identity we expect, from discovery. When it is pinned AND its
        /// Noise key is known, the session opens with IK and saves a round trip.
        crypto::PublicKey expectedPeer{};
        bool hasExpectedPeer = false;

        std::uint32_t negotiatedMaxRecordBytes = wire::kRecordBytesDefault;
    };

    enum class State : std::uint8_t {
        Idle,
        AwaitingPreamble,
        Handshaking,
        Established,
        Failed,
    };

    SecureSession() = default;

    /// Sends our preamble and prepares to read theirs. Takes the stream.
    Status begin(std::unique_ptr<transport::IByteStream> stream, const Config& cfg);

    /// Advances the handshake as far as the available bytes allow.
    ///
    /// Returns Ok when the session is Established, Busy when it needs more bytes
    /// from the peer, or a failure — which is terminal. There is no retry: a
    /// handshake that failed cannot be resumed, only replaced.
    Status pump();

    State state() const noexcept { return _state; }
    bool  established() const noexcept { return _state == State::Established; }

    /// Valid once Established.
    transport::RecordLayer* transport() noexcept { return _record.get(); }
    const crypto::PeerIdentity& peerIdentity() const noexcept { return _peer; }
    Trust trust() const noexcept { return _trust; }
    std::uint32_t grants() const noexcept { return _grants; }

    /// The six digits both users compare. Meaningful only when Unpaired — a
    /// paired session has already been confirmed and must not prompt again.
    std::uint32_t sas() const noexcept { return _sas; }
    const crypto::Hash& channelBinding() const noexcept { return _channelBinding; }

    /// True if the peer may send this kind of request yet. §3.14: an unpaired
    /// peer may only pair, ping, or say goodbye.
    bool mayList() const noexcept;
    bool mayAttach() const noexcept;

    /// Which pattern was actually used, for logs and tests.
    protocol::NoisePattern pattern() const noexcept { return _pattern; }

    const std::string& failureReason() const noexcept { return _why; }

private:
    Status fail(Status s, std::string why);
    Status readPeerPreamble();
    Status driveHandshake();
    Status finish();

    std::unique_ptr<transport::IByteStream> _stream;
    std::unique_ptr<transport::RecordLayer> _record;

    Config       _cfg;
    State        _state = State::Idle;
    Trust        _trust = Trust::Unknown;
    std::uint32_t _grants = 0;
    std::string  _why;

    std::vector<std::uint8_t> _ourPreamble;
    std::vector<std::uint8_t> _theirPreamble;

    protocol::NoisePattern     _pattern = protocol::NoisePattern::XX;
    protocol::HandshakeState   _hs;
    crypto::PeerIdentity       _peer;
    crypto::Hash               _channelBinding{};
    std::uint32_t              _sas = 0;

    /// Which handshake message comes next, and whether it is ours to send.
    std::uint8_t _msgIndex = 0;
};

/// The prologue: initiator preamble followed by responder preamble, always in
/// that order regardless of who is computing it. Both sides must build the same
/// bytes or nothing decrypts.
std::vector<std::uint8_t> buildPrologue(std::span<const std::uint8_t> initiatorPreamble,
                                        std::span<const std::uint8_t> responderPreamble);

} // namespace airusb::session

#endif // AIRUSB_SESSION_SECURESESSION_H
