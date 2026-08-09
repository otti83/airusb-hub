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
//     NoiseCipher adopted, records capped at the 8 KiB pre-HELLO ceiling
//         |
//         v
//     HELLO / HELLO_OK — and ONLY THEN is the session established
//
// WHY THE PREAMBLE IS SAFE IN THE CLEAR
//
// It is not protected, it is *bound*. Both preambles — ours as sent, the peer's
// as received — become the Noise prologue. An attacker who rewrites the version
// or clears a security flag makes the two sides compute different prologues, and
// the first MAC fails. §3.13: "a downgrade attempt on the plaintext preamble
// breaks the handshake MAC."
//
// WHY HELLO IS INSIDE THIS CLASS
//
// `HELLO` was defined in Wire.h from the beginning and exchanged by nobody.
// `SecureSession` adopted its OWN configured record size the moment the
// handshake finished, so two builds that disagreed about it completed the
// handshake, believed different numbers, and failed later on a record one side
// thought was legal — obscurely, and at the worst possible moment.
//
// So the greeting happens HERE, before `established()` is true. Everything
// above this class — the exporter, the importer, the window — asks
// `established()` before doing anything, so putting the negotiation on the
// other side of that question means no caller can observe a session whose
// limits are not yet agreed. There is no ordering for a caller to get wrong,
// because there is no moment at which a caller can act.
//
// VERSION FIXES SEMANTICS; HELLO NEGOTIATES BOUNDS
//
// What a message MEANS is fixed by the protocol version and is never
// negotiated — a peer that disagrees about that is refused, not accommodated.
// What HELLO settles is the numbers: record size, transfer size, keepalive, and
// which OPTIONAL capabilities both ends have. Sizes take the minimum,
// capabilities the intersection, and segmentation is mandatory rather than
// optional because a peer that cannot segment cannot carry a 1 MiB URB and
// would fail on the first real transfer instead of at the greeting.
//
// The RESPONDER decides, and the initiator adopts. One side computing the
// minimum removes the tie-break question entirely; the alternative — both
// computing it independently — is two implementations of one rule.
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

        /// What this build would LIKE. The peer's own preference is met with the
        /// minimum of the two, so this is a ceiling on us and never on them.
        std::uint32_t negotiatedMaxRecordBytes = wire::kRecordBytesDefault;

        /// What this build can do. Segmentation is not in the list because it
        /// is mandatory: `wire::kCapSegmentation` is added unconditionally and
        /// a peer that does not set it is refused.
        std::uint64_t capabilities = wire::kCapCancel | wire::kCapReset
                                   | wire::kCapManifestAuthoritative;

        std::uint32_t maxTransferBytes = wire::kTransferBytesDefault;
        std::uint32_t keepaliveMs      = 500;
        std::uint8_t  roleBits         = wire::kRoleCanExport | wire::kRoleCanImport;
    };

    /// What the two ends agreed. Valid once `established()`.
    struct Negotiated {
        std::uint32_t maxRecordBytes   = wire::kHandshakeRecordMax;
        std::uint32_t maxTransferBytes = 0;
        std::uint64_t capabilities     = 0;
        std::uint32_t keepaliveMs      = 0;
        std::uint8_t  peerRoleBits     = 0;
        std::uint8_t  peerPlatform     = 0;
    };

    enum class State : std::uint8_t {
        Idle,
        AwaitingPreamble,
        Handshaking,
        /// Encrypted, authenticated, and NOT yet usable: the two ends have not
        /// agreed their limits. `established()` is deliberately false here.
        Greeting,
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
    const Negotiated& negotiated() const noexcept { return _negotiated; }

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
    /// Sends our HELLO (initiator) and reads the peer's, or reads theirs and
    /// answers with the agreed numbers (responder).
    Status driveGreeting();
    Status sendHello(wire::Type type, const Negotiated* agreed);
    Status applyNegotiated();

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

    Negotiated _negotiated;
    bool       _helloSent = false;
};

/// The prologue: initiator preamble followed by responder preamble, always in
/// that order regardless of who is computing it. Both sides must build the same
/// bytes or nothing decrypts.
std::vector<std::uint8_t> buildPrologue(std::span<const std::uint8_t> initiatorPreamble,
                                        std::span<const std::uint8_t> responderPreamble);

} // namespace airusb::session

#endif // AIRUSB_SESSION_SECURESESSION_H
