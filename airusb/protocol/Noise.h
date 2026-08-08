// AirUSB Hub — the Noise Protocol Framework handshake (P1 plan §3.14).
//
//     Noise_XX_25519_ChaChaPoly_BLAKE2s   first contact, mutual authentication
//     Noise_IK_25519_ChaChaPoly_BLAKE2s   once the peer's static key is pinned
//
// Written against Noise revision 34. The primitives all come from crypto/, which
// wraps vendored, audited code; what is implemented here is the state machine,
// the key schedule and the message patterns.
//
// WHY THIS FILE IS TESTED THE WAY IT IS
//
// A Noise implementation can be entirely self-consistent and entirely wrong. Get
// the HKDF argument order backwards, or use BLAKE2s's native keyed mode instead
// of HMAC, or encode the nonce big-endian, and every round trip against yourself
// still succeeds — you have simply invented a private protocol that no other
// implementation can speak, with none of the review the real one has had.
//
// So the acceptance test is not a round trip. It is tests/vectors/NoiseVectors.h:
// the official cross-implementation vectors for exactly these two protocols,
// produced by somebody else's code, checked message by message down to the final
// handshake hash. The round-trip tests are there to catch the rest.
//
// WHAT THIS FILE DOES NOT DO
//
// Identity, pinning, trust and the SAS live in Identity.h / Sas.h. Noise
// authenticates that the peer holds the private key for a static public key; it
// says nothing about whether that key is one we should be talking to. Conflating
// the two is how a protocol ends up encrypting perfectly to an attacker.

#ifndef AIRUSB_PROTOCOL_NOISE_H
#define AIRUSB_PROTOCOL_NOISE_H

#include "../core/Status.h"
#include "../crypto/Primitives.h"

#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace airusb::protocol {

/// Noise's own ceiling: a transport message is at most 65535 bytes, of which 16
/// are the tag (Noise §3). P1 plan §3.1's plaintext ceiling of 65519 is this
/// number minus the tag, and is therefore a restatement rather than a choice.
inline constexpr std::size_t kNoiseMaxMessage   = 65535;
inline constexpr std::size_t kNoiseMaxPlaintext = kNoiseMaxMessage - crypto::kTagLen;

/// The reserved nonce Rekey() uses; encrypting with it is forbidden.
inline constexpr std::uint64_t kNoiseMaxNonce = 0xFFFFFFFFFFFFFFFFull;

// ---------------------------------------------------------------------------
// CipherState (Noise §5.1)
// ---------------------------------------------------------------------------

class CipherState {
public:
    void initializeKey(const crypto::Key& k) noexcept;
    void clear() noexcept;

    bool hasKey() const noexcept { return _hasKey; }
    std::uint64_t nonce() const noexcept { return _n; }

    /// Without a key these are the identity, which is what the first Noise
    /// handshake message needs. That is a documented part of the spec and not a
    /// fallback: the caller must not treat a keyless CipherState as an error.
    Status encryptWithAd(std::span<const std::uint8_t> ad,
                         std::span<const std::uint8_t> plaintext,
                         std::vector<std::uint8_t>& out);

    /// On authentication failure the nonce is NOT advanced (Noise §5.1), so a
    /// forged record cannot desynchronise a session that then recovers.
    Status decryptWithAd(std::span<const std::uint8_t> ad,
                         std::span<const std::uint8_t> ciphertext,
                         std::vector<std::uint8_t>& out);

    /// Noise §5.1 Rekey: k = ENCRYPT(k, 2^64-1, zerolen, zeros[32]). Deliberately
    /// does NOT reset the nonce — Noise is explicit that Rekey leaves n alone.
    void rekey();

private:
    crypto::Key   _k{};
    bool          _hasKey = false;
    std::uint64_t _n      = 0;
};

// ---------------------------------------------------------------------------
// SymmetricState (Noise §5.2)
// ---------------------------------------------------------------------------

class SymmetricState {
public:
    void initializeSymmetric(std::string_view protocolName);
    void mixKey(std::span<const std::uint8_t> ikm);
    void mixHash(std::span<const std::uint8_t> data);

    Status encryptAndHash(std::span<const std::uint8_t> plaintext,
                          std::vector<std::uint8_t>& out);
    Status decryptAndHash(std::span<const std::uint8_t> ciphertext,
                          std::vector<std::uint8_t>& out);

    /// Noise §5.2 Split. `c1` encrypts for the initiator, `c2` for the responder.
    void split(CipherState& c1, CipherState& c2);

    const crypto::Hash& handshakeHash() const noexcept { return _h; }
    bool hasKey() const noexcept { return _cipher.hasKey(); }

private:
    CipherState  _cipher;
    crypto::Hash _ck{};
    crypto::Hash _h{};
};

// ---------------------------------------------------------------------------
// HandshakeState (Noise §5.3)
// ---------------------------------------------------------------------------

enum class NoisePattern : std::uint8_t { XX, IK };

const char* noiseProtocolName(NoisePattern p) noexcept;

class HandshakeState {
public:
    struct Params {
        NoisePattern              pattern   = NoisePattern::XX;
        bool                      initiator = true;
        std::vector<std::uint8_t> prologue;

        /// Both patterns transmit a static key, so this is always required.
        crypto::SecretKey localStatic{};

        /// Required for an IK initiator (the pattern pre-shares it) and ignored
        /// otherwise. Supplying it for XX is an error rather than a hint: XX
        /// learns the remote static during the handshake, and pretending to know
        /// it in advance would silently change what is being authenticated.
        crypto::PublicKey remoteStatic{};
        bool              hasRemoteStatic = false;
    };

    Status start(const Params& p);

    /// TEST ONLY. Replaces the ephemeral that would otherwise be generated.
    ///
    /// Present for exactly one reason: the official Noise vectors specify the
    /// ephemerals, and without injecting them the vectors cannot be replayed —
    /// which would leave this implementation checked only against itself. It is
    /// named to be impossible to use by accident, refuses to run once the
    /// handshake has started, and is not reachable from any session code.
    Status setFixedEphemeralForTestingOnly(const crypto::SecretKey& e);

    Status writeMessage(std::span<const std::uint8_t> payload,
                        std::vector<std::uint8_t>& out);
    Status readMessage(std::span<const std::uint8_t> message,
                       std::vector<std::uint8_t>& payloadOut);

    bool complete() const noexcept { return _complete; }

    /// The channel binding. Commits to both static keys, both ephemerals and the
    /// prologue, which is what makes it safe to derive the SAS from.
    const crypto::Hash& handshakeHash() const noexcept;

    bool                     haveRemoteStatic() const noexcept { return _haveRs; }
    const crypto::PublicKey& remoteStatic() const noexcept { return _rs; }

    /// Valid only once complete(). `send` and `recv` are oriented for THIS peer,
    /// so both sides call it identically and the role swap happens inside.
    Status split(CipherState& send, CipherState& recv);

private:
    Status mixDh(const crypto::SecretKey& sk, const crypto::PublicKey& pk);

    SymmetricState _sym;

    crypto::SecretKey _s{};              ///< local static
    crypto::PublicKey _sPub{};
    crypto::SecretKey _e{};              ///< local ephemeral
    crypto::PublicKey _ePub{};
    crypto::PublicKey _rs{};             ///< remote static
    crypto::PublicKey _re{};             ///< remote ephemeral

    bool _haveE  = false;
    bool _haveRs = false;
    bool _haveRe = false;

    crypto::SecretKey _fixedE{};
    bool              _hasFixedE = false;

    NoisePattern _pattern   = NoisePattern::XX;
    bool         _initiator = true;
    bool         _started   = false;
    bool         _complete  = false;
    std::uint8_t _msgIndex  = 0;
};

} // namespace airusb::protocol

#endif // AIRUSB_PROTOCOL_NOISE_H
