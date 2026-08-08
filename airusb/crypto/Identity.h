// AirUSB Hub — peer identity, the binding signature, and the SAS (P1 plan §3.14).
//
// TWO KEYS, NOT ONE
//
// A peer has an Ed25519 identity key `I` and a SEPARATE X25519 static key `S`.
// No key is ever used for both signing and Diffie-Hellman. That is not caution
// for its own sake: the two schemes have different security proofs, and reusing
// one key across both invalidates the assumptions of each. It also lets `I`
// double as a TLS 1.3 raw-public-key certificate key when the QUIC transport
// arrives, without that transport inheriting the Noise static.
//
// The two are tied together by a signature:
//
//     sigS = Ed25519_Sign(I_sk, "AirUSB-identity-binding-v1" || I_pk || S_pk)
//
// The Noise XX payload carries `I_pk || sigS`. Verifying it is what turns "the
// peer holds the private key for this X25519 key" — all Noise can tell you —
// into "the peer is the identity we pinned". Without that step a session could
// be perfectly encrypted to an attacker.
//
// THE DOMAIN SEPARATION STRINGS ARE PART OF THE WIRE FORMAT
//
// Every constant below is hashed or signed over. Changing one is a protocol
// break, not a rename.

#ifndef AIRUSB_CRYPTO_IDENTITY_H
#define AIRUSB_CRYPTO_IDENTITY_H

#include "Primitives.h"
#include "../core/Status.h"

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace airusb::crypto {

inline constexpr std::string_view kBindingContext = "AirUSB-identity-binding-v1";
inline constexpr std::string_view kFingerprintContext = "AirUSB-fp-v1";
inline constexpr std::string_view kSasContext = "AirUSB-SAS-v1";

/// 20 bytes = 160 bits, which is exactly 32 base32 characters with no padding.
inline constexpr std::size_t kFingerprintLen = 20;
using Fingerprint = std::array<std::uint8_t, kFingerprintLen>;

// ---------------------------------------------------------------------------
// identity
// ---------------------------------------------------------------------------

/// The public half — everything a peer needs to authenticate us.
struct PeerIdentity {
    PublicKey identityKey{};    ///< Ed25519 I_pk
    PublicKey noiseKey{};       ///< X25519  S_pk
    Signature binding{};        ///< sigS
};

/// The full keypair set. Secrets are wiped on destruction.
class LocalIdentity {
public:
    LocalIdentity() = default;
    ~LocalIdentity();

    LocalIdentity(const LocalIdentity&)            = delete;
    LocalIdentity& operator=(const LocalIdentity&) = delete;
    LocalIdentity(LocalIdentity&&) noexcept;
    LocalIdentity& operator=(LocalIdentity&&) noexcept;

    /// Fresh keys from the system CSPRNG.
    static LocalIdentity generate();

    /// Deterministic from a stored seed, so an identity survives a restart.
    /// Both keypairs derive from the ONE seed, by separate domain-separated
    /// expansions — storing two independent secrets doubles the number of things
    /// that can be leaked or lost out of step.
    static LocalIdentity fromSeed(const Seed& seed);

    const Seed&      seed()          const noexcept { return _seed; }
    const PublicKey& identityKey()   const noexcept { return _idPub; }
    const PublicKey& noiseKey()      const noexcept { return _noisePub; }
    const SecretKey& noiseSecret()   const noexcept { return _noiseSk; }
    const Signature& binding()       const noexcept { return _binding; }

    PeerIdentity publicIdentity() const;

private:
    Seed      _seed{};
    EdSecret  _idSk{};
    PublicKey _idPub{};
    SecretKey _noiseSk{};
    PublicKey _noisePub{};
    Signature _binding{};
};

/// The exact bytes that get signed. Exposed so a test can prove the signature
/// covers both keys and the context, rather than trusting that it does.
std::vector<std::uint8_t> bindingMessage(const PublicKey& identityKey,
                                         const PublicKey& noiseKey);

/// Verifies that `binding` proves `identityKey` vouches for `noiseKey`.
///
/// This is the check that must run against the key Noise ACTUALLY negotiated,
/// never against a key taken from the payload. Verifying the payload's own claim
/// about itself proves nothing.
bool verifyBinding(const PeerIdentity& peer);

// ---------------------------------------------------------------------------
// XX payload encoding — `I_pk || sigS`
// ---------------------------------------------------------------------------

inline constexpr std::size_t kIdentityPayloadLen = kDhLen + kSigLen;   // 96

void encodeIdentityPayload(const LocalIdentity& id, std::vector<std::uint8_t>& out);

/// Decodes and verifies in one step, against the Noise static key that was
/// actually negotiated. Returns false on a short payload, a malformed one, or a
/// signature that does not bind — all of which are the same thing to the caller:
/// this peer is not who it says it is.
bool decodeAndVerifyIdentityPayload(std::span<const std::uint8_t> payload,
                                    const PublicKey& negotiatedNoiseKey,
                                    PeerIdentity& out);

// ---------------------------------------------------------------------------
// fingerprint
// ---------------------------------------------------------------------------

/// BLAKE2s-256("AirUSB-fp-v1" || I_pk), truncated to 20 bytes.
///
/// P1 plan §3.14 originally specified SHA-256 here. Changed to BLAKE2s, which
/// the handshake already requires: adding a whole second hash function to a
/// root daemon's attack surface to compute a display string is not a trade worth
/// making. The fingerprint is internal — it names a pin, it is never parsed by
/// anyone else — so this is not a wire-compatibility change.
Fingerprint fingerprint(const PublicKey& identityKey);

/// RFC 4648 base32, upper case, four groups of eight separated by spaces.
/// 160 bits divides exactly, so there is no padding to explain to a user.
std::string fingerprintText(const Fingerprint& fp);

// ---------------------------------------------------------------------------
// SAS — the six digits both users compare
// ---------------------------------------------------------------------------

/// SAS = decimal6( HKDF(channel_binding, "AirUSB-SAS-v1")[0..8) mod 10^6 )
///
/// `channelBinding` is the Noise handshake hash, which commits to both static
/// keys, both ephemerals and both preambles. Deriving from anything less would
/// let an attacker who sits in the middle show each side a matching number.
///
/// The eight bytes are read BIG endian. The spec did not say; it is pinned here
/// because both peers must agree and there is no negotiating it.
///
/// Security is Bluetooth Numeric Comparison: one in a million per attempt. That
/// bound holds ONLY if attempts cannot be retried, which is a session-layer
/// obligation (backoff, a hard cap per minute, a burned pairing session on
/// failure) and not something this function can enforce.
std::uint32_t sasDigits(const Hash& channelBinding);

/// Zero-padded to six characters, e.g. "004271".
std::string sasText(std::uint32_t sas);

} // namespace airusb::crypto

#endif // AIRUSB_CRYPTO_IDENTITY_H
