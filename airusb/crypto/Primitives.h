// AirUSB Hub — the only place vendored crypto is called from.
//
// Everything here is a thin, typed wrapper over third_party/. No algorithm is
// implemented in this file or its .cpp; the point of the layer is that there is
// exactly one place where a raw pointer meets a cryptographic primitive, so the
// length and lifetime discipline can be read in one sitting.
//
// The suite is fixed by P1 plan §3.14 and is not negotiable at runtime:
//
//     Noise_XX_25519_ChaChaPoly_BLAKE2s
//     Noise_IK_25519_ChaChaPoly_BLAKE2s
//
// A cipher-suite negotiation is an attack surface that buys nothing when both
// ends ship from the same repository. Versioning happens at the wire-protocol
// level (§3.13), where a peer either speaks AirUSB/1 or does not.
//
// THE ONE THING TO GET RIGHT IN THIS FILE
//
// Noise's key schedule is built on HMAC (RFC 2104) applied to the hash function.
// BLAKE2s also has a *native* keyed mode, which is faster and is NOT the same
// construction. Using BLAKE2s-keyed where the spec says HMAC-BLAKE2s produces a
// protocol that interoperates with nothing, agrees with itself perfectly, and
// passes every self-test. `hmacBlake2s` below is the real HMAC; the native keyed
// mode is deliberately not exposed.

#ifndef AIRUSB_CRYPTO_PRIMITIVES_H
#define AIRUSB_CRYPTO_PRIMITIVES_H

#include "../core/Status.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace airusb::crypto {

// --- sizes -------------------------------------------------------------------

inline constexpr std::size_t kHashLen   = 32;   ///< BLAKE2s-256
inline constexpr std::size_t kBlockLen  = 64;   ///< BLAKE2s block, for HMAC
inline constexpr std::size_t kKeyLen    = 32;   ///< ChaCha20 key
inline constexpr std::size_t kDhLen     = 32;   ///< X25519
inline constexpr std::size_t kTagLen    = 16;   ///< Poly1305
inline constexpr std::size_t kNonceLen  = 12;   ///< RFC 8439 nonce
inline constexpr std::size_t kSigLen    = 64;   ///< Ed25519
inline constexpr std::size_t kSeedLen   = 32;   ///< Ed25519 seed
inline constexpr std::size_t kEdSkLen   = 64;   ///< Ed25519 expanded secret

using Hash      = std::array<std::uint8_t, kHashLen>;
using Key       = std::array<std::uint8_t, kKeyLen>;
using PublicKey = std::array<std::uint8_t, kDhLen>;
using SecretKey = std::array<std::uint8_t, kDhLen>;
using Signature = std::array<std::uint8_t, kSigLen>;
using Seed      = std::array<std::uint8_t, kSeedLen>;
using EdSecret  = std::array<std::uint8_t, kEdSkLen>;

// --- hash --------------------------------------------------------------------

Hash blake2s(std::span<const std::uint8_t> in);

/// Streaming BLAKE2s, for hashing pieces without concatenating them first.
class Blake2s {
public:
    Blake2s();
    ~Blake2s();
    Blake2s(const Blake2s&)            = delete;
    Blake2s& operator=(const Blake2s&) = delete;

    void update(std::span<const std::uint8_t> in);
    Hash finish();

private:
    // Opaque, sized to blake2s_state. Checked with a static_assert in the .cpp so
    // a vendored-header change is a compile error rather than a stack overflow.
    //
    // std::uint64_t rather than `alignas(std::uint64_t) unsigned char`: both give
    // 512 bytes at 8-byte alignment, but the array type carries the alignment
    // itself instead of asking for it, and MSVC's /W4 emits C4324 ("structure was
    // padded due to alignment specifier") on every TU that materialises this
    // class when the specifier is what forces the tail padding. Getting the same
    // layout from the element type is the fix that removes the warning rather
    // than muting it — /wd4324 would also hide genuine accidental over-alignment
    // later. Nothing indexes this buffer bytewise; every use is sizeof, memset,
    // wipe, or a cast to blake2s_state*.
    std::uint64_t _state[64];
    bool _done = false;
};

/// HMAC-BLAKE2s (RFC 2104). This — not BLAKE2s's native keyed mode — is what
/// Noise §4.3 specifies. See the file header.
Hash hmacBlake2s(std::span<const std::uint8_t> key, std::span<const std::uint8_t> data);

/// Noise HKDF (§5.3). Two or three outputs, each HASHLEN bytes.
///
/// Split out as separate functions rather than a count parameter because the
/// caller always knows statically how many it wants, and a wrong count silently
/// derives the wrong keys.
void hkdf2(std::span<const std::uint8_t> chainingKey,
           std::span<const std::uint8_t> ikm,
           Hash& out1, Hash& out2);

void hkdf3(std::span<const std::uint8_t> chainingKey,
           std::span<const std::uint8_t> ikm,
           Hash& out1, Hash& out2, Hash& out3);

// --- AEAD --------------------------------------------------------------------

/// ChaCha20-Poly1305 (RFC 8439) with Noise's nonce encoding: 32 bits of zeros
/// followed by the 64-bit counter little-endian (Noise §12.3). Appends
/// ciphertext followed by the 16-byte tag.
Status aeadSeal(const Key& k, std::uint64_t nonce,
                std::span<const std::uint8_t> ad,
                std::span<const std::uint8_t> plaintext,
                std::vector<std::uint8_t>& out);

/// Any authentication failure is AuthFailed, which core/Status.h classifies as
/// fatal. There is no "retry"; a forged record ends the session.
Status aeadOpen(const Key& k, std::uint64_t nonce,
                std::span<const std::uint8_t> ad,
                std::span<const std::uint8_t> ciphertext,
                std::vector<std::uint8_t>& out);

// --- X25519 ------------------------------------------------------------------

void      x25519KeyPair(SecretKey& sk, PublicKey& pk);
PublicKey x25519PublicKey(const SecretKey& sk);

/// Returns false if the shared secret is all zeros, which is what a peer gets by
/// sending a low-order point. RFC 7748 §6.1 permits this check and it is worth
/// making: an attacker who can force a known shared secret controls the session
/// key. The Noise spec does not require it, so this is deliberately stricter.
bool x25519(const SecretKey& sk, const PublicKey& pk, Key& sharedOut);

// --- Ed25519 (RFC 8032) ------------------------------------------------------
//
// Standard Ed25519 with SHA-512, NOT Monocypher's default BLAKE2b EdDSA. The
// identity key is specified to double as a TLS 1.3 raw-public-key certificate
// key, so it has to be the one every TLS stack implements.

void      ed25519KeyPairFromSeed(const Seed& seed, EdSecret& sk, PublicKey& pk);
Signature ed25519Sign(const EdSecret& sk, std::span<const std::uint8_t> msg);
bool      ed25519Verify(const Signature& sig, const PublicKey& pk,
                        std::span<const std::uint8_t> msg);

// --- utilities ---------------------------------------------------------------

/// Constant time. Length mismatch returns false without comparing, which leaks
/// only the length — already public in every use here.
bool constantTimeEquals(std::span<const std::uint8_t> a,
                        std::span<const std::uint8_t> b);

/// Overwrites and is not optimised away.
void wipe(void* p, std::size_t n) noexcept;

template <typename Arr>
void wipeArray(Arr& a) noexcept { wipe(a.data(), a.size()); }

/// Cryptographically secure randomness. Aborts rather than returning on failure:
/// a key derived from a failed RNG is worse than no session at all, and there is
/// no sensible recovery from "this machine cannot produce entropy".
void randomBytes(std::span<std::uint8_t> out);

/// Hex helpers for vectors, logs and fingerprints. Not constant time; never used
/// on secret material outside tests.
std::string toHex(std::span<const std::uint8_t> in);
bool fromHex(std::string_view hex, std::vector<std::uint8_t>& out);

} // namespace airusb::crypto

#endif // AIRUSB_CRYPTO_PRIMITIVES_H
