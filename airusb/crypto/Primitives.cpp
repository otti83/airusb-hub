#include "Primitives.h"

extern "C" {
#include "../third_party/blake2s/blake2.h"
#include "../third_party/monocypher/monocypher.h"
#include "../third_party/monocypher/monocypher-ed25519.h"
}

#include <cstdlib>
#include <cstring>
#include <string>

#include <sys/random.h>

namespace airusb::crypto {

namespace {

const std::uint8_t* ptr(std::span<const std::uint8_t> s) noexcept
{
    // A null pointer with a zero length is legal for a span but not for every C
    // API, so hand out a stable non-null address instead. The length is zero, so
    // nothing is read from it.
    static const std::uint8_t kEmpty = 0;
    return s.empty() ? &kEmpty : s.data();
}

} // namespace

// ---------------------------------------------------------------------------
// hash
// ---------------------------------------------------------------------------

static_assert(sizeof(blake2s_state) <= 512,
              "Blake2s::_state is too small for the vendored blake2s_state");
static_assert(kHashLen == BLAKE2S_OUTBYTES, "BLAKE2s digest length changed upstream");
static_assert(kBlockLen == BLAKE2S_BLOCKBYTES, "BLAKE2s block length changed upstream");

Hash blake2s(std::span<const std::uint8_t> in)
{
    Hash out{};
    ::blake2s(out.data(), out.size(), ptr(in), in.size(), nullptr, 0);
    return out;
}

Blake2s::Blake2s()
{
    std::memset(_state, 0, sizeof _state);
    ::blake2s_init(reinterpret_cast<blake2s_state*>(_state), kHashLen);
}

Blake2s::~Blake2s()
{
    wipe(_state, sizeof _state);
}

void Blake2s::update(std::span<const std::uint8_t> in)
{
    if (_done) return;
    ::blake2s_update(reinterpret_cast<blake2s_state*>(_state), ptr(in), in.size());
}

Hash Blake2s::finish()
{
    Hash out{};
    if (!_done) {
        ::blake2s_final(reinterpret_cast<blake2s_state*>(_state), out.data(), out.size());
        _done = true;
    }
    return out;
}

Hash hmacBlake2s(std::span<const std::uint8_t> key, std::span<const std::uint8_t> data)
{
    // RFC 2104, with BLAKE2s as H. Written out rather than delegated to BLAKE2s's
    // native keyed mode, which is a different construction — see Primitives.h.
    std::uint8_t block[kBlockLen];
    std::memset(block, 0, sizeof block);

    if (key.size() > kBlockLen) {
        const Hash hk = blake2s(key);
        std::memcpy(block, hk.data(), hk.size());
    } else if (!key.empty()) {
        std::memcpy(block, key.data(), key.size());
    }

    std::uint8_t ipad[kBlockLen];
    std::uint8_t opad[kBlockLen];
    for (std::size_t i = 0; i < kBlockLen; ++i) {
        ipad[i] = static_cast<std::uint8_t>(block[i] ^ 0x36u);
        opad[i] = static_cast<std::uint8_t>(block[i] ^ 0x5Cu);
    }

    Blake2s inner;
    inner.update(std::span<const std::uint8_t>(ipad, kBlockLen));
    inner.update(data);
    const Hash innerHash = inner.finish();

    Blake2s outer;
    outer.update(std::span<const std::uint8_t>(opad, kBlockLen));
    outer.update(std::span<const std::uint8_t>(innerHash.data(), innerHash.size()));
    const Hash out = outer.finish();

    wipe(block, sizeof block);
    wipe(ipad, sizeof ipad);
    wipe(opad, sizeof opad);
    return out;
}

void hkdf2(std::span<const std::uint8_t> chainingKey,
           std::span<const std::uint8_t> ikm,
           Hash& out1, Hash& out2)
{
    // Noise §5.3. Note the chaining key is the HMAC *key* and the input keying
    // material is the *data* — the reverse of the intuitive reading, and a
    // classic way to produce a plausible but wrong key schedule.
    Hash tempKey = hmacBlake2s(chainingKey, ikm);

    const std::uint8_t one = 1;
    out1 = hmacBlake2s(std::span<const std::uint8_t>(tempKey.data(), tempKey.size()),
                       std::span<const std::uint8_t>(&one, 1));

    std::uint8_t buf[kHashLen + 1];
    std::memcpy(buf, out1.data(), kHashLen);
    buf[kHashLen] = 2;
    out2 = hmacBlake2s(std::span<const std::uint8_t>(tempKey.data(), tempKey.size()),
                       std::span<const std::uint8_t>(buf, kHashLen + 1));

    wipeArray(tempKey);
    wipe(buf, sizeof buf);
}

void hkdf3(std::span<const std::uint8_t> chainingKey,
           std::span<const std::uint8_t> ikm,
           Hash& out1, Hash& out2, Hash& out3)
{
    Hash tempKey = hmacBlake2s(chainingKey, ikm);

    const std::uint8_t one = 1;
    out1 = hmacBlake2s(std::span<const std::uint8_t>(tempKey.data(), tempKey.size()),
                       std::span<const std::uint8_t>(&one, 1));

    std::uint8_t buf[kHashLen + 1];
    std::memcpy(buf, out1.data(), kHashLen);
    buf[kHashLen] = 2;
    out2 = hmacBlake2s(std::span<const std::uint8_t>(tempKey.data(), tempKey.size()),
                       std::span<const std::uint8_t>(buf, kHashLen + 1));

    std::memcpy(buf, out2.data(), kHashLen);
    buf[kHashLen] = 3;
    out3 = hmacBlake2s(std::span<const std::uint8_t>(tempKey.data(), tempKey.size()),
                       std::span<const std::uint8_t>(buf, kHashLen + 1));

    wipeArray(tempKey);
    wipe(buf, sizeof buf);
}

// ---------------------------------------------------------------------------
// AEAD
// ---------------------------------------------------------------------------

namespace {

/// Noise §12.3: "96-bit nonce formed by encoding 32 bits of zeros followed by
/// little-endian encoding of n." The zeros come FIRST. Getting the order wrong
/// produces a cipher that talks to itself and to nothing else.
void noiseNonce(std::uint64_t n, std::uint8_t out[kNonceLen]) noexcept
{
    out[0] = out[1] = out[2] = out[3] = 0;
    for (std::size_t i = 0; i < 8; ++i)
        out[4 + i] = static_cast<std::uint8_t>((n >> (8 * i)) & 0xFFu);
}

} // namespace

Status aeadSeal(const Key& k, std::uint64_t nonce,
                std::span<const std::uint8_t> ad,
                std::span<const std::uint8_t> plaintext,
                std::vector<std::uint8_t>& out)
{
    std::uint8_t n[kNonceLen];
    noiseNonce(nonce, n);

    const std::size_t at = out.size();
    out.resize(at + plaintext.size() + kTagLen);

    crypto_aead_ctx ctx;
    crypto_aead_init_ietf(&ctx, k.data(), n);
    crypto_aead_write(&ctx,
                      out.data() + at,                      // ciphertext
                      out.data() + at + plaintext.size(),   // mac
                      ptr(ad), ad.size(),
                      ptr(plaintext), plaintext.size());
    crypto_wipe(&ctx, sizeof ctx);
    return Status::Ok;
}

Status aeadOpen(const Key& k, std::uint64_t nonce,
                std::span<const std::uint8_t> ad,
                std::span<const std::uint8_t> ciphertext,
                std::vector<std::uint8_t>& out)
{
    // A record shorter than the tag cannot be authentic, and computing on it
    // would read before the buffer.
    if (ciphertext.size() < kTagLen) return Status::AuthFailed;
    const std::size_t ptLen = ciphertext.size() - kTagLen;

    std::uint8_t n[kNonceLen];
    noiseNonce(nonce, n);

    std::vector<std::uint8_t> tmp(ptLen);

    crypto_aead_ctx ctx;
    crypto_aead_init_ietf(&ctx, k.data(), n);
    const int rc = crypto_aead_read(&ctx,
                                    tmp.data(),
                                    ciphertext.data() + ptLen,   // mac
                                    ptr(ad), ad.size(),
                                    ciphertext.data(), ptLen);
    crypto_wipe(&ctx, sizeof ctx);

    if (rc != 0) {
        // Monocypher has already wiped its own output on failure. Wipe ours too:
        // a caller that ignored the status must not find plausible plaintext.
        wipe(tmp.data(), tmp.size());
        return Status::AuthFailed;
    }

    out.insert(out.end(), tmp.begin(), tmp.end());
    wipe(tmp.data(), tmp.size());
    return Status::Ok;
}

// ---------------------------------------------------------------------------
// X25519
// ---------------------------------------------------------------------------

void x25519KeyPair(SecretKey& sk, PublicKey& pk)
{
    randomBytes(std::span<std::uint8_t>(sk.data(), sk.size()));
    crypto_x25519_public_key(pk.data(), sk.data());
}

PublicKey x25519PublicKey(const SecretKey& sk)
{
    PublicKey pk{};
    crypto_x25519_public_key(pk.data(), sk.data());
    return pk;
}

bool x25519(const SecretKey& sk, const PublicKey& pk, Key& sharedOut)
{
    crypto_x25519(sharedOut.data(), sk.data(), pk.data());

    // All-zero output means the peer supplied a low-order point. Refusing is
    // stricter than Noise requires and is the behaviour WireGuard chose.
    static const std::uint8_t zero[kDhLen] = {};
    if (crypto_verify32(sharedOut.data(), zero) == 0) {
        wipeArray(sharedOut);
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Ed25519
// ---------------------------------------------------------------------------

void ed25519KeyPairFromSeed(const Seed& seed, EdSecret& sk, PublicKey& pk)
{
    // Monocypher wipes the seed it is given, so it gets a copy: the caller may
    // legitimately still need theirs (writing it to the identity file, say).
    Seed scratch = seed;
    crypto_ed25519_key_pair(sk.data(), pk.data(), scratch.data());
    wipeArray(scratch);
}

Signature ed25519Sign(const EdSecret& sk, std::span<const std::uint8_t> msg)
{
    Signature sig{};
    crypto_ed25519_sign(sig.data(), sk.data(), ptr(msg), msg.size());
    return sig;
}

bool ed25519Verify(const Signature& sig, const PublicKey& pk,
                   std::span<const std::uint8_t> msg)
{
    // Monocypher's check is the strict, non-malleable one: it rejects
    // non-canonical scalars and small-order public keys, which is what P1 plan
    // §3.14 requires. A permissive verifier would let one signature be mauled
    // into another valid one for the same message.
    return crypto_ed25519_check(sig.data(), pk.data(), ptr(msg), msg.size()) == 0;
}

// ---------------------------------------------------------------------------
// utilities
// ---------------------------------------------------------------------------

bool constantTimeEquals(std::span<const std::uint8_t> a, std::span<const std::uint8_t> b)
{
    if (a.size() != b.size()) return false;
    std::uint8_t diff = 0;
    for (std::size_t i = 0; i < a.size(); ++i)
        diff = static_cast<std::uint8_t>(diff | (a[i] ^ b[i]));
    return diff == 0;
}

void wipe(void* p, std::size_t n) noexcept
{
    if (p && n) crypto_wipe(p, n);
}

void randomBytes(std::span<std::uint8_t> out)
{
    std::size_t at = 0;
    while (at < out.size()) {
        // getentropy(2) is capped at 256 bytes per call on both macOS and Linux.
        const std::size_t chunk = (out.size() - at) < 256 ? (out.size() - at) : 256;
        if (::getentropy(out.data() + at, chunk) != 0) {
            // Deliberately fatal. Continuing would mean deriving a session key
            // from whatever happened to be in the buffer, and every caller of
            // this function is producing key material.
            std::abort();
        }
        at += chunk;
    }
}

std::string toHex(std::span<const std::uint8_t> in)
{
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(in.size() * 2);
    for (std::uint8_t b : in) {
        s.push_back(d[b >> 4]);
        s.push_back(d[b & 0x0Fu]);
    }
    return s;
}

bool fromHex(std::string_view hex, std::vector<std::uint8_t>& out)
{
    out.clear();
    if (hex.size() % 2 != 0) return false;
    out.reserve(hex.size() / 2);

    const auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };

    for (std::size_t i = 0; i < hex.size(); i += 2) {
        const int hi = nib(hex[i]);
        const int lo = nib(hex[i + 1]);
        if (hi < 0 || lo < 0) { out.clear(); return false; }
        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return true;
}

} // namespace airusb::crypto
