#include "Identity.h"

#include <cstring>

namespace airusb::crypto {

namespace {

std::span<const std::uint8_t> bytesOf(std::string_view s) noexcept
{
    return std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(s.data()), s.size());
}

template <std::size_t N>
std::span<const std::uint8_t> asSpan(const std::array<std::uint8_t, N>& a) noexcept
{
    return std::span<const std::uint8_t>(a.data(), a.size());
}

void append(std::vector<std::uint8_t>& v, std::span<const std::uint8_t> s)
{
    v.insert(v.end(), s.begin(), s.end());
}

/// Domain-separated expansion of the one stored seed into the two keypairs.
/// The labels differ, so the Ed25519 seed and the X25519 secret are independent
/// even though one secret is written to disk.
inline constexpr std::string_view kSeedLabelIdentity = "AirUSB-seed-identity-v1";
inline constexpr std::string_view kSeedLabelNoise    = "AirUSB-seed-noise-v1";

Seed expandSeed(const Seed& seed, std::string_view label)
{
    const Hash h = hmacBlake2s(asSpan(seed), bytesOf(label));
    Seed out{};
    std::memcpy(out.data(), h.data(), out.size());
    return out;
}

} // namespace

// ---------------------------------------------------------------------------
// LocalIdentity
// ---------------------------------------------------------------------------

LocalIdentity::~LocalIdentity()
{
    wipeArray(_seed);
    wipeArray(_idSk);
    wipeArray(_noiseSk);
}

LocalIdentity::LocalIdentity(LocalIdentity&& o) noexcept
    : _seed(o._seed), _idSk(o._idSk), _idPub(o._idPub),
      _noiseSk(o._noiseSk), _noisePub(o._noisePub), _binding(o._binding)
{
    wipeArray(o._seed);
    wipeArray(o._idSk);
    wipeArray(o._noiseSk);
}

LocalIdentity& LocalIdentity::operator=(LocalIdentity&& o) noexcept
{
    if (this != &o) {
        wipeArray(_seed);
        wipeArray(_idSk);
        wipeArray(_noiseSk);
        _seed     = o._seed;
        _idSk     = o._idSk;
        _idPub    = o._idPub;
        _noiseSk  = o._noiseSk;
        _noisePub = o._noisePub;
        _binding  = o._binding;
        wipeArray(o._seed);
        wipeArray(o._idSk);
        wipeArray(o._noiseSk);
    }
    return *this;
}

LocalIdentity LocalIdentity::generate()
{
    Seed s{};
    randomBytes(std::span<std::uint8_t>(s.data(), s.size()));
    LocalIdentity id = fromSeed(s);
    wipeArray(s);
    return id;
}

LocalIdentity LocalIdentity::fromSeed(const Seed& seed)
{
    LocalIdentity id;
    id._seed = seed;

    Seed edSeed = expandSeed(seed, kSeedLabelIdentity);
    ed25519KeyPairFromSeed(edSeed, id._idSk, id._idPub);
    wipeArray(edSeed);

    Seed nSeed = expandSeed(seed, kSeedLabelNoise);
    std::memcpy(id._noiseSk.data(), nSeed.data(), id._noiseSk.size());
    wipeArray(nSeed);
    id._noisePub = x25519PublicKey(id._noiseSk);

    const std::vector<std::uint8_t> msg = bindingMessage(id._idPub, id._noisePub);
    id._binding = ed25519Sign(id._idSk, msg);
    return id;
}

PeerIdentity LocalIdentity::publicIdentity() const
{
    PeerIdentity p;
    p.identityKey = _idPub;
    p.noiseKey    = _noisePub;
    p.binding     = _binding;
    return p;
}

// ---------------------------------------------------------------------------
// binding
// ---------------------------------------------------------------------------

std::vector<std::uint8_t> bindingMessage(const PublicKey& identityKey,
                                         const PublicKey& noiseKey)
{
    // Context first, then both keys, in a fixed order. Both keys are fixed
    // length, so there is no ambiguity about where one ends and the next begins
    // and no length prefix is needed.
    std::vector<std::uint8_t> m;
    m.reserve(kBindingContext.size() + 2 * kDhLen);
    append(m, bytesOf(kBindingContext));
    append(m, asSpan(identityKey));
    append(m, asSpan(noiseKey));
    return m;
}

bool verifyBinding(const PeerIdentity& peer)
{
    const std::vector<std::uint8_t> msg = bindingMessage(peer.identityKey, peer.noiseKey);
    return ed25519Verify(peer.binding, peer.identityKey, msg);
}

// ---------------------------------------------------------------------------
// XX payload
// ---------------------------------------------------------------------------

void encodeIdentityPayload(const LocalIdentity& id, std::vector<std::uint8_t>& out)
{
    out.reserve(out.size() + kIdentityPayloadLen);
    append(out, asSpan(id.identityKey()));
    append(out, asSpan(id.binding()));
}

bool decodeAndVerifyIdentityPayload(std::span<const std::uint8_t> payload,
                                    const PublicKey& negotiatedNoiseKey,
                                    PeerIdentity& out)
{
    // Exactly this length. A longer payload is not "extra data to ignore": on
    // this path an unexplained trailing field is an attempt to smuggle something
    // past a parser, and the format has no extension point.
    if (payload.size() != kIdentityPayloadLen) return false;

    PeerIdentity p;
    std::memcpy(p.identityKey.data(), payload.data(), kDhLen);
    std::memcpy(p.binding.data(), payload.data() + kDhLen, kSigLen);

    // THE load-bearing line. The Noise key checked is the one the handshake
    // actually negotiated, not one taken from the payload. A payload that
    // carried its own noise key and was verified against it would prove only
    // that the attacker can sign their own pair of keys.
    p.noiseKey = negotiatedNoiseKey;

    if (!verifyBinding(p)) return false;
    out = p;
    return true;
}

// ---------------------------------------------------------------------------
// fingerprint
// ---------------------------------------------------------------------------

Fingerprint fingerprint(const PublicKey& identityKey)
{
    Blake2s h;
    h.update(bytesOf(kFingerprintContext));
    h.update(asSpan(identityKey));
    const Hash full = h.finish();

    Fingerprint fp{};
    std::memcpy(fp.data(), full.data(), fp.size());
    return fp;
}

std::string fingerprintText(const Fingerprint& fp)
{
    // RFC 4648 base32. 20 bytes is 160 bits, exactly 32 characters, so the
    // padding rules never come into play.
    static const char* kAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    std::string out;
    out.reserve(32 + 3);

    std::uint32_t buffer = 0;
    int bits = 0;
    int emitted = 0;
    for (std::uint8_t b : fp) {
        buffer = (buffer << 8) | b;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            if (emitted && emitted % 8 == 0) out.push_back(' ');
            out.push_back(kAlphabet[(buffer >> bits) & 0x1Fu]);
            ++emitted;
        }
    }
    return out;
}

// ---------------------------------------------------------------------------
// SAS
// ---------------------------------------------------------------------------

std::uint32_t sasDigits(const Hash& channelBinding)
{
    Hash o1{}, o2{};
    hkdf2(asSpan(channelBinding), bytesOf(kSasContext), o1, o2);

    // Big endian, pinned here because the spec did not say and both peers must
    // agree. Only the first eight bytes are used; the rest is discarded.
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < 8; ++i)
        v = (v << 8) | o1[i];

    wipeArray(o1);
    wipeArray(o2);

    // 2^64 is not a multiple of 10^6, so this has a modulo bias. It is about one
    // part in 2^44 — utterly dominated by the 1-in-10^6 guessing probability the
    // scheme is built on — and removing it would mean rejection sampling, which
    // makes the derivation non-constant-time for no security gain.
    return static_cast<std::uint32_t>(v % 1000000ull);
}

std::string sasText(std::uint32_t sas)
{
    std::string s = std::to_string(sas % 1000000u);
    while (s.size() < 6) s.insert(s.begin(), '0');
    return s;
}

} // namespace airusb::crypto
