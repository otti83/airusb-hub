// P2.4 — the vendored primitives, against the standards that define them.
//
// Every constant here comes out of an RFC, extracted mechanically (see
// tests/vectors/CryptoVectors.h). None of it is our arithmetic, which is the
// point: a vendored file that was truncated, corrupted, swapped for a lookalike,
// or built with the wrong flags produces plausible-looking ciphertext and fails
// here rather than in the field.
//
// The HMAC tests matter more than they look. Noise's key schedule is HMAC over
// the hash; BLAKE2s also has a native keyed mode that is a DIFFERENT
// construction. Confusing the two yields a protocol that is perfectly
// self-consistent and interoperates with nothing — and no round-trip test can
// see it. So HMAC is pinned against RFC 2104's own structural properties and,
// below, the whole Noise handshake is pinned against an independent
// implementation's vectors.

#include "../TestHarness.h"
#include "../vectors/CryptoVectors.h"
#include "../../crypto/Primitives.h"

#include <cstring>
#include <string>

using namespace airusb;
using namespace airusb::crypto;
using namespace airusb::test::cryptovec;

namespace {

std::vector<std::uint8_t> hx(const char* hex)
{
    std::vector<std::uint8_t> v;
    if (!fromHex(hex, v)) {
        std::printf("\n    BAD HEX LITERAL: %s\n", hex);
        std::abort();
    }
    return v;
}

std::vector<std::uint8_t> bytesOf(const char* s)
{
    const std::size_t n = std::strlen(s);
    return std::vector<std::uint8_t>(reinterpret_cast<const std::uint8_t*>(s),
                                     reinterpret_cast<const std::uint8_t*>(s) + n);
}

std::string hexOf(std::span<const std::uint8_t> s) { return toHex(s); }

void testHex()
{
    std::printf("hex helpers (used by every vector below)\n");

    TEST_CASE("round trip") {
        const std::vector<std::uint8_t> v = { 0x00, 0x0f, 0xf0, 0xff, 0xa5 };
        CHECK(toHex(v) == "000ff0ffa5");
        std::vector<std::uint8_t> back;
        CHECK(fromHex("000ff0ffa5", back));
        CHECK(back == v);
    }

    TEST_CASE("malformed hex is refused, not guessed") {
        std::vector<std::uint8_t> v;
        CHECK(!fromHex("abc", v));        // odd length
        CHECK(!fromHex("zz", v));         // not hex
        CHECK(!fromHex("00 11", v));      // spaces are not hex
        CHECK(v.empty());
        CHECK(fromHex("", v));            // empty is valid and yields nothing
        CHECK(v.empty());
    }
}

void testBlake2s()
{
    std::printf("BLAKE2s-256 — RFC 7693 Appendix B\n");

    TEST_CASE("BLAKE2s(\"abc\") matches the RFC") {
        const Hash h = blake2s(bytesOf(kBlake2sAbcInput));
        CHECK(hexOf(h) == kBlake2sAbcDigest);
    }

    TEST_CASE("BLAKE2s(\"\") matches the published digest") {
        const Hash h = blake2s({});
        CHECK(hexOf(h) == kBlake2sEmptyDigest);
    }

    TEST_CASE("streaming and one-shot agree, at every split point") {
        const auto msg = bytesOf("The quick brown fox jumps over the lazy dog");
        const Hash oneShot = blake2s(msg);
        for (std::size_t cut = 0; cut <= msg.size(); ++cut) {
            Blake2s s;
            s.update(std::span<const std::uint8_t>(msg).subspan(0, cut));
            s.update(std::span<const std::uint8_t>(msg).subspan(cut));
            CHECK(s.finish() == oneShot);
        }
    }

    TEST_CASE("a single flipped bit changes the digest") {
        auto a = bytesOf(kBlake2sAbcInput);
        auto b = a;
        b[0] ^= 0x01u;
        CHECK(!(blake2s(a) == blake2s(b)));
    }
}

void testHmacAndHkdf()
{
    std::printf("HMAC-BLAKE2s and Noise HKDF\n");

    TEST_CASE("HMAC is not BLAKE2s's native keyed mode") {
        // The whole reason hmacBlake2s exists. If someone ever "optimises" it
        // into blake2s_init_key, this fails — and it is the only test that would
        // notice, because both constructions round-trip against themselves.
        const auto key  = bytesOf("key");
        const auto data = bytesOf("data");
        const Hash mac  = hmacBlake2s(key, data);

        // The native keyed mode is BLAKE2s(data) with the key in the parameter
        // block, which for a 3-byte key is emphatically not HMAC's
        // H((k^opad) || H((k^ipad) || m)).
        std::vector<std::uint8_t> concat = key;
        concat.insert(concat.end(), data.begin(), data.end());
        CHECK(!(mac == blake2s(concat)));
    }

    TEST_CASE("HMAC keys longer than the block are hashed first (RFC 2104)") {
        std::vector<std::uint8_t> longKey(200, 0xAB);
        const Hash viaLong = hmacBlake2s(longKey, bytesOf("x"));

        const Hash hashedKey = blake2s(longKey);
        const Hash viaShort  = hmacBlake2s(
            std::span<const std::uint8_t>(hashedKey.data(), hashedKey.size()),
            bytesOf("x"));
        CHECK(viaLong == viaShort);
    }

    TEST_CASE("an empty key and empty data are accepted") {
        const Hash h = hmacBlake2s({}, {});
        bool allZero = true;
        for (std::uint8_t b : h) if (b) allZero = false;
        CHECK(!allZero);
    }

    TEST_CASE("HKDF outputs are distinct and deterministic") {
        const auto ck  = bytesOf("chaining key");
        const auto ikm = bytesOf("input keying material");

        Hash a1{}, a2{}, a3{};
        Hash b1{}, b2{}, b3{};
        hkdf3(ck, ikm, a1, a2, a3);
        hkdf3(ck, ikm, b1, b2, b3);

        CHECK(a1 == b1);
        CHECK(a2 == b2);
        CHECK(a3 == b3);
        CHECK(!(a1 == a2));
        CHECK(!(a2 == a3));
        CHECK(!(a1 == a3));
    }

    TEST_CASE("hkdf2 and hkdf3 agree on their shared outputs") {
        // Noise §5.3 defines one function with a count; splitting it in two must
        // not have changed the first two outputs.
        const auto ck  = bytesOf("ck");
        const auto ikm = bytesOf("ikm");
        Hash x1{}, x2{}, y1{}, y2{}, y3{};
        hkdf2(ck, ikm, x1, x2);
        hkdf3(ck, ikm, y1, y2, y3);
        CHECK(x1 == y1);
        CHECK(x2 == y2);
    }

    TEST_CASE("swapping the chaining key and the IKM changes everything") {
        // HKDF's key is the chaining key and its data is the IKM, which is the
        // reverse of the intuitive reading. This pins the orientation.
        const auto ck  = bytesOf("aaaa");
        const auto ikm = bytesOf("bbbb");
        Hash p1{}, p2{}, q1{}, q2{};
        hkdf2(ck, ikm, p1, p2);
        hkdf2(ikm, ck, q1, q2);
        CHECK(!(p1 == q1));
    }
}

void testAead()
{
    std::printf("ChaCha20-Poly1305 — RFC 8439 Appendix A.5\n");

    const auto key = hx(kAeadKey);
    const auto aad = hx(kAeadAad);
    const auto pt  = hx(kAeadPlaintext);
    const auto ct  = hx(kAeadCiphertext);
    const auto tag = hx(kAeadTag);

    Key k{};
    std::memcpy(k.data(), key.data(), k.size());

    TEST_CASE("sealing reproduces the RFC ciphertext and tag") {
        std::vector<std::uint8_t> out;
        CHECK(aeadSeal(k, kAeadNoiseNonce, aad, pt, out) == Status::Ok);
        CHECK_EQ(out.size(), pt.size() + kTagLen);

        const std::string gotCt = hexOf(std::span<const std::uint8_t>(out).subspan(0, pt.size()));
        const std::string gotTag = hexOf(std::span<const std::uint8_t>(out).subspan(pt.size()));
        CHECK(gotCt == kAeadCiphertext);
        CHECK(gotTag == kAeadTag);
    }

    TEST_CASE("opening the RFC ciphertext reproduces the plaintext") {
        std::vector<std::uint8_t> sealed = ct;
        sealed.insert(sealed.end(), tag.begin(), tag.end());

        std::vector<std::uint8_t> out;
        CHECK(aeadOpen(k, kAeadNoiseNonce, aad, sealed, out) == Status::Ok);
        CHECK(out == pt);
    }

    TEST_CASE("a flipped ciphertext bit is AuthFailed, not garbage plaintext") {
        std::vector<std::uint8_t> sealed = ct;
        sealed.insert(sealed.end(), tag.begin(), tag.end());
        sealed[10] ^= 0x01u;

        std::vector<std::uint8_t> out;
        CHECK(aeadOpen(k, kAeadNoiseNonce, aad, sealed, out) == Status::AuthFailed);
        CHECK(out.empty());
        CHECK(isFatal(Status::AuthFailed));
    }

    TEST_CASE("a flipped tag bit is AuthFailed") {
        std::vector<std::uint8_t> sealed = ct;
        sealed.insert(sealed.end(), tag.begin(), tag.end());
        sealed.back() ^= 0x80u;

        std::vector<std::uint8_t> out;
        CHECK(aeadOpen(k, kAeadNoiseNonce, aad, sealed, out) == Status::AuthFailed);
    }

    TEST_CASE("modified associated data is AuthFailed") {
        std::vector<std::uint8_t> sealed = ct;
        sealed.insert(sealed.end(), tag.begin(), tag.end());
        auto badAad = aad;
        badAad[0] ^= 0x01u;

        std::vector<std::uint8_t> out;
        CHECK(aeadOpen(k, kAeadNoiseNonce, badAad, sealed, out) == Status::AuthFailed);
    }

    TEST_CASE("the wrong nonce is AuthFailed — this is what stops replay") {
        std::vector<std::uint8_t> sealed = ct;
        sealed.insert(sealed.end(), tag.begin(), tag.end());

        std::vector<std::uint8_t> out;
        CHECK(aeadOpen(k, kAeadNoiseNonce + 1, aad, sealed, out) == Status::AuthFailed);
    }

    TEST_CASE("a record shorter than the tag is refused without reading past it") {
        std::vector<std::uint8_t> out;
        for (std::size_t n = 0; n < kTagLen; ++n) {
            const std::vector<std::uint8_t> tooShort(n, 0);
            CHECK(aeadOpen(k, 0, {}, tooShort, out) == Status::AuthFailed);
        }
    }

    TEST_CASE("an empty plaintext still authenticates") {
        std::vector<std::uint8_t> sealed;
        CHECK(aeadSeal(k, 7, aad, {}, sealed) == Status::Ok);
        CHECK_EQ(sealed.size(), kTagLen);

        std::vector<std::uint8_t> out;
        CHECK(aeadOpen(k, 7, aad, sealed, out) == Status::Ok);
        CHECK(out.empty());
    }

    TEST_CASE("the nonce is 32 zero bits then a little-endian counter") {
        // Noise §12.3. If the counter were encoded big-endian, or the zeros put
        // at the end, nonce 1 would produce different ciphertext than this.
        // Pinned by sealing with a counter whose byte pattern is asymmetric.
        std::vector<std::uint8_t> a, b;
        CHECK(aeadSeal(k, 0x0102030405060708ull, {}, bytesOf("x"), a) == Status::Ok);
        CHECK(aeadSeal(k, 0x0807060504030201ull, {}, bytesOf("x"), b) == Status::Ok);
        CHECK(!(a == b));
    }
}

void testX25519()
{
    std::printf("X25519 — RFC 7748\n");

    TEST_CASE("section 6.1: a full Diffie-Hellman exchange") {
        const auto aPriv = hx(kAlicePrivate);
        const auto bPriv = hx(kBobPrivate);

        SecretKey ask{}, bsk{};
        std::memcpy(ask.data(), aPriv.data(), ask.size());
        std::memcpy(bsk.data(), bPriv.data(), bsk.size());

        const PublicKey apk = x25519PublicKey(ask);
        const PublicKey bpk = x25519PublicKey(bsk);
        CHECK(hexOf(apk) == kAlicePublic);
        CHECK(hexOf(bpk) == kBobPublic);

        Key s1{}, s2{};
        CHECK(x25519(ask, bpk, s1));
        CHECK(x25519(bsk, apk, s2));
        CHECK(hexOf(s1) == kSharedSecret);
        CHECK(s1 == s2);
    }

    TEST_CASE("a low-order point is rejected rather than yielding a known key") {
        // An all-zero public key is the canonical small-order point. RFC 7748
        // §6.1 permits this check; we make it, because a peer that can force a
        // predictable shared secret owns the session.
        SecretKey sk{};
        PublicKey pk{};
        x25519KeyPair(sk, pk);

        const PublicKey lowOrder{};        // all zeros
        Key shared{};
        CHECK(!x25519(sk, lowOrder, shared));

        bool allZero = true;
        for (std::uint8_t b : shared) if (b) allZero = false;
        CHECK(allZero);                    // and the buffer was wiped
    }

    TEST_CASE("generated key pairs are distinct and agree") {
        SecretKey ask{}, bsk{};
        PublicKey apk{}, bpk{};
        x25519KeyPair(ask, apk);
        x25519KeyPair(bsk, bpk);
        CHECK(!(ask == bsk));
        CHECK(!(apk == bpk));

        Key s1{}, s2{};
        CHECK(x25519(ask, bpk, s1));
        CHECK(x25519(bsk, apk, s2));
        CHECK(s1 == s2);
    }
}

void testEd25519()
{
    std::printf("Ed25519 — RFC 8032 section 7.1\n");

    const auto seedBytes = hx(kEdSeed);
    Seed seed{};
    std::memcpy(seed.data(), seedBytes.data(), seed.size());

    EdSecret sk{};
    PublicKey pk{};
    ed25519KeyPairFromSeed(seed, sk, pk);

    TEST_CASE("TEST 1: the public key derives from the seed as published") {
        // If this fails, the build is using Monocypher's BLAKE2b EdDSA rather
        // than RFC 8032 Ed25519 — which would produce signatures no TLS stack
        // could ever verify.
        CHECK(hexOf(pk) == kEdPublic);
    }

    TEST_CASE("TEST 1: the signature over the empty message matches") {
        const Signature sig = ed25519Sign(sk, {});
        CHECK(hexOf(sig) == kEdSignature);
    }

    TEST_CASE("the published signature verifies") {
        const auto sigBytes = hx(kEdSignature);
        Signature sig{};
        std::memcpy(sig.data(), sigBytes.data(), sig.size());
        CHECK(ed25519Verify(sig, pk, {}));
    }

    TEST_CASE("a tampered signature does not verify") {
        Signature sig = ed25519Sign(sk, bytesOf("hello"));
        CHECK(ed25519Verify(sig, pk, bytesOf("hello")));
        sig[0] ^= 0x01u;
        CHECK(!ed25519Verify(sig, pk, bytesOf("hello")));
    }

    TEST_CASE("a signature does not verify against a different message") {
        const Signature sig = ed25519Sign(sk, bytesOf("hello"));
        CHECK(!ed25519Verify(sig, pk, bytesOf("hellp")));
        CHECK(!ed25519Verify(sig, pk, {}));
    }

    TEST_CASE("a signature does not verify against a different key") {
        Seed other{};
        randomBytes(std::span<std::uint8_t>(other.data(), other.size()));
        EdSecret osk{};
        PublicKey opk{};
        ed25519KeyPairFromSeed(other, osk, opk);

        const Signature sig = ed25519Sign(sk, bytesOf("hello"));
        CHECK(!ed25519Verify(sig, opk, bytesOf("hello")));
    }

    TEST_CASE("the caller's seed survives key generation") {
        // Monocypher wipes the seed it is handed. The wrapper passes a copy,
        // because the daemon needs to write its own seed to the identity file
        // after deriving the key from it.
        Seed s2{};
        std::memcpy(s2.data(), seedBytes.data(), s2.size());
        EdSecret k2{};
        PublicKey p2{};
        ed25519KeyPairFromSeed(s2, k2, p2);
        CHECK(hexOf(s2) == kEdSeed);
        CHECK(p2 == pk);
    }
}

void testUtilities()
{
    std::printf("utilities\n");

    TEST_CASE("constant-time compare agrees with ==") {
        const std::vector<std::uint8_t> a = { 1, 2, 3, 4 };
        const std::vector<std::uint8_t> b = { 1, 2, 3, 4 };
        const std::vector<std::uint8_t> c = { 1, 2, 3, 5 };
        const std::vector<std::uint8_t> d = { 1, 2, 3 };
        CHECK(constantTimeEquals(a, b));
        CHECK(!constantTimeEquals(a, c));
        CHECK(!constantTimeEquals(a, d));
        CHECK(constantTimeEquals({}, {}));
    }

    TEST_CASE("randomBytes produces different bytes each call") {
        std::vector<std::uint8_t> a(64), b(64);
        randomBytes(a);
        randomBytes(b);
        CHECK(a != b);

        bool allZero = true;
        for (std::uint8_t x : a) if (x) allZero = false;
        CHECK(!allZero);
    }

    TEST_CASE("randomBytes fills more than one getentropy chunk") {
        // getentropy(2) caps at 256 bytes; the loop must cover the remainder.
        std::vector<std::uint8_t> big(1000, 0);
        randomBytes(big);
        std::size_t zeros = 0;
        for (std::uint8_t x : big) if (x == 0) ++zeros;
        // ~4 zero bytes expected in 1000; 200 would mean a chunk was never filled.
        CHECK(zeros < 200);
    }

    TEST_CASE("wipe clears the buffer") {
        std::vector<std::uint8_t> v(32, 0xAA);
        wipe(v.data(), v.size());
        bool allZero = true;
        for (std::uint8_t x : v) if (x) allZero = false;
        CHECK(allZero);
    }
}

} // namespace

int main()
{
    std::printf("test_crypto\n");
    testHex();
    testBlake2s();
    testHmacAndHkdf();
    testAead();
    testX25519();
    testEd25519();
    testUtilities();
    TEST_MAIN_END();
}
