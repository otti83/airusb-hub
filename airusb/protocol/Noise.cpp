#include "Noise.h"

#include <cstring>

namespace airusb::protocol {

using crypto::Hash;
using crypto::Key;
using crypto::kDhLen;
using crypto::kHashLen;
using crypto::kTagLen;
using crypto::PublicKey;
using crypto::SecretKey;

// ---------------------------------------------------------------------------
// message patterns
// ---------------------------------------------------------------------------

namespace {

enum class Token : std::uint8_t { E, S, EE, ES, SE, SS };

struct Pattern {
    const Token* const* messages;   ///< token array per message
    const std::uint8_t* lengths;
    std::uint8_t        messageCount;
    bool                responderPreSharesStatic;   ///< the "<- s" pre-message
};

// Noise revision 34, §7.5.
//
//   XX:                      IK:
//     -> e                     <- s
//     <- e, ee, s, es          ...
//     -> s, se                 -> e, es, s, ss
//                              <- e, ee, se

constexpr Token kXx0[] = { Token::E };
constexpr Token kXx1[] = { Token::E, Token::EE, Token::S, Token::ES };
constexpr Token kXx2[] = { Token::S, Token::SE };
constexpr const Token* kXxMsgs[] = { kXx0, kXx1, kXx2 };
constexpr std::uint8_t kXxLens[] = { 1, 4, 2 };

constexpr Token kIk0[] = { Token::E, Token::ES, Token::S, Token::SS };
constexpr Token kIk1[] = { Token::E, Token::EE, Token::SE };
constexpr const Token* kIkMsgs[] = { kIk0, kIk1 };
constexpr std::uint8_t kIkLens[] = { 4, 3 };

constexpr Pattern kXx{ kXxMsgs, kXxLens, 3, false };
constexpr Pattern kIk{ kIkMsgs, kIkLens, 2, true };

const Pattern& patternFor(NoisePattern p) noexcept
{
    return p == NoisePattern::IK ? kIk : kXx;
}

/// One overload, because PublicKey, SecretKey, Key and Hash are all
/// std::array<uint8_t, 32> and are therefore the same type to the compiler. The
/// distinct names are documentation for the reader, not type safety — worth
/// knowing before relying on an overload to tell them apart.
template <std::size_t N>
std::span<const std::uint8_t> asSpan(const std::array<std::uint8_t, N>& a) noexcept
{
    return std::span<const std::uint8_t>(a.data(), a.size());
}

} // namespace

const char* noiseProtocolName(NoisePattern p) noexcept
{
    // Fixed strings, not built at runtime. They are hashed into the very first
    // byte of state, so a stray character silently forks the protocol.
    return p == NoisePattern::IK ? "Noise_IK_25519_ChaChaPoly_BLAKE2s"
                                 : "Noise_XX_25519_ChaChaPoly_BLAKE2s";
}

// ---------------------------------------------------------------------------
// CipherState
// ---------------------------------------------------------------------------

void CipherState::initializeKey(const Key& k) noexcept
{
    _k      = k;
    _hasKey = true;
    _n      = 0;
}

void CipherState::clear() noexcept
{
    crypto::wipeArray(_k);
    _hasKey = false;
    _n      = 0;
}

Status CipherState::encryptWithAd(std::span<const std::uint8_t> ad,
                                  std::span<const std::uint8_t> plaintext,
                                  std::vector<std::uint8_t>& out)
{
    if (!_hasKey) {
        // Noise §5.1: with no key, EncryptWithAd returns the plaintext. This is
        // how the first handshake message travels in the clear.
        out.insert(out.end(), plaintext.begin(), plaintext.end());
        return Status::Ok;
    }

    // 2^64-1 is reserved for Rekey. Reaching it means something upstream failed
    // to rotate keys; encrypting anyway would reuse the Rekey nonce.
    if (_n == kNoiseMaxNonce) return Status::LimitExceeded;

    const Status s = crypto::aeadSeal(_k, _n, ad, plaintext, out);
    if (s != Status::Ok) return s;
    ++_n;
    return Status::Ok;
}

Status CipherState::decryptWithAd(std::span<const std::uint8_t> ad,
                                  std::span<const std::uint8_t> ciphertext,
                                  std::vector<std::uint8_t>& out)
{
    if (!_hasKey) {
        out.insert(out.end(), ciphertext.begin(), ciphertext.end());
        return Status::Ok;
    }
    if (_n == kNoiseMaxNonce) return Status::LimitExceeded;

    const Status s = crypto::aeadOpen(_k, _n, ad, ciphertext, out);
    if (s != Status::Ok) {
        // Noise §5.1: "If an authentication failure occurs in DECRYPT() then n
        // is not incremented." Advancing here would let a forged record shift
        // the stream so that the next genuine record failed too.
        return s;
    }
    ++_n;
    return Status::Ok;
}

void CipherState::rekey()
{
    if (!_hasKey) return;

    const std::uint8_t zeros[crypto::kKeyLen] = {};
    std::vector<std::uint8_t> out;
    // The reserved nonce is used exactly here and nowhere else.
    (void)crypto::aeadSeal(_k, kNoiseMaxNonce, {},
                           std::span<const std::uint8_t>(zeros, sizeof zeros), out);
    if (out.size() >= crypto::kKeyLen)
        std::memcpy(_k.data(), out.data(), crypto::kKeyLen);
    crypto::wipe(out.data(), out.size());
    // Noise is explicit that Rekey does not reset n.
}

// ---------------------------------------------------------------------------
// SymmetricState
// ---------------------------------------------------------------------------

void SymmetricState::initializeSymmetric(std::string_view protocolName)
{
    const auto* p = reinterpret_cast<const std::uint8_t*>(protocolName.data());
    const std::span<const std::uint8_t> name(p, protocolName.size());

    if (protocolName.size() <= kHashLen) {
        _h.fill(0);
        std::memcpy(_h.data(), protocolName.data(), protocolName.size());
    } else {
        _h = crypto::blake2s(name);
    }
    _ck = _h;
    _cipher.clear();
}

void SymmetricState::mixKey(std::span<const std::uint8_t> ikm)
{
    Hash newCk{}, tempK{};
    crypto::hkdf2(asSpan(_ck), ikm, newCk, tempK);
    _ck = newCk;

    Key k{};
    std::memcpy(k.data(), tempK.data(), crypto::kKeyLen);
    _cipher.initializeKey(k);

    crypto::wipeArray(tempK);
    crypto::wipeArray(k);
}

void SymmetricState::mixHash(std::span<const std::uint8_t> data)
{
    crypto::Blake2s hasher;
    hasher.update(asSpan(_h));
    hasher.update(data);
    _h = hasher.finish();
}

Status SymmetricState::encryptAndHash(std::span<const std::uint8_t> plaintext,
                                      std::vector<std::uint8_t>& out)
{
    const std::size_t at = out.size();
    const Status s = _cipher.encryptWithAd(asSpan(_h), plaintext, out);
    if (s != Status::Ok) return s;
    // The ciphertext is hashed, not the plaintext: that is what binds the
    // transcript to what actually went on the wire.
    mixHash(std::span<const std::uint8_t>(out).subspan(at));
    return Status::Ok;
}

Status SymmetricState::decryptAndHash(std::span<const std::uint8_t> ciphertext,
                                      std::vector<std::uint8_t>& out)
{
    const Status s = _cipher.decryptWithAd(asSpan(_h), ciphertext, out);
    if (s != Status::Ok) return s;
    mixHash(ciphertext);
    return Status::Ok;
}

void SymmetricState::split(CipherState& c1, CipherState& c2)
{
    Hash t1{}, t2{};
    crypto::hkdf2(asSpan(_ck), {}, t1, t2);

    Key k1{}, k2{};
    std::memcpy(k1.data(), t1.data(), crypto::kKeyLen);
    std::memcpy(k2.data(), t2.data(), crypto::kKeyLen);
    c1.initializeKey(k1);
    c2.initializeKey(k2);

    crypto::wipeArray(t1);
    crypto::wipeArray(t2);
    crypto::wipeArray(k1);
    crypto::wipeArray(k2);
}

// ---------------------------------------------------------------------------
// HandshakeState
// ---------------------------------------------------------------------------

Status HandshakeState::start(const Params& p)
{
    _pattern   = p.pattern;
    _initiator = p.initiator;
    _msgIndex  = 0;
    _complete  = false;
    _haveE     = false;
    _haveRe    = false;
    _haveRs    = false;

    _s    = p.localStatic;
    _sPub = crypto::x25519PublicKey(_s);

    const Pattern& pat = patternFor(_pattern);

    // An IK initiator must already know the responder's static; that is what
    // makes IK one round trip. Anyone else must not claim to.
    const bool needsRs = pat.responderPreSharesStatic && _initiator;
    if (needsRs && !p.hasRemoteStatic) return Status::BadArgument;
    if (!needsRs && p.hasRemoteStatic) return Status::BadArgument;

    if (needsRs) {
        _rs     = p.remoteStatic;
        _haveRs = true;
    }

    _sym.initializeSymmetric(noiseProtocolName(_pattern));
    _sym.mixHash(p.prologue);

    // Pre-messages, in the order the pattern declares them (Noise §7.1).
    // Both sides must hash the same key: the initiator hashes the responder's
    // static that it already knows, the responder hashes its own.
    if (pat.responderPreSharesStatic)
        _sym.mixHash(asSpan(_initiator ? _rs : _sPub));

    _started = true;
    return Status::Ok;
}

Status HandshakeState::setFixedEphemeralForTestingOnly(const SecretKey& e)
{
    // Refused once anything has been written or read, so it can never rescue a
    // session mid-flight — it exists only to replay published vectors.
    if (_msgIndex != 0) return Status::BadArgument;
    _fixedE    = e;
    _hasFixedE = true;
    return Status::Ok;
}

Status HandshakeState::mixDh(const SecretKey& sk, const PublicKey& pk)
{
    Key shared{};
    if (!crypto::x25519(sk, pk, shared)) {
        // A low-order point. crypto::x25519 refuses it; treat it as a failed
        // authentication rather than a transport error, because it is an attempt
        // to force a known shared secret.
        return Status::AuthFailed;
    }
    _sym.mixKey(std::span<const std::uint8_t>(shared.data(), shared.size()));
    crypto::wipeArray(shared);
    return Status::Ok;
}

Status HandshakeState::writeMessage(std::span<const std::uint8_t> payload,
                                    std::vector<std::uint8_t>& out)
{
    if (!_started || _complete) return Status::BadArgument;
    if (payload.size() > kNoiseMaxPlaintext) return Status::LimitExceeded;

    const Pattern& pat = patternFor(_pattern);
    if (_msgIndex >= pat.messageCount) return Status::BadArgument;

    // Even-numbered messages are the initiator's.
    const bool ourTurn = ((_msgIndex % 2) == 0) == _initiator;
    if (!ourTurn) return Status::BadArgument;

    const Token* toks = pat.messages[_msgIndex];
    const std::uint8_t n = pat.lengths[_msgIndex];

    for (std::uint8_t i = 0; i < n; ++i) {
        switch (toks[i]) {
            case Token::E: {
                if (_hasFixedE) {
                    _e = _fixedE;
                } else {
                    SecretKey sk{};
                    PublicKey pk{};
                    crypto::x25519KeyPair(sk, pk);
                    _e = sk;
                }
                _ePub  = crypto::x25519PublicKey(_e);
                _haveE = true;
                out.insert(out.end(), _ePub.begin(), _ePub.end());
                _sym.mixHash(asSpan(_ePub));
                break;
            }
            case Token::S: {
                if (const Status s = _sym.encryptAndHash(asSpan(_sPub), out); s != Status::Ok)
                    return s;
                break;
            }
            case Token::EE:
                if (!_haveE || !_haveRe) return Status::Internal;
                if (const Status s = mixDh(_e, _re); s != Status::Ok) return s;
                break;
            case Token::ES:
                // "es" is DH(initiator's e, responder's s), named from the
                // initiator's point of view. Both sides must reach the same
                // secret from opposite halves.
                if (_initiator) {
                    if (!_haveE || !_haveRs) return Status::Internal;
                    if (const Status s = mixDh(_e, _rs); s != Status::Ok) return s;
                } else {
                    if (!_haveRe) return Status::Internal;
                    if (const Status s = mixDh(_s, _re); s != Status::Ok) return s;
                }
                break;
            case Token::SE:
                if (_initiator) {
                    if (!_haveRe) return Status::Internal;
                    if (const Status s = mixDh(_s, _re); s != Status::Ok) return s;
                } else {
                    if (!_haveE || !_haveRs) return Status::Internal;
                    if (const Status s = mixDh(_e, _rs); s != Status::Ok) return s;
                }
                break;
            case Token::SS:
                if (!_haveRs) return Status::Internal;
                if (const Status s = mixDh(_s, _rs); s != Status::Ok) return s;
                break;
        }
    }

    if (const Status s = _sym.encryptAndHash(payload, out); s != Status::Ok) return s;
    if (out.size() > kNoiseMaxMessage) return Status::LimitExceeded;

    ++_msgIndex;
    if (_msgIndex >= pat.messageCount) _complete = true;
    return Status::Ok;
}

Status HandshakeState::readMessage(std::span<const std::uint8_t> message,
                                   std::vector<std::uint8_t>& payloadOut)
{
    if (!_started || _complete) return Status::BadArgument;
    if (message.size() > kNoiseMaxMessage) return Status::LimitExceeded;

    const Pattern& pat = patternFor(_pattern);
    if (_msgIndex >= pat.messageCount) return Status::BadArgument;

    const bool ourTurn = ((_msgIndex % 2) == 0) != _initiator;
    if (!ourTurn) return Status::BadArgument;

    const Token* toks = pat.messages[_msgIndex];
    const std::uint8_t n = pat.lengths[_msgIndex];

    std::size_t at = 0;
    for (std::uint8_t i = 0; i < n; ++i) {
        switch (toks[i]) {
            case Token::E: {
                // Every length is checked against the bytes actually present
                // before any are read. A handshake message is peer-supplied and
                // arrives before anything is authenticated.
                if (message.size() - at < kDhLen) return Status::MalformedFrame;
                std::memcpy(_re.data(), message.data() + at, kDhLen);
                at += kDhLen;
                _haveRe = true;
                _sym.mixHash(asSpan(_re));
                break;
            }
            case Token::S: {
                const std::size_t len = _sym.hasKey() ? kDhLen + kTagLen : kDhLen;
                if (message.size() - at < len) return Status::MalformedFrame;

                std::vector<std::uint8_t> plain;
                const Status s = _sym.decryptAndHash(message.subspan(at, len), plain);
                if (s != Status::Ok) return s;
                if (plain.size() != kDhLen) return Status::MalformedFrame;

                // XX learns the remote static here. A second static in one
                // handshake would mean the pattern was mis-specified.
                if (_haveRs && _pattern == NoisePattern::XX) return Status::MalformedFrame;
                std::memcpy(_rs.data(), plain.data(), kDhLen);
                _haveRs = true;
                at += len;
                break;
            }
            case Token::EE:
                if (!_haveE || !_haveRe) return Status::Internal;
                if (const Status s = mixDh(_e, _re); s != Status::Ok) return s;
                break;
            case Token::ES:
                if (_initiator) {
                    if (!_haveE || !_haveRs) return Status::Internal;
                    if (const Status s = mixDh(_e, _rs); s != Status::Ok) return s;
                } else {
                    if (!_haveRe) return Status::Internal;
                    if (const Status s = mixDh(_s, _re); s != Status::Ok) return s;
                }
                break;
            case Token::SE:
                if (_initiator) {
                    if (!_haveRe) return Status::Internal;
                    if (const Status s = mixDh(_s, _re); s != Status::Ok) return s;
                } else {
                    if (!_haveE || !_haveRs) return Status::Internal;
                    if (const Status s = mixDh(_e, _rs); s != Status::Ok) return s;
                }
                break;
            case Token::SS:
                if (!_haveRs) return Status::Internal;
                if (const Status s = mixDh(_s, _rs); s != Status::Ok) return s;
                break;
        }
    }

    if (const Status s = _sym.decryptAndHash(message.subspan(at), payloadOut);
        s != Status::Ok)
        return s;

    ++_msgIndex;
    if (_msgIndex >= pat.messageCount) _complete = true;
    return Status::Ok;
}

const crypto::Hash& HandshakeState::handshakeHash() const noexcept
{
    return _sym.handshakeHash();
}

Status HandshakeState::split(CipherState& send, CipherState& recv)
{
    if (!_complete) return Status::BadArgument;

    CipherState c1, c2;
    _sym.split(c1, c2);

    // Noise §5.2: the first CipherState encrypts INITIATOR to responder. Both
    // peers call split() the same way and the swap happens here, so neither has
    // to remember which one it is at every send.
    if (_initiator) { send = c1; recv = c2; }
    else            { send = c2; recv = c1; }

    // The handshake keys are dead once the transport keys exist.
    crypto::wipeArray(_e);
    _haveE = false;
    return Status::Ok;
}

} // namespace airusb::protocol
