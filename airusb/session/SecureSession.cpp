#include "SecureSession.h"

#include "../transport/NoiseCipher.h"

#include <cstring>

namespace airusb::session {

using protocol::NoisePattern;

namespace {

/// XX is three messages, IK is two.
std::uint8_t messageCount(NoisePattern p) noexcept
{
    return p == NoisePattern::IK ? 2u : 3u;
}

/// Which handshake messages carry our identity payload.
///
///   XX:  -> e                    (nothing to say yet)
///        <- e, ee, s, es         responder's static travels here
///        -> s, se                initiator's static travels here
///
///   IK:  -> e, es, s, ss         initiator's static travels here
///        <- e, ee, se            responder is already known to the initiator,
///                                but still sends its identity so the initiator
///                                can verify the binding for the key it pinned
bool carriesIdentity(NoisePattern p, std::uint8_t msgIndex) noexcept
{
    if (p == NoisePattern::IK) return msgIndex == 0 || msgIndex == 1;
    return msgIndex == 1 || msgIndex == 2;
}

} // namespace

std::vector<std::uint8_t> buildPrologue(std::span<const std::uint8_t> initiatorPreamble,
                                        std::span<const std::uint8_t> responderPreamble)
{
    std::vector<std::uint8_t> p;
    p.reserve(initiatorPreamble.size() + responderPreamble.size());
    p.insert(p.end(), initiatorPreamble.begin(), initiatorPreamble.end());
    p.insert(p.end(), responderPreamble.begin(), responderPreamble.end());
    return p;
}

// ---------------------------------------------------------------------------

Status SecureSession::fail(Status s, std::string why)
{
    _state = State::Failed;
    _why   = std::move(why);
    _trust = Trust::Unknown;
    return s;
}

Status SecureSession::begin(std::unique_ptr<transport::IByteStream> stream,
                            const Config& cfg)
{
    if (_state != State::Idle) return Status::BadArgument;
    if (!stream) return fail(Status::BadArgument, "no byte stream");
    if (!cfg.identity) return fail(Status::BadArgument, "no local identity");

    _stream = std::move(stream);
    _cfg    = cfg;

    // ---- decide the pattern ------------------------------------------------
    //
    // IK needs the responder's static key in advance, which we only have if the
    // peer is pinned. Everyone else, and every responder, starts from XX and
    // learns the pattern from the initiator's preamble.
    _pattern = NoisePattern::XX;
    crypto::PublicKey remoteNoise{};
    bool haveRemoteNoise = false;

    if (cfg.initiator && cfg.hasExpectedPeer && cfg.peers) {
        if (const PinnedPeer* p = cfg.peers->find(cfg.expectedPeer); p != nullptr) {
            remoteNoise     = p->noiseKey;
            haveRemoteNoise = true;
            _pattern        = NoisePattern::IK;
        }
    }

    // ---- our preamble ------------------------------------------------------
    protocol::Preamble pre;
    pre.wireMajor = wire::kWireMajor;
    pre.wireMinor = wire::kWireMinor;
    pre.flags  = wire::kSecNoiseXX;
    if (_pattern == NoisePattern::IK) pre.flags |= wire::kSecNoiseIK;

    _ourPreamble.clear();
    protocol::encodePreamble(pre, _ourPreamble);

    const transport::IoResult w = _stream->write(_ourPreamble);
    if (w.status != Status::Ok || w.bytes != _ourPreamble.size())
        return fail(Status::TransportLost, "could not send the preamble");

    // The handshake state cannot start until the prologue is known, and the
    // prologue needs the peer's preamble. So only the pattern is settled here.
    (void)remoteNoise;
    (void)haveRemoteNoise;
    _state = State::AwaitingPreamble;
    return Status::Busy;
}

Status SecureSession::readPeerPreamble()
{
    // Read up to exactly the preamble size and no further: the bytes after it
    // belong to the record layer, which has not been created yet.
    while (_theirPreamble.size() < wire::kPreambleSize) {
        std::uint8_t byte = 0;
        const transport::IoResult r = _stream->read(std::span<std::uint8_t>(&byte, 1));
        if (r.status != Status::Ok) return Status::TransportLost;
        if (r.bytes == 0) return Status::Busy;
        _theirPreamble.push_back(byte);
    }

    protocol::Preamble theirs;
    if (!protocol::decodePreamble(_theirPreamble, theirs))
        return fail(Status::MalformedFrame, "the peer's preamble is not AirUSB");

    // §3.13: wire_major governs framing and the security suite. A mismatch is
    // unrecoverable and closes immediately — there is nothing to negotiate,
    // because we would not be able to parse what came next.
    if (theirs.wireMajor != wire::kWireMajor)
        return fail(Status::UnsupportedVersion,
                    "peer speaks wire major " + std::to_string(theirs.wireMajor) +
                    ", this build speaks " + std::to_string(wire::kWireMajor));

    if ((theirs.flags & wire::kSecNoiseXX) == 0)
        return fail(Status::UnsupportedVersion,
                    "peer did not offer Noise; SEC_NOISE_XX is mandatory on TCP");

    // ---- settle the pattern -------------------------------------------------
    //
    // The initiator chose; the responder obeys. If they disagree the handshake
    // will fail on the first MAC, which is the correct outcome — but catching it
    // here gives a legible reason instead of a bare AuthFailed.
    if (!_cfg.initiator) {
        _pattern = (theirs.flags & wire::kSecNoiseIK) ? NoisePattern::IK
                                                          : NoisePattern::XX;
    } else {
        const bool peerEchoedIk = (theirs.flags & wire::kSecNoiseIK) != 0;
        (void)peerEchoedIk;   // responders do not echo it; nothing to check
    }

    // ---- prologue ------------------------------------------------------------
    const std::vector<std::uint8_t> prologue =
        _cfg.initiator ? buildPrologue(_ourPreamble, _theirPreamble)
                       : buildPrologue(_theirPreamble, _ourPreamble);

    protocol::HandshakeState::Params hp;
    hp.pattern     = _pattern;
    hp.initiator   = _cfg.initiator;
    hp.prologue    = prologue;
    hp.localStatic = _cfg.identity->noiseSecret();

    if (_pattern == NoisePattern::IK && _cfg.initiator) {
        if (!_cfg.hasExpectedPeer || !_cfg.peers)
            return fail(Status::Internal, "IK chosen without a pinned peer");
        const PinnedPeer* p = _cfg.peers->find(_cfg.expectedPeer);
        if (!p) return fail(Status::Internal, "IK chosen but the pin vanished");
        hp.remoteStatic    = p->noiseKey;
        hp.hasRemoteStatic = true;
    }

    if (const Status s = _hs.start(hp); s != Status::Ok)
        return fail(s, "could not start the handshake");

    // Pre-handshake records are capped at 8 KiB (R1) and are NOT encrypted —
    // a Noise handshake message is its own protection. NullCipher here is
    // correct rather than a stand-in, and it is replaced the moment the
    // handshake produces real keys.
    _record = std::make_unique<transport::RecordLayer>(
        std::move(_stream), std::make_unique<transport::NullCipher>());

    _state = State::Handshaking;
    return Status::Ok;
}

Status SecureSession::driveHandshake()
{
    const std::uint8_t total = messageCount(_pattern);

    while (_msgIndex < total) {
        const bool oursToSend = ((_msgIndex % 2) == 0) == _cfg.initiator;

        if (oursToSend) {
            std::vector<std::uint8_t> payload;
            if (carriesIdentity(_pattern, _msgIndex))
                crypto::encodeIdentityPayload(*_cfg.identity, payload);

            std::vector<std::uint8_t> msg;
            if (const Status s = _hs.writeMessage(payload, msg); s != Status::Ok)
                return fail(s, "could not write handshake message " +
                               std::to_string(_msgIndex));

            if (const Status s = _record->sendRecord(msg); s != Status::Ok)
                return fail(s, "could not queue handshake message");
            if (const Status s = _record->flush(); s != Status::Ok)
                return fail(s, "could not send handshake message");

            ++_msgIndex;
            continue;
        }

        std::vector<std::uint8_t> msg;
        const Status r = _record->receiveRecord(msg);
        if (r == Status::Ok && msg.empty()) return Status::Busy;   // nothing yet
        if (r != Status::Ok) {
            if (r == Status::Busy) return Status::Busy;
            return fail(r, "could not read handshake message");
        }

        std::vector<std::uint8_t> payload;
        if (const Status s = _hs.readMessage(msg, payload); s != Status::Ok)
            return fail(s, "handshake message " + std::to_string(_msgIndex) +
                           " did not authenticate");

        if (carriesIdentity(_pattern, _msgIndex)) {
            // THE check. The binding is verified against the static key the
            // handshake negotiated, never one carried in the payload — see
            // crypto/Identity.h. Without this, Noise would prove only that the
            // peer holds SOME key.
            if (!_hs.haveRemoteStatic())
                return fail(Status::Internal, "no remote static after an identity message");
            if (!crypto::decodeAndVerifyIdentityPayload(payload, _hs.remoteStatic(), _peer))
                return fail(Status::AuthFailed,
                            "the peer's identity does not bind to the key it used");
        }

        ++_msgIndex;
    }

    return finish();
}

Status SecureSession::finish()
{
    if (!_hs.complete()) return fail(Status::Internal, "handshake ended incomplete");

    // Every pattern we speak carries both identities. A completed handshake with
    // no verified peer identity means a payload was missed, which would leave an
    // unauthenticated session looking established.
    static const crypto::PublicKey kZero{};
    if (_peer.identityKey == kZero)
        return fail(Status::AuthFailed, "the peer never presented an identity");

    _channelBinding = _hs.handshakeHash();
    _sas            = crypto::sasDigits(_channelBinding);

    protocol::CipherState send, recv;
    if (const Status s = _hs.split(send, recv); s != Status::Ok)
        return fail(s, "could not derive transport keys");

    // The last handshake record is already flushed, so the swap is safe.
    //
    // The record size stays at the PRE-HELLO ceiling here, not at whatever this
    // build prefers. Adopting our own preference before the peer has said
    // anything is what let two builds that disagreed complete a handshake and
    // then fail on a record one of them thought was legal.
    if (const Status s = _record->adoptCipher(
            std::make_unique<transport::NoiseCipher>(send, recv),
            wire::kHandshakeRecordMax);
        s != Status::Ok)
        return fail(s, "could not install the transport cipher");

    // ---- the trust gate ------------------------------------------------------
    //
    // Authenticated is not authorised. An unpinned peer reaches Unpaired, where
    // §3.14 permits only PAIR_*/PING/GOODBYE. There is no "the LAN is trusted".
    _trust  = Trust::Unpaired;
    _grants = 0;
    if (_cfg.peers) {
        if (const PinnedPeer* p = _cfg.peers->find(_peer.identityKey); p != nullptr) {
            // An IK session additionally proves the peer still holds the exact
            // static we pinned, because the handshake would not have completed
            // otherwise.
            _trust  = Trust::Paired;
            _grants = p->grants;
        }
    }

    // Encrypted and authenticated, and NOT yet usable. `established()` stays
    // false until the two ends have agreed their limits.
    _state = State::Greeting;
    return driveGreeting();
}

// ---------------------------------------------------------------------------
// HELLO
// ---------------------------------------------------------------------------

Status SecureSession::sendHello(wire::Type type, const Negotiated* agreed)
{
    protocol::HelloBody h;
    h.protoMin      = wire::kProtoVersionV1;
    h.protoMax      = wire::kProtoVersionV1;
    // Segmentation is added unconditionally and is not a preference: a peer
    // that cannot segment cannot carry a 1 MiB URB, and finding that out on the
    // first real transfer instead of at the greeting is the whole failure mode
    // this exchange exists to remove.
    h.caps          = _cfg.capabilities | wire::kCapSegmentation;
    h.maxTransfer   = agreed ? agreed->maxTransferBytes : _cfg.maxTransferBytes;
    h.maxRecord     = agreed ? agreed->maxRecordBytes   : _cfg.negotiatedMaxRecordBytes;
    h.maxSegment    = h.maxRecord;
    h.maxIsoPackets = 0;                     // v1 carries no isochronous transfers
    h.maxChannels   = static_cast<std::uint16_t>(wire::kMaxChannels);
    h.maxLinks      = 1;
    h.keepaliveMs   = agreed ? agreed->keepaliveMs : _cfg.keepaliveMs;
#if defined(__APPLE__)
    h.platformId    = wire::kPlatformMacos;
#elif defined(_WIN32)
    h.platformId    = wire::kPlatformWindows;
#else
    h.platformId    = wire::kPlatformLinux;
#endif
    h.roleBits      = _cfg.roleBits;
    if (agreed) h.caps = agreed->capabilities;

    // The session id binds this greeting to this handshake. Taken from the
    // channel binding rather than generated, so it cannot be replayed into a
    // different session: an attacker who records a HELLO has one that only
    // matches the handshake it came from.
    std::memcpy(h.sessionId, _channelBinding.data(), wire::kSessionIdBytes);

    std::vector<std::uint8_t> body;
    protocol::encodeHello(h, body);

    protocol::Header hdr;
    hdr.type     = static_cast<std::uint8_t>(type);
    hdr.flags    = wire::kFlagSegFirst;
    hdr.bodyLen  = static_cast<std::uint32_t>(body.size());
    hdr.totalLen = 0;

    std::vector<std::uint8_t> rec;
    protocol::encodeHeader(hdr, rec);
    rec.insert(rec.end(), body.begin(), body.end());

    if (const Status s = _record->sendRecord(rec); s != Status::Ok) return s;
    return _record->flush();
}

Status SecureSession::applyNegotiated()
{
    if (const Status s = _record->adoptRecordSize(_negotiated.maxRecordBytes);
        s != Status::Ok)
        return fail(s, "the agreed record size is not one this build can use");
    _state = State::Established;
    return Status::Ok;
}

Status SecureSession::driveGreeting()
{
    // The INITIATOR speaks first and adopts what comes back. The RESPONDER
    // computes the agreement. One side deciding removes the tie-break question
    // entirely, and the alternative — both computing it — is two
    // implementations of one rule that must never disagree.
    if (_cfg.initiator && !_helloSent) {
        if (const Status s = sendHello(wire::Type::Hello, nullptr); s != Status::Ok)
            return fail(s, "could not send HELLO");
        _helloSent = true;
    }

    std::vector<std::uint8_t> rec;
    const Status r = _record->receiveRecord(rec);
    if (r == Status::Busy) return Status::Busy;
    if (r != Status::Ok) return fail(r, "the peer did not complete the greeting");
    if (rec.empty()) return Status::Busy;

    protocol::Header hdr;
    if (!protocol::decodeHeader(rec, hdr))
        return fail(Status::MalformedFrame, "unparseable greeting");
    if (rec.size() - wire::kHeaderSize < hdr.bodyLen)
        return fail(Status::MalformedFrame, "greeting shorter than declared");

    const auto want = _cfg.initiator ? wire::Type::HelloOk : wire::Type::Hello;
    if (hdr.type != static_cast<std::uint8_t>(want))
        return fail(Status::MalformedFrame, "the peer said something other than hello");

    protocol::HelloBody peer;
    if (!protocol::decodeHello(
            std::span<const std::uint8_t>(rec).subspan(wire::kHeaderSize, hdr.bodyLen),
            peer))
        return fail(Status::MalformedFrame, "malformed HELLO");

    // Version fixes semantics and is REFUSED rather than negotiated. A peer
    // outside our range is not accommodated, because what a message means is
    // not a number to split the difference on.
    if (peer.protoMax < wire::kProtoVersionV1 || peer.protoMin > wire::kProtoVersionV1)
        return fail(Status::UnsupportedVersion,
                    "the other machine speaks a different version of this protocol");

    // The session id must be THIS handshake's. A greeting replayed from another
    // session is refused here rather than becoming a session with somebody
    // else's agreed limits.
    if (std::memcmp(peer.sessionId, _channelBinding.data(), wire::kSessionIdBytes) != 0)
        return fail(Status::AuthFailed, "the greeting does not belong to this session");

    if ((peer.caps & wire::kCapSegmentation) == 0)
        return fail(Status::UnsupportedVersion,
                    "the other machine cannot split large transfers, so it cannot "
                    "carry a real USB device");

    if (peer.maxRecord < wire::kRecordBytesFloor ||
        peer.maxRecord > wire::kRecordBytesCeiling)
        return fail(Status::LimitExceeded, "the peer proposed an illegal record size");

    if (_cfg.initiator) {
        // The responder already computed the agreement; adopt it verbatim
        // rather than recomputing, so there is exactly one answer.
        _negotiated.maxRecordBytes   = peer.maxRecord;
        _negotiated.maxTransferBytes = peer.maxTransfer;
        _negotiated.capabilities     = peer.caps;
        _negotiated.keepaliveMs      = peer.keepaliveMs;
        _negotiated.peerRoleBits     = peer.roleBits;
        _negotiated.peerPlatform     = peer.platformId;
        return applyNegotiated();
    }

    // Responder: minimum for sizes, intersection for capabilities.
    const auto minU32 = [](std::uint32_t a, std::uint32_t b) { return a < b ? a : b; };
    _negotiated.maxRecordBytes   = minU32(_cfg.negotiatedMaxRecordBytes, peer.maxRecord);
    _negotiated.maxTransferBytes = minU32(_cfg.maxTransferBytes, peer.maxTransfer);
    _negotiated.capabilities     = (_cfg.capabilities | wire::kCapSegmentation) & peer.caps;
    // Keepalive is the FASTER of the two, not the slower: each side is saying
    // how often it needs to hear from the other to believe the link is alive,
    // and honouring the slower one would leave the impatient side declaring a
    // healthy peer dead.
    _negotiated.keepaliveMs      = _cfg.keepaliveMs < peer.keepaliveMs
                                       ? _cfg.keepaliveMs : peer.keepaliveMs;
    _negotiated.peerRoleBits     = peer.roleBits;
    _negotiated.peerPlatform     = peer.platformId;

    if (const Status s = sendHello(wire::Type::HelloOk, &_negotiated); s != Status::Ok)
        return fail(s, "could not send HELLO_OK");

    return applyNegotiated();
}

Status SecureSession::pump()
{
    switch (_state) {
        case State::Idle:
            return Status::BadArgument;

        case State::AwaitingPreamble: {
            const Status s = readPeerPreamble();
            if (s != Status::Ok) return s;
            [[fallthrough]];
        }
        case State::Handshaking:
            return driveHandshake();

        case State::Greeting:
            return driveGreeting();

        case State::Established:
            return Status::Ok;

        case State::Failed:
            return Status::AuthFailed;
    }
    return Status::Internal;
}

bool SecureSession::mayList() const noexcept
{
    return _trust == Trust::Paired && (_grants & kMayList) != 0;
}

bool SecureSession::mayAttach() const noexcept
{
    return _trust == Trust::Paired && (_grants & kMayAttach) != 0;
}

} // namespace airusb::session
