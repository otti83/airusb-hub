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
    if (const Status s = _record->adoptCipher(
            std::make_unique<transport::NoiseCipher>(send, recv),
            _cfg.negotiatedMaxRecordBytes);
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

    _state = State::Established;
    return Status::Ok;
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
