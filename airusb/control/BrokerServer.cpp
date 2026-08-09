#include "BrokerServer.h"

#include "../crypto/Identity.h"

#include <algorithm>
#include <cstring>

namespace airusb::control {

using namespace airusb::control::broker;

namespace {

/// The device list the window renders, from the side that is showing it.
void fillDevices(const std::vector<DeviceView>& in, std::vector<DeviceEntry>& out)
{
    out.clear();
    for (const DeviceView& d : in) {
        if (out.size() >= kMaxDevices) break;
        DeviceEntry e;
        e.uidHex    = d.uid;
        e.vendorId  = d.vendorId;
        e.productId = d.productId;
        e.speed     = d.speed;
        e.flags     = d.flags;
        e.name      = d.name;
        out.push_back(std::move(e));
    }
}

} // namespace

void BrokerServer::dropClient(const char* why)
{
    (void)why;
    if (_client) _client->close();
    _client.reset();
    _greeted = false;
    _peer = PeerCredentials{};
    _rx.clear();
    _tx.clear();
    _txSent = 0;
}

void BrokerServer::reply(Op op, Status st, std::uint64_t tag,
                         std::span<const std::uint8_t> body)
{
    if (!_client) return;
    encodeFrame(op, st, tag, body, _tx);
}

void BrokerServer::replyState(Op op, Status st, std::uint64_t tag, const std::string& why)
{
    StateReply s;
    // Rendered HERE, by the authority, and relayed unchanged. See HubFacade.h
    // for why the window must not have a second opinion about what is true.
    s.json        = _hub.stateJson();
    s.error       = why;
    s.shareState  = static_cast<std::uint8_t>(_hub.shareState());
    s.importState = static_cast<std::uint8_t>(_hub.importState());
    s.sharePort   = _hub.sharePort();

    // The nonce travels WITH the digits and the fingerprint, always as one
    // reply. A window that could read them from three separate calls could
    // render a mixture of two moments, and the whole ceremony rests on the
    // person answering the question they were actually shown.
    s.shareSas             = _hub.shareSas();
    s.shareNonce           = _hub.shareNonce();
    s.sharePeerFingerprint = _hub.sharePeerFingerprint();

    s.importSas             = _hub.importSas();
    s.importNonce           = _hub.importNonce();
    s.importPeerFingerprint = _hub.importPeerFingerprint();

    s.leaseState = static_cast<std::uint8_t>(_hub.leaseState());

    s.attached    = _hub.importState() == ImportState::Attached;
    s.attachedVia = s.attached ? _hub.presenter().statusText() : std::string{};
    s.lastRttNs   = 0;
    s.notice      = _hub.notice();

    fillDevices(_hub.offeredDevices(), s.devices);

    std::vector<std::uint8_t> body;
    encode(s, body);
    reply(op, st, tag, body);
}

int BrokerServer::poll()
{
    int did = 0;

    // 1. A window wants in.
    if (!_client) {
        PeerCredentials creds;
        if (auto c = _listener.accept(&creds)) {
            if (_cfg.enforceUid && creds.uid != _cfg.allowedUid) {
                // Refused by the kernel's answer, not by anything the peer
                // said. A privileged broker driven by the wrong account is the
                // case this whole channel exists to make impossible.
                ++_refusals;
                c->close();
                return 1;
            }
            _client = std::move(c);
            _peer   = creds;
            ++did;
        } else {
            return did;
        }
    }

    // 2. Push whatever the socket would not take last time, BEFORE reading.
    //    Same rule as the exporter: a reply left in a buffer is an answer the
    //    window is still waiting for.
    while (_txSent < _tx.size()) {
        const auto r = _client->write(std::span<const std::uint8_t>(
            _tx.data() + _txSent, _tx.size() - _txSent));
        if (r.status == Status::Busy) break;
        if (r.status != Status::Ok) { dropClient("write failed"); return did + 1; }
        _txSent += r.bytes;
        ++did;
    }
    if (_txSent == _tx.size() && !_tx.empty()) { _tx.clear(); _txSent = 0; }

    // 3. Read whatever is there right now.
    for (;;) {
        std::uint8_t buf[4096];
        const auto r = _client->read(std::span<std::uint8_t>(buf, sizeof buf));
        if (r.status == Status::Busy) break;
        if (r.status != Status::Ok) { dropClient("the window closed"); return did + 1; }
        if (r.bytes == 0) break;
        _rx.insert(_rx.end(), buf, buf + r.bytes);
        ++did;
        // Bounded: a window that streams garbage cannot make the broker grow a
        // buffer without limit. One frame's worth of slack is the cap.
        if (_rx.size() > kMaxBodyBytes + kHeaderSize * 4) {
            dropClient("the window sent more than a frame's worth of nonsense");
            return did;
        }
    }

    // 4. Answer every complete frame.
    std::size_t at = 0;
    while (at < _rx.size()) {
        FrameHeader h;
        std::span<const std::uint8_t> body;
        std::size_t consumed = 0;
        const Status ps = parseFrame(
            std::span<const std::uint8_t>(_rx.data() + at, _rx.size() - at),
            h, body, consumed);
        if (ps == Status::Busy) break;
        if (ps != Status::Ok) {
            // A length prefix that does not make sense cannot be resynchronised
            // from. Closing is the only correct move.
            dropClient("malformed frame");
            return did + 1;
        }
        handleFrame(h, body);
        at += consumed;
        ++did;
    }
    if (at > 0) _rx.erase(_rx.begin(), _rx.begin() + static_cast<std::ptrdiff_t>(at));

    // 5. And push whatever those answers produced.
    while (_client && _txSent < _tx.size()) {
        const auto r = _client->write(std::span<const std::uint8_t>(
            _tx.data() + _txSent, _tx.size() - _txSent));
        if (r.status == Status::Busy) break;
        if (r.status != Status::Ok) { dropClient("write failed"); break; }
        _txSent += r.bytes;
    }
    if (_client && _txSent == _tx.size() && !_tx.empty()) { _tx.clear(); _txSent = 0; }

    return did;
}

void BrokerServer::handleFrame(const FrameHeader& h, std::span<const std::uint8_t> bodyIn)
{
    ++_frames;
    const std::uint64_t tag = h.tag;

    if (!isKnownOp(h.op)) {
        ++_refusals;
        reply(Op::GetState, Status::UnsupportedMessage, tag, {});
        return;
    }
    const Op op = static_cast<Op>(h.op);

    // ATTACH first, always. Answering anything before the versions agree means
    // acting on an opcode whose meaning has not been established.
    if (!_greeted && op != Op::Attach) {
        ++_refusals;
        reply(op, Status::NotPermitted, tag, {});
        return;
    }

    std::string why;
    auto done = [&](Status s) { replyState(op, s, tag, s == Status::Ok ? std::string{} : why); };
    auto refuse = [&](Status s) { ++_refusals; reply(op, s, tag, {}); };

    switch (op) {
    case Op::Attach: {
        AttachRequest req;
        if (!decode(bodyIn, req)) return refuse(Status::MalformedFrame);
        if (req.version != kProtocolVersion) {
            // Refused, never negotiated: the window and the broker ship
            // together, so a skew is a botched install rather than a peer to
            // accommodate.
            return refuse(Status::UnsupportedVersion);
        }
        _greeted = true;

        AttachReply rep;
        rep.version     = kProtocolVersion;
        rep.machineName = _machineName;
        rep.fingerprint = _fingerprint;
        rep.presenter   = _hub.presenter().name();
        rep.canPresent  = _hub.presenter().canPresent();
        std::vector<std::uint8_t> out;
        encode(rep, out);
        reply(op, Status::Ok, tag, out);
        return;
    }

    case Op::GetState:
        return done(Status::Ok);

    case Op::ShareStart: {
        ShareStartRequest req;
        if (!decode(bodyIn, req)) return refuse(Status::MalformedFrame);
        return done(_hub.shareStart(req.port, &why));
    }

    case Op::ShareStop:
        if (!bodyIn.empty()) return refuse(Status::MalformedFrame);
        _hub.shareStop();
        return done(Status::Ok);

    case Op::ShareApprove:
    case Op::ImportApprove: {
        ApproveRequest req;
        if (!decode(bodyIn, req)) return refuse(Status::MalformedFrame);
        // The three checks live in HubState, not here: this is a transport, and
        // the trust decision must not have two implementations.
        const Status s = (op == Op::ShareApprove)
            ? _hub.shareApprove(req.nonce, req.fingerprint, req.sas, req.accept, &why)
            : _hub.importApprove(req.nonce, req.fingerprint, req.sas, req.accept, &why);
        if (s != Status::Ok) ++_refusals;
        return done(s);
    }

    case Op::ImportConnect: {
        ImportConnectRequest req;
        if (!decode(bodyIn, req)) return refuse(Status::MalformedFrame);
        return done(_hub.importConnect(req.host, req.port, &why));
    }

    case Op::ImportDisconnect:
        if (!bodyIn.empty()) return refuse(Status::MalformedFrame);
        _hub.importDisconnect();
        return done(Status::Ok);

    case Op::ImportRefresh:
        if (!bodyIn.empty()) return refuse(Status::MalformedFrame);
        return done(_hub.importRefresh(&why));

    case Op::ImportAttach: {
        AttachDeviceRequest req;
        if (!decode(bodyIn, req)) return refuse(Status::MalformedFrame);
        return done(_hub.importAttach(req.uidHex, &why));
    }

    case Op::ImportDetach:
        if (!bodyIn.empty()) return refuse(Status::MalformedFrame);
        return done(_hub.importDetach(&why));

    case Op::ImportVerify:
        if (!bodyIn.empty()) return refuse(Status::MalformedFrame);
        return done(_hub.importVerify(&why));

    case Op::ImportPing:
        if (!bodyIn.empty()) return refuse(Status::MalformedFrame);
        return done(_hub.importPing(&why));

    case Op::ForceReclaim:
        if (!bodyIn.empty()) return refuse(Status::MalformedFrame);
        return done(_hub.forceReclaim(&why));
    }

    refuse(Status::UnsupportedMessage);
}

} // namespace airusb::control
