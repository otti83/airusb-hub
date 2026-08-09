#include "ImporterDataPlane.h"

#include "../core/Watchdog.h"

#include "../protocol/Codec.h"
#include "../protocol/Validate.h"

#include <cstring>

namespace airusb::session {

using namespace airusb::protocol;

ImporterDataPlane::ImporterDataPlane(transport::RecordLayer* link, const Clock* clock,
                                     const Config& cfg)
    : _link(link), _clock(clock), _cfg(cfg), _table(*clock)
{
    // Bound the reassembly arena to what admission can actually hold at once, so a
    // peer dribbling partial replies cannot grow it without bound.
    Reassembler::Limits rl;
    rl.maxTransferBytes = cfg.maxTransferBytes;
    rl.maxInFlight      = static_cast<std::uint32_t>(cfg.maxInFlight == 0 ? 1 : cfg.maxInFlight);
    rl.arenaBytes       = static_cast<std::uint64_t>(cfg.maxTransferBytes) * rl.maxInFlight;
    _reasm = Reassembler(rl);
}

Status ImporterDataPlane::submit(std::uint8_t epAddr, std::uint8_t xferType, std::uint8_t dir,
                                 std::uint32_t bufferLen, const std::uint8_t setup[8],
                                 std::span<const std::uint8_t> dataOut, std::uint32_t timeoutMs,
                                 std::uint16_t* channelOut, std::uint64_t* requestIdOut)
{
    if (!_link) return Status::TransportLost;
    if (_table.size() >= _cfg.maxInFlight) return Status::Busy;

    const std::uint16_t channel = wire::channelFor(_cfg.attachSlot, epAddr);
    const std::uint64_t rid     = _table.nextRequestId(channel);

    SubmitBody sb;
    sb.epAddr    = epAddr;
    sb.xferType  = xferType;
    sb.dir       = dir;
    sb.bufferLen = bufferLen;
    sb.timeoutMs = timeoutMs;
    if (setup) std::memcpy(sb.setup, setup, 8);

    std::vector<std::uint8_t> subBody;
    encodeSubmit(sb, subBody);

    Header base;
    base.type      = static_cast<std::uint8_t>(wire::Type::Submit);
    base.channel   = channel;
    base.attachId  = _cfg.attachId;
    base.requestId = rid;
    base.status    = 0;

    const bool isOut = (dir == static_cast<std::uint8_t>(wire::Dir::Out));
    const std::span<const std::uint8_t> outData =
        isOut ? dataOut : std::span<const std::uint8_t>{};

    const std::uint32_t maxPlain = _link->maxPlaintextBytes();
    if (maxPlain <= wire::kHeaderSize + wire::kBodySubmit) return Status::Internal;
    const std::uint32_t maxSeg = maxPlain - static_cast<std::uint32_t>(wire::kHeaderSize)
                                          - static_cast<std::uint32_t>(wire::kBodySubmit);

    // Register BEFORE the bytes go out, so a completion cannot arrive for a request
    // we are not yet tracking. The deadline is the ONLY timeout in the system: the
    // kernel has none, so if this transfer never returns, sweepDeadlines() is what
    // frees the kernel's URB instead of a D-state hang (R-C).
    OutstandingRequest req;
    req.requestId    = rid;
    req.channel      = channel;
    req.attachId     = _cfg.attachId;
    req.epAddr       = epAddr;
    req.xferType     = static_cast<XferType>(xferType);
    req.dir          = static_cast<Dir>(dir);
    req.requestedLen = bufferLen;
    req.deadline     = Deadline::afterMs(*_clock, timeoutMs);
    req.submittedNs  = _clock->nowNs();
    if (_table.add(req) != Status::Ok) return Status::Internal;   // monotonic id: unreachable

    if (const Status s = emitTransfer(base, subBody, outData, maxSeg,
            [this](std::span<const std::uint8_t> rec) { return _link->sendRecord(rec); });
        s != Status::Ok) {
        // The bytes did not all go out. Retire the request so it does not dangle;
        // the caller sees the failure and fails the URB itself.
        OutstandingRequest gone;
        (void)_table.take(channel, rid, &gone);
        return s;
    }
    (void)_link->flush();

    if (channelOut)   *channelOut   = channel;
    if (requestIdOut) *requestIdOut = rid;
    return Status::Ok;
}

Status ImporterDataPlane::clearHalt(std::uint8_t epAddr, std::uint16_t* channelOut,
                                    std::uint64_t* requestIdOut)
{
    if (channelOut)   *channelOut = 0;
    if (requestIdOut) *requestIdOut = 0;
    if (!_link) return Status::TransportLost;

    // The endpoint address is the low byte of the derived channel (§3.4), so
    // the verb carries no body: the exporter reads the endpoint out of the
    // channel it arrived on.
    const std::uint16_t channel = wire::channelFor(_cfg.attachSlot, epAddr);
    const std::uint64_t rid     = _nextVerbId++;

    Header h;
    h.type      = static_cast<std::uint8_t>(wire::Type::EpClearHalt);
    h.flags     = wire::kFlagSegFirst;
    h.channel   = channel;
    h.attachId  = _cfg.attachId;
    h.requestId = rid;
    h.bodyLen   = 0;
    h.totalLen  = 0;

    std::vector<std::uint8_t> rec;
    encodeHeader(h, rec);
    if (const Status s = _link->sendRecord(rec); s != Status::Ok) return s;
    (void)_link->flush();   // non-blocking; a full socket buffers, R-B

    PendingVerb v;
    v.epAddr = epAddr;
    // T_net_ctrl, not the URB ceiling: this is a control-plane exchange with
    // the exporter, not a transfer with a device. If it does not answer, the
    // endpoint stays halted and the guest is told so — which is recoverable —
    // rather than the bridge waiting on it for thirty seconds.
    v.deadlineNs = _clock ? _clock->nowNs() +
                            static_cast<ContinuousNs>(watchdog::kNetCtrl) * 1'000'000ull
                          : 0;
    _verbs[ReplyKey{channel, rid}] = v;

    if (channelOut)   *channelOut = channel;
    if (requestIdOut) *requestIdOut = rid;
    return Status::Ok;
}

Status ImporterDataPlane::handleCtrlAck(const Header& h, const OnVerb& onVerb)
{
    const ReplyKey key{h.channel, h.requestId};
    const auto it = _verbs.find(key);
    if (it == _verbs.end()) {
        // A CTRL_ACK for a verb we are not waiting on. Late after a timeout, or
        // a stale attach's. Dropped, not fatal — R12's rule, and the same
        // reasoning as a late transfer completion.
        return Status::Ok;
    }
    VerbCompletion vc;
    vc.channel   = h.channel;
    vc.requestId = h.requestId;
    vc.epAddr    = it->second.epAddr;
    vc.status    = static_cast<Status>(h.status);
    _verbs.erase(it);
    if (onVerb) onVerb(vc);
    return Status::Ok;
}

Status ImporterDataPlane::pump(const OnComplete& onComplete, const OnVerb& onVerb)
{
    if (!_link) return Status::TransportLost;
    (void)_link->flush();   // push whatever is buffered, non-blocking

    for (;;) {
        std::vector<std::uint8_t> in;
        const Status r = _link->receiveRecord(in);
        if (r == Status::Busy) break;          // no full record buffered right now
        if (r != Status::Ok) return r;         // fatal: TransportLost / AuthFailed / ...
        if (in.empty()) break;                 // would-block: input drained for now

        Header h;
        if (!decodeHeader(in, h)) return Status::MalformedFrame;
        if (in.size() - wire::kHeaderSize < h.bodyLen) return Status::MalformedFrame;

        switch (static_cast<wire::Type>(h.type)) {
            case wire::Type::Complete:
                if (const Status s = handleComplete(h, in, onComplete); s != Status::Ok) return s;
                break;
            case wire::Type::Data:
                if (const Status s = handleData(h, in, onComplete); s != Status::Ok) return s;
                break;
            case wire::Type::CtrlAck:
                if (const Status s = handleCtrlAck(h, onVerb); s != Status::Ok) return s;
                break;
            case wire::Type::CancelAck:
                // Informational, and deliberately not acted on. The transfer it
                // refers to was retired locally the instant `cancel()` was
                // called — that is what keeps a guest URB from ever waiting on
                // the network — so there is nothing left here for the count to
                // change. It is decoded rather than ignored only so that a
                // future diagnostic can report "the exporter stopped 0 of 1",
                // which is the honest and useful thing to say when a backend
                // could not abort a transfer already on the bus.
                break;
            case wire::Type::Error:
                // We send SUBMIT, DATA and EP_CLEAR_HALT, all supported, so a
                // protocol-level ERROR means the session is broken. Surface it as
                // fatal; the caller then drains with completeAll() so I1 holds.
                return static_cast<Status>(h.status) == Status::Ok
                           ? Status::MalformedFrame : static_cast<Status>(h.status);
            default:
                // Control-plane traffic (PONG, DEVICE_GONE, keepalive) belongs to
                // the session/bridge above, not here. v1 skips it; wiring a control
                // sink is part of the bridge integration.
                break;
        }
    }
    (void)_link->flush();
    return Status::Ok;
}

Status ImporterDataPlane::handleComplete(const Header& h, const std::vector<std::uint8_t>& rec,
                                         const OnComplete& onComplete)
{
    const auto rbody = std::span<const std::uint8_t>(rec).subspan(wire::kHeaderSize, h.bodyLen);
    CompleteBody cb;
    if (!decodeComplete(rbody, cb)) return Status::MalformedFrame;

    Limits lim;
    lim.maxRecordBytes   = _link->maxRecordBytes();
    lim.maxTransferBytes = _cfg.maxTransferBytes;
    const auto firstChunk = rbody.subspan(wire::kBodyComplete);
    if (auto v = validateComplete(h, cb, firstChunk, lim); !v.ok()) return v.status;

    // Is this for a transfer we still hold? A completion for an unknown request_id
    // is the EXPECTED outcome of a cancel racing a completion — drop it, not fatal.
    // Read it NON-destructively: every request-relative check runs BEFORE take(), so
    // a completion that fails validation stays in the table and teardown can still
    // retire it. Taking it first and then failing would evaporate it from I1.
    OutstandingRequest req;
    if (!_table.get(h.channel, h.requestId, req)) return Status::Ok;

    // Redundant-identity defense (response confusion / URB aliasing). The COMPLETE
    // echoes the transfer's attach, endpoint, type, direction and requested length
    // precisely so a stale or misrouted reply — e.g. a delayed completion from a
    // PREVIOUS attach that reused this (channel, request_id) — cannot be applied to
    // the wrong URB. Every echoed field must equal the request we are holding, or the
    // bytes could land in the wrong kernel buffer. Non-destructive: a mismatch leaves
    // the request in the table for teardown.
    if (h.attachId     != req.attachId
        || cb.epAddr   != req.epAddr
        || cb.xferType != static_cast<std::uint8_t>(req.xferType)
        || cb.dir      != static_cast<std::uint8_t>(req.dir)
        || cb.requestedLen != req.requestedLen)
        return Status::MalformedFrame;

    // R5 at the copy site: a completion can never claim more than we offered.
    if (cb.actualLen > req.requestedLen) return Status::MalformedFrame;

    if (!h.segMore()) {
        std::span<const std::uint8_t> payload;
        if (req.dir == Dir::In) {
            if (cb.payloadLen > req.requestedLen) return Status::MalformedFrame;
            if (cb.payloadLen > firstChunk.size()) return Status::MalformedFrame;
            payload = firstChunk.first(cb.payloadLen);
        }
        (void)_table.take(h.channel, h.requestId, &req);   // validated — now retire it
        deliver(req, static_cast<Status>(h.status), cb.actualLen, cb.isShort(), payload, onComplete);
        return Status::Ok;
    }

    // A segmented reply: stash the metadata and begin reassembly. The request stays
    // in the table, so its deadline still guards a reply that stalls half-sent.
    PendingReply pr;
    pr.status    = static_cast<Status>(h.status);
    pr.actualLen = cb.actualLen;
    pr.shortXfer = cb.isShort();
    _pendingReply[ReplyKey{h.channel, h.requestId}] = pr;

    Status e = Status::Ok;
    if (_reasm.accept(h, firstChunk, e) == Reassembler::Outcome::Rejected) {
        drop(h.channel, h.requestId);
        return e;   // the reply framing is broken -> fatal
    }
    return Status::Ok;
}

Status ImporterDataPlane::handleData(const Header& h, const std::vector<std::uint8_t>& rec,
                                     const OnComplete& onComplete)
{
    Limits lim;
    lim.maxRecordBytes   = _link->maxRecordBytes();
    lim.maxTransferBytes = _cfg.maxTransferBytes;
    if (auto v = validateHeader(h, rec.size() - wire::kHeaderSize, lim); !v.ok()) return v.status;

    const auto pit = _pendingReply.find(ReplyKey{h.channel, h.requestId});
    if (pit == _pendingReply.end())
        return Status::MalformedFrame;   // a DATA continuation with no reply in progress

    // A continuation must belong to the same attach as the record-0 COMPLETE that
    // opened this reassembly (whose identity was already verified). This blocks a
    // spoofed continuation from injecting bytes into a legitimate reply.
    if (OutstandingRequest req; _table.get(h.channel, h.requestId, req) && h.attachId != req.attachId)
        return Status::MalformedFrame;

    const auto dbody = std::span<const std::uint8_t>(rec).subspan(wire::kHeaderSize, h.bodyLen);
    Status e = Status::Ok;
    const Reassembler::Outcome o = _reasm.accept(h, dbody, e);
    if (o == Reassembler::Outcome::Rejected) {
        drop(h.channel, h.requestId);
        return e;
    }
    if (o == Reassembler::Outcome::NeedMore) return Status::Ok;

    // Complete. Validate against the outstanding request BEFORE retiring it, so a
    // malformed reply cannot pull it out of I1 tracking.
    OutstandingRequest req;
    const bool have = _table.get(h.channel, h.requestId, req);
    std::vector<std::uint8_t> full = _reasm.take(h);
    const PendingReply pr = pit->second;
    _pendingReply.erase(pit);

    if (!have) return Status::Ok;                                  // deadline fired mid-reassembly
    if (pr.actualLen > req.requestedLen) return Status::MalformedFrame;   // req stays in table

    (void)_table.take(h.channel, h.requestId, &req);
    const std::span<const std::uint8_t> payload =
        (req.dir == Dir::In) ? std::span<const std::uint8_t>(full)
                             : std::span<const std::uint8_t>{};
    deliver(req, pr.status, pr.actualLen, pr.shortXfer, payload, onComplete);
    return Status::Ok;
}

void ImporterDataPlane::sweepDeadlines(const OnComplete& onComplete, const OnVerb& onVerb)
{
    for (const OutstandingRequest& req : _table.expired()) {
        // A reply that had partially arrived is discarded: the transfer is over.
        _pendingReply.erase(ReplyKey{req.channel, req.requestId});
        _reasm.forget(req.channel, req.requestId);
        deliver(req, Status::XferTimeout, 0, false, {}, onComplete);
    }

    // Verbs have their own, shorter deadline. A stall recovery that never gets
    // its acknowledgement must be reported, not waited on: the guest is told
    // the clear failed, which it can act on, instead of the bridge holding an
    // endpoint callback open across a dead network.
    if (_clock) {
        const ContinuousNs now = _clock->nowNs();
        for (auto it = _verbs.begin(); it != _verbs.end();) {
            if (it->second.deadlineNs != 0 && now >= it->second.deadlineNs) {
                VerbCompletion vc;
                vc.channel   = it->first.first;
                vc.requestId = it->first.second;
                vc.epAddr    = it->second.epAddr;
                vc.status    = Status::XferTimeout;
                it = _verbs.erase(it);
                if (onVerb) onVerb(vc);
            } else {
                ++it;
            }
        }
    }
}

bool ImporterDataPlane::cancel(std::uint16_t channel, std::uint64_t requestId)
{
    OutstandingRequest gone;
    const bool was = _table.take(channel, requestId, &gone);
    _pendingReply.erase(ReplyKey{channel, requestId});
    _reasm.forget(channel, requestId);

    // Tell the exporter, which used to be missing entirely.
    //
    // Retiring the local record is what the KERNEL needs — the guest's URB gets
    // its terminal outcome immediately and never waits on the network, which is
    // the rule that keeps a dead link from wedging the USB stack. But it is only
    // half the transaction: without a CANCEL on the wire, the exporter goes on
    // driving a transfer nobody is waiting for, holds that endpoint's slot while
    // it does, and eventually answers a request id that no longer exists. On a
    // depth-1 endpoint that is every subsequent transfer queued behind a ghost.
    //
    // BEST EFFORT, and deliberately so: the local retirement above has already
    // happened and is not conditional on this reaching anybody. A send failure
    // here means the link is dying, and the link dying is already handled.
    if (was && _link) {
        protocol::CancelBody cb;
        cb.targetRequestId = requestId;
        cb.epAddr          = gone.epAddr;
        cb.scope           = static_cast<std::uint8_t>(protocol::CancelScope::Request);

        std::vector<std::uint8_t> body;
        protocol::encodeCancel(cb, body);

        protocol::Header h;
        h.type      = static_cast<std::uint8_t>(wire::Type::Cancel);
        // EXPEDITE, because a cancel that queues behind the very transfers it is
        // trying to stop is a cancel that arrives after they finish.
        h.flags     = wire::kFlagSegFirst | wire::kFlagExpedite;
        h.channel   = channel;
        h.attachId  = _cfg.attachId;
        h.requestId = requestId;
        h.bodyLen   = static_cast<std::uint32_t>(body.size());
        h.totalLen  = 0;

        std::vector<std::uint8_t> rec;
        protocol::encodeHeader(h, rec);
        rec.insert(rec.end(), body.begin(), body.end());
        (void)_link->sendRecord(rec);
        (void)_link->flush();
    }
    return was;
}

void ImporterDataPlane::completeAll(Status with, const OnComplete& onComplete,
                                    const OnVerb& onVerb)
{
    const std::vector<OutstandingRequest> drained = _table.takeAttach(_cfg.attachId);
    _pendingReply.clear();
    _reasm.clear();
    for (const OutstandingRequest& req : drained)
        deliver(req, with, 0, false, {}, onComplete);

    // Verbs too, or invariant I1 has a hole in it: a caller waiting on a stall
    // recovery would never hear anything after a teardown, and an endpoint
    // callback held open across a dead session is exactly what this design
    // exists to make impossible.
    auto verbs = std::move(_verbs);
    _verbs.clear();
    for (const auto& [key, v] : verbs) {
        VerbCompletion vc;
        vc.channel   = key.first;
        vc.requestId = key.second;
        vc.epAddr    = v.epAddr;
        vc.status    = with;
        if (onVerb) onVerb(vc);
    }
}

void ImporterDataPlane::deliver(const OutstandingRequest& req, Status status,
                                std::uint32_t actualLen, bool shortXfer,
                                std::span<const std::uint8_t> data, const OnComplete& onComplete)
{
    DataCompletion c;
    c.channel      = req.channel;
    c.requestId    = req.requestId;
    c.epAddr       = req.epAddr;
    c.dir          = req.dir;
    c.status       = status;
    c.requestedLen = req.requestedLen;
    c.actualLen    = actualLen;
    c.shortXfer    = shortXfer;
    c.data         = data;
    if (onComplete) onComplete(c);
}

void ImporterDataPlane::drop(std::uint16_t channel, std::uint64_t requestId)
{
    OutstandingRequest gone;
    (void)_table.take(channel, requestId, &gone);
    _pendingReply.erase(ReplyKey{channel, requestId});
    _reasm.forget(channel, requestId);
}

} // namespace airusb::session
