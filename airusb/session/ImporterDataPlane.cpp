#include "ImporterDataPlane.h"

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

Status ImporterDataPlane::pump(const OnComplete& onComplete)
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
            case wire::Type::Error:
                // We only ever send SUBMIT and DATA, both supported, so a
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

void ImporterDataPlane::sweepDeadlines(const OnComplete& onComplete)
{
    for (const OutstandingRequest& req : _table.expired()) {
        // A reply that had partially arrived is discarded: the transfer is over.
        _pendingReply.erase(ReplyKey{req.channel, req.requestId});
        _reasm.forget(req.channel, req.requestId);
        deliver(req, Status::XferTimeout, 0, false, {}, onComplete);
    }
}

bool ImporterDataPlane::cancel(std::uint16_t channel, std::uint64_t requestId)
{
    OutstandingRequest gone;
    const bool was = _table.take(channel, requestId, &gone);
    _pendingReply.erase(ReplyKey{channel, requestId});
    _reasm.forget(channel, requestId);
    return was;
}

void ImporterDataPlane::completeAll(Status with, const OnComplete& onComplete)
{
    const std::vector<OutstandingRequest> drained = _table.takeAttach(_cfg.attachId);
    _pendingReply.clear();
    _reasm.clear();
    for (const OutstandingRequest& req : drained)
        deliver(req, with, 0, false, {}, onComplete);
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
