#include "UdecxBridge.h"

#include "../../core/Watchdog.h"
#include "../../protocol/Wire.h"

#include <cstring>
#include <utility>

namespace airusb::windows {

using namespace airusb::protocol;

namespace {

/// A plane transfer is named by (channel, requestId). Folded into one key so
/// the outstanding map is a flat hash rather than a map of pairs.
std::uint64_t planeKey(std::uint16_t channel, std::uint64_t requestId) noexcept
{
    return (static_cast<std::uint64_t>(channel) << 48) ^ (requestId & 0x0000FFFFFFFFFFFFull);
}

std::uint8_t xferTypeToWire(ipc::TransferType t) noexcept
{
    switch (t) {
        case ipc::TransferType::Control:   return static_cast<std::uint8_t>(wire::XferType::Control);
        case ipc::TransferType::Interrupt: return static_cast<std::uint8_t>(wire::XferType::Interrupt);
        case ipc::TransferType::Bulk:      break;
    }
    return static_cast<std::uint8_t>(wire::XferType::Bulk);
}

std::uint32_t timeoutFor(ipc::TransferType t) noexcept
{
    // An interrupt IN may legitimately idle for ever, and giving it a deadline
    // would abort every one of them the instant it was submitted. Control and
    // bulk get the project's URB ceiling.
    return t == ipc::TransferType::Interrupt
               ? static_cast<std::uint32_t>(watchdog::kUrbDeadlineIntr)
               : static_cast<std::uint32_t>(watchdog::kUrbCeilingBulk);
}

} // namespace

UdecxBridge::UdecxBridge(IDriverChannel& channel, session::ImporterDataPlane& plane,
                         const Config& cfg)
    : _channel(channel), _plane(plane), _cfg(cfg), _arbiter(_cfg.manifest)
{
}

bool UdecxBridge::freshEnough(std::uint32_t session, std::uint32_t device) const noexcept
{
    // The whole point of carrying two incarnations. A record from a previous
    // binding, or from before a re-plug, refers to objects that no longer exist
    // — and its request id may since have been handed to something else.
    return session == _cfg.sessionIncarnation && device == _cfg.deviceIncarnation;
}

// ---------------------------------------------------------------------------

Status UdecxBridge::poll()
{
    // 1. The driver first, and completely. Nothing in here touches the network,
    //    so every lifecycle record is answerable even while the link is wedged.
    if (const Status s = drainDriver(); s != Status::Ok) return s;

    // 2. Deadlines for transfers still queued behind a full plane. They have had
    //    a clock since the driver handed them over, not since they reached the
    //    wire, or a transfer stuck in the queue would be immortal.
    sweepQueued();

    // 3. Only now is the network touched.
    admitQueued();

    // 4. Completions and timeouts become records for the driver.
    const Status ps = pumpPlane();

    // 5. Push whatever the channel could not take. A reply left in a buffer is a
    //    URB the guest is still waiting for; this project has already paid for
    //    that lesson once, on the exporter side.
    if (_channel.pendingToDriver() != 0) (void)_channel.flush();

    return ps;
}

Status UdecxBridge::drainDriver()
{
    std::vector<std::uint8_t> rec;
    for (;;) {
        if (!_channel.tryReceive(rec)) return Status::Ok;
        handleRecord(rec);
    }
}

void UdecxBridge::handleRecord(std::span<const std::uint8_t> rec)
{
    ipc::Opcode op{};
    if (!ipc::peekOpcode(rec, op)) {
        ++_stats.malformed;
        _lastError = "a record with no usable envelope";
        return;
    }

    switch (op) {
    case ipc::Opcode::UrbRequest: {
        ipc::UrbRequest r;
        if (!ipc::decode(rec, r)) { ++_stats.malformed; _lastError = "bad UrbRequest"; return; }
        onUrbRequest(r);
        return;
    }
    case ipc::Opcode::CancelRequest: {
        ipc::CancelRequest r;
        if (!ipc::decode(rec, r)) { ++_stats.malformed; _lastError = "bad CancelRequest"; return; }
        onCancel(r);
        return;
    }
    case ipc::Opcode::Configure: {
        ipc::Configure r;
        if (!ipc::decode(rec, r)) { ++_stats.malformed; _lastError = "bad Configure"; return; }
        onConfigure(r);
        return;
    }
    // The driver never sends these; receiving one means the two ends disagree
    // about who says what, which is worth counting rather than ignoring.
    case ipc::Opcode::UrbCompletion:
    case ipc::Opcode::ConfigureResult:
    case ipc::Opcode::CancelAck:
        ++_stats.malformed;
        _lastError = "a host-to-driver opcode arrived from the driver";
        return;
    }
    ++_stats.malformed;
}

void UdecxBridge::onUrbRequest(const ipc::UrbRequest& r)
{
    ++_stats.urbsIn;

    if (!freshEnough(r.sessionIncarnation, r.deviceIncarnation)) {
        // Not an error and not forwarded: it belongs to a device that no longer
        // exists. Answering it keeps the driver's table from growing.
        ++_stats.refused;
        completeToDriver(r.requestId, ipc::Result::Disconnected, 0, {});
        return;
    }

    if (r.offeredLength > _cfg.maxTransferBytes) {
        ++_stats.refused;
        completeToDriver(r.requestId, ipc::Result::Unsupported, 0, {});
        return;
    }

    if (answerLocally(r)) return;

    Queued q;
    q.req = r;
    const std::uint32_t ms = timeoutFor(r.transferType);
    q.deadlineNs = ms == 0 || !_cfg.clock
                       ? 0
                       : _cfg.clock->nowNs() + static_cast<ContinuousNs>(ms) * 1'000'000ull;
    _queued.push_back(std::move(q));
}

bool UdecxBridge::answerLocally(const ipc::UrbRequest& r)
{
    if (r.transferType != ipc::TransferType::Control) return false;

    SetupPacket setup;
    setup.bmRequestType = r.setup[0];
    setup.bRequest      = r.setup[1];
    setup.wValue        = static_cast<std::uint16_t>(r.setup[2] | (r.setup[3] << 8));
    setup.wIndex        = static_cast<std::uint16_t>(r.setup[4] | (r.setup[5] << 8));
    setup.wLength       = static_cast<std::uint16_t>(r.setup[6] | (r.setup[7] << 8));

    const Ep0Decision d = _arbiter.decide(setup);
    if (d.disposition != Ep0Disposition::Local) return false;

    // Zero network traffic. This is the entire reason the manifest is shipped
    // before the device exists: the guest's enumeration storm never leaves the
    // machine, so it happens at memory speed rather than at LAN latency, and it
    // still returns the device's own bytes verbatim.
    ++_stats.answeredLocally;
    completeToDriver(r.requestId, ipc::Result::Ok,
                     static_cast<std::uint32_t>(d.data.size()), d.data);
    return true;
}

void UdecxBridge::onCancel(const ipc::CancelRequest& r)
{
    ++_stats.cancelled;

    // Answered NOW, before anything else, and never conditional on the network.
    // The driver has already completed the guest's URB; this only tells it that
    // nothing of ours will touch that id again, so it can retire its bookkeeping.
    ipc::CancelAck ack;
    ack.requestId          = r.requestId;
    ack.sessionIncarnation = _cfg.sessionIncarnation;
    ack.deviceIncarnation  = _cfg.deviceIncarnation;
    std::vector<std::uint8_t> out;
    ipc::encode(ack, out);
    sendRecord(out);

    retire(r.requestId);

    // Drop it from the queue if it never reached the wire.
    for (auto it = _queued.begin(); it != _queued.end(); ++it) {
        if (it->req.requestId == r.requestId) { _queued.erase(it); return; }
    }

    // Otherwise stop the plane caring about it. A completion may still arrive;
    // `_retired` is what makes it disappear quietly instead of being delivered
    // to a request the driver has finished with.
    for (auto it = _outstanding.begin(); it != _outstanding.end(); ++it) {
        if (it->second.driverRequestId != r.requestId) continue;
        // The PLANE's id, not the driver's. They are different namespaces, and
        // passing the wrong one means the plane never cancels: the bridge
        // forgets the transfer while the admission slot stays occupied, and at
        // depth 1 every later URB queues behind a transfer nobody is waiting
        // for any more.
        (void)_plane.cancel(it->second.channel, it->second.planeRequestId);
        _outstanding.erase(it);
        return;
    }
}

void UdecxBridge::onConfigure(const ipc::Configure& r)
{
    ++_stats.configures;

    ipc::ConfigureResult res;
    res.ticketId           = r.ticketId;
    res.sessionIncarnation = _cfg.sessionIncarnation;
    res.deviceIncarnation  = _cfg.deviceIncarnation;
    res.result             = ipc::Result::Failed;

    if (!freshEnough(r.sessionIncarnation, r.deviceIncarnation)) {
        res.result = ipc::Result::Disconnected;
    } else if (r.isConfiguration) {
        // No exporter in this project can change a captured device's
        // configuration (P1 §4.8: WinUSB cannot at all, and the macOS capture
        // holds the configuration it captured). Selecting the captured value is
        // a no-op and succeeds; anything else is REFUSED rather than forwarded,
        // because a guest that believes a different configuration took effect
        // builds its endpoint table from descriptors the device is not using.
        if (r.configurationValue == _cfg.capturedConfig) {
            _arbiter.commitVerb(Ep0Verb::SetConfiguration, r.configurationValue, 0);
            res.result = ipc::Result::Ok;
        } else {
            ++_stats.refused;
            res.result = ipc::Result::Unsupported;
        }
    } else {
        // SET_INTERFACE. Alternate setting 0 is the default and is always
        // already in force; anything else needs the exporter to have selected
        // it, which v1 does not do. Refusing is the honest answer.
        if (r.alternateSetting == 0) {
            _arbiter.commitVerb(Ep0Verb::SetInterface, r.interfaceNumber, r.alternateSetting);
            res.result = ipc::Result::Ok;
        } else {
            ++_stats.refused;
            res.result = ipc::Result::Unsupported;
        }
    }

    // Every endpoint being RELEASED loses its transfers here, locally and now —
    // the ones still queued AND the ones already on the wire. An earlier
    // version drained only the queue, which left the interesting case
    // unhandled: the driver destroys the endpoint object, and the completion
    // for a transfer still in flight then arrives for something freed.
    for (std::uint32_t endpointId : r.release) {
        for (auto it = _queued.begin(); it != _queued.end();) {
            if (it->req.endpointId == endpointId) {
                completeToDriver(it->req.requestId, ipc::Result::Canceled, 0, {});
                retire(it->req.requestId);
                it = _queued.erase(it);
            } else {
                ++it;
            }
        }
        for (auto it = _outstanding.begin(); it != _outstanding.end();) {
            if (it->second.endpointId == endpointId) {
                (void)_plane.cancel(it->second.channel, it->second.planeRequestId);
                completeToDriver(it->second.driverRequestId, ipc::Result::Canceled, 0, {});
                retire(it->second.driverRequestId);
                it = _outstanding.erase(it);
            } else {
                ++it;
            }
        }
    }

    std::vector<std::uint8_t> out;
    ipc::encode(res, out);
    sendRecord(out);
}

// ---------------------------------------------------------------------------

void UdecxBridge::sweepQueued()
{
    if (!_cfg.clock) return;
    const ContinuousNs now = _cfg.clock->nowNs();
    for (auto it = _queued.begin(); it != _queued.end();) {
        if (it->deadlineNs != 0 && now >= it->deadlineNs) {
            ++_stats.timedOut;
            completeToDriver(it->req.requestId, ipc::Result::Timeout, 0, {});
            retire(it->req.requestId);
            it = _queued.erase(it);
        } else {
            ++it;
        }
    }
}

void UdecxBridge::admitQueued()
{
    while (!_queued.empty() && _plane.canAdmit()) {
        Queued q = std::move(_queued.front());
        _queued.pop_front();

        const std::uint8_t dir = q.req.direction == ipc::Direction::In
                                     ? static_cast<std::uint8_t>(wire::Dir::In)
                                     : static_cast<std::uint8_t>(wire::Dir::Out);

        std::uint16_t channel = 0;
        std::uint64_t planeId = 0;
        const Status s = _plane.submit(
            q.req.endpointAddress, xferTypeToWire(q.req.transferType), dir,
            q.req.offeredLength, q.req.setup, q.req.payload,
            timeoutFor(q.req.transferType), &channel, &planeId);

        if (s != Status::Ok) {
            // Could not even be sent. The guest is told now rather than left
            // waiting for a deadline that belongs to a transfer that never was.
            ++_stats.refused;
            completeToDriver(q.req.requestId, ipc::fromStatus(s), 0, {});
            retire(q.req.requestId);
            if (s == Status::TransportLost) { _linkDead = true; return; }
            continue;
        }

        Outstanding o;
        o.driverRequestId = q.req.requestId;
        o.channel         = channel;
        o.planeRequestId  = planeId;
        o.endpointId      = q.req.endpointId;
        o.offered         = q.req.offeredLength;
        o.dir             = q.req.direction;
        _outstanding[planeKey(channel, planeId)] = o;
        ++_stats.forwarded;
    }
}

Status UdecxBridge::pumpPlane()
{
    const Status s = _plane.pump([this](const session::DataCompletion& c) { onCompletion(c); });
    if (s == Status::Ok) {
        _plane.sweepDeadlines([this](const session::DataCompletion& c) { onCompletion(c); });
        return Status::Ok;
    }
    // The link died. Everything still outstanding is told so, because a URB the
    // guest never hears about is a hung driver, and the guest's own timeouts are
    // far longer than ours.
    _linkDead = true;
    _lastError = std::string("the session ended: ") + statusName(s);
    failAll(Status::TransportLost);
    return s;
}

void UdecxBridge::onCompletion(const session::DataCompletion& c)
{
    const std::uint64_t key = planeKey(c.channel, c.requestId);
    const auto it = _outstanding.find(key);
    if (it == _outstanding.end()) {
        // Late, for something already cancelled or retired. Normal, and silent:
        // treating it as an error would make ordinary cancellation look like a
        // protocol violation, which is exactly what the ABI review warned about.
        return;
    }

    const Outstanding o = it->second;
    _outstanding.erase(it);

    if (isRetired(o.driverRequestId)) return;
    retire(o.driverRequestId);
    ++_stats.completed;

    // The short-transfer question is NOT answered here. `fromStatus` maps a
    // short read to Ok on purpose: only the driver holds the guest's
    // USBD_SHORT_TRANSFER_OK, so only the driver can decide whether short is an
    // error for this particular URB. Deciding it here would take that away from
    // the side that has the information.
    completeToDriver(o.driverRequestId, ipc::fromStatus(c.status), c.actualLen, c.data);
}

void UdecxBridge::failAll(Status with)
{
    const ipc::Result r = ipc::fromStatus(with);

    for (auto& [key, o] : _outstanding) {
        (void)key;
        if (isRetired(o.driverRequestId)) continue;
        retire(o.driverRequestId);
        completeToDriver(o.driverRequestId, r, 0, {});
    }
    _outstanding.clear();

    for (Queued& q : _queued) {
        if (isRetired(q.req.requestId)) continue;
        retire(q.req.requestId);
        completeToDriver(q.req.requestId, r, 0, {});
    }
    _queued.clear();

    _plane.completeAll(with, [](const session::DataCompletion&) {});
    if (_channel.pendingToDriver() != 0) (void)_channel.flush();
}

void UdecxBridge::completeToDriver(std::uint64_t requestId, ipc::Result result,
                                   std::uint32_t actualLength,
                                   std::span<const std::uint8_t> payload)
{
    ipc::UrbCompletion c;
    c.requestId          = requestId;
    c.sessionIncarnation = _cfg.sessionIncarnation;
    c.deviceIncarnation  = _cfg.deviceIncarnation;
    c.result             = result;
    c.actualLength       = actualLength;
    c.payload.assign(payload.begin(), payload.end());

    // The single-length rule, and the bug an earlier version had here.
    //
    // It read "if they differ, the payload wins" — which is right for an IN
    // transfer and CATASTROPHIC for an OUT. An OUT completion carries no
    // payload by definition, so `payload.size()` is 0 and every successful
    // write was reported to the guest as having moved nothing. A filesystem
    // told that its 128 KiB write transferred 0 bytes does not retry politely.
    //
    // The rule is directional: an IN's length IS its payload; an OUT's length
    // is what the device accepted, and there is no payload to check it against.
    if (!c.payload.empty())
        c.actualLength = static_cast<std::uint32_t>(c.payload.size());

    std::vector<std::uint8_t> out;
    ipc::encode(c, out);
    sendRecord(out);
}

void UdecxBridge::retire(std::uint64_t driverRequestId)
{
    // A fixed cap, because a redundancy that grows without bound is a leak
    // charged to the service's uptime. The plane already guarantees one
    // terminal outcome per submit; this is the second lock, and 4096 is far
    // more than the number of ids that can still produce a late completion at
    // any admission depth this project will ship.
    constexpr std::size_t kMaxRetired = 4096;
    if (_retired.emplace(driverRequestId, true).second) {
        _retiredOrder.push_back(driverRequestId);
        while (_retiredOrder.size() > kMaxRetired) {
            _retired.erase(_retiredOrder.front());
            _retiredOrder.pop_front();
        }
    }
}

bool UdecxBridge::isRetired(std::uint64_t driverRequestId) const
{
    return _retired.find(driverRequestId) != _retired.end();
}

void UdecxBridge::sendRecord(std::span<const std::uint8_t> bytes)
{
    if (const Status s = _channel.send(bytes); s != Status::Ok) {
        _linkDead = true;
        _lastError = std::string("could not reach the driver: ") + statusName(s);
    }
}

} // namespace airusb::windows
