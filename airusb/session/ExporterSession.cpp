#include "ExporterSession.h"

#include "../core/Watchdog.h"
#include "../protocol/Codec.h"
#include "../protocol/ManifestCodec.h"
#include "../protocol/Validate.h"

#include <cstring>
#include <utility>

namespace airusb::session {

using namespace airusb::protocol;

namespace {

/// Records the exporter may act on before the peer is paired (§3.14).
bool isPreTrustMessage(wire::Type t) noexcept
{
    switch (t) {
        case wire::Type::Ping:
        case wire::Type::Pong:
        case wire::Type::Goodbye:
        case wire::Type::PairRequest:
        case wire::Type::PairConfirm:
        case wire::Type::PairResult:
            return true;
        default:
            return false;
    }
}

/// ep0 is not just another endpoint: a control transfer can change the
/// configuration or an alternate setting, which redefines what every other
/// endpoint on the device IS.
constexpr bool isEp0(std::uint8_t epAddr) noexcept { return (epAddr & 0x7Fu) == 0; }

/// The device deadline for a transfer, from THE timeout table. Zero means no
/// deadline, and for an interrupt endpoint that is the correct answer rather
/// than an oversight: an interrupt IN may legitimately idle for ever.
std::uint32_t deadlineMsFor(std::uint8_t xferType) noexcept
{
    switch (static_cast<wire::XferType>(xferType)) {
        case wire::XferType::Interrupt:   return static_cast<std::uint32_t>(watchdog::kUrbDeadlineIntr);
        case wire::XferType::Control:     return static_cast<std::uint32_t>(watchdog::kNetCtrl);
        case wire::XferType::Isochronous: return static_cast<std::uint32_t>(watchdog::kNetCtrl);
        case wire::XferType::Bulk:
        default:                          return static_cast<std::uint32_t>(watchdog::kUrbCeilingBulk);
    }
}

} // namespace

// ---------------------------------------------------------------------------

Status ExporterSession::begin(SecureSession* secure, const Config& cfg)
{
    if (!secure || !secure->established()) return Status::BadArgument;
    if (!cfg.devices || !cfg.clock) return Status::BadArgument;
    // A session with no lease authority cannot enforce exclusivity, and a
    // session that cannot enforce exclusivity is the bug this argument exists to
    // close. Refused rather than defaulted: the failure of the old design was
    // precisely that the ownership record was allowed not to exist.
    if (!cfg.leases) return Status::BadArgument;

    _secure   = secure;
    _devices  = cfg.devices;
    _clock    = cfg.clock;
    _leases   = cfg.leases;
    _peerName = cfg.peerName;
    _state    = State::Idle;
    _lastHeardNs = _clock->nowNs();
    return Status::Ok;
}

bool ExporterSession::permitted(wire::Type type) const
{
    if (isPreTrustMessage(type)) return true;
    // Everything else needs a pinned peer. There is no "allow on the local
    // network" branch here, deliberately.
    return _secure->trust() == Trust::Paired;
}

std::size_t ExporterSession::queuedTransfers() const noexcept
{
    std::size_t n = 0;
    for (const auto& [ep, q] : _queues) n += q.size();
    return n;
}

Status ExporterSession::sendRecord(std::span<const std::uint8_t> record)
{
    transport::RecordLayer* t = _secure->transport();
    if (!t) return Status::TransportLost;
    if (const Status s = t->sendRecord(record); s != Status::Ok) return s;
    return t->flush();
}

Status ExporterSession::sendSimple(wire::Type type, Status status,
                                   std::uint64_t requestId,
                                   std::span<const std::uint8_t> body)
{
    Header h;
    h.type      = static_cast<std::uint8_t>(type);
    h.flags     = wire::kFlagSegFirst;
    h.channel   = 0;
    h.attachId  = _attachId;
    h.requestId = requestId;
    h.status    = static_cast<std::uint16_t>(status);
    h.bodyLen   = static_cast<std::uint32_t>(body.size());
    // total_len is "total logical data length across all segments" (§3.2) — the
    // DATA payload, not the body. Control-plane messages carry no segmented data
    // payload, so it is zero. Setting it to body_len instead makes R4's exactness
    // rule reject every SUBMIT and COMPLETE, which is exactly what it did.
    h.totalLen  = 0;

    std::vector<std::uint8_t> rec;
    encodeHeader(h, rec);
    rec.insert(rec.end(), body.begin(), body.end());
    return sendRecord(rec);
}

Status ExporterSession::refuse(const Header& h, Status status, std::string_view why)
{
    _why.assign(why);
    std::vector<std::uint8_t> rec;
    buildError(h.type, status, why, rec);
    (void)sendRecord(rec);
    // A refusal is not fatal to the session unless the status says so. A peer
    // asking for something it may not have is ordinary; a malformed frame is not.
    return isFatal(status) ? status : Status::Ok;
}

// ---------------------------------------------------------------------------
// The event loop
// ---------------------------------------------------------------------------

Status ExporterSession::pump()
{
    transport::RecordLayer* t = _secure->transport();
    if (!t) return Status::TransportLost;

    // 1. Push whatever the socket would not take last time, BEFORE reading.
    //
    // `flush()` returns Ok on a would-block short write and leaves the rest
    // buffered, so a reply that did not fit is not an error — it is a reply that
    // has not been sent yet. Every record but the last self-heals, because the
    // next sendRecord() flushes again; the LAST record of a transfer has nothing
    // behind it, so without this line its tail sits in the buffer for ever while
    // the importer waits for bytes that will never move.
    //
    // Unreachable at small transfers, which is why it survived: a 2 KB reply
    // fits in any socket buffer. It appeared the first time a 128 KiB COMPLETE
    // crossed a real link between two machines — 8 records, ~28 ms away.
    if (t->pendingTxBytes() != 0) {
        if (const Status s = t->flush(); s != Status::Ok) return s;
    }

    // 2. Read and answer everything available RIGHT NOW.
    bool transportGone = false;
    for (;;) {
        std::vector<std::uint8_t> rec;
        const Status r = t->receiveRecord(rec);
        if (r == Status::Busy) break;
        if (r != Status::Ok) {
            if (r != Status::TransportLost) return r;
            transportGone = true;
            break;
        }
        if (rec.empty()) break;

        _lastHeardNs = _clock->nowNs();
        _leases->heard(_secure->peerIdentity().identityKey);

        // One record may carry several messages back to back (§3.1). Parse until
        // it is exactly consumed; leftover bytes are fatal.
        std::size_t at = 0;
        while (at < rec.size()) {
            const auto remaining = std::span<const std::uint8_t>(rec).subspan(at);
            Header h;
            if (!decodeHeader(remaining, h))
                return refuse(Header{}, Status::MalformedFrame, "unparseable header");

            Limits lim;
            lim.maxRecordBytes = t->maxRecordBytes();
            const std::size_t avail = remaining.size() - wire::kHeaderSize;
            if (auto v = validateHeader(h, avail, lim); !v.ok())
                return refuse(h, v.status, "header failed validation");

            if (avail < h.bodyLen)
                return refuse(h, Status::MalformedFrame, "body shorter than declared");

            const auto body = remaining.subspan(wire::kHeaderSize, h.bodyLen);
            if (const Status s = handle(h, body); isFatal(s)) return s;

            at += wire::kHeaderSize + h.bodyLen;
        }
        if (at != rec.size())
            return refuse(Header{}, Status::MalformedFrame, "trailing bytes in record");
    }

    if (transportGone) {
        // §7.3: silence does NOT release the capture, and — the half that used
        // to be missing — it does not release OWNERSHIP either. The lease is
        // quarantined, which keeps the device reserved for this peer until it
        // comes back, detaches, or somebody at this machine takes it back.
        if (_state == State::Leased) {
            _state = State::Orphaned;
            _leases->quarantine();
        }
        // Every transfer still owed an answer gets one locally. The peer will
        // never read them, but the DEVICE has to be told to stop, and the
        // exporter's own accounting has to end at zero rather than leaking a
        // slot per lost session.
        failAllTransfers(Status::TransportLost);
        resetReassembly();
        return Status::TransportLost;
    }

    // 3. Collect what the device finished BEFORE admitting anything.
    //
    // The order matters and it is not stylistic. A completion is what frees its
    // endpoint's slot, so collecting first lets the next transfer on that
    // endpoint go out in the SAME iteration. With admit-first, every queued
    // transfer waited a whole extra pump for a slot that was already free —
    // which on a depth-1 endpoint is every transfer after the first.
    if (const Status s = collect(); isFatal(s)) return s;

    // 4. Hand queued work to the device. The only place that submits.
    admit();

    // 5. And collect again, because a port may finish synchronously.
    //
    // `InlineAsyncPort` does exactly that: it issues the transfer inside
    // submit(), so its outcome is ready the instant admit() returns. Without
    // this second pass every transfer through a synchronous backend — which is
    // every transfer this project has ever run on real hardware — would be
    // answered one pump later than it could be.
    if (const Status s = collect(); isFatal(s)) return s;

    // WHILE WE OWE THE PEER AN ANSWER, IT COUNTS AS PRESENT.
    //
    // `heard()` means "the owner is demonstrably there", and it normally fires
    // when a record arrives. But an importer waiting for a transfer it already
    // submitted is silent BY DESIGN — it has nothing to say until we answer —
    // and a peer we have spent thirty seconds working for is as demonstrably
    // present as one that just pinged. So the timer is refreshed here, which
    // also means it restarts from the moment the LAST transfer is answered:
    // the clock on "are they still there?" starts when it becomes their turn to
    // speak.
    //
    // Without this the two numbers make a mid-write quarantine inevitable:
    // T_urb_ceiling_bulk is 30 s, T_lease_exporter is 20 s, and one WRITE(10)
    // on a cheap stick doing garbage collection legitimately takes 8-12 s.
    if (!_inFlight.empty() || queuedTransfers() != 0)
        _leases->heard(_secure->peerIdentity().identityKey);

    // The device has no clock of its own; ours is the only one.
    if (const Status s = sweepDeadlines(); isFatal(s)) return s;

    // The lease timer. Expiry QUARANTINES — it never frees, because the exporter
    // cannot know whether the silent importer has a dirty filesystem mounted.
    //
    // AND IT DOES NOT RUN WHILE WE OWE THE PEER AN ANSWER.
    //
    // The lease timer asks "have we heard from the owner", and `heard()` fires
    // only when a record ARRIVES. An importer waiting for a transfer it already
    // submitted is silent BY DESIGN — it has nothing to say until we answer.
    // The two numbers make that fatal on their own: T_urb_ceiling_bulk is 30 s
    // and T_lease_exporter is 20 s, so a cheap flash stick doing internal
    // garbage collection on one WRITE(10) — which the timeout table itself says
    // legitimately takes 8-12 s and which macOS allows 30 s for — would trip
    // the lease at 20 s and quarantine the drive MID-WRITE, on a peer that was
    // never absent.
    //
    // Found by a test written for a different bug: advancing the clock past the
    // URB ceiling necessarily advances it past the lease, and the session went
    // Orphaned where the test expected it to keep working.
    //
    // A peer we owe an answer to is demonstrably alive, so the sweep waits —
    // see the `heard()` above, which is what makes the timer restart from the
    // moment the last transfer is answered rather than from the last record.
    // It is not deferred indefinitely: the URB deadline answers the transfer at
    // the ceiling, and the lease timer resumes from there.
    const bool owedAnswers = !_inFlight.empty() || queuedTransfers() != 0;
    if (!owedAnswers && _state == State::Leased && _leases->silenceExpired()) {
        _leases->quarantine();
        _state = State::Orphaned;
        _why   = "the importer stopped answering; the device is held for it";
        failAllTransfers(Status::XferTimeout);
    }

    return Status::Ok;
}

Status ExporterSession::handle(const Header& h, std::span<const std::uint8_t> body)
{
    ++_handled;
    const auto type = static_cast<wire::Type>(h.type);

    if (!permitted(type)) {
        // The trust gate. An authenticated stranger gets a clear refusal rather
        // than a device list.
        return refuse(h, Status::NotPaired,
                      "This Mac has not been paired with yours yet.");
    }

    switch (type) {
        case wire::Type::Ping:        return handlePing(h, body);
        case wire::Type::ListDevices: return handleListDevices(h);
        case wire::Type::Attach:      return handleAttach(h, body);
        case wire::Type::Detach:      return handleDetach(h, body);
        case wire::Type::Submit:      return handleSubmit(h, body);
        case wire::Type::Data:        return handleData(h, body);
        case wire::Type::Cancel:      return handleCancel(h, body);
        case wire::Type::EpClearHalt: return handleClearHalt(h);
        case wire::Type::DeviceReset: return handleDeviceReset(h);

        case wire::Type::Goodbye:
            _state = State::Closed;
            close();
            return Status::Ok;

        default:
            // Unknown or not-yet-implemented control messages are refused
            // individually. Ignoring them would let a peer believe a request
            // succeeded, which is worse than a clear no.
            return refuse(h, Status::UnsupportedMessage,
                          "That request is not supported by this version.");
    }
}

Status ExporterSession::handlePing(const Header& h, std::span<const std::uint8_t> body)
{
    PingBody p;
    if (!decodePing(body, p)) return refuse(h, Status::MalformedFrame, "bad PING");

    PingBody pong;
    pong.pingTsNs = p.pingTsNs;
    pong.echoTsNs = _clock->nowNs();

    std::vector<std::uint8_t> out;
    encodePing(pong, out);
    return sendSimple(wire::Type::Pong, Status::Ok, h.requestId, out);
}

Status ExporterSession::handleListDevices(const Header& h)
{
    if (!_secure->mayList())
        return refuse(h, Status::NotPermitted,
                      "This Mac is not allowed to see your devices.");

    const auto devices = _devices->list();
    std::vector<std::uint8_t> body;
    encodeDeviceList(devices, body);
    return sendSimple(wire::Type::DeviceList, Status::Ok, h.requestId, body);
}

Status ExporterSession::handleAttach(const Header& h, std::span<const std::uint8_t> body)
{
    if (!_secure->mayAttach())
        return refuse(h, Status::NotPermitted,
                      "This Mac is not allowed to use your devices.");

    AttachBody a;
    if (!decodeAttach(body, a))
        return refuse(h, Status::MalformedFrame, "bad ATTACH");

    // §7.7: a second importer gets BUSY and is NEVER queued. Queuing creates an
    // ambiguous handover window in which neither peer knows who owns the device.
    if (_state != State::Idle)
        return refuse(h, Status::Busy, "That device is already in use.");

    // The cross-session question, which the session object cannot answer for
    // itself: does anybody ELSE still own this device? A peer that vanished
    // mid-write still owns it, and its lease outlived the session it was made in.
    {
        std::string leaseWhy;
        if (const Status s = _leases->mayClaim(_secure->peerIdentity().identityKey,
                                               a.uid, &leaseWhy);
            s != Status::Ok) {
            AttachOkBody fail;
            std::vector<std::uint8_t> b;
            encodeAttachOk(fail, b);
            appendTlv(wire::Tlv::RejectReason,
                      std::span<const std::uint8_t>(
                          reinterpret_cast<const std::uint8_t*>(leaseWhy.data()),
                          leaseWhy.size()), b);
            _why = leaseWhy;
            return sendSimple(wire::Type::AttachOk, s, h.requestId, b);
        }
    }

    IAsyncUsbDevicePort* port = nullptr;
    DeviceManifest manifest;
    std::uint8_t configValue = 0;
    std::string why;

    if (const Status s = _devices->claim(a.uid, &port, manifest, &configValue, &why);
        s != Status::Ok) {
        // The status carries the reason the user needs: MountedLocally means
        // "close the app using it", CaptureFailed means something else entirely.
        AttachOkBody fail;
        std::vector<std::uint8_t> b;
        encodeAttachOk(fail, b);
        appendTlv(wire::Tlv::RejectReason,
                  std::span<const std::uint8_t>(
                      reinterpret_cast<const std::uint8_t*>(why.data()), why.size()), b);
        _why = why;
        return sendSimple(wire::Type::AttachOk, s, h.requestId, b);
    }
    if (!port) {
        _devices->release(a.uid);
        return refuse(h, Status::Internal, "the device source returned no port");
    }

    // A port that cannot defer a transfer cannot carry an endpoint that idles.
    //
    // Refusing here is much better than the alternative. `InlineAsyncPort`
    // issues the transfer inside submit(), so an interrupt IN with nothing to
    // report would block this session inside one function call — and an exporter
    // that accepts a keyboard and then stops answering looks exactly like a
    // network fault to the person debugging it. "This build cannot share this
    // kind of device yet" is a sentence; a hang is not.
    if (!port->canIdle()) {
        bool hasIdlingEndpoint = false;
        for (std::size_t i = 0; i < manifest.configurationCount() && !hasIdlingEndpoint; ++i) {
            const auto blob = manifest.configurationByIndex(static_cast<std::uint8_t>(i));
            if (blob.size() < 6) continue;
            for (std::uint16_t iface = 0; iface < 256 && !hasIdlingEndpoint; ++iface) {
                for (const EndpointModel& e :
                         manifest.endpointsFor(blob[5], static_cast<std::uint8_t>(iface), 0)) {
                    if (e.type == XferType::Interrupt || e.type == XferType::Isochronous) {
                        hasIdlingEndpoint = true;
                        break;
                    }
                }
            }
        }
        if (hasIdlingEndpoint) {
            _devices->release(a.uid);
            AttachOkBody fail;
            std::vector<std::uint8_t> b;
            static constexpr char kWhy[] =
                "This machine cannot share a device with an interrupt or "
                "isochronous endpoint yet: its USB backend cannot report a "
                "transfer that has not finished, and such an endpoint may "
                "legitimately never finish.";
            encodeAttachOk(fail, b);
            appendTlv(wire::Tlv::RejectReason,
                      std::span<const std::uint8_t>(
                          reinterpret_cast<const std::uint8_t*>(kWhy), sizeof kWhy - 1), b);
            _why = kWhy;
            return sendSimple(wire::Type::AttachOk, Status::UnsupportedMessage,
                              h.requestId, b);
        }
    }

    _port        = port;
    _manifest    = std::move(manifest);
    _configValue = configValue;
    _uid         = a.uid;
    _attachSlot  = a.attachSlot;

    // The attach id comes from the authority, not from a per-session counter.
    // Two sessions against the same device must never mint the same one, and a
    // counter that resets when a session object is destroyed does exactly that.
    // No token is asked for, because there is nowhere to send one.
    //
    // `LeaseAuthority::tryRecover` is written and tested, and ATTACH_OK has no
    // field for a recovery token — so minting one here and dropping it, which
    // the first version did, is a feature the code implies and does not have.
    // The honest state is: a quarantined lease is recovered by a person at the
    // exporting machine, and RESUME (0x28, reserved) is the next session's job.
    _attachId = _leases->grant(_secure->peerIdentity().identityKey, _uid, nullptr);
    _leaseEpoch = _leases->snapshot().leaseEpoch;

    // The manifest is built and validated BEFORE anything is announced. §7.2
    // step 9: the importer never learns the device exists until it is fully
    // captured and fully described.
    std::vector<std::uint8_t> manifestBody;
    if (const Status s = encodeManifest(_manifest, _configValue, manifestBody);
        s != Status::Ok) {
        _leases->release(_secure->peerIdentity().identityKey);
        _devices->release(_uid);
        _port = nullptr;
        _attachId = 0;
        return refuse(h, Status::ManifestInvalid,
                      "This device's descriptors could not be read.");
    }

    AttachOkBody ok;
    ok.attachId          = _attachId;
    ok.creditUrbs        = static_cast<std::uint32_t>(kCreditUrbs);
    ok.creditBytes       = static_cast<std::uint32_t>(kCreditBytes);
    ok.speed             = static_cast<std::uint16_t>(_manifest.speed());
    // ENDPOINT scope only, and now that is a measured statement rather than a
    // guess: `InlineAsyncPort::cancel()` returns false because a synchronous
    // port genuinely cannot stop a transfer it has already issued.
    ok.cancelGranularity = 0;
    // Advertise DEVICE_RESET only now that there is a handler behind it. It used
    // to be set unconditionally, which is worse than not advertising it at all:
    // a recovery-capable importer picks the path that is guaranteed to be
    // refused, and reports a device that cannot be recovered.
    ok.exporterFlags     = kExpSupportsDeviceReset;
    ok.manifestLen       = static_cast<std::uint32_t>(manifestBody.size());
    ok.leaseEpoch        = _leaseEpoch;
    ok.urbCeilingMs      = static_cast<std::uint32_t>(watchdog::kUrbCeilingBulk);

    std::vector<std::uint8_t> okBody;
    encodeAttachOk(ok, okBody);
    if (const Status s = sendSimple(wire::Type::AttachOk, Status::Ok, h.requestId, okBody);
        s != Status::Ok)
        return s;

    // The manifest is SEGMENTED if it does not fit in one record.
    //
    // It used to be sent with sendSimple and fail outright when it did not fit,
    // with a comment saying a device with eight configurations and a full
    // string table could reach the limit. It can: at the 1 KiB floor two peers
    // may legitimately agree on, almost any real device reaches it. The data
    // plane has had `emitTransfer`/`Reassembler` since L5 and they are not
    // data-plane-specific, so the control plane uses the same pair.
    //
    // The fixed body is empty and the whole manifest is the DATA payload, which
    // is what makes `total_len` mean the manifest's length on every record —
    // exactly the shape R4's exactness rule wants.
    {
        Header base;
        base.type      = static_cast<std::uint8_t>(wire::Type::DeviceManifest);
        base.channel   = 0;
        base.attachId  = _attachId;
        base.requestId = h.requestId;
        base.status    = 0;

        const std::uint32_t maxPlain = _secure->transport()->maxPlaintextBytes();
        if (maxPlain <= wire::kHeaderSize) return Status::Internal;
        const std::uint32_t maxSeg =
            maxPlain - static_cast<std::uint32_t>(wire::kHeaderSize);

        if (const Status s = emitTransfer(base, {}, manifestBody, maxSeg,
                [this](std::span<const std::uint8_t> rec) { return sendRecord(rec); });
            s != Status::Ok) {
            _leases->release(_secure->peerIdentity().identityKey);
            _devices->release(_uid);
            _port = nullptr;
            _attachId = 0;
            _state = State::Idle;
            return refuse(h, s, "This device's descriptor set could not be sent.");
        }
    }

    _state = State::Leased;
    return Status::Ok;
}

Status ExporterSession::handleDetach(const Header& h, std::span<const std::uint8_t> body)
{
    DetachBody d;
    if (!decodeDetach(body, d))
        return refuse(h, Status::MalformedFrame, "bad DETACH");

    if (_state != State::Leased && _state != State::Orphaned)
        return refuse(h, Status::NotFound, "Nothing is attached.");

    // Any half-received segmented OUT dies with the attach; the device never saw
    // it, so there is nothing to unwind on its behalf.
    resetReassembly();

    _state = State::Draining;

    // DRAINING is real now. Every transfer the peer is still owed an answer for
    // gets one — cancelled if the device can stop it, its true outcome if not.
    // Under the old synchronous exporter there was never anything to drain,
    // because there was never more than one transfer and it had already
    // finished by the time any other record could be read.
    const std::size_t outstanding = _inFlight.size() + queuedTransfers();
    failAllTransfers(Status::XferCancelled);

    DetachOkBody ok;
    // The counter is 64-bit; the wire field is 32. A session that moved more
    // than 4 billion URBs saturates rather than wrapping to a small number,
    // because a wrapped count reads as a successful tiny drain.
    ok.urbsCompleted = _transfers > 0xFFFFFFFFull
                         ? 0xFFFFFFFFu
                         : static_cast<std::uint32_t>(_transfers);
    ok.urbsCancelled = outstanding > 0xFFFFFFFFull
                         ? 0xFFFFFFFFu
                         : static_cast<std::uint32_t>(outstanding);

    std::vector<std::uint8_t> okBody;
    encodeDetachOk(ok, okBody);
    const Status s = sendSimple(wire::Type::DetachOk, Status::Ok, h.requestId, okBody);

    // An explicit detach by the owner is the only automatic path back to Free.
    _leases->release(_secure->peerIdentity().identityKey);

    // Release order (§7.6) is the device source's business; it destroys the
    // device before unclaiming the disk.
    _devices->release(_uid);
    _port     = nullptr;
    _attachId = 0;
    _state    = State::Idle;
    return s;
}

Status ExporterSession::handleClearHalt(const Header& h)
{
    if (_state != State::Leased || !_port)
        return refuse(h, Status::Detaching, "That device is no longer attached.");
    if (h.attachId != _attachId) return Status::Ok;      // R12: stale, drop silently

    // The endpoint address is the low byte of the derived channel (§3.4), so the
    // verb needs no body of its own.
    const std::uint8_t epAddr = static_cast<std::uint8_t>(h.channel & 0xFFu);

    // A verb, not a forwarded control transfer: -clearStallWithError: clears the
    // device's stall AND the exporter host controller's data toggle. A raw
    // CLEAR_FEATURE forward clears only the former and leaves every later
    // transfer on that endpoint silently wrong.
    //
    // Asynchronous like everything else, and NOT admitted against the endpoint's
    // transfer slot — a stall recovery that queued behind the transfers it
    // exists to unblock would never run.
    const std::uint64_t token = _nextToken++;
    PendingVerb v;
    v.requestId = h.requestId;
    v.epAddr    = epAddr;
    v.isReset   = false;
    _verbs[token] = v;

    if (const Status s = _port->clearHalt(token, epAddr); s != Status::Ok) {
        _verbs.erase(token);
        return sendSimple(wire::Type::CtrlAck, s, h.requestId, {});
    }
    return Status::Ok;
}

Status ExporterSession::handleDeviceReset(const Header& h)
{
    if (_state != State::Leased || !_port)
        return refuse(h, Status::Detaching, "That device is no longer attached.");
    if (h.attachId != _attachId) return Status::Ok;      // R12

    // Full Bulk-Only Transport recovery is a class reset plus clearing BOTH bulk
    // halts. This project's exporters cannot issue a port reset — that would
    // re-enumerate the device out from under the capture — so DEVICE_RESET is
    // implemented as what it honestly can be: clear the halt on every bulk
    // endpoint of the captured configuration, and report the worst result.
    //
    // Doing something and saying what it was beats the previous behaviour, which
    // was to ADVERTISE the capability in ATTACH_OK and then answer
    // UnsupportedMessage — a recovery-capable importer would choose the path
    // guaranteed to be refused, and conclude the device was unrecoverable.
    std::vector<std::uint8_t> endpoints;
    for (std::uint16_t iface = 0; iface < 256; ++iface) {
        for (const EndpointModel& e :
                 _manifest.endpointsFor(_configValue, static_cast<std::uint8_t>(iface), 0)) {
            if (e.type == XferType::Bulk) endpoints.push_back(e.address);
        }
    }

    if (endpoints.empty())
        return sendSimple(wire::Type::CtrlAck, Status::Ok, h.requestId, {});

    // Only the LAST leg carries the request id, so exactly one CTRL_ACK is
    // sent — and it must report the WORST result, not the last one.
    //
    // The first version discarded every earlier leg's status, so a reset whose
    // bulk OUT failed and whose bulk IN succeeded reported success. Half of a
    // BOT recovery is not a recovery: the guest would resume writing to an
    // endpoint that is still halted, and its next command would fail for a
    // reason it had just been told did not exist.
    _resetWorst   = Status::Ok;
    _resetPending = 0;
    for (std::size_t i = 0; i < endpoints.size(); ++i) {
        const std::uint64_t token = _nextToken++;
        PendingVerb v;
        v.requestId = (i + 1 == endpoints.size()) ? h.requestId : 0;
        v.epAddr    = endpoints[i];
        v.isReset   = true;
        _verbs[token] = v;
        if (const Status s = _port->clearHalt(token, endpoints[i]); s != Status::Ok) {
            _verbs.erase(token);
            if (_resetWorst == Status::Ok) _resetWorst = s;
            if (v.requestId != 0)
                return sendSimple(wire::Type::CtrlAck, _resetWorst, h.requestId, {});
        } else {
            ++_resetPending;
        }
    }
    return Status::Ok;
}

Status ExporterSession::handleCancel(const Header& h, std::span<const std::uint8_t> body)
{
    if (_state != State::Leased)
        return refuse(h, Status::Detaching, "That device is no longer attached.");
    if (h.attachId != _attachId) return Status::Ok;      // R12

    CancelBody cb;
    if (!decodeCancel(body, cb))
        return refuse(h, Status::MalformedFrame, "bad CANCEL");

    const auto scope = static_cast<CancelScope>(cb.scope);
    if (scope != CancelScope::Request && scope != CancelScope::Endpoint)
        return refuse(h, Status::BadArgument, "unknown cancellation scope");

    // The endpoint the header's channel names and the one the body names must
    // agree. They are two spellings of the same fact, and a peer that disagrees
    // with itself is one whose bookkeeping we cannot follow.
    const std::uint8_t chanEp = static_cast<std::uint8_t>(h.channel & 0xFFu);
    if (cb.epAddr != chanEp)
        return refuse(h, Status::BadArgument,
                      "the cancel names one endpoint in its channel and another in its body");

    std::uint32_t stopped = 0;

    auto matches = [&](std::uint8_t ep, std::uint64_t rid) {
        if (scope == CancelScope::Endpoint) return ep == cb.epAddr;
        return rid == cb.targetRequestId && ep == cb.epAddr;
    };

    // 1. Queued but never issued: the device has not seen it, so it can be
    //    retired cleanly with no ambiguity at all. This is the good case and it
    //    is why the queue is worth having.
    if (auto it = _queues.find(cb.epAddr); it != _queues.end()) {
        std::deque<Pending> keep;
        while (!it->second.empty()) {
            Pending p = std::move(it->second.front());
            it->second.pop_front();
            if (matches(p.sb.epAddr, p.requestId)) {
                InFlight f;
                f.channel   = p.channel;
                f.requestId = p.requestId;
                f.epAddr    = p.sb.epAddr;
                f.sb        = p.sb;
                (void)emitComplete(f, Status::XferCancelled, 0, /*cancelled=*/true,
                                   false, {});
                ++stopped;
                ++_cancelled;
            } else {
                keep.push_back(std::move(p));
            }
        }
        it->second = std::move(keep);
    }

    // 2. Already on the device. Ask the port; it decides whether it can.
    std::vector<std::uint64_t> tokens;
    for (const auto& [token, f] : _inFlight)
        if (matches(f.epAddr, f.requestId)) tokens.push_back(token);

    for (const std::uint64_t token : tokens) {
        auto it = _inFlight.find(token);
        if (it == _inFlight.end()) continue;
        if (_port && _port->cancel(token)) {
            // The port will report it through poll(), like any other outcome.
            // Nothing is retired here — retiring it now and letting the outcome
            // arrive later is how a transfer gets two terminal answers.
            it->second.cancelRequested = true;
            ++stopped;
        } else {
            // 3. The backend cannot stop it, and pretending otherwise is the
            //    dangerous answer. The transfer stays outstanding and keeps its
            //    endpoint reserved; the importer is told, in CANCEL_ACK's count,
            //    that this one was NOT stopped. Starting a later transfer on the
            //    same endpoint while an abandoned one is still physically
            //    running is how a Bulk-Only Transport phase machine
            //    desynchronises, so the endpoint stays busy until the device
            //    finishes on its own or the deadline sweep fires.
            //
            // AND ITS DEADLINE IS LEFT ALONE. Setting `cancelRequested` here —
            // which the first version did — made `sweepDeadlines()` skip it, so
            // a transfer stuck in a backend that cannot abort got a
            // CANCEL_ACK saying "0 stopped" and then NO terminal outcome ever:
            // the one thing invariant I1 forbids. The deadline sweep is the only
            // thing that can end it, so the cancel must not disarm it.
        }
    }

    CancelAckBody ack;
    ack.cancelledCount = stopped;
    ack.granularity    = static_cast<std::uint8_t>(scope);
    std::vector<std::uint8_t> ackBody;
    encodeCancelAck(ack, ackBody);
    return sendSimple(wire::Type::CancelAck, Status::Ok, h.requestId, ackBody);
}

Status ExporterSession::handleSubmit(const Header& h, std::span<const std::uint8_t> body)
{
    if (_state != State::Leased)
        return refuse(h, Status::Detaching, "That device is no longer attached.");
    if (!_port)
        return refuse(h, Status::DeviceGone, "That device is gone.");

    // R12: a stale attach id is dropped SILENTLY and is not fatal. Escalating it
    // would turn every legitimate reset into a session teardown.
    if (h.attachId != _attachId) return Status::Ok;

    SubmitBody sb;
    if (!decodeSubmit(body, sb))
        return refuse(h, Status::MalformedFrame, "bad SUBMIT");

    const auto dataSection = body.subspan(wire::kBodySubmit);
    Limits lim;
    lim.maxRecordBytes = _secure->transport()->maxRecordBytes();
    if (auto v = validateSubmit(h, sb, dataSection, lim); !v.ok())
        return refuse(h, v.status, "SUBMIT failed validation");

    if (h.segMore()) {
        // A segmented transfer begins. Only an OUT transfer carries segmented
        // data — an IN transfer sends no OUT payload, so SEG_MORE on it is
        // malformed. Segmentation is a property of the serial RECORD stream, so
        // a second segmented transfer starting mid-reassembly is a framing error
        // rather than a queue: the two would be indistinguishable from one
        // misframed transfer.
        if (sb.dir != static_cast<std::uint8_t>(wire::Dir::Out))
            return refuse(h, Status::MalformedFrame, "a segmented IN SUBMIT is malformed");
        if (_rxActive)
            return refuse(h, Status::MalformedFrame, "overlapping segmented SUBMIT");

        _rxActive    = true;
        _rxChannel   = h.channel;
        _rxRequestId = h.requestId;
        _rxSb        = sb;
        _rx.clear();

        Status e = Status::Ok;
        const Reassembler::Outcome o = _rx.accept(h, dataSection, e);
        if (o == Reassembler::Outcome::Rejected) {
            resetReassembly();
            return refuse(h, e, "segmentation rejected the first segment");
        }
        // NeedMore: the device is NOT touched until the whole transfer arrives.
        // Handing it the segments as they land would inject a short packet at each
        // seam, which a bulk device reads as the end of the data phase.
        return Status::Ok;
    }

    // A transfer that fits in one record — the common case. If a segmented one is
    // mid-flight, a fresh single-record SUBMIT is a framing error.
    if (_rxActive)
        return refuse(h, Status::MalformedFrame, "a SUBMIT arrived during reassembly");

    return enqueueTransfer(h, sb, dataSection);
}

Status ExporterSession::handleData(const Header& h, std::span<const std::uint8_t> body)
{
    if (_state != State::Leased || !_port)
        return refuse(h, Status::Detaching, "That device is no longer attached.");

    // R12: as with SUBMIT, a stale attach id is dropped silently.
    if (h.attachId != _attachId) return Status::Ok;

    // A Data record only ever continues the one segmented OUT transfer being
    // reassembled. Any other (channel, request_id) — or a Data with nothing in
    // progress — means the stream is misaligned.
    if (!_rxActive || h.channel != _rxChannel || h.requestId != _rxRequestId)
        return refuse(h, Status::MalformedFrame,
                      "a DATA segment arrived with no transfer in progress");

    Status e = Status::Ok;
    const Reassembler::Outcome o = _rx.accept(h, body, e);
    if (o == Reassembler::Outcome::Rejected) {
        resetReassembly();
        return refuse(h, e, "segmentation rejected a continuation");
    }
    if (o == Reassembler::Outcome::NeedMore)
        return Status::Ok;

    // Complete: the whole OUT payload is assembled. Queue it as ONE transfer.
    const std::vector<std::uint8_t> full = _rx.take(h);
    const SubmitBody sb = _rxSb;

    Header reqHeader;
    reqHeader.type      = static_cast<std::uint8_t>(wire::Type::Submit);
    reqHeader.channel   = _rxChannel;
    reqHeader.requestId = _rxRequestId;
    reqHeader.attachId  = _attachId;

    resetReassembly();
    return enqueueTransfer(reqHeader, sb, full);
}

// ---------------------------------------------------------------------------
// Queue, admit, collect
// ---------------------------------------------------------------------------

Status ExporterSession::enqueueTransfer(const Header& reqHeader, const SubmitBody& sb,
                                        std::span<const std::uint8_t> dataOut)
{
    // BOUNDED, and the bound is the credit ATTACH_OK advertised.
    //
    // The queue used to just append. ATTACH_OK told the importer 64 URBs and
    // 4 MiB and nothing enforced either, so a peer that submitted faster than
    // the device drains grew this without limit — and because `pump()` reads
    // until the transport says Busy BEFORE collecting outcomes, a continuously
    // readable peer could postpone collection while doing it.
    //
    // Refused honestly rather than dropped: the importer gets a COMPLETE with
    // NoResources for the transfer it could not have, which is a terminal
    // outcome like any other and keeps invariant I1.
    std::size_t queued = 0;
    std::size_t bytes  = 0;
    for (const auto& [ep, q] : _queues) {
        queued += q.size();
        for (const Pending& e : q) bytes += e.dataOut.size();
    }
    if (queued + _inFlight.size() >= kCreditUrbs ||
        bytes + dataOut.size() > kCreditBytes) {
        InFlight f;
        f.channel   = reqHeader.channel;
        f.requestId = reqHeader.requestId;
        f.epAddr    = sb.epAddr;
        f.sb        = sb;
        return emitComplete(f, Status::NoResources, 0, false, false, {});
    }

    Pending p;
    p.channel   = reqHeader.channel;
    p.requestId = reqHeader.requestId;
    p.sb        = sb;
    p.dataOut.assign(dataOut.begin(), dataOut.end());

    // The deadline is stamped when WE accept it, not when it later reaches the
    // device. A transfer queued behind a busy endpoint would otherwise have no
    // clock at all, which is how a stuck endpoint turns into an unbounded queue.
    p.deadline = Deadline::afterMs(*_clock, deadlineMsFor(sb.xferType));

    _queues[sb.epAddr].push_back(std::move(p));
    return Status::Ok;
}

bool ExporterSession::mayAdmit(std::uint8_t epAddr) const
{
    if (isEp0(epAddr)) {
        // ep0 is a device-wide barrier: a control transfer may change the
        // configuration or an alternate setting, which redefines every other
        // endpoint. Admitting one alongside data transfers means the device's
        // endpoint table can change under a transfer already on the bus.
        return _inFlight.empty();
    }
    for (const auto& [token, f] : _inFlight)
        if (isEp0(f.epAddr)) return false;
    return _busyEndpoint.find(epAddr) == _busyEndpoint.end();
}

void ExporterSession::admit()
{
    if (!_port || _state != State::Leased) return;

    // Bounded: one pass over the endpoints per pump. A queue that refilled
    // faster than it drained could otherwise keep this loop running while the
    // socket goes unread, which is the same starvation the whole redesign is
    // about.
    for (auto& [epAddr, q] : _queues) {
        if (q.empty()) continue;
        if (!mayAdmit(epAddr)) continue;

        Pending p = std::move(q.front());
        q.pop_front();

        AsyncTransfer t;
        t.epAddr    = p.sb.epAddr;
        t.xferType  = static_cast<XferType>(p.sb.xferType);
        t.dir       = static_cast<Dir>(p.sb.dir);
        t.bufferLen = p.sb.bufferLen;
        t.dataOut   = std::span<const std::uint8_t>(p.dataOut.data(), p.dataOut.size());
        t.timeoutMs = deadlineMsFor(p.sb.xferType);
        // xflags used to be decoded and then dropped on the floor. ZERO_PACKET
        // in particular is not cosmetic: without it a device waiting for the
        // terminating ZLP after an exact-multiple OUT waits for ever.
        t.zeroPacket = (p.sb.xflags & wire::kXfZeroPacket) != 0;
        t.shortNotOk = (p.sb.xflags & wire::kXfShortNotOk) != 0;

        if (t.xferType == XferType::Control) {
            t.setup.bmRequestType = p.sb.setup[0];
            t.setup.bRequest      = p.sb.setup[1];
            t.setup.wValue  = static_cast<std::uint16_t>(p.sb.setup[2] | (p.sb.setup[3] << 8));
            t.setup.wIndex  = static_cast<std::uint16_t>(p.sb.setup[4] | (p.sb.setup[5] << 8));
            t.setup.wLength = static_cast<std::uint16_t>(p.sb.setup[6] | (p.sb.setup[7] << 8));
        }

        const std::uint64_t token = _nextToken++;
        const Status s = _port->submit(token, t);
        if (s == Status::Busy) {
            // The port has no room. Put it back at the FRONT — a transfer that
            // loses its place in its own endpoint's queue is a transfer
            // reordered on an endpoint USB guarantees is ordered.
            q.push_front(std::move(p));
            continue;
        }

        InFlight f;
        f.channel   = p.channel;
        f.requestId = p.requestId;
        f.epAddr    = p.sb.epAddr;
        f.sb        = p.sb;
        f.deadline  = p.deadline;

        if (s != Status::Ok) {
            // The port refused it outright and will produce no outcome, so this
            // is the one place a transfer is answered without the device ever
            // seeing it. I1 still holds: exactly one terminal outcome.
            (void)emitComplete(f, s, 0, false, false, {});
            continue;
        }

        _inFlight[token]      = f;
        _busyEndpoint[epAddr] = token;
    }
}

Status ExporterSession::collect()
{
    if (!_port) return Status::Ok;

    Status worst = Status::Ok;

    _port->poll([&](const AsyncOutcome& o) {
        // A verb (CLEAR_HALT, DEVICE_RESET) rather than a transfer.
        if (auto v = _verbs.find(o.token); v != _verbs.end()) {
            const PendingVerb pv = v->second;
            _verbs.erase(v);
            if (pv.isReset) {
                // Every leg's status counts. requestId 0 marks a non-final leg,
                // whose result is REMEMBERED rather than discarded.
                if (_resetPending != 0) --_resetPending;
                if (o.status != Status::Ok && _resetWorst == Status::Ok)
                    _resetWorst = o.status;
                if (pv.requestId != 0)
                    (void)sendSimple(wire::Type::CtrlAck, _resetWorst, pv.requestId, {});
            } else if (pv.requestId != 0) {
                (void)sendSimple(wire::Type::CtrlAck, o.status, pv.requestId, {});
            }
            return;
        }

        // THE ENDPOINT IS FREED FIRST, and unconditionally.
        //
        // It used to be freed only on the path that found the transfer in
        // `_inFlight`, which leaks the slot in exactly the case the slot exists
        // for: `sweepDeadlines()` answers a transfer the port could not cancel
        // and removes it from `_inFlight` while DELIBERATELY leaving the
        // endpoint reserved, and the port's eventual outcome then took the
        // early return below. The endpoint stayed busy for the life of the
        // session and every later transfer on it queued behind nothing.
        for (auto b = _busyEndpoint.begin(); b != _busyEndpoint.end(); ++b) {
            if (b->second == o.token) { _busyEndpoint.erase(b); break; }
        }

        auto it = _inFlight.find(o.token);
        if (it == _inFlight.end()) {
            // A late outcome for a transfer already retired. Normal after a
            // cancellation or a deadline; never an error, and never delivered
            // twice.
            return;
        }
        const InFlight f = it->second;
        _inFlight.erase(it);

        // `kCfWasCancelled` says the transfer WAS cancelled, so it comes from
        // what the port actually did — not from the fact that somebody asked.
        // A backend that could not abort and whose device then finished
        // normally has completed the transfer, and reporting real data beside
        // a cancelled flag is a contradiction the importer cannot act on.
        const Status s = emitComplete(f, o.status, o.actualLen, o.cancelled,
                                      o.zlpSent, o.dataIn);
        if (isFatal(s)) worst = s;
    });

    return worst;
}

Status ExporterSession::sweepDeadlines()
{
    Status worst = Status::Ok;
    const ContinuousNs now = _clock->nowNs();
    (void)now;

    // Queued: never reached the device, so a clean local timeout.
    for (auto& [epAddr, q] : _queues) {
        std::deque<Pending> keep;
        while (!q.empty()) {
            Pending p = std::move(q.front());
            q.pop_front();
            if (p.deadline.expired(*_clock)) {
                InFlight f;
                f.channel   = p.channel;
                f.requestId = p.requestId;
                f.epAddr    = p.sb.epAddr;
                f.sb        = p.sb;
                const Status s = emitComplete(f, Status::XferTimeout, 0, false, false, {});
                if (isFatal(s)) worst = s;
            } else {
                keep.push_back(std::move(p));
            }
        }
        q = std::move(keep);
    }

    // In flight: the device still owns it. Tell the port to stop, and only
    // retire our own record once it reports back — a transfer answered here AND
    // again by the port's eventual outcome is answered twice.
    // `cancelRequested` marks a transfer the PORT accepted a cancel for and
    // will report through `poll()`. Those are skipped because their outcome is
    // already on its way. A cancel the port REFUSED never sets the flag, so its
    // deadline still fires — which is the only terminal outcome it can get.
    std::vector<std::uint64_t> expired;
    for (auto& [token, f] : _inFlight)
        if (f.deadline.expired(*_clock) && !f.cancelRequested) expired.push_back(token);

    for (const std::uint64_t token : expired) {
        auto it = _inFlight.find(token);
        if (it == _inFlight.end()) continue;
        it->second.cancelRequested = true;
        if (_port && _port->cancel(token)) continue;   // outcome will arrive via poll()

        // The port cannot stop it. Answer the peer now — it has waited past the
        // ceiling and is entitled to a terminal status — but keep the endpoint
        // reserved, because the physical transfer really is still running and
        // starting another on the same endpoint would desynchronise it.
        const InFlight f = it->second;
        _inFlight.erase(it);
        const Status s = emitComplete(f, Status::XferTimeout, 0, false, false, {});
        if (isFatal(s)) worst = s;
    }

    return worst;
}

Status ExporterSession::emitComplete(const InFlight& f, Status st, std::uint32_t actualLen,
                                     bool cancelled, bool zlpSent,
                                     std::span<const std::uint8_t> payload)
{
    const bool isIn = f.sb.dir == static_cast<std::uint8_t>(wire::Dir::In);

    CompleteBody cb;
    cb.epAddr       = f.sb.epAddr;
    cb.xferType     = f.sb.xferType;
    cb.dir          = f.sb.dir;
    cb.requestedLen = f.sb.bufferLen;
    cb.submitTsNs   = f.sb.submitTsNs;
    cb.actualLen    = actualLen;
    cb.payloadLen   = isIn ? static_cast<std::uint32_t>(payload.size()) : 0;

    if (isIn) cb.actualLen = static_cast<std::uint32_t>(payload.size());
    if (st == Status::Ok && cb.actualLen < cb.requestedLen) cb.cflags |= wire::kCfShort;
    if (cancelled) cb.cflags |= wire::kCfWasCancelled;
    if (zlpSent)   cb.cflags |= wire::kCfZlpSent;

    // R5, re-asserted at the copy site: the device cannot have moved more than
    // was asked for. This is the check that stops a buggy or hostile exporter
    // overrunning a kernel transfer buffer whose size the importer's own kernel
    // chose (CVE-2016-3955 class).
    if (cb.actualLen > cb.requestedLen) {
        Header err;
        err.type      = static_cast<std::uint8_t>(wire::Type::Submit);
        err.channel   = f.channel;
        err.requestId = f.requestId;
        return refuse(err, Status::Internal, "device reported more than was requested");
    }

    Header base;
    base.type      = static_cast<std::uint8_t>(wire::Type::Complete);
    base.channel   = f.channel;
    base.attachId  = _attachId;
    base.requestId = f.requestId;
    base.status    = static_cast<std::uint16_t>(st);

    std::vector<std::uint8_t> cbody;
    encodeComplete(cb, cbody);

    const std::uint32_t maxPlain = _secure->transport()->maxPlaintextBytes();
    if (maxPlain <= wire::kHeaderSize + wire::kBodyComplete) return Status::Internal;
    const std::uint32_t maxSeg = maxPlain - static_cast<std::uint32_t>(wire::kHeaderSize)
                                          - static_cast<std::uint32_t>(wire::kBodyComplete);

    ++_transfers;
    return emitTransfer(base, cbody, isIn ? payload : std::span<const std::uint8_t>{},
                        maxSeg,
                        [this](std::span<const std::uint8_t> rec) { return sendRecord(rec); });
}

void ExporterSession::failAllTransfers(Status st)
{
    // The device first, so nothing it is holding can arrive after we have
    // declared it finished. `abortAll` produces exactly one outcome per token,
    // and those outcomes are answered here rather than being dropped.
    if (_port) {
        _port->abortAll(st, [&](const AsyncOutcome& o) {
            if (auto v = _verbs.find(o.token); v != _verbs.end()) {
                const PendingVerb pv = v->second;
                _verbs.erase(v);
                if (pv.requestId != 0)
                    (void)sendSimple(wire::Type::CtrlAck, o.status, pv.requestId, {});
                return;
            }
            auto it = _inFlight.find(o.token);
            if (it == _inFlight.end()) return;
            const InFlight f = it->second;
            _inFlight.erase(it);
            (void)emitComplete(f, o.status == Status::Ok ? st : o.status,
                               o.actualLen, /*cancelled=*/true, o.zlpSent, o.dataIn);
        });
    }

    // Anything the port did not know about — queued, or in flight on a port that
    // has already gone away — is answered here. Nothing may evaporate.
    for (auto& [token, f] : _inFlight)
        (void)emitComplete(f, st, 0, /*cancelled=*/true, false, {});
    _inFlight.clear();
    _busyEndpoint.clear();

    for (auto& [epAddr, q] : _queues) {
        while (!q.empty()) {
            Pending p = std::move(q.front());
            q.pop_front();
            InFlight f;
            f.channel   = p.channel;
            f.requestId = p.requestId;
            f.epAddr    = p.sb.epAddr;
            f.sb        = p.sb;
            (void)emitComplete(f, st, 0, /*cancelled=*/true, false, {});
        }
    }
    _queues.clear();

    for (auto& [token, v] : _verbs)
        if (v.requestId != 0) (void)sendSimple(wire::Type::CtrlAck, st, v.requestId, {});
    _verbs.clear();
}

void ExporterSession::resetReassembly() noexcept
{
    _rxActive    = false;
    _rxChannel   = 0;
    _rxRequestId = 0;
    _rx.clear();
}

void ExporterSession::close()
{
    resetReassembly();
    // Transfers are retired before the port is dropped, so the device is told to
    // stop rather than being abandoned with work outstanding.
    if (_port) failAllTransfers(Status::Detaching);

    if (_port) {
        // THE CAPTURE IS ONLY RELEASED IF NOBODY STILL OWNS IT.
        //
        // This unconditionally called `release()`, and that put the original bug
        // back one level up. `HubState` drops a peer that vanished by calling
        // close(), the lease is Quarantined at that moment by design, and
        // releasing the device source ends the capture — handing a possibly
        // dirty drive back to the local OS while the vanished peer still owns
        // it. The lease said "held for that machine" and the device source was
        // told otherwise in the same breath.
        //
        // Found by an adversarial read of this session's own code (GPT-5.6,
        // 2026-08-09), which is the whole argument for asking.
        const bool stillOwned = _leases != nullptr &&
                                _leases->state() != LeaseState::Free;
        if (!stillOwned) _devices->release(_uid);
        _port = nullptr;
    }
    _attachId = 0;
    if (_state != State::Closed) _state = State::Idle;
}

} // namespace airusb::session
