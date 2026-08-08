#include "ExporterSession.h"

#include "../core/Watchdog.h"
#include "../protocol/Codec.h"
#include "../protocol/ManifestCodec.h"
#include "../protocol/Validate.h"

#include <cstring>

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

} // namespace

// ---------------------------------------------------------------------------

Status ExporterSession::begin(SecureSession* secure, const Config& cfg)
{
    if (!secure || !secure->established()) return Status::BadArgument;
    if (!cfg.devices || !cfg.clock) return Status::BadArgument;

    _secure   = secure;
    _devices  = cfg.devices;
    _clock    = cfg.clock;
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

Status ExporterSession::pump()
{
    transport::RecordLayer* t = _secure->transport();
    if (!t) return Status::TransportLost;

    for (;;) {
        std::vector<std::uint8_t> rec;
        const Status r = t->receiveRecord(rec);
        if (r == Status::Busy) return Status::Ok;
        if (r != Status::Ok) {
            if (r == Status::TransportLost) {
                // §7.3: silence does NOT release the capture. The device stays
                // held until an explicit detach or the lease timer expires.
                if (_state == State::Leased) _state = State::Orphaned;
            }
            return r;
        }
        if (rec.empty()) return Status::Ok;

        _lastHeardNs = _clock->nowNs();

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

    IUsbDevicePort* port = nullptr;
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

    _port        = port;
    _manifest    = std::move(manifest);
    _configValue = configValue;
    _uid         = a.uid;
    _attachSlot  = a.attachSlot;
    _attachId    = _nextAttachId++;
    ++_leaseEpoch;

    // The manifest is built and validated BEFORE anything is announced. §7.2
    // step 9: the importer never learns the device exists until it is fully
    // captured and fully described.
    std::vector<std::uint8_t> manifestBody;
    if (const Status s = encodeManifest(_manifest, _configValue, manifestBody);
        s != Status::Ok) {
        _devices->release(_uid);
        _port = nullptr;
        _attachId = 0;
        return refuse(h, Status::ManifestInvalid,
                      "This device's descriptors could not be read.");
    }

    AttachOkBody ok;
    ok.attachId          = _attachId;
    ok.creditUrbs        = 64;
    ok.creditBytes       = 4u * 1024 * 1024;
    ok.speed             = static_cast<std::uint16_t>(_manifest.speed());
    ok.cancelGranularity = 0;                    // macOS: ENDPOINT scope only
    ok.exporterFlags     = kExpSupportsDeviceReset;
    ok.manifestLen       = static_cast<std::uint32_t>(manifestBody.size());
    ok.leaseEpoch        = _leaseEpoch;
    ok.urbCeilingMs      = static_cast<std::uint32_t>(watchdog::kUrbCeilingBulk);

    std::vector<std::uint8_t> okBody;
    encodeAttachOk(ok, okBody);
    if (const Status s = sendSimple(wire::Type::AttachOk, Status::Ok, h.requestId, okBody);
        s != Status::Ok)
        return s;

    if (const Status s = sendSimple(wire::Type::DeviceManifest, Status::Ok,
                                    h.requestId, manifestBody); s != Status::Ok) {
        // A manifest larger than one record needs segmentation, which the data
        // plane has and the control plane does not yet. A device with eight
        // configurations and a full string table could reach it. Failing here
        // with a clear status beats a truncated manifest.
        _devices->release(_uid);
        _port = nullptr;
        _attachId = 0;
        _state = State::Idle;
        return refuse(h, s, "This device's descriptor set is too large to send.");
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

    _state = State::Draining;

    // With one transfer in flight at a time there is nothing to drain yet. When
    // the data plane goes asynchronous this is where outstanding URBs are driven
    // to a COMPLETE within drain_timeout_ms and anything left is cancelled.
    DetachOkBody ok;
    // The counter is 64-bit; the wire field is 32. A session that moved more
    // than 4 billion URBs saturates rather than wrapping to a small number,
    // because a wrapped count reads as a successful tiny drain.
    ok.urbsCompleted = _transfers > 0xFFFFFFFFull
                         ? 0xFFFFFFFFu
                         : static_cast<std::uint32_t>(_transfers);

    std::vector<std::uint8_t> okBody;
    encodeDetachOk(ok, okBody);
    const Status s = sendSimple(wire::Type::DetachOk, Status::Ok, h.requestId, okBody);

    // Release order (§7.6) is the device source's business; it destroys the
    // device before unclaiming the disk.
    _devices->release(_uid);
    _port     = nullptr;
    _attachId = 0;
    _state    = State::Idle;
    return s;
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

    CompleteBody cb;
    cb.epAddr       = sb.epAddr;
    cb.xferType     = sb.xferType;
    cb.dir          = sb.dir;
    cb.requestedLen = sb.bufferLen;
    cb.submitTsNs   = sb.submitTsNs;

    std::vector<std::uint8_t> payload;
    Status st = Status::Ok;

    if (sb.xferType == static_cast<std::uint8_t>(wire::XferType::Control)) {
        SetupPacket sp;
        sp.bmRequestType = sb.setup[0];
        sp.bRequest      = sb.setup[1];
        sp.wValue        = static_cast<std::uint16_t>(sb.setup[2] | (sb.setup[3] << 8));
        sp.wIndex        = static_cast<std::uint16_t>(sb.setup[4] | (sb.setup[5] << 8));
        sp.wLength       = static_cast<std::uint16_t>(sb.setup[6] | (sb.setup[7] << 8));
        st = _port->controlTransfer(sp, dataSection, payload);
    } else if (sb.dir == static_cast<std::uint8_t>(wire::Dir::In)) {
        st = _port->bulkIn(sb.epAddr, sb.bufferLen, payload);
    } else {
        std::uint32_t moved = 0;
        st = _port->bulkOut(sb.epAddr, dataSection, &moved);
        cb.actualLen = moved;
    }

    if (sb.dir == static_cast<std::uint8_t>(wire::Dir::In)) {
        cb.actualLen  = static_cast<std::uint32_t>(payload.size());
        cb.payloadLen = static_cast<std::uint32_t>(payload.size());
    } else {
        cb.payloadLen = 0;
    }
    if (st == Status::Ok && cb.actualLen < cb.requestedLen) cb.cflags |= wire::kCfShort;

    // R5, re-asserted at the copy site: the device cannot have moved more than
    // was asked for. This is the check that stops a buggy or hostile exporter
    // overrunning a kernel transfer buffer whose size the importer's own kernel
    // chose (CVE-2016-3955 class).
    if (cb.actualLen > cb.requestedLen)
        return refuse(h, Status::Internal, "device reported more than was requested");

    Header rh;
    rh.type      = static_cast<std::uint8_t>(wire::Type::Complete);
    rh.flags     = wire::kFlagSegFirst;
    rh.channel   = h.channel;
    rh.attachId  = _attachId;
    rh.requestId = h.requestId;
    rh.status    = static_cast<std::uint16_t>(st);

    std::vector<std::uint8_t> cbody;
    encodeComplete(cb, cbody);
    cbody.insert(cbody.end(), payload.begin(), payload.end());
    rh.bodyLen  = static_cast<std::uint32_t>(cbody.size());
    // §3.6 exactness: total_len == iso_pkt_count*16 + payload_len. The fixed
    // 40-byte COMPLETE body is not part of it.
    rh.totalLen = cb.payloadLen;

    std::vector<std::uint8_t> rec;
    encodeHeader(rh, rec);
    rec.insert(rec.end(), cbody.begin(), cbody.end());

    ++_transfers;
    return sendRecord(rec);
}

void ExporterSession::close()
{
    if (_port) {
        _devices->release(_uid);
        _port = nullptr;
    }
    _attachId = 0;
    if (_state != State::Closed) _state = State::Idle;
}

} // namespace airusb::session
