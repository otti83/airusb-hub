#include "RemoteDevicePort.h"

#include "../core/Watchdog.h"
#include "../protocol/Validate.h"

#include <cstring>

namespace airusb::session {

using namespace airusb::protocol;

RemoteDevicePort::RemoteDevicePort(transport::RecordLayer* link,
                                   std::uint32_t attachId,
                                   std::uint8_t attachSlot,
                                   DeviceManifest manifest) noexcept
    : _link(link), _manifest(std::move(manifest)),
      _attachId(attachId), _attachSlot(attachSlot)
{
}

Status RemoteDevicePort::submit(std::uint8_t epAddr, std::uint8_t xferType,
                                std::uint8_t dir, std::uint32_t bufferLen,
                                const std::uint8_t setup[8],
                                std::span<const std::uint8_t> dataOut,
                                std::vector<std::uint8_t>& dataIn,
                                std::uint32_t* actualLen)
{
    dataIn.clear();
    if (actualLen) *actualLen = 0;
    if (!_link) return Status::TransportLost;

    SubmitBody sb;
    sb.epAddr    = epAddr;
    sb.xferType  = xferType;
    sb.dir       = dir;
    sb.bufferLen = bufferLen;
    sb.timeoutMs = static_cast<std::uint32_t>(watchdog::kUrbCeilingBulk);
    if (setup) std::memcpy(sb.setup, setup, 8);

    std::vector<std::uint8_t> body;
    encodeSubmit(sb, body);
    if (dir == static_cast<std::uint8_t>(wire::Dir::Out))
        body.insert(body.end(), dataOut.begin(), dataOut.end());

    const std::uint64_t rid = ++_requestId;

    Header h;
    h.type      = static_cast<std::uint8_t>(wire::Type::Submit);
    h.flags     = wire::kFlagSegFirst;
    // §3.4: the channel is derived, never negotiated. Both peers compute it
    // identically, which is what removes the per-endpoint open round trip that
    // the Linux vhci shim could not have provided anyway.
    h.channel   = static_cast<std::uint16_t>((_attachSlot << 8) | epAddr);
    h.attachId  = _attachId;
    h.requestId = rid;
    h.bodyLen   = static_cast<std::uint32_t>(body.size());
    // total_len is the DATA payload only: buffer_len on OUT, nothing on IN.
    h.totalLen  = (dir == static_cast<std::uint8_t>(wire::Dir::Out)) ? bufferLen : 0;

    std::vector<std::uint8_t> rec;
    encodeHeader(h, rec);
    rec.insert(rec.end(), body.begin(), body.end());

    if (const Status s = _link->sendRecord(rec); s != Status::Ok) return s;
    if (const Status s = _link->flush(); s != Status::Ok) return s;

    ++_issued;

    // ---- wait for the COMPLETE ---------------------------------------------
    std::vector<std::uint8_t> in;
    for (;;) {
        const Status r = _link->receiveRecord(in);
        if (r == Status::Busy) continue;          // caller's loop drives the socket
        if (r != Status::Ok) return r;
        if (!in.empty()) break;
    }

    Header rh;
    if (!decodeHeader(in, rh)) return Status::MalformedFrame;
    if (in.size() - wire::kHeaderSize < rh.bodyLen) return Status::MalformedFrame;

    if (rh.type != static_cast<std::uint8_t>(wire::Type::Complete)) {
        // An ERROR (or anything else) in place of a COMPLETE carries the reason
        // in its status. Reporting that beats a generic failure.
        const Status s = static_cast<Status>(rh.status);
        return s == Status::Ok ? Status::MalformedFrame : s;
    }
    if (rh.requestId != rid) return Status::MalformedFrame;

    const auto rbody = std::span<const std::uint8_t>(in)
                          .subspan(wire::kHeaderSize, rh.bodyLen);

    CompleteBody cb;
    if (!decodeComplete(rbody, cb)) return Status::MalformedFrame;

    Limits lim;
    lim.maxRecordBytes = _link->maxRecordBytes();
    const auto payload = rbody.subspan(wire::kBodyComplete);
    if (auto v = validateComplete(rh, cb, payload, lim); !v.ok()) return v.status;

    // R5 at the copy site, not only in the validator. This is the check that
    // stops a buggy or hostile exporter overrunning a buffer whose size OUR
    // kernel chose — CVE-2016-3955 class, and the reason R5 is asserted twice.
    if (cb.actualLen > bufferLen) return Status::XferOverrun;
    if (cb.payloadLen > payload.size()) return Status::MalformedFrame;

    if (dir == static_cast<std::uint8_t>(wire::Dir::In)) {
        if (cb.payloadLen > bufferLen) return Status::XferOverrun;
        dataIn.assign(payload.begin(),
                      payload.begin() + static_cast<std::ptrdiff_t>(cb.payloadLen));
    }
    if (actualLen) *actualLen = cb.actualLen;

    return static_cast<Status>(rh.status);
}

Status RemoteDevicePort::controlTransfer(const SetupPacket& setup,
                                         std::span<const std::uint8_t> dataOut,
                                         std::vector<std::uint8_t>& dataIn)
{
    std::uint8_t raw[8];
    raw[0] = setup.bmRequestType;
    raw[1] = setup.bRequest;
    raw[2] = static_cast<std::uint8_t>(setup.wValue);
    raw[3] = static_cast<std::uint8_t>(setup.wValue >> 8);
    raw[4] = static_cast<std::uint8_t>(setup.wIndex);
    raw[5] = static_cast<std::uint8_t>(setup.wIndex >> 8);
    raw[6] = static_cast<std::uint8_t>(setup.wLength);
    raw[7] = static_cast<std::uint8_t>(setup.wLength >> 8);

    const std::uint8_t dir = static_cast<std::uint8_t>(
        setup.direction() == Dir::In ? wire::Dir::In : wire::Dir::Out);

    return submit(0, static_cast<std::uint8_t>(wire::XferType::Control), dir,
                  setup.wLength, raw, dataOut, dataIn, nullptr);
}

Status RemoteDevicePort::bulkOut(std::uint8_t epAddr,
                                 std::span<const std::uint8_t> data,
                                 std::uint32_t* actualLen)
{
    std::vector<std::uint8_t> unused;
    return submit(epAddr, static_cast<std::uint8_t>(wire::XferType::Bulk),
                  static_cast<std::uint8_t>(wire::Dir::Out),
                  static_cast<std::uint32_t>(data.size()), nullptr,
                  data, unused, actualLen);
}

Status RemoteDevicePort::bulkIn(std::uint8_t epAddr, std::uint32_t maxLen,
                                std::vector<std::uint8_t>& out)
{
    return submit(epAddr, static_cast<std::uint8_t>(wire::XferType::Bulk),
                  static_cast<std::uint8_t>(wire::Dir::In),
                  maxLen, nullptr, {}, out, nullptr);
}

Status RemoteDevicePort::clearHalt(std::uint8_t epAddr)
{
    // ep0 never holds a persistent halt — a control STALL is per-transfer — so
    // there is nothing to clear and nothing to send.
    if ((epAddr & 0x7Fu) == 0) return Status::Ok;

    // EP_CLEAR_HALT is a VERB, not a forwarded CLEAR_FEATURE: the exporter must
    // also clear its own host controller's data toggle, which a raw forward does
    // not do, leaving every later transfer on that endpoint silently wrong.
    Header h;
    h.type      = static_cast<std::uint8_t>(wire::Type::EpClearHalt);
    h.flags     = wire::kFlagSegFirst | wire::kFlagExpedite;
    h.channel   = static_cast<std::uint16_t>((_attachSlot << 8) | epAddr);
    h.attachId  = _attachId;
    h.requestId = ++_requestId;
    h.bodyLen   = 0;
    h.totalLen  = 0;

    std::vector<std::uint8_t> rec;
    encodeHeader(h, rec);
    if (const Status s = _link->sendRecord(rec); s != Status::Ok) return s;
    if (const Status s = _link->flush(); s != Status::Ok) return s;

    // Waits for CTRL_ACK rather than firing and forgetting. A verb whose reply
    // is left in the stream would be read by the NEXT transfer as its own
    // COMPLETE — and a stall recovery is followed immediately by a transfer, so
    // that misread is the common case rather than a rare one.
    std::vector<std::uint8_t> in;
    for (;;) {
        const Status r = _link->receiveRecord(in);
        if (r == Status::Busy) continue;
        if (r != Status::Ok) return r;
        if (!in.empty()) break;
    }

    Header rh;
    if (!decodeHeader(in, rh)) return Status::MalformedFrame;
    if (rh.requestId != h.requestId) return Status::MalformedFrame;
    if (rh.type != static_cast<std::uint8_t>(wire::Type::CtrlAck)) {
        const Status s = static_cast<Status>(rh.status);
        return s == Status::Ok ? Status::MalformedFrame : s;
    }
    return static_cast<Status>(rh.status);
}

} // namespace airusb::session
