#include "RemoteDevicePort.h"

#include "../core/Watchdog.h"
#include "../protocol/Segmentation.h"
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

std::uint32_t RemoteDevicePort::maxSegmentBytes() const noexcept
{
    if (!_link) return 0;
    const std::uint32_t maxPlain = _link->maxPlaintextBytes();
    const std::uint32_t fixed = static_cast<std::uint32_t>(wire::kHeaderSize)
                              + static_cast<std::uint32_t>(wire::kBodySubmit);
    return maxPlain > fixed ? maxPlain - fixed : 0;
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

    const bool isOut = (dir == static_cast<std::uint8_t>(wire::Dir::Out));

    SubmitBody sb;
    sb.epAddr    = epAddr;
    sb.xferType  = xferType;
    sb.dir       = dir;
    sb.bufferLen = bufferLen;
    sb.timeoutMs = static_cast<std::uint32_t>(watchdog::kUrbCeilingBulk);
    if (setup) std::memcpy(sb.setup, setup, 8);

    std::vector<std::uint8_t> submitBody;
    encodeSubmit(sb, submitBody);

    const std::uint64_t rid = ++_requestId;

    Header base;
    base.type      = static_cast<std::uint8_t>(wire::Type::Submit);
    // §3.4: the channel is derived, never negotiated. Both peers compute it
    // identically, which is what removes the per-endpoint open round trip that
    // the Linux vhci shim could not have provided anyway.
    base.channel   = static_cast<std::uint16_t>((_attachSlot << 8) | epAddr);
    base.attachId  = _attachId;
    base.requestId = rid;
    base.status    = 0;

    // The DATA payload is buffer_len bytes on OUT and nothing on IN; that is what
    // gets segmented. The 40-byte SubmitBody rides on record 0 only. A transfer
    // that fits in one record emits exactly one record — the common case is
    // unchanged.
    const std::span<const std::uint8_t> outData =
        isOut ? dataOut : std::span<const std::uint8_t>{};

    const std::uint32_t maxPlain = _link->maxPlaintextBytes();
    if (maxPlain <= wire::kHeaderSize + wire::kBodySubmit) return Status::Internal;
    const std::uint32_t maxSeg = maxPlain - static_cast<std::uint32_t>(wire::kHeaderSize)
                                          - static_cast<std::uint32_t>(wire::kBodySubmit);

    if (outData.size() > maxSeg) ++_segmentedOut;

    if (const Status s = emitTransfer(base, submitBody, outData, maxSeg,
            [this](std::span<const std::uint8_t> rec) { return _link->sendRecord(rec); });
        s != Status::Ok)
        return s;
    if (const Status s = _link->flush(); s != Status::Ok) return s;

    ++_issued;

    // ---- wait for record 0 of the COMPLETE ---------------------------------
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
    lim.maxRecordBytes   = _link->maxRecordBytes();
    lim.maxTransferBytes = bufferLen;
    const auto firstChunk = rbody.subspan(wire::kBodyComplete);
    if (auto v = validateComplete(rh, cb, firstChunk, lim); !v.ok()) return v.status;

    // R5 at the copy site, not only in the validator. This is the check that
    // stops a buggy or hostile exporter overrunning a buffer whose size OUR
    // kernel chose — CVE-2016-3955 class, and the reason R5 is asserted twice.
    // It must bound the FULL transfer before we reassemble anything.
    if (cb.actualLen > bufferLen) return Status::XferOverrun;

    if (dir == static_cast<std::uint8_t>(wire::Dir::In)) {
        if (cb.payloadLen > bufferLen) return Status::XferOverrun;

        if (!rh.segMore()) {
            // The whole payload is in this one record — the common small case,
            // byte-for-byte the behaviour before segmentation existed.
            if (cb.payloadLen > firstChunk.size()) return Status::MalformedFrame;
            dataIn.assign(firstChunk.begin(),
                          firstChunk.begin() + static_cast<std::ptrdiff_t>(cb.payloadLen));
        } else {
            // Segmented: reassemble the payload across the Data continuations and
            // hand nothing up until it is whole. One transfer is outstanding, so
            // the arena and in-flight caps are as tight as they can be.
            Reassembler::Limits rl;
            rl.maxTransferBytes = bufferLen;
            rl.arenaBytes       = bufferLen;
            rl.maxInFlight      = 1;
            Reassembler ra(rl);
            ++_segmentedIn;

            Status e = Status::Ok;
            Reassembler::Outcome o = ra.accept(rh, firstChunk, e);
            if (o == Reassembler::Outcome::Rejected) return e;

            std::vector<std::uint8_t> dr;
            while (o == Reassembler::Outcome::NeedMore) {
                for (;;) {
                    const Status r = _link->receiveRecord(dr);
                    if (r == Status::Busy) continue;
                    if (r != Status::Ok) return r;
                    if (!dr.empty()) break;
                }
                Header dh;
                if (!decodeHeader(dr, dh)) return Status::MalformedFrame;
                if (dr.size() - wire::kHeaderSize < dh.bodyLen) return Status::MalformedFrame;
                // A continuation is a Data record on the exact same (channel,
                // request_id); anything else on this stream means the framing is
                // misaligned, and with one transfer outstanding there is no other
                // legitimate id to see.
                if (dh.type != static_cast<std::uint8_t>(wire::Type::Data))
                    return Status::MalformedFrame;
                if (dh.channel != rh.channel || dh.requestId != rid)
                    return Status::MalformedFrame;
                if (auto v = validateHeader(dh, dr.size() - wire::kHeaderSize, lim); !v.ok())
                    return v.status;
                ++_inContinuations;

                const auto dbody = std::span<const std::uint8_t>(dr)
                                      .subspan(wire::kHeaderSize, dh.bodyLen);
                o = ra.accept(dh, dbody, e);
                if (o == Reassembler::Outcome::Rejected) return e;
            }
            dataIn = ra.take(rh);
        }
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
