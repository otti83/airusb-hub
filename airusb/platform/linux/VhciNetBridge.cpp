#include "VhciNetBridge.h"

#include <algorithm>

namespace airusb::linuxvhci {

using session::DataCompletion;

VhciNetBridge::VhciNetBridge(transport::IByteStream& kernel, session::ImporterDataPlane& plane,
                             const DeviceManifest& manifest, const Config& cfg) noexcept
    : _kernel(kernel), _plane(plane), _manifest(manifest), _arbiter(manifest), _cfg(cfg)
{
}

// ---------------------------------------------------------------------------
// The one non-blocking step. Order is load-bearing: the kernel is drained BEFORE
// anything touches the network (R-A), and replies are buffered, never blocked on
// (R-B).
// ---------------------------------------------------------------------------

Status VhciNetBridge::poll()
{
    const Status ks = drainKernel();
    if (ks != Status::Ok && ks != Status::TransportLost) { (void)flushKernel(); return ks; }
    const bool kernelGone = (ks == Status::TransportLost);

    admitPending();
    const Status ps = pumpPlane();
    admitPending();                 // a completion may have freed the one admission slot

    const Status fs = flushKernel();

    if (ps != Status::Ok) {
        // The network is gone. Complete every outstanding and queued URB with
        // -ENODEV so no kernel URB waits forever, then report the session over.
        failAll(Status::DeviceGone);
        (void)flushKernel();
        return Status::TransportLost;
    }
    if (fs == Status::TransportLost || kernelGone) return Status::TransportLost;
    if (fs != Status::Ok) return fs;
    return Status::Ok;
}

// ---------------------------------------------------------------------------
// Kernel side — non-blocking framed I/O.
// ---------------------------------------------------------------------------

bool VhciNetBridge::nextPdu(UsbipPdu& pdu, std::span<const std::uint8_t>& payload)
{
    const std::size_t avail = _rx.size() - _rxHead;
    if (avail < kPduBytes) return false;

    bool clamped = false;
    if (!decodePdu(std::span<const std::uint8_t>(_rx).subspan(_rxHead, kPduBytes), pdu, &clamped)) {
        _decodeFatal = true;
        _lastError = "undecodable PDU from the kernel — the stream position is lost";
        return false;
    }
    if (clamped) {
        // The kernel never sends number_of_packets outside [0,1024]; a peer that
        // does is one whose framing we can no longer follow.
        _decodeFatal = true;
        _lastError = "number_of_packets outside [0,1024]";
        return false;
    }

    std::size_t total = kPduBytes;
    if (pdu.command == kCmdSubmit) {
        if (pdu.hasOutPayload()) total += static_cast<std::size_t>(pdu.transferBufferLength);
        if (pdu.numberOfPackets > 0)
            total += static_cast<std::size_t>(pdu.numberOfPackets) * kIsoDescBytes;
    }
    if (avail < total) return false;   // the payload/iso tail is not all here yet

    const std::size_t payloadLen =
        (pdu.command == kCmdSubmit && pdu.hasOutPayload())
            ? static_cast<std::size_t>(pdu.transferBufferLength) : 0;
    payload = std::span<const std::uint8_t>(_rx).subspan(_rxHead + kPduBytes, payloadLen);
    _rxHead += total;
    return true;
}

void VhciNetBridge::compactRx()
{
    if (_rxHead == 0) return;
    _rx.erase(_rx.begin(), _rx.begin() + static_cast<std::ptrdiff_t>(_rxHead));
    _rxHead = 0;
}

Status VhciNetBridge::drainKernel()
{
    for (;;) {
        UsbipPdu pdu;
        std::span<const std::uint8_t> payload;
        while (nextPdu(pdu, payload)) {
            const Status s = (pdu.command == kCmdSubmit) ? onSubmit(pdu, payload)
                           : (pdu.command == kCmdUnlink) ? onUnlink(pdu)
                                                         : Status::MalformedFrame;
            if (s != Status::Ok) { compactRx(); return s; }
        }
        if (_decodeFatal) { compactRx(); return Status::MalformedFrame; }
        compactRx();

        std::uint8_t buf[16384];
        const transport::IoResult r = _kernel.read(std::span<std::uint8_t>(buf, sizeof buf));
        if (r.status == Status::TransportLost) return Status::TransportLost;
        if (r.status != Status::Ok) return r.status;
        if (r.bytes == 0) break;                       // would-block: drained for now
        _rx.insert(_rx.end(), buf, buf + r.bytes);
        _stats.bytesFromKernel += r.bytes;
    }
    return Status::Ok;
}

void VhciNetBridge::queueToKernel(std::span<const std::uint8_t> bytes)
{
    _tx.insert(_tx.end(), bytes.begin(), bytes.end());
}

Status VhciNetBridge::flushKernel()
{
    while (_txSent < _tx.size()) {
        const transport::IoResult r = _kernel.write(
            std::span<const std::uint8_t>(_tx.data() + _txSent, _tx.size() - _txSent));
        if (r.status == Status::TransportLost) return Status::TransportLost;
        if (r.status != Status::Ok) return r.status;
        if (r.bytes == 0) break;                       // would-block: try again next poll
        _txSent += r.bytes;
        _stats.bytesToKernel += r.bytes;
    }
    if (_txSent == _tx.size()) { _tx.clear(); _txSent = 0; }
    else if (_txSent > 64 * 1024) {
        _tx.erase(_tx.begin(), _tx.begin() + static_cast<std::ptrdiff_t>(_txSent));
        _txSent = 0;
    }
    return Status::Ok;
}

// ---------------------------------------------------------------------------
// Dispatch.
// ---------------------------------------------------------------------------

Status VhciNetBridge::onSubmit(const UsbipPdu& pdu, std::span<const std::uint8_t> outData)
{
    ++_stats.submitsHandled;

    if (pdu.ep == 0) {
        SetupPacket setup;
        setup.bmRequestType = pdu.setup[0];
        setup.bRequest      = pdu.setup[1];
        setup.wValue        = static_cast<std::uint16_t>(pdu.setup[2] | (pdu.setup[3] << 8));
        setup.wIndex        = static_cast<std::uint16_t>(pdu.setup[4] | (pdu.setup[5] << 8));
        setup.wLength       = static_cast<std::uint16_t>(pdu.setup[6] | (pdu.setup[7] << 8));

        const Ep0Decision d = _arbiter.decide(setup);
        switch (d.disposition) {
            case Ep0Disposition::Local:
                localData(pdu, d.data);        // manifest bytes, verbatim; no network
                return Status::Ok;

            case Ep0Disposition::Absorb:
                ++_stats.answeredLocally;
                localStatus(pdu, 0, 0);
                return Status::Ok;

            case Ep0Disposition::Arbitrate:
                if (d.verb == Ep0Verb::SetConfiguration) {
                    _arbiter.commitVerb(d.verb, d.arg0, d.arg1);
                    ++_stats.answeredLocally;
                    localStatus(pdu, 0, 0);
                    return Status::Ok;
                }
                if (d.verb == Ep0Verb::SetInterface) {
                    if (d.arg1 == _arbiter.alternateSetting(static_cast<std::uint8_t>(d.arg0))) {
                        _arbiter.commitVerb(d.verb, d.arg0, d.arg1);
                        ++_stats.answeredLocally;
                        localStatus(pdu, 0, 0);
                        return Status::Ok;
                    }
                    ++_stats.stalled;
                    localStatus(pdu, -kEPipe, 0);
                    return Status::Ok;
                }
                // v1 narrowing: EP_CLEAR_HALT has no verb path on the async plane
                // yet, so a stall recovery over the network is deferred. Refuse
                // cleanly — a clean read-only mount never reaches this — rather than
                // fake a clear that leaves the device's toggle wrong.
                ++_stats.stalled;
                localStatus(pdu, -kEPipe, 0);
                return Status::Ok;

            case Ep0Disposition::Forward:
                admit(pdu, static_cast<std::uint8_t>(wire::XferType::Control),
                      _cfg.ctrlTimeoutMs, outData);
                return Status::Ok;

            case Ep0Disposition::Stall:
            default:
                ++_stats.stalled;
                localStatus(pdu,
                            toLinuxErrno(d.status == Status::Ok ? Status::XferStall : d.status), 0);
                return Status::Ok;
        }
    }

    EndpointModel ep;
    if (!lookupEndpoint(pdu.endpointAddress(), ep)) {
        // -EPIPE tells a driver the endpoint is not there, not that a transfer
        // failed.
        ++_stats.stalled;
        localStatus(pdu, -kEPipe, 0);
        return Status::Ok;
    }
    if (ep.type == XferType::Isochronous) {
        // v1 defers isochronous. The framing was already consumed in nextPdu, so
        // the stream stays in sync; the transfer itself is refused.
        ++_stats.stalled;
        localStatus(pdu, -kEPipe, 0);
        return Status::Ok;
    }

    const std::uint8_t  xt = static_cast<std::uint8_t>(ep.type);   // Bulk or Interrupt
    const std::uint32_t to = (ep.type == XferType::Interrupt)
                                 ? static_cast<std::uint32_t>(watchdog::kUrbDeadlineIntr)
                                 : _cfg.bulkTimeoutMs;
    admit(pdu, xt, to, outData);
    return Status::Ok;
}

Status VhciNetBridge::onUnlink(const UsbipPdu& pdu)
{
    ++_stats.unlinksHandled;
    const std::uint32_t victim = pdu.unlinkSeqnum;

    // Still outstanding on the network? Retire it locally so no RET_SUBMIT will ever
    // be produced for it, cancel it on the plane, and answer -ECONNRESET NOW. The
    // exporter may still be moving bytes; the kernel believes the URB is dead the
    // instant it gets this reply, which is the convenient half-truth §5.6 documents.
    if (const auto sit = _bySeqnum.find(victim); sit != _bySeqnum.end()) {
        const Ref ref = sit->second;
        (void)_plane.cancel(ref.first, ref.second);
        _outstanding.erase(ref);
        _bySeqnum.erase(sit);
        std::vector<std::uint8_t> out;
        encodeRetUnlink(pdu.seqnum, -kEConnReset, out);
        queueToKernel(out);
        return Status::Ok;
    }

    // Still only queued (never admitted)? Drop it and answer the same way.
    for (auto it = _pending.begin(); it != _pending.end(); ++it) {
        if (it->pdu.seqnum == victim) {
            _pending.erase(it);
            std::vector<std::uint8_t> out;
            encodeRetUnlink(pdu.seqnum, -kEConnReset, out);
            queueToKernel(out);
            return Status::Ok;
        }
    }

    // Already completed — its RET_SUBMIT is already on the wire. Linux spells that
    // status 0: "too late, it is done." Never leave a CMD_UNLINK unanswered: an
    // unanswered unlink is a task in uninterruptible sleep forever.
    std::vector<std::uint8_t> out;
    encodeRetUnlink(pdu.seqnum, 0, out);
    queueToKernel(out);
    return Status::Ok;
}

// ---------------------------------------------------------------------------
// Admission (never blocks; queues when the plane is full).
// ---------------------------------------------------------------------------

void VhciNetBridge::admit(const UsbipPdu& pdu, std::uint8_t xferType, std::uint32_t timeoutMs,
                          std::span<const std::uint8_t> outData)
{
    if (!_plane.canAdmit()) {
        _pending.push_back(Pending{
            pdu,
            std::vector<std::uint8_t>(outData.begin(), outData.end()),   // copied out of _rx
            xferType, timeoutMs});
        return;
    }
    doSubmit(pdu, xferType, timeoutMs, outData);
}

void VhciNetBridge::doSubmit(const UsbipPdu& pdu, std::uint8_t xferType, std::uint32_t timeoutMs,
                             std::span<const std::uint8_t> outData)
{
    const std::uint8_t epAddr = (pdu.ep == 0) ? 0 : pdu.endpointAddress();
    const std::uint8_t dir    = (pdu.direction == kDirIn)
                                    ? static_cast<std::uint8_t>(wire::Dir::In)
                                    : static_cast<std::uint8_t>(wire::Dir::Out);
    const std::uint32_t bufferLen = static_cast<std::uint32_t>(pdu.transferBufferLength);
    const std::uint8_t* setup = (pdu.ep == 0) ? pdu.setup : nullptr;

    std::uint16_t ch = 0;
    std::uint64_t rid = 0;
    const Status s = _plane.submit(
        epAddr, xferType, dir, bufferLen, setup,
        (dir == static_cast<std::uint8_t>(wire::Dir::Out)) ? outData : std::span<const std::uint8_t>{},
        timeoutMs, &ch, &rid);

    if (s == Status::Ok) {
        _outstanding[Ref{ch, rid}] = pdu;
        _bySeqnum[pdu.seqnum]      = Ref{ch, rid};
        ++_stats.forwardedToDevice;
    } else {
        // The submit itself failed (dead link, or an unexpected Busy). Fail this URB
        // now rather than leave the kernel waiting on a transfer that never left.
        completeToKernel(pdu,
                         toLinuxErrno(s == Status::Busy ? Status::NoResources : s), 0, {});
    }
}

void VhciNetBridge::admitPending()
{
    while (!_pending.empty() && _plane.canAdmit()) {
        Pending p = std::move(_pending.front());
        _pending.pop_front();
        doSubmit(p.pdu, p.xferType, p.timeoutMs, p.out);
    }
}

// ---------------------------------------------------------------------------
// Network completions -> RET_SUBMIT.
// ---------------------------------------------------------------------------

Status VhciNetBridge::pumpPlane()
{
    const Status s = _plane.pump([this](const DataCompletion& c) { onCompletion(c); });
    _plane.sweepDeadlines([this](const DataCompletion& c) { onCompletion(c); });
    return s;
}

void VhciNetBridge::onCompletion(const DataCompletion& c)
{
    const auto it = _outstanding.find(Ref{c.channel, c.requestId});
    if (it == _outstanding.end()) return;   // cancelled/unknown: nothing to answer
    const UsbipPdu cmd = it->second;
    _outstanding.erase(it);
    _bySeqnum.erase(cmd.seqnum);

    // A SHORT transfer is success with the true actual_length; the USB core
    // synthesizes -EREMOTEIO itself when URB_SHORT_NOT_OK is set (§5.5), so we must
    // NOT do it here. toLinuxErrno maps Ok and XferShort to 0.
    const std::int32_t err = toLinuxErrno(c.status);
    completeToKernel(cmd, err, static_cast<std::int32_t>(c.actualLen), c.data);
}

void VhciNetBridge::failAll(Status with)
{
    _plane.completeAll(with, [this](const DataCompletion& c) { onCompletion(c); });
    // Queued submits never reached the plane; fail them directly so I1 still holds.
    for (const Pending& p : _pending)
        completeToKernel(p.pdu, toLinuxErrno(with), 0, {});
    _pending.clear();
}

// ---------------------------------------------------------------------------
// RET_SUBMIT builders.
// ---------------------------------------------------------------------------

void VhciNetBridge::localData(const UsbipPdu& cmd, std::span<const std::uint8_t> data)
{
    ++_stats.answeredLocally;
    completeToKernel(cmd, 0, static_cast<std::int32_t>(data.size()), data);
}

void VhciNetBridge::localStatus(const UsbipPdu& cmd, std::int32_t status, std::int32_t actualLength)
{
    std::vector<std::uint8_t> out;
    encodeRetSubmit(cmd, status, actualLength, 0, out);
    queueToKernel(out);
}

void VhciNetBridge::completeToKernel(const UsbipPdu& cmd, std::int32_t status,
                                     std::int32_t actualLength, std::span<const std::uint8_t> payload)
{
    // Never over-report: actual_length above transfer_buffer_length makes the kernel
    // log "recv xbuf" and tear the whole port down, taking every in-flight URB with
    // it. And actual_length IS the frame length, so for an IN it must equal the
    // bytes we actually append.
    std::int32_t n = actualLength;
    if (n < 0) n = 0;
    if (n > cmd.transferBufferLength) n = cmd.transferBufferLength;

    std::size_t p = 0;
    if (cmd.direction == kDirIn) {
        p = std::min<std::size_t>(payload.size(), static_cast<std::size_t>(n));
        n = static_cast<std::int32_t>(p);
    }

    std::vector<std::uint8_t> out;
    encodeRetSubmit(cmd, status, n, 0, out);
    if (p > 0)
        out.insert(out.end(), payload.begin(), payload.begin() + static_cast<std::ptrdiff_t>(p));
    queueToKernel(out);
}

// ---------------------------------------------------------------------------

bool VhciNetBridge::lookupEndpoint(std::uint8_t addr, EndpointModel& out) const
{
    const std::uint8_t cfg = _arbiter.currentConfiguration();
    for (std::uint8_t iface = 0; iface < 32; ++iface) {
        const std::uint8_t alt = _arbiter.alternateSetting(iface);
        for (const EndpointModel& e : _manifest.endpointsFor(cfg, iface, alt)) {
            if (e.address == addr) { out = e; return true; }
        }
    }
    return false;
}

} // namespace airusb::linuxvhci
