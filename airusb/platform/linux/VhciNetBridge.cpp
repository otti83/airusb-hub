#include "VhciNetBridge.h"

#include <algorithm>
#include <string>

namespace airusb::linuxvhci {

using session::DataCompletion;

VhciNetBridge::VhciNetBridge(transport::IByteStream& kernel, session::ImporterDataPlane& plane,
                             const DeviceManifest& manifest, const Clock& clock,
                             const Config& cfg) noexcept
    : _kernel(kernel), _plane(plane), _manifest(manifest), _clock(clock),
      _arbiter(manifest), _cfg(cfg)
{
}

// ---------------------------------------------------------------------------
// The one non-blocking step. The ORDER is the whole safety argument: the kernel is
// drained end to end (R-A) before a single byte touches the network, replies are
// buffered (R-B), and every accepted URB already carries a deadline (R-C).
// ---------------------------------------------------------------------------

Status VhciNetBridge::poll()
{
    const Status ks = drainKernel();
    if (ks != Status::Ok && ks != Status::TransportLost) {
        // A fatal kernel-stream error still requires teardown draining: complete
        // every held URB before we stop, or they wait on the kernel forever (§5.7).
        failAll(Status::DeviceGone);
        (void)flushKernel();
        return ks;
    }
    const bool kernelGone = (ks == Status::TransportLost);

    sweepPending();                 // R-C: a queued URB can expire before it is admitted
    admitPending();                 // the FIRST time this poll touches the network
    const Status ps = pumpPlane();
    admitPending();                 // a completion may have freed the one admission slot

    const Status fs = flushKernel();

    if (ps != Status::Ok) {
        failAll(Status::DeviceGone);
        (void)flushKernel();
        return Status::TransportLost;
    }
    if (fs == Status::TransportLost || kernelGone) return Status::TransportLost;
    if (fs != Status::Ok) return fs;
    return Status::Ok;
}

// ---------------------------------------------------------------------------
// Kernel side — non-blocking framed I/O. drainKernel() NEVER touches the network.
// ---------------------------------------------------------------------------

bool VhciNetBridge::nextPdu(UsbipPdu& pdu, std::span<const std::uint8_t>& payload,
                            std::span<const std::uint8_t>& isoDescs)
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
        _decodeFatal = true;
        _lastError = "number_of_packets outside [0,1024]";
        return false;
    }

    std::size_t payloadLen = 0, isoBytes = 0;
    if (pdu.command == kCmdSubmit) {
        if (pdu.hasOutPayload()) payloadLen = static_cast<std::size_t>(pdu.transferBufferLength);
        if (pdu.numberOfPackets > 0)
            isoBytes = static_cast<std::size_t>(pdu.numberOfPackets) * kIsoDescBytes;
    }
    const std::size_t total = kPduBytes + payloadLen + isoBytes;
    if (avail < total) return false;   // the payload/iso tail is not all here yet

    payload  = std::span<const std::uint8_t>(_rx).subspan(_rxHead + kPduBytes, payloadLen);
    isoDescs = std::span<const std::uint8_t>(_rx).subspan(_rxHead + kPduBytes + payloadLen, isoBytes);
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
        std::span<const std::uint8_t> payload, isoDescs;
        while (nextPdu(pdu, payload, isoDescs)) {
            const Status s = (pdu.command == kCmdSubmit) ? onSubmit(pdu, payload, isoDescs)
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
        if (r.bytes == 0) break;                       // would-block: retry next poll
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
// Dispatch. onSubmit() only ever answers locally (ep0) or ENQUEUES — it never
// touches the network, which is what keeps R-A structural.
// ---------------------------------------------------------------------------

Status VhciNetBridge::onSubmit(const UsbipPdu& pdu, std::span<const std::uint8_t> outData,
                               std::span<const std::uint8_t> isoDescs)
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
                    // Local success ONLY for the configuration the exporter is
                    // actually in; anything else would tell the guest we reconfigured
                    // a device we cannot reach, and route later transfers by
                    // descriptors for endpoints it never enabled (§5.4).
                    if (d.arg0 == _cfg.capturedConfig) {
                        _arbiter.commitVerb(d.verb, d.arg0, d.arg1);
                        ++_stats.answeredLocally;
                        localStatus(pdu, 0, 0);
                    } else {
                        ++_stats.stalled;
                        localStatus(pdu, -kEPipe, 0);
                        trace("SET_CONFIGURATION " + std::to_string(d.arg0) +
                              " refused (v1: cannot reconfigure a remote device)");
                    }
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
                // yet. Refuse cleanly rather than fake a clear that leaves the
                // device's data toggle wrong — a clean read-only mount never
                // reaches this.
                ++_stats.stalled;
                localStatus(pdu, -kEPipe, 0);
                return Status::Ok;

            case Ep0Disposition::Forward:
                enqueue(pdu, static_cast<std::uint8_t>(wire::XferType::Control),
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
        ++_stats.stalled;
        localStatus(pdu, -kEPipe, 0);          // -EPIPE: no such endpoint here
        return Status::Ok;
    }
    if (ep.type == XferType::Isochronous) {
        refuseIso(pdu, isoDescs);              // v1 defers iso, but refuses it CORRECTLY
        return Status::Ok;
    }

    const std::uint8_t  xt = static_cast<std::uint8_t>(ep.type);   // Bulk or Interrupt
    const std::uint32_t to = (ep.type == XferType::Interrupt)
                                 ? static_cast<std::uint32_t>(watchdog::kUrbDeadlineIntr)
                                 : _cfg.bulkTimeoutMs;
    enqueue(pdu, xt, to, outData);
    return Status::Ok;
}

Status VhciNetBridge::onUnlink(const UsbipPdu& pdu)
{
    ++_stats.unlinksHandled;
    const std::uint32_t victim = pdu.unlinkSeqnum;

    // Still outstanding on the network? Retire it locally so no RET_SUBMIT will ever
    // be produced for it, cancel it on the plane, and answer -ECONNRESET NOW. The
    // exporter may still be moving bytes; the kernel believes the URB is dead the
    // instant it gets this reply — the convenient half-truth §5.6 documents.
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
    // status 0. Never leave a CMD_UNLINK unanswered: that is a task in
    // uninterruptible sleep forever.
    std::vector<std::uint8_t> out;
    encodeRetUnlink(pdu.seqnum, 0, out);
    queueToKernel(out);
    return Status::Ok;
}

// ---------------------------------------------------------------------------
// Admission. Every accepted URB gets a deadline the instant the kernel hands it to
// us (R-C), not when it later reaches the wire — so a URB queued behind a full
// depth-1 plane still has exactly one terminal outcome even if it never leaves.
// ---------------------------------------------------------------------------

void VhciNetBridge::enqueue(const UsbipPdu& pdu, std::uint8_t xferType, std::uint32_t timeoutMs,
                            std::span<const std::uint8_t> outData)
{
    _pending.push_back(Pending{
        pdu,
        std::vector<std::uint8_t>(outData.begin(), outData.end()),   // copied out of _rx
        xferType,
        Deadline::afterMs(_clock, timeoutMs)});
}

void VhciNetBridge::sweepPending()
{
    for (auto it = _pending.begin(); it != _pending.end(); ) {
        if (it->deadline.isSet() && it->deadline.expired(_clock)) {
            completeToKernel(it->pdu, -kETimedOut, 0, {});
            it = _pending.erase(it);
        } else {
            ++it;
        }
    }
}

void VhciNetBridge::admitPending()
{
    while (!_pending.empty() && _plane.canAdmit()) {
        Pending p = std::move(_pending.front());
        _pending.pop_front();

        if (p.deadline.isSet() && p.deadline.expired(_clock)) {
            completeToKernel(p.pdu, -kETimedOut, 0, {});   // expired between enqueue and admit
            continue;
        }
        // Forward only the REMAINING time, so the whole-URB deadline is honoured
        // regardless of how long it waited for the slot.
        const std::uint32_t rem = p.deadline.isSet()
            ? static_cast<std::uint32_t>(
                  std::max<std::uint64_t>(1, p.deadline.remainingNs(_clock) / 1000000ull))
            : 0;
        doSubmit(p.pdu, p.xferType, rem, p.out);
    }
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

    // completeAll fires onCompletion for every request the plane still held, which
    // retires their seqnums. Anything still mapped here was orphaned — e.g. a
    // malformed completion that removed its plane request without delivering — so
    // retire it directly. This is what makes I1 hold ABSOLUTELY on teardown.
    const std::int32_t err = toLinuxErrno(with);
    for (const auto& kv : _outstanding) completeToKernel(kv.second, err, 0, {});
    _outstanding.clear();
    _bySeqnum.clear();

    for (const Pending& p : _pending) completeToKernel(p.pdu, err, 0, {});
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

void VhciNetBridge::refuseIso(const UsbipPdu& pdu, std::span<const std::uint8_t> isoDescs)
{
    // v1 defers isochronous, but the refusal MUST still carry number_of_packets
    // descriptors: vhci_rx calls usbip_recv_iso() unconditionally after a RET_SUBMIT
    // whose header echoes number_of_packets > 0, and would otherwise wait for a
    // descriptor array that never arrives — a hang (§5.8). Header actual_length 0 =
    // sum of per-packet actual_length, so the kernel's consistency check passes and
    // usbip_pad_iso() early-returns.
    ++_stats.stalled;
    const int np = pdu.numberOfPackets;

    std::vector<UsbipIsoDesc> in;
    (void)decodeIsoDescs(isoDescs, static_cast<std::size_t>(np < 0 ? 0 : np), in);

    std::vector<std::uint8_t> out;
    encodeRetSubmit(pdu, -kEPipe, 0, np, out);      // error_count = number_of_packets

    std::vector<UsbipIsoDesc> refusal;
    refusal.reserve(static_cast<std::size_t>(np < 0 ? 0 : np));
    for (int i = 0; i < np; ++i) {
        UsbipIsoDesc d;
        if (static_cast<std::size_t>(i) < in.size()) {
            d.offset = in[static_cast<std::size_t>(i)].offset;
            d.length = in[static_cast<std::size_t>(i)].length;
        }
        d.actualLength = 0;
        d.status       = -kEProto;
        refusal.push_back(d);
    }
    encodeIsoDescs(refusal, out);
    queueToKernel(out);
    trace("iso refused (v1): echoed " + std::to_string(np) + " descriptors");
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
