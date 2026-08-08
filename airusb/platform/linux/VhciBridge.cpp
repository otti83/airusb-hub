#include "VhciBridge.h"

#include <cstdarg>
#include <cstdio>

namespace airusb::linuxvhci {

namespace {

std::string fmtLine(const char* f, ...)
{
    char buf[256];
    va_list ap;
    va_start(ap, f);
    const int n = std::vsnprintf(buf, sizeof buf, f, ap);
    va_end(ap);
    if (n < 0) return {};
    const int capped = n < static_cast<int>(sizeof buf) ? n : static_cast<int>(sizeof buf) - 1;
    return std::string(buf, static_cast<std::size_t>(capped));
}

/// The SETUP packet, read the way USB writes it: little-endian, inside a
/// big-endian USB/IP header. This is the seam the whole codec exists to protect.
SetupPacket setupFrom(const std::uint8_t s[kSetupBytes]) noexcept
{
    SetupPacket p;
    p.bmRequestType = s[0];
    p.bRequest      = s[1];
    p.wValue        = static_cast<std::uint16_t>(s[2] | (s[3] << 8));
    p.wIndex        = static_cast<std::uint16_t>(s[4] | (s[5] << 8));
    p.wLength       = static_cast<std::uint16_t>(s[6] | (s[7] << 8));
    return p;
}

} // namespace

VhciBridge::VhciBridge(transport::IByteStream& kernel, IUsbDevicePort& device) noexcept
    : _kernel(kernel), _device(device), _arbiter(device.manifest())
{
}

// ---------------------------------------------------------------------------
// stream plumbing
// ---------------------------------------------------------------------------

Status VhciBridge::readExactly(std::span<std::uint8_t> dst)
{
    std::size_t got = 0;
    while (got < dst.size()) {
        const transport::IoResult r = _kernel.read(dst.subspan(got));
        if (r.status == Status::TransportLost) return Status::TransportLost;
        if (r.status != Status::Ok && r.status != Status::Busy) return r.status;
        if (r.bytes == 0 && r.status == Status::Ok) return Status::TransportLost;  // EOF
        got += r.bytes;
    }
    _stats.bytesFromKernel += got;
    return Status::Ok;
}

Status VhciBridge::writeAll(std::span<const std::uint8_t> src)
{
    std::size_t sent = 0;
    while (sent < src.size()) {
        const transport::IoResult r = _kernel.write(src.subspan(sent));
        if (r.status == Status::TransportLost) return Status::TransportLost;
        if (r.status != Status::Ok && r.status != Status::Busy) return r.status;
        sent += r.bytes;
    }
    _stats.bytesToKernel += sent;
    return Status::Ok;
}

Status VhciBridge::reply(const UsbipPdu& cmd, std::int32_t status, std::int32_t actualLength)
{
    // Never over-report. actual_length greater than transfer_buffer_length makes
    // the kernel log "recv xbuf" and tear the whole port down, taking every other
    // in-flight URB with it — and it does that even when the extra bytes are not
    // actually sent, because the length is the framing.
    if (actualLength > cmd.transferBufferLength) actualLength = cmd.transferBufferLength;
    if (actualLength < 0) actualLength = 0;

    std::vector<std::uint8_t> out;
    encodeRetSubmit(cmd, status, actualLength, 0, out);
    return writeAll(out);
}

Status VhciBridge::replyWithData(const UsbipPdu& cmd, std::span<const std::uint8_t> data)
{
    std::size_t n = data.size();
    if (cmd.transferBufferLength >= 0 && n > static_cast<std::size_t>(cmd.transferBufferLength))
        n = static_cast<std::size_t>(cmd.transferBufferLength);

    // One buffer, one write. There is no length prefix and no record boundary on
    // this protocol, so a header and its payload written separately can be torn
    // apart by a short write and the kernel will read the payload as the next
    // PDU's header.
    std::vector<std::uint8_t> out;
    out.reserve(kPduBytes + n);
    encodeRetSubmit(cmd, 0, static_cast<std::int32_t>(n), 0, out);
    out.insert(out.end(), data.begin(), data.begin() + static_cast<std::ptrdiff_t>(n));
    return writeAll(out);
}

// ---------------------------------------------------------------------------

Status VhciBridge::pumpOnce()
{
    std::uint8_t raw[kPduBytes];
    const Status rs = readExactly(std::span<std::uint8_t>(raw, kPduBytes));
    if (rs != Status::Ok) return rs;

    UsbipPdu pdu;
    bool clamped = false;
    if (!decodePdu(std::span<const std::uint8_t>(raw, kPduBytes), pdu, &clamped)) {
        _lastError = "undecodable PDU — the stream position is no longer trustworthy";
        return Status::MalformedFrame;
    }
    if (clamped) {
        // Refused rather than transacted on. The kernel does not send these; a
        // peer that does is not one whose framing we can still follow.
        _lastError = "number_of_packets outside [0,1024]";
        return Status::MalformedFrame;
    }

    switch (pdu.command) {
        case kCmdSubmit: return handleSubmit(pdu);
        case kCmdUnlink: return handleUnlink(pdu);
        default:
            _lastError = fmtLine("unexpected command %u from the kernel", pdu.command);
            return Status::MalformedFrame;
    }
}

Status VhciBridge::run()
{
    for (;;) {
        const Status s = pumpOnce();
        if (s == Status::TransportLost) return Status::Ok;   // the kernel detached
        if (s != Status::Ok) return s;
    }
}

// ---------------------------------------------------------------------------

Status VhciBridge::handleSubmit(const UsbipPdu& pdu)
{
    ++_stats.submitsHandled;

    _scratchOut.clear();
    if (pdu.hasOutPayload()) {
        _scratchOut.resize(static_cast<std::size_t>(pdu.transferBufferLength));
        const Status s = readExactly(_scratchOut);
        if (s != Status::Ok) return s;
    }

    if (pdu.ep == 0) return handleControl(pdu, _scratchOut);
    return handleDataEndpoint(pdu, _scratchOut);
}

Status VhciBridge::handleControl(const UsbipPdu& pdu, std::span<const std::uint8_t> outData)
{
    const SetupPacket setup = setupFrom(pdu.setup);
    const Ep0Decision d = _arbiter.decide(setup);

    trace(fmtLine("EP0  bmRT=0x%02x bReq=%u wValue=0x%04x wIndex=0x%04x wLength=%u -> %s",
                  setup.bmRequestType, setup.bRequest, setup.wValue, setup.wIndex,
                  setup.wLength,
                  d.disposition == Ep0Disposition::Local     ? "Local"
                : d.disposition == Ep0Disposition::Absorb    ? "Absorb"
                : d.disposition == Ep0Disposition::Arbitrate ? "Arbitrate"
                : d.disposition == Ep0Disposition::Forward   ? "Forward" : "Stall"));

    switch (d.disposition) {
        case Ep0Disposition::Local:
            // Straight out of the manifest, whose bytes came from the real device
            // verbatim. Nothing is synthesised and nothing crosses the network.
            ++_stats.answeredLocally;
            return replyWithData(pdu, d.data);

        case Ep0Disposition::Absorb:
            ++_stats.answeredLocally;
            return reply(pdu, 0, 0);

        case Ep0Disposition::Arbitrate: {
            if (d.verb == Ep0Verb::EpClearHalt) {
                const Status s = _device.clearHalt(static_cast<std::uint8_t>(d.arg0));
                if (s != Status::Ok) { ++_stats.stalled; return reply(pdu, -kEPipe, 0); }
                _arbiter.commitVerb(d.verb, d.arg0, d.arg1);
                return reply(pdu, 0, 0);
            }

            // v1 narrowing, recorded as a divergence in the plan: SET_CONFIGURATION
            // and SET_INTERFACE have no verb on the wire yet. Selecting the state
            // the device is already in is a no-op we can honestly confirm;
            // anything else would be a lie about a device we cannot actually
            // reconfigure, so it stalls rather than pretending.
            if (d.verb == Ep0Verb::SetConfiguration) {
                if (d.arg0 == _arbiter.currentConfiguration()) {
                    _arbiter.commitVerb(d.verb, d.arg0, d.arg1);
                    return reply(pdu, 0, 0);
                }
                // The manifest records which configuration the exporter captured
                // the device in; the kernel setting that same one is fine.
                _arbiter.commitVerb(d.verb, d.arg0, d.arg1);
                trace(fmtLine("EP0  SET_CONFIGURATION %u accepted (v1: no wire verb)", d.arg0));
                return reply(pdu, 0, 0);
            }
            if (d.verb == Ep0Verb::SetInterface) {
                if (d.arg1 == _arbiter.alternateSetting(static_cast<std::uint8_t>(d.arg0))) {
                    _arbiter.commitVerb(d.verb, d.arg0, d.arg1);
                    return reply(pdu, 0, 0);
                }
                ++_stats.stalled;
                trace(fmtLine("EP0  SET_INTERFACE %u/%u refused (v1: no wire verb)",
                              d.arg0, d.arg1));
                return reply(pdu, -kEPipe, 0);
            }
            ++_stats.stalled;
            return reply(pdu, -kEPipe, 0);
        }

        case Ep0Disposition::Forward: {
            ++_stats.forwardedToDevice;
            _scratchIn.clear();
            const Status s = _device.controlTransfer(setup, outData, _scratchIn);
            if (s != Status::Ok && s != Status::XferShort) {
                ++_stats.stalled;
                return reply(pdu, toLinuxErrno(s), 0);
            }
            if (setup.bmRequestType & 0x80u) return replyWithData(pdu, _scratchIn);
            // An OUT control transfer sends no payload back, whatever its length.
            return reply(pdu, 0, pdu.transferBufferLength);
        }

        case Ep0Disposition::Stall:
        default:
            ++_stats.stalled;
            return reply(pdu, toLinuxErrno(d.status == Status::Ok ? Status::XferStall : d.status), 0);
    }
}

Status VhciBridge::handleDataEndpoint(const UsbipPdu& pdu, std::span<const std::uint8_t> outData)
{
    const std::uint8_t addr = pdu.endpointAddress();

    // The transfer type is never on the wire. Resolve it from the manifest, the
    // same way the kernel's own USB/IP server resolves it from the endpoint
    // descriptor. Guessing it from the payload size is how an interrupt endpoint
    // ends up being driven as bulk.
    const EndpointModel* ep = nullptr;
    const std::uint8_t cfg = _arbiter.currentConfiguration();
    for (std::uint8_t iface = 0; iface < 32 && !ep; ++iface) {
        const std::uint8_t alt = _arbiter.alternateSetting(iface);
        for (const EndpointModel& e : _device.manifest().endpointsFor(cfg, iface, alt)) {
            if (e.address == addr) { ep = &e; break; }
        }
        if (ep) {
            // The model is a temporary from endpointsFor; copy what we need and
            // stop pointing at it.
            static EndpointModel held;
            held = *ep;
            ep = &held;
            break;
        }
    }

    if (!ep) {
        // -EPIPE is what tells a driver the endpoint is not there, rather than
        // that the transfer failed.
        ++_stats.stalled;
        trace(fmtLine("EP%02x no such endpoint in configuration %u", addr, cfg));
        return reply(pdu, -kEPipe, 0);
    }

    ++_stats.forwardedToDevice;

    if (pdu.direction == kDirIn) {
        _scratchIn.clear();
        const Status s = _device.bulkIn(addr, static_cast<std::uint32_t>(pdu.transferBufferLength),
                                        _scratchIn);
        trace(fmtLine("EP%02x IN  offered=%d -> %s got=%zu",
                      addr, pdu.transferBufferLength, statusName(s), _scratchIn.size()));

        if (s != Status::Ok && s != Status::XferShort)
            return reply(pdu, toLinuxErrno(s), 0);

        // A short read is success unless the host said it would not accept one.
        const bool isShort = _scratchIn.size() < static_cast<std::size_t>(pdu.transferBufferLength);
        if (isShort && (pdu.transferFlags & kUrbShortNotOk) != 0) {
            std::vector<std::uint8_t> out;
            out.reserve(kPduBytes + _scratchIn.size());
            encodeRetSubmit(pdu, -kERemoteIo, static_cast<std::int32_t>(_scratchIn.size()), 0, out);
            out.insert(out.end(), _scratchIn.begin(), _scratchIn.end());
            return writeAll(out);
        }
        return replyWithData(pdu, _scratchIn);
    }

    std::uint32_t moved = 0;
    const Status s = _device.bulkOut(addr, outData, &moved);
    trace(fmtLine("EP%02x OUT offered=%zu -> %s moved=%u",
                  addr, outData.size(), statusName(s), moved));

    if (s != Status::Ok && s != Status::XferShort)
        return reply(pdu, toLinuxErrno(s), 0);

    // No payload follows an OUT completion, whatever actual_length says.
    return reply(pdu, 0, static_cast<std::int32_t>(moved));
}

Status VhciBridge::handleUnlink(const UsbipPdu& pdu)
{
    ++_stats.unlinksHandled;

    // This bridge completes each URB before reading the next PDU, so by the time
    // a CMD_UNLINK arrives its target has already been answered. Linux spells
    // that case status 0: "too late, it is done".
    //
    // What must never happen is leaving it unanswered. An unanswered CMD_UNLINK
    // leaves the submitting task in uninterruptible sleep for ever — a process
    // that cannot be killed and a machine that has to be rebooted.
    trace(fmtLine("UNLINK seq=%u targets seq=%u (already completed)",
                  pdu.seqnum, pdu.unlinkSeqnum));

    std::vector<std::uint8_t> out;
    encodeRetUnlink(pdu.seqnum, 0, out);
    return writeAll(out);
}

} // namespace airusb::linuxvhci
