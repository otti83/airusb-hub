#include "InlineAsyncPort.h"

#include <utility>

namespace airusb::session {

Status InlineAsyncPort::submit(std::uint64_t token, const AsyncTransfer& t)
{
    Finished f;
    f.token = token;

    if (t.xferType == XferType::Control) {
        f.status = _port.controlTransfer(t.setup, t.dataOut, f.data);
        if (t.dir == Dir::Out) {
            // USB has no partial control data stage — the status stage is what
            // says it worked — so on success the length IS what was offered.
            // Reporting zero here told every guest driver that checks the count
            // that its class or vendor request moved nothing.
            if (f.status == Status::Ok)
                f.actualLen = static_cast<std::uint32_t>(t.dataOut.size());
        } else {
            f.actualLen = static_cast<std::uint32_t>(f.data.size());
        }
    } else if (t.dir == Dir::In) {
        f.status    = _port.bulkIn(t.epAddr, t.bufferLen, f.data);
        f.actualLen = static_cast<std::uint32_t>(f.data.size());
    } else {
        std::uint32_t moved = 0;
        f.status    = _port.bulkOut(t.epAddr, t.dataOut, &moved);
        f.actualLen = moved;
        f.data.clear();

        // ZERO_PACKET, honoured rather than dropped.
        //
        // A synchronous `IUsbDevicePort` has no way to express "and then a
        // zero-length packet", so this issues one as a second, empty OUT — which
        // is precisely what a terminating ZLP is on the bus. It is only emitted
        // when the guest asked for it AND the transfer really ended on an exact
        // multiple of the packet size, because a ZLP after a short packet would
        // itself be a spurious extra transfer.
        //
        // Dropped, a device that is waiting for the terminating ZLP after an
        // exact-multiple OUT waits for ever. That is why this is here and not
        // filed as a nicety.
        if (t.zeroPacket && f.status == Status::Ok && f.actualLen != 0) {
            const std::uint32_t mps = maxPacketFor(t.epAddr);
            if (mps != 0 && (f.actualLen % mps) == 0) {
                std::uint32_t zeroMoved = 0;
                const Status z = _port.bulkOut(t.epAddr, {}, &zeroMoved);
                if (z == Status::Ok) f.zlpSent = true;
                else                 f.status  = z;
            }
        }
    }

    // SHORT_NOT_OK, likewise honoured. On Linux a short transfer is
    // unconditionally a success; on Windows the guest says per URB. Hardcoding
    // either answer breaks somebody, so the flag decides — and it decides HERE,
    // where the requested length is still in hand.
    if (t.shortNotOk && f.status == Status::Ok && t.dir == Dir::In
        && f.actualLen < t.bufferLen)
        f.status = Status::XferShort;

    _done.push_back(std::move(f));
    return Status::Ok;
}

std::uint32_t InlineAsyncPort::maxPacketFor(std::uint8_t epAddr) const noexcept
{
    // Alternate setting 0 everywhere: this adapter has no configure state of its
    // own, and a port that cannot idle is by construction not carrying the
    // composite devices where that distinction matters. Stated rather than
    // assumed, so that the day it does matter the assumption is visible.
    EndpointModel ep;
    const DeviceManifest& m = _port.manifest();
    for (std::size_t i = 0; i < m.configurationCount(); ++i) {
        const auto blob = m.configurationByIndex(static_cast<std::uint8_t>(i));
        if (blob.size() < 6) continue;
        if (m.findEndpoint(blob[5], epAddr, nullptr, ep)) return ep.maxPacketSize;
    }
    return 0;
}

bool InlineAsyncPort::cancel(std::uint64_t token)
{
    // Nothing is ever in flight here: `submit()` returned only after the device
    // was done. A cancel therefore either finds a finished outcome not yet
    // collected — which it must NOT discard, because the transfer really
    // happened and the importer is entitled to know what moved — or finds
    // nothing.
    //
    // Returning false in both cases is the honest answer: this port cannot stop
    // a transfer, and saying it could would make the exporter promise the
    // importer a cancellation it did not perform.
    (void)token;
    return false;
}

Status InlineAsyncPort::clearHalt(std::uint64_t token, std::uint8_t epAddr)
{
    Finished f;
    f.token  = token;
    f.status = _port.clearHalt(epAddr);
    _done.push_back(std::move(f));
    return Status::Ok;
}

void InlineAsyncPort::poll(const OnOutcome& onOutcome)
{
    // Drained by swap rather than in place: a callback is allowed to submit, and
    // iterating a container something else is pushing onto is how a test passes
    // and a product corrupts memory.
    std::deque<Finished> batch;
    batch.swap(_done);

    for (const Finished& f : batch) {
        AsyncOutcome o;
        o.token     = f.token;
        o.status    = f.status;
        o.actualLen = f.actualLen;
        o.cancelled = f.cancelled;
        o.zlpSent   = f.zlpSent;
        o.dataIn    = std::span<const std::uint8_t>(f.data.data(), f.data.size());
        if (onOutcome) onOutcome(o);
    }
}

void InlineAsyncPort::abortAll(Status with, const OnOutcome& onOutcome)
{
    std::deque<Finished> batch;
    batch.swap(_done);

    for (Finished& f : batch) {
        // The transfer already happened. Its real outcome is more useful than
        // the teardown status, so the status is only overwritten when the
        // transfer itself had not succeeded — I1 says exactly one outcome per
        // token, not one INVENTED outcome per token.
        AsyncOutcome o;
        o.token     = f.token;
        o.status    = f.status == Status::Ok ? Status::Ok : with;
        o.actualLen = f.actualLen;
        o.zlpSent   = f.zlpSent;
        o.dataIn    = std::span<const std::uint8_t>(f.data.data(), f.data.size());
        if (onOutcome) onOutcome(o);
    }
}

} // namespace airusb::session
