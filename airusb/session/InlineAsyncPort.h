// AirUSB Hub — a synchronous device pretending, honestly, to be an asynchronous one.
//
// `ExporterSession` drives an `IAsyncUsbDevicePort`. Most of the ports this
// project has are `IUsbDevicePort`: the RAM-backed `ScriptedDevice` the tests
// and CI run against, and `HostDeviceExporter` on macOS. This adapts one to the
// other by issuing the transfer inside `submit()` and holding its outcome until
// the next `poll()`.
//
// WHAT THAT IS AND IS NOT
//
// It is correct for a port whose transfers ALWAYS return: a RAM disk, a
// scripted fake, a bulk endpoint on a working drive. For those, "asynchronous"
// buys nothing and this costs nothing.
//
// It is WRONG for an endpoint that can legitimately idle. An interrupt IN with
// nothing to report returns nothing, for ever, and inside `submit()` that
// blocks the session exactly as the old inline code did. So this class does not
// merely document the limit — it REFUSES: `canIdle()` returns false, and
// `ExporterSession` will not attach a device with an interrupt or isochronous
// endpoint through a port that says so.
//
// A refusal at ATTACH is a much better failure than the alternative. An
// exporter that accepts a keyboard and then stops answering looks exactly like
// a network fault, and the person debugging it has no way to see that one
// function call simply never returned. "This build cannot share this kind of
// device yet" is a sentence; a hang is not.
//
// The way out is not to make this class cleverer. It is for the platform ports
// to become genuinely asynchronous — usbfs URB submit/reap on Linux,
// overlapped I/O on Windows, `enqueueIORequestWithData:completionHandler:` on
// macOS — at which point they implement `IAsyncUsbDevicePort` directly, say
// `canIdle() == true`, and this adapter is only ever used by the fakes.

#ifndef AIRUSB_SESSION_INLINEASYNCPORT_H
#define AIRUSB_SESSION_INLINEASYNCPORT_H

#include "../core/IAsyncUsbDevicePort.h"
#include "../core/IUsbDevicePort.h"

#include <cstdint>
#include <deque>
#include <vector>

namespace airusb::session {

class InlineAsyncPort final : public IAsyncUsbDevicePort {
public:
    explicit InlineAsyncPort(IUsbDevicePort& port) noexcept : _port(port) {}

    const DeviceManifest& manifest() const noexcept override { return _port.manifest(); }

    Status submit(std::uint64_t token, const AsyncTransfer& t) override;
    bool   cancel(std::uint64_t token) override;
    Status clearHalt(std::uint64_t token, std::uint8_t epAddr) override;
    void   poll(const OnOutcome& onOutcome) override;
    void   abortAll(Status with, const OnOutcome& onOutcome) override;

    std::size_t outstanding() const noexcept override { return _done.size(); }

    /// False, and the whole point of the class. See the header.
    bool canIdle() const noexcept override { return false; }

    /// The wrapped port, for callers that still need the synchronous instrument
    /// surface (a `BotProbe` run against the same device).
    IUsbDevicePort& sync() noexcept { return _port; }

private:
    /// A finished transfer waiting for the next `poll()`. The payload is OWNED,
    /// because `AsyncOutcome::dataIn` is a borrowed view and the buffer it
    /// borrows from has to outlive `submit()` returning.
    struct Finished {
        std::uint64_t token     = 0;
        Status        status    = Status::Ok;
        std::uint32_t actualLen = 0;
        bool          cancelled = false;
        bool          zlpSent   = false;
        std::vector<std::uint8_t> data;
    };

    /// wMaxPacketSize for an endpoint, or 0 if the manifest does not describe it.
    /// Needed only by the ZERO_PACKET rule, which has to know whether the
    /// transfer ended on an exact packet boundary.
    std::uint32_t maxPacketFor(std::uint8_t epAddr) const noexcept;

    IUsbDevicePort&      _port;
    std::deque<Finished> _done;
};

} // namespace airusb::session

#endif // AIRUSB_SESSION_INLINEASYNCPORT_H
