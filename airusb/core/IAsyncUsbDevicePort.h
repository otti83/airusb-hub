// AirUSB Hub — the EXPORTER's device seam, and the reason it is not IUsbDevicePort.
//
// WHAT WAS WRONG, IN ONE PARAGRAPH
//
// `ExporterSession` used to call `IUsbDevicePort::bulkIn()` inline while
// processing the session. That is fine for a bulk read from a flash drive, which
// returns in milliseconds, and it is catastrophic for an interrupt IN: an
// interrupt endpoint that has nothing to report legitimately returns NOTHING,
// for ever — a keyboard with no key pressed, a hub with no port change. The
// timeout table already says so (`kUrbDeadlineIntr = 0`, "may legitimately idle
// forever"). A session blocked inside that call cannot answer PING, cannot
// answer DETACH, and cannot answer the CANCEL that would end the wait. So the
// exporter could not carry HID, CDC, or any composite device — not because the
// protocol lacked anything, but because one function call did not return.
//
// WHY IT IS A SECOND INTERFACE RATHER THAN A CHANGE TO THE FIRST
//
// `IUsbDevicePort` is the INSTRUMENT interface. `diag/BotProbe` is written
// against it, `RemoteDevicePort` implements it so the probe cannot tell a remote
// drive from a local one, and that equivalence is what makes a hardware failure
// mean "the hardware path is broken" rather than "the instrument might be".
// Adding submit/poll to it would make every one of those callers carry a state
// machine it does not need, and would not make them asynchronous — a synchronous
// caller of an asynchronous interface is a spin loop with extra steps.
//
// So the split is by ROLE, not by taste: the instrument keeps a synchronous
// interface because it is driven by a program with nothing else to do, and the
// exporter gets an asynchronous one because it is driven by a session that must
// stay answerable. `InlineAsyncPort` bridges them for ports that genuinely
// cannot idle, and says so in its own header rather than pretending.
//
// THE CONTRACT, WHICH IS THE WHOLE VALUE OF THE FILE
//
//   * `submit()` NEVER blocks. It returns as soon as the transfer is accepted.
//   * `poll()` NEVER blocks. It reports whatever finished; "nothing finished" is
//     a normal answer and is not an error.
//   * EXACTLY ONE terminal outcome per accepted token. Not zero — a transfer
//     that evaporates leaves a guest driver waiting for ever — and not two.
//     `cancel()` and `abortAll()` are how the caller forces one; the port may
//     never simply forget a token.
//   * A cancelled transfer's outcome is delivered through `poll()` like any
//     other, with `cancelled = true`. Cancellation is not a separate channel.
//   * `poll()` may be re-entered from nothing: implementations must not call
//     back into `submit()` from inside their own completion callback.

#ifndef AIRUSB_CORE_IASYNCUSBDEVICEPORT_H
#define AIRUSB_CORE_IASYNCUSBDEVICEPORT_H

#include "DeviceManifest.h"
#include "Status.h"
#include "UsbTypes.h"

#include <cstdint>
#include <functional>
#include <span>
#include <vector>

namespace airusb {

/// One logical USB transfer. One of these is ONE call to the device — never
/// split, never coalesced. That rule is the same one `IUsbDevicePort` states,
/// and it is load-bearing for the same reason: a transfer split at a boundary
/// that is not a multiple of wMaxPacketSize injects a short packet, and a short
/// packet is how USB signals the end of a data phase.
struct AsyncTransfer {
    std::uint8_t  epAddr    = 0;
    XferType      xferType  = XferType::Bulk;
    Dir           dir       = Dir::Out;

    /// IN: what the host is offering. OUT: must equal `dataOut.size()`.
    std::uint32_t bufferLen = 0;

    /// Control transfers only; ignored otherwise.
    SetupPacket   setup{};

    /// The OUT payload. BORROWED for the duration of `submit()` only — a port
    /// that cannot issue the transfer synchronously must copy it. Stated here
    /// rather than left to each implementation because the alternative is a
    /// use-after-free that only appears once a transfer is actually deferred.
    std::span<const std::uint8_t> dataOut;

    /// 0 means NO DEADLINE, and it is the correct value for an interrupt IN.
    /// Anything else is milliseconds from the moment the port accepts it.
    std::uint32_t timeoutMs = 0;

    /// USB semantics the guest asked for, carried through rather than dropped.
    ///
    /// `zeroPacket`: the transfer must be terminated with a zero-length packet
    /// when its length is an exact multiple of wMaxPacketSize. Dropped, a device
    /// that is waiting for the terminating ZLP waits for ever.
    ///
    /// `shortNotOk`: a transfer that moves less than was asked for is an ERROR,
    /// not a success with a smaller number. Windows makes the guest say this per
    /// URB; Linux never does. Neither answer may be hardcoded.
    bool zeroPacket = false;
    bool shortNotOk = false;
};

/// The terminal outcome of exactly one submitted transfer.
struct AsyncOutcome {
    std::uint64_t token     = 0;
    Status        status    = Status::Ok;
    std::uint32_t actualLen = 0;

    /// True when this outcome exists because somebody asked for it to stop, not
    /// because the device finished. The distinction reaches the wire as
    /// `kCfWasCancelled`, and a guest that unlinked a URB is told what it asked.
    bool cancelled = false;

    /// A zero-length packet really was sent after the data. Only meaningful for
    /// an OUT that requested one.
    bool zlpSent = false;

    /// IN payload. A BORROWED view, valid only for the duration of the callback.
    std::span<const std::uint8_t> dataIn;
};

/// A device the exporter can drive without ever waiting for it.
class IAsyncUsbDevicePort {
public:
    using OnOutcome = std::function<void(const AsyncOutcome&)>;

    virtual ~IAsyncUsbDevicePort() = default;

    /// The complete descriptor bundle, valid for the lifetime of the port.
    virtual const DeviceManifest& manifest() const noexcept = 0;

    /// Accepts one transfer and returns. NEVER blocks.
    ///
    /// `token` is the caller's name for it and must be unique among the
    /// transfers currently outstanding. Returns Ok if the port has taken
    /// responsibility for producing exactly one outcome for it, Busy if it has
    /// no room right now (the caller queues and retries), or a failure — in
    /// which case NO outcome will be produced for this token, because the port
    /// never took it.
    virtual Status submit(std::uint64_t token, const AsyncTransfer& t) = 0;

    /// Asks for a transfer to stop. NEVER blocks, and is best-effort by nature:
    /// a transfer the device has already completed cannot be un-completed.
    ///
    /// Returns true if the token was outstanding and the port will now report it
    /// (cancelled, or with whatever the device actually did — both are honest).
    /// Returns false if the token is unknown, which is normal: a completion and
    /// a cancellation racing is the ordinary case, not an error.
    virtual bool cancel(std::uint64_t token) = 0;

    /// EP_CLEAR_HALT as a VERB — it must clear the device's stall AND the local
    /// host controller's data toggle. A raw CLEAR_FEATURE forward does only the
    /// first and leaves every later transfer on that endpoint silently wrong.
    ///
    /// Asynchronous like everything else, and reported through `poll()` with
    /// `actualLen == 0`. A stall recovery is followed immediately by a transfer,
    /// so a blocking clear would block exactly when the session can least afford
    /// it.
    virtual Status clearHalt(std::uint64_t token, std::uint8_t epAddr) = 0;

    /// Reports everything that has finished since the last call. NEVER blocks;
    /// firing nothing is a normal outcome.
    virtual void poll(const OnOutcome& onOutcome) = 0;

    /// Produces the one terminal outcome for EVERY outstanding token, right now,
    /// with `with`. Called on detach and on teardown, and it is what makes the
    /// one-outcome-per-token invariant hold when the world ends.
    virtual void abortAll(Status with, const OnOutcome& onOutcome) = 0;

    /// How many tokens are outstanding. Diagnostics and tests only.
    virtual std::size_t outstanding() const noexcept = 0;

    /// Ports that genuinely cannot defer a transfer say so, and the exporter
    /// then refuses to ATTACH a device with an interrupt or isochronous
    /// endpoint rather than wedging on the first idle one.
    ///
    /// This exists because the alternative is worse than a refusal: an exporter
    /// that accepts a keyboard and then stops answering looks like a network
    /// fault, and the person debugging it has no way to see that the transfer
    /// simply never returned.
    virtual bool canIdle() const noexcept = 0;
};

} // namespace airusb

#endif // AIRUSB_CORE_IASYNCUSBDEVICEPORT_H
