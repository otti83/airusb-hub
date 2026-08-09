// AirUSB Hub — the exporter's protocol state machine (P1 plan §7.3).
//
// Sits above SecureSession (which decides whether we are talking to anyone we
// trust) and below IAsyncUsbDevicePort (which is the actual device). It decides
// what a peer is allowed to ask for, and in what order.
//
//   IDLE → LEASED → DRAINING → IDLE
//   LEASED → ORPHANED                      (silence, or the transport dying)
//
// ORPHANED KEEPS THE DEVICE CAPTURED, AND — SINCE 2026-08-09 — KEEPS IT
// RESERVED FOR THE PEER THAT HAD IT. That second half used to be missing and it
// was the more important one: the session correctly refused to release the
// capture and then DIED, taking the only record of who owned the device with
// it, and the serving loop handed the same drive to the next peer that
// connected. Ownership now lives in `LeaseAuthority`, which outlives every
// session; see its header for why that is a lifetime rather than an `if`.
//
// NOTHING HERE EVER WAITS FOR THE DEVICE
//
// It used to. `completeSubmit()` called `bulkIn()` inline, and an interrupt IN
// with nothing to report legitimately never returns — a keyboard with no key
// pressed. So a session could be blocked inside one function call while PING,
// DETACH and the CANCEL that would end the wait all sat unread in the socket.
// That is why this exporter could not carry HID, CDC or any composite device.
//
// Now `pump()` is an event loop with four steps and no blocking call in any of
// them:
//
//   1. push whatever the socket would not take last time,
//   2. read and answer every record available RIGHT NOW — including CANCEL and
//      DETACH, which is the whole point,
//   3. admit queued transfers to the device, at most one per endpoint,
//   4. collect whatever the device finished and reply.
//
// ONE TRANSFER PER ENDPOINT, AND ep0 IS A BARRIER
//
// USB serialises per endpoint, so a second transfer on the same endpoint waits
// in that endpoint's FIFO rather than racing. ep0 is stricter still: a control
// transfer can change the device's configuration or alternate setting, which
// redefines what every other endpoint even IS. So ep0 admits only when nothing
// else is outstanding, and nothing else admits while ep0 is.
//
// THE TRUST GATE IS ENFORCED HERE, NOT SUGGESTED
//
// §3.14: an unpaired peer may send PAIR_*/PING/GOODBYE and nothing else.
// LIST_DEVICES and ATTACH return NOT_PAIRED. There is no configuration that
// relaxes this, because "the LAN is trusted" is not a security model.

#ifndef AIRUSB_SESSION_EXPORTERSESSION_H
#define AIRUSB_SESSION_EXPORTERSESSION_H

#include "LeaseAuthority.h"
#include "SecureSession.h"
#include "../core/Clock.h"
#include "../core/IAsyncUsbDevicePort.h"
#include "../core/IUsbDevicePort.h"
#include "../core/Status.h"
#include "../protocol/Messages.h"
#include "../protocol/Segmentation.h"

#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <string>
#include <vector>

namespace airusb::session {

/// What the exporter can offer, and how to get at it.
///
/// A seam rather than a concrete device list so the same session code runs
/// against ScriptedDevice in CI and against real captured hardware.
class IDeviceSource {
public:
    virtual ~IDeviceSource() = default;

    /// Everything shareable from this machine, already filtered: no boot disk,
    /// and nothing that arrived over AirUSB (re-export is forbidden in v1 —
    /// it creates forwarding loops).
    virtual std::vector<protocol::DeviceRecord> list() = 0;

    /// Captures the device and hands back an ASYNCHRONOUS port to drive it.
    ///
    /// Returns MountedLocally if a volume could not be unmounted, CaptureFailed
    /// if the OS refused, Busy if it is already leased. The port stays valid
    /// until release().
    ///
    /// A source whose backend is synchronous wraps it in `InlineAsyncPort`,
    /// which says `canIdle() == false` — and this session then refuses to
    /// attach a device with an interrupt or isochronous endpoint rather than
    /// accepting it and hanging on the first idle transfer.
    virtual Status claim(const protocol::DeviceUid& uid,
                         IAsyncUsbDevicePort** portOut,
                         DeviceManifest& manifestOut,
                         std::uint8_t* currentConfigValueOut,
                         std::string* whyNot) = 0;

    virtual void release(const protocol::DeviceUid& uid) = 0;
};

class ExporterSession {
public:
    enum class State : std::uint8_t {
        Idle,
        Leased,
        Draining,
        Orphaned,
        Closed,
    };

    struct Config {
        IDeviceSource* devices = nullptr;
        const Clock*   clock   = nullptr;
        std::string    peerName;

        /// Who owns the device, across sessions. MUST outlive this object and
        /// MUST be shared by every session against the same device source —
        /// that sharing is the entire mechanism. Null means "no exclusivity",
        /// which is only acceptable in a unit test that is testing something
        /// else, and `begin()` says so rather than silently allowing it.
        LeaseAuthority* leases = nullptr;
    };

    Status begin(SecureSession* secure, const Config& cfg);

    /// One non-blocking iteration of the four steps in the header. Returns Ok
    /// when it ran out of input cleanly, or a fatal status when the session must
    /// close. NEVER blocks on the device or on the network.
    Status pump();

    State state() const noexcept { return _state; }
    std::uint32_t attachId() const noexcept { return _attachId; }
    const std::string& lastError() const noexcept { return _why; }

    /// Counters, for logs and tests.
    std::uint64_t messagesHandled()   const noexcept { return _handled; }
    std::uint64_t transfersServed()   const noexcept { return _transfers; }
    std::uint64_t transfersCancelled() const noexcept { return _cancelled; }
    /// Transfers accepted but not yet handed to the device. A test asserts this
    /// is non-zero while an endpoint is busy, which is how "queued rather than
    /// raced" is checked rather than assumed.
    std::size_t   queuedTransfers()   const noexcept;
    std::size_t   inFlightTransfers() const noexcept { return _inFlight.size(); }

    /// Releases whatever is held. Safe to call twice.
    void close();

private:
    /// A transfer the peer has asked for. `dataOut` is OWNED — the record it
    /// arrived in is gone by the time this reaches the device.
    struct Pending {
        std::uint16_t             channel   = 0;
        std::uint64_t             requestId = 0;
        protocol::SubmitBody      sb;
        std::vector<std::uint8_t> dataOut;
        Deadline                  deadline;   ///< stamped when WE accepted it
    };

    /// A transfer the device currently owns.
    struct InFlight {
        std::uint16_t        channel   = 0;
        std::uint64_t        requestId = 0;
        std::uint8_t         epAddr    = 0;
        protocol::SubmitBody sb;
        Deadline             deadline;
        bool                 cancelRequested = false;
    };

    Status handle(const protocol::Header& h, std::span<const std::uint8_t> body);
    Status handleListDevices(const protocol::Header& h);
    Status handleAttach(const protocol::Header& h, std::span<const std::uint8_t> body);
    Status handleDetach(const protocol::Header& h, std::span<const std::uint8_t> body);
    Status handleSubmit(const protocol::Header& h, std::span<const std::uint8_t> body);
    Status handleData(const protocol::Header& h, std::span<const std::uint8_t> body);
    Status handleCancel(const protocol::Header& h, std::span<const std::uint8_t> body);
    Status handleClearHalt(const protocol::Header& h);
    Status handleDeviceReset(const protocol::Header& h);
    Status handlePing(const protocol::Header& h, std::span<const std::uint8_t> body);

    /// Accepts one fully-assembled transfer into its endpoint's queue. The
    /// device is NOT touched here — that is `admit()`, and keeping them apart is
    /// what lets a record be answered while the device is busy.
    Status enqueueTransfer(const protocol::Header& reqHeader,
                           const protocol::SubmitBody& sb,
                           std::span<const std::uint8_t> dataOut);

    /// Hands queued transfers to the device while their endpoints are free.
    /// The ONLY place the device is submitted to.
    void admit();

    /// Collects finished transfers and answers them.
    Status collect();

    /// Completes locally, with `st`, every transfer whose deadline has passed —
    /// both queued and in flight. The device has no timeout of its own.
    Status sweepDeadlines();

    /// Emits the COMPLETE for one finished transfer, segmenting an IN payload
    /// across records when it exceeds one.
    Status emitComplete(const InFlight& f, Status st, std::uint32_t actualLen,
                        bool cancelled, bool zlpSent,
                        std::span<const std::uint8_t> payload);

    /// True if ep0 may admit (nothing else outstanding) or a data endpoint may
    /// (ep0 not outstanding, and that endpoint idle).
    bool mayAdmit(std::uint8_t epAddr) const;

    /// Drops any half-received segmented OUT transfer and releases its arena.
    void resetReassembly() noexcept;

    /// Completes every queued and in-flight transfer with `st`, so no request
    /// the peer is waiting on evaporates. Invariant I1, exporter side.
    void failAllTransfers(Status st);

    Status sendRecord(std::span<const std::uint8_t> record);
    Status sendSimple(wire::Type type, Status status, std::uint64_t requestId,
                      std::span<const std::uint8_t> body);
    Status refuse(const protocol::Header& h, Status status, std::string_view why);

    /// True if the peer has cleared the trust gate for this kind of request.
    bool permitted(wire::Type type) const;

    SecureSession*  _secure  = nullptr;
    IDeviceSource*  _devices = nullptr;
    const Clock*    _clock   = nullptr;
    LeaseAuthority* _leases  = nullptr;
    std::string     _peerName;

    State                _state = State::Idle;
    std::string          _why;
    IAsyncUsbDevicePort* _port  = nullptr;
    DeviceManifest       _manifest;
    std::uint8_t         _configValue = 0;

    protocol::DeviceUid _uid{};
    std::uint32_t _attachId   = 0;
    std::uint32_t _leaseEpoch = 0;
    std::uint8_t  _attachSlot = 0;

    std::uint64_t _handled   = 0;
    std::uint64_t _transfers = 0;
    std::uint64_t _cancelled = 0;
    ContinuousNs  _lastHeardNs = 0;

    /// Per-endpoint FIFOs. USB serialises per endpoint, so this is the natural
    /// unit: a second transfer on a busy endpoint waits here rather than racing
    /// one that is already on the bus.
    std::map<std::uint8_t, std::deque<Pending>> _queues;

    /// The device's token for a transfer -> what the peer calls it. The token is
    /// ours to choose and is never reused within a session, so a late outcome
    /// from a retired transfer matches nothing and is dropped.
    std::map<std::uint64_t, InFlight> _inFlight;
    std::uint64_t _nextToken = 1;

    /// Endpoints with exactly one transfer on the device right now.
    std::map<std::uint8_t, std::uint64_t> _busyEndpoint;

    /// Verbs (CLEAR_HALT, DEVICE_RESET) awaiting their outcome. Kept out of the
    /// transfer accounting on purpose: a verb that consumed an endpoint's slot
    /// would let a stall recovery be blocked by the very transfer it exists to
    /// unblock.
    struct PendingVerb {
        std::uint64_t requestId = 0;
        std::uint8_t  epAddr    = 0;
        bool          isReset   = false;
    };
    std::map<std::uint64_t, PendingVerb> _verbs;

    /// A segmented OUT transfer being reassembled. One at a time: segmentation
    /// is a property of the RECORD stream, which is serial, so two interleaved
    /// segmented transfers cannot be distinguished from a misframed one.
    bool                  _rxActive    = false;
    std::uint16_t         _rxChannel   = 0;
    std::uint64_t         _rxRequestId = 0;
    protocol::SubmitBody  _rxSb;
    protocol::Reassembler _rx;
};

} // namespace airusb::session

#endif // AIRUSB_SESSION_EXPORTERSESSION_H
