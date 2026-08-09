// AirUSB Hub — the async, non-blocking importer data plane (LINUX_IMPORTER_PLAN §4.2).
//
// WHY THIS EXISTS, AND WHY IT IS NOT RemoteDevicePort
//
// `RemoteDevicePort` sends one SUBMIT and then SPINS in `receiveRecord()` until
// the matching COMPLETE arrives. That is correct behind a caller that owns the
// socket and has nothing else to service — `diag/BotProbe`, a CLI. It is
// CATASTROPHICALLY wrong behind Linux's `vhci-hcd`: the kernel writes CMD_SUBMIT
// and reads RET_SUBMIT over ONE socket via two independent kthreads, the AF_UNIX
// send window cannot hold a single large URB atomically so `vhci_tx` parks
// mid-message as normal behaviour, and if the bridge ever blocks on the network
// while that window fills, both sides wait forever — an unkillable `D`-state task
// and a machine that must be rebooted (§4.2).
//
// So this data plane NEVER BLOCKS. `submit()` emits and returns; `pump()` drains
// whatever the network has RIGHT NOW and returns; buffering absorbs a slow socket
// instead of a blocking write. The event loop above it (the vhci bridge) is then
// free to keep draining the kernel socket every iteration — which is the one rule
// (§4.2 R-A) that makes CMD_UNLINK answerable and the deadlock unreachable.
//
// It is deliberately not aggressive: admission depth defaults to ONE. "Async" here
// means "independent progress", not "maximum concurrency" — usb-storage issues one
// bulk transfer at a time (`can_queue = 1`), and correctness comes first.
//
// INVARIANT I1: exactly one terminal outcome per submit. Enforced by `RequestTable`
// (which also enforces R8) plus `completeAll()` on teardown and `sweepDeadlines()`
// (R-C) on silence. A transfer never evaporates when the link dies.

#ifndef AIRUSB_SESSION_IMPORTERDATAPLANE_H
#define AIRUSB_SESSION_IMPORTERDATAPLANE_H

#include "../core/Clock.h"
#include "../core/RequestTable.h"
#include "../core/Status.h"
#include "../core/UsbTypes.h"
#include "../protocol/Segmentation.h"
#include "../transport/RecordLayer.h"

#include <cstdint>
#include <functional>
#include <map>
#include <span>
#include <utility>
#include <vector>

namespace airusb::session {

/// One transfer's terminal outcome, delivered synchronously from `pump()`,
/// `sweepDeadlines()`, or `completeAll()`.
struct DataCompletion {
    std::uint16_t channel      = 0;
    std::uint64_t requestId    = 0;
    std::uint8_t  epAddr       = 0;
    Dir           dir          = Dir::Out;
    Status        status       = Status::Ok;
    std::uint32_t requestedLen = 0;
    std::uint32_t actualLen    = 0;
    bool          shortXfer    = false;
    /// IN payload. A BORROWED view, valid only for the duration of the callback —
    /// the bytes live in the plane's reassembly arena and are released after.
    std::span<const std::uint8_t> data;
};

/// A verb's outcome. Verbs are not transfers: they carry no data, they are not
/// admitted against the transfer depth, and their reply is a CTRL_ACK rather
/// than a COMPLETE.
struct VerbCompletion {
    std::uint16_t channel   = 0;
    std::uint64_t requestId = 0;
    std::uint8_t  epAddr    = 0;
    Status        status    = Status::Ok;
};

class ImporterDataPlane {
public:
    using OnComplete = std::function<void(const DataCompletion&)>;
    using OnVerb     = std::function<void(const VerbCompletion&)>;

    struct Config {
        std::uint32_t attachId         = 0;
        std::uint8_t  attachSlot       = 0;
        /// Admission depth. v1 ships ONE; the machinery (RequestTable, keyed
        /// reassembly) already supports more, so raising it is a later, measured
        /// step — not a rewrite.
        std::size_t   maxInFlight      = 1;
        std::uint32_t maxTransferBytes = wire::kTransferBytesDefault;
    };

    ImporterDataPlane(transport::RecordLayer* link, const Clock* clock, const Config& cfg);

    /// Can another transfer be admitted right now?
    bool canAdmit() const noexcept { return _table.size() < _cfg.maxInFlight; }
    std::size_t outstanding() const noexcept { return _table.size(); }

    /// Submits one transfer WITHOUT waiting. On Ok, `*channelOut`/`*requestIdOut`
    /// receive the identity the completion will carry, so the caller can map it
    /// back to a kernel seqnum. Returns Busy if the in-flight cap is reached (the
    /// caller queues and retries), or a fatal status if the link is already dead.
    /// `timeoutMs == 0` means "no deadline" (an interrupt IN may idle forever).
    Status submit(std::uint8_t epAddr, std::uint8_t xferType, std::uint8_t dir,
                  std::uint32_t bufferLen, const std::uint8_t setup[8],
                  std::span<const std::uint8_t> dataOut, std::uint32_t timeoutMs,
                  std::uint16_t* channelOut, std::uint64_t* requestIdOut);

    /// EP_CLEAR_HALT, asynchronously.
    ///
    /// A VERB, not a forwarded CLEAR_FEATURE. The exporter's `clearHalt` clears
    /// the device's stall AND the exporter host controller's data toggle; a raw
    /// forward clears only the first and leaves every later transfer on that
    /// endpoint silently wrong.
    ///
    /// It has to be asynchronous for the same reason everything else here does:
    /// a stall is answered by the guest's driver immediately, and a bridge that
    /// blocked on a LAN round trip to clear it would hold the kernel's endpoint
    /// callback across the network.
    ///
    /// The reply is a CTRL_ACK, and it is dispatched HERE — which is what makes
    /// the old hazard unreachable. When `clearHalt` was fire-and-forget its
    /// acknowledgement was left in the stream for whatever read next to
    /// mistake for its own COMPLETE, and a stall recovery is always followed
    /// immediately by a transfer, so the misread was the common case rather
    /// than a rare one.
    Status clearHalt(std::uint8_t epAddr, std::uint16_t* channelOut,
                     std::uint64_t* requestIdOut);

    std::size_t verbsOutstanding() const noexcept { return _verbs.size(); }

    /// Non-blocking. Flushes buffered tx, drains every record available RIGHT NOW,
    /// and fires `onComplete` once per finished transfer. Returns Ok when the input
    /// is momentarily drained, or a fatal status if the link died (the caller then
    /// completes the rest with `completeAll`). NEVER blocks on I/O.
    Status pump(const OnComplete& onComplete, const OnVerb& onVerb = {});

    /// R-C: completes locally, with XferTimeout, every transfer whose deadline has
    /// passed. The kernel has no timeout of its own; ours is the only one.
    void sweepDeadlines(const OnComplete& onComplete, const OnVerb& onVerb = {});

    /// Drops one outstanding transfer locally WITHOUT firing a completion — used
    /// when the kernel unlinks a URB, whose terminal outcome is the RET_UNLINK the
    /// bridge sends, not a RET_SUBMIT. A later COMPLETE for it then matches nothing
    /// and is dropped. Returns true if it was outstanding.
    bool cancel(std::uint16_t channel, std::uint64_t requestId);

    /// Completes EVERY outstanding transfer locally with `with` (teardown / device
    /// gone), so I1 holds when the link dies: no URB is left for the kernel to wait
    /// on forever.
    void completeAll(Status with, const OnComplete& onComplete,
                     const OnVerb& onVerb = {});

    /// Diagnostics.
    std::size_t pendingReplies() const noexcept { return _pendingReply.size(); }
    std::size_t bytesBuffered()  const noexcept { return _link ? _link->pendingTxBytes() : 0; }

private:
    using ReplyKey = std::pair<std::uint16_t, std::uint64_t>;

    /// Metadata for a segmented reply still being reassembled. The request stays in
    /// the table (its deadline still guards it) until the last segment lands.
    struct PendingReply {
        Status        status    = Status::Ok;
        std::uint32_t actualLen = 0;
        bool          shortXfer = false;
    };

    /// A verb awaiting its CTRL_ACK. Kept out of `RequestTable` on purpose: that
    /// table is the transfer admission accounting, and a verb that consumed a
    /// slot would let a stall recovery be blocked by the very transfers it
    /// exists to unblock.
    struct PendingVerb {
        std::uint8_t epAddr     = 0;
        ContinuousNs deadlineNs = 0;
    };

    Status handleCtrlAck(const protocol::Header& h, const OnVerb& onVerb);

    Status handleComplete(const protocol::Header& h,
                          const std::vector<std::uint8_t>& rec,
                          const OnComplete& onComplete);
    Status handleData(const protocol::Header& h,
                      const std::vector<std::uint8_t>& rec,
                      const OnComplete& onComplete);
    void deliver(const OutstandingRequest& req, Status status, std::uint32_t actualLen,
                 bool shortXfer, std::span<const std::uint8_t> data,
                 const OnComplete& onComplete);
    void drop(std::uint16_t channel, std::uint64_t requestId);

    transport::RecordLayer* _link  = nullptr;
    const Clock*            _clock = nullptr;
    Config                  _cfg;
    RequestTable            _table;
    protocol::Reassembler   _reasm;
    std::map<ReplyKey, PendingReply> _pendingReply;
    std::map<ReplyKey, PendingVerb>  _verbs;
    std::uint64_t                    _nextVerbId = 1;
};

} // namespace airusb::session

#endif // AIRUSB_SESSION_IMPORTERDATAPLANE_H
