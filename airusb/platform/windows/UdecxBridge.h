// AirUSB Hub — the Windows importer's translation layer (W3).
//
// The same problem `VhciNetBridge` solves for Linux, against a different kernel
// ABI. Read that file's header first: the rules it records about never blocking
// between "the kernel has work" and "the kernel is drained" are general, and
// this file obeys them for the same reasons.
//
// WHAT IS DIFFERENT FROM LINUX, AND IT IS NOT ALL HARDER
//
// UdeCx delivers URBs, not transfer descriptors. One URB is already one logical
// transfer, so there is no descriptor-chain walk and no risk of splitting a
// transfer at the wrong boundary — the hazard that dominates the macOS design
// (P1 §5.4) simply does not exist here. The driver forwards URBs whole and this
// bridge never sees a partial one.
//
// What IS harder is lifecycle. vhci-hcd has one socket and an UNLINK message.
// UdeCx has endpoint objects that are created and destroyed by configure
// transactions, endpoints that halt and must be reset, and a purge that stops
// an endpoint dead — each of them a `WDFREQUEST` the driver must complete, and
// each of them able to wedge the USB stack if it is answered late or never.
//
// THREE RULES THAT ARE NOT NEGOTIABLE, ALL FOR THE SAME REASON
//
//   1. **Cancellation is answered immediately**, before any network traffic and
//      without waiting for the far side. The driver has already completed the
//      guest's URB by the time we hear about it; our acknowledgement only says
//      that nothing of ours will touch that id again.
//   2. **Purge is answered immediately.** Every transfer on that endpoint is
//      completed locally, right now. Waiting for a remote acknowledgement would
//      let a slow link — or a dead exporter — hold an endpoint in teardown for
//      ever, which stops the guest's driver from unloading.
//   3. **A configure transaction is answered from local knowledge** wherever it
//      can be. The one that cannot is a genuine SET_CONFIGURATION to a value
//      the exporter did not capture the device in, and that is refused rather
//      than forwarded, because the exporters cannot change configuration
//      (P1 §4.8) and pretending otherwise means the guest builds its endpoint
//      table from a configuration the device is not in.
//
// Each of those is "answer now, be honest, never block". A bridge that waits on
// a WAN round trip to answer a kernel lifecycle callback is the same bug the
// Linux port had to be redesigned around, wearing a different hat.

#ifndef AIRUSB_PLATFORM_WINDOWS_UDECXBRIDGE_H
#define AIRUSB_PLATFORM_WINDOWS_UDECXBRIDGE_H

#include "UdecxIpc.h"

#include "../../core/Clock.h"
#include "../../core/DeviceManifest.h"
#include "../../core/Ep0Arbiter.h"
#include "../../core/Status.h"
#include "../../session/ImporterDataPlane.h"

#include <cstdint>
#include <deque>
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

namespace airusb::windows {

/// The driver channel, as message in / message out.
///
/// Modelled as whole records rather than a byte stream because that is what it
/// really is: each record is one IOCTL. A stream abstraction would invite a
/// partial-record state machine that the real transport can never produce, and
/// then that state machine would be the only untested code in the file.
class IDriverChannel {
public:
    virtual ~IDriverChannel() = default;

    /// One complete record, or false if there is nothing waiting. NEVER blocks.
    virtual bool tryReceive(std::vector<std::uint8_t>& out) = 0;

    /// One complete record to the driver. May buffer; see `pendingToDriver`.
    virtual Status send(std::span<const std::uint8_t> record) = 0;

    /// Bytes accepted but not yet handed to the driver. The bridge pushes these
    /// every poll, because a reply left in a buffer is a URB the guest is still
    /// waiting for — the exact defect that stranded a 128 KiB tail on the
    /// exporter side of this project.
    virtual std::size_t pendingToDriver() const = 0;
    virtual Status flush() = 0;
};

struct UdecxBridgeStats {
    std::uint64_t urbsIn          = 0;
    std::uint64_t answeredLocally = 0;   ///< from the manifest, zero network traffic
    std::uint64_t forwarded       = 0;
    std::uint64_t completed       = 0;
    std::uint64_t cancelled       = 0;
    std::uint64_t timedOut        = 0;
    std::uint64_t refused         = 0;
    std::uint64_t configures      = 0;
    std::uint64_t malformed       = 0;   ///< records the codec refused
};

class UdecxBridge {
public:
    using Trace = std::function<void(const std::string&)>;

    struct Config {
        DeviceManifest manifest;
        /// The configuration the EXPORTER captured the device in. A configure
        /// transaction naming anything else is refused, because no exporter in
        /// this project can change a captured device's configuration.
        std::uint8_t   capturedConfig      = 1;
        std::uint8_t   attachSlot          = 1;
        std::uint32_t  sessionIncarnation  = 0;
        std::uint32_t  deviceIncarnation   = 0;
        std::uint32_t  maxTransferBytes    = 1u << 20;
        const Clock*   clock               = nullptr;
    };

    UdecxBridge(IDriverChannel& channel, session::ImporterDataPlane& plane,
                const Config& cfg);

    void setTrace(Trace t) { _trace = std::move(t); }

    /// One non-blocking step. Drains the driver COMPLETELY before touching the
    /// network, exactly as the Linux bridge does and for the same reason: every
    /// lifecycle record must be answerable while the link is stalled.
    Status poll();

    /// Completes every outstanding transfer as disconnected. Called when the
    /// session dies; after it, the driver plugs the device out.
    void failAll(Status with);

    std::size_t outstanding() const noexcept { return _outstanding.size(); }
    std::size_t queued()      const noexcept { return _queued.size(); }
    const UdecxBridgeStats& stats() const noexcept { return _stats; }
    const std::string& lastError() const noexcept { return _lastError; }
    /// For the test that pins the retired set's bound. Exposed rather than
    /// inferred, because "it does not leak" is not observable from outside.
    std::size_t retiredForTest() const noexcept { return _retired.size(); }

private:
    /// A URB accepted from the driver but not yet on the wire. It carries its
    /// deadline from the moment the DRIVER handed it over, not from the moment
    /// it reaches the network — otherwise a transfer queued behind a full plane
    /// has no clock at all.
    struct Queued {
        ipc::UrbRequest req;
        ContinuousNs    deadlineNs = 0;
    };

    /// A transfer on the wire.
    ///
    /// It carries BOTH ids, and that is not redundancy. The driver's id and the
    /// data plane's id are different namespaces — one is a kernel's, one is
    /// ours — and an early version stored only the driver's, then handed it to
    /// `ImporterDataPlane::cancel()`. The plane never found it, so cancelling
    /// freed the bridge's bookkeeping and left the plane's admission slot
    /// occupied until the original transfer finished on its own. At depth 1
    /// that stalls every subsequent URB.
    ///
    /// The endpoint id is here for the same class of reason: a configure
    /// transaction that RELEASES an endpoint has to retire the transfers
    /// already on the wire for it, not just the queued ones, because the driver
    /// is about to destroy the object their completions would land on.
    struct Outstanding {
        std::uint64_t driverRequestId = 0;
        std::uint16_t channel         = 0;   ///< the plane's
        std::uint64_t planeRequestId  = 0;   ///< the plane's
        std::uint32_t endpointId      = 0;
        std::uint32_t offered         = 0;
        ipc::Direction dir            = ipc::Direction::Out;
    };

    Status drainDriver();
    void   handleRecord(std::span<const std::uint8_t> rec);
    void   onUrbRequest(const ipc::UrbRequest& r);
    void   onCancel(const ipc::CancelRequest& r);
    void   onConfigure(const ipc::Configure& r);

    /// True if this transfer can be answered from the manifest with no network
    /// traffic at all — a GET_DESCRIPTOR the importer already has the bytes for.
    bool answerLocally(const ipc::UrbRequest& r);

    void admitQueued();
    void sweepQueued();
    Status pumpPlane();
    void onCompletion(const session::DataCompletion& c);

    void completeToDriver(std::uint64_t requestId, ipc::Result result,
                          std::uint32_t actualLength,
                          std::span<const std::uint8_t> payload);
    void sendRecord(std::span<const std::uint8_t> bytes);
    bool freshEnough(std::uint32_t session, std::uint32_t device) const noexcept;

    void trace(const std::string& s) const { if (_trace) _trace(s); }

    IDriverChannel&             _channel;
    session::ImporterDataPlane& _plane;
    Config                      _cfg;
    Ep0Arbiter                  _arbiter;

    std::deque<Queued> _queued;
    /// (channel, plane requestId) -> what the driver called it. The plane's id
    /// and the driver's id are different namespaces and must never be conflated:
    /// one is ours, one is a kernel's.
    std::unordered_map<std::uint64_t, Outstanding> _outstanding;
    /// The driver's ids we have already answered. A late completion for one of
    /// these is dropped in silence — normal after a cancellation, not a
    /// protocol violation.
    ///
    /// BOUNDED, and the bound is the point. `ImporterDataPlane` already
    /// guarantees exactly one terminal outcome per submit and drops the late
    /// completion for anything cancelled, so this set is the SECOND lock, not
    /// the mechanism. An unbounded second lock is a leak that grows for the
    /// life of the service — which is a real cost paid for a redundancy — so it
    /// is a fixed-size FIFO and the oldest entry is evicted.
    void retire(std::uint64_t driverRequestId);
    bool isRetired(std::uint64_t driverRequestId) const;
    std::unordered_map<std::uint64_t, bool> _retired;
    std::deque<std::uint64_t>               _retiredOrder;

    UdecxBridgeStats _stats;
    Trace            _trace;
    std::string      _lastError;
    bool             _linkDead = false;
};

} // namespace airusb::windows

#endif // AIRUSB_PLATFORM_WINDOWS_UDECXBRIDGE_H
