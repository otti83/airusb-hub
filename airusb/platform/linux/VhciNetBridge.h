// AirUSB Hub — the event-driven vhci bridge for the NETWORKED importer (L6).
//
// WHY A SECOND BRIDGE
//
// `VhciBridge` is synchronous: read one PDU, call the device, write the reply,
// repeat. That is correct — and proven (L4) — for a LOCAL `IUsbDevicePort` that
// never blocks. It is catastrophic for a device on the far side of a network:
// vhci-hcd drives one socket with two kthreads (tx and rx), its AF_UNIX send
// window cannot hold a large URB atomically, and a bridge that blocks on the
// network while that window fills wedges both sides into an unkillable D-state and
// a reboot (LINUX_IMPORTER_PLAN §4.2).
//
// So this bridge NEVER blocks, and does so STRUCTURALLY, not by trusting a fd to
// be non-blocking. One `poll()` step:
//
//   1. drain the kernel socket COMPLETELY first (R-A) — parse every PDU available
//      now, answer ep0 from the manifest locally, ENQUEUE data/forwarded transfers
//      (touching the network not at all here), and answer CMD_UNLINK IMMEDIATELY.
//   2. sweep queued deadlines (a URB gets its clock the instant the kernel hands
//      it to us, R-C — not when it later reaches the wire).
//   3. admit queued transfers to the async data plane while it has room; only NOW
//      is the network touched, and only after the kernel is fully drained.
//   4. pump the plane: each completion or timeout becomes a buffered RET_SUBMIT.
//   5. flush the kernel tx buffer, non-blocking (R-B).
//
// Nothing between "the kernel is readable" and "the kernel is drained" touches the
// network at all. That is what makes the §4.2 deadlock and the D-state hang
// unreachable, and why CMD_UNLINK is always answerable.

#ifndef AIRUSB_PLATFORM_LINUX_VHCINETBRIDGE_H
#define AIRUSB_PLATFORM_LINUX_VHCINETBRIDGE_H

#include "LinuxUsb.h"
#include "UsbipCodec.h"
#include "VhciBridge.h"   // VhciBridgeStats

#include "../../core/Clock.h"
#include "../../core/DeviceManifest.h"
#include "../../core/Ep0Arbiter.h"
#include "../../core/Status.h"
#include "../../core/Watchdog.h"
#include "../../session/ImporterDataPlane.h"
#include "../../transport/IAirUsbTransport.h"

#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace airusb::linuxvhci {

class VhciNetBridge {
public:
    using Trace = std::function<void(const std::string&)>;

    struct Config {
        /// ep0 control transfers get a deadline STRICTLY below the kernel's own
        /// USB_CTRL_*_TIMEOUT of 5000 ms, or the kernel wins the race (§4.2 R-C).
        std::uint32_t ctrlTimeoutMs = 4000;
        /// Bulk/interrupt: the importer safety net, always above the exporter's
        /// ceiling so the two never race to recover a BOT phase.
        std::uint32_t bulkTimeoutMs = static_cast<std::uint32_t>(watchdog::kUrbWatchdogImporter);
        /// The configuration value the exporter CAPTURED the device in (from
        /// ATTACH). SET_CONFIGURATION to this value is a no-op we can honestly
        /// confirm locally; SET_CONFIGURATION to any other value is refused, because
        /// we cannot reconfigure a remote device and must not lie to the guest that
        /// we did (§5.4). The integration sets this from ATTACH_OK; 1 is the
        /// near-universal single-configuration default.
        std::uint8_t  capturedConfig = 1;
    };

    VhciNetBridge(transport::IByteStream& kernel, session::ImporterDataPlane& plane,
                  const DeviceManifest& manifest, const Clock& clock, const Config& cfg) noexcept;

    void setTrace(Trace t) { _trace = std::move(t); }

    /// One non-blocking iteration (the five steps above). Returns Ok normally, or
    /// TransportLost once a side is gone — after completing every outstanding URB
    /// with -ENODEV so the kernel never waits on one forever. NEVER blocks.
    ///
    /// The real driver arms a `poll(2)` over sv[1] and the network fd and calls this
    /// each time either is ready; the hosted tests call it by hand.
    Status poll();

    const VhciBridgeStats& stats() const noexcept { return _stats; }
    const std::string& lastError() const noexcept { return _lastError; }
    std::size_t pendingSubmits() const noexcept { return _pending.size(); }
    std::size_t outstanding()    const noexcept { return _outstanding.size(); }

    /// Bytes buffered for the kernel that have not been written yet. The poll(2)
    /// loop arms POLLOUT on the kernel fd only while this is non-zero, so a full
    /// kernel socket parks here (R-B) instead of spinning the loop.
    std::size_t pendingKernelTx() const noexcept { return _tx.size() - _txSent; }

private:
    using Ref = std::pair<std::uint16_t, std::uint64_t>;   // (channel, request_id)

    struct Pending {
        UsbipPdu                  pdu;
        std::vector<std::uint8_t> out;         // OUT payload, copied out of the rx buffer
        std::uint8_t              xferType = 0;
        Deadline                  deadline;    // stamped at kernel-admission (R-C)
    };

    Status drainKernel();
    bool   nextPdu(UsbipPdu& pdu, std::span<const std::uint8_t>& payload,
                   std::span<const std::uint8_t>& isoDescs);
    void   compactRx();
    Status flushKernel();
    void   queueToKernel(std::span<const std::uint8_t> bytes);

    Status onSubmit(const UsbipPdu& pdu, std::span<const std::uint8_t> outData,
                    std::span<const std::uint8_t> isoDescs);
    Status onUnlink(const UsbipPdu& pdu);

    void enqueue(const UsbipPdu& pdu, std::uint8_t xferType, std::uint32_t timeoutMs,
                 std::span<const std::uint8_t> outData);
    void doSubmit(const UsbipPdu& pdu, std::uint8_t xferType, std::uint32_t timeoutMs,
                  std::span<const std::uint8_t> outData);
    void sweepPending();       // R-C for URBs still queued behind a full plane
    void admitPending();       // the ONLY place the network is touched from a submit

    void refuseIso(const UsbipPdu& pdu, std::span<const std::uint8_t> isoDescs);

    Status pumpPlane();
    void   onCompletion(const session::DataCompletion& c);
    void   failAll(Status with);

    void localData(const UsbipPdu& cmd, std::span<const std::uint8_t> data);
    void localStatus(const UsbipPdu& cmd, std::int32_t status, std::int32_t actualLength);
    void completeToKernel(const UsbipPdu& cmd, std::int32_t status,
                          std::int32_t actualLength, std::span<const std::uint8_t> payload);

    bool lookupEndpoint(std::uint8_t addr, EndpointModel& out) const;

    void trace(const std::string& s) const { if (_trace) _trace(s); }

    transport::IByteStream&     _kernel;
    session::ImporterDataPlane& _plane;
    const DeviceManifest&       _manifest;
    const Clock&                _clock;
    Ep0Arbiter                  _arbiter;
    Config                      _cfg;

    std::vector<std::uint8_t> _rx;
    std::size_t               _rxHead = 0;
    std::vector<std::uint8_t> _tx;
    std::size_t               _txSent = 0;

    std::map<Ref, UsbipPdu>                _outstanding;   ///< (channel,rid) -> the CMD_SUBMIT
    std::unordered_map<std::uint32_t, Ref> _bySeqnum;      ///< seqnum -> (channel,rid)
    std::deque<Pending>                    _pending;       ///< accepted, not yet on the wire

    VhciBridgeStats _stats;
    Trace           _trace;
    std::string     _lastError;
    bool            _decodeFatal = false;
};

} // namespace airusb::linuxvhci

#endif // AIRUSB_PLATFORM_LINUX_VHCINETBRIDGE_H
