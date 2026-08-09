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
// So this bridge NEVER blocks. It owns no socket-spinning loop; one `poll()` step
// does bounded, non-blocking work and returns:
//
//   1. drain the kernel socket FIRST and unconditionally (R-A) — parse every PDU
//      available now, answer ep0 from the manifest locally, admit data/forwarded
//      transfers to the async data plane (or queue them), and answer CMD_UNLINK
//      IMMEDIATELY.
//   2. admit anything queued while the plane has room.
//   3. pump the data plane: each completion (or timeout, R-C) becomes a RET_SUBMIT
//      buffered for the kernel.
//   4. flush the kernel tx buffer, non-blocking (R-B) — a full kernel socket
//      buffers here, it never blocks the loop.
//
// Nothing between "the kernel is readable" and "the kernel is drained" ever waits
// on the network. That single property is what makes the §4.2 deadlock and the
// D-state hang unreachable, and it is why CMD_UNLINK is always answerable.
//
// The real driver wraps `run()`/`poll()` in a `poll(2)` over sv[1] and the network
// fd; the hosted tests feed PDUs through a `MemoryPipe` and call `poll()` by hand,
// so every liveness rule is proven with no kernel in the loop.

#ifndef AIRUSB_PLATFORM_LINUX_VHCINETBRIDGE_H
#define AIRUSB_PLATFORM_LINUX_VHCINETBRIDGE_H

#include "LinuxUsb.h"
#include "UsbipCodec.h"
#include "VhciBridge.h"   // VhciBridgeStats

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
        /// The channel/slot is the data plane's business, not the bridge's — the
        /// bridge only echoes the (channel, request_id) the plane hands back.
        std::uint32_t ctrlTimeoutMs = 4000;
        /// Bulk/interrupt: the importer safety net, always above the exporter's
        /// ceiling so the two never race to recover a BOT phase.
        std::uint32_t bulkTimeoutMs = static_cast<std::uint32_t>(watchdog::kUrbWatchdogImporter);
    };

    VhciNetBridge(transport::IByteStream& kernel, session::ImporterDataPlane& plane,
                  const DeviceManifest& manifest, const Config& cfg) noexcept;

    void setTrace(Trace t) { _trace = std::move(t); }

    /// One non-blocking iteration (the four steps above). Returns Ok normally, or
    /// TransportLost once a side is gone — after completing every outstanding URB
    /// with -ENODEV so the kernel never waits on one forever. NEVER blocks.
    ///
    /// The real driver arms a `poll(2)` over sv[1] and the network fd and calls this
    /// each time either is ready; the hosted tests call it by hand. There is
    /// deliberately no built-in `run()` busy-loop: "nothing to do right now" and
    /// "the session is over" are different, and only the fd layer can tell them
    /// apart without spinning.
    Status poll();

    const VhciBridgeStats& stats() const noexcept { return _stats; }
    const std::string& lastError() const noexcept { return _lastError; }
    std::size_t pendingSubmits() const noexcept { return _pending.size(); }
    std::size_t outstanding()    const noexcept { return _outstanding.size(); }

private:
    using Ref = std::pair<std::uint16_t, std::uint64_t>;   // (channel, request_id)

    struct Pending {
        UsbipPdu                  pdu;
        std::vector<std::uint8_t> out;         // OUT payload, copied out of the rx buffer
        std::uint8_t              xferType = 0;
        std::uint32_t             timeoutMs = 0;
    };

    Status drainKernel();
    bool   nextPdu(UsbipPdu& pdu, std::span<const std::uint8_t>& payload);
    void   compactRx();
    Status flushKernel();
    void   queueToKernel(std::span<const std::uint8_t> bytes);

    Status onSubmit(const UsbipPdu& pdu, std::span<const std::uint8_t> outData);
    Status onUnlink(const UsbipPdu& pdu);

    void admit(const UsbipPdu& pdu, std::uint8_t xferType, std::uint32_t timeoutMs,
               std::span<const std::uint8_t> outData);
    void doSubmit(const UsbipPdu& pdu, std::uint8_t xferType, std::uint32_t timeoutMs,
                  std::span<const std::uint8_t> outData);
    void admitPending();

    Status pumpPlane();                        // plane.pump + sweepDeadlines
    void   onCompletion(const session::DataCompletion& c);
    void   failAll(Status with);

    // ep0 local answers (no network).
    void localData(const UsbipPdu& cmd, std::span<const std::uint8_t> data);
    void localStatus(const UsbipPdu& cmd, std::int32_t status, std::int32_t actualLength);

    // RET_SUBMIT for a networked completion, clamped so we never over-report.
    void completeToKernel(const UsbipPdu& cmd, std::int32_t status,
                          std::int32_t actualLength, std::span<const std::uint8_t> payload);

    bool lookupEndpoint(std::uint8_t addr, EndpointModel& out) const;

    void trace(const std::string& s) const { if (_trace) _trace(s); }

    transport::IByteStream&     _kernel;
    session::ImporterDataPlane& _plane;
    const DeviceManifest&       _manifest;
    Ep0Arbiter                  _arbiter;
    Config                      _cfg;

    std::vector<std::uint8_t> _rx;
    std::size_t               _rxHead = 0;
    std::vector<std::uint8_t> _tx;
    std::size_t               _txSent = 0;

    std::map<Ref, UsbipPdu>                      _outstanding;   ///< (channel,rid) -> the CMD_SUBMIT
    std::unordered_map<std::uint32_t, Ref>       _bySeqnum;      ///< seqnum -> (channel,rid)
    std::deque<Pending>                          _pending;       ///< admission-blocked submits

    VhciBridgeStats _stats;
    Trace           _trace;
    std::string     _lastError;
    bool            _decodeFatal = false;
};

} // namespace airusb::linuxvhci

#endif // AIRUSB_PLATFORM_LINUX_VHCINETBRIDGE_H
