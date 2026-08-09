// AirUSB Hub — the exporter's protocol state machine (P1 plan §7.3).
//
// Sits above SecureSession (which decides whether we are talking to anyone we
// trust) and below IUsbDevicePort (which is the actual device). It decides what a
// peer is allowed to ask for, and in what order.
//
//   IDLE → CLAIMING → UNMOUNTING → CAPTURING → LEASED
//   LEASED → DRAINING → RELEASING → IDLE
//   LEASED → ORPHANED                      (silence past T_detach_importer)
//
// ORPHANED KEEPS THE DEVICE CAPTURED. The local OS still cannot mount it. That is
// the fail-closed state and the whole point of the design: a peer that vanished
// mid-write must not have the drive handed back underneath it.
//
// THE TRUST GATE IS ENFORCED HERE, NOT SUGGESTED
//
// §3.14: an unpaired peer may send PAIR_*/PING/GOODBYE and nothing else.
// LIST_DEVICES and ATTACH return NOT_PAIRED. There is no configuration that
// relaxes this, because "the LAN is trusted" is not a security model.

#ifndef AIRUSB_SESSION_EXPORTERSESSION_H
#define AIRUSB_SESSION_EXPORTERSESSION_H

#include "SecureSession.h"
#include "../core/Clock.h"
#include "../core/IUsbDevicePort.h"
#include "../core/Status.h"
#include "../protocol/Messages.h"
#include "../protocol/Segmentation.h"

#include <cstdint>
#include <functional>
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

    /// Captures the device and hands back a port to drive it.
    ///
    /// Returns MountedLocally if a volume could not be unmounted, CaptureFailed
    /// if the OS refused, Busy if it is already leased. The port stays valid
    /// until release().
    virtual Status claim(const protocol::DeviceUid& uid,
                         IUsbDevicePort** portOut,
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
    };

    Status begin(SecureSession* secure, const Config& cfg);

    /// Reads whatever records are available and answers them. Returns Ok when it
    /// ran out of input cleanly, or a fatal status when the session must close.
    Status pump();

    State state() const noexcept { return _state; }
    std::uint32_t attachId() const noexcept { return _attachId; }
    const std::string& lastError() const noexcept { return _why; }

    /// Counters, for logs and tests.
    std::uint64_t messagesHandled() const noexcept { return _handled; }
    std::uint64_t transfersServed() const noexcept { return _transfers; }

    /// Releases whatever is held. Safe to call twice.
    void close();

private:
    Status handle(const protocol::Header& h, std::span<const std::uint8_t> body);
    Status handleListDevices(const protocol::Header& h);
    Status handleAttach(const protocol::Header& h, std::span<const std::uint8_t> body);
    Status handleDetach(const protocol::Header& h, std::span<const std::uint8_t> body);
    Status handleSubmit(const protocol::Header& h, std::span<const std::uint8_t> body);
    Status handleData(const protocol::Header& h, std::span<const std::uint8_t> body);
    Status handleClearHalt(const protocol::Header& h);
    Status handlePing(const protocol::Header& h, std::span<const std::uint8_t> body);

    /// Issues one fully-assembled transfer to the device and answers with a
    /// COMPLETE, segmenting the reply across records when the IN payload exceeds
    /// one. `reqHeader` supplies the channel/request id the reply must echo (and
    /// the type an ERROR would reference). `dataOut` is the ENTIRE OUT payload —
    /// reassembled first for a segmented transfer, so the device sees exactly one
    /// logical transfer and never a segment boundary that would inject a short
    /// packet.
    Status completeSubmit(const protocol::Header& reqHeader,
                          const protocol::SubmitBody& sb,
                          std::span<const std::uint8_t> dataOut);

    /// Drops any half-received segmented OUT transfer and releases its arena.
    void resetReassembly() noexcept;

    Status sendRecord(std::span<const std::uint8_t> record);
    Status sendSimple(wire::Type type, Status status, std::uint64_t requestId,
                      std::span<const std::uint8_t> body);
    Status refuse(const protocol::Header& h, Status status, std::string_view why);

    /// True if the peer has cleared the trust gate for this kind of request.
    bool permitted(wire::Type type) const;

    SecureSession* _secure  = nullptr;
    IDeviceSource* _devices = nullptr;
    const Clock*   _clock   = nullptr;
    std::string    _peerName;

    State           _state = State::Idle;
    std::string     _why;
    IUsbDevicePort* _port  = nullptr;
    DeviceManifest  _manifest;
    std::uint8_t    _configValue = 0;

    protocol::DeviceUid _uid{};
    std::uint32_t _attachId   = 0;
    std::uint32_t _leaseEpoch = 0;
    std::uint8_t  _attachSlot = 0;

    std::uint64_t _handled   = 0;
    std::uint64_t _transfers = 0;
    ContinuousNs  _lastHeardNs = 0;

    /// A segmented OUT transfer being reassembled. The session is one-transfer-
    /// at-a-time today (the pipelined data plane is P2.9/L6), so at most one is
    /// in flight and a single pending slot is enough. The device is not touched
    /// until `_rx` reports the payload complete.
    bool               _rxActive    = false;
    std::uint16_t      _rxChannel   = 0;
    std::uint64_t      _rxRequestId = 0;
    protocol::SubmitBody _rxSb;
    protocol::Reassembler _rx;

    /// Retired attach ids are quarantined for 60 s (§3.8 step 8) so a late
    /// message from a torn-down attach cannot be mistaken for a live one.
    std::uint32_t _nextAttachId = 1;
};

} // namespace airusb::session

#endif // AIRUSB_SESSION_EXPORTERSESSION_H
