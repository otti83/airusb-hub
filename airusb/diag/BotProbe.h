// AirUSB Hub — a read-only USB Mass Storage Bulk-Only Transport prober.
//
// WHAT THIS IS FOR
//
// P2.8's gate is one sentence: "a real CBW -> data -> CSW exchange through pipes
// the agent obtained while the daemon holds the capture." This is the instrument
// that performs that exchange and reports what happened in enough detail to tell
// a working transport from a broken one.
//
// It is a DIAGNOSTIC, not the data path. AirUSB forwards opaque USB transfers and
// knows nothing about SCSI; nothing in core/, protocol/ or transport/ includes
// this header. It exists because the first device class being proven is mass
// storage, and mass storage is unforgiving in a way that makes it a good test
// instrument: a transfer boundary in the wrong place produces a hard stall rather
// than a silently wrong byte.
//
// IT NEVER WRITES. Every command issued is read-only (GET_MAX_LUN, TEST UNIT
// READY, INQUIRY, READ CAPACITY(10), READ(10)). Pointing it at a drive cannot
// damage its contents. The drive must still be unmounted first, which the exporter
// enforces separately.
//
// WHY IT IS PORTABLE C++ AND NOT PART OF platform/macos
//
// It drives an IUsbDevicePort, so the identical code runs against ScriptedDevice
// in CI on every commit and against a real captured drive on hardware. A probe
// that had only ever run against hardware would be untrustworthy exactly when it
// mattered: a failure would be equally consistent with a broken probe.
//
// References: USB Mass Storage Class Bulk-Only Transport 1.0 §5.1 (CBW), §5.2
// (CSW), §6.7.2/6.7.3 (the thirteen host/device length cases), SCSI SPC-4/SBC-3
// for the command descriptor blocks. SCSI CDB fields are BIG endian.

#ifndef AIRUSB_DIAG_BOTPROBE_H
#define AIRUSB_DIAG_BOTPROBE_H

#include "../core/DeviceManifest.h"
#include "../core/IUsbDevicePort.h"
#include "../core/Status.h"

#include <cstdint>
#include <functional>
#include <span>
#include <string>
#include <vector>

namespace airusb::diag {

// --- Bulk-Only Transport wire constants (BOT 1.0) ----------------------------

inline constexpr std::uint32_t kCbwSignature = 0x43425355u;  // "USBC"
inline constexpr std::uint32_t kCswSignature = 0x53425355u;  // "USBS"
inline constexpr std::size_t   kCbwLength    = 31;
inline constexpr std::size_t   kCswLength    = 13;

/// Mass Storage class / SCSI transparent subclass / Bulk-Only protocol.
inline constexpr std::uint8_t kMscClass    = 0x08;
inline constexpr std::uint8_t kScsiSubclass = 0x06;
inline constexpr std::uint8_t kBotProtocol  = 0x50;

// --- endpoint discovery ------------------------------------------------------

struct BotEndpoints {
    std::uint8_t  bulkIn         = 0;   ///< bEndpointAddress, direction bit set
    std::uint8_t  bulkOut        = 0;   ///< bEndpointAddress, direction bit clear
    std::uint8_t  interfaceNumber = 0;
    std::uint8_t  altSetting     = 0;
    std::uint16_t maxPacketSize  = 0;   ///< of the bulk IN endpoint

    bool valid() const noexcept
    {
        return bulkIn != 0 && bulkOut != 0 && (bulkIn & 0x80u) != 0 && (bulkOut & 0x80u) == 0;
    }
};

/// Locate the Bulk-Only Transport interface in the given configuration.
/// Returns false if the device has no 08/06/50 interface with a bulk IN and a
/// bulk OUT endpoint — which simply means it is not a BOT mass storage device and
/// this probe does not apply to it.
bool findBotInterface(const DeviceManifest& manifest,
                      std::uint8_t configValue,
                      BotEndpoints& out);

// --- results -----------------------------------------------------------------

struct BotStep {
    std::string  name;
    Status       status  = Status::Ok;
    bool         passed  = false;
    std::string  detail;
};

struct BotProbeResult {
    bool                  passed = false;
    std::string           failure;          ///< first failure, empty on success
    std::vector<BotStep>  steps;

    // Device facts, as read from the device rather than assumed.
    bool         maxLunStalled = false;     ///< a legal answer meaning "one LUN"
    std::uint8_t maxLun        = 0;
    std::string  vendor;                    ///< INQUIRY bytes 8..15
    std::string  product;                   ///< INQUIRY bytes 16..31
    std::string  revision;                  ///< INQUIRY bytes 32..35
    std::uint8_t peripheralDeviceType = 0xFF;
    bool         removableMedium = false;

    std::uint32_t blockSize = 0;
    std::uint64_t lastLba   = 0;            ///< READ CAPACITY(10) returns the LAST
                                            ///< LBA, not the block count
    std::uint64_t blockCount() const noexcept { return lastLba + 1; }

    std::vector<std::uint8_t> sector0;
    bool         sector0HasBootSignature = false;   ///< 0x55 0xAA at offset 510

    // Transport evidence — this is what P2.8 is actually measuring.
    std::uint32_t cbwCount        = 0;      ///< 31-byte OUT transfers issued
    std::uint32_t dataPhases      = 0;
    std::uint32_t cswCount        = 0;
    std::uint32_t stallRecoveries = 0;
    std::uint32_t shortReads      = 0;

    /// OQ-1 evidence: every CBW left as exactly 31 bytes in exactly one transfer,
    /// and every data phase returned in exactly one transfer. False means the
    /// layer beneath split or coalesced a logical URB.
    bool transferBoundariesIntact = true;

    std::string summary() const;
};

// --- the probe ---------------------------------------------------------------

class BotProbe {
public:
    /// `trace` receives one line per USB transfer, so a hardware run produces a
    /// log that can be read against the BOT spec rather than merely a verdict.
    using Trace = std::function<void(const std::string& line)>;

    BotProbe(IUsbDevicePort& port, const BotEndpoints& endpoints) noexcept
        : _port(port), _eps(endpoints) {}

    void setTrace(Trace t) { _trace = std::move(t); }

    /// Runs the full read-only sequence. Never throws; every failure is reported
    /// in the result.
    BotProbeResult run();

private:
    struct CmdOutcome {
        Status        status     = Status::Ok;   ///< transport status
        bool          ok         = false;        ///< transport AND CSW both good
        std::uint8_t  cswStatus  = 0xFF;
        std::uint32_t residue    = 0;
        std::vector<std::uint8_t> data;
        std::string   detail;
    };

    /// One complete BOT command: CBW out, optional data in, CSW in.
    /// `offerLen` is what we offer on the IN transfer, which is deliberately
    /// allowed to exceed `dataLen` so short-read fidelity can be measured.
    CmdOutcome command(std::span<const std::uint8_t> cdb,
                       std::uint32_t dataLen,
                       std::uint32_t offerLen);

    void trace(const std::string& line) const { if (_trace) _trace(line); }
    void note(const char* name, const CmdOutcome& r);

    IUsbDevicePort& _port;
    BotEndpoints    _eps;
    Trace           _trace;
    std::uint32_t   _tag = 0;
    BotProbeResult* _result = nullptr;
};

} // namespace airusb::diag

#endif // AIRUSB_DIAG_BOTPROBE_H
