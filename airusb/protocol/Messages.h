// AirUSB Hub — the L1 message bodies that were not needed until now.
//
// SUBMIT, COMPLETE and HELLO already live in Codec.h because the loopback gate
// needed them. This file adds the rest of the session: listing devices,
// attaching one, and tearing it down again.
//
// Same rules as Codec.h, for the same reasons: explicit byte loads, no struct
// overlay (coalesced messages start at arbitrary alignment), and every declared
// length checked against the bytes actually present before anything is allocated.
//
// One format is specified here rather than in the plan. DEVICE_LIST is listed in
// §3.3 with no body layout, so its record format is defined below and documented
// as ours — better than inventing it silently at three call sites.

#ifndef AIRUSB_PROTOCOL_MESSAGES_H
#define AIRUSB_PROTOCOL_MESSAGES_H

#include "Wire.h"
#include "../core/Status.h"
#include "../core/UsbTypes.h"

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace airusb::protocol {

/// Globally unique per device, per exporter: H(exporter identity ‖ stable device
/// key), so two peers sharing identical sticks never collide (§7.7).
using DeviceUid = std::array<std::uint8_t, 16>;

// ---------------------------------------------------------------------------
// LIST_DEVICES (0x13) — empty body
// DEVICE_LIST  (0x14)
// ---------------------------------------------------------------------------

inline constexpr std::size_t kBodyDeviceList = 8;
inline constexpr std::uint32_t kMaxListedDevices = 64;
inline constexpr std::size_t kDeviceRecordFixed = 24;
inline constexpr std::uint16_t kMaxDeviceNameLen = 128;

enum DeviceFlags : std::uint8_t {
    kDevHasStorage     = 1u << 0,
    kDevMountedLocally = 1u << 1,   ///< would have to be unmounted before sharing
    kDevShareable      = 1u << 2,   ///< false for the boot disk, and for a device
                                    ///< that arrived over AirUSB (no re-export)
    kDevAttached       = 1u << 3,   ///< already leased, to this or another peer
};

struct DeviceRecord {
    DeviceUid     uid{};
    std::uint16_t vendorId  = 0;
    std::uint16_t productId = 0;
    std::uint8_t  speed     = 0;    ///< airusb::Speed
    std::uint8_t  flags     = 0;
    std::string   name;             ///< UTF-8, display only, never trusted
};

void encodeDeviceList(const std::vector<DeviceRecord>& devices,
                      std::vector<std::uint8_t>& out);

/// Returns false on any inconsistency between the declared count, the declared
/// name lengths, and the bytes present.
bool decodeDeviceList(std::span<const std::uint8_t> body,
                      std::vector<DeviceRecord>& out);

// ---------------------------------------------------------------------------
// ATTACH (0x20), B = 24
// ---------------------------------------------------------------------------

inline constexpr std::size_t kBodyAttach = 24;

struct AttachBody {
    DeviceUid     uid{};
    /// MUST be 1 (EXCLUSIVE). A shared attach is not a mode this protocol has —
    /// two importers on one device is the corruption case the whole design
    /// exists to prevent, so the field exists only to be checked.
    std::uint8_t  exclusivity = 1;
    std::uint8_t  attachSlot  = 0;   ///< 1..15, chosen by the importer
    std::uint16_t flags       = 0;
    std::uint32_t importerMaxTransferBytes = 0;
};

void encodeAttach(const AttachBody& b, std::vector<std::uint8_t>& out);
bool decodeAttach(std::span<const std::uint8_t> body, AttachBody& out) noexcept;

// ---------------------------------------------------------------------------
// ATTACH_OK (0x21), B = 40
// ---------------------------------------------------------------------------

inline constexpr std::size_t kBodyAttachOk = 40;

enum ExporterFlags : std::uint8_t {
    kExpSupportsDeviceReset = 1u << 0,   ///< logical reset, never a bus reset
    kExpSupportsSuspendIo   = 1u << 1,
};

struct AttachOkBody {
    std::uint32_t attachId          = 0;   ///< non-zero; not reused for 60 s
    std::uint32_t creditUrbs        = 64;
    std::uint32_t creditBytes       = 4u * 1024 * 1024;
    std::uint16_t speed             = 0;
    std::uint8_t  cancelGranularity = 0;   ///< 0 ENDPOINT-only, 1 PER_REQUEST
    std::uint8_t  exporterFlags     = 0;
    std::uint32_t deviceLatencyUs   = 0;
    std::uint32_t manifestLen       = 0;
    std::uint32_t leaseEpoch        = 0;
    std::uint32_t urbCeilingMs      = 0;
};

void encodeAttachOk(const AttachOkBody& b, std::vector<std::uint8_t>& out);
bool decodeAttachOk(std::span<const std::uint8_t> body, AttachOkBody& out) noexcept;

// ---------------------------------------------------------------------------
// DETACH (0x23), B = 8 / DETACH_OK (0x24), B = 16
// ---------------------------------------------------------------------------

inline constexpr std::size_t kBodyDetach   = 8;
inline constexpr std::size_t kBodyDetachOk = 16;

enum class DetachReason : std::uint8_t {
    UserRequest       = 1,
    ImporterShutdown  = 2,
    ExporterReclaim   = 3,
    Policy            = 4,
    Error             = 5,
    Sleep             = 6,
};

bool isKnownDetachReason(std::uint8_t raw) noexcept;

struct DetachBody {
    DetachReason  reason = DetachReason::UserRequest;
    /// bit0 FORCE — skip the drain. Converted by the importer into a surprise
    /// removal, which loses the unflushed write cache. Never set silently.
    std::uint8_t  dflags = 0;
    std::uint16_t drainTimeoutMs = 0;   ///< 0 means the default, 2000
};

struct DetachOkBody {
    std::uint32_t urbsCompleted = 0;
    std::uint32_t urbsCancelled = 0;
    std::uint32_t bytesDropped  = 0;
};

void encodeDetach(const DetachBody& b, std::vector<std::uint8_t>& out);
bool decodeDetach(std::span<const std::uint8_t> body, DetachBody& out) noexcept;

void encodeDetachOk(const DetachOkBody& b, std::vector<std::uint8_t>& out);
bool decodeDetachOk(std::span<const std::uint8_t> body, DetachOkBody& out) noexcept;

// ---------------------------------------------------------------------------
// PING (0x03) / PONG (0x04), B = 24
// ---------------------------------------------------------------------------

struct PingBody {
    std::uint64_t pingTsNs = 0;
    std::uint64_t echoTsNs = 0;
    /// Populated in debug builds only, for the credit drift cross-check.
    std::uint32_t creditUrbsView  = 0;
    std::uint32_t creditBytesView = 0;
};

void encodePing(const PingBody& b, std::vector<std::uint8_t>& out);
bool decodePing(std::span<const std::uint8_t> body, PingBody& out) noexcept;

// ---------------------------------------------------------------------------
// ERROR (0x06), B = 8
// ---------------------------------------------------------------------------

struct ErrorBody {
    std::uint16_t offendingType = 0;
    std::uint32_t detail        = 0;
};

void encodeError(const ErrorBody& b, std::vector<std::uint8_t>& out);
bool decodeError(std::span<const std::uint8_t> body, ErrorBody& out) noexcept;

/// Builds a complete ERROR record: header, body, and a REJECT_REASON TLV.
///
/// The reason is UTF-8 and is shown to a user, so it is the one string in the
/// protocol that has to read like a sentence rather than an error code.
void buildError(std::uint16_t offendingType, Status status,
                std::string_view reason,
                std::vector<std::uint8_t>& out);

} // namespace airusb::protocol

#endif // AIRUSB_PROTOCOL_MESSAGES_H
