// AirUSB Hub — portable status codes (P1 plan §3.11)
//
// AirUsbStatus is the ONLY status that ever appears on the wire. Native codes
// (IOUSBHostCIMessageStatus, USBD_STATUS, Linux errno) exist exclusively inside
// platform backends, behind one canonical mapping table per platform.
//
// This is the structural fix for USB/IP putting raw Linux errno on the wire:
// ECONNRESET is 104 on Linux but 54 on macOS, and EREMOTEIO — which Linux uses as
// its standard short-read status — does not exist in the macOS SDK at all.

#ifndef AIRUSB_CORE_STATUS_H
#define AIRUSB_CORE_STATUS_H

#include <cstdint>

namespace airusb {

enum class Status : std::uint16_t {
    Ok = 0x0000,

    // ---- protocol / session -------------------------------------------------
    ErrorGeneric        = 0x0001,
    BadArgument         = 0x0002,
    UnsupportedVersion  = 0x0003,
    UnsupportedMessage  = 0x0004,
    MalformedFrame      = 0x0005,  // fatal
    LimitExceeded       = 0x0006,  // fatal
    NotPermitted        = 0x0007,
    NotPaired           = 0x0008,
    AuthFailed          = 0x0009,  // fatal
    NoResources         = 0x000A,
    Busy                = 0x000B,
    NotFound            = 0x000C,
    AlreadyExists       = 0x000D,
    Internal            = 0x000E,
    TransportLost       = 0x000F,  // LOCAL ONLY — must never appear on the wire
    AlreadyCompleted    = 0x0010,

    // ---- attach / lifecycle -------------------------------------------------
    DeviceGone          = 0x0020,
    Detaching           = 0x0021,
    ExclusivityDenied   = 0x0022,
    CaptureFailed       = 0x0023,
    AttachUnknown       = 0x0024,
    ManifestInvalid     = 0x0025,
    SpeedUnsupported    = 0x0026,
    MountedLocally      = 0x0027,

    // ---- usb transfer -------------------------------------------------------
    XferStall           = 0x0040,
    XferTimeout         = 0x0041,
    XferCancelled       = 0x0042,
    XferShort           = 0x0043,
    XferOverrun         = 0x0044,
    XferUnderrun        = 0x0045,
    XferCrc             = 0x0046,
    XferBitstuff        = 0x0047,
    XferProtocol        = 0x0048,
    XferNoBandwidth     = 0x0049,
    XferMissedService   = 0x004A,
    XferEpStopped       = 0x004B,
    XferDeviceOffline   = 0x004C,
    XferNakTimeout      = 0x004D,
    XferBadToggle       = 0x004E,
    XferStreamError     = 0x004F,
    XferUnknown         = 0x0050,
};

/// Fatal statuses require sending GOODBYE and closing the session.
constexpr bool isFatal(Status s) noexcept
{
    return s == Status::MalformedFrame
        || s == Status::LimitExceeded
        || s == Status::AuthFailed;
}

/// TransportLost means "we do not know whether this transfer happened", which USB
/// cannot express. It is never delivered to a guest OS as a transfer completion —
/// it is converted into a port disconnect — and it must never be serialized.
constexpr bool isWireLegal(Status s) noexcept
{
    return s != Status::TransportLost;
}

constexpr bool isTransferStatus(Status s) noexcept
{
    return static_cast<std::uint16_t>(s) >= 0x0040
        && static_cast<std::uint16_t>(s) <= 0x0050;
}

/// True for every value this build knows about. Unknown-but-well-formed values are
/// tolerated on receive (they decode to their numeric value); this predicate exists
/// so tests can assert table completeness, not to gate parsing.
bool isKnownStatus(std::uint16_t raw) noexcept;

const char* statusName(Status s) noexcept;

} // namespace airusb

#endif // AIRUSB_CORE_STATUS_H
