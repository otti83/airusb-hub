// AirUSB Hub — the two translations Windows needs, and the trap in each.
//
// The Linux port has a file exactly like this one, and it exists because a cast
// between two small integer enumerations of USB speeds silently produced the
// wrong speed. Windows has the same shape of hazard with different numbers, so
// it gets the same treatment: written-out tables, and a test that asserts the
// DISAGREEMENTS rather than the agreements.
//
// SPEEDS — worse here than on Linux
//
//     airusb::Speed          None=0 Full=1 Low=2  High=3  Super=4 SuperPlus=5
//     UDECX_USB_DEVICE_SPEED Low=0  Full=1 High=2 Super=3
//
// A cast sends **High as SuperSpeed** and **Super clean out of range**, and the
// one value that survives is Full. On Linux the coincidence was High — the value
// anyone tests with first. Here it is Full, so the two ports fail on opposite
// halves of the range and neither one's testing would have caught the other's.
//
// UdeCx has no SuperSpeedPlus at all. A Gen2 device cannot be described to it,
// and saying "Super" instead would be a lie about the link, so it is refused and
// the caller decides. Correctness outranks Compatibility.
//
// STATUSES — and the one that differs from Linux in kind, not in number
//
// On Linux a short transfer is unconditionally success: status 0 with the true
// actual_length, because reporting an error for a short read breaks every
// protocol that ends a transfer by sending less than was asked for.
//
// **Windows does not work that way, and copying the Linux rule here would be a
// bug in the other direction.** USBD makes the caller say whether a short
// transfer is acceptable, per URB, via `USBD_SHORT_TRANSFER_OK` in
// `TransferFlags`. Honour it:
//
//   * flag set   -> USBD_STATUS_SUCCESS with the short length. This is what
//                   usb-storage-equivalent callers set, and what makes a 512-byte
//                   answer to a 1024-byte request correct rather than an error.
//   * flag clear -> USBD_STATUS_ERROR_SHORT_TRANSFER. The caller said it wanted
//                   exactly what it asked for; quietly succeeding would hide a
//                   truncation it explicitly asked to be told about.
//
// Hardcoding the Linux answer would break the second case; hardcoding an error
// would break the first. Neither is visible without a Windows kernel, which is
// precisely why the decision is made here, in a file that compiles and is tested
// on all three platforms.
//
// WHY THE CONSTANTS ARE SPELLED OUT
//
// Same reason as `UsbipCodec` and `LinuxUsb`: this file must build on macOS and
// Linux so the tests can run there, and the WDK headers do not exist on either.
// The values below are transcribed from Microsoft's `usb.h` / `udecxusbdevice.h`.
// Transcription can be wrong, so when the WDK IS present the real macros are
// compared against these with static_assert — see `AIRUSB_WITH_WDK` in the .cpp.
// A number that only ever exists in our own header is a number nobody has
// checked.

#ifndef AIRUSB_PLATFORM_WINDOWS_WINDOWSUSB_H
#define AIRUSB_PLATFORM_WINDOWS_WINDOWSUSB_H

#include "../../core/Status.h"
#include "../../core/UsbTypes.h"

#include <cstdint>

namespace airusb::windows {

/// UDECX_USB_DEVICE_SPEED. Never include <udecxusbdevice.h> from portable code.
enum class UdecxSpeed : std::int32_t {
    Low   = 0,
    Full  = 1,
    High  = 2,
    Super = 3,
    /// Not a UdeCx value. Returned for speeds UdeCx cannot express, so the
    /// caller has to handle the case rather than receive a plausible wrong one.
    Unsupported = -1,
};

/// USBD_STATUS, the subset a forwarding driver can produce.
///
/// The top two bits are `USBD_STATUS_TYPE`, and they do NOT mean what the usual
/// severity reflex expects:
///
///     0x0.......  success
///     0x4.......  pending
///     0x8.......  ERROR  — the transfer failed
///     0xC.......  ERROR AND THE ENDPOINT IS HALTED — it needs a reset before
///                 any further transfer on it will be accepted
///
/// `USBD_ERROR()` in Microsoft's header is just "the value is negative", so
/// 0x8 and 0xC are both failures. The distinction between them is not severity,
/// it is whether the endpoint's state machine has stopped — which is the part a
/// forwarding driver has to act on.
enum class UsbdStatus : std::uint32_t {
    Success              = 0x00000000u,
    Pending              = 0x40000000u,

    Crc                  = 0xC0000001u,
    BtStuff              = 0xC0000002u,
    DataToggleMismatch   = 0xC0000003u,
    StallPid             = 0xC0000004u,
    DevNotResponding     = 0xC0000005u,
    PidCheckFailure      = 0xC0000006u,
    UnexpectedPid        = 0xC0000007u,
    DataOverrun          = 0xC0000008u,
    DataUnderrun         = 0xC0000009u,
    BufferOverrun        = 0xC000000Cu,
    BufferUnderrun       = 0xC000000Du,
    NotAccessed          = 0xC000000Fu,
    Fifo                 = 0xC0000010u,
    EndpointHalted       = 0xC0000030u,

    NoMemory             = 0x80000100u,
    InvalidUrbFunction   = 0x80000200u,
    InvalidParameter     = 0x80000300u,
    ErrorBusy            = 0x80000400u,
    RequestFailed        = 0x80000500u,
    InvalidPipeHandle    = 0x80000600u,
    NoBandwidth          = 0x80000700u,
    InternalHcError      = 0x80000800u,
    /// An error (0x8…) but NOT a halt (0xC…): the transfer moved fewer bytes
    /// than were offered and the caller did not set USBD_SHORT_TRANSFER_OK.
    /// The endpoint is still usable and must not be reset over it.
    ErrorShortTransfer   = 0x80000900u,

    Canceled             = 0xC0010000u,
    Timeout              = 0xC0006000u,
    DeviceGone           = 0xC0007000u,
};

/// USBD_SHORT_TRANSFER_OK, from the URB's TransferFlags.
inline constexpr std::uint32_t kUsbdShortTransferOk = 0x00000002u;
/// USBD_TRANSFER_DIRECTION_IN, bit 0 of the same field.
inline constexpr std::uint32_t kUsbdTransferDirectionIn = 0x00000001u;

/// USBD_ERROR: the value is negative as a signed 32-bit. Both 0x8… and 0xC…
/// qualify, which is why this is a top-BIT test and not a top-two-bits one.
constexpr bool isError(UsbdStatus s) noexcept
{
    return (static_cast<std::uint32_t>(s) & 0x80000000u) != 0;
}

/// USBD_STATUS_TYPE == USBD_STATUS_HALTED. The endpoint's state machine has
/// stopped and needs a reset before it will carry anything again.
///
/// This is the distinction that matters to a forwarding driver, and it is the
/// one a "severity" reading of the top bits gets backwards: a short transfer is
/// an error but leaves the endpoint running, while a stall is an error that
/// does not. Resetting an endpoint over a short read would turn every protocol
/// that ends a transfer early into a reset storm.
constexpr bool haltsEndpoint(UsbdStatus s) noexcept
{
    return (static_cast<std::uint32_t>(s) & 0xC0000000u) == 0xC0000000u;
}

/// The speed UdeCx should be told, or Unsupported if it cannot be told.
UdecxSpeed toUdecxSpeed(Speed s) noexcept;

/// The reverse, for reading back what UdeCx reports. Unknown values become None
/// rather than being cast, because a speed we do not recognise is not a speed.
Speed fromUdecxSpeed(UdecxSpeed s) noexcept;

/// The USBD_STATUS to complete an URB with.
///
/// `offered` and `moved` decide the short-transfer question together with
/// `transferFlags`; see the file header. `moved` is ignored for a failure.
UsbdStatus toUsbdStatus(Status s, std::uint32_t offered, std::uint32_t moved,
                        std::uint32_t transferFlags) noexcept;

/// What an URB completion coming back from the kernel means to us.
Status fromUsbdStatus(UsbdStatus s) noexcept;

const char* udecxSpeedName(UdecxSpeed s) noexcept;
const char* usbdStatusName(UsbdStatus s) noexcept;

} // namespace airusb::windows

#endif // AIRUSB_PLATFORM_WINDOWS_WINDOWSUSB_H
