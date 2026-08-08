// AirUSB Hub — the two translations Linux needs, and the trap in the first one.
//
// SPEEDS
//
// `airusb::Speed` and Linux's `enum usb_device_speed` are both small integer
// enumerations of USB speeds, and they DISAGREE on every value except one:
//
//     airusb::Speed   None=0 Full=1 Low=2  High=3 Super=4    SuperPlus=5
//     usb_device_speed UNKNOWN=0 LOW=1 FULL=2 HIGH=3 WIRELESS=4 SUPER=5 SUPER_PLUS=6
//
// A cast sends Full as LOW, Low as FULL, and — worst — **Super as WIRELESS**.
// The kernel's `valid_args()` ACCEPTS speed 4, so nothing complains; but 4 is not
// USB_SPEED_SUPER, so the device lands on the high-speed half of vhci's port
// range while we asked for a SuperSpeed port, and the kernel then disagrees with
// itself about where the device is.
//
// **The one value that coincides is High, which is the value anyone would test
// with first.** That is the entire reason this file exists rather than a cast at
// the call site. `DeviceManifest::validate()` cannot catch it either: it has
// never heard of a Linux speed.
//
// STATUSES
//
// The second translation is AirUSB's transfer status to the negative errno
// RET_SUBMIT carries. Two entries are not obvious and both matter:
//
//   * a SHORT transfer is **success**, status 0, with the true actual_length.
//     Reporting an error for a short read breaks every protocol that ends a
//     transfer by sending less than was asked for — which is most of them.
//   * the errno values are hardcoded, because this file compiles on macOS for
//     the hosted tests and the host's <errno.h> is a different set of numbers.
//     macOS ETIMEDOUT is 60, Linux's is 110, and macOS has no EREMOTEIO at all.

#ifndef AIRUSB_PLATFORM_LINUX_LINUXUSB_H
#define AIRUSB_PLATFORM_LINUX_LINUXUSB_H

#include "../../core/Status.h"
#include "../../core/UsbTypes.h"

#include <cstdint>

namespace airusb::linuxvhci {

/// Linux's enum usb_device_speed, spelled out. Never include <linux/usb.h>.
enum class KernelSpeed : int {
    Unknown   = 0,
    Low       = 1,
    Full      = 2,
    High      = 3,
    Wireless  = 4,
    Super     = 5,
    SuperPlus = 6,
};

/// Errno values as Linux defines them, spelled out for the same reason.
inline constexpr std::int32_t kEPipe      = 32;
inline constexpr std::int32_t kEProto     = 71;
inline constexpr std::int32_t kEOverflow  = 75;
inline constexpr std::int32_t kEIlSeq     = 84;
inline constexpr std::int32_t kENoDev     = 19;
inline constexpr std::int32_t kEInval     = 22;
inline constexpr std::int32_t kENoMem     = 12;
inline constexpr std::int32_t kEConnReset = 104;
inline constexpr std::int32_t kEShutdown  = 108;
inline constexpr std::int32_t kETimedOut  = 110;
inline constexpr std::int32_t kERemoteIo  = 121;
inline constexpr std::int32_t kENoSpc     = 28;
inline constexpr std::int32_t kEXDev      = 18;

/// The speed to write into vhci-hcd's `attach` line.
///
/// Returns Unknown for speeds Linux cannot express, which the caller must refuse
/// rather than approximate: attaching at the wrong speed produces a device whose
/// wMaxPacketSize the host controller then disbelieves.
KernelSpeed toKernelSpeed(Speed s) noexcept;

/// Whether this speed belongs on vhci's USB3 half of the port range.
bool isSuperSpeedHalf(KernelSpeed s) noexcept;

/// The RET_SUBMIT status for a completed transfer. 0 means success.
///
/// `shortIsOk` exists because one caller must override the default: a transfer
/// the host marked URB_SHORT_NOT_OK is one where a short result IS an error, and
/// Linux spells that -EREMOTEIO.
std::int32_t toLinuxErrno(Status s, bool shortIsError = false) noexcept;

/// The name of an errno, for logs. Returns "0" for success and "?" for anything
/// not in the table — never a made-up name.
const char* linuxErrnoName(std::int32_t e) noexcept;

} // namespace airusb::linuxvhci

#endif // AIRUSB_PLATFORM_LINUX_LINUXUSB_H
