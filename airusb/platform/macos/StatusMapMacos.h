// AirUSB Hub — the one macOS IOReturn -> AirUsbStatus table (P1 plan §3.11).
//
// Native codes exist only inside a platform backend. Nothing derived from IOKit
// reaches the wire, because a raw OS error code on the wire is how USB/IP ended
// up putting Linux errno numbers in front of macOS and Windows peers that read
// them as entirely different errors.
//
// This file is PURE C++ on purpose. The IOReturn values are a stable ABI — they
// have to be, since they cross the kernel boundary — so the table can be written,
// unit-tested and reviewed without IOKit, on any host. The risk of transcribing
// a constant wrongly is removed the other way round: MacUsbCommon.mm contains a
// static_assert per entry comparing these literals against the real headers, so
// a typo or an SDK change is a compile error on macOS rather than a mistranslated
// error code in the field.

#ifndef AIRUSB_PLATFORM_MACOS_STATUSMAPMACOS_H
#define AIRUSB_PLATFORM_MACOS_STATUSMAPMACOS_H

#include "../../core/Status.h"

#include <cstdint>

namespace airusb::macos {

// --- IOReturn values, transcribed from IOKit/IOReturn.h and
//     IOKit/usb/IOUSBHostFamilyDefinitions.h. Cross-checked at compile time.

inline constexpr std::uint32_t kIORetSuccess         = 0x00000000u;
inline constexpr std::uint32_t kIORetError           = 0xE00002BCu;
inline constexpr std::uint32_t kIORetNoMemory        = 0xE00002BDu;
inline constexpr std::uint32_t kIORetNoResources     = 0xE00002BEu;
inline constexpr std::uint32_t kIORetNoDevice        = 0xE00002C0u;
inline constexpr std::uint32_t kIORetNotPrivileged   = 0xE00002C1u;
inline constexpr std::uint32_t kIORetBadArgument     = 0xE00002C2u;
inline constexpr std::uint32_t kIORetExclusiveAccess = 0xE00002C5u;
inline constexpr std::uint32_t kIORetBadMessageID    = 0xE00002C6u;
inline constexpr std::uint32_t kIORetUnsupported     = 0xE00002C7u;
inline constexpr std::uint32_t kIORetInternalError   = 0xE00002C9u;
inline constexpr std::uint32_t kIORetIOError         = 0xE00002CAu;
inline constexpr std::uint32_t kIORetNotOpen         = 0xE00002CDu;
inline constexpr std::uint32_t kIORetBusy            = 0xE00002D5u;
inline constexpr std::uint32_t kIORetTimeout         = 0xE00002D6u;
inline constexpr std::uint32_t kIORetOffline         = 0xE00002D7u;
inline constexpr std::uint32_t kIORetNotReady        = 0xE00002D8u;
inline constexpr std::uint32_t kIORetNotAttached     = 0xE00002D9u;
inline constexpr std::uint32_t kIORetNoSpace         = 0xE00002DBu;
inline constexpr std::uint32_t kIORetUnderrun        = 0xE00002E7u;
inline constexpr std::uint32_t kIORetOverrun         = 0xE00002E8u;
inline constexpr std::uint32_t kIORetDeviceError     = 0xE00002E9u;
inline constexpr std::uint32_t kIORetAborted         = 0xE00002EBu;
inline constexpr std::uint32_t kIORetNotResponding   = 0xE00002EDu;
inline constexpr std::uint32_t kIORetNotPermitted    = 0xE00002E2u;
inline constexpr std::uint32_t kIORetNotFound        = 0xE00002F0u;

/// USB-family codes. The one that matters is PipeStalled: it is the single most
/// common non-success result on a working system and the ONLY one that must be
/// answered with a CLEAR_HALT verb rather than a retry.
inline constexpr std::uint32_t kUsbRetPipeStalled = 0xE0005000u;
inline constexpr std::uint32_t kUsbRetNoPower     = 0xE0005001u;
inline constexpr std::uint32_t kUsbRetRedundant   = 0xE0005002u;

/// Also the FB16524420 signature, recorded here because it is the code that cost
/// this project the most time to diagnose. It is a plain kIOReturnInternalError.
inline constexpr std::uint32_t kFb16524420Signature = kIORetInternalError;

/// The single translation point. `isTransfer` selects between the two contexts a
/// given IOReturn can arrive in: kIOReturnTimeout during a bulk transfer is
/// XferTimeout, but the same code while opening a device is not a transfer status
/// at all. One table, one function, one place to audit.
Status fromIOReturn(std::uint32_t ioReturn, bool isTransfer) noexcept;

/// Human-readable name for logs and for the NATIVE_STATUS TLV. Returns "?" for a
/// code this build has never seen, which is information rather than an error:
/// the raw hex is always logged alongside it.
const char* ioReturnName(std::uint32_t ioReturn) noexcept;

} // namespace airusb::macos

#endif // AIRUSB_PLATFORM_MACOS_STATUSMAPMACOS_H
