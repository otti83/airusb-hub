// AirUSB Hub — IOKit odds and ends shared by the exporter daemon and the agent.
//
// Everything here is either a lookup in the IORegistry or a wrapper that makes an
// Apple API safe to call. In particular:
//
//   * Every IOUSBHostObject initialiser goes through safeInit*, because
//     -[IOUSBHostObject openWithOptions:error:] can RAISE NSInvalidArgumentException
//     instead of returning an NSError when IOServiceOpen fails. Disassembly in
//     P1_CAPTURE_VERIFICATION.md §"Second, separate Apple bug": the framework
//     builds its NSError userInfo from three -[NSBundle localizedStringForKey:]
//     results and raises when the first is nil, which happens when
//     +[NSBundle mainBundle] is itself nil. A root daemon that dies from an
//     uncaught exception takes the captured device with it and leaves the user's
//     drive unmounted.
//
//   * Where the real IOReturn matters, IOServiceOpen is called directly, because
//     the framework destroys the NSError on exactly that path.
//
//   * Speed is read from USBSpeed and cross-checked against UsbLinkSpeed. The
//     IORegistry exposes two speed properties with DIFFERENT enumerations in which
//     the same integer 3 means High in one and Super in the other.

#ifndef AIRUSB_PLATFORM_MACOS_MACUSBCOMMON_H
#define AIRUSB_PLATFORM_MACOS_MACUSBCOMMON_H

#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#import <IOUSBHost/IOUSBHost.h>

#include "../../core/Status.h"
#include "../../core/UsbTypes.h"

#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace airusb::macos {

// --- structured logging ------------------------------------------------------
//
// One tag vocabulary shared by both halves so a daemon log and an agent log can
// be read interleaved. Tags match the P1 plan's logging schema (§10).

void logLine(const char* tag, NSString* fmt, ...) NS_FORMAT_FUNCTION(2, 3);
void setLogPrefix(const char* prefix);      ///< "exportd" or "agent"

/// Renders an NSError as domain + decimal + hex, because the hex is what matches
/// the IOReturn tables and the decimal is what Apple's own logs print.
std::string describeError(NSError* e);

// --- IORegistry --------------------------------------------------------------

NSNumber* propNum(io_service_t s, CFStringRef key);
NSString* propStr(io_service_t s, CFStringRef key);

/// Every BSD device name (disk4, disk4s1, ...) beneath a USB device.
void collectBsdNames(io_service_t node, std::set<std::string>& out);

/// Caller owns the returned io_service_t and must IOObjectRelease it.
io_service_t findDeviceByVidPid(std::uint16_t vid, std::uint16_t pid);
io_service_t findDeviceByLocationId(std::uint32_t locationId);

/// The IORegistry "locationID": stable for as long as the device stays in the
/// same port, and unique across ports. This is what the daemon hands the agent so
/// both halves are certain they are talking about the same physical device —
/// VID:PID is not unique when two identical sticks are plugged in.
std::uint32_t locationIdOf(io_service_t device);

/// Reads USBSpeed and cross-checks UsbLinkSpeed. Returns Speed::None if the
/// device reports neither, and logs loudly if the two disagree rather than
/// silently preferring one.
Speed readSpeed(io_service_t device);

/// Human-readable, including the link rate, for log lines and evidence.
std::string describeSpeed(io_service_t device);

// --- safe object construction ------------------------------------------------

/// Wraps -[IOUSBHostDevice initWithIOService:options:queue:error:interestHandler:]
/// in @try/@catch. On failure `ioReturn` carries the real IOReturn obtained from
/// a direct IOServiceOpen probe where one was available, not the framework's
/// NSError, which is unreliable on this path.
IOUSBHostDevice* safeInitDevice(io_service_t service,
                                IOUSBHostObjectInitOptions options,
                                std::uint32_t* ioReturn,
                                std::string* why);

IOUSBHostInterface* safeInitInterface(io_service_t service,
                                      IOUSBHostObjectInitOptions options,
                                      std::uint32_t* ioReturn,
                                      std::string* why);

/// Destroys an IOUSBHostObject without letting an exception escape.
///
/// Release order matters and is not a style choice (P1 plan §7.6): plain destroy
/// resets the device and re-registers its drivers for matching, which is exactly
/// what makes the local OS remount the stick. DestroyOptionsDeviceSurrender does
/// the opposite and is correct ONLY when honouring
/// kUSBHostMessageDeviceIsRequestingClose. Using Surrender on the normal path
/// makes the drive vanish from both machines until it is physically replugged.
void safeDestroy(IOUSBHostObject* obj, bool surrender);

/// A direct IOServiceOpen, closed again immediately. Used to learn the real
/// IOReturn for a service we are about to open through the framework, and to
/// answer "may this process open interfaces at all" without side effects.
std::uint32_t probeServiceOpen(io_service_t service);

/// True if this process is in a security session that may open IOUSBHostInterface
/// user clients. This is the gate that forced the two-process design; the agent
/// checks it at startup so a misconfigured install fails with a clear message
/// instead of an unexplained transfer error later.
bool canOpenInterfaces(io_service_t device, std::uint32_t* lastIoReturn);

} // namespace airusb::macos

#endif // AIRUSB_PLATFORM_MACOS_MACUSBCOMMON_H
