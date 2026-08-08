// AirUSB Hub — the one interface a captured USB device presents to the exporter.
//
// This is deliberately the SAME shape ScriptedDevice already had, promoted to an
// abstract base so that exactly one body of code can be pointed at either
//
//   * tests/fakes/ScriptedDevice   — a RAM-disk BOT device, no hardware, runs in CI
//   * platform/macos/MacDevicePort — a real captured USB device on real hardware
//
// The point is not tidiness. A diagnostic that is only ever run against hardware
// cannot be trusted when it fails, because a failure is equally consistent with a
// broken diagnostic. diag/BotProbe is validated against ScriptedDevice on every
// commit and only then pointed at a real drive, so on hardware a failure means the
// hardware path is broken.
//
// It is NOT IExporterBackend (P1 plan §4.2). That interface is asynchronous,
// ticketed, and carries claim/release lifecycle; this one is the synchronous
// per-transfer surface underneath it. P2.9 grows the async one on top.

#ifndef AIRUSB_CORE_IUSBDEVICEPORT_H
#define AIRUSB_CORE_IUSBDEVICEPORT_H

#include "DeviceManifest.h"
#include "Status.h"
#include "UsbTypes.h"

#include <cstdint>
#include <span>
#include <vector>

namespace airusb {

/// A captured USB device, addressed by endpoint.
///
/// Every method is synchronous and one call is ONE logical USB transfer. That
/// equivalence is load-bearing and is exactly open question OQ-1: a bulk transfer
/// split across two calls injects a short packet the device reads as a phase
/// boundary, and two transfers coalesced into one call destroy a boundary the
/// device requires. Implementations must not split or coalesce.
class IUsbDevicePort {
public:
    virtual ~IUsbDevicePort() = default;

    /// The complete descriptor bundle, valid for the lifetime of the port.
    virtual const DeviceManifest& manifest() const noexcept = 0;

    /// Endpoint 0. `dataOut` is the OUT stage payload (empty for IN transfers);
    /// `dataIn` receives the IN stage payload, truncated to setup.wLength.
    virtual Status controlTransfer(const SetupPacket& setup,
                                   std::span<const std::uint8_t> dataOut,
                                   std::vector<std::uint8_t>& dataIn) = 0;

    /// One logical OUT transfer. `*actualLen` is bytes accepted by the device.
    virtual Status bulkOut(std::uint8_t epAddr,
                           std::span<const std::uint8_t> data,
                           std::uint32_t* actualLen) = 0;

    /// One logical IN transfer. `maxLen` is what the host offered; `out` is sized
    /// to what the device actually sent, which may legitimately be less.
    virtual Status bulkIn(std::uint8_t epAddr,
                          std::uint32_t maxLen,
                          std::vector<std::uint8_t>& out) = 0;

    /// CLEAR_FEATURE(ENDPOINT_HALT) as a VERB, not a raw control forward: it must
    /// also clear the host controller's data toggle for that endpoint. A raw
    /// forward clears the device stall only and leaves every later transfer on
    /// that endpoint silently wrong (P1 plan §4.3).
    virtual Status clearHalt(std::uint8_t epAddr) = 0;
};

} // namespace airusb

#endif // AIRUSB_CORE_IUSBDEVICEPORT_H
