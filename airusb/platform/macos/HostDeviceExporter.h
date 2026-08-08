// AirUSB Hub — the root half of the macOS exporter (P1 plan §7.2, §7.3, §7.6).
//
// Owns everything that needs root and nothing that needs the console session:
//
//   * DiskArbitration claim and unmount, via DiskGuard
//   * IOUSBHostDevice + IOUSBHostObjectInitOptionsDeviceCapture
//   * configureWithValue:matchInterfaces:NO
//   * the manifest — every descriptor read once, verbatim
//   * endpoint 0. Control transfers work fine from a LaunchDaemon; it is only
//     IOUSBHostInterface that the System Policy refuses.
//   * the lease, and releasing it if the agent dies
//
// It implements IUsbDevicePort by routing ep0 to its own captured device object
// and bulk to the agent over the local socket. That split is invisible above this
// line, which is what lets diag/BotProbe — validated in CI against a RAM-disk
// device — run unmodified against real hardware.
//
// THE RELEASE ORDER IS NOT A STYLE CHOICE (§7.6)
//
//   1. the agent aborts and releases every pipe and interface
//   2. plain destroy on the device — resets it and re-registers drivers for
//      matching, which is what makes the local OS remount the stick
//   3. only then DADiskUnclaim
//
// Destroying with DeviceSurrender instead of plain destroy suppresses the reset
// and the re-match, and the drive vanishes from both machines until it is
// physically replugged. Unclaiming before the destroy reopens the automount
// window while the device is still captured.

#ifndef AIRUSB_PLATFORM_MACOS_HOSTDEVICEEXPORTER_H
#define AIRUSB_PLATFORM_MACOS_HOSTDEVICEEXPORTER_H

#import <Foundation/Foundation.h>
#import <IOUSBHost/IOUSBHost.h>

#include "AgentLink.h"
#include "AgentProtocol.h"
#include "DiskGuard.h"
#include "../../core/Clock.h"
#include "../../core/DeviceManifest.h"
#include "../../core/IUsbDevicePort.h"
#include "../../core/Status.h"

#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace airusb::macos {

struct ExporterConfig {
    std::uint16_t vendorId  = 0;
    std::uint16_t productId = 0;
    std::string   socketPath = "/var/run/airusb-exportd.sock";
    /// 0 waits forever. The agent is started independently and may lose the race.
    std::uint32_t agentWaitMs = 30000;
    /// Accept only this uid on the socket. 0xFFFFFFFF means "the console user",
    /// resolved from the owner of /dev/console at accept time.
    std::uint32_t allowedUid = 0xFFFFFFFFu;
};

class HostDeviceExporter final : public IUsbDevicePort {
public:
    HostDeviceExporter() = default;
    ~HostDeviceExporter() override;

    HostDeviceExporter(const HostDeviceExporter&)            = delete;
    HostDeviceExporter& operator=(const HostDeviceExporter&) = delete;

    /// The full attach sequence of §7.2, in order, unwinding completely on any
    /// failure so that the local OS keeps the drive.
    ///
    /// Nothing is announced to anybody until every step has succeeded: the
    /// importer never learns the device exists until it is fully captured and
    /// fully described.
    Status attach(const ExporterConfig& cfg, std::string* whyNot);

    /// Releases in the order documented above. Safe to call twice.
    void release();

    // --- IUsbDevicePort ------------------------------------------------------

    const DeviceManifest& manifest() const noexcept override { return _manifest; }

    /// Endpoint 0, issued by this process against the captured device. Root is
    /// sufficient; the console session is not required for control transfers.
    Status controlTransfer(const SetupPacket& setup,
                           std::span<const std::uint8_t> dataOut,
                           std::vector<std::uint8_t>& dataIn) override;

    /// Forwarded to the agent. One IPC round trip is one logical USB transfer;
    /// the request is never split and two are never coalesced.
    Status bulkOut(std::uint8_t epAddr, std::span<const std::uint8_t> data,
                   std::uint32_t* actualLen) override;
    Status bulkIn(std::uint8_t epAddr, std::uint32_t maxLen,
                  std::vector<std::uint8_t>& out) override;
    Status clearHalt(std::uint8_t epAddr) override;

    // --- state ---------------------------------------------------------------

    bool          attached()   const noexcept { return _device != nil; }
    bool          agentAlive() const noexcept { return _link.valid() && !_agentLost; }
    std::uint8_t  configValue() const noexcept { return _configValue; }
    std::uint32_t locationId()  const noexcept { return _locationId; }
    const ipc::PipeTable& pipeTable() const noexcept { return _pipes; }
    const DiskGuard&      diskGuard() const noexcept { return _disks; }

    /// Rebuilds the agent's pipe table and adopts the new generation (§7.5).
    Status rebuildPipeTable(std::string* whyNot);

    /// Blocks until the agent disconnects or `ms` elapses. Returns true if the
    /// agent is still alive. This is the daemon's idle state: the agent dying is
    /// the event that must release the capture and restore the drive.
    bool waitWhileAgentAlive(std::uint32_t ms);

private:
    Status waitForAgent(const ExporterConfig& cfg, std::string* whyNot);
    Status buildManifest(std::string* whyNot);
    Status fetchDescriptor(std::uint8_t type, std::uint8_t index, std::uint16_t langId,
                           std::size_t hint, std::vector<std::uint8_t>& out);
    void   noteAgentLost(const char* where);

    IOUSBHostDevice* __strong _device = nil;
    io_service_t     _service     = 0;
    std::uint32_t    _locationId  = 0;
    std::uint8_t     _configValue = 0;

    DiskGuard        _disks;
    DeviceManifest   _manifest;

    int              _listenFd = -1;
    std::string      _socketPath;
    ipc::AgentLink   _link;
    ipc::PipeTable   _pipes;
    bool             _agentLost = false;

    ContinuousNs     _leaseStartNs = 0;
};

/// The uid that owns /dev/console — the console user, as the kernel sees it.
/// Used to decide which peer may connect, rather than believing what the peer
/// says about itself.
std::uint32_t consoleUid() noexcept;

} // namespace airusb::macos

#endif // AIRUSB_PLATFORM_MACOS_HOSTDEVICEEXPORTER_H
