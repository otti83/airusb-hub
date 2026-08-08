// AirUSB Hub — the console-session half of the exporter (P1 plan §7.4, §7.5).
//
// This is everything the root daemon measurably CANNOT do. A LaunchDaemon (uid 0,
// ppid 1, system session) is refused by the kernel's System Policy when it tries
// to open an IOUSBHostInterface user client:
//
//   (Sandbox) System Policy: <proc>(pid) deny(1) iokit-open-service IOUSBHostInterface
//
// while a LaunchAgent (uid 501, ppid 1, Aqua session) succeeds. Same parent, same
// absence of a tty, strictly less privilege, opposite result. Session membership
// is the entire variable, and no shippable process can be both root and in the
// console session — hence this half.
//
// It owns the interfaces and the pipes and nothing else. It never unmounts, never
// claims, never captures. The daemon remains the single source of exclusivity
// truth.

#ifndef AIRUSB_PLATFORM_MACOS_AGENTUSBIO_H
#define AIRUSB_PLATFORM_MACOS_AGENTUSBIO_H

#import <Foundation/Foundation.h>
#import <IOUSBHost/IOUSBHost.h>

#include "AgentProtocol.h"
#include "../../core/Status.h"
#include "../../core/UsbTypes.h"

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace airusb::macos {

class AgentUsbIo {
public:
    AgentUsbIo() = default;
    ~AgentUsbIo();

    AgentUsbIo(const AgentUsbIo&)            = delete;
    AgentUsbIo& operator=(const AgentUsbIo&) = delete;

    /// Opens every IOUSBHostInterface child of the device at `locationId` and
    /// builds the pipe table. `configValue` is checked against what the device
    /// actually reports, so a daemon and an agent that disagree about the active
    /// configuration fail here rather than moving data on the wrong pipes.
    Status openInterfaces(std::uint32_t locationId,
                          std::uint8_t configValue,
                          ipc::PipeTable& out,
                          std::string* why);

    /// P1 plan §7.5. IOUSBHostInterface and IOUSBHostPipe objects are invalidated
    /// by a configuration change, an alternate-setting change, and by a logical
    /// reset's re-configure. After any of those the table MUST be rebuilt, or the
    /// device enumerates cleanly and then answers nothing — a harder failure to
    /// diagnose than one that never enumerates at all.
    Status rebuildPipeTable(ipc::PipeTable& out, std::string* why);

    /// One logical transfer. `generation` is checked first: a submit carrying a
    /// stale generation is failed with XferEpStopped rather than issued on a pipe
    /// that may now belong to a different alternate setting.
    Status bulkOut(std::uint32_t generation, std::uint8_t epAddr,
                   std::span<const std::uint8_t> data, std::uint32_t timeoutMs,
                   std::uint32_t* actualLen);

    Status bulkIn(std::uint32_t generation, std::uint8_t epAddr,
                  std::uint32_t maxLen, std::uint32_t timeoutMs,
                  std::vector<std::uint8_t>& out);

    /// -clearStallWithError:, which clears the device's stall AND the exporter
    /// host controller's data toggle. A raw CLEAR_FEATURE forward would clear only
    /// the former and leave every later transfer on the endpoint silently wrong.
    Status clearHalt(std::uint32_t generation, std::uint8_t epAddr);

    /// Synchronous abort, so the caller knows the pipe is quiet on return.
    Status abortEndpoint(std::uint32_t generation, std::uint8_t epAddr);

    /// Aborts and releases every pipe and interface. Idempotent.
    void closeAll();

    std::uint32_t generation() const noexcept { return _generation; }
    bool          isOpen()     const noexcept { return _interfaces.count > 0; }

private:
    struct PipeRow {
        std::uint8_t     address = 0;
        XferType         type    = XferType::Bulk;
        IOUSBHostPipe* __strong pipe = nil;
    };

    Status buildTable(ipc::PipeTable& out, std::string* why);
    PipeRow* find(std::uint8_t epAddr);
    Status   checkGeneration(std::uint32_t generation) const;

    NSMutableArray<IOUSBHostInterface*>* __strong _interfaces = nil;
    std::vector<PipeRow>  _pipes;
    std::uint32_t         _locationId  = 0;
    std::uint8_t          _configValue = 0;
    std::uint32_t         _generation  = 0;
};

} // namespace airusb::macos

#endif // AIRUSB_PLATFORM_MACOS_AGENTUSBIO_H
