// AirUSB Hub — a fake USB mass storage device (P1 plan §8.1, P2.6)
//
// Implements real USB Bulk-Only Transport over a RAM disk: CBW in, data, CSW out,
// with a real SCSI command set (INQUIRY, READ CAPACITY, READ(10), WRITE(10),
// TEST UNIT READY, REQUEST SENSE, MODE SENSE).
//
// It is a genuine BOT implementation rather than a stub because the bugs worth
// catching are BOT phase bugs: a transfer split at the wrong boundary injects a
// spurious short packet and desynchronises the phase machine, and a stub that
// just echoes bytes would happily accept that. This one refuses, exactly as real
// firmware does.
//
// The RAM disk is content-addressable by SHA-like checksum in the tests, so a
// corrupted write is detected as a data difference, not merely as an error code.

#ifndef AIRUSB_TESTS_FAKES_SCRIPTEDDEVICE_H
#define AIRUSB_TESTS_FAKES_SCRIPTEDDEVICE_H

#include "../../core/DeviceManifest.h"
#include "../../core/IUsbDevicePort.h"
#include "../../core/Status.h"
#include "../../core/UsbTypes.h"

#include <cstdint>
#include <span>
#include <vector>

namespace airusb::fakes {

/// USB Mass Storage Bulk-Only Transport constants (USB MSC BOT 1.0).
inline constexpr std::uint32_t kCbwSignature = 0x43425355;   // "USBC"
inline constexpr std::uint32_t kCswSignature = 0x53425355;   // "USBS"
inline constexpr std::size_t   kCbwLength    = 31;
inline constexpr std::size_t   kCswLength    = 13;

enum class BotPhase : std::uint8_t { AwaitingCbw, Data, AwaitingCswRead };

struct ScriptedFault {
    /// Stall the data endpoint on the Nth command, then require a CLEAR_HALT.
    std::uint32_t stallOnCommand = 0;
    /// Fail the Nth command with a CHECK CONDITION status.
    std::uint32_t checkConditionOnCommand = 0;
    /// Report fewer bytes than requested on the Nth READ.
    std::uint32_t shortReadOnCommand = 0;
};

/// The endpoint addresses this device publishes, matching the manifest built in
/// the constructor. Named so the address-taking IUsbDevicePort methods can reject
/// a wrong address loudly instead of silently servicing the only pipe there is.
inline constexpr std::uint8_t kScriptedBulkIn  = 0x81;
inline constexpr std::uint8_t kScriptedBulkOut = 0x02;

class ScriptedDevice final : public IUsbDevicePort {
public:
    ScriptedDevice(std::uint32_t blockCount = 2048, std::uint32_t blockSize = 512);

    /// The manifest this device would publish. Matches the real 058f:6387 shape:
    /// SuperSpeed, one configuration, one BOT interface, bulk IN + bulk OUT.
    const DeviceManifest& manifest() const noexcept override { return _manifest; }

    // --- control endpoint ---------------------------------------------------

    /// Handles a control transfer. Returns the status and fills `out` for IN.
    Status controlTransfer(const SetupPacket& setup,
                           std::span<const std::uint8_t> dataOut,
                           std::vector<std::uint8_t>& dataIn) override;

    // --- bulk endpoints -----------------------------------------------------

    /// Bulk OUT. One call is one logical transfer, exactly as one NormalTransfer
    /// descriptor is one logical URB.
    Status bulkOut(std::span<const std::uint8_t> data, std::uint32_t* actualLen);

    /// Bulk IN. `maxLen` is what the host offered; `out` is what the device sent.
    Status bulkIn(std::uint32_t maxLen, std::vector<std::uint8_t>& out);

    // --- IUsbDevicePort, addressed by endpoint ------------------------------
    //
    // The same two transfers, reached through the address the caller believes it
    // is talking to. A caller that has the direction backwards gets an error
    // rather than a working transfer on the other pipe, which is what makes this
    // fake usable as the reference implementation for diag/BotProbe.

    Status bulkOut(std::uint8_t epAddr, std::span<const std::uint8_t> data,
                   std::uint32_t* actualLen) override;
    Status bulkIn(std::uint8_t epAddr, std::uint32_t maxLen,
                  std::vector<std::uint8_t>& out) override;

    // --- state --------------------------------------------------------------

    BotPhase phase() const noexcept { return _phase; }
    bool inHalted() const noexcept { return _inHalted; }
    bool outHalted() const noexcept { return _outHalted; }
    Status clearHalt(std::uint8_t epAddr) noexcept override;
    void reset() noexcept;             ///< Bulk-Only Mass Storage Reset

    std::uint32_t commandCount() const noexcept { return _commands; }
    void setFaults(ScriptedFault f) noexcept { _faults = f; }

    // --- RAM disk -----------------------------------------------------------

    std::span<const std::uint8_t> media() const noexcept { return _media; }
    std::uint64_t checksum() const noexcept;
    void fillPattern(std::uint64_t seed);

    std::uint32_t blockSize()  const noexcept { return _blockSize; }
    std::uint32_t blockCount() const noexcept { return _blockCount; }

private:
    Status handleCbw(std::span<const std::uint8_t> cbw);
    Status executeScsi();

    DeviceManifest _manifest;
    std::vector<std::uint8_t> _media;
    std::uint32_t _blockSize;
    std::uint32_t _blockCount;

    BotPhase      _phase = BotPhase::AwaitingCbw;
    std::uint32_t _tag = 0;
    std::uint32_t _expectedLen = 0;
    bool          _dataIn = false;
    std::uint8_t  _cdb[16] = {};
    std::uint8_t  _cdbLen = 0;

    std::vector<std::uint8_t> _pendingIn;   ///< data the device owes the host
    std::uint32_t _residue = 0;
    std::uint8_t  _cswStatus = 0;

    bool _inHalted = false;
    bool _outHalted = false;
    std::uint32_t _commands = 0;
    ScriptedFault _faults;

    std::uint8_t _sense[18] = {};
};

} // namespace airusb::fakes

#endif // AIRUSB_TESTS_FAKES_SCRIPTEDDEVICE_H
