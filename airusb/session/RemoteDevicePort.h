// AirUSB Hub — a captured device on the other end of a session.
//
// The importer's data path, expressed as the same IUsbDevicePort the exporter
// implements locally. Everything above it — diag/BotProbe today, the virtual
// host controller later — cannot tell whether the device is in this machine or
// on the far side of a LAN.
//
// That equivalence is the point. It is what lets the same Bulk-Only Transport
// probe that was pointed at a physical drive during the P2.8 hardware gate be
// pointed at a remote one with no changes, so a failure means the network path
// is wrong rather than the instrument.
//
// SYNCHRONOUS, ONE TRANSFER AT A TIME, DELIBERATELY
//
// USB already serialises per endpoint, and a pipelined data plane needs the
// credit controller and the request table to be live on both sides before it is
// safe. Correctness first: this shape is provably ordered, and the depth-4
// pipeline replaces it once there is something to measure it against.

#ifndef AIRUSB_SESSION_REMOTEDEVICEPORT_H
#define AIRUSB_SESSION_REMOTEDEVICEPORT_H

#include "../core/DeviceManifest.h"
#include "../core/IUsbDevicePort.h"
#include "../core/Status.h"
#include "../protocol/Codec.h"
#include "../transport/RecordLayer.h"

#include <cstdint>
#include <span>
#include <vector>

namespace airusb::session {

class RemoteDevicePort final : public IUsbDevicePort {
public:
    RemoteDevicePort(transport::RecordLayer* link,
                     std::uint32_t attachId,
                     std::uint8_t attachSlot,
                     DeviceManifest manifest) noexcept;

    const DeviceManifest& manifest() const noexcept override { return _manifest; }

    Status controlTransfer(const SetupPacket& setup,
                           std::span<const std::uint8_t> dataOut,
                           std::vector<std::uint8_t>& dataIn) override;

    Status bulkOut(std::uint8_t epAddr, std::span<const std::uint8_t> data,
                   std::uint32_t* actualLen) override;
    Status bulkIn(std::uint8_t epAddr, std::uint32_t maxLen,
                  std::vector<std::uint8_t>& out) override;
    Status clearHalt(std::uint8_t epAddr) override;

    std::uint64_t transfersIssued() const noexcept { return _issued; }

    /// The largest DATA payload that still fits in one record, given the
    /// negotiated record size and this cipher's overhead. A transfer bigger than
    /// this is segmented; one smaller is not. Exposed so a test or a tool can
    /// state which of the two it just exercised instead of assuming.
    std::uint32_t maxSegmentBytes() const noexcept;

    /// Transfers that actually spanned more than one record, per direction.
    /// These are the counters that turn "segmentation is implemented" into
    /// "segmentation ran on this machine, in this build, over this socket".
    std::uint64_t segmentedOutTransfers() const noexcept { return _segmentedOut; }
    std::uint64_t segmentedInTransfers()  const noexcept { return _segmentedIn; }
    /// Continuation records received while reassembling IN payloads.
    std::uint64_t inContinuationRecords() const noexcept { return _inContinuations; }

private:
    /// One SUBMIT, then the matching COMPLETE.
    ///
    /// A reply whose request id does not match is treated as fatal rather than
    /// skipped: with one transfer outstanding there is no legitimate way to see
    /// another id, so a mismatch means the stream is misaligned and every later
    /// reply would be attributed to the wrong transfer.
    Status submit(std::uint8_t epAddr, std::uint8_t xferType, std::uint8_t dir,
                  std::uint32_t bufferLen, const std::uint8_t setup[8],
                  std::span<const std::uint8_t> dataOut,
                  std::vector<std::uint8_t>& dataIn,
                  std::uint32_t* actualLen);

    transport::RecordLayer* _link = nullptr;
    DeviceManifest _manifest;
    std::uint32_t  _attachId   = 0;
    std::uint8_t   _attachSlot = 0;
    std::uint64_t  _requestId  = 0;
    std::uint64_t  _issued     = 0;
    std::uint64_t  _segmentedOut    = 0;
    std::uint64_t  _segmentedIn     = 0;
    std::uint64_t  _inContinuations = 0;
};

} // namespace airusb::session

#endif // AIRUSB_SESSION_REMOTEDEVICEPORT_H
