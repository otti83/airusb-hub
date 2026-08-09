// AirUSB Hub — one logical transfer, carried across several records.
//
// WHY THIS HAS TO EXIST
//
// A record cannot exceed 65 519 bytes: that is Noise's plaintext ceiling, not a
// choice. A USB transfer routinely does. `usb-storage` asks for 122 880 bytes in
// a single URB at high speed and, once `slave_configure()` raises max_sectors on
// a SuperSpeed link, **one megabyte**. Raising the record size cannot close that
// gap, because the ceiling is cryptographic.
//
// So a logical transfer is split across records on the way out and put back
// together on the way in. `seg_offset`, `SEG_FIRST` and `SEG_MORE` were specified
// in Wire.h from the beginning and implemented nowhere; this is the
// implementation.
//
// THE RULE THAT MAKES THIS DANGEROUS
//
// Reassembly must COMPLETE before the transfer reaches the device. It is not
// enough to hand the exporter three segments and let it issue three `bulkOut`
// calls: a bulk transfer split anywhere other than a wMaxPacketSize boundary
// injects a short packet, and a short packet is how USB signals the end of a
// data phase. The device would read it as the end of the transfer and the next
// segment as the start of a new command. That is silent corruption, not a
// performance problem, and it is the reason `IUsbDevicePort` documents that one
// call is ONE logical transfer.
//
// So: segmentation lives entirely inside the transport. Nothing above it ever
// sees a partial transfer.
//
// WHAT A HOSTILE PEER GETS
//
// Every counter here is one a peer controls, so every one of them is bounded
// before it is used:
//
//   * `total_len` is capped by R2 against the negotiated maximum, and no buffer
//     is ever sized from it directly — the arena grows with the bytes that
//     actually arrive.
//   * offsets must be exactly contiguous. Not "non-overlapping", not "in range":
//     each segment must begin where the last one ended. A gap would leave
//     uninitialised bytes in a buffer that is about to be written to a disk.
//   * the arena is capped in total, so many small partial transfers cannot do
//     what one large one is not allowed to.

#ifndef AIRUSB_PROTOCOL_SEGMENTATION_H
#define AIRUSB_PROTOCOL_SEGMENTATION_H

#include "Codec.h"
#include "Wire.h"

#include "../core/Status.h"

#include <cstdint>
#include <map>
#include <span>
#include <vector>

namespace airusb::protocol {

/// How a logical transfer is cut up for the wire.
struct SegmentPlan {
    std::uint32_t offset = 0;   ///< seg_offset for this record
    std::uint32_t length = 0;   ///< payload bytes in this record
    bool          first  = false;
    bool          more   = false;
};

/// Splits `totalLen` into records of at most `maxSegmentBytes`.
///
/// A zero-length transfer produces exactly one segment: a transfer that carries
/// no data still has to be sent, and a zero-length bulk OUT is a real thing on
/// the wire (it is how a host terminates a transfer that is an exact multiple of
/// the packet size).
std::vector<SegmentPlan> planSegments(std::uint32_t totalLen,
                                      std::uint32_t maxSegmentBytes);

/// Reassembles segmented payloads, keyed by (channel, request_id).
///
/// One instance belongs to one session. It is not thread-safe; the session owns
/// a single Rx strand, which is what makes the contiguity check meaningful in the
/// first place.
class Reassembler {
public:
    struct Limits {
        /// Per-transfer ceiling. Should be the negotiated max_transfer_bytes.
        std::uint32_t maxTransferBytes = 1u << 20;
        /// Total bytes held across ALL partial transfers. A peer that opens a
        /// thousand transfers and never finishes them is bounded by this, not by
        /// the per-transfer limit.
        std::uint64_t arenaBytes = 8u << 20;
        /// How many transfers may be partially received at once.
        std::uint32_t maxInFlight = 64;
    };

    enum class Outcome {
        NeedMore,   ///< accepted; the transfer is not complete yet
        Complete,   ///< accepted and finished; call `take()`
        Rejected,   ///< the peer broke a rule; `error` says which. Session-fatal.
    };

    Reassembler() = default;
    explicit Reassembler(const Limits& l) noexcept : _limits(l) {}

    /// Feeds one record's payload.
    ///
    /// Returns Complete for an unsegmented message too — a message with neither
    /// SEG_FIRST nor SEG_MORE is a complete transfer of one segment, and the
    /// caller should not have to special-case it.
    Outcome accept(const Header& h, std::span<const std::uint8_t> payload, Status& error);

    /// Moves out the completed payload. Only valid immediately after Complete.
    std::vector<std::uint8_t> take(const Header& h);

    /// Drops any partial transfer for a channel — used when an attach goes away,
    /// so a peer that disconnects mid-transfer does not leave the arena held.
    void forgetChannel(std::uint16_t channel);
    void clear() noexcept;

    std::uint64_t bytesHeld() const noexcept { return _held; }
    std::size_t   inFlight()  const noexcept { return _partial.size(); }

private:
    struct Key {
        std::uint16_t channel;
        std::uint64_t requestId;
        bool operator<(const Key& o) const noexcept
        {
            return channel != o.channel ? channel < o.channel : requestId < o.requestId;
        }
    };

    struct Partial {
        std::uint32_t              totalLen = 0;
        std::vector<std::uint8_t>  bytes;
    };

    Limits                _limits;
    std::map<Key, Partial> _partial;
    std::uint64_t         _held = 0;

    /// The completed payload, parked between Complete and take().
    std::vector<std::uint8_t> _completed;
    bool                      _hasCompleted = false;
    Key                       _completedKey{};
};

} // namespace airusb::protocol

#endif // AIRUSB_PROTOCOL_SEGMENTATION_H
