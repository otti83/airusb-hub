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
#include <functional>
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

/// Emits one logical transfer as one or more records, invoking `send` once per
/// record with the fully framed bytes (header + body). This is the sender half of
/// segmentation, shared by the importer's `RemoteDevicePort` and the exporter's
/// `ExporterSession` so the two never disagree about the framing.
///
/// Record 0 keeps `base.type` (SUBMIT or COMPLETE) and `base.status`, sets
/// SEG_FIRST, and carries `fixedBody` (the encoded SubmitBody/CompleteBody)
/// followed by the first slice of `data`. Every later record is a `Type::Data`
/// continuation with status 0 and no fixed body — pure payload. On every record
/// `total_len` is `data.size()` and `seg_offset` advances exactly by the bytes
/// already sent, which is what the `Reassembler` on the far end verifies for
/// gap-free, overlap-free contiguity.
///
/// `maxSegmentBytes` is the most DATA bytes any single record may carry. The
/// caller derives it from the transport's plaintext ceiling MINUS the 32-byte
/// header MINUS `fixedBody.size()`, so record 0 — the largest, because it also
/// carries the fixed body — still fits. Passing that same value for the (smaller)
/// continuation records simply wastes `fixedBody.size()` bytes per record, which
/// is negligible and keeps every seg_offset a clean multiple.
///
/// A zero-length transfer still emits exactly one record: a zero-length transfer
/// is a real wire event (how a host terminates one that is an exact multiple of
/// the packet size), and swallowing it would lose it.
///
/// This is deliberately NOT "issue each record as its own USB transfer". A bulk
/// transfer split anywhere but a wMaxPacketSize boundary injects a short packet
/// the device reads as the end of the data phase; reassembly MUST complete before
/// the transfer reaches a device. This helper only frames the wire; the far end
/// pairs it with `Reassembler`.
Status emitTransfer(const Header& base,
                    std::span<const std::uint8_t> fixedBody,
                    std::span<const std::uint8_t> data,
                    std::uint32_t maxSegmentBytes,
                    const std::function<Status(std::span<const std::uint8_t>)>& send);

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

    /// Drops the one partial transfer keyed by (channel, request_id) — used when a
    /// single transfer is cancelled or times out mid-reply, so a pipelined
    /// receiver releases just that reassembly and not its siblings on the same
    /// endpoint. A no-op if nothing is partial for that key.
    void forget(std::uint16_t channel, std::uint64_t requestId);

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
