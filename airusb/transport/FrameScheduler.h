// AirUSB Hub — egress scheduling (P1 plan §3.4)
//
// One TCP connection carries every endpoint of every attached device. Without a
// scheduler, a 1 MiB bulk IN sits in front of an 8-byte HID interrupt completion
// and adds ~8.4 ms of latency to it on 1 GbE. Mandatory 16 KiB segmentation plus
// deficit round robin across priority classes cuts that worst case to ~131 us.
//
// This removes SELF-INFLICTED head-of-line blocking. Kernel-level TCP HOL from a
// lost segment survives until QUIC; that is stated honestly rather than hidden.
//
// Pure data structure: no sockets, no time, no allocation on the hot path beyond
// the queues themselves. That is what makes the ordering properties testable.

#ifndef AIRUSB_TRANSPORT_FRAMESCHEDULER_H
#define AIRUSB_TRANSPORT_FRAMESCHEDULER_H

#include "../core/UsbTypes.h"

#include <cstdint>
#include <deque>
#include <vector>

namespace airusb::transport {

/// Strict-priority class 0, then DRR between the rest.
enum class Priority : std::uint8_t {
    Control = 0,   ///< session control, PING/PONG, CANCEL. Strict priority.
    Rt      = 1,   ///< isochronous
    High    = 2,   ///< control + interrupt endpoints
    Bulk    = 3,
};

constexpr std::size_t kPriorityCount = 4;

/// Priority for a data-plane frame, derived from the transfer type. Deliberately a
/// pure function of xfer_type so both peers agree without negotiating anything.
constexpr Priority priorityFor(XferType t) noexcept
{
    switch (t) {
        case XferType::Isochronous: return Priority::Rt;
        case XferType::Control:
        case XferType::Interrupt:   return Priority::High;
        case XferType::Bulk:        return Priority::Bulk;
    }
    return Priority::Bulk;
}

struct Frame {
    std::vector<std::uint8_t> bytes;
    Priority                  priority = Priority::Bulk;
    std::uint16_t             channel  = 0;
    bool                      expedite = false;
};

/// Deficit round robin. Quantum is the segment size, so one dequeue turn moves at
/// most one segment's worth of a class before yielding.
class FrameScheduler {
public:
    explicit FrameScheduler(std::uint32_t quantumBytes = 16384) noexcept
        : _quantum(quantumBytes) {}

    /// EXPEDITE jumps to the head of its own class queue, never across classes.
    /// Letting it cross classes would let a flood of expedited bulk frames starve
    /// control traffic, which is the thing strict priority exists to prevent.
    void enqueue(Frame f);

    /// Next frame to write, or false when everything is empty.
    bool dequeue(Frame& out);

    bool empty() const noexcept;
    std::size_t queuedFrames() const noexcept;
    std::size_t queuedBytes() const noexcept { return _totalBytes; }

    /// Frames queued for one channel, so an endpoint teardown can drop them
    /// without walking the whole scheduler.
    std::size_t dropChannel(std::uint16_t channel);

private:
    std::uint32_t _quantum;
    std::deque<Frame> _q[kPriorityCount];
    std::int64_t      _deficit[kPriorityCount] = {0, 0, 0, 0};
    std::size_t       _rrCursor   = static_cast<std::size_t>(Priority::Rt);
    std::size_t       _totalBytes = 0;
};

} // namespace airusb::transport

#endif // AIRUSB_TRANSPORT_FRAMESCHEDULER_H
