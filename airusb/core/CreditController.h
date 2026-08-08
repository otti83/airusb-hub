// AirUSB Hub — two-dimensional flow control (P1 plan §6.3, defect D-30)
//
// Credit is counted in BOTH urbs and bytes, because either alone is exploitable:
// 10,000 8-byte interrupt transfers exhaust memory in urb terms but look free in
// byte terms, and one 16 MiB bulk read is the reverse.
//
// D-30 was "credit accounting can silently drift and deadlock". The fix is
// structural, not vigilance: there is exactly ONE release point, and the
// invariant 0 <= inUse <= granted is asserted on every mutation. A drift of one
// urb is not a rounding error here — it is a permanent stall of that endpoint once
// the window closes and never reopens.

#ifndef AIRUSB_CORE_CREDITCONTROLLER_H
#define AIRUSB_CORE_CREDITCONTROLLER_H

#include "Status.h"

#include <cstdint>

namespace airusb {

struct CreditGrant {
    std::uint32_t urbs  = 64;
    std::uint32_t bytes = 4u * 1024 * 1024;
};

class CreditController {
public:
    CreditController() = default;
    explicit CreditController(CreditGrant grant) noexcept : _grant(grant) {}

    void setGrant(CreditGrant g) noexcept { _grant = g; }
    CreditGrant grant() const noexcept { return _grant; }

    /// Try to reserve one urb of `bytes`. Returns Ok, or NoResources when the
    /// window is closed. The caller must answer NoResources rather than queueing
    /// without bound (R11).
    Status acquire(std::uint32_t bytes) noexcept;

    /// THE single release point. Must be called exactly once per successful
    /// acquire, with the same byte count. Returns false if that would drive the
    /// counters negative, which means an accounting bug rather than a peer problem
    /// — the caller should treat it as fatal in debug builds.
    bool release(std::uint32_t bytes) noexcept;

    std::uint32_t urbsInUse()  const noexcept { return _urbsInUse; }
    std::uint32_t bytesInUse() const noexcept { return _bytesInUse; }

    std::uint32_t urbsAvailable()  const noexcept { return _grant.urbs - _urbsInUse; }
    std::uint32_t bytesAvailable() const noexcept { return _grant.bytes - _bytesInUse; }

    bool wouldFit(std::uint32_t bytes) const noexcept
    {
        return _urbsInUse < _grant.urbs
            && static_cast<std::uint64_t>(_bytesInUse) + bytes <= _grant.bytes;
    }

    /// R11 offence tracking. First overrun is answered with NO_RESOURCES; the
    /// session is torn down if the peer exceeds by more than 2x or offends three
    /// times, because at that point it is not backpressure, it is a peer that does
    /// not implement flow control.
    void recordOverrun(std::uint32_t requestedBytes) noexcept;
    bool overrunIsFatal() const noexcept;
    std::uint32_t overrunCount() const noexcept { return _overruns; }

    /// Debug cross-check carried in PING (D-30). Both sides compare their view;
    /// a mismatch means drift and is logged as a design defect.
    bool matches(std::uint32_t peerUrbs, std::uint32_t peerBytes) const noexcept
    {
        return peerUrbs == _urbsInUse && peerBytes == _bytesInUse;
    }

    /// Only for attach teardown, where every outstanding request has already been
    /// drained and completed by RequestTable::takeAttach.
    void resetForTeardown() noexcept { _urbsInUse = 0; _bytesInUse = 0; _overruns = 0; }

private:
    CreditGrant   _grant;
    std::uint32_t _urbsInUse  = 0;
    std::uint32_t _bytesInUse = 0;
    std::uint32_t _overruns   = 0;
    bool          _grossOverrun = false;
};

} // namespace airusb

#endif // AIRUSB_CORE_CREDITCONTROLLER_H
