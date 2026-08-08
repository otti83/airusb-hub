// AirUSB Hub — the only clock (P1 plan §6.2)
//
// All lease, detach and keepalive timers use a CONTINUOUS clock that advances
// while the system is asleep. This is a correctness requirement, not hygiene.
//
// A sleep-blind clock is the only way to break
//     T_detach_importer + t_disconnect_max < T_lease_exporter
// because the machine can sleep for hours between two ticks. If the exporter's
// lease timer stops during sleep, it will still believe the lease is fresh on
// wake, hand the drive back to nobody, or -- worse -- keep it captured while the
// importer has already given up and the user has replugged it elsewhere.
//
// Platform mapping:
//   macOS   mach_continuous_time()      (NOT mach_absolute_time)
//   Linux   clock_gettime(CLOCK_BOOTTIME)
//   Windows QueryUnbiasedInterruptTime / GetTickCount64 semantics
//
// A lint rule bans mach_absolute_time outside this file. std::chrono::steady_clock
// is also banned for lease timing: on Apple platforms it is backed by
// mach_absolute_time and therefore stops during sleep.

#ifndef AIRUSB_CORE_CLOCK_H
#define AIRUSB_CORE_CLOCK_H

#include <cstdint>

namespace airusb {

/// Nanoseconds on a monotonic clock that keeps counting across system sleep.
using ContinuousNs = std::uint64_t;

class Clock {
public:
    virtual ~Clock() = default;

    /// Monotonic and continuous across sleep. Never wall-clock, never resettable.
    virtual ContinuousNs nowNs() const noexcept = 0;

    /// The process-wide clock.
    static const Clock& system() noexcept;
};

/// Deterministic clock for tests. Time only moves when a test moves it, which is
/// what makes the lease/detach ordering testable at all -- those deadlines are
/// tens of seconds apart and no test suite can afford to wait them out.
class ManualClock final : public Clock {
public:
    explicit ManualClock(ContinuousNs start = 0) noexcept : _now(start) {}
    ContinuousNs nowNs() const noexcept override { return _now; }

    void advanceNs(ContinuousNs d) noexcept { _now += d; }
    void advanceMs(std::uint64_t ms) noexcept { _now += ms * 1'000'000ull; }

private:
    ContinuousNs _now;
};

/// A deadline expressed on the continuous clock. Deliberately a value type with no
/// clock reference of its own, so a deadline can be created on one strand and
/// checked on another without sharing anything mutable.
class Deadline {
public:
    Deadline() noexcept = default;

    static Deadline never() noexcept { return Deadline{}; }

    static Deadline afterMs(const Clock& c, std::uint64_t ms) noexcept
    {
        // ms == 0 means "no deadline" (see kUrbDeadlineIntr): an interrupt IN may
        // legitimately idle forever, and turning that into an immediate expiry
        // would abort every interrupt transfer the instant it was submitted.
        if (ms == 0) return never();
        Deadline d;
        d._atNs = c.nowNs() + ms * 1'000'000ull;
        d._set  = true;
        return d;
    }

    bool isSet() const noexcept { return _set; }

    bool expired(const Clock& c) const noexcept
    {
        return _set && c.nowNs() >= _atNs;
    }

    /// Remaining time, 0 once expired. Returns 0 for an unset deadline too, so
    /// callers must check isSet() before treating 0 as "fire now".
    std::uint64_t remainingNs(const Clock& c) const noexcept
    {
        if (!_set) return 0;
        const ContinuousNs now = c.nowNs();
        return now >= _atNs ? 0 : _atNs - now;
    }

    ContinuousNs atNs() const noexcept { return _atNs; }

private:
    ContinuousNs _atNs = 0;
    bool         _set  = false;
};

} // namespace airusb

#endif // AIRUSB_CORE_CLOCK_H
