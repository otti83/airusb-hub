#include "Watchdog.h"
#include "Clock.h"

#if defined(__APPLE__)
#  include <mach/mach_time.h>
#elif defined(__linux__)
#  include <ctime>
#endif

namespace airusb::watchdog {

bool assertConsistent() noexcept
{
    // Every one of these is also a static_assert in the header. This exists so a
    // build that somehow relaxes one is caught at daemon launch rather than in the
    // field, where the symptom would be a corrupted filesystem rather than a
    // failed check.
    return kCmdDeferredMax * 4 < kCmdKernelFatal
        && kUrbCeilingBulk < kUrbWatchdogImporter
        && kKeepaliveMiss < kDetachImporter
        && kDetachImporter + kDisconnectMax + 1000 < kLeaseExporter
        && kNetCtrl < kUrbCeilingBulk
        && kKeepaliveInterval * 3 <= kKeepaliveMiss;
}

} // namespace airusb::watchdog

namespace airusb {

namespace {

/// The continuous clock. See Clock.h: this MUST keep counting across system sleep,
/// or the lease/detach ordering breaks the moment the lid closes.
class SystemClock final : public Clock {
public:
    ContinuousNs nowNs() const noexcept override
    {
#if defined(__APPLE__)
        // mach_continuous_time, NOT mach_absolute_time. The latter stops during
        // sleep, which would let a lease look fresh after hours of downtime.
        static const mach_timebase_info_data_t tb = [] {
            mach_timebase_info_data_t t{};
            mach_timebase_info(&t);
            return t;
        }();
        const std::uint64_t ticks = mach_continuous_time();
        // numer/denom is 1/1 on Apple Silicon, but do the conversion properly so
        // this stays correct on any timebase.
        return tb.numer == tb.denom
             ? ticks
             : static_cast<ContinuousNs>((static_cast<__uint128_t>(ticks) * tb.numer) / tb.denom);
#elif defined(__linux__)
        // CLOCK_BOOTTIME includes suspend; CLOCK_MONOTONIC does not.
        struct timespec ts{};
        clock_gettime(CLOCK_BOOTTIME, &ts);
        return static_cast<ContinuousNs>(ts.tv_sec) * 1'000'000'000ull
             + static_cast<ContinuousNs>(ts.tv_nsec);
#else
#  error "AirUSB needs a sleep-continuous monotonic clock on this platform"
#endif
    }
};

} // namespace

const Clock& Clock::system() noexcept
{
    static const SystemClock c;
    return c;
}

} // namespace airusb
