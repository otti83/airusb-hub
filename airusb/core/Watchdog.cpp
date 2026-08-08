#include "Watchdog.h"
#include "Clock.h"

#if defined(__APPLE__)
#  include <mach/mach_time.h>
#elif defined(__linux__)
#  include <ctime>
#elif defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
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
#elif defined(_WIN32)
        // The BIASED interrupt time, which INCLUDES time spent asleep.
        //
        // Not QueryUnbiasedInterruptTime: "unbiased" means the count EXCLUDES
        // sleep and hibernation, which is exactly the property that must not
        // hold here. The P1 plan named the unbiased call; that was wrong for
        // this reason, and this is the correction.
        //
        // Getting it backwards produces the failure Clock.h describes: a lease
        // that still looks fresh after the machine slept for hours, so the
        // exporter hands the drive back to a peer that has long since given up.
        //
        // QueryInterruptTimePrecise lives in an API-set DLL with no import
        // library on some toolchains (MinGW has none), so it is resolved at
        // runtime and falls back to GetTickCount64 — which MSDN documents as
        // also including suspend time, and which is always linkable. The
        // fallback is ~15 ms granular; every deadline in the timeout table is
        // hundreds of milliseconds or more, so that is precision lost from the
        // PING latency figure and nothing else.
        using QitpFn = void (WINAPI*)(PULONGLONG);
        static const QitpFn qitp = [] {
            const HMODULE h = ::GetModuleHandleW(L"kernelbase.dll");
            return h ? reinterpret_cast<QitpFn>(reinterpret_cast<void*>(
                           ::GetProcAddress(h, "QueryInterruptTimePrecise")))
                     : nullptr;
        }();

        if (qitp) {
            ULONGLONG hundredNs = 0;
            qitp(&hundredNs);
            return static_cast<ContinuousNs>(hundredNs) * 100ull;
        }
        return static_cast<ContinuousNs>(::GetTickCount64()) * 1'000'000ull;
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
