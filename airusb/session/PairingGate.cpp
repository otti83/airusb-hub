#include "PairingGate.h"

#include <sstream>

namespace airusb::session {

namespace {

constexpr const char* kHeader = "airusb-pairgate-v1";

constexpr std::uint64_t kMsToNs = 1'000'000ull;

} // namespace

std::uint64_t PairingGate::lockoutMsFor(std::uint32_t failures) const noexcept
{
    if (failures <= _limits.freeAttempts) return 0;

    // Doubling, but computed so it cannot wrap. A shift of 64 or more is
    // undefined behaviour, not a large number, and the cap is small enough that
    // anything past a few dozen doublings is the same answer anyway.
    const std::uint32_t over = failures - _limits.freeAttempts;
    std::uint64_t ms = _limits.baseLockoutMs;
    for (std::uint32_t i = 1; i < over; ++i) {
        if (ms >= _limits.maxLockoutMs) break;
        ms *= 2;
    }
    return ms > _limits.maxLockoutMs ? _limits.maxLockoutMs : ms;
}

bool PairingGate::lockedOut(const Clock& clock) const noexcept
{
    std::uint64_t ignored = 0;
    return mayAttempt(clock, &ignored) != Status::Ok;
}

Status PairingGate::mayAttempt(const Clock& clock, std::uint64_t* retryAfterMs) const noexcept
{
    if (retryAfterMs) *retryAfterMs = 0;
    if (!_everFailed || _failures == 0) return Status::Ok;

    const ContinuousNs now = clock.nowNs();

    // A clock that appears to have gone backwards means something changed
    // underneath us. Fail CLOSED: treat it as no time having passed, so the
    // lockout stands. The alternative hands an attacker a reset for the price of
    // whatever made the clock move.
    const ContinuousNs sinceNs = now >= _lastFailureNs ? now - _lastFailureNs : 0;

    if (_limits.decayAfterMs != 0 && sinceNs >= _limits.decayAfterMs * kMsToNs)
        return Status::Ok;                       // quiet long enough; streak forgotten

    const std::uint64_t lockMs = lockoutMsFor(_failures);
    if (lockMs == 0) return Status::Ok;          // still within the free attempts

    const ContinuousNs lockNs = lockMs * kMsToNs;
    if (sinceNs >= lockNs) return Status::Ok;

    if (retryAfterMs) *retryAfterMs = (lockNs - sinceNs) / kMsToNs + 1;
    return Status::Busy;
}

void PairingGate::recordFailure(const Clock& clock) noexcept
{
    const ContinuousNs now = clock.nowNs();

    // Decay first, so a streak that has already aged out does not resume from
    // where it left off a week ago.
    if (_everFailed && _limits.decayAfterMs != 0) {
        const ContinuousNs sinceNs = now >= _lastFailureNs ? now - _lastFailureNs : 0;
        if (sinceNs >= _limits.decayAfterMs * kMsToNs) _failures = 0;
    }

    if (_failures != 0xFFFFFFFFu) ++_failures;
    _lastFailureNs = now;
    _everFailed    = true;
}

void PairingGate::recordSuccess(const Clock& clock) noexcept
{
    (void)clock;
    _failures   = 0;
    _everFailed = false;
}

// ---------------------------------------------------------------------------

std::string PairingGate::serialize() const
{
    std::ostringstream os;
    os << kHeader << '\n'
       << _failures << '\t'
       << _lastFailureNs << '\t'
       << (_everFailed ? 1 : 0) << '\n';
    return os.str();
}

bool PairingGate::deserialize(const std::string& text)
{
    std::istringstream is(text);
    std::string line;

    if (!std::getline(is, line)) return false;
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (line != kHeader) return false;

    if (!std::getline(is, line)) return false;
    if (!line.empty() && line.back() == '\r') line.pop_back();

    std::istringstream ls(line);
    std::string a, b, c;
    if (!std::getline(ls, a, '\t')) return false;
    if (!std::getline(ls, b, '\t')) return false;
    if (!std::getline(ls, c, '\t')) return false;

    try {
        // Committed only once every field parsed. A half-read gate is a gate that
        // is open, which is the wrong way for this particular door to fail.
        const std::uint32_t f  = static_cast<std::uint32_t>(std::stoul(a));
        const ContinuousNs  ns = static_cast<ContinuousNs>(std::stoull(b));
        const bool          ev = std::stoul(c) != 0;
        _failures      = f;
        _lastFailureNs = ns;
        _everFailed    = ev;
    } catch (...) {
        return false;
    }
    return true;
}

} // namespace airusb::session
