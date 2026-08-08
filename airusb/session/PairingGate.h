// AirUSB Hub — how many times a stranger may guess at the SAS.
//
// THE ARGUMENT THIS EXISTS TO SUPPORT
//
// Pairing shows both users a six-digit number and asks whether they match. A man
// in the middle who relays the handshake produces a DIFFERENT number on each
// side, so the comparison catches them — with probability 1 - 10^-6, because the
// attacker gets one guess out of a million at what the honest side will display.
//
// "One in a million" is a statement about ONE attempt. It says nothing about an
// attacker who may make a million. Without a limit, the SAS is not a
// one-in-a-million defence; it is a one-in-a-million defence per try, against an
// adversary with unlimited tries, which is no defence at all. This file is what
// makes the number mean what the security argument claims it means.
//
// WHY THE LIMIT IS GLOBAL AND NOT PER-PEER
//
// The obvious design — count failures per peer identity — is worthless here, and
// worse than nothing because it looks like protection. A peer identity is an
// Ed25519 key the peer generates for itself. An attacker mints a fresh one per
// attempt at no cost, and every attempt looks like a first offence.
//
// So the counter belongs to the side being protected: this exporter allows N
// pairing attempts, from anyone, per window. That is unfriendly to a user who
// fat-fingers a comparison several times in a row, and that is the correct trade.
// The failure mode of a limit that is too tight is a person waiting; the failure
// mode of one that is too loose is a stranger owning a disk.
//
// WHY THE CLOCK MUST BE THE CONTINUOUS ONE
//
// Every deadline here is on ContinuousNs — mach_continuous_time, CLOCK_BOOTTIME,
// biased Windows interrupt time — the clock that keeps counting through system
// sleep. A monotonic clock that stops while suspended would let an attacker clear
// a lockout by suspending the machine, which is not a theoretical capability on a
// laptop somebody closed.
//
// WHAT IT DOES NOT DEFEND
//
//   * It does not survive a process restart on its own. `serialize`/`deserialize`
//     exist so a daemon can persist it next to the pin store; a gate held only in
//     memory is reset by anything that can restart the daemon.
//   * It does not distinguish attackers from a user having a bad day. It cannot:
//     that is the same event on the wire.

#ifndef AIRUSB_SESSION_PAIRINGGATE_H
#define AIRUSB_SESSION_PAIRINGGATE_H

#include "../core/Clock.h"
#include "../core/Status.h"

#include <cstdint>
#include <string>

namespace airusb::session {

/// Defaults chosen so that exhausting a six-digit SAS is not a thing a patient
/// attacker does. With a 30-second floor doubling to an hour, a million guesses
/// is on the order of a hundred thousand years; with no limit it is an afternoon.
struct PairingLimits {
    /// Attempts allowed before the backoff starts biting. Small on purpose: a
    /// person comparing six digits needs one or two, not ten.
    std::uint32_t freeAttempts = 3;

    /// The first lockout, applied on the failure after `freeAttempts`.
    std::uint64_t baseLockoutMs = 30'000;

    /// Each further consecutive failure doubles the wait, up to this.
    std::uint64_t maxLockoutMs = 3'600'000;   // one hour

    /// A quiet period after which the consecutive-failure count decays back to
    /// zero. Without it the gate is a one-way ratchet and the only cure is a
    /// restart — which is exactly the reset an attacker would look for.
    std::uint64_t decayAfterMs = 86'400'000;  // one day
};

class PairingGate {
public:
    PairingGate() = default;
    explicit PairingGate(const PairingLimits& limits) noexcept : _limits(limits) {}

    /// May a pairing attempt start right now?
    ///
    /// Returns Ok, or Busy when locked out. `retryAfterMs`, if given, receives how
    /// long the caller must wait — a peer that is told "not now, try in 40
    /// seconds" behaves better than one told only "no", and the number leaks
    /// nothing an attacker cannot measure with a stopwatch anyway.
    Status mayAttempt(const Clock& clock, std::uint64_t* retryAfterMs = nullptr) const noexcept;

    /// A pairing attempt finished and the SAS was NOT confirmed. This is the
    /// event the whole file is about, and it must be recorded for a peer that
    /// disconnects mid-pairing as well as one that answers "no" — otherwise the
    /// cheapest attack is to hang up before the answer.
    void recordFailure(const Clock& clock) noexcept;

    /// A human confirmed the SAS. Clears the streak: the point of the limit is to
    /// bound guessing, and a correct answer is evidence there was no guessing.
    void recordSuccess(const Clock& clock) noexcept;

    std::uint32_t consecutiveFailures() const noexcept { return _failures; }
    bool lockedOut(const Clock& clock) const noexcept;

    /// Line-oriented text, same reasoning as the pin store: security state a user
    /// may want to read or clear by hand.
    std::string serialize() const;
    bool deserialize(const std::string& text);

private:
    std::uint64_t lockoutMsFor(std::uint32_t failures) const noexcept;

    PairingLimits _limits{};
    std::uint32_t _failures      = 0;
    ContinuousNs  _lastFailureNs = 0;
    bool          _everFailed    = false;
};

} // namespace airusb::session

#endif // AIRUSB_SESSION_PAIRINGGATE_H
