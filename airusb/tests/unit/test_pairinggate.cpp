// The limit that makes "one in a million" mean something.
//
// The SAS argument is a statement about ONE attempt. These cases are about the
// attacker who intends to make a million of them, and about the two shortcuts
// that would otherwise be available to them: minting a fresh identity per try,
// and suspending the machine to clear a lockout.

#include "../TestHarness.h"
#include "../../session/PairingGate.h"

using namespace airusb;
using namespace airusb::session;

namespace {

constexpr ContinuousNs kMs = 1'000'000ull;

PairingLimits tightLimits()
{
    PairingLimits l;
    l.freeAttempts  = 3;
    l.baseLockoutMs = 1000;
    l.maxLockoutMs  = 8000;
    l.decayAfterMs  = 100'000;
    return l;
}

void testTheBudget()
{
    std::printf("the attempt budget\n");

    TEST_CASE("a fresh gate lets anyone in") {
        ManualClock clock;
        const PairingGate g;
        CHECK(g.mayAttempt(clock) == Status::Ok);
        CHECK(!g.lockedOut(clock));
    }

    TEST_CASE("the free attempts really are free") {
        ManualClock clock;
        PairingGate g(tightLimits());
        for (int i = 0; i < 3; ++i) {
            CHECK(g.mayAttempt(clock) == Status::Ok);
            g.recordFailure(clock);
        }
        CHECK_EQ(g.consecutiveFailures(), 3u);
        CHECK(g.mayAttempt(clock) == Status::Ok);   // 3 failures, still at the line
    }

    TEST_CASE("the attempt after the budget is refused") {
        ManualClock clock;
        PairingGate g(tightLimits());
        for (int i = 0; i < 4; ++i) g.recordFailure(clock);

        std::uint64_t retry = 0;
        CHECK(g.mayAttempt(clock, &retry) == Status::Busy);
        CHECK(g.lockedOut(clock));
        CHECK(retry > 0);
        CHECK(retry <= 1001);
    }

    TEST_CASE("waiting out the lockout reopens it") {
        ManualClock clock;
        PairingGate g(tightLimits());
        for (int i = 0; i < 4; ++i) g.recordFailure(clock);
        CHECK(g.lockedOut(clock));

        clock.advanceNs(1000 * kMs);
        CHECK(g.mayAttempt(clock) == Status::Ok);
    }

    TEST_CASE("each further failure doubles the wait, up to the cap") {
        ManualClock clock;
        PairingGate g(tightLimits());
        for (int i = 0; i < 4; ++i) g.recordFailure(clock);

        std::uint64_t r1 = 0, r2 = 0, r3 = 0;
        (void)g.mayAttempt(clock, &r1);            // ~1000
        clock.advanceNs(1000 * kMs);
        g.recordFailure(clock);
        (void)g.mayAttempt(clock, &r2);            // ~2000
        clock.advanceNs(2000 * kMs);
        g.recordFailure(clock);
        (void)g.mayAttempt(clock, &r3);            // ~4000

        CHECK(r2 > r1);
        CHECK(r3 > r2);

        // And it stops doubling rather than running away.
        for (int i = 0; i < 20; ++i) {
            clock.advanceNs(8000 * kMs);
            g.recordFailure(clock);
        }
        std::uint64_t capped = 0;
        (void)g.mayAttempt(clock, &capped);
        CHECK(capped <= 8001);
    }

    TEST_CASE("a confirmed pairing clears the streak") {
        ManualClock clock;
        PairingGate g(tightLimits());
        for (int i = 0; i < 4; ++i) g.recordFailure(clock);
        CHECK(g.lockedOut(clock));

        g.recordSuccess(clock);
        CHECK_EQ(g.consecutiveFailures(), 0u);
        CHECK(g.mayAttempt(clock) == Status::Ok);
    }

    TEST_CASE("a long quiet period forgives the streak") {
        // Otherwise the gate is a one-way ratchet whose only cure is a restart,
        // and a restart is exactly the reset an attacker would go looking for.
        ManualClock clock;
        PairingGate g(tightLimits());
        for (int i = 0; i < 6; ++i) g.recordFailure(clock);
        CHECK(g.lockedOut(clock));

        clock.advanceNs(100'000 * kMs);
        CHECK(g.mayAttempt(clock) == Status::Ok);

        // And the next failure starts from one, not from seven.
        g.recordFailure(clock);
        CHECK_EQ(g.consecutiveFailures(), 1u);
    }
}

void testTheShortcuts()
{
    std::printf("the two shortcuts an attacker would take\n");

    TEST_CASE("minting a fresh identity per attempt does not help") {
        // The whole reason the counter is global. A peer identity is a key the
        // peer generates for itself, so per-peer counting would see a first
        // offence every time, for ever. Nothing in this API accepts a peer.
        ManualClock clock;
        PairingGate g(tightLimits());
        for (int i = 0; i < 4; ++i) g.recordFailure(clock);
        CHECK(g.lockedOut(clock));
        // There is no per-peer state to reset, and no argument to pass that
        // would reset it. A "different attacker" is refused identically.
        CHECK(g.mayAttempt(clock) == Status::Busy);
    }

    TEST_CASE("suspending the machine does not clear a lockout") {
        // ContinuousNs keeps counting through sleep, so this test is really a
        // statement about which clock the caller must pass. The failure it guards
        // against is closing a laptop lid to reset the gate.
        ManualClock clock;
        PairingGate g(tightLimits());
        for (int i = 0; i < 4; ++i) g.recordFailure(clock);

        // A monotonic clock would not have advanced across the suspend; the
        // continuous one does, and that is what makes the lockout expire on
        // wall time rather than on awake time.
        CHECK(g.lockedOut(clock));
        clock.advanceNs(500 * kMs);
        CHECK(g.lockedOut(clock));      // half the lockout: still shut
    }

    TEST_CASE("a clock that goes backwards fails closed") {
        ManualClock clock(10'000 * kMs);
        PairingGate g(tightLimits());
        for (int i = 0; i < 4; ++i) g.recordFailure(clock);
        CHECK(g.lockedOut(clock));

        // Something moved the clock back. The lockout must stand, not evaporate.
        ManualClock earlier(0);
        CHECK(g.mayAttempt(earlier) == Status::Busy);
    }

    TEST_CASE("hanging up mid-pairing counts as a failure") {
        // Recorded by the caller, but asserted here because it is the cheapest
        // attack if it is ever forgotten: guess, and disconnect before answering.
        ManualClock clock;
        PairingGate g(tightLimits());
        for (int i = 0; i < 4; ++i) g.recordFailure(clock);   // as if all were aborts
        CHECK(g.lockedOut(clock));
    }
}

void testPersistence()
{
    std::printf("surviving a restart\n");

    TEST_CASE("a gate round-trips through its text form") {
        ManualClock clock(7777 * kMs);
        PairingGate g(tightLimits());
        for (int i = 0; i < 5; ++i) g.recordFailure(clock);

        PairingGate loaded(tightLimits());
        CHECK(loaded.deserialize(g.serialize()));
        CHECK_EQ(loaded.consecutiveFailures(), g.consecutiveFailures());
        CHECK(loaded.lockedOut(clock));
    }

    TEST_CASE("a corrupt gate is refused rather than half-loaded") {
        PairingGate g(tightLimits());
        CHECK(!g.deserialize(""));
        CHECK(!g.deserialize("wrong-header\n1\t2\t1\n"));
        CHECK(!g.deserialize("airusb-pairgate-v1\n"));
        CHECK(!g.deserialize("airusb-pairgate-v1\nnot-a-number\t2\t1\n"));
        CHECK(!g.deserialize("airusb-pairgate-v1\n1\t2\n"));
        CHECK_EQ(g.consecutiveFailures(), 0u);
    }

    TEST_CASE("a CRLF file still loads") {
        ManualClock clock(500 * kMs);
        PairingGate g(tightLimits());
        g.recordFailure(clock);
        std::string crlf;
        for (char c : g.serialize()) { if (c == '\n') crlf += '\r'; crlf += c; }

        PairingGate loaded(tightLimits());
        CHECK(loaded.deserialize(crlf));
        CHECK_EQ(loaded.consecutiveFailures(), 1u);
    }
}

} // namespace

int main()
{
    std::printf("test_pairinggate\n");
    testTheBudget();
    testTheShortcuts();
    testPersistence();
    TEST_MAIN_END();
}
