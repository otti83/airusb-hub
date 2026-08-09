// The kernel/user ABI, and mostly the inputs it must refuse.
//
// The user-mode end of this channel is UNPRIVILEGED, and the other end is a
// kernel driver. A length trusted where it should be checked is kernel memory
// corruption reachable from a normal account, so almost every case below is a
// malformed record that must be rejected outright rather than clamped,
// normalised or partially accepted.
//
// The cases that are NOT refusals matter just as much, and they come from the
// same review: a short successful transfer, a zero-length transfer, and a
// completion naming a request that no longer exists are ordinary USB lifecycle
// events. A codec that called those "malformed" would make routine
// cancellation indistinguishable from an attack.

#include "../TestHarness.h"
#include "../../platform/windows/UdecxIpc.h"

#include <vector>

using namespace airusb;
using namespace airusb::windows::ipc;

namespace {

std::vector<std::uint8_t> bytes(std::size_t n, std::uint8_t seed = 1)
{
    std::vector<std::uint8_t> v(n);
    for (std::size_t i = 0; i < n; ++i)
        v[i] = static_cast<std::uint8_t>(i * 7u + seed);
    return v;
}

UrbRequest sampleOut()
{
    UrbRequest r;
    r.requestId          = 0x0102030405060708ull;
    r.sessionIncarnation = 0xAABBCCDDu;
    r.deviceIncarnation  = 7;
    r.endpointId         = 42;
    r.offeredLength      = 31;
    r.transferType       = TransferType::Bulk;
    r.direction          = Direction::Out;
    r.endpointAddress    = 0x02;
    r.flags              = 0;
    r.payload            = bytes(31);
    return r;
}

UrbRequest sampleIn()
{
    UrbRequest r = sampleOut();
    r.direction       = Direction::In;
    r.endpointAddress = 0x81;
    r.offeredLength   = 1024;
    r.flags           = kFlagShortOk;
    r.payload.clear();
    return r;
}

/// Encode, then hand the caller the buffer to corrupt.
template <typename T>
std::vector<std::uint8_t> enc(const T& r)
{
    std::vector<std::uint8_t> v;
    encode(r, v);
    return v;
}

void testRoundTrips()
{
    std::printf("round trips\n");

    TEST_CASE("an OUT transfer survives exactly") {
        const UrbRequest a = sampleOut();
        UrbRequest b;
        CHECK(decode(enc(a), b));
        CHECK_EQ(static_cast<long long>(b.requestId), static_cast<long long>(a.requestId));
        CHECK_EQ(b.sessionIncarnation, a.sessionIncarnation);
        CHECK_EQ(b.deviceIncarnation, a.deviceIncarnation);
        CHECK_EQ(b.endpointId, a.endpointId);
        CHECK_EQ(b.offeredLength, a.offeredLength);
        CHECK(b.direction == Direction::Out);
        CHECK(b.transferType == TransferType::Bulk);
        CHECK(b.payload == a.payload);
    }

    TEST_CASE("an IN transfer carries no data down") {
        UrbRequest b;
        CHECK(decode(enc(sampleIn()), b));
        CHECK(b.direction == Direction::In);
        CHECK(b.payload.empty());
        CHECK_EQ(b.flags, static_cast<std::uint8_t>(kFlagShortOk));
    }

    TEST_CASE("a control transfer keeps its setup packet") {
        UrbRequest a = sampleIn();
        a.transferType = TransferType::Control;
        a.endpointAddress = 0x80;
        const std::uint8_t setup[8] = { 0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x12, 0x00 };
        std::memcpy(a.setup, setup, 8);
        UrbRequest b;
        CHECK(decode(enc(a), b));
        CHECK(std::memcmp(b.setup, setup, 8) == 0);
    }

    TEST_CASE("a completion with IN data") {
        UrbCompletion a;
        a.requestId = 99; a.sessionIncarnation = 5; a.deviceIncarnation = 2;
        a.result = Result::Ok;
        a.payload = bytes(512, 3);
        a.actualLength = 512;
        UrbCompletion b;
        CHECK(decode(enc(a), b));
        CHECK(b.result == Result::Ok);
        CHECK_EQ(b.actualLength, 512u);
        CHECK(b.payload == a.payload);
    }

    TEST_CASE("a configure transaction keeps both endpoint sets separate") {
        // The released set is the one that matters: using a released endpoint's
        // queue afterwards is a use-after-free on a kernel object.
        Configure a;
        a.ticketId = 3; a.sessionIncarnation = 1; a.deviceIncarnation = 1;
        a.isConfiguration = true;
        a.configurationValue = 1;
        a.enable  = { 10, 11, 12 };
        a.release = { 7 };
        Configure b;
        CHECK(decode(enc(a), b));
        CHECK(b.isConfiguration);
        CHECK(b.enable  == a.enable);
        CHECK(b.release == a.release);
    }

    TEST_CASE("cancel and its acknowledgement are distinct opcodes") {
        CancelRequest a; a.requestId = 1234; a.sessionIncarnation = 9; a.deviceIncarnation = 4;
        CancelRequest b;
        CHECK(decode(enc(a), b));
        CHECK_EQ(static_cast<long long>(b.requestId), 1234LL);

        // A CancelAck must not decode as a CancelRequest. They carry identical
        // bodies, so only the opcode separates them, and confusing the two
        // would let the host retire a request the driver never cancelled.
        CancelAck ack; ack.requestId = 1234;
        CancelRequest wrong;
        CHECK(!decode(enc(ack), wrong));
    }
}

void testNormalUsbIsNotMalformed()
{
    std::printf("things that look wrong and are not\n");

    TEST_CASE("a short successful transfer decodes") {
        UrbCompletion a;
        a.result = Result::Ok;
        a.payload = bytes(512);
        a.actualLength = 512;           // against an offer of 1024, elsewhere
        UrbCompletion b;
        CHECK(decode(enc(a), b));
        CHECK(b.result == Result::Ok);
    }

    TEST_CASE("a zero-length transfer decodes, both directions") {
        UrbRequest a = sampleOut();
        a.offeredLength = 0;
        a.payload.clear();
        UrbRequest b;
        CHECK(decode(enc(a), b));
        CHECK_EQ(b.offeredLength, 0u);

        UrbCompletion c;
        c.result = Result::Ok;
        c.actualLength = 0;
        UrbCompletion d;
        CHECK(decode(enc(c), d));
        CHECK_EQ(d.actualLength, 0u);
    }

    TEST_CASE("a failure reporting partial progress decodes") {
        // Error completions may carry bytes that really did move. Refusing this
        // would discard data the guest is entitled to.
        UrbCompletion a;
        a.result = Result::Stall;
        a.payload = bytes(64);
        a.actualLength = 64;
        UrbCompletion b;
        CHECK(decode(enc(a), b));
        CHECK(b.result == Result::Stall);
        CHECK_EQ(b.actualLength, 64u);
    }

    TEST_CASE("a completion for an unknown request is a state question, not a codec one") {
        // Late completions after cancellation are expected. The codec's job is
        // to decode it; the driver's job is to discard it. If this were a
        // decode failure the driver could not tell a stale completion from an
        // attack, and would tear down a session over routine behaviour.
        UrbCompletion a;
        a.requestId = 0xFFFFFFFFFFFFFFFFull;
        a.result = Result::Canceled;
        UrbCompletion b;
        CHECK(decode(enc(a), b));
    }
}

void testRefusals()
{
    std::printf("what it refuses, one deviation at a time\n");

    TEST_CASE("a truncated record") {
        std::vector<std::uint8_t> v = enc(sampleOut());
        for (std::size_t cut = 1; cut < 12; ++cut) {
            std::vector<std::uint8_t> t(v.begin(), v.end() - static_cast<std::ptrdiff_t>(cut));
            UrbRequest r;
            CHECK(!decode(t, r));
        }
    }

    TEST_CASE("a length that does not match the buffer, in either direction") {
        std::vector<std::uint8_t> v = enc(sampleOut());
        v[0] = static_cast<std::uint8_t>(v[0] + 1);      // claims one more byte
        UrbRequest r;
        CHECK(!decode(v, r));

        v = enc(sampleOut());
        v[0] = static_cast<std::uint8_t>(v[0] - 1);      // claims one fewer
        CHECK(!decode(v, r));

        // Trailing bytes are a refusal, not something to ignore: "ignore the
        // rest" is how two parsers come to disagree about where a record ends.
        v = enc(sampleOut());
        v.push_back(0);
        CHECK(!decode(v, r));
    }

    TEST_CASE("a wrong version") {
        std::vector<std::uint8_t> v = enc(sampleOut());
        v[4] = 99;
        UrbRequest r;
        CHECK(!decode(v, r));
    }

    TEST_CASE("a record decoded as the wrong opcode") {
        UrbRequest r;
        UrbCompletion c;
        CHECK(!decode(enc(sampleOut()), c));
        CHECK(!decode(enc(UrbCompletion{}), r));
    }

    TEST_CASE("any nonzero reserved byte") {
        // Reserved fields are the version escape hatch. An unchecked one is a
        // field that has silently become load-bearing.
        std::vector<std::uint8_t> v = enc(sampleOut());
        const std::size_t reservedAt = 8 + 8 + 4 + 4 + 4 + 4 + 4 + 8;   // envelope + body
        for (std::size_t i = 0; i < 4; ++i) {
            std::vector<std::uint8_t> t = v;
            t[reservedAt + i] = 1;
            UrbRequest r;
            CHECK(!decode(t, r));
        }
    }

    TEST_CASE("an enum outside its range") {
        std::vector<std::uint8_t> v = enc(sampleOut());
        const std::size_t typeAt = 8 + 8 + 4 + 4 + 4 + 4;
        v[typeAt] = 3;                                   // no such transfer type
        UrbRequest r;
        CHECK(!decode(v, r));

        v = enc(sampleOut());
        v[typeAt + 1] = 2;                               // no such direction
        CHECK(!decode(v, r));

        UrbCompletion a;
        a.result = static_cast<Result>(999);
        UrbCompletion b;
        CHECK(!decode(enc(a), b));
    }

    TEST_CASE("an undefined flag bit") {
        std::vector<std::uint8_t> v = enc(sampleOut());
        const std::size_t flagsAt = 8 + 8 + 4 + 4 + 4 + 4 + 3;
        v[flagsAt] = 0x80;
        UrbRequest r;
        CHECK(!decode(v, r));
    }

    TEST_CASE("a payload that disagrees with the header — the whole point") {
        // An OUT that offers 31 bytes and carries 30, and an IN that carries
        // data at all. Either would mean the driver has two numbers and has to
        // choose; the format makes the choice impossible instead.
        UrbRequest a = sampleOut();
        a.payload = bytes(30);              // offeredLength is still 31
        UrbRequest r;
        CHECK(!decode(enc(a), r));

        UrbRequest b = sampleIn();
        b.payload = bytes(8);               // IN carries nothing down
        CHECK(!decode(enc(b), r));

        UrbCompletion c;
        c.result = Result::Ok;
        c.actualLength = 100;
        c.payload = bytes(99);
        UrbCompletion d;
        CHECK(!decode(enc(c), d));
    }

    TEST_CASE("a setup packet on a non-control transfer") {
        UrbRequest a = sampleOut();
        a.setup[0] = 0x21;
        UrbRequest r;
        CHECK(!decode(enc(a), r));
    }

    TEST_CASE("a length past the cap") {
        // Constructed by hand: the encoder would never produce it, which is
        // exactly why the decoder must not assume the encoder made it.
        std::vector<std::uint8_t> v(8, 0);
        const std::uint32_t huge = kMaxRecordBytes + 1;
        v[0] = static_cast<std::uint8_t>(huge);
        v[1] = static_cast<std::uint8_t>(huge >> 8);
        v[2] = static_cast<std::uint8_t>(huge >> 16);
        v[3] = static_cast<std::uint8_t>(huge >> 24);
        v[4] = 1;
        v[6] = 1;
        UrbRequest r;
        CHECK(!decode(v, r));
        CHECK(!decodeAny(v));
    }

    TEST_CASE("a configure whose counts do not match its body") {
        Configure a;
        a.enable = { 1, 2, 3 };
        std::vector<std::uint8_t> v = enc(a);
        v.resize(v.size() - 4);                          // drop one id
        const std::uint32_t n = static_cast<std::uint32_t>(v.size());
        v[0] = static_cast<std::uint8_t>(n);
        v[1] = static_cast<std::uint8_t>(n >> 8);
        v[2] = static_cast<std::uint8_t>(n >> 16);
        v[3] = static_cast<std::uint8_t>(n >> 24);
        Configure b;
        CHECK(!decode(v, b));                            // count says 3, body has 2
    }

    TEST_CASE("a configure that names both a configuration and an alt setting") {
        Configure a;
        a.isConfiguration  = true;
        a.alternateSetting = 1;                          // contradicts the transition
        Configure b;
        CHECK(!decode(enc(a), b));
    }

    TEST_CASE("a bool that is not 0 or 1") {
        Configure a;
        std::vector<std::uint8_t> v = enc(a);
        v[8 + 8 + 4 + 4] = 2;
        Configure b;
        CHECK(!decode(v, b));
    }

    TEST_CASE("an unknown opcode is refused, never skipped") {
        std::vector<std::uint8_t> v = enc(sampleOut());
        v[6] = 0x77;
        CHECK(!decodeAny(v));
        Opcode op{};
        CHECK(peekOpcode(v, op));                        // the envelope is fine
        CHECK(static_cast<int>(op) == 0x77);             // the body is not attempted
    }

    TEST_CASE("an empty buffer") {
        UrbRequest r;
        CHECK(!decode({}, r));
        CHECK(!decodeAny({}));
    }
}

void testResultMapping()
{
    std::printf("results\n");

    TEST_CASE("an unknown result never becomes success") {
        // The direction of the default is the whole safety property here.
        CHECK(toStatus(static_cast<Result>(4242)) != Status::Ok);
        CHECK(toStatus(Result::Failed) != Status::Ok);
        CHECK(toStatus(Result::Ok) == Status::Ok);
    }

    TEST_CASE("a short transfer is reported as success and decided by the driver") {
        // Windows makes the guest say, per URB, whether short is acceptable, and
        // only the driver holds that flag. Reporting a failure from user mode
        // would take the decision away from the side that has the information.
        CHECK(fromStatus(Status::XferShort) == Result::Ok);
    }

    TEST_CASE("the statuses a guest acts on differently survive the round trip") {
        const Status keep[] = {
            Status::Ok, Status::XferStall, Status::XferCancelled, Status::XferTimeout,
            Status::XferOverrun, Status::XferUnderrun,
        };
        for (Status s : keep) CHECK(toStatus(fromStatus(s)) == s);
        // Everything that means "the device is not there any more" collapses to
        // one wire value, on purpose, and comes back as something the guest can
        // act on.
        CHECK(fromStatus(Status::TransportLost) == Result::Disconnected);
        CHECK(fromStatus(Status::DeviceGone)    == Result::Disconnected);
    }

    TEST_CASE("every result has a name") {
        for (std::uint16_t i = 0; i <= static_cast<std::uint16_t>(Result::Failed); ++i) {
            const char* n = resultName(static_cast<Result>(i));
            CHECK(std::strcmp(n, "?") != 0);
        }
        CHECK(std::strcmp(resultName(static_cast<Result>(500)), "?") == 0);
    }
}

void testNoCrashOnGarbage()
{
    std::printf("garbage, deterministically\n");

    TEST_CASE("every single-byte mutation of a valid record is handled") {
        // Not a fuzz run — that is tests/fuzz — but it makes the common case
        // deterministic: no mutation may crash, and none may be accepted with
        // the record's meaning changed underneath.
        const std::vector<std::uint8_t> good = enc(sampleOut());
        std::size_t accepted = 0;
        for (std::size_t i = 0; i < good.size(); ++i) {
            for (std::uint8_t bit = 0; bit < 8; ++bit) {
                std::vector<std::uint8_t> t = good;
                t[i] = static_cast<std::uint8_t>(t[i] ^ (1u << bit));
                UrbRequest r;
                if (decode(t, r)) ++accepted;
            }
        }
        // Mutations inside the payload, the request id and the addresses are
        // legitimately still valid records — that is data, not structure. What
        // matters is that nothing crashed and that structural bytes rejected.
        CHECK(accepted > 0);
        CHECK(accepted < good.size() * 8);
    }
}

} // namespace

int main()
{
    std::printf("test_udecxipc\n");
    testRoundTrips();
    testNormalUsbIsNotMalformed();
    testRefusals();
    testResultMapping();
    testNoCrashOnGarbage();
    TEST_MAIN_END();
}
