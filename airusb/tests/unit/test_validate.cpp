// P2.0 — one test per validation rule R1..R12 (P1 plan §3.12).
//
// These are the rules that stand between a hostile or buggy peer and a kernel
// transfer buffer. R5 in particular is the CVE-2016-3955 class fix.

#include "../TestHarness.h"
#include "../../protocol/Validate.h"

using namespace airusb;
using namespace airusb::protocol;

namespace {

Limits defaultLimits()
{
    Limits l;
    l.maxRecordBytes   = wire::kRecordBytesDefault;
    l.maxTransferBytes = wire::kTransferBytesDefault;
    l.maxSegmentBytes  = wire::kSegmentBytesDefault;
    l.maxIsoPackets    = 128;
    return l;
}

Header submitHeader(std::uint32_t totalLen)
{
    Header h;
    h.type      = static_cast<std::uint8_t>(wire::Type::Submit);
    h.flags     = wire::kFlagSegFirst;
    h.channel   = wire::channelFor(1, 0x81);
    h.bodyLen   = static_cast<std::uint32_t>(wire::kBodySubmit + totalLen);
    h.attachId  = 1;
    h.requestId = 100;
    h.totalLen  = totalLen;
    return h;
}

void testR1()
{
    TEST_CASE("R1 record size ceiling, pre- and post-handshake") {
        auto lim = defaultLimits();
        CHECK(r1_recordSize(8192, lim, /*handshakeDone=*/false).ok());
        CHECK(!r1_recordSize(8193, lim, false).ok());
        CHECK_EQ(static_cast<int>(r1_recordSize(8193, lim, false).status),
                 static_cast<int>(Status::LimitExceeded));
        CHECK(r1_recordSize(16640, lim, /*handshakeDone=*/true).ok());
        CHECK(!r1_recordSize(16641, lim, true).ok());
        CHECK(r1_recordSize(8193, lim, false).fatal);
    }
}

void testR2()
{
    TEST_CASE("R2 total_len ceiling; no allocation sized by one peer field") {
        auto lim = defaultLimits();
        Header h = submitHeader(0);
        h.totalLen = lim.maxTransferBytes;
        CHECK(r2_totalLen(h, lim).ok());

        h.totalLen = lim.maxTransferBytes + 1;
        CHECK(!r2_totalLen(h, lim).ok());
        CHECK_EQ(static_cast<int>(r2_totalLen(h, lim).status),
                 static_cast<int>(Status::LimitExceeded));
    }

    TEST_CASE("R2 seg_offset beyond total_len is malformed") {
        auto lim = defaultLimits();
        Header h = submitHeader(100);
        h.segOffset = 101;
        CHECK(!r2_totalLen(h, lim).ok());
    }
}

void testR3()
{
    TEST_CASE("R3 body_len must cover the fixed body") {
        Header h = submitHeader(0);
        h.bodyLen = wire::kBodySubmit - 1;
        CHECK(!r3_bodyLen(h, 1024).ok());

        h.bodyLen = wire::kBodySubmit;
        CHECK(r3_bodyLen(h, wire::kBodySubmit).ok());
    }

    TEST_CASE("R3 body_len larger than the bytes actually present is malformed") {
        Header h = submitHeader(0);
        h.bodyLen = 1000;
        CHECK(!r3_bodyLen(h, 40).ok());
    }

    TEST_CASE("R3 unknown non-data-plane type is skipped, not rejected") {
        Header h;
        h.type    = 0xEE;          // unknown, outside 0x40-0x4F
        h.bodyLen = 12;
        CHECK(r3_bodyLen(h, 12).ok());   // forward compatibility
    }

    TEST_CASE("R3 unknown DATA-PLANE type is rejected") {
        Header h;
        h.type    = 0x4F;          // unknown but inside the data-plane range
        h.bodyLen = 12;
        auto v = r3_bodyLen(h, 12);
        CHECK(!v.ok());
        CHECK_EQ(static_cast<int>(v.status), static_cast<int>(Status::UnsupportedMessage));
    }
}

void testR4()
{
    TEST_CASE("R4 SUBMIT exactness: total_len == iso*16 + (OUT ? buffer_len : 0)") {
        SubmitBody b;
        b.epAddr   = 0x01;                                   // OUT endpoint 1
        b.dir      = static_cast<std::uint8_t>(wire::Dir::Out);
        b.xferType = static_cast<std::uint8_t>(wire::XferType::Bulk);
        b.bufferLen = 512;

        Header h = submitHeader(512);
        CHECK(r4_submitIdentity(h, b).ok());

        h.totalLen = 511;                                    // off by one
        CHECK(!r4_submitIdentity(h, b).ok());
    }

    TEST_CASE("R4 IN transfers carry no OUT payload") {
        SubmitBody b;
        b.epAddr    = 0x81;
        b.dir       = static_cast<std::uint8_t>(wire::Dir::In);
        b.xferType  = static_cast<std::uint8_t>(wire::XferType::Bulk);
        b.bufferLen = 512;

        Header h = submitHeader(0);                          // IN: total_len must be 0
        CHECK(r4_submitIdentity(h, b).ok());

        h.totalLen = 512;
        CHECK(!r4_submitIdentity(h, b).ok());
    }

    TEST_CASE("R4 dir must match the endpoint address direction bit") {
        SubmitBody b;
        b.epAddr   = 0x81;                                   // IN by address
        b.dir      = static_cast<std::uint8_t>(wire::Dir::Out);  // contradicts it
        b.xferType = static_cast<std::uint8_t>(wire::XferType::Bulk);
        Header h = submitHeader(0);
        CHECK(!r4_submitIdentity(h, b).ok());
    }

    TEST_CASE("R4 ep0 dir is authoritative, not derived from the address") {
        // A control transfer's data direction comes from bmRequestType, so ep0 must
        // be allowed to declare either direction with address 0x00.
        SubmitBody b;
        b.epAddr   = 0x00;
        b.dir      = static_cast<std::uint8_t>(wire::Dir::In);
        b.xferType = static_cast<std::uint8_t>(wire::XferType::Control);
        Header h = submitHeader(0);
        CHECK(r4_submitIdentity(h, b).ok());

        b.dir = static_cast<std::uint8_t>(wire::Dir::Out);
        b.bufferLen = 8;
        h.totalLen  = 8;
        CHECK(r4_submitIdentity(h, b).ok());
    }

    TEST_CASE("R4 non-iso transfers must not declare iso packets") {
        SubmitBody b;
        b.epAddr      = 0x81;
        b.dir         = static_cast<std::uint8_t>(wire::Dir::In);
        b.xferType    = static_cast<std::uint8_t>(wire::XferType::Bulk);
        b.isoPktCount = 4;
        Header h = submitHeader(0);
        CHECK(!r4_submitIdentity(h, b).ok());
    }

    TEST_CASE("R4 COMPLETE reserved field must be zero") {
        CompleteBody b;
        b.epAddr   = 0x81;
        b.dir      = static_cast<std::uint8_t>(wire::Dir::In);
        b.xferType = static_cast<std::uint8_t>(wire::XferType::Bulk);
        b.reserved = 1;
        Header h; h.totalLen = 0;
        CHECK(!r4_completeIdentity(h, b).ok());
    }
}

void testR5()
{
    TEST_CASE("R5 actual_len > requested_len is rejected (CVE-2016-3955 class)") {
        CompleteBody b;
        b.epAddr       = 0x81;
        b.dir          = static_cast<std::uint8_t>(wire::Dir::In);
        b.xferType     = static_cast<std::uint8_t>(wire::XferType::Bulk);
        b.requestedLen = 512;
        b.actualLen    = 513;          // claims more than the kernel buffer holds
        b.payloadLen   = 513;

        auto v = r5_actualLen(b);
        CHECK(!v.ok());
        CHECK_EQ(static_cast<int>(v.rule), static_cast<int>(Rule::R5_ActualLen));
        CHECK(v.fatal);
    }

    TEST_CASE("R5 a short read is legitimate") {
        CompleteBody b;
        b.epAddr       = 0x81;
        b.dir          = static_cast<std::uint8_t>(wire::Dir::In);
        b.xferType     = static_cast<std::uint8_t>(wire::XferType::Bulk);
        b.requestedLen = 512;
        b.actualLen    = 13;           // a CSW, for instance
        b.payloadLen   = 13;
        CHECK(r5_actualLen(b).ok());
    }

    TEST_CASE("R5 IN requires payload_len == actual_len") {
        CompleteBody b;
        b.epAddr       = 0x81;
        b.dir          = static_cast<std::uint8_t>(wire::Dir::In);
        b.xferType     = static_cast<std::uint8_t>(wire::XferType::Bulk);
        b.requestedLen = 512;
        b.actualLen    = 100;
        b.payloadLen   = 99;           // disagrees
        CHECK(!r5_actualLen(b).ok());
    }

    TEST_CASE("R5 OUT carries no payload back") {
        CompleteBody b;
        b.epAddr       = 0x01;
        b.dir          = static_cast<std::uint8_t>(wire::Dir::Out);
        b.xferType     = static_cast<std::uint8_t>(wire::XferType::Bulk);
        b.requestedLen = 512;
        b.actualLen    = 512;
        b.payloadLen   = 512;          // must be 0
        CHECK(!r5_actualLen(b).ok());

        b.payloadLen = 0;
        CHECK(r5_actualLen(b).ok());
    }
}

void testR6()
{
    TEST_CASE("R6 iso offsets must stay inside the buffer") {
        auto lim = defaultLimits();
        std::vector<std::uint8_t> table;
        IsoDesc d;
        d.offset = 0;    d.length = 192; encodeIsoDesc(d, table);
        d.offset = 192;  d.length = 192; encodeIsoDesc(d, table);
        CHECK(r6_isoTable(table, 2, 384, lim).ok());

        // Second packet now runs past the declared buffer.
        std::vector<std::uint8_t> bad;
        d.offset = 0;    d.length = 192; encodeIsoDesc(d, bad);
        d.offset = 192;  d.length = 300; encodeIsoDesc(d, bad);
        CHECK(!r6_isoTable(bad, 2, 384, lim).ok());
    }

    TEST_CASE("R6 offset+length cannot wrap into a passing check") {
        auto lim = defaultLimits();
        std::vector<std::uint8_t> table;
        IsoDesc d;
        d.offset = 0xFFFFFFF0u;
        d.length = 0x20u;          // 32-bit sum would wrap to 0x10
        encodeIsoDesc(d, table);
        CHECK(!r6_isoTable(table, 1, 1024, lim).ok());
    }

    TEST_CASE("R6 packet count ceiling") {
        auto lim = defaultLimits();
        std::vector<std::uint8_t> table;
        CHECK(!r6_isoTable(table, lim.maxIsoPackets + 1, 1024, lim).ok());
        CHECK(!r6_isoTable(table, wire::kIsoPacketsCeiling + 1, 1024, lim).ok());
    }

    TEST_CASE("R6 truncated table is rejected before the loop reads it") {
        auto lim = defaultLimits();
        std::vector<std::uint8_t> table(wire::kIsoDescSize, 0);   // room for 1
        CHECK(!r6_isoTable(table, 4, 1024, lim).ok());            // claims 4
    }

    TEST_CASE("R6 offsets must be non-decreasing") {
        auto lim = defaultLimits();
        std::vector<std::uint8_t> table;
        IsoDesc d;
        d.offset = 192; d.length = 100; encodeIsoDesc(d, table);
        d.offset = 0;   d.length = 100; encodeIsoDesc(d, table);
        CHECK(!r6_isoTable(table, 2, 1024, lim).ok());
    }
}

void testR7()
{
    TEST_CASE("R7 UTF-8 validation rejects the classic attacks") {
        auto s = [](const char* t) {
            return std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t*>(t), std::strlen(t));
        };
        CHECK(isValidUtf8(s("SanDisk Ultra")));
        CHECK(isValidUtf8(s("USB\xE3\x83\xA1\xE3\x83\xA2\xE3\x83\xAA")));   // Japanese

        const std::uint8_t overlong[]  = {0xC0, 0xAF};                 // overlong '/'
        const std::uint8_t surrogate[] = {0xED, 0xA0, 0x80};           // U+D800
        const std::uint8_t truncated[] = {0xE3, 0x83};                 // cut short
        const std::uint8_t badCont[]   = {0xE3, 0x28, 0xA1};           // bad continuation
        const std::uint8_t embeddedNul[] = {'a', 0x00, 'b'};
        const std::uint8_t tooBig[]    = {0xF5, 0x80, 0x80, 0x80};     // > U+10FFFF

        CHECK(!isValidUtf8(overlong));
        CHECK(!isValidUtf8(surrogate));
        CHECK(!isValidUtf8(truncated));
        CHECK(!isValidUtf8(badCont));
        CHECK(!isValidUtf8(embeddedNul));
        CHECK(!isValidUtf8(tooBig));
    }

    TEST_CASE("R7 length ceiling") {
        std::vector<std::uint8_t> big(wire::kUtf8FieldMax + 1, 'a');
        CHECK(!r7_utf8Field(big).ok());
        std::vector<std::uint8_t> okSize(wire::kUtf8FieldMax, 'a');
        CHECK(r7_utf8Field(okSize).ok());
    }
}

void testR8()
{
    TEST_CASE("R8 request_id must be strictly increasing and not outstanding") {
        CHECK(r8_requestId(101, 100, false).ok());
        CHECK(!r8_requestId(100, 100, false).ok());   // equal
        CHECK(!r8_requestId(99, 100, false).ok());    // regressed
        // Reuse of a LIVE request_id is how URB aliasing and response confusion happen.
        auto v = r8_requestId(101, 100, /*outstanding=*/true);
        CHECK(!v.ok());
        CHECK(v.fatal);
    }
}

void testR9()
{
    TEST_CASE("R9 counts are bounded before the loop that consumes them") {
        CHECK(r9_countCeiling(8, wire::kMaxConfigs).ok());
        CHECK(!r9_countCeiling(9, wire::kMaxConfigs).ok());
        CHECK(r9_countCeiling(128, wire::kMaxStrings).ok());
        CHECK(!r9_countCeiling(129, wire::kMaxStrings).ok());
    }
}

void testR12()
{
    TEST_CASE("R12 epoch mismatch drops silently, never escalates") {
        auto v = r12_deviceEpoch(3, 4);
        CHECK(!v.ok());
        CHECK(v.silentDrop);
        CHECK(!v.fatal);                                    // expected after a reset
        CHECK_EQ(static_cast<int>(v.status), static_cast<int>(Status::Ok));

        CHECK(r12_deviceEpoch(4, 4).ok());
    }
}

void testReservedFlags()
{
    TEST_CASE("reserved flags are fatal on the data plane, ignored elsewhere") {
        Header h;
        h.type  = static_cast<std::uint8_t>(wire::Type::Submit);
        h.flags = 0x10;                                     // an MBZ bit
        CHECK(!reservedFlags(h).ok());

        h.type = static_cast<std::uint8_t>(wire::Type::Ping);
        CHECK(reservedFlags(h).ok());                       // tolerated
    }
}

void testHeaderComposite()
{
    TEST_CASE("TRANSPORT_LOST must never appear on the wire") {
        auto lim = defaultLimits();
        Header h;
        h.type    = static_cast<std::uint8_t>(wire::Type::Complete);
        h.bodyLen = wire::kBodyComplete;
        h.status  = static_cast<std::uint16_t>(Status::TransportLost);
        CHECK(!validateHeader(h, wire::kBodyComplete, lim).ok());
    }

    TEST_CASE("a request may not carry a non-zero status") {
        auto lim = defaultLimits();
        Header h;
        h.type    = static_cast<std::uint8_t>(wire::Type::Submit);
        h.bodyLen = wire::kBodySubmit;
        h.status  = static_cast<std::uint16_t>(Status::XferStall);
        CHECK(!validateHeader(h, wire::kBodySubmit, lim).ok());

        h.type = static_cast<std::uint8_t>(wire::Type::Complete);
        h.bodyLen = wire::kBodyComplete;
        CHECK(validateHeader(h, wire::kBodyComplete, lim).ok());   // responses may
    }
}

void testStatusTable()
{
    TEST_CASE("status table is complete and self-consistent") {
        CHECK(isKnownStatus(static_cast<std::uint16_t>(Status::XferStall)));
        CHECK(isKnownStatus(0x0000));
        CHECK(!isKnownStatus(0x7FFF));
        CHECK(isFatal(Status::MalformedFrame));
        CHECK(isFatal(Status::AuthFailed));
        CHECK(!isFatal(Status::XferStall));
        CHECK(!isWireLegal(Status::TransportLost));
        CHECK(isWireLegal(Status::XferStall));
        CHECK(isTransferStatus(Status::XferStall));
        CHECK(!isTransferStatus(Status::DeviceGone));
        CHECK(std::strcmp(statusName(Status::XferStall), "XFER_STALL") == 0);
    }
}

} // namespace

int main()
{
    std::printf("test_validate\n");
    testR1();
    testR2();
    testR3();
    testR4();
    testR5();
    testR6();
    testR7();
    testR8();
    testR9();
    testR12();
    testReservedFlags();
    testHeaderComposite();
    testStatusTable();
    TEST_MAIN_END();
}
