// P2.0 — codec round-trip and golden vectors.
//
// The golden vectors matter more than the round-trips: a round-trip test passes
// even if encode and decode share the same wrong offset. A byte-exact vector is
// what actually pins the wire format, so a macOS build and a future Windows build
// cannot silently disagree.

#include "../TestHarness.h"
#include "../../protocol/Codec.h"
#include "../../protocol/Wire.h"

using namespace airusb;
using namespace airusb::protocol;

namespace {

std::vector<std::uint8_t> fromHex(const char* h)
{
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::vector<std::uint8_t> v;
    for (const char* p = h; *p && *(p + 1); p += 2)
        v.push_back(static_cast<std::uint8_t>((nib(p[0]) << 4) | nib(p[1])));
    return v;
}

void testPrimitives()
{
    TEST_CASE("little-endian primitive accessors") {
        std::uint8_t buf[8] = {0x78, 0x56, 0x34, 0x12, 0xF0, 0xDE, 0xBC, 0x9A};
        CHECK_EQ(rd_u8(buf), 0x78u);
        CHECK_EQ(rd_u16(buf), 0x5678u);
        CHECK_EQ(rd_u32(buf), 0x12345678u);
        CHECK_EQ(rd_u64(buf), 0x9ABCDEF012345678ull);

        std::uint8_t out[8] = {};
        wr_u64(out, 0x9ABCDEF012345678ull);
        CHECK(std::memcmp(buf, out, 8) == 0);
    }

    TEST_CASE("unaligned access is safe (coalesced messages)") {
        // A coalesced record puts message starts at arbitrary offsets. Reading a
        // u64 from offset 1 must work; this is why there is no struct overlay.
        std::uint8_t buf[16] = {0xFF, 0x78, 0x56, 0x34, 0x12, 0xF0, 0xDE, 0xBC, 0x9A};
        CHECK_EQ(rd_u64(buf + 1), 0x9ABCDEF012345678ull);
        CHECK_EQ(rd_u32(buf + 1), 0x12345678u);
    }
}

void testHeaderGolden()
{
    TEST_CASE("header golden vector is byte-exact") {
        Header h;
        h.type        = static_cast<std::uint8_t>(wire::Type::Submit);   // 0x40
        h.flags       = wire::kFlagSegFirst;                            // 0x02
        h.channel     = wire::channelFor(1, 0x81);                      // 0x0181
        h.bodyLen     = wire::kBodySubmit;                              // 40 = 0x28
        h.attachId    = 0x11223344;
        h.segOffset   = 0;
        h.requestId   = 0x0102030405060708ull;
        h.status      = 0;
        h.deviceEpoch = 7;
        h.totalLen    = 0;

        std::vector<std::uint8_t> enc;
        encodeHeader(h, enc);
        CHECK_EQ(enc.size(), wire::kHeaderSize);

        const auto want = fromHex(
            "40"        // type
            "02"        // flags
            "8101"      // channel 0x0181 LE
            "28000000"  // body_len 40
            "44332211"  // attach_id 0x11223344 LE
            "00000000"  // seg_offset
            "0807060504030201"  // request_id LE
            "0000"      // status
            "0700"      // device_epoch 7
            "00000000"  // total_len
        );
        CHECK_EQ(enc.size(), want.size());
        CHECK(enc == want);
        if (enc != want) {
            std::printf("\n      got  %s\n      want %s\n",
                        test::hex(enc).c_str(), test::hex(want).c_str());
        }

        Header back;
        CHECK(decodeHeader(enc, back));
        CHECK_EQ(back.type, h.type);
        CHECK_EQ(back.channel, h.channel);
        CHECK_EQ(back.bodyLen, h.bodyLen);
        CHECK_EQ(back.attachId, h.attachId);
        CHECK_EQ(back.requestId, h.requestId);
        CHECK_EQ(back.deviceEpoch, h.deviceEpoch);
    }

    TEST_CASE("header decode rejects short input") {
        std::vector<std::uint8_t> shortBuf(wire::kHeaderSize - 1, 0);
        Header h;
        CHECK(!decodeHeader(shortBuf, h));
    }
}

void testSubmitComplete()
{
    TEST_CASE("SUBMIT round-trip preserves every field") {
        SubmitBody b;
        b.epAddr      = 0x81;
        b.xferType    = static_cast<std::uint8_t>(wire::XferType::Bulk);
        b.dir         = static_cast<std::uint8_t>(wire::Dir::In);
        b.xflags      = wire::kXfShortNotOk;
        b.bufferLen   = 0x00010000;
        b.timeoutMs   = 5000;
        b.isoPktCount = 0;
        b.interval    = 0;
        b.streamId    = 0;
        for (int i = 0; i < 8; ++i) b.setup[i] = static_cast<std::uint8_t>(0xA0 + i);
        b.submitTsNs  = 0xDEADBEEFCAFEBABEull;

        std::vector<std::uint8_t> enc;
        encodeSubmit(b, enc);
        CHECK_EQ(enc.size(), wire::kBodySubmit);

        SubmitBody back;
        CHECK(decodeSubmit(enc, back));
        CHECK_EQ(back.epAddr, b.epAddr);
        CHECK_EQ(back.xferType, b.xferType);
        CHECK_EQ(back.dir, b.dir);
        CHECK_EQ(back.xflags, b.xflags);
        CHECK_EQ(back.bufferLen, b.bufferLen);
        CHECK_EQ(back.timeoutMs, b.timeoutMs);
        CHECK_EQ(back.submitTsNs, b.submitTsNs);
        CHECK(std::memcmp(back.setup, b.setup, 8) == 0);
    }

    TEST_CASE("SETUP travels verbatim in USB wire order") {
        // GET_DESCRIPTOR(DEVICE), wLength 18 — the exact request the importer's
        // kernel issues, and the one verified against real hardware in
        // docs/P1_CAPTURE_VERIFICATION.md.
        SubmitBody b;
        b.epAddr = 0x00;
        b.dir    = static_cast<std::uint8_t>(wire::Dir::In);
        const std::uint8_t setup[8] = {0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x12, 0x00};
        std::memcpy(b.setup, setup, 8);

        std::vector<std::uint8_t> enc;
        encodeSubmit(b, enc);
        CHECK(std::memcmp(enc.data() + wire::kSubOffSetup, setup, 8) == 0);
    }

    TEST_CASE("COMPLETE is self-describing without SUBMIT state") {
        // The whole point: ep_addr, xfer_type and dir are echoed, so payload length
        // is computable from the COMPLETE alone. USB/IP zeroes these in RET_SUBMIT.
        CompleteBody b;
        b.epAddr       = 0x81;
        b.xferType     = static_cast<std::uint8_t>(wire::XferType::Bulk);
        b.dir          = static_cast<std::uint8_t>(wire::Dir::In);
        b.cflags       = wire::kCfShort;
        b.requestedLen = 512;
        b.actualLen    = 31;
        b.payloadLen   = 31;
        b.submitTsNs   = 0x1122334455667788ull;

        std::vector<std::uint8_t> enc;
        encodeComplete(b, enc);

        CompleteBody back;
        CHECK(decodeComplete(enc, back));
        CHECK_EQ(back.epAddr, 0x81u);
        CHECK_EQ(back.dir, static_cast<std::uint8_t>(wire::Dir::In));
        CHECK_EQ(back.actualLen, 31u);
        CHECK_EQ(back.payloadLen, 31u);
        CHECK(back.isShort());
        CHECK_EQ(back.submitTsNs, b.submitTsNs);
    }
}

void testHello()
{
    TEST_CASE("HELLO body is 56 bytes and round-trips") {
        // The plan stated B=48 while listing 56 bytes of fields. Resolved to 56;
        // this test is what keeps the resolution from silently regressing.
        CHECK_EQ(wire::kBodyHello, std::size_t{56});

        HelloBody b;
        b.protoMin      = 1;
        b.protoMax      = 1;
        b.caps          = wire::kCapSegmentation | wire::kCapExport | wire::kCapImport;
        b.maxTransfer   = wire::kTransferBytesDefault;
        b.maxRecord     = wire::kRecordBytesDefault;
        b.maxSegment    = wire::kSegmentBytesDefault;
        b.maxIsoPackets = 0;
        b.maxChannels   = 256;
        b.maxLinks      = 1;
        b.keepaliveMs   = 1000;
        b.platformId    = wire::kPlatformMacos;
        b.roleBits      = wire::kRoleCanExport | wire::kRoleCanImport;
        for (int i = 0; i < 16; ++i) b.sessionId[i] = static_cast<std::uint8_t>(i);

        std::vector<std::uint8_t> enc;
        encodeHello(b, enc);
        CHECK_EQ(enc.size(), wire::kBodyHello);

        HelloBody back;
        CHECK(decodeHello(enc, back));
        CHECK_EQ(back.caps, b.caps);
        CHECK_EQ(back.maxSegment, b.maxSegment);
        CHECK_EQ(back.platformId, b.platformId);
        CHECK(std::memcmp(back.sessionId, b.sessionId, 16) == 0);
    }
}

void testPreamble()
{
    TEST_CASE("preamble golden vector") {
        Preamble p;
        std::vector<std::uint8_t> enc;
        encodePreamble(p, enc);
        CHECK(enc == fromHex("4155534201000100"));   // "AUSB" 01 00 0100

        Preamble back;
        CHECK(decodePreamble(enc, back));
        CHECK_EQ(back.wireMajor, wire::kWireMajor);
        CHECK_EQ(back.flags, wire::kSecNoiseXX);
    }

    TEST_CASE("preamble rejects wrong magic") {
        auto bad = fromHex("4155534301000100");   // "AUSC"
        Preamble p;
        CHECK(!decodePreamble(bad, p));
    }
}

void testTlv()
{
    TEST_CASE("TLV append and walk") {
        std::vector<std::uint8_t> buf;
        const std::uint8_t name[] = {'M', 'a', 'c'};
        appendTlv(wire::Tlv::PeerName, name, buf);
        const std::uint8_t ids[] = {0x8f, 0x05, 0x87, 0x63};
        appendTlv(wire::Tlv::DeviceIds, ids, buf);

        int seen = 0;
        bool ok = forEachTlv(buf, [&](const TlvView& v) {
            ++seen;
            if (seen == 1) {
                CHECK_EQ(v.type, static_cast<std::uint16_t>(wire::Tlv::PeerName));
                CHECK_EQ(v.value.size(), std::size_t{3});
            } else {
                CHECK_EQ(v.type, static_cast<std::uint16_t>(wire::Tlv::DeviceIds));
                CHECK_EQ(v.value.size(), std::size_t{4});
            }
            return true;
        });
        CHECK(ok);
        CHECK_EQ(seen, 2);
    }

    TEST_CASE("TLV walk rejects a truncated value") {
        // type=0x0001, len=0x0010, but only 2 value bytes present.
        auto bad = fromHex("010010000102");
        bool ok = forEachTlv(bad, [](const TlvView&) { return true; });
        CHECK(!ok);
    }

    TEST_CASE("TLV walk rejects a truncated header") {
        auto bad = fromHex("0100");
        bool ok = forEachTlv(bad, [](const TlvView&) { return true; });
        CHECK(!ok);
    }

    TEST_CASE("empty TLV run is valid") {
        std::vector<std::uint8_t> empty;
        bool ok = forEachTlv(empty, [](const TlvView&) { return true; });
        CHECK(ok);
    }
}

void testIsoDesc()
{
    TEST_CASE("iso descriptor round-trip and bounds") {
        IsoDesc d;
        d.offset = 0; d.length = 192; d.actualLength = 0; d.status = 0;
        std::vector<std::uint8_t> enc;
        encodeIsoDesc(d, enc);
        CHECK_EQ(enc.size(), wire::kIsoDescSize);

        IsoDesc back;
        CHECK(decodeIsoDesc(enc, 0, back));
        CHECK_EQ(back.length, 192u);

        // Index past the end must fail rather than read out of bounds.
        CHECK(!decodeIsoDesc(enc, 1, back));
        // A huge index must not overflow into a passing bounds check.
        CHECK(!decodeIsoDesc(enc, 0x40000000u, back));
    }
}

void testFixedBodySizes()
{
    TEST_CASE("fixed body sizes and unknown-type handling") {
        bool known = false;
        CHECK_EQ(wire::fixedBodySize(static_cast<std::uint8_t>(wire::Type::Submit), &known),
                 wire::kBodySubmit);
        CHECK(known);

        CHECK_EQ(wire::fixedBodySize(static_cast<std::uint8_t>(wire::Type::Data), &known),
                 std::size_t{0});
        CHECK(known);   // DATA is known and genuinely has B = 0

        wire::fixedBodySize(0xEE, &known);
        CHECK(!known);  // truly unknown

        // Phase 4 reservations are deliberately "unknown" to a v1 build.
        wire::fixedBodySize(static_cast<std::uint8_t>(wire::Type::Resume), &known);
        CHECK(!known);
    }
}

} // namespace

int main()
{
    std::printf("test_codec\n");
    testPrimitives();
    testHeaderGolden();
    testSubmitComplete();
    testHello();
    testPreamble();
    testTlv();
    testIsoDesc();
    testFixedBodySizes();
    TEST_MAIN_END();
}
