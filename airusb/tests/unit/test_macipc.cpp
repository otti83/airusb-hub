// P2.8 — the daemon/agent IPC, exercised without hardware.
//
// This codec sits between a root process and an unprivileged one, so it gets the
// same treatment protocol/ gets rather than the treatment "internal IPC" usually
// gets. Two things are tested here that a round-trip test alone would miss:
//
//   1. Hostile input. Every decoder is fed a truncated, oversized, or
//      inconsistent frame and must refuse it rather than trusting a length field
//      over the buffer it actually holds.
//   2. The real socket path. AgentLink is driven over a socketpair by two
//      threads, so send/receive, partial reads, frame reassembly across recv
//      boundaries and peer death are all covered by the same code that runs on
//      the machine with the drive plugged in.

// The file is split by that same distinction. AgentProtocol is the codec and is
// portable, so its tests build and run everywhere — including Windows, which is
// the point of compiling the codec everywhere in the first place. AgentLink is
// the socket underneath it and is POSIX: unix domain sockets, socketpair(2),
// getpeereid(2). CMake already excludes AgentLink.cpp from the Windows build, so
// the tests that drive it are excluded here to match, rather than the whole
// suite being dropped and the codec losing its Windows coverage with it.

#include "../TestHarness.h"
#include "../../platform/macos/AgentProtocol.h"

#if !defined(_WIN32)
  #include "../../platform/macos/AgentLink.h"

  #include <sys/socket.h>
  #include <unistd.h>

  #include <thread>
#endif

using namespace airusb;
using namespace airusb::macos::ipc;

namespace {

std::vector<std::uint8_t> frameBytes(Op op, Status st, std::uint64_t tag,
                                     const std::vector<std::uint8_t>& body)
{
    Frame f;
    f.op     = op;
    f.status = st;
    f.tag    = tag;
    f.body   = body;
    std::vector<std::uint8_t> out;
    encodeFrame(f, out);
    return out;
}

void testFrameCodec()
{
    std::printf("frame codec\n");

    TEST_CASE("a frame round-trips with its status, tag and body intact") {
        const std::vector<std::uint8_t> body = { 1, 2, 3, 4, 5 };
        const auto bytes = frameBytes(Op::BulkIn, Status::XferShort, 0x0123456789ABCDEFull, body);

        Frame got;
        std::size_t used = 0;
        CHECK(decodeFrame(bytes, got, used) == Decode::Ok);
        CHECK_EQ(used, bytes.size());
        CHECK(got.op == Op::BulkIn);
        CHECK(got.status == Status::XferShort);
        CHECK_EQ(got.tag, 0x0123456789ABCDEFull);
        CHECK(got.body == body);
    }

    TEST_CASE("the header is exactly 16 bytes and the body follows it") {
        const auto bytes = frameBytes(Op::Ping, Status::Ok, 1, {});
        CHECK_EQ(bytes.size(), kHeaderSize);
    }

    TEST_CASE("a partial frame asks for more rather than guessing") {
        const auto bytes = frameBytes(Op::BulkOut, Status::Ok, 9, { 7, 7, 7, 7 });
        for (std::size_t n = 0; n < bytes.size(); ++n) {
            Frame got;
            std::size_t used = 0;
            const auto d = decodeFrame(std::span<const std::uint8_t>(bytes).subspan(0, n),
                                       got, used);
            CHECK(d == Decode::NeedMore);
            CHECK_EQ(used, 0u);
        }
    }

    TEST_CASE("two coalesced frames decode one at a time") {
        auto a = frameBytes(Op::Ping, Status::Ok, 1, {});
        const auto b = frameBytes(Op::Close, Status::Ok, 2, { 0xFF });
        a.insert(a.end(), b.begin(), b.end());

        Frame f1;
        std::size_t used1 = 0;
        CHECK(decodeFrame(a, f1, used1) == Decode::Ok);
        CHECK(f1.op == Op::Ping);
        CHECK_EQ(used1, kHeaderSize);

        Frame f2;
        std::size_t used2 = 0;
        CHECK(decodeFrame(std::span<const std::uint8_t>(a).subspan(used1), f2, used2) == Decode::Ok);
        CHECK(f2.op == Op::Close);
        CHECK_EQ(f2.tag, 2u);
    }

    TEST_CASE("a body length past the ceiling is refused before it is buffered") {
        // The whole point: a peer that announces 4 GiB must be rejected on the
        // strength of the announcement, not after allocating for it.
        std::vector<std::uint8_t> bytes(kHeaderSize, 0);
        bytes[0] = 0xFF; bytes[1] = 0xFF; bytes[2] = 0xFF; bytes[3] = 0xFF;
        bytes[4] = static_cast<std::uint8_t>(Op::Ping);
        Frame got;
        std::size_t used = 0;
        CHECK(decodeFrame(bytes, got, used) == Decode::Malformed);
    }

    TEST_CASE("exactly one byte over the ceiling is still refused") {
        std::vector<std::uint8_t> bytes(kHeaderSize, 0);
        const std::uint32_t tooBig = kMaxBodyBytes + 1u;
        bytes[0] = static_cast<std::uint8_t>(tooBig);
        bytes[1] = static_cast<std::uint8_t>(tooBig >> 8);
        bytes[2] = static_cast<std::uint8_t>(tooBig >> 16);
        bytes[3] = static_cast<std::uint8_t>(tooBig >> 24);
        bytes[4] = static_cast<std::uint8_t>(Op::BulkOut);
        Frame got;
        std::size_t used = 0;
        CHECK(decodeFrame(bytes, got, used) == Decode::Malformed);
    }

    TEST_CASE("an unknown opcode is fatal, not skipped") {
        std::vector<std::uint8_t> bytes(kHeaderSize, 0);
        bytes[4] = 0xEE;
        bytes[5] = 0xEE;
        Frame got;
        std::size_t used = 0;
        CHECK(decodeFrame(bytes, got, used) == Decode::Malformed);
        CHECK(!isKnownOp(0xEEEE));
    }

    TEST_CASE("every opcode this build sends is one it also recognises") {
        const Op all[] = { Op::Hello, Op::OpenInterfaces, Op::RebuildPipes,
                           Op::BulkOut, Op::BulkIn, Op::ClearHalt,
                           Op::AbortEndpoint, Op::Close, Op::Ping };
        for (Op op : all) {
            CHECK(isKnownOp(static_cast<std::uint16_t>(op)));
            CHECK(std::strcmp(opName(op), "?") != 0);
        }
    }
}

void testBodyCodecs()
{
    std::printf("body codecs\n");

    TEST_CASE("hello round-trips") {
        HelloBody in;
        in.protocolVersion = kProtocolVersion;
        in.pid  = 4242;
        in.euid = 501;
        std::vector<std::uint8_t> b;
        encodeHello(in, b);
        CHECK_EQ(b.size(), kHelloBodySize);

        HelloBody out;
        CHECK(decodeHello(b, out));
        CHECK_EQ(out.protocolVersion, kProtocolVersion);
        CHECK_EQ(out.pid, 4242u);
        CHECK_EQ(out.euid, 501u);
    }

    TEST_CASE("open round-trips and keeps configValue distinct from an index") {
        OpenBody in;
        in.locationId  = 0x14300000u;
        in.configValue = 1;
        std::vector<std::uint8_t> b;
        encodeOpen(in, b);
        OpenBody out;
        CHECK(decodeOpen(b, out));
        CHECK_EQ(out.locationId, 0x14300000u);
        CHECK_EQ(out.configValue, 1);
    }

    TEST_CASE("a pipe table round-trips with SuperSpeed burst intact") {
        PipeTable in;
        in.generation = 7;
        in.endpoints.push_back({ 0x81, static_cast<std::uint8_t>(XferType::Bulk), 1024, 0, 15, 0, 0 });
        in.endpoints.push_back({ 0x02, static_cast<std::uint8_t>(XferType::Bulk), 1024, 0, 15, 0, 0 });
        std::vector<std::uint8_t> b;
        encodePipeTable(in, b);
        CHECK_EQ(b.size(), kPipeTableHeaderSize + 2 * kEpEntrySize);

        PipeTable out;
        CHECK(decodePipeTable(b, out));
        CHECK_EQ(out.generation, 7u);
        CHECK_EQ(out.endpoints.size(), 2u);
        CHECK_EQ(out.endpoints[0].address, 0x81);
        CHECK_EQ(out.endpoints[0].maxPacketSize, 1024);
        CHECK_EQ(out.endpoints[0].maxBurst, 15);
        CHECK_EQ(out.endpoints[1].address, 0x02);
    }

    TEST_CASE("a pipe table claiming more rows than it carries is refused") {
        std::vector<std::uint8_t> b(kPipeTableHeaderSize, 0);
        b[4] = 8;                          // count = 8, but no rows follow
        PipeTable out;
        CHECK(!decodePipeTable(b, out));
    }

    TEST_CASE("a pipe table over the endpoint ceiling is refused") {
        std::vector<std::uint8_t> b(kPipeTableHeaderSize + 64 * kEpEntrySize, 0);
        b[4] = 64;
        PipeTable out;
        CHECK(!decodePipeTable(b, out));
    }

    TEST_CASE("an out-of-range transfer type is refused") {
        PipeTable in;
        in.generation = 1;
        in.endpoints.push_back({ 0x81, 9, 512, 0, 0, 0, 0 });   // 9 is not an XferType
        std::vector<std::uint8_t> b;
        encodePipeTable(in, b);
        PipeTable out;
        CHECK(!decodePipeTable(b, out));
    }

    TEST_CASE("a transfer request round-trips with its payload") {
        XferReq in;
        in.generation = 3;
        in.timeoutMs  = 30000;
        in.length     = 31;
        in.epAddr     = 0x02;
        const std::vector<std::uint8_t> payload(31, 0xAB);

        std::vector<std::uint8_t> b;
        encodeXferReq(in, payload, b);
        CHECK_EQ(b.size(), kXferReqSize + 31);

        XferReq out;
        std::span<const std::uint8_t> got;
        CHECK(decodeXferReq(b, XferPayload::Present, out, got));
        CHECK_EQ(out.generation, 3u);
        CHECK_EQ(out.timeoutMs, 30000u);
        CHECK_EQ(out.length, 31u);
        CHECK_EQ(out.epAddr, 0x02);
        CHECK_EQ(got.size(), 31u);
        CHECK_EQ(got[0], 0xAB);
    }

    TEST_CASE("a declared length that disagrees with the bytes present is refused") {
        // The CVE-2016-3955 shape: the receiver must not trust a length field
        // over the buffer it actually holds.
        XferReq in;
        in.length = 1024;
        in.epAddr = 0x02;
        std::vector<std::uint8_t> b;
        encodeXferReq(in, std::vector<std::uint8_t>(16, 0), b);   // says 1024, carries 16

        XferReq out;
        std::span<const std::uint8_t> got;
        CHECK(!decodeXferReq(b, XferPayload::Present, out, got));
    }

    TEST_CASE("a zero length with bytes attached is refused") {
        // Found by fuzz_agentipc. The old decoder let this through, so a caller
        // reading the length from the field and the data from the payload would
        // have disagreed with itself about how much data there was.
        XferReq in;
        in.length = 0;
        in.epAddr = 0x02;
        std::vector<std::uint8_t> b;
        encodeXferReq(in, std::vector<std::uint8_t>(28, 0xAB), b);

        XferReq out;
        std::span<const std::uint8_t> got;
        CHECK(!decodeXferReq(b, XferPayload::Present, out, got));
        CHECK(!decodeXferReq(b, XferPayload::None, out, got));
    }

    TEST_CASE("an IN request that carries a payload is refused") {
        // BULK_IN offers a buffer; it never sends one. Bytes attached to an IN
        // request mean the peer is not speaking this protocol.
        XferReq in;
        in.length = 512;
        in.epAddr = 0x81;
        std::vector<std::uint8_t> b;
        encodeXferReq(in, std::vector<std::uint8_t>(512, 0), b);

        XferReq out;
        std::span<const std::uint8_t> got;
        CHECK(!decodeXferReq(b, XferPayload::None, out, got));

        // The same bytes are a perfectly good OUT request.
        CHECK(decodeXferReq(b, XferPayload::Present, out, got));
        CHECK_EQ(got.size(), 512u);
    }

    TEST_CASE("a transfer longer than the ceiling is refused") {
        std::vector<std::uint8_t> b(kXferReqSize, 0);
        const std::uint32_t tooBig = kMaxTransferBytes + 1u;
        b[8]  = static_cast<std::uint8_t>(tooBig);
        b[9]  = static_cast<std::uint8_t>(tooBig >> 8);
        b[10] = static_cast<std::uint8_t>(tooBig >> 16);
        b[11] = static_cast<std::uint8_t>(tooBig >> 24);
        XferReq out;
        std::span<const std::uint8_t> got;
        CHECK(!decodeXferReq(b, XferPayload::None, out, got));
        CHECK(!decodeXferReq(b, XferPayload::Present, out, got));
    }

    TEST_CASE("every decoder refuses a body one byte short") {
        std::vector<std::uint8_t> b;
        HelloBody h; encodeHello({}, b);
        CHECK(!decodeHello(std::span<const std::uint8_t>(b).subspan(0, b.size() - 1), h));

        b.clear(); OpenBody o; encodeOpen({}, b);
        CHECK(!decodeOpen(std::span<const std::uint8_t>(b).subspan(0, b.size() - 1), o));

        b.clear(); EpRef e; encodeEpRef({}, b);
        CHECK(!decodeEpRef(std::span<const std::uint8_t>(b).subspan(0, b.size() - 1), e));

        b.clear(); std::uint32_t n = 0; encodeActualLen(0, b);
        CHECK(!decodeActualLen(std::span<const std::uint8_t>(b).subspan(0, b.size() - 1), n));

        b.clear(); XferReq x; std::span<const std::uint8_t> p;
        encodeXferReq({}, {}, b);
        CHECK(!decodeXferReq(std::span<const std::uint8_t>(b).subspan(0, b.size() - 1),
                             XferPayload::None, x, p));
    }

    TEST_CASE("an actual length beyond the ceiling is refused") {
        std::vector<std::uint8_t> b(kActualLenSize, 0xFF);
        std::uint32_t n = 0;
        CHECK(!decodeActualLen(b, n));
    }
}

// ---------------------------------------------------------------------------
// The real socket path. POSIX only — see the note at the top of the file.
// ---------------------------------------------------------------------------
#if !defined(_WIN32)

/// A minimal agent: echoes BulkIn requests with `length` bytes of a pattern,
/// acknowledges BulkOut with the payload size it actually received, and exits on
/// Close. This is the same loop shape airusb-agent runs.
void fakeAgentLoop(int fd)
{
    AgentLink link(fd);
    for (;;) {
        Frame req;
        if (link.receive(req, 5000) != Status::Ok) return;

        Frame rep;
        rep.op     = req.op;
        rep.tag    = req.tag;
        rep.status = Status::Ok;

        switch (req.op) {
            case Op::Ping:
                break;
            case Op::Hello: {
                HelloBody h;
                if (!decodeHello(req.body, h) || h.protocolVersion != kProtocolVersion) {
                    rep.status = Status::UnsupportedVersion;
                    break;
                }
                HelloBody mine;
                mine.pid  = 1;
                mine.euid = 501;
                encodeHello(mine, rep.body);
                break;
            }
            case Op::BulkOut: {
                XferReq r;
                std::span<const std::uint8_t> payload;
                if (!decodeXferReq(req.body, XferPayload::Present, r, payload)) {
                    rep.status = Status::MalformedFrame; break;
                }
                // Answer with the bytes actually present, never with the field.
                encodeActualLen(static_cast<std::uint32_t>(payload.size()), rep.body);
                break;
            }
            case Op::BulkIn: {
                XferReq r;
                std::span<const std::uint8_t> payload;
                if (!decodeXferReq(req.body, XferPayload::None, r, payload)) {
                    rep.status = Status::MalformedFrame; break;
                }
                rep.body.resize(r.length);
                for (std::size_t i = 0; i < rep.body.size(); ++i)
                    rep.body[i] = static_cast<std::uint8_t>(i & 0xFFu);
                break;
            }
            case Op::Close:
                (void)link.send(rep);
                return;
            default:
                rep.status = Status::UnsupportedMessage;
                break;
        }
        if (link.send(rep) != Status::Ok) return;
    }
}

void testSocketPath()
{
    std::printf("the socket path\n");

    ignoreSigpipe();

    TEST_CASE("request/response over a real socket") {
        int sv[2] = { -1, -1 };
        CHECK_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);

        std::thread agent(fakeAgentLoop, sv[1]);
        AgentLink daemon(sv[0]);

        std::vector<std::uint8_t> body;
        HelloBody h;
        h.pid = 99;
        encodeHello(h, body);

        Frame rep;
        CHECK(daemon.call(Op::Hello, body, 5000, rep) == Status::Ok);
        CHECK(rep.status == Status::Ok);
        HelloBody back;
        CHECK(decodeHello(rep.body, back));
        CHECK_EQ(back.euid, 501u);

        Frame closeRep;
        (void)daemon.call(Op::Close, {}, 5000, closeRep);
        daemon.close();
        agent.join();
    }

    TEST_CASE("a one-megabyte transfer survives recv fragmentation") {
        // The transfer ceiling exactly. This is the case where a frame will not
        // arrive in one recv() and reassembly is actually exercised.
        int sv[2] = { -1, -1 };
        CHECK_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);

        std::thread agent(fakeAgentLoop, sv[1]);
        AgentLink daemon(sv[0]);

        XferReq req;
        req.generation = 1;
        req.epAddr     = 0x81;
        req.length     = kMaxTransferBytes;
        std::vector<std::uint8_t> body;
        encodeXferReq(req, {}, body);

        Frame rep;
        CHECK(daemon.call(Op::BulkIn, body, 10000, rep) == Status::Ok);
        CHECK(rep.status == Status::Ok);
        CHECK_EQ(rep.body.size(), kMaxTransferBytes);
        CHECK_EQ(rep.body[0], 0);
        CHECK_EQ(rep.body[255], 255);
        CHECK_EQ(rep.body[256], 0);

        daemon.close();
        agent.join();
    }

    TEST_CASE("a large OUT payload is reported by what arrived, not what was claimed") {
        int sv[2] = { -1, -1 };
        CHECK_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);

        std::thread agent(fakeAgentLoop, sv[1]);
        AgentLink daemon(sv[0]);

        const std::vector<std::uint8_t> payload(65536, 0x5A);
        XferReq req;
        req.generation = 1;
        req.epAddr     = 0x02;
        req.length     = static_cast<std::uint32_t>(payload.size());
        std::vector<std::uint8_t> body;
        encodeXferReq(req, payload, body);

        Frame rep;
        CHECK(daemon.call(Op::BulkOut, body, 10000, rep) == Status::Ok);
        std::uint32_t actual = 0;
        CHECK(decodeActualLen(rep.body, actual));
        CHECK_EQ(actual, 65536u);

        daemon.close();
        agent.join();
    }

    TEST_CASE("a dead peer is TransportLost, not a hang and not a crash") {
        int sv[2] = { -1, -1 };
        CHECK_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
        ::close(sv[1]);                       // the agent dies before answering

        AgentLink daemon(sv[0]);
        Frame rep;
        const Status s = daemon.call(Op::Ping, {}, 2000, rep);
        CHECK(s == Status::TransportLost);
    }

    TEST_CASE("a silent peer times out rather than blocking forever") {
        int sv[2] = { -1, -1 };
        CHECK_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);

        AgentLink daemon(sv[0]);
        Frame rep;
        const Status s = daemon.call(Op::Ping, {}, 150, rep);
        CHECK(s == Status::XferTimeout);
        ::close(sv[1]);
    }

    TEST_CASE("garbage on the wire is fatal rather than resynchronised") {
        int sv[2] = { -1, -1 };
        CHECK_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);

        // A header claiming an impossible body length.
        std::uint8_t junk[kHeaderSize] = {};
        junk[0] = junk[1] = junk[2] = junk[3] = 0xFF;
        CHECK(::send(sv[1], junk, sizeof junk, 0) == static_cast<ssize_t>(sizeof junk));

        AgentLink daemon(sv[0]);
        Frame f;
        CHECK(daemon.receive(f, 2000) == Status::MalformedFrame);

        ::close(sv[1]);
    }
}

void testUnixSocketLifecycle()
{
    std::printf("unix socket lifecycle\n");

    TEST_CASE("a path too long for sun_path is refused, not truncated") {
        Status st = Status::Ok;
        const std::string tooLong(200, 'x');
        const int fd = listenOnUnixSocket("/tmp/" + tooLong, 0600, st);
        CHECK_EQ(fd, -1);
        CHECK(st == Status::BadArgument);
    }

    TEST_CASE("connect gives up rather than spinning when nothing listens") {
        Status st = Status::Ok;
        const int fd = connectUnixSocket("/tmp/airusb-test-nonexistent-socket", 200, st);
        CHECK_EQ(fd, -1);
        CHECK(st == Status::XferTimeout);
    }
}

#endif // !_WIN32

} // namespace

int main()
{
    std::printf("test_macipc\n");
    testFrameCodec();
    testBodyCodecs();
#if !defined(_WIN32)
    testSocketPath();
    testUnixSocketLifecycle();
#else
    std::printf("socket path: skipped — AgentLink is POSIX and is not built here\n");
#endif
    TEST_MAIN_END();
}
