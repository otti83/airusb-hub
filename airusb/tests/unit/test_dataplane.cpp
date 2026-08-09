// The async importer data plane: the thing that makes the Linux vhci bridge
// possible without deadlocking the kernel (LINUX_IMPORTER_PLAN §4.2).
//
// The properties under test are liveness, not speed:
//   * submit() never blocks, even when the socket cannot take the bytes (R-B):
//     the record is buffered and flushed later.
//   * pump() never blocks: it consumes what is there and returns.
//   * every submit yields EXACTLY ONE terminal outcome (invariant I1) — via a
//     normal COMPLETE, a deadline (R-C), a cancel, or teardown.
//   * a completion for a cancelled/timed-out request is dropped, never applied to
//     the wrong transfer.
//
// Faithfulness: the "peer" replies with the SAME protocol::emitTransfer the real
// exporter uses, and one test drives the REAL ExporterSession end to end.

#include "../TestHarness.h"
#include "../fakes/ScriptedDevice.h"
#include "../../protocol/Codec.h"
#include "../../protocol/Segmentation.h"
#include "../../session/ExporterSession.h"
#include "../../session/ImporterDataPlane.h"
#include "../../transport/RecordLayer.h"
#include "../../transport/TcpTransport.h"

#include <algorithm>
#include <cstring>
#include <memory>
#include <span>
#include <vector>

using namespace airusb;
using namespace airusb::crypto;
using namespace airusb::protocol;
using namespace airusb::session;
using namespace airusb::transport;
using namespace airusb::fakes;

namespace {

constexpr std::uint8_t  kEpIn    = 0x81;
constexpr std::uint8_t  kEpOut   = 0x02;
constexpr std::uint8_t  kSlot    = 1;
constexpr std::uint32_t kAttach  = 5;
constexpr std::uint8_t  kBulk    = static_cast<std::uint8_t>(wire::XferType::Bulk);
constexpr std::uint8_t  kIn      = static_cast<std::uint8_t>(wire::Dir::In);
constexpr std::uint8_t  kOut     = static_cast<std::uint8_t>(wire::Dir::Out);
constexpr std::uint32_t kBig     = 122'880;

std::vector<std::uint8_t> pattern(std::size_t n, std::uint8_t salt = 0)
{
    std::vector<std::uint8_t> v(n);
    for (std::size_t i = 0; i < n; ++i)
        v[i] = static_cast<std::uint8_t>((i * 31u + salt * 7u + (i >> 8)) & 0xFF);
    return v;
}

/// Collects completions, copying the borrowed payload out of each (the span is
/// only valid for the callback).
struct Collector {
    std::vector<DataCompletion>            comps;
    std::vector<std::vector<std::uint8_t>> data;

    void operator()(const DataCompletion& c)
    {
        comps.push_back(c);
        data.emplace_back(c.data.begin(), c.data.end());
    }
    std::size_t count() const { return comps.size(); }
};

// ---------------------------------------------------------------------------
// Section 1 — bare pipe, a hand-driven peer using the real emit/reassemble.
// ---------------------------------------------------------------------------

struct Pair {
    MemoryPipe  pipe;
    RecordLayer planeLink;   // endpointA — the data plane's link
    RecordLayer peerLink;    // endpointB — the "exporter"
    ManualClock clock{1000};

    explicit Pair(std::uint32_t recSize)
        : planeLink(pipe.endpointA(), std::make_unique<NullCipher>())
        , peerLink(pipe.endpointB(), std::make_unique<NullCipher>())
    {
        planeLink.setHandshakeComplete(recSize);
        peerLink.setHandshakeComplete(recSize);
    }
};

/// Sends a COMPLETE from the peer, framed exactly as the exporter would.
void peerComplete(RecordLayer& peer, std::uint16_t channel, std::uint64_t rid,
                  std::uint8_t epAddr, std::uint8_t dir, std::uint32_t requestedLen,
                  std::span<const std::uint8_t> payload, Status status = Status::Ok)
{
    CompleteBody cb;
    cb.epAddr       = epAddr;
    cb.xferType     = kBulk;
    cb.dir          = dir;
    cb.requestedLen = requestedLen;
    if (dir == kIn) {
        cb.actualLen  = static_cast<std::uint32_t>(payload.size());
        cb.payloadLen = static_cast<std::uint32_t>(payload.size());
    } else {
        cb.actualLen  = requestedLen;
        cb.payloadLen = 0;
    }
    if (status == Status::Ok && cb.actualLen < cb.requestedLen) cb.cflags |= wire::kCfShort;

    std::vector<std::uint8_t> cbody;
    encodeComplete(cb, cbody);

    Header base;
    base.type      = static_cast<std::uint8_t>(wire::Type::Complete);
    base.channel   = channel;
    base.attachId  = kAttach;
    base.requestId = rid;
    base.status    = static_cast<std::uint16_t>(status);

    const std::uint32_t maxSeg = peer.maxPlaintextBytes()
                                 - static_cast<std::uint32_t>(wire::kHeaderSize)
                                 - static_cast<std::uint32_t>(wire::kBodyComplete);
    (void)emitTransfer(base, cbody, (dir == kIn) ? payload : std::span<const std::uint8_t>{},
                       maxSeg, [&](std::span<const std::uint8_t> rec) { return peer.sendRecord(rec); });
    (void)peer.flush();
}

/// Reassembles the SUBMIT the plane put on the wire; returns its decoded body and
/// the OUT data. Returns the number of records it spanned.
int peerReadSubmit(RecordLayer& peer, SubmitBody& sbOut, std::vector<std::uint8_t>& dataOut)
{
    Reassembler ra;
    Status e = Status::Ok;
    Reassembler::Outcome o = Reassembler::Outcome::NeedMore;
    Header last;
    int records = 0;
    bool saw = false;
    std::vector<std::uint8_t> rec;
    while (peer.receiveRecord(rec) == Status::Ok && !rec.empty()) {
        ++records;
        Header h;
        if (!decodeHeader(rec, h)) break;
        if (h.type == static_cast<std::uint8_t>(wire::Type::Submit)) {
            saw = true;
            decodeSubmit(std::span<const std::uint8_t>(rec).subspan(wire::kHeaderSize), sbOut);
            o = ra.accept(h, std::span<const std::uint8_t>(rec).subspan(wire::kHeaderSize + wire::kBodySubmit), e);
            last = h;
        } else if (h.type == static_cast<std::uint8_t>(wire::Type::Data)) {
            o = ra.accept(h, std::span<const std::uint8_t>(rec).subspan(wire::kHeaderSize), e);
            last = h;
        }
        if (o == Reassembler::Outcome::Complete) break;
    }
    dataOut.clear();
    if (saw && o == Reassembler::Outcome::Complete) dataOut = ra.take(last);
    return saw ? records : 0;
}

ImporterDataPlane::Config cfg1()
{
    ImporterDataPlane::Config c;
    c.attachId   = kAttach;
    c.attachSlot = kSlot;
    c.maxInFlight = 1;
    return c;
}

void testRoundTrip()
{
    std::printf("round trips through the async plane (peer = real emitTransfer)\n");

    for (std::uint32_t recSize : { std::uint32_t{4096}, wire::kRecordBytesCeiling }) {
        TEST_CASE("a large OUT is emitted, reassembled by the peer, and completed once") {
            Pair p(recSize);
            ImporterDataPlane plane(&p.planeLink, &p.clock, cfg1());

            const auto out = pattern(kBig, 0x11);
            std::uint16_t ch = 0; std::uint64_t rid = 0;
            CHECK(plane.submit(kEpOut, kBulk, kOut, kBig, nullptr, out, 45000, &ch, &rid) == Status::Ok);
            CHECK_EQ(plane.outstanding(), std::size_t{1});

            // The peer sees exactly the payload, as one logical transfer.
            SubmitBody sb; std::vector<std::uint8_t> got;
            const int recs = peerReadSubmit(p.peerLink, sb, got);
            CHECK(recs > 0);
            CHECK_EQ(sb.epAddr, kEpOut);
            CHECK_EQ(sb.bufferLen, kBig);
            CHECK(got == out);

            // Peer completes it; the plane fires exactly one completion.
            peerComplete(p.peerLink, ch, rid, kEpOut, kOut, kBig, {});
            Collector col;
            CHECK(plane.pump(std::ref(col)) == Status::Ok);
            CHECK_EQ(col.count(), std::size_t{1});
            CHECK(col.comps[0].status == Status::Ok);
            CHECK_EQ(col.comps[0].actualLen, kBig);
            CHECK_EQ(plane.outstanding(), std::size_t{0});
        }

        TEST_CASE("a large IN reassembles across Data segments and completes once") {
            Pair p(recSize);
            ImporterDataPlane plane(&p.planeLink, &p.clock, cfg1());

            std::uint16_t ch = 0; std::uint64_t rid = 0;
            CHECK(plane.submit(kEpIn, kBulk, kIn, kBig, nullptr, {}, 45000, &ch, &rid) == Status::Ok);

            SubmitBody sb; std::vector<std::uint8_t> ignore;
            CHECK(peerReadSubmit(p.peerLink, sb, ignore) > 0);      // drain the SUBMIT

            const auto payload = pattern(kBig, 0x5A);
            peerComplete(p.peerLink, ch, rid, kEpIn, kIn, kBig, payload);

            Collector col;
            CHECK(plane.pump(std::ref(col)) == Status::Ok);
            CHECK_EQ(col.count(), std::size_t{1});
            CHECK_EQ(col.comps[0].actualLen, kBig);
            CHECK(col.data[0] == payload);
            CHECK_EQ(plane.outstanding(), std::size_t{0});
        }
    }
}

void testAdmissionAndCancel()
{
    std::printf("admission depth, cancel, and completion dropping\n");

    TEST_CASE("depth 1: a second submit is refused Busy until the first completes") {
        Pair p(16384);
        ImporterDataPlane plane(&p.planeLink, &p.clock, cfg1());

        std::uint16_t ch = 0; std::uint64_t rid = 0;
        CHECK(plane.submit(kEpIn, kBulk, kIn, 512, nullptr, {}, 45000, &ch, &rid) == Status::Ok);
        std::uint16_t ch2 = 0; std::uint64_t rid2 = 0;
        CHECK(plane.submit(kEpIn, kBulk, kIn, 512, nullptr, {}, 45000, &ch2, &rid2) == Status::Busy);

        SubmitBody sb; std::vector<std::uint8_t> ig;
        CHECK(peerReadSubmit(p.peerLink, sb, ig) > 0);
        peerComplete(p.peerLink, ch, rid, kEpIn, kIn, 512, pattern(512, 1));
        Collector col;
        CHECK(plane.pump(std::ref(col)) == Status::Ok);
        CHECK_EQ(col.count(), std::size_t{1});

        // Now there is room again.
        CHECK(plane.submit(kEpIn, kBulk, kIn, 512, nullptr, {}, 45000, &ch2, &rid2) == Status::Ok);
    }

    TEST_CASE("a cancelled transfer drops its later completion, firing nothing") {
        Pair p(16384);
        ImporterDataPlane plane(&p.planeLink, &p.clock, cfg1());

        std::uint16_t ch = 0; std::uint64_t rid = 0;
        CHECK(plane.submit(kEpIn, kBulk, kIn, 512, nullptr, {}, 45000, &ch, &rid) == Status::Ok);
        SubmitBody sb; std::vector<std::uint8_t> ig;
        CHECK(peerReadSubmit(p.peerLink, sb, ig) > 0);

        CHECK(plane.cancel(ch, rid));                 // the kernel unlinked it
        CHECK_EQ(plane.outstanding(), std::size_t{0});

        // A completion still arrives from the exporter (it was mid-flight). It must
        // be dropped, not applied to anything.
        peerComplete(p.peerLink, ch, rid, kEpIn, kIn, 512, pattern(512, 2));
        Collector col;
        CHECK(plane.pump(std::ref(col)) == Status::Ok);
        CHECK_EQ(col.count(), std::size_t{0});        // I1 already satisfied by the RET_UNLINK
    }

    TEST_CASE("a completion that fails the copy-site check stays in I1 tracking") {
        // A hostile exporter sends a COMPLETE that is internally consistent (passes
        // validateComplete) but claims more than we OFFERED. It must be rejected
        // WITHOUT being pulled out of the request table first, so teardown can still
        // retire it. Taking it before the check would evaporate it from I1.
        Pair p(16384);
        ImporterDataPlane plane(&p.planeLink, &p.clock, cfg1());
        std::uint16_t ch = 0; std::uint64_t rid = 0;
        CHECK(plane.submit(kEpIn, kBulk, kIn, 512, nullptr, {}, 45000, &ch, &rid) == Status::Ok);
        SubmitBody sb; std::vector<std::uint8_t> ig;
        CHECK(peerReadSubmit(p.peerLink, sb, ig) > 0);

        // requestedLen/actualLen both 2048 > the 512 we offered.
        peerComplete(p.peerLink, ch, rid, kEpIn, kIn, 2048, pattern(2048, 4));
        Collector col;
        CHECK(plane.pump(std::ref(col)) == Status::MalformedFrame);   // fatal, refused
        CHECK_EQ(col.count(), std::size_t{0});                        // nothing delivered
        CHECK_EQ(plane.outstanding(), std::size_t{1});                // STILL tracked

        Collector td;
        plane.completeAll(Status::DeviceGone, std::ref(td));
        CHECK_EQ(td.count(), std::size_t{1});                         // teardown can retire it
        CHECK(td.comps[0].status == Status::DeviceGone);
    }
}

void testDeadline()
{
    std::printf("R-C: a silent transfer times out locally, exactly once\n");

    TEST_CASE("a transfer past its deadline is completed with XferTimeout") {
        Pair p(16384);
        ImporterDataPlane plane(&p.planeLink, &p.clock, cfg1());

        std::uint16_t ch = 0; std::uint64_t rid = 0;
        CHECK(plane.submit(kEpIn, kBulk, kIn, 512, nullptr, {}, 3500, &ch, &rid) == Status::Ok);

        // Before the deadline: nothing fires.
        Collector before;
        plane.sweepDeadlines(std::ref(before));
        CHECK_EQ(before.count(), std::size_t{0});

        p.clock.advanceMs(4000);                      // past the 3500 ms deadline
        Collector col;
        plane.sweepDeadlines(std::ref(col));
        CHECK_EQ(col.count(), std::size_t{1});
        CHECK(col.comps[0].status == Status::XferTimeout);
        CHECK_EQ(plane.outstanding(), std::size_t{0});

        // A late completion for the timed-out transfer is now unknown: dropped.
        SubmitBody sb; std::vector<std::uint8_t> ig;
        (void)peerReadSubmit(p.peerLink, sb, ig);
        peerComplete(p.peerLink, ch, rid, kEpIn, kIn, 512, pattern(512, 3));
        Collector late;
        CHECK(plane.pump(std::ref(late)) == Status::Ok);
        CHECK_EQ(late.count(), std::size_t{0});
    }

    TEST_CASE("timeoutMs == 0 means no deadline (an interrupt IN idles forever)") {
        Pair p(16384);
        ImporterDataPlane plane(&p.planeLink, &p.clock, cfg1());
        std::uint16_t ch = 0; std::uint64_t rid = 0;
        CHECK(plane.submit(0x83, static_cast<std::uint8_t>(wire::XferType::Interrupt), kIn,
                           8, nullptr, {}, 0, &ch, &rid) == Status::Ok);
        p.clock.advanceMs(10'000'000);                // ~2.7 hours
        Collector col;
        plane.sweepDeadlines(std::ref(col));
        CHECK_EQ(col.count(), std::size_t{0});        // never expires
        CHECK_EQ(plane.outstanding(), std::size_t{1});
    }
}

void testTeardown()
{
    std::printf("teardown completes every outstanding transfer (I1 under link death)\n");

    TEST_CASE("completeAll drains outstanding transfers with DeviceGone") {
        Pair p(16384);
        ImporterDataPlane plane(&p.planeLink, &p.clock, cfg1());
        std::uint16_t ch = 0; std::uint64_t rid = 0;
        CHECK(plane.submit(kEpIn, kBulk, kIn, 512, nullptr, {}, 45000, &ch, &rid) == Status::Ok);

        Collector col;
        plane.completeAll(Status::DeviceGone, std::ref(col));
        CHECK_EQ(col.count(), std::size_t{1});
        CHECK(col.comps[0].status == Status::DeviceGone);
        CHECK_EQ(plane.outstanding(), std::size_t{0});
    }
}

// ---------------------------------------------------------------------------
// Section 2 — R-B: submit never blocks on a socket that cannot take the bytes.
// ---------------------------------------------------------------------------

/// A stream whose write accepts at most `_cap` bytes total before reporting
/// would-block ({Ok, 0}), exactly as a socket does when its send window is full.
/// Raising the cap models the window draining.
class StallStream final : public IByteStream {
public:
    IoResult write(std::span<const std::uint8_t> src) override
    {
        const std::size_t room = (_cap == 0) ? src.size()
                               : (_written < _cap ? _cap - _written : 0);
        const std::size_t n = std::min(room, src.size());
        _out.insert(_out.end(), src.begin(), src.begin() + static_cast<std::ptrdiff_t>(n));
        _written += n;
        return { Status::Ok, n };
    }
    IoResult read(std::span<std::uint8_t> dst) override
    {
        const std::size_t n = std::min(dst.size(), _in.size() - _readPos);
        if (n) std::memcpy(dst.data(), _in.data() + _readPos, n);
        _readPos += n;
        return { Status::Ok, n };
    }
    void close() override { _open = false; }
    bool isOpen() const noexcept override { return _open; }

    void setCap(std::size_t c) noexcept { _cap = c; }        // 0 == unbounded
    std::size_t written() const noexcept { return _written; }

private:
    std::vector<std::uint8_t> _out;
    std::vector<std::uint8_t> _in;
    std::size_t _readPos = 0;
    std::size_t _written = 0;
    std::size_t _cap = 0;
    bool        _open = true;
};

void testNonBlocking()
{
    std::printf("R-B: submit buffers instead of blocking when the socket is full\n");

    TEST_CASE("a submit onto a stalled socket returns immediately, buffered") {
        auto raw = std::make_unique<StallStream>();
        StallStream* stall = raw.get();
        stall->setCap(64);                       // the socket takes almost nothing

        RecordLayer link(std::move(raw), std::make_unique<NullCipher>());
        link.setHandshakeComplete(wire::kRecordBytesDefault);

        ManualClock clock{1000};
        ImporterDataPlane plane(&link, &clock, cfg1());

        // A 4 KiB OUT cannot fit through a 64-byte window. submit MUST NOT block.
        const auto out = pattern(4096, 9);
        std::uint16_t ch = 0; std::uint64_t rid = 0;
        CHECK(plane.submit(kEpOut, kBulk, kOut, 4096, nullptr, out, 45000, &ch, &rid) == Status::Ok);
        CHECK(plane.bytesBuffered() > 0);        // the rest is buffered, not blocked on
        CHECK_EQ(plane.outstanding(), std::size_t{1});

        // Drain the "window": now the buffered bytes flush, still without blocking.
        stall->setCap(0);
        CHECK(plane.pump([](const DataCompletion&) {}) == Status::Ok);
        CHECK_EQ(plane.bytesBuffered(), std::size_t{0});
        CHECK(stall->written() >= wire::kHeaderSize + wire::kBodySubmit + 4096);
    }
}

// ---------------------------------------------------------------------------
// Section 3 — the async plane against the REAL ExporterSession, end to end.
// ---------------------------------------------------------------------------

DeviceUid uidOf(std::uint8_t seed)
{
    DeviceUid u{};
    for (std::size_t i = 0; i < u.size(); ++i) u[i] = static_cast<std::uint8_t>(seed + i);
    return u;
}

class EchoDevice final : public IUsbDevicePort {
public:
    explicit EchoDevice(DeviceManifest m) : _m(std::move(m)) {}
    const DeviceManifest& manifest() const noexcept override { return _m; }
    Status controlTransfer(const SetupPacket&, std::span<const std::uint8_t>,
                           std::vector<std::uint8_t>& in) override { in.clear(); return Status::Ok; }
    Status bulkOut(std::uint8_t, std::span<const std::uint8_t> d, std::uint32_t* a) override
    { ++outCalls; lastOut.assign(d.begin(), d.end()); if (a) *a = static_cast<std::uint32_t>(d.size()); return Status::Ok; }
    Status bulkIn(std::uint8_t, std::uint32_t maxLen, std::vector<std::uint8_t>& out) override
    { ++inCalls; out = pattern(maxLen, 0x5A); return Status::Ok; }
    Status clearHalt(std::uint8_t) override { return Status::Ok; }
    int outCalls = 0, inCalls = 0;
    std::vector<std::uint8_t> lastOut;
private:
    DeviceManifest _m;
};

class EchoSource final : public IDeviceSource {
public:
    explicit EchoSource(EchoDevice* d) : _dev(d) {}
    std::vector<DeviceRecord> list() override
    {
        DeviceRecord r; r.uid = uidOf(1); r.vendorId = 0x058f; r.productId = 0x6387;
        r.speed = static_cast<std::uint8_t>(Speed::Super); r.flags = kDevHasStorage | kDevShareable;
        r.name = "Echo"; return { r };
    }
    Status claim(const DeviceUid& uid, IUsbDevicePort** port, DeviceManifest& m,
                 std::uint8_t* cfg, std::string*) override
    {
        if (!(uid == uidOf(1))) return Status::NotFound;
        *port = _dev; m = _dev->manifest(); if (cfg) *cfg = 1; return Status::Ok;
    }
    void release(const DeviceUid&) override {}
private:
    EchoDevice* _dev;
};

struct Rig {
    MemoryPipe      pipe;
    LocalIdentity   idA = LocalIdentity::generate();
    LocalIdentity   idB = LocalIdentity::generate();
    PeerStore       storeA, storeB;
    SecureSession   a, b;
    EchoDevice      device;
    EchoSource      source;
    ExporterSession exporter;
    ManualClock     clock{1000};
    bool            ok = false;
    std::uint64_t   reqId = 0;

    Rig(std::uint32_t recSize, DeviceManifest m)
        : device(std::move(m)), source(&device)
    {
        (void)storeA.pin(idB.publicIdentity(), "B", kDefaultGrants, 1);
        (void)storeB.pin(idA.publicIdentity(), "A", kDefaultGrants, 1);
        SecureSession::Config ca; ca.initiator = true;  ca.identity = &idA; ca.peers = &storeA;
        ca.negotiatedMaxRecordBytes = recSize;
        SecureSession::Config cb; cb.initiator = false; cb.identity = &idB; cb.peers = &storeB;
        cb.negotiatedMaxRecordBytes = recSize;
        (void)a.begin(pipe.endpointA(), ca);
        (void)b.begin(pipe.endpointB(), cb);
        for (int i = 0; i < 40 && !(a.established() && b.established()); ++i) { (void)a.pump(); (void)b.pump(); }
        if (!(a.established() && b.established())) return;
        ExporterSession::Config ec; ec.devices = &source; ec.clock = &clock;
        if (exporter.begin(&b, ec) != Status::Ok) return;
        ok = true;
    }
};

std::uint32_t doAttach(Rig& r)
{
    AttachBody ab; ab.uid = uidOf(1); ab.attachSlot = kSlot; ab.importerMaxTransferBytes = 1u << 20;
    std::vector<std::uint8_t> req; encodeAttach(ab, req);
    Header h; h.type = static_cast<std::uint8_t>(wire::Type::Attach); h.flags = wire::kFlagSegFirst;
    h.requestId = ++r.reqId; h.bodyLen = static_cast<std::uint32_t>(req.size());
    std::vector<std::uint8_t> rec; encodeHeader(h, rec); rec.insert(rec.end(), req.begin(), req.end());
    (void)r.a.transport()->sendRecord(rec); (void)r.a.transport()->flush();
    (void)r.exporter.pump();
    std::vector<std::uint8_t> in;
    if (r.a.transport()->receiveRecord(in) != Status::Ok || in.empty()) return 0;
    Header rh; decodeHeader(in, rh);
    if (rh.type != static_cast<std::uint8_t>(wire::Type::AttachOk)) return 0;
    AttachOkBody ok;
    if (!decodeAttachOk(std::span<const std::uint8_t>(in).subspan(wire::kHeaderSize, rh.bodyLen), ok))
        return 0;
    std::vector<std::uint8_t> drain; (void)r.a.transport()->receiveRecord(drain);   // manifest
    return ok.attachId;
}

void testFullStack()
{
    std::printf("the async plane against the REAL exporter, end to end\n");

    ScriptedDevice proto;

    TEST_CASE("120 KiB OUT and IN through the plane and the real exporter") {
        Rig r(8192, proto.manifest());
        CHECK(r.ok);
        const std::uint32_t attachId = doAttach(r);
        CHECK(attachId != 0);

        ImporterDataPlane::Config c;
        c.attachId = attachId; c.attachSlot = kSlot; c.maxInFlight = 1;
        ImporterDataPlane plane(r.a.transport(), &r.clock, c);

        // OUT: importer -> device.
        const auto out = pattern(kBig, 0x11);
        std::uint16_t ch = 0; std::uint64_t rid = 0;
        CHECK(plane.submit(kEpOut, kBulk, kOut, kBig, nullptr, out, 45000, &ch, &rid) == Status::Ok);
        (void)r.exporter.pump();                       // the exporter reassembles + replies
        Collector co;
        CHECK(plane.pump(std::ref(co)) == Status::Ok);
        CHECK_EQ(co.count(), std::size_t{1});
        CHECK(co.comps[0].status == Status::Ok);
        CHECK_EQ(r.device.outCalls, 1);                // ONE transfer reached the device
        CHECK(r.device.lastOut == out);

        // IN: device -> importer, segmented reply reassembled by the plane.
        std::uint16_t ch2 = 0; std::uint64_t rid2 = 0;
        CHECK(plane.submit(kEpIn, kBulk, kIn, kBig, nullptr, {}, 45000, &ch2, &rid2) == Status::Ok);
        (void)r.exporter.pump();
        Collector ci;
        CHECK(plane.pump(std::ref(ci)) == Status::Ok);
        CHECK_EQ(ci.count(), std::size_t{1});
        CHECK_EQ(r.device.inCalls, 1);
        CHECK_EQ(ci.comps[0].actualLen, kBig);
        CHECK(ci.data[0] == pattern(kBig, 0x5A));
    }
}

} // namespace

int main()
{
    std::printf("test_dataplane\n");
    testRoundTrip();
    testAdmissionAndCancel();
    testDeadline();
    testTeardown();
    testNonBlocking();
    testFullStack();
    TEST_MAIN_END();
}
