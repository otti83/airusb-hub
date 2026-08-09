// L5 — a single large USB transfer crosses AirUSB as ONE logical transfer.
//
// A record cannot exceed Noise's plaintext ceiling, and usb-storage asks for
// 122 880 bytes in one URB at high speed (a megabyte at SuperSpeed). So a large
// transfer is split across records on the way out and reassembled on the way in.
// The rule that makes this dangerous rather than merely fiddly: reassembly MUST
// complete before the transfer reaches the device. Handing the device the
// segments one at a time injects a short packet at every seam, which a bulk
// device reads as the end of the data phase — silent corruption.
//
// So the load-bearing assertions here are not only "the bytes came back
// identical" but "the DEVICE saw exactly one bulkOut / one bulkIn per URB",
// across record sizes from 4 KiB (dozens of segments) to the ceiling.
//
// Two harnesses, both single-threaded and deterministic:
//   * the real ExporterSession, driven end-to-end through a real Noise session by
//     an importer that uses the same emitTransfer()/Reassembler the production
//     RemoteDevicePort uses (Path B reassemble, Path C segment);
//   * the real RemoteDevicePort in isolation against a pre-scripted peer (Path A
//     emit, Path D reassemble), which covers its own glue.

#include "../TestHarness.h"
#include "../fakes/ScriptedDevice.h"
#include "../../protocol/ManifestCodec.h"
#include "../../protocol/Segmentation.h"
#include "../../session/ExporterSession.h"
#include "../../session/InlineAsyncPort.h"
#include "../../session/LeaseAuthority.h"
#include "../../session/RemoteDevicePort.h"
#include "../../transport/RecordLayer.h"
#include "../../transport/TcpTransport.h"

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

constexpr std::uint8_t  kEpIn  = 0x81;
constexpr std::uint8_t  kEpOut = 0x02;
constexpr std::uint8_t  kSlot  = 1;
constexpr std::uint32_t kBig   = 122'880;   // usb-storage's high-speed max URB

// Record sizes spanning many-segments (4 KiB) to few-segments (the ceiling). The
// Noise plaintext ceiling is 65 519; nothing negotiated may exceed it.
const std::uint32_t kRecordSizes[] = { 4096, 8192, 16384, 32768, wire::kRecordBytesCeiling };

const std::uint8_t kBulk = static_cast<std::uint8_t>(wire::XferType::Bulk);
const std::uint8_t kIn   = static_cast<std::uint8_t>(wire::Dir::In);
const std::uint8_t kOut  = static_cast<std::uint8_t>(wire::Dir::Out);

std::vector<std::uint8_t> pattern(std::size_t n, std::uint8_t salt = 0)
{
    std::vector<std::uint8_t> v(n);
    for (std::size_t i = 0; i < n; ++i)
        v[i] = static_cast<std::uint8_t>((i * 31u + salt * 7u + (i >> 8)) & 0xFF);
    return v;
}

DeviceUid uidOf(std::uint8_t seed)
{
    DeviceUid u{};
    for (std::size_t i = 0; i < u.size(); ++i) u[i] = static_cast<std::uint8_t>(seed + i);
    return u;
}

// ---------------------------------------------------------------------------
// An IUsbDevicePort that echoes, and — crucially — counts its calls. One large
// URB must reach it as exactly one call; a segment leaking through as its own
// transfer shows up here as an extra call.
// ---------------------------------------------------------------------------
class EchoDevice final : public IUsbDevicePort {
public:
    explicit EchoDevice(DeviceManifest m) : _m(std::move(m)) {}

    const DeviceManifest& manifest() const noexcept override { return _m; }

    Status controlTransfer(const SetupPacket&, std::span<const std::uint8_t>,
                           std::vector<std::uint8_t>& in) override
    {
        in.clear();
        return Status::Ok;
    }

    Status bulkOut(std::uint8_t, std::span<const std::uint8_t> data,
                   std::uint32_t* actualLen) override
    {
        ++outCalls;
        lastOut.assign(data.begin(), data.end());
        if (actualLen) *actualLen = static_cast<std::uint32_t>(data.size());
        return Status::Ok;
    }

    Status bulkIn(std::uint8_t, std::uint32_t maxLen, std::vector<std::uint8_t>& out) override
    {
        ++inCalls;
        out = pattern(maxLen, 0x5A);
        return Status::Ok;
    }

    Status clearHalt(std::uint8_t) override { return Status::Ok; }

    int outCalls = 0;
    int inCalls  = 0;
    std::vector<std::uint8_t> lastOut;

private:
    DeviceManifest _m;
};

class EchoSource final : public IDeviceSource {
public:
    explicit EchoSource(EchoDevice* dev) : _dev(dev) {}

    std::vector<DeviceRecord> list() override
    {
        DeviceRecord r;
        r.uid       = uidOf(1);
        r.vendorId  = 0x058f;
        r.productId = 0x6387;
        r.speed     = static_cast<std::uint8_t>(Speed::Super);
        r.flags     = kDevHasStorage | kDevShareable;
        r.name      = "Echo";
        return { r };
    }

    Status claim(const DeviceUid& uid, IAsyncUsbDevicePort** portOut, DeviceManifest& m,
                 std::uint8_t* cfg, std::string* whyNot) override
    {
        if (!(uid == uidOf(1))) {
            if (whyNot) *whyNot = "no such device";
            return Status::NotFound;
        }
        _async   = std::make_unique<InlineAsyncPort>(*_dev);
        *portOut = _async.get();
        m        = _dev->manifest();
        if (cfg) *cfg = 1;
        return Status::Ok;
    }

    void release(const DeviceUid&) override {}

private:
    EchoDevice* _dev;
    std::unique_ptr<InlineAsyncPort> _async;
};

// ---------------------------------------------------------------------------
// A full session: two SecureSessions over a pipe with a real Noise handshake, the
// exporter on side B driving an EchoDevice, and a chosen record size.
// ---------------------------------------------------------------------------
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
    LeaseAuthority  leases{clock};
    bool            ok    = false;
    std::uint64_t   reqId = 0;

    /// `exporterSendCap` limits how much the exporter may leave unread in the
    /// pipe, which is how a socket whose send buffer is full behaves. 0 is
    /// unbounded, and unbounded is why the stranded-tail bug was invisible here
    /// for the life of the project.
    Rig(std::uint32_t recSize, DeviceManifest m, std::size_t exporterSendCap = 0)
        : device(std::move(m)), source(&device)
    {
        pipe.setCapacity(/*aToB=*/0, /*bToA=*/exporterSendCap);
        (void)storeA.pin(idB.publicIdentity(), "B", kDefaultGrants, 1);
        (void)storeB.pin(idA.publicIdentity(), "A", kDefaultGrants, 1);

        SecureSession::Config ca;
        ca.initiator = true;  ca.identity = &idA; ca.peers = &storeA;
        ca.negotiatedMaxRecordBytes = recSize;
        SecureSession::Config cb;
        cb.initiator = false; cb.identity = &idB; cb.peers = &storeB;
        cb.negotiatedMaxRecordBytes = recSize;

        (void)a.begin(pipe.endpointA(), ca);
        (void)b.begin(pipe.endpointB(), cb);
        for (int i = 0; i < 40 && !(a.established() && b.established()); ++i) {
            (void)a.pump();
            (void)b.pump();
        }
        if (!(a.established() && b.established())) return;

        ExporterSession::Config ec;
        ec.devices = &source;
        ec.clock   = &clock;
        ec.leases  = &leases;
        if (exporter.begin(&b, ec) != Status::Ok) return;
        ok = true;
    }
};

/// Sends one control-plane message from A, pumps the exporter, reads one reply.
Status ask(Rig& r, wire::Type type, std::span<const std::uint8_t> body,
           Header& replyHeader, std::vector<std::uint8_t>& replyBody,
           std::uint32_t attachId)
{
    Header h;
    h.type      = static_cast<std::uint8_t>(type);
    h.flags     = wire::kFlagSegFirst;
    h.attachId  = attachId;
    h.requestId = ++r.reqId;
    h.bodyLen   = static_cast<std::uint32_t>(body.size());
    h.totalLen  = 0;

    std::vector<std::uint8_t> rec;
    encodeHeader(h, rec);
    rec.insert(rec.end(), body.begin(), body.end());

    if (const Status s = r.a.transport()->sendRecord(rec); s != Status::Ok) return s;
    if (const Status s = r.a.transport()->flush(); s != Status::Ok) return s;

    (void)r.exporter.pump();

    std::vector<std::uint8_t> in;
    const Status rr = r.a.transport()->receiveRecord(in);
    if (rr != Status::Ok || in.empty()) return Status::Busy;
    if (!decodeHeader(in, replyHeader)) return Status::MalformedFrame;
    replyBody.assign(in.begin() + static_cast<std::ptrdiff_t>(wire::kHeaderSize),
                     in.begin() + static_cast<std::ptrdiff_t>(wire::kHeaderSize + replyHeader.bodyLen));
    return Status::Ok;
}

std::uint32_t doAttach(Rig& r)
{
    AttachBody ab;
    ab.uid                      = uidOf(1);
    ab.attachSlot               = kSlot;
    ab.importerMaxTransferBytes = 1u << 20;
    std::vector<std::uint8_t> req;
    encodeAttach(ab, req);

    Header h;
    std::vector<std::uint8_t> body;
    if (ask(r, wire::Type::Attach, req, h, body, 0) != Status::Ok) return 0;
    if (h.type != static_cast<std::uint8_t>(wire::Type::AttachOk)) return 0;

    AttachOkBody ok;
    if (!decodeAttachOk(body, ok)) return 0;

    // The manifest follows on the same request id; drain it.
    std::vector<std::uint8_t> drain;
    (void)r.a.transport()->receiveRecord(drain);
    return ok.attachId;
}

/// Drives one transfer from the importer side using exactly the emit/reassemble
/// code RemoteDevicePort uses, with an exporter.pump() interleaved where a real
/// network would carry the bytes across on its own.
Status remoteTransfer(Rig& r, std::uint8_t ep, std::uint8_t dir, std::uint32_t bufferLen,
                      std::span<const std::uint8_t> dataOut,
                      std::vector<std::uint8_t>& dataIn, std::uint32_t attachId,
                      std::uint32_t* actualOut = nullptr)
{
    dataIn.clear();
    if (actualOut) *actualOut = 0;
    RecordLayer* link = r.a.transport();

    SubmitBody sb;
    sb.epAddr    = ep;
    sb.xferType  = kBulk;
    sb.dir       = dir;
    sb.bufferLen = bufferLen;
    std::vector<std::uint8_t> subBody;
    encodeSubmit(sb, subBody);

    const std::uint64_t rid = ++r.reqId;
    Header base;
    base.type      = static_cast<std::uint8_t>(wire::Type::Submit);
    base.channel   = wire::channelFor(kSlot, ep);
    base.attachId  = attachId;
    base.requestId = rid;
    base.status    = 0;

    const std::span<const std::uint8_t> data =
        (dir == kOut) ? dataOut : std::span<const std::uint8_t>{};

    const std::uint32_t maxSeg = link->maxPlaintextBytes()
                                 - static_cast<std::uint32_t>(wire::kHeaderSize)
                                 - static_cast<std::uint32_t>(wire::kBodySubmit);

    if (const Status s = emitTransfer(base, subBody, data, maxSeg,
            [&](std::span<const std::uint8_t> rec) { return link->sendRecord(rec); });
        s != Status::Ok)
        return s;
    (void)link->flush();

    (void)r.exporter.pump();

    // Reading one record used to be enough because the pipe was unbounded, so
    // the exporter's single pump() wrote the entire reply at once. Against a
    // pipe that can fill — like every real socket — the reply arrives over
    // several pumps, and starving here would report TransportLost for a peer
    // that is simply mid-send.
    auto nextRecord = [&](std::vector<std::uint8_t>& into) -> Status {
        for (int spins = 0; spins < 100000; ++spins) {
            const Status rr = link->receiveRecord(into);
            if (rr == Status::Ok && !into.empty()) return Status::Ok;
            if (rr != Status::Ok && rr != Status::Busy) return rr;
            (void)r.exporter.pump();
        }
        return Status::TransportLost;
    };

    std::vector<std::uint8_t> in;
    if (nextRecord(in) != Status::Ok) return Status::Busy;
    Header rh;
    if (!decodeHeader(in, rh)) return Status::MalformedFrame;
    if (rh.type != static_cast<std::uint8_t>(wire::Type::Complete))
        return static_cast<Status>(rh.status);

    const auto rbody = std::span<const std::uint8_t>(in)
                          .subspan(wire::kHeaderSize, rh.bodyLen);
    CompleteBody cb;
    if (!decodeComplete(rbody, cb)) return Status::MalformedFrame;
    if (actualOut) *actualOut = cb.actualLen;

    const auto firstChunk = rbody.subspan(wire::kBodyComplete);
    if (dir == kIn) {
        if (!rh.segMore()) {
            dataIn.assign(firstChunk.begin(),
                          firstChunk.begin() + static_cast<std::ptrdiff_t>(cb.payloadLen));
        } else {
            Reassembler::Limits rl;
            rl.maxTransferBytes = bufferLen;
            rl.arenaBytes       = bufferLen;
            rl.maxInFlight      = 1;
            Reassembler ra(rl);
            Status e = Status::Ok;
            Reassembler::Outcome o = ra.accept(rh, firstChunk, e);
            while (o == Reassembler::Outcome::NeedMore) {
                std::vector<std::uint8_t> dr;
                if (const Status rr = nextRecord(dr); rr != Status::Ok) return rr;
                Header dh;
                if (!decodeHeader(dr, dh)) return Status::MalformedFrame;
                const auto db = std::span<const std::uint8_t>(dr)
                                   .subspan(wire::kHeaderSize, dh.bodyLen);
                o = ra.accept(dh, db, e);
            }
            if (o != Reassembler::Outcome::Complete) return e;
            dataIn = ra.take(rh);
        }
    }
    return static_cast<Status>(rh.status);
}

/// A manifest that cannot fit in one record, so the control plane has to
/// segment it. Eight configurations is legal USB and is exactly the case the
/// exporter used to refuse outright with "too large to send".
DeviceManifest fatManifest()
{
    DeviceManifest m;
    std::vector<std::uint8_t> dev = {
        18, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 9,
        0x8f, 0x05, 0x87, 0x63, 0x00, 0x01, 0, 0, 0, 8   // bNumConfigurations = 8
    };
    m.setSpeed(Speed::Super);
    m.setDeviceDescriptor(dev);
    // SuperSpeed requires a BOS descriptor, and validate() says so — which is
    // the manifest validator earning its place: the first version of this
    // fixture built an eight-configuration SuperSpeed device with no BOS and
    // would have been refused by a real importer for a reason the test would
    // have reported as "segmentation is broken".
    m.setBos(std::vector<std::uint8_t>{
        5, 0x0F, 12, 0x00, 1,                 // BOS, wTotalLength 12, 1 capability
        7, 0x10, 0x03, 0x0E, 0x00, 0x00, 0x00 // SuperSpeed USB device capability
    });

    for (int c = 1; c <= 8; ++c) {
        std::vector<std::uint8_t> cfg = {
            9, 0x02, 0, 0, 1, static_cast<std::uint8_t>(c), 0, 0x80, 50,
            9, 0x04, 0, 0, 2, 0x08, 0x06, 0x50, 0,
            7, 0x05, 0x81, 0x02, 0x00, 0x04, 0,
            6, 0x30, 15, 0, 0, 0,
            7, 0x05, 0x02, 0x02, 0x00, 0x04, 0,
            6, 0x30, 15, 0, 0, 0,
        };
        // Padded with a vendor-specific descriptor so the set is genuinely
        // larger than a small record, rather than only just over the line.
        for (int pad = 0; pad < 24; ++pad) {
            cfg.push_back(64);
            cfg.push_back(0xFF);
            for (int k = 0; k < 62; ++k) cfg.push_back(static_cast<std::uint8_t>(k));
        }
        cfg[2] = static_cast<std::uint8_t>(cfg.size() & 0xFF);
        cfg[3] = static_cast<std::uint8_t>((cfg.size() >> 8) & 0xFF);
        m.addConfiguration(cfg);
    }
    return m;
}

void testSegmentedManifest()
{
    std::printf("a manifest too big for one record\n");

    TEST_CASE("an eight-configuration manifest crosses records and arrives whole") {
        const DeviceManifest fat = fatManifest();
        CHECK(fat.validate(nullptr) == Status::Ok);

        std::vector<std::uint8_t> encoded;
        CHECK(encodeManifest(fat, 1, encoded) == Status::Ok);
        // The premise of the case. If this ever stops holding, the test is
        // passing for the wrong reason and would keep passing if segmentation
        // were removed.
        CHECK(encoded.size() > 8192);

        Rig r(8192, fat);
        CHECK(r.ok);
        if (!r.ok) return;

        AttachBody ab;
        ab.uid        = uidOf(1);
        ab.attachSlot = kSlot;
        ab.importerMaxTransferBytes = 1u << 20;
        std::vector<std::uint8_t> req;
        encodeAttach(ab, req);

        Header h;
        std::vector<std::uint8_t> body;
        CHECK(ask(r, wire::Type::Attach, req, h, body, 0) == Status::Ok);
        CHECK_EQ(h.type, static_cast<std::uint8_t>(wire::Type::AttachOk));
        AttachOkBody ok;
        CHECK(decodeAttachOk(body, ok));
        CHECK(ok.attachId != 0);
        CHECK_EQ(static_cast<long long>(ok.manifestLen),
                 static_cast<long long>(encoded.size()));

        // Read the manifest off the wire and reassemble it the way
        // ImporterClient does, so what is asserted is the BYTES rather than a
        // verdict about them.
        std::vector<std::uint8_t> in;
        CHECK(r.a.transport()->receiveRecord(in) == Status::Ok);
        Header mh;
        CHECK(decodeHeader(in, mh));
        CHECK_EQ(mh.type, static_cast<std::uint8_t>(wire::Type::DeviceManifest));
        // The premise again, from the other side: it really did segment.
        CHECK(mh.segMore());
        CHECK_EQ(static_cast<long long>(mh.totalLen),
                 static_cast<long long>(encoded.size()));

        Reassembler::Limits rl;
        rl.maxTransferBytes = wire::kManifestBytesMax;
        rl.arenaBytes       = wire::kManifestBytesMax;
        rl.maxInFlight      = 1;
        Reassembler ra(rl);
        Status e = Status::Ok;
        Reassembler::Outcome o = ra.accept(
            mh, std::span<const std::uint8_t>(in).subspan(wire::kHeaderSize, mh.bodyLen), e);
        CHECK(o != Reassembler::Outcome::Rejected);

        int records = 1;
        while (o == Reassembler::Outcome::NeedMore) {
            std::vector<std::uint8_t> more;
            CHECK(r.a.transport()->receiveRecord(more) == Status::Ok);
            if (more.empty()) break;
            Header dh;
            CHECK(decodeHeader(more, dh));
            CHECK_EQ(dh.type, static_cast<std::uint8_t>(wire::Type::Data));
            CHECK_EQ(static_cast<long long>(dh.requestId),
                     static_cast<long long>(mh.requestId));
            o = ra.accept(dh, std::span<const std::uint8_t>(more)
                                  .subspan(wire::kHeaderSize, dh.bodyLen), e);
            CHECK(o != Reassembler::Outcome::Rejected);
            ++records;
        }
        CHECK(o == Reassembler::Outcome::Complete);
        CHECK(records > 1);

        const std::vector<std::uint8_t> got = ra.take(mh);
        CHECK_EQ(static_cast<long long>(got.size()),
                 static_cast<long long>(encoded.size()));
        CHECK(got == encoded);

        // And it still decodes to the device it started as.
        DeviceManifest back;
        ManifestHeader mhdr;
        std::string why;
        CHECK(decodeManifest(got, back, mhdr, &why) == Status::Ok);
        CHECK_EQ(static_cast<long long>(back.configurationCount()), 8);
    }
}

void testExporterEndToEnd()
{
    std::printf("the real exporter, reassembling OUT and segmenting IN\n");

    ScriptedDevice proto;   // built once, only for its (valid, SuperSpeed) manifest

    for (std::uint32_t recSize : kRecordSizes) {
        TEST_CASE("120 KiB round trip, one transfer per URB") {
            Rig r(recSize, proto.manifest());
            CHECK(r.ok);
            if (!r.ok) continue;

            const std::uint32_t attachId = doAttach(r);
            CHECK(attachId != 0);
            CHECK_EQ(r.device.outCalls, 0);
            CHECK_EQ(r.device.inCalls, 0);

            // Large OUT: importer -> device. The device must see it as ONE call.
            const auto outData = pattern(kBig, 0x11);
            std::vector<std::uint8_t> ignore;
            std::uint32_t moved = 0;
            const Status so = remoteTransfer(r, kEpOut, kOut, kBig, outData, ignore, attachId, &moved);
            CHECK(so == Status::Ok);
            CHECK_EQ(r.device.outCalls, 1);                        // not split into segments
            CHECK_EQ(r.device.lastOut.size(), std::size_t{kBig});
            CHECK(r.device.lastOut == outData);                   // byte-identical
            CHECK_EQ(moved, kBig);

            // Large IN: device -> importer, reassembled before it is handed up.
            std::vector<std::uint8_t> inData;
            const Status si = remoteTransfer(r, kEpIn, kIn, kBig, {}, inData, attachId);
            CHECK(si == Status::Ok);
            CHECK_EQ(r.device.inCalls, 1);
            CHECK_EQ(inData.size(), std::size_t{kBig});
            CHECK(inData == pattern(kBig, 0x5A));                 // the device's bytes, intact
        }
    }

    TEST_CASE("a reply whose tail does not fit is still delivered") {
        // The bug this pins down was found between two machines, not here.
        //
        // `flush()` returns Ok on a would-block short write and keeps the rest
        // buffered — correct, because a short write is not an error. But every
        // record except the last one gets pushed along by the NEXT sendRecord,
        // and the last one has nothing behind it. Before ExporterSession::pump
        // drained the buffer, the tail of a large reply sat there for ever
        // while the importer waited for bytes that would never move.
        //
        // 8 KiB of capacity against a 120 KiB reply guarantees the socket fills
        // several times over, so this fails without the fix rather than
        // depending on timing.
        Rig r(wire::kRecordBytesDefault, proto.manifest(), /*exporterSendCap=*/8192);
        CHECK(r.ok);
        const std::uint32_t attachId = doAttach(r);
        CHECK(attachId != 0);

        std::vector<std::uint8_t> inData;
        const Status si = remoteTransfer(r, kEpIn, kIn, kBig, {}, inData, attachId);
        CHECK(si == Status::Ok);
        CHECK_EQ(r.device.inCalls, 1);
        CHECK_EQ(inData.size(), std::size_t{kBig});
        CHECK(inData == pattern(kBig, 0x5A));
    }

    TEST_CASE("a small transfer still emits exactly one record (fast path intact)") {
        Rig r(wire::kRecordBytesDefault, proto.manifest());
        CHECK(r.ok);
        const std::uint32_t attachId = doAttach(r);
        CHECK(attachId != 0);

        const auto small = pattern(31, 7);        // a 31-byte CBW, the common case
        std::vector<std::uint8_t> ignore;
        std::uint32_t moved = 0;
        CHECK(remoteTransfer(r, kEpOut, kOut, 31, small, ignore, attachId, &moved) == Status::Ok);
        CHECK_EQ(r.device.outCalls, 1);
        CHECK(r.device.lastOut == small);
    }
}

// ---------------------------------------------------------------------------
// RemoteDevicePort in isolation: a pre-scripted peer supplies the COMPLETE, so
// the port's own segmentation glue is exercised single-threaded.
// ---------------------------------------------------------------------------

struct Pair {
    MemoryPipe  pipe;
    RecordLayer portLink;
    RecordLayer peerLink;

    explicit Pair(std::uint32_t recSize)
        : portLink(pipe.endpointA(), std::make_unique<NullCipher>())
        , peerLink(pipe.endpointB(), std::make_unique<NullCipher>())
    {
        portLink.setHandshakeComplete(recSize);
        peerLink.setHandshakeComplete(recSize);
    }
};

void testRemoteDevicePort()
{
    std::printf("RemoteDevicePort emits segmented OUT and reassembles segmented IN\n");

    ScriptedDevice proto;

    for (std::uint32_t recSize : kRecordSizes) {
        TEST_CASE("bulkIn reassembles a segmented COMPLETE") {
            Pair p(recSize);
            RemoteDevicePort port(&p.portLink, /*attachId*/ 5, kSlot, proto.manifest());

            const auto payload = pattern(kBig, 0x5A);

            // Pre-load the reply the port will read (its first request id is 1).
            CompleteBody cb;
            cb.epAddr       = kEpIn;
            cb.xferType     = kBulk;
            cb.dir          = kIn;
            cb.requestedLen = kBig;
            cb.actualLen    = kBig;
            cb.payloadLen   = kBig;
            std::vector<std::uint8_t> cbody;
            encodeComplete(cb, cbody);

            Header base;
            base.type      = static_cast<std::uint8_t>(wire::Type::Complete);
            base.channel   = wire::channelFor(kSlot, kEpIn);
            base.attachId  = 5;
            base.requestId = 1;
            base.status    = 0;
            const std::uint32_t maxSeg = p.peerLink.maxPlaintextBytes()
                                         - static_cast<std::uint32_t>(wire::kHeaderSize)
                                         - static_cast<std::uint32_t>(wire::kBodyComplete);
            CHECK(emitTransfer(base, cbody, payload, maxSeg,
                    [&](std::span<const std::uint8_t> rec) { return p.peerLink.sendRecord(rec); })
                  == Status::Ok);
            (void)p.peerLink.flush();

            std::vector<std::uint8_t> out;
            CHECK(port.bulkIn(kEpIn, kBig, out) == Status::Ok);
            CHECK_EQ(out.size(), std::size_t{kBig});
            CHECK(out == payload);
        }

        TEST_CASE("bulkOut segments the payload into contiguous records") {
            Pair p(recSize);
            RemoteDevicePort port(&p.portLink, /*attachId*/ 5, kSlot, proto.manifest());

            const auto outData = pattern(kBig, 0x11);

            // The single-record COMPLETE the port expects back (OUT carries none).
            CompleteBody cb;
            cb.epAddr       = kEpOut;
            cb.xferType     = kBulk;
            cb.dir          = kOut;
            cb.requestedLen = kBig;
            cb.actualLen    = kBig;
            cb.payloadLen   = 0;
            std::vector<std::uint8_t> cbody;
            encodeComplete(cb, cbody);

            Header base;
            base.type      = static_cast<std::uint8_t>(wire::Type::Complete);
            base.channel   = wire::channelFor(kSlot, kEpOut);
            base.attachId  = 5;
            base.requestId = 1;
            base.status    = 0;
            CHECK(emitTransfer(base, cbody, {}, 1024,
                    [&](std::span<const std::uint8_t> rec) { return p.peerLink.sendRecord(rec); })
                  == Status::Ok);
            (void)p.peerLink.flush();

            std::uint32_t moved = 0;
            CHECK(port.bulkOut(kEpOut, outData, &moved) == Status::Ok);
            CHECK_EQ(moved, kBig);

            // Reassemble what the port put on the wire and prove it is the payload,
            // carried as ONE logical transfer across contiguous segments.
            Reassembler ra;
            Status e = Status::Ok;
            Reassembler::Outcome o = Reassembler::Outcome::NeedMore;
            int records = 0;
            bool sawSubmit = false;
            SubmitBody gotSb{};
            std::vector<std::uint8_t> rec;
            while (p.peerLink.receiveRecord(rec) == Status::Ok && !rec.empty()) {
                ++records;
                Header hi;
                CHECK(decodeHeader(rec, hi));
                if (hi.type == static_cast<std::uint8_t>(wire::Type::Submit)) {
                    sawSubmit = true;
                    CHECK(decodeSubmit(std::span<const std::uint8_t>(rec).subspan(wire::kHeaderSize),
                                       gotSb));
                    const auto chunk = std::span<const std::uint8_t>(rec)
                                          .subspan(wire::kHeaderSize + wire::kBodySubmit);
                    o = ra.accept(hi, chunk, e);
                } else if (hi.type == static_cast<std::uint8_t>(wire::Type::Data)) {
                    const auto chunk = std::span<const std::uint8_t>(rec).subspan(wire::kHeaderSize);
                    o = ra.accept(hi, chunk, e);
                }
                if (o == Reassembler::Outcome::Complete) break;
            }
            CHECK(sawSubmit);
            CHECK_EQ(gotSb.epAddr, kEpOut);
            CHECK_EQ(gotSb.bufferLen, kBig);
            if (recSize < kBig) CHECK(records > 1);       // it genuinely segmented
            CHECK(o == Reassembler::Outcome::Complete);

            Header key;
            key.channel   = wire::channelFor(kSlot, kEpOut);
            key.requestId = 1;
            CHECK(ra.take(key) == outData);
        }
    }
}

} // namespace

int main()
{
    std::printf("test_l5_segmentation\n");
    testExporterEndToEnd();
    testSegmentedManifest();
    testRemoteDevicePort();
    TEST_MAIN_END();
}
