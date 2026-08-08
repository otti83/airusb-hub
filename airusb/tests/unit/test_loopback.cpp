// P2.7 — the loopback gate.
//
// A real Bulk-Only Transport host drives the fake mass storage device through the
// REAL protocol codec, the REAL validation rules, the REAL record layer, and the
// REAL request table. Nothing on the path is stubbed except the device itself and
// the byte pipe.
//
// The point is not that bytes move. It is that the round trip preserves USB
// semantics: transfer boundaries survive segmentation, a short read stays short,
// a stall halts the endpoint and requires a real recovery sequence, and the RAM
// disk's checksum is unchanged after a write-then-read cycle. A test that only
// checked "no error returned" would pass with all of that broken.

#include "../TestHarness.h"
#include "../fakes/ScriptedDevice.h"
#include "../../core/RequestTable.h"
#include "../../protocol/Codec.h"
#include "../../protocol/Validate.h"
#include "../../transport/RecordLayer.h"
#include "../../transport/TcpTransport.h"

using namespace airusb;
using namespace airusb::protocol;
using namespace airusb::transport;
using namespace airusb::fakes;

namespace {

constexpr std::uint8_t kEpIn  = 0x81;
constexpr std::uint8_t kEpOut = 0x02;
constexpr std::uint32_t kAttachId = 1;
constexpr std::uint8_t  kSlot = 1;

// ---------------------------------------------------------------------------
// A minimal exporter: decodes SUBMIT, drives ScriptedDevice, encodes COMPLETE.
// ---------------------------------------------------------------------------
class Exporter {
public:
    Exporter(ScriptedDevice& dev, RecordLayer& link) : _dev(dev), _link(link) {}

    /// Processes everything currently readable. Returns the number of SUBMITs served.
    int pump()
    {
        int served = 0;
        for (;;) {
            std::vector<std::uint8_t> rec;
            if (_link.receiveRecord(rec) != Status::Ok || rec.empty()) break;

            Header h;
            if (!decodeHeader(rec, h)) { ++_protocolErrors; break; }

            Limits lim;
            lim.maxRecordBytes = wire::kRecordBytesDefault;
            if (auto v = validateHeader(h, rec.size() - wire::kHeaderSize, lim); !v.ok()) {
                ++_protocolErrors;
                break;
            }
            if (h.type != static_cast<std::uint8_t>(wire::Type::Submit)) continue;

            auto body = std::span<const std::uint8_t>(rec).subspan(wire::kHeaderSize);
            SubmitBody sb;
            if (!decodeSubmit(body, sb)) { ++_protocolErrors; break; }

            auto dataSection = body.subspan(wire::kBodySubmit);
            if (auto v = validateSubmit(h, sb, dataSection, lim); !v.ok()) {
                ++_protocolErrors;
                break;
            }

            serve(h, sb, dataSection);
            ++served;
        }
        return served;
    }

    int protocolErrors() const noexcept { return _protocolErrors; }

private:
    void serve(const Header& h, const SubmitBody& sb, std::span<const std::uint8_t> dataOut)
    {
        CompleteBody cb;
        cb.epAddr       = sb.epAddr;
        cb.xferType     = sb.xferType;
        cb.dir          = sb.dir;
        cb.requestedLen = sb.bufferLen;
        cb.submitTsNs   = sb.submitTsNs;

        std::vector<std::uint8_t> payload;
        Status st = Status::Ok;

        if (sb.xferType == static_cast<std::uint8_t>(wire::XferType::Control)) {
            SetupPacket sp;
            sp.bmRequestType = sb.setup[0];
            sp.bRequest      = sb.setup[1];
            sp.wValue        = static_cast<std::uint16_t>(sb.setup[2] | (sb.setup[3] << 8));
            sp.wIndex        = static_cast<std::uint16_t>(sb.setup[4] | (sb.setup[5] << 8));
            sp.wLength       = static_cast<std::uint16_t>(sb.setup[6] | (sb.setup[7] << 8));
            st = _dev.controlTransfer(sp, dataOut, payload);
        } else if (sb.dir == static_cast<std::uint8_t>(wire::Dir::In)) {
            st = _dev.bulkIn(sb.bufferLen, payload);
        } else {
            std::uint32_t moved = 0;
            st = _dev.bulkOut(dataOut, &moved);
            cb.actualLen = moved;
        }

        if (sb.dir == static_cast<std::uint8_t>(wire::Dir::In)) {
            cb.actualLen  = static_cast<std::uint32_t>(payload.size());
            cb.payloadLen = static_cast<std::uint32_t>(payload.size());
        } else {
            cb.payloadLen = 0;
        }
        if (st == Status::Ok && cb.actualLen < cb.requestedLen) cb.cflags |= wire::kCfShort;

        Header rh;
        rh.type      = static_cast<std::uint8_t>(wire::Type::Complete);
        rh.flags     = wire::kFlagSegFirst;
        rh.channel   = h.channel;
        rh.attachId  = h.attachId;
        rh.requestId = h.requestId;
        rh.status    = static_cast<std::uint16_t>(st);
        rh.totalLen  = cb.payloadLen;
        rh.bodyLen   = static_cast<std::uint32_t>(wire::kBodyComplete + payload.size());

        std::vector<std::uint8_t> rec;
        encodeHeader(rh, rec);
        encodeComplete(cb, rec);
        rec.insert(rec.end(), payload.begin(), payload.end());
        _link.sendRecord(rec);
    }

    ScriptedDevice& _dev;
    RecordLayer&    _link;
    int             _protocolErrors = 0;
};

// ---------------------------------------------------------------------------
// A minimal importer: a synchronous BOT host.
// ---------------------------------------------------------------------------
class Importer {
public:
    Importer(RecordLayer& link, Exporter& exporter, RequestTable& table)
        : _link(link), _exporter(exporter), _table(table) {}

    Status control(const SetupPacket& sp, std::span<const std::uint8_t> out,
                   std::vector<std::uint8_t>& in)
    {
        SubmitBody sb;
        sb.epAddr   = 0;
        sb.xferType = static_cast<std::uint8_t>(wire::XferType::Control);
        sb.dir      = static_cast<std::uint8_t>(sp.direction() == Dir::In ? wire::Dir::In
                                                                          : wire::Dir::Out);
        sb.bufferLen = sp.direction() == Dir::In ? sp.wLength
                                                 : static_cast<std::uint32_t>(out.size());
        sb.setup[0] = sp.bmRequestType; sb.setup[1] = sp.bRequest;
        sb.setup[2] = static_cast<std::uint8_t>(sp.wValue & 0xFFu);
        sb.setup[3] = static_cast<std::uint8_t>(sp.wValue >> 8);
        sb.setup[4] = static_cast<std::uint8_t>(sp.wIndex & 0xFFu);
        sb.setup[5] = static_cast<std::uint8_t>(sp.wIndex >> 8);
        sb.setup[6] = static_cast<std::uint8_t>(sp.wLength & 0xFFu);
        sb.setup[7] = static_cast<std::uint8_t>(sp.wLength >> 8);
        return exchange(wire::channelFor(kSlot, 0), sb, out, in);
    }

    Status bulkIn(std::uint32_t maxLen, std::vector<std::uint8_t>& in)
    {
        SubmitBody sb;
        sb.epAddr    = kEpIn;
        sb.xferType  = static_cast<std::uint8_t>(wire::XferType::Bulk);
        sb.dir       = static_cast<std::uint8_t>(wire::Dir::In);
        sb.bufferLen = maxLen;
        return exchange(wire::channelFor(kSlot, kEpIn), sb, {}, in);
    }

    Status bulkOut(std::span<const std::uint8_t> data)
    {
        SubmitBody sb;
        sb.epAddr    = kEpOut;
        sb.xferType  = static_cast<std::uint8_t>(wire::XferType::Bulk);
        sb.dir       = static_cast<std::uint8_t>(wire::Dir::Out);
        sb.bufferLen = static_cast<std::uint32_t>(data.size());
        std::vector<std::uint8_t> in;
        return exchange(wire::channelFor(kSlot, kEpOut), sb, data, in);
    }

    std::uint32_t lastActualLen() const noexcept { return _lastActual; }
    bool lastWasShort() const noexcept { return _lastShort; }

private:
    Status exchange(std::uint16_t channel, const SubmitBody& sb,
                    std::span<const std::uint8_t> outData,
                    std::vector<std::uint8_t>& in)
    {
        in.clear();
        const std::uint64_t rid = _table.nextRequestId(channel);

        OutstandingRequest req;
        req.requestId    = rid;
        req.channel      = channel;
        req.attachId     = kAttachId;
        req.epAddr       = sb.epAddr;
        req.requestedLen = sb.bufferLen;
        if (_table.add(req) != Status::Ok) return Status::Internal;

        Header h;
        h.type      = static_cast<std::uint8_t>(wire::Type::Submit);
        h.flags     = wire::kFlagSegFirst;
        h.channel   = channel;
        h.attachId  = kAttachId;
        h.requestId = rid;
        h.totalLen  = sb.dir == static_cast<std::uint8_t>(wire::Dir::Out)
                    ? sb.bufferLen : 0;
        h.bodyLen   = static_cast<std::uint32_t>(wire::kBodySubmit + outData.size());

        std::vector<std::uint8_t> rec;
        encodeHeader(h, rec);
        encodeSubmit(sb, rec);
        rec.insert(rec.end(), outData.begin(), outData.end());
        if (Status s = _link.sendRecord(rec); s != Status::Ok) return s;

        _exporter.pump();

        std::vector<std::uint8_t> resp;
        if (_link.receiveRecord(resp) != Status::Ok || resp.empty()) return Status::TransportLost;

        Header rh;
        if (!decodeHeader(resp, rh)) return Status::MalformedFrame;

        Limits lim; lim.maxRecordBytes = wire::kRecordBytesDefault;
        if (auto v = validateHeader(rh, resp.size() - wire::kHeaderSize, lim); !v.ok())
            return v.status;

        auto body = std::span<const std::uint8_t>(resp).subspan(wire::kHeaderSize);
        CompleteBody cb;
        if (!decodeComplete(body, cb)) return Status::MalformedFrame;

        auto ds = body.subspan(wire::kBodyComplete);
        if (auto v = validateComplete(rh, cb, ds, lim); !v.ok()) return v.status;

        OutstandingRequest done;
        if (!_table.take(rh.channel, rh.requestId, &done)) return Status::AlreadyCompleted;

        // R5 re-asserted at the copy site, exactly as the real backend must.
        if (cb.actualLen > done.requestedLen) return Status::MalformedFrame;

        in.assign(ds.begin(), ds.begin() + static_cast<std::ptrdiff_t>(cb.payloadLen));
        _lastActual = cb.actualLen;
        _lastShort  = cb.isShort();
        return static_cast<Status>(rh.status);
    }

    RecordLayer&  _link;
    Exporter&     _exporter;
    RequestTable& _table;
    std::uint32_t _lastActual = 0;
    bool          _lastShort  = false;
};

// ---------------------------------------------------------------------------
// BOT helpers on top of the importer.
// ---------------------------------------------------------------------------

std::vector<std::uint8_t> makeCbw(std::uint32_t tag, std::uint32_t xferLen, bool dataIn,
                                  std::span<const std::uint8_t> cdb)
{
    std::vector<std::uint8_t> c(kCbwLength, 0);
    auto put32 = [&](std::size_t at, std::uint32_t v) {
        c[at]   = static_cast<std::uint8_t>(v);
        c[at+1] = static_cast<std::uint8_t>(v >> 8);
        c[at+2] = static_cast<std::uint8_t>(v >> 16);
        c[at+3] = static_cast<std::uint8_t>(v >> 24);
    };
    put32(0, kCbwSignature);
    put32(4, tag);
    put32(8, xferLen);
    c[12] = dataIn ? 0x80 : 0x00;
    c[13] = 0;
    c[14] = static_cast<std::uint8_t>(cdb.size());
    std::memcpy(c.data() + 15, cdb.data(), cdb.size());
    return c;
}

struct BotResult {
    Status                    status = Status::Ok;
    std::vector<std::uint8_t> data;
    std::uint8_t              cswStatus = 0xFF;
    std::uint32_t             residue = 0;
};

BotResult botRead(Importer& imp, std::uint32_t tag,
                  std::span<const std::uint8_t> cdb, std::uint32_t expect)
{
    BotResult r;
    auto cbw = makeCbw(tag, expect, true, cdb);
    r.status = imp.bulkOut(cbw);
    if (r.status != Status::Ok) return r;

    if (expect > 0) {
        r.status = imp.bulkIn(expect, r.data);
        if (r.status != Status::Ok) return r;
    }

    std::vector<std::uint8_t> csw;
    r.status = imp.bulkIn(kCswLength, csw);
    if (r.status == Status::Ok && csw.size() == kCswLength) {
        r.cswStatus = csw[12];
        r.residue = static_cast<std::uint32_t>(csw[8] | (csw[9] << 8)
                                             | (csw[10] << 16) | (csw[11] << 24));
    }
    return r;
}

BotResult botWrite(Importer& imp, std::uint32_t tag,
                   std::span<const std::uint8_t> cdb, std::span<const std::uint8_t> data)
{
    BotResult r;
    auto cbw = makeCbw(tag, static_cast<std::uint32_t>(data.size()), false, cdb);
    r.status = imp.bulkOut(cbw);
    if (r.status != Status::Ok) return r;

    r.status = imp.bulkOut(data);
    if (r.status != Status::Ok) return r;

    std::vector<std::uint8_t> csw;
    r.status = imp.bulkIn(kCswLength, csw);
    if (r.status == Status::Ok && csw.size() == kCswLength) r.cswStatus = csw[12];
    return r;
}

std::vector<std::uint8_t> read10Cdb(std::uint32_t lba, std::uint16_t blocks)
{
    std::vector<std::uint8_t> c(10, 0);
    c[0] = 0x28;
    c[2] = static_cast<std::uint8_t>(lba >> 24); c[3] = static_cast<std::uint8_t>(lba >> 16);
    c[4] = static_cast<std::uint8_t>(lba >> 8);  c[5] = static_cast<std::uint8_t>(lba);
    c[7] = static_cast<std::uint8_t>(blocks >> 8); c[8] = static_cast<std::uint8_t>(blocks);
    return c;
}

std::vector<std::uint8_t> write10Cdb(std::uint32_t lba, std::uint16_t blocks)
{
    auto c = read10Cdb(lba, blocks);
    c[0] = 0x2A;
    return c;
}

/// Wires an importer and exporter together over the real record layer.
struct Rig {
    MemoryPipe    pipe;
    ScriptedDevice device;
    ManualClock   clock;
    RecordLayer   hostLink;
    RecordLayer   devLink;
    RequestTable  table;
    Exporter      exporter;
    Importer      importer;

    Rig()
        : hostLink(pipe.endpointA(), std::make_unique<NullCipher>())
        , devLink(pipe.endpointB(), std::make_unique<NullCipher>())
        , table(clock)
        , exporter(device, devLink)
        , importer(hostLink, exporter, table)
    {
        hostLink.setHandshakeComplete(wire::kRecordBytesDefault);
        devLink.setHandshakeComplete(wire::kRecordBytesDefault);
    }
};

// ---------------------------------------------------------------------------

void testEnumeration()
{
    TEST_CASE("GET_DESCRIPTOR(DEVICE) survives the full round trip") {
        Rig rig;
        SetupPacket s;
        s.bmRequestType = 0x80; s.bRequest = kGetDescriptor;
        s.wValue = kDescDevice << 8; s.wLength = 18;

        std::vector<std::uint8_t> in;
        CHECK_EQ(static_cast<int>(rig.importer.control(s, {}, in)), static_cast<int>(Status::Ok));
        CHECK_EQ(in.size(), std::size_t{18});
        CHECK_EQ(in[0], 18u);
        CHECK_EQ(in[1], kDescDevice);
        CHECK_EQ(in[7], 9u);                  // SuperSpeed bMaxPacketSize0 exponent
        CHECK_EQ(rig.exporter.protocolErrors(), 0);
    }

    TEST_CASE("an 8-byte descriptor request comes back short, not padded") {
        Rig rig;
        SetupPacket s;
        s.bmRequestType = 0x80; s.bRequest = kGetDescriptor;
        s.wValue = kDescDevice << 8; s.wLength = 8;

        std::vector<std::uint8_t> in;
        rig.importer.control(s, {}, in);
        CHECK_EQ(in.size(), std::size_t{8});
        CHECK_EQ(rig.importer.lastActualLen(), 8u);
    }

    TEST_CASE("GET_MAX_LUN is answered by the device, not locally") {
        Rig rig;
        SetupPacket s;
        s.bmRequestType = 0xA1; s.bRequest = 0xFE; s.wLength = 1;
        std::vector<std::uint8_t> in;
        CHECK_EQ(static_cast<int>(rig.importer.control(s, {}, in)), static_cast<int>(Status::Ok));
        CHECK_EQ(in.size(), std::size_t{1});
        CHECK_EQ(in[0], 0u);
    }
}

void testScsi()
{
    TEST_CASE("INQUIRY returns a well-formed response with a good CSW") {
        Rig rig;
        const std::uint8_t cdb[6] = {0x12, 0, 0, 0, 36, 0};
        auto r = botRead(rig.importer, 1, cdb, 36);
        CHECK_EQ(static_cast<int>(r.status), static_cast<int>(Status::Ok));
        CHECK_EQ(r.data.size(), std::size_t{36});
        CHECK_EQ(r.cswStatus, 0u);
        CHECK_EQ(r.data[1], 0x80u);            // removable
    }

    TEST_CASE("READ CAPACITY reports last LBA, not block count") {
        // Off by one here is the classic bug: the device reports the LAST LBA.
        Rig rig;
        const std::uint8_t cdb[10] = {0x25,0,0,0,0,0,0,0,0,0};
        auto r = botRead(rig.importer, 2, cdb, 8);
        CHECK_EQ(r.data.size(), std::size_t{8});
        const std::uint32_t lastLba = static_cast<std::uint32_t>(
            (r.data[0] << 24) | (r.data[1] << 16) | (r.data[2] << 8) | r.data[3]);
        const std::uint32_t bs = static_cast<std::uint32_t>(
            (r.data[4] << 24) | (r.data[5] << 16) | (r.data[6] << 8) | r.data[7]);
        CHECK_EQ(lastLba, rig.device.blockCount() - 1);
        CHECK_EQ(bs, rig.device.blockSize());
    }

    TEST_CASE("READ(10) returns exactly the media bytes") {
        Rig rig;
        rig.device.fillPattern(0xC0FFEE);
        auto cdb = read10Cdb(0, 4);
        auto r = botRead(rig.importer, 3, cdb, 4 * 512);
        CHECK_EQ(static_cast<int>(r.status), static_cast<int>(Status::Ok));
        CHECK_EQ(r.data.size(), std::size_t{2048});
        CHECK_EQ(r.cswStatus, 0u);
        CHECK(std::memcmp(r.data.data(), rig.device.media().data(), 2048) == 0);
    }

    TEST_CASE("write-then-read round trips the exact bytes") {
        // The real test of the whole stack: bytes go out through segmentation,
        // framing and validation, land on the media, and come back identical.
        Rig rig;
        std::vector<std::uint8_t> payload(2048);
        for (std::size_t i = 0; i < payload.size(); ++i)
            payload[i] = static_cast<std::uint8_t>((i * 31 + 7) & 0xFF);

        auto wcdb = write10Cdb(8, 4);
        auto w = botWrite(rig.importer, 4, wcdb, payload);
        CHECK_EQ(static_cast<int>(w.status), static_cast<int>(Status::Ok));
        CHECK_EQ(w.cswStatus, 0u);

        auto rcdb = read10Cdb(8, 4);
        auto r = botRead(rig.importer, 5, rcdb, 2048);
        CHECK_EQ(r.data.size(), std::size_t{2048});
        CHECK(r.data == payload);
    }

    TEST_CASE("an out-of-range LBA is a CHECK CONDITION, not a crash") {
        Rig rig;
        auto cdb = read10Cdb(rig.device.blockCount() + 100, 1);
        auto r = botRead(rig.importer, 6, cdb, 0);
        CHECK_EQ(r.cswStatus, 1u);
    }

    TEST_CASE("media is untouched by a read-only workload") {
        Rig rig;
        rig.device.fillPattern(0xABCDEF);
        const std::uint64_t before = rig.device.checksum();
        for (std::uint32_t i = 0; i < 20; ++i) {
            auto cdb = read10Cdb(i, 1);
            botRead(rig.importer, 100 + i, cdb, 512);
        }
        CHECK_EQ(rig.device.checksum(), before);
    }
}

void testFaults()
{
    TEST_CASE("a stall halts the endpoint and needs a real recovery sequence") {
        Rig rig;
        ScriptedFault f; f.stallOnCommand = 1;
        rig.device.setFaults(f);

        const std::uint8_t cdb[6] = {0x12, 0, 0, 0, 36, 0};
        auto cbw = makeCbw(1, 36, true, cdb);
        rig.importer.bulkOut(cbw);
        CHECK(rig.device.inHalted());

        // While halted, IN transfers keep stalling. A fake that silently recovered
        // would hide the missing CLEAR_HALT in the layer above.
        std::vector<std::uint8_t> data;
        CHECK_EQ(static_cast<int>(rig.importer.bulkIn(36, data)),
                 static_cast<int>(Status::XferStall));

        SetupPacket clear;
        clear.bmRequestType = 0x02; clear.bRequest = kClearFeature;
        clear.wValue = kFeatEndpointHalt; clear.wIndex = kEpIn;
        std::vector<std::uint8_t> none;
        rig.importer.control(clear, {}, none);
        CHECK(!rig.device.inHalted());

        std::vector<std::uint8_t> csw;
        CHECK_EQ(static_cast<int>(rig.importer.bulkIn(kCswLength, csw)),
                 static_cast<int>(Status::Ok));
        CHECK_EQ(csw.size(), kCswLength);
    }

    TEST_CASE("GET_STATUS reports the live halt bit") {
        // The arbiter forwards GET_STATUS precisely so this works. Cached, the
        // driver would never see the halt and would never recover.
        Rig rig;
        SetupPacket setHalt;
        setHalt.bmRequestType = 0x02; setHalt.bRequest = kSetFeature;
        setHalt.wValue = kFeatEndpointHalt; setHalt.wIndex = kEpIn;
        std::vector<std::uint8_t> none;
        rig.importer.control(setHalt, {}, none);

        SetupPacket getStatus;
        getStatus.bmRequestType = 0x82; getStatus.bRequest = kGetStatus;
        getStatus.wIndex = kEpIn; getStatus.wLength = 2;
        std::vector<std::uint8_t> st;
        rig.importer.control(getStatus, {}, st);
        CHECK_EQ(st.size(), std::size_t{2});
        CHECK_EQ(st[0], 1u);                   // halted
    }

    TEST_CASE("a short read stays short all the way back") {
        Rig rig;
        ScriptedFault f; f.shortReadOnCommand = 1;
        rig.device.setFaults(f);

        auto cdb = read10Cdb(0, 4);
        auto cbw = makeCbw(9, 4 * 512, true, cdb);
        rig.importer.bulkOut(cbw);

        std::vector<std::uint8_t> data;
        rig.importer.bulkIn(4 * 512, data);
        CHECK_EQ(data.size(), std::size_t{3 * 512});
        CHECK(rig.importer.lastWasShort());
    }

    TEST_CASE("a truncated CBW is refused rather than half-executed") {
        // If the layer above ever splits a 31-byte CBW, real firmware stalls both
        // pipes. The fake does the same so that bug cannot pass unnoticed.
        Rig rig;
        const std::uint8_t cdb[6] = {0x12, 0, 0, 0, 36, 0};
        auto cbw = makeCbw(10, 36, true, cdb);
        cbw.resize(20);
        CHECK_EQ(static_cast<int>(rig.importer.bulkOut(cbw)),
                 static_cast<int>(Status::XferStall));
        CHECK(rig.device.inHalted());
        CHECK(rig.device.outHalted());
    }

    TEST_CASE("BOT reset restarts the phase machine but leaves halts set") {
        // Getting this wrong makes recovery look fine in a fake and hang against
        // real firmware, which requires CLEAR_FEATURE on both pipes after a reset.
        Rig rig;
        rig.device.setFaults(ScriptedFault{1, 0, 0});
        const std::uint8_t cdb[6] = {0x12, 0, 0, 0, 36, 0};
        rig.importer.bulkOut(makeCbw(11, 36, true, cdb));
        CHECK(rig.device.inHalted());

        SetupPacket botReset;
        botReset.bmRequestType = 0x21; botReset.bRequest = 0xFF;
        std::vector<std::uint8_t> none;
        rig.importer.control(botReset, {}, none);

        CHECK_EQ(static_cast<int>(rig.device.phase()), static_cast<int>(BotPhase::AwaitingCbw));
        CHECK(rig.device.inHalted());          // still halted, by spec
    }
}

void testVolume()
{
    TEST_CASE("1000 mixed transfers leave the media exactly as computed") {
        Rig rig;
        rig.device.fillPattern(0x1234);

        std::vector<std::uint8_t> shadow(rig.device.media().begin(), rig.device.media().end());
        std::uint64_t rng = 0xDEADBEEF;
        auto next = [&] { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return rng; };

        std::uint32_t tag = 1000;
        for (int i = 0; i < 1000; ++i) {
            const std::uint32_t lba = static_cast<std::uint32_t>(next() % (rig.device.blockCount() - 4));
            const std::uint16_t n   = static_cast<std::uint16_t>(1 + (next() % 4));

            if (next() & 1) {
                std::vector<std::uint8_t> data(static_cast<std::size_t>(n) * 512);
                for (auto& b : data) b = static_cast<std::uint8_t>(next());
                auto cdb = write10Cdb(lba, n);
                auto w = botWrite(rig.importer, tag++, cdb, data);
                CHECK_EQ(w.cswStatus, 0u);
                std::memcpy(shadow.data() + static_cast<std::size_t>(lba) * 512,
                            data.data(), data.size());
            } else {
                auto cdb = read10Cdb(lba, n);
                auto r = botRead(rig.importer, tag++, cdb, static_cast<std::uint32_t>(n) * 512);
                CHECK_EQ(r.cswStatus, 0u);
                CHECK(std::memcmp(r.data.data(),
                                  shadow.data() + static_cast<std::size_t>(lba) * 512,
                                  r.data.size()) == 0);
            }
        }

        CHECK(std::memcmp(shadow.data(), rig.device.media().data(), shadow.size()) == 0);
        CHECK_EQ(rig.exporter.protocolErrors(), 0);
        CHECK(rig.device.commandCount() >= 1000u);
    }
}

} // namespace

int main()
{
    std::printf("test_loopback\n");
    testEnumeration();
    testScsi();
    testFaults();
    testVolume();
    TEST_MAIN_END();
}
