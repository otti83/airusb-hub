// The exporter that does not wait, and the lease that outlives its session.
//
// Everything here is a property the old code could not have had, so every case
// is written to FAIL against it rather than to pass against this one. The three
// groups:
//
//   1. ASYNCHRONY. An endpoint that never completes must not stop the session
//      answering anything else. The instrument is `IdlingPort` — an
//      `IAsyncUsbDevicePort` whose interrupt IN is accepted and then simply
//      never finished, which is exactly what a keyboard with no key pressed
//      does. Under the previous exporter these cases could not even be
//      expressed: the test would have blocked inside `bulkIn()`.
//
//   2. CANCELLATION, end to end. `CANCEL` was an opcode with no handler on one
//      side and no sender on the other.
//
//   3. OWNERSHIP. A lease has to survive the death of the session that made it,
//      because the bug it replaces was precisely that it did not.
//
// The counters are asserted, not just the verdicts. §3.10 of the handoff is
// about four bugs that survived green tests which checked a verdict and never
// the number beside it, so a cancellation here is checked for the count it
// stopped and the flag it set, not merely for arriving.

#include "../TestHarness.h"
#include "../fakes/ScriptedDevice.h"
#include "../../core/IAsyncUsbDevicePort.h"
#include "../../core/Watchdog.h"
#include "../../session/ExporterSession.h"
#include "../../session/InlineAsyncPort.h"
#include "../../session/LeaseAuthority.h"
#include "../../transport/TcpTransport.h"

#include <cstring>
#include <map>
#include <memory>
#include <string>
#include <vector>

using namespace airusb;
using namespace airusb::crypto;
using namespace airusb::protocol;
using namespace airusb::session;
using namespace airusb::transport;
using namespace airusb::fakes;

namespace {

DeviceUid uidOf(std::uint8_t seed)
{
    DeviceUid u{};
    for (std::size_t i = 0; i < u.size(); ++i) u[i] = static_cast<std::uint8_t>(seed + i);
    return u;
}

// ---------------------------------------------------------------------------
// A port that can genuinely leave a transfer unfinished.
//
// This is the instrument the whole first group depends on. `ScriptedDevice`
// always answers, so it can never demonstrate that an unanswered transfer is
// survivable; `InlineAsyncPort` says `canIdle() == false` precisely because it
// cannot host one. This can, and additionally reports `canIdle() == true`, so
// the exporter will attach a manifest with an interrupt endpoint through it.
// ---------------------------------------------------------------------------

class IdlingPort final : public IAsyncUsbDevicePort {
public:
    /// Endpoint 0x83 is interrupt IN and NEVER completes on its own, which is
    /// legal USB behaviour and is the case the redesign exists for.
    static constexpr std::uint8_t kIdleEp = 0x83;

    IdlingPort() { buildManifest(); }

    const DeviceManifest& manifest() const noexcept override { return _m; }

    Status submit(std::uint64_t token, const AsyncTransfer& t) override
    {
        Live l;
        l.epAddr = t.epAddr;
        l.dir    = t.dir;
        l.wanted = t.bufferLen;
        _live[token] = l;
        ++submits;
        return Status::Ok;
    }

    bool cancel(std::uint64_t token) override
    {
        auto it = _live.find(token);
        if (it == _live.end()) return false;
        if (!cancellable) return false;      // a backend that cannot abort
        it->second.cancelled = true;
        ++cancels;
        return true;
    }

    Status clearHalt(std::uint64_t token, std::uint8_t) override
    {
        Live l;
        l.isVerb = true;
        _live[token] = l;
        return Status::Ok;
    }

    void poll(const OnOutcome& onOutcome) override
    {
        std::vector<std::uint64_t> ready;
        for (auto& [token, l] : _live)
            if (l.cancelled || l.isVerb || l.finish) ready.push_back(token);

        for (const std::uint64_t token : ready) {
            auto it = _live.find(token);
            if (it == _live.end()) continue;
            const Live l = it->second;
            _live.erase(it);

            AsyncOutcome o;
            o.token     = token;
            o.cancelled = l.cancelled;
            o.status    = l.cancelled ? Status::XferCancelled : Status::Ok;
            o.actualLen = l.cancelled ? 0u : static_cast<std::uint32_t>(l.payload.size());
            o.dataIn    = std::span<const std::uint8_t>(l.payload.data(), l.payload.size());
            if (onOutcome) onOutcome(o);
        }
    }

    void abortAll(Status with, const OnOutcome& onOutcome) override
    {
        auto live = std::move(_live);
        _live.clear();
        for (const auto& [token, l] : live) {
            AsyncOutcome o;
            o.token  = token;
            o.status = with;
            if (onOutcome) onOutcome(o);
        }
    }

    std::size_t outstanding() const noexcept override { return _live.size(); }
    bool canIdle() const noexcept override { return true; }

    /// Lets a test finish one transfer on purpose.
    void finishNext(std::vector<std::uint8_t> payload)
    {
        for (auto& [token, l] : _live) {
            if (l.isVerb || l.cancelled) continue;
            l.finish  = true;
            l.payload = std::move(payload);
            return;
        }
    }

    bool          cancellable = true;
    std::uint64_t submits     = 0;
    std::uint64_t cancels     = 0;

private:
    struct Live {
        std::uint8_t  epAddr    = 0;
        Dir           dir       = Dir::In;
        std::uint32_t wanted    = 0;
        bool          cancelled = false;
        bool          isVerb    = false;
        bool          finish    = false;
        std::vector<std::uint8_t> payload;
    };

    void buildManifest();

    DeviceManifest                     _m;
    std::map<std::uint64_t, Live>      _live;
};

void IdlingPort::buildManifest()
{
    // A High Speed device with one interface carrying bulk IN/OUT and an
    // INTERRUPT IN. The interrupt endpoint is the whole reason it exists: it is
    // the shape the exporter could not previously carry at all.
    std::vector<std::uint8_t> dev = {
        18, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 64,
        0x8f, 0x05, 0x87, 0x63, 0x00, 0x01, 0, 0, 0, 1
    };

    std::vector<std::uint8_t> cfg = {
        9, 0x02, 0, 0, 1, 1, 0, 0x80, 50,
        9, 0x04, 0, 0, 3, 0x08, 0x06, 0x50, 0,
        7, 0x05, 0x81, 0x02, 0x00, 0x02, 0,      // bulk IN  512
        7, 0x05, 0x02, 0x02, 0x00, 0x02, 0,      // bulk OUT 512
        7, 0x05, 0x83, 0x03, 0x08, 0x00, 8,      // interrupt IN 8, interval 8
    };
    cfg[2] = static_cast<std::uint8_t>(cfg.size() & 0xFF);
    cfg[3] = static_cast<std::uint8_t>(cfg.size() >> 8);

    _m.setSpeed(Speed::High);
    _m.setDeviceDescriptor(dev);
    _m.addConfiguration(cfg);
}

// ---------------------------------------------------------------------------
// A device source over any IAsyncUsbDevicePort.
// ---------------------------------------------------------------------------

class PortSource final : public IDeviceSource {
public:
    explicit PortSource(IAsyncUsbDevicePort* p) : _p(p) {}

    std::vector<DeviceRecord> list() override
    {
        DeviceRecord r;
        r.uid   = uidOf(1);
        r.flags = kDevHasStorage | kDevShareable;
        r.name  = "Test device";
        return { r };
    }

    Status claim(const DeviceUid& u, IAsyncUsbDevicePort** portOut, DeviceManifest& m,
                 std::uint8_t* cfg, std::string* whyNot) override
    {
        if (!(u == uidOf(1))) { if (whyNot) *whyNot = "no such device"; return Status::NotFound; }
        *portOut = _p;
        m        = _p->manifest();
        if (cfg) *cfg = 1;
        ++claims;
        return Status::Ok;
    }

    void release(const DeviceUid&) override { ++releases; }

    int claims = 0, releases = 0;

private:
    IAsyncUsbDevicePort* _p;
};

// ---------------------------------------------------------------------------
// Two peers, handshaken, exporter on side B.
// ---------------------------------------------------------------------------

struct Rig {
    MemoryPipe      pipe;
    LocalIdentity   idA = LocalIdentity::generate();
    LocalIdentity   idB = LocalIdentity::generate();
    PeerStore       storeA, storeB;
    SecureSession   a, b;
    ManualClock     clock{1000};
    LeaseAuthority  leases{clock};
    ExporterSession exporter;
    bool            ok = false;
    std::uint64_t   reqId = 0;
    std::uint32_t   attachId = 0;

    explicit Rig(IDeviceSource& source)
    {
        (void)storeA.pin(idB.publicIdentity(), "B", kDefaultGrants, 1);
        (void)storeB.pin(idA.publicIdentity(), "A", kDefaultGrants, 1);
        SecureSession::Config ca; ca.initiator = true;  ca.identity = &idA; ca.peers = &storeA;
        SecureSession::Config cb; cb.initiator = false; cb.identity = &idB; cb.peers = &storeB;
        (void)a.begin(pipe.endpointA(), ca);
        (void)b.begin(pipe.endpointB(), cb);
        for (int i = 0; i < 40 && !(a.established() && b.established()); ++i) {
            (void)a.pump(); (void)b.pump();
        }
        if (!(a.established() && b.established())) return;

        ExporterSession::Config ec;
        ec.devices = &source;
        ec.clock   = &clock;
        ec.leases  = &leases;
        if (exporter.begin(&b, ec) != Status::Ok) return;
        ok = true;
    }

    /// Sends one message from A. Does NOT pump — the caller decides when the
    /// exporter runs, which is what makes "it answered while a transfer was
    /// outstanding" an observable fact rather than an assumption.
    Status send(wire::Type type, std::span<const std::uint8_t> body,
                std::uint32_t attach = 0, std::uint16_t channel = 0,
                std::uint32_t totalLen = 0, std::uint64_t* ridOut = nullptr,
                std::uint8_t extraFlags = 0)
    {
        Header h;
        h.type      = static_cast<std::uint8_t>(type);
        h.flags     = static_cast<std::uint8_t>(wire::kFlagSegFirst | extraFlags);
        h.channel   = channel;
        h.attachId  = attach;
        h.requestId = ++reqId;
        h.bodyLen   = static_cast<std::uint32_t>(body.size());
        h.totalLen  = totalLen;
        if (ridOut) *ridOut = h.requestId;

        std::vector<std::uint8_t> rec;
        encodeHeader(h, rec);
        rec.insert(rec.end(), body.begin(), body.end());
        if (const Status s = a.transport()->sendRecord(rec); s != Status::Ok) return s;
        return a.transport()->flush();
    }

    /// Reads one record from A's side, if there is one.
    bool recv(Header& h, std::vector<std::uint8_t>& body)
    {
        std::vector<std::uint8_t> in;
        const Status r = a.transport()->receiveRecord(in);
        if (r != Status::Ok || in.empty()) return false;
        if (!decodeHeader(in, h)) return false;
        body.assign(in.begin() + static_cast<std::ptrdiff_t>(wire::kHeaderSize),
                    in.begin() + static_cast<std::ptrdiff_t>(wire::kHeaderSize + h.bodyLen));
        return true;
    }

    /// Reads records until one of `type` arrives, or there are none left.
    bool recvOfType(wire::Type type, Header& h, std::vector<std::uint8_t>& body)
    {
        for (int i = 0; i < 64; ++i) {
            if (!recv(h, body)) return false;
            if (h.type == static_cast<std::uint8_t>(type)) return true;
        }
        return false;
    }

    /// ATTACH, and swallow the manifest that follows it.
    bool doAttach()
    {
        AttachBody ab;
        ab.uid = uidOf(1);
        ab.attachSlot = 1;
        std::vector<std::uint8_t> req;
        encodeAttach(ab, req);
        if (send(wire::Type::Attach, req) != Status::Ok) return false;
        (void)exporter.pump();

        Header h;
        std::vector<std::uint8_t> body;
        if (!recvOfType(wire::Type::AttachOk, h, body)) return false;
        if (static_cast<Status>(h.status) != Status::Ok) return false;
        AttachOkBody aok;
        if (!decodeAttachOk(body, aok)) return false;
        attachId = aok.attachId;
        (void)recvOfType(wire::Type::DeviceManifest, h, body);
        return attachId != 0;
    }

    std::uint16_t channelFor(std::uint8_t ep) const
    {
        return static_cast<std::uint16_t>((1 << 8) | ep);
    }

    /// A single-record SUBMIT for an IN transfer on `ep`.
    std::uint64_t submitIn(std::uint8_t ep, std::uint8_t xferType, std::uint32_t len)
    {
        SubmitBody sb;
        sb.epAddr    = ep;
        sb.xferType  = xferType;
        sb.dir       = static_cast<std::uint8_t>(wire::Dir::In);
        sb.bufferLen = len;
        std::vector<std::uint8_t> body;
        encodeSubmit(sb, body);
        std::uint64_t rid = 0;
        (void)send(wire::Type::Submit, body, attachId, channelFor(ep), 0, &rid);
        return rid;
    }
};

// ---------------------------------------------------------------------------
// 1. Asynchrony
// ---------------------------------------------------------------------------

void testIdleEndpointDoesNotBlock()
{
    std::printf("an endpoint that never answers\n");

    TEST_CASE("an interrupt IN can be outstanding while PING is answered") {
        IdlingPort port;
        PortSource src(&port);
        Rig r(src);
        CHECK(r.ok);
        CHECK(r.doAttach());

        // Submit an interrupt IN. The port accepts it and will never finish it.
        (void)r.submitIn(IdlingPort::kIdleEp,
                         static_cast<std::uint8_t>(wire::XferType::Interrupt), 8);
        (void)r.exporter.pump();
        CHECK_EQ(static_cast<long long>(port.submits), 1);
        CHECK_EQ(static_cast<long long>(r.exporter.inFlightTransfers()), 1);

        // Now PING. Under the old exporter this record could not have been read
        // at all: the session was inside bulkIn() and would never return.
        PingBody p;
        p.pingTsNs = 42;
        std::vector<std::uint8_t> pb;
        encodePing(p, pb);
        CHECK(r.send(wire::Type::Ping, pb) == Status::Ok);
        CHECK(r.exporter.pump() == Status::Ok);

        Header h;
        std::vector<std::uint8_t> body;
        CHECK(r.recvOfType(wire::Type::Pong, h, body));
        PingBody pong;
        CHECK(decodePing(body, pong));
        CHECK_EQ(static_cast<long long>(pong.pingTsNs), 42);

        // And the transfer really is still outstanding — the PONG did not come
        // from a session that had given up on it.
        CHECK_EQ(static_cast<long long>(r.exporter.inFlightTransfers()), 1);
    }

    TEST_CASE("DETACH completes an idling transfer rather than waiting for it") {
        IdlingPort port;
        PortSource src(&port);
        Rig r(src);
        CHECK(r.ok);
        CHECK(r.doAttach());

        const std::uint64_t rid =
            r.submitIn(IdlingPort::kIdleEp,
                       static_cast<std::uint8_t>(wire::XferType::Interrupt), 8);
        (void)r.exporter.pump();
        CHECK_EQ(static_cast<long long>(r.exporter.inFlightTransfers()), 1);

        DetachBody db;
        std::vector<std::uint8_t> dbody;
        encodeDetach(db, dbody);
        CHECK(r.send(wire::Type::Detach, dbody, r.attachId) == Status::Ok);
        CHECK(r.exporter.pump() == Status::Ok);

        // The idling transfer got a terminal answer. Invariant I1: nothing the
        // peer is waiting on may evaporate, even at teardown.
        Header h;
        std::vector<std::uint8_t> body;
        CHECK(r.recvOfType(wire::Type::Complete, h, body));
        CHECK_EQ(static_cast<long long>(h.requestId), static_cast<long long>(rid));
        CompleteBody cb;
        CHECK(decodeComplete(body, cb));
        CHECK(cb.wasCancelled());

        CHECK(r.recvOfType(wire::Type::DetachOk, h, body));
        DetachOkBody ok;
        CHECK(decodeDetachOk(body, ok));
        CHECK_EQ(static_cast<long long>(ok.urbsCancelled), 1);
        CHECK_EQ(static_cast<long long>(r.exporter.inFlightTransfers()), 0);
    }

    TEST_CASE("a second transfer on a busy endpoint QUEUES rather than racing") {
        IdlingPort port;
        PortSource src(&port);
        Rig r(src);
        CHECK(r.ok);
        CHECK(r.doAttach());

        (void)r.submitIn(0x81, static_cast<std::uint8_t>(wire::XferType::Bulk), 64);
        (void)r.submitIn(0x81, static_cast<std::uint8_t>(wire::XferType::Bulk), 64);
        (void)r.exporter.pump();

        // USB serialises per endpoint. Exactly one reached the device.
        CHECK_EQ(static_cast<long long>(port.submits), 1);
        CHECK_EQ(static_cast<long long>(r.exporter.inFlightTransfers()), 1);
        CHECK_EQ(static_cast<long long>(r.exporter.queuedTransfers()), 1);

        // Finish the first; the second is admitted on the next pump.
        port.finishNext(std::vector<std::uint8_t>(4, 0xAB));
        (void)r.exporter.pump();
        CHECK_EQ(static_cast<long long>(port.submits), 2);
        CHECK_EQ(static_cast<long long>(r.exporter.queuedTransfers()), 0);
    }

    TEST_CASE("ep0 is a barrier: no control transfer while a data one is on the bus") {
        IdlingPort port;
        PortSource src(&port);
        Rig r(src);
        CHECK(r.ok);
        CHECK(r.doAttach());

        (void)r.submitIn(0x81, static_cast<std::uint8_t>(wire::XferType::Bulk), 64);
        (void)r.exporter.pump();
        CHECK_EQ(static_cast<long long>(port.submits), 1);

        // A control transfer may change the configuration, which redefines what
        // 0x81 even is. It waits.
        SubmitBody sb;
        sb.epAddr    = 0;
        sb.xferType  = static_cast<std::uint8_t>(wire::XferType::Control);
        sb.dir       = static_cast<std::uint8_t>(wire::Dir::In);
        sb.bufferLen = 8;
        sb.setup[0]  = 0x80;
        sb.setup[1]  = 0x06;
        sb.setup[6]  = 8;
        std::vector<std::uint8_t> body;
        encodeSubmit(sb, body);
        (void)r.send(wire::Type::Submit, body, r.attachId, r.channelFor(0));
        (void)r.exporter.pump();

        CHECK_EQ(static_cast<long long>(port.submits), 1);
        CHECK_EQ(static_cast<long long>(r.exporter.queuedTransfers()), 1);

        port.finishNext(std::vector<std::uint8_t>(4, 0x11));
        (void)r.exporter.pump();
        CHECK_EQ(static_cast<long long>(port.submits), 2);
    }
}

// ---------------------------------------------------------------------------
// 2. Cancellation
// ---------------------------------------------------------------------------

void testCancel()
{
    std::printf("CANCEL, which used to be an opcode with no handler\n");

    TEST_CASE("cancelling a transfer on the bus reports it cancelled, once") {
        IdlingPort port;
        PortSource src(&port);
        Rig r(src);
        CHECK(r.ok);
        CHECK(r.doAttach());

        const std::uint64_t rid =
            r.submitIn(IdlingPort::kIdleEp,
                       static_cast<std::uint8_t>(wire::XferType::Interrupt), 8);
        (void)r.exporter.pump();
        CHECK_EQ(static_cast<long long>(r.exporter.inFlightTransfers()), 1);

        CancelBody cb;
        cb.targetRequestId = rid;
        cb.epAddr          = IdlingPort::kIdleEp;
        cb.scope           = static_cast<std::uint8_t>(CancelScope::Request);
        std::vector<std::uint8_t> body;
        encodeCancel(cb, body);
        CHECK(r.send(wire::Type::Cancel, body, r.attachId,
                     r.channelFor(IdlingPort::kIdleEp)) == Status::Ok);
        CHECK(r.exporter.pump() == Status::Ok);

        CHECK_EQ(static_cast<long long>(port.cancels), 1);

        Header h;
        std::vector<std::uint8_t> rb;
        CHECK(r.recvOfType(wire::Type::CancelAck, h, rb));
        CancelAckBody ack;
        CHECK(decodeCancelAck(rb, ack));
        // The COUNT, not just the arrival. A CANCEL_ACK that says nothing about
        // how many it stopped is the shape of evidence §3.10 is about.
        CHECK_EQ(static_cast<long long>(ack.cancelledCount), 1);
        CHECK_EQ(static_cast<long long>(ack.granularity),
                 static_cast<long long>(CancelScope::Request));

        CHECK(r.recvOfType(wire::Type::Complete, h, rb));
        CHECK_EQ(static_cast<long long>(h.requestId), static_cast<long long>(rid));
        CompleteBody done;
        CHECK(decodeComplete(rb, done));
        CHECK(done.wasCancelled());
        CHECK(static_cast<Status>(h.status) == Status::XferCancelled);

        // Exactly one terminal outcome. A second COMPLETE for the same id would
        // be the double-completion bug this invariant exists to exclude.
        CHECK(!r.recvOfType(wire::Type::Complete, h, rb));
        CHECK_EQ(static_cast<long long>(r.exporter.inFlightTransfers()), 0);
    }

    TEST_CASE("cancelling a QUEUED transfer retires it without touching the device") {
        IdlingPort port;
        PortSource src(&port);
        Rig r(src);
        CHECK(r.ok);
        CHECK(r.doAttach());

        (void)r.submitIn(0x81, static_cast<std::uint8_t>(wire::XferType::Bulk), 64);
        const std::uint64_t queued =
            r.submitIn(0x81, static_cast<std::uint8_t>(wire::XferType::Bulk), 64);
        (void)r.exporter.pump();
        CHECK_EQ(static_cast<long long>(r.exporter.queuedTransfers()), 1);

        const std::uint64_t submitsBefore = port.submits;

        CancelBody cb;
        cb.targetRequestId = queued;
        cb.epAddr          = 0x81;
        cb.scope           = static_cast<std::uint8_t>(CancelScope::Request);
        std::vector<std::uint8_t> body;
        encodeCancel(cb, body);
        (void)r.send(wire::Type::Cancel, body, r.attachId, r.channelFor(0x81));
        (void)r.exporter.pump();

        // The device never saw it, so this is the unambiguous case: nothing
        // physical happened and nothing has to be recovered.
        CHECK_EQ(static_cast<long long>(port.submits),
                 static_cast<long long>(submitsBefore));
        CHECK_EQ(static_cast<long long>(port.cancels), 0);
        CHECK_EQ(static_cast<long long>(r.exporter.queuedTransfers()), 0);

        Header h;
        std::vector<std::uint8_t> rb;
        CHECK(r.recvOfType(wire::Type::Complete, h, rb));
        CHECK_EQ(static_cast<long long>(h.requestId), static_cast<long long>(queued));
        CompleteBody done;
        CHECK(decodeComplete(rb, done));
        CHECK(done.wasCancelled());
    }

    TEST_CASE("a backend that cannot abort says so: count 0, and the slot stays held") {
        IdlingPort port;
        port.cancellable = false;            // like a synchronous capture backend
        PortSource src(&port);
        Rig r(src);
        CHECK(r.ok);
        CHECK(r.doAttach());

        const std::uint64_t rid =
            r.submitIn(IdlingPort::kIdleEp,
                       static_cast<std::uint8_t>(wire::XferType::Interrupt), 8);
        (void)r.exporter.pump();

        CancelBody cb;
        cb.targetRequestId = rid;
        cb.epAddr          = IdlingPort::kIdleEp;
        cb.scope           = static_cast<std::uint8_t>(CancelScope::Request);
        std::vector<std::uint8_t> body;
        encodeCancel(cb, body);
        (void)r.send(wire::Type::Cancel, body, r.attachId,
                     r.channelFor(IdlingPort::kIdleEp));
        (void)r.exporter.pump();

        Header h;
        std::vector<std::uint8_t> rb;
        CHECK(r.recvOfType(wire::Type::CancelAck, h, rb));
        CancelAckBody ack;
        CHECK(decodeCancelAck(rb, ack));
        // ZERO. The honest answer, and the one that tells the importer the
        // physical transfer is still running.
        CHECK_EQ(static_cast<long long>(ack.cancelledCount), 0);

        // The endpoint stays reserved. Starting another transfer on an endpoint
        // whose previous one is still physically running is how a Bulk-Only
        // Transport phase machine desynchronises.
        CHECK_EQ(static_cast<long long>(r.exporter.inFlightTransfers()), 1);
    }

    TEST_CASE("a deadline on an un-abortable transfer does not wedge its endpoint") {
        // The case that leaked, and that 149 green checks did not notice.
        //
        // `sweepDeadlines` answers a transfer the port could not cancel and
        // removes it from the in-flight table while DELIBERATELY leaving the
        // endpoint reserved — the physical transfer really is still running.
        // The port's eventual outcome then found nothing in the table and
        // returned early WITHOUT freeing the endpoint, so every later transfer
        // on it queued behind a slot nobody owned. Throughput on that endpoint
        // goes to zero with nothing looking broken, which is the same shape as
        // the cancellation bug §3.10 records.
        IdlingPort port;
        port.cancellable = false;
        PortSource src(&port);
        Rig r(src);
        CHECK(r.ok);
        CHECK(r.doAttach());

        // Bulk, so it has a deadline at all; an interrupt IN deliberately has none.
        (void)r.submitIn(0x81, static_cast<std::uint8_t>(wire::XferType::Bulk), 64);
        (void)r.exporter.pump();
        CHECK_EQ(static_cast<long long>(r.exporter.inFlightTransfers()), 1);

        // Past the bulk ceiling. The sweep answers the peer and keeps the
        // endpoint reserved.
        r.clock.advanceMs(watchdog::kUrbCeilingBulk + 1000);
        (void)r.exporter.pump();
        CHECK_EQ(static_cast<long long>(r.exporter.inFlightTransfers()), 0);

        Header h;
        std::vector<std::uint8_t> rb;
        CHECK(r.recvOfType(wire::Type::Complete, h, rb));
        CHECK(static_cast<Status>(h.status) == Status::XferTimeout);

        // Now the device finishes on its own, late. Its outcome matches nothing
        // and is dropped — but it MUST release the endpoint.
        port.finishNext(std::vector<std::uint8_t>(8, 0x22));
        (void)r.exporter.pump();

        // No PING is needed, and that is itself the point: the clock moved past
        // the LEASE timer too, and the session survived because we owed this
        // peer an answer the whole time.
        CHECK(r.exporter.state() == ExporterSession::State::Leased);

        // And the proof: a fresh transfer on that endpoint reaches the device.
        const std::uint64_t before = port.submits;
        (void)r.submitIn(0x81, static_cast<std::uint8_t>(wire::XferType::Bulk), 64);
        (void)r.exporter.pump();
        CHECK_EQ(static_cast<long long>(port.submits),
                 static_cast<long long>(before + 1));
        CHECK_EQ(static_cast<long long>(r.exporter.queuedTransfers()), 0);
    }

    TEST_CASE("a slow transfer does not trip the lease timer under the peer") {
        // The bug this case exists for was found BY a test written for a
        // different one, which is worth recording: T_urb_ceiling_bulk is 30 s
        // and T_lease_exporter is 20 s, and an importer waiting for a transfer
        // it already submitted is silent by design. So a cheap flash stick
        // doing garbage collection on one WRITE(10) — 8-12 s legitimately, and
        // macOS allows 30 — would have quarantined the drive MID-WRITE on a
        // peer that was never absent.
        IdlingPort port;
        PortSource src(&port);
        Rig r(src);
        CHECK(r.ok);
        CHECK(r.doAttach());

        (void)r.submitIn(0x81, static_cast<std::uint8_t>(wire::XferType::Bulk), 64);
        (void)r.exporter.pump();
        CHECK_EQ(static_cast<long long>(r.exporter.inFlightTransfers()), 1);

        // Well past the lease timer, and still inside the URB ceiling.
        r.clock.advanceMs(watchdog::kLeaseExporter + 5000);
        (void)r.exporter.pump();

        // Still leased, still working. Quarantining here would hand the drive
        // to nobody while its owner waited for an answer we owed it.
        CHECK(r.exporter.state() == ExporterSession::State::Leased);
        CHECK(r.leases.state() == LeaseState::Leased);
        CHECK_EQ(static_cast<long long>(r.exporter.inFlightTransfers()), 1);

        // And the device answers, as it was always going to.
        port.finishNext(std::vector<std::uint8_t>(64, 0x44));
        (void)r.exporter.pump();
        Header h;
        std::vector<std::uint8_t> rb;
        CHECK(r.recvOfType(wire::Type::Complete, h, rb));
        CHECK(static_cast<Status>(h.status) == Status::Ok);
    }

    TEST_CASE("but silence with NOTHING outstanding does quarantine") {
        // The other half. The suppression above must not turn the lease timer
        // off; it must only stop it firing while we owe an answer.
        IdlingPort port;
        PortSource src(&port);
        Rig r(src);
        CHECK(r.ok);
        CHECK(r.doAttach());
        CHECK(r.leases.state() == LeaseState::Leased);

        r.clock.advanceMs(watchdog::kLeaseExporter + 1000);
        (void)r.exporter.pump();

        CHECK(r.exporter.state() == ExporterSession::State::Orphaned);
        CHECK(r.leases.state() == LeaseState::Quarantined);
    }

    TEST_CASE("an un-abortable transfer that finishes normally is NOT reported cancelled") {
        // `kCfWasCancelled` says the transfer WAS cancelled. A backend that
        // could not abort, whose device then completed the transfer, has not
        // cancelled anything — and real data beside a cancelled flag is a
        // contradiction the importer cannot act on.
        IdlingPort port;
        port.cancellable = false;
        PortSource src(&port);
        Rig r(src);
        CHECK(r.ok);
        CHECK(r.doAttach());

        const std::uint64_t rid =
            r.submitIn(0x81, static_cast<std::uint8_t>(wire::XferType::Bulk), 64);
        (void)r.exporter.pump();

        CancelBody cb;
        cb.targetRequestId = rid;
        cb.epAddr          = 0x81;
        cb.scope           = static_cast<std::uint8_t>(CancelScope::Request);
        std::vector<std::uint8_t> body;
        encodeCancel(cb, body);
        (void)r.send(wire::Type::Cancel, body, r.attachId, r.channelFor(0x81));
        (void)r.exporter.pump();

        Header h;
        std::vector<std::uint8_t> rb;
        CHECK(r.recvOfType(wire::Type::CancelAck, h, rb));

        // The device finishes anyway.
        port.finishNext(std::vector<std::uint8_t>(4, 0x33));
        (void)r.exporter.pump();

        CHECK(r.recvOfType(wire::Type::Complete, h, rb));
        CompleteBody done;
        CHECK(decodeComplete(rb, done));
        CHECK(!done.wasCancelled());
        CHECK(static_cast<Status>(h.status) == Status::Ok);
    }

    TEST_CASE("a cancel that names two different endpoints is refused") {
        IdlingPort port;
        PortSource src(&port);
        Rig r(src);
        CHECK(r.ok);
        CHECK(r.doAttach());

        CancelBody cb;
        cb.targetRequestId = 1;
        cb.epAddr          = 0x81;           // body says 0x81
        cb.scope           = static_cast<std::uint8_t>(CancelScope::Request);
        std::vector<std::uint8_t> body;
        encodeCancel(cb, body);
        (void)r.send(wire::Type::Cancel, body, r.attachId,
                     r.channelFor(0x02));    // channel says 0x02
        (void)r.exporter.pump();

        Header h;
        std::vector<std::uint8_t> rb;
        CHECK(r.recvOfType(wire::Type::Error, h, rb));
        CHECK(static_cast<Status>(h.status) == Status::BadArgument);
    }

    TEST_CASE("ENDPOINT scope stops every transfer on that endpoint") {
        IdlingPort port;
        PortSource src(&port);
        Rig r(src);
        CHECK(r.ok);
        CHECK(r.doAttach());

        (void)r.submitIn(0x81, static_cast<std::uint8_t>(wire::XferType::Bulk), 64);
        (void)r.submitIn(0x81, static_cast<std::uint8_t>(wire::XferType::Bulk), 64);
        (void)r.exporter.pump();
        CHECK_EQ(static_cast<long long>(r.exporter.inFlightTransfers()), 1);
        CHECK_EQ(static_cast<long long>(r.exporter.queuedTransfers()), 1);

        CancelBody cb;
        cb.epAddr = 0x81;
        cb.scope  = static_cast<std::uint8_t>(CancelScope::Endpoint);
        std::vector<std::uint8_t> body;
        encodeCancel(cb, body);
        (void)r.send(wire::Type::Cancel, body, r.attachId, r.channelFor(0x81));
        (void)r.exporter.pump();

        Header h;
        std::vector<std::uint8_t> rb;
        CHECK(r.recvOfType(wire::Type::CancelAck, h, rb));
        CancelAckBody ack;
        CHECK(decodeCancelAck(rb, ack));
        CHECK_EQ(static_cast<long long>(ack.cancelledCount), 2);   // queued + in flight
        CHECK_EQ(static_cast<long long>(r.exporter.queuedTransfers()), 0);
    }
}

// ---------------------------------------------------------------------------
// 3. Ownership
// ---------------------------------------------------------------------------

void testLeaseAuthority()
{
    std::printf("the lease that outlives its session\n");

    LocalIdentity alice = LocalIdentity::generate();
    LocalIdentity bob   = LocalIdentity::generate();
    const PublicKey a = alice.publicIdentity().identityKey;
    const PublicKey b = bob.publicIdentity().identityKey;

    TEST_CASE("a free device may be claimed by anyone permitted") {
        ManualClock c{0};
        LeaseAuthority la(c);
        CHECK(la.mayClaim(a, uidOf(1), nullptr) == Status::Ok);
        CHECK(la.state() == LeaseState::Free);
    }

    TEST_CASE("silence QUARANTINES rather than freeing, and B is refused") {
        ManualClock c{0};
        LeaseAuthority la(c);
        const std::uint32_t id = la.grant(a, uidOf(1), nullptr);
        CHECK(id != 0);
        CHECK(la.state() == LeaseState::Leased);

        // A goes quiet. This is the exact sequence that used to hand B the drive.
        la.quarantine();
        CHECK(la.state() == LeaseState::Quarantined);

        std::string why;
        CHECK(la.mayClaim(b, uidOf(1), &why) == Status::ExclusivityDenied);
        CHECK(!why.empty());
        // And it stays refused. A quarantined lease is not a grace period: it
        // never decays into availability, however long it waits.
        c.advanceMs(60 * 60 * 1000);
        CHECK(la.mayClaim(b, uidOf(1), nullptr) == Status::ExclusivityDenied);
    }

    TEST_CASE("the lease timer expires into quarantine, not into free") {
        ManualClock c{0};
        LeaseAuthority la(c);
        (void)la.grant(a, uidOf(1), nullptr);
        CHECK(!la.silenceExpired());
        c.advanceMs(watchdog::kLeaseExporter - 1);
        CHECK(!la.silenceExpired());
        c.advanceMs(2);
        CHECK(la.silenceExpired());

        la.quarantine();
        CHECK(la.state() == LeaseState::Quarantined);
        CHECK(la.mayClaim(b, uidOf(1), nullptr) != Status::Ok);
    }

    TEST_CASE("the owner recovers with its token; the incarnation moves") {
        ManualClock c{0};
        LeaseAuthority la(c);
        RecoveryToken token{};
        const std::uint32_t first = la.grant(a, uidOf(1), &token);
        const std::uint16_t inc0  = la.incarnation();
        la.quarantine();

        std::uint32_t second = 0;
        RecoveryToken next{};
        CHECK(la.tryRecover(a, token, &second, &next) == Status::Ok);
        CHECK(la.state() == LeaseState::Leased);
        // A NEW attach id and a bumped incarnation: ownership is recovered,
        // execution history is not, and the guest re-enumerates cleanly.
        CHECK(second != first);
        CHECK(la.incarnation() != inc0);
    }

    TEST_CASE("a different peer cannot recover, even with the right token") {
        ManualClock c{0};
        LeaseAuthority la(c);
        RecoveryToken token{};
        (void)la.grant(a, uidOf(1), &token);
        la.quarantine();
        CHECK(la.tryRecover(b, token, nullptr, nullptr) == Status::NotPermitted);
        CHECK(la.state() == LeaseState::Quarantined);
    }

    TEST_CASE("a recovery token is single use") {
        ManualClock c{0};
        LeaseAuthority la(c);
        RecoveryToken token{};
        (void)la.grant(a, uidOf(1), &token);
        la.quarantine();
        CHECK(la.tryRecover(a, token, nullptr, nullptr) == Status::Ok);
        la.quarantine();
        // The same bytes again. A replay of the last recovery message must not
        // work, which is why tryRecover mints a fresh token on success.
        CHECK(la.tryRecover(a, token, nullptr, nullptr) == Status::NotPermitted);
    }

    TEST_CASE("only the owner's DETACH frees it") {
        ManualClock c{0};
        LeaseAuthority la(c);
        (void)la.grant(a, uidOf(1), nullptr);
        la.release(b);                       // not yours to give away
        CHECK(la.state() == LeaseState::Leased);
        la.release(a);
        CHECK(la.state() == LeaseState::Free);
        CHECK(la.mayClaim(b, uidOf(1), nullptr) == Status::Ok);
    }

    TEST_CASE("a person at the machine can take it back, and the token dies with it") {
        ManualClock c{0};
        LeaseAuthority la(c);
        RecoveryToken token{};
        (void)la.grant(a, uidOf(1), &token);
        la.quarantine();
        la.forceReclaim();
        CHECK(la.state() == LeaseState::Free);
        CHECK(la.mayClaim(b, uidOf(1), nullptr) == Status::Ok);
        CHECK(la.tryRecover(a, token, nullptr, nullptr) == Status::NotFound);
    }

    TEST_CASE("hearing from the owner heals a quarantine without a new attach id") {
        ManualClock c{0};
        LeaseAuthority la(c);
        const std::uint32_t id = la.grant(a, uidOf(1), nullptr);
        la.quarantine();
        la.heard(a);
        CHECK(la.state() == LeaseState::Leased);
        CHECK_EQ(static_cast<long long>(la.attachId()), static_cast<long long>(id));
        // Somebody else being heard from changes nothing at all.
        la.quarantine();
        la.heard(b);
        CHECK(la.state() == LeaseState::Quarantined);
    }
}

void testLeaseAcrossSessions()
{
    std::printf("the exporter refuses a second peer after the first vanished\n");

    TEST_CASE("a new session cannot take a quarantined device") {
        ScriptedDevice dev{64, 512};
        InlineAsyncPort async(dev);
        PortSource src(&async);

        ManualClock clock{1000};
        LeaseAuthority leases(clock);

        LocalIdentity idA = LocalIdentity::generate();   // the first importer
        LocalIdentity idC = LocalIdentity::generate();   // a different importer
        LocalIdentity idB = LocalIdentity::generate();   // the exporter

        // Session one: A attaches, then the transport dies.
        {
            MemoryPipe pipe;
            PeerStore storeA, storeB;
            (void)storeA.pin(idB.publicIdentity(), "B", kDefaultGrants, 1);
            (void)storeB.pin(idA.publicIdentity(), "A", kDefaultGrants, 1);
            SecureSession a, b;
            SecureSession::Config ca; ca.initiator = true;  ca.identity = &idA; ca.peers = &storeA;
            SecureSession::Config cb; cb.initiator = false; cb.identity = &idB; cb.peers = &storeB;
            (void)a.begin(pipe.endpointA(), ca);
            (void)b.begin(pipe.endpointB(), cb);
            for (int i = 0; i < 40 && !(a.established() && b.established()); ++i) {
                (void)a.pump(); (void)b.pump();
            }
            CHECK(a.established() && b.established());

            ExporterSession ex;
            ExporterSession::Config ec;
            ec.devices = &src; ec.clock = &clock; ec.leases = &leases;
            CHECK(ex.begin(&b, ec) == Status::Ok);

            AttachBody ab; ab.uid = uidOf(1); ab.attachSlot = 1;
            std::vector<std::uint8_t> req; encodeAttach(ab, req);
            Header h; h.type = static_cast<std::uint8_t>(wire::Type::Attach);
            h.flags = wire::kFlagSegFirst; h.requestId = 1;
            h.bodyLen = static_cast<std::uint32_t>(req.size());
            std::vector<std::uint8_t> rec; encodeHeader(h, rec);
            rec.insert(rec.end(), req.begin(), req.end());
            CHECK(a.transport()->sendRecord(rec) == Status::Ok);
            CHECK(a.transport()->flush() == Status::Ok);
            CHECK(ex.pump() == Status::Ok);
            CHECK(ex.state() == ExporterSession::State::Leased);
            CHECK(leases.state() == LeaseState::Leased);

            // A's machine goes away mid-session. THIS is the sequence: the old
            // code marked the session Orphaned and then destroyed it.
            a.transport()->close();
            (void)ex.pump();
            CHECK(ex.state() == ExporterSession::State::Orphaned);
            ex.close();
        }

        // The session object is gone. The ownership is not.
        CHECK(leases.state() == LeaseState::Quarantined);

        // Session two: a DIFFERENT paired importer connects and asks for it.
        {
            MemoryPipe pipe;
            PeerStore storeC, storeB;
            (void)storeC.pin(idB.publicIdentity(), "B", kDefaultGrants, 1);
            (void)storeB.pin(idC.publicIdentity(), "C", kDefaultGrants, 1);
            SecureSession c, b;
            SecureSession::Config cc; cc.initiator = true;  cc.identity = &idC; cc.peers = &storeC;
            SecureSession::Config cb; cb.initiator = false; cb.identity = &idB; cb.peers = &storeB;
            (void)c.begin(pipe.endpointA(), cc);
            (void)b.begin(pipe.endpointB(), cb);
            for (int i = 0; i < 40 && !(c.established() && b.established()); ++i) {
                (void)c.pump(); (void)b.pump();
            }
            CHECK(c.established() && b.established());

            ExporterSession ex;
            ExporterSession::Config ec;
            ec.devices = &src; ec.clock = &clock; ec.leases = &leases;
            CHECK(ex.begin(&b, ec) == Status::Ok);

            AttachBody ab; ab.uid = uidOf(1); ab.attachSlot = 1;
            std::vector<std::uint8_t> req; encodeAttach(ab, req);
            Header h; h.type = static_cast<std::uint8_t>(wire::Type::Attach);
            h.flags = wire::kFlagSegFirst; h.requestId = 1;
            h.bodyLen = static_cast<std::uint32_t>(req.size());
            std::vector<std::uint8_t> rec; encodeHeader(h, rec);
            rec.insert(rec.end(), req.begin(), req.end());
            CHECK(c.transport()->sendRecord(rec) == Status::Ok);
            CHECK(c.transport()->flush() == Status::Ok);
            CHECK(ex.pump() == Status::Ok);

            // REFUSED. This is the assertion the whole file exists for.
            CHECK(ex.state() == ExporterSession::State::Idle);

            std::vector<std::uint8_t> in;
            CHECK(c.transport()->receiveRecord(in) == Status::Ok);
            Header rh;
            CHECK(decodeHeader(in, rh));
            CHECK_EQ(rh.type, static_cast<std::uint8_t>(wire::Type::AttachOk));
            CHECK(static_cast<Status>(rh.status) == Status::ExclusivityDenied);
        }
    }
}

// ---------------------------------------------------------------------------
// 4. Transfer flags, which were decoded and then dropped
// ---------------------------------------------------------------------------

/// A bulk device that records every OUT it is given, including empty ones.
class RecordingDevice final : public IUsbDevicePort {
public:
    RecordingDevice()
    {
        std::vector<std::uint8_t> dev = {
            18, 0x01, 0x00, 0x02, 0, 0, 0, 64,
            0x8f, 0x05, 0x87, 0x63, 0, 1, 0, 0, 0, 1
        };
        std::vector<std::uint8_t> cfg = {
            9, 0x02, 0, 0, 1, 1, 0, 0x80, 50,
            9, 0x04, 0, 0, 2, 0x08, 0x06, 0x50, 0,
            7, 0x05, 0x81, 0x02, 0x00, 0x02, 0,    // bulk IN,  wMaxPacketSize 512
            7, 0x05, 0x02, 0x02, 0x00, 0x02, 0,    // bulk OUT, wMaxPacketSize 512
        };
        cfg[2] = static_cast<std::uint8_t>(cfg.size() & 0xFF);
        cfg[3] = static_cast<std::uint8_t>(cfg.size() >> 8);
        _m.setSpeed(Speed::High);
        _m.setDeviceDescriptor(dev);
        _m.addConfiguration(cfg);
    }

    const DeviceManifest& manifest() const noexcept override { return _m; }
    Status controlTransfer(const SetupPacket&, std::span<const std::uint8_t>,
                           std::vector<std::uint8_t>&) override { return Status::Ok; }
    Status bulkOut(std::uint8_t, std::span<const std::uint8_t> d,
                   std::uint32_t* n) override
    {
        outLengths.push_back(static_cast<std::uint32_t>(d.size()));
        if (n) *n = static_cast<std::uint32_t>(d.size());
        return Status::Ok;
    }
    Status bulkIn(std::uint8_t, std::uint32_t maxLen,
                  std::vector<std::uint8_t>& out) override
    {
        out.assign(maxLen > shortBy ? maxLen - shortBy : 0, 0x5A);
        return Status::Ok;
    }
    Status clearHalt(std::uint8_t) override { return Status::Ok; }

    std::vector<std::uint32_t> outLengths;
    std::uint32_t shortBy = 0;

private:
    DeviceManifest _m;
};

void testTransferFlags()
{
    std::printf("xflags, which were on the wire and read by nobody\n");

    TEST_CASE("ZERO_PACKET sends the terminating ZLP after an exact multiple") {
        RecordingDevice dev;
        InlineAsyncPort port(dev);

        AsyncTransfer t;
        t.epAddr     = 0x02;
        t.xferType   = XferType::Bulk;
        t.dir        = Dir::Out;
        std::vector<std::uint8_t> data(512, 0x11);      // exactly wMaxPacketSize
        t.dataOut    = data;
        t.bufferLen  = 512;
        t.zeroPacket = true;
        CHECK(port.submit(1, t) == Status::Ok);

        bool zlp = false;
        port.poll([&](const AsyncOutcome& o) { zlp = o.zlpSent; });
        CHECK(zlp);
        CHECK_EQ(static_cast<long long>(dev.outLengths.size()), 2);
        CHECK_EQ(static_cast<long long>(dev.outLengths[0]), 512);
        CHECK_EQ(static_cast<long long>(dev.outLengths[1]), 0);
    }

    TEST_CASE("ZERO_PACKET sends nothing extra after a short final packet") {
        RecordingDevice dev;
        InlineAsyncPort port(dev);

        AsyncTransfer t;
        t.epAddr     = 0x02;
        t.xferType   = XferType::Bulk;
        t.dir        = Dir::Out;
        std::vector<std::uint8_t> data(500, 0x11);      // NOT a multiple of 512
        t.dataOut    = data;
        t.bufferLen  = 500;
        t.zeroPacket = true;
        CHECK(port.submit(1, t) == Status::Ok);

        bool zlp = true;
        port.poll([&](const AsyncOutcome& o) { zlp = o.zlpSent; });
        CHECK(!zlp);
        CHECK_EQ(static_cast<long long>(dev.outLengths.size()), 1);
    }

    TEST_CASE("SHORT_NOT_OK turns a short IN into an error, and its absence does not") {
        RecordingDevice dev;
        dev.shortBy = 8;
        InlineAsyncPort port(dev);

        AsyncTransfer t;
        t.epAddr    = 0x81;
        t.xferType  = XferType::Bulk;
        t.dir       = Dir::In;
        t.bufferLen = 64;

        t.shortNotOk = false;
        CHECK(port.submit(1, t) == Status::Ok);
        Status got = Status::Internal;
        port.poll([&](const AsyncOutcome& o) { got = o.status; });
        CHECK(got == Status::Ok);           // Linux's rule: short is success

        t.shortNotOk = true;
        CHECK(port.submit(2, t) == Status::Ok);
        port.poll([&](const AsyncOutcome& o) { got = o.status; });
        CHECK(got == Status::XferShort);    // Windows lets the guest say otherwise
    }
}

// ---------------------------------------------------------------------------
// 5. The endpoint scan that stopped at interface 31
// ---------------------------------------------------------------------------

void testEndpointLookupRange()
{
    std::printf("an endpoint on a high-numbered interface\n");

    TEST_CASE("findEndpoint sees interface 200, which the 0..31 scan could not") {
        DeviceManifest m;
        std::vector<std::uint8_t> dev = {
            18, 0x01, 0x00, 0x02, 0, 0, 0, 64,
            0x8f, 0x05, 0x87, 0x63, 0, 1, 0, 0, 0, 1
        };
        std::vector<std::uint8_t> cfg = {
            9, 0x02, 0, 0, 1, 1, 0, 0x80, 50,
            9, 0x04, 200, 0, 1, 0xFF, 0, 0, 0,     // bInterfaceNumber = 200
            7, 0x05, 0x84, 0x02, 0x00, 0x02, 0,    // bulk IN 0x84
        };
        cfg[2] = static_cast<std::uint8_t>(cfg.size() & 0xFF);
        cfg[3] = static_cast<std::uint8_t>(cfg.size() >> 8);
        m.setSpeed(Speed::High);
        m.setDeviceDescriptor(dev);
        m.addConfiguration(cfg);

        EndpointModel ep;
        CHECK(m.findEndpoint(1, 0x84, nullptr, ep));
        CHECK_EQ(static_cast<long long>(ep.maxPacketSize), 512);
        CHECK(ep.type == XferType::Bulk);

        // And an address that is not there is still not there.
        CHECK(!m.findEndpoint(1, 0x85, nullptr, ep));
    }

    TEST_CASE("a SuperSpeed companion is picked up with its endpoint") {
        DeviceManifest m;
        std::vector<std::uint8_t> dev = {
            18, 0x01, 0x00, 0x03, 0, 0, 0, 9,
            0x8f, 0x05, 0x87, 0x63, 0, 1, 0, 0, 0, 1
        };
        std::vector<std::uint8_t> cfg = {
            9, 0x02, 0, 0, 1, 1, 0, 0x80, 50,
            9, 0x04, 0, 0, 1, 0x08, 0x06, 0x50, 0,
            7, 0x05, 0x81, 0x02, 0x00, 0x04, 0,     // bulk IN 1024
            6, 0x30, 15, 0, 0, 0,                   // SS companion, bMaxBurst 15
        };
        cfg[2] = static_cast<std::uint8_t>(cfg.size() & 0xFF);
        cfg[3] = static_cast<std::uint8_t>(cfg.size() >> 8);
        m.setSpeed(Speed::Super);
        m.setDeviceDescriptor(dev);
        m.addConfiguration(cfg);

        EndpointModel ep;
        CHECK(m.findEndpoint(1, 0x81, nullptr, ep));
        CHECK_EQ(static_cast<long long>(ep.maxPacketSize), 1024);
        // Without this the burst size is lost and a SuperSpeed device is driven
        // as if it were USB 2.
        CHECK_EQ(static_cast<long long>(ep.maxBurst), 15);
    }
}

} // namespace

int main()
{
    testIdleEndpointDoesNotBlock();
    testCancel();
    testLeaseAuthority();
    testLeaseAcrossSessions();
    testTransferFlags();
    testEndpointLookupRange();
    TEST_MAIN_END();
}
