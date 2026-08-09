// The Windows translation layer, with no Windows and no driver.
//
// This is the same test `test_netbridge` is for Linux, and it exists for a
// sharper version of the same reason: the machine that could run the real thing
// is reachable only by RDP, a mistake there is a bugcheck, and each iteration
// costs a reboot with a person present. Everything below runs in milliseconds
// on a Mac.
//
// The cases that matter are the ones where the bridge must answer WITHOUT the
// network — a descriptor read, a cancellation, a configure transaction. If any
// of those ever waits on a WAN round trip, the guest's USB stack stalls, and on
// Windows that means an endpoint stuck in teardown and a driver that will not
// unload.

#include "../TestHarness.h"
#include "../fakes/ScriptedDevice.h"
#include "../../platform/windows/UdecxBridge.h"
#include "../../session/ExporterSession.h"
#include "../../session/InlineAsyncPort.h"
#include "../../session/LeaseAuthority.h"
#include "../../transport/RecordLayer.h"
#include "../../transport/TcpTransport.h"

#include <deque>
#include <vector>

using namespace airusb;
using namespace airusb::windows;
using namespace airusb::protocol;
using namespace airusb::session;
using namespace airusb::transport;

namespace {

constexpr std::uint32_t kSession = 0xA1B2C3D4u;
constexpr std::uint32_t kDevice  = 9;

/// A driver that is a pair of queues. It also counts flushes, so a test can tell
/// "the bridge replied" from "the bridge buffered a reply and forgot it".
class FakeDriver final : public IDriverChannel {
public:
    bool tryReceive(std::vector<std::uint8_t>& out) override
    {
        if (toBridge.empty()) return false;
        out = std::move(toBridge.front());
        toBridge.pop_front();
        return true;
    }

    Status send(std::span<const std::uint8_t> record) override
    {
        if (failSends) return Status::TransportLost;
        fromBridge.emplace_back(record.begin(), record.end());
        return Status::Ok;
    }

    std::size_t pendingToDriver() const override { return 0; }
    Status flush() override { ++flushes; return Status::Ok; }

    /// Pops the next record if it decodes as T.
    template <typename T>
    bool next(T& out)
    {
        if (fromBridge.empty()) return false;
        std::vector<std::uint8_t> rec = std::move(fromBridge.front());
        fromBridge.pop_front();
        return ipc::decode(rec, out);
    }

    template <typename T>
    void push(const T& r)
    {
        std::vector<std::uint8_t> v;
        ipc::encode(r, v);
        toBridge.push_back(std::move(v));
    }

    void pushRaw(std::vector<std::uint8_t> v) { toBridge.push_back(std::move(v)); }

    std::deque<std::vector<std::uint8_t>> toBridge;
    std::deque<std::vector<std::uint8_t>> fromBridge;
    bool failSends = false;
    int  flushes   = 0;
};

/// A real ExporterSession on the far end of a real Noise session, so a forwarded
/// transfer really crosses the protocol rather than a stub.
struct Peer {
    MemoryPipe      pipe;
    crypto::LocalIdentity idA = crypto::LocalIdentity::generate();
    crypto::LocalIdentity idB = crypto::LocalIdentity::generate();
    PeerStore       storeA, storeB;
    SecureSession   a, b;
    fakes::ScriptedDevice device{2048, 512};
    ExporterSession exporter;
    ManualClock     clock{1000};
    bool ok = false;
    /// The exporter refuses a SUBMIT that names no lease, so the rig has to do
    /// a real ATTACH before any transfer can cross. Skipping it made every
    /// forwarded transfer fail in a way that looked like a bridge bug.
    std::uint32_t attachId = 0;
    std::uint64_t reqId    = 0;

    struct Source final : IDeviceSource {
        fakes::ScriptedDevice* dev;
        std::unique_ptr<InlineAsyncPort> async;
        std::vector<DeviceRecord> list() override { return {}; }
        Status claim(const protocol::DeviceUid&, IAsyncUsbDevicePort** p, DeviceManifest& m,
                     std::uint8_t* c, std::string*) override
        { async = std::make_unique<InlineAsyncPort>(*dev);
          *p = async.get(); m = dev->manifest(); if (c) *c = 1; return Status::Ok; }
        void release(const protocol::DeviceUid&) override {}
    } source;
    LeaseAuthority leases{clock};

    Peer()
    {
        source.dev = &device;
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
        ExporterSession::Config ec; ec.devices = &source; ec.clock = &clock; ec.leases = &leases;
        if (exporter.begin(&b, ec) != Status::Ok) return;

        attachId = doAttach();
        ok = attachId != 0;
    }

    std::uint32_t doAttach()
    {
        AttachBody ab;
        for (std::size_t i = 0; i < ab.uid.size(); ++i)
            ab.uid[i] = static_cast<std::uint8_t>(i + 1);
        ab.attachSlot = 1;
        ab.importerMaxTransferBytes = 1u << 20;

        std::vector<std::uint8_t> body; encodeAttach(ab, body);
        Header h;
        h.type      = static_cast<std::uint8_t>(wire::Type::Attach);
        h.flags     = wire::kFlagSegFirst;
        h.requestId = ++reqId;
        h.bodyLen   = static_cast<std::uint32_t>(body.size());
        std::vector<std::uint8_t> rec; encodeHeader(h, rec);
        rec.insert(rec.end(), body.begin(), body.end());
        (void)a.transport()->sendRecord(rec);
        (void)a.transport()->flush();
        (void)exporter.pump();

        std::vector<std::uint8_t> in;
        if (a.transport()->receiveRecord(in) != Status::Ok || in.empty()) return 0;
        Header rh;
        if (!decodeHeader(in, rh)) return 0;
        if (rh.type != static_cast<std::uint8_t>(wire::Type::AttachOk)) return 0;
        AttachOkBody ok2;
        if (!decodeAttachOk(std::span<const std::uint8_t>(in).subspan(wire::kHeaderSize, rh.bodyLen), ok2))
            return 0;
        std::vector<std::uint8_t> drain;
        (void)a.transport()->receiveRecord(drain);      // the manifest that follows
        return ok2.attachId;
    }
};

ipc::UrbRequest urb(std::uint64_t id, std::uint8_t ep, ipc::Direction dir,
                    std::uint32_t offered, ipc::TransferType t = ipc::TransferType::Bulk)
{
    ipc::UrbRequest r;
    r.requestId          = id;
    r.sessionIncarnation = kSession;
    r.deviceIncarnation  = kDevice;
    r.endpointId         = ep;
    r.endpointAddress    = ep;
    r.direction          = dir;
    r.transferType       = t;
    r.offeredLength      = offered;
    if (dir == ipc::Direction::Out) r.payload.assign(offered, 0xC3);
    return r;
}

/// A real 31-byte Command Block Wrapper. The device on the far end is a
/// Bulk-Only Transport state machine, not an echo: 31 bytes of filler is not a
/// command and it correctly stalls one. Sending a real CBW makes the forwarding
/// tests prove that actual USB mass-storage traffic crosses the session, which
/// is worth more than proving that a stall propagates.
std::vector<std::uint8_t> cbw(std::uint32_t tag)
{
    std::vector<std::uint8_t> c(31, 0);
    const std::uint32_t sig = 0x43425355u;              // "USBC"
    for (int i = 0; i < 4; ++i) c[static_cast<std::size_t>(i)]     = static_cast<std::uint8_t>(sig >> (8 * i));
    for (int i = 0; i < 4; ++i) c[static_cast<std::size_t>(4 + i)] = static_cast<std::uint8_t>(tag >> (8 * i));
    // dataTransferLength 0, flags 0, LUN 0
    c[14] = 6;                                          // cdb length
    c[15] = 0x00;                                       // TEST UNIT READY
    return c;
}

ipc::UrbRequest getDescriptor(std::uint64_t id, std::uint8_t type, std::uint16_t len)
{
    ipc::UrbRequest r = urb(id, 0x80, ipc::Direction::In, len, ipc::TransferType::Control);
    r.setup[0] = 0x80;                 // device-to-host, standard, device
    r.setup[1] = 0x06;                 // GET_DESCRIPTOR
    r.setup[2] = 0x00;
    r.setup[3] = type;
    r.setup[6] = static_cast<std::uint8_t>(len);
    r.setup[7] = static_cast<std::uint8_t>(len >> 8);
    return r;
}

struct Rig {
    Peer peer;
    FakeDriver driver;
    ManualClock clock{5000};
    ImporterDataPlane plane;
    UdecxBridge bridge;

    Rig()
        : plane(peer.a.transport(), &clock, [this] {
              ImporterDataPlane::Config c;
              c.attachId    = peer.attachId;
              c.attachSlot  = 1;
              c.maxInFlight = 1;      // usb-storage is can_queue=1
              return c;
          }())
        , bridge(driver, plane, [this] {
              UdecxBridge::Config c;
              c.manifest           = peer.device.manifest();
              c.capturedConfig     = 1;
              c.attachSlot         = 1;
              c.sessionIncarnation = kSession;
              c.deviceIncarnation  = kDevice;
              c.clock              = &clock;
              c.maxTransferBytes   = 65536;   // below the codec's cap, so the
                                              // bridge's own limit is reachable
              return c;
          }())
    {}

    /// One bridge step plus an exporter step, which is what a real network does
    /// between the two ends on its own.
    void step(int times = 6)
    {
        for (int i = 0; i < times; ++i) {
            (void)bridge.poll();
            (void)peer.exporter.pump();
            (void)bridge.poll();
        }
    }
};

// ---------------------------------------------------------------------------

void testLocalAnswers()
{
    std::printf("what must never reach the network\n");

    TEST_CASE("a device descriptor is answered from the manifest, with zero traffic") {
        Rig r;
        CHECK(r.peer.ok);
        const std::uint64_t before = r.peer.exporter.transfersServed();

        r.driver.push(getDescriptor(1, 0x01 /* DEVICE */, 18));
        (void)r.bridge.poll();

        ipc::UrbCompletion c;
        CHECK(r.driver.next(c));
        CHECK(c.result == ipc::Result::Ok);
        CHECK(c.actualLength == 18u);
        CHECK(c.payload.size() == 18u);
        // The bytes are the device's own, verbatim — the rule the whole manifest
        // design exists to keep.
        CHECK(c.payload[0] == 18);
        CHECK(c.payload[1] == 0x01);

        CHECK_EQ(static_cast<long long>(r.peer.exporter.transfersServed()),
                 static_cast<long long>(before));
        CHECK_EQ(static_cast<long long>(r.bridge.stats().answeredLocally), 1LL);
        CHECK_EQ(static_cast<long long>(r.bridge.stats().forwarded), 0LL);
    }

    TEST_CASE("the enumeration storm never leaves the machine") {
        // A guest reads descriptors dozens of times while enumerating. At LAN
        // latency that would be seconds; answered locally it is memory speed.
        Rig r;
        for (std::uint64_t i = 0; i < 20; ++i)
            r.driver.push(getDescriptor(100 + i, 0x01, 18));
        (void)r.bridge.poll();
        CHECK_EQ(static_cast<long long>(r.bridge.stats().answeredLocally), 20LL);
        CHECK_EQ(static_cast<long long>(r.peer.exporter.transfersServed()), 0LL);
    }
}

void testForwarding()
{
    std::printf("what must reach it\n");

    TEST_CASE("a bulk OUT crosses the real protocol and comes back") {
        Rig r;
        CHECK(r.peer.ok);
        ipc::UrbRequest w = urb(7, 0x02, ipc::Direction::Out, 31);
        w.payload = cbw(1);
        r.driver.push(w);
        r.step();

        ipc::UrbCompletion c;
        CHECK(r.driver.next(c));
        CHECK_EQ(static_cast<long long>(c.requestId), 7LL);
        CHECK(c.result == ipc::Result::Ok);
        // The length, which the original test did not check and which was
        // therefore wrong: an OUT completion carries no payload, and a version
        // of completeToDriver that "let the payload win" reported every
        // successful write as having moved 0 bytes. A filesystem told its write
        // transferred nothing does not retry politely.
        CHECK_EQ(c.actualLength, 31u);
        CHECK(c.payload.empty());
        CHECK_EQ(static_cast<long long>(r.bridge.stats().forwarded), 1LL);
        CHECK(r.peer.exporter.transfersServed() > 0);
    }

    TEST_CASE("the admission queue holds the second transfer, and it still finishes") {
        Rig r;
        ipc::UrbRequest w1 = urb(1, 0x02, ipc::Direction::Out, 31); w1.payload = cbw(1);
        ipc::UrbRequest w2 = urb(2, 0x02, ipc::Direction::Out, 31); w2.payload = cbw(2);
        r.driver.push(w1);
        r.driver.push(w2);
        (void)r.bridge.poll();
        // Depth 1: one on the wire, one waiting.
        CHECK_EQ(static_cast<long long>(r.bridge.outstanding()), 1LL);
        CHECK_EQ(static_cast<long long>(r.bridge.queued()), 1LL);

        r.step();

        // Both are answered, exactly once each. NOT both successful: the device
        // on the far end is a Bulk-Only Transport state machine, and a second
        // raw 31-byte write is out of phase, so it legitimately stalls. What
        // the admission queue has to guarantee is that a transfer held behind a
        // full plane still reaches the wire and still gets ONE terminal
        // outcome — never that the device likes what it was sent.
        ipc::UrbCompletion a, b;
        CHECK(r.driver.next(a));
        CHECK(r.driver.next(b));
        CHECK(a.requestId != b.requestId);
        CHECK((a.requestId == 1 && b.requestId == 2) || (a.requestId == 2 && b.requestId == 1));
        CHECK(a.result == ipc::Result::Ok);      // the first is a well-formed CBW
        CHECK_EQ(static_cast<long long>(r.bridge.queued()), 0LL);
        CHECK_EQ(static_cast<long long>(r.bridge.outstanding()), 0LL);
        ipc::UrbCompletion extra;
        CHECK(!r.driver.next(extra));            // and nothing is answered twice
    }
}

void testCancellation()
{
    std::printf("cancellation, which may never wait for the network\n");

    TEST_CASE("a cancel is acknowledged immediately, before any traffic") {
        Rig r;
        r.driver.push(urb(11, 0x81, ipc::Direction::In, 512));
        (void)r.bridge.poll();
        CHECK_EQ(static_cast<long long>(r.bridge.outstanding()), 1LL);
        r.driver.fromBridge.clear();

        ipc::CancelRequest cq;
        cq.requestId = 11; cq.sessionIncarnation = kSession; cq.deviceIncarnation = kDevice;
        r.driver.push(cq);
        (void)r.bridge.poll();          // ONE poll, and the exporter never ran

        ipc::CancelAck ack;
        CHECK(r.driver.next(ack));
        CHECK_EQ(static_cast<long long>(ack.requestId), 11LL);
        CHECK_EQ(static_cast<long long>(r.bridge.outstanding()), 0LL);
    }

    TEST_CASE("the late completion is dropped, not delivered") {
        // The exporter answers a transfer the guest has already given up on.
        // Delivering it would complete a WDFREQUEST the driver has finished
        // with, which is a double completion and a bugcheck.
        Rig r;
        r.driver.push(urb(12, 0x02, ipc::Direction::Out, 31));
        (void)r.bridge.poll();

        ipc::CancelRequest cq;
        cq.requestId = 12; cq.sessionIncarnation = kSession; cq.deviceIncarnation = kDevice;
        r.driver.push(cq);
        (void)r.bridge.poll();
        r.driver.fromBridge.clear();

        r.step();                       // let the exporter answer anyway

        ipc::UrbCompletion c;
        CHECK(!r.driver.next(c));       // nothing was sent for it
        CHECK_EQ(static_cast<long long>(r.bridge.outstanding()), 0LL);
    }

    TEST_CASE("cancelling frees the plane's slot, not just the bridge's bookkeeping") {
        // The bug this pins: the bridge stored only the DRIVER's request id and
        // handed that to ImporterDataPlane::cancel(). The plane names transfers
        // by its own id, never found it, and kept the admission slot occupied —
        // so at depth 1 every later URB queued behind a transfer nobody was
        // waiting for. The bridge looked fine; throughput went to zero.
        //
        // The ids are deliberately far apart so one cannot pass for the other.
        Rig r;
        ipc::UrbRequest w = urb(9000, 0x02, ipc::Direction::Out, 31);
        w.payload = cbw(1);
        r.driver.push(w);
        (void)r.bridge.poll();
        CHECK_EQ(static_cast<long long>(r.bridge.outstanding()), 1LL);

        ipc::CancelRequest cq;
        cq.requestId = 9000; cq.sessionIncarnation = kSession; cq.deviceIncarnation = kDevice;
        r.driver.push(cq);
        (void)r.bridge.poll();
        r.driver.fromBridge.clear();

        // The slot must be free NOW, so the next URB goes straight out rather
        // than queueing behind the cancelled one.
        ipc::UrbRequest w2 = urb(9001, 0x02, ipc::Direction::Out, 31);
        w2.payload = cbw(2);
        r.driver.push(w2);
        (void)r.bridge.poll();
        CHECK_EQ(static_cast<long long>(r.bridge.queued()), 0LL);
        CHECK_EQ(static_cast<long long>(r.bridge.outstanding()), 1LL);
    }

    TEST_CASE("cancelling something still in the queue also answers at once") {
        Rig r;
        r.driver.push(urb(1, 0x02, ipc::Direction::Out, 31));
        r.driver.push(urb(2, 0x02, ipc::Direction::Out, 31));
        (void)r.bridge.poll();
        CHECK_EQ(static_cast<long long>(r.bridge.queued()), 1LL);
        r.driver.fromBridge.clear();

        ipc::CancelRequest cq;
        cq.requestId = 2; cq.sessionIncarnation = kSession; cq.deviceIncarnation = kDevice;
        r.driver.push(cq);
        (void)r.bridge.poll();

        ipc::CancelAck ack;
        CHECK(r.driver.next(ack));
        CHECK_EQ(static_cast<long long>(r.bridge.queued()), 0LL);
    }
}

void testConfigure()
{
    std::printf("configure, which is a transaction\n");

    TEST_CASE("selecting the captured configuration succeeds locally") {
        Rig r;
        ipc::Configure cfg;
        cfg.ticketId = 5; cfg.sessionIncarnation = kSession; cfg.deviceIncarnation = kDevice;
        cfg.isConfiguration = true; cfg.configurationValue = 1;
        r.driver.push(cfg);
        (void)r.bridge.poll();

        ipc::ConfigureResult res;
        CHECK(r.driver.next(res));
        CHECK(res.result == ipc::Result::Ok);
        CHECK_EQ(static_cast<long long>(res.ticketId), 5LL);
        CHECK_EQ(static_cast<long long>(r.peer.exporter.transfersServed()), 0LL);
    }

    TEST_CASE("a different configuration is REFUSED, not forwarded") {
        // No exporter here can change a captured device's configuration, and a
        // guest that believes one took effect builds its endpoint table from
        // descriptors the device is not using.
        Rig r;
        ipc::Configure cfg;
        cfg.ticketId = 6; cfg.sessionIncarnation = kSession; cfg.deviceIncarnation = kDevice;
        cfg.isConfiguration = true; cfg.configurationValue = 2;
        r.driver.push(cfg);
        (void)r.bridge.poll();

        ipc::ConfigureResult res;
        CHECK(r.driver.next(res));
        CHECK(res.result == ipc::Result::Unsupported);
    }

    TEST_CASE("releasing an endpoint retires transfers already ON THE WIRE") {
        // The interesting half, and the one an earlier version missed: it
        // drained the queue and left the in-flight transfer alone. The driver
        // then destroys the endpoint object, and the completion for the
        // in-flight transfer arrives for something freed.
        Rig r;
        ipc::UrbRequest w = urb(1, 0x02, ipc::Direction::Out, 31);
        w.payload = cbw(1);
        r.driver.push(w);
        (void)r.bridge.poll();
        CHECK_EQ(static_cast<long long>(r.bridge.outstanding()), 1LL);
        r.driver.fromBridge.clear();

        ipc::Configure cfg;
        cfg.ticketId = 11; cfg.sessionIncarnation = kSession; cfg.deviceIncarnation = kDevice;
        cfg.isConfiguration = false; cfg.interfaceNumber = 0; cfg.alternateSetting = 0;
        cfg.release = { 0x02 };
        r.driver.push(cfg);
        (void)r.bridge.poll();

        CHECK_EQ(static_cast<long long>(r.bridge.outstanding()), 0LL);
        ipc::UrbCompletion c;
        CHECK(r.driver.next(c));
        CHECK_EQ(static_cast<long long>(c.requestId), 1LL);
        CHECK(c.result == ipc::Result::Canceled);

        // And the exporter's late answer must not be delivered afterwards.
        r.step();
        ipc::ConfigureResult res;
        (void)r.driver.next(res);
        ipc::UrbCompletion late;
        CHECK(!r.driver.next(late));
    }

    TEST_CASE("releasing an endpoint completes its queued transfers at once") {
        // The driver is about to destroy those endpoint objects. A completion
        // arriving afterwards would land on a freed kernel object.
        Rig r;
        r.driver.push(urb(1, 0x02, ipc::Direction::Out, 31));
        r.driver.push(urb(2, 0x02, ipc::Direction::Out, 31));   // queued behind depth 1
        (void)r.bridge.poll();
        CHECK_EQ(static_cast<long long>(r.bridge.queued()), 1LL);
        r.driver.fromBridge.clear();

        ipc::Configure cfg;
        cfg.ticketId = 8; cfg.sessionIncarnation = kSession; cfg.deviceIncarnation = kDevice;
        cfg.isConfiguration = false; cfg.interfaceNumber = 0; cfg.alternateSetting = 0;
        cfg.release = { 0x02 };
        r.driver.push(cfg);
        (void)r.bridge.poll();

        // The queued transfer on that endpoint was answered before the
        // transaction result, so the driver can retire it before deleting the
        // endpoint.
        ipc::UrbCompletion c;
        CHECK(r.driver.next(c));
        CHECK_EQ(static_cast<long long>(c.requestId), 2LL);
        CHECK(c.result == ipc::Result::Canceled);
        CHECK_EQ(static_cast<long long>(r.bridge.queued()), 0LL);
    }
}

void testFailureModes()
{
    std::printf("when things go wrong\n");

    TEST_CASE("a dead network completes every outstanding URB") {
        // A URB the guest never hears about is a hung driver: its own timeouts
        // are far longer than ours, and some class drivers have none.
        Rig r;
        r.driver.push(urb(21, 0x81, ipc::Direction::In, 512));
        r.driver.push(urb(22, 0x81, ipc::Direction::In, 512));
        (void)r.bridge.poll();
        r.driver.fromBridge.clear();

        r.bridge.failAll(Status::TransportLost);

        int answered = 0;
        ipc::UrbCompletion c;
        while (r.driver.next(c)) {
            CHECK(c.result == ipc::Result::Disconnected);
            ++answered;
        }
        CHECK_EQ(answered, 2);
        CHECK_EQ(static_cast<long long>(r.bridge.outstanding()), 0LL);
        CHECK_EQ(static_cast<long long>(r.bridge.queued()), 0LL);
    }

    TEST_CASE("a record from a stale incarnation is answered, not forwarded") {
        // It names a device that no longer exists. Answering keeps the driver's
        // table from growing; forwarding would attach it to the wrong device.
        Rig r;
        ipc::UrbRequest old = urb(31, 0x02, ipc::Direction::Out, 31);
        old.deviceIncarnation = kDevice - 1;
        r.driver.push(old);
        (void)r.bridge.poll();

        ipc::UrbCompletion c;
        CHECK(r.driver.next(c));
        CHECK(c.result == ipc::Result::Disconnected);
        CHECK_EQ(static_cast<long long>(r.bridge.stats().forwarded), 0LL);
    }

    TEST_CASE("the retired set does not grow without bound") {
        // It is the SECOND lock — the data plane already guarantees one terminal
        // outcome per submit — and an unbounded second lock is a leak charged to
        // the service's uptime. 6000 answered requests must not leave 6000
        // entries behind.
        // Cancellations, not descriptor reads: a request answered from the
        // manifest never reaches the plane, so it can never produce a late
        // completion and is never retired at all. Only the paths that CAN be
        // raced put anything in this set — which is itself the right design and
        // is why a first version of this test measured zero.
        Rig r;
        for (std::uint64_t i = 0; i < 6000; ++i) {
            ipc::CancelRequest cq;
            cq.requestId = 500000 + i;
            cq.sessionIncarnation = kSession;
            cq.deviceIncarnation  = kDevice;
            r.driver.push(cq);
        }
        (void)r.bridge.poll();
        r.driver.fromBridge.clear();
        CHECK(r.bridge.retiredForTest() > 0u);
        CHECK(r.bridge.retiredForTest() <= 4096u);
    }

    TEST_CASE("a malformed record is counted and skipped, not fatal") {
        Rig r;
        r.driver.pushRaw({ 0xFF, 0xFF, 0xFF, 0xFF, 1, 0, 1, 0 });
        r.driver.push(getDescriptor(41, 0x01, 18));
        (void)r.bridge.poll();

        CHECK(r.bridge.stats().malformed >= 1);
        // The good record after it was still handled: one bad IOCTL must not
        // stop the channel.
        ipc::UrbCompletion c;
        CHECK(r.driver.next(c));
        CHECK(c.result == ipc::Result::Ok);
    }

    TEST_CASE("a transfer past this device's limit is refused rather than attempted") {
        Rig r;
        ipc::UrbRequest big = urb(51, 0x81, ipc::Direction::In, 0);
        big.offeredLength = 131072;            // decodes fine; past maxTransferBytes
        r.driver.push(big);
        (void)r.bridge.poll();

        ipc::UrbCompletion c;
        CHECK(r.driver.next(c));
        CHECK(c.result == ipc::Result::Unsupported);
        CHECK_EQ(static_cast<long long>(r.bridge.stats().forwarded), 0LL);
    }

    TEST_CASE("an offer past the ABI's own cap never reaches the bridge at all") {
        // Two different limits, and it matters which one fires. The codec caps
        // at 1 MiB for every device; the bridge caps at what THIS device
        // negotiated. A record above the ABI cap is refused by the decoder, so
        // the bridge counts it malformed and answers nothing — there is no
        // request to answer, because nothing well-formed ever arrived.
        Rig r;
        ipc::UrbRequest huge = urb(52, 0x81, ipc::Direction::In, 0);
        huge.offeredLength = 2u << 20;
        r.driver.push(huge);
        (void)r.bridge.poll();

        CHECK(r.bridge.stats().malformed >= 1);
        ipc::UrbCompletion c;
        CHECK(!r.driver.next(c));
    }
}

} // namespace

int main()
{
    std::printf("test_udecxbridge\n");
    testLocalAnswers();
    testForwarding();
    testCancellation();
    testConfigure();
    testFailureModes();
    TEST_MAIN_END();
}
