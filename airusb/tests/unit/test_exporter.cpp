// The exporter session, end to end through the real stack.
//
// Two SecureSessions on a pipe, a real Noise handshake, real records, real
// validation, and a real Bulk-Only Transport device on the far side. The only
// thing faked is the device itself and the byte pipe.
//
// The point is not that a device list arrives. It is that the trust gate holds
// under a peer that asks for things in the wrong order, with the wrong
// credentials, or twice.

#include "../TestHarness.h"
#include "../fakes/ScriptedDevice.h"
#include "../../diag/BotProbe.h"
#include "../../session/ExporterSession.h"
#include "../../session/InlineAsyncPort.h"
#include "../../session/LeaseAuthority.h"
#include "../../protocol/ManifestCodec.h"
#include "../../transport/TcpTransport.h"

#include <cstring>
#include <string>

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

/// A device source backed by ScriptedDevice, so the whole session runs against
/// something that behaves like real firmware rather than an echo.
class FakeSource final : public IDeviceSource {
public:
    ScriptedDevice device;
    std::unique_ptr<InlineAsyncPort> async;
    bool           claimRefused = false;
    Status         refuseWith   = Status::MountedLocally;
    int            claims = 0, releases = 0;

    std::vector<DeviceRecord> list() override
    {
        DeviceRecord r;
        r.uid       = uidOf(1);
        r.vendorId  = 0x058f;
        r.productId = 0x6387;
        r.speed     = static_cast<std::uint8_t>(Speed::Super);
        r.flags     = kDevHasStorage | kDevShareable;
        r.name      = "Memory 32GB";
        return { r };
    }

    Status claim(const DeviceUid& uid, IAsyncUsbDevicePort** portOut,
                 DeviceManifest& manifestOut, std::uint8_t* cfgOut,
                 std::string* whyNot) override
    {
        if (!(uid == uidOf(1))) {
            if (whyNot) *whyNot = "no such device";
            return Status::NotFound;
        }
        if (claimRefused) {
            if (whyNot) *whyNot = "“Memory 32GB” is in use by another app.";
            return refuseWith;
        }
        ++claims;
        async       = std::make_unique<InlineAsyncPort>(device);
        *portOut    = async.get();
        manifestOut = device.manifest();
        *cfgOut     = 1;
        return Status::Ok;
    }

    void release(const DeviceUid&) override { ++releases; }
};

/// Two peers, handshaken, with the exporter running on side B.
struct Rig {
    MemoryPipe    pipe;
    LocalIdentity idA = LocalIdentity::generate();
    LocalIdentity idB = LocalIdentity::generate();
    PeerStore     storeA, storeB;
    SecureSession a, b;
    FakeSource    source;
    ExporterSession exporter;
    ManualClock   clock{1000};
    LeaseAuthority leases{clock};
    bool          ok = false;
    std::uint64_t _reqId = 0;

    /// `pair` false leaves both peers authenticated but unpinned, which is the
    /// state the trust gate is supposed to refuse from.
    explicit Rig(bool pair = true)
    {
        if (pair) {
            (void)storeA.pin(idB.publicIdentity(), "B", kDefaultGrants, 1);
            (void)storeB.pin(idA.publicIdentity(), "A", kDefaultGrants, 1);
        }

        SecureSession::Config ca;
        ca.initiator = true;  ca.identity = &idA; ca.peers = &storeA;
        SecureSession::Config cb;
        cb.initiator = false; cb.identity = &idB; cb.peers = &storeB;

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

    /// Sends one message from A and returns the exporter's first reply.
    ///
    /// `totalLen` is the DATA payload length, not the body length (§3.2). Control
    /// messages carry none; a SUBMIT carries buffer_len on OUT and nothing on IN.
    Status ask(wire::Type type, std::span<const std::uint8_t> body,
               Header& replyHeader, std::vector<std::uint8_t>& replyBody,
               std::uint32_t attachId = 0, std::uint32_t totalLen = 0)
    {
        Header h;
        h.type     = static_cast<std::uint8_t>(type);
        h.flags    = wire::kFlagSegFirst;
        h.attachId = attachId;
        h.requestId = ++_reqId;
        h.bodyLen  = static_cast<std::uint32_t>(body.size());
        h.totalLen = totalLen;

        std::vector<std::uint8_t> rec;
        encodeHeader(h, rec);
        rec.insert(rec.end(), body.begin(), body.end());

        if (const Status s = a.transport()->sendRecord(rec); s != Status::Ok) return s;
        if (const Status s = a.transport()->flush(); s != Status::Ok) return s;

        // The reply is read even when pump() reports a fatal status: a fatal
        // refusal still SENDS the ERROR record first, and the whole point of
        // ERROR is that the peer gets to read it before the session closes.
        (void)exporter.pump();

        std::vector<std::uint8_t> in;
        const Status r = a.transport()->receiveRecord(in);
        if (r != Status::Ok || in.empty()) return Status::Busy;
        if (!decodeHeader(in, replyHeader)) return Status::MalformedFrame;
        replyBody.assign(in.begin() + static_cast<std::ptrdiff_t>(wire::kHeaderSize),
                         in.begin() + static_cast<std::ptrdiff_t>(wire::kHeaderSize + replyHeader.bodyLen));
        return Status::Ok;
    }
};

void testTrustGate()
{
    std::printf("the trust gate\n");

    TEST_CASE("an unpaired peer is refused a device list") {
        Rig r(/*pair=*/false);
        CHECK(r.ok);
        CHECK(r.b.trust() == Trust::Unpaired);

        Header h;
        std::vector<std::uint8_t> body;
        CHECK(r.ask(wire::Type::ListDevices, {}, h, body) == Status::Ok);
        CHECK_EQ(h.type, static_cast<std::uint8_t>(wire::Type::Error));
        CHECK(static_cast<Status>(h.status) == Status::NotPaired);
    }

    TEST_CASE("an unpaired peer is refused an attach") {
        Rig r(/*pair=*/false);
        CHECK(r.ok);

        AttachBody ab;
        ab.uid = uidOf(1);
        ab.attachSlot = 1;
        std::vector<std::uint8_t> req;
        encodeAttach(ab, req);

        Header h;
        std::vector<std::uint8_t> body;
        CHECK(r.ask(wire::Type::Attach, req, h, body) == Status::Ok);
        CHECK(static_cast<Status>(h.status) == Status::NotPaired);
        CHECK_EQ(r.source.claims, 0);       // and nothing was captured
    }

    TEST_CASE("an unpaired peer may still ping") {
        // PING/PONG stays open so a peer can be reached to be paired at all.
        Rig r(/*pair=*/false);
        CHECK(r.ok);

        PingBody p;
        p.pingTsNs = 12345;
        std::vector<std::uint8_t> req;
        encodePing(p, req);

        Header h;
        std::vector<std::uint8_t> body;
        CHECK(r.ask(wire::Type::Ping, req, h, body) == Status::Ok);
        CHECK_EQ(h.type, static_cast<std::uint8_t>(wire::Type::Pong));

        PingBody pong;
        CHECK(decodePing(body, pong));
        CHECK_EQ(pong.pingTsNs, 12345ull);
    }

}

void testListAndAttach()
{
    std::printf("list, attach, detach\n");

    TEST_CASE("a paired peer gets the device list") {
        Rig r;
        CHECK(r.ok);
        CHECK(r.b.trust() == Trust::Paired);

        Header h;
        std::vector<std::uint8_t> body;
        CHECK(r.ask(wire::Type::ListDevices, {}, h, body) == Status::Ok);
        CHECK_EQ(h.type, static_cast<std::uint8_t>(wire::Type::DeviceList));

        std::vector<DeviceRecord> devices;
        CHECK(decodeDeviceList(body, devices));
        CHECK_EQ(devices.size(), 1u);
        CHECK(devices[0].name == "Memory 32GB");
        CHECK_EQ(devices[0].vendorId, 0x058f);
        CHECK(devices[0].speed == static_cast<std::uint8_t>(Speed::Super));
    }

    TEST_CASE("attach returns ATTACH_OK then the manifest") {
        Rig r;
        CHECK(r.ok);

        AttachBody ab;
        ab.uid = uidOf(1);
        ab.attachSlot = 1;
        ab.importerMaxTransferBytes = 65536;
        std::vector<std::uint8_t> req;
        encodeAttach(ab, req);

        Header h;
        std::vector<std::uint8_t> body;
        CHECK(r.ask(wire::Type::Attach, req, h, body) == Status::Ok);
        CHECK_EQ(h.type, static_cast<std::uint8_t>(wire::Type::AttachOk));
        CHECK(static_cast<Status>(h.status) == Status::Ok);

        AttachOkBody ok;
        CHECK(decodeAttachOk(body, ok));
        CHECK(ok.attachId != 0);
        CHECK(ok.speed == static_cast<std::uint16_t>(Speed::Super));
        CHECK(ok.manifestLen > 0);
        CHECK_EQ(r.source.claims, 1);

        // The manifest follows on the same request id.
        std::vector<std::uint8_t> rec;
        CHECK(r.a.transport()->receiveRecord(rec) == Status::Ok);
        Header mh;
        CHECK(decodeHeader(rec, mh));
        CHECK_EQ(mh.type, static_cast<std::uint8_t>(wire::Type::DeviceManifest));
        CHECK_EQ(mh.bodyLen, ok.manifestLen);

        DeviceManifest got;
        ManifestHeader mhdr;
        std::string why;
        const auto mbody = std::span<const std::uint8_t>(rec)
                              .subspan(wire::kHeaderSize, mh.bodyLen);
        const Status ms = decodeManifest(mbody, got, mhdr, &why);
        if (ms != Status::Ok) std::printf("\n    manifest: %s\n", why.c_str());
        CHECK(ms == Status::Ok);
        CHECK(got.speed() == Speed::Super);
    }

    TEST_CASE("a second attach gets BUSY and is never queued") {
        // §7.7. Queuing creates a window in which neither peer knows who owns
        // the device.
        Rig r;
        CHECK(r.ok);

        AttachBody ab;
        ab.uid = uidOf(1);
        ab.attachSlot = 1;
        std::vector<std::uint8_t> req;
        encodeAttach(ab, req);

        Header h;
        std::vector<std::uint8_t> body;
        CHECK(r.ask(wire::Type::Attach, req, h, body) == Status::Ok);
        std::vector<std::uint8_t> drain;
        (void)r.a.transport()->receiveRecord(drain);       // the manifest

        CHECK(r.ask(wire::Type::Attach, req, h, body) == Status::Ok);
        CHECK(static_cast<Status>(h.status) == Status::Busy);
        CHECK_EQ(r.source.claims, 1);                      // still one
    }

    TEST_CASE("a refused unmount is reported as MOUNTED_LOCALLY with a reason") {
        Rig r;
        CHECK(r.ok);
        r.source.claimRefused = true;

        AttachBody ab;
        ab.uid = uidOf(1);
        ab.attachSlot = 1;
        std::vector<std::uint8_t> req;
        encodeAttach(ab, req);

        Header h;
        std::vector<std::uint8_t> body;
        CHECK(r.ask(wire::Type::Attach, req, h, body) == Status::Ok);
        CHECK_EQ(h.type, static_cast<std::uint8_t>(wire::Type::AttachOk));
        CHECK(static_cast<Status>(h.status) == Status::MountedLocally);

        // The reason is the part a user can act on, so it must survive.
        bool sawReason = false;
        const auto tail = std::span<const std::uint8_t>(body).subspan(kBodyAttachOk);
        forEachTlv(tail, [&](const TlvView& t) {
            if (static_cast<wire::Tlv>(t.type) == wire::Tlv::RejectReason) {
                sawReason = t.value.size() > 0;
            }
            return true;
        });
        CHECK(sawReason);
    }

    TEST_CASE("an attach slot outside 1..15 is refused") {
        // The channel id is (slot << 8) | ep_addr, and slot 0 is the session
        // control channel — an attach must never claim it.
        Rig r;
        CHECK(r.ok);

        for (std::uint8_t slot : { std::uint8_t{0}, std::uint8_t{16}, std::uint8_t{255} }) {
            AttachBody ab;
            ab.uid = uidOf(1);
            ab.attachSlot = slot;
            std::vector<std::uint8_t> req;
            encodeAttach(ab, req);

            Header h;
            std::vector<std::uint8_t> body;
            CHECK(r.ask(wire::Type::Attach, req, h, body) == Status::Ok);
            CHECK(static_cast<Status>(h.status) == Status::MalformedFrame);
        }
        CHECK_EQ(r.source.claims, 0);
    }

    TEST_CASE("detach releases the device") {
        Rig r;
        CHECK(r.ok);

        AttachBody ab;
        ab.uid = uidOf(1);
        ab.attachSlot = 1;
        std::vector<std::uint8_t> req;
        encodeAttach(ab, req);

        Header h;
        std::vector<std::uint8_t> body;
        CHECK(r.ask(wire::Type::Attach, req, h, body) == Status::Ok);
        AttachOkBody ok;
        CHECK(decodeAttachOk(body, ok));
        std::vector<std::uint8_t> drain;
        (void)r.a.transport()->receiveRecord(drain);

        DetachBody d;
        d.reason = DetachReason::UserRequest;
        std::vector<std::uint8_t> dreq;
        encodeDetach(d, dreq);

        CHECK(r.ask(wire::Type::Detach, dreq, h, body, ok.attachId) == Status::Ok);
        CHECK_EQ(h.type, static_cast<std::uint8_t>(wire::Type::DetachOk));
        CHECK_EQ(r.source.releases, 1);
        CHECK(r.exporter.state() == ExporterSession::State::Idle);
    }

    TEST_CASE("an unknown detach reason is refused rather than defaulted") {
        Rig r;
        CHECK(r.ok);
        std::vector<std::uint8_t> bad(kBodyDetach, 0);
        bad[0] = 99;

        Header h;
        std::vector<std::uint8_t> body;
        CHECK(r.ask(wire::Type::Detach, bad, h, body) == Status::Ok);
        CHECK(static_cast<Status>(h.status) == Status::MalformedFrame);
    }
}

void testDataPlane()
{
    std::printf("the data plane, through the whole stack\n");

    TEST_CASE("a real BOT exchange runs over the encrypted session") {
        // The loopback gate, but through SecureSession and ExporterSession
        // rather than a bare record layer: real Noise, real records, real
        // validation, a real BOT device.
        Rig r;
        CHECK(r.ok);
        r.source.device.fillPattern(0xC0FFEEu);
        const std::uint64_t before = r.source.device.checksum();

        AttachBody ab;
        ab.uid = uidOf(1);
        ab.attachSlot = 1;
        std::vector<std::uint8_t> req;
        encodeAttach(ab, req);

        Header h;
        std::vector<std::uint8_t> body;
        CHECK(r.ask(wire::Type::Attach, req, h, body) == Status::Ok);
        AttachOkBody ok;
        CHECK(decodeAttachOk(body, ok));

        std::vector<std::uint8_t> mrec;
        CHECK(r.a.transport()->receiveRecord(mrec) == Status::Ok);

        // A tiny importer: turns IUsbDevicePort calls into SUBMIT/COMPLETE over
        // the live session, so diag/BotProbe can drive the remote device.
        struct RemotePort final : IUsbDevicePort {
            Rig& rig;
            std::uint32_t attachId;
            DeviceManifest manifest_;

            RemotePort(Rig& g, std::uint32_t id, DeviceManifest m)
                : rig(g), attachId(id), manifest_(std::move(m)) {}

            const DeviceManifest& manifest() const noexcept override { return manifest_; }

            Status submit(std::uint8_t ep, std::uint8_t type, std::uint8_t dir,
                          std::uint32_t bufferLen, const std::uint8_t setup[8],
                          std::span<const std::uint8_t> dataOut,
                          std::vector<std::uint8_t>& dataIn)
            {
                SubmitBody sb;
                sb.epAddr    = ep;
                sb.xferType  = type;
                sb.dir       = dir;
                sb.bufferLen = bufferLen;
                if (setup) std::memcpy(sb.setup, setup, 8);

                std::vector<std::uint8_t> b;
                encodeSubmit(sb, b);
                b.insert(b.end(), dataOut.begin(), dataOut.end());

                Header rh;
                std::vector<std::uint8_t> rb;
                const std::uint32_t total =
                    (dir == static_cast<std::uint8_t>(wire::Dir::Out)) ? bufferLen : 0;
                const Status s = rig.ask(wire::Type::Submit, b, rh, rb, attachId, total);
                if (s != Status::Ok) return s;
                if (rh.type != static_cast<std::uint8_t>(wire::Type::Complete))
                    return static_cast<Status>(rh.status);

                CompleteBody cb;
                if (!decodeComplete(rb, cb)) return Status::MalformedFrame;
                if (cb.payloadLen > 0) {
                    const auto p = std::span<const std::uint8_t>(rb).subspan(wire::kBodyComplete);
                    dataIn.assign(p.begin(), p.begin() + static_cast<std::ptrdiff_t>(cb.payloadLen));
                }
                return static_cast<Status>(rh.status);
            }

            Status controlTransfer(const SetupPacket& sp,
                                   std::span<const std::uint8_t> out,
                                   std::vector<std::uint8_t>& in) override
            {
                std::uint8_t setup[8];
                setup[0] = sp.bmRequestType; setup[1] = sp.bRequest;
                setup[2] = static_cast<std::uint8_t>(sp.wValue);
                setup[3] = static_cast<std::uint8_t>(sp.wValue >> 8);
                setup[4] = static_cast<std::uint8_t>(sp.wIndex);
                setup[5] = static_cast<std::uint8_t>(sp.wIndex >> 8);
                setup[6] = static_cast<std::uint8_t>(sp.wLength);
                setup[7] = static_cast<std::uint8_t>(sp.wLength >> 8);
                return submit(0, static_cast<std::uint8_t>(wire::XferType::Control),
                              static_cast<std::uint8_t>(sp.direction() == Dir::In
                                                          ? wire::Dir::In : wire::Dir::Out),
                              sp.wLength, setup, out, in);
            }

            Status bulkOut(std::uint8_t ep, std::span<const std::uint8_t> data,
                           std::uint32_t* actual) override
            {
                std::vector<std::uint8_t> in;
                const Status s = submit(ep, static_cast<std::uint8_t>(wire::XferType::Bulk),
                                        static_cast<std::uint8_t>(wire::Dir::Out),
                                        static_cast<std::uint32_t>(data.size()),
                                        nullptr, data, in);
                if (actual) *actual = (s == Status::Ok)
                                        ? static_cast<std::uint32_t>(data.size()) : 0;
                return s;
            }

            Status bulkIn(std::uint8_t ep, std::uint32_t maxLen,
                          std::vector<std::uint8_t>& out) override
            {
                return submit(ep, static_cast<std::uint8_t>(wire::XferType::Bulk),
                              static_cast<std::uint8_t>(wire::Dir::In),
                              maxLen, nullptr, {}, out);
            }

            Status clearHalt(std::uint8_t) override { return Status::Ok; }
        };

        RemotePort remote(r, ok.attachId, r.source.device.manifest());

        diag::BotEndpoints eps;
        CHECK(diag::findBotInterface(remote.manifest(), 1, eps));

        diag::BotProbe probe(remote, eps);
        const diag::BotProbeResult res = probe.run();
        if (!res.passed) std::printf("\n%s", res.summary().c_str());

        CHECK(res.passed);
        CHECK(res.transferBoundariesIntact);
        CHECK(res.blockSize == 512);
        // Read-only: the medium is untouched.
        CHECK_EQ(r.source.device.checksum(), before);
    }

    TEST_CASE("a SUBMIT for a stale attach is dropped silently, not fatal") {
        // R12. Escalating an epoch mismatch would turn every legitimate reset
        // into a session teardown.
        Rig r;
        CHECK(r.ok);

        AttachBody ab;
        ab.uid = uidOf(1);
        ab.attachSlot = 1;
        std::vector<std::uint8_t> req;
        encodeAttach(ab, req);
        Header h;
        std::vector<std::uint8_t> body;
        CHECK(r.ask(wire::Type::Attach, req, h, body) == Status::Ok);
        AttachOkBody ok;
        CHECK(decodeAttachOk(body, ok));
        std::vector<std::uint8_t> drain;
        (void)r.a.transport()->receiveRecord(drain);

        SubmitBody sb;
        sb.epAddr = 0x81;
        sb.xferType = static_cast<std::uint8_t>(wire::XferType::Bulk);
        sb.dir = static_cast<std::uint8_t>(wire::Dir::In);
        sb.bufferLen = 13;
        std::vector<std::uint8_t> sbody;
        encodeSubmit(sb, sbody);

        // Wrong attach id: no reply at all, and the session stays healthy.
        const Status s = r.ask(wire::Type::Submit, sbody, h, body, ok.attachId + 99, 0);
        CHECK(s == Status::Busy);                       // nothing came back
        CHECK(r.exporter.state() == ExporterSession::State::Leased);
    }

    TEST_CASE("a SUBMIT with no attach is refused") {
        Rig r;
        CHECK(r.ok);

        SubmitBody sb;
        sb.epAddr = 0x81;
        sb.xferType = static_cast<std::uint8_t>(wire::XferType::Bulk);
        sb.dir = static_cast<std::uint8_t>(wire::Dir::In);
        sb.bufferLen = 13;
        std::vector<std::uint8_t> sbody;
        encodeSubmit(sb, sbody);

        Header h;
        std::vector<std::uint8_t> body;
        CHECK(r.ask(wire::Type::Submit, sbody, h, body, 0, 0) == Status::Ok);
        CHECK(static_cast<Status>(h.status) == Status::Detaching);
    }
}

} // namespace

int main()
{
    std::printf("test_exporter\n");
    testTrustGate();
    testListAndAttach();
    testDataPlane();
    TEST_MAIN_END();
}
