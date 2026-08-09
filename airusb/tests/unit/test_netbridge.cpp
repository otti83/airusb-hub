// The event-driven vhci bridge, proven to be non-blocking (LINUX_IMPORTER_PLAN §4.2).
//
// This is the piece that can wedge a real machine into an unkillable D-state if it
// is wrong, so the properties are proven with no kernel in the loop: a MemoryPipe
// stands in for sv[1] (we write CMD_SUBMIT/CMD_UNLINK PDUs and read RET_SUBMIT /
// RET_UNLINK), and a second pipe carries the async data plane to a hand-driven
// exporter we can stall or kill at will.
//
// The load-bearing test is unlink-while-outstanding: a CMD_UNLINK is answered
// IMMEDIATELY, without waiting for the network, and a completion that arrives after
// is dropped. That is exactly the "answer CMD_UNLINK even though the device is
// still moving bytes" rule that keeps usb_kill_urb() from sleeping forever.

#include "../TestHarness.h"
#include "../fakes/ScriptedDevice.h"
#include "../../platform/linux/UsbipCodec.h"
#include "../../platform/linux/LinuxUsb.h"
#include "../../platform/linux/VhciNetBridge.h"
#include "../../protocol/Codec.h"
#include "../../protocol/Segmentation.h"
#include "../../session/ImporterDataPlane.h"
#include "../../transport/RecordLayer.h"
#include "../../transport/TcpTransport.h"

#include <cstring>
#include <memory>
#include <span>
#include <vector>

using namespace airusb;
using namespace airusb::protocol;
using namespace airusb::session;
using namespace airusb::transport;
using namespace airusb::linuxvhci;
using namespace airusb::fakes;

namespace {

constexpr std::uint32_t kAttach = 5;
constexpr std::uint8_t  kSlot   = 1;
constexpr std::uint32_t kDevId  = 0x00020002;

// GET_MAX_LUN (class, interface, IN, 1 byte) — the arbiter forwards it to the
// device, so it exercises the NETWORK path on ep0 without needing a configured
// device or a bulk pipe.
const std::uint8_t kGetMaxLun[8] = { 0xA1, 0xFE, 0, 0, 0, 0, 1, 0 };
// GET_DESCRIPTOR(DEVICE, 18) — answered locally from the manifest, never the wire.
const std::uint8_t kGetDevDesc[8] = { 0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x12, 0x00 };

// --- kernel-side raw PDU helpers (no framing; USB/IP has none) ---------------

void kWriteRaw(IByteStream& k, std::span<const std::uint8_t> bytes)
{
    std::size_t sent = 0;
    while (sent < bytes.size()) {
        const IoResult r = k.write(bytes.subspan(sent));
        if (r.status != Status::Ok || r.bytes == 0) break;
        sent += r.bytes;
    }
}

void kSubmit(IByteStream& k, std::uint32_t seq, std::uint32_t ep, std::uint32_t dir,
             std::int32_t bufLen, const std::uint8_t setup[8],
             std::span<const std::uint8_t> outData = {})
{
    UsbipPdu p;
    p.command = kCmdSubmit;
    p.seqnum  = seq;
    p.devid   = kDevId;
    p.direction = dir;
    p.ep = ep;
    p.transferBufferLength = bufLen;
    if (setup) std::memcpy(p.setup, setup, 8);

    std::vector<std::uint8_t> b;
    encodeCmdSubmit(p, b);
    if (dir == kDirOut) b.insert(b.end(), outData.begin(), outData.end());
    kWriteRaw(k, b);
}

void kUnlink(IByteStream& k, std::uint32_t seq, std::uint32_t target)
{
    std::vector<std::uint8_t> b;
    encodeCmdUnlink(seq, kDevId, target, b);
    kWriteRaw(k, b);
}

/// Reads one RET PDU (and its IN payload when asked). Returns false if nothing is
/// buffered — which is itself an assertion the tests use ("nothing came back").
bool kReadPdu(IByteStream& k, UsbipPdu& out, std::vector<std::uint8_t>& payload, bool inPayload)
{
    std::uint8_t hdr[kPduBytes];
    std::size_t got = 0;
    while (got < kPduBytes) {
        const IoResult r = k.read(std::span<std::uint8_t>(hdr + got, kPduBytes - got));
        if (r.status != Status::Ok || r.bytes == 0) return false;
        got += r.bytes;
    }
    if (!decodePdu(std::span<const std::uint8_t>(hdr, kPduBytes), out)) return false;
    payload.clear();
    if (inPayload && out.command == kRetSubmit && out.actualLength > 0) {
        payload.resize(static_cast<std::size_t>(out.actualLength));
        std::size_t p = 0;
        while (p < payload.size()) {
            const IoResult r = k.read(std::span<std::uint8_t>(payload.data() + p, payload.size() - p));
            if (r.status != Status::Ok || r.bytes == 0) break;
            p += r.bytes;
        }
    }
    return true;
}

// --- exporter-side helpers (framed, real emitTransfer) -----------------------

bool peerReadSubmit(RecordLayer& peer, Header& hOut, SubmitBody& sbOut)
{
    std::vector<std::uint8_t> rec;
    if (peer.receiveRecord(rec) != Status::Ok || rec.empty()) return false;
    if (!decodeHeader(rec, hOut)) return false;
    return decodeSubmit(std::span<const std::uint8_t>(rec).subspan(wire::kHeaderSize), sbOut);
}

void peerComplete(RecordLayer& peer, std::uint16_t channel, std::uint64_t rid,
                  std::uint8_t epAddr, std::uint8_t xferType, std::uint8_t dir,
                  std::uint32_t requestedLen, std::span<const std::uint8_t> payload,
                  Status status = Status::Ok)
{
    CompleteBody cb;
    cb.epAddr       = epAddr;
    cb.xferType     = xferType;
    cb.dir          = dir;
    cb.requestedLen = requestedLen;
    if (dir == static_cast<std::uint8_t>(wire::Dir::In)) {
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
    (void)emitTransfer(base, cbody,
                       (dir == static_cast<std::uint8_t>(wire::Dir::In)) ? payload
                                                                         : std::span<const std::uint8_t>{},
                       maxSeg, [&](std::span<const std::uint8_t> r) { return peer.sendRecord(r); });
    (void)peer.flush();
}

// --- the rig -----------------------------------------------------------------

ImporterDataPlane::Config planeCfg()
{
    ImporterDataPlane::Config c;
    c.attachId = kAttach;
    c.attachSlot = kSlot;
    c.maxInFlight = 1;
    return c;
}

struct Rig {
    ScriptedDevice proto;
    MemoryPipe     kpipe;
    MemoryPipe     npipe;
    std::unique_ptr<IByteStream> kBridge = kpipe.endpointA();
    std::unique_ptr<IByteStream> kSim    = kpipe.endpointB();
    RecordLayer    planeLink;
    RecordLayer    peerLink;
    ManualClock    clock{1000};
    ImporterDataPlane plane;
    VhciNetBridge     bridge;

    Rig()
        : planeLink(npipe.endpointA(), std::make_unique<NullCipher>())
        , peerLink(npipe.endpointB(), std::make_unique<NullCipher>())
        , plane(&planeLink, &clock, planeCfg())
        , bridge(*kBridge, plane, proto.manifest(), VhciNetBridge::Config{})
    {
        planeLink.setHandshakeComplete(wire::kRecordBytesDefault);
        peerLink.setHandshakeComplete(wire::kRecordBytesDefault);
    }
};

void testForwardRoundTrip()
{
    std::printf("a forwarded ep0 transfer crosses the network and returns\n");

    TEST_CASE("GET_MAX_LUN forwards, completes, and becomes a RET_SUBMIT") {
        Rig r;
        kSubmit(*r.kSim, /*seq*/ 1, /*ep*/ 0, kDirIn, 1, kGetMaxLun);
        CHECK(r.bridge.poll() == Status::Ok);            // drains kernel, forwards to plane

        Header h; SubmitBody sb;
        CHECK(peerReadSubmit(r.peerLink, h, sb));         // the exporter sees the SUBMIT
        CHECK_EQ(sb.epAddr, 0u);
        CHECK_EQ(sb.bufferLen, 1u);

        const std::uint8_t lun[1] = { 0x00 };
        peerComplete(r.peerLink, h.channel, h.requestId, 0, sb.xferType, kDirIn, 1, lun);
        CHECK(r.bridge.poll() == Status::Ok);            // plane completes -> RET_SUBMIT

        UsbipPdu ret; std::vector<std::uint8_t> pl;
        CHECK(kReadPdu(*r.kSim, ret, pl, /*inPayload*/ true));
        CHECK_EQ(ret.command, kRetSubmit);
        CHECK_EQ(ret.seqnum, 1u);
        CHECK_EQ(ret.status, 0);
        CHECK_EQ(ret.actualLength, 1);
        CHECK_EQ(pl.size(), std::size_t{1});
        CHECK_EQ(pl[0], 0x00u);
    }

    TEST_CASE("GET_DESCRIPTOR is answered locally, with no network traffic") {
        Rig r;
        kSubmit(*r.kSim, 2, 0, kDirIn, 18, kGetDevDesc);
        CHECK(r.bridge.poll() == Status::Ok);

        // Nothing was sent to the exporter.
        Header h; SubmitBody sb;
        CHECK(!peerReadSubmit(r.peerLink, h, sb));

        UsbipPdu ret; std::vector<std::uint8_t> pl;
        CHECK(kReadPdu(*r.kSim, ret, pl, true));
        CHECK_EQ(ret.seqnum, 2u);
        CHECK_EQ(ret.status, 0);
        CHECK_EQ(ret.actualLength, 18);
        CHECK_EQ(pl.size(), std::size_t{18});
        CHECK_EQ(pl[0], 18u);            // bLength
        CHECK_EQ(pl[1], 0x01u);          // bDescriptorType == DEVICE
    }
}

void testUnlinkWhileOutstanding()
{
    std::printf("CMD_UNLINK is answered immediately, without the network (the D-state test)\n");

    TEST_CASE("an unlink retires the URB with -ECONNRESET before any completion") {
        Rig r;
        kSubmit(*r.kSim, 3, 0, kDirIn, 1, kGetMaxLun);
        CHECK(r.bridge.poll() == Status::Ok);
        CHECK_EQ(r.bridge.outstanding(), std::size_t{1});

        // Drain the SUBMIT so the exporter "has" it, but do NOT complete it: the
        // device is still moving bytes.
        Header h; SubmitBody sb;
        CHECK(peerReadSubmit(r.peerLink, h, sb));

        // The kernel unlinks it. This MUST be answered now, not after the network.
        kUnlink(*r.kSim, /*unlink seq*/ 100, /*target*/ 3);
        CHECK(r.bridge.poll() == Status::Ok);
        CHECK_EQ(r.bridge.outstanding(), std::size_t{0});

        UsbipPdu ret; std::vector<std::uint8_t> pl;
        CHECK(kReadPdu(*r.kSim, ret, pl, false));
        CHECK_EQ(ret.command, kRetUnlink);
        CHECK_EQ(ret.seqnum, 100u);              // the unlink's OWN seqnum
        CHECK_EQ(ret.status, -kEConnReset);

        // The exporter finally completes the (retired) transfer. It must be dropped
        // — no RET_SUBMIT — because the URB is already dead.
        const std::uint8_t lun[1] = { 0x00 };
        peerComplete(r.peerLink, h.channel, h.requestId, 0, sb.xferType, kDirIn, 1, lun);
        CHECK(r.bridge.poll() == Status::Ok);
        UsbipPdu none; std::vector<std::uint8_t> np;
        CHECK(!kReadPdu(*r.kSim, none, np, true));   // nothing at all
    }

    TEST_CASE("an unlink of an already-completed URB is answered status 0") {
        Rig r;
        kSubmit(*r.kSim, 4, 0, kDirIn, 1, kGetMaxLun);
        CHECK(r.bridge.poll() == Status::Ok);
        Header h; SubmitBody sb;
        CHECK(peerReadSubmit(r.peerLink, h, sb));
        const std::uint8_t lun[1] = { 0x00 };
        peerComplete(r.peerLink, h.channel, h.requestId, 0, sb.xferType, kDirIn, 1, lun);
        CHECK(r.bridge.poll() == Status::Ok);
        UsbipPdu ret; std::vector<std::uint8_t> pl;
        CHECK(kReadPdu(*r.kSim, ret, pl, true));      // the RET_SUBMIT
        CHECK_EQ(ret.seqnum, 4u);

        kUnlink(*r.kSim, 101, 4);                     // too late — it is done
        CHECK(r.bridge.poll() == Status::Ok);
        UsbipPdu ru; std::vector<std::uint8_t> np;
        CHECK(kReadPdu(*r.kSim, ru, np, false));
        CHECK_EQ(ru.command, kRetUnlink);
        CHECK_EQ(ru.seqnum, 101u);
        CHECK_EQ(ru.status, 0);
    }
}

void testFailureModes()
{
    std::printf("network drop and deadline each yield a RET_SUBMIT, never a hang\n");

    TEST_CASE("a network drop completes the outstanding URB with -ENODEV") {
        Rig r;
        kSubmit(*r.kSim, 5, 0, kDirIn, 1, kGetMaxLun);
        CHECK(r.bridge.poll() == Status::Ok);
        Header h; SubmitBody sb;
        CHECK(peerReadSubmit(r.peerLink, h, sb));

        r.peerLink.close();                           // the exporter vanishes
        CHECK(r.bridge.poll() == Status::TransportLost);

        UsbipPdu ret; std::vector<std::uint8_t> pl;
        CHECK(kReadPdu(*r.kSim, ret, pl, true));
        CHECK_EQ(ret.command, kRetSubmit);
        CHECK_EQ(ret.seqnum, 5u);
        CHECK_EQ(ret.status, -kENoDev);               // not a hang, not a retry-inviting timeout
    }

    TEST_CASE("a transfer past its deadline completes with -ETIMEDOUT locally") {
        Rig r;
        kSubmit(*r.kSim, 6, 0, kDirIn, 1, kGetMaxLun);
        CHECK(r.bridge.poll() == Status::Ok);
        Header h; SubmitBody sb;
        CHECK(peerReadSubmit(r.peerLink, h, sb));      // forwarded, but never completed

        r.clock.advanceMs(5000);                       // past the 4000 ms ctrl deadline
        CHECK(r.bridge.poll() == Status::Ok);

        UsbipPdu ret; std::vector<std::uint8_t> pl;
        CHECK(kReadPdu(*r.kSim, ret, pl, true));
        CHECK_EQ(ret.seqnum, 6u);
        CHECK_EQ(ret.status, -kETimedOut);
    }
}

void testAdmissionQueue()
{
    std::printf("a second URB queues behind a full depth-1 plane, and still completes\n");

    TEST_CASE("two forwards: the second waits, then runs when the first completes") {
        Rig r;
        kSubmit(*r.kSim, 7, 0, kDirIn, 1, kGetMaxLun);
        kSubmit(*r.kSim, 8, 0, kDirIn, 1, kGetMaxLun);
        CHECK(r.bridge.poll() == Status::Ok);          // both drained; #7 admitted, #8 queued
        CHECK_EQ(r.bridge.outstanding(), std::size_t{1});
        CHECK_EQ(r.bridge.pendingSubmits(), std::size_t{1});

        // Only #7 is on the wire so far.
        Header h7; SubmitBody sb7;
        CHECK(peerReadSubmit(r.peerLink, h7, sb7));
        Header hx; SubmitBody sbx;
        CHECK(!peerReadSubmit(r.peerLink, hx, sbx));    // #8 not yet

        const std::uint8_t lun[1] = { 0x00 };
        peerComplete(r.peerLink, h7.channel, h7.requestId, 0, sb7.xferType, kDirIn, 1, lun);
        CHECK(r.bridge.poll() == Status::Ok);          // #7 completes, #8 admitted
        CHECK_EQ(r.bridge.pendingSubmits(), std::size_t{0});

        UsbipPdu ret7; std::vector<std::uint8_t> pl7;
        CHECK(kReadPdu(*r.kSim, ret7, pl7, true));
        CHECK_EQ(ret7.seqnum, 7u);

        Header h8; SubmitBody sb8;
        CHECK(peerReadSubmit(r.peerLink, h8, sb8));      // now #8 is on the wire
        peerComplete(r.peerLink, h8.channel, h8.requestId, 0, sb8.xferType, kDirIn, 1, lun);
        CHECK(r.bridge.poll() == Status::Ok);

        UsbipPdu ret8; std::vector<std::uint8_t> pl8;
        CHECK(kReadPdu(*r.kSim, ret8, pl8, true));
        CHECK_EQ(ret8.seqnum, 8u);
    }
}

} // namespace

int main()
{
    std::printf("test_netbridge\n");
    testForwardRoundTrip();
    testUnlinkWhileOutstanding();
    testFailureModes();
    testAdmissionQueue();
    TEST_MAIN_END();
}
