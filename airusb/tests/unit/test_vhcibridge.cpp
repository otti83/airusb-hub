// L3 — enumeration, with no kernel anywhere near it.
//
// The bridge translates what vhci-hcd says into transfers on an IUsbDevicePort.
// Here the port is ScriptedDevice, a RAM disk, and the kernel is replaced by
// hand-written 48-byte PDUs, so this whole file runs on a Mac in a fraction of a
// second and every failure is deterministic.
//
// That is not a convenience, it is the plan's L3/L4 split. A bug found with a
// real kernel in the loop costs a VM reboot per iteration and leaves D-state
// processes that make the next iteration's evidence untrustworthy.
//
// The load-bearing assertion is byte-identity: what the bridge hands back for a
// descriptor request must be exactly the bytes in the manifest, which came from
// the real device verbatim. The moment this layer synthesises or rewrites a
// descriptor, the importer presents a device that does not exist.

#include "../TestHarness.h"
#include "../fakes/ScriptedDevice.h"
#include "../../platform/linux/VhciBridge.h"
#include "../../transport/TcpTransport.h"

#include <cstring>

using namespace airusb;
using namespace airusb::fakes;
using namespace airusb::linuxvhci;
using namespace airusb::transport;

namespace {

/// A kernel, as far as the bridge can tell: it writes CMD_SUBMITs and reads
/// whatever comes back.
class FakeKernel {
public:
    explicit FakeKernel(std::unique_ptr<IByteStream> s) : _s(std::move(s)) {}

    void submitControl(std::uint32_t seq, std::uint8_t bmRequestType, std::uint8_t bRequest,
                       std::uint16_t wValue, std::uint16_t wIndex, std::uint16_t wLength,
                       std::span<const std::uint8_t> outData = {},
                       std::uint32_t flags = 0)
    {
        UsbipPdu p;
        p.command              = kCmdSubmit;
        p.seqnum               = seq;
        p.devid                = 0x00020002;
        p.direction            = (bmRequestType & 0x80u) ? kDirIn : kDirOut;
        p.ep                   = 0;
        p.transferFlags        = flags;
        p.transferBufferLength = static_cast<std::int32_t>(wLength);
        p.setup[0] = bmRequestType;
        p.setup[1] = bRequest;
        p.setup[2] = static_cast<std::uint8_t>(wValue & 0xFF);
        p.setup[3] = static_cast<std::uint8_t>(wValue >> 8);
        p.setup[4] = static_cast<std::uint8_t>(wIndex & 0xFF);
        p.setup[5] = static_cast<std::uint8_t>(wIndex >> 8);
        p.setup[6] = static_cast<std::uint8_t>(wLength & 0xFF);
        p.setup[7] = static_cast<std::uint8_t>(wLength >> 8);

        std::vector<std::uint8_t> b;
        encodeCmdSubmit(p, b);
        if (p.direction == kDirOut && !outData.empty())
            b.insert(b.end(), outData.begin(), outData.end());
        writeAll(b);
    }

    void submitData(std::uint32_t seq, std::uint8_t epAddr, std::int32_t len,
                    std::span<const std::uint8_t> outData = {}, std::uint32_t flags = 0)
    {
        UsbipPdu p;
        p.command              = kCmdSubmit;
        p.seqnum               = seq;
        p.devid                = 0x00020002;
        p.direction            = (epAddr & 0x80u) ? kDirIn : kDirOut;
        p.ep                   = static_cast<std::uint32_t>(epAddr & 0x0F);
        p.transferFlags        = flags;
        p.transferBufferLength = len;

        std::vector<std::uint8_t> b;
        encodeCmdSubmit(p, b);
        if (p.direction == kDirOut && !outData.empty())
            b.insert(b.end(), outData.begin(), outData.end());
        writeAll(b);
    }

    void submitUnlink(std::uint32_t seq, std::uint32_t target)
    {
        std::vector<std::uint8_t> b;
        encodeCmdUnlink(seq, 0x00020002, target, b);
        writeAll(b);
    }

    /// Reads one reply: the 48-byte PDU plus whatever payload it declares.
    bool readReply(UsbipPdu& hdr, std::vector<std::uint8_t>& payload)
    {
        std::uint8_t raw[kPduBytes];
        if (!readExactly(raw, kPduBytes)) return false;
        if (!decodePdu(std::span<const std::uint8_t>(raw, kPduBytes), hdr)) return false;

        payload.clear();
        if (hdr.command == kRetSubmit && hdr.actualLength > 0) {
            payload.resize(static_cast<std::size_t>(hdr.actualLength));
            // Only IN transfers carry a payload back. The caller knows which it
            // asked for; a RET_SUBMIT for an OUT with a non-zero actual_length
            // and no bytes is correct and must not hang this reader, so the
            // read is attempted and a failure is reported rather than blocking.
            if (!readExactly(payload.data(), payload.size())) { payload.clear(); return true; }
        }
        return true;
    }

    void close() { _s->close(); }

private:
    void writeAll(std::span<const std::uint8_t> b)
    {
        std::size_t sent = 0;
        while (sent < b.size()) {
            const IoResult r = _s->write(b.subspan(sent));
            if (r.status != Status::Ok && r.status != Status::Busy) return;
            sent += r.bytes;
        }
    }
    bool readExactly(std::uint8_t* p, std::size_t n)
    {
        std::size_t got = 0;
        int spins = 0;
        while (got < n) {
            const IoResult r = _s->read(std::span<std::uint8_t>(p + got, n - got));
            if (r.status != Status::Ok && r.status != Status::Busy) return false;
            if (r.bytes == 0 && ++spins > 1000) return false;
            got += r.bytes;
        }
        return true;
    }

    std::unique_ptr<IByteStream> _s;
};

struct Rig {
    ScriptedDevice dev{61440, 512};
    MemoryPipe     pipe;
    FakeKernel     kernel{pipe.endpointA()};
    std::unique_ptr<IByteStream> bridgeSide = pipe.endpointB();
    VhciBridge     bridge{*bridgeSide, dev};
};

constexpr std::uint8_t kGetDescriptor  = 0x06;
constexpr std::uint8_t kSetConfiguration = 0x09;
constexpr std::uint16_t kDeviceDesc    = 0x0100;
constexpr std::uint16_t kConfigDesc    = 0x0200;

void testEnumeration()
{
    std::printf("enumeration\n");

    TEST_CASE("the device descriptor comes back byte for byte from the manifest") {
        // The whole point. These bytes came off a real device; if this layer ever
        // rewrites one, the guest enumerates a device that does not exist.
        Rig r;
        r.kernel.submitControl(1, 0x80, kGetDescriptor, kDeviceDesc, 0, 64);
        CHECK(r.bridge.pumpOnce() == Status::Ok);

        UsbipPdu hdr; std::vector<std::uint8_t> data;
        CHECK(r.kernel.readReply(hdr, data));
        CHECK_EQ(hdr.command, kRetSubmit);
        CHECK_EQ(hdr.seqnum, 1u);
        CHECK_EQ(hdr.status, 0);

        const std::span<const std::uint8_t> want = r.dev.manifest().deviceDescriptor();
        CHECK_EQ(data.size(), want.size());
        CHECK(std::memcmp(data.data(), want.data(), want.size()) == 0);
        CHECK(!want.empty());
    }

    TEST_CASE("a 64-byte request for an 18-byte descriptor is a short SUCCESS") {
        // The device descriptor is 18 bytes and the kernel asks for 64. Reporting
        // an error here would fail enumeration at its first step.
        Rig r;
        r.kernel.submitControl(1, 0x80, kGetDescriptor, kDeviceDesc, 0, 64);
        CHECK(r.bridge.pumpOnce() == Status::Ok);

        UsbipPdu hdr; std::vector<std::uint8_t> data;
        CHECK(r.kernel.readReply(hdr, data));
        CHECK_EQ(hdr.status, 0);
        CHECK(hdr.actualLength < 64);
        CHECK_EQ(static_cast<std::size_t>(hdr.actualLength), data.size());
    }

    TEST_CASE("the configuration descriptor is served twice, 9 bytes then the whole thing") {
        // Exactly what a real kernel does: read the header to learn
        // wTotalLength, then read that many bytes.
        Rig r;
        r.kernel.submitControl(1, 0x80, kGetDescriptor, kConfigDesc, 0, 9);
        CHECK(r.bridge.pumpOnce() == Status::Ok);
        UsbipPdu h1; std::vector<std::uint8_t> d1;
        CHECK(r.kernel.readReply(h1, d1));
        CHECK_EQ(h1.status, 0);
        CHECK_EQ(d1.size(), 9u);

        const std::uint16_t wTotal = static_cast<std::uint16_t>(d1[2] | (d1[3] << 8));
        CHECK(wTotal > 9);

        r.kernel.submitControl(2, 0x80, kGetDescriptor, kConfigDesc, 0, wTotal);
        CHECK(r.bridge.pumpOnce() == Status::Ok);
        UsbipPdu h2; std::vector<std::uint8_t> d2;
        CHECK(r.kernel.readReply(h2, d2));
        CHECK_EQ(d2.size(), wTotal);

        const std::span<const std::uint8_t> want = r.dev.manifest().configurationByIndex(0);
        CHECK_EQ(d2.size(), want.size());
        CHECK(std::memcmp(d2.data(), want.data(), want.size()) == 0);
    }

    TEST_CASE("no descriptor request ever reaches the device") {
        // They are answered from the manifest. On the networked path this is the
        // difference between enumeration costing zero round trips and costing
        // twenty.
        Rig r;
        r.kernel.submitControl(1, 0x80, kGetDescriptor, kDeviceDesc, 0, 64);
        CHECK(r.bridge.pumpOnce() == Status::Ok);
        UsbipPdu h; std::vector<std::uint8_t> d;
        CHECK(r.kernel.readReply(h, d));

        CHECK_EQ(r.bridge.stats().answeredLocally, 1u);
        CHECK_EQ(r.bridge.stats().forwardedToDevice, 0u);
    }

    TEST_CASE("SET_CONFIGURATION is accepted and moves the arbiter's shadow") {
        Rig r;
        r.kernel.submitControl(1, 0x00, kSetConfiguration, 1, 0, 0);
        CHECK(r.bridge.pumpOnce() == Status::Ok);
        UsbipPdu h; std::vector<std::uint8_t> d;
        CHECK(r.kernel.readReply(h, d));
        CHECK_EQ(h.status, 0);
        CHECK_EQ(h.actualLength, 0);
    }
}

void testDataEndpoints()
{
    std::printf("data endpoints\n");

    /// Configure first: before SET_CONFIGURATION there is no pipe table.
    void (*configure)(Rig&) = [](Rig& r) {
        r.kernel.submitControl(100, 0x00, kSetConfiguration, 1, 0, 0);
        (void)r.bridge.pumpOnce();
        UsbipPdu h; std::vector<std::uint8_t> d;
        (void)r.kernel.readReply(h, d);
    };

    TEST_CASE("a bulk OUT of a CBW moves exactly 31 bytes and returns no payload") {
        Rig r; configure(r);

        // A real Bulk-Only Transport CBW: signature, tag, length, flags, LUN,
        // CDB length, then INQUIRY.
        std::vector<std::uint8_t> cbw(31, 0);
        cbw[0]='U'; cbw[1]='S'; cbw[2]='B'; cbw[3]='C';
        cbw[4]=1;                       // tag
        cbw[8]=36;                      // dCBWDataTransferLength
        cbw[12]=0x80;                   // device -> host
        cbw[14]=6;                      // CDB length
        cbw[15]=0x12;                   // INQUIRY
        cbw[19]=36;

        r.kernel.submitData(1, 0x02, 31, cbw);
        CHECK(r.bridge.pumpOnce() == Status::Ok);

        UsbipPdu h; std::vector<std::uint8_t> d;
        CHECK(r.kernel.readReply(h, d));
        CHECK_EQ(h.status, 0);
        CHECK_EQ(h.actualLength, 31);
        CHECK(d.empty());               // OUT completions carry no bytes back
    }

    TEST_CASE("a bulk IN returns what the device sent") {
        Rig r; configure(r);

        std::vector<std::uint8_t> cbw(31, 0);
        cbw[0]='U'; cbw[1]='S'; cbw[2]='B'; cbw[3]='C';
        cbw[4]=1; cbw[8]=36; cbw[12]=0x80; cbw[14]=6; cbw[15]=0x12; cbw[19]=36;
        r.kernel.submitData(1, 0x02, 31, cbw);
        CHECK(r.bridge.pumpOnce() == Status::Ok);
        UsbipPdu h0; std::vector<std::uint8_t> d0;
        CHECK(r.kernel.readReply(h0, d0));

        r.kernel.submitData(2, 0x81, 36);
        CHECK(r.bridge.pumpOnce() == Status::Ok);
        UsbipPdu h; std::vector<std::uint8_t> d;
        CHECK(r.kernel.readReply(h, d));
        CHECK_EQ(h.status, 0);
        CHECK_EQ(d.size(), 36u);
        // INQUIRY vendor field, straight off the scripted device.
        CHECK(std::memcmp(d.data() + 8, "AirUSB  ", 8) == 0);
    }

    TEST_CASE("an endpoint that is not in the configuration is EPIPE, not a failure") {
        Rig r; configure(r);
        r.kernel.submitData(1, 0x87, 64);
        CHECK(r.bridge.pumpOnce() == Status::Ok);
        UsbipPdu h; std::vector<std::uint8_t> d;
        CHECK(r.kernel.readReply(h, d));
        CHECK_EQ(h.status, -32);          // -EPIPE
        CHECK_EQ(h.actualLength, 0);
    }
}

void testTheRulesThatKillThePort()
{
    std::printf("the rules that kill the port if broken\n");

    TEST_CASE("actual_length is never larger than what was asked for") {
        // Over-reporting makes the kernel log "recv xbuf" and tear the whole port
        // down, taking every other in-flight URB with it. Ask for 4 bytes of an
        // 18-byte descriptor and the answer must be 4.
        Rig r;
        r.kernel.submitControl(1, 0x80, kGetDescriptor, kDeviceDesc, 0, 4);
        CHECK(r.bridge.pumpOnce() == Status::Ok);
        UsbipPdu h; std::vector<std::uint8_t> d;
        CHECK(r.kernel.readReply(h, d));
        CHECK_EQ(h.actualLength, 4);
        CHECK_EQ(d.size(), 4u);
    }

    TEST_CASE("a CMD_UNLINK is always answered") {
        // An unanswered CMD_UNLINK leaves the submitting task in uninterruptible
        // sleep for ever: a process that cannot be killed and a machine that has
        // to be rebooted. Silence is the one unacceptable response.
        Rig r;
        r.kernel.submitUnlink(7, 3);
        CHECK(r.bridge.pumpOnce() == Status::Ok);

        UsbipPdu h; std::vector<std::uint8_t> d;
        CHECK(r.kernel.readReply(h, d));
        CHECK_EQ(h.command, kRetUnlink);
        CHECK_EQ(h.seqnum, 7u);           // the UNLINK's own seqnum, not 3
        CHECK_EQ(h.status, 0);
    }

    TEST_CASE("every reply is exactly 48 bytes plus its declared payload") {
        Rig r;
        r.kernel.submitControl(1, 0x80, kGetDescriptor, kDeviceDesc, 0, 8);
        CHECK(r.bridge.pumpOnce() == Status::Ok);
        // If the bridge had written a 20-byte header the reader would come up
        // short and the kernel would block for ever rather than erroring.
        UsbipPdu h; std::vector<std::uint8_t> d;
        CHECK(r.kernel.readReply(h, d));
        CHECK_EQ(d.size(), 8u);
    }

    TEST_CASE("an undecodable PDU stops the bridge instead of resynchronising") {
        // There is no length prefix in USB/IP. A PDU we cannot parse means the
        // stream position is unknown, and guessing a length to resync is how a
        // bridge starts reading payload as headers.
        Rig r;
        std::vector<std::uint8_t> junk(kPduBytes, 0xEE);
        std::size_t sent = 0;
        auto ep = r.pipe.endpointA();
        while (sent < junk.size()) {
            const IoResult w = ep->write(std::span<const std::uint8_t>(junk).subspan(sent));
            if (w.status != Status::Ok && w.status != Status::Busy) break;
            sent += w.bytes;
        }
        CHECK(r.bridge.pumpOnce() == Status::MalformedFrame);
        CHECK(!r.bridge.lastError().empty());
    }

    TEST_CASE("the kernel closing the socket is a clean end, not an error") {
        Rig r;
        r.kernel.close();
        CHECK(r.bridge.pumpOnce() == Status::TransportLost);
        CHECK(r.bridge.run() == Status::Ok);
    }
}

void testShortReads()
{
    std::printf("short reads\n");

    TEST_CASE("a short IN is success by default") {
        Rig r;
        r.kernel.submitControl(1, 0x80, kGetDescriptor, kDeviceDesc, 0, 255);
        CHECK(r.bridge.pumpOnce() == Status::Ok);
        UsbipPdu h; std::vector<std::uint8_t> d;
        CHECK(r.kernel.readReply(h, d));
        CHECK_EQ(h.status, 0);
        CHECK(h.actualLength < 255);
    }

    TEST_CASE("a short IN is EREMOTEIO when the host set SHORT_NOT_OK") {
        // The bytes still come back — the driver is entitled to see what arrived
        // even though it declared a short result unacceptable.
        Rig r;
        r.kernel.submitControl(100, 0x00, kSetConfiguration, 1, 0, 0);
        (void)r.bridge.pumpOnce();
        UsbipPdu h0; std::vector<std::uint8_t> d0;
        (void)r.kernel.readReply(h0, d0);

        std::vector<std::uint8_t> cbw(31, 0);
        cbw[0]='U'; cbw[1]='S'; cbw[2]='B'; cbw[3]='C';
        cbw[4]=1; cbw[8]=36; cbw[12]=0x80; cbw[14]=6; cbw[15]=0x12; cbw[19]=36;
        r.kernel.submitData(1, 0x02, 31, cbw);
        (void)r.bridge.pumpOnce();
        UsbipPdu h1; std::vector<std::uint8_t> d1;
        (void)r.kernel.readReply(h1, d1);

        // Offer more than the 36 bytes INQUIRY will produce, and forbid short.
        r.kernel.submitData(2, 0x81, 64, {}, kUrbShortNotOk);
        CHECK(r.bridge.pumpOnce() == Status::Ok);
        UsbipPdu h; std::vector<std::uint8_t> d;
        CHECK(r.kernel.readReply(h, d));
        CHECK_EQ(h.status, -121);         // -EREMOTEIO
        CHECK_EQ(h.actualLength, 36);
        CHECK_EQ(d.size(), 36u);
    }
}

} // namespace

int main()
{
    std::printf("test_vhcibridge\n");
    testEnumeration();
    testDataEndpoints();
    testTheRulesThatKillThePort();
    testShortReads();
    TEST_MAIN_END();
}
