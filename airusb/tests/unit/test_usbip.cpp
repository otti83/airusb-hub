// The USB/IP byte layer, checked before a kernel is anywhere near it.
//
// This runs on macOS with no Linux and no vhci-hcd, which is the point: a bug
// found here costs a rebuild, and the same bug found with a real kernel in the
// loop costs a VM reboot per iteration and leaves D-state processes that make
// the next iteration's evidence untrustworthy.
//
// The case that matters most is the one about setup[8]. Every u32 in the header
// is big-endian and those eight bytes are not, because they are the raw USB SETUP
// packet. A codec that byteswaps the header wholesale looks completely correct
// until it corrupts every control transfer — which is to say, until enumeration
// fails for a reason eight bytes deep.

#include "../TestHarness.h"
#include "../../platform/linux/UsbipCodec.h"

#include <cstring>

using namespace airusb;
using namespace airusb::linuxvhci;

namespace {

/// The first PDU vhci-hcd sends after an attach: GET_DESCRIPTOR(DEVICE), 64
/// bytes, on endpoint 0 IN. Built here by hand from the field table so that the
/// test is a statement about the wire, not about our own encoder.
std::vector<std::uint8_t> getDescriptorPdu()
{
    std::vector<std::uint8_t> b(kPduBytes, 0);
    // command = 1 (CMD_SUBMIT)
    b[0x03] = 0x01;
    // seqnum = 1
    b[0x07] = 0x01;
    // devid = 0x00020002
    b[0x09] = 0x02; b[0x0B] = 0x02;
    // direction = 1 (IN)
    b[0x0F] = 0x01;
    // ep = 0
    // transfer_flags = 0x00000200 (USBIP_URB_DIR_IN)
    b[0x16] = 0x02;
    // transfer_buffer_length = 64
    b[0x1B] = 0x40;
    // setup: bmRequestType=0x80 bRequest=0x06 wValue=0x0100 wIndex=0 wLength=0x0040
    // wValue and wLength are LITTLE endian INSIDE this big-endian header.
    b[0x28] = 0x80;   // bmRequestType: device-to-host, standard, device
    b[0x29] = 0x06;   // GET_DESCRIPTOR
    b[0x2A] = 0x00;   // wValue lo  \  0x0100 = DEVICE descriptor, index 0
    b[0x2B] = 0x01;   // wValue hi  /
    b[0x2C] = 0x00;   // wIndex lo
    b[0x2D] = 0x00;   // wIndex hi
    b[0x2E] = 0x40;   // wLength lo \  64, little-endian
    b[0x2F] = 0x00;   // wLength hi /
    return b;
}

void testTheGoldenPdu()
{
    std::printf("the first PDU a kernel sends\n");

    TEST_CASE("GET_DESCRIPTOR(DEVICE) decodes field for field") {
        UsbipPdu p;
        bool clamped = true;
        CHECK(decodePdu(getDescriptorPdu(), p, &clamped));
        CHECK(!clamped);

        CHECK_EQ(p.command, kCmdSubmit);
        CHECK_EQ(p.seqnum, 1u);
        CHECK_EQ(p.devid, 0x00020002u);
        CHECK_EQ(p.direction, kDirIn);
        CHECK_EQ(p.ep, 0u);
        CHECK_EQ(p.transferFlags, kUrbDirIn);
        CHECK_EQ(p.transferBufferLength, 64);
        CHECK_EQ(p.numberOfPackets, 0);
    }

    TEST_CASE("setup[8] survives verbatim, little-endian inside") {
        // The whole file exists for this case. If the header decoder ever
        // byteswaps these eight bytes, wLength becomes 0x4000 = 16384 and
        // wValue becomes 0x0001, and enumeration asks for the wrong descriptor
        // at sixteen kilobytes.
        UsbipPdu p;
        CHECK(decodePdu(getDescriptorPdu(), p));

        CHECK_EQ(p.setup[0], 0x80u);
        CHECK_EQ(p.setup[1], 0x06u);
        CHECK_EQ(p.setup[2], 0x00u);
        CHECK_EQ(p.setup[3], 0x01u);
        CHECK_EQ(p.setup[6], 0x40u);
        CHECK_EQ(p.setup[7], 0x00u);

        // Read as USB reads it: little-endian.
        const std::uint16_t wValue  = static_cast<std::uint16_t>(p.setup[2] | (p.setup[3] << 8));
        const std::uint16_t wLength = static_cast<std::uint16_t>(p.setup[6] | (p.setup[7] << 8));
        CHECK_EQ(wValue, 0x0100u);     // DEVICE descriptor, index 0
        CHECK_EQ(wLength, 64u);
    }

    TEST_CASE("the endpoint address puts the direction bit back on") {
        UsbipPdu p;
        CHECK(decodePdu(getDescriptorPdu(), p));
        CHECK_EQ(p.endpointAddress(), 0x80u);       // ep 0, IN

        p.ep = 2; p.direction = kDirOut;
        CHECK_EQ(p.endpointAddress(), 0x02u);
        p.ep = 1; p.direction = kDirIn;
        CHECK_EQ(p.endpointAddress(), 0x81u);
    }
}

void testFraming()
{
    std::printf("framing\n");

    TEST_CASE("a PDU is 48 bytes and nothing else is accepted") {
        UsbipPdu p;
        std::vector<std::uint8_t> shortPdu(20, 0); shortPdu[3] = 1;
        std::vector<std::uint8_t> longPdu(64, 0);  longPdu[3]  = 1;
        CHECK(!decodePdu(shortPdu, p));
        CHECK(!decodePdu(longPdu, p));
        CHECK(decodePdu(std::vector<std::uint8_t>(48, 0), p) == false);  // command 0
    }

    TEST_CASE("every encoded PDU is exactly 48 bytes") {
        // A RET_SUBMIT written as 20 bytes does not error on the kernel side.
        // vhci_rx_pdu asks for sizeof(pdu) with MSG_WAITALL, so it blocks for
        // ever and the port becomes unkillable.
        std::vector<std::uint8_t> out;
        UsbipPdu cmd;
        cmd.seqnum = 9;
        encodeRetSubmit(cmd, 0, 0, 0, out);
        CHECK_EQ(out.size(), kPduBytes);

        out.clear();
        encodeRetUnlink(3, -104, out);
        CHECK_EQ(out.size(), kPduBytes);

        out.clear();
        encodeCmdSubmit(cmd, out);
        CHECK_EQ(out.size(), kPduBytes);

        out.clear();
        encodeCmdUnlink(1, 2, 3, out);
        CHECK_EQ(out.size(), kPduBytes);
    }

    TEST_CASE("two PDUs concatenate without a length prefix") {
        std::vector<std::uint8_t> out;
        UsbipPdu a; a.seqnum = 1;
        UsbipPdu b; b.seqnum = 2;
        encodeRetSubmit(a, 0, 0, 0, out);
        encodeRetSubmit(b, 0, 0, 0, out);
        CHECK_EQ(out.size(), 2 * kPduBytes);

        UsbipPdu d1, d2;
        CHECK(decodePdu(std::span(out).subspan(0, kPduBytes), d1));
        CHECK(decodePdu(std::span(out).subspan(kPduBytes, kPduBytes), d2));
        CHECK_EQ(d1.seqnum, 1u);
        CHECK_EQ(d2.seqnum, 2u);
    }

    TEST_CASE("an OUT payload is announced, an IN payload is not") {
        UsbipPdu p;
        CHECK(decodePdu(getDescriptorPdu(), p));
        CHECK(!p.hasOutPayload());              // it is IN

        p.direction = kDirOut;
        CHECK(p.hasOutPayload());
        p.transferBufferLength = 0;
        CHECK(!p.hasOutPayload());              // zero-length OUT carries nothing
    }
}

void testRoundTrips()
{
    std::printf("round trips\n");

    TEST_CASE("CMD_SUBMIT survives encode and decode") {
        UsbipPdu in;
        in.command              = kCmdSubmit;
        in.seqnum               = 0x11223344;
        in.devid                = 0x00020003;
        in.direction            = kDirOut;
        in.ep                   = 2;
        in.transferFlags        = kUrbZeroPacket | kUrbDmaMapSg;
        in.transferBufferLength = 31;
        in.startFrame           = -1;
        in.numberOfPackets      = 0;
        in.interval             = 0;
        for (std::size_t i = 0; i < kSetupBytes; ++i)
            in.setup[i] = static_cast<std::uint8_t>(0xF0 + i);

        std::vector<std::uint8_t> bytes;
        encodeCmdSubmit(in, bytes);

        UsbipPdu out;
        CHECK(decodePdu(bytes, out));
        CHECK_EQ(out.seqnum, in.seqnum);
        CHECK_EQ(out.devid, in.devid);
        CHECK_EQ(out.direction, in.direction);
        CHECK_EQ(out.ep, in.ep);
        CHECK_EQ(out.transferFlags, in.transferFlags);
        CHECK_EQ(out.transferBufferLength, in.transferBufferLength);
        CHECK_EQ(out.startFrame, -1);
        CHECK(std::memcmp(out.setup, in.setup, kSetupBytes) == 0);
    }

    TEST_CASE("RET_SUBMIT echoes what the kernel compares") {
        // start_frame and number_of_packets are echoed, never invented. The
        // kernel is entitled to look at what it gets back.
        UsbipPdu cmd;
        cmd.seqnum          = 0x0A0B0C0D;
        cmd.startFrame      = 12345;
        cmd.numberOfPackets = 7;

        std::vector<std::uint8_t> bytes;
        encodeRetSubmit(cmd, -32, 512, 2, bytes);

        UsbipPdu out;
        CHECK(decodePdu(bytes, out));
        CHECK_EQ(out.command, kRetSubmit);
        CHECK_EQ(out.seqnum, cmd.seqnum);
        CHECK_EQ(out.status, -32);            // -EPIPE
        CHECK_EQ(out.actualLength, 512);
        CHECK_EQ(out.startFrame, 12345);
        CHECK_EQ(out.numberOfPackets, 7);
        CHECK_EQ(out.errorCount, 2);
        CHECK_EQ(out.devid, 0u);              // zero on returns
        CHECK_EQ(out.direction, 0u);
        CHECK_EQ(out.ep, 0u);
    }

    TEST_CASE("a negative status survives as a negative number") {
        for (const std::int32_t st : { -1, -32, -71, -104, -108, -110, -2147483647 - 1 }) {
            std::vector<std::uint8_t> bytes;
            UsbipPdu cmd; cmd.seqnum = 5;
            encodeRetSubmit(cmd, st, 0, 0, bytes);
            UsbipPdu out;
            CHECK(decodePdu(bytes, out));
            CHECK_EQ(out.status, st);
        }
    }

    TEST_CASE("RET_UNLINK echoes the UNLINK's own seqnum, not its target") {
        // Getting this backwards answers a seqnum the kernel is not holding,
        // which kills the port and every URB on it.
        std::vector<std::uint8_t> cmdBytes;
        encodeCmdUnlink(/*seqnum*/ 77, /*devid*/ 1, /*targetSeqnum*/ 42, cmdBytes);

        UsbipPdu unlink;
        CHECK(decodePdu(cmdBytes, unlink));
        CHECK_EQ(unlink.command, kCmdUnlink);
        CHECK_EQ(unlink.seqnum, 77u);
        CHECK_EQ(unlink.unlinkSeqnum, 42u);

        std::vector<std::uint8_t> retBytes;
        encodeRetUnlink(unlink.seqnum, -104, retBytes);
        UsbipPdu ret;
        CHECK(decodePdu(retBytes, ret));
        CHECK_EQ(ret.command, kRetUnlink);
        CHECK_EQ(ret.seqnum, 77u);          // the unlink, NOT 42
        CHECK_EQ(ret.status, -104);
    }
}

void testHostileInput()
{
    std::printf("what a broken or hostile peer sends\n");

    TEST_CASE("an unknown command is refused rather than skipped") {
        // There is no length prefix on this protocol. An unknown command means
        // the stream position is no longer trustworthy, so the only safe answer
        // is to tear the connection down — never to guess a length and resync.
        for (const std::uint32_t c : { 0u, 5u, 0xFFFFFFFFu }) {
            std::vector<std::uint8_t> b(kPduBytes, 0);
            b[0x00] = static_cast<std::uint8_t>(c >> 24);
            b[0x01] = static_cast<std::uint8_t>(c >> 16);
            b[0x02] = static_cast<std::uint8_t>(c >> 8);
            b[0x03] = static_cast<std::uint8_t>(c);
            UsbipPdu p;
            CHECK(!decodePdu(b, p));
        }
    }

    TEST_CASE("number_of_packets is clamped, and the clamp is reported") {
        // Unclamped, a caller multiplies this by 16 and tries to read 64 GiB of
        // descriptors for what is an ordinary bulk transfer.
        std::vector<std::uint8_t> b(kPduBytes, 0);
        b[0x03] = 0x01;                               // CMD_SUBMIT
        b[0x20] = 0xFF; b[0x21] = 0xFF; b[0x22] = 0xFF; b[0x23] = 0xFF;  // -1

        UsbipPdu p;
        bool clamped = false;
        CHECK(decodePdu(b, p, &clamped));
        CHECK(clamped);
        CHECK_EQ(p.numberOfPackets, 0);

        b[0x20] = 0x00; b[0x21] = 0x01; b[0x22] = 0x00; b[0x23] = 0x00;  // 65536
        clamped = false;
        CHECK(decodePdu(b, p, &clamped));
        CHECK(clamped);
        CHECK_EQ(p.numberOfPackets, kMaxIsoPackets);
    }

    TEST_CASE("a negative transfer_buffer_length is decoded as negative, not huge") {
        // It must reach the caller as -1 so the caller can refuse it. Decoding it
        // into an unsigned length is how a 4 GiB read gets attempted.
        std::vector<std::uint8_t> b(kPduBytes, 0);
        b[0x03] = 0x01;
        b[0x18] = 0xFF; b[0x19] = 0xFF; b[0x1A] = 0xFF; b[0x1B] = 0xFF;
        UsbipPdu p;
        CHECK(decodePdu(b, p));
        CHECK_EQ(p.transferBufferLength, -1);
        CHECK(!p.hasOutPayload());          // and it announces no payload
    }

    TEST_CASE("unknown transfer_flags bits are preserved, not rejected") {
        // DMA_MAP_SG, DIR_IN and NO_INTERRUPT are present on ordinary
        // usb-storage traffic. A decoder that rejects what it does not
        // recognise refuses every real URB.
        std::vector<std::uint8_t> b(kPduBytes, 0);
        b[0x03] = 0x01;
        b[0x14] = 0xDE; b[0x15] = 0xAD; b[0x16] = 0xBE; b[0x17] = 0xEF;
        UsbipPdu p;
        CHECK(decodePdu(b, p));
        CHECK_EQ(p.transferFlags, 0xDEADBEEFu);
    }

    TEST_CASE("the flags seen on real usb-storage traffic decode as themselves") {
        struct { std::uint32_t flags; bool shortNotOk; } cases[] = {
            { 0x00000000u, false },   // CBW, ep2 OUT
            { 0x00040201u, true  },   // INQUIRY data, ep1 IN: SHORT_NOT_OK|DIR_IN|DMA_MAP_SG
            { 0x00000200u, false },   // CSW, ep1 IN
        };
        for (const auto& c : cases) {
            std::vector<std::uint8_t> b(kPduBytes, 0);
            b[0x03] = 0x01;
            b[0x14] = static_cast<std::uint8_t>(c.flags >> 24);
            b[0x15] = static_cast<std::uint8_t>(c.flags >> 16);
            b[0x16] = static_cast<std::uint8_t>(c.flags >> 8);
            b[0x17] = static_cast<std::uint8_t>(c.flags);
            UsbipPdu p;
            CHECK(decodePdu(b, p));
            CHECK_EQ(p.transferFlags, c.flags);
            CHECK_EQ((p.transferFlags & kUrbShortNotOk) != 0, c.shortNotOk);
        }
    }
}

void testIso()
{
    std::printf("isochronous descriptors\n");

    TEST_CASE("all four fields are big-endian, including status") {
        std::vector<UsbipIsoDesc> in{ { 0, 192, 180, 0 }, { 192, 192, 0, -71 } };
        std::vector<std::uint8_t> bytes;
        encodeIsoDescs(in, bytes);
        CHECK_EQ(bytes.size(), 2 * kIsoDescBytes);
        CHECK_EQ(bytes[3], 0u);      // offset 0, big-endian
        CHECK_EQ(bytes[7], 192u);    // length 192 in the LAST byte

        std::vector<UsbipIsoDesc> out;
        CHECK(decodeIsoDescs(bytes, 2, out));
        CHECK_EQ(out.size(), 2u);
        CHECK_EQ(out[0].length, 192u);
        CHECK_EQ(out[0].actualLength, 180u);
        CHECK_EQ(out[1].offset, 192u);
        CHECK_EQ(out[1].status, -71);
    }

    TEST_CASE("a descriptor array of the wrong size is refused") {
        std::vector<std::uint8_t> bytes(kIsoDescBytes * 2, 0);
        std::vector<UsbipIsoDesc> out;
        CHECK(!decodeIsoDescs(bytes, 3, out));                       // too few bytes
        CHECK(!decodeIsoDescs(bytes, 1, out));                       // too many
        CHECK(!decodeIsoDescs({}, kMaxIsoPackets + 1, out));         // past the clamp
        CHECK(decodeIsoDescs(bytes, 2, out));
    }
}

} // namespace

int main()
{
    std::printf("test_usbip\n");
    testTheGoldenPdu();
    testFraming();
    testRoundTrips();
    testHostileInput();
    testIso();
    TEST_MAIN_END();
}
