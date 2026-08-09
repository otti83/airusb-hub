// The write path, which until now had never carried a byte.
//
// Every data phase this project has measured travelled device -> host. `bulkOut`
// has only ever carried 31-byte CBWs, so the host -> device direction — a real
// payload, fragmented across records, through the cipher and the credit
// controller — was entirely unexercised. §5 of the handoff records it as
// "untested" and expects a real importer to test it "for free" by mounting a
// filesystem. That is a bad way to find out: the free test is performed on
// somebody's data.
//
// So the instrument is validated here first, the same way BotProbe was: against
// ScriptedDevice, and against ports that break exactly one property, so a PASS
// from it over the network means something.

#include "../TestHarness.h"
#include "../fakes/ScriptedDevice.h"
#include "../../diag/WriteProbe.h"
#include "../../protocol/Wire.h"

using namespace airusb;
using namespace airusb::diag;
using namespace airusb::fakes;

namespace {

BotEndpoints endpointsOf(ScriptedDevice& d)
{
    BotEndpoints eps;
    CHECK(findBotInterface(d.manifest(), 1, eps));
    return eps;
}

/// Truncates OUT data phases (but not the 31-byte CBW, so the failure shows up
/// as corrupted data rather than a stalled wrapper). This is the bug that would
/// silently write short blocks to a filesystem.
class TruncatingOutPort final : public IUsbDevicePort {
public:
    explicit TruncatingOutPort(ScriptedDevice& d) : _d(d) {}
    const DeviceManifest& manifest() const noexcept override { return _d.manifest(); }
    Status controlTransfer(const SetupPacket& s, std::span<const std::uint8_t> o,
                           std::vector<std::uint8_t>& i) override
    { return _d.controlTransfer(s, o, i); }
    Status bulkOut(std::uint8_t ep, std::span<const std::uint8_t> data,
                   std::uint32_t* actual) override
    {
        if (data.size() > 31) {
            const std::size_t half = data.size() / 2;
            return _d.bulkOut(ep, data.subspan(0, half), actual);
        }
        return _d.bulkOut(ep, data, actual);
    }
    Status bulkIn(std::uint8_t ep, std::uint32_t maxLen,
                  std::vector<std::uint8_t>& out) override
    { return _d.bulkIn(ep, maxLen, out); }
    Status clearHalt(std::uint8_t ep) override { return _d.clearHalt(ep); }

private:
    ScriptedDevice& _d;
};

/// Corrupts one byte in the middle of every large OUT payload. Everything else
/// works: the CBW goes out whole, the CSW comes back good, the lengths all
/// agree. Only the bytes are wrong, which is exactly what quiet corruption is.
class ByteFlippingPort final : public IUsbDevicePort {
public:
    explicit ByteFlippingPort(ScriptedDevice& d) : _d(d) {}
    const DeviceManifest& manifest() const noexcept override { return _d.manifest(); }
    Status controlTransfer(const SetupPacket& s, std::span<const std::uint8_t> o,
                           std::vector<std::uint8_t>& i) override
    { return _d.controlTransfer(s, o, i); }
    Status bulkOut(std::uint8_t ep, std::span<const std::uint8_t> data,
                   std::uint32_t* actual) override
    {
        if (data.size() > 31) {
            std::vector<std::uint8_t> copy(data.begin(), data.end());
            copy[copy.size() / 2] ^= 0xFFu;
            return _d.bulkOut(ep, std::span<const std::uint8_t>(copy), actual);
        }
        return _d.bulkOut(ep, data, actual);
    }
    Status bulkIn(std::uint8_t ep, std::uint32_t maxLen,
                  std::vector<std::uint8_t>& out) override
    { return _d.bulkIn(ep, maxLen, out); }
    Status clearHalt(std::uint8_t ep) override { return _d.clearHalt(ep); }

private:
    ScriptedDevice& _d;
};

void testPattern()
{
    std::printf("the pattern\n");

    TEST_CASE("a one-block displacement changes the byte") {
        // The whole point of keying on the LBA. If the pattern repeated per
        // block, a write landing on the wrong block would verify clean.
        int differing = 0;
        for (std::uint32_t i = 0; i < 512; ++i)
            if (writePatternByte(7, i) != writePatternByte(8, i)) ++differing;
        CHECK(differing > 400);
    }

    TEST_CASE("a one-byte displacement changes the byte") {
        int differing = 0;
        for (std::uint32_t i = 0; i < 511; ++i)
            if (writePatternByte(7, i) != writePatternByte(7, i + 1)) ++differing;
        CHECK(differing > 400);
    }

    TEST_CASE("it is not a constant and not all one value") {
        bool seenLow = false, seenHigh = false;
        for (std::uint32_t i = 0; i < 512; ++i) {
            const std::uint8_t b = writePatternByte(3, i);
            if (b < 0x40) seenLow = true;
            if (b > 0xC0) seenHigh = true;
        }
        CHECK(seenLow);
        CHECK(seenHigh);
    }
}

void testHappyPath()
{
    std::printf("writing to a working device\n");

    TEST_CASE("a write round-trips byte for byte, at every size") {
        ScriptedDevice dev{61440, 512};
        WriteProbe probe(dev, endpointsOf(dev));
        WriteProbe::Options opt;
        opt.startLba = 100;
        const WriteProbeResult r = probe.runDestructiveWriteTest(opt);

        CHECK(r.passed);
        CHECK_EQ(r.mismatchedBytes, 0u);
        CHECK(r.outBoundariesIntact);
        CHECK(r.restored);
        // 1 + 4 + 32 + 256 blocks of 512, plus the 256-block restore.
        CHECK_EQ(r.bytesWritten, (1u + 4u + 32u + 256u + 256u) * 512u);
    }

    TEST_CASE("the largest run cannot fit in any legal record") {
        // This used to assert 32 blocks x 512 = 16384 and describe it as forcing
        // the record layer to fragment. It did not. The default record is 16 640
        // bytes, so 16 384 of payload plus a 32-byte header, a 40-byte body and a
        // 16-byte AEAD tag came to 16 472 — comfortably inside one record. The
        // end-to-end runs that cited this test as their segmentation evidence
        // were therefore exercising the unsegmented path, twice.
        //
        // The honest bound is the protocol's, not today's default: 65 519 is
        // Noise's plaintext limit and so the largest record that can ever be
        // negotiated. A run above it segments at every legal record size, which
        // is the property the network probe depends on.
        ScriptedDevice dev{61440, 512};
        WriteProbe probe(dev, endpointsOf(dev));
        const WriteProbeResult r = probe.runDestructiveWriteTest({});
        CHECK(r.passed);
        CHECK_EQ(r.largestOutBytes, 256u * 512u);
        CHECK(r.largestOutBytes > wire::kRecordBytesCeiling);
    }

    TEST_CASE("the original contents come back") {
        ScriptedDevice dev{61440, 512};

        // Put something recognisable down first, then check the probe leaves it.
        BotEndpoints eps = endpointsOf(dev);
        WriteProbe seed(dev, eps);
        WriteProbe::Options s;
        s.startLba        = 0;
        s.runs            = { 32 };
        s.restoreOriginal = false;
        CHECK(seed.runDestructiveWriteTest(s).passed);

        // Now run at the same place and demand it is put back.
        WriteProbe probe(dev, eps);
        WriteProbe::Options opt;
        opt.startLba = 0;
        const WriteProbeResult r = probe.runDestructiveWriteTest(opt);
        CHECK(r.passed);
        CHECK(r.restored);

        // The seed pattern is what should be on the medium again.
        WriteProbe check(dev, eps);
        WriteProbe::Options verify;
        verify.startLba        = 0;
        verify.runs            = { 1 };
        verify.restoreOriginal = false;
        const WriteProbeResult after = check.runDestructiveWriteTest(verify);
        CHECK(after.passed);
    }
}

void testItCatchesBreakage()
{
    std::printf("what it must not miss\n");

    TEST_CASE("a truncated OUT data phase is caught, not rounded up") {
        ScriptedDevice dev{61440, 512};
        TruncatingOutPort port(dev);
        WriteProbe probe(port, endpointsOf(dev));
        const WriteProbeResult r = probe.runDestructiveWriteTest({});

        CHECK(!r.passed);
        CHECK(!r.outBoundariesIntact);
        CHECK(!r.failure.empty());
    }

    TEST_CASE("one flipped byte in a 16 KB payload is caught") {
        // The failure that a length check alone would sail past.
        ScriptedDevice dev{61440, 512};
        ByteFlippingPort port(dev);
        WriteProbe probe(port, endpointsOf(dev));
        const WriteProbeResult r = probe.runDestructiveWriteTest({});

        CHECK(!r.passed);
        CHECK(r.mismatchedBytes > 0u);
    }

    TEST_CASE("a device that refuses the write reports FAIL, not a crash") {
        ScriptedDevice dev{61440, 512};
        ScriptedFault f;
        f.stallOnCommand = 2;          // the first WRITE_10, after the save read
        dev.setFaults(f);

        WriteProbe probe(dev, endpointsOf(dev));
        const WriteProbeResult r = probe.runDestructiveWriteTest({});
        CHECK(!r.passed);
        CHECK(!r.failure.empty());
    }
}

} // namespace

int main()
{
    std::printf("test_writeprobe\n");
    testPattern();
    testHappyPath();
    testItCatchesBreakage();
    TEST_MAIN_END();
}
