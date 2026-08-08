// P2.8 — the BOT prober, validated before it is ever pointed at hardware.
//
// diag/BotProbe is the instrument that answers P2.8's gate question on a real
// drive: "did a CBW go out, did data come back, did a CSW close the phase?" On
// hardware a FAIL from that instrument has to mean the hardware path is broken.
// It can only mean that if the instrument itself is known-good, so it is run here
// against ScriptedDevice — a real Bulk-Only Transport implementation over a RAM
// disk — on every commit.
//
// The negative cases matter more than the positive one. A probe that reports PASS
// against a working device but also fails to notice a split transfer would sail
// through the hardware run and certify a broken exporter.

#include "../TestHarness.h"
#include "../fakes/ScriptedDevice.h"
#include "../../diag/BotProbe.h"

using namespace airusb;
using namespace airusb::diag;
using namespace airusb::fakes;

namespace {

// ---------------------------------------------------------------------------
// Decorators that break exactly one property of the transport, so the probe can
// be shown to catch each one. These are what a buggy exporter would look like.
// ---------------------------------------------------------------------------

/// Splits every OUT transfer in half and reports only the first half as moved.
/// This is the transfer-splitting bug OQ-1 is about: a real device sees a short
/// packet where a 31-byte CBW should have been and stalls.
class SplittingPort final : public IUsbDevicePort {
public:
    explicit SplittingPort(ScriptedDevice& d) : _d(d) {}
    const DeviceManifest& manifest() const noexcept override { return _d.manifest(); }
    Status controlTransfer(const SetupPacket& s, std::span<const std::uint8_t> o,
                           std::vector<std::uint8_t>& i) override
    { return _d.controlTransfer(s, o, i); }
    Status bulkOut(std::uint8_t ep, std::span<const std::uint8_t> data,
                   std::uint32_t* actual) override
    {
        const std::size_t half = data.size() / 2;
        return _d.bulkOut(ep, data.subspan(0, half), actual);
    }
    Status bulkIn(std::uint8_t ep, std::uint32_t max, std::vector<std::uint8_t>& out) override
    { return _d.bulkIn(ep, max, out); }
    Status clearHalt(std::uint8_t ep) noexcept override { return _d.clearHalt(ep); }
private:
    ScriptedDevice& _d;
};

/// Reports the offered length as the actual length on every IN transfer, padding
/// with zeros. A filesystem reading a partially-filled final block would get
/// silent garbage; nothing returns an error anywhere.
class PaddingPort final : public IUsbDevicePort {
public:
    explicit PaddingPort(ScriptedDevice& d) : _d(d) {}
    const DeviceManifest& manifest() const noexcept override { return _d.manifest(); }
    Status controlTransfer(const SetupPacket& s, std::span<const std::uint8_t> o,
                           std::vector<std::uint8_t>& i) override
    { return _d.controlTransfer(s, o, i); }
    Status bulkOut(std::uint8_t ep, std::span<const std::uint8_t> data,
                   std::uint32_t* actual) override
    { return _d.bulkOut(ep, data, actual); }
    Status bulkIn(std::uint8_t ep, std::uint32_t max, std::vector<std::uint8_t>& out) override
    {
        const Status st = _d.bulkIn(ep, max, out);
        if (st == Status::Ok) out.resize(max, 0u);
        return st;
    }
    Status clearHalt(std::uint8_t ep) noexcept override { return _d.clearHalt(ep); }
private:
    ScriptedDevice& _d;
};

/// Truncates every IN transfer to one maximum packet, as a transport that
/// mistook a USB packet for a USB transfer would.
class FragmentingPort final : public IUsbDevicePort {
public:
    FragmentingPort(ScriptedDevice& d, std::uint32_t cap) : _d(d), _cap(cap) {}
    const DeviceManifest& manifest() const noexcept override { return _d.manifest(); }
    Status controlTransfer(const SetupPacket& s, std::span<const std::uint8_t> o,
                           std::vector<std::uint8_t>& i) override
    { return _d.controlTransfer(s, o, i); }
    Status bulkOut(std::uint8_t ep, std::span<const std::uint8_t> data,
                   std::uint32_t* actual) override
    { return _d.bulkOut(ep, data, actual); }
    Status bulkIn(std::uint8_t ep, std::uint32_t max, std::vector<std::uint8_t>& out) override
    { return _d.bulkIn(ep, max < _cap ? max : _cap, out); }
    Status clearHalt(std::uint8_t ep) noexcept override { return _d.clearHalt(ep); }
private:
    ScriptedDevice& _d;
    std::uint32_t   _cap;
};

// ---------------------------------------------------------------------------

void testEndpointDiscovery()
{
    std::printf("endpoint discovery\n");

    ScriptedDevice dev;

    TEST_CASE("the BOT interface is found from the manifest alone") {
        BotEndpoints eps;
        CHECK(findBotInterface(dev.manifest(), 1, eps));
        CHECK_EQ(eps.bulkIn, kScriptedBulkIn);
        CHECK_EQ(eps.bulkOut, kScriptedBulkOut);
        CHECK_EQ(eps.interfaceNumber, 0);
        CHECK_EQ(eps.altSetting, 0);
        // 1024 is the SuperSpeed bulk maximum. Reading 512 here would mean the
        // manifest parser lost the SuperSpeed companion.
        CHECK_EQ(eps.maxPacketSize, 1024);
        CHECK(eps.valid());
    }

    TEST_CASE("a configuration value that does not exist is not invented") {
        BotEndpoints eps;
        CHECK(!findBotInterface(dev.manifest(), 7, eps));
    }

    TEST_CASE("an empty manifest yields no endpoints rather than a crash") {
        DeviceManifest empty;
        BotEndpoints eps;
        CHECK(!findBotInterface(empty, 1, eps));
    }
}

void testHappyPath()
{
    std::printf("the probe against a correct device\n");

    ScriptedDevice dev(2048, 512);
    dev.fillPattern(0xA1B2C3D4u);
    const std::uint64_t before = dev.checksum();

    BotEndpoints eps;
    CHECK(findBotInterface(dev.manifest(), 1, eps));

    BotProbe probe(dev, eps);
    const BotProbeResult r = probe.run();

    TEST_CASE("the probe passes") {
        if (!r.passed) std::printf("\n%s", r.summary().c_str());
        CHECK(r.passed);
        CHECK(r.failure.empty());
        CHECK(r.transferBoundariesIntact);
    }

    TEST_CASE("it reports the device's real geometry, not assumptions") {
        CHECK_EQ(r.blockSize, 512u);
        CHECK_EQ(r.blockCount(), 2048ull);
        // READ CAPACITY(10) returns the LAST LBA. A probe that reported 2048 here
        // would be off by one at exactly the end of the medium.
        CHECK_EQ(r.lastLba, 2047ull);
    }

    TEST_CASE("INQUIRY strings are decoded and space-trimmed") {
        CHECK(!r.vendor.empty());
        CHECK(!r.product.empty());
        CHECK(r.vendor.back() != ' ');
        CHECK(r.product.back() != ' ');
    }

    TEST_CASE("every phase actually happened") {
        // 5 commands minimum: TUR, INQUIRY, READ CAPACITY, READ, short-read,
        // multiblock. Each is one CBW and one CSW.
        CHECK(r.cbwCount >= 5);
        CHECK_EQ(r.cswCount, r.cbwCount);
        CHECK(r.dataPhases >= 4);
    }

    TEST_CASE("a read-only probe leaves the medium byte-identical") {
        CHECK_EQ(dev.checksum(), before);
    }

    TEST_CASE("the device is left in a clean phase state") {
        CHECK(dev.phase() == BotPhase::AwaitingCbw);
        CHECK(!dev.inHalted());
        CHECK(!dev.outHalted());
    }
}

void testDetection()
{
    std::printf("the probe against broken transports\n");

    TEST_CASE("a split OUT transfer is caught, not tolerated") {
        ScriptedDevice dev;
        BotEndpoints eps;
        CHECK(findBotInterface(dev.manifest(), 1, eps));
        SplittingPort port(dev);
        BotProbe probe(port, eps);
        const BotProbeResult r = probe.run();
        CHECK(!r.passed);
        CHECK(!r.failure.empty());
    }

    TEST_CASE("an IN transfer padded up to the offered length is caught") {
        ScriptedDevice dev;
        BotEndpoints eps;
        CHECK(findBotInterface(dev.manifest(), 1, eps));
        PaddingPort port(dev);
        BotProbe probe(port, eps);
        const BotProbeResult r = probe.run();
        // The CSW read is what catches it first: 13 bytes offered, 13 returned,
        // but the INQUIRY data phase came back 36 bytes when 36 were asked for
        // and then the short-read case gets blockSize+512 instead of blockSize.
        CHECK(!r.passed);
    }

    TEST_CASE("an IN transfer fragmented at the packet boundary is caught") {
        ScriptedDevice dev(2048, 512);
        BotEndpoints eps;
        CHECK(findBotInterface(dev.manifest(), 1, eps));
        FragmentingPort port(dev, 512);      // one block max, so 4 blocks cannot fit
        BotProbe probe(port, eps);
        const BotProbeResult r = probe.run();
        CHECK(!r.passed);
        CHECK(!r.transferBoundariesIntact);
    }
}

void testStallRecovery()
{
    std::printf("stall recovery\n");

    TEST_CASE("a scripted stall is recovered and reported, not hidden") {
        ScriptedDevice dev;
        ScriptedFault f;
        f.stallOnCommand = 3;              // stall the third command's data phase
        dev.setFaults(f);

        BotEndpoints eps;
        CHECK(findBotInterface(dev.manifest(), 1, eps));
        BotProbe probe(dev, eps);
        const BotProbeResult r = probe.run();

        // Whether the run as a whole passes depends on which command was hit;
        // what must be true either way is that the stall was SEEN. A probe that
        // silently swallowed it would report a clean run on a wedged endpoint.
        CHECK(r.stallRecoveries > 0 || !r.failure.empty());
    }
}

void testTracing()
{
    std::printf("evidence\n");

    TEST_CASE("every transfer is traceable for the hardware run's log") {
        ScriptedDevice dev;
        BotEndpoints eps;
        CHECK(findBotInterface(dev.manifest(), 1, eps));

        int lines = 0;
        BotProbe probe(dev, eps);
        probe.setTrace([&](const std::string& s) { if (!s.empty()) ++lines; });
        const BotProbeResult r = probe.run();
        CHECK(r.passed);
        // One line per CBW, per data phase and per CSW, plus the header and the
        // control request. A silent probe produces no usable hardware evidence.
        CHECK(lines >= static_cast<int>(r.cbwCount + r.cswCount));
    }

    TEST_CASE("the summary names the failing step") {
        ScriptedDevice dev;
        BotEndpoints eps;
        CHECK(findBotInterface(dev.manifest(), 1, eps));
        SplittingPort port(dev);
        BotProbe probe(port, eps);
        const BotProbeResult r = probe.run();
        const std::string s = r.summary();
        CHECK(s.find("FAIL") != std::string::npos);
        CHECK(!r.failure.empty());
    }
}

} // namespace

int main()
{
    std::printf("test_botprobe\n");
    testEndpointDiscovery();
    testHappyPath();
    testDetection();
    testStallRecovery();
    testTracing();
    TEST_MAIN_END();
}
