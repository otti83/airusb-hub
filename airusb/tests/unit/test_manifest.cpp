// DEVICE_MANIFEST on the wire.
//
// The manifest is a completeness contract, not a cache: Windows UdeCx needs the
// whole descriptor set before the device can be created at all, and macOS needs
// it to answer kernel commands without a LAN round trip. So the tests here are
// about completeness and about refusing anything incomplete — not about whether
// bytes survive a round trip.
//
// It is also the first large, variable-length, peer-shaped structure in a
// session. Every declared count in the header is a number an attacker chose, and
// each one is tested against a body that does not match it.

#include "../TestHarness.h"
#include "../fakes/ScriptedDevice.h"
#include "../../protocol/ManifestCodec.h"
#include "../../protocol/Codec.h"

#include <cstring>
#include <string>

using namespace airusb;
using namespace airusb::protocol;
using namespace airusb::fakes;

namespace {

/// A manifest with strings and a LANGID table, which ScriptedDevice's does not
/// have — the string path is the part most likely to be got wrong.
DeviceManifest richManifest()
{
    DeviceManifest m;
    m.setSpeed(Speed::Super);

    const std::uint8_t dev[18] = {
        18, kDescDevice, 0x20, 0x03, 0x00, 0x00, 0x00, 9,
        0x8f, 0x05, 0x87, 0x63, 0x02, 0x00, 1, 2, 3, 1
    };
    m.setDeviceDescriptor(dev);

    const std::uint8_t cfg[44] = {
        9, kDescConfiguration, 44, 0, 1, 1, 0, 0x80, 50,
        9, kDescInterface, 0, 0, 2, 0x08, 0x06, 0x50, 0,
        7, kDescEndpoint, 0x81, 0x02, 0x00, 0x04, 0,
        6, kDescSsEndpointCompanion, 15, 0, 0, 0,
        7, kDescEndpoint, 0x02, 0x02, 0x00, 0x04, 0,
        6, kDescSsEndpointCompanion, 15, 0, 0, 0,
    };
    m.addConfiguration(cfg);

    const std::uint8_t bos[22] = {
        5, kDescBos, 22, 0, 2,
        7, kDescDeviceCapability, 2, 0x06, 0, 0, 0,
        10, kDescDeviceCapability, 3, 0x00, 0x0E, 0x00, 0x01, 0x0A, 0x00, 0x00,
    };
    m.setBos(bos);

    const std::uint16_t langs[1] = { 0x0409 };
    m.setLangIds(langs);

    // Index 1, 2, 3 are referenced by the device descriptor above.
    const std::uint8_t s1[] = { 8, kDescString, 'G',0,'e',0,'n',0 };
    const std::uint8_t s2[] = { 10, kDescString, 'F',0,'l',0,'a',0,'s',0 };
    const std::uint8_t s3[] = { 6, kDescString, '0',0,'1',0 };
    m.addString(1, 0x0409, s1);
    m.addString(2, 0x0409, s2);
    m.addString(3, 0x0409, s3);
    return m;
}

std::vector<std::uint8_t> encodeOf(const DeviceManifest& m, std::uint8_t cfgValue = 1)
{
    std::vector<std::uint8_t> out;
    const Status s = encodeManifest(m, cfgValue, out);
    if (s != Status::Ok) {
        std::printf("\n    encodeManifest failed: %s\n", statusName(s));
        out.clear();
    }
    return out;
}

void testRoundTrip()
{
    std::printf("round trip\n");

    TEST_CASE("a scripted device's manifest survives the wire") {
        ScriptedDevice dev;
        const auto body = encodeOf(dev.manifest());
        CHECK(!body.empty());

        DeviceManifest got;
        ManifestHeader hdr;
        std::string why;
        const Status s = decodeManifest(body, got, hdr, &why);
        if (s != Status::Ok) std::printf("\n    decode: %s\n", why.c_str());
        CHECK(s == Status::Ok);

        CHECK(got.speed() == Speed::Super);
        CHECK_EQ(got.configurationCount(), 1u);
        CHECK_EQ(hdr.currentConfigValue, 1);
    }

    TEST_CASE("descriptor bytes are byte-identical, not re-serialized") {
        // The whole point. A SuperSpeed device must arrive as a SuperSpeed
        // device, companion descriptors and all — the moment this layer starts
        // rewriting descriptors, the importer presents a device that does not
        // exist.
        const DeviceManifest m = richManifest();
        const auto body = encodeOf(m);
        CHECK(!body.empty());

        DeviceManifest got;
        ManifestHeader hdr;
        CHECK(decodeManifest(body, got, hdr) == Status::Ok);

        const auto a = m.deviceDescriptor();
        const auto b = got.deviceDescriptor();
        CHECK_EQ(a.size(), b.size());
        CHECK(std::memcmp(a.data(), b.data(), a.size()) == 0);

        const auto ca = m.configurationByIndex(0);
        const auto cb = got.configurationByIndex(0);
        CHECK_EQ(ca.size(), cb.size());
        CHECK(std::memcmp(ca.data(), cb.data(), ca.size()) == 0);

        const auto ba = m.bos();
        const auto bb = got.bos();
        CHECK_EQ(ba.size(), bb.size());
        CHECK(std::memcmp(ba.data(), bb.data(), ba.size()) == 0);
    }

    TEST_CASE("strings and the LANGID table survive, keyed by index and language") {
        const DeviceManifest m = richManifest();
        const auto body = encodeOf(m);
        CHECK(!body.empty());

        DeviceManifest got;
        ManifestHeader hdr;
        std::string why;
        const Status s = decodeManifest(body, got, hdr, &why);
        if (s != Status::Ok) std::printf("\n    decode: %s\n", why.c_str());
        CHECK(s == Status::Ok);
        CHECK_EQ(hdr.stringCount, 3u);
        CHECK_EQ(hdr.langidCount, 1u);

        for (std::uint8_t i = 1; i <= 3; ++i) {
            const auto a = m.stringDescriptor(i, 0x0409);
            const auto b = got.stringDescriptor(i, 0x0409);
            CHECK(!b.empty());
            CHECK_EQ(a.size(), b.size());
            CHECK(std::memcmp(a.data(), b.data(), a.size()) == 0);
        }

        // Index 0 is the LANGID table, not a string — which is what USB says
        // GET_DESCRIPTOR(STRING, 0) returns, and what DeviceManifest implements.
        // The thing that would be a bug is the table being stored as string 0
        // AND counted as one, so check both the value and the count.
        const auto zero = got.stringDescriptor(0, 0x0409);
        CHECK(!zero.empty());
        CHECK(zero.size() == got.langIdTable().size());
        CHECK(std::memcmp(zero.data(), got.langIdTable().data(), zero.size()) == 0);
        CHECK_EQ(hdr.stringCount, 3u);      // 1, 2, 3 — the table is not among them
    }

    TEST_CASE("the endpoint table rebuilds, with SuperSpeed burst intact") {
        ScriptedDevice dev;
        const auto body = encodeOf(dev.manifest());
        DeviceManifest got;
        ManifestHeader hdr;
        CHECK(decodeManifest(body, got, hdr) == Status::Ok);

        const auto eps = got.endpointsFor(1, 0, 0);
        CHECK_EQ(eps.size(), 2u);
        CHECK_EQ(eps[0].maxPacketSize, 1024);
        CHECK_EQ(eps[0].maxBurst, 15);
    }
}

void testHostileInput()
{
    std::printf("a manifest is peer-shaped input\n");

    const DeviceManifest m = richManifest();
    const auto good = encodeOf(m);

    TEST_CASE("truncation at every length is refused, never read past") {
        DeviceManifest got;
        ManifestHeader hdr;
        for (std::size_t n = 0; n < good.size(); ++n) {
            const Status s = decodeManifest(
                std::span<const std::uint8_t>(good).subspan(0, n), got, hdr);
            CHECK(s != Status::Ok);
        }
    }

    TEST_CASE("a config count larger than the body carries is refused") {
        auto bad = good;
        wr_u32(bad.data() + 4, 8);          // claim 8 configs; one is present
        DeviceManifest got;
        ManifestHeader hdr;
        std::string why;
        CHECK(decodeManifest(bad, got, hdr, &why) != Status::Ok);
        CHECK(why.find("configurations") != std::string::npos);
    }

    TEST_CASE("a config count over the ceiling is refused before allocating") {
        auto bad = good;
        wr_u32(bad.data() + 4, 0xFFFFFFFFu);
        DeviceManifest got;
        ManifestHeader hdr;
        CHECK(decodeManifest(bad, got, hdr) == Status::ManifestInvalid);
    }

    TEST_CASE("a string count that disagrees with the TLVs is refused") {
        auto bad = good;
        wr_u32(bad.data() + 8, 99);
        DeviceManifest got;
        ManifestHeader hdr;
        std::string why;
        CHECK(decodeManifest(bad, got, hdr, &why) != Status::Ok);
        CHECK(why.find("string") != std::string::npos);
    }

    TEST_CASE("a blob total longer than the body is refused") {
        auto bad = good;
        wr_u32(bad.data() + 20, 0x000FFFFFu);
        DeviceManifest got;
        ManifestHeader hdr;
        CHECK(decodeManifest(bad, got, hdr) != Status::Ok);
    }

    TEST_CASE("a blob total over the 256 KiB ceiling is refused") {
        auto bad = good;
        wr_u32(bad.data() + 20, wire::kManifestBytesMax + 1);
        DeviceManifest got;
        ManifestHeader hdr;
        CHECK(decodeManifest(bad, got, hdr) == Status::LimitExceeded);
    }

    TEST_CASE("an unknown manifest version is refused, not guessed at") {
        auto bad = good;
        wr_u32(bad.data() + 0, 2);
        DeviceManifest got;
        ManifestHeader hdr;
        CHECK(decodeManifest(bad, got, hdr) == Status::UnsupportedVersion);
    }

    TEST_CASE("a corrupted descriptor byte is caught by the hash") {
        auto bad = good;
        // Flip a byte inside the blob sections, past the 32-byte header.
        bad[kManifestHeaderSize + 12] ^= 0x01u;
        DeviceManifest got;
        ManifestHeader hdr;
        std::string why;
        const Status s = decodeManifest(bad, got, hdr, &why);
        CHECK(s != Status::Ok);
    }

    TEST_CASE("a stripped MANIFEST_HASH is refused") {
        // Truncating the trailer removes the hash. A receiver that accepted a
        // manifest with no hash would accept one with a forged one too.
        const std::size_t hdrBlobs =
            kManifestHeaderSize + rd_u32(good.data() + 20);
        std::vector<std::uint8_t> bad(good.begin(), good.begin() + static_cast<std::ptrdiff_t>(hdrBlobs));
        DeviceManifest got;
        ManifestHeader h2;
        std::string why;
        CHECK(decodeManifest(bad, got, h2, &why) != Status::Ok);
        CHECK(why.find("HASH") != std::string::npos);
    }

    TEST_CASE("a speed that contradicts the descriptors is refused") {
        // The USBSpeed/Device Speed trap, on the wire. A SuperSpeed descriptor
        // set declared as High Speed is exactly the silent USB-2 downgrade the
        // manifest validator exists to stop.
        auto bad = good;
        wr_u16(bad.data() + 16, static_cast<std::uint16_t>(Speed::High));
        DeviceManifest got;
        ManifestHeader hdr;
        std::string why;
        const Status s = decodeManifest(bad, got, hdr, &why);
        CHECK(s != Status::Ok);
    }

    TEST_CASE("a current_config_value naming no configuration is refused") {
        const DeviceManifest r = richManifest();
        std::vector<std::uint8_t> body;
        CHECK(encodeManifest(r, 7, body) == Status::Ok);   // no config has value 7
        DeviceManifest got;
        ManifestHeader hdr;
        std::string why;
        CHECK(decodeManifest(body, got, hdr, &why) == Status::ManifestInvalid);
        CHECK(why.find("current_config_value") != std::string::npos);
    }

    TEST_CASE("unknown TLVs are ignored, as the extension rule requires") {
        // §3.0: receivers ignore unknown TLVs. Anything semantics-bearing gets a
        // new manifest_version instead.
        const DeviceManifest r = richManifest();
        std::vector<std::uint8_t> body;
        CHECK(encodeManifest(r, 1, body) == Status::Ok);

        // Append a TLV nobody knows, after the hash.
        const std::uint8_t junk[4] = { 0xDE, 0xAD, 0xBE, 0xEF };
        appendTlv(static_cast<wire::Tlv>(0x7FFF),
                  std::span<const std::uint8_t>(junk, sizeof junk), body);

        DeviceManifest got;
        ManifestHeader hdr;
        CHECK(decodeManifest(body, got, hdr) == Status::Ok);
    }
}

void testRefusesToSendGarbage()
{
    std::printf("the encoder refuses what the decoder would\n");

    TEST_CASE("an empty manifest is not serialized") {
        DeviceManifest empty;
        std::vector<std::uint8_t> out;
        CHECK(encodeManifest(empty, 0, out) == Status::ManifestInvalid);
        CHECK(out.empty());
    }

    TEST_CASE("a manifest that fails validation is not serialized") {
        // Sending a manifest we would refuse to receive means the peer debugs
        // our bug.
        DeviceManifest m = richManifest();
        m.setSpeed(Speed::High);            // contradicts the SS companions
        std::vector<std::uint8_t> out;
        CHECK(encodeManifest(m, 1, out) == Status::ManifestInvalid);
    }
}

} // namespace

int main()
{
    std::printf("test_manifest\n");
    testRoundTrip();
    testHostileInput();
    testRefusesToSendGarbage();
    TEST_MAIN_END();
}
