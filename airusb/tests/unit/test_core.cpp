// P2.2 — core layer: Watchdog, Clock, DeviceManifest, Ep0Arbiter,
// RequestTable, CreditController.
//
// The manifest fixture is the REAL descriptor set read off the test device in
// docs/P1_CAPTURE_VERIFICATION.md (058f:6387, SuperSpeed BOT mass storage), not an
// invented one. A fabricated fixture would have quietly encoded whatever
// assumptions the code already makes.

#include "../TestHarness.h"
#include "../../core/Clock.h"
#include "../../core/CreditController.h"
#include "../../core/DeviceManifest.h"
#include "../../core/Ep0Arbiter.h"
#include "../../core/RequestTable.h"
#include "../../core/Watchdog.h"

using namespace airusb;

namespace {

// ---------------------------------------------------------------------------
// Fixture: 058f:6387 as actually measured.
//   bcdUSB 0x0320, bMaxPacketSize0 = 9 (2^9 = 512, SuperSpeed encoding)
//   1 configuration, wTotalLength 44, 1 interface, class 08/06/50 (BOT), 2 endpoints
// ---------------------------------------------------------------------------

DeviceManifest realDeviceManifest()
{
    DeviceManifest m;
    m.setSpeed(Speed::Super);

    const std::uint8_t dev[18] = {
        18, kDescDevice,
        0x20, 0x03,           // bcdUSB 0x0320
        0x00, 0x00, 0x00,     // class/subclass/protocol at interface level
        9,                    // bMaxPacketSize0: SuperSpeed exponent, 2^9 = 512
        0x8f, 0x05,           // idVendor  058f
        0x87, 0x63,           // idProduct 6387
        0x02, 0x00,           // bcdDevice 0002
        1, 2, 3,              // iManufacturer, iProduct, iSerialNumber
        1                     // bNumConfigurations
    };
    m.setDeviceDescriptor(dev);

    // Configuration: 9 + interface 9 + endpoint 7 + companion 6 + endpoint 7 + companion 6 = 44
    const std::uint8_t cfg[44] = {
        9, kDescConfiguration, 44, 0, 1, 1, 0, 0x80, 50,
        9, kDescInterface, 0, 0, 2, 0x08, 0x06, 0x50, 0,
        7, kDescEndpoint, 0x81, 0x02, 0x00, 0x04, 0,      // bulk IN,  1024
        6, kDescSsEndpointCompanion, 15, 0, 0, 0,          // bMaxBurst 15
        7, kDescEndpoint, 0x02, 0x02, 0x00, 0x04, 0,      // bulk OUT, 1024
        6, kDescSsEndpointCompanion, 15, 0, 0, 0,
    };
    m.addConfiguration(cfg);

    const std::uint8_t bos[5] = { 5, kDescBos, 5, 0, 0 };
    m.setBos(bos);

    const std::uint16_t langs[1] = { 0x0409 };
    m.setLangIds(langs);
    const std::uint8_t prod[8] = { 8, kDescString, 'M',0, 'a',0, 's',0 };
    m.addString(2, 0x0409, prod);

    return m;
}

SetupPacket setup(std::uint8_t bmRequestType, std::uint8_t bRequest,
                  std::uint16_t wValue, std::uint16_t wIndex, std::uint16_t wLength)
{
    SetupPacket s;
    s.bmRequestType = bmRequestType;
    s.bRequest      = bRequest;
    s.wValue        = wValue;
    s.wIndex        = wIndex;
    s.wLength       = wLength;
    return s;
}

// ---------------------------------------------------------------------------

void testWatchdog()
{
    TEST_CASE("watchdog ordering holds at runtime as well as compile time") {
        CHECK(watchdog::assertConsistent());
    }

    TEST_CASE("the importer never times out before the exporter") {
        // Two independent timeouts racing to recover a BOT phase is a corruption
        // path, so this ordering is a data-safety property, not a preference.
        CHECK(watchdog::kUrbCeilingBulk < watchdog::kUrbWatchdogImporter);
        CHECK_EQ(watchdog::kUrbWatchdogImporter - watchdog::kUrbCeilingBulk, 15000ull);
    }

    TEST_CASE("the exporter holds the lease past the importer's own giving-up") {
        CHECK(watchdog::kDetachImporter + watchdog::kDisconnectMax < watchdog::kLeaseExporter);
    }

    TEST_CASE("interrupt transfers have no deadline at all") {
        // An interrupt IN may legitimately idle forever; a deadline here would
        // abort every one of them.
        CHECK_EQ(watchdog::kUrbDeadlineIntr, 0ull);
    }
}

void testClock()
{
    TEST_CASE("manual clock drives deadlines deterministically") {
        ManualClock c;
        Deadline d = Deadline::afterMs(c, 1000);
        CHECK(d.isSet());
        CHECK(!d.expired(c));
        c.advanceMs(999);
        CHECK(!d.expired(c));
        c.advanceMs(1);
        CHECK(d.expired(c));
        CHECK_EQ(d.remainingNs(c), 0ull);
    }

    TEST_CASE("zero ms means no deadline, not immediate expiry") {
        ManualClock c;
        Deadline d = Deadline::afterMs(c, watchdog::kUrbDeadlineIntr);
        CHECK(!d.isSet());
        c.advanceMs(1'000'000);
        CHECK(!d.expired(c));     // an idle interrupt IN must never be aborted
    }

    TEST_CASE("system clock is continuous and monotonic") {
        const Clock& c = Clock::system();
        const ContinuousNs a = c.nowNs();
        const ContinuousNs b = c.nowNs();
        CHECK(b >= a);
        CHECK(a > 0);
    }
}

void testManifest()
{
    TEST_CASE("the real device's manifest validates") {
        auto m = realDeviceManifest();
        std::string why;
        auto st = m.validate(&why);
        if (st != Status::Ok) std::printf("\n      whyNot: %s\n", why.c_str());
        CHECK_EQ(static_cast<int>(st), static_cast<int>(Status::Ok));
    }

    TEST_CASE("identity is read from the real descriptor") {
        auto id = realDeviceManifest().identity();
        CHECK_EQ(id.vendorId, 0x058Fu);
        CHECK_EQ(id.productId, 0x6387u);
        CHECK_EQ(static_cast<int>(id.speed), static_cast<int>(Speed::Super));
    }

    TEST_CASE("SuperSpeed requires bMaxPacketSize0 == 9, not 64") {
        // The P1 speed-reporting bug in a testable form: a SuperSpeed manifest
        // carrying a High Speed bMaxPacketSize0 must be rejected, not accepted and
        // silently driven as USB 2.
        auto m = realDeviceManifest();
        std::uint8_t dev[18];
        std::memcpy(dev, m.deviceDescriptor().data(), 18);
        dev[7] = 64;
        m.setDeviceDescriptor(dev);
        CHECK_EQ(static_cast<int>(m.validate()), static_cast<int>(Status::ManifestInvalid));
    }

    TEST_CASE("SuperSpeed requires a BOS descriptor") {
        DeviceManifest m = realDeviceManifest();
        DeviceManifest m2;
        m2.setSpeed(Speed::Super);
        m2.setDeviceDescriptor(m.deviceDescriptor());
        m2.addConfiguration(m.configurationByIndex(0));
        CHECK_EQ(static_cast<int>(m2.validate()), static_cast<int>(Status::ManifestInvalid));
    }

    TEST_CASE("configuration index and bConfigurationValue are not interchangeable") {
        auto m = realDeviceManifest();
        CHECK_EQ(m.configurationByIndex(0).size(), std::size_t{44});
        CHECK_EQ(m.configurationByValue(1).size(), std::size_t{44});
        CHECK(m.configurationByValue(0).empty());   // value 0 does not exist
        CHECK(m.configurationByIndex(1).empty());   // index 1 does not exist
    }

    TEST_CASE("endpoints are parsed with their SuperSpeed companions") {
        auto eps = realDeviceManifest().endpointsFor(1, 0, 0);
        CHECK_EQ(eps.size(), std::size_t{2});
        CHECK_EQ(eps[0].address, 0x81u);
        CHECK_EQ(static_cast<int>(eps[0].direction()), static_cast<int>(Dir::In));
        CHECK_EQ(static_cast<int>(eps[0].type), static_cast<int>(XferType::Bulk));
        CHECK_EQ(eps[0].maxPacketSize, 1024u);
        CHECK_EQ(eps[0].maxBurst, 15u);            // lost -> SuperSpeed driven as USB 2
        CHECK_EQ(eps[1].address, 0x02u);
        CHECK_EQ(static_cast<int>(eps[1].direction()), static_cast<int>(Dir::Out));
    }

    TEST_CASE("descriptor walk rejects a zero bLength instead of looping") {
        const std::uint8_t bad[4] = { 0, kDescInterface, 0, 0 };
        CHECK(!forEachDescriptor(bad, [](std::uint8_t, std::span<const std::uint8_t>) { return true; }));
    }

    TEST_CASE("descriptor walk rejects a bLength past the end") {
        const std::uint8_t bad[4] = { 99, kDescInterface, 0, 0 };
        CHECK(!forEachDescriptor(bad, [](std::uint8_t, std::span<const std::uint8_t>) { return true; }));
    }

    TEST_CASE("a string naming an undeclared LANGID is rejected") {
        auto m = realDeviceManifest();
        const std::uint8_t s[4] = { 4, kDescString, 'x', 0 };
        m.addString(4, 0x0411, s);        // Japanese, not in the table
        CHECK_EQ(static_cast<int>(m.validate()), static_cast<int>(Status::ManifestInvalid));
    }
}

void testEp0Arbiter()
{
    auto manifest = realDeviceManifest();

    TEST_CASE("A-3: an 8-byte GET_DESCRIPTOR(DEVICE) is truncated, not overrun") {
        // macOS enumeration asks for 8 bytes first to learn bMaxPacketSize0.
        // Returning all 18 against an 8-byte kernel buffer overruns kernel memory.
        Ep0Arbiter a(manifest);
        auto d = a.decide(setup(0x80, kGetDescriptor, (kDescDevice << 8), 0, 8));
        CHECK_EQ(static_cast<int>(d.disposition), static_cast<int>(Ep0Disposition::Local));
        CHECK_EQ(d.data.size(), std::size_t{8});
        CHECK(!d.isShort);
        CHECK_EQ(d.data[0], 18u);          // bLength still reports the true length
    }

    TEST_CASE("A-3: a 9-byte GET_DESCRIPTOR(CONFIG) is truncated") {
        Ep0Arbiter a(manifest);
        auto d = a.decide(setup(0x80, kGetDescriptor, (kDescConfiguration << 8), 0, 9));
        CHECK_EQ(d.data.size(), std::size_t{9});
        CHECK_EQ(d.data[2], 44u);          // wTotalLength, which is what it asked for
    }

    TEST_CASE("A-3: an over-long request completes short") {
        Ep0Arbiter a(manifest);
        auto d = a.decide(setup(0x80, kGetDescriptor, (kDescDevice << 8), 0, 255));
        CHECK_EQ(d.data.size(), std::size_t{18});
        CHECK(d.isShort);
    }

    TEST_CASE("SET_ADDRESS is absorbed and never reaches the wire") {
        Ep0Arbiter a(manifest);
        auto d = a.decide(setup(0x00, kSetAddress, 5, 0, 0));
        CHECK_EQ(static_cast<int>(d.disposition), static_cast<int>(Ep0Disposition::Absorb));
    }

    TEST_CASE("GET_STATUS is always forwarded, never cached") {
        // The endpoint HALT bit is live device truth and is exactly what a class
        // driver queries to decide whether recovery is needed. Cached, the drive
        // wedges permanently.
        Ep0Arbiter a(manifest);
        CHECK_EQ(static_cast<int>(a.decide(setup(0x80, kGetStatus, 0, 0, 2)).disposition),
                 static_cast<int>(Ep0Disposition::Forward));
        CHECK_EQ(static_cast<int>(a.decide(setup(0x82, kGetStatus, 0, 0x81, 2)).disposition),
                 static_cast<int>(Ep0Disposition::Forward));
    }

    TEST_CASE("CLEAR_FEATURE(ENDPOINT_HALT) becomes a verb, not a raw forward") {
        // A raw forward clears the device stall but not the exporter host
        // controller's data toggle, leaving every later transfer silently wrong.
        Ep0Arbiter a(manifest);
        auto d = a.decide(setup(0x02, kClearFeature, kFeatEndpointHalt, 0x81, 0));
        CHECK_EQ(static_cast<int>(d.disposition), static_cast<int>(Ep0Disposition::Arbitrate));
        CHECK_EQ(static_cast<int>(d.verb), static_cast<int>(Ep0Verb::EpClearHalt));
        CHECK_EQ(d.arg0, 0x81u);
    }

    TEST_CASE("link-power features are absorbed, not forwarded") {
        // Forwarding these drops the EXPORTER's real link into U1/U2 and destroys
        // throughput, for a setting that is meaningless across a LAN.
        Ep0Arbiter a(manifest);
        for (std::uint16_t f : {kFeatU1Enable, kFeatU2Enable, kFeatLtmEnable, kFeatDeviceRemoteWakeup}) {
            auto d = a.decide(setup(0x00, kSetFeature, f, 0, 0));
            CHECK_EQ(static_cast<int>(d.disposition), static_cast<int>(Ep0Disposition::Absorb));
        }
    }

    TEST_CASE("SET_DESCRIPTOR and TEST_MODE are stalled") {
        Ep0Arbiter a(manifest);
        CHECK_EQ(static_cast<int>(a.decide(setup(0x00, kSetDescriptor, 0, 0, 0)).disposition),
                 static_cast<int>(Ep0Disposition::Stall));
        CHECK_EQ(static_cast<int>(a.decide(setup(0x00, kSetFeature, kFeatTestMode, 0, 0)).disposition),
                 static_cast<int>(Ep0Disposition::Stall));
    }

    TEST_CASE("mass-storage class requests are forwarded") {
        // Bulk-Only Reset (0x21/0xFF) and GET_MAX_LUN (0xA1/0xFE) are how the class
        // driver recovers; answering them locally breaks recovery exactly when it
        // matters.
        Ep0Arbiter a(manifest);
        CHECK_EQ(static_cast<int>(a.decide(setup(0x21, 0xFF, 0, 0, 0)).disposition),
                 static_cast<int>(Ep0Disposition::Forward));
        CHECK_EQ(static_cast<int>(a.decide(setup(0xA1, 0xFE, 0, 0, 1)).disposition),
                 static_cast<int>(Ep0Disposition::Forward));
    }

    TEST_CASE("SET_CONFIGURATION arbitrates, and only commit moves the shadow") {
        Ep0Arbiter a(manifest);
        auto d = a.decide(setup(0x00, kSetConfiguration, 1, 0, 0));
        CHECK_EQ(static_cast<int>(d.verb), static_cast<int>(Ep0Verb::SetConfiguration));
        CHECK_EQ(a.currentConfiguration(), 0u);       // not applied yet

        a.commitVerb(Ep0Verb::SetConfiguration, 1, 0);
        CHECK_EQ(a.currentConfiguration(), 1u);

        auto g = a.decide(setup(0x80, kGetConfiguration, 0, 0, 1));
        CHECK_EQ(static_cast<int>(g.disposition), static_cast<int>(Ep0Disposition::Local));
        CHECK_EQ(g.data.size(), std::size_t{1});
        CHECK_EQ(g.data[0], 1u);
    }

    TEST_CASE("a configuration change resets every alternate setting") {
        // USB 2.0 §9.4.7. Forgetting this leaves the arbiter claiming an alt
        // setting the device no longer has.
        Ep0Arbiter a(manifest);
        a.commitVerb(Ep0Verb::SetInterface, 0, 3);
        CHECK_EQ(a.alternateSetting(0), 3u);
        a.commitVerb(Ep0Verb::SetConfiguration, 1, 0);
        CHECK_EQ(a.alternateSetting(0), 0u);
    }

    TEST_CASE("generation advances on config and alt changes") {
        Ep0Arbiter a(manifest);
        const auto g0 = a.generation();
        a.commitVerb(Ep0Verb::SetConfiguration, 1, 0);
        CHECK(a.generation() > g0);
        const auto g1 = a.generation();
        a.commitVerb(Ep0Verb::SetInterface, 0, 1);
        CHECK(a.generation() > g1);
        // EP_CLEAR_HALT does not invalidate the pipe table.
        const auto g2 = a.generation();
        a.commitVerb(Ep0Verb::EpClearHalt, 0x81, 0);
        CHECK_EQ(a.generation(), g2);
    }

    TEST_CASE("a class-defined descriptor type is forwarded") {
        Ep0Arbiter a(manifest);
        auto d = a.decide(setup(0x81, kGetDescriptor, (0x22 << 8), 0, 64));  // HID Report
        CHECK_EQ(static_cast<int>(d.disposition), static_cast<int>(Ep0Disposition::Forward));
    }
}

void testRequestTable()
{
    TEST_CASE("R8: request ids must strictly increase per channel") {
        ManualClock c;
        RequestTable t(c);
        OutstandingRequest r; r.channel = 0x0181; r.requestId = 10;
        CHECK_EQ(static_cast<int>(t.add(r)), static_cast<int>(Status::Ok));

        r.requestId = 10;
        CHECK_EQ(static_cast<int>(t.add(r)), static_cast<int>(Status::AlreadyExists));
        r.requestId = 9;
        CHECK_EQ(static_cast<int>(t.add(r)), static_cast<int>(Status::BadArgument));
        r.requestId = 11;
        CHECK_EQ(static_cast<int>(t.add(r)), static_cast<int>(Status::Ok));
    }

    TEST_CASE("ids are scoped per channel, not global") {
        ManualClock c;
        RequestTable t(c);
        OutstandingRequest a; a.channel = 0x0181; a.requestId = 100;
        OutstandingRequest b; b.channel = 0x0102; b.requestId = 5;
        CHECK_EQ(static_cast<int>(t.add(a)), static_cast<int>(Status::Ok));
        CHECK_EQ(static_cast<int>(t.add(b)), static_cast<int>(Status::Ok));
        CHECK_EQ(t.size(), std::size_t{2});
    }

    TEST_CASE("take removes exactly once; a second take reports unknown") {
        ManualClock c;
        RequestTable t(c);
        OutstandingRequest r; r.channel = 1; r.requestId = 1; r.requestedLen = 512;
        t.add(r);
        OutstandingRequest got;
        CHECK(t.take(1, 1, &got));
        CHECK_EQ(got.requestedLen, 512u);
        CHECK(!t.take(1, 1, &got));      // a cancel racing a completion, not fatal
        CHECK(t.empty());
    }

    TEST_CASE("expired() returns only past-deadline requests") {
        ManualClock c;
        RequestTable t(c);
        OutstandingRequest a; a.channel=1; a.requestId=1;
        a.deadline = Deadline::afterMs(c, 1000);
        OutstandingRequest b; b.channel=1; b.requestId=2;
        b.deadline = Deadline::afterMs(c, 5000);
        OutstandingRequest n; n.channel=1; n.requestId=3;   // interrupt IN, no deadline
        t.add(a); t.add(b); t.add(n);

        c.advanceMs(1500);
        auto e = t.expired();
        CHECK_EQ(e.size(), std::size_t{1});
        CHECK_EQ(e[0].requestId, 1ull);
        CHECK_EQ(t.size(), std::size_t{2});

        c.advanceMs(1'000'000);
        auto e2 = t.expired();
        CHECK_EQ(e2.size(), std::size_t{1});      // only b; n never expires
        CHECK_EQ(t.size(), std::size_t{1});
    }

    TEST_CASE("takeAttach drains everything so I1 survives teardown") {
        ManualClock c;
        RequestTable t(c);
        for (std::uint64_t i = 1; i <= 5; ++i) {
            OutstandingRequest r; r.channel = 1; r.requestId = i; r.attachId = 7;
            t.add(r);
        }
        OutstandingRequest other; other.channel = 2; other.requestId = 1; other.attachId = 8;
        t.add(other);

        auto drained = t.takeAttach(7);
        CHECK_EQ(drained.size(), std::size_t{5});
        CHECK_EQ(t.size(), std::size_t{1});
    }

    TEST_CASE("takeStaleEpoch drops only the pre-reset generation") {
        ManualClock c;
        RequestTable t(c);
        OutstandingRequest a; a.channel=1; a.requestId=1; a.attachId=1; a.deviceEpoch=3;
        OutstandingRequest b; b.channel=1; b.requestId=2; b.attachId=1; b.deviceEpoch=4;
        t.add(a); t.add(b);
        auto stale = t.takeStaleEpoch(1, 4);
        CHECK_EQ(stale.size(), std::size_t{1});
        CHECK_EQ(stale[0].requestId, 1ull);
    }

    TEST_CASE("nextRequestId is monotonic per channel and never 0") {
        ManualClock c;
        RequestTable t(c);
        CHECK_EQ(t.nextRequestId(5), 1ull);       // 0 means "unsolicited" on the wire
        CHECK_EQ(t.nextRequestId(5), 2ull);
        CHECK_EQ(t.nextRequestId(6), 1ull);
    }
}

void testCredit()
{
    TEST_CASE("credit is two-dimensional: urbs and bytes") {
        CreditController c(CreditGrant{2, 1000});
        CHECK_EQ(static_cast<int>(c.acquire(100)), static_cast<int>(Status::Ok));
        CHECK_EQ(static_cast<int>(c.acquire(100)), static_cast<int>(Status::Ok));
        // urb limit reached even though plenty of bytes remain
        CHECK_EQ(static_cast<int>(c.acquire(1)), static_cast<int>(Status::NoResources));

        CreditController d(CreditGrant{100, 500});
        CHECK_EQ(static_cast<int>(d.acquire(400)), static_cast<int>(Status::Ok));
        // byte limit reached even though plenty of urbs remain
        CHECK_EQ(static_cast<int>(d.acquire(200)), static_cast<int>(Status::NoResources));
    }

    TEST_CASE("release restores exactly what was taken") {
        CreditController c(CreditGrant{4, 1000});
        c.acquire(250); c.acquire(250);
        CHECK_EQ(c.urbsInUse(), 2u);
        CHECK_EQ(c.bytesInUse(), 500u);
        CHECK(c.release(250));
        CHECK_EQ(c.urbsInUse(), 1u);
        CHECK_EQ(c.bytesInUse(), 250u);
    }

    TEST_CASE("release refuses to underflow rather than wrapping (D-30)") {
        // An unsigned wrap would make bytesInUse enormous and close the window
        // permanently — a one-off accounting slip becoming a dead endpoint.
        CreditController c(CreditGrant{4, 1000});
        c.acquire(100);
        CHECK(!c.release(200));            // more than is in use: refused
        CHECK_EQ(c.bytesInUse(), 100u);    // and nothing changed
        CHECK(c.release(100));             // the matching release succeeds
        CHECK_EQ(c.urbsInUse(), 0u);
        CHECK(!c.release(1));              // nothing left to release
    }

    TEST_CASE("R11: first overrun is answered, repeated overrun is fatal") {
        CreditController c(CreditGrant{4, 1000});
        c.recordOverrun(1100);
        CHECK(!c.overrunIsFatal());
        c.recordOverrun(1100);
        CHECK(!c.overrunIsFatal());
        c.recordOverrun(1100);
        CHECK(c.overrunIsFatal());
    }

    TEST_CASE("a gross overrun is fatal immediately") {
        CreditController c(CreditGrant{4, 1000});
        c.recordOverrun(3000);           // > 2x the grant
        CHECK(c.overrunIsFatal());
    }

    TEST_CASE("credit views can be cross-checked between peers") {
        CreditController c(CreditGrant{8, 4096});
        c.acquire(512);
        CHECK(c.matches(1, 512));
        CHECK(!c.matches(1, 513));
    }
}

} // namespace

int main()
{
    std::printf("test_core\n");
    testWatchdog();
    testClock();
    testManifest();
    testEp0Arbiter();
    testRequestTable();
    testCredit();
    TEST_MAIN_END();
}
