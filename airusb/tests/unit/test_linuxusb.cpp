// The speed table, and why a cast would have shipped.
//
// airusb::Speed and Linux's usb_device_speed agree on exactly one value. That
// value is High, which is what anyone reaches for first when testing, so a naive
// cast passes the test you would write and then attaches a SuperSpeed device to
// the high-speed half of vhci's port range in production.
//
// These cases assert the disagreement explicitly, so that if either enum is ever
// reordered the test fails rather than the device.

#include "../TestHarness.h"
#include "../../platform/linux/LinuxUsb.h"

using namespace airusb;
using namespace airusb::linuxvhci;

namespace {

void testSpeeds()
{
    std::printf("speeds\n");

    TEST_CASE("every speed maps to the kernel's number, not to its own") {
        CHECK(toKernelSpeed(Speed::Low)       == KernelSpeed::Low);
        CHECK(toKernelSpeed(Speed::Full)      == KernelSpeed::Full);
        CHECK(toKernelSpeed(Speed::High)      == KernelSpeed::High);
        CHECK(toKernelSpeed(Speed::Super)     == KernelSpeed::Super);
        CHECK(toKernelSpeed(Speed::SuperPlus) == KernelSpeed::SuperPlus);
    }

    TEST_CASE("a cast would have been wrong for all but one of them") {
        // This is the case that documents the hazard. If someone later "simplifies"
        // toKernelSpeed into a static_cast, these are the four that break.
        struct { Speed ours; int castWouldGive; int correct; } cases[] = {
            { Speed::Full,      1, 2 },   // cast -> LOW,      correct FULL
            { Speed::Low,       2, 1 },   // cast -> FULL,     correct LOW
            { Speed::Super,     4, 5 },   // cast -> WIRELESS, correct SUPER
            { Speed::SuperPlus, 5, 6 },   // cast -> SUPER,    correct SUPER_PLUS
        };
        for (const auto& c : cases) {
            const int got = static_cast<int>(toKernelSpeed(c.ours));
            CHECK_EQ(got, c.correct);
            CHECK(got != c.castWouldGive);
        }
    }

    TEST_CASE("High is the one that coincides, which is why it hides the bug") {
        CHECK_EQ(static_cast<int>(Speed::High), 3);
        CHECK_EQ(static_cast<int>(toKernelSpeed(Speed::High)), 3);
    }

    TEST_CASE("speeds Linux cannot express are refused, not approximated") {
        // Attaching at a speed the link is not running at produces a device whose
        // wMaxPacketSize the host controller then disbelieves.
        CHECK(toKernelSpeed(Speed::None)         == KernelSpeed::Unknown);
        CHECK(toKernelSpeed(Speed::Other)        == KernelSpeed::Unknown);
        CHECK(toKernelSpeed(Speed::SuperPlusBy2) == KernelSpeed::Unknown);
    }

    TEST_CASE("only SuperSpeed and above belong on the USB3 port half") {
        // vhci-hcd splits its ports by speed. Putting a SuperSpeed device on a
        // low port is accepted and then the kernel disagrees with itself.
        CHECK(isSuperSpeedHalf(KernelSpeed::Super));
        CHECK(isSuperSpeedHalf(KernelSpeed::SuperPlus));
        CHECK(!isSuperSpeedHalf(KernelSpeed::High));
        CHECK(!isSuperSpeedHalf(KernelSpeed::Full));
        CHECK(!isSuperSpeedHalf(KernelSpeed::Low));
        CHECK(!isSuperSpeedHalf(KernelSpeed::Wireless));   // never ours to send
        CHECK(!isSuperSpeedHalf(KernelSpeed::Unknown));
    }
}

void testStatuses()
{
    std::printf("statuses\n");

    TEST_CASE("a short transfer is success, with the length carrying the fact") {
        // Reporting an error here breaks every protocol that ends a transfer by
        // sending less than was asked for, which is most of them.
        CHECK_EQ(toLinuxErrno(Status::XferShort), 0);
    }

    TEST_CASE("a short transfer IS an error when the host said SHORT_NOT_OK") {
        CHECK_EQ(toLinuxErrno(Status::XferShort, /*shortIsError*/ true), -kERemoteIo);
    }

    TEST_CASE("a stall is EPIPE, which is what makes a driver clear the halt") {
        CHECK_EQ(toLinuxErrno(Status::XferStall), -32);
        CHECK_EQ(toLinuxErrno(Status::XferEpStopped), -32);
    }

    TEST_CASE("the values are Linux's, not this host's") {
        // macOS ETIMEDOUT is 60 and Linux's is 110; macOS has no EREMOTEIO at
        // all. Compiling against <errno.h> would have produced a table that is
        // correct on the machine that cannot run it.
        CHECK_EQ(toLinuxErrno(Status::XferTimeout), -110);
        CHECK_EQ(toLinuxErrno(Status::XferNakTimeout), -110);
        CHECK_EQ(toLinuxErrno(Status::XferUnderrun), -121);
        CHECK_EQ(toLinuxErrno(Status::XferCancelled), -104);
        CHECK_EQ(toLinuxErrno(Status::XferOverrun), -75);
    }

    TEST_CASE("a line error is EILSEQ and a framing error is EPROTO") {
        CHECK_EQ(toLinuxErrno(Status::XferCrc), -84);
        CHECK_EQ(toLinuxErrno(Status::XferBitstuff), -84);
        CHECK_EQ(toLinuxErrno(Status::XferBadToggle), -84);
        CHECK_EQ(toLinuxErrno(Status::XferProtocol), -71);
        CHECK_EQ(toLinuxErrno(Status::XferStreamError), -71);
    }

    TEST_CASE("a departed device is ENODEV, so drivers give up instead of retrying") {
        CHECK_EQ(toLinuxErrno(Status::XferDeviceOffline), -19);
        CHECK_EQ(toLinuxErrno(Status::DeviceGone), -19);
        CHECK_EQ(toLinuxErrno(Status::Detaching), -19);
    }

    TEST_CASE("everything maps to something, and nothing maps to success by accident") {
        // Ok and a short transfer are the ONLY inputs that may produce 0. A new
        // Status added later must not silently become "the transfer worked".
        for (int v = 0; v <= 0x50; ++v) {
            const Status s = static_cast<Status>(v);
            const std::int32_t e = toLinuxErrno(s);
            if (s == Status::Ok || s == Status::XferShort) CHECK_EQ(e, 0);
            else                                           CHECK(e < 0);
        }
    }

    TEST_CASE("errno names are real or admitted, never invented") {
        CHECK(std::string(linuxErrnoName(0)) == "0");
        CHECK(std::string(linuxErrnoName(-32)) == "EPIPE");
        CHECK(std::string(linuxErrnoName(32)) == "EPIPE");     // sign-agnostic
        CHECK(std::string(linuxErrnoName(-110)) == "ETIMEDOUT");
        CHECK(std::string(linuxErrnoName(-4242)) == "?");
    }
}

} // namespace

int main()
{
    std::printf("test_linuxusb\n");
    testSpeeds();
    testStatuses();
    TEST_MAIN_END();
}
