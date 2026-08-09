// The Windows speed and status tables, asserted where they DISAGREE.
//
// A test that checks High maps to High tells you nothing — that is the arm a
// cast would also have got right. The arms worth pinning are the ones where the
// two enumerations happen to line up wrongly, because those are the ones that
// produce a plausible, working-looking, incorrect result.
//
// The Linux port shipped this same file and it caught a real bug: `Super` would
// have gone out as `WIRELESS`, which the kernel accepts. Windows has the same
// hazard rotated by one, so this file is written before the driver exists rather
// than after it misbehaves.

#include "../TestHarness.h"
#include "../../platform/windows/WindowsUsb.h"

using namespace airusb;
using namespace airusb::windows;

namespace {

void testSpeeds()
{
    std::printf("speeds, and what a cast would have done instead\n");

    TEST_CASE("every speed UdeCx can express is translated, not cast") {
        CHECK(toUdecxSpeed(Speed::Low)   == UdecxSpeed::Low);
        CHECK(toUdecxSpeed(Speed::Full)  == UdecxSpeed::Full);
        CHECK(toUdecxSpeed(Speed::High)  == UdecxSpeed::High);
        CHECK(toUdecxSpeed(Speed::Super) == UdecxSpeed::Super);
    }

    TEST_CASE("the numbers really do disagree — this is the whole point") {
        // If this ever passes trivially it means someone renumbered one of the
        // enums and the table became a no-op, at which point deleting it would
        // look safe. Assert the mismatch so that cannot happen quietly.
        auto raw = [](Speed s) { return static_cast<std::int32_t>(s); };
        auto out = [](UdecxSpeed s) { return static_cast<std::int32_t>(s); };

        // High is the dangerous one: a cast makes a High-speed device claim to
        // be SuperSpeed, and every descriptor the guest then reads contradicts
        // the port it is on.
        CHECK(raw(Speed::High) == out(UdecxSpeed::Super));
        CHECK(out(toUdecxSpeed(Speed::High)) != raw(Speed::High));

        // Low would arrive as High.
        CHECK(raw(Speed::Low) == out(UdecxSpeed::High));
        CHECK(out(toUdecxSpeed(Speed::Low)) != raw(Speed::Low));

        // Super would be out of range entirely.
        CHECK(raw(Speed::Super) > out(UdecxSpeed::Super));

        // Full is the single coincidence — and on Linux the coincidence was
        // High instead, so neither port's testing would have caught the other's.
        CHECK(raw(Speed::Full) == out(UdecxSpeed::Full));
    }

    TEST_CASE("SuperSpeedPlus is refused rather than understated") {
        CHECK(toUdecxSpeed(Speed::SuperPlus)    == UdecxSpeed::Unsupported);
        CHECK(toUdecxSpeed(Speed::SuperPlusBy2) == UdecxSpeed::Unsupported);
        CHECK(toUdecxSpeed(Speed::None)         == UdecxSpeed::Unsupported);
        CHECK(toUdecxSpeed(Speed::Other)        == UdecxSpeed::Unsupported);
    }

    TEST_CASE("the round trip is exact for everything UdeCx can hold") {
        for (Speed s : { Speed::Low, Speed::Full, Speed::High, Speed::Super })
            CHECK(fromUdecxSpeed(toUdecxSpeed(s)) == s);
        CHECK(fromUdecxSpeed(UdecxSpeed::Unsupported) == Speed::None);
    }
}

void testShortTransfer()
{
    std::printf("the short-transfer decision, which Linux answers differently\n");

    TEST_CASE("short IS success when the caller said it would accept it") {
        // 512 bytes answering a 1024-byte request. This is the case the whole
        // project's SHORT_READ_FIDELITY check exists to protect, and rounding it
        // up to an error would break every protocol that ends a transfer by
        // sending less than was asked for.
        CHECK(toUsbdStatus(Status::Ok, 1024, 512, kUsbdShortTransferOk) ==
              UsbdStatus::Success);
        CHECK(toUsbdStatus(Status::XferShort, 1024, 512, kUsbdShortTransferOk) ==
              UsbdStatus::Success);
    }

    TEST_CASE("short is an ERROR when the caller did not") {
        // And this is why the Linux rule cannot simply be copied: there, short
        // is unconditionally success. Here the caller gets to ask to be told,
        // and silently succeeding would hide a truncation it asked about.
        CHECK(toUsbdStatus(Status::Ok, 1024, 512, 0) == UsbdStatus::ErrorShortTransfer);
        CHECK(toUsbdStatus(Status::XferShort, 1024, 512, 0) ==
              UsbdStatus::ErrorShortTransfer);
    }

    TEST_CASE("a full-length transfer is success either way") {
        CHECK(toUsbdStatus(Status::Ok, 1024, 1024, 0) == UsbdStatus::Success);
        CHECK(toUsbdStatus(Status::Ok, 1024, 1024, kUsbdShortTransferOk) ==
              UsbdStatus::Success);
        CHECK(toUsbdStatus(Status::Ok, 0, 0, 0) == UsbdStatus::Success);
    }

    TEST_CASE("a short transfer fails WITHOUT halting the endpoint") {
        // The distinction the top two bits actually encode, and the one a
        // "severity" reading gets backwards. USBD_ERROR() is just "negative",
        // so 0x8… and 0xC… are both failures; only 0xC… means the endpoint's
        // state machine stopped.
        //
        // Getting this wrong in the halting direction turns every protocol that
        // ends a transfer early into a reset storm.
        CHECK(isError(UsbdStatus::ErrorShortTransfer));
        CHECK(!haltsEndpoint(UsbdStatus::ErrorShortTransfer));

        CHECK(!isError(UsbdStatus::Success));
        CHECK(!haltsEndpoint(UsbdStatus::Success));

        CHECK(isError(UsbdStatus::StallPid));
        CHECK(haltsEndpoint(UsbdStatus::StallPid));
        CHECK(haltsEndpoint(UsbdStatus::EndpointHalted));
        CHECK(haltsEndpoint(UsbdStatus::DeviceGone));
        CHECK(haltsEndpoint(UsbdStatus::Canceled));
        CHECK(haltsEndpoint(UsbdStatus::Timeout));

        // The 0x8 class: real failures that leave the pipe alone.
        CHECK(isError(UsbdStatus::NoMemory)      && !haltsEndpoint(UsbdStatus::NoMemory));
        CHECK(isError(UsbdStatus::RequestFailed) && !haltsEndpoint(UsbdStatus::RequestFailed));
    }
}

void testStatuses()
{
    std::printf("transfer statuses\n");

    TEST_CASE("the ones a guest acts on differently") {
        CHECK(toUsbdStatus(Status::XferStall, 8, 0, 0)     == UsbdStatus::StallPid);
        CHECK(toUsbdStatus(Status::XferTimeout, 8, 0, 0)   == UsbdStatus::Timeout);
        CHECK(toUsbdStatus(Status::XferCancelled, 8, 0, 0) == UsbdStatus::Canceled);
        CHECK(toUsbdStatus(Status::XferOverrun, 8, 0, 0)   == UsbdStatus::BufferOverrun);
    }

    TEST_CASE("TransportLost becomes DEVICE_GONE, because USB cannot say 'unknown'") {
        // TransportLost means "we do not know whether this transfer happened".
        // There is no USB status for that, so the honest translation is the one
        // the guest can act on: the device left.
        CHECK(toUsbdStatus(Status::TransportLost, 8, 0, 0) == UsbdStatus::DeviceGone);
        CHECK(toUsbdStatus(Status::DeviceGone, 8, 0, 0)    == UsbdStatus::DeviceGone);
    }

    TEST_CASE("an unmapped status fails rather than succeeding") {
        // The direction of the default matters: a status this table has not
        // heard of must not become Success.
        CHECK(toUsbdStatus(Status::Internal, 8, 0, 0)       == UsbdStatus::RequestFailed);
        CHECK(toUsbdStatus(Status::MalformedFrame, 8, 0, 0) == UsbdStatus::RequestFailed);
        CHECK(toUsbdStatus(Status::NotPaired, 8, 0, 0)      == UsbdStatus::RequestFailed);
        CHECK(isError(toUsbdStatus(Status::Internal, 8, 0, 0)));
    }

    TEST_CASE("statuses coming back from the kernel are understood") {
        CHECK(fromUsbdStatus(UsbdStatus::Success)            == Status::Ok);
        CHECK(fromUsbdStatus(UsbdStatus::StallPid)           == Status::XferStall);
        CHECK(fromUsbdStatus(UsbdStatus::EndpointHalted)     == Status::XferStall);
        CHECK(fromUsbdStatus(UsbdStatus::Canceled)           == Status::XferCancelled);
        CHECK(fromUsbdStatus(UsbdStatus::ErrorShortTransfer) == Status::XferShort);
        CHECK(fromUsbdStatus(UsbdStatus::DeviceGone)         == Status::XferDeviceOffline);
        CHECK(fromUsbdStatus(static_cast<UsbdStatus>(0xC0009999u)) == Status::XferUnknown);
    }

    TEST_CASE("every name is spelled, so a log never shows a bare number") {
        const UsbdStatus all[] = {
            UsbdStatus::Success, UsbdStatus::Pending, UsbdStatus::Crc, UsbdStatus::BtStuff,
            UsbdStatus::DataToggleMismatch, UsbdStatus::StallPid, UsbdStatus::DevNotResponding,
            UsbdStatus::PidCheckFailure, UsbdStatus::UnexpectedPid, UsbdStatus::DataOverrun,
            UsbdStatus::DataUnderrun, UsbdStatus::BufferOverrun, UsbdStatus::BufferUnderrun,
            UsbdStatus::NotAccessed, UsbdStatus::Fifo, UsbdStatus::EndpointHalted,
            UsbdStatus::NoMemory, UsbdStatus::InvalidUrbFunction, UsbdStatus::InvalidParameter,
            UsbdStatus::ErrorBusy, UsbdStatus::RequestFailed, UsbdStatus::InvalidPipeHandle,
            UsbdStatus::NoBandwidth, UsbdStatus::InternalHcError, UsbdStatus::ErrorShortTransfer,
            UsbdStatus::Canceled, UsbdStatus::Timeout, UsbdStatus::DeviceGone,
        };
        for (UsbdStatus s : all) {
            const char* n = usbdStatusName(s);
            CHECK(n[0] == 'U');
            CHECK(std::strcmp(n, "USBD_STATUS_?") != 0);
        }
        CHECK(std::strcmp(usbdStatusName(static_cast<UsbdStatus>(0xDEADBEEFu)),
                          "USBD_STATUS_?") == 0);
    }
}

} // namespace

int main()
{
    std::printf("test_windowsusb\n");
    testSpeeds();
    testShortTransfer();
    testStatuses();
    TEST_MAIN_END();
}
