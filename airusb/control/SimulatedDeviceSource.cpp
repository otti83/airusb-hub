#include "SimulatedDeviceSource.h"

namespace airusb::control {

using namespace airusb::protocol;

DeviceUid SimulatedDeviceSource::uid() noexcept
{
    DeviceUid u{};
    for (std::size_t i = 0; i < u.size(); ++i)
        u[i] = static_cast<std::uint8_t>(0xA0 + i);
    return u;
}

std::vector<DeviceRecord> SimulatedDeviceSource::list()
{
    DeviceRecord r;
    r.uid       = uid();
    r.vendorId  = 0x058f;
    r.productId = 0x6387;
    r.speed     = static_cast<std::uint8_t>(Speed::Super);
    r.flags     = kDevHasStorage | kDevShareable;
    if (_claimed) r.flags |= kDevAttached;
    // Named so nobody reads it as hardware. The window shows this string
    // verbatim, and a person deciding whether it is safe to let a stranger
    // write to a drive should not have to work out which one this is.
    r.name      = "Simulated Flash Disk (no real hardware)";
    return { r };
}

Status SimulatedDeviceSource::claim(const DeviceUid& u, IAsyncUsbDevicePort** portOut,
                                    DeviceManifest& manifestOut, std::uint8_t* configOut,
                                    std::string* whyNot)
{
    if (!(u == uid())) {
        if (whyNot) *whyNot = "There is no such device on this machine.";
        return Status::NotFound;
    }
    if (_claimed) {
        if (whyNot) *whyNot = "That device is already in use by another machine.";
        return Status::Busy;
    }
    // A Bulk-Only Mass Storage Reset, on every claim.
    //
    // This device outlives the sessions that use it, unlike a real one: a real
    // capture re-opens the hardware and the hardware resets itself. Here the
    // same RAM disk is handed to whoever attaches next, with whatever phase the
    // last peer left it in — and a peer that disconnected mid-command leaves it
    // expecting a data phase. The next peer's very first CBW is then answered
    // with a stall, on a device that is in fact perfectly healthy.
    //
    // Observed between two machines: a write probe failed halfway, and the next
    // attach could not get past TEST_UNIT_READY. Resetting on CLAIM rather than
    // on release is deliberate — release does not run if the process is killed,
    // and the invariant worth having is "an attach starts from a known phase".
    _device.reset();

    _claimed    = true;
    *portOut    = &_async;
    manifestOut = _device.manifest();
    *configOut  = 1;
    return Status::Ok;
}

void SimulatedDeviceSource::release(const DeviceUid& u)
{
    if (u == uid()) _claimed = false;
}

} // namespace airusb::control
