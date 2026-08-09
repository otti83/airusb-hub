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

Status SimulatedDeviceSource::claim(const DeviceUid& u, IUsbDevicePort** portOut,
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
    _claimed    = true;
    *portOut    = &_device;
    manifestOut = _device.manifest();
    *configOut  = 1;
    return Status::Ok;
}

void SimulatedDeviceSource::release(const DeviceUid& u)
{
    if (u == uid()) _claimed = false;
}

} // namespace airusb::control
