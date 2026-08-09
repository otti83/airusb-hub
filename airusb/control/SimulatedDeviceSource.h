// AirUSB Hub — a device that is not there.
//
// A RAM-backed Bulk-Only Transport drive, offered through the same IDeviceSource
// the real capture backends implement. It exists so the whole product — window,
// pairing, session, transfers, verification — can be exercised on a machine with
// no hardware, no root and nothing to lose.
//
// It is not a mock in the testing sense. The bytes really cross the network,
// really go through the cipher, and are really segmented and reassembled; the
// only fiction is where the medium lives. That is the same fiction the CI gates
// have run on since the beginning, which is why a failure here is a failure of
// the stack rather than of the stand-in.
//
// WHY IT IS NOT COMPILED OUT OF RELEASE BUILDS
//
// Because "does the network work" is a question people ask about installed
// software on machines that have no spare USB stick, and answering it should
// not require a special build. The device announces itself as simulated in its
// name, so nothing in the window can be mistaken for real hardware.

#ifndef AIRUSB_CONTROL_SIMULATEDDEVICESOURCE_H
#define AIRUSB_CONTROL_SIMULATEDDEVICESOURCE_H

#include "../session/ExporterSession.h"
#include "../tests/fakes/ScriptedDevice.h"

namespace airusb::control {

class SimulatedDeviceSource final : public session::IDeviceSource {
public:
    explicit SimulatedDeviceSource(std::uint32_t blockCount = 61440,
                                   std::uint32_t blockSize  = 512)
        : _device(blockCount, blockSize) {}

    std::vector<protocol::DeviceRecord> list() override;

    Status claim(const protocol::DeviceUid& uid, IUsbDevicePort** portOut,
                 DeviceManifest& manifestOut, std::uint8_t* configOut,
                 std::string* whyNot) override;

    void release(const protocol::DeviceUid& uid) override;

    bool claimed() const noexcept { return _claimed; }

    /// The one uid this source ever answers to.
    static protocol::DeviceUid uid() noexcept;

private:
    fakes::ScriptedDevice _device;
    bool _claimed = false;
};

} // namespace airusb::control

#endif // AIRUSB_CONTROL_SIMULATEDDEVICESOURCE_H
