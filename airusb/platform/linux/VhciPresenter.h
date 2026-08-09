// AirUSB Hub — the Linux presenter: the window's Attach, made real.
//
// Everything below this file already existed and was proven on a real kernel:
// `ImporterDataPlane` (non-blocking, deadline-swept), `VhciNetBridge`
// (event-driven, never waits on the network to answer the kernel), the
// socketpair vhci-hcd accepts, and the sysfs `attach` line. What did not exist
// was a way for the PRODUCT'S WINDOW to drive them. `airusb-vhci --host` is a
// command-line program with its own identity, its own pin store and its own
// idea of who to trust, so the six-digit ceremony the window performs protected
// a different session from the one that enumerated a device.
//
// This is that stack behind `IDevicePresenter`, so the privileged broker — the
// one process that owns the machine's identity, its pins and its leases — is
// also the one that hands the device to the kernel. One identity, one
// ceremony, one meaning of "attach".
//
// WHY IT MUST LIVE IN THE PRIVILEGED PROCESS, AND CANNOT BE DELEGATED
//
// vhci-hcd is told about the socket by writing a FILE DESCRIPTOR NUMBER into
// sysfs. The number is only meaningful in the process that writes it, so the
// process holding the socket is necessarily the process writing sysfs — and
// writing there needs root. The network session is on the other end of that
// same socket, so the network session is in the root process too, and therefore
// so is the identity that authenticates it. That chain is why the broker is
// root rather than a matter of taste.

#ifndef AIRUSB_PLATFORM_LINUX_VHCIPRESENTER_H
#define AIRUSB_PLATFORM_LINUX_VHCIPRESENTER_H

#include "FdStream.h"
#include "VhciNetBridge.h"

#include "../../session/DevicePresenter.h"
#include "../../core/Clock.h"
#include "../../session/ImporterDataPlane.h"

#include <memory>
#include <string>

namespace airusb::linuxvhci {

class VhciPresenter final : public session::IDevicePresenter {
public:
    explicit VhciPresenter(const Clock& clock) noexcept : _clock(clock) {}
    ~VhciPresenter() override;

    const char* name() const noexcept override { return "linux-vhci"; }

    /// True only when vhci-hcd is actually loaded AND this process can write
    /// its sysfs. Both are checked by looking, not by assuming: a hub running
    /// unprivileged, or on a kernel built without `CONFIG_USB_SUPPORT`, has to
    /// say so before somebody clicks Attach rather than after.
    bool canPresent() const noexcept override;
    std::string whyNot() const override;

    Status present(session::ImporterClient& client,
                   session::ImporterClient::BridgeAttach& attached,
                   std::string* why) override;

    Status pump() override;
    void   withdraw() override;
    bool   presenting() const noexcept override { return _bridge != nullptr; }
    std::string statusText() const override;

    /// Which vhci port the device took, for the log and the window. -1 when not
    /// presenting.
    int port() const noexcept { return _port; }

    const VhciBridgeStats* stats() const noexcept
    {
        return _bridge ? &_bridge->stats() : nullptr;
    }

private:
    const Clock& _clock;

    int _sock = -1;      ///< our end of the socketpair; the kernel holds the other
    int _port = -1;

    std::unique_ptr<FdStream>                   _stream;
    std::unique_ptr<session::ImporterDataPlane> _plane;
    std::unique_ptr<VhciNetBridge>              _bridge;
    std::string                                 _last;
};

} // namespace airusb::linuxvhci

#endif // AIRUSB_PLATFORM_LINUX_VHCIPRESENTER_H
