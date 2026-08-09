// AirUSB Hub — W5: the Windows presenter, and the last piece of the importer.
//
// This is what `airusb-vhci` is on Linux, wearing the broker's `IDevicePresenter`
// so that the window's Attach means the same thing on both operating systems.
// It is deliberately NOT a fourth program with a fourth identity: the review
// that produced A1 was explicit that W5 should be the Windows broker service,
// not a service beside it, and a separate host would recreate exactly the split
// A1 exists to remove.
//
// Everything under it is already built and already tested:
//
//   UdecxDriverChannel  the IOCTL transport                      (this session)
//   UdecxBridge         URBs <-> transfers, 77 hosted checks     (W3)
//   ImporterDataPlane   non-blocking, deadline-swept, I1         (L6)
//   ImporterClient      handshake, attach, manifest              (P2)
//
// So this file is wiring, and short on purpose. What it adds is the honesty:
// `canPresent()` is false until the driver is actually installed AND openable,
// and it says which of those failed, because "Windows cannot do this yet" and
// "this process may not" are different sentences for the person reading them.
//
// THE FIRST LOAD HAS NOT HAPPENED
//
// `airusb.sys` compiles, passes Code Analysis with zero findings, and has never
// been loaded on any machine. Until it is, `open()` returns NotFound on every
// Windows box in existence and the broker reports that verbatim. Nothing here
// is evidence about a kernel.

#ifndef AIRUSB_PLATFORM_WINDOWS_UDECXPRESENTER_H
#define AIRUSB_PLATFORM_WINDOWS_UDECXPRESENTER_H

#include "UdecxBridge.h"
#include "UdecxDriverChannel.h"

#include "../../core/Clock.h"
#include "../../session/DevicePresenter.h"
#include "../../session/ImporterDataPlane.h"

#include <memory>
#include <string>

namespace airusb::windows {

class UdecxPresenter final : public session::IDevicePresenter {
public:
    explicit UdecxPresenter(const Clock& clock) noexcept : _clock(clock) {}
    ~UdecxPresenter() override;

    const char* name() const noexcept override { return "windows-udecx"; }

    /// Looked at, not assumed: the driver is opened and closed once to find
    /// out. A GUID that resolves to nothing means the driver is not installed;
    /// access denied means it is, and this process is not allowed to drive it.
    bool canPresent() const noexcept override;
    std::string whyNot() const override;

    Status present(session::ImporterClient& client,
                   session::ImporterClient::BridgeAttach& attached,
                   std::string* why) override;

    Status pump() override;
    void   withdraw() override;
    bool   presenting() const noexcept override { return _bridge != nullptr; }
    std::string statusText() const override;

    const UdecxBridgeStats* stats() const noexcept
    {
        return _bridge ? &_bridge->stats() : nullptr;
    }

private:
    const Clock& _clock;

    std::unique_ptr<UdecxDriverChannel>         _channel;
    std::unique_ptr<session::ImporterDataPlane> _plane;
    std::unique_ptr<UdecxBridge>                _bridge;
    mutable std::string                         _last;
};

} // namespace airusb::windows

#endif // AIRUSB_PLATFORM_WINDOWS_UDECXPRESENTER_H
