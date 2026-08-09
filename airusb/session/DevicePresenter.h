// AirUSB Hub — "present this remote device to THIS computer", as a seam.
//
// THE TWO MEANINGS OF "ATTACH", WHICH IS THE BUG THIS FILE CLOSES
//
// In the window, Attach built a `RemoteDevicePort` and ran a read-only
// Bulk-Only Transport probe against it. In the product, attach makes an
// operating system enumerate a device and load its own drivers. Both were
// spelled "attach", both reported success, and only one of them was the thing
// this project exists to do. A person who clicked the button and saw PASS had
// no way to learn that no device had appeared on their computer.
//
// So the verb is now split by TYPE rather than by documentation. A presenter
// says what it is, says whether it can present at all, and — when it cannot —
// says why in a sentence the person can act on. The window renders that string
// verbatim and never infers capability, because inferring it is how the two
// meanings merged in the first place.
//
// THE FOUR IMPLEMENTATIONS, AND WHAT EACH IS HONEST ABOUT
//
//   linux-vhci        real. Makes the Linux kernel enumerate the device.
//   windows-udecx     real, once airusb.sys is loaded. Absent until then.
//   diagnostic-probe  NOT real, and says so: canPresent() is false. It opens
//                     the device for a read-only probe so that a machine with
//                     no driver can still answer "does the network work?".
//   unavailable       not real and cannot become real in this build — macOS
//                     without the Apple entitlement is the case that matters.
//
// NEVER BLOCKS
//
// `present()` returns as soon as the operating system has been told, not when
// the device has finished enumerating, and `pump()` is one non-blocking step.
// The reason is the same one that shapes `VhciNetBridge` and `UdecxBridge`: the
// caller is a single-threaded loop that also has to keep answering a window and
// a network peer, and a presenter that waits inside a call takes both down.

#ifndef AIRUSB_SESSION_DEVICEPRESENTER_H
#define AIRUSB_SESSION_DEVICEPRESENTER_H

#include "../core/Status.h"
#include "ImporterClient.h"

#include <memory>
#include <string>

namespace airusb::session {

class IDevicePresenter {
public:
    virtual ~IDevicePresenter() = default;

    /// A short, stable, machine-readable name. Shown in the window and logged,
    /// so that "which half of this product am I running" is answerable from a
    /// screenshot.
    virtual const char* name() const noexcept = 0;

    /// True only if this really makes the local operating system enumerate the
    /// device. A read-only probe is not presenting and must not claim to be.
    virtual bool canPresent() const noexcept = 0;

    /// Why not, in words a person can act on. Empty when `canPresent()`.
    virtual std::string whyNot() const = 0;

    /// Takes over an attached device. Returns as soon as the local OS has been
    /// told; enumeration continues in `pump()`. NEVER blocks.
    virtual Status present(ImporterClient& client,
                           ImporterClient::BridgeAttach& attached,
                           std::string* why) = 0;

    /// One non-blocking step. Returns TransportLost once the device is gone.
    virtual Status pump() = 0;

    /// Stops presenting. Safe to call when not presenting.
    virtual void withdraw() = 0;

    virtual bool presenting() const noexcept = 0;

    /// One line for the window, e.g. "presented to this computer as a USB
    /// device" or "opened for diagnostics only — no device was added to this
    /// computer". The second sentence is the one that used to be missing.
    virtual std::string statusText() const = 0;
};

/// A build that cannot present, and knows exactly why.
///
/// macOS is the case this exists for: the importer is blocked on Apple granting
/// `com.apple.developer.usb.host-controller-interface` (FB24214361), and until
/// then no amount of code makes a Mac enumerate a remote device. Saying that in
/// the window is better than a button that silently does something else.
class UnavailablePresenter final : public IDevicePresenter {
public:
    UnavailablePresenter(std::string named, std::string reason)
        : _name(std::move(named)), _why(std::move(reason)) {}

    const char* name() const noexcept override { return _name.c_str(); }
    bool canPresent() const noexcept override { return false; }
    std::string whyNot() const override { return _why; }

    Status present(ImporterClient&, ImporterClient::BridgeAttach&,
                   std::string* why) override
    {
        if (why) *why = _why;
        return Status::UnsupportedMessage;
    }

    Status pump() override { return Status::Ok; }
    void withdraw() override {}
    bool presenting() const noexcept override { return false; }
    std::string statusText() const override { return _why; }

private:
    std::string _name;
    std::string _why;
};

/// The old behaviour, kept — and renamed so it can never again be mistaken for
/// the product.
///
/// It attaches a `RemoteDevicePort`, which is the synchronous instrument
/// `diag/BotProbe` is written against, and nothing else. No operating system is
/// involved and no device appears anywhere. That is genuinely useful — it is
/// how a machine with no driver answers "is the network and the exporter
/// working?" — and it is not presenting, so `canPresent()` is false.
class ProbePresenter final : public IDevicePresenter {
public:
    const char* name() const noexcept override { return "diagnostic-probe"; }
    bool canPresent() const noexcept override { return false; }

    std::string whyNot() const override
    {
        return "This build can talk to the other machine and read the device, but "
               "it cannot add it to this computer as a real USB device. That needs "
               "the importer for this operating system.";
    }

    Status present(ImporterClient& client,
                   ImporterClient::BridgeAttach& attached,
                   std::string* why) override;

    Status pump() override { return Status::Ok; }
    void withdraw() override { _port.reset(); }
    bool presenting() const noexcept override { return false; }

    std::string statusText() const override
    {
        return _port ? "Opened for diagnostics only — no device was added to this computer."
                     : "Nothing is open.";
    }

    /// The instrument, for the "check it really works" button. Null unless a
    /// device is open.
    RemoteDevicePort* port() noexcept { return _port.get(); }
    const RemoteDevicePort* port() const noexcept { return _port.get(); }

private:
    std::unique_ptr<RemoteDevicePort> _port;
};

} // namespace airusb::session

#endif // AIRUSB_SESSION_DEVICEPRESENTER_H
