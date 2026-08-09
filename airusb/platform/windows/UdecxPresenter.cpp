#include "UdecxPresenter.h"

#include "../../crypto/Primitives.h"

namespace airusb::windows {

UdecxPresenter::~UdecxPresenter() { withdraw(); }

bool UdecxPresenter::canPresent() const noexcept
{
    // Opened and closed to find out, rather than inferred from the platform.
    // "This is Windows, so it can present" is exactly the assumption that made
    // the window's Attach and the product's Attach look the same.
    UdecxDriverChannel probe;
    std::string why;
    const Status s = probe.open(&why);
    _last = why;
    if (s == Status::Ok) { probe.close(); return true; }
    return false;
}

std::string UdecxPresenter::whyNot() const
{
    UdecxDriverChannel probe;
    std::string why;
    if (probe.open(&why) == Status::Ok) { probe.close(); return {}; }
    return why.empty()
        ? std::string("The AirUSB virtual host controller is not available on this "
                      "machine.")
        : why;
}

Status UdecxPresenter::present(session::ImporterClient& client,
                               session::ImporterClient::BridgeAttach& attached,
                               std::string* why)
{
    auto fail = [&](Status s, std::string m) {
        _last = std::move(m);
        if (why) *why = _last;
        withdraw();
        return s;
    };

    (void)client;
    if (_bridge) return fail(Status::Busy, "a device is already presented");
    if (!attached.link) return fail(Status::TransportLost, "the session has no link");

    _channel = std::make_unique<UdecxDriverChannel>();
    std::string openWhy;
    if (const Status s = _channel->open(&openWhy); s != Status::Ok)
        return fail(s, openWhy);

    // The plane FIRST, then the bridge, then the plug-in. Ordering matters: the
    // driver starts handing over URBs the instant the device is plugged in, and
    // a URB that arrives before the bridge exists has nowhere to go.
    session::ImporterDataPlane::Config pc;
    pc.attachId         = attached.attachId;
    pc.attachSlot       = attached.slot;
    pc.maxInFlight      = 1;              // usb-storage is can_queue = 1
    pc.maxTransferBytes = attached.maxTransferBytes;
    _plane = std::make_unique<session::ImporterDataPlane>(attached.link, &_clock, pc);

    UdecxBridge::Config bc;
    bc.manifest         = attached.manifest;
    bc.capturedConfig   = attached.capturedConfig;
    bc.attachSlot       = attached.slot;
    bc.maxTransferBytes = attached.maxTransferBytes;
    bc.clock            = &_clock;
    // The incarnations are the driver's and are echoed on every record. Random
    // rather than counted, so a late completion from a previous session cannot
    // match a fresh one by arithmetic.
    {
        std::uint8_t raw[8];
        crypto::randomBytes(std::span<std::uint8_t>(raw, sizeof raw));
        bc.sessionIncarnation = static_cast<std::uint32_t>(
            raw[0] | (raw[1] << 8) | (raw[2] << 16) | (raw[3] << 24));
        bc.deviceIncarnation = static_cast<std::uint32_t>(
            raw[4] | (raw[5] << 8) | (raw[6] << 16) | (raw[7] << 24));
    }
    _bridge = std::make_unique<UdecxBridge>(*_channel, *_plane, bc);

    std::string plugWhy;
    if (const Status s = _channel->plugIn(attached.manifest, attached.capturedConfig,
                                          &plugWhy); s != Status::Ok)
        return fail(s, plugWhy);

    _last = "Presented to this computer as a USB device. It should appear in "
            "Device Manager and, for a drive, in File Explorer.";
    if (why) *why = _last;
    return Status::Ok;
}

Status UdecxPresenter::pump()
{
    if (!_bridge) return Status::Ok;
    const Status s = _bridge->poll();
    if (s != Status::Ok && s != Status::Busy) _last = _bridge->lastError();
    return s;
}

void UdecxPresenter::withdraw()
{
    // Plug out FIRST, while the bridge is still alive to answer whatever the
    // driver sends on the way down. Dropping the bridge first would leave the
    // driver's teardown records arriving at nothing — which the driver survives
    // (it retires everything locally, by design) but which loses the completion
    // the guest is waiting for.
    if (_channel) {
        std::string why;
        (void)_channel->plugOut(&why);
    }
    if (_bridge) _bridge->failAll(Status::DeviceGone);
    _bridge.reset();
    _plane.reset();
    _channel.reset();
}

std::string UdecxPresenter::statusText() const
{
    if (!_bridge) return "Nothing is presented to this computer.";
    return _last;
}

} // namespace airusb::windows
