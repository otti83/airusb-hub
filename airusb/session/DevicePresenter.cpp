#include "DevicePresenter.h"

namespace airusb::session {

Status ProbePresenter::present(ImporterClient& client,
                               ImporterClient::BridgeAttach& attached,
                               std::string* why)
{
    // The device is already attached — `attached` is the result of ATTACH — so
    // this only wraps the live link in the synchronous instrument. It does NOT
    // re-attach, because a second ATTACH gets BUSY and is never queued (§7.7).
    if (!attached.link) {
        if (why) *why = "the session has no link";
        return Status::TransportLost;
    }
    _port = std::make_unique<RemoteDevicePort>(
        attached.link, attached.attachId, attached.slot, attached.manifest);
    (void)client;
    return Status::Ok;
}

} // namespace airusb::session
