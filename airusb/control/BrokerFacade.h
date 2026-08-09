// AirUSB Hub — the window's routes, pointed at a broker instead of at itself.
//
// Every method is one round trip and nothing else. There is deliberately no
// caching, no retry and no local decision: a facade that answered from a stale
// copy would be the window having an opinion, which is exactly what the broker
// exists to take away from it.
//
// The one thing it does add is a sentence when the broker is gone, because
// "the daemon that owns your USB devices has stopped" is something a person
// needs told, and a bare transport error is not that.

#ifndef AIRUSB_CONTROL_BROKERFACADE_H
#define AIRUSB_CONTROL_BROKERFACADE_H

#include "BrokerClient.h"
#include "HubFacade.h"

namespace airusb::control {

class BrokerFacade final : public IHubFacade {
public:
    explicit BrokerFacade(BrokerClient& c) noexcept : _c(c) {}

    std::string stateJson() override;

    Status shareStart(std::uint16_t port, std::string* why) override
    { return _c.shareStart(port, why); }
    Status shareStop(std::string* why) override { return _c.shareStop(why); }
    Status shareApprove(const ApprovalTicket& t, const std::string& fp,
                        std::uint32_t sas, bool accept, std::string* why) override
    { return _c.shareApprove(t, fp, sas, accept, why); }
    Status forceReclaim(std::string* why) override { return _c.forceReclaim(why); }

    Status importConnect(const std::string& host, std::uint16_t port,
                         std::string* why) override
    { return _c.importConnect(host, port, why); }
    Status importDisconnect(std::string* why) override { return _c.importDisconnect(why); }
    Status importApprove(const ApprovalTicket& t, const std::string& fp,
                         std::uint32_t sas, bool accept, std::string* why) override
    { return _c.importApprove(t, fp, sas, accept, why); }
    Status importRefresh(std::string* why) override { return _c.importRefresh(why); }
    Status importAttach(const std::string& uid, std::string* why) override
    { return _c.importAttach(uid, why); }
    Status importDetach(std::string* why) override { return _c.importDetach(why); }
    Status importVerify(std::string* why) override { return _c.importVerify(why); }
    Status importPing(std::string* why) override { return _c.importPing(why); }

private:
    BrokerClient& _c;
};

} // namespace airusb::control

#endif // AIRUSB_CONTROL_BROKERFACADE_H
