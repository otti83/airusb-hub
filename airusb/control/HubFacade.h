// AirUSB Hub — the one thing the routes talk to, whichever half is behind it.
//
// `ControlApi` is a pure function of (request, state) and must stay that way,
// so it cannot know whether the authority is in this process or across a local
// socket. This is the seam: `HubState` implements it directly for the
// standalone diagnostic mode, and `BrokerFacade` implements it by forwarding
// to `airusb-brokerd`.
//
// THE STATE DOCUMENT IS RENDERED ONCE, BY THE AUTHORITY
//
// `stateJson()` returns the finished document rather than fields the window
// then assembles. That is deliberate: the window must not have an opinion about
// what is true. If it rendered the state itself it would need its own copy of
// "is this presented or merely probed", "is this lease quarantined", "is there
// a pairing question pending" — and a second copy of those judgements is a
// second answer, diverging exactly where it matters most.

#ifndef AIRUSB_CONTROL_HUBFACADE_H
#define AIRUSB_CONTROL_HUBFACADE_H

#include "../core/Status.h"

#include <array>
#include <cstdint>
#include <string>

namespace airusb::control {

using ApprovalTicket = std::array<std::uint8_t, 16>;

class IHubFacade {
public:
    virtual ~IHubFacade() = default;

    /// The whole window state, already rendered as JSON by the authority.
    virtual std::string stateJson() = 0;

    virtual Status shareStart(std::uint16_t port, std::string* why) = 0;
    virtual Status shareStop(std::string* why) = 0;
    virtual Status shareApprove(const ApprovalTicket& ticket, const std::string& fingerprint,
                                std::uint32_t sas, bool accept, std::string* why) = 0;
    virtual Status forceReclaim(std::string* why) = 0;

    virtual Status importConnect(const std::string& host, std::uint16_t port,
                                 std::string* why) = 0;
    virtual Status importDisconnect(std::string* why) = 0;
    virtual Status importApprove(const ApprovalTicket& ticket, const std::string& fingerprint,
                                 std::uint32_t sas, bool accept, std::string* why) = 0;
    virtual Status importRefresh(std::string* why) = 0;
    virtual Status importAttach(const std::string& uidHex, std::string* why) = 0;
    virtual Status importDetach(std::string* why) = 0;
    virtual Status importVerify(std::string* why) = 0;
    virtual Status importPing(std::string* why) = 0;
};

} // namespace airusb::control

#endif // AIRUSB_CONTROL_HUBFACADE_H
