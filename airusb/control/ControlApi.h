// AirUSB Hub — the routes, and nothing else.
//
// Deliberately a pure function of (request, state): give it an HttpRequest and
// it returns an HttpResponse. No sockets, no clock, no globals. That is what
// makes the guard testable — every refusal in this file can be provoked in a
// unit test by handing it a request, which is the only honest way to check that
// a security check fires, because the alternative is to trust that it would.
//
// THE ROUTE TABLE IS SHORT ON PURPOSE
//
// Every endpoint here is one thing a person can do in the window. There is no
// generic "run this" verb, no path that names a file, and no parameter that
// selects code. An API whose surface is a list of nouns can be read in one go
// and reasoned about; one that grows a general escape hatch cannot.

#ifndef AIRUSB_CONTROL_CONTROLAPI_H
#define AIRUSB_CONTROL_CONTROLAPI_H

#include "HttpServer.h"
#include "HubState.h"

#include <string>

namespace airusb::control {

class ControlApi {
public:
    ControlApi(HubState& hub, GuardConfig guard) noexcept
        : _hub(hub), _guard(std::move(guard)) {}

    /// The handler to hand to HttpServer::poll.
    HttpResponse handle(const HttpRequest& req);

    /// Counts refusals by kind, so a run can say "nothing was turned away" and
    /// mean it. A control plane that is quietly rejecting the page's requests
    /// looks exactly like one that is idle.
    std::uint64_t refusals() const noexcept { return _refusals; }

private:
    HttpResponse state() const;
    HttpResponse error(int status, std::string_view message) const;
    HttpResponse ok(std::string_view message) const;

    HubState&   _hub;
    GuardConfig _guard;
    std::uint64_t _refusals = 0;
};

} // namespace airusb::control

#endif // AIRUSB_CONTROL_CONTROLAPI_H
