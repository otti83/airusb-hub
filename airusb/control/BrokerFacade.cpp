#include "BrokerFacade.h"

namespace airusb::control {

std::string BrokerFacade::stateJson()
{
    std::string why;
    (void)_c.refreshState(&why);

    if (!_c.connected()) {
        // A document rather than an error, because the page polls this and has
        // to render SOMETHING. Saying which daemon stopped is the part a person
        // can act on; "connection refused" is not.
        return std::string(
            "{\"connected\":false,\"notice\":\"The AirUSB broker is not running. "
            "It is the part of AirUSB that owns this machine's identity and can "
            "add a remote device to this computer; without it nothing here can "
            "pair or attach.\",\"share\":{\"state\":\"off\"},"
            "\"import\":{\"state\":\"off\"}}");
    }
    return _c.state().json;
}

} // namespace airusb::control
