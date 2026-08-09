#include "ControlApi.h"

#include "Json.h"
#include "WebUi.h"

namespace airusb::control {

namespace {

/// Maps a Status onto an HTTP code. Only the distinctions a browser acts on are
/// made; everything else is 500, because inventing a code per protocol status
/// would suggest the page should behave differently for each, and it should not.
int httpFor(Status s) noexcept
{
    switch (s) {
    case Status::Ok:                 return 200;
    case Status::BadArgument:        return 400;
    case Status::NotPaired:
    case Status::NotPermitted:       return 403;
    case Status::NotFound:           return 404;
    case Status::Busy:
    case Status::ExclusivityDenied:  return 409;
    case Status::UnsupportedMessage: return 501;
    default:                         return 500;
    }
}

} // namespace

HttpResponse ControlApi::error(int status, std::string_view message) const
{
    JsonOut j;
    j.beginObject().kv("ok", false).kv("error", message).endObject();
    return HttpResponse::json(status, j.take());
}

HttpResponse ControlApi::ok(std::string_view message) const
{
    JsonOut j;
    j.beginObject().kv("ok", true).kv("message", message).endObject();
    return HttpResponse::json(200, j.take());
}

HttpResponse ControlApi::state() const
{
    JsonOut j;
    _hub.writeStateJson(j);
    return HttpResponse::json(200, j.take());
}

HttpResponse ControlApi::handle(const HttpRequest& req)
{
    // The page itself is served WITHOUT the token, and that is not a hole: it
    // is a static document with no data in it. It has to be, because the token
    // arrives in the URL fragment and a browser does not send a fragment to the
    // server — which is the point of putting it there. Every byte of state
    // lives behind /api/, and /api/ is behind the guard.
    if (req.path == "/" || req.path == "/index.html") {
        if (req.method != "GET" && req.method != "HEAD")
            return error(405, "the page is only served for GET");
        HttpResponse r;
        r.contentType = "text/html; charset=utf-8";
        r.body        = indexHtml();
        return r;
    }

    if (req.path.rfind("/api/", 0) != 0)
        return error(404, "no such endpoint");

    if (const GuardVerdict v = guardRequest(req, _guard); v != GuardVerdict::Allow) {
        ++_refusals;
        const int code = (v == GuardVerdict::MissingToken || v == GuardVerdict::BadToken)
                             ? 401 : 403;
        return error(code, guardVerdictText(v));
    }

    const bool isPost = req.method == "POST";
    const bool isGet  = req.method == "GET";

    JsonObject in;
    if (isPost && !req.body.empty()) {
        std::string why;
        if (!in.parse(req.body, &why)) return error(400, "malformed request body: " + why);
    }

    std::string why;

    // --- read ---------------------------------------------------------------

    if (req.path == "/api/state") {
        if (!isGet) return error(405, "GET only");
        return state();
    }

    // --- sharing ------------------------------------------------------------

    if (req.path == "/api/share/start") {
        if (!isPost) return error(405, "POST only");
        const std::uint16_t port = in.port("port", 7714);
        if (const Status s = _hub.shareStart(port, &why); s != Status::Ok)
            return error(httpFor(s), why);
        return state();
    }

    if (req.path == "/api/share/stop") {
        if (!isPost) return error(405, "POST only");
        _hub.shareStop();
        return state();
    }

    if (req.path == "/api/share/approve") {
        if (!isPost) return error(405, "POST only");
        // Defaulting to false is the only safe default for a question whose
        // wrong answer hands a drive to a stranger. A request that forgets the
        // field refuses; it does not accept.
        const bool accept = in.boolean("accept", false);
        if (const Status s = _hub.shareApprove(accept, &why); s != Status::Ok)
            return error(httpFor(s), why);
        return state();
    }

    // --- importing ----------------------------------------------------------

    if (req.path == "/api/import/connect") {
        if (!isPost) return error(405, "POST only");
        const std::string host = in.string("host");
        const std::uint16_t port = in.port("port", 7714);
        if (host.empty()) return error(400, "no address given");
        if (const Status s = _hub.importConnect(host, port, &why); s != Status::Ok)
            return error(httpFor(s), why);
        return state();
    }

    if (req.path == "/api/import/approve") {
        if (!isPost) return error(405, "POST only");
        const bool accept = in.boolean("accept", false);
        if (const Status s = _hub.importApprove(accept, &why); s != Status::Ok)
            return error(httpFor(s), why);
        return state();
    }

    if (req.path == "/api/import/refresh") {
        if (!isPost) return error(405, "POST only");
        if (const Status s = _hub.importRefresh(&why); s != Status::Ok)
            return error(httpFor(s), why);
        return state();
    }

    if (req.path == "/api/import/attach") {
        if (!isPost) return error(405, "POST only");
        const std::string uid = in.string("uid");
        if (uid.empty()) return error(400, "no device chosen");
        if (const Status s = _hub.importAttach(uid, &why); s != Status::Ok)
            return error(httpFor(s), why);
        return state();
    }

    if (req.path == "/api/import/detach") {
        if (!isPost) return error(405, "POST only");
        if (const Status s = _hub.importDetach(&why); s != Status::Ok)
            return error(httpFor(s), why);
        return state();
    }

    if (req.path == "/api/import/disconnect") {
        if (!isPost) return error(405, "POST only");
        _hub.importDisconnect();
        return state();
    }

    if (req.path == "/api/import/verify") {
        if (!isPost) return error(405, "POST only");
        if (const Status s = _hub.importVerify(&why); s != Status::Ok)
            return error(httpFor(s), why);
        return state();
    }

    if (req.path == "/api/import/ping") {
        if (!isPost) return error(405, "POST only");
        if (const Status s = _hub.importPing(&why); s != Status::Ok)
            return error(httpFor(s), why);
        return state();
    }

    return error(404, "no such endpoint");
}

} // namespace airusb::control
