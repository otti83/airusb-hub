// AirUSB Hub — the smallest HTTP server that can safely face a browser.
//
// WHY THERE IS AN HTTP SERVER IN A USB PROJECT
//
// The product needs a window: pick a device to share, pick one to import, read
// a six-digit number off the screen and say whether it matches. That window has
// to exist on macOS, Linux and Windows. The alternatives were three native
// toolkits (three implementations, and two of them on machines this project
// cannot run) or one page in the browser every one of those machines already
// has. The browser wins on reach and on being testable: the same `curl` drives
// it in CI as drives it by hand.
//
// WHAT IT IS NOT
//
// It is not a web server. It serves one embedded page and a handful of JSON
// endpoints, from memory. There is no filesystem path anywhere in it, so there
// is no traversal to get wrong; no chunked encoding, no keep-alive, no
// redirects, no cookies, no TLS. Every one of those is a thing that cannot be
// misimplemented because it is not implemented.
//
// THE THREE THINGS THAT MAKE IT SAFE, AND WHY EACH IS THERE
//
//   1. It binds 127.0.0.1, not INADDR_ANY. Another host cannot reach it at all.
//      This is the only one of the three that does not depend on the peer
//      behaving like a browser.
//
//   2. It requires a bearer token, read from a file only this user can read.
//      Loopback is not a boundary on a shared machine: every local account can
//      connect to 127.0.0.1. The token is what makes "local" mean "this user".
//
//   3. It checks Host and Origin. Without the Host check, any web page you
//      visit can point a hostname it controls at 127.0.0.1 (DNS rebinding) and
//      then talk to this server with your browser as the proxy — loopback does
//      not stop that, because the request really does come from your machine.
//      Without the Origin check, a page can POST cross-origin without ever
//      reading a response. The token defeats both on its own; these are the
//      second and third locks, because the first one is a file whose contents
//      end up in a URL, and URLs get shared.
//
// It never blocks. `poll()` services whatever is ready and returns, so the
// caller keeps pumping its USB sessions on the same thread. That is also why
// there are no threads: the session objects were written single-threaded and
// stay that way.

#ifndef AIRUSB_CONTROL_HTTPSERVER_H
#define AIRUSB_CONTROL_HTTPSERVER_H

#include "../core/Platform.h"
#include "../core/Status.h"

#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace airusb::control {

/// One parsed request. Headers are stored with lowercased names, because HTTP
/// header names are case-insensitive and a lookup that forgets it is a security
/// check that can be bypassed with a capital letter.
struct HttpRequest {
    std::string method;      ///< "GET", "POST", ...
    std::string path;        ///< the part before '?', percent-decoded
    std::string query;       ///< the part after '?', NOT decoded
    std::string body;

    std::string header(std::string_view lowercaseName) const;
    bool hasHeader(std::string_view lowercaseName) const;

    std::vector<std::pair<std::string, std::string>> headers;
};

struct HttpResponse {
    int         status      = 200;
    std::string contentType = "application/json; charset=utf-8";
    std::string body;

    static HttpResponse json(int status, std::string body);
    static HttpResponse text(int status, std::string body);
};

class HttpServer {
public:
    using Handler = std::function<HttpResponse(const HttpRequest&)>;

    ~HttpServer();

    /// Binds 127.0.0.1:port. Pass 0 to let the OS choose, then read `port()`.
    Status start(std::uint16_t port);
    void   stop();
    bool   running() const noexcept { return platform::isValid(_listen); }
    std::uint16_t port() const noexcept { return _port; }

    /// Services whatever is ready and returns immediately. Returns the number of
    /// requests handled, which a caller can use to decide whether to sleep.
    int poll(const Handler& handler);

    std::uint64_t requestsHandled() const noexcept { return _handled; }

    // --- the parts worth testing without a socket in the way ----------------

    /// Parses a complete request. Returns false if `raw` is not yet complete or
    /// is malformed; `complete` distinguishes the two.
    static bool parseRequest(std::string_view raw, HttpRequest& out, bool& complete,
                             std::string* why = nullptr);

    /// Percent-decoding, refusing a NUL and any incomplete escape.
    static bool percentDecode(std::string_view in, std::string& out);

private:
    struct Conn {
        platform::SocketHandle fd = platform::kInvalidSocket;
        std::string in;
        std::string out;
        std::size_t sent = 0;
        bool        replied = false;
        unsigned    idlePolls = 0;
    };

    void closeConn(Conn& c);

    platform::SocketHandle _listen = platform::kInvalidSocket;
    std::uint16_t     _port    = 0;
    std::vector<Conn> _conns;
    std::uint64_t     _handled = 0;
};

// ---------------------------------------------------------------------------
// The guard. Separate from the server so it is a pure function of a request:
// the tests for it need no sockets, no browser and no timing.
// ---------------------------------------------------------------------------

struct GuardConfig {
    std::string   token;    ///< required, compared in constant time
    std::uint16_t port = 0; ///< the port we are actually listening on
};

enum class GuardVerdict {
    Allow,
    BadHost,        ///< Host: names something other than this loopback endpoint
    BadOrigin,      ///< Origin: is cross-origin
    MissingToken,
    BadToken,
};

const char* guardVerdictText(GuardVerdict v) noexcept;

/// Applies checks 2 and 3 from the file header. Check 1 is the bind address and
/// cannot be expressed here.
GuardVerdict guardRequest(const HttpRequest& req, const GuardConfig& cfg);

/// Compares two secrets without leaking their common prefix through timing.
bool constantTimeEquals(std::string_view a, std::string_view b) noexcept;

} // namespace airusb::control

#endif // AIRUSB_CONTROL_HTTPSERVER_H
