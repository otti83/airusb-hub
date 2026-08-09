#include "HttpServer.h"

#include "../transport/TcpTransport.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace airusb::control {

namespace {

/// Bounds, all of them deliberate. A control plane that will only ever be
/// spoken to by one page on one machine has no reason to accept a request
/// larger than the largest thing that page sends, and every byte of slack is
/// memory an unauthenticated caller can make this process allocate before the
/// token is even checked.
constexpr std::size_t kMaxHeaderBytes = 8u * 1024u;
constexpr std::size_t kMaxBodyBytes   = 64u * 1024u;
constexpr std::size_t kMaxConns       = 16;
/// Roughly 20 s at the hub's 20 ms poll interval. A browser that opens a socket
/// and says nothing must not hold a slot for ever.
constexpr unsigned    kIdlePollLimit  = 1000;

std::string lower(std::string_view s)
{
    std::string o;
    o.reserve(s.size());
    for (char c : s)
        o += (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
    return o;
}

std::string_view trim(std::string_view s)
{
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
    while (!s.empty() && (s.back()  == ' ' || s.back()  == '\t' ||
                          s.back()  == '\r' || s.back() == '\n')) s.remove_suffix(1);
    return s;
}

const char* reasonPhrase(int status) noexcept
{
    switch (status) {
    case 200: return "OK";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 409: return "Conflict";
    case 413: return "Payload Too Large";
    case 431: return "Request Header Fields Too Large";
    case 500: return "Internal Server Error";
    case 503: return "Service Unavailable";
    default:  return "Status";
    }
}

int hexVal(char c) noexcept
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

} // namespace

// ---------------------------------------------------------------------------

std::string HttpRequest::header(std::string_view lowercaseName) const
{
    for (const auto& h : headers) if (h.first == lowercaseName) return h.second;
    return {};
}

bool HttpRequest::hasHeader(std::string_view lowercaseName) const
{
    for (const auto& h : headers) if (h.first == lowercaseName) return true;
    return false;
}

HttpResponse HttpResponse::json(int status, std::string body)
{
    HttpResponse r;
    r.status = status;
    r.body   = std::move(body);
    return r;
}

HttpResponse HttpResponse::text(int status, std::string body)
{
    HttpResponse r;
    r.status      = status;
    r.contentType = "text/plain; charset=utf-8";
    r.body        = std::move(body);
    return r;
}

// ---------------------------------------------------------------------------

bool HttpServer::percentDecode(std::string_view in, std::string& out)
{
    out.clear();
    out.reserve(in.size());
    for (std::size_t i = 0; i < in.size(); ++i) {
        if (in[i] != '%') {
            // '+' is form encoding, not URI encoding. Decoding it here would
            // make a path containing a plus mean something else.
            out += in[i];
            continue;
        }
        if (i + 2 >= in.size()) return false;
        const int hi = hexVal(in[i + 1]);
        const int lo = hexVal(in[i + 2]);
        if (hi < 0 || lo < 0) return false;
        const char c = static_cast<char>((hi << 4) | lo);
        if (c == '\0') return false;      // a decoded NUL truncates every C API downstream
        out += c;
        i += 2;
    }
    return true;
}

bool HttpServer::parseRequest(std::string_view raw, HttpRequest& out, bool& complete,
                              std::string* why)
{
    complete = false;
    auto fail = [&](const char* r) { if (why) *why = r; return false; };

    const std::size_t headEnd = raw.find("\r\n\r\n");
    if (headEnd == std::string_view::npos) {
        if (raw.size() > kMaxHeaderBytes) return fail("headers too large");
        return false;                    // not complete yet, not an error
    }

    const std::string_view head = raw.substr(0, headEnd);
    std::size_t lineEnd = head.find("\r\n");
    if (lineEnd == std::string_view::npos) lineEnd = head.size();
    const std::string_view start = head.substr(0, lineEnd);

    const std::size_t sp1 = start.find(' ');
    if (sp1 == std::string_view::npos) return fail("no method");
    const std::size_t sp2 = start.find(' ', sp1 + 1);
    if (sp2 == std::string_view::npos) return fail("no version");

    out = HttpRequest{};
    out.method.assign(start.substr(0, sp1));
    const std::string_view target = start.substr(sp1 + 1, sp2 - sp1 - 1);
    if (target.empty() || target.front() != '/') return fail("target is not an absolute path");

    const std::size_t q = target.find('?');
    const std::string_view rawPath = q == std::string_view::npos ? target : target.substr(0, q);
    if (q != std::string_view::npos) out.query.assign(target.substr(q + 1));
    if (!percentDecode(rawPath, out.path)) return fail("bad percent-encoding");

    // No filesystem is ever consulted, so ".." cannot escape anything — but a
    // route table is still a lookup, and a path that needs normalising before
    // it can be compared is a path that will one day be compared unnormalised.
    if (out.path.find("..") != std::string::npos) return fail("path contains ..");

    std::size_t pos = lineEnd + 2;
    std::size_t contentLength = 0;
    bool haveLength = false;
    while (pos < head.size()) {
        std::size_t e = head.find("\r\n", pos);
        if (e == std::string_view::npos) e = head.size();
        const std::string_view line = head.substr(pos, e - pos);
        pos = e + 2;
        if (line.empty()) continue;

        const std::size_t colon = line.find(':');
        if (colon == std::string_view::npos) return fail("header without a colon");
        const std::string name  = lower(trim(line.substr(0, colon)));
        const std::string value = std::string(trim(line.substr(colon + 1)));
        if (name.empty()) return fail("empty header name");

        if (name == "content-length") {
            if (haveLength) return fail("two Content-Length headers");
            haveLength = true;
            char* end = nullptr;
            const unsigned long long v = std::strtoull(value.c_str(), &end, 10);
            if (end == value.c_str() || (end && *end != '\0')) return fail("bad Content-Length");
            if (v > kMaxBodyBytes) return fail("body too large");
            contentLength = static_cast<std::size_t>(v);
        }
        // Transfer-Encoding is refused rather than ignored. Ignoring it is the
        // classic request-smuggling primitive: two parties disagree about where
        // the body ends. Nothing this server talks to needs it.
        if (name == "transfer-encoding") return fail("Transfer-Encoding is not accepted");

        out.headers.emplace_back(name, value);
        if (out.headers.size() > 64) return fail("too many headers");
    }

    const std::size_t bodyStart = headEnd + 4;
    if (raw.size() - bodyStart < contentLength) return false;   // body still arriving
    out.body.assign(raw.substr(bodyStart, contentLength));
    complete = true;
    return true;
}

// ---------------------------------------------------------------------------

HttpServer::~HttpServer() { stop(); }

Status HttpServer::start(std::uint16_t port)
{
    stop();
    Status st = Status::Ok;
    _listen = transport::TcpStream::listen(port, &st, /*loopbackOnly=*/true);
    if (!platform::isValid(_listen)) return st == Status::Ok ? Status::TransportLost : st;

    if (port != 0) {
        _port = port;
    } else {
        struct sockaddr_in a{};
#if defined(_WIN32)
        int len = static_cast<int>(sizeof a);
#else
        socklen_t len = sizeof a;
#endif
        if (::getsockname(_listen, reinterpret_cast<struct sockaddr*>(&a), &len) != 0) {
            stop();
            return Status::Internal;
        }
        _port = ntohs(a.sin_port);
    }
    return Status::Ok;
}

void HttpServer::stop()
{
    for (Conn& c : _conns) platform::closeSocket(c.fd);
    _conns.clear();
    platform::closeSocket(_listen);
    _listen = platform::kInvalidSocket;
    _port   = 0;
}

void HttpServer::closeConn(Conn& c)
{
    platform::closeSocket(c.fd);
    c.fd = platform::kInvalidSocket;
}

int HttpServer::poll(const Handler& handler)
{
    if (!platform::isValid(_listen)) return 0;

    // Accept whatever is pending, up to the cap. Beyond it, new sockets are
    // closed immediately rather than queued: the alternative is letting anyone
    // who can reach loopback make this process hold arbitrary many fds.
    for (;;) {
        const platform::SocketHandle fd = ::accept(_listen, nullptr, nullptr);
        if (!platform::isValid(fd)) break;
        platform::setNonBlocking(fd);
        if (_conns.size() >= kMaxConns) { platform::closeSocket(fd); continue; }
        Conn c;
        c.fd = fd;
        _conns.push_back(std::move(c));
    }

    int served = 0;

    for (Conn& c : _conns) {
        if (!platform::isValid(c.fd)) continue;

        if (!c.replied) {
            char buf[4096];
            for (;;) {
                const auto n = ::recv(c.fd, buf, platform::ioLength(sizeof buf), 0);
                if (n > 0) {
                    c.idlePolls = 0;
                    c.in.append(buf, static_cast<std::size_t>(n));
                    if (c.in.size() > kMaxHeaderBytes + kMaxBodyBytes) {
                        c.out = "HTTP/1.1 413 Payload Too Large\r\nConnection: close\r\n"
                                "Content-Length: 0\r\n\r\n";
                        c.replied = true;
                        break;
                    }
                    continue;
                }
                if (n == 0) { closeConn(c); break; }     // peer hung up
                if (!platform::wouldBlock(platform::lastSocketError())) { closeConn(c); }
                break;
            }
        }

        if (!platform::isValid(c.fd)) continue;

        if (!c.replied) {
            HttpRequest req;
            bool complete = false;
            std::string why;
            const bool ok = parseRequest(c.in, req, complete, &why);
            if (!ok && !complete && !why.empty()) {
                c.out = "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n"
                        "Content-Length: 0\r\n\r\n";
                c.replied = true;
            } else if (ok && complete) {
                HttpResponse res = handler(req);
                char headline[256];
                std::snprintf(headline, sizeof headline,
                              "HTTP/1.1 %d %s\r\n", res.status, reasonPhrase(res.status));
                c.out  = headline;
                c.out += "Content-Type: " + res.contentType + "\r\n";
                c.out += "Content-Length: " + std::to_string(res.body.size()) + "\r\n";
                c.out += "Connection: close\r\n";
                // The page is served to itself and fetches nothing. Saying so
                // in headers means a mistake in the page cannot become a way to
                // reach this API from somewhere else.
                c.out += "Cache-Control: no-store\r\n";
                c.out += "X-Content-Type-Options: nosniff\r\n";
                c.out += "Referrer-Policy: no-referrer\r\n";
                c.out += "Content-Security-Policy: default-src 'none'; "
                         "style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
                         "connect-src 'self'; img-src data:; form-action 'none'; "
                         "frame-ancestors 'none'; base-uri 'none'\r\n";
                c.out += "\r\n";
                if (req.method != "HEAD") c.out += res.body;
                c.replied = true;
                ++_handled;
                ++served;
            } else {
                if (++c.idlePolls > kIdlePollLimit) closeConn(c);
                continue;
            }
        }

        while (platform::isValid(c.fd) && c.sent < c.out.size()) {
            const auto n = ::send(c.fd, c.out.data() + c.sent,
                                  platform::ioLength(c.out.size() - c.sent), 0);
            if (n > 0) { c.sent += static_cast<std::size_t>(n); continue; }
            if (n < 0 && platform::wouldBlock(platform::lastSocketError())) break;
            closeConn(c);
        }
        if (platform::isValid(c.fd) && c.sent >= c.out.size()) closeConn(c);
    }

    for (std::size_t i = _conns.size(); i-- > 0;)
        if (!platform::isValid(_conns[i].fd)) _conns.erase(_conns.begin() + static_cast<std::ptrdiff_t>(i));

    return served;
}

// ---------------------------------------------------------------------------
// The guard
// ---------------------------------------------------------------------------

const char* guardVerdictText(GuardVerdict v) noexcept
{
    switch (v) {
    case GuardVerdict::Allow:        return "allow";
    case GuardVerdict::BadHost:      return "the Host header does not name this loopback endpoint";
    case GuardVerdict::BadOrigin:    return "cross-origin request refused";
    case GuardVerdict::MissingToken: return "no control token was presented";
    case GuardVerdict::BadToken:     return "the control token is wrong";
    }
    return "refused";
}

bool constantTimeEquals(std::string_view a, std::string_view b) noexcept
{
    // The length is not a secret — it is fixed by the generator — so comparing
    // it up front leaks nothing, and it lets the loop below be a clean fold.
    if (a.size() != b.size()) return false;
    unsigned char diff = 0;
    for (std::size_t i = 0; i < a.size(); ++i)
        diff = static_cast<unsigned char>(
            diff | (static_cast<unsigned char>(a[i]) ^ static_cast<unsigned char>(b[i])));
    return diff == 0;
}

namespace {

/// True if `hostHeader` names this loopback endpoint. An absent port means 80,
/// which we never listen on, so it is refused rather than assumed.
bool hostIsOurs(std::string_view hostHeader, std::uint16_t port)
{
    const std::string expectedNumeric = "127.0.0.1:" + std::to_string(port);
    const std::string expectedName    = "localhost:" + std::to_string(port);
    // [::1] is accepted in the header even though the socket binds IPv4 only:
    // a browser given http://[::1]:port/ would not reach us at all, so the case
    // cannot arise — but if the bind ever grows an IPv6 half, the guard should
    // not be the thing that silently keeps working by rejecting it.
    const std::string expectedV6      = "[::1]:" + std::to_string(port);
    return hostHeader == expectedNumeric || hostHeader == expectedName ||
           hostHeader == expectedV6;
}

} // namespace

GuardVerdict guardRequest(const HttpRequest& req, const GuardConfig& cfg)
{
    // Host first. It is the check that stops DNS rebinding, and rebinding is
    // the only one of these attacks that works against a victim who did
    // nothing but visit a web page.
    if (!hostIsOurs(req.header("host"), cfg.port)) return GuardVerdict::BadHost;

    // Origin is present on every cross-origin request a browser makes, and on
    // same-origin POSTs from this page. Absent is normal for a GET typed into
    // the address bar and for curl, so absence is allowed; a WRONG value never
    // is.
    if (const std::string origin = req.header("origin"); !origin.empty()) {
        const std::string ours    = "http://127.0.0.1:" + std::to_string(cfg.port);
        const std::string oursAlt = "http://localhost:" + std::to_string(cfg.port);
        if (origin != ours && origin != oursAlt) return GuardVerdict::BadOrigin;
    }

    std::string presented = req.header("x-airusb-token");
    if (presented.empty()) {
        const std::string auth = req.header("authorization");
        constexpr std::string_view kBearer = "Bearer ";
        if (auth.size() > kBearer.size() && auth.compare(0, kBearer.size(), kBearer) == 0)
            presented = auth.substr(kBearer.size());
    }
    if (presented.empty()) return GuardVerdict::MissingToken;
    if (!constantTimeEquals(presented, cfg.token)) return GuardVerdict::BadToken;

    return GuardVerdict::Allow;
}

} // namespace airusb::control
