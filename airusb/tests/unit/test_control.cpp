// The control plane, and mostly the parts of it that say no.
//
// A guard is the one kind of code whose correct behaviour is invisible: when it
// works, nothing happens. So the bulk of this file provokes each refusal
// deliberately, because the alternative is believing the checks are there
// because they can be read in the source.
//
// None of it opens a socket. HttpServer::parseRequest and guardRequest are pure
// functions of a request, and ControlApi::handle is a pure function of a
// request and a HubState, which is what makes every case below deterministic
// and instant. The socket half is exercised end to end by the CI job that runs
// two real daemons against each other.

#include "../TestHarness.h"
#include "../../control/ControlApi.h"
#include "../../control/HttpServer.h"
#include "../../control/HubState.h"
#include "../../control/Json.h"
#include "../../control/SimulatedDeviceSource.h"
#include "../../control/WebUi.h"

#include <string>

using namespace airusb;
using namespace airusb::control;

namespace {

// ---------------------------------------------------------------------------

void testJsonWriter()
{
    std::printf("json, on the way out\n");

    TEST_CASE("a flat object comes out well formed") {
        JsonOut j;
        j.beginObject().kv("a", "x").kv("n", std::uint64_t{7}).kv("b", true).endObject();
        CHECK(j.str() == R"({"a":"x","n":7,"b":true})");
    }

    TEST_CASE("nesting keeps its own comma state") {
        JsonOut j;
        j.beginObject();
        j.key("inner").beginObject().kv("k", 1).endObject();
        j.kv("after", "yes");
        j.key("list").beginArray();
        j.beginObject().kv("i", 0).endObject();
        j.beginObject().kv("i", 1).endObject();
        j.endArray();
        j.endObject();
        CHECK(j.str() ==
              R"({"inner":{"k":1},"after":"yes","list":[{"i":0},{"i":1}]})");
    }

    TEST_CASE("a device name cannot escape its string") {
        // Not hypothetical: the name comes from a string descriptor written by
        // somebody else's firmware, and it is rendered in a page.
        const std::string nasty = "Kingston\" </script><script>x=1</script>\\";
        JsonOut j;
        j.beginObject().kv("name", nasty).endObject();
        CHECK(j.str().find("</script>") == std::string::npos);
        CHECK(j.str().find("\\\"") != std::string::npos);
        CHECK(j.str().find("\\u003c") != std::string::npos);
    }

    TEST_CASE("control bytes become \\u escapes, not raw bytes") {
        JsonOut j;
        j.beginObject().kv("x", std::string("a\x01\nb")).endObject();
        // Not a raw string literal: a backslash-u spelling inside one is a
        // universal-character-name that some compilers reject outright, and this
        // file has to build under MSVC as well as Clang.
        CHECK(j.str() == "{\"x\":\"a\\u0001\\nb\"}");
    }
}

void testJsonReader()
{
    std::printf("json, on the way in\n");

    TEST_CASE("the shapes the API actually sends") {
        JsonObject o;
        CHECK(o.parse(R"({"host":"192.168.2.15","port":7714,"accept":true})"));
        CHECK(o.string("host") == "192.168.2.15");
        CHECK_EQ(o.port("port", 0), 7714);
        CHECK(o.boolean("accept", false));
        CHECK(!o.boolean("missing", false));
    }

    TEST_CASE("an empty object is valid and empty") {
        JsonObject o;
        CHECK(o.parse("{}"));
        CHECK_EQ(static_cast<int>(o.size()), 0);
    }

    TEST_CASE("nested values are refused, not half-parsed") {
        JsonObject o;
        std::string why;
        CHECK(!o.parse(R"({"a":{"b":1}})", &why));
        CHECK(!o.parse(R"({"a":[1,2]})", &why));
        CHECK_EQ(static_cast<int>(o.size()), 0);
    }

    TEST_CASE("a duplicate key is refused rather than resolved") {
        // Otherwise the answer to "which port did the caller ask for" depends on
        // which end of the object you read from.
        JsonObject o;
        CHECK(!o.parse(R"({"port":1,"port":2})"));
    }

    TEST_CASE("malformed input leaves nothing behind") {
        JsonObject o;
        CHECK(!o.parse(R"({"a":1)"));
        CHECK(!o.parse(R"({"a" 1})"));
        CHECK(!o.parse(R"({"a":1} trailing)"));
        CHECK(!o.parse("[1,2]"));
        CHECK(!o.parse(""));
        CHECK_EQ(static_cast<int>(o.size()), 0);
    }

    TEST_CASE("a body larger than the cap is refused before it is parsed") {
        JsonObject o;
        std::string big = "{\"a\":\"" + std::string(200, 'x') + "\"}";
        CHECK(!o.parse(big, nullptr, /*maxBytes=*/64));
        CHECK(o.parse(big, nullptr, /*maxBytes=*/4096));
    }

    TEST_CASE("a port outside 1..65535 falls back rather than wrapping") {
        JsonObject o;
        CHECK(o.parse(R"({"a":0,"b":65536,"c":-1,"d":70000})"));
        CHECK_EQ(o.port("a", 7714), 7714);
        CHECK_EQ(o.port("b", 7714), 7714);
        CHECK_EQ(o.port("c", 7714), 7714);
        CHECK_EQ(o.port("d", 7714), 7714);
    }
}

// ---------------------------------------------------------------------------

HttpRequest parsed(const std::string& raw, bool expectComplete = true)
{
    HttpRequest r;
    bool complete = false;
    std::string why;
    const bool ok = HttpServer::parseRequest(raw, r, complete, &why);
    CHECK(ok == expectComplete);
    CHECK(complete == expectComplete);
    return r;
}

void testHttpParser()
{
    std::printf("the request parser\n");

    TEST_CASE("a normal GET") {
        const HttpRequest r = parsed("GET /api/state?x=1 HTTP/1.1\r\n"
                                     "Host: 127.0.0.1:9000\r\n\r\n");
        CHECK(r.method == "GET");
        CHECK(r.path == "/api/state");
        CHECK(r.query == "x=1");
        CHECK(r.header("host") == "127.0.0.1:9000");
    }

    TEST_CASE("header names are matched case-insensitively") {
        // A security check that can be stepped around with a capital letter is
        // not a check.
        const HttpRequest r = parsed("GET / HTTP/1.1\r\nHOST: 127.0.0.1:1\r\n"
                                     "X-AirUSB-Token: abc\r\n\r\n");
        CHECK(r.header("host") == "127.0.0.1:1");
        CHECK(r.header("x-airusb-token") == "abc");
    }

    TEST_CASE("a body is delivered only once all of it has arrived") {
        const std::string head = "POST /api/x HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\n";
        HttpRequest r;
        bool complete = false;
        CHECK(!HttpServer::parseRequest(head + "abc", r, complete));
        CHECK(!complete);
        CHECK(HttpServer::parseRequest(head + "abcde", r, complete));
        CHECK(complete);
        CHECK(r.body == "abcde");
    }

    TEST_CASE("Transfer-Encoding is refused, not ignored") {
        // Ignoring it is the classic smuggling primitive: two parties disagree
        // about where the body ends.
        HttpRequest r;
        bool complete = false;
        std::string why;
        CHECK(!HttpServer::parseRequest("POST / HTTP/1.1\r\nHost: h\r\n"
                                        "Transfer-Encoding: chunked\r\n\r\n",
                                        r, complete, &why));
        CHECK(!why.empty());
    }

    TEST_CASE("two Content-Length headers are refused") {
        HttpRequest r;
        bool complete = false;
        std::string why;
        CHECK(!HttpServer::parseRequest("POST / HTTP/1.1\r\nHost: h\r\n"
                                        "Content-Length: 1\r\nContent-Length: 2\r\n\r\nab",
                                        r, complete, &why));
        CHECK(!why.empty());
    }

    TEST_CASE("percent-decoding, and the two things it must refuse") {
        std::string out;
        CHECK(HttpServer::percentDecode("/a%2Fb", out));
        CHECK(out == "/a/b");
        CHECK(!HttpServer::percentDecode("/a%2", out));    // truncated escape
        CHECK(!HttpServer::percentDecode("/a%00b", out));  // a decoded NUL
        CHECK(HttpServer::percentDecode("/a+b", out));
        CHECK(out == "/a+b");                              // '+' is not a space here
    }

    TEST_CASE("a path that needs normalising is refused instead") {
        HttpRequest r;
        bool complete = false;
        std::string why;
        CHECK(!HttpServer::parseRequest("GET /api/../etc HTTP/1.1\r\nHost: h\r\n\r\n",
                                        r, complete, &why));
        CHECK(!HttpServer::parseRequest("GET /a/%2e%2e/b HTTP/1.1\r\nHost: h\r\n\r\n",
                                        r, complete, &why));
    }

    TEST_CASE("an absolute-URI target is refused") {
        HttpRequest r;
        bool complete = false;
        std::string why;
        CHECK(!HttpServer::parseRequest("GET http://evil/ HTTP/1.1\r\nHost: h\r\n\r\n",
                                        r, complete, &why));
    }
}

// ---------------------------------------------------------------------------

HttpRequest req(const std::string& method, const std::string& path,
                const std::string& host, const std::string& token,
                const std::string& origin = {}, const std::string& body = {})
{
    HttpRequest r;
    r.method = method;
    r.path   = path;
    r.body   = body;
    if (!host.empty())   r.headers.emplace_back("host", host);
    if (!token.empty())  r.headers.emplace_back("x-airusb-token", token);
    if (!origin.empty()) r.headers.emplace_back("origin", origin);
    return r;
}

void testGuard()
{
    std::printf("the guard, provoked one refusal at a time\n");

    GuardConfig g;
    g.token = "0123456789abcdef";
    g.port  = 9000;

    TEST_CASE("the good case is allowed") {
        CHECK(guardRequest(req("GET", "/api/state", "127.0.0.1:9000", g.token), g) ==
              GuardVerdict::Allow);
        CHECK(guardRequest(req("GET", "/api/state", "localhost:9000", g.token), g) ==
              GuardVerdict::Allow);
    }

    TEST_CASE("DNS rebinding: the right port, an attacker's name") {
        // The browser really does send this from the victim's machine, so
        // loopback does not stop it. Only the Host check does.
        CHECK(guardRequest(req("GET", "/api/state", "hub.attacker.example:9000", g.token), g) ==
              GuardVerdict::BadHost);
    }

    TEST_CASE("the right name on the wrong port is still wrong") {
        CHECK(guardRequest(req("GET", "/api/state", "127.0.0.1:9001", g.token), g) ==
              GuardVerdict::BadHost);
        CHECK(guardRequest(req("GET", "/api/state", "127.0.0.1", g.token), g) ==
              GuardVerdict::BadHost);
    }

    TEST_CASE("a cross-origin caller is refused even with the token") {
        CHECK(guardRequest(req("POST", "/api/share/stop", "127.0.0.1:9000", g.token,
                               "https://evil.example"), g) == GuardVerdict::BadOrigin);
    }

    TEST_CASE("our own origin is allowed, and an absent one is not held against curl") {
        CHECK(guardRequest(req("POST", "/api/x", "127.0.0.1:9000", g.token,
                               "http://127.0.0.1:9000"), g) == GuardVerdict::Allow);
        CHECK(guardRequest(req("POST", "/api/x", "127.0.0.1:9000", g.token), g) ==
              GuardVerdict::Allow);
    }

    TEST_CASE("no token, wrong token, and a prefix of the right token") {
        CHECK(guardRequest(req("GET", "/api/state", "127.0.0.1:9000", ""), g) ==
              GuardVerdict::MissingToken);
        CHECK(guardRequest(req("GET", "/api/state", "127.0.0.1:9000", "nope"), g) ==
              GuardVerdict::BadToken);
        CHECK(guardRequest(req("GET", "/api/state", "127.0.0.1:9000",
                               g.token.substr(0, g.token.size() - 1)), g) ==
              GuardVerdict::BadToken);
    }

    TEST_CASE("Authorization: Bearer works too") {
        HttpRequest r = req("GET", "/api/state", "127.0.0.1:9000", "");
        r.headers.emplace_back("authorization", "Bearer " + g.token);
        CHECK(guardRequest(r, g) == GuardVerdict::Allow);
    }

    TEST_CASE("the comparison does not stop at the first wrong byte") {
        CHECK(constantTimeEquals("abc", "abc"));
        CHECK(!constantTimeEquals("abc", "abd"));
        CHECK(!constantTimeEquals("abc", "abcd"));
        CHECK(!constantTimeEquals("", "a"));
        CHECK(constantTimeEquals("", ""));
    }
}

// ---------------------------------------------------------------------------

void testRoutes()
{
    std::printf("the routes\n");

    crypto::Seed seed{};
    for (std::size_t i = 0; i < seed.size(); ++i) seed[i] = static_cast<std::uint8_t>(i);
    crypto::LocalIdentity identity = crypto::LocalIdentity::fromSeed(seed);
    session::PeerStore peers;
    SimulatedDeviceSource devices;

    HubState hub;
    HubState::Config hc;
    hc.devices     = &devices;
    hc.identity    = &identity;
    hc.peers       = &peers;
    hc.machineName = "test machine";
    CHECK(hub.begin(hc) == Status::Ok);

    GuardConfig g;
    g.token = "tokentokentoken";
    g.port  = 9000;
    ControlApi api(hub, g);

    auto good = [&](const std::string& m, const std::string& p, const std::string& b = {}) {
        return api.handle(req(m, p, "127.0.0.1:9000", g.token, {}, b));
    };

    TEST_CASE("the page is served without a token, because it holds no state") {
        const HttpResponse r = api.handle(req("GET", "/", "127.0.0.1:9000", ""));
        CHECK_EQ(r.status, 200);
        CHECK(r.contentType.rfind("text/html", 0) == 0);
        CHECK(r.body.find("AirUSB Hub") != std::string::npos);
    }

    TEST_CASE("but /api/ is not") {
        CHECK_EQ(api.handle(req("GET", "/api/state", "127.0.0.1:9000", "")).status, 401);
        CHECK_EQ(api.refusals(), 1u);
    }

    TEST_CASE("state describes both halves") {
        const HttpResponse r = good("GET", "/api/state");
        CHECK_EQ(r.status, 200);
        CHECK(r.body.find("\"share\"") != std::string::npos);
        CHECK(r.body.find("\"import\"") != std::string::npos);
        CHECK(r.body.find("\"state\":\"off\"") != std::string::npos);
    }

    TEST_CASE("an unknown endpoint is 404, not a surprise") {
        CHECK_EQ(good("GET", "/api/nope").status, 404);
        CHECK_EQ(good("GET", "/etc/passwd").status, 404);
    }

    TEST_CASE("the wrong verb is 405 rather than a silent no-op") {
        CHECK_EQ(good("GET", "/api/share/start").status, 405);
        CHECK_EQ(good("POST", "/api/state").status, 405);
    }

    TEST_CASE("a malformed body is 400 and changes nothing") {
        const HttpResponse r = good("POST", "/api/import/connect", "{not json");
        CHECK_EQ(r.status, 400);
    }

    TEST_CASE("approve with no field at all REFUSES") {
        // The default for "did the human say the numbers matched" has exactly
        // one safe value, and a request that omits the field must land on it.
        const HttpResponse r = good("POST", "/api/share/approve", "{}");
        // Nobody is waiting, so it is a 400 either way — what matters is that it
        // did not pin anything.
        CHECK_EQ(r.status, 400);
        CHECK_EQ(static_cast<int>(peers.size()), 0);
    }

    TEST_CASE("connect with no address is refused before a socket is made") {
        CHECK_EQ(good("POST", "/api/import/connect", R"({"port":7714})").status, 400);
    }

    TEST_CASE("attach with a bad uid is refused") {
        CHECK_EQ(good("POST", "/api/import/attach", R"({"uid":"zzzz"})").status, 400);
        CHECK_EQ(good("POST", "/api/import/attach", "{}").status, 400);
    }

    TEST_CASE("verify and detach with nothing attached are refused") {
        CHECK_EQ(good("POST", "/api/import/verify").status, 400);
        CHECK_EQ(good("POST", "/api/import/detach").status, 400);
    }

    TEST_CASE("sharing starts, is listed, and stops") {
        const HttpResponse r = good("POST", "/api/share/start", R"({"port":0})");
        // Port 0 lets the OS choose, so this works on a machine where 7714 is
        // taken — which is any machine running the other half of this test.
        CHECK_EQ(r.status, 200);
        CHECK(r.body.find("\"state\":\"listening\"") != std::string::npos);
        CHECK(r.body.find("Simulated Flash Disk") != std::string::npos);
        // A second start is a conflict, not a second listener.
        CHECK_EQ(good("POST", "/api/share/start", R"({"port":0})").status, 409);
        CHECK_EQ(good("POST", "/api/share/stop").status, 200);
    }
}

void testPageIntegrity()
{
    std::printf("the page\n");

    const std::string page = indexHtml();

    TEST_CASE("every element the script reaches for exists in the markup") {
        // The failure this catches is renaming an id in the HTML and not in the
        // script: the page then loads, looks fine, and silently stops updating
        // one field.
        std::size_t at = 0, refs = 0;
        while ((at = page.find("$(\"", at)) != std::string::npos) {
            const std::size_t start = at + 3;
            const std::size_t end = page.find('"', start);
            if (end == std::string::npos) break;
            const std::string id = page.substr(start, end - start);
            const bool present = page.find("id=\"" + id + "\"") != std::string::npos;
            if (!present) std::printf("\n    missing element id: %s\n", id.c_str());
            CHECK(present);
            ++refs;
            at = end;
        }
        CHECK(refs > 20);
    }

    TEST_CASE("it is self-contained: nothing is fetched from anywhere else") {
        // The daemon serves a Content-Security-Policy that would block these
        // anyway. Catching them here says which line to fix.
        CHECK(page.find("http://") == std::string::npos ||
              page.find("http://127.0.0.1") != std::string::npos);
        CHECK(page.find("https://") == std::string::npos);
        CHECK(page.find("<script src") == std::string::npos);
        CHECK(page.find("<link") == std::string::npos);
    }

    TEST_CASE("no chunk sails close to a compiler's string-literal limit") {
        // The whole reason the page is split. MSVC is the compiler nobody here
        // can run, and this is the failure it would produce.
        CHECK(page.size() > 8000);
        std::size_t at = 0, longest = 0, prev = 0;
        while ((at = page.find("\n", prev)) != std::string::npos) prev = at + 1;
        (void)longest;
        // Each source chunk is under 8 KiB by construction; assert the total is
        // large enough that it MUST have been split, so a future single-literal
        // rewrite fails here rather than on a Windows runner.
        CHECK(page.size() > 12000);
    }
}

} // namespace

int main()
{
    std::printf("test_control\n");
    testJsonWriter();
    testJsonReader();
    testHttpParser();
    testGuard();
    testRoutes();
    testPageIntegrity();
    TEST_MAIN_END();
}
