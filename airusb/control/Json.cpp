#include "Json.h"

#include <cstdio>
#include <cstdlib>

namespace airusb::control {

namespace {

bool isWs(char c) noexcept { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }

} // namespace

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

std::string jsonEscape(std::string_view s)
{
    std::string out;
    out.reserve(s.size() + 8);
    for (const char c : s) {
        const auto u = static_cast<unsigned char>(c);
        switch (c) {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b";  break;
        case '\f': out += "\\f";  break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        // Not required by RFC 8259. See the header: it costs nothing and it
        // means `</script>` in a USB string descriptor cannot close an element.
        case '<':  out += "\\u003c"; break;
        case '>':  out += "\\u003e"; break;
        case '&':  out += "\\u0026"; break;
        case '/':  out += "\\/";  break;
        default:
            if (u < 0x20) {
                char buf[7];
                std::snprintf(buf, sizeof buf, "\\u%04x", u);
                out += buf;
            } else {
                out += c;
            }
        }
    }
    return out;
}

void JsonOut::comma()
{
    if (_afterKey) { _afterKey = false; return; }
    if (_first.empty()) return;
    if (_first.back()) _first.back() = false;
    else               _s += ',';
}

JsonOut& JsonOut::beginObject() { comma(); _s += '{'; _first.push_back(true); return *this; }
JsonOut& JsonOut::beginArray()  { comma(); _s += '['; _first.push_back(true); return *this; }

JsonOut& JsonOut::endObject()
{
    _s += '}';
    if (!_first.empty()) _first.pop_back();
    return *this;
}

JsonOut& JsonOut::endArray()
{
    _s += ']';
    if (!_first.empty()) _first.pop_back();
    return *this;
}

JsonOut& JsonOut::key(std::string_view k)
{
    comma();
    _s += '"';
    _s += jsonEscape(k);
    _s += "\":";
    _afterKey = true;
    return *this;
}

JsonOut& JsonOut::str(std::string_view v)
{
    comma();
    _s += '"';
    _s += jsonEscape(v);
    _s += '"';
    return *this;
}

JsonOut& JsonOut::num(std::int64_t v)
{
    comma();
    char buf[32];
    std::snprintf(buf, sizeof buf, "%lld", static_cast<long long>(v));
    _s += buf;
    return *this;
}

JsonOut& JsonOut::num(std::uint64_t v)
{
    comma();
    char buf[32];
    std::snprintf(buf, sizeof buf, "%llu", static_cast<unsigned long long>(v));
    _s += buf;
    return *this;
}

JsonOut& JsonOut::boolean(bool v) { comma(); _s += v ? "true" : "false"; return *this; }
JsonOut& JsonOut::null()          { comma(); _s += "null";              return *this; }

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

bool JsonObject::parse(std::string_view text, std::string* why, std::size_t maxBytes)
{
    _members.clear();
    auto fail = [&](const char* reason) {
        if (why) *why = reason;
        _members.clear();
        return false;
    };

    if (text.size() > maxBytes) return fail("body too large");

    std::size_t i = 0;
    auto skipWs = [&] { while (i < text.size() && isWs(text[i])) ++i; };

    // A string, with the escapes this parser admits resolved. \u is refused
    // rather than decoded: no field the control plane accepts needs it, and a
    // half-written surrogate decoder is worse than no decoder.
    auto readString = [&](std::string& out) -> bool {
        if (i >= text.size() || text[i] != '"') return false;
        ++i;
        out.clear();
        while (i < text.size()) {
            const char c = text[i++];
            if (c == '"') return true;
            if (c == '\\') {
                if (i >= text.size()) return false;
                const char e = text[i++];
                switch (e) {
                case '"':  out += '"';  break;
                case '\\': out += '\\'; break;
                case '/':  out += '/';  break;
                case 'b':  out += '\b'; break;
                case 'f':  out += '\f'; break;
                case 'n':  out += '\n'; break;
                case 'r':  out += '\r'; break;
                case 't':  out += '\t'; break;
                default:   return false;
                }
                continue;
            }
            if (static_cast<unsigned char>(c) < 0x20) return false;  // raw control byte
            out += c;
        }
        return false;   // unterminated
    };

    skipWs();
    if (i >= text.size() || text[i] != '{') return fail("not an object");
    ++i;
    skipWs();
    if (i < text.size() && text[i] == '}') { ++i; skipWs(); return i == text.size(); }

    for (;;) {
        skipWs();
        Member m;
        if (!readString(m.key)) return fail("expected a key");
        skipWs();
        if (i >= text.size() || text[i] != ':') return fail("expected ':'");
        ++i;
        skipWs();
        if (i >= text.size()) return fail("truncated");

        const char c = text[i];
        if (c == '"') {
            if (!readString(m.value)) return fail("bad string value");
        } else if (c == '{' || c == '[') {
            // Refused on purpose. Every request this API accepts is flat, and a
            // parser that accepts a shape the API does not is surface with no
            // consumer to review it.
            return fail("nested values are not accepted");
        } else if (c == 't' || c == 'f' || c == 'n') {
            if (text.compare(i, 4, "true") == 0)       { m.value = "true";  i += 4; }
            else if (text.compare(i, 5, "false") == 0) { m.value = "false"; i += 5; }
            else if (text.compare(i, 4, "null") == 0)  { m.value.clear();   i += 4; }
            else return fail("bad literal");
        } else {
            const std::size_t start = i;
            if (i < text.size() && (text[i] == '-' || text[i] == '+')) ++i;
            bool digits = false;
            while (i < text.size() &&
                   ((text[i] >= '0' && text[i] <= '9') || text[i] == '.' ||
                    text[i] == 'e' || text[i] == 'E' || text[i] == '-' || text[i] == '+')) {
                if (text[i] >= '0' && text[i] <= '9') digits = true;
                ++i;
            }
            if (!digits) return fail("bad value");
            m.value.assign(text.substr(start, i - start));
        }

        // Last writer wins would let a request smuggle a second `port`. Refuse
        // instead: there is no legitimate reason to send a key twice, and the
        // two halves of an API that disagree about which one counts is a class
        // of bug worth never having.
        for (const Member& e : _members)
            if (e.key == m.key) return fail("duplicate key");

        _members.push_back(std::move(m));
        if (_members.size() > 64) return fail("too many members");

        skipWs();
        if (i < text.size() && text[i] == ',') { ++i; continue; }
        if (i < text.size() && text[i] == '}') { ++i; break; }
        return fail("expected ',' or '}'");
    }

    skipWs();
    if (i != text.size()) return fail("trailing bytes");
    return true;
}

bool JsonObject::has(std::string_view k) const noexcept
{
    for (const Member& m : _members) if (m.key == k) return true;
    return false;
}

std::string JsonObject::string(std::string_view k, std::string_view fallback) const
{
    for (const Member& m : _members) if (m.key == k) return m.value;
    return std::string(fallback);
}

std::int64_t JsonObject::integer(std::string_view k, std::int64_t fallback) const
{
    for (const Member& m : _members) {
        if (m.key != k) continue;
        if (m.value.empty()) return fallback;
        char* end = nullptr;
        const long long v = std::strtoll(m.value.c_str(), &end, 10);
        if (end == m.value.c_str() || (end && *end != '\0')) return fallback;
        return static_cast<std::int64_t>(v);
    }
    return fallback;
}

std::uint16_t JsonObject::port(std::string_view k, std::uint16_t fallback) const
{
    const std::int64_t v = integer(k, -1);
    if (v < 1 || v > 65535) return fallback;
    return static_cast<std::uint16_t>(v);
}

std::uint16_t JsonObject::listenPort(std::string_view k, std::uint16_t fallback,
                                     bool* wasZero) const
{
    if (wasZero) *wasZero = false;
    const std::int64_t v = integer(k, -1);
    if (v == 0) { if (wasZero) *wasZero = true; return 0; }
    if (v < 1 || v > 65535) return fallback;
    return static_cast<std::uint16_t>(v);
}

bool JsonObject::boolean(std::string_view k, bool fallback) const
{
    for (const Member& m : _members) {
        if (m.key != k) continue;
        if (m.value == "true")  return true;
        if (m.value == "false") return false;
        return fallback;
    }
    return fallback;
}

} // namespace airusb::control
