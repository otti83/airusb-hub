// AirUSB Hub — just enough JSON, and deliberately not one byte more.
//
// The control plane speaks JSON because a browser is the one UI toolkit already
// installed on macOS, Linux and Windows. That does not justify vendoring a JSON
// library: this project vendors exactly two files, both cryptographic, both
// pinned and checksummed, and the bar for a third is that nothing smaller will
// do. Something smaller will do here.
//
// WHAT THE WRITER IS
//
// A string builder with escaping that cannot be forgotten, because the only way
// to put a string in is through a function that escapes it. There is no "raw"
// door. A device name arrives from a USB descriptor written by a stranger's
// firmware, and it lands in a page the user reads; the escaping is not a
// formatting nicety, it is the boundary.
//
// WHAT THE READER IS
//
// A parser for ONE shape: a flat object whose values are strings, numbers,
// booleans or null. Every request this API accepts is that shape. Nesting,
// arrays and unicode escapes are REJECTED rather than half-supported, because a
// parser that quietly accepts more than it was designed for is how a control
// plane grows an attack surface nobody reviewed. Values come out as strings;
// the caller says what it expected and gets a default if the text does not say
// that.

#ifndef AIRUSB_CONTROL_JSON_H
#define AIRUSB_CONTROL_JSON_H

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace airusb::control {

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

/// Escapes per RFC 8259 §7. Control characters below 0x20 become \u00XX; the
/// two mandatory escapes are `"` and `\`. Bytes above 0x7F pass through, which
/// is correct for UTF-8 and is why the response is served as UTF-8.
///
/// `<` and `/` are ALSO escaped, which RFC 8259 does not require. It costs
/// nothing and it means a device name containing `</script>` cannot end a
/// script element if this text is ever inlined into HTML rather than fetched.
/// The page does not inline it today. Pages change.
std::string jsonEscape(std::string_view s);

/// Builds one JSON document. Commas and braces are the class's problem, not the
/// caller's, because a hand-built JSON string is exactly the kind of code that
/// is correct until someone adds a field inside an `if`.
class JsonOut {
public:
    JsonOut() { _s.reserve(1024); }

    JsonOut& beginObject();
    JsonOut& endObject();
    JsonOut& beginArray();
    JsonOut& endArray();

    /// A key inside an object. The next call supplies its value.
    JsonOut& key(std::string_view k);

    JsonOut& str(std::string_view v);
    JsonOut& num(std::int64_t v);
    JsonOut& num(std::uint64_t v);
    JsonOut& boolean(bool v);
    JsonOut& null();

    // The overwhelmingly common shapes, so a caller writing a flat object does
    // not alternate key()/value() and lose track of which it is on.
    JsonOut& kv(std::string_view k, std::string_view v)  { return key(k).str(v); }
    JsonOut& kv(std::string_view k, const char* v)       { return key(k).str(v ? v : ""); }
    JsonOut& kv(std::string_view k, const std::string& v){ return key(k).str(v); }
    JsonOut& kv(std::string_view k, std::int64_t v)      { return key(k).num(v); }
    JsonOut& kv(std::string_view k, std::uint64_t v)     { return key(k).num(v); }
    JsonOut& kv(std::string_view k, std::uint32_t v)     { return key(k).num(static_cast<std::uint64_t>(v)); }
    JsonOut& kv(std::string_view k, int v)               { return key(k).num(static_cast<std::int64_t>(v)); }
    JsonOut& kv(std::string_view k, bool v)              { return key(k).boolean(v); }

    const std::string& str() const noexcept { return _s; }
    std::string take() { return std::move(_s); }

private:
    void comma();

    std::string _s;
    /// True while the next thing written is the first member of its container.
    /// A vector rather than a counter because objects and arrays nest.
    std::vector<bool> _first;
    bool _afterKey = false;
};

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

/// A flat JSON object, parsed. Values are held as text exactly as they would
/// have been written: a string's escapes are resolved, a number keeps its
/// spelling, `true`/`false` become "true"/"false", `null` becomes "".
class JsonObject {
public:
    /// Returns false — and leaves the object empty — on anything this parser
    /// does not accept, which includes valid JSON that is merely a shape the
    /// control plane never sends. `why` gets a short reason, for the log.
    ///
    /// `maxBytes` bounds the input before parsing begins, so a large body is
    /// refused rather than parsed and then refused.
    bool parse(std::string_view text, std::string* why = nullptr,
               std::size_t maxBytes = 64u * 1024u);

    bool has(std::string_view k) const noexcept;
    std::string     string(std::string_view k, std::string_view fallback = {}) const;
    std::int64_t    integer(std::string_view k, std::int64_t fallback = 0) const;
    /// 1..65535, or `fallback`. Zero is refused because a caller asking to
    /// CONNECT to port 0 has made a mistake, and silently turning that into a
    /// default would hide it.
    std::uint16_t   port(std::string_view k, std::uint16_t fallback = 0) const;

    /// The same, except 0 is accepted and means "let the OS choose one".
    ///
    /// Only for LISTENING. The two cases genuinely differ — 0 is meaningless as
    /// a destination and useful as a bind — and giving them one accessor is how
    /// a test that meant "any free port" quietly asked for 7714 instead, passed
    /// for as long as nothing else wanted 7714, and then failed the first time
    /// something did.
    std::uint16_t   listenPort(std::string_view k, std::uint16_t fallback,
                               bool* wasZero = nullptr) const;
    bool            boolean(std::string_view k, bool fallback = false) const;

    std::size_t size() const noexcept { return _members.size(); }

private:
    struct Member { std::string key, value; };
    std::vector<Member> _members;
};

} // namespace airusb::control

#endif // AIRUSB_CONTROL_JSON_H
