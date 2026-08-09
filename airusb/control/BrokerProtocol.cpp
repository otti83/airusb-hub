#include "BrokerProtocol.h"

#include "../protocol/Codec.h"

#include <cstring>

namespace airusb::control::broker {

using protocol::rd_u8;
using protocol::rd_u16;
using protocol::rd_u32;
using protocol::rd_u64;
using protocol::wr_u8;
using protocol::wr_u16;
using protocol::wr_u32;
using protocol::wr_u64;

namespace {

std::uint8_t* grow(std::vector<std::uint8_t>& out, std::size_t n)
{
    const std::size_t at = out.size();
    out.resize(at + n);
    return out.data() + at;
}

void putU8 (std::vector<std::uint8_t>& o, std::uint8_t v)  { wr_u8 (grow(o, 1), v); }
void putU16(std::vector<std::uint8_t>& o, std::uint16_t v) { wr_u16(grow(o, 2), v); }
void putU32(std::vector<std::uint8_t>& o, std::uint32_t v) { wr_u32(grow(o, 4), v); }
void putU64(std::vector<std::uint8_t>& o, std::uint64_t v) { wr_u64(grow(o, 8), v); }

/// A string as u16 length + bytes. Strings on this channel are display text,
/// but they are still attacker-controlled once the broker echoes a peer's name,
/// so the length is capped by the decoder rather than by the writer's manners.
void putStr(std::vector<std::uint8_t>& o, const std::string& s)
{
    const std::size_t n = s.size() > kMaxStringLen ? kMaxStringLen : s.size();
    putU16(o, static_cast<std::uint16_t>(n));
    if (n) std::memcpy(grow(o, n), s.data(), n);
}

/// A blob with a u32 length, for the one field that is bigger than a string.
void putBlob(std::vector<std::uint8_t>& o, const std::string& s)
{
    const std::size_t n = s.size() > kMaxJsonBytes ? kMaxJsonBytes : s.size();
    putU32(o, static_cast<std::uint32_t>(n));
    if (n) std::memcpy(grow(o, n), s.data(), n);
}

void putNonce(std::vector<std::uint8_t>& o, const Nonce& n)
{
    std::memcpy(grow(o, kNonceBytes), n.data(), kNonceBytes);
}

/// A cursor that can only fail closed. Every read checks the remaining bytes
/// against the buffer actually present, never against a length the peer stated.
struct Cursor {
    std::span<const std::uint8_t> in;
    std::size_t at = 0;
    bool bad = false;

    bool has(std::size_t n) const noexcept { return !bad && in.size() - at >= n; }

    std::uint8_t u8()   { if (!has(1)) { bad = true; return 0; } const auto v = rd_u8 (in.data() + at); at += 1; return v; }
    std::uint16_t u16() { if (!has(2)) { bad = true; return 0; } const auto v = rd_u16(in.data() + at); at += 2; return v; }
    std::uint32_t u32() { if (!has(4)) { bad = true; return 0; } const auto v = rd_u32(in.data() + at); at += 4; return v; }
    std::uint64_t u64() { if (!has(8)) { bad = true; return 0; } const auto v = rd_u64(in.data() + at); at += 8; return v; }

    std::string str()
    {
        const std::uint16_t n = u16();
        if (bad) return {};
        if (n > kMaxStringLen) { bad = true; return {}; }
        if (!has(n)) { bad = true; return {}; }
        std::string s(reinterpret_cast<const char*>(in.data() + at), n);
        at += n;
        return s;
    }

    std::string blob()
    {
        const std::uint32_t n = u32();
        if (bad) return {};
        if (n > kMaxJsonBytes) { bad = true; return {}; }
        if (!has(n)) { bad = true; return {}; }
        std::string s(reinterpret_cast<const char*>(in.data() + at), n);
        at += n;
        return s;
    }

    Nonce nonce()
    {
        Nonce v{};
        if (!has(kNonceBytes)) { bad = true; return v; }
        std::memcpy(v.data(), in.data() + at, kNonceBytes);
        at += kNonceBytes;
        return v;
    }

    /// Trailing bytes are a deviation, not slack. A decoder that accepts two
    /// spellings of one message accepts one the writer never produced.
    bool done() const noexcept { return !bad && at == in.size(); }
};

} // namespace

// ---------------------------------------------------------------------------

bool isKnownOp(std::uint16_t raw) noexcept
{
    switch (static_cast<Op>(raw)) {
    case Op::Attach: case Op::GetState:
    case Op::ShareStart: case Op::ShareStop: case Op::ShareApprove:
    case Op::ImportConnect: case Op::ImportDisconnect: case Op::ImportApprove:
    case Op::ImportRefresh: case Op::ImportAttach: case Op::ImportDetach:
    case Op::ImportVerify: case Op::ImportPing:
    case Op::ForceReclaim:
        return true;
    }
    return false;
}

const char* opName(Op op) noexcept
{
    switch (op) {
    case Op::Attach:           return "ATTACH";
    case Op::GetState:         return "GET_STATE";
    case Op::ShareStart:       return "SHARE_START";
    case Op::ShareStop:        return "SHARE_STOP";
    case Op::ShareApprove:     return "SHARE_APPROVE";
    case Op::ImportConnect:    return "IMPORT_CONNECT";
    case Op::ImportDisconnect: return "IMPORT_DISCONNECT";
    case Op::ImportApprove:    return "IMPORT_APPROVE";
    case Op::ImportRefresh:    return "IMPORT_REFRESH";
    case Op::ImportAttach:     return "IMPORT_ATTACH";
    case Op::ImportDetach:     return "IMPORT_DETACH";
    case Op::ImportVerify:     return "IMPORT_VERIFY";
    case Op::ImportPing:       return "IMPORT_PING";
    case Op::ForceReclaim:     return "FORCE_RECLAIM";
    }
    return "UNKNOWN";
}

// ---------------------------------------------------------------------------

void encodeFrame(Op op, Status status, std::uint64_t tag,
                 std::span<const std::uint8_t> body,
                 std::vector<std::uint8_t>& out)
{
    std::uint8_t* p = grow(out, kHeaderSize);
    wr_u32(p + kOffBodyLen, static_cast<std::uint32_t>(body.size()));
    wr_u16(p + kOffOp,      static_cast<std::uint16_t>(op));
    wr_u16(p + kOffStatus,  static_cast<std::uint16_t>(status));
    wr_u64(p + kOffTag,     tag);
    if (!body.empty()) std::memcpy(grow(out, body.size()), body.data(), body.size());
}

Status parseFrame(std::span<const std::uint8_t> in, FrameHeader& h,
                  std::span<const std::uint8_t>& body, std::size_t& consumed) noexcept
{
    if (in.size() < kHeaderSize) return Status::Busy;

    h.bodyLen = rd_u32(in.data() + kOffBodyLen);
    h.op      = rd_u16(in.data() + kOffOp);
    h.status  = rd_u16(in.data() + kOffStatus);
    h.tag     = rd_u64(in.data() + kOffTag);

    // Checked BEFORE it is used to size anything, and fatal rather than
    // clamped: a length past the cap means the stream is not what it claims,
    // and continuing to read it would be reading somebody else's framing.
    if (h.bodyLen > kMaxBodyBytes) return Status::MalformedFrame;
    if (in.size() - kHeaderSize < h.bodyLen) return Status::Busy;

    body     = in.subspan(kHeaderSize, h.bodyLen);
    consumed = kHeaderSize + h.bodyLen;
    return Status::Ok;
}

// ---------------------------------------------------------------------------

void encode(const AttachRequest& r, std::vector<std::uint8_t>& out)
{
    putU32(out, r.version);
}

bool decode(std::span<const std::uint8_t> in, AttachRequest& out) noexcept
{
    Cursor c{in};
    const std::uint32_t v = c.u32();
    if (!c.done()) return false;
    out.version = v;
    return true;
}

void encode(const AttachReply& r, std::vector<std::uint8_t>& out)
{
    putU32(out, r.version);
    putStr(out, r.machineName);
    putStr(out, r.fingerprint);
    putStr(out, r.presenter);
    putU8 (out, r.canPresent ? 1u : 0u);
}

bool decode(std::span<const std::uint8_t> in, AttachReply& out) noexcept
{
    Cursor c{in};
    AttachReply v;
    v.version     = c.u32();
    v.machineName = c.str();
    v.fingerprint = c.str();
    v.presenter   = c.str();
    const std::uint8_t can = c.u8();
    // A bool that is neither 0 nor 1 is a peer writing something other than
    // this format. Refused, not coerced.
    if (can > 1) return false;
    if (!c.done()) return false;
    v.canPresent = can != 0;
    out = std::move(v);
    return true;
}

void encode(const ShareStartRequest& r, std::vector<std::uint8_t>& out)
{
    putU16(out, r.port);
}

bool decode(std::span<const std::uint8_t> in, ShareStartRequest& out) noexcept
{
    Cursor c{in};
    const std::uint16_t p = c.u16();
    if (!c.done()) return false;
    out.port = p;
    return true;
}

void encode(const ImportConnectRequest& r, std::vector<std::uint8_t>& out)
{
    putStr(out, r.host);
    putU16(out, r.port);
}

bool decode(std::span<const std::uint8_t> in, ImportConnectRequest& out) noexcept
{
    Cursor c{in};
    ImportConnectRequest v;
    v.host = c.str();
    v.port = c.u16();
    if (!c.done()) return false;
    // Port 0 is a real answer for a LISTEN and a meaningless one for a connect.
    if (v.port == 0) return false;
    out = std::move(v);
    return true;
}

void encode(const ApproveRequest& r, std::vector<std::uint8_t>& out)
{
    putNonce(out, r.nonce);
    putStr  (out, r.fingerprint);
    putU32  (out, r.sas);
    putU8   (out, r.accept ? 1u : 0u);
}

bool decode(std::span<const std::uint8_t> in, ApproveRequest& out) noexcept
{
    Cursor c{in};
    ApproveRequest v;
    v.nonce       = c.nonce();
    v.fingerprint = c.str();
    v.sas         = c.u32();
    const std::uint8_t acc = c.u8();
    if (acc > 1) return false;
    if (!c.done()) return false;
    v.accept = acc != 0;
    out = std::move(v);
    return true;
}

void encode(const AttachDeviceRequest& r, std::vector<std::uint8_t>& out)
{
    putStr(out, r.uidHex);
}

bool decode(std::span<const std::uint8_t> in, AttachDeviceRequest& out) noexcept
{
    Cursor c{in};
    AttachDeviceRequest v;
    v.uidHex = c.str();
    if (!c.done()) return false;
    return (out = std::move(v), true);
}

void encode(const StateReply& r, std::vector<std::uint8_t>& out)
{
    putBlob(out, r.json);
    putStr (out, r.error);
    putU8 (out, r.shareState);
    putU8 (out, r.importState);
    putU16(out, r.sharePort);

    putU32  (out, r.shareSas);
    putNonce(out, r.shareNonce);
    putStr  (out, r.sharePeerFingerprint);

    putU32  (out, r.importSas);
    putNonce(out, r.importNonce);
    putStr  (out, r.importPeerFingerprint);

    putU8 (out, r.leaseState);
    putU8 (out, r.attached ? 1u : 0u);
    putStr(out, r.attachedUid);
    putStr(out, r.attachedName);
    putStr(out, r.attachedVia);
    putU64(out, r.lastRttNs);
    putStr(out, r.notice);

    const std::size_t n = r.devices.size() > kMaxDevices ? kMaxDevices : r.devices.size();
    putU16(out, static_cast<std::uint16_t>(n));
    for (std::size_t i = 0; i < n; ++i) {
        const DeviceEntry& d = r.devices[i];
        putStr(out, d.uidHex);
        putU16(out, d.vendorId);
        putU16(out, d.productId);
        putU8 (out, d.speed);
        putU8 (out, d.flags);
        putStr(out, d.name);
    }
}

bool decode(std::span<const std::uint8_t> in, StateReply& out) noexcept
{
    Cursor c{in};
    StateReply v;
    v.json        = c.blob();
    v.error       = c.str();
    v.shareState  = c.u8();
    v.importState = c.u8();
    v.sharePort   = c.u16();

    v.shareSas             = c.u32();
    v.shareNonce           = c.nonce();
    v.sharePeerFingerprint = c.str();

    v.importSas             = c.u32();
    v.importNonce           = c.nonce();
    v.importPeerFingerprint = c.str();

    v.leaseState = c.u8();
    const std::uint8_t att = c.u8();
    if (att > 1) return false;
    v.attached     = att != 0;
    v.attachedUid  = c.str();
    v.attachedName = c.str();
    v.attachedVia  = c.str();
    v.lastRttNs    = c.u64();
    v.notice       = c.str();

    const std::uint16_t count = c.u16();
    if (c.bad) return false;
    // The cap is checked before the loop, so a huge count cannot drive an
    // allocation even briefly.
    if (count > kMaxDevices) return false;
    v.devices.reserve(count);
    for (std::uint16_t i = 0; i < count; ++i) {
        DeviceEntry d;
        d.uidHex    = c.str();
        d.vendorId  = c.u16();
        d.productId = c.u16();
        d.speed     = c.u8();
        d.flags     = c.u8();
        d.name      = c.str();
        if (c.bad) return false;
        v.devices.push_back(std::move(d));
    }
    if (!c.done()) return false;
    out = std::move(v);
    return true;
}

bool decodeAny(std::uint16_t op, std::span<const std::uint8_t> in) noexcept
{
    if (!isKnownOp(op)) return false;
    switch (static_cast<Op>(op)) {
    case Op::Attach:          { AttachRequest r;        if (decode(in, r)) return true;
                                AttachReply rr;         return decode(in, rr); }
    case Op::GetState:        { if (in.empty()) return true;
                                StateReply r;           return decode(in, r); }
    case Op::ShareStart:      { ShareStartRequest r;    return decode(in, r); }
    case Op::ImportConnect:   { ImportConnectRequest r; return decode(in, r); }
    case Op::ShareApprove:
    case Op::ImportApprove:   { ApproveRequest r;       return decode(in, r); }
    case Op::ImportAttach:    { AttachDeviceRequest r;  return decode(in, r); }
    case Op::ShareStop:
    case Op::ImportDisconnect:
    case Op::ImportRefresh:
    case Op::ImportDetach:
    case Op::ImportVerify:
    case Op::ImportPing:
    case Op::ForceReclaim:
        // Verbs with no arguments. An empty body is the only correct spelling;
        // trailing bytes mean the sender and this build disagree about the
        // message, which is exactly what a version check exists to catch.
        return in.empty();
    }
    return false;
}

} // namespace airusb::control::broker
