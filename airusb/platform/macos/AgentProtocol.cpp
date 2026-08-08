#include "AgentProtocol.h"

#include "../../protocol/Codec.h"   // rd_u8/rd_u16/rd_u32/rd_u64, wr_* — one set only

namespace airusb::macos::ipc {

using protocol::rd_u16;
using protocol::rd_u32;
using protocol::rd_u64;
using protocol::rd_u8;
using protocol::wr_u16;
using protocol::wr_u32;
using protocol::wr_u64;
using protocol::wr_u8;

namespace {

/// Reserve `n` bytes at the end of `out` and hand back a writable pointer to
/// them. Taken after the resize, never before: a pointer into a vector taken
/// before it grows is a use-after-free waiting for a reallocation.
std::uint8_t* extend(std::vector<std::uint8_t>& out, std::size_t n)
{
    const std::size_t at = out.size();
    out.resize(at + n);
    return out.data() + at;
}

} // namespace

// ---------------------------------------------------------------------------

bool isKnownOp(std::uint16_t raw) noexcept
{
    switch (raw) {
        case static_cast<std::uint16_t>(Op::Hello):
        case static_cast<std::uint16_t>(Op::OpenInterfaces):
        case static_cast<std::uint16_t>(Op::RebuildPipes):
        case static_cast<std::uint16_t>(Op::BulkOut):
        case static_cast<std::uint16_t>(Op::BulkIn):
        case static_cast<std::uint16_t>(Op::ClearHalt):
        case static_cast<std::uint16_t>(Op::AbortEndpoint):
        case static_cast<std::uint16_t>(Op::Close):
        case static_cast<std::uint16_t>(Op::Ping):
            return true;
        default:
            return false;
    }
}

const char* opName(Op op) noexcept
{
    switch (op) {
        case Op::Hello:          return "HELLO";
        case Op::OpenInterfaces: return "OPEN_INTERFACES";
        case Op::RebuildPipes:   return "REBUILD_PIPES";
        case Op::BulkOut:        return "BULK_OUT";
        case Op::BulkIn:         return "BULK_IN";
        case Op::ClearHalt:      return "CLEAR_HALT";
        case Op::AbortEndpoint:  return "ABORT_ENDPOINT";
        case Op::Close:          return "CLOSE";
        case Op::Ping:           return "PING";
    }
    return "?";
}

// ---------------------------------------------------------------------------
// frame
// ---------------------------------------------------------------------------

void encodeFrame(const Frame& f, std::vector<std::uint8_t>& out)
{
    std::uint8_t* h = extend(out, kHeaderSize);
    wr_u32(h + kOffBodyLen, static_cast<std::uint32_t>(f.body.size()));
    wr_u16(h + kOffOp,      static_cast<std::uint16_t>(f.op));
    wr_u16(h + kOffStatus,  static_cast<std::uint16_t>(f.status));
    wr_u64(h + kOffTag,     f.tag);
    out.insert(out.end(), f.body.begin(), f.body.end());
}

Decode decodeFrame(std::span<const std::uint8_t> buf,
                   Frame& out,
                   std::size_t& consumed) noexcept
{
    consumed = 0;
    if (buf.size() < kHeaderSize) return Decode::NeedMore;

    const std::uint32_t bodyLen = rd_u32(buf.data() + kOffBodyLen);
    const std::uint16_t rawOp   = rd_u16(buf.data() + kOffOp);
    const std::uint16_t rawSt   = rd_u16(buf.data() + kOffStatus);

    // Check the declared length BEFORE waiting for more bytes. A peer that
    // announces a 4 GiB body must be rejected immediately, not buffered until it
    // arrives -- that is the shape of a trivial memory-exhaustion attack against
    // a root process.
    if (bodyLen > kMaxBodyBytes) return Decode::Malformed;

    // An unknown opcode is fatal rather than skippable. Both halves ship together;
    // an opcode this build does not know means the peer is not the agent we
    // installed, and quietly ignoring it would let a hostile peer probe for one
    // that IS handled.
    if (!isKnownOp(rawOp)) return Decode::Malformed;

    // The 64-bit sum cannot wrap: both operands are bounded well under 2^32 and
    // std::size_t is 64-bit on every target this runs on. Kept explicit anyway so
    // the bound is checked rather than assumed.
    const std::uint64_t need = static_cast<std::uint64_t>(kHeaderSize)
                             + static_cast<std::uint64_t>(bodyLen);
    if (static_cast<std::uint64_t>(buf.size()) < need) return Decode::NeedMore;

    out.op     = static_cast<Op>(rawOp);
    out.status = static_cast<Status>(rawSt);
    out.tag    = rd_u64(buf.data() + kOffTag);
    out.body.assign(buf.begin() + static_cast<std::ptrdiff_t>(kHeaderSize),
                    buf.begin() + static_cast<std::ptrdiff_t>(need));
    consumed = static_cast<std::size_t>(need);
    return Decode::Ok;
}

// ---------------------------------------------------------------------------
// bodies
// ---------------------------------------------------------------------------

void encodeHello(const HelloBody& h, std::vector<std::uint8_t>& out)
{
    std::uint8_t* p = extend(out, kHelloBodySize);
    wr_u32(p + 0, h.protocolVersion);
    wr_u32(p + 4, h.pid);
    wr_u32(p + 8, h.euid);
}

bool decodeHello(std::span<const std::uint8_t> b, HelloBody& h) noexcept
{
    if (b.size() < kHelloBodySize) return false;
    h.protocolVersion = rd_u32(b.data() + 0);
    h.pid             = rd_u32(b.data() + 4);
    h.euid            = rd_u32(b.data() + 8);
    return true;
}

void encodeOpen(const OpenBody& o, std::vector<std::uint8_t>& out)
{
    std::uint8_t* p = extend(out, kOpenBodySize);
    wr_u32(p + 0, o.locationId);
    wr_u8 (p + 4, o.configValue);
    p[5] = p[6] = p[7] = 0;
}

bool decodeOpen(std::span<const std::uint8_t> b, OpenBody& o) noexcept
{
    if (b.size() < kOpenBodySize) return false;
    o.locationId  = rd_u32(b.data() + 0);
    o.configValue = rd_u8 (b.data() + 4);
    return true;
}

void encodePipeTable(const PipeTable& t, std::vector<std::uint8_t>& out)
{
    const std::size_t n = t.endpoints.size() < kMaxEndpoints ? t.endpoints.size() : kMaxEndpoints;
    std::uint8_t* p = extend(out, kPipeTableHeaderSize + n * kEpEntrySize);
    wr_u32(p + 0, t.generation);
    wr_u16(p + 4, static_cast<std::uint16_t>(n));
    wr_u16(p + 6, 0);
    std::uint8_t* e = p + kPipeTableHeaderSize;
    for (std::size_t i = 0; i < n; ++i, e += kEpEntrySize) {
        const EpEntry& ep = t.endpoints[i];
        wr_u8 (e + 0, ep.address);
        wr_u8 (e + 1, ep.type);
        wr_u16(e + 2, ep.maxPacketSize);
        wr_u8 (e + 4, ep.interval);
        wr_u8 (e + 5, ep.maxBurst);
        wr_u8 (e + 6, ep.interfaceNumber);
        wr_u8 (e + 7, ep.altSetting);
    }
}

bool decodePipeTable(std::span<const std::uint8_t> b, PipeTable& t)
{
    if (b.size() < kPipeTableHeaderSize) return false;
    const std::uint32_t gen   = rd_u32(b.data() + 0);
    const std::uint16_t count = rd_u16(b.data() + 4);

    if (count > kMaxEndpoints) return false;

    // The count is checked against the bytes actually present before a single
    // element is read, so a large count on a short buffer cannot walk off the end.
    const std::size_t need = kPipeTableHeaderSize + static_cast<std::size_t>(count) * kEpEntrySize;
    if (b.size() < need) return false;

    t.generation = gen;
    t.endpoints.clear();
    t.endpoints.reserve(count);
    const std::uint8_t* e = b.data() + kPipeTableHeaderSize;
    for (std::uint16_t i = 0; i < count; ++i, e += kEpEntrySize) {
        EpEntry ep;
        ep.address         = rd_u8 (e + 0);
        ep.type            = rd_u8 (e + 1);
        ep.maxPacketSize   = rd_u16(e + 2);
        ep.interval        = rd_u8 (e + 4);
        ep.maxBurst        = rd_u8 (e + 5);
        ep.interfaceNumber = rd_u8 (e + 6);
        ep.altSetting      = rd_u8 (e + 7);
        if (ep.type > static_cast<std::uint8_t>(XferType::Interrupt)) return false;
        t.endpoints.push_back(ep);
    }
    return true;
}

void encodeXferReq(const XferReq& r,
                   std::span<const std::uint8_t> payload,
                   std::vector<std::uint8_t>& out)
{
    std::uint8_t* p = extend(out, kXferReqSize);
    wr_u32(p + 0,  r.generation);
    wr_u32(p + 4,  r.timeoutMs);
    wr_u32(p + 8,  r.length);
    wr_u8 (p + 12, r.epAddr);
    p[13] = p[14] = p[15] = 0;
    if (!payload.empty()) out.insert(out.end(), payload.begin(), payload.end());
}

bool decodeXferReq(std::span<const std::uint8_t> b,
                   XferPayload expect,
                   XferReq& r,
                   std::span<const std::uint8_t>& payload) noexcept
{
    if (b.size() < kXferReqSize) return false;
    r.generation = rd_u32(b.data() + 0);
    r.timeoutMs  = rd_u32(b.data() + 4);
    r.length     = rd_u32(b.data() + 8);
    r.epAddr     = rd_u8 (b.data() + 12);

    if (r.length > kMaxTransferBytes) return false;

    payload = b.subspan(kXferReqSize);

    // The declared length and the bytes actually present must agree EXACTLY, in
    // both directions. An earlier version let a zero length pass with a non-empty
    // payload; a fuzz run found it. The failure mode that would have caused is a
    // transfer whose length the daemon reads from one place and whose bytes it
    // reads from another.
    switch (expect) {
        case XferPayload::None:
            if (!payload.empty()) return false;
            break;
        case XferPayload::Present:
            if (payload.size() != r.length) return false;
            break;
    }
    return true;
}

void encodeEpRef(const EpRef& r, std::vector<std::uint8_t>& out)
{
    std::uint8_t* p = extend(out, kEpRefSize);
    wr_u32(p + 0, r.generation);
    wr_u8 (p + 4, r.epAddr);
    p[5] = p[6] = p[7] = 0;
}

bool decodeEpRef(std::span<const std::uint8_t> b, EpRef& r) noexcept
{
    if (b.size() < kEpRefSize) return false;
    r.generation = rd_u32(b.data() + 0);
    r.epAddr     = rd_u8 (b.data() + 4);
    return true;
}

void encodeActualLen(std::uint32_t actualLen, std::vector<std::uint8_t>& out)
{
    std::uint8_t* p = extend(out, kActualLenSize);
    wr_u32(p + 0, actualLen);
    wr_u32(p + 4, 0);
}

bool decodeActualLen(std::span<const std::uint8_t> b, std::uint32_t& actualLen) noexcept
{
    if (b.size() < kActualLenSize) return false;
    actualLen = rd_u32(b.data());
    return actualLen <= kMaxTransferBytes;
}

} // namespace airusb::macos::ipc
