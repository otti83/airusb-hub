#include "Codec.h"

namespace airusb::protocol {

namespace {

/// Append `n` zero bytes and return a pointer to the first of them.
/// Taking the pointer AFTER the resize is required: resize may reallocate.
std::uint8_t* grow(std::vector<std::uint8_t>& out, std::size_t n)
{
    const std::size_t at = out.size();
    out.resize(at + n);
    return out.data() + at;
}

} // namespace

// ---------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------

bool decodeHeader(std::span<const std::uint8_t> in, Header& out) noexcept
{
    if (in.size() < wire::kHeaderSize) return false;
    const std::uint8_t* p = in.data();

    out.type        = rd_u8 (p + wire::kOffType);
    out.flags       = rd_u8 (p + wire::kOffFlags);
    out.channel     = rd_u16(p + wire::kOffChannel);
    out.bodyLen     = rd_u32(p + wire::kOffBodyLen);
    out.attachId    = rd_u32(p + wire::kOffAttachId);
    out.segOffset   = rd_u32(p + wire::kOffSegOffset);
    out.requestId   = rd_u64(p + wire::kOffRequestId);
    out.status      = rd_u16(p + wire::kOffStatus);
    out.deviceEpoch = rd_u16(p + wire::kOffDeviceEpoch);
    out.totalLen    = rd_u32(p + wire::kOffTotalLen);
    return true;
}

void encodeHeader(const Header& h, std::vector<std::uint8_t>& out)
{
    std::uint8_t* p = grow(out, wire::kHeaderSize);

    wr_u8 (p + wire::kOffType,        h.type);
    wr_u8 (p + wire::kOffFlags,       h.flags);
    wr_u16(p + wire::kOffChannel,     h.channel);
    wr_u32(p + wire::kOffBodyLen,     h.bodyLen);
    wr_u32(p + wire::kOffAttachId,    h.attachId);
    wr_u32(p + wire::kOffSegOffset,   h.segOffset);
    wr_u64(p + wire::kOffRequestId,   h.requestId);
    wr_u16(p + wire::kOffStatus,      h.status);
    wr_u16(p + wire::kOffDeviceEpoch, h.deviceEpoch);
    wr_u32(p + wire::kOffTotalLen,    h.totalLen);
}

// ---------------------------------------------------------------------------
// SUBMIT
// ---------------------------------------------------------------------------

bool decodeSubmit(std::span<const std::uint8_t> body, SubmitBody& out) noexcept
{
    if (body.size() < wire::kBodySubmit) return false;
    const std::uint8_t* p = body.data();

    out.epAddr      = rd_u8 (p + wire::kSubOffEpAddr);
    out.xferType    = rd_u8 (p + wire::kSubOffXferType);
    out.dir         = rd_u8 (p + wire::kSubOffDir);
    out.xflags      = rd_u8 (p + wire::kSubOffXFlags);
    out.bufferLen   = rd_u32(p + wire::kSubOffBufferLen);
    out.timeoutMs   = rd_u32(p + wire::kSubOffTimeoutMs);
    out.isoPktCount = rd_u32(p + wire::kSubOffIsoPktCount);
    out.interval    = rd_u32(p + wire::kSubOffInterval);
    out.streamId    = rd_u32(p + wire::kSubOffStreamId);
    std::memcpy(out.setup, p + wire::kSubOffSetup, sizeof(out.setup));
    out.submitTsNs  = rd_u64(p + wire::kSubOffSubmitTsNs);
    return true;
}

void encodeSubmit(const SubmitBody& b, std::vector<std::uint8_t>& out)
{
    std::uint8_t* p = grow(out, wire::kBodySubmit);

    wr_u8 (p + wire::kSubOffEpAddr,      b.epAddr);
    wr_u8 (p + wire::kSubOffXferType,    b.xferType);
    wr_u8 (p + wire::kSubOffDir,         b.dir);
    wr_u8 (p + wire::kSubOffXFlags,      b.xflags);
    wr_u32(p + wire::kSubOffBufferLen,   b.bufferLen);
    wr_u32(p + wire::kSubOffTimeoutMs,   b.timeoutMs);
    wr_u32(p + wire::kSubOffIsoPktCount, b.isoPktCount);
    wr_u32(p + wire::kSubOffInterval,    b.interval);
    wr_u32(p + wire::kSubOffStreamId,    b.streamId);
    std::memcpy(p + wire::kSubOffSetup, b.setup, sizeof(b.setup));
    wr_u64(p + wire::kSubOffSubmitTsNs,  b.submitTsNs);
}

// ---------------------------------------------------------------------------
// COMPLETE
// ---------------------------------------------------------------------------

bool decodeComplete(std::span<const std::uint8_t> body, CompleteBody& out) noexcept
{
    if (body.size() < wire::kBodyComplete) return false;
    const std::uint8_t* p = body.data();

    out.epAddr       = rd_u8 (p + wire::kCplOffEpAddr);
    out.xferType     = rd_u8 (p + wire::kCplOffXferType);
    out.dir          = rd_u8 (p + wire::kCplOffDir);
    out.cflags       = rd_u8 (p + wire::kCplOffCFlags);
    out.requestedLen = rd_u32(p + wire::kCplOffRequestedLen);
    out.actualLen    = rd_u32(p + wire::kCplOffActualLen);
    out.payloadLen   = rd_u32(p + wire::kCplOffPayloadLen);
    out.isoPktCount  = rd_u32(p + wire::kCplOffIsoPktCount);
    out.errorCount   = rd_u32(p + wire::kCplOffErrorCount);
    out.startFrame   = rd_u32(p + wire::kCplOffStartFrame);
    out.reserved     = rd_u32(p + wire::kCplOffReserved);
    out.submitTsNs   = rd_u64(p + wire::kCplOffSubmitTsNs);
    return true;
}

void encodeComplete(const CompleteBody& b, std::vector<std::uint8_t>& out)
{
    std::uint8_t* p = grow(out, wire::kBodyComplete);

    wr_u8 (p + wire::kCplOffEpAddr,       b.epAddr);
    wr_u8 (p + wire::kCplOffXferType,     b.xferType);
    wr_u8 (p + wire::kCplOffDir,          b.dir);
    wr_u8 (p + wire::kCplOffCFlags,       b.cflags);
    wr_u32(p + wire::kCplOffRequestedLen, b.requestedLen);
    wr_u32(p + wire::kCplOffActualLen,    b.actualLen);
    wr_u32(p + wire::kCplOffPayloadLen,   b.payloadLen);
    wr_u32(p + wire::kCplOffIsoPktCount,  b.isoPktCount);
    wr_u32(p + wire::kCplOffErrorCount,   b.errorCount);
    wr_u32(p + wire::kCplOffStartFrame,   b.startFrame);
    wr_u32(p + wire::kCplOffReserved,     b.reserved);
    wr_u64(p + wire::kCplOffSubmitTsNs,   b.submitTsNs);
}

// ---------------------------------------------------------------------------
// HELLO
// ---------------------------------------------------------------------------

bool decodeHello(std::span<const std::uint8_t> body, HelloBody& out) noexcept
{
    if (body.size() < wire::kBodyHello) return false;
    const std::uint8_t* p = body.data();

    out.protoMin      = rd_u16(p + wire::kHelOffProtoMin);
    out.protoMax      = rd_u16(p + wire::kHelOffProtoMax);
    out.caps          = rd_u64(p + wire::kHelOffCaps);
    out.maxTransfer   = rd_u32(p + wire::kHelOffMaxTransfer);
    out.maxRecord     = rd_u32(p + wire::kHelOffMaxRecord);
    out.maxSegment    = rd_u32(p + wire::kHelOffMaxSegment);
    out.maxIsoPackets = rd_u32(p + wire::kHelOffMaxIsoPackets);
    out.maxChannels   = rd_u16(p + wire::kHelOffMaxChannels);
    out.maxLinks      = rd_u16(p + wire::kHelOffMaxLinks);
    out.keepaliveMs   = rd_u32(p + wire::kHelOffKeepaliveMs);
    out.platformId    = rd_u8 (p + wire::kHelOffPlatformId);
    out.roleBits      = rd_u8 (p + wire::kHelOffRoleBits);
    out.reserved      = rd_u16(p + wire::kHelOffReserved);
    std::memcpy(out.sessionId, p + wire::kHelOffSessionId, wire::kSessionIdBytes);
    return true;
}

void encodeHello(const HelloBody& b, std::vector<std::uint8_t>& out)
{
    std::uint8_t* p = grow(out, wire::kBodyHello);

    wr_u16(p + wire::kHelOffProtoMin,      b.protoMin);
    wr_u16(p + wire::kHelOffProtoMax,      b.protoMax);
    wr_u64(p + wire::kHelOffCaps,          b.caps);
    wr_u32(p + wire::kHelOffMaxTransfer,   b.maxTransfer);
    wr_u32(p + wire::kHelOffMaxRecord,     b.maxRecord);
    wr_u32(p + wire::kHelOffMaxSegment,    b.maxSegment);
    wr_u32(p + wire::kHelOffMaxIsoPackets, b.maxIsoPackets);
    wr_u16(p + wire::kHelOffMaxChannels,   b.maxChannels);
    wr_u16(p + wire::kHelOffMaxLinks,      b.maxLinks);
    wr_u32(p + wire::kHelOffKeepaliveMs,   b.keepaliveMs);
    wr_u8 (p + wire::kHelOffPlatformId,    b.platformId);
    wr_u8 (p + wire::kHelOffRoleBits,      b.roleBits);
    wr_u16(p + wire::kHelOffReserved,      b.reserved);
    std::memcpy(p + wire::kHelOffSessionId, b.sessionId, wire::kSessionIdBytes);
}

// ---------------------------------------------------------------------------
// Isochronous packet descriptors
// ---------------------------------------------------------------------------

bool decodeIsoDesc(std::span<const std::uint8_t> in, std::size_t index, IsoDesc& out) noexcept
{
    const std::size_t at = index * wire::kIsoDescSize;
    // Overflow-safe bound: compare against the remaining space, never at + size.
    if (index > in.size() / wire::kIsoDescSize) return false;
    if (in.size() - at < wire::kIsoDescSize) return false;

    const std::uint8_t* p = in.data() + at;
    out.offset       = rd_u32(p + wire::kIsoOffOffset);
    out.length       = rd_u32(p + wire::kIsoOffLength);
    out.actualLength = rd_u32(p + wire::kIsoOffActualLength);
    out.status       = rd_u16(p + wire::kIsoOffStatus);
    out.reserved     = rd_u16(p + wire::kIsoOffReserved);
    return true;
}

void encodeIsoDesc(const IsoDesc& d, std::vector<std::uint8_t>& out)
{
    std::uint8_t* p = grow(out, wire::kIsoDescSize);
    wr_u32(p + wire::kIsoOffOffset,       d.offset);
    wr_u32(p + wire::kIsoOffLength,       d.length);
    wr_u32(p + wire::kIsoOffActualLength, d.actualLength);
    wr_u16(p + wire::kIsoOffStatus,       d.status);
    wr_u16(p + wire::kIsoOffReserved,     d.reserved);
}

// ---------------------------------------------------------------------------
// Preamble
// ---------------------------------------------------------------------------

void encodePreamble(const Preamble& p, std::vector<std::uint8_t>& out)
{
    std::uint8_t* q = grow(out, wire::kPreambleSize);
    std::memcpy(q + wire::kPreOffMagic, wire::kMagic, sizeof(wire::kMagic));
    wr_u8 (q + wire::kPreOffWireMajor, p.wireMajor);
    wr_u8 (q + wire::kPreOffWireMinor, p.wireMinor);
    wr_u16(q + wire::kPreOffFlags,     p.flags);
}

bool decodePreamble(std::span<const std::uint8_t> in, Preamble& out) noexcept
{
    if (in.size() < wire::kPreambleSize) return false;
    if (std::memcmp(in.data() + wire::kPreOffMagic, wire::kMagic, sizeof(wire::kMagic)) != 0)
        return false;

    out.wireMajor = rd_u8 (in.data() + wire::kPreOffWireMajor);
    out.wireMinor = rd_u8 (in.data() + wire::kPreOffWireMinor);
    out.flags     = rd_u16(in.data() + wire::kPreOffFlags);
    return true;
}

// ---------------------------------------------------------------------------
// TLVs
// ---------------------------------------------------------------------------

bool forEachTlv(std::span<const std::uint8_t> in,
                const std::function<bool(const TlvView&)>& fn) noexcept
{
    std::size_t at = 0;
    while (at != in.size()) {
        if (in.size() - at < wire::kTlvHeaderSize) return false;

        TlvView v;
        v.type = rd_u16(in.data() + at + wire::kTlvOffType);
        const std::uint16_t len = rd_u16(in.data() + at + wire::kTlvOffLen);
        at += wire::kTlvHeaderSize;

        if (in.size() - at < len) return false;   // truncated value
        v.value = in.subspan(at, len);
        at += len;

        if (!fn(v)) return false;
    }
    return true;
}

void appendTlv(wire::Tlv type, std::span<const std::uint8_t> value,
               std::vector<std::uint8_t>& out)
{
    std::uint8_t* p = grow(out, wire::kTlvHeaderSize);
    wr_u16(p + wire::kTlvOffType, static_cast<std::uint16_t>(type));
    wr_u16(p + wire::kTlvOffLen,  static_cast<std::uint16_t>(value.size()));
    if (!value.empty()) {
        std::uint8_t* q = grow(out, value.size());
        std::memcpy(q, value.data(), value.size());
    }
}

} // namespace airusb::protocol
