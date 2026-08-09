// AirUSB Hub — message encode/decode (P1 plan §3.2, §3.5, §3.6)
//
// Explicit byte loads and stores only. No struct overlay, no reinterpret_cast onto
// the wire: coalesced messages inside one record start at arbitrary alignment, and
// a packed-struct overlay would be both UB-adjacent and endianness-dependent.

#ifndef AIRUSB_PROTOCOL_CODEC_H
#define AIRUSB_PROTOCOL_CODEC_H

#include "Wire.h"
#include "../core/Status.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <span>
#include <vector>

namespace airusb::protocol {

// ---------------------------------------------------------------------------
// Primitive little-endian accessors
// ---------------------------------------------------------------------------

inline std::uint8_t rd_u8(const std::uint8_t* p) noexcept { return p[0]; }

inline std::uint16_t rd_u16(const std::uint8_t* p) noexcept
{
    return static_cast<std::uint16_t>(p[0])
         | static_cast<std::uint16_t>(static_cast<std::uint16_t>(p[1]) << 8);
}

inline std::uint32_t rd_u32(const std::uint8_t* p) noexcept
{
    return static_cast<std::uint32_t>(p[0])
         | (static_cast<std::uint32_t>(p[1]) << 8)
         | (static_cast<std::uint32_t>(p[2]) << 16)
         | (static_cast<std::uint32_t>(p[3]) << 24);
}

inline std::uint64_t rd_u64(const std::uint8_t* p) noexcept
{
    return static_cast<std::uint64_t>(rd_u32(p))
         | (static_cast<std::uint64_t>(rd_u32(p + 4)) << 32);
}

inline void wr_u8(std::uint8_t* p, std::uint8_t v) noexcept { p[0] = v; }

inline void wr_u16(std::uint8_t* p, std::uint16_t v) noexcept
{
    p[0] = static_cast<std::uint8_t>(v);
    p[1] = static_cast<std::uint8_t>(v >> 8);
}

inline void wr_u32(std::uint8_t* p, std::uint32_t v) noexcept
{
    p[0] = static_cast<std::uint8_t>(v);
    p[1] = static_cast<std::uint8_t>(v >> 8);
    p[2] = static_cast<std::uint8_t>(v >> 16);
    p[3] = static_cast<std::uint8_t>(v >> 24);
}

inline void wr_u64(std::uint8_t* p, std::uint64_t v) noexcept
{
    wr_u32(p, static_cast<std::uint32_t>(v));
    wr_u32(p + 4, static_cast<std::uint32_t>(v >> 32));
}

// ---------------------------------------------------------------------------
// Decoded views
// ---------------------------------------------------------------------------

struct Header {
    std::uint8_t  type        = 0;
    std::uint8_t  flags       = 0;
    std::uint16_t channel     = 0;
    std::uint32_t bodyLen     = 0;
    std::uint32_t attachId    = 0;
    std::uint32_t segOffset   = 0;
    std::uint64_t requestId   = 0;
    std::uint16_t status      = 0;
    std::uint16_t deviceEpoch = 0;
    std::uint32_t totalLen    = 0;

    constexpr bool segMore()  const noexcept { return flags & wire::kFlagSegMore; }
    constexpr bool segFirst() const noexcept { return flags & wire::kFlagSegFirst; }
    constexpr bool expedite() const noexcept { return flags & wire::kFlagExpedite; }
    constexpr bool isoTable() const noexcept { return flags & wire::kFlagIsoTable; }
};

struct SubmitBody {
    std::uint8_t  epAddr      = 0;
    std::uint8_t  xferType    = 0;
    std::uint8_t  dir         = 0;
    std::uint8_t  xflags      = 0;
    std::uint32_t bufferLen   = 0;
    std::uint32_t timeoutMs   = 0;
    std::uint32_t isoPktCount = 0;
    std::uint32_t interval    = 0;
    std::uint32_t streamId    = 0;
    std::uint8_t  setup[8]    = {};
    std::uint64_t submitTsNs  = 0;
};

struct CompleteBody {
    std::uint8_t  epAddr       = 0;
    std::uint8_t  xferType     = 0;
    std::uint8_t  dir          = 0;
    std::uint8_t  cflags       = 0;
    std::uint32_t requestedLen = 0;
    std::uint32_t actualLen    = 0;
    std::uint32_t payloadLen   = 0;
    std::uint32_t isoPktCount  = 0;
    std::uint32_t errorCount   = 0;
    std::uint32_t startFrame   = 0;
    std::uint32_t reserved     = 0;
    std::uint64_t submitTsNs   = 0;

    constexpr bool isShort()       const noexcept { return cflags & wire::kCfShort; }
    constexpr bool toggleUnknown() const noexcept { return cflags & wire::kCfToggleUnknown; }
    constexpr bool wasCancelled()  const noexcept { return cflags & wire::kCfWasCancelled; }
    constexpr bool collateral()    const noexcept { return cflags & wire::kCfCollateral; }
};

/// CANCEL (0x42). `scope` says how much the sender means: one request, or every
/// transfer on the endpoint. It is a u8 rather than a bool because ENDPOINT scope
/// is the only granularity some exporters can offer — macOS aborts a pipe, not a
/// single transfer — and ATTACH_OK's `cancelGranularity` is what tells the
/// importer which it will get.
enum class CancelScope : std::uint8_t {
    Request  = 0,   ///< the one named request_id
    Endpoint = 1,   ///< every transfer outstanding on ep_addr; target id ignored
};

struct CancelBody {
    std::uint64_t targetRequestId = 0;
    std::uint8_t  epAddr          = 0;
    std::uint8_t  scope           = 0;   ///< CancelScope
    std::uint16_t reserved        = 0;   ///< MBZ
    std::uint32_t reserved2       = 0;   ///< MBZ
};

/// CANCEL_ACK (0x43). `cancelledCount` is how many transfers the exporter
/// actually stopped, which is legitimately zero: a transfer that had already
/// completed on the wire cannot be un-completed, and saying so is more useful
/// than pretending.
struct CancelAckBody {
    std::uint32_t cancelledCount = 0;
    std::uint8_t  granularity    = 0;   ///< the scope actually applied
    std::uint8_t  reserved[3]    = {};  ///< MBZ
};

struct HelloBody {
    std::uint16_t protoMin      = 0;
    std::uint16_t protoMax      = 0;
    std::uint64_t caps          = 0;
    std::uint32_t maxTransfer   = 0;
    std::uint32_t maxRecord     = 0;
    std::uint32_t maxSegment    = 0;
    std::uint32_t maxIsoPackets = 0;
    std::uint16_t maxChannels   = 0;
    std::uint16_t maxLinks      = 0;
    std::uint32_t keepaliveMs   = 0;
    std::uint8_t  platformId    = 0;
    std::uint8_t  roleBits      = 0;
    std::uint16_t reserved      = 0;
    std::uint8_t  sessionId[wire::kSessionIdBytes] = {};
};

struct IsoDesc {
    std::uint32_t offset       = 0;
    std::uint32_t length       = 0;
    std::uint32_t actualLength = 0;
    std::uint16_t status       = 0;
    std::uint16_t reserved     = 0;
};

// ---------------------------------------------------------------------------
// Decode. Each returns false if the input is too short; field-level semantic
// checks live in Validate.h, deliberately separated so the fuzzer can exercise
// each layer independently.
// ---------------------------------------------------------------------------

bool decodeHeader(std::span<const std::uint8_t> in, Header& out) noexcept;
bool decodeSubmit(std::span<const std::uint8_t> body, SubmitBody& out) noexcept;
bool decodeComplete(std::span<const std::uint8_t> body, CompleteBody& out) noexcept;
bool decodeHello(std::span<const std::uint8_t> body, HelloBody& out) noexcept;
bool decodeCancel(std::span<const std::uint8_t> body, CancelBody& out) noexcept;
bool decodeCancelAck(std::span<const std::uint8_t> body, CancelAckBody& out) noexcept;
bool decodeIsoDesc(std::span<const std::uint8_t> in, std::size_t index, IsoDesc& out) noexcept;

// ---------------------------------------------------------------------------
// Encode. Each appends to `out` and returns the number of bytes written.
// ---------------------------------------------------------------------------

void encodeHeader(const Header& h, std::vector<std::uint8_t>& out);
void encodeSubmit(const SubmitBody& b, std::vector<std::uint8_t>& out);
void encodeComplete(const CompleteBody& b, std::vector<std::uint8_t>& out);
void encodeHello(const HelloBody& b, std::vector<std::uint8_t>& out);
void encodeCancel(const CancelBody& b, std::vector<std::uint8_t>& out);
void encodeCancelAck(const CancelAckBody& b, std::vector<std::uint8_t>& out);
void encodeIsoDesc(const IsoDesc& d, std::vector<std::uint8_t>& out);

// ---------------------------------------------------------------------------
// Preamble (L0)
// ---------------------------------------------------------------------------

struct Preamble {
    std::uint8_t  wireMajor = wire::kWireMajor;
    std::uint8_t  wireMinor = wire::kWireMinor;
    std::uint16_t flags     = wire::kSecNoiseXX;
};

void encodePreamble(const Preamble& p, std::vector<std::uint8_t>& out);
bool decodePreamble(std::span<const std::uint8_t> in, Preamble& out) noexcept;

// ---------------------------------------------------------------------------
// TLV walking. Values are borrowed views into the input buffer.
// ---------------------------------------------------------------------------

struct TlvView {
    std::uint16_t                 type = 0;
    std::span<const std::uint8_t> value;
};

/// Iterates TLVs from `in`, invoking `fn(TlvView)`. Returns false on a truncated or
/// self-inconsistent TLV run, so a malformed tail is a decode failure rather than a
/// silently short list.
bool forEachTlv(std::span<const std::uint8_t> in,
                const std::function<bool(const TlvView&)>& fn) noexcept;

void appendTlv(wire::Tlv type, std::span<const std::uint8_t> value,
               std::vector<std::uint8_t>& out);

} // namespace airusb::protocol

#endif // AIRUSB_PROTOCOL_CODEC_H
