#include "UdecxIpc.h"

#include <cstring>

namespace airusb::windows::ipc {

namespace {

// The envelope, on every record:
//
//   0  u32 length     total bytes, header included. EXACT, never "at least".
//   4  u16 version
//   6  u16 opcode
//
// The length is written last, once the body is known, so it can never describe
// a body that was not produced.
constexpr std::size_t kEnvelope = 8;

void put8 (std::vector<std::uint8_t>& v, std::uint8_t x) { v.push_back(x); }

void put16(std::vector<std::uint8_t>& v, std::uint16_t x)
{
    v.push_back(static_cast<std::uint8_t>(x));
    v.push_back(static_cast<std::uint8_t>(x >> 8));
}

void put32(std::vector<std::uint8_t>& v, std::uint32_t x)
{
    for (int i = 0; i < 4; ++i) v.push_back(static_cast<std::uint8_t>(x >> (8 * i)));
}

void put64(std::vector<std::uint8_t>& v, std::uint64_t x)
{
    for (int i = 0; i < 8; ++i) v.push_back(static_cast<std::uint8_t>(x >> (8 * i)));
}

std::uint16_t rd16(const std::uint8_t* p) noexcept
{
    return static_cast<std::uint16_t>(p[0] | (static_cast<std::uint16_t>(p[1]) << 8));
}

std::uint32_t rd32(const std::uint8_t* p) noexcept
{
    return static_cast<std::uint32_t>(p[0])
         | (static_cast<std::uint32_t>(p[1]) << 8)
         | (static_cast<std::uint32_t>(p[2]) << 16)
         | (static_cast<std::uint32_t>(p[3]) << 24);
}

std::uint64_t rd64(const std::uint8_t* p) noexcept
{
    std::uint64_t v = 0;
    for (int i = 7; i >= 0; --i) v = (v << 8) | p[static_cast<std::size_t>(i)];
    return v;
}

void beginRecord(std::vector<std::uint8_t>& v, Opcode op)
{
    v.clear();
    put32(v, 0);                                  // length, patched by endRecord
    put16(v, kVersion);
    put16(v, static_cast<std::uint16_t>(op));
}

void endRecord(std::vector<std::uint8_t>& v)
{
    const std::uint32_t n = static_cast<std::uint32_t>(v.size());
    v[0] = static_cast<std::uint8_t>(n);
    v[1] = static_cast<std::uint8_t>(n >> 8);
    v[2] = static_cast<std::uint8_t>(n >> 16);
    v[3] = static_cast<std::uint8_t>(n >> 24);
}

/// Validates the envelope and hands back the body. The length must match the
/// buffer EXACTLY — trailing bytes are a refusal, not something to ignore,
/// because "ignore the rest" is how two parsers come to disagree about where a
/// record ends.
bool openRecord(std::span<const std::uint8_t> in, Opcode want,
                std::span<const std::uint8_t>& body) noexcept
{
    if (in.size() < kEnvelope) return false;
    if (in.size() > kMaxRecordBytes) return false;
    const std::uint32_t len = rd32(in.data());
    if (len != in.size()) return false;
    if (rd16(in.data() + 4) != kVersion) return false;
    if (rd16(in.data() + 6) != static_cast<std::uint16_t>(want)) return false;
    body = in.subspan(kEnvelope);
    return true;
}

bool allZero(std::span<const std::uint8_t> b) noexcept
{
    for (std::uint8_t x : b) if (x != 0) return false;
    return true;
}

// Body sizes, excluding the envelope and any payload. Spelled out so a field
// added without touching the size is a test failure rather than a silent
// reinterpretation of the next field.
constexpr std::size_t kBodyUrbRequest      = 8 + 4 + 4 + 4 + 4 + 1 + 1 + 1 + 1 + 8 + 4;  // 40
constexpr std::size_t kBodyUrbCompletion   = 8 + 4 + 4 + 2 + 2 + 4 + 4;                  // 28
constexpr std::size_t kBodyConfigureFixed  = 8 + 4 + 4 + 1 + 1 + 1 + 1 + 2 + 2 + 4;      // 28
constexpr std::size_t kBodyConfigureResult = 8 + 4 + 4 + 2 + 2 + 4;                      // 24
constexpr std::size_t kBodyCancel          = 8 + 4 + 4 + 4;                              // 20

} // namespace

// ---------------------------------------------------------------------------

bool isKnown(Result r) noexcept
{
    return static_cast<std::uint16_t>(r) <= static_cast<std::uint16_t>(Result::Failed);
}

const char* resultName(Result r) noexcept
{
    switch (r) {
        case Result::Ok:           return "Ok";
        case Result::Stall:        return "Stall";
        case Result::Canceled:     return "Canceled";
        case Result::Timeout:      return "Timeout";
        case Result::Disconnected: return "Disconnected";
        case Result::Overrun:      return "Overrun";
        case Result::Underrun:     return "Underrun";
        case Result::Protocol:     return "Protocol";
        case Result::Unsupported:  return "Unsupported";
        case Result::Failed:       return "Failed";
    }
    return "?";
}

Status toStatus(Result r) noexcept
{
    switch (r) {
        case Result::Ok:           return Status::Ok;
        case Result::Stall:        return Status::XferStall;
        case Result::Canceled:     return Status::XferCancelled;
        case Result::Timeout:      return Status::XferTimeout;
        case Result::Disconnected: return Status::XferDeviceOffline;
        case Result::Overrun:      return Status::XferOverrun;
        case Result::Underrun:     return Status::XferUnderrun;
        case Result::Protocol:     return Status::XferProtocol;
        case Result::Unsupported:  return Status::UnsupportedMessage;
        case Result::Failed:       return Status::XferUnknown;
    }
    // An unknown value must not become Ok. This is the direction that matters:
    // a status nobody recognises is a failure, not a success.
    return Status::XferUnknown;
}

Result fromStatus(Status s) noexcept
{
    switch (s) {
        case Status::Ok:                 return Result::Ok;
        // A short transfer is NOT decided here. Windows makes the guest say
        // whether short is acceptable, and only the driver holds that flag, so
        // the wire reports success and the driver decides what USBD_STATUS the
        // guest sees. Reporting a failure here would take that choice away.
        case Status::XferShort:          return Result::Ok;
        case Status::XferStall:
        case Status::XferEpStopped:      return Result::Stall;
        case Status::XferCancelled:      return Result::Canceled;
        case Status::XferTimeout:
        case Status::XferNakTimeout:     return Result::Timeout;
        case Status::XferDeviceOffline:
        case Status::DeviceGone:
        case Status::TransportLost:      return Result::Disconnected;
        case Status::XferOverrun:        return Result::Overrun;
        case Status::XferUnderrun:       return Result::Underrun;
        case Status::XferCrc:
        case Status::XferBitstuff:
        case Status::XferBadToggle:
        case Status::XferProtocol:       return Result::Protocol;
        case Status::UnsupportedMessage: return Result::Unsupported;
        default:                         return Result::Failed;
    }
}

// ---------------------------------------------------------------------------

void encode(const UrbRequest& r, std::vector<std::uint8_t>& out)
{
    beginRecord(out, Opcode::UrbRequest);
    put64(out, r.requestId);
    put32(out, r.sessionIncarnation);
    put32(out, r.deviceIncarnation);
    put32(out, r.endpointId);
    put32(out, r.offeredLength);
    put8 (out, static_cast<std::uint8_t>(r.transferType));
    put8 (out, static_cast<std::uint8_t>(r.direction));
    put8 (out, r.endpointAddress);
    put8 (out, r.flags);
    out.insert(out.end(), r.setup, r.setup + 8);
    put32(out, 0);                                  // reserved
    out.insert(out.end(), r.payload.begin(), r.payload.end());
    endRecord(out);
}

bool decode(std::span<const std::uint8_t> in, UrbRequest& out) noexcept
{
    std::span<const std::uint8_t> b;
    if (!openRecord(in, Opcode::UrbRequest, b)) return false;
    if (b.size() < kBodyUrbRequest) return false;

    UrbRequest r;
    const std::uint8_t* p = b.data();
    r.requestId          = rd64(p);      p += 8;
    r.sessionIncarnation = rd32(p);      p += 4;
    r.deviceIncarnation  = rd32(p);      p += 4;
    r.endpointId         = rd32(p);      p += 4;
    r.offeredLength      = rd32(p);      p += 4;
    const std::uint8_t type = *p++;
    const std::uint8_t dir  = *p++;
    r.endpointAddress    = *p++;
    r.flags              = *p++;
    std::memcpy(r.setup, p, 8);          p += 8;
    if (rd32(p) != 0) return false;      // reserved

    if (type > static_cast<std::uint8_t>(TransferType::Interrupt)) return false;
    if (dir  > static_cast<std::uint8_t>(Direction::In))           return false;
    // Every bit we do not define must be zero, or the flag byte becomes a
    // covert field the next version cannot use.
    if ((r.flags & ~static_cast<std::uint8_t>(kFlagShortOk)) != 0) return false;
    r.transferType = static_cast<TransferType>(type);
    r.direction    = static_cast<Direction>(dir);

    if (r.offeredLength > kMaxPayloadBytes) return false;

    const std::size_t payload = b.size() - kBodyUrbRequest;
    if (payload > kMaxPayloadBytes) return false;
    // An IN transfer carries no data down, and an OUT carries exactly what it
    // offered. Anything else is two numbers disagreeing, which is the shape of
    // bug this format is built to make impossible rather than survivable.
    if (r.direction == Direction::In) {
        if (payload != 0) return false;
    } else {
        if (payload != r.offeredLength) return false;
    }
    // A control transfer's setup packet is the only place `setup` is meaningful;
    // a non-control transfer carrying one means the two ends disagree about
    // what this is.
    if (r.transferType != TransferType::Control && !allZero(std::span(r.setup, 8)))
        return false;

    r.payload.assign(b.begin() + static_cast<std::ptrdiff_t>(kBodyUrbRequest), b.end());
    out = std::move(r);
    return true;
}

void encode(const UrbCompletion& r, std::vector<std::uint8_t>& out)
{
    beginRecord(out, Opcode::UrbCompletion);
    put64(out, r.requestId);
    put32(out, r.sessionIncarnation);
    put32(out, r.deviceIncarnation);
    put16(out, static_cast<std::uint16_t>(r.result));
    put16(out, 0);                                  // reserved
    put32(out, r.actualLength);
    put32(out, 0);                                  // reserved
    out.insert(out.end(), r.payload.begin(), r.payload.end());
    endRecord(out);
}

bool decode(std::span<const std::uint8_t> in, UrbCompletion& out) noexcept
{
    std::span<const std::uint8_t> b;
    if (!openRecord(in, Opcode::UrbCompletion, b)) return false;
    if (b.size() < kBodyUrbCompletion) return false;

    UrbCompletion r;
    const std::uint8_t* p = b.data();
    r.requestId          = rd64(p); p += 8;
    r.sessionIncarnation = rd32(p); p += 4;
    r.deviceIncarnation  = rd32(p); p += 4;
    const std::uint16_t res = rd16(p); p += 2;
    if (rd16(p) != 0) return false;                 // reserved
    p += 2;
    r.actualLength = rd32(p); p += 4;
    if (rd32(p) != 0) return false;                 // reserved

    if (!isKnown(static_cast<Result>(res))) return false;
    r.result = static_cast<Result>(res);

    if (r.actualLength > kMaxPayloadBytes) return false;

    const std::size_t payload = b.size() - kBodyUrbCompletion;
    if (payload > kMaxPayloadBytes) return false;
    // The single-length rule. Either the payload IS the actual length, or there
    // is no payload and the transfer went the other way. There is no third
    // reading, so the driver never has to pick which number to trust.
    if (payload != 0 && payload != r.actualLength) return false;

    r.payload.assign(b.begin() + static_cast<std::ptrdiff_t>(kBodyUrbCompletion), b.end());
    out = std::move(r);
    return true;
}

void encode(const Configure& r, std::vector<std::uint8_t>& out)
{
    beginRecord(out, Opcode::Configure);
    put64(out, r.ticketId);
    put32(out, r.sessionIncarnation);
    put32(out, r.deviceIncarnation);
    put8 (out, r.isConfiguration ? 1u : 0u);
    put8 (out, r.configurationValue);
    put8 (out, r.interfaceNumber);
    put8 (out, r.alternateSetting);
    put16(out, static_cast<std::uint16_t>(r.enable.size()));
    put16(out, static_cast<std::uint16_t>(r.release.size()));
    put32(out, 0);                                  // reserved
    for (std::uint32_t id : r.enable)  put32(out, id);
    for (std::uint32_t id : r.release) put32(out, id);
    endRecord(out);
}

bool decode(std::span<const std::uint8_t> in, Configure& out) noexcept
{
    std::span<const std::uint8_t> b;
    if (!openRecord(in, Opcode::Configure, b)) return false;
    if (b.size() < kBodyConfigureFixed) return false;

    Configure r;
    const std::uint8_t* p = b.data();
    r.ticketId           = rd64(p); p += 8;
    r.sessionIncarnation = rd32(p); p += 4;
    r.deviceIncarnation  = rd32(p); p += 4;
    const std::uint8_t isCfg = *p++;
    r.configurationValue = *p++;
    r.interfaceNumber    = *p++;
    r.alternateSetting   = *p++;
    const std::uint16_t nEnable  = rd16(p); p += 2;
    const std::uint16_t nRelease = rd16(p); p += 2;
    if (rd32(p) != 0) return false;                 // reserved

    if (isCfg > 1) return false;                    // a bool is 0 or 1
    r.isConfiguration = isCfg != 0;

    if (nEnable  > kMaxEndpointsPerConfigure) return false;
    if (nRelease > kMaxEndpointsPerConfigure) return false;

    // Counted in elements, checked in bytes, with no multiplication that can
    // wrap: both counts are already bounded above by 32.
    const std::size_t need = static_cast<std::size_t>(nEnable + nRelease) * 4u;
    if (b.size() - kBodyConfigureFixed != need) return false;

    const std::uint8_t* q = b.data() + kBodyConfigureFixed;
    r.enable.reserve(nEnable);
    for (std::uint16_t i = 0; i < nEnable;  ++i) { r.enable.push_back(rd32(q));  q += 4; }
    r.release.reserve(nRelease);
    for (std::uint16_t i = 0; i < nRelease; ++i) { r.release.push_back(rd32(q)); q += 4; }

    // A SET_INTERFACE that names a configuration, or a SET_CONFIGURATION that
    // names an alternate setting, is two ends disagreeing about the transition.
    if (r.isConfiguration) {
        if (r.interfaceNumber != 0 || r.alternateSetting != 0) return false;
    }

    out = std::move(r);
    return true;
}

void encode(const ConfigureResult& r, std::vector<std::uint8_t>& out)
{
    beginRecord(out, Opcode::ConfigureResult);
    put64(out, r.ticketId);
    put32(out, r.sessionIncarnation);
    put32(out, r.deviceIncarnation);
    put16(out, static_cast<std::uint16_t>(r.result));
    put16(out, 0);
    put32(out, 0);
    endRecord(out);
}

bool decode(std::span<const std::uint8_t> in, ConfigureResult& out) noexcept
{
    std::span<const std::uint8_t> b;
    if (!openRecord(in, Opcode::ConfigureResult, b)) return false;
    if (b.size() != kBodyConfigureResult) return false;

    ConfigureResult r;
    const std::uint8_t* p = b.data();
    r.ticketId           = rd64(p); p += 8;
    r.sessionIncarnation = rd32(p); p += 4;
    r.deviceIncarnation  = rd32(p); p += 4;
    const std::uint16_t res = rd16(p); p += 2;
    if (rd16(p) != 0) return false;
    p += 2;
    if (rd32(p) != 0) return false;

    if (!isKnown(static_cast<Result>(res))) return false;
    r.result = static_cast<Result>(res);
    out = r;
    return true;
}

namespace {

void encodeCancelLike(std::vector<std::uint8_t>& out, Opcode op, std::uint64_t requestId,
                      std::uint32_t session, std::uint32_t device)
{
    beginRecord(out, op);
    put64(out, requestId);
    put32(out, session);
    put32(out, device);
    put32(out, 0);
    endRecord(out);
}

bool decodeCancelLike(std::span<const std::uint8_t> in, Opcode op, std::uint64_t& requestId,
                      std::uint32_t& session, std::uint32_t& device) noexcept
{
    std::span<const std::uint8_t> b;
    if (!openRecord(in, op, b)) return false;
    if (b.size() != kBodyCancel) return false;
    const std::uint8_t* p = b.data();
    const std::uint64_t rid = rd64(p); p += 8;
    const std::uint32_t s   = rd32(p); p += 4;
    const std::uint32_t d   = rd32(p); p += 4;
    if (rd32(p) != 0) return false;
    requestId = rid; session = s; device = d;
    return true;
}

} // namespace

void encode(const CancelRequest& r, std::vector<std::uint8_t>& out)
{
    encodeCancelLike(out, Opcode::CancelRequest, r.requestId,
                     r.sessionIncarnation, r.deviceIncarnation);
}

bool decode(std::span<const std::uint8_t> in, CancelRequest& out) noexcept
{
    CancelRequest r;
    if (!decodeCancelLike(in, Opcode::CancelRequest, r.requestId,
                          r.sessionIncarnation, r.deviceIncarnation)) return false;
    out = r;
    return true;
}

void encode(const CancelAck& r, std::vector<std::uint8_t>& out)
{
    encodeCancelLike(out, Opcode::CancelAck, r.requestId,
                     r.sessionIncarnation, r.deviceIncarnation);
}

bool decode(std::span<const std::uint8_t> in, CancelAck& out) noexcept
{
    CancelAck r;
    if (!decodeCancelLike(in, Opcode::CancelAck, r.requestId,
                          r.sessionIncarnation, r.deviceIncarnation)) return false;
    out = r;
    return true;
}

bool peekOpcode(std::span<const std::uint8_t> in, Opcode& out) noexcept
{
    if (in.size() < kEnvelope || in.size() > kMaxRecordBytes) return false;
    if (rd32(in.data()) != in.size()) return false;
    if (rd16(in.data() + 4) != kVersion) return false;
    out = static_cast<Opcode>(rd16(in.data() + 6));
    return true;
}

bool decodeAny(std::span<const std::uint8_t> in) noexcept
{
    Opcode op{};
    if (!peekOpcode(in, op)) return false;
    switch (op) {
        case Opcode::UrbRequest:      { UrbRequest r;      return decode(in, r); }
        case Opcode::UrbCompletion:   { UrbCompletion r;   return decode(in, r); }
        case Opcode::Configure:       { Configure r;       return decode(in, r); }
        case Opcode::ConfigureResult: { ConfigureResult r; return decode(in, r); }
        case Opcode::CancelRequest:   { CancelRequest r;   return decode(in, r); }
        case Opcode::CancelAck:       { CancelAck r;       return decode(in, r); }
    }
    return false;   // an unknown opcode is refused, not skipped
}

} // namespace airusb::windows::ipc
