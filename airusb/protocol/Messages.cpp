#include "Messages.h"

#include "Codec.h"

#include <cstring>

namespace airusb::protocol {

namespace {

std::uint8_t* grow(std::vector<std::uint8_t>& v, std::size_t n)
{
    const std::size_t at = v.size();
    v.resize(at + n);
    return v.data() + at;      // taken AFTER the resize; before it, a realloc dangles
}

} // namespace

// ---------------------------------------------------------------------------
// DEVICE_LIST
// ---------------------------------------------------------------------------

void encodeDeviceList(const std::vector<DeviceRecord>& devices,
                      std::vector<std::uint8_t>& out)
{
    const std::uint32_t n = devices.size() > kMaxListedDevices
                              ? kMaxListedDevices
                              : static_cast<std::uint32_t>(devices.size());

    std::uint8_t* h = grow(out, kBodyDeviceList);
    wr_u32(h + 0, n);
    wr_u32(h + 4, 0);

    for (std::uint32_t i = 0; i < n; ++i) {
        const DeviceRecord& d = devices[i];
        const std::uint16_t nameLen =
            d.name.size() > kMaxDeviceNameLen ? kMaxDeviceNameLen
                                              : static_cast<std::uint16_t>(d.name.size());

        std::uint8_t* r = grow(out, kDeviceRecordFixed + nameLen);
        std::memcpy(r, d.uid.data(), d.uid.size());
        wr_u16(r + 16, d.vendorId);
        wr_u16(r + 18, d.productId);
        wr_u8 (r + 20, d.speed);
        wr_u8 (r + 21, d.flags);
        wr_u16(r + 22, nameLen);
        if (nameLen) std::memcpy(r + kDeviceRecordFixed, d.name.data(), nameLen);
    }
}

bool decodeDeviceList(std::span<const std::uint8_t> body,
                      std::vector<DeviceRecord>& out)
{
    out.clear();
    if (body.size() < kBodyDeviceList) return false;

    const std::uint32_t n = rd_u32(body.data());
    // Bounded before it is used to reserve, so a peer cannot ask for an
    // arbitrary allocation by lying about the count.
    if (n > kMaxListedDevices) return false;

    std::size_t at = kBodyDeviceList;
    out.reserve(n);

    for (std::uint32_t i = 0; i < n; ++i) {
        if (body.size() - at < kDeviceRecordFixed) return false;
        const std::uint8_t* r = body.data() + at;

        DeviceRecord d;
        std::memcpy(d.uid.data(), r, d.uid.size());
        d.vendorId  = rd_u16(r + 16);
        d.productId = rd_u16(r + 18);
        d.speed     = rd_u8 (r + 20);
        d.flags     = rd_u8 (r + 21);
        const std::uint16_t nameLen = rd_u16(r + 22);

        if (nameLen > kMaxDeviceNameLen) return false;
        at += kDeviceRecordFixed;
        if (body.size() - at < nameLen) return false;

        // The name comes from a peer and is displayed. Anything outside
        // printable ASCII is replaced rather than passed through: a device name
        // is not a place to accept control characters or terminal escapes.
        d.name.reserve(nameLen);
        for (std::uint16_t k = 0; k < nameLen; ++k) {
            const std::uint8_t c = body[at + k];
            d.name.push_back((c >= 0x20 && c < 0x7F) ? static_cast<char>(c) : '.');
        }
        at += nameLen;

        if (d.speed > static_cast<std::uint8_t>(Speed::Other)) return false;
        out.push_back(std::move(d));
    }

    // Trailing bytes mean the sender and receiver disagree about the format.
    return at == body.size();
}

// ---------------------------------------------------------------------------
// ATTACH
// ---------------------------------------------------------------------------

void encodeAttach(const AttachBody& b, std::vector<std::uint8_t>& out)
{
    std::uint8_t* p = grow(out, kBodyAttach);
    std::memcpy(p, b.uid.data(), b.uid.size());
    wr_u8 (p + 16, b.exclusivity);
    wr_u8 (p + 17, b.attachSlot);
    wr_u16(p + 18, b.flags);
    wr_u32(p + 20, b.importerMaxTransferBytes);
}

bool decodeAttach(std::span<const std::uint8_t> body, AttachBody& out) noexcept
{
    if (body.size() < kBodyAttach) return false;
    std::memcpy(out.uid.data(), body.data(), out.uid.size());
    out.exclusivity = rd_u8 (body.data() + 16);
    out.attachSlot  = rd_u8 (body.data() + 17);
    out.flags       = rd_u16(body.data() + 18);
    out.importerMaxTransferBytes = rd_u32(body.data() + 20);

    // §3.4: attach_slot is 1..15 because the channel id is (slot << 8) | ep_addr
    // and the field is four bits on the importer's side. Slot 0 is the session
    // control channel and must never be claimed by an attach.
    if (out.attachSlot == 0 || out.attachSlot > 15) return false;

    // Not a negotiation. EXCLUSIVE is the only mode; anything else is a peer
    // asking for something this protocol deliberately cannot express.
    if (out.exclusivity != 1) return false;
    return true;
}

// ---------------------------------------------------------------------------
// ATTACH_OK
// ---------------------------------------------------------------------------

void encodeAttachOk(const AttachOkBody& b, std::vector<std::uint8_t>& out)
{
    std::uint8_t* p = grow(out, kBodyAttachOk);
    std::memset(p, 0, kBodyAttachOk);
    wr_u32(p + 0,  b.attachId);
    wr_u32(p + 4,  b.creditUrbs);
    wr_u32(p + 8,  b.creditBytes);
    wr_u16(p + 12, b.speed);
    wr_u8 (p + 14, b.cancelGranularity);
    wr_u8 (p + 15, b.exporterFlags);
    wr_u32(p + 16, b.deviceLatencyUs);
    wr_u32(p + 20, b.manifestLen);
    wr_u32(p + 24, b.leaseEpoch);
    wr_u32(p + 28, b.urbCeilingMs);
}

bool decodeAttachOk(std::span<const std::uint8_t> body, AttachOkBody& out) noexcept
{
    if (body.size() < kBodyAttachOk) return false;
    out.attachId          = rd_u32(body.data() + 0);
    out.creditUrbs        = rd_u32(body.data() + 4);
    out.creditBytes       = rd_u32(body.data() + 8);
    out.speed             = rd_u16(body.data() + 12);
    out.cancelGranularity = rd_u8 (body.data() + 14);
    out.exporterFlags     = rd_u8 (body.data() + 15);
    out.deviceLatencyUs   = rd_u32(body.data() + 16);
    out.manifestLen       = rd_u32(body.data() + 20);
    out.leaseEpoch        = rd_u32(body.data() + 24);
    out.urbCeilingMs      = rd_u32(body.data() + 28);

    if (out.speed > static_cast<std::uint16_t>(Speed::Other)) return false;
    if (out.manifestLen > wire::kManifestBytesMax) return false;
    if (out.cancelGranularity > 1) return false;
    return true;
}

// ---------------------------------------------------------------------------
// DETACH / DETACH_OK
// ---------------------------------------------------------------------------

bool isKnownDetachReason(std::uint8_t raw) noexcept
{
    return raw >= static_cast<std::uint8_t>(DetachReason::UserRequest)
        && raw <= static_cast<std::uint8_t>(DetachReason::Sleep);
}

void encodeDetach(const DetachBody& b, std::vector<std::uint8_t>& out)
{
    std::uint8_t* p = grow(out, kBodyDetach);
    std::memset(p, 0, kBodyDetach);
    wr_u8 (p + 0, static_cast<std::uint8_t>(b.reason));
    wr_u8 (p + 1, b.dflags);
    wr_u16(p + 2, b.drainTimeoutMs);
}

bool decodeDetach(std::span<const std::uint8_t> body, DetachBody& out) noexcept
{
    if (body.size() < kBodyDetach) return false;
    const std::uint8_t raw = rd_u8(body.data());
    // An unknown reason is refused rather than mapped to a default. The reason
    // decides whether the importer must unmount first, and guessing it wrong
    // either loses data or wedges the attach.
    if (!isKnownDetachReason(raw)) return false;

    out.reason         = static_cast<DetachReason>(raw);
    out.dflags         = rd_u8 (body.data() + 1);
    out.drainTimeoutMs = rd_u16(body.data() + 2);
    return true;
}

void encodeDetachOk(const DetachOkBody& b, std::vector<std::uint8_t>& out)
{
    std::uint8_t* p = grow(out, kBodyDetachOk);
    std::memset(p, 0, kBodyDetachOk);
    wr_u32(p + 0, b.urbsCompleted);
    wr_u32(p + 4, b.urbsCancelled);
    wr_u32(p + 8, b.bytesDropped);
}

bool decodeDetachOk(std::span<const std::uint8_t> body, DetachOkBody& out) noexcept
{
    if (body.size() < kBodyDetachOk) return false;
    out.urbsCompleted = rd_u32(body.data() + 0);
    out.urbsCancelled = rd_u32(body.data() + 4);
    out.bytesDropped  = rd_u32(body.data() + 8);
    return true;
}

// ---------------------------------------------------------------------------
// PING / PONG
// ---------------------------------------------------------------------------

void encodePing(const PingBody& b, std::vector<std::uint8_t>& out)
{
    std::uint8_t* p = grow(out, wire::kBodyPing);
    wr_u64(p + 0,  b.pingTsNs);
    wr_u64(p + 8,  b.echoTsNs);
    wr_u32(p + 16, b.creditUrbsView);
    wr_u32(p + 20, b.creditBytesView);
}

bool decodePing(std::span<const std::uint8_t> body, PingBody& out) noexcept
{
    if (body.size() < wire::kBodyPing) return false;
    out.pingTsNs        = rd_u64(body.data() + 0);
    out.echoTsNs        = rd_u64(body.data() + 8);
    out.creditUrbsView  = rd_u32(body.data() + 16);
    out.creditBytesView = rd_u32(body.data() + 20);
    return true;
}

// ---------------------------------------------------------------------------
// ERROR
// ---------------------------------------------------------------------------

void encodeError(const ErrorBody& b, std::vector<std::uint8_t>& out)
{
    std::uint8_t* p = grow(out, wire::kBodyError);
    wr_u16(p + 0, b.offendingType);
    wr_u16(p + 2, 0);
    wr_u32(p + 4, b.detail);
}

bool decodeError(std::span<const std::uint8_t> body, ErrorBody& out) noexcept
{
    if (body.size() < wire::kBodyError) return false;
    out.offendingType = rd_u16(body.data() + 0);
    out.detail        = rd_u32(body.data() + 4);
    return true;
}

void buildError(std::uint16_t offendingType, Status status,
                std::string_view reason,
                std::vector<std::uint8_t>& out)
{
    std::vector<std::uint8_t> body;
    ErrorBody eb;
    eb.offendingType = offendingType;
    encodeError(eb, body);

    if (!reason.empty()) {
        appendTlv(wire::Tlv::RejectReason,
                  std::span<const std::uint8_t>(
                      reinterpret_cast<const std::uint8_t*>(reason.data()), reason.size()),
                  body);
    }

    Header h;
    h.type    = static_cast<std::uint8_t>(wire::Type::Error);
    h.flags   = wire::kFlagSegFirst | wire::kFlagExpedite;
    h.channel = 0;
    h.status  = static_cast<std::uint16_t>(status);
    h.bodyLen = static_cast<std::uint32_t>(body.size());
    h.totalLen = 0;              // control plane: no segmented data payload

    encodeHeader(h, out);
    out.insert(out.end(), body.begin(), body.end());
}

} // namespace airusb::protocol
