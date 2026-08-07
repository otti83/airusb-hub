#include "Validate.h"

namespace airusb::protocol {

namespace {

constexpr Verdict fail(Rule r, Status s, bool fatal = true) noexcept
{
    Verdict v;
    v.rule   = r;
    v.status = s;
    v.fatal  = fatal;
    return v;
}

} // namespace

const char* ruleName(Rule r) noexcept
{
    switch (r) {
        case Rule::Ok:                   return "ok";
        case Rule::R1_RecordSize:        return "R1_RecordSize";
        case Rule::R2_TotalLen:          return "R2_TotalLen";
        case Rule::R3_BodyLen:           return "R3_BodyLen";
        case Rule::R4_TypeIdentity:      return "R4_TypeIdentity";
        case Rule::R5_ActualLen:         return "R5_ActualLen";
        case Rule::R6_IsoTable:          return "R6_IsoTable";
        case Rule::R7_Utf8Field:         return "R7_Utf8Field";
        case Rule::R8_RequestId:         return "R8_RequestId";
        case Rule::R9_CountCeiling:      return "R9_CountCeiling";
        case Rule::R10_DescriptorOpaque: return "R10_DescriptorOpaque";
        case Rule::R11_Credit:           return "R11_Credit";
        case Rule::R12_DeviceEpoch:      return "R12_DeviceEpoch";
        case Rule::ReservedFlagSet:      return "ReservedFlagSet";
        case Rule::UnknownType:          return "UnknownType";
    }
    return "unknown";
}

// ---------------------------------------------------------------------------

Verdict r1_recordSize(std::uint32_t recordLen, const Limits& lim, bool handshakeDone) noexcept
{
    const std::uint32_t ceiling = handshakeDone ? lim.maxRecordBytes
                                                : wire::kHandshakeRecordMax;
    if (recordLen > ceiling) return fail(Rule::R1_RecordSize, Status::LimitExceeded);
    return Verdict::pass();
}

Verdict r2_totalLen(const Header& h, const Limits& lim) noexcept
{
    if (h.totalLen > lim.maxTransferBytes)
        return fail(Rule::R2_TotalLen, Status::LimitExceeded);

    // seg_offset + data_len <= total_len, computed without overflow.
    if (h.segOffset > h.totalLen)
        return fail(Rule::R2_TotalLen, Status::MalformedFrame);

    return Verdict::pass();
}

Verdict r3_bodyLen(const Header& h, std::size_t availableBody) noexcept
{
    bool known = false;
    const std::size_t fixed = wire::fixedBodySize(h.type, &known);

    if (!known) {
        // Unknown types are skipped via body_len — the forward-compatibility
        // primitive USB/IP lacks. But an unknown DATA-PLANE type is not a future
        // extension we can safely ignore: it would carry transfer semantics.
        if (wire::isDataPlane(h.type))
            return fail(Rule::UnknownType, Status::UnsupportedMessage);
        return Verdict::pass();
    }

    if (h.bodyLen < fixed)
        return fail(Rule::R3_BodyLen, Status::MalformedFrame);

    if (availableBody < h.bodyLen)
        return fail(Rule::R3_BodyLen, Status::MalformedFrame);

    return Verdict::pass();
}

Verdict r4_submitIdentity(const Header& h, const SubmitBody& b) noexcept
{
    // dir must agree with the endpoint address direction bit for non-zero endpoints.
    // ep0 is the exception: `dir` is authoritative there because a control transfer's
    // data direction comes from bmRequestType, not from the endpoint address.
    if ((b.epAddr & 0x0Fu) != 0) {
        const std::uint8_t dirFromAddr = static_cast<std::uint8_t>(b.epAddr >> 7);
        if (b.dir != dirFromAddr)
            return fail(Rule::R4_TypeIdentity, Status::MalformedFrame);
    }

    if (b.dir > 1) return fail(Rule::R4_TypeIdentity, Status::MalformedFrame);
    if (b.xferType > static_cast<std::uint8_t>(wire::XferType::Interrupt))
        return fail(Rule::R4_TypeIdentity, Status::MalformedFrame);

    const bool isIso = b.xferType == static_cast<std::uint8_t>(wire::XferType::Isochronous);
    if (!isIso && b.isoPktCount != 0)
        return fail(Rule::R4_TypeIdentity, Status::MalformedFrame);

    // Exactness rule (§3.5): total_len == iso_pkt_count*16 + (dir==OUT ? buffer_len : 0)
    std::uint64_t expected = static_cast<std::uint64_t>(b.isoPktCount) * wire::kIsoDescSize;
    if (b.dir == static_cast<std::uint8_t>(wire::Dir::Out))
        expected += b.bufferLen;

    if (expected != h.totalLen)
        return fail(Rule::R4_TypeIdentity, Status::MalformedFrame);

    return Verdict::pass();
}

Verdict r4_completeIdentity(const Header& h, const CompleteBody& b) noexcept
{
    if (b.dir > 1) return fail(Rule::R4_TypeIdentity, Status::MalformedFrame);
    if (b.xferType > static_cast<std::uint8_t>(wire::XferType::Interrupt))
        return fail(Rule::R4_TypeIdentity, Status::MalformedFrame);
    if (b.reserved != 0)
        return fail(Rule::R4_TypeIdentity, Status::MalformedFrame);

    const bool isIso = b.xferType == static_cast<std::uint8_t>(wire::XferType::Isochronous);
    if (!isIso && b.isoPktCount != 0)
        return fail(Rule::R4_TypeIdentity, Status::MalformedFrame);

    // The redundancy between payload_len, total_len and data_len is deliberate:
    // three independent statements of one fact, so a mismatch is a fatal protocol
    // error rather than a silently wrong parse.
    std::uint64_t expected = static_cast<std::uint64_t>(b.isoPktCount) * wire::kIsoDescSize;
    expected += b.payloadLen;

    if (expected != h.totalLen)
        return fail(Rule::R4_TypeIdentity, Status::MalformedFrame);

    return Verdict::pass();
}

Verdict r5_actualLen(const CompleteBody& b) noexcept
{
    if (b.actualLen > b.requestedLen)
        return fail(Rule::R5_ActualLen, Status::MalformedFrame);

    const bool isIso = b.xferType == static_cast<std::uint8_t>(wire::XferType::Isochronous);
    if (!isIso) {
        if (b.dir == static_cast<std::uint8_t>(wire::Dir::In)) {
            if (b.payloadLen != b.actualLen)
                return fail(Rule::R5_ActualLen, Status::MalformedFrame);
        } else {
            // OUT carries no USB data back.
            if (b.payloadLen != 0)
                return fail(Rule::R5_ActualLen, Status::MalformedFrame);
        }
    }
    return Verdict::pass();
}

Verdict r6_isoTable(std::span<const std::uint8_t> isoTable,
                    std::uint32_t isoPktCount,
                    std::uint32_t bufferLen,
                    const Limits& lim) noexcept
{
    if (isoPktCount == 0) return Verdict::pass();

    const std::uint32_t ceiling = lim.maxIsoPackets < wire::kIsoPacketsCeiling
                                ? lim.maxIsoPackets : wire::kIsoPacketsCeiling;
    if (isoPktCount > ceiling)
        return fail(Rule::R6_IsoTable, Status::LimitExceeded);

    if (isoTable.size() < static_cast<std::size_t>(isoPktCount) * wire::kIsoDescSize)
        return fail(Rule::R6_IsoTable, Status::MalformedFrame);

    std::uint64_t sum = 0;
    std::uint32_t prevOffset = 0;

    for (std::uint32_t i = 0; i < isoPktCount; ++i) {
        IsoDesc d;
        if (!decodeIsoDesc(isoTable, i, d))
            return fail(Rule::R6_IsoTable, Status::MalformedFrame);

        // offset[i] + length[i] <= buffer_len, computed in 64-bit so the sum
        // cannot wrap into a passing value.
        if (static_cast<std::uint64_t>(d.offset) + d.length > bufferLen)
            return fail(Rule::R6_IsoTable, Status::MalformedFrame);

        if (i > 0 && d.offset < prevOffset)   // offsets non-decreasing
            return fail(Rule::R6_IsoTable, Status::MalformedFrame);

        prevOffset = d.offset;
        sum += d.length;
    }

    if (sum > bufferLen)
        return fail(Rule::R6_IsoTable, Status::MalformedFrame);

    return Verdict::pass();
}

Verdict r7_utf8Field(std::span<const std::uint8_t> field) noexcept
{
    if (field.size() > wire::kUtf8FieldMax)
        return fail(Rule::R7_Utf8Field, Status::LimitExceeded);
    if (!isValidUtf8(field))
        return fail(Rule::R7_Utf8Field, Status::MalformedFrame);
    return Verdict::pass();
}

Verdict r8_requestId(std::uint64_t requestId,
                     std::uint64_t lastSeenOnChannel,
                     bool isCurrentlyOutstanding) noexcept
{
    if (isCurrentlyOutstanding)
        return fail(Rule::R8_RequestId, Status::MalformedFrame);
    if (requestId <= lastSeenOnChannel)
        return fail(Rule::R8_RequestId, Status::MalformedFrame);
    return Verdict::pass();
}

Verdict r9_countCeiling(std::uint32_t count, std::uint32_t ceiling) noexcept
{
    if (count > ceiling) return fail(Rule::R9_CountCeiling, Status::LimitExceeded);
    return Verdict::pass();
}

Verdict r12_deviceEpoch(std::uint16_t received, std::uint16_t expected) noexcept
{
    if (received == expected) return Verdict::pass();

    // Expected after a reset. Drop silently — escalating this to an error would
    // turn every legitimate reset into a session teardown.
    Verdict v;
    v.rule        = Rule::R12_DeviceEpoch;
    v.status      = Status::Ok;
    v.fatal       = false;
    v.silentDrop  = true;
    return v;
}

Verdict reservedFlags(const Header& h) noexcept
{
    if ((h.flags & wire::kFlagReservedMask) == 0) return Verdict::pass();

    // MBZ bits set. On data-plane types this is fatal: a flag we do not understand
    // may change transfer semantics, and proceeding would corrupt the transfer.
    if (wire::isDataPlane(h.type))
        return fail(Rule::ReservedFlagSet, Status::MalformedFrame);

    return Verdict::pass();   // tolerated (ignored) on non-data-plane types
}

// ---------------------------------------------------------------------------

Verdict validateHeader(const Header& h, std::size_t availableBody, const Limits& lim) noexcept
{
    if (Verdict v = reservedFlags(h); !v.ok()) return v;
    if (Verdict v = r2_totalLen(h, lim);  !v.ok()) return v;
    if (Verdict v = r3_bodyLen(h, availableBody); !v.ok()) return v;

    // Requests must carry status 0; a non-zero status on a request is a peer that
    // has confused its own request and response paths.
    if (h.status != 0) {
        const bool isResponse = h.type == static_cast<std::uint8_t>(wire::Type::Complete)
                             || h.type == static_cast<std::uint8_t>(wire::Type::HelloOk)
                             || h.type == static_cast<std::uint8_t>(wire::Type::AttachOk)
                             || h.type == static_cast<std::uint8_t>(wire::Type::DetachOk)
                             || h.type == static_cast<std::uint8_t>(wire::Type::CancelAck)
                             || h.type == static_cast<std::uint8_t>(wire::Type::CtrlAck)
                             || h.type == static_cast<std::uint8_t>(wire::Type::Error)
                             || h.type == static_cast<std::uint8_t>(wire::Type::PairResult)
                             || h.type == static_cast<std::uint8_t>(wire::Type::DeviceGone)
                             || h.type == static_cast<std::uint8_t>(wire::Type::Pong);
        if (!isResponse)
            return fail(Rule::R4_TypeIdentity, Status::MalformedFrame);
    }

    // TransportLost is local-only and must never appear on the wire.
    if (!isWireLegal(static_cast<Status>(h.status)))
        return fail(Rule::R4_TypeIdentity, Status::MalformedFrame);

    return Verdict::pass();
}

Verdict validateSubmit(const Header& h,
                       const SubmitBody& b,
                       std::span<const std::uint8_t> dataSection,
                       const Limits& lim) noexcept
{
    if (Verdict v = r4_submitIdentity(h, b); !v.ok()) return v;

    if (b.bufferLen > lim.maxTransferBytes)
        return fail(Rule::R2_TotalLen, Status::LimitExceeded);

    const bool isIso = b.xferType == static_cast<std::uint8_t>(wire::XferType::Isochronous);
    if (isIso) {
        if (Verdict v = r6_isoTable(dataSection, b.isoPktCount, b.bufferLen, lim); !v.ok())
            return v;
    }

    if (b.streamId != 0)   // v1 carries no USB3 streams
        return fail(Rule::R4_TypeIdentity, Status::UnsupportedMessage);

    return Verdict::pass();
}

Verdict validateComplete(const Header& h,
                         const CompleteBody& b,
                         std::span<const std::uint8_t> dataSection,
                         const Limits& lim) noexcept
{
    if (Verdict v = r4_completeIdentity(h, b); !v.ok()) return v;
    if (Verdict v = r5_actualLen(b);           !v.ok()) return v;

    const bool isIso = b.xferType == static_cast<std::uint8_t>(wire::XferType::Isochronous);
    if (isIso) {
        if (Verdict v = r6_isoTable(dataSection, b.isoPktCount, b.requestedLen, lim); !v.ok())
            return v;
    }
    return Verdict::pass();
}

// ---------------------------------------------------------------------------

bool isValidUtf8(std::span<const std::uint8_t> s) noexcept
{
    std::size_t i = 0;
    while (i < s.size()) {
        const std::uint8_t c = s[i];

        if (c == 0x00) return false;            // never NUL-terminated on the wire

        std::size_t   extra = 0;
        std::uint32_t cp    = 0;
        std::uint32_t min   = 0;

        if (c < 0x80)                    { ++i; continue; }
        else if ((c & 0xE0u) == 0xC0u)   { extra = 1; cp = c & 0x1Fu; min = 0x80; }
        else if ((c & 0xF0u) == 0xE0u)   { extra = 2; cp = c & 0x0Fu; min = 0x800; }
        else if ((c & 0xF8u) == 0xF0u)   { extra = 3; cp = c & 0x07u; min = 0x10000; }
        else                             { return false; }   // 0x80-0xBF lead, or 0xF8+

        if (s.size() - i - 1 < extra) return false;          // truncated sequence

        for (std::size_t k = 1; k <= extra; ++k) {
            const std::uint8_t cc = s[i + k];
            if ((cc & 0xC0u) != 0x80u) return false;         // bad continuation
            cp = (cp << 6) | (cc & 0x3Fu);
        }

        if (cp < min)                        return false;   // overlong
        if (cp > 0x10FFFF)                   return false;   // out of range
        if (cp >= 0xD800 && cp <= 0xDFFF)    return false;   // surrogate

        i += extra + 1;
    }
    return true;
}

} // namespace airusb::protocol
