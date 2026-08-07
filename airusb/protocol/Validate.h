// AirUSB Hub — receive-side validation rules R1..R12 (P1 plan §3.12)
//
// Every rule is one named function so that each has exactly one unit test and one
// fuzz seed, and so a failure names the rule it violated rather than "malformed".
//
// The load-bearing one is R5. `actual_len <= requested_len` is what stops a buggy
// or hostile exporter from overrunning a kernel transfer buffer whose size the
// importer's own kernel chose. It is checked here AND re-asserted at the copy site
// in the backend, because this layer cannot see the kernel buffer.
// This is the CVE-2016-3955 class of bug.

#ifndef AIRUSB_PROTOCOL_VALIDATE_H
#define AIRUSB_PROTOCOL_VALIDATE_H

#include "Codec.h"
#include "Wire.h"
#include "../core/Status.h"

#include <cstdint>
#include <span>

namespace airusb::protocol {

/// Which rule rejected the message. `Ok` means it passed.
enum class Rule : std::uint8_t {
    Ok = 0,
    R1_RecordSize,
    R2_TotalLen,
    R3_BodyLen,
    R4_TypeIdentity,
    R5_ActualLen,
    R6_IsoTable,
    R7_Utf8Field,
    R8_RequestId,
    R9_CountCeiling,
    R10_DescriptorOpaque,
    R11_Credit,
    R12_DeviceEpoch,
    ReservedFlagSet,
    UnknownType,
};

const char* ruleName(Rule r) noexcept;

/// A rule violation and the status to answer with. `fatal` means: send GOODBYE and
/// close. R12 is the notable non-fatal case — an epoch mismatch is EXPECTED after a
/// reset and must be dropped silently, never escalated.
struct Verdict {
    Rule   rule   = Rule::Ok;
    Status status = Status::Ok;
    bool   fatal  = false;
    bool   silentDrop = false;

    constexpr bool ok() const noexcept { return rule == Rule::Ok; }
    static constexpr Verdict pass() noexcept { return {}; }
};

/// Negotiated limits. Defaults are the pre-HELLO_OK conservative values; after
/// negotiation the session installs the ANDed/min'd values.
struct Limits {
    std::uint32_t maxRecordBytes   = wire::kHandshakeRecordMax;
    std::uint32_t maxTransferBytes = wire::kTransferBytesDefault;
    std::uint32_t maxSegmentBytes  = wire::kSegmentBytesDefault;
    std::uint32_t maxIsoPackets    = 0;            // iso is off unless negotiated
    std::uint16_t maxChannels      = static_cast<std::uint16_t>(wire::kMaxChannels);
};

// ---------------------------------------------------------------------------
// Individual rules
// ---------------------------------------------------------------------------

/// R1 — record length ceiling. `handshakeDone` selects 8 KiB vs the negotiated max.
Verdict r1_recordSize(std::uint32_t recordLen, const Limits& lim, bool handshakeDone) noexcept;

/// R2 — no allocation is ever sized by a single peer field.
Verdict r2_totalLen(const Header& h, const Limits& lim) noexcept;

/// R3 — body_len >= B(type) for known types; also rejects unknown data-plane types.
Verdict r3_bodyLen(const Header& h, std::size_t availableBody) noexcept;

/// R4 — per-type exact-equality identities (§3.5, §3.6). Not an inequality: any
/// other value is a malformed frame, because three independent statements of one
/// fact must agree or the parse is silently wrong somewhere.
Verdict r4_submitIdentity(const Header& h, const SubmitBody& b) noexcept;
Verdict r4_completeIdentity(const Header& h, const CompleteBody& b) noexcept;

/// R5 — actual_len <= requested_len, and on IN payload_len == actual_len.
Verdict r5_actualLen(const CompleteBody& b) noexcept;

/// R6 — isochronous packet table bounds. CVE-2017-16911/16912 class.
Verdict r6_isoTable(std::span<const std::uint8_t> isoTable,
                    std::uint32_t isoPktCount,
                    std::uint32_t bufferLen,
                    const Limits& lim) noexcept;

/// R7 — UTF-8 fields: u16-prefixed, <= 256 bytes, valid UTF-8, never NUL-terminated.
Verdict r7_utf8Field(std::span<const std::uint8_t> field) noexcept;

/// R8 — a new request_id on a channel must be strictly greater than the last seen
/// and not currently outstanding. Reuse of a live request_id is fatal: it is exactly
/// how URB aliasing and response confusion happen.
Verdict r8_requestId(std::uint64_t requestId,
                     std::uint64_t lastSeenOnChannel,
                     bool isCurrentlyOutstanding) noexcept;

/// R9 — every count has a ceiling checked BEFORE the loop that consumes it.
Verdict r9_countCeiling(std::uint32_t count, std::uint32_t ceiling) noexcept;

/// R12 — device_epoch mismatch drops silently; expected after a reset.
Verdict r12_deviceEpoch(std::uint16_t received, std::uint16_t expected) noexcept;

/// Reserved header flag bits are MBZ, and must be rejected on data-plane types.
/// Silently ignoring a flag you do not understand is how you corrupt a transfer.
Verdict reservedFlags(const Header& h) noexcept;

// ---------------------------------------------------------------------------
// Composite entry points
// ---------------------------------------------------------------------------

/// Validates a header in isolation: reserved flags, R2, R3.
Verdict validateHeader(const Header& h, std::size_t availableBody, const Limits& lim) noexcept;

/// Validates a fully-reassembled SUBMIT: header rules, R4, R6, R9.
Verdict validateSubmit(const Header& h,
                       const SubmitBody& b,
                       std::span<const std::uint8_t> dataSection,
                       const Limits& lim) noexcept;

/// Validates a fully-reassembled COMPLETE: header rules, R4, R5.
Verdict validateComplete(const Header& h,
                         const CompleteBody& b,
                         std::span<const std::uint8_t> dataSection,
                         const Limits& lim) noexcept;

/// UTF-8 well-formedness. Rejects overlong encodings, surrogates, > U+10FFFF and
/// embedded NUL — a permissive decoder here becomes a filename/display injection
/// vector at the UI layer.
bool isValidUtf8(std::span<const std::uint8_t> s) noexcept;

} // namespace airusb::protocol

#endif // AIRUSB_PROTOCOL_VALIDATE_H
