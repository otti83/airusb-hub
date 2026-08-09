// AirUSB Hub — the ABI between airusb.sys and the user-mode host.
//
// THE TRUST DIRECTION IS INVERTED FROM EVERYWHERE ELSE IN THIS PROJECT
//
// Everywhere else, we are the privileged side defending against a peer. Here
// the kernel is one end of the channel and an UNPRIVILEGED user process is the
// other, so a length trusted where it should be validated is kernel memory
// corruption reachable from a normal account. That is why this codec exists as
// a separate, portable, fuzzed file rather than as struct casts inside the
// driver: the same reason `UsbipCodec` exists, with worse consequences.
//
// THE MISCONCEPTION THIS FILE WAS REDESIGNED AROUND
//
// The first design had a shared-memory arena, carved into slots by the driver,
// with the host naming a slot index and "never choosing an offset". Reviewed
// against that claim (GPT-5.6, 2026-08-09), it does not hold: once a section is
// mapped writable into a process, slot indices constrain what the PROTOCOL
// accepts, not what memory the host can write. Every arena byte is
// continuously changing, by assumption.
//
// So there is no arena. Payload travels in the IOCTL buffer itself:
// METHOD_OUT_DIRECT for work going down, METHOD_IN_DIRECT for completions
// coming up. The I/O manager probes and locks the pages and hands the driver an
// MDL whose length is authoritative — which deletes, rather than mitigates,
// slot arithmetic, mapping lifetime, stale-slot disclosure and slot quarantine.
// If measurement later shows the copies matter, an arena can be reintroduced
// carrying PAYLOAD ONLY and never metadata.
//
// FIVE RULES THIS FORMAT EXISTS TO ENFORCE
//
//  1. **Identity is more than a request id.** A late completion arriving after
//     a plug-out and re-plug must not land on a fresh request that happens to
//     reuse the number. Every record therefore carries the session incarnation
//     and the device incarnation, and request ids are never reused within a
//     session.
//  2. **Endpoint address is not endpoint identity.** Alternate settings reuse
//     addresses. Endpoints are named by an opaque driver-assigned id; the
//     address rides along for logging only.
//  3. **No raw kernel constants on the wire.** `USBD_STATUS` and USBD transfer
//     flags stay inside the driver. The wire carries a small abstract result
//     enum, so the host cannot express a status/length combination that means
//     nothing, and the ABI does not become Windows-shaped.
//  4. **One length, not two.** A payload length that can disagree with the
//     record length is a bug waiting for someone to check the wrong one. The
//     payload is whatever follows the header, and `actualLength` must equal it
//     for an IN transfer or be zero-payload for an OUT.
//  5. **Reserved bytes are zero and are checked.** They are the version escape
//     hatch, and an unchecked reserved field is a field that silently becomes
//     load-bearing.
//
// WHAT IS DELIBERATELY NOT AN ERROR
//
// A short successful transfer, a zero-length transfer, partial progress
// alongside a failure, and a completion for a request that has already been
// retired are all NORMAL USB lifecycle events, not malformed input. The codec
// decodes them; the state machine above decides. Refusing them as protocol
// violations would make ordinary cancellation look like an attack.

#ifndef AIRUSB_PLATFORM_WINDOWS_UDECXIPC_H
#define AIRUSB_PLATFORM_WINDOWS_UDECXIPC_H

#include "../../core/Status.h"
#include "../../core/UsbTypes.h"

#include <cstdint>
#include <span>
#include <vector>

namespace airusb::windows::ipc {

/// Bumped when a field's meaning changes. A mismatch is refused, never
/// negotiated: the driver and the host ship together.
inline constexpr std::uint16_t kVersion = 1;

/// Bounds, all enforced by the decoder. They exist so a hostile or confused
/// host cannot make the kernel size an allocation from a number it supplied.
inline constexpr std::uint32_t kMaxPayloadBytes   = 1u << 20;   // usb-storage's SuperSpeed URB
inline constexpr std::uint32_t kMaxRecordBytes    = kMaxPayloadBytes + 256;
inline constexpr std::uint32_t kMaxEndpointsPerConfigure = 32;

enum class Opcode : std::uint16_t {
    UrbRequest      = 0x0001,   ///< driver -> host: forward this transfer
    UrbCompletion   = 0x0002,   ///< host -> driver: it finished, or it did not
    Configure       = 0x0003,   ///< driver -> host: a configure transaction
    ConfigureResult = 0x0004,   ///< host -> driver: how it went
    CancelRequest   = 0x0005,   ///< driver -> host: stop caring about this id
    CancelAck       = 0x0006,   ///< host -> driver: nothing of mine touches it now
};

/// The abstract outcome. Small on purpose: the driver maps it to USBD_STATUS
/// using its OWN copy of the transfer flags, so the short-transfer question —
/// which on Windows depends on USBD_SHORT_TRANSFER_OK and therefore on the
/// guest's intent — is never decided by the user-mode process.
enum class Result : std::uint16_t {
    Ok           = 0,
    Stall        = 1,
    Canceled     = 2,
    Timeout      = 3,
    Disconnected = 4,
    Overrun      = 5,
    Underrun     = 6,
    Protocol     = 7,   ///< babble, toggle, PID — the device misbehaved
    Unsupported  = 8,
    Failed       = 9,   ///< anything else; never silently success
};

bool isKnown(Result r) noexcept;
const char* resultName(Result r) noexcept;

/// Result -> Status, for the driver side. Never maps to Ok by accident: an
/// unknown value becomes a failure.
Status toStatus(Result r) noexcept;
Result fromStatus(Status s) noexcept;

// ---------------------------------------------------------------------------

enum class TransferType : std::uint8_t { Control = 0, Bulk = 1, Interrupt = 2 };
enum class Direction    : std::uint8_t { Out = 0, In = 1 };

/// W1's own flags. NOT `USBD_*`: the driver translates, so the host neither
/// sees nor can forge a kernel constant.
enum Flags : std::uint8_t {
    kFlagShortOk = 1u << 0,   ///< the guest set USBD_SHORT_TRANSFER_OK
};

struct UrbRequest {
    std::uint64_t requestId          = 0;   ///< never reused within a session
    std::uint32_t sessionIncarnation = 0;   ///< random, per host binding
    std::uint32_t deviceIncarnation  = 0;   ///< bumped on every plug-in
    std::uint32_t endpointId         = 0;   ///< opaque; NOT the address
    std::uint32_t offeredLength      = 0;   ///< what the guest offered
    TransferType  transferType       = TransferType::Bulk;
    Direction     direction          = Direction::Out;   ///< driver-derived, canonical
    std::uint8_t  endpointAddress    = 0;   ///< logging only
    std::uint8_t  flags              = 0;
    std::uint8_t  setup[8]           = {};  ///< control only; zero otherwise
    /// OUT bytes. Empty for IN. Copied by the driver BEFORE the request is
    /// parked, because the MDL is only valid while the request is held.
    std::vector<std::uint8_t> payload;
};

struct UrbCompletion {
    std::uint64_t requestId          = 0;
    std::uint32_t sessionIncarnation = 0;
    std::uint32_t deviceIncarnation  = 0;
    Result        result             = Result::Failed;
    std::uint32_t actualLength       = 0;
    /// IN bytes. For an IN transfer this must be exactly `actualLength` long;
    /// for an OUT it must be empty. Checked, not assumed.
    std::vector<std::uint8_t> payload;
};

/// A configure transaction, which is NOT a simple acknowledgement.
///
/// UdeCx hands the driver a WDFREQUEST naming the endpoints to bring up and the
/// endpoints being released, and the driver must have queues attached to the
/// new ones before completing it. Modelling that as "resolve a ticket" loses
/// the two sets, and the released set is the one that matters: using a released
/// endpoint's queue afterwards is a use-after-free with a kernel object.
struct Configure {
    std::uint64_t ticketId           = 0;
    std::uint32_t sessionIncarnation = 0;
    std::uint32_t deviceIncarnation  = 0;
    /// True for a SET_CONFIGURATION, false for a SET_INTERFACE.
    bool          isConfiguration    = false;
    std::uint8_t  configurationValue = 0;
    std::uint8_t  interfaceNumber    = 0;
    std::uint8_t  alternateSetting   = 0;
    std::vector<std::uint32_t> enable;    ///< opaque endpoint ids
    std::vector<std::uint32_t> release;   ///< opaque endpoint ids
};

struct ConfigureResult {
    std::uint64_t ticketId           = 0;
    std::uint32_t sessionIncarnation = 0;
    std::uint32_t deviceIncarnation  = 0;
    Result        result             = Result::Failed;
};

/// Cancel is a notification, never a prerequisite.
///
/// The driver completes the guest's URB the moment cancellation wins; it does
/// not wait for the far side. `CancelAck` says only that the host's worker has
/// stopped touching that id, which lets the driver retire its bookkeeping —
/// and a host that never sends one must not be able to wedge anything.
struct CancelRequest {
    std::uint64_t requestId          = 0;
    std::uint32_t sessionIncarnation = 0;
    std::uint32_t deviceIncarnation  = 0;
};

struct CancelAck {
    std::uint64_t requestId          = 0;
    std::uint32_t sessionIncarnation = 0;
    std::uint32_t deviceIncarnation  = 0;
};

// ---------------------------------------------------------------------------
// Encoding. Every field is written as an explicit little-endian fixed-width
// value; nothing is ever a struct cast. Padding, alignment, enum width and
// unaligned access all differ between the compilers that build the two ends.
// ---------------------------------------------------------------------------

void encode(const UrbRequest& r,      std::vector<std::uint8_t>& out);
void encode(const UrbCompletion& r,   std::vector<std::uint8_t>& out);
void encode(const Configure& r,       std::vector<std::uint8_t>& out);
void encode(const ConfigureResult& r, std::vector<std::uint8_t>& out);
void encode(const CancelRequest& r,   std::vector<std::uint8_t>& out);
void encode(const CancelAck& r,       std::vector<std::uint8_t>& out);

/// Reads the opcode without committing to a body. Returns false if the record
/// is not even a well-formed envelope.
bool peekOpcode(std::span<const std::uint8_t> in, Opcode& out) noexcept;

// Every decode returns false on ANY deviation and leaves `out` untouched:
// wrong version, wrong length for the opcode, a reserved byte that is not
// zero, an enum outside its range, a payload that disagrees with the header,
// or a count past its cap. Nothing is clamped, because a clamped length is a
// length somebody chose for the attacker.
bool decode(std::span<const std::uint8_t> in, UrbRequest& out) noexcept;
bool decode(std::span<const std::uint8_t> in, UrbCompletion& out) noexcept;
bool decode(std::span<const std::uint8_t> in, Configure& out) noexcept;
bool decode(std::span<const std::uint8_t> in, ConfigureResult& out) noexcept;
bool decode(std::span<const std::uint8_t> in, CancelRequest& out) noexcept;
bool decode(std::span<const std::uint8_t> in, CancelAck& out) noexcept;

/// Decodes whatever the buffer holds, for the fuzzer and for a dispatcher that
/// has not yet switched on the opcode.
bool decodeAny(std::span<const std::uint8_t> in) noexcept;

} // namespace airusb::windows::ipc

#endif // AIRUSB_PLATFORM_WINDOWS_UDECXIPC_H
