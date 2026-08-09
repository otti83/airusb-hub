// AirUSB Hub — the narrow channel between the window and the privileged broker.
//
// WHAT WAS ARCHITECTURALLY WRONG, AND WHY A PROTOCOL FIXES IT
//
// `airusb-hubd` generated its OWN identity seed and its OWN pin store, ran its
// own `SecureSession`, showed a six-digit number, and recorded the pairing
// itself. Meanwhile `airusb-exportd` and `airusb-vhci` — the two programs that
// actually take a drive away from an operating system and give it to another —
// had a second identity and a second pin store, and paired without ever showing
// anybody anything.
//
// So the ceremony protected the wrong session. A person compared six digits
// belonging to a diagnostic connection, and the connection that really moved a
// filesystem was authorised by a different key that person had never seen. And
// "attach" meant two things: in the window it built a `RemoteDevicePort` and ran
// a read-only probe; in the product it made a kernel enumerate a device.
//
// The fix is a per-machine AUTHORITY that owns the identity, the pins, the
// leases and the OS presentation, and a window that can only PROPOSE. This file
// is the boundary between them, and it is deliberately a small closed set of
// verbs rather than a general remote-call mechanism: an API whose surface is a
// list of nouns can be read in one sitting; one with an escape hatch cannot.
//
// THE THREE RULES THIS FORMAT ENFORCES
//
//  1. **The broker never decides trust.** `Approve` carries a NONCE the broker
//     minted for one specific session, together with the peer fingerprint and
//     the SAS digits that were on screen. The broker refuses a pin whose nonce
//     it did not mint, whose nonce it has already spent, or whose fingerprint
//     and SAS do not match the session that nonce belongs to. A UI that
//     approves "whatever is pending" cannot exist, because there is no verb for
//     it.
//
//  2. **The window never sees a key.** No request or reply carries a private
//     key, a seed, or a raw protocol record. The most powerful thing a
//     compromised window can do is pair with a machine whose six digits it can
//     also see — which is exactly the authority a person at that screen already
//     has, and no more.
//
//  3. **The peer is hostile until the kernel says otherwise.** The transport
//     checks credentials (`getpeereid` on POSIX, the pipe client's token on
//     Windows); this codec assumes nothing regardless. Same treatment as
//     `AgentProtocol` and `UdecxIpc`, for the same reason and with the same
//     fuzzer.
//
// WHAT THIS DOES NOT YET DO, STATED HERE RATHER THAN DISCOVERED LATER
//
// On POSIX the credential check establishes WHICH USER is talking, not WHICH
// PROGRAM. A different process of the same user can open the socket. Closing
// that needs platform machinery this file deliberately does not pretend to
// have — XPC audit tokens and a code requirement on macOS, polkit on Linux, an
// Authenticode check on Windows — and the honest position is that today the
// boundary is "this user", the same boundary the token file already had.

#ifndef AIRUSB_CONTROL_BROKERPROTOCOL_H
#define AIRUSB_CONTROL_BROKERPROTOCOL_H

#include "../core/Status.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace airusb::control::broker {

/// Bumped on any incompatible change. A mismatch is REFUSED, never negotiated:
/// the window and the broker ship together, so a skew is a botched install
/// rather than a peer to accommodate.
inline constexpr std::uint32_t kProtocolVersion = 1;

// --- frame header ----------------------------------------------------------

inline constexpr std::size_t kOffBodyLen = 0;   // u32
inline constexpr std::size_t kOffOp      = 4;   // u16
inline constexpr std::size_t kOffStatus  = 6;   // u16
inline constexpr std::size_t kOffTag     = 8;   // u64
inline constexpr std::size_t kHeaderSize = 16;

/// Nothing on this channel carries USB payload — the broker owns the data path
/// — so the only large thing is a device list. 64 KiB is generous for that and
/// small enough that a hostile length cannot become an allocation.
inline constexpr std::uint32_t kMaxBodyBytes = 64u * 1024u;

inline constexpr std::size_t kMaxDevices    = 64;
inline constexpr std::size_t kMaxStringLen  = 512;
/// The rendered state document. Larger than a string field because it carries
/// the whole device list, and separately capped for exactly that reason: one
/// generous limit shared by every string would be a generous limit on a peer
/// name too.
inline constexpr std::size_t kMaxJsonBytes  = 48u * 1024u;
inline constexpr std::size_t kNonceBytes    = 16;

using Nonce = std::array<std::uint8_t, kNonceBytes>;

enum class Op : std::uint16_t {
    /// Version check and hello. First frame on every connection.
    Attach          = 0x0001,
    /// Everything the window renders, in one reply.
    GetState        = 0x0002,

    ShareStart      = 0x0010,
    ShareStop       = 0x0011,
    /// Answers the six-digit question for an INBOUND peer.
    ShareApprove    = 0x0012,

    ImportConnect   = 0x0020,
    ImportDisconnect= 0x0021,
    /// Answers the six-digit question for an OUTBOUND peer.
    ImportApprove   = 0x0022,
    ImportRefresh   = 0x0023,
    /// PRESENT the device to this machine's operating system. The product verb.
    ImportAttach    = 0x0024,
    ImportDetach    = 0x0025,
    /// The read-only diagnostic probe, which is a DIFFERENT verb on purpose.
    ImportVerify    = 0x0026,
    ImportPing      = 0x0027,

    /// Take a quarantined device back from a peer that stopped answering. The
    /// one operation here that can lose somebody else's data, so it is its own
    /// verb with its own name rather than a flag on detach.
    ForceReclaim    = 0x0030,
};

bool isKnownOp(std::uint16_t raw) noexcept;
const char* opName(Op op) noexcept;

// ---------------------------------------------------------------------------
// Bodies
// ---------------------------------------------------------------------------

/// Op::Attach request.
struct AttachRequest {
    std::uint32_t version = kProtocolVersion;
};

/// Op::Attach reply. `presenter` is the honest name of what this machine can do
/// with a remote device, and the window shows it verbatim — the point being
/// that a build which can only PROBE must never look like one that can present.
struct AttachReply {
    std::uint32_t version = 0;
    std::string   machineName;
    std::string   fingerprint;    ///< THE machine identity, not the window's
    std::string   presenter;      ///< e.g. "linux-vhci", "diagnostic-probe"
    bool          canPresent = false;
};

struct ShareStartRequest {
    std::uint16_t port = 0;
};

struct ImportConnectRequest {
    std::string   host;
    std::uint16_t port = 0;
};

/// The approval, and the reason this protocol exists.
///
/// All three fields are checked against the session the nonce was minted for.
/// A window that has fallen behind — showing the digits of a session that has
/// since been replaced — is refused rather than silently pinning the current
/// one, which is the failure a person at the screen has no way to detect.
struct ApproveRequest {
    Nonce         nonce{};
    std::string   fingerprint;   ///< as displayed
    std::uint32_t sas = 0;       ///< as displayed
    bool          accept = false;
};

struct AttachDeviceRequest {
    std::string uidHex;
};

/// One device, as the window lists it.
struct DeviceEntry {
    std::string   uidHex;
    std::uint16_t vendorId  = 0;
    std::uint16_t productId = 0;
    std::uint8_t  speed     = 0;
    std::uint8_t  flags     = 0;
    std::string   name;
};

/// Everything the window renders. One reply, so the window can never show a
/// half-updated mixture of two moments — which is how the blank-SAS defect
/// (§3.9) was able to exist.
struct StateReply {
    /// The window's state document, rendered BY THE BROKER.
    ///
    /// One renderer, not two. The window is a relay: it passes this to the page
    /// verbatim and computes nothing about trust, capability or lease state.
    /// A second renderer in the window would be a second opinion about what is
    /// true, and the two would diverge exactly where it mattered.
    std::string   json;

    /// Why the request that produced this reply was refused, in the broker's
    /// own words. Empty on success.
    ///
    /// It is carried explicitly rather than left to the status code because the
    /// status is a category and the sentence is the actionable part — "that
    /// answer is for a pairing question that is no longer on screen" and "the
    /// machine on screen is not the machine that is connected" are both
    /// NotPermitted, and they call for different behaviour from the person
    /// reading them. Dropping it produced a 403 with an empty body, which is
    /// exactly the failure that made this field necessary.
    std::string   error;

    std::uint8_t  shareState  = 0;
    std::uint8_t  importState = 0;
    std::uint16_t sharePort   = 0;

    /// The digits currently on offer, and the nonce that authorises answering
    /// them. Zero nonce means there is no question pending, and the window must
    /// then show no number — not a stale one.
    std::uint32_t shareSas = 0;
    Nonce         shareNonce{};
    std::string   sharePeerFingerprint;

    std::uint32_t importSas = 0;
    Nonce         importNonce{};
    std::string   importPeerFingerprint;

    /// Lease state on the SHARING side, so a person can see that a drive is
    /// being held for a machine that went away rather than merely "busy".
    std::uint8_t  leaseState = 0;

    bool          attached   = false;
    std::string   attachedUid;
    std::string   attachedName;
    /// What actually happened to the device: "presented to this computer" or
    /// "opened for diagnostics only". Never inferred by the window.
    std::string   attachedVia;
    std::uint64_t lastRttNs = 0;
    std::string   notice;

    std::vector<DeviceEntry> devices;
};

// ---------------------------------------------------------------------------
// Framing. `encodeFrame` prepends the 16-byte header; `parseFrame` reports the
// header and the body span without copying.
// ---------------------------------------------------------------------------

struct FrameHeader {
    std::uint32_t bodyLen = 0;
    std::uint16_t op      = 0;
    std::uint16_t status  = 0;
    std::uint64_t tag     = 0;
};

void encodeFrame(Op op, Status status, std::uint64_t tag,
                 std::span<const std::uint8_t> body,
                 std::vector<std::uint8_t>& out);

/// Reads a whole frame out of `in`.
///
/// Returns Ok with `consumed` set, Busy when `in` does not yet hold a complete
/// frame, or MalformedFrame — which is FATAL and means close the connection,
/// because a stream whose length prefix is wrong cannot be resynchronised.
Status parseFrame(std::span<const std::uint8_t> in, FrameHeader& h,
                  std::span<const std::uint8_t>& body, std::size_t& consumed) noexcept;

// Every decode returns false on ANY deviation and leaves `out` untouched.
// Nothing is clamped: a clamped length is a length somebody chose for the
// attacker.
void encode(const AttachRequest& r,        std::vector<std::uint8_t>& out);
bool decode(std::span<const std::uint8_t> in, AttachRequest& out) noexcept;
void encode(const AttachReply& r,          std::vector<std::uint8_t>& out);
bool decode(std::span<const std::uint8_t> in, AttachReply& out) noexcept;
void encode(const ShareStartRequest& r,    std::vector<std::uint8_t>& out);
bool decode(std::span<const std::uint8_t> in, ShareStartRequest& out) noexcept;
void encode(const ImportConnectRequest& r, std::vector<std::uint8_t>& out);
bool decode(std::span<const std::uint8_t> in, ImportConnectRequest& out) noexcept;
void encode(const ApproveRequest& r,       std::vector<std::uint8_t>& out);
bool decode(std::span<const std::uint8_t> in, ApproveRequest& out) noexcept;
void encode(const AttachDeviceRequest& r,  std::vector<std::uint8_t>& out);
bool decode(std::span<const std::uint8_t> in, AttachDeviceRequest& out) noexcept;
void encode(const StateReply& r,           std::vector<std::uint8_t>& out);
bool decode(std::span<const std::uint8_t> in, StateReply& out) noexcept;

/// Decodes whatever a frame's opcode says it is, for the fuzzer and for a
/// dispatcher that has not yet switched.
bool decodeAny(std::uint16_t op, std::span<const std::uint8_t> in) noexcept;

} // namespace airusb::control::broker

#endif // AIRUSB_CONTROL_BROKERPROTOCOL_H
