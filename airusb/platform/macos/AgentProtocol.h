// AirUSB Hub — the local IPC between airusb-exportd and airusb-agent.
//
// WHY THIS EXISTS AT ALL
//
// P1_CAPTURE_VERIFICATION.md established that no single macOS process can be both
// root and a member of the console security session, and that the two halves of
// the exporter need one each:
//
//   airusb-exportd  root LaunchDaemon        DiskArbitration unmount + claim,
//                                            IOUSBHostDevice + DeviceCapture,
//                                            lease ownership, ep0 control transfers
//   airusb-agent    console-session Agent    IOUSBHostInterface, copyPipeWithAddress:,
//                   (unprivileged)           bulk and interrupt transfers
//
// So the exporter's data plane crosses a process boundary, and this file is the
// format it crosses in.
//
// WHY IT IS PORTABLE C++ AND NOT OBJECTIVE-C++
//
// It is a parser sitting between a root process and an unprivileged one. That is
// precisely the position from which a length-confusion bug becomes a local
// privilege escalation, so it gets the same treatment protocol/ gets: named offset
// constants, explicit byte loads, no struct overlay, every length checked against
// the buffer actually present, and a libFuzzer target. None of that needs IOKit,
// so it builds and is fuzzed on every platform CI runs on rather than only on the
// machine with the USB stick plugged in.
//
// THREAT MODEL
//
// The socket lives in a root-owned directory. The daemon additionally checks the
// peer's uid with getpeereid(2) and accepts only the console user. This codec
// still assumes nothing about its input: the peer is treated as hostile.

#ifndef AIRUSB_PLATFORM_MACOS_AGENTPROTOCOL_H
#define AIRUSB_PLATFORM_MACOS_AGENTPROTOCOL_H

#include "../../core/Status.h"
#include "../../core/UsbTypes.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace airusb::macos::ipc {

/// Bumped on any incompatible change. The daemon refuses a mismatched agent
/// rather than negotiating: both halves ship in the same bundle and a version
/// skew means a botched install, not a peer to be accommodated.
inline constexpr std::uint32_t kProtocolVersion = 1;

// --- frame header ------------------------------------------------------------

inline constexpr std::size_t kOffBodyLen = 0;   // u32
inline constexpr std::size_t kOffOp      = 4;   // u16
inline constexpr std::size_t kOffStatus  = 6;   // u16
inline constexpr std::size_t kOffTag     = 8;   // u64
inline constexpr std::size_t kHeaderSize = 16;

/// One transfer may carry at most 1 MiB (P1 plan §4.5 maxTransferBytes), plus the
/// fixed request preamble. A frame claiming more is malformed, not merely large.
inline constexpr std::uint32_t kMaxTransferBytes = 1u << 20;
inline constexpr std::uint32_t kMaxBodyBytes     = kMaxTransferBytes + 256u;

/// A device with more than this many endpoints in one configuration is not
/// something this exporter supports; the bound exists so a hostile pipe table
/// cannot force an unbounded allocation.
inline constexpr std::size_t kMaxEndpoints = 32;

enum class Op : std::uint16_t {
    Hello          = 0x0001,  ///< version + identity handshake, agent -> daemon reply
    OpenInterfaces = 0x0002,  ///< open every IOUSBHostInterface, build the pipe table
    RebuildPipes   = 0x0003,  ///< §7.5, after SET_CONFIGURATION / SET_INTERFACE / reset
    BulkOut        = 0x0004,
    BulkIn         = 0x0005,
    ClearHalt      = 0x0006,  ///< -clearStallWithError:, which also clears the toggle
    AbortEndpoint  = 0x0007,  ///< IOUSBHostAbortOptionSynchronous
    Close          = 0x0008,  ///< release pipes and interfaces, keep the socket
    Ping           = 0x0009,
};

bool        isKnownOp(std::uint16_t raw) noexcept;
const char* opName(Op op) noexcept;

struct Frame {
    Op                        op     = Op::Ping;
    Status                    status = Status::Ok;   ///< responses only
    std::uint64_t             tag    = 0;
    std::vector<std::uint8_t> body;
};

void encodeFrame(const Frame& f, std::vector<std::uint8_t>& out);

enum class Decode : std::uint8_t {
    Ok,         ///< one whole frame decoded; `consumed` bytes may be dropped
    NeedMore,   ///< a valid prefix, but the frame is not complete yet
    Malformed,  ///< fatal: close the socket, do not attempt resynchronisation
};

/// Decodes exactly one frame from the front of `buf`.
///
/// There is no streaming parser and no resynchronisation. A frame is either
/// wholly present or it is not, which is what removes the desync failure class
/// entirely rather than handling it.
Decode decodeFrame(std::span<const std::uint8_t> buf,
                   Frame& out,
                   std::size_t& consumed) noexcept;

// --- bodies ------------------------------------------------------------------

struct HelloBody {
    std::uint32_t protocolVersion = kProtocolVersion;
    std::uint32_t pid  = 0;
    std::uint32_t euid = 0;
};
inline constexpr std::size_t kHelloBodySize = 12;

struct OpenBody {
    std::uint32_t locationId  = 0;   ///< IORegistry "locationID", unique per port
    std::uint8_t  configValue = 0;   ///< bConfigurationValue, NOT the index
};
inline constexpr std::size_t kOpenBodySize = 8;

/// One row of the pipe table the agent publishes back to the daemon.
struct EpEntry {
    std::uint8_t  address         = 0;
    std::uint8_t  type            = 0;   ///< airusb::XferType
    std::uint16_t maxPacketSize   = 0;
    std::uint8_t  interval        = 0;
    std::uint8_t  maxBurst        = 0;
    std::uint8_t  interfaceNumber = 0;
    std::uint8_t  altSetting      = 0;
};
inline constexpr std::size_t kEpEntrySize = 8;

struct PipeTable {
    /// Bumped on every rebuild. A transfer carrying a stale generation is failed
    /// with XferEpStopped rather than being issued on a pipe that may now belong
    /// to a different alternate setting (P1 plan §7.5).
    std::uint32_t        generation = 0;
    std::vector<EpEntry> endpoints;
};
inline constexpr std::size_t kPipeTableHeaderSize = 8;

struct XferReq {
    std::uint32_t generation = 0;
    std::uint32_t timeoutMs  = 0;   ///< 0 means no deadline; mandatory for interrupt
    std::uint32_t length     = 0;   ///< OUT: bytes following. IN: bytes offered.
    std::uint8_t  epAddr     = 0;
};
inline constexpr std::size_t kXferReqSize = 16;

struct EpRef {
    std::uint32_t generation = 0;
    std::uint8_t  epAddr     = 0;
};
inline constexpr std::size_t kEpRefSize = 8;

// Encoders append; decoders return false on any malformed input and never read
// past the span they were given.

void encodeHello(const HelloBody&, std::vector<std::uint8_t>& out);
bool decodeHello(std::span<const std::uint8_t>, HelloBody&) noexcept;

void encodeOpen(const OpenBody&, std::vector<std::uint8_t>& out);
bool decodeOpen(std::span<const std::uint8_t>, OpenBody&) noexcept;

void encodePipeTable(const PipeTable&, std::vector<std::uint8_t>& out);
bool decodePipeTable(std::span<const std::uint8_t>, PipeTable&);

/// Whether a transfer request carries its data with it.
///
/// The same fixed header serves both directions, but `length` means different
/// things in each: for BULK_OUT it counts the bytes that follow, for BULK_IN it
/// is the size of the buffer being offered and nothing follows at all. The
/// decoder is told which one to expect rather than inferring it, because the
/// inference has an ambiguous case — a zero length with bytes attached — and an
/// ambiguous case here is a length field and a buffer disagreeing about how much
/// data there is. That disagreement is the CVE-2016-3955 shape. Found by
/// tests/fuzz/fuzz_agentipc.
enum class XferPayload : std::uint8_t {
    None,      ///< BULK_IN: `length` is offered, the body ends after the header
    Present,   ///< BULK_OUT: exactly `length` bytes follow, no more and no fewer
};

/// For BulkOut the payload follows the fixed part; `payload` is a view into the
/// caller's buffer and is valid only as long as it is.
void encodeXferReq(const XferReq&, std::span<const std::uint8_t> payload,
                   std::vector<std::uint8_t>& out);
bool decodeXferReq(std::span<const std::uint8_t>, XferPayload expect, XferReq&,
                   std::span<const std::uint8_t>& payload) noexcept;

void encodeEpRef(const EpRef&, std::vector<std::uint8_t>& out);
bool decodeEpRef(std::span<const std::uint8_t>, EpRef&) noexcept;

/// BulkOut response: how many bytes the device actually accepted.
void encodeActualLen(std::uint32_t actualLen, std::vector<std::uint8_t>& out);
bool decodeActualLen(std::span<const std::uint8_t>, std::uint32_t& actualLen) noexcept;
inline constexpr std::size_t kActualLenSize = 8;

} // namespace airusb::macos::ipc

#endif // AIRUSB_PLATFORM_MACOS_AGENTPROTOCOL_H
