// AirUSB Hub — AirUSB/1 wire format (P1 plan §3)
//
// Every offset and width is a named constant with a static_assert. There is
// deliberately NO struct overlay anywhere in this protocol: message coalescing
// inside a record makes message starts arbitrarily aligned, so all access goes
// through explicit byte loads/stores in Encode/Decode. That also keeps the code
// correct on a hypothetical big-endian host.
//
// Little-endian everywhere. USB itself is little-endian (wValue/wIndex/wLength and
// every descriptor field), and all three target platforms are little-endian.
// USB/IP's 48-byte big-endian header forces a byteswap of every field on every host
// and buys nothing.

#ifndef AIRUSB_PROTOCOL_WIRE_H
#define AIRUSB_PROTOCOL_WIRE_H

#include <cstddef>
#include <cstdint>

namespace airusb::wire {

// ---------------------------------------------------------------------------
// L0 — connection preamble (plaintext, 8 bytes, both directions)
// ---------------------------------------------------------------------------

inline constexpr std::uint8_t  kMagic[4]      = {'A', 'U', 'S', 'B'};
inline constexpr std::size_t   kPreambleSize  = 8;

inline constexpr std::size_t   kPreOffMagic     = 0;  // 4 bytes
inline constexpr std::size_t   kPreOffWireMajor = 4;  // u8
inline constexpr std::size_t   kPreOffWireMinor = 5;  // u8
inline constexpr std::size_t   kPreOffFlags     = 6;  // u16

inline constexpr std::uint8_t  kWireMajor = 1;
inline constexpr std::uint8_t  kWireMinor = 0;

/// Preamble security-suite flags.
enum PreambleFlags : std::uint16_t {
    kSecNoiseXX  = 1u << 0,   // MUST be set on TCP
    kSecTls13Rpk = 1u << 1,   // reserved for the QUIC transport
};

/// Record framing: u32 length prefix, then the record body.
inline constexpr std::size_t   kRecordLenSize        = 4;
inline constexpr std::uint32_t kHandshakeRecordMax   = 8192;    // R1, before HELLO_OK
inline constexpr std::uint32_t kRecordBytesDefault   = 16640;
inline constexpr std::uint32_t kRecordBytesCeiling   = 65519;   // Noise plaintext limit
inline constexpr std::size_t   kAeadTagSize          = 16;

// ---------------------------------------------------------------------------
// L1 — message header, exactly 32 bytes
// ---------------------------------------------------------------------------

inline constexpr std::size_t kHeaderSize = 32;

inline constexpr std::size_t kOffType        = 0;   // u8
inline constexpr std::size_t kOffFlags       = 1;   // u8
inline constexpr std::size_t kOffChannel     = 2;   // u16
inline constexpr std::size_t kOffBodyLen     = 4;   // u32
inline constexpr std::size_t kOffAttachId    = 8;   // u32
inline constexpr std::size_t kOffSegOffset   = 12;  // u32
inline constexpr std::size_t kOffRequestId   = 16;  // u64
inline constexpr std::size_t kOffStatus      = 24;  // u16
inline constexpr std::size_t kOffDeviceEpoch = 26;  // u16
inline constexpr std::size_t kOffTotalLen    = 28;  // u32

static_assert(kOffTotalLen + 4 == kHeaderSize, "header layout must be exactly 32 bytes");

/// Header flag bits. Bits 4-7 are MBZ and are rejected on data-plane types.
enum HeaderFlags : std::uint8_t {
    kFlagSegMore   = 1u << 0,
    kFlagSegFirst  = 1u << 1,
    kFlagExpedite  = 1u << 2,
    kFlagIsoTable  = 1u << 3,
    kFlagReservedMask = 0xF0u,
};

// ---------------------------------------------------------------------------
// Message types (§3.3)
// ---------------------------------------------------------------------------

enum class Type : std::uint8_t {
    // session
    Hello            = 0x01,
    HelloOk          = 0x02,
    Ping             = 0x03,
    Pong             = 0x04,
    Goodbye          = 0x05,
    Error            = 0x06,
    LinkJoin         = 0x08,  // reserved, Phase 4 multilink
    LinkJoinOk       = 0x09,  // reserved, Phase 4 multilink

    // pairing / inventory
    PairRequest      = 0x10,
    PairConfirm      = 0x11,
    PairResult       = 0x12,
    ListDevices      = 0x13,
    DeviceList       = 0x14,
    DeviceEvent      = 0x15,

    // attach lifecycle
    Attach           = 0x20,
    AttachOk         = 0x21,
    DeviceManifest   = 0x22,
    Detach           = 0x23,
    DetachOk         = 0x24,
    DeviceGone       = 0x25,
    AttachCredit     = 0x26,
    Resume           = 0x28,  // reserved, Phase 4
    ResumeOk         = 0x29,  // reserved, Phase 4
    ResumeRefused    = 0x2A,  // reserved, Phase 4

    // usb control (intercept-and-reissue verbs)
    SetConfiguration = 0x30,
    SetInterface     = 0x31,
    EpClearHalt      = 0x32,
    DeviceReset      = 0x33,
    SuspendIo        = 0x34,
    ResumeIo         = 0x35,
    CtrlAck          = 0x36,

    // data plane
    Submit           = 0x40,
    Complete         = 0x41,
    Cancel           = 0x42,
    CancelAck        = 0x43,
    Data             = 0x44,
};

constexpr bool isDataPlane(std::uint8_t t) noexcept { return t >= 0x40 && t <= 0x4F; }

// ---------------------------------------------------------------------------
// Fixed body sizes B(type). Unknown types have B = 0 and are skipped via body_len —
// the forward-compatibility primitive USB/IP lacks entirely.
// ---------------------------------------------------------------------------

// Spec correction: P1 plan §3.13 lists HELLO's fields and separately states B = 48,
// but the field list sums to 56 (session_id[16] begins at offset 40). Resolved in
// favour of the field list — the 16-byte session id is load-bearing for the Noise
// prologue binding, whereas 48 was an arithmetic slip. B(HELLO) = B(HELLO_OK) = 56.
inline constexpr std::size_t kBodyHello      = 56;
inline constexpr std::size_t kBodyPing       = 24;
inline constexpr std::size_t kBodyError      = 8;
inline constexpr std::size_t kBodySubmit     = 40;
inline constexpr std::size_t kBodyComplete   = 40;
inline constexpr std::size_t kBodyCancel     = 16;
inline constexpr std::size_t kBodyCancelAck  = 8;
inline constexpr std::size_t kBodyData       = 0;

/// Returns the fixed body size for a type, or 0 for types this build does not know.
/// `known` distinguishes "unknown type" from "known type whose body is genuinely 0".
std::size_t fixedBodySize(std::uint8_t type, bool* known) noexcept;

// ---------------------------------------------------------------------------
// SUBMIT (0x40), B = 40  (§3.5)
// ---------------------------------------------------------------------------

inline constexpr std::size_t kSubOffEpAddr      = 0;   // u8
inline constexpr std::size_t kSubOffXferType    = 1;   // u8
inline constexpr std::size_t kSubOffDir         = 2;   // u8
inline constexpr std::size_t kSubOffXFlags      = 3;   // u8
inline constexpr std::size_t kSubOffBufferLen   = 4;   // u32
inline constexpr std::size_t kSubOffTimeoutMs   = 8;   // u32
inline constexpr std::size_t kSubOffIsoPktCount = 12;  // u32
inline constexpr std::size_t kSubOffInterval    = 16;  // u32
inline constexpr std::size_t kSubOffStreamId    = 20;  // u32
inline constexpr std::size_t kSubOffSetup       = 24;  // 8 bytes, verbatim USB SETUP
inline constexpr std::size_t kSubOffSubmitTsNs  = 32;  // u64

static_assert(kSubOffSubmitTsNs + 8 == kBodySubmit, "SUBMIT body must be 40 bytes");

enum SubmitXFlags : std::uint8_t {
    kXfShortNotOk  = 1u << 0,
    kXfZeroPacket  = 1u << 1,
    kXfIsoAsap     = 1u << 2,
};

// ---------------------------------------------------------------------------
// COMPLETE (0x41), B = 40  (§3.6)
//
// A COMPLETE is fully parseable with ZERO state about its SUBMIT. That is the
// direct fix for USB/IP's RET_SUBMIT zeroing direction and endpoint, which makes
// its payload length computable only from client-side per-seqnum state.
// ---------------------------------------------------------------------------

inline constexpr std::size_t kCplOffEpAddr       = 0;   // u8   echoed
inline constexpr std::size_t kCplOffXferType     = 1;   // u8   echoed
inline constexpr std::size_t kCplOffDir          = 2;   // u8   echoed
inline constexpr std::size_t kCplOffCFlags       = 3;   // u8
inline constexpr std::size_t kCplOffRequestedLen = 4;   // u32  echoed buffer_len
inline constexpr std::size_t kCplOffActualLen    = 8;   // u32  bytes moved on the bus
inline constexpr std::size_t kCplOffPayloadLen   = 12;  // u32  USB data bytes carried
inline constexpr std::size_t kCplOffIsoPktCount  = 16;  // u32  echoed
inline constexpr std::size_t kCplOffErrorCount   = 20;  // u32  iso
inline constexpr std::size_t kCplOffStartFrame   = 24;  // u32  iso
inline constexpr std::size_t kCplOffReserved     = 28;  // u32  MBZ
inline constexpr std::size_t kCplOffSubmitTsNs   = 32;  // u64  echoed verbatim

static_assert(kCplOffSubmitTsNs + 8 == kBodyComplete, "COMPLETE body must be 40 bytes");

enum CompleteFlags : std::uint8_t {
    kCfShort         = 1u << 0,
    kCfZlpSent       = 1u << 1,
    kCfWasCancelled  = 1u << 2,
    kCfCollateral    = 1u << 3,
    kCfToggleUnknown = 1u << 4,
};

// ---------------------------------------------------------------------------
// Isochronous packet descriptor, 16 bytes (§3.5)
// ---------------------------------------------------------------------------

inline constexpr std::size_t kIsoDescSize        = 16;
inline constexpr std::size_t kIsoOffOffset       = 0;   // u32
inline constexpr std::size_t kIsoOffLength       = 4;   // u32
inline constexpr std::size_t kIsoOffActualLength = 8;   // u32
inline constexpr std::size_t kIsoOffStatus       = 12;  // u16
inline constexpr std::size_t kIsoOffReserved     = 14;  // u16

static_assert(kIsoOffReserved + 2 == kIsoDescSize, "iso descriptor must be 16 bytes");

// ---------------------------------------------------------------------------
// HELLO / HELLO_OK (0x01 / 0x02), B = 48  (§3.13)
// ---------------------------------------------------------------------------

inline constexpr std::size_t kHelOffProtoMin       = 0;   // u16
inline constexpr std::size_t kHelOffProtoMax       = 2;   // u16
inline constexpr std::size_t kHelOffCaps           = 4;   // u64
inline constexpr std::size_t kHelOffMaxTransfer    = 12;  // u32
inline constexpr std::size_t kHelOffMaxRecord      = 16;  // u32
inline constexpr std::size_t kHelOffMaxSegment     = 20;  // u32
inline constexpr std::size_t kHelOffMaxIsoPackets  = 24;  // u32
inline constexpr std::size_t kHelOffMaxChannels    = 28;  // u16
inline constexpr std::size_t kHelOffMaxLinks       = 30;  // u16
inline constexpr std::size_t kHelOffKeepaliveMs    = 32;  // u32
inline constexpr std::size_t kHelOffPlatformId     = 36;  // u8
inline constexpr std::size_t kHelOffRoleBits       = 37;  // u8
inline constexpr std::size_t kHelOffReserved       = 38;  // u16
inline constexpr std::size_t kHelOffSessionId      = 40;  // 16 bytes
inline constexpr std::size_t kSessionIdBytes       = 16;

static_assert(kHelOffSessionId + kSessionIdBytes == kBodyHello,
              "HELLO body must be exactly 56 bytes");

enum RoleBits : std::uint8_t {
    kRoleCanExport = 1u << 0,
    kRoleCanImport = 1u << 1,
};

enum PlatformId : std::uint8_t {
    kPlatformMacos   = 1,
    kPlatformWindows = 2,
    kPlatformLinux   = 3,
};

/// Capability bits, ANDed by both peers. Bit 1 (Segmentation) must be set.
enum Caps : std::uint64_t {
    kCapCoalesce             = 1ull << 0,
    kCapSegmentation         = 1ull << 1,   // mandatory
    kCapMultilink            = 1ull << 2,
    kCapIso                  = 1ull << 3,
    kCapUsb3Streams          = 1ull << 4,
    kCapManifestAuthoritative= 1ull << 5,
    kCapExport               = 1ull << 6,
    kCapImport               = 1ull << 7,
    kCapHotplugEvents        = 1ull << 8,
    kCapCancel               = 1ull << 9,
    kCapReset                = 1ull << 10,
    kCapSuspendResume        = 1ull << 11,
    kCapNativeStatusTlv      = 1ull << 12,
    kCapReservedMask         = ~((1ull << 13) - 1),
};

inline constexpr std::uint16_t kProtoVersionV1 = 1;

// ---------------------------------------------------------------------------
// PING / PONG (0x03 / 0x04), B = 24
// ---------------------------------------------------------------------------

inline constexpr std::size_t kPingOffPingTsNs        = 0;   // u64
inline constexpr std::size_t kPingOffEchoTsNs        = 8;   // u64
inline constexpr std::size_t kPingOffCreditUrbsView  = 16;  // u32, debug builds only
inline constexpr std::size_t kPingOffCreditBytesView = 20;  // u32, debug builds only

static_assert(kPingOffCreditBytesView + 4 == kBodyPing, "PING body must be 24 bytes");

// ---------------------------------------------------------------------------
// ERROR (0x06), B = 8
// ---------------------------------------------------------------------------

inline constexpr std::size_t kErrOffOffendingType = 0;  // u16
inline constexpr std::size_t kErrOffReserved      = 2;  // u16
inline constexpr std::size_t kErrOffDetail        = 4;  // u32

static_assert(kErrOffDetail + 4 == kBodyError, "ERROR body must be 8 bytes");

// ---------------------------------------------------------------------------
// CANCEL (0x42) B = 16 / CANCEL_ACK (0x43) B = 8
// ---------------------------------------------------------------------------

inline constexpr std::size_t kCanOffTargetRequestId = 0;  // u64
inline constexpr std::size_t kCanOffEpAddr          = 8;  // u8
inline constexpr std::size_t kCanOffScope           = 9;  // u8
inline constexpr std::size_t kCanOffReserved        = 10; // u16
inline constexpr std::size_t kCanOffReserved2       = 12; // u32

static_assert(kCanOffReserved2 + 4 == kBodyCancel, "CANCEL body must be 16 bytes");

inline constexpr std::size_t kCakOffCancelledCount = 0;  // u32
inline constexpr std::size_t kCakOffGranularity    = 4;  // u8
inline constexpr std::size_t kCakOffReserved       = 5;  // 3 bytes

static_assert(kCakOffReserved + 3 == kBodyCancelAck, "CANCEL_ACK body must be 8 bytes");

// ---------------------------------------------------------------------------
// TLVs (§3.13). Format: u16 type; u16 len; u8 value[len]. Unpadded.
// ---------------------------------------------------------------------------

inline constexpr std::size_t kTlvHeaderSize = 4;
inline constexpr std::size_t kTlvOffType    = 0;
inline constexpr std::size_t kTlvOffLen     = 2;

enum class Tlv : std::uint16_t {
    ImplString           = 0x0001,
    NativeStatus         = 0x0002,
    DeviceName           = 0x0003,
    DeviceIds            = 0x0004,
    Serial               = 0x0005,
    PeerName             = 0x0006,
    ManifestHash         = 0x0007,
    RejectReason         = 0x0008,
    Grants               = 0x0009,
    DeviceDesc           = 0x000A,
    ConfigDesc           = 0x000B,
    BosDesc              = 0x000C,
    StringDesc           = 0x000D,
    LangidTable          = 0x000E,
    DeviceQualifierDesc  = 0x000F,
    OtherSpeedConfigDesc = 0x0010,
    SessionId            = 0x0011,
};

// ---------------------------------------------------------------------------
// Negotiated limits and hard ceilings (R2, R9)
// ---------------------------------------------------------------------------

inline constexpr std::uint32_t kSegmentBytesDefault  = 16384;
inline constexpr std::uint32_t kTransferBytesDefault = 1u << 20;   // 1 MiB
inline constexpr std::uint32_t kTransferBytesCeiling = 16u << 20;  // 16 MiB
inline constexpr std::uint32_t kIsoPacketsCeiling    = 1024;

inline constexpr std::uint32_t kMaxConfigs         = 8;
inline constexpr std::uint32_t kMaxStrings         = 128;
inline constexpr std::uint32_t kMaxLangids         = 16;
inline constexpr std::uint32_t kMaxDevicesPerList  = 64;
inline constexpr std::uint32_t kMaxChannels        = 256;
inline constexpr std::uint32_t kManifestBytesMax   = 256u * 1024;
inline constexpr std::uint32_t kConfigTotalLenMax  = 65535;
inline constexpr std::uint32_t kUtf8FieldMax       = 256;
inline constexpr std::uint8_t  kAttachSlotMin      = 1;
inline constexpr std::uint8_t  kAttachSlotMax      = 15;   // macOS portCount is 4 bits

/// Channel id is a pure function of (attach_slot, ep_addr) — never negotiated, so
/// no EP_OPEN round trip exists. This is what makes the Linux vhci-hcd shim
/// implementable: vhci emits no endpoint-open event at all, only CMD_SUBMIT.
constexpr std::uint16_t channelFor(std::uint8_t attachSlot, std::uint8_t epAddr) noexcept
{
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(attachSlot) << 8) | epAddr);
}

inline constexpr std::uint16_t kChannelSession = 0;

// ---------------------------------------------------------------------------
// USB transfer types as carried on the wire
// ---------------------------------------------------------------------------

enum class XferType : std::uint8_t {
    Control     = 0,
    Isochronous = 1,
    Bulk        = 2,
    Interrupt   = 3,
};

enum class Dir : std::uint8_t { Out = 0, In = 1 };

} // namespace airusb::wire

#endif // AIRUSB_PROTOCOL_WIRE_H
