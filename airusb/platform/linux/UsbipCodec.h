// AirUSB Hub — the USB/IP protocol data unit, as vhci-hcd speaks it.
//
// WHAT THIS IS
//
// Once userspace hands a socket to vhci-hcd, the KERNEL becomes the client on
// that socket and talks USB/IP over it: CMD_SUBMIT for every URB its drivers
// issue, CMD_UNLINK to cancel one, and it expects RET_SUBMIT / RET_UNLINK back.
// This file is the byte layer of that conversation and nothing else. It has no
// sockets, no sysfs, no AirUSB and no Linux headers, so it compiles and is fuzzed
// on macOS in CI — which is the only reason a bug in it is cheap to find.
//
// THE ONE THING TO GET RIGHT
//
// Every u32/s32 in the header is BIG endian. `setup[8]` is NOT. It is the raw USB
// SETUP packet, so wValue/wIndex/wLength inside it stay LITTLE endian, sitting in
// the middle of an otherwise big-endian header. A layer that byteswaps the header
// wholesale corrupts every control transfer, which means it corrupts enumeration
// itself, which means nothing works and the reason is eight bytes deep.
//
// It is also the project's own rule arriving from the other direction: descriptor
// and setup bytes travel verbatim. Never reorder them.
//
// SIZES
//
// A PDU is ALWAYS 48 bytes, both directions, every command — 20 bytes of header
// plus a 28-byte union. `vhci_rx_pdu` reads sizeof(pdu) unconditionally, so a
// RET_SUBMIT written as 20 bytes leaves the kernel blocked forever waiting for
// the other 28. Everything unused is zero.
//
// WHAT IS DELIBERATELY NOT HERE
//
// The transfer TYPE is never on the wire. The kernel's own server resolves it
// from the endpoint descriptor and so must we, from the DEVICE_MANIFEST. Nothing
// in this file guesses it, and in particular nothing here decides "is this
// isochronous" — see kMaxIsoPackets.

#ifndef AIRUSB_PLATFORM_LINUX_USBIPCODEC_H
#define AIRUSB_PLATFORM_LINUX_USBIPCODEC_H

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace airusb::linuxvhci {

/// Every PDU, every direction, every command.
inline constexpr std::size_t kPduBytes     = 48;
inline constexpr std::size_t kIsoDescBytes = 16;
inline constexpr std::size_t kSetupBytes   = 8;

/// usbip_common.h:117-123.
inline constexpr std::uint32_t kCmdSubmit = 1;
inline constexpr std::uint32_t kCmdUnlink = 2;
inline constexpr std::uint32_t kRetSubmit = 3;
inline constexpr std::uint32_t kRetUnlink = 4;

inline constexpr std::uint32_t kDirOut = 0;
inline constexpr std::uint32_t kDirIn  = 1;

// transfer_flags. These are the USBIP_URB_* values from
// include/uapi/linux/usbip.h, hardcoded on purpose. They happen to be
// numerically identical to the URB_* values in include/linux/usb.h today, but
// flag_map[]/urb_to_usbip() is exactly the seam where the two are allowed to
// diverge, and <linux/usb.h> is not a header this file may ever include.
inline constexpr std::uint32_t kUrbShortNotOk  = 0x00000001;
inline constexpr std::uint32_t kUrbIsoAsap     = 0x00000002;
inline constexpr std::uint32_t kUrbZeroPacket  = 0x00000040;
inline constexpr std::uint32_t kUrbNoInterrupt = 0x00000080;  ///< scheduling hint; ignore
inline constexpr std::uint32_t kUrbDirIn       = 0x00000200;  ///< redundant; ignore
inline constexpr std::uint32_t kUrbDmaMapSg    = 0x00040000;  ///< host DMA artifact; ignore

/// stub_rx.c:370-377 clamps to this. An unclamped count is read amplification:
/// believing a 0xFFFFFFFF would have us try to read 64 GiB of descriptors for an
/// ordinary bulk transfer.
inline constexpr std::int32_t kMaxIsoPackets = 1024;

/// One decoded PDU. Which members are meaningful depends on `command`, exactly as
/// the kernel's union does; the names say which.
struct UsbipPdu {
    // usbip_header_basic — present on all four commands.
    std::uint32_t command   = 0;
    std::uint32_t seqnum    = 0;
    std::uint32_t devid     = 0;
    std::uint32_t direction = 0;   ///< kDirOut / kDirIn. CMD_SUBMIT only.
    std::uint32_t ep        = 0;   ///< endpoint NUMBER 0..15, with no 0x80 bit.

    // CMD_SUBMIT.
    std::uint32_t transferFlags        = 0;
    std::int32_t  transferBufferLength = 0;
    std::int32_t  startFrame           = 0;
    std::int32_t  numberOfPackets      = 0;
    std::int32_t  interval             = 0;
    std::uint8_t  setup[kSetupBytes]   = {};   ///< verbatim; little-endian inside

    // RET_SUBMIT / RET_UNLINK. `status` is a negative errno.
    std::int32_t  status       = 0;
    std::int32_t  actualLength = 0;
    std::int32_t  errorCount   = 0;

    // CMD_UNLINK: the seqnum being cancelled, which is NOT this PDU's own seqnum.
    std::uint32_t unlinkSeqnum = 0;

    /// The endpoint address as USB spells it, direction bit and all. This is what
    /// a pipe table is keyed on; `ep` alone is ambiguous between IN and OUT.
    std::uint8_t endpointAddress() const noexcept
    {
        return static_cast<std::uint8_t>((ep & 0x0Fu) | (direction == kDirIn ? 0x80u : 0x00u));
    }

    /// Whether a payload follows this CMD_SUBMIT header on the wire, and how much.
    /// An OUT transfer carries exactly transfer_buffer_length bytes.
    bool hasOutPayload() const noexcept
    {
        return command == kCmdSubmit && direction == kDirOut && transferBufferLength > 0;
    }
};

/// One isochronous packet descriptor. All four fields are big-endian — including
/// `status`, which is declared unsigned in the kernel and carries a negative
/// errno anyway.
///
/// AirUSB's own iso descriptor (Wire.h) is also 16 bytes and also starts with
/// offset/length/actual_length, and then differs: u16 status + u16 reserved,
/// little-endian. Same size, different tail, opposite byte order. Whoever
/// implements isochronous will meet that trap; it is written down here so they
/// meet it on purpose.
struct UsbipIsoDesc {
    std::uint32_t offset       = 0;
    std::uint32_t length       = 0;
    std::uint32_t actualLength = 0;
    std::int32_t  status       = 0;
};

// --- decode ------------------------------------------------------------------

/// Decodes exactly `kPduBytes`. Returns false if the span is the wrong size or
/// the command is not one of the four; every other field is accepted as-is,
/// because rejecting values the kernel is allowed to send is how a bridge
/// deadlocks rather than errors.
///
/// `numberOfPackets` is clamped into [0, kMaxIsoPackets] and the clamp is
/// reported, so a caller can refuse rather than silently transact on a value the
/// kernel did not send.
bool decodePdu(std::span<const std::uint8_t> in, UsbipPdu& out, bool* clamped = nullptr) noexcept;

/// Decodes `count` descriptors from `count * kIsoDescBytes` bytes.
bool decodeIsoDescs(std::span<const std::uint8_t> in, std::size_t count,
                    std::vector<UsbipIsoDesc>& out);

// --- encode ------------------------------------------------------------------

/// RET_SUBMIT for the URB `cmd` requested. Appends exactly kPduBytes.
///
/// `startFrame` and `numberOfPackets` are echoed from `cmd` rather than invented:
/// start_frame is not a discriminator and the kernel compares what it gets back.
void encodeRetSubmit(const UsbipPdu& cmd,
                     std::int32_t status,
                     std::int32_t actualLength,
                     std::int32_t errorCount,
                     std::vector<std::uint8_t>& out);

/// RET_UNLINK for a CMD_UNLINK. `seqnum` is the UNLINK's own seqnum, echoed —
/// not the seqnum it was cancelling.
void encodeRetUnlink(std::uint32_t unlinkPduSeqnum,
                     std::int32_t status,
                     std::vector<std::uint8_t>& out);

void encodeIsoDescs(std::span<const UsbipIsoDesc> descs, std::vector<std::uint8_t>& out);

/// For tests and for the hosted harness: build a CMD_SUBMIT the way the kernel
/// would. Not used on the real path — the kernel writes those, we only read them.
void encodeCmdSubmit(const UsbipPdu& cmd, std::vector<std::uint8_t>& out);
void encodeCmdUnlink(std::uint32_t seqnum, std::uint32_t devid,
                     std::uint32_t targetSeqnum, std::vector<std::uint8_t>& out);

} // namespace airusb::linuxvhci

#endif // AIRUSB_PLATFORM_LINUX_USBIPCODEC_H
