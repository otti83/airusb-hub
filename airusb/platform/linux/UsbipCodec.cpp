#include "UsbipCodec.h"

#include <cstring>

namespace airusb::linuxvhci {

namespace {

// Explicit big-endian access. Not htonl: this file compiles on macOS for the
// hosted tests, and a byte-order helper that depends on a socket header is a
// portability problem waiting to be discovered on the machine that has no kernel.
std::uint32_t rd32be(const std::uint8_t* p) noexcept
{
    return (static_cast<std::uint32_t>(p[0]) << 24)
         | (static_cast<std::uint32_t>(p[1]) << 16)
         | (static_cast<std::uint32_t>(p[2]) << 8)
         |  static_cast<std::uint32_t>(p[3]);
}

void wr32be(std::uint8_t* p, std::uint32_t v) noexcept
{
    p[0] = static_cast<std::uint8_t>(v >> 24);
    p[1] = static_cast<std::uint8_t>(v >> 16);
    p[2] = static_cast<std::uint8_t>(v >> 8);
    p[3] = static_cast<std::uint8_t>(v);
}

/// Signed fields travel as the same 32 bits; the conversion is a reinterpretation,
/// not an arithmetic one, so it goes through the unsigned type explicitly rather
/// than relying on implementation-defined narrowing.
std::int32_t asS32(std::uint32_t v) noexcept
{
    std::int32_t s;
    std::memcpy(&s, &v, sizeof s);
    return s;
}

std::uint32_t asU32(std::int32_t v) noexcept
{
    std::uint32_t u;
    std::memcpy(&u, &v, sizeof u);
    return u;
}

std::uint8_t* grow(std::vector<std::uint8_t>& out, std::size_t n)
{
    const std::size_t at = out.size();
    out.resize(at + n, 0);
    return out.data() + at;
}

} // namespace

// ---------------------------------------------------------------------------

bool decodePdu(std::span<const std::uint8_t> in, UsbipPdu& out, bool* clamped) noexcept
{
    if (clamped) *clamped = false;
    if (in.size() != kPduBytes) return false;

    const std::uint8_t* p = in.data();

    out = UsbipPdu{};
    out.command   = rd32be(p + 0x00);
    out.seqnum    = rd32be(p + 0x04);
    out.devid     = rd32be(p + 0x08);
    out.direction = rd32be(p + 0x0C);
    out.ep        = rd32be(p + 0x10);

    switch (out.command) {
        case kCmdSubmit:
            out.transferFlags        = rd32be(p + 0x14);
            out.transferBufferLength = asS32(rd32be(p + 0x18));
            out.startFrame           = asS32(rd32be(p + 0x1C));
            out.numberOfPackets      = asS32(rd32be(p + 0x20));
            out.interval             = asS32(rd32be(p + 0x24));
            // VERBATIM. This is the raw USB SETUP packet: wValue, wIndex and
            // wLength inside it are little-endian and must stay that way.
            std::memcpy(out.setup, p + 0x28, kSetupBytes);

            if (out.numberOfPackets < 0 || out.numberOfPackets > kMaxIsoPackets) {
                // Clamped rather than rejected, and reported. The kernel clamps
                // identically on its own receive path; what matters is that no
                // caller ever multiplies an unclamped value by 16 and reads it.
                out.numberOfPackets = (out.numberOfPackets < 0) ? 0 : kMaxIsoPackets;
                if (clamped) *clamped = true;
            }
            return true;

        case kRetSubmit:
            out.status          = asS32(rd32be(p + 0x14));
            out.actualLength    = asS32(rd32be(p + 0x18));
            out.startFrame      = asS32(rd32be(p + 0x1C));
            out.numberOfPackets = asS32(rd32be(p + 0x20));
            out.errorCount      = asS32(rd32be(p + 0x24));
            if (out.numberOfPackets < 0 || out.numberOfPackets > kMaxIsoPackets) {
                out.numberOfPackets = (out.numberOfPackets < 0) ? 0 : kMaxIsoPackets;
                if (clamped) *clamped = true;
            }
            return true;

        case kCmdUnlink:
            out.unlinkSeqnum = rd32be(p + 0x14);
            return true;

        case kRetUnlink:
            out.status = asS32(rd32be(p + 0x14));
            return true;

        default:
            // Not one of the four. The caller must tear the connection down:
            // there is no length prefix on this protocol, so an unknown command
            // means the stream position is no longer trustworthy.
            return false;
    }
}

bool decodeIsoDescs(std::span<const std::uint8_t> in, std::size_t count,
                    std::vector<UsbipIsoDesc>& out)
{
    out.clear();
    if (count > static_cast<std::size_t>(kMaxIsoPackets)) return false;
    if (in.size() != count * kIsoDescBytes) return false;

    out.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        const std::uint8_t* p = in.data() + i * kIsoDescBytes;
        UsbipIsoDesc d;
        d.offset       = rd32be(p + 0);
        d.length       = rd32be(p + 4);
        d.actualLength = rd32be(p + 8);
        d.status       = asS32(rd32be(p + 12));
        out.push_back(d);
    }
    return true;
}

// ---------------------------------------------------------------------------

void encodeRetSubmit(const UsbipPdu& cmd,
                     std::int32_t status,
                     std::int32_t actualLength,
                     std::int32_t errorCount,
                     std::vector<std::uint8_t>& out)
{
    // Zero-filled to the full 48 bytes. A short PDU does not produce an error on
    // the kernel side; vhci_rx_pdu asks for sizeof(pdu) with MSG_WAITALL, so it
    // simply never returns and the port becomes unkillable.
    std::uint8_t* p = grow(out, kPduBytes);

    wr32be(p + 0x00, kRetSubmit);
    wr32be(p + 0x04, cmd.seqnum);       // echo: this is how it is matched
    wr32be(p + 0x08, 0);                // devid is 0 on returns
    wr32be(p + 0x0C, 0);                // direction is 0 on returns
    wr32be(p + 0x10, 0);                // ep is 0 on returns
    wr32be(p + 0x14, asU32(status));
    wr32be(p + 0x18, asU32(actualLength));
    wr32be(p + 0x1C, asU32(cmd.startFrame));       // echoed, never invented
    wr32be(p + 0x20, asU32(cmd.numberOfPackets));  // echoed
    wr32be(p + 0x24, asU32(errorCount));
    // 0x28..0x2F stay zero: setup has no meaning on a return.
}

void encodeRetUnlink(std::uint32_t unlinkPduSeqnum,
                     std::int32_t status,
                     std::vector<std::uint8_t>& out)
{
    std::uint8_t* p = grow(out, kPduBytes);
    wr32be(p + 0x00, kRetUnlink);
    // The UNLINK's own seqnum, not the one it was cancelling. Getting this
    // backwards answers a seqnum the kernel is not holding, which kills the port
    // and every URB on it.
    wr32be(p + 0x04, unlinkPduSeqnum);
    wr32be(p + 0x14, asU32(status));
    // everything else zero
}

void encodeIsoDescs(std::span<const UsbipIsoDesc> descs, std::vector<std::uint8_t>& out)
{
    for (const UsbipIsoDesc& d : descs) {
        std::uint8_t* p = grow(out, kIsoDescBytes);
        wr32be(p + 0,  d.offset);
        wr32be(p + 4,  d.length);
        wr32be(p + 8,  d.actualLength);
        wr32be(p + 12, asU32(d.status));
    }
}

void encodeCmdSubmit(const UsbipPdu& cmd, std::vector<std::uint8_t>& out)
{
    std::uint8_t* p = grow(out, kPduBytes);
    wr32be(p + 0x00, kCmdSubmit);
    wr32be(p + 0x04, cmd.seqnum);
    wr32be(p + 0x08, cmd.devid);
    wr32be(p + 0x0C, cmd.direction);
    wr32be(p + 0x10, cmd.ep);
    wr32be(p + 0x14, cmd.transferFlags);
    wr32be(p + 0x18, asU32(cmd.transferBufferLength));
    wr32be(p + 0x1C, asU32(cmd.startFrame));
    wr32be(p + 0x20, asU32(cmd.numberOfPackets));
    wr32be(p + 0x24, asU32(cmd.interval));
    std::memcpy(p + 0x28, cmd.setup, kSetupBytes);   // verbatim
}

void encodeCmdUnlink(std::uint32_t seqnum, std::uint32_t devid,
                     std::uint32_t targetSeqnum, std::vector<std::uint8_t>& out)
{
    std::uint8_t* p = grow(out, kPduBytes);
    wr32be(p + 0x00, kCmdUnlink);
    wr32be(p + 0x04, seqnum);
    wr32be(p + 0x08, devid);
    wr32be(p + 0x14, targetSeqnum);
}

} // namespace airusb::linuxvhci
