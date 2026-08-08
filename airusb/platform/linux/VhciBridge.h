// AirUSB Hub — the kernel on one side, a USB device on the other.
//
// vhci-hcd hands us a socket and then behaves like a USB host controller driver
// talking to a device: CMD_SUBMIT for every URB, CMD_UNLINK to cancel one,
// RET_SUBMIT and RET_UNLINK expected back. This class is the translation, and
// nothing else. It owns no socket and no device: it reads PDUs from an
// `IByteStream` and issues transfers to an `IUsbDevicePort`.
//
// That indirection is the whole design. `IUsbDevicePort` is implemented by
// `ScriptedDevice` (a RAM disk, in a unit test, on a Mac with no kernel) and by
// `RemoteDevicePort` (a real device across an encrypted network session). The
// same bridge drives both, so enumeration can be proven correct byte for byte
// before a kernel is ever in the loop — which matters because a bug found with a
// kernel in the loop costs a VM reboot per iteration and leaves D-state processes
// that make the next iteration's evidence untrustworthy.
//
// WHAT IT REFUSES TO DO
//
// It never invents a descriptor. Control transfers on endpoint 0 go through
// `Ep0Arbiter`, which either answers from the manifest — whose bytes came from
// the real device verbatim — or forwards to the device. The kernel's first act
// after attach is to ask what the device is, and the answer has to be the truth
// or it has enumerated something that does not exist.
//
// It never guesses a transfer type. USB/IP does not carry one; the kernel's own
// server resolves it from the endpoint descriptor and so does this, from the
// manifest's pipe table.
//
// THREADING
//
// One strand. `pumpOnce()` reads one PDU, does the work, writes the reply. That
// is correct for a synchronous `IUsbDevicePort` and is what L3 proves. It is NOT
// sufficient for the networked case, where the kernel may have many URBs in
// flight and blocking on the network while its socket buffer fills is the
// deadlock the plan's §4.2 is about. The async data plane is L4 work; this class
// is written so that the translation is already tested when it arrives.

#ifndef AIRUSB_PLATFORM_LINUX_VHCIBRIDGE_H
#define AIRUSB_PLATFORM_LINUX_VHCIBRIDGE_H

#include "LinuxUsb.h"
#include "UsbipCodec.h"

#include "../../core/Ep0Arbiter.h"
#include "../../core/IUsbDevicePort.h"
#include "../../core/Status.h"
#include "../../transport/IAirUsbTransport.h"

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace airusb::linuxvhci {

struct VhciBridgeStats {
    std::uint32_t submitsHandled   = 0;
    std::uint32_t unlinksHandled   = 0;
    std::uint32_t answeredLocally  = 0;   ///< from the manifest; never touched the device
    std::uint32_t forwardedToDevice = 0;
    std::uint32_t stalled          = 0;
    std::uint64_t bytesToKernel    = 0;
    std::uint64_t bytesFromKernel  = 0;
};

class VhciBridge {
public:
    using Trace = std::function<void(const std::string& line)>;

    VhciBridge(transport::IByteStream& kernel, IUsbDevicePort& device) noexcept;

    void setTrace(Trace t) { _trace = std::move(t); }

    /// Reads one PDU and answers it.
    ///
    /// Returns Ok when a PDU was handled, TransportLost at end of stream, and a
    /// fatal status when the stream said something that cannot be resynchronised.
    /// There is no length prefix in USB/IP, so a PDU we cannot parse means the
    /// stream position is no longer trustworthy and the only safe answer is to
    /// stop — never to guess a length and resync.
    Status pumpOnce();

    /// Pumps until the stream ends or something fatal happens.
    Status run();

    const VhciBridgeStats& stats() const noexcept { return _stats; }
    const std::string& lastError() const noexcept { return _lastError; }

private:
    Status handleSubmit(const UsbipPdu& pdu);
    Status handleUnlink(const UsbipPdu& pdu);

    /// ep0. Goes through the arbiter before anything else.
    Status handleControl(const UsbipPdu& pdu, std::span<const std::uint8_t> outData);

    /// Everything else, resolved against the manifest's pipe table.
    Status handleDataEndpoint(const UsbipPdu& pdu, std::span<const std::uint8_t> outData);

    Status readExactly(std::span<std::uint8_t> dst);
    Status writeAll(std::span<const std::uint8_t> src);

    /// RET_SUBMIT with no payload.
    Status reply(const UsbipPdu& cmd, std::int32_t status, std::int32_t actualLength);

    /// RET_SUBMIT followed by exactly `data.size()` bytes. `data` must already be
    /// truncated to what was asked for: reporting more than
    /// transfer_buffer_length makes the kernel log "recv xbuf" and tear the whole
    /// port down, taking every other in-flight URB with it.
    Status replyWithData(const UsbipPdu& cmd, std::span<const std::uint8_t> data);

    void trace(const std::string& s) const { if (_trace) _trace(s); }

    transport::IByteStream& _kernel;
    IUsbDevicePort&         _device;
    Ep0Arbiter              _arbiter;
    VhciBridgeStats         _stats;
    Trace                   _trace;
    std::string             _lastError;

    std::vector<std::uint8_t> _scratchIn;
    std::vector<std::uint8_t> _scratchOut;
};

} // namespace airusb::linuxvhci

#endif // AIRUSB_PLATFORM_LINUX_VHCIBRIDGE_H
