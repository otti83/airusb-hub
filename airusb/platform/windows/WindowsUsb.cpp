#include "WindowsUsb.h"

// The transcribed constants are NOT checked here.
//
// They cannot be: this file is compiled on macOS and Linux so the mapping can be
// tested without Windows, and the WDK's kernel headers cannot coexist with the
// C++ standard library in one translation unit. Putting the checks here meant
// they would never actually run anywhere.
//
// `platform/windows/wdk_abi_check.c` is where they live now — a translation unit
// that includes the real WDK headers, C_ASSERTs every value in
// `WindowsUsbAbi.h`, produces no code and is never linked. Compiling it IS the
// test, and only a machine with the WDK can do it.

namespace airusb::windows {

UdecxSpeed toUdecxSpeed(Speed s) noexcept
{
    // One line at a time, with what a cast would have produced, because the bug
    // this prevents is invisible at the call site.
    switch (s) {
        case Speed::Full:  return UdecxSpeed::Full;   // the only coincidence
        case Speed::Low:   return UdecxSpeed::Low;    // a cast would give High
        case Speed::High:  return UdecxSpeed::High;   // a cast would give Super
        case Speed::Super: return UdecxSpeed::Super;  // a cast would be out of range

        // UdeCx has no SuperSpeedPlus. Reporting Super would understate a Gen2
        // link, and every descriptor the guest then reads — the BOS SuperSpeedPlus
        // capability in particular — would contradict the port it is on.
        case Speed::SuperPlus:
        case Speed::SuperPlusBy2:
            return UdecxSpeed::Unsupported;

        case Speed::None:
        case Speed::Other:
            return UdecxSpeed::Unsupported;
    }
    return UdecxSpeed::Unsupported;
}

Speed fromUdecxSpeed(UdecxSpeed s) noexcept
{
    switch (s) {
        case UdecxSpeed::Low:   return Speed::Low;
        case UdecxSpeed::Full:  return Speed::Full;
        case UdecxSpeed::High:  return Speed::High;
        case UdecxSpeed::Super: return Speed::Super;
        case UdecxSpeed::Unsupported: return Speed::None;
    }
    return Speed::None;
}

UsbdStatus toUsbdStatus(Status s, std::uint32_t offered, std::uint32_t moved,
                        std::uint32_t transferFlags) noexcept
{
    switch (s) {
    case Status::Ok:
        // The short-transfer question, and the reason this function takes three
        // arguments instead of one. See the header: Windows makes the CALLER
        // say whether short is acceptable, and both possible hardcoded answers
        // are wrong for somebody.
        if (moved < offered && (transferFlags & kUsbdShortTransferOk) == 0)
            return UsbdStatus::ErrorShortTransfer;
        return UsbdStatus::Success;

    // XferShort is the exporter telling us the device sent less than was asked
    // for. That is the same fact as the branch above, so it takes the same
    // decision — not an automatic error.
    case Status::XferShort:
        if ((transferFlags & kUsbdShortTransferOk) == 0)
            return UsbdStatus::ErrorShortTransfer;
        return UsbdStatus::Success;

    case Status::XferStall:
    case Status::XferEpStopped:     return UsbdStatus::StallPid;
    case Status::XferTimeout:
    case Status::XferNakTimeout:    return UsbdStatus::Timeout;
    case Status::XferCancelled:     return UsbdStatus::Canceled;
    case Status::XferOverrun:       return UsbdStatus::BufferOverrun;
    case Status::XferUnderrun:      return UsbdStatus::BufferUnderrun;
    case Status::XferCrc:           return UsbdStatus::Crc;
    case Status::XferBitstuff:      return UsbdStatus::BtStuff;
    case Status::XferBadToggle:     return UsbdStatus::DataToggleMismatch;
    case Status::XferProtocol:      return UsbdStatus::UnexpectedPid;
    case Status::XferNoBandwidth:   return UsbdStatus::NoBandwidth;
    case Status::XferMissedService: return UsbdStatus::NotAccessed;

    // The device is gone, from the guest's point of view, and saying so is the
    // only honest answer. TransportLost means "we do not know whether this
    // transfer happened", which USB cannot express — the importer converts it
    // into a port disconnect, and this status is what the in-flight URBs get on
    // the way there.
    case Status::XferDeviceOffline:
    case Status::DeviceGone:
    case Status::TransportLost:     return UsbdStatus::DeviceGone;

    case Status::NoResources:       return UsbdStatus::NoMemory;
    case Status::BadArgument:       return UsbdStatus::InvalidParameter;
    case Status::Busy:              return UsbdStatus::ErrorBusy;

    default:                        return UsbdStatus::RequestFailed;
    }
}

Status fromUsbdStatus(UsbdStatus s) noexcept
{
    switch (s) {
    case UsbdStatus::Success:            return Status::Ok;
    case UsbdStatus::ErrorShortTransfer: return Status::XferShort;
    case UsbdStatus::StallPid:
    case UsbdStatus::EndpointHalted:     return Status::XferStall;
    case UsbdStatus::Timeout:            return Status::XferTimeout;
    case UsbdStatus::Canceled:           return Status::XferCancelled;
    case UsbdStatus::DataOverrun:
    case UsbdStatus::BufferOverrun:      return Status::XferOverrun;
    case UsbdStatus::DataUnderrun:
    case UsbdStatus::BufferUnderrun:     return Status::XferUnderrun;
    case UsbdStatus::Crc:                return Status::XferCrc;
    case UsbdStatus::BtStuff:            return Status::XferBitstuff;
    case UsbdStatus::DataToggleMismatch: return Status::XferBadToggle;
    case UsbdStatus::DevNotResponding:
    case UsbdStatus::DeviceGone:         return Status::XferDeviceOffline;
    case UsbdStatus::NoBandwidth:        return Status::XferNoBandwidth;
    case UsbdStatus::NotAccessed:        return Status::XferMissedService;
    case UsbdStatus::NoMemory:           return Status::NoResources;
    case UsbdStatus::InvalidParameter:   return Status::BadArgument;
    case UsbdStatus::ErrorBusy:          return Status::Busy;
    default:                             return Status::XferUnknown;
    }
}

const char* udecxSpeedName(UdecxSpeed s) noexcept
{
    switch (s) {
        case UdecxSpeed::Low:         return "Low";
        case UdecxSpeed::Full:        return "Full";
        case UdecxSpeed::High:        return "High";
        case UdecxSpeed::Super:       return "Super";
        case UdecxSpeed::Unsupported: return "Unsupported";
    }
    return "Unsupported";
}

const char* usbdStatusName(UsbdStatus s) noexcept
{
    switch (s) {
        case UsbdStatus::Success:            return "USBD_STATUS_SUCCESS";
        case UsbdStatus::Pending:            return "USBD_STATUS_PENDING";
        case UsbdStatus::Crc:                return "USBD_STATUS_CRC";
        case UsbdStatus::BtStuff:            return "USBD_STATUS_BTSTUFF";
        case UsbdStatus::DataToggleMismatch: return "USBD_STATUS_DATA_TOGGLE_MISMATCH";
        case UsbdStatus::StallPid:           return "USBD_STATUS_STALL_PID";
        case UsbdStatus::DevNotResponding:   return "USBD_STATUS_DEV_NOT_RESPONDING";
        case UsbdStatus::PidCheckFailure:    return "USBD_STATUS_PID_CHECK_FAILURE";
        case UsbdStatus::UnexpectedPid:      return "USBD_STATUS_UNEXPECTED_PID";
        case UsbdStatus::DataOverrun:        return "USBD_STATUS_DATA_OVERRUN";
        case UsbdStatus::DataUnderrun:       return "USBD_STATUS_DATA_UNDERRUN";
        case UsbdStatus::BufferOverrun:      return "USBD_STATUS_BUFFER_OVERRUN";
        case UsbdStatus::BufferUnderrun:     return "USBD_STATUS_BUFFER_UNDERRUN";
        case UsbdStatus::NotAccessed:        return "USBD_STATUS_NOT_ACCESSED";
        case UsbdStatus::Fifo:               return "USBD_STATUS_FIFO";
        case UsbdStatus::EndpointHalted:     return "USBD_STATUS_ENDPOINT_HALTED";
        case UsbdStatus::NoMemory:           return "USBD_STATUS_NO_MEMORY";
        case UsbdStatus::InvalidUrbFunction: return "USBD_STATUS_INVALID_URB_FUNCTION";
        case UsbdStatus::InvalidParameter:   return "USBD_STATUS_INVALID_PARAMETER";
        case UsbdStatus::ErrorBusy:          return "USBD_STATUS_ERROR_BUSY";
        case UsbdStatus::RequestFailed:      return "USBD_STATUS_REQUEST_FAILED";
        case UsbdStatus::InvalidPipeHandle:  return "USBD_STATUS_INVALID_PIPE_HANDLE";
        case UsbdStatus::NoBandwidth:        return "USBD_STATUS_NO_BANDWIDTH";
        case UsbdStatus::InternalHcError:    return "USBD_STATUS_INTERNAL_HC_ERROR";
        case UsbdStatus::ErrorShortTransfer: return "USBD_STATUS_ERROR_SHORT_TRANSFER";
        case UsbdStatus::Canceled:           return "USBD_STATUS_CANCELED";
        case UsbdStatus::Timeout:            return "USBD_STATUS_TIMEOUT";
        case UsbdStatus::DeviceGone:         return "USBD_STATUS_DEVICE_GONE";
    }
    return "USBD_STATUS_?";
}

} // namespace airusb::windows
