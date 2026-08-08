#include "LinuxUsb.h"

namespace airusb::linuxvhci {

KernelSpeed toKernelSpeed(Speed s) noexcept
{
    // Written out one line at a time on purpose. Every arm where the two numbers
    // differ is commented with what a cast would have produced, because the bug
    // this file prevents is invisible at the call site and survives testing at
    // High speed, the one value that coincides.
    switch (s) {
        case Speed::Full:         return KernelSpeed::Full;   // cast would give LOW
        case Speed::Low:          return KernelSpeed::Low;    // cast would give FULL
        case Speed::High:         return KernelSpeed::High;   // the only coincidence
        case Speed::Super:        return KernelSpeed::Super;  // cast would give WIRELESS
        case Speed::SuperPlus:    return KernelSpeed::SuperPlus;

        // SuperSpeedPlus Gen2x2 has no usb_device_speed of its own. Reporting it
        // as SuperPlus would be a lie about the link, and Correctness outranks
        // Compatibility here, so it is refused and the caller decides.
        case Speed::SuperPlusBy2: return KernelSpeed::Unknown;

        case Speed::None:
        case Speed::Other:
        default:                  return KernelSpeed::Unknown;
    }
}

bool isSuperSpeedHalf(KernelSpeed s) noexcept
{
    return s == KernelSpeed::Super || s == KernelSpeed::SuperPlus;
}

std::int32_t toLinuxErrno(Status s, bool shortIsError) noexcept
{
    switch (s) {
        case Status::Ok:
            return 0;

        // A short transfer is SUCCESS. The true actual_length carries the fact,
        // and every protocol that ends a transfer by sending less than was asked
        // for depends on it being reported that way — which is most of them.
        // The exception is a URB the host marked SHORT_NOT_OK, where short is
        // exactly what the host said it would not accept.
        case Status::XferShort:
            return shortIsError ? -kERemoteIo : 0;

        case Status::XferStall:         return -kEPipe;
        case Status::XferTimeout:
        case Status::XferNakTimeout:    return -kETimedOut;
        case Status::XferCancelled:     return -kEConnReset;
        case Status::XferOverrun:       return -kEOverflow;
        case Status::XferUnderrun:      return -kERemoteIo;

        case Status::XferCrc:
        case Status::XferBitstuff:
        case Status::XferBadToggle:     return -kEIlSeq;

        case Status::XferProtocol:
        case Status::XferStreamError:   return -kEProto;

        case Status::XferNoBandwidth:   return -kENoSpc;
        case Status::XferMissedService: return -kEXDev;
        case Status::XferEpStopped:     return -kEPipe;

        // The device is gone. -ENODEV is what the USB core uses, and it is what
        // makes a class driver give up rather than retry for ever.
        case Status::XferDeviceOffline:
        case Status::DeviceGone:
        case Status::Detaching:         return -kENoDev;

        case Status::TransportLost:     return -kEShutdown;
        case Status::NoResources:       return -kENoMem;
        case Status::BadArgument:       return -kEInval;

        // Anything else is a protocol-level failure rather than a wire error.
        // -EPROTO rather than -EINVAL: the class driver's question is "did the
        // transfer happen", and the honest answer is "something broke below you".
        case Status::XferUnknown:
        default:                        return -kEProto;
    }
}

const char* linuxErrnoName(std::int32_t e) noexcept
{
    switch (e < 0 ? -e : e) {
        case 0:            return "0";
        case kENoMem:      return "ENOMEM";
        case kEXDev:       return "EXDEV";
        case kENoDev:      return "ENODEV";
        case kEInval:      return "EINVAL";
        case kENoSpc:      return "ENOSPC";
        case kEPipe:       return "EPIPE";
        case kEProto:      return "EPROTO";
        case kEOverflow:   return "EOVERFLOW";
        case kEIlSeq:      return "EILSEQ";
        case kEConnReset:  return "ECONNRESET";
        case kEShutdown:   return "ESHUTDOWN";
        case kETimedOut:   return "ETIMEDOUT";
        case kERemoteIo:   return "EREMOTEIO";
        default:           return "?";
    }
}

} // namespace airusb::linuxvhci
