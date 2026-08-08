#include "StatusMapMacos.h"

namespace airusb::macos {

Status fromIOReturn(std::uint32_t ioReturn, bool isTransfer) noexcept
{
    switch (ioReturn) {
        case kIORetSuccess: return Status::Ok;

        // ---- endpoint state ------------------------------------------------
        //
        // A stalled pipe is the one error the exporter must NOT retry. It is
        // cleared with the EP_CLEAR_HALT verb, which also resets the host
        // controller's data toggle; a retry without that leaves every later
        // transfer on the endpoint silently wrong.
        case kUsbRetPipeStalled: return Status::XferStall;

        // ---- length -------------------------------------------------------
        //
        // IOKit "underrun" means the device sent less than was asked for, which
        // for USB is an ordinary short transfer and not an error. It is mapped to
        // XferShort rather than to a failure so a filesystem reading a partial
        // final block sees a short read, exactly as it would locally.
        case kIORetUnderrun: return Status::XferShort;
        case kIORetOverrun:  return Status::XferOverrun;

        // ---- timing and cancellation --------------------------------------
        case kIORetTimeout:  return isTransfer ? Status::XferTimeout : Status::Busy;
        case kIORetAborted:  return isTransfer ? Status::XferCancelled : Status::Busy;

        // ---- the device went away ------------------------------------------
        //
        // Distinguished from a transfer failure deliberately: a gone device must
        // become a port disconnect on the importer, not a failed URB that its
        // driver will retry against hardware that is no longer there.
        case kIORetNoDevice:
        case kIORetNotAttached:
        case kIORetOffline:
            return isTransfer ? Status::XferDeviceOffline : Status::DeviceGone;

        case kIORetNotResponding:
            return isTransfer ? Status::XferDeviceOffline : Status::DeviceGone;

        // ---- exclusivity and permission -------------------------------------
        case kIORetExclusiveAccess: return Status::ExclusivityDenied;
        case kIORetNotPermitted:    return Status::NotPermitted;
        case kIORetNotPrivileged:   return Status::NotPermitted;

        // ---- resources -------------------------------------------------------
        case kIORetNoMemory:
        case kIORetNoResources:
        case kIORetNoSpace:
            return Status::NoResources;
        case kUsbRetNoPower: return Status::NoResources;

        case kIORetBusy:     return Status::Busy;
        case kIORetNotReady: return Status::Busy;

        // ---- programming errors on our side ----------------------------------
        case kIORetBadArgument:  return Status::BadArgument;
        case kIORetUnsupported:  return Status::UnsupportedMessage;
        case kIORetBadMessageID: return Status::UnsupportedMessage;
        case kIORetNotFound:     return Status::NotFound;

        // A redundant setting is not a failure: asking for the alternate setting
        // that is already selected has achieved what was asked.
        case kUsbRetRedundant: return Status::Ok;

        // ---- bus-level failures -----------------------------------------------
        case kIORetIOError:
        case kIORetDeviceError:
            return isTransfer ? Status::XferProtocol : Status::ErrorGeneric;

        // kIOReturnNotOpen means we asked a closed object to do something, which
        // is our bug and never the peer's.
        case kIORetNotOpen: return Status::Internal;

        // This is FB16524420's code. It is deliberately NOT special-cased into
        // something friendlier: the diagnosis lives in the log line that carries
        // the raw IOReturn next to the operation that produced it.
        case kIORetInternalError: return Status::Internal;

        case kIORetError:
        default:
            // Unknown is reported as unknown. Guessing a specific transfer status
            // for a code we have never seen would put a confident wrong answer on
            // the wire, and the raw code is logged alongside so it can be added.
            return isTransfer ? Status::XferUnknown : Status::ErrorGeneric;
    }
}

const char* ioReturnName(std::uint32_t ioReturn) noexcept
{
    switch (ioReturn) {
        case kIORetSuccess:         return "kIOReturnSuccess";
        case kIORetError:           return "kIOReturnError";
        case kIORetNoMemory:        return "kIOReturnNoMemory";
        case kIORetNoResources:     return "kIOReturnNoResources";
        case kIORetNoDevice:        return "kIOReturnNoDevice";
        case kIORetNotPrivileged:   return "kIOReturnNotPrivileged";
        case kIORetBadArgument:     return "kIOReturnBadArgument";
        case kIORetExclusiveAccess: return "kIOReturnExclusiveAccess";
        case kIORetBadMessageID:    return "kIOReturnBadMessageID";
        case kIORetUnsupported:     return "kIOReturnUnsupported";
        case kIORetInternalError:   return "kIOReturnInternalError";
        case kIORetIOError:         return "kIOReturnIOError";
        case kIORetNotOpen:         return "kIOReturnNotOpen";
        case kIORetBusy:            return "kIOReturnBusy";
        case kIORetTimeout:         return "kIOReturnTimeout";
        case kIORetOffline:         return "kIOReturnOffline";
        case kIORetNotReady:        return "kIOReturnNotReady";
        case kIORetNotAttached:     return "kIOReturnNotAttached";
        case kIORetNoSpace:         return "kIOReturnNoSpace";
        case kIORetUnderrun:        return "kIOReturnUnderrun";
        case kIORetOverrun:         return "kIOReturnOverrun";
        case kIORetDeviceError:     return "kIOReturnDeviceError";
        case kIORetAborted:         return "kIOReturnAborted";
        case kIORetNotResponding:   return "kIOReturnNotResponding";
        case kIORetNotPermitted:    return "kIOReturnNotPermitted";
        case kIORetNotFound:        return "kIOReturnNotFound";
        case kUsbRetPipeStalled:    return "kUSBHostReturnPipeStalled";
        case kUsbRetNoPower:        return "kUSBHostReturnNoPower";
        case kUsbRetRedundant:      return "kUSBHostReturnRedundant";
        default:                    return "?";
    }
}

} // namespace airusb::macos
