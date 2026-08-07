#include "Status.h"
#include "../protocol/Wire.h"

#include <cstddef>

namespace airusb {

namespace {

struct Entry { Status s; const char* name; };

// One table, used by BOTH statusName and isKnownStatus, so the two can never
// disagree about which statuses exist.
constexpr Entry kTable[] = {
    { Status::Ok,                 "OK" },

    { Status::ErrorGeneric,       "ERROR_GENERIC" },
    { Status::BadArgument,        "BAD_ARGUMENT" },
    { Status::UnsupportedVersion, "UNSUPPORTED_VERSION" },
    { Status::UnsupportedMessage, "UNSUPPORTED_MESSAGE" },
    { Status::MalformedFrame,     "MALFORMED_FRAME" },
    { Status::LimitExceeded,      "LIMIT_EXCEEDED" },
    { Status::NotPermitted,       "NOT_PERMITTED" },
    { Status::NotPaired,          "NOT_PAIRED" },
    { Status::AuthFailed,         "AUTH_FAILED" },
    { Status::NoResources,        "NO_RESOURCES" },
    { Status::Busy,               "BUSY" },
    { Status::NotFound,           "NOT_FOUND" },
    { Status::AlreadyExists,      "ALREADY_EXISTS" },
    { Status::Internal,           "INTERNAL" },
    { Status::TransportLost,      "TRANSPORT_LOST" },
    { Status::AlreadyCompleted,   "ALREADY_COMPLETED" },

    { Status::DeviceGone,         "DEVICE_GONE" },
    { Status::Detaching,          "DETACHING" },
    { Status::ExclusivityDenied,  "EXCLUSIVITY_DENIED" },
    { Status::CaptureFailed,      "CAPTURE_FAILED" },
    { Status::AttachUnknown,      "ATTACH_UNKNOWN" },
    { Status::ManifestInvalid,    "MANIFEST_INVALID" },
    { Status::SpeedUnsupported,   "SPEED_UNSUPPORTED" },
    { Status::MountedLocally,     "MOUNTED_LOCALLY" },

    { Status::XferStall,          "XFER_STALL" },
    { Status::XferTimeout,        "XFER_TIMEOUT" },
    { Status::XferCancelled,      "XFER_CANCELLED" },
    { Status::XferShort,          "XFER_SHORT" },
    { Status::XferOverrun,        "XFER_OVERRUN" },
    { Status::XferUnderrun,       "XFER_UNDERRUN" },
    { Status::XferCrc,            "XFER_CRC" },
    { Status::XferBitstuff,       "XFER_BITSTUFF" },
    { Status::XferProtocol,       "XFER_PROTOCOL" },
    { Status::XferNoBandwidth,    "XFER_NO_BANDWIDTH" },
    { Status::XferMissedService,  "XFER_MISSED_SERVICE" },
    { Status::XferEpStopped,      "XFER_EP_STOPPED" },
    { Status::XferDeviceOffline,  "XFER_DEVICE_OFFLINE" },
    { Status::XferNakTimeout,     "XFER_NAK_TIMEOUT" },
    { Status::XferBadToggle,      "XFER_BAD_TOGGLE" },
    { Status::XferStreamError,    "XFER_STREAM_ERROR" },
    { Status::XferUnknown,        "XFER_UNKNOWN" },
};

} // namespace

bool isKnownStatus(std::uint16_t raw) noexcept
{
    for (const Entry& e : kTable)
        if (static_cast<std::uint16_t>(e.s) == raw) return true;
    return false;
}

const char* statusName(Status s) noexcept
{
    for (const Entry& e : kTable)
        if (e.s == s) return e.name;
    return "UNKNOWN";
}

} // namespace airusb

namespace airusb::wire {

std::size_t fixedBodySize(std::uint8_t type, bool* known) noexcept
{
    if (known) *known = true;

    switch (static_cast<Type>(type)) {
        case Type::Hello:
        case Type::HelloOk:          return kBodyHello;
        case Type::Ping:
        case Type::Pong:             return kBodyPing;
        case Type::Error:            return kBodyError;
        case Type::Submit:           return kBodySubmit;
        case Type::Complete:         return kBodyComplete;
        case Type::Cancel:           return kBodyCancel;
        case Type::CancelAck:        return kBodyCancelAck;
        case Type::Data:             return kBodyData;

        // Known types whose bodies are TLV-only in v1.
        case Type::Goodbye:
        case Type::PairRequest:
        case Type::PairConfirm:
        case Type::PairResult:
        case Type::ListDevices:
        case Type::DeviceList:
        case Type::DeviceEvent:
        case Type::Attach:
        case Type::AttachOk:
        case Type::DeviceManifest:
        case Type::Detach:
        case Type::DetachOk:
        case Type::DeviceGone:
        case Type::AttachCredit:
        case Type::SetConfiguration:
        case Type::SetInterface:
        case Type::EpClearHalt:
        case Type::DeviceReset:
        case Type::SuspendIo:
        case Type::ResumeIo:
        case Type::CtrlAck:          return 0;

        // Reserved for Phase 4. Not implemented, so treated as unknown: a peer
        // sending these to a v1 build is asking for behaviour we do not have.
        case Type::LinkJoin:
        case Type::LinkJoinOk:
        case Type::Resume:
        case Type::ResumeOk:
        case Type::ResumeRefused:
            break;
    }

    if (known) *known = false;
    return 0;
}

} // namespace airusb::wire
