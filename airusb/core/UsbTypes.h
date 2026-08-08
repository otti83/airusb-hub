// AirUSB Hub — USB primitives shared by core, protocol and every backend.
// Pure values. No IOKit, no Windows DDI, no sockets.

#ifndef AIRUSB_CORE_USBTYPES_H
#define AIRUSB_CORE_USBTYPES_H

#include <cstdint>

namespace airusb {

enum class Speed : std::uint8_t {
    None = 0, Full, Low, High, Super, SuperPlus, SuperPlusBy2, Other,
};

enum class XferType : std::uint8_t { Control = 0, Isochronous = 1, Bulk = 2, Interrupt = 3 };
enum class Dir      : std::uint8_t { Out = 0, In = 1 };

// --- SETUP packet (USB 3.2 §9.3) --------------------------------------------

struct SetupPacket {
    std::uint8_t  bmRequestType = 0;
    std::uint8_t  bRequest      = 0;
    std::uint16_t wValue        = 0;
    std::uint16_t wIndex        = 0;
    std::uint16_t wLength       = 0;

    // bmRequestType decomposition
    constexpr Dir direction() const noexcept
    {
        return (bmRequestType & 0x80u) ? Dir::In : Dir::Out;
    }
    constexpr std::uint8_t type()      const noexcept { return (bmRequestType >> 5) & 0x03u; }
    constexpr std::uint8_t recipient() const noexcept { return bmRequestType & 0x1Fu; }

    constexpr bool isStandard() const noexcept { return type() == 0; }
    constexpr bool isClass()    const noexcept { return type() == 1; }
    constexpr bool isVendor()   const noexcept { return type() == 2; }
};

enum RequestType : std::uint8_t { kReqStandard = 0, kReqClass = 1, kReqVendor = 2 };
enum Recipient   : std::uint8_t { kRcpDevice = 0, kRcpInterface = 1, kRcpEndpoint = 2, kRcpOther = 3 };

// --- standard requests (USB 2.0 §9.4) ---------------------------------------

enum StandardRequest : std::uint8_t {
    kGetStatus        = 0x00,
    kClearFeature     = 0x01,
    kSetFeature       = 0x03,
    kSetAddress       = 0x05,
    kGetDescriptor    = 0x06,
    kSetDescriptor    = 0x07,
    kGetConfiguration = 0x08,
    kSetConfiguration = 0x09,
    kGetInterface     = 0x0A,
    kSetInterface     = 0x0B,
    kSynchFrame       = 0x0C,
    kSetSel           = 0x30,
    kSetIsochDelay    = 0x31,
};

enum DescriptorType : std::uint8_t {
    kDescDevice             = 0x01,
    kDescConfiguration      = 0x02,
    kDescString             = 0x03,
    kDescInterface          = 0x04,
    kDescEndpoint           = 0x05,
    kDescDeviceQualifier    = 0x06,
    kDescOtherSpeedConfig   = 0x07,
    kDescInterfacePower     = 0x08,
    kDescOtg                = 0x09,
    kDescBos                = 0x0F,
    kDescDeviceCapability   = 0x10,
    kDescSsEndpointCompanion= 0x30,   // SuperSpeed Endpoint Companion
};

enum FeatureSelector : std::uint16_t {
    kFeatEndpointHalt      = 0,
    kFeatDeviceRemoteWakeup= 1,
    kFeatTestMode          = 2,
    kFeatU1Enable          = 48,
    kFeatU2Enable          = 49,
    kFeatLtmEnable         = 50,
};

// --- endpoint model ---------------------------------------------------------

struct EndpointModel {
    std::uint8_t  address       = 0;   ///< bEndpointAddress, direction bit included
    XferType      type          = XferType::Bulk;
    std::uint16_t maxPacketSize = 0;
    std::uint8_t  interval      = 0;
    std::uint8_t  maxBurst      = 0;   ///< SuperSpeed companion bMaxBurst
    std::uint8_t  mult          = 0;   ///< SuperSpeed companion, isochronous
    std::uint16_t bytesPerInterval = 0;

    constexpr std::uint8_t number() const noexcept { return address & 0x0Fu; }
    constexpr Dir direction() const noexcept
    {
        return (address & 0x80u) ? Dir::In : Dir::Out;
    }
};

/// A device's identity as shown to the user and matched against pairing grants.
struct DeviceIdentity {
    std::uint16_t vendorId   = 0;
    std::uint16_t productId  = 0;
    std::uint16_t bcdDevice  = 0;
    std::uint8_t  deviceClass= 0;
    std::uint8_t  subClass   = 0;
    std::uint8_t  protocol   = 0;
    Speed         speed      = Speed::None;
};

const char* speedName(Speed s) noexcept;

} // namespace airusb

#endif // AIRUSB_CORE_USBTYPES_H
