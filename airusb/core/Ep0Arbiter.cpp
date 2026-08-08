#include "Ep0Arbiter.h"

namespace airusb {

namespace {

Ep0Decision local(std::span<const std::uint8_t> blob, std::uint16_t wLength, const char* why)
{
    Ep0Decision d;
    d.disposition = Ep0Disposition::Local;
    d.reason      = why;

    // Rule A-3, mandatory. macOS enumeration asks for GET_DESCRIPTOR(DEVICE,
    // wLength=8) to learn bMaxPacketSize0, and GET_DESCRIPTOR(CONFIG, wLength=9)
    // to learn wTotalLength, before asking for the whole thing. Serving the full
    // blob against a 9-byte kernel buffer either overruns kernel memory or trips
    // R5, so a LOCAL response is always truncated to wLength.
    const std::size_t n = blob.size() < wLength ? blob.size() : wLength;
    d.data    = blob.first(n);
    d.isShort = n < wLength;
    return d;
}

Ep0Decision absorb(const char* why)
{
    Ep0Decision d;
    d.disposition = Ep0Disposition::Absorb;
    d.reason      = why;
    return d;
}

Ep0Decision forward(const char* why)
{
    Ep0Decision d;
    d.disposition = Ep0Disposition::Forward;
    d.reason      = why;
    return d;
}

Ep0Decision arbitrate(Ep0Verb v, std::uint16_t a0, std::uint16_t a1, const char* why)
{
    Ep0Decision d;
    d.disposition = Ep0Disposition::Arbitrate;
    d.verb        = v;
    d.arg0        = a0;
    d.arg1        = a1;
    d.reason      = why;
    return d;
}

Ep0Decision stall(Status s, const char* why)
{
    Ep0Decision d;
    d.disposition = Ep0Disposition::Stall;
    d.status      = s;
    d.reason      = why;
    return d;
}

} // namespace

// ---------------------------------------------------------------------------

Ep0Arbiter::Ep0Arbiter(const DeviceManifest& manifest) noexcept : _manifest(manifest) {}

std::uint8_t Ep0Arbiter::alternateSetting(std::uint8_t interfaceNumber) const noexcept
{
    return interfaceNumber < sizeof(_altSetting) ? _altSetting[interfaceNumber] : 0;
}

void Ep0Arbiter::commitVerb(Ep0Verb verb, std::uint16_t arg0, std::uint16_t arg1) noexcept
{
    switch (verb) {
        case Ep0Verb::SetConfiguration:
            _config = static_cast<std::uint8_t>(arg0);
            // A configuration change resets every interface to alt 0 (USB 2.0
            // §9.4.7). Forgetting this leaves the arbiter claiming an alt setting
            // the device no longer has.
            for (auto& a : _altSetting) a = 0;
            ++_generation;
            break;
        case Ep0Verb::SetInterface:
            if (arg0 < sizeof(_altSetting))
                _altSetting[arg0] = static_cast<std::uint8_t>(arg1);
            ++_generation;
            break;
        case Ep0Verb::EpClearHalt:
        case Ep0Verb::None:
            break;
    }
}

// ---------------------------------------------------------------------------

Ep0Decision Ep0Arbiter::descriptorResponse(const SetupPacket& s) const noexcept
{
    const std::uint8_t type  = static_cast<std::uint8_t>(s.wValue >> 8);
    const std::uint8_t index = static_cast<std::uint8_t>(s.wValue & 0xFFu);

    switch (type) {
        case kDescDevice:
            return local(_manifest.deviceDescriptor(), s.wLength, "GET_DESCRIPTOR(DEVICE)");

        case kDescConfiguration:
            return local(_manifest.configurationByIndex(index), s.wLength,
                         "GET_DESCRIPTOR(CONFIGURATION)");

        case kDescString:
            return local(_manifest.stringDescriptor(index, s.wIndex), s.wLength,
                         "GET_DESCRIPTOR(STRING)");

        case kDescBos:
            return local(_manifest.bos(), s.wLength, "GET_DESCRIPTOR(BOS)");

        case kDescDeviceQualifier:
            return local(_manifest.deviceQualifier(), s.wLength,
                         "GET_DESCRIPTOR(DEVICE_QUALIFIER)");

        case kDescOtherSpeedConfig:
            return local(_manifest.otherSpeedConfig(), s.wLength,
                         "GET_DESCRIPTOR(OTHER_SPEED_CONFIG)");

        default:
            // Class- or vendor-defined descriptor types (HID Report, for example)
            // are not in the manifest and only the device knows them.
            return forward("GET_DESCRIPTOR(class/vendor type)");
    }
}

Ep0Decision Ep0Arbiter::decideStandard(const SetupPacket& s) const noexcept
{
    switch (s.bRequest) {
        case kGetDescriptor:
            return descriptorResponse(s);

        case kSetAddress:
            // Never reaches the wire. macOS assigns the address via
            // IOUSBHostCIDeviceStateMachine respondToCommand:status:deviceAddress:,
            // UdeCx and vhci absorb it, and the remote device already holds an
            // address on its own real bus.
            return absorb("SET_ADDRESS absorbed; the device is already addressed on its own bus");

        case kSetConfiguration:
            return arbitrate(Ep0Verb::SetConfiguration,
                             static_cast<std::uint16_t>(s.wValue & 0xFFu), 0,
                             "SET_CONFIGURATION");

        case kSetInterface:
            return arbitrate(Ep0Verb::SetInterface, s.wIndex, s.wValue, "SET_INTERFACE");

        case kGetConfiguration:
            _scratchConfig = _config;
            return local(std::span<const std::uint8_t>(&_scratchConfig, 1), s.wLength,
                         "GET_CONFIGURATION from arbiter state");

        case kGetInterface: {
            _scratchAlt = alternateSetting(static_cast<std::uint8_t>(s.wIndex & 0xFFu));
            return local(std::span<const std::uint8_t>(&_scratchAlt, 1), s.wLength,
                         "GET_INTERFACE from arbiter state");
        }

        case kGetStatus:
            // FORWARD for every recipient. The endpoint HALT bit is live device
            // truth and is exactly what a class driver queries to decide whether
            // recovery is needed. Serving it from cache wedges the drive
            // permanently, because the driver would never see the halt clear.
            return forward("GET_STATUS is live device state, never cached");

        case kClearFeature:
            if (s.recipient() == kRcpEndpoint && s.wValue == kFeatEndpointHalt) {
                // Maps to -clearStallWithError:, which clears the device stall AND
                // the exporter host controller's data toggle. A raw forward clears
                // only the former, leaving the toggle desynchronised and every
                // subsequent transfer on that endpoint silently wrong.
                return arbitrate(Ep0Verb::EpClearHalt, s.wIndex, 0,
                                 "CLEAR_FEATURE(ENDPOINT_HALT) -> EP_CLEAR_HALT verb");
            }
            [[fallthrough]];
        case kSetFeature: {
            const std::uint16_t f = s.wValue;
            if (f == kFeatDeviceRemoteWakeup || f == kFeatU1Enable
                || f == kFeatU2Enable || f == kFeatLtmEnable) {
                // Link-power parameters are meaningless across a LAN, and
                // forwarding them drops the EXPORTER's real link into U1/U2 and
                // destroys throughput.
                return absorb("link-power feature absorbed; meaningless across a LAN");
            }
            if (s.bRequest == kSetFeature && f == kFeatTestMode)
                return stall(Status::NotPermitted, "SET_FEATURE(TEST_MODE) refused");
            if (s.recipient() == kRcpEndpoint && f == kFeatEndpointHalt)
                return forward("SET_FEATURE(ENDPOINT_HALT)");
            return forward("SET/CLEAR_FEATURE, other selector");
        }

        case kSetDescriptor:
            // Would invalidate the manifest the importer has already published to
            // its own kernel, and on Windows the descriptors are baked into the
            // UDE device at creation and cannot change at all.
            return stall(Status::NotPermitted, "SET_DESCRIPTOR refused; would invalidate the manifest");

        case kSetSel:
        case kSetIsochDelay:
            return absorb("SET_SEL / SET_ISOCH_DELAY absorbed; latency parameters are local");

        default:
            return forward("unrecognised standard request");
    }
}

Ep0Decision Ep0Arbiter::decide(const SetupPacket& s) const noexcept
{
    if (s.isStandard()) return decideStandard(s);

    // Class and vendor requests, any recipient, always go to the device. This
    // deliberately includes mass-storage Bulk-Only Reset (0x21/0xFF) and
    // GET_MAX_LUN (0xA1/0xFE): they are how the class driver recovers, and
    // answering them locally would break recovery in the exact situation where it
    // matters most.
    return forward(s.isClass() ? "class request forwarded" : "vendor request forwarded");
}

// ---------------------------------------------------------------------------

const char* dispositionName(Ep0Disposition d) noexcept
{
    switch (d) {
        case Ep0Disposition::Local:     return "LOCAL";
        case Ep0Disposition::Absorb:    return "ABSORB";
        case Ep0Disposition::Arbitrate: return "ARBITRATE";
        case Ep0Disposition::Forward:   return "FORWARD";
        case Ep0Disposition::Stall:     return "STALL";
    }
    return "?";
}

const char* verbName(Ep0Verb v) noexcept
{
    switch (v) {
        case Ep0Verb::None:             return "none";
        case Ep0Verb::SetConfiguration: return "SET_CONFIGURATION";
        case Ep0Verb::SetInterface:     return "SET_INTERFACE";
        case Ep0Verb::EpClearHalt:      return "EP_CLEAR_HALT";
    }
    return "?";
}

} // namespace airusb
