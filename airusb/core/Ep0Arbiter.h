// AirUSB Hub — endpoint-0 request policy (P1 plan §4.3)
//
// Decides, for every control request the importing OS issues on endpoint 0,
// whether it is answered locally from the manifest, absorbed, converted into an
// AirUSB verb, forwarded verbatim to the remote device, or stalled.
//
// This is the highest-leverage piece of core logic: it is unit-testable with zero
// platform code, and it is the one place all three importer backends converge.
// macOS and Linux forward enumeration control transfers to the remote device;
// Windows UdeCx answers them itself from descriptors supplied up front. Putting
// the policy here means that difference is a backend detail, not a fork in the
// protocol.

#ifndef AIRUSB_CORE_EP0ARBITER_H
#define AIRUSB_CORE_EP0ARBITER_H

#include "DeviceManifest.h"
#include "Status.h"
#include "UsbTypes.h"

#include <cstdint>
#include <span>

namespace airusb {

enum class Ep0Disposition : std::uint8_t {
    Local,      ///< answer from the manifest or arbiter state; never reaches the wire
    Absorb,     ///< ack Success locally; never reaches the wire; no data
    Arbitrate,  ///< convert into an AirUSB control verb (see `verb`)
    Forward,    ///< send verbatim to the remote device as a control transfer
    Stall,      ///< refuse; would invalidate the manifest or corrupt state
};

/// The control verb an Arbitrate disposition maps to.
enum class Ep0Verb : std::uint8_t {
    None = 0,
    SetConfiguration,
    SetInterface,
    EpClearHalt,
};

struct Ep0Decision {
    Ep0Disposition disposition = Ep0Disposition::Forward;
    Ep0Verb        verb        = Ep0Verb::None;

    /// For Local: the bytes to return, already truncated to wLength per rule A-3.
    ///
    /// BORROWED, never owned. It points either into the manifest (valid as long as
    /// the manifest is alive) or into the arbiter's scratch byte for
    /// GET_CONFIGURATION / GET_INTERFACE. In the latter case it is only valid until
    /// the next decide() call on that arbiter — which is safe because decide() is
    /// called from exactly one strand and the response is consumed before the next
    /// request is dispatched. It is deliberately NOT stored inside Ep0Decision:
    /// a span pointing into its own struct would dangle the moment the decision
    /// was copied or returned by value.
    std::span<const std::uint8_t> data;

    /// For Local: true when the response is shorter than wLength, which the
    /// backend must report as a short transfer rather than padding.
    bool isShort = false;

    /// For Arbitrate: the verb's parameters, meaning depends on `verb`.
    std::uint16_t arg0 = 0;   ///< config value / interface number / endpoint address
    std::uint16_t arg1 = 0;   ///< alternate setting

    /// For Stall.
    Status status = Status::Ok;

    /// One-line reason, for @@AIRUSB_REQ@@ logging. Static storage.
    const char* reason = "";
};

class Ep0Arbiter {
public:
    explicit Ep0Arbiter(const DeviceManifest& manifest) noexcept;

    /// The policy table. Pure: no I/O, no allocation, no mutation except the
    /// configuration/alt-setting shadow updated by `commitVerb`.
    Ep0Decision decide(const SetupPacket& setup) const noexcept;

    /// Called once a verb the arbiter produced has been confirmed by the exporter,
    /// so GET_CONFIGURATION / GET_INTERFACE can be answered locally afterwards.
    /// Never called on failure: a rejected SET_CONFIGURATION must not move the
    /// shadow, or the arbiter starts lying to the guest about the device's state.
    void commitVerb(Ep0Verb verb, std::uint16_t arg0, std::uint16_t arg1) noexcept;

    std::uint8_t currentConfiguration() const noexcept { return _config; }
    std::uint8_t alternateSetting(std::uint8_t interfaceNumber) const noexcept;

    /// Bumped whenever the configuration or an alternate setting changes, so the
    /// exporter's pipe table can be invalidated (see §7.5 rebuildPipeTable).
    std::uint32_t generation() const noexcept { return _generation; }

private:
    Ep0Decision decideStandard(const SetupPacket& s) const noexcept;
    Ep0Decision descriptorResponse(const SetupPacket& s) const noexcept;

    const DeviceManifest& _manifest;
    std::uint8_t  _config     = 0;    ///< 0 = unconfigured
    std::uint8_t  _altSetting[32] = {};
    std::uint32_t _generation = 0;

    /// Backing storage for the one-byte GET_CONFIGURATION / GET_INTERFACE answers.
    /// mutable because decide() is logically const; see the lifetime note on
    /// Ep0Decision::data.
    mutable std::uint8_t _scratchConfig = 0;
    mutable std::uint8_t _scratchAlt    = 0;
};

const char* dispositionName(Ep0Disposition d) noexcept;
const char* verbName(Ep0Verb v) noexcept;

} // namespace airusb

#endif // AIRUSB_CORE_EP0ARBITER_H
