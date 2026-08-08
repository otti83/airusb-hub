// AirUSB Hub — the immutable descriptor bundle (P1 plan §3.7)
//
// Everything the importer needs to present the device without a LAN round trip.
// Descriptor blobs are carried verbatim: AirUSB never rewrites a descriptor, so a
// SuperSpeed device arrives as a SuperSpeed device, companion descriptors and all.
//
// The manifest must be COMPLETE, not merely a cache, because Windows UdeCx demands
// the whole descriptor set before UdecxUsbDeviceCreate and then answers standard
// requests itself. On macOS completeness is what lets the importer answer kernel
// commands from local state instead of a network round trip -- and a command left
// unanswered past commandTimeoutThreshold is fatal.

#ifndef AIRUSB_CORE_DEVICEMANIFEST_H
#define AIRUSB_CORE_DEVICEMANIFEST_H

#include "Status.h"
#include "UsbTypes.h"

#include <cstdint>
#include <functional>
#include <span>
#include <string>
#include <vector>

namespace airusb {

struct StringDescriptorEntry {
    std::uint8_t              index    = 0;
    std::uint16_t             langId   = 0;
    std::vector<std::uint8_t> blob;     ///< verbatim, including bLength/bDescriptorType
};

class DeviceManifest {
public:
    DeviceManifest() = default;

    // --- construction (exporter side) ---------------------------------------
    void setSpeed(Speed s) noexcept { _speed = s; }
    void setDeviceDescriptor(std::span<const std::uint8_t> blob);
    void addConfiguration(std::span<const std::uint8_t> blob);
    void setBos(std::span<const std::uint8_t> blob);
    void setDeviceQualifier(std::span<const std::uint8_t> blob);
    void setOtherSpeedConfig(std::span<const std::uint8_t> blob);
    void setLangIds(std::span<const std::uint16_t> langIds);
    void addString(std::uint8_t index, std::uint16_t langId, std::span<const std::uint8_t> blob);

    // --- access -------------------------------------------------------------
    Speed speed() const noexcept { return _speed; }
    DeviceIdentity identity() const noexcept;

    std::span<const std::uint8_t> deviceDescriptor() const noexcept { return _device; }
    std::span<const std::uint8_t> bos() const noexcept { return _bos; }
    std::span<const std::uint8_t> deviceQualifier() const noexcept { return _deviceQualifier; }
    std::span<const std::uint8_t> otherSpeedConfig() const noexcept { return _otherSpeedConfig; }

    std::size_t configurationCount() const noexcept { return _configs.size(); }

    /// By descriptor INDEX (0-based), which is what GET_DESCRIPTOR carries.
    std::span<const std::uint8_t> configurationByIndex(std::uint8_t index) const noexcept;

    /// By bConfigurationValue, which is what SET_CONFIGURATION carries. These are
    /// not the same number and conflating them is a classic enumeration bug.
    std::span<const std::uint8_t> configurationByValue(std::uint8_t value) const noexcept;

    /// String descriptor index 0 is the LANGID table, not a string.
    std::span<const std::uint8_t> stringDescriptor(std::uint8_t index, std::uint16_t langId) const noexcept;
    std::span<const std::uint8_t> langIdTable() const noexcept { return _langIdTable; }

    /// Endpoints of the given interface/alt in the given configuration value,
    /// parsed from the verbatim configuration blob including SuperSpeed companions.
    std::vector<EndpointModel> endpointsFor(std::uint8_t configValue,
                                            std::uint8_t interfaceNumber,
                                            std::uint8_t altSetting) const;

    /// Total serialized size, checked against the 256 KiB manifest ceiling (R9).
    std::size_t byteSize() const noexcept;

    /// Structural validation. Every bLength/wTotalLength walk is re-validated here
    /// independently of protocol/, which treats descriptor blobs as opaque (R10).
    /// Also cross-checks the descriptors against the declared speed, because
    /// a backend that cannot report SuperSpeed would otherwise silently present a
    /// SuperSpeed descriptor set as High Speed.
    Status validate(std::string* whyNot = nullptr) const;

private:
    Speed _speed = Speed::None;
    std::vector<std::uint8_t> _device;
    std::vector<std::vector<std::uint8_t>> _configs;
    std::vector<std::uint8_t> _bos;
    std::vector<std::uint8_t> _deviceQualifier;
    std::vector<std::uint8_t> _otherSpeedConfig;
    std::vector<std::uint8_t> _langIdTable;
    std::vector<StringDescriptorEntry> _strings;
};

/// Walk a configuration blob and invoke `fn(type, blob)` for each descriptor.
/// Returns false on any malformed bLength or a walk that overruns wTotalLength --
/// the bug class that lets a hostile manifest walk off the end of a buffer.
bool forEachDescriptor(std::span<const std::uint8_t> blob,
                       const std::function<bool(std::uint8_t type,
                                                std::span<const std::uint8_t>)>& fn) noexcept;

} // namespace airusb

#endif // AIRUSB_CORE_DEVICEMANIFEST_H
