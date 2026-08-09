#include "DeviceManifest.h"

#include <cstring>

namespace airusb {

namespace {

inline std::uint16_t rd16(const std::uint8_t* p) noexcept
{
    return static_cast<std::uint16_t>(p[0] | (static_cast<std::uint16_t>(p[1]) << 8));
}

std::vector<std::uint8_t> copyOf(std::span<const std::uint8_t> s)
{
    return std::vector<std::uint8_t>(s.begin(), s.end());
}

} // namespace

// ---------------------------------------------------------------------------

bool forEachDescriptor(std::span<const std::uint8_t> blob,
                       const std::function<bool(std::uint8_t, std::span<const std::uint8_t>)>& fn) noexcept
{
    std::size_t at = 0;
    while (at < blob.size()) {
        // Need at least bLength and bDescriptorType.
        if (blob.size() - at < 2) return false;

        const std::uint8_t bLength = blob[at];
        const std::uint8_t bType   = blob[at + 1];

        // A zero bLength would loop forever; a bLength past the end would walk off
        // the buffer. Both are the classic malformed-descriptor bug.
        if (bLength < 2) return false;
        if (blob.size() - at < bLength) return false;

        if (!fn(bType, blob.subspan(at, bLength))) return false;
        at += bLength;
    }
    return true;
}

// ---------------------------------------------------------------------------

void DeviceManifest::setDeviceDescriptor(std::span<const std::uint8_t> blob) { _device = copyOf(blob); }
void DeviceManifest::addConfiguration(std::span<const std::uint8_t> blob)   { _configs.push_back(copyOf(blob)); }
void DeviceManifest::setBos(std::span<const std::uint8_t> blob)             { _bos = copyOf(blob); }
void DeviceManifest::setDeviceQualifier(std::span<const std::uint8_t> b)    { _deviceQualifier = copyOf(b); }
void DeviceManifest::setOtherSpeedConfig(std::span<const std::uint8_t> b)   { _otherSpeedConfig = copyOf(b); }

void DeviceManifest::setLangIds(std::span<const std::uint16_t> langIds)
{
    // String descriptor index 0 is the LANGID table: bLength, bDescriptorType,
    // then one u16 per language.
    _langIdTable.clear();
    const std::size_t len = 2 + langIds.size() * 2;
    _langIdTable.push_back(static_cast<std::uint8_t>(len));
    _langIdTable.push_back(kDescString);
    for (std::uint16_t id : langIds) {
        _langIdTable.push_back(static_cast<std::uint8_t>(id & 0xFFu));
        _langIdTable.push_back(static_cast<std::uint8_t>(id >> 8));
    }
}

void DeviceManifest::addString(std::uint8_t index, std::uint16_t langId,
                               std::span<const std::uint8_t> blob)
{
    _strings.push_back(StringDescriptorEntry{index, langId, copyOf(blob)});
}

// ---------------------------------------------------------------------------

DeviceIdentity DeviceManifest::identity() const noexcept
{
    DeviceIdentity id;
    id.speed = _speed;
    if (_device.size() >= 18) {
        id.deviceClass = _device[4];
        id.subClass    = _device[5];
        id.protocol    = _device[6];
        id.vendorId    = rd16(_device.data() + 8);
        id.productId   = rd16(_device.data() + 10);
        id.bcdDevice   = rd16(_device.data() + 12);
    }
    return id;
}

std::span<const std::uint8_t> DeviceManifest::configurationByIndex(std::uint8_t index) const noexcept
{
    if (index >= _configs.size()) return {};
    return _configs[index];
}

std::span<const std::uint8_t> DeviceManifest::configurationByValue(std::uint8_t value) const noexcept
{
    // bConfigurationValue lives at offset 5 of the configuration descriptor. It is
    // NOT the descriptor index; conflating the two is a classic enumeration bug,
    // which is why these are two separate accessors rather than one.
    for (const auto& c : _configs)
        if (c.size() >= 9 && c[5] == value) return c;
    return {};
}

std::span<const std::uint8_t> DeviceManifest::stringDescriptor(std::uint8_t index,
                                                               std::uint16_t langId) const noexcept
{
    if (index == 0) return _langIdTable;
    for (const auto& s : _strings)
        if (s.index == index && s.langId == langId) return s.blob;
    return {};
}

std::size_t DeviceManifest::byteSize() const noexcept
{
    std::size_t n = _device.size() + _bos.size() + _deviceQualifier.size()
                  + _otherSpeedConfig.size() + _langIdTable.size();
    for (const auto& c : _configs) n += c.size();
    for (const auto& s : _strings) n += s.blob.size() + 4;
    return n;
}

// ---------------------------------------------------------------------------

std::vector<EndpointModel> DeviceManifest::endpointsFor(std::uint8_t configValue,
                                                        std::uint8_t interfaceNumber,
                                                        std::uint8_t altSetting) const
{
    std::vector<EndpointModel> out;
    auto cfg = configurationByValue(configValue);
    if (cfg.empty()) return out;

    bool inTarget = false;
    forEachDescriptor(cfg, [&](std::uint8_t type, std::span<const std::uint8_t> d) {
        if (type == kDescInterface && d.size() >= 9) {
            inTarget = (d[2] == interfaceNumber) && (d[3] == altSetting);
        } else if (type == kDescEndpoint && inTarget && d.size() >= 7) {
            EndpointModel ep;
            ep.address       = d[2];
            ep.type          = static_cast<XferType>(d[3] & 0x03u);
            ep.maxPacketSize = rd16(d.data() + 4);
            ep.interval      = d[6];
            out.push_back(ep);
        } else if (type == kDescSsEndpointCompanion && inTarget && d.size() >= 6) {
            // A SuperSpeed companion always follows the endpoint it describes, so
            // it belongs to the endpoint we appended last. Without this the burst
            // size is lost and a SuperSpeed device is driven as if it were USB 2.
            if (!out.empty()) {
                out.back().maxBurst         = d[2];
                out.back().mult             = static_cast<std::uint8_t>(d[3] & 0x03u);
                out.back().bytesPerInterval = rd16(d.data() + 4);
            }
        }
        return true;
    });
    return out;
}

bool DeviceManifest::findEndpoint(std::uint8_t configValue, std::uint8_t epAddr,
                                  const std::function<std::uint8_t(std::uint8_t)>& altOf,
                                  EndpointModel& out) const
{
    auto cfg = configurationByValue(configValue);
    if (cfg.empty()) return false;

    bool inActiveAlt = false;
    bool found       = false;

    forEachDescriptor(cfg, [&](std::uint8_t type, std::span<const std::uint8_t> d) {
        if (type == kDescInterface && d.size() >= 9) {
            const std::uint8_t iface = d[2];
            const std::uint8_t alt   = d[3];
            // The full 8-bit interface number, not 0..31. This is the range bug
            // the two bridges independently had; see the header.
            const std::uint8_t want = altOf ? altOf(iface) : 0;
            inActiveAlt = (alt == want);
        } else if (type == kDescEndpoint && inActiveAlt && d.size() >= 7 && !found) {
            if (d[2] == epAddr) {
                out = EndpointModel{};
                out.address       = d[2];
                out.type          = static_cast<XferType>(d[3] & 0x03u);
                out.maxPacketSize = rd16(d.data() + 4);
                out.interval      = d[6];
                found = true;
                return true;   // keep walking: the SS companion may still follow
            }
        } else if (type == kDescSsEndpointCompanion && found && d.size() >= 6) {
            // Only ever applies to the endpoint immediately before it, which is
            // the one just matched — so this must run before the walk stops.
            out.maxBurst         = d[2];
            out.mult             = static_cast<std::uint8_t>(d[3] & 0x03u);
            out.bytesPerInterval = rd16(d.data() + 4);
            return false;
        } else if (found && (type == kDescEndpoint || type == kDescInterface)) {
            return false;      // past our endpoint and its companion
        }
        return true;
    });

    return found;
}

// ---------------------------------------------------------------------------

Status DeviceManifest::validate(std::string* whyNot) const
{
    auto fail = [&](const char* m) {
        if (whyNot) *whyNot = m;
        return Status::ManifestInvalid;
    };

    if (_device.size() < 18)               return fail("device descriptor shorter than 18 bytes");
    if (_device[0] != _device.size())      return fail("device descriptor bLength disagrees with its size");
    if (_device[1] != kDescDevice)         return fail("device descriptor has the wrong bDescriptorType");

    const std::uint8_t numConfigs = _device[17];
    if (numConfigs == 0)                   return fail("bNumConfigurations is zero");
    if (_configs.size() != numConfigs)     return fail("configuration count disagrees with bNumConfigurations");

    for (const auto& c : _configs) {
        if (c.size() < 9)                  return fail("configuration descriptor shorter than 9 bytes");
        if (c[1] != kDescConfiguration)    return fail("configuration has the wrong bDescriptorType");
        const std::uint16_t total = rd16(c.data() + 2);
        if (total != c.size())             return fail("wTotalLength disagrees with the blob size");
        if (!forEachDescriptor(c, [](std::uint8_t, std::span<const std::uint8_t>) { return true; }))
            return fail("configuration descriptor walk is malformed");
    }

    // Speed consistency. bMaxPacketSize0 is an EXPONENT at SuperSpeed (9 -> 2^9 =
    // 512) and a byte count below it, so the two encodings are distinguishable and
    // a contradiction means the backend misreported the speed. This is exactly the
    // mistake that made a SuperSpeed test device look like High Speed during P1.
    const std::uint8_t  mps0   = _device[7];
    const std::uint16_t bcdUsb = rd16(_device.data() + 2);
    const bool superOrFaster = _speed == Speed::Super || _speed == Speed::SuperPlus
                            || _speed == Speed::SuperPlusBy2;

    if (superOrFaster) {
        if (mps0 != 9)     return fail("SuperSpeed requires bMaxPacketSize0 == 9 (2^9 = 512)");
        if (bcdUsb < 0x0300) return fail("SuperSpeed declared but bcdUSB < 0x0300");
        if (_bos.empty())  return fail("SuperSpeed requires a BOS descriptor");
    } else if (_speed == Speed::High) {
        if (mps0 != 64)    return fail("High Speed requires bMaxPacketSize0 == 64");
    } else if (_speed == Speed::Full || _speed == Speed::Low) {
        if (mps0 != 8 && mps0 != 16 && mps0 != 32 && mps0 != 64)
            return fail("Full/Low Speed bMaxPacketSize0 must be 8, 16, 32 or 64");
    } else {
        return fail("manifest declares no usable speed");
    }

    if (!_bos.empty()) {
        if (_bos.size() < 5)            return fail("BOS descriptor shorter than 5 bytes");
        if (_bos[1] != kDescBos)        return fail("BOS has the wrong bDescriptorType");
        if (rd16(_bos.data() + 2) != _bos.size())
            return fail("BOS wTotalLength disagrees with the blob size");
    }

    if (!_langIdTable.empty()) {
        if (_langIdTable.size() < 4)        return fail("LANGID table shorter than one entry");
        if (_langIdTable[1] != kDescString) return fail("LANGID table has the wrong bDescriptorType");
        if (_langIdTable[0] != _langIdTable.size())
            return fail("LANGID table bLength disagrees with its size");
    }

    // Every string must name a language that actually exists in the table,
    // otherwise the importer will answer GET_DESCRIPTOR(STRING) for a language the
    // guest was never told about.
    for (const auto& s : _strings) {
        if (s.blob.size() < 2)           return fail("string descriptor shorter than 2 bytes");
        if (s.blob[1] != kDescString)    return fail("string has the wrong bDescriptorType");
        if (s.blob[0] != s.blob.size())  return fail("string bLength disagrees with its size");
        bool known = false;
        for (std::size_t i = 2; i + 1 < _langIdTable.size(); i += 2)
            if (rd16(_langIdTable.data() + i) == s.langId) { known = true; break; }
        if (!known)                      return fail("string declares a LANGID absent from the table");
    }

    if (byteSize() > 256u * 1024u)       return fail("manifest exceeds the 256 KiB ceiling");

    if (whyNot) whyNot->clear();
    return Status::Ok;
}

} // namespace airusb
