#include "ManifestCodec.h"

#include "Codec.h"
#include "../crypto/Primitives.h"

#include <cstring>

namespace airusb::protocol {

namespace {

std::span<const std::uint8_t> asBytes(const std::vector<std::uint8_t>& v) noexcept
{
    return std::span<const std::uint8_t>(v.data(), v.size());
}

/// STRING_DESC value layout: `u8 index; u16 langid; u16 len; bytes`.
inline constexpr std::size_t kStringDescPrefix = 5;

} // namespace

void manifestHash(std::span<const std::uint8_t> blobSections, std::uint8_t out[32])
{
    // P1 plan §3.7 specified SHA-256. BLAKE2s-256 is used instead, for the same
    // reason the fingerprint moved: it is the hash the handshake already
    // requires, and adding a second one to compute an internal consistency check
    // is not worth the extra primitive.
    //
    // This is an integrity check, not a security boundary — the manifest arrives
    // inside an authenticated, encrypted Noise session, so an attacker cannot
    // alter it in flight. What the hash catches is a receiver that reassembled
    // the sections differently from the sender, which is a bug, not an attack.
    const crypto::Hash h = crypto::blake2s(blobSections);
    std::memcpy(out, h.data(), h.size());
}

// ---------------------------------------------------------------------------
// encode
// ---------------------------------------------------------------------------

Status encodeManifest(const DeviceManifest& m,
                      std::uint8_t currentConfigValue,
                      std::vector<std::uint8_t>& out)
{
    // The manifest must be structurally valid before it is serialised. Sending a
    // manifest we would refuse to receive is how a peer ends up debugging our bug.
    if (m.validate() != Status::Ok) return Status::ManifestInvalid;

    const std::size_t configCount = m.configurationCount();
    if (configCount == 0 || configCount > kMaxConfigs) return Status::ManifestInvalid;

    // ---- collect the blob sections first ---------------------------------
    //
    // Built separately from the header because the header carries their total
    // size and their hash, and neither is known until they exist.
    std::vector<std::uint8_t> blobs;

    const auto dev = m.deviceDescriptor();
    if (dev.size() < 18) return Status::ManifestInvalid;
    appendTlv(wire::Tlv::DeviceDesc, dev, blobs);

    for (std::size_t i = 0; i < configCount; ++i) {
        const auto cfg = m.configurationByIndex(static_cast<std::uint8_t>(i));
        if (cfg.size() < 9) return Status::ManifestInvalid;
        appendTlv(wire::Tlv::ConfigDesc, cfg, blobs);
    }

    if (const auto bos = m.bos(); !bos.empty())
        appendTlv(wire::Tlv::BosDesc, bos, blobs);
    if (const auto dq = m.deviceQualifier(); !dq.empty())
        appendTlv(wire::Tlv::DeviceQualifierDesc, dq, blobs);
    if (const auto osc = m.otherSpeedConfig(); !osc.empty())
        appendTlv(wire::Tlv::OtherSpeedConfigDesc, osc, blobs);

    const auto langIds = m.langIdTable();
    std::uint32_t langidCount = 0;
    if (!langIds.empty()) {
        appendTlv(wire::Tlv::LangidTable, langIds, blobs);
        // The table is `bLength, bDescriptorType, then u16 per language`.
        langidCount = static_cast<std::uint32_t>((langIds.size() - 2) / 2);
        if (langidCount > kMaxLangIds) return Status::ManifestInvalid;
    }

    // ---- strings ----------------------------------------------------------
    //
    // Every index referenced by any descriptor, for every declared LANGID. The
    // manifest carries them because UdeCx answers GET_DESCRIPTOR(STRING) itself
    // and cannot ask us later.
    std::uint32_t stringCount = 0;
    for (std::uint32_t li = 0; li < langidCount; ++li) {
        const std::uint16_t lang = static_cast<std::uint16_t>(
            langIds[2 + li * 2] | (langIds[3 + li * 2] << 8));

        for (std::uint32_t idx = 1; idx <= 255; ++idx) {
            const auto s = m.stringDescriptor(static_cast<std::uint8_t>(idx), lang);
            if (s.empty()) continue;
            if (++stringCount > kMaxStrings) return Status::ManifestInvalid;

            std::vector<std::uint8_t> v(kStringDescPrefix + s.size());
            v[0] = static_cast<std::uint8_t>(idx);
            wr_u16(v.data() + 1, lang);
            wr_u16(v.data() + 3, static_cast<std::uint16_t>(s.size()));
            std::memcpy(v.data() + kStringDescPrefix, s.data(), s.size());
            appendTlv(wire::Tlv::StringDesc, asBytes(v), blobs);
        }
    }

    if (blobs.size() > wire::kManifestBytesMax) return Status::LimitExceeded;

    // ---- header ------------------------------------------------------------
    const std::size_t at = out.size();
    out.resize(at + kManifestHeaderSize);
    std::uint8_t* h = out.data() + at;
    std::memset(h, 0, kManifestHeaderSize);

    wr_u32(h + 0,  1);
    wr_u32(h + 4,  static_cast<std::uint32_t>(configCount));
    wr_u32(h + 8,  stringCount);
    wr_u32(h + 12, langidCount);
    wr_u16(h + 16, static_cast<std::uint16_t>(m.speed()));
    wr_u16(h + 18, 0);                                  // dflags, filled by the caller later
    wr_u32(h + 20, static_cast<std::uint32_t>(blobs.size()));
    h[24] = currentConfigValue;

    out.insert(out.end(), blobs.begin(), blobs.end());

    // ---- hash, over the blob sections exactly as written -------------------
    std::uint8_t digest[32];
    manifestHash(asBytes(blobs), digest);
    appendTlv(wire::Tlv::ManifestHash,
              std::span<const std::uint8_t>(digest, sizeof digest), out);
    return Status::Ok;
}

// ---------------------------------------------------------------------------
// decode
// ---------------------------------------------------------------------------

Status decodeManifest(std::span<const std::uint8_t> body,
                      DeviceManifest& out,
                      ManifestHeader& headerOut,
                      std::string* whyNot)
{
    const auto fail = [&](Status s, const char* why) {
        if (whyNot) *whyNot = why;
        return s;
    };

    if (body.size() < kManifestHeaderSize)
        return fail(Status::MalformedFrame, "shorter than the manifest header");

    ManifestHeader hdr;
    hdr.manifestVersion    = rd_u32(body.data() + 0);
    hdr.configCount        = rd_u32(body.data() + 4);
    hdr.stringCount        = rd_u32(body.data() + 8);
    hdr.langidCount        = rd_u32(body.data() + 12);
    hdr.speed              = rd_u16(body.data() + 16);
    hdr.dflags             = rd_u16(body.data() + 18);
    hdr.totalBlobBytes     = rd_u32(body.data() + 20);
    hdr.currentConfigValue = body[24];

    if (hdr.manifestVersion != 1)
        return fail(Status::UnsupportedVersion, "manifest version is not 1");

    // Every declared count is bounded BEFORE anything is allocated from it. The
    // manifest is the first large, variable-length, peer-shaped structure in the
    // session; a count read out of it must never size a buffer unchecked.
    if (hdr.configCount == 0 || hdr.configCount > kMaxConfigs)
        return fail(Status::ManifestInvalid, "config count out of range");
    if (hdr.stringCount > kMaxStrings)
        return fail(Status::ManifestInvalid, "string count out of range");
    if (hdr.langidCount > kMaxLangIds)
        return fail(Status::ManifestInvalid, "langid count out of range");
    if (hdr.totalBlobBytes > wire::kManifestBytesMax)
        return fail(Status::LimitExceeded, "blob total exceeds the manifest ceiling");
    if (hdr.speed > static_cast<std::uint16_t>(Speed::Other))
        return fail(Status::ManifestInvalid, "speed out of range");

    const auto tlvs = body.subspan(kManifestHeaderSize);
    if (tlvs.size() < hdr.totalBlobBytes)
        return fail(Status::MalformedFrame, "body shorter than the declared blob total");

    // The blob sections are exactly the first totalBlobBytes of the TLV area;
    // MANIFEST_HASH follows them and is deliberately NOT hashed.
    const auto blobs = tlvs.subspan(0, hdr.totalBlobBytes);
    const auto trailer = tlvs.subspan(hdr.totalBlobBytes);

    DeviceManifest m;
    m.setSpeed(static_cast<Speed>(hdr.speed));

    std::uint32_t seenConfigs = 0, seenStrings = 0;
    bool seenDevice = false;
    bool structureOk = true;
    const char* why = "";

    const bool walked = forEachTlv(blobs, [&](const TlvView& t) {
        switch (static_cast<wire::Tlv>(t.type)) {
            case wire::Tlv::DeviceDesc:
                if (seenDevice) { structureOk = false; why = "two device descriptors"; return false; }
                if (t.value.size() < 18) { structureOk = false; why = "device descriptor too short"; return false; }
                m.setDeviceDescriptor(t.value);
                seenDevice = true;
                break;

            case wire::Tlv::ConfigDesc:
                if (++seenConfigs > hdr.configCount) {
                    structureOk = false; why = "more configurations than declared"; return false;
                }
                m.addConfiguration(t.value);
                break;

            case wire::Tlv::BosDesc:                 m.setBos(t.value); break;
            case wire::Tlv::DeviceQualifierDesc:     m.setDeviceQualifier(t.value); break;
            case wire::Tlv::OtherSpeedConfigDesc:    m.setOtherSpeedConfig(t.value); break;

            case wire::Tlv::LangidTable: {
                if (t.value.size() < 2 || (t.value.size() - 2) % 2 != 0) {
                    structureOk = false; why = "malformed LANGID table"; return false;
                }
                std::vector<std::uint16_t> ids;
                for (std::size_t at = 2; at + 1 < t.value.size(); at += 2)
                    ids.push_back(static_cast<std::uint16_t>(
                        t.value[at] | (t.value[at + 1] << 8)));
                if (ids.size() != hdr.langidCount) {
                    structureOk = false; why = "LANGID count disagrees with the header"; return false;
                }
                m.setLangIds(ids);
                break;
            }

            case wire::Tlv::StringDesc: {
                if (t.value.size() < kStringDescPrefix) {
                    structureOk = false; why = "string descriptor TLV too short"; return false;
                }
                const std::uint8_t  index = t.value[0];
                const std::uint16_t lang  = rd_u16(t.value.data() + 1);
                const std::uint16_t len   = rd_u16(t.value.data() + 3);
                // The inner length must agree with the bytes present; trusting it
                // over the TLV would read past the value.
                if (t.value.size() != kStringDescPrefix + len) {
                    structureOk = false; why = "string descriptor length disagrees with its TLV"; return false;
                }
                if (++seenStrings > hdr.stringCount) {
                    structureOk = false; why = "more strings than declared"; return false;
                }
                m.addString(index, lang, t.value.subspan(kStringDescPrefix));
                break;
            }

            default:
                // Unknown TLVs are ignored by design (§3.0) — that is the
                // extension point. Anything semantics-bearing gets a new
                // manifest_version, not a silently-added TLV.
                break;
        }
        return true;
    });

    if (!walked)     return fail(Status::MalformedFrame, "TLV walk overran the blob sections");
    if (!structureOk) return fail(Status::ManifestInvalid, why);
    if (!seenDevice)  return fail(Status::ManifestInvalid, "no device descriptor");
    if (seenConfigs != hdr.configCount)
        return fail(Status::ManifestInvalid, "fewer configurations than declared");
    if (seenStrings != hdr.stringCount)
        return fail(Status::ManifestInvalid, "fewer strings than declared");

    // ---- hash ---------------------------------------------------------------
    bool hashSeen = false, hashOk = false;
    forEachTlv(trailer, [&](const TlvView& t) {
        if (static_cast<wire::Tlv>(t.type) != wire::Tlv::ManifestHash) return true;
        hashSeen = true;
        if (t.value.size() != 32) return false;
        std::uint8_t expect[32];
        manifestHash(blobs, expect);
        hashOk = crypto::constantTimeEquals(
            std::span<const std::uint8_t>(expect, sizeof expect), t.value);
        return false;
    });

    if (!hashSeen) return fail(Status::ManifestInvalid, "no MANIFEST_HASH");
    if (!hashOk)   return fail(Status::ManifestInvalid,
                               "MANIFEST_HASH does not match the blob sections");

    // ---- and finally the structural rules the core owns ---------------------
    //
    // Re-validated on receive, independently of the sender. R10: this layer
    // treats descriptor blobs as opaque, so the walk that proves they are
    // well-formed has to happen here, on bytes a peer chose.
    std::string mwhy;
    if (const Status v = m.validate(&mwhy); v != Status::Ok) {
        if (whyNot) *whyNot = "manifest validation failed: " + mwhy;
        return v;
    }

    if (hdr.currentConfigValue != 0 &&
        m.configurationByValue(hdr.currentConfigValue).empty())
        return fail(Status::ManifestInvalid,
                    "current_config_value names no configuration");

    out       = std::move(m);
    headerOut = hdr;
    return Status::Ok;
}

} // namespace airusb::protocol
