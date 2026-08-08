// AirUSB Hub — DEVICE_MANIFEST on the wire (P1 plan §3.7).
//
// The manifest is a COMPLETENESS CONTRACT, not a cache. Windows UdeCx demands
// the entire descriptor set before UdecxUsbDeviceCreate and then answers standard
// requests itself, so a missing string descriptor is not a slow path — it is a
// device that cannot be created. On macOS completeness is what lets the importer
// answer kernel commands from local state instead of a LAN round trip, and a
// command left unanswered past commandTimeoutThreshold is fatal.
//
// DESCRIPTOR BYTES TRAVEL VERBATIM, ALWAYS
//
// Every blob is carried exactly as the device produced it. Nothing is
// re-serialized, reordered, padded or "normalised". A SuperSpeed device must
// arrive as a SuperSpeed device, companion descriptors and all — the moment this
// layer starts rewriting descriptors, the importer is presenting a device that
// does not exist, and the guest OS is the one that finds out.
//
// This layer treats the blobs as opaque. It checks lengths and counts; what the
// bytes mean is core/DeviceManifest's business (R10).

#ifndef AIRUSB_PROTOCOL_MANIFESTCODEC_H
#define AIRUSB_PROTOCOL_MANIFESTCODEC_H

#include "Wire.h"
#include "../core/DeviceManifest.h"
#include "../core/Status.h"

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace airusb::protocol {

/// Fixed part of DEVICE_MANIFEST (0x22), B = 32.
struct ManifestHeader {
    std::uint32_t manifestVersion   = 1;
    std::uint32_t configCount       = 0;   ///< <= 8
    std::uint32_t stringCount       = 0;   ///< <= 128
    std::uint32_t langidCount       = 0;   ///< <= 16
    std::uint16_t speed             = 0;   ///< MUST equal ATTACH_OK.speed
    std::uint16_t dflags            = 0;   ///< bit0 self-powered, 1 remote-wakeup,
                                           ///< 2 USB3 streams, 3 composite
    std::uint32_t totalBlobBytes    = 0;   ///< <= 256 KiB
    std::uint8_t  currentConfigValue = 0;
};

inline constexpr std::size_t kManifestHeaderSize = 32;
inline constexpr std::uint32_t kMaxConfigs = 8;
inline constexpr std::uint32_t kMaxStrings = 128;
inline constexpr std::uint32_t kMaxLangIds = 16;

/// Serialises a manifest into a DEVICE_MANIFEST body: the 32-byte header, then
/// TLV sections carrying the raw descriptor bytes, then MANIFEST_HASH.
///
/// The hash is over the concatenated blob sections in the order written, so a
/// receiver that reassembles them differently gets a different hash and refuses
/// rather than silently accepting a manifest it rebuilt.
Status encodeManifest(const DeviceManifest& m,
                      std::uint8_t currentConfigValue,
                      std::vector<std::uint8_t>& out);

/// Parses a DEVICE_MANIFEST body.
///
/// Rejects — rather than repairs — a body whose declared counts disagree with the
/// TLVs present, whose blob total exceeds the 256 KiB ceiling, or whose hash does
/// not match. `whyNot` is filled with a reason suitable for a log line.
///
/// A manifest is the first structured thing an authenticated peer sends that is
/// large, variable-length and attacker-shaped, so every length is checked against
/// the bytes actually present before anything is allocated from it.
Status decodeManifest(std::span<const std::uint8_t> body,
                      DeviceManifest& out,
                      ManifestHeader& headerOut,
                      std::string* whyNot = nullptr);

/// The hash a receiver must reproduce. Exposed so a test can prove the hash
/// actually covers the blobs rather than trusting that it does.
void manifestHash(std::span<const std::uint8_t> blobSections,
                  std::uint8_t out[32]);

} // namespace airusb::protocol

#endif // AIRUSB_PROTOCOL_MANIFESTCODEC_H
