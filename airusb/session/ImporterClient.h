// AirUSB Hub — the importer's side of a session.
//
// Connects, handshakes, lists what the peer offers, and attaches one device.
// What it does NOT do is present that device to an operating system: that is
// CiHostBackend on macOS, airusb.sys on Windows, the vhci shim on Linux. This
// class stops at handing back an IUsbDevicePort.
//
// The split is deliberate and is what makes the network testable on its own. A
// client that can attach a real drive and read sector 0 from it proves the
// protocol, the crypto, the exporter and the LAN — on any platform, with no
// driver, no entitlement and no signing.

#ifndef AIRUSB_SESSION_IMPORTERCLIENT_H
#define AIRUSB_SESSION_IMPORTERCLIENT_H

#include "RemoteDevicePort.h"
#include "SecureSession.h"
#include "../core/DeviceManifest.h"
#include "../core/Status.h"
#include "../core/UsbTypes.h"
#include "../protocol/ManifestCodec.h"
#include "../protocol/Messages.h"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace airusb::session {

class ImporterClient {
public:
    struct Config {
        const crypto::LocalIdentity* identity = nullptr;
        PeerStore*  peers = nullptr;
        std::string peerName;
        /// Blocks until the handshake finishes or this elapses.
        std::uint32_t handshakeTimeoutMs = 15000;
    };

    /// Takes the connected stream and drives the whole handshake.
    Status connect(std::unique_ptr<transport::IByteStream> stream, const Config& cfg);

    /// Pins whatever peer we just authenticated, with default grants.
    ///
    /// The real product shows the SAS and waits for a human. This is the
    /// headless equivalent and is named so it cannot be mistaken for one: it
    /// trusts on first use, which is a decision a person should be making.
    Status trustPeerWithoutConfirmation(const std::string& name);

    /// The same mechanism, with the promise the other name disclaims: a person
    /// was shown `sas()` and said it matched what the other machine showed.
    ///
    /// Two functions rather than a `bool confirmed` parameter, because the
    /// difference between them is not a behaviour, it is a claim about what
    /// happened outside the process — and a claim is worth a name. Grepping for
    /// the honest one has to keep working.
    Status trustPeerAfterSasConfirmed(const std::string& name);

    Status listDevices(std::vector<protocol::DeviceRecord>& out);

    /// PING, and the PONG that comes back, with the round trip in nanoseconds.
    ///
    /// A GUI that sits attached and idle otherwise has no way to tell a live
    /// link from a peer that went away: TCP will happily hold a socket open
    /// across a sleeping laptop for minutes. This is what lets the window say
    /// "connected" and mean it.
    Status ping(std::uint64_t* rttNs = nullptr);

    /// Attaches and returns a synchronous port for it (the BotProbe instrument).
    /// `slot` must be 1..15.
    Status attach(const protocol::DeviceUid& uid, std::uint8_t slot,
                  std::unique_ptr<RemoteDevicePort>& portOut,
                  std::string* whyNot = nullptr);

    /// Everything the ASYNCHRONOUS importer path needs from an attach: the live
    /// record layer, the attach id and slot, the manifest, the configuration the
    /// exporter captured the device in (for the vhci bridge's SET_CONFIGURATION
    /// policy), and the link speed (for the vhci port-half choice). Unlike
    /// `attach()`, it builds no `RemoteDevicePort` — the async data plane and
    /// `VhciNetBridge` drive the link directly.
    struct BridgeAttach {
        transport::RecordLayer* link             = nullptr;
        std::uint32_t           attachId         = 0;
        std::uint8_t            slot             = 0;
        std::uint8_t            capturedConfig   = 0;
        Speed                   speed            = Speed::None;
        std::uint32_t           maxTransferBytes = 0;
        DeviceManifest          manifest;
    };
    Status attachForBridge(const protocol::DeviceUid& uid, std::uint8_t slot,
                           BridgeAttach& out, std::string* whyNot = nullptr);

    Status detach();

    bool established() const noexcept { return _secure.established(); }
    Trust trust() const noexcept { return _secure.trust(); }
    std::uint32_t sas() const noexcept { return _secure.sas(); }
    const crypto::PeerIdentity& peerIdentity() const noexcept
    {
        return _secure.peerIdentity();
    }
    const std::string& failureReason() const noexcept { return _why; }

    transport::RecordLayer* transport() noexcept { return _secure.transport(); }

private:
    /// Sends one control message and waits for its reply, ignoring nothing:
    /// an unexpected type is reported rather than skipped.
    Status call(wire::Type type, std::span<const std::uint8_t> body,
                protocol::Header& replyHeader, std::vector<std::uint8_t>& replyBody);

    /// The shared ATTACH handshake: sends ATTACH, reads ATTACH_OK and the manifest,
    /// checks the speed agreement, and stamps `_attachId`/`_attachSlot`. Both
    /// `attach()` and `attachForBridge()` are thin wrappers over it.
    Status doAttach(const protocol::DeviceUid& uid, std::uint8_t slot,
                    protocol::AttachOkBody& ok, DeviceManifest& manifest,
                    protocol::ManifestHeader& mhdr, std::string* whyNot);

    SecureSession _secure;
    Config        _cfg;
    std::string   _why;
    std::uint64_t _requestId = 0;
    std::uint32_t _attachId  = 0;
    std::uint8_t  _attachSlot = 0;
};

} // namespace airusb::session

#endif // AIRUSB_SESSION_IMPORTERCLIENT_H
