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
#include "../core/Status.h"
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

    Status listDevices(std::vector<protocol::DeviceRecord>& out);

    /// Attaches and returns a port for it. `slot` must be 1..15.
    Status attach(const protocol::DeviceUid& uid, std::uint8_t slot,
                  std::unique_ptr<RemoteDevicePort>& portOut,
                  std::string* whyNot = nullptr);

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

    SecureSession _secure;
    Config        _cfg;
    std::string   _why;
    std::uint64_t _requestId = 0;
    std::uint32_t _attachId  = 0;
    std::uint8_t  _attachSlot = 0;
};

} // namespace airusb::session

#endif // AIRUSB_SESSION_IMPORTERCLIENT_H
