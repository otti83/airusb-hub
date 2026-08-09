// AirUSB Hub — everything the window shows, and everything its buttons do.
//
// This is the product's state machine. The session layer below it knows how to
// carry USB over an authenticated network; it does not know that a person is
// watching, or that the person has to be asked something before a stranger's
// machine is trusted. That question is the whole reason this file exists.
//
// THE PAIRING GATE IS THE POINT
//
// `airusb-net` pins any peer that completes a handshake and says so in the log:
// "pinning it because this is a test tool". That is the correct behaviour for a
// test tool and the wrong behaviour for a product. Noise_XX authenticates that
// both ends hold the keys they claim; it cannot tell you the machine on the
// other end is the one you meant. Only the short authentication string can —
// two people, or one person at two screens, reading six digits and agreeing.
//
// So both roles STOP at `AwaitingApproval` and wait for a human. The exporter
// stops there too, which matters more than the importer: the importer risks
// attaching to the wrong drive, the exporter risks handing its drive to the
// wrong machine.
//
// WHY THE EXPORTER DROPS THE CONNECTION AFTER APPROVAL
//
// Grants are read at handshake time. A session that begins Unpaired stays
// Unpaired for its whole life, because pretending a mid-session pin applied
// retroactively would mean the exporter's own record of what it authorised is
// wrong. So approval pins and disconnects, and the peer reconnects into a
// session that really is paired. The importer does that reconnect by itself, so
// the person sees one dialog, not two.
//
// SINGLE-THREADED, LIKE EVERYTHING ABOVE IT
//
// `pump()` is called from the same loop that services HTTP. Actions that need a
// round trip (attach, verify) run inside their request and take milliseconds on
// a LAN. Nothing here is called from two threads, and nothing here is safe if
// it were.

#ifndef AIRUSB_CONTROL_HUBSTATE_H
#define AIRUSB_CONTROL_HUBSTATE_H

#include "HubFacade.h"

#include "../session/DevicePresenter.h"

#include "../core/Clock.h"
#include "../core/Platform.h"
#include "../core/Status.h"
#include "../crypto/Identity.h"
#include "../diag/BotProbe.h"
#include "../session/ExporterSession.h"
#include "../session/ImporterClient.h"
#include "../session/LeaseAuthority.h"
#include "../session/PeerStore.h"
#include "../session/SecureSession.h"

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace airusb::control {

class JsonOut;

/// What the sharing half is doing.
///
/// `AwaitingApproval` and `Serving` BOTH have a live ExporterSession under them.
/// That is not an oversight: §3.14 says an unpaired peer may send PING, PAIR_*
/// and GOODBYE and nothing else, and the session object enforces exactly that.
/// Refusing to run the session at all would look identical to a dead machine,
/// and the importer needs a heartbeat during pairing to notice the moment this
/// side accepts.
enum class ShareState {
    Off,
    Listening,          ///< socket open, nobody connected
    Handshaking,        ///< a peer connected, Noise is in progress
    AwaitingApproval,   ///< session live but unpaired; SAS on screen
    Serving,            ///< a paired peer has a session
};

/// What the importing half is doing.
enum class ImportState {
    Off,
    Connecting,
    AwaitingApproval,   ///< session live but we have not pinned them; SAS on screen
    WaitingForPeer,     ///< we pinned them; they have not pinned us yet
    Connected,          ///< paired both ways; devices listed
    Attached,           ///< one device leased, an IUsbDevicePort exists
};

const char* shareStateText(ShareState s) noexcept;
const char* importStateText(ImportState s) noexcept;

/// A device as the window lists it.
struct DeviceView {
    std::string   uid;          ///< 32 hex characters
    std::uint16_t vendorId  = 0;
    std::uint16_t productId = 0;
    std::uint8_t  speed     = 0;
    std::uint8_t  flags     = 0;
    std::string   name;
};

/// A one-use ticket that says "a person looked at THESE digits, for THIS
/// session, and said yes".
///
/// The reason it exists is that `shareApprove(true)` used to mean "pin whoever
/// is currently pending", which is a different sentence from the one the person
/// answered. A window a second out of date — the session replaced underneath
/// it, a new peer connected, a new SAS computed — would pin a machine whose
/// number nobody had ever compared, and the person at the screen has no way to
/// detect that. The nonce turns a stale answer into a refusal.
using ApprovalNonce = ApprovalTicket;

bool nonceIsZero(const ApprovalNonce& n) noexcept;

/// The authority itself. `IHubFacade` is how the routes reach it when it is in
/// this process; `BrokerFacade` is how they reach one that is not.
class HubState final : public IHubFacade {
public:
    struct Config {
        /// What this machine can offer. Null means "this build shares nothing",
        /// which is the honest state on a machine with no capture backend.
        session::IDeviceSource*      devices  = nullptr;
        const crypto::LocalIdentity* identity = nullptr;
        session::PeerStore*          peers    = nullptr;
        std::string                  peersPath;
        /// Shown to the peer, and stored beside its pin. Display only.
        std::string                  machineName;
        /// How this machine gives a remote device to its own operating system.
        /// Null means the read-only diagnostic probe, and the window is told so
        /// rather than left to assume — see DevicePresenter.h for why that
        /// distinction is the whole point.
        session::IDevicePresenter*   presenter = nullptr;
    };

    Status begin(const Config& cfg);

    /// Services the sharing listener and any live exporter session. Returns the
    /// number of things it did, so the caller can sleep when idle.
    int pump();

    // --- sharing ------------------------------------------------------------

    Status shareStart(std::uint16_t port, std::string* why) override;
    void   shareStop();
    Status shareStop(std::string* why) override { (void)why; shareStop(); return Status::Ok; }
    std::string stateJson() override;

    /// The ticket for the question currently on screen, or all zeroes when
    /// there is no question. The window MUST show no number when this is zero:
    /// a person trained to answer a security question while looking at nothing
    /// has lost the whole value of the ceremony (§3.9).
    ApprovalNonce shareNonce()  const noexcept { return _shareNonce; }
    ApprovalNonce importNonce() const noexcept { return _importNonce; }

    /// The peer's fingerprint as the window would render it. Part of the
    /// approval, so it is readable rather than only writable.
    const std::string& sharePeerFingerprint()  const noexcept { return _sharePeerFingerprint; }
    const std::string& importPeerFingerprint() const noexcept { return _importPeerFingerprint; }

    /// Who owns the shared device across sessions, for the window.
    session::LeaseState leaseState() const noexcept { return _leases.state(); }

    /// What the peer is currently offering, as the window lists it.
    const std::vector<DeviceView>& offeredDevices() const noexcept { return _offered; }
    /// The port actually bound. Differs from what was asked for when 0 was
    /// passed, which is how a test gets a port without racing another test for
    /// a fixed one.
    std::uint16_t sharePort() const noexcept { return _sharePort; }
    ShareState  shareState()  const noexcept { return _shareState; }
    ImportState importState() const noexcept { return _importState; }
    std::uint32_t shareSas()  const noexcept { return _shareSas; }
    std::uint32_t importSas() const noexcept { return _importSas; }
    /// Answers the SAS question for an inbound peer. Accepting pins it and drops
    /// the connection so it can come back paired; refusing drops it unpinned.
    ///
    /// `nonce`, `fingerprint` and `sas` are what the window DISPLAYED, and all
    /// three are checked against the session they belong to. A mismatch is
    /// refused rather than resolved in favour of the current session: the whole
    /// point of the ceremony is that a specific number was compared, and
    /// pinning a different peer than the one the person looked at is the
    /// failure it exists to prevent.
    Status shareApprove(const ApprovalNonce& nonce, const std::string& fingerprint,
                        std::uint32_t sas, bool accept, std::string* why) override;

    // --- importing ----------------------------------------------------------

    Status importConnect(const std::string& host, std::uint16_t port,
                         std::string* why) override;
    /// Accepting pins the peer and reconnects once, so the caller does not have
    /// to know that a pin needs a fresh session to take effect. Same three
    /// checks as `shareApprove`, for the same reason.
    Status importApprove(const ApprovalNonce& nonce, const std::string& fingerprint,
                         std::uint32_t sas, bool accept, std::string* why) override;
    Status importRefresh(std::string* why) override;
    Status importAttach(const std::string& uidHex, std::string* why) override;
    Status importDetach(std::string* why) override;
    void   importDisconnect();
    Status importDisconnect(std::string* why) override
    {
        (void)why; importDisconnect(); return Status::Ok;
    }

    /// A read-only Bulk-Only Transport exchange against the attached device.
    /// BotProbe cannot write; this is safe to point at anything.
    ///
    /// Available ONLY when the device was opened for diagnostics. Once it has
    /// been presented to this computer as a real USB device, the operating
    /// system owns the endpoints and a second reader driving the same pipes
    /// would corrupt the phase machine — so this refuses and says to use the
    /// computer's own tools, which is what a presented device is for.
    Status importVerify(std::string* why) override;

    /// Takes a quarantined device back from a peer that stopped answering.
    ///
    /// Its own verb, not a flag on detach, because it is the one operation here
    /// that can lose somebody else's data: the machine holding the lease may
    /// have a filesystem mounted and dirty.
    Status forceReclaim(std::string* why) override;

    /// What this build can actually do with a remote device. Rendered verbatim.
    const session::IDevicePresenter& presenter() const noexcept { return *_presenter; }

    /// PING/PONG, for the "is the link alive" indicator.
    Status importPing(std::string* why) override;

    // --- what the window renders --------------------------------------------

    void writeStateJson(JsonOut& j) const;

    /// The most recent thing worth telling the user, in their own words. Set by
    /// every action, cleared by none — a UI shows the last outcome until there
    /// is a newer one.
    const std::string& notice() const noexcept { return _notice; }

private:
    struct ImportSession;

    void   setNotice(std::string s) { _notice = std::move(s); }
    Status importOpen(const std::string& host, std::uint16_t port, std::string* why);
    void   shareDropPeer(const char* why);
    /// Mints a fresh ticket for a question about to be asked, or clears it.
    static void mintNonce(ApprovalNonce& out);
    static void clearNonce(ApprovalNonce& out) noexcept;
    /// Checks a window's answer against the session it claims to be answering.
    Status checkApproval(const ApprovalNonce& have, const std::string& haveFp,
                         std::uint32_t haveSas, const ApprovalNonce& said,
                         const std::string& saidFp, std::uint32_t saidSas,
                         std::string* why) const;
    /// Keeps a half-paired session alive and reconnects when the far side ends
    /// it. Runs from pump(), only while pairing is in progress.
    int    pumpImportPairing();
    void   importDropSession();
    static std::string uidHex(const protocol::DeviceUid& u);
    static bool parseUidHex(const std::string& hex, protocol::DeviceUid& out);

    Config _cfg;
    std::string _notice;

    // --- sharing ------------------------------------------------------------
    ShareState             _shareState = ShareState::Off;
    std::uint16_t          _sharePort  = 0;
    platform::SocketHandle _shareListen = platform::kInvalidSocket;
    std::unique_ptr<session::SecureSession>   _shareSecure;
    std::unique_ptr<session::ExporterSession> _shareExporter;
    /// Outlives every exporter session, deliberately. See LeaseAuthority.h.
    session::LeaseAuthority _leases{Clock::system()};
    std::string   _sharePeerFingerprint;
    std::uint32_t _shareSas = 0;
    ApprovalNonce _shareNonce{};
    std::uint64_t _shareTransfers = 0;
    std::uint64_t _shareMessages  = 0;
    ContinuousNs  _shareHandshakeStartedNs = 0;

    // --- importing ----------------------------------------------------------
    ImportState _importState = ImportState::Off;
    std::string _importHost;
    std::uint16_t _importPort = 0;
    std::unique_ptr<session::ImporterClient>   _client;
    /// How the attached device reached this computer. Never null: a build with
    /// no real importer gets a ProbePresenter, which reports canPresent() ==
    /// false rather than quietly looking like one that can.
    session::IDevicePresenter*                 _presenter = nullptr;
    session::ProbePresenter                    _ownProbe;
    session::ImporterClient::BridgeAttach      _attached;
    std::string   _importPeerFingerprint;
    std::uint32_t _importSas = 0;
    ApprovalNonce _importNonce{};
    std::vector<DeviceView> _offered;
    std::string   _attachedUid;
    std::string   _attachedName;
    std::string   _manifestSummary;
    std::uint64_t _lastRttNs = 0;
    /// True once this side has pinned the peer. Distinguishes "you have not
    /// decided" from "you decided and they have not", which are different
    /// sentences to put in front of a person.
    bool          _importPinned = false;
    /// Set by connect, cleared by disconnect and by a refusal. While it is set,
    /// pump() may reopen a session that the far side ended; while it is clear,
    /// nothing here ever dials out on its own.
    bool          _importAuto = false;
    ContinuousNs  _importNextTickNs = 0;

    // Evidence from the last verification, kept so the window can show it after
    // the fact rather than only as it happens.
    bool          _haveProbe = false;
    bool          _probePassed = false;
    std::string   _probeSummary;
    std::string   _probeFailure;
    std::uint64_t _probeBlockCount = 0;
    std::uint32_t _probeBlockSize  = 0;
    std::string   _probeVendor;
    std::string   _probeProduct;
};

} // namespace airusb::control

#endif // AIRUSB_CONTROL_HUBSTATE_H
