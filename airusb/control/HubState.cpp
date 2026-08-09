#include "HubState.h"

#include "Json.h"

#include "../crypto/Primitives.h"
#include "../transport/TcpTransport.h"

#include <cstdio>

namespace airusb::control {

using namespace airusb::protocol;
using namespace airusb::session;

namespace {

/// How long a half-finished inbound handshake may sit before the socket is
/// reclaimed. A peer that connects and then says nothing must not be able to
/// hold the sharing listener hostage — there is only one slot.
constexpr std::uint64_t kInboundHandshakeNs = 20ull * 1000 * 1000 * 1000;

std::string fmtHex16(const protocol::DeviceUid& u)
{
    static const char* kHex = "0123456789abcdef";
    std::string s;
    s.reserve(u.size() * 2);
    for (const std::uint8_t b : u) {
        s += kHex[(b >> 4) & 0xF];
        s += kHex[b & 0xF];
    }
    return s;
}

} // namespace

const char* shareStateText(ShareState s) noexcept
{
    switch (s) {
    case ShareState::Off:              return "off";
    case ShareState::Listening:        return "listening";
    case ShareState::Handshaking:      return "handshaking";
    case ShareState::AwaitingApproval: return "awaiting-approval";
    case ShareState::Serving:          return "serving";
    }
    return "off";
}

const char* importStateText(ImportState s) noexcept
{
    switch (s) {
    case ImportState::Off:              return "off";
    case ImportState::Connecting:       return "connecting";
    case ImportState::AwaitingApproval: return "awaiting-approval";
    case ImportState::WaitingForPeer:   return "waiting-for-peer";
    case ImportState::Connected:        return "connected";
    case ImportState::Attached:         return "attached";
    }
    return "off";
}

std::string HubState::uidHex(const protocol::DeviceUid& u) { return fmtHex16(u); }

bool HubState::parseUidHex(const std::string& hex, protocol::DeviceUid& out)
{
    if (hex.size() != out.size() * 2) return false;
    auto nyb = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i < out.size(); ++i) {
        const int hi = nyb(hex[i * 2]);
        const int lo = nyb(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
    }
    return true;
}

bool nonceIsZero(const ApprovalNonce& n) noexcept
{
    for (const std::uint8_t b : n) if (b != 0) return false;
    return true;
}

void HubState::mintNonce(ApprovalNonce& out)
{
    crypto::randomBytes(std::span<std::uint8_t>(out.data(), out.size()));
    // Astronomically unlikely, and cheap to exclude: all zeroes is the sentinel
    // for "there is no question pending", so a real ticket must never be it.
    if (nonceIsZero(out)) out[0] = 1;
}

void HubState::clearNonce(ApprovalNonce& out) noexcept { out.fill(0); }

Status HubState::checkApproval(const ApprovalNonce& have, const std::string& haveFp,
                               std::uint32_t haveSas, const ApprovalNonce& said,
                               const std::string& saidFp, std::uint32_t saidSas,
                               std::string* why) const
{
    auto no = [&](const char* m) { if (why) *why = m; return Status::NotPermitted; };

    if (nonceIsZero(have))
        return no("there is no pairing question waiting to be answered");

    // Constant time, and not because the nonce is a high-value secret — it
    // lives for one session and authorises only what the person at the screen
    // could already do. It is constant time because the day somebody copies
    // this comparison onto something that IS high-value, nobody will remember
    // to change it.
    if (!crypto::constantTimeEquals(
            std::span<const std::uint8_t>(said.data(), said.size()),
            std::span<const std::uint8_t>(have.data(), have.size())))
        return no("that answer is for a pairing question that is no longer on "
                  "screen — check the number again");

    // The fingerprint and the digits are checked TOO, not just the nonce.
    // Belt and braces on purpose: the nonce proves which question was asked,
    // and these prove the window rendered the same answer to it that this side
    // is about to act on. If they ever disagree, something between the two is
    // wrong and refusing is the only safe move.
    if (saidFp != haveFp)
        return no("the machine on screen is not the machine that is connected");
    if (saidSas != haveSas)
        return no("the number on screen is not this session's number");

    return Status::Ok;
}

Status HubState::begin(const Config& cfg)
{
    _cfg = cfg;
    if (!_cfg.identity || !_cfg.peers) return Status::BadArgument;
    // Never null. A build with no real importer gets the diagnostic probe,
    // which reports canPresent() == false — the alternative is a null check
    // scattered everywhere and a window that cannot tell the two apart.
    _presenter = _cfg.presenter ? _cfg.presenter
                                : static_cast<session::IDevicePresenter*>(&_ownProbe);
    return Status::Ok;
}

// ---------------------------------------------------------------------------
// Sharing
// ---------------------------------------------------------------------------

Status HubState::shareStart(std::uint16_t port, std::string* why)
{
    auto fail = [&](Status s, const char* m) { if (why) *why = m; return s; };

    if (_shareState != ShareState::Off) return fail(Status::Busy, "already sharing");
    if (!_cfg.devices)
        return fail(Status::UnsupportedMessage,
                    "this build has no way to capture a device, so it has nothing to share");

    Status st = Status::Ok;
    // NOT loopback-only. Being reachable from the LAN is this socket's entire
    // purpose, and it is the one socket in the process that is.
    _shareListen = transport::TcpStream::listen(port, &st);
    if (!platform::isValid(_shareListen))
        return fail(st == Status::Ok ? Status::TransportLost : st,
                    "could not listen on that port — something else may already have it");

    _sharePort = port;
    if (port == 0) {
        // Ask the socket what it got. Without this the window would show
        // "listening on port 0", which is not a port anybody can type into the
        // other machine.
        struct sockaddr_in bound{};
#if defined(_WIN32)
        int len = static_cast<int>(sizeof bound);
#else
        socklen_t len = sizeof bound;
#endif
        if (::getsockname(_shareListen, reinterpret_cast<struct sockaddr*>(&bound), &len) == 0)
            _sharePort = ntohs(bound.sin_port);
    }
    _shareState = ShareState::Listening;
    setNotice("Sharing is on. Give the other machine this machine's address and port " +
              std::to_string(_sharePort) + ".");
    return Status::Ok;
}

void HubState::shareStop()
{
    if (_shareExporter) { _shareExporter->close(); _shareExporter.reset(); }
    _shareSecure.reset();
    platform::closeSocket(_shareListen);
    _shareListen = platform::kInvalidSocket;
    _shareState  = ShareState::Off;
    _sharePort   = 0;
    _sharePeerFingerprint.clear();
    _shareSas = 0;
    clearNonce(_shareNonce);
    setNotice("Sharing is off. Any device this machine had captured has been released.");
}

void HubState::shareDropPeer(const char* why)
{
    if (_shareExporter) { _shareExporter->close(); _shareExporter.reset(); }
    _shareSecure.reset();
    _sharePeerFingerprint.clear();
    _shareSas = 0;
    clearNonce(_shareNonce);
    _shareState = platform::isValid(_shareListen) ? ShareState::Listening : ShareState::Off;
    if (why && *why) setNotice(why);
}

Status HubState::shareApprove(const ApprovalNonce& nonce, const std::string& fingerprint,
                              std::uint32_t sas, bool accept, std::string* why)
{
    if (_shareState != ShareState::AwaitingApproval || !_shareSecure) {
        if (why) *why = "nobody is waiting to be approved";
        return Status::BadArgument;
    }

    if (const Status s = checkApproval(_shareNonce, _sharePeerFingerprint, _shareSas,
                                       nonce, fingerprint, sas, why); s != Status::Ok)
        return s;

    if (!accept) {
        shareDropPeer("Refused. The other machine was not trusted and has been "
                      "disconnected.");
        return Status::Ok;
    }

    const Status s = _cfg.peers->pin(_shareSecure->peerIdentity(), _cfg.machineName,
                                     kDefaultGrants, 0);
    if (s != Status::Ok) { if (why) *why = "could not record the pairing"; return s; }
    if (!_cfg.peersPath.empty()) (void)_cfg.peers->save(_cfg.peersPath);

    // Grants were read when this session began, so this one stays unpaired for
    // as long as it lives. Dropping it is not a limitation being worked around;
    // it is the session layer refusing to misreport what it authorised. The
    // other end treats the drop as its cue to come back, so nobody has to press
    // anything twice.
    shareDropPeer("Paired. The other machine can now connect — it will reconnect "
                  "by itself.");
    return Status::Ok;
}

int HubState::pump()
{
    int did = pumpImportPairing();

    // The presenter is a non-blocking event loop of its own — on Linux it is
    // draining vhci-hcd's socket and the network in the same step. It has to be
    // pumped from here for the same reason everything else is: this process is
    // single-threaded above the platform layer.
    if (_presenter && _presenter->presenting()) {
        const Status ps = _presenter->pump();
        if (ps != Status::Ok && ps != Status::Busy) {
            setNotice("The device stopped being available to this computer: " +
                      _presenter->statusText());
            _presenter->withdraw();
            _attached = session::ImporterClient::BridgeAttach{};
            if (_importState == ImportState::Attached)
                _importState = ImportState::Connected;
        }
        ++did;
    }

    if (!platform::isValid(_shareListen)) return did;

    // One peer at a time. A second connection while one is live is closed
    // rather than queued: there is one device source, and a queue would only
    // move the refusal somewhere harder to explain.
    if (!_shareSecure) {
        Status st = Status::Ok;
        if (auto conn = transport::TcpStream::accept(_shareListen, &st)) {
            _shareSecure = std::make_unique<SecureSession>();
            SecureSession::Config sc;
            sc.initiator = false;
            sc.identity  = _cfg.identity;
            sc.peers     = _cfg.peers;
            (void)_shareSecure->begin(std::move(conn), sc);
            _shareState  = ShareState::Handshaking;
            _shareHandshakeStartedNs = Clock::system().nowNs();
            ++did;
        }
    } else if (transport::TcpStream::accept(_shareListen, nullptr)) {
        // Accepted and immediately dropped by the unique_ptr going out of scope.
        ++did;
    }

    if (!_shareSecure) return did;

    if (_shareState == ShareState::Handshaking) {
        const Status s = _shareSecure->pump();
        if (_shareSecure->state() == SecureSession::State::Failed) {
            shareDropPeer(("A machine tried to connect but the handshake failed: " +
                           _shareSecure->failureReason()).c_str());
            return did + 1;
        }
        if (s != Status::Ok && s != Status::Busy) {
            shareDropPeer("A machine connected and then disconnected before pairing.");
            return did + 1;
        }
        if (_shareSecure->established()) {
            _sharePeerFingerprint =
                crypto::fingerprintText(crypto::fingerprint(_shareSecure->peerIdentity().identityKey));
            _shareSas = _shareSecure->sas();

            // Started in BOTH cases. An unpaired peer gets a session that
            // answers PING and refuses everything else, which is what §3.14
            // specifies and what lets the other end tell "not approved yet"
            // apart from "that machine is gone".
            _shareExporter = std::make_unique<ExporterSession>();
            ExporterSession::Config ec;
            ec.devices  = _cfg.devices;
            ec.clock    = &Clock::system();
            ec.peerName = _cfg.machineName;
            // The authority is a MEMBER of HubState, not of the session, and
            // that placement is the whole point: a peer that vanishes mid-write
            // keeps its lease across the session that carried it.
            ec.leases   = &_leases;
            if (_shareExporter->begin(_shareSecure.get(), ec) != Status::Ok) {
                shareDropPeer("A machine connected but the session could not be started.");
                return did + 1;
            }

            if (_shareSecure->trust() == Trust::Paired) {
                _shareState = ShareState::Serving;
                setNotice("A paired machine is connected.");
            } else {
                _shareState = ShareState::AwaitingApproval;
                // The ticket is minted WITH the question. It names this session,
                // and it is what makes an answer that arrives after the session
                // has been replaced a refusal rather than a pin.
                mintNonce(_shareNonce);
                setNotice("A machine wants to use a device from here. Check the number "
                          "matches the one on its screen.");
            }
            return did + 1;
        }
        if (Clock::system().nowNs() - _shareHandshakeStartedNs > kInboundHandshakeNs) {
            shareDropPeer("A machine connected but never finished the handshake.");
            return did + 1;
        }
        return did;
    }

    if ((_shareState == ShareState::Serving ||
         _shareState == ShareState::AwaitingApproval) && _shareExporter) {
        const Status s = _shareExporter->pump();
        _shareTransfers = _shareExporter->transfersServed();
        _shareMessages  = _shareExporter->messagesHandled();
        if (s == Status::TransportLost) {
            shareDropPeer("The other machine disconnected.");
            return did + 1;
        }
        if (isFatal(s)) {
            shareDropPeer(("The session was closed: " + std::string(statusName(s)) +
                           " — " + _shareExporter->lastError()).c_str());
            return did + 1;
        }
        ++did;
    }

    return did;
}

// ---------------------------------------------------------------------------
// Importing
// ---------------------------------------------------------------------------

void HubState::importDropSession()
{
    _presenter->withdraw();
    _attached = session::ImporterClient::BridgeAttach{};
    _client.reset();
    _offered.clear();
    _importPeerFingerprint.clear();
    _importSas = 0;
}

// The whole reason this function exists, in one paragraph.
//
// The short authentication string is derived from the handshake hash, so it is
// different in every session — which means both machines have to compare the
// SAME session's number, and neither may end that session until both people
// have looked. But the exporter's grants are read once at handshake time, so
// the moment it pins a peer it MUST end the session; carrying on would mean its
// own record of what it authorised is a lie.
//
// Those two facts together mean the connection will be torn down mid-pairing,
// exactly once, no matter who presses first. Rather than explain that to a
// person, this reconnects on their behalf:
//
//   * we approved first  -> we pin, keep the session, and wait. When the far
//     side approves it drops us; the ping notices, and the reconnect lands in a
//     session where both sides are paired.
//   * they approved first -> the drop arrives while we are still deciding. We
//     reconnect, and the new session shows a NEW number — which is correct and
//     is why the window shows the current session's number at all times, on
//     both sides, not only when a decision is pending.
int HubState::pumpImportPairing()
{
    if (!_importAuto) return 0;
    if (_importState != ImportState::AwaitingApproval &&
        _importState != ImportState::WaitingForPeer &&
        _importState != ImportState::Connecting)
        return 0;

    const ContinuousNs now = Clock::system().nowNs();
    if (now < _importNextTickNs) return 0;
    _importNextTickNs = now + 1000ull * 1000 * 1000;   // once a second

    if (!_client) {
        std::string why;
        if (importOpen(_importHost, _importPort, &why) != Status::Ok) return 1;
        _importState = _importPinned ? ImportState::WaitingForPeer
                                     : ImportState::AwaitingApproval;
        // A NEW session means a new number, so the old ticket must die with it.
        // This is the reconnect that used to leave the window asking "do these
        // six digits match?" with nothing underneath it (§3.9); the ticket makes
        // the stale state refuse rather than merely look wrong.
        if (_importPinned) clearNonce(_importNonce);
        else               mintNonce(_importNonce);
        if (!_importPinned)
            setNotice("Reconnected. Compare this new number with the one on the "
                      "other machine — it changes with every connection, and that "
                      "is what makes it worth comparing.");
        return 1;
    }

    // PING is one of the three things an unpaired peer is allowed to send, so
    // it works during pairing — which is the only time this heartbeat runs.
    std::uint64_t rtt = 0;
    if (_client->ping(&rtt) != Status::Ok) {
        importDropSession();
        // Connecting, NOT AwaitingApproval. The SAS died with the session, and
        // leaving the state at AwaitingApproval would put the question "do
        // these six digits match?" on screen above a blank space — for about a
        // second, every single first pairing. Observed against `airusb-net
        // serve`, which pins and drops on the spot, so the window is not
        // theoretical and not rare.
        _importState = ImportState::Connecting;
        setNotice(_importPinned
                      ? "The other machine ended the session — that is what it does "
                        "when it accepts. Reconnecting."
                      : "The other machine ended the session before this side "
                        "accepted. Reconnecting.");
        return 1;
    }
    _lastRttNs = rtt;

    if (_importState == ImportState::WaitingForPeer) {
        std::string why;
        const Status s = importRefresh(&why);
        if (s == Status::Ok) {
            _importState = ImportState::Connected;
            setNotice("Paired and connected.");
            return 1;
        }
        // NotPaired is the expected answer until somebody accepts over there.
        // Anything else is worth showing.
        if (s != Status::NotPaired && s != Status::NotPermitted) setNotice(why);
    }
    return 1;
}

Status HubState::importOpen(const std::string& host, std::uint16_t port, std::string* why)
{
    auto fail = [&](Status s, const std::string& m) { if (why) *why = m; return s; };

    Status st = Status::Ok;
    auto conn = transport::TcpStream::connect(host, port, &st);
    if (!conn)
        return fail(st == Status::Ok ? Status::TransportLost : st,
                    "could not reach " + host + ":" + std::to_string(port));

    _client = std::make_unique<ImporterClient>();
    ImporterClient::Config cc;
    cc.identity = _cfg.identity;
    cc.peers    = _cfg.peers;
    cc.peerName = _cfg.machineName;

    if (const Status s = _client->connect(std::move(conn), cc); s != Status::Ok) {
        const std::string reason = _client->failureReason();
        _client.reset();
        return fail(s, "the handshake failed: " + reason);
    }

    _importHost = host;
    _importPort = port;
    _importPeerFingerprint =
        crypto::fingerprintText(crypto::fingerprint(_client->peerIdentity().identityKey));
    _importSas = _client->sas();
    return Status::Ok;
}

Status HubState::importConnect(const std::string& host, std::uint16_t port, std::string* why)
{
    if (_importState != ImportState::Off) importDisconnect();
    if (host.empty()) { if (why) *why = "no address given"; return Status::BadArgument; }

    _importState = ImportState::Connecting;
    _importPinned = false;
    _importAuto   = true;
    _importNextTickNs = 0;
    if (const Status s = importOpen(host, port, why); s != Status::Ok) {
        _importState = ImportState::Off;
        _importAuto  = false;
        setNotice(why && !why->empty() ? *why : std::string("Could not connect."));
        return s;
    }

    if (_client->trust() != Trust::Paired) {
        _importState = ImportState::AwaitingApproval;
        mintNonce(_importNonce);
        setNotice("Check that the number below matches the one on the other machine's "
                  "screen before accepting.");
        return Status::Ok;
    }

    _importPinned = true;
    if (const Status s = importRefresh(why); s == Status::Ok) {
        _importState = ImportState::Connected;
        setNotice("Connected.");
        _importAuto = false;
        return Status::Ok;
    } else if (s == Status::NotPaired || s == Status::NotPermitted) {
        // We trust them; they have not (or no longer) trust us. Their side has
        // to accept, and until it does this waits rather than reporting a
        // failure the person cannot act on from here.
        _importState = ImportState::WaitingForPeer;
        setNotice("This machine is paired with that one, but it has not accepted "
                  "this machine. Approve it there.");
        return Status::Ok;
    } else {
        _importState = ImportState::Connected;
        setNotice("Connected, but listing its devices failed.");
        _importAuto = false;
        return s;
    }
}

Status HubState::importApprove(const ApprovalNonce& nonce, const std::string& fingerprint,
                               std::uint32_t sas, bool accept, std::string* why)
{
    if (_importState != ImportState::AwaitingApproval || !_client) {
        if (why) *why = "there is nothing waiting to be approved";
        return Status::BadArgument;
    }

    if (const Status s = checkApproval(_importNonce, _importPeerFingerprint, _importSas,
                                       nonce, fingerprint, sas, why); s != Status::Ok)
        return s;

    if (!accept) {
        importDisconnect();
        setNotice("Refused. Nothing was trusted and the connection is closed.");
        return Status::Ok;
    }

    if (const Status s = _client->trustPeerAfterSasConfirmed(_importHost); s != Status::Ok) {
        if (why) *why = "could not record the pairing";
        return s;
    }
    if (!_cfg.peersPath.empty()) (void)_cfg.peers->save(_cfg.peersPath);
    _importPinned = true;
    // Spent. One use, so a replayed answer cannot pin a later peer.
    clearNonce(_importNonce);

    // The session is NOT dropped here, and that is the whole design.
    //
    // Pinning on this side is purely local bookkeeping — the importer
    // authorises nothing, so nothing it decided at handshake time is now stale.
    // The exporter is the opposite, and when it accepts it has to end the
    // session. Keeping ours alive means the other person is still looking at a
    // screen showing the same number as ours while they decide.
    std::string listWhy;
    const Status s = importRefresh(&listWhy);
    if (s == Status::Ok) {
        _importState = ImportState::Connected;
        _importAuto  = false;
        setNotice("Paired and connected.");
        return Status::Ok;
    }
    if (s == Status::NotPaired || s == Status::NotPermitted) {
        _importState = ImportState::WaitingForPeer;
        setNotice("Accepted here. Now accept on the other machine — this will "
                  "finish by itself when you do.");
        return Status::Ok;
    }
    if (why) *why = listWhy;
    _importState = ImportState::WaitingForPeer;
    return Status::Ok;
}

Status HubState::importRefresh(std::string* why)
{
    if (!_client || _importState == ImportState::Off) {
        if (why) *why = "not connected";
        return Status::BadArgument;
    }

    std::vector<DeviceRecord> devices;
    if (const Status s = _client->listDevices(devices); s != Status::Ok) {
        if (why) *why = "the other machine refused to list its devices: " +
                        std::string(statusName(s)) + " — " + _client->failureReason();
        return s;
    }

    _offered.clear();
    for (const DeviceRecord& d : devices) {
        DeviceView v;
        v.uid       = uidHex(d.uid);
        v.vendorId  = d.vendorId;
        v.productId = d.productId;
        v.speed     = d.speed;
        v.flags     = d.flags;
        v.name      = d.name;
        _offered.push_back(std::move(v));
    }
    return Status::Ok;
}

Status HubState::importAttach(const std::string& uid, std::string* why)
{
    auto fail = [&](Status s, const std::string& m) { if (why) *why = m; return s; };

    if (!_client || _importState != ImportState::Connected)
        return fail(Status::BadArgument, "not connected");

    DeviceUid parsed{};
    if (!parseUidHex(uid, parsed)) return fail(Status::BadArgument, "that is not a device id");

    // attachForBridge, not attach: it returns the live link and the manifest
    // WITHOUT building a RemoteDevicePort, so the presenter decides what the
    // device becomes. Building the synchronous instrument here was the whole
    // reason the window's "attach" and the product's "attach" were different
    // verbs — the instrument was the only thing it could ever produce.
    std::string whyNot;
    session::ImporterClient::BridgeAttach att;
    if (const Status s = _client->attachForBridge(parsed, 1, att, &whyNot); s != Status::Ok)
        return fail(s, whyNot.empty()
                        ? "the other machine refused to attach that device"
                        : whyNot);

    _attached = std::move(att);

    std::string pwhy;
    if (const Status s = _presenter->present(*_client, _attached, &pwhy); s != Status::Ok) {
        // The device is attached over the network but this computer cannot take
        // it. Give it straight back rather than holding a lease nothing can use.
        (void)_client->detach();
        _attached = session::ImporterClient::BridgeAttach{};
        return fail(s, pwhy.empty() ? _presenter->whyNot() : pwhy);
    }

    _attachedUid  = uid;
    _attachedName.clear();
    for (const DeviceView& d : _offered)
        if (d.uid == uid) _attachedName = d.name;

    const DeviceIdentity id = _attached.manifest.identity();
    char buf[192];
    std::snprintf(buf, sizeof buf, "%04x:%04x  %s  %u configuration(s)",
                  id.vendorId, id.productId, speedName(id.speed),
                  static_cast<unsigned>(_attached.manifest.configurationCount()));
    _manifestSummary = buf;

    _haveProbe = false;
    _probeSummary.clear();
    _probeFailure.clear();

    _importState = ImportState::Attached;
    // The notice says WHICH of the two things happened. It used to say
    // "Attached." for both, and a person reading that had no way to learn that
    // no device had appeared on their computer.
    setNotice(_presenter->statusText());
    return Status::Ok;
}

Status HubState::importDetach(std::string* why)
{
    if (_importState != ImportState::Attached || !_client) {
        if (why) *why = "nothing is attached";
        return Status::BadArgument;
    }
    _presenter->withdraw();
    _attached = session::ImporterClient::BridgeAttach{};
    const Status s = _client->detach();
    _attachedUid.clear();
    _attachedName.clear();
    _manifestSummary.clear();
    _importState = ImportState::Connected;
    setNotice("Released. The device has gone back to the machine that owns it.");
    (void)importRefresh(nullptr);
    return s;
}

void HubState::importDisconnect()
{
    if (_importState == ImportState::Attached && _client) {
        _presenter->withdraw();
        _attached = session::ImporterClient::BridgeAttach{};
        (void)_client->detach();
    }
    importDropSession();
    _attachedUid.clear();
    _attachedName.clear();
    _manifestSummary.clear();
    _lastRttNs = 0;
    _haveProbe = false;
    _importPinned = false;
    // Cleared, so nothing here dials out again on its own. A person who pressed
    // Disconnect meant it, and a daemon that quietly reconnects to a machine
    // after being told to stop is a daemon nobody should run.
    _importAuto  = false;
    _importState = ImportState::Off;
}

Status HubState::importVerify(std::string* why)
{
    if (_importState != ImportState::Attached) {
        if (why) *why = "nothing is attached";
        return Status::BadArgument;
    }

    // Only in diagnostic mode, and this refusal is a feature.
    //
    // Once a device is PRESENTED, the operating system owns its endpoints. A
    // second reader driving the same bulk pipes would desynchronise the
    // Bulk-Only Transport phase machine underneath a mounted filesystem — the
    // same class of corruption the "one logical transfer is one call" rule
    // exists to prevent, arriving from a completely different direction.
    session::RemoteDevicePort* port = _ownProbe.port();
    if (_presenter != static_cast<session::IDevicePresenter*>(&_ownProbe) || !port) {
        if (why) *why = "This device has been added to this computer as a real USB "
                        "device, so this computer's own tools are what read it. "
                        "This check only applies to a device opened for diagnostics.";
        return Status::UnsupportedMessage;
    }

    diag::BotEndpoints eps;
    if (!diag::findBotInterface(port->manifest(), 1, eps)) {
        if (why) *why = "this device is not USB Mass Storage, so there is nothing "
                        "this check knows how to read from it";
        _haveProbe = false;
        return Status::UnsupportedMessage;
    }

    // BotProbe, not WriteProbe. Its header promises without qualification that
    // it cannot damage a drive's contents, and a button in a window is exactly
    // the place that promise has to hold: the person pressing it may have a real
    // disk on the other end and no way to know what the button does.
    diag::BotProbe probe(*port, eps);
    const diag::BotProbeResult r = probe.run();

    _haveProbe       = true;
    _probePassed     = r.passed;
    _probeSummary    = r.summary();
    _probeFailure    = r.failure;
    _probeBlockCount = r.blockCount();
    _probeBlockSize  = r.blockSize;
    _probeVendor     = r.vendor;
    _probeProduct    = r.product;

    if (!r.passed) {
        if (why) *why = r.failure;
        setNotice("The check failed: " + r.failure);
        return Status::Internal;
    }
    setNotice("Verified — a real USB Mass Storage exchange completed over the "
              "encrypted session.");
    return Status::Ok;
}

Status HubState::forceReclaim(std::string* why)
{
    if (_leases.state() == session::LeaseState::Free) {
        if (why) *why = "no machine is holding a device from here";
        return Status::NotFound;
    }
    const bool wasQuarantined = _leases.state() == session::LeaseState::Quarantined;
    _leases.forceReclaim();

    // Drop whatever session is live too. Reclaiming the lease while a peer is
    // still driving transfers against it would leave the exporter answering a
    // machine it no longer believes owns the device — two authorities on one
    // drive, which is the exact ambiguity the lease exists to remove.
    shareDropPeer(nullptr);

    setNotice(wasQuarantined
                  ? "Taken back. The machine that was holding this device had stopped "
                    "answering; if it had unsaved changes they are lost."
                  : "Taken back from a machine that was using it. If it had unsaved "
                    "changes they are lost.");
    return Status::Ok;
}

Status HubState::importPing(std::string* why)
{
    if (!_client || _importState == ImportState::Off ||
        _importState == ImportState::Connecting) {
        if (why) *why = "not connected";
        return Status::BadArgument;
    }
    std::uint64_t rtt = 0;
    const Status s = _client->ping(&rtt);
    if (s != Status::Ok) {
        if (why) *why = "the other machine did not answer";
        return s;
    }
    _lastRttNs = rtt;
    return Status::Ok;
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

std::string HubState::stateJson()
{
    JsonOut j;
    writeStateJson(j);
    return j.take();
}

void HubState::writeStateJson(JsonOut& j) const
{
    j.beginObject();
    j.kv("machine", _cfg.machineName);
    j.kv("notice", _notice);
    j.kv("identity",
         crypto::fingerprintText(crypto::fingerprint(_cfg.identity->identityKey())));
    j.kv("pinnedPeers", static_cast<std::uint64_t>(_cfg.peers->size()));

    j.key("share").beginObject();
    j.kv("state", shareStateText(_shareState));
    j.kv("canShare", _cfg.devices != nullptr);
    j.kv("port", static_cast<std::uint64_t>(_sharePort));
    j.kv("peerFingerprint", _sharePeerFingerprint);
    // The SAS is six digits and leading zeros are significant: 042571 and
    // 42571 are different strings to compare on two screens. It travels as a
    // string for that reason and is never a JSON number.
    //
    // Sent whenever a session exists, not only when this side has a decision to
    // make. It is derived from the handshake hash, so it changes every session
    // — and a pairing that gets interrupted leaves one side already paired and
    // therefore not being asked anything, with the other side staring at a
    // number and nothing to compare it against. Showing it always costs a line
    // of small text and removes that dead end.
    if (_shareState == ShareState::AwaitingApproval || _shareState == ShareState::Serving) {
        j.kv("sas", crypto::sasText(_shareSas));
    } else {
        j.key("sas").null();
    }
    j.kv("approvalTicket", crypto::toHex(std::span<const std::uint8_t>(_shareNonce.data(),
                                                              _shareNonce.size())));
    j.kv("needsApproval", _shareState == ShareState::AwaitingApproval);
    // Who owns the shared device, across sessions. "quarantined" is the state a
    // person needs to see and could not before: it means a machine took the
    // drive and stopped answering, and nothing else will get it until somebody
    // here decides.
    j.kv("lease", session::leaseStateText(_leases.state()));
    j.kv("transfersServed", _shareTransfers);
    j.kv("messagesHandled", _shareMessages);
    j.key("devices").beginArray();
    if (_cfg.devices) {
        for (const DeviceRecord& d : _cfg.devices->list()) {
            j.beginObject();
            j.kv("uid", uidHex(d.uid));
            j.kv("vendorId", static_cast<std::uint64_t>(d.vendorId));
            j.kv("productId", static_cast<std::uint64_t>(d.productId));
            j.kv("speed", speedName(static_cast<Speed>(d.speed)));
            j.kv("name", d.name);
            j.kv("shareable", (d.flags & kDevShareable) != 0);
            j.kv("attached", (d.flags & kDevAttached) != 0);
            j.kv("mountedLocally", (d.flags & kDevMountedLocally) != 0);
            j.endObject();
        }
    }
    j.endArray();
    j.endObject();

    j.key("import").beginObject();
    j.kv("state", importStateText(_importState));
    j.kv("host", _importHost);
    j.kv("port", static_cast<std::uint64_t>(_importPort));
    j.kv("peerFingerprint", _importPeerFingerprint);
    if (_client) {
        j.kv("sas", crypto::sasText(_importSas));
    } else {
        j.key("sas").null();
    }
    // `_client` is in the condition as well as the state, so this can never be
    // true with a null `sas` beside it. A pairing prompt with no number in it
    // is worse than no prompt: it asks a person to compare something that is
    // not on screen, and the honest answer to that question is unavailable.
    j.kv("approvalTicket", crypto::toHex(std::span<const std::uint8_t>(_importNonce.data(),
                                                              _importNonce.size())));
    j.kv("needsApproval", _importState == ImportState::AwaitingApproval && _client != nullptr);
    j.kv("pinned", _importPinned);
    j.kv("attachedUid", _attachedUid);
    j.kv("attachedName", _attachedName);
    j.kv("manifest", _manifestSummary);
    j.kv("rttMicros", static_cast<std::uint64_t>(_lastRttNs / 1000));
    // WHAT ACTUALLY HAPPENED TO THE DEVICE, said in the state rather than left
    // for the window to infer. `presented` is the whole distinction: false means
    // this computer did not gain a USB device, however green everything looks.
    j.kv("presenter", _presenter->name());
    j.kv("canPresent", _presenter->canPresent());
    j.kv("presented", _presenter->presenting());
    j.kv("attachedVia", _importState == ImportState::Attached
                            ? _presenter->statusText() : std::string{});
    if (!_presenter->canPresent()) j.kv("cannotPresentBecause", _presenter->whyNot());

    if (const session::RemoteDevicePort* dp = _ownProbe.port()) {
        j.kv("transfersIssued", dp->transfersIssued());
        j.kv("segmentedOut", dp->segmentedOutTransfers());
        j.kv("segmentedIn", dp->segmentedInTransfers());
        j.kv("maxSegmentBytes", static_cast<std::uint64_t>(dp->maxSegmentBytes()));
    }
    j.key("devices").beginArray();
    for (const DeviceView& d : _offered) {
        j.beginObject();
        j.kv("uid", d.uid);
        j.kv("vendorId", static_cast<std::uint64_t>(d.vendorId));
        j.kv("productId", static_cast<std::uint64_t>(d.productId));
        j.kv("speed", speedName(static_cast<Speed>(d.speed)));
        j.kv("name", d.name);
        j.kv("shareable", (d.flags & kDevShareable) != 0);
        j.kv("attached", (d.flags & kDevAttached) != 0);
        j.endObject();
    }
    j.endArray();

    j.key("probe");
    if (!_haveProbe) {
        j.null();
    } else {
        j.beginObject();
        j.kv("passed", _probePassed);
        j.kv("summary", _probeSummary);
        j.kv("failure", _probeFailure);
        j.kv("vendor", _probeVendor);
        j.kv("product", _probeProduct);
        j.kv("blockCount", _probeBlockCount);
        j.kv("blockSize", static_cast<std::uint64_t>(_probeBlockSize));
        j.endObject();
    }
    j.endObject();

    j.endObject();
}

} // namespace airusb::control
