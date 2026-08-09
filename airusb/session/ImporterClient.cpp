#include "ImporterClient.h"

#include "../core/Clock.h"
#include "../core/Platform.h"
#include "../core/Watchdog.h"
#include "../protocol/ManifestCodec.h"
#include "../protocol/Segmentation.h"

#include <cstring>

namespace airusb::session {

using namespace airusb::protocol;

Status ImporterClient::connect(std::unique_ptr<transport::IByteStream> stream,
                               const Config& cfg)
{
    _cfg = cfg;

    SecureSession::Config sc;
    sc.initiator = true;
    sc.identity  = cfg.identity;
    sc.peers     = cfg.peers;

    // If the peer is already pinned we could open with IK and save a round trip,
    // but we do not know WHICH peer is at the far end of a raw socket until the
    // handshake tells us. Discovery supplies that later; until then XX, which
    // learns it.
    if (const Status s = _secure.begin(std::move(stream), sc);
        s != Status::Ok && s != Status::Busy) {
        _why = _secure.failureReason();
        return s;
    }

    // Spin the handshake. The stream is non-blocking, so Busy simply means the
    // peer has not answered yet.
    //
    // Measured against the clock, not counted in iterations. Counting assumed
    // sleepMs(1) sleeps one millisecond; on Windows the platform tick is 15.625
    // ms, so the documented 15 s window was really about four minutes there, and
    // a half-open peer pinned this single-threaded client for all of it. The
    // clock is the continuous one, so a laptop that suspends mid-handshake does
    // not come back with the deadline still fresh.
    //
    // Deadline::afterMs treats 0 as "never" — right for an interrupt IN that may
    // idle forever, wrong here, where 0 must stay "do not wait at all" as the
    // counted loop did.
    if (cfg.handshakeTimeoutMs == 0) {
        _why = "the peer did not complete the handshake";
        return Status::XferTimeout;
    }
    const Clock& clock = Clock::system();
    const Deadline deadline = Deadline::afterMs(clock, cfg.handshakeTimeoutMs);
    while (!deadline.expired(clock)) {
        const Status s = _secure.pump();
        if (_secure.established()) return Status::Ok;
        if (_secure.state() == SecureSession::State::Failed) {
            _why = _secure.failureReason();
            return s == Status::Ok ? Status::AuthFailed : s;
        }
        if (s != Status::Ok && s != Status::Busy) {
            _why = _secure.failureReason();
            return s;
        }
        platform::sleepMs(1);
    }
    _why = "the peer did not complete the handshake";
    return Status::XferTimeout;
}

Status ImporterClient::trustPeerWithoutConfirmation(const std::string& name)
{
    if (!_secure.established()) return Status::BadArgument;
    if (!_cfg.peers) return Status::BadArgument;
    return _cfg.peers->pin(_secure.peerIdentity(), name, kDefaultGrants, 0);
}

Status ImporterClient::trustPeerAfterSasConfirmed(const std::string& name)
{
    if (!_secure.established()) return Status::BadArgument;
    if (!_cfg.peers) return Status::BadArgument;
    return _cfg.peers->pin(_secure.peerIdentity(), name, kDefaultGrants, 0);
}

Status ImporterClient::ping(std::uint64_t* rttNs)
{
    if (rttNs) *rttNs = 0;
    if (!_secure.established()) return Status::BadArgument;

    const Clock& clock = Clock::system();

    PingBody p;
    p.pingTsNs = clock.nowNs();
    std::vector<std::uint8_t> body;
    encodePing(p, body);

    Header h;
    std::vector<std::uint8_t> reply;
    if (const Status s = call(wire::Type::Ping, body, h, reply); s != Status::Ok) return s;

    if (h.type == static_cast<std::uint8_t>(wire::Type::Error)) {
        _why = "the peer refused the ping: ";
        _why += statusName(static_cast<Status>(h.status));
        return static_cast<Status>(h.status);
    }
    if (h.type != static_cast<std::uint8_t>(wire::Type::Pong)) return Status::MalformedFrame;

    PingBody pong;
    if (!decodePing(reply, pong)) return Status::MalformedFrame;
    // The echo has to be OUR timestamp coming back. Accepting any PONG would
    // make this measure "something arrived" rather than "this peer answered
    // this ping", and on a stream where a stale reply is possible those are
    // different facts.
    if (pong.pingTsNs != p.pingTsNs) return Status::MalformedFrame;

    const std::uint64_t now = clock.nowNs();
    if (rttNs) *rttNs = now > p.pingTsNs ? now - p.pingTsNs : 0;
    return Status::Ok;
}

Status ImporterClient::call(wire::Type type, std::span<const std::uint8_t> body,
                            Header& replyHeader, std::vector<std::uint8_t>& replyBody)
{
    transport::RecordLayer* link = _secure.transport();
    if (!link) return Status::TransportLost;

    Header h;
    h.type      = static_cast<std::uint8_t>(type);
    h.flags     = wire::kFlagSegFirst;
    h.channel   = 0;
    h.attachId  = _attachId;
    h.requestId = ++_requestId;
    h.bodyLen   = static_cast<std::uint32_t>(body.size());
    h.totalLen  = 0;                 // control plane carries no segmented data

    std::vector<std::uint8_t> rec;
    encodeHeader(h, rec);
    rec.insert(rec.end(), body.begin(), body.end());

    const Clock& clock = Clock::system();
    const Deadline deadline = Deadline::afterMs(clock, watchdog::kNetCtrl);

    if (const Status s = link->sendRecord(rec); s != Status::Ok) return s;
    // Control messages are small and will almost always leave in one write, but
    // "almost always" is what a partial write is. Waiting for a reply to a
    // request still sitting in our own send buffer is a deadlock, and the cost
    // of ruling it out here is one comparison.
    for (;;) {
        if (const Status s = link->flush(); s != Status::Ok) return s;
        if (link->pendingTxBytes() == 0) break;
        if (deadline.expired(clock)) {
            _why = "could not send the request in time";
            return Status::XferTimeout;
        }
    }

    // A deadline, because this loop used to have none.
    //
    // `Busy` means "nothing on the socket yet", so an unbounded spin here waits
    // for ever on a peer that accepted the connection and then stopped
    // answering — which is not a hypothetical: a peer holding a session it is
    // not allowed to serve, a machine that went to sleep, and a half-open TCP
    // connection all produce exactly that. In a command-line tool it looks like
    // a hang; in a daemon with a window attached it wedges the window too,
    // because this runs on the same thread.
    //
    // T_net_ctrl is the project's own name for how long a control-plane
    // exchange may take (§ the timeout table), so the number is not invented
    // here. The clock is the continuous one, so a laptop that sleeps mid-call
    // times out on waking rather than granting itself the nap.
    std::vector<std::uint8_t> in;
    for (;;) {
        const Status r = link->receiveRecord(in);
        if (r != Status::Busy && r != Status::Ok) return r;
        if (r == Status::Ok && !in.empty()) break;
        if (deadline.expired(clock)) {
            _why = "the other machine did not answer in time";
            return Status::XferTimeout;
        }
    }

    if (!decodeHeader(in, replyHeader)) return Status::MalformedFrame;
    if (in.size() - wire::kHeaderSize < replyHeader.bodyLen) return Status::MalformedFrame;
    replyBody.assign(
        in.begin() + static_cast<std::ptrdiff_t>(wire::kHeaderSize),
        in.begin() + static_cast<std::ptrdiff_t>(wire::kHeaderSize + replyHeader.bodyLen));
    return Status::Ok;
}

Status ImporterClient::listDevices(std::vector<DeviceRecord>& out)
{
    out.clear();

    Header h;
    std::vector<std::uint8_t> body;
    if (const Status s = call(wire::Type::ListDevices, {}, h, body); s != Status::Ok)
        return s;

    if (h.type == static_cast<std::uint8_t>(wire::Type::Error)) {
        _why = "the peer refused: ";
        _why += statusName(static_cast<Status>(h.status));
        return static_cast<Status>(h.status);
    }
    if (h.type != static_cast<std::uint8_t>(wire::Type::DeviceList))
        return Status::MalformedFrame;

    if (!decodeDeviceList(body, out)) return Status::MalformedFrame;
    return Status::Ok;
}

Status ImporterClient::doAttach(const DeviceUid& uid, std::uint8_t slot,
                                AttachOkBody& ok, DeviceManifest& manifest,
                                ManifestHeader& mhdr, std::string* whyNot)
{
    if (slot == 0 || slot > 15) return Status::BadArgument;

    AttachBody ab;
    ab.uid         = uid;
    ab.exclusivity = 1;
    ab.attachSlot  = slot;
    ab.importerMaxTransferBytes = 1u << 20;

    std::vector<std::uint8_t> req;
    encodeAttach(ab, req);

    Header h;
    std::vector<std::uint8_t> body;
    if (const Status s = call(wire::Type::Attach, req, h, body); s != Status::Ok)
        return s;

    if (h.type == static_cast<std::uint8_t>(wire::Type::Error)) {
        _why = statusName(static_cast<Status>(h.status));
        if (whyNot) *whyNot = _why;
        return static_cast<Status>(h.status);
    }
    if (h.type != static_cast<std::uint8_t>(wire::Type::AttachOk))
        return Status::MalformedFrame;

    if (static_cast<Status>(h.status) != Status::Ok) {
        // The reason TLV is the part a user can act on — "close the app using
        // it" rather than "error 0x27".
        //
        // The length check is not decoration. call() validates the header and
        // that the body is as long as body_len claims, but it does not run
        // validateHeader on a REPLY, so nothing upstream has established that a
        // rejecting ATTACH_OK carries the 40-byte fixed body at all. A peer
        // answering ATTACH_OK with status != Ok and body_len == 0 reached
        // subspan(40) on an empty span here, which is unsigned wraparound to a
        // 2^64-sized span over a null pointer — forEachTlv then reads it and the
        // process dies. Conforming exporters always send the 40 bytes, so this
        // costs nothing against a peer that is behaving; the point is the one
        // that is not, and the importer dials out to an address a user typed.
        if (body.size() >= kBodyAttachOk) {
            forEachTlv(std::span<const std::uint8_t>(body).subspan(kBodyAttachOk),
                       [&](const TlvView& t) {
                           if (static_cast<wire::Tlv>(t.type) == wire::Tlv::RejectReason)
                               _why.assign(reinterpret_cast<const char*>(t.value.data()),
                                           t.value.size());
                           return true;
                       });
        }
        if (whyNot) *whyNot = _why;
        return static_cast<Status>(h.status);
    }

    if (!decodeAttachOk(body, ok)) return Status::MalformedFrame;
    if (ok.attachId == 0) return Status::MalformedFrame;

    // The manifest follows. Nothing is usable until it arrives and validates:
    // §7.2 step 9, the importer never learns the device exists until it is fully
    // described.
    Header mh;
    std::vector<std::uint8_t> mbody;
    transport::RecordLayer* link = _secure.transport();
    std::vector<std::uint8_t> in;

    // BOUNDED, which it was not.
    //
    // `Busy` means the socket has nothing yet, so the loop that used to be here
    // spun at full speed for ever against an exporter that sent ATTACH_OK and
    // then stopped — a hang with no message, burning a core, on the one code
    // path a user reaches by typing somebody else's address. Found by an
    // adversarial read (GPT-5.6, 2026-08-09); it is the same defect class as the
    // `Busy` spins already fixed in `ImporterClient::call()` and
    // `RemoteDevicePort::submit()`, and this was the one instance left.
    //
    // T_net_ctrl is the right ceiling: the manifest is already built and is
    // being sent by a peer that has just answered, so this is a control-plane
    // exchange, not a device transfer.
    const Clock& clock = Clock::system();
    const Deadline manifestBy = Deadline::afterMs(clock, watchdog::kNetCtrl);
    for (;;) {
        const Status r = link->receiveRecord(in);
        if (r != Status::Busy && r != Status::Ok) return r;
        if (r == Status::Ok && !in.empty()) break;
        if (manifestBy.expired(clock)) {
            _why = "the peer accepted the attach and then never sent the device's "
                   "descriptors";
            if (whyNot) *whyNot = _why;
            return Status::XferTimeout;
        }
    }
    if (!decodeHeader(in, mh)) return Status::MalformedFrame;
    if (mh.type != static_cast<std::uint8_t>(wire::Type::DeviceManifest))
        return Status::MalformedFrame;
    if (in.size() - wire::kHeaderSize < mh.bodyLen) return Status::MalformedFrame;

    if (!mh.segMore()) {
        // The whole manifest is in one record — the common case, and byte for
        // byte what happened before segmentation existed here.
        mbody.assign(in.begin() + static_cast<std::ptrdiff_t>(wire::kHeaderSize),
                     in.begin() + static_cast<std::ptrdiff_t>(wire::kHeaderSize + mh.bodyLen));
    } else {
        // SEGMENTED. A device with eight configurations and a full string table
        // exceeds one record, and at the 1 KiB floor two peers may legitimately
        // agree on, almost any real device does. The exporter used to fail
        // outright here with "too large to send"; the same
        // `emitTransfer`/`Reassembler` pair the data plane has used since L5
        // carries it now, because neither is data-plane-specific.
        Reassembler::Limits rl;
        rl.maxTransferBytes = wire::kManifestBytesMax;
        rl.arenaBytes       = wire::kManifestBytesMax;
        rl.maxInFlight      = 1;
        Reassembler ra(rl);

        Status e = Status::Ok;
        Reassembler::Outcome o = ra.accept(
            mh, std::span<const std::uint8_t>(in).subspan(wire::kHeaderSize, mh.bodyLen), e);
        if (o == Reassembler::Outcome::Rejected) return e;

        std::vector<std::uint8_t> more;
        while (o == Reassembler::Outcome::NeedMore) {
            const Status r = link->receiveRecord(more);
            if (r != Status::Busy && r != Status::Ok) return r;
            if (r != Status::Ok || more.empty()) {
                if (manifestBy.expired(clock)) {
                    _why = "the peer started sending the device's descriptors and "
                           "stopped partway";
                    if (whyNot) *whyNot = _why;
                    return Status::XferTimeout;
                }
                continue;
            }
            Header dh;
            if (!decodeHeader(more, dh)) return Status::MalformedFrame;
            if (more.size() - wire::kHeaderSize < dh.bodyLen) return Status::MalformedFrame;
            // A continuation is a Data record on the same request. Anything
            // else means the stream is misaligned, and with one exchange
            // outstanding there is no other legitimate thing to see.
            if (dh.type != static_cast<std::uint8_t>(wire::Type::Data))
                return Status::MalformedFrame;
            if (dh.requestId != mh.requestId || dh.channel != mh.channel)
                return Status::MalformedFrame;
            o = ra.accept(dh, std::span<const std::uint8_t>(more)
                                  .subspan(wire::kHeaderSize, dh.bodyLen), e);
            if (o == Reassembler::Outcome::Rejected) return e;
        }
        mbody = ra.take(mh);
    }

    std::string mwhy;
    if (const Status s = decodeManifest(mbody, manifest, mhdr, &mwhy); s != Status::Ok) {
        _why = "the peer's manifest was rejected: " + mwhy;
        if (whyNot) *whyNot = _why;
        return s;
    }

    // §3.7's speed rule: no downgrade, ever. The importer refuses rather than
    // presenting SuperSpeed descriptors on a slower virtual port, which would
    // make the guest OS mis-enumerate the device. There is no backend here yet,
    // so the only check available is that the two sides agree.
    if (mhdr.speed != ok.speed) {
        _why = "the peer's manifest and attach disagree about the link speed";
        if (whyNot) *whyNot = _why;
        return Status::ManifestInvalid;
    }

    _attachId   = ok.attachId;
    _attachSlot = slot;
    return Status::Ok;
}

Status ImporterClient::attach(const DeviceUid& uid, std::uint8_t slot,
                              std::unique_ptr<RemoteDevicePort>& portOut,
                              std::string* whyNot)
{
    portOut.reset();
    AttachOkBody ok;
    DeviceManifest manifest;
    ManifestHeader mhdr;
    if (const Status s = doAttach(uid, slot, ok, manifest, mhdr, whyNot); s != Status::Ok)
        return s;
    portOut = std::make_unique<RemoteDevicePort>(_secure.transport(), ok.attachId, slot,
                                                 std::move(manifest));
    return Status::Ok;
}

Status ImporterClient::attachForBridge(const DeviceUid& uid, std::uint8_t slot,
                                       BridgeAttach& out, std::string* whyNot)
{
    out = BridgeAttach{};
    AttachOkBody ok;
    DeviceManifest manifest;
    ManifestHeader mhdr;
    if (const Status s = doAttach(uid, slot, ok, manifest, mhdr, whyNot); s != Status::Ok)
        return s;

    // Everything the async path (ImporterDataPlane + VhciNetBridge) needs, and
    // nothing it does not. capturedConfig is the value SET_CONFIGURATION may be
    // confirmed for locally; speed drives the vhci port-half choice.
    out.link             = _secure.transport();
    out.attachId         = ok.attachId;
    out.slot             = slot;
    out.capturedConfig   = mhdr.currentConfigValue;
    out.speed            = manifest.speed();
    out.maxTransferBytes = 1u << 20;
    out.manifest         = std::move(manifest);
    return Status::Ok;
}

Status ImporterClient::detach()
{
    if (_attachId == 0) return Status::Ok;

    DetachBody d;
    d.reason = DetachReason::UserRequest;
    std::vector<std::uint8_t> req;
    encodeDetach(d, req);

    Header h;
    std::vector<std::uint8_t> body;
    const Status s = call(wire::Type::Detach, req, h, body);
    _attachId = 0;
    return s;
}

} // namespace airusb::session
