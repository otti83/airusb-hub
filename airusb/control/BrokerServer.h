// AirUSB Hub — the privileged side of the local channel.
//
// One `HubState` (the authority: identity, pins, leases, sessions, the
// presenter) and one connected window at a time. It translates
// `BrokerProtocol` frames into calls on that authority and nothing else — there
// is no verb here that is not a thing a person can do in the window, and no
// path by which a request becomes an arbitrary operation.
//
// ONE CLIENT, NOT MANY
//
// A second window is refused rather than queued or multiplexed. Two windows
// answering the same six-digit question is not a concurrency problem to solve;
// it is an ambiguity about which person approved what, and the honest handling
// is to have one.
//
// NEVER BLOCKS
//
// `poll()` is one non-blocking step, called from the same loop that pumps the
// exporter, the importer and the presenter. A broker that waited on its window
// would stop answering the network, and the window is the least important thing
// attached to it.

#ifndef AIRUSB_CONTROL_BROKERSERVER_H
#define AIRUSB_CONTROL_BROKERSERVER_H

#include "BrokerProtocol.h"
#include "HubState.h"
#include "LocalEndpoint.h"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace airusb::control {

class BrokerServer {
public:
    struct Config {
        /// Only this uid may drive the broker. `0xFFFFFFFF` means "whoever owns
        /// the socket's directory can reach it, and any uid that gets through
        /// is accepted" — which is correct ONLY for a broker running as the
        /// same unprivileged user as its window, and is refused for a root one.
        std::uint32_t allowedUid = 0xFFFFFFFFu;
        /// Refuse every peer whose uid is not `allowedUid`. Set for a
        /// privileged broker; the socket mode is the first line and this is the
        /// second, because a mode bit is a property of a file somebody could
        /// have changed and this is a property of the running process.
        bool enforceUid = false;
    };

    BrokerServer(HubState& hub, LocalListener& listener, const Config& cfg) noexcept
        : _hub(hub), _listener(listener), _cfg(cfg) {}

    /// One non-blocking step: accept a window if one is waiting, read whatever
    /// frames are complete, answer them. Returns the number of things it did.
    int poll();

    /// Whether a window is currently attached, and who it belongs to.
    bool connected() const noexcept { return _client != nullptr; }
    const PeerCredentials& peer() const noexcept { return _peer; }

    /// Counters, so a run can say "nothing was turned away" and mean it.
    std::uint64_t framesHandled() const noexcept { return _frames; }
    std::uint64_t refusals()      const noexcept { return _refusals; }

    /// Set by the daemon so the window can be told what this build can do.
    void setMachineName(std::string s) { _machineName = std::move(s); }
    void setFingerprint(std::string s) { _fingerprint = std::move(s); }

private:
    void dropClient(const char* why);
    void handleFrame(const broker::FrameHeader& h, std::span<const std::uint8_t> body);
    void reply(broker::Op op, Status st, std::uint64_t tag,
               std::span<const std::uint8_t> body);
    void replyState(broker::Op op, Status st, std::uint64_t tag,
                    const std::string& why = {});

    HubState&      _hub;
    LocalListener& _listener;
    Config         _cfg;

    std::unique_ptr<transport::IByteStream> _client;
    PeerCredentials                         _peer;
    /// True once the window has sent a version-matching ATTACH. Nothing else is
    /// answered before that: a peer that has not agreed on the version cannot
    /// be assumed to mean what its opcodes say.
    bool _greeted = false;

    std::vector<std::uint8_t> _rx;
    std::vector<std::uint8_t> _tx;
    std::size_t               _txSent = 0;

    std::string _machineName;
    std::string _fingerprint;

    std::uint64_t _frames   = 0;
    std::uint64_t _refusals = 0;
};

} // namespace airusb::control

#endif // AIRUSB_CONTROL_BROKERSERVER_H
