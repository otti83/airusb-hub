// AirUSB Hub — the framed socket between airusb-exportd and airusb-agent.
//
// Blocking, one request in flight at a time, deliberately. The exporter's data
// plane is already serialised per endpoint by USB itself, and a pipelined local
// IPC would buy nothing while adding a reordering hazard between a transfer and
// the CLEAR_HALT that recovers it.
//
// Plain POSIX, no IOKit, no Objective-C. That is what lets tests/unit exercise the
// real send/receive path over a socketpair in CI, on any host, with no hardware:
// the bytes that cross a socketpair in a test are the same bytes that cross the
// unix socket on the machine with the drive plugged in.

#ifndef AIRUSB_PLATFORM_MACOS_AGENTLINK_H
#define AIRUSB_PLATFORM_MACOS_AGENTLINK_H

#include "AgentProtocol.h"
#include "../../core/Status.h"

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace airusb::macos::ipc {

/// Owns a connected SOCK_STREAM fd and speaks whole frames over it.
class AgentLink {
public:
    AgentLink() noexcept = default;
    explicit AgentLink(int fd) noexcept;
    ~AgentLink();

    AgentLink(const AgentLink&)            = delete;
    AgentLink& operator=(const AgentLink&) = delete;
    AgentLink(AgentLink&& other) noexcept;
    AgentLink& operator=(AgentLink&& other) noexcept;

    bool valid() const noexcept { return _fd >= 0; }
    int  fd()    const noexcept { return _fd; }
    void close() noexcept;

    /// Sends one whole frame. Partial writes are retried; EINTR is retried.
    /// Returns TransportLost if the peer is gone.
    Status send(const Frame& f) noexcept;

    /// Receives one whole frame.
    ///
    /// `timeoutMs` of 0 blocks indefinitely. Returns:
    ///   Ok              a frame is in `out`
    ///   XferTimeout     the deadline passed with no complete frame
    ///   TransportLost   clean EOF or a socket error — the peer died
    ///   MalformedFrame  FATAL. The stream is not recoverable; close the socket.
    Status receive(Frame& out, std::uint32_t timeoutMs) noexcept;

    /// Daemon side: send a request and wait for the matching reply.
    ///
    /// A reply whose tag does not match is treated as MalformedFrame rather than
    /// skipped. With one request in flight there is no legitimate way to receive
    /// another tag, so a mismatch means the stream is desynchronised and every
    /// subsequent byte would be misattributed.
    Status call(Op op,
                std::span<const std::uint8_t> body,
                std::uint32_t timeoutMs,
                Frame& reply) noexcept;

private:
    Status fill(std::uint32_t timeoutMs) noexcept;

    int                       _fd      = -1;
    std::uint64_t             _nextTag = 1;
    std::vector<std::uint8_t> _in;
};

// --- unix socket helpers -----------------------------------------------------

/// Creates `path` (unlinking any stale socket first), binds, and listens.
/// The socket is created with mode 0600 and then relaxed to `mode`, so there is
/// no window in which it is more permissive than intended.
int listenOnUnixSocket(const std::string& path, unsigned mode, Status& st) noexcept;

/// Accepts exactly one connection, waiting up to `timeoutMs`.
///
/// `peerUid`/`peerPid` are filled from the kernel's own record of the peer via
/// getpeereid(2), not from anything the peer said about itself. The daemon runs
/// as root; believing a self-reported uid would make the handshake decorative.
int acceptOne(int listenFd,
              std::uint32_t timeoutMs,
              std::uint32_t* peerUid,
              std::uint32_t* peerPid,
              Status& st) noexcept;

/// Connects to `path`, retrying for up to `totalWaitMs`. The agent is started
/// independently of the daemon and may well win the race, so "connection refused"
/// is an expected transient rather than an error.
int connectUnixSocket(const std::string& path,
                      std::uint32_t totalWaitMs,
                      Status& st) noexcept;

/// Ignores SIGPIPE process-wide. A write to a socket whose peer just died must
/// return EPIPE, not kill a root daemon holding a captured drive.
void ignoreSigpipe() noexcept;

} // namespace airusb::macos::ipc

#endif // AIRUSB_PLATFORM_MACOS_AGENTLINK_H
