#include "AgentLink.h"

#include <cerrno>
#include <csignal>
#include <cstring>

#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

namespace airusb::macos::ipc {

namespace {

/// Monotonic milliseconds for deadline arithmetic inside a single blocking call.
/// Deliberately NOT core/Clock: this is a socket read deadline measured in
/// milliseconds within one call, not a lease timer, and it must not be confused
/// with the continuous clock the lease ordering depends on.
std::uint64_t nowMonoMs() noexcept
{
    struct timespec ts {};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<std::uint64_t>(ts.tv_sec) * 1000ull
         + static_cast<std::uint64_t>(ts.tv_nsec) / 1000000ull;
}

/// The uid on the other end of a unix socket.
///
/// There is no portable spelling of this. macOS and the BSDs have getpeereid(3);
/// glibc has never had it and answers with SO_PEERCRED and a `struct ucred`.
/// Compiling this file on Linux is what surfaced that — it had only ever been
/// built on macOS, because the Linux reproduction in the handoff used a hand
/// written g++ line that does not include this file.
///
/// It fails CLOSED. The caller uses the uid to refuse an agent that is not the
/// console user, so "I could not tell" must not be reported as a uid that might
/// be right.
bool peerUidOf(int fd, std::uint32_t& out) noexcept
{
#if defined(__linux__)
    struct ucred cr {};
    socklen_t len = sizeof cr;
    if (::getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cr, &len) != 0) return false;
    if (len != sizeof cr) return false;
    out = static_cast<std::uint32_t>(cr.uid);
    return true;
#else
    uid_t uid = static_cast<uid_t>(-1);
    gid_t gid = static_cast<gid_t>(-1);
    if (::getpeereid(fd, &uid, &gid) != 0) return false;
    out = static_cast<std::uint32_t>(uid);
    return true;
#endif
}

void setNoSigPipeOnSocket(int fd) noexcept
{
#ifdef SO_NOSIGPIPE
    int on = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof on);
#else
    (void)fd;
#endif
}

int sendFlags() noexcept
{
#ifdef MSG_NOSIGNAL
    return MSG_NOSIGNAL;
#else
    return 0;
#endif
}

/// Fills a sockaddr_un, refusing a path that would be silently truncated.
/// A truncated path binds the wrong socket, which for a root daemon means
/// listening somewhere unintended.
bool fillSunPath(sockaddr_un& sa, const std::string& path) noexcept
{
    std::memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    if (path.size() >= sizeof sa.sun_path) return false;
    std::memcpy(sa.sun_path, path.c_str(), path.size() + 1);
    return true;
}

} // namespace

// ---------------------------------------------------------------------------

AgentLink::AgentLink(int fd) noexcept : _fd(fd)
{
    if (_fd >= 0) setNoSigPipeOnSocket(_fd);
}

AgentLink::~AgentLink() { close(); }

AgentLink::AgentLink(AgentLink&& other) noexcept
    : _fd(other._fd), _nextTag(other._nextTag), _in(std::move(other._in))
{
    other._fd = -1;
}

AgentLink& AgentLink::operator=(AgentLink&& other) noexcept
{
    if (this != &other) {
        close();
        _fd       = other._fd;
        _nextTag  = other._nextTag;
        _in       = std::move(other._in);
        other._fd = -1;
    }
    return *this;
}

void AgentLink::close() noexcept
{
    if (_fd >= 0) {
        ::close(_fd);
        _fd = -1;
    }
    _in.clear();
}

// ---------------------------------------------------------------------------

Status AgentLink::send(const Frame& f) noexcept
{
    if (_fd < 0) return Status::TransportLost;

    std::vector<std::uint8_t> buf;
    buf.reserve(kHeaderSize + f.body.size());
    encodeFrame(f, buf);

    std::size_t sent = 0;
    while (sent < buf.size()) {
        const ssize_t n = ::send(_fd, buf.data() + sent, buf.size() - sent, sendFlags());
        if (n > 0) {
            sent += static_cast<std::size_t>(n);
            continue;
        }
        if (n < 0 && (errno == EINTR)) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            // The fd is blocking, so this should not happen; treat it as a
            // transient and poll rather than spinning.
            struct pollfd pfd { _fd, POLLOUT, 0 };
            if (::poll(&pfd, 1, 1000) > 0) continue;
        }
        return Status::TransportLost;
    }
    return Status::Ok;
}

Status AgentLink::fill(std::uint32_t timeoutMs) noexcept
{
    struct pollfd pfd { _fd, POLLIN, 0 };
    const int pollTimeout = (timeoutMs == 0)
                              ? -1
                              : static_cast<int>(timeoutMs > 0x7FFFFFFFu ? 0x7FFFFFFF
                                                                        : timeoutMs);
    const int pr = ::poll(&pfd, 1, pollTimeout);
    if (pr == 0)  return Status::XferTimeout;
    if (pr < 0)   return (errno == EINTR) ? Status::Busy : Status::TransportLost;

    std::uint8_t chunk[16384];
    const ssize_t n = ::recv(_fd, chunk, sizeof chunk, 0);
    if (n == 0)  return Status::TransportLost;          // clean EOF: peer exited
    if (n < 0)   return (errno == EINTR) ? Status::Busy : Status::TransportLost;

    _in.insert(_in.end(), chunk, chunk + n);
    return Status::Ok;
}

Status AgentLink::receive(Frame& out, std::uint32_t timeoutMs) noexcept
{
    if (_fd < 0) return Status::TransportLost;

    const std::uint64_t start    = nowMonoMs();
    const std::uint64_t deadline = timeoutMs == 0 ? 0 : start + timeoutMs;

    for (;;) {
        std::size_t consumed = 0;
        const Decode d = decodeFrame(_in, out, consumed);
        if (d == Decode::Ok) {
            _in.erase(_in.begin(), _in.begin() + static_cast<std::ptrdiff_t>(consumed));
            return Status::Ok;
        }
        if (d == Decode::Malformed) {
            // Fatal by construction: there is no resynchronisation path, so the
            // buffer is dropped and the caller is expected to close the socket.
            _in.clear();
            return Status::MalformedFrame;
        }

        std::uint32_t remaining = 0;
        if (deadline != 0) {
            const std::uint64_t now = nowMonoMs();
            if (now >= deadline) return Status::XferTimeout;
            remaining = static_cast<std::uint32_t>(deadline - now);
        }

        const Status fs = fill(remaining);
        if (fs == Status::Busy) continue;              // EINTR
        if (fs != Status::Ok)  return fs;
    }
}

Status AgentLink::call(Op op,
                       std::span<const std::uint8_t> body,
                       std::uint32_t timeoutMs,
                       Frame& reply) noexcept
{
    if (_fd < 0) return Status::TransportLost;

    Frame req;
    req.op  = op;
    req.tag = _nextTag++;
    req.body.assign(body.begin(), body.end());

    if (const Status s = send(req); s != Status::Ok) return s;

    const Status r = receive(reply, timeoutMs);
    if (r != Status::Ok) return r;

    if (reply.tag != req.tag || reply.op != req.op) return Status::MalformedFrame;
    return Status::Ok;
}

// ---------------------------------------------------------------------------
// unix socket helpers
// ---------------------------------------------------------------------------

int listenOnUnixSocket(const std::string& path, unsigned mode, Status& st) noexcept
{
    sockaddr_un sa {};
    if (!fillSunPath(sa, path)) { st = Status::BadArgument; return -1; }

    const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { st = Status::Internal; return -1; }
    setNoSigPipeOnSocket(fd);

    // A stale socket from a previous run would make bind fail with EADDRINUSE
    // even though nothing is listening.
    (void)::unlink(path.c_str());

    // Bind under a restrictive umask so the socket is never briefly world
    // writable between bind and chmod.
    const mode_t oldMask = ::umask(0177);
    const int br = ::bind(fd, reinterpret_cast<const sockaddr*>(&sa), sizeof sa);
    (void)::umask(oldMask);

    if (br != 0) { ::close(fd); st = Status::Internal; return -1; }
    if (::chmod(path.c_str(), static_cast<mode_t>(mode)) != 0) {
        ::close(fd); (void)::unlink(path.c_str()); st = Status::Internal; return -1;
    }
    if (::listen(fd, 4) != 0) {
        ::close(fd); (void)::unlink(path.c_str()); st = Status::Internal; return -1;
    }

    st = Status::Ok;
    return fd;
}

int acceptOne(int listenFd,
              std::uint32_t timeoutMs,
              std::uint32_t* peerUid,
              std::uint32_t* peerPid,
              Status& st) noexcept
{
    const std::uint64_t deadline = timeoutMs == 0 ? 0 : nowMonoMs() + timeoutMs;

    for (;;) {
        int wait = -1;
        if (deadline != 0) {
            const std::uint64_t now = nowMonoMs();
            if (now >= deadline) { st = Status::XferTimeout; return -1; }
            wait = static_cast<int>(deadline - now);
        }

        struct pollfd pfd { listenFd, POLLIN, 0 };
        const int pr = ::poll(&pfd, 1, wait);
        if (pr == 0)  { st = Status::XferTimeout; return -1; }
        if (pr < 0)   { if (errno == EINTR) continue; st = Status::Internal; return -1; }

        const int fd = ::accept(listenFd, nullptr, nullptr);
        if (fd < 0) { if (errno == EINTR) continue; st = Status::Internal; return -1; }
        setNoSigPipeOnSocket(fd);

        if (peerUid) {
            std::uint32_t uid = 0;
            *peerUid = peerUidOf(fd, uid) ? uid : 0xFFFFFFFFu;
        }
        if (peerPid) {
            // LOCAL_PEERPID is macOS-specific and advisory: it is used for log
            // lines only, never for an access decision.
            *peerPid = 0;
#ifdef LOCAL_PEERPID
            pid_t pid = 0;
            socklen_t len = sizeof pid;
            if (::getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &pid, &len) == 0)
                *peerPid = static_cast<std::uint32_t>(pid);
#endif
        }

        st = Status::Ok;
        return fd;
    }
}

int connectUnixSocket(const std::string& path, std::uint32_t totalWaitMs, Status& st) noexcept
{
    sockaddr_un sa {};
    if (!fillSunPath(sa, path)) { st = Status::BadArgument; return -1; }

    const std::uint64_t deadline = nowMonoMs() + totalWaitMs;
    for (;;) {
        const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) { st = Status::Internal; return -1; }
        setNoSigPipeOnSocket(fd);

        if (::connect(fd, reinterpret_cast<const sockaddr*>(&sa), sizeof sa) == 0) {
            st = Status::Ok;
            return fd;
        }
        const int e = errno;
        ::close(fd);

        // ENOENT: the daemon has not created the socket yet.
        // ECONNREFUSED: it exists but nothing is listening on it yet.
        // Both are the normal startup race, not failures.
        const bool transient = (e == ENOENT || e == ECONNREFUSED || e == EINTR ||
                                e == EAGAIN || e == EWOULDBLOCK);
        if (!transient || nowMonoMs() >= deadline) {
            st = transient ? Status::XferTimeout : Status::NotFound;
            return -1;
        }

        struct timespec ts { 0, 100 * 1000 * 1000 };   // 100 ms
        (void)::nanosleep(&ts, nullptr);
    }
}

void ignoreSigpipe() noexcept
{
    struct sigaction sa {};
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    (void)::sigaction(SIGPIPE, &sa, nullptr);
}

} // namespace airusb::macos::ipc
