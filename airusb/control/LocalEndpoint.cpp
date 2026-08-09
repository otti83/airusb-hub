#include "LocalEndpoint.h"

#include <cstdlib>
#include <cstring>

#if defined(_WIN32)
#  include <windows.h>
// sddl.h is where ConvertStringSecurityDescriptorToSecurityDescriptor lives, and
// it is NOT reached by windows.h. Omitting it produced an "undeclared" error
// that reads like a missing library rather than a missing include — the same
// failure mode the WDK ABI check hit with usbdi.h, recorded there for the same
// reason.
#  include <sddl.h>
#  if defined(_MSC_VER)
// MinGW links advapi32 by default and warns on an unknown pragma; MSVC does
// not link it and needs to be told. Guarded rather than dropped, because the
// symbol lives there under both toolchains.
#    pragma comment(lib, "advapi32.lib")
#  endif
#else
#  include <errno.h>
#  include <fcntl.h>
#  include <sys/socket.h>
#  include <sys/stat.h>
#  include <sys/un.h>
#  include <unistd.h>
#endif

namespace airusb::control {

namespace {

#if defined(_WIN32)

/// A named pipe, as an IByteStream. Overlapped is not used: this channel
/// carries small control records and the broker polls it, so a non-blocking
/// pipe in message-agnostic byte mode is all it needs.
class PipeStream final : public transport::IByteStream {
public:
    explicit PipeStream(HANDLE h) noexcept : _h(h) {}
    ~PipeStream() override { close(); }

    transport::IoResult write(std::span<const std::uint8_t> src) override
    {
        if (_h == INVALID_HANDLE_VALUE) return { Status::TransportLost, 0 };
        DWORD wrote = 0;
        if (!::WriteFile(_h, src.data(), static_cast<DWORD>(src.size()), &wrote, nullptr)) {
            const DWORD e = ::GetLastError();
            if (e == ERROR_NO_DATA || e == ERROR_BROKEN_PIPE) return { Status::TransportLost, 0 };
            return { Status::TransportLost, 0 };
        }
        return { Status::Ok, static_cast<std::size_t>(wrote) };
    }

    transport::IoResult read(std::span<std::uint8_t> dst) override
    {
        if (_h == INVALID_HANDLE_VALUE) return { Status::TransportLost, 0 };
        // PeekNamedPipe first: ReadFile on a byte-mode pipe blocks until at
        // least one byte arrives, and this stream must never block the broker's
        // single loop.
        DWORD avail = 0;
        if (!::PeekNamedPipe(_h, nullptr, 0, nullptr, &avail, nullptr))
            return { Status::TransportLost, 0 };
        if (avail == 0) return { Status::Busy, 0 };

        DWORD want = static_cast<DWORD>(dst.size() < avail ? dst.size() : avail);
        DWORD got  = 0;
        if (!::ReadFile(_h, dst.data(), want, &got, nullptr))
            return { Status::TransportLost, 0 };
        if (got == 0) return { Status::TransportLost, 0 };
        return { Status::Ok, static_cast<std::size_t>(got) };
    }

    void close() override
    {
        if (_h != INVALID_HANDLE_VALUE) { ::CloseHandle(_h); _h = INVALID_HANDLE_VALUE; }
    }

    bool isOpen() const noexcept override { return _h != INVALID_HANDLE_VALUE; }

private:
    HANDLE _h;
};

#else

/// A connected AF_UNIX socket, as an IByteStream. Non-blocking, because the
/// broker's loop also has to service a network peer and a device.
class UnixStream final : public transport::IByteStream {
public:
    explicit UnixStream(int fd) noexcept : _fd(fd) {}
    ~UnixStream() override { close(); }

    transport::IoResult write(std::span<const std::uint8_t> src) override
    {
        if (_fd < 0) return { Status::TransportLost, 0 };
        for (;;) {
            const ssize_t n = ::send(_fd, src.data(), src.size(), 0);
            if (n > 0) return { Status::Ok, static_cast<std::size_t>(n) };
            if (n == 0) return { Status::Busy, 0 };
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return { Status::Busy, 0 };
            return { Status::TransportLost, 0 };
        }
    }

    transport::IoResult read(std::span<std::uint8_t> dst) override
    {
        if (_fd < 0) return { Status::TransportLost, 0 };
        for (;;) {
            const ssize_t n = ::recv(_fd, dst.data(), dst.size(), 0);
            // Zero bytes is end of file, not "nothing yet". Reporting it as
            // Busy would spin for ever after the window exits.
            if (n == 0) return { Status::TransportLost, 0 };
            if (n > 0)  return { Status::Ok, static_cast<std::size_t>(n) };
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return { Status::Busy, 0 };
            return { Status::TransportLost, 0 };
        }
    }

    void close() override { if (_fd >= 0) { ::close(_fd); _fd = -1; } }
    bool isOpen() const noexcept override { return _fd >= 0; }

private:
    int _fd;
};

void setNonBlocking(int fd) noexcept
{
    const int fl = ::fcntl(fd, F_GETFL, 0);
    (void)::fcntl(fd, F_SETFL, (fl < 0 ? 0 : fl) | O_NONBLOCK);
}

#endif

} // namespace

// ---------------------------------------------------------------------------

std::string defaultBrokerPath()
{
    if (const char* e = std::getenv("AIRUSB_BROKER"); e && *e) return e;
#if defined(_WIN32)
    return R"(\\.\pipe\airusb-broker)";
#elif defined(__APPLE__)
    return "/var/run/airusb-broker.sock";
#else
    return "/run/airusb-broker.sock";
#endif
}

LocalListener::~LocalListener() { close(); }

bool LocalListener::isOpen() const noexcept
{
    return _handle != static_cast<std::uintptr_t>(-1);
}

// ---------------------------------------------------------------------------

#if defined(_WIN32)

Status LocalListener::open(const std::string& path, unsigned, std::string* why)
{
    // On Windows the ACL is the mechanism, not the mode bits. The pipe is
    // created with a security descriptor allowing SYSTEM, Administrators and
    // the INTERACTIVE group — the last of those is what lets the person
    // physically at the machine drive their own broker, and what keeps a
    // service account or a remote session from doing it silently.
    //
    // SDDL: D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)
    _path = path;
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof sa;
    sa.bInheritHandle = FALSE;
    if (!::ConvertStringSecurityDescriptorToSecurityDescriptorA(
            "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)",
            SDDL_REVISION_1, &sa.lpSecurityDescriptor, nullptr)) {
        if (why) *why = "could not build the pipe's security descriptor";
        return Status::Internal;
    }

    // FILE_FLAG_FIRST_PIPE_INSTANCE on the FIRST instance only.
    //
    // Every instance used to claim to be the first, so the replacement listener
    // created after accepting a client failed — the connected first instance
    // still existed — and the error was ignored. The broker served exactly one
    // window per run: close the page and reopen it, or start a second one, and
    // nothing could reach the daemon until it was restarted. Found by an
    // adversarial read of this session's own code.
    DWORD openMode = PIPE_ACCESS_DUPLEX;
    if (_first) openMode |= FILE_FLAG_FIRST_PIPE_INSTANCE;

    const HANDLE h = ::CreateNamedPipeA(
        path.c_str(),
        openMode,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT,
        PIPE_UNLIMITED_INSTANCES, 64 * 1024, 64 * 1024, 0, &sa);
    ::LocalFree(sa.lpSecurityDescriptor);

    if (h == INVALID_HANDLE_VALUE) {
        if (why) *why = "could not create the broker pipe — is one already running?";
        return Status::Busy;
    }
    _handle = reinterpret_cast<std::uintptr_t>(h);
    _bound  = true;
    _first  = false;
    return Status::Ok;
}

std::unique_ptr<transport::IByteStream> LocalListener::accept(PeerCredentials* credsOut)
{
    if (!isOpen()) return nullptr;
    const HANDLE h = reinterpret_cast<HANDLE>(_handle);

    if (!::ConnectNamedPipe(h, nullptr)) {
        const DWORD e = ::GetLastError();
        if (e != ERROR_PIPE_CONNECTED) return nullptr;   // nobody waiting
    }

    PeerCredentials c;
    ULONG pid = 0;
    if (::GetNamedPipeClientProcessId(h, &pid)) {
        c.pid   = static_cast<std::uint32_t>(pid);
        c.known = true;
        // The uid analogue on Windows is the client's token, and the pipe ACL
        // above is what enforces it. Recorded as known-with-no-uid rather than
        // invented, because a made-up number here would read as a check that
        // happened.
        c.uid = 0;
    }
    if (!c.known) {
        // Fail closed: an unknown peer on a privileged channel is exactly the
        // case not to accept.
        ::DisconnectNamedPipe(h);
        return nullptr;
    }
    if (credsOut) *credsOut = c;

    // Hand the connected instance out and create a fresh one to keep listening.
    // The failure is NOT ignored: a broker that has silently stopped listening
    // looks exactly like one that is running.
    auto stream = std::make_unique<PipeStream>(h);
    _handle = static_cast<std::uintptr_t>(-1);
    std::string why;
    if (open(_path, 0, &why) != Status::Ok) {
        // Nothing can reach us now, and saying so on stderr is the only channel
        // left — the control channel is the thing that just died.
        ::OutputDebugStringA("airusb: could not re-arm the broker pipe\n");
    }
    return stream;
}

void LocalListener::close()
{
    if (isOpen()) {
        const HANDLE h = reinterpret_cast<HANDLE>(_handle);
        ::DisconnectNamedPipe(h);
        ::CloseHandle(h);
    }
    _handle = static_cast<std::uintptr_t>(-1);
    _bound  = false;
    _first  = true;
}

std::unique_ptr<transport::IByteStream> connectLocal(const std::string& path,
                                                     Status* st, std::string* why)
{
    const HANDLE h = ::CreateFileA(path.c_str(), GENERIC_READ | GENERIC_WRITE,
                                   0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        if (st) *st = Status::NotFound;
        if (why) *why = "no broker is listening at " + path;
        return nullptr;
    }
    DWORD mode = PIPE_READMODE_BYTE | PIPE_NOWAIT;
    (void)::SetNamedPipeHandleState(h, &mode, nullptr, nullptr);
    if (st) *st = Status::Ok;
    return std::make_unique<PipeStream>(h);
}

#else

Status LocalListener::open(const std::string& path, unsigned mode, std::string* why)
{
    _path = path;

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (path.size() + 1 > sizeof addr.sun_path) {
        if (why) *why = "the broker socket path is too long for AF_UNIX";
        return Status::BadArgument;
    }
    std::memcpy(addr.sun_path, path.c_str(), path.size() + 1);

    const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        if (why) *why = std::string("socket: ") + std::strerror(errno);
        return Status::Internal;
    }

    // A stale socket from a crashed broker would make bind() fail with EADDRINUSE
    // for ever. Unlinked first — the same thing `listenOnUnixSocket` does, and
    // the reason a broker restart does not need a human.
    (void)::unlink(path.c_str());

    // 0600 first, THEN relaxed. Creating it at the final mode leaves a window,
    // however short, in which a socket that grants control of this machine's USB
    // devices is more permissive than intended.
    const mode_t old = ::umask(0177);
    const int rc = ::bind(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof addr);
    ::umask(old);
    if (rc != 0) {
        const int e = errno;
        ::close(fd);
        if (why) *why = std::string("bind(") + path + "): " + std::strerror(e);
        return Status::Busy;
    }
    if (mode != 0) (void)::chmod(path.c_str(), static_cast<mode_t>(mode));

    if (::listen(fd, 4) != 0) {
        const int e = errno;
        ::close(fd);
        (void)::unlink(path.c_str());
        if (why) *why = std::string("listen: ") + std::strerror(e);
        return Status::Internal;
    }

    setNonBlocking(fd);
    _handle = static_cast<std::uintptr_t>(fd);
    _bound  = true;
    return Status::Ok;
}

std::unique_ptr<transport::IByteStream> LocalListener::accept(PeerCredentials* credsOut)
{
    if (!isOpen()) return nullptr;
    const int lfd = static_cast<int>(_handle);

    const int fd = ::accept(lfd, nullptr, nullptr);
    if (fd < 0) return nullptr;

    PeerCredentials c;
#if defined(SO_PEERCRED) && !defined(__APPLE__)
    struct ucred uc{};
    socklen_t len = sizeof uc;
    if (::getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &uc, &len) == 0) {
        c.uid = static_cast<std::uint32_t>(uc.uid);
        c.pid = static_cast<std::uint32_t>(uc.pid);
        c.known = true;
    }
#else
    uid_t euid = 0;
    gid_t egid = 0;
    if (::getpeereid(fd, &euid, &egid) == 0) {
        c.uid = static_cast<std::uint32_t>(euid);
        c.known = true;
    }
#endif

    if (!c.known) {
        // Fail closed. A peer whose identity the kernel will not vouch for is
        // exactly the one not to let drive a privileged daemon.
        ::close(fd);
        return nullptr;
    }
    if (credsOut) *credsOut = c;

    setNonBlocking(fd);
    return std::make_unique<UnixStream>(fd);
}

void LocalListener::close()
{
    if (isOpen()) {
        ::close(static_cast<int>(_handle));
        if (_bound && !_path.empty()) (void)::unlink(_path.c_str());
    }
    _handle = static_cast<std::uintptr_t>(-1);
    _bound  = false;
}

std::unique_ptr<transport::IByteStream> connectLocal(const std::string& path,
                                                     Status* st, std::string* why)
{
    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (path.size() + 1 > sizeof addr.sun_path) {
        if (st) *st = Status::BadArgument;
        if (why) *why = "the broker socket path is too long for AF_UNIX";
        return nullptr;
    }
    std::memcpy(addr.sun_path, path.c_str(), path.size() + 1);

    const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        if (st) *st = Status::Internal;
        if (why) *why = std::string("socket: ") + std::strerror(errno);
        return nullptr;
    }
    if (::connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof addr) != 0) {
        const int e = errno;
        ::close(fd);
        if (st) *st = Status::NotFound;
        if (why) *why = "no broker is listening at " + path + " (" + std::strerror(e) + ")";
        return nullptr;
    }
    setNonBlocking(fd);
    if (st) *st = Status::Ok;
    return std::make_unique<UnixStream>(fd);
}

#endif

} // namespace airusb::control
