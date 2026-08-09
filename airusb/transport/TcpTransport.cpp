#include "TcpTransport.h"

#include "../core/Platform.h"

#include <cstring>

namespace airusb::transport {

namespace {

void setNonBlocking(platform::SocketHandle fd) noexcept
{
    (void)platform::setNonBlocking(fd);
}

void setNoDelay(platform::SocketHandle fd) noexcept
{
    // USB control transfers are small and latency-critical, and every one of them
    // sits in the enumeration critical path. Nagle would coalesce them into 40 ms
    // stalls and make enumeration look broken.
    int one = 1;
    ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
                 reinterpret_cast<const char*>(&one), sizeof(one));
}

/// The two families of socket error codes, mapped through one predicate set so
/// the call sites read the same on every platform.
Status socketErrorToStatus(int e) noexcept
{
    // "Would block" is Ok with zero bytes moved, not an error: the caller's loop
    // retries. Conflating it with a real failure turns every non-blocking socket
    // into a dead one.
    if (platform::wouldBlock(e)) return Status::Ok;
    if (platform::connectionLost(e)) return Status::TransportLost;
    return Status::TransportLost;
}

} // namespace

// ---------------------------------------------------------------------------

TcpStream::~TcpStream() { close(); }

void TcpStream::close()
{
    platform::closeSocket(_fd);
    _fd = platform::kInvalidSocket;
}

IoResult TcpStream::write(std::span<const std::uint8_t> src)
{
    if (!platform::isValid(_fd)) return {Status::TransportLost, 0};
    // Winsock's send takes `const char*` and an int length; POSIX takes void*
    // and size_t. platform::ioLength picks the right one and clamps.
    const auto n = ::send(_fd, reinterpret_cast<const char*>(src.data()),
                          platform::ioLength(src.size()), 0);
    if (n < 0) return {socketErrorToStatus(platform::lastSocketError()), 0};
    return {Status::Ok, static_cast<std::size_t>(n < 0 ? 0 : n)};
}

IoResult TcpStream::read(std::span<std::uint8_t> dst)
{
    if (!platform::isValid(_fd)) return {Status::TransportLost, 0};
    const auto n = ::recv(_fd, reinterpret_cast<char*>(dst.data()),
                          platform::ioLength(dst.size()), 0);
    if (n < 0) return {socketErrorToStatus(platform::lastSocketError()), 0};
    // A zero-length read on a stream socket is an orderly peer close, not "no data
    // yet" — conflating the two makes a closed connection look like a stall.
    if (n == 0) return {Status::TransportLost, 0};
    return {Status::Ok, static_cast<std::size_t>(n < 0 ? 0 : n)};
}

std::unique_ptr<TcpStream> TcpStream::connect(const std::string& host, std::uint16_t port,
                                              Status* status)
{
    auto set = [&](Status s) { if (status) *status = s; };
    if (!platform::ensureNetworkReady()) { set(Status::Internal); return nullptr; }

    struct addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    const std::string portStr = std::to_string(port);
    struct addrinfo* res = nullptr;
    if (::getaddrinfo(host.c_str(), portStr.c_str(), &hints, &res) != 0 || !res) {
        set(Status::NotFound);
        return nullptr;
    }

    platform::SocketHandle fd = platform::kInvalidSocket;
    for (struct addrinfo* p = res; p; p = p->ai_next) {
        fd = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (!platform::isValid(fd)) continue;
        // Connect while still blocking, then switch to non-blocking. A
        // non-blocking connect would need its own completion path on every
        // platform for no benefit at session setup.
        if (::connect(fd, p->ai_addr,
                      static_cast<socklen_t>(p->ai_addrlen)) == 0) break;
        platform::closeSocket(fd);
        fd = platform::kInvalidSocket;
    }
    ::freeaddrinfo(res);

    if (!platform::isValid(fd)) { set(Status::TransportLost); return nullptr; }

    setNoDelay(fd);
    setNonBlocking(fd);
    set(Status::Ok);
    return std::make_unique<TcpStream>(fd);
}

platform::SocketHandle TcpStream::listen(std::uint16_t port, Status* status,
                                         bool loopbackOnly)
{
    auto set = [&](Status s) { if (status) *status = s; };
    if (!platform::ensureNetworkReady()) {
        set(Status::Internal);
        return platform::kInvalidSocket;
    }

    const platform::SocketHandle fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (!platform::isValid(fd)) { set(Status::TransportLost); return platform::kInvalidSocket; }

    // SO_REUSEADDR, deliberately, on Windows as well as POSIX. SO_EXCLUSIVEADDRUSE
    // was considered here and rejected; the reasoning is recorded so it is not
    // re-litigated:
    //
    //   * Winsock's hijack rule is keyed on the SECOND binder, not the first. A
    //     socket that sets SO_REUSEADDR can bind over one that set no options at
    //     all, so dropping the option here would not have prevented anything.
    //     Only SO_EXCLUSIVEADDRUSE on THIS socket blocks it.
    //   * Since Server 2003 that hijack requires the same user account — and a
    //     process running as this user can already read the Ed25519 seed that
    //     loadOrCreateIdentity writes (on Windows `privateToOwner` is a no-op and
    //     the file inherits the directory ACL). Someone who can steal the port
    //     can already steal the identity, so it is inside the trust boundary
    //     rather than a new primitive.
    //   * SO_EXCLUSIVEADDRUSE has a real cost: Windows refuses a wildcard bind
    //     under it while any socket on the port sits in TIME_WAIT. Ctrl-C on
    //     `serve` with a session open makes this side the active closer, so the
    //     next `serve` on the same port fails for up to 120 s. For a tool whose
    //     job is repeated hand-driven bring-up, that trade is the wrong way round.
    int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                 reinterpret_cast<const char*>(&one), sizeof(one));

    struct sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(loopbackOnly ? INADDR_LOOPBACK : INADDR_ANY);
    addr.sin_port        = htons(port);

    if (::bind(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0
        || ::listen(fd, 8) != 0) {
        platform::closeSocket(fd);
        set(Status::TransportLost);
        return platform::kInvalidSocket;
    }

    setNonBlocking(fd);
    set(Status::Ok);
    return fd;
}

std::unique_ptr<TcpStream> TcpStream::accept(platform::SocketHandle listenFd,
                                            Status* status)
{
    auto set = [&](Status s) { if (status) *status = s; };
    const platform::SocketHandle fd = ::accept(listenFd, nullptr, nullptr);
    if (!platform::isValid(fd)) {
        set(socketErrorToStatus(platform::lastSocketError()));
        return nullptr;
    }
    setNoDelay(fd);
    setNonBlocking(fd);
    set(Status::Ok);
    return std::make_unique<TcpStream>(fd);
}

// ---------------------------------------------------------------------------

IoResult MemoryPipe::Endpoint::write(std::span<const std::uint8_t> src)
{
    if (!*_self || !*_peer) return {Status::TransportLost, 0};

    std::size_t room = src.size();
    if (_capacity != 0) {
        if (_out->size() >= _capacity) return {Status::Ok, 0};      // would block
        room = _capacity - _out->size();
        if (room > src.size()) room = src.size();
    }
    _out->insert(_out->end(), src.begin(), src.begin() + static_cast<std::ptrdiff_t>(room));
    return {Status::Ok, room};
}

IoResult MemoryPipe::Endpoint::read(std::span<std::uint8_t> dst)
{
    if (_in->empty()) {
        // Drained AND the peer is gone is a close; drained with the peer still up
        // is just "nothing yet". Buffered bytes are always delivered first, so a
        // close never discards data the peer already wrote.
        return (*_self && *_peer) ? IoResult{Status::Ok, 0}
                                  : IoResult{Status::TransportLost, 0};
    }
    const std::size_t n = _in->size() < dst.size() ? _in->size() : dst.size();
    for (std::size_t i = 0; i < n; ++i) dst[i] = (*_in)[i];
    _in->erase(_in->begin(), _in->begin() + static_cast<std::ptrdiff_t>(n));
    return {Status::Ok, n};
}

std::unique_ptr<IByteStream> MemoryPipe::endpointA()
{
    return std::make_unique<Endpoint>(&_bToA, &_aToB, &_openA, &_openB);
}

std::unique_ptr<IByteStream> MemoryPipe::endpointB()
{
    return std::make_unique<Endpoint>(&_aToB, &_bToA, &_openB, &_openA);
}

} // namespace airusb::transport
