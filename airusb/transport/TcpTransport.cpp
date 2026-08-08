#include "TcpTransport.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

namespace airusb::transport {

namespace {

void setNonBlocking(int fd) noexcept
{
    const int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags >= 0) ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

void setNoDelay(int fd) noexcept
{
    // USB control transfers are small and latency-critical, and every one of them
    // sits in the enumeration critical path. Nagle would coalesce them into 40 ms
    // stalls and make enumeration look broken.
    int one = 1;
    ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
}

Status errnoToStatus(int e) noexcept
{
    switch (e) {
        case EAGAIN:
#if EWOULDBLOCK != EAGAIN
        case EWOULDBLOCK:
#endif
        case EINTR:       return Status::Ok;          // caller retries
        case ECONNRESET:
        case EPIPE:
        case ENOTCONN:
        case ETIMEDOUT:   return Status::TransportLost;
        case EACCES:
        case EPERM:       return Status::NotPermitted;
        default:          return Status::TransportLost;
    }
}

} // namespace

// ---------------------------------------------------------------------------

TcpStream::~TcpStream() { close(); }

void TcpStream::close()
{
    if (_fd >= 0) { ::close(_fd); _fd = -1; }
}

IoResult TcpStream::write(std::span<const std::uint8_t> src)
{
    if (_fd < 0) return {Status::TransportLost, 0};
    const ssize_t n = ::send(_fd, src.data(), src.size(), 0);
    if (n < 0) return {errnoToStatus(errno), 0};
    return {Status::Ok, static_cast<std::size_t>(n)};
}

IoResult TcpStream::read(std::span<std::uint8_t> dst)
{
    if (_fd < 0) return {Status::TransportLost, 0};
    const ssize_t n = ::recv(_fd, dst.data(), dst.size(), 0);
    if (n < 0) return {errnoToStatus(errno), 0};
    // A zero-length read on a stream socket is an orderly peer close, not "no data
    // yet" — conflating the two makes a closed connection look like a stall.
    if (n == 0) return {Status::TransportLost, 0};
    return {Status::Ok, static_cast<std::size_t>(n)};
}

std::unique_ptr<TcpStream> TcpStream::connect(const std::string& host, std::uint16_t port,
                                              Status* status)
{
    auto set = [&](Status s) { if (status) *status = s; };

    struct addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    const std::string portStr = std::to_string(port);
    struct addrinfo* res = nullptr;
    if (::getaddrinfo(host.c_str(), portStr.c_str(), &hints, &res) != 0 || !res) {
        set(Status::NotFound);
        return nullptr;
    }

    int fd = -1;
    for (struct addrinfo* p = res; p; p = p->ai_next) {
        fd = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;
        if (::connect(fd, p->ai_addr, p->ai_addrlen) == 0) break;
        ::close(fd);
        fd = -1;
    }
    ::freeaddrinfo(res);

    if (fd < 0) { set(Status::TransportLost); return nullptr; }

    setNoDelay(fd);
    setNonBlocking(fd);
    set(Status::Ok);
    return std::make_unique<TcpStream>(fd);
}

int TcpStream::listen(std::uint16_t port, Status* status)
{
    auto set = [&](Status s) { if (status) *status = s; };

    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { set(Status::TransportLost); return -1; }

    int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port        = htons(port);

    if (::bind(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0
        || ::listen(fd, 8) != 0) {
        ::close(fd);
        set(Status::TransportLost);
        return -1;
    }

    setNonBlocking(fd);
    set(Status::Ok);
    return fd;
}

std::unique_ptr<TcpStream> TcpStream::accept(int listenFd, Status* status)
{
    auto set = [&](Status s) { if (status) *status = s; };
    const int fd = ::accept(listenFd, nullptr, nullptr);
    if (fd < 0) { set(errnoToStatus(errno)); return nullptr; }
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
