// AirUSB Hub — TCP byte stream, and the in-memory pipe used by every test.
//
// TcpStream is deliberately thin: non-blocking sockets, TCP_NODELAY, and nothing
// else. All the interesting behaviour (framing, priority, backpressure) lives
// above it, so it can be swapped for QUIC without any of that moving.

#ifndef AIRUSB_TRANSPORT_TCPTRANSPORT_H
#define AIRUSB_TRANSPORT_TCPTRANSPORT_H

#include "IAirUsbTransport.h"
#include "../core/Platform.h"

#include <deque>
#include <memory>
#include <string>

namespace airusb::transport {

class TcpStream final : public IByteStream {
public:
    TcpStream() = default;
    explicit TcpStream(platform::SocketHandle fd) noexcept : _fd(fd) {}
    ~TcpStream() override;

    TcpStream(const TcpStream&) = delete;
    TcpStream& operator=(const TcpStream&) = delete;

    /// Blocking connect, then the socket is switched to non-blocking.
    static std::unique_ptr<TcpStream> connect(const std::string& host, std::uint16_t port,
                                              Status* status = nullptr);

    /// Listening socket helper. Returns platform::kInvalidSocket on failure.
    ///
    /// `loopbackOnly` binds 127.0.0.1 instead of INADDR_ANY. It is a different
    /// kind of guarantee from a firewall rule or an authentication check: a
    /// socket bound to the loopback address cannot receive a packet from
    /// another host at all, so the control plane's reachability stops being a
    /// property of configuration. The device-sharing listener does NOT use it —
    /// being reachable from the LAN is that socket's entire purpose.
    static platform::SocketHandle listen(std::uint16_t port, Status* status = nullptr,
                                         bool loopbackOnly = false);

    /// Accepts one connection from a listening fd. Returns nullptr when there is
    /// nothing pending.
    static std::unique_ptr<TcpStream> accept(platform::SocketHandle listenFd,
                                            Status* status = nullptr);

    IoResult write(std::span<const std::uint8_t> src) override;
    IoResult read(std::span<std::uint8_t> dst) override;
    void close() override;
    bool isOpen() const noexcept override { return platform::isValid(_fd); }

    platform::SocketHandle fd() const noexcept { return _fd; }

private:
    platform::SocketHandle _fd = platform::kInvalidSocket;
};

/// A byte pipe in memory. Two of these cross-wired give a full-duplex connection
/// with no kernel involved, which is what makes the loopback gate deterministic:
/// a real socketpair introduces scheduling noise that turns ordering bugs
/// intermittent.
class MemoryPipe {
public:
    /// One direction of the pipe.
    class Endpoint final : public IByteStream {
    public:
        // Both open flags are needed, not just our own: a reader must be able to
        // tell "nothing yet" from "the peer hung up", and only the peer's flag
        // says which. Tracking one flag makes a closed connection look like an
        // indefinite stall.
        Endpoint(std::deque<std::uint8_t>* in, std::deque<std::uint8_t>* out,
                 bool* selfOpen, bool* peerOpen) noexcept
            : _in(in), _out(out), _self(selfOpen), _peer(peerOpen) {}

        IoResult write(std::span<const std::uint8_t> src) override;
        IoResult read(std::span<std::uint8_t> dst) override;
        void close() override { *_self = false; }
        bool isOpen() const noexcept override { return *_self; }

        /// Caps how much may sit unread, so a test can exercise backpressure.
        void setCapacity(std::size_t bytes) noexcept { _capacity = bytes; }

    private:
        std::deque<std::uint8_t>* _in;
        std::deque<std::uint8_t>* _out;
        bool*                     _self;
        bool*                     _peer;
        std::size_t               _capacity = 0;   // 0 = unbounded
    };

    MemoryPipe() = default;

    std::unique_ptr<IByteStream> endpointA();
    std::unique_ptr<IByteStream> endpointB();

    std::size_t bytesAtoB() const noexcept { return _aToB.size(); }
    std::size_t bytesBtoA() const noexcept { return _bToA.size(); }

private:
    std::deque<std::uint8_t> _aToB;
    std::deque<std::uint8_t> _bToA;
    bool _openA = true;
    bool _openB = true;
};

} // namespace airusb::transport

#endif // AIRUSB_TRANSPORT_TCPTRANSPORT_H
