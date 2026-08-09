// AirUSB Hub — an IByteStream over a raw file descriptor.
//
// Small on purpose. It exists so VhciBridge, which is written against
// IByteStream and tested over MemoryPipe on a Mac, can be handed the socket that
// vhci-hcd is on the other end of, without knowing that is what happened.

#ifndef AIRUSB_PLATFORM_LINUX_FDSTREAM_H
#define AIRUSB_PLATFORM_LINUX_FDSTREAM_H

#include "../../transport/IAirUsbTransport.h"

#include <cerrno>
#include <span>
#include <unistd.h>

namespace airusb::linuxvhci {

class FdStream final : public transport::IByteStream {
public:
    explicit FdStream(int fd) noexcept : _fd(fd) {}
    ~FdStream() override { close(); }

    FdStream(const FdStream&)            = delete;
    FdStream& operator=(const FdStream&) = delete;

    transport::IoResult write(std::span<const std::uint8_t> src) override
    {
        if (_fd < 0) return { Status::TransportLost, 0 };
        for (;;) {
            const ssize_t n = ::write(_fd, src.data(), src.size());
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
            const ssize_t n = ::read(_fd, dst.data(), dst.size());
            // Zero bytes on a blocking read is end of file, not "nothing yet".
            // Reporting it as Busy would spin for ever after the kernel detached.
            if (n == 0) return { Status::TransportLost, 0 };
            if (n > 0)  return { Status::Ok, static_cast<std::size_t>(n) };
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return { Status::Busy, 0 };
            return { Status::TransportLost, 0 };
        }
    }

    void close() override
    {
        if (_fd >= 0) { ::close(_fd); _fd = -1; }
    }

    bool isOpen() const noexcept override { return _fd >= 0; }

private:
    int _fd;
};

} // namespace airusb::linuxvhci

#endif // AIRUSB_PLATFORM_LINUX_FDSTREAM_H
