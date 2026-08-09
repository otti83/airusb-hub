// AirUSB Hub — W5's transport: the IOCTL channel to airusb.sys.
//
// `UdecxBridge` is written against `IDriverChannel`, an interface of whole
// records in and whole records out, and has been tested for a session against
// a fake one. This is the real one, and it is deliberately the ONLY file in the
// Windows importer that knows what a HANDLE is.
//
// FOUR OVERLAPPED FETCHES, NOT ONE
//
// The inverted call is a request the driver holds until it has work. With one
// parked at a time, every URB costs a full round trip before the next can even
// be asked for, so the pipe idles for the length of a syscall on every
// transfer. Four is enough to keep one in the driver's hands while three are
// being processed, and small enough that a host which dies leaves a bounded
// number of requests for the kernel to cancel.
//
// NOTHING HERE BLOCKS
//
// `tryReceive` polls its overlapped results with a zero wait and re-arms;
// `send` takes a free completion slot and returns; `flush` reaps. The bridge
// above is a single-threaded event loop that also has to keep the network
// moving, and it is the same discipline the Linux side follows for the same
// reason — a host that waits inside a callback is a host that stops answering.
//
// AND IT PUSHES ITS OWN BACKLOG
//
// `pendingToDriver()` is not decoration. The exporter side of this project once
// stranded the tail of a 128 KiB reply because a short write reported success
// and nobody flushed again; the same shape of bug here is a completion the
// driver never receives and a guest URB that never ends. The bridge asks every
// poll, and this answers honestly.

#ifndef AIRUSB_PLATFORM_WINDOWS_UDECXDRIVERCHANNEL_H
#define AIRUSB_PLATFORM_WINDOWS_UDECXDRIVERCHANNEL_H

#include "UdecxBridge.h"

#include <cstdint>
#include <string>
#include <vector>

namespace airusb::windows {

/// Opens the driver's device interface and speaks the IOCTL ABI over it.
///
/// Compiles ONLY on Windows. Everything it drives — `UdecxBridge`, `UdecxIpc`,
/// `ImporterDataPlane` — is portable and is built and tested on three
/// platforms, which is what makes this file small enough to reason about
/// without a kernel in the room.
class UdecxDriverChannel final : public IDriverChannel {
public:
    UdecxDriverChannel() = default;
    ~UdecxDriverChannel() override;

    UdecxDriverChannel(const UdecxDriverChannel&)            = delete;
    UdecxDriverChannel& operator=(const UdecxDriverChannel&) = delete;

    /// Finds the driver through its device-interface GUID and binds to it.
    ///
    /// Returns NotFound when the driver is not installed, which is the ordinary
    /// case on every Windows machine today and is what the broker turns into a
    /// sentence rather than a failure.
    Status open(std::string* why);
    void   close();
    bool   isOpen() const noexcept;

    /// Presents a device to Windows. The manifest travels whole, in one
    /// buffered IOCTL, because the driver must snapshot it before walking any
    /// nested length in it.
    Status plugIn(const DeviceManifest& manifest, std::uint8_t configValue,
                  std::string* why);
    Status plugOut(std::string* why);

    /// The incarnations the DRIVER assigned, learned from BIND and PLUG_IN.
    ///
    /// They are not ours to choose, and choosing them was a stop-ship bug: the
    /// presenter invented random values, the driver used its own counters, and
    /// every record the two exchanged was rejected as stale by the other side.
    /// The first enumeration URB would have waited for ever, and the hosted
    /// bridge test could not have seen it because it configures both ends with
    /// the same constants.
    std::uint32_t sessionIncarnation() const noexcept;
    std::uint32_t deviceIncarnation()  const noexcept;

    // --- IDriverChannel -----------------------------------------------------
    bool   tryReceive(std::vector<std::uint8_t>& out) override;
    Status send(std::span<const std::uint8_t> record) override;
    std::size_t pendingToDriver() const override;
    Status flush() override;

    /// Diagnostics. `fetchesInFlight` is how many inverted calls the driver is
    /// holding; if it ever reaches zero while transfers are moving, the host is
    /// the bottleneck and not the network.
    std::size_t fetchesInFlight() const noexcept;

private:
    struct Impl;
    Impl* _impl = nullptr;
};

} // namespace airusb::windows

#endif // AIRUSB_PLATFORM_WINDOWS_UDECXDRIVERCHANNEL_H
