// AirUSB Hub — transport abstraction (P1 plan §2, master spec §4)
//
// The USB protocol must not be coupled to the transport. TCP is v1; QUIC replaces
// this implementation without the protocol layer noticing, which is the whole
// reason the L1 header carries a channel id and mandatory segmentation: those map
// onto QUIC streams directly, so the move is a transport swap rather than a
// protocol redesign.
//
// Two layers, deliberately separate:
//   IByteStream         an ordered, reliable byte pipe (a TCP socket, a socketpair,
//                       or an in-memory pipe in tests)
//   IAirUsbTransport    record-oriented: hands whole records up and down, and is
//                       where framing and AEAD live

#ifndef AIRUSB_TRANSPORT_IAIRUSBTRANSPORT_H
#define AIRUSB_TRANSPORT_IAIRUSBTRANSPORT_H

#include "../core/Status.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace airusb::transport {

/// Result of a partial read/write. `bytes` is meaningful only when status is Ok.
struct IoResult {
    Status      status = Status::Ok;
    std::size_t bytes  = 0;
};

/// An ordered, reliable byte pipe. Implementations are not required to be
/// thread-safe; the session owns one Rx strand and one Tx strand per connection.
class IByteStream {
public:
    virtual ~IByteStream() = default;

    /// Writes as much as it can. A short write is normal and not an error.
    virtual IoResult write(std::span<const std::uint8_t> src) = 0;

    /// Reads as much as is available. `bytes == 0` with Ok means "would block".
    /// Peer close is reported as Status::TransportLost.
    virtual IoResult read(std::span<std::uint8_t> dst) = 0;

    virtual void close() = 0;
    virtual bool isOpen() const noexcept = 0;
};

/// Record-oriented transport. One send() is one record; one receive() yields one
/// whole record or nothing.
class IAirUsbTransport {
public:
    virtual ~IAirUsbTransport() = default;

    virtual Status sendRecord(std::span<const std::uint8_t> body) = 0;

    /// Returns Ok with `out` filled when a whole record is available, Ok with `out`
    /// empty when more bytes are needed, or a failure. A framing violation is
    /// MalformedFrame and is fatal to the session — there is no resync, by design:
    /// a resync marker is a way to keep talking to a peer that has already proven
    /// it disagrees with us about the byte stream.
    virtual Status receiveRecord(std::vector<std::uint8_t>& out) = 0;

    virtual void close() = 0;
    virtual bool isOpen() const noexcept = 0;
};

} // namespace airusb::transport

#endif // AIRUSB_TRANSPORT_IAIRUSBTRANSPORT_H
