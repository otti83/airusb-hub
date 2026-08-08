// AirUSB Hub — fault injection decorator (P1 plan §8.1, P2.5)
//
// Test-only. Wraps any IByteStream and misbehaves on demand, so the recovery
// paths are exercised deterministically instead of being hoped for.
//
// SlowPeer is the important one. INV-CMD says the macOS command handler must
// never block on network I/O, because an unanswered command past
// commandTimeoutThreshold destroys the controller. A uniform multi-second delay
// here is what proves the design holds: if any code path waits for the peer
// inside the command handler, the fault matrix turns that into a reproducible
// failure rather than a rare field crash.
//
// Determinism is deliberate: a seeded xorshift, never a real RNG, so a failing
// run can be replayed exactly.

#ifndef AIRUSB_TRANSPORT_FAULTTRANSPORT_H
#define AIRUSB_TRANSPORT_FAULTTRANSPORT_H

#include "IAirUsbTransport.h"
#include "../core/Clock.h"

#include <deque>
#include <memory>

namespace airusb::transport {

struct FaultConfig {
    /// Every write is held for this long before becoming readable.
    std::uint64_t delayMs = 0;

    /// Truncate writes to at most this many bytes, forcing the framing layer to
    /// reassemble across reads. 0 = no limit.
    std::size_t maxWriteChunk = 0;

    /// Return "would block" on one write in every N. 0 = never.
    std::uint32_t stallEveryN = 0;

    /// Drop the connection after this many bytes have been written. 0 = never.
    std::uint64_t resetAfterBytes = 0;

    /// Deliver bytes in reverse order within each flush window. Only meaningful
    /// with delayMs > 0, and used to prove the record layer never depends on
    /// arrival order within a record.
    bool reorder = false;

    std::uint64_t seed = 0x5EED1234;
};

class FaultStream final : public IByteStream {
public:
    FaultStream(std::unique_ptr<IByteStream> inner, FaultConfig cfg, const Clock& clock)
        : _inner(std::move(inner)), _cfg(cfg), _clock(clock), _rng(cfg.seed ? cfg.seed : 1) {}

    IoResult write(std::span<const std::uint8_t> src) override;
    IoResult read(std::span<std::uint8_t> dst) override;
    void close() override { _inner->close(); }
    bool isOpen() const noexcept override { return !_reset && _inner->isOpen(); }

    /// Releases anything whose delay has elapsed. A test drives this explicitly so
    /// timing is a controlled variable rather than a race.
    void pump();

    std::uint64_t bytesWritten() const noexcept { return _written; }
    bool wasReset() const noexcept { return _reset; }

private:
    struct Pending {
        std::vector<std::uint8_t> bytes;
        ContinuousNs              dueNs;
    };

    std::uint64_t next() noexcept
    {
        _rng ^= _rng << 13; _rng ^= _rng >> 7; _rng ^= _rng << 17;
        return _rng;
    }

    std::unique_ptr<IByteStream> _inner;
    FaultConfig                  _cfg;
    const Clock&                 _clock;
    std::uint64_t                _rng;

    std::deque<Pending> _pending;
    std::uint64_t       _written  = 0;
    std::uint32_t       _writeSeq = 0;
    bool                _reset    = false;
};

} // namespace airusb::transport

#endif // AIRUSB_TRANSPORT_FAULTTRANSPORT_H
