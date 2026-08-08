#include "FaultTransport.h"

#include <algorithm>

namespace airusb::transport {

IoResult FaultStream::write(std::span<const std::uint8_t> src)
{
    if (_reset) return {Status::TransportLost, 0};

    if (_cfg.stallEveryN != 0 && (++_writeSeq % _cfg.stallEveryN) == 0)
        return {Status::Ok, 0};                      // would block

    std::size_t n = src.size();
    if (_cfg.maxWriteChunk != 0) n = std::min(n, _cfg.maxWriteChunk);
    if (n == 0) return {Status::Ok, 0};

    _written += n;
    if (_cfg.resetAfterBytes != 0 && _written >= _cfg.resetAfterBytes) {
        _reset = true;
        return {Status::TransportLost, 0};
    }

    if (_cfg.delayMs == 0) {
        return _inner->write(src.first(n));
    }

    Pending p;
    p.bytes.assign(src.begin(), src.begin() + static_cast<std::ptrdiff_t>(n));
    p.dueNs = _clock.nowNs() + _cfg.delayMs * 1'000'000ull;
    _pending.push_back(std::move(p));
    return {Status::Ok, n};
}

void FaultStream::pump()
{
    const ContinuousNs now = _clock.nowNs();

    // Collect everything that is due.
    std::vector<Pending> due;
    while (!_pending.empty() && _pending.front().dueNs <= now) {
        due.push_back(std::move(_pending.front()));
        _pending.pop_front();
    }
    if (due.empty()) return;

    // Reordering is applied across the due set, never inside a single write: a
    // transport that shuffled bytes within one write would be modelling corruption,
    // not reordering, and TCP does not do that.
    if (_cfg.reorder) std::reverse(due.begin(), due.end());

    for (auto& p : due) {
        std::size_t sent = 0;
        while (sent < p.bytes.size()) {
            IoResult r = _inner->write(std::span<const std::uint8_t>(p.bytes.data() + sent,
                                                                     p.bytes.size() - sent));
            if (r.status != Status::Ok) { _reset = true; return; }
            if (r.bytes == 0) {
                // The inner pipe is full. Put the remainder back at the front so
                // nothing is silently dropped -- a dropped byte would look like
                // corruption to the record layer rather than backpressure.
                Pending rest;
                rest.bytes.assign(p.bytes.begin() + static_cast<std::ptrdiff_t>(sent),
                                  p.bytes.end());
                rest.dueNs = now;
                _pending.push_front(std::move(rest));
                return;
            }
            sent += r.bytes;
        }
    }
}

IoResult FaultStream::read(std::span<std::uint8_t> dst)
{
    if (_reset) return {Status::TransportLost, 0};
    pump();
    return _inner->read(dst);
}

} // namespace airusb::transport
