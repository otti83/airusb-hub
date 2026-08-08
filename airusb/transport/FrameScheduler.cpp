#include "FrameScheduler.h"

namespace airusb::transport {

void FrameScheduler::enqueue(Frame f)
{
    const std::size_t p = static_cast<std::size_t>(f.priority);
    _totalBytes += f.bytes.size();
    if (f.expedite) _q[p].push_front(std::move(f));
    else            _q[p].push_back(std::move(f));
}

bool FrameScheduler::dequeue(Frame& out)
{
    // Class 0 has strict priority: session control, PING/PONG and CANCEL must never
    // wait behind data. CANCEL in particular is latency-critical, because a cancel
    // that arrives after the transfer it was cancelling is useless.
    auto& ctrl = _q[static_cast<std::size_t>(Priority::Control)];
    if (!ctrl.empty()) {
        out = std::move(ctrl.front());
        ctrl.pop_front();
        _totalBytes -= out.bytes.size();
        return true;
    }

    // Deficit round robin over the remaining classes.
    constexpr std::size_t first = static_cast<std::size_t>(Priority::Rt);
    constexpr std::size_t count = kPriorityCount - first;

    for (std::size_t attempt = 0; attempt < count * 2; ++attempt) {
        const std::size_t p = first + ((_rrCursor - first + attempt) % count);
        if (_q[p].empty()) {
            // An empty class must not bank credit; otherwise a silent endpoint
            // accumulates deficit and then bursts ahead of everyone when it wakes.
            _deficit[p] = 0;
            continue;
        }

        if (_deficit[p] <= 0) {
            _deficit[p] += _quantum;
            continue;                     // credited; give the next class a turn
        }

        out = std::move(_q[p].front());
        _q[p].pop_front();
        _deficit[p] -= static_cast<std::int64_t>(out.bytes.size());
        _totalBytes -= out.bytes.size();
        _rrCursor = first + ((p - first + 1) % count);
        return true;
    }

    // Everything non-empty was out of credit; grant a round and take the first.
    for (std::size_t p = first; p < kPriorityCount; ++p) {
        if (!_q[p].empty()) {
            _deficit[p] += _quantum;
            out = std::move(_q[p].front());
            _q[p].pop_front();
            _deficit[p] -= static_cast<std::int64_t>(out.bytes.size());
            _totalBytes -= out.bytes.size();
            _rrCursor = first + ((p - first + 1) % count);
            return true;
        }
    }
    return false;
}

bool FrameScheduler::empty() const noexcept
{
    for (const auto& q : _q) if (!q.empty()) return false;
    return true;
}

std::size_t FrameScheduler::queuedFrames() const noexcept
{
    std::size_t n = 0;
    for (const auto& q : _q) n += q.size();
    return n;
}

std::size_t FrameScheduler::dropChannel(std::uint16_t channel)
{
    std::size_t dropped = 0;
    for (auto& q : _q) {
        for (auto it = q.begin(); it != q.end(); ) {
            if (it->channel == channel) {
                _totalBytes -= it->bytes.size();
                it = q.erase(it);
                ++dropped;
            } else {
                ++it;
            }
        }
    }
    return dropped;
}

} // namespace airusb::transport
