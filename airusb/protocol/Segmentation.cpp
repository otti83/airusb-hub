#include "Segmentation.h"

namespace airusb::protocol {

std::vector<SegmentPlan> planSegments(std::uint32_t totalLen, std::uint32_t maxSegmentBytes)
{
    std::vector<SegmentPlan> out;
    if (maxSegmentBytes == 0) return out;

    if (totalLen == 0) {
        // Still one record. A zero-length transfer is a real event on the wire —
        // it is how a host terminates a transfer that is an exact multiple of the
        // packet size — and swallowing it here would lose it.
        out.push_back(SegmentPlan{ 0, 0, true, false });
        return out;
    }

    std::uint32_t offset = 0;
    while (offset < totalLen) {
        const std::uint32_t remaining = totalLen - offset;
        const std::uint32_t take = remaining < maxSegmentBytes ? remaining : maxSegmentBytes;
        SegmentPlan p;
        p.offset = offset;
        p.length = take;
        p.first  = (offset == 0);
        p.more   = (offset + take) < totalLen;
        out.push_back(p);
        offset += take;
    }
    return out;
}

// ---------------------------------------------------------------------------

Reassembler::Outcome Reassembler::accept(const Header& h,
                                         std::span<const std::uint8_t> payload,
                                         Status& error)
{
    error = Status::Ok;
    _hasCompleted = false;
    _completed.clear();

    const bool first = h.segFirst();
    const bool more  = h.segMore();
    const Key key{ h.channel, h.requestId };

    auto existing = _partial.find(key);

    // The LAST segment of a multi-segment transfer carries neither SEG_FIRST nor
    // SEG_MORE — exactly like a message that was never segmented at all. The
    // flags alone cannot tell them apart, so the transfer already in flight is
    // what decides: if one is open on this key, this is its continuation.
    //
    // Getting this backwards treats every final segment as a fresh unsegmented
    // message, which silently discards everything received before it.
    if (!first && !more && existing == _partial.end()) {
        if (h.totalLen > _limits.maxTransferBytes) {
            error = Status::LimitExceeded;
            return Outcome::Rejected;
        }
        if (payload.size() != h.totalLen) {
            error = Status::MalformedFrame;
            return Outcome::Rejected;
        }
        _completed.assign(payload.begin(), payload.end());
        _completedKey = key;
        _hasCompleted = true;
        return Outcome::Complete;
    }

    if (h.totalLen > _limits.maxTransferBytes) {
        error = Status::LimitExceeded;
        return Outcome::Rejected;
    }

    auto it = existing;

    if (first) {
        if (it != _partial.end()) {
            // A second SEG_FIRST for a transfer already in progress. Either the
            // peer is confused or it is trying to make us drop and re-hold the
            // arena; neither is something to recover from mid-transfer.
            error = Status::MalformedFrame;
            return Outcome::Rejected;
        }
        if (h.segOffset != 0) {
            error = Status::MalformedFrame;
            return Outcome::Rejected;
        }
        if (_partial.size() >= _limits.maxInFlight) {
            error = Status::LimitExceeded;
            return Outcome::Rejected;
        }
        Partial p;
        p.totalLen = h.totalLen;
        it = _partial.emplace(key, std::move(p)).first;
    } else {
        if (it == _partial.end()) {
            // A continuation for a transfer we never saw start. There is nothing
            // to append it to, and inventing a start would leave the bytes before
            // it uninitialised.
            error = Status::MalformedFrame;
            return Outcome::Rejected;
        }
        if (h.totalLen != it->second.totalLen) {
            // The declared size changed mid-transfer.
            error = Status::MalformedFrame;
            return Outcome::Rejected;
        }
    }

    Partial& p = it->second;

    // EXACT contiguity, not "within range". Each segment must begin precisely
    // where the last one ended: a gap would leave uninitialised bytes in a buffer
    // that is about to be written to a disk, and an overlap would let a peer
    // rewrite bytes we had already accepted.
    if (h.segOffset != p.bytes.size()) {
        error = Status::MalformedFrame;
        _held -= p.bytes.size();
        _partial.erase(it);
        return Outcome::Rejected;
    }

    // No allocation is ever sized by total_len alone; the arena grows with bytes
    // that actually arrived.
    if (p.bytes.size() + payload.size() > p.totalLen) {
        error = Status::MalformedFrame;
        _held -= p.bytes.size();
        _partial.erase(it);
        return Outcome::Rejected;
    }
    if (_held + payload.size() > _limits.arenaBytes) {
        error = Status::LimitExceeded;
        _held -= p.bytes.size();
        _partial.erase(it);
        return Outcome::Rejected;
    }

    p.bytes.insert(p.bytes.end(), payload.begin(), payload.end());
    _held += payload.size();

    if (more) return Outcome::NeedMore;

    // Last segment. It has to land exactly on total_len — a peer that says "no
    // more" while short of what it declared has given us a truncated transfer,
    // and the layer above would have no way to know.
    if (p.bytes.size() != p.totalLen) {
        error = Status::MalformedFrame;
        _held -= p.bytes.size();
        _partial.erase(it);
        return Outcome::Rejected;
    }

    _completed    = std::move(p.bytes);
    _completedKey = key;
    _hasCompleted = true;
    _held -= _completed.size();
    _partial.erase(it);
    return Outcome::Complete;
}

std::vector<std::uint8_t> Reassembler::take(const Header& h)
{
    const Key key{ h.channel, h.requestId };
    if (!_hasCompleted) return {};
    // Only the transfer that just completed may be taken, and only once. Handing
    // back the wrong buffer would be worse than handing back nothing.
    if (key < _completedKey || _completedKey < key) return {};
    _hasCompleted = false;
    return std::move(_completed);
}

void Reassembler::forgetChannel(std::uint16_t channel)
{
    for (auto it = _partial.begin(); it != _partial.end(); ) {
        if (it->first.channel == channel) {
            _held -= it->second.bytes.size();
            it = _partial.erase(it);
        } else {
            ++it;
        }
    }
}

void Reassembler::clear() noexcept
{
    _partial.clear();
    _held = 0;
    _completed.clear();
    _hasCompleted = false;
}

} // namespace airusb::protocol
