#include "RequestTable.h"

namespace airusb {

Status RequestTable::add(const OutstandingRequest& r)
{
    const Key k{r.channel, r.requestId};

    // Reuse of a LIVE request_id is the URB-aliasing bug: a late completion for
    // the old transfer would be applied to the new one.
    if (_byKey.find(k) != _byKey.end()) return Status::AlreadyExists;

    auto it = _lastSeen.find(r.channel);
    if (it != _lastSeen.end() && r.requestId <= it->second) return Status::BadArgument;

    _lastSeen[r.channel] = r.requestId;
    _byKey.emplace(k, r);
    return Status::Ok;
}

bool RequestTable::take(std::uint16_t channel, std::uint64_t requestId, OutstandingRequest* out)
{
    auto it = _byKey.find(Key{channel, requestId});
    if (it == _byKey.end()) return false;
    if (out) *out = it->second;
    _byKey.erase(it);
    return true;
}

bool RequestTable::isOutstanding(std::uint16_t channel, std::uint64_t requestId) const noexcept
{
    return _byKey.find(Key{channel, requestId}) != _byKey.end();
}

bool RequestTable::get(std::uint16_t channel, std::uint64_t requestId,
                       OutstandingRequest& out) const noexcept
{
    const auto it = _byKey.find(Key{channel, requestId});
    if (it == _byKey.end()) return false;
    out = it->second;
    return true;
}

std::vector<OutstandingRequest> RequestTable::expired()
{
    std::vector<OutstandingRequest> out;
    for (auto it = _byKey.begin(); it != _byKey.end(); ) {
        if (it->second.deadline.expired(_clock)) {
            out.push_back(it->second);
            it = _byKey.erase(it);
        } else {
            ++it;
        }
    }
    return out;
}

std::vector<OutstandingRequest> RequestTable::takeEndpoint(std::uint32_t attachId,
                                                           std::uint8_t epAddr)
{
    std::vector<OutstandingRequest> out;
    for (auto it = _byKey.begin(); it != _byKey.end(); ) {
        if (it->second.attachId == attachId && it->second.epAddr == epAddr) {
            out.push_back(it->second);
            it = _byKey.erase(it);
        } else {
            ++it;
        }
    }
    return out;
}

std::vector<OutstandingRequest> RequestTable::takeAttach(std::uint32_t attachId)
{
    std::vector<OutstandingRequest> out;
    for (auto it = _byKey.begin(); it != _byKey.end(); ) {
        if (it->second.attachId == attachId) {
            out.push_back(it->second);
            it = _byKey.erase(it);
        } else {
            ++it;
        }
    }
    return out;
}

std::vector<OutstandingRequest> RequestTable::takeStaleEpoch(std::uint32_t attachId,
                                                             std::uint16_t currentEpoch)
{
    std::vector<OutstandingRequest> out;
    for (auto it = _byKey.begin(); it != _byKey.end(); ) {
        if (it->second.attachId == attachId && it->second.deviceEpoch != currentEpoch) {
            out.push_back(it->second);
            it = _byKey.erase(it);
        } else {
            ++it;
        }
    }
    return out;
}

std::uint64_t RequestTable::nextRequestId(std::uint16_t channel) noexcept
{
    // request_id 0 means "unsolicited notification" on the wire, so ids start at 1.
    std::uint64_t& n = _nextId[channel];
    if (n == 0) n = 1;
    return n++;
}

} // namespace airusb
