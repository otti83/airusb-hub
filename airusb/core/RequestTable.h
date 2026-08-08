// AirUSB Hub — outstanding request tracking and request_id rules (P1 plan §3.12 R8)
//
// Enforces invariant I1: exactly one COMPLETE per SUBMIT, always — including for
// cancelled, collateral, timed-out and device-gone transfers. No implicit
// completion by connection teardown.
//
// And rule R8: a new request_id on a channel must be strictly greater than the
// last seen and must not already be outstanding. Reusing a live request_id is
// fatal, because that is exactly how URB aliasing and response confusion happen:
// a late completion for the old transfer gets applied to the new one, and the
// wrong bytes land in the wrong kernel buffer.

#ifndef AIRUSB_CORE_REQUESTTABLE_H
#define AIRUSB_CORE_REQUESTTABLE_H

#include "Clock.h"
#include "Status.h"
#include "UsbTypes.h"

#include <cstdint>
#include <functional>
#include <unordered_map>
#include <vector>

namespace airusb {

struct OutstandingRequest {
    std::uint64_t requestId    = 0;
    std::uint16_t channel      = 0;
    std::uint32_t attachId     = 0;
    std::uint8_t  epAddr       = 0;
    XferType      xferType     = XferType::Bulk;
    Dir           dir          = Dir::Out;
    std::uint32_t requestedLen = 0;
    std::uint16_t deviceEpoch  = 0;
    std::uint32_t epGeneration = 0;
    Deadline      deadline;
    ContinuousNs  submittedNs  = 0;
};

class RequestTable {
public:
    explicit RequestTable(const Clock& clock) noexcept : _clock(clock) {}

    /// R8. Returns Ok and records the request, or the reason it was refused.
    /// A refusal here is fatal to the session by design — see the header.
    Status add(const OutstandingRequest& r);

    /// Removes and returns the request, or nullptr if it is not outstanding.
    /// A completion for an unknown request_id is NOT fatal: it is the expected
    /// outcome of a cancel racing a completion, or of a completion arriving after
    /// a device epoch bump. The caller drops it and rate-limits a debug log.
    bool take(std::uint16_t channel, std::uint64_t requestId, OutstandingRequest* out);

    bool isOutstanding(std::uint16_t channel, std::uint64_t requestId) const noexcept;

    /// Every request whose deadline has expired. The caller completes each with
    /// XferTimeout — the table never completes anything itself, so there is exactly
    /// one place completions are generated.
    std::vector<OutstandingRequest> expired();

    /// Drains everything for an endpoint. Used by endpoint destroy/pause and by
    /// cancel, which is endpoint-scoped in AirUSB (there is no per-URB cancel
    /// guarantee; see §3.9).
    std::vector<OutstandingRequest> takeEndpoint(std::uint32_t attachId, std::uint8_t epAddr);

    /// Drains everything for an attach. Used on DEVICE_GONE and on teardown, so
    /// that I1 holds even when the transport dies: the caller must complete every
    /// one of these locally rather than letting them evaporate.
    std::vector<OutstandingRequest> takeAttach(std::uint32_t attachId);

    /// Drains everything whose epoch is stale after a reset.
    std::vector<OutstandingRequest> takeStaleEpoch(std::uint32_t attachId, std::uint16_t currentEpoch);

    std::size_t size() const noexcept { return _byKey.size(); }
    bool empty() const noexcept { return _byKey.empty(); }

    /// Next request_id to use on a channel. Monotonic per channel, never reused.
    std::uint64_t nextRequestId(std::uint16_t channel) noexcept;

private:
    // channel is 16 bits and request_id 64, so the composite key needs both; a
    // request_id is only unique within its channel.
    struct Key {
        std::uint16_t channel;
        std::uint64_t requestId;
        bool operator==(const Key& o) const noexcept
        {
            return channel == o.channel && requestId == o.requestId;
        }
    };
    struct KeyHash {
        std::size_t operator()(const Key& k) const noexcept
        {
            return std::hash<std::uint64_t>{}(k.requestId) ^ (std::size_t{k.channel} << 1);
        }
    };

    const Clock& _clock;
    std::unordered_map<Key, OutstandingRequest, KeyHash> _byKey;
    std::unordered_map<std::uint16_t, std::uint64_t>     _lastSeen;   ///< per channel, for R8
    std::unordered_map<std::uint16_t, std::uint64_t>     _nextId;     ///< per channel, for emission
};

} // namespace airusb

#endif // AIRUSB_CORE_REQUESTTABLE_H
