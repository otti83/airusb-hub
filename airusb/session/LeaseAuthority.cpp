#include "LeaseAuthority.h"

#include "../core/Watchdog.h"
#include "../crypto/Primitives.h"

namespace airusb::session {

namespace {

/// Identity keys are public, so this could be a plain memcmp. It is constant
/// time anyway, because the day one of these comparisons is moved onto a value
/// that is NOT public, nobody will remember to change it — and a timing leak
/// introduced by a copy-paste is the kind nobody looks for.
bool sameKey(const crypto::PublicKey& a, const crypto::PublicKey& b) noexcept
{
    return crypto::constantTimeEquals(std::span<const std::uint8_t>(a.data(), a.size()),
                                      std::span<const std::uint8_t>(b.data(), b.size()));
}

} // namespace

const char* leaseStateText(LeaseState s) noexcept
{
    switch (s) {
    case LeaseState::Free:        return "free";
    case LeaseState::Leased:      return "leased";
    case LeaseState::Quarantined: return "quarantined";
    }
    return "free";
}

bool LeaseAuthority::isOwner(const crypto::PublicKey& peer) const noexcept
{
    return _s.hasOwner && sameKey(_s.owner, peer);
}

void LeaseAuthority::mintToken()
{
    crypto::randomBytes(std::span<std::uint8_t>(_token.data(), _token.size()));
}

Status LeaseAuthority::mayClaim(const crypto::PublicKey& peer,
                                const protocol::DeviceUid& uid,
                                std::string* whyNot) const
{
    auto no = [&](Status s, const char* m) { if (whyNot) *whyNot = m; return s; };

    switch (_s.state) {
    case LeaseState::Free:
        return Status::Ok;

    case LeaseState::Leased:
        // The same peer asking again is a second ATTACH, and §7.7 says that is
        // BUSY and is never queued — the answer is the same whoever asks, so
        // there is deliberately no owner shortcut here.
        if (_s.uid == uid)
            return no(Status::Busy, "That device is already in use.");
        return no(Status::Busy, "This machine is already sharing a device.");

    case LeaseState::Quarantined:
        // The owner coming back is not refused — it is told to recover, which is
        // a different verb with a different outcome (a new attach id and a clean
        // re-enumeration) and must not be reachable by simply retrying ATTACH.
        if (isOwner(peer))
            return no(Status::ExclusivityDenied,
                      "Your earlier session is still holding this device. "
                      "Recover it rather than attaching again.");
        return no(Status::ExclusivityDenied,
                  "Another machine still holds this device. It stopped answering "
                  "rather than releasing it, so it is being kept for that machine "
                  "until somebody at this one takes it back.");
    }
    return no(Status::Internal, "unknown lease state");
}

std::uint32_t LeaseAuthority::grant(const crypto::PublicKey& peer,
                                    const protocol::DeviceUid& uid,
                                    RecoveryToken* tokenOut)
{
    _s.state       = LeaseState::Leased;
    _s.owner       = peer;
    _s.hasOwner    = true;
    _s.uid         = uid;
    _s.attachId    = _nextAttachId++;
    ++_s.leaseEpoch;
    ++_s.incarnation;
    _s.lastHeardNs = _clock.nowNs();
    _s.sinceNs     = _s.lastHeardNs;

    mintToken();
    if (tokenOut) *tokenOut = _token;
    return _s.attachId;
}

void LeaseAuthority::heard(const crypto::PublicKey& peer)
{
    if (!isOwner(peer)) return;
    _s.lastHeardNs = _clock.nowNs();

    // A blip that healed before anybody acted on it costs nothing. Coming back
    // from Quarantined WITHOUT a new attach id is only safe because the session
    // that reaches here is the same one — a reconnecting peer arrives on a new
    // session and goes through tryRecover(), which does mint one.
    if (_s.state == LeaseState::Quarantined) {
        _s.state   = LeaseState::Leased;
        _s.sinceNs = _s.lastHeardNs;
    }
}

void LeaseAuthority::quarantine()
{
    if (_s.state != LeaseState::Leased) return;
    _s.state   = LeaseState::Quarantined;
    _s.sinceNs = _clock.nowNs();
}

void LeaseAuthority::release(const crypto::PublicKey& peer)
{
    // Only the owner may release. A DETACH from anyone else is not a way to take
    // somebody's drive away, which it would be if this were unguarded.
    if (!isOwner(peer)) return;
    _s = Snapshot{};
    _s.sinceNs = _clock.nowNs();
    _token = RecoveryToken{};
}

void LeaseAuthority::forceReclaim()
{
    _s = Snapshot{};
    _s.sinceNs = _clock.nowNs();
    // The token dies with the lease. A peer that comes back afterwards is told
    // NotFound and has to attach fresh, which is correct: the device it thought
    // it owned has been handed to somebody else's operating system since.
    _token = RecoveryToken{};
}

Status LeaseAuthority::tryRecover(const crypto::PublicKey& peer,
                                  const RecoveryToken& token,
                                  std::uint32_t* attachIdOut,
                                  RecoveryToken* nextTokenOut)
{
    if (_s.state == LeaseState::Free) return Status::NotFound;
    if (!isOwner(peer)) return Status::NotPermitted;
    if (!crypto::constantTimeEquals(
            std::span<const std::uint8_t>(token.data(), token.size()),
            std::span<const std::uint8_t>(_token.data(), _token.size())))
        return Status::NotPermitted;

    // Ownership is recovered; execution history is not. A new attach id and a
    // bumped incarnation make the importing OS re-enumerate, which is the only
    // honest answer when nobody can say which in-flight transfers took effect.
    _s.state       = LeaseState::Leased;
    _s.attachId    = _nextAttachId++;
    ++_s.leaseEpoch;
    ++_s.incarnation;
    _s.lastHeardNs = _clock.nowNs();
    _s.sinceNs     = _s.lastHeardNs;

    // One use. The token that recovered the lease cannot recover it twice, so a
    // replay of the last recovery message is refused rather than granted.
    mintToken();
    if (attachIdOut)   *attachIdOut   = _s.attachId;
    if (nextTokenOut)  *nextTokenOut  = _token;
    return Status::Ok;
}

bool LeaseAuthority::silenceExpired() const noexcept
{
    if (_s.state != LeaseState::Leased) return false;
    const ContinuousNs now = _clock.nowNs();
    if (now < _s.lastHeardNs) return false;          // clock went backwards; do nothing
    return (now - _s.lastHeardNs) >= watchdog::kLeaseExporter * 1'000'000ull;
}

LeaseAuthority::Snapshot LeaseAuthority::snapshot() const noexcept { return _s; }

} // namespace airusb::session
