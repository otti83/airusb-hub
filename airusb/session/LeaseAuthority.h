// AirUSB Hub — who owns the captured device, and for how long.
//
// THE BUG THIS FILE EXISTS TO CLOSE
//
// `ExporterSession` documented, correctly, that "silence does NOT release the
// capture" and moved itself to `Orphaned` when the transport died. That was
// true and it was not enough, because the state lived in the SESSION OBJECT and
// the session object died with the socket. `airusb-exportd` then broke out of
// its pump loop, destroyed the session, went back to `accept()`, and handed the
// same physical drive to whichever paired peer connected next —
// `CapturedDeviceSource::claim()` had no owner check at all. The physical
// capture was retained; the remote exclusivity it was supposed to enforce was
// not. So the invariant the whole design is built on —
//
//     a peer that vanished mid-write must not have the drive handed back
//     underneath it
//
// — held against the LOCAL operating system and failed against every other
// machine on the network, which is the case it was written for. Found by an
// adversarial read (GPT-5.6, 2026-08-09) and confirmed against both files.
//
// THE FIX IS A LIFETIME, NOT A CHECK
//
// One `LeaseAuthority` per device source, created OUTSIDE the accept loop and
// outliving every session. A session asks it whether this peer may claim; it
// answers from state no session can destroy. Adding an `if` inside `claim()`
// would not have worked, because there was nothing left to compare against.
//
// THE FOUR STATES, AND WHY QUARANTINED IS NOT FREE
//
//   Free         nobody holds it. Any permitted peer may claim.
//   Leased       an identified peer holds it and is being heard from.
//   Quarantined  an identified peer holds it and has gone quiet. The device
//                stays captured and stays UNCLAIMABLE BY ANYONE ELSE.
//   Reclaimed    a person at this machine took it back deliberately.
//
// `Quarantined` is the state the old code did not have. It is not a grace
// period before `Free`: a lease NEVER decays into availability, because the
// exporter cannot know whether the silent importer has a filesystem mounted and
// dirty. It leaves quarantine in exactly three ways, all of them somebody's
// decision rather than a timer's:
//
//   1. the SAME peer comes back and recovers it (`tryRecover`),
//   2. the same peer detaches explicitly (`release`),
//   3. a human at the exporting machine says take it back (`forceReclaim`),
//      which is the one that can lose data and therefore has to be asked for.
//
// The lease timer still exists and still matters — it is what stops the
// exporter forwarding transfers to a peer that is gone — but what it does at
// expiry is QUARANTINE, never release. That is the whole difference.
//
// RECOVERY IS OF OWNERSHIP, NOT OF EXECUTION HISTORY
//
// `tryRecover` mints a NEW attach id and bumps the device incarnation, so the
// importing OS re-enumerates cleanly. It deliberately does not attempt to
// resurrect in-flight URBs: after a network loss nobody can say which physical
// transfers took effect, and replaying an OUT is how a filesystem gets a
// duplicate write. The recovery token is bound to the peer's identity key, the
// old attach id and the lease epoch, so a different peer cannot present it and
// the same peer cannot replay it after the lease has moved on.

#ifndef AIRUSB_SESSION_LEASEAUTHORITY_H
#define AIRUSB_SESSION_LEASEAUTHORITY_H

#include "../core/Clock.h"
#include "../core/Status.h"
#include "../crypto/Identity.h"
#include "../protocol/Messages.h"

#include <cstdint>
#include <string>

namespace airusb::session {

enum class LeaseState : std::uint8_t {
    Free,
    Leased,
    Quarantined,
};

const char* leaseStateText(LeaseState s) noexcept;

/// A 16-byte unguessable token that proves "I am the peer that had this lease".
///
/// It is generated from the CSPRNG rather than derived from the attach id or the
/// peer key, because a derived token is one an observer of the earlier session
/// could compute. It is compared in constant time for the same reason every
/// other secret in this project is.
using RecoveryToken = std::array<std::uint8_t, 16>;

class LeaseAuthority {
public:
    struct Snapshot {
        LeaseState          state       = LeaseState::Free;
        protocol::DeviceUid uid{};
        crypto::PublicKey   owner{};
        bool                hasOwner    = false;
        std::uint32_t       attachId    = 0;
        std::uint32_t       leaseEpoch  = 0;
        std::uint16_t       incarnation = 0;
        ContinuousNs        lastHeardNs = 0;
        ContinuousNs        sinceNs     = 0;   ///< when the current state began
    };

    explicit LeaseAuthority(const Clock& clock) noexcept : _clock(clock) {}

    /// May this peer take this device right now?
    ///
    /// Ok, or a status that says who has it. `Busy` means somebody else holds a
    /// live lease; `ExclusivityDenied` means somebody else holds a QUARANTINED
    /// one, which is a different sentence to put in front of a person — the
    /// first resolves itself when they finish, the second needs a decision.
    Status mayClaim(const crypto::PublicKey& peer,
                    const protocol::DeviceUid& uid,
                    std::string* whyNot) const;

    /// Records a lease granted to `peer`. Returns the attach id to use, which is
    /// allocated here rather than by the session so that two sessions can never
    /// mint the same one.
    std::uint32_t grant(const crypto::PublicKey& peer,
                        const protocol::DeviceUid& uid,
                        RecoveryToken* tokenOut);

    /// The lease's owner said something. Resets the silence timer, and brings a
    /// quarantined lease back to Leased if it is the same peer — which is what
    /// makes a brief blip a non-event rather than a ceremony.
    void heard(const crypto::PublicKey& peer);

    /// The transport died, or the lease timer expired. QUARANTINE — never free.
    void quarantine();

    /// The owner detached explicitly. This is the only automatic path to Free.
    void release(const crypto::PublicKey& peer);

    /// A person at this machine took the device back knowing it may be in use.
    /// The one operation here that can lose somebody else's data, which is why
    /// it has a name a caller has to type rather than being a timeout.
    void forceReclaim();

    /// The same peer, with the token it was given, wants its device back.
    ///
    /// On success a NEW attach id is allocated and the incarnation is bumped, so
    /// the importing OS re-enumerates instead of resuming — see the header.
    /// Returns NotFound if there is nothing to recover, NotPermitted if the peer
    /// or the token does not match.
    Status tryRecover(const crypto::PublicKey& peer,
                      const RecoveryToken& token,
                      std::uint32_t* attachIdOut,
                      RecoveryToken* nextTokenOut);

    /// True once the owner has been silent for longer than T_lease_exporter.
    /// Reading it does nothing; `quarantine()` is what acts on it, so that the
    /// decision and the observation are separable in a test.
    bool silenceExpired() const noexcept;

    Snapshot snapshot() const noexcept;
    LeaseState state() const noexcept { return _s.state; }
    std::uint32_t attachId() const noexcept { return _s.attachId; }
    std::uint16_t incarnation() const noexcept { return _s.incarnation; }

    /// True if this peer is the one holding the lease. False when nobody is.
    bool isOwner(const crypto::PublicKey& peer) const noexcept;

private:
    void mintToken();

    const Clock&  _clock;
    Snapshot      _s;
    RecoveryToken _token{};
    std::uint32_t _nextAttachId = 1;
};

} // namespace airusb::session

#endif // AIRUSB_SESSION_LEASEAUTHORITY_H
