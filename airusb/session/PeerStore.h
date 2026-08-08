// AirUSB Hub — pinned peer identities and what they are allowed to do (§3.14).
//
// Noise proves the peer holds the private key for a static key. This file
// answers the different question of whether we have ever agreed to talk to that
// key, and what we agreed it may do.
//
// **There is no "the LAN is trusted" mode.** An unpinned peer is `Unpaired`, and
// in that state the only permitted messages are PAIR_REQUEST / PAIR_CONFIRM /
// PAIR_RESULT / PING / GOODBYE. LIST_DEVICES and ATTACH return NotPaired. A
// local network is not a security boundary and never has been.
//
// PERSISTENCE
//
// The file is a line-oriented text format, not a binary blob, because it is
// security state a user may need to read, audit, or delete by hand. It is
// written atomically (temp file, fsync, rename) so a crash midway cannot leave a
// truncated pin store — which would silently unpair every peer.

#ifndef AIRUSB_SESSION_PEERSTORE_H
#define AIRUSB_SESSION_PEERSTORE_H

#include "../core/Clock.h"
#include "../core/Status.h"
#include "../crypto/Identity.h"

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace airusb::session {

/// Per-peer permissions (§3.14). Deliberately a small closed set: a grant model
/// nobody can hold in their head is one nobody audits.
enum Grant : std::uint32_t {
    kMayList                = 1u << 0,
    kMayAttach              = 1u << 1,
    kMayAttachWithoutPrompt = 1u << 2,
};

/// What a newly paired peer gets. Not `kMayAttachWithoutPrompt`: taking a drive
/// away from the machine it is plugged into should require someone to say yes
/// the first time, at least.
inline constexpr std::uint32_t kDefaultGrants = kMayList | kMayAttach;

struct PinnedPeer {
    crypto::PublicKey identityKey{};   ///< Ed25519 I_pk — the pin
    crypto::PublicKey noiseKey{};      ///< the X25519 static bound to it
    std::string       name;            ///< display only, never trusted
    std::uint32_t     grants = 0;
    ContinuousNs      firstSeenNs = 0;
    ContinuousNs      lastSeenNs  = 0;

    crypto::Fingerprint fingerprint() const { return crypto::fingerprint(identityKey); }
};

class PeerStore {
public:
    /// Whether this peer is known, and what it may do.
    ///
    /// Matching is on the IDENTITY key, not the Noise key: the identity key is
    /// the long-lived thing a user confirmed, and the Noise static is allowed to
    /// be rotated by a peer that can prove the binding.
    const PinnedPeer* find(const crypto::PublicKey& identityKey) const;

    bool isPaired(const crypto::PublicKey& identityKey) const
    {
        return find(identityKey) != nullptr;
    }

    bool hasGrant(const crypto::PublicKey& identityKey, Grant g) const;

    /// Records a peer after a successful SAS confirmation.
    ///
    /// Re-pinning an existing identity with a DIFFERENT Noise key is allowed and
    /// is how key rotation works — but only because the caller has already
    /// verified the binding signature, which proves the identity key vouches for
    /// the new one. Pinning without that check would let anyone claim any
    /// identity's Noise key.
    Status pin(const crypto::PeerIdentity& peer, std::string name,
               std::uint32_t grants, ContinuousNs nowNs);

    /// Removes a pin. Live sessions with this peer must be torn down by the
    /// caller with DETACH{POLICY} then GOODBYE; this class does not know about
    /// sessions.
    bool unpin(const crypto::PublicKey& identityKey);

    void setGrants(const crypto::PublicKey& identityKey, std::uint32_t grants);
    void touch(const crypto::PublicKey& identityKey, ContinuousNs nowNs);

    std::vector<PinnedPeer> peers() const;
    std::size_t size() const noexcept { return _peers.size(); }
    void clear() noexcept { _peers.clear(); }

    // --- persistence ---------------------------------------------------------

    /// Serialises to the on-disk text format. Exposed separately from save() so
    /// it can be tested without touching a filesystem.
    std::string serialize() const;

    /// Parses the text format. Returns false on any malformed line and loads
    /// NOTHING — a partially-loaded pin store is a security failure that looks
    /// like a working one.
    bool deserialize(const std::string& text);

    /// Atomic: writes a temp file, fsyncs it, renames over the target. Creates
    /// the file 0600.
    Status save(const std::string& path) const;

    /// Missing file is Ok with an empty store — a first run is not an error.
    Status load(const std::string& path);

private:
    /// Keyed by hex of the identity key, so lookup is O(log n) and the map key
    /// is printable in a log without a conversion step.
    std::map<std::string, PinnedPeer> _peers;
};

} // namespace airusb::session

#endif // AIRUSB_SESSION_PEERSTORE_H
