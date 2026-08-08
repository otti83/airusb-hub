#include "PeerStore.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <sstream>

#include <fcntl.h>
#include <unistd.h>

namespace airusb::session {

namespace {

constexpr const char* kFileHeader = "airusb-peers-v1";

std::string keyOf(const crypto::PublicKey& k)
{
    return crypto::toHex(std::span<const std::uint8_t>(k.data(), k.size()));
}

bool parseKey(const std::string& hex, crypto::PublicKey& out)
{
    std::vector<std::uint8_t> v;
    if (!crypto::fromHex(hex, v) || v.size() != out.size()) return false;
    std::memcpy(out.data(), v.data(), out.size());
    return true;
}

/// The name is display-only and comes from a peer, so it is neither trusted nor
/// allowed to break the line-oriented format. Anything outside printable ASCII,
/// and the field separator itself, is replaced.
std::string sanitizeName(std::string s)
{
    if (s.size() > 64) s.resize(64);
    for (char& c : s) {
        const unsigned char u = static_cast<unsigned char>(c);
        if (u < 0x20 || u > 0x7E || c == '\t' || c == '\n') c = '.';
    }
    return s;
}

} // namespace

// ---------------------------------------------------------------------------

const PinnedPeer* PeerStore::find(const crypto::PublicKey& identityKey) const
{
    const auto it = _peers.find(keyOf(identityKey));
    return it == _peers.end() ? nullptr : &it->second;
}

bool PeerStore::hasGrant(const crypto::PublicKey& identityKey, Grant g) const
{
    const PinnedPeer* p = find(identityKey);
    return p != nullptr && (p->grants & static_cast<std::uint32_t>(g)) != 0;
}

Status PeerStore::pin(const crypto::PeerIdentity& peer, std::string name,
                      std::uint32_t grants, ContinuousNs nowNs)
{
    // The caller must have verified this already. Checking again here costs one
    // signature verification and removes any way to reach a pinned peer whose
    // binding was never checked.
    if (!crypto::verifyBinding(peer)) return Status::AuthFailed;

    const std::string k = keyOf(peer.identityKey);
    auto it = _peers.find(k);
    if (it == _peers.end()) {
        PinnedPeer p;
        p.identityKey = peer.identityKey;
        p.noiseKey    = peer.noiseKey;
        p.name        = sanitizeName(std::move(name));
        p.grants      = grants;
        p.firstSeenNs = nowNs;
        p.lastSeenNs  = nowNs;
        _peers.emplace(k, std::move(p));
    } else {
        // Key rotation: same identity, new Noise static. Safe only because the
        // binding above proves the identity key vouches for it.
        it->second.noiseKey   = peer.noiseKey;
        it->second.name       = sanitizeName(std::move(name));
        it->second.grants     = grants;
        it->second.lastSeenNs = nowNs;
    }
    return Status::Ok;
}

bool PeerStore::unpin(const crypto::PublicKey& identityKey)
{
    return _peers.erase(keyOf(identityKey)) > 0;
}

void PeerStore::setGrants(const crypto::PublicKey& identityKey, std::uint32_t grants)
{
    const auto it = _peers.find(keyOf(identityKey));
    if (it != _peers.end()) it->second.grants = grants;
}

void PeerStore::touch(const crypto::PublicKey& identityKey, ContinuousNs nowNs)
{
    const auto it = _peers.find(keyOf(identityKey));
    if (it != _peers.end()) it->second.lastSeenNs = nowNs;
}

std::vector<PinnedPeer> PeerStore::peers() const
{
    std::vector<PinnedPeer> out;
    out.reserve(_peers.size());
    for (const auto& [k, v] : _peers) out.push_back(v);
    return out;
}

// ---------------------------------------------------------------------------
// persistence
// ---------------------------------------------------------------------------

std::string PeerStore::serialize() const
{
    // One peer per line, tab separated, header first. Text rather than a binary
    // blob because this is security state a user may reasonably want to read or
    // delete by hand, and because a corrupted binary format fails obscurely.
    std::ostringstream os;
    os << kFileHeader << "\n";
    for (const auto& [k, p] : _peers) {
        os << keyOf(p.identityKey) << '\t'
           << keyOf(p.noiseKey) << '\t'
           << p.grants << '\t'
           << p.firstSeenNs << '\t'
           << p.lastSeenNs << '\t'
           << p.name << '\n';
    }
    return os.str();
}

bool PeerStore::deserialize(const std::string& text)
{
    std::map<std::string, PinnedPeer> parsed;
    std::istringstream is(text);
    std::string line;

    if (!std::getline(is, line)) return false;
    if (line != kFileHeader) return false;

    while (std::getline(is, line)) {
        if (line.empty()) continue;

        std::vector<std::string> f;
        std::string cur;
        std::istringstream ls(line);
        while (std::getline(ls, cur, '\t')) f.push_back(cur);
        // The name may be empty, so getline drops a trailing field; accept both.
        if (f.size() == 5) f.push_back("");
        if (f.size() != 6) return false;

        PinnedPeer p;
        if (!parseKey(f[0], p.identityKey)) return false;
        if (!parseKey(f[1], p.noiseKey)) return false;

        try {
            p.grants      = static_cast<std::uint32_t>(std::stoul(f[2]));
            p.firstSeenNs = static_cast<ContinuousNs>(std::stoull(f[3]));
            p.lastSeenNs  = static_cast<ContinuousNs>(std::stoull(f[4]));
        } catch (...) {
            return false;
        }
        p.name = sanitizeName(f[5]);

        // The binding signature is deliberately NOT stored. The peer presents it
        // on every connection and it is verified there, against the Noise key
        // that handshake actually negotiated. What is pinned is the IDENTITY
        // key; the stored Noise key is only a cache of what it last vouched for,
        // used to decide whether IK is available.
        parsed.emplace(keyOf(p.identityKey), std::move(p));
    }

    // Only commit once the whole file parsed. A half-loaded pin store looks like
    // a working one while silently having forgotten peers.
    _peers = std::move(parsed);
    return true;
}

Status PeerStore::save(const std::string& path) const
{
    const std::string text = serialize();
    const std::string tmp = path + ".tmp";

    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return Status::NotPermitted;

    std::size_t at = 0;
    while (at < text.size()) {
        const ssize_t n = ::write(fd, text.data() + at, text.size() - at);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            ::close(fd);
            (void)::unlink(tmp.c_str());
            return Status::Internal;
        }
        at += static_cast<std::size_t>(n);
    }

    // fsync before rename. Without it a crash can leave the rename durable and
    // the contents not, which produces an empty pin store — every peer silently
    // unpaired, and the user prompted to re-pair as if nothing had happened.
    if (::fsync(fd) != 0) {
        ::close(fd);
        (void)::unlink(tmp.c_str());
        return Status::Internal;
    }
    ::close(fd);

    if (::rename(tmp.c_str(), path.c_str()) != 0) {
        (void)::unlink(tmp.c_str());
        return Status::Internal;
    }
    return Status::Ok;
}

Status PeerStore::load(const std::string& path)
{
    const int fd = ::open(path.c_str(), O_RDONLY);
    if (fd < 0) {
        // No file is a first run, not a failure. The store stays empty, which
        // means every peer is unpaired — the correct default.
        if (errno == ENOENT) { _peers.clear(); return Status::Ok; }
        return Status::NotPermitted;
    }

    std::string text;
    char buf[4096];
    for (;;) {
        const ssize_t n = ::read(fd, buf, sizeof buf);
        if (n == 0) break;
        if (n < 0) {
            if (errno == EINTR) continue;
            ::close(fd);
            return Status::Internal;
        }
        text.append(buf, static_cast<std::size_t>(n));
        // A pin store this large is not a pin store.
        if (text.size() > (1u << 20)) { ::close(fd); return Status::LimitExceeded; }
    }
    ::close(fd);

    return deserialize(text) ? Status::Ok : Status::MalformedFrame;
}

} // namespace airusb::session
