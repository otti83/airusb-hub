// AirUSB Hub — the real IRecordCipher, replacing NullCipher (P1 plan §3.1).
//
// Post-handshake every record body is a Noise transport message: ChaCha20-
// Poly1305 with a 16-byte tag, keyed by the two CipherStates that Split()
// produced. One state per direction, never shared.
//
// WHY THE L1 HEADER HAS NO SEQUENCE NUMBER
//
// The nonce is the Noise counter, and both peers advance it independently. A
// replayed record decrypts under the wrong counter; a reordered one likewise; a
// truncated stream leaves the counters apart forever. So replay, reorder and
// truncation are not detected by a check we wrote — they are cryptographically
// impossible, which is a stronger statement and one fewer field to get wrong.
//
// The consequence is that a gap is unrecoverable BY DESIGN. §3.1: "Counter must
// advance by exactly 1; a gap is MALFORMED_FRAME -> GOODBYE, never a resync."
// There is no resynchronisation path here, deliberately: resyncing would mean
// accepting a record whose position in the stream an attacker chose.

#ifndef AIRUSB_TRANSPORT_NOISECIPHER_H
#define AIRUSB_TRANSPORT_NOISECIPHER_H

#include "RecordLayer.h"
#include "../protocol/Noise.h"

#include <cstdint>

namespace airusb::transport {

/// §3.1: "Rekey at 2^32 records." Both peers count the same records in the same
/// direction, so the rotation is deterministic and needs no signalling.
inline constexpr std::uint64_t kRekeyInterval = 1ull << 32;

class NoiseCipher final : public IRecordCipher {
public:
    /// `send` and `recv` come from HandshakeState::split() and are already
    /// oriented for this peer.
    ///
    /// `rekeyInterval` exists so a test can prove both sides rotate in step
    /// without running 2^32 records; production always uses the default. A test
    /// hook rather than a tunable — the value is a protocol constant.
    NoiseCipher(protocol::CipherState send,
                protocol::CipherState recv,
                std::uint64_t rekeyInterval = kRekeyInterval) noexcept;

    Status seal(std::span<const std::uint8_t> plaintext,
                std::vector<std::uint8_t>& out) override;

    Status open(std::span<const std::uint8_t> ciphertext,
                std::vector<std::uint8_t>& out) override;

    std::size_t overhead() const noexcept override { return crypto::kTagLen; }

    std::uint64_t recordsSealed() const noexcept { return _sealed; }
    std::uint64_t recordsOpened() const noexcept { return _opened; }
    std::uint64_t sendNonce()     const noexcept { return _send.nonce(); }
    std::uint64_t recvNonce()     const noexcept { return _recv.nonce(); }

private:
    protocol::CipherState _send;
    protocol::CipherState _recv;
    std::uint64_t _rekeyInterval;
    std::uint64_t _sealed = 0;
    std::uint64_t _opened = 0;
};

} // namespace airusb::transport

#endif // AIRUSB_TRANSPORT_NOISECIPHER_H
