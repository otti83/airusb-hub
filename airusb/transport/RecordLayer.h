// AirUSB Hub — record framing (P1 plan §3.1)
//
//   u32 record_len  (little-endian)
//   u8  record_body[record_len]
//
// Every record is fully received and bounded BEFORE anything parses it. There is
// no streaming parser acting on partial input, so the desync/resync failure class
// simply does not exist — which is why there is no resync marker and no recovery
// path. R1 caps record_len at 8 KiB before the handshake completes and at the
// negotiated maximum afterwards, so a peer cannot make us buffer arbitrarily by
// announcing a huge length.
//
// The cipher is an interface rather than ChaCha20-Poly1305 directly, so P2.4 can
// drop Noise in without touching framing, and so the framing itself is testable
// without pulling a crypto implementation into every test.

#ifndef AIRUSB_TRANSPORT_RECORDLAYER_H
#define AIRUSB_TRANSPORT_RECORDLAYER_H

#include "IAirUsbTransport.h"
#include "../protocol/Wire.h"

#include <memory>

namespace airusb::transport {

/// An AEAD with an implicit, monotonically increasing nonce — the Noise transport
/// contract. Because the nonce is a counter owned by the cipher, replay, reorder
/// and truncation are cryptographically impossible and the L1 header needs no
/// sequence number of its own.
class IRecordCipher {
public:
    virtual ~IRecordCipher() = default;

    /// Appends ciphertext (plus tag) for `plaintext` to `out`.
    virtual Status seal(std::span<const std::uint8_t> plaintext,
                        std::vector<std::uint8_t>& out) = 0;

    /// Decrypts in place into `out`. Any authentication failure is AuthFailed and
    /// is fatal.
    virtual Status open(std::span<const std::uint8_t> ciphertext,
                        std::vector<std::uint8_t>& out) = 0;

    /// Bytes added to each record. Used to size limits correctly.
    virtual std::size_t overhead() const noexcept = 0;
};

/// Identity cipher. Test-only, and named so that its presence in a shipping
/// configuration is obvious at a glance.
class NullCipher final : public IRecordCipher {
public:
    Status seal(std::span<const std::uint8_t> pt, std::vector<std::uint8_t>& out) override;
    Status open(std::span<const std::uint8_t> ct, std::vector<std::uint8_t>& out) override;
    std::size_t overhead() const noexcept override { return 0; }
};

class RecordLayer final : public IAirUsbTransport {
public:
    RecordLayer(std::unique_ptr<IByteStream> stream,
                std::unique_ptr<IRecordCipher> cipher);

    Status sendRecord(std::span<const std::uint8_t> body) override;
    Status receiveRecord(std::vector<std::uint8_t>& out) override;
    void close() override;
    bool isOpen() const noexcept override;

    /// R1: 8 KiB until the handshake completes, the negotiated value after.
    void setHandshakeComplete(std::uint32_t negotiatedMaxRecordBytes) noexcept;
    std::uint32_t maxRecordBytes() const noexcept { return _maxRecord; }

    /// Drains whatever is buffered for sending. Returns Ok when the buffer is
    /// empty. A partial flush is normal on a non-blocking socket.
    Status flush();

    std::size_t pendingTxBytes() const noexcept { return _tx.size() - _txSent; }

    // Diagnostics.
    std::uint64_t recordsSent()     const noexcept { return _recordsSent; }
    std::uint64_t recordsReceived() const noexcept { return _recordsReceived; }

private:
    std::unique_ptr<IByteStream>   _stream;
    std::unique_ptr<IRecordCipher> _cipher;

    std::vector<std::uint8_t> _tx;
    std::size_t               _txSent = 0;

    std::vector<std::uint8_t> _rx;
    std::vector<std::uint8_t> _scratch;

    std::uint32_t _maxRecord = wire::kHandshakeRecordMax;
    bool          _handshakeDone = false;
    bool          _fatal = false;

    std::uint64_t _recordsSent = 0;
    std::uint64_t _recordsReceived = 0;
};

} // namespace airusb::transport

#endif // AIRUSB_TRANSPORT_RECORDLAYER_H
