#include "RecordLayer.h"
#include "../protocol/Codec.h"
#include "../protocol/Validate.h"

#include <cstring>

namespace airusb::transport {

// ---------------------------------------------------------------------------

Status NullCipher::seal(std::span<const std::uint8_t> pt, std::vector<std::uint8_t>& out)
{
    out.insert(out.end(), pt.begin(), pt.end());
    return Status::Ok;
}

Status NullCipher::open(std::span<const std::uint8_t> ct, std::vector<std::uint8_t>& out)
{
    out.assign(ct.begin(), ct.end());
    return Status::Ok;
}

// ---------------------------------------------------------------------------

RecordLayer::RecordLayer(std::unique_ptr<IByteStream> stream,
                         std::unique_ptr<IRecordCipher> cipher)
    : _stream(std::move(stream)), _cipher(std::move(cipher))
{
}

void RecordLayer::setHandshakeComplete(std::uint32_t negotiated) noexcept
{
    _handshakeDone = true;
    _maxRecord = negotiated > wire::kRecordBytesCeiling ? wire::kRecordBytesCeiling
                                                        : negotiated;
}

bool RecordLayer::isOpen() const noexcept
{
    return !_fatal && _stream && _stream->isOpen();
}

void RecordLayer::close()
{
    if (_stream) _stream->close();
}

Status RecordLayer::sendRecord(std::span<const std::uint8_t> body)
{
    if (_fatal) return Status::TransportLost;

    // Size the record with the cipher's overhead included, so the limit means the
    // same thing on both sides regardless of which cipher is installed.
    const std::size_t recordLen = body.size() + _cipher->overhead();
    if (recordLen > _maxRecord) return Status::LimitExceeded;

    const std::size_t at = _tx.size();
    _tx.resize(at + wire::kRecordLenSize);
    protocol::wr_u32(_tx.data() + at, static_cast<std::uint32_t>(recordLen));

    if (Status s = _cipher->seal(body, _tx); s != Status::Ok) return s;

    ++_recordsSent;
    return flush();
}

Status RecordLayer::flush()
{
    while (_txSent < _tx.size()) {
        IoResult r = _stream->write(std::span<const std::uint8_t>(_tx.data() + _txSent,
                                                                  _tx.size() - _txSent));
        if (r.status != Status::Ok) { _fatal = true; return r.status; }
        if (r.bytes == 0) break;                 // would block; try again later
        _txSent += r.bytes;
    }

    if (_txSent == _tx.size()) { _tx.clear(); _txSent = 0; }
    else if (_txSent > 64 * 1024) {
        // Compact so the buffer does not grow without bound on a slow peer.
        _tx.erase(_tx.begin(), _tx.begin() + static_cast<std::ptrdiff_t>(_txSent));
        _txSent = 0;
    }
    return Status::Ok;
}

Status RecordLayer::receiveRecord(std::vector<std::uint8_t>& out)
{
    out.clear();
    if (_fatal) return Status::TransportLost;

    for (;;) {
        // Do we already hold a whole record?
        if (_rx.size() >= wire::kRecordLenSize) {
            const std::uint32_t len = protocol::rd_u32(_rx.data());

            // R1 BEFORE allocating anything. This is the check that stops a peer
            // making us buffer gigabytes by announcing a huge length.
            protocol::Limits lim;
            lim.maxRecordBytes = _maxRecord;
            if (auto v = protocol::r1_recordSize(len, lim, _handshakeDone); !v.ok()) {
                _fatal = true;
                return v.status;
            }
            if (len < _cipher->overhead()) { _fatal = true; return Status::MalformedFrame; }

            if (_rx.size() >= wire::kRecordLenSize + len) {
                auto ct = std::span<const std::uint8_t>(_rx.data() + wire::kRecordLenSize, len);
                if (Status s = _cipher->open(ct, out); s != Status::Ok) {
                    _fatal = true;                  // an auth failure is never retried
                    return s;
                }
                _rx.erase(_rx.begin(),
                          _rx.begin() + static_cast<std::ptrdiff_t>(wire::kRecordLenSize + len));
                ++_recordsReceived;
                return Status::Ok;
            }
        }

        // Need more bytes.
        const std::size_t chunk = 16 * 1024;
        const std::size_t at = _rx.size();
        _rx.resize(at + chunk);
        IoResult r = _stream->read(std::span<std::uint8_t>(_rx.data() + at, chunk));
        _rx.resize(at + r.bytes);

        if (r.status != Status::Ok) { _fatal = true; return r.status; }
        if (r.bytes == 0) return Status::Ok;        // would block; out stays empty
    }
}

} // namespace airusb::transport
