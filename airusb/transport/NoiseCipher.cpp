#include "NoiseCipher.h"

namespace airusb::transport {

NoiseCipher::NoiseCipher(protocol::CipherState send,
                         protocol::CipherState recv,
                         std::uint64_t rekeyInterval) noexcept
    : _send(send), _recv(recv), _rekeyInterval(rekeyInterval)
{
}

Status NoiseCipher::seal(std::span<const std::uint8_t> plaintext,
                         std::vector<std::uint8_t>& out)
{
    // Noise's own ceiling. RecordLayer enforces the negotiated, smaller limit;
    // this is the absolute one, restated where the encryption happens so it
    // cannot be bypassed by a caller that skipped the layer above.
    if (plaintext.size() > protocol::kNoiseMaxPlaintext) return Status::LimitExceeded;

    if (const Status s = _send.encryptWithAd({}, plaintext, out); s != Status::Ok)
        return s;

    ++_sealed;
    if (_rekeyInterval != 0 && _sealed % _rekeyInterval == 0) _send.rekey();
    return Status::Ok;
}

Status NoiseCipher::open(std::span<const std::uint8_t> ciphertext,
                         std::vector<std::uint8_t>& out)
{
    if (ciphertext.size() > protocol::kNoiseMaxMessage) return Status::LimitExceeded;

    if (const Status s = _recv.decryptWithAd({}, ciphertext, out); s != Status::Ok) {
        // AuthFailed is fatal (core/Status.h) and the counter has NOT advanced,
        // so the session is closed rather than continuing out of step. There is
        // no resync path and that is the design, not an omission.
        return s;
    }

    ++_opened;
    // The rekey must happen at the same record count on both sides. It is keyed
    // off the count of records successfully opened, which — because a failure is
    // fatal — is exactly the count the sender sealed.
    if (_rekeyInterval != 0 && _opened % _rekeyInterval == 0) _recv.rekey();
    return Status::Ok;
}

} // namespace airusb::transport
