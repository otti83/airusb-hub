#include "BrokerClient.h"

#include "../core/Platform.h"
#include "../core/Watchdog.h"

#include <cstring>

namespace airusb::control {

using namespace airusb::control::broker;

namespace {

/// How long the window waits for the broker. Generous, because the broker may
/// be mid-handshake with a peer when the request lands, and finite, because a
/// window that hangs on a wedged daemon has no way to say so.
constexpr std::uint64_t kCallTimeoutMs = 10000;

} // namespace

Status BrokerClient::open(const std::string& path, std::string* why)
{
    close();

    Status st = Status::Ok;
    _stream = connectLocal(path, &st, why);
    if (!_stream) return st == Status::Ok ? Status::NotFound : st;

    AttachRequest req;
    std::vector<std::uint8_t> body;
    encode(req, body);

    std::vector<std::uint8_t> rep;
    if (const Status s = call(Op::Attach, body, rep, why); s != Status::Ok) {
        close();
        return s;
    }
    if (!decode(rep, _hello)) {
        close();
        if (why) *why = "the broker answered something this window cannot read";
        return Status::MalformedFrame;
    }
    if (_hello.version != kProtocolVersion) {
        close();
        if (why) *why = "the broker and this window are different versions";
        return Status::UnsupportedVersion;
    }
    return Status::Ok;
}

void BrokerClient::close()
{
    if (_stream) _stream->close();
    _stream.reset();
    _rx.clear();
    _hello = AttachReply{};
    _state = StateReply{};
}

Status BrokerClient::sendAll(std::span<const std::uint8_t> bytes)
{
    if (!_stream) return Status::TransportLost;
    const Clock& clock = Clock::system();
    const Deadline by = Deadline::afterMs(clock, kCallTimeoutMs);

    std::size_t sent = 0;
    while (sent < bytes.size()) {
        const auto r = _stream->write(bytes.subspan(sent));
        if (r.status == Status::Ok) { sent += r.bytes; continue; }
        if (r.status != Status::Busy) return r.status;
        if (by.expired(clock)) return Status::XferTimeout;
        platform::sleepMs(1);
    }
    return Status::Ok;
}

Status BrokerClient::readFrame(FrameHeader& h, std::vector<std::uint8_t>& body,
                               const Deadline& by)
{
    const Clock& clock = Clock::system();
    for (;;) {
        std::span<const std::uint8_t> view;
        std::size_t consumed = 0;
        const Status ps = parseFrame(_rx, h, view, consumed);
        if (ps == Status::Ok) {
            body.assign(view.begin(), view.end());
            _rx.erase(_rx.begin(), _rx.begin() + static_cast<std::ptrdiff_t>(consumed));
            return Status::Ok;
        }
        if (ps != Status::Busy) return ps;

        if (!_stream) return Status::TransportLost;
        std::uint8_t buf[4096];
        const auto r = _stream->read(std::span<std::uint8_t>(buf, sizeof buf));
        if (r.status == Status::Ok && r.bytes > 0) {
            _rx.insert(_rx.end(), buf, buf + r.bytes);
            continue;
        }
        if (r.status != Status::Ok && r.status != Status::Busy) return r.status;
        if (by.expired(clock)) return Status::XferTimeout;
        platform::sleepMs(1);
    }
}

Status BrokerClient::call(Op op, std::span<const std::uint8_t> body,
                          std::vector<std::uint8_t>& replyBody, std::string* why)
{
    if (!_stream) {
        if (why) *why = "not connected to a broker";
        return Status::TransportLost;
    }

    const std::uint64_t tag = ++_tag;
    std::vector<std::uint8_t> frame;
    encodeFrame(op, Status::Ok, tag, body, frame);
    if (const Status s = sendAll(frame); s != Status::Ok) {
        if (why) *why = "the broker stopped listening";
        close();
        return s;
    }

    const Clock& clock = Clock::system();
    const Deadline by = Deadline::afterMs(clock, kCallTimeoutMs);
    for (;;) {
        FrameHeader h;
        const Status s = readFrame(h, replyBody, by);
        if (s != Status::Ok) {
            if (why) *why = s == Status::XferTimeout
                                ? "the broker did not answer"
                                : "the broker connection ended";
            close();
            return s;
        }
        // A reply for an older tag can only exist if a previous call timed out
        // and its answer arrived late. Skipped rather than returned, because
        // attributing one call's answer to another is how a window shows the
        // outcome of something the person did not just do.
        if (h.tag != tag) continue;
        return static_cast<Status>(h.status);
    }
}

Status BrokerClient::refreshState(std::string* why)
{
    std::vector<std::uint8_t> rep;
    const Status s = call(Op::GetState, {}, rep, why);
    // The state comes back even on a refusal — the window has to be able to
    // render "that was refused, and here is what is actually true".
    if (!rep.empty()) (void)decode(rep, _state);
    if (s != Status::Ok && why && !_state.error.empty()) *why = _state.error;
    return s;
}

namespace {

/// Every verb has the same shape: send, and the reply IS the new state.
Status verb(BrokerClient& c, Op op, std::span<const std::uint8_t> body,
            StateReply& into, std::string* why)
{
    std::vector<std::uint8_t> rep;
    const Status s = c.call(op, body, rep, why);
    if (!rep.empty()) (void)decode(rep, into);
    // The broker's own sentence wins over the transport's guess. `call()` only
    // knows "it failed"; the broker knows why, and the person reading the
    // window needs the second one.
    if (s != Status::Ok && why && !into.error.empty()) *why = into.error;
    return s;
}

} // namespace

Status BrokerClient::shareStart(std::uint16_t port, std::string* why)
{
    ShareStartRequest r; r.port = port;
    std::vector<std::uint8_t> b; encode(r, b);
    return verb(*this, Op::ShareStart, b, _state, why);
}

Status BrokerClient::shareStop(std::string* why)
{
    return verb(*this, Op::ShareStop, {}, _state, why);
}

Status BrokerClient::shareApprove(const Nonce& n, const std::string& fp,
                                  std::uint32_t sas, bool accept, std::string* why)
{
    ApproveRequest r; r.nonce = n; r.fingerprint = fp; r.sas = sas; r.accept = accept;
    std::vector<std::uint8_t> b; encode(r, b);
    return verb(*this, Op::ShareApprove, b, _state, why);
}

Status BrokerClient::importConnect(const std::string& host, std::uint16_t port,
                                   std::string* why)
{
    ImportConnectRequest r; r.host = host; r.port = port;
    std::vector<std::uint8_t> b; encode(r, b);
    return verb(*this, Op::ImportConnect, b, _state, why);
}

Status BrokerClient::importDisconnect(std::string* why)
{
    return verb(*this, Op::ImportDisconnect, {}, _state, why);
}

Status BrokerClient::importApprove(const Nonce& n, const std::string& fp,
                                   std::uint32_t sas, bool accept, std::string* why)
{
    ApproveRequest r; r.nonce = n; r.fingerprint = fp; r.sas = sas; r.accept = accept;
    std::vector<std::uint8_t> b; encode(r, b);
    return verb(*this, Op::ImportApprove, b, _state, why);
}

Status BrokerClient::importRefresh(std::string* why)
{
    return verb(*this, Op::ImportRefresh, {}, _state, why);
}

Status BrokerClient::importAttach(const std::string& uidHex, std::string* why)
{
    AttachDeviceRequest r; r.uidHex = uidHex;
    std::vector<std::uint8_t> b; encode(r, b);
    return verb(*this, Op::ImportAttach, b, _state, why);
}

Status BrokerClient::importDetach(std::string* why)
{
    return verb(*this, Op::ImportDetach, {}, _state, why);
}

Status BrokerClient::importVerify(std::string* why)
{
    return verb(*this, Op::ImportVerify, {}, _state, why);
}

Status BrokerClient::importPing(std::string* why)
{
    return verb(*this, Op::ImportPing, {}, _state, why);
}

Status BrokerClient::forceReclaim(std::string* why)
{
    return verb(*this, Op::ForceReclaim, {}, _state, why);
}

} // namespace airusb::control
