// AirUSB Hub — the window's side of the local channel.
//
// `airusb-hubd` holds one of these instead of holding an identity, a pin store
// and a session of its own. Every method is a request/reply against the broker,
// bounded by a deadline, and every one of them returns the broker's own state
// rather than a view assembled here — the window renders what the authority
// says, and computes nothing about trust.
//
// SYNCHRONOUS, AND THAT IS CORRECT HERE
//
// The broker is on the same machine, over a unix socket or a pipe, and every
// verb is a state change the person just asked for. Blocking for a few
// milliseconds inside an HTTP request is the shape the window already has for
// its own actions. What must never block is the BROKER, and it does not: it
// answers each frame in one non-blocking step.
//
// The deadline exists anyway, because "the broker is on the same machine"
// stops being true the moment it is wedged or killed, and a window that hangs
// on a dead daemon is a window with no way to say so.

#ifndef AIRUSB_CONTROL_BROKERCLIENT_H
#define AIRUSB_CONTROL_BROKERCLIENT_H

#include "BrokerProtocol.h"
#include "LocalEndpoint.h"

#include "../core/Clock.h"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace airusb::control {

class BrokerClient {
public:
    /// Connects and performs the version handshake. Returns NotFound when no
    /// broker is listening, which is the ordinary case on a machine where only
    /// the window has been started, and is what makes the standalone
    /// diagnostic mode reachable without pretending it is the same thing.
    Status open(const std::string& path, std::string* why);

    void close();
    bool connected() const noexcept { return _stream != nullptr; }

    const broker::AttachReply& hello() const noexcept { return _hello; }

    /// One round trip. `body` may be empty for the verbs that take none.
    Status call(broker::Op op, std::span<const std::uint8_t> body,
                std::vector<std::uint8_t>& replyBody, std::string* why);

    /// The broker's whole view. Cached from the last reply so the window can
    /// render between polls without a round trip per field.
    const broker::StateReply& state() const noexcept { return _state; }

    Status refreshState(std::string* why);

    // The verbs, each a thin wrapper that also refreshes the cached state.
    Status shareStart(std::uint16_t port, std::string* why);
    Status shareStop(std::string* why);
    Status shareApprove(const broker::Nonce& n, const std::string& fp,
                        std::uint32_t sas, bool accept, std::string* why);
    Status importConnect(const std::string& host, std::uint16_t port, std::string* why);
    Status importDisconnect(std::string* why);
    Status importApprove(const broker::Nonce& n, const std::string& fp,
                         std::uint32_t sas, bool accept, std::string* why);
    Status importRefresh(std::string* why);
    Status importAttach(const std::string& uidHex, std::string* why);
    Status importDetach(std::string* why);
    Status importVerify(std::string* why);
    Status importPing(std::string* why);
    Status forceReclaim(std::string* why);

private:
    Status sendAll(std::span<const std::uint8_t> bytes);
    Status readFrame(broker::FrameHeader& h, std::vector<std::uint8_t>& body,
                     const Deadline& by);

    std::unique_ptr<transport::IByteStream> _stream;
    std::vector<std::uint8_t>               _rx;
    broker::AttachReply                     _hello;
    broker::StateReply                      _state;
    std::uint64_t                           _tag = 0;
};

} // namespace airusb::control

#endif // AIRUSB_CONTROL_BROKERCLIENT_H
