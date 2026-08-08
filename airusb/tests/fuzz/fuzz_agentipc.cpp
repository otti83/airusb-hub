// Fuzz target for the daemon <-> agent IPC parser (platform/macos/AgentProtocol).
//
// This parser is the one place in the exporter where a root process reads bytes
// written by a process it does not control. A length-confusion bug here is a
// local privilege escalation, not a crash, so it gets the same fuzzing the LAN
// protocol gets.
//
// The contract, for ANY byte string:
//   * decodeFrame never reads outside the span it was handed,
//   * it never allocates on the strength of a peer-supplied length that has not
//     been checked against the bytes actually present,
//   * a body decoder that returns true has produced values consistent with the
//     bytes it was given, and
//   * a frame that decodes must re-encode to a byte-identical frame, so no field
//     is silently dropped or invented.
//
// The last one is the interesting invariant: it is what would catch a decoder
// that quietly ignored a field an encoder writes.

#include "../../platform/macos/AgentProtocol.h"

#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>

using namespace airusb;
using namespace airusb::macos::ipc;

namespace {

void exerciseBodies(const Frame& f)
{
    // Every body decoder is offered every body, not merely the one matching the
    // opcode. A peer is free to send a BULK_OUT body under a HELLO opcode, and
    // "the caller would never do that" is not a memory-safety argument.
    HelloBody h;
    if (decodeHello(f.body, h)) {
        std::vector<std::uint8_t> re;
        encodeHello(h, re);
        assert(re.size() == kHelloBodySize);
        assert(std::memcmp(re.data(), f.body.data(), kHelloBodySize) == 0);
    }

    OpenBody o;
    if (decodeOpen(f.body, o)) {
        std::vector<std::uint8_t> re;
        encodeOpen(o, re);
        assert(re.size() == kOpenBodySize);
    }

    EpRef e;
    (void)decodeEpRef(f.body, e);

    std::uint32_t actual = 0;
    if (decodeActualLen(f.body, actual)) {
        // The decoder promises this bound; a caller sizing a buffer from it must
        // be able to rely on it without re-checking.
        assert(actual <= kMaxTransferBytes);
    }

    PipeTable t;
    if (decodePipeTable(f.body, t)) {
        assert(t.endpoints.size() <= kMaxEndpoints);
        for (const EpEntry& ep : t.endpoints)
            assert(ep.type <= static_cast<std::uint8_t>(XferType::Interrupt));

        // A decoded table must survive a re-encode with the same row count.
        std::vector<std::uint8_t> re;
        encodePipeTable(t, re);
        assert(re.size() == kPipeTableHeaderSize + t.endpoints.size() * kEpEntrySize);
    }

    for (XferPayload expect : { XferPayload::None, XferPayload::Present }) {
        XferReq x;
        std::span<const std::uint8_t> payload;
        if (!decodeXferReq(f.body, expect, x, payload)) continue;

        assert(x.length <= kMaxTransferBytes);

        // The declared length and the bytes present must agree exactly. This is
        // the assertion that caught the zero-length-with-payload case; keeping it
        // unconditional is what stops that class coming back.
        if (expect == XferPayload::None) assert(payload.empty());
        else                             assert(payload.size() == x.length);

        // The payload must be a view INSIDE the body it came from.
        assert(payload.empty() ||
               (payload.data() >= f.body.data() &&
                payload.data() + payload.size() <= f.body.data() + f.body.size()));
    }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    std::span<const std::uint8_t> buf(data, size);

    // Drain the buffer exactly as AgentLink::receive does, so a frame stream is
    // fuzzed rather than only a single frame.
    std::size_t at = 0;
    for (int guard = 0; guard < 64 && at <= size; ++guard) {
        Frame f;
        std::size_t consumed = 0;
        const Decode d = decodeFrame(buf.subspan(at), f, consumed);

        if (d == Decode::NeedMore) break;
        if (d == Decode::Malformed) break;

        // Progress is mandatory: a decoder that returns Ok while consuming zero
        // bytes would spin AgentLink::receive forever on a hostile stream.
        assert(consumed >= kHeaderSize);
        assert(consumed == kHeaderSize + f.body.size());
        assert(at + consumed <= size);

        // Round-trip: re-encoding a decoded frame must reproduce it byte for byte.
        std::vector<std::uint8_t> re;
        encodeFrame(f, re);
        assert(re.size() == consumed);
        assert(std::memcmp(re.data(), data + at, consumed) == 0);

        assert(isKnownOp(static_cast<std::uint16_t>(f.op)));
        exerciseBodies(f);

        at += consumed;
    }

    return 0;
}
