// libFuzzer target over the window/broker channel.
//
// Same position as `fuzz_agentipc`, and for the same reason: this parser sits
// between a program an ordinary user runs and a daemon that owns the machine's
// USB identity, its pinned peers and its leases. A length trusted where it
// should be checked is a local privilege escalation, not a crash in a tool.
//
// It fuzzes the framing AND the bodies, because the two fail differently. The
// framing decides how many bytes to hand onward from a length the peer wrote;
// the bodies decide what those bytes mean. A target that only drove the bodies
// would never exercise the one arithmetic that can hand a decoder a span it
// does not own.
//
// And it asserts round-tripping, not merely absence of crashes: anything the
// decoder accepts must re-encode to identical bytes. A decoder that normalises
// accepts two spellings of one message, and the whole value of a version-locked
// channel is that both ends agree on exactly one.
//
// Build/run: tests/fuzz/build_and_run.sh

#include "../../control/BrokerProtocol.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

using namespace airusb;
using namespace airusb::control::broker;

namespace {

/// Decode as T, and if it worked, demand that re-encoding reproduces the input.
template <typename T>
void roundTripsOrRejects(std::span<const std::uint8_t> in)
{
    T value;
    if (!decode(in, value)) return;          // refused: nothing more to check

    std::vector<std::uint8_t> again;
    encode(value, again);
    if (again.size() != in.size()) __builtin_trap();
    for (std::size_t i = 0; i < again.size(); ++i)
        if (again[i] != in[i]) __builtin_trap();
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    const std::span<const std::uint8_t> in(data, size);

    // 1. The framing. Walk the buffer exactly as BrokerServer does, so the
    //    length arithmetic is driven with the same code path rather than an
    //    approximation of it.
    std::size_t at = 0;
    for (int guard = 0; guard < 64 && at < in.size(); ++guard) {
        FrameHeader h;
        std::span<const std::uint8_t> body;
        std::size_t consumed = 0;
        const Status s = parseFrame(in.subspan(at), h, body, consumed);
        if (s != Status::Ok) break;

        // Whatever the opcode claims, the body must survive being read as it.
        (void)decodeAny(h.op, body);

        // A frame that parsed must have consumed at least its header, or the
        // walk above would not terminate. Asserted rather than assumed: an
        // off-by-one here is an infinite loop in a privileged daemon.
        if (consumed < kHeaderSize) __builtin_trap();
        at += consumed;
    }

    // 2. The bodies, driven directly so the fuzzer can reach them without
    //    having to synthesise a valid frame first.
    roundTripsOrRejects<AttachRequest>(in);
    roundTripsOrRejects<AttachReply>(in);
    roundTripsOrRejects<ShareStartRequest>(in);
    roundTripsOrRejects<ImportConnectRequest>(in);
    roundTripsOrRejects<ApproveRequest>(in);
    roundTripsOrRejects<AttachDeviceRequest>(in);
    // StateReply round-trips too, and the reason is worth stating: its encoder
    // truncates at every cap while its decoder REFUSES past every cap, so
    // anything the decoder accepted was already within them and re-encoding
    // cannot shorten it. If that ever stops being true — a cap relaxed on one
    // side only — this is the assertion that says so.
    roundTripsOrRejects<StateReply>(in);

    return 0;
}
