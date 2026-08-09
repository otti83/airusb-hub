// libFuzzer target over the kernel/user ABI decoder.
//
// This one has the worst blast radius of the four. The other three parse bytes
// from a network peer into a user-mode process; this parses bytes from an
// UNPRIVILEGED LOCAL PROCESS into a kernel-mode driver. A missed bound here is
// not a crash, it is kernel memory corruption reachable from a normal account,
// and the machine it would be found on is reachable only by RDP and takes a
// reboot per iteration.
//
// So the contract is asserted here, on a Mac, where finding it costs a rebuild:
// for ANY byte string, decoding must not crash, must not read out of bounds,
// and must not size an allocation from a number the input supplied.
//
// The second half is the part a "does it crash" fuzzer would miss: anything
// that decodes must round-trip. If a record is accepted, re-encoding the
// decoded value must reproduce the input byte for byte. That forbids a decoder
// that quietly normalises — accepting two spellings of one record is how the
// two ends come to disagree about what was said, and this format's whole
// premise is that they cannot.
//
// Build/run: tests/fuzz/build_and_run.sh

#include "../../platform/windows/UdecxIpc.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

using namespace airusb::windows::ipc;

namespace {

/// Decode as T, and if it worked, demand that re-encoding reproduces the input.
template <typename T>
bool roundTripsOrRejects(std::span<const std::uint8_t> in)
{
    T value;
    if (!decode(in, value)) return true;          // refused: nothing more to check

    std::vector<std::uint8_t> again;
    encode(value, again);
    if (again.size() != in.size()) __builtin_trap();
    for (std::size_t i = 0; i < again.size(); ++i)
        if (again[i] != in[i]) __builtin_trap();
    return true;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    std::span<const std::uint8_t> in(data, size);

    // The dispatcher first: it must survive anything, including an envelope
    // that names an opcode nobody implements.
    (void)decodeAny(in);

    // Then every decoder against every input, not only the one whose opcode is
    // in the envelope. A decoder must reject a record addressed to a different
    // one on the opcode alone, and the cheapest way to be sure is to try them
    // all against everything.
    (void)roundTripsOrRejects<UrbRequest>(in);
    (void)roundTripsOrRejects<UrbCompletion>(in);
    (void)roundTripsOrRejects<Configure>(in);
    (void)roundTripsOrRejects<ConfigureResult>(in);
    (void)roundTripsOrRejects<CancelRequest>(in);
    (void)roundTripsOrRejects<CancelAck>(in);

    Opcode op{};
    (void)peekOpcode(in, op);
    return 0;
}
