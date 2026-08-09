// libFuzzer target over the USB/IP byte layer (platform/linux/UsbipCodec).
//
// WHY THIS FILE EXISTS, AND WHY IT DID NOT
//
// `LINUX_IMPORTER_PLAN.md` §L2 has named `tests/fuzz/fuzz_usbip.cpp` as part of
// L2's evidence since the plan was written. The file was never created. Worse,
// `HANDOFF.md` rebutted a review that pointed this out, asserting that "no
// reference exists in this tree" — which was wrong, and is the exact shape of
// mistake the project's own Evidence First rule exists to catch: a claim
// checked against another document instead of against the tree. Found by
// GPT-5.6 on 2026-08-09, verified with grep, and closed by writing the target
// rather than deleting the claim.
//
// WHAT IT GUARDS
//
// This decoder reads bytes the LINUX KERNEL writes. That sounds like a trusted
// source and is not the useful way to think about it: the bytes arrive over a
// socket, the header is 48 bytes of big-endian fields with a payload length
// inside it, and the code that consumes the result goes on to allocate and to
// index. A bug here is reachable from any process that can hand our end of the
// socketpair to something else, and — much more likely in practice — from our
// own bridge misreading a PDU and walking off the end of a buffer.
//
// THE BYTE-ORDER TRAP IS THE POINT
//
// USB/IP's header is BIG-endian while the `setup[8]` field inside it is the USB
// SETUP packet, which is LITTLE-endian and must travel verbatim. One PDU, both
// orders. A codec that byteswaps the header wholesale corrupts enumeration
// itself — the L1 gate's hex dump exists because of exactly this. The
// round-trip assertion below is what would catch a regression into it: if a
// CMD_SUBMIT decodes, re-encoding it must reproduce the input byte for byte,
// so a field read in the wrong order cannot survive the trip.
//
// Build/run: tests/fuzz/build_and_run.sh

#include "../../platform/linux/UsbipCodec.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

using namespace airusb;
using namespace airusb::linuxvhci;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    const std::span<const std::uint8_t> in(data, size);

    UsbipPdu pdu;
    bool clamped = false;
    if (decodePdu(in, pdu, &clamped)) {
        // A decode that succeeded consumed exactly one header. Anything else
        // means the size check and the reader disagree.
        if (in.size() != kPduBytes) __builtin_trap();

        // Round trip, for the two commands the importer ever sends back. The
        // clamp is the one legitimate normalisation in this codec — it exists
        // so a caller can REFUSE rather than transact on a packet count the
        // kernel did not send — so a clamped PDU is skipped rather than being
        // held to a byte-identical re-encode it cannot meet.
        if (!clamped && pdu.command == kCmdSubmit) {
            std::vector<std::uint8_t> again;
            encodeCmdSubmit(pdu, again);
            if (again.size() != in.size()) __builtin_trap();
            for (std::size_t i = 0; i < again.size(); ++i)
                if (again[i] != in[i]) __builtin_trap();
        }
        if (!clamped && pdu.command == kCmdUnlink) {
            std::vector<std::uint8_t> again;
            encodeCmdUnlink(pdu.seqnum, pdu.devid, pdu.unlinkSeqnum, again);
            if (again.size() != in.size()) __builtin_trap();
            for (std::size_t i = 0; i < again.size(); ++i)
                if (again[i] != in[i]) __builtin_trap();
        }

        // And the reply path, driven with whatever the input produced. This is
        // where a bad `actualLength` would size a buffer if anything here ever
        // trusted it.
        std::vector<std::uint8_t> out;
        encodeRetSubmit(pdu, pdu.status, pdu.actualLength, pdu.errorCount, out);
        if (out.size() != kPduBytes) __builtin_trap();

        out.clear();
        encodeRetUnlink(pdu.seqnum, pdu.status, out);
        if (out.size() != kPduBytes) __builtin_trap();
    }

    // The isochronous descriptor array, whose COUNT comes out of the header
    // above and is therefore attacker-influenced. Driven with the count the PDU
    // actually claimed, so the fuzzer explores the real relationship between
    // the two rather than an invented one.
    {
        const std::size_t count =
            pdu.numberOfPackets < 0 ? 0 : static_cast<std::size_t>(pdu.numberOfPackets);
        std::vector<UsbipIsoDesc> descs;
        (void)decodeIsoDescs(in, count, descs);
        if (descs.size() > count) __builtin_trap();
    }

    return 0;
}
