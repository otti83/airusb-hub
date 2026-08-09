#!/bin/bash
# Build and run the protocol fuzzer.
#
# The contract: for ANY byte string, decode+validate must not crash, must not read
# out of bounds, and must not allocate based on a peer-supplied length. The target
# additionally traps if R4 or R5 ever report "ok" while their invariant is violated,
# so a logic regression in the rules is a fuzzer finding, not just a memory bug.
#
# ---------------------------------------------------------------------------
# AddressSanitizer is DISABLED BY DEFAULT, and that is a deliberate,
# environment-specific decision — not an oversight. On the macOS 26.5.1 /
# Apple Silicon machine this was developed on, ANY binary linked with
# -fsanitize=address hangs before reaching main(). Verified by bisection:
#
#   -fsanitize=fuzzer              -> works
#   -fsanitize=fuzzer,undefined    -> works
#   -fsanitize=address             -> hangs, even for a hello-world main()
#                                     with no libFuzzer involved at all
#
# So the hang is in the ASan runtime on this host, not in AirUSB code. Set
# AIRUSB_FUZZ_ASAN=1 to opt back in on a host where ASan works — CI on Linux
# should always do so, because UBSan does not detect heap out-of-bounds reads
# and that is exactly the bug class R2/R5/R6 exist to prevent.
# ---------------------------------------------------------------------------
set -euo pipefail
cd "$(dirname "$0")/../.."

RUNS="${1:-300000}"
CORPUS="${2:-tests/vectors/corpus}"
mkdir -p "$CORPUS" build

SAN="fuzzer,undefined"
if [[ "${AIRUSB_FUZZ_ASAN:-0}" == "1" ]]; then
    SAN="fuzzer,address,undefined"
    echo "note: AddressSanitizer enabled — if this hangs before the libFuzzer"
    echo "      banner appears, your host has the ASan problem described above."
fi

clang++ -std=c++20 -g -O1 -fsanitize="$SAN" \
    -fno-sanitize-recover=undefined \
    tests/fuzz/fuzz_decode.cpp \
    protocol/Codec.cpp protocol/Validate.cpp core/Status.cpp \
    -o build/fuzz_decode

echo "running ${RUNS} executions over ${CORPUS} (sanitizers: ${SAN})"
./build/fuzz_decode -max_len=4096 -runs="${RUNS}" -print_final_stats=1 "$CORPUS"

# ---------------------------------------------------------------------------
# The daemon <-> agent IPC parser (P2.8).
#
# The LAN protocol is not the only parser in this system that reads bytes from a
# process we do not control. airusb-exportd runs as root and parses frames written
# by the unprivileged airusb-agent, so the same contract and the same fuzzing
# apply -- a length-confusion bug there is a local privilege escalation rather
# than a remote crash.
# ---------------------------------------------------------------------------
IPC_CORPUS="${3:-tests/vectors/corpus_ipc}"
mkdir -p "$IPC_CORPUS"

clang++ -std=c++20 -g -O1 -fsanitize="$SAN" \
    -fno-sanitize-recover=undefined \
    tests/fuzz/fuzz_agentipc.cpp \
    platform/macos/AgentProtocol.cpp protocol/Codec.cpp core/Status.cpp \
    -o build/fuzz_agentipc

echo
echo "running ${RUNS} executions over ${IPC_CORPUS} (sanitizers: ${SAN})"
./build/fuzz_agentipc -max_len=4096 -runs="${RUNS}" -print_final_stats=1 "$IPC_CORPUS"

# ---------------------------------------------------------------------------
# The Noise handshake parser (P2.4).
#
# HandshakeState::readMessage is the FIRST code in the system to touch bytes from
# an unauthenticated peer -- before the version, the identity, or even "is this
# Noise at all" has been established. Every length in it is peer-controlled.
#
# The vendored crypto is compiled in but is not the target: it has its own
# audits and its own vectors. What is being fuzzed is our state machine around
# it, and in particular that a malformed message can never advance a handshake.
# ---------------------------------------------------------------------------
NOISE_CORPUS="${4:-tests/vectors/corpus_noise}"
mkdir -p "$NOISE_CORPUS"

clang++ -std=c++20 -g -O1 -fsanitize="$SAN" \
    -fno-sanitize-recover=undefined \
    -Wno-deprecated-declarations \
    tests/fuzz/fuzz_noise.cpp \
    protocol/Noise.cpp crypto/Primitives.cpp crypto/Identity.cpp core/Status.cpp \
    third_party/monocypher/monocypher.c \
    third_party/monocypher/monocypher-ed25519.c \
    third_party/blake2s/blake2s-ref.c \
    -o build/fuzz_noise

echo
echo "running ${RUNS} executions over ${NOISE_CORPUS} (sanitizers: ${SAN})"
./build/fuzz_noise -max_len=4096 -runs="${RUNS}" -print_final_stats=1 "$NOISE_CORPUS"

# ---------------------------------------------------------------------------
# The kernel/user ABI (W1).
#
# The worst blast radius of the four. The others parse bytes from a network peer
# into a user-mode process; this one parses bytes from an UNPRIVILEGED LOCAL
# PROCESS into a kernel-mode driver, so a missed bound is kernel memory
# corruption reachable from a normal account. The machine that would find it is
# reachable only by RDP and costs a reboot per iteration, which is the entire
# argument for fuzzing it here instead.
#
# It also asserts round-tripping, not merely absence of crashes: anything the
# decoder accepts must re-encode to the identical bytes. A decoder that
# normalises accepts two spellings of one record, and two ends that disagree
# about what was said is the failure this format exists to prevent.
# ---------------------------------------------------------------------------
UDECX_CORPUS="${5:-tests/vectors/corpus_udecxipc}"
mkdir -p "$UDECX_CORPUS"

clang++ -std=c++20 -g -O1 -fsanitize="$SAN" \
    -fno-sanitize-recover=undefined \
    tests/fuzz/fuzz_udecxipc.cpp \
    platform/windows/UdecxIpc.cpp core/Status.cpp core/UsbTypes.cpp \
    -o build/fuzz_udecxipc

echo
echo "running ${RUNS} executions over ${UDECX_CORPUS} (sanitizers: ${SAN})"
./build/fuzz_udecxipc -max_len=4096 -runs="${RUNS}" -print_final_stats=1 "$UDECX_CORPUS"

# ---------------------------------------------------------------------------
# The USB/IP byte layer (L2).
#
# Named in LINUX_IMPORTER_PLAN.md §L2 since the plan was written, and absent
# from the tree until 2026-08-09 — while HANDOFF.md asserted the reference did
# not exist. Both are now true.
#
# It parses bytes the kernel writes, which sounds trusted and is not the useful
# framing: the header is 48 bytes of BIG-endian fields carrying a payload length,
# and inside it sits the USB SETUP packet, which is LITTLE-endian and must
# travel verbatim. One PDU, both orders. The round-trip assertion is what stops
# a regression into byteswapping the header wholesale, which corrupts
# enumeration itself.
# ---------------------------------------------------------------------------
USBIP_CORPUS="${6:-tests/vectors/corpus_usbip}"
mkdir -p "$USBIP_CORPUS"

clang++ -std=c++20 -g -O1 -fsanitize="$SAN" \
    -fno-sanitize-recover=undefined \
    tests/fuzz/fuzz_usbip.cpp \
    platform/linux/UsbipCodec.cpp core/Status.cpp core/UsbTypes.cpp \
    -o build/fuzz_usbip

echo
echo "running ${RUNS} executions over ${USBIP_CORPUS} (sanitizers: ${SAN})"
./build/fuzz_usbip -max_len=4096 -runs="${RUNS}" -print_final_stats=1 "$USBIP_CORPUS"

# ---------------------------------------------------------------------------
# The window <-> broker channel (A1).
#
# Same position as the agent IPC: a program an ordinary user runs, talking to a
# daemon that owns this machine's USB identity, its pinned peers and its leases.
# A length trusted where it should be checked is a local privilege escalation.
#
# It drives the FRAMING as well as the bodies, because the two fail differently:
# the framing decides how many bytes to hand onward from a length the peer wrote,
# and that is the one arithmetic that can produce a span nobody owns.
# ---------------------------------------------------------------------------
BROKER_CORPUS="${7:-tests/vectors/corpus_broker}"
mkdir -p "$BROKER_CORPUS"

clang++ -std=c++20 -g -O1 -fsanitize="$SAN" \
    -fno-sanitize-recover=undefined \
    tests/fuzz/fuzz_broker.cpp \
    control/BrokerProtocol.cpp protocol/Codec.cpp core/Status.cpp \
    -o build/fuzz_broker

echo
echo "running ${RUNS} executions over ${BROKER_CORPUS} (sanitizers: ${SAN})"
./build/fuzz_broker -max_len=4096 -runs="${RUNS}" -print_final_stats=1 "$BROKER_CORPUS"
