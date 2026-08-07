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
