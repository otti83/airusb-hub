#!/bin/bash
# Build and run the protocol fuzzer under ASan + UBSan.
#
# The contract: for ANY byte string, decode+validate must not crash, must not read
# out of bounds, and must not allocate based on a peer-supplied length. The target
# additionally traps if R4 or R5 ever report "ok" while their invariant is violated,
# so a logic regression in the rules is a fuzzer finding, not just a memory bug.
set -euo pipefail
cd "$(dirname "$0")/../.."

SECONDS_TO_RUN="${1:-60}"
CORPUS="${2:-tests/vectors/corpus}"
mkdir -p "$CORPUS" build

clang++ -std=c++20 -g -O1 -fsanitize=fuzzer,address,undefined \
    -fno-sanitize-recover=undefined \
    tests/fuzz/fuzz_decode.cpp \
    protocol/Codec.cpp protocol/Validate.cpp core/Status.cpp \
    -o build/fuzz_decode

echo "running ${SECONDS_TO_RUN}s over ${CORPUS}"
./build/fuzz_decode -max_len=4096 -max_total_time="${SECONDS_TO_RUN}" \
    -print_final_stats=1 "$CORPUS"
