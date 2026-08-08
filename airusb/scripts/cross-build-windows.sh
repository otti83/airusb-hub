#!/bin/bash
# Cross-compile the portable client for Windows from macOS or Linux.
#
# This exists because "it should build on Windows" is not the same statement as
# "it builds on Windows", and the difference was four real defects: a missing
# continuous clock, a GCC-only function attribute, %zu in printf, and a POSIX
# socket layer compiled into a Windows target.
#
#   brew install mingw-w64        # macOS
#   apt install g++-mingw-w64     # Debian/Ubuntu
#
# MinGW catches headers, APIs and linkage. It does NOT catch MSVC-specific
# issues, so a real MSVC build is still the acceptance test — see docs/WINDOWS.md.
set -euo pipefail
cd "$(dirname "$0")/.."

CXX="${MINGW_CXX:-x86_64-w64-mingw32-g++}"
command -v "$CXX" >/dev/null || { echo "error: $CXX not found" >&2; exit 1; }

OUT="${1:-build-win}"
mkdir -p "$OUT"

"$CXX" -std=c++20 -O2 -I. -Wall -Wextra -static \
    tools/airusb_net_main.cpp tests/fakes/ScriptedDevice.cpp \
    core/*.cpp crypto/*.cpp protocol/*.cpp transport/*.cpp session/*.cpp diag/*.cpp \
    -x c third_party/monocypher/monocypher.c \
         third_party/monocypher/monocypher-ed25519.c \
         third_party/blake2s/blake2s-ref.c \
    -lws2_32 -lbcrypt \
    -o "$OUT/airusb-net.exe"

echo "built $OUT/airusb-net.exe"
file "$OUT/airusb-net.exe" 2>/dev/null || true
