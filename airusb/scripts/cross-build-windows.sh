#!/bin/bash
# Cross-compile the portable Windows binaries from macOS or Linux.
#
#   airusb-net.exe    the command-line client
#   airusb-hubd.exe   the daemon behind the window
#
# Both are statically linked and need nothing installed on the target machine.
# That matters more for the second one than the first: the whole argument for
# making the interface a web page was that every machine already has a browser,
# and it would be a poor argument if getting the page onto a Windows box needed
# Visual Studio. One file, copy it, run it.
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

COMMON=(core/*.cpp crypto/*.cpp protocol/*.cpp transport/*.cpp session/*.cpp diag/*.cpp)
VENDORED=(-x c third_party/monocypher/monocypher.c
                third_party/monocypher/monocypher-ed25519.c
                third_party/blake2s/blake2s-ref.c)

"$CXX" -std=c++20 -O2 -I. -Wall -Wextra -static \
    tools/airusb_net_main.cpp tests/fakes/ScriptedDevice.cpp \
    "${COMMON[@]}" "${VENDORED[@]}" \
    -lws2_32 -lbcrypt \
    -o "$OUT/airusb-net.exe"

"$CXX" -std=c++20 -O2 -I. -Wall -Wextra -static \
    tools/airusb_hubd_main.cpp tests/fakes/ScriptedDevice.cpp \
    control/*.cpp "${COMMON[@]}" "${VENDORED[@]}" \
    -lws2_32 -lbcrypt \
    -o "$OUT/airusb-hubd.exe"

for exe in airusb-net airusb-hubd; do
    echo "built $OUT/$exe.exe"
    file "$OUT/$exe.exe" 2>/dev/null || true
done
