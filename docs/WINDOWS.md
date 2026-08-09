# Testing with Windows

The client is portable C++ with no platform USB API. It builds and runs on
Windows today and talks to a macOS exporter over the LAN — which proves the wire
protocol, the crypto and the session layer on Windows long before there is a
Windows driver.

What it does **not** do yet is present the device to Windows' USB stack. That is
the UdeCx driver, and it is the next piece.

---

## Quickest path: use the prebuilt binary

A statically linked `airusb-net.exe` is attached to the latest
[release](https://github.com/otti83/airusb-hub/releases). Download it and skip to
"Run it against the Mac" — no Visual Studio, no toolchain.

It is cross-compiled from the same sources with MinGW-w64
(`scripts/cross-build-windows.sh`).

---

## Build it yourself

Needs **Visual Studio 2022** (the "Desktop development with C++" workload) and
**CMake**. Both ship with the VS installer.

In a *Developer PowerShell for VS 2022*:

```powershell
git clone https://github.com/otti83/airusb-hub
cd airusb-hub\airusb
cmake -S . -B build
cmake --build build --config Release --target airusb-net
```

The binary lands at `build\Release\airusb-net.exe`.

MinGW-w64 works too if you prefer it — `cmake -S . -B build -G "MinGW Makefiles"`.

### What was actually verified

The sources cross-compile cleanly to a Windows PE with MinGW-w64, which is how
four real defects were found and fixed rather than guessed at:

| defect | why it mattered |
|---|---|
| no continuous clock for Windows | a hard `#error`; the lease timers need a clock that keeps counting through sleep |
| `__attribute__((format))` | GCC/Clang only; MSVC has no equivalent |
| `%zu` in `printf` | MinGW's C runtime has no `z` length modifier |
| the POSIX unix-socket layer was compiled into every target | Windows has no `sys/un.h`, and no need for that layer at all |

MinGW proves headers, APIs and linkage. It does **not** prove MSVC, which is
stricter under `/permissive-` and needs `/utf-8` for the non-ASCII characters in
user-facing strings. Both are set in `CMakeLists.txt`, and the MSVC build is now
the acceptance test in CI — see below.

### What MSVC actually does now (2026-08-09)

The audit below was a prediction. CI has since settled it, and then some:

```
MSVC 19.51.36252.0, /W4 /permissive-, zero warnings
100% tests passed out of 24
verdict=PASS  outTransfers=5 largestOut=131072 bytesWritten=281088 mismatched=0
SEGMENTATION out=2 in=2 contRecords=14 maxSegment=16552 largestOut=131072 fired=yes
RESULT=PASS
```

That `SEGMENTATION` line is the load-bearing one and it is new. Before it, the
largest transfer any end-to-end run had ever carried was 16 384 bytes — which
fits inside one 16 640-byte record, so the segmented path had never executed
anywhere, on any platform, while a unit test claimed it was being exercised. The
write probe's largest run is now 131 072 bytes, sized against Noise's 65 519-byte
plaintext ceiling so that it must split at any legal record size, and the run
FAILS if it does not.

The Windows job also starts two `airusb-hubd` daemons and pairs them through the
control API — all three guard refusals provoked, the exporter-first order that
tears the session down mid-decision, reconnect, attach, `probe verdict=PASS`. So
the product's window is verified on Windows too, not merely compiled. See
[`GUI.md`](GUI.md).

The whole Windows target now also compiles warning-free under the flag set CMake
actually configures — `-Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion
-Wshadow` — and not merely under the `-Wall -Wextra` the cross-build script uses.
Those are different claims and only the weaker one used to be true.

### The MSVC audit, and the one thing it found

Because MSVC could not be run, the sources were audited against it directly:
seven passes over the 21 translation units in the `airusb-net` target — missing
transitive includes, GNU extensions, the Windows API shim, `/permissive-`
strictness, Windows runtime behaviour, the CMake configure, and byte-level wire
compatibility — with every finding then adversarially re-checked.

**One genuine build break existed and is fixed.** `crypto/Primitives.h` declared
`std::string toHex(...)` while including `<string_view>` but not `<string>`.
libc++ and libstdc++ both leak `<string>` through other headers, so Clang and
MinGW never complained. Microsoft's does not: `<string_view>` reaches `<xstring>`
only under the opt-in `_LEGACY_CODE_ASSUMES_STRING_VIEW_INCLUDES_XSTRING`, and
`std::string`'s alias lives nowhere else. Seven of the ten translation units that
reach that header had no prior `<string>`, and `crypto/Primitives.cpp` is the
first source of the first library the documented command builds — so MSVC would
have failed almost immediately, with `C2039: 'string': is not a member of 'std'`.

Everything else that looked like a Windows defect was refuted on inspection, and
the refutations are worth more than the findings:

| looked like | why it is not |
|---|---|
| `SO_REUSEADDR` on the listener is a Windows port-hijack switch | the hijack is keyed on the *second* binder, and since Server 2003 needs the same user — who can already read the identity seed. `SO_EXCLUSIVEADDRUSE` would also block rebinding for up to 120 s of `TIME_WAIT` after Ctrl-C, which is the worse trade for a hand-driven tool |
| the pin store's parser rejects CRLF and would silently unpair everyone | nothing writes CRLF: `writeFileAtomically` is `"wb"` and `readWholeFile` is `"rb"`. Notepad has preserved LF since Windows 10 1809 |
| the listening `SOCKET` is truncated to `int` | real type-hygiene slip, fixed — but not a defect: Windows kernel handles are capped near 2²⁶ by the handle table, and MSDN documents the truncate/sign-extend round trip |

Two latent defects unrelated to Windows were found and fixed on the way: an
out-of-bounds read in the importer's ATTACH reject path on a peer-controlled
body, and a handshake timeout that counted iterations rather than reading a clock
(making the documented 15 s window about four minutes on Windows, where the sleep
tick is 15.625 ms).

---

## With a window instead of a command line

`airusb-hubd` is the same thing with an interface. It runs on Windows exactly as
it runs everywhere else, needs no privileges, and opens a page in whatever
browser is already installed:

```powershell
.\build\Release\airusb-hubd.exe --share --share-port 7714 --name "GMKtec"
```

The two-machine procedure — firewall rule, which side shares, what to compare —
is written out in [`GUI.md`](GUI.md).

---

## Run it against the Mac

**On the Mac**, serve a simulated drive:

```bash
cd "AirUSB Hub/airusb"
./build/airusb-net serve --port 7714
```

Note the Mac's LAN address (`ipconfig getifaddr en0`).

**On Windows**, connect:

```powershell
.\build\Release\airusb-net.exe connect --host <MAC-IP> --port 7714 --probe
```

The first run pairs and disconnects — that is the trust-on-first-use path. Both
sides print a six-digit SAS; **they must match**. Run it a second time to attach
and read.

A successful run ends with:

```
verdict=PASS  cbw=6 data=5 csw=6 stallRecoveries=0 boundariesIntact=yes
RESULT=PASS — a USB Mass Storage exchange completed over an encrypted,
              authenticated network session
```

That is a complete USB Mass Storage exchange — CBW, data, CSW — carried between
two operating systems over ChaCha20-Poly1305 with mutually authenticated
identities.

If the Mac's firewall prompts, allow incoming connections for `airusb-net`.

---

## What this proves, and what it does not

| | |
|---|---|
| wire protocol on Windows | proven by this |
| Noise handshake, pinning, SAS on Windows | proven by this |
| a Windows app can drive a remote USB device | proven by this |
| Windows *enumerating* it as a real USB device | **not yet** — needs the driver |

The same binary has already been run macOS→macOS and macOS→Linux, so a Windows
result that differs is a Windows problem and not an ambiguity in the protocol.

---

## The part that still needs writing

`UdecxHostBackend` plus `airusb.sys`, a KMDF client driver using the USB Device
Emulation Class Extension. Design in
[`P1_IMPLEMENTATION_PLAN.md`](P1_IMPLEMENTATION_PLAN.md) §4.6. The split is
forced: the client driver is kernel-mode and cannot host the protocol or the
transport, so they talk over an inverted-call IOCTL channel plus a shared-memory
arena.

**Windows' gate is different from Apple's, and better.** Development needs only
test signing, which is self-service:

```powershell
bcdedit /set testsigning on     # then reboot
```

Distribution needs an EV certificate and Microsoft attestation signing — a paid
process, but a process, not a discretionary approval. Nothing about the Windows
path waits on anyone's decision.

Compare the macOS importer, which cannot run **at all** without an entitlement
Apple grants by hand: see [`ENTITLEMENT_REQUEST.md`](ENTITLEMENT_REQUEST.md).
