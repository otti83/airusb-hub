# AirUSB Hub — Session Handoff

**Written:** 2026-08-08
**Purpose:** resume this project in a fresh session with no access to the previous
conversation. Everything load-bearing is here or in the documents it points to.
**Repo:** `/Users/mba/Desktop/AirUSB Hub` — **now public** at
<https://github.com/otti83/airusb-hub> (Apache-2.0, branch `main`, `gh`
authenticated as `otti83`).

---

## 0. Where things stand, in one screen

| | state |
|---|---|
| Sharing a USB device from a Mac | **works on real hardware** (058f:6387 SuperSpeed) |
| Encryption + authentication | **done** — Noise_XX / Noise_IK, official vectors matched |
| Session layer, L1 protocol, manifest | **done** |
| Networking | **done** — real TCP, macOS↔macOS and macOS↔Linux |
| Windows client | **works** — MSVC 19.51 builds it, 13/13 suites pass natively, full BOT exchange over a real socket |
| Receiving on a Mac | **blocked on Apple** — FB24214361, see §2 |
| Receiving on Windows / Linux | driver half not written |

```
15 test suites / 0 failures
3 fuzz targets / 0 crashes / 0 UB findings
Zero warnings: macOS (Clang, full flag set), Linux (GCC 12, -Wall -Wextra),
               Windows (MinGW, full flag set — -Wpedantic -Wconversion
               -Wsign-conversion -Wshadow, not just -Wall -Wextra),
               Windows (MSVC 19.51, /W4 /permissive-) — measured in CI
CI: 4/4 green — Windows/MSVC, Linux/ASan+UBSan, macOS/Clang, MinGW cross
~21,500 lines ours + 10 vendored files
```

### Windows is DONE. THE NEXT TASK is the UdeCx driver.

CI ran on 2026-08-09 and **all four jobs are green**, and the two-machine run was
then done on real hardware (§3.4). Measured on Windows Server 2025 with
**MSVC 19.51.36252.0**:

```
13/13 suites pass natively on Windows      zero MSVC warnings at /W4 /permissive-
verdict=PASS  cbw=6 data=5 csw=6 stallRecoveries=0 shortReads=0
RESULT=PASS — a USB Mass Storage exchange completed over an encrypted,
              authenticated network session
```

**ASan ran for the first time in this project's life**, on Linux, and found
nothing: 13/13 plus its own `RESULT=PASS` under `address,undefined`.

And the part CI structurally cannot do — **two machines, two operating systems,
a real network** — was done by hand the same day and passed, with the SAS
confirmed identical on both consoles (§3.4).

**Nothing about the portable half is unmeasured any more.** The next task is
§5.1, the UdeCx driver: the piece that makes Windows *enumerate* the device
rather than merely drive it. Windows' gate is self-service (`bcdedit /set
testsigning on`), so unlike the macOS importer it waits on nobody's decision.

---

## 1. What this project is

An OSS cross-platform virtual USB hub. A USB device attached to one machine is
forwarded over the LAN so the importing machine's OS **enumerates it as a real USB
device and loads its own native drivers**. Not file sharing.

Governing rules from the master prompt:

- **Natural Path Only.** No private API, no SIP disable, no OS modification, no
  mass-storage-specific fake presented as generic USB.
- **Evidence First.** No claim of "works" without a log, dump or before/after from
  the *same* iteration.
- **Phase Gate.** Goal / Implementation / Evidence / PASS-FAIL / Known Issues /
  Next. A failed gate does not advance.
- Correctness > Compatibility > Reliability > Latency > Throughput.

---

## 2. The Apple entitlement — the only thing blocking the macOS importer

### 2.1 Status

| | |
|---|---|
| Entitlement | `com.apple.developer.usb.host-controller-interface` |
| Feedback ID | **FB24214361** |
| Filed | 2026-08-08 14:08 |
| Team ID | **GZUV3UMV3B** |
| Account type | **Individual** ← the known risk |
| Response | none yet |

**Outstanding action:** post FB24214361 in
<https://developer.apple.com/forums/thread/802495>. Apple DTS (Kevin Elliott,
CoreOS/Hardware) states in that thread:

> "The engineer who approves these requests is generally good about handling these
> quickly, but **if you post the bug number here I'm happy to make sure it gets to
> the right place.**"

Filing alone puts it in the ordinary queue. Posting the number is what routes it.
Ready-to-paste text is in `ENTITLEMENT_REQUEST.md`.

### 2.2 Why it is not in the developer portal — measured, not assumed

**Do not send anyone looking for a checkbox. There is not one.** This already cost
real time in a previous session.

Xcode 26.5 caches the portal's own capability catalogue at
`/Applications/Xcode.app/Contents/SharedFrameworks/DVTPortal.framework/Versions/A/Resources/DVTPortalCachedPortalCapabilities.json`:

```
total capabilities Xcode knows: 196
USB-related entries: 2
    DRIVERKIT_TRANSPORT_USB_VENDORID
    DRIVERKIT_USBTRANSPORT_PUB
host-controller-interface present anywhere: False
```

Searching the whole Xcode bundle for the string finds it **only in SDK headers**,
which merely document that the entitlement is required — never in a capability
list, a provisioning definition, or a UI resource.

The comparison is what makes it conclusive. Entitlements that need Apple's
approval but *are* requestable still appear in the catalogue:

| entitlement | in the catalogue? |
|---|---|
| `MULTICAST_NETWORKING` (managed, has a form) | **yes** |
| `CARPLAY_*` (managed) | **yes** |
| `DRIVERKIT_USBTRANSPORT_PUB` | **yes** |
| `APP_GROUPS`, `HOMEKIT` (self-serve) | yes |
| `host-controller-interface` | **no** |

This one is in a rarer class: not exposed through the portal at all, matching DTS
saying the request volume "is low enough that it's never been integrated into the
developer portal". **Making it a SwiftUI app changes nothing** — Xcode does not
know the capability exists, so no "+ Capability" list can show it.

### 2.3 Team ID was settled by measurement

```
$ defaults read com.apple.dt.Xcode IDEProvisioningTeamByIdentifier
    isFreeProvisioningTeam = 0;
    teamID   = GZUV3UMV3B;
    teamName = "Hiroya Ochiai";
    teamType = Individual;
```

Exactly one team is signed into Xcode. `WT36SR3Q23` exists only as a keychain
signing identity with no provisionable team behind it. The provisioning profile
Xcode issued for `apple/` is against `GZUV3UMV3B`.

`teamType = Individual` is the honest statement of the risk: every confirmed
holder of this entitlement found during Phase 0 is an **Organization**. Publishing
the repository was the cheapest available mitigation and has been done.

### 2.4 Prior authorization evidence (Phase 0, `poc/p0-probe/run_probe.sh`)

Six signing variants, measured:

```
A ad-hoc,    no entitlement                    exit 2    kIOReturnNotOpen 0xE00002CD
B ad-hoc,    HCI entitlement                   exit 137  SIGKILL by AMFI
C Apple Dev, HCI entitlement                   exit 137  SIGKILL by AMFI
D Apple Dev, no entitlement                    exit 2    kIOReturnNotOpen
E Apple Dev, FABRICATED com.apple.developer.*  exit 137  SIGKILL
F Apple Dev, com.apple.security.cs.*           exit 2    runs
```

E vs F is the informative pair: a *made-up* `com.apple.developer.*` entitlement is
killed identically, so this is AMFI's generic restricted-prefix rule, not a
targeted block. It **is** obtainable — VirtualHere ships it under a notarized
Developer ID signature, verified locally with `codesign -d --entitlements -`,
`spctl -a -vvv` and `security cms -D`.

### 2.5 How to tell the moment it lands

`apple/` is an Xcode project (generated from `project.yml` by `xcodegen`; the
`.xcodeproj` is gitignored). Build and run it:

```bash
cd "/Users/mba/Desktop/AirUSB Hub/apple" && xcodegen generate
xcodebuild -project AirUSBHub.xcodeproj -scheme AirUSBHub \
           -destination 'platform=macOS' -allowProvisioningUpdates build
open ~/Library/Developer/Xcode/DerivedData/AirUSBHub-*/Build/Products/Debug/AirUSBHub.app
```

The window's "Receiving devices" bar runs the probe. Current, expected state:

```
embedded.provisionprofile: PRESENT (14558 bytes)
profile authorises host-controller-interface: NO
RESULT=REFUSED 0xE00002CD kIOReturnNotOpen
```

After the grant, add one line to `apple/Sources/AirUSBHub.entitlements`:

```xml
<key>com.apple.developer.usb.host-controller-interface</key><true/>
```

then `xcodegen generate` and rebuild. `RESULT=GRANTED` means P2.9 is unblocked.

**Why the App Group is in that entitlements file:** it is a real need (the exporter
is two processes sharing a pin store) *and* it is a capability that requires a
provisioning profile. Without it, macOS development signing needs no profile,
Xcode never contacts the portal, and none is issued — verified: the first build
here, before the App Group was added, signed cleanly and produced nothing.

---

## 3. Cross-platform status in detail

### 3.1 What has actually been run

| combination | result |
|---|---|
| macOS exporter ↔ macOS client, TCP loopback | **PASS** |
| macOS exporter ↔ Linux client, real network | **PASS** |
| Windows, built with MSVC 19.51, loopback | **PASS** — 13/13 suites + a full BOT exchange, in CI |
| Linux under ASan + UBSan, loopback | **PASS** — 13/13 + BOT exchange, no sanitizer findings |
| Windows client, cross-compiled to a PE | **builds** (CI job `windows-cross`) |
| **Windows exporter ↔ macOS importer, two machines, real network** | **PASS** — 2026-08-09, see §3.4 |

The passing runs end with a complete USB Mass Storage exchange:

```
verdict=PASS  cbw=6 data=5 csw=6 stallRecoveries=0 shortReads=0 boundariesIntact=yes
  GET_MAX_LUN            ok   bMaxLUN=0
  TEST_UNIT_READY        ok
  INQUIRY                ok   'AirUSB' 'Scripted Device' rev '0001'
  READ_CAPACITY_10       ok   lastLBA=61439 blockSize=512 -> 61440 blocks
  READ_10_LBA0           ok   512 bytes, residue=0
  SHORT_READ_FIDELITY    ok   offered 1024, device sent 512 — short read preserved
  READ_10_MULTIBLOCK     ok   2048 bytes in one transfer, residue=0
RESULT=PASS — a USB Mass Storage exchange completed over an encrypted,
              authenticated network session
```

Different compilers, different libc, different kernels, byte-identical protocol.
The instrument is `diag/BotProbe`, the same one that drove a physical drive during
the P2.8 hardware gate — so a failure means the network is wrong, not the probe.

### 3.2 Linux — how to reproduce

A Lima VM already exists on this Mac, named **`kbuild`** (Debian 12, aarch64,
GCC 12.2). It belongs to another project; nothing here modified it.

```bash
limactl start kbuild
limactl shell kbuild bash -lc '
SRC="/Users/mba/Desktop/AirUSB Hub/airusb"; mkdir -p /tmp/airusb-linux; cd /tmp/airusb-linux
g++ -std=c++20 -O1 -I"$SRC" -Wall -Wextra \
  "$SRC"/tools/airusb_net_main.cpp "$SRC"/tests/fakes/ScriptedDevice.cpp \
  "$SRC"/core/*.cpp "$SRC"/crypto/*.cpp "$SRC"/protocol/*.cpp \
  "$SRC"/transport/*.cpp "$SRC"/session/*.cpp "$SRC"/diag/*.cpp \
  -x c "$SRC"/third_party/monocypher/monocypher.c \
       "$SRC"/third_party/monocypher/monocypher-ed25519.c \
       "$SRC"/third_party/blake2s/blake2s-ref.c \
  -o airusb-net'
```

The Mac host is reachable from the VM at **192.168.5.2**. There is no cmake in
that VM; the direct `g++` line above doubles as proof that nothing depends on
cmake.

Then, with `./build/airusb-net serve --port 7714` running on the Mac:

```bash
limactl shell kbuild bash -lc \
  'cd /tmp/airusb-linux && ./airusb-net connect --host 192.168.5.2 --port 7714 --probe'
```

The first run pairs and disconnects; the second attaches and reads.

**vhci-hcd, for a Linux importer later:** the VM's running `cloud` kernel does NOT
ship it, but Debian's standard kernel does — verified by unpacking the package:

```
./lib/modules/6.1.0-50-arm64/kernel/drivers/usb/usbip/vhci-hcd.ko
```

So a Linux importer needs `apt install linux-image-arm64`, a reboot, then
`modprobe vhci-hcd`. **No permission from anyone, no signing, no special boot
mode.** That makes Linux the cheapest route to a working importer if Apple
declines.

### 3.3 Windows — exactly what is and is not verified

`mingw-w64` is installed via Homebrew. `scripts/cross-build-windows.sh` produces a
statically linked `airusb-net.exe` (PE32+ x86-64).

**Cross-compiling found four real defects.** They were bugs, not warnings:

| defect | why it mattered |
|---|---|
| `core/Watchdog.cpp` had no Windows clock — a hard `#error` | the lease timers need a clock that counts through sleep |
| `__attribute__((format(printf)))` | GCC/Clang only; MSVC has no equivalent |
| `%zu` in `printf`, seven sites | MinGW's C runtime has no `z` length modifier |
| the POSIX unix-socket layer compiled into every target | Windows has no `sys/un.h` |

**The clock fix corrects the P1 plan, which was wrong.** The plan named
`QueryUnbiasedInterruptTime`. "Unbiased" means the count **excludes** time spent
asleep — precisely the property that must not hold. The code uses the *biased*
interrupt time, which includes suspend, matching `mach_continuous_time` and
`CLOCK_BOOTTIME`. Getting it backwards gives a lease that still looks fresh after
hours of sleep, so the exporter hands the drive back to a peer that has long since
given up.

`QueryInterruptTimePrecise` has no import library on MinGW, so it is resolved at
runtime with a `GetTickCount64` fallback (MSDN documents that as also including
suspend time). The fallback is ~15 ms granular; every deadline in the timeout
table is hundreds of ms or more, so that costs precision in the PING latency
figure and nothing else.

**The MSVC audit (2026-08-09) — read this before touching Windows again.**

MSVC cannot be run on this Mac, so the sources were audited against it instead:
seven passes over the 21 TUs in the `airusb-net` target, every finding then
adversarially re-checked against the real microsoft/STL sources.

**It found exactly one hard build break, and it was fixed.**
`crypto/Primitives.h` declared `std::string toHex(...)` while including
`<string_view>` but not `<string>`. libc++ and libstdc++ both leak `<string>`
elsewhere, which is why Clang and MinGW were silent for the life of the project.
Microsoft's does not: `<string_view>` reaches `<xstring>` only under the opt-in
`_LEGACY_CODE_ASSUMES_STRING_VIEW_INCLUDES_XSTRING`, and `std::string`'s alias
lives nowhere else. 7 of the 10 TUs reaching that header had no prior `<string>`,
and `crypto/Primitives.cpp` is the first source of the first library the
documented command builds — MSVC would have died in the first minute.

**What it refuted is the more useful half. Do not re-derive these:**

| hypothesis | verdict |
|---|---|
| `SO_REUSEADDR` on the listener is a Windows port-hijack switch | REFUTED — keyed on the *second* binder, and needs the same user, who can already read the identity seed. `SO_EXCLUSIVEADDRUSE` was applied, then reverted: it blocks rebinding for up to 120 s of TIME_WAIT after Ctrl-C, the wrong trade for a hand-driven tool |
| the pin store rejects CRLF and would silently unpair everyone | REFUTED — `writeFileAtomically` is `"wb"`, `readWholeFile` is `"rb"`; nothing writes CRLF, and Notepad has preserved LF since Win10 1809 |
| the listening `SOCKET` truncated to `int` breaks on Windows | REFUTED as a defect — kernel handles are capped near 2²⁶ by the handle table and MSDN documents the truncate/sign-extend round trip. Fixed anyway as type hygiene |
| `protocol/Messages.h` needs `<string_view>` | REFUTED — MSVC's `<string>` → `<xstring>` → `__msvc_string_view.hpp` supplies it |

Checked and clean: header order (only three TUs include `windows.h`, none before
`winsock2.h`), `WSAStartup` on both entry points, `BCryptGenRandom`'s NTSTATUS
handling, `ws2_32`/`bcrypt` reaching the link line, `C_STANDARD 99` degrading to
a no-op on MSVC, the `$<NOT:$<BOOL:${WIN32}>>` genex, zero bitfields, zero struct
overlays on the wire, and no order-of-evaluation hazards.

**Still not verified, and this is the point of the next task:**

- **No MSVC build has ever been run.** The audit is a prediction. CI settles it.
- **The `.exe` has never been executed.** Wine was considered and declined:
  Homebrew's `wine-stable` is deprecated, fails macOS Gatekeeper, and Homebrew
  disables it 2026-09-01. CI executes it on real Windows instead.
- The Windows clock's behaviour across sleep has never been observed.
- **The predicted `/W4` noise did not appear.** MSVC 19.51 emitted **zero**
  warnings. The C4324 on `Blake2s` was pre-empted by giving `_state` a
  `std::uint64_t` element type instead of an `alignas` specifier (same 512 bytes,
  same alignment, nothing to mute), and the expected C4018/C4389 signed-unsigned
  noise never materialised. `/wd4018 /wd4389` is therefore NOT needed.

**Residual risk the audit could not settle:** MSVC's optimizer is not modelled by
either available compiler, and `RecordLayer::flush` returns `Ok` on a would-block
short write without any caller re-flushing — unreachable at the current 16 KB
record ceiling and ≤2 KB transfers, but the first thing to suspect if record
sizes ever grow toward the 65519 ceiling.

**The Windows machine:** `192.168.0.225`, reachable, **RDP 3389 open, SSH closed**.
The assistant cannot run anything there; every Windows step must be handed to the
user as a copy-pasteable command.

---

### 3.4 The two-machine run — PASS, 2026-08-09

Roles reversed deliberately: **Windows was the exporter, the Mac the importer.**
The documented direction could not run, because Windows has no route back to the
Mac (§4.1); `airusb-net` is symmetric, so serving from Windows proves the same
protocol across the same two operating systems.

```
Windows GMKtec 192.168.0.109   MSVC 19.51 build, sha256 2fc7164a…
   fingerprint CH3XOC7N EMWISCDU 4RST5S5V VW5B3TEB
macOS M1       192.168.2.15    Clang build
   fingerprint 4DWO33UF HJZESZT6 NY67S5LR VDGIUCTJ

Each side reported the other's fingerprint exactly. SAS 927920 on BOTH consoles.

attempt 1  exit 3   trust on first use: pinned, dropped
attempt 2  exit 0   attached, manifest validated
           verdict=PASS  cbw=6 data=5 csw=6 stallRecoveries=0 shortReads=0
           SHORT_READ_FIDELITY ok — offered 1024, device sent 512, short read preserved
           RESULT=PASS
exporter:  served 18 transfer(s), 21 message(s)
```

Two details worth keeping:

- **`SHORT_READ_FIDELITY` passing across the network is the load-bearing one.**
  It says a device returning less than was asked for is reported as such after
  crossing two operating systems, a cipher and a record layer. Rounding that up
  is how a filesystem gets corrupted.
- **The exporter logged three spurious `peer connected` lines before the real
  handshake.** They were `nc -z` reachability probes from the Mac-side script. A
  bare TCP connect is *accepted* and enters the handshake loop, so probing the
  port perturbs the thing being measured — the exact hazard the CI job avoids by
  retrying the real client instead. Do not probe the port; just retry `connect`.

---

## 4. Verifying Windows again (all of this now passes)

### 4.0 Done — CI covers it

`.github/workflows/ci.yml` builds with MSVC, runs the suites natively on Windows,
and requires a full BOT exchange over a loopback socket; it also runs Linux under
ASan. All four jobs are green (§0). Push and it re-verifies itself. What follows
is only the part CI structurally cannot do.

### 4.1 The two-machine run — MEASURE THE NETWORK FIRST

**The addresses in older notes are stale, and this cost real time once already.**
Measured 2026-08-09:

| | |
|---|---|
| Mac, LAN (`en0`) | `192.168.2.15` |
| Mac, Tailscale | `100.120.39.113` |
| Windows box (`GMKtec`) | `192.168.0.109` — **a different LAN**, reached through `utun8`. NOT `.225`, which is some other machine that also answers on 445/3389 |
| Windows box on Tailscale? | **no** — every Windows peer in `tailscale status` is offline |
| open on it | 3389 (RDP), 445 (SMB). 22 closed |

The two machines are **not on the same LAN**. The Mac reaches the Windows box
only because `ts-464` (`100.67.175.141`) is a Tailscale subnet router advertising
`192.168.0.0/24`. Subnet routers SNAT by default, so:

- **Mac → Windows works** (ping, 3389 and 445 all verified).
- **Windows → Mac probably does not.** The Windows box has no route to
  `100.120.39.113` and none to `192.168.2.15`.

That matters because the documented direction — Mac serves, Windows connects —
runs the wrong way down that path. **Measure before assuming.** On the Windows
box:

```powershell
Test-NetConnection 100.120.39.113 -Port 7714 -InformationLevel Detailed
```

- **reachable** → the documented direction works. Mac runs `serve`, Windows runs
  `connect --host 100.120.39.113`.
- **not reachable** → **reverse the roles.** `airusb-net` is symmetric and
  `serve` is fully portable, so run `serve --port 7714` on Windows and `connect`
  from the Mac. It proves the same protocol, crypto and session layer across two
  operating systems and a real network; the only difference is which side drives
  the exporter FSM and which drives the importer. Note it in the result.
- To get the documented direction instead, install Tailscale on the Windows box —
  it then has a `100.x` address both ways.

`serve` binds `INADDR_ANY`, so it accepts on the LAN and Tailscale addresses
alike — verified on this Mac.

⚠️ **Do not test with the published preview binary.** The release at
<https://github.com/otti83/airusb-hub/releases/tag/v0.1.0-preview>
(`airusb-net.exe`, sha256
`a450f90f780d98282e781d2a994444e003dcf3f129fa59005eb4b332181b4ecc`) predates the
`<string>`, ATTACH-reject and handshake-timeout fixes — that build does not even
compile under MSVC. Take the `airusb-net-msvc-x64` artifact from a CI run, or
rebuild. **Re-cutting the release is worth doing now that CI is green.**

**On the Mac:**

```bash
cd "/Users/mba/Desktop/AirUSB Hub/airusb"
cmake -S . -B build && cmake --build build --target airusb-net
./build/airusb-net serve --port 7714
ipconfig getifaddr en0        # the IP to use below
```

Allow the incoming-connection prompt if the firewall asks.

**On Windows** (PowerShell, in the folder holding the exe):

```powershell
.\airusb-net.exe connect --host <MAC-IP> --port 7714 --probe
```

First run pairs and disconnects — that is trust-on-first-use. **Both sides print a
six-digit SAS; confirm they match.** Run it a second time to attach and read.
Success ends with `RESULT=PASS`.

### 4.2 Building it with MSVC by hand

CI does this for you now. Do it by hand only if CI is red and you need the full
compiler output, or if you want the Windows box's own toolchain in the loop.

*Developer PowerShell for VS 2022*, needs the "Desktop development with C++"
workload:

```powershell
git clone https://github.com/otti83/airusb-hub
cd airusb-hub\airusb
cmake -S . -B build
cmake --build build --config Release --target airusb-net
.\build\Release\airusb-net.exe connect --host <MAC-IP> --port 7714 --probe
```

Expect MSVC to find things MinGW did not. Paste whatever it says.

### 4.3 How to read the result

| outcome | meaning |
|---|---|
| `RESULT=PASS` | the protocol, crypto and session layer work on Windows. Next: the UdeCx driver. |
| handshake fails | the crypto or the preamble differs on Windows — compare the SAS on both sides first |
| MSVC compile errors | portability gaps MinGW cannot see; fix, then re-verify all three platforms |
| **SAS mismatch** | **stop.** That is either a man in the middle or a real protocol bug. |

---

## 5. What is left

### 5.1 THE NEXT TASK — the UdeCx driver

1. **UdeCx driver** — `UdecxHostBackend` + `airusb.sys`, KMDF, design in
   `P1_IMPLEMENTATION_PLAN.md` §4.6. Windows' gate is self-service:
   `bcdedit /set testsigning on` for development; EV certificate + Microsoft
   attestation for distribution — a paid process, not a discretionary approval.
   **Nothing about the Windows path waits on anyone's decision.**
2. **Linux importer** — vhci-hcd shim (§4.7). Cheapest of the three.
3. **P2.9 `CiHostBackend`** — blocked on Apple only.
4. ~~**The exporter's write path**~~ — **DONE, 2026-08-09.** It was going to be
   "tested for free" by a real importer mounting a filesystem, which is a bad way
   to find out: the free test is performed on somebody's data. `diag/WriteProbe`
   now exercises it deliberately, and `airusb-net connect --write-test` runs it
   over the network in CI on every commit.

   Measured over a loopback session: `outTransfers=4 largestOut=16384
   bytesWritten=35328 mismatched=0 outBoundariesIntact=yes restored=yes`. The
   16384-byte run matters — it exceeds the record payload ceiling, so a single
   logical OUT transfer has to be fragmented and reassembled, and nothing had ever
   made the record layer do that in this direction. It came back byte-identical.

   **It is a SEPARATE class from BotProbe on purpose.** BotProbe's header promises
   without qualification that pointing it at a drive cannot damage its contents.
   An opt-in flag would have turned an absolute guarantee into a conditional one,
   which is the kind a tired person misreads with a drive attached. The write
   instrument is a different type, and the only entry point is named
   `runDestructiveWriteTest`.
5. **`PAIR_*` messages** — the opcodes are reserved in `Wire.h` (0x10/0x11/0x12)
   and the trust gate already refuses everything else to an Unpaired peer, but no
   handler exists. **The rate limiter half is now DONE**: `session/PairingGate`,
   40 checks.

   Two design points worth not re-deriving. **The counter is global, not
   per-peer** — a peer identity is an Ed25519 key the peer generates for itself,
   so an attacker mints a fresh one per attempt and per-peer counting sees a first
   offence every time. It would look like protection and be none. **And it runs on
   the continuous clock**, so closing a laptop lid does not clear a lockout; a
   clock that appears to move backwards fails closed for the same reason.

   `serialize`/`deserialize` exist so a daemon can persist it beside the pin
   store. A gate held only in memory is reset by anything that can restart the
   daemon, and that is the reset an attacker would look for.
6. **Manifest segmentation.** A manifest larger than one record needs it; the
   control plane has none. An 8-configuration device with a full string table could
   reach it. The attach currently fails with a clear status rather than truncating.

---

## 6. Environment (verified, not assumed)

| Property | Value |
|---|---|
| macOS | 26.5.1 (25F80), Apple M1, arm64 |
| Xcode / SDK | 26.5 (17F42) / macOS 26.5 |
| SIP | **enabled** |
| Secure Boot | **Reduced**. Full Security NOT tested — re-verify before release |
| Signing identities | `Apple Development … (WT36SR3Q23)`, `Apple Distribution … (GZUV3UMV3B)` |
| Test USB device | `058f:6387` Generic Mass Storage, 31.5 GB exFAT, **SuperSpeed**, `disk22` |
| Linux VM | Lima `kbuild`, Debian 12 aarch64, GCC 12.2; Mac host at 192.168.5.2 |
| Windows box | `GMKtec`, **192.168.0.109**, RDP + SMB open, **SSH closed**, no Tailscale. Different LAN from the Mac — reached only via the `ts-464` subnet router. `.225` is a DIFFERENT machine |
| Cross-compiler | `x86_64-w64-mingw32-g++` (Homebrew mingw-w64) |
| GitHub | `gh` authenticated as `otti83` |

### Tooling constraints learned the hard way

- **`sudo` is blocked for the assistant.** Every root experiment is handed to the
  user as a copy-pasteable command.
- **AddressSanitizer hangs on this host** — any `-fsanitize=address` binary hangs
  before `main()`, including a hello-world with no libFuzzer. Bisected: `fuzzer`
  works, `fuzzer,undefined` works, `address` hangs. Fuzzing defaults to
  `fuzzer,undefined`; `AIRUSB_FUZZ_ASAN=1` opts back in. **Linux CI now enables
  ASan** (`.github/workflows/ci.yml`, job `linux-asan`) — UBSan does not catch
  heap out-of-bounds, which is exactly what R2/R5/R6 exist to stop. That job has
  never run; it is the likeliest of the four to go red first, and that would be
  a finding rather than a broken workflow.
- **`timeout(1)` does not exist on macOS.**
- **`.gitignore` has no trailing comments.** `path/  # note` matches nothing.
- Objective-C files compile as C, not C++: no declaration-in-`if`.

---

## 7. Code map

```
airusb/
  core/        Status, UsbTypes, Clock, Watchdog (the ONE clock), DeviceManifest,
               Ep0Arbiter, RequestTable, CreditController, IUsbDevicePort,
               Platform (the only place three OSes differ)
  crypto/      Primitives (the ONLY caller of third_party), Identity
  protocol/    Wire.h, Codec, Validate (R1–R12), Messages, ManifestCodec, Noise
  transport/   RecordLayer, FrameScheduler, TcpTransport, FaultTransport,
               NoiseCipher
  session/     SecureSession, PeerStore, ExporterSession, ImporterClient,
               RemoteDevicePort
  diag/        BotProbe — read-only BOT prober. A test instrument, NOT the data
               path; nothing in core/protocol/transport includes it
  tools/       airusb_net_main — serve/connect over a real socket
  platform/macos/  StatusMapMacos, MacUsbCommon, DiskGuard, AgentUsbIo,
               HostDeviceExporter, airusb_exportd_main, airusb_agent_main,
               AgentProtocol (portable) + AgentLink (POSIX only)
  third_party/ Monocypher 4.0.3, BLAKE2s reference — pinned, checksummed
  scripts/     cross-build-windows.sh
apple/         SwiftUI app (device list, detail, eject) + the entitlement probe
poc/           p0-probe (entitlement matrix), p1-capture-test
.github/workflows/ci.yml
               Windows/MSVC + native ctest + a real loopback BOT exchange;
               Linux under ASan; macOS; the MinGW cross-build. Committed,
               NEVER RUN — nothing has been pushed yet.
```

Layer graph, one direction only:
`core → crypto → protocol → transport → session`

### Build and test

```bash
cd "/Users/mba/Desktop/AirUSB Hub/airusb"
cmake -S . -B build && cmake --build build && (cd build && ctest --output-on-failure)
./tests/fuzz/build_and_run.sh 300000
./scripts/cross-build-windows.sh          # produces build-win/airusb-net.exe

# The cross-build script passes only -Wall -Wextra. To check the Windows target
# under the flag set CMake actually configures — which is how the last warning
# in it was found — compile each TU with the full set:
for f in tools/airusb_net_main.cpp tests/fakes/ScriptedDevice.cpp \
         core/*.cpp crypto/*.cpp protocol/*.cpp transport/*.cpp \
         session/*.cpp diag/*.cpp; do
  x86_64-w64-mingw32-g++ -std=c++20 -O2 -I. -c -Wall -Wextra -Wpedantic \
    -Wconversion -Wsign-conversion -Wshadow "$f" -o /dev/null || break
done

# hardware, needs the user (sudo is blocked for the assistant):
sudo ./platform/macos/scripts/p28_run.sh 058f:6387
```

---

## 8. Decisions and findings not to re-derive

### The exporter is two processes — measured, binding

| operation | needs root | needs console session |
|---|---|---|
| DiskArbitration whole-disk unmount | **yes** | no |
| `IOUSBHostDevice` + `DeviceCapture` | **yes** | **no** |
| `IOUSBHostInterface` open | **no** | **yes** |

The kernel names the gate:
`(Sandbox) System Policy: <proc>(pid) deny(1) iokit-open-service IOUSBHostInterface`.
A LaunchDaemon (uid 0, ppid 1, system session) is denied; a LaunchAgent (uid 501,
ppid 1, Aqua session) succeeds. Same parent, no tty either way, **less** privilege,
opposite result. Session membership is the entire variable. Full evidence in
`P1_CAPTURE_VERIFICATION.md`.

### Apple's error path RAISES instead of returning

Observed twice on real hardware:

```
-[IOUSBHostObject openWithOptions:error:]  →  NSInvalidArgumentException objects[0]
-[IOUSBHostObject descriptorWithType:…]    →  the same exception, during the P2.8 gate
```

So it is a property of the framework's error construction, **not of one selector**.
Wrap every call into IOUSBHost in `@try`/`@catch`, not just the inits, and do not
narrow the wrapping to observed sites. Where the real `IOReturn` matters, call
`IOServiceOpen` directly — the framework destroys its own `NSError` on that path.

### `0xE00002C9` is ambiguous

It is both the FB16524420 signature **and** what you get when a driver simply still
owns the interface. `AgentUsbIo` probes the service directly on failure and says
which of the two it hit.

### Refuted — do not retry

| hypothesis | verdict |
|---|---|
| the binary living in TCC-protected `~/Desktop` causes the denial | REFUTED — staging to `/usr/local/libexec` changes nothing |
| `SessionCreate` in the plist fixes it | REFUTED |
| `IOServiceAuthorize()` is the mechanism | REFUTED — `0xE00002C6` either way |
| it is a privilege (root) problem | REFUTED — a non-root uid 501 process opens fine |
| libusb / legacy IOUSBLib avoids it | REFUTED — same `IOServiceOpen`, same nub |
| the test device is High Speed | REFUTED — `USBSpeed = 4`, `UsbLinkSpeed = 5e9` |

**The speed trap, because it bites repeatedly:** the IORegistry exposes two speed
properties with *different* enumerations, in which the integer `3` means High in
one and Super in the other. Read `USBSpeed`, cross-check `UsbLinkSpeed`.
`DeviceManifest::validate()` rejects a SuperSpeed manifest carrying a High Speed
`bMaxPacketSize0`, so this is a test failure rather than a silent USB-2 downgrade.

### Protocol rules worth not re-litigating

- **`total_len` is the DATA payload, not the body.** Setting it to `body_len` makes
  R4's exactness rule reject every SUBMIT and COMPLETE. This was a real bug, twice.
- **Descriptor bytes travel verbatim.** Never re-serialized, reordered or
  normalised — the moment this layer rewrites a descriptor, the importer presents a
  device that does not exist.
- **A second ATTACH gets BUSY and is never queued** (§7.7).
- **A stale attach id is dropped SILENTLY and is not fatal** (R12). Escalating it
  turns every legitimate reset into a session teardown.
- **`clearHalt` must wait for CTRL_ACK.** Fire-and-forget leaves the verb's reply in
  the stream for the next transfer to read as its own COMPLETE — and a stall
  recovery is always followed immediately by a transfer, so that misread is the
  common case rather than a rare one.
- **The clock must be continuous across sleep.** `mach_continuous_time`,
  `CLOCK_BOOTTIME`, biased Windows interrupt time. Never `mach_absolute_time`,
  `CLOCK_MONOTONIC`, or `QueryUnbiasedInterruptTime`.
- **HMAC, not BLAKE2s's native keyed mode.** Substituting it yields a protocol that
  round-trips against itself perfectly and interoperates with nothing.
- **Two spec amendments, both recorded in the plan:** the fingerprint and the
  manifest hash use BLAKE2s rather than SHA-256 (a fourth hash function for an
  internal value is not worth the attack surface), and the plan's reference to
  libsodium is corrected to Monocypher, which is what the code vendors.

### Open questions

| # | question | state |
|---|---|---|
| OQ-1 | is one `NormalTransfer` one logical URB? | **ANSWERED for the exporter: yes.** Measured three ways on hardware. Still open for the importer, where the kernel assembles the TD chain. |
| OQ-5 | will Apple grant the entitlement to an Individual team? | **filed, FB24214361, awaiting** |
| OQ-6 | are the credit/pipeline constants in the safe direction? | unresolved; instrument in P2.9 |
| OQ-7 | no `API_AVAILABLE` on the IOUSBHostCI headers, so the ABI could shift | pin a tested range; treat any exception at init as a hard refusal |
| new | does the exporter's **write** path work? | **ANSWERED: yes** — `diag/WriteProbe`, byte-exact to 16 KB over the network, in CI. Sustained load is still unmeasured |
| new | does the Windows client actually run? | **ANSWERED: yes.** MSVC 19.51, 13/13 suites, RESULT=PASS over a real socket, in CI |
| new | does MSVC accept the sources? | **ANSWERED: yes**, after one missing `<string>` was fixed. Zero warnings at /W4 /permissive- |
| new | does anything break under ASan? | **ANSWERED: no.** First ASan run ever, Linux, 13/13 + RESULT=PASS, no findings |
| new | two machines, real network, one Windows | **ANSWERED: PASS** (§3.4), SAS confirmed on both consoles |
| new | does the console mangle user-facing text on a Japanese Windows? | **it did** — CP932 read the em dash as `窶・` in the SAS line. Fixed with `platform::ConsoleUtf8` |
