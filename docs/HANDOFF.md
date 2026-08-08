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
| Windows client | **cross-compiles**; never built with MSVC, never executed |
| Receiving on a Mac | **blocked on Apple** — FB24214361, see §2 |
| Receiving on Windows / Linux | driver half not written |

```
13 test suites / 0 failures
3 fuzz targets / 0 crashes / 0 UB findings
Zero warnings: macOS (Clang, full flag set), Linux (GCC 12, -Wall -Wextra)
~21,500 lines ours + 10 vendored files
```

### THE NEXT TASK: verify on Windows

Everything needed is built and published. §4 is the procedure. It is the one
claim in this project that is currently *assumed* rather than measured.

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
| Windows client, cross-compiled to a PE | **builds**; never run |
| Windows client built with MSVC | **never attempted** |

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

**Not verified, and this is the point of the next task:**

- **No MSVC build has ever been run.** MinGW proves headers, APIs and linkage.
  MSVC is stricter under `/permissive-`; `/utf-8` is set because the sources carry
  em dashes and typographic quotes inside user-facing string literals, which MSVC
  would otherwise read in the active code page and mangle.
- **The `.exe` has never been executed.** Wine is not installed on this Mac and
  the Windows box has no SSH.
- The Windows clock's behaviour across sleep has never been observed.

**The Windows machine:** `192.168.0.225`, reachable, **RDP 3389 open, SSH closed**.
The assistant cannot run anything there; every Windows step must be handed to the
user as a copy-pasteable command.

---

## 4. NEXT TASK — verify on Windows

A prebuilt binary is published so Visual Studio is not required for the first run:
<https://github.com/otti83/airusb-hub/releases/tag/v0.1.0-preview>
`airusb-net.exe`, sha256
`a450f90f780d98282e781d2a994444e003dcf3f129fa59005eb4b332181b4ecc`

### 4.1 Run it

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

### 4.2 Then build it with MSVC

This has never been done and is the real acceptance test.

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

## 5. After Windows verification

1. **UdeCx driver** — `UdecxHostBackend` + `airusb.sys`, KMDF, design in
   `P1_IMPLEMENTATION_PLAN.md` §4.6. Windows' gate is self-service:
   `bcdedit /set testsigning on` for development; EV certificate + Microsoft
   attestation for distribution — a paid process, not a discretionary approval.
   **Nothing about the Windows path waits on anyone's decision.**
2. **Linux importer** — vhci-hcd shim (§4.7). Cheapest of the three.
3. **P2.9 `CiHostBackend`** — blocked on Apple only.
4. **The exporter's write path** — P2.8's probe is read-only, so `bulkOut` has only
   ever carried 31-byte CBWs. A real importer mounting a filesystem tests it for
   free.
5. **`PAIR_*` messages and the pairing rate limiter.** The SAS's one-in-a-million
   bound assumes attempts cannot be retried; nothing enforces that yet.
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
| Windows box | 192.168.0.225, RDP open, **SSH closed** |
| Cross-compiler | `x86_64-w64-mingw32-g++` (Homebrew mingw-w64) |
| GitHub | `gh` authenticated as `otti83` |

### Tooling constraints learned the hard way

- **`sudo` is blocked for the assistant.** Every root experiment is handed to the
  user as a copy-pasteable command.
- **AddressSanitizer hangs on this host** — any `-fsanitize=address` binary hangs
  before `main()`, including a hello-world with no libFuzzer. Bisected: `fuzzer`
  works, `fuzzer,undefined` works, `address` hangs. Fuzzing defaults to
  `fuzzer,undefined`; `AIRUSB_FUZZ_ASAN=1` opts back in. **Linux CI must enable
  ASan** — UBSan does not catch heap out-of-bounds, which is exactly what R2/R5/R6
  exist to stop.
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
```

Layer graph, one direction only:
`core → crypto → protocol → transport → session`

### Build and test

```bash
cd "/Users/mba/Desktop/AirUSB Hub/airusb"
cmake -S . -B build && cmake --build build && (cd build && ctest --output-on-failure)
./tests/fuzz/build_and_run.sh 300000
./scripts/cross-build-windows.sh          # produces build-win/airusb-net.exe

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
| new | does the exporter's **write** path work under load? | **untested** — the probe is read-only |
| new | does the Windows client actually run? | **THE NEXT TASK, §4** |
