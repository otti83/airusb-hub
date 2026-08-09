# AirUSB Hub — Session Handoff

**Written:** 2026-08-08 · **Last updated:** 2026-08-09, after **Windows
verification and the GUI** — both of the things the previous handoff named as the
next session's work are done (§0). The product now has an interface, it is the
same interface on three operating systems, and Windows is verified against the
code that is actually in the tree rather than against the code that was there
before segmentation landed.
**Purpose:** resume this project in a fresh session with no access to the previous
conversation. Everything load-bearing is here or in the documents it points to.
**Repo:** `/Users/mba/Desktop/AirUSB Hub` — public at
<https://github.com/otti83/airusb-hub> (Apache-2.0, branch `main`, `gh`
authenticated as `otti83`). Everything below is committed AND pushed to
`origin/main` (this session's L5→L6 work through the real-hardware pass; last commit
records this line).

---

## 0. Where things stand, in one screen

| | state |
|---|---|
| Sharing a USB device from a Mac | **works on real hardware** (058f:6387 SuperSpeed) |
| Encryption + authentication | **done** — Noise_XX / Noise_IK, official vectors matched |
| Session layer, L1 protocol, manifest | **done** |
| Networking | **done** — real TCP; macOS↔macOS, macOS↔Linux, **Windows↔macOS on two machines** |
| Windows client | **done, and re-verified against the CURRENT tree** — MSVC 19.51, 24/24 native, full BOT exchange **with segmentation actually firing** (§3.4) |
| **The product's window** | **done, and proven on two real machines** — `airusb-hubd` on the GMKtec and this Mac paired with a human comparing the six digits, then read a device; §3.9, `GUI.md` |
| **Receiving on Linux** | **WORKS on real hardware, over the network** — a real 058f:6387 drive captured on the Mac (`airusb-exportd --serve`) mounted on the Linux kernel via `airusb-vhci --host`, read-only, real files read; clean teardown (full L6 + L8 PASS, `LINUX_IMPORTER_PLAN.md` §7) |
| Receiving on a Mac | **blocked on Apple** — FB24214361, §2 |
| Receiving on Windows | UdeCx driver not written. **Not blocked by anyone** |

```
24 test suites / 0 failures  (was 22; +test_control 154 checks, +test_hub_e2e 62)
3 fuzz targets / 0 crashes / 0 UB findings
Zero warnings: macOS (Clang, full set), Linux (GCC, ASan+UBSan),
               Windows (MinGW, full set), Windows (MSVC 19.51, /W4 /permissive-)
~32,000 lines ours + 10 vendored files
```

### What the previous handoff asked for, and what came of it

Both items are done. Neither needed Apple.

**1. Windows verification — DONE, and it found the thing it was meant to find.**
The instruction was to re-run Windows with "a transfer big enough to actually
segment (>16 640 B)". It turned out nothing had *ever* segmented end to end, on
any platform: the write probe's largest run was 16 384 bytes, which fits inside
the 16 640-byte default record once you subtract the header, body and AEAD tag —
and the unit test asserting that this run "is big enough to force record
fragmentation" was asserting the opposite of what it said. The largest run is now
131 072 bytes, chosen against Noise's 65 519-byte plaintext ceiling so it segments
at *any* legal record size. `RemoteDevicePort` counts what happened, `airusb-net`
prints it and FAILS the run if a 128 KiB transfer crossed unsplit, and both CI
jobs assert `fired=yes`. Windows/MSVC now reports
`SEGMENTATION out=2 in=2 contRecords=14 maxSegment=16552 largestOut=131072
fired=yes` alongside `RESULT=PASS`. §3.4.

**2. The GUI — DONE.** The open question was "SwiftUI for macOS; what for Windows
and Linux". The answer is one loopback HTTP control plane and one page compiled
into the binary, because the browser is the only toolkit already present on all
three machines *and* the only one this project can test on all three. No
dependency was added. It shares, connects, pairs with the six-digit check,
attaches and verifies — on macOS, Linux and Windows. Design, security model and
the two-machine procedure: **`GUI.md`**. Evidence: §3.9.

### THE NEXT SESSION

In order, and none of it waits on Apple:

1. **The Windows importer, UdeCx (§4.4).** With real hardware through the window
   now done (§3.9), this is the largest remaining piece and the only one that
   would add a new operating system to the "really enumerates it" column. It is
   self-service: `bcdedit /set testsigning on` for development.

   (macOS ↔ Windows with the hub is **done** — §3.9. The binary question that
   blocked it is also settled: `scripts/cross-build-windows.sh` now produces
   `airusb-hubd.exe`, and both CI jobs publish it as
   `airusb-windows-msvc-x64` / `airusb-windows-mingw-x64`. Before that it was
   produced by nothing at all, and the procedure told the user to run a file
   that did not exist. **No release asset has been published**; if a plain
   no-login download URL would be easier, that is a deliberate publishing step
   and needs asking for.)
2. **The hub against real hardware.** `airusb-exportd --serve` already speaks this
   exact protocol, so pointing the hub's importer at a real captured drive needs
   no new code — only `sudo` on the Mac, which the assistant does not have. One
   command each side; see §3.9.
3. **Windows × Linux (§4.3).** Both halves exist. The routing between the Windows
   box and the Lima guest has still never been measured.
4. **The Windows importer, UdeCx (§4.4).** The only remaining large piece, and
   self-service.

The **Windows box**: `GMKtec 192.168.0.109`, RDP + SMB open, **SSH closed**, on a
different LAN from the Mac (reached via the `ts-464` subnet router). The assistant
cannot run anything there — every Windows step is handed to the user as a
copy-pasteable command (§5, `GUI.md`).

### The Linux importer is DONE — full L6 + L8 on real hardware (2026-08-09)

This session finished the whole Linux importer, end to end: a real 058f:6387 drive
captured on the Mac (`airusb-exportd --serve`, new) → encrypted network session →
`airusb-vhci --host` → the Linux kernel enumerated it and mounted its exFAT
filesystem read-only; teardown returned the drive to the Mac, data untouched.
Killing the exporter mid-write gave an I/O error, not an unkillable D-state (L8).
The three correctness cores (segmentation L5; async `ImporterDataPlane`; non-blocking
`VhciNetBridge`) were built hosted-first, GPT-5.6-reviewed to PASS across three
rounds, then proven on a real kernel. Details + how-to-reproduce: §3.7, §4.1, §7;
gate evidence in `LINUX_IMPORTER_PLAN.md` §7 (L5–L8). **Reproduce the whole thing
from the VM in ~30 s** with the two binaries already built at `/tmp/vhci-build` in
the Lima `airusb` VM (see §3.3 / §4.1).

### Apple entitlement — LOWEST PRIORITY now, RECORD ONLY (human-only action)

**Do not prioritize this. Apple will not grant it for a while, and everything that
does not depend on it is either done or is the next-session work above.** It is
kept here only so it is not lost:

- The macOS *importer* — enumerating a remote device as a real USB device ON A MAC —
  is the ONLY thing blocked by Apple: entitlement
  `com.apple.developer.usb.host-controller-interface`, **FB24214361**, filed
  2026-08-08, Individual team `GZUV3UMV3B`, no response.
- **The one action only a human can take:** post `FB24214361` in
  <https://developer.apple.com/forums/thread/802495> (ready-to-paste text in
  `ENTITLEMENT_REQUEST.md`). Filing alone sits in the ordinary queue; posting the
  number routes it to the approver (DTS said so in that thread).
- **Do NOT send anyone hunting for a portal checkbox — there is not one** (measured,
  §2.2). The full evidence, the six-variant signing matrix, and the "if Apple says
  no" options are all in §2; none of it needs re-deriving.

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

---

## 2. The Apple entitlement — the only thing blocking the macOS importer

> **PRIORITY: LOWEST. This is record-only.** Apple will not grant this for a while,
> and it blocks ONLY the macOS *importer* — nothing the next session needs. The one
> action (a human posting FB24214361, §0) can happen any time; do not build around
> it or wait on it. Everything below is preserved so the reasoning is not re-derived.

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

### 2.6 What is NOT blocked by Apple — read this before deciding to wait

Apple gates exactly one thing: **macOS as the importer**. It gates nothing else,
and the project has since proven that the rest of the stack works without it.

| | needs Apple? |
|---|---|
| macOS as the **exporter**, on real hardware | no — done, P2.8 |
| The protocol, crypto, session layer, networking | no — done on three OSes |
| Windows client, MSVC | no — done |
| **Linux as the importer** | **no — done** (§3.6) |
| Windows as the importer (UdeCx) | no — self-service test signing |
| macOS as the **importer** | **yes, and only this** |

An entitlement that never arrives costs this project the macOS importer. It does
not cost it a working product: a Mac can already share a drive, and a Linux box
can already receive one as a real USB device. §4 is a queue of work that exists
regardless of Apple's answer, and it is long enough to be worth starting now.

### 2.7 If Apple says no

Nothing needs re-deriving; the options were already established.

1. **Ship without the macOS importer.** macOS exports, Linux and Windows import.
   That is a coherent product and most of the value.
2. **Re-file as an Organization.** `teamType = Individual` is the honest statement
   of the risk (§2.3): every confirmed holder found during Phase 0 is an
   Organization. Publishing the repository was the cheapest available mitigation
   and has been done.
3. **Do not look for a technical workaround.** §2.4's matrix is the measurement
   that closes this off: a *fabricated* `com.apple.developer.*` entitlement is
   SIGKILLed by AMFI exactly as the real one is, so this is a generic restricted-
   prefix rule and not a targeted block with a seam in it. The Natural Path Only
   rule forbids the alternatives anyway.

---

## 3. Cross-device status — what has actually been run

### 3.1 The matrix, and which cells need Apple

Rows are the machine holding the device (**exporter**); columns are the machine
that wants to use it (**importer**). "Importer works" means the OS enumerates it
as a real USB device and binds its own drivers, not merely that bytes moved.

| exporter ↓ / importer → | macOS | Linux | Windows |
|---|---|---|---|
| **macOS** (real hardware) | protocol PASS (loopback) · importer **BLOCKED ON APPLE** | protocol PASS · **importer exists** → §4.1 is finishing this | protocol PASS (two machines) · importer needs UdeCx |
| **Linux** | not written | — | not written |
| **Windows** (simulated device) | **PASS, two machines, 2026-08-09** (§3.6) | **importer exists on both sides — §4.3** | — |

Read the matrix this way:

* **Only one cell is blocked by Apple**: macOS as the *importer*. Every other cell
  is work, not permission.
* **macOS × Linux is the valuable one** and is the next task: a real drive, real
  hardware, real network, and an OS that really enumerates it.
* **Windows × Linux is the cell that needs no Mac at all** — both halves already
  exist and are proven separately. See §4.3 for why it is scheduled *after* the
  macOS pairs rather than before.

### 3.2 What "PASS" means in each row

| run | date | evidence |
|---|---|---|
| macOS exporter ↔ macOS client, loopback | earlier | `RESULT=PASS`, full BOT exchange |
| macOS exporter ↔ Linux client, real network | earlier | `RESULT=PASS` |
| Windows exporter ↔ macOS importer, **two machines, different subnets** | 2026-08-09 | §3.5 — SAS `927920` matched on both consoles |
| Windows, MSVC 19.51, loopback | 2026-08-09 | 13/13 native + `verdict=PASS` + write probe |
| Linux, ASan+UBSan, loopback | 2026-08-09 | 13/13 + `RESULT=PASS`, no sanitizer findings |
| **Linux kernel enumerated a device** | 2026-08-09 | §3.6 — `Attached SCSI removable disk`, then `mkfs`/`mount`/write/read-back |

---

### 3.3 Linux — how to reproduce, on the VM that matters

Use Lima **`airusb`** (Ubuntu 24.04 aarch64). `kbuild` is another project's and
cannot do vhci-hcd at all — its Debian `cloud` kernel is built with
`CONFIG_USB_SUPPORT` unset, so no package can ever supply the module.

```bash
limactl start airusb
limactl shell airusb bash -lc 'sudo modprobe vhci-hcd && cat /sys/devices/platform/vhci_hcd.0/status | head -3'
```

If `modinfo -n vhci_hcd` comes up empty on a fresh VM:
`sudo apt-get install -y linux-modules-extra-$(uname -r)` — **no kernel change and
no reboot**, because the Lima cloud image already runs the `generic` kernel via
`linux-image-virtual` and only the `-extra` module set is missing. On Ubuntu 26.04
it is in the base package and even that is unnecessary. **Resolve it at runtime
with `modinfo -n vhci_hcd`; do not encode either case as a rule.**

The VM has `build-essential` and `cmake`. `/Users/mba` is mounted read-only, so
build into `/tmp`:

```bash
limactl shell airusb bash -lc '
SRC="/Users/mba/Desktop/AirUSB Hub/airusb"; mkdir -p /tmp/vhci && cd /tmp/vhci
g++ -std=c++20 -O1 -I"$SRC" -Wall -Wextra \
  "$SRC"/platform/linux/airusb_vhci_main.cpp "$SRC"/platform/linux/UsbipCodec.cpp \
  "$SRC"/platform/linux/LinuxUsb.cpp "$SRC"/platform/linux/VhciBridge.cpp \
  "$SRC"/tests/fakes/ScriptedDevice.cpp \
  "$SRC"/core/*.cpp "$SRC"/crypto/*.cpp "$SRC"/protocol/*.cpp "$SRC"/transport/*.cpp \
  -x c "$SRC"/third_party/monocypher/*.c "$SRC"/third_party/blake2s/blake2s-ref.c \
  -o airusb-vhci'
```

Then, as root inside the VM, `./airusb-vhci` — and in another shell `dmesg | tail`,
`lsusb`, `lsblk`. §3.6 is what you should see.

The portable client still builds the same way it always did (swap
`airusb_vhci_main.cpp` + `platform/linux/*` for `tools/airusb_net_main.cpp`), and
that direct `g++` line doubles as proof that nothing depends on cmake.

### 3.4 Windows — exactly what is and is not verified

> **STATUS (2026-08-09): RE-VERIFIED against the current tree. The stale warning
> that used to be here is discharged.** MSVC 19.51 builds every portable target,
> runs 24/24 suites natively, completes a loopback BOT exchange read AND write,
> and — the part that was missing — **segments a 128 KiB transfer while doing it**:
>
> ```
> 100% tests passed out of 24
> verdict=PASS  outTransfers=5 largestOut=131072 bytesWritten=281088 mismatched=0
> SEGMENTATION out=2 in=2 contRecords=14 maxSegment=16552 largestOut=131072 fired=yes
> RESULT=PASS
> PASS: a USB Mass Storage exchange completed on Windows, segmented.
> ```
>
> And separately, the window: two `airusb-hubd` processes on the Windows runner
> pair with each other through the control API — all three guard refusals
> provoked, exporter-first (the order that tears the session down mid-decision),
> reconnect with a new SAS matching on both sides, attach, `probe verdict=PASS`.
>
> **What made the difference is not that the job was re-run.** Nothing had ever
> segmented end to end: the largest transfer any run had carried was 16 384 bytes,
> which fits in one 16 640-byte record, and the unit test claiming otherwise was
> wrong. Re-running the old job would have produced the old green tick. See §0.
>
> Still not verified on Windows: the two-machine run, and the clock's behaviour
> across sleep. Both need the physical box (§5).

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

**Residual risk the audit could not settle — the flush half HAPPENED, and is
fixed (2026-08-09). Read this one; it is the best evidence in the file that
writing a risk down is worth the minute it costs.** The paragraph used to say:

> `RecordLayer::flush` returns `Ok` on a would-block short write without any
> caller re-flushing — unreachable at the current 16 KB record ceiling and
> ≤2 KB transfers, but the first thing to suspect if record sizes ever grow
> toward the 65519 ceiling.

This session raised the largest transfer to 128 KiB and then ran it between two
machines ~28 ms apart, which is exactly the named condition. It failed on the
first attempt. The exporter sends eight records, the socket fills, `flush()`
buffers the remainder and reports `Ok` — correct, a short write is not an error
— and every record except the last is pushed along by the next `sendRecord()`.
The last one has nothing behind it, and `pump()` only ever read. Evidence, from
the failing run itself: `SEGMENTATION out=0 in=1 contRecords=3` — three
continuations out of eight, then silence.

Fixed: `ExporterSession::pump()` drains before it reads, and the two synchronous
senders (`RemoteDevicePort::submit`, `ImporterClient::call`) flush to empty
before blocking for a reply — waiting for an answer to a request still in your
own send buffer is a deadlock you hold both ends of. `pendingTxBytes()` existed
the whole time and had exactly one caller outside a test (the Linux vhci loop),
which is why only that path was safe.

**Why no test caught it, and what changed:** `MemoryPipe` was unbounded, so
`flush()` always completed and the buffered tail could not exist.
`MemoryPipe::setCapacity()` now makes a pipe fill like a socket, and
`test_l5_segmentation` drives a 120 KiB reply through 8 KiB of capacity.
Verified to bite: 207 checks / 3 failures without the fix, 0 with.

**Still unsettled:** MSVC's optimizer is not modelled by either available
compiler.

**The Windows machine:** `192.168.0.225`, reachable, **RDP 3389 open, SSH closed**.
The assistant cannot run anything there; every Windows step must be handed to the
user as a copy-pasteable command.

---

### 3.5 The two-machine run — PASS, 2026-08-09

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

### 3.6 Linux enumerated it — 2026-08-09

The thing this project exists to do, done for the first time on any platform.
`platform/linux/airusb-vhci` attaches a socketpair to vhci-hcd and runs
`VhciBridge` against a `ScriptedDevice`. The kernel's own dmesg:

```
vhci_hcd vhci_hcd.0: Device attached
usb 4-1: new SuperSpeed USB device number 6 using vhci_hcd
usb 4-1: New USB device found, idVendor=058f, idProduct=6387, bcdDevice= 0.02
usb 4-1: Product: AirUSB
usb-storage 4-1:1.0: USB Mass Storage device detected
scsi 0:0:0:0: Direct-Access     AirUSB   Scripted Device  0001 PQ: 0 ANSI: 6
sd 0:0:0:0: [sda] 61440 512-byte logical blocks: (31.5 MB/30.0 MiB)
sd 0:0:0:0: [sda] Attached SCSI removable disk
```

`lsusb` resolves it out of the USB ID database — `058f:6387 Alcor Micro Corp.
Flash Drive` — which is the verbatim rule proving itself: the VID and PID the
kernel read are the manifest's bytes, unaltered. `lsblk` shows `sda`, 30M.

Then a real filesystem, which is L7 arriving early:

```
dd if=/dev/sda ... 32768 bytes copied, 11.5 MB/s
mkfs.vfat /dev/sda        OK
mount /dev/sda /mnt/air   OK
echo ... > hello.txt      OK
umount                    OK      <- the cache flush completed: WRITE(10) and the
                                     CSW path both work through the bridge
remount + cat             "hello from a remote USB device"
```

**The defect this gate found.** The first version of the tool took `--speed` from
the command line. Attaching the SuperSpeed manifest at high speed produced:

```
usb 3-1: Invalid ep0 maxpacket: 9
usb usb3-port1: unable to enumerate USB device
```

`bMaxPacketSize0` is a power-of-two EXPONENT at SuperSpeed (9 = 512) and a
literal byte count at high speed, where only 8/16/32/64 are legal. The
descriptors were right; the speed claimed for them was not. The fix was not to
document the flag — it was to delete it. The speed now comes from
`manifest().speed()`, because it is a fact about the device rather than a
preference, and a tool that can express that contradiction will eventually be
asked to. This is the project's speed trap arriving from a third direction.

**What this does NOT yet do:** the device is simulated and local. Pointing the
same bridge at a `RemoteDevicePort` — a real drive on the Mac, across the
encrypted session — is L6, and it needs the two prerequisites that remain:
segmentation, and a data plane that can pipeline.

---

### 3.7 The Linux importer, gate by gate
Full plan with staged evidence gates in
[`LINUX_IMPORTER_PLAN.md`](LINUX_IMPORTER_PLAN.md). This is the only importer
path that waits on nobody, and it is the one that would make this project do
the thing it exists to do for the first time on any platform.

**Feasibility settled by measurement, not argument.** vhci-hcd accepts an
`AF_UNIX` **socketpair** — the only checks are `sockfd_lookup()` and
`SOCK_STREAM`, with no address-family test anywhere in `drivers/usb/usbip/`.
That kills the TCP-loopback fallback the P1 plan assumed (§4.7, OQ-3) and,
better, means **no plaintext USB/IP ever exists on a socket anyone can reach**.
A full enumeration was driven over such a socketpair at both HS and SS during
the design pass, ending in `Attached SCSI removable disk` and `/dev/ttyACM0`.

**Three prerequisites are ours, not the kernel's**, and none is a blocker of
the approach: manifest/transfer **segmentation is unimplemented** (usb-storage
asks for 122 880 B per URB at HS and **1 MiB at SuperSpeed**, against a 65 431 B
record ceiling — raising the ceiling cannot close it); `RemoteDevicePort`
**cannot pipeline** (one SUBMIT at a time, any other `request_id` is fatal);
and **`airusb::Speed` does not match Linux's `usb_device_speed`** — see §8 R3,
it is the nastiest of the three.

**The environment claim in older notes was wrong in two ways.** Debian's
genericcloud kernel is not merely missing vhci-hcd: it is built with
`CONFIG_USB_SUPPORT` unset, so no package can ever supply it. And no reboot is
needed anywhere — Ubuntu 26.04 ships vhci-hcd in base `linux-modules`, 24.04
needs one `linux-modules-extra`. Resolve it at runtime with
`modinfo -n vhci_hcd` rather than encoding either as a rule.

A working VM already exists on this Mac: Lima **`airusb`** (Ubuntu 24.04,
aarch64), vhci-hcd loaded, `nports=16` as 8 `hs` + 8 `ss`, lockdown `[none]`,
with `build-essential` and `cmake` installed.

**L1 PASSED on 2026-08-09, at both speeds.** `platform/linux/vhci_probe_main.cpp`
opens a socketpair, hands one end to vhci-hcd through sysfs `attach`, and reads
what the kernel says first. It says:

```
0000  00 00 00 01 00 00 00 01 00 02 00 02 00 00 00 01
0010  00 00 00 00 00 00 02 00 00 00 00 40 00 00 00 00
0020  00 00 00 00 00 00 00 00 80 06 00 01 00 00 40 00
CMD_SUBMIT=yes ep0-IN=yes GET_DESCRIPTOR(DEVICE)=yes devid-echoed=yes
```

That dump is the byte-order rule made visible, and worth keeping for whoever
doubts it: `transfer_buffer_length` = 64 appears at 0x18 as `00 00 00 40`
BIG-endian, and the same value 64 appears sixteen bytes later inside `setup`
as `40 00` LITTLE-endian. One PDU, both orders. A codec that byteswaps the
header wholesale corrupts enumeration itself.

High speed asks `wLength=64`, SuperSpeed asks `wLength=8` — the design
predicted both. SuperSpeed correctly took port 8, the first of the `ss` half;
`dmesg` confirms `new SuperSpeed USB device number 2 using vhci_hcd`. After
exit all 16 ports return to `sta 004` with no leak.

**L2 DONE:** `platform/linux/UsbipCodec` — 117 checks, built and tested on
macOS, Linux and Windows/MSVC in CI. It has no sockets, no sysfs and no Linux
headers on purpose: a kernel-ABI bug found on the development Mac costs a
rebuild, and the same bug found with a kernel in the loop costs a VM reboot per
iteration.

**L3 DONE:** `platform/linux/VhciBridge` translates USB/IP into transfers on an
`IUsbDevicePort`, and enumeration is proven byte-for-byte with no kernel in the
loop — 72 checks, plus `LinuxUsb` (128 checks) for the speed and errno tables.
The device descriptor the bridge returns is `memcmp`-identical to the
manifest's, which is the verbatim rule asserted rather than asserted about.

**R3 is closed.** `toKernelSpeed()` is a written-out table with a test that
asserts the DISAGREEMENT: `Full→LOW`, `Low→FULL`, `Super→WIRELESS` are what a
cast would have produced, and the test fails if anyone ever "simplifies" it
back into one.

**L4 PASSED, and it went straight through L7 on the way.** See §3.5.

**L5 hosted PASS, 2026-08-09.** Segmentation is now wired into the real
`ExporterSession` and `RemoteDevicePort`, not just written. `protocol::emitTransfer`
is the shared sender (record 0 carries the SUBMIT/COMPLETE fixed body + the first
data slice; every later record is a `Type::Data` continuation with status 0), and
`Reassembler` is the receiver on both ends. `RecordLayer::maxPlaintextBytes()`
sizes each segment so a segment plus the AEAD tag never trips the ceiling. Evidence:
`tests/unit/test_l5_segmentation.cpp` runs a **120 KiB round trip through the real
exporter at record sizes 4 KiB → 65 519**, byte-identical both directions, and
asserts the device sees **exactly one `bulkOut`/`bulkIn` per URB** — reassembly
completes before the device is touched, so no seam short-packet. 20/20 suites
green; zero warnings, Clang full set + strict MinGW. The remaining half of §4.1 is
the **async data plane (L6)**, and the on-kernel `dd` half of the L5 gate belongs
to it.

---

### 3.9 The window, and what it has actually done — 2026-08-09

`airusb-hubd` is a loopback HTTP control plane plus one page compiled into the
binary. Full design, security model and the copy-pasteable two-machine procedure:
**[`GUI.md`](GUI.md)**. Only the evidence and the traps are here.

**macOS ↔ Linux, over the real network, both directions, by hand.**
Mac (`airusb-hubd --share --share-port 7751`) ↔ Lima `airusb` guest
(`--host host.lima.internal`):

```
SAS 486844 on BOTH windows; the Mac named the Linux hub's fingerprint exactly
  V6VJE4PE POZDK4MO LVYOMORI WVJ6IN5Z
macOS accepted FIRST — the hard order — pinned, and dropped the session
Linux reconnected by itself with a NEW number, 428174, and the Mac showed the
  same 428174 as its session number rather than as a question
Linux accepted, attached, verified:
  PASS  058f:6387 Super(5G)  'AirUSB' 'Scripted Device'  61440 x 512  rtt 2032 us
Reverse (Linux shares on 7752, Mac imports through Lima's forward): PASS, rtt 5453 us
```

The reverse direction went straight to `connected` with no prompt, correctly:
pins are per identity pair, not per direction.

**Interop — the hub is not merely talking to itself.** Both directions against
the pre-existing `airusb-net`: hub importer ← `airusb-net serve` gives
`BotProbe PASS, 61440 x 512`; and `airusb-net --write-test` → hub share gives
`RESULT=PASS` with `SEGMENTATION out=2 in=2 largestOut=131072 fired=yes`. The
hub's exporter half therefore handles segmented 128 KiB transfers too.

**The pairing ceremony is the hard part, and the reason it works is written
down.** The SAS comes from the handshake hash, so it differs every session and
both people must compare the SAME session's number — but the exporter's grants
are read at handshake time, so the instant it pins a peer it MUST end the
session. Together those guarantee a tear-down mid-pairing, every time, and
whether that recovers depends on who pressed first. The resolution: the importer
pins **without** dropping (it authorises nothing, so nothing it decided is
stale), the exporter pins **and** drops, the importer reconnects by itself, and
both windows show the current session's number at all times. `test_hub_e2e` runs
both orders over real TCP on all three platforms.

**Two defects this work found in the existing code, both now fixed:**

- `ImporterClient::call()` and `RemoteDevicePort::submit()` spun on `Busy`
  **for ever**. A peer that accepted a connection and then stopped answering hung
  the caller — invisible in a command-line tool that exits, fatal in a daemon
  that also serves a window from the same thread. They now use `T_net_ctrl` and
  `T_urb_wd_imp` from the project's own timeout table.
- The window asked "do these six digits match?" with **no number under it** for
  about a second, on every first pairing, because the drop cleared the SAS but
  left the state at "awaiting approval". A one-second window that repairs itself
  — so it would have survived every manual test. The previous CI run recorded it
  happening on Windows before the fix landed:
  `importer awaiting-approval sas=287034` / `sas=` / `sas=` / `sas=058752`.
  It matters because a person trained to answer a security question while looking
  at nothing has lost the whole value of the ceremony.

**Traps worth keeping:**

- **Do not probe the sharing port with `nc -z` or `Test-NetConnection`.** §3.5
  recorded this for `airusb-net`; it applies to the hub and was reproduced on
  2026-08-09. A bare TCP connect is *accepted* and enters the handshake, so a
  probe occupies the hub's single peer slot. It is reclaimed after twenty seconds
  by the handshake deadline, as designed — but the twenty seconds are real.
- **`mv` preserves mtime, so `make` can skip the rebuild.** The first attempt to
  prove the blank-SAS regression test bit was measuring a stale object file and
  reported the fixed tree as still broken. `touch` after restoring a file.
- The exporter now runs its `ExporterSession` for **unpaired** peers as well,
  which is what §3.14 always specified: PING answered, LIST_DEVICES refused. It
  had to change — without it, a machine that has not approved you yet is
  indistinguishable from one that has gone away, and the pairing heartbeat has to
  tell those apart.

**macOS ↔ Windows, two machines, with the hub — PASS, 2026-08-09.** The GMKtec ran
`airusb-hubd.exe --share --share-port 7714` (the MinGW cross-build, its first
execution anywhere), the Mac imported over the Tailscale subnet router, and both
windows named each other exactly:

```
GMKtec  SN6AJTQJ HVZA33NS S22XH5N7 OB347LE5      SAS 052861 on BOTH screens
Mac     NRPWP5HX 2JI6HVGZ 4I7Q4K2A 7CRBNIKQ      (a human compared them)
importer accepted first, exporter second -> reconnect -> paired, new SAS 450218
attach -> BotProbe PASS, 61440 x 512, rtt 28.3 ms
  SHORT_READ_FIDELITY ok — offered 1024, device sent 512, short read preserved
```

**And the run that found the bugs.** A 128 KiB write across the same link,
before the fixes: `verdict=FAIL outTransfers=0`, `SEGMENTATION out=0 in=1
contRecords=3`; and the NEXT attach could not get past `TEST_UNIT_READY`,
because the simulated device was still in the phase the failed run had abandoned
(§3.4, and `SimulatedDeviceSource` now resets on claim). After both fixes, three
consecutive runs:

```
verdict=PASS  outTransfers=5 largestOut=131072 bytesWritten=281088 mismatched=0 restored=yes
SEGMENTATION out=2 in=2 contRecords=14 maxSegment=16552 largestOut=131072 fired=yes
RESULT=PASS
```

Fourteen continuation records, twice eight-record transfers. That is the
segmentation path proven between two operating systems on a real network, which
is the strongest evidence for it anywhere in this project — loopback never fills
a socket, and that is precisely why loopback never found this.

### Real hardware, through the window — PASS, 2026-08-09

The last cell. `airusb-exportd --serve` captured the physical 058f:6387 and the
hub read it through the control API, with no new code on either side — the
daemon already spoke this protocol.

```
INQUIRY   'Generic' 'Flash Disk' rev '8.01'     <- the drive's OWN firmware strings,
                                                   not 'AirUSB' / 'Scripted Device'
CAPACITY  61440000 x 512 = 31.46 GB
LBA 0     bootsig=55AA
          head=[fa b8 00 00 8e d0 bc 00 7c 8b f4 50 07 50 1f fb]
                 cli; mov ax,0; mov ss,ax; mov sp,0x7c00   <- a real MBR
SHORT_READ_FIDELITY ok — offered 1024, device sent 512, short read preserved
```

**And the write path, on the physical medium, with the owner's explicit
permission** (the stick was declared disposable; `WriteProbe` writes from LBA
1024, well past the partition table, and restores):

```
SAVE_ORIGINAL     131072 bytes held for restore
WRITE_10_1blk / 4blk / 32blk / 256blk    all ok, each in ONE transfer
VERIFY_256blk     131072 bytes identical after the round trip
RESTORE_ORIGINAL  ok
verdict=PASS  outTransfers=5 largestOut=131072 bytesWritten=281088
              mismatched=0 outBoundariesIntact=yes restored=yes
SEGMENTATION out=2 in=2 contRecords=14 maxSegment=16552 fired=yes
```

Re-read afterwards: `bootsig=55AA`, the same sixteen boot bytes, the same
capacity. Releasing the capture (SIGINT to the agent — Ctrl-C's equivalent, and
the assistant CAN send it because the agent runs as the console user) returned
the drive to macOS as `/dev/disk22`, the same identifier as before, remounted at
`/Volumes/Memory 32GB` with its files intact.

**And the write went somewhere the code claimed it would not.** That drive's
partition starts at **LBA 128**, so absolute LBA 1024 is 896 sectors INSIDE the
exFAT filesystem — not the free space the caller's comment promised ("damages
free space rather than the map of where everything is"). The restore worked and
the volume mounted clean, so nothing was lost; the comment was still wrong, and
is now corrected in both `tools/airusb_net_main.cpp` and `diag/WriteProbe.h`.
The offset was NOT raised, because there is no safe one: past the metadata is
user data. What makes the instrument safe to keep is that it is a separate type
from `BotProbe` with a method called `runDestructiveWriteTest`, not a hopeful
choice of sector.

That is the whole product, minus only the Apple-blocked macOS importer: a real
drive taken from macOS, carried over an authenticated encrypted session,
segmented into eight records per transfer, and read AND written byte-exactly by
a person clicking a button.

**Two gotchas from doing it:**

- **Start the agent FIRST.** `airusb-exportd` waits 30 s for it and then hands
  the drive back (correctly — it fails closed); `airusb-agent` waits 60 s for
  the daemon's socket. So the agent is the one that should be waiting. The first
  attempt here died on exactly that, with `RESULT=ATTACH_FAILED XFER_TIMEOUT: no
  agent connected`, and the drive was returned untouched.
- **`lsof -iTCP -sTCP:LISTEN` as a normal user cannot see a root process's
  listening socket.** It reported nothing and led to a wrong conclusion that
  exportd had not reached its listener. Connect with the real client instead —
  which is also the rule §3.5 already gives for a different reason.

**How to reproduce the above.** Terminal 2 FIRST, as the console user, no sudo —
`./build/airusb-agent`. Then terminal 1, as root —
`sudo ./build/airusb-exportd --device 058f:6387 --serve --port 7714`. Then
Connect from any hub to that Mac's address on 7714. Ctrl-C the agent to hand the
drive back in the §7.6 order. `sudo` is blocked for the assistant, so terminals
1 and 2 are always a user step.

**Nothing is left that needs no new code.** Everything remaining is either a
driver (§4.4, Windows UdeCx) or Apple's answer (§2).

---

## 4. THE WORK QUEUE while Apple decides

Apple's answer has no timeline and may be "no". **Nothing in this section waits on
it.** The order below is deliberate; §4.3 in particular is scheduled where it is
for a reason, not by accident.

### 4.1 DONE — macOS × Linux, on real hardware (full L6 + L8, 2026-08-09)

**This is finished.** A real USB drive on the Mac, enumerated by Linux as a real USB
device across the encrypted session — the entire product, minus only the
Apple-blocked macOS importer. The narrative and gate evidence are in §0 and
`LINUX_IMPORTER_PLAN.md` §7 (L5–L8). Kept here: **how to reproduce it.**

**Build (in the Lima `airusb` VM; `/Users/mba` is read-only, so build into /tmp):**
```bash
limactl shell airusb
cmake -S "/Users/mba/Desktop/AirUSB Hub/airusb" -B /tmp/vhci-build -DCMAKE_BUILD_TYPE=Release
cmake --build /tmp/vhci-build --target airusb-vhci airusb-net -j4
```
On the Mac, `cmake --build build --target airusb-exportd airusb-agent`.

**Simulated device, all in the VM (no Mac, no hardware, no user):**
```bash
/tmp/vhci-build/airusb-net serve --port 7714 &                      # exporter (fake device)
sudo /tmp/vhci-build/airusb-vhci --host 127.0.0.1 --port 7714       # run TWICE: 1st pairs, 2nd mounts
```

**Real drive, Mac → VM (READ-ONLY on the Linux side, or you WRITE the drive):**
```bash
# Mac, terminal 1 (root): sudo ./airusb-exportd --device 058f:6387 --serve --port 7714
# Mac, terminal 2 (console user, no sudo): ./airusb-agent
# VM: sudo /tmp/vhci-build/airusb-vhci --host host.lima.internal --port 7714   # twice (pair, mount)
# VM: sudo mount -o ro /dev/sdX1 /mnt   ← READ-ONLY. mkfs/write DESTROYS real data.
# Release: Ctrl-C the agent (terminal 2) → exportd frees the drive in §7.6 order and exits.
```
Gotchas: fresh pairing needs `rm airusb-vhci.id airusb-vhci.peers` on the importer;
the importer's background process holds the SSH channel unless launched
`setsid … </dev/null >log 2>&1 &` (poll a result file instead of reading its output);
`timeout(1)` exists in the VM but NOT on the Mac.

**Both halves also existed separately first:** the macOS exporter drives real
hardware (P2.8, 058f:6387), and `airusb-vhci` (no `--host`) makes the kernel
enumerate a LOCAL simulated device (§3.6).

**Two pieces of work, both ours, neither blocked:**

1. **Wire segmentation in. — DONE, L5 hosted PASS, 2026-08-09.**
   `protocol::planSegments`/`Reassembler` (139 checks) are now joined by
   `protocol::emitTransfer`, and the two are wired into the real `ExporterSession`
   (reassembles a segmented OUT before one `bulkOut`; segments a large IN COMPLETE)
   and `RemoteDevicePort` (segments a large OUT; reassembles a segmented IN).
   `RecordLayer::maxPlaintextBytes()` sizes segments against the ceiling *minus the
   AEAD tag*. Proof: a 120 KiB round trip through the real exporter at record sizes
   4 KiB → 65 519, byte-identical, one device transfer per URB
   (`tests/unit/test_l5_segmentation.cpp`). See §3.7.

   Why it was mandatory rather than an optimisation: a record cannot exceed 65 519
   bytes — Noise's plaintext ceiling, not a tuning parameter — and `usb-storage`
   asks for 122 880 bytes in one URB at high speed and **a megabyte** once
   `slave_configure()` raises `max_sectors` on a SuperSpeed link.

   **Reassembly completes before the device sees anything** — the load-bearing
   rule, now enforced and tested. Handing the exporter three segments to issue as
   three `bulkOut` calls injects a short packet at each seam, and a short packet is
   how USB signals the end of a data phase — the device reads the first seam as the
   end of the transfer and the next segment as a new command. Silent corruption.
   This is why `IUsbDevicePort` documents one call as ONE logical transfer, and why
   the L5 test asserts `outCalls == 1` / `inCalls == 1` for a 120 KiB URB.

2. **A non-blocking data plane. — HALF DONE.** `RemoteDevicePort` sends one SUBMIT
   and blocks in `receiveRecord` until the COMPLETE; behind vhci that deadlocks
   (vhci-hcd writes CMD_SUBMIT and reads RET_SUBMIT over ONE socket via two
   kthreads, so a bridge that blocks on the network while the kernel's socket fills
   hangs both sides → unkillable D-state, reboot). The hazard is **liveness, not
   throughput** — see the GPT-5.6 cross-check recorded below.

   **Built and hosted-proven (2026-08-09): `session/ImporterDataPlane`.** The async,
   non-blocking analogue of `RemoteDevicePort`: `submit()` emits and returns (never
   blocks — a full socket buffers, R-B); `pump()` drains what the network has right
   now and fires one completion per finished transfer; `sweepDeadlines()` is the
   only timeout in the system (R-C); `cancel()`/`completeAll()` keep invariant I1
   (exactly one terminal outcome per submit) on unlink and teardown. Demux and
   reassembly are keyed by `(channel, request_id)` on `core::RequestTable` +
   `protocol::Reassembler`. Admission depth defaults to **1** (usb-storage is
   `can_queue=1`); the machinery already supports more. `tests/unit/test_dataplane.cpp`
   (82 checks) proves round trips vs the real `ExporterSession`, non-blocking under
   a stalled socket, R-C timeout, cancel-drops-the-late-completion, and I1 on
   teardown.

   **The event-driven bridge — DONE, hosted PASS 2026-08-09: `platform/linux/VhciNetBridge`.**
   The synchronous `VhciBridge` stays as-is (it is L4's proof against a local
   device); `VhciNetBridge` is the networked one. One non-blocking `poll()` step:
   drain `sv[1]` FIRST and unconditionally (R-A), answer ep0 from the manifest
   locally, admit data/forwarded transfers to `ImporterDataPlane` or queue them,
   answer `CMD_UNLINK` immediately, turn completions/timeouts into buffered
   RET_SUBMITs (R-B), and complete every outstanding URB with -ENODEV if the network
   dies. `tests/unit/test_netbridge.cpp` (68 checks) proves it with a MemoryPipe
   standing in for the kernel: a forwarded round trip, a local GET_DESCRIPTOR with
   ZERO network traffic, **CMD_UNLINK answered with -ECONNRESET before any completion
   and the late completion dropped** (the D-state test), an already-completed
   unlink → status 0, a network drop → RET_SUBMIT{-ENODEV}, a deadline →
   RET_SUBMIT{-ETIMEDOUT}, and a depth-1 admission queue.

   **What remains for L6:** the `--host` form of `airusb-vhci` — wire
   `ImporterClient` (connect/handshake/attach) → `ImporterDataPlane` →
   `VhciNetBridge` → the real socketpair (`FdStream`) behind a `poll(2)` loop — and
   then the real run on the Lima `airusb` VM against the macOS exporter (L6's
   `sha256sum` gate). Every hard-correctness core (segmentation, the non-blocking
   data plane, the non-blocking bridge) is now built and proven with no kernel in
   the loop.

**Gates:** L5 then L6 in `LINUX_IMPORTER_PLAN.md` §7. L6's evidence is
`sha256sum /dev/sdX` matching a known image and `dmesg` free of `usb-storage`
resets.

### 4.2 macOS × Windows — as far as it can currently go

The protocol half is **done and measured** (§3.6), and since 2026-08-09 the
Windows half is measured against the *current* tree rather than a pre-segmentation
one (§3.4). The one thing outstanding that does not need the UdeCx driver is the
**two-machine run with the hub**, which needs the physical box: `GUI.md` has the
procedure ready to paste, and the direction is forced — Windows shares, the Mac
imports, because Windows still has no route back to the Mac.

Beyond that it cannot go further until the Windows importer exists, and that is
§4.4.

There is one cheap, unblocked follow-up: the Windows box currently serves a
simulated device only. A **Windows exporter for real hardware** (WinUSB/UsbDk
capture) is a separate piece nobody has started, and is not required for anything
below.

### 4.3 Windows × Linux — the pair that needs no Mac, and why it comes third

**Do this after §4.1 and §4.2.**

Both halves already exist and are proven independently: `airusb-net serve` runs on
Windows under MSVC and completed a two-machine exchange (§3.6), and
`airusb-vhci` makes Linux enumerate a device (§3.6). Connecting them gives an
**end-to-end run with zero macOS and zero Apple involvement**: Windows serves,
Linux enumerates, a filesystem mounts.

Its value is real and specific:

* it proves the protocol and the importer are genuinely platform-independent
  rather than accidentally macOS-shaped;
* it is the only full-stack configuration that could plausibly run **unattended in
  CI**, since both ends are commodity runners and no hardware is involved;
* it survives Apple saying no.

**Why it is third and not first.** The device it can carry is *simulated* — the
real-hardware capture path only exists on macOS today. So Windows × Linux
exercises the network, the session, the bridge and the kernel, but never a real
USB device. §4.1 does exercise one. Doing §4.1 first means that when §4.3 runs,
any failure it finds is a Windows-or-Linux failure rather than an ambiguity
between "the pair is broken" and "the stack is broken" — the same reasoning that
made `diag/BotProbe` run against `ScriptedDevice` in CI before it was ever pointed
at a drive.

**Concretely, once §4.1 lands:**

```powershell
# Windows (the exporter). Use the v0.2.1 release binary or a fresh CI artifact.
.\airusb-net-msvc-x64.exe serve --port 7714
```
```bash
# Linux (the importer), in the airusb VM
sudo ./airusb-vhci --host <WINDOWS-IP> --port 7714     # the --host form is §4.1 work
dmesg | tail ; lsblk ; sudo mount /dev/sdX /mnt/x
```

The `--host` form does not exist yet: `airusb-vhci` currently instantiates a local
`ScriptedDevice`. Giving it an `ImporterClient` instead is the same change §4.1
needs, so §4.3 costs almost nothing extra once §4.1 is done.

**Route first, as always.** The Mac and the Windows box are not on the same LAN
(§6). Whether Windows and the Linux VM can reach each other is a separate
question that has never been measured — the Lima guest reaches the host via
`host.lima.internal`, and reaching the Windows box beyond that is unproven.
Measure before assuming; §3.4 records what that cost last time.

### 4.4 The Windows importer — UdeCx

`UdecxHostBackend` + `airusb.sys`, KMDF, design in `P1_IMPLEMENTATION_PLAN.md`
§4.6. **Windows' gate is self-service:** `bcdedit /set testsigning on` for
development, EV certificate + Microsoft attestation for distribution — a paid
process, not a discretionary approval. **Nothing about the Windows path waits on
anyone's decision.**

Much of the work is now cheaper than it was: `VhciBridge` proved that the
translation layer can be written against `IUsbDevicePort` and tested with no
kernel in the loop, and the same split applies to UdeCx.

### 4.5 Smaller, fully unblocked

* **`PAIR_*` handlers.** The opcodes are reserved in `Wire.h` (0x10/0x11/0x12) and
  the trust gate already refuses everything else to an Unpaired peer, but no
  handler exists. The rate limiter half is done (`session/PairingGate`).
* **Manifest segmentation on the control plane.** `protocol::emitTransfer`/
  `Reassembler` are now wired into the **data** plane (§4.1), but the manifest path
  still has none — an 8-configuration device with a full string table could exceed
  one record. The attach currently fails with a clear status rather than
  truncating. `emitTransfer` is control-plane-agnostic, so this is now mostly a
  matter of teaching `ImporterClient`'s manifest read to reassemble.
* **`kXfShortNotOk` / `kXfZeroPacket` / `kXfIsoAsap` have no consumer.**
  `Codec.cpp` round-trips `xflags`; nothing reads it. Both ends need wiring in one
  commit. `ZERO_PACKET` matters for real writes: dropped, a device waits for ever
  for a terminating ZLP after an exact-multiple OUT.
* **Interrupt and isochronous endpoints.** `ExporterSession::handleSubmit`
  dispatches on direction only and discards `sb.xferType`;
  `RemoteDevicePort::bulkIn/bulkOut` hardcode `XferType::Bulk`. An interrupt IN
  that legitimately idles forever wedges the exporter's serial read loop with no
  deadline anywhere. Either promote `submit()` or refuse ATTACH for such devices
  in v1 and say so.

---

## 5. Environment (verified, not assumed)

| Property | Value |
|---|---|
| macOS | 26.5.1 (25F80), Apple M1, arm64 |
| Xcode / SDK | 26.5 (17F42) / macOS 26.5 |
| SIP | **enabled** |
| Secure Boot | **Reduced**. Full Security NOT tested — re-verify before release |
| Signing identities | `Apple Development … (WT36SR3Q23)`, `Apple Distribution … (GZUV3UMV3B)` |
| Test USB device | `058f:6387` Generic Mass Storage, 31.5 GB exFAT, **SuperSpeed**, `disk22` |
| **Working Linux VM** | Lima **`airusb`** — Ubuntu 24.04 aarch64, kernel 6.8.0-134-generic, GCC 13.3, cmake 3.28. **vhci-hcd loaded**, `nports=16` (8 `hs` + 8 `ss`), lockdown `[none]`. This is the one to use |
| Other Linux VM | Lima `kbuild`, Debian 12 aarch64, GCC 12.2 — **belongs to another project, do not modify.** Its `cloud` kernel is built with `CONFIG_USB_SUPPORT` unset, so it can never do vhci-hcd |
| Mac LAN / Tailscale | `192.168.2.15` (en0) / `100.120.39.113` (utun8) |
| Windows box | `GMKtec`, **192.168.0.109**, RDP + SMB open, **SSH closed**, no Tailscale. Different LAN from the Mac — reached only via the `ts-464` subnet router. `.225` is a DIFFERENT machine |
| Cross-compiler | `x86_64-w64-mingw32-g++` (Homebrew mingw-w64) |
| GitHub | `gh` authenticated as `otti83` |

### Tooling constraints learned the hard way

- **`sudo` is blocked for the assistant ON THE MAC.** Every root experiment on
  macOS is handed to the user as a copy-pasteable command. **Inside a Lima VM
  passwordless sudo works**, which is what made the whole Linux importer possible
  without the user in the loop — the old note said "sudo is blocked" without that
  qualifier and it cost a session's worth of hesitation.
- **AddressSanitizer hangs on this host** — any `-fsanitize=address` binary hangs
  before `main()`, including a hello-world with no libFuzzer. Bisected: `fuzzer`
  works, `fuzzer,undefined` works, `address` hangs. Fuzzing defaults to
  `fuzzer,undefined`; `AIRUSB_FUZZ_ASAN=1` opts back in. **Linux CI now enables
  ASan** (`.github/workflows/ci.yml`, job `linux-asan`) — UBSan does not catch
  heap out-of-bounds, which is exactly what R2/R5/R6 exist to stop. **It has now
  run and is clean**, including a 16 KB OUT transfer through the write probe.
- **`timeout(1)` does not exist on macOS.** It does exist in the Linux VMs.
- **Do not run `usbip bind` or load `usbip-host` in a Lima `vz` guest.** It wedged
  a guest during the design pass: the command never returned, SSH hung, no ICMP,
  empty journal, `limactl stop -f` required. Undiagnosed, and irrelevant to us —
  `usbip-host` is the *exporter* side and we never need it. `usbipd`, `usbip
  attach` and `usbip list -r` are equally unnecessary: we replace USB/IP's
  userspace handshake with AirUSB and write the sysfs `attach` line ourselves.
- **`.gitignore` has no trailing comments.** `path/  # note` matches nothing.
- Objective-C files compile as C, not C++: no declaration-in-`if`.

---

## 6. Code map

```
airusb/
  core/        Status, UsbTypes, Clock, Watchdog (the ONE clock), DeviceManifest,
               Ep0Arbiter, RequestTable, CreditController, IUsbDevicePort,
               Platform (the only place three OSes differ)
  crypto/      Primitives (the ONLY caller of third_party), Identity
  protocol/    Wire.h, Codec, Validate (R1–R12), Messages, ManifestCodec, Noise,
               Segmentation (split/reassemble; written, NOT yet wired in)
  transport/   RecordLayer, FrameScheduler, TcpTransport, FaultTransport,
               NoiseCipher
  session/     SecureSession, PeerStore, PairingGate (the SAS attempt budget),
               ExporterSession (now reassembles/segments — L5), ImporterClient
               (+ attachForBridge for the async path), RemoteDevicePort (sync,
               BotProbe's instrument), ImporterDataPlane (NEW — the async,
               non-blocking importer data plane the vhci bridge needs)
  diag/        BotProbe — read-only BOT prober, and its header promises WITHOUT
               QUALIFICATION that it cannot damage a drive. WriteProbe is a
               SEPARATE type so that promise stays absolute rather than becoming
               conditional on a flag. Test instruments, NOT the data path;
               nothing in core/protocol/transport includes them
  control/     THE PRODUCT'S WINDOW, and the same one on three OSes. Json (a
               writer whose only door escapes, and a reader that accepts exactly
               one shape), HttpServer (loopback-only, no filesystem anywhere in
               it, guard as a pure function), HubState (the pairing ceremony —
               read its header before changing anything), ControlApi (the routes),
               WebUi (the page, in chunks so no single string literal can hit
               MSVC's limit), SimulatedDeviceSource
  tools/       airusb_net_main — serve/connect over a real socket
               airusb_hubd_main — the daemon behind the window. No root, ever
  platform/macos/  StatusMapMacos, MacUsbCommon, DiskGuard, AgentUsbIo,
               HostDeviceExporter (an IUsbDevicePort), airusb_exportd_main
               (+ NEW `--serve`: TCP ExporterSession over the captured real drive),
               airusb_agent_main, AgentProtocol (portable) + AgentLink (POSIX only)
  platform/linux/  UsbipCodec (the USB/IP byte layer, built and fuzzed on EVERY
               platform), LinuxUsb (the speed and errno tables), VhciBridge (the
               SYNCHRONOUS translation, L4/local), VhciNetBridge (NEW — the
               event-driven, non-blocking bridge for the NETWORKED importer, L6),
               FdStream, vhci_probe_main (the L1 gate), airusb_vhci_main
               (L4 local, AND `--host` = the real network importer, L6)
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

## 7. Decisions and findings not to re-derive

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
- **A second ATTACH gets BUSY and is never queued** (`P1_IMPLEMENTATION_PLAN.md` §7.7).
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

### The L6 blocker is liveness, not throughput — settled, cross-checked

Do not re-open this as "the protocol is too slow, speed it up first." The reason
the synchronous `RemoteDevicePort` cannot sit behind vhci is **deadlock**, not
latency: vhci-hcd runs tx and rx as two kthreads over one socket, the AF_UNIX send
window cannot hold a large URB atomically, and a bridge that blocks on the network
while that window fills wedges both sides into an unkillable `D`-state (reboot).
The fix — a non-blocking data plane — *also* removes the per-URB round-trip that
would make a mounted filesystem crawl, so "avoid the deadlock" and "make it usable"
are the **same component** (`ImporterDataPlane`), correctness-first. The project's
own priority order says so: Correctness > Compatibility > Reliability > Latency >
Throughput. This was independently cross-checked with GPT-5.6 (`gpt-5.6-sol` via
`codex exec`, read-only) on 2026-08-09, which verified the mechanism against
`RemoteDevicePort`/`VhciBridge` and agreed: build the async plane first, keep
admission depth 1 until there is something to measure, throughput-tune only after
L6 passes.

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
| new | two machines, real network, one Windows | **ANSWERED: PASS** (§3.6), SAS confirmed on both consoles |
| new | does the console mangle user-facing text on a Japanese Windows? | **it did** — CP932 read the em dash as `窶・` in the SAS line. Fixed with `platform::ConsoleUtf8` |
