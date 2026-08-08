# AirUSB Hub — Session Handoff / Debug Report

**Written:** 2026-08-08
**Purpose:** resume this project in a fresh session with no access to the previous
conversation. Everything load-bearing is here or in the documents it points to.
**Repo:** `/Users/mba/Desktop/AirUSB Hub` (git initialised, 19 commits, no remote)

---

## 0. Read this first — where the work actually is

**P2.8 is done and its gate PASSED on real hardware** (2026-08-08, 058f:6387
SuperSpeed). Bulk I/O works through pipes the *agent* obtains while the *daemon*
holds the capture. The split exporter is proven end to end, the drive was restored
with the mount table byte-identical, and **OQ-1 is answered: transfer boundaries
INTACT**. Full evidence in `docs/P2_8_EXPORTER.md` §4.

**P2.4 is done too, and the session layer with it.** `NullCipher` is no longer
the only `IRecordCipher`: `Noise_XX` / `Noise_IK` over X25519 +
ChaCha20-Poly1305 + BLAKE2s, matched byte for byte against an independent
implementation's official vectors, with the Ed25519 identity binding, the
six-digit SAS, the L0 preamble, the trust gate and a persistent pin store.
Evidence in `docs/P2_4_SECURITY.md`.

**What is left is blocked on you, not on code.** The importer half (P2.9) needs
`com.apple.developer.usb.host-controller-interface`, which only an Account Holder
can request from Apple. Procedure and a ready-to-paste draft are in
`docs/ENTITLEMENT_REQUEST.md`; the two decisions it needs are in §8. Everything
downstream — P2.10, P2.11 — depends on it.

Unblocked work that remains is listed in §9.

### The process failure this section used to describe

An earlier session repeatedly announced "proceeding to the next phase" and then
stopped without writing code — three times across consecutive turns. The failure
mode was treating a long explanatory message as if it were delivery. It is
recorded here because the fix generalises: **report after it builds and its tests
pass, not before, and do not restate a plan that is already written down.**

---

## 1. What this project is

An OSS cross-platform virtual USB hub. A physical USB device attached to one
machine is forwarded over the LAN so the importing machine's OS **enumerates it as
a real USB device and loads its own native drivers**. Not file sharing — the USB
device itself is transported.

macOS first, then Windows and Linux. TCP first, QUIC later. First test device:
USB flash drive (mass storage).

The governing spec is the user's master prompt. Its hard rules:

- **Natural Path Only.** No private API, no SIP disable, no OS modification, no
  mass-storage-specific fake implementation presented as generic USB.
- **Evidence First.** No claim of "works" or "fixed" without a build log, runtime
  log, descriptor dump, IORegistry output, or before/after comparison from the
  *same* iteration.
- **Phase Gate.** Each phase ends with Goal / Implementation / Evidence / PASS-FAIL
  / Known Issues / Next Phase. A failed gate does not advance.
- Correctness > Compatibility > Reliability > Latency > Throughput.
- Exporter and Importer are session roles, not product roles — every peer can do
  both. (The PoC may fix roles.)

---

## 2. Environment (verified, not assumed)

| Property | Value |
|---|---|
| macOS | 26.5.1 (25F80) |
| CPU | Apple M1 (T8103), arm64 |
| Model | MacBookAir10,1 |
| Xcode / Swift / SDK | 26.5 (17F42) / 6.3.2 / macOS 26.5, DriverKit 25.5 |
| SIP | **enabled** |
| Secure Boot | **Reduced** (`低セキュリティ`), Allow All Kernel Extensions: YES |
| Signing identities | `Apple Development: Hiroya Ochiai (WT36SR3Q23)`, `Apple Distribution: Hiroya Ochiai (GZUV3UMV3B)` — **two different teams** |
| Test USB device | `058f:6387` Generic Mass Storage, 31.5 GB exFAT, **SuperSpeed 5 Gb/s** |

**Full Security has NOT been tested.** This Mac is at Reduced Security. Re-verify
before release.

### Tooling constraints discovered the hard way

- **`sudo` is blocked** for the assistant in this harness. Every root experiment
  must be handed to the user as a copy-pasteable command. The user runs it in their
  own terminal and pastes the output back.
- **AddressSanitizer hangs on this host.** Any binary linked with
  `-fsanitize=address` hangs before `main()`, including a hello-world with no
  libFuzzer. Bisected: `fuzzer` works, `fuzzer,undefined` works, `address` hangs.
  This is the ASan runtime on this machine, not project code. Fuzzing defaults to
  `fuzzer,undefined`; `AIRUSB_FUZZ_ASAN=1` opts back in. **Linux CI must enable
  ASan** — UBSan does not detect heap out-of-bounds, which is precisely the class
  R2/R5/R6 exist to stop. Recorded in `airusb/tests/fuzz/build_and_run.sh`.
- **`timeout(1)` does not exist on macOS.** Use the harness timeout.
- Objective-C files are compiled as C, not C++: no declaration-in-`if`.

---

## 3. Gate results

### Gate 0 — macOS feasibility: **CONDITIONAL PASS**

`docs/P0_MACOS_FEASIBILITY.md`

macOS ships a **public** user-space virtual USB host controller API:
`IOUSBHostControllerInterface` in `IOUSBHost.framework`. Its own header says it
exists "to provide access to remote USB devices or create synthetic USB devices".
Apple's `com.apple.driver.usb.AppleUSBUserHCI` kext provides the kernel half and is
loaded on a stock system. No kext of ours, SIP stays on, Apple Silicon supported.

The API is sufficient for real USB: controller/port/device/endpoint state machines,
control/bulk/interrupt/isochronous, endpoint halt+reset, port reset/suspend/resume,
descriptor updates, frame-number sync. Hard limit: **15 root ports per controller**
(`portCount` is a 4-bit field).

**The one obstacle is an entitlement**, `com.apple.developer.usb.host-controller-interface`
(named in `IOUSBHostControllerInterface.h:19` and `#define`d in the public
`IOUSBHostFamilyDefinitions.h:172`). Authorization was tested, not assumed —
`poc/p0-probe/run_probe.sh`, six signing variants:

```
A ad-hoc,    no entitlement      exit 2    kIOReturnNotOpen 0xE00002CD
B ad-hoc,    HCI entitlement     exit 137  SIGKILL by AMFI
C Apple Dev, HCI entitlement     exit 137  SIGKILL by AMFI
D Apple Dev, no entitlement      exit 2    kIOReturnNotOpen
E Apple Dev, FABRICATED com.apple.developer.*  exit 137  SIGKILL
F Apple Dev, com.apple.security.cs.*          exit 2    runs
```

E vs F is the informative pair: a *made-up* `com.apple.developer.*` entitlement is
killed identically, so this is AMFI's generic restricted-prefix rule, not a targeted
block.

**It is obtainable — proven, not inferred.** VirtualHere ships it under a notarized
Developer ID signature, and its `embedded.provisionprofile` authorizes exactly that
key (verified locally with `codesign -d --entitlements -`, `spctl -a -vvv`, and
`security cms -D`). End users need nothing: no entitlement, no SIP change.

**Risk:** every confirmed holder is an **Organization** team. No public instance of
an Individual account being granted it was found.

### Gate 1 — architecture: **PASS**

`docs/P1_IMPLEMENTATION_PLAN.md` (1107 lines). Produced by three independent
designs judged by three adversarial lenses; all 32 defects raised are resolved or
explicitly accepted, tracked in §0.

### Gate P1 hardware verification: **PASS**

`docs/P1_CAPTURE_VERIFICATION.md`. See §4 — this is the most important finding.

### Gate P2.4 + session layer: **PASS**

`docs/P2_4_SECURITY.md`. The acceptance test is not a round trip — a Noise
implementation that only talks to itself agrees with itself perfectly while being
wrong. It is the official cross-implementation vectors:

```
official Noise vectors (independent implementation)
  Noise_IK_25519_ChaChaPoly_BLAKE2s   pass, byte for byte
  Noise_XX_25519_ChaChaPoly_BLAKE2s   pass, byte for byte
```

Every handshake message, every transport message after the split, and the final
handshake hash the SAS derives from. Primitives separately checked against
RFC 7693 / 8439 / 7748 / 8032, extracted mechanically from the RFC text.

The session layer on top is tested against **an actual man in the middle**: a
relay between two pipes flips `wire_minor` — a field nothing else validates — and
the handshake dies, because both preambles feed the Noise prologue. A control
test relays the same bytes faithfully and requires the session to come up, so the
attack test cannot pass merely because the relay is broken.

### Gate P2.8 — the real exporter, on real hardware: **PASS**

`docs/P2_8_EXPORTER.md`. Run 2026-08-08 against 058f:6387 at SuperSpeed, with both
halves as real launchd jobs (root LaunchDaemon in the system session, unprivileged
LaunchAgent in the Aqua session).

```
verdict=PASS  cbw=6 data=5 csw=6 stallRecoveries=0 shortReads=0 boundariesIntact=yes
  READ_10_LBA0         512 bytes, residue=0, bootsig=55AA
  SHORT_READ_FIDELITY  offered 1024, device sent 512 — short read preserved
  READ_10_MULTIBLOCK   2048 bytes in one transfer, residue=0
restore: drive back on this Mac = yes; mount table matches 'before' exactly
```

Bulk I/O works through pipes the agent obtains while the daemon holds the capture.
The last unproven step of the split architecture is now proven.

---

## 4. THE key architectural finding: the exporter is two processes

FB16524420 reproduces on macOS 26.5.1, but **not for the reason the radar states**.

### Measured permission map

| operation | needs root | needs console session |
|---|---|---|
| DiskArbitration whole-disk unmount | **yes** (`0xF8DA0009 kDAReturnNotPrivileged`) | no |
| `IOUSBHostDevice` + `DeviceCapture` | **yes** | **no** — works under launchd |
| `IOUSBHostInterface` open | **no** — works as uid 501 | **yes** |

### The isolating experiment (`run_matrix.sh`, five contexts, one device)

```
A direct — root, console session                 0x00000000  SUCCESS
B LaunchDaemon — root, system session            0xE00002E2  kIOReturnNotPermitted
C LaunchDaemon + SessionCreate                   0xE00002E2  kIOReturnNotPermitted
D launchctl asuser 501 — root, console session   0x00000000  SUCCESS
E LaunchDaemon, binary in /usr/local/libexec     0xE00002E2  kIOReturnNotPermitted
```

The kernel names the gate:

```
(Sandbox) System Policy: capture_test(pid) deny(1) iokit-open-service IOUSBHostInterface
(Sandbox) System Policy: configd(342)      deny(1) iokit-open-service IOUSBHostInterface
```

Apple's own `configd` is denied identically.

The decisive pair — same launchd parent, same absence of a tty, **less** privilege,
opposite result:

| | uid | ppid | tty | session | result |
|---|---|---|---|---|---|
| LaunchDaemon | 0 | 1 | none | system | **denied** |
| LaunchAgent | 501 | 1 | none | Aqua | **success** |

**Session membership is the entire variable.**

### The resulting architecture

```
airusb-exportd   root LaunchDaemon       DiskArbitration unmount/claim,
                                         IOUSBHostDevice + DeviceCapture,
                                         lease ownership, restore on release
       │  local IPC (unix socket)
       ▼
airusb-agent     console-session Agent   IOUSBHostInterface, copyPipeWithAddress:,
                 (unprivileged)          bulk/interrupt transfers — the data plane
```

Verified with `run_split_test.sh`: the daemon captures and holds the device for
25 s while a **separate, non-root, console-session process opens the interface
successfully**. Re-confirmed in the real production shape via an actual LaunchAgent.

### Second, separate Apple bug — binding on our code

Under launchd the process did not merely fail, it **died**:

```
-[IOUSBHostObject openWithOptions:error:] + 432
NSInvalidArgumentException: attempt to insert nil object from objects[0]
```

Disassembly (lldb, arm64e): `IOServiceOpen` fails at +168; the framework falls
through to build an `NSError` userInfo from three
`-[NSBundle localizedStringForKey:…]` results (+208…+404) and raises at +428
because one is nil. `objects[0]` is the *first* value, so `+[NSBundle mainBundle]`
itself returned nil.

**P2.8 update — it is not confined to the open path.** The same exception was
raised by `-[IOUSBHostObject descriptorWithType:length:index:languageID:error:]`
during the P2.8 gate run, when a SuperSpeed device STALLed a DEVICE_QUALIFIER
request:

```
descriptorWithType:6 raised NSInvalidArgumentException:
  -[__NSPlaceholderDictionary initWithObjects:forKeys:count:]:
  attempt to insert nil object from objects[0]
```

So this is a general property of the framework's error-construction path, not a
quirk of one selector. **Do not narrow the wrapping to the sites where it has been
observed.** The `@try`/`@catch` in `HostDeviceExporter::fetchDescriptor` is the
only reason the daemon survived that line holding a captured, unmounted drive.

Three consequences for the real exporter:

1. **Wrap every call into `IOUSBHost` in `@try`/`@catch`** — inits and ordinary
   methods alike. Apple's error path can raise instead of returning an `NSError`.
   A root daemon that dies from an uncaught exception takes the captured device
   with it and leaves the user's drive unmounted.
2. **Never rely on the `NSError`.** Call `IOServiceOpen` directly when the real
   `IOReturn` matters; the framework destroys it on this path.
3. **Do not provoke it needlessly.** DEVICE_QUALIFIER is undefined for SuperSpeed
   (USB 2.0 §9.6.2), so the request is no longer made at those speeds. The STALL
   was correct device behaviour; asking was our mistake.

### A third code that looks like the second and is not

`0xE00002C9 kIOReturnInternalError` is the FB16524420 signature — and it is also
what the framework returns when a driver simply still owns the interface because
nothing has captured the device. Those look identical and mean opposite things.
`AgentUsbIo` now probes the service with a direct `IOServiceOpen` on failure and
states which of the two it hit:

```
interface 0 open failed: 0xE00002C9 kIOReturnInternalError
  ^ the security session is FINE (a raw open of this service returns
    0x00000000 kIOReturnSuccess). The framework's open is what failed — the
    usual cause is that a driver still holds the interface because no capture
    is in effect.
```

---

## 5. Hypotheses that were REFUTED — do not retry these

Recorded so the next session does not spend hours re-deriving them.

| Hypothesis | Verdict | Evidence |
|---|---|---|
| The binary living in TCC-protected `~/Desktop` causes the denial | **REFUTED** | context E: staging to `/usr/local/libexec` changes nothing |
| `SessionCreate` in the plist fixes it | **REFUTED** | context C: still `0xE00002E2` |
| `IOServiceAuthorize()` is the mechanism | **REFUTED** | returns `0xE00002C6 kIOReturnBadMessageID` both unsigned and Apple-Development-signed |
| It is a privilege (root) problem | **REFUTED** | a non-root uid 501 process opens the interface fine |
| Switching to libusb / legacy IOUSBLib avoids it | **REFUTED** | both land on the same `IOServiceOpen` on the same interface nub, differing only in user-client type |
| The nil is the third `localizedStringForKey:` (nil key at +376) | **REFUTED** | the exception names `objects[0]`; stores at +268/+340/+404 show that is the *first* value |
| The test device is High Speed / USB 2.0 | **REFUTED** | `USBSpeed = 4`, `UsbLinkSpeed = 5,000,000,000`; it is SuperSpeed |

### The speed trap, because it will bite again

The IORegistry exposes **two speed properties with different enumerations**:

| property | enumeration | value here | means |
|---|---|---|---|
| `Device Speed` | legacy: Low=0, Full=1, High=2, **Super=3** | 3 | Super |
| `USBSpeed` | `tIOUSBHostConnectionSpeed`: …, **High=3**, Super=4 | 4 | Super |

The same integer `3` means *High* in one and *Super* in the other. Read `USBSpeed`
and cross-check `UsbLinkSpeed`. `DeviceManifest::validate()` now rejects a
SuperSpeed manifest carrying a High Speed `bMaxPacketSize0`, so this specific
mistake is a test failure rather than a silent USB-2 downgrade.

**Decision on record:** the user offered to let the app downgrade to USB 2.0
because they have no USB 2.0 hub. Declined, deliberately — downgrading requires
*fabricating* descriptors (`bMaxPacketSize0` 9→64, bulk `wMaxPacketSize` 1024→512,
deleting SS companions), which contradicts verbatim passthrough. SuperSpeed
passthrough is both simpler and more correct. A `--force-high-speed` debug flag may
exist, but it is not the product path.

---

## 6. Code state

```
11 suites / 0 failures
3 fuzz targets / 0 crashes / 0 UB findings
Zero warnings under -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion
  -Wshadow — Objective-C++ included
```

```
airusb/
  CMakeLists.txt              C++20 + Objective-C++, warnings-as-listed, ctest
  core/       Status, UsbTypes, Clock, Watchdog, DeviceManifest,
              Ep0Arbiter, RequestTable, CreditController, IUsbDevicePort
  protocol/   Wire.h (every offset a named constant + static_assert),
              Codec, Validate (R1–R12),
              Noise — CipherState / SymmetricState / HandshakeState, XX and IK
  transport/  IAirUsbTransport, RecordLayer, FrameScheduler,
              TcpTransport (+ MemoryPipe), FaultTransport,
              NoiseCipher — the real IRecordCipher, replacing NullCipher
  session/    SecureSession  preamble -> handshake -> trust gate -> transport
              PeerStore      pinned identities, grants, atomic persistence
  crypto/     Primitives  the ONLY caller of third_party. BLAKE2s, HMAC,
                          Noise HKDF, ChaCha20-Poly1305, X25519, Ed25519
              Identity    identity keys, binding signature, fingerprint, SAS
  third_party/ vendored, pinned, checksummed — see PROVENANCE.md
              monocypher/ X25519, RFC 8032 Ed25519, RFC 8439 ChaCha20-Poly1305
              blake2s/    the BLAKE2 designers' reference implementation
  diag/       BotProbe — read-only Bulk-Only Transport prober. A test
              instrument, not the data path; nothing in core/protocol/
              transport includes it.
  platform/macos/
              StatusMapMacos  IOReturn -> Status, pure C++, cross-checked
                              against the SDK by static_assert in the .mm
              AgentProtocol   daemon<->agent IPC codec, pure C++, fuzzed
              AgentLink       framed unix socket, plain POSIX
              MacUsbCommon    IORegistry helpers, safe IOUSBHostObject init
              DiskGuard       claim / unmount / deny-automount / unclaim
              AgentUsbIo      IOUSBHostInterface, pipes, transfers
              HostDeviceExporter  capture, manifest, lease, release order
              airusb_exportd_main.mm / airusb_agent_main.mm
              scripts/p28_run.sh      the hardware gate, production shape
              scripts/agent_smoke.py  drives the real agent, no root needed
  tests/      TestHarness.h,
              unit/{codec,validate,core,transport,loopback,botprobe,macipc,
                    crypto,noise,identity,session},
              fakes/ScriptedDevice, fuzz/{decode,agentipc,noise},
              vectors/{corpus*/,CryptoVectors.h,NoiseVectors.h}
poc/
  p0-probe/           entitlement authorization matrix
  p1-capture-test/    capture_test.m + 5 runner scripts
docs/
  P0_MACOS_FEASIBILITY.md  P1_IMPLEMENTATION_PLAN.md
  P1_CAPTURE_VERIFICATION.md  P2_8_EXPORTER.md  P2_4_SECURITY.md
  ENTITLEMENT_REQUEST.md  HANDOFF.md
```

Build and test:

```bash
cd "/Users/mba/Desktop/AirUSB Hub/airusb"
cmake -S . -B build && cmake --build build && (cd build && ctest --output-on-failure)
./tests/fuzz/build_and_run.sh 300000

# no root, no hardware capture — drives the real agent binary
python3 platform/macos/scripts/agent_smoke.py build/airusb-agent 0x01200000 1
```

### Design decisions worth not re-litigating

- **No struct overlay on the wire, anywhere.** Coalesced messages start at arbitrary
  alignment; all access is explicit byte loads. A test reads a `u64` from offset 1.
- **Spec correction:** the plan lists HELLO's fields and separately states B = 48,
  but the fields sum to 56 (`session_id[16]` at offset 40). Resolved to **56** — the
  session id is load-bearing for the Noise prologue binding. A test pins the size.
- **R5 (`actual_len <= requested_len`) is the memory-safety-critical rule.** It is
  what stops a buggy or hostile exporter overrunning a kernel transfer buffer whose
  size the importer's own kernel chose. Checked in `Validate` *and* re-asserted at
  the copy site. CVE-2016-3955 class.
- **R6 computes `offset+length` in 64-bit.** A 32-bit sum wraps and a wrapped sum
  passes a naive bounds check. CVE-2017-16911/16912 class.
- **R12 drops silently and is non-fatal.** An epoch mismatch is *expected* after a
  reset; escalating it would turn every legitimate reset into a session teardown.
- **`GET_STATUS` is FORWARD for every recipient.** The endpoint HALT bit is live
  device truth; serving it from cache wedges the drive permanently.
- **`CLEAR_FEATURE(ENDPOINT_HALT)` becomes a verb, not a raw forward** —
  `-clearStallWithError:` also clears the exporter host controller's data toggle,
  and a raw forward does not, leaving every later transfer silently wrong.
- **Link-power features are absorbed**, never forwarded: forwarding drops the
  *exporter's real link* into U1/U2 and destroys throughput.
- **Interrupt endpoints have no deadline** (`kUrbDeadlineIntr = 0`), and
  `IOUSBHostPipe.completionTimeout` **must be 0** for them.
- **`T_urb_ceiling_bulk < T_urb_watchdog_importer`** and
  **`T_detach + t_disconnect < T_lease`** are data-safety properties, not tunables.
  `static_assert`ed in `core/Watchdog.h`.
- **The clock must be continuous across sleep** (`mach_continuous_time`,
  `CLOCK_BOOTTIME`), never `mach_absolute_time` or `steady_clock`. A sleep-blind
  clock is the only way to break the lease ordering.
- **`ScriptedDevice` is a real BOT implementation, not a stub.** It stalls both
  pipes on a CBW that is not exactly 31 bytes, exactly as real firmware does, so a
  transfer-splitting bug fails loudly instead of corrupting a filesystem. SCSI CDB
  fields are **big endian**; `READ CAPACITY(10)` returns the **last LBA**; a BOT
  reset restarts the phase machine but does **not** clear endpoint halts.

---

## 7. Open questions

| # | Question | Blocks | State |
|---|---|---|---|
| **OQ-1** | Is one `NormalTransfer` really one logical URB on a non-control endpoint? | P2.9 correctness | **ANSWERED for the exporter: yes.** Measured on hardware, three ways — 6/6 CBWs accepted as exactly 31 bytes, a 2048-byte read returned in one data phase with residue 0, and a 1024-byte offer answered with 512 and no padding. Still open for the *importer*, where the TD chain is assembled by the kernel rather than by us; that is P2.9's problem. |
| **OQ-2** | FB16524420 | — | **CLOSED.** See §4. |
| **OQ-5** | Will Apple grant the entitlement to this team? | P2.9, P2.10 only | **Not yet filed.** See §8. |
| **OQ-6** | Are `interruptRateHz = 1000`, 16 KiB segments, depth-4 pipeline, 64 urb / 4 MiB credit in the safe direction? | P2.9 | Instrument with counters. `InterruptOverflow` and `DoorbellOverflow` are **fatal**, not merely slow. |
| **OQ-7** | No `API_AVAILABLE` on any IOUSBHostCI header, so the message ABI could shift silently across macOS releases | release | Pin a tested range; treat any `IOUSBHostCIExceptionType` at init as a hard refusal, not a retry. |
| **OQ-8** | Does bulk I/O actually work through pipes the agent obtains while the daemon holds the capture? | P2.8 gate | **CLOSED — yes.** Real CBW → data → CSW completed across the split on 2026-08-08. See §3 and `docs/P2_8_EXPORTER.md` §4. |
| new | Does the exporter's **write** path work, and does it hold up under sustained load? | P2.10 | **Untested.** P2.8's probe is read-only by design, so `bulkOut` has only ever carried 31-byte CBWs and only ~3 KB has moved in total. A defect that appears only on a large OUT transfer would not have been caught. |

**How OQ-1 was measured, since the method matters more than the answer:**
`diag/BotProbe` drives an abstract `IUsbDevicePort`, so the identical code runs
against `ScriptedDevice`'s RAM disk in CI and against the captured drive on
hardware. CI additionally points it at three deliberately broken transports — one
that splits OUT transfers, one that pads IN transfers up to the offered length,
one that fragments at the packet boundary — and requires it to catch each. That is
what makes the hardware `INTACT` worth believing: a broken instrument would have
failed in CI first.

---

## 8. Decisions pending from the user

Neither blocks P2.8.

1. **File the entitlement request.** Procedure, URLs and a ready-to-paste draft are
   in `docs/ENTITLEMENT_REQUEST.md`. Needs Account Holder role. Blocks only P2.9/P2.10.
   Apple approvals were observed as recently as July 2026.
2. **Choose the Team ID** — `WT36SR3Q23` or `GZUV3UMV3B`. The grant lands on one
   team; moving it later means filing again. The account visible in the portal
   (`GZUV3UMV3B`) is populated with sideloading/emulator App IDs, and Apple's review
   asks for "marketing material for your product(s) and/or company".
3. **Bundle ID** — proposed `com.otti83.airusbhub`, not confirmed. Decide before
   filing.

Note for whoever explains the portal: **Xcode's automatic signing registers App IDs
via the Developer API**, as do sideloading tools — that is why the existing App IDs
carry the team ID inside the bundle string and were never created by hand.
`codesign(1)` on a bare binary registers nothing. AirUSB has no App ID because it
has no Xcode project yet.

---

## 9. Next task

### 9.1 THE blocker — only you can clear it

P2.9 (the importer) needs `com.apple.developer.usb.host-controller-interface`.
Requesting it needs the Account Holder role, so it cannot be done from here.
`docs/ENTITLEMENT_REQUEST.md` has the procedure, the URLs and a ready-to-paste
draft. §8 lists the two decisions it depends on: which Team ID, and the bundle
ID. **P2.9, P2.10 and P2.11 are all downstream of this.**

Apple approvals were observed as recently as July 2026, and every confirmed
holder is an Organization team — that risk is unchanged and is why filing early
matters.

### 9.2 Unblocked work, in rough order

1. **Join the two halves.** The exporter works and the session layer works, and
   nothing opens a TCP socket and drives `SecureSession` in front of the
   exporter. This is the biggest remaining piece that needs no entitlement.
2. **`PAIR_REQUEST` / `PAIR_CONFIRM` / `PAIR_RESULT`** and the pairing rate
   limiter. Both sides can already compute the SAS; no message carries the
   confirmation, and nothing enforces the backoff the SAS's one-in-a-million
   bound depends on.
3. **`HELLO` / `HELLO_OK`** — §3.13's second negotiation axis. `session_id[16]`
   at offset 40 is load-bearing for the prologue binding, and the 56-byte HELLO
   size is pinned by a test for exactly that reason.
4. **Identity and pin-store persistence** under
   `/Library/Application Support/AirUSB/`. `LocalIdentity::fromSeed` and
   `PeerStore::save/load` exist and are tested; nothing calls them yet.
5. **The exporter's write path.** P2.8's probe is read-only, so `bulkOut` has
   only ever carried 31-byte CBWs.

### 9.3 Then, once the entitlement lands

- **P2.9** `CiHostBackend` — the entitled half. Blocked on OQ-5 only.
- **P2.10** real ↔ real over 127.0.0.1 on one Mac. **This is where the write path
  and sustained throughput first get tested** — P2.8's probe is read-only by
  design, so `bulkOut` has so far only ever carried 31-byte CBWs.
- **P2.11** two Macs, wired → Wi-Fi → roam/sleep matrix.

Explicitly out of Phase 2: isochronous, USB3 streams, external hubs, multi-link,
session resume, QUIC, Windows, Linux, mDNS discovery.

---

## 10. Reproduction commands

```bash
# Software, no hardware, no root
cd "/Users/mba/Desktop/AirUSB Hub/airusb"
cmake -S . -B build && cmake --build build && (cd build && ctest --output-on-failure)
./tests/fuzz/build_and_run.sh 300000

# Entitlement authorization matrix (no root)
"/Users/mba/Desktop/AirUSB Hub/poc/p0-probe/run_probe.sh"

# USB tooling — build first
cd "/Users/mba/Desktop/AirUSB Hub/poc/p1-capture-test" && ./build.sh

./capture_test                              # list devices, read-only
./capture_test --probe-interface 058f:6387  # non-destructive, no root, any context
./run_as_agent.sh 058f:6387                 # LaunchAgent, NO sudo

# These need the user to run them (sudo is blocked for the assistant):
sudo ./capture_test --capture 058f:6387     # full lifecycle
sudo ./run_as_daemon.sh 058f:6387           # LaunchDaemon
sudo ./run_matrix.sh 058f:6387              # five execution contexts
sudo ./run_split_test.sh 058f:6387          # the split-architecture test
```

### P2.8 — the real exporter

```bash
cd "/Users/mba/Desktop/AirUSB Hub/airusb"
cmake -S . -B build && cmake --build build

./build/airusb-exportd --list                          # read-only, no root
python3 platform/macos/scripts/agent_smoke.py \
        build/airusb-agent 0x01200000 1                # real agent, no root

# THE GATE — needs the user:
sudo ./platform/macos/scripts/p28_run.sh 058f:6387
```

`--probe-interface` performs no unmount and no capture and is safe anywhere.
