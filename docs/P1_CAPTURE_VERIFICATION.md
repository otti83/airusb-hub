# P1 — Exporter Capture Verification

**Date:** 2026-08-08
**Host:** macOS 26.5.1 (25F80), Apple M1 (T8103), SIP enabled, Secure Boot Reduced
**Device:** `058f:6387` Generic Mass Storage, 31.5 GB exFAT, **SuperSpeed 5 Gb/s**
**Tools:** `poc/p1-capture-test/`

**Resolves:** P0 open risk #2 (FB16524420) and P1 OQ-2.

---

## Verdict

**The exporter is viable, but it must be split across two processes.**

FB16524420 reproduces on macOS 26.5.1. The cause is not what the radar describes,
and not what this project first assumed. It is **security-session membership**, not
privilege, not the TCC status of the binary's path, and not an IOUSBHost bug.

```
root LaunchDaemon      : DiskArbitration unmount + IOUSBHostDevice capture + lifecycle
console-session agent  : IOUSBHostInterface + IOUSBHostPipe + bulk/interrupt transfers
```

Both halves are verified on real hardware, and the two were verified working
**simultaneously against the same device**.

---

## 1. The permission map

Measured, not inferred. Each cell is a real run against the real device.

| Operation | needs root | needs console session |
|---|---|---|
| DiskArbitration whole-disk unmount | **yes** — `0xF8DA0009` `kDAReturnNotPrivileged` | no |
| `IOUSBHostDevice` + `…OptionsDeviceCapture` | **yes** | **no** — works under launchd |
| `sendDeviceRequest` on ep0 | with the above | no |
| `configureWithValue:matchInterfaces:NO` | with the above | no |
| **`IOUSBHostInterface` open** | **no** — succeeds as uid 501 | **yes** |

No process in a shippable macOS product can be both root and a member of the console
session: `SMAppService.daemon` runs in the system session, `SMAppService.agent` runs
in the console session but as the user. Hence the split.

---

## 2. How the discriminator was isolated

`run_matrix.sh`, five contexts, one device, raw `IOServiceOpen` on the interface nub:

| | context | raw open | |
|---|---|---|---|
| A | direct — root, console session | `0x00000000` | SUCCESS |
| B | LaunchDaemon — root, system session | `0xE00002E2` | `kIOReturnNotPermitted` |
| C | LaunchDaemon + `SessionCreate` | `0xE00002E2` | `kIOReturnNotPermitted` |
| D | `launchctl asuser 501` — root, console session | `0x00000000` | SUCCESS |
| E | LaunchDaemon, binary staged to `/usr/local/libexec` | `0xE00002E2` | `kIOReturnNotPermitted` |

**E refutes the TCC-path hypothesis.** Moving the binary out of `~/Desktop` changed
nothing, so the protected path was never the cause of the denial.

**C refutes `SessionCreate`.** Creating a *new* security session does not help; the
check wants the *console* session specifically.

The kernel names the gate outright:

```
(Sandbox) System Policy: capture_test(20182) deny(1) iokit-open-service IOUSBHostInterface
(Sandbox) System Policy: configd(342)        deny(1) iokit-open-service IOUSBHostInterface
```

Apple's own `configd` is denied identically, which is a useful sanity check that this
is a blanket policy rather than something about our binary.

Then the measurement that settled it — a **non-root** process in the console session:

```
probe: euid=501 ppid=22958 no-tty
raw IOServiceOpen(interface 0, type=0) -> 0x00000000 (SUCCESS)
```

Root is not required. Compare the two launchd-parented runs, which differ in
*nothing* but session:

| | uid | ppid | tty | session | result |
|---|---|---|---|---|---|
| LaunchDaemon | 0 | 1 | none | system | **denied** |
| LaunchAgent | 501 | 1 | none | Aqua | **success** |

Same parent, same absence of a controlling terminal, *less* privilege — and it works.
Session membership is the entire variable.

---

## 3. The split, verified end to end

`run_split_test.sh`: a root LaunchDaemon captures the device and holds it for 25 s
while a separate non-root console-session process opens the interface.

```
=== step 1: root LaunchDaemon captures 058f:6387 and holds it 25s ===
  RESULT=DEVICE_CAPTURED
  interface nubs republished: 1
  HOLDING capture for 25s

=== step 2: non-root console-session process probes the interface ===
  raw IOServiceOpen(interface 0, type=0) -> 0x00000000 (SUCCESS)
  VERDICT=PASS

=== step 3 ===
  RESULT=RESTORED (hold mode)

SPLIT IS VIABLE
```

And in the actual production shape, a real LaunchAgent:

```
probe: euid=501 ppid=1 launchd
raw IOServiceOpen(interface 0, type=0) -> 0x00000000 (SUCCESS)
```

### What is proven, and what is not

**Proven:** the interface user client can be opened, from the production process
shape, while a different root process holds the device capture.

**Not yet proven:** actual bulk transfers through pipes obtained that way, with the
daemon holding the device. `copyPipeWithAddress:` and a real CBW/data/CSW exchange
are P2.8. The *gate* that was blocking is passed; the plumbing behind it is untested.

---

## 4. The exception was a second, separate Apple bug

Under launchd the process did not merely fail — it died:

```
-[IOUSBHostObject openWithOptions:error:] + 432
NSInvalidArgumentException: attempt to insert nil object from objects[0]
```

Disassembly (lldb, arm64e) shows why. `IOServiceOpen` fails at +168; the framework
falls through to build an `NSError` userInfo from three
`-[NSBundle localizedStringForKey:…]` results (+208…+404) and raises at +428 because
one is nil. `objects[0]` is the first value, so `+[NSBundle mainBundle]` itself
returned nil — a message to a nil receiver returns nil.

Two consequences, both binding on the real exporter:

1. **Every `IOUSBHostObject` init must be wrapped in `@try`/`@catch`.** Apple's error
   path can raise instead of returning an `NSError`. A root exporter daemon that dies
   from an uncaught exception takes the captured device down with it and leaves the
   user's drive unmounted.
2. **Never rely on the `NSError`.** Call `IOServiceOpen` directly when the real
   `IOReturn` matters; the framework destroys it on this path.

An earlier revision of this document blamed the third `localizedStringForKey:` call,
which does pass a nil key at +376. That was wrong — the exception names `objects[0]`,
and tracing the stores at +268/+340/+404 shows `objects[0]` is the *first* value.

---

## 5. Device facts worth carrying into Phase 2

```
bcdUSB 0x0320, bMaxPacketSize0 = 9 (exponent -> 512), numConfigurations = 1
config[0]: bConfigurationValue=1, wTotalLength=44, bNumInterfaces=1
interface 0 alt 0: class 08/06/50 -> Mass Storage / SCSI transparent /
                   Bulk-Only Transport, 2 endpoints
USBSpeed = 4 (Super), UsbLinkSpeed = 5,000,000,000
GET_DESCRIPTOR(DEVICE) -> 18 bytes, 12 01 20 03 …
```

**The device runs at SuperSpeed, not High Speed.** The IORegistry exposes two speed
properties with *different* enumerations, and reading the wrong one silently
misreports USB 3 as USB 2:

| property | enumeration | value | means |
|---|---|---|---|
| `Device Speed` | legacy: Low=0, Full=1, High=2, **Super=3** | 3 | Super |
| `USBSpeed` | `tIOUSBHostConnectionSpeed`: …, **High=3**, Super=4 | 4 | Super |

The same integer `3` means *High* in one and *Super* in the other. The tool now reads
`USBSpeed` and cross-checks `UsbLinkSpeed`.

Consequence: the Phase 2 manifest must carry the BOS descriptor and SuperSpeed
Endpoint Companion descriptors (`bDescriptorType` 0x30). AirUSB passes descriptors
through verbatim, so this costs nothing — but a design that assumed USB 2.0 would
have broken here.

---

## 6. What this changes in the plan

`P1_IMPLEMENTATION_PLAN.md` §7 assumed a single root daemon owns the whole exporter.
That is now false. Required changes:

- §7.2 capture order splits across two processes, with the interface phase moved to
  the session agent.
- §7.4's FB16524420 mitigation ladder is obsolete. Neither rung was the answer:
  `matchInterfaces:NO` is still necessary (it stops `IOUSBMassStorageDriver`
  re-attaching) but is not sufficient, and retrying with `DeviceCapture` on the
  interface fails identically.
- A daemon↔agent IPC contract is now a Phase 2 deliverable: the daemon owns the
  lease and the device capture, the agent owns the interfaces and the transfer plane.
- The agent must handle the daemon dying, and the daemon must handle the agent dying,
  without leaving the drive captured-but-unused. The exclusivity theorem in §7.1 has
  to be restated over two processes.

---

## 7. Reproducing

```
./build.sh
./capture_test                                   # list devices (read-only)
./capture_test --probe-interface 058f:6387       # non-destructive, no root
sudo ./run_matrix.sh 058f:6387                   # five execution contexts
sudo ./run_split_test.sh 058f:6387               # the split-architecture test
./run_as_agent.sh 058f:6387                      # LaunchAgent, no sudo
sudo ./run_as_daemon.sh 058f:6387                # LaunchDaemon
```

`--probe-interface` performs no unmount and no capture, so it is safe in any context.
