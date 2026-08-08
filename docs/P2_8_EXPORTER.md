# P2.8 — the real macOS exporter

**Status: implemented; software gate PASSED; hardware gate NOT YET RUN.**
The hardware gate needs one `sudo` command, which the assistant cannot issue. It
is in §6.

---

## 1. Goal

Build the exporter half described in `P1_CAPTURE_VERIFICATION.md` — a root
LaunchDaemon plus a console-session LaunchAgent — and settle the one step that
was still unproven at the end of P1:

> Bulk transfers through pipes the **agent** obtains while the **daemon** holds
> the capture. The gate is passed; the plumbing behind it is untested.

P1 proved a console-session process may *open* an interface on a device another
process captured. It never moved a byte through one. P2.8's gate is a real
CBW → data → CSW exchange across that split.

---

## 2. What was built

```
airusb/
  core/IUsbDevicePort.h          one interface, two implementations
  diag/BotProbe.{h,cpp}          read-only Bulk-Only Transport prober (portable)
  platform/macos/
    StatusMapMacos.{h,cpp}       IOReturn -> AirUsbStatus, pure C++
    AgentProtocol.{h,cpp}        daemon<->agent IPC codec, pure C++
    AgentLink.{h,cpp}            framed unix-socket transport, plain POSIX
    MacUsbCommon.{h,mm}          IORegistry helpers, safe IOUSBHostObject init
    DiskGuard.{h,mm}             DADiskClaim / unmount / approval-deny / unclaim
    AgentUsbIo.{h,mm}            IOUSBHostInterface + pipes + transfers
    HostDeviceExporter.{h,mm}    capture, manifest, lease, release order
    airusb_exportd_main.mm       the root daemon
    airusb_agent_main.mm         the console-session agent
    scripts/p28_run.sh           the hardware gate, production shape
    scripts/agent_smoke.py       drives the real agent binary, no root needed
  tests/unit/test_botprobe.cpp   the prober, against a RAM-disk device
  tests/unit/test_macipc.cpp     the IPC codec and the real socket path
  tests/fuzz/fuzz_agentipc.cpp   the IPC parser
```

### 2.1 The design decision that makes the gate trustworthy

`diag/BotProbe` drives an abstract `IUsbDevicePort`, and there are two
implementations:

| implementation | what it is | where it runs |
|---|---|---|
| `tests/fakes/ScriptedDevice` | a real BOT/SCSI device over a RAM disk | CI, every commit |
| `platform/macos/HostDeviceExporter` | a real captured USB device | hardware only |

The identical prober runs against both. This matters because a diagnostic that
has only ever run against hardware cannot be trusted when it fails: a FAIL would
be equally consistent with a broken diagnostic. `test_botprobe` additionally
points the prober at three *deliberately broken* transports — one that splits OUT
transfers, one that pads IN transfers up to the offered length, one that
fragments at the packet boundary — and requires it to catch each. So on hardware,
a PASS means the transport is right and a FAIL means the transport is wrong.

### 2.2 The split, and who does what

```
airusb-exportd   root LaunchDaemon        DiskArbitration claim + unmount
                 (system session)         IOUSBHostDevice + DeviceCapture
                                          configureWithValue:matchInterfaces:NO
                                          the manifest
                                          endpoint 0 (control transfers)
                                          the lease, and releasing it
       │  unix socket, framed, one request in flight
       ▼
airusb-agent     LaunchAgent              IOUSBHostInterface
                 (console Aqua session,   copyPipeWithAddress:
                  unprivileged)           bulk / interrupt transfers
                                          clearStallWithError:
```

`HostDeviceExporter` implements `IUsbDevicePort` by routing ep0 to its own
captured device and bulk to the agent. The split is invisible above that line.

### 2.3 Things that are load-bearing, not stylistic

- **`matchInterfaces:` is always `NO`.** `YES` invites `IOUSBMassStorageDriver` to
  match and mount the drive locally while it is leased out.
- **The `DADiskClaim` is held for the entire lease**, plus a mount-approval
  callback that denies automounts of the claimed disks. Two independent barriers:
  capture at the driver layer, claim at the mount layer.
- **Release order is agent-close → plain `destroy` → `DADiskUnclaim`.** Plain
  destroy resets the device and re-registers drivers, which is what makes the
  drive remount locally. `DeviceSurrender` does the opposite and is only correct
  when honouring `kUSBHostMessageDeviceIsRequestingClose`. Unclaiming before the
  destroy reopens the automount window while the device is still captured.
- **Every `IOUSBHostObject` init is wrapped in `@try`/`@catch`**, and the real
  `IOReturn` comes from a direct `IOServiceOpen` probe rather than from the
  framework's `NSError`, which it destroys on the failure path.
- **`completionTimeout` is 0 for interrupt pipes**, per `IOUSBHostPipe.h`.
- **A stale pipe-table generation fails with `XferEpStopped`** rather than being
  issued on a pipe that may now belong to a different alternate setting.
- **The peer uid comes from `getpeereid(2)`**, not from the handshake. The daemon
  is root; believing a self-reported identity would make the check decorative.

---

## 3. Evidence — software gate

All of this runs with no hardware and no root, on every commit.

```
$ cmake -S . -B build && cmake --build build && (cd build && ctest --output-on-failure)
100% tests passed, 0 tests failed out of 7

    test_codec  test_validate  test_core  test_transport  test_loopback
    test_botprobe   NEW   the prober vs. a RAM-disk device + 3 broken transports
    test_macipc     NEW   the IPC codec, and AgentLink over a real socketpair
```

Zero warnings under `-Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion
-Wshadow`, Objective-C++ included.

```
$ ./tests/fuzz/build_and_run.sh 150000
fuzz_decode    150000 runs, 0 crashes, 0 UB findings
fuzz_agentipc  150000 runs, 0 crashes, 0 UB findings
```

### 3.1 A defect the IPC fuzzer found, and the fix

`decodeXferReq` accepted a frame declaring `length == 0` while carrying a
non-empty payload. A caller reading the length from the field and the data from
the payload would have disagreed with itself about how much data there was —
CVE-2016-3955 in miniature, in a parser a root process runs on bytes from an
unprivileged one.

The root cause was that one struct meant two things: for `BULK_OUT`, `length`
counts the bytes that follow; for `BULK_IN` it is the size of a buffer being
offered and nothing follows. The decoder was inferring which, and the inference
had an ambiguous case.

Fixed by making the caller state which it expects (`XferPayload::None` /
`::Present`) and requiring exact agreement in both directions. Regression tests in
`test_macipc`; the fuzzer asserts it unconditionally.

### 3.2 The real agent binary, without root

`scripts/agent_smoke.py` launches the shipping `airusb-agent` and drives it from a
fake daemon that speaks the wire format by hand — a second opinion, since a bug
present in both the encoder and the decoder is invisible to a round-trip test.

```
$ python3 platform/macos/scripts/agent_smoke.py build/airusb-agent 0x01200000 1
  agent connected
  HELLO ok: version=1 pid=99305 euid=501
  OPEN_INTERFACES -> INTERNAL (0xE00002C9 expected here)
  CLOSE acknowledged
  the agent exited cleanly
  unknown opcode closed the connection (exit 0) — fatal, as intended
agent_smoke: PASS
```

The interesting line is in the agent's own log:

```
interface 0 open failed: 0xE00002C9 kIOReturnInternalError
  ^ the security session is FINE (a raw open of this service returns
    0x00000000 kIOReturnSuccess). The framework's open is what failed — the
    usual cause is that a driver still holds the interface because no capture
    is in effect.
```

That is the correct and expected result with nothing captured: `0xE00002C9` is
the FB16524420 signature, but here it simply means `IOUSBMassStorageDriver` owns
the interface, which is exactly why the daemon must capture first. The direct
`IOServiceOpen` succeeding proves the System Policy gate — the one that forced the
two-process design — passes in this session.

**This distinction is now printed by the agent itself.** Anyone who hits
`0xE00002C9` in future gets told immediately whether the session gate failed or
whether a driver simply still owns the interface. Those look identical and mean
opposite things.

Because the plain framework open can fail this way, `AgentUsbIo` now falls back to
`IOUSBHostObjectInitOptionsDeviceCapture` on the interface if the plain open does
not take — the same fallback `poc/p1-capture-test/capture_test.m` used.

---

## 4. Evidence — hardware gate

**NOT YET RUN.** See §6.

---

## 5. What the hardware gate will report

`p28_run.sh` installs both halves as real launchd jobs — a LaunchDaemon in the
system session and a LaunchAgent in the console user's Aqua session. Neither is
started from the terminal, because a terminal-launched process inherits the
console session and would pass a test the shipping configuration fails. Launch
context is load-bearing; that was P1's central finding.

It then prints one of:

| verdict | meaning |
|---|---|
| `P2.8 GATE: PASS` | CBW → data → CSW completed across the split. Also reports whether transfer boundaries survived, which is OQ-1. |
| `P2.8 GATE: FAIL` | The exchange was reached but did not survive. The prober names the failing step and why. |
| `P2.8 GATE: BLOCKED` | The device was never captured, so the transfer path was not reached. If the agent logs `System Policy denied`, the split architecture itself needs re-examining. |

It also checks that the drive came back: the device must re-enumerate **with block
media beneath it**, and the mount table is diffed against the state recorded
before the run. Restore is half of the safety story and is verified, not assumed.

---

## 6. Running the hardware gate

```bash
cd "/Users/mba/Desktop/AirUSB Hub/airusb"
cmake -S . -B build && cmake --build build
sudo ./platform/macos/scripts/p28_run.sh 058f:6387
```

The probe is **read-only** — `GET_MAX_LUN`, `TEST UNIT READY`, `INQUIRY`,
`READ CAPACITY(10)`, `READ(10)`. Not one byte is written to the medium. The drive
is unmounted before capture and handed back afterwards, and if any unmount is
refused the run aborts before anything is captured. The boot disk is refused
outright. Use a drive you do not care about anyway.

Logs are kept at `/tmp/airusb_p28_exportd.log` and `/tmp/airusb_p28_agent.log`.

---

## 7. Known issues and deliberate limits

- **The hardware gate has not been run.** Everything above the hardware line is
  verified; the last step is one command.
- **`OQ-1` is instrumented but not yet answered.** The prober measures whether one
  logical transfer survives as one logical transfer — a 31-byte CBW accepted whole,
  a multi-block read returned in one transfer, a short read staying short — and the
  daemon prints `OQ-1: transfer boundaries INTACT|VIOLATED`. The answer arrives
  with the hardware run.
- **One request in flight per socket.** Deliberate: USB already serialises per
  endpoint, and a pipelined local IPC would add a reordering hazard between a
  transfer and the `CLEAR_HALT` that recovers it. Throughput work belongs after
  correctness.
- **No `SUSPEND_IO`/`RESUME_IO`, no `ORPHANED` state, no lease timer expiry.** The
  daemon releases on agent death, which is the case P2.8 needs. The full state
  machine of §7.3 arrives with the session layer.
- **Isochronous is not implemented.** Out of scope for Phase 2.
- **The socket is mode 0666 with a `getpeereid` uid check.** Correct for a PoC on
  one machine. A shipping product should use an `SMAppService` XPC MachService,
  which removes the filesystem rendezvous entirely.
- **`configureWithValue:0` is attempted and tolerated on failure.** Some devices
  refuse configuration 0; the subsequent select is what matters.

---

## 8. Next

- Run §6 and paste the output. That closes the gate and answers OQ-1.
- **P2.4** security: Noise_XX + Noise_IK. `IRecordCipher` is the slot; `NullCipher`
  is the current stand-in.
- **P2.9** `CiHostBackend` — the entitled half. Blocked on OQ-5 (the entitlement)
  only.
- **P2.10** real ↔ real over 127.0.0.1 on one Mac.
