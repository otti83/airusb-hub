# P2.8 — the real macOS exporter

**Status: PASS.** Software gate and hardware gate both passed on 2026-08-08
against the real 058f:6387 SuperSpeed flash drive. OQ-1 answered: transfer
boundaries INTACT. Full evidence in §4.

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

**PASS.** `sudo ./platform/macos/scripts/p28_run.sh 058f:6387` on macOS 26.5.1,
Apple M1, SIP enabled. Real 058f:6387 Generic Flash Disk, SuperSpeed 5 Gb/s,
31.46 GB exFAT. Logs: `/tmp/airusb_p28_exportd.log`, `/tmp/airusb_p28_agent.log`.

### 4.1 The split, in the production shape

Both halves ran as real launchd jobs, neither from a terminal:

```
[exportd] airusb-exportd starting: pid=54696 euid=0   ppid=1 (launchd)   system session
[agent]   airusb-agent   starting: pid=54326 euid=501 ppid=1 (launchd)   Aqua session
[exportd] agent connected: uid=501 pid=54326          uid from getpeereid(2)
```

The daemon captured; the agent — unprivileged, in a different security session —
opened the interface and got both pipes:

```
[agent] 1 interface nub(s) present
[agent] interface 0 alt 0: class=08/06/50 endpoints=2
[agent]   endpoint 0x81 type=2 maxPacket=1024 burst=2
[agent]   endpoint 0x02 type=2 maxPacket=1024 burst=2
[agent] pipe table generation 1: 2 endpoint(s) across 1 interface(s)
```

`maxPacket=1024` with a burst is SuperSpeed bulk. No USB 2.0 downgrade occurred.

### 4.2 The gate itself — CBW → data → CSW across the split

```
CBW  tag=1 op=0x00 len=0    -> OK moved=31
CSW  tag=1 -> OK got=13 [55 53 42 53 01 00 00 00 00 00 00 00 00]
CBW  tag=2 op=0x12 len=36   -> OK moved=31
DATA tag=2 offered=36   -> OK got=36
CSW  tag=2 -> OK got=13 [55 53 42 53 02 00 00 00 00 00 00 00 00]
CBW  tag=3 op=0x25 len=8    -> OK moved=31
DATA tag=3 offered=8    -> OK got=8
CBW  tag=4 op=0x28 len=512  -> OK moved=31
DATA tag=4 offered=512  -> OK got=512
CBW  tag=5 op=0x28 len=512  -> OK moved=31
DATA tag=5 offered=1024 -> OK got=512      <- short read preserved
CBW  tag=6 op=0x28 len=2048 -> OK moved=31
DATA tag=6 offered=2048 -> OK got=2048     <- one transfer, not two packets
CSW  tag=6 -> OK got=13 [55 53 42 53 06 00 00 00 00 00 00 00 00]
```

```
verdict=PASS  cbw=6 data=5 csw=6 stallRecoveries=0 shortReads=0 boundariesIntact=yes
  GET_MAX_LUN          ok   bMaxLUN=0
  TEST_UNIT_READY      ok
  INQUIRY              ok   'Generic' 'Flash Disk' rev '8.01' type=0x00 removable=yes
  READ_CAPACITY_10     ok   lastLBA=61439999 blockSize=512 -> 61440000 blocks, 31.46 GB
  READ_10_LBA0         ok   512 bytes, residue=0, bootsig=55AA
  SHORT_READ_FIDELITY  ok   offered 1024, device sent 512 — short read preserved
  READ_10_MULTIBLOCK   ok   2048 bytes in one transfer, residue=0
```

Sector 0, read through the whole split path:

```
fa b8 00 00 8e d0 bc 00 7c 8b f4 50 07 50 1f fb fc bf 00 06 b9 00 01 f3 a5 ea 1e 06 00 00 be be
boot signature 55AA: present
```

That is a real x86 MBR boot sector (`cli; mov ax,0; mov ss,ax; mov sp,0x7c00; ...`),
not a plausible-looking buffer. `READ_CAPACITY_10` reported 61,439,999 as the
**last LBA**, giving 61,440,000 blocks — 31.46 GB, matching the 31.5 GB drive.

### 4.3 OQ-1 — ANSWERED

```
OQ-1: transfer boundaries INTACT — one NormalTransfer is one logical URB on this path
```

Three independent measurements support it, and the instrument that made them is
required by CI to fail on transports that break each one:

| measurement | result | what it rules out |
|---|---|---|
| every CBW `moved=31` | 6/6 | the layer beneath splitting an OUT transfer |
| offered 1024, got 512, residue 0 | ✅ | padding a short read up to the offered length |
| 2048 bytes in one data phase, residue 0 | ✅ | fragmenting at the 1024-byte packet boundary |

`stallRecoveries=0` and every CSW signature/tag correct means the phase machine
never desynchronised.

**One `NormalTransfer` is one logical URB on this path.** OQ-1 is closed for the
macOS exporter. It remains open for the *importer* side, where the TD chain is
assembled by the kernel rather than by us — that is P2.9's problem, not this one.

### 4.4 Restore

```
[exportd] destroying the captured device (reset + driver rematch)
[exportd] releasing 1 disk claim(s)
[exportd] RESULT=RESTORED lease held 0.1 s
...
restore: drive back on this Mac = yes
mount table matches the 'before' state exactly
```

`/dev/disk22s1 on /Volumes/Memory 32GB` was present before and after, byte-identical
mount table. Plain `destroy` → reset → driver re-match → automount worked as
designed, and the deny-automount approval callback correctly stopped denying once
unregistered.

### 4.5 A NEW finding: the Apple exception is not confined to the open path

```
[exportd] descriptorWithType:6 raised NSInvalidArgumentException:
          *** -[__NSPlaceholderDictionary initWithObjects:forKeys:count:]:
          attempt to insert nil object from objects[0]
```

`P1_CAPTURE_VERIFICATION.md` diagnosed this defect on
`-[IOUSBHostObject openWithOptions:error:]`. It is the same fault in
`-[IOUSBHostObject descriptorWithType:length:index:languageID:error:]`: when the
device STALLs, the framework builds an `NSError` userInfo from three
`-[NSBundle localizedStringForKey:]` results and raises because the first is nil.

**This is the `@try`/`@catch` rule earning its keep on the production path.**
Without it, a root daemon would have died at that line while holding a captured,
unmounted drive — the user's disk left claimed and unmountable until reboot. The
exception was caught, the manifest completed, and the gate passed.

Two changes followed:

1. The catch block now names the defect and cites this run, so the next person to
   see `objects[0]` in a log does not re-derive it.
2. **The request is no longer made at all on SuperSpeed.** DEVICE_QUALIFIER is
   defined by USB 2.0 §9.6.2 only for high-speed-capable devices and is not
   defined for SuperSpeed, so the STALL was correct device behaviour. There is no
   reason to provoke a known-buggy Apple path to ask a question the specification
   has already answered. `Full`/`High` still ask; everything else does not.

The wrapping stays everywhere regardless — the lesson of this finding is that the
defect appears in places it had not been observed in before, so the defence
cannot be narrowed to the sites where it has been seen.

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

- **The gate proves the path, not the throughput.** Six commands and 3 KB moved.
  Sustained multi-gigabyte transfer, and the write path, are P2.10's job. Nothing
  here has been measured under load.
- **The write path is untested by construction.** The probe is read-only, so
  `bulkOut` is exercised only by 31-byte CBWs. A defect that only shows up on a
  large OUT transfer would not have been caught.
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

- **P2.4** security: Noise_XX + Noise_IK. `IRecordCipher` is the slot; `NullCipher`
  is the current stand-in.
- **P2.9** `CiHostBackend` — the entitled half. Blocked on OQ-5 (the entitlement)
  only.
- **P2.10** real ↔ real over 127.0.0.1 on one Mac.
