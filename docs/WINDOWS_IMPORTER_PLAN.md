# The Windows importer — UdeCx, gate by gate

**Goal.** Windows enumerates a device that is plugged into another machine, binds
its own driver, and a flash drive appears in Explorer.

**Nobody's permission is needed.** Development requires test signing, which is
self-service (`bcdedit /set testsigning on`); distribution requires an EV
certificate and Microsoft attestation, which is a paid process rather than a
discretionary approval. Compare the macOS importer, which cannot run at all
without an entitlement Apple grants by hand.

This plan copies the shape of [`LINUX_IMPORTER_PLAN.md`](LINUX_IMPORTER_PLAN.md),
because that shape worked: **build everything that can be tested without a kernel
first, prove it, and only then put a kernel in the loop.** The Linux importer's
three hard cores (segmentation, the async data plane, the non-blocking bridge)
were all finished and green before a single line ran against `vhci-hcd`, and the
on-kernel bring-up then took one session. The reason to repeat it here is
sharper: a bug in a KMDF driver is a bugcheck on a machine reachable only by
RDP, and each iteration costs a reboot somebody has to be present for.

---

## The shape

```
airusb.sys  (KMDF + UdeCx, kernel mode)         W4 — cannot be built or run here
    │  IOCTL_INTERNAL_USB_SUBMIT_URB from the guest's drivers
    │
    └── inverted call: N parked "give me the next URB" IOCTLs.
        Payload travels in the IOCTL buffer (METHOD_OUT_DIRECT down,
        METHOD_IN_DIRECT up) — NOT a shared arena; see W1 for why that
        idea was removed rather than hardened.
    │
    ▼
airusb-winhost.exe  (user mode, no privileges)  W5
    │
    ▼
UdecxBridge          the translation                 W3 — portable, testable here
    │
    ▼
ImporterDataPlane → ImporterClient → the network      already built and proven
```

The split is forced: a kernel-mode driver cannot host the protocol or the
transport. What is NOT forced, and is the design decision worth stating, is that
**the kernel side stays as thin as it can possibly be.** Everything that can be
decided in user mode is decided in user mode, because that is the half that can
be unit-tested, fuzzed, sanitised and debugged without rebooting anything.

---

## Gates

Each gate is Goal / Evidence / PASS, and a failed gate does not advance.

### W1 — the driver↔host channel, fuzzed · **DONE, 2026-08-09**

**Goal.** A codec for the records crossing between `airusb.sys` and the
user-mode host, written portably and fuzzed, because it is an ABI whose
user-mode end is unprivileged and whose kernel end is not.

**The design was reviewed before implementation (GPT-5.6, read-only) and the
review deleted a whole subsystem.** The original plan had a shared-memory arena
carved into slots by the driver, with the host naming a slot index and "never
choosing an offset". That claim is false:

> Once the whole section is writable in its process, the host can write every
> byte of every slot at any time. Slot indices restrict what the protocol
> accepts; they do not restrict memory access.

So there is **no arena**. Payload rides in the IOCTL buffer —
`METHOD_OUT_DIRECT` for work going down, `METHOD_IN_DIRECT` for completions
coming up — and the I/O manager probes and locks the pages, handing the driver
an MDL whose length is authoritative. That does not mitigate slot arithmetic,
mapping lifetime, stale-slot disclosure and slot quarantine; it deletes them. An
arena can come back later if measurement demands it, carrying **payload only and
never metadata**.

**What the format enforces, and why each rule exists:**

* **Identity is more than a request id.** Every record carries a session
  incarnation (random, per binding) and a device incarnation (bumped per
  plug-in), and ids are never reused within a session. "Unique while
  outstanding" is not enough: a late completion arriving after a plug-out and
  re-plug would otherwise land on a fresh request that reused the number.
* **Endpoint address is not endpoint identity** — alternate settings reuse
  addresses. Endpoints are named by an opaque driver-assigned id.
* **No raw kernel constants on the wire.** `USBD_STATUS` and USBD transfer flags
  stay inside the driver; the wire carries a small abstract result enum. This
  keeps the ABI from becoming Windows-shaped, and — the load-bearing part —
  means the short-transfer decision is made by the side that holds
  `USBD_SHORT_TRANSFER_OK`, which is the driver, never the unprivileged host.
* **One length, not two.** A payload length that can disagree with the record
  length is a bug waiting for someone to check the wrong one.
* **Configure is a transaction, not a ticket acknowledgement.** It carries the
  set to enable AND the set to release. The released set is the one that
  matters: touching a released endpoint's queue afterwards is a use-after-free
  on a kernel object.
* **Cancel is a notification, never a prerequisite.** The driver completes the
  guest's URB the moment cancellation wins and does not wait for the far side.

**And what it deliberately does NOT refuse.** A short successful transfer, a
zero-length transfer, partial progress alongside a failure, and a completion for
a request that has already been retired are ordinary USB lifecycle events. A
codec that called those malformed would make routine cancellation
indistinguishable from an attack.

**Evidence.** `tests/unit/test_udecxipc.cpp` (100 checks): round trips, then one
case per deviation — truncation, a length that disagrees with the buffer in
either direction, trailing bytes, a wrong version, a record decoded as the wrong
opcode, every reserved byte, out-of-range enums, undefined flag bits, a payload
disagreeing with its header, a setup packet on a non-control transfer, a length
past the cap, a configure whose counts do not match its body, a configure naming
both a configuration and an alternate setting, a bool that is neither 0 nor 1,
and an unknown opcode. Plus `tests/fuzz/fuzz_udecxipc.cpp`, seeded with eleven
valid records, which asserts more than absence of crashes: **anything the
decoder accepts must re-encode to identical bytes**, because a decoder that
normalises accepts two spellings of one record.

400 000 executions, coverage 243, no crashes and no round-trip violations.

**PASS.**

### What the same review says about W3 and W4 — do not rediscover these

Recorded here because they cost nothing now and a bugcheck later.

* **Purge must not wait for the network.** During purge every forwarded request
  must be completed and new ones must fail, and only then may the driver call
  `UdecxUsbEndpointPurgeComplete`. Making a remote acknowledgement a
  prerequisite lets a dead or malicious host wedge UdeCx permanently.
* **Endpoint reset is not cancellation.** It means clear the halt and restore
  data-toggle semantics, and it is an asynchronous `WDFREQUEST` that must be
  completed after the exporter has done it or failed.
* **One request state machine**, `QUEUED → EXPORTED → COMPLETING → RETIRED`,
  with cancellation and completion competing for exactly one transition out of
  `EXPORTED`. KMDF requires winning `WdfRequestUnmarkCancelable` before an
  ordinary completion; if it returns `STATUS_CANCELLED`, the cancel path owns
  the request and completing it again is a double completion.
* **Complete UDE URBs at `DISPATCH_LEVEL`**, on a separate DPC where necessary,
  including cancellations. `UdecxUsbDevicePlugOutAndDelete` is `PASSIVE_LEVEL`.
* **Snapshot the whole IOCTL buffer before walking nested lengths**, and never
  retain a pointer into it after completing that IOCTL. This applies hardest to
  the manifest, whose `bLength`/`wTotalLength`/counts are all bounds.
* **Zero a buffer before it is exposed.** A short transfer otherwise lets user
  mode read whatever a previous guest transfer left behind.
* **Bind everything to one `WDFFILEOBJECT` session**, and on cleanup atomically
  disconnect devices and retire requests. Two handles must never implicitly
  share a session.
* **A malformed completion that names a live request must retire that request**
  with a driver-chosen failure. Merely rejecting the IOCTL leaves the guest's
  URB hanging forever.

**And one finding that is not a memory-safety issue at all**, which is why it is
easy to miss: an unprivileged process that can call `plugIn` can present
*arbitrary USB identities* to Windows and make it load guest kernel drivers
against attacker-chosen descriptors and traffic. That is a local "malicious USB
device" capability. The control device needs a restrictive ACL, and **who is
allowed to plug in has to be a decision this project makes explicitly** rather
than inherits from "the host is unprivileged, so it is safe". It is not the same
question, and W4 must answer it before the driver ships to anyone.

### W2 — the speed and status tables · **DONE, 2026-08-09**

**Goal.** `airusb::Speed` ↔ `UDECX_USB_DEVICE_SPEED`, and `Status` ↔
`USBD_STATUS`, written out rather than cast.

**Why.** The Linux port shipped this file and it caught a real bug — `Super`
would have gone out as `WIRELESS`, which the kernel accepts. Windows has the
same hazard rotated:

```
airusb::Speed          None=0 Full=1 Low=2  High=3  Super=4
UDECX_USB_DEVICE_SPEED Low=0  Full=1 High=2 Super=3
```

A cast sends **High as SuperSpeed** and **Super out of range**. The one value
that coincides is Full — where on Linux it was High, so neither port's testing
would have caught the other's.

**Two findings while writing it, both now pinned by tests:**

1. **The short-transfer rule is not the Linux one, and copying it would be a bug
   in the other direction.** On Linux short is unconditionally success. Windows
   makes the caller say, per URB, via `USBD_SHORT_TRANSFER_OK`. Honour the flag:
   set → `SUCCESS` with the short length; clear → `ERROR_SHORT_TRANSFER`.
   Hardcoding either answer breaks somebody.
2. **`USBD_ERROR()` is "the value is negative", so `0x8…` and `0xC…` are both
   failures.** The top two bits are not a severity — `0xC…` means *the endpoint
   is halted*. A short transfer is an error that leaves the pipe running;
   treating it as a halt turns every protocol that ends a transfer early into a
   reset storm. `isError()` and `haltsEndpoint()` are separate predicates for
   this reason. (This one was caught by the test, against the first version of
   the header, which had it wrong.)

**Evidence.** `tests/unit/test_windowsusb.cpp`, 112 checks, run on macOS, Linux
and Windows/MSVC in CI. It asserts the DISAGREEMENTS, so the table cannot decay
into a no-op without failing.

**The numbers themselves are transcribed — and as of 2026-08-09 they are
VERIFIED.** `platform/windows/wdk_abi_check.c` includes the real WDK headers and
`C_ASSERT`s every value in `WindowsUsbAbi.h`; it emits no code and is never
linked, so compiling it IS the test. Run on the GMKtec against SDK 10.0.28000.0,
KMDF 1.35, UdeCx 1.1:

```
SDK 10.0.28000.0   KMDF 1.35   UdeCx 1.1
wdk_abi_check.c
ABI CHECK PASS - every transcribed constant matches the WDK
```

`scripts/wdk-abi-check.ps1` finds the kit, the KMDF version and the UdeCx
version and invokes `cl.exe`. Deliberately not a `.vcxproj`: a project file is
one more thing that can be configured differently from the answer you wanted.

**Four things that first attempt got wrong, none of them a wrong constant**, and
all four produce errors that point somewhere other than the cause:

1. `usbdi.h` is in `shared\`, not `km\`, and `shared\usb.h` does NOT include
   it. Without it the 0x8-class statuses (`REQUEST_FAILED`, `NO_MEMORY`) are
   absent and their `C_ASSERT`s fail — **which reads exactly like a wrong
   value.** It was the include set. This is the single best argument for
   compiling the check rather than reading the header: the failure mode of a
   missing include and a bad constant are indistinguishable on paper.
2. Include ORDER matters: `usb.h`/`usbdi.h`/`usbdlib.h` before `wdfusb.h`,
   `wdfusb.h` before `UdeCx.h`. Get it wrong and the errors appear inside
   Microsoft's headers, reading like a broken kit.
3. `ucrt` must be on the include path even for a kernel-mode compile — `ntdef.h`
   reaches `ctype.h`. Leaving it out looks like a broken WDK.
4. The kit's headers need `/external:I` + `/external:W0`. Under a plain `/I`
   they are "our" code, and `/WX` promotes the WDK's own C4324 padding warnings
   into a failure in `wdfrequest.h`. Our file stays at `/W4 /WX`.

**And one real finding: `USBD_STATUS_TYPE` does not exist.** Searched across the
entire kit, not assumed. `USBD_STATUS_HALTED` (0xC0000000) does, and
`USBD_SUCCESS`/`USBD_PENDING`/`USBD_ERROR` do. So `haltsEndpoint()` is our own
convention over a documented constant rather than a wrapper around a documented
macro — the check asserts the mask against `USBD_STATUS_HALTED` directly, which
is as close to verified as that idea can get.

**PASS.**

### W3 — `UdecxBridge`, proven with no kernel · **DONE, 2026-08-09**

**Goal.** Turn URB submissions into transfers on `ImporterDataPlane`, and
completions back into URB completions, without ever waiting on the network to
answer a kernel lifecycle callback.

**What UdeCx makes EASIER than macOS, and it is worth saying.** UdeCx delivers
URBs, not transfer descriptors, so one URB is already one logical transfer.
There is no descriptor-chain walk, and the hazard that dominates the macOS
design — splitting a transfer at a boundary that injects a short packet
(P1 §5.4) — cannot arise. The driver forwards URBs whole and the bridge never
sees a partial one.

**What it makes harder is lifecycle**, and all three answers are the same shape:

* **Cancellation is answered in the same `poll()` that receives it**, before any
  network traffic. The driver has already completed the guest's URB; the
  acknowledgement only says nothing of ours will touch that id again.
* **A configure transaction is answered from local knowledge.** Selecting the
  captured configuration succeeds; selecting a different one is **refused, not
  forwarded**, because no exporter in this project can change a captured
  device's configuration (P1 §4.8) and a guest that believes otherwise builds
  its endpoint table from descriptors the device is not using.
* **Every endpoint in a configure's RELEASE set has its queued transfers
  completed immediately**, before the transaction result is sent. The driver is
  about to destroy those endpoint objects; a completion arriving afterwards
  lands on a freed kernel object.

**And the descriptor path never leaves the machine.** `Ep0Arbiter` answers
GET_DESCRIPTOR from the manifest, so a guest's enumeration storm — dozens of
control reads — happens at memory speed instead of at LAN latency, and still
returns the device's own bytes verbatim. The test asserts twenty such reads
produce **zero** exporter traffic.

**Evidence.** `tests/unit/test_udecxbridge.cpp`, 64 checks, against a fake
driver channel and a REAL `ExporterSession` over a real Noise session — so a
forwarded transfer really crosses the protocol. Cases: local descriptor answers
with zero traffic; a real Bulk-Only Transport CBW forwarded and completed; the
depth-1 admission queue holding a second transfer and still giving it exactly
one terminal outcome; cancellation acknowledged in one poll with the exporter
never running; the late completion dropped rather than delivered; a configure
refused for the wrong configuration; released endpoints drained before the
result; a dead network completing everything outstanding; a stale incarnation
answered rather than forwarded; a malformed record counted and skipped without
stopping the channel; and the two different size caps — the ABI's and this
device's — firing in the right places.

**Three test bugs found on the way, all mine, all worth recording** because each
is a wrong belief about the system rather than a typo:

1. The rig submitted transfers without an ATTACH, so the exporter refused every
   one for having no lease. It looked exactly like a bridge that could not
   forward.
2. The forwarded payload was 31 bytes of filler. The device on the far end is a
   BOT state machine, not an echo, and it correctly stalled a non-command. The
   fix — send a real CBW — makes the test prove more than it originally claimed.
3. An "oversized transfer" case used 2 MiB, which the ABI codec refuses before
   the bridge ever sees it. There are two caps, they are different, and the test
   now exercises each one separately.

**PASS.**

### W4 — `airusb.sys` · NOT STARTED, and not buildable here

**Goal.** The KMDF client driver: UdeCx callbacks, the endpoint queues, the
inverted-call channel, the arena, and an INF.

**Cannot be done on this machine.** It needs the WDK, and it cannot be tested
without the target. CI *may* be able to build it — the WDK is installable on a
`windows-latest` runner — and getting it to COMPILE in CI is worth doing on its
own, because it is what turns the W2 `static_assert`s from aspiration into a
check that runs.

**Evidence.** A driver that builds, and `AIRUSB_WITH_WDK` compiled at least once.

### W5 — `airusb-winhost.exe` · NOT STARTED

**Goal.** The user-mode half: open the driver, park N inverted-call IOCTLs, run
`UdecxBridge` over `ImporterClient`, and hand the arena around.

Mostly wiring, once W1 and W3 exist. It should look like
`platform/linux/airusb_vhci_main.cpp`, including the part that the Linux one got
right and everything else got wrong: **it watches for pending TX and pushes it**
(`pendingTxBytes()`), which is the bug that cost this project a session when the
exporter stranded the tail of a 128 KiB reply.

### W6 — bring-up on the GMKtec · NEEDS THE USER

`bcdedit /set testsigning on`, reboot, install the INF, plug in a share from the
Mac, and watch Device Manager.

**Evidence.** The Windows equivalent of the Linux gate: the device appears in
Device Manager under the right VID/PID, `diskmgmt` shows the volume, files are
read, and the drive is returned to the sharing machine cleanly afterwards. A
`sha256sum` equivalent against a known image is the real proof, as it was on
Linux.

---

## What this reuses rather than rebuilds

The expensive parts are already done and proven on real kernels:

| | |
|---|---|
| segmentation, both directions | done, and now proven between two machines |
| `ImporterDataPlane` — non-blocking, deadline-swept, one terminal outcome per submit | done, 82 checks |
| the "never block the kernel" discipline | done, and the reason `VhciNetBridge` exists in the shape it does |
| the manifest, and answering ep0 locally from it | done |
| pairing, the window, device selection | done — `airusb-hubd` runs on Windows today |

`VhciNetBridge` is the thing to read before writing `UdecxBridge`. It is the same
problem with a different kernel ABI, and its header records which of its rules
are USB/IP-specific and which are general.

---

## The one thing to decide before W3

**How much of the transfer assembly happens in the driver.** UdeCx delivers URBs,
not transfer descriptors, so Windows does not have the TD-chain walk that macOS's
`IOUSBHostControllerInterface` imposes (§5.4 of the implementation plan) — one
URB is already one logical transfer. That is a genuine simplification and it
should be taken: the driver forwards URBs whole, and `UdecxBridge` never sees a
partial one.

The rule it must still honour is the same one that has bitten this project on
every platform: **one logical transfer is one call to the device.** Splitting a
URB at a non-`wMaxPacketSize` boundary injects a short packet, and a short packet
is how USB signals the end of a data phase.
