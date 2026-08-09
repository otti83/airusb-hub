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
    ├── inverted call: N parked "give me the next URB" IOCTLs
    └── shared-memory arena: OUT data copied in before parking, IN data copied back
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

### W1 — the driver↔host channel, fuzzed · NOT STARTED

**Goal.** A codec for the inverted-call records: URB metadata down, completions
up, arena slot indices in both directions.

**Why first.** It is the ABI between two processes, one of which is in the
kernel. A length field trusted where it should be validated is a kernel-mode
memory bug reachable from user mode — the exact CVE class `protocol/` was
designed around, and the reason `UsbipCodec` and `AgentProtocol` are both fuzzed
on every platform rather than only on the OS they serve.

**Evidence.** Round-trip tests over the full field ranges; a fuzz target added
to `tests/fuzz`; every decode of a hostile record refused rather than clamped.

**PASS** iff the codec builds and is fuzzed on macOS, Linux and Windows, and no
decode path can produce an arena slot index, offset or length that has not been
bounds-checked against the arena the host actually allocated.

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

**The numbers themselves are transcribed, and transcription can be wrong.** When
a build defines `AIRUSB_WITH_WDK` — which any real driver build does —
`WindowsUsb.cpp` `static_assert`s every constant against Microsoft's own
headers. That build is the acceptance test for the values; these tests are the
acceptance test for the mapping. A constant that only ever exists in our header
is a constant nobody has checked.

**PASS.**

### W3 — `UdecxBridge`, proven with no kernel · NOT STARTED

**Goal.** The analogue of `VhciNetBridge`: turn URB submissions into transfers
on `ImporterDataPlane`, and completions back into URB completions.

Responsibilities, all of which `VhciNetBridge` already has a proven answer for:

* answer `GET_DESCRIPTOR` from the manifest locally, with zero network traffic;
* admit data transfers to the data plane, or queue them at the admission depth;
* answer cancellation immediately and drop the late completion;
* complete every outstanding URB with `DEVICE_GONE` if the network dies;
* never block — the kernel side must never wait on a network round trip.

**What is different from Linux, and needs its own thought:**

* **UdeCx answers some control requests itself** from the descriptor table given
  at `plugIn`, and those are unrecoverable by construction (§4.6 of the
  implementation plan). The manifest makes `GET_DESCRIPTOR` safe; the residual
  exposure is a device that rejects a configuration the manifest said it had.
* **`EvtUsbDeviceEndpointsConfigure` hands over a `WDFREQUEST` that must be
  parked** and completed only when the far side has answered. That is the whole
  reason the verb interface is ticketed.
* **The MDL is only valid while the request is held**, so OUT data must be
  copied into the arena *before* the request is parked — not lazily when the
  network is ready for it.

**Evidence.** A `test_udecxbridge` with a fake driver channel standing in for the
kernel, mirroring `test_netbridge`: a forwarded round trip, a local
`GET_DESCRIPTOR` with zero network traffic, cancellation answered before any
completion with the late completion dropped, a network drop completing
everything outstanding, and the admission queue at depth 1.

**PASS** iff all of that is green on three platforms with no driver in existence.

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
