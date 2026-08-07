# P1 — Exporter Capture Verification

**Date:** 2026-08-08
**Host:** macOS 26.5.1 (25F80), Apple M1 (T8103), SIP enabled, Secure Boot Reduced
**Tool:** `poc/p1-capture-test/`
**Purpose:** resolve P0 open risk #2 (FB16524420) before writing exporter code.

---

## Result summary

| Question | Answer | Decisive? |
|---|---|---|
| Does `IOUSBHostObjectInitOptionsDeviceCapture` work as root on 26.5? | **Yes** | Yes |
| Does `IOUSBHostInterface` capture work for **mass storage**? | **Yes, from Terminal** | **No — see §3** |
| Do raw control transfers work on a captured device? | **Yes** | Yes |
| Does DiskArbitration unmount + capture + restore round-trip cleanly? | **Yes, no data loss** | Yes |
| Is FB16524420 closed? | **Not yet** | Needs the LaunchDaemon run |

---

## 1. Test device

```
058f:6387  Generic / "Mass Storage"   (Alcor Micro class controller)
31.5 GB, MBR, exFAT volume "Memory 32GB"
USBSpeed = 4 (kIOUSBHostConnectionSpeedSuper), UsbLinkSpeed = 5,000,000,000
```

**The device operates at SuperSpeed (USB 3.0, 5 Gb/s), not High Speed.**

This was initially misreported. The IORegistry exposes two speed properties with
**different enumerations**, and reading the wrong one silently misreports USB 3 as USB 2:

| Property | Enumeration | Value here | Means |
|---|---|---|---|
| `Device Speed` | **legacy**: Low=0, Full=1, High=2, **Super=3** | 3 | Super |
| `USBSpeed` | `tIOUSBHostConnectionSpeed` (`IOUSBHostFamilyDefinitions.h:88`): None=0, Full=1, Low=2, **High=3**, Super=4 | 4 | Super |

Both say Super; the trap is that the same integer `3` means *High* in one enum and
*Super* in the other. Corroborating evidence from the device descriptor:
`bcdUSB = 0x0320` (USB 3.2) and `bMaxPacketSize0 = 9`, which for SuperSpeed is an
**exponent** (2⁹ = 512 bytes), not a byte count. A High Speed device would report 64.

The tool now reads `USBSpeed` and cross-checks `UsbLinkSpeed`, printing
`speed=Super(5G) (5.0 Gb/s link)`.

**Implication for Phase 2:** the device manifest must carry the BOS descriptor and
SuperSpeed Endpoint Companion descriptors (`bDescriptorType` 0x30). The P1 plan's
manifest contract (§3.7) already requires both. If the first PoC should exercise the
simpler USB 2.0 path instead, insert a USB 2.0 hub to force High Speed operation —
this is a deliberate choice to make, not something to leave to chance.

---

## 2. Verified transcript

Run as `sudo ./capture_test --capture 058f:6387` from an interactive Terminal:

```
@@AIRUSB_ATTACH@@ capture_test  euid=0  args=--capture 058f:6387
@@AIRUSB_ATTACH@@ target 058f:6387 Mass Storage
@@AIRUSB_ATTACH@@ BSD media: [disk22,disk22s1]
@@AIRUSB_ATTACH@@ unmounting /dev/disk22 (whole disk)
@@AIRUSB_ATTACH@@ unmounted /dev/disk22
@@AIRUSB_ATTACH@@ capturing IOUSBHostDevice with IOUSBHostObjectInitOptionsDeviceCapture
@@AIRUSB_ATTACH@@ RESULT=DEVICE_CAPTURED
@@AIRUSB_ENUM@@ deviceDescriptor: USB 0320  class=00/00/00  VID=058f PID=6387
                bcdDevice=0002  ep0MaxPacket=9  numConfigs=1
@@AIRUSB_REQ@@ RESULT=CONTROL_OK GET_DESCRIPTOR(DEVICE) bytes=18 head=12 01 20 03
@@AIRUSB_ATTACH@@ RESULT=INTERFACE_CAPTURED num=0 class=0x08
@@AIRUSB_ENUM@@   interface 0 alt 0: class=08/06/50 endpoints=2
@@AIRUSB_ATTACH@@ interfaces: 1 captured / 1 present
@@AIRUSB_DETACH@@ releasing interfaces and destroying device (triggers reset + driver rematch)
@@AIRUSB_DETACH@@ RESULT=RESTORED
@@AIRUSB_ATTACH@@ VERDICT=PASS
```

### What each line proves

- **`unmounted /dev/disk22`** — the DiskArbitration safe-unmount path works, so the
  exclusivity lifecycle in P1 §7 has a working first step.
- **`RESULT=DEVICE_CAPTURED`** — `IOUSBHostObjectInitOptionsDeviceCapture` succeeds
  with root and **no entitlement**, confirming the P0 §5 reading of the header. The
  built-in `IOUSBMassStorageDriver` was evicted.
- **`GET_DESCRIPTOR bytes=18 head=12 01 20 03`** — decoded: `bLength=0x12` (18),
  `bDescriptorType=0x01` (DEVICE), `bcdUSB=0x0320` little-endian. A **real control
  transfer completed against real hardware** through the public API. This is the same
  request the importer's kernel will issue at us in Phase 2, so the round trip is
  de-risked at both ends.
- **`INTERFACE_CAPTURED num=0 class=0x08`** and
  **`class=08/06/50 endpoints=2`** — Mass Storage (0x08) / SCSI transparent (0x06) /
  **Bulk-Only Transport (0x50)** with two endpoints (bulk IN + bulk OUT). A textbook
  BOT profile, and exactly the class FB16524420 concerns.
- **`RESULT=RESTORED`** — plain `destroy` reset the device and re-registered drivers.
  Verified afterwards: the volume remounted at `/Volumes/Memory 32GB` with contents
  intact. **No data loss.**

---

## 3. Why this is NOT yet a close on FB16524420

FB16524420 states the interface-capture failure occurs **from a LaunchDaemon**, and
**not** from Terminal or Xcode. This run was from an interactive Terminal.

> A PASS from an interactive shell is the **expected** result even when the bug is
> present. It therefore proves the API works, but says nothing about whether the bug
> affects us.

This matters because AirUSB Hub's exporter *must* be a root LaunchDaemon — that is the
supported shape for a notarized Developer ID product (an `SMAppService`/launchd daemon
plus an unprivileged UI). The LaunchDaemon result is the one that decides the
architecture.

The tool now detects its launch context (`getppid() == 1`) and reports
`VERDICT=PASS_NONDECISIVE` rather than `PASS` when run interactively, so this
distinction cannot be lost again.

### The decisive run

```
sudo ./run_as_daemon.sh 058f:6387
```

Loads a one-shot LaunchDaemon, runs the same test, prints the log, then unloads and
removes itself. Nothing stays installed.

| Outcome | Meaning |
|---|---|
| `VERDICT=PASS` + `launch context: launchd (daemon)` | FB16524420 does not affect us. Exporter design confirmed; P1 §7.4's mitigation ladder becomes dead code and should be deleted. |
| `VERDICT=FAIL` + `0xE00002C9` | It does. Run the §7.4 ladder: retry after `configureWithValue:matchInterfaces:NO`, then decide between a different launch context and an Apple escalation. |

---

## 4. Status of P0 risk #2

**Downgraded from HIGH to MEDIUM, not closed.**

What is now certain: device capture, interface capture, control transfers, and the
unmount/capture/restore lifecycle all work through public API, as root, with SIP
enabled and no entitlement. The remaining uncertainty is narrow and specific — whether
the launch context changes the interface-capture result — and one command settles it.

Tracked as **OQ-2** in `P1_IMPLEMENTATION_PLAN.md`.
