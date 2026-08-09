# AirUSB Hub

**Use a USB device that is plugged into another computer as if it were plugged
into yours.**

The receiving machine enumerates the device through its own USB stack and loads
its own drivers — a flash drive appears as a normal volume, because as far as
that operating system can tell, it really is attached. Not file sharing. The
device itself is forwarded.

Peer to peer, LAN only. No cloud, no account, no server. Mutually authenticated
and encrypted (Noise), with a six-digit number you compare on both screens
before anything is trusted.

---

## What works today

| | |
|---|---|
| **Share a device from a Mac** | **works, on real hardware** — a 31.5 GB SuperSpeed drive, captured from macOS and handed back cleanly |
| **Receive a device on Linux** | **works** — the Linux kernel enumerates it, binds `usb-storage`, and mounts the filesystem |
| **The window** | **works on macOS, Linux and Windows** — one interface, one binary, no toolkit to install ([`docs/GUI.md`](docs/GUI.md)) |
| Encryption, authentication, pairing | done — Noise_XX / Noise_IK, checked against the official test vectors |
| Receive a device on **Windows** | not yet — needs a UdeCx driver. Nobody's permission required; just unwritten |
| Receive a device on **macOS** | **blocked on Apple** — see below |

So there is a working product today: **a Mac shares a drive, a Linux machine
uses it as a real USB device.** Sharing from Linux or Windows, and receiving on
Windows or macOS, are the parts still missing.

> **The macOS receiving half is blocked, and only that half.** Presenting a
> virtual USB host controller on macOS needs
> `com.apple.developer.usb.host-controller-interface`, an entitlement only Apple
> grants by hand and which is not requestable through the developer portal
> (measured, not assumed — [`docs/HANDOFF.md`](docs/HANDOFF.md) §2.2). Requested
> 2026-08-08, **FB24214361**, no reply yet. Nothing else in this project waits
> on it.

---

## Try it

One binary, no installation, no privileges:

```bash
cd airusb && cmake -S . -B build && cmake --build build --target airusb-hubd
./build/airusb-hubd
```

It prints a local address and opens it:

```
  AirUSB Hub is running. Open this address:

    http://127.0.0.1:53412/#t=a3f9240fcc5c7a8c…
```

Do the same on a second machine, press **Connect**, compare the six digits on
both screens, and accept. It offers a simulated drive so the whole path works on
a machine with nothing plugged in; add `airusb-exportd` on a Mac to share real
hardware. Windows binaries are published by CI on every commit.

The window is a page served to `127.0.0.1` only, behind a token, because the
browser is the one interface toolkit that is already installed on all three
operating systems — and the only one this project can actually test on all
three. Details and the security model: [`docs/GUI.md`](docs/GUI.md).

---

## How it works

```
 sharing machine                                receiving machine
 ───────────────                                ─────────────────
 USB device
    │  captured from the OS, its disks unmounted
    ▼
 AirUSB exporter ──── encrypted, mutually authenticated, LAN ────► AirUSB importer
   (macOS today)                                                        │
                                                                        ▼
                                                        virtual USB host controller
                                                                        │
                                                                        ▼
                                                     the OS loads its own driver
                                              Linux: vhci-hcd  ·  Windows: UdeCx (todo)
                                              macOS: blocked on an Apple entitlement
```

Every peer can share and receive; there is no dedicated server.

**The sharing side is two processes, because macOS requires it.** Capturing a
device and unmounting its disks need root; opening a USB interface needs
membership of the console GUI session — and no process can be both. Measured,
not guessed: a root LaunchDaemon is denied `iokit-open-service
IOUSBHostInterface` while an unprivileged LaunchAgent succeeds. Same parent, no
tty either way, *less* privilege, opposite result.

**The receiving side needs a user-space USB host controller.** On Linux that is
`vhci-hcd`, which is in the stock kernel. On Windows it is a UdeCx driver, which
needs only test-signing to develop. On macOS it is
`IOUSBHostControllerInterface`, which needs Apple's entitlement. No kernel
extension, no SIP changes, no private APIs — anywhere.

---

## Evidence

This project does not claim anything works without a log from the same
iteration that produced the claim. The load-bearing ones:

**A Linux kernel enumerated a real drive that was plugged into a Mac.** The
31.5 GB stick was captured on the Mac by `airusb-exportd --serve`, carried over
the encrypted session, and attached to `vhci-hcd` on a Linux VM:

```
scsi  Direct-Access  Generic  Flash Disk
sd [sda] 61440000 512-byte logical blocks: (31.5 GB)
lsblk  sda1  exfat  "Memory 32GB"
mount -o ro /dev/sda1     -> the drive's real files, read over the network
```

Read-only on the Linux side on purpose. Unmounting returned the drive to the
Mac with its data untouched, and killing the exporter mid-write produced an I/O
error rather than an unkillable `D`-state process — the failure mode that would
have meant a reboot.

The same bridge also enumerates a *simulated* device with no Mac involved,
which is how it is tested; that run reports `Product: AirUSB` and 30 MB, so the
two are never mistaken for one another in the logs.

**A real drive, read and written through the window.** The strings are the
drive's own firmware, not a simulation's:

```
INQUIRY   'Generic' 'Flash Disk' rev '8.01'
CAPACITY  61440000 x 512 = 31.46 GB
LBA 0     bootsig=55AA   head=[fa b8 00 00 8e d0 bc 00 7c 8b f4 ...]   (a real MBR)
SHORT_READ_FIDELITY  offered 1024, device sent 512 — short read preserved
```

A 128 KiB write to the physical medium came back byte-identical and the original
was restored; the drive was re-read afterwards and is unchanged.

**Two machines, two operating systems, a person comparing the number.** macOS
and Windows, on different subnets, each naming the other's fingerprint exactly,
then a 128 KiB transfer split across eight records in each direction:

```
SEGMENTATION out=2 in=2 contRecords=14 maxSegment=16552 largestOut=131072 fired=yes
RESULT=PASS — a USB Mass Storage exchange completed over an encrypted,
              authenticated network session
```

**The Noise handshake is checked byte for byte against the official
cross-implementation test vectors**, including the final handshake hash. A Noise
implementation that only talks to itself can be perfectly self-consistent and
completely wrong.

```
24 test suites, 0 failures      3 fuzz targets, 0 crashes
CI on every commit: macOS/Clang · Linux/GCC+ASan+UBSan · Windows/MSVC · MinGW cross-build
zero warnings under -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow,
and under MSVC /W4 /permissive-
```

The Windows and Linux CI jobs do not merely compile: each starts two daemons,
makes them pair, and requires a USB Mass Storage exchange to complete through
the control API before the job passes.

---

## Safety

A USB drive mounted in two places at once destroys its filesystem. AirUSB
unmounts the drive on the sharing machine before handing it over, holds that
claim for the whole session, and gives it back cleanly. If it cannot do that
safely, it refuses — and it fails closed: a peer that vanishes mid-write does
**not** get the drive handed back underneath it.

The read-only prober used by the window's "check it really works" button cannot
write; the writing instrument is a separate type with a method called
`runDestructiveWriteTest`, so the guarantee stays absolute rather than becoming
conditional on a flag.

While testing, use a drive you do not care about.

---

## Build

```bash
cd airusb
cmake -S . -B build && cmake --build build
(cd build && ctest)
```

Windows binaries can be cross-built from macOS or Linux with
`./scripts/cross-build-windows.sh` (needs `mingw-w64`), and CI publishes both an
MSVC and a MinGW build on every commit.

The macOS SwiftUI shell — which today shows attached devices and hosts the
entitlement probe, and does **not** yet drive sharing:

```bash
cd apple && xcodegen generate
xcodebuild -project AirUSBHub.xcodeproj -scheme AirUSBHub \
           -destination 'platform=macOS' -allowProvisioningUpdates build
```

Requires macOS 13+, Xcode 26. Tested on macOS 26.5, Apple M1.

![The macOS shell, showing a captured drive](docs/images/app.png)

---

## Documentation

| | |
|---|---|
| [The window](docs/GUI.md) | The interface: why it is a page, the security model, and the two-machine procedure. |
| [Session handoff](docs/HANDOFF.md) | The state of everything, and every decision not worth re-deriving. Start here. |
| [Feasibility](docs/P0_MACOS_FEASIBILITY.md) | Can this be built through supported APIs? Evidence and verdict. |
| [Architecture](docs/P1_IMPLEMENTATION_PLAN.md) | Wire protocol, concurrency, timeouts, test plan. |
| [Why two processes](docs/P1_CAPTURE_VERIFICATION.md) | What was measured on real hardware. |
| [The exporter](docs/P2_8_EXPORTER.md) | How sharing works, and the hardware evidence. |
| [The Linux importer](docs/LINUX_IMPORTER_PLAN.md) | vhci-hcd, gate by gate, with the evidence for each. |
| [Security](docs/P2_4_SECURITY.md) | What protects a session, and how it was verified. |
| [Windows](docs/WINDOWS.md) | Building and running on Windows, and what MSVC settled. |
| [Entitlement](docs/ENTITLEMENT_REQUEST.md) | The one Apple-managed entitlement the macOS receiving half needs. |

---

## License

[Apache License 2.0](LICENSE). Chosen over MIT for its explicit patent grant,
which matters for something that implements a transport protocol.

Vendors [Monocypher](https://github.com/LoupVaillant/Monocypher) 4.0.3 (BSD-2 / CC0)
and the [BLAKE2](https://github.com/BLAKE2/BLAKE2) reference implementation (CC0),
unmodified — see [`airusb/third_party/PROVENANCE.md`](airusb/third_party/PROVENANCE.md).
Vendored rather than linked because the sharing daemon runs as root, and a library
loaded from a user-writable path would be a way to run code as root.
