# AirUSB Hub

**Use a USB device that is plugged into another computer as if it were plugged
into yours.**

The receiving machine enumerates the device through its own USB stack and loads
its own drivers — a flash drive appears as a normal volume, because as far as
that operating system can tell, it really is attached. Not file sharing. The
device itself is forwarded.

Peer to peer, LAN only. No cloud, no account, no server. Every session is
encrypted and mutually authenticated (Noise).

> **One identity per machine, and one ceremony.** `airusb-brokerd` owns the
> machine's identity, its pinned peers and its leases, and it is the process
> that hands a device to your operating system. The window is a client of it: it
> never holds the machine's key, and it cannot pin a peer the broker did not
> itself put a question about. (Run standalone it does have an identity — its
> own, for the diagnostic half — and it says so on startup.) So the six digits you compare belong to the session that
> really moves a filesystem — which was not true before 2026-08-09, when the
> window had an identity of its own and the command-line tools had another.
>
> The command-line tools are still there and still useful, and an unpaired peer
> is REFUSED by default: they print the number and tell you to compare it.
> `--trust-on-first-use` is the honest name for taking the risk deliberately,
> and it has to be typed.

---

## What works today

| | |
|---|---|
| **Share a device from a Mac** | **works, on real hardware** — a 31.5 GB SuperSpeed drive, captured from macOS and handed back cleanly |
| **Receive a device on Linux** | **works** — the Linux kernel enumerates it, binds `usb-storage`, and mounts the filesystem |
| **The window** | **works on macOS, Linux and Windows** — one interface, one binary, no toolkit to install ([`docs/GUI.md`](docs/GUI.md)). On Linux its **Attach** really enumerates the device; where it cannot, it says so instead of doing something smaller |
| Encryption, authentication, pairing | done — Noise_XX, checked against the official test vectors. The two ends agree their record size at HELLO before either can act; the other negotiated numbers are exchanged and not yet acted on. Noise_IK is implemented and vector-tested; production runs XX |
| Receive a device on **Windows** | **written, and never run.** The driver builds and passes Code Analysis; the host half builds. Neither has been loaded or executed against a kernel. Nobody's permission required; it needs a spare machine and a person at the keyboard |
| Receive a device on **macOS** | **blocked on Apple** — see below |

So there is a working product today: **a Mac shares a drive, a Linux machine
uses it as a real USB device, and the window is how you do it.** Sharing from
Linux or Windows, and receiving on Windows or macOS, are the parts still
missing.

**And one limit worth stating plainly:** every hardware claim here rests on a
single SuperSpeed flash drive on a clean LAN. No keyboards, no cameras, no USB 2
speeds, no hubs, no unplug-mid-write. The exporter now REFUSES a device with an
interrupt or isochronous endpoint rather than accepting it and hanging — so a
keyboard gets a sentence, not a silence — but that is a refusal, not support.

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
hardware.

**There are no downloadable builds, on purpose.** CI compiles for Windows on
every commit and does not publish the result: the Windows importer's driver has
never been loaded, and every hardware claim here rests on one flash drive. A
binary behind a green tick tells somebody neither of those things. Build it
yourself with the two lines above, or cross-compile with
`airusb/scripts/cross-build-windows.sh`.

Started that way, the window says **DIAGNOSTIC ONLY** — it can pair with another
machine and read a device from it, and it cannot add one to this computer. To
actually receive a device, run the broker as well; on Linux that is:

```bash
# The broker owns the identity and the vhci port, so it is root. Its socket is
# 0600 by design, which means the window has to be able to read it — run both
# as the same user, or relax the socket deliberately.
sudo ./build/airusb-brokerd --socket /tmp/airusb.sock --simulated --share
sudo ./build/airusb-hubd --broker /tmp/airusb.sock --no-open
```

`--simulated` is what gives the broker something to share; without it there is
no capture backend wired in yet and `--share` offers nothing. The window then
shows **this machine's** identity rather than one of its own, and Attach means
what it says.

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
                                     Linux: vhci-hcd  ·  Windows: UdeCx (written, never loaded)
                                              macOS: blocked on an Apple entitlement
```

There is no dedicated server; the protocol is symmetric. What is NOT yet
symmetric is the platform support: real hardware can only be shared **from
macOS**, and a forwarded device can only be enumerated **on Linux**. The
protocol, the window and the command-line client run everywhere.

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
29 suites, 0 failures      6 fuzz targets, 0 crashes
CI on every commit: macOS/Clang · Linux/GCC+ASan+UBSan · Windows/MSVC · MinGW cross-build
zero warnings under -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow,
and under MSVC /W4 /permissive-
```

The Windows and Linux CI jobs do not merely compile: each starts two daemons,
makes them pair, and requires a USB Mass Storage exchange to complete through
the control API before the job passes. Both first check that an approval which
does not name the question it is answering is REFUSED — a pairing ceremony
whose refusals have quietly stopped working looks exactly like one that works.

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
| [The Windows importer](docs/WINDOWS_IMPORTER_PLAN.md) | UdeCx, gate by gate. In progress — the portable half first, as on Linux. |
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
