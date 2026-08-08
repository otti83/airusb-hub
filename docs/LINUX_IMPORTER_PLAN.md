# Linux Importer — Implementation Plan

**Written:** 2026-08-09
**Status:** design pass. Nothing here is built yet; §7 is the staged plan.

**Why Linux first.** This is the only importer path that waits on nobody. The
macOS importer is blocked on an Apple entitlement (FB24214361, indefinite); the
Windows importer needs a UdeCx driver that is not written. `vhci-hcd` is in the
mainline kernel, needs no signing, no out-of-tree module and no permission, and
would make this project do the thing it exists to do — have an OS enumerate a
remote device as a real USB device — for the first time on any platform.

**How this was produced.** Five research lenses (USB/IP wire format, vhci-hcd
sysfs attach, the mapping onto the existing AirUSB client, process architecture,
and the environment), each adversarially re-verified against kernel source and
against live aarch64 Linux VMs. Passages marked **[V]** are where a verifier
overrode the researcher; the verifier's version is normative there. The
feasibility claims in §2 were demonstrated on this machine, not reasoned about.

---

**Status:** design pass, not built. Derived from five verified research lenses (usbip-wire, vhci-attach, airusb-mapping, architecture, environment), each adversarially re-checked against kernel source at v6.1/v6.8/v6.12/master and against live aarch64 Linux VMs on this machine.

**Convention used throughout:** where a verifier overrode the researcher, the passage is tagged **[V]** and states both versions. The verifier's version is normative. Unresolved items are tagged **UNRESOLVED**.

---

## 1. What this delivers

A userspace program, `airusb-vhci`, that runs on a Linux box, opens an AirUSB session to a remote exporter (today: the working macOS exporter), and hands the local kernel one end of an `AF_UNIX` socketpair through `vhci-hcd`'s documented sysfs `attach` interface — so that the local kernel enumerates the remote device as a real USB device, reads its real descriptor bytes, binds its own real class driver (`usb-storage`, `cdc_acm`, `usbhid`, …) and creates its own device node. A person will see `dmesg` announce `New USB device found, idVendor=…`, see `/dev/sdX` appear, mount a filesystem on it, read and write files, and `umount` cleanly. What they still will **not** see: a device imported *to macOS* (blocked on Apple entitlement FB24214361) or *to Windows* (needs the unwritten UdeCx driver); isochronous devices (webcams, USB audio) — deferred, refused with a well-formed error; UAS/USB3 bulk streams (`vhci_alloc_streams()` is a kernel stub returning 0); and `usb_reset_device()` propagating to the remote device (vhci absorbs port reset locally — see §8, R9).

---

## 2. Feasibility verdict

**Yes. It can be built and demonstrated on an aarch64 Lima VM, and every load-bearing kernel behaviour has already been demonstrated on this machine.** There is no blocker.

Proven live during research, on Ubuntu 24.04 / kernel 6.8.0-134-generic / aarch64, with no hardware and no network:

- `vhci-hcd`'s `attach` accepts an `AF_UNIX SOCK_STREAM` **socketpair** fd. The only checks in `attach_store` are `sockfd_lookup()` succeeding and `socket->type == SOCK_STREAM` (`vhci_sysfs.c:360-372`); there is no address-family check anywhere in `drivers/usb/usbip/`. This kills the plan's TCP-loopback fallback (`P1_IMPLEMENTATION_PLAN.md` §4.7, OQ-3) as unnecessary: **no plaintext USB/IP ever exists on any socket a third party can reach.**
- A full enumeration completed over that socketpair, at both **high speed** and **SuperSpeed**, ending in `sd 0:0:0:0: [sda] Attached SCSI removable disk` and in `cdc_acm … ttyACM0: USB ACM device` / `/dev/ttyACM0`. Two independent verifiers reproduced this with different responders.
- Killing the userspace process tears everything down cleanly: EOF → `VDEV_EVENT_DOWN` → `vhci_shutdown_connection()` → `vhci_device_reset()` → port back to `VDEV_ST_NULL`. No stale ports, no reboot.
- No signing, no lockdown, no Secure Boot obstacle: `/sys/kernel/security/lockdown` = `[none]`, `sig_enforce` = N, and every module we load is distro-built and in-tree. **We ship no kernel module.** This is exactly why Linux is the cheap path.

Three things are *hard prerequisites above `platform/linux/`*, not blockers of the approach but blockers of a mounted filesystem:

1. **AirUSB segmentation is unimplemented.** `RecordLayer::sendRecord` rejects bodies over `kRecordBytesDefault = 16640`; the ceiling is `kRecordBytesCeiling = 65519` (max payload 65 431 B). `usb-storage` sets `max_sectors = 240` → **122 880 bytes in one URB** at ≤HIGH speed, and **[V]** at SuperSpeed `slave_configure()` raises it to 2048 sectors = **1 MiB** (the researcher gave only the 240/120 KiB figure). Raising the record ceiling cannot close this. `kFlagSegMore`/`kFlagSegFirst`/`seg_offset`/`Type::Data` are specified in `Wire.h` and implemented nowhere.
2. **`RemoteDevicePort` cannot pipeline** — it sends one SUBMIT and treats any other `request_id` as a fatal `MalformedFrame` (`RemoteDevicePort.cpp:88`). A sibling async data plane is required.
3. **The `airusb::Speed` enum does not match Linux's `usb_device_speed`, and only `High` coincides.** See §8, R3. A naive cast attaches devices at the wrong speed *silently*.

None of these is a kernel problem. All three are ours, all three are bounded.

---

## 3. Environment setup

### Recommended: Ubuntu 26.04 (zero installs, no reboot)

```bash
limactl start --name=airusb-linux --tty=false --cpus=4 --memory=8 --disk=40 template:ubuntu-26.04
limactl shell airusb-linux
```

In Lima 2.2.0, `template:ubuntu` and `template:ubuntu-lts` both resolve to 26.04. `template://` is deprecated; use `template:`.

```bash
sudo modprobe vhci-hcd
```

That is the whole setup. Ubuntu 26.04 (resolute) has **no `linux-modules-extra` package for `generic` at all** — `vhci-hcd.ko.zst` ships in base `linux-modules`, and `linux-image-virtual` (what the cloud image runs) already has it. Verified live on a stock 26.04 VM: `modinfo -n vhci-hcd` resolved with nothing installed.

### Alternative: Ubuntu 24.04 (one apt, still no reboot)

```bash
sudo apt-get install -y linux-modules-extra-$(uname -r)   # ~123 MB, 2 packages
sudo modprobe vhci-hcd
```

No kernel change and no reboot, because the Lima cloud image already runs the `generic` kernel binary via `linux-image-virtual`; only the `-extra` module set is missing.

**[V] Do not encode "always apt-install `-extra`" as a rule.** The researcher's claim was flavour-specific. `vhci-hcd` is *not* in `-extra` for `generic-64k`, `raspi` or `lowlatency`, and on the noble **HWE** track (7.0.0-generic) it moves back into base `linux-modules`. The correct rule is: **resolve at runtime with `modinfo -n vhci_hcd`**, and only apt-install if that fails.

### Do not use Debian

`template:debian-12` / `debian-13` use the **genericcloud** image, whose kernel is built with `# CONFIG_USB_SUPPORT is not set` — verified in both bookworm and trixie configs. There is no USB subsystem at all, so no package can ever supply `vhci-hcd.ko`. Fixing it means installing `linux-image-arm64` (a different kernel flavour) **and rebooting**. Strictly worse. This also explains the existing `kbuild` VM (`6.1.0-51-cloud-arm64`) — leave it alone.

### Reboot?

**No reboot is needed on either Ubuntu path.** For persistence across reboots either write `/etc/modules-load.d/vhci-hcd.conf`, or better, have the bridge `modprobe` on its own when `/sys/devices/platform/vhci_hcd.0` is absent — that removes a boot-ordering dependency and a distro-specific file.

### Verifying vhci-hcd is live

```bash
modinfo -n vhci_hcd                                       # path, or "not found"
sudo modprobe vhci-hcd
lsmod | grep -E '^(vhci_hcd|usbip_core) '
ls -l /sys/devices/platform/vhci_hcd.0/                   # attach detach nports status usbip_debug usb3 usb4
cat /sys/devices/platform/vhci_hcd.0/nports               # 16 on Ubuntu
cat /sys/devices/platform/vhci_hcd.0/status               # header + 8 "hs" rows + 8 "ss" rows, all sta 004
```

Facts the code must respect:

- File is `vhci-hcd.ko` (hyphen); loaded name and every sysfs path use `vhci_hcd` (underscore). `modprobe` accepts either.
- Control attributes live **only** under `vhci_hcd.0`, even with `CONFIG_USBIP_VHCI_NR_HCS > 1` (`vhci_hcd.c:1208`, guarded by `id == 0 && usb_hcd_is_primary_hcd(hcd)`). Extra controllers appear as `status.1` … `status.N`. **There is no `/sys/devices/platform/vhci_hcd` symlink** — the kernel removes one it never creates. Hardcode `vhci_hcd.0`; hardcode nothing else.
- Modes: `attach` and `detach` are `0200 root:root`; `status` and `nports` are `0444`; **[V]** `usbip_debug` is `0644`, not write-only (the researcher listed it as write-only).
- **Do not hardcode `usb3`/`usb4`.** The Lima `vz` VM already has a real xHCI carrying Apple's virtual keyboard, so vhci lands on buses 3 and 4 *here*. Read `/sys/devices/platform/vhci_hcd.0/usb*/busnum`.
- **Do not hardcode 8 ports.** `VHCI_HC_PORTS` is `CONFIG_USBIP_VHCI_HC_PORTS` (range 1..15). Derive from `nports` and the count of `vhci_hcd.*` platform devices.
- Debug tracing needs **two** knobs, not one: `echo 0xffffffff > usbip_debug` *and* `echo 'module vhci_hcd +p' > /sys/kernel/debug/dynamic_debug/control`, because Ubuntu ships `# CONFIG_USBIP_DEBUG is not set` and the macros route through `pr_debug()`.

### Build environment

The cloud image has **no C/C++ toolchain**: `sudo apt-get install -y --no-install-recommends build-essential cmake` (37 packages). `/Users/mba` is mounted via virtiofs **read-only**, so the repo is visible at the same absolute path but cannot be built in place — add a writable mount or build into a guest-local directory.

### Existing VMs

`airusb-vhci` (Ubuntu 24.04, 6.8.0-134-generic, `vhci_hcd` loaded, `gcc` installed, all 16 ports free) is a ready reference environment and is where most of the live evidence was produced. `usbip-probe` and `u2604-probe` are stopped probes; `kbuild` is unrelated Debian work — do not touch it.

---

## 4. Architecture

### 4.1 Process and thread structure

**One process. One thread. One `poll(2)` loop over exactly two file descriptors.**

```
  ┌──────────────────────────────────────────────────────────────┐
  │ kernel: vhci_hcd                                             │
  │   vhci_tx kthread ──CMD_SUBMIT / CMD_UNLINK──►  sv[0]        │
  │   vhci_rx kthread ◄─RET_SUBMIT / RET_UNLINK──   sv[0]        │
  └──────────────────────────────────────────────────────────────┘
                              ▲ sv[1]  (AF_UNIX, SOCK_STREAM, O_NONBLOCK)
                              │
  ┌───────────────────────────┴──────────────────────────────────┐
  │ airusb-vhci — ONE THREAD                                     │
  │   poll({sv[1]: IN|OUT?, tcp: IN|OUT?}, 250 ms)               │
  │    1. drain sv[1]  ALWAYS, FIRST, UNCONDITIONALLY            │
  │    2. Ep0Arbiter: Local / Absorb / Arbitrate / Forward/Stall  │
  │    3. admit from pendingQueue under CreditController          │
  │    4. drain tcp → COMPLETE → RequestTable → queue RET_SUBMIT  │
  │    5. flush both tx buffers, non-blocking                     │
  │    6. sweep deadlines → synthesize RET_SUBMIT locally         │
  └──────────────────────────────────────────────────────────────┘
```

Threads buy nothing here. The only blocking primitives are two sockets, both made non-blocking; the project has zero `std::thread` today and a deterministic single-strand test harness; `IAirUsbTransport.h` states implementations are not thread-safe and the session owns one Rx and one Tx strand; and `P1_IMPLEMENTATION_PLAN.md` §5.2 forbids locks in `core/`.

**Concurrency the kernel actually imposes is small for the first target.** `usb-storage` sets `.can_queue = 1`, so exactly one SCSI command is in flight and CBW→data→CSW are strictly sequential. Enumeration is entirely synchronous `usb_control_msg()`. Many-in-flight arrives later from HID, CDC and above all from userspace `usbfs`, where the USB core imposes no cap at all. That is absorbed by a hash map keyed on `seqnum`, not by threads.

**Out-of-order completion is free and should be used.** `pickup_urb_and_free_priv()` (`vhci_rx.c:13-53`) is a linear search of `priv_rx` by `seqnum`; no other field participates and no ordering is required. `Documentation/usb/usbip_protocol.rst:62-86` diagrams interleaved completion explicitly. This is what stops a never-completing interrupt IN (`watchdog::kUrbDeadlineIntr == 0`, "may legitimately idle forever") from head-of-line-blocking a bulk transfer.

### 4.2 The deadlock hazard, precisely

The kernel side **cannot** self-deadlock: `vhci_tx_loop()` and `vhci_rx_loop()` are two independent kthreads on one socket, so the kernel stays full-duplex even when one side is wedged. The hazard is entirely ours.

**Stage 1 — stall (recoverable).** If the bridge stops reading `sv[1]`, `vhci_send_cmd_submit()`'s `kernel_sendmsg()` (`vhci_tx.c:139`, **no timeout, no `MSG_DONTWAIT`**) sleeps once the `AF_UNIX` send window fills. That window is the sender's `SO_SNDBUF` — measured `net.core.wmem_default = 212992`, with `wmem_max` also 212992 — and per-skb it is capped at `(sk_sndbuf >> 1) - 64 ≈ 106 432` bytes. **A single 122 928-byte bulk-OUT `kernel_sendmsg` therefore cannot fit atomically: `vhci_tx` parks mid-message on every large OUT. That is the normal case, not an error case.**

**Stage 2 — unkillable hang.** If the bridge stays blocked past the class driver's patience: the SCSI error handler fires (`/sys/block/sdX/device/timeout`, default `SD_TIMEOUT = 30 s`) → `usb_stor_stop_transport()` → `usb_unlink_urb()` → `vhci_urb_dequeue()` takes the `tcp_socket != NULL` branch, queues a `CMD_UNLINK`, and **returns 0 without giving the URB back** (`vhci_hcd.c:943-970`, and the comment at `:932-936` says so). `vhci_tx` is still parked, so the `CMD_UNLINK` never leaves. `usb_kill_urb()` then waits in `wait_event(usb_kill_urb_queue, …)` — `TASK_UNINTERRUPTIBLE`, no timeout — **forever**. Result: D-state `scsi_eh` thread, wedged block device, `umount`/`sync` in D state, SIGKILL useless, reboot required.

**Stage 3 — collateral.** `vhci_shutdown_connection()` is what unwedges a parked sender (`kernel_sock_shutdown(SHUT_RDWR)` *before* `kthread_stop_put()` at `vhci_hcd.c:1040-1053`). **[V] This escape hatch is confirmed, not inferred:** `sock_wait_for_wmem()` (`net/core/sock.c:2705-2727`) breaks on `sk_shutdown & SEND_SHUTDOWN` at `:2719`, and `unix_shutdown()` sets it and calls `sk_state_change()`. `kthread_stop` alone would **not** work — kthreads have no pending signals and `timeo` is `MAX_SCHEDULE_TIMEOUT`. But that handler runs on the **single global `usbip_event` workqueue** with **one** shared `usbip_work` and **one** shared `event_list` (`usbip_event.c:126-130, 144-172`), so a stuck teardown blocks event handling for every usbip device on the machine — and with the bridge alive-but-stuck and `sv[1]` open, nothing ever queues the event.

**Three structural rules that make the hazard unreachable:**

- **R-A. `sv[1]` is drained on every loop iteration, before anything else, unconditionally.** No code path between "poll returned" and "sv[1] drained" may block on the network. In particular the bridge never calls `RemoteDevicePort::submit()` or anything else that spins on `receiveRecord()`.
- **R-B. Writes to `sv[1]` are never blocking writes.** Buffer in-process, flush on `POLLOUT`. `RecordLayer`'s `_tx` vector + `_txSent` cursor + `flush()` is the exact shape to copy (structurally — the USB/IP stream has no length prefix and no cipher). **[V] Setting `O_NONBLOCK` on the fd handed to `attach` has no effect on the kernel side**, because `kernel_sendmsg`/`sock_recvmsg` pass only `msg_flags` and never consult `file->f_flags`. Verified live: the device still enumerated with the fd non-blocking. Non-blocking-ness is for *our* end only.
- **R-C. Every URB we accept has a deadline, and on expiry we synthesize the completion ourselves.** The kernel has no timeout anywhere; ours is the only one. `core/Watchdog.h` already defines `kUrbWatchdogImporter = 45000` for exactly this and `static_assert`s it above `kUrbCeilingBulk = 30000`. Ep0 traffic that crosses the LAN needs a **strictly smaller** deadline than 5000 ms, because `USB_CTRL_GET_TIMEOUT`/`USB_CTRL_SET_TIMEOUT` are both 5000 ms and `core/Watchdog.h:55` sets `kNetCtrl = 5000` — exactly equal, a race the kernel wins. Use 3500–4000 ms for `Arbitrate`/`Forward` on ep0.

Optional belt-and-braces, documented but not shipped in v1: `setsockopt(sv[0], SO_RCVTIMEO)` before `attach`. `vhci_rx_pdu` has an explicit `-EAGAIN` branch (`vhci_rx.c:212-216`) that raises `VDEV_EVENT_ERROR_TCP` cleanly. Safe only if every PDU is written with a single `writev()`.

### 4.3 What lives in `platform/linux/`, and what changes above it

| file | layer | OS headers | built on | note |
|---|---|---|---|---|
| `platform/linux/UsbipCodec.{h,cpp}` | platform | **none** | **all platforms** | pure `span<const uint8_t> ↔ struct`. Explicit big-endian byte loads, never a struct overlay (same rule as `protocol/Wire.h`). **This file gets the same fuzzing treatment as `protocol/`** — §4.7 of the plan is right that a casually-written USB/IP parser inside our own process re-imports the exact CVE class AirUSB was designed to eliminate. |
| `platform/linux/VhciBridge.{h,cpp}` | platform | **none** | **all platforms** | the FSM: pending queue, `seqnum ↔ (channel, request_id)` map, credit admission, deadline sweep, `Ep0Arbiter` dispatch, unlink bookkeeping. Takes a `transport::IByteStream&` for the kernel side. |
| `platform/linux/VhciAttach.{h,cpp}` | platform | `<sys/socket.h>`, `<poll.h>` | `#if defined(__linux__)` | `socketpair()`, sysfs port allocation, `attach`/`detach` writes, `FdStream` |
| `platform/linux/LinuxSpeed.{h,cpp}` | platform | none | all | `toKernelSpeed(airusb::Speed)` — see §8 R3 |
| `protocol/StatusMapLinux.cpp` | protocol | none | **all platforms** | the errno table. **Hardcodes Linux numbers**; `static_assert`s them against `<errno.h>` only under `#if defined(__linux__)`. macOS's `ETIMEDOUT` is 60, Linux's is 110, and macOS has no `EREMOTEIO` at all — the host header is wrong everywhere but Linux. |

**The structural trick:** the kernel side of the bridge is a byte stream, and `transport::IByteStream` already has the right contract (`IAirUsbTransport.h:38-48` — short writes normal, `{Ok,0}` = would-block, peer close = `TransportLost`). So `VhciBridge` never sees a file descriptor; on Linux it gets a thin `FdStream` over `sv[1]`, and in tests it gets `transport::MemoryPipe` (with `setCapacity()` for backpressure). **The entire bridge — codec, seqnum table, credit admission, unlink logic — is therefore testable on macOS and Windows with no kernel involved.** This is the same property that made `AgentProtocol` fuzzable in CI, and it is worth more here than anywhere else in the project. Precedent to copy verbatim: `platform/macos/AgentProtocol.cpp` (portable, built everywhere) vs `platform/macos/AgentLink.cpp` (POSIX, guarded in `CMakeLists.txt`).

**Layer graph.** `airusb_vhci` links `airusb_session`, adding a `platform/linux → session` arrow that mirrors the existing `platform/macos → session`. No cycle; `core → crypto → protocol → transport → session` is untouched. **The USB/IP codec must not go into `protocol/`** — `protocol/` is AirUSB/1 and nothing else, and putting a second wire format there would ship a USB/IP parser inside the macOS root daemon.

**What must change above `platform/linux/`:**

1. `transport/` + `session/` — **segmentation**: emit N records for one logical transfer (same `request_id`, `SEG_FIRST` on the first, `SEG_MORE` on all but the last, `seg_offset` advancing, `total_len` constant) and reassemble per `(channel, request_id)` into a per-attach arena capped at `credit_bytes` (R2). `FrameScheduler` already exists and is unused outside tests.
2. `session/` — a new **async data plane** (`ImporterDataPlane`) over the `RecordLayer*` that `ImporterClient::transport()` already exposes, demultiplexing on `(channel, request_id)` via the existing `core/RequestTable`. `RemoteDevicePort` stays exactly as it is; it is the instrument `diag/BotProbe` validates the network with, and the two use cases have opposite requirements.
3. `core/Ep0Arbiter.cpp` — `local()` on an **empty** blob must return `Stall(NotFound)`, not a zero-length success (§8 R7).
4. `session/ExporterSession.cpp` + `platform/macos/` — control-OUT `actualLen`, interrupt/iso routing, `xflags` honouring (§8 R4, R5, R8).
5. `core/IUsbDevicePort.h` — an `actualLen` out-param on `controlTransfer`, and a per-transfer timeout parameter so `SubmitBody::timeoutMs` stops being decoded and dropped.

### 4.4 Privilege

`sockfd_lookup()` is `fget()` against **`current->files`**, and sysfs `store` runs synchronously in the writer's task context — so **the process that writes `attach` must be the process holding the socketpair fd**. There is no way to pass a bare integer between processes.

**[V] This argues for the opposite of the researcher's recommendation.** The researcher proposed a ~200-line root helper receiving `sv[0]` over `SCM_RIGHTS`. The verifier's point: if the bridge can write `attach` itself, there is no fd to pass at all, and the helper is strictly more moving parts for the same result. Also **[V]** udev cannot grant that permission declaratively — `MODE=`/`OWNER=`/`GROUP=` apply to *device nodes*, and `vhci_hcd.0` has none; only `RUN+="/bin/chmod …"` or a systemd unit works, and the chmod is lost on module unload.

**v1 decision: run `airusb-vhci` as root.** It is one process, it needs no capability beyond `CAP_DAC_OVERRIDE` (there is no `capable()` check anywhere in `attach_store`/`detach_store`), and write access to `attach` is close to root anyway — it means "hand the kernel any socket and have it treated as a USB device". Privilege separation is a later, separate decision; if taken, the daemon must own both the socket and the write permission.

`sockfd_lookup()` takes its own file reference, so **close your copy of `sv[0]` immediately after the `attach` write** — verified live, the device stays at `VDEV_ST_USED`. That way the session dies exactly when our process does.

---

## 5. The USB/IP bridge, concretely

### 5.1 The PDU

`struct usbip_header` is **always exactly 48 bytes**, both directions, every command: `usbip_header_basic` (20) + a union whose largest member is `usbip_header_cmd_submit` (28). Verified by compiling the packed structs standalone, twice, independently. `vhci_rx_pdu` reads `sizeof(pdu)` unconditionally (`vhci_rx.c:208`). **A `RET_SUBMIT` must be padded to 48 bytes (20 + 20 + 8 zero); a `RET_UNLINK` to 48 (20 + 4 + 24 zero).** The kernel `memset`s the whole PDU before filling on every send path, so padding is reliably zero inbound.

**All `__u32`/`__s32` fields are big-endian.** `setup[8]` is **not** byte-swapped — it is raw USB SETUP, so `wValue`/`wIndex`/`wLength` inside it stay **little-endian**, sitting inside an otherwise big-endian header. **[V] The airusb-mapping researcher wrote "all fields network byte order"; that is wrong in the one place it is fatal.** A layer that byteswaps the header wholesale corrupts every control transfer, i.e. enumeration itself. This is also exactly the project's verbatim rule applied to the setup packet.

| off | CMD_SUBMIT (1) | RET_SUBMIT (3) | CMD_UNLINK (2) | RET_UNLINK (4) |
|---|---|---|---|---|
| 0x00 | `command` = 1 | 3 | 2 | 4 |
| 0x04 | `seqnum` | echo the CMD's | the unlink's **own** seqnum | echo the CMD_UNLINK's seqnum |
| 0x08 | `devid` | 0 | `devid` | 0 |
| 0x0C | `direction` 0=OUT 1=IN | 0 | 0 | 0 |
| 0x10 | `ep` — **number 0..15, no 0x80 bit** | 0 | 0 | 0 |
| 0x14 | `transfer_flags` u32 | **`status`** s32 | target `seqnum` u32 | **`status`** s32 |
| 0x18 | `transfer_buffer_length` s32 | **`actual_length`** s32 | pad 0 | pad 0 |
| 0x1C | `start_frame` s32 | `start_frame` (echo) | pad 0 | pad 0 |
| 0x20 | `number_of_packets` s32 | `number_of_packets` (echo) | pad 0 | pad 0 |
| 0x24 | `interval` s32 | `error_count` s32 | pad 0 | pad 0 |
| 0x28 | `setup[8]` **verbatim, LE inside** | 8 bytes zero | pad 0 | pad 0 |

`usbip_iso_packet_descriptor` is 16 bytes: `{u32 offset, length, actual_length, status}`, **all four big-endian**, `status` declared unsigned but carrying a negative errno. Note AirUSB's own 16-byte iso descriptor (`Wire.h:220-226`) is `{u32 offset, u32 length, u32 actual_length, u16 status, u16 reserved}` — same size, different last 4 bytes, opposite endianness. A trap laid for whoever does iso.

**Framing.**

```
CMD_SUBMIT: [48-byte header]
            [payload]   iff direction == OUT and transfer_buffer_length > 0,
                        length EXACTLY transfer_buffer_length (padded, even for iso OUT)
            [iso desc]  iff the endpoint is isochronous, number_of_packets * 16 bytes

RET_SUBMIT: [48-byte header]
            [payload]   iff the original URB was IN and actual_length > 0,
                        length EXACTLY actual_length  (NOT transfer_buffer_length)
            [iso desc]  iff isochronous, number_of_packets * 16 bytes, COMPACTED
```

Scatter-gather is invisible on the wire: `kernel_sendmsg` concatenates the sg iovecs into one contiguous run, capped at `txsize`. Treat every payload as one flat buffer.

**[V] Iso framing is asymmetric and the `.rst` obscures it:** `CMD_SUBMIT` iso OUT carries the **full padded** `transfer_buffer_length`, while `RET_SUBMIT` iso IN carries a **compacted** buffer (sum of per-packet `actual_length`), which the client re-expands with `usbip_pad_iso()`. The `.rst` prints "padding is not transmitted" under both tables; it is wrong for CMD_SUBMIT.

**Constants** (`usbip_common.h:117-123`): `USBIP_CMD_SUBMIT=1, USBIP_CMD_UNLINK=2, USBIP_RET_SUBMIT=3, USBIP_RET_UNLINK=4`; `USBIP_DIR_OUT=0, USBIP_DIR_IN=1`.

### 5.2 `transfer_flags`

**[V] The wire namespace is `USBIP_URB_*` from `include/uapi/linux/usbip.h`, not `URB_*` from `include/linux/usb.h`** (the airusb-mapping researcher cited the wrong header). They are numerically identical in 6.1 and 6.12, but `flag_map[]`/`urb_to_usbip()` is precisely the seam where they may diverge. **Hardcode the UAPI values. Never `#include <linux/usb.h>`.**

| flag | value | meaning to us |
|---|---|---|
| `USBIP_URB_SHORT_NOT_OK` | `0x0001` | → `wire::kXfShortNotOk` |
| `USBIP_URB_ISO_ASAP` | `0x0002` | → `wire::kXfIsoAsap` |
| `USBIP_URB_ZERO_PACKET` | `0x0040` | → `wire::kXfZeroPacket` (bulk OUT only) |
| `USBIP_URB_NO_INTERRUPT` | `0x0080` | host scheduling hint — **ignore** |
| `USBIP_URB_DIR_IN` | `0x0200` | redundant with `base.direction` — **ignore** |
| `USBIP_URB_DMA_MAP_SG` | `0x00040000` | host DMA artifact — **ignore** |

`URB_NO_TRANSFER_DMA_MAP (0x4)` is stripped by `tweak_transfer_flags()` and never appears. **Mask bit-by-bit; never compare the whole word and never reject unknown bits.** `DMA_MAP_SG` genuinely appears on every usb-storage URB because `vhci_hcd.c:1165` sets `sg_tablesize = 32`. Direction comes from `base.direction` at 0x0C, never from `transfer_flags` — and note that a **control IN with `wLength == 0`** carries `direction = IN` but `DIR_MASK == DIR_OUT`, so do not cross-check the two and abort on mismatch.

Confirmed live for usb-storage:

```
[22] ep2 OUT len=31   flags=0x00000000  CBW   (no SHORT_NOT_OK)
[23] ep1 IN  len=36   flags=0x00040201  {SHORT_NOT_OK|DIR_IN|DMA_MAP_SG}  INQUIRY data
[24] ep1 IN  len=13   flags=0x00000200  CSW   (no SHORT_NOT_OK)
[58] ep1 IN  len=4096 flags=0x00040201  READ(10)
```

### 5.3 The parse algorithm

Transfer type is **never on the wire** — the kernel's own server resolves it from the endpoint descriptor (`stub_rx.c:329-388`), and so must we, from `DEVICE_MANIFEST`.

```
read exactly 48 bytes -> hdr; byteswap the 5 base fields
switch (hdr.command):
  case USBIP_CMD_SUBMIT:
    byteswap transfer_flags, transfer_buffer_length, start_frame,
             number_of_packets, interval        /* setup[8] UNTOUCHED */
    epAddr  = hdr.ep | (hdr.direction == IN ? 0x80 : 0x00)
    ep_desc = pipeTable.lookup(epAddr)          /* from the manifest, current cfg+alt */
    if (!ep_desc && hdr.ep != 0)      -> RET_SUBMIT{-EPIPE}
    if (hdr.direction == OUT && transfer_buffer_length > 0)
        read exactly transfer_buffer_length bytes
    if (ep_desc is ISOCHRONOUS) {
        if (number_of_packets < 0 || number_of_packets > 1024) -> tear down
        read exactly number_of_packets * 16 bytes
    }
  case USBIP_CMD_UNLINK: byteswap u.cmd_unlink.seqnum; no payload
  default: -> tear down
```

**Never derive "is iso" from `number_of_packets != 0`.** If a future client honoured the `.rst`'s "0xffffffff if not ISO", that heuristic would try to read 64 GiB of descriptors for an ordinary bulk transfer. Clamp `number_of_packets` to `[0, 1024]` exactly as `stub_rx.c:370-377` does — an unclamped value is a trivial allocation/read amplification.

### 5.4 CMD_SUBMIT → AirUSB `SUBMIT`

| USB/IP | → | AirUSB `SubmitBody` / L1 header |
|---|---|---|
| `base.ep`, `base.direction` | | `epAddr = ep \| (dir==IN ? 0x80 : 0)`; `channel = wire::channelFor(attachSlot, epAddr)` |
| *(from manifest pipe table)* | | `xferType` — Control/Bulk/Interrupt/Iso. **Never guessed.** |
| `base.direction` | | `dir` (`r4_submitIdentity` requires `dir == epAddr>>7` for non-ep0; **ep0 is exempt** and `dir` is authoritative there, derived from `setup[0] & 0x80`) |
| `transfer_buffer_length` | | `bufferLen`, and `total_len = iso*16 + (dir==OUT ? bufferLen : 0)` |
| `setup[8]` | verbatim | `setup[8]` |
| `transfer_flags & 0x0001/0x0040/0x0002` | | `xflags` = `kXfShortNotOk` / `kXfZeroPacket` / `kXfIsoAsap` |
| `interval` | | `interval` — informational only. **[V] It is the *computed URB interval*, not `bInterval`**: a HS endpoint declaring `bInterval=4` puts `interval=8` on the wire (`1 << (bInterval-1)`). The exporter must never write it into a descriptor. |
| `number_of_packets`, `start_frame` | | remembered, echoed back verbatim in `RET_SUBMIT` |
| `base.seqnum` | | key of `seqnum → (channel, request_id)`; `request_id` from `RequestTable::nextRequestId(channel)` (strictly increasing per channel, R8) |
| everything else | | dropped |

**ep0 goes through `Ep0Arbiter::decide()` first — never straight to `controlTransfer`:**

| disposition | bridge action |
|---|---|
| `Local` | `RET_SUBMIT{status=0, actual_length=d.data.size()}` + the bytes. **No network traffic.** `d.data` is already truncated to `wLength`. |
| `Absorb` | `RET_SUBMIT{0, 0}`, nothing on the wire (SET_SEL, SET_ISOCH_DELAY, U1/U2/LTM/REMOTE_WAKEUP features) |
| `Arbitrate` | convert to a verb — `EpClearHalt` → `wire::Type::EpClearHalt (0x32)` → on `CtrlAck.status == Ok`, `RET_SUBMIT{0,0}` + `Ep0Arbiter::commitVerb()`. **`SetConfiguration (0x30)` and `SetInterface (0x31)` have no codec, no port method and no exporter handler.** v1 narrowing: if `arg0 == arbiter.currentConfiguration()` (resp. current alt), answer `RET_SUBMIT{0,0}` locally and `commitVerb()` — the exporter is already in that state, which is why the manifest records `currentConfigValue`. Anything else → `-EPIPE` and log it. Record as a divergence. |
| `Forward` | AirUSB `SUBMIT{epAddr=0, xferType=Control, dir from bmRequestType, bufferLen=wLength, setup verbatim}` |
| `Stall` | `RET_SUBMIT{-EPIPE}` |

Two free invariants worth asserting: for control, `base.direction == ((setup[0] & 0x80) ? IN : OUT)` always holds (`urb.c:411` enforces it with a `dev_WARN_ONCE`), and `transfer_buffer_length == wLength` always holds (`urb.c:414-419` returns `-EBADR` otherwise).

**Requests the kernel never sends us:** `SET_ADDRESS` is completed locally by `vhci_urb_enqueue` (`vhci_hcd.c:759-777`) and never reaches the wire. `GET_DESCRIPTOR` to devnum 0 **is** forwarded. **[V] Any *other* request to devnum 0 is rejected `-EINVAL` before transmission** — only those two are legal there. Also **[V] `SET_FEATURE(PORT_RESET)` never reaches us**: `vhci_hub_control` handles `USB_PORT_FEAT_RESET` entirely locally (`vhci_hcd.c:573-585`). The airusb-mapping researcher worried that the exporter would fail to handle it; the real consequence is the inverse — `usb_reset_device()` on the importer **never propagates to the exporter** (§8, R9).

**[V] The first PDU is speed-dependent.** The vhci-attach researcher's transcript showed `GET_DESCRIPTOR(DEVICE, wLength=8)` first; that is the **SuperSpeed** path, because `use_new_scheme()` (`hub.c:2824`) returns false for `speed >= USB_SPEED_SUPER`. At **high/full/low** speed the new scheme is used and the first wire PDU is `GET_DESCRIPTOR(DEVICE)` with **`wLength = 64`** (`GET_DESCRIPTOR_BUFSIZE`), followed by a local port reset, then SET_ADDRESS. **Do not hardcode "first request is an 8-byte device-descriptor read."**

SuperSpeed additionally demands a valid **BOS** descriptor (requested twice — 5 bytes then `wTotalLength`) and issues **`SET_ISOCH_DELAY` (bRequest 0x31)**, both observed live. **[V]** the BOS gate is `bcdUSB >= 0x0201`, not "SuperSpeed" — a USB 2.1 device at high speed gets it too. **[V]** `DEVICE_QUALIFIER` is requested only when `bcdUSB >= 0x0200 && speed == USB_SPEED_FULL && highspeed_hubs != 0` — narrower than "not SuperSpeed". `SET_SEL (0x30)` and `SET_FEATURE(U1_ENABLE/U2_ENABLE)` appear only if the device advertises non-zero U1/U2 exit latencies; `SetPortFeature(U1/U2_TIMEOUT)` goes to the root hub and is absorbed.

### 5.5 AirUSB `COMPLETE` → RET_SUBMIT

```
base.command   = 3
base.seqnum    = the CMD_SUBMIT's seqnum   <- the ONLY matching key
base.devid     = 0        base.direction = 0        base.ep = 0
status         = mapToLinuxErrno(header.status, cflags, xflags)
actual_length  = CompleteBody::actualLen
start_frame    = echoed from the CMD_SUBMIT
number_of_packets = echoed from the CMD_SUBMIT
error_count    = CompleteBody::errorCount   (0 for non-iso)
[8 bytes zero]
payload        = IN  -> exactly actual_length bytes
                 OUT -> NOTHING, regardless of actual_length
```

Hard rules, each of which is fatal to the whole port if broken:

- **`actual_length` is the framing length.** Send exactly that many bytes.
- **`actual_length > transfer_buffer_length` → `dev_err("recv xbuf")` → `VDEV_EVENT_ERROR_TCP`** (proven live: replying 80 for a 64-byte request killed the connection). Never over-report, even on babble — clamp and report `-EOVERFLOW`.
- **Never emit a negative `actual_length`**; it is silently swallowed (`!(size > 0)`) but leaves a negative `urb->actual_length` visible to the class driver.
- **`RET_SUBMIT` for a seqnum vhci does not hold → `pr_err("cannot find a urb of seqnum %u")` → `VDEV_EVENT_ERROR_TCP`** (proven live). One duplicate or stale completion kills the port and every other in-flight URB with it. **[V] This is *not* a use-after-free** — the airusb-mapping researcher called it a UAF class bug; `pickup_urb_and_free_priv()` returns NULL and the kernel raises a detected error. The design conclusion is unchanged (swallow late COMPLETEs), but the severity argument is "silent whole-device teardown mid-I/O", not memory corruption.
- **[V] `start_frame` is 0 for control and bulk, not `0xffffffff`.** The usbip-wire researcher generalised from an *interrupt* capture. `usb_fill_control_urb`/`usb_fill_bulk_urb` never touch `start_frame`, so `usb_alloc_urb`'s kzalloc leaves it **0**; only `usb_fill_int_urb` sets `-1`, and only on the **first** submission — thereafter the server's echoed value comes back, because `usbip_pack_ret_submit(pack=0)` writes `urb->start_frame = rpdu->start_frame` and interrupt URBs are resubmitted without re-filling. Demonstrated live over 20+ resubmissions. **Echo both `start_frame` and `number_of_packets`; never use either as a discriminator.**

**Status mapping.** The table is `protocol/StatusMapLinux.cpp`, hardcoded Linux constants (values measured on the aarch64 target):

| `AirUsbStatus` | RET_SUBMIT `status` | errno |
|---|---|---|
| `OK` | `0` | — |
| `XFER_SHORT` | **`0`** with the true `actual_length` | — |
| `XFER_STALL` | `-EPIPE` | 32 |
| `XFER_TIMEOUT`, `XFER_NAK_TIMEOUT` | `-ETIMEDOUT` | 110 |
| `XFER_CANCELLED` | `-ECONNRESET` | 104 |
| `XFER_OVERRUN` | `-EOVERFLOW` | 75 |
| `XFER_UNDERRUN` | `-EREMOTEIO` | 121 |
| `XFER_CRC`, `XFER_BITSTUFF`, `XFER_BAD_TOGGLE` | `-EILSEQ` | 84 |
| `XFER_PROTOCOL`, `XFER_STREAM_ERROR` | `-EPROTO` | 71 |
| `XFER_NO_BANDWIDTH` | `-ENOSPC` | 28¹ |
| `XFER_MISSED_SERVICE` | `-EXDEV` | 18 |
| `XFER_EP_STOPPED` | `-ESHUTDOWN` | 108 |
| `XFER_DEVICE_OFFLINE`, `DEVICE_GONE` | `-ENODEV` | 19 |
| `NO_RESOURCES` | `-ENOMEM` | 12¹ |
| `BAD_ARGUMENT` | `-EINVAL` | 22 |
| `XFER_UNKNOWN`, `ERROR_GENERIC` | `-EIO` | 5¹ |
| `TRANSPORT_LOST` | **never a URB status** — port disconnect (§5.7) | — |
| `DETACHING`, `ATTACH_UNKNOWN`, `NOT_PERMITTED` | not URB statuses either — complete outstanding with `-ESHUTDOWN` and tear the port down | 108 |

¹ asm-generic, not measured on the target; `static_assert` against `<errno.h>` on the Linux build.

**[V] Do NOT synthesize `-EREMOTEIO` for a short IN with `SHORT_NOT_OK`.** The usbip-wire researcher required it; the airusb-mapping verifier refuted the necessity by reading `__usb_hcd_giveback_urb()`:

```c
int status = urb->unlinked;
if (unlikely((urb->transfer_flags & URB_SHORT_NOT_OK) &&
    urb->actual_length < urb->transfer_buffer_length && !status))
        status = -EREMOTEIO;
```

**The USB core performs the conversion itself.** Report `status = 0` with the true `actual_length` and let it. Hand-rolling would collide with the concurrently-unlinked case, where `urb->unlinked` is already non-zero. The architecture verifier independently downgraded this to "HCD fidelity, not a correctness gate": usb-storage converges on `USB_STOR_XFER_SHORT` either way, because `interpret_urb_result` case 0 already returns short when `partial != length`.

Two shapes of "short" both arrive and both must be handled: header `status == Ok` with `actualLen < requestedLen` and `cflags & kCfShort` (what `ExporterSession::handleSubmit` produces today), and header `status == XferShort` from a backend that reports it explicitly (macOS `kIOReturnUnderrun`).

`cflags & kCfToggleUnknown` must raise a per-endpoint **stall barrier**: hold further submits on that endpoint until an `EP_CLEAR_HALT` is acked (plan §3.9).

### 5.6 CMD_UNLINK → RET_UNLINK

`base.seqnum` at 0x04 is the **unlink's own** seqnum; the **victim's** seqnum is at 0x14. `vhci_rx.c:122` matches `unlink->seqnum == pdu->base.seqnum`, so **`RET_UNLINK.base.seqnum` must be the unlink's own**, not the victim's.

| situation | reply |
|---|---|
| victim still outstanding | remove it from our table so no `RET_SUBMIT` will ever be produced for it, send AirUSB `CANCEL` (endpoint-scoped) best-effort, reply `RET_UNLINK{status = -ECONNRESET}` **immediately and locally** |
| victim already completed and its `RET_SUBMIT` is already in the stream | reply `RET_UNLINK{status = 0}` |

**Every `CMD_UNLINK` must be answered.** `usb_kill_urb()` waits in `TASK_UNINTERRUPTIBLE` with no timeout; an unanswered unlink is an unkillable D-state process. This is not optional: `usb-storage`'s abort handler fires on every SCSI command timeout, which is exactly what a LAN hiccup produces.

Failure asymmetry to internalise: a `RET_UNLINK` for an unknown unlink is **benign** (`pr_info`, `vhci_rx.c:149-153`); a `RET_SUBMIT` for an unknown seqnum is **lethal**. And a successful `RET_UNLINK` calls `pickup_urb_and_free_priv(unlink_seqnum)`, retiring the victim — **once you answer an unlink with `-ECONNRESET`, that seqnum is permanently retired.**

Order matters when both fire: if the transfer completed *and then* was unlinked, send `RET_SUBMIT` first, then `RET_UNLINK{0}`. A `RET_UNLINK{0}` arriving while the victim is still in `priv_rx` completes it as a **successful zero-length transfer** — a lie the class driver will act on.

**Known divergence to record:** the exporter's `handleSubmit` blocks inside the device call, so a `CANCEL` cannot be read until that transfer returns (worst case `kUrbCeilingBulk = 30 s`). We reply `-ECONNRESET` immediately anyway, on the strength of having retired the seqnum locally. **The kernel believes the URB is dead the instant it gets `RET_UNLINK`; the device is still moving bytes.** For a bulk OUT that means data may still land on the medium after the kernel gave up. Invariant I1 (one COMPLETE per SUBMIT) still holds on the AirUSB side; the USB/IP side is being told a convenient half-truth.

### 5.7 Attach, detach, and the port invariant

**`attach` string:** `sscanf(buf, "%u %u %u %u", &port, &sockfd, &devid, &speed)` — four **decimal** fields, space separated, single `write(2)`, no trailing newline needed. **[V] "Anything else returns `-EINVAL`" is over-stated:** trailing bytes after the fourth integer are ignored, leading/inter-field whitespace is skipped, and a 5th field is accepted. Hex (`0x10002`) fails. `devid` is written decimal but printed hex (`%08x`) in `status`. `detach` is `kstrtoint(buf, 10, &port)` — a single decimal port, and it **rejects** leading whitespace.

**[V] The errno is not always `EINVAL`, and the difference is load-bearing:** an occupied port returns **`EBUSY (16)`** (`"port N already used"`) — that is the "try another port" signal. `EAGAIN (11)` means the port is not ready. Also silently accepted: `speed=1` (LOW), `speed=2`, `speed=4` (WIRELESS), and an **unconnected `AF_INET` SOCK_STREAM socket**. Detaching a free port also returns `EINVAL`, so `EINVAL` from `detach` is ambiguous between "bad parse" and "nothing there".

**THE PORT INVARIANT — the single most likely place to introduce a latent bug.**

`attach_store` picks the hub half from **speed** (`vhci_sysfs.c:352`); `detach_store` picks it from the **port number** (`vhci_sysfs.c:258`, `(port / VHCI_HC_PORTS) % 2`); both use `rhport = port % VHCI_HC_PORTS`, so attach discards the high bit. Isolated live:

```
attach(port=8, speed=3 HIGH) -> OK, but lands on 'hs' port 0, not 'ss' port 8
detach(8) -> EINVAL          detach(0) -> OK
```

**[V] The kernel does not reject the mismatch — it silently relocates the device and then disagrees with itself about where it is.** ("Stranded" was too strong; the device is reachable at the port `status` reports. The sharper hazard is aliasing: for a given speed, port P and P+8 address the *same* vdev, so a naive allocator treating 0..15 as sixteen slots collides on its ninth device with `EBUSY`.)

**Required invariant, enforced in one function:**

```
speed >= USB_SPEED_SUPER  ->  port ∈ [p*VHCI_PORTS + VHCI_HC_PORTS, p*VHCI_PORTS + VHCI_PORTS)
otherwise                 ->  port ∈ [p*VHCI_PORTS,                 p*VHCI_PORTS + VHCI_HC_PORTS)
```

with `VHCI_PORTS = 2 * VHCI_HC_PORTS`, `VHCI_HC_PORTS` read at runtime from `nports` and the controller count. This matches `usbip_vhci_get_free_port()` (`tools/usb/usbip/libsrc/vhci_driver.c:335`).

**Free-port discovery** is: parse `status` (whitespace-split, not columns — the header does not line up), take a row with `sta == 004` (`VDEV_ST_NULL`) **in the correct hub half**. There is no atomic reserve-then-attach; retry on `EBUSY`.

**Detach is asynchronous** — the write returns before teardown completes (`usbip_event_add(VDEV_EVENT_DOWN)` onto the workqueue), so an immediate re-attach can lose the race for `ud->sysfs_lock` and get `EBUSY`. Poll `status` until the row reads `004`.

**Session drop / teardown order:**

1. Stop admitting.
2. Complete every outstanding URB with `status = -ENODEV`, `actual_length = 0`. Not `-ETIMEDOUT` (invites retries), not `0` (invites a partial write being read as a successful short write). `TRANSPORT_LOST` means "we do not know whether this transfer happened", which USB cannot express — a hung mount is strictly worse than a failed one, and choosing the failure is the point.
3. `close(sv[1])`. EOF → `VDEV_EVENT_DOWN` → shutdown + reset → port back to `VDEV_ST_NULL`. **[V]** if un-consumed bytes are still queued to us, `unix_release_sock` sets `sk_err = ECONNRESET` on the peer and the kernel takes the `VDEV_EVENT_ERROR_TCP` branch and logs `"connection reset by peer"` instead of `"connection closed"` — **both expand to `(SHUTDOWN|RESET)`, so the outcome is identical**, but do not assert on the dmesg string.
4. Optionally also write the port to `detach`, for the case where `sv[1]` was already gone.

**Never `close()` as an error signal while URBs matter** without answering them first — the disable path gives them back with a bare `-ENODEV` and no reason.

### 5.8 Isochronous

Deferred, but **the framing must be parsed on day one**, because skipping the descriptor array desynchronises the stream and the next header read returns garbage. Clean refusal: consume the descriptors, reply `RET_SUBMIT{status = -EPIPE, actual_length = 0, error_count = number_of_packets}` echoing `number_of_packets`, and emit that many descriptors with `offset`/`length` echoed, `actual_length = 0`, `status = -EPROTO`. Sum of `actual_length` = 0 = header `actual_length`, so `usbip_recv_iso`'s consistency check (`usbip_common.c:703-714`) passes and `usbip_pad_iso()` early-returns. Refusing iso costs USB audio, UVC and HID-over-iso; it costs nothing for mass storage, HID, printers, serial or Ethernet. Given *Correctness > Compatibility*, deferring is right.

---

## 6. The descriptor question

**Answer `GET_DESCRIPTOR` locally, from the immutable `DeviceManifest`, via `Ep0Arbiter`.** That is already what the code does (`Ep0Arbiter.cpp:95-128` returns `Local` for DEVICE, CONFIGURATION, STRING, BOS, DEVICE_QUALIFIER, OTHER_SPEED_CONFIG, forwarding only class/vendor types). **The comment in `Ep0Arbiter.h` claiming "macOS and Linux forward enumeration control transfers to the remote device" contradicts the implementation; the implementation is right and the comment must be fixed.**

**The deciding argument is `descriptors_changed()`.** `usb_reset_and_verify_device()` re-reads every configuration descriptor at its **cached `wTotalLength`** and the serial-number string, `memcmp`s them against the cached copies, and on any difference does `dev_info("device firmware changed"); goto re_enumerate;` → `hub_port_logical_disconnect()` → `-ENODEV`. **The device does not resume; it disappears.** And `usb_reset_device()` is exactly what `usb-storage`'s error handler invokes — so this path is hit under precisely the conditions (a LAN hiccup) where forwarding is least deterministic. The config re-read demands `length == old_length` **exactly**; a short read counts as "changed". An immutable manifest guarantees byte-identical answers on every re-read forever. A forwarded read is only *probably* identical: a flaky ep0, a renumerating device, or a truncated reply under load turns a recoverable stall into a vanished disk.

**[V] Mechanism correction:** the airusb-mapping researcher said `descriptors_changed()` re-reads the device descriptor itself. It does not — the caller re-reads it and passes it in as `new_device_descriptor`. The function memcmps that plus every config plus the serial. Conclusion unchanged.

**This does not violate the verbatim rule.** `DeviceManifest` stores the exact bytes the exporter read (`ManifestCodec`: "every blob is carried exactly as the device produced it", hashed end to end by `manifestHash`). `Ep0Arbiter::local()` only truncates to `wLength`, which is what the device itself does per USB 2.0 §9.3.5. **Nothing is synthesised, reordered or re-serialised**, and it should be asserted in code that the importer never constructs a descriptor byte. If the manifest is ever wrong, the fix is to make the exporter read it correctly, not to route around it.

Three corollaries, all required:

- **Consistency across importers.** `Ep0Arbiter` lives in `core/` precisely because it is where all three importer backends converge. If Linux forwarded and macOS answered locally, a manifest bug would be invisible on the platform we can test and fatal on the one we cannot. Keeping Linux on the same policy makes the Linux bridge a **test of the manifest pipeline for macOS and Windows**.
- **Evidence obligation.** Ship a diagnostic mode that *also* forwards each descriptor request and `memcmp`s the device's answer against the manifest blob, logging divergence. That is the Evidence-First discharge of the risk this choice takes on, and it costs nothing when off.
- **Regression oracle.** `/sys/bus/usb/devices/<bus>-<port>/descriptors` is the kernel's cached raw device descriptor concatenated with the raw configuration descriptors. `cmp` it against the manifest blobs. Exit code 0 is the strongest single artifact this project can produce for the verbatim rule, because it passes through a real kernel.

**Required fix before this ships (§8, R7):** `Ep0Arbiter::local()` on an **empty** blob returns `Local` with zero bytes and `isShort = true` — so a device with no BOS, no device qualifier, or an unpopulated string index yields `RET_SUBMIT{0, 0}` instead of the `-EPIPE` the kernel expects. `usb_get_bos_descriptor()`/`usb_string()` then see a malformed short read. **`descriptorResponse` must return `Stall(NotFound)` when the blob is absent.**

**UNRESOLVED:** for `GET_DESCRIPTOR(STRING)` with an index absent from the manifest, `Stall` (matches a device with no such string) vs `Forward` (covers userspace asking for arbitrary indices via usbfs). Both defensible; the current zero-length success is not.

---

## 7. Staged plan with evidence gates

Each gate is Goal / Implementation / Evidence / PASS-FAIL. A failed gate does not advance.

---

### L0 — vhci-hcd is live *(cheapest possible; ~5 minutes)*

**Goal.** Prove the running kernel has the module and the sysfs ABI we expect.
**Implementation.** §3.
**Evidence.** `modinfo -n vhci_hcd`; `lsmod`; `ls -l /sys/devices/platform/vhci_hcd.0/`; `cat nports`; `cat status`; `uname -r`.
**PASS** iff `nports` is readable, `status` shows N/2 `hs` rows then N/2 `ss` rows all at `sta 004`, and `attach`/`detach` are `0200 root:root`. **FAIL** → wrong kernel flavour; §3.

---

### L1 — The kernel talks to us *(the first real gate)*

**Goal.** Prove `vhci-hcd` will accept our socketpair and start driving enumeration, with no AirUSB, no network, no manifest.
**Implementation.** ~80 lines: `socketpair(AF_UNIX, SOCK_STREAM)`, allocate a port obeying the §5.7 invariant, write `"<port> <fd> <devid> <speed>"` to `attach`, `close()` our copy of the kernel's fd, `read()` 48 bytes, decode big-endian, print, `close()`.
**Evidence.** The 48-byte hex dump with a field-by-field decode; `cat status` showing the row at `sta 005`; `dmesg | grep vhci_hcd`; and after close, `status` back to `sta 004` plus `dmesg` showing `release socket / disconnect device`.
**PASS** iff (a) the first PDU decodes as `command=1`, `direction=1`, `ep=0`, with a `GET_DESCRIPTOR(DEVICE)` setup packet — `wLength=64` at HS, `wLength=8` at SS; (b) `devid` on the wire equals what we wrote; (c) the port returns to `004` after close with no leak. **FAIL** → nothing downstream is worth writing.

---

### L2 — `UsbipCodec`, hosted and fuzzed

**Goal.** A byte-exact, memory-safe USB/IP codec that builds and runs on macOS.
**Implementation.** `platform/linux/UsbipCodec.{h,cpp}` — explicit BE byte loads, `setup[8]` untouched, 48-byte encode with padding, iso descriptor array, `number_of_packets` clamped to `[0,1024]`. `tests/fuzz/fuzz_usbip.cpp`.
**Evidence.** Golden-vector test against the captured PDUs in `Documentation/usb/usbip_protocol.rst:447-453` (real captured wire data) plus the L1 dump, byte for byte in both directions. `static_assert`ed offsets. One hour of libFuzzer clean under ASan+UBSan, seeded with the three USB/IP CVE shapes (oversized length; `actual_length > requested_length`; iso quads overrunning the payload).
**PASS** iff round-trip is the identity on every vector, `setup[8]` survives unswapped, and the fuzzer is clean. Must run in CI on macOS and Linux.

---

### L3 — Enumeration, hosted, no kernel

**Goal.** `VhciBridge` + `Ep0Arbiter` + async data plane + `ScriptedDevice` over `MemoryPipe`, driven by hand-written 48-byte PDUs.
**Implementation.** `VhciBridge` over `IByteStream`; `ImporterDataPlane`; `Ep0Arbiter` empty-blob fix; `LinuxSpeed`; `StatusMapLinux`.
**Evidence.** Test cases, each asserting exact bytes: enumeration replay (`GET_DESCRIPTOR(DEVICE,64)` → `(DEVICE,18)` → `(CONFIG,9)` → `(CONFIG,wTotalLength)` → strings → `SET_CONFIGURATION`) with **byte-identity against the manifest blob**; out-of-order completion (submit 10,11,12; complete 12,10,11); short IN with and without `SHORT_NOT_OK`; `CMD_UNLINK` of an outstanding URB → `RET_UNLINK{-ECONNRESET}` and **no** subsequent `RET_SUBMIT`; `CMD_UNLINK` of a completed URB → `RET_UNLINK{0}` **after** its `RET_SUBMIT`; backpressure (`MemoryPipe::setCapacity` forcing short writes, 200 URBs, assert one reply each, `CreditController::urbsInUse()` back to 0, nothing blocks); network drop via `FaultTransport` → every outstanding URB gets `-ENODEV`, then stream closed; `toKernelSpeed()` per speed.
**PASS** iff all green on macOS with no kernel. **Do not skip to L4.** A bug found with a real kernel in the loop costs a VM reboot per iteration and leaves D-state processes that make the next iteration's evidence untrustworthy.

---

### L4 — Enumeration on a real kernel

**Goal.** The Linux kernel enumerates a device served from a manifest, over the real bridge.
**Implementation.** `VhciAttach` + `FdStream`; run against `ScriptedDevice` over TCP loopback inside the VM (no hardware, no LAN).
**Evidence.**
```
vhci_hcd vhci_hcd.0: Device attached
usb 3-1: new high-speed USB device number 2 using vhci_hcd
usb 3-1: New USB device found, idVendor=…, idProduct=…
usb-storage 3-1:1.0: USB Mass Storage device detected
sd 0:0:0:0: [sdb] … 512-byte logical blocks
```
plus `status` row at `sta 006` with the expected `hub`/`spd`, plus `readlink /sys/bus/usb/devices/3-1:1.0/driver`, plus **`cmp` of `/sys/bus/usb/devices/3-1/descriptors` against the manifest blobs**.
**PASS** iff the `New USB device found` line reports the manifest's real VID/PID (the kernel is reading bytes we served, so this is simultaneously an enumeration and a verbatim proof), the class driver binds, and `cmp` exits 0. **FAIL on any `cmp` mismatch** — that is the verbatim rule broken.

---

### L5 — Segmentation

**Goal.** A single 122 880-byte (and, at SuperSpeed, 1 MiB) transfer crosses AirUSB as **one logical transfer** and returns intact.
**Implementation.** `SEG_FIRST`/`SEG_MORE`/`seg_offset`/`total_len` emit and reassemble, per-attach arena capped at `credit_bytes` (R2). Reassembly at the **exporter** into one `bulkOut`/`bulkIn` call.
**Evidence.** Hosted: a 120 KiB round trip over `MemoryPipe` at every record size from 4 KiB to the ceiling, byte-compared. On kernel: `dd bs=1M count=64` read from the device, `sha256sum` matching the `ScriptedDevice` image. `WriteProbe`'s `outBoundariesIntact`.
**PASS** iff bytes are identical and the exporter observes **one** transfer per URB. **A split that does not land on a `wMaxPacketSize` boundary injects a short packet the device reads as a phase boundary** — that is corruption, not a performance issue.

---

### L6 — Read-only block device over the real network

**Goal.** A real USB flash drive on the Mac, mounted read-only on Linux.
**Implementation.** macOS exporter + Lima guest over `host.lima.internal` (guest→host TCP verified working; the importer is the TCP client so no port forwarding is needed).
**Evidence.** `dmesg` enumeration lines; `lsblk`; `mount -o ro`; `ls`; `sha256sum /dev/sdX` against a known image; `descriptors` `cmp` again, now against a real device's real bytes.
**PASS** iff the checksum matches and `dmesg` is free of `usb-storage` resets and I/O errors.

---

### L7 — The write path

**Goal.** First real exercise of the exporter's OUT path with payloads larger than a 31-byte CBW.
**Implementation.** `diag/WriteProbe` green against `ScriptedDevice` in CI **before** any kernel sees an OUT transfer. Then plumb `kXfZeroPacket`.
**Evidence.** `WriteProbe` verdict=PASS in CI; then on hardware: `mkfs.vfat /dev/sdX`, mount rw, write a known 16 MiB pattern, `umount` (exit 0 — the cache flush completed, so WRITE(10) and the CSW path both worked), remount, `sha256sum` the file, and read the same LBAs back through a second path.
**PASS** iff every checksum matches and `umount` returns 0. **FAIL on any silent short OUT.**

---

### L8 — Failure injection *(worth as much as every positive gate)*

**Goal.** Prove the §4.2 deadlock is unreachable and that failure is honest.
**Implementation.** `iptables -j DROP` on the AirUSB port, or SIGSTOP the exporter, mid-write. Separately, SIGKILL the bridge mid-write.
**Evidence.** Within `kUrbWatchdogImporter`: `dmesg` shows `usb 3-1: USB disconnect`, the mount errors out or goes read-only, `status` returns to `sta 004`, and **`umount -f` returns rather than hanging**. `ps -eo stat,comm | grep '^D'` is empty. No reboot.
**PASS-FAIL:** **a run where `umount` hangs or any process is left in D state is a FAIL even if every positive gate passed.** That is the failure this whole design exists to prevent.

---

## 8. Risks and unknowns, ranked

**R1 — The exporter WRITE path has never been exercised.** `docs/HANDOFF.md` §5.1 and `diag/WriteProbe.h` both say `bulkOut` has only ever carried 31-byte CBWs. The first thing Linux does after enumerating is mount a filesystem, and filesystems write. Three specific hazards: (a) a segmented OUT replayed as several `bulkOut` calls injects short packets a BOT device reads as phase boundaries; (b) if a backend returns `actualLen = 0` from `bulkOut` having written everything, `kCfShort` fires and `usb-storage` retries the WRITE — survivable — but a *wrong non-zero* value is not; (c) `URB_ZERO_PACKET` dropped means the device waits forever for a terminating ZLP after an exact-multiple OUT. *Settles it:* L7, plus a device-side length assertion in `ScriptedDevice`.

**R2 — Segmentation is unimplemented and mandatory.** 122 880 B at ≤HIGH, **1 MiB at SUPER [V]**, against a 65 431 B ceiling. Raising `negotiatedMaxRecordBytes` cannot close the gap. A third, cheap mitigation exists on the natural path (`/sys/block/sdX/device/max_sectors` is `DEVICE_ATTR_RW`, clamp to ≤32 sectors post-enumeration) but it is racy for the first few commands and useless for non-storage classes — demo aid only, not a design. *Settles it:* L5.

**R3 — `airusb::Speed` does not match `usb_device_speed`, and only `High` coincides.** `{None=0, Full=1, Low=2, High=3, Super=4, SuperPlus=5, …}` vs `{UNKNOWN=0, LOW=1, FULL=2, HIGH=3, WIRELESS=4, SUPER=5, SUPER_PLUS=6}`. `ManifestCodec.cpp:120` puts the raw numeric on the wire; there is no `USB_SPEED_*` mapping anywhere in the tree. A cast gives: Full→LOW, Low→FULL, **Super→WIRELESS** (accepted by `valid_args()`, and since `4 != USB_SPEED_SUPER` it lands on the **HS** hub, breaking the §5.7 invariant), High→HIGH. **The one value that coincides is the one you will test with first.** `DeviceManifest::validate()` will not catch it — it never looks at a Linux speed. *Settles it:* an explicit `static_assert`ed `toKernelSpeed()` table + a unit test per speed + an L4 assertion that the `status` row's hub matches the speed.

**R4 — Control OUT with a data stage reports `actual_length = 0` and a spurious short.** `ExporterSession::handleSubmit` never sets `cb.actualLen` on the control path (`controlTransfer` has no out-param), so `0 < requestedLen` sets `kCfShort`. Standard enumeration survives (SET_CONFIGURATION/SET_INTERFACE carry `wLength = 0`), but any class driver doing a control OUT with data and checking `ret != size` fails. *Settles it:* add the out-param; a hosted test with a 64-byte control OUT.

**R5 — Interrupt transfers are served through `bulkIn`/`bulkOut`, and iso is silently misrouted through the bulk path.** `handleSubmit` dispatches on direction only; `sb.xferType` is validated then discarded. `RemoteDevicePort::bulkIn/bulkOut` hardcode `XferType::Bulk` and `submit()` is private. Compounding it, `SubmitBody::timeoutMs` is decoded and dropped and `IUsbDevicePort` has no timeout parameter — so an interrupt IN that legitimately idles forever (`kUrbDeadlineIntr = 0`) wedges the exporter's serial read loop with **no deadline anywhere**. *Settles it:* promote `submit()` with `xferType`/`xflags`/`interval`/`timeoutMs`; make the exporter async, **or** refuse ATTACH for devices with interrupt endpoints in v1 and say so.

**R6 — AF_UNIX buffer deadlock if the bridge ever blocks.** ~208 KiB in each direction, and vhci parks mid-message on every large OUT as normal behaviour. *Settles it:* the R-A/R-B/R-C rules plus L3's `setCapacity` backpressure test plus L8.

**R7 — `Ep0Arbiter::local()` returns zero-length success on an absent blob** where the kernel expects a stall. *Settles it:* the fix in §6 + a hosted test for a missing BOS and a missing string index.

**R8 — `kXfShortNotOk` / `kXfZeroPacket` / `kXfIsoAsap` have no consumer anywhere in the tree.** `Codec.cpp` round-trips `xflags`; nothing reads it. Both ends need wiring in one commit. *Settles it:* a hosted assertion that a bulk-OUT of exactly `wMaxPacketSize` with `ZERO_PACKET` produces a trailing ZLP at the device.

**R9 — `usb_reset_device()` never propagates to the exporter.** `vhci_hub_control` absorbs `USB_PORT_FEAT_RESET` locally, so drivers using reset as error recovery — including `usb-storage`'s reset-recovery path — will appear to reset and silently fail to clear real device state. *Settles it:* an explicit design decision. Options: map a detected port reset to a logical `DEVICE_RESET` toward the exporter (plan §6.4 already says `DEVICE_RESET` is always logical), or document the divergence. **UNRESOLVED.**

**R10 — seqnum 2^31 wrap is a latent kernel defect.** `atomic_inc_return` returns `int` into `unsigned long priv->seqnum`; past `INT_MAX` it sign-extends and can never match the zero-extended `__u32` read back, so every subsequent `RET_SUBMIT` fails lookup and kills the connection. Type analysis confirmed independently twice; **never tested**. The counter is per-hub-half, shared across 8 ports, and **[V] survives detach — it resets only in `vhci_start()`, i.e. module load** (observed first seqnums 12, 101, 137, 139 on successive attaches; the `@seqnum` kerneldoc claiming "per connection" is wrong). Reachability is order-10¹¹ URBs. *Settles it:* log seqnum magnitude so the failure is diagnosable rather than mysterious; consider a proactive re-attach if a counter approaches `INT_MAX`.

**R11 — SuperSpeedPlus is unrepresentable below 6.12, and effectively unrepresentable above it. [V]** `valid_args()` rejects speed 6 before v6.12 (bisected across v6.9/6.10/6.11/6.12; live `EINVAL` on 6.8). But **[V]** even on 6.12+ it buys nothing: `hub_is_superspeedplus()` requires `hdev->bos->ssp_cap`, and vhci's `usb3_bos_desc` has `bNumDeviceCaps = 1` with only a `USB_SS_CAP_TYPE` capability — so attached devices are pinned to `USB_SPEED_SUPER` regardless. (The researcher attributed this to `wSpeedSupported = USB_5GBPS_OPERATION`; nothing in `drivers/usb/core/` reads that field for speed selection.) Descriptor bytes still travel verbatim, so the guest sees an SSP-capable BOS on a port the hub calls SS. *Settles it:* given *Correctness > Compatibility*, refuse with `SPEED_UNSUPPORTED (0x0026)` by default, with a documented opt-in downgrade. **UNRESOLVED** which default ships.

**R12 — Isochronous is deferred but its framing is not optional.** Skipping the descriptor array desynchronises the stream permanently.

**R13 — `usbip bind` hard-wedges a Lima `vz` guest.** Observed once (command never returns, SSH hangs, no ICMP, empty journal, `limactl stop -f` required); **[V] deliberately not reproduced by the verifier**, so undiagnosed. Hypothesis: `stub_probe()` calls `usb_reset_device()` on the target, and a port reset to Virtualization.framework's emulated xHCI stalls below the guest's logging. Irrelevant to us — `usbip-host` is the exporter side — but it must be written down as a hazard.

**R14 — `CreditController::matches()` has no caller. [V]** The researcher warned of a false drift alarm from a pipelined importer against a serial exporter; the verifier found the function is referenced only in `test_core.cpp`. **Nothing to fix now**; make the comparison directional when the pipeline lands.

**R15 — Lima friction.** `/Users/mba` is virtiofs read-only, no toolchain in the cloud image, and four to five project VMs now exist (`airusb`, `airusb-vhci`, `kbuild`, plus stopped probes). Cheap, but budget it.

---

## 9. What NOT to do

**Wire format**

- **Do not byteswap `setup[8]`.** It is raw USB SETUP; its `wValue`/`wIndex`/`wLength` stay little-endian inside a big-endian header. Swapping the header wholesale breaks enumeration.
- **Do not use the host's `<errno.h>` values** in any code that can be compiled off-Linux. macOS `ETIMEDOUT` is 60, Linux's is 110, and macOS has no `EREMOTEIO`.
- **Do not include `<linux/usb.h>` or use `URB_*`.** The wire namespace is `USBIP_URB_*` from `include/uapi/linux/usbip.h`.
- **Do not reject unknown `transfer_flags` bits, or compare the whole word.** `DMA_MAP_SG`, `DIR_IN` and `NO_INTERRUPT` are always present on usb-storage traffic. Mask bit by bit.
- **Do not derive "is iso" from `number_of_packets != 0`**, and do not believe the `.rst`'s "shall be 0xffffffff if not ISO". The kernel sends 0.
- **Do not use `start_frame` as any kind of discriminator.** Echo it. It is 0 for control/bulk, `-1` only on an interrupt URB's first submission, and thereafter whatever we last returned.
- **Do not assume `seqnum` starts at 1, is dense, or resets on attach.** Hash map, always.
- **Do not emit a 20-byte `RET_SUBMIT`.** Every PDU is 48 bytes with the tail zeroed.
- **Do not synthesize `-EREMOTEIO`.** The USB core does it in `__usb_hcd_giveback_urb()`.

**Kernel contract**

- **Do not send a `RET_SUBMIT` for a seqnum the kernel does not hold** — including one already answered, one already retired by a `RET_UNLINK`, and duplicates. It kills the port and every URB on it.
- **Do not leave a `CMD_UNLINK` unanswered.** Unkillable D-state.
- **Do not under-deliver a header or a payload.** `MSG_WAITALL` with no timeout means the `vhci_rx` kthread **hangs**, it does not error — and then silently consumes the next PDU's header as payload. *(The architecture researcher called a truncated header "a fatal framing error"; **[V]** the `ret != sizeof(pdu)` branch is effectively unreachable and the real outcome is an indefinite hang.)*
- **Do not report `actual_length > transfer_buffer_length`**, and **do not send payload after an OUT `RET_SUBMIT`** regardless of `actual_length`.
- **Do not write a PDU in two syscalls.** One `writev()` per PDU, or a dedicated tx buffer. There is no length prefix and no record boundary.
- **Do not `close()` the socket as an error signal** while URBs matter without answering them first.

**sysfs**

- **Do not pick a port whose half disagrees with the speed.** The kernel accepts it and then disagrees with itself about where the device is.
- **Do not treat `EBUSY` as a parse error.** It is the "try another port" signal.
- **Do not hardcode** 8 ports, 16 ports, `usb3`/`usb4`, or `/sys/devices/platform/vhci_hcd` (that symlink does not exist; the kernel removes one it never creates). Read `nports`, `status`, and `usb*/busnum`.
- **Do not set `O_NONBLOCK` and expect it to change the kernel's behaviour.** It applies only to our end.
- **Do not try to chmod sysfs attributes with udev `MODE=`/`OWNER=`/`GROUP=`.** They are inert for anything without a device node.
- **Do not pass a bare fd number between processes.** `sockfd_lookup()` resolves against the writer's own fd table.

**Tooling and environment**

- **Do not run `usbip bind`, and do not load `usbip-host`, in a Lima `vz` VM.** It wedged a guest once and is exporter-side work we never need.
- **Do not run `usbipd`, `usbip attach`, or `usbip list -r`.** We are not a USB/IP peer; we replace the handshake with AirUSB and do the sysfs write ourselves. The kernel never speaks `OP_REQ_IMPORT` — that is a userspace-only preamble.
- **Do not plan to link `libusbip`.** It does not exist on Debian or Ubuntu; both ship only static binaries.
- **Do not use Debian's genericcloud/cloud kernel.** No `CONFIG_USB_SUPPORT` at all; unfixable by any package.
- **Do not encode "always apt-install `linux-modules-extra`".** Resolve with `modinfo -n vhci_hcd`.
- **Do not rely on `usbip_debug` alone** for tracing; you also need the `dynamic_debug` line.

**Architecture**

- **Do not put the USB/IP codec in `protocol/`.** It would ship a USB/IP parser inside the macOS root daemon.
- **Do not use `RemoteDevicePort` behind vhci.** It is one-transfer-at-a-time by design and treats any other `request_id` as fatal.
- **Do not introduce threads or locks** to solve the concurrency; use the seqnum table and one poll loop.
- **Do not block the socketpair reader on the network, ever.** Every hang in §4.2 is a violation of that one rule.
- **Do not split one URB into several AirUSB transfers.** Segment and reassemble into one transfer at the exporter.
- **Do not synthesise a descriptor byte anywhere, for any reason.**
- **Do not skip L3 to L4.** A kernel in the loop costs a reboot per iteration and leaves evidence you cannot trust.