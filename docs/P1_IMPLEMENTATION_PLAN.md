# AirUSB Hub — Phase 1 Implementation Plan

**Status:** Final Phase 1 architecture. Implementable as written.
**Scope:** macOS↔macOS first; Windows and Linux backends designed for but not built in Phase 2.
**Priority order (hard):** Correctness > Compatibility > Reliability > Latency > Throughput.

---

## 0. Synthesis summary and defect register

This design takes the **failure-first spine** (fatal-deadline analysis, watchdog budget table, single-mount safety theorem, macOS CI mechanism depth), the **wire-protocol-first protocol** (32-byte self-describing header, mandatory segmentation, numbered validation rules, portable status enum), and the **platform-abstraction-first boundary** (`BackendCaps`, `Ep0Arbiter` with two origins, copy-at-the-boundary, quiesce-before-respond).

Every defect raised by the three judgements is resolved below. "Accepted" means the defect is real and we ship with it, for the stated reason.

| # | Defect | Resolution | Section |
|---|---|---|---|
| D-01 | Doorbell loop mishandles `StatusTransfer`; no-data control transfer deadlocks the CI queue | Explicit TD→URB assembly rule; `StatusTransfer` is a mandatory case; every TD in a chain is completed | §5.4 |
| D-02 | One SUBMIT per `NormalTransfer` splits a logical bulk transfer, injecting spurious short packets | Rule: on non-control endpoints **one `NormalTransfer` == one logical URB**; never split, never coalesce. Runtime assertion + P2 probe (open question OQ-1) | §5.4, §12 |
| D-03 | Cached `GET_DESCRIPTOR` not truncated to `wLength` | `Ep0Arbiter` rule A-3: response is `min(len(blob), wLength)`, reported short when shorter | §4.3 |
| D-04 | `GET_STATUS` served from cache (halt bit is live state) | `GET_STATUS` is **FORWARD** for every recipient | §4.3 |
| D-05 | No stall barrier → unbounded LAN-RTT stall retry loop | Per-endpoint `stall_barrier`; doorbells always consumed, transmission gated until `CTRL_ACK(EP_CLEAR_HALT)` | §5.5 |
| D-06 | `-resetWithError:` destroys the capture mid-lease | Banned by lint. `DEVICE_RESET` is a **logical** reset only | §6.4, §7.5 |
| D-07 | No re-check of `endpointState` before writing kernel IO buffer (silent kernel corruption) | Five-part A9 defence, mandatory from the first line of `CiHostBackend` | §5.6 |
| D-08 | `matchInterfaces:` default YES lets `IOUSBMassStorageDriver` mount a leased drive | `matchInterfaces:NO` always, enforced by lint | §7.2 |
| D-09 | Pipe handles not re-acquired after config/alt change or logical reset | Mandatory `rebuildPipeTable()` after every `SET_CONFIG`/`SET_ALT`/`DEVICE_RESET`; pipe table generation counter | §7.5 |
| D-10 | Per-pipe abort + blind resubmit corrupts BOT phase | **AirUSB has no per-URB cancel guarantee.** `CANCEL` is endpoint-scoped with declared granularity; collateral is reported honestly with `TOGGLE_UNKNOWN`; nothing is ever resubmitted by AirUSB | §3.9, §6.6 |
| D-11 | 5 s bulk deadline aborts legitimate flash GC mid-data-phase | Exporter ceiling 30 s; importer watchdog 45 s; rule: **the importer never times out before the exporter** | §6.1 |
| D-12 | Link speed absent from the wire | `speed` is an explicit field in `ATTACH_OK` and `DEVICE_MANIFEST`; manifest/speed consistency validator | §3.6, §3.7 |
| D-13 | IN-completion fragmentation unspecified | Segmentation is mandatory and typed: first segment is `COMPLETE` (fixed body), continuations are `DATA` (B=0) | §3.2, §3.5 |
| D-14 | No Windows origin for `CLEAR_HALT` | Verb origin table names `UdecxUsbEndpointSetCallbacks`/`EvtUsbEndpointReset` and `EvtUsbEndpointPurge` | §4.4 |
| D-15 | Synchronous no-I/O delegate makes the Windows parked-`WDFREQUEST` pattern inexpressible | Backend verbs are **ticketed**: `beginX() -> Ticket`, resolved by `onVerbResult(Ticket, status)` | §4.1 |
| D-16 | `complete()` carries no buffer | `TransferResult` carries a `BufferRef` | §4.1 |
| D-17 | Manifest is a cache, not a UdeCx completeness contract | Manifest must carry device, all configs at full `wTotalLength`, BOS, device qualifier, other-speed config, LANGID table, all strings × all LANGIDs, speed | §3.7 |
| D-18 | WinUSB cannot report SuperSpeed → speed guard defeated | `manifest_validate()` cross-checks descriptors against declared speed and refuses on contradiction | §3.7 |
| D-19 | Channel model needs per-endpoint open events Linux vhci cannot produce | Channel id is a **pure function** of `(attach_slot, ep_addr)`. `EP_OPEN`/`EP_CLOSE` deleted from v1 | §3.4 |
| D-20 | Ordering contract depends on the TCP scheduler; breaks under QUIC | No cross-channel ordering is guaranteed, ever. Terminal messages are not barriers; on `DEVICE_GONE`/`DETACH_OK` the importer completes everything outstanding locally | §3.10 |
| D-21 | Status enum defined only against macOS | Three-column mapping table + `NATIVE_STATUS` TLV (diagnostics only) | §3.11 |
| D-22 | `onStandardRequestAbsorbed(SetupPacket)` forces Windows to fabricate a SETUP it never saw | Replaced by structured `AbsorbedControlEvent` | §4.1 |
| D-23 | Missing `actual_len <= requested_len` check before copying into a kernel VA | Rule **R5**, enforced in `protocol/validate` *and* re-asserted at the copy site | §3.12, §5.6 |
| D-24 | Arena reservation / allocation inside the fatal-deadline command handler | Arena is preallocated on the session strand at attach time from the manifest; the CI queue only pops from a lock-free per-endpoint freelist | §5.3 |
| D-25 | `DETACH_OK` ordering guarantee false under multilink | Multilink deferred to Phase 4; and the guarantee is deleted outright (see D-20) | §3.10, §3.8 |
| D-26 | Backpressure cutoff stops draining doorbells → fatal `DoorbellOverflow` | Doorbells are **always** consumed and `processDoorbell:` always called; only *transmission* is gated | §5.5, §6.3 |
| D-27 | `RESUME`/dedup has a lost-completion hole that hangs an endpoint | **Cut from v1.** Reconnection always means a fresh `ATTACH`. Verbs reserved | §3.8, §12 |
| D-28 | `DeviceSurrender` used on the normal release path (suppresses reset + rematch) | Plain `destroy` is the normal path; `Surrender` only on `kUSBHostMessageDeviceIsRequestingClose` | §7.6 |
| D-29 | No exporter-side lease / no ordering between importer disconnect and capture release | Watchdog table with startup assertion `T_detach_importer + t_disconnect_max < T_lease_exporter` | §6.1, §7.1 |
| D-30 | Credit accounting can silently drift and deadlock | Single defined release point; `assert 0 <= credit <= granted`; debug credit cross-check in `PING` | §6.3 |
| D-31 | 6-digit SAS collapses if pairing is retryable | Hard cap 3 attempts/min/peer, exponential backoff, failed attempt burns the pairing session | §3.14 |
| D-32 | Single socket means a lost segment stalls PING too | **Accepted.** `DEGRADED` is silent and 1.5 s; disconnect only at 6 s. Multilink is a Phase 4 capability bit | §12 |

---

## 1. Layer diagram

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  UI / CLI  (airusbctl, menu-bar agent)          — out of Phase 2 scope        │
└──────────────────────────────────────────────────────────────────────────────┘
                                    │ local IPC (unix socket, JSON lines)
┌──────────────────────────────────────────────────────────────────────────────┐
│  core/        no OS USB API, no sockets, no wire bytes                        │
│    Ep0Arbiter · DeviceManifest · AttachRegistry · RequestTable · Arena        │
│    CreditController · Watchdog · Clock · Log · Lease                          │
└───────────┬──────────────────────────────────────────┬───────────────────────┘
            │ IImporterBackend / IExporterBackend      │ IAirUsbSession
┌───────────┴───────────────────┐        ┌─────────────┴───────────────────────┐
│  platform/{macos,windows,linux}│       │  protocol/   frame codec, validate,  │
│    thin adapters only          │       │              manifest codec, status  │
│                                │       │              maps, Noise handshake   │
└────────────────────────────────┘       └─────────────┬───────────────────────┘
                                                       │ IAirUsbTransport
                                         ┌─────────────┴───────────────────────┐
                                         │  transport/  TcpTransport (+ sched)  │
                                         │              QuicTransport (Ph. 5)   │
                                         └──────────────────────────────────────┘
                                         ┌──────────────────────────────────────┐
                                         │  discovery/  mDNS _airusb._tcp,      │
                                         │              PeerStore, pairing flow │
                                         └──────────────────────────────────────┘
```

**Dependency rule, enforced in CI:** `core/` and `protocol/` compile against libc/libc++ alone with `-DAIRUSB_NO_PLATFORM`. CI greps both trees for `IOKit|IOUSBHost|dispatch_|windows\.h|linux/usb|winusb|udecx` and fails the build on a hit. `platform/*` may include `core/`, `protocol/`, `transport/`; nothing may include `platform/*`.

**Language:** C++20 for `core/`, `protocol/`, `transport/`, `discovery/`. Objective-C++ for `platform/macos`. C (KMDF) for `platform/windows/airusb_sys`, C++ for the Windows usermode service. C++ for `platform/linux`. Chosen because it is the only language that links into all three driver-adjacent environments with no FFI layer.

---

## 2. Directory / module layout

```
airusb/
  core/
    Ep0Arbiter.{h,cpp}        the standard-request policy table (§4.3). Zero platform code.
    DeviceManifest.{h,cpp}    immutable descriptor bundle + accessors + validator
    AttachRegistry.{h,cpp}    device_uid -> Lease. Single source of exclusivity truth.
    Lease.{h,cpp}             lease_epoch, device_epoch, holder peer_id, lease timers
    RequestTable.{h,cpp}      outstanding requests per (attach, endpoint); request_id rules
    Arena.{h,cpp}             per-attach slab arena; lock-free per-endpoint freelists
    CreditController.{h,cpp}  2-D credit (urbs, bytes); single release point
    Watchdog.{h,cpp}          THE timeout table (§6.1) + startup consistency assertions
    Clock.{h,cpp}             monotonic-continuous only. mach_absolute_time banned by lint.
    Log.{h,cpp}               structured tags, token-bucket limiter, lock-free trace ring
    Status.h                  AirUsbStatus (§3.11)
    UsbTypes.h                Speed, XferType, SetupPacket, EndpointDescriptorModel
    ImporterSession.{h,cpp}   importer-side protocol FSM (owns SessionStrand state)
    ExporterSession.{h,cpp}   exporter-side protocol FSM
    IImporterBackend.h        §4.1
    IExporterBackend.h        §4.2
  protocol/
    Wire.h                    every offset/width as a named constant + static_asserts
    Encode.cpp Decode.cpp     explicit byte loads/stores only; no struct overlay
    Validate.cpp              rules R1..R12 (§3.12), one function per message type
    ManifestCodec.{h,cpp}     TLV container; descriptor blobs opaque to this layer
    StatusMapMacos.cpp StatusMapWindows.cpp StatusMapLinux.cpp
    Version.{h,cpp}           two-axis negotiation (§3.13)
    Noise.{h,cpp}             Noise_XX / Noise_IK over a vendored, audited core
    Sas.{h,cpp}               6-digit short authentication string derivation
  transport/
    IAirUsbTransport.h
    TcpTransport.{h,cpp}
    FrameScheduler.{h,cpp}    3 priority classes, 16 KiB quantum, DRR
    RecordLayer.{h,cpp}       length prefix + ChaCha20-Poly1305 records
    QuicTransport.{h,cpp}     Phase 5
    FaultTransport.{h,cpp}    test-only decorator (delay/jitter/drop/RST/stall/reorder)
  discovery/
    MdnsResponder.{h,cpp} MdnsBrowser.{h,cpp}
    PeerStore.{h,cpp}         pinned Ed25519 identities, grants, first_seen
  platform/
    macos/
      CiMessage.{h,cpp}       IOUSBHostCIMessage bit-packing as PURE FUNCTIONS (no IOKit)
      CiHostBackend.mm        IOUSBHostControllerInterface + the four state machines
      HostDeviceExporter.mm   IOUSBHostDevice / Interface / Pipe capture
      DiskGuard.mm            DiskArbitration claim / unmount / unclaim
      PowerObserver.mm        IOPMrootDomain sleep/wake
    windows/
      UdecxHostBackend.cpp    usermode service half
      airusb_sys/             KMDF UdeCx client driver
      WinUsbExporter.cpp
    linux/
      VhciShimBackend.cpp     socketpair + sysfs attach
      UsbipShimCodec.cpp      USB/IP <-> AirUSB translation, loopback only
      UsbfsExporter.cpp
  tests/
    unit/                     §8.1
    vectors/                  golden hex blobs, one per message type + CI capabilities blob
    fuzz/                     libFuzzer targets over decode+validate and the usbip shim
    fakes/ScriptedDevice.cpp  fake exporter: RAM-disk mass-storage device
    fakes/InMemoryVhca.cpp    fake importer (two variants, §8.1)
    integration/              §8.2 — requires hardware, not run in CI
  docs/
    P1_IMPLEMENTATION_PLAN.md (this file)
```

---

## 3. The AirUSB/1 wire protocol

### 3.0 Conventions

* **Little-endian everywhere.** USB is LE; all three targets are LE. Descriptor blobs travel verbatim, so no buffer ever holds mixed endianness.
* **No struct overlay.** All decode uses explicit `rd_u8/rd_u16/rd_u32/rd_u64`; message starts are arbitrarily aligned after coalescing.
* Senders MUST zero reserved fields. Receivers MUST ignore unknown reserved bits and unknown TLVs, and MUST **reject** unknown flag bits on data-plane messages (`0x40`–`0x4F`) — a semantics-bearing flag you don't understand corrupts a transfer.
* Parsing always operates on a **fully received, bounded record**. There is no streaming parser over partial input, so the desync/resync failure class does not exist.

### 3.1 L0 — preamble and record framing

First 8 bytes of every TCP connection, plaintext, both directions:

| off | sz | field | value |
|---|---|---|---|
| 0 | 4 | magic | `"AUSB"` (41 55 53 42) |
| 4 | 1 | wire_major | 1 |
| 5 | 1 | wire_minor | 0 |
| 6 | 2 | sec_flags | bit0 `SEC_NOISE_XX` (MUST be 1 on TCP), bit1 `SEC_TLS13_RPK`, rest MBZ |

Bad magic or unsupported `wire_major` → send `"AUSB" FF 00 <u16 supported_major_mask>` and close. This is the only plaintext message after the preamble.

Records:

```
+0  4  record_len  LE u32, length of record_body
+4  N  record_body
```

* Pre-handshake: `record_len <= 8192`, body is a raw Noise handshake message.
* Post-handshake: body is a Noise transport message (ChaCha20-Poly1305, 16-byte tag). Nonce is the Noise counter, so replay, reorder and truncation are cryptographically impossible and the L1 header needs no sequence number. Counter must advance by exactly 1; a gap is `MALFORMED_FRAME` → `GOODBYE`, never a resync.
* Plaintext ceiling 65519 (Noise limit). Negotiated `max_record_bytes` default 16640.
* **Coalescing:** one record MAY carry several L1 messages back to back, each self-delimiting via `body_len`. Parse until the record is exactly consumed; leftover bytes = `MALFORMED_FRAME` = fatal.
* Rekey at 2^32 records.

### 3.2 L1 — message header, exactly 32 bytes

| off | sz | field | notes |
|---|---|---|---|
| 0 | 1 | `type` | §3.3 |
| 1 | 1 | `flags` | bit0 `SEG_MORE`, bit1 `SEG_FIRST`, bit2 `EXPEDITE`, bit3 `ISO_TABLE`, bits4-7 MBZ (reject if set on 0x40–0x4F) |
| 2 | 2 | `channel` | u16, §3.4. 0 = session control |
| 4 | 4 | `body_len` | bytes following this header **in this message** (fixed body + data) |
| 8 | 4 | `attach_id` | 0 for session-scope messages |
| 12 | 4 | `seg_offset` | byte offset of this segment inside the logical data payload |
| 16 | 8 | `request_id` | monotonic per `(channel, initiator)`. 0 = unsolicited |
| 24 | 2 | `status` | `AirUsbStatus`. MUST be 0 on every request |
| 26 | 2 | `device_epoch` | bumped on attach and on every completed logical reset; mismatch → drop silently |
| 28 | 4 | `total_len` | total logical data length across all segments |

Derived: `data_len = body_len - B(type)`, where `B(type)` is the type's fixed-body size (0 for unknown types). **Unknown types are skipped via `body_len`** — the forward-compatibility primitive USB/IP lacks. An unknown type with `request_id != 0` gets `ERROR{UNSUPPORTED_MESSAGE}` echoing the request_id.

**Segmentation is mandatory.** Max data bytes per message = negotiated `max_segment_bytes`, default **16384**.

* The first segment of a logical payload has `SEG_FIRST` set and carries the message's fixed body.
* **Continuation segments are always type `DATA` (0x44), `B(DATA)=0`**, correlated by `(channel, request_id)`, with `seg_offset` and `total_len` copied forward. This removes the "is `actual_len` per-frame or per-transfer?" ambiguity that would otherwise make two implementations diverge.
* `seg_offset + data_len <= total_len`; the last segment clears `SEG_MORE` and satisfies `seg_offset + data_len == total_len`.
* Segments of one payload are strictly ordered and never interleaved with another payload **on the same channel**. Different channels interleave freely.

Rationale for 16 KiB: a 1 MiB bulk IN becomes 64 messages, so the worst self-inflicted delay in front of a queued 8-byte interrupt completion is ~131 µs on 1 GbE instead of ~8.4 ms. This removes *self-inflicted* head-of-line blocking. Kernel-level TCP HOL from a lost segment survives until QUIC; that is stated honestly, not hidden.

### 3.3 Message types

```
session          0x01 HELLO      0x02 HELLO_OK   0x03 PING    0x04 PONG
                 0x05 GOODBYE    0x06 ERROR
                 0x08 LINK_JOIN  0x09 LINK_JOIN_OK        [RESERVED, Phase 4 multilink]
pairing / list   0x10 PAIR_REQUEST 0x11 PAIR_CONFIRM 0x12 PAIR_RESULT
                 0x13 LIST_DEVICES 0x14 DEVICE_LIST 0x15 DEVICE_EVENT
attach           0x20 ATTACH     0x21 ATTACH_OK  0x22 DEVICE_MANIFEST
                 0x23 DETACH     0x24 DETACH_OK  0x25 DEVICE_GONE  0x26 ATTACH_CREDIT
                 0x28 RESUME     0x29 RESUME_OK  0x2A RESUME_REFUSED  [RESERVED, Phase 4]
usb control      0x30 SET_CONFIGURATION 0x31 SET_INTERFACE 0x32 EP_CLEAR_HALT
                 0x33 DEVICE_RESET      0x34 SUSPEND_IO    0x35 RESUME_IO
                 0x36 CTRL_ACK
data plane       0x40 SUBMIT     0x41 COMPLETE   0x42 CANCEL  0x43 CANCEL_ACK
                 0x44 DATA
```

`HELLO` is symmetric — both peers send it — so exporter/importer are session roles, not product roles.

### 3.4 Channels — derived, never negotiated

```
channel 0                              session control
channel = (attach_slot << 8) | ep_addr data plane, attach_slot ∈ 1..15
```

`attach_slot` is assigned by the **importer** and carried in `ATTACH`. Both peers compute channel ids identically; there is **no `EP_OPEN` handshake and no channel-open round trip**. This is what makes the Linux `vhci-hcd` shim implementable: vhci emits no endpoint-open event at all, only `CMD_SUBMIT`, so any design requiring a per-endpoint open message either has to eagerly open every endpoint of every alt setting or insert a round trip into the first transfer of every endpoint. Neither is necessary.

The exporter derives its pipe set from the active configuration and alt settings — exactly as a real host controller does — not from wire messages.

Priority class from `xfer_type`: `RT` (isochronous), `HIGH` (control + interrupt), `BULK`. Class 0 (session control + `PING`/`PONG` + `CANCEL`) has strict priority. Within a link, deficit round robin with a 16 KiB quantum; `EXPEDITE` jumps to the head of its class queue. `EXPEDITE` is set only on `PING`/`PONG`, `CANCEL`, and control-plane verbs.

### 3.5 SUBMIT (0x40), B = 40

| off | sz | field |
|---|---|---|
| 0 | 1 | `ep_addr` — `bEndpointAddress` incl. direction bit. Always explicit, never inferred |
| 1 | 1 | `xfer_type` — 0 CONTROL, 1 ISOCHRONOUS, 2 BULK, 3 INTERRUPT |
| 2 | 1 | `dir` — 0 OUT, 1 IN. **Authoritative for ep0.** MUST equal `ep_addr>>7` when `(ep_addr & 0x0F) != 0` |
| 3 | 1 | `xflags` — bit0 `SHORT_NOT_OK`, bit1 `ZERO_PACKET`, bit2 `ISO_ASAP`, rest MBZ |
| 4 | 4 | `buffer_len` — IN: max to read. OUT: bytes supplied. ISO: size of the packed data area |
| 8 | 4 | `timeout_ms` — 0 = none; the exporter always applies its own ceiling (§6.1) |
| 12 | 4 | `iso_pkt_count` — 0 unless `xfer_type == 1` |
| 16 | 4 | `interval` — service interval in (micro)frames for INT/ISO, else 0 |
| 20 | 4 | `stream_id` — 0 in v1 |
| 24 | 8 | `setup[8]` — verbatim USB SETUP packet, wire order (USB 3.2 §9.3). All-zero if `xfer_type != 0` |
| 32 | 8 | `submit_ts_ns` — importer monotonic timestamp, echoed verbatim in COMPLETE |

Data section = `[iso table: iso_pkt_count × 16]` then `[OUT payload]`.
Iso packet descriptor (16 B): `u32 offset; u32 length; u32 actual_length(0); u16 status(0); u16 rsvd`.

**Exactness rule:** `total_len == iso_pkt_count*16 + (dir==OUT ? buffer_len : 0)`. Any other value = `MALFORMED_FRAME` = fatal.

### 3.6 COMPLETE (0x41), B = 40

| off | sz | field |
|---|---|---|
| 0 | 1 | `ep_addr` — **echoed** |
| 1 | 1 | `xfer_type` — **echoed** |
| 2 | 1 | `dir` — **echoed** |
| 3 | 1 | `cflags` — bit0 `SHORT`, bit1 `ZLP_SENT`, bit2 `WAS_CANCELLED`, bit3 `COLLATERAL`, bit4 `TOGGLE_UNKNOWN` |
| 4 | 4 | `requested_len` — echoed `buffer_len` |
| 8 | 4 | `actual_len` — bytes actually moved on the bus |
| 12 | 4 | `payload_len` — USB data bytes carried across all segments of this completion (== `actual_len` for non-iso IN; 0 for OUT) |
| 16 | 4 | `iso_pkt_count` — echoed |
| 20 | 4 | `error_count` — iso |
| 24 | 4 | `start_frame` — iso |
| 28 | 4 | reserved MBZ |
| 32 | 8 | `submit_ts_ns` — echoed verbatim (importer-local clock; latency = `now - echo`) |

`status` lives in the L1 header. A COMPLETE is fully parseable with **zero** state about its SUBMIT — that is the direct fix for USB/IP's `RET_SUBMIT` zeroing direction and endpoint.

The redundancy between `payload_len`, `total_len` and `data_len` is deliberate: three independent statements of one fact, so a mismatch is a fatal protocol error rather than a silently wrong parse.

**Invariant I1 — exactly one COMPLETE per SUBMIT, always**, on the same channel with the same `request_id`, including for cancelled, collateral, timed-out and device-gone transfers. No implicit completion by connection teardown. `TOGGLE_UNKNOWN` means the exporter forced a pipe abort while this transfer may have been mid-phase; the importer must treat the endpoint as requiring halt recovery (§3.9).

### 3.7 ATTACH / ATTACH_OK / DEVICE_MANIFEST

**ATTACH (0x20), B = 24**
`u8 device_uid[16]; u8 exclusivity (MUST be 1 = EXCLUSIVE); u8 attach_slot (1..15); u16 flags; u32 importer_max_transfer_bytes;` + TLVs.

**ATTACH_OK (0x21), B = 40**
```
+0   4  attach_id            non-zero, exporter-assigned, not reused for 60 s
+4   4  credit_urbs          default 64
+8   4  credit_bytes         default 4 MiB
+12  2  speed                0 Low 1 Full 2 High 3 Super 4 SuperPlus 5 SuperPlusBy2
+14  1  cancel_granularity   0 = ENDPOINT-only, 1 = PER_REQUEST
+15  1  exporter_flags       bit0 supports DEVICE_RESET(logical), bit1 supports SUSPEND_IO
+16  4  device_latency_us    exporter's measured local device turnaround
+20  4  manifest_len
+24  4  lease_epoch
+28  4  urb_ceiling_ms       exporter's own per-URB abort ceiling (bulk/control)
+32  8  reserved MBZ
```
Failure carries the reason in `status` (`BUSY`, `EXCLUSIVITY_DENIED`, `CAPTURE_FAILED`, `MOUNTED_LOCALLY`, `NOT_PERMITTED`, `SPEED_UNSUPPORTED`) plus `TLV NATIVE_STATUS` and `TLV REJECT_REASON` (UTF-8, shown to the user).

**DEVICE_MANIFEST (0x22), B = 32** — *a completeness contract, not a cache*

```
+0   4  manifest_version = 1
+4   4  config_count       <= 8
+8   4  string_count       <= 128
+12  4  langid_count       <= 16
+16  2  speed              MUST equal ATTACH_OK.speed
+18  2  dflags   bit0 self-powered, bit1 remote-wakeup, bit2 USB3 streams, bit3 composite
+20  4  total_blob_bytes   <= 262144
+24  1  current_config_value
+25  3  reserved MBZ
+28  4  reserved MBZ
```

Then TLV sections carrying **verbatim raw descriptor bytes**, never re-serialized:

| TLV | required | why |
|---|---|---|
| `DEVICE_DESC` (18 B) | yes | |
| `CONFIG_DESC` ×N (full `wTotalLength` blob) | yes, all configs | UdeCx `UdecxUsbDeviceInitAddDescriptor` before `UdecxUsbDeviceCreate` |
| `BOS_DESC` | if `bcdUSB >= 0x0300` | |
| `DEVICE_QUALIFIER_DESC` | if HS-capable | **UdeCx answers this locally and cannot forward it** |
| `OTHER_SPEED_CONFIG_DESC` ×N | if HS-capable | same |
| `LANGID_TABLE` (string desc 0 verbatim) | yes | |
| `STRING_DESC` ×M `{u8 index; u16 langid; u16 len; bytes}` | every index referenced by any descriptor, for every LANGID | |
| `MANIFEST_HASH` (SHA-256 of concatenated blob sections) | yes | |

**`manifest_validate()` (in `protocol/`, runs on both peers before the attach completes):**

1. Every descriptor blob walks cleanly: `bLength` chain sums to `wTotalLength`, no `bLength == 0`, no overrun.
2. `speed >= Super` **iff** every configuration's superspeed endpoints carry SuperSpeed Endpoint Companion descriptors, and `bMaxPacketSize0 == 9`.
3. `speed <= High` **iff** `bMaxPacketSize0 ∈ {8,16,32,64}` and no SS companion descriptors are present.
4. Every string index referenced by any descriptor is present for every declared LANGID.
5. `current_config_value` names an existing configuration or is 0.

Failure at any step → `ATTACH_OK{status = MANIFEST_INVALID}` and the attach is abandoned. This single validator catches the WinUSB-cannot-report-SuperSpeed case, the "bcdUSB is not speed" case, and the missing-device-qualifier case at once.

**Speed rule (no downgrade, ever):** the importer computes `effective = min(manifest.speed, backend.caps.max_speed)`. If `effective < manifest.speed` the importer **refuses the attach** with `SPEED_UNSUPPORTED` and logs `@@AIRUSB_ATTACH@@ status=speed_unsupported`. Presenting SuperSpeed descriptors on a High-Speed virtual port yields a device the guest OS mis-enumerates.

### 3.8 Detach and teardown

**DETACH (0x23), B = 8:** `u8 reason (1 USER_REQUEST, 2 IMPORTER_SHUTDOWN, 3 EXPORTER_RECLAIM, 4 POLICY, 5 ERROR, 6 SLEEP); u8 dflags (bit0 FORCE = skip drain); u16 drain_timeout_ms (0 = 2000); u32 reserved`
**DETACH_OK (0x24), B = 16:** `u32 urbs_completed; u32 urbs_cancelled; u32 bytes_dropped; u32 reserved`.

Normal importer-initiated sequence — the explicit fix for USB/IP's silent `shutdown(SHUT_RDWR)`:

1. Importer's OS unmounts the volume. **If the unmount is dissented, the detach is refused and the user is told which app holds it.** Never forced.
2. Importer quiesces every endpoint locally and stops issuing SUBMITs.
3. Importer → `DETACH{USER_REQUEST}`.
4. Exporter enters `DRAINING`: refuses new SUBMITs with `DETACHING`, drives every outstanding URB to a COMPLETE within `drain_timeout_ms`, synthesizes `COMPLETE{XFER_CANCELLED}` for anything left.
5. Exporter → `DETACH_OK`.
6. **On receipt of `DETACH_OK` the importer immediately and locally completes anything still outstanding with `XFER_DEVICE_OFFLINE`, then tears down the virtual device.** It does not wait for late COMPLETEs and MUST ignore any that arrive afterwards. (See §3.10 — `DETACH_OK` is *not* an ordering barrier.)
7. Exporter releases the physical device with plain `destroy` (§7.6), then `DADiskUnclaim`.
8. `attach_id` retired, quarantined 60 s.

**Exporter reclaim:** `DETACH{EXPORTER_RECLAIM}` → importer must unmount before answering. If its OS refuses, it answers `DETACH_OK{status=BUSY}`; the exporter **keeps the attach alive** and surfaces the refusal to its user. The user may send `DETACH{FORCE}`, which the importer converts to a surprise-removal event, logged at `@@AIRUSB_ERROR@@` with an explicit data-loss warning.

**Surprise physical unplug:** exporter sends unsolicited `DEVICE_GONE` (request_id 0). The importer, on `DEVICE_GONE`, **locally completes everything outstanding with `XFER_DEVICE_OFFLINE` and ignores every late COMPLETE for that `attach_id`.** It never waits.

**Transport loss:** after `T_link_dead` the importer treats the attach as `DEVICE_GONE`. **In-flight URBs are never resumed and sessions are never resumed for an existing attach in v1.** Replaying a mass-storage WRITE whose outcome is unknown is a corruption hazard, USB offers no idempotency, and the exactly-once dedup mechanism that would make resume safe has a lost-completion hole that hangs an endpoint with no local timer to recover it. Reconnection always means a fresh `ATTACH` and a fresh enumeration. `RESUME` verbs are reserved for Phase 4.

### 3.9 CANCEL (0x42) B=16 / CANCEL_ACK (0x43) B=8

```
CANCEL:      u8 ep_addr; u8 mode (0 REQUEST, 1 ENDPOINT); u16 reserved;
             u32 reserved; u64 target_request_id  (ignored when mode==ENDPOINT)
CANCEL_ACK:  u32 cancelled_count; u32 collateral_count
```

**AirUSB does not promise per-URB cancellation.** `-[IOUSBHostPipe abortWithOption:]` aborts *all* pending I/O on a pipe; WinUSB has no per-request abort either; only Linux usbfs has `USBDEVFS_DISCARDURB`. Pretending otherwise produces an interface that macOS cannot implement.

Rules:

* The exporter declares `cancel_granularity` in `ATTACH_OK`.
* An exporter with `ENDPOINT`-only granularity that receives `mode=REQUEST` **MAY escalate to endpoint scope**. It then MUST emit `COMPLETE{XFER_CANCELLED}` for every collateral request with `cflags.COLLATERAL` set, and MUST set `cflags.TOGGLE_UNKNOWN` on every collateral completion, because a forced pipe abort leaves the data toggle and any in-progress class-level phase indeterminate.
* **AirUSB never resubmits anything on the peer's behalf.** Resubmitting the survivors of a pipe abort is a silent write-corruption path: the device may be mid-data-phase, the toggle was not reset (only `-clearStallWithError:` resets it), and the host's Bulk-Only Transport phase machine has already desynchronised. Cancelled is reported as cancelled; the guest's own class driver owns recovery.
* On receipt of any completion with `TOGGLE_UNKNOWN`, the importer sets that endpoint's `stall_barrier` (§5.5). Subsequent transfers are held locally until an `EP_CLEAR_HALT` for that endpoint is acknowledged. The guest driver's standard halt-recovery (`CLEAR_FEATURE(ENDPOINT_HALT)`) supplies it; for mass storage the driver additionally issues the class Bulk-Only Reset (`0x21/0xFF`), which AirUSB forwards verbatim.
* `CANCEL_ACK` status: `OK`, `ALREADY_COMPLETED` (benign race, not an error), `NOT_FOUND` (logged, non-fatal — a late completion racing a cancel is legitimate).

### 3.10 The ordering contract (must survive the QUIC swap)

1. **Within one channel, messages are strictly ordered.** This is the only ordering guarantee the protocol makes.
2. **No ordering is guaranteed across channels**, including between channel 0 and any data channel. USB itself does not require cross-endpoint ordering.
3. Terminal messages (`DETACH_OK`, `DEVICE_GONE`, `GOODBYE`) are **not barriers**. A receiver must never assume the data channels have drained when one arrives; it locally completes everything outstanding.
4. Therefore correctness never depends on the TCP frame scheduler. Under QUIC, channel→stream is a direct mapping and rules 1–3 are unchanged; the `FrameScheduler` is deleted and segmentation becomes a no-op.
5. **Test obligation:** `FaultTransport` includes a `ReorderAcrossChannels` mode used in every loopback conformance run, so a dependency on cross-channel ordering fails in Phase 2, not in Phase 5.

### 3.11 Portable status enum and the three mapping tables

`AirUsbStatus` is `u16`. It is the **only** status on the wire. Native codes exist only inside platform backends.

```
0x0000 OK
protocol/session
0x0001 ERROR_GENERIC       0x0002 BAD_ARGUMENT       0x0003 UNSUPPORTED_VERSION
0x0004 UNSUPPORTED_MESSAGE 0x0005 MALFORMED_FRAME*   0x0006 LIMIT_EXCEEDED*
0x0007 NOT_PERMITTED       0x0008 NOT_PAIRED         0x0009 AUTH_FAILED*
0x000A NO_RESOURCES        0x000B BUSY               0x000C NOT_FOUND
0x000D ALREADY_EXISTS      0x000E INTERNAL           0x000F TRANSPORT_LOST†
0x0010 ALREADY_COMPLETED
attach / lifecycle
0x0020 DEVICE_GONE         0x0021 DETACHING          0x0022 EXCLUSIVITY_DENIED
0x0023 CAPTURE_FAILED      0x0024 ATTACH_UNKNOWN     0x0025 MANIFEST_INVALID
0x0026 SPEED_UNSUPPORTED   0x0027 MOUNTED_LOCALLY
usb transfer
0x0040 XFER_STALL          0x0041 XFER_TIMEOUT       0x0042 XFER_CANCELLED
0x0043 XFER_SHORT          0x0044 XFER_OVERRUN       0x0045 XFER_UNDERRUN
0x0046 XFER_CRC            0x0047 XFER_BITSTUFF      0x0048 XFER_PROTOCOL
0x0049 XFER_NO_BANDWIDTH   0x004A XFER_MISSED_SERVICE 0x004B XFER_EP_STOPPED
0x004C XFER_DEVICE_OFFLINE 0x004D XFER_NAK_TIMEOUT   0x004E XFER_BAD_TOGGLE
0x004F XFER_STREAM_ERROR   0x0050 XFER_UNKNOWN
* = fatal: send GOODBYE and close the session
† = LOCAL ONLY. MUST NEVER APPEAR ON THE WIRE.
```

`TRANSPORT_LOST` means "we do not know whether this transfer happened", which USB cannot express. It is never delivered to a guest OS as a transfer completion; it is converted into a port disconnect.

Unmappable native codes become `XFER_UNKNOWN` + `TLV NATIVE_STATUS{u32 platform_id, u32 native_code}`, **for logging only, never for semantics**. This is the structural fix for USB/IP putting raw Linux errno on the wire (`ECONNRESET` is 104 on Linux, 54 on macOS; `EREMOTEIO` does not exist in the macOS SDK).

| AirUsbStatus | macOS `IOUSBHostCIMessageStatus` | Windows `USBD_STATUS` | Linux errno (emitted by the shim, on Linux) |
|---|---|---|---|
| `OK` | `Success` | `USBD_STATUS_SUCCESS` | `0` |
| `XFER_SHORT` | `Success` **with `transferLength < requested`** (macOS has no short status) | `USBD_STATUS_SUCCESS` (or `ERROR_SHORT_TRANSFER` if `SHORT_NOT_OK`) | `0`, or `-EREMOTEIO` if `SHORT_NOT_OK` |
| `XFER_STALL` | `StallError` | `USBD_STATUS_STALL_PID` / `ENDPOINT_HALTED` | `-EPIPE` |
| `XFER_TIMEOUT` | `Timeout` | `USBD_STATUS_TIMEOUT` | `-ETIMEDOUT` |
| `XFER_CANCELLED` | `EndpointStopped` | `USBD_STATUS_CANCELED` | `-ECONNRESET` |
| `XFER_OVERRUN` | `OverrunError` | `USBD_STATUS_BABBLE_DETECTED` / `DATA_OVERRUN` | `-EOVERFLOW` |
| `XFER_UNDERRUN` | `OverrunError` (no underrun on macOS) | `USBD_STATUS_DATA_UNDERRUN` | `-EREMOTEIO` |
| `XFER_CRC` | `TransactionError` | `USBD_STATUS_CRC` | `-EILSEQ` |
| `XFER_BITSTUFF` | `ProtocolError` | `USBD_STATUS_BTSTUFF` | `-EILSEQ` |
| `XFER_BAD_TOGGLE` | `ProtocolError` | `USBD_STATUS_DATA_TOGGLE_MISMATCH` | `-EILSEQ` |
| `XFER_PROTOCOL` | `ProtocolError` | `USBD_STATUS_INTERNAL_HC_ERROR` / `INVALID_PIPE_HANDLE` | `-EPROTO` |
| `XFER_NAK_TIMEOUT` | `TransactionError` | `USBD_STATUS_TIMEOUT` | `-ETIMEDOUT` |
| `XFER_NO_BANDWIDTH` | `NoResources` | `USBD_STATUS_NO_BANDWIDTH` | `-ENOSPC` |
| `XFER_MISSED_SERVICE` | `MissedServiceError` | `USBD_STATUS_ISOCH_REQUEST_FAILED` / `ISO_NOT_ACCESSED_BY_HW` | `-EXDEV` |
| `XFER_EP_STOPPED` | `EndpointStopped` | `USBD_STATUS_CANCELED` | `-ESHUTDOWN` |
| `XFER_DEVICE_OFFLINE`, `DEVICE_GONE` | `Offline` | `USBD_STATUS_DEVICE_GONE` | `-ENODEV` |
| `XFER_STREAM_ERROR` | `ProtocolError` | `USBD_STATUS_INTERNAL_HC_ERROR` | `-EPROTO` |
| `NO_RESOURCES` | `NoResources` | `USBD_STATUS_INSUFFICIENT_RESOURCES` | `-ENOMEM` |
| `NOT_PERMITTED` | `NotPermitted` | `USBD_STATUS_INVALID_PARAMETER` | `-EPERM` |
| `BAD_ARGUMENT` | `BadArgument` | `USBD_STATUS_INVALID_PARAMETER` | `-EINVAL` |
| `UNSUPPORTED_MESSAGE` | `Error` | `USBD_STATUS_NOT_SUPPORTED` | `-EOPNOTSUPP` |
| `XFER_UNKNOWN`, `ERROR_GENERIC` | `Error` | `USBD_STATUS_INTERNAL_HC_ERROR` | `-EIO` |

**Discipline:** one canonical table per platform in `protocol/StatusMap*.cpp`. Windows numeric constants are lifted from `usbdi.h`/`usb.h` at build time and locked with `static_assert`; hand-copying them is forbidden. Unit tests assert (a) `AirUsb → native → AirUsb` is the identity for every status the platform can express, (b) every native constant the platform can produce has a defined image, defaulting to `XFER_UNKNOWN`, (c) no duplicate entries.

### 3.12 Receive-side validation rules R1–R12 (each fatal unless noted)

* **R1** `record_len <= 8192` before `HELLO_OK`; `<= max_record_bytes` after.
* **R2** No allocation is ever sized by a single peer field. `total_len <= negotiated max_transfer_bytes` (default 1 MiB, ceiling 16 MiB). Reassembly buffers come from a per-attach arena hard-capped at `credit_bytes`.
* **R3** `body_len >= B(type)` for known types; `data_len = body_len - B(type)`.
* **R4** Per-type exact-equality identities (§3.5, §3.6) MUST hold.
* **R5** `actual_len <= requested_len` recorded for that `request_id`; on IN, `payload_len == actual_len`. **Enforced in `protocol/Validate.cpp` AND re-asserted at the copy site in the backend.** This is the CVE-2016-3955 fix, and it is also what stops a buggy exporter from overrunning a kernel transfer buffer sized by the importer's own kernel.
* **R6** Iso: `iso_pkt_count <= min(1024, max_iso_packets)`; `offset[i] + length[i] <= buffer_len`; offsets non-decreasing; `sum(length) <= buffer_len`. (CVE-2017-16911/16912 class.)
* **R7** UTF-8 fields are `u16`-prefixed, `<= 256` bytes, validated UTF-8, never NUL-terminated on the wire.
* **R8** `attach_id` must name a live attach on this session (else `ATTACH_UNKNOWN`). A new `request_id` on a channel must be strictly greater than the last seen and not currently outstanding. Reuse of a live `request_id` is fatal — it is how URB aliasing and response confusion happen.
* **R9** Every count has a ceiling checked *before* the loop: configs 8, strings 128, langids 16, devices per `DEVICE_LIST` 64, channels 256, manifest 256 KiB, config `wTotalLength` 65535, attach_slot 1..15.
* **R10** Descriptor blobs are opaque bytes to `protocol/`. Parsing happens only in `core/DeviceManifest` and the platform backend, each re-validating every `bLength`/`wTotalLength` walk independently.
* **R11** Credit overrun: respond `COMPLETE{NO_RESOURCES}` on first offence; fatal if exceeded by >2× or three times in a session.
* **R12** `device_epoch` mismatch → **drop silently** (expected after a reset), rate-limited `@@AIRUSB_ERROR@@` at debug level only.

Every rule is one named function, one unit test, and one seed in the fuzz corpus.

### 3.13 Version negotiation — two independent axes

* `wire_major` in the plaintext preamble governs record framing and the security suite. Mismatch is unrecoverable and closes immediately.
* `proto_version` in `HELLO` governs message semantics. `chosen = min(a.proto_max, b.proto_max)`; if `chosen < max(a.proto_min, b.proto_min)` → `ERROR{UNSUPPORTED_VERSION}` and close. v1 = 1.
* Capabilities are ANDed; every numeric parameter is the min of both sides. `HELLO_OK` is authoritative and the initiator MUST adopt it.
* **Both preambles are fed into the Noise prologue**, so a downgrade attempt on the plaintext preamble breaks the handshake MAC.

**HELLO (0x01) / HELLO_OK (0x02), B = 48**
`u16 proto_min; u16 proto_max; u64 caps; u32 max_transfer_bytes; u32 max_record_bytes; u32 max_segment_bytes; u32 max_iso_packets; u16 max_channels; u16 max_links; u32 keepalive_ms; u8 platform_id; u8 role_bits (bit0 can_export, bit1 can_import); u16 reserved; u8 session_id[16]` + TLVs (`IMPL_STRING`, `PEER_NAME`).

Capability bits: `0 COALESCE, 1 SEGMENTATION(must be 1), 2 MULTILINK, 3 ISO, 4 USB3_STREAMS, 5 MANIFEST_AUTHORITATIVE, 6 EXPORT, 7 IMPORT, 8 HOTPLUG_EVENTS, 9 CANCEL, 10 RESET, 11 SUSPEND_RESUME, 12 NATIVE_STATUS_TLV`, 13–63 reserved MBZ.

**TLV format:** `u16 tlv_type; u16 tlv_len; u8 value[]`, unpadded, accessed by memcpy.
Types: `0x0001 IMPL_STRING, 0x0002 NATIVE_STATUS, 0x0003 DEVICE_NAME, 0x0004 DEVICE_IDS, 0x0005 SERIAL, 0x0006 PEER_NAME, 0x0007 MANIFEST_HASH, 0x0008 REJECT_REASON, 0x0009 GRANTS, 0x000A DEVICE_DESC, 0x000B CONFIG_DESC, 0x000C BOS_DESC, 0x000D STRING_DESC, 0x000E LANGID_TABLE, 0x000F DEVICE_QUALIFIER_DESC, 0x0010 OTHER_SPEED_CONFIG_DESC`. `platform_id`: 1 macOS, 2 Windows, 3 Linux.

`PING (0x03)` / `PONG (0x04)`, B = 24: `u64 ping_ts_ns; u64 echo_ts_ns; u32 credit_urbs_view; u32 credit_bytes_view` (the credit view fields are populated in debug builds only, for the drift cross-check).

`ERROR (0x06)`, B = 8: `u16 offending_type; u16 reserved; u32 detail` + `TLV REJECT_REASON`. Fatal errors are followed by `GOODBYE` and close.

### 3.14 Pairing and authentication

**Identity** (`/Library/Application Support/AirUSB/identity` for the daemon, 0600; user keychain for the agent): an Ed25519 identity keypair `I` (reusable as a TLS 1.3 raw-public-key cert key), a separate X25519 static keypair `S` for Noise, and a binding signature `sigS = Ed25519_Sign(I_sk, "AirUSB-identity-binding-v1" || I_pk || S_pk)`. Two keys, not one, so no key is used for both signing and DH.
Fingerprint = first 20 bytes of `SHA-256("AirUSB-fp-v1" || I_pk)`, displayed as 4 base32 groups of 8.

**Session establishment** — `Noise_XX_25519_ChaChaPoly_BLAKE2s` on first contact, `Noise_IK` once the static key is pinned. Prologue = initiator preamble ‖ responder preamble. `XX` payloads carry `I_pk || sigS`; each side verifies that `sigS` binds the received Noise static key to the claimed identity key, using libsodium's strict (non-malleable) verification. Any failure — including a parse error — rejects the session.

**Trust gate.** If the peer's `I_pk` is not pinned, the session is `UNPAIRED` and the *only* permitted messages are `PAIR_REQUEST`/`PAIR_CONFIRM`/`PAIR_RESULT`/`PING`/`GOODBYE`. `LIST_DEVICES` and `ATTACH` return `NOT_PAIRED`. **There is no "the LAN is trusted" mode.**

**SAS.** `SAS = decimal6( HKDF(channel_binding, "AirUSB-SAS-v1", 8) mod 10^6 )`, where `channel_binding` is the Noise handshake hash `h` (which commits to both static keys and both preambles). Both peers display the same six digits; each user confirms. Security model is Bluetooth Numeric Comparison: 1e-6 per attempt. **This only holds if attempts are not retryable**, so: exponential backoff per peer address, a hard cap of 3 pairing attempts per minute per listener, a burned pairing session on failure, and an `@@AIRUSB_ERROR@@` line on every failure.
Headless: `airusbctl pair --show` prints the SAS to stdout and to `@@AIRUSB_DISCOVERY@@`; `airusbctl pair --accept <fp>` confirms.

**Grants** (per peer bitmap): `MAY_LIST | MAY_ATTACH | MAY_ATTACH_WITHOUT_PROMPT`. Default on pairing: `MAY_LIST | MAY_ATTACH`. `airusbctl unpair <fp>` removes the pin and tears down live sessions with `DETACH{POLICY}` then `GOODBYE`.

**QUIC path, no redesign** (`SEC_TLS13_RPK`): TLS 1.3 with RFC 7250 raw public keys, cert key = `I`, peer verification against the *same* pin store, `channel_binding` = RFC 9266 `tls-exporter`. SAS derivation, pin store, grants, and every L1/L2 byte are unchanged; only the handshake code is replaced.

**Discovery:** mDNS `_airusb._tcp`, TXT `v=1; fp=<base32>; n=<name>`. The TXT fingerprint is a display hint only — authentication is always the handshake. Redial is always **by peer_id via mDNS re-resolve, never by cached IP**, which is what makes QUIC connection migration a later transport swap rather than a redesign. Tag `@@AIRUSB_DISCOVERY@@`.

---

## 4. Platform backend interfaces

### 4.1 Importer: `IImporterBackend` + `BackendDelegate`

```cpp
struct BackendCaps {
  UsbSpeed maxSpeed;
  uint8_t  maxDevices;              // macOS 15 (portCount is a 4-bit field)
  bool     forwardsStandardRequests;// macOS true, vhci true, UdeCx FALSE
  bool     needsManifestBeforeCreate;// macOS false, vhci false, UdeCx TRUE
  bool     supportsIsoch, supportsStreams;
  uint32_t maxInFlightPerEndpoint;  // macOS 32, UdeCx 16, vhci 16
  uint32_t maxTransferBytes;        // 1 MiB
};

using Ticket = uint64_t;            // 0 == "resolved synchronously, no callback"

class IImporterBackend {
public:
  virtual Result      start(BackendDelegate&)                                   = 0;
  virtual BackendCaps caps() const                                              = 0;
  virtual Result      stop()                                                    = 0;

  virtual Result plugIn (DeviceHandle, const DeviceManifest&, UsbSpeed)         = 0;
  virtual Result plugOut(DeviceHandle, DetachReason)                            = 0;

  // Verbs are TICKETED: the backend may resolve them later. This is what lets the
  // Windows backend park a WDFREQUEST across a LAN round trip -- which is the correct
  // Windows behaviour even though it is forbidden on the macOS command path.
  virtual Ticket beginApplyConfiguration (DeviceHandle, uint8_t cfg)            = 0;
  virtual Ticket beginApplyAltSetting    (DeviceHandle, uint8_t itf, uint8_t alt)=0;
  virtual Ticket beginApplyHaltCleared   (DeviceHandle, uint8_t epAddr)         = 0;
  virtual Ticket beginApplyResetComplete (DeviceHandle, ResetOutcome)           = 0;
  virtual void   resolveTicket(Ticket, AirUsbStatus)                            = 0;

  virtual void   completeTransfer(const TransferResult&)                        = 0;
  virtual void   setPaused(DeviceHandle, uint8_t epAddr, bool)                  = 0;
};

struct TransferResult {
  DeviceHandle device; RequestId id; uint8_t endpoint;
  bool isIn; AirUsbStatus status; uint32_t actualLen;
  BufferRef buffer;             // core-owned arena slab; NEVER null for IN with actualLen>0
  uint16_t deviceEpoch; uint32_t endpointGeneration;
  bool toggleUnknown, collateral;
};

// The absorbed-control event carries what the platform ACTUALLY observed.
// It never forces a backend to fabricate a SETUP packet it never saw.
struct AbsorbedControlEvent {
  enum Kind { SetConfiguration, SetInterface, ClearEndpointHalt, DeviceReset } kind;
  uint8_t  configurationValue;   // Kind::SetConfiguration
  uint8_t  interfaceNumber, alternateSetting; // Kind::SetInterface
  uint8_t  endpointAddress;      // Kind::ClearEndpointHalt
  Ticket   ticket;               // resolve when the remote result is known
};

class BackendDelegate {           // core::ImporterSession implements this
public:
  virtual void onTransferSubmit(TransferRequest&&)                              = 0;
  virtual void onTransferCancel(DeviceHandle, uint8_t ep, CancelScope, RequestId)= 0;
  virtual void onAbsorbedControl(DeviceHandle, const AbsorbedControlEvent&)     = 0;
  virtual void onPortReset(DeviceHandle)                                        = 0;
  virtual void onSuspend(DeviceHandle)                                          = 0;
  virtual void onResume (DeviceHandle)                                          = 0;
  virtual void onBackendFatal(DeviceHandle, BackendFault)                       = 0;

  // Buffer acquisition/release is O(1), lock-free, from a per-endpoint freelist that
  // was PREALLOCATED at attach time. It must be callable from the CI queue.
  virtual BufferRef acquireBuffer(DeviceHandle, uint8_t ep, uint32_t len) noexcept = 0;
  virtual void      releaseBuffer(BufferRef) noexcept                             = 0;
};
```

**The buffer rule (copy at the boundary, always).** `BufferRef` always points into a core arena. OUT: the backend memcpys OS→arena *before* calling `onTransferSubmit`, after which the OS buffer is untouchable. IN: the core fills the arena from the network and calls `completeTransfer`; the backend memcpys arena→OS buffer while holding its own live state check. This one rule is derived independently from three constraints — macOS's "only an Active endpoint may inspect transfer structures, read or modify IO buffers", Windows MDL lifetime across a parked `WDFREQUEST`, and Linux's no-buffer-at-all socket model. Cost is one memcpy per transfer (~0.1% against a 1 GbE link). The zero-copy alternative — holding a kernel virtual address across a network round trip — makes macOS's Paused/Halted rule unsatisfiable.

### 4.2 Exporter: `IExporterBackend` + `ExporterDelegate`

```cpp
struct ExporterCaps {
  bool canSetConfiguration;      // WinUSB: false
  bool cancelPerRequest;         // usbfs true; macOS/WinUSB false -> ENDPOINT scope only
  uint32_t urbCeilingMs;         // 30000
};

class IExporterBackend {
public:
  virtual Result enumerateLocalDevices(std::vector<LocalDeviceInfo>&)           = 0;
  virtual ExporterCaps caps() const                                             = 0;
  virtual Result claim  (LocalDeviceId, ClaimPolicy, ExporterDelegate&)         = 0;
  virtual Result buildManifest(LocalDeviceId, DeviceManifest&)                  = 0; // once, after claim, before IO
  virtual Result release(LocalDeviceId, ReleaseMode)                            = 0; // Reset (normal) | Surrender (polite close)

  virtual Result submit (const RemoteTransfer&)                                 = 0;
  virtual Result cancel (LocalDeviceId, uint8_t ep, CancelScope, RequestId)     = 0;

  virtual Result setConfiguration(LocalDeviceId, uint8_t cfg)                   = 0; // NEVER a control transfer
  virtual Result setAltSetting   (LocalDeviceId, uint8_t itf, uint8_t alt)      = 0;
  virtual Result clearHalt       (LocalDeviceId, uint8_t epAddr)                = 0;
  virtual Result logicalReset    (LocalDeviceId, DeviceManifest& refreshed)     = 0; // NEVER a physical bus reset
};

class ExporterDelegate {
public:
  virtual void onTransferDone(const RemoteTransferResult&)                      = 0;
  virtual void onDeviceUnplugged(LocalDeviceId)                                 = 0;
  virtual void onClaimLost(LocalDeviceId, ClaimLossReason)                      = 0;
  virtual void onPoliteCloseRequested(LocalDeviceId)                            = 0;
};
```

### 4.3 `core::Ep0Arbiter` — one policy table, three origins

The single highest-leverage piece of core logic: it is unit-testable with zero platform code, and it is the piece all three backends converge on.

| Request | Disposition | Notes |
|---|---|---|
| `GET_DESCRIPTOR(DEVICE, CONFIG, STRING, BOS, DEVICE_QUALIFIER, OTHER_SPEED_CONFIG)` | **LOCAL** from manifest | rule A-3 below |
| `GET_DESCRIPTOR(class/vendor type, e.g. HID Report)` | **FORWARD** | |
| `SET_ADDRESS` | **ABSORB** — never reaches the wire | macOS assigns via `IOUSBHostCIDeviceStateMachine respondToCommand:status:deviceAddress:`; UdeCx and vhci absorb it; the remote device already holds an address on its real bus |
| `SET_CONFIGURATION` | **ARBITRATE** → `SET_CONFIGURATION` verb | |
| `SET_INTERFACE` | **ARBITRATE** → `SET_INTERFACE` verb | |
| `CLEAR_FEATURE(ENDPOINT_HALT)` | **ARBITRATE** → `EP_CLEAR_HALT` verb | maps to `-clearStallWithError:`, which clears the device stall **and** the exporter host controller's data toggle — a raw forward clears only the former |
| `GET_CONFIGURATION` / `GET_INTERFACE` | **LOCAL** from arbiter state | |
| `GET_STATUS` (device, interface, **endpoint**) | **FORWARD** | the endpoint HALT bit is live device truth and is exactly what a driver queries to decide whether recovery is needed. Serving it from cache wedges the drive permanently |
| `SET/CLEAR_FEATURE(REMOTE_WAKEUP, U1_ENABLE, U2_ENABLE, LTM_ENABLE)`, `SET_SEL`, `SET_ISOCH_DELAY` | **ABSORB**, ack Success | link-power and latency parameters are meaningless across a LAN, and forwarding them drops the **exporter's real link** into U1/U2 and destroys throughput |
| `SET_FEATURE(TEST_MODE)`, `SET_DESCRIPTOR` | **STALL** | would invalidate the manifest |
| class / vendor, any recipient | **FORWARD** | includes mass-storage Bulk-Only Reset `0x21/0xFF` and `GET_MAX_LUN` `0xA1/0xFE` |

**Rule A-3 (descriptor truncation — mandatory).** A LOCAL descriptor response is `resp = blob[0 .. min(len(blob), wLength))`. If `len(blob) < wLength`, the transfer completes as **short** (`XFER_SHORT`; on macOS, `Success` with `transferLength < requested`). macOS enumeration issues `GET_DESCRIPTOR(DEVICE, wLength=8)` to learn `bMaxPacketSize0` and `GET_DESCRIPTOR(CONFIG, wLength=9)` to learn `wTotalLength` before asking for the whole thing. Serving the full blob against a 9-byte kernel buffer either overruns kernel memory or trips R5.

**Rule A-4.** A LOCAL response never exceeds `wLength` and is always subject to R5 at the copy site.

### 4.4 Verb origin and result table (the cross-platform contract)

| Verb | macOS origin | Windows origin | Linux origin | Result path to the guest |
|---|---|---|---|---|
| `SET_CONFIGURATION` | intercepted ep0 SETUP | `EvtUsbDeviceEndpointsConfigure` with `UdecxEndpointsConfigureTypeDeviceConfigurationChange` | intercepted ep0 SETUP (vhci forwards it) | macOS/Linux: complete the ep0 transfer with the verb's status. Windows: park the `WDFREQUEST`, complete it on `resolveTicket` |
| `SET_INTERFACE` | intercepted ep0 SETUP | `EvtUsbDeviceEndpointsConfigure` with `...InterfaceSettingChange` | intercepted ep0 SETUP | same |
| `EP_CLEAR_HALT` | intercepted `CLEAR_FEATURE(ENDPOINT_HALT)` on ep0, **and** the `EndpointReset` CI command | **`EvtUsbEndpointReset`**, registered via `UdecxUsbEndpointSetCallbacks` (Windows never surfaces this as a standard request — it arrives as `URB_FUNCTION_SYNC_RESET_PIPE_AND_CLEAR_STALL`) | intercepted ep0 SETUP | park/resolve; stall barrier released on `CTRL_ACK` |
| endpoint abort/purge | `EndpointPause` / `EndpointDestroy` CI commands | **`EvtUsbEndpointPurge`** | `CMD_UNLINK` | `CANCEL{mode=ENDPOINT}` |
| `DEVICE_RESET` (logical) | `PortReset` CI command | `EvtUsbDeviceLinkPowerExit` / device reset callback | vhci port reset | respond locally first, drive the verb async |

**Without the `EvtUsbEndpointReset` row, a Windows importer wedges permanently on the first recoverable stall** — `usbstor` runs standard Bulk-Only error recovery, UdeCx routes it to an unregistered callback, no `EP_CLEAR_HALT` ever reaches the exporter, and every subsequent transfer returns Stall.

### 4.5 macOS importer — `CiHostBackend`

* `caps()`: `maxSpeed = SuperPlusBy2`, `maxDevices = 15` (the `portCount` field is 4 bits — hard ceiling), `forwardsStandardRequests = true`, `needsManifestBeforeCreate = false`, `supportsIsoch = false` in v1, `maxInFlightPerEndpoint = 32`, `maxTransferBytes = 1 MiB`.
* Capabilities NSData = one `ControllerCapabilities` + N `PortCapabilities`. `commandTimeoutThreshold` = 3 (2³ = **8 s**, the maximum of the 2-bit field) because a `CommandTimeout` is unrecoverable; our own watchdog fires 5.3× earlier. `connectionLatency` = 5 (2⁵ = **32 ms**) to cover Wi-Fi p99 jitter without inflating every kernel timing assumption. Both values are golden-vector tested (§8.1).
* `plugIn` allocates a free root port, sets `psm.connected = YES`, calls `-updateLinkState:speed:inhibitLinkStateChange:error:`, enqueues a `PortEvent` interrupt with `expedite:YES`. **No descriptors are pushed anywhere** — the kernel then drives PortStatus → PortReset → DeviceCreate → ep0 `GET_DESCRIPTOR`s, all answered from the manifest with zero network round trips.
* Device address is assigned from a local 1..127 bitmap via `respondToCommand:status:deviceAddress:error:`. **The USB device address never appears on the wire.**
* Beyond 15 devices requires a second `IOUSBHostControllerInterface` instance with its own capabilities blob, port allocator and address bitmap. The port allocator and `DeviceHandle` namespace are per-controller from day one so this is not a retrofit.

### 4.6 Windows importer — `UdecxHostBackend` + `airusb.sys`

The split is forced: the KMDF client driver is kernel-mode and cannot host the protocol or transport. They talk over an inverted-call IOCTL channel plus a shared-memory arena; the service parks N "give me the next URB" IOCTLs which the driver completes with URB metadata and an arena slot index.

* `caps()`: `maxSpeed = Super`, `forwardsStandardRequests = **false**`, `needsManifestBeforeCreate = **true**`, `supportsIsoch = false` (undocumented and reported broken), `supportsStreams = false`, no external hub support.
* `plugIn` ships the **entire manifest down in one IOCTL before the device exists**: `UdecxUsbDeviceInitSetSpeed`, then `UdecxUsbDeviceInitAddDescriptor` for the device descriptor, every configuration at full `wTotalLength`, BOS, device qualifier and other-speed configs, then `UdecxUsbDeviceInitAddStringDescriptor` for every string/LANGID pair, then `UdecxUsbDeviceCreate` + `UdecxUsbDevicePlugIn`. **This is the entire reason `buildManifest()` is mandatory for every exporter on every platform.**
* Callbacks registered: `EvtUsbDeviceLinkPowerEntry/Exit`, `EvtUsbDeviceDefaultEndpointAdd`, `EvtUsbDeviceEndpointAdd`, `EvtUsbDeviceEndpointsConfigure`, and — per §4.4 — `UdecxUsbEndpointSetCallbacks` with `EvtUsbEndpointReset` and `EvtUsbEndpointPurge`.
* `EvtUsbDeviceEndpointsConfigure` receives a `WDFREQUEST`; it is **parked** on a pending queue and completed only on `resolveTicket`. This is the whole reason the verb interface is ticketed.
* URBs arrive as `IOCTL_INTERNAL_USB_SUBMIT_URB` on the per-`UDECXUSBENDPOINT` `WDFQUEUE`. The driver maps the MDL with `UdecxUrbRetrieveBuffer`, copies OUT data into the arena slot **before** parking the request (the MDL is only valid while the request is held), and copies IN data back on completion.
* **Residual asymmetry, accepted:** anything UdeCx completes synchronously from its own descriptor table (`GET_DESCRIPTOR`, `SET_ADDRESS`) is unrecoverable by construction. The manifest makes `GET_DESCRIPTOR` safe; `SET_ADDRESS` is genuinely importer-local. The remaining exposure is a device that rejects a configuration the manifest said it supported.

### 4.7 Linux importer — `VhciShimBackend`

`vhci-hcd` takes a socket fd via sysfs and gives userspace **zero** per-URB visibility. Resolution: AirUSB does **not** hand the kernel the LAN socket.

1. `socketpair(AF_UNIX, SOCK_STREAM, 0, sv)`.
2. Write `"<port> <sv[0]> <devid> <speed>"` to `/sys/devices/platform/vhci_hcd.0/attach`, then `close(sv[0])`.
3. Speak **literal USB/IP on `sv[1]`, in-process**, translating `CMD_SUBMIT`/`RET_SUBMIT`/`CMD_UNLINK` ↔ AirUSB `SUBMIT`/`COMPLETE`/`CANCEL`.

Consequences: AirUSB keeps full per-URB visibility, its own flow control, its own crypto and its own failure handling on Linux; the kernel never speaks AirUSB over the wire; and the fd-handoff asymmetry is confined to `UsbipShimCodec.cpp`. USB/IP encodes transfer type nowhere, so the shim recovers it from the manifest's endpoint table — that client-side-state requirement is contained here and never reaches core.

`AF_UNIX` is chosen over TCP loopback (no port, no firewall interaction, no third party can connect). Fallback if a hardened kernel's `sockfd_lookup` rejects it: `127.0.0.1` on an ephemeral loopback-bound port with a one-shot accept and a connection token, probed at first run and cached per kernel version.

**The shim's USB/IP decoder gets the same fuzzing treatment as `protocol/`.** Reintroducing a casually-written USB/IP parser inside our own process would re-import the exact CVE class the AirUSB format was designed to eliminate.

### 4.8 Exporters

**macOS** (root LaunchDaemon, **no restricted entitlement** — `IOUSBHostObjectInitOptionsDeviceCapture` states root privileges substitute for the entitlement): `IOUSBHostDevice` / `IOUSBHostInterface` / `IOUSBHostPipe`. Details in §7.

**Linux** (usbfs, cleanest manifest of the three — the whole descriptor set is a byte stream from `/dev/bus/usb/BBB/DDD`): `USBDEVFS_DISCONNECT_CLAIM` with `DISCONNECT_CLAIM_EXCEPT_DRIVER` per interface after unmounting; `USBDEVFS_SUBMITURB`/`REAPURBNDELAY`; `USBDEVFS_SETINTERFACE`; `USBDEVFS_CLEAR_HALT`. `cancelPerRequest = true` (`USBDEVFS_DISCARDURB`).

**Windows** (WinUSB, Phase 3+): requires rebinding the target device to WinUSB via a signed per-VID/PID INF from an elevated service. `WinUsb_QueryDeviceInformation` reports only Low/Full/High, so the manifest validator (§3.7) is what prevents a mis-declared SuperSpeed device. **WinUSB cannot change configuration**, so `canSetConfiguration = false`: the Windows exporter refuses ATTACH for multi-configuration devices with `UNSUPPORTED`, and `setConfiguration(cfg)` succeeds iff `cfg == current`.

---

## 5. Concurrency model

### 5.1 The governing rule

Kernel→client commands on macOS are **one outstanding at a time**, and a command unanswered within `commandTimeoutThreshold` raises `IOUSBHostCIExceptionTypeCommandTimeout`, which destroys the controller. Therefore: **no kernel command may ever await a network round trip.** Everything below follows.

### 5.2 Strands

| Strand | Implementation | Owns |
|---|---|---|
| **CiStrand** | `dispatch_queue_create("com.airusb.ci", SERIAL)`, `QOS_CLASS_USER_INTERACTIVE`, passed as the `queue:` argument to `-initWithCapabilities:queue:...` | All four state machine families (`Controller`/`Port`/`Device`/`Endpoint` — the SDK provides **no** concurrency protection); the transfer-descriptor walk including Link chasing; **every** read/write of a kernel transfer buffer; every `enqueueInterrupt(s)` call |
| **SessionStrand** | one serial queue per session | `Ep0Arbiter`, `AttachRegistry`, `RequestTable`, `CreditController`, arena metadata, the protocol FSM. The protocol layer has **no locks at all** |
| **TxStrand / RxStrand** | one each per connection | Rx: read a full record, AEAD-decrypt, split coalesced messages, run R1–R12, copy payload into an owned arena slab, post to SessionStrand. Tx: run `FrameScheduler` |
| **ControlStrand** | one per daemon | attach/detach/lease/discovery/UI IPC/logging drain. **May block freely.** Never touched by CiStrand |
| **ExporterIoPool** | 2 threads | `IOUSBHostPipe` async completions |

Windows: the inverted-call completion thread pool funnelled into one strand (WDF completes on arbitrary threads). Linux: the per-device `shimLoop` thread is the PlatformStrand.

### 5.3 INV-CMD — the never-block rule, as a testable invariant

> **INV-CMD:** the command handler performs **zero heap allocations**, takes **zero locks held by any other strand**, issues **zero I/O syscalls**, and returns within **200 µs at p99.9**.

Structural enforcement:

* `CiStrand → SessionStrand` is **always** a post, never a blocking call. `SessionStrand → CiStrand` (completions) is **always** a post. **No lock is ever held across a post.** The only path from the command handler to the network is a `post()`, so blocking on I/O is not expressible in the code shape.
* **Arena preallocation happens on SessionStrand at attach time**, sized from the manifest's full endpoint set (all endpoints of all configurations and alt settings, capped), *before* `plugIn` is called. `acquireBuffer`/`releaseBuffer` are O(1) lock-free pops/pushes on a per-endpoint freelist and are the only core calls permitted from CiStrand. Reserving or allocating arena inside `EndpointCreate` — a multi-megabyte allocation on the fatal-deadline path — is forbidden.
* Logging from CiStrand writes into a lock-free MPSC ring drained by ControlStrand. Nothing on CiStrand ever touches a file.
* Enforcement: an in-process latency histogram asserted in CI against a synthetic 10,000-command trace, plus a fault-injection run using `SlowPeerTransport` (uniform 30 s delay) against a real flash drive asserting that no `IOUSBHostCIExceptionType` is ever delivered.

### 5.4 Answering every command from local state — and the TD→URB assembly rule

The importer is a **state mirror**, not a proxy. The manifest arrives before the virtual port ever reports a connect.

| Command | Handling |
|---|---|
| Controller PowerOn/PowerOff/Start/Pause | local, immediate |
| Controller FrameNumber | local synthetic clock; the remote frame number is **never** consulted |
| Port PowerOn/PowerOff/Resume/Suspend/Disable/Status | local port model |
| **Port Reset** | **respond Success immediately**, bump `device_epoch`, invalidate all cached transfer pointers, then drive `DEVICE_RESET` (logical) asynchronously. If it fails, `plugOut(ResetFailed)` — a forced detach is a state the guest handles natively; a lie about reset state is not recoverable |
| Device Create | address from the local 1..127 bitmap |
| Device Destroy/Start/Pause/Update | shadow model; kernel-supplied descriptor VAs are parsed **synchronously** (pure memory read, no IO) and **deep-copied**; the pointer never escapes the handler |
| Endpoint Create/Update | build `EndpointModel` from the descriptor VA; bind the preallocated freelist |
| **Endpoint Reset** (valid only in Halted) | **respond Success immediately**, set `stall_barrier`, drive `EP_CLEAR_HALT` async (§5.5) |
| **Endpoint Pause / Destroy** | **quiesce first, respond second** (§5.6) |
| **Endpoint SetNextTransfer** | clear the cached `currentTransferMessage` pointer. **Mandatory** — the header requires the client to force a refresh of the transfer-structure pointer on the next doorbell; ignoring it means walking a stale ring, a classic desync-to-corruption bug |

**Doorbell handler** — O(1) per doorbell, strictly: decode the u32 (`deviceAddress` bits 0–7, `endpointAddress` 8–15, `streamID` 16–31) → index a preallocated flat array → `processDoorbell:` → set a runnable bit → return. The handler receives an array plus a count, so batching is free. This is the entire defence against `IOUSBHostCIExceptionTypeDoorbellOverflow`.

**Transfer-descriptor → URB assembly rule (mandatory, and the fix for the deadlock/short-packet defects):**

```
walk(endpoint):
  while endpointState == Active:
    tm = endpointStateMachine.currentTransferMessage
    if !tm || !(tm->control & Valid): break
    switch type(tm):
      case Link:                 follow to the next array; NOT a transfer boundary; continue
      case SetupTransfer:        begin a control transfer; decode setup from data1; record tm; continue
      case NormalTransfer:
         if in a control transfer: append (data0 length, data1 VA) to the data stage; continue
         else:                    ONE NormalTransfer == ONE logical bulk/interrupt URB. Emit SUBMIT. break
      case StatusTransfer:        end the control transfer. Emit SUBMIT (ep0). break
      case IsochronousTransfer:   v1: complete with Unsupported. (ISO out of scope.)
```

* **A control transfer is `Setup` + zero-or-more `Normal` + exactly one `Status`.** A no-data control transfer — mass-storage Bulk-Only Reset (`bmRequestType=0x21, bRequest=0xFF, wLength=0`) — has **no** `Normal` TD at all. Any loop that only advances on `NormalTransfer` spins forever here on the serial CI queue while `commandTimeoutThreshold` ticks. **Every TD in the chain is completed** via `enqueueTransferCompletionForMessage:` in order, with the data-stage length distributed across the `Normal` TDs and the overall status carried on the `Status` TD.
* **On non-control endpoints, exactly one `NormalTransfer` is one logical URB.** Never split it (a split at a non-`wMaxPacketSize` boundary injects a spurious short packet and desynchronises the Bulk-Only Transport phase machine) and never coalesce adjacent TDs (coalescing a 31-byte CBW with the following data stage destroys the CBW's transfer boundary). `data0` carries a 28-bit length, so no splitting is needed. See **OQ-1**.
* Debug builds assert that a non-control endpoint never presents a second `NormalTransfer` as Active before the first is completed, and log `@@AIRUSB_ERROR@@ assumption=td_chaining` if it does.

### 5.5 Stall barrier and the always-drain rule

* Doorbells are **always** consumed and `processDoorbell:` is **always** called, unconditionally. Un-drained doorbells are exactly what `DoorbellOverflow` fires on, and that exception is fatal. **Only transmission is gated.**
* Per-endpoint `stall_barrier` is set on: `EndpointReset`, any completion carrying `TOGGLE_UNKNOWN`, and any completion with `XFER_STALL`. While set, transfers are accepted from the kernel and queued locally but **not transmitted**. It is cleared by `CTRL_ACK(EP_CLEAR_HALT, OK)`.
* Without this, every stall becomes an unbounded retry loop at LAN RTT: the kernel halts the endpoint, issues `EndpointReset`, we answer Success, the kernel immediately rings the doorbell, the retry reaches a pipe on which `-clearStallWithError:` has not yet run, stalls again — and the mass-storage driver eventually escalates to a device reset.

### 5.6 The A9 defence — writing kernel IO buffers

> *"Only an endpoint in the Active state may inspect transfer structures, read or modify IO buffers, and generate transfer completions."* Paused and Halted both forbid it. Violating this produces **silent kernel memory corruption with no exception raised** — there is no detector, only prevention. It is the worst failure mode in the project and the trigger is routine: a completion for a bulk IN arriving 40 ms after the kernel issued `EndpointPause`.

Five mandatory defences, in place from the first line of `CiHostBackend`, never retrofitted:

1. **Every** kernel-buffer read/write happens only on CiStrand.
2. Immediately before the memcpy, **re-read `endpointStateMachine.endpointState` and require `== Active`**.
3. An **epoch triple** `(controller_epoch, device_epoch, endpoint_generation)` is stamped on every outbound SUBMIT and checked on every inbound COMPLETE. `endpoint_generation` is incremented on `EndpointCreate`, `EndpointDestroy`, `EndpointReset` and `PortReset`.
4. The completion's transfer-message pointer **must equal** `endpointStateMachine.currentTransferMessage`.
5. **Clamp `transferLength`** to the `NormalTransfer`'s declared 28-bit `data0` length, and independently re-assert R5 (`actual_len <= requested_len`) at the copy site — not only in the frame decoder.

**Quiesce-before-respond ordering** for `EndpointPause`/`EndpointDestroy`: insert the endpoint key into `_quiesced` and bump `endpoint_generation` **before** calling `respondToCommand:`, so a completion already in flight from the network drops (releasing its arena slab) instead of writing into a buffer the header forbids touching. The ordering is the whole trick.

Failing any check: drop the completion, release the buffer, rate-limited `@@AIRUSB_ERROR@@`. This is a **normal, expected event**, not a bug.

### 5.7 The deliberate extra copy

Path: socket → arena slab (RxStrand) → kernel transfer buffer (CiStrand). We could copy straight from the socket into the kernel VA and save one memcpy. **We will not.** Only CiStrand knows whether the endpoint is still Active. Copying from RxStrand is failure mode A9. Cost: memcpy at ~10 GB/s against a 1 Gbps link is ~0.1%. This justification is duplicated as a comment **at the copy site**, because without it a future reviewer profiling throughput will "optimize" it into a kernel-corruption bug.

### 5.8 Interrupt moderation

`interruptRateHz = 1000`. TransferComplete interrupts are batched with `-enqueueInterrupts:count:`, never one call per completion. `expedite:YES` is used **only** for PortEvent (connect/disconnect), where latency is user-visible and volume is negligible. This is the defence against `IOUSBHostCIExceptionTypeInterruptOverflow`; every occurrence is treated as a design defect requiring a written explanation, never as a value to quietly tune.

---

## 6. Timeout / watchdog budget hierarchy

### 6.1 The table (`core/Watchdog.cpp` — one file, asserted at startup)

| Symbol | Value | Meaning |
|---|---|---|
| `T_cmd_kernel_fatal` | **8000 ms** | capabilities `commandTimeoutThreshold` = 3 (2³ s), the maximum of the 2-bit field. **NEVER approach.** A `CommandTimeout` is unrecoverable; we take maximum headroom. Cost: a genuinely deadlocked daemon stalls the OS USB stack for 8 s instead of 2 s — a bug to fix, not a parameter to tune, and strictly preferable to a destroyed controller |
| `T_cmd_handler_budget` | **200 µs p99.9** | INV-CMD, asserted in CI |
| `T_cmd_deferred_max` | **1500 ms** | watchdog on any command we were ever forced to defer. In the normal design **no such path exists**; if it fires, we synthesize a local failure response and log a design defect |
| `T_net_ctrl` | **5000 ms** | deadline on a forwarded ep0 control transfer (USB 2.0 §9.2.6 allows 5 s for standard requests) |
| `T_urb_ceiling_bulk` | **30000 ms** | **exporter's** per-URB abort ceiling for bulk and control |
| `T_urb_watchdog_importer` | **45000 ms** | importer-side safety net only. **Ordering rule: the importer must never time out before the exporter.** Two independent timeouts racing to recover a Bulk-Only Transport phase is a corruption path. A cheap flash stick doing internal garbage collection legitimately takes 8–12 s for one `WRITE(10)`; macOS's own SCSI timeout is 30 s+ |
| `T_urb_deadline_intr` | **0** | no deadline. An interrupt IN may legitimately idle forever. Also forced: `IOUSBHostPipe.completionTimeout` **must be 0 for interrupt pipes and streams**, so the exporter cannot delegate interrupt timeouts to IOKit at all; they are aborted only on cancel, endpoint destroy, lease loss or detach |
| `T_keepalive_interval` | **500 ms** | `PING` when otherwise idle |
| `T_keepalive_miss` | **1500 ms** | 3 misses → `DEGRADED` (silent; no user-visible change) |
| `T_detach_importer` | **6000 ms** | silence → force virtual port disconnect (surprise removal) |
| `t_disconnect_max` | **1000 ms** | measured, asserted bound on how long the importer's disconnect takes once triggered |
| `T_lease_exporter` | **20000 ms** | silence → release capture, restore the device to the local OS |
| `T_suspend_hold` | **600000 ms** | explicit `SUSPEND_IO` → hold capture 10 minutes (lid closed) |
| `T_drain_graceful` | **2000 ms** | `DRAINING`: wait for outstanding completions before release |

**Startup assertions (compile-time where possible):**

```
static_assert(T_cmd_deferred_max * 4  <  T_cmd_kernel_fatal);
static_assert(T_urb_ceiling_bulk      <  T_urb_watchdog_importer);
assert     (T_keepalive_miss          <  T_detach_importer);
assert     (T_detach_importer + t_disconnect_max + 1000 < T_lease_exporter);
static_assert(T_net_ctrl              <  T_urb_ceiling_bulk);
```

### 6.2 Clocks

**All lease, detach and keepalive timers use `mach_continuous_time` (advances during system sleep), never `mach_absolute_time` (does not).** A sleep-blind clock is the only way to break `T_detach + t_disconnect < T_lease`, so this is a correctness requirement, not hygiene. Enforced by a lint rule banning `mach_absolute_time` outside `core/Clock`, and by an integration test that sleeps the machine mid-lease. On wake the importer re-reads elapsed continuous time **before** resuming anything; if elapsed > `T_suspend_hold` it force-disconnects without attempting anything else.

### 6.3 Flow control and backpressure

* Credit is **two-dimensional per attach**: `credit_urbs` (default 64) and `credit_bytes` (default 4 MiB), granted in `ATTACH_OK`, adjusted at runtime with `ATTACH_CREDIT`.
* **Single release point:** credit is released exactly when the final segment of the single COMPLETE for that `request_id` arrives, whatever its status. Both sides compute the identical release because COMPLETE echoes `requested_len`. `assert(0 <= credit <= granted)` on every update. Debug builds cross-check both sides' views in `PING`/`PONG`.
* Out of credit, the importer **holds the transfer in its endpoint state machine** — legal on macOS, because holding a transfer blocks no kernel *command*, and only Active endpoints touch buffers anyway.
* **Doorbells are never left un-drained.** Pending work sits in the kernel's own transfer ring, sized by the kernel, rather than in an unbounded userspace buffer of ours. When credits are exhausted the exporter simply stops issuing IN URBs and the device NAKs — exactly what a real host controller causes when the host is busy. Correct by construction; no watermarks, no heuristics.
* Per-link writer high-water 4 MiB: the transport stops accepting new BULK-class messages and returns `NO_RESOURCES`, which the session layer converts into "hold the transfer". We deliberately do not rely on TCP backpressure, because a blocked socket write would otherwise convert into unbounded queueing on CiStrand — the exact path to a fatal command timeout.

### 6.4 `DEVICE_RESET` is always logical

`-[IOUSBHostDevice resetWithError:]` terminates the object **and all of its children** and re-registers the device for driver matching. Calling it during a lease hands the drive back to the local OS mid-lease, `IOUSBMassStorageDriver` re-matches, and both hosts have the block layer active — the exact outcome the single-mount theorem forbids.

**`-resetWithError:` is banned by lint.** `logicalReset()` is: abort all pipes (synchronous) → `clearStall` all pipes (this is what actually resets the data toggles on the real bus) → re-apply `configureWithValue:<cfg> matchInterfaces:NO` → `selectAlternateSetting:0` → **`rebuildPipeTable()`** (§7.5) → refresh the manifest and compare `MANIFEST_HASH` → bump `device_epoch`. The one physical reset we actually want comes for free at exactly the right moment: destroying the `IOUSBHostDevice` resets the device and re-registers drivers for matching. A genuinely wedged device is not reset — the lease ends (`DEVICE_GONE`), which is safer than racing a re-capture against `IOUSBMassStorageDriver`.

If the refreshed manifest hash differs, the core forces `plugOut` + fresh `ATTACH`. UdeCx cannot update descriptors in place, so re-creation is the only universally correct behaviour.

### 6.5 Fatal exception recovery (importer)

`kUSBHostMessageControllerException` at the interest handler. Uniform recovery: destroy the controller, bump `controller_epoch`, surprise-remove all slots, `GOODBYE` to all peers, dump the last 256 CI messages from the lock-free trace ring to a diagnostic file, recreate a fresh controller after 2 s, and **do not auto-reattach devices** (re-attaching into a controller that just faulted is a loop). Exception-specific deltas: `InterruptOverflow` → halve `interruptRateHz` (floor 250 Hz); `Terminated` → clean shutdown, do **not** recreate; `CapabilitiesInvalid` → refuse to start and log the exact 32 bytes we sent.

### 6.6 Cancellation

* `CANCEL` semantics are §3.9. On macOS the exporter uses `IOUSBHostAbortOptionSynchronous` on teardown paths (we must know the pipe is quiet before releasing the interface) and Asynchronous on the hot path.
* Outstanding URBs are capped at **4 per bulk pipe** so that the collateral of an endpoint-scope abort is bounded, while ~64 KiB in flight still saturates 1 Gbps at 5 ms RTT.
* Nothing is ever resubmitted by AirUSB (§3.9).

---

## 7. Exclusivity, capture and restore

### 7.1 The safety theorem

> **Single-mount invariant.** At no instant can both operating systems have the device's block layer active.

Proof obligations, each discharged by a named mechanism:

| Obligation | Mechanism |
|---|---|
| (a) While capture is held, the exporter's OS cannot mount | `IOUSBHostObjectInitOptionsDeviceCapture` terminates all clients/drivers of the device, **and** a `DADiskClaim` is held for the whole lease |
| (b) Capture is released only after `T_lease_exporter` of silence, or an explicit definitive `DETACH`/`GOODBYE` | exporter state machine, §7.3 |
| (c) The importer's virtual port is force-disconnected after `T_detach_importer` of silence | importer watchdog |
| (d) `T_detach_importer + t_disconnect_max < T_lease_exporter` (6 s + 1 s < 20 s) | startup assertion, §6.1 |
| (e) All three timers use continuous time | §6.2 |

**Corollary — the safe failure mode is `exit()`.** If the `IOUSBHostControllerInterface` object is freed, `destroy` is called automatically; process death tears down the user client, which the kernel treats as controller loss and surprise-removes every virtual device. On the exporter, process death releases `IOUSBHostDevice`, which resets the device and re-registers drivers, so the drive comes back locally. Therefore, on any detected internal inconsistency the daemon calls `abort()` rather than continuing with a possibly-corrupt device model. **The set of conditions permitted to call `abort()` is small, enumerated in one file (`core/Fatal.cpp`), and each must be genuinely unrecoverable** — a spurious abort while a user is copying files loses their unflushed data.

**Rejected alternative:** a separate root "guard" process holding capture so exporter crashes don't release the device. On exporter process death the TCP socket closes immediately, the importer sees EOF and force-disconnects within `t_disconnect_max`, whereas the exporter's local re-enumerate + match + mount takes >1 s. The importer's device is gone before the local mount exists. `t_disconnect_max` is a **tested assertion** (SIGKILL the exporter, measure), not an assumption.

### 7.2 Capture order (macOS)

1. **Enumerate** every BSD disk backed by the target `IOUSBHostDevice` via IOKit registry traversal.
2. **`DADiskClaim`** the whole disk and every partition, with a deny-all approval callback, so nothing remounts under us. Held in an RAII scope guard.
3. **`DADiskUnmount`** with `kDADiskUnmountOptionWhole`. **If any unmount is dissented: `DADiskUnclaim`, abort the whole attach, answer `ATTACH_OK{status = MOUNTED_LOCALLY}` + `TLV REJECT_REASON` naming the blocking process when DiskArbitration supplies it.** Never force. Capturing a mounted device evicts `IOUSBMassStorageDriver` out from under a filesystem holding dirty buffers — a yank with extra steps.
4. **Capture the device:** `[[IOUSBHostDevice alloc] initWithIOService:… options:IOUSBHostObjectInitOptionsDeviceCapture …]`.
5. **`configureWithValue:0`**, then **`configureWithValue:<cfg> matchInterfaces:NO`**.
   **Hard rule: `matchInterfaces:` is ALWAYS `NO`, everywhere, enforced by lint.** Passing `YES` invites `IOUSBMassStorageDriver` to match and mount the drive locally while it is leased out — a direct two-mount corruption path.
6. **Open each child `IOUSBHostInterface`** — first with a **plain** `-initWithIOService:` (no capture option). See §7.4.
7. **`rebuildPipeTable()`** (§7.5).
8. **`buildManifest()`** — read every descriptor once, verbatim, and run `manifest_validate()`.
9. Only now send `ATTACH_OK` then `DEVICE_MANIFEST`. **The importer never learns the device exists until it is fully captured and fully described.**

Any failure unwinds **completely** (release objects, `DADiskUnclaim`) so the local OS remounts the drive.

### 7.3 Exporter device state machine

```
IDLE → CLAIMING → UNMOUNTING → CAPTURING → LEASED
LEASED ⇄ SUSPENDED           (only via explicit SUSPEND_IO / RESUME_IO — never via silence)
LEASED → DRAINING → RELEASING → IDLE
LEASED → ORPHANED            (silence past T_detach_importer)
ORPHANED → RELEASING         on (a) definitive DETACH/GOODBYE, (b) T_lease_exporter of
                             continuous-clock silence, (c) explicit user override
```

**`ORPHANED` keeps the device captured.** The local OS still cannot mount. This is the fail-closed state and it is the whole point of the design. The user override must display: *"The other Mac may still think this drive is connected. Reclaiming it could damage files. Only do this if that Mac is switched off or has been restarted."*

**The `DADiskClaim` is held for the ENTIRE lease**, not just across the unmount. A naive claim → unmount → capture → unclaim sequence leaves a window in which any event that re-registers the interfaces for matching lets `IOUSBMassStorageDriver` match and `diskarbitrationd` automount underneath a live lease. Two independent barriers, both held through `LEASED`/`SUSPENDED`/`DRAINING`/`ORPHANED`: **capture at the driver layer, claim at the mount layer.**

### 7.4 FB16524420 tolerance

Since macOS 15.3, a root LaunchDaemon may fail to capture `IOUSBHostInterface` for **mass storage** with `kIOReturnInternalError (0xE00002C9)` unless SIP is off or the process was launched from Terminal/Xcode. Unverified on 26.5. This is the first device class we target, so it hits the PoC directly.

**Mitigation ladder, tried in order at step 6 of §7.2:**

1. **Plain `-initWithIOService:` after `configureWithValue:matchInterfaces:NO`.** The hypothesis: FB16524420 is a failure to *capture an interface away from an already-matched driver*; if no driver ever matches the interface, there is nothing to capture away. **This is a hypothesis derived from the header, not an observation** — P2.5 resolves it.
2. If that fails, retry with `IOUSBHostObjectInitOptionsDeviceCapture` on the interface and record the exact `IOReturn`.
3. If both fail: unwind the **entire** attach (release the device object, `DADiskUnclaim`) so the local OS remounts the drive; set a sticky per-daemon `degraded` flag so the user is not asked to unmount repeatedly.

**Protocol-visible handling:** `ATTACH_OK{status = CAPTURE_FAILED}` + `TLV NATIVE_STATUS{platform_id=1, native_code=0xE00002C9}` + `TLV REJECT_REASON`, so the importer shows a real diagnostic. It never becomes a silent hang.
**User-facing:** *"Could not take control of \<Drive\>. It has been returned to this Mac."* plus a Help link naming the two known workarounds (launch from Terminal; disable SIP on a dev machine). Never a bare error code in the primary text.

P2.5 records results in all three launch contexts (LaunchDaemon, Terminal, Xcode) on macOS 26.5.

### 7.5 Pipe-handle validity — `rebuildPipeTable()`

`IOUSBHostInterface` and `IOUSBHostPipe` objects are invalidated by a configuration change, an alternate-setting change, and by the logical reset's re-configure (which tears down and republishes the child interface IOServices). **After every `setConfiguration`, `setAltSetting`, and `logicalReset`, the exporter MUST:**

1. Abort and release every pipe in the old table.
2. Re-enumerate the child `IOUSBHostInterface` IOServices.
3. Re-open each with `matchInterfaces:NO` semantics preserved.
4. `copyPipeWithAddress:` for every endpoint of the now-active alt setting.
5. Bump `pipe_table_generation`; any submit carrying a stale generation is failed with `XFER_EP_STOPPED`.

Without this, the device enumerates cleanly and then answers nothing — a harder failure to diagnose than one that never enumerates at all.

### 7.6 Release order — plain destroy, not Surrender

1. `cancel(ENDPOINT scope)` on every endpoint, `IOUSBHostAbortOptionSynchronous`.
2. Wait for in-flight completions, bounded by `T_drain_graceful`.
3. Destroy interfaces, then the device with **plain `destroy`**. Plain destroy resets the device and re-registers drivers for matching — that is exactly what makes the local OS remount the stick. `IOUSBHostObjectDestroyOptionsDeviceSurrender` does the **opposite** (no reset, no re-registration) and is used **only** when we received `kUSBHostMessageDeviceIsRequestingClose` and are honouring a polite close request. Using Surrender on the normal path makes the drive vanish from both Macs until the user physically replugs it.
4. `DADiskUnclaim`.

### 7.7 Race resolutions

| Race | Resolution |
|---|---|
| Two importers for one device | Single-holder lease with a monotonic `lease_epoch`; the second gets `BUSY`, **never queued**. Queuing creates an ambiguous handover window |
| Drive already mounted locally | `UNMOUNTING` gate refuses (`MOUNTED_LOCALLY`). We never capture a mounted device |
| `device_uid` collision across peers | `device_uid` = H(exporter peer_id ‖ stable device key). Globally unique by construction |
| Stale frames after handover | `device_epoch` in every header, R12 drops mismatches silently; `lease_epoch` does the same at session level |
| Re-export of an imported device | **Forbidden in v1.** A device that arrived over AirUSB is flagged `virtual` and excluded from `enumerateLocalDevices()`. Prevents forwarding loops |
| Reboot / crash | **No lease state is persisted, deliberately.** After a reboot there is no capture and no claim, so the drive mounts locally — the correct default. On daemon start, devices we previously captured (identified by an IOKit property we set) are released cleanly. Persisting a lease would create a resurrection hazard |

### 7.8 Importer side

* **Graceful detach:** `DADiskUnmount` the imported volume **first** → wait for the callback → tear down the virtual port → send `DETACH`. If the unmount is dissented, **refuse the detach** and name the holding app — exactly what macOS itself does.
* **Forced detach** (link loss, `DEVICE_GONE`, exception recovery): `PortStateMachine.connected = NO`. The OS sees a surprise USB removal; unflushed cache is lost. That is identical to physically yanking the drive, which is the correct and honest semantic when we cannot flush, and journaled filesystems handle it. We do not pretend to do better; we display a persistent hint whenever a writable volume is imported: *"Eject \<Drive\> before disconnecting to avoid losing data."*
* **Data loss is bounded** to the importer's unflushed write cache — the same bound as a physical yank. Filesystem *corruption* additionally requires two writers, which the single-mount theorem excludes.

### 7.9 Sleep

* **Importer sleeps:** macOS issues PortSuspend / ControllerPause / ControllerPowerOff on the normal power path. Answer all locally and immediately, then send `SUSPEND_IO`. The exporter moves to `SUSPENDED` and extends its lease to `T_suspend_hold` **while keeping capture** — which is precisely what makes it safe.
* **Exporter sleeps:** on `kIOMessageCanSystemSleep`, graceful detach *before* sleeping: `DEVICE_GONE{SLEEP}`, wait up to 2 s for the ack, then release. **Do not deny sleep** — denying sleep on someone's laptop is user-hostile. The exporter UI states up front: *"Sharing stops when this Mac sleeps."*

---

## 8. Test plan

### 8.1 Unit / pure-software tests (run in CI on every commit, no hardware, no root, no entitlement)

| Suite | Contents | Gate |
|---|---|---|
| `protocol/wire` | Golden hex vectors, one per message type, checked both directions. `static_assert` on every offset and every `B(type)` | byte-exact |
| `protocol/validate` | One test per rule R1–R12, positive and negative | 100% rule coverage |
| `protocol/fuzz` | libFuzzer over `decode + validate`, seeded with the golden vectors **and the three USB/IP CVE shapes** (oversized length; `actual_length > requested_length`; iso quads overrunning the payload) | 1 h clean under ASan+UBSan; zero reads outside the record |
| `protocol/status` | For each platform: AirUsb→native→AirUsb identity; every native constant has an image; no duplicate entries; Windows constants `static_assert`ed against `usbdi.h` | total coverage both directions |
| `protocol/manifest` | `manifest_validate()` against hand-built manifests: truncated `wTotalLength`, `bLength==0`, SS companion at High Speed, `bMaxPacketSize0=9` at High Speed, missing string index, missing device qualifier | every rejection reason hit |
| `core/ep0arbiter` | **Data-driven: one case per row of §4.3**, asserting disposition, emitted verb, arbiter state, and rule A-3 truncation for `wLength ∈ {8, 9, full, full+1}` | every row, every truncation case |
| `core/watchdog` | Startup assertions; a mutation test that flips each constant and asserts the build/boot fails | all assertions fire |
| `core/credit` | Randomized submit/complete/cancel sequences; assert `0 <= credit <= granted` and no drift over 10⁶ operations | invariant holds |
| `core/clock` | Lint test: `mach_absolute_time` appears nowhere outside `core/Clock` | grep-clean |
| `platform/macos/CiMessage` | **Pure functions, no IOKit, no kernel contact.** Golden vectors for the capabilities blob (`commandTimeoutThreshold=3`, `connectionLatency=5`, `portCount`), doorbell decode, TD decode, completion encode | bit-exact vs. the header's sample block and our chosen values |
| `tests/fakes/ScriptedDevice` | Synthetic mass-storage device: 64 MiB RAM disk, Bulk-Only Transport, SCSI subset (INQUIRY, TEST UNIT READY, READ CAPACITY(10), READ(10), WRITE(10), REQUEST SENSE), with injectable stalls, short transfers, disappearance | deterministic |
| `tests/fakes/InMemoryVhca` | Fake importer replaying a recorded enumeration. **Two variants: `forwardsStandardRequests = true` and `= false`.** The `false` variant drives the `onAbsorbedControl` path, so **the UdeCx asymmetry is exercised in CI, on macOS, years before any Windows code exists** | both variants green |
| `transport/fault` | `FaultTransport` decorator: fixed delay, jitter, drop-after-N, RST, stall, truncation, corruption, slow drain, **`ReorderAcrossChannels`**, `SlowPeerTransport` (uniform 30 s) | every catalogued failure mode has a named script |
| `loopback/conformance` | Two `core` sessions over a socketpair; full sequence preamble → Noise_XX → binding verify → UNPAIRED → pair → HELLO → LIST → ATTACH → MANIFEST → SUBMIT/COMPLETE → DETACH. **10⁶ randomized URBs including cancels, timeouts and mid-flight `DEVICE_GONE`, asserting invariant I1** | I1 never violated; RAM-disk SHA-256 matches after every run |
| `linux/usbip_shim` | Same fuzzing treatment as `protocol/` on the USB/IP decoder | 1 h clean |

**The `ReorderAcrossChannels` mode is mandatory in every loopback run.** It is what proves no invariant depends on the TCP scheduler — before `QuicTransport` exists, when the coupling is cheap to fix.

### 8.2 Integration tests (real USB hardware; not run in CI)

| # | Test | Needs | Gate |
|---|---|---|---|
| I-1 | FB16524420 ladder: capture a real flash drive as LaunchDaemon, from Terminal, and from Xcode, on macOS 26.5, recording exact `IOReturn` for both interface-open strategies | root, USB stick | result recorded; ladder step 1 or 2 succeeds, or the exporter architecture is re-opened |
| I-2 | Capture / unmount / unwind / restore lifecycle, including every error path | root, USB stick | drive remounts locally after every failure path |
| I-3 | Real exporter ↔ `InMemoryVhca`: full SCSI read of 64 MiB verified byte-identical against a local read | root, USB stick | SHA-256 match |
| I-4 | Physical yank mid-transfer; stall injection on the CSW pipe; `GET_MAX_LUN`; Bulk-Only Reset | USB stick | no hang, honest statuses, `diskutil verifyVolume` clean |
| I-5 | Real importer ↔ `ScriptedDevice` over loopback, full `FaultTransport` matrix including `SlowPeerTransport` at 30 s | **entitlement** (or SIP-off dev machine, explicitly labelled) | **zero `IOUSBHostCIExceptionType`**; INV-CMD p99.9 < 200 µs |
| I-6 | **Real ↔ real on one Mac over 127.0.0.1** — a physical stick disappears from the Mac and reappears on the same Mac as a different USB device | entitlement + root + stick | 4 GiB write-read-verify SHA-256 match; `diskutil verifyVolume` clean, after **every** injected fault |
| I-7 | Endpoint pause/destroy stress under sustained bulk load (the A9 race) | entitlement + stick | zero kernel faults over 4 h |
| I-8 | Two Macs: wired, then Wi-Fi, then the roam/sleep matrix (importer sleep, exporter sleep, AP handoff, subnet change, IPv6 privacy rotation, both machines' power loss) | 2 Macs + stick | single-mount invariant never violated |
| I-9 | Multi-hour soak measuring worst-case timer drift and the exporter lease/importer detach ordering under machine sleep | 2 Macs | `T_detach + t_disconnect < T_lease` never violated |

**Acceptance gate from I-2 onward:** `diskutil verifyVolume` clean **and** a 4 GiB write-read-verify with matching SHA-256, after **every** injected fault. A stage is not done until every fault in its matrix passes this gate. **A failure mode that cannot be reproduced by a named `FaultTransport` script is untested and does not count as designed-for.**

---

## 9. Phase 2 — local-loopback PoC, ordered task list

Ordered so that the entire product minus one file is provable before Apple answers the entitlement request. **Steps P2.0–P2.5 need no entitlement at all.**

| # | Task | Deliverable | Est. | Blocks on |
|---|---|---|---|---|
| **P2.0** | `protocol/` in isolation: `Wire.h` with named offsets + `static_assert`s, `Encode`/`Decode` (byte loads only), `Validate` (R1–R12), `ManifestCodec` | golden vectors + libFuzzer target | 3 d | — |
| **P2.1** | Status maps: macOS complete, Linux complete, Windows skeleton with symbolic names and `#error` if built without `usbdi.h` | round-trip + coverage tests | 1 d | P2.0 |
| **P2.2** | `core/`: `Watchdog` + startup assertions, `Clock` (+ lint rule), `Ep0Arbiter` + full table test, `DeviceManifest` + `manifest_validate()`, `RequestTable`, `Arena`, `CreditController`, `Log` | all unit suites green | 4 d | P2.0 |
| **P2.3** | `platform/macos/CiMessage` as **pure functions**: capabilities blob, doorbell decode, TD decode, completion encode | bit-exact golden vectors, **no kernel contact** | 2 d | P2.0 |
| **P2.4** | `security/`: Noise_XX + Noise_IK over a vendored audited core, identity + binding signature, SAS, `PeerStore`, pairing rate limits | negative test vectors for malleable signatures | 3 d | P2.0 |
| **P2.5** | `transport/TcpTransport` + `RecordLayer` + `FrameScheduler` + **`FaultTransport`** (all modes incl. `ReorderAcrossChannels`, `SlowPeerTransport`) | loopback record framing, segmentation verified | 3 d | P2.0 |
| **P2.6** | `tests/fakes/ScriptedDevice` (RAM-disk BOT/SCSI) and `tests/fakes/InMemoryVhca` (**both variants**) | deterministic fakes | 3 d | P2.2 |
| **P2.7** | **Loopback gate:** fake importer reads sector 0 of the fake drive through the real codec, real arbiter, real credit controller, real Noise, real TCP socket. 10⁶ randomized URBs; every log tag present with all fields; rate limiter exercised under a 10 k burst | full `FaultTransport` matrix green; RAM-disk SHA-256 stable | 4 d | P2.5, P2.6 |
| **P2.8** | **`platform/macos/HostDeviceExporter` + `DiskGuard` against a REAL flash drive**, driven by `InMemoryVhca` over loopback. **Runs the FB16524420 ladder first (I-1).** Validates capture/unmount/unwind/restore, `matchInterfaces:NO`, `rebuildPipeTable()`, `logicalReset`, stall handling, physical yank, plain-destroy remount | I-1 … I-4 gates | 6 d | P2.7 |
| **P2.9** | **`platform/macos/CiHostBackend`** — the entitled half. All four state machines on `CiStrand`, TD→URB assembly (§5.4), stall barrier, A9 five-part defence, quiesce-before-respond, `EndpointSetNextTransfer` handling, doorbell O(1) loop, batched interrupts. Debugged first against `ScriptedDevice` over a socketpair (I-5) | zero CI exceptions across the fault matrix; INV-CMD histogram | 8 d | P2.3, P2.7, entitlement |
| **P2.10** | **I-6, the killer test:** real ↔ real over 127.0.0.1 on one Mac | 4 GiB verify + `verifyVolume` clean after every fault | 3 d | P2.8, P2.9 |
| **P2.11** | I-7 (pause/destroy stress) and I-8 (two Macs: wired → Wi-Fi → roam/sleep matrix) | gates green | 5 d | P2.10 |

**Explicitly out of Phase 2** (wire encoding reserved now so each is a capability bit, not a version bump): isochronous, USB3 bulk streams, external hubs, multi-link (`LINK_JOIN`), session `RESUME`, QUIC, Windows, Linux, multi-device attach per session, hotplug `DEVICE_EVENT`, mDNS (hardcoded peer address in P2). Roles are fixed for the PoC per the project's own allowance, but `HELLO` is already symmetric so nothing is redesigned when both peers become dual-role.

---

## 10. Structured logging schema

One helper, `airusb_log(tag, ctx, ...)`, emitting one JSON object per line to a rotating file plus `os_log` on macOS. The hot path writes into a lock-free MPSC ring drained by ControlStrand; drops are counted and reported, never blocking a producer. Rate limiting is a token bucket keyed on `(tag, ep_addr)`. At `DEBUG` every URB is emitted; at `INFO`, per-second aggregates (count, bytes, p50/p99 latency, error histogram).

**Common fields on every record:** `ts` (ISO 8601 + continuous-clock ns), `tag`, `sev`, `pid`, `peer_fp`, `session_id`.

| Tag | Additional fields |
|---|---|
| `@@AIRUSB_DISCOVERY@@` | `peer_name`, `peer_fp`, `addr`, `txt_v`, `action` (announce/resolve/lost), `sas` (pairing only) |
| `@@AIRUSB_ATTACH@@` | `device_id` (= `attach_id` + `device_uid`), `device_uid`, `vid`, `pid`, `serial`, `speed`, `attach_id`, `lease_epoch`, `status`, `manifest_hash`, `capture_path` (ladder step), `native_status` |
| `@@AIRUSB_ENUM@@` | `device_id`, `request_id`, `bmRequestType`, `bRequest`, `wValue`, `wIndex`, `wLength`, `disposition` (LOCAL/FORWARD/ABSORB/ARBITRATE/STALL), `size`, `status`, `latency_us` |
| `@@AIRUSB_REQ@@` | `device_id`, `request_id`, `endpoint`, `transfer_type`, `direction`, `size` (= `buffer_len`), `credit_urbs`, `credit_bytes`, `seg_count` |
| `@@AIRUSB_COMPLETE@@` | `device_id`, `request_id`, `endpoint`, `transfer_type`, `direction`, `size` (= `actual_len`), `requested`, `status`, `latency_us` (`now − submit_ts_ns`), `cflags`, `native_status` |
| `@@AIRUSB_RESET@@` | `device_id`, `scope` (port/device/endpoint), `endpoint`, `device_epoch_old`, `device_epoch_new`, `pipe_table_generation`, `manifest_hash_changed`, `status`, `latency_us` |
| `@@AIRUSB_DETACH@@` | `device_id`, `reason`, `initiator`, `urbs_completed`, `urbs_cancelled`, `bytes_dropped`, `drain_ms`, `release_mode` (reset/surrender), `status` |
| `@@AIRUSB_ERROR@@` | `device_id`, `request_id`, `endpoint`, `class` (A1..A10/B1..B7/C1..C12/D1..D5), `status`, `native_status`, `detail`, `rate_limited_count` |

The L1 header maps 1:1 onto the mandated fields, so `airusb_log_msg(tag, hdr, body)` covers `@@AIRUSB_REQ@@` and `@@AIRUSB_COMPLETE@@` with no manual field assembly.

**User-facing vocabulary** (fixed strings; **never** an error code in the primary sentence; never a blocking modal; never an OK-only dialog for a recoverable state; the diagnostic code lives in a copyable detail disclosure):

```
"Connecting…" / "Shared with <peer>" / "In use by <peer>" / "Reconnecting…"
"<Drive> was disconnected because the connection was lost."
"Eject <Drive> before disconnecting to avoid losing data."   (persistent, writable volumes)
"<Drive> is in use on this Mac. Close the apps using it, or eject it first."
"Could not take control of <Drive>. It has been returned to this Mac."
"Sharing of <Drive> stopped because another app needs it."
"USB sharing stopped unexpectedly. Devices were disconnected."  [Reconnect]
"<Peer> wants to connect. Confirm this code matches on both Macs:  4 8 2 9 1 7"
```

---

## 11. Open questions

| # | Question | Why it matters | How it gets answered |
|---|---|---|---|
| **OQ-1** | Are the chaining semantics of `NormalTransfer` arrays on a **non-control** endpoint really one-TD-per-URB? The `data0` 28-bit length and the singular `currentTransferMessage` strongly suggest yes, but the ground truth does not state it | Splitting one logical transfer injects a spurious short packet and desynchronises Bulk-Only Transport; coalescing destroys the CBW's transfer boundary. Both are silent data corruption | P2.9: runtime assertion + trace-ring capture of every TD chain seen on a real mass-storage read/write; if the assumption is violated, the assembly rule changes before the importer ships |
| **OQ-2** | Does the FB16524420 mitigation (`matchInterfaces:NO` + plain interface open) actually work on 26.5, from a LaunchDaemon? | If both ladder steps fail, the exporter has no supported shape on 15.3+ and we need a different launch context or an Apple escalation | P2.8 / I-1, before the importer exists |
| **OQ-3** | Does `vhci_hcd`'s `store_attach` accept an `AF_UNIX` socket on hardened/older kernels? | Determines whether the loopback shim needs the 127.0.0.1 fallback | Probe at first run, cache per kernel version. Phase 4 |
| **OQ-4** | Does UdeCx's `EvtUsbDeviceEndpointsConfigure` callback ordering carry enough information to reconstruct the intended configuration and alt setting in every case? | If not, the exporter's handle state silently desyncs from what Windows believes | Dedicated spike before committing to the Windows backend. Phase 3 |
| **OQ-5** | Is the entitlement `com.apple.developer.usb.host-controller-interface` grantable to this team? Every confirmed holder found is an Organization account | Blocks only P2.9/P2.10 | Request filed at Phase 1 start; P2.0–P2.8 proceed regardless |
| **OQ-6** | Are the chosen `interruptRateHz = 1000`, 16 KiB segment, depth-4 pipeline, and credit defaults (64 URBs / 4 MiB) in the safe direction? | `InterruptOverflow` and `DoorbellOverflow` are **fatal**, not merely slow | Instrument all four with counters from P2.9. Any overflow exception is a design defect requiring a written explanation, never a value to quietly tune |
| **OQ-7** | No `API_AVAILABLE` annotations exist on any IOUSBHost CI header, so the message ABI could shift silently across macOS releases with no compiler diagnostic | A silent ABI change presents as a fatal exception at init | Pin a tested macOS range, add a runtime capability probe at `start()`, treat any `IOUSBHostCIExceptionType` at init as a hard refusal to attach rather than a retry |

---

## 12. Accepted risks

Each is a real cost we are shipping with, and the reason.

1. **No session resume; a Wi-Fi roam longer than 6 s surprise-removes the device.** The exactly-once dedup that would make resume safe has a lost-completion hole (bounded replay buffer + no importer-local per-URB timer) that hangs an endpoint forever, which is worse than a clean disconnect. Cost: a remount after a roam. Revisit in Phase 4 behind the adversarial-reordering harness.
2. **Single TCP connection in v1, so a lost segment stalls `PING` too** and can push us into `DEGRADED` spuriously. Accepted because `DEGRADED` is silent and the disconnect threshold is 4× further out (6 s). Multi-link is a Phase 4 capability bit, to be measured against K=1 per the no-optimization-without-profiling rule.
3. **Kernel-level TCP head-of-line blocking is not removed, only self-inflicted and cross-class HOL.** Only QUIC removes the former. Stated honestly rather than papered over.
4. **AirUSB never performs Bulk-Only Transport phase recovery on the guest's behalf.** After a forced endpoint-scope abort we report `TOGGLE_UNKNOWN` and set the stall barrier; the guest's class driver owns recovery. Synthesizing a BOT reset from inside a generic USB proxy is a layering violation that would misfire on non-mass-storage devices. Residual risk: a class driver that does not perform standard recovery leaves the endpoint in the same state a real abort would have left it — which is the honest outcome.
5. **Two copies per transfer** (socket → arena → kernel VA). ~0.1% against 1 GbE. Trading it away is failure mode A9. Documented at the copy site, not only here.
6. **15 imported devices per macOS controller instance** (`portCount` is a 4-bit field), and no hub forwarding on Windows (UdeCx has no external hub support). Documented; we do not design a hub-forwarding feature.
7. **Isochronous is out of scope and will never be presented as synchronized.** A 125 µs microframe clock is not synchronizable across a LAN, the macOS frame clock must be locally synthesized within 1% variance or `IOUSBHostCIExceptionTypeFrameUpdateError` is fatal, and UdeCx iso is undocumented and reported broken. When it lands it will be open-loop with an explicit jitter budget and a declared drop policy, over an unreliable QUIC datagram channel — a protocol change, not a backend change.
8. **`CAP_MANIFEST_AUTHORITATIVE` assumes descriptors are stable across reads.** Quirky firmware that returns different bytes on re-read, or changes descriptors without a reset, will diverge and there is no defence. Mitigations: `MANIFEST_HASH`, a debug mode that forwards every `GET_DESCRIPTOR` and diffs against the cache, and a per-device quirk flag disabling the cache. Correctness beats the ~10-round-trip latency win if any device trips this.
9. **Shipping a Noise implementation now that TLS 1.3 replaces under QUIC** is real duplicated surface. Accepted because the alternative — raw TCP with pairing bolted on — violates the no-unauthenticated-attach rule from day one, and because the pin store, SAS derivation and grants are defined against an abstract channel binding, so only the handshake code is discarded, not the trust model. A security review of `protocol/Noise` + `Sas` before any release is non-negotiable.
10. **6-digit SAS gives 1e-6 per online attempt** and only defeats MITM if the user actually compares the digits. Mitigated by rate limits and by making comparison the path of least resistance rather than a dismissible step; not eliminated.
11. **Any link death kills the whole session.** There is no per-link recovery. Simple, and it degrades into the same `DEVICE_GONE` path everything else uses.
12. **The Windows importer must synthesize `SET_CONFIGURATION`/`SET_INTERFACE` from UdeCx endpoint-configure callbacks**, not from ep0 traffic (OQ-4), and anything UdeCx completes synchronously from its own tables is unrecoverable by construction.
13. **`abort()`-on-inconsistency loses the user's unflushed data.** Correct for kernel safety, hostile if the trigger set is broad. The permitted conditions are enumerated in one file and each must be genuinely unrecoverable, not merely unexpected.
14. **Windows driver signing (WHLK) is the schedule risk for Phase 3**, not the code. Same for the WinUSB rebinding INF on the Windows exporter side, which is per-VID/PID and not cleanly reversible without a driver uninstall.