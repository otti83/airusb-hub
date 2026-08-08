# AirUSB Hub

**Your USB devices, anywhere on your LAN.**

Plug a USB drive into one computer. Use it on another — as if you had plugged it in
there yourself. The other machine's operating system loads its own normal drivers and
mounts it as a normal volume, because as far as it can tell, the device really is
attached to it.

This is not file sharing. There is no SMB, no NFS, no sync folder. The USB device
itself is forwarded.

- No cloud
- No account
- No central server
- Peer to peer, on your local network
- Native USB passthrough
- Open source

---

## Status

**Early development.** Feasibility is settled and the sharing half is written.

macOS turns out to ship a public API for exactly this — `IOUSBHostControllerInterface`
in `IOUSBHost.framework` — and Apple's own kernel driver does the hard part. No kernel
extension, no System Integrity Protection changes, no private APIs.

| | |
|---|---|
| Feasibility on macOS | done — [`docs/P0_MACOS_FEASIBILITY.md`](docs/P0_MACOS_FEASIBILITY.md) |
| Protocol, transport, core | done, tested and fuzzed |
| The sharing side (exporter) | working on real hardware — [`docs/P2_8_EXPORTER.md`](docs/P2_8_EXPORTER.md) |
| The receiving side (importer) | not started; needs an entitlement Apple grants on request |
| Encryption | done — Noise_XX / Noise_IK, [`docs/P2_4_SECURITY.md`](docs/P2_4_SECURITY.md) |
| Pairing and trust | key exchange and the confirmation code are done; the pin store is not |

Nothing is usable yet. Follow along rather than depending on it.

---

## Where it is going

| | |
|---|---|
| **Now** | macOS ↔ macOS, USB flash drives, wired and Wi-Fi LAN |
| **Next** | Zero-configuration discovery, device pairing, more device classes |
| **Later** | Windows and Linux, cross-platform in every direction |

The first device class being proven is USB mass storage, because it is unforgiving:
it needs correct bulk transfers, correct error handling, and correct disconnect
behaviour, or you lose data. Once that is solid, HID, serial adapters, and phones
follow.

---

## How it works

```
 Computer A                            Computer B
 ──────────                            ──────────
 USB flash drive
      │
      │  captured from the OS
      ▼
 AirUSB exporter
      │
      │         AirUSB protocol over your LAN
      ├────────────────────────────────────────────►  AirUSB importer
                                                            │
                                                            │ virtual USB host controller
                                                            ▼
                                                      Operating system
                                                            │
                                                            │ loads its own driver
                                                            ▼
                                                      A normal mounted volume
```

Every peer can export and import at the same time. There is no dedicated server.

---

## Safety

A USB drive can only be mounted in one place at a time, or its filesystem is
destroyed. AirUSB Hub unmounts the drive on the sharing computer before handing it
over, and gives it back cleanly when you are done. If it cannot do that safely, it
refuses rather than risking your data.

While developing and testing, use a USB drive you do not care about.

---

## Documentation

| Document | Contents |
|---|---|
| [`docs/HANDOFF.md`](docs/HANDOFF.md) | **Start here.** Current state, verified facts, refuted hypotheses, open questions, next task. |
| [`docs/P0_MACOS_FEASIBILITY.md`](docs/P0_MACOS_FEASIBILITY.md) | Can this be built on macOS through supported APIs? Evidence and verdict. |
| [`docs/P1_IMPLEMENTATION_PLAN.md`](docs/P1_IMPLEMENTATION_PLAN.md) | Architecture, wire protocol, concurrency model, timeout budget, test plan. |
| [`docs/P1_CAPTURE_VERIFICATION.md`](docs/P1_CAPTURE_VERIFICATION.md) | What was measured on real hardware, and why the exporter is two processes. |
| [`docs/P2_8_EXPORTER.md`](docs/P2_8_EXPORTER.md) | The macOS exporter: how it works, and the hardware evidence that it does. |
| [`docs/P2_4_SECURITY.md`](docs/P2_4_SECURITY.md) | Encryption and authentication: what protects a session, and how it was verified. |
| [`docs/ENTITLEMENT_REQUEST.md`](docs/ENTITLEMENT_REQUEST.md) | How to request the one Apple-managed entitlement the importer needs. |

---

## License

To be determined before the first release.

AirUSB Hub vendors two pieces of third-party cryptography, unmodified, under
permissive licences. Both are recorded with their upstream version and checksums
in [`airusb/third_party/PROVENANCE.md`](airusb/third_party/PROVENANCE.md).

| | | |
|---|---|---|
| [Monocypher](https://github.com/LoupVaillant/Monocypher) | 4.0.3 | BSD-2-Clause **or** CC0-1.0 |
| [BLAKE2 reference implementation](https://github.com/BLAKE2/BLAKE2) | `ed1974ea` | CC0-1.0 |

They are vendored rather than linked because the sharing daemon runs as root, and
a library loaded from a user-writable path would be a way to run code as root.
