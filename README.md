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

**Early development.** Phase 0 (technical feasibility) is complete.

macOS turns out to ship a public API for exactly this — `IOUSBHostControllerInterface`
in `IOUSBHost.framework` — and Apple's own kernel driver does the hard part. No kernel
extension, no System Integrity Protection changes, no private APIs.

See [`docs/P0_MACOS_FEASIBILITY.md`](docs/P0_MACOS_FEASIBILITY.md) for the full
investigation, the evidence behind it, and the one open item: the importing side needs
an entitlement that Apple grants on request.

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
| [`docs/P0_MACOS_FEASIBILITY.md`](docs/P0_MACOS_FEASIBILITY.md) | Can this be built on macOS through supported APIs? Evidence and verdict. |

More documents (architecture, protocol, platform backends, test matrix, known
limitations) arrive as the phases they describe are completed.

---

## License

To be determined before the first release.
