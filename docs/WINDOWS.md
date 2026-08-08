# Testing with Windows

The client is portable C++ with no platform USB API. It builds and runs on
Windows today and talks to a macOS exporter over the LAN — which proves the wire
protocol, the crypto and the session layer on Windows long before there is a
Windows driver.

What it does **not** do yet is present the device to Windows' USB stack. That is
the UdeCx driver, and it is the next piece.

---

## Build it

Needs **Visual Studio 2022** (the "Desktop development with C++" workload) and
**CMake**. Both ship with the VS installer.

In a *Developer PowerShell for VS 2022*:

```powershell
git clone https://github.com/otti83/airusb-hub
cd airusb-hub\airusb
cmake -S . -B build
cmake --build build --config Release --target airusb-net
```

The binary lands at `build\Release\airusb-net.exe`.

MinGW-w64 works too if you prefer it — `cmake -S . -B build -G "MinGW Makefiles"`.

---

## Run it against the Mac

**On the Mac**, serve a simulated drive:

```bash
cd "AirUSB Hub/airusb"
./build/airusb-net serve --port 7714
```

Note the Mac's LAN address (`ipconfig getifaddr en0`).

**On Windows**, connect:

```powershell
.\build\Release\airusb-net.exe connect --host <MAC-IP> --port 7714 --probe
```

The first run pairs and disconnects — that is the trust-on-first-use path. Both
sides print a six-digit SAS; **they must match**. Run it a second time to attach
and read.

A successful run ends with:

```
verdict=PASS  cbw=6 data=5 csw=6 stallRecoveries=0 boundariesIntact=yes
RESULT=PASS — a USB Mass Storage exchange completed over an encrypted,
              authenticated network session
```

That is a complete USB Mass Storage exchange — CBW, data, CSW — carried between
two operating systems over ChaCha20-Poly1305 with mutually authenticated
identities.

If the Mac's firewall prompts, allow incoming connections for `airusb-net`.

---

## What this proves, and what it does not

| | |
|---|---|
| wire protocol on Windows | proven by this |
| Noise handshake, pinning, SAS on Windows | proven by this |
| a Windows app can drive a remote USB device | proven by this |
| Windows *enumerating* it as a real USB device | **not yet** — needs the driver |

The same binary has already been run macOS→macOS and macOS→Linux, so a Windows
result that differs is a Windows problem and not an ambiguity in the protocol.

---

## The part that still needs writing

`UdecxHostBackend` plus `airusb.sys`, a KMDF client driver using the USB Device
Emulation Class Extension. Design in
[`P1_IMPLEMENTATION_PLAN.md`](P1_IMPLEMENTATION_PLAN.md) §4.6. The split is
forced: the client driver is kernel-mode and cannot host the protocol or the
transport, so they talk over an inverted-call IOCTL channel plus a shared-memory
arena.

**Windows' gate is different from Apple's, and better.** Development needs only
test signing, which is self-service:

```powershell
bcdedit /set testsigning on     # then reboot
```

Distribution needs an EV certificate and Microsoft attestation signing — a paid
process, but a process, not a discretionary approval. Nothing about the Windows
path waits on anyone's decision.

Compare the macOS importer, which cannot run **at all** without an entitlement
Apple grants by hand: see [`ENTITLEMENT_REQUEST.md`](ENTITLEMENT_REQUEST.md).
