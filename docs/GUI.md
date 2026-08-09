> **UPDATE, 2026-08-09 — read this before the rest of the file.** The window is
> no longer the authority. `airusb-brokerd` owns the machine's identity, its
> pinned peers, its leases and its USB presentation; `airusb-hubd` is a client
> that holds no key and cannot pin a peer the broker did not itself ask about.
> Everything below about the CEREMONY is still exactly right — the SAS, the
> drop-after-approval, the reconnect — and everything below that implies the
> window IS the product's session should be read as describing the broker it now
> drives. Where the window runs with no broker it says **DIAGNOSTIC ONLY** and
> cannot add a device to the computer. See `HANDOFF.md` §3.16 and §3.17.

# The window

`airusb-hubd` is the product's interface. It runs on macOS, Linux and Windows,
from the same source, with no toolkit and nothing to install.

```bash
airusb-hubd
```

It prints an address and opens it:

```
  AirUSB Hub is running. Open this address:

    http://127.0.0.1:53412/#t=a3f9240fcc5c7a8c…
```

That page is the whole interface: pick a device to share, connect to a machine
that is sharing one, compare six digits with the person at the other end, and
watch the device attach.

---

## Why it is a web page

The alternative was three native front ends — SwiftUI, WinUI, GTK — which is
three implementations of the same window, and two of them on machines this
project cannot run. The browser is the one toolkit already installed on every
machine in the matrix, and it is the only choice that can be **tested** on every
machine in the matrix: the same `curl` drives it in CI as drives it by hand.

Nothing was added to the dependency list. The page is one HTML document compiled
into the binary; the JSON writer and parser are about 300 lines in `control/`,
and the parser accepts exactly one shape — a flat object — and refuses the rest.

The macOS app in `apple/` is a separate question and is not superseded by this.
When it becomes the product's front door it can host this same page in a
`WKWebView`, so there is one interface rather than two that drift.

---

## What it can and cannot do

| | |
|---|---|
| Share a simulated device from this machine | yes, on all three |
| Connect to a machine that is sharing one | yes, on all three |
| Pair, with the six-digit check | yes, on all three |
| Attach a device and read from it over the session | yes, on all three |
| Present the device to **this** machine's USB stack | **no — that is not this process** |

The last row is the important one. Making an operating system enumerate a remote
device is `airusb-vhci` on Linux, `airusb.sys` on Windows (unwritten) and a
CoreMedia host-controller backend on macOS (blocked on an Apple entitlement).
Those are privileged; this is not. `airusb-hubd` never asks for root, and that is
why it is the half that can be handed to a person.

Sharing **real hardware** is likewise a privileged capture, and on macOS it lives
in `airusb-exportd`. The hub offers a simulated drive so the whole path can be
exercised on a machine with nothing plugged in; it says so in the device's name.

That is a split, not a limitation: `airusb-exportd --serve` speaks the same
protocol, so the window imports a **real** captured drive with no extra code.
Done on 2026-08-09 — the hub read a physical 058f:6387's own firmware strings,
its 31.46 GB capacity and its MBR. Start `airusb-agent` FIRST (it waits 60 s for
the daemon's socket; the daemon only waits 30 s for it, then correctly hands the
drive back).

---

## The six digits, and why the connection drops in the middle

Both machines show a six-digit number. They must match. If they do not, something
is between you and the machine you meant, and the number is the only thing that
would tell you.

The number comes from the handshake, so **it is different every time you
connect** — which is what makes it worth comparing, and which means both people
have to be looking at the *same* connection's number.

There is a consequence that looks like a bug the first time you see it:

> The connection drops in the middle of the first pairing, exactly once.

That is correct behaviour. The machine that is sharing decides what a peer is
allowed to do when the connection is made, so the moment it accepts a new peer it
has to end that connection — carrying on would mean its own record of what it
authorised is wrong. The other side reconnects by itself and shows a new number.
Nothing needs pressing twice.

Because of that, both windows show the current connection's number **at all
times**, not only when a decision is pending. Otherwise the side that has already
accepted has nothing on screen for the other person to compare against.

It works in either order:

* **You accept first.** Your side pins and stays connected — the other person is
  still reading the same number. When they accept, they drop you, and you
  reconnect already paired.
* **They accept first.** You lose the connection while still deciding. You
  reconnect, both windows show a *new* number, and you compare that one instead.

---

## Security

Three separate locks, each for a different attacker.

**It binds 127.0.0.1.** Not a firewall rule — a bind address. No other host can
reach it at all. (The device-sharing port is a different socket and is
deliberately reachable from the LAN; that is its job.)

**It requires a token.** Loopback is not an authorisation boundary: on a shared
machine every local account can open a socket to 127.0.0.1. The token is 256 bits
from the same CSPRNG the identity seed comes from, written to
`airusb-hub.token` with owner-only permissions, and regenerated on every start.

It travels in the URL **fragment** — after the `#` — because a browser never
sends a fragment to a server. It stays out of the access log, out of `Referer`,
and out of anything else that records URLs.

**It checks `Host` and `Origin`.** Without the `Host` check, any web page you
visit can point a hostname it controls at 127.0.0.1 and talk to the daemon using
your browser as the proxy. Loopback does not stop that, because the request
genuinely comes from your machine. The token defeats it too; this is the second
lock.

On Windows the token file inherits the directory's ACL rather than being 0600 —
the same exposure the identity seed already has, recorded here rather than
papered over.

---

## Driving it without a browser

Every button is one endpoint. This is how CI runs it, and it is the fastest way
to reproduce anything.

```bash
T=$(cat airusb-hub.token)
api() { curl -sS -H "X-AirUSB-Token: $T" -H 'Content-Type: application/json' "$@"; }

api http://127.0.0.1:8802/api/state
api -X POST -d '{"port":7714}'                       …/api/share/start
api -X POST -d '{"accept":true}'                     …/api/share/approve
api -X POST -d '{"host":"192.168.0.109","port":7714}' …/api/import/connect
api -X POST -d '{"accept":true}'                     …/api/import/approve
api -X POST -d '{"uid":"a0a1…"}'                     …/api/import/attach
api -X POST -d '{}'                                  …/api/import/verify
```

`verify` runs `diag/BotProbe`, which is read-only: its header promises without
qualification that pointing it at a drive cannot damage the contents. That is why
it, and not `WriteProbe`, is behind a button.

Every endpoint returns the full state, so a caller never has to poll after
acting.

---

## Two machines, macOS and Windows

The Windows box on this network (`GMKtec`, `192.168.0.109`) has RDP and SMB open
and **SSH closed**, and it is on a different LAN from the Mac. Measured
2026-08-09: the Mac reaches it in ~28 ms through the Tailscale subnet router
(`utun8`), and **it has no route back to the Mac**. So Windows shares and the Mac
imports — the same direction the two-machine run in `HANDOFF.md` §3.5 had to use,
for the same reason.

### Step 0 — get `airusb-hubd.exe` onto the Windows machine

**Read this step. It is the one that used to be missing**, and without it the rest
is a procedure for running a file that does not exist. It is one file either way;
the two builds differ in what they expect the machine to already have, and the
difference is measured rather than assumed — these are the DLLs each one imports:

| | size | needs |
|---|---|---|
| **MinGW** (`scripts/cross-build-windows.sh`) | 13 MB | `bcrypt` · `kernel32` · `ws2_32` · UCRT — all part of Windows 10 and later. **Nothing to install.** |
| **MSVC** (the CI artifact) | 347 KB | the above **plus `MSVCP140.dll`, `VCRUNTIME140.dll`, `VCRUNTIME140_1.dll`** — the Visual C++ 2015–2022 x64 redistributable |

The GMKtec already has that redistributable: it ran an MSVC-built `airusb-net.exe`
during the two-machine run in `HANDOFF.md` §3.5. On a machine where that is not
known, take the MinGW one.

**Route A — copy it from the Mac over SMB.** Fastest, because the Mac can already
build it. Measured 2026-08-09: `192.168.0.109` answers on 445 (SMB) and 3389
(RDP), so the file has somewhere to go; the share and the credentials are yours.

On the Mac:

```bash
cd "/Users/mba/Desktop/AirUSB Hub/airusb"
./scripts/cross-build-windows.sh          # -> build-win/airusb-hubd.exe, ~13 MB
open build-win                            # then drag it to the mounted share
```

Mount the share first with **Finder → Go → Connect to Server →
`smb://192.168.0.109`**, or from an RDP session copy it out of a folder you share
back. This binary is the MinGW one from the table above: same sources, same
protocol, nothing to install on the far side, and CI cross-builds it on every
commit.

**Route B — download the MSVC build from CI.** This is the binary the Windows job
actually tested, which is the stronger provenance — at the cost of the runtime
dependency in the table above. In a browser **on the Windows machine**, signed in
to GitHub:

<https://github.com/otti83/airusb-hub/actions/workflows/ci.yml> → the newest
green run → **Artifacts** → `airusb-windows-msvc-x64` → unzip. It contains
`airusb-hubd.exe` and `airusb-net.exe`.

(Artifacts need a signed-in GitHub session, which is why this is Route B rather
than a one-line `Invoke-WebRequest`. If it would be more convenient as a public
release asset — a plain URL, no login — say so and it can be attached to a
release; that is a deliberate publishing step and is not done unasked.)

**Route C — build it on the Windows machine.** Needs Visual Studio 2022 with the
"Desktop development with C++" workload. In a *Developer PowerShell for VS 2022*:

```powershell
git clone https://github.com/otti83/airusb-hub
cd airusb-hub\airusb
cmake -S . -B build
cmake --build build --config Release --target airusb-hubd
# -> build\Release\airusb-hubd.exe
```

### Step 1 — run it, sharing

```powershell
cd C:\where-you-put-it

# Let the sharing port through the firewall. Once, and only for this port.
# Needs an elevated PowerShell; the daemon itself does NOT.
New-NetFirewallRule -DisplayName "AirUSB Hub 7714" -Direction Inbound `
  -Protocol TCP -LocalPort 7714 -Action Allow

.\airusb-hubd.exe --share --share-port 7714 --name "GMKtec"
```

Windows Defender may also prompt the first time it listens — allow it on private
networks. The daemon opens the window and prints the address; leave it running.
It writes three files into the current directory (`airusb-hub.id`,
`.peers`, `.token`), so run it from a folder you can find again.

### Step 2 — on the Mac

```bash
cd "/Users/mba/Desktop/AirUSB Hub/airusb"
cmake --build build --target airusb-hubd     # if it is not built yet
./build/airusb-hubd --name "MacBook Air"
```

In the Mac's window, type `192.168.0.109` and port `7714`, and press **Connect**.

Both windows now show a six-digit number. **Compare them.** If they match, press
the accept button on both — in either order. The connection will drop once and
come back by itself; if the number changes, compare the new one.

Then press **Use it** on the device the Windows machine is offering, and **Check
it really works**. A pass reads:

```
PASS — AirUSB Scripted Device, 61440 blocks of 512 bytes read over the
encrypted session
```

That is a complete USB Mass Storage exchange — CBW, data, CSW — carried between
two operating systems over ChaCha20-Poly1305 with mutually authenticated
identities.

### If it does not connect

* **The Mac cannot reach the port.** `ping 192.168.0.109` first; if that works
  and the connection does not, it is the Windows firewall rule above.
* **Do not test the port with `nc -z` or `Test-NetConnection`.** A bare TCP
  connect is *accepted* and enters the handshake, so probing occupies the hub's
  single peer slot for twenty seconds and perturbs the thing you are measuring.
  Just press Connect again. (This is recorded in `HANDOFF.md` §3.5 for the
  command-line tool; it applies here too, and was reproduced on 2026-08-09 —
  the slot was reclaimed by the handshake deadline, as designed.)
* **Starting again from unpaired**: delete `airusb-hub.peers` on both machines.

---

## What is verified, and where

| claim | evidence |
|---|---|
| the guard refuses no-token, rebinding and cross-origin | `test_control`, and both CI jobs provoke all three against a live daemon |
| the pairing ceremony works in either order | `test_hub_e2e`, over real TCP, on macOS, Linux and Windows/MSVC in CI |
| the window never asks the six-digit question with no number under it | `test_hub_e2e` samples the state across the tear-down |
| two daemons pair and read a device, Linux | CI, under AddressSanitizer |
| two daemons pair and read a device, Windows | CI, MSVC 19.51, PowerShell |
| macOS ↔ Linux over a real network, both directions | run by hand 2026-08-09, `HANDOFF.md` §3.9 |
| the hub speaks the same protocol as `airusb-net` | both directions, 2026-08-09, including a segmented 128 KiB write |
| **macOS ↔ Windows, two machines** | **PASS 2026-08-09** — SAS compared by a person on both screens, attach, `BotProbe PASS 61440 × 512`, rtt 28.3 ms; then a segmented 128 KiB write, `fired=yes`, three times running |
| **a real USB drive, read through this window** | **PASS 2026-08-09** — `airusb-exportd --serve` captured the physical 058f:6387; the hub read `'Generic' 'Flash Disk' rev '8.01'`, 61 440 000 × 512 = 31.46 GB, and a genuine MBR at LBA 0 (`bootsig=55AA`) |
| a real USB drive, **written** through the session | **PASS 2026-08-09**, with the owner's explicit permission — 128 KiB segmented write from LBA 1024, byte-identical read-back, original restored, medium verified unchanged afterwards |

That last row cost two real bugs to earn, and both were invisible on loopback:
a socket that never fills never strands a tail, and a device that is only ever
used once is never handed on mid-phase. `HANDOFF.md` §3.4 and §3.9 have the
details. It is the argument for running the two-machine case rather than
trusting the matrix.
