# Requesting `com.apple.developer.usb.host-controller-interface`

> ## READ THIS BEFORE OPENING THE PORTAL
>
> **You will not find it. There is nothing to find.**
>
> This entitlement is not a checkbox anywhere — not in the App ID Capabilities
> editor, not in Capability Requests, not in Xcode's Signing & Capabilities.
> Measured on this machine, 2026-08-08:
>
> ```
> $ python3 -c '...' DVTPortalCachedPortalCapabilities.json
> total capabilities Xcode knows: 196
> USB-related entries: 2
>     DRIVERKIT_TRANSPORT_USB_VENDORID
>     DRIVERKIT_USBTRANSPORT_PUB
> host-controller-interface present anywhere: False
> ```
>
> That file is the portal's own capability list, cached by Xcode. 196 entries,
> two of them USB, and neither is this one. Searching the portal for it is
> guaranteed to fail — **that is the expected state, not a mistake you made.**
>
> **The only way to get it is to ask Apple directly: §2 Route B.** Everything in
> Route A is preparation for after the grant, not a way to obtain it.

**Blocks:** P2.9 / P2.10 only (the importer's `CiHostBackend`).
**Does not block:** P2.0–P2.8 — protocol, core, security, transport, fakes, the
loopback gate, and the entire real-hardware exporter.
**Tracked as:** OQ-5 in `P1_IMPLEMENTATION_PLAN.md`.

---

## 1. What you are asking for, and why it is not self-serve

`IOUSBHostControllerInterface.h:19` states it plainly:

> The entitlement `com.apple.developer.usb.host-controller-interface` is required
> to use this class.

The entitlement is **restricted *and* managed**:

- **Restricted** — AMFI kills any process claiming it without an Apple-issued
  provisioning profile that grants it. Verified locally: `poc/p0-probe/run_probe.sh`
  variants B, C and E all exit 137 (SIGKILL), including when signed with a genuine
  Apple Development identity.
- **Managed** — it cannot be self-assigned. It is absent from Xcode 26.5's
  `DVTPortalCachedPortalCapabilities.json` (196 entries) and from the App ID
  Capabilities editor.

It **is** granted to third parties. VirtualHere ships it under a notarized
Developer ID signature; its `embedded.provisionprofile` authorizes exactly this key.
See `P0_MACOS_FEASIBILITY.md` §4 for the verification.

---

## 2. Two routes — try both

### Route A — Capability Requests tab (try first, 2 minutes)

<https://developer.apple.com/help/account/capabilities/capability-requests/>

**The tab lives inside an individual App ID, not in the sidebar.** Apple's steps:

> 1. Certificates, Identifiers & Profiles → **Identifiers**
> 2. **Click the name of the identifier** in the list of App IDs
> 3. Click the **Capability Requests** tab

So an App ID must exist before the tab exists at all.

**How App IDs actually get registered** — there are three ways, and only one of
them is manual:

| how the app is signed | registers an App ID in the portal? |
|---|---|
| Xcode with *Automatically manage signing* | **yes** — Xcode calls the Developer API and creates it on demand |
| Sideloading tools (AltStore, SideStore, …) | **yes** — same API, which is why such App IDs carry the team ID in the bundle string |
| `codesign -s …` on a bare binary | **no** — codesign never contacts the portal |
| the **⊕** button | yes, manually |

AirUSB Hub has no App ID yet because it has no Xcode project yet: `capture_test`
is a bare clang binary signed with `codesign` directly. Either build it from an
Xcode project with automatic signing, or register the App ID by hand.

**To register by hand** (role: Account Holder or Admin):

| field | value |
|---|---|
| type | App IDs → App |
| Description | `AirUSB Hub` |
| type | **Explicit App ID** |
| Bundle ID | e.g. `com.<yourdomain>.airusbhub` — must later match the Xcode target |

Leave the capability checkboxes alone for now; they can be changed later.

Then open the App ID and check the Capability Requests tab for anything USB-related.

**Expect it to be absent.** Apple's own documentation does not describe how to
request a capability that is *not* listed there, which matches Kevin Elliott (DTS,
CoreOS/Hardware) saying the request volume "is low enough that it's never been
integrated into the developer portal". An empty or USB-free tab is the normal
outcome, not a misconfiguration — go to Route B.

### Route B — Feedback Assistant (the documented path)

<https://feedbackassistant.apple.com>

Exact form values, quoted from Apple DTS in
<https://developer.apple.com/forums/thread/802495>:

| Field | Value |
|---|---|
| OS button | **macOS** |
| Descriptive title | `Request for Entitlement - com.apple.developer.usb.host-controller-interface` |
| Problem Area | **USB** |
| Type of Feedback | **Other Bug** |

In *Describe the Issue*, include:

1. Your **Team ID**
2. A general overview of the product you intend to make
3. **Links to any marketing material** you have for your product and/or company

DTS is explicit about what actually gets read:

> "what's going here isn't really a 'bug' … the critical information here isn't
> 'what's happening', it's **'what product are you trying to build and why does it
> require simulating a USB controller'**."

After filing, post the Feedback ID in that forum thread — Kevin Elliott has offered
to route requests to the right reviewers.

---

## 3. Which Team ID — SETTLED: `GZUV3UMV3B`

This was an open decision. It is not any more, because the machine answers it.

Xcode has exactly **one** team signed in:

```
$ defaults read com.apple.dt.Xcode IDEProvisioningTeamByIdentifier
    isFreeProvisioningTeam = 0;
    teamID   = GZUV3UMV3B;
    teamName = "Hiroya Ochiai";
    teamType = Individual;
```

`WT36SR3Q23` exists only as a local *signing identity* in the keychain, not as a
team Xcode can provision against. The provisioning profile Xcode generated for
this project is issued to `GZUV3UMV3B`. So:

**File against `GZUV3UMV3B`.**

`teamType = Individual` is also the honest statement of the risk in §5: every
confirmed holder of this entitlement is an Organization. That does not make the
request pointless, but it is the thing most likely to get it declined, and it is
worth knowing before spending effort on the wording rather than after.

---

## 4. Draft request text

Ready to paste into *Describe the Issue*. Nothing left to fill in. Written to
answer the question DTS says is the deciding one — not "what went wrong" but
"what are you building and why does it need to simulate a USB controller".

```
Team ID: GZUV3UMV3B

I am requesting the com.apple.developer.usb.host-controller-interface entitlement
for an open-source macOS application called AirUSB Hub.

WHAT THE PRODUCT IS

AirUSB Hub lets a USB device physically attached to one Mac be used from another
Mac on the same local network, as if it were plugged into that second machine
directly. The importing Mac enumerates the device through its own USB stack and
loads its own unmodified class drivers, so a USB flash drive mounts as a normal
volume, a HID device is seen by the normal HID stack, and so on.

It is peer to peer and LAN only. There is no cloud service, no account, and no
central server. Sessions are mutually authenticated and encrypted, and devices are
only shared between explicitly paired machines.

WHY IT REQUIRES A USER-MODE USB HOST CONTROLLER

The product's whole purpose is that the remote device is presented to the OS as a
real USB device, so that Apple's own drivers bind to it and behave exactly as they
would locally. That requires a host controller on the importing machine that can
create a device from descriptors fetched over the network and service its transfers.

IOUSBHostControllerInterface is the only supported API on macOS that can do this.
The alternatives were evaluated and rejected:

- A kernel extension implementing a host controller would require users to reduce
  Secure Boot and reboot into recoveryOS, which is unacceptable for general
  distribution and contrary to Apple's direction.
- A DriverKit driver cannot help: USBDriverKit exposes IOUSBHostDevice /
  IOUSBHostInterface / IOUSBHostPipe for consuming a physical device, and no
  virtual host controller class.
- A file-sharing approach (SMB, or a FSKit filesystem) is a different product. It
  does not present a USB device, does not load the device's own class driver, and
  cannot support non-storage devices at all.

The exporting side needs no special entitlement — it uses
IOUSBHostObjectInitOptionsDeviceCapture from a root helper, which is already
working against real hardware.

SCOPE OF USE

The entitlement would be used only by the importing daemon, solely to instantiate
a host controller whose devices are supplied by an authenticated peer that the user
has explicitly paired with.

DISTRIBUTION

Developer ID signed and notarized, distributed outside the Mac App Store, with
full source published under an open-source license.

PROJECT

  https://github.com/otti83/airusb-hub

Open source, full history, screenshots and hardware verification logs in the repo.

What is already built and working:

- The sharing half, verified against real hardware. A root LaunchDaemon captures a
  USB device with IOUSBHostObjectInitOptionsDeviceCapture; an unprivileged
  console-session agent opens the interface and moves data. A complete USB Mass
  Storage exchange (CBW, data, CSW) runs end to end against a SuperSpeed flash
  drive and the drive is returned to the host cleanly afterwards.
- Session security: Noise_XX / Noise_IK over X25519, ChaCha20-Poly1305 and
  BLAKE2s, checked byte for byte against the official Noise cross-implementation
  test vectors. Mutual authentication against pinned peer identities, with a
  six-digit numeric comparison for pairing.
- A SwiftUI app for device status and ejection.

The importing half is the only part not built, because it is the only part that
needs this entitlement.
```

> Published 2026-08-08: <https://github.com/otti83/airusb-hub>

---

## 5. What to expect

- Approvals were observed being granted as recently as **July 2026**, so this is a
  live process, not a dead form.
- **Known risk:** every confirmed holder found during Phase 0 is an **Organization**
  team (VirtualHere Pty. Ltd. is an Australian proprietary limited company). No
  public instance of an **Individual** account being granted this entitlement was
  found. Apple's stated criteria are product- and company-shaped ("marketing
  material for your product(s) and/or company"), which is exactly the filter a solo
  developer with no published product is most likely to fail.
- If the request is declined, that does **not** invalidate the architecture. The
  exporter half remains fully functional and the protocol is unaffected; what is
  lost is the ability for *this* team to ship the importer. Options at that point:
  publish source so a granted team can build it, re-apply with a published product
  and a project page, or enroll as an organization.

Do not disable SIP as a workaround for shipping. It is acceptable only as a
clearly-labelled development configuration on a dedicated test machine, and only if
the project owner explicitly chooses it.

---

## Sources

- [IOUSBHostControllerInterface entitlement request — Apple Developer Forums thread 802495](https://developer.apple.com/forums/thread/802495)
- [Capability Requests — Apple Developer Account Help](https://developer.apple.com/help/account/capabilities/capability-requests/)
- [Provisioning with managed capabilities — Apple Developer Account Help](https://developer.apple.com/help/account/reference/provisioning-with-managed-capabilities)
- [Feedback Assistant](https://feedbackassistant.apple.com)
