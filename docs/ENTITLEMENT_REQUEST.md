# Requesting `com.apple.developer.usb.host-controller-interface`

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

Apple added a self-service request tab:

<https://developer.apple.com/help/account/capabilities/capability-requests/>

> Certificates, Identifiers & Profiles → **Identifiers** → **Capability Requests**

Requires the **Account Holder** role. If `USB Host Controller Interface` appears in
the list, request it there and skip Route B.

As of the most recent Apple DTS statement it is *not* listed there — Kevin Elliott
(DTS, CoreOS/Hardware) said the request volume "is low enough that it's never been
integrated into the developer portal" — but the tab is new and the list changes, so
it costs nothing to look.

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

## 3. Which Team ID to use

This machine holds two signing identities on **different teams**:

| Identity | Team ID |
|---|---|
| Apple Development: Hiroya Ochiai | `WT36SR3Q23` |
| Apple Distribution: Hiroya Ochiai | `GZUV3UMV3B` |

Decide which team will ship AirUSB Hub **before** filing, and request against that
one. The grant lands on a team, and moving it later means filing again.

---

## 4. Draft request text

Fill in the two bracketed items and paste into *Describe the Issue*. Written to
answer the question DTS says is the deciding one.

```
Team ID: [WT36SR3Q23 or GZUV3UMV3B — pick the team that will ship the product]

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

PROJECT / MATERIAL

[Link to the repository, project page, or any marketing material. If none exists
yet, say so and describe the current state of the project — a feasibility report
and a working exporter prototype exist.]
```

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
