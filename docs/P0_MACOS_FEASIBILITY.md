# P0 — macOS Virtual USB Feasibility

**Project:** AirUSB Hub
**Date:** 2026-08-08
**Author:** Phase 0 investigation
**Status:** Gate 0 complete

---

## Verdict

```
Feasibility:            CONDITIONAL PASS

Required APIs:          IOUSBHost.framework (public, macOS SDK)
                          Importer: IOUSBHostControllerInterface
                                    IOUSBHostCIControllerStateMachine
                                    IOUSBHostCIPortStateMachine
                                    IOUSBHostCIDeviceStateMachine
                                    IOUSBHostCIEndpointStateMachine
                          Exporter: IOUSBHostDevice / IOUSBHostInterface / IOUSBHostPipe
                                    (IOUSBHostObjectInitOptionsDeviceCapture)
                          Unmount:  DiskArbitration.framework

Required entitlement:   Importer: com.apple.developer.usb.host-controller-interface
                                  -> RESTRICTED *and* MANAGED. Not self-serve.
                                     Must be granted by Apple and carried in an
                                     Apple-issued provisioning profile.
                        Exporter: none, if the capture helper runs as root.
                                  (com.apple.vm.device-access is the alternative,
                                   but it is MAS-hypervisor-only per Apple DTS.)

SIP:                    Not Required   (for the shipping, entitled product)
                        Required to disable ONLY as an interim development
                        workaround before the entitlement is granted.

Private API:            Not Required

OS modification:        Not Required. No kext of ours. Apple's own
                        com.apple.driver.usb.AppleUSBUserHCI does the kernel work.

Apple Silicon:          Supported   (verified on M1 / T8103, macOS 26.5.1)

Minimum macOS:          11.0  (headers carry NO API_AVAILABLE annotations;
                               absent from the 10.15 SDK, present in 11.3)

Distribution:           Developer ID + notarization works. PROVEN by a shipping
                        third-party product (see §4). Mac App Store not required.
                        End users need no entitlement, no SIP change, no kext
                        approval — they just run a notarized app.

Recommended PoC:        Two-process design, see §7.
```

**One-sentence summary:** macOS ships a complete, public, documented user-space virtual USB host controller API that does exactly what AirUSB Hub needs; the only obstacle is an Apple-managed entitlement that must be requested, and a shipping third-party product proves Apple grants it.

---

## 1. Environment under test

All findings below were produced on this machine unless explicitly marked otherwise.

| Property | Value | Command |
|---|---|---|
| macOS | 26.5.1 (25F80) | `sw_vers` |
| CPU | Apple M1 (T8103), arm64 | `uname -a` |
| Model | MacBookAir10,1 | `system_profiler SPiBridgeDataType` |
| Xcode | 26.5 (17F42) | `xcodebuild -version` |
| Swift | 6.3.2 | `swift --version` |
| macOS SDK | 26.5 | `xcodebuild -showsdks` |
| DriverKit SDK | 25.5 | `xcodebuild -showsdks` |
| SIP | **enabled** | `csrutil status` |
| Secure Boot | **低セキュリティ / Reduced Security** | `system_profiler SPiBridgeDataType` |
| Allow All Kernel Extensions | **YES** | `system_profiler SPiBridgeDataType` |
| Signing identities | Apple Development (WT36SR3Q23), Apple Distribution (GZUV3UMV3B) | `security find-identity -v -p codesigning` |
| USB root controllers | 2 × `AppleT8103USBXHCI` | `ioreg -p IOUSB` |
| USB devices attached | none at time of test | `system_profiler SPUSBDataType` |

> **Note on Secure Boot.** This Mac is *not* at Full Security. That does not affect
> the conclusions — the API refused to open regardless, and the experiments in §3
> show that only SIP state and code-signing authorization matter. But it does mean
> "works at Full Security" has **not** been demonstrated here and should be
> re-verified on a Full Security machine before release.

---

## 2. The mechanism macOS provides

### 2.1 It is public, and it is exactly the right primitive

`/System/Library/Frameworks/IOUSBHost.framework` is a **public** framework in the macOS 26.5 SDK. Its header states the purpose verbatim:

> `IOUSBHostControllerInterface.h:16-20`
> ```
> @class   IOUSBHostControllerInterface
> @brief   The object representing a user-mode USB host controller
> @details IOUSBHostControllerInterface enables a process to instantiate a USB host
>          controller to provide access to remote USB devices or create synthetic
>          USB devices.
>          The entitlement com.apple.developer.usb.host-controller-interface is
>          required to use this class.
> ```

Publicness is not an inference. It is established by four independent facts:

1. The headers live in `Versions/A/Headers/`, not `PrivateHeaders/`. The framework has **no** `PrivateHeaders` directory.
2. `Modules/module.modulemap` declares `framework module IOUSBHost { umbrella header "IOUSBHost.h" export * }`, and `IOUSBHost.h` `#import`s `IOUSBHostControllerInterface.h` plus all four state-machine headers. `@import IOUSBHost` exports them.
3. The class symbol is exported in `IOUSBHost.tbd`.
4. The required entitlement is itself a `#define` in a **public IOKit SDK header**, in the third-party `com.apple.developer.*` namespace:

   > `IOKit.framework/Headers/usb/IOUSBHostFamilyDefinitions.h:168-173`
   > ```c
   > #pragma mark Entitlements
   > #define kIOUSBTransportDextEntitlement            "com.apple.developer.driverkit.transport.usb"
   > #define kIOUSBHostVMEntitlement                   "com.apple.vm.device-access"
   > #define kIOUSBHostControllerInterfaceEntitlement  "com.apple.developer.usb.host-controller-interface"
   > #define kIOUSBBillboardEntitlement                "com.apple.developer.usb.billboard"
   > ```

Apple does not put SPI in an umbrella header and then name its entitlement in the third-party namespace of a second public header.

### 2.2 The kernel side is present and live

```
$ kmutil showloaded --list-only | grep -iE "UserHCI|IOUSBHostFamily"
  66 com.apple.iokit.IOUSBHostFamily (1.2)
  78 com.apple.driver.usb.AppleUSBUserHCI (1)

$ ioreg -c AppleUSBUserHCIResources -r -l -w 0
+-o AppleUSBUserHCIResources  <class AppleUSBUserHCIResources, id 0x1000002c8,
                               registered, matched, active, busy 0 (21 ms)>
    "CFBundleIdentifier" = "com.apple.driver.usb.AppleUSBUserHCI"
    "IOProviderClass"    = "IOResources"
    "IOMatchedAtBoot"    = Yes
```

Apple ships and boots the kernel half. AirUSB Hub supplies **no** kernel code.
`kmutil showloaded --list-only | grep -vc com.apple` = 0 — zero third-party kexts are involved.

### 2.3 The API is sufficient for real USB, not a toy

`IOUSBHostControllerInterfaceDefinitions.h` (876 lines) defines a complete xHCI-shaped contract:

| Concern | Mechanism |
|---|---|
| Message unit | `IOUSBHostCIMessage` — packed 16 bytes: `uint32 control; uint32 data0; uint64 data1` |
| Kernel → client commands | types `0x10..0x37`: controller power/start/pause/frame, port power/resume/suspend/reset/disable/status, device create/destroy/start/pause/update, endpoint create/destroy/pause/update/reset/setNextTransfer. One outstanding command at a time; each requires a response. |
| Client → kernel interrupts | `enqueueInterrupt(s):expedite:error:`, moderated by `interruptRateHz`. Carries port events, frame/timestamp updates, transfer completions. |
| Transfer descriptors | types `0x38..0x3C`: `SetupTransfer`, `NormalTransfer`, `StatusTransfer`, `IsochronousTransfer`, `Link`. Arrays chained by `Link`; kernel writes them into memory the client dereferences directly (`data1` = virtual address). |
| Transfer doorbell | 32-bit `IOUSBHostCIDoorbell` packing device address / endpoint address / stream ID |
| Completion | `IOUSBHostCIMessageTypeTransferComplete` with status, device+endpoint address, actual length, and the originating transfer-structure address |
| Control transfers | `SetupTransfer.data1` packs `bmRequestType/bRequest/wValue/wIndex/wLength` exactly per USB 3.2 §9.3 |
| Speeds | Low / Full / High / Super / SuperPlus / SuperPlusBy2 |
| Error model | 14 statuses incl. `StallError`, `TransactionError`, `OverrunError`, `Timeout`, `MissedServiceError` |
| Fatal errors | 13 `IOUSBHostCIExceptionType` values delivered via `kUSBHostMessageControllerException` |

Control, bulk, interrupt **and** isochronous are all representable. Endpoint halt/reset, port reset/suspend/resume, `SET_CONFIGURATION`/`SET_INTERFACE` (via DeviceUpdate/EndpointUpdate descriptor pointers), and device address assignment are all first-class.

**Hard constraint found:** `IOUSBHostCICapabilitiesMessageControlPortCount` is `IOUSBBitRange(16,19)` — **4 bits, so a maximum of 15 root ports per controller instance.** (This matches VirtualHere publicly bumping its limit "from 15 to 45 ports", i.e. 3 controller instances.)

**Descriptor flow is bidirectional**, which matters for protocol design: the kernel issues genuine `GET_DESCRIPTOR` control transfers on endpoint 0 that the client must service by forwarding to the real device — *and* separately hands the client already-parsed descriptor pointers on `DeviceUpdate`/`EndpointCreate`/`EndpointUpdate` so the "controller" can size its own resources.

---

## 3. Authorization: what actually gates it

This is the crux of Gate 0, so it was tested rather than assumed.
Reproduce with `poc/p0-probe/run_probe.sh`.

| # | Signature | Entitlement | Result | Meaning |
|---|---|---|---|---|
| A | ad-hoc | none | exit 2 | runs; `initWithCapabilities:` → nil, `kIOReturnNotOpen` |
| B | ad-hoc | `...usb.host-controller-interface` | **exit 137** | **SIGKILL by AMFI at exec** |
| C | Apple Development | `...usb.host-controller-interface` | **exit 137** | **SIGKILL by AMFI at exec** |
| D | Apple Development | none | exit 2 | runs; same `kIOReturnNotOpen` |
| E | Apple Development | `com.apple.developer.airusb.totally-made-up` | **exit 137** | **SIGKILL by AMFI at exec** |
| F | Apple Development | `com.apple.security.cs.disable-library-validation` | exit 2 | runs — not a restricted prefix |

Exact error for A/D/F:

```
IOUSBHostErrorDomain Code=-536870195 "Failed to create IOUSBHostControllerInterface."
  NSLocalizedFailureReason = "Unable to connect to the kernel."
-536870195 = 0xE00002CD = kIOReturnNotOpen   (IOReturn.h:115, iokit_common_err(0x2cd))
```

### Interpretation

The **E vs F** contrast is the informative one. A *fabricated* `com.apple.developer.*` entitlement is SIGKILLed identically to the real one, while a `com.apple.security.cs.*` entitlement is not. So this is **not** a targeted block on the USB entitlement. It is AMFI's generic rule:

> Any `com.apple.developer.*` entitlement must be authorized by an Apple-issued
> provisioning profile embedded in the bundle. Claiming one without a profile is
> fatal at exec, regardless of which certificate signed the binary.

And without the entitlement, the kernel simply refuses to open the user client.

There is **no SIP involvement and no kext involvement in either failure.** The gate is purely code-signing authorization.

---

## 4. Is the entitlement actually obtainable? — Yes. Proven.

This was the one question that could have failed Gate 0. It was settled by inspecting a shipping third-party product.

**VirtualHere Client** (commercial, non-Apple, downloaded from `virtualhere.com`):

```
$ spctl -a -vvv -t exec VirtualHereUniversal.app
  accepted
  source=Notarized Developer ID
  origin=Developer ID Application: VirtualHere Pty. Ltd. (N8C8ZTN347)

$ codesign -d --entitlements - VirtualHereUniversal.app
  com.apple.application-identifier              = N8C8ZTN347.com.virtualhere.client
  com.apple.developer.team-identifier           = N8C8ZTN347
  com.apple.developer.usb.host-controller-interface = true      <-- GRANTED
  com.apple.security.device.camera              = true

$ security cms -D -i Contents/embedded.provisionprofile | plutil -p -
  "Name"       => "virtualhere_22"
  "TeamName"   => "VirtualHere Pty. Ltd."
  "Entitlements" => {
      "com.apple.developer.usb.host-controller-interface" => true   <-- AUTHORIZED
  }
  "IsXcodeManaged"      => false
  "ProvisionsAllDevices"=> true
  "CreationDate"        => 2022-10-08
  "ExpirationDate"      => 2040-10-03
```

This establishes, with no inference required:

1. **Apple grants this entitlement to third parties.**
2. It ships via **Developer ID + notarization** — no Mac App Store requirement.
3. The authorization vehicle is exactly the `embedded.provisionprofile` that experiments B/C/E predicted was missing.
4. The profile is long-lived (18 years) and `ProvisionsAllDevices`, so it is not a per-machine development artifact.

### How it is obtained

It is **restricted *and* managed**: absent from Xcode 26.5's `DVTPortalCachedPortalCapabilities.json` (196 entries), and absent from the Developer portal's App ID Capabilities editor — so it cannot be self-assigned. Per Apple DTS (Kevin Elliott, CoreOS/Hardware; Quinn "The Eskimo!"), the request path is out-of-band:

- File a **macOS Feedback Assistant** report
- Title: `Request for Entitlement - com.apple.developer.usb.host-controller-interface`
- Problem Area: **USB**, Type: **Other Bug**
- Include: **Team ID**, a product overview, and **links to marketing material for the product/company**
- Requires the **Account Holder** role
- Apple's stated decision criterion: *"what product are you trying to build and why does it require simulating a USB controller"*

Approvals were observed being granted as recently as **July 2026**.

### ⚠ The one unproven qualifier

Every confirmed holder found is an **Organization** team (VirtualHere Pty. Ltd. is an Australian proprietary limited company). **No public instance of an *Individual* Apple Developer Program account being granted this entitlement was found.** Apple's gate is explicitly product/company-shaped ("marketing material for your product(s) and/or company"), which is precisely the filter a solo developer with a pre-release repository is most likely to fail.

**This is the project's #1 risk.** See §8.

---

## 5. Exporter side (the machine with the physical USB stick)

Good news: the exporter needs **no restricted entitlement.**

`IOUSBHostDefinitions.h:139-157`:

```c
// IOUSBHostObjectInitOptionsDeviceCapture:
//   Callers must have the "com.apple.vm.device-access" entitlement and the
//   IOUSBHostDevice IOService object needs to have successfully been authorized
//   by IOServiceAuthorize().
//   *** If the caller has root privileges the entitlement and authorization
//       is not needed. ***
//   Using this option will terminate all clients and drivers of the
//   IOUSBHostDevice and associated IOUSBHostInterface clients besides the caller.
//   Upon destroy of the IOUSBHostDevice, the device will be reset and drivers
//   will be re-registered for matching. This option is only valid for macOS.
typedef NS_OPTIONS (NSUInteger, IOUSBHostObjectInitOptions) {
    IOUSBHostObjectInitOptionsNone          = 0,
    IOUSBHostObjectInitOptionsDeviceCapture = (1 << 0),
    IOUSBHostObjectInitOptionsDeviceSeize   = (1 << 1)
};
```

This is exactly the capture/restore lifecycle §7 of the master spec requires: it evicts `IOUSBMassStorageDriver`, and on `destroy` it resets the device and re-registers drivers so the local OS remounts the stick normally. `IOUSBHostObjectDestroyOptionsDeviceSurrender` additionally supports honoring a polite close request.

**Root is sufficient** → the design is a root `launchd` helper + unprivileged UI, which is a completely normal, notarizable macOS shape (`SMAppService`). `com.apple.vm.device-access` is *not* a viable alternative for us: Apple DTS states it is granted only to Mac App Store hypervisor apps, and it was verified that **zero** processes on this Mac hold it — not even Apple's own Virtualization.framework VM XPC service.

### Paths that are dead ends (do not attempt)

- **Legacy IOUSBLib** — `kUSBReEnumerateCaptureDeviceBit` is documented in `USB.h` to explicitly **not** terminate drivers on a Mass Storage Class interface; `USBDeviceOpenSeize` only politely asks, and `IOUSBMassStorageDriver` refuses.
- **Unloading the mass storage kext** — `IOUSBMassStorageDriver.kext` is `OSBundleRequired = Local-Root` inside `BootKernelExtensions.kc`; not unloadable under SIP.
- **`kIOUSBHostDeviceForceRemove`** — does not exist anywhere in the macOS 26.5 SDK.
- **DriverKit dext exporter** — technically works, but needs Apple-approved VID/PID-scoped entitlements an OSS project cannot ship.

### ⚠ Exporter risk to verify before committing

**FB16524420 (open):** since macOS 15.3, a root helper can capture `IOUSBHostDevice` but reportedly **fails to capture `IOUSBHostInterface` for mass-storage devices** with `kIOReturnInternalError` (0xE00002C9) — *unless* SIP is disabled, or the process is launched from Terminal/Xcode rather than as a LaunchDaemon.

**This has not yet been tested on macOS 26.5 because no USB device was attached during Phase 0.** It is the first task of Phase 1 and it gates the exporter architecture. See §8.

---

## 6. Prior art

| Project | What it does | Relevance |
|---|---|---|
| **VirtualHere** (commercial) | macOS client switched from kexts to `IOUSBHostControllerInterface` in v5.2.4 (19 Nov 2021, the Monterey/M1 release) | Proves the API works in production and that Apple grants the entitlement |
| **Apple `MediaAgnosticUSB.framework`** (private) | Apple's own implementation of the USB-IF **MA-USB** (USB-over-network) spec. Links `IOUSBHost` + `Network.framework`; exports `_IOUSBHostCIDeviceSpeedForMAUSBSpeed` | **Apple built USB-over-network on this exact API.** Strong validation of the architecture |
| **carlossless/usbip-macos** | Rust USB/IP client (created May 2025, active Jul 2026) | Runs as **root with SIP disabled** because the author lacks the entitlement — documents the interim workaround |
| **SagerNet/sing-usbip** | Go cross-platform usbip; platform table lists `IOUSBHostControllerInterface` for macOS | Confirms the same choice independently |
| **JJTech0130** gist | Swift synthetic USB HID device | Minimal working reference |

Not comparable: **Karabiner-DriverKit-VirtualHIDDevice** creates a virtual *HID* device via HIDDriverKit — not a virtual USB device. (It is installed on this Mac and was initially misleading.)

Confirmed **not** users of the CI classes: Virtualization.framework (uses only `IOUSBHostDevice` for physical capture), CoreSimulator, CoreDevice, `devicectl`.

---

## 7. Recommended PoC architecture

```
┌───────────────── Exporter Mac ─────────────────┐   ┌───────────────── Importer Mac ─────────────────┐
│                                                │   │                                                │
│  Physical USB flash drive                      │   │        macOS USB stack (Apple's)               │
│         │                                      │   │              ▲                                 │
│  DiskArbitration: unmount + claim              │   │              │ IOUSBHostControllerInterface    │
│         │                                      │   │              │ (needs entitlement)             │
│  IOUSBHostDevice(DeviceCapture)  ← root helper │   │  airusbd (unprivileged) — virtual HCI          │
│  IOUSBHostInterface / IOUSBHostPipe            │   │    4 state machines, doorbell pump             │
│         │                                      │   │              ▲                                 │
│  airusb-exportd (root launchd)                 │   │              │                                 │
└─────────┼──────────────────────────────────────┘   └──────────────┼─────────────────────────────────┘
          │                                                         │
          └──────────── AirUSB Protocol over TCP (LAN) ─────────────┘
```

**Two separate processes with different privilege levels — this is forced, not stylistic:**

- **Exporter** must be **root** (for `DeviceCapture`) but needs **no entitlement**.
- **Importer** needs the **entitlement** but **no root**.

Keeping them separate means the exporter half is fully implementable and testable **today**, with zero dependency on Apple's approval.

**Port budget:** 15 root ports per `IOUSBHostControllerInterface` instance. Instantiate additional controllers if more devices are needed.

**Protocol:** reuse USB/IP's *semantic* model (URB-level remoting, 4 verbs, seqnum correlation, intercept-and-reissue for `CLEAR_HALT`/`SET_INTERFACE`/`SET_CONFIGURATION`/reset) but **not** its wire format. USB/IP's format is not self-describing (RET_SUBMIT zeroes direction and ep), carries host-local DMA flags as ABI, and puts **raw Linux errno values** in `status` — disqualifying for a macOS-first project, since `ECONNRESET` is 104 on Linux but 54 on macOS, and `EREMOTEIO` (Linux's standard short-read status) does not exist in the macOS SDK at all. AirUSB should use little-endian, length-prefixed, self-describing framing with u64 seqnums + a session epoch, its own portable status enum, explicit deadlines, flow control, and an explicit DETACH/DEVICE_GONE message — designed so the QUIC mapping (one stream per endpoint, DATAGRAMs for isochronous, connection migration for Wi-Fi roaming) is a transport swap, not a redesign.

---

## 8. Risks and open items

| # | Risk | Severity | Status |
|---|---|---|---|
| 1 | Entitlement may not be granted to an **Individual** developer account | **HIGH** | Unproven either way. Requires filing the request. Blocks the importer only. |
| 2 | FB16524420 — `IOUSBHostInterface` capture fails for mass storage from a LaunchDaemon since 15.3 | **HIGH** | Untested on 26.5 (no USB device attached). **First Phase 1 task.** |
| 3 | The CI message protocol is documented only in headers; no Apple sample code exists | MEDIUM | Mitigate with a strict message-encoder unit-test suite before touching the kernel |
| 4 | Malformed messages may destabilize the kernel driver | MEDIUM | Kernel signals `IOUSBHostCIExceptionType*` and expects teardown; implement exception handling first, use Apple's example capabilities verbatim |
| 5 | Watchdog: command timeout is 2^n seconds and a timeout is **fatal** | MEDIUM | Never block the command handler on network I/O. Respond locally, pipeline remotely. |
| 6 | 15-port ceiling per controller | LOW | Instantiate multiple controllers |
| 7 | No `API_AVAILABLE` annotations → silent breakage across macOS versions | MEDIUM | Pin a tested macOS range; add runtime capability checks |
| 8 | Full Security posture untested (this Mac is Reduced Security) | LOW | Re-verify on a Full Security machine before release |

---

## 9. Gate 0 decision

**CONDITIONAL PASS.**

The macOS Natural Path exists and is unambiguous:

- ✅ Public, documented SDK API — no private API
- ✅ Apple's own kernel driver — no kext from us, no OS modification
- ✅ SIP stays enabled
- ✅ Apple Silicon supported
- ✅ Normal Developer ID + notarized distribution, proven by a shipping product
- ✅ Exporter side requires no entitlement at all (root suffices)
- ⚠️ Importer side requires an Apple-**managed** entitlement that must be requested,
     with no confirmed precedent for an Individual developer account

The one condition is administrative, not technical. Per the master spec's own FAIL criteria, this is **not** a FAIL: the entitlement is demonstrably not "一般配布困難" — end users need nothing special, and a notarized Developer ID build reaches everyone. The burden falls once, on the project owner, at request time.

### Decision required from the project owner

1. **File the Apple entitlement request** (Account Holder role, Feedback Assistant, product justification + marketing material). This is on the critical path for the importer and has unknown latency.
2. **Decide the interim development posture** for the importer before the grant arrives. The only known alternative is *root + SIP disabled on a dedicated test machine*, which the master spec forbids as a product path. It would be an explicitly-labelled, temporary development configuration — but it is the project owner's call, not an assumption to make silently.

### What proceeds regardless

Phase 1 work that is **not** blocked by either decision:

- AirUSB protocol definition + encoder/decoder + unit tests
- Transport abstraction (`IAirUSBTransport`) + TCP implementation
- Core/platform layer split
- **The entire exporter**, including the FB16524420 verification (risk #2) — needs only root and a USB stick
- The importer's CI message encoding layer, unit-testable without ever opening the kernel user client

---

## Appendix A — reproducing the authorization matrix

```
poc/p0-probe/
  p0_probe.m       minimal IOUSBHostControllerInterface instantiation probe
  entitlements.plist
  run_probe.sh     builds and runs all six signing variants
```

```
$ ./poc/p0-probe/run_probe.sh
```

Override the signing identity with `AIRUSB_SIGN_IDENTITY`.

## Appendix B — evidence index

| Claim | Evidence |
|---|---|
| API is public | `Headers/` not `PrivateHeaders/`; module.modulemap umbrella; `IOUSBHost.tbd` export |
| Entitlement name | `IOUSBHostControllerInterface.h:19`; `IOUSBHostFamilyDefinitions.h:172` |
| Kernel provider live | `kmutil showloaded`; `ioreg -c AppleUSBUserHCIResources` |
| Denial without entitlement | probe variants A/D/F → `0xE00002CD kIOReturnNotOpen` |
| AMFI rule is generic | probe variants B/C/E (SIGKILL) vs F (runs) |
| Apple grants it to 3rd parties | VirtualHere: `codesign -d --entitlements -`, `spctl -a -vvv`, decoded `embedded.provisionprofile` |
| Exporter needs only root | `IOUSBHostDefinitions.h:141-147` |
| 15-port ceiling | `IOUSBHostCICapabilitiesMessageControlPortCount = IOUSBBitRange(16,19)` |
