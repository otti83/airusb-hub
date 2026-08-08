# apple/ — the Xcode project

Generated from `project.yml` by [xcodegen](https://github.com/yonaskolb/XcodeGen):

```bash
cd apple && xcodegen generate
```

The `.xcodeproj` is **not** committed. It is a generated artefact, and a
`project.pbxproj` diff is unreadable — the spec is the source of truth.

## What this target is for

Two things, neither of which a bare `clang` binary can do:

1. **Get a provisioning profile.** A restricted entitlement is authorised by an
   Apple-issued provisioning profile embedded in the bundle. `codesign` on a loose
   Mach-O has no bundle and never contacts the portal, which is why
   `poc/p0-probe` could measure the refusal but could never carry a grant.

2. **Tell you the moment the entitlement lands.** Running the app reports whether
   `com.apple.developer.usb.host-controller-interface` is authorised, and whether
   `IOUSBHostControllerInterface` can actually be instantiated.

```bash
xcodebuild -project AirUSBHub.xcodeproj -scheme AirUSBHub \
           -destination 'platform=macOS' -allowProvisioningUpdates build

~/Library/Developer/Xcode/DerivedData/AirUSBHub-*/Build/Products/Debug/AirUSBHub.app/Contents/MacOS/AirUSBHub
```

Reading the result:

| output | meaning |
|---|---|
| `RESULT=GRANTED`, exit 0 | the entitlement is live. **P2.9 unblocks.** |
| `RESULT=REFUSED 0xE00002CD`, exit 2 | ran and was refused — the expected state before the grant |
| killed by SIGKILL | AMFI: the binary claimed a restricted entitlement the profile does not authorise |

Current state on this machine:

```
embedded.provisionprofile: PRESENT (14558 bytes)
profile authorises host-controller-interface: NO
RESULT=REFUSED 0xE00002CD kIOReturnNotOpen
```

## After Apple grants it

One line in `Sources/AirUSBHub.entitlements`:

```xml
<key>com.apple.developer.usb.host-controller-interface</key>
<true/>
```

then `xcodegen generate` and rebuild. Xcode fetches a profile that carries it, and
the probe should print `RESULT=GRANTED`.

## Why there is an App Group

`com.apple.security.application-groups` is in the entitlements for a real reason —
the exporter is two processes that must share the pin store and identity seed —
and for a useful side effect: it is a capability that requires a provisioning
profile. Without it, macOS development signing needs no profile at all, Xcode
never contacts the portal, and no profile is issued. Verified: the first build
here, before the App Group was added, signed successfully and produced no profile.

## Note on the App ID

Xcode provisioned this against the team wildcard (`GZUV3UMV3B.*`, "Mac Team
Provisioning Profile: *") rather than registering an explicit App ID for
`com.otti83.airusbhub`. That is fine for now. An explicit App ID is only needed if
the Capability Requests tab turns out to be usable — and it is not, because this
entitlement is absent from the portal's capability list entirely. See
`docs/ENTITLEMENT_REQUEST.md`.
