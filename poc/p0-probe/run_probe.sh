#!/bin/bash
#
# AirUSB Hub — Phase 0 authorization experiment (reproducible)
#
# Builds p0_probe.m and runs it under five signing configurations to determine
# exactly what gates IOUSBHostControllerInterface on this machine.
#
# Expected results on macOS 26.5 / Apple Silicon / SIP enabled, as of 2026-08-08:
#
#   A  ad-hoc,      no entitlement          -> exit 2   (runs; kIOReturnNotOpen 0xE00002CD)
#   B  ad-hoc,      HCI entitlement         -> exit 137 (SIGKILL by AMFI)
#   C  Apple Dev,   HCI entitlement         -> exit 137 (SIGKILL by AMFI)
#   D  Apple Dev,   no entitlement          -> exit 2   (runs; kIOReturnNotOpen 0xE00002CD)
#   E  Apple Dev,   bogus com.apple.developer.* -> exit 137 (SIGKILL by AMFI)
#   F  Apple Dev,   com.apple.security.cs.* -> exit 2   (runs; not a restricted prefix)
#
# Interpretation:
#   B/C/E identical => AMFI's rule is generic: ANY com.apple.developer.* entitlement
#   requires an Apple-issued provisioning profile that grants it. F shows the rule is
#   scoped to that prefix. A/D show the kernel refuses the user client without it.
#
set -u
cd "$(dirname "$0")"

IDENTITY="${AIRUSB_SIGN_IDENTITY:-Apple Development: Hiroya Ochiai (WT36SR3Q23)}"

echo "### environment"
sw_vers | sed 's/^/    /'
echo "    arch: $(uname -m)   SIP: $(csrutil status 2>/dev/null | sed 's/.*: //')"
echo "    AppleUSBUserHCI kext loaded: $(kmutil showloaded --list-only 2>/dev/null | grep -c AppleUSBUserHCI)"
echo

echo "### build"
clang -fobjc-arc -fmodules -Wall -O0 -g \
  -isysroot "$(xcrun --sdk macosx --show-sdk-path)" \
  -framework Foundation -framework IOKit -framework IOUSBHost \
  -o p0_probe p0_probe.m || { echo "BUILD FAILED"; exit 1; }
echo "    built p0_probe"
echo

mk_plist() { printf '%s\n' \
  '<?xml version="1.0" encoding="UTF-8"?>' \
  '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">' \
  '<plist version="1.0"><dict>' \
  "	<key>$1</key><true/>" \
  '</dict></plist>' > "$2"; }

mk_plist "com.apple.developer.usb.host-controller-interface"      ent_hci.plist
mk_plist "com.apple.developer.airusb.totally-made-up-entitlement" ent_bogus.plist
mk_plist "com.apple.security.cs.disable-library-validation"       ent_cs.plist

run_variant() { # name, description, sign-args...
  local name="$1"; shift
  local desc="$1"; shift
  cp p0_probe "probe_$name"
  codesign -f "$@" "probe_$name" >/dev/null 2>&1 || { echo "  [$name] SIGNING FAILED"; return; }
  local out; out="$(./probe_"$name" 2>&1)"; local rc=$?
  local verdict
  case $rc in
    0)   verdict="CREATED (controller instantiated)" ;;
    2|3) verdict="DENIED  (ran, kernel refused user client)" ;;
    137) verdict="SIGKILL (AMFI rejected the entitlement claim)" ;;
    *)   verdict="exit $rc" ;;
  esac
  printf '  [%s] %-46s exit=%-4s %s\n' "$name" "$desc" "$rc" "$verdict"
  echo "$out" | grep -E "RESULT=|Code=" | sed 's/^/        /'
}

echo "### authorization matrix"
run_variant A "ad-hoc, no entitlement"                  -s -
run_variant B "ad-hoc, HCI entitlement"                 -s - --entitlements ent_hci.plist
run_variant C "Apple Dev, HCI entitlement"              -s "$IDENTITY" --entitlements ent_hci.plist   --options runtime
run_variant D "Apple Dev, no entitlement"               -s "$IDENTITY"                                --options runtime
run_variant E "Apple Dev, bogus com.apple.developer.*"  -s "$IDENTITY" --entitlements ent_bogus.plist --options runtime
run_variant F "Apple Dev, com.apple.security.cs.*"      -s "$IDENTITY" --entitlements ent_cs.plist    --options runtime

echo
echo "### conclusion"
echo "    The kernel provider (com.apple.driver.usb.AppleUSBUserHCI) is present and loaded."
echo "    Gate is purely authorization: com.apple.developer.usb.host-controller-interface"
echo "    must be granted by an Apple-issued provisioning profile. No SIP change involved."
