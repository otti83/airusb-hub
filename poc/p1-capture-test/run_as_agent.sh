#!/bin/bash
#
# AirUSB Hub — test G: run the capture test as a LaunchAgent.
#
# WHY
#   The context matrix showed the discriminator is the security session, not uid:
#     A direct (root, console session)      IOServiceOpen -> SUCCESS
#     B LaunchDaemon (root, system session) -> 0xE00002E2 kIOReturnNotPermitted
#     C LaunchDaemon + SessionCreate        -> 0xE00002E2
#     D launchctl asuser (root, console)    -> SUCCESS
#     E LaunchDaemon outside TCC paths      -> 0xE00002E2
#   and the kernel names the gate:
#     (Sandbox) System Policy: capture_test(pid) deny(1) iokit-open-service IOUSBHostInterface
#
#   A LaunchAgent runs inside the console user's Aqua session — the context that
#   works — but as the USER, not root. This tests the two things that decides the
#   exporter architecture:
#     1. does IOUSBHostInterface open succeed for a non-root, console-session process?
#     2. does IOUSBHostObjectInitOptionsDeviceCapture work without root?
#
#   If (1) passes and (2) fails, the exporter splits: a root LaunchDaemon does the
#   unmount and the IOUSBHostDevice capture (both already proven to work under
#   launchd), and a session agent opens the interface and does bulk I/O. Those are
#   separate user clients, so a split is legitimate rather than a workaround.
#
# USAGE
#   ./run_as_agent.sh 058f:6387        # NOT sudo — must run as the console user
#
set -uo pipefail

VIDPID="${1:-}"
if ! [[ "$VIDPID" =~ ^[0-9a-fA-F]{4}:[0-9a-fA-F]{4}$ ]]; then
    echo "usage: $0 VID:PID     e.g. $0 058f:6387" >&2
    exit 64
fi
if [[ $EUID -eq 0 ]]; then
    echo "error: run this WITHOUT sudo — a LaunchAgent must load as the console user" >&2
    exit 1
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$HERE/capture_test"
[[ -x "$BIN" ]] || { echo "error: $BIN not built. Run ./build.sh" >&2; exit 1; }

LABEL="com.airusb.capture-test-agent"
PLIST="$HOME/Library/LaunchAgents/${LABEL}.plist"
LOG="/tmp/airusb_agent.log"

cleanup() { launchctl bootout "gui/$(id -u)/${LABEL}" 2>/dev/null; rm -f "$PLIST"; }
trap cleanup EXIT

mkdir -p "$HOME/Library/LaunchAgents"
rm -f "$LOG"

cat > "$PLIST" <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>           <string>${LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${BIN}</string><string>--probe-interface</string><string>${VIDPID}</string>
    </array>
    <key>RunAtLoad</key>        <true/>
    <key>StandardOutPath</key>  <string>${LOG}</string>
    <key>StandardErrorPath</key><string>${LOG}</string>
    <key>LimitLoadToSessionType</key> <string>Aqua</string>
</dict>
</plist>
PLISTEOF

echo "=== loading LaunchAgent ${LABEL} into gui/$(id -u) ==="
launchctl bootout "gui/$(id -u)/${LABEL}" 2>/dev/null
launchctl bootstrap "gui/$(id -u)" "$PLIST" 2>&1 | sed 's/^/  /'

echo "=== waiting (up to 60s) ==="
for _ in $(seq 1 120); do
    grep -qE "VERDICT=" "$LOG" 2>/dev/null && break
    sleep 0.5
done

echo
echo "==================== agent output ===================="
cat "$LOG" 2>/dev/null || echo "(no output — the agent may not have started)"
echo "====================================================="
echo
echo "Reading it:"
echo "  'must run as root'                  -> expected; DeviceCapture needs root."
echo "     The decisive line is still the raw IOServiceOpen result, so if the tool"
echo "     bailed before reaching it, we learn only that capture needs root."
echo "  raw IOServiceOpen -> 0x00000000     -> a console-session process CAN open"
echo "     the interface without root. Exporter splits: root daemon captures the"
echo "     device, session agent opens interfaces and moves data."
echo "  raw IOServiceOpen -> 0xE00002E2     -> session membership is not sufficient"
echo "     on its own; the gate wants an entitlement or TCC grant as well."
