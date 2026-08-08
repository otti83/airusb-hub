#!/bin/bash
#
# AirUSB Hub — the test that decides the exporter architecture.
#
# WHAT WE ESTABLISHED
#   Operation                              root?  console session?
#   DiskArbitration whole-disk unmount     YES    no      (kDAReturnNotPrivileged)
#   IOUSBHostDevice DeviceCapture          YES    no      (works under launchd)
#   IOUSBHostInterface open                NO     YES     (works as uid 501;
#                                                          0xE00002E2 under launchd)
#
#   No single process in a shippable product can be both root and a member of the
#   console session. So the exporter must split — IF a session process can open an
#   interface on a device captured by a DIFFERENT process.
#
# WHAT THIS TESTS
#   1. A root LaunchDaemon captures the device and holds it (proven to work).
#   2. While it holds, a non-root process in the console session tries to open the
#      interface user client.
#
#   PASS -> the split exporter is viable:
#             root daemon  : unmount + IOUSBHostDevice capture + lifecycle
#             session agent: IOUSBHostInterface + pipes + bulk I/O
#   FAIL -> capture and interface I/O cannot be separated. The exporter then has to
#           live entirely in the console session, and unmount has to be delegated to
#           a small root helper over IPC.
#
# USAGE
#   sudo ./run_split_test.sh 058f:6387
#
set -uo pipefail

VIDPID="${1:-}"
if ! [[ "$VIDPID" =~ ^[0-9a-fA-F]{4}:[0-9a-fA-F]{4}$ ]]; then
    echo "usage: sudo $0 VID:PID     e.g. sudo $0 058f:6387" >&2
    exit 64
fi
[[ $EUID -eq 0 ]] || { echo "error: must run as root: sudo $0 $VIDPID" >&2; exit 1; }

HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$HERE/capture_test"
[[ -x "$BIN" ]] || { echo "error: $BIN not built. Run ./build.sh" >&2; exit 1; }

CONSOLE_UID="$(stat -f%u /dev/console)"
CONSOLE_USER="$(id -un "$CONSOLE_UID")"
LABEL="com.airusb.capture-hold"
PLIST="/Library/LaunchDaemons/${LABEL}.plist"
HOLD_LOG=/tmp/airusb_split_daemon.log
PROBE_LOG=/tmp/airusb_split_probe.log

cleanup() { launchctl bootout "system/${LABEL}" 2>/dev/null; rm -f "$PLIST"; }
trap cleanup EXIT

rm -f "$HOLD_LOG" "$PROBE_LOG"

cat > "$PLIST" <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>           <string>${LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${BIN}</string><string>--capture</string><string>${VIDPID}</string><string>25</string>
    </array>
    <key>RunAtLoad</key>        <true/>
    <key>StandardOutPath</key>  <string>${HOLD_LOG}</string>
    <key>StandardErrorPath</key><string>${HOLD_LOG}</string>
</dict>
</plist>
PLISTEOF
chown root:wheel "$PLIST"; chmod 644 "$PLIST"

echo "=== step 1: root LaunchDaemon captures ${VIDPID} and holds it 25s ==="
launchctl bootout "system/${LABEL}" 2>/dev/null
launchctl bootstrap system "$PLIST" 2>&1 | sed 's/^/  /'

# Wait for the daemon to actually reach the hold, so the probe runs while the
# device is genuinely captured rather than racing the capture.
for _ in $(seq 1 60); do
    grep -q "HOLDING capture" "$HOLD_LOG" 2>/dev/null && break
    sleep 0.5
done

if ! grep -q "HOLDING capture" "$HOLD_LOG" 2>/dev/null; then
    echo "  daemon never reached the hold — its log:"
    sed 's/^/    /' "$HOLD_LOG" 2>/dev/null
    exit 1
fi
echo "  daemon is holding the capture."
sed -n 's/^/    /p' "$HOLD_LOG" | grep -E "DEVICE_CAPTURED|republished|HOLDING" || true

echo
echo "=== step 2: non-root console-session process probes the interface ==="
sudo -u "$CONSOLE_USER" "$BIN" --probe-interface "$VIDPID" > "$PROBE_LOG" 2>&1
sed 's/^/  /' "$PROBE_LOG"

echo
echo "=== step 3: waiting for the daemon to release ==="
for _ in $(seq 1 80); do
    grep -q "RESULT=RESTORED" "$HOLD_LOG" 2>/dev/null && break
    sleep 0.5
done
grep -E "RESULT=RESTORED" "$HOLD_LOG" | sed 's/^/  /' || echo "  (release not observed)"

echo
echo "==================== VERDICT ===================="
if grep -q "VERDICT=PASS" "$PROBE_LOG" 2>/dev/null; then
    echo "  SPLIT IS VIABLE"
    echo "    root daemon   : unmount + IOUSBHostDevice capture + lifecycle"
    echo "    session agent : IOUSBHostInterface + pipes + bulk transfers"
else
    R=$(grep -oE "raw IOServiceOpen.* -> 0x[0-9A-F]+" "$PROBE_LOG" | tail -1)
    echo "  SPLIT IS NOT VIABLE"
    echo "    ${R:-no raw open result captured}"
    echo "    The exporter must live entirely in the console session, with a small"
    echo "    root helper doing only the unmount over IPC."
fi
echo "================================================"
