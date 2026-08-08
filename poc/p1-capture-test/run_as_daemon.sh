#!/bin/bash
#
# AirUSB Hub — run capture_test in the DECISIVE launch context for FB16524420.
#
# WHY THIS EXISTS
#   FB16524420 reports that IOUSBHostInterface capture of a mass storage device
#   fails with kIOReturnInternalError (0xE00002C9) *from a LaunchDaemon*, but
#   succeeds from Terminal/Xcode. A PASS from an interactive shell is therefore
#   the expected result even when the bug is present — it proves nothing.
#
#   AirUSB Hub's exporter must run as a root LaunchDaemon (that is the supported
#   shape for a notarized Developer ID app: an SMAppService/launchd daemon plus an
#   unprivileged UI). So the LaunchDaemon result is the one that decides the
#   architecture.
#
# WHAT IT DOES
#   Loads a one-shot LaunchDaemon that runs capture_test once, captures its
#   stdout/stderr to a log, prints the log, then unloads and removes itself.
#   Nothing is left installed.
#
# USAGE
#   sudo ./run_as_daemon.sh 058f:6387
#
set -euo pipefail

VIDPID="${1:-}"
if [[ -z "$VIDPID" ]]; then
    echo "usage: sudo $0 VID:PID     e.g. sudo $0 058f:6387" >&2
    exit 64
fi
if ! [[ "$VIDPID" =~ ^[0-9a-fA-F]{4}:[0-9a-fA-F]{4}$ ]]; then
    echo "error: '$VIDPID' is not a VID:PID (four hex, colon, four hex)" >&2
    exit 64
fi
if [[ $EUID -ne 0 ]]; then
    echo "error: must run as root:  sudo $0 $VIDPID" >&2
    exit 1
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
# AIRUSB_BIN lets us point at a copy that has been granted Full Disk Access in
# System Settings — TCC grants follow the binary's path, so the granted copy must
# be the one launchd executes.
BIN="${AIRUSB_BIN:-$HERE/capture_test}"
[[ -x "$BIN" ]] || { echo "error: $BIN not built. Run: ./build.sh" >&2; exit 1; }
echo "using binary: $BIN"

LABEL="com.airusb.capture-test-oneshot"
PLIST="/Library/LaunchDaemons/${LABEL}.plist"
LOG="/tmp/airusb_capture_daemon.log"

cleanup() {
    launchctl bootout "system/${LABEL}" 2>/dev/null || true
    rm -f "$PLIST"
}
trap cleanup EXIT

rm -f "$LOG"

cat > "$PLIST" <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>              <string>${LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${BIN}</string>
        <string>--capture</string>
        <string>${VIDPID}</string>
    </array>
    <key>RunAtLoad</key>          <true/>
    <key>StandardOutPath</key>    <string>${LOG}</string>
    <key>StandardErrorPath</key>  <string>${LOG}</string>
    <key>ProcessType</key>        <string>Standard</string>
</dict>
</plist>
PLISTEOF

chown root:wheel "$PLIST"
chmod 644 "$PLIST"

echo "=== loading LaunchDaemon ${LABEL} ==="
launchctl bootout "system/${LABEL}" 2>/dev/null || true
launchctl bootstrap system "$PLIST"

# Wait for the one-shot to finish. capture_test does an unmount (up to 15s) plus
# capture and teardown, so allow generous headroom.
echo "=== waiting for it to run (up to 60s) ==="
for _ in $(seq 1 120); do
    if grep -q "VERDICT=" "$LOG" 2>/dev/null; then break; fi
    sleep 0.5
done

echo
echo "=================== daemon output ==================="
if [[ -s "$LOG" ]]; then
    cat "$LOG"
else
    echo "(no output captured — the daemon may not have started)"
    launchctl print "system/${LABEL}" 2>&1 | head -30 || true
fi
echo "====================================================="
echo
echo "This is the DECISIVE context. Look for:"
echo "  VERDICT=PASS  + 'launch context: launchd (daemon)'  -> FB16524420 does not affect us"
echo "  VERDICT=FAIL  + 0xE00002C9                          -> it does; exporter design changes"
