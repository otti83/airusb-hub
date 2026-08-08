#!/bin/bash
#
# P2.8 — the hardware gate, run in the real production shape.
#
# WHAT IT PROVES
#
#   A real CBW -> data -> CSW exchange through pipes the AGENT obtained while the
#   DAEMON holds the capture. That is the last unproven step of the split
#   exporter: P1 established that a console-session process may OPEN an interface
#   on a device another process captured, but never moved a byte through one.
#
# THE PRODUCTION SHAPE, NOT AN APPROXIMATION
#
#   airusb-exportd runs as a root LaunchDaemon (system session)
#   airusb-agent   runs as a LaunchAgent in the console user's Aqua session
#
#   Neither is launched from this terminal, because a process launched from a
#   terminal inherits the console session and would pass a test the shipping
#   configuration fails. The whole point of P1's context matrix was that launch
#   context is load-bearing.
#
# SAFETY
#
#   The probe is READ-ONLY: GET_MAX_LUN, TEST UNIT READY, INQUIRY,
#   READ CAPACITY(10), READ(10). Not one byte is written to the medium.
#
#   The drive is unmounted before capture and handed back afterwards. If any
#   unmount is refused, the run aborts before anything is captured. The boot disk
#   is refused outright.
#
#   Use a USB drive whose contents you do not care about anyway.
#
# USAGE
#   sudo ./p28_run.sh 058f:6387
#
set -uo pipefail

VIDPID="${1:-}"
if ! [[ "$VIDPID" =~ ^[0-9a-fA-F]{4}:[0-9a-fA-F]{4}$ ]]; then
    echo "usage: sudo $0 VID:PID     e.g. sudo $0 058f:6387" >&2
    echo >&2
    echo "Attached devices:" >&2
    HERE="$(cd "$(dirname "$0")" && pwd)"
    # Order matters: send stdout to stderr FIRST, then silence stderr. The other
    # way round points stdout at the /dev/null that stderr has already become.
    "$HERE/../../../build/airusb-exportd" --list >&2 2>/dev/null || true
    exit 64
fi
[[ $EUID -eq 0 ]] || { echo "error: must run as root: sudo $0 $VIDPID" >&2; exit 1; }

HERE="$(cd "$(dirname "$0")" && pwd)"
BUILD="$(cd "$HERE/../../.." && pwd)/build"
EXPORTD="$BUILD/airusb-exportd"
AGENT="$BUILD/airusb-agent"

for b in "$EXPORTD" "$AGENT"; do
    [[ -x "$b" ]] || {
        echo "error: $b not built." >&2
        echo "  cd \"$(cd "$HERE/../../.." && pwd)\" && cmake -S . -B build && cmake --build build" >&2
        exit 1
    }
done

CONSOLE_UID="$(stat -f%u /dev/console)"
CONSOLE_USER="$(id -un "$CONSOLE_UID")"
CONSOLE_HOME="$(dscl . -read "/Users/$CONSOLE_USER" NFSHomeDirectory | awk '{print $2}')"

if [[ "$CONSOLE_UID" == "0" || -z "$CONSOLE_HOME" ]]; then
    echo "error: no console user is logged in. The agent half must run in an Aqua session." >&2
    exit 1
fi

DLABEL="com.airusb.exportd.p28"
ALABEL="com.airusb.agent.p28"
DPLIST="/Library/LaunchDaemons/${DLABEL}.plist"
APLIST="${CONSOLE_HOME}/Library/LaunchAgents/${ALABEL}.plist"
SOCKET="/var/run/airusb-exportd-p28.sock"
DLOG="/tmp/airusb_p28_exportd.log"
ALOG="/tmp/airusb_p28_agent.log"

cleanup() {
    launchctl bootout "system/${DLABEL}"              2>/dev/null
    launchctl bootout "gui/${CONSOLE_UID}/${ALABEL}"  2>/dev/null
    rm -f "$DPLIST" "$APLIST" "$SOCKET"
}
trap cleanup EXIT

cleanup
rm -f "$DLOG" "$ALOG"
mkdir -p "${CONSOLE_HOME}/Library/LaunchAgents"

# ---------------------------------------------------------------------------
# record the "before" state, so the restore can be checked rather than assumed
# ---------------------------------------------------------------------------
echo "=== before ==="
"$EXPORTD" --list | sed 's/^/  /'
BEFORE_MOUNTS="$(mount | grep -E '^/dev/disk' | sort)"
echo "  mounted volumes:"
echo "$BEFORE_MOUNTS" | sed 's/^/    /'
echo

# ---------------------------------------------------------------------------
# step 1: the agent, into the console user's GUI session
#
# It starts FIRST and retries the connect, because the daemon does not create the
# socket until after it has captured the device. Whichever wins the race, the
# agent is waiting when the socket appears.
# ---------------------------------------------------------------------------
cat > "$APLIST" <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>           <string>${ALABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${AGENT}</string>
        <string>--socket</string>       <string>${SOCKET}</string>
        <string>--connect-wait</string> <string>90000</string>
    </array>
    <key>RunAtLoad</key>        <true/>
    <key>StandardOutPath</key>  <string>${ALOG}</string>
    <key>StandardErrorPath</key><string>${ALOG}</string>
    <key>LimitLoadToSessionType</key> <string>Aqua</string>
</dict>
</plist>
PLISTEOF
chown "$CONSOLE_UID" "$APLIST"
chmod 644 "$APLIST"

echo "=== step 1: LaunchAgent into gui/${CONSOLE_UID} (${CONSOLE_USER}, unprivileged) ==="
launchctl bootstrap "gui/${CONSOLE_UID}" "$APLIST" 2>&1 | sed 's/^/  /'

for _ in $(seq 1 40); do
    grep -q "airusb-agent starting" "$ALOG" 2>/dev/null && break
    sleep 0.25
done
if grep -q "airusb-agent starting" "$ALOG" 2>/dev/null; then
    grep -m1 "airusb-agent starting" "$ALOG" | sed 's/^/  /'
else
    echo "  WARNING: the agent has not logged a start line yet"
fi
echo

# ---------------------------------------------------------------------------
# step 2: the daemon, into the system session as root
# ---------------------------------------------------------------------------
cat > "$DPLIST" <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>           <string>${DLABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${EXPORTD}</string>
        <string>--device</string>     <string>${VIDPID}</string>
        <string>--socket</string>     <string>${SOCKET}</string>
        <string>--agent-wait</string> <string>60000</string>
        <string>--selftest-bot</string>
    </array>
    <key>RunAtLoad</key>        <true/>
    <key>StandardOutPath</key>  <string>${DLOG}</string>
    <key>StandardErrorPath</key><string>${DLOG}</string>
</dict>
</plist>
PLISTEOF
chown root:wheel "$DPLIST"
chmod 644 "$DPLIST"

echo "=== step 2: LaunchDaemon into system (root, system session) ==="
launchctl bootstrap system "$DPLIST" 2>&1 | sed 's/^/  /'
echo

# ---------------------------------------------------------------------------
# step 3: wait for a verdict
# ---------------------------------------------------------------------------
echo "=== step 3: waiting for the probe (up to 120 s) ==="
for _ in $(seq 1 240); do
    grep -qE "RESULT=(SELFTEST_PASS|SELFTEST_FAIL|SELFTEST_SKIPPED|ATTACH_FAILED)" \
         "$DLOG" 2>/dev/null && break
    sleep 0.5
done

echo
echo "==================== daemon log ===================="
cat "$DLOG" 2>/dev/null || echo "(no daemon output)"
echo
echo "==================== agent log ====================="
cat "$ALOG" 2>/dev/null || echo "(no agent output)"
echo "===================================================="
echo

# ---------------------------------------------------------------------------
# step 4: the drive must come back
#
# Restore is half of the safety story and is checked, not assumed. Plain destroy
# resets the device and re-registers its drivers, so the volume should remount
# on its own within a few seconds.
# ---------------------------------------------------------------------------
cleanup
trap - EXIT

echo "=== step 4: confirming the drive came back to this Mac ==="
RESTORED=no
for _ in $(seq 1 40); do
    # Restored means both that the device is enumerated again AND that block
    # media has reappeared beneath it. The device coming back with no bsd=[...]
    # would mean the reset happened but the driver never re-matched.
    AFTER_BSD="$("$EXPORTD" --list 2>/dev/null | grep -i "$VIDPID" | sed 's/.*bsd=\[//;s/\].*//')"
    if [[ -n "$AFTER_BSD" ]]; then RESTORED=yes; break; fi
    sleep 0.5
done

"$EXPORTD" --list 2>/dev/null | sed 's/^/  /'
AFTER_MOUNTS="$(mount | grep -E '^/dev/disk' | sort)"
echo "  mounted volumes:"
echo "$AFTER_MOUNTS" | sed 's/^/    /'

if [[ "$BEFORE_MOUNTS" == "$AFTER_MOUNTS" ]]; then
    echo "  mount table matches the 'before' state exactly"
else
    echo "  NOTE: the mount table differs from 'before'. Diff:"
    diff <(echo "$BEFORE_MOUNTS") <(echo "$AFTER_MOUNTS") | sed 's/^/    /'
    echo "  (a volume can take a few more seconds to remount; re-run 'mount' to confirm)"
fi
echo

# ---------------------------------------------------------------------------
# verdict
# ---------------------------------------------------------------------------
echo "==================== VERDICT ===================="
if grep -q "RESULT=SELFTEST_PASS" "$DLOG" 2>/dev/null; then
    echo "  P2.8 GATE: PASS"
    echo "    Bulk I/O works through pipes the agent obtained while the daemon"
    echo "    held the capture. The split exporter is proven end to end."
    grep -E "OQ-1:" "$DLOG" | sed 's/^.*\] /    /'
    RC=0
elif grep -q "RESULT=SELFTEST_FAIL" "$DLOG" 2>/dev/null; then
    echo "  P2.8 GATE: FAIL — the transfers did not survive the round trip."
    grep -E "RESULT=SELFTEST_FAIL|first failure" "$DLOG" | sed 's/^.*\] /    /'
    RC=3
elif grep -q "RESULT=ATTACH_FAILED" "$DLOG" 2>/dev/null; then
    echo "  P2.8 GATE: BLOCKED — the device was never captured, so the transfer"
    echo "  path was not reached."
    grep -E "RESULT=ATTACH_FAILED" "$DLOG" | sed 's/^.*\] /    /'
    if grep -q "System Policy denied" "$ALOG" 2>/dev/null; then
        echo
        echo "    The agent was refused iokit-open-service on IOUSBHostInterface."
        echo "    That is the gate the two-process design exists for. If this"
        echo "    appears, the split architecture needs re-examining, not the code."
    fi
    RC=2
else
    echo "  P2.8 GATE: NO VERDICT — the daemon produced no result line."
    echo "  Read the logs above. The most common causes are the device not being"
    echo "  attached, and the agent never reaching the Aqua session."
    RC=1
fi
echo "  restore: drive back on this Mac = ${RESTORED}"
echo "================================================"
echo
echo "logs kept at:"
echo "  $DLOG"
echo "  $ALOG"
exit $RC
