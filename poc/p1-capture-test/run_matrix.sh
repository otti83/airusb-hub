#!/bin/bash
#
# AirUSB Hub — execution-context matrix for the IOUSBHostInterface open failure.
#
# WHAT WE KNOW
#   root + Terminal (console session) : IOServiceOpen(interface) SUCCEEDS
#   root + LaunchDaemon               : IOServiceOpen(interface) -> 0xE00002E2
#                                       kIOReturnNotPermitted
#
#   IOUserClient::clientHasPrivilege has session-scoped privileges
#   (kIOClientPrivilegeConsoleUser, kIOClientPrivilegeLocalUser) that root does
#   NOT satisfy — they are about which security session the caller belongs to,
#   not about uid. A LaunchDaemon belongs to the system session and has no
#   console user. That would explain everything we have measured.
#
# WHAT THIS SCRIPT DECIDES
#   Which execution contexts can open a USB interface, and therefore what shape
#   the AirUSB exporter is allowed to have. Run it once; it tests four contexts
#   back to back against the same device.
#
#     A  direct           root, console session      (expected: works)
#     B  LaunchDaemon     root, system session       (expected: NotPermitted)
#     C  LaunchDaemon     + SessionCreate=true       (does a fresh security
#                                                     session satisfy the check?)
#     D  launchctl asuser root, console user's session context
#                                                    (root AND session — the
#                                                     shape a shipping daemon
#                                                     could actually adopt)
#
# USAGE
#   sudo ./run_matrix.sh 058f:6387
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
LABEL="com.airusb.capture-test-matrix"
PLIST="/Library/LaunchDaemons/${LABEL}.plist"

cleanup() { launchctl bootout "system/${LABEL}" 2>/dev/null; rm -f "$PLIST"; }
trap cleanup EXIT

# Pull just the lines that decide the outcome.
digest() {
    grep -E "raw IOServiceOpen|IOServiceAuthorize|INTERFACE_CAPTURED|interfaces:|launch context|VERDICT" "$1" \
        | sed 's/^/      /' || echo "      (no decisive lines — see full log)"
}

run_daemon() {  # $1 = label suffix, $2 = extra plist XML
    local log="/tmp/airusb_matrix_$1.log"
    rm -f "$log"
    cat > "$PLIST" <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>           <string>${LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${BIN}</string><string>--capture</string><string>${VIDPID}</string>
    </array>
    <key>RunAtLoad</key>       <true/>
    <key>StandardOutPath</key> <string>${log}</string>
    <key>StandardErrorPath</key><string>${log}</string>
${2}
</dict>
</plist>
PLISTEOF
    chown root:wheel "$PLIST"; chmod 644 "$PLIST"
    launchctl bootout "system/${LABEL}" 2>/dev/null
    launchctl bootstrap system "$PLIST" 2>&1 | sed 's/^/      /'
    for _ in $(seq 1 100); do
        grep -q "VERDICT=" "$log" 2>/dev/null && break
        sleep 0.5
    done
    launchctl bootout "system/${LABEL}" 2>/dev/null
    digest "$log"
}

echo "console user uid: ${CONSOLE_UID}"
echo

echo "=== A: direct — root, console session (baseline) ==="
A_LOG=/tmp/airusb_matrix_A.log
"$BIN" --capture "$VIDPID" > "$A_LOG" 2>&1
digest "$A_LOG"
sleep 3

echo
echo "=== B: LaunchDaemon — root, system session ==="
run_daemon B ""
sleep 3

echo
echo "=== C: LaunchDaemon + SessionCreate ==="
run_daemon C "    <key>SessionCreate</key>  <true/>"
sleep 3

echo
echo "=== D: launchctl asuser ${CONSOLE_UID} — root inside the console user's session ==="
D_LOG=/tmp/airusb_matrix_D.log
launchctl asuser "$CONSOLE_UID" "$BIN" --capture "$VIDPID" > "$D_LOG" 2>&1
digest "$D_LOG"

echo
echo "==================== SUMMARY ===================="
for ctx in A B C D; do
    L=/tmp/airusb_matrix_${ctx}.log
    if [[ -f "$L" ]]; then
        V=$(grep -oE "VERDICT=[A-Z_]+" "$L" | tail -1)
        R=$(grep -oE "raw IOServiceOpen\(interface, type=0\) -> 0x[0-9A-F]+" "$L" | tail -1 | grep -oE "0x[0-9A-F]+")
        printf "  %s  %-22s raw_open=%s\n" "$ctx" "${V:-NO_VERDICT}" "${R:-n/a}"
    fi
done
echo "================================================"
echo
echo "Reading it: any context with VERDICT=PASS is a viable exporter shape."
echo "If only A and D pass, the exporter must run inside the console user's"
echo "session, and a plain LaunchDaemon is ruled out."
