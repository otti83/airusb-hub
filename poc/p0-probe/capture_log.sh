#!/bin/bash
# Capture the IOUSBHost framework's own os_log output while the probe attempts
# to create a user-mode USB host controller. The framework logs to subsystem
# com.apple.iokit.usb.framework.IOUSBHost (documented in IOUSBHostControllerInterface.h).
set -u
BIN="${1:?usage: capture_log.sh <probe-binary>}"
OUT="$(mktemp -t airusb_iousbhost)"

log stream --style compact --level debug \
    --predicate 'subsystem BEGINSWITH "com.apple.iokit.usb"' > "$OUT" 2>&1 &
LOGPID=$!
sleep 2

echo "=== running $BIN ==="
"./$BIN"
echo "exit=$?"

sleep 2
kill "$LOGPID" 2>/dev/null
wait "$LOGPID" 2>/dev/null

echo "=== com.apple.iokit.usb* log during attempt ==="
grep -v "^Filtering the log data" "$OUT" | head -60
rm -f "$OUT"
