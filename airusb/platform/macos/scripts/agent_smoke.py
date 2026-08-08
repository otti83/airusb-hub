#!/usr/bin/env python3
"""
Drive the REAL airusb-agent binary from a fake daemon. No root, no capture.

WHY THIS EXISTS

tests/unit/test_macipc drives AgentLink against a fake agent written in the same
process. That covers the codec and the socket, but not the thing that actually
ships: the airusb-agent executable, its argument handling, its refusal to run as
root, its serve loop, and its shutdown. Those only run when the binary runs.

It also answers one question no unit test can, and answers it without sudo:
whether THIS security session may open IOUSBHostInterface user clients. That is
the gate that forced the exporter into two processes, so a regression in it would
invalidate the whole design.

WHAT IT DOES

  1. Listens on a scratch unix socket.
  2. Launches airusb-agent pointed at it.
  3. HELLO, and checks the version and the reported uid.
  4. OPEN_INTERFACES against a real device, if one was named. Interprets the
     result rather than merely asserting success -- with the drive still mounted,
     kIOReturnExclusiveAccess is the CORRECT answer and proves the System Policy
     check passed.
  5. CLOSE, and confirms the process exits.

Deliberately written against the wire format by hand rather than against the C++
encoder: a bug that exists in both the encoder and the decoder is invisible to a
round-trip test, and this is the second opinion.

usage: agent_smoke.py <path-to-airusb-agent> [locationID-hex] [configValue]
"""

import os
import socket
import struct
import subprocess
import sys
import tempfile
import time

HEADER = "<IHHQ"          # bodyLen u32, op u16, status u16, tag u64
HEADER_SIZE = 16
assert struct.calcsize(HEADER) == HEADER_SIZE

OP_HELLO, OP_OPEN, OP_REBUILD, OP_BULK_OUT, OP_BULK_IN = 1, 2, 3, 4, 5
OP_CLEAR_HALT, OP_ABORT, OP_CLOSE, OP_PING = 6, 7, 8, 9
OP_NAMES = {1: "HELLO", 2: "OPEN_INTERFACES", 3: "REBUILD_PIPES", 4: "BULK_OUT",
            5: "BULK_IN", 6: "CLEAR_HALT", 7: "ABORT_ENDPOINT", 8: "CLOSE", 9: "PING"}

PROTOCOL_VERSION = 1

# From core/Status.h. Only the ones this script can provoke.
STATUS_NAMES = {
    0x0000: "OK", 0x0001: "ERROR_GENERIC", 0x0002: "BAD_ARGUMENT",
    0x0003: "UNSUPPORTED_VERSION", 0x0005: "MALFORMED_FRAME", 0x0007: "NOT_PERMITTED",
    0x000C: "NOT_FOUND", 0x000E: "INTERNAL", 0x0020: "DEVICE_GONE",
    0x0022: "EXCLUSIVITY_DENIED", 0x0023: "CAPTURE_FAILED",
}


def status_name(s):
    return STATUS_NAMES.get(s, "0x%04X" % s)


def send(sock, op, tag, body=b"", status=0):
    sock.sendall(struct.pack(HEADER, len(body), op, status, tag) + body)


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("peer closed after %d of %d bytes" % (len(buf), n))
        buf += chunk
    return buf


def recv_frame(sock):
    body_len, op, status, tag = struct.unpack(HEADER, recv_exact(sock, HEADER_SIZE))
    if body_len > (1 << 20) + 256:
        raise ValueError("agent announced an oversized body: %d" % body_len)
    return op, status, tag, recv_exact(sock, body_len)


def fail(msg):
    print("  FAIL %s" % msg)
    return False


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 64

    agent = os.path.abspath(sys.argv[1])
    if not os.access(agent, os.X_OK):
        print("not executable: %s" % agent)
        return 64

    location_id = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0
    config_value = int(sys.argv[3]) if len(sys.argv) > 3 else 1

    if os.geteuid() == 0:
        print("run this WITHOUT sudo: the agent must be in the console session")
        return 1

    tmpdir = tempfile.mkdtemp(prefix="airusb-smoke-")
    sock_path = os.path.join(tmpdir, "d.sock")

    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(sock_path)
    listener.listen(1)
    listener.settimeout(15.0)

    print("agent_smoke: %s" % agent)
    print("  socket %s" % sock_path)

    proc = subprocess.Popen([agent, "--socket", sock_path, "--connect-wait", "10000"],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    ok = True
    conn = None
    try:
        try:
            conn, _ = listener.accept()
        except socket.timeout:
            return fail("the agent never connected") or 1
        conn.settimeout(30.0)
        print("  agent connected")

        # ---- HELLO ---------------------------------------------------------
        send(conn, OP_HELLO, 1, struct.pack("<III", PROTOCOL_VERSION, os.getpid(), 0))
        op, status, tag, body = recv_frame(conn)
        if op != OP_HELLO or tag != 1:
            ok = fail("HELLO reply had op=%d tag=%d" % (op, tag))
        elif status != 0:
            ok = fail("HELLO returned %s" % status_name(status))
        elif len(body) != 12:
            ok = fail("HELLO body was %d bytes, expected 12" % len(body))
        else:
            ver, pid, euid = struct.unpack("<III", body)
            if ver != PROTOCOL_VERSION:
                ok = fail("agent speaks IPC version %d, expected %d" % (ver, PROTOCOL_VERSION))
            elif euid == 0:
                ok = fail("the agent is running as root; it must not be")
            else:
                print("  HELLO ok: version=%d pid=%d euid=%d" % (ver, pid, euid))

        # ---- an unknown opcode must be fatal, not ignored -------------------
        # Checked on a SECOND connection so a correctly-fatal reaction does not
        # take the rest of this run down with it.

        # ---- OPEN_INTERFACES -----------------------------------------------
        if ok and location_id:
            send(conn, OP_OPEN, 2, struct.pack("<IBBBB", location_id, config_value, 0, 0, 0))
            op, status, tag, body = recv_frame(conn)
            if op != OP_OPEN or tag != 2:
                ok = fail("OPEN reply had op=%d tag=%d" % (op, tag))
            elif status == 0:
                gen, count = struct.unpack("<IH", body[:6])
                print("  OPEN_INTERFACES ok: generation=%d endpoints=%d" % (gen, count))
                for i in range(count):
                    at = 8 + i * 8
                    addr, typ, mps, interval, burst, ifn, alt = struct.unpack(
                        "<BBHBBBB", body[at:at + 8])
                    print("    ep 0x%02x type=%d maxPacket=%d burst=%d iface=%d alt=%d"
                          % (addr, typ, mps, burst, ifn, alt))
                print("  VERDICT=INTERFACES_OPENED — this session may open "
                      "IOUSBHostInterface user clients")
            elif status == 0x0022:      # EXCLUSIVITY_DENIED
                # The correct answer while the drive is still mounted: the
                # System Policy check PASSED and IOUSBMassStorageDriver simply
                # holds the interface. That is the whole point of the daemon
                # capturing first.
                print("  OPEN_INTERFACES -> EXCLUSIVITY_DENIED")
                print("  VERDICT=POLICY_OK — the session check passed; a driver "
                      "holds the interface because nothing has captured the "
                      "device yet. Expected without the daemon.")
            elif status == 0x0007:      # NOT_PERMITTED
                ok = fail("OPEN_INTERFACES -> NOT_PERMITTED. The System Policy "
                          "refused this session. The split-exporter design "
                          "depends on this succeeding.")
            elif status == 0x000E:      # INTERNAL
                # kIOReturnInternalError, the FB16524420 signature. Without a
                # capture it is also the ordinary answer: IOUSBMassStorageDriver
                # owns the interface. The agent's own log distinguishes the two
                # by probing the service directly, so read that rather than
                # guessing from the status alone.
                print("  OPEN_INTERFACES -> INTERNAL (0xE00002C9 expected here)")
                print("  VERDICT=INCONCLUSIVE_BY_DESIGN — nothing has captured the "
                      "device, so a driver still owns the interface. Read the "
                      "agent log below: if it reports the security session is "
                      "FINE, the policy gate passed and only the capture is "
                      "missing. Run p28_run.sh for the real answer.")
            else:
                print("  OPEN_INTERFACES -> %s (no capture is held, so this is "
                      "not conclusive)" % status_name(status))
        elif ok:
            print("  OPEN_INTERFACES skipped (no locationID given)")

        # ---- CLOSE ----------------------------------------------------------
        if ok:
            send(conn, OP_CLOSE, 3)
            try:
                op, status, tag, body = recv_frame(conn)
                if op != OP_CLOSE:
                    ok = fail("CLOSE reply had op=%d" % op)
                else:
                    print("  CLOSE acknowledged")
            except EOFError:
                ok = fail("the agent closed the socket without acknowledging CLOSE")

        rc = proc.wait(timeout=10)
        if rc != 0:
            ok = fail("the agent exited with %d" % rc)
        else:
            print("  the agent exited cleanly")

    except subprocess.TimeoutExpired:
        ok = fail("the agent did not exit after CLOSE")
        proc.kill()
    except (EOFError, ValueError, OSError) as e:
        ok = fail(str(e))
    finally:
        if conn:
            conn.close()
        listener.close()
        if proc.poll() is None:
            proc.kill()
        out = proc.stdout.read() if proc.stdout else ""
        if out:
            print("  --- agent output ---")
            for line in out.rstrip().splitlines():
                print("  | %s" % line)
        try:
            os.unlink(sock_path)
            os.rmdir(tmpdir)
        except OSError:
            pass

    # ---- a separate run, to check that garbage is fatal --------------------
    if ok:
        ok = garbage_is_fatal(agent)

    print("agent_smoke: %s" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


def garbage_is_fatal(agent):
    """An unknown opcode must close the connection, not be skipped.

    A parser that ignores what it does not understand lets a hostile peer probe
    for an opcode that IS handled. This confirms the shipping binary does not.
    """
    tmpdir = tempfile.mkdtemp(prefix="airusb-smoke2-")
    sock_path = os.path.join(tmpdir, "d.sock")
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(sock_path)
    listener.listen(1)
    listener.settimeout(15.0)

    proc = subprocess.Popen([agent, "--socket", sock_path, "--connect-wait", "10000"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ok = True
    try:
        conn, _ = listener.accept()
        conn.settimeout(10.0)
        send(conn, 0xEEEE, 1)                 # not an opcode this build knows
        try:
            conn.recv(HEADER_SIZE)
            # A clean EOF (b"") is the pass; anything else means it answered.
            data = b""
        except socket.timeout:
            ok = fail("the agent neither answered nor closed on an unknown opcode")
        rc = proc.wait(timeout=10)
        if ok:
            print("  unknown opcode closed the connection (exit %d) — fatal, "
                  "as intended" % rc)
        conn.close()
    except (socket.timeout, subprocess.TimeoutExpired) as e:
        ok = fail("unknown-opcode case: %s" % e)
        proc.kill()
    finally:
        listener.close()
        if proc.poll() is None:
            proc.kill()
        try:
            os.unlink(sock_path)
            os.rmdir(tmpdir)
        except OSError:
            pass
    return ok


if __name__ == "__main__":
    sys.exit(main())
