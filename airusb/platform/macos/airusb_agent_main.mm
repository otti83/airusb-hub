// airusb-agent — the console-session half of the macOS exporter.
//
// Unprivileged by design and by necessity. It opens IOUSBHostInterface user
// clients, which a root LaunchDaemon measurably cannot do, and it moves bulk and
// interrupt data. It never unmounts, never claims a disk, and never captures a
// device: the daemon remains the single source of exclusivity truth.
//
// Lifecycle: connect to the daemon's socket (retrying, because the two are
// started independently), then serve requests until the socket closes. Daemon
// death is EOF, which exits — and the daemon's own death releases the capture, so
// the drive comes back to this Mac either way.

#include "AgentLink.h"
#include "AgentProtocol.h"
#include "AgentUsbIo.h"
#include "MacUsbCommon.h"
#include "../../core/Status.h"

#import <Foundation/Foundation.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unistd.h>

using namespace airusb;
using namespace airusb::macos;

namespace {

void usage(const char* argv0)
{
    std::fprintf(stderr,
        "usage: %s [--socket PATH] [--connect-wait MS]\n"
        "\n"
        "  The console-session half of the AirUSB exporter. Run it as the logged-in\n"
        "  user, NOT with sudo: a root process is in the system security session and\n"
        "  the kernel refuses it access to IOUSBHostInterface.\n", argv0);
}

/// Answers one request. Returns false when the loop should end.
bool serve(ipc::AgentLink& link, AgentUsbIo& io, const ipc::Frame& req)
{
    ipc::Frame rep;
    rep.op     = req.op;
    rep.tag    = req.tag;
    rep.status = Status::Ok;

    switch (req.op) {
        case ipc::Op::Ping:
            break;

        case ipc::Op::Hello: {
            ipc::HelloBody theirs;
            if (!ipc::decodeHello(req.body, theirs)) {
                rep.status = Status::MalformedFrame;
                break;
            }
            if (theirs.protocolVersion != ipc::kProtocolVersion) {
                logLine("ERROR", @"daemon speaks IPC version %u, this agent speaks %u",
                        theirs.protocolVersion, ipc::kProtocolVersion);
                rep.status = Status::UnsupportedVersion;
            }
            ipc::HelloBody mine;
            mine.protocolVersion = ipc::kProtocolVersion;
            mine.pid  = static_cast<std::uint32_t>(::getpid());
            mine.euid = static_cast<std::uint32_t>(::geteuid());
            ipc::encodeHello(mine, rep.body);
            logLine("ATTACH", @"handshake with daemon pid=%u euid=%u",
                    theirs.pid, theirs.euid);
            break;
        }

        case ipc::Op::OpenInterfaces: {
            ipc::OpenBody ob;
            if (!ipc::decodeOpen(req.body, ob)) { rep.status = Status::MalformedFrame; break; }

            ipc::PipeTable table;
            std::string why;
            rep.status = io.openInterfaces(ob.locationId, ob.configValue, table, &why);
            if (rep.status == Status::Ok) ipc::encodePipeTable(table, rep.body);
            else logLine("ERROR", @"OPEN_INTERFACES failed: %s (%s)",
                         statusName(rep.status), why.c_str());
            break;
        }

        case ipc::Op::RebuildPipes: {
            ipc::PipeTable table;
            std::string why;
            rep.status = io.rebuildPipeTable(table, &why);
            if (rep.status == Status::Ok) ipc::encodePipeTable(table, rep.body);
            else logLine("ERROR", @"REBUILD_PIPES failed: %s (%s)",
                         statusName(rep.status), why.c_str());
            break;
        }

        case ipc::Op::BulkOut: {
            ipc::XferReq r;
            std::span<const std::uint8_t> payload;
            if (!ipc::decodeXferReq(req.body, ipc::XferPayload::Present, r, payload)) {
                rep.status = Status::MalformedFrame;
                break;
            }
            // The bytes actually present are the transfer, never the length
            // field. The decoder has already proved the two agree.
            std::uint32_t moved = 0;
            rep.status = io.bulkOut(r.generation, r.epAddr, payload, r.timeoutMs, &moved);
            ipc::encodeActualLen(moved, rep.body);
            break;
        }

        case ipc::Op::BulkIn: {
            ipc::XferReq r;
            std::span<const std::uint8_t> payload;
            if (!ipc::decodeXferReq(req.body, ipc::XferPayload::None, r, payload)) {
                rep.status = Status::MalformedFrame;
                break;
            }
            std::vector<std::uint8_t> data;
            rep.status = io.bulkIn(r.generation, r.epAddr, r.length, r.timeoutMs, data);
            if (data.size() > r.length) {
                // Cannot happen through AgentUsbIo, which already refuses it.
                // Checked again because this is the byte count the daemon will
                // use to size its own buffers.
                logLine("ERROR", @"internal: %zu bytes for a %u byte request",
                        data.size(), r.length);
                rep.status = Status::XferOverrun;
                data.clear();
            }
            rep.body = std::move(data);
            break;
        }

        case ipc::Op::ClearHalt: {
            ipc::EpRef e;
            if (!ipc::decodeEpRef(req.body, e)) { rep.status = Status::MalformedFrame; break; }
            rep.status = io.clearHalt(e.generation, e.epAddr);
            break;
        }

        case ipc::Op::AbortEndpoint: {
            ipc::EpRef e;
            if (!ipc::decodeEpRef(req.body, e)) { rep.status = Status::MalformedFrame; break; }
            rep.status = io.abortEndpoint(e.generation, e.epAddr);
            break;
        }

        case ipc::Op::Close:
            logLine("DETACH", @"CLOSE — releasing pipes and interfaces");
            io.closeAll();
            (void)link.send(rep);
            return false;
    }

    if (link.send(rep) != Status::Ok) {
        logLine("ERROR", @"could not reply to %@ — the daemon is gone",
                @(ipc::opName(req.op)));
        return false;
    }
    return true;
}

} // namespace

int main(int argc, const char* argv[])
{
    @autoreleasepool {
        setLogPrefix("agent");
        ipc::ignoreSigpipe();

        std::string socketPath = "/var/run/airusb-exportd.sock";
        std::uint32_t connectWaitMs = 60000;

        for (int i = 1; i < argc; ++i) {
            const std::string a = argv[i];
            if (a == "--socket" && i + 1 < argc)            socketPath = argv[++i];
            else if (a == "--connect-wait" && i + 1 < argc) connectWaitMs = static_cast<std::uint32_t>(std::atoi(argv[++i]));
            else { usage(argv[0]); return 64; }
        }

        if (::geteuid() == 0) {
            // Not a style preference. A root process is in the system security
            // session, and the kernel's System Policy refuses it
            // iokit-open-service on IOUSBHostInterface. Running this half as root
            // is precisely the configuration that does not work.
            logLine("ERROR", @"refusing to run as root — this half must run in the "
                              "console session as the logged-in user. Run it without sudo.");
            return 77;
        }

        logLine("ATTACH", @"airusb-agent starting: pid=%d euid=%d ppid=%d %s",
                ::getpid(), ::geteuid(), ::getppid(),
                ::getppid() == 1 ? "(launchd)" : (isatty(STDIN_FILENO) ? "(tty)" : "(no tty)"));

        Status st = Status::Ok;
        const int fd = ipc::connectUnixSocket(socketPath, connectWaitMs, st);
        if (fd < 0) {
            logLine("ERROR", @"could not connect to %s within %u ms: %s",
                    socketPath.c_str(), connectWaitMs, statusName(st));
            return 69;
        }
        logLine("ATTACH", @"connected to %s", socketPath.c_str());

        ipc::AgentLink link(fd);
        AgentUsbIo io;

        for (;;) {
            ipc::Frame req;
            // No deadline: the daemon may legitimately be idle for the whole
            // lease. Its death arrives as EOF, not as a timeout.
            const Status r = link.receive(req, 0);
            if (r == Status::TransportLost) {
                logLine("DETACH", @"the daemon closed the socket — exiting; it will "
                                   "release the capture and the drive comes back here");
                break;
            }
            if (r == Status::MalformedFrame) {
                logLine("ERROR", @"malformed frame from the daemon — closing, there "
                                  "is no resynchronisation path");
                break;
            }
            if (r != Status::Ok) continue;

            if (!serve(link, io, req)) break;
        }

        io.closeAll();
        logLine("DETACH", @"airusb-agent exiting");
        return 0;
    }
}
