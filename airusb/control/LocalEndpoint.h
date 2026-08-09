// AirUSB Hub — the local socket between the window and the privileged broker,
// and the only place this project asks the kernel who is on the other end.
//
// WHY NOT LOOPBACK TCP, WHICH IS WHAT THE WINDOW ALREADY USES
//
// Because a TCP socket carries no identity. `airusb-hubd` guards its HTTP API
// with a bearer token in a 0600 file, which is a real control and is the right
// one for a BROWSER — a browser cannot speak anything else. But the broker is
// not talking to a browser. It is talking to a program, over a channel where
// the kernel already knows the answer, and asking the kernel is strictly better
// than trusting a secret that has to be written to disk to be shared.
//
// So: `AF_UNIX` with `getpeereid(2)` on POSIX, a named pipe with the client's
// token on Windows. Both give a uid the peer cannot lie about, because the
// peer never says it.
//
// WHAT THIS ESTABLISHES, AND WHAT IT DOES NOT
//
// It establishes WHICH USER is connected. It does NOT establish which PROGRAM,
// and on a POSIX system it cannot: a user can run any binary they like and can
// attach a debugger to their own processes. So another program of the same user
// can drive the broker.
//
// That is written here rather than left to be discovered because the honest
// consequence matters: the broker's authority is bounded to what the logged-in
// person could already do at the keyboard. It can pair with a machine whose six
// digits it can also see, and it can hand that person's own devices around.
// What it CANNOT do is exceed the user — the broker never returns a key, never
// forwards a raw protocol record, and never takes an instruction to pin a peer
// that it did not itself put a question about (see BrokerProtocol.h).
//
// Closing the same-user gap needs platform machinery this file deliberately
// does not pretend to have: XPC audit tokens plus a code requirement on macOS,
// polkit on Linux, an Authenticode publisher check on Windows. Those are real
// answers and they are the next step; a `strcmp` on /proc/pid/exe is not one,
// and shipping it would make the boundary look stronger than it is.

#ifndef AIRUSB_CONTROL_LOCALENDPOINT_H
#define AIRUSB_CONTROL_LOCALENDPOINT_H

#include "../core/Status.h"
#include "../transport/IAirUsbTransport.h"

#include <cstdint>
#include <memory>
#include <string>

namespace airusb::control {

/// What the KERNEL says about the peer. Never what the peer says about itself.
struct PeerCredentials {
    std::uint32_t uid = 0xFFFFFFFFu;
    std::uint32_t pid = 0;
    bool          known = false;
};

/// A listening local endpoint: a unix socket path, or a named pipe name.
class LocalListener {
public:
    LocalListener() = default;
    ~LocalListener();

    LocalListener(const LocalListener&)            = delete;
    LocalListener& operator=(const LocalListener&) = delete;

    /// Creates the endpoint. `path` is a filesystem path on POSIX and a pipe
    /// name on Windows.
    ///
    /// On POSIX the socket is created 0600 and then relaxed to `mode`, so there
    /// is never a window in which it is more permissive than intended — the
    /// same rule `AgentLink::listenOnUnixSocket` already follows, for the same
    /// reason.
    Status open(const std::string& path, unsigned mode, std::string* why);

    /// Accepts one connection if there is one waiting. NEVER blocks.
    ///
    /// `credsOut` is filled from the kernel's record. A connection whose
    /// credentials cannot be determined is REFUSED and closed rather than
    /// accepted with `known == false`: an unknown peer on a privileged channel
    /// is the case to fail closed on.
    std::unique_ptr<transport::IByteStream> accept(PeerCredentials* credsOut);

    bool isOpen() const noexcept;
    void close();

    const std::string& path() const noexcept { return _path; }

private:
    std::string _path;
    /// A raw handle: an int fd on POSIX, a HANDLE-as-uintptr on Windows.
    std::uintptr_t _handle = static_cast<std::uintptr_t>(-1);
    bool _bound = false;
};

/// Connects to a broker's local endpoint. Blocks only for the connect itself.
std::unique_ptr<transport::IByteStream> connectLocal(const std::string& path,
                                                     Status* st, std::string* why);

/// Where the broker listens by default, per platform. A function rather than a
/// constant because it consults the environment: a test, and a developer with
/// two checkouts, both need a second broker that is not the machine's.
std::string defaultBrokerPath();

} // namespace airusb::control

#endif // AIRUSB_CONTROL_LOCALENDPOINT_H
