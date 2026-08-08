// AirUSB Hub — the few places three operating systems genuinely differ.
//
// Deliberately small. Everything above this file is written once and compiled
// everywhere; this is the list of things that could not be, and the list is
// meant to stay short enough to read in one go:
//
//   * socket handles are a signed int on POSIX and an unsigned UINT_PTR on
//     Windows, so a shared `SocketHandle` is needed rather than `int`
//   * the last socket error lives in errno or in WSAGetLastError()
//   * sleeping for a few milliseconds
//   * replacing a file atomically
//
// Cryptographic randomness is deliberately NOT here — it lives in crypto/, next
// to the code that depends on it being right, rather than in a grab-bag header
// where it looks like just another portability detail.

#ifndef AIRUSB_CORE_PLATFORM_H
#define AIRUSB_CORE_PLATFORM_H

#include <cstddef>
#include <cstdint>
#include <string>

#if defined(_WIN32)
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #ifndef NOMINMAX
    #define NOMINMAX
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #include <arpa/inet.h>
  #include <netdb.h>
  #include <netinet/in.h>
  #include <netinet/tcp.h>
  #include <sys/socket.h>
  #include <unistd.h>
#endif

namespace airusb::platform {

#if defined(_WIN32)

using SocketHandle = SOCKET;
inline constexpr SocketHandle kInvalidSocket = INVALID_SOCKET;

inline bool isValid(SocketHandle s) noexcept { return s != INVALID_SOCKET; }
inline void closeSocket(SocketHandle s) noexcept { if (isValid(s)) ::closesocket(s); }
inline int  lastSocketError() noexcept { return ::WSAGetLastError(); }

inline bool wouldBlock(int e) noexcept
{
    return e == WSAEWOULDBLOCK || e == WSAEINPROGRESS;
}
inline bool connectionLost(int e) noexcept
{
    return e == WSAECONNRESET || e == WSAECONNABORTED || e == WSAENETRESET
        || e == WSAESHUTDOWN || e == WSAENOTCONN;
}

inline bool setNonBlocking(SocketHandle s) noexcept
{
    u_long on = 1;
    // FIONBIO is defined as an unsigned long (0x8004667E) but ioctlsocket takes a
    // signed long, so the canonical MSDN call is a sign-changing conversion. The
    // bit pattern is what the API matches on and it is preserved; the cast just
    // stops -Wsign-conversion reporting the value change as news.
    return ::ioctlsocket(s, static_cast<long>(FIONBIO), &on) == 0;
}

/// Winsock needs initialising once per process, and is refcounted, so calling
/// this from several places is safe. Doing it lazily here means no caller has to
/// remember — a forgotten WSAStartup fails as "socket() returned an error" and
/// sends people looking in the wrong place.
bool ensureNetworkReady() noexcept;

#else

using SocketHandle = int;
inline constexpr SocketHandle kInvalidSocket = -1;

inline bool isValid(SocketHandle s) noexcept { return s >= 0; }
inline void closeSocket(SocketHandle s) noexcept { if (isValid(s)) ::close(s); }
int  lastSocketError() noexcept;
bool wouldBlock(int e) noexcept;
bool connectionLost(int e) noexcept;
bool setNonBlocking(SocketHandle s) noexcept;
inline bool ensureNetworkReady() noexcept { return true; }

#endif

/// The length argument send()/recv() take: `int` on Winsock, `size_t` on POSIX.
/// Passing the wrong one is a sign-conversion warning on one platform and a
/// truncation on the other, so the conversion happens here once.
#if defined(_WIN32)
using IoLength = int;
#else
using IoLength = std::size_t;
#endif

/// Clamps to what the platform's socket call can express. On Winsock that is
/// INT_MAX; a partial write is already the normal case on a non-blocking socket,
/// so clamping is a short write rather than an error.
inline IoLength ioLength(std::size_t n) noexcept
{
#if defined(_WIN32)
    constexpr std::size_t kMax = 0x7FFFFFFFu;
    return static_cast<IoLength>(n > kMax ? kMax : n);
#else
    return n;
#endif
}

/// Milliseconds. Used only to pace polling loops; nothing correctness-bearing
/// depends on its precision.
void sleepMs(unsigned ms) noexcept;

/// Makes a Windows console read this process's output as UTF-8, and puts the code
/// page back afterwards. A no-op everywhere else.
///
/// `/utf-8` only settles what the COMPILER does with the em dashes and
/// typographic quotes in user-facing literals; the bytes reaching stdout are
/// UTF-8 either way. It is the console that misreads them: a Japanese console
/// runs CP932, takes the em dash's `E2 80 94` for two Shift-JIS characters, and
/// prints `窶・` — observed on real hardware, in the middle of
///
///     peer is not paired — pinning it because this is a test tool. SAS would be 927920
///
/// which is precisely the line a person is asked to read the SAS off before
/// trusting a peer. Garbling the sentence that explains a security decision is
/// not a cosmetic problem.
///
/// Restores on destruction because the code page belongs to the console, which
/// outlives this process, and leaving it changed would affect whatever the user
/// runs next in the same window. Redirected output is unaffected either way: a
/// pipe or a file receives the same UTF-8 bytes regardless of the console's code
/// page, which is why CI never saw this.
class ConsoleUtf8 {
public:
    ConsoleUtf8() noexcept;
    ~ConsoleUtf8();
    ConsoleUtf8(const ConsoleUtf8&)            = delete;
    ConsoleUtf8& operator=(const ConsoleUtf8&) = delete;

private:
#if defined(_WIN32)
    unsigned _previous = 0;   ///< 0 means "nothing to restore"
#endif
};

/// Writes `data` to `path` via a temporary file, flushes it to disk, and renames
/// it over the target.
///
/// The flush before the rename is the part that matters: without it a crash can
/// leave the rename durable and the contents not, which for the pin store means
/// every peer silently unpaired and the user re-prompted as if nothing happened.
bool writeFileAtomically(const std::string& path,
                         const std::string& data,
                         bool privateToOwner) noexcept;

/// Reads a whole file. Returns false if it does not exist, which callers treat
/// as a first run rather than an error.
bool readWholeFile(const std::string& path, std::string& out,
                   std::size_t maxBytes) noexcept;

} // namespace airusb::platform

#endif // AIRUSB_CORE_PLATFORM_H
