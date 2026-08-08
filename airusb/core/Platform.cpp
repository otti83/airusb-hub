#include "Platform.h"

#include <cstdio>
#include <cstring>

#if defined(_WIN32)
  #include <io.h>
  #include <windows.h>
#else
  #include <cerrno>
  #include <fcntl.h>
  #include <sys/stat.h>
  #include <time.h>
#endif

namespace airusb::platform {

// ---------------------------------------------------------------------------
// sockets
// ---------------------------------------------------------------------------

#if defined(_WIN32)

bool ensureNetworkReady() noexcept
{
    // Refcounted by Winsock, and guarded so the common case is a single atomic
    // read rather than a repeated WSAStartup.
    static bool started = [] {
        WSADATA d;
        return ::WSAStartup(MAKEWORD(2, 2), &d) == 0;
    }();
    return started;
}

#else

int lastSocketError() noexcept { return errno; }

bool wouldBlock(int e) noexcept
{
    return e == EAGAIN || e == EWOULDBLOCK || e == EINPROGRESS;
}

bool connectionLost(int e) noexcept
{
    return e == ECONNRESET || e == EPIPE || e == ENOTCONN || e == ECONNABORTED;
}

bool setNonBlocking(SocketHandle s) noexcept
{
    const int flags = ::fcntl(s, F_GETFL, 0);
    if (flags < 0) return false;
    return ::fcntl(s, F_SETFL, flags | O_NONBLOCK) == 0;
}

#endif

// ---------------------------------------------------------------------------
// sleep
// ---------------------------------------------------------------------------

void sleepMs(unsigned ms) noexcept
{
#if defined(_WIN32)
    ::Sleep(ms);
#else
    struct timespec ts;
    ts.tv_sec  = static_cast<time_t>(ms / 1000u);
    ts.tv_nsec = static_cast<long>((ms % 1000u) * 1000000ul);
    (void)::nanosleep(&ts, nullptr);
#endif
}

// ---------------------------------------------------------------------------
// files
// ---------------------------------------------------------------------------

bool writeFileAtomically(const std::string& path, const std::string& data,
                         bool privateToOwner) noexcept
{
    const std::string tmp = path + ".tmp";

    FILE* f = std::fopen(tmp.c_str(), "wb");
    if (!f) return false;

    if (!data.empty() &&
        std::fwrite(data.data(), 1, data.size(), f) != data.size()) {
        std::fclose(f);
        std::remove(tmp.c_str());
        return false;
    }
    if (std::fflush(f) != 0) {
        std::fclose(f);
        std::remove(tmp.c_str());
        return false;
    }

    // Flush the OS buffers too, not just the stdio ones. fflush alone leaves the
    // data in the page cache, which a crash discards while keeping the rename.
#if defined(_WIN32)
    const HANDLE h = reinterpret_cast<HANDLE>(_get_osfhandle(_fileno(f)));
    if (h != INVALID_HANDLE_VALUE) ::FlushFileBuffers(h);
#else
    (void)::fsync(::fileno(f));
#endif
    std::fclose(f);

#if !defined(_WIN32)
    if (privateToOwner) (void)::chmod(tmp.c_str(), 0600);
#else
    (void)privateToOwner;   // Windows inherits the directory ACL
#endif

#if defined(_WIN32)
    // rename() refuses to overwrite on Windows; MoveFileEx with
    // MOVEFILE_REPLACE_EXISTING is the atomic replace.
    if (!::MoveFileExA(tmp.c_str(), path.c_str(),
                       MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        std::remove(tmp.c_str());
        return false;
    }
#else
    if (std::rename(tmp.c_str(), path.c_str()) != 0) {
        std::remove(tmp.c_str());
        return false;
    }
#endif
    return true;
}

bool readWholeFile(const std::string& path, std::string& out,
                   std::size_t maxBytes) noexcept
{
    out.clear();
    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return false;

    char buf[4096];
    for (;;) {
        const std::size_t n = std::fread(buf, 1, sizeof buf, f);
        if (n == 0) break;
        // Bounded so a file that is not what we expect cannot be read into
        // memory unbounded.
        if (out.size() + n > maxBytes) { std::fclose(f); out.clear(); return false; }
        out.append(buf, n);
    }
    std::fclose(f);
    return true;
}

} // namespace airusb::platform
