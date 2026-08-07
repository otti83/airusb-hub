// Minimal assertion harness. Deliberately dependency-free: an OSS project that
// needs a package manager to run its own unit tests loses contributors.

#ifndef AIRUSB_TESTS_HARNESS_H
#define AIRUSB_TESTS_HARNESS_H

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace airusb::test {

inline int g_failures = 0;
inline int g_checks   = 0;
inline const char* g_currentCase = "";

inline void beginCase(const char* name)
{
    g_currentCase = name;
    std::printf("  %-52s", name);
    std::fflush(stdout);
}

inline void endCase()
{
    std::printf("\n");
}

inline void reportFailure(const char* file, int line, const std::string& what)
{
    ++g_failures;
    std::printf("\n    FAIL %s:%d\n      %s\n", file, line, what.c_str());
}

inline std::string hex(const std::vector<unsigned char>& v, std::size_t limit = 64)
{
    static const char* d = "0123456789abcdef";
    std::string s;
    for (std::size_t i = 0; i < v.size() && i < limit; ++i) {
        s += d[v[i] >> 4];
        s += d[v[i] & 0xF];
    }
    if (v.size() > limit) s += "...";
    return s;
}

} // namespace airusb::test

#define CHECK(cond)                                                                  \
    do {                                                                             \
        ++::airusb::test::g_checks;                                                  \
        if (!(cond)) {                                                               \
            ::airusb::test::reportFailure(__FILE__, __LINE__, "CHECK(" #cond ")");    \
        } else {                                                                     \
            std::printf(".");                                                        \
        }                                                                            \
    } while (0)

#define CHECK_EQ(a, b)                                                               \
    do {                                                                             \
        ++::airusb::test::g_checks;                                                  \
        auto _a = (a);                                                               \
        auto _b = (b);                                                               \
        if (!(_a == _b)) {                                                           \
            ::airusb::test::reportFailure(                                           \
                __FILE__, __LINE__,                                                  \
                std::string(#a " == " #b "  (got ")                                  \
                    + std::to_string(static_cast<long long>(_a)) + ", want "         \
                    + std::to_string(static_cast<long long>(_b)) + ")");             \
        } else {                                                                     \
            std::printf(".");                                                        \
        }                                                                            \
    } while (0)

#define TEST_CASE(name)                                                              \
    for (bool _once = (::airusb::test::beginCase(name), true); _once;                \
         _once = (::airusb::test::endCase(), false))

#define TEST_MAIN_END()                                                              \
    do {                                                                             \
        std::printf("\n%d checks, %d failures\n",                                    \
                    ::airusb::test::g_checks, ::airusb::test::g_failures);           \
        return ::airusb::test::g_failures == 0 ? 0 : 1;                              \
    } while (0)

#endif // AIRUSB_TESTS_HARNESS_H
