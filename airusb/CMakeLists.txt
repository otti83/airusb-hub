cmake_minimum_required(VERSION 3.20)
project(airusb CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

add_compile_options(
    -Wall -Wextra -Wpedantic
    -Wconversion -Wsign-conversion
    -Wshadow
    -Wno-unused-parameter
)

# ---------------------------------------------------------------------------
# protocol/ + core/  — platform-independent. No OS USB API, no sockets.
# ---------------------------------------------------------------------------
add_library(airusb_protocol STATIC
    protocol/Codec.cpp
    protocol/Validate.cpp
    core/Status.cpp
    core/UsbTypes.cpp
    core/Watchdog.cpp
    core/DeviceManifest.cpp
    core/Ep0Arbiter.cpp
    core/RequestTable.cpp
    core/CreditController.cpp
)
target_include_directories(airusb_protocol PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# The whole point of this layer is portability. Guard it: nothing here may pull in
# an OS USB header. Enforced by tests/unit/test_layering.cpp as well.
target_compile_definitions(airusb_protocol PRIVATE AIRUSB_PORTABLE_CORE=1)

# ---------------------------------------------------------------------------
# tests
# ---------------------------------------------------------------------------
enable_testing()
add_subdirectory(tests)
