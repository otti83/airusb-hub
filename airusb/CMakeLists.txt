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

add_library(airusb_transport STATIC
    transport/RecordLayer.cpp
    transport/FrameScheduler.cpp
    transport/TcpTransport.cpp
    transport/FaultTransport.cpp
)
target_include_directories(airusb_transport PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(airusb_transport PUBLIC airusb_protocol)
target_include_directories(airusb_protocol PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# ---------------------------------------------------------------------------
# diag/  — test instruments. Portable, and deliberately NOT on the data path:
# nothing in core/, protocol/ or transport/ may include it. BotProbe understands
# SCSI so that P2.8 has an instrument it can trust; AirUSB itself does not.
# ---------------------------------------------------------------------------
add_library(airusb_diag STATIC
    diag/BotProbe.cpp
)
target_link_libraries(airusb_diag PUBLIC airusb_protocol)

# ---------------------------------------------------------------------------
# platform/macos IPC — the daemon<->agent codec and socket transport.
#
# Built on EVERY platform, not just macOS, and with no IOKit dependency. It is a
# parser between a root process and an unprivileged one, so it is unit-tested and
# fuzzed in CI rather than only on the machine that has the drive plugged in.
# ---------------------------------------------------------------------------
add_library(airusb_macos_ipc STATIC
    platform/macos/AgentProtocol.cpp
    platform/macos/AgentLink.cpp
)
target_link_libraries(airusb_macos_ipc PUBLIC airusb_protocol)

# The whole point of this layer is portability. Guard it: nothing here may pull in
# an OS USB header. Enforced by tests/unit/test_layering.cpp as well.
target_compile_definitions(airusb_protocol PRIVATE AIRUSB_PORTABLE_CORE=1)

# ---------------------------------------------------------------------------
# platform/macos — the real exporter. Objective-C++, IOKit, DiskArbitration.
#
# Two executables, because P1_CAPTURE_VERIFICATION.md measured that no single
# process can do both halves: DeviceCapture and whole-disk unmount need root,
# and opening an IOUSBHostInterface needs console-session membership, and no
# shippable process is both.
# ---------------------------------------------------------------------------
if(APPLE)
    enable_language(OBJCXX)
    set(CMAKE_OBJCXX_STANDARD 20)
    set(CMAKE_OBJCXX_STANDARD_REQUIRED ON)

    add_library(airusb_macos STATIC
        platform/macos/StatusMapMacos.cpp
        platform/macos/MacUsbCommon.mm
        platform/macos/DiskGuard.mm
        platform/macos/AgentUsbIo.mm
        platform/macos/HostDeviceExporter.mm
    )
    target_link_libraries(airusb_macos PUBLIC airusb_macos_ipc airusb_diag)

    # ARC for the Objective-C half. The C++ half is unaffected.
    target_compile_options(airusb_macos PRIVATE
        $<$<COMPILE_LANGUAGE:OBJCXX>:-fobjc-arc>
        # -Wpedantic flags #import as a language extension. It is THE idiomatic
        # include directive in Objective-C and every Apple header uses it, so the
        # single warning is silenced rather than the whole pedantic set.
        $<$<COMPILE_LANGUAGE:OBJCXX>:-Wno-import-preprocessor-directive-pedantic>
    )

    target_link_libraries(airusb_macos PUBLIC
        "-framework Foundation"
        "-framework IOKit"
        "-framework IOUSBHost"
        "-framework DiskArbitration"
        "-framework CoreFoundation"
    )

    add_executable(airusb-exportd platform/macos/airusb_exportd_main.mm)
    target_link_libraries(airusb-exportd PRIVATE airusb_macos)
    target_compile_options(airusb-exportd PRIVATE
        $<$<COMPILE_LANGUAGE:OBJCXX>:-fobjc-arc>
        $<$<COMPILE_LANGUAGE:OBJCXX>:-Wno-import-preprocessor-directive-pedantic>
    )

    add_executable(airusb-agent platform/macos/airusb_agent_main.mm)
    target_link_libraries(airusb-agent PRIVATE airusb_macos)
    target_compile_options(airusb-agent PRIVATE
        $<$<COMPILE_LANGUAGE:OBJCXX>:-fobjc-arc>
        $<$<COMPILE_LANGUAGE:OBJCXX>:-Wno-import-preprocessor-directive-pedantic>
    )
endif()

# ---------------------------------------------------------------------------
# tests
# ---------------------------------------------------------------------------
enable_testing()
add_subdirectory(tests)
