cmake_minimum_required(VERSION 3.20)
project(airusb C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

if(MSVC)
    # /W4 is MSVC's equivalent of -Wall -Wextra. The specific disables are the
    # ones that fire on correct, portable C++ rather than on anything worth
    # fixing: 4100 unreferenced parameter, 4267/4244 the size_t/int narrowing
    # that the platform shim already handles at the socket boundary.
    # /utf-8 is not cosmetic. The sources contain non-ASCII characters inside
    # string literals — em dashes and typographic quotes in user-facing text —
    # and without it MSVC reads them in the active code page and mangles them.
    add_compile_options(/W4 /wd4100 /wd4267 /wd4244 /permissive- /Zc:__cplusplus /utf-8)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN)
else()
    add_compile_options(
        -Wall -Wextra -Wpedantic
        -Wconversion -Wsign-conversion
        -Wshadow
        -Wno-unused-parameter
    )
endif()

# ---------------------------------------------------------------------------
# The layer graph. Each library depends only on the ones above it:
#
#   core        values and policy. No OS, no sockets, no crypto.
#   crypto      vendored primitives, identity, SAS.          -> core
#   protocol    wire format, validation, Noise handshake.    -> core, crypto
#   transport   framing, scheduling, record cipher.          -> protocol
#   session     preamble, trust gate, pin store.             -> transport
#
# core and protocol used to be one library, which made crypto depend on protocol
# and protocol unable to call crypto — so the manifest hash had nowhere to live.
# Splitting them is what makes the arrows point one way.
# ---------------------------------------------------------------------------
add_library(airusb_core STATIC
    core/Status.cpp
    core/UsbTypes.cpp
    core/Watchdog.cpp
    core/DeviceManifest.cpp
    core/Ep0Arbiter.cpp
    core/RequestTable.cpp
    core/CreditController.cpp
    core/Platform.cpp
)
target_include_directories(airusb_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
if(WIN32)
    # Winsock 2. ws2_32 is the sockets themselves; the platform shim calls
    # WSAStartup lazily so no caller has to remember.
    target_link_libraries(airusb_core PUBLIC ws2_32)
endif()

# ---------------------------------------------------------------------------
# third_party/ — vendored crypto. NOT our code; see third_party/PROVENANCE.md.
#
# Compiled with warnings OFF, deliberately. The alternative is editing upstream
# source to silence them, which makes the next diff against upstream unreadable
# and is exactly how a vendored library quietly forks. Correctness here is
# established by the standards' own test vectors (tests/unit/test_crypto.cpp),
# not by our warning flags.
# ---------------------------------------------------------------------------
add_library(airusb_thirdparty STATIC
    third_party/monocypher/monocypher.c
    third_party/monocypher/monocypher-ed25519.c
    third_party/blake2s/blake2s-ref.c
)
set_target_properties(airusb_thirdparty PROPERTIES C_STANDARD 99 C_STANDARD_REQUIRED ON)
if(MSVC)
    target_compile_options(airusb_thirdparty PRIVATE /W0)
else()
    target_compile_options(airusb_thirdparty PRIVATE -w)
endif()

# ---------------------------------------------------------------------------
# crypto/ + the Noise handshake — the security layer.
#
# crypto/ is the ONLY place third_party is called from, and third_party is linked
# PRIVATE so that nothing above this line can reach a raw primitive by accident.
#
# Noise lives here rather than in airusb_protocol because it depends on crypto/
# and airusb_protocol does not: putting it there would make the two libraries
# mutually dependent, which is a sign the layering is wrong rather than a build
# quirk to work around.
# ---------------------------------------------------------------------------
add_library(airusb_crypto STATIC
    crypto/Primitives.cpp
    crypto/Identity.cpp
)
target_link_libraries(airusb_crypto PUBLIC airusb_core PRIVATE airusb_thirdparty)
if(WIN32)
    # BCryptGenRandom, the CSPRNG randomBytes() uses on Windows.
    target_link_libraries(airusb_crypto PRIVATE bcrypt)
endif()

# ---------------------------------------------------------------------------
# protocol/ — the wire format, and the handshake that protects it.
# ---------------------------------------------------------------------------
add_library(airusb_protocol STATIC
    protocol/Codec.cpp
    protocol/Validate.cpp
    protocol/ManifestCodec.cpp
    protocol/Messages.cpp
    protocol/Noise.cpp
    protocol/Segmentation.cpp
)
target_link_libraries(airusb_protocol PUBLIC airusb_core airusb_crypto)

# ---------------------------------------------------------------------------
# transport/ — framing and the record cipher.
# ---------------------------------------------------------------------------
add_library(airusb_transport STATIC
    transport/RecordLayer.cpp
    transport/FrameScheduler.cpp
    transport/TcpTransport.cpp
    transport/FaultTransport.cpp
    transport/NoiseCipher.cpp
)
target_link_libraries(airusb_transport PUBLIC airusb_protocol)

# ---------------------------------------------------------------------------
# session/ — preamble, handshake drive, trust gate, pin store.
# ---------------------------------------------------------------------------
add_library(airusb_session STATIC
    session/PairingGate.cpp
    session/PeerStore.cpp
    session/SecureSession.cpp
    session/ExporterSession.cpp
    session/RemoteDevicePort.cpp
    session/ImporterDataPlane.cpp
    session/ImporterClient.cpp
)
target_link_libraries(airusb_session PUBLIC airusb_transport)

# ---------------------------------------------------------------------------
# diag/  — test instruments. Portable, and deliberately NOT on the data path:
# nothing in core/, protocol/ or transport/ may include it. BotProbe understands
# SCSI so that P2.8 has an instrument it can trust; AirUSB itself does not.
#
# BotProbe never writes, and its header says so without qualification. WriteProbe
# is a separate type precisely so that promise stays absolute rather than becoming
# conditional on a flag.
# ---------------------------------------------------------------------------
add_library(airusb_diag STATIC
    diag/BotProbe.cpp
    diag/WriteProbe.cpp
)
target_link_libraries(airusb_diag PUBLIC airusb_core)

# ---------------------------------------------------------------------------
# platform/linux — the USB/IP byte layer.
#
# Built on EVERY platform, deliberately. UsbipCodec has no sockets, no sysfs and
# no Linux headers; it is pure byte manipulation against a kernel ABI where a
# misremembered field offset produces a device that enumerates and then corrupts
# data. Compiling and fuzzing it on the development Mac is what makes that bug
# cheap to find, instead of costing a VM reboot per iteration.
# ---------------------------------------------------------------------------
add_library(airusb_linux_usbip STATIC
    platform/linux/UsbipCodec.cpp
    platform/linux/LinuxUsb.cpp
    platform/linux/VhciBridge.cpp
    platform/linux/VhciNetBridge.cpp
)
# VhciNetBridge drives session::ImporterDataPlane (the platform/linux -> session
# arrow the plan sanctions). UsbipCodec/LinuxUsb/VhciBridge themselves stay pure,
# so the fuzzed codec is unaffected.
target_link_libraries(airusb_linux_usbip PUBLIC airusb_core airusb_transport airusb_session)

# ---------------------------------------------------------------------------
# platform/windows — the Windows importer's portable half.
#
# Built on EVERY platform, for the same reason platform/linux/UsbipCodec is: it
# is pure translation against a kernel ABI, and a wrong constant produces a
# device that enumerates and then misbehaves. Finding that on the development
# Mac costs a rebuild; finding it with a kernel-mode driver in the loop costs a
# bugcheck and a reboot on a machine this project can only reach by RDP.
#
# The WDK headers are not included here and must not be. When a real driver
# build DOES include them, AIRUSB_WITH_WDK static_asserts every transcribed
# constant against Microsoft's own — that build is the acceptance test for the
# numbers, and these tests are the acceptance test for the mapping.
# ---------------------------------------------------------------------------
add_library(airusb_windows_udecx STATIC
    platform/windows/WindowsUsb.cpp
    platform/windows/UdecxIpc.cpp
)
target_link_libraries(airusb_windows_udecx PUBLIC airusb_core)

# The L1 gate. Linux only, because it writes to vhci-hcd's sysfs and there is
# nothing to point it at anywhere else.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(vhci_probe platform/linux/vhci_probe_main.cpp)
    target_link_libraries(vhci_probe PRIVATE airusb_linux_usbip)

    # L4: the same bridge the unit tests drive, against a real kernel.
    add_executable(airusb-vhci
        platform/linux/airusb_vhci_main.cpp
        tests/fakes/ScriptedDevice.cpp
    )
    target_link_libraries(airusb-vhci PRIVATE airusb_linux_usbip airusb_session)
endif()

# ---------------------------------------------------------------------------
# platform/macos IPC — the daemon<->agent codec and socket transport.
#
# Built on EVERY platform, not just macOS, and with no IOKit dependency. It is a
# parser between a root process and an unprivileged one, so it is unit-tested and
# fuzzed in CI rather than only on the machine that has the drive plugged in.
# ---------------------------------------------------------------------------
#
# AgentProtocol is the codec and is portable. AgentLink is the socket underneath
# it and is POSIX — unix domain sockets, poll(2), getpeereid(2). Windows has no
# equivalent and no need for one: the two-process split exists because of a macOS
# security-session rule that does not apply there.
#
# Splitting them keeps the codec fuzzable everywhere while the transport stays
# where it belongs.
add_library(airusb_macos_ipc STATIC
    platform/macos/AgentProtocol.cpp
    $<$<NOT:$<BOOL:${WIN32}>>:${CMAKE_CURRENT_SOURCE_DIR}/platform/macos/AgentLink.cpp>
)
target_link_libraries(airusb_macos_ipc PUBLIC airusb_protocol)

# The whole point of this layer is portability. Guard it: nothing here may pull in
# an OS USB header. Enforced by tests/unit/test_layering.cpp as well.
target_compile_definitions(airusb_core PRIVATE AIRUSB_PORTABLE_CORE=1)

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
    # airusb_session for the --serve mode's TCP ExporterSession (the real drive,
    # over the network, to a remote importer). airusb_macos already brings the
    # capture (HostDeviceExporter, an IUsbDevicePort); session adds the network.
    target_link_libraries(airusb-exportd PRIVATE airusb_macos airusb_session)
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
# tools/ — the network, without the hardware.
#
# Portable C++ on purpose: this is what runs on Windows and Linux against a macOS
# exporter, and proves the protocol, the crypto and the LAN path long before any
# of those platforms has a driver.
# ---------------------------------------------------------------------------
add_executable(airusb-net
    tools/airusb_net_main.cpp
    tests/fakes/ScriptedDevice.cpp
)
target_link_libraries(airusb-net PRIVATE airusb_session airusb_diag)

# ---------------------------------------------------------------------------
# control/ — the product's interface.
#
# A loopback HTTP control plane and one embedded page. It is here rather than in
# a platform/ directory because it is the same code on all three operating
# systems: the window is the browser every one of them already has, so there is
# no toolkit to choose and nothing to port.
#
# It depends on session (it drives the protocol) and diag (the "check it really
# works" button is BotProbe, which cannot write). Nothing depends on IT — the
# arrow points one way, like every other arrow in this file.
# ---------------------------------------------------------------------------
add_library(airusb_control STATIC
    control/Json.cpp
    control/HttpServer.cpp
    control/HubState.cpp
    control/ControlApi.cpp
    control/WebUi.cpp
    control/SimulatedDeviceSource.cpp
    tests/fakes/ScriptedDevice.cpp
)
target_link_libraries(airusb_control PUBLIC airusb_session airusb_diag)

add_executable(airusb-hubd tools/airusb_hubd_main.cpp)
target_link_libraries(airusb-hubd PRIVATE airusb_control)

# ---------------------------------------------------------------------------
# tests
# ---------------------------------------------------------------------------
enable_testing()
add_subdirectory(tests)
