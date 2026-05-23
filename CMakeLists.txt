cmake_minimum_required(VERSION 3.21)

project(RouteLens VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(GPD_BUILD_TESTS "Build smoke tests" ON)
option(GPD_DEPLOY_QT "Run windeployqt after building the GUI executable" ON)

find_package(Qt6 6.5 REQUIRED COMPONENTS Core Widgets Network Charts Concurrent)
find_package(maxminddb CONFIG QUIET)

qt_standard_project_setup()

set(GPD_SOURCES
    src/app/Application.cpp
    src/app/Logger.cpp
    src/core/ConnectionEnricher.cpp
    src/core/ClashApiClient.cpp
    src/core/ClashConnectionMatcher.cpp
    src/core/diagnostic/AnchorPingProbe.cpp
    src/core/diagnostic/BackgroundTrafficProbe.cpp
    src/core/diagnostic/BufferbloatProbe.cpp
    src/core/diagnostic/DiagnosticEngine.cpp
    src/core/diagnostic/DiagnosticRuleEngine.cpp
    src/core/diagnostic/DiagnosticTypes.cpp
    src/core/InterfaceClassifier.cpp
    src/core/GeoIpResolver.cpp
    src/core/PingAggregator.cpp
    src/core/PingScheduler.cpp
    src/core/RouteClassifier.cpp
    src/core/TunnelCorrelator.cpp
    src/core/TunnelProcessRegistry.cpp
    src/core/UdpFlowAggregator.cpp
    src/platform/windows/ConnectionScannerWin.cpp
    src/platform/windows/diagnostic/AdapterErrorProbe.cpp
    src/platform/windows/diagnostic/CpuPressureProbe.cpp
    src/platform/windows/diagnostic/HopProbe.cpp
    src/platform/windows/diagnostic/PacketLossProbe.cpp
    src/platform/windows/diagnostic/VpnRouteProbe.cpp
    src/platform/windows/diagnostic/WifiMetricsProbe.cpp
    src/platform/windows/EtwNetworkTap.cpp
    src/platform/windows/EtwParser.cpp
    src/platform/windows/InterfaceInspectorWin.cpp
    src/platform/windows/ProcessMonitorWin.cpp
    src/platform/windows/PingProbeWin.cpp
    src/platform/windows/RouteResolverWin.cpp
    src/platform/windows/TcpPingProbeWin.cpp
    src/platform/windows/WinapiUtils.cpp
    src/ui/InterfacesPanel.cpp
    src/ui/KindIcon.cpp
    src/ui/MainWindow.cpp
    src/ui/VerdictBadge.cpp
)

set(GPD_HEADERS
    src/app/Application.h
    src/app/Logger.h
    src/core/ConnectionEnricher.h
    src/core/ClashApiClient.h
    src/core/ClashConnectionMatcher.h
    src/core/diagnostic/AnchorPingProbe.h
    src/core/diagnostic/BackgroundTrafficProbe.h
    src/core/diagnostic/BufferbloatProbe.h
    src/core/diagnostic/DiagnosticEngine.h
    src/core/diagnostic/DiagnosticRuleEngine.h
    src/core/diagnostic/DiagnosticTypes.h
    src/core/diagnostic/IDiagnosticProbe.h
    src/core/GeoIpResolver.h
    src/core/InterfaceClassifier.h
    src/core/Models.h
    src/core/RouteClassifier.h
    src/core/TunnelCorrelator.h
    src/core/TunnelProcessRegistry.h
    src/core/PingAggregator.h
    src/core/PingScheduler.h
    src/core/UdpFlowAggregator.h
    src/platform/windows/ConnectionScannerWin.h
    src/platform/windows/diagnostic/AdapterErrorProbe.h
    src/platform/windows/diagnostic/CpuPressureProbe.h
    src/platform/windows/diagnostic/HopProbe.h
    src/platform/windows/diagnostic/PacketLossProbe.h
    src/platform/windows/diagnostic/VpnRouteProbe.h
    src/platform/windows/diagnostic/WifiMetricsProbe.h
    src/platform/windows/EtwNetworkTap.h
    src/platform/windows/EtwParser.h
    src/platform/windows/InterfaceInspectorWin.h
    src/platform/windows/ProcessMonitorWin.h
    src/platform/windows/PingProbeWin.h
    src/platform/windows/RouteResolverWin.h
    src/platform/windows/TcpPingProbeWin.h
    src/platform/windows/WinapiUtils.h
    src/ui/InterfacesPanel.h
    src/ui/KindIcon.h
    src/ui/MainWindow.h
    src/ui/VerdictBadge.h
)

add_library(RouteLensApp STATIC
    ${GPD_SOURCES}
    ${GPD_HEADERS}
)

target_include_directories(RouteLensApp PUBLIC src resources)

target_compile_definitions(RouteLensApp PUBLIC
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    QT_NO_KEYWORDS
    _WIN32_WINNT=0x0A00
    WINVER=0x0A00
)

if(MSVC)
    target_compile_options(RouteLensApp PRIVATE /W4 /permissive- /EHsc /utf-8)
else()
    target_compile_options(RouteLensApp PRIVATE -Wall -Wextra -Wpedantic)
endif()

target_link_libraries(RouteLensApp PUBLIC
    Qt6::Core
    Qt6::Widgets
    Qt6::Network
    Qt6::Charts
    Qt6::Concurrent
    advapi32
    iphlpapi
    shell32
    tdh
    wlanapi
    ws2_32
)

if(TARGET maxminddb::maxminddb)
    target_link_libraries(RouteLensApp PUBLIC maxminddb::maxminddb)
    target_compile_definitions(RouteLensApp PUBLIC GPD_HAS_MAXMINDDB=1)
else()
    message(WARNING "maxminddb not found; GeoIP resolver will be disabled for this build")
endif()

qt_add_executable(RouteLens WIN32
    src/app/main.cpp
)

target_link_libraries(RouteLens PRIVATE RouteLensApp)

if(MSVC)
    target_link_options(RouteLens PRIVATE "/MANIFESTUAC:level='requireAdministrator' uiAccess='false'")
else()
    target_sources(RouteLens PRIVATE resources/app.rc)
endif()

set_target_properties(RouteLens PROPERTIES
    OUTPUT_NAME "RouteLens"
    VS_DEBUGGER_WORKING_DIRECTORY "$<TARGET_FILE_DIR:RouteLens>"
)

if(WIN32 AND GPD_DEPLOY_QT)
    get_target_property(_qt_qmake_executable Qt6::qmake IMPORTED_LOCATION)
    get_filename_component(_qt_bin_dir "${_qt_qmake_executable}" DIRECTORY)
    find_program(WINDEPLOYQT_EXECUTABLE
        NAMES windeployqt windeployqt.exe
        HINTS "${_qt_bin_dir}"
    )

    if(WINDEPLOYQT_EXECUTABLE)
        add_custom_command(
            TARGET RouteLens
            POST_BUILD
            COMMAND "${WINDEPLOYQT_EXECUTABLE}"
                    --no-compiler-runtime
                    "$<TARGET_FILE:RouteLens>"
            COMMENT "Deploying Qt runtime for RouteLens.exe"
            VERBATIM
        )
    else()
        message(WARNING "windeployqt was not found. Runtime deployment is skipped.")
    endif()
endif()

if(GPD_BUILD_TESTS)
    enable_testing()
    qt_add_executable(RouteLensSmoke
        tests/smoke.cpp
    )
    target_link_libraries(RouteLensSmoke PRIVATE RouteLensApp)
    add_test(NAME smoke_basic COMMAND RouteLensSmoke)
    get_target_property(_qt_core_location Qt6::Core IMPORTED_LOCATION_RELEASE)
    if(NOT _qt_core_location)
        get_target_property(_qt_core_location Qt6::Core IMPORTED_LOCATION)
    endif()
    get_filename_component(_qt_runtime_dir "${_qt_core_location}" DIRECTORY)
    set_tests_properties(smoke_basic PROPERTIES
        ENVIRONMENT "PATH=${_qt_runtime_dir};$ENV{PATH}"
    )
endif()
