# tests/CMakeLists.txt - Enhanced KSP Test Suite for Task 4.3
# Copyright (c) 2025 ludicrypt. All rights reserved.
# Licensed under the MIT License.

if(NOT BUILD_TESTING)
    return()
endif()

# Find testing dependencies
find_package(GTest REQUIRED)
find_package(GMock REQUIRED)

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Enhanced test framework library for KSP
add_library(ksp_test_framework STATIC
    framework/ksp_test_framework.cpp
    framework/ksp_performance_profiler.cpp
    framework/ksp_security_validator.cpp
    framework/ksp_windows_utils.cpp
    test_utils.cpp
    mock_backend.cpp
    test_fixtures.cpp
)

target_link_libraries(ksp_test_framework
    supacrypt::ksp
    GTest::gtest
    GTest::gmock
    ncrypt
    crypt32
    advapi32
    kernel32
    psapi
)

target_include_directories(ksp_test_framework PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/framework
)

# Enhanced unit tests for 100% coverage
add_executable(ksp_enhanced_unit_tests
    enhanced/enhanced_unit_tests.cpp
    enhanced/concurrent_tests.cpp
    enhanced/edge_case_tests.cpp
    enhanced/stress_tests.cpp
)

target_link_libraries(ksp_enhanced_unit_tests
    ksp_test_framework
    GTest::gtest_main
)

# Performance benchmark tests
add_executable(ksp_performance_tests
    performance/initialization_benchmarks.cpp
    performance/key_operations_benchmarks.cpp
    performance/signature_benchmarks.cpp
    performance/enumeration_benchmarks.cpp
    performance/load_tests.cpp
)

target_link_libraries(ksp_performance_tests
    ksp_test_framework
    GTest::gtest_main
)

# Security validation tests  
add_executable(ksp_security_tests
    security/access_control_tests.cpp
    security/key_isolation_tests.cpp
    security/memory_security_tests.cpp
    security/handle_security_tests.cpp
    security/attack_simulation_tests.cpp
)

target_link_libraries(ksp_security_tests
    ksp_test_framework
    GTest::gtest_main
)

# Unit tests (existing)
add_subdirectory(unit)

# Integration tests (enhanced)
add_subdirectory(integration)

# CNG compliance tests (enhanced)
add_subdirectory(cng_compliance)

# Multi-architecture tests
add_executable(ksp_architecture_tests
    architecture/x86_compatibility_tests.cpp
    architecture/x64_optimization_tests.cpp
    architecture/arm64_support_tests.cpp
    architecture/wow64_tests.cpp
)

target_link_libraries(ksp_architecture_tests
    ksp_test_framework
    GTest::gtest_main
)

# Windows integration tests
add_executable(ksp_windows_integration_tests
    windows_integration/certificate_enrollment_tests.cpp
    windows_integration/system_integration_tests.cpp
    windows_integration/application_compatibility_tests.cpp
)

target_link_libraries(ksp_windows_integration_tests
    ksp_test_framework
    GTest::gtest_main
    cryptui
    certcli
)

# Test runner executable
add_executable(ksp_test_runner
    test_runner.cpp
)

target_link_libraries(ksp_test_runner
    ksp_test_framework
    GTest::gtest_main
)

# Custom test targets for Task 4.3
add_custom_target(ksp_run_all_tests
    COMMAND ksp_test_runner --gtest_output=xml:ksp_test_results.xml
    DEPENDS ksp_test_runner
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

add_custom_target(ksp_coverage_tests
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_ksp_coverage.ps1
    DEPENDS ksp_test_runner
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

add_custom_target(ksp_performance_validation
    COMMAND ksp_performance_tests --gtest_output=xml:ksp_performance_results.xml
    DEPENDS ksp_performance_tests
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

add_custom_target(ksp_security_assessment
    COMMAND ksp_security_tests --gtest_output=xml:ksp_security_results.xml
    DEPENDS ksp_security_tests
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

# Test configuration
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/test_config.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/test_config.h
)

# Test data directory
file(COPY test_data DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

# Add all tests to CTest
add_test(NAME KSP_Enhanced_Unit_Tests COMMAND ksp_enhanced_unit_tests)
add_test(NAME KSP_Performance_Tests COMMAND ksp_performance_tests)
add_test(NAME KSP_Security_Tests COMMAND ksp_security_tests)
add_test(NAME KSP_Architecture_Tests COMMAND ksp_architecture_tests)
add_test(NAME KSP_Windows_Integration_Tests COMMAND ksp_windows_integration_tests)

# Installation
install(TARGETS ksp_test_runner
    DESTINATION bin
)

install(DIRECTORY scripts/
    DESTINATION scripts
    FILES_MATCHING PATTERN "*.ps1"
)

message(STATUS "Configured Enhanced KSP Test Suite (Task 4.3):")
message(STATUS "  Enhanced Unit Tests: 100% coverage target")
message(STATUS "  Performance Tests: KSP targets (Init<100ms, Sign<100ms, ECC<50ms, Enum<200ms)")
message(STATUS "  Security Tests: Comprehensive vulnerability assessment")
message(STATUS "  Architecture Tests: x86, x64, ARM64, WOW64 validation")
message(STATUS "  Windows Integration: Certificate enrollment, system integration")
message(STATUS "  Unit tests: unit/")
message(STATUS "  Integration tests: integration/")
message(STATUS "  CNG compliance tests: cng_compliance/")