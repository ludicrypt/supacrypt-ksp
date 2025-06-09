# tests/CMakeLists.txt - Test configuration for Supacrypt KSP

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

# Test utilities library
add_library(ksp_test_utils STATIC
    test_utils.cpp
    mock_backend.cpp
    test_fixtures.cpp
)

target_link_libraries(ksp_test_utils
    supacrypt::ksp
    GTest::gtest
    GTest::gmock
)

target_include_directories(ksp_test_utils PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Unit tests
add_subdirectory(unit)

# Integration tests
add_subdirectory(integration)

# CNG compliance tests
add_subdirectory(cng_compliance)

# Performance tests
if(BUILD_BENCHMARKS)
    add_subdirectory(performance)
endif()

# Test configuration
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/test_config.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/test_config.h
)

# Test data directory
file(COPY test_data DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

message(STATUS "Configured KSP tests:")
message(STATUS "  Unit tests: unit/")
message(STATUS "  Integration tests: integration/")
message(STATUS "  CNG compliance tests: cng_compliance/")
if(BUILD_BENCHMARKS)
    message(STATUS "  Performance tests: performance/")
endif()