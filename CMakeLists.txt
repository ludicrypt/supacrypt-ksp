# CMakeLists.txt - Supacrypt Key Storage Provider (KSP)
cmake_minimum_required(VERSION 3.20)

project(supacrypt-ksp
    VERSION 1.0.0
    DESCRIPTION "Supacrypt Windows CNG Key Storage Provider"
    LANGUAGES CXX
)

# Build type configuration
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# Add CMake modules path
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# Include CMake modules
include(CompilerOptions)
include(Dependencies)
include(Platform)
include(ProtoGeneration)
include(Installation)

# Feature flags
option(ENABLE_GRPC "Enable gRPC backend communication" ON)
option(ENABLE_OBSERVABILITY "Enable observability and metrics" ON)
option(BUILD_TESTING "Build test suite" ON)
option(BUILD_BENCHMARKS "Build performance benchmarks" ON)
option(BUILD_TOOLS "Build registration and management tools" ON)
option(BUILD_INSTALLER "Build Windows MSI installer" ON)

# Enforce Windows-only build
if(NOT WIN32)
    message(FATAL_ERROR "Supacrypt KSP is only supported on Windows")
endif()

# Enforce x64 architecture for initial implementation
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(WARNING "Supacrypt KSP is primarily tested on x64. x86 support may be limited.")
endif()

# C++ standard and extensions
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Configure compiler options
configure_compiler_options()

# Find dependencies
find_dependencies()

# Generate protobuf/gRPC code
if(ENABLE_GRPC)
    generate_proto_sources()
endif()

# Configure platform-specific settings
configure_platform_settings()

# Add subdirectories
add_subdirectory(src)

if(BUILD_TESTING)
    enable_testing()
    add_subdirectory(tests)
endif()

if(BUILD_TOOLS)
    add_subdirectory(tools)
endif()

if(BUILD_INSTALLER)
    add_subdirectory(installer)
endif()

# Installation configuration
configure_installation()

# Package configuration
if(BUILD_INSTALLER)
    include(Packaging)
    configure_packaging()
endif()

# Summary
message(STATUS "Supacrypt KSP Configuration Summary:")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  C++ standard: C++${CMAKE_CXX_STANDARD}")
message(STATUS "  gRPC backend: ${ENABLE_GRPC}")
message(STATUS "  Observability: ${ENABLE_OBSERVABILITY}")
message(STATUS "  Testing: ${BUILD_TESTING}")
message(STATUS "  Benchmarks: ${BUILD_BENCHMARKS}")
message(STATUS "  Tools: ${BUILD_TOOLS}")
message(STATUS "  Installer: ${BUILD_INSTALLER}")
message(STATUS "  Architecture: ${CMAKE_SYSTEM_PROCESSOR}")