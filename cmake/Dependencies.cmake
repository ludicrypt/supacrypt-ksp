# Dependencies.cmake - Dependency management for Supacrypt KSP

function(find_dependencies)
    # gRPC and Protobuf for backend communication
    if(ENABLE_GRPC)
        find_package(Protobuf REQUIRED)
        find_package(gRPC REQUIRED)
        
        if(NOT TARGET protobuf::protobuf OR NOT TARGET gRPC::grpc++)
            message(FATAL_ERROR "gRPC and Protobuf are required for backend communication")
        endif()

        target_link_libraries(${PROJECT_NAME} INTERFACE
            protobuf::protobuf
            gRPC::grpc++
            gRPC::grpc++_reflection
        )

        message(STATUS "gRPC dependencies found:")
        message(STATUS "  Protobuf version: ${Protobuf_VERSION}")
        message(STATUS "  gRPC version: ${gRPC_VERSION}")
    endif()

    # OpenSSL for TLS/mTLS support
    find_package(OpenSSL REQUIRED)
    if(NOT TARGET OpenSSL::SSL OR NOT TARGET OpenSSL::Crypto)
        message(FATAL_ERROR "OpenSSL is required for TLS support")
    endif()

    target_link_libraries(${PROJECT_NAME} INTERFACE
        OpenSSL::SSL
        OpenSSL::Crypto
    )

    message(STATUS "OpenSSL version: ${OPENSSL_VERSION}")

    # Testing dependencies
    if(BUILD_TESTING)
        find_package(GTest REQUIRED)
        find_package(GMock REQUIRED)
        
        if(NOT TARGET GTest::gtest OR NOT TARGET GTest::gmock)
            message(FATAL_ERROR "Google Test and Google Mock are required for testing")
        endif()

        # Make GTest/GMock available globally for test targets
        set(GTEST_LIBRARIES GTest::gtest GTest::gtest_main PARENT_SCOPE)
        set(GMOCK_LIBRARIES GTest::gmock GTest::gmock_main PARENT_SCOPE)

        message(STATUS "Google Test version: ${GTest_VERSION}")
    endif()

    # Benchmarking dependencies
    if(BUILD_BENCHMARKS)
        find_package(benchmark REQUIRED)
        
        if(NOT TARGET benchmark::benchmark)
            message(FATAL_ERROR "Google Benchmark is required for performance testing")
        endif()

        message(STATUS "Google Benchmark found")
    endif()

    # Observability dependencies
    if(ENABLE_OBSERVABILITY)
        # OpenTelemetry C++ SDK (optional)
        find_package(opentelemetry-cpp QUIET)
        
        if(TARGET opentelemetry-cpp::api)
            target_link_libraries(${PROJECT_NAME} INTERFACE
                opentelemetry-cpp::api
                opentelemetry-cpp::sdk
                opentelemetry-cpp::ext
                opentelemetry-cpp::exporters_ostream
                opentelemetry-cpp::exporters_otlp_grpc
            )
            
            target_compile_definitions(${PROJECT_NAME} INTERFACE
                SUPACRYPT_OPENTELEMETRY_ENABLED
            )
            
            message(STATUS "OpenTelemetry C++ SDK found")
        else()
            message(STATUS "OpenTelemetry C++ SDK not found - using basic observability")
        endif()

        # Prometheus C++ client (optional)
        find_package(prometheus-cpp QUIET)
        
        if(TARGET prometheus-cpp::core)
            target_link_libraries(${PROJECT_NAME} INTERFACE
                prometheus-cpp::core
                prometheus-cpp::pull
            )
            
            target_compile_definitions(${PROJECT_NAME} INTERFACE
                SUPACRYPT_PROMETHEUS_ENABLED
            )
            
            message(STATUS "Prometheus C++ client found")
        endif()
    endif()

    # JSON library for configuration and logging
    find_package(nlohmann_json REQUIRED)
    if(NOT TARGET nlohmann_json::nlohmann_json)
        message(FATAL_ERROR "nlohmann_json is required for configuration management")
    endif()

    target_link_libraries(${PROJECT_NAME} INTERFACE
        nlohmann_json::nlohmann_json
    )

    message(STATUS "nlohmann_json version: ${nlohmann_json_VERSION}")

    # Structured logging library (spdlog)
    find_package(spdlog REQUIRED)
    if(NOT TARGET spdlog::spdlog)
        message(FATAL_ERROR "spdlog is required for structured logging")
    endif()

    target_link_libraries(${PROJECT_NAME} INTERFACE
        spdlog::spdlog
    )

    message(STATUS "spdlog version: ${spdlog_VERSION}")

    # Windows-specific dependencies
    if(WIN32)
        # Windows Implementation Libraries (WIL) for modern C++ Windows programming
        find_package(Microsoft.Windows.ImplementationLibrary QUIET)
        
        if(TARGET Microsoft.Windows.ImplementationLibrary::WIL)
            target_link_libraries(${PROJECT_NAME} INTERFACE
                Microsoft.Windows.ImplementationLibrary::WIL
            )
            
            target_compile_definitions(${PROJECT_NAME} INTERFACE
                SUPACRYPT_WIL_ENABLED
            )
            
            message(STATUS "Windows Implementation Libraries (WIL) found")
        else()
            message(STATUS "WIL not found - using traditional Windows APIs")
        endif()

        # Windows Runtime C++ Template Library (WRL) - usually included with Windows SDK
        target_compile_definitions(${PROJECT_NAME} INTERFACE
            SUPACRYPT_WRL_AVAILABLE
        )
    endif()

    # Development and debugging tools
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        # Memory debugging
        if(WIN32)
            # CRT debug heap (built into MSVC runtime)
            target_compile_definitions(${PROJECT_NAME} INTERFACE
                _CRTDBG_MAP_ALLOC
            )
        endif()

        # LeakSanitizer and AddressSanitizer support
        if(ENABLE_SANITIZERS)
            message(STATUS "Sanitizers enabled for debug build")
        endif()
    endif()

    # Thread Building Blocks (TBB) for parallel algorithms (optional)
    find_package(TBB QUIET)
    if(TARGET TBB::tbb)
        target_link_libraries(${PROJECT_NAME} INTERFACE
            TBB::tbb
        )
        
        target_compile_definitions(${PROJECT_NAME} INTERFACE
            SUPACRYPT_TBB_ENABLED
        )
        
        message(STATUS "Intel TBB found - parallel algorithms enabled")
    endif()

    # Crypto++ library for additional cryptographic primitives (optional fallback)
    find_package(cryptopp QUIET)
    if(TARGET cryptopp::cryptopp)
        target_link_libraries(${PROJECT_NAME} INTERFACE
            cryptopp::cryptopp
        )
        
        target_compile_definitions(${PROJECT_NAME} INTERFACE
            SUPACRYPT_CRYPTOPP_ENABLED
        )
        
        message(STATUS "Crypto++ found - additional crypto primitives available")
    endif()
endfunction()

# Function to setup vcpkg integration if available
function(setup_vcpkg_integration)
    if(DEFINED ENV{VCPKG_ROOT})
        set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
            CACHE STRING "Vcpkg toolchain file" FORCE)
        message(STATUS "Using vcpkg from: $ENV{VCPKG_ROOT}")
    elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/vcpkg")
        set(CMAKE_TOOLCHAIN_FILE "${CMAKE_CURRENT_SOURCE_DIR}/vcpkg/scripts/buildsystems/vcpkg.cmake"
            CACHE STRING "Vcpkg toolchain file" FORCE)
        message(STATUS "Using local vcpkg from: ${CMAKE_CURRENT_SOURCE_DIR}/vcpkg")
    endif()
endfunction()

# Function to configure Conan integration if available
function(setup_conan_integration)
    if(EXISTS "${CMAKE_BINARY_DIR}/conan_paths.cmake")
        include("${CMAKE_BINARY_DIR}/conan_paths.cmake")
        message(STATUS "Using Conan package manager")
    endif()
endfunction()

# Setup package managers
setup_vcpkg_integration()
setup_conan_integration()