# src/CMakeLists.txt - Source build configuration for Supacrypt KSP

# Define the main KSP library target
add_library(${PROJECT_NAME} SHARED
    # Main DLL entry point and exports
    ksp_main.cpp
    ksp_exports.def
    
    # Core implementation
    ksp_provider.cpp
    key_storage.cpp
    algorithm_provider.cpp
    grpc_backend.cpp
    error_handling.cpp
    
    # Property and utility handlers
    property_handlers.cpp
    crypto_utilities.cpp
    
    # Resource file for version information
    resources/supacrypt-ksp.rc
)

# Set target properties
set_target_properties(${PROJECT_NAME} PROPERTIES
    # Windows DLL settings
    SUFFIX ".dll"
    PREFIX ""
    
    # Version information
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    
    # Windows-specific properties
    WIN32_EXECUTABLE FALSE
    LINK_FLAGS "/SUBSYSTEM:WINDOWS"
    
    # Export all symbols for debugging
    $<$<CONFIG:Debug>:WINDOWS_EXPORT_ALL_SYMBOLS> TRUE
)

# Include directories
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../include/windows
)

# Public include directories
target_include_directories(${PROJECT_NAME} PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

# Link dependencies
target_link_libraries(${PROJECT_NAME} PRIVATE
    # Windows system libraries
    kernel32
    user32
    advapi32
    ncrypt
    crypt32
    bcrypt
    ntdll
    ws2_32
    secur32
    rpcrt4
)

# gRPC dependencies
if(ENABLE_GRPC)
    target_link_libraries(${PROJECT_NAME} PRIVATE
        ${SUPACRYPT_PROTO_LIBRARY}
    )
    
    target_compile_definitions(${PROJECT_NAME} PRIVATE
        SUPACRYPT_GRPC_ENABLED
    )
endif()

# Observability dependencies
if(ENABLE_OBSERVABILITY)
    target_compile_definitions(${PROJECT_NAME} PRIVATE
        SUPACRYPT_OBSERVABILITY_ENABLED
    )
    
    # Optional OpenTelemetry
    if(TARGET opentelemetry-cpp::api)
        target_link_libraries(${PROJECT_NAME} PRIVATE
            opentelemetry-cpp::api
            opentelemetry-cpp::sdk
        )
        target_compile_definitions(${PROJECT_NAME} PRIVATE
            SUPACRYPT_OPENTELEMETRY_ENABLED
        )
    endif()
    
    # Optional Prometheus
    if(TARGET prometheus-cpp::core)
        target_link_libraries(${PROJECT_NAME} PRIVATE
            prometheus-cpp::core
        )
        target_compile_definitions(${PROJECT_NAME} PRIVATE
            SUPACRYPT_PROMETHEUS_ENABLED
        )
    endif()
endif()

# Additional libraries
target_link_libraries(${PROJECT_NAME} PRIVATE
    nlohmann_json::nlohmann_json
    spdlog::spdlog
    OpenSSL::SSL
    OpenSSL::Crypto
)

# Windows Implementation Libraries (WIL) if available
if(TARGET Microsoft.Windows.ImplementationLibrary::WIL)
    target_link_libraries(${PROJECT_NAME} PRIVATE
        Microsoft.Windows.ImplementationLibrary::WIL
    )
    target_compile_definitions(${PROJECT_NAME} PRIVATE
        SUPACRYPT_WIL_ENABLED
    )
endif()

# Compiler-specific settings
if(MSVC)
    # MSVC-specific options
    target_compile_options(${PROJECT_NAME} PRIVATE
        /bigobj          # Large object files
        /MP              # Multi-processor compilation
    )
    
    # Disable specific warnings for Windows APIs
    target_compile_options(${PROJECT_NAME} PRIVATE
        /wd4005          # Macro redefinition (Windows headers)
        /wd4996          # Deprecated function warnings
    )
    
    # Link-time code generation for release builds
    target_compile_options(${PROJECT_NAME} PRIVATE
        $<$<CONFIG:Release>:/GL>
    )
    target_link_options(${PROJECT_NAME} PRIVATE
        $<$<CONFIG:Release>:/LTCG>
    )
endif()

# Debug configuration
target_compile_definitions(${PROJECT_NAME} PRIVATE
    $<$<CONFIG:Debug>:SUPACRYPT_DEBUG_LOGGING>
    $<$<CONFIG:Debug>:SUPACRYPT_DETAILED_TRACING>
)

# Release configuration
target_compile_definitions(${PROJECT_NAME} PRIVATE
    $<$<CONFIG:Release>:SUPACRYPT_OPTIMIZED>
)

# Module definition file for explicit exports
set_target_properties(${PROJECT_NAME} PROPERTIES
    LINK_FLAGS "/DEF:${CMAKE_CURRENT_SOURCE_DIR}/ksp_exports.def"
)

# Custom post-build steps
if(WIN32)
    # Sign the DLL if code signing certificate is available
    find_program(SIGNTOOL_EXECUTABLE signtool)
    if(SIGNTOOL_EXECUTABLE AND EXISTS "${SUPACRYPT_CODE_SIGNING_CERT}")
        add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
            COMMAND ${SIGNTOOL_EXECUTABLE} sign 
                /f "${SUPACRYPT_CODE_SIGNING_CERT}"
                /t http://timestamp.comodoca.com/authenticode
                $<TARGET_FILE:${PROJECT_NAME}>
            COMMENT "Code signing ${PROJECT_NAME}"
            VERBATIM
        )
    endif()
    
    # Copy to system directory in debug builds for testing
    if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND SUPACRYPT_DEBUG_INSTALL_SYSTEM)
        add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                $<TARGET_FILE:${PROJECT_NAME}>
                "${SUPACRYPT_INSTALL_KSPDIR}/$<TARGET_FILE_NAME:${PROJECT_NAME}>"
            COMMENT "Installing ${PROJECT_NAME} to system directory for debugging"
            VERBATIM
        )
    endif()
endif()

# Generate export header
include(GenerateExportHeader)
generate_export_header(${PROJECT_NAME}
    BASE_NAME SUPACRYPT_KSP
    EXPORT_MACRO_NAME SUPACRYPT_KSP_API
    EXPORT_FILE_NAME ${CMAKE_CURRENT_BINARY_DIR}/supacrypt_ksp_export.h
)

target_include_directories(${PROJECT_NAME} PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
)

# Install the generated export header
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/supacrypt_ksp_export.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/supacrypt
)

# Create PDB files for release builds on Windows
if(WIN32 AND CMAKE_BUILD_TYPE STREQUAL "Release")
    target_compile_options(${PROJECT_NAME} PRIVATE /Zi)
    target_link_options(${PROJECT_NAME} PRIVATE 
        /DEBUG 
        /OPT:REF 
        /OPT:ICF
    )
    
    # Install PDB file
    install(FILES $<TARGET_PDB_FILE:${PROJECT_NAME}>
        DESTINATION ${CMAKE_INSTALL_BINDIR}
        OPTIONAL
    )
endif()

# Alias for consistent naming
add_library(supacrypt::ksp ALIAS ${PROJECT_NAME})

message(STATUS "Configured Supacrypt KSP library with:")
message(STATUS "  Target: ${PROJECT_NAME}")
message(STATUS "  Type: SHARED")
message(STATUS "  gRPC: ${ENABLE_GRPC}")
message(STATUS "  Observability: ${ENABLE_OBSERVABILITY}")
message(STATUS "  Output: $<TARGET_FILE:${PROJECT_NAME}>")

# Validation
if(NOT WIN32)
    message(FATAL_ERROR "Supacrypt KSP can only be built on Windows")
endif()

if(NOT ENABLE_GRPC)
    message(WARNING "gRPC is disabled - KSP will not be able to communicate with backend")
endif()