# Platform.cmake - Windows-specific platform configuration for Supacrypt KSP

function(configure_platform_settings)
    # Verify Windows platform
    if(NOT WIN32)
        message(FATAL_ERROR "Supacrypt KSP requires Windows platform")
    endif()

    # Set minimum Windows version (Windows 7 SP1 / Server 2008 R2 SP1)
    # CNG APIs were enhanced significantly in Windows 8, but basic support exists in Windows 7
    set(CMAKE_SYSTEM_VERSION "6.1" CACHE STRING "Windows minimum version" FORCE)

    # Architecture-specific configurations
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(SUPACRYPT_ARCHITECTURE "x64")
        set(SUPACRYPT_PLATFORM_SUFFIX "_x64")
    else()
        set(SUPACRYPT_ARCHITECTURE "x86")
        set(SUPACRYPT_PLATFORM_SUFFIX "_x86")
    endif()

    # Set target properties
    target_compile_definitions(${PROJECT_NAME} INTERFACE
        SUPACRYPT_ARCHITECTURE="${SUPACRYPT_ARCHITECTURE}"
        SUPACRYPT_PLATFORM_SUFFIX="${SUPACRYPT_PLATFORM_SUFFIX}"
    )

    # Windows SDK version detection
    if(CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION)
        target_compile_definitions(${PROJECT_NAME} INTERFACE
            SUPACRYPT_WINDOWS_SDK_VERSION="${CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION}"
        )
    endif()

    # Registry paths for KSP registration
    set(SUPACRYPT_REGISTRY_ROOT "SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider")
    set(SUPACRYPT_KSP_NAME "Supacrypt Key Storage Provider")
    set(SUPACRYPT_KSP_IMAGE_PATH "${CMAKE_INSTALL_PREFIX}/bin/supacrypt-ksp${SUPACRYPT_PLATFORM_SUFFIX}.dll")

    target_compile_definitions(${PROJECT_NAME} INTERFACE
        SUPACRYPT_REGISTRY_ROOT="${SUPACRYPT_REGISTRY_ROOT}"
        SUPACRYPT_KSP_NAME="${SUPACRYPT_KSP_NAME}"
        SUPACRYPT_KSP_IMAGE_PATH="${SUPACRYPT_KSP_IMAGE_PATH}"
    )

    # Windows libraries required for KSP implementation
    set(SUPACRYPT_WINDOWS_LIBRARIES
        kernel32
        user32
        advapi32        # Registry access
        ncrypt          # CNG Key Storage API
        crypt32         # Cryptography API
        bcrypt          # CNG Primitive API
        ntdll           # NT API for NTSTATUS
        ws2_32          # Windows Sockets (for gRPC)
        secur32         # Security Support Provider Interface
        rpcrt4          # RPC runtime (for UUID generation)
    )

    target_link_libraries(${PROJECT_NAME} INTERFACE ${SUPACRYPT_WINDOWS_LIBRARIES})

    # Windows-specific compiler definitions
    target_compile_definitions(${PROJECT_NAME} INTERFACE
        # Security features
        SECURITY_WIN32
        
        # CNG feature level
        NCRYPT_USE_CNG_COMPLETE_EXTENSION
        
        # Enable modern Windows features
        _WIN32_WINNT_WIN7=0x0601
        _WIN32_WINNT_WIN8=0x0602
        _WIN32_WINNT_WIN10=0x0A00
        
        # KSP-specific definitions
        SUPACRYPT_KSP_PROVIDER_NAME=L"${SUPACRYPT_KSP_NAME}"
        SUPACRYPT_KSP_PROVIDER_TYPE=NCRYPT_KEY_STORAGE_INTERFACE
    )

    # DLL-specific settings
    if(BUILD_SHARED_LIBS OR TARGET_TYPE STREQUAL "SHARED")
        target_compile_definitions(${PROJECT_NAME} INTERFACE
            SUPACRYPT_KSP_EXPORTS
            _WINDLL
        )
        
        # Set DLL characteristics
        target_link_options(${PROJECT_NAME} INTERFACE
            /DLL
            /SUBSYSTEM:WINDOWS
            /MACHINE:${SUPACRYPT_ARCHITECTURE}
        )
    endif()

    # Debug heap verification
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        target_compile_definitions(${PROJECT_NAME} INTERFACE
            _CRTDBG_MAP_ALLOC
            _CRT_SECURE_NO_WARNINGS
        )
    endif()

    # Export all symbols for easier debugging in development
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        target_link_options(${PROJECT_NAME} INTERFACE
            /EXPORT:DllMain
        )
    endif()

    # Windows Application Verifier compatibility
    target_compile_definitions(${PROJECT_NAME} INTERFACE
        SUPACRYPT_APPVERIFIER_COMPATIBLE
    )

    # Set output directories
    set_target_properties(${PROJECT_NAME} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
        ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    )

    # Append platform suffix to output name
    set_target_properties(${PROJECT_NAME} PROPERTIES
        OUTPUT_NAME "supacrypt-ksp${SUPACRYPT_PLATFORM_SUFFIX}"
    )

    # Windows-specific include directories
    target_include_directories(${PROJECT_NAME} INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}/include/windows
    )

    # Resource file for version information
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/resources/supacrypt-ksp.rc")
        target_sources(${PROJECT_NAME} PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}/src/resources/supacrypt-ksp.rc"
        )
    endif()

    # Module definition file for explicit exports
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/supacrypt-ksp.def")
        target_link_options(${PROJECT_NAME} INTERFACE
            "/DEF:${CMAKE_CURRENT_SOURCE_DIR}/src/supacrypt-ksp.def"
        )
    endif()

    # Configure Windows Event Tracing (ETW) if available
    if(ENABLE_OBSERVABILITY)
        # Check for Windows SDK ETW headers
        find_path(ETW_INCLUDE_DIR
            NAMES evntprov.h
            PATHS "${CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION}/Include"
            PATH_SUFFIXES um
        )
        
        if(ETW_INCLUDE_DIR)
            target_compile_definitions(${PROJECT_NAME} INTERFACE
                SUPACRYPT_ETW_ENABLED
            )
            target_include_directories(${PROJECT_NAME} INTERFACE ${ETW_INCLUDE_DIR})
        endif()
    endif()

    # Performance counter support
    target_link_libraries(${PROJECT_NAME} INTERFACE pdh)

    # Message for configuration summary
    message(STATUS "Windows Platform Configuration:")
    message(STATUS "  Architecture: ${SUPACRYPT_ARCHITECTURE}")
    message(STATUS "  Platform suffix: ${SUPACRYPT_PLATFORM_SUFFIX}")
    message(STATUS "  KSP name: ${SUPACRYPT_KSP_NAME}")
    message(STATUS "  Registry root: ${SUPACRYPT_REGISTRY_ROOT}")
    message(STATUS "  Image path: ${SUPACRYPT_KSP_IMAGE_PATH}")
    
    if(ETW_INCLUDE_DIR)
        message(STATUS "  ETW support: Enabled")
    else()
        message(STATUS "  ETW support: Disabled (headers not found)")
    endif()
endfunction()