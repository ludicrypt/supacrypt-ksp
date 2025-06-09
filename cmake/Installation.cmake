# Installation.cmake - Installation configuration for Supacrypt KSP

function(configure_installation)
    # Default installation prefix
    if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
        if(WIN32)
            set(CMAKE_INSTALL_PREFIX "C:/Program Files/Supacrypt" CACHE PATH "Installation prefix" FORCE)
        else()
            set(CMAKE_INSTALL_PREFIX "/usr/local" CACHE PATH "Installation prefix" FORCE)
        endif()
    endif()

    # Include required modules
    include(GNUInstallDirs)
    include(CMakePackageConfigHelpers)

    # Installation directories
    set(SUPACRYPT_INSTALL_BINDIR "${CMAKE_INSTALL_BINDIR}")
    set(SUPACRYPT_INSTALL_LIBDIR "${CMAKE_INSTALL_LIBDIR}")
    set(SUPACRYPT_INSTALL_INCLUDEDIR "${CMAKE_INSTALL_INCLUDEDIR}/supacrypt")
    set(SUPACRYPT_INSTALL_CONFIGDIR "${CMAKE_INSTALL_LIBDIR}/cmake/supacrypt-ksp")
    set(SUPACRYPT_INSTALL_DOCDIR "${CMAKE_INSTALL_DOCDIR}")

    # Windows-specific directories
    if(WIN32)
        set(SUPACRYPT_INSTALL_SYSTEM32DIR "C:/Windows/System32")
        set(SUPACRYPT_INSTALL_SYSWOW64DIR "C:/Windows/SysWOW64")
        
        # KSP registration directory (depends on architecture)
        if(CMAKE_SIZEOF_VOID_P EQUAL 8)
            set(SUPACRYPT_INSTALL_KSPDIR "${SUPACRYPT_INSTALL_SYSTEM32DIR}")
        else()
            set(SUPACRYPT_INSTALL_KSPDIR "${SUPACRYPT_INSTALL_SYSWOW64DIR}")
        endif()
    endif()

    # Install main KSP library
    install(TARGETS ${PROJECT_NAME}
        EXPORT supacrypt-ksp-targets
        RUNTIME DESTINATION ${SUPACRYPT_INSTALL_BINDIR}
        LIBRARY DESTINATION ${SUPACRYPT_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${SUPACRYPT_INSTALL_LIBDIR}
        INCLUDES DESTINATION ${SUPACRYPT_INSTALL_INCLUDEDIR}
    )

    # Install generated protobuf library if enabled
    if(ENABLE_GRPC AND TARGET supacrypt_proto)
        install(TARGETS supacrypt_proto
            EXPORT supacrypt-ksp-targets
            ARCHIVE DESTINATION ${SUPACRYPT_INSTALL_LIBDIR}
            INCLUDES DESTINATION ${SUPACRYPT_INSTALL_INCLUDEDIR}
        )
    endif()

    # Install public headers
    install(DIRECTORY include/
        DESTINATION ${SUPACRYPT_INSTALL_INCLUDEDIR}
        FILES_MATCHING PATTERN "*.h" PATTERN "*.hpp"
        PATTERN "internal" EXCLUDE
        PATTERN "private" EXCLUDE
    )

    # Install generated protobuf headers if enabled
    if(ENABLE_GRPC AND DEFINED SUPACRYPT_PROTO_GENERATED_DIR)
        install(DIRECTORY "${SUPACRYPT_PROTO_GENERATED_DIR}/"
            DESTINATION ${SUPACRYPT_INSTALL_INCLUDEDIR}/proto
            FILES_MATCHING PATTERN "*.h"
        )
    endif()

    # Install documentation
    install(FILES
        README.md
        LICENSE
        DESTINATION ${SUPACRYPT_INSTALL_DOCDIR}
    )

    # Install additional documentation if it exists
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/docs")
        install(DIRECTORY docs/
            DESTINATION ${SUPACRYPT_INSTALL_DOCDIR}
            FILES_MATCHING 
            PATTERN "*.md"
            PATTERN "*.txt"
            PATTERN "*.pdf"
        )
    endif()

    # Windows-specific installation components
    if(WIN32)
        # Install to system directory for direct KSP access (requires admin privileges)
        install(TARGETS ${PROJECT_NAME}
            RUNTIME DESTINATION ${SUPACRYPT_INSTALL_KSPDIR}
            COMPONENT KSP_System
            OPTIONAL
        )

        # Install registration tools
        if(BUILD_TOOLS)
            install(DIRECTORY tools/
                DESTINATION ${SUPACRYPT_INSTALL_BINDIR}
                FILES_MATCHING
                PATTERN "*.exe"
                PATTERN "*.ps1"
                PATTERN "*.bat"
                PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
                            GROUP_READ GROUP_EXECUTE
                            WORLD_READ WORLD_EXECUTE
            )
        endif()

        # Install PowerShell scripts
        if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/installer/install.ps1")
            install(FILES installer/install.ps1
                DESTINATION ${SUPACRYPT_INSTALL_BINDIR}
                PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
                           GROUP_READ GROUP_EXECUTE
                           WORLD_READ WORLD_EXECUTE
            )
        endif()

        # Install MSI if built
        if(BUILD_INSTALLER AND EXISTS "${CMAKE_CURRENT_BINARY_DIR}/installer")
            install(DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/installer/"
                DESTINATION ${SUPACRYPT_INSTALL_BINDIR}/installer
                FILES_MATCHING PATTERN "*.msi"
                COMPONENT Installer
            )
        endif()
    endif()

    # Create and install package configuration files
    configure_package_config_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake/supacrypt-ksp-config.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/supacrypt-ksp-config.cmake"
        INSTALL_DESTINATION ${SUPACRYPT_INSTALL_CONFIGDIR}
        PATH_VARS
            SUPACRYPT_INSTALL_INCLUDEDIR
            SUPACRYPT_INSTALL_LIBDIR
    )

    # Create version file
    write_basic_package_version_file(
        "${CMAKE_CURRENT_BINARY_DIR}/supacrypt-ksp-config-version.cmake"
        VERSION ${PROJECT_VERSION}
        COMPATIBILITY SameMajorVersion
    )

    # Install package configuration files
    install(FILES
        "${CMAKE_CURRENT_BINARY_DIR}/supacrypt-ksp-config.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/supacrypt-ksp-config-version.cmake"
        DESTINATION ${SUPACRYPT_INSTALL_CONFIGDIR}
    )

    # Install export targets
    install(EXPORT supacrypt-ksp-targets
        FILE supacrypt-ksp-targets.cmake
        NAMESPACE supacrypt::
        DESTINATION ${SUPACRYPT_INSTALL_CONFIGDIR}
    )

    # Installation summary
    message(STATUS "Installation Configuration:")
    message(STATUS "  Prefix: ${CMAKE_INSTALL_PREFIX}")
    message(STATUS "  Binaries: ${CMAKE_INSTALL_PREFIX}/${SUPACRYPT_INSTALL_BINDIR}")
    message(STATUS "  Libraries: ${CMAKE_INSTALL_PREFIX}/${SUPACRYPT_INSTALL_LIBDIR}")
    message(STATUS "  Headers: ${CMAKE_INSTALL_PREFIX}/${SUPACRYPT_INSTALL_INCLUDEDIR}")
    message(STATUS "  Config files: ${CMAKE_INSTALL_PREFIX}/${SUPACRYPT_INSTALL_CONFIGDIR}")
    
    if(WIN32)
        message(STATUS "  KSP System Dir: ${SUPACRYPT_INSTALL_KSPDIR}")
    endif()

    # Create installation script for easy deployment
    if(WIN32)
        set(INSTALL_SCRIPT "${CMAKE_CURRENT_BINARY_DIR}/install_ksp.ps1")
        file(WRITE "${INSTALL_SCRIPT}"
            "# Supacrypt KSP Installation Script\n"
            "param(\n"
            "    [switch]$System = $false,\n"
            "    [switch]$User = $false,\n"
            "    [switch]$Uninstall = $false\n"
            ")\n\n"
            "if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] \"Administrator\")) {\n"
            "    Write-Error \"This script requires administrator privileges\"\n"
            "    exit 1\n"
            "}\n\n"
            "if ($Uninstall) {\n"
            "    Write-Host \"Uninstalling Supacrypt KSP...\"\n"
            "    # Add uninstallation logic here\n"
            "} else {\n"
            "    Write-Host \"Installing Supacrypt KSP...\"\n"
            "    # Add installation logic here\n"
            "}\n"
        )
    endif()

    # Component-based installation
    if(WIN32)
        # Define installation components
        set(CPACK_COMPONENTS_ALL
            Runtime
            Development
            Documentation
            KSP_System
            Tools
            Installer
        )

        # Component descriptions
        set(CPACK_COMPONENT_RUNTIME_DISPLAY_NAME "Supacrypt KSP Runtime")
        set(CPACK_COMPONENT_RUNTIME_DESCRIPTION "Core KSP runtime library")
        set(CPACK_COMPONENT_RUNTIME_REQUIRED TRUE)

        set(CPACK_COMPONENT_DEVELOPMENT_DISPLAY_NAME "Development Files")
        set(CPACK_COMPONENT_DEVELOPMENT_DESCRIPTION "Headers and import libraries for development")
        set(CPACK_COMPONENT_DEVELOPMENT_DEPENDS Runtime)

        set(CPACK_COMPONENT_DOCUMENTATION_DISPLAY_NAME "Documentation")
        set(CPACK_COMPONENT_DOCUMENTATION_DESCRIPTION "User and developer documentation")

        set(CPACK_COMPONENT_KSP_SYSTEM_DISPLAY_NAME "System Integration")
        set(CPACK_COMPONENT_KSP_SYSTEM_DESCRIPTION "Install KSP directly to Windows system directory")
        set(CPACK_COMPONENT_KSP_SYSTEM_DEPENDS Runtime)

        set(CPACK_COMPONENT_TOOLS_DISPLAY_NAME "Management Tools")
        set(CPACK_COMPONENT_TOOLS_DESCRIPTION "Registration and management utilities")
        set(CPACK_COMPONENT_TOOLS_DEPENDS Runtime)

        set(CPACK_COMPONENT_INSTALLER_DISPLAY_NAME "MSI Installer")
        set(CPACK_COMPONENT_INSTALLER_DESCRIPTION "Windows MSI installer package")
    endif()
endfunction()