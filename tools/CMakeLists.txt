# tools/CMakeLists.txt - Build configuration for KSP tools

if(NOT BUILD_TOOLS)
    return()
endif()

# KSP Registration utility
add_executable(ksp_register
    ksp_register.cpp
    registry_utils.cpp
    certificate_utils.cpp
)

target_include_directories(ksp_register PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(ksp_register PRIVATE
    supacrypt::ksp
    advapi32
    crypt32
    version
)

target_compile_definitions(ksp_register PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

set_target_properties(ksp_register PROPERTIES
    OUTPUT_NAME "supacrypt-ksp-register"
    WIN32_EXECUTABLE TRUE
)

# KSP Management utility
add_executable(ksp_manage
    ksp_manage.cpp
    command_parser.cpp
    key_operations.cpp
)

target_include_directories(ksp_manage PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(ksp_manage PRIVATE
    supacrypt::ksp
    ncrypt
    crypt32
)

target_compile_definitions(ksp_manage PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

set_target_properties(ksp_manage PROPERTIES
    OUTPUT_NAME "supacrypt-ksp-manage"
    WIN32_EXECUTABLE FALSE  # Console application
)

# KSP Test utility
add_executable(ksp_test
    ksp_test.cpp
    test_operations.cpp
    performance_tests.cpp
)

target_include_directories(ksp_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(ksp_test PRIVATE
    supacrypt::ksp
    ncrypt
    crypt32
    bcrypt
)

target_compile_definitions(ksp_test PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

set_target_properties(ksp_test PROPERTIES
    OUTPUT_NAME "supacrypt-ksp-test"
    WIN32_EXECUTABLE FALSE  # Console application
)

# Install tools
install(TARGETS ksp_register ksp_manage ksp_test
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    COMPONENT Tools
)

# Install PowerShell scripts
install(FILES
    install.ps1
    uninstall.ps1
    test.ps1
    DESTINATION ${CMAKE_INSTALL_BINDIR}
    COMPONENT Tools
    PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
                GROUP_READ GROUP_EXECUTE
                WORLD_READ WORLD_EXECUTE
)

message(STATUS "Configured KSP tools:")
message(STATUS "  Registration utility: ksp_register")
message(STATUS "  Management utility: ksp_manage")
message(STATUS "  Test utility: ksp_test")