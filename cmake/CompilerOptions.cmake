# CompilerOptions.cmake - Compiler configuration for Supacrypt KSP

function(configure_compiler_options)
    # MSVC-specific options
    if(MSVC)
        # Warning level and language features
        target_compile_options(${PROJECT_NAME} INTERFACE
            /W4                     # High warning level
            /WX                     # Treat warnings as errors
            /permissive-            # Disable non-conforming code
            /Zc:__cplusplus         # Enable correct __cplusplus macro
            /Zc:preprocessor        # Enable conforming preprocessor
            /utf-8                  # Source and execution character sets are UTF-8
        )

        # Security features
        target_compile_options(${PROJECT_NAME} INTERFACE
            /GS                     # Buffer security check
            /guard:cf               # Control Flow Guard
            /Qspectre               # Spectre mitigation
        )

        # Runtime library
        set_property(TARGET ${PROJECT_NAME} PROPERTY
            MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL"
        )

        # Linker options
        target_link_options(${PROJECT_NAME} INTERFACE
            /NXCOMPAT               # Data Execution Prevention
            /DYNAMICBASE            # Address Space Layout Randomization
            /HIGHENTROPYVA          # High Entropy ASLR
            /SAFESEH                # Safe Exception Handlers (x86 only)
        )

        # Debug configuration
        target_compile_options(${PROJECT_NAME} INTERFACE
            $<$<CONFIG:Debug>:/Od>          # Disable optimization
            $<$<CONFIG:Debug>:/Zi>          # Generate debug information
            $<$<CONFIG:Debug>:/RTC1>        # Runtime checks
        )

        # Release configuration
        target_compile_options(${PROJECT_NAME} INTERFACE
            $<$<CONFIG:Release>:/O2>        # Full optimization
            $<$<CONFIG:Release>:/Ob2>       # Inline expansion
            $<$<CONFIG:Release>:/Oi>        # Enable intrinsics
            $<$<CONFIG:Release>:/Ot>        # Favor fast code
            $<$<CONFIG:Release>:/GL>        # Whole program optimization
        )

        target_link_options(${PROJECT_NAME} INTERFACE
            $<$<CONFIG:Release>:/LTCG>      # Link-time code generation
            $<$<CONFIG:Release>:/OPT:REF>   # Eliminate unreferenced functions
            $<$<CONFIG:Release>:/OPT:ICF>   # COMDAT folding
        )

    # GCC/Clang options
    else()
        target_compile_options(${PROJECT_NAME} INTERFACE
            -Wall
            -Wextra
            -Werror
            -Wpedantic
            -Wconversion
            -Wsign-conversion
            -Wcast-align
            -Wcast-qual
            -Wctor-dtor-privacy
            -Wdisabled-optimization
            -Wformat=2
            -Winit-self
            -Wmissing-declarations
            -Wmissing-include-dirs
            -Wold-style-cast
            -Woverloaded-virtual
            -Wredundant-decls
            -Wshadow
            -Wsign-promo
            -Wstrict-overflow=5
            -Wundef
            -Wno-unused
        )

        # Security features
        target_compile_options(${PROJECT_NAME} INTERFACE
            -fstack-protector-strong
            -D_FORTIFY_SOURCE=2
        )

        target_link_options(${PROJECT_NAME} INTERFACE
            -Wl,-z,relro
            -Wl,-z,now
            -Wl,-z,noexecstack
        )

        # Debug configuration
        target_compile_options(${PROJECT_NAME} INTERFACE
            $<$<CONFIG:Debug>:-O0>
            $<$<CONFIG:Debug>:-g3>
        )

        # Release configuration
        target_compile_options(${PROJECT_NAME} INTERFACE
            $<$<CONFIG:Release>:-O3>
            $<$<CONFIG:Release>:-DNDEBUG>
        )
    endif()

    # Preprocessor definitions
    target_compile_definitions(${PROJECT_NAME} INTERFACE
        $<$<CONFIG:Debug>:SUPACRYPT_DEBUG>
        $<$<CONFIG:Release>:SUPACRYPT_RELEASE>
        SUPACRYPT_KSP_VERSION_MAJOR=${PROJECT_VERSION_MAJOR}
        SUPACRYPT_KSP_VERSION_MINOR=${PROJECT_VERSION_MINOR}
        SUPACRYPT_KSP_VERSION_PATCH=${PROJECT_VERSION_PATCH}
        SUPACRYPT_KSP_VERSION_STRING="${PROJECT_VERSION}"
    )

    # Windows-specific definitions
    if(WIN32)
        target_compile_definitions(${PROJECT_NAME} INTERFACE
            WIN32_LEAN_AND_MEAN
            NOMINMAX
            UNICODE
            _UNICODE
            _WIN32_WINNT=0x0601     # Windows 7+
            WINVER=0x0601
            NTDDI_VERSION=0x06010000
        )
    endif()

    # Code coverage support
    if(ENABLE_COVERAGE AND CMAKE_BUILD_TYPE STREQUAL "Debug")
        if(MSVC)
            # Visual Studio Code Coverage
            target_compile_options(${PROJECT_NAME} INTERFACE /PROFILE)
            target_link_options(${PROJECT_NAME} INTERFACE /PROFILE)
        else()
            # GCC/Clang coverage
            target_compile_options(${PROJECT_NAME} INTERFACE --coverage)
            target_link_options(${PROJECT_NAME} INTERFACE --coverage)
        endif()
    endif()

    # Sanitizer support (Debug builds only)
    if(ENABLE_SANITIZERS AND CMAKE_BUILD_TYPE STREQUAL "Debug")
        if(MSVC)
            # AddressSanitizer for MSVC
            target_compile_options(${PROJECT_NAME} INTERFACE /fsanitize=address)
        else()
            # Multiple sanitizers for GCC/Clang
            target_compile_options(${PROJECT_NAME} INTERFACE
                -fsanitize=address
                -fsanitize=undefined
                -fsanitize=leak
                -fno-omit-frame-pointer
            )
            target_link_options(${PROJECT_NAME} INTERFACE
                -fsanitize=address
                -fsanitize=undefined
                -fsanitize=leak
            )
        endif()
    endif()
endfunction()