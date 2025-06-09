# ProtoGeneration.cmake - Protobuf and gRPC code generation for Supacrypt KSP

function(generate_proto_sources)
    if(NOT ENABLE_GRPC)
        return()
    endif()

    # Find required tools
    find_program(PROTOC_EXECUTABLE protoc REQUIRED)
    find_program(GRPC_CPP_PLUGIN grpc_cpp_plugin REQUIRED)

    # Proto file locations
    set(PROTO_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../supacrypt-common/proto")
    set(PROTO_FILE "${PROTO_DIR}/supacrypt.proto")
    
    # Verify proto file exists
    if(NOT EXISTS "${PROTO_FILE}")
        message(FATAL_ERROR "Protocol buffer file not found: ${PROTO_FILE}")
    endif()

    # Output directories
    set(PROTO_GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated/proto")
    set(PROTO_INCLUDE_DIR "${PROTO_GENERATED_DIR}")

    # Create output directory
    file(MAKE_DIRECTORY "${PROTO_GENERATED_DIR}")

    # Generated file names
    set(PROTO_GENERATED_FILES
        "${PROTO_GENERATED_DIR}/supacrypt.pb.h"
        "${PROTO_GENERATED_DIR}/supacrypt.pb.cc"
        "${PROTO_GENERATED_DIR}/supacrypt.grpc.pb.h"
        "${PROTO_GENERATED_DIR}/supacrypt.grpc.pb.cc"
    )

    # Custom command to generate protobuf sources
    add_custom_command(
        OUTPUT ${PROTO_GENERATED_FILES}
        COMMAND ${PROTOC_EXECUTABLE}
        ARGS
            --proto_path=${PROTO_DIR}
            --cpp_out=${PROTO_GENERATED_DIR}
            --grpc_out=${PROTO_GENERATED_DIR}
            --plugin=protoc-gen-grpc=${GRPC_CPP_PLUGIN}
            ${PROTO_FILE}
        DEPENDS ${PROTO_FILE}
        COMMENT "Generating protobuf and gRPC sources for supacrypt.proto"
        VERBATIM
    )

    # Create a custom target for proto generation
    add_custom_target(generate_protos
        DEPENDS ${PROTO_GENERATED_FILES}
        COMMENT "Ensuring protobuf sources are generated"
    )

    # Create a library target for generated sources
    add_library(supacrypt_proto STATIC ${PROTO_GENERATED_FILES})

    # Configure the proto library
    target_include_directories(supacrypt_proto PUBLIC
        ${PROTO_INCLUDE_DIR}
        ${Protobuf_INCLUDE_DIRS}
    )

    target_link_libraries(supacrypt_proto PUBLIC
        protobuf::protobuf
        gRPC::grpc++
    )

    # Ensure proto generation happens before building the library
    add_dependencies(supacrypt_proto generate_protos)

    # Suppress warnings in generated code
    if(MSVC)
        target_compile_options(supacrypt_proto PRIVATE
            /wd4996  # 'function': was declared deprecated
            /wd4267  # 'var' : conversion from 'size_t' to 'type', possible loss of data
            /wd4244  # 'conversion' conversion from 'type1' to 'type2', possible loss of data
            /wd4800  # 'type' : forcing value to bool 'true' or 'false'
        )
    else()
        target_compile_options(supacrypt_proto PRIVATE
            -Wno-unused-parameter
            -Wno-array-bounds
            -Wno-deprecated-declarations
        )
    endif()

    # Make generated sources available to main project
    target_link_libraries(${PROJECT_NAME} INTERFACE supacrypt_proto)
    target_include_directories(${PROJECT_NAME} INTERFACE ${PROTO_INCLUDE_DIR})

    # Set global variables for use in other CMakeLists.txt files
    set(SUPACRYPT_PROTO_GENERATED_DIR "${PROTO_GENERATED_DIR}" PARENT_SCOPE)
    set(SUPACRYPT_PROTO_INCLUDE_DIR "${PROTO_INCLUDE_DIR}" PARENT_SCOPE)
    set(SUPACRYPT_PROTO_LIBRARY "supacrypt_proto" PARENT_SCOPE)

    message(STATUS "Protocol buffer configuration:")
    message(STATUS "  Proto file: ${PROTO_FILE}")
    message(STATUS "  Generated sources: ${PROTO_GENERATED_DIR}")
    message(STATUS "  Protoc: ${PROTOC_EXECUTABLE}")
    message(STATUS "  gRPC plugin: ${GRPC_CPP_PLUGIN}")
endfunction()

# Function to validate protobuf installation
function(validate_protobuf_installation)
    if(NOT ENABLE_GRPC)
        return()
    endif()

    # Check protobuf version compatibility
    if(Protobuf_VERSION VERSION_LESS "3.12.0")
        message(WARNING "Protobuf version ${Protobuf_VERSION} may be too old. Recommended: 3.12.0+")
    endif()

    # Check for C++17 compatibility
    if(Protobuf_VERSION VERSION_LESS "3.15.0" AND CMAKE_CXX_STANDARD GREATER_EQUAL 17)
        message(WARNING "Protobuf ${Protobuf_VERSION} may have C++17 compatibility issues. Consider upgrading to 3.15.0+")
    endif()

    # Verify gRPC plugin is available
    find_program(GRPC_CPP_PLUGIN grpc_cpp_plugin)
    if(NOT GRPC_CPP_PLUGIN)
        message(FATAL_ERROR "gRPC C++ plugin not found. Please install gRPC development tools.")
    endif()

    # Test protoc execution
    execute_process(
        COMMAND ${PROTOC_EXECUTABLE} --version
        OUTPUT_VARIABLE PROTOC_VERSION_OUTPUT
        ERROR_QUIET
    )

    if(PROTOC_VERSION_OUTPUT MATCHES "libprotoc ([0-9]+\\.[0-9]+\\.[0-9]+)")
        set(PROTOC_VERSION "${CMAKE_MATCH_1}")
        message(STATUS "protoc version: ${PROTOC_VERSION}")
        
        if(NOT PROTOC_VERSION VERSION_EQUAL Protobuf_VERSION)
            message(WARNING "protoc version (${PROTOC_VERSION}) differs from Protobuf library version (${Protobuf_VERSION})")
        endif()
    else()
        message(WARNING "Unable to determine protoc version")
    endif()
endfunction()

# Function to setup proto file watching for development
function(setup_proto_watching)
    if(NOT ENABLE_GRPC OR NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
        return()
    endif()

    # Find file watching tools for automatic regeneration during development
    find_program(INOTIFYWAIT_EXECUTABLE inotifywait)
    find_program(FSWATCH_EXECUTABLE fswatch)

    if(INOTIFYWAIT_EXECUTABLE OR FSWATCH_EXECUTABLE)
        message(STATUS "File watching available for proto regeneration during development")
        
        # Create a script for automatic proto regeneration
        set(WATCH_SCRIPT "${CMAKE_CURRENT_BINARY_DIR}/watch_protos.sh")
        
        if(INOTIFYWAIT_EXECUTABLE)
            file(WRITE "${WATCH_SCRIPT}"
                "#!/bin/bash\n"
                "while inotifywait -e modify ${PROTO_DIR}/*.proto; do\n"
                "    echo \"Proto file changed, regenerating...\"\n"
                "    ${CMAKE_COMMAND} --build ${CMAKE_CURRENT_BINARY_DIR} --target generate_protos\n"
                "done\n"
            )
        elseif(FSWATCH_EXECUTABLE)
            file(WRITE "${WATCH_SCRIPT}"
                "#!/bin/bash\n"
                "fswatch -o ${PROTO_DIR}/*.proto | while read f; do\n"
                "    echo \"Proto file changed, regenerating...\"\n"
                "    ${CMAKE_COMMAND} --build ${CMAKE_CURRENT_BINARY_DIR} --target generate_protos\n"
                "done\n"
            )
        endif()

        # Make script executable
        file(CHMOD "${WATCH_SCRIPT}" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE)
        
        # Add custom target for watching
        add_custom_target(watch_protos
            COMMAND "${WATCH_SCRIPT}"
            COMMENT "Watching proto files for changes..."
            VERBATIM
        )
    endif()
endfunction()

# Validate installation and setup watching
validate_protobuf_installation()
setup_proto_watching()