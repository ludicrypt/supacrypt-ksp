# tests/unit/CMakeLists.txt - Unit tests for Supacrypt KSP

# Unit test executables
set(UNIT_TEST_SOURCES
    test_error_handling.cpp
    test_key_storage.cpp
    test_algorithm_provider.cpp
    test_grpc_backend.cpp
    test_ksp_provider.cpp
)

foreach(TEST_SOURCE ${UNIT_TEST_SOURCES})
    get_filename_component(TEST_NAME ${TEST_SOURCE} NAME_WE)
    
    add_executable(${TEST_NAME}
        ${TEST_SOURCE}
        test_main.cpp
    )
    
    target_link_libraries(${TEST_NAME}
        supacrypt::ksp
        ksp_test_utils
        GTest::gtest
        GTest::gmock
        GTest::gtest_main
    )
    
    target_include_directories(${TEST_NAME} PRIVATE
        ${CMAKE_CURRENT_BINARY_DIR}/..
    )
    
    # Add test to CTest
    add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
    
    # Set test properties
    set_tests_properties(${TEST_NAME} PROPERTIES
        TIMEOUT 60
        LABELS "unit"
    )
    
    # Windows-specific test settings
    if(WIN32)
        set_tests_properties(${TEST_NAME} PROPERTIES
            ENVIRONMENT "PATH=${CMAKE_BINARY_DIR}/bin;$ENV{PATH}"
        )
    endif()
endforeach()

message(STATUS "Configured ${UNIT_TEST_SOURCES} unit tests")