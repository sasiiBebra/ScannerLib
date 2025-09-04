cmake_minimum_required(VERSION 3.20)

# Fetch GoogleTest
include(FetchContent)

FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.14.0
)

# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(googletest)

# Test sources
set(TEST_SOURCES
    test_main.cpp
    test_hashbase.cpp
    test_md5compute.cpp
    test_scanner.cpp
    test_pathchecker.cpp
)

# Create test executable
add_executable(scanner_tests ${TEST_SOURCES})

# Link libraries
target_link_libraries(scanner_tests
    PRIVATE
        scanner_core
        GTest::gtest_main
        GTest::gmock_main
)

# Include directories
target_include_directories(scanner_tests
    PRIVATE
        ${CMAKE_SOURCE_DIR}/core
)

# Discover tests
include(GoogleTest)
gtest_discover_tests(scanner_tests)

# Organize test files in IDE
source_group("Test Files" FILES ${TEST_SOURCES})

# Copy test data if needed
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/test_data)
    file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/test_data 
         DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
endif()