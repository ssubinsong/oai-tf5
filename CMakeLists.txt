cmake_minimum_required(VERSION 3.16)
project(tf5-core-pkg C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

# BLST library path - configurable via -DBLST_DIR=<path>
# Default: use local submodule at third_party/blst
if(NOT DEFINED BLST_DIR)
    set(BLST_DIR "${CMAKE_SOURCE_DIR}/third_party/blst")
endif()

# Convert to absolute path (required for INTERFACE_INCLUDE_DIRECTORIES)
# Resolve relative paths from source directory, not build directory
get_filename_component(BLST_DIR "${BLST_DIR}" ABSOLUTE BASE_DIR "${CMAKE_SOURCE_DIR}")

# Verify blst directory exists
if(NOT EXISTS "${BLST_DIR}/src/server.c")
    message(FATAL_ERROR
        "BLST library not found at ${BLST_DIR}\n"
        "Options:\n"
        "  1. Initialize submodule: git submodule update --init\n"
        "  2. Specify path: cmake -DBLST_DIR=/path/to/blst ..")
endif()

message(STATUS "Using BLST library from: ${BLST_DIR}")

set(BLST_LIB "${BLST_DIR}/libblst.a")

# Build BLST using its native build script (handles platform-specific assembly)
# The build script creates libblst.a in the blst root directory
add_custom_command(
    OUTPUT ${BLST_LIB}
    COMMAND ${CMAKE_COMMAND} -E chdir ${BLST_DIR} ./build.sh
    DEPENDS ${BLST_DIR}/build.sh
    COMMENT "Building blst library with native build script"
    VERBATIM
)

add_custom_target(blst_build DEPENDS ${BLST_LIB})

# Create imported library target for blst
add_library(blst STATIC IMPORTED)
set_target_properties(blst PROPERTIES
    IMPORTED_LOCATION ${BLST_LIB}
    INTERFACE_INCLUDE_DIRECTORIES ${BLST_DIR}/bindings
)
add_dependencies(blst blst_build)

# IBS common library (shared code)
add_library(tf5_ibs_common STATIC
    src/tf5_ibs_common.c
)
target_include_directories(tf5_ibs_common PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${BLST_DIR}/bindings
)
target_link_libraries(tf5_ibs_common PRIVATE blst)
add_dependencies(tf5_ibs_common blst_build)

# IBS full library (includes keygen and issue functions for testing)
# Compile library functions separately from main()
add_library(tf5_ibs_full STATIC
    src/tf5_ibs_common.c
    src/tf5_ibs_keygen.c
    src/tf5_ibs_issue.c
)
target_include_directories(tf5_ibs_full PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${BLST_DIR}/bindings
)
target_compile_definitions(tf5_ibs_full PRIVATE TF5_IBS_NO_MAIN)
target_link_libraries(tf5_ibs_full PRIVATE blst)
add_dependencies(tf5_ibs_full blst_build)

# Master keypair generation utility
add_executable(tf5_ibs_pkg_keygen src/tf5_ibs_keygen.c)
target_include_directories(tf5_ibs_pkg_keygen PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${BLST_DIR}/bindings
)
target_link_libraries(tf5_ibs_pkg_keygen PRIVATE tf5_ibs_common blst)

# gNB secret key issuance utility
add_executable(tf5_ibs_issue src/tf5_ibs_issue.c)
target_include_directories(tf5_ibs_issue PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${BLST_DIR}/bindings
)
target_link_libraries(tf5_ibs_issue PRIVATE tf5_ibs_common blst)

# Installation
install(TARGETS tf5_ibs_pkg_keygen tf5_ibs_issue
    RUNTIME DESTINATION bin
)

install(FILES include/tf5_ibs_pkg.h
    DESTINATION include
)

# =============================================================================
# Unit Tests (enabled by default, disable with -DENABLE_TESTS=OFF)
# =============================================================================

option(ENABLE_TESTS "Build unit tests" ON)

if(ENABLE_TESTS)
    message(STATUS "Building TF5 IBS PKG unit tests")
    enable_testing()
    find_package(GTest REQUIRED)

    add_executable(test_tf5_ibs_pkg tests/test_tf5_ibs_pkg.cpp)
    target_include_directories(test_tf5_ibs_pkg PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${BLST_DIR}/bindings
    )
    target_link_libraries(test_tf5_ibs_pkg PRIVATE tf5_ibs_full blst GTest::gtest)
    add_test(NAME test_tf5_ibs_pkg COMMAND test_tf5_ibs_pkg)
endif()
