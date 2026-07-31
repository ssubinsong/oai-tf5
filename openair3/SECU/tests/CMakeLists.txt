# TF5 TESLA Unit Tests
#
# Per OAI convention (doc/UnitTests.md), tests are guarded with ENABLE_TESTS
# and linked to the 'tests' target for unified test building.
#
# Build all OAI tests:  ninja tests
# Build TF5 tests only: ninja tf5_tests
# Run TF5 tests:        ctest -R test_tf5_tesla

if(ENABLE_TESTS)

message(STATUS "Add TF5 TESLA tests")

# Common compile definitions for all TF5 tests
set(TF5_TEST_COMPILE_DEFS ENABLE_TF5)

# Common libraries for all TF5 tests
# - SECURITY: Core security library with TF5 TESLA implementation
# - LOG: OAI logging (provides g_log, logRecord_mt)
# - minimal_lib: Provides T tracer stubs (T_stdout, T_active, T_cache, etc.)
# - GTest::gtest: Google Test framework (we use custom main(), not gtest_main)
# - sodium: Ed25519 cryptography library (libsodium)
set(TF5_TEST_LIBS SECURITY LOG minimal_lib GTest::gtest sodium)

# Common include directories for TF5 tests
set(TF5_TEST_INCLUDE_DIRS ${OPENAIR_DIR}/common/utils/ds)

# Custom target to build only TF5 tests (use: ninja tf5_tests)
add_custom_target(tf5_tests)

# -----------------------------------------------------------------------------
# Crypto primitives tests
# -----------------------------------------------------------------------------
add_executable(test_tf5_tesla_crypto test_tf5_tesla_crypto.cpp)
add_dependencies(tests test_tf5_tesla_crypto)
add_dependencies(tf5_tests test_tf5_tesla_crypto)
target_link_libraries(test_tf5_tesla_crypto PRIVATE ${TF5_TEST_LIBS})
target_include_directories(test_tf5_tesla_crypto PRIVATE ${TF5_TEST_INCLUDE_DIRS})
target_compile_definitions(test_tf5_tesla_crypto PRIVATE ${TF5_TEST_COMPILE_DEFS})
add_test(NAME test_tf5_tesla_crypto COMMAND test_tf5_tesla_crypto)

# -----------------------------------------------------------------------------
# gNB-side tests
# -----------------------------------------------------------------------------
add_executable(test_tf5_tesla_gnb test_tf5_tesla_gnb.cpp)
add_dependencies(tests test_tf5_tesla_gnb)
add_dependencies(tf5_tests test_tf5_tesla_gnb)
target_include_directories(test_tf5_tesla_gnb PRIVATE ${OPENAIR3_DIR}/SECU)
target_link_libraries(test_tf5_tesla_gnb PRIVATE ${TF5_TEST_LIBS})
target_compile_definitions(test_tf5_tesla_gnb PRIVATE ${TF5_TEST_COMPILE_DEFS})
add_test(NAME test_tf5_tesla_gnb COMMAND test_tf5_tesla_gnb)

# -----------------------------------------------------------------------------
# UE-side tests
# -----------------------------------------------------------------------------
add_executable(test_tf5_tesla_ue test_tf5_tesla_ue.cpp)
add_dependencies(tests test_tf5_tesla_ue)
add_dependencies(tf5_tests test_tf5_tesla_ue)
target_include_directories(test_tf5_tesla_ue PRIVATE ${OPENAIR3_DIR}/SECU)
target_link_libraries(test_tf5_tesla_ue PRIVATE ${TF5_TEST_LIBS})
target_compile_definitions(test_tf5_tesla_ue PRIVATE ${TF5_TEST_COMPILE_DEFS})
add_test(NAME test_tf5_tesla_ue COMMAND test_tf5_tesla_ue)

# -----------------------------------------------------------------------------
# Serialization tests
# -----------------------------------------------------------------------------
add_executable(test_tf5_tesla_serial test_tf5_tesla_serial.cpp)
add_dependencies(tests test_tf5_tesla_serial)
add_dependencies(tf5_tests test_tf5_tesla_serial)
target_link_libraries(test_tf5_tesla_serial PRIVATE ${TF5_TEST_LIBS})
target_compile_definitions(test_tf5_tesla_serial PRIVATE ${TF5_TEST_COMPILE_DEFS})
add_test(NAME test_tf5_tesla_serial COMMAND test_tf5_tesla_serial)

# -----------------------------------------------------------------------------
# GG09 Schnorr IBS signature tests
# -----------------------------------------------------------------------------
add_executable(test_tf5_tesla_ibs test_tf5_tesla_ibs.cpp)
add_dependencies(tests test_tf5_tesla_ibs)
add_dependencies(tf5_tests test_tf5_tesla_ibs)
target_include_directories(test_tf5_tesla_ibs PRIVATE ${OPENAIR3_DIR}/SECU)
target_link_libraries(test_tf5_tesla_ibs PRIVATE ${TF5_TEST_LIBS})
target_compile_definitions(test_tf5_tesla_ibs PRIVATE ${TF5_TEST_COMPILE_DEFS})
add_test(NAME test_tf5_tesla_ibs COMMAND test_tf5_tesla_ibs)

# -----------------------------------------------------------------------------
# Timing and replay protection tests
# -----------------------------------------------------------------------------
add_executable(test_tf5_tesla_timing test_tf5_tesla_timing.cpp)
add_dependencies(tests test_tf5_tesla_timing)
add_dependencies(tf5_tests test_tf5_tesla_timing)
target_link_libraries(test_tf5_tesla_timing PRIVATE ${TF5_TEST_LIBS})
target_compile_definitions(test_tf5_tesla_timing PRIVATE ${TF5_TEST_COMPILE_DEFS})
add_test(NAME test_tf5_tesla_timing COMMAND test_tf5_tesla_timing)

# -----------------------------------------------------------------------------
# File I/O tests
# -----------------------------------------------------------------------------
add_executable(test_tf5_tesla_fileio test_tf5_tesla_fileio.cpp)
add_dependencies(tests test_tf5_tesla_fileio)
add_dependencies(tf5_tests test_tf5_tesla_fileio)
target_link_libraries(test_tf5_tesla_fileio PRIVATE ${TF5_TEST_LIBS})
target_compile_definitions(test_tf5_tesla_fileio PRIVATE ${TF5_TEST_COMPILE_DEFS})
add_test(NAME test_tf5_tesla_fileio COMMAND test_tf5_tesla_fileio)

endif(ENABLE_TESTS)
