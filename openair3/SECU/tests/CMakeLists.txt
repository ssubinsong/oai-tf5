message(STATUS "Add TF5 TESLA tests")

# Common compile definitions and include directories for all TF5 tests
set(TF5_TEST_COMPILE_DEFS ENABLE_TF5)

# Common libraries for all TF5 tests
# - SECURITY: Core security library with TF5 TESLA implementation
# - LOG: OAI logging (provides g_log, logRecord_mt)
# - minimal_lib: Provides T tracer stubs (T_stdout, T_active, T_cache, etc.)
# - GTest::gtest: Google Test framework
# - blst: BLS12-381 cryptography library
set(TF5_TEST_LIBS SECURITY LOG minimal_lib GTest::gtest blst)

# Common include directories for TF5 tests
set(TF5_TEST_INCLUDE_DIRS ${OPENAIR_DIR}/common/utils/ds)

# Custom target to build only TF5 tests (use: ninja tf5_tests)
add_custom_target(tf5_tests)

# Crypto primitives tests
add_executable(test_tf5_tesla_crypto test_tf5_tesla_crypto.cpp)
add_dependencies(tests test_tf5_tesla_crypto)
add_dependencies(tf5_tests test_tf5_tesla_crypto)
target_link_libraries(test_tf5_tesla_crypto PRIVATE ${TF5_TEST_LIBS})
target_include_directories(test_tf5_tesla_crypto PRIVATE ${TF5_TEST_INCLUDE_DIRS})
target_compile_definitions(test_tf5_tesla_crypto PRIVATE ${TF5_TEST_COMPILE_DEFS})
add_test(NAME test_tf5_tesla_crypto COMMAND ./test_tf5_tesla_crypto)

# gNB-side tests
add_executable(test_tf5_tesla_gnb test_tf5_tesla_gnb.cpp)
add_dependencies(tests test_tf5_tesla_gnb)
add_dependencies(tf5_tests test_tf5_tesla_gnb)
target_link_libraries(test_tf5_tesla_gnb PRIVATE ${TF5_TEST_LIBS})
target_compile_definitions(test_tf5_tesla_gnb PRIVATE ${TF5_TEST_COMPILE_DEFS})
add_test(NAME test_tf5_tesla_gnb COMMAND ./test_tf5_tesla_gnb)

# UE-side tests
add_executable(test_tf5_tesla_ue test_tf5_tesla_ue.cpp)
add_dependencies(tests test_tf5_tesla_ue)
add_dependencies(tf5_tests test_tf5_tesla_ue)
target_link_libraries(test_tf5_tesla_ue PRIVATE ${TF5_TEST_LIBS})
target_compile_definitions(test_tf5_tesla_ue PRIVATE ${TF5_TEST_COMPILE_DEFS})
add_test(NAME test_tf5_tesla_ue COMMAND ./test_tf5_tesla_ue)

# Serialization tests
add_executable(test_tf5_tesla_serial test_tf5_tesla_serial.cpp)
add_dependencies(tests test_tf5_tesla_serial)
add_dependencies(tf5_tests test_tf5_tesla_serial)
target_link_libraries(test_tf5_tesla_serial PRIVATE ${TF5_TEST_LIBS})
target_compile_definitions(test_tf5_tesla_serial PRIVATE ${TF5_TEST_COMPILE_DEFS})
add_test(NAME test_tf5_tesla_serial COMMAND ./test_tf5_tesla_serial)

# BLS signature tests
add_executable(test_tf5_tesla_bls test_tf5_tesla_bls.cpp)
add_dependencies(tests test_tf5_tesla_bls)
add_dependencies(tf5_tests test_tf5_tesla_bls)
target_link_libraries(test_tf5_tesla_bls PRIVATE ${TF5_TEST_LIBS})
target_compile_definitions(test_tf5_tesla_bls PRIVATE ${TF5_TEST_COMPILE_DEFS})
add_test(NAME test_tf5_tesla_bls COMMAND ./test_tf5_tesla_bls)

# End-to-end integration tests
add_executable(test_tf5_tesla_e2e test_tf5_tesla_e2e.cpp)
add_dependencies(tests test_tf5_tesla_e2e)
add_dependencies(tf5_tests test_tf5_tesla_e2e)
target_link_libraries(test_tf5_tesla_e2e PRIVATE ${TF5_TEST_LIBS})
target_compile_definitions(test_tf5_tesla_e2e PRIVATE ${TF5_TEST_COMPILE_DEFS})
add_test(NAME test_tf5_tesla_e2e COMMAND ./test_tf5_tesla_e2e)

# Timing and replay protection tests
add_executable(test_tf5_tesla_timing test_tf5_tesla_timing.cpp)
add_dependencies(tests test_tf5_tesla_timing)
add_dependencies(tf5_tests test_tf5_tesla_timing)
target_link_libraries(test_tf5_tesla_timing PRIVATE ${TF5_TEST_LIBS})
target_compile_definitions(test_tf5_tesla_timing PRIVATE ${TF5_TEST_COMPILE_DEFS})
add_test(NAME test_tf5_tesla_timing COMMAND ./test_tf5_tesla_timing)

# File I/O tests
add_executable(test_tf5_tesla_fileio test_tf5_tesla_fileio.cpp)
add_dependencies(tests test_tf5_tesla_fileio)
add_dependencies(tf5_tests test_tf5_tesla_fileio)
target_link_libraries(test_tf5_tesla_fileio PRIVATE ${TF5_TEST_LIBS})
target_compile_definitions(test_tf5_tesla_fileio PRIVATE ${TF5_TEST_COMPILE_DEFS})
add_test(NAME test_tf5_tesla_fileio COMMAND ./test_tf5_tesla_fileio)
