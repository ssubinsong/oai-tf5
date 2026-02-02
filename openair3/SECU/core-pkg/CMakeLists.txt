# TF5 IBS PKG (Private Key Generator) Utilities
# Only builds executables - shared code is in parent SECURITY library
if(ENABLE_TF5)

message(STATUS "Building TF5 IBS PKG utilities")

set(BLST_DIR ${CMAKE_SOURCE_DIR}/cmake_targets/third_party/blst)

# Master keypair generation utility
add_executable(tf5_ibs_pkg_keygen ${CMAKE_CURRENT_SOURCE_DIR}/tf5_ibs_keygen.c)
target_include_directories(tf5_ibs_pkg_keygen PRIVATE
    ${OPENAIR3_DIR}/SECU
    ${BLST_DIR}/bindings)
target_link_libraries(tf5_ibs_pkg_keygen PRIVATE SECURITY blst)

# gNB key issuance utility
add_executable(tf5_ibs_issue ${CMAKE_CURRENT_SOURCE_DIR}/tf5_ibs_issue.c)
target_include_directories(tf5_ibs_issue PRIVATE
    ${OPENAIR3_DIR}/SECU
    ${BLST_DIR}/bindings)
target_link_libraries(tf5_ibs_issue PRIVATE SECURITY blst)

endif(ENABLE_TF5)
