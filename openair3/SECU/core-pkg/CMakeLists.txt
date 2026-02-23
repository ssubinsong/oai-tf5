# TF5 IBS PKG (Private Key Generator) Utilities
# Shared code is in parent SECURITY library
if(ENABLE_TF5)

message(STATUS "Building TF5 IBS PKG utilities")

# PKG library (for testing) - includes keygen and issue functions
add_library(tf5_ibs_pkg STATIC
    ${CMAKE_CURRENT_SOURCE_DIR}/tf5_ibs_keygen.c
    ${CMAKE_CURRENT_SOURCE_DIR}/tf5_ibs_issue.c
)
target_include_directories(tf5_ibs_pkg PUBLIC
    ${OPENAIR3_DIR}/SECU)
target_compile_definitions(tf5_ibs_pkg PRIVATE TF5_IBS_NO_MAIN)
target_link_libraries(tf5_ibs_pkg PRIVATE SECURITY sodium)

# Master keypair generation utility
add_executable(tf5_ibs_pkg_keygen ${CMAKE_CURRENT_SOURCE_DIR}/tf5_ibs_keygen.c)
target_include_directories(tf5_ibs_pkg_keygen PRIVATE
    ${OPENAIR3_DIR}/SECU)
target_link_libraries(tf5_ibs_pkg_keygen PRIVATE SECURITY sodium)

# gNB key issuance utility
add_executable(tf5_ibs_issue ${CMAKE_CURRENT_SOURCE_DIR}/tf5_ibs_issue.c)
target_include_directories(tf5_ibs_issue PRIVATE
    ${OPENAIR3_DIR}/SECU)
target_link_libraries(tf5_ibs_issue PRIVATE SECURITY sodium)

# Place PKG utilities directly in the build directory root for easy access
set_target_properties(tf5_ibs_pkg_keygen tf5_ibs_issue PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)

endif(ENABLE_TF5)
