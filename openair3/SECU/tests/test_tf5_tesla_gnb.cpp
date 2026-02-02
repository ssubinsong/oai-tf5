/**
 * @file test_tf5_tesla_gnb.cpp
 * @brief Unit tests for TF5 TESLA gNB-side functions
 *
 * Tests for:
 * - tf5_tesla_gnb_init(): gNB state initialization
 * - tf5_tesla_gnb_get_interval(): Interval index calculation
 * - tf5_tesla_gnb_prepare_extension(): Extension generation
 * - tf5_tesla_gnb_free(): Resource cleanup
 */

#include <gtest/gtest.h>
#include <cstring>
#include <cstdlib>

extern "C" {
#include "openair3/SECU/tf5_tesla.h"
#include "common/config/config_userapi.h"
#include "log.h"

// Required by OAI logging infrastructure
configmodule_interface_t *uniqCfg;
void exit_function(const char *file, const char *function, const int line, const char *s, const int assert) {
    if (assert) abort();
    else exit(EXIT_SUCCESS);
}
}

#include "tf5_test_vectors.h"

class TF5GnbTest : public ::testing::Test {
protected:
    tf5_gnb_state_t gnb_state;
    uint8_t test_private_key[TF5_BLS_SECRET_KEY_LEN];
    tf5_tesla_slot_time_t t0;

    void SetUp() override {
        // Initialize BLS library
        tf5_tesla_bls_init();

        // Clear state
        memset(&gnb_state, 0, sizeof(gnb_state));

        // Use test private key
        memcpy(test_private_key, tf5_test::TV_BLS_SECRET_KEY, TF5_BLS_SECRET_KEY_LEN);

        // Set T_0 to SFN=0, slot=0
        t0 = tf5_slot_time_make(tf5_test::TV_T0_SFN, tf5_test::TV_T0_SLOT);
    }

    void TearDown() override {
        tf5_tesla_gnb_free(&gnb_state);
    }

    // Helper to initialize gNB with default test parameters
    int initGnbDefault(uint32_t chain_len = 100) {
        return tf5_tesla_gnb_init(
            &gnb_state,
            tf5_test::TV_EXT_T_INT_MS,   // t_int_ms = 20
            tf5_test::TV_EXT_D,          // d = 1
            chain_len,
            test_private_key,
            &t0,
            tf5_test::TV_SLOTS_PER_FRAME // slots_per_frame = 20
        );
    }
};

// ============================================================================
// Initialization Tests (tf5_tesla_gnb_init)
// ============================================================================

TEST_F(TF5GnbTest, GnbInit_Success) {
    int ret = initGnbDefault();

    EXPECT_EQ(0, ret) << "gNB init should return 0 on success";
    EXPECT_TRUE(gnb_state.initialized) << "State should be marked as initialized";
}

TEST_F(TF5GnbTest, GnbInit_KeyChainGenerated) {
    int ret = initGnbDefault(100);

    EXPECT_EQ(0, ret);
    EXPECT_NE(nullptr, gnb_state.key_chain) << "Key chain should be allocated";
    EXPECT_EQ(100u, gnb_state.key_chain_len) << "Chain length should match requested";
}

TEST_F(TF5GnbTest, GnbInit_BootstrapKeyComputed) {
    int ret = initGnbDefault(10);
    EXPECT_EQ(0, ret);

    // Bootstrap key K_{-1} = F(K_0)
    uint8_t computed_bootstrap[TF5_TESLA_KEY_LEN];
    tf5_tesla_chain_key(gnb_state.key_chain[0], computed_bootstrap);

    EXPECT_EQ(0, memcmp(gnb_state.k_bootstrap, computed_bootstrap, TF5_TESLA_KEY_LEN))
        << "Bootstrap key K_{-1} should equal F(K_0)";
}

TEST_F(TF5GnbTest, GnbInit_KeyChainValid) {
    int ret = initGnbDefault(10);
    EXPECT_EQ(0, ret);

    // Verify key chain: K_i = F(K_{i+1})
    for (uint32_t i = 0; i < gnb_state.key_chain_len - 1; i++) {
        uint8_t computed[TF5_TESLA_KEY_LEN];
        tf5_tesla_chain_key(gnb_state.key_chain[i + 1], computed);

        EXPECT_EQ(0, memcmp(gnb_state.key_chain[i], computed, TF5_TESLA_KEY_LEN))
            << "K_" << i << " should equal F(K_" << (i + 1) << ")";
    }
}

TEST_F(TF5GnbTest, GnbInit_ParamsStored) {
    int ret = initGnbDefault(100);
    EXPECT_EQ(0, ret);

    EXPECT_EQ(tf5_test::TV_EXT_T_INT_MS, gnb_state.tesla_params.t_int_ms);
    EXPECT_EQ(tf5_test::TV_EXT_D, gnb_state.tesla_params.d);
    EXPECT_EQ(100u, gnb_state.tesla_params.chain_len);
    EXPECT_EQ(tf5_test::TV_SLOTS_PER_FRAME, gnb_state.slots_per_frame);
}

TEST_F(TF5GnbTest, GnbInit_NullState_ReturnsError) {
    int ret = tf5_tesla_gnb_init(
        nullptr,
        tf5_test::TV_EXT_T_INT_MS,
        tf5_test::TV_EXT_D,
        100,
        test_private_key,
        &t0,
        tf5_test::TV_SLOTS_PER_FRAME
    );

    EXPECT_LT(ret, 0) << "Null state should return error";
}

TEST_F(TF5GnbTest, GnbInit_NullPrivateKey_ReturnsError) {
    int ret = tf5_tesla_gnb_init(
        &gnb_state,
        tf5_test::TV_EXT_T_INT_MS,
        tf5_test::TV_EXT_D,
        100,
        nullptr,
        &t0,
        tf5_test::TV_SLOTS_PER_FRAME
    );

    EXPECT_LT(ret, 0) << "Null private key should return error";
}

TEST_F(TF5GnbTest, GnbInit_NullT0_ReturnsError) {
    int ret = tf5_tesla_gnb_init(
        &gnb_state,
        tf5_test::TV_EXT_T_INT_MS,
        tf5_test::TV_EXT_D,
        100,
        test_private_key,
        nullptr,
        tf5_test::TV_SLOTS_PER_FRAME
    );

    EXPECT_LT(ret, 0) << "Null T_0 should return error";
}

TEST_F(TF5GnbTest, GnbInit_ZeroChainLen_ReturnsError) {
    int ret = tf5_tesla_gnb_init(
        &gnb_state,
        tf5_test::TV_EXT_T_INT_MS,
        tf5_test::TV_EXT_D,
        0,  // Invalid chain length
        test_private_key,
        &t0,
        tf5_test::TV_SLOTS_PER_FRAME
    );

    EXPECT_LT(ret, 0) << "Zero chain length should return error";
}

TEST_F(TF5GnbTest, GnbInit_ZeroInterval_ReturnsError) {
    int ret = tf5_tesla_gnb_init(
        &gnb_state,
        0,  // Invalid interval duration
        tf5_test::TV_EXT_D,
        100,
        test_private_key,
        &t0,
        tf5_test::TV_SLOTS_PER_FRAME
    );

    EXPECT_LT(ret, 0) << "Zero interval duration should return error";
}

// ============================================================================
// Interval Calculation Tests (tf5_tesla_gnb_get_interval)
// ============================================================================

TEST_F(TF5GnbTest, GetInterval_AtT0_ReturnsZero) {
    ASSERT_EQ(0, initGnbDefault(100));

    uint32_t interval = tf5_tesla_gnb_get_interval(&gnb_state, t0.sfn, t0.slot);

    EXPECT_EQ(0u, interval) << "At T_0, interval should be 0";
}

TEST_F(TF5GnbTest, GetInterval_AfterOneInterval) {
    ASSERT_EQ(0, initGnbDefault(100));

    // T_int = 20ms, with 20 slots/frame (10ms frame), each slot = 0.5ms
    // 20ms = 40 slots
    uint16_t sfn = 0;
    uint16_t slot = 40;  // 40 slots = 20ms = 1 interval

    uint32_t interval = tf5_tesla_gnb_get_interval(&gnb_state, sfn, slot);

    EXPECT_EQ(1u, interval) << "After T_int (20ms = 40 slots), interval should be 1";
}

TEST_F(TF5GnbTest, GetInterval_PartialInterval_ReturnsFloor) {
    ASSERT_EQ(0, initGnbDefault(100));

    // Less than one full interval (30 slots = 15ms)
    uint16_t sfn = 0;
    uint16_t slot = 30;

    uint32_t interval = tf5_tesla_gnb_get_interval(&gnb_state, sfn, slot);

    EXPECT_EQ(0u, interval) << "Partial interval should floor to 0";
}

TEST_F(TF5GnbTest, GetInterval_MultipleIntervals) {
    ASSERT_EQ(0, initGnbDefault(100));

    // 5 intervals = 100ms = 200 slots
    // With 20 slots/frame, 200 slots = 10 frames = SFN 10, slot 0
    uint16_t sfn = 10;
    uint16_t slot = 0;

    uint32_t interval = tf5_tesla_gnb_get_interval(&gnb_state, sfn, slot);

    EXPECT_EQ(5u, interval) << "200 slots at 20 slots/frame = 5 intervals";
}

TEST_F(TF5GnbTest, GetInterval_UninitializedState_ReturnsZero) {
    // Don't initialize the state
    tf5_gnb_state_t uninit_state;
    memset(&uninit_state, 0, sizeof(uninit_state));

    uint32_t interval = tf5_tesla_gnb_get_interval(&uninit_state, 100, 10);

    EXPECT_EQ(0u, interval) << "Uninitialized state should return 0";
}

// ============================================================================
// Extension Preparation Tests (tf5_tesla_gnb_prepare_extension)
// ============================================================================

TEST_F(TF5GnbTest, PrepareExtension_Success) {
    ASSERT_EQ(0, initGnbDefault(100));

    tf5_tesla_extension_t ext;
    const char sib1[] = "Test SIB1 content";

    int ret = tf5_tesla_gnb_prepare_extension(
        &gnb_state,
        5,   // SFN
        10,  // slot
        (const uint8_t*)sib1,
        strlen(sib1),
        &ext
    );

    EXPECT_EQ(0, ret) << "prepare_extension should return 0 on success";
}

TEST_F(TF5GnbTest, PrepareExtension_CorrectVersion) {
    ASSERT_EQ(0, initGnbDefault(100));

    tf5_tesla_extension_t ext;
    const char sib1[] = "Test SIB1 content";

    tf5_tesla_gnb_prepare_extension(&gnb_state, 5, 10, (const uint8_t*)sib1, strlen(sib1), &ext);

    EXPECT_EQ(TF5_VERSION, ext.te_version) << "Extension version should be TF5_VERSION";
}

TEST_F(TF5GnbTest, PrepareExtension_CorrectInterval) {
    ASSERT_EQ(0, initGnbDefault(100));

    tf5_tesla_extension_t ext;
    const char sib1[] = "Test SIB1 content";

    // At SFN=5, slot=0, with 20 slots/frame:
    // Total slots = 5*20 + 0 = 100 slots
    // At 0.5ms/slot, this is 50ms = 2.5 intervals, floor = 2
    tf5_tesla_gnb_prepare_extension(&gnb_state, 5, 0, (const uint8_t*)sib1, strlen(sib1), &ext);

    EXPECT_EQ(2u, ext.i) << "Interval index should match calculation";
}

TEST_F(TF5GnbTest, PrepareExtension_CorrectKeyDisclosure_NormalInterval) {
    ASSERT_EQ(0, initGnbDefault(100));

    tf5_tesla_extension_t ext;
    const char sib1[] = "Test SIB1 content";

    // Force interval 5 (200 slots = SFN 10, slot 0)
    tf5_tesla_gnb_prepare_extension(&gnb_state, 10, 0, (const uint8_t*)sib1, strlen(sib1), &ext);

    // At interval 5 with d=1, should disclose K_{5-1} = K_4
    EXPECT_EQ(0, memcmp(ext.key_disclosure, gnb_state.key_chain[4], TF5_TESLA_KEY_LEN))
        << "At interval 5 with d=1, should disclose K_4";
}

TEST_F(TF5GnbTest, PrepareExtension_BootstrapInterval_DiscloseKMinus1) {
    ASSERT_EQ(0, initGnbDefault(100));

    tf5_tesla_extension_t ext;
    const char sib1[] = "Test SIB1 content";

    // At interval 0 (T_0), should disclose K_{-1} (bootstrap key)
    tf5_tesla_gnb_prepare_extension(&gnb_state, 0, 0, (const uint8_t*)sib1, strlen(sib1), &ext);

    EXPECT_EQ(0, memcmp(ext.key_disclosure, gnb_state.k_bootstrap, TF5_TESLA_KEY_LEN))
        << "At interval 0 with d=1, should disclose K_{-1} (bootstrap key)";
}

TEST_F(TF5GnbTest, PrepareExtension_TagComputed) {
    ASSERT_EQ(0, initGnbDefault(100));

    tf5_tesla_extension_t ext;
    const char sib1[] = "Test SIB1 content";

    tf5_tesla_gnb_prepare_extension(&gnb_state, 5, 0, (const uint8_t*)sib1, strlen(sib1), &ext);

    // Tag should not be all zeros
    bool all_zeros = true;
    for (int i = 0; i < TF5_TESLA_TAG_LEN; i++) {
        if (ext.tesla_tag[i] != 0) {
            all_zeros = false;
            break;
        }
    }
    EXPECT_FALSE(all_zeros) << "TESLA tag should be computed (not all zeros)";
}

TEST_F(TF5GnbTest, PrepareExtension_SignatureComputed) {
    ASSERT_EQ(0, initGnbDefault(100));

    tf5_tesla_extension_t ext;
    const char sib1[] = "Test SIB1 content";

    tf5_tesla_gnb_prepare_extension(&gnb_state, 5, 0, (const uint8_t*)sib1, strlen(sib1), &ext);

    // Signature should not be all zeros
    bool all_zeros = true;
    for (int i = 0; i < TF5_TESLA_SIG_LEN; i++) {
        if (ext.signature[i] != 0) {
            all_zeros = false;
            break;
        }
    }
    EXPECT_FALSE(all_zeros) << "BLS signature should be computed (not all zeros)";
}

TEST_F(TF5GnbTest, PrepareExtension_ParamsIncluded) {
    ASSERT_EQ(0, initGnbDefault(100));

    tf5_tesla_extension_t ext;
    const char sib1[] = "Test SIB1 content";

    tf5_tesla_gnb_prepare_extension(&gnb_state, 5, 0, (const uint8_t*)sib1, strlen(sib1), &ext);

    EXPECT_EQ(gnb_state.tesla_params.t_int_ms, ext.tesla_params.t_int_ms);
    EXPECT_EQ(gnb_state.tesla_params.d, ext.tesla_params.d);
    EXPECT_EQ(gnb_state.tesla_params.chain_len, ext.tesla_params.chain_len);
}

TEST_F(TF5GnbTest, PrepareExtension_IntervalExceedsChain_ReturnsError) {
    // Initialize with small chain
    ASSERT_EQ(0, initGnbDefault(10));

    tf5_tesla_extension_t ext;
    const char sib1[] = "Test SIB1 content";

    // Try to get extension for interval 15 (10 * 40 slots = SFN 20)
    // which exceeds chain length of 10
    int ret = tf5_tesla_gnb_prepare_extension(
        &gnb_state,
        20, 0,  // Way beyond chain length
        (const uint8_t*)sib1, strlen(sib1), &ext
    );

    EXPECT_LT(ret, 0) << "Interval exceeding chain length should return error";
}

TEST_F(TF5GnbTest, PrepareExtension_NullState_ReturnsError) {
    tf5_tesla_extension_t ext;
    const char sib1[] = "Test SIB1 content";

    int ret = tf5_tesla_gnb_prepare_extension(
        nullptr, 5, 0, (const uint8_t*)sib1, strlen(sib1), &ext
    );

    EXPECT_LT(ret, 0) << "Null state should return error";
}

TEST_F(TF5GnbTest, PrepareExtension_NullSib1_ReturnsError) {
    ASSERT_EQ(0, initGnbDefault(100));

    tf5_tesla_extension_t ext;

    int ret = tf5_tesla_gnb_prepare_extension(
        &gnb_state, 5, 0, nullptr, 10, &ext
    );

    EXPECT_LT(ret, 0) << "Null SIB1 should return error";
}

TEST_F(TF5GnbTest, PrepareExtension_NullExt_ReturnsError) {
    ASSERT_EQ(0, initGnbDefault(100));

    const char sib1[] = "Test SIB1 content";

    int ret = tf5_tesla_gnb_prepare_extension(
        &gnb_state, 5, 0, (const uint8_t*)sib1, strlen(sib1), nullptr
    );

    EXPECT_LT(ret, 0) << "Null extension output should return error";
}

// ============================================================================
// Free Tests (tf5_tesla_gnb_free)
// ============================================================================

TEST_F(TF5GnbTest, GnbFree_Success) {
    ASSERT_EQ(0, initGnbDefault(100));
    ASSERT_NE(nullptr, gnb_state.key_chain);

    tf5_tesla_gnb_free(&gnb_state);

    EXPECT_FALSE(gnb_state.initialized) << "State should be marked as not initialized";
    EXPECT_EQ(nullptr, gnb_state.key_chain) << "Key chain should be freed";
}

TEST_F(TF5GnbTest, GnbFree_NullState_NoOp) {
    // Should not crash
    tf5_tesla_gnb_free(nullptr);
    SUCCEED();
}

TEST_F(TF5GnbTest, GnbFree_UninitializedState_NoOp) {
    tf5_gnb_state_t uninit_state;
    memset(&uninit_state, 0, sizeof(uninit_state));

    // Should not crash
    tf5_tesla_gnb_free(&uninit_state);
    SUCCEED();
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char **argv) {
    logInit();
    g_log->log_component[NR_RRC].level = OAILOG_WARNING;
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
