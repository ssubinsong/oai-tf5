/**
 * @file test_tf5_tesla_gnb.cpp
 * @brief Unit tests for TF5 TESLA gNB-side functions
 *
 * Tests for:
 * - tf5_tesla_gnb_init(): gNB state initialization
 * - tf5_tesla_gnb_free(): Resource cleanup
 */

#define TF5_TEST_NEEDS_OAI_STUBS
#include "tf5_test_common.h"

extern "C" {
#include "openair3/SECU/tf5_tesla.h"
}

#include "tf5_test_vectors.h"

bool TF5IbsTestFixture::ibs_initialized = false;

class TF5GnbTest : public TF5IbsTestFixture {
protected:
    tf5_gnb_state_t gnb_state;
    tf5_slot_time_t t0;

    void SetUp() override {
        TF5IbsTestFixture::SetUp();

        // Generate PKG keys for signing
        setupTestDir("tf5_gnb_test");
        generateAndLoadKeys();

        // Clear state
        memset(&gnb_state, 0, sizeof(gnb_state));

        // Set T_0 to SFN=0, slot=0
        t0 = tf5_slot_time_make(tf5_test::TV_T0_SFN, tf5_test::TV_T0_SLOT);
    }

    void TearDown() override {
        tf5_gnb_free(&gnb_state);
        TF5IbsTestFixture::TearDown();
    }

    // Helper to initialize gNB with default test parameters
    int initGnbDefault(uint32_t chain_len = 100) {
        return tf5_gnb_init(
            &gnb_state,
            tf5_test::TV_EXT_T_INT_MS,   // t_int_ms = 160
            tf5_test::TV_EXT_D,          // d = 1
            chain_len,
            ibs_sk,                      // 64B sk_id: y[32] + pk[32] from PKG
            &t0,
            tf5_test::TV_SLOTS_PER_FRAME // slots_per_frame = 20
        );
    }
};

// ============================================================================
// Initialization Tests (tf5_gnb_init)
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

    // Bootstrap key K_{-1} = F(K_0), stored at index 0
    uint8_t computed_bootstrap[TF5_TESLA_KEY_LEN];
    tf5_chain_key(gnb_state.key_chain[tf5_key_interval_to_index(0)], computed_bootstrap);

    EXPECT_EQ(0, memcmp(gnb_state.key_chain[tf5_key_interval_to_index(-1)], computed_bootstrap, TF5_TESLA_KEY_LEN))
        << "Bootstrap key K_{-1} at index 0 should equal F(K_0)";
}

TEST_F(TF5GnbTest, GnbInit_KeyChainValid) {
    int ret = initGnbDefault(10);
    EXPECT_EQ(0, ret);

    for (int32_t i = -1; i < (int32_t)gnb_state.key_chain_len - 1; i++) {
        uint8_t computed[TF5_TESLA_KEY_LEN];
        tf5_chain_key(gnb_state.key_chain[tf5_key_interval_to_index(i + 1)], computed);

        EXPECT_EQ(0, memcmp(gnb_state.key_chain[tf5_key_interval_to_index(i)], computed, TF5_TESLA_KEY_LEN))
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
    int ret = tf5_gnb_init(
        nullptr,
        tf5_test::TV_EXT_T_INT_MS,
        tf5_test::TV_EXT_D,
        100,
        ibs_sk,
        &t0,
        tf5_test::TV_SLOTS_PER_FRAME
    );

    EXPECT_LT(ret, 0) << "Null state should return error";
}

TEST_F(TF5GnbTest, GnbInit_NullPrivateKey_ReturnsError) {
    int ret = tf5_gnb_init(
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
    int ret = tf5_gnb_init(
        &gnb_state,
        tf5_test::TV_EXT_T_INT_MS,
        tf5_test::TV_EXT_D,
        100,
        ibs_sk,
        nullptr,
        tf5_test::TV_SLOTS_PER_FRAME
    );

    EXPECT_LT(ret, 0) << "Null T_0 should return error";
}

TEST_F(TF5GnbTest, GnbInit_ZeroChainLen_ReturnsError) {
    int ret = tf5_gnb_init(
        &gnb_state,
        tf5_test::TV_EXT_T_INT_MS,
        tf5_test::TV_EXT_D,
        0,
        ibs_sk,
        &t0,
        tf5_test::TV_SLOTS_PER_FRAME
    );

    EXPECT_LT(ret, 0) << "Zero chain length should return error";
}

TEST_F(TF5GnbTest, GnbInit_ZeroInterval_ReturnsError) {
    int ret = tf5_gnb_init(
        &gnb_state,
        0,
        tf5_test::TV_EXT_D,
        100,
        ibs_sk,
        &t0,
        tf5_test::TV_SLOTS_PER_FRAME
    );

    EXPECT_LT(ret, 0) << "Zero interval duration should return error";
}

TEST_F(TF5GnbTest, GnbInit_DoubleInit_Succeeds) {
    ASSERT_EQ(0, initGnbDefault(50));
    EXPECT_TRUE(gnb_state.initialized);
    EXPECT_NE(nullptr, gnb_state.key_chain);

    int ret = tf5_gnb_init(
        &gnb_state,
        40, 2, 200,
        ibs_sk,
        &t0,
        tf5_test::TV_SLOTS_PER_FRAME
    );

    EXPECT_EQ(0, ret) << "Double init should succeed (reinit path)";
    EXPECT_EQ(200u, gnb_state.key_chain_len);
    EXPECT_EQ(40, gnb_state.tesla_params.t_int_ms);
    EXPECT_EQ(2, gnb_state.tesla_params.d);
}

TEST_F(TF5GnbTest, GnbInit_MinimalChain) {
    int ret = initGnbDefault(1);

    EXPECT_EQ(0, ret) << "chain_len = 1 should succeed";
    EXPECT_EQ(1u, gnb_state.key_chain_len);
    EXPECT_NE(nullptr, gnb_state.key_chain);
}

// ============================================================================
// Free Tests (tf5_gnb_free)
// ============================================================================

TEST_F(TF5GnbTest, GnbFree_Success) {
    ASSERT_EQ(0, initGnbDefault(100));
    ASSERT_NE(nullptr, gnb_state.key_chain);

    tf5_gnb_free(&gnb_state);

    EXPECT_FALSE(gnb_state.initialized) << "State should be marked as not initialized";
    EXPECT_EQ(nullptr, gnb_state.key_chain) << "Key chain should be freed";
}

TEST_F(TF5GnbTest, GnbFree_NullState_NoOp) {
    tf5_gnb_free(nullptr);
    SUCCEED();
}

TEST_F(TF5GnbTest, GnbFree_UninitializedState_NoOp) {
    tf5_gnb_state_t uninit_state;
    memset(&uninit_state, 0, sizeof(uninit_state));

    tf5_gnb_free(&uninit_state);
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
