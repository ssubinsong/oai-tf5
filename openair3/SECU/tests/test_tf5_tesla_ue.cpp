/**
 * @file test_tf5_tesla_ue.cpp
 * @brief Unit tests for TF5 TESLA UE-side functions
 *
 * Tests for:
 * - tf5_tesla_ue_init(): UE state initialization
 * - tf5_tesla_ue_safe_packet_test(): Safe packet timing verification
 * - tf5_tesla_ue_buffer_sib1(): SIB1 buffering for delayed verification
 * - tf5_tesla_ue_verify_key_chain(): Key chain integrity verification
 * - tf5_tesla_ue_verify_buffered_with_key_disclosure(): Verify buffered SIB1s with disclosed key
 * - tf5_tesla_ibs_verify(): IBS signature verification (via TF5UeSignatureTest)
 */

#define TF5_TEST_NEEDS_OAI_STUBS
#include "tf5_test_common.h"

extern "C" {
#include "openair3/SECU/tf5_ibs_pkg.h"
#include "openair3/SECU/tf5_tesla.h"
#include "openair3/SECU/tf5_tesla_sig.h"
}

#include "tf5_test_vectors.h"

class TF5UeTest : public ::testing::Test {
protected:
    tf5_ue_state_t ue_state;
    uint8_t test_mpk[TF5_IBS_MPK_LEN];

    // For tests that need a gNB state
    tf5_gnb_state_t gnb_state;
    uint8_t test_private_key[TF5_IBS_GNB_SK_LEN];

    void SetUp() override {
        // Initialize BLS library
        tf5_bls_init();

        // Clear states
        memset(&ue_state, 0, sizeof(ue_state));
        memset(&gnb_state, 0, sizeof(gnb_state));

        // Generate test MPK from test private key
        memcpy(test_private_key, tf5_test::TV_BLS_SECRET_KEY, TF5_IBS_GNB_SK_LEN);

        // For basic tests, use a dummy MPK (96 bytes)
        memset(test_mpk, 0x42, TF5_IBS_MPK_LEN);
    }

    void TearDown() override {
        tf5_ue_free(&ue_state);
        tf5_gnb_free(&gnb_state);
    }

    // Helper to initialize UE with default test parameters
    int initUeDefault() {
        return tf5_ue_init(
            &ue_state,
            test_mpk,
            tf5_test::TV_SLOTS_PER_FRAME,
            TF5_TESLA_DEFAULT_D_BOUND_US,
            TF5_RP_DEFAULT_TIME_WINDOW_MS
        );
    }

    // Helper to initialize gNB for integration-style tests
    int initGnbDefault(uint32_t chain_len = 100) {
        tf5_slot_time_t t0 = tf5_slot_time_make(0, 0);
        return tf5_gnb_init(
            &gnb_state,
            tf5_test::TV_EXT_T_INT_MS,
            tf5_test::TV_EXT_D,
            chain_len,
            test_private_key,
            &t0,
            tf5_test::TV_SLOTS_PER_FRAME
        );
    }

    // Helper to set up UE state with a trust anchor
    void setupUeWithTrustAnchor(const uint8_t* anchor_key, int32_t anchor_idx) {
        memcpy(ue_state.trust_anchor_key, anchor_key, TF5_TESLA_KEY_LEN);
        ue_state.trust_anchor_idx = anchor_idx;
        ue_state.chain_bootstrapped = true;
    }
};

// ============================================================================
// Initialization Tests (tf5_ue_init)
// ============================================================================

TEST_F(TF5UeTest, UeInit_Success) {
    int ret = initUeDefault();

    EXPECT_EQ(0, ret) << "UE init should return 0 on success";
    EXPECT_TRUE(ue_state.initialized) << "State should be marked as initialized";
}

TEST_F(TF5UeTest, UeInit_MpkStored) {
    int ret = initUeDefault();

    EXPECT_EQ(0, ret);
    EXPECT_EQ(0, memcmp(ue_state.mpk, test_mpk, TF5_IBS_MPK_LEN))
        << "MPK should be stored in state";
}

TEST_F(TF5UeTest, UeInit_BufferEmpty) {
    int ret = initUeDefault();

    EXPECT_EQ(0, ret);
    EXPECT_EQ(0, ue_state.buffer_queue_count) << "Buffer queue should be empty initially";
}

TEST_F(TF5UeTest, UeInit_NotBootstrapped) {
    int ret = initUeDefault();

    EXPECT_EQ(0, ret);
    EXPECT_FALSE(ue_state.chain_bootstrapped) << "Chain should not be bootstrapped initially";
}

TEST_F(TF5UeTest, UeInit_AuthStateUnauthenticated) {
    int ret = initUeDefault();

    EXPECT_EQ(0, ret);
    EXPECT_EQ(TF5_PHASE_INITIAL, ue_state.curr_phase);
}

TEST_F(TF5UeTest, UeInit_NullState_ReturnsError) {
    int ret = tf5_ue_init(nullptr, test_mpk, tf5_test::TV_SLOTS_PER_FRAME,
                                 TF5_TESLA_DEFAULT_D_BOUND_US, TF5_RP_DEFAULT_TIME_WINDOW_MS);

    EXPECT_LT(ret, 0) << "Null state should return error";
}

TEST_F(TF5UeTest, UeInit_NullMpk_ReturnsError) {
    int ret = tf5_ue_init(&ue_state, nullptr, tf5_test::TV_SLOTS_PER_FRAME,
                                 TF5_TESLA_DEFAULT_D_BOUND_US, TF5_RP_DEFAULT_TIME_WINDOW_MS);

    EXPECT_LT(ret, 0) << "Null MPK should return error";
}

TEST_F(TF5UeTest, UeInit_DefaultTimestampWindow) {
    // Pass 0 for timestamp window - should use default
    int ret = tf5_ue_init(&ue_state, test_mpk, tf5_test::TV_SLOTS_PER_FRAME,
                                 TF5_TESLA_DEFAULT_D_BOUND_US, 0);

    EXPECT_EQ(0, ret);
    EXPECT_EQ(TF5_RP_DEFAULT_TIME_WINDOW_MS, ue_state.rp_timestamp_window_ms)
        << "Should use default timestamp window when 0 is passed";
}

// ============================================================================
// d_offset_slots Verification Tests (Gap #3)
// ============================================================================

TEST_F(TF5UeTest, UeInit_DOffsetSlots_DefaultParams) {
    // Default: d_bound=1005us, slots_per_frame=20 (mu=1, 30kHz SCS)
    // slot_duration = 10000/20 = 500us
    // d_offset_slots = ceil(1005/500) = (1005+499)/500 = 3
    int ret = initUeDefault();
    ASSERT_EQ(0, ret);
    EXPECT_EQ(3u, ue_state.d_offset_slots)
        << "mu=1: ceil(1005/500) should be 3 slots";
}

TEST_F(TF5UeTest, UeInit_DOffsetSlots_Mu0) {
    // mu=0 (15kHz SCS): slots_per_frame=10
    // slot_duration = 10000/10 = 1000us
    // d_offset_slots = ceil(1005/1000) = (1005+999)/1000 = 2
    int ret = tf5_ue_init(&ue_state, test_mpk, 10,
                          TF5_TESLA_DEFAULT_D_BOUND_US, TF5_RP_DEFAULT_TIME_WINDOW_MS);
    ASSERT_EQ(0, ret);
    EXPECT_EQ(2u, ue_state.d_offset_slots)
        << "mu=0: ceil(1005/1000) should be 2 slots";
}

TEST_F(TF5UeTest, UeInit_DOffsetSlots_Mu2) {
    // mu=2 (60kHz SCS): slots_per_frame=40
    // slot_duration = 10000/40 = 250us
    // d_offset_slots = ceil(1005/250) = (1005+249)/250 = 5
    int ret = tf5_ue_init(&ue_state, test_mpk, 40,
                          TF5_TESLA_DEFAULT_D_BOUND_US, TF5_RP_DEFAULT_TIME_WINDOW_MS);
    ASSERT_EQ(0, ret);
    EXPECT_EQ(5u, ue_state.d_offset_slots)
        << "mu=2: ceil(1005/250) should be 5 slots";
}

TEST_F(TF5UeTest, UeInit_DOffsetSlots_ExactDivisor) {
    // d_bound=1000us, slots_per_frame=10 → slot_duration=1000us
    // d_offset_slots = ceil(1000/1000) = 1
    int ret = tf5_ue_init(&ue_state, test_mpk, 10,
                          1000, TF5_RP_DEFAULT_TIME_WINDOW_MS);
    ASSERT_EQ(0, ret);
    EXPECT_EQ(1u, ue_state.d_offset_slots)
        << "Exact divisor: ceil(1000/1000) should be 1 slot";
}

// ============================================================================
// Safe Packet Test (tf5_ue_safe_packet_test)
// ============================================================================

TEST_F(TF5UeTest, SafePacketTest_SafePacket_ReturnsTrue) {
    ASSERT_EQ(0, initUeDefault());

    // Set up TESLA params (normally set from extension)
    ue_state.tesla_params.t_int_ms = tf5_test::TV_EXT_T_INT_MS;
    ue_state.tesla_params.d = tf5_test::TV_EXT_D;
    ue_state.tesla_params.t0 = tf5_slot_time_make(0, 0);

    // Create extension claiming interval 5
    tf5_extension_t ext;
    memset(&ext, 0, sizeof(ext));
    ext.i = 5;
    ext.tesla_params = ue_state.tesla_params;

    // Receive at interval 5 (same interval) - should be safe
    // 5 intervals = 200 slots (at 40 slots/interval) = SFN 10, slot 0
    bool safe = tf5_ue_safe_packet_test(&ue_state, &ext, 10, 0);

    EXPECT_TRUE(safe) << "Packet received in same interval should be safe";
}

TEST_F(TF5UeTest, SafePacketTest_UnsafePacket_ReturnsFalse) {
    ASSERT_EQ(0, initUeDefault());

    ue_state.tesla_params.t_int_ms = tf5_test::TV_EXT_T_INT_MS;
    ue_state.tesla_params.d = 1;  // d = 1
    ue_state.tesla_params.t0 = tf5_slot_time_make(0, 0);

    // Create extension claiming interval 5
    tf5_extension_t ext;
    memset(&ext, 0, sizeof(ext));
    ext.i = 5;
    ext.tesla_params = ue_state.tesla_params;

    // Receive much later - at interval 10 (400 slots = SFN 20)
    // Safe if: x < i + d, i.e., 10 < 5 + 1 = 6? NO -> unsafe
    bool safe = tf5_ue_safe_packet_test(&ue_state, &ext, 20, 0);

    EXPECT_FALSE(safe) << "Packet received too late should be unsafe";
}

TEST_F(TF5UeTest, SafePacketTest_BoundaryExact_ReturnsFalse) {
    ASSERT_EQ(0, initUeDefault());

    ue_state.tesla_params.t_int_ms = tf5_test::TV_EXT_T_INT_MS;
    ue_state.tesla_params.d = 1;
    ue_state.tesla_params.t0 = tf5_slot_time_make(0, 0);

    // Create extension claiming interval 5
    tf5_extension_t ext;
    memset(&ext, 0, sizeof(ext));
    ext.i = 5;
    ext.tesla_params = ue_state.tesla_params;

    // Receive at exactly interval 6 (i + d boundary)
    // 6 intervals = 240 slots = SFN 12
    // Safe if: x < i + d, i.e., 6 < 6? NO -> unsafe
    bool safe = tf5_ue_safe_packet_test(&ue_state, &ext, 12, 0);

    EXPECT_FALSE(safe) << "Packet received exactly at boundary should be unsafe";
}

TEST_F(TF5UeTest, SafePacketTest_NullState_ReturnsFalse) {
    tf5_extension_t ext;
    memset(&ext, 0, sizeof(ext));

    bool safe = tf5_ue_safe_packet_test(nullptr, &ext, 0, 0);

    EXPECT_FALSE(safe) << "Null state should return false";
}

TEST_F(TF5UeTest, SafePacketTest_NullExt_ReturnsFalse) {
    ASSERT_EQ(0, initUeDefault());

    bool safe = tf5_ue_safe_packet_test(&ue_state, nullptr, 0, 0);

    EXPECT_FALSE(safe) << "Null extension should return false";
}

// ============================================================================
// Buffering Tests (tf5_ue_buffer_msg)
// ============================================================================

TEST_F(TF5UeTest, BufferSib1_Success) {
    ASSERT_EQ(0, initUeDefault());

    const char auth_input[] = "test auth input";
    uint8_t tag[TF5_TESLA_TAG_LEN] = {0};
    tf5_slot_time_t rx_time = tf5_slot_time_make(0, 0);

    int ret = tf5_ue_buffer_msg(&ue_state,
                                       (const uint8_t*)auth_input,
                                       strlen(auth_input),
                                       5, // interval_index
                                       tag,
                                       false // triggered_rrc_setup
    );

    EXPECT_EQ(0, ret) << "Buffer SIB1 should return 0 on success";
}

TEST_F(TF5UeTest, BufferSib1_QueueCountIncremented) {
    ASSERT_EQ(0, initUeDefault());

    const char auth_input[] = "test auth input";
    uint8_t tag[TF5_TESLA_TAG_LEN] = {0};
    tf5_slot_time_t rx_time = tf5_slot_time_make(0, 0);

    EXPECT_EQ(0, ue_state.buffer_queue_count);

    tf5_ue_buffer_msg(&ue_state, (const uint8_t*)auth_input, strlen(auth_input), 5, tag, false);

    EXPECT_EQ(1, ue_state.buffer_queue_count);
}

TEST_F(TF5UeTest, BufferSib1_DataStored) {
    ASSERT_EQ(0, initUeDefault());

    const char auth_input[] = "test auth input data";
    uint8_t tag[TF5_TESLA_TAG_LEN] = {0xde, 0xad, 0xbe, 0xef};
    tf5_slot_time_t rx_time = tf5_slot_time_make(0, 0);

    tf5_ue_buffer_msg(&ue_state, (const uint8_t*)auth_input, strlen(auth_input), 5, tag, false);

    // Find the entry in the queue
    bool found = false;
    for (int i = 0; i < TF5_TESLA_BUFFER_QUEUE_SIZE; i++) {
        if (ue_state.buffer_queue[i].valid) {
            EXPECT_EQ(0, memcmp(ue_state.buffer_queue[i].auth_input, auth_input, strlen(auth_input)));
            EXPECT_EQ(strlen(auth_input), ue_state.buffer_queue[i].auth_input_len);
            EXPECT_EQ(0, memcmp(ue_state.buffer_queue[i].tag, tag, TF5_TESLA_TAG_LEN));
            EXPECT_EQ(5u, ue_state.buffer_queue[i].rx_interval_index);
            found = true;
            break;
        }
    }
    EXPECT_TRUE(found) << "Entry should be stored in buffer queue";
}

TEST_F(TF5UeTest, BufferSib1_RrcTriggerFlagSet) {
    ASSERT_EQ(0, initUeDefault());

    const char auth_input[] = "test auth input";
    uint8_t tag[TF5_TESLA_TAG_LEN] = {0};
    tf5_slot_time_t rx_time = tf5_slot_time_make(0, 0);

    tf5_ue_buffer_msg(&ue_state, (const uint8_t*)auth_input, strlen(auth_input), 5, tag, true);  // triggered_rrc_setup = true

    // Find the entry
    for (int i = 0; i < TF5_TESLA_BUFFER_QUEUE_SIZE; i++) {
        if (ue_state.buffer_queue[i].valid) {
            EXPECT_TRUE(ue_state.buffer_queue[i].triggered_rrc_setup);
            break;
        }
    }
}

TEST_F(TF5UeTest, BufferSib1_MultipleEntries) {
    ASSERT_EQ(0, initUeDefault());

    const char auth_input1[] = "auth input 1";
    const char auth_input2[] = "auth input 2";
    uint8_t tag1[TF5_TESLA_TAG_LEN] = {0x01};
    uint8_t tag2[TF5_TESLA_TAG_LEN] = {0x02};
    tf5_slot_time_t rx_time = tf5_slot_time_make(0, 0);

    tf5_ue_buffer_msg(&ue_state, (const uint8_t*)auth_input1, strlen(auth_input1), 5, tag1, false);
    tf5_ue_buffer_msg(&ue_state, (const uint8_t*)auth_input2, strlen(auth_input2), 6, tag2, false);

    EXPECT_EQ(2, ue_state.buffer_queue_count);
}

TEST_F(TF5UeTest, BufferSib1_FullQueue_DropsOldest) {
    ASSERT_EQ(0, initUeDefault());

    uint8_t tag[TF5_TESLA_TAG_LEN] = {0};
    tf5_slot_time_t rx_time = tf5_slot_time_make(0, 0);

    // Fill the queue
    for (int i = 0; i < TF5_TESLA_BUFFER_QUEUE_SIZE; i++) {
        char auth_input[32];
        snprintf(auth_input, sizeof(auth_input), "auth input %d", i);
        tf5_ue_buffer_msg(&ue_state, (const uint8_t*)auth_input, strlen(auth_input), i, tag, false);
    }

    EXPECT_EQ(TF5_TESLA_BUFFER_QUEUE_SIZE, ue_state.buffer_queue_count);

    // Add one more - should replace oldest
    const char new_auth[] = "new auth input";
    tf5_ue_buffer_msg(&ue_state, (const uint8_t*)new_auth, strlen(new_auth), 99, tag, false);

    // Queue should still be at max size
    EXPECT_EQ(TF5_TESLA_BUFFER_QUEUE_SIZE, ue_state.buffer_queue_count);
}

TEST_F(TF5UeTest, BufferSib1_NullInputs_ReturnsError) {
    ASSERT_EQ(0, initUeDefault());

    uint8_t tag[TF5_TESLA_TAG_LEN] = {0};
    tf5_slot_time_t rx_time = tf5_slot_time_make(0, 0);

    int ret = tf5_ue_buffer_msg(nullptr, (const uint8_t*)"test", 4, 5, tag, false);
    EXPECT_LT(ret, 0) << "Null state should return error";

    ret = tf5_ue_buffer_msg(&ue_state, nullptr, 4, 5, tag, false);
    EXPECT_LT(ret, 0) << "Null auth_input should return error";

    ret = tf5_ue_buffer_msg(&ue_state, (const uint8_t*)"test", 4, 5, nullptr, false);
    EXPECT_LT(ret, 0) << "Null tag should return error";
}

// ============================================================================
// Key Chain Verification Tests (tf5_ue_verify_key_disclosure)
// ============================================================================

TEST_F(TF5UeTest, VerifyKeyChain_ValidChain_ReturnsTrue) {
    ASSERT_EQ(0, initUeDefault());
    ASSERT_EQ(0, initGnbDefault(10));

    // Set up UE with K_0 as trust anchor (from bootstrap)
    setupUeWithTrustAnchor(gnb_state.key_chain[tf5_key_interval_to_index(0)], 0);

    // Verify K_1 chains to K_0
    bool valid = tf5_ue_verify_key_disclosure(&ue_state, gnb_state.key_chain[tf5_key_interval_to_index(1)], 1);

    EXPECT_TRUE(valid) << "K_1 should chain to K_0";
}

TEST_F(TF5UeTest, VerifyKeyChain_InvalidChain_ReturnsFalse) {
    ASSERT_EQ(0, initUeDefault());
    ASSERT_EQ(0, initGnbDefault(10));

    // Set up UE with K_0 as trust anchor
    setupUeWithTrustAnchor(gnb_state.key_chain[tf5_key_interval_to_index(0)], 0);

    // Try to verify a fake key
    uint8_t fake_key[TF5_TESLA_KEY_LEN] = {0xff, 0xff, 0xff, 0xff};

    bool valid = tf5_ue_verify_key_disclosure(&ue_state, fake_key, 1);

    EXPECT_FALSE(valid) << "Fake key should not chain to anchor";
}

TEST_F(TF5UeTest, VerifyKeyChain_SkippedKeys_MultipleHashOps) {
    ASSERT_EQ(0, initUeDefault());
    ASSERT_EQ(0, initGnbDefault(10));

    // Set up UE with K_0 as trust anchor
    setupUeWithTrustAnchor(gnb_state.key_chain[tf5_key_interval_to_index(0)], 0);

    // Verify K_5 chains to K_0 (requires 5 hash operations)
    bool valid = tf5_ue_verify_key_disclosure(&ue_state, gnb_state.key_chain[tf5_key_interval_to_index(5)], 5);

    EXPECT_TRUE(valid) << "K_5 should chain to K_0 via 5 hash ops";
}

TEST_F(TF5UeTest, VerifyKeyChain_BootstrapAnchor) {
    ASSERT_EQ(0, initUeDefault());
    ASSERT_EQ(0, initGnbDefault(10));

    // Set up UE with K_{-1} as bootstrap anchor (stored at index 0)
    memcpy(ue_state.trust_anchor_key, gnb_state.key_chain[tf5_key_interval_to_index(-1)], TF5_TESLA_KEY_LEN);
    ue_state.trust_anchor_idx = -1;
    ue_state.chain_bootstrapped = true;

    // Verify K_0 chains to K_{-1} (K_0 is at index 1)
    bool valid = tf5_ue_verify_key_disclosure(&ue_state, gnb_state.key_chain[tf5_key_interval_to_index(0)], 0);

    EXPECT_TRUE(valid) << "K_0 should chain to K_{-1} (bootstrap anchor)";
}

TEST_F(TF5UeTest, VerifyKeyChain_NotBootstrapped_ReturnsFalse) {
    ASSERT_EQ(0, initUeDefault());
    ASSERT_EQ(0, initGnbDefault(10));

    // UE is not bootstrapped (no trust anchor)
    EXPECT_FALSE(ue_state.chain_bootstrapped);

    bool valid = tf5_ue_verify_key_disclosure(&ue_state, gnb_state.key_chain[tf5_key_interval_to_index(1)], 1);

    EXPECT_FALSE(valid) << "Should fail when not bootstrapped";
}

TEST_F(TF5UeTest, VerifyKeyChain_NullInputs_ReturnsFalse) {
    ASSERT_EQ(0, initUeDefault());

    uint8_t key[TF5_TESLA_KEY_LEN] = {0};

    bool valid = tf5_ue_verify_key_disclosure(nullptr, key, 1);
    EXPECT_FALSE(valid) << "Null state should return false";

    valid = tf5_ue_verify_key_disclosure(&ue_state, nullptr, 1);
    EXPECT_FALSE(valid) << "Null key should return false";
}

// ============================================================================
// Key Recovery Tests (tf5_tesla_ue_verify_buffered_msgs)
// ============================================================================

TEST_F(TF5UeTest, KeyRecovery_SingleMissedInterval) {
    ASSERT_EQ(0, initUeDefault());
    ASSERT_EQ(0, initGnbDefault(100));

    // Generate extensions for intervals 5 and 7
    tf5_extension_t ext5, ext7;
    const char sib1_5[] = "SIB1 at interval 5";
    const char sib1_7[] = "SIB1 at interval 7";

    // Interval 5 = 200 slots = SFN 10
    tf5_gnb_prepare_extension(&gnb_state, 10, 0, (const uint8_t*)sib1_5, strlen(sib1_5), &ext5);
    // Interval 7 = 280 slots = SFN 14
    tf5_gnb_prepare_extension(&gnb_state, 14, 0, (const uint8_t*)sib1_7, strlen(sib1_7), &ext7);

    // Set up UE
    ue_state.tesla_params = ext5.tesla_params;
    setupUeWithTrustAnchor(gnb_state.key_chain[tf5_key_interval_to_index(0)], 0);

    // Buffer SIB1 from interval 5
    uint8_t mac_auth_input[TF5_MAX_AUTH_INPUT];
    size_t mac_auth_input_len;
    tf5_build_mac_auth_input(mac_auth_input, &mac_auth_input_len,
                                   (const uint8_t*)sib1_5, strlen(sib1_5),
                                   gnb_state.key_validity_end);

    tf5_slot_time_t rx_time = tf5_slot_time_make(10, 0);
    tf5_ue_buffer_msg(&ue_state, mac_auth_input, mac_auth_input_len, 5, ext5.tesla_tag, false);

    // Simulate missed disclosure for interval 5, receive at interval 7
    // Use key from interval 7 to recover key for interval 5
    bool rrc_trigger_verified = false;

    // First verify key chain (K_7 -> anchor)
    bool key_valid = tf5_ue_verify_key_disclosure(&ue_state, gnb_state.key_chain[tf5_key_interval_to_index(7)], 7);
    EXPECT_TRUE(key_valid) << "Key chain should verify";

    // Then verify buffered entries using the disclosed key
    int ret = tf5_tesla_ue_verify_buffered_msgs(&ue_state, gnb_state.key_chain[tf5_key_interval_to_index(7)],
                                                                7, &rrc_trigger_verified);

    EXPECT_EQ(0, ret) << "Key recovery should succeed";
}

// ============================================================================
// verify_buffered_msgs Null/Error Input Tests (Gap #2)
// ============================================================================

TEST_F(TF5UeTest, VerifyBuffered_NullState_ReturnsError) {
    uint8_t key[TF5_TESLA_KEY_LEN] = {0};
    bool rrc_trigger = false;

    int ret = tf5_tesla_ue_verify_buffered_msgs(nullptr, key, 1, &rrc_trigger);

    EXPECT_EQ(TF5_ERR_INVALID_PARAM, ret)
        << "NULL ue_state should return TF5_ERR_INVALID_PARAM";
}

TEST_F(TF5UeTest, VerifyBuffered_NullKeyDisclosure_ReturnsError) {
    ASSERT_EQ(0, initUeDefault());
    bool rrc_trigger = false;

    int ret = tf5_tesla_ue_verify_buffered_msgs(&ue_state, nullptr, 1, &rrc_trigger);

    EXPECT_EQ(TF5_ERR_INVALID_PARAM, ret)
        << "NULL key_disclosure should return TF5_ERR_INVALID_PARAM";
}

TEST_F(TF5UeTest, VerifyBuffered_NullRrcTrigger_ReturnsError) {
    ASSERT_EQ(0, initUeDefault());
    uint8_t key[TF5_TESLA_KEY_LEN] = {0};

    int ret = tf5_tesla_ue_verify_buffered_msgs(&ue_state, key, 1, nullptr);

    EXPECT_EQ(TF5_ERR_INVALID_PARAM, ret)
        << "NULL rrc_trigger_verified should return TF5_ERR_INVALID_PARAM";
}

TEST_F(TF5UeTest, VerifyBuffered_UninitializedState_ReturnsError) {
    // ue_state is memset(0) in SetUp() — initialized == false
    uint8_t key[TF5_TESLA_KEY_LEN] = {0};
    bool rrc_trigger = false;

    int ret = tf5_tesla_ue_verify_buffered_msgs(&ue_state, key, 1, &rrc_trigger);

    EXPECT_EQ(TF5_ERR_INVALID_PARAM, ret)
        << "Uninitialized state should return TF5_ERR_INVALID_PARAM";
}

TEST_F(TF5UeTest, VerifyBuffered_EmptyBuffer_ReturnsNoData) {
    ASSERT_EQ(0, initUeDefault());
    uint8_t key[TF5_TESLA_KEY_LEN] = {0};
    bool rrc_trigger = false;

    // No entries buffered — buffer_queue_count == 0
    int ret = tf5_tesla_ue_verify_buffered_msgs(&ue_state, key, 1, &rrc_trigger);

    EXPECT_EQ(TF5_ERR_NO_DATA, ret)
        << "Empty buffer should return TF5_ERR_NO_DATA";
}

// ============================================================================
// IBS Signature Verification Tests (tf5_sig_verify)
// ============================================================================

/**
 * Test fixture for IBS signature verification (tf5_sig_verify) that uses
 * Core PKG library to generate properly issued IBS keys.
 */
bool TF5IbsTestFixture::bls_initialized = false;

/**
 * Test fixture for IBS signature verification (tf5_sig_verify) that uses
 * Core PKG library to generate properly issued IBS keys.
 * Inherits UE state from TF5UeTest and IBS key management from TF5IbsTestFixture
 * (via composition, since C++ lacks multiple inheritance of test fixtures cleanly).
 */
class TF5UeSignatureTest : public TF5UeTest {
protected:
    // IBS key management (mirrors TF5IbsTestFixture members)
    std::string test_dir;
    std::string msk_path;
    std::string mpk_path;
    std::string sk_gnb_path;

    uint8_t ibs_msk[TF5_IBS_GNB_SK_LEN];
    uint8_t ibs_mpk[TF5_IBS_MPK_LEN];
    uint8_t ibs_sk[TF5_IBS_GNB_SK_LEN];
    uint8_t cell_id[TF5_IBS_CELL_ID_LEN];
    uint32_t validity_end;

    static bool bls_initialized;

    void SetUp() override {
        TF5UeTest::SetUp();

        if (!bls_initialized) {
            tf5_bls_init();
            bls_initialized = true;
        }

        memset(cell_id, 0, TF5_IBS_CELL_ID_LEN);
        cell_id[0] = 0x12;
        cell_id[1] = 0x34;
        cell_id[2] = 0x56;
        cell_id[3] = 0x78;
        cell_id[4] = 0x90;

        validity_end = 1051200;

        test_dir = "/tmp/tf5_ue_sig_test_" + std::to_string(getpid());
        std::filesystem::create_directories(test_dir);
        msk_path = test_dir + "/msk.bin";
        mpk_path = test_dir + "/mpk.bin";
        sk_gnb_path = test_dir + "/sk_gnb.bin";

        generateAndLoadKeys();
    }

    void TearDown() override {
        if (!test_dir.empty()) {
            std::filesystem::remove_all(test_dir);
        }
        TF5UeTest::TearDown();
    }

    void generateAndLoadKeys() {
        int rc = tf5_ibs_generate_master_keypair(msk_path.c_str(), mpk_path.c_str());
        ASSERT_EQ(0, rc) << "Failed to generate master keypair";

        rc = tf5_ibs_issue_gnb_key(msk_path.c_str(), cell_id, validity_end, sk_gnb_path.c_str());
        ASSERT_EQ(0, rc) << "Failed to issue gNB key";

        rc = tf5_ibs_load_master_secret(msk_path.c_str(), ibs_msk);
        ASSERT_EQ(0, rc) << "Failed to load MSK";

        rc = tf5_load_core_mpk(mpk_path.c_str(), ibs_mpk);
        ASSERT_EQ(0, rc) << "Failed to load MPK";

        FILE* f = fopen(sk_gnb_path.c_str(), "rb");
        ASSERT_NE(nullptr, f) << "Failed to open gNB SK file";
        uint8_t sk_file[TF5_IBS_SK_FILE_SIZE];
        size_t n = fread(sk_file, 1, TF5_IBS_SK_FILE_SIZE, f);
        fclose(f);
        ASSERT_EQ(TF5_IBS_SK_FILE_SIZE, n) << "Failed to read gNB SK";

        memcpy(ibs_sk, sk_file, TF5_IBS_GNB_SK_LEN);
    }

    int initUeWithTestMpk() {
        return tf5_ue_init(&ue_state, ibs_mpk, tf5_test::TV_SLOTS_PER_FRAME,
                                  TF5_TESLA_DEFAULT_D_BOUND_US, TF5_RP_DEFAULT_TIME_WINDOW_MS);
    }

    void createValidSignature(const uint8_t* auth_input, size_t auth_input_len,
                              uint8_t signature_out[TF5_IBS_SIG_LEN]) {
        int rc = tf5_bls_sign(ibs_sk, auth_input, auth_input_len, signature_out);
        ASSERT_EQ(0, rc) << "Failed to create signature";
    }
};

bool TF5UeSignatureTest::bls_initialized = false;

// IBS signature verification test using PKG-generated keys
TEST_F(TF5UeSignatureTest, VerifySignature_ValidIBS_ReturnsZero) {
    const char auth_input[] = "test authentication input for IBS signature";
    uint8_t signature[TF5_IBS_SIG_LEN];

    // Create a valid IBS signature using the PKG-issued key
    createValidSignature((const uint8_t*)auth_input, strlen(auth_input), signature);

    int ret = tf5_sig_verify(ibs_mpk, cell_id, validity_end,
                                   (const uint8_t*)auth_input, strlen(auth_input),
                                   signature);

    EXPECT_EQ(0, ret) << "Valid IBS signature should verify successfully";
}

TEST_F(TF5UeSignatureTest, VerifySignature_TamperedData_Fails) {
    const char auth_input[] = "original authentication input";
    uint8_t signature[TF5_IBS_SIG_LEN];

    // Create signature over original data
    createValidSignature((const uint8_t*)auth_input, strlen(auth_input), signature);

    // Verify with tampered data
    const char tampered_input[] = "tampered authentication input";

    int ret = tf5_sig_verify(ibs_mpk, cell_id, validity_end,
                                   (const uint8_t*)tampered_input, strlen(tampered_input),
                                   signature);

    EXPECT_NE(0, ret) << "Tampered data should fail verification";
}

TEST_F(TF5UeSignatureTest, VerifySignature_TamperedSignature_Fails) {
    const char auth_input[] = "test authentication input";
    uint8_t signature[TF5_IBS_SIG_LEN];

    // Create a valid signature
    createValidSignature((const uint8_t*)auth_input, strlen(auth_input), signature);

    // Tamper with the signature
    signature[0] ^= 0xFF;
    signature[10] ^= 0xFF;

    int ret = tf5_sig_verify(ibs_mpk, cell_id, validity_end,
                                   (const uint8_t*)auth_input, strlen(auth_input),
                                   signature);

    EXPECT_NE(0, ret) << "Tampered signature should fail verification";
}

TEST_F(TF5UeSignatureTest, VerifySignature_WrongCellId_Fails) {
    const char auth_input[] = "test authentication input";
    uint8_t signature[TF5_IBS_SIG_LEN];

    // Create a valid signature
    createValidSignature((const uint8_t*)auth_input, strlen(auth_input), signature);

    // Use wrong cell ID
    uint8_t wrong_cell_id[TF5_IBS_CELL_ID_LEN] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE};

    int ret = tf5_sig_verify(ibs_mpk, wrong_cell_id, validity_end,
                                   (const uint8_t*)auth_input, strlen(auth_input),
                                   signature);

    EXPECT_NE(0, ret) << "Wrong cell ID should fail verification";
}

TEST_F(TF5UeSignatureTest, VerifySignature_WrongValidity_Fails) {
    const char auth_input[] = "test authentication input";
    uint8_t signature[TF5_IBS_SIG_LEN];

    // Create a valid signature
    createValidSignature((const uint8_t*)auth_input, strlen(auth_input), signature);

    // Use wrong validity
    uint32_t wrong_validity = 999999;

    int ret = tf5_sig_verify(ibs_mpk, cell_id, wrong_validity,
                                   (const uint8_t*)auth_input, strlen(auth_input),
                                   signature);

    EXPECT_NE(0, ret) << "Wrong validity should fail verification";
}

TEST_F(TF5UeSignatureTest, VerifySignature_WrongMpk_Fails) {
    // Use wrong MPK for verification
    uint8_t wrong_mpk[TF5_IBS_MPK_LEN];
    memset(wrong_mpk, 0x99, TF5_IBS_MPK_LEN);

    const char auth_input[] = "test authentication input";
    uint8_t signature[TF5_IBS_SIG_LEN];

    // Create signature with correct key
    createValidSignature((const uint8_t*)auth_input, strlen(auth_input), signature);

    // Verify with wrong MPK - should fail
    int ret = tf5_sig_verify(wrong_mpk, cell_id, validity_end,
                                   (const uint8_t*)auth_input, strlen(auth_input),
                                   signature);

    EXPECT_NE(0, ret) << "Wrong MPK should fail verification";
}

TEST_F(TF5UeSignatureTest, VerifySignature_NullMpk_ReturnsError) {
    const char auth_input[] = "test";
    uint8_t signature[TF5_IBS_SIG_LEN] = {0};

    int ret = tf5_sig_verify(nullptr, cell_id, validity_end,
                                   (const uint8_t*)auth_input, strlen(auth_input),
                                   signature);

    EXPECT_LT(ret, 0) << "Null MPK should return error";
}

TEST_F(TF5UeSignatureTest, VerifySignature_NullCellId_ReturnsError) {
    const char auth_input[] = "test";
    uint8_t signature[TF5_IBS_SIG_LEN] = {0};

    int ret = tf5_sig_verify(ibs_mpk, nullptr, validity_end,
                                   (const uint8_t*)auth_input, strlen(auth_input),
                                   signature);

    EXPECT_LT(ret, 0) << "Null cell_id should return error";
}

TEST_F(TF5UeSignatureTest, VerifySignature_NullAuthInput_ReturnsError) {
    uint8_t signature[TF5_IBS_SIG_LEN] = {0};

    int ret = tf5_sig_verify(ibs_mpk, cell_id, validity_end,
                                   nullptr, 10, signature);

    EXPECT_LT(ret, 0) << "Null auth_input should return error";
}

TEST_F(TF5UeSignatureTest, VerifySignature_NullSignature_ReturnsError) {
    const char auth_input[] = "test";

    int ret = tf5_sig_verify(ibs_mpk, cell_id, validity_end,
                                   (const uint8_t*)auth_input, strlen(auth_input),
                                   nullptr);

    EXPECT_LT(ret, 0) << "Null signature should return error";
}

// ============================================================================
// Authentication State Machine Tests
// ============================================================================

TEST_F(TF5UeTest, AuthState_InitialStateIsUnauthenticated) {
    // Covered by UeInit_AuthStateUnauthenticated - but verify explicitly here
    ASSERT_EQ(0, initUeDefault());

    EXPECT_EQ(TF5_PHASE_INITIAL, ue_state.curr_phase)
        << "Initial auth state should be UNAUTHENTICATED";
}

TEST_F(TF5UeTest, AuthState_CanBeSetToBuffered) {
    ASSERT_EQ(0, initUeDefault());

    // Simulate RRC layer setting BUFFERED state after buffering SIB1
    ue_state.curr_phase = TF5_PHASE_BUFFERED;

    EXPECT_EQ(TF5_PHASE_BUFFERED, ue_state.curr_phase)
        << "Auth state should be settable to BUFFERED";
}

TEST_F(TF5UeTest, AuthState_RrcTriggerTrackedInBuffer) {
    ASSERT_EQ(0, initUeDefault());
    ASSERT_EQ(0, initGnbDefault(100));

    // Generate valid extension
    tf5_extension_t ext;
    const char sib1[] = "SIB1 that triggers RRC setup";
    tf5_gnb_prepare_extension(&gnb_state, 5, 0, (const uint8_t*)sib1, strlen(sib1), &ext);

    // Set up UE
    ue_state.tesla_params = ext.tesla_params;
    setupUeWithTrustAnchor(gnb_state.key_chain[tf5_key_interval_to_index(0)], 0);

    // Buffer with triggered_rrc_setup = true
    uint8_t mac_auth_input[TF5_MAX_AUTH_INPUT];
    size_t mac_auth_input_len;
    tf5_build_mac_auth_input(mac_auth_input, &mac_auth_input_len,
                                   (const uint8_t*)sib1, strlen(sib1),
                                   gnb_state.key_validity_end);

    tf5_slot_time_t rx_time = tf5_slot_time_make(5, 0);
    int ret = tf5_ue_buffer_msg(&ue_state, mac_auth_input, mac_auth_input_len, ext.i, ext.tesla_tag, true);  // RRC trigger!

    EXPECT_EQ(0, ret);

    // Verify the flag is tracked in buffer
    bool found_rrc_trigger = false;
    for (int i = 0; i < TF5_TESLA_BUFFER_QUEUE_SIZE; i++) {
        if (ue_state.buffer_queue[i].valid && ue_state.buffer_queue[i].triggered_rrc_setup) {
            found_rrc_trigger = true;
            break;
        }
    }
    EXPECT_TRUE(found_rrc_trigger) << "Buffer should track RRC trigger flag";
}

TEST_F(TF5UeTest, AuthState_RrcTriggerVerifiedOnSuccess) {
    ASSERT_EQ(0, initUeDefault());
    ASSERT_EQ(0, initGnbDefault(100));

    // Generate valid extension
    tf5_extension_t ext;
    const char sib1[] = "SIB1 that triggers RRC setup";
    tf5_gnb_prepare_extension(&gnb_state, 5, 0, (const uint8_t*)sib1, strlen(sib1), &ext);

    // Set up UE
    ue_state.tesla_params = ext.tesla_params;
    setupUeWithTrustAnchor(gnb_state.key_chain[tf5_key_interval_to_index(0)], 0);

    // Buffer with triggered_rrc_setup = true
    uint8_t mac_auth_input[TF5_MAX_AUTH_INPUT];
    size_t mac_auth_input_len;
    tf5_build_mac_auth_input(mac_auth_input, &mac_auth_input_len,
                                   (const uint8_t*)sib1, strlen(sib1),
                                   gnb_state.key_validity_end);

    tf5_slot_time_t rx_time = tf5_slot_time_make(5, 0);
    tf5_ue_buffer_msg(&ue_state, mac_auth_input, mac_auth_input_len, ext.i, ext.tesla_tag, true);  // RRC trigger!

    // Verify and check rrc_trigger_verified
    bool rrc_trigger_verified = false;

    // First verify key chain
    bool key_valid = tf5_ue_verify_key_disclosure(&ue_state, gnb_state.key_chain[tf5_key_interval_to_index(ext.i)], ext.i);
    EXPECT_TRUE(key_valid) << "Key chain should verify";

    // Then verify buffered entries
    int ret = tf5_tesla_ue_verify_buffered_msgs(&ue_state, gnb_state.key_chain[tf5_key_interval_to_index(ext.i)],
                                                                ext.i, &rrc_trigger_verified);

    EXPECT_EQ(0, ret) << "Verification should succeed";
    EXPECT_TRUE(rrc_trigger_verified) << "rrc_trigger_verified should be true when RRC-triggering SIB1 verifies";
}

TEST_F(TF5UeTest, AuthState_RrcSetupDeferredCanBeSet) {
    ASSERT_EQ(0, initUeDefault());

    // Simulate RRC layer setting RRCSETUP_DEFERRED state
    ue_state.curr_phase = TF5_PHASE_BUFFERED;
    ue_state.rrcsetup_transaction_id = 42;  // Save transaction ID

    // RRCSetup received while auth pending
    ue_state.curr_phase = TF5_PHASE_RRCSETUP_DEFERRED;

    EXPECT_EQ(TF5_PHASE_RRCSETUP_DEFERRED, ue_state.curr_phase)
        << "Auth state should be settable to RRCSETUP_DEFERRED";
    EXPECT_EQ(42, ue_state.rrcsetup_transaction_id)
        << "Transaction ID should be preserved";
}

// ============================================================================
// Free Tests (tf5_ue_free)
// ============================================================================

TEST_F(TF5UeTest, UeFree_Success) {
    ASSERT_EQ(0, initUeDefault());

    tf5_ue_free(&ue_state);

    EXPECT_FALSE(ue_state.initialized) << "State should be marked as not initialized";
}

TEST_F(TF5UeTest, UeFree_NullState_NoOp) {
    // Should not crash
    tf5_ue_free(nullptr);
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
