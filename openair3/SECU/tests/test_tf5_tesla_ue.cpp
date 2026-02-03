/**
 * @file test_tf5_tesla_ue.cpp
 * @brief Unit tests for TF5 TESLA UE-side functions
 *
 * Tests for:
 * - tf5_tesla_ue_init(): UE state initialization
 * - tf5_tesla_ue_safe_packet_test(): Safe packet timing verification
 * - tf5_tesla_ue_buffer_sib1(): SIB1 buffering for delayed verification
 * - tf5_tesla_ue_verify_key_chain(): Key chain integrity verification
 * - tf5_tesla_ue_verify_all_buffered(): Buffered entry verification
 * - tf5_tesla_ue_verify_with_key_recovery(): Key recovery for lost disclosures
 * - tf5_tesla_ue_verify_signature(): IBS signature verification
 * - tf5_tesla_ue_verify_buffered(): Legacy single-entry verification
 */

#include <gtest/gtest.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <unistd.h>
#include <sys/stat.h>

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

class TF5UeTest : public ::testing::Test {
protected:
    tf5_tesla_ue_state_t ue_state;
    uint8_t test_mpk[TF5_IBS_PUBKEY_LEN];

    // For tests that need a gNB state
    tf5_gnb_state_t gnb_state;
    uint8_t test_private_key[TF5_BLS_SECRET_KEY_LEN];

    void SetUp() override {
        // Initialize BLS library
        tf5_tesla_bls_init();

        // Clear states
        memset(&ue_state, 0, sizeof(ue_state));
        memset(&gnb_state, 0, sizeof(gnb_state));

        // Generate test MPK from test private key
        memcpy(test_private_key, tf5_test::TV_BLS_SECRET_KEY, TF5_BLS_SECRET_KEY_LEN);

        // For basic tests, use a dummy MPK (96 bytes)
        memset(test_mpk, 0x42, TF5_IBS_PUBKEY_LEN);
    }

    void TearDown() override {
        tf5_tesla_ue_free(&ue_state);
        tf5_tesla_gnb_free(&gnb_state);
    }

    // Helper to initialize UE with default test parameters
    int initUeDefault() {
        return tf5_tesla_ue_init(
            &ue_state,
            test_mpk,
            tf5_test::TV_SLOTS_PER_FRAME,
            TF5_TESLA_DEFAULT_D_BOUND_US,
            TF5_RP_DEFAULT_TIME_WINDOW_MS
        );
    }

    // Helper to initialize gNB for integration-style tests
    int initGnbDefault(uint32_t chain_len = 100) {
        tf5_tesla_slot_time_t t0 = tf5_slot_time_make(0, 0);
        return tf5_tesla_gnb_init(
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
    void setupUeWithTrustAnchor(const uint8_t* anchor_key, uint32_t anchor_idx) {
        memcpy(ue_state.trust_anchor_key, anchor_key, TF5_TESLA_KEY_LEN);
        ue_state.trust_anchor_idx = anchor_idx;
        ue_state.chain_bootstrapped = true;
    }
};

// ============================================================================
// Initialization Tests (tf5_tesla_ue_init)
// ============================================================================

TEST_F(TF5UeTest, UeInit_Success) {
    int ret = initUeDefault();

    EXPECT_EQ(0, ret) << "UE init should return 0 on success";
    EXPECT_TRUE(ue_state.initialized) << "State should be marked as initialized";
}

TEST_F(TF5UeTest, UeInit_MpkStored) {
    int ret = initUeDefault();

    EXPECT_EQ(0, ret);
    EXPECT_EQ(0, memcmp(ue_state.mpk, test_mpk, TF5_IBS_PUBKEY_LEN))
        << "MPK should be stored in state";
    EXPECT_TRUE(ue_state.has_mpk) << "has_mpk flag should be set";
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
    EXPECT_EQ(TF5_AUTH_STATE_UNAUTHENTICATED, ue_state.auth_state);
}

TEST_F(TF5UeTest, UeInit_NullState_ReturnsError) {
    int ret = tf5_tesla_ue_init(nullptr, test_mpk, tf5_test::TV_SLOTS_PER_FRAME,
                                 TF5_TESLA_DEFAULT_D_BOUND_US, TF5_RP_DEFAULT_TIME_WINDOW_MS);

    EXPECT_LT(ret, 0) << "Null state should return error";
}

TEST_F(TF5UeTest, UeInit_NullMpk_ReturnsError) {
    int ret = tf5_tesla_ue_init(&ue_state, nullptr, tf5_test::TV_SLOTS_PER_FRAME,
                                 TF5_TESLA_DEFAULT_D_BOUND_US, TF5_RP_DEFAULT_TIME_WINDOW_MS);

    EXPECT_LT(ret, 0) << "Null MPK should return error";
}

TEST_F(TF5UeTest, UeInit_DefaultTimestampWindow) {
    // Pass 0 for timestamp window - should use default
    int ret = tf5_tesla_ue_init(&ue_state, test_mpk, tf5_test::TV_SLOTS_PER_FRAME,
                                 TF5_TESLA_DEFAULT_D_BOUND_US, 0);

    EXPECT_EQ(0, ret);
    EXPECT_EQ(TF5_RP_DEFAULT_TIME_WINDOW_MS, ue_state.timestamp_window_ms)
        << "Should use default timestamp window when 0 is passed";
}

// ============================================================================
// Safe Packet Test (tf5_tesla_ue_safe_packet_test)
// ============================================================================

TEST_F(TF5UeTest, SafePacketTest_SafePacket_ReturnsTrue) {
    ASSERT_EQ(0, initUeDefault());

    // Set up TESLA params (normally set from extension)
    ue_state.tesla_params.t_int_ms = tf5_test::TV_EXT_T_INT_MS;
    ue_state.tesla_params.d = tf5_test::TV_EXT_D;
    ue_state.tesla_params.t0 = tf5_slot_time_make(0, 0);

    // Create extension claiming interval 5
    tf5_tesla_extension_t ext;
    memset(&ext, 0, sizeof(ext));
    ext.i = 5;
    ext.tesla_params = ue_state.tesla_params;

    // Receive at interval 5 (same interval) - should be safe
    // 5 intervals = 200 slots (at 40 slots/interval) = SFN 10, slot 0
    bool safe = tf5_tesla_ue_safe_packet_test(&ue_state, &ext, 10, 0);

    EXPECT_TRUE(safe) << "Packet received in same interval should be safe";
}

TEST_F(TF5UeTest, SafePacketTest_UnsafePacket_ReturnsFalse) {
    ASSERT_EQ(0, initUeDefault());

    ue_state.tesla_params.t_int_ms = tf5_test::TV_EXT_T_INT_MS;
    ue_state.tesla_params.d = 1;  // d = 1
    ue_state.tesla_params.t0 = tf5_slot_time_make(0, 0);

    // Create extension claiming interval 5
    tf5_tesla_extension_t ext;
    memset(&ext, 0, sizeof(ext));
    ext.i = 5;
    ext.tesla_params = ue_state.tesla_params;

    // Receive much later - at interval 10 (400 slots = SFN 20)
    // Safe if: x < i + d, i.e., 10 < 5 + 1 = 6? NO -> unsafe
    bool safe = tf5_tesla_ue_safe_packet_test(&ue_state, &ext, 20, 0);

    EXPECT_FALSE(safe) << "Packet received too late should be unsafe";
}

TEST_F(TF5UeTest, SafePacketTest_BoundaryExact_ReturnsFalse) {
    ASSERT_EQ(0, initUeDefault());

    ue_state.tesla_params.t_int_ms = tf5_test::TV_EXT_T_INT_MS;
    ue_state.tesla_params.d = 1;
    ue_state.tesla_params.t0 = tf5_slot_time_make(0, 0);

    // Create extension claiming interval 5
    tf5_tesla_extension_t ext;
    memset(&ext, 0, sizeof(ext));
    ext.i = 5;
    ext.tesla_params = ue_state.tesla_params;

    // Receive at exactly interval 6 (i + d boundary)
    // 6 intervals = 240 slots = SFN 12
    // Safe if: x < i + d, i.e., 6 < 6? NO -> unsafe
    bool safe = tf5_tesla_ue_safe_packet_test(&ue_state, &ext, 12, 0);

    EXPECT_FALSE(safe) << "Packet received exactly at boundary should be unsafe";
}

TEST_F(TF5UeTest, SafePacketTest_NullState_ReturnsFalse) {
    tf5_tesla_extension_t ext;
    memset(&ext, 0, sizeof(ext));

    bool safe = tf5_tesla_ue_safe_packet_test(nullptr, &ext, 0, 0);

    EXPECT_FALSE(safe) << "Null state should return false";
}

TEST_F(TF5UeTest, SafePacketTest_NullExt_ReturnsFalse) {
    ASSERT_EQ(0, initUeDefault());

    bool safe = tf5_tesla_ue_safe_packet_test(&ue_state, nullptr, 0, 0);

    EXPECT_FALSE(safe) << "Null extension should return false";
}

// ============================================================================
// Buffering Tests (tf5_tesla_ue_buffer_sib1)
// ============================================================================

TEST_F(TF5UeTest, BufferSib1_Success) {
    ASSERT_EQ(0, initUeDefault());

    const char auth_input[] = "test auth input";
    uint8_t tag[TF5_TESLA_TAG_LEN] = {0};
    tf5_tesla_slot_time_t rx_time = tf5_slot_time_make(0, 0);

    int ret = tf5_tesla_ue_buffer_sib1(
        &ue_state,
        (const uint8_t*)auth_input,
        strlen(auth_input),
        5,  // interval_index
        tag,
        &rx_time,
        false  // triggered_rrc_setup
    );

    EXPECT_EQ(0, ret) << "Buffer SIB1 should return 0 on success";
}

TEST_F(TF5UeTest, BufferSib1_QueueCountIncremented) {
    ASSERT_EQ(0, initUeDefault());

    const char auth_input[] = "test auth input";
    uint8_t tag[TF5_TESLA_TAG_LEN] = {0};
    tf5_tesla_slot_time_t rx_time = tf5_slot_time_make(0, 0);

    EXPECT_EQ(0, ue_state.buffer_queue_count);

    tf5_tesla_ue_buffer_sib1(&ue_state, (const uint8_t*)auth_input, strlen(auth_input),
                             5, tag, &rx_time, false);

    EXPECT_EQ(1, ue_state.buffer_queue_count);
}

TEST_F(TF5UeTest, BufferSib1_DataStored) {
    ASSERT_EQ(0, initUeDefault());

    const char auth_input[] = "test auth input data";
    uint8_t tag[TF5_TESLA_TAG_LEN] = {0xde, 0xad, 0xbe, 0xef};
    tf5_tesla_slot_time_t rx_time = tf5_slot_time_make(0, 0);

    tf5_tesla_ue_buffer_sib1(&ue_state, (const uint8_t*)auth_input, strlen(auth_input),
                             5, tag, &rx_time, false);

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
    tf5_tesla_slot_time_t rx_time = tf5_slot_time_make(0, 0);

    tf5_tesla_ue_buffer_sib1(&ue_state, (const uint8_t*)auth_input, strlen(auth_input),
                             5, tag, &rx_time, true);  // triggered_rrc_setup = true

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
    tf5_tesla_slot_time_t rx_time = tf5_slot_time_make(0, 0);

    tf5_tesla_ue_buffer_sib1(&ue_state, (const uint8_t*)auth_input1, strlen(auth_input1),
                             5, tag1, &rx_time, false);
    tf5_tesla_ue_buffer_sib1(&ue_state, (const uint8_t*)auth_input2, strlen(auth_input2),
                             6, tag2, &rx_time, false);

    EXPECT_EQ(2, ue_state.buffer_queue_count);
}

TEST_F(TF5UeTest, BufferSib1_FullQueue_DropsOldest) {
    ASSERT_EQ(0, initUeDefault());

    uint8_t tag[TF5_TESLA_TAG_LEN] = {0};
    tf5_tesla_slot_time_t rx_time = tf5_slot_time_make(0, 0);

    // Fill the queue
    for (int i = 0; i < TF5_TESLA_BUFFER_QUEUE_SIZE; i++) {
        char auth_input[32];
        snprintf(auth_input, sizeof(auth_input), "auth input %d", i);
        tf5_tesla_ue_buffer_sib1(&ue_state, (const uint8_t*)auth_input, strlen(auth_input),
                                 i, tag, &rx_time, false);
    }

    EXPECT_EQ(TF5_TESLA_BUFFER_QUEUE_SIZE, ue_state.buffer_queue_count);

    // Add one more - should replace oldest
    const char new_auth[] = "new auth input";
    tf5_tesla_ue_buffer_sib1(&ue_state, (const uint8_t*)new_auth, strlen(new_auth),
                             99, tag, &rx_time, false);

    // Queue should still be at max size
    EXPECT_EQ(TF5_TESLA_BUFFER_QUEUE_SIZE, ue_state.buffer_queue_count);
}

TEST_F(TF5UeTest, BufferSib1_NullInputs_ReturnsError) {
    ASSERT_EQ(0, initUeDefault());

    uint8_t tag[TF5_TESLA_TAG_LEN] = {0};
    tf5_tesla_slot_time_t rx_time = tf5_slot_time_make(0, 0);

    int ret = tf5_tesla_ue_buffer_sib1(nullptr, (const uint8_t*)"test", 4, 5, tag, &rx_time, false);
    EXPECT_LT(ret, 0) << "Null state should return error";

    ret = tf5_tesla_ue_buffer_sib1(&ue_state, nullptr, 4, 5, tag, &rx_time, false);
    EXPECT_LT(ret, 0) << "Null auth_input should return error";

    ret = tf5_tesla_ue_buffer_sib1(&ue_state, (const uint8_t*)"test", 4, 5, nullptr, &rx_time, false);
    EXPECT_LT(ret, 0) << "Null tag should return error";
}

// ============================================================================
// Key Chain Verification Tests (tf5_tesla_ue_verify_key_chain)
// ============================================================================

TEST_F(TF5UeTest, VerifyKeyChain_ValidChain_ReturnsTrue) {
    ASSERT_EQ(0, initUeDefault());
    ASSERT_EQ(0, initGnbDefault(10));

    // Set up UE with K_0 as trust anchor (from bootstrap)
    setupUeWithTrustAnchor(gnb_state.key_chain[0], 0);

    // Verify K_1 chains to K_0
    bool valid = tf5_tesla_ue_verify_key_chain(&ue_state, gnb_state.key_chain[1], 1);

    EXPECT_TRUE(valid) << "K_1 should chain to K_0";
}

TEST_F(TF5UeTest, VerifyKeyChain_InvalidChain_ReturnsFalse) {
    ASSERT_EQ(0, initUeDefault());
    ASSERT_EQ(0, initGnbDefault(10));

    // Set up UE with K_0 as trust anchor
    setupUeWithTrustAnchor(gnb_state.key_chain[0], 0);

    // Try to verify a fake key
    uint8_t fake_key[TF5_TESLA_KEY_LEN] = {0xff, 0xff, 0xff, 0xff};

    bool valid = tf5_tesla_ue_verify_key_chain(&ue_state, fake_key, 1);

    EXPECT_FALSE(valid) << "Fake key should not chain to anchor";
}

TEST_F(TF5UeTest, VerifyKeyChain_SkippedKeys_MultipleHashOps) {
    ASSERT_EQ(0, initUeDefault());
    ASSERT_EQ(0, initGnbDefault(10));

    // Set up UE with K_0 as trust anchor
    setupUeWithTrustAnchor(gnb_state.key_chain[0], 0);

    // Verify K_5 chains to K_0 (requires 5 hash operations)
    bool valid = tf5_tesla_ue_verify_key_chain(&ue_state, gnb_state.key_chain[5], 5);

    EXPECT_TRUE(valid) << "K_5 should chain to K_0 via 5 hash ops";
}

TEST_F(TF5UeTest, VerifyKeyChain_BootstrapAnchor) {
    ASSERT_EQ(0, initUeDefault());
    ASSERT_EQ(0, initGnbDefault(10));

    // Set up UE with K_{-1} as bootstrap anchor
    memcpy(ue_state.trust_anchor_key, gnb_state.k_bootstrap, TF5_TESLA_KEY_LEN);
    ue_state.trust_anchor_idx = TF5_TESLA_BOOTSTRAP_IDX;
    ue_state.chain_bootstrapped = true;

    // Verify K_0 chains to K_{-1}
    bool valid = tf5_tesla_ue_verify_key_chain(&ue_state, gnb_state.key_chain[0], 0);

    EXPECT_TRUE(valid) << "K_0 should chain to K_{-1} (bootstrap anchor)";
}

TEST_F(TF5UeTest, VerifyKeyChain_NotBootstrapped_ReturnsFalse) {
    ASSERT_EQ(0, initUeDefault());
    ASSERT_EQ(0, initGnbDefault(10));

    // UE is not bootstrapped (no trust anchor)
    EXPECT_FALSE(ue_state.chain_bootstrapped);

    bool valid = tf5_tesla_ue_verify_key_chain(&ue_state, gnb_state.key_chain[1], 1);

    EXPECT_FALSE(valid) << "Should fail when not bootstrapped";
}

TEST_F(TF5UeTest, VerifyKeyChain_NullInputs_ReturnsFalse) {
    ASSERT_EQ(0, initUeDefault());

    uint8_t key[TF5_TESLA_KEY_LEN] = {0};

    bool valid = tf5_tesla_ue_verify_key_chain(nullptr, key, 1);
    EXPECT_FALSE(valid) << "Null state should return false";

    valid = tf5_tesla_ue_verify_key_chain(&ue_state, nullptr, 1);
    EXPECT_FALSE(valid) << "Null key should return false";
}

// ============================================================================
// Buffered Verification Tests (tf5_tesla_ue_verify_all_buffered)
// ============================================================================

TEST_F(TF5UeTest, VerifyAllBuffered_ValidTags_Success) {
    ASSERT_EQ(0, initUeDefault());
    ASSERT_EQ(0, initGnbDefault(100));

    // Generate a valid gNB extension to get a proper tag
    tf5_tesla_extension_t ext;
    const char sib1[] = "Test SIB1 content";
    tf5_tesla_gnb_prepare_extension(&gnb_state, 5, 0, (const uint8_t*)sib1, strlen(sib1), &ext);

    // Set up UE with proper TESLA params and trust anchor
    ue_state.tesla_params = ext.tesla_params;
    setupUeWithTrustAnchor(gnb_state.key_chain[0], 0);

    // Build the MAC auth input and buffer it
    uint8_t mac_auth_input[TF5_MAX_AUTH_INPUT];
    size_t mac_auth_input_len;
    tf5_tesla_build_mac_auth_input(mac_auth_input, &mac_auth_input_len,
                                   (const uint8_t*)sib1, strlen(sib1),
                                   gnb_state.key_validity_end);

    tf5_tesla_slot_time_t rx_time = tf5_slot_time_make(5, 0);
    tf5_tesla_ue_buffer_sib1(&ue_state, mac_auth_input, mac_auth_input_len,
                             ext.i, ext.tesla_tag, &rx_time, false);

    // Verify using the disclosed key
    int verified_count = 0, failed_count = 0;
    bool rrc_trigger_verified = false;

    int ret = tf5_tesla_ue_verify_all_buffered(&ue_state, gnb_state.key_chain[ext.i],
                                                ext.i, &verified_count, &failed_count,
                                                &rrc_trigger_verified);

    EXPECT_EQ(0, ret) << "Verification should succeed";
    EXPECT_EQ(1, verified_count) << "One entry should be verified";
    EXPECT_EQ(0, failed_count) << "No entries should fail";
}

TEST_F(TF5UeTest, VerifyAllBuffered_InvalidTag_Fails) {
    ASSERT_EQ(0, initUeDefault());
    ASSERT_EQ(0, initGnbDefault(100));

    // Set up UE with trust anchor
    setupUeWithTrustAnchor(gnb_state.key_chain[0], 0);
    ue_state.tesla_params.t_int_ms = tf5_test::TV_EXT_T_INT_MS;
    ue_state.tesla_params.d = tf5_test::TV_EXT_D;

    // Buffer an entry with a fake tag
    const char auth_input[] = "test auth input";
    uint8_t fake_tag[TF5_TESLA_TAG_LEN] = {0xba, 0xad, 0xf0, 0x0d};
    tf5_tesla_slot_time_t rx_time = tf5_slot_time_make(0, 0);

    tf5_tesla_ue_buffer_sib1(&ue_state, (const uint8_t*)auth_input, strlen(auth_input),
                             5, fake_tag, &rx_time, false);

    // Try to verify
    int verified_count = 0, failed_count = 0;
    bool rrc_trigger_verified = false;

    int ret = tf5_tesla_ue_verify_all_buffered(&ue_state, gnb_state.key_chain[5],
                                                5, &verified_count, &failed_count,
                                                &rrc_trigger_verified);

    EXPECT_LT(ret, 0) << "Verification should fail with invalid tag";
    EXPECT_EQ(0, verified_count) << "No entries should be verified";
    EXPECT_EQ(1, failed_count) << "One entry should fail";
}

TEST_F(TF5UeTest, VerifyAllBuffered_NoEntries_ReturnsError) {
    ASSERT_EQ(0, initUeDefault());
    ASSERT_EQ(0, initGnbDefault(100));

    setupUeWithTrustAnchor(gnb_state.key_chain[0], 0);

    // Don't buffer anything
    int verified_count = 0, failed_count = 0;
    bool rrc_trigger_verified = false;

    int ret = tf5_tesla_ue_verify_all_buffered(&ue_state, gnb_state.key_chain[5],
                                                5, &verified_count, &failed_count,
                                                &rrc_trigger_verified);

    EXPECT_LT(ret, 0) << "Should return error when no entries to verify";
}

// ============================================================================
// Key Recovery Tests (tf5_tesla_ue_verify_with_key_recovery)
// ============================================================================

TEST_F(TF5UeTest, KeyRecovery_SingleMissedInterval) {
    ASSERT_EQ(0, initUeDefault());
    ASSERT_EQ(0, initGnbDefault(100));

    // Generate extensions for intervals 5 and 7
    tf5_tesla_extension_t ext5, ext7;
    const char sib1_5[] = "SIB1 at interval 5";
    const char sib1_7[] = "SIB1 at interval 7";

    // Interval 5 = 200 slots = SFN 10
    tf5_tesla_gnb_prepare_extension(&gnb_state, 10, 0, (const uint8_t*)sib1_5, strlen(sib1_5), &ext5);
    // Interval 7 = 280 slots = SFN 14
    tf5_tesla_gnb_prepare_extension(&gnb_state, 14, 0, (const uint8_t*)sib1_7, strlen(sib1_7), &ext7);

    // Set up UE
    ue_state.tesla_params = ext5.tesla_params;
    setupUeWithTrustAnchor(gnb_state.key_chain[0], 0);

    // Buffer SIB1 from interval 5
    uint8_t mac_auth_input[TF5_MAX_AUTH_INPUT];
    size_t mac_auth_input_len;
    tf5_tesla_build_mac_auth_input(mac_auth_input, &mac_auth_input_len,
                                   (const uint8_t*)sib1_5, strlen(sib1_5),
                                   gnb_state.key_validity_end);

    tf5_tesla_slot_time_t rx_time = tf5_slot_time_make(10, 0);
    tf5_tesla_ue_buffer_sib1(&ue_state, mac_auth_input, mac_auth_input_len,
                             5, ext5.tesla_tag, &rx_time, false);

    // Simulate missed disclosure for interval 5, receive at interval 7
    // Use key from interval 7 to recover key for interval 5
    int total_verified = 0, total_failed = 0;
    bool rrc_trigger_verified = false;

    // This should recover K_5 from K_7 and verify the buffered entry
    int ret = tf5_tesla_ue_verify_with_key_recovery(&ue_state, gnb_state.key_chain[7],
                                                     7, &total_verified, &total_failed,
                                                     &rrc_trigger_verified);

    EXPECT_EQ(0, ret) << "Key recovery should succeed";
    EXPECT_EQ(1, total_verified) << "One entry should be verified via key recovery";
}

// ============================================================================
// IBS Signature Verification Tests (tf5_tesla_ue_verify_signature)
// ============================================================================

/**
 * Test fixture for IBS signature verification that uses Core PKG binaries
 * to generate properly issued IBS keys.
 */
class TF5UeSignatureTest : public TF5UeTest {
protected:
    // Paths to PKG binaries (relative to test working directory: oai-tf5/cmake_targets/ran_build/build/openair3/SECU/tests)
    static constexpr const char* PKG_KEYGEN_PATH = "../../../../../../../tf5-code/core-pkg/build/tf5_ibs_pkg_keygen";
    static constexpr const char* PKG_ISSUE_PATH = "../../../../../../../tf5-code/core-pkg/build/tf5_ibs_issue";

    std::string test_dir;
    std::string msk_path;
    std::string mpk_path;
    std::string sk_gnb_path;

    // IBS keys generated by PKG
    uint8_t ibs_msk[TF5_BLS_SECRET_KEY_LEN];
    uint8_t ibs_mpk[TF5_IBS_PUBKEY_LEN];
    uint8_t ibs_sk[TF5_BLS_SECRET_KEY_LEN];  // sk_ID issued by PKG
    uint8_t cell_id[TF5_IBS_CELL_ID_LEN];
    uint32_t validity_end;

    bool pkg_available;

    void SetUp() override {
        TF5UeTest::SetUp();

        // Set up test cell ID and validity
        memset(cell_id, 0, TF5_IBS_CELL_ID_LEN);
        cell_id[0] = 0x12;
        cell_id[1] = 0x34;
        cell_id[2] = 0x56;
        cell_id[3] = 0x78;
        cell_id[4] = 0x90;  // 36-bit cell ID = 0x123456789

        validity_end = 1051200;  // 2 years

        // Create temp directory for PKG output
        test_dir = "/tmp/tf5_ue_sig_test_" + std::to_string(getpid());
        mkdir(test_dir.c_str(), 0700);
        msk_path = test_dir + "/msk.bin";
        mpk_path = test_dir + "/mpk.bin";
        sk_gnb_path = test_dir + "/sk_gnb.bin";

        // Check if PKG binaries are available and generate keys
        pkg_available = checkAndGenerateKeys();
    }

    void TearDown() override {
        // Clean up temp files
        unlink(msk_path.c_str());
        unlink(mpk_path.c_str());
        unlink(sk_gnb_path.c_str());
        rmdir(test_dir.c_str());

        TF5UeTest::TearDown();
    }

    bool checkAndGenerateKeys() {
        // Check if keygen binary exists
        if (access(PKG_KEYGEN_PATH, X_OK) != 0) {
            return false;
        }
        // Check if issue binary exists
        if (access(PKG_ISSUE_PATH, X_OK) != 0) {
            return false;
        }

        // Generate master keypair
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "%s %s %s >/dev/null 2>&1",
                 PKG_KEYGEN_PATH, msk_path.c_str(), mpk_path.c_str());
        if (system(cmd) != 0) return false;

        // Issue gNB key
        snprintf(cmd, sizeof(cmd), "%s %s 123456789 %u %s >/dev/null 2>&1",
                 PKG_ISSUE_PATH, msk_path.c_str(), validity_end, sk_gnb_path.c_str());
        if (system(cmd) != 0) return false;

        // Load generated keys
        return loadGeneratedKeys();
    }

    bool loadGeneratedKeys() {
        // Load MSK
        FILE* f = fopen(msk_path.c_str(), "rb");
        if (!f) return false;
        size_t n = fread(ibs_msk, 1, TF5_BLS_SECRET_KEY_LEN, f);
        fclose(f);
        if (n != TF5_BLS_SECRET_KEY_LEN) return false;

        // Load MPK
        f = fopen(mpk_path.c_str(), "rb");
        if (!f) return false;
        n = fread(ibs_mpk, 1, TF5_IBS_PUBKEY_LEN, f);
        fclose(f);
        if (n != TF5_IBS_PUBKEY_LEN) return false;

        // Load gNB secret key (35 bytes: 32 sk + 3 validity)
        f = fopen(sk_gnb_path.c_str(), "rb");
        if (!f) return false;
        uint8_t sk_file[35];
        n = fread(sk_file, 1, 35, f);
        fclose(f);
        if (n != 35) return false;

        // Extract secret key (first 32 bytes)
        memcpy(ibs_sk, sk_file, TF5_BLS_SECRET_KEY_LEN);

        return true;
    }

    // Helper to initialize UE with the PKG-generated MPK
    int initUeWithTestMpk() {
        return tf5_tesla_ue_init(&ue_state, ibs_mpk, tf5_test::TV_SLOTS_PER_FRAME,
                                  TF5_TESLA_DEFAULT_D_BOUND_US, TF5_RP_DEFAULT_TIME_WINDOW_MS);
    }

    // Helper to create a valid IBS signature using the PKG-issued key
    void createValidSignature(const uint8_t* auth_input, size_t auth_input_len,
                              uint8_t signature_out[TF5_TESLA_SIG_LEN]) {
        // Sign with sk_ID (the IBS secret key issued by PKG)
        int rc = tf5_tesla_bls_sign(ibs_sk, auth_input, auth_input_len, signature_out);
        ASSERT_EQ(0, rc) << "Failed to create signature";
    }
};

// IBS signature verification test using PKG-generated keys
TEST_F(TF5UeSignatureTest, VerifySignature_ValidIBS_ReturnsZero) {
    if (!pkg_available) {
        GTEST_SKIP() << "PKG binaries not available, skipping IBS verification test";
    }

    ASSERT_EQ(0, initUeWithTestMpk());

    const char auth_input[] = "test authentication input for IBS signature";
    uint8_t signature[TF5_TESLA_SIG_LEN];

    // Create a valid IBS signature using the PKG-issued key
    createValidSignature((const uint8_t*)auth_input, strlen(auth_input), signature);

    int ret = tf5_tesla_ue_verify_signature(&ue_state, cell_id, validity_end,
                                             (const uint8_t*)auth_input, strlen(auth_input),
                                             signature);

    EXPECT_EQ(0, ret) << "Valid IBS signature should verify successfully";
}

TEST_F(TF5UeSignatureTest, VerifySignature_TamperedData_Fails) {
    if (!pkg_available) {
        GTEST_SKIP() << "PKG binaries not available, skipping IBS test";
    }
    ASSERT_EQ(0, initUeWithTestMpk());

    const char auth_input[] = "original authentication input";
    uint8_t signature[TF5_TESLA_SIG_LEN];

    // Create signature over original data
    createValidSignature((const uint8_t*)auth_input, strlen(auth_input), signature);

    // Verify with tampered data
    const char tampered_input[] = "tampered authentication input";

    int ret = tf5_tesla_ue_verify_signature(&ue_state, cell_id, validity_end,
                                             (const uint8_t*)tampered_input, strlen(tampered_input),
                                             signature);

    EXPECT_NE(0, ret) << "Tampered data should fail verification";
}

TEST_F(TF5UeSignatureTest, VerifySignature_TamperedSignature_Fails) {
    if (!pkg_available) {
        GTEST_SKIP() << "PKG binaries not available, skipping IBS test";
    }
    ASSERT_EQ(0, initUeWithTestMpk());

    const char auth_input[] = "test authentication input";
    uint8_t signature[TF5_TESLA_SIG_LEN];

    // Create a valid signature
    createValidSignature((const uint8_t*)auth_input, strlen(auth_input), signature);

    // Tamper with the signature
    signature[0] ^= 0xFF;
    signature[10] ^= 0xFF;

    int ret = tf5_tesla_ue_verify_signature(&ue_state, cell_id, validity_end,
                                             (const uint8_t*)auth_input, strlen(auth_input),
                                             signature);

    EXPECT_NE(0, ret) << "Tampered signature should fail verification";
}

TEST_F(TF5UeSignatureTest, VerifySignature_WrongCellId_Fails) {
    if (!pkg_available) {
        GTEST_SKIP() << "PKG binaries not available, skipping IBS test";
    }
    ASSERT_EQ(0, initUeWithTestMpk());

    const char auth_input[] = "test authentication input";
    uint8_t signature[TF5_TESLA_SIG_LEN];

    // Create a valid signature
    createValidSignature((const uint8_t*)auth_input, strlen(auth_input), signature);

    // Use wrong cell ID
    uint8_t wrong_cell_id[TF5_IBS_CELL_ID_LEN] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE};

    int ret = tf5_tesla_ue_verify_signature(&ue_state, wrong_cell_id, validity_end,
                                             (const uint8_t*)auth_input, strlen(auth_input),
                                             signature);

    EXPECT_NE(0, ret) << "Wrong cell ID should fail verification";
}

TEST_F(TF5UeSignatureTest, VerifySignature_WrongValidity_Fails) {
    if (!pkg_available) {
        GTEST_SKIP() << "PKG binaries not available, skipping IBS test";
    }
    ASSERT_EQ(0, initUeWithTestMpk());

    const char auth_input[] = "test authentication input";
    uint8_t signature[TF5_TESLA_SIG_LEN];

    // Create a valid signature
    createValidSignature((const uint8_t*)auth_input, strlen(auth_input), signature);

    // Use wrong validity
    uint32_t wrong_validity = 999999;

    int ret = tf5_tesla_ue_verify_signature(&ue_state, cell_id, wrong_validity,
                                             (const uint8_t*)auth_input, strlen(auth_input),
                                             signature);

    EXPECT_NE(0, ret) << "Wrong validity should fail verification";
}

TEST_F(TF5UeSignatureTest, VerifySignature_WrongMpk_Fails) {
    if (!pkg_available) {
        GTEST_SKIP() << "PKG binaries not available, skipping IBS test";
    }

    // Initialize UE with wrong MPK
    uint8_t wrong_mpk[TF5_IBS_PUBKEY_LEN];
    memset(wrong_mpk, 0x99, TF5_IBS_PUBKEY_LEN);

    int init_ret = tf5_tesla_ue_init(&ue_state, wrong_mpk, tf5_test::TV_SLOTS_PER_FRAME,
                                      TF5_TESLA_DEFAULT_D_BOUND_US, TF5_RP_DEFAULT_TIME_WINDOW_MS);
    ASSERT_EQ(0, init_ret);

    const char auth_input[] = "test authentication input";
    uint8_t signature[TF5_TESLA_SIG_LEN];

    // Create signature with correct key
    createValidSignature((const uint8_t*)auth_input, strlen(auth_input), signature);

    // Verify with wrong MPK - should fail
    int ret = tf5_tesla_ue_verify_signature(&ue_state, cell_id, validity_end,
                                             (const uint8_t*)auth_input, strlen(auth_input),
                                             signature);

    EXPECT_NE(0, ret) << "Wrong MPK should fail verification";
}

TEST_F(TF5UeSignatureTest, VerifySignature_NullState_ReturnsError) {
    const char auth_input[] = "test";
    uint8_t signature[TF5_TESLA_SIG_LEN] = {0};

    int ret = tf5_tesla_ue_verify_signature(nullptr, cell_id, validity_end,
                                             (const uint8_t*)auth_input, strlen(auth_input),
                                             signature);

    EXPECT_LT(ret, 0) << "Null state should return error";
}

TEST_F(TF5UeSignatureTest, VerifySignature_NullCellId_ReturnsError) {
    ASSERT_EQ(0, initUeWithTestMpk());

    const char auth_input[] = "test";
    uint8_t signature[TF5_TESLA_SIG_LEN] = {0};

    int ret = tf5_tesla_ue_verify_signature(&ue_state, nullptr, validity_end,
                                             (const uint8_t*)auth_input, strlen(auth_input),
                                             signature);

    EXPECT_LT(ret, 0) << "Null cell_id should return error";
}

TEST_F(TF5UeSignatureTest, VerifySignature_NullAuthInput_ReturnsError) {
    ASSERT_EQ(0, initUeWithTestMpk());

    uint8_t signature[TF5_TESLA_SIG_LEN] = {0};

    int ret = tf5_tesla_ue_verify_signature(&ue_state, cell_id, validity_end,
                                             nullptr, 10, signature);

    EXPECT_LT(ret, 0) << "Null auth_input should return error";
}

TEST_F(TF5UeSignatureTest, VerifySignature_NullSignature_ReturnsError) {
    ASSERT_EQ(0, initUeWithTestMpk());

    const char auth_input[] = "test";

    int ret = tf5_tesla_ue_verify_signature(&ue_state, cell_id, validity_end,
                                             (const uint8_t*)auth_input, strlen(auth_input),
                                             nullptr);

    EXPECT_LT(ret, 0) << "Null signature should return error";
}

TEST_F(TF5UeSignatureTest, VerifySignature_UninitializedState_ReturnsError) {
    // Don't initialize state
    const char auth_input[] = "test";
    uint8_t signature[TF5_TESLA_SIG_LEN] = {0};

    int ret = tf5_tesla_ue_verify_signature(&ue_state, cell_id, validity_end,
                                             (const uint8_t*)auth_input, strlen(auth_input),
                                             signature);

    EXPECT_LT(ret, 0) << "Uninitialized state should return error";
}

// ============================================================================
// Legacy Single-Entry Verification Tests (tf5_tesla_ue_verify_buffered)
// ============================================================================

TEST_F(TF5UeTest, VerifyBuffered_Success) {
    ASSERT_EQ(0, initUeDefault());
    ASSERT_EQ(0, initGnbDefault(100));

    // Generate a valid extension
    tf5_tesla_extension_t ext;
    const char sib1[] = "Test SIB1 for verify_buffered";
    tf5_tesla_gnb_prepare_extension(&gnb_state, 5, 0, (const uint8_t*)sib1, strlen(sib1), &ext);

    // Set up UE
    ue_state.tesla_params = ext.tesla_params;
    setupUeWithTrustAnchor(gnb_state.key_chain[0], 0);

    // Build MAC auth input and buffer
    uint8_t mac_auth_input[TF5_MAX_AUTH_INPUT];
    size_t mac_auth_input_len;
    tf5_tesla_build_mac_auth_input(mac_auth_input, &mac_auth_input_len,
                                   (const uint8_t*)sib1, strlen(sib1),
                                   gnb_state.key_validity_end);

    tf5_tesla_slot_time_t rx_time = tf5_slot_time_make(5, 0);
    tf5_tesla_ue_buffer_sib1(&ue_state, mac_auth_input, mac_auth_input_len,
                             ext.i, ext.tesla_tag, &rx_time, false);

    // Use legacy verify_buffered function
    int ret = tf5_tesla_ue_verify_buffered(&ue_state, gnb_state.key_chain[ext.i], ext.i);

    EXPECT_EQ(0, ret) << "Legacy verify_buffered should succeed with valid entry";
}

TEST_F(TF5UeTest, VerifyBuffered_InvalidTag_Fails) {
    ASSERT_EQ(0, initUeDefault());
    ASSERT_EQ(0, initGnbDefault(100));

    // Set up UE with trust anchor
    setupUeWithTrustAnchor(gnb_state.key_chain[0], 0);
    ue_state.tesla_params.t_int_ms = tf5_test::TV_EXT_T_INT_MS;
    ue_state.tesla_params.d = tf5_test::TV_EXT_D;

    // Buffer entry with invalid tag
    const char auth_input[] = "test auth input";
    uint8_t fake_tag[TF5_TESLA_TAG_LEN] = {0xDE, 0xAD, 0xBE, 0xEF};
    tf5_tesla_slot_time_t rx_time = tf5_slot_time_make(0, 0);

    tf5_tesla_ue_buffer_sib1(&ue_state, (const uint8_t*)auth_input, strlen(auth_input),
                             5, fake_tag, &rx_time, false);

    int ret = tf5_tesla_ue_verify_buffered(&ue_state, gnb_state.key_chain[5], 5);

    EXPECT_LT(ret, 0) << "Legacy verify_buffered should fail with invalid tag";
}

TEST_F(TF5UeTest, VerifyBuffered_NoMatchingEntry_Fails) {
    ASSERT_EQ(0, initUeDefault());
    ASSERT_EQ(0, initGnbDefault(100));

    setupUeWithTrustAnchor(gnb_state.key_chain[0], 0);

    // Buffer entry for interval 5
    const char auth_input[] = "test";
    uint8_t tag[TF5_TESLA_TAG_LEN] = {0};
    tf5_tesla_slot_time_t rx_time = tf5_slot_time_make(0, 0);
    tf5_tesla_ue_buffer_sib1(&ue_state, (const uint8_t*)auth_input, strlen(auth_input),
                             5, tag, &rx_time, false);

    // Try to verify interval 10 (no entry exists)
    int ret = tf5_tesla_ue_verify_buffered(&ue_state, gnb_state.key_chain[10], 10);

    EXPECT_LT(ret, 0) << "Should return error when no matching entry exists";
}

TEST_F(TF5UeTest, VerifyBuffered_NullState_ReturnsError) {
    uint8_t key[TF5_TESLA_KEY_LEN] = {0};

    int ret = tf5_tesla_ue_verify_buffered(nullptr, key, 5);

    EXPECT_LT(ret, 0) << "Null state should return error";
}

TEST_F(TF5UeTest, VerifyBuffered_NullKey_ReturnsError) {
    ASSERT_EQ(0, initUeDefault());

    int ret = tf5_tesla_ue_verify_buffered(&ue_state, nullptr, 5);

    EXPECT_LT(ret, 0) << "Null disclosed_key should return error";
}

// ============================================================================
// Authentication State Machine Tests
// ============================================================================

TEST_F(TF5UeTest, AuthState_InitialStateIsUnauthenticated) {
    // Covered by UeInit_AuthStateUnauthenticated - but verify explicitly here
    ASSERT_EQ(0, initUeDefault());

    EXPECT_EQ(TF5_AUTH_STATE_UNAUTHENTICATED, ue_state.auth_state)
        << "Initial auth state should be UNAUTHENTICATED";
}

TEST_F(TF5UeTest, AuthState_CanBeSetToBuffered) {
    ASSERT_EQ(0, initUeDefault());

    // Simulate RRC layer setting BUFFERED state after buffering SIB1
    ue_state.auth_state = TF5_AUTH_STATE_BUFFERED;

    EXPECT_EQ(TF5_AUTH_STATE_BUFFERED, ue_state.auth_state)
        << "Auth state should be settable to BUFFERED";
}

TEST_F(TF5UeTest, AuthState_RrcTriggerTrackedInBuffer) {
    ASSERT_EQ(0, initUeDefault());
    ASSERT_EQ(0, initGnbDefault(100));

    // Generate valid extension
    tf5_tesla_extension_t ext;
    const char sib1[] = "SIB1 that triggers RRC setup";
    tf5_tesla_gnb_prepare_extension(&gnb_state, 5, 0, (const uint8_t*)sib1, strlen(sib1), &ext);

    // Set up UE
    ue_state.tesla_params = ext.tesla_params;
    setupUeWithTrustAnchor(gnb_state.key_chain[0], 0);

    // Buffer with triggered_rrc_setup = true
    uint8_t mac_auth_input[TF5_MAX_AUTH_INPUT];
    size_t mac_auth_input_len;
    tf5_tesla_build_mac_auth_input(mac_auth_input, &mac_auth_input_len,
                                   (const uint8_t*)sib1, strlen(sib1),
                                   gnb_state.key_validity_end);

    tf5_tesla_slot_time_t rx_time = tf5_slot_time_make(5, 0);
    int ret = tf5_tesla_ue_buffer_sib1(&ue_state, mac_auth_input, mac_auth_input_len,
                                        ext.i, ext.tesla_tag, &rx_time, true);  // RRC trigger!

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
    tf5_tesla_extension_t ext;
    const char sib1[] = "SIB1 that triggers RRC setup";
    tf5_tesla_gnb_prepare_extension(&gnb_state, 5, 0, (const uint8_t*)sib1, strlen(sib1), &ext);

    // Set up UE
    ue_state.tesla_params = ext.tesla_params;
    setupUeWithTrustAnchor(gnb_state.key_chain[0], 0);

    // Buffer with triggered_rrc_setup = true
    uint8_t mac_auth_input[TF5_MAX_AUTH_INPUT];
    size_t mac_auth_input_len;
    tf5_tesla_build_mac_auth_input(mac_auth_input, &mac_auth_input_len,
                                   (const uint8_t*)sib1, strlen(sib1),
                                   gnb_state.key_validity_end);

    tf5_tesla_slot_time_t rx_time = tf5_slot_time_make(5, 0);
    tf5_tesla_ue_buffer_sib1(&ue_state, mac_auth_input, mac_auth_input_len,
                             ext.i, ext.tesla_tag, &rx_time, true);  // RRC trigger!

    // Verify and check rrc_trigger_verified
    int verified_count = 0, failed_count = 0;
    bool rrc_trigger_verified = false;

    int ret = tf5_tesla_ue_verify_all_buffered(&ue_state, gnb_state.key_chain[ext.i],
                                                ext.i, &verified_count, &failed_count,
                                                &rrc_trigger_verified);

    EXPECT_EQ(0, ret) << "Verification should succeed";
    EXPECT_TRUE(rrc_trigger_verified) << "rrc_trigger_verified should be true when RRC-triggering SIB1 verifies";
}

TEST_F(TF5UeTest, AuthState_RrcSetupDeferredCanBeSet) {
    ASSERT_EQ(0, initUeDefault());

    // Simulate RRC layer setting RRCSETUP_DEFERRED state
    ue_state.auth_state = TF5_AUTH_STATE_BUFFERED;
    ue_state.rrcsetup_transaction_id = 42;  // Save transaction ID

    // RRCSetup received while auth pending
    ue_state.auth_state = TF5_AUTH_STATE_RRCSETUP_DEFERRED;

    EXPECT_EQ(TF5_AUTH_STATE_RRCSETUP_DEFERRED, ue_state.auth_state)
        << "Auth state should be settable to RRCSETUP_DEFERRED";
    EXPECT_EQ(42, ue_state.rrcsetup_transaction_id)
        << "Transaction ID should be preserved";
}

// ============================================================================
// Free Tests (tf5_tesla_ue_free)
// ============================================================================

TEST_F(TF5UeTest, UeFree_Success) {
    ASSERT_EQ(0, initUeDefault());

    tf5_tesla_ue_free(&ue_state);

    EXPECT_FALSE(ue_state.initialized) << "State should be marked as not initialized";
}

TEST_F(TF5UeTest, UeFree_NullState_NoOp) {
    // Should not crash
    tf5_tesla_ue_free(nullptr);
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
