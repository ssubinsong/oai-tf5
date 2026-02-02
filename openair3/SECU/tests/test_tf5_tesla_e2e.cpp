/**
 * @file test_tf5_tesla_e2e.cpp
 * @brief End-to-end integration tests for TF5 TESLA
 *
 * Tests the complete gNB -> UE flow:
 * - gNB generates extension with signature and tag
 * - Extension is serialized and transmitted
 * - UE deserializes and verifies the extension
 */

#include <gtest/gtest.h>
#include <cstring>

extern "C" {
#include "openair3/SECU/tf5_tesla.h"
}

#include "tf5_test_vectors.h"

// Extension packed size
#define TF5_EXTENSION_PACKED_SIZE 102

class TF5E2ETest : public ::testing::Test {
protected:
    // gNB state
    tf5_gnb_state_t gnb_state;
    uint8_t gnb_private_key[TF5_BLS_SECRET_KEY_LEN];
    uint8_t gnb_public_key[TF5_BLS_PUBKEY_LEN];

    // UE state
    tf5_tesla_ue_state_t ue_state;

    // Simulated cell ID
    uint8_t cell_id[TF5_IBS_CELL_ID_LEN];

    // T_0 timing
    tf5_tesla_slot_time_t t0;

    static bool bls_initialized;

    void SetUp() override {
        // Initialize BLS library once
        if (!bls_initialized) {
            tf5_tesla_bls_init();
            bls_initialized = true;
        }

        // Clear states
        memset(&gnb_state, 0, sizeof(gnb_state));
        memset(&ue_state, 0, sizeof(ue_state));

        // Generate gNB key pair
        memcpy(gnb_private_key, tf5_test::TV_BLS_SECRET_KEY, TF5_BLS_SECRET_KEY_LEN);
        tf5_tesla_bls_derive_public(gnb_private_key, gnb_public_key);

        // Set cell ID
        memcpy(cell_id, tf5_test::TV_IBS_CELL_ID, TF5_IBS_CELL_ID_LEN);

        // Set T_0
        t0 = tf5_slot_time_make(0, 0);
    }

    void TearDown() override {
        tf5_tesla_gnb_free(&gnb_state);
        tf5_tesla_ue_free(&ue_state);
    }

    // Initialize gNB with test parameters
    int initGnb(uint32_t chain_len = 100) {
        return tf5_tesla_gnb_init(
            &gnb_state,
            tf5_test::TV_EXT_T_INT_MS,   // t_int_ms = 20
            tf5_test::TV_EXT_D,          // d = 1
            chain_len,
            gnb_private_key,
            &t0,
            tf5_test::TV_SLOTS_PER_FRAME
        );
    }

    // Initialize UE with test parameters
    int initUe() {
        return tf5_tesla_ue_init(
            &ue_state,
            gnb_public_key,  // Use gNB's public key as MPK for testing
            tf5_test::TV_SLOTS_PER_FRAME,
            TF5_TESLA_DEFAULT_D_BOUND_US,
            TF5_RP_DEFAULT_TIME_WINDOW_MS
        );
    }

    // Simulate gNB extension preparation and transmission
    int gnbPrepareAndPack(uint16_t sfn, uint16_t slot,
                          const uint8_t* sib1, size_t sib1_len,
                          tf5_tesla_extension_t* ext,
                          uint8_t* packed, size_t packed_len) {
        int ret = tf5_tesla_gnb_prepare_extension(&gnb_state, sfn, slot, sib1, sib1_len, ext);
        if (ret != 0) return ret;

        ret = tf5_tesla_pack_extension(ext, packed, packed_len);
        return ret;
    }

    // Simulate UE receive and unpack
    int ueReceiveAndUnpack(const uint8_t* packed, size_t packed_len,
                           tf5_tesla_extension_t* ext) {
        return tf5_tesla_unpack_extension(packed, packed_len, ext);
    }

    // Setup UE with TESLA params and bootstrap anchor
    void bootstrapUe(const tf5_tesla_extension_t* ext) {
        ue_state.tesla_params = ext->tesla_params;
        memcpy(ue_state.trust_anchor_key, gnb_state.k_bootstrap, TF5_TESLA_KEY_LEN);
        ue_state.trust_anchor_idx = TF5_TESLA_BOOTSTRAP_IDX;
        ue_state.chain_bootstrapped = true;
    }
};

bool TF5E2ETest::bls_initialized = false;

// ============================================================================
// Basic End-to-End Flow Tests
// ============================================================================

TEST_F(TF5E2ETest, E2E_SingleSib1_Verified) {
    // Setup
    ASSERT_EQ(0, initGnb(100));
    ASSERT_EQ(0, initUe());

    const char sib1[] = "Test SIB1 content for E2E test";
    tf5_tesla_extension_t ext;
    uint8_t packed[TF5_EXTENSION_PACKED_SIZE];

    // gNB: Prepare extension at interval 5 (SFN=10, slot=0 = 200 slots = 5 intervals)
    int ret = gnbPrepareAndPack(10, 0, (const uint8_t*)sib1, strlen(sib1), &ext, packed, sizeof(packed));
    ASSERT_EQ(TF5_EXTENSION_PACKED_SIZE, ret);

    // UE: Receive and unpack
    tf5_tesla_extension_t rx_ext;
    ret = ueReceiveAndUnpack(packed, TF5_EXTENSION_PACKED_SIZE, &rx_ext);
    ASSERT_EQ(0, ret);

    // Verify fields match
    EXPECT_EQ(ext.te_version, rx_ext.te_version);
    EXPECT_EQ(ext.i, rx_ext.i);
    EXPECT_EQ(ext.tesla_params.t_int_ms, rx_ext.tesla_params.t_int_ms);
    EXPECT_EQ(0, memcmp(ext.key_disclosure, rx_ext.key_disclosure, TF5_TESLA_KEY_LEN));
    EXPECT_EQ(0, memcmp(ext.signature, rx_ext.signature, TF5_TESLA_SIG_LEN));
    EXPECT_EQ(0, memcmp(ext.tesla_tag, rx_ext.tesla_tag, TF5_TESLA_TAG_LEN));

    // UE: Setup TESLA params and trust anchor
    bootstrapUe(&rx_ext);

    // UE: Build MAC auth input and buffer
    uint8_t mac_auth_input[TF5_MAX_AUTH_INPUT];
    size_t mac_auth_input_len;
    tf5_tesla_build_mac_auth_input(mac_auth_input, &mac_auth_input_len,
                                   (const uint8_t*)sib1, strlen(sib1),
                                   gnb_state.key_validity_end);

    tf5_tesla_slot_time_t rx_time = tf5_slot_time_make(10, 0);
    ret = tf5_tesla_ue_buffer_sib1(&ue_state, mac_auth_input, mac_auth_input_len,
                                    rx_ext.i, rx_ext.tesla_tag, &rx_time, false);
    ASSERT_EQ(0, ret);

    // UE: Verify key chain (disclosed key K_{i-d} chains to anchor)
    bool key_valid = tf5_tesla_ue_verify_key_chain(&ue_state, rx_ext.key_disclosure, rx_ext.i - 1);
    EXPECT_TRUE(key_valid) << "Disclosed key should chain to trust anchor";

    // UE: Verify buffered SIB1 using disclosed key
    int verified_count = 0, failed_count = 0;
    bool rrc_trigger = false;

    // The disclosed key in ext is K_{i-d}, we need the key for the interval we buffered
    // Since we buffered at interval 5, and d=1, we need K_5 to verify
    // The disclosed key is K_{5-1} = K_4
    // We need to wait for next disclosure to get K_5, or use key at current interval

    // For this test, let's verify using the key for the buffered interval directly
    ret = tf5_tesla_ue_verify_all_buffered(&ue_state, gnb_state.key_chain[rx_ext.i],
                                            rx_ext.i, &verified_count, &failed_count, &rrc_trigger);

    EXPECT_EQ(0, ret) << "Buffered SIB1 verification should succeed";
    EXPECT_EQ(1, verified_count) << "One entry should be verified";
    EXPECT_EQ(0, failed_count) << "No entries should fail";
}

TEST_F(TF5E2ETest, E2E_MultipleSib1s_AllVerified) {
    // Setup
    ASSERT_EQ(0, initGnb(100));
    ASSERT_EQ(0, initUe());

    const char sib1_5[] = "SIB1 at interval 5";
    const char sib1_6[] = "SIB1 at interval 6";

    // gNB: Prepare extensions at intervals 5 and 6
    tf5_tesla_extension_t ext5, ext6;
    uint8_t packed5[TF5_EXTENSION_PACKED_SIZE], packed6[TF5_EXTENSION_PACKED_SIZE];

    gnbPrepareAndPack(10, 0, (const uint8_t*)sib1_5, strlen(sib1_5), &ext5, packed5, sizeof(packed5));
    gnbPrepareAndPack(12, 0, (const uint8_t*)sib1_6, strlen(sib1_6), &ext6, packed6, sizeof(packed6));

    // UE: Setup
    bootstrapUe(&ext5);

    // UE: Buffer both SIB1s
    uint8_t mac_auth5[TF5_MAX_AUTH_INPUT], mac_auth6[TF5_MAX_AUTH_INPUT];
    size_t mac_auth5_len, mac_auth6_len;

    tf5_tesla_build_mac_auth_input(mac_auth5, &mac_auth5_len,
                                   (const uint8_t*)sib1_5, strlen(sib1_5),
                                   gnb_state.key_validity_end);
    tf5_tesla_build_mac_auth_input(mac_auth6, &mac_auth6_len,
                                   (const uint8_t*)sib1_6, strlen(sib1_6),
                                   gnb_state.key_validity_end);

    tf5_tesla_slot_time_t rx_time5 = tf5_slot_time_make(10, 0);
    tf5_tesla_slot_time_t rx_time6 = tf5_slot_time_make(12, 0);

    tf5_tesla_ue_buffer_sib1(&ue_state, mac_auth5, mac_auth5_len, ext5.i, ext5.tesla_tag, &rx_time5, false);
    tf5_tesla_ue_buffer_sib1(&ue_state, mac_auth6, mac_auth6_len, ext6.i, ext6.tesla_tag, &rx_time6, false);

    EXPECT_EQ(2, ue_state.buffer_queue_count);

    // UE: Verify both using key recovery from interval 7
    int total_verified = 0, total_failed = 0;
    bool rrc_trigger = false;

    int ret = tf5_tesla_ue_verify_with_key_recovery(&ue_state, gnb_state.key_chain[7],
                                                     7, &total_verified, &total_failed, &rrc_trigger);

    EXPECT_EQ(0, ret) << "Key recovery verification should succeed";
    EXPECT_EQ(2, total_verified) << "Both entries should be verified";
    EXPECT_EQ(0, total_failed) << "No entries should fail";
}

TEST_F(TF5E2ETest, E2E_BootstrapThenNormal) {
    // Setup
    ASSERT_EQ(0, initGnb(100));
    ASSERT_EQ(0, initUe());

    // Bootstrap interval (interval 0)
    const char sib1_0[] = "SIB1 at bootstrap interval 0";
    tf5_tesla_extension_t ext0;
    uint8_t packed0[TF5_EXTENSION_PACKED_SIZE];

    gnbPrepareAndPack(0, 0, (const uint8_t*)sib1_0, strlen(sib1_0), &ext0, packed0, sizeof(packed0));

    // At interval 0 with d=1, should disclose K_{-1}
    EXPECT_EQ(0u, ext0.i) << "Should be at interval 0";
    EXPECT_EQ(0, memcmp(ext0.key_disclosure, gnb_state.k_bootstrap, TF5_TESLA_KEY_LEN))
        << "Bootstrap interval should disclose K_{-1}";

    // Normal interval (interval 5)
    const char sib1_5[] = "SIB1 at normal interval 5";
    tf5_tesla_extension_t ext5;
    uint8_t packed5[TF5_EXTENSION_PACKED_SIZE];

    gnbPrepareAndPack(10, 0, (const uint8_t*)sib1_5, strlen(sib1_5), &ext5, packed5, sizeof(packed5));

    EXPECT_EQ(5u, ext5.i) << "Should be at interval 5";
    EXPECT_EQ(0, memcmp(ext5.key_disclosure, gnb_state.key_chain[4], TF5_TESLA_KEY_LEN))
        << "Interval 5 with d=1 should disclose K_4";
}

// ============================================================================
// Error Scenario Tests
// ============================================================================

TEST_F(TF5E2ETest, E2E_TamperedTag_Rejected) {
    // Setup
    ASSERT_EQ(0, initGnb(100));
    ASSERT_EQ(0, initUe());

    const char sib1[] = "Test SIB1 content";
    tf5_tesla_extension_t ext;
    uint8_t packed[TF5_EXTENSION_PACKED_SIZE];

    gnbPrepareAndPack(10, 0, (const uint8_t*)sib1, strlen(sib1), &ext, packed, sizeof(packed));

    // UE: Setup
    bootstrapUe(&ext);

    // Build MAC auth input
    uint8_t mac_auth[TF5_MAX_AUTH_INPUT];
    size_t mac_auth_len;
    tf5_tesla_build_mac_auth_input(mac_auth, &mac_auth_len,
                                   (const uint8_t*)sib1, strlen(sib1),
                                   gnb_state.key_validity_end);

    // Tamper with the tag
    uint8_t tampered_tag[TF5_TESLA_TAG_LEN];
    memcpy(tampered_tag, ext.tesla_tag, TF5_TESLA_TAG_LEN);
    tampered_tag[0] ^= 0xFF;  // Flip bits

    // Buffer with tampered tag
    tf5_tesla_slot_time_t rx_time = tf5_slot_time_make(10, 0);
    tf5_tesla_ue_buffer_sib1(&ue_state, mac_auth, mac_auth_len, ext.i, tampered_tag, &rx_time, false);

    // Try to verify
    int verified_count = 0, failed_count = 0;
    bool rrc_trigger = false;

    int ret = tf5_tesla_ue_verify_all_buffered(&ue_state, gnb_state.key_chain[ext.i],
                                                ext.i, &verified_count, &failed_count, &rrc_trigger);

    EXPECT_LT(ret, 0) << "Verification should fail with tampered tag";
    EXPECT_EQ(0, verified_count) << "No entries should be verified";
    EXPECT_EQ(1, failed_count) << "One entry should fail";
}

TEST_F(TF5E2ETest, E2E_TamperedSib1_Rejected) {
    // Setup
    ASSERT_EQ(0, initGnb(100));
    ASSERT_EQ(0, initUe());

    const char sib1[] = "Test SIB1 content";
    tf5_tesla_extension_t ext;
    uint8_t packed[TF5_EXTENSION_PACKED_SIZE];

    gnbPrepareAndPack(10, 0, (const uint8_t*)sib1, strlen(sib1), &ext, packed, sizeof(packed));

    // UE: Setup
    bootstrapUe(&ext);

    // Build MAC auth input with DIFFERENT SIB1 content (simulating tampering)
    const char tampered_sib1[] = "TAMPERED SIB1 content";
    uint8_t mac_auth[TF5_MAX_AUTH_INPUT];
    size_t mac_auth_len;
    tf5_tesla_build_mac_auth_input(mac_auth, &mac_auth_len,
                                   (const uint8_t*)tampered_sib1, strlen(tampered_sib1),
                                   gnb_state.key_validity_end);

    // Buffer with original tag but tampered content
    tf5_tesla_slot_time_t rx_time = tf5_slot_time_make(10, 0);
    tf5_tesla_ue_buffer_sib1(&ue_state, mac_auth, mac_auth_len, ext.i, ext.tesla_tag, &rx_time, false);

    // Try to verify - should fail because MAC auth input doesn't match tag
    int verified_count = 0, failed_count = 0;
    bool rrc_trigger = false;

    int ret = tf5_tesla_ue_verify_all_buffered(&ue_state, gnb_state.key_chain[ext.i],
                                                ext.i, &verified_count, &failed_count, &rrc_trigger);

    EXPECT_LT(ret, 0) << "Verification should fail with tampered SIB1";
    EXPECT_EQ(0, verified_count);
    EXPECT_EQ(1, failed_count);
}

TEST_F(TF5E2ETest, E2E_WrongKey_Rejected) {
    // Setup
    ASSERT_EQ(0, initGnb(100));
    ASSERT_EQ(0, initUe());

    const char sib1[] = "Test SIB1 content";
    tf5_tesla_extension_t ext;
    uint8_t packed[TF5_EXTENSION_PACKED_SIZE];

    gnbPrepareAndPack(10, 0, (const uint8_t*)sib1, strlen(sib1), &ext, packed, sizeof(packed));

    // UE: Setup
    bootstrapUe(&ext);

    // Build correct MAC auth input
    uint8_t mac_auth[TF5_MAX_AUTH_INPUT];
    size_t mac_auth_len;
    tf5_tesla_build_mac_auth_input(mac_auth, &mac_auth_len,
                                   (const uint8_t*)sib1, strlen(sib1),
                                   gnb_state.key_validity_end);

    tf5_tesla_slot_time_t rx_time = tf5_slot_time_make(10, 0);
    tf5_tesla_ue_buffer_sib1(&ue_state, mac_auth, mac_auth_len, ext.i, ext.tesla_tag, &rx_time, false);

    // Try to verify with WRONG key
    uint8_t wrong_key[TF5_TESLA_KEY_LEN] = {0xba, 0xad, 0xf0, 0x0d};

    int verified_count = 0, failed_count = 0;
    bool rrc_trigger = false;

    int ret = tf5_tesla_ue_verify_all_buffered(&ue_state, wrong_key,
                                                ext.i, &verified_count, &failed_count, &rrc_trigger);

    EXPECT_LT(ret, 0) << "Verification should fail with wrong key";
    EXPECT_EQ(0, verified_count);
    EXPECT_EQ(1, failed_count);
}

// ============================================================================
// Key Recovery Scenario Tests
// ============================================================================

TEST_F(TF5E2ETest, E2E_MissedDisclosure_KeyRecovery) {
    // Setup
    ASSERT_EQ(0, initGnb(100));
    ASSERT_EQ(0, initUe());

    // Simulate receiving SIB1 at interval 5, but missing disclosures until interval 8
    const char sib1_5[] = "SIB1 at interval 5";
    tf5_tesla_extension_t ext5;
    uint8_t packed5[TF5_EXTENSION_PACKED_SIZE];

    gnbPrepareAndPack(10, 0, (const uint8_t*)sib1_5, strlen(sib1_5), &ext5, packed5, sizeof(packed5));

    // UE: Setup with bootstrap
    bootstrapUe(&ext5);

    // Buffer SIB1 from interval 5
    uint8_t mac_auth[TF5_MAX_AUTH_INPUT];
    size_t mac_auth_len;
    tf5_tesla_build_mac_auth_input(mac_auth, &mac_auth_len,
                                   (const uint8_t*)sib1_5, strlen(sib1_5),
                                   gnb_state.key_validity_end);

    tf5_tesla_slot_time_t rx_time = tf5_slot_time_make(10, 0);
    tf5_tesla_ue_buffer_sib1(&ue_state, mac_auth, mac_auth_len, ext5.i, ext5.tesla_tag, &rx_time, false);

    // Simulate missing disclosures for intervals 6, 7
    // Now receive at interval 8 with K_7 disclosed (since d=1)

    // Verify using key from interval 8 (should recover K_5, K_6, K_7)
    int total_verified = 0, total_failed = 0;
    bool rrc_trigger = false;

    int ret = tf5_tesla_ue_verify_with_key_recovery(&ue_state, gnb_state.key_chain[8],
                                                     8, &total_verified, &total_failed, &rrc_trigger);

    EXPECT_EQ(0, ret) << "Key recovery should succeed";
    EXPECT_EQ(1, total_verified) << "Entry from interval 5 should be verified";
}

// ============================================================================
// Serialization Round-Trip Tests
// ============================================================================

TEST_F(TF5E2ETest, E2E_PackUnpack_PreservesAllFields) {
    ASSERT_EQ(0, initGnb(100));

    const char sib1[] = "Test SIB1 for serialization test";
    tf5_tesla_extension_t original;
    uint8_t packed[TF5_EXTENSION_PACKED_SIZE];

    // gNB prepares extension
    tf5_tesla_gnb_prepare_extension(&gnb_state, 10, 0, (const uint8_t*)sib1, strlen(sib1), &original);

    // Pack
    int pack_ret = tf5_tesla_pack_extension(&original, packed, sizeof(packed));
    ASSERT_EQ(TF5_EXTENSION_PACKED_SIZE, pack_ret);

    // Unpack
    tf5_tesla_extension_t unpacked;
    int unpack_ret = tf5_tesla_unpack_extension(packed, TF5_EXTENSION_PACKED_SIZE, &unpacked);
    ASSERT_EQ(0, unpack_ret);

    // Verify all fields match
    EXPECT_EQ(original.te_version, unpacked.te_version);
    EXPECT_EQ(original.tesla_params.t_int_ms, unpacked.tesla_params.t_int_ms);
    EXPECT_EQ(original.tesla_params.d, unpacked.tesla_params.d);
    EXPECT_EQ(original.tesla_params.t0.sfn, unpacked.tesla_params.t0.sfn);
    EXPECT_EQ(original.tesla_params.t0.slot, unpacked.tesla_params.t0.slot);
    EXPECT_EQ(original.tesla_params.chain_len, unpacked.tesla_params.chain_len);
    EXPECT_EQ(original.validity_end, unpacked.validity_end);
    EXPECT_EQ(original.i, unpacked.i);
    EXPECT_EQ(original.timestamp_ms, unpacked.timestamp_ms);
    EXPECT_EQ(0, memcmp(original.key_disclosure, unpacked.key_disclosure, TF5_TESLA_KEY_LEN));
    EXPECT_EQ(0, memcmp(original.signature, unpacked.signature, TF5_TESLA_SIG_LEN));
    EXPECT_EQ(0, memcmp(original.tesla_tag, unpacked.tesla_tag, TF5_TESLA_TAG_LEN));
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char **argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
