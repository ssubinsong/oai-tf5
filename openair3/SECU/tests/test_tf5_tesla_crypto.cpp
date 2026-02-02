/**
 * @file test_tf5_tesla_crypto.cpp
 * @brief Unit tests for TF5 TESLA cryptographic primitives
 *
 * Tests for:
 * - tf5_tesla_chain_key(): Key chain derivation (K_i = SHA256(0x00 || K_{i+1})[0:15])
 * - tf5_tesla_derive_mac_key(): MAC key derivation (K'_i = SHA256(0x01 || K_i))
 * - tf5_tesla_compute_tag(): TESLA tag computation (HMAC-SHA256 truncated)
 */

#include <gtest/gtest.h>
#include <cstring>

extern "C" {
#include "openair3/SECU/tf5_tesla.h"
}

#include "tf5_test_vectors.h"

class TF5CryptoTest : public ::testing::Test {
protected:
    void SetUp() override {
        // No setup needed for crypto primitive tests
    }
};

// ============================================================================
// Key Chain Function Tests (tf5_tesla_chain_key)
// ============================================================================

TEST_F(TF5CryptoTest, ChainKey_BasicDerivation) {
    uint8_t key_out[TF5_TESLA_KEY_LEN];

    // Derive K_4 from K_5
    tf5_tesla_chain_key(tf5_test::TV_KEY_CHAIN_K5, key_out);

    // Should produce a 16-byte output
    // Verify it's not all zeros (basic sanity check)
    bool all_zeros = true;
    for (int i = 0; i < TF5_TESLA_KEY_LEN; i++) {
        if (key_out[i] != 0) {
            all_zeros = false;
            break;
        }
    }
    EXPECT_FALSE(all_zeros) << "Chain key output should not be all zeros";
}

TEST_F(TF5CryptoTest, ChainKey_KnownVector) {
    uint8_t key_out[TF5_TESLA_KEY_LEN];

    // Derive K_4 from K_5
    tf5_tesla_chain_key(tf5_test::TV_KEY_CHAIN_K5, key_out);

    // Compare with expected value
    EXPECT_EQ(0, memcmp(key_out, tf5_test::TV_KEY_CHAIN_K4_EXPECTED, TF5_TESLA_KEY_LEN))
        << "K_4 derivation from K_5 does not match expected value";
}

TEST_F(TF5CryptoTest, ChainKey_ChainProperty) {
    // Generate a small chain and verify F^n(K_n) = K_0
    const int chain_len = 5;
    uint8_t keys[chain_len + 1][TF5_TESLA_KEY_LEN];

    // Start with K_5 as the seed
    memcpy(keys[chain_len], tf5_test::TV_KEY_CHAIN_K5, TF5_TESLA_KEY_LEN);

    // Derive K_4, K_3, K_2, K_1, K_0
    for (int i = chain_len - 1; i >= 0; i--) {
        tf5_tesla_chain_key(keys[i + 1], keys[i]);
    }

    // Now verify: starting from K_5, applying F five times should give K_0
    uint8_t computed[TF5_TESLA_KEY_LEN];
    memcpy(computed, keys[chain_len], TF5_TESLA_KEY_LEN);

    for (int i = 0; i < chain_len; i++) {
        uint8_t next[TF5_TESLA_KEY_LEN];
        tf5_tesla_chain_key(computed, next);
        memcpy(computed, next, TF5_TESLA_KEY_LEN);
    }

    EXPECT_EQ(0, memcmp(computed, keys[0], TF5_TESLA_KEY_LEN))
        << "F^5(K_5) should equal K_0";
}

TEST_F(TF5CryptoTest, ChainKey_Deterministic) {
    uint8_t key_out1[TF5_TESLA_KEY_LEN];
    uint8_t key_out2[TF5_TESLA_KEY_LEN];

    // Derive twice with same input
    tf5_tesla_chain_key(tf5_test::TV_KEY_CHAIN_K5, key_out1);
    tf5_tesla_chain_key(tf5_test::TV_KEY_CHAIN_K5, key_out2);

    // Outputs should be identical
    EXPECT_EQ(0, memcmp(key_out1, key_out2, TF5_TESLA_KEY_LEN))
        << "Chain key derivation should be deterministic";
}

TEST_F(TF5CryptoTest, ChainKey_DifferentInputs_DifferentOutputs) {
    uint8_t key1[TF5_TESLA_KEY_LEN] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                       0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    uint8_t key2[TF5_TESLA_KEY_LEN] = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                                       0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};
    uint8_t out1[TF5_TESLA_KEY_LEN];
    uint8_t out2[TF5_TESLA_KEY_LEN];

    tf5_tesla_chain_key(key1, out1);
    tf5_tesla_chain_key(key2, out2);

    EXPECT_NE(0, memcmp(out1, out2, TF5_TESLA_KEY_LEN))
        << "Different inputs should produce different outputs";
}

// ============================================================================
// MAC Key Derivation Tests (tf5_tesla_derive_mac_key)
// ============================================================================

TEST_F(TF5CryptoTest, DeriveMacKey_BasicDerivation) {
    uint8_t mac_key_out[32];

    tf5_tesla_derive_mac_key(tf5_test::TV_MAC_KEY_INPUT, mac_key_out);

    // Should produce a 32-byte output (full SHA-256)
    bool all_zeros = true;
    for (int i = 0; i < 32; i++) {
        if (mac_key_out[i] != 0) {
            all_zeros = false;
            break;
        }
    }
    EXPECT_FALSE(all_zeros) << "MAC key output should not be all zeros";
}

TEST_F(TF5CryptoTest, DeriveMacKey_KnownVector) {
    uint8_t mac_key_out[32];

    tf5_tesla_derive_mac_key(tf5_test::TV_MAC_KEY_INPUT, mac_key_out);

    EXPECT_EQ(0, memcmp(mac_key_out, tf5_test::TV_MAC_KEY_OUTPUT_EXPECTED, 32))
        << "MAC key derivation does not match expected value";
}

TEST_F(TF5CryptoTest, DeriveMacKey_Deterministic) {
    uint8_t mac_key1[32];
    uint8_t mac_key2[32];

    tf5_tesla_derive_mac_key(tf5_test::TV_MAC_KEY_INPUT, mac_key1);
    tf5_tesla_derive_mac_key(tf5_test::TV_MAC_KEY_INPUT, mac_key2);

    EXPECT_EQ(0, memcmp(mac_key1, mac_key2, 32))
        << "MAC key derivation should be deterministic";
}

TEST_F(TF5CryptoTest, DeriveMacKey_DomainSeparation) {
    // Verify that MAC key derivation (0x01 prefix) produces different output
    // than chain key derivation (0x00 prefix)
    uint8_t chain_key_out[TF5_TESLA_KEY_LEN];
    uint8_t mac_key_out[32];

    tf5_tesla_chain_key(tf5_test::TV_MAC_KEY_INPUT, chain_key_out);
    tf5_tesla_derive_mac_key(tf5_test::TV_MAC_KEY_INPUT, mac_key_out);

    // First 16 bytes of MAC key should be different from chain key
    EXPECT_NE(0, memcmp(chain_key_out, mac_key_out, TF5_TESLA_KEY_LEN))
        << "MAC key derivation should use different domain separator than chain key";
}

// ============================================================================
// Tag Computation Tests (tf5_tesla_compute_tag)
// ============================================================================

TEST_F(TF5CryptoTest, ComputeTag_BasicComputation) {
    uint8_t tag_out[TF5_TESLA_TAG_LEN];

    int ret = tf5_tesla_compute_tag(
        tf5_test::TV_TAG_KEY,
        (const uint8_t*)tf5_test::TV_TAG_MESSAGE,
        tf5_test::TV_TAG_MESSAGE_LEN,
        tag_out
    );

    EXPECT_EQ(0, ret) << "Tag computation should return 0 on success";

    // Verify output is not all zeros
    bool all_zeros = true;
    for (int i = 0; i < TF5_TESLA_TAG_LEN; i++) {
        if (tag_out[i] != 0) {
            all_zeros = false;
            break;
        }
    }
    EXPECT_FALSE(all_zeros) << "Tag output should not be all zeros";
}

TEST_F(TF5CryptoTest, ComputeTag_Deterministic) {
    uint8_t tag1[TF5_TESLA_TAG_LEN];
    uint8_t tag2[TF5_TESLA_TAG_LEN];

    tf5_tesla_compute_tag(
        tf5_test::TV_TAG_KEY,
        (const uint8_t*)tf5_test::TV_TAG_MESSAGE,
        tf5_test::TV_TAG_MESSAGE_LEN,
        tag1
    );

    tf5_tesla_compute_tag(
        tf5_test::TV_TAG_KEY,
        (const uint8_t*)tf5_test::TV_TAG_MESSAGE,
        tf5_test::TV_TAG_MESSAGE_LEN,
        tag2
    );

    EXPECT_EQ(0, memcmp(tag1, tag2, TF5_TESLA_TAG_LEN))
        << "Tag computation should be deterministic";
}

TEST_F(TF5CryptoTest, ComputeTag_DifferentKeys_DifferentTags) {
    uint8_t key1[TF5_TESLA_KEY_LEN] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                       0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00};
    uint8_t key2[TF5_TESLA_KEY_LEN] = {0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99,
                                       0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11};
    uint8_t tag1[TF5_TESLA_TAG_LEN];
    uint8_t tag2[TF5_TESLA_TAG_LEN];

    tf5_tesla_compute_tag(key1, (const uint8_t*)tf5_test::TV_TAG_MESSAGE,
                          tf5_test::TV_TAG_MESSAGE_LEN, tag1);
    tf5_tesla_compute_tag(key2, (const uint8_t*)tf5_test::TV_TAG_MESSAGE,
                          tf5_test::TV_TAG_MESSAGE_LEN, tag2);

    EXPECT_NE(0, memcmp(tag1, tag2, TF5_TESLA_TAG_LEN))
        << "Different keys should produce different tags";
}

TEST_F(TF5CryptoTest, ComputeTag_DifferentData_DifferentTags) {
    const char msg1[] = "Message one";
    const char msg2[] = "Message two";
    uint8_t tag1[TF5_TESLA_TAG_LEN];
    uint8_t tag2[TF5_TESLA_TAG_LEN];

    tf5_tesla_compute_tag(tf5_test::TV_TAG_KEY, (const uint8_t*)msg1, strlen(msg1), tag1);
    tf5_tesla_compute_tag(tf5_test::TV_TAG_KEY, (const uint8_t*)msg2, strlen(msg2), tag2);

    EXPECT_NE(0, memcmp(tag1, tag2, TF5_TESLA_TAG_LEN))
        << "Different data should produce different tags";
}

TEST_F(TF5CryptoTest, ComputeTag_NullKey_ReturnsError) {
    uint8_t tag_out[TF5_TESLA_TAG_LEN];
    const char msg[] = "test";

    int ret = tf5_tesla_compute_tag(nullptr, (const uint8_t*)msg, strlen(msg), tag_out);

    EXPECT_LT(ret, 0) << "Null key should return error";
}

TEST_F(TF5CryptoTest, ComputeTag_NullData_ReturnsError) {
    uint8_t tag_out[TF5_TESLA_TAG_LEN];

    int ret = tf5_tesla_compute_tag(tf5_test::TV_TAG_KEY, nullptr, 10, tag_out);

    EXPECT_LT(ret, 0) << "Null data should return error";
}

TEST_F(TF5CryptoTest, ComputeTag_NullOutput_ReturnsError) {
    const char msg[] = "test";

    int ret = tf5_tesla_compute_tag(tf5_test::TV_TAG_KEY, (const uint8_t*)msg, strlen(msg), nullptr);

    EXPECT_LT(ret, 0) << "Null output buffer should return error";
}

TEST_F(TF5CryptoTest, ComputeTag_ZeroLength_ReturnsError) {
    uint8_t tag_out[TF5_TESLA_TAG_LEN];
    const char msg[] = "test";

    int ret = tf5_tesla_compute_tag(tf5_test::TV_TAG_KEY, (const uint8_t*)msg, 0, tag_out);

    EXPECT_LT(ret, 0) << "Zero-length data should return error";
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char **argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
