/**
 * @file test_tf5_tesla_crypto.cpp
 * @brief Unit tests for TF5 TESLA cryptographic primitives
 *
 * Tests for:
 * - tf5_sha256(): SHA-256 hash function
 * - tf5_tesla_chain_key(): Key chain derivation (K_i = SHA256(0x00 || K_{i+1})[0:15])
 * - tf5_tesla_derive_mac_key(): MAC key derivation (K'_i = SHA256(0x01 || K_i))
 * - tf5_tesla_compute_tag(): TESLA tag computation (HMAC-SHA256 truncated)
 * - tf5_tesla_build_mac_auth_input(): Build MAC authentication input
 * - tf5_tesla_build_sig_auth_input(): Build signature authentication input
 */

#include "tf5_test_common.h"

extern "C" {
#include "openair3/SECU/tf5_tesla.h"
#include "openair3/SECU/tf5_crypto.h"
}

#include "tf5_test_vectors.h"

class TF5CryptoTest : public ::testing::Test {
protected:
    void SetUp() override {
        // No setup needed for crypto primitive tests
    }
};

// ============================================================================
// Key Chain Function Tests (tf5_chain_key)
// ============================================================================

TEST_F(TF5CryptoTest, ChainKey_BasicDerivation) {
    uint8_t key_out[TF5_TESLA_KEY_LEN];

    // Derive K_4 from K_5
    tf5_chain_key(tf5_test::TV_KEY_CHAIN_K5, key_out);

    // Should produce a 16-byte output
    EXPECT_FALSE(is_all_zeros(key_out, TF5_TESLA_KEY_LEN))
        << "Chain key output should not be all zeros";
}

TEST_F(TF5CryptoTest, ChainKey_KnownVector) {
    uint8_t key_out[TF5_TESLA_KEY_LEN];

    // Derive K_4 from K_5
    tf5_chain_key(tf5_test::TV_KEY_CHAIN_K5, key_out);

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
        tf5_chain_key(keys[i + 1], keys[i]);
    }

    // Now verify: starting from K_5, applying F five times should give K_0
    uint8_t computed[TF5_TESLA_KEY_LEN];
    memcpy(computed, keys[chain_len], TF5_TESLA_KEY_LEN);

    for (int i = 0; i < chain_len; i++) {
        uint8_t next[TF5_TESLA_KEY_LEN];
        tf5_chain_key(computed, next);
        memcpy(computed, next, TF5_TESLA_KEY_LEN);
    }

    EXPECT_EQ(0, memcmp(computed, keys[0], TF5_TESLA_KEY_LEN))
        << "F^5(K_5) should equal K_0";
}

TEST_F(TF5CryptoTest, ChainKey_Deterministic) {
    uint8_t key_out1[TF5_TESLA_KEY_LEN];
    uint8_t key_out2[TF5_TESLA_KEY_LEN];

    // Derive twice with same input
    tf5_chain_key(tf5_test::TV_KEY_CHAIN_K5, key_out1);
    tf5_chain_key(tf5_test::TV_KEY_CHAIN_K5, key_out2);

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

    tf5_chain_key(key1, out1);
    tf5_chain_key(key2, out2);

    EXPECT_NE(0, memcmp(out1, out2, TF5_TESLA_KEY_LEN))
        << "Different inputs should produce different outputs";
}

// ============================================================================
// MAC Key Derivation Tests (tf5_derive_mac_key)
// ============================================================================

TEST_F(TF5CryptoTest, DeriveMacKey_BasicDerivation) {
    uint8_t mac_key_out[32];

    tf5_derive_mac_key(tf5_test::TV_MAC_KEY_INPUT, mac_key_out);

    // Should produce a 32-byte output (full SHA-256)
    EXPECT_FALSE(is_all_zeros(mac_key_out, 32))
        << "MAC key output should not be all zeros";
}

TEST_F(TF5CryptoTest, DeriveMacKey_KnownVector) {
    uint8_t mac_key_out[32];

    tf5_derive_mac_key(tf5_test::TV_MAC_KEY_INPUT, mac_key_out);

    EXPECT_EQ(0, memcmp(mac_key_out, tf5_test::TV_MAC_KEY_OUTPUT_EXPECTED, 32))
        << "MAC key derivation does not match expected value";
}

TEST_F(TF5CryptoTest, DeriveMacKey_Deterministic) {
    uint8_t mac_key1[32];
    uint8_t mac_key2[32];

    tf5_derive_mac_key(tf5_test::TV_MAC_KEY_INPUT, mac_key1);
    tf5_derive_mac_key(tf5_test::TV_MAC_KEY_INPUT, mac_key2);

    EXPECT_EQ(0, memcmp(mac_key1, mac_key2, 32))
        << "MAC key derivation should be deterministic";
}

TEST_F(TF5CryptoTest, DeriveMacKey_DomainSeparation) {
    // Verify that MAC key derivation (0x01 prefix) produces different output
    // than chain key derivation (0x00 prefix)
    uint8_t chain_key_out[TF5_TESLA_KEY_LEN];
    uint8_t mac_key_out[32];

    tf5_chain_key(tf5_test::TV_MAC_KEY_INPUT, chain_key_out);
    tf5_derive_mac_key(tf5_test::TV_MAC_KEY_INPUT, mac_key_out);

    // First 16 bytes of MAC key should be different from chain key
    EXPECT_NE(0, memcmp(chain_key_out, mac_key_out, TF5_TESLA_KEY_LEN))
        << "MAC key derivation should use different domain separator than chain key";
}

// ============================================================================
// Tag Computation Tests (tf5_compute_tag)
// ============================================================================

TEST_F(TF5CryptoTest, ComputeTag_BasicComputation) {
    uint8_t tag_out[TF5_TESLA_TAG_LEN];

    int ret = tf5_compute_tag(
        tf5_test::TV_TAG_KEY,
        (const uint8_t*)tf5_test::TV_TAG_MESSAGE,
        tf5_test::TV_TAG_MESSAGE_LEN,
        tag_out
    );

    EXPECT_EQ(0, ret) << "Tag computation should return 0 on success";

    // Verify output is not all zeros
    EXPECT_FALSE(is_all_zeros(tag_out, TF5_TESLA_TAG_LEN))
        << "Tag output should not be all zeros";
}

TEST_F(TF5CryptoTest, ComputeTag_Deterministic) {
    uint8_t tag1[TF5_TESLA_TAG_LEN];
    uint8_t tag2[TF5_TESLA_TAG_LEN];

    tf5_compute_tag(
        tf5_test::TV_TAG_KEY,
        (const uint8_t*)tf5_test::TV_TAG_MESSAGE,
        tf5_test::TV_TAG_MESSAGE_LEN,
        tag1
    );

    tf5_compute_tag(
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

    tf5_compute_tag(key1, (const uint8_t*)tf5_test::TV_TAG_MESSAGE,
                          tf5_test::TV_TAG_MESSAGE_LEN, tag1);
    tf5_compute_tag(key2, (const uint8_t*)tf5_test::TV_TAG_MESSAGE,
                          tf5_test::TV_TAG_MESSAGE_LEN, tag2);

    EXPECT_NE(0, memcmp(tag1, tag2, TF5_TESLA_TAG_LEN))
        << "Different keys should produce different tags";
}

TEST_F(TF5CryptoTest, ComputeTag_DifferentData_DifferentTags) {
    const char msg1[] = "Message one";
    const char msg2[] = "Message two";
    uint8_t tag1[TF5_TESLA_TAG_LEN];
    uint8_t tag2[TF5_TESLA_TAG_LEN];

    tf5_compute_tag(tf5_test::TV_TAG_KEY, (const uint8_t*)msg1, strlen(msg1), tag1);
    tf5_compute_tag(tf5_test::TV_TAG_KEY, (const uint8_t*)msg2, strlen(msg2), tag2);

    EXPECT_NE(0, memcmp(tag1, tag2, TF5_TESLA_TAG_LEN))
        << "Different data should produce different tags";
}

TEST_F(TF5CryptoTest, ComputeTag_NullKey_ReturnsError) {
    uint8_t tag_out[TF5_TESLA_TAG_LEN];
    const char msg[] = "test";

    int ret = tf5_compute_tag(nullptr, (const uint8_t*)msg, strlen(msg), tag_out);

    EXPECT_LT(ret, 0) << "Null key should return error";
}

TEST_F(TF5CryptoTest, ComputeTag_NullData_ReturnsError) {
    uint8_t tag_out[TF5_TESLA_TAG_LEN];

    int ret = tf5_compute_tag(tf5_test::TV_TAG_KEY, nullptr, 10, tag_out);

    EXPECT_LT(ret, 0) << "Null data should return error";
}

TEST_F(TF5CryptoTest, ComputeTag_NullOutput_ReturnsError) {
    const char msg[] = "test";

    int ret = tf5_compute_tag(tf5_test::TV_TAG_KEY, (const uint8_t*)msg, strlen(msg), nullptr);

    EXPECT_LT(ret, 0) << "Null output buffer should return error";
}

TEST_F(TF5CryptoTest, ComputeTag_ZeroLength_ReturnsError) {
    uint8_t tag_out[TF5_TESLA_TAG_LEN];
    const char msg[] = "test";

    int ret = tf5_compute_tag(tf5_test::TV_TAG_KEY, (const uint8_t*)msg, 0, tag_out);

    EXPECT_LT(ret, 0) << "Zero-length data should return error";
}

// ============================================================================
// SHA-256 Tests (tf5_sha256)
// ============================================================================

TEST_F(TF5CryptoTest, Sha256_KnownVector_Abc) {
    // NIST test vector: SHA-256("abc") = ba7816bf8f01cfea...
    const uint8_t expected[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };

    const char input[] = "abc";
    uint8_t output[32];

    tf5_sha256((const uint8_t*)input, 3, output);

    EXPECT_EQ(0, memcmp(expected, output, 32))
        << "SHA-256(\"abc\") should match NIST test vector";
}

TEST_F(TF5CryptoTest, Sha256_EmptyInput) {
    // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    const uint8_t expected[32] = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
    };

    uint8_t empty_buf[1] = {0};  // Empty but valid buffer
    uint8_t output[32];

    tf5_sha256(empty_buf, 0, output);

    EXPECT_EQ(0, memcmp(expected, output, 32))
        << "SHA-256(\"\") should match known value";
}

TEST_F(TF5CryptoTest, Sha256_LargeInput) {
    // Test with a larger input (1024 bytes)
    uint8_t large_input[1024];
    for (int i = 0; i < 1024; i++) {
        large_input[i] = (uint8_t)(i & 0xFF);
    }

    uint8_t output[32];

    tf5_sha256(large_input, 1024, output);

    // Just verify it produces 32 bytes and is not all zeros
    EXPECT_FALSE(is_all_zeros(output, 32))
        << "SHA-256 of large input should not be all zeros";
}

TEST_F(TF5CryptoTest, Sha256_Deterministic) {
    const char input[] = "deterministic test input";
    uint8_t output1[32];
    uint8_t output2[32];

    tf5_sha256((const uint8_t*)input, strlen(input), output1);
    tf5_sha256((const uint8_t*)input, strlen(input), output2);

    EXPECT_EQ(0, memcmp(output1, output2, 32))
        << "SHA-256 should be deterministic";
}

TEST_F(TF5CryptoTest, Sha256_DifferentInputs) {
    const char input1[] = "input one";
    const char input2[] = "input two";
    uint8_t output1[32];
    uint8_t output2[32];

    tf5_sha256((const uint8_t*)input1, strlen(input1), output1);
    tf5_sha256((const uint8_t*)input2, strlen(input2), output2);

    EXPECT_NE(0, memcmp(output1, output2, 32))
        << "Different inputs should produce different hashes";
}

// ============================================================================
// Build MAC Auth Input Tests (tf5_build_mac_auth_input)
// ============================================================================

TEST_F(TF5CryptoTest, BuildMacAuthInput_Success) {
    uint8_t out[TF5_MAX_AUTH_INPUT];
    size_t out_len;
    const uint8_t sib1[] = {0x01, 0x02, 0x03, 0x04, 0x05};

    int ret = tf5_build_mac_auth_input(out, &out_len, sib1, sizeof(sib1), TF5_VERSION);

    EXPECT_EQ(0, ret) << "Building MAC auth input should succeed";
    EXPECT_EQ(sizeof(sib1) + 1, out_len) << "Output length should be sib1_len + 1 (version)";
}

TEST_F(TF5CryptoTest, BuildMacAuthInput_Layout) {
    uint8_t out[TF5_MAX_AUTH_INPUT];
    size_t out_len;
    const uint8_t sib1[] = {0xAA, 0xBB, 0xCC};
    uint8_t te_version = 0x42;

    tf5_build_mac_auth_input(out, &out_len, sib1, sizeof(sib1), te_version);

    // Verify SIB1 is at the beginning
    EXPECT_EQ(0xAA, out[0]);
    EXPECT_EQ(0xBB, out[1]);
    EXPECT_EQ(0xCC, out[2]);

    // Verify version at offset 3 (1 byte)
    EXPECT_EQ(0x42, out[3]) << "Version byte";
}

TEST_F(TF5CryptoTest, BuildMacAuthInput_NullOut) {
    size_t out_len;
    const uint8_t sib1[] = {0x01, 0x02};

    int ret = tf5_build_mac_auth_input(nullptr, &out_len, sib1, sizeof(sib1), TF5_VERSION);

    EXPECT_LT(ret, 0) << "Null output buffer should return error";
}

TEST_F(TF5CryptoTest, BuildMacAuthInput_NullOutLen) {
    uint8_t out[TF5_MAX_AUTH_INPUT];
    const uint8_t sib1[] = {0x01, 0x02};

    int ret = tf5_build_mac_auth_input(out, nullptr, sib1, sizeof(sib1), TF5_VERSION);

    EXPECT_LT(ret, 0) << "Null out_len should return error";
}

TEST_F(TF5CryptoTest, BuildMacAuthInput_NullSib1) {
    uint8_t out[TF5_MAX_AUTH_INPUT];
    size_t out_len;

    int ret = tf5_build_mac_auth_input(out, &out_len, nullptr, 5, TF5_VERSION);

    EXPECT_LT(ret, 0) << "Null SIB1 should return error";
}

TEST_F(TF5CryptoTest, BuildMacAuthInput_Deterministic) {
    uint8_t out1[TF5_MAX_AUTH_INPUT];
    uint8_t out2[TF5_MAX_AUTH_INPUT];
    size_t out_len1, out_len2;
    const uint8_t sib1[] = {0x01, 0x02, 0x03, 0x04};

    tf5_build_mac_auth_input(out1, &out_len1, sib1, sizeof(sib1), TF5_VERSION);
    tf5_build_mac_auth_input(out2, &out_len2, sib1, sizeof(sib1), TF5_VERSION);

    EXPECT_EQ(out_len1, out_len2);
    EXPECT_EQ(0, memcmp(out1, out2, out_len1))
        << "Same inputs should produce identical output";
}

// ============================================================================
// Build Signature Auth Input Tests (tf5_build_sig_auth_input)
// ============================================================================

TEST_F(TF5CryptoTest, BuildSigAuthInput_Success) {
    uint8_t out[TF5_MAX_AUTH_INPUT];
    size_t out_len;
    tf5_tesla_params_t params = {
        .t_int_ms = 160,
        .d = 1,
        .t0 = {.sfn = 100, .slot = 0},
        .chain_len = 65536
    };

    int ret = tf5_build_sig_auth_input(out, &out_len,
                                              0x01, &params, 525600, 1000);

    EXPECT_EQ(0, ret) << "Building signature auth input should succeed";
    // Expected: version(1) + params(11) + validity(3) + timestamp(3) = 18 bytes
    EXPECT_EQ(18u, out_len) << "Output length should be 18 bytes";
}

TEST_F(TF5CryptoTest, BuildSigAuthInput_Layout) {
    uint8_t out[TF5_MAX_AUTH_INPUT];
    size_t out_len;
    tf5_tesla_params_t params = {
        .t_int_ms = 160,
        .d = 1,
        .t0 = {.sfn = 100, .slot = 5},
        .chain_len = 1000
    };

    tf5_build_sig_auth_input(out, &out_len,
                                    0x01, &params, 0x112233, 0x778899);

    // Layout: version(1) + params(11) + validity(3) + timestamp(3) = 18B

    // Verify version at offset 0
    EXPECT_EQ(0x01, out[0]);

    // Skip params (11 bytes) at offset 1-11

    // Verify validity_end at offset 12 (3 bytes, big-endian)
    EXPECT_EQ(0x11, out[12]);
    EXPECT_EQ(0x22, out[13]);
    EXPECT_EQ(0x33, out[14]);

    // Verify timestamp at offset 15 (3 bytes, big-endian)
    EXPECT_EQ(0x77, out[15]);
    EXPECT_EQ(0x88, out[16]);
    EXPECT_EQ(0x99, out[17]);
}

TEST_F(TF5CryptoTest, BuildSigAuthInput_NullOut) {
    size_t out_len;
    tf5_tesla_params_t params = {};

    int ret = tf5_build_sig_auth_input(nullptr, &out_len,
                                              0x01, &params, 0, 0);

    EXPECT_LT(ret, 0) << "Null output should return error";
}

TEST_F(TF5CryptoTest, BuildSigAuthInput_NullParams) {
    uint8_t out[TF5_MAX_AUTH_INPUT];
    size_t out_len;

    int ret = tf5_build_sig_auth_input(out, &out_len,
                                              0x01, nullptr, 0, 0);

    EXPECT_LT(ret, 0) << "Null params should return error";
}

TEST_F(TF5CryptoTest, BuildSigAuthInput_FixedSize) {
    // sig_auth_input is always 18 bytes (no variable-length SIB1)
    uint8_t out[TF5_MAX_AUTH_INPUT];
    size_t out_len;
    tf5_tesla_params_t params = {
        .t_int_ms = 160,
        .d = 1,
        .t0 = {.sfn = 0, .slot = 0},
        .chain_len = 1000
    };

    tf5_build_sig_auth_input(out, &out_len, 0x01, &params, 123456, 789);
    EXPECT_EQ(18u, out_len) << "Sig auth input should always be 18 bytes";
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char **argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
