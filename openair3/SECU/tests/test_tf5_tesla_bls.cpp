/**
 * @file test_tf5_tesla_bls.cpp
 * @brief Unit tests for TF5 TESLA BLS signature operations
 *
 * Tests for:
 * - tf5_bls_init(): BLS library initialization
 * - tf5_bls_derive_pubkey(): Public key derivation
 * - tf5_bls_sign(): BLS signing
 * - tf5_sig_verify(): Identity-Based Signature verification
 */

#define TF5_TEST_NEEDS_OAI_STUBS
#include "tf5_test_common.h"

extern "C" {
#include "openair3/SECU/tf5_ibs_pkg.h"
#include "openair3/SECU/tf5_tesla.h"
}

#include "tf5_test_vectors.h"

class TF5BlsTest : public ::testing::Test {
protected:
    uint8_t secret_key[TF5_IBS_GNB_SK_LEN];
    uint8_t public_key[TF5_IBS_GNB_PK_LEN];
    uint8_t signature[TF5_IBS_SIG_LEN];

    static bool bls_initialized;

    void SetUp() override {
        // Initialize BLS library once
        if (!bls_initialized) {
            int ret = tf5_bls_init();
            ASSERT_EQ(0, ret) << "BLS init should succeed";
            bls_initialized = true;
        }

        // Use test secret key
        memcpy(secret_key, tf5_test::TV_BLS_SECRET_KEY, TF5_IBS_GNB_SK_LEN);

        // Clear output buffers
        memset(public_key, 0, sizeof(public_key));
        memset(signature, 0, sizeof(signature));
    }
};

bool TF5BlsTest::bls_initialized = false;

// ============================================================================
// BLS Initialization Tests
// ============================================================================

TEST_F(TF5BlsTest, BlsInit_Success) {
    // Already initialized in SetUp, verify it worked
    EXPECT_TRUE(bls_initialized);
}

// ============================================================================
// Public Key Derivation Tests
// ============================================================================

TEST_F(TF5BlsTest, BlsDerivePublic_Success) {
    int ret = tf5_bls_derive_pubkey(secret_key, public_key);

    EXPECT_EQ(0, ret) << "Public key derivation should succeed";

    // Verify public key is not all zeros
    EXPECT_FALSE(is_all_zeros(public_key, TF5_IBS_GNB_PK_LEN))
        << "Public key should not be all zeros";
}

TEST_F(TF5BlsTest, BlsDerivePublic_Deterministic) {
    uint8_t pk1[TF5_IBS_GNB_PK_LEN], pk2[TF5_IBS_GNB_PK_LEN];

    tf5_bls_derive_pubkey(secret_key, pk1);
    tf5_bls_derive_pubkey(secret_key, pk2);

    EXPECT_EQ(0, memcmp(pk1, pk2, TF5_IBS_GNB_PK_LEN))
        << "Same secret key should derive same public key";
}

TEST_F(TF5BlsTest, BlsDerivePublic_DifferentKeys) {
    uint8_t sk1[TF5_IBS_GNB_SK_LEN] = {0x01};
    uint8_t sk2[TF5_IBS_GNB_SK_LEN] = {0x02};
    uint8_t pk1[TF5_IBS_GNB_PK_LEN], pk2[TF5_IBS_GNB_PK_LEN];

    tf5_bls_derive_pubkey(sk1, pk1);
    tf5_bls_derive_pubkey(sk2, pk2);

    EXPECT_NE(0, memcmp(pk1, pk2, TF5_IBS_GNB_PK_LEN))
        << "Different secret keys should derive different public keys";
}

TEST_F(TF5BlsTest, BlsDerivePublic_NullInputs_ReturnsError) {
    int ret = tf5_bls_derive_pubkey(nullptr, public_key);
    EXPECT_LT(ret, 0) << "Null secret key should return error";

    ret = tf5_bls_derive_pubkey(secret_key, nullptr);
    EXPECT_LT(ret, 0) << "Null public key output should return error";
}

// ============================================================================
// BLS Sign Tests
// ============================================================================

TEST_F(TF5BlsTest, BlsSign_Success) {
    int ret = tf5_bls_sign(
        secret_key,
        (const uint8_t*)tf5_test::TV_BLS_MESSAGE,
        tf5_test::TV_BLS_MESSAGE_LEN,
        signature
    );

    EXPECT_EQ(0, ret) << "BLS sign should succeed";

    // Verify signature is not all zeros
    EXPECT_FALSE(is_all_zeros(signature, TF5_IBS_SIG_LEN))
        << "Signature should not be all zeros";
}

TEST_F(TF5BlsTest, BlsSign_Deterministic) {
    uint8_t sig1[TF5_IBS_SIG_LEN], sig2[TF5_IBS_SIG_LEN];

    tf5_bls_sign(secret_key, (const uint8_t*)tf5_test::TV_BLS_MESSAGE,
                       tf5_test::TV_BLS_MESSAGE_LEN, sig1);
    tf5_bls_sign(secret_key, (const uint8_t*)tf5_test::TV_BLS_MESSAGE,
                       tf5_test::TV_BLS_MESSAGE_LEN, sig2);

    EXPECT_EQ(0, memcmp(sig1, sig2, TF5_IBS_SIG_LEN))
        << "Same key and message should produce same signature";
}

TEST_F(TF5BlsTest, BlsSign_DifferentMessages_DifferentSignatures) {
    const char msg1[] = "Message one";
    const char msg2[] = "Message two";
    uint8_t sig1[TF5_IBS_SIG_LEN], sig2[TF5_IBS_SIG_LEN];

    tf5_bls_sign(secret_key, (const uint8_t*)msg1, strlen(msg1), sig1);
    tf5_bls_sign(secret_key, (const uint8_t*)msg2, strlen(msg2), sig2);

    EXPECT_NE(0, memcmp(sig1, sig2, TF5_IBS_SIG_LEN))
        << "Different messages should produce different signatures";
}

TEST_F(TF5BlsTest, BlsSign_NullInputs_ReturnsError) {
    int ret = tf5_bls_sign(nullptr, (const uint8_t*)"test", 4, signature);
    EXPECT_LT(ret, 0) << "Null secret key should return error";

    ret = tf5_bls_sign(secret_key, nullptr, 4, signature);
    EXPECT_LT(ret, 0) << "Null data should return error";

    ret = tf5_bls_sign(secret_key, (const uint8_t*)"test", 4, nullptr);
    EXPECT_LT(ret, 0) << "Null signature output should return error";
}

// ============================================================================
// IBS Verify Tests
// ============================================================================

// Note: Full IBS verification requires a properly issued gNB key from Core PKG
// These tests verify error handling and basic structure

TEST_F(TF5BlsTest, IbsVerify_NullMpk_ReturnsError) {
    uint8_t dummy_sig[TF5_IBS_SIG_LEN] = {0};
    const char data[] = "test data";

    int ret = tf5_sig_verify(nullptr, tf5_test::TV_IBS_CELL_ID,
                                    tf5_test::TV_IBS_VALIDITY_END,
                                    (const uint8_t*)data, strlen(data), dummy_sig);

    EXPECT_LT(ret, 0) << "Null MPK should return error";
}

TEST_F(TF5BlsTest, IbsVerify_NullCellId_ReturnsError) {
    uint8_t dummy_mpk[TF5_IBS_GNB_PK_LEN] = {0};
    uint8_t dummy_sig[TF5_IBS_SIG_LEN] = {0};
    const char data[] = "test data";

    int ret = tf5_sig_verify(dummy_mpk, nullptr,
                                    tf5_test::TV_IBS_VALIDITY_END,
                                    (const uint8_t*)data, strlen(data), dummy_sig);

    EXPECT_LT(ret, 0) << "Null cell_id should return error";
}

TEST_F(TF5BlsTest, IbsVerify_NullData_ReturnsError) {
    uint8_t dummy_mpk[TF5_IBS_GNB_PK_LEN] = {0};
    uint8_t dummy_sig[TF5_IBS_SIG_LEN] = {0};

    int ret = tf5_sig_verify(dummy_mpk, tf5_test::TV_IBS_CELL_ID,
                                    tf5_test::TV_IBS_VALIDITY_END,
                                    nullptr, 10, dummy_sig);

    EXPECT_LT(ret, 0) << "Null data should return error";
}

TEST_F(TF5BlsTest, IbsVerify_NullSignature_ReturnsError) {
    uint8_t dummy_mpk[TF5_IBS_GNB_PK_LEN] = {0};
    const char data[] = "test data";

    int ret = tf5_sig_verify(dummy_mpk, tf5_test::TV_IBS_CELL_ID,
                                    tf5_test::TV_IBS_VALIDITY_END,
                                    (const uint8_t*)data, strlen(data), nullptr);

    EXPECT_LT(ret, 0) << "Null signature should return error";
}

// ============================================================================
// IBS End-to-End Tests using PKG binaries
// ============================================================================

bool TF5IbsTestFixture::bls_initialized = false;

/**
 * Test fixture that uses the Core PKG library to generate IBS keys.
 * Inherits common key generation from TF5IbsTestFixture.
 */
class TF5IbsE2ETest : public TF5IbsTestFixture {
protected:
    // Aliases for backward compatibility with existing tests
    uint8_t (&msk)[TF5_IBS_GNB_SK_LEN] = ibs_msk;
    uint8_t (&mpk)[TF5_IBS_MPK_LEN] = ibs_mpk;
    uint8_t (&sk_gnb)[TF5_IBS_GNB_SK_LEN] = ibs_sk;

    void SetUp() override {
        TF5IbsTestFixture::SetUp();
        setupTestDir("tf5_ibs_e2e_test");
        generateAndLoadKeys();
    }
};

TEST_F(TF5IbsE2ETest, IbsSignVerify_ValidSignature_Success) {
    const char message[] = "Test message for IBS signature verification";
    uint8_t signature[TF5_IBS_SIG_LEN];

    // Sign with the IBS secret key (sk_ID issued by PKG)
    int sign_ret = tf5_bls_sign(sk_gnb, (const uint8_t*)message,
                                       strlen(message), signature);
    ASSERT_EQ(0, sign_ret) << "IBS signing should succeed";

    // Verify using IBS verification (with MPK and identity)
    int verify_ret = tf5_sig_verify(mpk, cell_id, validity_end,
                                           (const uint8_t*)message,
                                           strlen(message), signature);

    EXPECT_EQ(0, verify_ret) << "Valid IBS signature should verify successfully";
}

TEST_F(TF5IbsE2ETest, IbsSignVerify_TamperedMessage_Fails) {
    const char message[] = "Original message";
    uint8_t signature[TF5_IBS_SIG_LEN];

    // Sign with the IBS secret key
    tf5_bls_sign(sk_gnb, (const uint8_t*)message, strlen(message), signature);

    // Verify with tampered message
    const char tampered[] = "Tampered message";
    int verify_ret = tf5_sig_verify(mpk, cell_id, validity_end,
                                           (const uint8_t*)tampered,
                                           strlen(tampered), signature);

    EXPECT_NE(0, verify_ret) << "Tampered message should fail verification";
}

TEST_F(TF5IbsE2ETest, IbsSignVerify_WrongCellId_Fails) {
    const char message[] = "Test message";
    uint8_t signature[TF5_IBS_SIG_LEN];

    // Sign with the IBS secret key
    tf5_bls_sign(sk_gnb, (const uint8_t*)message, strlen(message), signature);

    // Verify with wrong cell ID
    uint8_t wrong_cell_id[TF5_IBS_CELL_ID_LEN] = {0xAA, 0xBB, 0xCC, 0xDD, 0xE0};
    int verify_ret = tf5_sig_verify(mpk, wrong_cell_id, validity_end,
                                           (const uint8_t*)message,
                                           strlen(message), signature);

    EXPECT_NE(0, verify_ret) << "Wrong cell ID should fail verification";
}

TEST_F(TF5IbsE2ETest, IbsSignVerify_WrongValidity_Fails) {
    const char message[] = "Test message";
    uint8_t signature[TF5_IBS_SIG_LEN];

    // Sign with the IBS secret key
    tf5_bls_sign(sk_gnb, (const uint8_t*)message, strlen(message), signature);

    // Verify with wrong validity
    uint32_t wrong_validity = 999999;
    int verify_ret = tf5_sig_verify(mpk, cell_id, wrong_validity,
                                           (const uint8_t*)message,
                                           strlen(message), signature);

    EXPECT_NE(0, verify_ret) << "Wrong validity should fail verification";
}

TEST_F(TF5IbsE2ETest, IbsSignVerify_TamperedSignature_Fails) {
    const char message[] = "Test message";
    uint8_t signature[TF5_IBS_SIG_LEN];

    // Sign with the IBS secret key
    tf5_bls_sign(sk_gnb, (const uint8_t*)message, strlen(message), signature);

    // Tamper with signature
    signature[0] ^= 0xFF;
    signature[10] ^= 0xFF;

    int verify_ret = tf5_sig_verify(mpk, cell_id, validity_end,
                                           (const uint8_t*)message,
                                           strlen(message), signature);

    EXPECT_NE(0, verify_ret) << "Tampered signature should fail verification";
}

TEST_F(TF5IbsE2ETest, IbsSignVerify_DifferentMessages_DifferentSignatures) {
    const char msg1[] = "Message one";
    const char msg2[] = "Message two";
    uint8_t sig1[TF5_IBS_SIG_LEN], sig2[TF5_IBS_SIG_LEN];

    tf5_bls_sign(sk_gnb, (const uint8_t*)msg1, strlen(msg1), sig1);
    tf5_bls_sign(sk_gnb, (const uint8_t*)msg2, strlen(msg2), sig2);

    EXPECT_NE(0, memcmp(sig1, sig2, TF5_IBS_SIG_LEN))
        << "Different messages should produce different signatures";

    // Both should verify with correct parameters
    EXPECT_EQ(0, tf5_sig_verify(mpk, cell_id, validity_end,
                                       (const uint8_t*)msg1, strlen(msg1), sig1));
    EXPECT_EQ(0, tf5_sig_verify(mpk, cell_id, validity_end,
                                       (const uint8_t*)msg2, strlen(msg2), sig2));
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
