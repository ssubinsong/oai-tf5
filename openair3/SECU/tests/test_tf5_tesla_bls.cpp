/**
 * @file test_tf5_tesla_bls.cpp
 * @brief Unit tests for TF5 BLMQ IBS signature operations
 *
 * Tests for:
 * - tf5_ibs_init(): BLMQ IBS subsystem initialization
 * - tf5_ibs_validate_sk(): Secret key validation
 * - tf5_ibs_sign(): BLMQ IBS signing
 * - tf5_ibs_verify(): BLMQ IBS verification
 */

#define TF5_TEST_NEEDS_OAI_STUBS
#include "tf5_test_common.h"

extern "C" {
#include "openair3/SECU/tf5_ibs_pkg.h"
#include "openair3/SECU/tf5_tesla.h"
}

#include "tf5_test_vectors.h"

// ============================================================================
// IBS Initialization Tests
// ============================================================================

class TF5IbsInitTest : public ::testing::Test {
protected:
    static bool ibs_initialized;

    void SetUp() override {
        if (!ibs_initialized) {
            int ret = tf5_ibs_init();
            ASSERT_EQ(0, ret) << "IBS init should succeed";
            ibs_initialized = true;
        }
    }
};

bool TF5IbsInitTest::ibs_initialized = false;

TEST_F(TF5IbsInitTest, IbsInit_Success) {
    EXPECT_TRUE(ibs_initialized);
}

// ============================================================================
// IBS Validate SK Tests
// ============================================================================

TEST_F(TF5IbsInitTest, IbsValidateSk_NullInput_ReturnsError) {
    int ret = tf5_ibs_validate_sk(nullptr);
    EXPECT_LT(ret, 0) << "Null sk_id should return error";
}

TEST_F(TF5IbsInitTest, IbsValidateSk_ZeroKey_ReturnsError) {
    uint8_t zero_key[TF5_IBS_GNB_SK_LEN] = {0};
    // G1 identity (all zeros compressed) should be rejected as infinity
    int ret = tf5_ibs_validate_sk(zero_key);
    EXPECT_NE(0, ret) << "All-zero key (identity point) should be rejected";
}

TEST_F(TF5IbsInitTest, IbsValidateSk_GarbageKey_ReturnsError) {
    uint8_t garbage[TF5_IBS_GNB_SK_LEN];
    memset(garbage, 0xFF, sizeof(garbage));
    int ret = tf5_ibs_validate_sk(garbage);
    EXPECT_NE(0, ret) << "Garbage bytes should fail G1 decompression";
}

// ============================================================================
// IBS Sign Tests
// ============================================================================

TEST_F(TF5IbsInitTest, IbsSign_NullInputs_ReturnsError) {
    uint8_t dummy_sk[TF5_IBS_GNB_SK_LEN] = {0};
    uint8_t dummy_sig[TF5_IBS_SIG_LEN] = {0};
    const uint8_t data[] = "test";

    int ret = tf5_ibs_sign(nullptr, data, 4, dummy_sig);
    EXPECT_LT(ret, 0) << "Null sk should return error";

    ret = tf5_ibs_sign(dummy_sk, nullptr, 4, dummy_sig);
    EXPECT_LT(ret, 0) << "Null data should return error";

    ret = tf5_ibs_sign(dummy_sk, data, 4, nullptr);
    EXPECT_LT(ret, 0) << "Null signature output should return error";

    ret = tf5_ibs_sign(dummy_sk, data, 0, dummy_sig);
    EXPECT_LT(ret, 0) << "Zero-length data should return error";
}

// ============================================================================
// IBS Verify Tests (null input handling)
// ============================================================================

TEST_F(TF5IbsInitTest, IbsVerify_NullMpk_ReturnsError) {
    uint8_t dummy_sig[TF5_IBS_SIG_LEN] = {0};
    const char data[] = "test data";

    int ret = tf5_ibs_verify(nullptr, tf5_test::TV_IBS_CELL_ID,
                                    tf5_test::TV_IBS_VALIDITY_END,
                                    (const uint8_t*)data, strlen(data), dummy_sig);

    EXPECT_LT(ret, 0) << "Null MPK should return error";
}

TEST_F(TF5IbsInitTest, IbsVerify_NullCellId_ReturnsError) {
    uint8_t dummy_mpk[TF5_IBS_GNB_PK_LEN] = {0};
    uint8_t dummy_sig[TF5_IBS_SIG_LEN] = {0};
    const char data[] = "test data";

    int ret = tf5_ibs_verify(dummy_mpk, nullptr,
                                    tf5_test::TV_IBS_VALIDITY_END,
                                    (const uint8_t*)data, strlen(data), dummy_sig);

    EXPECT_LT(ret, 0) << "Null cell_id should return error";
}

TEST_F(TF5IbsInitTest, IbsVerify_NullData_ReturnsError) {
    uint8_t dummy_mpk[TF5_IBS_GNB_PK_LEN] = {0};
    uint8_t dummy_sig[TF5_IBS_SIG_LEN] = {0};

    int ret = tf5_ibs_verify(dummy_mpk, tf5_test::TV_IBS_CELL_ID,
                                    tf5_test::TV_IBS_VALIDITY_END,
                                    nullptr, 10, dummy_sig);

    EXPECT_LT(ret, 0) << "Null data should return error";
}

TEST_F(TF5IbsInitTest, IbsVerify_NullSignature_ReturnsError) {
    uint8_t dummy_mpk[TF5_IBS_GNB_PK_LEN] = {0};
    const char data[] = "test data";

    int ret = tf5_ibs_verify(dummy_mpk, tf5_test::TV_IBS_CELL_ID,
                                    tf5_test::TV_IBS_VALIDITY_END,
                                    (const uint8_t*)data, strlen(data), nullptr);

    EXPECT_LT(ret, 0) << "Null signature should return error";
}

// ============================================================================
// IBS End-to-End Tests using PKG-generated keys
// ============================================================================

bool TF5IbsTestFixture::ibs_initialized = false;

class TF5IbsE2ETest : public TF5IbsTestFixture {
protected:
    uint8_t (&msk)[TF5_IBS_MASTER_SECRET_LEN] = ibs_msk;
    uint8_t (&mpk)[TF5_IBS_MPK_LEN] = ibs_mpk;
    uint8_t (&sk_gnb)[TF5_IBS_GNB_SK_LEN] = ibs_sk;

    void SetUp() override {
        TF5IbsTestFixture::SetUp();
        setupTestDir("tf5_ibs_e2e_test");
        generateAndLoadKeys();
    }
};

TEST_F(TF5IbsE2ETest, IbsValidateSk_ValidKey_Success) {
    int ret = tf5_ibs_validate_sk(sk_gnb);
    EXPECT_EQ(0, ret) << "PKG-issued sk_ID should validate successfully";
}

TEST_F(TF5IbsE2ETest, IbsSignVerify_ValidSignature_Success) {
    const char message[] = "Test message for BLMQ IBS signature verification";
    uint8_t signature[TF5_IBS_SIG_LEN];

    int sign_ret = tf5_ibs_sign(sk_gnb, (const uint8_t*)message,
                                       strlen(message), signature);
    ASSERT_EQ(0, sign_ret) << "BLMQ IBS signing should succeed";

    // Verify signature is not all zeros
    EXPECT_FALSE(is_all_zeros(signature, TF5_IBS_SIG_LEN))
        << "Signature should not be all zeros";

    int verify_ret = tf5_ibs_verify(mpk, cell_id, validity_end,
                                           (const uint8_t*)message,
                                           strlen(message), signature);

    EXPECT_EQ(0, verify_ret) << "Valid BLMQ IBS signature should verify successfully";
}

TEST_F(TF5IbsE2ETest, IbsSign_Randomized) {
    // BLMQ IBS signing is randomized (unlike deterministic BLS)
    const char message[] = "Same message";
    uint8_t sig1[TF5_IBS_SIG_LEN], sig2[TF5_IBS_SIG_LEN];

    tf5_ibs_sign(sk_gnb, (const uint8_t*)message, strlen(message), sig1);
    tf5_ibs_sign(sk_gnb, (const uint8_t*)message, strlen(message), sig2);

    // Signatures should differ due to random nonce x
    EXPECT_NE(0, memcmp(sig1, sig2, TF5_IBS_SIG_LEN))
        << "BLMQ IBS signatures should be randomized";

    // But both should verify correctly
    EXPECT_EQ(0, tf5_ibs_verify(mpk, cell_id, validity_end,
                                       (const uint8_t*)message, strlen(message), sig1));
    EXPECT_EQ(0, tf5_ibs_verify(mpk, cell_id, validity_end,
                                       (const uint8_t*)message, strlen(message), sig2));
}

TEST_F(TF5IbsE2ETest, IbsSignVerify_TamperedMessage_Fails) {
    const char message[] = "Original message";
    uint8_t signature[TF5_IBS_SIG_LEN];

    tf5_ibs_sign(sk_gnb, (const uint8_t*)message, strlen(message), signature);

    const char tampered[] = "Tampered message";
    int verify_ret = tf5_ibs_verify(mpk, cell_id, validity_end,
                                           (const uint8_t*)tampered,
                                           strlen(tampered), signature);

    EXPECT_NE(0, verify_ret) << "Tampered message should fail verification";
}

TEST_F(TF5IbsE2ETest, IbsSignVerify_WrongCellId_Fails) {
    const char message[] = "Test message";
    uint8_t signature[TF5_IBS_SIG_LEN];

    tf5_ibs_sign(sk_gnb, (const uint8_t*)message, strlen(message), signature);

    uint8_t wrong_cell_id[TF5_IBS_CELL_ID_LEN] = {0xAA, 0xBB, 0xCC, 0xDD, 0xE0};
    int verify_ret = tf5_ibs_verify(mpk, wrong_cell_id, validity_end,
                                           (const uint8_t*)message,
                                           strlen(message), signature);

    EXPECT_NE(0, verify_ret) << "Wrong cell ID should fail verification";
}

TEST_F(TF5IbsE2ETest, IbsSignVerify_WrongValidity_Fails) {
    const char message[] = "Test message";
    uint8_t signature[TF5_IBS_SIG_LEN];

    tf5_ibs_sign(sk_gnb, (const uint8_t*)message, strlen(message), signature);

    uint32_t wrong_validity = 999999;
    int verify_ret = tf5_ibs_verify(mpk, cell_id, wrong_validity,
                                           (const uint8_t*)message,
                                           strlen(message), signature);

    EXPECT_NE(0, verify_ret) << "Wrong validity should fail verification";
}

TEST_F(TF5IbsE2ETest, IbsSignVerify_TamperedSignature_Fails) {
    const char message[] = "Test message";
    uint8_t signature[TF5_IBS_SIG_LEN];

    tf5_ibs_sign(sk_gnb, (const uint8_t*)message, strlen(message), signature);

    // Tamper with the h part (first 32 bytes)
    signature[0] ^= 0xFF;

    int verify_ret = tf5_ibs_verify(mpk, cell_id, validity_end,
                                           (const uint8_t*)message,
                                           strlen(message), signature);

    EXPECT_NE(0, verify_ret) << "Tampered signature should fail verification";
}

TEST_F(TF5IbsE2ETest, IbsSignVerify_DifferentMessages_BothVerify) {
    const char msg1[] = "Message one";
    const char msg2[] = "Message two";
    uint8_t sig1[TF5_IBS_SIG_LEN], sig2[TF5_IBS_SIG_LEN];

    tf5_ibs_sign(sk_gnb, (const uint8_t*)msg1, strlen(msg1), sig1);
    tf5_ibs_sign(sk_gnb, (const uint8_t*)msg2, strlen(msg2), sig2);

    EXPECT_EQ(0, tf5_ibs_verify(mpk, cell_id, validity_end,
                                       (const uint8_t*)msg1, strlen(msg1), sig1));
    EXPECT_EQ(0, tf5_ibs_verify(mpk, cell_id, validity_end,
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
