/**
 * @file test_tf5_tesla_bls.cpp
 * @brief Unit tests for TF5 TESLA BLS signature operations
 *
 * Tests for:
 * - tf5_tesla_bls_init(): BLS library initialization
 * - tf5_tesla_bls_keygen(): Key pair generation
 * - tf5_tesla_bls_derive_public(): Public key derivation
 * - tf5_tesla_bls_sign(): BLS signing
 * - tf5_tesla_bls_verify(): BLS verification
 * - tf5_tesla_ibs_verify(): Identity-Based Signature verification
 * - tf5_tesla_ibs_hash_to_scalar(): Identity hash function
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

class TF5BlsTest : public ::testing::Test {
protected:
    uint8_t secret_key[TF5_BLS_SECRET_KEY_LEN];
    uint8_t public_key[TF5_BLS_PUBKEY_LEN];
    uint8_t signature[TF5_BLS_SIG_LEN];

    static bool bls_initialized;

    void SetUp() override {
        // Initialize BLS library once
        if (!bls_initialized) {
            int ret = tf5_tesla_bls_init();
            ASSERT_EQ(0, ret) << "BLS init should succeed";
            bls_initialized = true;
        }

        // Use test secret key
        memcpy(secret_key, tf5_test::TV_BLS_SECRET_KEY, TF5_BLS_SECRET_KEY_LEN);

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
// Key Generation Tests
// ============================================================================

TEST_F(TF5BlsTest, BlsKeygen_Success) {
    uint8_t new_sk[TF5_BLS_SECRET_KEY_LEN];
    uint8_t new_pk[TF5_BLS_PUBKEY_LEN];

    int ret = tf5_tesla_bls_keygen(new_sk, new_pk);

    EXPECT_EQ(0, ret) << "Key generation should succeed";

    // Verify keys are not all zeros
    bool sk_all_zeros = true, pk_all_zeros = true;
    for (int i = 0; i < TF5_BLS_SECRET_KEY_LEN; i++) {
        if (new_sk[i] != 0) sk_all_zeros = false;
    }
    for (int i = 0; i < TF5_BLS_PUBKEY_LEN; i++) {
        if (new_pk[i] != 0) pk_all_zeros = false;
    }

    EXPECT_FALSE(sk_all_zeros) << "Secret key should not be all zeros";
    EXPECT_FALSE(pk_all_zeros) << "Public key should not be all zeros";
}

TEST_F(TF5BlsTest, BlsKeygen_DifferentKeysEachTime) {
    uint8_t sk1[TF5_BLS_SECRET_KEY_LEN], sk2[TF5_BLS_SECRET_KEY_LEN];
    uint8_t pk1[TF5_BLS_PUBKEY_LEN], pk2[TF5_BLS_PUBKEY_LEN];

    tf5_tesla_bls_keygen(sk1, pk1);
    tf5_tesla_bls_keygen(sk2, pk2);

    EXPECT_NE(0, memcmp(sk1, sk2, TF5_BLS_SECRET_KEY_LEN))
        << "Each keygen should produce different secret keys";
    EXPECT_NE(0, memcmp(pk1, pk2, TF5_BLS_PUBKEY_LEN))
        << "Each keygen should produce different public keys";
}

// ============================================================================
// Public Key Derivation Tests
// ============================================================================

TEST_F(TF5BlsTest, BlsDerivePublic_Success) {
    int ret = tf5_tesla_bls_derive_public(secret_key, public_key);

    EXPECT_EQ(0, ret) << "Public key derivation should succeed";

    // Verify public key is not all zeros
    bool all_zeros = true;
    for (int i = 0; i < TF5_BLS_PUBKEY_LEN; i++) {
        if (public_key[i] != 0) {
            all_zeros = false;
            break;
        }
    }
    EXPECT_FALSE(all_zeros) << "Public key should not be all zeros";
}

TEST_F(TF5BlsTest, BlsDerivePublic_Deterministic) {
    uint8_t pk1[TF5_BLS_PUBKEY_LEN], pk2[TF5_BLS_PUBKEY_LEN];

    tf5_tesla_bls_derive_public(secret_key, pk1);
    tf5_tesla_bls_derive_public(secret_key, pk2);

    EXPECT_EQ(0, memcmp(pk1, pk2, TF5_BLS_PUBKEY_LEN))
        << "Same secret key should derive same public key";
}

TEST_F(TF5BlsTest, BlsDerivePublic_DifferentKeys) {
    uint8_t sk1[TF5_BLS_SECRET_KEY_LEN] = {0x01};
    uint8_t sk2[TF5_BLS_SECRET_KEY_LEN] = {0x02};
    uint8_t pk1[TF5_BLS_PUBKEY_LEN], pk2[TF5_BLS_PUBKEY_LEN];

    tf5_tesla_bls_derive_public(sk1, pk1);
    tf5_tesla_bls_derive_public(sk2, pk2);

    EXPECT_NE(0, memcmp(pk1, pk2, TF5_BLS_PUBKEY_LEN))
        << "Different secret keys should derive different public keys";
}

TEST_F(TF5BlsTest, BlsDerivePublic_NullInputs_ReturnsError) {
    int ret = tf5_tesla_bls_derive_public(nullptr, public_key);
    EXPECT_LT(ret, 0) << "Null secret key should return error";

    ret = tf5_tesla_bls_derive_public(secret_key, nullptr);
    EXPECT_LT(ret, 0) << "Null public key output should return error";
}

// ============================================================================
// BLS Sign Tests
// ============================================================================

TEST_F(TF5BlsTest, BlsSign_Success) {
    int ret = tf5_tesla_bls_sign(
        secret_key,
        (const uint8_t*)tf5_test::TV_BLS_MESSAGE,
        tf5_test::TV_BLS_MESSAGE_LEN,
        signature
    );

    EXPECT_EQ(0, ret) << "BLS sign should succeed";

    // Verify signature is not all zeros
    bool all_zeros = true;
    for (int i = 0; i < TF5_BLS_SIG_LEN; i++) {
        if (signature[i] != 0) {
            all_zeros = false;
            break;
        }
    }
    EXPECT_FALSE(all_zeros) << "Signature should not be all zeros";
}

TEST_F(TF5BlsTest, BlsSign_Deterministic) {
    uint8_t sig1[TF5_BLS_SIG_LEN], sig2[TF5_BLS_SIG_LEN];

    tf5_tesla_bls_sign(secret_key, (const uint8_t*)tf5_test::TV_BLS_MESSAGE,
                       tf5_test::TV_BLS_MESSAGE_LEN, sig1);
    tf5_tesla_bls_sign(secret_key, (const uint8_t*)tf5_test::TV_BLS_MESSAGE,
                       tf5_test::TV_BLS_MESSAGE_LEN, sig2);

    EXPECT_EQ(0, memcmp(sig1, sig2, TF5_BLS_SIG_LEN))
        << "Same key and message should produce same signature";
}

TEST_F(TF5BlsTest, BlsSign_DifferentMessages_DifferentSignatures) {
    const char msg1[] = "Message one";
    const char msg2[] = "Message two";
    uint8_t sig1[TF5_BLS_SIG_LEN], sig2[TF5_BLS_SIG_LEN];

    tf5_tesla_bls_sign(secret_key, (const uint8_t*)msg1, strlen(msg1), sig1);
    tf5_tesla_bls_sign(secret_key, (const uint8_t*)msg2, strlen(msg2), sig2);

    EXPECT_NE(0, memcmp(sig1, sig2, TF5_BLS_SIG_LEN))
        << "Different messages should produce different signatures";
}

TEST_F(TF5BlsTest, BlsSign_NullInputs_ReturnsError) {
    int ret = tf5_tesla_bls_sign(nullptr, (const uint8_t*)"test", 4, signature);
    EXPECT_LT(ret, 0) << "Null secret key should return error";

    ret = tf5_tesla_bls_sign(secret_key, nullptr, 4, signature);
    EXPECT_LT(ret, 0) << "Null data should return error";

    ret = tf5_tesla_bls_sign(secret_key, (const uint8_t*)"test", 4, nullptr);
    EXPECT_LT(ret, 0) << "Null signature output should return error";
}

// ============================================================================
// BLS Verify Tests
// ============================================================================

TEST_F(TF5BlsTest, BlsVerify_ValidSignature_Success) {
    // Derive public key
    tf5_tesla_bls_derive_public(secret_key, public_key);

    // Sign message
    tf5_tesla_bls_sign(secret_key, (const uint8_t*)tf5_test::TV_BLS_MESSAGE,
                       tf5_test::TV_BLS_MESSAGE_LEN, signature);

    // Verify
    int ret = tf5_tesla_bls_verify(public_key, (const uint8_t*)tf5_test::TV_BLS_MESSAGE,
                                   tf5_test::TV_BLS_MESSAGE_LEN, signature);

    EXPECT_EQ(0, ret) << "Valid signature should verify";
}

TEST_F(TF5BlsTest, BlsVerify_WrongKey_Fails) {
    // Derive public key
    tf5_tesla_bls_derive_public(secret_key, public_key);

    // Sign message
    tf5_tesla_bls_sign(secret_key, (const uint8_t*)tf5_test::TV_BLS_MESSAGE,
                       tf5_test::TV_BLS_MESSAGE_LEN, signature);

    // Generate a different key pair
    uint8_t wrong_sk[TF5_BLS_SECRET_KEY_LEN], wrong_pk[TF5_BLS_PUBKEY_LEN];
    tf5_tesla_bls_keygen(wrong_sk, wrong_pk);

    // Verify with wrong public key
    int ret = tf5_tesla_bls_verify(wrong_pk, (const uint8_t*)tf5_test::TV_BLS_MESSAGE,
                                   tf5_test::TV_BLS_MESSAGE_LEN, signature);

    EXPECT_NE(0, ret) << "Signature should not verify with wrong key";
}

TEST_F(TF5BlsTest, BlsVerify_WrongMessage_Fails) {
    // Derive public key
    tf5_tesla_bls_derive_public(secret_key, public_key);

    // Sign original message
    tf5_tesla_bls_sign(secret_key, (const uint8_t*)tf5_test::TV_BLS_MESSAGE,
                       tf5_test::TV_BLS_MESSAGE_LEN, signature);

    // Verify with different message
    const char wrong_msg[] = "Wrong message";
    int ret = tf5_tesla_bls_verify(public_key, (const uint8_t*)wrong_msg,
                                   strlen(wrong_msg), signature);

    EXPECT_NE(0, ret) << "Signature should not verify for wrong message";
}

TEST_F(TF5BlsTest, BlsVerify_TamperedSignature_Fails) {
    // Derive public key
    tf5_tesla_bls_derive_public(secret_key, public_key);

    // Sign message
    tf5_tesla_bls_sign(secret_key, (const uint8_t*)tf5_test::TV_BLS_MESSAGE,
                       tf5_test::TV_BLS_MESSAGE_LEN, signature);

    // Tamper with signature
    signature[0] ^= 0xFF;

    // Verify tampered signature
    int ret = tf5_tesla_bls_verify(public_key, (const uint8_t*)tf5_test::TV_BLS_MESSAGE,
                                   tf5_test::TV_BLS_MESSAGE_LEN, signature);

    EXPECT_NE(0, ret) << "Tampered signature should not verify";
}

TEST_F(TF5BlsTest, BlsVerify_NullInputs_ReturnsError) {
    tf5_tesla_bls_derive_public(secret_key, public_key);
    tf5_tesla_bls_sign(secret_key, (const uint8_t*)"test", 4, signature);

    int ret = tf5_tesla_bls_verify(nullptr, (const uint8_t*)"test", 4, signature);
    EXPECT_LT(ret, 0) << "Null public key should return error";

    ret = tf5_tesla_bls_verify(public_key, nullptr, 4, signature);
    EXPECT_LT(ret, 0) << "Null data should return error";

    ret = tf5_tesla_bls_verify(public_key, (const uint8_t*)"test", 4, nullptr);
    EXPECT_LT(ret, 0) << "Null signature should return error";
}

// ============================================================================
// IBS Hash to Scalar Tests
// ============================================================================

TEST_F(TF5BlsTest, IbsHashToScalar_Deterministic) {
    uint8_t scalar1[TF5_BLS_SECRET_KEY_LEN], scalar2[TF5_BLS_SECRET_KEY_LEN];

    tf5_tesla_ibs_hash_to_scalar(tf5_test::TV_IBS_CELL_ID, TF5_IBS_CELL_ID_LEN,
                                  tf5_test::TV_IBS_VALIDITY_END, scalar1);
    tf5_tesla_ibs_hash_to_scalar(tf5_test::TV_IBS_CELL_ID, TF5_IBS_CELL_ID_LEN,
                                  tf5_test::TV_IBS_VALIDITY_END, scalar2);

    EXPECT_EQ(0, memcmp(scalar1, scalar2, TF5_BLS_SECRET_KEY_LEN))
        << "Same inputs should produce same scalar";
}

TEST_F(TF5BlsTest, IbsHashToScalar_DifferentCellIds) {
    uint8_t cell_id1[TF5_IBS_CELL_ID_LEN] = {0x01, 0x02, 0x03, 0x04, 0x05};
    uint8_t cell_id2[TF5_IBS_CELL_ID_LEN] = {0x11, 0x12, 0x13, 0x14, 0x15};
    uint8_t scalar1[TF5_BLS_SECRET_KEY_LEN], scalar2[TF5_BLS_SECRET_KEY_LEN];

    tf5_tesla_ibs_hash_to_scalar(cell_id1, TF5_IBS_CELL_ID_LEN,
                                  tf5_test::TV_IBS_VALIDITY_END, scalar1);
    tf5_tesla_ibs_hash_to_scalar(cell_id2, TF5_IBS_CELL_ID_LEN,
                                  tf5_test::TV_IBS_VALIDITY_END, scalar2);

    EXPECT_NE(0, memcmp(scalar1, scalar2, TF5_BLS_SECRET_KEY_LEN))
        << "Different cell IDs should produce different scalars";
}

TEST_F(TF5BlsTest, IbsHashToScalar_DifferentValidity) {
    uint8_t scalar1[TF5_BLS_SECRET_KEY_LEN], scalar2[TF5_BLS_SECRET_KEY_LEN];

    tf5_tesla_ibs_hash_to_scalar(tf5_test::TV_IBS_CELL_ID, TF5_IBS_CELL_ID_LEN,
                                  1000, scalar1);
    tf5_tesla_ibs_hash_to_scalar(tf5_test::TV_IBS_CELL_ID, TF5_IBS_CELL_ID_LEN,
                                  2000, scalar2);

    EXPECT_NE(0, memcmp(scalar1, scalar2, TF5_BLS_SECRET_KEY_LEN))
        << "Different validity periods should produce different scalars";
}

TEST_F(TF5BlsTest, IbsHashToScalar_NullInputs_ReturnsError) {
    uint8_t scalar[TF5_BLS_SECRET_KEY_LEN];

    int ret = tf5_tesla_ibs_hash_to_scalar(nullptr, TF5_IBS_CELL_ID_LEN,
                                            tf5_test::TV_IBS_VALIDITY_END, scalar);
    EXPECT_LT(ret, 0) << "Null cell_id should return error";

    ret = tf5_tesla_ibs_hash_to_scalar(tf5_test::TV_IBS_CELL_ID, TF5_IBS_CELL_ID_LEN,
                                        tf5_test::TV_IBS_VALIDITY_END, nullptr);
    EXPECT_LT(ret, 0) << "Null scalar output should return error";
}

// ============================================================================
// IBS Verify Tests
// ============================================================================

// Note: Full IBS verification requires a properly issued gNB key from Core PKG
// These tests verify error handling and basic structure

TEST_F(TF5BlsTest, IbsVerify_NullMpk_ReturnsError) {
    uint8_t dummy_sig[TF5_BLS_SIG_LEN] = {0};
    const char data[] = "test data";

    int ret = tf5_tesla_ibs_verify(nullptr, tf5_test::TV_IBS_CELL_ID,
                                    tf5_test::TV_IBS_VALIDITY_END,
                                    (const uint8_t*)data, strlen(data), dummy_sig);

    EXPECT_LT(ret, 0) << "Null MPK should return error";
}

TEST_F(TF5BlsTest, IbsVerify_NullCellId_ReturnsError) {
    uint8_t dummy_mpk[TF5_BLS_PUBKEY_LEN] = {0};
    uint8_t dummy_sig[TF5_BLS_SIG_LEN] = {0};
    const char data[] = "test data";

    int ret = tf5_tesla_ibs_verify(dummy_mpk, nullptr,
                                    tf5_test::TV_IBS_VALIDITY_END,
                                    (const uint8_t*)data, strlen(data), dummy_sig);

    EXPECT_LT(ret, 0) << "Null cell_id should return error";
}

TEST_F(TF5BlsTest, IbsVerify_NullData_ReturnsError) {
    uint8_t dummy_mpk[TF5_BLS_PUBKEY_LEN] = {0};
    uint8_t dummy_sig[TF5_BLS_SIG_LEN] = {0};

    int ret = tf5_tesla_ibs_verify(dummy_mpk, tf5_test::TV_IBS_CELL_ID,
                                    tf5_test::TV_IBS_VALIDITY_END,
                                    nullptr, 10, dummy_sig);

    EXPECT_LT(ret, 0) << "Null data should return error";
}

TEST_F(TF5BlsTest, IbsVerify_NullSignature_ReturnsError) {
    uint8_t dummy_mpk[TF5_BLS_PUBKEY_LEN] = {0};
    const char data[] = "test data";

    int ret = tf5_tesla_ibs_verify(dummy_mpk, tf5_test::TV_IBS_CELL_ID,
                                    tf5_test::TV_IBS_VALIDITY_END,
                                    (const uint8_t*)data, strlen(data), nullptr);

    EXPECT_LT(ret, 0) << "Null signature should return error";
}

// ============================================================================
// IBS End-to-End Tests using PKG binaries
// ============================================================================

/**
 * Test fixture that uses the Core PKG binaries to generate IBS keys.
 * This enables full end-to-end IBS signature testing with properly issued keys.
 *
 * The PKG binaries must be available at TF5_PKG_KEYGEN_PATH and TF5_PKG_ISSUE_PATH.
 * If not found, these tests are skipped.
 */
class TF5IbsE2ETest : public ::testing::Test {
protected:
    // Paths to PKG binaries (relative to test working directory: oai-tf5/cmake_targets/ran_build/build/openair3/SECU/tests)
    static constexpr const char* PKG_KEYGEN_PATH = "../../../../../../../tf5-code/core-pkg/build/tf5_ibs_pkg_keygen";
    static constexpr const char* PKG_ISSUE_PATH = "../../../../../../../tf5-code/core-pkg/build/tf5_ibs_issue";

    std::string test_dir;
    std::string msk_path;
    std::string mpk_path;
    std::string sk_gnb_path;

    uint8_t msk[TF5_BLS_SECRET_KEY_LEN];
    uint8_t mpk[TF5_IBS_PUBKEY_LEN];
    uint8_t sk_gnb[TF5_BLS_SECRET_KEY_LEN];
    uint8_t cell_id[TF5_IBS_CELL_ID_LEN];
    uint32_t validity_end;

    bool pkg_available;

    static bool bls_initialized;

    void SetUp() override {
        // Initialize BLS library once
        if (!bls_initialized) {
            tf5_tesla_bls_init();
            bls_initialized = true;
        }

        // Set up test parameters
        memset(cell_id, 0, TF5_IBS_CELL_ID_LEN);
        cell_id[0] = 0x12;
        cell_id[1] = 0x34;
        cell_id[2] = 0x56;
        cell_id[3] = 0x78;
        cell_id[4] = 0x90;  // 36-bit cell ID = 0x123456789

        validity_end = 1051200;  // 2 years from epoch

        // Create temp directory
        test_dir = "/tmp/tf5_ibs_e2e_test_" + std::to_string(getpid());
        mkdir(test_dir.c_str(), 0700);
        msk_path = test_dir + "/msk.bin";
        mpk_path = test_dir + "/mpk.bin";
        sk_gnb_path = test_dir + "/sk_gnb.bin";

        // Check if PKG binaries are available
        pkg_available = checkPkgBinaries();

        if (pkg_available) {
            // Generate keys using PKG binaries
            generateKeysWithPkg();
            loadGeneratedKeys();
        }
    }

    void TearDown() override {
        // Clean up
        unlink(msk_path.c_str());
        unlink(mpk_path.c_str());
        unlink(sk_gnb_path.c_str());
        rmdir(test_dir.c_str());
    }

    bool checkPkgBinaries() {
        // Check if keygen binary exists
        if (access(PKG_KEYGEN_PATH, X_OK) != 0) {
            return false;
        }
        // Check if issue binary exists
        if (access(PKG_ISSUE_PATH, X_OK) != 0) {
            return false;
        }
        return true;
    }

    void generateKeysWithPkg() {
        // Generate master keypair
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "%s %s %s >/dev/null 2>&1",
                 PKG_KEYGEN_PATH, msk_path.c_str(), mpk_path.c_str());
        int ret = system(cmd);
        ASSERT_EQ(0, ret) << "Failed to generate master keypair";

        // Issue gNB key
        // Cell ID 0x123456789 as hex string
        snprintf(cmd, sizeof(cmd), "%s %s 123456789 %u %s >/dev/null 2>&1",
                 PKG_ISSUE_PATH, msk_path.c_str(), validity_end, sk_gnb_path.c_str());
        ret = system(cmd);
        ASSERT_EQ(0, ret) << "Failed to issue gNB key";
    }

    void loadGeneratedKeys() {
        // Load MSK
        FILE* f = fopen(msk_path.c_str(), "rb");
        ASSERT_NE(nullptr, f) << "Failed to open MSK file";
        size_t n = fread(msk, 1, TF5_BLS_SECRET_KEY_LEN, f);
        fclose(f);
        ASSERT_EQ(TF5_BLS_SECRET_KEY_LEN, n) << "Failed to read MSK";

        // Load MPK
        f = fopen(mpk_path.c_str(), "rb");
        ASSERT_NE(nullptr, f) << "Failed to open MPK file";
        n = fread(mpk, 1, TF5_IBS_PUBKEY_LEN, f);
        fclose(f);
        ASSERT_EQ(TF5_IBS_PUBKEY_LEN, n) << "Failed to read MPK";

        // Load gNB secret key (35 bytes: 32 sk + 3 validity)
        f = fopen(sk_gnb_path.c_str(), "rb");
        ASSERT_NE(nullptr, f) << "Failed to open gNB SK file";
        uint8_t sk_file[35];
        n = fread(sk_file, 1, 35, f);
        fclose(f);
        ASSERT_EQ(35, n) << "Failed to read gNB SK";

        // Extract secret key (first 32 bytes)
        memcpy(sk_gnb, sk_file, TF5_BLS_SECRET_KEY_LEN);

        // Extract validity (last 3 bytes, big-endian) for verification
        uint32_t file_validity = ((uint32_t)sk_file[32] << 16) |
                                 ((uint32_t)sk_file[33] << 8) |
                                 (uint32_t)sk_file[34];
        ASSERT_EQ(validity_end, file_validity) << "Validity mismatch in key file";
    }
};

bool TF5IbsE2ETest::bls_initialized = false;

TEST_F(TF5IbsE2ETest, IbsSignVerify_ValidSignature_Success) {
    if (!pkg_available) {
        GTEST_SKIP() << "PKG binaries not available, skipping IBS E2E test";
    }

    const char message[] = "Test message for IBS signature verification";
    uint8_t signature[TF5_BLS_SIG_LEN];

    // Sign with the IBS secret key (sk_ID issued by PKG)
    int sign_ret = tf5_tesla_bls_sign(sk_gnb, (const uint8_t*)message,
                                       strlen(message), signature);
    ASSERT_EQ(0, sign_ret) << "IBS signing should succeed";

    // Verify using IBS verification (with MPK and identity)
    int verify_ret = tf5_tesla_ibs_verify(mpk, cell_id, validity_end,
                                           (const uint8_t*)message,
                                           strlen(message), signature);

    EXPECT_EQ(0, verify_ret) << "Valid IBS signature should verify successfully";
}

TEST_F(TF5IbsE2ETest, IbsSignVerify_TamperedMessage_Fails) {
    if (!pkg_available) {
        GTEST_SKIP() << "PKG binaries not available, skipping IBS E2E test";
    }

    const char message[] = "Original message";
    uint8_t signature[TF5_BLS_SIG_LEN];

    // Sign with the IBS secret key
    tf5_tesla_bls_sign(sk_gnb, (const uint8_t*)message, strlen(message), signature);

    // Verify with tampered message
    const char tampered[] = "Tampered message";
    int verify_ret = tf5_tesla_ibs_verify(mpk, cell_id, validity_end,
                                           (const uint8_t*)tampered,
                                           strlen(tampered), signature);

    EXPECT_NE(0, verify_ret) << "Tampered message should fail verification";
}

TEST_F(TF5IbsE2ETest, IbsSignVerify_WrongCellId_Fails) {
    if (!pkg_available) {
        GTEST_SKIP() << "PKG binaries not available, skipping IBS E2E test";
    }

    const char message[] = "Test message";
    uint8_t signature[TF5_BLS_SIG_LEN];

    // Sign with the IBS secret key
    tf5_tesla_bls_sign(sk_gnb, (const uint8_t*)message, strlen(message), signature);

    // Verify with wrong cell ID
    uint8_t wrong_cell_id[TF5_IBS_CELL_ID_LEN] = {0xAA, 0xBB, 0xCC, 0xDD, 0xE0};
    int verify_ret = tf5_tesla_ibs_verify(mpk, wrong_cell_id, validity_end,
                                           (const uint8_t*)message,
                                           strlen(message), signature);

    EXPECT_NE(0, verify_ret) << "Wrong cell ID should fail verification";
}

TEST_F(TF5IbsE2ETest, IbsSignVerify_WrongValidity_Fails) {
    if (!pkg_available) {
        GTEST_SKIP() << "PKG binaries not available, skipping IBS E2E test";
    }

    const char message[] = "Test message";
    uint8_t signature[TF5_BLS_SIG_LEN];

    // Sign with the IBS secret key
    tf5_tesla_bls_sign(sk_gnb, (const uint8_t*)message, strlen(message), signature);

    // Verify with wrong validity
    uint32_t wrong_validity = 999999;
    int verify_ret = tf5_tesla_ibs_verify(mpk, cell_id, wrong_validity,
                                           (const uint8_t*)message,
                                           strlen(message), signature);

    EXPECT_NE(0, verify_ret) << "Wrong validity should fail verification";
}

TEST_F(TF5IbsE2ETest, IbsSignVerify_TamperedSignature_Fails) {
    if (!pkg_available) {
        GTEST_SKIP() << "PKG binaries not available, skipping IBS E2E test";
    }

    const char message[] = "Test message";
    uint8_t signature[TF5_BLS_SIG_LEN];

    // Sign with the IBS secret key
    tf5_tesla_bls_sign(sk_gnb, (const uint8_t*)message, strlen(message), signature);

    // Tamper with signature
    signature[0] ^= 0xFF;
    signature[10] ^= 0xFF;

    int verify_ret = tf5_tesla_ibs_verify(mpk, cell_id, validity_end,
                                           (const uint8_t*)message,
                                           strlen(message), signature);

    EXPECT_NE(0, verify_ret) << "Tampered signature should fail verification";
}

TEST_F(TF5IbsE2ETest, IbsSignVerify_DifferentMessages_DifferentSignatures) {
    if (!pkg_available) {
        GTEST_SKIP() << "PKG binaries not available, skipping IBS E2E test";
    }

    const char msg1[] = "Message one";
    const char msg2[] = "Message two";
    uint8_t sig1[TF5_BLS_SIG_LEN], sig2[TF5_BLS_SIG_LEN];

    tf5_tesla_bls_sign(sk_gnb, (const uint8_t*)msg1, strlen(msg1), sig1);
    tf5_tesla_bls_sign(sk_gnb, (const uint8_t*)msg2, strlen(msg2), sig2);

    EXPECT_NE(0, memcmp(sig1, sig2, TF5_BLS_SIG_LEN))
        << "Different messages should produce different signatures";

    // Both should verify with correct parameters
    EXPECT_EQ(0, tf5_tesla_ibs_verify(mpk, cell_id, validity_end,
                                       (const uint8_t*)msg1, strlen(msg1), sig1));
    EXPECT_EQ(0, tf5_tesla_ibs_verify(mpk, cell_id, validity_end,
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
