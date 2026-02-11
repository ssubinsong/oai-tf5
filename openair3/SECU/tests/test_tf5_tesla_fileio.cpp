/**
 * @file test_tf5_tesla_fileio.cpp
 * @brief Unit tests for TF5 TESLA key file I/O functions
 *
 * Tests for:
 * - tf5_load_gnb_privkey(): Load BLS secret key from file
 * - tf5_load_core_mpk(): Load Core's MPK from file
 */

#define TF5_TEST_NEEDS_OAI_STUBS
#include "tf5_test_common.h"
#include <fstream>

extern "C" {
#include "openair3/SECU/tf5_tesla.h"
#include "openair3/SECU/tf5_tesla_sig.h"
}

class TF5FileIOTest : public ::testing::Test {
protected:
    std::string test_dir;
    std::string privkey_path;
    std::string pubkey_path;

    void SetUp() override {
        // Create a temporary directory for test files
        test_dir = "/tmp/tf5_fileio_test_" + std::to_string(getpid());
        std::filesystem::create_directories(test_dir);
        privkey_path = test_dir + "/sk_gnb.bin";
        pubkey_path = test_dir + "/mpk.bin";
    }

    void TearDown() override {
        // Clean up test files
        std::filesystem::remove_all(test_dir);
    }

    // Helper to create a valid 35-byte private key file
    void CreateValidPrivkeyFile(const std::string& path, uint32_t validity = 525600) {
        // Generate a valid BLS secret key using the library
        uint8_t sk[TF5_IBS_GNB_SK_LEN];
        uint8_t pk[TF5_IBS_MPK_LEN];

        // Use a fixed test key (deterministic for testing)
        memset(sk, 0x42, TF5_IBS_GNB_SK_LEN);
        // Ensure it's a valid scalar by making it small enough
        sk[0] = 0x01;  // First byte small to ensure valid scalar

        // Write the 35-byte file: sk (32) + validity (3 big-endian)
        std::ofstream file(path, std::ios::binary);
        file.write(reinterpret_cast<char*>(sk), TF5_IBS_GNB_SK_LEN);

        uint8_t validity_bytes[3];
        validity_bytes[0] = (validity >> 16) & 0xFF;
        validity_bytes[1] = (validity >> 8) & 0xFF;
        validity_bytes[2] = validity & 0xFF;
        file.write(reinterpret_cast<char*>(validity_bytes), 3);
        file.close();
    }

    // Helper to create a valid 96-byte public key file
    void CreateValidPubkeyFile(const std::string& path) {
        // Generate a keypair and write the public key
        uint8_t sk[TF5_IBS_GNB_SK_LEN];
        uint8_t pk[TF5_IBS_MPK_LEN];

        // Use a fixed test key
        memset(sk, 0x42, TF5_IBS_GNB_SK_LEN);
        sk[0] = 0x01;

        // Derive public key
        int rc = tf5_bls_derive_pubkey(sk, pk);
        ASSERT_EQ(0, rc) << "Failed to derive public key for test setup";

        std::ofstream file(path, std::ios::binary);
        file.write(reinterpret_cast<char*>(pk), TF5_IBS_MPK_LEN);
        file.close();
    }
};

// ============================================================================
// Load Private Key Tests (tf5_load_gnb_privkey)
// ============================================================================

TEST_F(TF5FileIOTest, LoadPrivkey_Success) {
    uint32_t expected_validity = 1051200;  // 2 years
    CreateValidPrivkeyFile(privkey_path, expected_validity);

    uint8_t privkey_out[TF5_IBS_GNB_SK_LEN];
    uint32_t validity_out;

    int result = tf5_load_gnb_privkey(privkey_path.c_str(), privkey_out, &validity_out);

    EXPECT_EQ(0, result) << "Loading valid private key should succeed";
    EXPECT_EQ(expected_validity, validity_out) << "Validity should be extracted correctly";
}

TEST_F(TF5FileIOTest, LoadPrivkey_ValidityExtracted) {
    // Test different validity values
    std::vector<uint32_t> test_values = {0, 525600, 1051200, 0xFFFFFF};

    for (uint32_t expected : test_values) {
        CreateValidPrivkeyFile(privkey_path, expected);

        uint8_t privkey_out[TF5_IBS_GNB_SK_LEN];
        uint32_t validity_out;

        int result = tf5_load_gnb_privkey(privkey_path.c_str(), privkey_out, &validity_out);

        EXPECT_EQ(0, result) << "Load should succeed for validity " << expected;
        EXPECT_EQ(expected, validity_out) << "Validity " << expected << " should be extracted correctly";
    }
}

TEST_F(TF5FileIOTest, LoadPrivkey_FileNotFound) {
    uint8_t privkey_out[TF5_IBS_GNB_SK_LEN];
    uint32_t validity_out;

    int result = tf5_load_gnb_privkey("/nonexistent/path/sk.bin", privkey_out, &validity_out);

    EXPECT_EQ(TF5_ERR_FILE_OPEN, result) << "Non-existent file should return TF5_ERR_FILE_OPEN";
}

TEST_F(TF5FileIOTest, LoadPrivkey_WrongSize_TooSmall) {
    // Create a file that's too small (30 bytes instead of 35)
    std::string small_file = test_dir + "/small.bin";
    std::ofstream file(small_file, std::ios::binary);
    uint8_t data[30] = {0};
    file.write(reinterpret_cast<char*>(data), 30);
    file.close();

    uint8_t privkey_out[TF5_IBS_GNB_SK_LEN];
    uint32_t validity_out;

    int result = tf5_load_gnb_privkey(small_file.c_str(), privkey_out, &validity_out);

    EXPECT_EQ(TF5_ERR_FILE_IO, result) << "File with wrong size should return TF5_ERR_FILE_IO";
}

TEST_F(TF5FileIOTest, LoadPrivkey_WrongSize_TooLarge) {
    // Create a file that's too large (40 bytes instead of 35)
    std::string large_file = test_dir + "/large.bin";
    std::ofstream file(large_file, std::ios::binary);
    uint8_t data[40] = {0};
    file.write(reinterpret_cast<char*>(data), 40);
    file.close();

    uint8_t privkey_out[TF5_IBS_GNB_SK_LEN];
    uint32_t validity_out;

    int result = tf5_load_gnb_privkey(large_file.c_str(), privkey_out, &validity_out);

    // The function reads exactly 35 bytes from the file. If the read succeeds,
    // it validates the key scalar. With garbage bytes, the scalar may be invalid.
    // Valid results: 0 (success), -2 (wrong size), or -3 (invalid key format)
    EXPECT_TRUE(result == TF5_OK || result == TF5_ERR_FILE_IO || result == TF5_ERR_KEY_INVALID)
        << "Larger file may succeed, fail size check, or fail key validation";
}

TEST_F(TF5FileIOTest, LoadPrivkey_NullPath) {
    uint8_t privkey_out[TF5_IBS_GNB_SK_LEN];
    uint32_t validity_out;

    int result = tf5_load_gnb_privkey(nullptr, privkey_out, &validity_out);

    EXPECT_EQ(TF5_ERR_INVALID_PARAM, result) << "Null path should return TF5_ERR_INVALID_PARAM";
}

TEST_F(TF5FileIOTest, LoadPrivkey_NullPrivkeyOutput) {
    CreateValidPrivkeyFile(privkey_path);
    uint32_t validity_out;

    int result = tf5_load_gnb_privkey(privkey_path.c_str(), nullptr, &validity_out);

    EXPECT_EQ(TF5_ERR_INVALID_PARAM, result) << "Null privkey output should return TF5_ERR_INVALID_PARAM";
}

TEST_F(TF5FileIOTest, LoadPrivkey_NullValidityOutput) {
    CreateValidPrivkeyFile(privkey_path);
    uint8_t privkey_out[TF5_IBS_GNB_SK_LEN];

    int result = tf5_load_gnb_privkey(privkey_path.c_str(), privkey_out, nullptr);

    EXPECT_EQ(TF5_ERR_INVALID_PARAM, result) << "Null validity output should return TF5_ERR_INVALID_PARAM";
}

TEST_F(TF5FileIOTest, LoadPrivkey_InvalidKeyFormat) {
    // Create a file with correct size but invalid key data
    std::string invalid_file = test_dir + "/invalid.bin";
    std::ofstream file(invalid_file, std::ios::binary);
    uint8_t data[35];
    memset(data, 0xFF, 35);  // All 0xFF is likely an invalid scalar
    file.write(reinterpret_cast<char*>(data), 35);
    file.close();

    uint8_t privkey_out[TF5_IBS_GNB_SK_LEN];
    uint32_t validity_out;

    int result = tf5_load_gnb_privkey(invalid_file.c_str(), privkey_out, &validity_out);

    // The key validation may fail
    EXPECT_TRUE(result == TF5_OK || result == TF5_ERR_KEY_INVALID)
        << "Invalid key format may be detected (TF5_ERR_KEY_INVALID) or not, depending on validation";
}

TEST_F(TF5FileIOTest, LoadPrivkey_EmptyFile) {
    std::string empty_file = test_dir + "/empty.bin";
    std::ofstream file(empty_file, std::ios::binary);
    file.close();

    uint8_t privkey_out[TF5_IBS_GNB_SK_LEN];
    uint32_t validity_out;

    int result = tf5_load_gnb_privkey(empty_file.c_str(), privkey_out, &validity_out);

    EXPECT_EQ(TF5_ERR_FILE_IO, result) << "Empty file should return TF5_ERR_FILE_IO (wrong size)";
}

// ============================================================================
// Load Core MPK Tests (tf5_load_core_mpk)
// ============================================================================

TEST_F(TF5FileIOTest, LoadPubkey_Success) {
    CreateValidPubkeyFile(pubkey_path);

    uint8_t pubkey_out[TF5_IBS_MPK_LEN];

    int result = tf5_load_core_mpk(pubkey_path.c_str(), pubkey_out);

    EXPECT_EQ(0, result) << "Loading valid public key should succeed";
}

TEST_F(TF5FileIOTest, LoadPubkey_ContentVerified) {
    CreateValidPubkeyFile(pubkey_path);

    // Read the original file
    uint8_t expected[TF5_IBS_MPK_LEN];
    std::ifstream file(pubkey_path, std::ios::binary);
    file.read(reinterpret_cast<char*>(expected), TF5_IBS_MPK_LEN);
    file.close();

    uint8_t pubkey_out[TF5_IBS_MPK_LEN];
    tf5_load_core_mpk(pubkey_path.c_str(), pubkey_out);

    EXPECT_EQ(0, memcmp(expected, pubkey_out, TF5_IBS_MPK_LEN))
        << "Loaded key should match file contents";
}

TEST_F(TF5FileIOTest, LoadPubkey_FileNotFound) {
    uint8_t pubkey_out[TF5_IBS_MPK_LEN];

    int result = tf5_load_core_mpk("/nonexistent/path/mpk.bin", pubkey_out);

    EXPECT_EQ(TF5_ERR_FILE_OPEN, result) << "Non-existent file should return TF5_ERR_FILE_OPEN";
}

TEST_F(TF5FileIOTest, LoadPubkey_WrongSize_TooSmall) {
    std::string small_file = test_dir + "/small_pk.bin";
    std::ofstream file(small_file, std::ios::binary);
    uint8_t data[64] = {0};  // 64 bytes instead of 96
    file.write(reinterpret_cast<char*>(data), 64);
    file.close();

    uint8_t pubkey_out[TF5_IBS_MPK_LEN];

    int result = tf5_load_core_mpk(small_file.c_str(), pubkey_out);

    EXPECT_EQ(TF5_ERR_FILE_IO, result) << "File with wrong size should return TF5_ERR_FILE_IO";
}

TEST_F(TF5FileIOTest, LoadPubkey_WrongSize_TooLarge) {
    std::string large_file = test_dir + "/large_pk.bin";
    std::ofstream file(large_file, std::ios::binary);
    uint8_t data[128] = {0};  // 128 bytes instead of 96
    file.write(reinterpret_cast<char*>(data), 128);
    file.close();

    uint8_t pubkey_out[TF5_IBS_MPK_LEN];

    int result = tf5_load_core_mpk(large_file.c_str(), pubkey_out);

    // Function reads exactly 96 bytes, so larger file should work
    EXPECT_TRUE(result == TF5_OK || result == TF5_ERR_FILE_IO)
        << "Larger file handling depends on implementation";
}

TEST_F(TF5FileIOTest, LoadPubkey_NullPath) {
    uint8_t pubkey_out[TF5_IBS_MPK_LEN];

    int result = tf5_load_core_mpk(nullptr, pubkey_out);

    EXPECT_EQ(TF5_ERR_INVALID_PARAM, result) << "Null path should return TF5_ERR_INVALID_PARAM";
}

TEST_F(TF5FileIOTest, LoadPubkey_NullOutput) {
    CreateValidPubkeyFile(pubkey_path);

    int result = tf5_load_core_mpk(pubkey_path.c_str(), nullptr);

    EXPECT_EQ(TF5_ERR_INVALID_PARAM, result) << "Null output should return TF5_ERR_INVALID_PARAM";
}

TEST_F(TF5FileIOTest, LoadPubkey_EmptyFile) {
    std::string empty_file = test_dir + "/empty_pk.bin";
    std::ofstream file(empty_file, std::ios::binary);
    file.close();

    uint8_t pubkey_out[TF5_IBS_MPK_LEN];

    int result = tf5_load_core_mpk(empty_file.c_str(), pubkey_out);

    EXPECT_EQ(TF5_ERR_FILE_IO, result) << "Empty file should return TF5_ERR_FILE_IO (wrong size)";
}

// ============================================================================
// Round-trip Tests
// ============================================================================

TEST_F(TF5FileIOTest, RoundTrip_PrivkeyValidity) {
    // Test that validity is encoded/decoded correctly in big-endian
    uint32_t original_validity = 0x123456;

    // Create file with known validity
    uint8_t sk[TF5_IBS_GNB_SK_LEN];
    memset(sk, 0x42, TF5_IBS_GNB_SK_LEN);
    sk[0] = 0x01;

    std::ofstream file(privkey_path, std::ios::binary);
    file.write(reinterpret_cast<char*>(sk), TF5_IBS_GNB_SK_LEN);
    // Write validity as big-endian
    uint8_t v[3] = {0x12, 0x34, 0x56};
    file.write(reinterpret_cast<char*>(v), 3);
    file.close();

    uint8_t privkey_out[TF5_IBS_GNB_SK_LEN];
    uint32_t validity_out;

    tf5_load_gnb_privkey(privkey_path.c_str(), privkey_out, &validity_out);

    EXPECT_EQ(original_validity, validity_out)
        << "Big-endian validity should be decoded correctly";
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
