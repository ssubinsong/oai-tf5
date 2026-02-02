/**
 * @file test_tf5_ibs_pkg.cpp
 * @brief Unit tests for TF5 IBS PKG (Private Key Generator)
 *
 * Tests for:
 * - tf5_ibs_hash_to_scalar(): Hash identity to scalar
 * - tf5_ibs_parse_cell_id_hex(): Parse hex Cell ID
 * - tf5_ibs_format_cell_id_hex(): Format Cell ID as hex
 * - tf5_ibs_load_master_secret(): Load MSK from file
 * - tf5_ibs_load_master_public(): Load MPK from file
 * - tf5_ibs_compute_gnb_secret(): Compute sk_ID
 * - tf5_ibs_generate_master_keypair(): Generate master keypair
 * - tf5_ibs_issue_gnb_key(): Issue gNB key to file
 * - Validity period conversion utilities
 */

#include <gtest/gtest.h>
#include <cstring>
#include <cstdio>
#include <fstream>
#include <filesystem>
#include <sys/stat.h>

extern "C" {
#include "tf5_ibs_pkg.h"
}

class TF5IbsPkgTest : public ::testing::Test {
protected:
    std::string test_dir;

    void SetUp() override {
        // Create a temporary directory for test files
        test_dir = "/tmp/tf5_ibs_pkg_test_" + std::to_string(getpid());
        std::filesystem::create_directories(test_dir);
    }

    void TearDown() override {
        // Clean up test files
        std::filesystem::remove_all(test_dir);
    }

    // Helper to create a valid MSK file (32 bytes)
    void CreateMskFile(const std::string& path, uint8_t fill = 0x42) {
        uint8_t msk[TF5_IBS_MASTER_SECRET_LEN];
        memset(msk, fill, TF5_IBS_MASTER_SECRET_LEN);
        msk[0] = 0x01;  // Ensure valid scalar
        std::ofstream file(path, std::ios::binary);
        file.write(reinterpret_cast<char*>(msk), TF5_IBS_MASTER_SECRET_LEN);
        file.close();
    }

    // Helper to create a valid MPK file (96 bytes)
    void CreateMpkFile(const std::string& path) {
        // Just create a file with 96 bytes - actual content doesn't matter for I/O tests
        uint8_t mpk[TF5_IBS_MASTER_PUBLIC_LEN];
        memset(mpk, 0x55, TF5_IBS_MASTER_PUBLIC_LEN);
        std::ofstream file(path, std::ios::binary);
        file.write(reinterpret_cast<char*>(mpk), TF5_IBS_MASTER_PUBLIC_LEN);
        file.close();
    }
};

// ============================================================================
// Hash to Scalar Tests (tf5_ibs_hash_to_scalar)
// ============================================================================

TEST_F(TF5IbsPkgTest, HashToScalar_Deterministic) {
    uint8_t cell_id[TF5_IBS_CELL_ID_LEN] = {0x12, 0x34, 0x56, 0x78, 0x90};
    uint32_t validity = 525600;  // 1 year

    uint8_t scalar1[TF5_IBS_GNB_SECRET_LEN];
    uint8_t scalar2[TF5_IBS_GNB_SECRET_LEN];

    int rc1 = tf5_ibs_hash_to_scalar(cell_id, TF5_IBS_CELL_ID_LEN, validity, scalar1);
    int rc2 = tf5_ibs_hash_to_scalar(cell_id, TF5_IBS_CELL_ID_LEN, validity, scalar2);

    EXPECT_EQ(0, rc1);
    EXPECT_EQ(0, rc2);
    EXPECT_EQ(0, memcmp(scalar1, scalar2, TF5_IBS_GNB_SECRET_LEN))
        << "Same input should produce same output";
}

TEST_F(TF5IbsPkgTest, HashToScalar_DifferentCellIds) {
    uint8_t cell_id1[TF5_IBS_CELL_ID_LEN] = {0x12, 0x34, 0x56, 0x78, 0x90};
    uint8_t cell_id2[TF5_IBS_CELL_ID_LEN] = {0x12, 0x34, 0x56, 0x78, 0xA0};
    uint32_t validity = 525600;

    uint8_t scalar1[TF5_IBS_GNB_SECRET_LEN];
    uint8_t scalar2[TF5_IBS_GNB_SECRET_LEN];

    tf5_ibs_hash_to_scalar(cell_id1, TF5_IBS_CELL_ID_LEN, validity, scalar1);
    tf5_ibs_hash_to_scalar(cell_id2, TF5_IBS_CELL_ID_LEN, validity, scalar2);

    EXPECT_NE(0, memcmp(scalar1, scalar2, TF5_IBS_GNB_SECRET_LEN))
        << "Different Cell IDs should produce different scalars";
}

TEST_F(TF5IbsPkgTest, HashToScalar_DifferentValidity) {
    uint8_t cell_id[TF5_IBS_CELL_ID_LEN] = {0x12, 0x34, 0x56, 0x78, 0x90};
    uint32_t validity1 = 525600;   // 1 year
    uint32_t validity2 = 1051200;  // 2 years

    uint8_t scalar1[TF5_IBS_GNB_SECRET_LEN];
    uint8_t scalar2[TF5_IBS_GNB_SECRET_LEN];

    tf5_ibs_hash_to_scalar(cell_id, TF5_IBS_CELL_ID_LEN, validity1, scalar1);
    tf5_ibs_hash_to_scalar(cell_id, TF5_IBS_CELL_ID_LEN, validity2, scalar2);

    EXPECT_NE(0, memcmp(scalar1, scalar2, TF5_IBS_GNB_SECRET_LEN))
        << "Different validity should produce different scalars";
}

TEST_F(TF5IbsPkgTest, HashToScalar_NullInput) {
    uint8_t scalar[TF5_IBS_GNB_SECRET_LEN];
    uint8_t cell_id[TF5_IBS_CELL_ID_LEN] = {0};

    EXPECT_EQ(-1, tf5_ibs_hash_to_scalar(nullptr, TF5_IBS_CELL_ID_LEN, 0, scalar));
    EXPECT_EQ(-1, tf5_ibs_hash_to_scalar(cell_id, TF5_IBS_CELL_ID_LEN, 0, nullptr));
    EXPECT_EQ(-1, tf5_ibs_hash_to_scalar(cell_id, 0, 0, scalar));
}

// ============================================================================
// Cell ID Parsing Tests (tf5_ibs_parse_cell_id_hex)
// ============================================================================

TEST_F(TF5IbsPkgTest, ParseCellIdHex_Valid) {
    uint8_t cell_id[TF5_IBS_CELL_ID_LEN];
    int rc = tf5_ibs_parse_cell_id_hex("123456789", cell_id);
    EXPECT_EQ(0, rc);

    // Verify encoding: 0x123456789 = 36 bits
    // byte[0] = 0x12, byte[1] = 0x34, byte[2] = 0x56, byte[3] = 0x78, byte[4] = 0x90
    EXPECT_EQ(0x12, cell_id[0]);
    EXPECT_EQ(0x34, cell_id[1]);
    EXPECT_EQ(0x56, cell_id[2]);
    EXPECT_EQ(0x78, cell_id[3]);
    EXPECT_EQ(0x90, cell_id[4]);
}

TEST_F(TF5IbsPkgTest, ParseCellIdHex_UpperCase) {
    uint8_t cell_id[TF5_IBS_CELL_ID_LEN];
    int rc = tf5_ibs_parse_cell_id_hex("ABCDEF012", cell_id);
    EXPECT_EQ(0, rc);
}

TEST_F(TF5IbsPkgTest, ParseCellIdHex_MixedCase) {
    uint8_t cell_id[TF5_IBS_CELL_ID_LEN];
    int rc = tf5_ibs_parse_cell_id_hex("AbCdEf012", cell_id);
    EXPECT_EQ(0, rc);
}

TEST_F(TF5IbsPkgTest, ParseCellIdHex_TooShort) {
    uint8_t cell_id[TF5_IBS_CELL_ID_LEN];
    int rc = tf5_ibs_parse_cell_id_hex("12345678", cell_id);  // 8 chars instead of 9
    EXPECT_EQ(-2, rc);
}

TEST_F(TF5IbsPkgTest, ParseCellIdHex_TooLong) {
    uint8_t cell_id[TF5_IBS_CELL_ID_LEN];
    int rc = tf5_ibs_parse_cell_id_hex("1234567890", cell_id);  // 10 chars instead of 9
    EXPECT_EQ(-2, rc);
}

TEST_F(TF5IbsPkgTest, ParseCellIdHex_InvalidChars) {
    uint8_t cell_id[TF5_IBS_CELL_ID_LEN];
    int rc = tf5_ibs_parse_cell_id_hex("12345678G", cell_id);  // G is not hex
    EXPECT_EQ(-3, rc);
}

TEST_F(TF5IbsPkgTest, ParseCellIdHex_NullInput) {
    uint8_t cell_id[TF5_IBS_CELL_ID_LEN];
    EXPECT_EQ(-1, tf5_ibs_parse_cell_id_hex(nullptr, cell_id));
    EXPECT_EQ(-1, tf5_ibs_parse_cell_id_hex("123456789", nullptr));
}

// ============================================================================
// Cell ID Formatting Tests (tf5_ibs_format_cell_id_hex)
// ============================================================================

TEST_F(TF5IbsPkgTest, FormatCellIdHex_Valid) {
    uint8_t cell_id[TF5_IBS_CELL_ID_LEN] = {0x12, 0x34, 0x56, 0x78, 0x90};
    char hex_str[10];

    int rc = tf5_ibs_format_cell_id_hex(cell_id, hex_str);
    EXPECT_EQ(0, rc);
    EXPECT_STREQ("123456789", hex_str);
}

TEST_F(TF5IbsPkgTest, FormatCellIdHex_RoundTrip) {
    const char *original = "abcdef012";
    uint8_t cell_id[TF5_IBS_CELL_ID_LEN];
    char formatted[10];

    int rc1 = tf5_ibs_parse_cell_id_hex(original, cell_id);
    int rc2 = tf5_ibs_format_cell_id_hex(cell_id, formatted);

    EXPECT_EQ(0, rc1);
    EXPECT_EQ(0, rc2);
    EXPECT_STREQ(original, formatted);
}

TEST_F(TF5IbsPkgTest, FormatCellIdHex_NullInput) {
    uint8_t cell_id[TF5_IBS_CELL_ID_LEN] = {0};
    char hex_str[10];
    EXPECT_EQ(-1, tf5_ibs_format_cell_id_hex(nullptr, hex_str));
    EXPECT_EQ(-1, tf5_ibs_format_cell_id_hex(cell_id, nullptr));
}

// ============================================================================
// Load Master Secret Tests (tf5_ibs_load_master_secret)
// ============================================================================

TEST_F(TF5IbsPkgTest, LoadMasterSecret_Success) {
    std::string msk_path = test_dir + "/msk.bin";
    CreateMskFile(msk_path);

    uint8_t msk_out[TF5_IBS_MASTER_SECRET_LEN];
    int rc = tf5_ibs_load_master_secret(msk_path.c_str(), msk_out);

    EXPECT_EQ(0, rc);
    EXPECT_EQ(0x01, msk_out[0]);  // First byte set in CreateMskFile
}

TEST_F(TF5IbsPkgTest, LoadMasterSecret_FileNotFound) {
    uint8_t msk_out[TF5_IBS_MASTER_SECRET_LEN];
    int rc = tf5_ibs_load_master_secret("/nonexistent/path/msk.bin", msk_out);
    EXPECT_EQ(-2, rc);
}

TEST_F(TF5IbsPkgTest, LoadMasterSecret_WrongSize) {
    std::string msk_path = test_dir + "/small_msk.bin";
    std::ofstream file(msk_path, std::ios::binary);
    uint8_t data[16] = {0};  // Too small
    file.write(reinterpret_cast<char*>(data), 16);
    file.close();

    uint8_t msk_out[TF5_IBS_MASTER_SECRET_LEN];
    int rc = tf5_ibs_load_master_secret(msk_path.c_str(), msk_out);
    EXPECT_EQ(-3, rc);
}

TEST_F(TF5IbsPkgTest, LoadMasterSecret_NullInput) {
    uint8_t msk_out[TF5_IBS_MASTER_SECRET_LEN];
    EXPECT_EQ(-1, tf5_ibs_load_master_secret(nullptr, msk_out));

    std::string path = test_dir + "/test.bin";
    EXPECT_EQ(-1, tf5_ibs_load_master_secret(path.c_str(), nullptr));
}

// ============================================================================
// Load Master Public Tests (tf5_ibs_load_master_public)
// ============================================================================

TEST_F(TF5IbsPkgTest, LoadMasterPublic_Success) {
    std::string mpk_path = test_dir + "/mpk.bin";
    CreateMpkFile(mpk_path);

    uint8_t mpk_out[TF5_IBS_MASTER_PUBLIC_LEN];
    int rc = tf5_ibs_load_master_public(mpk_path.c_str(), mpk_out);

    EXPECT_EQ(0, rc);
}

TEST_F(TF5IbsPkgTest, LoadMasterPublic_FileNotFound) {
    uint8_t mpk_out[TF5_IBS_MASTER_PUBLIC_LEN];
    int rc = tf5_ibs_load_master_public("/nonexistent/path/mpk.bin", mpk_out);
    EXPECT_EQ(-2, rc);
}

TEST_F(TF5IbsPkgTest, LoadMasterPublic_WrongSize) {
    std::string mpk_path = test_dir + "/small_mpk.bin";
    std::ofstream file(mpk_path, std::ios::binary);
    uint8_t data[48] = {0};  // Too small (should be 96)
    file.write(reinterpret_cast<char*>(data), 48);
    file.close();

    uint8_t mpk_out[TF5_IBS_MASTER_PUBLIC_LEN];
    int rc = tf5_ibs_load_master_public(mpk_path.c_str(), mpk_out);
    EXPECT_EQ(-3, rc);
}

// ============================================================================
// Compute gNB Secret Tests (tf5_ibs_compute_gnb_secret)
// ============================================================================

TEST_F(TF5IbsPkgTest, ComputeGnbSecret_Success) {
    uint8_t msk[TF5_IBS_MASTER_SECRET_LEN];
    memset(msk, 0x42, TF5_IBS_MASTER_SECRET_LEN);
    msk[0] = 0x01;  // Ensure valid scalar

    uint8_t cell_id[TF5_IBS_CELL_ID_LEN] = {0x12, 0x34, 0x56, 0x78, 0x90};
    uint32_t validity = 525600;

    uint8_t sk_out[TF5_IBS_GNB_SECRET_LEN];
    int rc = tf5_ibs_compute_gnb_secret(msk, cell_id, validity, sk_out);

    EXPECT_EQ(0, rc);
    // Verify output is not all zeros
    bool all_zeros = true;
    for (int i = 0; i < TF5_IBS_GNB_SECRET_LEN; i++) {
        if (sk_out[i] != 0) {
            all_zeros = false;
            break;
        }
    }
    EXPECT_FALSE(all_zeros) << "Output should not be all zeros";
}

TEST_F(TF5IbsPkgTest, ComputeGnbSecret_Deterministic) {
    uint8_t msk[TF5_IBS_MASTER_SECRET_LEN];
    memset(msk, 0x42, TF5_IBS_MASTER_SECRET_LEN);
    msk[0] = 0x01;

    uint8_t cell_id[TF5_IBS_CELL_ID_LEN] = {0x12, 0x34, 0x56, 0x78, 0x90};
    uint32_t validity = 525600;

    uint8_t sk1[TF5_IBS_GNB_SECRET_LEN];
    uint8_t sk2[TF5_IBS_GNB_SECRET_LEN];

    tf5_ibs_compute_gnb_secret(msk, cell_id, validity, sk1);
    tf5_ibs_compute_gnb_secret(msk, cell_id, validity, sk2);

    EXPECT_EQ(0, memcmp(sk1, sk2, TF5_IBS_GNB_SECRET_LEN))
        << "Same inputs should produce same output";
}

TEST_F(TF5IbsPkgTest, ComputeGnbSecret_DifferentMsk) {
    uint8_t msk1[TF5_IBS_MASTER_SECRET_LEN];
    uint8_t msk2[TF5_IBS_MASTER_SECRET_LEN];
    memset(msk1, 0x42, TF5_IBS_MASTER_SECRET_LEN);
    memset(msk2, 0x43, TF5_IBS_MASTER_SECRET_LEN);
    msk1[0] = 0x01;
    msk2[0] = 0x01;

    uint8_t cell_id[TF5_IBS_CELL_ID_LEN] = {0x12, 0x34, 0x56, 0x78, 0x90};
    uint32_t validity = 525600;

    uint8_t sk1[TF5_IBS_GNB_SECRET_LEN];
    uint8_t sk2[TF5_IBS_GNB_SECRET_LEN];

    tf5_ibs_compute_gnb_secret(msk1, cell_id, validity, sk1);
    tf5_ibs_compute_gnb_secret(msk2, cell_id, validity, sk2);

    EXPECT_NE(0, memcmp(sk1, sk2, TF5_IBS_GNB_SECRET_LEN))
        << "Different MSK should produce different sk_ID";
}

TEST_F(TF5IbsPkgTest, ComputeGnbSecret_NullInput) {
    uint8_t msk[TF5_IBS_MASTER_SECRET_LEN] = {0};
    uint8_t cell_id[TF5_IBS_CELL_ID_LEN] = {0};
    uint8_t sk_out[TF5_IBS_GNB_SECRET_LEN];

    EXPECT_EQ(-1, tf5_ibs_compute_gnb_secret(nullptr, cell_id, 0, sk_out));
    EXPECT_EQ(-1, tf5_ibs_compute_gnb_secret(msk, nullptr, 0, sk_out));
    EXPECT_EQ(-1, tf5_ibs_compute_gnb_secret(msk, cell_id, 0, nullptr));
}

// ============================================================================
// Master Keypair Generation Tests (tf5_ibs_generate_master_keypair)
// ============================================================================

TEST_F(TF5IbsPkgTest, GenerateMasterKeypair_CreatesFiles) {
    std::string msk_path = test_dir + "/gen_msk.bin";
    std::string mpk_path = test_dir + "/gen_mpk.bin";

    int rc = tf5_ibs_generate_master_keypair(msk_path.c_str(), mpk_path.c_str());
    EXPECT_EQ(0, rc);

    // Verify files exist
    EXPECT_TRUE(std::filesystem::exists(msk_path)) << "MSK file should exist";
    EXPECT_TRUE(std::filesystem::exists(mpk_path)) << "MPK file should exist";

    // Verify file sizes
    EXPECT_EQ(TF5_IBS_MASTER_SECRET_LEN, std::filesystem::file_size(msk_path))
        << "MSK should be 32 bytes";
    EXPECT_EQ(TF5_IBS_MASTER_PUBLIC_LEN, std::filesystem::file_size(mpk_path))
        << "MPK should be 96 bytes";
}

TEST_F(TF5IbsPkgTest, GenerateMasterKeypair_CorrectPermissions) {
    std::string msk_path = test_dir + "/gen_msk.bin";
    std::string mpk_path = test_dir + "/gen_mpk.bin";

    tf5_ibs_generate_master_keypair(msk_path.c_str(), mpk_path.c_str());

    struct stat msk_stat, mpk_stat;
    stat(msk_path.c_str(), &msk_stat);
    stat(mpk_path.c_str(), &mpk_stat);

    // MSK should be 0600 (owner read/write only)
    EXPECT_EQ(0600, msk_stat.st_mode & 0777) << "MSK should have restricted permissions";
    // MPK should be 0644 (public readable)
    EXPECT_EQ(0644, mpk_stat.st_mode & 0777) << "MPK should be public readable";
}

TEST_F(TF5IbsPkgTest, GenerateMasterKeypair_DifferentEachTime) {
    std::string msk_path1 = test_dir + "/gen_msk1.bin";
    std::string mpk_path1 = test_dir + "/gen_mpk1.bin";
    std::string msk_path2 = test_dir + "/gen_msk2.bin";
    std::string mpk_path2 = test_dir + "/gen_mpk2.bin";

    tf5_ibs_generate_master_keypair(msk_path1.c_str(), mpk_path1.c_str());
    tf5_ibs_generate_master_keypair(msk_path2.c_str(), mpk_path2.c_str());

    // Read both MSKs
    uint8_t msk1[TF5_IBS_MASTER_SECRET_LEN];
    uint8_t msk2[TF5_IBS_MASTER_SECRET_LEN];
    tf5_ibs_load_master_secret(msk_path1.c_str(), msk1);
    tf5_ibs_load_master_secret(msk_path2.c_str(), msk2);

    EXPECT_NE(0, memcmp(msk1, msk2, TF5_IBS_MASTER_SECRET_LEN))
        << "Each keypair generation should produce different keys";
}

TEST_F(TF5IbsPkgTest, GenerateMasterKeypair_NullInput) {
    std::string valid_path = test_dir + "/test.bin";
    EXPECT_EQ(-1, tf5_ibs_generate_master_keypair(nullptr, valid_path.c_str()));
    EXPECT_EQ(-1, tf5_ibs_generate_master_keypair(valid_path.c_str(), nullptr));
}

// ============================================================================
// gNB Key Issuance Tests (tf5_ibs_issue_gnb_key)
// ============================================================================

TEST_F(TF5IbsPkgTest, IssueGnbKey_Creates35ByteFile) {
    // First generate a master keypair
    std::string msk_path = test_dir + "/msk.bin";
    std::string mpk_path = test_dir + "/mpk.bin";
    tf5_ibs_generate_master_keypair(msk_path.c_str(), mpk_path.c_str());

    // Issue gNB key
    std::string sk_path = test_dir + "/sk_gnb.bin";
    uint8_t cell_id[TF5_IBS_CELL_ID_LEN] = {0x12, 0x34, 0x56, 0x78, 0x90};
    uint32_t validity = 525600;

    int rc = tf5_ibs_issue_gnb_key(msk_path.c_str(), cell_id, validity, sk_path.c_str());
    EXPECT_EQ(0, rc);

    // Verify file size is 35 bytes (32 sk + 3 validity)
    EXPECT_EQ(TF5_IBS_SK_FILE_SIZE, std::filesystem::file_size(sk_path))
        << "gNB key file should be 35 bytes";
}

TEST_F(TF5IbsPkgTest, IssueGnbKey_ValidityEncoding) {
    // Generate master keypair
    std::string msk_path = test_dir + "/msk.bin";
    std::string mpk_path = test_dir + "/mpk.bin";
    tf5_ibs_generate_master_keypair(msk_path.c_str(), mpk_path.c_str());

    // Issue key with specific validity
    std::string sk_path = test_dir + "/sk_gnb.bin";
    uint8_t cell_id[TF5_IBS_CELL_ID_LEN] = {0x12, 0x34, 0x56, 0x78, 0x90};
    uint32_t validity = 0x123456;  // Known test value

    tf5_ibs_issue_gnb_key(msk_path.c_str(), cell_id, validity, sk_path.c_str());

    // Read the file and check validity bytes
    std::ifstream file(sk_path, std::ios::binary);
    uint8_t data[TF5_IBS_SK_FILE_SIZE];
    file.read(reinterpret_cast<char*>(data), TF5_IBS_SK_FILE_SIZE);
    file.close();

    // Last 3 bytes should be big-endian validity
    EXPECT_EQ(0x12, data[32]) << "Validity byte 0 (MSB)";
    EXPECT_EQ(0x34, data[33]) << "Validity byte 1";
    EXPECT_EQ(0x56, data[34]) << "Validity byte 2 (LSB)";
}

TEST_F(TF5IbsPkgTest, IssueGnbKey_DifferentCellIds) {
    // Generate master keypair
    std::string msk_path = test_dir + "/msk.bin";
    std::string mpk_path = test_dir + "/mpk.bin";
    tf5_ibs_generate_master_keypair(msk_path.c_str(), mpk_path.c_str());

    uint8_t cell_id1[TF5_IBS_CELL_ID_LEN] = {0x12, 0x34, 0x56, 0x78, 0x90};
    uint8_t cell_id2[TF5_IBS_CELL_ID_LEN] = {0x12, 0x34, 0x56, 0x78, 0xA0};
    uint32_t validity = 525600;

    std::string sk_path1 = test_dir + "/sk1.bin";
    std::string sk_path2 = test_dir + "/sk2.bin";

    tf5_ibs_issue_gnb_key(msk_path.c_str(), cell_id1, validity, sk_path1.c_str());
    tf5_ibs_issue_gnb_key(msk_path.c_str(), cell_id2, validity, sk_path2.c_str());

    // Read both keys
    uint8_t sk1[TF5_IBS_SK_FILE_SIZE];
    uint8_t sk2[TF5_IBS_SK_FILE_SIZE];
    std::ifstream f1(sk_path1, std::ios::binary);
    std::ifstream f2(sk_path2, std::ios::binary);
    f1.read(reinterpret_cast<char*>(sk1), TF5_IBS_SK_FILE_SIZE);
    f2.read(reinterpret_cast<char*>(sk2), TF5_IBS_SK_FILE_SIZE);

    EXPECT_NE(0, memcmp(sk1, sk2, TF5_IBS_GNB_SECRET_LEN))
        << "Different Cell IDs should produce different secret keys";
}

TEST_F(TF5IbsPkgTest, IssueGnbKey_MskNotFound) {
    uint8_t cell_id[TF5_IBS_CELL_ID_LEN] = {0x12, 0x34, 0x56, 0x78, 0x90};
    std::string sk_path = test_dir + "/sk.bin";

    int rc = tf5_ibs_issue_gnb_key("/nonexistent/msk.bin", cell_id, 525600, sk_path.c_str());
    EXPECT_EQ(-2, rc);
}

// ============================================================================
// Validity Period Conversion Tests
// ============================================================================

TEST_F(TF5IbsPkgTest, ValidityConversion_RoundTrip) {
    // Test round-trip conversion
    uint64_t original_unix = 1735689600;  // 2025-01-01 00:00:00 UTC

    uint32_t validity = tf5_ibs_unix_to_gnb_key_validity(original_unix);
    uint64_t recovered_unix = tf5_ibs_gnb_key_validity_to_unix(validity);

    // Should be within 1 minute (60 seconds) due to minute granularity
    EXPECT_LE(std::abs((int64_t)(recovered_unix - original_unix)), 60)
        << "Round-trip should preserve timestamp within minute granularity";
}

TEST_F(TF5IbsPkgTest, ValidityConversion_Epoch) {
    // At epoch (2024-01-01 00:00:00 UTC), validity should be 0
    uint32_t validity = tf5_ibs_unix_to_gnb_key_validity(TF5_VALIDITY_EPOCH);
    EXPECT_EQ(0, validity);
}

TEST_F(TF5IbsPkgTest, ValidityConversion_BeforeEpoch) {
    // Before epoch should return 0
    uint32_t validity = tf5_ibs_unix_to_gnb_key_validity(TF5_VALIDITY_EPOCH - 1000);
    EXPECT_EQ(0, validity);
}

TEST_F(TF5IbsPkgTest, ValidityConversion_OneYear) {
    // 1 year = 525600 minutes
    uint64_t one_year_after = TF5_VALIDITY_EPOCH + (525600UL * 60);
    uint32_t validity = tf5_ibs_unix_to_gnb_key_validity(one_year_after);
    EXPECT_EQ(525600, validity);
}

// ============================================================================
// End-to-End Tests
// ============================================================================

TEST_F(TF5IbsPkgTest, EndToEnd_KeypairAndIssuance) {
    // Generate master keypair
    std::string msk_path = test_dir + "/msk.bin";
    std::string mpk_path = test_dir + "/mpk.bin";
    ASSERT_EQ(0, tf5_ibs_generate_master_keypair(msk_path.c_str(), mpk_path.c_str()));

    // Issue gNB key
    std::string sk_path = test_dir + "/sk_gnb.bin";
    uint8_t cell_id[TF5_IBS_CELL_ID_LEN];
    ASSERT_EQ(0, tf5_ibs_parse_cell_id_hex("123456789", cell_id));
    uint32_t validity = 1051200;  // 2 years

    ASSERT_EQ(0, tf5_ibs_issue_gnb_key(msk_path.c_str(), cell_id, validity, sk_path.c_str()));

    // Load the issued key and verify validity
    std::ifstream file(sk_path, std::ios::binary);
    uint8_t data[TF5_IBS_SK_FILE_SIZE];
    file.read(reinterpret_cast<char*>(data), TF5_IBS_SK_FILE_SIZE);
    file.close();

    // Verify validity encoding
    uint32_t read_validity = ((uint32_t)data[32] << 16) |
                             ((uint32_t)data[33] << 8) |
                             (uint32_t)data[34];
    EXPECT_EQ(validity, read_validity);

    // Verify sk_ID matches what we'd compute directly
    uint8_t msk[TF5_IBS_MASTER_SECRET_LEN];
    ASSERT_EQ(0, tf5_ibs_load_master_secret(msk_path.c_str(), msk));

    uint8_t expected_sk[TF5_IBS_GNB_SECRET_LEN];
    ASSERT_EQ(0, tf5_ibs_compute_gnb_secret(msk, cell_id, validity, expected_sk));

    EXPECT_EQ(0, memcmp(data, expected_sk, TF5_IBS_GNB_SECRET_LEN))
        << "Issued key should match directly computed key";
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char **argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
