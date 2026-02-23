/**
 * @file test_tf5_ibs_pkg.cpp
 * @brief Unit tests for TF5 IBS PKG (Private Key Generator)
 *
 * Tests for:
 * - tf5_ibs_hash_identity(): Hash identity to scalar (GG09 Schnorr)
 * - tf5_ibs_parse_cell_id_hex(): Parse hex Cell ID
 * - tf5_ibs_format_cell_id_hex(): Format Cell ID as hex
 * - tf5_ibs_load_master_secret(): Load MSK from file
 * - tf5_ibs_compute_gnb_secret(): Compute sk_id (y[32] + pk[32])
 * - tf5_ibs_generate_master_keypair(): Generate master keypair
 * - tf5_ibs_issue_gnb_key(): Issue gNB key to file
 * - Validity period conversion utilities
 */

#include "tf5_test_common.h"
#include <fstream>

extern "C" {
#include "tf5_ibs_pkg.h"
#include <sodium.h>
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

    // Helper to derive MPK from MSK (Ed25519 seed) for hash_identity tests
    void DeriveMpk(const uint8_t msk[TF5_IBS_MASTER_SECRET_LEN],
                   uint8_t mpk[TF5_IBS_MASTER_PUBLIC_LEN]) {
        uint8_t sk_tmp[crypto_sign_SECRETKEYBYTES];
        crypto_sign_seed_keypair(mpk, sk_tmp, msk);
        sodium_memzero(sk_tmp, sizeof(sk_tmp));
    }
};

// ============================================================================
// Hash Identity Tests (tf5_ibs_hash_identity)
// ============================================================================

TEST_F(TF5IbsPkgTest, HashIdentity_Deterministic) {
    uint8_t cell_id[TF5_IBS_CELL_ID_LEN] = {0x12, 0x34, 0x56, 0x78, 0x90};
    uint32_t validity = 525600;  // 1 year

    // Need pk and mpk for hash_identity
    uint8_t pk[TF5_ED25519_POINT_LEN] = {0};
    pk[0] = 0x01;  // Dummy pk
    uint8_t mpk[TF5_IBS_MASTER_PUBLIC_LEN] = {0};
    mpk[0] = 0x02;  // Dummy mpk

    uint8_t scalar1[TF5_ED25519_SCALAR_LEN];
    uint8_t scalar2[TF5_ED25519_SCALAR_LEN];

    int rc1 = tf5_ibs_hash_identity(cell_id, TF5_IBS_CELL_ID_LEN, validity, pk, mpk, scalar1);
    int rc2 = tf5_ibs_hash_identity(cell_id, TF5_IBS_CELL_ID_LEN, validity, pk, mpk, scalar2);

    EXPECT_EQ(0, rc1);
    EXPECT_EQ(0, rc2);
    EXPECT_EQ(0, memcmp(scalar1, scalar2, TF5_ED25519_SCALAR_LEN))
        << "Same input should produce same output";
}

TEST_F(TF5IbsPkgTest, HashIdentity_DifferentCellIds) {
    uint8_t cell_id1[TF5_IBS_CELL_ID_LEN] = {0x12, 0x34, 0x56, 0x78, 0x90};
    uint8_t cell_id2[TF5_IBS_CELL_ID_LEN] = {0x12, 0x34, 0x56, 0x78, 0xA0};
    uint32_t validity = 525600;

    uint8_t pk[TF5_ED25519_POINT_LEN] = {0};
    pk[0] = 0x01;
    uint8_t mpk[TF5_IBS_MASTER_PUBLIC_LEN] = {0};
    mpk[0] = 0x02;

    uint8_t scalar1[TF5_ED25519_SCALAR_LEN];
    uint8_t scalar2[TF5_ED25519_SCALAR_LEN];

    tf5_ibs_hash_identity(cell_id1, TF5_IBS_CELL_ID_LEN, validity, pk, mpk, scalar1);
    tf5_ibs_hash_identity(cell_id2, TF5_IBS_CELL_ID_LEN, validity, pk, mpk, scalar2);

    EXPECT_NE(0, memcmp(scalar1, scalar2, TF5_ED25519_SCALAR_LEN))
        << "Different Cell IDs should produce different scalars";
}

TEST_F(TF5IbsPkgTest, HashIdentity_DifferentValidity) {
    uint8_t cell_id[TF5_IBS_CELL_ID_LEN] = {0x12, 0x34, 0x56, 0x78, 0x90};
    uint32_t validity1 = 525600;   // 1 year
    uint32_t validity2 = 1051200;  // 2 years

    uint8_t pk[TF5_ED25519_POINT_LEN] = {0};
    pk[0] = 0x01;
    uint8_t mpk[TF5_IBS_MASTER_PUBLIC_LEN] = {0};
    mpk[0] = 0x02;

    uint8_t scalar1[TF5_ED25519_SCALAR_LEN];
    uint8_t scalar2[TF5_ED25519_SCALAR_LEN];

    tf5_ibs_hash_identity(cell_id, TF5_IBS_CELL_ID_LEN, validity1, pk, mpk, scalar1);
    tf5_ibs_hash_identity(cell_id, TF5_IBS_CELL_ID_LEN, validity2, pk, mpk, scalar2);

    EXPECT_NE(0, memcmp(scalar1, scalar2, TF5_ED25519_SCALAR_LEN))
        << "Different validity should produce different scalars";
}

TEST_F(TF5IbsPkgTest, HashIdentity_DifferentPk) {
    uint8_t cell_id[TF5_IBS_CELL_ID_LEN] = {0x12, 0x34, 0x56, 0x78, 0x90};
    uint32_t validity = 525600;

    uint8_t pk1[TF5_ED25519_POINT_LEN] = {0};
    pk1[0] = 0x01;
    uint8_t pk2[TF5_ED25519_POINT_LEN] = {0};
    pk2[0] = 0x03;
    uint8_t mpk[TF5_IBS_MASTER_PUBLIC_LEN] = {0};
    mpk[0] = 0x02;

    uint8_t scalar1[TF5_ED25519_SCALAR_LEN];
    uint8_t scalar2[TF5_ED25519_SCALAR_LEN];

    tf5_ibs_hash_identity(cell_id, TF5_IBS_CELL_ID_LEN, validity, pk1, mpk, scalar1);
    tf5_ibs_hash_identity(cell_id, TF5_IBS_CELL_ID_LEN, validity, pk2, mpk, scalar2);

    EXPECT_NE(0, memcmp(scalar1, scalar2, TF5_ED25519_SCALAR_LEN))
        << "Different pk should produce different scalars";
}

TEST_F(TF5IbsPkgTest, HashIdentity_NullInput) {
    uint8_t scalar[TF5_ED25519_SCALAR_LEN];
    uint8_t cell_id[TF5_IBS_CELL_ID_LEN] = {0};
    uint8_t pk[TF5_ED25519_POINT_LEN] = {0};
    uint8_t mpk[TF5_IBS_MASTER_PUBLIC_LEN] = {0};

    EXPECT_EQ(TF5_ERR_INVALID_PARAM, tf5_ibs_hash_identity(nullptr, TF5_IBS_CELL_ID_LEN, 0, pk, mpk, scalar));
    EXPECT_EQ(TF5_ERR_INVALID_PARAM, tf5_ibs_hash_identity(cell_id, TF5_IBS_CELL_ID_LEN, 0, pk, mpk, nullptr));
    EXPECT_EQ(TF5_ERR_INVALID_PARAM, tf5_ibs_hash_identity(cell_id, 0, 0, pk, mpk, scalar));
    EXPECT_EQ(TF5_ERR_INVALID_PARAM, tf5_ibs_hash_identity(cell_id, TF5_IBS_CELL_ID_LEN, 0, nullptr, mpk, scalar));
    EXPECT_EQ(TF5_ERR_INVALID_PARAM, tf5_ibs_hash_identity(cell_id, TF5_IBS_CELL_ID_LEN, 0, pk, nullptr, scalar));
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
    EXPECT_EQ(TF5_ERR_INVALID_PARAM, rc);
}

TEST_F(TF5IbsPkgTest, ParseCellIdHex_TooLong) {
    uint8_t cell_id[TF5_IBS_CELL_ID_LEN];
    int rc = tf5_ibs_parse_cell_id_hex("1234567890", cell_id);  // 10 chars instead of 9
    EXPECT_EQ(TF5_ERR_INVALID_PARAM, rc);
}

TEST_F(TF5IbsPkgTest, ParseCellIdHex_InvalidChars) {
    uint8_t cell_id[TF5_IBS_CELL_ID_LEN];
    int rc = tf5_ibs_parse_cell_id_hex("12345678G", cell_id);  // G is not hex
    EXPECT_EQ(TF5_ERR_INVALID_PARAM, rc);
}

TEST_F(TF5IbsPkgTest, ParseCellIdHex_NullInput) {
    uint8_t cell_id[TF5_IBS_CELL_ID_LEN];
    EXPECT_EQ(TF5_ERR_INVALID_PARAM, tf5_ibs_parse_cell_id_hex(nullptr, cell_id));
    EXPECT_EQ(TF5_ERR_INVALID_PARAM, tf5_ibs_parse_cell_id_hex("123456789", nullptr));
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
    EXPECT_EQ(TF5_ERR_INVALID_PARAM, tf5_ibs_format_cell_id_hex(nullptr, hex_str));
    EXPECT_EQ(TF5_ERR_INVALID_PARAM, tf5_ibs_format_cell_id_hex(cell_id, nullptr));
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
    EXPECT_EQ(TF5_ERR_FILE_OPEN, rc);
}

TEST_F(TF5IbsPkgTest, LoadMasterSecret_WrongSize) {
    std::string msk_path = test_dir + "/small_msk.bin";
    std::ofstream file(msk_path, std::ios::binary);
    uint8_t data[16] = {0};  // Too small
    file.write(reinterpret_cast<char*>(data), 16);
    file.close();

    uint8_t msk_out[TF5_IBS_MASTER_SECRET_LEN];
    int rc = tf5_ibs_load_master_secret(msk_path.c_str(), msk_out);
    EXPECT_EQ(TF5_ERR_FILE_IO, rc);
}

TEST_F(TF5IbsPkgTest, LoadMasterSecret_NullInput) {
    uint8_t msk_out[TF5_IBS_MASTER_SECRET_LEN];
    EXPECT_EQ(TF5_ERR_INVALID_PARAM, tf5_ibs_load_master_secret(nullptr, msk_out));

    std::string path = test_dir + "/test.bin";
    EXPECT_EQ(TF5_ERR_INVALID_PARAM, tf5_ibs_load_master_secret(path.c_str(), nullptr));
}

// ============================================================================
// Compute gNB Secret Tests (tf5_ibs_compute_gnb_secret)
// ============================================================================

TEST_F(TF5IbsPkgTest, ComputeGnbSecret_Success) {
    uint8_t msk[TF5_IBS_MASTER_SECRET_LEN];
    memset(msk, 0x42, TF5_IBS_MASTER_SECRET_LEN);
    msk[0] = 0x01;  // Ensure valid scalar

    uint8_t mpk[TF5_IBS_MASTER_PUBLIC_LEN];
    DeriveMpk(msk, mpk);

    uint8_t cell_id[TF5_IBS_CELL_ID_LEN] = {0x12, 0x34, 0x56, 0x78, 0x90};
    uint32_t validity = 525600;

    uint8_t sk_out[TF5_IBS_GNB_SK_LEN];
    int rc = tf5_ibs_compute_gnb_secret(msk, cell_id, validity, mpk, sk_out);

    EXPECT_EQ(0, rc);
    // Verify output is not all zeros
    EXPECT_FALSE(is_all_zeros(sk_out, TF5_IBS_GNB_SK_LEN))
        << "Output should not be all zeros";
}

TEST_F(TF5IbsPkgTest, ComputeGnbSecret_Deterministic) {
    // Ed25519-based extract uses deterministic nonce, so same inputs produce same output
    uint8_t msk[TF5_IBS_MASTER_SECRET_LEN];
    memset(msk, 0x42, TF5_IBS_MASTER_SECRET_LEN);
    msk[0] = 0x01;

    uint8_t mpk[TF5_IBS_MASTER_PUBLIC_LEN];
    DeriveMpk(msk, mpk);

    uint8_t cell_id[TF5_IBS_CELL_ID_LEN] = {0x12, 0x34, 0x56, 0x78, 0x90};
    uint32_t validity = 525600;

    uint8_t sk1[TF5_IBS_GNB_SK_LEN];
    uint8_t sk2[TF5_IBS_GNB_SK_LEN];

    tf5_ibs_compute_gnb_secret(msk, cell_id, validity, mpk, sk1);
    tf5_ibs_compute_gnb_secret(msk, cell_id, validity, mpk, sk2);

    EXPECT_EQ(0, memcmp(sk1, sk2, TF5_IBS_GNB_SK_LEN))
        << "Ed25519-based extract is deterministic: same inputs should produce same output";
}

TEST_F(TF5IbsPkgTest, ComputeGnbSecret_DifferentMsk) {
    uint8_t msk1[TF5_IBS_MASTER_SECRET_LEN];
    uint8_t msk2[TF5_IBS_MASTER_SECRET_LEN];
    memset(msk1, 0x42, TF5_IBS_MASTER_SECRET_LEN);
    memset(msk2, 0x43, TF5_IBS_MASTER_SECRET_LEN);
    msk1[0] = 0x01;
    msk2[0] = 0x01;

    uint8_t mpk1[TF5_IBS_MASTER_PUBLIC_LEN];
    uint8_t mpk2[TF5_IBS_MASTER_PUBLIC_LEN];
    DeriveMpk(msk1, mpk1);
    DeriveMpk(msk2, mpk2);

    uint8_t cell_id[TF5_IBS_CELL_ID_LEN] = {0x12, 0x34, 0x56, 0x78, 0x90};
    uint32_t validity = 525600;

    uint8_t sk1[TF5_IBS_GNB_SK_LEN];
    uint8_t sk2[TF5_IBS_GNB_SK_LEN];

    tf5_ibs_compute_gnb_secret(msk1, cell_id, validity, mpk1, sk1);
    tf5_ibs_compute_gnb_secret(msk2, cell_id, validity, mpk2, sk2);

    EXPECT_NE(0, memcmp(sk1, sk2, TF5_IBS_GNB_SK_LEN))
        << "Different MSK should produce different sk_id";
}

TEST_F(TF5IbsPkgTest, ComputeGnbSecret_NullInput) {
    uint8_t msk[TF5_IBS_MASTER_SECRET_LEN] = {0};
    uint8_t mpk[TF5_IBS_MASTER_PUBLIC_LEN] = {0};
    uint8_t cell_id[TF5_IBS_CELL_ID_LEN] = {0};
    uint8_t sk_out[TF5_IBS_GNB_SK_LEN];

    EXPECT_EQ(TF5_ERR_INVALID_PARAM, tf5_ibs_compute_gnb_secret(nullptr, cell_id, 0, mpk, sk_out));
    EXPECT_EQ(TF5_ERR_INVALID_PARAM, tf5_ibs_compute_gnb_secret(msk, nullptr, 0, mpk, sk_out));
    EXPECT_EQ(TF5_ERR_INVALID_PARAM, tf5_ibs_compute_gnb_secret(msk, cell_id, 0, nullptr, sk_out));
    EXPECT_EQ(TF5_ERR_INVALID_PARAM, tf5_ibs_compute_gnb_secret(msk, cell_id, 0, mpk, nullptr));
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
        << "MPK should be 32 bytes";
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
    EXPECT_EQ(TF5_ERR_INVALID_PARAM, tf5_ibs_generate_master_keypair(nullptr, valid_path.c_str()));
    EXPECT_EQ(TF5_ERR_INVALID_PARAM, tf5_ibs_generate_master_keypair(valid_path.c_str(), nullptr));
}

// ============================================================================
// gNB Key Issuance Tests (tf5_ibs_issue_gnb_key)
// ============================================================================

TEST_F(TF5IbsPkgTest, IssueGnbKey_Creates67ByteFile) {
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

    // Verify file size is 67 bytes (64B sk_id: y[32] + pk[32], plus 3B validity)
    EXPECT_EQ(TF5_IBS_SK_FILE_SIZE, std::filesystem::file_size(sk_path))
        << "gNB key file should be 67 bytes";
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

    // Last 3 bytes should be big-endian validity (at offset TF5_IBS_GNB_SK_LEN)
    EXPECT_EQ(0x12, data[TF5_IBS_GNB_SK_LEN + 0]) << "Validity byte 0 (MSB)";
    EXPECT_EQ(0x34, data[TF5_IBS_GNB_SK_LEN + 1]) << "Validity byte 1";
    EXPECT_EQ(0x56, data[TF5_IBS_GNB_SK_LEN + 2]) << "Validity byte 2 (LSB)";
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

    EXPECT_NE(0, memcmp(sk1, sk2, TF5_IBS_GNB_SK_LEN))
        << "Different Cell IDs should produce different secret keys";
}

TEST_F(TF5IbsPkgTest, IssueGnbKey_MskNotFound) {
    uint8_t cell_id[TF5_IBS_CELL_ID_LEN] = {0x12, 0x34, 0x56, 0x78, 0x90};
    std::string sk_path = test_dir + "/sk.bin";

    int rc = tf5_ibs_issue_gnb_key("/nonexistent/msk.bin", cell_id, 525600, sk_path.c_str());
    EXPECT_EQ(TF5_ERR_FILE_OPEN, rc);
}

// ============================================================================
// Validity Period Conversion Tests
// ============================================================================

TEST_F(TF5IbsPkgTest, ValidityConversion_RoundTrip) {
    // Test round-trip conversion
    uint64_t original_unix = 1735689600;  // 2025-01-01 00:00:00 UTC

    uint32_t validity = tf5_unix_to_gnb_key_validity(original_unix);
    uint64_t recovered_unix = tf5_gnb_key_validity_to_unix(validity);

    // Should be within 1 minute (60 seconds) due to minute granularity
    EXPECT_LE(std::abs((int64_t)(recovered_unix - original_unix)), 60)
        << "Round-trip should preserve timestamp within minute granularity";
}

TEST_F(TF5IbsPkgTest, ValidityConversion_Epoch) {
    // At epoch (2024-01-01 00:00:00 UTC), validity should be 0
    uint32_t validity = tf5_unix_to_gnb_key_validity(TF5_IBS_VALIDITY_EPOCH);
    EXPECT_EQ(0, validity);
}

TEST_F(TF5IbsPkgTest, ValidityConversion_BeforeEpoch) {
    // Before epoch should return 0
    uint32_t validity = tf5_unix_to_gnb_key_validity(TF5_IBS_VALIDITY_EPOCH - 1000);
    EXPECT_EQ(0, validity);
}

TEST_F(TF5IbsPkgTest, ValidityConversion_OneYear) {
    // 1 year = 525600 minutes
    uint64_t one_year_after = TF5_IBS_VALIDITY_EPOCH + (525600UL * 60);
    uint32_t validity = tf5_unix_to_gnb_key_validity(one_year_after);
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

    // Verify validity encoding (at offset TF5_IBS_GNB_SK_LEN = 64)
    uint32_t read_validity = ((uint32_t)data[TF5_IBS_GNB_SK_LEN] << 16) |
                             ((uint32_t)data[TF5_IBS_GNB_SK_LEN + 1] << 8) |
                             (uint32_t)data[TF5_IBS_GNB_SK_LEN + 2];
    EXPECT_EQ(validity, read_validity);

    // Verify the key is non-zero and has valid structure
    EXPECT_FALSE(is_all_zeros(data, TF5_IBS_GNB_SK_LEN))
        << "Issued key should not be all zeros";
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char **argv) {
    if (sodium_init() < 0) {
        fprintf(stderr, "ERROR: sodium_init() failed\n");
        return 1;
    }
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
