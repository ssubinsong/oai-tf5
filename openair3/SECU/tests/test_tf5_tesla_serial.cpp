/**
 * @file test_tf5_tesla_serial.cpp
 * @brief Unit tests for TF5 TESLA serialization functions
 *
 * Tests for:
 * - tf5_tesla_pack_extension(): Serialize extension to binary (102 bytes)
 * - tf5_tesla_unpack_extension(): Deserialize extension from binary
 * - Big-endian encoding/decoding helpers
 */

#include <gtest/gtest.h>
#include <cstring>

extern "C" {
#include "openair3/SECU/tf5_tesla.h"
}

#include "tf5_test_vectors.h"

// Extension packed size
#define TF5_EXTENSION_PACKED_SIZE 102

class TF5SerialTest : public ::testing::Test {
protected:
    tf5_tesla_extension_t ext;
    uint8_t packed_buf[TF5_EXTENSION_PACKED_SIZE + 16];  // Extra space for overflow tests

    void SetUp() override {
        memset(&ext, 0, sizeof(ext));
        memset(packed_buf, 0, sizeof(packed_buf));

        // Set up a test extension with known values
        ext.te_version = TF5_VERSION;
        ext.tesla_params.t_int_ms = tf5_test::TV_EXT_T_INT_MS;
        ext.tesla_params.d = tf5_test::TV_EXT_D;
        ext.tesla_params.t0 = tf5_slot_time_make(tf5_test::TV_EXT_T0_SFN, tf5_test::TV_EXT_T0_SLOT);
        ext.tesla_params.chain_len = tf5_test::TV_EXT_CHAIN_LEN;
        ext.i = tf5_test::TV_EXT_INTERVAL;
        memcpy(ext.key_disclosure, tf5_test::TV_EXT_DISCLOSED_KEY, TF5_TESLA_KEY_LEN);
        ext.validity_end = tf5_test::TV_EXT_VALIDITY_END;
        ext.timestamp_ms = tf5_test::TV_EXT_TIMESTAMP_MS;
        memcpy(ext.signature, tf5_test::TV_EXT_SIGNATURE, TF5_TESLA_SIG_LEN);
        memcpy(ext.tesla_tag, tf5_test::TV_EXT_TAG, TF5_TESLA_TAG_LEN);
    }
};

// ============================================================================
// Pack Extension Tests (tf5_tesla_pack_extension)
// ============================================================================

TEST_F(TF5SerialTest, PackExtension_Success) {
    int ret = tf5_tesla_pack_extension(&ext, packed_buf, sizeof(packed_buf));

    EXPECT_EQ(TF5_EXTENSION_PACKED_SIZE, ret)
        << "Pack should return 102 bytes";
}

TEST_F(TF5SerialTest, PackExtension_VersionAtOffset0) {
    tf5_tesla_pack_extension(&ext, packed_buf, sizeof(packed_buf));

    EXPECT_EQ(TF5_VERSION, packed_buf[0])
        << "Version should be at offset 0";
}

TEST_F(TF5SerialTest, PackExtension_TIntAtOffset1) {
    tf5_tesla_pack_extension(&ext, packed_buf, sizeof(packed_buf));

    // T_int is 2 bytes big-endian at offset 1
    uint16_t t_int = tf5_decode_u16_be(&packed_buf[1]);

    EXPECT_EQ(tf5_test::TV_EXT_T_INT_MS, t_int)
        << "T_int should be at offset 1-2";
}

TEST_F(TF5SerialTest, PackExtension_DAtOffset3) {
    tf5_tesla_pack_extension(&ext, packed_buf, sizeof(packed_buf));

    EXPECT_EQ(tf5_test::TV_EXT_D, packed_buf[3])
        << "d should be at offset 3";
}

TEST_F(TF5SerialTest, PackExtension_T0AtOffset4) {
    tf5_tesla_pack_extension(&ext, packed_buf, sizeof(packed_buf));

    // T_0 SFN is 2 bytes at offset 4
    uint16_t t0_sfn = tf5_decode_u16_be(&packed_buf[4]);
    // T_0 slot is 2 bytes at offset 6
    uint16_t t0_slot = tf5_decode_u16_be(&packed_buf[6]);

    EXPECT_EQ(tf5_test::TV_EXT_T0_SFN, t0_sfn) << "T_0 SFN should be at offset 4-5";
    EXPECT_EQ(tf5_test::TV_EXT_T0_SLOT, t0_slot) << "T_0 slot should be at offset 6-7";
}

TEST_F(TF5SerialTest, PackExtension_ChainLenAtOffset8) {
    tf5_tesla_pack_extension(&ext, packed_buf, sizeof(packed_buf));

    // chain_len is 4 bytes at offset 8
    uint32_t chain_len = tf5_decode_u32_be(&packed_buf[8]);

    EXPECT_EQ(tf5_test::TV_EXT_CHAIN_LEN, chain_len)
        << "chain_len should be at offset 8-11";
}

TEST_F(TF5SerialTest, PackExtension_ValidityEndAtOffset12) {
    tf5_tesla_pack_extension(&ext, packed_buf, sizeof(packed_buf));

    // validity_end is 3 bytes at offset 12
    uint32_t validity_end = tf5_decode_u24_be(&packed_buf[12]);

    EXPECT_EQ(tf5_test::TV_EXT_VALIDITY_END, validity_end)
        << "validity_end should be at offset 12-14";
}

TEST_F(TF5SerialTest, PackExtension_IntervalAtOffset15) {
    tf5_tesla_pack_extension(&ext, packed_buf, sizeof(packed_buf));

    // interval is 4 bytes at offset 15
    uint32_t interval = tf5_decode_u32_be(&packed_buf[15]);

    EXPECT_EQ(tf5_test::TV_EXT_INTERVAL, interval)
        << "interval should be at offset 15-18";
}

TEST_F(TF5SerialTest, PackExtension_KeyDisclosureAtOffset19) {
    tf5_tesla_pack_extension(&ext, packed_buf, sizeof(packed_buf));

    // key_disclosure is 16 bytes at offset 19
    EXPECT_EQ(0, memcmp(&packed_buf[19], tf5_test::TV_EXT_DISCLOSED_KEY, TF5_TESLA_KEY_LEN))
        << "key_disclosure should be at offset 19-34";
}

TEST_F(TF5SerialTest, PackExtension_TimestampAtOffset35) {
    tf5_tesla_pack_extension(&ext, packed_buf, sizeof(packed_buf));

    // timestamp_ms is 3 bytes at offset 35
    uint32_t timestamp = tf5_decode_u24_be(&packed_buf[35]);

    EXPECT_EQ(tf5_test::TV_EXT_TIMESTAMP_MS, timestamp)
        << "timestamp_ms should be at offset 35-37";
}

TEST_F(TF5SerialTest, PackExtension_SignatureAtOffset38) {
    tf5_tesla_pack_extension(&ext, packed_buf, sizeof(packed_buf));

    // signature is 48 bytes at offset 38
    EXPECT_EQ(0, memcmp(&packed_buf[38], tf5_test::TV_EXT_SIGNATURE, TF5_TESLA_SIG_LEN))
        << "signature should be at offset 38-85";
}

TEST_F(TF5SerialTest, PackExtension_TagAtOffset86) {
    tf5_tesla_pack_extension(&ext, packed_buf, sizeof(packed_buf));

    // tesla_tag is 16 bytes at offset 86
    EXPECT_EQ(0, memcmp(&packed_buf[86], tf5_test::TV_EXT_TAG, TF5_TESLA_TAG_LEN))
        << "tesla_tag should be at offset 86-101";
}

TEST_F(TF5SerialTest, PackExtension_BufferTooSmall_ReturnsError) {
    int ret = tf5_tesla_pack_extension(&ext, packed_buf, TF5_EXTENSION_PACKED_SIZE - 1);

    EXPECT_LT(ret, 0) << "Should return error when buffer too small";
}

TEST_F(TF5SerialTest, PackExtension_NullExt_ReturnsError) {
    int ret = tf5_tesla_pack_extension(nullptr, packed_buf, sizeof(packed_buf));

    EXPECT_LT(ret, 0) << "Should return error for null extension";
}

TEST_F(TF5SerialTest, PackExtension_NullBuf_ReturnsError) {
    int ret = tf5_tesla_pack_extension(&ext, nullptr, sizeof(packed_buf));

    EXPECT_LT(ret, 0) << "Should return error for null buffer";
}

// ============================================================================
// Unpack Extension Tests (tf5_tesla_unpack_extension)
// ============================================================================

TEST_F(TF5SerialTest, UnpackExtension_Success) {
    // First pack the extension
    tf5_tesla_pack_extension(&ext, packed_buf, sizeof(packed_buf));

    // Then unpack
    tf5_tesla_extension_t unpacked;
    int ret = tf5_tesla_unpack_extension(packed_buf, TF5_EXTENSION_PACKED_SIZE, &unpacked);

    EXPECT_EQ(0, ret) << "Unpack should return 0 on success";
}

TEST_F(TF5SerialTest, UnpackExtension_AllFieldsCorrect) {
    // First pack the extension
    tf5_tesla_pack_extension(&ext, packed_buf, sizeof(packed_buf));

    // Then unpack
    tf5_tesla_extension_t unpacked;
    tf5_tesla_unpack_extension(packed_buf, TF5_EXTENSION_PACKED_SIZE, &unpacked);

    // Verify all fields
    EXPECT_EQ(ext.te_version, unpacked.te_version);
    EXPECT_EQ(ext.tesla_params.t_int_ms, unpacked.tesla_params.t_int_ms);
    EXPECT_EQ(ext.tesla_params.d, unpacked.tesla_params.d);
    EXPECT_EQ(ext.tesla_params.t0.sfn, unpacked.tesla_params.t0.sfn);
    EXPECT_EQ(ext.tesla_params.t0.slot, unpacked.tesla_params.t0.slot);
    EXPECT_EQ(ext.tesla_params.chain_len, unpacked.tesla_params.chain_len);
    EXPECT_EQ(ext.validity_end, unpacked.validity_end);
    EXPECT_EQ(ext.i, unpacked.i);
    EXPECT_EQ(0, memcmp(ext.key_disclosure, unpacked.key_disclosure, TF5_TESLA_KEY_LEN));
    EXPECT_EQ(ext.timestamp_ms, unpacked.timestamp_ms);
    EXPECT_EQ(0, memcmp(ext.signature, unpacked.signature, TF5_TESLA_SIG_LEN));
    EXPECT_EQ(0, memcmp(ext.tesla_tag, unpacked.tesla_tag, TF5_TESLA_TAG_LEN));
}

TEST_F(TF5SerialTest, PackUnpack_RoundTrip) {
    // Pack
    int pack_ret = tf5_tesla_pack_extension(&ext, packed_buf, sizeof(packed_buf));
    ASSERT_EQ(TF5_EXTENSION_PACKED_SIZE, pack_ret);

    // Unpack
    tf5_tesla_extension_t unpacked;
    int unpack_ret = tf5_tesla_unpack_extension(packed_buf, TF5_EXTENSION_PACKED_SIZE, &unpacked);
    ASSERT_EQ(0, unpack_ret);

    // Repack
    uint8_t repacked_buf[TF5_EXTENSION_PACKED_SIZE];
    int repack_ret = tf5_tesla_pack_extension(&unpacked, repacked_buf, sizeof(repacked_buf));
    ASSERT_EQ(TF5_EXTENSION_PACKED_SIZE, repack_ret);

    // Compare
    EXPECT_EQ(0, memcmp(packed_buf, repacked_buf, TF5_EXTENSION_PACKED_SIZE))
        << "Round-trip pack -> unpack -> pack should produce identical bytes";
}

TEST_F(TF5SerialTest, UnpackExtension_BufferTooSmall_ReturnsError) {
    tf5_tesla_pack_extension(&ext, packed_buf, sizeof(packed_buf));

    tf5_tesla_extension_t unpacked;
    int ret = tf5_tesla_unpack_extension(packed_buf, TF5_EXTENSION_PACKED_SIZE - 1, &unpacked);

    EXPECT_LT(ret, 0) << "Should return error when buffer too small";
}

TEST_F(TF5SerialTest, UnpackExtension_NullBuf_ReturnsError) {
    tf5_tesla_extension_t unpacked;
    int ret = tf5_tesla_unpack_extension(nullptr, TF5_EXTENSION_PACKED_SIZE, &unpacked);

    EXPECT_LT(ret, 0) << "Should return error for null buffer";
}

TEST_F(TF5SerialTest, UnpackExtension_NullExt_ReturnsError) {
    tf5_tesla_pack_extension(&ext, packed_buf, sizeof(packed_buf));

    int ret = tf5_tesla_unpack_extension(packed_buf, TF5_EXTENSION_PACKED_SIZE, nullptr);

    EXPECT_LT(ret, 0) << "Should return error for null extension output";
}

// ============================================================================
// Big-Endian Encoding Helper Tests
// ============================================================================

TEST_F(TF5SerialTest, EncodeU16_BigEndian) {
    uint8_t buf[2];
    tf5_encode_u16_be(buf, 0x1234);

    EXPECT_EQ(0x12, buf[0]) << "High byte should be first";
    EXPECT_EQ(0x34, buf[1]) << "Low byte should be second";
}

TEST_F(TF5SerialTest, DecodeU16_BigEndian) {
    uint8_t buf[2] = {0x12, 0x34};
    uint16_t val = tf5_decode_u16_be(buf);

    EXPECT_EQ(0x1234u, val);
}

TEST_F(TF5SerialTest, EncodeU24_BigEndian) {
    uint8_t buf[3];
    tf5_encode_u24_be(buf, 0x123456);

    EXPECT_EQ(0x12, buf[0]);
    EXPECT_EQ(0x34, buf[1]);
    EXPECT_EQ(0x56, buf[2]);
}

TEST_F(TF5SerialTest, DecodeU24_BigEndian) {
    uint8_t buf[3] = {0x12, 0x34, 0x56};
    uint32_t val = tf5_decode_u24_be(buf);

    EXPECT_EQ(0x123456u, val);
}

TEST_F(TF5SerialTest, EncodeU32_BigEndian) {
    uint8_t buf[4];
    tf5_encode_u32_be(buf, 0x12345678);

    EXPECT_EQ(0x12, buf[0]);
    EXPECT_EQ(0x34, buf[1]);
    EXPECT_EQ(0x56, buf[2]);
    EXPECT_EQ(0x78, buf[3]);
}

TEST_F(TF5SerialTest, DecodeU32_BigEndian) {
    uint8_t buf[4] = {0x12, 0x34, 0x56, 0x78};
    uint32_t val = tf5_decode_u32_be(buf);

    EXPECT_EQ(0x12345678u, val);
}

TEST_F(TF5SerialTest, EncodeU64_BigEndian) {
    uint8_t buf[8];
    tf5_encode_u64_be(buf, 0x123456789ABCDEF0ULL);

    EXPECT_EQ(0x12, buf[0]);
    EXPECT_EQ(0x34, buf[1]);
    EXPECT_EQ(0x56, buf[2]);
    EXPECT_EQ(0x78, buf[3]);
    EXPECT_EQ(0x9A, buf[4]);
    EXPECT_EQ(0xBC, buf[5]);
    EXPECT_EQ(0xDE, buf[6]);
    EXPECT_EQ(0xF0, buf[7]);
}

TEST_F(TF5SerialTest, DecodeU64_BigEndian) {
    uint8_t buf[8] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0};
    uint64_t val = tf5_decode_u64_be(buf);

    EXPECT_EQ(0x123456789ABCDEF0ULL, val);
}

TEST_F(TF5SerialTest, RoundTrip_U16) {
    uint16_t original = 0xABCD;
    uint8_t buf[2];

    tf5_encode_u16_be(buf, original);
    uint16_t decoded = tf5_decode_u16_be(buf);

    EXPECT_EQ(original, decoded);
}

TEST_F(TF5SerialTest, RoundTrip_U24) {
    uint32_t original = 0x987654;
    uint8_t buf[3];

    tf5_encode_u24_be(buf, original);
    uint32_t decoded = tf5_decode_u24_be(buf);

    EXPECT_EQ(original, decoded);
}

TEST_F(TF5SerialTest, RoundTrip_U32) {
    uint32_t original = 0xDEADBEEF;
    uint8_t buf[4];

    tf5_encode_u32_be(buf, original);
    uint32_t decoded = tf5_decode_u32_be(buf);

    EXPECT_EQ(original, decoded);
}

TEST_F(TF5SerialTest, RoundTrip_U64) {
    uint64_t original = 0xCAFEBABEDEADBEEFULL;
    uint8_t buf[8];

    tf5_encode_u64_be(buf, original);
    uint64_t decoded = tf5_decode_u64_be(buf);

    EXPECT_EQ(original, decoded);
}

// ============================================================================
// Validity Period Encoding Tests
// ============================================================================

TEST_F(TF5SerialTest, EncodeGnbKeyValidityEnd) {
    uint8_t buf[3];
    tf5_encode_gnb_key_validity_end(buf, 0x080604);  // Example validity

    EXPECT_EQ(0x08, buf[0]);
    EXPECT_EQ(0x06, buf[1]);
    EXPECT_EQ(0x04, buf[2]);
}

TEST_F(TF5SerialTest, DecodeGnbKeyValidityEnd) {
    uint8_t buf[3] = {0x08, 0x06, 0x04};
    uint32_t val = tf5_decode_gnb_key_validity_end(buf);

    EXPECT_EQ(0x080604u, val);
}

TEST_F(TF5SerialTest, RoundTrip_GnbKeyValidityEnd) {
    uint32_t original = tf5_test::TV_EXT_VALIDITY_END;
    uint8_t buf[3];

    tf5_encode_gnb_key_validity_end(buf, original);
    uint32_t decoded = tf5_decode_gnb_key_validity_end(buf);

    EXPECT_EQ(original, decoded);
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char **argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
