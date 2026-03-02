/**
 * @file test_tf5_tesla_serial.cpp
 * @brief Unit tests for TF5 TESLA serialization helpers
 *
 * Tests for:
 * - Big-endian encoding/decoding helpers
 * - Auth input buffer construction
 * - Validity period encoding/decoding
 */

#include <gtest/gtest.h>
#include <cstring>

extern "C" {
#include "openair3/SECU/tf5_tesla.h"
}

#include "tf5_test_vectors.h"

class TF5SerialTest : public ::testing::Test {
protected:
    void SetUp() override {}
};

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

// ============================================================================
// Auth Input Buffer Bounds Tests
// ============================================================================

TEST_F(TF5SerialTest, BuildSigAuthInput_FixedSize) {
    // sig_auth_input is now fixed 18 bytes (no SIB1), so overflow is impossible
    uint8_t out[TF5_MAX_AUTH_INPUT];
    size_t out_len = 0;

    tf5_tesla_params_t params = {};
    params.t_int_ms = 160;
    params.d = 1;
    params.chain_len = 100;

    int ret = tf5_build_sig_auth_input(out, &out_len,
                                       TF5_VERSION, &params, 525600, 0x123456);

    EXPECT_EQ(0, ret);
    EXPECT_EQ(18u, out_len) << "Sig auth input should be exactly 18 bytes";
}

TEST_F(TF5SerialTest, BuildMacAuthInput_ExceedsMaxAuthInput) {
    // SIB1 larger than TF5_MAX_AUTH_INPUT - 1 (version byte) should return TF5_ERR_BUFFER_OVERFLOW
    uint8_t out[TF5_MAX_AUTH_INPUT + 100];
    size_t out_len = 0;

    // TF5_MAX_AUTH_INPUT = 373, overhead = 1, so > 372 bytes fails
    uint8_t big_sib1[373];
    memset(big_sib1, 0xBB, sizeof(big_sib1));

    int ret = tf5_build_mac_auth_input(out, &out_len, big_sib1, sizeof(big_sib1), TF5_VERSION);

    EXPECT_EQ(TF5_ERR_BUFFER_OVERFLOW, ret) << "SIB1 exceeding max auth input should return TF5_ERR_BUFFER_OVERFLOW";
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
// SIB1 Extension Pack/Unpack Tests
// ============================================================================

TEST_F(TF5SerialTest, PackUnpack_Sib1Ext_RoundTrip) {
    tf5_sib1_ext_t orig = {};
    orig.te_version = TF5_VERSION;
    orig.i = tf5_test::TV_EXT_INTERVAL;
    memcpy(orig.key_disclosure, tf5_test::TV_EXT_DISCLOSED_KEY, TF5_TESLA_KEY_LEN);
    memcpy(orig.tesla_tag, tf5_test::TV_EXT_TAG, TF5_TESLA_TAG_LEN);

    uint8_t buf[TF5_SIB1_EXT_PACKED_SIZE];
    int packed = tf5_pack_sib1_ext(&orig, buf, sizeof(buf));
    ASSERT_EQ(TF5_SIB1_EXT_PACKED_SIZE, packed);

    tf5_sib1_ext_t unpacked = {};
    int rc = tf5_unpack_sib1_ext(buf, sizeof(buf), &unpacked);
    ASSERT_EQ(TF5_OK, rc);

    EXPECT_EQ(orig.te_version, unpacked.te_version);
    EXPECT_EQ(orig.i, unpacked.i);
    EXPECT_EQ(0, memcmp(orig.key_disclosure, unpacked.key_disclosure, TF5_TESLA_KEY_LEN));
    EXPECT_EQ(0, memcmp(orig.tesla_tag, unpacked.tesla_tag, TF5_TESLA_TAG_LEN));
}

TEST_F(TF5SerialTest, PackUnpack_Sib9Ext_RoundTrip) {
    tf5_sib9_ext_t orig = {};
    orig.te_version = TF5_VERSION;
    orig.tesla_params.t_int_ms = tf5_test::TV_EXT_T_INT_MS;
    orig.tesla_params.d = tf5_test::TV_EXT_D;
    orig.tesla_params.t0 = tf5_slot_time_make(tf5_test::TV_EXT_T0_SFN, tf5_test::TV_EXT_T0_SLOT);
    orig.tesla_params.chain_len = tf5_test::TV_EXT_CHAIN_LEN;
    orig.validity_end = tf5_test::TV_EXT_VALIDITY_END;
    orig.timestamp_s = tf5_test::TV_EXT_TIMESTAMP_S;
    memcpy(orig.signature, tf5_test::TV_EXT_SIGNATURE, TF5_IBS_SIG_LEN);

    uint8_t buf[TF5_SIB9_EXT_PACKED_SIZE];
    int packed = tf5_pack_sib9_ext(&orig, buf, sizeof(buf));
    ASSERT_EQ(TF5_SIB9_EXT_PACKED_SIZE, packed);

    tf5_sib9_ext_t unpacked = {};
    int rc = tf5_unpack_sib9_ext(buf, sizeof(buf), &unpacked);
    ASSERT_EQ(TF5_OK, rc);

    EXPECT_EQ(orig.te_version, unpacked.te_version);
    EXPECT_EQ(orig.tesla_params.t_int_ms, unpacked.tesla_params.t_int_ms);
    EXPECT_EQ(orig.tesla_params.d, unpacked.tesla_params.d);
    EXPECT_EQ(orig.tesla_params.t0.sfn, unpacked.tesla_params.t0.sfn);
    EXPECT_EQ(orig.tesla_params.t0.slot, unpacked.tesla_params.t0.slot);
    EXPECT_EQ(orig.tesla_params.chain_len, unpacked.tesla_params.chain_len);
    EXPECT_EQ(orig.validity_end, unpacked.validity_end);
    EXPECT_EQ(orig.timestamp_s, unpacked.timestamp_s);
    EXPECT_EQ(0, memcmp(orig.signature, unpacked.signature, TF5_IBS_SIG_LEN));
}

TEST_F(TF5SerialTest, PackSib1Ext_BufferTooSmall) {
    tf5_sib1_ext_t ext = {};
    uint8_t buf[TF5_SIB1_EXT_PACKED_SIZE - 1];

    int rc = tf5_pack_sib1_ext(&ext, buf, sizeof(buf));
    EXPECT_LT(rc, 0);
}

TEST_F(TF5SerialTest, PackSib9Ext_BufferTooSmall) {
    tf5_sib9_ext_t ext = {};
    uint8_t buf[TF5_SIB9_EXT_PACKED_SIZE - 1];

    int rc = tf5_pack_sib9_ext(&ext, buf, sizeof(buf));
    EXPECT_LT(rc, 0);
}

TEST_F(TF5SerialTest, UnpackSib1Ext_WrongSize) {
    uint8_t buf[TF5_SIB1_EXT_PACKED_SIZE - 1] = {};
    tf5_sib1_ext_t ext = {};

    int rc = tf5_unpack_sib1_ext(buf, sizeof(buf), &ext);
    EXPECT_LT(rc, 0);
}

TEST_F(TF5SerialTest, UnpackSib9Ext_WrongSize) {
    uint8_t buf[TF5_SIB9_EXT_PACKED_SIZE - 1] = {};
    tf5_sib9_ext_t ext = {};

    int rc = tf5_unpack_sib9_ext(buf, sizeof(buf), &ext);
    EXPECT_LT(rc, 0);
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char **argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
