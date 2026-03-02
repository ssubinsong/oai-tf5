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
// Main
// ============================================================================

int main(int argc, char **argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
