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

// Test vector for cell_id used in SIB9 tests
static const uint8_t TV_CELL_ID[TF5_IBS_CELL_ID_LEN] = {0x00, 0x00, 0x00, 0x01, 0xC0};

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
    // sig_auth_input is fixed 39 bytes: version(1) + cell_id(5) + params(11) + K_0(16) + timestamp(3) + validity(3)
    uint8_t out[TF5_MAX_AUTH_INPUT];
    size_t out_len = 0;

    tf5_tesla_params_t params = {};
    params.t_int_ms = 160;
    params.d = 1;
    params.chain_len = 100;

    uint8_t cell_id[TF5_IBS_CELL_ID_LEN] = {0x00, 0x00, 0x00, 0x01, 0xC0};
    uint8_t k0[TF5_TESLA_KEY_LEN];
    memset(k0, 0xAA, TF5_TESLA_KEY_LEN);
    int ret = tf5_build_sig_auth_input(out, &out_len, TF5_VERSION,
                                       cell_id, &params, k0,
                                       tf5_test::TV_EXT_TIMESTAMP_S, 0x123456);

    EXPECT_EQ(0, ret);
    EXPECT_EQ(39u, out_len) << "Sig auth input should be exactly 39 bytes";
}

TEST_F(TF5SerialTest, BuildMacAuthInput_ExceedsMaxAuthInput) {
    uint8_t out[TF5_MAX_AUTH_INPUT];
    size_t out_len;
    uint8_t k0_next[TF5_TESLA_KEY_LEN] = {};

    // 372B SIB1 + 1B version_sp + 16B K_0^next = 389 <= 390 → OK
    uint8_t sib1_ok[372];
    memset(sib1_ok, 0x42, sizeof(sib1_ok));
    EXPECT_EQ(tf5_build_mac_auth_input(out, &out_len, sib1_ok, sizeof(sib1_ok),
                                        TF5_VERSION, k0_next), TF5_OK);

    // 374B SIB1 + 1B + 16B = 391 > 390 → overflow
    uint8_t sib1_big[374];
    memset(sib1_big, 0x42, sizeof(sib1_big));
    EXPECT_LT(tf5_build_mac_auth_input(out, &out_len, sib1_big, sizeof(sib1_big),
                                        TF5_VERSION, k0_next), 0);
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
    orig.sp_next = 0;  // chain renewal unused
    memset(orig.k0_next, 0, TF5_TESLA_KEY_LEN);  // all zeros when unused

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
    EXPECT_EQ(unpacked.sp_next, orig.sp_next);
    EXPECT_EQ(memcmp(unpacked.k0_next, orig.k0_next, TF5_TESLA_KEY_LEN), 0);
}

TEST_F(TF5SerialTest, PackUnpack_Sib1Ext_SpNextBitPacking) {
    tf5_sib1_ext_t sib1_ext = {};
    sib1_ext.te_version = TF5_VERSION;
    sib1_ext.sp_next = 1;
    sib1_ext.i = 42;
    memset(sib1_ext.key_disclosure, 0xAA, TF5_TESLA_KEY_LEN);
    memset(sib1_ext.k0_next, 0xBB, TF5_TESLA_KEY_LEN);
    memset(sib1_ext.tesla_tag, 0xCC, TF5_TESLA_TAG_LEN);

    uint8_t buf[TF5_SIB1_EXT_PACKED_SIZE];
    int written = tf5_pack_sib1_ext(&sib1_ext, buf, sizeof(buf));
    ASSERT_EQ(written, TF5_SIB1_EXT_PACKED_SIZE);

    // Verify wire byte 0: (version << 1) | sp_next = (0x02 << 1) | 1 = 0x05
    EXPECT_EQ(buf[0], 0x05);

    tf5_sib1_ext_t unpacked = {};
    ASSERT_EQ(tf5_unpack_sib1_ext(buf, sizeof(buf), &unpacked), TF5_OK);
    EXPECT_EQ(unpacked.te_version, TF5_VERSION);
    EXPECT_EQ(unpacked.sp_next, 1);
    EXPECT_EQ(unpacked.i, 42u);
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
    memcpy(orig.cell_id, TV_CELL_ID, TF5_IBS_CELL_ID_LEN);
    memset(orig.k0, 0xDD, TF5_TESLA_KEY_LEN);

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
    EXPECT_EQ(memcmp(unpacked.cell_id, orig.cell_id, TF5_IBS_CELL_ID_LEN), 0);
    EXPECT_EQ(memcmp(unpacked.k0, orig.k0, TF5_TESLA_KEY_LEN), 0);
}

TEST_F(TF5SerialTest, PackSib9Ext_WireFieldOrder) {
    tf5_sib9_ext_t sib9_ext = {};
    sib9_ext.te_version = TF5_VERSION;
    memcpy(sib9_ext.cell_id, TV_CELL_ID, TF5_IBS_CELL_ID_LEN);
    sib9_ext.tesla_params.t_int_ms = 160;
    sib9_ext.tesla_params.d = 1;
    sib9_ext.tesla_params.t0.sfn = 0;
    sib9_ext.tesla_params.t0.slot = 0;
    sib9_ext.tesla_params.chain_len = 65536;
    memset(sib9_ext.k0, 0xEE, TF5_TESLA_KEY_LEN);
    memset(sib9_ext.signature, 0xFF, TF5_IBS_SIG_LEN);
    sib9_ext.timestamp_s = 0x123456;
    sib9_ext.validity_end = 0xABCDEF;

    uint8_t buf[TF5_SIB9_EXT_PACKED_SIZE];
    int written = tf5_pack_sib9_ext(&sib9_ext, buf, sizeof(buf));
    ASSERT_EQ(written, TF5_SIB9_EXT_PACKED_SIZE);

    // Verify wire layout offsets:
    // 0: te_version, 1-5: cell_id, 6-16: params, 17-32: k0, 33-128: sig, 129-131: timestamp, 132-134: validity
    EXPECT_EQ(buf[0], TF5_VERSION);
    EXPECT_EQ(memcmp(buf + 1, TV_CELL_ID, TF5_IBS_CELL_ID_LEN), 0);
    // timestamp at offset 129
    EXPECT_EQ(buf[129], 0x12);
    EXPECT_EQ(buf[130], 0x34);
    EXPECT_EQ(buf[131], 0x56);
    // validity at offset 132
    EXPECT_EQ(buf[132], 0xAB);
    EXPECT_EQ(buf[133], 0xCD);
    EXPECT_EQ(buf[134], 0xEF);
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
