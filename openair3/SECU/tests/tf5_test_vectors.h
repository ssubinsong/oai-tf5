/**
 * @file tf5_test_vectors.h
 * @brief Test vectors for TF5 TESLA unit tests
 *
 * Contains known-answer test vectors for:
 * - Key chain derivation (K_i = SHA256(0x00 || K_{i+1})[0:15])
 * - MAC key derivation (K'_i = SHA256(0x01 || K_i))
 * - Tag computation (HMAC-SHA256 truncated to 16 bytes)
 * - Extension serialization
 */

#ifndef TF5_TEST_VECTORS_H
#define TF5_TEST_VECTORS_H

#include <stdint.h>
#include <cstring>

namespace tf5_test {

/* ==========================================================================
 * Key Chain Test Vectors
 * ========================================================================== */

// Seed key K_5 for chain derivation test
static const uint8_t TV_KEY_CHAIN_K5[16] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
};

// Expected K_4 = SHA256(0x00 || K_5)[0:15]
// Computed: SHA256(00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10) = 3e5718fea51a8f3f5baca61c77afab47...
static const uint8_t TV_KEY_CHAIN_K4_EXPECTED[16] = {
    0x3e, 0x57, 0x18, 0xfe, 0xa5, 0x1a, 0x8f, 0x3f,
    0x5b, 0xac, 0xa6, 0x1c, 0x77, 0xaf, 0xab, 0x47
};

/* ==========================================================================
 * MAC Key Derivation Test Vectors
 * ========================================================================== */

// Input TESLA key for MAC key derivation
static const uint8_t TV_MAC_KEY_INPUT[16] = {
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
    0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99
};

// Expected MAC key K' = SHA256(0x01 || K)
// Computed: SHA256(01 aa bb cc dd ee ff 00 11 22 33 44 55 66 77 88 99) = d872bd99451ce18f6391c70162b6fe09...
static const uint8_t TV_MAC_KEY_OUTPUT_EXPECTED[32] = {
    0xd8, 0x72, 0xbd, 0x99, 0x45, 0x1c, 0xe1, 0x8f,
    0x63, 0x91, 0xc7, 0x01, 0x62, 0xb6, 0xfe, 0x09,
    0x9e, 0x0e, 0x22, 0x59, 0x9a, 0xbf, 0xca, 0x8f,
    0x46, 0xc9, 0x0d, 0xb3, 0x7e, 0xc0, 0x01, 0x8f
};

/* ==========================================================================
 * Tag Computation Test Vectors
 * ========================================================================== */

// Key for tag computation
static const uint8_t TV_TAG_KEY[16] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00
};

// Test message for tag computation
static const char TV_TAG_MESSAGE[] = "Test SIB1 message for TESLA authentication";
static const size_t TV_TAG_MESSAGE_LEN = sizeof(TV_TAG_MESSAGE) - 1;  // Exclude null terminator

/* ==========================================================================
 * IBS Test Vectors
 * ========================================================================== */

// Cell ID (5 bytes, 36 bits)
static const uint8_t TV_IBS_CELL_ID[5] = {
    0x01, 0x23, 0x45, 0x67, 0x89
};

// Key validity end (minutes since 2024-01-01)
// Example: 525600 minutes = 1 year from epoch
static const uint32_t TV_IBS_VALIDITY_END = 525600;

/* ==========================================================================
 * Extension Serialization Test Vectors
 * ========================================================================== */

// Test TESLA parameters
static const uint16_t TV_EXT_T_INT_MS = 20;
static const uint8_t  TV_EXT_D = 1;
static const uint16_t TV_EXT_T0_SFN = 100;
static const uint16_t TV_EXT_T0_SLOT = 5;
static const uint32_t TV_EXT_CHAIN_LEN = 65536;
static const uint32_t TV_EXT_INTERVAL = 42;
static const uint32_t TV_EXT_VALIDITY_END = 525600;  // ~1 year
static const uint32_t TV_EXT_TIMESTAMP_MS = 0x123456;

// Test disclosed key
static const uint8_t TV_EXT_DISCLOSED_KEY[16] = {
    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0
};

// Test signature (80 bytes = 32B h + 48B S for BLMQ IBS)
static const uint8_t TV_EXT_SIGNATURE[80] = {
    // h part (32 bytes)
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
    0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
    // S part (48 bytes)
    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
    0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
    0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
    0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
    0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef
};

// Test TESLA tag (16 bytes)
static const uint8_t TV_EXT_TAG[16] = {
    0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
    0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf
};

/* ==========================================================================
 * Timing Test Vectors
 * ========================================================================== */

// Slots per frame for 30 kHz SCS (FR1, numerology 1)
static const uint16_t TV_SLOTS_PER_FRAME = 20;

// T_0 timing
static const uint16_t TV_T0_SFN = 0;
static const uint16_t TV_T0_SLOT = 0;

/* ==========================================================================
 * Utility Functions
 * ========================================================================== */

// Helper to print hex bytes for debugging
inline void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// Helper to compare byte arrays
inline bool bytes_equal(const uint8_t* a, const uint8_t* b, size_t len) {
    return memcmp(a, b, len) == 0;
}

}  // namespace tf5_test

#endif /* TF5_TEST_VECTORS_H */
