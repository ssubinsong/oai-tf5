/**
 * @file tf5_test_common.h
 * @brief Shared test infrastructure for TF5 unit tests
 *
 * Provides:
 * - OAI logging infrastructure stubs (exit_function, uniqCfg)
 * - Common test utilities (is_all_zeros)
 * - IBS test fixture base class (TF5IbsTestFixture)
 */

#ifndef TF5_TEST_COMMON_H
#define TF5_TEST_COMMON_H

#include <gtest/gtest.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <fstream>
#include <unistd.h>
#include <sys/stat.h>
#include <filesystem>
#include <sodium.h>

/*
 * =============================================================================
 * OAI Logging Infrastructure Stubs
 * =============================================================================
 *
 * Required by OAI modules that use AssertFatal/LOG_* macros.
 * Only include this section in test files that link against OAI logging.
 */
#ifdef TF5_TEST_NEEDS_OAI_STUBS

extern "C" {
#include "common/config/config_userapi.h"
#include "log.h"

configmodule_interface_t *uniqCfg;
void exit_function(const char *file, const char *function, const int line, const char *s, const int assert) {
    if (assert) abort();
    else exit(EXIT_SUCCESS);
}
}

#endif /* TF5_TEST_NEEDS_OAI_STUBS */

/*
 * =============================================================================
 * Common Test Utilities
 * =============================================================================
 */

/**
 * Check if a buffer is all zeros
 */
static inline bool is_all_zeros(const uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (buf[i] != 0) {
            return false;
        }
    }
    return true;
}

/*
 * =============================================================================
 * IBS Test Fixture Base Class
 * =============================================================================
 *
 * Common setup for tests that need PKG-generated IBS keys.
 * Generates master keypair, issues gNB key, and loads all keys into members.
 *
 * Subclasses should call TF5IbsTestFixture::SetUp() in their own SetUp().
 */

extern "C" {
#include "openair3/SECU/tf5_ibs_pkg.h"
#include "openair3/SECU/tf5_tesla.h"
}

class TF5IbsTestFixture : public ::testing::Test {
protected:
    std::string test_dir;
    std::string msk_path;
    std::string mpk_path;
    std::string sk_gnb_path;

    uint8_t ibs_msk[TF5_IBS_MASTER_SECRET_LEN];
    uint8_t ibs_mpk[TF5_IBS_MPK_LEN];
    uint8_t ibs_sk[TF5_IBS_GNB_SK_LEN];  // 64B: y[32] scalar + pk[32] point for GG09 Schnorr
    uint8_t cell_id[TF5_IBS_CELL_ID_LEN];
    uint32_t validity_end;

    static bool ibs_initialized;

    void SetUp() override {
        if (!ibs_initialized) {
            tf5_ibs_init();
            ibs_initialized = true;
        }

        memset(cell_id, 0, TF5_IBS_CELL_ID_LEN);
        cell_id[0] = 0x12;
        cell_id[1] = 0x34;
        cell_id[2] = 0x56;
        cell_id[3] = 0x78;
        cell_id[4] = 0x90;  // 36-bit cell ID = 0x123456789

        validity_end = 1051200;  // 2 years from epoch
    }

    void TearDown() override {
        if (!test_dir.empty()) {
            std::filesystem::remove_all(test_dir);
        }
    }

    void setupTestDir(const std::string &prefix) {
        test_dir = "/tmp/" + prefix + "_" + std::to_string(getpid());
        std::filesystem::create_directories(test_dir);
        msk_path = test_dir + "/msk.bin";
        mpk_path = test_dir + "/mpk.bin";
        sk_gnb_path = test_dir + "/sk_gnb.bin";
    }

    static void writeTestKeyFile(const std::string &path, const uint8_t *data, size_t len, mode_t mode) {
        std::ofstream f(path, std::ios::binary);
        f.write(reinterpret_cast<const char*>(data), len);
        f.close();
        chmod(path.c_str(), mode);
    }

    void generateAndLoadKeys() {
        // 1. Generate random seed (MSK)
        randombytes_buf(ibs_msk, TF5_IBS_MASTER_SECRET_LEN);

        // 2. Derive MPK via Ed25519 key expansion
        uint8_t sk_tmp[crypto_sign_SECRETKEYBYTES];
        crypto_sign_seed_keypair(ibs_mpk, sk_tmp, ibs_msk);
        sodium_memzero(sk_tmp, sizeof(sk_tmp));

        // 3. Write MSK and MPK to files
        writeTestKeyFile(msk_path, ibs_msk, TF5_IBS_MASTER_SECRET_LEN, 0600);
        writeTestKeyFile(mpk_path, ibs_mpk, TF5_IBS_MASTER_PUBLIC_LEN, 0644);

        // 4. Compute gNB secret key
        int rc = tf5_ibs_compute_gnb_secret(ibs_msk, cell_id, validity_end, ibs_sk);
        ASSERT_EQ(0, rc) << "Failed to compute gNB secret key";

        // 5. Write gNB SK file: sk_id[64] + validity_be[3]
        uint8_t sk_file[TF5_IBS_SK_FILE_SIZE];
        memcpy(sk_file, ibs_sk, TF5_IBS_GNB_SK_LEN);
        sk_file[TF5_IBS_GNB_SK_LEN + 0] = (validity_end >> 16) & 0xFF;
        sk_file[TF5_IBS_GNB_SK_LEN + 1] = (validity_end >> 8) & 0xFF;
        sk_file[TF5_IBS_GNB_SK_LEN + 2] = validity_end & 0xFF;
        writeTestKeyFile(sk_gnb_path, sk_file, TF5_IBS_SK_FILE_SIZE, 0600);
    }

    void loadGeneratedKeys() {
        int rc = tf5_ibs_load_master_secret(msk_path.c_str(), ibs_msk);
        ASSERT_EQ(0, rc) << "Failed to load MSK";

        rc = tf5_load_core_mpk(mpk_path.c_str(), ibs_mpk);
        ASSERT_EQ(0, rc) << "Failed to load MPK";

        FILE* f = fopen(sk_gnb_path.c_str(), "rb");
        ASSERT_NE(nullptr, f) << "Failed to open gNB SK file";
        uint8_t sk_file[TF5_IBS_SK_FILE_SIZE];
        size_t n = fread(sk_file, 1, TF5_IBS_SK_FILE_SIZE, f);
        fclose(f);
        ASSERT_EQ(TF5_IBS_SK_FILE_SIZE, n) << "Failed to read gNB SK";

        memcpy(ibs_sk, sk_file, TF5_IBS_GNB_SK_LEN);
    }
};

// Static member definition - must be in exactly one translation unit
// Each test file that uses TF5IbsTestFixture should define this:
//   bool TF5IbsTestFixture::ibs_initialized = false;

#endif /* TF5_TEST_COMMON_H */
