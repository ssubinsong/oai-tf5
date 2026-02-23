/*
 * TF5 IBS - Master Keypair Generation Utility (GG09 Schnorr IBS)
 *
 * Generates the Core PKG master secret key (z) and master public key (MPK = z·B).
 *
 * Usage: tf5_ibs_pkg_keygen <msk_path> <mpk_path>
 *
 * SECURITY WARNING: The master secret key (msk) is the root of trust for the
 * entire IBS system. If compromised, an attacker can forge keys for any gNB.
 * Store the msk file securely (e.g., HSM, encrypted storage).
 */

#include "tf5_ibs_pkg.h"

#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "tf5_ibs_file_util.h"

/* Reduce a 32-byte value mod l (Ed25519 group order) */
static void scalar_reduce_32(uint8_t out[32], const uint8_t in[32])
{
    uint8_t tmp[64];
    memcpy(tmp, in, 32);
    memset(tmp + 32, 0, 32);
    crypto_core_ed25519_scalar_reduce(out, tmp);
}

/*
 * Generate master keypair and save to files
 */
int tf5_ibs_generate_master_keypair(const char *msk_path, const char *mpk_path)
{
    if (!msk_path || !mpk_path) {
        return TF5_ERR_INVALID_PARAM;
    }

    uint8_t msk[TF5_IBS_MASTER_SECRET_LEN];
    uint8_t mpk[TF5_IBS_MASTER_PUBLIC_LEN];

    /* Generate random master secret z and reduce mod l */
    randombytes_buf(msk, TF5_IBS_MASTER_SECRET_LEN);
    scalar_reduce_32(msk, msk);

    /* Validate: z must not be zero */
    uint8_t zero[TF5_IBS_MASTER_SECRET_LEN] = {0};
    if (sodium_memcmp(msk, zero, TF5_IBS_MASTER_SECRET_LEN) == 0) {
        fprintf(stderr, "Generated zero secret key (probability ~2^-252)\n");
        sodium_memzero(msk, TF5_IBS_MASTER_SECRET_LEN);
        return TF5_ERR_KEY_INVALID;
    }

    /* Derive master public key: MPK = z · B (Ed25519 base point) */
    if (crypto_scalarmult_ed25519_base_noclamp(mpk, msk) != 0) {
        sodium_memzero(msk, TF5_IBS_MASTER_SECRET_LEN);
        return TF5_ERR_CRYPTO;
    }

    /* Write master secret key (restricted permissions: owner read/write only) */
    if (write_key_file(msk_path, msk, TF5_IBS_MASTER_SECRET_LEN, 0600) != 0) {
        sodium_memzero(msk, TF5_IBS_MASTER_SECRET_LEN);
        return TF5_ERR_FILE_WRITE;
    }

    /* Clear msk from memory */
    sodium_memzero(msk, TF5_IBS_MASTER_SECRET_LEN);

    /* Write master public key (public readable) */
    if (write_key_file(mpk_path, mpk, TF5_IBS_MASTER_PUBLIC_LEN, 0644) != 0) {
        /* Try to remove the msk file since we failed */
        unlink(msk_path);
        return TF5_ERR_FILE_WRITE;
    }

    return TF5_OK;
}

/*
 * Print usage information
 */
static void print_usage(const char *prog)
{
    fprintf(stderr, "TF5 IBS - Master Keypair Generation\n\n");
    fprintf(stderr, "Usage: %s <msk_path> <mpk_path>\n\n", prog);
    fprintf(stderr, "Arguments:\n");
    fprintf(stderr, "  msk_path  Path to save master secret key (32 bytes)\n");
    fprintf(stderr, "  mpk_path  Path to save master public key (32 bytes)\n\n");
    fprintf(stderr, "Example:\n");
    fprintf(stderr, "  %s pkg_keys/msk.bin pkg_keys/mpk.bin\n\n", prog);
    fprintf(stderr, "SECURITY: The master secret key is the root of trust.\n");
    fprintf(stderr, "          Store it securely (HSM, encrypted storage).\n");
}

#ifndef TF5_IBS_NO_MAIN
int main(int argc, char *argv[])
{
    if (argc != 3) {
        print_usage(argv[0]);
        return 1;
    }

    if (sodium_init() < 0) {
        fprintf(stderr, "ERROR: sodium_init() failed\n");
        return 1;
    }

    const char *msk_path = argv[1];
    const char *mpk_path = argv[2];

    printf("Generating IBS master keypair...\n");
    printf("  Master secret: %s\n", msk_path);
    printf("  Master public: %s\n", mpk_path);

    int rc = tf5_ibs_generate_master_keypair(msk_path, mpk_path);
    if (rc != 0) {
        fprintf(stderr, "Failed to generate master keypair (error %d)\n", rc);
        return 1;
    }

    printf("Master keypair generated successfully.\n");
    printf("\n");
    printf("Next steps:\n");
    printf("  1. Secure the master secret key (%s)\n", msk_path);
    printf("  2. Distribute the master public key (%s) to UEs\n", mpk_path);
    printf("  3. Issue gNB keys using: tf5_ibs_issue %s <cell_id_hex> <sk_path>\n", msk_path);

    return 0;
}
#endif /* TF5_IBS_NO_MAIN */
