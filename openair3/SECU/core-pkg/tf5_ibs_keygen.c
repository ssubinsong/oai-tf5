/*
 * TF5 IBS - Master Keypair Generation Utility (GG09 Schnorr IBS)
 *
 * Generates the Core PKG master keypair using Ed25519 seed-based key derivation:
 *   MSK = random 32-byte seed
 *   MPK = crypto_sign_seed_keypair(seed) → public key
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

/*
 * Generate master keypair and save to files
 *
 * MSK = random 32-byte seed (used as Ed25519 seed)
 * MPK = public key derived via crypto_sign_seed_keypair(seed)
 */
int tf5_ibs_generate_master_keypair(const char *msk_path, const char *mpk_path)
{
    if (!msk_path || !mpk_path) {
        return TF5_ERR_INVALID_PARAM;
    }

    uint8_t seed[TF5_IBS_MASTER_SECRET_LEN];
    uint8_t mpk[TF5_IBS_MASTER_PUBLIC_LEN];
    uint8_t sk_tmp[crypto_sign_SECRETKEYBYTES];

    /* Generate random seed */
    randombytes_buf(seed, TF5_IBS_MASTER_SECRET_LEN);

    /* Derive keypair: seed → (mpk, sk_tmp) via Ed25519 key expansion */
    crypto_sign_seed_keypair(mpk, sk_tmp, seed);
    sodium_memzero(sk_tmp, sizeof(sk_tmp));

    /* Write master secret key (restricted permissions: owner read/write only) */
    if (write_key_file(msk_path, seed, TF5_IBS_MASTER_SECRET_LEN, 0600) != 0) {
        sodium_memzero(seed, TF5_IBS_MASTER_SECRET_LEN);
        return TF5_ERR_FILE_WRITE;
    }

    /* Clear seed from memory */
    sodium_memzero(seed, TF5_IBS_MASTER_SECRET_LEN);

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
