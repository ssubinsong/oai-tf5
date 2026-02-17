/*
 * TF5 IBS - Master Keypair Generation Utility (BLMQ IBS)
 *
 * Generates the Core PKG master secret key (s) and master public key (MPK = s*Q).
 * Master key format is unchanged between old and BLMQ IBS schemes.
 *
 * Usage: tf5_ibs_pkg_keygen <msk_path> <mpk_path>
 *
 * SECURITY WARNING: The master secret key (msk) is the root of trust for the
 * entire IBS system. If compromised, an attacker can forge keys for any gNB.
 * Store the msk file securely (e.g., HSM, encrypted storage).
 */

#include "tf5_ibs_pkg.h"
#include "blst.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <unistd.h>
#include <sys/stat.h>

#include "tf5_ibs_file_util.h"

/*
 * Read cryptographically secure random bytes from /dev/urandom
 */
static int read_random_bytes(uint8_t *buf, size_t len)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        perror("Failed to open /dev/urandom");
        return -1;
    }

    ssize_t n = read(fd, buf, len);
    close(fd);

    if (n != (ssize_t)len) {
        fprintf(stderr, "Failed to read %zu random bytes\n", len);
        return -1;
    }

    return 0;
}

/*
 * Generate master keypair and save to files
 */
int tf5_ibs_generate_master_keypair(const char *msk_path, const char *mpk_path)
{
    if (!msk_path || !mpk_path) {
        return TF5_ERR_INVALID_PARAM;
    }

    uint8_t ikm[TF5_BLS_SCALAR_LEN];
    blst_scalar s;
    blst_p2 mpk;
    uint8_t msk_bytes[TF5_IBS_MASTER_SECRET_LEN];
    uint8_t mpk_bytes[TF5_IBS_MASTER_PUBLIC_LEN];

    /* Generate random IKM */
    if (read_random_bytes(ikm, TF5_BLS_SCALAR_LEN) != 0) {
        return TF5_ERR_CRYPTO;
    }

    /* Derive master secret key using blst_keygen */
    blst_keygen(&s, ikm, TF5_BLS_SCALAR_LEN, NULL, 0);

    /* Clear IKM from memory */
    OPENSSL_cleanse(ikm, TF5_BLS_SCALAR_LEN);

    /* Validate secret key */
    if (!blst_sk_check(&s)) {
        fprintf(stderr, "Generated invalid secret key (probability ~2^-256)\n");
        OPENSSL_cleanse(&s, sizeof(s));
        return TF5_ERR_KEY_INVALID;
    }

    /* Derive master public key: MPK = s * Q (Q is G2 generator) */
    blst_sk_to_pk_in_g2(&mpk, &s);

    /* Serialize keys */
    blst_bendian_from_scalar(msk_bytes, &s);
    blst_p2_compress(mpk_bytes, &mpk);

    /* Clear scalar from memory before file I/O */
    OPENSSL_cleanse(&s, sizeof(s));

    /* Write master secret key (restricted permissions: owner read/write only) */
    if (write_key_file(msk_path, msk_bytes, TF5_IBS_MASTER_SECRET_LEN, 0600) != 0) {
        OPENSSL_cleanse(msk_bytes, TF5_IBS_MASTER_SECRET_LEN);
        return TF5_ERR_FILE_WRITE;
    }

    /* Clear msk from memory */
    OPENSSL_cleanse(msk_bytes, TF5_IBS_MASTER_SECRET_LEN);

    /* Write master public key (public readable) */
    if (write_key_file(mpk_path, mpk_bytes, TF5_IBS_MASTER_PUBLIC_LEN, 0644) != 0) {
        /* Try to remove the msk file since we failed */
        unlink(msk_path);
        return TF5_ERR_FILE_WRITE;
    }

    return 0;
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
    fprintf(stderr, "  mpk_path  Path to save master public key (96 bytes)\n\n");
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
