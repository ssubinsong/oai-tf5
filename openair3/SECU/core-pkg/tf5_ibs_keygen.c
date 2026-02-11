/*
 * TF5 IBS - Master Keypair Generation Utility
 *
 * Generates the Core PKG master secret key (s) and master public key (MPK = s*Q).
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

#define TF5_IBS_KEYGEN_IKM_LEN 32  /* Input Keying Material length */

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
 * Write binary data to file with specified permissions
 */
static int write_key_file(const char *path, const uint8_t *data, size_t len, mode_t mode)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd < 0) {
        perror("Failed to create output file");
        return -1;
    }

    ssize_t n = write(fd, data, len);
    close(fd);

    if (n != (ssize_t)len) {
        fprintf(stderr, "Failed to write %zu bytes to %s\n", len, path);
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
        return -1;
    }

    uint8_t ikm[TF5_IBS_KEYGEN_IKM_LEN];
    blst_scalar s;
    blst_p2 mpk;
    uint8_t msk_bytes[TF5_IBS_MASTER_SECRET_LEN];
    uint8_t mpk_bytes[TF5_IBS_MASTER_PUBLIC_LEN];

    /* Generate random IKM */
    if (read_random_bytes(ikm, TF5_IBS_KEYGEN_IKM_LEN) != 0) {
        return -2;
    }

    /* Derive master secret key using blst_keygen */
    blst_keygen(&s, ikm, TF5_IBS_KEYGEN_IKM_LEN, NULL, 0);

    /* Clear IKM from memory */
    OPENSSL_cleanse(ikm, TF5_IBS_KEYGEN_IKM_LEN);

    /* Validate secret key */
    if (!blst_sk_check(&s)) {
        fprintf(stderr, "Generated invalid secret key (probability ~2^-256)\n");
        OPENSSL_cleanse(&s, sizeof(s));
        return -3;
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
        return -4;
    }

    /* Clear msk from memory */
    OPENSSL_cleanse(msk_bytes, TF5_IBS_MASTER_SECRET_LEN);

    /* Write master public key (public readable) */
    if (write_key_file(mpk_path, mpk_bytes, TF5_IBS_MASTER_PUBLIC_LEN, 0644) != 0) {
        /* Try to remove the msk file since we failed */
        unlink(msk_path);
        return -4;
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
