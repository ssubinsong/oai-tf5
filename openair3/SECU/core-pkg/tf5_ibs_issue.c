/*
 * TF5 IBS - gNB Secret Key Issuance Utility
 *
 * Issues a gNB-specific secret key based on its NR Cell ID and validity period.
 * sk_ID = s * H_s(cell_id || gnb_key_validity_end) mod r
 *
 * Usage: tf5_ibs_issue <msk_path> <cell_id_hex> <gnb_key_validity_end> <sk_path>
 *
 * Example: tf5_ibs_issue pkg_keys/msk.bin 123456789 1051200 gnb_keys/sk_001.bin
 *          (Key valid until 2026-01-01, which is 1051200 minutes from 2024-01-01)
 */

#include "tf5_ibs_pkg.h"
#include "blst.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>

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
 * Issue gNB secret key and save to file
 */
int tf5_ibs_issue_gnb_key(const char *msk_path,
                           const uint8_t cell_id[TF5_IBS_CELL_ID_LEN],
                           uint32_t gnb_key_validity_end,
                           const char *sk_path)
{
    if (!msk_path || !cell_id || !sk_path) {
        return -1;
    }

    uint8_t msk[TF5_IBS_MASTER_SECRET_LEN];
    uint8_t sk_id[TF5_GNB_SECRET_KEY_LEN];
    int rc;

    /* Load master secret key */
    rc = tf5_ibs_load_master_secret(msk_path, msk);
    if (rc != 0) {
        return -2;
    }

    /* Compute gNB secret key with validity period */
    rc = tf5_ibs_compute_gnb_secret(msk, cell_id, gnb_key_validity_end, sk_id);

    /* Clear master secret from memory */
    memset(msk, 0, TF5_IBS_MASTER_SECRET_LEN);

    if (rc != 0) {
        return -4;
    }

    /* Build combined key file: sk_id (32 bytes) + gnb_key_validity_end (3 bytes, big-endian) */
    uint8_t key_file_data[TF5_IBS_SK_FILE_SIZE];
    memcpy(key_file_data, sk_id, TF5_GNB_SECRET_KEY_LEN);

    /* Encode validity as 3 bytes big-endian (24 bits) */
    key_file_data[32] = (gnb_key_validity_end >> 16) & 0xFF;
    key_file_data[33] = (gnb_key_validity_end >> 8) & 0xFF;
    key_file_data[34] = gnb_key_validity_end & 0xFF;

    /* Write combined key file (35 bytes) */
    rc = write_key_file(sk_path, key_file_data, TF5_IBS_SK_FILE_SIZE, 0600);

    /* Clear key data from memory */
    memset(key_file_data, 0, TF5_IBS_SK_FILE_SIZE);
    memset(sk_id, 0, TF5_GNB_SECRET_KEY_LEN);

    if (rc != 0) {
        return -5;
    }

    return 0;
}

/*
 * Format gnb_key_validity_end as human-readable string
 */
static void format_gnb_key_validity_time(uint32_t gnb_key_validity_end, char *buf, size_t buf_len)
{
    time_t unix_time = (time_t)tf5_gnb_key_validity_to_unix(gnb_key_validity_end);
    struct tm *tm = gmtime(&unix_time);
    strftime(buf, buf_len, "%Y-%m-%d %H:%M UTC", tm);
}

/*
 * Print usage information
 */
static void print_usage(const char *prog)
{
    fprintf(stderr, "TF5 IBS - gNB Secret Key Issuance\n\n");
    fprintf(stderr, "Usage: %s <msk_path> <cell_id_hex> <gnb_key_validity_end> <sk_path>\n\n", prog);
    fprintf(stderr, "Arguments:\n");
    fprintf(stderr, "  msk_path               Path to master secret key file\n");
    fprintf(stderr, "  cell_id_hex            NR Cell ID as 9-character hex string (36 bits)\n");
    fprintf(stderr, "  gnb_key_validity_end   Key expiration (minutes since 2024-01-01 00:00 UTC)\n");
    fprintf(stderr, "  sk_path                Path to save gNB secret key (35 bytes: sk + validity)\n\n");
    fprintf(stderr, "Examples:\n");
    fprintf(stderr, "  # Key valid until 2026-01-01 (1051200 minutes from 2024-01-01)\n");
    fprintf(stderr, "  %s pkg_keys/msk.bin 123456789 1051200 gnb_keys/sk_001.bin\n\n", prog);
    fprintf(stderr, "  # Key valid for 1 year (525600 minutes)\n");
    fprintf(stderr, "  %s pkg_keys/msk.bin 123456789 525600 gnb_keys/sk_001.bin\n\n", prog);
    fprintf(stderr, "Validity period format:\n");
    fprintf(stderr, "  Minutes since 2024-01-01 00:00:00 UTC (epoch).\n");
    fprintf(stderr, "  Range: 0 to 16777215 (~31.9 years, until ~2056)\n\n");
    fprintf(stderr, "Common values:\n");
    fprintf(stderr, "  525600   = 1 year   (2025-01-01)\n");
    fprintf(stderr, "  1051200  = 2 years  (2026-01-01)\n");
    fprintf(stderr, "  2628000  = 5 years  (2029-01-01)\n");
    fprintf(stderr, "  5256000  = 10 years (2034-01-01)\n");
}

/*
 * Print computed pk_ID for debugging/verification
 */
static void print_pk_id(const uint8_t cell_id[TF5_IBS_CELL_ID_LEN], uint32_t gnb_key_validity_end)
{
    uint8_t pk_id_bytes[32];
    tf5_ibs_hash_to_scalar(cell_id, TF5_IBS_CELL_ID_LEN, gnb_key_validity_end, pk_id_bytes);

    printf("  pk_ID (H_s(cell_id || gnb_key_validity)): ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", pk_id_bytes[i]);
    }
    printf("\n");

    memset(pk_id_bytes, 0, 32);
}

#ifndef TF5_IBS_NO_MAIN
int main(int argc, char *argv[])
{
    if (argc != 5) {
        print_usage(argv[0]);
        return 1;
    }

    const char *msk_path = argv[1];
    const char *cell_id_hex = argv[2];
    const char *validity_str = argv[3];
    const char *sk_path = argv[4];

    /* Parse Cell ID from hex string */
    uint8_t cell_id[TF5_IBS_CELL_ID_LEN];
    int rc = tf5_ibs_parse_cell_id_hex(cell_id_hex, cell_id);
    if (rc != 0) {
        fprintf(stderr, "Invalid Cell ID format: \"%s\"\n", cell_id_hex);
        fprintf(stderr, "Expected 9 hex characters (36 bits), e.g., \"123456789\"\n");
        return 1;
    }

    /* Parse gnb_key_validity_end (minutes since 2024-01-01) */
    char *endptr;
    unsigned long validity_val = strtoul(validity_str, &endptr, 10);
    if (*endptr != '\0' || validity_val > 0xFFFFFF) {
        fprintf(stderr, "Invalid gnb_key_validity_end: \"%s\"\n", validity_str);
        fprintf(stderr, "Expected 0 to 16777215 (minutes since 2024-01-01 00:00 UTC)\n");
        return 1;
    }
    uint32_t gnb_key_validity_end = (uint32_t)validity_val;

    /* Format back for display */
    char cell_id_str[10];
    tf5_ibs_format_cell_id_hex(cell_id, cell_id_str);

    /* Format validity as human-readable */
    char validity_time_str[64];
    format_gnb_key_validity_time(gnb_key_validity_end, validity_time_str, sizeof(validity_time_str));

    printf("Issuing gNB secret key...\n");
    printf("  Master secret: %s\n", msk_path);
    printf("  Cell ID: 0x%s (36 bits)\n", cell_id_str);
    printf("  Validity end: %u (%s)\n", gnb_key_validity_end, validity_time_str);
    printf("  Output: %s\n", sk_path);

    /* Show pk_ID for verification */
    print_pk_id(cell_id, gnb_key_validity_end);

    /* Issue the key */
    rc = tf5_ibs_issue_gnb_key(msk_path, cell_id, gnb_key_validity_end, sk_path);
    if (rc != 0) {
        switch (rc) {
        case -2:
            fprintf(stderr, "Failed to load master secret from %s\n", msk_path);
            break;
        case -4:
            fprintf(stderr, "Failed to compute gNB secret key\n");
            break;
        case -5:
            fprintf(stderr, "Failed to write key file to %s\n", sk_path);
            break;
        default:
            fprintf(stderr, "Failed to issue gNB key (error %d)\n", rc);
            break;
        }
        return 1;
    }

    printf("gNB secret key issued successfully (35 bytes: sk + validity).\n");
    printf("\n");
    printf("Next steps:\n");
    printf("  1. Securely transfer %s to the gNB\n", sk_path);
    printf("  2. Configure gNB with: --tf5-privkey %s\n", sk_path);
    printf("  3. Ensure gNB's Cell ID matches 0x%s\n", cell_id_str);
    printf("  4. Key expires: %s\n", validity_time_str);

    return 0;
}
#endif /* TF5_IBS_NO_MAIN */
