/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1  (the "License"); you may not use this file
 * except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.openairinterface.org/?page_id=698
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */

/*
 * BLS Key Generation Utility for TESLA
 *
 * Generates a BLS12-381 keypair and saves to binary files.
 * Uses blst library (Supranational) with pk-in-G2 variant.
 *
 * Usage: tf5_bls_keygen <privkey_path> <pubkey_path>
 *
 * Key sizes (BLS12-381, pk-in-G2 / minimal-signature-size):
 *   - Secret key: 32 bytes (scalar, big-endian)
 *   - Public key: 96 bytes (G2 point, compressed)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "blst.h"

#define SECRET_KEY_LEN 32
#define PUBLIC_KEY_LEN 96

static void print_hex(const char *label, const uint8_t *data, size_t len)
{
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main(int argc, char *argv[])
{
    if (argc != 3) {
        fprintf(stderr, "BLS Key Generation Utility for TESLA\n\n");
        fprintf(stderr, "Usage: %s <privkey_path> <pubkey_path>\n\n", argv[0]);
        fprintf(stderr, "Generates:\n");
        fprintf(stderr, "  <privkey_path>  BLS secret key (32 bytes, raw binary, big-endian)\n");
        fprintf(stderr, "  <pubkey_path>   BLS public key (96 bytes, raw binary, G2 compressed)\n\n");
        fprintf(stderr, "Example:\n");
        fprintf(stderr, "  %s tesla_keys/gnb_tesla_privkey.bin tesla_keys/gnb_tesla_pubkey.bin\n", argv[0]);
        return 1;
    }

    const char *privkey_path = argv[1];
    const char *pubkey_path = argv[2];

    printf("BLS12-381 key generation (blst library, pk-in-G2 mode)\n");
    printf("  Signature size: 48 bytes (G1, compressed)\n");
    printf("  Public key size: 96 bytes (G2, compressed)\n\n");

    /* Read random IKM from /dev/urandom */
    uint8_t ikm[32];
    FILE *urandom = fopen("/dev/urandom", "rb");
    if (!urandom) {
        fprintf(stderr, "Error: Cannot open /dev/urandom\n");
        return 1;
    }
    if (fread(ikm, 1, sizeof(ikm), urandom) != sizeof(ikm)) {
        fprintf(stderr, "Error: Failed to read from /dev/urandom\n");
        fclose(urandom);
        return 1;
    }
    fclose(urandom);

    /* Generate secret key from IKM */
    blst_scalar sk;
    blst_keygen(&sk, ikm, sizeof(ikm), NULL, 0);

    /* Clear IKM immediately */
    memset(ikm, 0, sizeof(ikm));

    /* Derive public key in G2 */
    blst_p2 pk_p2;
    blst_sk_to_pk_in_g2(&pk_p2, &sk);

    /* Serialize keys */
    uint8_t sec_buf[SECRET_KEY_LEN];
    uint8_t pub_buf[PUBLIC_KEY_LEN];

    blst_bendian_from_scalar(sec_buf, &sk);
    blst_p2_compress(pub_buf, &pk_p2);

    /* Clear secret key object from memory */
    memset(&sk, 0, sizeof(sk));

    /* Write secret key */
    FILE *fp = fopen(privkey_path, "wb");
    if (!fp) {
        fprintf(stderr, "Error: Cannot create file %s\n", privkey_path);
        memset(sec_buf, 0, sizeof(sec_buf));
        return 1;
    }
    if (fwrite(sec_buf, 1, SECRET_KEY_LEN, fp) != SECRET_KEY_LEN) {
        fprintf(stderr, "Error: Failed to write secret key\n");
        fclose(fp);
        memset(sec_buf, 0, sizeof(sec_buf));
        return 1;
    }
    fclose(fp);

    /* Clear secret key buffer from memory */
    memset(sec_buf, 0, sizeof(sec_buf));

    /* Write public key */
    fp = fopen(pubkey_path, "wb");
    if (!fp) {
        fprintf(stderr, "Error: Cannot create file %s\n", pubkey_path);
        return 1;
    }
    if (fwrite(pub_buf, 1, PUBLIC_KEY_LEN, fp) != PUBLIC_KEY_LEN) {
        fprintf(stderr, "Error: Failed to write public key\n");
        fclose(fp);
        return 1;
    }
    fclose(fp);

    printf("Generated BLS keypair:\n");
    printf("  Secret key: %s (%d bytes)\n", privkey_path, SECRET_KEY_LEN);
    printf("  Public key: %s (%d bytes)\n", pubkey_path, PUBLIC_KEY_LEN);
    printf("\n");

    /* Print public key in hex for verification */
    print_hex("Public key (hex)", pub_buf, PUBLIC_KEY_LEN);

    return 0;
}
