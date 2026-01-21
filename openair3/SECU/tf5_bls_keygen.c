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
 * Usage: tf5_bls_keygen <privkey_path> <pubkey_path>
 *
 * Key sizes (BLS12-381, non-ETH mode):
 *   - Secret key: 32 bytes (Fr element)
 *   - Public key: 96 bytes (G2 point, compressed)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <bls/bls.h>
#include <mcl/bn.h>

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
        fprintf(stderr, "  <privkey_path>  BLS secret key (32 bytes, raw binary)\n");
        fprintf(stderr, "  <pubkey_path>   BLS public key (96 bytes, raw binary)\n\n");
        fprintf(stderr, "Example:\n");
        fprintf(stderr, "  %s tesla_keys/gnb_tesla_privkey.bin tesla_keys/gnb_tesla_pubkey.bin\n", argv[0]);
        return 1;
    }

    const char *privkey_path = argv[1];
    const char *pubkey_path = argv[2];

    /* Initialize BLS library (BLS12-381, non-ETH mode) */
    int rc = blsInit(MCL_BLS12_381, MCLBN_COMPILED_TIME_VAR);
    if (rc != 0) {
        fprintf(stderr, "Error: blsInit failed with error %d\n", rc);
        return 1;
    }

    printf("BLS12-381 library initialized (non-ETH mode)\n");
    printf("  Signature size: 48 bytes (G1)\n");
    printf("  Public key size: 96 bytes (G2)\n\n");

    /* Generate keypair */
    blsSecretKey sec;
    blsPublicKey pub;

    if (blsSecretKeySetByCSPRNG(&sec) != 0) {
        fprintf(stderr, "Error: Failed to generate secret key\n");
        return 1;
    }

    blsGetPublicKey(&pub, &sec);

    /* Serialize keys */
    uint8_t sec_buf[SECRET_KEY_LEN];
    uint8_t pub_buf[PUBLIC_KEY_LEN];

    size_t sec_len = blsSecretKeySerialize(sec_buf, sizeof(sec_buf), &sec);
    if (sec_len != SECRET_KEY_LEN) {
        fprintf(stderr, "Error: Unexpected secret key size: %zu (expected %d)\n",
                sec_len, SECRET_KEY_LEN);
        return 1;
    }

    size_t pub_len = blsPublicKeySerialize(pub_buf, sizeof(pub_buf), &pub);
    if (pub_len != PUBLIC_KEY_LEN) {
        fprintf(stderr, "Error: Unexpected public key size: %zu (expected %d)\n",
                pub_len, PUBLIC_KEY_LEN);
        return 1;
    }

    /* Write secret key */
    FILE *fp = fopen(privkey_path, "wb");
    if (!fp) {
        fprintf(stderr, "Error: Cannot create file %s\n", privkey_path);
        return 1;
    }
    if (fwrite(sec_buf, 1, SECRET_KEY_LEN, fp) != SECRET_KEY_LEN) {
        fprintf(stderr, "Error: Failed to write secret key\n");
        fclose(fp);
        return 1;
    }
    fclose(fp);

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

    /* Clear secret key from memory */
    memset(&sec, 0, sizeof(sec));
    memset(sec_buf, 0, sizeof(sec_buf));

    printf("Generated BLS keypair:\n");
    printf("  Secret key: %s (%d bytes)\n", privkey_path, SECRET_KEY_LEN);
    printf("  Public key: %s (%d bytes)\n", pubkey_path, PUBLIC_KEY_LEN);
    printf("\n");

    /* Print public key in hex for verification */
    print_hex("Public key (hex)", pub_buf, PUBLIC_KEY_LEN);

    return 0;
}
