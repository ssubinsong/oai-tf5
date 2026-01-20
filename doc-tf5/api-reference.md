# API Reference

[Back to Index](index.md)

---

## gNB API

```c
// Initialize TESLA state
int tf5_tesla_gnb_init(tf5_tesla_gnb_state_t *state,
                       uint16_t t_int_ms,      // Interval duration (20)
                       uint8_t d,              // Disclosure delay (1)
                       uint32_t chain_len,     // Number of intervals (65536)
                       const uint8_t private_key[32],
                       uint16_t hfn,           // Initial HFN (0)
                       uint16_t sfn,           // T_0 SFN
                       uint16_t slot,          // T_0 slot
                       uint16_t slots_per_frame);

// Free resources
void tf5_tesla_gnb_free(tf5_tesla_gnb_state_t *state);

// Get current interval (updates HFN tracking)
uint32_t tf5_tesla_gnb_get_interval(tf5_tesla_gnb_state_t *state,
                                    uint16_t sfn,
                                    uint16_t slot);

// Prepare TESLA extension for transmission
int tf5_tesla_gnb_prepare_extension(tf5_tesla_gnb_state_t *state,
                                    uint16_t sfn,
                                    uint16_t slot,
                                    const uint8_t *original_sib1,
                                    size_t sib1_len,
                                    tf5_tesla_extension_t *ext);

// Pack extension to binary
int tf5_tesla_pack_extension(const tf5_tesla_extension_t *ext,
                             uint8_t *buf,
                             size_t buf_len);
```

---

## UE API

```c
// Initialize UE state
int tf5_tesla_ue_init(tf5_tesla_ue_state_t *state,
                      const uint8_t gnb_public_key[32],
                      uint16_t slots_per_frame);

// Free resources
void tf5_tesla_ue_free(tf5_tesla_ue_state_t *state);

// Unpack extension from binary
int tf5_tesla_unpack_extension(const uint8_t *buf,
                               size_t buf_len,
                               tf5_tesla_extension_t *ext);

// Verify Ed25519 signature
int tf5_tesla_ue_verify_signature(const tf5_tesla_ue_state_t *state,
                                  const uint8_t *auth_input,
                                  size_t auth_input_len,
                                  const uint8_t signature[64]);

// Safe packet test (also initializes HFN tracking)
bool tf5_tesla_ue_safe_packet_test(tf5_tesla_ue_state_t *state,
                                   const tf5_tesla_extension_t *ext,
                                   uint16_t rx_sfn,
                                   uint16_t rx_slot);

// Buffer SIB1 for delayed verification
int tf5_tesla_ue_buffer_sib1(tf5_tesla_ue_state_t *state,
                             const uint8_t *auth_input,
                             size_t auth_input_len,
                             uint32_t interval_index,
                             const uint8_t tag[16],
                             uint16_t ti_hfn,
                             uint16_t rx_sfn,
                             uint16_t rx_slot);

// Verify buffered SIB1 with disclosed key
int tf5_tesla_ue_verify_buffered(tf5_tesla_ue_state_t *state,
                                 const uint8_t disclosed_key[16],
                                 uint32_t key_interval);

// Verify key chain integrity
bool tf5_tesla_ue_verify_key_chain(tf5_tesla_ue_state_t *state,
                                   const uint8_t disclosed_key[16],
                                   uint32_t key_index);
```

---

## File I/O Functions

```c
// Load Ed25519 private key from PEM file
// Returns: 0 on success, negative on error
//   -1: Cannot open file
//   -2: Cannot parse PEM
//   -3: Cannot extract raw key
int tf5_tesla_load_privkey(const char *filepath, uint8_t privkey_out[32]);

// Load Ed25519 public key from PEM certificate file
// Returns: 0 on success, negative on error
//   -1: Cannot open file
//   -2: Cannot parse certificate
//   -3: Cannot extract public key from certificate
//   -4: Cannot extract raw key
int tf5_tesla_load_cert_pubkey(const char *filepath, uint8_t pubkey_out[32]);
```

---

## Utility Functions

```c
// Build authentication input
int tf5_tesla_build_auth_input(uint8_t *out,
                               size_t *out_len,
                               const uint8_t *original_sib1,
                               size_t sib1_len,
                               const tf5_tesla_static_params_t *static_params,
                               const tf5_tesla_dynamic_params_t *dynamic_params);

// Derive MAC key from TESLA key
void tf5_tesla_derive_mac_key(const uint8_t key_in[16],
                              uint8_t mac_key_out[32]);

// Compute key chain (K_i from K_{i+1})
void tf5_tesla_chain_key(const uint8_t key_next[16],
                         uint8_t key_out[16]);

// Compute TESLA tag
int tf5_tesla_compute_tag(const uint8_t key[16],
                          const uint8_t *auth_input,
                          size_t auth_input_len,
                          uint8_t tag_out[16]);

// Get slots since T_0 (with HFN)
uint64_t tf5_tesla_slots_since_t0(uint16_t current_hfn,
                                  uint16_t current_sfn,
                                  uint16_t current_slot,
                                  uint16_t t0_hfn,
                                  uint16_t t0_sfn,
                                  uint16_t t0_slot,
                                  uint16_t slots_per_frame);

// Get interval index
uint32_t tf5_tesla_get_interval_index(uint16_t hfn,
                                      uint16_t sfn,
                                      uint16_t slot,
                                      uint16_t t0_hfn,
                                      uint16_t t0_sfn,
                                      uint16_t t0_slot,
                                      uint16_t t_int_ms,
                                      uint16_t slots_per_frame);
```
