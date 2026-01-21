# API Reference

[Back to Index](index.md)

---

## gNB API

**Source**: [tf5_tesla.h](../openair3/SECU/tf5_tesla.h), [tf5_tesla.c](../openair3/SECU/tf5_tesla.c)

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

| Function | Header | Implementation |
|----------|--------|----------------|
| `tf5_tesla_gnb_init` | [tf5_tesla.h:212](../openair3/SECU/tf5_tesla.h#L212) | [tf5_tesla.c:319](../openair3/SECU/tf5_tesla.c#L319) |
| `tf5_tesla_gnb_free` | [tf5_tesla.h:227](../openair3/SECU/tf5_tesla.h#L227) | [tf5_tesla.c:393](../openair3/SECU/tf5_tesla.c#L393) |
| `tf5_tesla_gnb_get_interval` | [tf5_tesla.h:239](../openair3/SECU/tf5_tesla.h#L239) | [tf5_tesla.c:406](../openair3/SECU/tf5_tesla.c#L406) |
| `tf5_tesla_gnb_prepare_extension` | [tf5_tesla.h:277](../openair3/SECU/tf5_tesla.h#L277) | [tf5_tesla.c:425](../openair3/SECU/tf5_tesla.c#L425) |
| `tf5_tesla_pack_extension` | [tf5_tesla.h:292](../openair3/SECU/tf5_tesla.h#L292) | [tf5_tesla.c:200](../openair3/SECU/tf5_tesla.c#L200) |

---

## UE API

**Source**: [tf5_tesla.h](../openair3/SECU/tf5_tesla.h), [tf5_tesla.c](../openair3/SECU/tf5_tesla.c)

```c
// Initialize UE state
int tf5_tesla_ue_init(tf5_tesla_ue_state_t *state,
                      const uint8_t gnb_public_key[96],
                      uint16_t slots_per_frame);

// Free resources
void tf5_tesla_ue_free(tf5_tesla_ue_state_t *state);

// Unpack extension from binary
int tf5_tesla_unpack_extension(const uint8_t *buf,
                               size_t buf_len,
                               tf5_tesla_extension_t *ext);

// Verify BLS signature
int tf5_tesla_ue_verify_signature(const tf5_tesla_ue_state_t *state,
                                  const uint8_t *auth_input,
                                  size_t auth_input_len,
                                  const uint8_t signature[48]);

// Safe packet test (also initializes HFN tracking)
// Note: Uses state->static_params (cached from first authenticated SIB1)
//       Only ext->interval_index is used from the extension parameter
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

| Function | Header | Implementation |
|----------|--------|----------------|
| `tf5_tesla_ue_init` | [tf5_tesla.h:310](../openair3/SECU/tf5_tesla.h#L310) | [tf5_tesla.c:512](../openair3/SECU/tf5_tesla.c#L512) |
| `tf5_tesla_ue_free` | [tf5_tesla.h:319](../openair3/SECU/tf5_tesla.h#L319) | [tf5_tesla.c:550](../openair3/SECU/tf5_tesla.c#L550) |
| `tf5_tesla_unpack_extension` | [tf5_tesla.h:329](../openair3/SECU/tf5_tesla.h#L329) | [tf5_tesla.c:257](../openair3/SECU/tf5_tesla.c#L257) |
| `tf5_tesla_ue_verify_signature` | [tf5_tesla.h:342](../openair3/SECU/tf5_tesla.h#L342) | — |
| `tf5_tesla_ue_safe_packet_test` | [tf5_tesla.h:368](../openair3/SECU/tf5_tesla.h#L368) | [tf5_tesla.c:571](../openair3/SECU/tf5_tesla.c#L571) |
| `tf5_tesla_ue_buffer_sib1` | [tf5_tesla.h:386](../openair3/SECU/tf5_tesla.h#L386) | [tf5_tesla.c:629](../openair3/SECU/tf5_tesla.c#L629) |
| `tf5_tesla_ue_verify_buffered` | [tf5_tesla.h:403](../openair3/SECU/tf5_tesla.h#L403) | [tf5_tesla.c:663](../openair3/SECU/tf5_tesla.c#L663) |
| `tf5_tesla_ue_verify_key_chain` | [tf5_tesla.h:417](../openair3/SECU/tf5_tesla.h#L417) | [tf5_tesla.c:722](../openair3/SECU/tf5_tesla.c#L722) |

---

## File I/O Functions

**Source**: [tf5_tesla.h](../openair3/SECU/tf5_tesla.h), [tf5_tesla.c](../openair3/SECU/tf5_tesla.c)

```c
// Load BLS secret key from binary file
// Returns: 0 on success, negative on error
//   -1: Cannot open file
//   -2: File read error or wrong size
//   -3: Invalid key format
int tf5_tesla_load_privkey(const char *filepath, uint8_t privkey_out[32]);

// Load BLS public key from binary file
// Returns: 0 on success, negative on error
//   -1: Cannot open file
//   -2: File read error or wrong size
//   -3: Invalid key format
int tf5_tesla_load_pubkey(const char *filepath, uint8_t pubkey_out[96]);
```

| Function | Header | Implementation |
|----------|--------|----------------|
| `tf5_tesla_load_privkey` | [tf5_tesla.h:581](../openair3/SECU/tf5_tesla.h#L581) | [tf5_tesla.c](../openair3/SECU/tf5_tesla.c) |
| `tf5_tesla_load_pubkey` | [tf5_tesla.h:594](../openair3/SECU/tf5_tesla.h#L594) | [tf5_tesla.c](../openair3/SECU/tf5_tesla.c) |

---

## Utility Functions

**Source**: [tf5_tesla.h](../openair3/SECU/tf5_tesla.h), [tf5_tesla.c](../openair3/SECU/tf5_tesla.c)

```c
// Build MAC authentication input (excludes interval_index/disclosed_key per RFC 4082)
int tf5_tesla_build_mac_auth_input(uint8_t *out,
                                   size_t *out_len,
                                   const uint8_t *original_sib1,
                                   size_t sib1_len,
                                   const tf5_tesla_static_params_t *static_params,
                                   const tf5_tesla_timesync_info_t *timesync_info);

// Build signature authentication input (full content)
int tf5_tesla_build_sig_auth_input(uint8_t *out,
                                   size_t *out_len,
                                   const uint8_t *original_sib1,
                                   size_t sib1_len,
                                   const tf5_tesla_static_params_t *static_params,
                                   const tf5_tesla_timesync_info_t *timesync_info,
                                   uint32_t interval_index,
                                   const uint8_t disclosed_key[16]);

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

| Function | Header | Implementation |
|----------|--------|----------------|
| `tf5_tesla_build_auth_input` | [tf5_tesla.h:257](../openair3/SECU/tf5_tesla.h#L257) | [tf5_tesla.c:149](../openair3/SECU/tf5_tesla.c#L149) |
| `tf5_tesla_derive_mac_key` | [tf5_tesla.h:466](../openair3/SECU/tf5_tesla.h#L466) | [tf5_tesla.c:48](../openair3/SECU/tf5_tesla.c#L48) |
| `tf5_tesla_chain_key` | [tf5_tesla.h:477](../openair3/SECU/tf5_tesla.h#L477) | [tf5_tesla.c:62](../openair3/SECU/tf5_tesla.c#L62) |
| `tf5_tesla_compute_tag` | [tf5_tesla.h:491](../openair3/SECU/tf5_tesla.h#L491) | [tf5_tesla.c:79](../openair3/SECU/tf5_tesla.c#L79) |
| `tf5_tesla_slots_since_t0` | [tf5_tesla.h:511](../openair3/SECU/tf5_tesla.h#L511) | [tf5_tesla.c:103](../openair3/SECU/tf5_tesla.c#L103) |
| `tf5_tesla_get_interval_index` | [tf5_tesla.h:532](../openair3/SECU/tf5_tesla.h#L532) | [tf5_tesla.c:121](../openair3/SECU/tf5_tesla.c#L121) |
