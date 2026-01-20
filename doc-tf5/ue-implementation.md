# UE-Side Implementation

[Back to Index](index.md)

---

## Initialization

**Location**: `openair2/RRC/NR_UE/rrc_UE.c`

```c
// Allocate TESLA state
SI_info->tesla_state = calloc(1, sizeof(tf5_tesla_ue_state_t));

// Initialize with pre-provisioned gNB public key
tf5_tesla_ue_init(SI_info->tesla_state, gnb_public_key, slots_per_frame);
```

**Note**: The gNB public key must be pre-provisioned on the UE. In the current implementation, it's hardcoded for testing.

---

## SIB1 Reception Flow

```
1. Check for TESLA extension
   └── sib1->message.lateNonCriticalExtension

2. Unpack extension
   └── tf5_tesla_unpack_extension()

3. Store static params (first reception)
   └── Copy to UE state

4. Build auth_input for verification
   └── tf5_tesla_build_auth_input()

5. Verify Ed25519 signature (IMMEDIATE)
   └── tf5_tesla_ue_verify_signature()
       └── If valid: SIB1 is authenticated

6. Check buffered SIB1 verification (DELAYED)
   └── If disclosed_key available for buffered message:
       └── tf5_tesla_ue_verify_buffered()

7. Buffer current SIB1
   └── tf5_tesla_ue_buffer_sib1()
```

---

## Safe Packet Test

The safe packet test determines if a message could have been forged by an attacker who saw a key disclosure:

```c
bool tf5_tesla_ue_safe_packet_test(state, ext, rx_sfn, rx_slot) {
    // Get ti_hfn from signed extension (trusted)
    uint16_t ref_hfn = ext->dynamic_params.ti_hfn;

    // Initialize or verify HFN tracking
    if (!state->hfn_initialized) {
        state->current_hfn = ref_hfn;  // Bootstrap
        state->hfn_initialized = true;
    } else {
        // Check for HFN mismatch (potential replay)
        if (abs(ref_hfn - state->current_hfn) > 1) {
            return false;  // Possible replay attack
        }
    }

    // Compute current interval
    uint32_t x = compute_interval(ref_hfn, rx_sfn, rx_slot, ...);
    uint32_t i = ext->dynamic_params.interval_index;
    uint8_t d = ext->static_params.disclosure_delay;

    // Safe if: x < i + d
    return (x < i + d);
}
```

---

## Key Chain Verification

When verifying a disclosed key:

```c
bool tf5_tesla_ue_verify_key_chain(state, disclosed_key, key_index) {
    // Case 1: First key verification - chain to root K_0
    // Case 2: Subsequent - chain to last verified key

    // Apply F repeatedly until reaching known key
    uint8_t computed_key[16];
    memcpy(computed_key, disclosed_key, 16);

    for (uint32_t i = key_index; i > target_index; i--) {
        tf5_tesla_chain_key(computed_key, computed_key);
    }

    // Compare with known key
    return memcmp(computed_key, known_key, 16) == 0;
}
```
