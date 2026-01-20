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

**CRITICAL SECURITY REQUIREMENT**: K_0 must be authenticated via Ed25519 signature BEFORE being accepted.
RFC 4082 Section 3.3 requires the root commitment to be signed by the sender.

```
1. Check for TESLA extension
   └── sib1->message.lateNonCriticalExtension

2. Unpack extension
   └── tf5_tesla_unpack_extension()

3. Build auth_input for signature verification
   └── Re-encode original SIB1 (without extension)
   └── tf5_tesla_build_auth_input()

4. Verify Ed25519 signature (REQUIRED - AssertFatal if no public key)
   └── tf5_tesla_ed25519_verify()
   └── If FAILED: Reject SIB1 immediately (return)
   └── K_0 is NOT trusted until this succeeds

5. Accept K_0: Store static params ONLY after signature verification
   └── Copy authenticated static_params (including K_0) to UE state
   └── Set initialized = true

6. Verify buffered SIB1 (DELAYED authentication)
   └── tf5_tesla_ue_verify_buffered() which includes:
       a. tf5_tesla_ue_verify_key_chain() - verify disclosed key chains to K_0
       b. tf5_tesla_compute_tag() - compute expected MAC
       c. Compare with buffered tag

7. Buffer current SIB1
   └── tf5_tesla_ue_buffer_sib1()
```

**Design Assumption**: The UE always has a pre-provisioned gNB public key. If not available, the code will AssertFatal.

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

Key chain verification is called automatically by `tf5_tesla_ue_verify_buffered()` before MAC verification.
This ensures disclosed keys are cryptographically validated against the authenticated K_0.

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

    // Compare with known key (K_0 or last verified key)
    return memcmp(computed_key, known_key, 16) == 0;
}
```

**Security Note**: If a disclosed key does not chain to K_0, `tf5_tesla_ue_verify_buffered()` returns error -6
and the buffered SIB1 MAC verification is rejected. This prevents use of forged keys.
