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

## Parallel Authentication with RACH/RRC

The UE performs SIB1 authentication **in parallel** with RACH/RRC setup to minimize latency while protecting sensitive information (SUCI in NAS Registration).

### Security Constraint

**NAS Registration Request (containing SUCI) MUST NOT be sent until SIB1 is authenticated.**

If authentication fails, the RRC connection is aborted before any NAS message is transmitted.

### UE Types

| UE Type | Has K_0? | Authentication Method | Timing |
|---------|----------|----------------------|--------|
| First-time | No | Ed25519 signature | Immediate (fast) |
| Returning | Yes | TESLA MAC | Delayed (waits for key disclosure) |

### State Fields for Parallel Authentication

**Location**: `openair3/SECU/tf5_tesla.h`

```c
typedef struct {
    // ... existing fields ...

    // Parallel authentication state
    bool     k0_trusted;              // K_0 authenticated via Ed25519 (persistent)
    bool     sib1_authenticated;      // Current SIB1 verified (sig OR tesla)
    bool     auth_in_progress;        // Authentication running in parallel
    bool     auth_failed;             // Authentication failed - must abort RRC
    bool     rrcsetup_deferred;       // RRCSetupComplete deferred waiting for auth
    uint8_t  rrcsetup_transaction_id; // Saved transaction ID for deferred RRCSetupComplete
} tf5_tesla_ue_state_t;
```

---

## Parallel Authentication Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              SIB1 RECEIVED                                   │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
      ┌──────────────────────────────┴──────────────────────────────┐
      ▼                                                              ▼
┌─────────────────────┐                                    ┌─────────────────────┐
│   AUTHENTICATION    │                                    │   RACH/RRC SETUP    │
│     (PARALLEL)      │                                    │     (PARALLEL)      │
└─────────────────────┘                                    └─────────────────────┘
      │                                                              │
      ▼                                                              ▼
┌─────────────────────┐                                    ┌─────────────────────┐
│ k0_trusted == false │                                    │ Proceed immediately │
│   (First-time UE)   │                                    │  to Random Access   │
│   → Ed25519 verify  │                                    │                     │
│         OR          │                                    │  MSG1 → MSG2 → MSG3 │
│ k0_trusted == true  │                                    │       → MSG4        │
│   (Returning UE)    │                                    └─────────────────────┘
│   → Wait for TESLA  │                                              │
│     key disclosure  │                                              ▼
└─────────────────────┘                                    ┌─────────────────────┐
      │                                                    │ RRCSetup received   │
      ▼                                                    │ SRB1 established    │
┌─────────────────────┐                                    │                     │
│ Authentication      │                                    │ Check: auth done?   │
│ Result:             │──────────────────────────────────▶│ ├── YES + SUCCESS:  │
│ ├── SUCCESS:        │                                    │ │   Send NAS in      │
│ │   sib1_auth=true  │                                    │ │   RRCSetupComplete │
│ │   k0_trusted=true │                                    │ ├── YES + FAILED:   │
│ │   → trigger NAS   │                                    │ │   ABORT RRC        │
│ └── FAILED:         │                                    │ └── NO (pending):   │
│     auth_failed=true│                                    │     Defer RRCSetup- │
│     → ABORT RRC     │                                    │     Complete, wait  │
└─────────────────────┘                                    └─────────────────────┘
```

---

## SIB1 Processing Flow

**Location**: `nr_rrc_process_sib1()` in `openair2/RRC/NR_UE/rrc_UE.c`

### First-Time UE (k0_trusted == false)

```
1. Unpack TESLA extension from lateNonCriticalExtension

2. Build auth_input for signature verification
   └── Re-encode original SIB1 (without extension)
   └── tf5_tesla_build_auth_input()

3. Verify Ed25519 signature (synchronous - fast)
   └── tf5_tesla_ed25519_verify()
   ├── SUCCESS:
   │   └── Accept K_0: k0_trusted = true, sib1_authenticated = true
   │   └── If rrcsetup_deferred: send RRCSetupComplete now
   └── FAILED:
       └── auth_failed = true
       └── nr_rrc_abort_connection() → return

4. Buffer current SIB1 for future TESLA verification
```

### Returning UE (k0_trusted == true)

```
1. Unpack TESLA extension from lateNonCriticalExtension

2. Build auth_input for MAC verification

3. Check if disclosed key available for buffered SIB1
   └── If interval matches: tf5_tesla_ue_verify_buffered()
       ├── SUCCESS:
       │   └── sib1_authenticated = true
       │   └── If rrcsetup_deferred: send RRCSetupComplete now
       └── FAILED:
           └── auth_failed = true
           └── nr_rrc_abort_connection() → return
   └── If no key yet: auth_in_progress = true (keep waiting)

4. Buffer current SIB1 for future TESLA verification
```

---

## NAS Gating in RRCSetup Processing

**Location**: `nr_rrc_process_rrcsetup()` in `openair2/RRC/NR_UE/rrc_UE.c`

The RRC connection setup (bearers, cell group config) proceeds normally, but NAS message transmission is gated on authentication:

```c
if (tesla_state->auth_failed) {
    // Should not reach here normally - abort
    nr_rrc_abort_connection();
    return;
}

if (tesla_state->sib1_authenticated || tesla_state->k0_trusted) {
    // Auth succeeded - include NAS in RRCSetupComplete
    rrc_ue_generate_RRCSetupComplete();
    return;
}

// Auth in progress - defer RRCSetupComplete
tesla_state->rrcsetup_deferred = true;
tesla_state->rrcsetup_transaction_id = Transaction_id;
// RRCSetupComplete will be sent when auth completes
```

---

## RRC Connection Abort

**Location**: `nr_rrc_abort_connection()` in `openair2/RRC/NR_UE/rrc_UE.c`

Called when TESLA authentication fails (signature or MAC verification):

```c
static void nr_rrc_abort_connection(NR_UE_RRC_INST_t *rrc, int gNB_index)
{
    // Stop timers (SIB1, T300, T301, T319)
    // Reset RRC state to IDLE
    // Clear RNTI
    // Reset MAC (GO_TO_IDLE cause)
    // Clear TESLA pending state
}
```

**Security**: This ensures no NAS message (containing SUCI) is ever sent if SIB1 authentication fails, protecting against fake base station attacks.

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

---

## Security Summary

| Scenario | SUCI Protected? | Connection Aborted? |
|----------|-----------------|---------------------|
| First-time UE, Ed25519 succeeds | Yes | No |
| First-time UE, Ed25519 fails | Yes | **Yes** |
| Returning UE, TESLA MAC succeeds | Yes | No |
| Returning UE, TESLA MAC fails | Yes | **Yes** |
| Attacker spoofs SIB1 | Yes | **Yes** |

**Key Property**: NAS Registration is always gated on successful authentication. RACH/RRC can proceed in parallel, but SUCI is never exposed until SIB1 is verified.
