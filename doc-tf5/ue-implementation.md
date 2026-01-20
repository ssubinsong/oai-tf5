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

## Key Chain Verification (O(1) Optimization)

Key chain verification is called automatically by `tf5_tesla_ue_verify_buffered()` before MAC verification.
This ensures disclosed keys are cryptographically validated against a trusted anchor key.

### Anchor Key Strategy

Instead of chaining every disclosed key back to K_0 (which requires O(i) hash operations), the UE uses the **last verified key** as anchor:

1. **First SIB1 (interval i)**: Ed25519 signature authenticates both K_0 and K_{i-d}
   - K_{i-d} becomes the anchor (0 hash ops - signature authenticated)
2. **Subsequent SIB1s**: New disclosed key verified against last anchor
   - Verify: F(K_{new}) == K_{anchor}? (typically 1 hash op)
   - Anchor updates to K_{new} after successful verification

### Example (d=1)

```
Interval i (UE joins): anchor = K_{i-1}  (signature authenticated)
Interval i+1: verify K_i → K_{i-1} (1 hash), anchor = K_i
Interval i+2: verify K_{i+1} → K_i (1 hash), anchor = K_{i+1}
...
```

### Implementation

```c
bool tf5_tesla_ue_verify_key_chain(state, disclosed_key, key_index) {
    // Require valid anchor (set by Ed25519 or previous TESLA verification)
    if (!state->last_verified_key_valid) return false;

    if (key_index > state->last_verified_key_idx) {
        // Chain from disclosed key down to anchor
        uint32_t steps = key_index - state->last_verified_key_idx;
        // Apply F 'steps' times and compare with anchor
        // O(1) for consecutive intervals
    }
    return true;
}
```

**Security Note**: If a disclosed key does not chain to the anchor, `tf5_tesla_ue_verify_buffered()` returns error -6
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
