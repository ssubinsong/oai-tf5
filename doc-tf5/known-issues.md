# Known Issues

## 1. Returning UE cannot re-trigger RACH after reconnection

**Severity:** High — blocks reconnection for returning UEs
**Location:** `openair2/RRC/NR_UE/rrc_UE.c` (`tf5_verify_returning`, `nr_rrc_process_sib1`)

### Problem

`tf5_ue_free()` is never called in production, so `chain_bootstrapped` persists
for the process lifetime. After the first connection completes
(`RRCSETUP_COMPLETE`), if the UE returns to IDLE and attempts a new connection,
the returning-path (`tf5_verify_returning`) always returns
`TF5_VERIFY_BUFFERED`, which causes `nr_rrc_process_sib1` to return early —
RACH is never triggered and system info is never processed.

### Suggested fix

Add a new return value `TF5_VERIFY_BUFFERED_RACH` for the first SIB1 of a new
connection (when phase transitions `INITIAL -> BUFFERED`), and handle it in
`nr_rrc_process_sib1` to fall through to RACH trigger.

---

## 2. No timeout for `RRCSETUP_DEFERRED` state

**Severity:** Medium — can leave UE stuck indefinitely
**Location:** `openair2/RRC/NR_UE/rrc_UE.c` (`tf5_verify_sib1`)

### Problem

If the UE enters `RRCSETUP_DEFERRED` and TESLA verification never succeeds
(e.g., persistent key-chain mismatch or gNB restart), the UE is stuck
indefinitely. T300 is already stopped when RRCSetup is received
(`rrc_UE.c:2318`), so it cannot cover this case.

### Suggested fix

Add a `deferred_sib1_count` counter to `tf5_ue_state_t`, increment on each
SIB1 processed while in `RRCSETUP_DEFERRED`, and abort the deferred path after
a configurable limit (e.g., 10 SIB1 broadcasts). On abort, the UE should
discard the pending RRCSetup and fall back to the first-time authentication
path.

---

## 3. TESLA key recovery not implemented

**Status:** By design (removed for delay measurement simplification)

Multi-step TESLA key chain recovery (RFC 4082 §3: "if intermediate values
of the one-way chain are lost, they can be recomputed using subsequent values
in the chain") is not implemented. If the UE misses a key disclosure interval,
the buffered SIB1 from that interval cannot be verified. Only consecutive
(1-step) key chain verification is supported.
