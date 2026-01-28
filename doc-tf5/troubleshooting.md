# Troubleshooting & Log Verification

[Back to Index](index.md)

---

## Verifying TESLA is Working

All TESLA log messages are prefixed with `TESLA:` for easy filtering.

---

## gNB Side - Successful Startup

Look for these messages in gNB logs:

```
[NR_RRC] TESLA: BLST library ready (BLS12-381, pk-in-G2 mode)
[NR_RRC] TESLA: Key chain generated with N intervals
[NR_RRC] TESLA IBS: gNB initialized - T_int=160ms, d=2, T_0=SFN0.0
```

These indicate the gNB has:
1. Initialized the BLS signature library
2. Generated the TESLA key chain
3. Started TESLA with configured parameters

---

## UE Side - Successful Authentication

### First-Time UE (Signature Verification Path)

```
[NR_RRC] TESLA: Loaded gNB public key from ./tesla_keys/gnb_tesla_pubkey.bin
[NR_RRC] TESLA: First-time UE - K_0 authenticated via BLS, K_N accepted as anchor
[NR_RRC] TESLA: Initial timesync OK (diff=X slots, max=Y, E_sync=Z us)
[NR_RRC] TESLA: MAC verification SUCCESS for slot X (interval Y)
[NR_RRC] TESLA: Auth complete - sending deferred RRCSetupComplete
```

### Returning UE (TESLA MAC Path)

```
[NR_RRC] TESLA: Returning UE - using TESLA for SIB1 authentication
[NR_RRC] TESLA: MAC verification SUCCESS for slot X (interval Y)
[NR_RRC] TESLA: Returning UE - N SIB1(s) MAC verified (interval Y)
```

**Key indicator**: If you see `Auth complete - sending deferred RRCSetupComplete`, TESLA verification succeeded.

---

## Common Error Messages

| Message | Meaning | Action |
|---------|---------|--------|
| `Failed to load gNB public key` | Key file missing or wrong path | Run `./scripts/tf5_generate_bls_keys.sh` and check key paths |
| `Signature verification FAILED - aborting RRC` | BLS signature invalid | Verify gNB and UE use same public key |
| `All MAC verification(s) FAILED` | TESLA MAC mismatch | Check time sync between gNB and UE |
| `Safe packet test FAILED - possible replay` | Key disclosed too early | May indicate clock drift or attack |
| `Key chain verification FAILED` | Disclosed key doesn't chain to anchor | Verify key chain integrity |
| `Initial timesync FAILED` | Time difference too large | Check SSB synchronization |

---

## Log Filtering Commands

```bash
# Show all TESLA messages
grep "TESLA:" <logfile>

# Show only success indicators
grep "TESLA:" <logfile> | grep -E "(initialized|SUCCESS|authenticated|verified|complete)"

# Show errors and warnings
grep "TESLA:" <logfile> | grep -E "(FAILED|ERROR|aborting)"

# Real-time monitoring (during execution)
tail -f <logfile> | grep "TESLA:"
```

---

## Expected Authentication Flow

| Step | gNB Log | UE Log |
|------|---------|--------|
| 1. Startup | `Key chain generated`, `gNB initialized` | `Loaded gNB public key` |
| 2. SIB1 sent | `Prepared extension for interval N` | - |
| 3. SIB1 received | - | `Auth in progress - deferring RRCSetupComplete` |
| 4. Signature check | - | `K_0 authenticated via BLS` |
| 5. Time sync | - | `Initial timesync OK` |
| 6. MAC verification | - | `MAC verification SUCCESS` |
| 7. Complete | - | `Auth complete - sending deferred RRCSetupComplete` |

---

## Debug Logging

To enable verbose TESLA debug logs, set the log level for NR_RRC to debug:

```bash
# In config file or command line
--log_config.NR_RRC_log_level debug
```

This will show additional `LOG_D` messages including:
- Buffer operations
- Key chain state
- Intermediate verification steps
