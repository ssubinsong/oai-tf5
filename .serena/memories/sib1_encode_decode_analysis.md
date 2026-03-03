# SIB1 Encode-Decode Byte-Identity Analysis

## Summary
**YES, byte-identical output is achievable IF implemented correctly.** The gNB-side and UE-side both null `lateNonCriticalExtension` and encode only the NR_SIB1 structure (not BCCH-DL-SCH-Message), which is the correct approach for deterministic re-encoding.

However, there are **potential sources of non-determinism** related to UPER extension handling that require careful consideration.

---

## Key Findings

### 1. Encoding Approach: Both Sides Encode NR_SIB1, Not BCCH-DL-SCH-Message

**gNB side (nr_radio_config.c:4385-4397):**
- Extracts `NR_SIB1_t *sib1` from `cc->sib1->message.choice.c1->choice.systemInformationBlockType1`
- Nulls `lateNonCriticalExtension`
- Encodes using `asn_DEF_NR_SIB1` (NOT `asn_DEF_NR_BCCH_DL_SCH_Message`)
- Restores `lateNonCriticalExtension`

**UE side (rrc_UE.c:543-568, tf5_encode_sib1_for_auth):**
- Receives NR_SIB1_t already decoded from BCCH-DL-SCH-Message
- Nulls `lateNonCriticalExtension`
- Encodes using `asn_DEF_NR_SIB1` (identical to gNB)
- Restores `lateNonCriticalExtension`

This design choice is **explicitly documented** at line 4388-4389: "CRITICAL: Must encode NR_SIB1 (not NR_BCCH_DL_SCH_Message) to match UE-side verification which also encodes just NR_SIB1"

### 2. Decoding Path: BCCH-DL-SCH-Message → NR_SIB1_t

**UE decode flow (rrc_UE.c:2006-2061):**
1. Receives BCCH-DL-SCH message bytes in SDU
2. Decodes as `NR_BCCH_DL_SCH_Message_t` using `uper_decode_complete(&asn_DEF_NR_BCCH_DL_SCH_Message, ...)`
3. Extracts SIB1: `bcch_message->message.choice.c1->choice.systemInformationBlockType1`
4. Passes SIB1 to `nr_rrc_process_sib1()` and eventually to `tf5_verify_sib1()`

This extraction **does not re-serialize**; the NR_SIB1_t structure is directly extracted from the decoded BCCH message structure.

### 3. ASN.1 Structure: NR_SIB1 Has Both nonCriticalExtension AND lateNonCriticalExtension

**NR_SIB1.h (lines 100-105):**
```c
typedef struct NR_SIB1 {
    // ... 12 fields ...
    OCTET_STRING_t *lateNonCriticalExtension;  /* OPTIONAL */
    struct NR_SIB1_v1610_IEs *nonCriticalExtension; /* OPTIONAL */
    asn_struct_ctx_t _asn_ctx;
} NR_SIB1_t;
```

**Key distinction:**
- `nonCriticalExtension` is an ASN.1 SEQUENCE extension (version-controlled, follows UPER extension rules)
- `lateNonCriticalExtension` is an OCTET_STRING (opaque binary blob at end, not subject to UPER extension encoding)

### 4. UPER Encoding Rules and Extensions

When `uper_encode_to_buffer(&asn_DEF_NR_SIB1, NULL, sib1, ...)` is called with `nonCriticalExtension != NULL`:

**UPER extension encoding includes:**
1. Extension bit: If nonCriticalExtension is present, extension root is marked
2. Extension length: Number of octets encoding all extensions
3. Extension fields: Each field is prefixed with presence bitmap and length

This means **if nonCriticalExtension differs in any way between gNB and UE, the entire UPER stream will differ**, even if the core SIB1 fields are identical.

**Critical question:** Do gNB and UE have **identical nonCriticalExtension content**?

### 5. Potential Sources of Non-Determinism

#### A. nonCriticalExtension Chain (Unlikely But Possible)
The gNB SIB1 is constructed with a potentially different `nonCriticalExtension` tree than what the UE decodes. This could happen if:
- gNB initializes SIB1 from configuration with v1610, v1630, v1700 IEs
- Network provides different extension versions on different SIBs
- UE decodes receives BCCH-DL-SCH which contains the same SIB1 with those extensions

**In TF5 code, both should decode/process the same BCCH-DL-SCH message**, so they should have identical nonCriticalExtension.

#### B. Pointer vs Memory State Issues
ASN.1 structures use pointers. If the decoded SIB1 is modified after decoding but before re-encoding:
- Any field set/modified would change encoding
- The code properly **does not modify** the SIB1 between extraction and re-encoding (only temporarily nulls lateNonCriticalExtension)

#### C. UPER Encoding Determinism
UPER encoding in asn1c-0.9.29 should be **fully deterministic** for identical input structures (given the same compiler, same asn1c version). However:
- Presence bitmaps must be accurately set in ASN.1 structures
- Optional fields must be strictly NULL or non-NULL (not partially initialized)
- Bit padding at message boundaries must be handled consistently

### 6. Why Byte-Identity is Achievable

1. **Both encode NR_SIB1 directly**: No wrapper layer (BCCH-DL-SCH) encoding difference
2. **Both null lateNonCriticalExtension**: Ensures signature input is "clean" SIB1
3. **Both extract from same BCCH-DL-SCH**: UE decodes the gNB-sent message
4. **Both use same asn_DEF_NR_SIB1**: Same encoder/decoder definition
5. **UPER is deterministic**: Given identical input, produces identical output

---

## Verification Strategy

To ensure byte-identity:

1. **Before encoding, verify nonCriticalExtension state:**
   - Print/log the entire nonCriticalExtension tree (if present)
   - Confirm gNB and UE have identical pointers/values

2. **Capture both encodings:**
   - gNB: Already captured in `cc->sib1_original[cc->sib1_original_length]` (line 4395-4401)
   - UE: Captured in `sib1_buf[sib1_len]` (line 791-796)

3. **Compare byte-by-byte:**
   - Log both encodings in hex
   - They should match exactly

4. **If they differ, check for:**
   - Pointer differences in nonCriticalExtension chain
   - Optional field presence flags (NULL vs allocated)
   - Memory initialization differences (memset vs calloc behavior)

---

## ASN.1 Encoder Used

**asn1c version:** 0.9.29
**Codec:** UPER (Unaligned Packed Encoding Rules)
**Encoding mode:** `-gen-UPER` (no BER, JER, OER, or APER)
**Compiler flags:** `-pdu=all -fcompound-names -no-gen-example -findirect-choice`

---

## Code Locations

| Component | File | Line | Function |
|-----------|------|------|----------|
| gNB encode for signing | nr_radio_config.c | 4385-4397 | nr_mac_update_sib1_tf5() |
| gNB full BCCH encode | nr_radio_config.c | 3024-3032 | encode_SIB_NR() |
| UE re-encode | rrc_UE.c | 543-568 | tf5_encode_sib1_for_auth() |
| UE verify call | rrc_UE.c | 758-802 | tf5_verify_sib1() |
| UE BCCH decode | rrc_UE.c | 2006-2061 | nr_rrc_ue_decode_NR_BCCH_DL_SCH_Message() |
| SIB1 struct def | NR_SIB1.h | 58-105 | NR_SIB1_t typedef |
