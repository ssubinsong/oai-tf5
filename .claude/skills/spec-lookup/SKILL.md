---
name: spec-lookup
description: Look up RFC or 3GPP specs from local reference corpus
---

# Spec Lookup

Look up a specific RFC or 3GPP TS spec from the local corpus under `claude-ref/`.

Arguments: spec identifier (e.g., `rfc4082`, `38.212`, `TS 38.331`)

## Steps

1. Parse the spec identifier from arguments
2. For RFCs: search in `claude-ref/rfc/` for matching `.txt` files
   - e.g., `rfc4082` → `claude-ref/rfc/rfc4082.txt`
3. For 3GPP: search in `claude-ref/3gpp/` — TS numbers map to directory names
   - e.g., TS 38.212 → `claude-ref/3gpp/38212-*/38212-*.html` (or `.txt`)
   - Strip the dot from TS number: `38.212` → `38212`
4. Read and summarize the relevant sections
5. If a specific section/clause is requested, navigate directly to it

## File naming conventions
- RFC: `claude-ref/rfc/rfc{number}.txt`
- 3GPP: `claude-ref/3gpp/{tsnum}-{version}/{tsnum}-{version}.html` (fallback: `.txt`)

## Tips
- Use Grep to search within large spec files for specific keywords
- 3GPP specs can be very large — read specific sections rather than the entire file
- Cross-reference related specs when needed (e.g., 38.212 for channel coding, 38.331 for RRC)
