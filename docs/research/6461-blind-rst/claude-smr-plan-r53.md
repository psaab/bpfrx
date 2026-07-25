# Claude SMR hostile plan-review — round 53 (v9.9.51 @ f8f03bbe9)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — I wrote the
v9.9.51 folds; this pass attacks them. Verdict: **PLAN NO for
v9.9.51-as-committed** — two precision pins (all LOW; no design defect
found). The v9.9.51 mechanisms verify sound in direction against code.

## Finding 1 (nit — the golden vectors are complete (input, key, output) triples)

The vectors' power is only as good as their completeness: each vector
must pin the ENTIRE input byte string (both HELLO payloads and both
capability records, every field value written out — not a
"representative" subset), the exact HMAC key bytes used, and the
expected output — for BOTH roles. A vector that leaves any field
unpinned lets two "conforming" implementations diverge on that field.

## Finding 2 (nit — the bits-packed u32's assignment table is enumerated)

The capability bits' LSB-first packing needs its table: bit 0 =
identity-enforcement, bit 1 = lease-input, bit 2 = repair-vN, bit 3 =
reset-vN, bit 4 = heartbeat-ack-capable, bits 5-31 reserved-zero — so
"packed LSB-first" is unambiguous to an implementer.

## Verified sound this round (my own re-trace)

- r52-B1 fold: the term grammar (u16-LE(len) || raw payload, header
  excluded) + the fixed-layout cap record make both directions
  byte-identical (with Findings 1-2's pins).
- r52-M2 fold: the advertisement-only HELLO + same-connection CONFIRM
  rule is now the only capability contract (my grep finds no
  activation path that skips the CONFIRM on a v1-proof connection).

## Verdict

**PLAN NO for v9.9.51** — fold Findings 1-2 as v9.9.52 (precision pins;
no design change). Part A remains converged and untouched.
