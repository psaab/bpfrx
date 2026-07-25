# Claude SMR hostile plan-review — round 52 (v9.9.49 @ b3597980b)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — I wrote the
v9.9.49 folds; this pass attacks them. Verdict: **PLAN NO for
v9.9.49-as-committed** — two precision pins (all LOW; no design defect
found). The v9.9.49 mechanisms verify sound in direction against code.

## Finding 1 (nit — the cap records enter the proof as WIRE bytes, never reconstructed)

The formula's determinism needs one more sentence: `dialer_cap` and
`acceptor_cap` enter the proof as the EXACT wire bytes sent/received
(the sender hashes what it sent, the verifier hashes what it received —
byte-identical by TCP), never as reconstructed fields (a reconstruction
risks divergence in integer widths and field order even with the
declared encoding). And the cap record's own wire encoding is the same
discipline: declared field order, u16-LE lengths, little-endian
integers, no padding.

## Finding 2 (nit — the version field's trust model stated)

State: the HELLO version field is unauthenticated pre-proof and that is
safe by construction — a v2 peer seeing a v1-version claim simply uses
v1 rules (all capabilities disabled on a v1-proof connection until
matching CONFIRMs, so a false v1 claim can only DE_FEATURE the
connection, never elevate it); a v1 peer ignores the version entirely
and reads the nonce; and between v2 peers the version is covered by the
v2 transcript itself. No proof-covered version field is needed.

## Verified sound this round (my own re-trace)

- r51-B1 fold: the immediate-v1-proof rule closes the reconnect loop
  (the v1 peer's next frame after HELLO is exactly the expected
  `syncMsgAuthProof`).
- r51-B2 fold: the formula's fixed-order records + prover_role make both
  directions byte-identical (with Finding 1's as-sent pin).
- r51-M3 fold: the §9 rule and the normative rule agree (my grep finds
  no capability negotiated on a v1-proof connection without the
  CONFIRM).

## Verdict

**PLAN NO for v9.9.49** — fold Findings 1-2 as v9.9.50 (precision pins;
no design change). Part A remains converged and untouched.
