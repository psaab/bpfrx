# Claude SMR hostile plan-review — round 54 (v9.9.53 @ 8a45cb7a9)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — I wrote the
v9.9.53 folds; this pass attacks them. Verdict: **PLAN NO for
v9.9.53-as-committed** — two precision pins (all LOW; no design defect
found). The v9.9.53 mechanisms verify sound in direction against code.

## Finding 1 (nit — the vectors' presentation encoding is also byte-exact)

State: the golden vectors are normative test constants whose own
presentation is byte-exact — each is a labeled triple of hex strings
(key, the complete role-specific input concatenation, expected digest)
with the field labels named, so the test file leaves no interpretation
freedom beyond the protocol's byte content.

## Finding 2 (nit — the lazy-confirm retry is bounded and terminates in the legacy class)

State: the CONFIRM exchange carries its own deadline (like the auth
handshake's); a persistently slow or never-confirming peer fails the
install, the retry follows the standard reconnect backoff, and after a
defined failure count the connection settles PERMANENTLY into the
legacy class for that incarnation — the latch means one protocol class
per connection, so a peer that cannot confirm gets legacy (the safe,
complete class), never a flap.

## Verified sound this round (my own re-trace)

- r53-B1 fold: HMAC-SHA256 + the bit table + complete vector triples
  close the interoperability gap (with Finding 1's presentation pin).
- r53-H2 fold: the pre-dispatch CONFIRM + latched protocol class closes
  the mid-transaction activation race (with Finding 2's liveness pin).
- r52-2 (RESOLVED) holds.

## Verdict

**PLAN NO for v9.9.53** — fold Findings 1-2 as v9.9.54 (precision pins;
no design change). Part A remains converged and untouched.
