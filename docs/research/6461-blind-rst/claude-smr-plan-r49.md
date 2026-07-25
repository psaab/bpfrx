# Claude SMR hostile plan-review — round 49 (v9.9.43 @ 7e7c90ced)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — I wrote the
v9.9.43 folds; this pass attacks them. Verdict: **PLAN NO for
v9.9.43-as-committed** — three precision pins (all LOW; no design defect
found). The v9.9.43 mechanisms verify sound in direction against code.

## Finding 1 (nit — the v1 mask list is explicit and complete)

State the mask contents: the transcript-dependent features are EXACTLY
the reset lane itself, `RESET_GEN`/`RESET_ACK`, and the reset-generation
handshake — so the v1 mask is `reset-vN` plus those named frames; the
REPAIR protocol (`repair-vN`, `JOURNAL_END`/`JOURNAL_ACK`,
`RESYNC_REQUEST`, the cutoff/marker frames) rides the ESTABLISHED
authenticated connection and does NOT depend on the v2 transcript, so it
is negotiated independently and never masked.

## Finding 2 (nit — the domain-separation constant)

State: the v2 domain separator is a fixed tag string distinct from the
v1 proof tag (a different constant, e.g.
`xpf-cluster-sync/v2/hello-transcript`), so a v2 transcript proof can
never collide with or be mistaken for a v1 nonce proof.

## Finding 3 (nit — one pending at a time; latest-pending-wins on re-restart)

State: the registry admits at most ONE `pending` incarnation per peer;
a THIRD incarnation arriving while one is pending REPLACES the pending
entry (the peer has moved on — the newest authenticated incarnation is
always authoritative), the replaced pending is retired without ever
becoming current, and the completion CAS checks the transition epoch
against the CURRENT pending, so a superseded pending's completion fails
the CAS and cannot promote.

## Verified sound this round (my own re-trace)

- r48-B1 fold: the terminology lock + sweep is complete — my grep finds
  every discharge clause direction-explicit (`JOURNAL_END` → receiver
  inbound/readiness; `JOURNAL_ACK` → sender outbound/cold-prime;
  `BulkEnd`/bare `BulkAck` → neither).
- r48-H2 fold: the v1/v2 split preserves rolling upgrades (with
  Findings 1-2's pins).
- r48-M3 fold: the metadata-only lock phase + release-then-close closes
  the deadlock both Codex and AGY traced (with Finding 3's pin).

## Verdict

**PLAN NO for v9.9.43** — fold Findings 1-3 as v9.9.44 (precision pins;
no design change). Part A remains converged and untouched.
