# Claude SMR hostile plan-review — round 122 (v10.38.0)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — forty-second
pass; I authored the v10.38.0 fold of Codex r122's 8B/1H/1M AND caught
one false claim in my own fold during verification. Verdict: **PLAN
YES** (fold verification + hostile sweep below).

## 1. Fold verification (Codex r122)

**r122-1 (B — admission).** The decisive fact from my own earlier
rounds: §5.2's commit-point text ALWAYS demanded wire/local-stack
commit with the mandatory overflow no-learn (the v10.37.0 "TX-pipeline
admission" redefinition contradicted it — Codex's contradiction trace
was correct). The v10.38.0 per-arm rule rides an optional authority
payload on both request types and applies at dispatch-admission
success. **My own fold's first cut claimed the in-place arm's
`pending_tx_prepared` push was final — FALSE**: `bound_pending_tx_prepared`
FIFO-overflow discards prepared requests under TX backpressure
(`tx/drain/mod.rs:56-81`, #804, verified by reading the function — the
pop-front + recycle + `pending_tx_local_overflow_drops` accounting is
right there). Corrected in-revision: BOTH arms ride the payload; every
discard class (hoisted geometry, build failure, redirect-inbox
overflow, bound-prepared overflow) skips the apply. The re-validation
at dispatch is load-bearing (a mid-batch transient purge can stale the
handle). The walk-the-anchor analysis stands: geometry is hoisted
before every apply; a blind attacker cannot chain slides without
feedback; an overrun only produces fail-closed legit-close refusals.

**r122-2 (B — drain topology).** Verified: `poll_binding` regains
control only after the batch (`worker/lifecycle.rs:209-225`), so the
v10.37.0 "before the next descriptor" drain was mechanically
impossible. The three-drain topology (inline current-binding at the
install's own dispatch with invalidate-before-cache ordering;
post-batch sibling fan-out per the existing SSOT; loop-top all-binding
command drain) is consistent with the ownership reality
(`poll_descriptor/mod.rs:110-131` owns the batch loop).

**r122-3 (B — family completeness + producers + capacity).**
`reverse_canonical` verified as a separately-indexed reply-match shape
(`key.rs:19-26`, `session/mod.rs:1920-1933`, consumed at
`lookup.rs:222-250`) — added to the family. The old-family capture at
REMOVE time verified necessary (`local_delivery.rs:90-105` removes K
before the installer runs). `refresh_for_ha_transition`'s reindex
(`session/mod.rs:1627-1666`) joins the producers. The capacity
contract: fixed inline capacity + saturation→whole-cache-flush (the
FlushFlowCaches precedent) — zero-allocation reconciled.

**r122-4 (B — adoption lifecycle).** The adopt now takes S2's trusted
replica bits and preserves only probation + the absolute deadline;
both §5.8 and the §9 assertion text are updated (K-alive→S2-RST and
K-closing→S2-alive fixtures named).

**r122-5/6/7 (B — id transport + promote source).**
`MaterializeReport.family_id`; the promote's `SessionUpdate` carries
BOTH the incoming family id AND the incoming `expected_fwd_id` (the
replacement branch seeds the expectation from it — the
shared-reverse-S2-over-K path keeps its family proof); a successful
zero-wire-id upsert surfaces its final minted id; every promotion
reads `closing`/`reset` from the LIVE post-transition entry (not the
report, not raw flags, not `observed_tcp_flags` — Codex's point that
accounting ORs refused raw closes into it is correct,
`session/mod.rs:1177-1210`); the SharedPromote republication reads the
final entry back (`promote.rs:116-140`).

**r122-8 (H — cross-worker closure).** The accepted site-2b close
re-publishes the forward shared row's close state independent of the
reverse install's success (publication rode `installed` today,
`shared_ops.rs:857-892`; the stale-alive-shared-F synth trace was
real). The re-publish rides the forward entry's identity (the carried
handle).

**r122-9 (M).** The fallback's producer classes are now the full Local
identity-agreeing refusal set that forwards without R — accepted-close
CapacityRefused, ValidatorRefused close, AND the non-closing
OPENING-proof refusal; Shared/identity-mismatch remain excluded.

## 2. Hostile sweep of v10.38.0

- The payload's ~128 B (handles + seg summary + identity) rides only
  TCP session-backed packets; the request structs' growth is `Option`
  niche-packed; the queues are bounded by `max_pending_tx` — memory
  bounded. Stated in §8.
- The dispatch re-validation cost: one `entries.get` + compares per
  payload-carrying request — the same order as the postblock apply it
  replaces; no new probe.
- The three-drain topology's worst case (a full batch of
  install-producing descriptors) is covered by the flush fallback;
  the common case is a handful of exact-key invalidations.

## 3. Bottom line

PLAN YES for v10.38.0 as the round-123 review basis. The gate
(§5.1–§5.4, §5.7) is untouched for the thirty-seventh consecutive
round; rounds 118-122 have been binding/commit mechanics and
producer/carrier plumbing around an unmoving core.
