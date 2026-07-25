# Claude SMR hostile plan-review — round 39 (v9.9.24 @ ac1c89b6f)

Reviewer: Claude SMR (in-conversation). Posture: HOSTILE — I wrote the
v9.9.24 folds; this pass attacks them. Verdict: **PLAN NO for
v9.9.24-as-committed** — two self-found precision gaps (one MEDIUM: the
barrier's refusal mechanism has an accept-side occupancy window; one LOW:
the sender cutoff's interaction with the sender's own dual-fabric send).
Everything else verifies sound against code.

## Finding 1 (MEDIUM — the barrier refusal must cover the install-before-kill window on B's own accept side)

The barrier-and-drain fold says B "REFUSES inbound connections (dial AND
accept) during its barrier — every connection attempt is
accepted-and-immediately-closed (or never answered)". On B's ACCEPT side,
an inbound connection that A dials during the barrier installs a slot on B
briefly (accept → `installConn` → immediate close per the refusal). During
that brief window B's own `wasDisconnected` computation sees a non-empty
slot — harmless for B's OWN cold-prime (B is the repair target, not the
bulk source), but the SAME window exists on A if A is the accept-side for
B's redial after the barrier... no: after the barrier both A's slots are
already empty (they drained during the barrier), so the first post-barrier
install cold-primes regardless of side. The real window: A's dialer
installs fab0 on A at T (barrier), B refuses (immediate close), A's dialer
backs off — the install-die cycle repeats. Each install on A computes
wasDisconnected at install time: if fab1 already drained (EOF'd), an
install-die cycle could briefly leave A thinking the peer is connected on
fab0 while B has nothing — fine, it dies immediately. The invariant the
fold MUST state explicitly: the cold-prime that matters is the SENDER's
(A's) bulk drive, which fires on A's installConn decision — and A's
post-barrier install always computes both-empty because the barrier
outlasts A's slot drain. The refusal mechanism (immediate close vs
never-answer) must be pinned to ONE: immediate-close is the right choice
(never-answer delays A's retry backoff detection and can wedge A's
connect timeout accounting); and B's refusal must ALSO suppress B's own
outbound dial until the barrier ends (a B-initiated early dial is an
install on B too).

## Finding 2 (LOW — the sender cutoff must name which send path pauses)

The cutoff says "the sender PAUSES incremental emission when it arms the
repair, FLUSHES the pre-cutoff queue". The sender's incremental path is
the sendLoop draining `sendCh` over whichever connection is active
(`sync_conn_write.go:268`). Pausing "emission" must mean: stop dequeuing
new incrementals AND let the in-flight queue drain (flush) BEFORE the
snapshot — but a frame already dequeued and retrying on the other
connection (the sendLoop's retry-on-active-fabric behavior) can still
land after the pause. The fold should state: the cutoff is taken with the
sendLoop quiesced (its retry loop joined), not merely the enqueue paused
— otherwise the pre-cutoff frame Codex traced can still land
post-BulkEnd from the retry path.

## Verified sound this round (my own re-trace)

- PendingRelease ticket: the ticket is allocated inside the allocator's
  live lock (same critical section as the NoChange check), so claim and
  cancel serialize; the drain's (generation, ticket) compare is
  ABA-complete; the slot-namespaced floor survives retarget.
- DirectHold→GroupHold conversion: one allocator critical section (mint
  group owning the reservation + decrement direct count) is the same
  lock the release paths use — no interleaving; the transition matrix is
  exhaustive over the receipt variants.
- Transactional bulk: staging members+gen-map and committing at a
  validating BulkEnd makes O1-after-O2 harmless by construction; the
  staged reset also fixes the pre-existing failed-bulk wipe (v9.9.23.2).
- Incarnation-namespaced repair epochs: the nonce is the same
  origin_process_nonce the identity tail already authenticates.

## Verdict

**PLAN NO for v9.9.24** — fold Finding 1 (refusal pinned to
immediate-close + B's own dial suppressed; the post-barrier cold-prime
invariant stated) and Finding 2 (sendLoop quiesce-and-join at the cutoff)
as v9.9.25. Part A remains converged and untouched.
