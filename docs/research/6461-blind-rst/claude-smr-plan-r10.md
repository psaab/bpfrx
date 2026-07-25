# Claude SMR hostile plan review — round 10 — #6461 blind-RST demote gate

Reviewer: Claude (SMR pass, adversarial). Scope: plan v8 (@ 3d89f0dab)
and v8.1 (@ 0d5e91b7b), Codex r10 verdict (PLAN NO, 6B/3H/3M/1L), AGY r10
verdict (1 SOUND, 2 UNSOUND). Codex's blockers re-traced against the
code; AGY's Q2 (TTL liveness) was folded into v8.1 mid-round, so Codex's
finding 2 is adjudicated against both.

**Verdict: PLAN NO for v8/v8.1 (v8.2 required).** The v8 deletion of the
ticket tower was right and survives; its three replacements (TTL sweep,
marked-only emission, Phase-2 protocol) were each one level short —
clock, incarnation, ordering. v8.2 supplies them without rebuilding any
tower: the mark is the entry's existing sticky bits with normative
creation rules, exactly-once falls out of the existing delete
propagation, and the fence is a two-field tuple with connection-scoped
node identity.

## Adjudication of Codex r10

1. **BLOCKER — predicate omits the validated mark: CONFIRMED.** The gate
   formula and the marked-only rule were two different predicates, and
   `closing` alone couldn't be the mark because... actually it CAN —
   once its creation rules are normative: the sticky `closing || reset`
   bits are set only by (i) local §5.4-accepted closes (with companion
   propagation), (ii) wire imports carrying closing flags (site 4 — the
   peer validated), or (iii) trusted-local tunnel packets; refused closes
   never set them (§5.7); reimports re-seed from wire flags (peer-validated
   — a reimport before the 2 s reap loses the RECORD but the wire copy
   carries the peer's mark, answering 7b). v8.2's single predicate:
   `!is_reverse && !is_transient_seed && owner_gate && (locally_born ||
   closing || reset)`. The §3 site inventory recheck is §11 Q1.

2. **BLOCKER — TTL has no liveness clock: CONFIRMED (AGY Q2 first).**
   `SyncedSessionEntry` had no age field. v8.2: `last_touch_ns` stamped
   on events, on every shared-map READ (a packet-driven lookup now keeps
   its alias alive), and by the 30 s batched worker push; purge at
   K × expires_after with **K ≥ 4** (the standby-hold ceiling ~T+3T,
   `session/mod.rs:103`, `expire.rs:585`) so a held entry can't be swept
   mid-hold.

3. **BLOCKER — TTL family deletion collision/ABA-unsafe: CONFIRMED.**
   Displacement at a derived NAT alias (`shared_ops.rs:918`) means
   sweeping stale E1 could delete live E2's aliases. v8.2: scan + age
   recheck + per-member deletes are ONE critical section, and each
   family member is deleted only if its `flow_incarnation_id` matches
   the candidate's. The clone-before-purge race is bounded by the lookup
   touch (live flows keep their aliases present).

4. **BLOCKER — same-node key-only updates cross incarnations:
   CONFIRMED, with the fix Codex's own r9 demanded.** Every entry,
   replica, and alias gains `flow_incarnation_id: u64`, SEPARATE from
   the RT_FLOW `session_id`: locally-born aliases stamp the owner's mint
   (today id 0), replicas INHERIT it (no more per-worker mint divergence),
   coordinator imports mint once before fanout (`session_import.rs:115`).
   Anchor updates are incarnation-conditional.

5. **BLOCKER — no writer generation/owner-epoch gate: CONFIRMED.**
   Coordinator-issued per-bundle `writer_gen` handed to the most recent
   observer (queue migration can't produce equal-version conflicts);
   the receiver applies only when the sender is the current RG owner per
   its own HA view with `sender.rg_epoch >= current` (the FabricRedirect
   observation case Codex names: a non-owner observing external packets
   would otherwise renew stale trust).

6. **BLOCKER — reconnect/fresh ordering: CONFIRMED.** `fresh` is
   computed at write time (the sender retries encoded frames
   indefinitely, `sync_conn_write.go:268`); `BulkStart` carries the
   sender's process nonce and incrementals are accepted only after the
   first BulkStart of a connection (session sync always opens with
   bulk); a nonce change resets the floor before any epoch rule runs.

7. **HIGH — single marked producer neither unique nor durable:
   CONFIRMED, and the answer was already in the tree.** Uniform marked
   emission for ALL classes (a marked `WorkerLocalImport` emits — its
   mark required a validated close, so the r7-1 stale-sibling hazard
   stays dead: unmarked siblings can never emit). Exactly-once falls out
   of the EXISTING delete propagation (`session_delta.rs:436, :453` →
   `delete_synced.rs:16`): a marked split-steering sibling emits at 2 s
   and the fan-out removes worker A's entry before its natural reap —
   one Close, no duplicate RT_FLOW; the two-marked-workers race is
   idempotent plus a documented rare duplicate record. Mark durability
   across reimport: the wire re-seeds the bits (peer-validated).

8. **HIGH — fence tuple inconsistency: CONFIRMED.** The tuple is now
   `(origin_process_nonce, flow_incarnation_id)`; node identity comes
   from the connection (no separate node_id field); the nonce is
   retained from the wire import alongside the id.

9. **HIGH — async residual broader than tunnel-egress: CONFIRMED, but
   Codex's own arithmetic defuses it.** The malformed-precursor channel
   needs the SAME ~1/6,554–1/10,923 in-window hit as the direct blind
   close, and the direct close is strictly worse for the victim (demote
   vs soft-stall) — no rational attacker uses the channel. v8.2 also
   takes Codex's narrower fix: selective no-learn on
   NoRoute/NextTableUnsupported/MissingNeighbor/build-failure
   reinjection, mandatory capacity-discard reporting
   (`umem/mod.rs:1290`).

10. **MEDIUM — capacity/memory: CONFIRMED.** Staggered heartbeats by
    key-hash (~140 keys/s/worker instead of a synchronized 8,333-key
    cycle); flush floor sized to steady state (≥8 × 256-record
    batches/s); whole-cost accounting (~80 B/entry + Go sidecar).

11. **MEDIUM — pending-neigh fresh dispositions: CONFIRMED.**
    Standard-dispatch the fresh decision or drop; never transmit the
    stale one.

12. **MEDIUM — stale texts/tests: CONFIRMED (swept; several were
    v8.1-era and already fixed by the Edit Codex didn't see).**

## AGY r10 dispositions

- Q1 SOUND: marking worker = reaping worker (thread-local table +
  wheel); companion propagation yields exactly one Close (forward emits,
  `is_reverse` suppresses). Verified, and the v8.2 uniform-emission rule
  preserves it.
- Q2 UNSOUND (TTL purges live-but-quiet): valid, folded in v8.1/v8.2
  (liveness clock + batched push + K ≥ 4).
- Q3 UNSOUND (stale v7.2 test text): valid, swept.

## Bottom line

Ten rounds in, the authority design is: master's origin rule PLUS one
normative mark (the existing sticky bits, three creation paths, all
validated), exactly-once via existing propagation, a TTL sweep with a
real clock and compare-delete, one flow incarnation id end to end, and a
Phase-2 protocol with writer generations, owner-epoch gating, write-time
freshness, and a nonce-floored reconnect rule. The dataplane trust model
is untouched for the seventh consecutive round. My verdict on v8.2:
implementation-ready modulo round-11 verification of the six §11
questions — the residual design risk has narrowed to the two new
mechanisms introduced THIS round (liveness clock, writer generation),
which round 11 should concentrate on.
