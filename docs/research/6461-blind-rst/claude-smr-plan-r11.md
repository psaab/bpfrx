# Claude SMR hostile plan review — round 11 — #6461 blind-RST demote gate

Reviewer: Claude (SMR pass, adversarial). Scope: plan v8.2 (@ f6dbb3bde)
and v8.3 (@ 253f2608d), Codex r11 verdict (PLAN NO, 7B/1H/3M), AGY r11
verdict (3×UNSOUND). Codex reviewed v8.2 (pre-v8.3); its finding 1 is
the same hazard AGY's Q2 found and v8.3 fixed — adjudicated against both.

**Verdict: PLAN NO for v8.2/v8.3 (v8.4 required).** This round's
substance: three of my v8.2 "fixes" were themselves defective (the
read-touch was attacker-refreshable, the family clock was per-clone
incoherent, and the epoch gate compared node-local counters that mean
nothing cross-node), and two premises were unverified (the wire carries
no mark; secondary fabrics get no bulk). All fold cleanly. The dataplane
trust model remains untouched for the eighth consecutive round.

## Adjudication of Codex r11

1. **BLOCKER — TTL stale-NAT window: RESOLVED in v8.3 (AGY Q2) + v8.4
   refinement.** The reservation-release drives the alias purge (zero
   hazard window for NAT'd flows; TTL is the non-NAT backstop). Codex's
   second cut is the live one: v8.2's read-touch let a blind spray
   refresh a stale alias forever and made a refused close an alias
   refresh (violating §5.7 inertness). v8.4 drops the read-touch —
   events + the batched worker push are the whole clock (a live flow's
   worker-local entries push; a stale alias has none).

2. **BLOCKER — per-clone clock incoherence: CONFIRMED.** Canonical/NAT/
   wire maps hold independent clones under separate mutexes, and the
   reverse canonical entry (`ha/session_import.rs:104`) wasn't even in
   the family. v8.4: ONE family clock on the canonical forward entry —
   every member's event stamps it via a helper; deletion is
   compare-delete per member on `flow_incarnation_id` under a documented
   lock order (canonical → NAT → wire → indexes) that every publisher,
   touch helper, sweep, and commit obeys.

3. **BLOCKER — the wire carries no mark: CONFIRMED, and it was my
   unverified premise.** `SessionSyncRequest` has no close flags
   (`control.rs:988`); imports hardcode `tcp_flags: 0`
   (`server/helpers/session_sync.rs:168`). v8.4: the peer-validated mark
   rides the Phase-2 anchor tail (`closing: u8` — the anchor message is
   exactly closing-state carriage). Phase-1 zero-producer residuals are
   documented as hygiene-bounded (mark erasure on reimport → natural
   reaps + sweep cleanup; reverse-synth's forward entry emits at its
   natural reap as locally-born — a producer exists, just later).

4. **BLOCKER — rg_epoch compares unrelated counters: CONFIRMED.** Rust
   `rg_epochs` and Go `rgStateMachine.epoch` are node-local; a new owner
   at epoch 5 would lose to a former at 100. v8.4: the owner gate is
   `writer_node == current_owner(rg)` per the receiver's HA state —
   cluster-coherent by VRRP design, with the masterDownInterval overlap
   documented (both pass; the lease merge converges when the loser steps
   down).

5. **BLOCKER — payload can't name two writers: CONFIRMED.** Writer
   identity moved INTO each direction bundle (`writer_node`/
   `writer_worker`), and the `writer_gen` protocol is replaced by the
   coordinator as the single sequencer: writers submit bundles with
   `observed_ns`; the coordinator assigns `coord_seqno` and drops
   submissions older than the accepted observation. No atomic
   claim/grant protocol needed — ordering authority is centralized at
   the point the bundles already funnel through.

6. **BLOCKER — stream init + write-time freshness: CONFIRMED all three
   sub-failures.** Secondary fabrics get no bulk (`sync_conn.go:125,
   :208`) → v8.4's `AnchorStreamStart` opens anchor traffic on EVERY
   connection with the sender nonce + current epoch. The Go retry queue
   holds `[]byte` → the anchor-update queue is TYPED from the start and
   each bundle carries `observed_ns`; freshness is receiver-computed on
   receipt (a retried frame reports its true age). Epoch activation
   moves to the `BulkStart` write (an `E+1` incremental can no longer
   precede its `BulkStart(E+1)`).

7. **BLOCKER — incarnation/deletion not end-to-end: CONFIRMED.**
   Forward-mint inheritance: the reverse entry and its publication
   inherit the forward's id (constructors hold the forward match in
   hand); fabric/tunnel inherit likewise; `DeleteSynced` becomes
   incarnation-conditional (a delayed E1 cleanup can't kill E2); the
   Close codec carries `(origin_process_nonce, flow_incarnation_id)`
   (additive, all three layers).

8. **HIGH — malformed tail not strictly dominated: CONFIRMED, and it's
   the correct framing.** The channel adds nothing to demote
   probability, but anchor-poisoning for resource retention (keep the
   victim's close soft-refused → slot/NAT reservation held for the
   ordinary timeout) is a real objective. v8.4 states it as a
   same-probability resource-retention channel bounded by the ordinary
   timeout (no `last_seen` refresh on refused closes, §5.7), accepted
   because the alternatives are worse.

9. **MEDIUM — two unvalidated constructors: CONFIRMED, documented as
   harmless-by-class.** Fabric `SYN|ACK|RST/FIN` seeds (`fabric.rs:404`)
   are `is_reverse`-silent; LocalDelivery bare-close seeds
   (`session_admission.rs:78`) are owner-zero (Go excludes host-local
   sessions from HA sync) — neither has cluster authority. The §3
   inventory states both honestly with tests.

10. **MEDIUM — cost/capacity understated: CONFIRMED.** Scheduling is
    ~48 B (not 24); whole cost ≈ 104 B/entry (~13.6 MiB/worker, ~82 MiB
    at 6 workers); the flush floor accounts for split steering
    (~2.1k bundle records/s → ≥3k records/s floor); sidecar bounded to
    live synced entries with close/bulk-reconcile deletion.

11. **MEDIUM — text contradictions: SWEPT (several already fixed in
    v8.3, which Codex didn't see).** §5.8's "no shared-map schema
    change" now reads node-local-additive; the obsolete fencing and
    merge-rule texts are aligned.

## AGY r11 (3×UNSOUND) dispositions

- Q1 (mark rules vs raw flag seeds): valid as a spec-precision point —
  the plan now states the enforcement is at the constructors (§5.6):
  reverse-synth validates before seeding, materialize installs alive on
  refuse, fabric-ingress closes validate at site 1 (non-owner imports
  have no anchor in Phase 1 → refuse → no mark → the 2 s failover window
  AGY traced closes).
- Q2 (reservation released ~3T before alias purge): valid — fixed
  event-driven in v8.3 (release drives the purge).
- Q3 (text contradictions): valid — swept in v8.3/v8.4.

## Bottom line

v8.4's authority design: ONE canonical family clock with ordered
compare-delete and reservation-release-driven purge for NAT'd flows;
the mark as the sticky bits (validated-only creation) riding the
Phase-2 tail for imports; ONE emission predicate with uniform marked
emission and exactly-once via delete propagation; an owner gate by
node identity; coordinator-sequenced Phase-2 bundles with
receiver-computed freshness and per-connection stream starts. The
residual inventory (§11 Q5) is five named, bounded, documented items.
My verdict on v8.4: implementation-ready modulo round-12 verification
of the six §11 questions — the two mechanisms introduced in the last
two rounds (family clock, coordinator sequencing) are where round 12
should concentrate.
