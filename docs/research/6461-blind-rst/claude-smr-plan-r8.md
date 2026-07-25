# Claude SMR hostile plan review — round 8 — #6461 blind-RST demote gate

Reviewer: Claude (SMR pass, adversarial). Scope: plan v7.4 (@ fdf54f7af),
Codex r8 verdict (PLAN NO, 6B/3H/1M/1L), AGY r8 verdict (3×SOUND, no
contradictions). Codex's blockers re-traced against the code.

**Verdict: PLAN NO for v7.4 (v7.5 required).** One of the six blockers
(Codex 5, split steering) collapses on analysis from "83% of flows" to
"master-parity, documented"; the other five are real identity/ordering
defects in the authority ticket and Phase-2 protocol. The dataplane trust
model remains untouched since v6 — this is the third consecutive round
confined to the HA/authority layer.

## Adjudication of Codex r8

1. **BLOCKER — CAS neither universal nor ABA-safe: CONFIRMED both
   halves.** (a) Zero-ID imports exist (legacy per-worker id allocation,
   `session_sync.rs:274`, `install.rs:335`; bulk export emits id 0,
   `export.rs:143`) — a strict CAS never wins for them (stranding
   returns) and a zero wildcard restores key-only deletion. v7.5:
   mint-on-zero — the import mints a fresh node-local stable id and
   publishes the alias WITH it (the ticket is node-local; node-local
   uniqueness suffices). (b) The delayed key-only downstream teardown
   (`session_delta.rs:436, :453`, `delete_synced.rs:16`) can delete E2's
   aliases/entries after E1 legitimately won its CAS. v7.5: the
   teardown becomes id-conditional on the delta's `session_id` (already
   carried, #4915).

2. **BLOCKER — promotion straddles the ticket: CONFIRMED.** Promote
   flips `SyncImport→SharedPromote` FIRST and republishes the alias with
   id 0 AFTER (`promote.rs:99-131`); in between, a stale sibling matches
   the old alias and can win. v7.5: the CAS requires
   `alias.origin ∈ {SyncImport, SharedMaterialize}` AND matching id —
   and promote REPUBLISHES (entry's own stable id, promoted origin)
   BEFORE the origin flip, so the alias leaves the import class before
   any authority transition. The residual pre-republish window is a
   microseconds in-memory interval inside one worker command,
   documented.

3. **BLOCKER — demotion/generation fencing: PARTIALLY CONFIRMED.**
   (a) The publish-before-command window is real but is ALSO master's
   window — v7.5 closes it for stamped entries by making the gate
   `owner_rg_active(metadata.owner_rg_id)` against live state (the
   locally-born branch was redundant for stamped entries); `owner_rg_id
   == 0` edge entries keep master's fallback, documented. (b) The
   generation claim was fictional (generations are per-(sender,key),
   `sync.go:537`; echoed gens aren't compared). v7.5's cross-node fence
   is Go-side `(node_id, session_id)`-conditional close processing
   (`daemon_ha_userspace_stream.go:393`) — a stale E1 Close can't kill
   E2's cluster entry; id-0 legacy keeps today's behavior and churns
   out.

4. **BLOCKER — the tail is not purely capacity: CONFIRMED, and it
   narrows the fix rather than exploding it.** Packet geometry pairs
   with any chosen sequence, so geometry-determined checks left in the
   tail (slice validity, malformed, `verify.rs:16`, `tunnel.rs:119`)
   are sequence-targeted poisoning channels (walk the anchor with
   deliberately malformed in-window packets). v7.5: the admission stage
   subsumes ALL geometry-determined checks (deterministic per geometry,
   hoistable); the documented tail is then only runtime-capacity
   (ring fullness, alloc pressure, XSK commit race) — aggregate-state
   classes, volumetric-only. Per-item post-commit callbacks remain
   rejected (per-packet cross-worker mutation traffic is worse than the
   residual).

5. **BLOCKER — split steering: CONFIRMED as quantified (~1−1/N flows,
   ~83% at 6 queues) but RE-ADJUDICATED to master-parity.** The key
   verification Codex's framing omitted: on master, worker B's close
   propagation is local-table-only (`mod.rs:1232-1278`) and B's
   replica/synth entries are peer-synced/is_reverse — silent reaps, no
   delta — so master ALSO cannot demote the authoritative entry from B;
   A's entry idles out identically, and a blind reverse close on B kills
   only B's 2 s re-synthesizable caches (toothless). v7.4's soft-refuse
   on B ≈ master's outcome for the flow and strictly better for B (no
   churn). Forward closes land on A (validated). Phase 2 then repairs B
   properly (the same-node alias carries A's trusted fwd sides; B's
   observed rev samples cross-prove → trusted → validated demote on B,
   better than master). Writer migration is covered: the heartbeat is an
   OBSERVATION refresh, so a migrated-away writer cannot heartbeat
   indefinitely. Documented in §7 with the full analysis.

6. **BLOCKER — Phase-2 encoding: CONFIRMED on every sub-point.** Payload
   is 64 B pre-generation/lease, not ~52 (now ~72 B with boot_id +
   presence + bulk_epoch stated); the sync generation is NOT stable
   identity (reassigned per sweep, `sync_conn_gen.go:113`) → incarnation
   = `(node_id, boot_id, session_id)`; `side_present` message-presence
   mask distinct from state masks; snapshot fields ordered (OPENING
   endpoints immutable per incarnation, phase monotone, wnds follow
   their side's seqno); per-side lazy leases (+16 B → 56 B anchor, cost
   restated); deadlines computed from the receiver's clock on receipt
   (absolute deadlines never transmitted).

7. **HIGH — bulk ordering: CONFIRMED.** `bulk_epoch` on every baseline
   and update; apply iff `update.bulk_epoch >= stored`; interleaved
   older-epoch updates discarded (`sync_bulk.go:81, :105` ×
   `sync_conn_write.go:268` interleaving is real).

8. **HIGH — capacity math: CONFIRMED.** Restated: steady-state = Σ
   per-flow change rates (50k idle ≈ 833/s heartbeats + 10k quiet-active
   ≈ 333/s ≈ 1.2k records/s ≈ 5 msgs/s at 256/batch — inside the 16
   msgs/s cap); the per-entry 1/s is burst absorption; sustained
   oversubscription degrades to decay→refuse-biased (safe), and the
   1-interval freshness claim is steady-state-only.

9. **HIGH — pending-neigh unbounded re-pend: CONFIRMED.** One
   re-resolution preserving the original deadline/probe budget; drop on
   the second MissingNeighbor; proof/promote recomputed against the new
   incarnation.

10. **MEDIUM — stale §5.4 number + leg-2/3 contradiction: CONFIRMED
    (both fixed).**

11. **LOW — tests: CONFIRMED (the enumerated race/ordering/saturation
    cases added).**

## AGY r8 (3×SOUND)

Ticket narrowing + origin disjointness (`worker_replica_origin`),
per-side writer totality under symmetric and split steering, and
owner-only lease renewal all verified against the code with no
contradictions found. Its verdict is compatible with Codex's: AGY
verified the v7.4 folds that survive; Codex attacked the next layer
down.

## Bottom line

v7.5's authority rule reaches its fourth and (I believe) final form:
live `owner_rg_active` gate + import-origin-narrowed `(origin, id)` CAS
ticket with mint-on-zero and promote-publishes-first + id-conditional
teardown + Go id-conditional close. Phase 2 is now encoded, ordered,
and budgeted. The split-steering elephant from Codex 5 is, on
verification, master-parity — the round's most important correction to
MY framing was that master's propagation is local-table-only, so B-side
closes never had demote authority to lose. My verdict on v7.5:
implementation-ready modulo round-9 verification. If round 9 turns up
yet another layer in the HA machinery, the right call is to split the
verdict: PLAN-READY for Phase 1 (standalone-safe) with Phase 2 gated on
the remaining protocol verification.
