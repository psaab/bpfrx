# Claude SMR hostile plan review — round 9 — #6461 blind-RST demote gate

Reviewer: Claude (SMR pass, adversarial). Scope: plan v7.5/v7.6
(@ bb2d3e5f3/49523ccd1), Codex r9 verdict (PLAN NO, 7B/3H/2M/1L), AGY r9
verdict (4×UNSOUND). Codex's blockers re-traced against the code.

**Verdict: PLAN NO for v7.5/v7.6 — answered by DELETION, not
completion.** Codex r9 is the round that proved the v7.x
incarnation-ticket tower cannot be finished: every layer demanded the
next (CAS → promote atomicity → full-flow incarnation → cross-node
transport → commit callbacks → writer transfer → bulk floors). The right
response was to remove the requirement, and v8 does. The dataplane trust
model is untouched for the fifth consecutive round.

## The strategic read

The ticket tower existed to give never-observed imports an authoritative
Close producer. Codex r9's deepest point: there is no full-flow
incarnation available (forward/reverse halves mint independently, locally
born aliases publish id 0, tunnel `UpsertLocal` fans out id-0
`SyncImport`, the Close codec drops the id at `session_sync.rs:215`, Go
queues key-only deletes, the shim redirect map stores a u8). Building
transactional conditional deletion across Rust/BPF/Go/cluster on that
foundation is a rewrite of the HA identity system — disproportionate to
the hazard.

The hazard (round-5 Codex 1) is stale shared NAT aliases rematerializing
after allocator reuse. It does not require authority semantics at all:
a coordinator-side shared-map TTL sweep (purge aliases with no worker
refresh for K × timeout) closes it directly, and the Go-side floor
already exists (`pkg/conntrack` GC with HA delete-sync callbacks).
Validated closes carry their own authority — a close that passed §5.4
against a trusted anchor marks the entry, and the marking worker is the
necessarily-single producer whose delete is correct by construction.
Unmarked import reaps stay silent — exactly master's origin rule. The
whole CAS/mint/promote-ordering tower evaporates.

## Adjudication of Codex r9 (post-v8)

1. **BLOCKER — no end-to-end identity for conditional teardown:
   CONFIRMED — moot in v8.** No id-conditional teardown is needed:
   aliases die by TTL sweep; the Go close fence is
   `(origin_node_id, session_id)`-conditional where ids exist (the
   sidecar supplies them; id-less entries keep master's unconditional
   behavior, documented as master's existing mark→reap-vs-re-seed
   exposure).

2. **BLOCKER — publish-before-flip isn't atomic (CAS-win → republish →
   delayed id-conditional cleanup still matches): CONFIRMED — moot.** No
   CAS exists; promote keeps master's semantics; the resurrection race
   was ticket-specific.

3. **BLOCKER — mint-on-zero not universal (tunnel `UpsertLocal` id-0
   `SyncImport` fanout): CONFIRMED — moot.** No minting.

4. **BLOCKER — cross-node fence unavailable/restart-unsafe: CONFIRMED,
   folded.** The fence now carries the origin node id on the Close delta
   (additive; the Rust entry retains it from the wire import), node
   identity is a RANDOM process nonce (`heartbeat.go:624` precedent —
   wall-clock `boot_id` rejected: timestamp collision/rollback), and the
   Go sidecar (Phase 2) supplies the ids the BPF store drops
   (`bpf_session_value.go:204`). Phase 1 keeps master's gen-zero
   behavior for id-less entries (documented exposure).

5. **BLOCKER — final admission can't reach the canonical anchor (CoS
   handoff owner ≠ RX worker): CONFIRMED, bounded honestly.** The apply
   moves to the RX worker's own final admission. The tail is
   restated: (a) CoS-owner admission drop (runtime-capacity); (b)
   runtime-state UMEM slice validity (capacity, not hoistable);
   (c) XSK commit race; (d) the tunnel/TUN/kernel-slowpath subset —
   async write `EINVAL` is per-packet malformed (geometry-steerable,
   `tunnel.rs:119, :180`, `slowpath.rs:534, :607`) — a chosen-malformed
   in-window sample can advance the anchor without delivery on
   tunnel-egress flows. Griefing-only (soft-stall), 1/2^13 entry cost,
   bounded subset — the alternatives (per-packet callbacks, or freezing
   tunnel anchors entirely = soft-refuse every tunnel close) are worse.

6. **BLOCKER — Phase-2 split-worker repair: CONFIRMED, folded.**
   Same-node propagation is worker→coordinator-shared-map→worker (no Go
   round trip — the anchor_update op already applies to shared aliases;
   ids are irrelevant to the anchor fanout — the alias is key-indexed).
   Writer migration vs idle: heartbeats are observation-gated
   (≥1 committed packet this interval with zero movement) — a
   migrated-away writer stops; a keepalived quiet flow continues; a
   totally silent flow decays to refuse-biased (documented posture).

7. **BLOCKER — bulk ordering: CONFIRMED, folded.** Global epoch floor
   at `BulkStart(E)` (older-epoch updates discarded on receipt),
   per-bundle lexicographic `(bulk_epoch, seqno)` (v7.6, from AGY r9-3),
   and full session installs apply the sidecar's MERGED anchor state
   (the raw upsert's `remove_entry` can't regress trust).

8. **HIGH — lease resurrection + wnd ordering + payload arithmetic:
   CONFIRMED, folded.** Sender `fresh` bits omit observation-stale
   bundles (a stale sidecar value can't resurrect trust with a fresh
   receiver lease); payload regrouped into per-direction bundles
   `{seq_hi, ack_hi, wnd, seqno}` — each direction-observing writer
   versions its own bundle; ~70 B packed stated.

9. **HIGH — owner_rg coverage contradiction: CONFIRMED, folded in
   v7.6/v8.** Universal stamping via `owner_rg_for_resolution`; the
   predicate is explicit
   `(owner_rg_id > 0 && active_now) || (owner_rg_id == 0 && locally_born)`;
   LocalDelivery stays owner-zero by design (Go excludes host-local
   sessions from HA sync, `daemon_ha_userspace_stream.go:29`).

10. **MEDIUM — capacity pipeline: CONFIRMED, noted.** The arithmetic
    holds (~1.2k records/s steady-state); the Go→Rust flush must meet
    it (batch/flush sizing floor stated; safe decay posture covers
    bursts).

11. **MEDIUM — stale texts: CONFIRMED (swept).**

12. **LOW — tests: CONFIRMED (replaced with v8 semantics + the
    enumerated races).**

## AGY r9 (4×UNSOUND)

All four valid and folded in v7.6/v8: universal `owner_rg_id` stamping;
the alias-carrying-mint observation (moot with the ticket deleted, but
its analysis informed v8's single-producer-by-marking); the equal-epoch
baseline overwrite (per-bundle lexicographic ordering); the three text
contradictions (swept).

## Bottom line

v8 is the smallest authority design that satisfies every constraint
raised in nine rounds: master's origin rule for unmarked entries,
marked-by-validated-close single production, TTL-swept aliases, an
id-conditional Go fence with a random nonce, RX-worker commit with a
bounded tunnel-egress griefing residual, and a Phase-2 protocol with
bundles/floor/freshness. The question I now put to round 10 is whether
any reviewer can still find a kill that does not require a full HA
identity rewrite to close. My verdict on v8: implementation-ready
modulo round-10 verification of the six §11 questions.
