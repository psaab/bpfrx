# #1628 — Empirical per-class waterfill trace counters for the CoS scheduler

**Status:** DRAFT v1 — pending adversarial plan review (Codex + AGY + Claude SMR)

## 1. Issue framing

#1628 asks for empirical per-class trace-counter instrumentation in the CoS
scheduler so future CoS algorithmic work has the data to identify why a class
undershoots its guarantee. It was recommended by the #1625 PLAN-KILL (3-of-3)
as a prerequisite for any new CoS mechanism, then parked 2026-05-28 ("no live
consumer") with the explicit note that the #1630 CoS-equalize root-cause
research MAY surface a need for a **narrower** counter set scoped against a
**verified** need rather than the broad speculative list in the issue body.

That verified consumer now exists. #1630's research (all-three PLAN-NEEDS-MAJOR,
verified root cause) concluded:

> **Multi-worker queue-ownership fragmentation + flat root shaper.**
> `coordinator/mod.rs` round-robins each CoS queue to a distinct owner worker
> (6 workers, ~2 queues each). Packets are cross-binding-redirected to the
> owner, so each worker's `guarantee-rate` waterfill selector
> (`queue_service/mod.rs:777-1026`) only sees its own ~2 backlogged queues —
> others are `cos_queue_is_empty` → skipped.

The #1630 issue body further names two concrete code suspects to disambiguate:

1. **Phase-2 lock-in** at `queue_service/mod.rs` waterfill Phase-2 descending
   walk — "most likely cause" per #1625 reviewers.
2. **`worker_fair_share` math** in the waterfill Phase-1 budget split.

So this PR scopes the counters to make the waterfill selector's per-class
decisions empirically visible, mapped 1:1 to #1614's three measured symptoms:

- **Symptom 1 (class starvation / shape undershoot under simul load):** which
  phase admitted a class (Phase 1 small-first honor vs Phase 2 descending
  residual) and how often Phase-1 budget was exhausted before the class was
  reached.
- **Symptom 2 (push-direction cluster ceiling / fragmentation):** how many
  exact queues each worker's selector actually *considered* vs *honored* per
  epoch — the direct fingerprint of the per-worker ~2-queue fragmentation.
- **Symptom 3 (per-flow CoV under simul):** already covered by the existing
  `active_flow_buckets_peak` + flow-fair telemetry; this PR adds the
  **selection-skip-reason** breakdown so an operator can tell a "queue was
  empty because its owner worker never saw the flow" skip from a
  "queue had backlog but lost the Phase-1 budget race" skip.

## 2. Honest scope / value framing

This is **observability only** — no scheduling-decision change. The win is not
cycles or throughput; it is turning the #1630 root cause from "verified by
reading source" into "confirmed by counters an operator can read from `show
class-of-service interface` and Prometheus." The acceptance bar in #1628 is:
"Counters expose enough info to answer: is this an algorithm bug, a
misconfiguration, or a cluster-ceiling problem?"

The cost is a handful of `u64` increments at the waterfill selection sites
(epoch-boundary / per-selection, **not** per-packet) plus wire/Prometheus/CLI
plumbing that mirrors the existing #710/#751/#760/#1369 owner-profile pattern
byte-for-byte.

*If reviewers conclude the counter set is still too broad / speculative, or
that the chosen write sites don't actually disambiguate the #1630 suspects,
PLAN-KILL is an acceptable verdict.* The parking note explicitly invites a
narrower scoping; this plan must justify each counter against a #1630 suspect
or a #1614 symptom, and any counter that fails that test should be cut.

## 3. What's already shipped / what this composes with

The per-queue telemetry infrastructure is mature. This PR extends it; it does
not invent a new mechanism.

- `CoSQueueDropCounters` (`types/cos.rs:899`): plain-`u64`, single-writer
  (owner worker), park-reason + admission counters. Written via
  `count_park_reason(root, queue_idx, ParkReason)` (`tx_completion.rs:51`).
- `CoSQueueOwnerProfile` (`types/cos.rs:965`): `AtomicU64` per-queue drain
  telemetry (guarantee/surplus byte split, park counts, drain hist). Atomic
  because the snapshot reader runs on a different thread; Relaxed throughout.
- Snapshot aggregation: `accumulate_queue_row` (`worker/cos/queue_row.rs:50`)
  sums each worker instance's per-queue counters into one
  `protocol::CoSQueueStatus` row (Rust `protocol/cos.rs:168`).
- Wire: serde JSON, every field `#[serde(rename=..., default)]` →
  backward-compatible additions. Go mirror `pkg/dataplane/userspace/
  protocol.go:726` (JSON tags MUST match byte-for-byte).
- Prometheus: `pkg/api/metrics_descriptors.go` + `metrics_userspace.go`.
- CLI: `pkg/dataplane/userspace/cosfmt.go` `show class-of-service interface`.

The waterfill selector `select_exact_cos_guarantee_queue_waterfill`
(`queue_service/mod.rs:777-1026`) is the **only** code path that implements the
`guarantee-rate` Phase-1/Phase-2 split #1630 indicts; the Proportional default
selector (`select_exact_cos_guarantee_queue_with_lease_telemetry` legacy RR arm)
does not have phases. So the new phase counters are only ever written from the
waterfill path; the legacy arm leaves them at zero (which is itself a useful
"this interface is not in guarantee-rate mode" signal).

## 4. Concrete design

### 4a. New per-queue counters (all `u64`, single-writer owner worker)

Add to `CoSQueueDropCounters` (plain `u64`, NOT atomic — same single-writer
discipline as the existing park-reason fields; the snapshot reader tolerates
monotonic tearing exactly as documented on the struct):

```rust
/// #1628: waterfill Phase-1 (small-first honored set) admissions for
/// this queue. Incremented once per waterfill Phase-1 honor (the
/// `return Some(...)` at the end of the ascending walk). Zero on the
/// Proportional-mode legacy RR path. A class that undershoots its
/// guarantee with this near zero AND phase2_admissions > 0 is being
/// served only as Phase-2 residual — the #1630 Phase-2-lock-in
/// fingerprint.
pub(in crate::afxdp) waterfill_phase1_admissions: u64,
/// #1628: waterfill Phase-2 (descending residual) admissions for this
/// queue. See above.
pub(in crate::afxdp) waterfill_phase2_admissions: u64,
/// #1628: count of waterfill selector visits to this queue where the
/// queue was eligible (nonempty + runnable + guarantee + exact) and
/// had tokens, but the Phase-1 rate-scaled cost exceeded the remaining
/// Phase-1 epoch budget — i.e. this queue forced (or would have forced)
/// the break into Phase 2. This is the direct counter for "Phase-1
/// budget exhausted before the class was honored" (Symptom 1) and the
/// `worker_fair_share` math suspect from #1630.
pub(in crate::afxdp) waterfill_phase1_budget_exhausted: u64,
/// #1628: count of waterfill selector visits where this queue was
/// SKIPPED because it was empty/not-runnable from THIS worker's
/// perspective. High relative to a class's configured presence is the
/// per-worker queue-ownership fragmentation fingerprint (Symptom 2):
/// the class exists but this worker's selector never has its backlog.
pub(in crate::afxdp) waterfill_skipped_not_backlogged: u64,
```

### 4b. New per-interface (root) counters

Add to `CoSInterfaceRuntime` (plain `u64`, single-writer). These are
epoch-scoped aggregates the per-queue counters can't express:

```rust
/// #1628: number of completed waterfill epochs (Phase-1 budget
/// refills) on this interface since snapshot. Pairs with the per-queue
/// phaseN_admissions so an operator can normalize "admissions per
/// epoch". Incremented at the lazy Phase-1 budget refill site.
pub(in crate::afxdp) waterfill_epochs: u64,
/// #1628: count of exact queues CONSIDERED in the current/most-recent
/// Phase-1 ascending walk on this worker's view of the interface
/// (length of `exact_queues_by_rate_ascending` that were eligible).
/// Snapshot reads the last-epoch value. Pairs with
/// `waterfill_queues_honored_last_epoch` to expose the
/// considered-vs-honored fragmentation ratio directly (Symptom 2).
pub(in crate::afxdp) waterfill_queues_considered_last_epoch: u64,
pub(in crate::afxdp) waterfill_queues_honored_last_epoch: u64,
```

(The "last_epoch" pair is a snapshot of the in-progress epoch counters,
swapped at epoch refill — same shape as a min/max-over-window gauge. This
keeps them O(1) and avoids unbounded growth.)

### 4c. Write sites (all inside `select_exact_cos_guarantee_queue_waterfill`)

1. **Epoch refill** (`mod.rs:793` `if waterfill_pass1_remaining_bytes == 0`):
   `root.waterfill_epochs = root.waterfill_epochs.wrapping_add(1);` and swap
   the in-progress considered/honored counts into the `*_last_epoch` fields,
   reset in-progress to 0.
2. **Phase-1 honor** (`mod.rs:912` just before `return Some(...)`): bump
   the chosen queue's `waterfill_phase1_admissions` and the root
   `waterfill_queues_honored` in-progress counter.
3. **Phase-1 budget-exhausted break** (`mod.rs:906` `if phase1_cost >
   remaining`): bump the queue's `waterfill_phase1_budget_exhausted` before
   `break`.
4. **Phase-1 skip-not-backlogged** (`mod.rs:817` `cos_queue_is_empty(queue)
   || !runnable || ...` continue): bump `waterfill_skipped_not_backlogged`.
   (Considered count is incremented for queues that pass the eligibility gate.)
5. **Phase-2 admission** (`mod.rs:1015` Phase-2 `return Some(...)`): bump the
   chosen queue's `waterfill_phase2_admissions`.

All five sites already hold `&mut root` (or `&mut queue` via
`root.queues[queue_idx]`), so no new borrows are introduced. The increments are
`wrapping_add(1)` on plain `u64` — identical to the existing
`count_park_reason` discipline. A small helper
`count_waterfill_event(root, queue_idx, WaterfillEvent)` mirrors
`count_park_reason` to keep the formula in one place (engineering-style
principle 3).

### 4d. Snapshot aggregation (`worker/cos/queue_row.rs`)

Add six `saturating_add` lines to `accumulate_queue_row` mirroring the existing
park-counter aggregation (per-queue counters sum across worker instances; the
root `waterfill_epochs` / considered / honored are surfaced once per interface
on the interface-status struct, NOT the queue row — they belong on
`CoSInterfaceStatus`, same nesting as `timer_level0_sleepers`).

### 4e. Wire surface (serde + Go mirror)

- Rust `protocol/cos.rs`: 4 new `u64` on `CoSQueueStatus`, 3 new `u64` on
  `CoSInterfaceStatus`, each `#[serde(rename="...", default)]`.
- Go `pkg/dataplane/userspace/protocol.go`: matching fields, JSON tags
  byte-for-byte. Both sides per `feedback_wire_protocol_both_sides`.

### 4f. Prometheus + CLI

- 7 new Prometheus counter/gauge descriptors in `metrics_descriptors.go` +
  emit in `metrics_userspace.go` (per-queue counters → `_total`; per-interface
  considered/honored → gauges; epochs → `_total`).
- `cosfmt.go`: surface the per-queue waterfill counters in the existing
  per-queue detail block (they render only when non-zero, matching the
  existing `q.drainGuaranteeSentBytes != 0 || ...` gate).

## 5. Public API preservation

No function signature changes to any selector. The new helper
`count_waterfill_event` is `pub(in crate::afxdp)`-internal. All existing
`select_*` / `service_*` signatures unchanged. The serde wire surface is
additive-only (every field `default`), so old Go ↔ new Rust and new Go ↔ old
Rust both deserialize cleanly.

## 6. Hidden invariants this change must preserve

- **Single-writer discipline:** every new counter is written only by the owner
  worker on the drain path; the snapshot reader is read-only. Plain `u64` for
  the `CoSQueueDropCounters` additions (matching existing park counters);
  the `CoSInterfaceRuntime` root counters are also owner-only.
- **No new allocation, no per-packet cost:** writes are at per-selection /
  per-epoch granularity, which is per *batch* at most (one selection drains up
  to `TX_BATCH_SIZE` frames). Strictly less frequent than the existing
  `drain_park_*` writes that already live at these sites.
- **Selection ordering unchanged:** counters are bumped adjacent to existing
  `return`/`break`/`continue` without moving any of them. Phase-1 budget
  decrement, RR cursor advance, honored_mask set all stay in place.
- **Proportional-mode parity:** the legacy RR arm is not touched; its queues
  report zero waterfill counters (correct — it has no phases).
- **HA portability:** counters are diagnostic-only, never synced, never read by
  the scheduler. No effect on session sync / failover.

## 7. Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression | LOW | Pure counter increments adjacent to unchanged control flow; no scheduling decision reads these. 5 write sites, all in one fn. |
| Lifetime / borrow-checker | LOW | All sites already hold the needed `&mut`. Helper takes `&mut CoSInterfaceRuntime` + `usize` like `count_park_reason`. |
| Performance regression | LOW | ≤ 1 `u64` write per selection (per batch), strictly rarer than the `drain_park_*` writes already present. Shares the owner's hot cache line — no new false sharing. |
| Architectural mismatch (#961/#946-P2) | LOW-MED | Risk is that the chosen counters don't actually disambiguate the #1630 suspects. Mitigated by mapping each counter to a named suspect/symptom in §1; reviewers must confirm the mapping holds. |

## 8. Test plan

- `cargo build` clean; `cargo test --release` full suite green.
- New unit tests in `queue_service/tests.rs` that drive the waterfill selector
  through (a) a Phase-1 honor, (b) a Phase-1 budget-exhausted break into
  Phase 2, (c) a Phase-2 admission, (d) a not-backlogged skip — and assert each
  counter increments **exactly** at the expected site and stays zero on the
  Proportional path. Counter-factual strength: assert phase2 stays 0 when only
  Phase 1 fires (recreates the #1630 "everything looks like Phase 2" confusion
  if the write site is wrong).
- 5/5 flake loop on the new named tests.
- Go: `protocol_test.go` round-trip (serde→Go JSON parity), `cosfmt_test.go`
  render, `metrics_test.go` descriptor wiring. `go test ./...` 30 packages.
- Deploy + smoke on loss userspace cluster is the **PARENT's** job (cluster
  serialized). This agent posts `<!-- AWAITING-PARENT-SMOKE-1628 -->`.

## 9. Out of scope (explicitly)

- Any change to the waterfill scheduling decision itself (that's #1630's fix).
- The flat-root-shaper FCFS counters (the root `SharedCoSRootLease` greedy
  pool) — #1630 names it but the *fix* there is structural; counting FCFS
  grants per-class would need a new write site in `shared_cos_lease/` and is a
  separate, larger surface. Deferred; noted for the #1630 fix PR.
- `rotate_epoch_v8.rs` / `coordinator/cos_state.rs` counters from the #1628
  body's broad list — the verified #1630 consumer is the *worker-local
  waterfill selector*, not the v8 epoch rotation. Adding epoch-rotation
  counters now would be the speculative breadth the parking note warned against.
  Deferred until a verified consumer needs them.

## 10. Open questions for adversarial review

1. **Do these 7 counters actually disambiguate #1630's two named suspects?**
   Phase-2-lock-in shows as `phase2_admissions >> phase1_admissions` on
   undershooting classes; `worker_fair_share` math error shows as
   `phase1_budget_exhausted` firing on small classes that should fit. Is that
   mapping sound, or is there a third failure mode these miss?
2. **Is `waterfill_skipped_not_backlogged` the right fragmentation fingerprint,
   or does the existing `worker_instances` + per-worker queue presence already
   expose it without a new counter?** (i.e. is this counter redundant?)
3. **`*_last_epoch` swap semantics** — is snapshotting in-progress
   considered/honored at epoch refill the right cadence, or should these be
   plain monotonic `_total`s the reader rate-computes (simpler, no swap race)?
4. **Plain `u64` vs `AtomicU64`** for the `CoSQueueDropCounters` additions —
   the existing park counters are plain `u64` and read cross-thread under the
   "tolerate tearing" doc. The `owner_profile` counters are `AtomicU64`. Which
   is correct for a counter the snapshot reads? (I claim plain `u64` matches the
   park-counter precedent; challenge this.)
5. **Should the per-interface considered/honored live on `CoSInterfaceStatus`
   or be folded onto every queue row?** I chose interface-level to avoid
   N-way duplication, but the existing `post_drain_backup_bytes` is
   broadcast per-queue-row binding-scoped — is there a consumer reason to
   match that anti-pattern instead?
6. **Is cutting the v8/coordinator/FCFS counters (the broad #1628 body list)
   the right call, or does the #1630 fix genuinely need them now** such that
   deferring forces a second instrumentation PR?
