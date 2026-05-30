# #1628 — Empirical per-class waterfill trace counters for the CoS scheduler

**Status:** DRAFT v2 — addresses Codex `task-mprtl981-wg7p3w` + AGY
`adversarial-review-mprtlgg5-txzcuz` round-1 PLAN-NEEDS-MAJOR (both convergent).
Pending re-review.

## 1. Issue framing

#1628 asks for empirical per-class trace-counter instrumentation in the CoS
scheduler so future CoS work has the data to identify why a class undershoots
its guarantee. It was recommended by the #1625 PLAN-KILL (3-of-3) as a
prerequisite for any new CoS mechanism, then parked 2026-05-28 ("no live
consumer") with the explicit note that the #1630 root-cause research MAY
surface a need for a **narrower** counter set scoped against a **verified** need
rather than the broad speculative list in the issue body (which named
`coordinator/cos_state.rs` + `rotate_epoch_v8.rs`).

That verified consumer now exists. #1630's research (all-three
PLAN-NEEDS-MAJOR, verified root cause) concluded:

> **Multi-worker queue-ownership fragmentation + flat root shaper.**
> `coordinator/mod.rs` round-robins each CoS queue to a distinct owner worker
> (6 workers, ~2 queues each). Packets are cross-binding-redirected to the
> owner, so each worker's `guarantee-rate` waterfill selector
> (`queue_service/mod.rs:777-1026`) only sees its own ~2 backlogged queues —
> others are `cos_queue_is_empty` → skipped.

This PR scopes counters to the **worker-local waterfill selector** — the only
code path that implements the Phase-1/Phase-2 split #1630 indicts.

## 2. Honest scope / value framing

Observability only — no scheduling-decision change. The win is turning the
#1630 root cause from "verified by reading source" into "confirmed by counters
readable from `show class-of-service interface` + Prometheus". The cost is a
handful of `u64` increments at the waterfill selection sites (per-selection /
per-epoch, **not** per-packet) plus wire/Prometheus/CLI plumbing mirroring the
existing #710/#751/#760/#1369 owner-profile pattern.

*If reviewers conclude the counter set is still too broad / speculative, or the
write sites don't disambiguate the #1630 suspect they claim to, PLAN-KILL is an
acceptable verdict.*

### v1→v2 reviewer-driven changes

Both reviewers returned PLAN-NEEDS-MAJOR with convergent fatals. v2 changes:

- **F1 (both): `*_last_epoch` swap is broken** — refill at `mod.rs:793` runs
  thousands of times/sec but the scraper samples 1/s (transient-sampling
  loss), AND it **freezes during the Phase-2 lock-in being investigated**
  (when `waterfill_pass1_remaining_bytes` never reaches 0, the refill block —
  and thus the swap — never executes). → **All counters are now monotonic
  `_total`s; the reader rate-computes over the scrape window.** No swap, no
  freeze, no race.
- **F2 (both): `worker_fair_share` is NOT diagnosable by waterfill-only
  counters** — the real per-worker fair share lives in v8 lease state
  (`shared_cos_lease/mod.rs:407-409`, computed `rotate_epoch_v8.rs:306-310`,
  enforced `acquire_v8` `shared_cos_lease/mod.rs:1175-1217`). → **Dropped the
  `worker_fair_share` diagnostic claim entirely.** This PR diagnoses
  **Phase-2 lock-in** and **per-worker queue-ownership fragmentation** only.
  A v8 fair-share counter is deferred to the #1630 fix PR, which owns the v8
  lease surface (§9).
- **F3 (both): per-interface considered/honored SUMMED across workers hides
  fragmentation** (6 workers × ~2 queues each → "12 considered" looks
  healthy). → **Dropped the per-interface considered/honored fields.** Replaced
  with **per-queue** visit/honor counters that aggregate to the queue's single
  owner worker, so the per-class row reflects exactly the one worker that owns
  it (§4b).
- **F4 (both): `skipped_not_backlogged` summed is ambiguous** (globally-empty
  vs fragmented-active look identical). → **Cut.** The per-queue
  visit-vs-admit ratio (below) plus the existing `owner_worker_id` +
  `queued_bytes` already separate "this class has no load" from "this class's
  load is funneled to one worker." Re-adding a skip counter without per-worker
  keying would just reintroduce the noise.
- **F5 (AGY): semantic pollution** — scheduler-selection counters do not belong
  in `CoSQueueDropCounters` (reserved for drops/ECN/parks). → **New dedicated
  `CoSQueueWaterfillCounters` struct on `CoSQueueTelemetry`.**
- **F6 (both): write-site line correction** — Phase-1 honor `return` is at
  `mod.rs:924`, not 912. Corrected in §4c.
- **F7 (both): plain `u64` is correct, rationale was sloppy** —
  `build_worker_cos_statuses` runs **on the owner worker thread itself**
  (`worker/loop_body/mod.rs:835-839`), iterating its own thread-local
  `CoSQueueRuntime` and publishing the built snapshot via `ArcSwap`. There is
  **no live cross-thread read** of these fields; the increment and the
  serialization are sequential on the same thread. Plain `u64` is correct for
  that reason — not "tearing is tolerated." Rationale fixed.
- **F8 (Codex #3): Phase-1 budget-exhausted only fires on the first queue that
  crosses the boundary** — larger ascending queues after the `break` are never
  visited in Phase 1, so a per-queue "budget exhausted before *this* class"
  would stay silent on them. → The exhaustion event is therefore counted as a
  **per-interface (root) monotonic total** (`waterfill_phase1_budget_breaks`),
  not per-queue. It answers "how often did Phase 1 run out of budget mid-walk"
  without falsely attributing the break to queues never reached.

## 3. What's already shipped / what this composes with

- `CoSQueueDropCounters` (`types/cos.rs:899`): plain `u64`, owner-worker
  single-writer, drop/ECN/park counters. (NOT extended — F5.)
- `CoSQueueOwnerProfile` (`types/cos.rs:965`): `AtomicU64` per-queue drain
  telemetry. (Atomic because #751 had a binding-scoped rollup read pattern;
  the new waterfill counters do not need atomics per F7.)
- `CoSQueueTelemetry` (`types/cos.rs:873`): the container the new
  `CoSQueueWaterfillCounters` is added to.
- Snapshot aggregation: `accumulate_queue_row` (`worker/cos/queue_row.rs:50`)
  sums per-worker per-queue counters into one `CoSQueueStatus`.
- Coordinator cross-worker merge: `aggregate_cos_statuses_across_workers`
  (`coordinator/mod.rs:914`); per-interface scalars `saturating_add` here
  (e.g. `timer_level0_sleepers` at `:932`).
- Wire: serde JSON, additive-only (`#[serde(rename, default)]`); Go mirror
  `pkg/dataplane/userspace/protocol.go:726` (JSON tags byte-for-byte).
- Prometheus `pkg/api/metrics_descriptors.go` + `metrics_userspace.go`; CLI
  `pkg/dataplane/userspace/cosfmt.go`.

## 4. Concrete design (v2)

### 4a. New struct `CoSQueueWaterfillCounters` (on `CoSQueueTelemetry`)

Plain `u64`, owner-worker single-writer (F5, F7). All monotonic (F1).

```rust
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::afxdp) struct CoSQueueWaterfillCounters {
    /// #1628: times this queue was admitted via the waterfill Phase-1
    /// (small-first honored) walk. Bumped at the Phase-1 `return Some`.
    /// Zero on the Proportional legacy-RR path (no phases).
    pub(in crate::afxdp) phase1_admissions: u64,
    /// #1628: times this queue was admitted via the Phase-2 (descending
    /// residual) walk. #1630 Phase-2-LOCK-IN fingerprint: an
    /// undershooting class with phase2_admissions climbing while
    /// phase1_admissions stays flat is locked into best-effort residual
    /// service — the exact failure #1625/#1630 named. (See §10 Q1 for
    /// the worked trace.)
    pub(in crate::afxdp) phase2_admissions: u64,
    /// #1628: times the waterfill selector VISITED this queue and found
    /// it eligible (nonempty + runnable + guarantee + exact) — i.e. the
    /// queue's owner worker actually had its backlog this pass. Pair
    /// with phase1+phase2 admissions to see how often a visit converted
    /// to service vs lost the token/budget gate. A class whose owner
    /// worker never sees its backlog (the fragmentation root cause)
    /// shows near-zero eligible_visits relative to its configured
    /// presence — the per-OWNER fragmentation signal that survives
    /// cross-worker aggregation because the queue has ONE owner.
    pub(in crate::afxdp) eligible_visits: u64,
}
```

### 4b. New per-interface (root) counters on `CoSInterfaceRuntime`

Plain `u64`, owner-worker single-writer, monotonic (F1, F8).

```rust
/// #1628: completed waterfill epochs (Phase-1 budget refills) on this
/// interface (this worker's view). Normalizer for the per-queue
/// admission counters ("admissions per epoch"). Bumped at the lazy
/// refill site.
pub(in crate::afxdp) waterfill_epochs: u64,
/// #1628: times Phase 1 broke into Phase 2 because the next ascending
/// queue's rate-scaled cost exceeded the remaining Phase-1 budget
/// (the `break` at mod.rs:910). Per-INTERFACE not per-queue (F8: the
/// break only sees the first crossing queue; attributing it per-queue
/// would silently miss the larger queues never reached). A high
/// breaks-per-epoch ratio means Phase 1 routinely exhausts its budget
/// mid-walk — the budget-split half of the diagnosis.
pub(in crate::afxdp) waterfill_phase1_budget_breaks: u64,
```

These sum across workers in `aggregate_cos_statuses_across_workers` exactly
like `timer_level0_sleepers` (`coordinator/mod.rs:932`). Summing IS the right
semantic here (unlike the cut considered/honored fields): epochs and
budget-breaks are events, and the operator wants the cluster-wide event rate;
the per-OWNER fragmentation signal lives on the per-queue `eligible_visits`
(F3 — a queue has one owner, so its row already reflects that single worker).

### 4c. Write sites (all inside `select_exact_cos_guarantee_queue_waterfill`)

Verified against the real control flow (Codex + AGY both confirmed):

1. **Epoch refill** (`mod.rs:793` `if waterfill_pass1_remaining_bytes == 0`):
   `root.waterfill_epochs = root.waterfill_epochs.wrapping_add(1);`
2. **Phase-1 eligible visit** (`mod.rs:832` after the
   `cos_queue_is_empty || !runnable || ...` continue gate passes and a head is
   present): bump the queue's `eligible_visits`.
3. **Phase-1 budget-exhausted break** (`mod.rs:906`, before `break` at `:910`):
   `root.waterfill_phase1_budget_breaks.wrapping_add(1)`.
4. **Phase-1 honor return** (`mod.rs:924`, before `return Some(...)`): bump the
   chosen queue's `phase1_admissions`.
5. **Phase-2 eligible visit** (`mod.rs:982` after the Phase-2 eligibility gate
   passes and a head is present): bump `eligible_visits` (so the visit count
   covers both phases' reachability).
6. **Phase-2 admission return** (`mod.rs:1015`, before `return Some(...)`):
   bump the chosen queue's `phase2_admissions`.

A single helper `count_waterfill_event(root, queue_idx, WaterfillEvent)`
(mirroring `count_park_reason`, `tx_completion.rs:51`) centralizes the queue
counter writes; the two root counters are bumped inline (they don't take a
queue_idx). Every site already holds the needed `&mut`.

### 4d. Snapshot aggregation

- `accumulate_queue_row` (`worker/cos/queue_row.rs`): 3 `saturating_add` lines
  for the per-queue waterfill counters (sum across worker instances; correct —
  a queue has one owner so only its owner's instance is nonzero in the steady
  state, and summing is safe regardless).
- `aggregate_cos_statuses_across_workers` (`coordinator/mod.rs:914`): 2
  `saturating_add` lines for `waterfill_epochs` + `waterfill_phase1_budget_breaks`
  on the interface row, mirroring `timer_level0_sleepers`.
- The worker-side interface-status builder
  (`worker/cos/mod.rs` / `worker/cos/status.rs`) copies the root counters from
  `CoSInterfaceRuntime` into the per-worker `CoSInterfaceStatus` before the
  coordinator sum.

### 4e. Wire surface (serde + Go mirror, F: wire_protocol_both_sides)

- Rust `protocol/cos.rs`: 3 new `u64` on `CoSQueueStatus`
  (`waterfill_phase1_admissions`, `waterfill_phase2_admissions`,
  `waterfill_eligible_visits`), 2 new `u64` on `CoSInterfaceStatus`
  (`waterfill_epochs`, `waterfill_phase1_budget_breaks`). Each
  `#[serde(rename="...", default)]`.
- Go `pkg/dataplane/userspace/protocol.go`: matching fields, JSON tags
  byte-for-byte.

### 4f. Prometheus + CLI

- 5 new Prometheus counter descriptors (`_total`) in
  `metrics_descriptors.go` + emit in `metrics_userspace.go`.
- `cosfmt.go`: surface the 3 per-queue waterfill counters in the per-queue
  detail block, gated `!= 0` like the existing `drainGuaranteeSentBytes`
  block; the 2 per-interface counters in the interface header block.

## 5. Public API preservation

No selector / service-fn signature changes. New helper
`count_waterfill_event` is internal `pub(in crate::afxdp)`. Wire surface is
additive-only (all `default`), so old↔new deserialize cleanly both directions.

## 6. Hidden invariants this change must preserve

- **Single-writer, same-thread read (F7):** every counter is written by the
  owner worker on the drain path; `build_worker_cos_statuses` reads them on the
  same worker thread and publishes via `ArcSwap`. No live cross-thread read →
  plain `u64` correct.
- **No new allocation, no per-packet cost:** writes are per-selection /
  per-epoch (per *batch* at most), strictly rarer than the existing
  `drain_park_*` writes already at these sites.
- **Selection ordering unchanged:** counters bumped adjacent to existing
  `return`/`break`/`continue`; budget decrement, RR cursor advance,
  `honored_mask` set all stay put.
- **Proportional-mode parity:** legacy RR arm untouched; its queues report zero
  waterfill counters (a correct "not in guarantee-rate mode" signal).
- **HA portability:** diagnostic-only, never synced, never read by the
  scheduler. No failover effect.

## 7. Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression | LOW | Pure counter increments adjacent to unchanged control flow; scheduler reads none of them. |
| Lifetime / borrow-checker | LOW | All sites hold the needed `&mut`; helper signature mirrors `count_park_reason`. |
| Performance regression | LOW | ≤ 1 `u64` write per selection/epoch; rarer than existing `drain_park_*`. Same owner cache line, no new false sharing. |
| Architectural mismatch | LOW | F2/F3/F5 resolved: scope is strictly the worker-local waterfill selector, dedicated struct, monotonic totals, per-queue signal keyed to single owner. v8 fair-share explicitly deferred to its owning PR. |

## 8. Test plan

- `cargo build` clean; `cargo test --release` full suite green.
- New unit tests in `queue_service/tests.rs` driving the waterfill selector
  through: (a) Phase-1 honor → `phase1_admissions == 1`, `phase2 == 0`,
  `eligible_visits >= 1`; (b) Phase-1 budget-exhausted break into Phase 2 →
  root `waterfill_phase1_budget_breaks == 1`, chosen queue
  `phase2_admissions == 1`; (c) epoch refill → `waterfill_epochs` advances;
  (d) Proportional mode → all waterfill counters stay 0 (counter-factual: a
  wrong write site would light them up on the RR path). Assert the
  Phase-2-lock-in fingerprint directly: a fixture where the small class is
  only ever Phase-2-admitted yields `phase2 > 0 && phase1 == 0` on its row.
- 5/5 flake loop on the new named tests.
- Go: `protocol_test.go` serde→Go round-trip parity, `cosfmt_test.go` render,
  `metrics_test.go` descriptor wiring. `go test ./...` 30 packages.
- Smoke (loss userspace cluster) is the PARENT's job (serialized). This agent
  posts `<!-- AWAITING-PARENT-SMOKE-1628 -->`.

## 9. Out of scope (explicitly)

- Any waterfill scheduling-decision change (that's #1630's fix).
- **v8 fair-share observability** (`shared_cos_lease` per-worker fair-share
  watermark counters). F2: the real `worker_fair_share` lives there, not in the
  selector. Diagnosing it needs a counter at `acquire_v8`
  (`shared_cos_lease/mod.rs:1175-1217`) / the epoch-rotate
  (`rotate_epoch_v8.rs:306`). Deferred to the #1630 FIX PR, which owns and
  reshapes that surface — instrumenting it now would be throwaway against an
  unknown fix design (both reviewers concur the deferral is correct).
- Flat-root-shaper FCFS per-class grant counters (`SharedCoSRootLease`) —
  separate larger surface; deferred to #1630 fix.
- `coordinator/cos_state.rs` / `rotate_epoch_v8.rs` counters from the #1628
  body's broad list — the verified consumer is the worker-local waterfill
  selector, not v8 epoch rotation. Deferred.

## 10. Open questions for adversarial re-review

1. **Worked trace for the Phase-2-lock-in fingerprint:** under the #1630
   failure, `waterfill_pass1_remaining_bytes` never reaches 0 (Phase-2 returns
   don't decrement it), so the refill at `mod.rs:793` rarely fires → few
   `waterfill_epochs`, and the small class is admitted only via Phase 2 →
   `phase2_admissions` climbs, `phase1_admissions` flat. Does that signature
   uniquely identify Phase-2 lock-in, or can a healthy guarantee-rate
   interface produce the same signature transiently?
2. **Is `eligible_visits` the right fragmentation signal now that it's
   per-queue (single owner)?** A class whose owner worker rarely sees its
   backlog shows low `eligible_visits` relative to its `phase*_admissions` on
   other workers — but with cross-binding redirect the queue has ONE owner, so
   is there any aggregation path that still blurs this?
3. **Are the 2 per-interface counters (`waterfill_epochs`,
   `phase1_budget_breaks`) safe to SUM across workers** (F3 said considered/
   honored were NOT)? My claim: epochs/breaks are per-worker *events* and the
   cluster-wide rate is what the operator wants; they are not a
   "considered set size" that masks fragmentation. Challenge this.
4. **Does cutting `skipped_not_backlogged` lose a needed signal**, or do
   `eligible_visits` + `owner_worker_id` + `queued_bytes` fully cover the
   "no load vs fragmented load" distinction?
5. **Is the dedicated `CoSQueueWaterfillCounters` struct the right home**, or
   should these live on `CoSQueueOwnerProfile` (the other per-queue telemetry
   struct) — noting that one is `AtomicU64` and these are plain `u64`?
6. **Write-site #2/#5 (`eligible_visits` after the eligibility gate):** is
   counting at "passed eligibility AND has a head" the right definition of
   "visited eligibly", or should it count at the gate entry (before the token
   check) so token-starvation parks are still counted as visits?
