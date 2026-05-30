# #1628 — Empirical per-class waterfill trace counters for the CoS scheduler

**Status:** IMPLEMENTED — 4-of-4 clean code review (Codex+AGY+Copilot+Claude-SMR MERGE-READY) at HEAD ec8790b43; AWAITING-PARENT-SMOKE. See reviewer-ids.md for the full plan(4)+code(4) review trail. (Plan reached PLAN-READY at v5 after Codex r4 PLAN-READY + AGY r4 PLAN-NEEDS-MINOR borrow fix — the kind-hoist.)

### v4→v5 reviewer-driven change (round 4)

- **AGY r4 (new, real): borrow conflict at the eligible-visit writes.** `head`
  (`&`-borrow of `queue`) is still used at the `return`'s `match head`, so a
  `&mut queue.telemetry` write before the return conflicts. → **Hoist
  `let kind = match head {...}` up next to `head_len`** (both `Copy`), ending
  `head`'s borrow immediately; all telemetry writes then compile and the return
  uses the pre-computed `kind`. §4c. Codex r4 was PLAN-READY independently.

### v3→v4 reviewer-driven changes (round 3)

- **MAJOR (both, identical fix): `waterfill_min_epochs_per_worker` conflated a
  Phase-2-locked worker with an idle worker AND had a default-0 trap.** An idle
  worker never advances `waterfill_epochs` (skips `drain_shaped_tx`'s service
  path) so a naive MIN reports 0; and `or_default()` seeds 0 so `.min(0)==0`
  always. → The MIN is now taken **only over interface rows with active
  exact-guarantee backlog**, seeded on first inclusion via a local
  `HashSet<ifindex>` (not `worker_instances`, which counts idle workers too).
  See §4d.
- **MINOR (AGY): lock-in signature is healthy for large classes above the
  Phase-1 cutoff.** → `phase2_admissions` doc qualified: the lock-in reading
  applies ONLY to small classes configured to fit Phase-1; the same shape on a
  large class is expected rate-limiting. §4a.
- **MINOR (AGY): write-site typo** — bare `root.x.wrapping_add(1)` is a no-op;
  all sites now use `x = x.wrapping_add(1)`. §4c.
- **MINOR (Codex): head-borrow ordering** — per-queue telemetry writes go AFTER
  `head_len`/`kind` are computed and the `head` borrow ends. §4c.
- **MINOR (Codex): stale `count_waterfill_event` text** removed from §5 + §7
  risk row (v3 made all increments inline).
- Confirmed by both r3: inline disjoint-field root writes compile; v8
  fair-share deferral correct.

### v2→v3 reviewer-driven changes (round 2)

Both r2 reviewers confirmed the v2 counter set, struct placement, monotonic
redesign, `eligible_visits` write location, and the `skipped_not_backlogged`
cut. The remaining findings were framing/API-shape, not counter-set:

- **F1 borrow shape (Codex minor + AGY major):** a
  `count_waterfill_event(&mut root, queue_idx, ...)` helper will NOT compile at
  the Phase-1/Phase-2 sites because `let queue = &mut root.queues[queue_idx]`
  is already live there (unlike `count_park_reason`, which is only ever called
  at the end of an iteration after `queue` is dropped). → **Per-queue counters
  are incremented INLINE via the live `queue` borrow**
  (`queue.telemetry.waterfill_counters.X = ...wrapping_add(1)`); the two
  per-interface root counters are bumped via disjoint `root` field borrows
  (also inline). No helper for the queue events.
- **F2 cross-worker summing masks a single frozen worker (both):** if one
  worker locks into Phase 2, its `waterfill_epochs` freezes at a low value, but
  summing across 6 workers lets the 5 healthy cores' climbing counters drown
  it. → **Add a coordinator-level MIN aggregation
  `waterfill_min_epochs_per_worker`** (follows the existing `.max()` pattern at
  `coordinator/mod.rs:927`). A single stalled core drops the MIN to its frozen
  value even while the SUM climbs — the stalled-core flag the operator needs.
- **F3 the Phase-2 signature is NOT unique (both):** a healthy interface under
  asymmetric/idle load (small classes idle, a large class above the Phase-1
  cutoff) naturally produces `phase2>0, phase1=0, epochs frozen`. →
  **Reframed throughout: these counters are EVIDENCE to be combined with the
  existing per-queue depth/park telemetry, not a standalone fingerprint.** The
  starving-lock-in case is distinguished from healthy-idle by pairing with
  `queued_bytes > 0` AND `root_token_starvation_parks` /
  `queue_token_starvation_parks` on the same row (both already on
  `CoSQueueStatus`). Test assertions softened accordingly.
- **F4 `eligible_visits` undercounts token-parked-but-backlogged queues
  (AGY):** a backlogged queue parked on token starvation is `!runnable` →
  skipped at the eligibility gate (`mod.rs:818`) → low `eligible_visits`,
  which alone reads as "idle". → **Documented the pairing:** low
  `eligible_visits` + high `*_starvation_parks` = backlogged-but-starved; low
  `eligible_visits` + low parks = genuinely idle. No new counter — the park
  counters already capture this (they fire at the park sites `mod.rs:855/878`).

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
    /// residual) walk. EVIDENCE for #1630 Phase-2 lock-in, NOT a unique
    /// fingerprint: `phase2_admissions` climbing while `phase1_admissions`
    /// stays flat ALSO occurs on a healthy guarantee-rate interface for a
    /// class above the Phase-1 cutoff under asymmetric load (r2 finding).
    /// The starving-lock-in case is identified only by COMBINING this with
    /// `queued_bytes > 0` AND `root_token_starvation_parks` /
    /// `queue_token_starvation_parks` on the same row, AND ONLY for a
    /// SMALL class whose rate-scaled cost is configured to fit within the
    /// Phase-1 budget: such a class that has backlog, is being parked, and
    /// is only ever Phase-2-admitted is the locked-in case. For a LARGE
    /// class above the Phase-1 cutoff, the same shape
    /// (`phase1==0, phase2>0, backlog, parks`) is HEALTHY, expected
    /// rate-limiting — it was never supposed to win Phase 1. The
    /// small-vs-large distinction is the operator's (or the consuming
    /// analysis's) call from the configured `transmit-rate` vs the
    /// interface Phase-1 budget; this counter does not encode it. An idle
    /// small class with no backlog and no parks is healthy residual
    /// service regardless. (See §10 Q1.)
    pub(in crate::afxdp) phase2_admissions: u64,
    /// #1628: times the waterfill selector VISITED this queue and found
    /// it eligible (nonempty + runnable + guarantee + exact) — i.e. the
    /// queue's owner worker actually had its backlog this pass. Counted
    /// AFTER the eligibility gate (nonempty+runnable+guarantee+exact) and
    /// head-present check, BEFORE the root/queue token gate — so a queue
    /// that is eligible but token-starved IS counted as a visit.
    ///
    /// Interpretation requires pairing (r2 finding F4): a backlogged queue
    /// PARKED on token starvation is marked `!runnable` and skipped at the
    /// eligibility gate, so it shows LOW `eligible_visits`. Therefore:
    ///   * low eligible_visits + high `*_starvation_parks` (same row) =
    ///     backlogged but starved/parked — NOT idle.
    ///   * low eligible_visits + low parks + zero queued_bytes =
    ///     genuinely idle (no load funneled to this owner).
    /// The park counters that disambiguate already exist on CoSQueueStatus
    /// (`root_token_starvation_parks` / `queue_token_starvation_parks`),
    /// so no new counter is added for the parked case.
    pub(in crate::afxdp) eligible_visits: u64,
}
```

### 4b. New per-interface (root) counters on `CoSInterfaceRuntime`

Plain `u64`, owner-worker single-writer, monotonic (F1, F8).

```rust
/// #1628: completed waterfill epochs (Phase-1 budget refills) on this
/// interface, THIS WORKER'S view. Bumped at the lazy refill site.
///
/// NOT a per-queue normalizer (r2 finding): per-queue `phase*_admissions`
/// are owner-local, but the summed cross-worker `waterfill_epochs`
/// includes other workers' epochs, so the ratio would be diluted by
/// worker count. Used as a cluster event counter (SUM) PLUS the
/// per-worker MIN below — a single worker locked into Phase 2 freezes
/// its own `waterfill_epochs`, which the SUM hides but the MIN exposes.
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

These SUM across workers in `aggregate_cos_statuses_across_workers` like
`timer_level0_sleepers` (`coordinator/mod.rs:932`) for the cluster event rate.

**`waterfill_min_epochs_per_worker` MIN aggregation (r2 F2 + r3 fix).** The MIN
must NOT be a naive `.min()` for two reasons both r3 reviewers caught:

1. **Default-0 trap:** `interfaces.entry(ifindex).or_default()`
   (`coordinator/mod.rs:922`) seeds every `u64` to 0, so
   `entry.min(iface.waterfill_epochs)` is **always 0**. Seed on first inclusion.
2. **Idle-worker conflation:** a worker that owns no backlogged exact-guarantee
   queue never enters `drain_shaped_tx`'s service path
   (`queue_service/mod.rs:167`), so its `waterfill_epochs` stays 0 forever — a
   naive MIN would report 0 (looks like lock-in) when that worker is simply
   idle, masking a real lock-in on a different worker.

The MIN is therefore taken **only over worker interface rows that have current
active exact-guarantee backlog**, seeded via a dedicated "first included" flag
(not `worker_instances`, which counts all workers including idle ones):

```rust
// per-interface, in aggregate_cos_statuses_across_workers:
let iface_has_active_exact_backlog = iface.queues.iter().any(|q| {
    q.exact && q.guarantee_enabled && (q.queued_bytes > 0 || q.queued_packets > 0)
});
if iface_has_active_exact_backlog {
    if min_epochs_seen.insert(iface.ifindex) /* first active worker for ifindex */ {
        entry.waterfill_min_epochs_per_worker = iface.waterfill_epochs;
    } else {
        entry.waterfill_min_epochs_per_worker =
            entry.waterfill_min_epochs_per_worker.min(iface.waterfill_epochs);
    }
}
// If NO worker has active exact backlog on the interface, the field stays 0
// (its or_default()) — interpreted as "no active lock-in candidate", NOT
// "locked at 0". The CLI/Prometheus doc states this explicitly.
```

`min_epochs_seen` is a local `HashSet<i32>` in the aggregation fn (the
aggregation already builds local `BTreeMap`s, so one more local set is free).
The MIN lives only on the aggregated `CoSInterfaceStatus`, not the per-worker
runtime. A worker locked in Phase 2 *while holding backlog* keeps its
`waterfill_epochs` frozen and IS included in the MIN, dropping it; an idle
worker is excluded so it can't poison it.

The per-OWNER fragmentation signal lives on the per-queue `eligible_visits`
(a queue has one owner, so its row reflects that single worker — F3).

### 4c. Write sites (all inside `select_exact_cos_guarantee_queue_waterfill`)

Verified against the real control flow (Codex + AGY both confirmed). All
increments use the explicit `x = x.wrapping_add(1)` assignment form — a bare
`x.wrapping_add(1)` expression statement is a no-op (r3 AGY catch).

**Borrow ordering (r3 Codex + r4 AGY).** At the per-queue sites, `head` is a
`&`-borrow of `queue` (`let head = cos_queue_front(queue)`). In the current
source `head` is STILL used at the return (`mod.rs:920 match head` / `:1011`),
so a `&mut queue.telemetry` write at the eligible-visit site (between the
`head` definition and the return) would conflict — `head` outlives it. r4 AGY
flagged this as a real compile defect in the v3/v4 wording. The fix is to
**hoist the `kind` match next to `head_len`, immediately after `head` is
obtained, so `head`'s borrow ends right there** (both `head_len: u64` and
`kind: ExactCoSQueueKind` are `Copy`). After that line `head` is dead, every
subsequent `queue.telemetry` mutation compiles, and the `return` uses the
pre-computed `kind` instead of re-matching `head`. This is a small reorder of
the existing `let kind = match head {...}` (currently at `:920` / `:1011`) up
to just after `head_len`; no behavior change.

1. **Epoch refill** (`mod.rs:793` `if waterfill_pass1_remaining_bytes == 0`):
   `root.waterfill_epochs = root.waterfill_epochs.wrapping_add(1);` (no `queue`
   borrowed yet — pre-loop).
2. **Phase-1 eligible visit** — after hoisting `let head_len = ...; let kind =
   match head {...};` (so `head` is dead):
   `queue.telemetry.waterfill_counters.eligible_visits =
   queue.telemetry.waterfill_counters.eligible_visits.wrapping_add(1);`.
3. **Phase-1 budget-exhausted break** (`mod.rs:906`, before `break` at `:910`):
   `root.waterfill_phase1_budget_breaks =
   root.waterfill_phase1_budget_breaks.wrapping_add(1);` (disjoint root field;
   same pattern as the existing `:913` write — compiles regardless of the
   `queue` borrow since it touches a different `root` field).
4. **Phase-1 honor** (before `return Some(...)`, using the hoisted `kind`):
   `queue.telemetry.waterfill_counters.phase1_admissions =
   ...wrapping_add(1);`.
5. **Phase-2 eligible visit** — after the hoisted `head_len`/`kind` in the
   Phase-2 body: bump `eligible_visits` (so the visit count covers both phases'
   reachability).
6. **Phase-2 admission** (before `return Some(...)`, using the hoisted `kind`):
   bump the chosen queue's `phase2_admissions`.

The implementation must hoist `kind` in BOTH the Phase-1 ascending loop and the
Phase-2 descending loop; the unit tests then confirm the `kind`-hoist did not
change which variant is returned (the selector's Local/Prepared dispatch is
unaffected).

**All increments are INLINE; no helper that takes `&mut root` (r2 finding
F1).** A `count_waterfill_event(&mut root, queue_idx, ...)` helper would NOT
compile at the Phase-1/Phase-2 sites: unlike `count_park_reason` (called only
at end-of-iteration, after `queue`/`head` are dropped), these sites have
`let queue = &mut root.queues[queue_idx]` and `let head = cos_queue_front(queue)`
live through the `return`/`break`, so passing the whole `&mut root` to a
function (which could touch `root.queues`) overlaps the existing borrow.

The increments are therefore:

- **Per-queue counters** (`eligible_visits`, `phase1_admissions`,
  `phase2_admissions`): direct on the live borrow,
  `queue.telemetry.waterfill_counters.<field> =
  queue.telemetry.waterfill_counters.<field>.wrapping_add(1);`.
- **Root counters** (`waterfill_epochs`, `waterfill_phase1_budget_breaks`):
  direct `root.<field> = root.<field>.wrapping_add(1);`. This is the SAME
  disjoint-field pattern the existing selector already uses — `mod.rs:913`
  writes `root.waterfill_pass1_remaining_bytes` and `:919` writes
  `root.exact_guarantee_rr` while `queue`/`head` are still live and compile
  today. `root.waterfill_phase1_budget_breaks` (added at the `:906` branch,
  before the `break`) and `root.waterfill_epochs` (added at the `:793` pre-loop
  refill, where no `queue` is borrowed yet) are provably the same shape.

No new borrow is introduced at any site.

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
  `waterfill_eligible_visits`), 3 new `u64` on `CoSInterfaceStatus`
  (`waterfill_epochs`, `waterfill_phase1_budget_breaks`,
  `waterfill_min_epochs_per_worker`). Each `#[serde(rename="...", default)]`.
  `waterfill_min_epochs_per_worker` is only ever set by the coordinator MIN
  aggregation (per-worker `CoSInterfaceStatus` leaves it 0; the coordinator
  fills it from the worker `waterfill_epochs` values).
- Go `pkg/dataplane/userspace/protocol.go`: matching fields, JSON tags
  byte-for-byte.

### 4f. Prometheus + CLI

- 5 new Prometheus counter descriptors (`_total`) for the per-queue +
  per-interface monotonic counters, plus 1 gauge for
  `waterfill_min_epochs_per_worker`, in `metrics_descriptors.go` + emit in
  `metrics_userspace.go`.
- `cosfmt.go`: surface the 3 per-queue waterfill counters in the per-queue
  detail block, gated `!= 0` like the existing `drainGuaranteeSentBytes`
  block; the 3 per-interface counters in the interface header block.

## 5. Public API preservation

No selector / service-fn signature changes. No new helper function (the
counter writes are all inline — see §4c; a `&mut root` helper would not compile
at the per-queue sites). Wire surface is additive-only (all `default`), so
old↔new deserialize cleanly both directions.

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
| Lifetime / borrow-checker | LOW | All increments inline; per-queue writes after the `head` borrow ends, root writes via disjoint fields (the existing `mod.rs:913` pattern). No `&mut root` helper. |
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
  wrong write site would light them up on the RR path); (e)
  `eligible_visits` counts a token-starved-but-backlogged queue on the visit
  where it is still `runnable` (before the park marks it `!runnable`).
- The tests assert the COUNTERS increment at the right sites, NOT that any one
  counter is a unique fingerprint (r2 F3): the `phase2>0 && phase1==0` shape is
  asserted to occur, but the test docstring records that this shape is also
  healthy-residual for above-cutoff classes — the distinguishing signal is the
  paired `queued_bytes`/`*_starvation_parks`, which the unit test sets up
  explicitly in the lock-in fixture and leaves zero in the healthy-idle fixture.
- Coordinator tests on `aggregate_cos_statuses_across_workers`:
  - one worker WITH active exact backlog reporting frozen `waterfill_epochs`
    and others (also with backlog) climbing → `waterfill_min_epochs_per_worker`
    equals the frozen value while the summed `waterfill_epochs` climbs (the F2
    single-worker-mask regression guard);
  - an IDLE worker (no active exact backlog) reporting `waterfill_epochs == 0`
    alongside an active worker at a high value → MIN equals the ACTIVE worker's
    value, NOT 0 (the r3 idle-conflation regression guard);
  - no worker with active exact backlog → MIN stays 0 (documented "no lock-in
    candidate" sentinel, not a false lock-in).
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

## 10. Open questions for adversarial re-review (v4)

1. **Is the small-vs-large-class qualifier on the `phase2_admissions` lock-in
   reading now correct and complete** (§4a), or is there still a residual
   ambiguity the docs should state — e.g. a borderline class whose configured
   `transmit-rate` is right at the Phase-1 budget boundary so it flips between
   honored and residual epoch-to-epoch?
2. **Does the active-exact-backlog-guarded MIN (§4d) fully resolve the
   idle/locked conflation**, or can a worker that has backlog but is parked on
   token starvation (so its queues show `queued_bytes > 0` but it is NOT
   actually entering the waterfill selector this instant) still be miscounted
   into the MIN? Is "has queued_bytes" the right inclusion predicate, or should
   it be "entered the selector at least once this window"?
3. **Is the `HashSet<ifindex>` first-inclusion seed (§4d) the simplest correct
   approach**, or is there a cleaner single-pass formulation (e.g. an
   `Option<u64>` accumulator per interface)?
4. **Scope:** is deferring the v8 fair-share counter still the right call? (Both
   r1 + r3 reviewers endorsed the deferral; re-confirm against v4.)
