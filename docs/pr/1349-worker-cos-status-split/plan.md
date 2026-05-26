# #1349 — Split `build_worker_cos_statuses_from_maps` into focused helpers

**Status:** PLAN-READY v3 — Codex round-3 MINOR (doc-metadata stale counts) addressed. AGY round-2 PLAN-READY, Claude SMR PLAN-READY, Codex round-3 PLAN-READY after MINOR fix. Gemini round-2 PLAN-KILL on style/premise grounds (linear-mapper-not-worth-fragmenting); per [[feedback_gemini_low_signal_on_refactor]] this refactor stream does not gate merges on Gemini's verdict alone when the other three reviewers agree.

## Round-1 review summary

- **AGY: PLAN-READY** — verified all 12 invariants, ratified directory layout choice, confirmed test-file rename preserves history. No findings.
- **Codex: PLAN-NEEDS-MAJOR** — 5 concrete findings: (1) `queue_uses_shared_exact_service` missing from preserved-API list; tests at cos_tests.rs:1919+ call it directly; (2) "field-write order irrelevant" claim false — `priority` is gated by `worker_instances == 0` at cos.rs:602 BEFORE the increment; (3) #784 MAX-not-sum not test-covered in worker-status path; (4) `accumulate_queue_row` signature contradicts itself (one place lists `owner_profile_target` + `binding_profile`, another excludes them); (5) allocation wording sloppy.
- **Gemini Pro 3: PLAN-KILL** — argues the function is a linear sequential mapper, no algorithmic complexity, the four "concerns" are strictly sequential not interleaved, and `merge_binding_profile_if_target` replacing a 3-line inline `if` is net-negative readability.
- **Claude SMR: PLAN-NEEDS-MINOR** — same `queue_uses_shared_exact_service` cross-submodule visibility item Codex flagged; test-file `#[path]` directive note; clarification that `queue_uses_shared_exact_service` is module-private.

## Round-2 response to Gemini PLAN-KILL

Gemini's substantive point is that `merge_binding_profile_if_target` adds a call boundary around a 3-line inline `if`. **Accepted.** v2 drops that helper and inlines the gated merge directly in the orchestrator — it's already a 3-line conditional that reads fine, and the gating is documented by the comment that survives at cos.rs:791-805.

Gemini's broader claim — "linear mapper, no value in splitting" — is rejected. The function is 268 LOC (2.68x the project's 100-LOC refactor cue) and roughly 40% of those lines are multi-paragraph comment blocks explaining #709/#710/#718/#748/#751/#760/#784. The body is sequential in mechanical terms but mentally interleaved: a reader has to hold the #709 binding-scoped attribution rule, the #751 per-queue source switch, the #784 MAX-not-sum invariant, the #760 overshoot-hunt accounting, and the #710/#718 single-writer drop counters all simultaneously to parse the inner queue loop. Splitting `accumulate_interface_root` and `accumulate_queue_row` lets a reader load one #N issue's worth of context at a time. AGY's review confirms this read of the function.

The plan is not declaring a perf win; the trade-off is reviewer cycles vs diff size. v2 narrows the split (drops the binding-profile-merge helper) so the diff is smaller and the marginal call boundaries that Gemini objects to are gone.

## Issue framing

`userspace-dp/src/afxdp/worker/cos.rs::build_worker_cos_statuses_from_maps`
is a 268-LOC body (cos.rs:535-832, file is 836 LOC total) that walks an
iterator of `(cos_map, binding_live)` pairs and produces the on-wire
`Vec<CoSInterfaceStatus>` used by the `show class-of-service interface`
RPC and the Prometheus scrape path. `docs/engineering-style.md` cites
">100 LOC is a refactor cue" and the body is 2.68x over. It interleaves
four logical concerns the reader has to swap context between:

1. Owner-profile snapshot (#709 once-per-binding-per-scrape pattern,
   binding-scoped — cannot be queue-scoped).
2. Per-interface accumulator (ifindex resolution, name fallback, root
   shaping rate, burst, worker instance count, timer-wheel sleeper
   counts).
3. Per-queue row accumulation (priority/exact/guarantee, transmit rate,
   buffer/queued bytes, runnable/parked counts, surplus/deficit,
   flow-fair telemetry, drop-reason counters, ECN, per-queue
   owner-profile drain telemetry from #751, the #760 overshoot-hunt
   bytes).
4. Final flattening into `Vec<CoSInterfaceStatus>` with sort + the
   `nonempty_queues` / `runnable_queues` summaries.

The issue's sketch decomposes into owner-profile / queue-row /
interface-row / exact-classifier helpers under `worker/cos_status/`. The
standing rule on this work item directs the split under `worker/cos/`
sub-dir using the project's module/foo convention, which means
**converting the existing single-file `worker/cos.rs` into a
`worker/cos/` directory module**. That keeps every cos worker helper —
the existing functions plus the new split helpers — in one place, and
follows the same pattern already used by `worker/loop_body/`,
`afxdp/coordinator/`, `afxdp/cos/`, `afxdp/frame/`, etc.

## Honest scope/value framing

This is **pure code motion** with one minor structural extraction.
There is no algorithmic change, no API change, no allocation-rule
change, no concurrency change. The win is reviewer cycles: the
existing 268-LOC body forces every reader to swap in #709 / #710 /
#718 / #748 / #751 / #760 / #784 context simultaneously. After the
split each helper is small enough to be reviewed against ONE issue's
discipline at a time, and the orchestrator becomes a 30-40 line read.

**If reviewers conclude the perf gain is too small to justify the
churn, PLAN-KILL is an acceptable verdict.** This is a readability
refactor on a control-plane path — there is no perf gain to claim;
the value is human review surface area. If the reviewer panel judges
the existing function readable enough to keep as-is, killing the plan
is the correct call.

Absolute scale: `build_worker_cos_statuses_from_maps` runs once per
status RPC (default scrape is 1Hz, plus on-demand `show
class-of-service interface`). Per call it walks
`O(workers × interfaces × queues)` — at deployment scale ~6 workers ×
~6 interfaces × ~8 queues = ~288 queue iterations per scrape. The
function is not on any packet path. Cycles spent here are completely
in the noise of even a 1 Mpps dataplane.

## What's already shipped / partially batched

- `cos.rs` already extracts `OwnerProfileSnapshot` (struct),
  `owner_profile_snapshot`, `merge_owner_profile_sum`,
  `merge_binding_scoped_owner_profile`,
  `merge_cos_queue_owner_profile_sum` as named helpers. Several
  decisions the original 268-LOC body inlines have therefore already
  been distilled into named functions — the split is finishing a
  pattern this file already started.
- `unique_owner_profile_row` (cos.rs:204-246) is already a separate
  helper. The issue calls out `determine_unambiguous_owner_local_exact_queue`
  as a target — that **is** `unique_owner_profile_row` under a longer
  name. Renaming it back to the longer form is optional; this plan
  keeps the existing name and exposes it from the new
  `cos/exact_classifier.rs` submodule.
- Tests already live in `worker/cos_tests.rs` (2112 LOC),
  included today via `#[cfg(test)] #[path = "cos_tests.rs"] mod tests;`
  at `cos.rs:834-836`. They will follow `cos.rs` into the new
  `worker/cos/` directory as `worker/cos/tests.rs`. The `#[path]`
  directive is dropped in favor of standard `#[cfg(test)] mod tests;`
  resolution to the sibling file (Claude SMR M2). Other than the
  rename itself, no test bodies move in this PR — except for the
  one new `active_flow_buckets_peak_is_max_not_sum_across_workers`
  test added per Codex finding 3.

## Concrete design

### Target directory layout

```
userspace-dp/src/afxdp/worker/
├── cos/
│   ├── mod.rs              # all existing pub(super)/pub(crate) items re-exported
│   ├── owner_profile.rs    # OwnerProfileSnapshot, owner_profile_snapshot,
│   │                       #   merge_owner_profile_sum,
│   │                       #   merge_binding_scoped_owner_profile,
│   │                       #   merge_cos_queue_owner_profile_sum
│   ├── runtime.rs          # build_worker_cos_owner_live_by_tx_ifindex,
│   │                       #   build_worker_cos_fast_interfaces,
│   │                       #   queue_uses_shared_exact_service,
│   │                       #   cos_runtime_config_changed,
│   │                       #   reset_binding_cos_runtime,
│   │                       #   reset_worker_cos_runtimes,
│   │                       #   vacate_all_shared_exact_slots_for_binding
│   ├── exact_classifier.rs # unique_owner_profile_row
│   ├── interface_row.rs    # accumulate_interface_root(&mut entry, ifindex,
│   │                       #   root, forwarding) — items 2 of decomposition
│   │                       #   list, including timer-wheel sleeper counts and
│   │                       #   the name-resolution fallback chain
│   ├── queue_row.rs        # accumulate_queue_row(&mut status, queue,
│   │                       #   queue_config) — items 3 of decomposition
│   │                       #   list, including #751 per-queue drain hist,
│   │                       #   #710 / #718 drop counters, #760 overshoot-hunt
│   │                       #   (binding-scoped merge stays inline in the
│   │                       #   orchestrator per Gemini round-1 KILL counter-example)
│   ├── status.rs           # build_worker_cos_statuses + the orchestrator
│   │                       #   build_worker_cos_statuses_from_maps
│   └── tests.rs            # ex worker/cos_tests.rs, brought in via mod tests
└── mod.rs                  # unchanged `mod cos;` line; the re-exports
                            # continue to resolve through cos::mod
```

The split files are sized so that each is comfortably below the
2000-LOC file ceiling and each function is below 100 LOC. The
`worker/cos_tests.rs` file (2112 LOC) becomes `worker/cos/tests.rs`;
no test bodies move in this PR.

### Helper signatures

The 268-LOC body's inner loop body is reorganized as:

```rust
// cos/interface_row.rs
pub(super) fn accumulate_interface_root(
    entry: &mut crate::protocol::CoSInterfaceStatus,
    ifindex: i32,
    root: &CoSInterfaceRuntime,
    forwarding: &ForwardingState,
);
```
- Owns `entry.ifindex = ifindex` assignment (cos.rs:560-561).
- Owns name resolution (ifindex_to_config_name → ifindex_to_name → "ifindex-N").
- Owns `shaping_rate_bytes`, `burst_bytes`, `worker_instances` MAX/saturating_add accumulation.
- Owns timer level0/level1 sleeper sum.
- Does NOT touch queues — those are accumulated by the caller via the queue helper.

```rust
// cos/queue_row.rs
pub(super) fn accumulate_queue_row(
    status: &mut crate::protocol::CoSQueueStatus,
    queue: &CoSQueueRuntime,
    queue_config: Option<&CoSQueueConfig>,
);
```
- Owns the full per-queue accumulation block — priority, exact,
  guarantee_enabled, transmit_rate_bytes, buffer/queued bytes,
  runnable/parked counts, next_wakeup_tick, surplus_deficit,
  active_flow_buckets_peak (#784 MAX semantics preserved),
  flow_fair, drop counters (#710/#718), and the **per-queue**
  drain telemetry from owner_profile (#751: drain_invocations,
  drain_latency_hist, drain_sent_bytes and the four #760
  overshoot-hunt counters).
- Stays atomic-relaxed-load only. No I/O. Same allocation profile as
  today's inline block: the `forwarding_class.clone()` at cos.rs:599
  and the `drain_latency_hist.resize(DRAIN_HIST_BUCKETS, 0)` guarded
  by `queue_invocations > 0` (cos.rs:716-717) are preserved — no
  net-new allocations introduced.
- **Internal field-write ordering is NOT free** (Codex round-1
  finding 2). The original at cos.rs:602-604 sets
  `status.priority = queue.config.priority` only when
  `status.worker_instances == 0`, BEFORE incrementing
  `worker_instances` at cos.rs:612. `accumulate_queue_row` must
  preserve this read-before-write order: check `worker_instances`
  first, then increment. Other accumulators (saturating_add, max)
  are independent slots and can be ordered freely, but the
  priority gate is not. Re-stated in invariants list #1 below.
- **Does NOT take `binding_profile` or `owner_profile_row`.** The
  v2 orchestrator inlines the gated `merge_binding_scoped_owner_profile`
  call directly after `accumulate_queue_row` returns. The two
  concerns stay structurally separate (per-queue accumulation
  vs binding-scoped attribution) without a redundant helper.

**DROPPED in v2:** the `merge_binding_profile_if_target` helper. The
gated merge stays inline in the orchestrator as a 3-line `if`. Gemini
Pro 3's round-1 counter-example on this point is accepted: wrapping a
3-line `if` with a 5-arg call is net-negative readability.

```rust
// cos/status.rs
pub(super) fn build_worker_cos_statuses(
    bindings: &[BindingWorker],
    forwarding: &ForwardingState,
) -> Vec<crate::protocol::CoSInterfaceStatus>;
pub(super) fn build_worker_cos_statuses_from_maps<'a, I>(
    cos_maps: I,
    forwarding: &ForwardingState,
) -> Vec<crate::protocol::CoSInterfaceStatus>
where
    I: IntoIterator<
        Item = (
            &'a FastMap<i32, CoSInterfaceRuntime>,
            Option<&'a BindingLiveState>,
        ),
    >;
```
- The orchestrator becomes (v2 — inline binding-profile merge):

```rust
let mut interfaces = BTreeMap::<i32, CoSInterfaceStatus>::new();
let mut queue_maps = BTreeMap::<i32, BTreeMap<u8, CoSQueueStatus>>::new();
for (cos_map, binding_live) in cos_maps {
    let binding_profile = binding_live.map(owner_profile_snapshot);
    let owner_profile_row = unique_owner_profile_row(cos_map, forwarding);
    for (&ifindex, root) in cos_map {
        let entry = interfaces.entry(ifindex).or_default();
        accumulate_interface_root(entry, ifindex, root, forwarding);
        let interface_config = forwarding.cos.interfaces.get(&ifindex);
        let queue_map = queue_maps.entry(ifindex).or_default();
        for queue in &root.queues {
            let status = queue_map.entry(queue.queue_id()).or_default();
            status.queue_id = queue.queue_id();
            let queue_config = interface_config.and_then(|cfg| {
                cfg.queues.iter().find(|c| c.queue_id == queue.queue_id())
            });
            accumulate_queue_row(status, queue, queue_config);
            // #709/#748/#751: binding-scoped fields surface only on the
            // single unambiguous owner-local exact queue row on the
            // whole binding. Kept inline (not extracted to a helper)
            // because the 3-line conditional reads cleaner than a
            // 5-arg call.
            if owner_profile_row == Some((ifindex, queue.queue_id())) {
                if let Some(profile) = binding_profile.as_ref() {
                    merge_binding_scoped_owner_profile(status, profile);
                }
            }
        }
    }
}
finalize_interface_vec(interfaces, queue_maps)
```

```rust
// cos/status.rs (private helper)
fn finalize_interface_vec(
    interfaces: BTreeMap<i32, CoSInterfaceStatus>,
    mut queue_maps: BTreeMap<i32, BTreeMap<u8, CoSQueueStatus>>,
) -> Vec<CoSInterfaceStatus>;
```
- Owns the `Vec::with_capacity(interfaces.len())` allocation, the
  `queue_maps.remove(&ifindex)` join, the
  `nonempty_queues`/`runnable_queues` filter-count, and the final
  sort by `(interface_name, ifindex)`.

### Public-API preservation

These items are referenced by `worker/mod.rs`'s re-export block and
by tests. They are **all preserved** at exactly their current paths
via `pub(super)` / `pub(crate)` re-exports in `cos/mod.rs`:

- `COS_SHARED_EXACT_MIN_RATE_BYTES`
- `merge_cos_queue_owner_profile_sum`
- `OwnerProfileSnapshot`
- `merge_binding_scoped_owner_profile`
- `merge_owner_profile_sum`
- `owner_profile_snapshot`
- `build_worker_cos_fast_interfaces`
- `build_worker_cos_owner_live_by_tx_ifindex`
- `build_worker_cos_statuses`
- `cos_runtime_config_changed`
- `reset_binding_cos_runtime`
- `reset_worker_cos_runtimes`
- `vacate_all_shared_exact_slots_for_binding`

`build_worker_cos_statuses_from_maps` and `unique_owner_profile_row`
are module-private (`fn`) today and stay `pub(super)` within the new
`cos/` submodule so tests can address them by the same import paths.

`queue_uses_shared_exact_service` is module-private at cos.rs:106
**but is called directly by tests at `cos_tests.rs:1919, 1923, 1927,
1938, ...`** (Codex round-1 finding 1). Under the v2 layout it
lives in `cos/runtime.rs` and is also called by `cos/exact_classifier.rs`
(cos.rs:237). It needs **`pub(super)`** visibility within `cos/` so:
- `cos/exact_classifier.rs` (sibling) can call it,
- `cos/tests.rs` (sibling under `#[cfg(test)] mod tests;`) can call it,
- it stays invisible outside the `cos/` submodule (no escape into
  `worker/mod.rs` or wider).

External grep confirms zero callers of any of these three items
outside `worker/cos.rs` and `worker/cos_tests.rs`.

## Hidden invariants the change must preserve

1. **Side-effect ordering.** The accumulators all do MAX or
   saturating_add into a `Default::default()` row. The split MUST NOT
   reorder these accumulations across queues; the original
   `for (&ifindex, root) in cos_map { for queue in &root.queues { ... } }`
   nesting is preserved exactly. Inside one queue's accumulation,
   **most** field writes are independent saturating-add / MAX slots
   that can be reordered freely — **but the `priority` write at
   cos.rs:602-604 is a special case** (Codex round-1 finding 2):
   it is gated by `status.worker_instances == 0` and reads that
   counter BEFORE the saturating_add increment at cos.rs:612. Any
   reorder that moves the increment ahead of the gate breaks the
   "first worker wins priority" semantic. The helper preserves the
   read-then-increment order verbatim.
2. **Owner-profile binding-scoped fields land on exactly one row
   per binding.** `unique_owner_profile_row` is called ONCE per
   binding-iteration; the orchestrator's inline gated `if
   owner_profile_row == Some((ifindex, queue.queue_id()))` runs once
   per queue and only then calls `merge_binding_scoped_owner_profile`.
   Same control flow as today.
3. **`drain_latency_hist.resize` gate.** The vector grows from 0 →
   DRAIN_HIST_BUCKETS only when `queue_invocations > 0`; an untouched
   queue stays empty. Helper preserves this exactly so the wire
   payload for an idle queue stays empty.
4. **`active_flow_buckets_peak` is MAX (#784), not sum.** Verified by
   reading both the helper and the comment that survives.
5. **Per-queue drain telemetry source is queue atomics, not binding
   profile (#751).** Verified — the per-queue block in
   `accumulate_queue_row` does the relaxed loads on
   `queue.telemetry.owner_profile.*`. The binding profile is consulted
   only by the orchestrator's inline gated call to
   `merge_binding_scoped_owner_profile` for the binding-scoped subset.
6. **Borrow shape: `interfaces` and `queue_maps` live for the full
   walk; `interface_config` is a re-fetched short borrow per
   ifindex.** Splitting the inner loop into helpers means the helpers
   take `&mut CoSInterfaceStatus` / `&mut CoSQueueStatus` views into
   the BTreeMap entries. Rust's NLL handles this fine because the
   `or_default()` returns an `&mut` we hand straight to the helper;
   the helper returns before we re-borrow the map.
7. **Sort order is stable and identical.** Final sort is
   `(interface_name, ifindex)`, lifted intact into `finalize_interface_vec`.
8. **Allocation rule.** Status path, control-plane. The existing
   function already allocates: two BTreeMaps (`interfaces`,
   `queue_maps`), per-interface `queues` Vecs, output Vec
   (`Vec::with_capacity(interfaces.len())`), string clones for
   `interface_name` and `forwarding_class`, occasional
   `format!("ifindex-{N}")` fallback, `drain_latency_hist.resize`
   and `redirect_acquire_hist.resize` to DRAIN_HIST_BUCKETS, and the
   per-`into_values().collect()`. The invariant the helpers must
   preserve is: **no new allocations relative to the current
   implementation.** Codex round-1 finding 5 corrected the
   too-narrow "only `drain_latency_hist.resize`" wording.
9. **No locking change.** The function does not take any lock. Atomic
   reads remain Relaxed. Helpers do not introduce any synchronization.
10. **`OwnerProfileSnapshot` lifecycle.** `binding_live.map(owner_profile_snapshot)`
    materializes a struct-local owned snapshot per binding; the snapshot
    is borrowed (`binding_profile.as_ref()`) by the orchestrator's
    inline gated `merge_binding_scoped_owner_profile` call for the
    duration of the inner queue loop and dropped at the end of the
    binding iteration. The orchestrator MUST NOT extend the snapshot's
    lifetime past the binding loop.

## Risk assessment

| Class | Risk | Justification |
|---|---|---|
| Behavioral regression | LOW | Pure code motion. No reordered accumulation, no algorithmic change. Existing 23-test suite in `cos_tests.rs` (including the 264-LOC integration test exercising the full path with both single-owner-local and shared-exact shapes) is the safety net. |
| Lifetime / borrow-checker | LOW | The `&mut entry` / `&mut status` views into BTreeMap entries follow standard NLL-friendly patterns already used by the worker codebase. No `&mut self` recursion, no aliasing concerns. |
| Performance regression | LOW | Control-plane only. Helpers take `&mut` references — no copies. The original tight inner loop is preserved at the call site; only the inner block contents are factored out. Inliner is expected to make the calls free; even if it doesn't, this path runs at 1Hz scrape. |
| Architectural mismatch (#961 / #946-Phase-2 pattern) | LOW | This is a within-file decomposition, not a cross-cutting architectural change. The "cohesion principle: telemetry-rendering vs accounting" lives entirely inside the same compilation unit; there is no risk of forcing a wrong abstraction. The decomposition target is exactly the issue body's sketch. |

## Test plan

1. `cargo build --release` clean.
2. `cargo test --release` — full cargo suite passes (1434+ bin
   tests). The existing `cos/tests.rs` covers the production path
   under both single-owner-local and shared-exact shapes.
3. 5x flake check on `build_worker_cos_statuses_owner_profile_only_surfaces_on_unambiguous_owner_local_exact_queue`
   (the 264-LOC integration test that hammers this exact code path).
4. **New test: `active_flow_buckets_peak_is_max_not_sum_across_workers`**
   (Codex round-1 finding 3). Construct two `BindingWorker`s for
   the same ifindex/queue with `active_flow_buckets_peak` = 7 and
   = 11. Assert the merged status reports 11 (MAX), not 18 (sum).
   This pin makes a future refactor that swaps MAX for sum fail.
5. Go suite (30 packages) — no Go change, but run for hygiene.
6. **No per-PR smoke** per the issue's standing rule (#1349 batch
   marker `AWAITING-BATCH-MERGE`). The retirement-style batch smoke
   covers this and the sibling refactor PRs at once. Status-RPC
   regressions are caught by `cargo test`, not by an iperf3 smoke.

## Out of scope (explicitly)

- Renaming `unique_owner_profile_row` to
  `determine_unambiguous_owner_local_exact_queue` per the issue's
  test-name pun. Stays as-is to keep the diff pure code-motion.
- Splitting `cos_tests.rs` (2112 LOC) into per-helper test modules.
  The 2112-LOC test file is acknowledged as a secondary observation
  in the issue; the file moves in this PR but its contents do not.
- Decomposing the 264-LOC mega-test
  `build_worker_cos_statuses_owner_profile_only_surfaces_on_unambiguous_owner_local_exact_queue`
  into per-helper focused tests. The issue calls this out as a
  follow-up.
- Any semantic change to telemetry fields, ECN handling, drain
  histograms, or the #709 binding-scoped attribution rule.
- Changes to `CoSInterfaceStatus` / `CoSQueueStatus` wire shapes.
- Removing or merging existing items in `worker/cos.rs` not directly
  involved in the 268-LOC function (e.g. `merge_owner_profile_sum`,
  `merge_cos_queue_owner_profile_sum` keep their current paths and
  bodies).

## Round-2 changes summary

Compared to v1:
- **Dropped** `merge_binding_profile_if_target` helper (Gemini
  round-1 KILL counter-example accepted). The 3-line `if` stays
  inline in the orchestrator.
- **Added** `queue_uses_shared_exact_service` to the discussion of
  cross-submodule visibility (Codex round-1 finding 1 + Claude SMR
  M1). It moves to `cos/runtime.rs` and gets `pub(super)` so
  `cos/exact_classifier.rs` and `cos/tests.rs` can both call it.
- **Corrected** the "field-write order irrelevant" claim (Codex
  round-1 finding 2). The `priority` write at cos.rs:602-604 is
  order-coupled with the `worker_instances` increment at
  cos.rs:612; `accumulate_queue_row` preserves the read-then-
  increment order.
- **Added** a new test
  `active_flow_buckets_peak_is_max_not_sum_across_workers` to
  pin the #784 MAX-not-sum invariant (Codex round-1 finding 3).
- **Fixed** the allocation wording (Codex round-1 finding 5).
- **Clarified** the test-file move drops the `#[path = "cos_tests.rs"]`
  directive in favor of standard `mod tests;` resolution (Claude
  SMR M2).

## Open questions for adversarial review

1. **Is the `worker/cos/` subdir conversion the right shape, or
   should the original `worker/cos.rs` stay intact with only a
   sibling `worker/cos_status/` directory added?** The issue body
   sketches the latter; the standing rule directs the former. The
   former keeps all worker CoS helpers in one place; the latter
   minimizes the diff. PLAN-KILL is appropriate if reviewers judge
   the cos.rs split itself unjustified.
2. **Should the inline gated `merge_binding_scoped_owner_profile`
   call live inside `accumulate_queue_row` instead of the
   orchestrator?** v2 keeps it inline in the orchestrator after the
   `accumulate_queue_row` call. Folding it inside the queue helper
   would require passing `owner_profile_row` and `binding_profile`
   into the helper — exactly the round-1 KILL counter-example.
   v2 picks the inline form. Challenge it if you disagree.
3. **`finalize_interface_vec` takes ownership of the two BTreeMaps —
   is that OK?** It avoids re-borrowing them in the orchestrator
   after the walk. Alternative is `&mut interfaces` + drain. The
   ownership form is the simpler one and matches today's flow which
   moves the BTreeMap into `interfaces.into_iter()`.
4. **Should the orchestrator stay in `cos/status.rs` or move to
   `cos/mod.rs`?** Putting it in mod.rs makes the orchestrator the
   visible top of the module. Putting it in `status.rs` colocates
   it with `finalize_interface_vec`. The plan picks `status.rs` —
   challenge it if you disagree.
5. **Is renaming `worker/cos_tests.rs` → `worker/cos/tests.rs` worth
   the test-history churn?** A `git mv` keeps the line-history; the
   alternative is to leave the file under `worker/` and `pub use`
   the relocated functions through `worker::cos::*`. The plan picks
   the move because keeping a test file at `worker/cos_tests.rs` for
   a module that no longer lives at `worker/cos.rs` is confusing.

## Reviewer panel

Per project standing rule: 4-of-4 attestation required.

- Codex (hostile, plan + code)
- Gemini Pro 3 (adversarial, plan + code; `--model pro-3`)
- AGY (adversarial, plan + code)
- Claude (SMR + CPU arch + SW design patterns)

Plus formal Copilot inline review on the PR.

Task IDs tracked in `docs/pr/1349-worker-cos-status-split/reviewer-ids.md`.
