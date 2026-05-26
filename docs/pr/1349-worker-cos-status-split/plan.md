# #1349 — Split `build_worker_cos_statuses_from_maps` into focused helpers

**Status:** DRAFT v1 — pending adversarial plan review (Codex + Gemini Pro 3 + AGY + Claude SMR).

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
- Tests already live in `worker/cos_tests.rs` (2112 LOC). They will
  follow `cos.rs` into the new `worker/cos/` directory as
  `worker/cos/tests.rs` and be brought into the new `mod.rs` under
  `#[cfg(test)]`. No test code changes in this PR.

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
│   │                       #   queue_config, owner_profile_target,
│   │                       #   binding_profile) — items 3 of decomposition
│   │                       #   list, including #751 per-queue drain hist,
│   │                       #   #710 / #718 drop counters, #760 overshoot-hunt
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
- Stays atomic-relaxed-load only. No I/O, no allocs except the
  one `drain_latency_hist.resize(DRAIN_HIST_BUCKETS, 0)` already in
  the original code — guarded by the same `queue_invocations > 0`
  early-out so untouched queues still serialize as empty.

```rust
// cos/queue_row.rs  (kept colocated — same call frame)
pub(super) fn merge_binding_profile_if_target(
    status: &mut crate::protocol::CoSQueueStatus,
    owner_profile_row: Option<(i32, u8)>,
    ifindex: i32,
    queue_id: u8,
    binding_profile: Option<&OwnerProfileSnapshot>,
);
```
- Owns the "is this the unambiguous owner-profile row?" check and the
  `merge_binding_scoped_owner_profile` call. Keeps the producer rule
  (#709 / #748 / #751) co-located with the consumer.

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
- The orchestrator becomes:

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
            merge_binding_profile_if_target(
                status, owner_profile_row, ifindex, queue.queue_id(),
                binding_profile.as_ref(),
            );
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

External grep confirms zero callers outside `worker/cos.rs` and
`worker/cos_tests.rs`.

## Hidden invariants the change must preserve

1. **Side-effect ordering.** The accumulators all do MAX or
   saturating_add into a `Default::default()` row. The split MUST NOT
   reorder these accumulations across queues; the original
   `for (&ifindex, root) in cos_map { for queue in &root.queues { ... } }`
   nesting is preserved exactly. Inside one queue's accumulation,
   field-write order is irrelevant (each field is an independent
   accumulator slot) so the helpers reorder freely within one call.
2. **Owner-profile binding-scoped fields land on exactly one row
   per binding.** `unique_owner_profile_row` is called ONCE per
   binding-iteration; `merge_binding_profile_if_target` is called
   once per queue and checks `Some(target) == (ifindex, queue_id)`
   before merging. This is the same control flow as today.
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
   only by `merge_binding_profile_if_target` for the binding-scoped
   subset.
6. **Borrow shape: `interfaces` and `queue_maps` live for the full
   walk; `interface_config` is a re-fetched short borrow per
   ifindex.** Splitting the inner loop into helpers means the helpers
   take `&mut CoSInterfaceStatus` / `&mut CoSQueueStatus` views into
   the BTreeMap entries. Rust's NLL handles this fine because the
   `or_default()` returns an `&mut` we hand straight to the helper;
   the helper returns before we re-borrow the map.
7. **Sort order is stable and identical.** Final sort is
   `(interface_name, ifindex)`, lifted intact into `finalize_interface_vec`.
8. **Allocation rule.** Status path, control-plane, allocates one
   `Vec` and two `BTreeMap`s. No new allocations introduced; the only
   allocation churn is the same `drain_latency_hist.resize` already
   in master.
9. **No locking change.** The function does not take any lock. Atomic
   reads remain Relaxed. Helpers do not introduce any synchronization.
10. **`OwnerProfileSnapshot` lifecycle.** `binding_live.map(owner_profile_snapshot)`
    materializes a struct-local owned snapshot per binding; the snapshot
    is borrowed (`binding_profile.as_ref()`) into `merge_binding_profile_if_target`
    for the duration of the inner queue loop and dropped at the end of
    the binding iteration. Helpers MUST NOT extend the snapshot's
    lifetime past the binding loop.

## Risk assessment

| Class | Risk | Justification |
|---|---|---|
| Behavioral regression | LOW | Pure code motion. No reordered accumulation, no algorithmic change. Existing 13-test suite in `cos_tests.rs` (including the 264-LOC integration test exercising the full path with both single-owner-local and shared-exact shapes) is the safety net. |
| Lifetime / borrow-checker | LOW | The `&mut entry` / `&mut status` views into BTreeMap entries follow standard NLL-friendly patterns already used by the worker codebase. No `&mut self` recursion, no aliasing concerns. |
| Performance regression | LOW | Control-plane only. Helpers take `&mut` references — no copies. The original tight inner loop is preserved at the call site; only the inner block contents are factored out. Inliner is expected to make the calls free; even if it doesn't, this path runs at 1Hz scrape. |
| Architectural mismatch (#961 / #946-Phase-2 pattern) | LOW | This is a within-file decomposition, not a cross-cutting architectural change. The "cohesion principle: telemetry-rendering vs accounting" lives entirely inside the same compilation unit; there is no risk of forcing a wrong abstraction. The decomposition target is exactly the issue body's sketch. |

## Test plan

1. `cargo build --release` clean.
2. `cargo test --release` — all 952+ tests pass (existing
   `cos_tests.rs` covers the production path under both
   single-owner-local and shared-exact shapes).
3. 5x flake check on `build_worker_cos_statuses_owner_profile_only_surfaces_on_unambiguous_owner_local_exact_queue`
   (the 264-LOC integration test that hammers this exact code path).
4. Go suite (30 packages) — no Go change, but run for hygiene.
5. **No per-PR smoke** per the issue's standing rule (#1349 batch
   marker `AWAITING-BATCH-MERGE`). The retirement-style batch smoke
   covers this and the sibling refactor PRs at once. Status-RPC
   regressions are caught by `cargo test`, not by an iperf3 smoke.

## Out of scope (explicitly)

- Renaming `unique_owner_profile_row` to
  `determine_unambiguous_owner_local_exact_queue` per the issue's
  test-name pun. Stays as-is to keep the diff pure code-motion.
- Splitting `cos_tests.rs` (2112 LOC) into per-helper test modules.
  The 2014-LOC test file is acknowledged as a secondary observation
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

## Open questions for adversarial review

1. **Is the `worker/cos/` subdir conversion the right shape, or
   should the original `worker/cos.rs` stay intact with only a
   sibling `worker/cos_status/` directory added?** The issue body
   sketches the latter; the standing rule directs the former. The
   former keeps all worker CoS helpers in one place; the latter
   minimizes the diff. PLAN-KILL is appropriate if reviewers judge
   the cos.rs split itself unjustified.
2. **Should `accumulate_queue_row` and `merge_binding_profile_if_target`
   be one function instead of two?** They are called back-to-back at
   the same call site. Splitting them keeps each helper aligned with
   one decision domain (#710/#718/#751/#760 per-queue vs
   #709/#748/#751 binding-scoped). Reviewers should challenge whether
   the seam helps or just adds a call boundary.
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
