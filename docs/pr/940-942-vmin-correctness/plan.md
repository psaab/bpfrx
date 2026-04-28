# #940 — V_min correctness sweep (v6 — #942 DEFERRED)

## Status update (2026-04-28)

**#942 has been DEFERRED from this PR.** Cluster smoke caught a severe
regression caused by wiring `cos_queue_v_min_continue` into
`drain_exact_prepared_items_to_scratch_flow_fair`: iperf-c P=1 collapsed
from 6.78 Gb/s → 4.4 Mb/s with cwnd stuck at 1.41 KB. Bisection
isolated the cause to that one hunk; removing it restored full
throughput (6.87 Gb/s). The Local-flow-fair V_min wiring (which has
been in place since #917 phase 4) is unaffected.

Root cause is unclear: single-stream P=1 has no participating peers, so
`cos_queue_v_min_continue` should return `true` at the first
`pop_count==1` check. Yet adding the call broke SNAT-Prepared traffic
forwarding. Hypotheses for separate investigation:

- The Prepared scratch builder's invocation cadence interacts with
  V_min in some way the Local path doesn't (e.g., re-entrancy,
  unexpected concurrent draining).
- The `cos_queue_v_min_continue` function reads `queue.transmit_rate_bytes`
  via `compute_v_min_lag_threshold`. If this field is 0 or stale on
  a Prepared-only path, lag becomes the floor (24 KB) and the throttle
  may fire unexpectedly.
- The peer-slot iteration may be reading slots that ARE participating
  (e.g., HA secondary worker's stale slot from a previous epoch).

**This PR now ships #940 only.** #942 is split into its own follow-up
issue (or task #359) for focused investigation.

# Original plan: #940 + #942 — V_min correctness sweep (v2)

Bundles two V_min wiring fixes from the post-#917 hostile review.
Both touch the same publish/check surface; landing them together
gives one cohesive "V_min correctness" PR before the harder #941 +
#943 work begins.

## Problem

### #940 — speculative publish

`cos_queue_pop_front_inner` at `userspace-dp/src/afxdp/tx.rs:4685-4697`
publishes `queue.queue_vtime` to the V_min slot on EVERY pop, including
the snapshot variant (speculative) AND the no-snapshot variant (used by
`cos_queue_drain_all` whose only production caller is the live
demote-fallback at `tx.rs:5489`, NOT teardown).

Peers reading the slot during the speculative window observe inflated
vtime; if the pop later rolls back via `cos_queue_push_front`
(tx.rs:4407), the rollback republishes the corrected value — but peers
that already used the inflated value have already made their throttle
decision. Wrong decisions are not undone.

For the no-snapshot variant via drain_all, the issue is worse: drain_all
inflates `queue_vtime` by `+= bytes` per drained item, and the demote
path at tx.rs:5485-5524 SAVES + RESTORES vtime around the drain_all
call. The drain_all-induced publishes broadcast spurious inflated vtime
to peers DURING the drain, then restore happens silently (no
re-publish) — peers see the inflation, never see the restore.

Plan §3.2 v3 specified "publish only at commit boundary." PR #939
deviated for performance simplicity; the deviation must be fully
reverted (both snapshot and no-snapshot variants).

### #942 — Prepared scratch builder bypasses V_min

The Local-flow scratch builder `drain_exact_local_items_to_scratch_flow_fair`
at tx.rs:2602 has the V_min check loop wired in at tx.rs:2624-2637.
The Prepared flow-fair builder
`drain_exact_prepared_items_to_scratch_flow_fair` at tx.rs:2805-2901
does NOT have the wiring. Prepared traffic on shared_exact queues
bypasses the throttle entirely.

The FIFO Prepared variant `drain_exact_prepared_fifo_items_to_scratch`
at tx.rs:2706 runs only on `!flow_fair` queues per its
`debug_assert!(!queue.flow_fair)` at tx.rs:2717; shared_exact requires
flow_fair (per `flow_fair = queue.exact` at tx.rs:5622-5623), so this
path is unreachable on shared_exact. No wiring needed there.

## Approach

### #940 — move publish to TX-ring commit (post-settle)

#### Commit-site enumeration (Codex Q1 + Q2)

There are SIX `writer.commit()` sites in tx.rs. Treatment per site:

| # | Site | Function | Visits queue.queue_vtime? | Treatment |
|---|---|---|---|---|
| 1 | tx.rs:2028 | `service_exact_local_queue_direct` (Local-FIFO non-flow-fair) | NO during build (FIFO peeks via `queue.items.get(idx)`); `queue.items.pop_front()` happens at settle in `settle_exact_local_fifo_submission` (call at tx.rs:2068, helper body at tx.rs:2944, actual pop at tx.rs:2958). vtime_floor=None on FIFO queues. | ADD post-settle publish for uniformity (always no-op today; shields future flow_fair adoption) |
| 2 | tx.rs:2169 | `service_exact_local_queue_direct_flow_fair` | YES — `cos_queue_pop_front` (snapshot variant) advances `queue.queue_vtime` per pop | ADD post-settle publish |
| 3 | tx.rs:2321 | `service_exact_prepared_queue_direct` (Prepared-FIFO non-flow-fair) | NO during build (FIFO peeks); `queue.items.pop_front()` happens at settle in `settle_exact_prepared_fifo_submission` (call at tx.rs:2354, helper body at tx.rs:3001, actual pop at tx.rs:3015). vtime_floor=None on FIFO queues. | ADD post-settle publish for uniformity (always no-op today) |
| 4 | tx.rs:2459 | `service_exact_prepared_queue_direct_flow_fair` | YES — `cos_queue_pop_front` (snapshot variant) advances `queue.queue_vtime` per pop | ADD post-settle publish |
| 5 | tx.rs:6561 | `transmit_batch` (post-CoS backup) | NO — operates on `pending: VecDeque<TxRequest>` directly, never touches CoSQueueRuntime | EXCLUDED — document why with a comment |
| 6 | tx.rs:6790 | `transmit_prepared_queue` (post-CoS backup) | NO — operates on `pending: VecDeque<PreparedTxRequest>` directly | EXCLUDED — document why with a comment |

Sites 1+3 (FIFO non-flow-fair) get the publish hook for uniformity even
though `vtime_floor` is `None` on those queues today. The hook is a
no-op via `Option::and_then`. This shields against future flow_fair
expansion.

#### Publish boundary (Codex Q2)

The publish must happen AFTER settle, not after `outstanding_tx`. Settle
(`settle_exact_local_scratch_submission_flow_fair` at tx.rs:2977 and
`settle_exact_prepared_scratch_submission_flow_fair` at tx.rs:3032)
handles partial reservation by calling `cos_queue_push_front` on
uninserted tail. push_front already publishes the rolled-back vtime via
the existing hook at tx.rs:4483-4490. Publishing post-settle ensures
the slot reflects only the actually-shipped state.

Concrete pattern at each of the four sites (1-4):

```rust
// (after settle returns sent_packets/sent_bytes, before
// apply_*_send_result + maybe_wake_tx)
publish_committed_queue_vtime(
    binding
        .cos_interfaces
        .get(&root_ifindex)
        .and_then(|root| root.queues.get(queue_idx)),
);
```

New helper near the existing V_min helpers (~tx.rs:5722):

```rust
/// #940: publish the committed queue_vtime to the V_min floor slot.
/// Called from each TX-ring commit site AFTER settle, so the published
/// value reflects only frames that were actually inserted into the TX
/// ring (rollbacks via cos_queue_push_front have already republished
/// any corrected vtime).
///
/// Memory ordering: libxdp's `xsk_ring_prod__submit` (called by
/// `RingTx::commit` via xsk_bridge.c:108-110) issues an
/// `smp_store_release` on the producer head. Our `slot.publish()`
/// uses `Ordering::Release` (types.rs:1442). Peers that observe the
/// slot via `Acquire` are guaranteed to also observe the producer-head
/// update (transitive happens-before via the worker thread's program
/// order). Slot publish is safe to call after the producer commit; the
/// happens-before chain is one-way (slot → ring not ring → slot, but
/// the latter is unused — peers don't read the TX ring).
#[inline]
fn publish_committed_queue_vtime(queue: Option<&CoSQueueRuntime>) {
    let Some(queue) = queue else { return };
    // F4: type-level invariant. vtime_floor is only set on flow_fair
    // queues (per `promote_cos_queue_flow_fair` at tx.rs:5773). If a
    // future caller sets a floor on a non-flow-fair queue, the publish
    // would broadcast a `queue_vtime` that is not MQFQ-meaningful
    // (FIFO queues don't advance vtime in any consistent way). Trip
    // loud in debug builds; release-builds tolerate it (no UB, just
    // garbage telemetry).
    debug_assert!(
        queue.vtime_floor.is_none() || queue.flow_fair,
        "publish_committed_queue_vtime: vtime_floor set on non-flow-fair queue (queue_id={})",
        queue.queue_id,
    );
    let Some(floor) = queue.vtime_floor.as_ref() else { return };
    let Some(slot) = floor.slots.get(queue.worker_id as usize) else { return };
    slot.publish(queue.queue_vtime);
}
```

#### Remove BOTH pop-time publishes (Codex Q3 + Q4)

Remove the publish at tx.rs:4685-4697 entirely (both snapshot and
no-snapshot variants).

The drain_all production caller is `demote_prepared_cos_queue_to_local`
at tx.rs:5489, which is a LIVE fallback path reached from
`enqueue_local_into_cos` on prepared-materialization failure. It
SAVES + RESTORES queue_vtime around drain_all (lines 5485, 5522). The
existing pop-time publish leaks intermediate inflated vtime to peers
during the drain.

After removing the no-snapshot publish, the demote restore at
tx.rs:5522 must also explicitly publish the restored vtime so peers see
the post-demote state. Add a `publish_committed_queue_vtime(Some(&*queue))`
call after the three restore stores.

#### Keep the rollback publish (already correct)

The publish in `cos_queue_push_front` at tx.rs:4483-4490 is correct as
the rollback primitive. Keep it. After a rollback, peers see the
corrected vtime via Acquire load. After all rollbacks complete, our
post-settle publish at the commit site overwrites with the same value
(idempotent).

### #942 — wire V_min into Prepared flow-fair builder

Mirror the Local-path wiring at tx.rs:2624-2637 into
`drain_exact_prepared_items_to_scratch_flow_fair` at tx.rs:2820-2826.

```rust
// (after pop_snapshot_stack.clear() at tx.rs:2822)
let mut v_min_pop_count = 0u32;

while scratch_prepared_tx.len() < TX_BATCH_SIZE {
    v_min_pop_count = v_min_pop_count.saturating_add(1);
    if !cos_queue_v_min_continue(queue, v_min_pop_count) {
        break;
    }
    let Some(front) = cos_queue_front(queue) else {
        break;
    };
    // ... rest of existing loop body
}
```

Add a comment in `drain_exact_prepared_fifo_items_to_scratch` at tx.rs:2706
documenting why the FIFO variant skips V_min wiring (`!flow_fair` per
debug_assert; shared_exact implies flow_fair).

## File-level changes

| File | Lines | Change |
|---|---|---|
| `userspace-dp/src/afxdp/tx.rs` | 4685-4697 | REMOVE publish in `cos_queue_pop_front_inner` (BOTH snapshot and no-snapshot variants). Update doc comment to point at the new commit-boundary publish helper. |
| `userspace-dp/src/afxdp/tx.rs` | new helper near 5722 | ADD `publish_committed_queue_vtime(queue: Option<&CoSQueueRuntime>)` with the libxdp memory-ordering doc comment. |
| `userspace-dp/src/afxdp/tx.rs` | post-settle in site #1 (~2210 area) | ADD `publish_committed_queue_vtime(...)` call. Find the analogous post-settle site in `service_exact_local_queue_direct` (FIFO variant). |
| `userspace-dp/src/afxdp/tx.rs` | post-settle in site #2 (~2215) | ADD `publish_committed_queue_vtime(...)` call after `settle_exact_local_scratch_submission_flow_fair`. |
| `userspace-dp/src/afxdp/tx.rs` | post-settle in site #3 (FIFO Prepared) | ADD `publish_committed_queue_vtime(...)` call after `settle_exact_prepared_fifo_submission`. |
| `userspace-dp/src/afxdp/tx.rs` | post-settle in site #4 | ADD `publish_committed_queue_vtime(...)` call after `settle_exact_prepared_scratch_submission_flow_fair`. |
| `userspace-dp/src/afxdp/tx.rs` | sites #5 + #6 (`transmit_batch`, `transmit_prepared_queue`) | ADD ONE-LINE comment after each `writer.commit()` documenting why no V_min publish is needed (operates on non-CoS pending deques; never advances queue_vtime). |
| `userspace-dp/src/afxdp/tx.rs` | 5522 (demote restore) | ADD `publish_committed_queue_vtime(Some(&*queue))` after the three restore stores. |
| `userspace-dp/src/afxdp/tx.rs` | 2820-2826 | ADD V_min check loop wiring in `drain_exact_prepared_items_to_scratch_flow_fair`. |
| `userspace-dp/src/afxdp/tx.rs` | 2706-2720 | ADD comment in `drain_exact_prepared_fifo_items_to_scratch` documenting V_min unreachability. |
| `userspace-dp/src/afxdp/tx.rs` | test module | ADD test fixture helper that wraps a queue with a real `SharedCoSQueueVtimeFloor` (replacing `vtime_floor: None` defaults). |
| `userspace-dp/src/afxdp/tx.rs` | test module | ADD test: speculative pop does not publish (snapshot variant; assert slot stays at NOT_PARTICIPATING). |
| `userspace-dp/src/afxdp/tx.rs` | test module | ADD test: rollback via `cos_queue_push_front` publishes the rolled-back vtime (existing rollback hook). |
| `userspace-dp/src/afxdp/tx.rs` | test module | ADD test: `publish_committed_queue_vtime` no-ops when `vtime_floor = None`. |
| `userspace-dp/src/afxdp/tx.rs` | test module | ADD test: Prepared flow-fair builder honors V_min throttle (synthetic peer slot pegged at 0; assert builder breaks at K=8 pops). |
| `userspace-dp/src/afxdp/tx.rs` | test module | ADD test: demote_prepared_cos_queue_to_local performs no publish during drain_all phase. Reframed (per Gemini): assert `slot.read()` BEFORE demote == `slot.read()` AFTER demote completes restore but BEFORE the new explicit post-restore publish call. Then call publish, assert slot reflects restored value. Single-thread test; uses the slot-read API directly since the transient is invisible from outside. |
| `userspace-dp/src/afxdp/tx.rs` | bench at ~14255 in-module pattern | ADD `#[test] #[ignore]` named `bench_pop_publish` measuring `cos_queue_pop_front` + post-settle publish vs current pop-time publish. Document the baseline command. |
| `userspace-dp/src/afxdp/worker.rs` | ~1900 (just before `binding.cos_interfaces.clear()`) | ADD FIXME(#941 work item D) comment documenting the reset-epoch stale-slot gap. See "Known gap" section. |

## Memory ordering (Codex Q7 / B7)

- Producer head: `RingTx::commit` (xsk_ffi.rs:763-766) calls
  `bridge_xsk_ring_prod_submit` (csrc/xsk_bridge.c:108-111), which is
  a thin wrapper delegating to libxdp's `xsk_ring_prod__submit`. The
  release-store on the producer index is an **upstream ABI contract
  of libxdp** — `xsk_ring_prod__submit` issues a `libbpf_smp_store_release`
  on the producer index per the AF_XDP ring-buffer protocol. The
  worktree does NOT vendor libxdp; this contract is therefore external
  and MUST be re-verified on any libxdp upgrade or replacement. No
  source-line citation is offered because the source is not in the
  worktree.
- V_min publish: `slot.publish()` uses `Ordering::Release` (types.rs:1442).
- Worker thread program order: producer commit happens-before V_min
  publish on the same worker thread.
- Peer worker reads slot via `Ordering::Acquire` (types.rs:1461).
  Acquire pairs with the publish's Release. Peer's V_min decision is
  made against a value that reflects only frames already in the TX ring.

This invariant is documented in the `publish_committed_queue_vtime`
doc comment so a future libxdp upgrade or RingTx implementation change
trips a code-search hit.

## Test scaffolding (Codex Q5 / B5)

Existing test fixtures default to `vtime_floor: None` (e.g. tx.rs:5860,
6957). Add a helper that returns the `Arc` so tests can read peer slots
back to verify published values:

```rust
#[cfg(test)]
fn attach_test_vtime_floor(
    queue: &mut CoSQueueRuntime,
    num_workers: u32,
    my_worker_id: u32,
) -> Arc<SharedCoSQueueVtimeFloor> {
    let floor = Arc::new(SharedCoSQueueVtimeFloor::new(num_workers as usize));
    queue.vtime_floor = Some(Arc::clone(&floor));
    queue.worker_id = my_worker_id;
    floor
}
```

New tests use this to enable V_min participation. Synthetic peer state
(pegging a peer slot at a specific vtime) is set via
`floor.slots[peer_id].publish(value)`. Reading back the worker's own
slot to verify a publish fired uses `floor.slots[my_worker_id].read()`.

## Microbenchmark (Codex Q6 / B6)

For this PR's per-pop microbench, public APIs aren't sufficient — we
need to drive the FULL `pop + writer.commit() + settle + publish` cycle
end-to-end (Gemini review: measuring just `cos_queue_pop_front` would
underestimate the new design's cost since the publish moved out of
pop into the post-settle hook; an end-to-end measurement captures the
full cost relocation). Use the in-module ignored-test pattern at
`tx.rs:14234/14255` (existing precedent: a `#[test] #[ignore]` that
times an inner workload and prints results). Naming:
`bench_pop_commit_settle_publish` (renamed from `bench_pop_publish`
to reflect the broader scope).

The bench harness builds a synthetic CoS queue with a small batch of
items, runs `drain_exact_local_items_to_scratch_flow_fair` →
mock-transmit (the bench skips the actual `RingTx::transmit` call —
or uses a no-op fake — since libxdp isn't suitable for a unit-time
microbench loop) → settle → publish, in a tight loop, and reports
ns/iter. The current code's pop-time publish is measured the same way
on the pre-change baseline.

`userspace-dp/Cargo.toml` features section (line 6) defines only
`default` and `debug-log`; no `bench` feature exists. The microbench
is gated by `#[ignore]` alone.

Acceptance gate: per-pop CPU regression < 1% measured by:

```
cargo test --release -p xpf-userspace-dp -- bench_pop_commit_settle_publish --nocapture --ignored
```

vs the same on the pre-change baseline. Document the baseline number
in the PR body.

## Acceptance criteria

- [ ] Existing #785 / #913 / #917 test pins all pass.
- [ ] New: speculative-pop-no-publish test passes.
- [ ] New: rollback-republishes-corrected-vtime test passes.
- [ ] New: publish_committed_queue_vtime is a no-op when vtime_floor=None test passes.
- [ ] New: Prepared flow-fair builder honors V_min throttle test passes.
- [ ] New: demote_prepared_cos_queue_to_local does no publish during
      drain_all (reframed): slot value before demote == slot value
      after restore but before explicit publish; explicit publish
      after restore broadcasts the saved (== restored) vtime.
- [ ] In-module microbench shows < 1% per-pop regression vs baseline
      (with explicit baseline number in PR body).
- [ ] `make test` green.
- [ ] Cluster smoke on `loss:xpf-userspace-fw0/fw1`: iperf-b retx still
  0 at P=12; iperf-c P=12 throughput ≥ 22 Gb/s; mouse p99 within ±5 %
  of the post-#917 baseline (59.51 ms).

## Risks

- **Six commit sites + one demote restore = seven publish-add sites.**
  Easy to miss one. Mitigate via grep for `writer.commit()` after the
  PR is drafted; confirm seven publish-or-excluded sites total.
- **Settle-then-publish ordering**: must verify the publish happens
  AFTER settle returns and BEFORE `apply_*_send_result` /
  `maybe_wake_tx`. Document with a comment. Place the publish call
  after settle's return-tuple unpacking but before the next call.
- **Demote restore publish**: the saved vtime (line 5485) and restored
  vtime (line 5522) must be EQUAL post-restore. The publish broadcasts
  the restored value. Verify with the demote-no-leak test.
- **Test fixture proliferation**: `attach_test_vtime_floor` only added
  to the new tests; do NOT retrofit existing tests (would diff-thrash
  the surface). Existing tests stay at `vtime_floor: None` and exercise
  the no-op path of the publish helper.

## Test-and-deploy plan

1. Implement; `cargo build` clean.
2. Run unit tests in tx.rs module; new pins green.
3. Run in-module microbench; record baseline + post numbers.
4. `make test-deploy` to standalone bpfrx-fw VM; verify XSK still binds.
5. `make cluster-deploy` to userspace cluster; cluster smoke (iperf-b
   N=12, iperf-c N=12 + N=128, mouse latency same-class N=128 M=10).
6. Codex hostile review of the patch.
7. Gemini adversarial review.
8. Both PASS → merge.

## Known gap: reset-epoch stale slot (Codex N4+N5)

**Acknowledged but punted to #941.**

`build_shared_cos_queue_vtime_floors_reusing_existing` at
`coordinator.rs:2061` reuses an existing floor `Arc` when
`(ifindex, queue_id)` and `worker_count` match across rebuilds. On
worker reset (the binding-rebuild path at worker.rs:~1885-1905, which
clears `cos_interfaces` and rebuilds queue runtimes), the new
`CoSQueueRuntime` starts with `queue_vtime = 0` (tx.rs:5848 area). The
floor's slot for this worker still holds the OLD worker's last-published
vtime — typically large.

Failure mode: peers reading the slot before this worker's first
post-reset commit-publish observe the OLD high vtime. Their V_min
includes that high value. After the first post-reset publish, the slot
drops dramatically (OLD-high → new-low ≈ 0). Peers then compute
`peer_queue_vtime > new_low + LAG`, which is usually true, so peers
throttle erroneously for one or more drain batches.

**Why punt to #941**: the symmetric fix is `floor.slots[worker_id].vacate()`
at the reset point. That's the same primitive #941 Work item B (HA
demotion vacate) introduces. Folding both into #941 keeps the vacate
surface in one place.

**This PR adds a FIXME at the reset path** (worker.rs:~1900 area, just
before `binding.cos_interfaces.clear()`) referencing #941, so a future
reader doesn't lose track of the gap.

```rust
// FIXME(#941 work item D): vacate any V_min slots owned by this
// worker before clearing cos_interfaces. Without vacate, the new
// runtime's queue_vtime=0 will cause a one-batch peer-throttle
// burst at the reset-epoch boundary. See
// docs/issue-refinements/941-body.md and
// docs/pr/940-942-vmin-correctness/plan.md "Known gap".
```

**Risk quantification (Gemini review)**: even a 10-50 ms window of
incorrect throttling is meaningful in this dataplane — at 25 Gb/s line
rate that's 31-156 MB of throughput choke. The first post-reset
post-settle publish happens at the first TX-ring commit on this
queue, which depends on traffic. For sparse low-rate flows the window
can easily exceed 100 ms.

If the cluster smoke at HA failback shows mouse-latency regression
(or even a perceptible aggregate-throughput dip on the reset binding's
peers), this gap is promoted from "punt" to "must fix in this PR" —
add `vacate()` calls in the worker reset path before
`cos_interfaces.clear()` rather than wait for #941.

## Out of scope

- #941 vacate / hard-cap / first-enqueue-publish (separate PR; needs
  the memory-ordering doc + work-items A/B/C).
- #943 telemetry counters (co-lands with #941).
- Generic `transmit_batch` / `transmit_prepared_queue` paths (sites #5,
  #6) — they don't advance queue_vtime; documenting exclusion is
  sufficient.
- Removing the `queue_vtime += bytes` advance in the no-snapshot pop
  variant (the demote-path semantic). The publish removal alone is
  sufficient for V_min correctness; the vtime advance itself is
  separately required by #913 §3.7 round-trip neutrality.
- Reset-epoch vacate (folds into #941 Work item D — see "Known gap"
  above).
