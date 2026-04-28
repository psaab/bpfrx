# Plan v7: #941 — V_min vacate + hard-cap-with-suspension (B dropped)

## Context

- **#940 landed** (PR #950 merged): post-settle V_min publish at four
  TX-ring commit sites + demote-restore publish + helper. Pop-time
  publish removed.
- **#942 deferred**: wiring `cos_queue_v_min_continue` into
  `drain_exact_prepared_items_to_scratch_flow_fair` caused a severe
  shared_exact regression; bisection isolated to that hunk.
- **Root cause confirmed** (branch `investigate/942-instrumentation`,
  doc `docs/pr/940-942-vmin-correctness/942-investigation.md`): peer
  slots can hold values that throttle the heavy worker. Captured
  DBG_VMIN log showed worker 4 (qvtime 4.1 GB) throttled because peer
  slots held qvtime=255 (worker 1) and qvtime=664 (worker 5) from
  small early packets.

This PR implements the corrective semantics needed before #942 can be
re-enabled.

## Captured failure — full peer vector

The captured DBG_VMIN log (worker 5's POV, but the bug fires on
worker 4):

```
peers=[NOT_PART, 255, NOT_PART, NOT_PART, 4105732787, NOT_PART, ...]
                  ^worker 1                ^worker 4
```

Worker 5's POV:
- `worker.queue_vtime = 664`
- peers[0] = NOT_PART, peers[1] = 255, peers[2] = NOT_PART,
  peers[3] = NOT_PART, peers[4] = 4 105 732 787, peers[5..] = NOT_PART
- participating = 2 (workers 1 and 4)
- v_min = min(255, 4.1 GB) = 255
- `lag = 1.04 MB`
- `664 ≤ 255 + 1.04 MB` → true (worker 5 doesn't throttle)

**Worker 4's POV** (the bug location):
- `worker.queue_vtime = 4 105 732 787`
- peers = [NOT_PART, 255, NOT_PART, NOT_PART, ..., 664, NOT_PART, ...]
- participating = 2 (workers 1 and 5)
- v_min = min(255, 664) = **255**
- `4.1 GB ≤ 255 + 1.04 MB` → **FALSE** → throttle.

Worker 4 throttles every batch because workers 1 and 5 are stuck at
tiny qvtimes from one or two small packets each. Their slots aren't
phantom (they're actively-participating; they've published recently),
just FAR BELOW worker 4's frontier.

## Problem

Three correctness/liveness flaws:

### Flaw 1 — missing vacate

`PaddedVtimeSlot::vacate()` at `userspace-dp/src/afxdp/types.rs:1453-1455`
exists but is never called. Phantom-participating workers throttle
peers indefinitely.

### Flaw 2 — superseded

Plan v6 listed a "no first-enqueue publish on re-entry" flaw. Gemini
adversarial review of plan v6 showed that adding such a publish would
re-introduce the very stale-OLD-vtime failure mode this PR aims to fix
(see "Work item B — DROPPED"). The correct semantic is: after vacate,
the slot stays at NOT_PARTICIPATING until first post-settle publish
(provided by #940's `publish_committed_queue_vtime`). The gap is brief
and semantically correct (no committed work yet → not participating).

### Flaw 3 — V_min throttle has no graceful failure mode

When peer slots are persistently below the heavy worker's qvtime, the
algorithm throttles every batch. PR #939's early-break has no escape
hatch. The captured failure shows this is not a corner case — it
fires under normal staggered-startup.

## Approach

**Four work items** — same PR, separate commits per item.

| Item | Subject | Commit boundary |
|---|---|---|
| A | Bucket-empty vacate | tx.rs:account_cos_queue_flow_dequeue |
| ~~B~~ | ~~First-enqueue publish~~ — DROPPED (re-introduces stale-vtime bug) | (dropped) |
| C | HA-demotion vacate + reset-epoch vacate | types.rs WorkerCommand + worker.rs reset path + dispatch |
| D | Hard-cap WITH suspension after force-continue | tx.rs cos_queue_v_min_continue + CoSQueueRuntime fields |

**Work item E (outlier trim) from plan v2 is DROPPED.** It doesn't
fix the captured failure (lone-stale-low peer becomes max_peer; filter
trims nothing; throttle fires). The simpler fix is **beefing up Work
item D**: after hard-cap force-continue, suspend V_min check for N
batches. This gives 99 % throughput recovery and subsumes E.

### Work item A — bucket-empty vacate

Hook into `account_cos_queue_flow_dequeue` at `tx.rs:4344-4368`. After
the existing decrement of `active_flow_buckets`, when
`active_flow_buckets` just transitioned from 1 to 0 AND
`queue.shared_exact`, vacate the slot:

```rust
// (after line 4368 `queue.flow_bucket_bytes[bucket] = remaining;`)
if queue.shared_exact && queue.active_flow_buckets == 0 {
    if let Some(floor) = queue.vtime_floor.as_ref() {
        if let Some(slot) = floor.slots.get(queue.worker_id as usize) {
            slot.vacate();
        }
    }
}
```

Single-thread invariant: `account_cos_queue_flow_dequeue` runs in the
worker thread. The slot is single-writer; vacate is race-free against
this worker's own publish. Peer reads are Acquire-ordered against this
Release.

**Initial-state correctness** (Gemini adversarial review Q3): a
`flow_fair` queue with `active_flow_buckets == 0` and `vtime_floor`
attached but no enqueues yet — the slot starts at NOT_PARTICIPATING
via `PaddedVtimeSlot::not_participating()` in `types.rs:1429-1434`.
`SharedCoSQueueVtimeFloor::new` initializes ALL slots via that
constructor. Dormant queues correctly do not present a false-low
V_min.

### Work item B — DROPPED

Plan v6 had a "first-enqueue publish" work item: hook into
`account_cos_queue_flow_enqueue` and publish `queue.queue_vtime` on
the 0→1 active_flow_buckets transition.

**Gemini adversarial review (plan v6) flagged this as a design flaw**:
`queue.queue_vtime` persists across vacates. After a vacate, the
field still holds the OLD pre-vacate value — possibly stale-low.
Publishing it on re-entry re-introduces exactly the failure pattern
this PR aims to fix. The plan v6 justification ("Work item D's
suspension handles it") is admission of bug-then-mitigate rather
than correctness.

**Correct semantic**: after vacate, the slot stays at NOT_PARTICIPATING
until the worker actually completes a drain → settle cycle, at which
point #940's `publish_committed_queue_vtime` (the post-settle hook
landed in PR #950) publishes the now-current `queue.queue_vtime`. In
the gap between re-enqueue and first post-settle publish, peers see
this worker as not-participating — which is correct, since the
worker hasn't done any committed work yet.

**Conclusion**: drop Work item B entirely. Work item A (vacate) +
#940's post-settle publish cover the lifecycle without needing a
re-publish on enqueue.

### Work item C — HA-demotion vacate AND reset-epoch vacate

Two paths trigger slot cleanup; both must vacate via a shared helper.

**Helper** (in worker.rs):

```rust
fn vacate_all_shared_exact_slots(binding: &BindingWorker) {
    for root in binding.cos_interfaces.values() {
        for queue in &root.queues {
            if !queue.shared_exact { continue; }
            if let Some(floor) = queue.vtime_floor.as_ref() {
                if let Some(slot) = floor.slots.get(queue.worker_id as usize) {
                    slot.vacate();
                }
            }
        }
    }
}
```

**Path 1 — HA demotion via WorkerCommand**:

`apply_worker_commands` at `userspace-dp/src/afxdp/session_glue.rs:316-625`
does NOT have access to `BindingWorker`. **Codex flagged this as
BROKEN in plan v2.** The fix is to extend the result struct and
dispatch from the outer loop (which has `&mut bindings`):

1. Add variant `WorkerCommand::VacateAllSharedExactSlots` at
   `types.rs:2064-2072`.
2. Add `vacate_all_shared_exact_slots: bool` field to
   `WorkerCommandResults`.
3. `apply_worker_commands` sets the field to `true` when it processes
   the variant; it does NOT call the helper itself (no binding access).
4. `worker.rs:818-822` (where command_results is destructured) checks
   the flag; if `true`, iterate `bindings` and call
   `vacate_all_shared_exact_slots(binding)` for each.
5. Coordinator's HA-demotion path (`ha.rs:40-50`) enqueues
   `VacateAllSharedExactSlots` on each affected worker's command queue.

**Path 2 — reset-epoch direct call**:

`reset_binding_cos_runtime` at `worker.rs:1875-1919` is a worker-thread
direct call (NOT via WorkerCommand). Add an inline call BEFORE
`binding.cos_interfaces.clear()` at `worker.rs:1919`:

```rust
// at worker.rs:~1918, before the clear()
vacate_all_shared_exact_slots(binding);
binding.cos_interfaces.clear();
```

Remove the FIXME at `worker.rs:1905`.

**HA-demotion timing** (Codex Q4 correction): commands are processed
once per worker poll-loop iteration at `worker.rs:797-822`, not per
queue drain. Poll loop runs continuously under load (~µs cadence).
Bound: "next poll iteration" — well below VRRP failover timing
(~60-97 ms `masterDownInterval`). Acceptable for V_min slot cleanup;
this path doesn't own HA forwarding correctness.

**HA-demotion vacate scope** (Codex Q5 NEEDS-MINOR correction): the
helper iterates ALL bindings on this worker and vacates every
shared_exact slot, not just those for the demoted RG. Justification:
HA demotion is a node-level event; even if multiple RGs are
configured, demotion typically affects all RGs simultaneously. A more
restricted scope (vacate only demoted-RG slots) would require
threading RG identity through the WorkerCommand and the helper.
**Tradeoff accepted**: unaffected RG bindings see their slots
transiently NOT_PARTICIPATING until the next post-settle publish
(#940's hook) re-establishes them. This adds ~µs of "phantom-
participating-NOT" — peers see no participating peers for that
worker's queues until the next drain. Strictly safer than leaving
stale values; overhead is negligible.

**All demotion-trigger paths** (Gemini adversarial review Q5): the
following demotion-related code paths must ALL trigger
`VacateAllSharedExactSlots`:

1. **VRRP failover** (HA Primary → Secondary): coordinator's
   `ha.rs:40-50` enqueues the command on each affected worker.
2. **Manual failover** (CLI `request chassis cluster failover`):
   same `ha.rs` demotion path; the command is enqueued.
3. **Reset-epoch** (config reload, RG reconfiguration): triggered
   directly via `reset_binding_cos_runtime` at `worker.rs:1875-1919`,
   which now calls `vacate_all_shared_exact_slots(binding)` inline
   (NOT via WorkerCommand — the reset path is already on the worker
   thread).
4. **Single-RG config demotion** (e.g., `delete chassis cluster
   redundancy-group <N>`): same code path as VRRP failover, since
   the RG state machine treats all demotion events uniformly.

If a future code path adds a NEW demotion mechanism (e.g., a
configuration-driven RG-only demotion that bypasses VRRP), it MUST
also enqueue `VacateAllSharedExactSlots`. Audit any future demotion
PR for this hook.

Single-thread invariant: both paths run on the worker thread. The
slot is written only by its owning worker.

### Work item D — hard-cap WITH suspension at drain-entry boundary

The original Work item D in v1/v2 was "force-continue 1 batch every 8
skips" — that gives 1/9 ≈ 11 % throughput, which is unacceptable.
**Beef this up**: after the hard-cap force-continue fires, **suspend
V_min check for N drain calls**. During suspension, the worker drains
at full rate. After N drain calls, V_min check resumes; if it would
still throttle (peers still out-of-band), force-continue + suspension
fire again.

Effective throughput: `N / (N + 8) ≈ 99.2 %` at `N = 1000`.

**Decrement boundary** (Codex Q1 BLOCKER fix): suspension counts
**drain calls**, not pops. The decrement happens ONCE per
`drain_exact_local_items_to_scratch_flow_fair` /
`drain_exact_prepared_items_to_scratch_flow_fair` invocation —
specifically, AFTER the `free_tx_frames.is_empty()` preflight passes
and BEFORE the per-pop loop body. The "Suspension decrement placement"
section below details the exact implementation. This makes the math
honest: N=1000 means 1000 drain calls that actually had a chance to
make progress.

Drain calls are at the OwnerProfile granularity (`drain_invocations`
field, `worker.rs:1948-1949`) — i.e., one drain per
`service_exact_*_queue_direct_flow_fair` call. At TX_BATCH_SIZE=64
(per `afxdp.rs:187`, NOT 32) and ~333 Kpps per-worker line rate,
~5 K drains/sec, so N=1000 ≈ 200 ms suspension window. Well below
mouse-latency budgets (#905) but long enough for peers to either
catch up or visibly persist as out-of-band.

**Suspension does NOT end early** (Codex Q3 explicit acknowledgment):
even if the queue's local conditions change during suspension (e.g.,
peer slots advance to in-band), suspension counts down deterministically
to 0 before V_min check resumes. Conservative; avoids flapping at
the boundary.

**Counter plumbing** (Codex E BLOCKER fix): counter lives on
`BindingLiveState` (umem.rs ~1797 area, alongside `flow_cache_collision_evictions`).
`cos_queue_v_min_continue` does NOT increment it directly (would
require threading `&BindingLiveState` into the function — clutter,
plus borrow conflict with `&mut queue`). Instead, add a SCRATCH
counter `v_min_hard_cap_overrides_scratch: u32` to `CoSQueueRuntime`;
flush it at `update_binding_debug_state` (umem.rs:2526) into
`live.v_min_throttle_hard_cap_overrides`. This matches the existing
`flow_cache_collision_evictions` flush pattern at umem.rs:2603-2607.

Fields on `CoSQueueRuntime` (in types.rs):
- `consecutive_v_min_skips: u32` — counts back-to-back early-breaks.
- `v_min_suspended_remaining: u32` — counts down from
  `V_MIN_SUSPENSION_BATCHES` when suspension is active.
- `v_min_hard_cap_overrides_scratch: u32` — local counter, flushed
  to BindingLiveState by `update_binding_debug_state`.

Field on `BindingLiveState` (in umem.rs, alongside flow_cache counters):
- `v_min_throttle_hard_cap_overrides: AtomicU64`.

Constants in `tx.rs`:
- `V_MIN_CONSECUTIVE_SKIP_HARD_CAP: u32 = 8;`
- `V_MIN_SUSPENSION_BATCHES: u32 = 1000;` (drain calls, not pops)

`cos_queue_v_min_continue` modifications:

```rust
fn cos_queue_v_min_continue(queue: &mut CoSQueueRuntime, pop_count: u32) -> bool {
    // [Existing] cadence skip — UNCHANGED, runs first.
    if pop_count != 1 && !pop_count.is_multiple_of(V_MIN_READ_CADENCE) {
        return true;
    }
    // [Existing] non-shared_exact short-circuit + floor lookup + peer scan.
    //
    // Suspension boundary: this function does NOT *read* or *consume*
    // `v_min_suspended_remaining` — that's done at drain-entry by
    // `cos_queue_v_min_consume_suspension` in the wrapping drain
    // function. This function only *arms* suspension (writes to
    // `v_min_suspended_remaining`) on the hard-cap activation path
    // below. So the lifecycle is:
    //   - drain function consumes suspension (reads + decrements).
    //   - this function arms suspension (writes max value on hard-cap).
    // ... (peer scan unchanged) ...
    let cont = queue.queue_vtime <= v_min.saturating_add(lag);
    // [NEW] Hard-cap accounting (Work item D).
    if cont {
        queue.consecutive_v_min_skips = 0;
        return true;
    }
    queue.consecutive_v_min_skips = queue.consecutive_v_min_skips.saturating_add(1);
    if queue.consecutive_v_min_skips >= V_MIN_CONSECUTIVE_SKIP_HARD_CAP {
        queue.consecutive_v_min_skips = 0;
        queue.v_min_suspended_remaining = V_MIN_SUSPENSION_BATCHES;
        queue.v_min_hard_cap_overrides_scratch =
            queue.v_min_hard_cap_overrides_scratch.saturating_add(1);
        return true;
    }
    false
}
```

**Suspension decrement placement** (Codex round-4 B fix +
Codex round-5 sketch fix): the decrement must fire only when the
drain has CONFIRMED forward-progress opportunity — i.e.,
`free_tx_frames` is non-empty AND we're about to enter the per-pop
work. If decrement fires before the free-frame preflight, a
TX-ring-full no-progress drain call would still consume one
suspension slot, eroding the suspension window without doing any
work.

Helper:

```rust
/// Returns true if this drain call is suspended (V_min check should
/// be skipped for the entire drain). Decrements
/// `v_min_suspended_remaining` exactly once per call.
fn cos_queue_v_min_consume_suspension(queue: &mut CoSQueueRuntime) -> bool {
    if queue.v_min_suspended_remaining > 0 {
        queue.v_min_suspended_remaining -= 1;
        return true;
    }
    false
}
```

Drain loop integration: the `suspended` flag is computed ONCE before
the loop (after a preflight check ensures the loop will actually
attempt work), and persists for the entire loop body. Every pop in
this drain call sees the SAME suspension state — fixing the v5 sketch
bug where pop_count==1 took the suspended path but cadence checks at
pop_count==8 still ran V_min.

```rust
fn drain_exact_local_items_to_scratch_flow_fair(
    queue: &mut CoSQueueRuntime,
    free_tx_frames: &mut VecDeque<u64>,
    scratch_local_tx: &mut Vec<(u64, TxRequest)>,
    /* ... */
) -> ExactCoSScratchBuild {
    // [Existing] pop_snapshot_stack.clear() etc.
    queue.pop_snapshot_stack.clear();
    let mut remaining_root = root_budget;
    let mut remaining_secondary = secondary_budget;

    // [NEW] Drain-call preflight: if no free TX frames at entry, skip
    // the suspension decrement so it isn't burned on a no-progress call.
    if free_tx_frames.is_empty() {
        return ExactCoSScratchBuild::Ready;
    }
    // [NEW] Consume one suspension slot (or determine we aren't
    // suspended). Decrements once; persists for the whole loop body.
    let suspended = cos_queue_v_min_consume_suspension(queue);

    let mut v_min_pop_count = 0u32;
    while scratch_local_tx.len() < TX_BATCH_SIZE {
        if free_tx_frames.is_empty() {
            break;  // mid-loop frame exhaustion; suspension already
                    // consumed — that's correct (we made progress).
        }
        v_min_pop_count = v_min_pop_count.saturating_add(1);
        if !suspended && !cos_queue_v_min_continue(queue, v_min_pop_count) {
            break;
        }
        // ... rest of loop body unchanged ...
    }
    ExactCoSScratchBuild::Ready
}
```

Same pattern in `drain_exact_prepared_items_to_scratch_flow_fair`.

Note on the `cos_queue_v_min_continue` sketch above: it does NOT
include a suspension check inside the function (suspension is
handled by the wrapping drain loop). The function purely handles
the per-pop V_min decision and hard-cap accounting.

Note: `cos_queue_v_min_continue` now takes `&mut queue` (was `&queue`).
Callers at `tx.rs:2677` (Local) and any future Prepared site must be
updated. Test sites at `tx.rs:16925` and `tx.rs:16932` (the renamed
`vmin_throttle_function_fires_on_lag_breach` test) must use `&mut`.

Lone-stale-low-peer degenerate (Codex Q2): only one peer remains, it's
stuck at qvtime=255. Worker 4's check returns false → consecutive_skips
increments. After 8 skips, hard-cap fires → suspension activates →
worker drains 1000 drain calls at full rate. Suspension elapses →
check resumes → still throttled → suspension cycle continues. Worker
4 gets ~99 % throughput.

Burst-refill peer (Codex Q7): peer 2 just re-entered after a pause,
its slot has the OLD pre-pause vtime (low). Worker 4's check:
`v_min = old_low → throttle`. Same path as above — hard-cap +
suspension recover. The brief throttle window is bounded by 8 drain
calls (≈ 1.6 ms at 5 K drains/sec).

### Hard-cap override-rate metric (Codex Q6 + Q8)

The acceptance gate "hard-cap override rate < 5 % under normal load"
needs a precise denominator and aggregation:

- **Numerator**: `v_min_throttle_hard_cap_overrides` counter
  (sum of all queues' `v_min_hard_cap_overrides_scratch` flushed to
  `BindingLiveState` at `update_binding_debug_state`). Per-binding.
- **Denominator**: `drain_invocations` from `OwnerProfile` at
  `types.rs:1324-1345` — note this counts **successful queue service
  invocations** (per Codex Q8 correction), not all drain attempts.
  Increments on successful service at `tx.rs:411-425` and
  `tx.rs:471-485`. Frame count per invocation varies. Sum across all
  queues on this binding.
- **Aggregation scope**: **per-binding**. Aggregate across that
  binding's queues (Local-flow-fair drains, Prepared-flow-fair drains
  on shared_exact queues).
- **TOCTOU note**: numerator and denominator are read at the same
  snapshot point (the gRPC consumer's snapshot). If an evaluator
  reads them at different times (e.g., shell scripted), wider
  variance — acceptance is "under steady-state cluster smoke", which
  tolerates TOCTOU drift in practice.
- **Acceptance gate**: under normal load (iperf-c P=12, no asymmetry),
  per-binding hard-cap override rate stays below 5 %.

If override rate is high, suspension is firing too often — peer-vtime
spread is wider than expected; investigate.

## Memory ordering specification

`vacate()` write uses `Ordering::Release`. Peer reads use
`Ordering::Acquire` via `PaddedVtimeSlot::read()` at
`types.rs:1460-1467`.

**Hot read path** (Codex Q3 correction): V_min throttle decisions are
made in `cos_queue_v_min_continue` at `tx.rs:5846-5881` (post-#940
line numbers), which open-codes the slot scan rather than going
through `read_v_min`. The memory-ordering documentation belongs as a
doc comment on `cos_queue_v_min_continue`, not on `read_v_min`.

The slot iteration is **non-atomic across slots**: a slot can
transition `vtime → NOT_PARTICIPATING` between two reads in the same
iteration. Acceptable because each individual slot read is
independently Acquire-ordered against the corresponding Release write.

## File-level changes

| File | Lines | Change |
|---|---|---|
| `userspace-dp/src/afxdp/tx.rs` | 4344-4369 | Work item A: vacate hook in `account_cos_queue_flow_dequeue`. |
| ~~`userspace-dp/src/afxdp/tx.rs` | 4294-4341 | Work item B: first-enqueue publish in `account_cos_queue_flow_enqueue`.~~ DROPPED — see "Work item B — DROPPED" section. |
| `userspace-dp/src/afxdp/types.rs` | 2064 (`WorkerCommand`) | Work item C: `VacateAllSharedExactSlots` variant. |
| `userspace-dp/src/afxdp/session_glue.rs` | 316-625 (`apply_worker_commands`) | Work item C: handle new variant; sets `vacate_all_shared_exact_slots: bool` in `WorkerCommandResults`. |
| `userspace-dp/src/afxdp/types.rs` (or wherever WorkerCommandResults is defined) | new field | `vacate_all_shared_exact_slots: bool` in `WorkerCommandResults`. |
| `userspace-dp/src/afxdp/worker.rs` | 818-822 area | Work item C: dispatch the flag — iterate bindings and call `vacate_all_shared_exact_slots(binding)`. |
| `userspace-dp/src/afxdp/worker.rs` | 1875-1919 (`reset_binding_cos_runtime`) | Inline call to `vacate_all_shared_exact_slots(binding)` before `binding.cos_interfaces.clear()`. Remove FIXME at line 1905. |
| `userspace-dp/src/afxdp/worker.rs` | new helper near reset_binding_cos_runtime | `vacate_all_shared_exact_slots(binding: &BindingWorker)` — single shared helper used by both paths. |
| `userspace-dp/src/afxdp/coordinator.rs` | HA-demotion path | Work item C: enqueue `VacateAllSharedExactSlots` on demotion. Search for the existing demotion enqueue point. |
| `userspace-dp/src/afxdp/types.rs` | `CoSQueueRuntime` struct (~types.rs:1062-1275) | Work item D: add three new fields — `consecutive_v_min_skips: u32`, `v_min_suspended_remaining: u32`, `v_min_hard_cap_overrides_scratch: u32`. **Initialization is enforced by Rust struct-literal compile gate**: the struct has no `Default` impl; all construction sites must initialize the new fields explicitly. Compile errors will catch missed sites. Production sites: `tx.rs:5943-5988` (`build_cos_interface_runtime`). Test sites: `tx.rs:14735, 14783, 14842` and `worker.rs:~2465, 2609, 2819, 2857, 2895, 3058, 3096, 3224, 3397, 3435`. |
| `userspace-dp/src/afxdp/umem.rs` | `BindingLiveState` (~1797 area) | Work item D: add `v_min_throttle_hard_cap_overrides: AtomicU64` (mirrors `flow_cache_collision_evictions`). Initialize to 0 in `BindingLiveState::new()`. |
| `userspace-dp/src/afxdp/umem.rs` | `update_binding_debug_state` (umem.rs:2526) | Work item D: flush each queue's `v_min_hard_cap_overrides_scratch` into `live.v_min_throttle_hard_cap_overrides` (mirrors flow_cache_collision_evictions flush at umem.rs:2603-2607). |
| `userspace-dp/src/afxdp/tx.rs` | new const | Work item D: `V_MIN_CONSECUTIVE_SKIP_HARD_CAP: u32 = 8;` and `V_MIN_SUSPENSION_BATCHES: u32 = 1000;` |
| `userspace-dp/src/afxdp/tx.rs` | 5846-5881 (`cos_queue_v_min_continue`) | Work item D: change signature to `&mut CoSQueueRuntime`; add hard-cap accounting at bottom (suspension is handled by the calling drain function, NOT inside this function). Update call site at `tx.rs:2677`. |
| `userspace-dp/src/afxdp/tx.rs` | 5846 doc comment | Memory-ordering doc on `cos_queue_v_min_continue` (correction from Codex Q3). |
| `userspace-dp/src/afxdp/tx.rs` | new helper | Work item D: `cos_queue_v_min_consume_suspension(&mut CoSQueueRuntime) -> bool` — decrements `v_min_suspended_remaining` once if active. Called by drain functions before the per-pop loop. |
| `userspace-dp/src/afxdp/tx.rs` | drain functions | Work item D: in `drain_exact_local_items_to_scratch_flow_fair` and `drain_exact_prepared_items_to_scratch_flow_fair`, add the `if free_tx_frames.is_empty() { return Ready; }` preflight + `let suspended = cos_queue_v_min_consume_suspension(queue);` before the per-pop loop. Inside the loop, gate the V_min check with `if !suspended`. |
| `userspace-dp/src/afxdp/tx.rs` | hard-cap path inside `cos_queue_v_min_continue` | Work item D: increment `queue.v_min_hard_cap_overrides_scratch` (the per-queue scratch counter) when hard-cap fires. The scratch counter flushes to `BindingLiveState::v_min_throttle_hard_cap_overrides` via `update_binding_debug_state` (umem.rs flush row above). |

## Tests

| Test | Purpose |
|---|---|
| `vmin_vacate_on_bucket_empty` | After active_flow_buckets→0 on shared_exact queue, slot reads NOT_PARTICIPATING. |
| `vmin_no_first_enqueue_publish` | After vacate + re-enqueue, slot stays at NOT_PARTICIPATING until first post-settle publish (Work item B intentionally NOT included). |
| `vmin_suspension_not_decremented_on_empty_tx_frames` (Gemini Q6) | Drain function called with empty `free_tx_frames`: returns early WITHOUT decrementing `v_min_suspended_remaining`. Validates the preflight gate. |
| `vmin_phantom_participating_no_stall` | Worker A drains; worker B vacates. Worker A's V_min check sees no participating peers; no throttle. |
| `vmin_hard_cap_force_continue_activates_suspension` | Synthetic peer slot pegged at low. Worker hits 8 skips, hard-cap fires, suspension activates for 1000 batches. Within suspension, V_min check returns true unconditionally. |
| `vmin_suspension_resumes_after_n_batches` | After 1000 batches of suspension, V_min check resumes. If condition still bad, hard-cap fires again. |
| **`vmin_captured_failure_lone_stale_low_peer`** (Codex Q2 + Q9) | Reproduce captured peer vector: worker_id=4, peer_vtimes=[NOT_PART, 255, NOT_PART, NOT_PART, ..., 664, NOT_PART, ...], qvtime=4.1 GB. First call returns false (throttle). After 8 calls, hard-cap fires, returns true with suspension activated. |
| **`vmin_captured_failure_full_vector`** (Codex Q1 + Q9) | Full peer vector matching the captured DBG_VMIN trace. Pin the throttle decision at each pop_count. |
| `vmin_ha_demotion_vacates_all_slots` | HA demotion command executes vacate path; all owned shared_exact slots return NOT_PARTICIPATING. |
| `vmin_reset_epoch_vacates_all_slots` | `reset_binding_cos_runtime` called; all slots vacated before clear. |
| (existing 6 V_min tests still pass) | Regression check. |

## Acceptance criteria

- [ ] All four work items committed (A/B/C/D as separate commits).
- [ ] All new tests pass; existing 6 V_min tests pass.
- [ ] Cluster smoke on `loss:xpf-userspace-fw0/fw1`:
  - iperf-c P=12 ≥ 22 Gb/s (current baseline post-#940).
  - iperf-b P=12 ≥ 9.5 Gb/s, 0 retx.
  - iperf-c P=1 ≥ 6 Gb/s.
  - Mouse p99 within ±5 % of post-#917 baseline (59.51 ms).
- [ ] **#942 re-test on this branch (BEFORE merging)**: temporarily
  add the `cos_queue_v_min_continue` call back into
  `drain_exact_prepared_items_to_scratch_flow_fair`. Run iperf-c P=12
  cluster smoke. **Must pass at ≥ 22 Gb/s** (the throttled batches
  during the 8 hard-cap-skips are << 1 % of total drain time at
  N=1000). Then remove the temporary wiring before commit (#942 stays
  a separate PR).
- [ ] **Hard-cap override rate < 5 %** per binding under normal load
  (iperf-c P=12 saturating). Numerator = `v_min_throttle_hard_cap_overrides`
  counter, denominator = `drain_invocations` summed across the
  binding's workers.
- [ ] Co-land or land-first relative to #943 (the
  `v_min_throttle_hard_cap_overrides` counter is the validation
  surface for Work item D's suspension activations).

## Risks

- **Suspension hides peer-bucket-balance regressions**: if peers truly
  have wide vtime spread (RSS-induced), suspension means V_min sync
  is essentially disabled most of the time. The "fairness" benefit of
  V_min sync is lost. Tradeoff: liveness > fairness when the algorithm
  can't make progress.
- **N=1000 drain-call suspension**: arbitrary. At TX_BATCH_SIZE=64
  (per `afxdp.rs:187`) and ~5 K successful drain invocations/sec under
  load, N=1000 ≈ 200 ms suspension window. Long enough that peers
  might catch up if they're going to. If they're not (RSS imbalance
  is permanent), suspension cycle continues. Telemetry (counter
  flushed via `update_binding_debug_state`) shows how often this fires.
- **State coherence on `&mut queue`**: V_min check now mutates the
  queue runtime (counters). All callers must hold the queue mutably.
  Audit `tx.rs:2677` and any test sites.

## Test-and-deploy plan

1. Implement Work items A/B/C/D as separate commits.
2. `cargo build` + `cargo test` — all unit tests green.
3. `make cluster-deploy` — apply CoS config — run cluster smoke.
4. **#942 re-test**: temporarily re-add wiring; run smoke; verify
   ≥ 22 Gb/s at iperf-c P=12. Remove wiring.
5. Codex hostile review.
6. Gemini adversarial review.
7. Both PASS → merge.
8. Re-open #942 PR (separate, after #941 merge).

## Out of scope

- #942 wiring itself (separate PR after #941 lands).
- The full #943 telemetry pipeline (`v_min_throttles` regular counter,
  per-worker breakdown). #941 only adds the
  `v_min_throttle_hard_cap_overrides` counter that Work item D needs.
  #943's broader telemetry can land as a follow-up.

## Plan history

- v1 (initial): Work items A/B/C/D, no E. Codex NEEDS-MAJOR — A+B+C+D
  bound liveness but don't fix asymmetry; reset-epoch not subsumed by C.
- v2: Promoted Work item E (outlier trim) to required. Codex
  NEEDS-MAJOR — E2 doesn't fix lone-stale-low; dispatch BROKEN; tests
  missing.
- v3: Dropped Work item E. Beefed up Work item D with
  suspension-after-force-continue (subsumes E). Fixed dispatch via
  WorkerCommandResults flag. Added deterministic captured-failure tests.
  Codex NEEDS-MAJOR — suspension decrement was per-pop (not per-batch),
  arithmetic wrong; counter plumbing (where does `&AtomicU64` come
  from); TX_BATCH_SIZE stale (32 vs actual 64); HA scope unclear.
- v4: Suspension decrement moved to drain-entry (one decrement
  per drain call, not per pop). Counter on CoSQueueRuntime as scratch
  field, flushed via `update_binding_debug_state` (matches
  `flow_cache_collision_evictions` pattern). TX_BATCH_SIZE corrected.
  HA scope clarified (all bindings, with tradeoff acknowledged).
  Drain denominator clarified as "successful queue service
  invocations". Codex NEEDS-MINOR — drain-entry decrement burns
  suspension on TX-ring-full no-progress drains; "Default::default()"
  language was wrong.
- v5: Decrement gated on `pop_count==1` AND inside the loop body
  AFTER `free_tx_frames` preflight (`cos_queue_v_min_consume_suspension`
  helper). Compile-gate language replaces Default-impl assumption;
  all CoSQueueRuntime construction sites enumerated. Codex
  NEEDS-MAJOR — the v5 sketch had a logic bug: `pop_count==1`-gated
  flag meant cadence checks at pop_count==8 still ran V_min during
  "suspension". Plus stale top-of-function decrement language and
  duplicated BindingLiveState row.
- v6: `suspended` flag computed ONCE before the loop (after
  preflight), persists for the entire drain call. V_min check is
  gated by `if !suspended` for every pop in the loop, not just
  pop_count==1. Suspension read/consume lives entirely in the drain
  function; `cos_queue_v_min_continue` only arms suspension on
  hard-cap activation. Codex PLAN-READY after 6 rounds.
- v7 (this): Gemini adversarial review caught Work item B as a
  design flaw (re-publishing OLD queue_vtime re-introduces the
  failure pattern). **Dropped Work item B entirely.** After vacate,
  slot stays NOT_PARTICIPATING until first post-settle publish
  (provided by #940's hook). Initial-state correctness explicit.
  All-demotion-paths verification added. New
  `vmin_suspension_not_decremented_on_empty_tx_frames` test.
