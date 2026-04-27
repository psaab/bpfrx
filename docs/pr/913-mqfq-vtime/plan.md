# Plan: #913 — MQFQ queue_vtime semantics fix (WFQ-correct)

Issue: #913 (Gemini-flagged)
Umbrella: #911 (same-class HOL on shared_exact CoS queues)
Related: #912 (closed; bucket-count grow was wrong-direction; this
plan addresses the actual root cause)
Diagnosis: `docs/pr/905-mouse-latency/findings.md` + #913 issue body

## 1. Problem

`queue_vtime` is incremented by **the bytes of every drained
packet** in `cos_queue_pop_front_inner` at
`userspace-dp/src/afxdp/tx.rs:4513`:

```rust
let bytes = cos_item_len(&item);
queue.queue_vtime = queue.queue_vtime.saturating_add(bytes);
```

Under MQFQ (Multi-Queue Fair Queueing — the algorithm this
scheduler implements), the per-queue virtual time should track
the **MQFQ system frontier** — the finish time of the packet
currently being served, which by construction equals the
smallest `head_finish` across all currently-active flow
buckets at pop time (because MQFQ pops min-finish-first).
The current implementation tracks aggregate bytes drained
instead, which is a Stochastic-Fair-Queueing (SFQ) V(t)
formulation and DOES NOT match MQFQ semantics.

(Note on terminology: this is **NOT canonical WFQ** in the
Demers/Keshav/Shenker sense. Canonical WFQ has V(t) advancing
at rate 1 / Σ(active_weights), which would advance more slowly
under N flows. MQFQ instead computes per-flow finish-times at
enqueue via `F = max(F_prev, V(t)) + bytes` and serves
min-F-first; V(t) is approximated as the served packet's
finish-time. Gemini reviewer flagged this distinction; the
fix is to clarify the wording, not change the algorithm.)

The aggregate-bytes formulation produces **temporal inversion**:

- With N active flows (buckets) backlogged, each pop bumps vtime
  by ~MTU.
- After serving one round of N flows, vtime has grown by N × MTU.
- A new mouse arrival anchors at `head[b] = max(tail[b], vtime) + bytes`
  (frame.rs idle-bucket re-entry rule). Its `tail[b]` is 0 (fresh
  bucket), so `head[b] = vtime + bytes` — far in the "future"
  relative to the elephants' head_finish (which has only
  advanced by ~MTU per their own bucket).
- MQFQ pops the bucket with smallest head_finish → mouse comes
  AFTER all backlogged elephants.

This explains the empirical iperf-b same-class FAIL: at 8
elephant flows + many short mice, mice consistently anchor in
the future and are served LAST. p50 mouse latency stays at idle
(early in the queue activity) while p99 blows up to hundreds of
ms or seconds (mice arriving when many elephants have built up
backlog).

The issue was further confirmed empirically by #912's failed
attempt to fix this via bucket-count grow: with more buckets,
mice were MORE consistently in their own buckets, but their
finish-time anchoring problem persisted. Raising buckets
1024→16384 made things worse, not better, because mice that
PREVIOUSLY collided with elephants got at least the elephant's
local pop rate; mice in fresh buckets always landed at
`vtime + bytes` which is the worst possible position.

## 2. Goal

Make `queue_vtime` track the **MQFQ system frontier** — the
served packet's finish time, which equals the smallest
`head_finish` across active buckets at pop time — rather than
aggregate bytes drained. Mouse arrivals in fresh buckets then
anchor at `max(0, vtime) + bytes` (= roughly the smallest
active head_finish + their own size), interleaving with
elephants rather than queueing behind them.

Idle-bucket staleness: if a queue's vtime is "behind" the
true frontier (e.g., the only flow served has a small
head_finish), a returning idle flow anchors via
`account_cos_queue_flow_enqueue`'s `max(tail, vtime) + bytes`.
The `max` here ensures returning flows can't anchor below
the current frontier — and since vtime is monotonic and only
advances on pop, this is sound for MQFQ. (Gemini's concern
that vtime might "stale" applies to canonical WFQ; in MQFQ
the served-finish-tracking design self-stabilizes via this
enqueue-side `max`.)

## 3. Approach

Three changes in `tx.rs` + one struct field addition in
`types.rs`:

### 3.1 Pop semantics (the core fix)

`cos_queue_pop_front_inner` (`tx.rs:4451`) has TWO call sites
distinguished by the `push_snapshot` parameter:

- **Hot path** (`push_snapshot=true`, via `cos_queue_pop_front`):
  used by every TX drain, MUST get the new WFQ semantics. This
  is the path that suffers temporal inversion under many-flow
  load.
- **No-snapshot path** (`push_snapshot=false`, via
  `cos_queue_pop_front_no_snapshot`): used by `cos_queue_drain_all`
  (which has a non-teardown caller — see §3.7) and the worker
  teardown loop. MUST keep the legacy aggregate-bytes advance.
  The drain-restore failure path (`demote_prepared_cos_queue_to_local`,
  `tx.rs:5208/5213/5217`) relies on the symmetric `pop: vtime
  += bytes` / `push_front: vtime -= item_len` invariant to
  reconstruct queue state. Switching this path to max-based
  semantics breaks round-trip neutrality (Codex R2 demonstrated
  with vtime=5000, items=[1000,2000,1500]: drain followed by
  reverse push_front yields head=3000 instead of pre-drain
  head=6000).

Replace the unconditional advance at `tx.rs:4513`:

```rust
let bytes = cos_item_len(&item);
queue.queue_vtime = queue.queue_vtime.saturating_add(bytes);
```

with this branched structure (served_finish captured BEFORE the
head-advance below overwrites the slot, so the snapshot can pin
the pre-pop value):

```rust
let bucket_u16 = cos_queue_min_finish_bucket(queue)?;
let bucket = usize::from(bucket_u16);
let served_finish = queue.flow_bucket_head_finish_bytes[bucket];
if push_snapshot {
    debug_assert!(/* ... existing bound check ... */);
    queue.pop_snapshot_stack.push(CoSQueuePopSnapshot {
        bucket: bucket_u16,
        pre_pop_head_finish: served_finish,
        pre_pop_tail_finish: queue.flow_bucket_tail_finish_bytes[bucket],
        pre_pop_queue_vtime: queue.queue_vtime, // NEW (§3.2)
    });
}
let item = queue.flow_bucket_items[bucket].pop_front()?;
if push_snapshot {
    // Hot path: WFQ V(t) — system virtual time tracks the
    // finish time of the packet currently being served,
    // monotonically. Closes #913 temporal inversion.
    queue.queue_vtime = queue.queue_vtime.max(served_finish);
} else {
    // No-snapshot path: legacy aggregate-bytes advance. The
    // drain_all/restore_front failure path
    // (demote_prepared_cos_queue_to_local) relies on
    // pop: `vtime += bytes` paired with push_front: `vtime
    // -= item_len` for state reconstruction. Keeping the old
    // semantics here costs us nothing on the hot path — drain_all
    // is rare and not fairness-critical, and the items are
    // re-enqueued via push_back after success or LIFO push_front
    // on failure, both of which restore correct vtime ordering.
    queue.queue_vtime = queue.queue_vtime.saturating_add(cos_item_len(&item));
}
// ... existing head-advance / rr_buckets.remove paths unchanged ...
```

Monotonicity (hot path): `served_finish` ≥ pre-pop `vtime` in
the steady-state case (the bucket's head was anchored at-least-
vtime when the packet enqueued); the `max` defends against
degenerate orderings where this temporarily does not hold (see
§8).

### 3.2 Snapshot the pre-pop vtime for rollback

The current rollback path at `tx.rs:4334` does:

```rust
queue.queue_vtime = queue.queue_vtime.saturating_sub(item_len);
```

This was symmetric with the old `saturating_add(bytes)` advance.
In the new semantics, the advance is `max(vtime, served_finish)`
which has no fixed delta — so symmetric subtraction is wrong.

Add a `pre_pop_queue_vtime: u64` field to `CoSQueuePopSnapshot`
(`types.rs`) and capture pre-pop vtime alongside the existing
`pre_pop_head_finish` and `pre_pop_tail_finish`.

**Cache locality / no-realloc (Gemini MAJOR #3, scoped down)**:
`pop_snapshot_stack: Vec<CoSQueuePopSnapshot>` is preallocated
to `TX_BATCH_SIZE` capacity at `CoSQueueRuntime` construction
(existing invariant — see `types.rs` and the debug_assert at
`tx.rs:4493`); no realloc on the hot path. The new field
`pre_pop_queue_vtime` (8 bytes) extends the snapshot struct
from ~24 to ~32 bytes; at `TX_BATCH_SIZE=256`
(`afxdp.rs:159`) the full stack is ~8KB, which still fits
in L1 (32-64KB typical).

**NUMA discipline is NOT addressed by this PR**. Gemini R8
correctly noted that `coordinator.rs:696` uses
`thread::Builder::spawn` with no explicit NUMA policy — the
allocation is wherever the OS happens to place it. A
multi-socket NUMA-aware allocator + `numa_alloc_onnode` /
mempool placement is a separate larger change; this PR makes
no claim about cross-socket access. The bigger NUMA exposure
in this dataplane is the AF_XDP UMEM (~96 MB per binding),
which is also not NUMA-pinned today; the snapshot stack at
~8KB is a small additional concern.

```rust
queue.pop_snapshot_stack.push(CoSQueuePopSnapshot {
    bucket: bucket_u16,
    pre_pop_head_finish: queue.flow_bucket_head_finish_bytes[bucket],
    pre_pop_tail_finish: queue.flow_bucket_tail_finish_bytes[bucket],
    pre_pop_queue_vtime: queue.queue_vtime,  // NEW
});
```

### 3.3 Restore vtime from snapshot in push_front

The unconditional `queue_vtime.saturating_sub(item_len)` at
`tx.rs:4334` becomes **branched on snapshot presence**. With a
matching snapshot, vtime is restored from `pre_pop_queue_vtime`
(closing the new max-based advance). Without a snapshot — the
drain_all/restore_front failure path or any non-Phase-3 caller
— the legacy aggregate-bytes rewind is preserved, matching the
no-snapshot pop in §3.1.

**Critically, vtime restore happens for BOTH `was_empty` and
active-bucket push_front paths** (Codex R2 bug 2). The existing
test `mqfq_push_front_is_finish_time_neutral_on_active_bucket`
at `tx.rs:11377` explicitly pins
"queue_vtime must be round-trip neutral on pop→push_front…
without this, newly-active flows inherit an inflated vtime
anchor and start behind established traffic even though zero
bytes were actually transmitted during the rollback" (lines
11432-11438). That test would fail under any plan that leaves
vtime advanced after an active-bucket rollback.

```rust
// (was tx.rs:4334) — REPLACED with peek-then-pop snapshot-aware
// restore. Mismatch is a HARD CONTRACT VIOLATION: the only way
// the stack's top entry can have a non-matching bucket is if a
// scratch builder failed to clean up its orphan snapshot when
// dropping a popped item (see §3.4). With the §3.4 cleanup in
// place, mismatch is believed unreachable in current code; we
// panic loud if it ever fires (loud failure > silent corruption).
let stack_top_bucket = queue
    .pop_snapshot_stack
    .last()
    .map(|s| usize::from(s.bucket));

let snapshot = match stack_top_bucket {
    None => None, // Legitimate empty stack: drain_all cleared,
                  // or fresh-flow caller. Aggregate-bytes path.
    Some(top) if top == bucket => queue.pop_snapshot_stack.pop(),
    Some(top) => {
        // CONTRACT VIOLATION: scratch builder did not clean up
        // its orphan snapshot, or a future code path
        // introduced a new pop+drop site that bypasses §3.4
        // cleanup. With orphan-cleanup at the source, this is
        // believed unreachable in current code; the handler
        // below is a TRIPWIRE.
        //
        // Why hard panic, not graceful recovery:
        //   Codex R8 + Gemini R8 converged: graceful recovery
        //   (clear stack + degrade-to-aggregate) trades a loud
        //   detectable failure for silent compounding fairness
        //   drift. Once the stack is cleared, every remaining
        //   in-flight rollback item takes the empty-stack
        //   `vtime -= item_len` path despite their pops having
        //   used `max(vtime, served_finish)`, which can let
        //   `queue_vtime` regress below the pre-batch frontier.
        //   That is far worse than a panic in production —
        //   the bug becomes a hard-to-debug performance anomaly
        //   instead of a clear crash.
        //
        // For a (believed-)UNREACHABLE invariant violation,
        // fail-loud is correct. The production failure mode
        // (no supervisor in #913 — see §3.6):
        //   - Default Rust panic handler emits the panic
        //     message to stderr → journald via systemd.
        //   - The worker thread dies; helper process keeps
        //     running with one fewer worker.
        //   - Bindings served by that worker stall until the
        //     daemon is restarted via config change or manual
        //     intervention.
        //   - SAME blast radius as any existing panic vector
        //     in `worker_loop` (`unwrap`, `expect`, `panic!`,
        //     OOB index). #913 adds one more believed-
        //     unreachable site of the same class.
        //
        // Proper panic containment (parent-side helper
        // supervision in `pkg/dataplane/userspace/process.go`
        // + producer-side dispatch-bypass + bounded queues +
        // structured logging) is tracked in #925. It's
        // cross-cutting reliability work that benefits ALL
        // panic vectors, not just this one.
        assert!(
            false,
            "pop_snapshot_stack bucket mismatch on push_front: \
             top entry's bucket {} != target bucket {}; a \
             caller pop+dropped without §3.4 cleanup",
            top,
            bucket,
        );
        unreachable!() // satisfies the Option type; not reached.
    }
};

// Restore queue_vtime. Covers both was_empty and active paths.
match snapshot.as_ref() {
    Some(snap) => {
        // Hot-path matched-bucket restore.
        queue.queue_vtime = snap.pre_pop_queue_vtime;
    }
    None => {
        // Empty stack: drain_all/restore_front (aggregate-bytes
        // pop semantics) or fresh-flow non-Phase-3 caller.
        // Legacy aggregate-bytes rewind.
        queue.queue_vtime = queue.queue_vtime.saturating_sub(item_len);
    }
}

let was_empty = queue.flow_bucket_items[bucket].is_empty();
if was_empty {
    if let Some(snap) = snapshot {
        queue.flow_bucket_head_finish_bytes[bucket] = snap.pre_pop_head_finish;
        queue.flow_bucket_tail_finish_bytes[bucket] = snap.pre_pop_tail_finish;
        // ... existing bucket-level restore (active count, ring) ...
    } else {
        // Aggregate-bytes path: existing account_cos_queue_flow_enqueue
        // re-anchor. The vtime rewind above leaves vtime
        // correctly positioned for the re-anchor's
        // `max(tail, vtime)` calculation in the drain_all path.
    }
} else {
    // Active bucket: existing head -= bytes(current_head)
    // reversal (tx.rs:4416-4422). vtime already restored above.
}
```

### 3.4 Scratch builder orphan-snapshot cleanup

`drain_exact_local_items_to_scratch_flow_fair` (`tx.rs:2611`)
and `drain_exact_prepared_items_to_scratch_flow_fair`
(`tx.rs:2780`) both follow this pattern:

1. Call `cos_queue_pop_front` (which pushes a snapshot).
2. Either accept the popped item into scratch, OR drop it
   on a per-item failure (frame too big, slice fails).

When step 2 drops the item, **the snapshot remains on the
stack with no item to match it**. The caller of the builder
sees `ExactCoSScratchBuild::Drop` and invokes
`restore_exact_local_scratch_to_queue_head_flow_fair`
(`tx.rs:2125`, `:2192`, `:2409`, `:2481`), which `push_front`s
the surviving scratch items. The orphan snapshot at the top
of the stack does NOT match the bucket of the item being
push_front-ed (Codex R6 finding 1).

**Fix: pop the orphan snapshot at each drop site before
returning.** Four sites in `tx.rs`, one line each:

| Site | Condition |
|------|-----------|
| `tx.rs:2649-2658` | Local frame exceeds UMEM frame capacity. |
| `tx.rs:2663-2672` | Local UMEM slice out of range. |
| `tx.rs:2821-2828` | Prepared frame exceeds UMEM frame capacity. |
| `tx.rs:2849-2862` | Prepared UMEM slice out of range (with DSCP rewrite). |

Each gets `queue.pop_snapshot_stack.pop();` immediately before
the `return ExactCoSScratchBuild::Drop { ... };` statement.
The pop removes only the orphan snapshot for the just-dropped
item; earlier successful items' snapshots stay intact for
the subsequent restore.

Note: `tx.rs:2659-2661` (no-free-frame case) already
push_fronts the item back, which correctly consumes its own
snapshot. No cleanup needed there.

After this fix, `cos_queue_push_front` mismatch is believed
unreachable in current code, and the §3.3 `assert!(false)` is
purely defensive — a tripwire for future scratch-builder
additions that forget the cleanup, or unknown races. The
behavior is strictly safer than all prior plan revisions:

| Plan revision | Mismatch behavior |
|---------------|-------------------|
| Pre-R3 | Silent aggregate-bytes rewind (wrong inverse). |
| R3 (debug_assert + pop) | Release: wrong snapshot applied to wrong bucket. |
| R4 (peek-then-pop, fall through) | Release: wrong vtime rewind on mismatched fallback. |
| R5 (peek + clear + skip vtime) | Release: clears valid outstanding snapshots — destroys rest of rollback batch (R6 finding 2). |
| **R6 (orphan cleanup at source + assert!() on mismatch)** | Mismatch is believed unreachable in current code. Defensive `assert!()` panics dev+release if a future code path forgets cleanup or an unknown race re-introduces it. |

This design closes:
- Codex R2's active-bucket rollback counterexample (test
  `:11377` passes unchanged).
- Codex R3 finding 4 (bucket-mismatch fallback): mismatch is
  believed unreachable in current code; the assert is a tripwire.
- Codex R4's release-mode silent-corruption: peek-then-pop
  prevents wrong-snapshot consumption.
- Codex R5's "wrong vtime rewind on mismatch": mismatch path
  hard-panics, no vtime mutation possible.
- Codex R6 finding 1 (real mismatch path exists today via
  scratch-builder Drop returns): closed by the four
  one-line cleanups in scratch builders.

### 3.5 Test updates

Eight existing tests interact with vtime semantics. Seven pass
numerically (single-flow scenarios where `served_finish` = `Σ bytes
drained`, or multi-bucket cases that produce identical numerical
results under both semantics); one (the cross-flow interleaved test)
genuinely fails:

| Site | Behavior under revised plan | Action |
|------|------------------------------|--------|
| `tx.rs:10811` (4-pop interleaved across 3 flows, equal-byte) | **FAILS**: expected 6000, new value 3000. Interleaved pops [1111, 1112, 1113, 1111] each pick a bucket whose head_finish=1500 except the last (3000). `max(0,1500,1500,1500,3000)` = 3000, not Σbytes=6000. | Replace `assert_eq!(queue.queue_vtime, 6000);` with `assert_eq!(queue.queue_vtime, 3000, "vtime tracks last served packet's finish-time, not aggregate bytes drained")`. |
| `tx.rs:11042-11050` (3-pop single-flow A, idle-B re-anchor probe) | **PASSES numerically**: served_finish progression 1500 → 3000 → 4500 yields final 4500. The load-bearing idle-B re-anchor at 5700 is unaffected. | Keep `assert_eq!(queue.queue_vtime, 4500)`. Update the comment "vtime reaches 4500" → "vtime reaches 4500 (3rd served-packet finish-time under MQFQ served-finish semantics)". |
| `tx.rs:11220-11272` (`mqfq_queue_vtime_advances_by_drained_bytes`, single-flow 3-packet) | **PASSES numerically** for the same reason. Test name and docstring pin the now-wrong "vtime += bytes per pop, NOT bucket_finish" principle. | Rename test to `mqfq_queue_vtime_tracks_served_finish_time`. Rewrite docstring to describe MQFQ served-finish semantics (not canonical WFQ V(t); see §1/§2 distinction). Numerical asserts (1500 / 3000 / 4500) unchanged. |
| `tx.rs:11377` (`mqfq_push_front_is_finish_time_neutral_on_active_bucket`) | **PASSES UNCHANGED** under revised §3.3 (snapshot-based vtime restore on active push_front). The test pins all of head_finish, tail_finish, bytes, AND `queue_vtime` round-trip neutrality. Codex R2 flagged this test as one my prior plan revision would have broken at line 11433. | No change. The revised §3.3 explicitly preserves this invariant — it is the load-bearing test for active-bucket rollback correctness. |
| `tx.rs:11456` (`mqfq_push_front_is_neutral_on_drained_bucket_round_trip`) | **PASSES UNCHANGED** — single-flow drained-bucket round trip. Pop sees served_finish=6500; vtime advances to 6500 (matches pre_pop_vtime+1500 by numeric coincidence at line 11500). push_front consumes the matching snapshot, restores vtime=5000 and head/tail=6500. | No change. (Codex R3 finding 6 listed this test; verified passes under revised plan.) |
| `tx.rs:11548` (`mqfq_batched_rollback_restores_queue_vtime`) | **PASSES UNCHANGED** — single-bucket 4-pop batched rollback. Each pop captures snapshot {head, tail, vtime} pre-pop; LIFO restore matches each. Active-path head reversal (head -= bytes(current_head)) yields identical numerical values. | No change. |
| `tx.rs:11681` (`mqfq_batched_rollback_across_multiple_buckets`) | **PASSES UNCHANGED** — but two stale narrative bits become wrong under max semantics: (a) docstring at 11663-11665 ("vtime goes 5000 → 5900 → 7400. Both buckets drain") — vtime actually stays at 5000 throughout because both pops see served_finish < pre-pop vtime (1000 < 5000, 1600 < 5000); (b) inline comment at 11733 ("B's head (1400) < A's head (2000)") — actual heads at drain time are 1000 and 1600 (Codex R4 catch). | Update both narrative sites to reflect new semantics. The numerical assertion `queue_vtime == pre_batch_vtime` still holds for the right reason now (vtime never advanced during drain → snapshot restore is a no-op on vtime). |
| `tx.rs:11997` (`mqfq_brief_idle_reentry_exercises_both_max_arms`) | **PASSES UNCHANGED** — A drains then B drains; vtime goes 0 → 1500 (served_finish for A's pop) → 2300 (served_finish for B's pop, anchored at max(0,1500)+800 by re-anchor). Both arms of `max(tail, vtime)` in `account_cos_queue_flow_enqueue` are exercised correctly. | No change. The test continues to validate the brief-idle re-entry path under the new semantics. |

Add a new test that **distinguishes** the two semantics — i.e.,
fails under old, passes under new. Construct N=10 flows × 5
packets each (1500 B), pop one packet from each flow in a
round (10 pops). Under old semantics vtime would be 10 × 1500
= 15000; under new semantics each pop sees served_finish=1500
(every flow's head packet), so `vtime = max(0, 1500, 1500,
..., 1500) = 1500`.

```rust
#[test]
fn mqfq_vtime_does_not_accumulate_across_flows() {
    // 10 flows × 1 packet per round, pop in MQFQ order.
    // OLD aggregate-bytes: vtime would equal 15000.
    // NEW MQFQ served-finish: vtime should equal 1500 (each
    // pop sees same head_finish=1500 across flows; max never
    // advances).
    // ...
    assert_eq!(queue.queue_vtime, 1500,
        "MQFQ vtime tracks served-packet finish, not aggregate \
         bytes drained across multiple flows");
}
```

### 3.6 Worker supervisor — REVERTED, no supervisor in #913

**Scope decision (R4 code review, after 4 rounds of design
exploration)**: #913 ships **no supervisor**. The §3.3
`assert!(false)` invariant tripwire propagates to the default
Rust panic handler, which emits the panic message to stderr
(→ journald via systemd) and kills the panicking worker
thread. The helper process (`xpf-userspace-dp`) keeps running
with one fewer worker, exactly as it does today for any
existing `unwrap`/`expect`/`panic!` site in `worker_loop`.

#### 3.6.1 Why no supervisor

We tried four supervisor designs across rounds R0-R4 of code
review, each rejected:

| Round | Design | Rejection reason |
|-------|--------|------------------|
| R0 | catch_unwind + log + dead flag (detection-only) | Producers keep enqueuing → unbounded queue (Codex+Gemini R2). |
| R1 | + coordinator-side dispatch-bypass at 2 sites | Incomplete; ~10 producer sites across coordinator/ha/tx/tunnel; HA-ack timeout (Codex+Gemini R3). |
| R2 | + std::process::exit(1) on panic | xpfd runs xpf-userspace-dp as a CHILD HELPER (`pkg/dataplane/userspace/process.go:72`) without auto-restart on unexpected exit; helper death is detected only on next status-poll failure and recovered only on next `applyConfigLocked` (Codex R4). exit(1) just kills the helper without triggering recovery. |
| R3 | + Gemini's stderr flush + Codex's documented map cleanup | Same R4 finding: exit(1) is not actually triggering systemd restart. |

The honest answer: **proper panic containment requires
infrastructure work outside #913's scope** — at minimum, parent-
side helper supervision in `pkg/dataplane/userspace/process.go`
that detects helper exit, clears stale BPF map state, and
re-applies the config. That's #925's domain.

#### 3.6.2 What this means for #913 in practice

The §3.3 panic site is **believed unreachable in current code**
(per §3.4's scratch-builder orphan cleanup). If it ever fires,
the failure mode is identical to any other `panic!` in
`worker_loop`:

1. Default Rust panic handler emits "thread 'xpf-userspace-worker-N'
   panicked at 'pop_snapshot_stack bucket mismatch...'" to stderr.
2. journald captures the message via systemd's stderr redirect.
3. Worker thread N dies. Helper process keeps running.
4. Bindings served by worker N stop processing. Status poll
   from xpfd may degrade (depends on which bindings).
5. Next config change OR a manual daemon restart triggers
   recovery.

This is **strictly equal blast radius** to existing panic
vectors (`unwrap` on Mutex, `expect` on send/recv,
`panic!` macros, OOB index, etc.). #913 adds ONE new
believed-unreachable site of the same class.

#### 3.6.3 What's deferred to #925

Tracked in GitHub #925 (filed during this PR's review cycle):

- Parent-side helper supervision: `cmd.Wait()`-based detection
  of unexpected exit; auto-restart with map cleanup.
- catch_unwind on the helper side, paired with parent
  supervision so panic → controlled exit → parent restart.
- Per-worker liveness reporting via gRPC.
- Producer-side dispatch-bypass at the ~10 enqueue sites.
- Bounded worker command queues (OOM containment).
- HA-ack-vs-dead-worker semantics.

The combination of those changes is what "proper panic
handling" looks like for this dataplane. They're cross-cutting
and benefit ALL panic vectors (not just #913's), which is why
they belong in their own PR with their own design discussion.


### 3.7 No-snapshot path retains legacy aggregate-bytes semantics

`cos_queue_pop_front_no_snapshot` (`tx.rs:4444`) wraps
`cos_queue_pop_front_inner` with `push_snapshot=false`. It has
two callers:

- `cos_queue_drain_all` (`tx.rs:4548`) — drained items are
  either re-enqueued via `cos_queue_push_back` (success path
  in `demote_prepared_cos_queue_to_local`, `tx.rs:5223`) or
  restored via `cos_queue_restore_front` on failure
  (`tx.rs:5213/5217`). **The failure-restore path is the
  load-bearing case** — it must be round-trip neutral on all of
  vtime, head_finish, tail_finish, and item ordering.
- `worker.rs:1859` — worker teardown discard path. Queue is
  destroyed afterward; vtime semantics don't matter.

**Critical: `cos_queue_drain_all` MUST clear `pop_snapshot_stack`
at start.** Hot-path committed drains (`tx.rs:2620`, `:2797`)
clear at batch start, but committed-and-drained snapshots remain
on the stack until the next batch start or push_back. Without
clearing in drain_all, a stale hot-path snapshot would be
consumed by the subsequent `restore_front`'s `push_front`,
matching the wrong bucket state and corrupting both vtime and
head/tail (Codex R3 finding 1). The fix is a one-line addition:

```rust
fn cos_queue_drain_all(queue: &mut CoSQueueRuntime) -> VecDeque<CoSPendingTxItem> {
    // Clear any stale snapshots from prior committed hot-path
    // drains. This guarantees the subsequent restore_front (via
    // push_front) sees an empty stack and takes the aggregate-
    // bytes rewind path described in §3.7 — no risk of
    // consuming an unrelated hot-path snapshot.
    queue.pop_snapshot_stack.clear();
    let mut items = VecDeque::new();
    while let Some(item) = cos_queue_pop_front_no_snapshot(queue) {
        items.push_back(item);
    }
    items
}
```

With this clear in place, the no-snapshot path is provably
isolated from hot-path snapshot state.

The legacy aggregate-bytes design happened to be round-trip
neutral by an accidental coincidence:

```
drain pop:          vtime += bytes(item)  —  total advance = Σbytes
restore push_front: vtime -= item_len     —  total rewind  = Σbytes
                    (plus head_finish reset on bucket-empty,
                     reseeded by first push_front via re-anchor
                     using the inflated vtime, then trimmed by
                     active-bucket head -= bytes(current_head)
                     on subsequent push_fronts)
```

Walking through Codex R2's counterexample under the revised
design (`pop_no_snapshot` keeps `vtime += bytes`; `push_front`
without snapshot keeps `vtime -= item_len`):

```
Pre:  vtime=5000  head=6000  tail=9500  items=[1000, 2000, 1500]

drain (no-snapshot, aggregate-bytes):
  pop 1000:  vtime=6000  head=8000  (items[1])
  pop 2000:  vtime=8000  head=9500  (items[2])
  pop 1500:  vtime=9500  bucket empty → head=0  tail=0

restore (LIFO, no snapshot, aggregate-bytes rewind):
  push_front 1500:  vtime=9500-1500=8000
                    was_empty → re-anchor: tail=max(0,8000)+1500=9500
                                            head=tail=9500
  push_front 2000:  vtime=8000-2000=6000
                    active → head -= bytes(current_head=1500) = 8000
  push_front 1000:  vtime=6000-1000=5000
                    active → head -= bytes(current_head=2000) = 6000

Post: vtime=5000  head=6000  tail=9500  items=[1000, 2000, 1500]  ✓
```

Round-trip neutral. The trick: the inflated vtime at the moment
of the first re-anchor lifts the new head/tail to the original
tail value, and the LIFO subtractions in subsequent push_fronts
sequentially trim head_finish back to the original.

| Path | Pop advances vtime? | push_front rewinds vtime? |
|------|---------------------|---------------------------|
| Hot path (push_snapshot=true, matched-bucket restore) | yes (`max(vtime, served_finish)`) | yes (`= snapshot.pre_pop_queue_vtime`) — both was_empty AND active |
| No-snapshot drain (drain_all → push_back success) | yes (`+= bytes`) | n/a (push_back, not push_front) |
| No-snapshot drain (drain_all → restore_front failure) | yes (`+= bytes`) | yes (`-= item_len`) — neutral by §3.7 walkthrough |
| Worker teardown discard | yes (`+= bytes`) | n/a (items dropped) |
| Bucket-mismatch invariant violation (believed-unreachable per §3.4 cleanup) | n/a (pop side captures snapshot) | `assert!(false)` — worker thread panics; all bindings served by that worker stall until daemon restart |

## 4. What this is NOT

- Not a change to enqueue logic. The
  `head[b] = max(tail[b], vtime) + bytes` formula stays —
  it just sees a vtime that grows correctly now.
- Not a Phase-4 V_min cross-worker fix. That's #917, separate.
- Not a change to admission policy (per-flow caps). That's
  #914, separate.
- Not a change to bucket count or bucket sizing.
- Not a fix for cross-NIC memcpy or any throughput-level work.

## 5. Files touched

- `userspace-dp/src/afxdp/types.rs`: add `pre_pop_queue_vtime: u64`
  field to `CoSQueuePopSnapshot`.
- `userspace-dp/src/afxdp/tx.rs`:
  - `cos_queue_pop_front_inner` (`:4451`): branched vtime
    advance — `max(vtime, served_finish)` for `push_snapshot=true`
    (hot path), legacy `vtime += bytes` for `push_snapshot=false`
    (no-snapshot path); capture `pre_pop_queue_vtime` in the
    snapshot push.
  - `cos_queue_push_front` (`:4308`): replace the unconditional
    `saturating_sub(item_len)` at `:4334` with peek-then-pop
    snapshot-aware branch — matched snapshot → restore from
    snapshot; empty stack → legacy aggregate-bytes rewind;
    bucket-mismatch → `assert!(false)` hard-panic.
  - `cos_queue_drain_all` (`:4548`): add `pop_snapshot_stack.clear()`
    at start to prevent stale-snapshot consumption by subsequent
    `restore_front` (Codex R3 finding 1).
  - `drain_exact_local_items_to_scratch_flow_fair` (`:2611`):
    add `queue.pop_snapshot_stack.pop()` cleanup at the two
    drop sites (`:2649-2658`, `:2663-2672`) before
    `return ExactCoSScratchBuild::Drop`. (Codex R6 finding 1.)
  - `drain_exact_prepared_items_to_scratch_flow_fair` (`:2780`):
    add `queue.pop_snapshot_stack.pop()` cleanup at the two
    drop sites (`:2821-2828`, `:2849-2862`).
  - Test updates: 1 assertion change (`:10811`), comment/docstring
    refreshes on `:11042-:11050`, `:11220-:11272`, `:11663-11665`,
    `:11733`, 1 new test for cross-flow round-pop semantic, 1
    new test for scratch-builder-Drop snapshot-cleanup invariant.

    **Scratch-Drop test design (Codex R7 #5 + R8 #3)**: the
    test must construct a multi-survivor LIFO scenario with the
    drop happening AFTER successful pops. Specifically:
    - Enqueue 3+ items across at least 3 distinct buckets
      (surviving items in X and Y, dropped item in Z, with
      X, Y, Z all distinct).
    - Run the scratch builder; force a drop on the LAST item
      (bucket Z) via a frame-too-big or slice-fail injection.
    - On `Drop` return, the snapshot stack should contain
      snapshots for the surviving items only (X and Y), with
      the orphan (Z) cleaned up by §3.4.
    - Call `restore_..._scratch_to_queue_head_flow_fair`.
    - Assert post-restore (Codex R9 #5 expansion):
      - **State**: `queue_vtime`, `head_finish[X/Y]`,
        `tail_finish[X/Y]`, `flow_bucket_bytes[X/Y]`,
        `active_flow_buckets`, `active_flow_buckets_peak`,
        `flow_rr_buckets` membership all match pre-batch.
      - **Item identity**: each restored bucket's items have
        the same flow keys, byte lengths, and order as
        pre-batch (catches identity-swap regressions).
      - **Item count**: total items in queue == pre-batch
        count; per-bucket item counts == pre-batch.
      - **Stack**: `pop_snapshot_stack.is_empty()`.
      - **Scratch**: `scratch_local_tx.is_empty()` (or
        `scratch_prepared_tx.is_empty()`) after restore.
      - **Free frames** (local builder only): the offset(s)
        the dropped item was about to use are returned to
        `free_tx_frames` (catches frame-leak regressions).
    - Cover both local builder (capacity-fail and slice-fail
      drop branches) and prepared builder (capacity-fail and
      slice-fail). If all four variants in one test is
      infeasible, at minimum cover one local + one prepared
      site, plus one "drained-bucket survivor" + one
      "active-bucket survivor" case.
    - A same-bucket variant would falsely pass even with the
      cleanup omitted, because the orphan's bucket would
      coincidentally match the next push_front target. The
      X≠Y≠Z requirement is load-bearing.

No worker.rs change required — `worker.rs:1859` already uses
`cos_queue_pop_front_no_snapshot`. Under the revised semantics
this path keeps the legacy `vtime += bytes` advance (§3.1, §3.7),
which is harmless for worker teardown because the runtime is
destroyed afterward.

**No supervisor additions (R4 revert)** — see §3.6. The
§3.3 `assert!(false)` propagates to the default Rust panic
handler. No changes to `coordinator.rs` or `worker_runtime.rs`.
Cross-cutting panic-containment work tracked in #925.

**Preexisting MQFQ-correctness bugs (NOT fixed in #913)** —
discovered during code review. Each predates #913 and is
independent of the MQFQ vtime fix:

- **#926** — `demote_prepared_cos_queue_to_local`
  (`tx.rs:5303-5319`) success path drains the queue (vtime +=
  bytes per pop) then re-enqueues via `push_back` (re-anchor
  at vtime). Inflates vtime for items that were never
  transmitted; new flows after demotion can anchor below the
  demoted backlog. Predates #913 (drain_all aggregate-bytes
  and push_back re-anchor formula were both there before).

- **#927** — `cos_queue_push_front` was_empty (drained-bucket)
  snapshot restore loses the dropped item's "virtual service"
  contribution in multi-pop+tail-drop scenarios. Setup:
  bucket A pops A1, bucket C pops, bucket A pops A2 (drains
  A), drop A2. Restoring A1 via was_empty snapshot path sets
  A.head=1000 (snap_1.pre_pop_head), losing A2's commitment.
  A1 then pops before C (head_C=2500) — scheduling
  inversion. Predates #913: the was_empty snapshot restore
  at `cos_queue_push_front` is on master unchanged.

## 6. Test strategy

### 6.1 Unit tests

`cargo test --release` for the userspace-dp crate. Pre-existing
E0063 errors in `BindingCountersSnapshot` test code remain
(verified on master baseline; out of scope for this PR).

### 6.2 New test: round-pop semantic

`mqfq_vtime_does_not_accumulate_across_flows` — see §3.5.
Construct 10 active flows × 5 packets each (1500 B). Pop
one packet from each flow via 10 sequential
`cos_queue_pop_front` calls. Assert:

- New semantics: `queue.queue_vtime == 1500` (each pop sees
  its bucket's first-packet head_finish=1500; `max` never
  advances past the first round).
- Old semantics would have produced `10 × 1500 = 15000`.

This test exists specifically to FAIL under the old
aggregate-bytes implementation and PASS under the
served_finish implementation — i.e., it would have caught
this bug had it existed at the time the original code
landed.

### 6.3 Cluster validation

Deploy to loss userspace cluster. PASS gate:

- Smoke: iperf-b N=8 M=10 60s rep produces valid probe.json.
- Re-run iperf-b same-class matrix (`ELEPHANT_PORT=5202
  MOUSE_CLASS=iperf-b`).
- iperf-b N=8 M=10 mouse p99 should drop materially. Expected
  to land below 50 ms (vs the morning's 323 ms baseline /
  afternoon's 5210 ms — see #912 findings for the variability
  warning).

### 6.4 Throughput sanity

iperf3 -P 128 to iperf-c port 5203 — verify steady-state
throughput unchanged (≥ 15 Gb/s). The vtime change should
not affect throughput; if it does materially, that's a
regression to investigate.

### 6.5 HA failover

`make test-failover` clean — vtime semantics don't touch
session sync or VRRP; no expected interaction.

## 7. Acceptance

### 7.1 Merge gates

- `cargo build --release` clean.
- New unit test passes; existing tests updated to reflect WFQ
  semantics pass.
- Codex hostile plan + code review: PLAN-READY YES + MERGE YES,
  every finding disposed.
- Cluster smoke: valid probe.json on N=0 M=1 and N=8 M=10 at
  iperf-b same-class.
- iperf-c throughput ≥ 15 Gb/s.
- `make test-failover` clean.

### 7.2 Decision threshold (reported, not gating)

- iperf-b N=8 M=10 p99 drops by ≥ 5× vs the pre-change baseline
  on the same cluster session.
- The 2.0× gate ratio at p99(N=128, M=10) / p99(N=0, M=10)
  PASSES. If yes, this single fix closes #911. If still FAIL,
  proceed to candidate (B) #914 (rate-aware admission cap).

## 8. Risks

- **Numerical-coincidence test invariance.** Existing tests
  with single-packet buckets pass under both semantics
  because served_finish numerically equals
  pre_pop_vtime + bytes. New test (§6.2) breaks the
  coincidence and demonstrates the semantic difference.
- **Monotonicity edge cases.** The `max(vtime, served_finish)`
  defends against `served_finish < vtime`, which is reachable
  in one narrow situation even with the revised §3.3 vtime
  restore:
    - **External mutation of `flow_bucket_head_finish_bytes`**
      (e.g. by future code paths that touch finish-time arrays
      outside the pop/push_front pair). None today, but the
      `max` is defensive against future refactors that could
      otherwise make vtime regress.
  In this case the `max` clamping is strictly safer than
  letting vtime go backwards — that would let returning flows
  sweep past established flows (the very bug #785 closed).
- **Rollback invariant violation = catastrophic.** push_front
  expects a matching snapshot whenever the snapshot stack is
  non-empty, per §3.4's orphan-cleanup contract. If that
  contract is violated (a future code path adds a new
  pop+drop site without §3.4 cleanup, or an unknown race
  condition), the §3.3 mismatch handler hard-panics via
  `assert!(false)`.

  **No supervisor in #913 (R4 scope decision)**: the panic
  propagates to the default Rust panic handler, which emits
  to stderr → journald and kills the worker thread. The
  helper process keeps running with one fewer worker — same
  blast radius as any existing `unwrap`/`expect`/`panic!`
  site in `worker_loop`. Recovery: next config change or
  manual daemon restart. See §3.6 for the full scope-decision
  story across 4 rounds of code review (R0 detection-only →
  R1 dispatch-bypass → R2 exit(1) → R3+R4 revert) and #925
  for the cross-cutting reliability work that proper panic
  containment requires.

  Mitigations in scope for THIS PR:

  1. The mismatch is **believed unreachable in current code**
     (§3.4's four scratch-builder cleanups close every known
     orphan source). "Believed unreachable" ≠ "proven
     unreachable" — future code or unknown races could
     re-introduce the panic vector.
  2. **Loud-and-debuggable trade**: hard-panic to journald >
     silent fairness drift. For a believed-unreachable
     invariant violation, this is the correct primitive
     (Codex R5+R6+R8 converged on this).
  3. The blast radius equals every other panic vector in
     `worker_loop` today. Closing the broader gap is #925's
     scope, not #913's.
- **Cluster state variability** (per #912 findings): the same
  master binary measured wildly different mouse p99 across
  the day. Validation needs multiple reps and ideally a
  fresh cluster state before before/after comparison.
- **Compile-time test failures.** Pre-existing E0063 in
  `BindingCountersSnapshot` test code. Verified on master.
  Out of scope; document that the test build is broken
  independently of this change.

## 9. Acceptance checklist

- [ ] Plan reviewed by Codex (hostile); PLAN-READY YES.
- [ ] Implemented; `cargo build --release` clean.
- [ ] New round-pop test passes; existing vtime tests updated.
- [ ] Codex hostile code review: MERGE YES.
- [ ] Deploy to loss cluster; `make test-failover` clean.
- [ ] Smoke: iperf-b N=0 M=1 + N=8 M=10 produce valid probes.
- [ ] iperf-c -P 128 throughput ≥ 15 Gb/s.
- [ ] iperf-b same-class N=8 M=10 mouse p99 drops by ≥ 5×.
- [ ] Findings committed to `docs/pr/913-mqfq-vtime/findings.md`.
- [ ] PR opened, Copilot review addressed, both reviewers clean.

## 10. Codex R1 disposition

R1 returned PLAN-NEEDS-MINOR with three actionable items.
Each is addressed in this revision:

| R1 finding | Disposition | Section |
|------------|-------------|---------|
| (1) No-snapshot restore path (`cos_queue_drain_all` → `cos_queue_push_front`) mutates vtime without reversing it. | Initial fix gated the vtime advance inside `if push_snapshot`. R2 demonstrated this broke the `demote_prepared_cos_queue_to_local` failure-restore round trip; **revised** to keep legacy aggregate-bytes semantics on the no-snapshot path (paired pop/push_front) while applying the new max-based semantics on the hot path only. See §3.1, §3.3, §3.7 and the R2 disposition in §11. | §3.1, §3.3, §3.7 |
| (2) Test-update list missing sites: `tx.rs:10811`, `tx.rs:11042-11050`, `tx.rs:11228-11272`. | Concrete site-by-site disposition table; R2 added `tx.rs:11377` (which now passes unchanged under the revised §3.3). | §3.5 |
| (3) §8 risk: "served_finish < vtime impossible / only due to bugs" overclaim. | Rewritten. R2 found the initial rewrite still incorrect (idle-bucket returning example was wrong by construction); §8 now lists only the genuinely-reachable cases (bucket-mismatch fallback; external mutation). | §8 |

## 11. Codex R2 disposition

R2 returned PLAN-NEEDS-MAJOR with four findings (one numeric
verification — passes — and three real bugs in the prior
revision). All addressed:

| R2 finding | Disposition | Section |
|------------|-------------|---------|
| (1) `cos_queue_drain_all → cos_queue_restore_front` failure restore in `demote_prepared_cos_queue_to_local` (`tx.rs:5208-5217`) is NOT teardown — old aggregate-bytes accidentally made it round-trip neutral, and gating-out vtime mutation broke that. | Revised §3.1 keeps legacy `vtime += bytes` on the `push_snapshot=false` path (used by `drain_all`). Revised §3.3 keeps legacy `vtime -= item_len` on the no-snapshot push_front branch. §3.7 walks the full counterexample under the revised semantics and shows post-restore state matches pre-drain (vtime=5000, head=6000, tail=9500). | §3.1, §3.3, §3.7 |
| (2) Active-bucket push_front not rewinding vtime is not harmless; counterexample with mouse arriving at 1600 instead of 100. Existing test at `tx.rs:11377` (line 11433) explicitly pins this. | Revised §3.3 restores `vtime = snap.pre_pop_queue_vtime` for BOTH was_empty and active-bucket paths when a matching snapshot is present. Test `:11377` passes unchanged. | §3.3, §3.5 |
| (3) Numeric checks for `:10811` (=3000) and `:11050` (=4500) confirmed correct. | No change needed; §3.5 disposition was already accurate. | §3.5 |
| (4) §8 risk language still wrong: "idle bucket returning with small first packet" doesn't actually produce `served_finish < vtime` because enqueue uses `max(tail, vtime) + bytes` so head ≥ vtime by construction. | §8 rewritten to drop the wrong example. Genuinely-reachable cases: bucket-mismatch fallback path (no current caller) and future external-mutation refactors. | §8 |

## 12. Codex R3 disposition

R3 returned PLAN-NEEDS-MAJOR with six findings (one numeric
verification — passes — and five real bugs/missed scope). All
addressed:

| R3 finding | Disposition | Section |
|------------|-------------|---------|
| (1) Stale snapshot cross-talk: `pop_snapshot_stack` is NOT cleared before `cos_queue_drain_all`. Hot-path committed drains leave stale snapshots; subsequent `restore_front` via `push_front` consumes them and corrupts state. | Added `pop_snapshot_stack.clear()` at start of `cos_queue_drain_all` (`tx.rs:4548`). Documented in §3.7 with explicit code excerpt. | §3.7, §5 |
| (2) §3.5 arithmetic correct under "empty stack" condition. | No change needed; condition now enforced by R3-1 fix and R6 scratch-builder cleanup. | §3.7 |
| (3) `:11377` passes unchanged confirmed. | No change. | §3.5 |
| (4) Bucket-mismatch fallback in push_front isn't actually correct (subtracting item_len is not the inverse of X's max-based pop when push_front goes to bucket Y). | R3 fix tightened to debug_assert. R4-R6 found progressively that this was insufficient — final design (R6) makes mismatch believed unreachable in current code via scratch-builder cleanup, with `assert!()` as a defensive tripwire. | §3.3, §3.4 |
| (5) `served_finish < vtime` can arise; existing test `:11713` manually constructs this state. `max` prevents vtime regression but can't repair corrupted head/tail from bad rollback. | §8 acknowledges this; the design relies on `max` clamping for vtime monotonicity, with R3-1/R3-4 closing the head/tail-corruption paths. | §8 |
| (6) §3.4 missed `:11456`, `:11548`, `:11681`, `:11997` — all pin vtime semantics. The cross-bucket test docstring narrative ("5000 → 5900 → 7400") becomes wrong under max semantics. | All four added to §3.5 disposition table. All four pass numerically; `:11681` needs docstring narrative refresh (assertion is fine; trace narrative is wrong). | §3.5 |

## 13. Codex R4 disposition

R4 returned PLAN-NEEDS-MAJOR with one major finding plus several
minor scope confirmations and a wording issue. All addressed:

| R4 finding | Disposition | Section |
|------------|-------------|---------|
| (Major) §3.3 pseudocode pops snapshot before `debug_assert`. In release builds (no `debug_assertions`) a mismatched snapshot is consumed and applied to bucket Y — silent corruption worse than the prior fallback. | R4 introduced peek-then-pop. R5/R6 found this still allowed wrong vtime rewind on mismatch. Final R6 design: mismatch is believed unreachable in current code (via scratch-builder cleanup); `assert!()` panics if it ever fires. | §3.3, §3.4 |
| Drain_all stack-clear sufficiency confirmed. | No change needed; design is correct. | §3.7 |
| Four §3.5 added tests verified pass under revised plan; `:11681` has a SECOND stale comment at line 11733 ("B's head (1400) < A's head (2000)") — actual heads are 1000 and 1600. | Added second narrative-fix note to `:11681` row in §3.5 disposition. | §3.5 |
| `cos_queue_pop_front_no_snapshot` callers verified (only drain_all + worker.rs:1859). | No change needed. | §3.7 |
| §5 incorrectly described worker.rs no-snapshot path as a "strict no-op on queue_vtime"; revised plan keeps legacy `vtime += bytes` there. | Fixed §5 wording: "keeps the legacy `vtime += bytes` advance, harmless for worker teardown because the runtime is destroyed afterward." | §5 |
| Active-bucket head reversal correctness reconfirmed for same-item rollback. | No change needed. | §3.3 |

## 14. Codex R5 disposition

R5 returned PLAN-NEEDS-MAJOR with one finding. Addressed:

| R5 finding | Disposition | Section |
|------------|-------------|---------|
| (Major) Peek-then-pop avoids R4's silent-corruption mode but the mismatch fallback's `vtime -= item_len` is NOT the inverse of the matching pop's `vtime = max(...)`. Release builds still proceed through known-corrupt rollback state, just with a different corruption mode. The "stale snapshots stay on stack until cleared" claim is not a correctness proof. | R5 introduced three-state model with stack-clear-and-skip on mismatch. R6 found this destroys valid outstanding snapshots; superseded by R6's scratch-builder cleanup design. | §3.3, §3.4 |

(Section renumbering: prior §3.4 "Test updates" → §3.5; prior
§3.5 "No-snapshot path" → §3.7. References updated throughout
the body.)

## 15. Codex R6 disposition

R6 returned PLAN-NEEDS-MAJOR with five findings. All addressed:

| R6 finding | Disposition | Section |
|------------|-------------|---------|
| (1) "No current caller can produce mismatch" is FALSE. Scratch builders at `tx.rs:2637/2812` pop items, then drop them on per-item failures (`:2649`, `:2663`, `:2821`, `:2849`); the orphan snapshot stays on the stack and trips the next `push_front` from `restore_..._scratch_to_queue_head`. | New §3.4 "Scratch builder orphan-snapshot cleanup" requires four one-line `queue.pop_snapshot_stack.pop();` additions in the drop paths. After this, mismatch is believed unreachable in current code. §5 files-touched updated. | §3.4 (new), §5 |
| (2) §3.4's "clear stack on mismatch" destroys valid outstanding snapshots for the rest of the rollback batch. | Replaced with `assert!(false)` hard-panic. Combined with R6-1 cleanup, mismatch is believed unreachable in current code so the assert is a defensive tripwire. | §3.3, §3.4 |
| (3) Production mismatch enqueue isn't structurally safe for `was_empty=false` (active bucket). | Moot — R6-2 makes mismatch a hard panic, not a fallback. No production "queue the item" path needed. | §3.3 |
| (4) §3.3 sketch's `return` would leak `local_item_count` and lose the item. | Moot for the same reason — `assert!(false)` panics; control flow never reaches the bucket-restore section. | §3.3 |
| (5) §10-§13 still point at old §3.4 (Test updates) instead of new §3.5; no-snapshot at old §3.5 instead of new §3.7. R4 disposition still says "stale snapshots stay on stack" which contradicts new §3.4. | Disposition tables updated throughout: §10 → §3.5/§3.7 refs; §11 → §3.5/§3.7; §12 → §3.5/§3.7; §13 narrative updated to reflect R5/R6 progression. | §10, §11, §12, §13, §14 |

## 16. Codex R7 + Gemini parallel disposition

R7 returned PLAN-NEEDS-MINOR (six wording fixes). Gemini parallel
review returned PLAN-NEEDS-MAJOR with three MAJOR findings in
categories Codex didn't surface. All addressed:

| Finding | Source | Disposition | Section |
|---------|--------|-------------|---------|
| (R7-1) Hard-panic worker wording: workers are plain spawned threads in `coordinator.rs:696`; no `catch_unwind`, no automatic respawn. "Contained TX outage" wording was misleading. | Codex R7 + Gemini MAJOR #1 (initially escalated, R8 reverted) | **R8 reverted**: graceful recovery (clear-stack + degrade) was found to compound corruption (Codex R8 #1, Gemini R8 #1). For an unreachable invariant, panic is the right primitive — it's loud and debuggable; silent fairness drift is not. Updated wording: workers panic, binding traffic stalls until restart, supervisor work is separate. | §3.3 |
| (R7-2) Scratch-Drop test must use different buckets for successful A and dropped B; same-bucket variant would falsely pass. | Codex R7 finding 5 | §5 test note expanded to require X ≠ Y bucket selection; coverage requirement added (local + prepared at minimum). | §5 |
| (R7-3) plan.md:681 said "Four §3.4 added tests" — should be §3.5. | Codex R7 finding 6 | Fixed. | §13 |
| (R7-4) plan.md:454/586/604 stale "Bucket-mismatch fallback" / "fallback semantics" wording. | Codex R7 finding 7 | All three sites rewritten to describe the §3.4 hard-invariant + §3.3 hard-panic design (graceful-recovery design from R7 was reverted in R8). | §3.7 table, §8 |
| (G-1) `assert!(false)` panic in worker = dataplane outage on 1/N flows. No supervisor mechanism. | Gemini MAJOR #1 (initial), reversed in R8 | R8 finding: graceful recovery introduced silent fairness drift worse than the panic. Reverted to `assert!(false)`. Documented production failure mode honestly: panic, binding stall, daemon restart. Supervisor is future work. The trade chosen: loud-and-debuggable > silent-and-corrupt. | §3.3 |
| (G-2) Plan describes design as "WFQ" but implementation is MQFQ — V(t) advances at served-finish-time, not 1/Σweights. The conflation was misleading; algorithm is sound. | Gemini MAJOR #2 | §1 and §2 rewritten to clarify MQFQ vs canonical WFQ distinction. Algorithm unchanged; wording corrected. | §1, §2 |
| (G-3) `pop_snapshot_stack` is heap Vec; potential cross-NUMA hot-path access on multi-socket systems. | Gemini MAJOR #3 (initial), reversed in R8/R9 | Initial fix overclaimed "worker-local NUMA node". R8 corrected: stack is preallocated to TX_BATCH_SIZE=256 (~8KB fits L1); no realloc on hot path; **NUMA discipline is NOT addressed by this PR** — `coordinator.rs:696` ambient-OS placement, future work. | §3.2 |
| (G-4) `last()` then `pop()` has double bounds check; `pop_if`-style helper would be cleaner. | Gemini MINOR #4 | Acknowledged but not fixed in this PR — the double check is on a cold path (push_front rollback, not the per-packet hot path). Left as a future optimization. | (not fixed) |

## 17. Codex R8 + Gemini R8 disposition

Both R8 reviewers returned PLAN-NEEDS-MAJOR with converging
findings on the graceful-recovery design. R8 reverses two of
the R7 fixes after both reviewers identified that they made
the design worse:

| Finding | Source | Disposition | Section |
|---------|--------|-------------|---------|
| (R8-1) Graceful recovery clears stack → remaining rollback items take aggregate `vtime -= item_len` despite their pops using `max(vtime, served_finish)` → `queue_vtime` can REGRESS below pre-batch frontier → future flows anchor too early. | Codex R8 + Gemini R8 (converged) | **Reverted to `assert!(false)` hard-panic.** For an unreachable invariant violation, loud-and-debuggable > silent-and-corrupt. Documented production failure mode honestly: worker thread panics, binding traffic stalls, daemon restart needed; supervisor work is separate. | §3.3 |
| (R8-2) §3.7 table row inaccurate ("rest re-queues via re-anchor") — items aren't lost, but active buckets use head reversal not re-anchor; all remaining restores get aggregate vtime subtraction despite hot-path max pops. | Codex R8 #2 | Moot after R8-1 revert: row now reads "worker panics; binding stalls". | §3.7 |
| (R8-3) Scratch-Drop test must cover multi-survivor LIFO, not just 1 survivor + 1 drop. Should assert exact post-restore `queue_vtime`, head/tail per bucket, active count, ring membership, empty stack. Cover local + prepared, drained-bucket + active-bucket survivors. | Codex R8 #3 | §5 test design rewritten with full multi-survivor + X≠Y≠Z bucket selection + per-builder coverage. | §5 |
| (R8-4) Recovery introduces fairness regression by allowing vtime to regress; must quantify bound or sacrifice monotonicity explicitly. | Codex R8 #4 | Moot after R8-1 revert: panic preserves monotonicity by definition (worker dies before mutating vtime backward). | §3.3 |
| (R8-5) §3.3 specifies `binding.live.rollback_invariant_violations` counter increment but `cos_queue_push_front` only has `&mut CoSQueueRuntime`; signature/caller plumbing not specified. | Codex R8 blocker | Moot after R8-1 revert: no counter needed. Panic message + journald is the observability mechanism. | §3.3 |
| (R8-6) §5 plan.md:557 still says hard-panic, contradicting the (now-reverted) graceful-recovery design. | Codex R8 blocker | Now consistent: §3.3 and §5 both describe hard-panic. | §3.3, §5 |
| (G-R8-1) Graceful recovery silently induces fairness drift difficult to debug in production. | Gemini R8 #1 (converged with Codex R8-1) | Same disposition as R8-1: revert to panic. | §3.3 |
| (G-R8-2) §3.2 NUMA claim ("worker-local NUMA node") not supported by code — `coordinator.rs:696` uses `thread::Builder::spawn` with no NUMA policy. | Gemini R8 #2 (NEW) | §3.2 rewritten: scoped-down to "preallocated capacity, no realloc, fits L1"; explicitly notes "NUMA discipline is NOT addressed by this PR" and points at `coordinator.rs:696` ambient-OS placement. UMEM 96MB also not NUMA-pinned today; snapshot stack ~8KB (TX_BATCH_SIZE=256, ~32B per entry) is small in comparison. | §3.2 |

## 18. Codex R9 + Gemini R9 disposition

R9 split: Codex returned MAJOR (5 wording cleanups; design
correct, narrative lagged). Gemini returned MINOR (one wording
softening). All addressed:

| Finding | Source | Disposition | Section |
|---------|--------|-------------|---------|
| (R9-1) §8 still describes the rejected graceful-recovery path ("clears stack", "degrades to aggregate", `rollback_invariant_violations` counter). | Codex R9 #1 | §8 rewritten to match §3.3 hard-panic: removed "Bucket-mismatch invariant violation" sub-bullet from "Monotonicity edge cases"; replaced "Rollback correctness" bullet with "Rollback invariant violation = catastrophic" describing panic + journald + believed-unreachable + supervisor-future-work. | §8 |
| (R9-2) §3.2 says TX_BATCH_SIZE=32 / 1KB; actual is 256 / ~8KB per `afxdp.rs:159`. §17 row 824 still has stale "worker-local NUMA node". | Codex R9 #2 | Math fixed (256 entries × ~32B = ~8KB, still fits L1 32-64KB); §17 G-3 row updated to "initial overclaim, R8 corrected"; §17 G-R8-2 row stays accurate. | §3.2, §17 |
| (R9-3) "binding traffic stalls" wording is too narrow — a worker can serve multiple bindings; panic stalls all bindings on that worker. | Codex R9 #3 | §3.3 + §3.7 wording updated: "all bindings served by that worker stall". | §3.3, §3.7 |
| (R9-4) §3.7 row accurate (modulo R9-3 wording fix). | Codex R9 #4 | No change beyond R9-3 wording. | §3.7 |
| (R9-5) Scratch-Drop test design: add asserts on `flow_bucket_bytes`, item identity/order/count, scratch vec empty, free-frame return. | Codex R9 #5 | §5 test design expanded with explicit assertion list grouped into State / Item identity / Item count / Stack / Scratch / Free frames categories. | §5 |
| (G-R9-1) "Truly unreachable" claim too strong; future code or unknown races could re-introduce. Reframe as "catastrophic, believed-unreachable due to X,Y,Z". | Gemini R9 (MINOR) | Replaced all "genuinely unreachable" → "believed unreachable in current code". §8 explicitly says "'believed unreachable' is not the same as 'proven unreachable'" and acknowledges supervisor work as out-of-scope future work. | §3.3, §8 |

## 19. Codex R10 + Gemini R10 disposition

R10: Codex returned MINOR (5 wording residues from R9). Gemini
returned MAJOR (persisting on its earlier supervisor-scope
objection from R8/R9 — not a new finding, a scope disagreement).

| Finding | Source | Disposition | Section |
|---------|--------|-------------|---------|
| (R10-1) plan.md:202 still says "1KB"; should be "~8KB" per the corrected TX_BATCH_SIZE math. | Codex R10 #1 | Fixed. | §3.2 (or near it) |
| (R10-2) plan.md:256/370/387 still have bare/overstrong "unreachable" claims (especially "genuinely unreachable" at line 370). | Codex R10 #2 | All three sites changed to "believed unreachable in current code". | §3.3, §3.4 |
| (R10-3) plan.md:835 still says §3.3 "graceful-recovery design"; contradicts the R8 revert to hard-panic. | Codex R10 #3 | Fixed: row reads "rewritten to describe the §3.4 hard-invariant + §3.3 hard-panic design (graceful-recovery design from R7 was reverted in R8)". | §17 |
| (R10-4) plan.md:695 says `served_finish < vtime` reachable in "two narrow situations", but §8 only lists one. | Codex R10 #4 | Fixed: "two narrow situations" → "one narrow situation" matching the actual content. | §8 |
| (R10-5) plan.md:574 says "at least 2 distinct buckets" but the X/Y/Z constraint requires 3. | Codex R10 #5 | Fixed: "at least 3 distinct buckets (surviving items in X and Y, dropped item in Z, with X, Y, Z all distinct)". | §5 |
| (G-R10-1, persistent) Hard-panic without supervisor is unacceptable production failure mode; supervisor must be in scope. | Gemini R8/R9/R10/R11 (persistent objection) | Initial response: framed as scope disagreement + documented trade-off. **Final response (R12, user decision)**: bundle a MINIMAL panic supervisor (§3.6) into #913 — `catch_unwind` around worker spawn calls + log + dead-flag. Broader supervisor work (respawn, liveness Prometheus, coordinated state recovery, generalized panic handling) tracked in #925. | §3.6 (new), §8 |

## 20. Scope decision: minimal supervisor bundled (R12)

User authorized expanding #913's scope to include a MINIMAL
panic supervisor in response to Gemini's persistent R8-R11
concern. The bundling balances Gemini's reliability argument
against the original scope split:

Scope evolved across R12-R13. Final scope after R13 user
decision is **detection-only**:

| Aspect | Original (R8-R10) | R12 attempt | **Final (R13)** |
|--------|-------------------|-------------|------------------|
| MQFQ vtime fix | ✓ | ✓ | ✓ |
| Scratch-builder orphan cleanup | ✓ | ✓ | ✓ |
| `assert!(false)` invariant tripwire | ✓ | ✓ | ✓ |
| `catch_unwind` wrap on `:696` worker spawn | ✗ | ✓ | ✓ |
| `eprintln!`→journald log on panic catch | ✗ | ✓ | ✓ |
| `dead` AtomicBool flag | ✗ | ✓ | ✓ |
| Coordinator dispatch-bypass (`:333`, `:823`) | ✗ | ✓ | **✗ removed (R13: incomplete; honest detection-only)** |
| Producer-side filter (ha.rs/tx.rs/tunnel.rs ~10 sites) | ✗ | ✗ | ✗ deferred to #925 |
| HA-ack-vs-dead-worker semantics | ✗ | ✗ | ✗ deferred to #925 |
| Automatic worker respawn | ✗ | ✗ | ✗ deferred to #925 |
| Structured logging via slog/tracing | ✗ | ✗ | ✗ deferred to #925 |
| Prometheus liveness metric | ✗ | ✗ | ✗ deferred to #925 |
| Coordinated state recovery | ✗ | ✗ | ✗ deferred to #925 |
| Generalized panic supervisor (UMEM, NIC errors, `:786`, `:833`) | ✗ | ✗ | ✗ deferred to #925 |

GitHub issue #925 tracks all deferred items. The detection-
only supervisor closes the silent-thread-death gap (panic now
gets logged in journald) without
expanding #913 into the multi-PR effort that proper
containment would require. Honest framing: this is detection,
not containment. Operators see the panic, decide to restart;
the dataplane doesn't auto-recover.

## 21. Codex R12 + Gemini R12 disposition

R12: Codex returned MAJOR (5 implementation/design holes in
§3.6 plus wording residues). Gemini returned MAJOR (the
dead-flag is write-only — coordinator must read it to bypass
dead workers). Both reviewers landed real bugs in the
supervisor design, not scope arguments. All addressed:

| Finding | Source | Disposition | Section |
|---------|--------|-------------|---------|
| (G-R12-1) `dead` AtomicBool is write-only — nothing reads it. Coordinator keeps dispatching to dead workers → silent blackhole persists. The "supervisor" is just a logging change. | Gemini R12 | **R12 attempted dispatch-bypass at coordinator sites; R13 found this incomplete (10+ producer sites across coordinator/ha/tx/tunnel). User chose to keep §3.6 as DETECTION-ONLY in #913.** §3.6.2 explicitly states the supervisor doesn't claim containment; producers continue to push to dead-worker queues; commands accumulate without bound (R14: explicit OOM risk acceptance); HA acks time out same as for slow workers. Full containment (producer-side filtering, HA-ack-timeout coordination) deferred to #925. | §3.6.2, §5 |
| (R12-1) §3.6 doesn't actually work for `:786`/`:833` spawns — those are `neigh_monitor_thread`/`local_tunnel_source_loop` without `WorkerRuntimeAtomics`. Plan asserted same `runtime_atomics.dead = true` applies to all three. | Codex R12 #1 | §3.6 scoped explicitly to `:696` only. The other two spawns are documented as out-of-scope and tracked in #925. §5 files-touched updated to reflect this. | §3.6, §5 |
| (R12-2) `runtime_atomics_clone.dead.clone()` invalid — `AtomicBool` is not Clone. `runtime_atomics_clone` is moved into `worker_loop` so supervisor needs a separate Arc clone. `slog::error!` doesn't match this crate (no slog dependency; existing logging is `eprintln!`). | Codex R12 #2 | §3.6.1 rewritten: third Arc clone `runtime_atomics_for_supervisor` created on the coordinator side and captured by the supervisor closure. `eprintln!` instead of `slog::error!`. Concrete `panic_payload_to_string` helper provided. | §3.6.1 |
| (R12-3) `AssertUnwindSafe` justification false — claimed dead-flag check ensures coordinator stops issuing, but no such check existed in the original §3.6 design. | Codex R12 #3 + Gemini R12 | R12 attempted to add coordinator-side flag check; R13 found it incomplete. After R13/R14 detection-only revert, `AssertUnwindSafe` justification rewritten in §3.6.4 to NOT depend on a coordinator-side check — soundness now stems purely from `worker_loop` owning its captures (no cross-thread `&mut` borrows). | §3.6.4 |
| (R12-4) Test design underspecified; log-output assertion needs injectable sink. | Codex R12 #4 | §3.6.4 reframed: drop log-output test (no sink); test `panic_payload_to_string` and `dead.load()` outcome only. Real-`worker_loop` integration test deferred to #925. | §3.6.4 |
| (R12-5) Wording residues: plan.md:272 still says "no catch_unwind", plan.md:822 says "worker dies (no catch_unwind)" before contradicting it, plan.md:523 says "Prometheus alerts can fire on dead_flag" but Prometheus exposure is deferred. | Codex R12 #5 | All three sites updated to reflect §3.6 supervisor: `:272` now says §3.6 catches the panic; `:822` describes §3.6 supervisor flow; `:523` says "operators discover via journald + manual `dead` flag inspection (Prometheus exposure deferred to #925)". | §3.3, §8 |

## 22. Codex R13 + Gemini R13 disposition + scope decision (R13)

R13: both reviewers MAJOR. Codex enumerated 4 implementation
blockers (existing WorkerHandle field duplication, incomplete
dispatch-bypass set across ha.rs/tx.rs/tunnel.rs, non-existent
function name, ~10 enqueue sites missed). Gemini elevated
the same point: dispatch-bypass leaves "gaping hole" for
async/timer/internal worker enqueues; abandoned mid-flight
HA commands cause state desynchronization; `eprintln!` is
inadequate for production observability.

User decision after R13: **scale back to detection-only**.
Full containment requires ~10 enqueue-site changes plus
HA-ack semantics design — 3-5x the implementation work of
the MQFQ vtime fix and overlaps massively with #925.

| Finding | Source | Disposition | Section |
|---------|--------|-------------|---------|
| (R13-1) `WorkerHandle.runtime_atomics` ALREADY EXISTS at `types.rs:183`. Plan said to add it; would duplicate field. | Codex R13 #1 | §5 corrected: reuse existing field; only `WorkerRuntimeAtomics` gets the new `dead` AtomicBool. No `WorkerHandle` change. | §5 |
| (R13-2) Dispatch-bypass set incomplete — ha.rs:41/:97/:165/:303/:359, tx.rs:1129/:1277, tunnel.rs:308 also enqueue commands. `export_owner_rg_sessions` waits for all-worker acks → dead worker = timeout. | Codex R13 #2 + Gemini R13 | **Scope decision: detection-only, no producer-side filtering in #913.** §3.6.2 documents that producers continue pushing to dead-worker queues; commands accumulate without bound (R14 OOM risk acceptance); HA acks time out same as for slow workers (existing HA timeout handling applies). Full filtering deferred to #925. | §3.6.2, §3.6.6, §5 |
| (R13-3) Worker→worker enqueues bypass coordinator entirely; local-tunnel source enqueues at `tunnel.rs:308` from a static Vec captured at spawn time. | Codex R13 #3 | Same disposition as R13-2: detection-only; defer to #925. The honest answer is that proper containment requires either a `WorkerCommandQueue` wrapper struct that bundles queue + dead flag, or per-site dead checks at all 10+ producer sites — neither is in #913 scope. | §3.6.2, §3.6.6 |
| (R13-4) `coordinator.rs:333` is `replay_synced_sessions` taking `BTreeMap<u32, Arc<Mutex<VecDeque<...>>>>`, not WorkerHandles. No runtime_atomics access there. `dispatch_with_worker_queues` is not a real function name. | Codex R13 #4 | Both wrong claims removed: §3.6.2 no longer names that site. Dispatch-bypass is not in this PR. | §3.6.2 |
| (G-R13-1) Mid-flight HA commands "abandoned" causes state desync between active/standby; cascading failures on failover. | Gemini R13 | §3.6.2 acknowledges: HA acks from a dead worker time out the same way they would for a slow worker or partition. HA already has timeout handling. The panic doesn't introduce new failure modes — same blackhole as pre-supervisor (worker dies; commands queue uselessly), just now visibly logged. Recovery (auto-respawn or re-shard) deferred to #925. | §3.6.2 |
| (G-R13-2) `eprintln!` to journald lacks structured context for production alerting. | Gemini R13 | Acknowledged. Structured logging via `slog`/`tracing` deferred to #925. The minimal supervisor uses project-convention `eprintln!`; operators see the panic message + worker_id; alerting can grep journald for the `worker panic` substring. | §3.6.1, §3.6.6 |
| (R13-wording) §5 names `dispatch_with_worker_queues` (no such function); §21 says "three subsections" but §3.6 has four; §20 says "Slog-error log" instead of `eprintln!`; §3.3 says supervisor is "separate larger change" but §3.6 now does part of it. | Codex R13 wording | All four wording sites fixed: §5 reuses existing WorkerHandle field, no fake function name; §21 wording reflects R12's actual disposition history; §20 row says `eprintln!→journald`; §3.3 comment block describes §3.6 detection-only scope and references #925 for containment work. | §3.3, §5, §20, §21 |

## 23. Codex R14 + Gemini R14 disposition

R14: both reviewers MAJOR. Codex enumerated 4 issues (3 real,
1 wording). Gemini converged on 2 of those (unbounded queue,
HA desync) plus a meta-objection that #913 trades a fairness
bug for "catastrophic reliability failure". All addressed:

| Finding | Source | Disposition | Section |
|---------|--------|-------------|---------|
| (R14-1) "Commands accumulate harmlessly" is FALSE — VecDeque has no capacity bound; producers use plain `push_back`; dead worker queue grows until restart or OOM. | Codex R14 #1 + Gemini R14 | §3.6.2 rewritten: "**accumulate without bound** until the daemon restarts" → **accepted unbounded-memory-growth risk in #913**, deferred to #925. R15 refinement: there is no hard upper bound; only an operational expectation (typical control-plane rate ≪ 1 MB/s; minute-scale operator response → ~tens of MB). Pathological producer loops or delayed restart leave growth unbounded. | §3.6.2 |
| (R14-2) HA ack timeout claim verified true (`export_owner_rg_sessions` waits 15s at `ha.rs:175`). | Codex R14 #2 | No change needed; existing claim accurate. | §3.6.2 |
| (R14-3) §3.6 claimed gRPC observability is "automatic" — false. `WorkerRuntimeStatus` has no `dead` field in Rust (`protocol.rs:1043`) or Go (`protocol.go:528`); status mapping at `coordinator.rs:1179` is manual. | Codex R14 #3 | gRPC observability claim **dropped**. §3.6.2 + §3.6.3 now state "operator-visible signal in #913 is the journald log line" emitted by `eprintln!`. Alerting via journald-grep for "worker panic" substring. gRPC `dead` field deferred to #925 along with structured-observability work. | §3.6.2, §3.6.3 |
| (R14-4) Residual dispatch-bypass mentions at §3.3:278, §8:966/:988, §21 contradict detection-only. | Codex R14 #4 | All four sites rewritten to describe detection-only flow without bypass language. §3.3 comment block: "producers continue pushing to dead worker's queue; commands accumulate unbounded until daemon restart". §8 trade-off: "No dispatch-bypass / containment in #913 (deferred to #925)". §21 row: detection-only, no containment claim. | §3.3, §8, §21 |
| (G-R14-1) HA state desync on failover: standby may not see state transitions if dead worker never processed in-flight commands. "Catastrophic reliability failure". | Gemini R14 | §3.6.2 expanded: HA state-consistency risk applies to **any preexisting panic vector** in `worker_loop` (any `unwrap`, `expect`, OOB index, `panic!`), not just the new §3.3 site. **#913 does not introduce a new HA failure mode or larger blast radius** (R15 refinement); it adds one believed-unreachable trigger for the existing worker-panic failure mode. The §3.6 detection adds visibility for ALL panics in `worker_loop`, not just §3.3. Comprehensive HA-ack semantics tracked in #925. | §3.6.2 |
| (G-R14-meta) "Trades a fairness bug for catastrophic reliability failure". | Gemini R14 (meta-objection) | This is a scope-philosophy objection not a new bug. The plan explicitly acknowledges (§3.6.2 + §3.6.6) that #913 does not solve preexisting reliability gaps that affect ALL panic vectors in `worker_loop`. The fairness fix is real and load-bearing for #911. The §3.3 panic site is incremental risk equivalent to existing panic sites. The §3.6 detection is net better than the status quo for ALL panics. Closing the broader reliability gap is significant work tracked in #925. The plan doesn't claim to solve #925. | (no change) |

## 24. Codex R15 + Gemini R15 disposition

R15 split: Codex MINOR (4 wording fixes; design conceptually sound).
Gemini MAJOR purely on persistent scope-philosophy ("trade is
unacceptable", "fragile anti-pattern", "disingenuous framing").

| Finding | Source | Disposition | Section |
|---------|--------|-------------|---------|
| (R15-1) "Bounding worst-case OOM growth to tens of MB" overclaims a hard bound; pathological producer loops or delayed restart are unbounded. | Codex R15 #1 | §3.6.2 rewritten: "**no hard upper bound** on accumulated memory; only an operational expectation". Tens-of-MB figure presented as a typical operator-response scenario, not a worst-case bound. §23 R14-1 row updated similarly. | §3.6.2, §23 |
| (R15-2) "Does not change this risk surface" overclaimed — a new panic site is technically a new trigger surface, even if the consequence is identical to existing panic sites. | Codex R15 #2 | §3.6.2 + §23 G-R14-1 row rewritten: "#913 does not introduce a new HA failure mode or larger blast radius; it adds one believed-unreachable trigger for the existing worker-panic failure mode". | §3.6.2, §23 |
| (R15-3) Residual wording: panic surfaces in "journald and the gRPC status RPC" (false after R14 dropped gRPC); §22 row says "harmlessly"; §22 row says "coordinator-side flag check" exists; §20 says "minimum panic containment" (should be "detection"). | Codex R15 #3 | All five sites fixed: §3.3 panic comment now says "(gRPC observability deferred to #925)"; §20 says "detection"; §22 rows scrubbed of "harmlessly" + "coordinator-side flag check". | §3.3, §20, §22 |
| (R15-4) Nothing else rises to MAJOR; design is sound. | Codex R15 #4 | No action; this is the convergence signal. | n/a |
| (G-R15-meta, persistent) "Operator-response time is fragile anti-pattern"; "HA framing disingenuous"; "trading fairness bug for silent resource bomb is unacceptable trade-off". | Gemini R15 (persistent meta-objection) | **Final scope-philosophy disagreement, not a new bug.** Gemini's R8/R10/R11/R12/R13/R14/R15 chain has consistently called for full supervisor (catch_unwind + producer-side bypass + bounded queues + structured logging + gRPC liveness + HA-ack semantics + auto-respawn). User decision after R13 was explicit: that's #925's scope, not #913's. Plan acknowledges Gemini's concerns are valid but documents them as deferred. Convergence requirement: Codex MERGE YES + user-acknowledged Gemini scope objection. R15 satisfies Codex (PLAN-NEEDS-MINOR closes after the wording fixes); Gemini's MAJOR is the documented disagreement. | (no change) |
