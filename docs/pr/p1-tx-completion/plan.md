# P1: extract cos/tx_completion.rs from tx.rs

Plan v3 — 2026-04-30. First PR after #956's 8-phase cos/ submodule
decomposition merged at PR #983.

## v3 changelog vs v2 (from Codex round-2)

- R2-F1 [BLOCKER]: queue_service.rs imports **10** moving symbols from
  `crate::afxdp::tx` (lines 59-65), not 1. v3 spells out the full
  migration: switch all 10 to `super::tx_completion::{...}` (or via
  `super::` re-export). v2 understated this; "1 fewer import" wording
  removed.
- R2-F2 [BLOCKER]: `cos/builders.rs` imports `cos_tick_for_ns` from
  `crate::afxdp::tx` (builders.rs:33). v3 adds builders.rs to
  files-touched and the import migration list.
- R2-F3 [BLOCKER]: `tx_completion.rs` import block was source-inaccurate.
  v3 reconciles against actual moved-fn bodies:
  - Add `cos_queue_is_empty`, `cos_queue_push_front` to queue_ops imports.
  - Use `CoSServicePhase` (queue_service) — NOT `ParkReason`.
  - Add `maybe_top_up_cos_root_lease`, `release_cos_root_lease`,
    `park_cos_queue`, `count_park_reason` from queue_service.
- R2-F4 [BLOCKER]: tx.rs always-on `use super::cos::{...}` block only
  needs `mark_cos_queue_runnable` (the one production caller outside
  the move set, at tx.rs:2080). All other moved items are reached only
  by tests at tx.rs:10533-10737 → goes in a `#[cfg(test)] use
  super::cos::{...}` block. Avoids unused-import warnings on
  `cargo build --bins`.
- R2-F5 [MINOR]: visibility count fixed — 14 items are
  `pub(in crate::afxdp)`, not 10.

## v2 changelog vs v1 (preserved from round-1)

- R1-1: `mark_cos_queue_runnable` was classified file-private but
  tx::enqueue_cos_item at tx.rs:2080 calls it (NOT moving) — v2 makes
  it `pub(in crate::afxdp)`.
- R1-2: `normalize_cos_queue_state` was classified file-private but
  `refresh_cos_interface_activity` AND test at tx.rs:10612 reach it —
  v2 makes it `pub(in crate::afxdp)`.
- R1-3: **`refresh_cos_interface_activity` joins the move list.** All
  3 tx.rs callers (1180/2217/2282) are in moving fns; cos/queue_service.rs
  has 13 callers. Moving it kills the largest cos→tx back-edge.
- R1-4: Test usages of moved items at tx.rs:10533/10537/10558/10562/
  10612/10673/10737 — bumped 4 items to `pub(in crate::afxdp)` AND
  added a tx.rs cos:: import line so tests resolve them.
- R1-7/R1-8: `#[inline]` list reconciled. Imports corrected —
  `BindingWorker` lives in `worker.rs:13`, `CoSServicePhase` in
  `cos/queue_service.rs`, `std::sync::atomic::Ordering` added.

## Goal

Move the TX-completion + timer-wheel cluster from tx.rs into
`userspace-dp/src/afxdp/cos/tx_completion.rs`. After this PR:
- Every cos→tx back-edge introduced by #956 Phases 6/7/8 is closed.
- `cos/queue_service.rs` no longer imports any of the 10 moving symbols
  from `crate::afxdp::tx`.
- `cos/builders.rs` no longer imports `cos_tick_for_ns` from tx.

Remaining cos→tx back-edges after P1 are XSK-ring / worker-binding /
prepared-frame primitives (transmit_*, reap_tx_completions, maybe_wake_tx,
recycle_*), slated for #984 (afxdp/tx/ split).

## Move list (19 fns + 2 constants)

### Timer wheel cluster (~150 LOC)

| Item | Line | Visibility after move |
|---|---|---|
| `COS_TIMER_WHEEL_TICK_NS` | 1202 | `pub(in crate::afxdp)` (tests at 10533/10537/10558/10562) |
| `COS_TIMER_WHEEL_L0_HORIZON_TICKS` | 1207 | file-private |
| `cos_tick_for_ns` | 1266 | `pub(in crate::afxdp)` |
| `cos_timer_wheel_level_and_slot` | 1270 | `pub(in crate::afxdp)` |
| `wake_cos_queue` | 1292 | file-private |
| `count_tx_ring_full_submit_stall` | 1322 | `pub(in crate::afxdp)` |
| `rearm_cos_queue` | 1341 | file-private |
| `mark_cos_queue_runnable` | 1345 | `pub(in crate::afxdp)` (called by `enqueue_cos_item` tx.rs:2080) |
| `normalize_cos_queue_state` | 1351 | `pub(in crate::afxdp)` (test at 10612) |
| `advance_cos_timer_wheel` | 1370 | `pub(in crate::afxdp)` |
| `cascade_cos_timer_wheel_level1` | 1381 | file-private |
| `wake_due_cos_timer_slot` | 1400 | file-private |

### TX-completion cluster (~450 LOC)

| Item | Line | Visibility after move |
|---|---|---|
| `prime_cos_root_for_service` | 1127 | `pub(in crate::afxdp)` |
| `apply_direct_exact_send_result` | 1142 | `pub(in crate::afxdp)` |
| `refresh_cos_interface_activity` | 2114 | `pub(in crate::afxdp)` |
| `apply_cos_send_result` | 2159 | `pub(in crate::afxdp)` |
| `apply_cos_prepared_result` | 2220 | `pub(in crate::afxdp)` |
| `restore_cos_local_items_inner` | 2285 | `pub(in crate::afxdp)` (test at 10673) |
| `restore_cos_prepared_items_inner` | 2300 | `pub(in crate::afxdp)` (test at 10737) |

### Total

**~600 LOC** moved. After this PR, `tx.rs` size drops from 13731 → ~13130.

## Visibility rules — source-verified (14 + 6)

`pub(in crate::afxdp)` (14 items) — required because they have callers
outside `cos/tx_completion.rs`:

Constants (1):
- `COS_TIMER_WHEEL_TICK_NS` — tests at tx.rs:10533, 10537, 10558, 10562

Functions (13):
- 11 with cos/queue_service.rs callers (most named in queue_service.rs:59-65):
  `prime_cos_root_for_service`, `apply_direct_exact_send_result`,
  `apply_cos_send_result`, `apply_cos_prepared_result`,
  `cos_tick_for_ns`, `cos_timer_wheel_level_and_slot`,
  `count_tx_ring_full_submit_stall`, `refresh_cos_interface_activity`,
  `restore_cos_local_items_inner`, `restore_cos_prepared_items_inner`,
  `advance_cos_timer_wheel`.
- 1 with cos/builders.rs caller: `cos_tick_for_ns` (already counted).
- 1 with tx.rs production caller: `mark_cos_queue_runnable` (tx.rs:2080).
- 1 with test caller: `normalize_cos_queue_state` (tx.rs:10612).

File-private (5 fns + 1 const) — only callers are co-located in the
move set:
- `wake_cos_queue` (tx.rs:1305 inside cos_tick_for_ns area, 1419 inside
  wake_due_cos_timer_slot — both moving).
- `rearm_cos_queue` (tx.rs:1396 inside cascade, 1422 inside wake_due —
  both moving).
- `cascade_cos_timer_wheel_level1` (tx.rs:1375 inside advance_cos_timer_wheel).
- `wake_due_cos_timer_slot` (tx.rs:1377 inside advance_cos_timer_wheel).
- `COS_TIMER_WHEEL_L0_HORIZON_TICKS`.

`COS_TIMER_WHEEL_L0_SLOTS` / `_L1_SLOTS` (referenced by
`cos_timer_wheel_level_and_slot` and `cascade_cos_timer_wheel_level1`)
already live in `afxdp/types.rs` as `pub(super)` — reachable from
`cos/*` via the existing pattern.

## #[inline] adds — source-verified list

Hot-path additions for cross-module inlining (per Phase 4-8 lesson):
- `cos_tick_for_ns`, `cos_timer_wheel_level_and_slot`,
  `mark_cos_queue_runnable`, `normalize_cos_queue_state`,
  `count_tx_ring_full_submit_stall` — already short, single-purpose.
- `prime_cos_root_for_service`, `apply_direct_exact_send_result`,
  `apply_cos_send_result`, `apply_cos_prepared_result`,
  `advance_cos_timer_wheel`, `restore_cos_local_items_inner`,
  `restore_cos_prepared_items_inner` — per-batch in drain loop.
- `refresh_cos_interface_activity` — fires every per-batch helper, so
  must inline across the cos→cos boundary too.

Not inlined (off per-byte path; preserve existing attributes):
- `wake_cos_queue`, `rearm_cos_queue`,
  `cascade_cos_timer_wheel_level1`, `wake_due_cos_timer_slot`.

(Round-3 reviewer: verify which of these already carry `#[inline]` and
preserve them — never silently downgrade.)

## Imports for cos/tx_completion.rs (source-verified)

Reconciled against the moved-fn bodies (tx.rs:1127-1422, 2114-2310):

```rust
use std::collections::VecDeque;
use std::sync::atomic::Ordering;

use crate::afxdp::types::{
    CoSInterfaceRuntime, CoSPendingTxItem, CoSQueueRuntime,
    CoSTimerWheelRuntime, PreparedTxRequest, PreparedTxRecycle,
    TxRequest, COS_TIMER_WHEEL_L0_SLOTS, COS_TIMER_WHEEL_L1_SLOTS,
};
use crate::afxdp::worker::BindingWorker;     // worker.rs:13

use super::queue_ops::{
    cos_item_len, cos_queue_clear_orphan_snapshot_after_drop,
    cos_queue_drain_all, cos_queue_is_empty, cos_queue_pop_front,
    cos_queue_push_back, cos_queue_push_front, cos_queue_restore_front,
    publish_committed_queue_vtime,
};
use super::queue_service::{
    count_park_reason, maybe_top_up_cos_root_lease, park_cos_queue,
    release_cos_root_lease, CoSServicePhase, ParkReason,
};

// Back-edges remaining to tx.rs (slated for #984 — afxdp/tx/ split):
use crate::afxdp::tx::{
    maybe_wake_tx, reap_tx_completions, recycle_cancelled_prepared_offset,
    recycle_prepared_immediately, transmit_batch, transmit_prepared_queue,
};
```

(Round-3 reviewers: verify the exact list against the moved bodies
once written; this is the upper bound. Unused imports trigger build
warnings.)

## cos/queue_service.rs import migration

Source today (queue_service.rs:59-65):
```rust
use crate::afxdp::tx::{
    apply_cos_prepared_result, apply_cos_send_result,
    apply_direct_exact_send_result, cos_queue_dscp_rewrite, cos_tick_for_ns,
    cos_timer_wheel_level_and_slot, count_tx_ring_full_submit_stall, maybe_wake_tx,
    prime_cos_root_for_service, reap_tx_completions, recycle_cancelled_prepared_offset,
    refresh_cos_interface_activity, remember_prepared_recycle, restore_cos_local_items_inner,
    restore_cos_prepared_items_inner, stamp_submits, transmit_batch, transmit_prepared_queue,
    TxError, COS_GUARANTEE_QUANTUM_MAX_BYTES, COS_GUARANTEE_QUANTUM_MIN_BYTES,
    COS_GUARANTEE_VISIT_NS, COS_SURPLUS_ROUND_QUANTUM_BYTES,
};
```

After P1: split into two `use` blocks. The 10 moved symbols come from
`super::tx_completion` (or `super::` via cos/mod.rs re-export); the
unmoved 8 stay on `crate::afxdp::tx`:

```rust
use super::tx_completion::{
    apply_cos_prepared_result, apply_cos_send_result,
    apply_direct_exact_send_result, cos_tick_for_ns,
    cos_timer_wheel_level_and_slot, count_tx_ring_full_submit_stall,
    prime_cos_root_for_service, refresh_cos_interface_activity,
    restore_cos_local_items_inner, restore_cos_prepared_items_inner,
};
use crate::afxdp::tx::{
    cos_queue_dscp_rewrite, maybe_wake_tx, reap_tx_completions,
    recycle_cancelled_prepared_offset, remember_prepared_recycle,
    stamp_submits, transmit_batch, transmit_prepared_queue,
    TxError, COS_GUARANTEE_QUANTUM_MAX_BYTES, COS_GUARANTEE_QUANTUM_MIN_BYTES,
    COS_GUARANTEE_VISIT_NS, COS_SURPLUS_ROUND_QUANTUM_BYTES,
};
```

(`advance_cos_timer_wheel` is moved but is NOT in queue_service.rs's
current import list — it's reached via tx.rs. After move, it's reached
via `super::tx_completion::advance_cos_timer_wheel` if needed in
queue_service or via cos/mod.rs re-export.)

## cos/builders.rs import migration

Source today (builders.rs:33):
```rust
use crate::afxdp::tx::cos_tick_for_ns;
```

After P1:
```rust
use super::tx_completion::cos_tick_for_ns;
```

The "One back-edge" comment block at builders.rs:14-19 must be updated
or removed — that back-edge is now closed.

## cos/mod.rs additions

```rust
pub(super) mod tx_completion;

pub(in crate::afxdp) use tx_completion::{
    advance_cos_timer_wheel, apply_cos_prepared_result, apply_cos_send_result,
    apply_direct_exact_send_result, cos_tick_for_ns, cos_timer_wheel_level_and_slot,
    count_tx_ring_full_submit_stall, mark_cos_queue_runnable,
    normalize_cos_queue_state, prime_cos_root_for_service,
    refresh_cos_interface_activity, restore_cos_local_items_inner,
    restore_cos_prepared_items_inner, COS_TIMER_WHEEL_TICK_NS,
};
```

(Re-export visibility matches the items themselves: anything
`pub(in crate::afxdp)` in tx_completion.rs gets the same re-export
visibility from cos/mod.rs. File-private items are NOT re-exported.)

## tx.rs changes

1. Remove the 19 fn definitions + 2 constants.
2. Remove the Phase-6 visibility-bump comment block above
   `cos_tick_for_ns` (will not exist post-move).
3. **Always-on import** (cos:: block at tx.rs:1227 / 1240) — add ONLY
   the production caller's symbol:

   ```rust
   use super::cos::mark_cos_queue_runnable;
   ```

   This is the only moved symbol used outside the `mod tests` block —
   `enqueue_cos_item` at tx.rs:2080 calls it.

4. **Test-only import block** — added next to `mod tests` (around
   tx.rs:2907):

   ```rust
   #[cfg(test)]
   use super::cos::{
       advance_cos_timer_wheel, normalize_cos_queue_state,
       restore_cos_local_items_inner, restore_cos_prepared_items_inner,
       COS_TIMER_WHEEL_TICK_NS,
   };
   ```

   Or equivalently, add these to the existing `#[cfg(test)]` block
   inside `mod tests { use super::*; … }`. Either pattern resolves
   `mod tests` calls at tx.rs:10533, 10537, 10558, 10562, 10612,
   10673, 10737 without leaking unused imports into release builds.

(Splitting always-on vs cfg-test imports avoids `cargo build --bins`
unused-import warnings — see Acceptance section.)

## Back-edges remaining — explicit, scoped to #984

These are NOT in P1's scope. They stay because they're XSK-ring /
worker-binding / prepared-frame primitives owned by `tx::*` until the
afxdp/tx/ module split (#984). After P1's queue_service.rs migration,
the remaining cos→tx imports in queue_service.rs and cross_binding.rs
are:

`cos/queue_service.rs` (the 8 unmoved symbols + 4 constants):
- `cos_queue_dscp_rewrite` (tx.rs:1966)
- `maybe_wake_tx` (tx.rs:2808)
- `reap_tx_completions`
- `recycle_cancelled_prepared_offset`
- `remember_prepared_recycle`
- `stamp_submits`
- `transmit_batch`, `transmit_prepared_queue`
- `TxError`
- guarantee/quantum constants (`COS_GUARANTEE_VISIT_NS`,
  `COS_GUARANTEE_QUANTUM_MAX_BYTES`, `COS_GUARANTEE_QUANTUM_MIN_BYTES`,
  `COS_SURPLUS_ROUND_QUANTUM_BYTES`)

`cos/cross_binding.rs:30`:
- `recycle_prepared_immediately` (tx.rs:2375)

P1 does NOT claim "every back-edge resolved" — only "every back-edge
introduced by #956 Phases 6/7/8 closed."

## Files touched

- **NEW** `userspace-dp/src/afxdp/cos/tx_completion.rs`: ~650 LOC
  (~600 moved + ~50 lines header/imports/notes).
- `userspace-dp/src/afxdp/cos/mod.rs`: register module + re-exports.
- `userspace-dp/src/afxdp/cos/queue_service.rs`: split tx import block
  (10 symbols → super::tx_completion::, 8 stay on crate::afxdp::tx).
- `userspace-dp/src/afxdp/cos/builders.rs`: switch single
  `cos_tick_for_ns` import; update comment block.
- `userspace-dp/src/afxdp/tx.rs`: −600 LOC; one always-on cos:: import,
  one test-only cos:: import block.

## Tests

No new tests required — pure structural refactor. Existing
`tx::tests` callers (tx.rs:10533, 10537, 10558, 10562, 10612, 10673,
10737) reach moved items via the test-only `#[cfg(test)] use super::cos::{...}`
block in tx.rs. The cos/mod.rs re-export chain backs that import.

## Risk

**Low-medium.** ~600 LOC. Hot-path concerns:

- `apply_cos_send_result` / `apply_cos_prepared_result` /
  `refresh_cos_interface_activity` fire per batch. Cross-module
  `#[inline]` preserves the inlining boundary per Phase 4-8 lesson.
- `cos_tick_for_ns` is a one-liner; cross-module move + `#[inline]`
  is free.
- Timer-wheel functions (`advance_cos_timer_wheel`,
  `cascade_*_level1`, `wake_due_*`) fire on each drain cycle but only
  hit the slow path when timer slots have queued queues. No per-byte
  overhead concern.

Atomic ordering: `apply_cos_send_result` advances queue state and
calls `publish_committed_queue_vtime` (cos/queue_ops.rs) — that fn's
Release ordering is preserved by the move (already-extracted
publish_* doesn't change). `Ordering::Release` / `Ordering::Acquire`
explicitly imported from `std::sync::atomic`.

After this PR, every `pub(in crate::afxdp)` visibility bump from
Phases 6/7/8 except those tied to XSK-ring helpers (#984 scope) is
cleaned up.

## Acceptance

- `cargo build --bins` clean (no new unused-import warnings — F4
  always-on/test-only split prevents warnings on test-only items).
- `cargo test --bins` 865/0/2 (current rolling baseline).
- Cluster smoke: `cluster-setup.sh deploy`, `apply-cos-config.sh`,
  per-CoS-class iperf3 (all 7 classes 5201-5207), failover (RG1
  cycled twice, ≥95% intervals ≥3 Gbps, 0 zero-bps).
- **Triadic plan + impl review**: Codex + Gemini converge
  PLAN-READY/IMPL-READY with NO new findings on the cross-reviews.
- Copilot review on the PR addressed.

## After P1

Stage 2 of the long sequence: #984 — afxdp/tx/ module
(P2a stats.rs, P2b rings.rs, P2c dispatch.rs, P2d collapse tx.rs).
