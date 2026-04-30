# #956 Phase 7: extract cos/queue_service.rs from tx.rs

Plan v1 — 2026-04-30. Continues #956. Phases 1-6 merged at PRs
#976-#981.

## Goal

Move the CoS dispatch / drain / service-path subsystem from tx.rs
into `userspace-dp/src/afxdp/cos/queue_service.rs`. This is the
largest move of the campaign (~1100 LOC) and brings together:

- The 3 dispatch enums (`CoSBatch`, `CoSServicePhase`,
  `ExactCoSQueueKind`).
- The select/dispatch entry points
  (`drain_shaped_tx`, `select_cos_guarantee_batch` +
  `_with_fast_path`, `select_exact_cos_guarantee_queue_with_fast_path`,
  `select_cos_surplus_batch`, `select_nonexact_cos_guarantee_batch`).
- The service-direct paths (`service_exact_guarantee_queue_direct` +
  `_with_info`, `service_exact_local_queue_direct` + `_flow_fair`,
  `service_exact_prepared_queue_direct` + `_flow_fair`).
- The batch-construction primitive (`build_cos_batch_from_queue` —
  deferred from Phase 6 because it uses the dispatch enums and
  mutates queue state).

## Move list (12 fns + 3 enums)

| Item | Line | Visibility | Production callers |
|---|---|---|---|
| `enum CoSServicePhase` | 771 | private | dispatch internals |
| `enum CoSBatch` | 776 | private | dispatch internals |
| `enum ExactCoSQueueKind` | 792 | private | dispatch internals |
| `drain_shaped_tx` | 1437 | private | tx.rs (6 sites) + worker.rs:1 |
| `service_exact_guarantee_queue_direct` | 1536 | private | tx.rs |
| `service_exact_guarantee_queue_direct_with_info` | 1560 | private | tx.rs |
| `select_cos_guarantee_batch` | 1612 | private | tx.rs (production) + tests |
| `select_cos_guarantee_batch_with_fast_path` | 1626 | `#[cfg(test)]` | tests only |
| `select_exact_cos_guarantee_queue_with_fast_path` | 1717 | private | tx.rs |
| `select_nonexact_cos_guarantee_batch` | 1814 | private | tx.rs |
| `select_cos_surplus_batch` | 1876 | private | tx.rs |
| `service_exact_local_queue_direct` | 1932 | private | tx.rs |
| `service_exact_local_queue_direct_flow_fair` | 2091 | private | tx.rs |
| `service_exact_prepared_queue_direct` | 2240 | private | tx.rs |
| `service_exact_prepared_queue_direct_flow_fair` | 2395 | private | tx.rs |
| `build_cos_batch_from_queue` | 3231 | private | dispatch internals |

(Codex round-1 verifies the call-site classification — same
`#[cfg(test)]` selector trap as Phase 4-6. Items with at-least-one
non-test caller in tx.rs become `pub(in crate::afxdp)`; pure-test
items go cfg-gated.)

## Deferred to a future TX-completion phase

These were also flagged for Phase 7 scope review but architecturally
belong to TX-completion (post-send result reconciliation), not the
service-dispatch path:

- `apply_cos_send_result` (tx.rs:4635)
- `apply_cos_prepared_result` (tx.rs:4696)
- `apply_direct_exact_send_result` (tx.rs:3171)
- `apply_direct_exact_prepared_result` (verify exists)
- `prime_cos_root_for_service` (tx.rs:1505)
- `advance_cos_timer_wheel` + timer helpers + restore helpers

Phase 7 keeps these in tx.rs. Since the moving service paths CALL
some of them (e.g., `service_exact_local_queue_direct` calls
`apply_cos_send_result`), the move list creates a **back-edge**
`cos/queue_service.rs -> tx::apply_cos_send_result` etc. That's
explicit forward-debt cleaned up by the eventual TX-completion
phase. Visibility bumped to `pub(in crate::afxdp)` for the back-
referenced items.

## Approach

Visibility:
- Items with cross-module production callers: `pub(in crate::afxdp)`.
- `select_cos_guarantee_batch_with_fast_path` is already
  `#[cfg(test)]` in source — preserve as cfg-gated.
- Enums get `pub(in crate::afxdp)` so they can be re-exported via
  cos/mod.rs and used by the moving fns' signatures.

`#[inline]` per the Phase 4-6 lesson:
- `drain_shaped_tx` is the per-poll-cycle entry point — preserve
  any existing `#[inline]`.
- The select_* variants and service_*_direct fns fire per drain
  iteration — they sit on the per-byte-batch hot path; preserve
  existing `#[inline]` and add where the source lacked it on
  per-byte fns.
- `build_cos_batch_from_queue` is per-batch-build hot path —
  needs `#[inline]`.

`#[inline]` decisions are subject to source verification (Codex
round-1 will list which fns currently carry `#[inline]` and which
need it added).

## Imports for cos/queue_service.rs

The moving fns reach into many existing cos/* + tx items. Expected
import surface (Codex round-1 verifies completeness):

```rust
use std::collections::VecDeque;

use crate::afxdp::types::{
    BindingWorker, // service_*_direct mutates the binding
    CoSInterfaceConfig, CoSInterfaceRuntime, CoSPendingTxItem,
    CoSQueueRuntime, ForwardingState, PreparedTxRequest, TxRequest,
    WorkerCoSInterfaceFastPath, WorkerCoSQueueFastPath,
    // plus drop counter / timer / batch-state types
};
use crate::afxdp::worker::BindingWorker;
use crate::afxdp::{TX_BATCH_SIZE, /* ring/frame helpers */};
use super::admission::{
    apply_cos_admission_ecn_policy, cos_flow_aware_buffer_limit,
    cos_queue_flow_share_limit,
};
use super::flow_hash::{cos_flow_bucket_index, cos_item_flow_key};
use super::queue_ops::{
    cos_item_len, cos_queue_clear_orphan_snapshot_after_drop,
    cos_queue_drain_all, cos_queue_front, cos_queue_is_empty,
    cos_queue_pop_front, cos_queue_pop_front_no_snapshot,
    cos_queue_push_back, cos_queue_push_front,
    cos_queue_restore_front, cos_queue_v_min_consume_suspension,
    cos_queue_v_min_continue, publish_committed_queue_vtime,
};
use super::token_bucket::{
    cos_refill_ns_until, maybe_top_up_cos_queue_lease,
    maybe_top_up_cos_root_lease, refill_cos_tokens,
    COS_MIN_BURST_BYTES,
};
// Back-edges to tx.rs (deferred TX-completion phase will resolve):
use crate::afxdp::tx::{
    apply_cos_send_result, apply_cos_prepared_result,
    apply_direct_exact_send_result, prime_cos_root_for_service,
    advance_cos_timer_wheel,
    // restore helpers if used directly
};
```

## cos/mod.rs additions

```rust
pub(super) mod queue_service;

pub(super) use queue_service::{
    drain_shaped_tx,
    // any other items production tx.rs calls; rest stay
    // file-private inside queue_service.rs.
};
```

## tx.rs changes

- Remove the 12 fn definitions + 3 enum definitions.
- Bump visibility on the back-referenced TX-completion fns to
  `pub(in crate::afxdp)`:
  - `apply_cos_send_result`, `apply_cos_prepared_result`,
    `apply_direct_exact_send_result`,
    `prime_cos_root_for_service`, `advance_cos_timer_wheel`.
- Add `use super::cos::drain_shaped_tx;` (and any other production
  re-exports the move list determines).

## Files touched

- **NEW** `userspace-dp/src/afxdp/cos/queue_service.rs`: ~1100 LOC.
- `userspace-dp/src/afxdp/cos/mod.rs`: register module + re-exports.
- `userspace-dp/src/afxdp/tx.rs`: -1100 LOC; bump visibility on
  ~5 helpers; extend cos:: imports.
- `userspace-dp/src/afxdp/worker.rs`: extend cos:: import for
  `drain_shaped_tx` if not already reached via glob.

## Risk

**High.** Largest move yet (~1100 LOC, 12 fns + 3 enums). Touches
the absolute hot path: every TX byte goes through `drain_shaped_tx
-> select_cos_*_batch -> service_exact_*_queue_direct -> push/pop`.

Risks:
- **Hot-path inline preservation.** Phase 4-6 lesson: `pub(in
  crate::afxdp)` + `#[inline]` preserves cross-module inlining;
  losing either causes regression. Verify the move keeps every
  source `#[inline]` and adds where needed.
- **Back-edges.** Multiple `cos/queue_service -> tx` edges for
  TX-completion helpers. Documented as forward-debt; not a
  release-build correctness concern.
- **Enum visibility.** Moving the enums forces rethinking pattern-
  match exhaustiveness checks if any tx.rs comment-only references
  remain.
- **Test surface.** ~30+ test sites in `tx::tests` exercise these
  fns; cfg-gated re-exports must cover everything they reach.

The move pattern itself is the same as Phases 1-6: pub(in
crate::afxdp) + cos/mod.rs re-exports + tests stay in tx::tests.

## Acceptance

- `cargo build --bins` clean.
- `cargo test --bins` 865/0/2 baseline.
- Cluster smoke per the standard 7-class iperf3 + failover.
- Both reviewers (Codex hostile + Gemini adversarial) sign off.
