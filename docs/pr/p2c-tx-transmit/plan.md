# P2c: extract afxdp/tx/transmit.rs from tx/mod.rs

Plan v1 — 2026-04-30. Stage 2 step 3 of the long sequence after #992
(P2b: tx/rings.rs) merged at master `e7d66795`.

## Goal

Extract the **transmit + recycle + dscp-rewrite** cluster from
`tx/mod.rs` into a sibling `tx/transmit.rs`. This is the third carve
of `tx/` after stats.rs and rings.rs. The two giant drain functions
(`drain_pending_tx`, `drain_pending_tx_local_owner`, ~1.2K LOC
combined) and their backpressure helpers stay for a separate later PR
(P2c2 or P2d).

## Why this scope

The transmit + recycle path is a coherent unit:
- `transmit_batch` / `transmit_prepared_batch` / `transmit_prepared_queue`
  push descriptors into the XSK TX ring via `device.tx().insert(...)`
  + `commit()`. They're the actual ring-submit primitives (the rings
  module owns completion + fill, transmit owns submit).
- `recycle_cancelled_prepared_offset`, `recycle_prepared_immediately`,
  `remember_prepared_recycle` handle the prepared-frame cleanup paths
  (hand-off back to free_tx_frames or fill ring on cancel/drop).
- `cos_queue_dscp_rewrite` is the per-batch DSCP-rewrite helper used
  by both transmit_batch and the drain path.
- `TxError` enum is the error type returned by transmit_*.

Drains reference these but are themselves a separate concern (CoS
scheduling decisions, cross-worker scheduling), so leaving them in
tx/mod.rs and importing transmit_* from `super::transmit::*` is clean.

## Move list (7 fns + 1 enum, ~750 LOC)

| Item | Line (post-P2b) | Source visibility (transmit.rs) | Facade re-export (tx/mod.rs) |
|---|---|---|---|
| `TxError` (enum) | 477 | `pub(in crate::afxdp)` (preserved) | `pub(in crate::afxdp) use transmit::TxError;` |
| `recycle_cancelled_prepared_offset` | 1307 | `pub(in crate::afxdp)` (preserved) | `pub(in crate::afxdp) use transmit::recycle_cancelled_prepared_offset;` |
| `cos_queue_dscp_rewrite` | 1449 | `pub(in crate::afxdp)` (preserved) | `pub(in crate::afxdp) use transmit::cos_queue_dscp_rewrite;` |
| `recycle_prepared_immediately` | 1631 | `pub(in crate::afxdp)` (preserved) | `pub(in crate::afxdp) use transmit::recycle_prepared_immediately;` |
| `remember_prepared_recycle` | 1653 | `pub(in crate::afxdp)` (preserved) | `pub(in crate::afxdp) use transmit::remember_prepared_recycle;` |
| `transmit_batch` | 1662 | `pub(in crate::afxdp)` (preserved) | `pub(in crate::afxdp) use transmit::transmit_batch;` |
| `transmit_prepared_batch` | 1833 | `pub(super)` (preserved) | `pub(super) use transmit::transmit_prepared_batch;` |
| `transmit_prepared_queue` | 1843 | `pub(in crate::afxdp)` (preserved) | `pub(in crate::afxdp) use transmit::transmit_prepared_queue;` |

All 8 items have at least one external caller (cos/queue_service.rs
imports `recycle_cancelled_prepared_offset`, `cos_queue_dscp_rewrite`,
`remember_prepared_recycle`, `transmit_batch`, `transmit_prepared_queue`,
`TxError` directly via `crate::afxdp::tx::*`; drains in tx/mod.rs
also call them).

## NOT in P2c scope (deferred)

- `drain_pending_tx` (line 84, ~537 LOC)
- `drain_pending_tx_local_owner` (line 621, ~685 LOC)
- `pending_tx_capacity`, `bound_pending_tx_local`,
  `bound_pending_tx_prepared` (lines 33-83, the queue-bound /
  backpressure helpers)
- `COS_GUARANTEE_VISIT_NS`, `COS_GUARANTEE_QUANTUM_MIN_BYTES`,
  `COS_GUARANTEE_QUANTUM_MAX_BYTES`, `COS_SURPLUS_ROUND_QUANTUM_BYTES`
  constants (lines 841-844 — drain-related, scheduled with the drain
  carve)
- Various `CoSTxSelection`, struct types around line 482+ (drain-side
  types)

These all go in a separate later PR — likely a `tx/drain.rs` extract
that tackles the larger ~1.2K LOC mass on its own.

## Module-structure change

```
Before P2c:
  userspace-dp/src/afxdp/tx/
    mod.rs       (~12891 LOC)
    stats.rs     (~187 LOC)
    rings.rs     (~322 LOC)

After P2c:
  userspace-dp/src/afxdp/tx/
    mod.rs       (~12140 LOC)
    stats.rs     (unchanged)
    rings.rs     (unchanged)
    transmit.rs  (~770 LOC)
```

`afxdp.rs:99` already points at `afxdp/tx/mod.rs` after P2a. No
parent-module changes.

Steps:
1. Create `userspace-dp/src/afxdp/tx/transmit.rs` with the moved fns
   and enum.
2. In `tx/mod.rs`, add `pub(super) mod transmit;` next to
   `pub(super) mod rings;`.
3. Add the re-export block (all `pub(in crate::afxdp)` except
   `transmit_prepared_batch` which stays `pub(super)`).
4. Existing call sites stay unchanged via re-export.

## Imports for tx/transmit.rs (source-verified upper bound, v1)

Reconciled against actual moved-fn bodies (verified on impl):

```rust
use std::collections::VecDeque;
use std::sync::atomic::Ordering;

use crate::afxdp::frame::{apply_dscp_rewrite_to_frame};
use crate::afxdp::neighbor::monotonic_nanos;
use crate::afxdp::types::{
    CoSPendingTxItem, PreparedTxRecycle, PreparedTxRequest, TxRequest,
};
use crate::afxdp::worker::BindingWorker;
use crate::afxdp::TX_BATCH_SIZE;

use super::stats::stamp_submits;
use super::{maybe_wake_tx, update_binding_debug_state};

// Sibling cos:: helpers used by these bodies:
use crate::afxdp::cos::{cos_queue_push_back, ensure_cos_interface_runtime};
```

(Round-1 reviewer: verify against actual moved-fn bodies. List is the
upper bound; remove any unused.)

## TxError type

`TxError` is currently at `tx/mod.rs:477`, defined as
`pub(in crate::afxdp) enum`. After P2c, it lives in `tx/transmit.rs`
and is re-exported from `tx/mod.rs` for cos/queue_service.rs's
existing `crate::afxdp::tx::TxError` import (queue_service.rs:84).

## #[inline] preservation

Source-verify on impl. Existing #[inline] attributes preserved
verbatim — no silent downgrades, no aggressive `#[inline(always)]`
escalation in this PR.

## tx/mod.rs changes

- Remove the 7 fn definitions + 1 enum + their doc blocks.
- Add `pub(super) mod transmit;` next to `pub(super) mod rings;`.
- Add the `pub(in crate::afxdp) use transmit::{...}` re-export block.
- Existing call sites within tx/mod.rs (drain_pending_tx,
  drain_pending_tx_local_owner) keep working through the re-export.

External call sites (cos/queue_service.rs's tx imports keep working
unchanged via the same `crate::afxdp::tx::*` paths).

## Tests

Pre-existing tests for the moved fns:
- `tx/mod.rs::tests` block contains test pins for `transmit_batch`,
  `transmit_prepared_queue`, `recycle_*`, etc. They reach the moved
  fns via `super::*` resolution which finds the re-exported names
  through the `pub(in crate::afxdp) use transmit::...` chain in
  `tx/mod.rs`.
- `umem.rs::tests` and other sibling tests reach moved fns via
  `crate::afxdp::tx::*` — same load-bearing re-export pattern as P2a.

Round-1 reviewer: enumerate exact test pin locations.

## Risk

**Medium-high.** ~750 LOC across 7 fns + 1 enum. Larger than P2a
(~110 LOC) and P2b (~280 LOC). Single-writer (owner worker) for the
fns that touch BindingWorker. All atomic ops `Ordering::Relaxed`.

Hot-path: `transmit_batch` and `transmit_prepared_queue` fire per
drain cycle (hundreds of times per second under load). Cross-module
`#[inline]` retention works the same way as P1+P2a+P2b.

Atomic ordering: same Ordering::Relaxed counters as P1/P2a/P2b. The
move does not change publish/observe semantics — `publish_committed_queue_vtime`
is in cos/queue_ops.rs (Release ordering) and is called from
queue_service, not transmit. Unchanged.

## Acceptance

- `cargo build --bins` clean (no new unused-import warnings).
- `cargo test --bins` 865/0/2 (rolling baseline post-#992).
- Cluster smoke: `cluster-setup.sh deploy`, `apply-cos-config.sh`,
  per-CoS-class iperf3 (5201–5207), failover (RG1 cycled twice,
  ≥95% intervals ≥3 Gbps, 0 zero-bps).
- **Triadic plan + impl review**: Codex + Gemini converge
  PLAN-READY/IMPL-READY with NO new findings on cross-reviews.
- Copilot review on the PR addressed.

## After P2c

P2c2 / P2d (the largest carve): drain_pending_tx +
drain_pending_tx_local_owner + bound_pending_tx_* +
pending_tx_capacity + the 4 quantum/guarantee constants → `tx/drain.rs`.
~1.2K LOC. Will need its own multi-round plan + careful review.

P2d-final: collapse `tx/mod.rs` to a thin facade or delete if no fns
remain.
