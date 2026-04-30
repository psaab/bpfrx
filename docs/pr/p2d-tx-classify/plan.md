# P2d: extract afxdp/tx/cos_classify.rs from tx/mod.rs (final carve)

Plan v3 — 2026-04-30. Stage 2 step 5 (final) of the long sequence
after #994 (P2c2: tx/drain.rs) merged at master `ff982ad1`.

## v3 changelog vs v2 (from Codex round-2)

- R2-1: `enqueue_prepared_into_cos` re-export shape — v2 said
  `pub(super)` source + `pub(super) use` re-export, which fails
  Rust privacy (E0364: re-export wider than source). v3 fixes:
  use a **private** `use cos_classify::enqueue_prepared_into_cos;`
  in tx/mod.rs (same pattern as `transmit_prepared_batch` from
  P2c) — keeps the source `pub(super)` and gives drain.rs's
  `use super::*;` the resolution it needs.
- R2-2: tx/mod.rs facade sketch DROPPED the existing
  `use super::cos::{...}` imports. drain.rs uses them via
  `use super::*;` (drain_shaped_tx, redirect helpers,
  resolve_local_routing_decision, LocalRoutingDecision, Step1Action).
  v3 KEEPS the cos:: imports in the facade.
- R2-3: cfg-test plan was inconsistent — parent's `tx/mod.rs::tests`
  can't access private children of `cos_classify.rs`. v3 makes the
  5 directly-pinned helpers (resolve_cos_queue_idx,
  clone_prepared_request_for_cos, prepare_local_request_for_cos,
  cos_queue_accepts_prepared, demote_prepared_cos_queue_to_local)
  `pub(super)` in cos_classify.rs **with `#[cfg(test)]` re-exports
  in tx/mod.rs**. Tests stay in tx/mod.rs::tests.
- R2-4: count corrected — 10 helpers including
  enqueue_prepared_into_cos.

## v2 changelog vs v1 (from Codex round-1)

- R1-1: `enqueue_prepared_into_cos` is called from drain.rs:488. v1
  marked it file-private. v2 makes it `pub(super)` in cos_classify.rs
  with a `pub(super) use cos_classify::enqueue_prepared_into_cos;`
  re-export from tx/mod.rs so drain.rs's `use super::*;` resolves.
- R1-2: tx/mod.rs facade sketch dropped `use super::cos::{...}`
  imports that drain.rs uses (`drain_shaped_tx`, redirect helpers,
  `resolve_local_routing_decision`, `Step1Action`). v2 keeps those
  in the facade so drain.rs's `use super::*;` keeps resolving.
- R1-3: tests stay in tx/mod.rs::tests for this PR. v2 adds explicit
  cfg-test re-exports for helpers directly pinned in tx/mod.rs
  (resolve_cos_queue_idx, clone_prepared_request_for_cos,
  prepare_local_request_for_cos, cos_queue_accepts_prepared,
  demote_prepared_cos_queue_to_local). No test splitting in this PR.
- R1-4: corrected count-table headings (was "Public items (4)" /
  "Private helpers (8)" — actual = 6 / 10).

## Goal

Extract the **CoS classify + enqueue + cached-selection cluster**
(~870 LOC, 14 fns + 1 struct) from `tx/mod.rs` into a sibling
`tx/cos_classify.rs`. After this PR, `tx/mod.rs` becomes a thin
facade containing only `mod` declarations + re-exports + the test
mod block (the test mod stays in mod.rs as the canonical pin
location that reaches all 5 sibling modules via `super::*`).

This is the FINAL carve — closes #984.

## Move list (~870 LOC)

### Public items (6)

| Item | Line | Source visibility | Facade re-export |
|---|---|---|---|
| `CoSTxSelection` (struct) | 122 | `pub(in crate::afxdp)` (bumped from `pub(super)`; struct fields also bumped to `pub(in crate::afxdp)`) | `pub(super) use cos_classify::CoSTxSelection;` |
| `resolve_cached_cos_tx_selection` | 134 | `pub(in crate::afxdp)` (bumped) | `pub(super) use cos_classify::resolve_cached_cos_tx_selection;` |
| `resolve_cos_queue_id` | 335 | `pub(in crate::afxdp)` (bumped) | `pub(super) use cos_classify::resolve_cos_queue_id;` |
| `resolve_cos_tx_selection` | 344 | `pub(in crate::afxdp)` (bumped) | `pub(super) use cos_classify::resolve_cos_tx_selection;` |
| `enqueue_local_into_cos` | 518 | `pub(in crate::afxdp)` (bumped) | `pub(super) use cos_classify::enqueue_local_into_cos;` |
| `cos_queue_dscp_rewrite` | 860+ | `pub(in crate::afxdp)` (preserved) | `pub(in crate::afxdp) use cos_classify::cos_queue_dscp_rewrite;` |

### Helpers (10 total)

`enqueue_prepared_into_cos` is `pub(super)` in cos_classify.rs
(called by drain.rs:488). tx/mod.rs adds a **private**
`use cos_classify::enqueue_prepared_into_cos;` (NOT a re-export —
re-exporting would be E0364 since pub(super) source can't be
re-exported as pub(super) from tx/mod.rs's perspective). Same
pattern as `transmit_prepared_batch` from P2c. drain.rs's
`use super::*;` then resolves it transitively through tx/mod.rs.

5 of the helpers have direct test pins in `tx/mod.rs::tests`. They
become `pub(super)` in cos_classify.rs and tx/mod.rs adds:

```rust
#[cfg(test)]
use cos_classify::{
    clone_prepared_request_for_cos, cos_queue_accepts_prepared,
    demote_prepared_cos_queue_to_local, prepare_local_request_for_cos,
    resolve_cos_queue_idx,
};
```

so `mod tests { use super::*; }` resolves them. (Tests stay in
`tx/mod.rs::tests` — no test split in this PR.)

The remaining 4 helpers are file-private (no external callers,
no test pins):

| Item | Line |
|---|---|
| `map_cached_forwarding_class_queue` | 127 |
| `resolve_cos_dscp_classifier_queue_id` | 501 |
| `resolve_cos_ieee8021_classifier_queue_id` | 506 |
| `prepare_local_request_for_cos` | 616 |
| `enqueue_prepared_into_cos` | 647 |
| `clone_prepared_request_for_cos` | 703 |
| `resolve_cos_queue_idx` | 717 |
| `demote_prepared_cos_queue_to_local` | 734 |
| `cos_queue_accepts_prepared` | 850 |
| `enqueue_cos_item` | 872 |

(Round-1 reviewer: verify the line numbers and the full set against
source — there may be additional small private helpers nested in.)

## After P2d

`tx/mod.rs` becomes a thin facade (~150 LOC: `use super::*;`, 5 `mod`
declarations, ~4 re-export blocks, ~5 cfg-test re-exports for tests
in `mod tests`). The actual test mod block (~10K LOC) STAYS in
`tx/mod.rs::tests` since it's the canonical pin location for the
whole tx subsystem and moving it would require shuffling tests across
5 files.

Final tx/ structure:
```
userspace-dp/src/afxdp/tx/
  mod.rs            (~150 LOC + ~10K LOC tests)
  stats.rs          (P2a)
  rings.rs          (P2b)
  transmit.rs       (P2c)
  drain.rs          (P2c2)
  cos_classify.rs   (P2d, ~900 LOC)
```

## Module-structure change

```
Before P2d:
  tx/mod.rs       (11733 LOC, ~1020 production + ~10700 tests)

After P2d:
  tx/mod.rs       (~10870 LOC, ~150 production facade + ~10700 tests)
  tx/cos_classify.rs (~900 LOC)
```

## tx/mod.rs final shape

```rust
use super::*;

pub(super) mod stats;
pub(super) mod rings;
pub(super) mod transmit;
pub(super) mod drain;
pub(super) mod cos_classify;

pub(in crate::afxdp) use stats::stamp_submits;
#[cfg(test)]
pub(in crate::afxdp) use stats::{record_kick_latency, record_tx_completions_with_stamp};

pub(in crate::afxdp) use rings::{maybe_wake_tx, reap_tx_completions};
pub(super) use rings::{drain_pending_fill, maybe_wake_rx};
#[cfg(test)]
use rings::apply_prepared_recycle;

pub(in crate::afxdp) use transmit::{
    recycle_cancelled_prepared_offset, recycle_prepared_immediately,
    remember_prepared_recycle, transmit_batch, transmit_prepared_queue, TxError,
};
use transmit::transmit_prepared_batch;

pub(super) use drain::{
    bound_pending_tx_local, bound_pending_tx_prepared, drain_pending_tx,
    drain_pending_tx_local_owner, pending_tx_capacity,
};
pub(in crate::afxdp) use drain::{
    COS_GUARANTEE_QUANTUM_MAX_BYTES, COS_GUARANTEE_QUANTUM_MIN_BYTES,
    COS_GUARANTEE_VISIT_NS, COS_SURPLUS_ROUND_QUANTUM_BYTES,
};

pub(super) use cos_classify::{
    CoSTxSelection, enqueue_local_into_cos, resolve_cached_cos_tx_selection,
    resolve_cos_queue_id, resolve_cos_tx_selection,
};
pub(in crate::afxdp) use cos_classify::cos_queue_dscp_rewrite;
// Private import (NOT re-export — would be E0364): drain.rs:488
// reaches it via `use super::*;` through this private use.
use cos_classify::enqueue_prepared_into_cos;
// Test pins for 5 helpers in tx/mod.rs::tests (resolve via super::*).
#[cfg(test)]
use cos_classify::{
    clone_prepared_request_for_cos, cos_queue_accepts_prepared,
    demote_prepared_cos_queue_to_local, prepare_local_request_for_cos,
    resolve_cos_queue_idx,
};

// Existing load-bearing imports (preserved from pre-P2d tx/mod.rs):
// drain.rs uses these via `use super::*;` for drain_shaped_tx, redirect
// helpers, resolve_local_routing_decision, LocalRoutingDecision, Step1Action.
use super::cos::{
    apply_cos_admission_ecn_policy, cos_flow_aware_buffer_limit,
    cos_flow_bucket_index, cos_item_flow_key, cos_queue_drain_all,
    cos_queue_flow_share_limit, cos_queue_is_empty, cos_queue_push_back,
    cos_queue_restore_front, drain_shaped_tx, ensure_cos_interface_runtime,
    mark_cos_queue_runnable, publish_committed_queue_vtime,
    redirect_prepared_cos_request_to_owner,
    redirect_prepared_cos_request_to_owner_binding,
    resolve_local_routing_decision, LocalRoutingDecision, Step1Action,
};
// (Plus the existing #[cfg(test)] cos:: imports — preserved verbatim.)

#[cfg(test)]
mod tests {
    use super::*;
    // ... ~10K LOC of unit tests, unchanged ...
}
```

## Tests

Pre-existing tests in `tx/mod.rs::tests` reference many of the moved
fns. After this PR, `super::*` in the test mod resolves to the
re-export chain. Tests that reach moved private helpers will need
either `#[cfg(test)] use cos_classify::PRIVATE_FN;` re-exports OR
those tests move into `cos_classify.rs::tests`.

Round-1 reviewer: enumerate the test pins and decide per-test:
move-with-fn vs cfg-test re-export.

## Imports for tx/cos_classify.rs

Likely a wide import surface (the moved bodies touch BindingWorker,
CoSInterfaceConfig, CoSPendingTxItem, ForwardingState, FastMap,
session helpers, etc). Same as P2c2: use `use super::*;` initially
with explicit enumeration deferred to a cleanup PR.

## Risk

**High.** ~870 LOC across 14 fns + 1 struct. The CoS classify path
is on the steady-state enqueue hot path. Single-writer (owner
worker), all atomic ops Ordering::Relaxed.

`CoSTxSelection` has external callers (afxdp.rs, icmp.rs, tunnel.rs,
coordinator.rs, frame_tx.rs per Codex's earlier flag) — bumping its
field visibility to `pub(in crate::afxdp)` is required and must be
verified to not break those sites.

## Acceptance

- `cargo build --bins` clean.
- `cargo test --bins` 865/0/2.
- Cluster smoke: per-CoS iperf3 + RG1 cycled-twice failover ≥95% ≥3
  Gbps.
- Triadic plan + impl review.
- Copilot review on the PR.

## After P2d

This closes #984 (afxdp/tx/ module decomposition) and the long
sequence started with #956. Next stages:
- Stage 3 (#987): HAL traits + MockDriver
- Stage 4 (#985 / #986): Coordinator decompose, umem/ split
- Stage 5: Test consolidation, doc pass, profiling pass
