# P2c2: extract afxdp/tx/drain.rs from tx/mod.rs

Plan v1 — 2026-04-30. Stage 2 step 4 of the long sequence after #993
(P2c: tx/transmit.rs) merged at master `e2b99aa9`.

## Goal

Extract the **drain dispatch + queue-bound + drain-cluster constants**
from `tx/mod.rs` into a sibling `tx/drain.rs`. Largest carve in the
sequence (~600 LOC of dense drain-loop code + private helpers).

CoS classification + enqueue cluster (resolve_cos_*, enqueue_*,
prepare_*, demote_*, cos_queue_dscp_rewrite) stays for P2d.

## Why this scope

`drain_pending_tx` and `drain_pending_tx_local_owner` are the
worker-side drain-loop entry points. They:
- consult queue-bound state (`bound_pending_tx_*`,
  `pending_tx_capacity`),
- drop / partition / ingest CoS-bound items via private helpers
  (`drop_cos_bound_prepared_leftovers`,
  `partition_cos_bound_local_with_rescue`,
  `drop_cos_bound_local_leftovers`,
  `binding_has_pending_tx_work`,
  `ingest_cos_pending_tx`, `ingest_cos_pending_tx_with_provenance`),
- consume the cached-tx-selection struct (`CoSTxSelection`,
  `map_cached_forwarding_class_queue`,
  `resolve_cached_cos_tx_selection`),
- are time-budgeted by the drain-cluster constants
  (`COS_GUARANTEE_VISIT_NS`, `COS_GUARANTEE_QUANTUM_*`,
  `COS_SURPLUS_ROUND_QUANTUM_BYTES`).

All of these form one cohesive drain-dispatch unit. Moving them
together into `tx/drain.rs` leaves `tx/mod.rs` with just the
classification/enqueue side.

## Move list (~600 LOC)

### Public fns + struct (5 items)

| Item | Line | Source visibility | Facade re-export |
|---|---|---|---|
| `pending_tx_capacity` | 49 | `pub(in crate::afxdp)` (bumped from `pub(super)` for sibling worker.rs reach) | `pub(super) use drain::pending_tx_capacity;` |
| `bound_pending_tx_local` | 55 | `pub(in crate::afxdp)` (bumped from `pub(super)`) | `pub(super) use drain::bound_pending_tx_local;` |
| `bound_pending_tx_prepared` | 76 | `pub(in crate::afxdp)` (bumped from `pub(super)`) | `pub(super) use drain::bound_pending_tx_prepared;` |
| `drain_pending_tx` | 100 | `pub(in crate::afxdp)` (bumped from `pub(super)`) | `pub(super) use drain::drain_pending_tx;` |
| `drain_pending_tx_local_owner` | 633 | `pub(in crate::afxdp)` (bumped from `pub(super)`) | `pub(super) use drain::drain_pending_tx_local_owner;` |
| `CoSTxSelection` (struct) | 495 | `pub(in crate::afxdp)` (bumped from `pub(super)`) | `pub(super) use drain::CoSTxSelection;` |
| `resolve_cached_cos_tx_selection` | 507 | `pub(in crate::afxdp)` (bumped from `pub(super)`) | `pub(super) use drain::resolve_cached_cos_tx_selection;` |

### Private helpers (6 items)

| Item | Line | Source visibility |
|---|---|---|
| `drop_cos_bound_prepared_leftovers` | 342 | file-private |
| `partition_cos_bound_local_with_rescue` | 431 | file-private |
| `drop_cos_bound_local_leftovers` | 459 | file-private |
| `map_cached_forwarding_class_queue` | 500 | file-private |
| `binding_has_pending_tx_work` | 625 | file-private |
| `ingest_cos_pending_tx` | 655 | file-private |
| `ingest_cos_pending_tx_with_provenance` | 685 | file-private |

### Constants (4 items)

| Item | Line | Source visibility | Facade re-export |
|---|---|---|---|
| `COS_GUARANTEE_VISIT_NS` | 853 | `pub(in crate::afxdp)` (preserved) | `pub(in crate::afxdp) use drain::COS_GUARANTEE_VISIT_NS;` |
| `COS_GUARANTEE_QUANTUM_MIN_BYTES` | 854 | `pub(in crate::afxdp)` | same |
| `COS_GUARANTEE_QUANTUM_MAX_BYTES` | 855 | `pub(in crate::afxdp)` | same |
| `COS_SURPLUS_ROUND_QUANTUM_BYTES` | 856 | `pub(in crate::afxdp)` | same |

(cos/queue_service.rs imports the 4 constants via `crate::afxdp::tx::*`,
so the re-export is load-bearing.)

## NOT in P2c2 scope (defer to P2d)

- `cos_queue_dscp_rewrite` (1446) — CoS-side classification helper.
- `resolve_cos_queue_id`, `resolve_cos_tx_selection` — classification.
- `resolve_cos_dscp_classifier_queue_id`,
  `resolve_cos_ieee8021_classifier_queue_id` — DSCP/802.1p classifier.
- `enqueue_local_into_cos`, `enqueue_prepared_into_cos`,
  `enqueue_cos_item`, `prepare_local_request_for_cos`,
  `clone_prepared_request_for_cos`, `resolve_cos_queue_idx`,
  `demote_prepared_cos_queue_to_local`, `cos_queue_accepts_prepared` —
  CoS enqueue path.
- `process_pending_queue_in_place`, `take_pending_tx_requests`,
  `restore_pending_tx_requests` — generic pending-queue helpers.

These all go to `tx/cos_classify.rs` (or similar) in P2d.

## Module-structure change

```
Before P2c2:
  userspace-dp/src/afxdp/tx/
    mod.rs       (~12460 LOC)
    stats.rs     (~187 LOC)
    rings.rs     (~322 LOC)
    transmit.rs  (~484 LOC)

After P2c2:
  userspace-dp/src/afxdp/tx/
    mod.rs       (~11860 LOC)
    stats.rs     (unchanged)
    rings.rs     (unchanged)
    transmit.rs  (unchanged)
    drain.rs     (~610 LOC)
```

## Imports for tx/drain.rs (source-verified upper bound)

Reconciled against the moved-fn bodies (round-1 reviewer to verify):

```rust
use std::collections::VecDeque;
use std::sync::atomic::Ordering;

use crate::afxdp::frame::frame_has_tcp_rst;
use crate::afxdp::neighbor::monotonic_nanos;
use crate::afxdp::types::{
    CoSPendingTxItem, FastMap, ForwardingState, PreparedTxRecycle,
    PreparedTxRequest, TxRequest,
};
use crate::afxdp::worker::BindingWorker;
use crate::afxdp::{
    PENDING_TX_LIMIT_MULTIPLIER, TX_BATCH_SIZE,
};

use super::rings::{drain_pending_fill, maybe_wake_rx, maybe_wake_tx, reap_tx_completions};
use super::transmit::{
    recycle_cancelled_prepared_offset, transmit_batch, transmit_prepared_queue,
};
// CoS-side helpers still in tx/mod.rs (deferred to P2d):
use super::{
    cos_queue_dscp_rewrite, enqueue_cos_item, enqueue_local_into_cos,
    enqueue_prepared_into_cos, prepare_local_request_for_cos,
    resolve_cos_queue_id, resolve_cos_tx_selection,
};
// CoS submodule helpers:
use crate::afxdp::cos::{
    advance_cos_timer_wheel, apply_cos_admission_ecn_policy,
    apply_cos_send_result, drain_shaped_tx, ensure_cos_interface_runtime,
    prime_cos_root_for_service, refresh_cos_interface_activity,
};
```

(Round-1 reviewer: this is a large import block; verify against the
moved bodies. Likely needs trimming for unused items.)

## tx/mod.rs changes

- Remove the move-listed items (~600 LOC).
- Add `pub(super) mod drain;` next to existing `mod stats; mod rings;
  mod transmit;`.
- Add the re-export blocks per the visibility tables.
- Existing internal call sites in tx/mod.rs (CoS classify/enqueue
  cluster) keep working through the re-export.

## Tests

`tx/mod.rs::tests` (line 1635+) has tests for some of these:
- `demote_prepared_cos_queue_to_local_*` (lines 3335, 3423) —
  exercises a private helper that's NOT moving (stays in tx/mod.rs
  with the enqueue cluster). No impact.
- `apply_prepared_recycle_routes_*` (line 3329) — apply_prepared_recycle
  was moved in P2b, already cfg-test re-exported.

Round-1 reviewer: enumerate test pins for the drain-side fns. Likely
indirect (covered by smoke + failover) rather than direct unit pins.

## Risk

**High.** ~600 LOC across 12 fns + 1 struct + 4 constants. This is the
densest, most algorithm-heavy carve in the sequence. The drain
fns coordinate XSK ring submit, CoS scheduling, frame recycling, and
worker bookkeeping. Single-writer (owner worker), all atomic ops
`Ordering::Relaxed`.

Hot-path: `drain_pending_tx` and `drain_pending_tx_local_owner` are
the per-tick drain entry points. Algorithmically unchanged.

## Acceptance

- `cargo build --bins` clean.
- `cargo test --bins` 865/0/2.
- Cluster smoke: deploy + per-CoS iperf3 + RG1 cycled twice ≥95% ≥3
  Gbps.
- **Triadic plan + impl review** — likely 3+ rounds given the scale.
- Copilot review on the PR addressed.

## After P2c2

P2d: extract the residual classification/enqueue cluster into
`tx/cos_classify.rs` (or similar). Then collapse `tx/mod.rs` to a
thin facade.
