# P2c2: extract afxdp/tx/drain.rs from tx/mod.rs

Plan v3 — 2026-04-30. Stage 2 step 4 of the long sequence after #993
(P2c: tx/transmit.rs) merged at master `e2b99aa9`.

## v3 changelog vs v2 (from Codex round-2)

- R2-1 [MEDIUM]: missed test pin
  `process_pending_queue_in_place_preserves_failed_item_order` at
  `tx/mod.rs:1795` directly calls `process_pending_queue_in_place`.
  Since v2 moves that helper file-private into `drain.rs`, the test
  must also move to `drain.rs::tests`. v3 adds it to the test-move
  list.
- R2-2 [LOW]: stale wording — earlier section said partition tests
  stay in `tx/mod.rs::tests` via re-export, but the chosen approach
  is moving them into `drain.rs::tests`. v3 drops the stale "option (b)"
  wording.
- Codex r2 also confirmed: 3 pending helpers correctly in scope,
  cached-selection deferral clean, import-block deferral acceptable.

## v2 changelog vs v1 (from Codex round-1)

- R1-1 [HIGH]: take_pending_tx_requests, restore_pending_tx_requests,
  process_pending_queue_in_place are CALLED BY drain (tx/mod.rs:278,
  326, 699, 790). v1 deferred them to P2d, creating drain → tx/mod.rs
  back-edges. v2 moves them with the drain cluster.
- R1-2 [HIGH]: `CoSTxSelection` and `resolve_cached_cos_tx_selection`
  are NOT actually used by drain_pending_tx. They're cache/classification
  logic (used by flow_cache.rs and depend on deferred classifier
  helpers). v2 DEFERS them to P2d with the rest of classification.
  This also avoids the field-visibility issue (CoSTxSelection fields
  are `pub(super)` and reached from afxdp.rs:3269/3153, icmp.rs,
  tunnel.rs, coordinator.rs, frame_tx.rs — too many sites for this PR
  to bump correctly).
- R1-3 [HIGH]: Import block was not source-verified. v2 explicitly
  defers the source-accurate import list to round-1 of impl review
  (after the actual move), since the moved bodies are too large
  (~600 LOC) to enumerate every import in the plan reliably.
- R1-4 [MEDIUM]: cached-selection move was scope-weak — confirmed by
  R1-2 deferral.
- R1-5 [MEDIUM]: Direct test pins for `partition_cos_bound_local_with_rescue`
  (tx/mod.rs:1712, 1761) exist. v2 documents that those tests stay
  in `tx/mod.rs::tests` and reach the moved fn via `super::*`
  resolution through the `pub(super) use drain::partition_cos_bound_local_with_rescue;`
  re-export (or move the tests into drain.rs::tests if cleaner).

## Goal

Extract the **drain dispatch + queue-bound + drain-cluster constants**
(plus the supporting pending-queue helpers used exclusively by drain)
from `tx/mod.rs` into a sibling `tx/drain.rs`. ~600 LOC.

Cached-selection (`CoSTxSelection`, `resolve_cached_cos_tx_selection`,
`map_cached_forwarding_class_queue`) and CoS classify/enqueue stay
for P2d.

## Move list (v2 — refined)

### Public fns (5 items)

| Item | Line | Source visibility | Facade re-export |
|---|---|---|---|
| `pending_tx_capacity` | 49 | `pub(in crate::afxdp)` (bumped from `pub(super)`) | `pub(super) use drain::pending_tx_capacity;` |
| `bound_pending_tx_local` | 55 | `pub(in crate::afxdp)` | `pub(super)` |
| `bound_pending_tx_prepared` | 76 | `pub(in crate::afxdp)` | `pub(super)` |
| `drain_pending_tx` | 100 | `pub(in crate::afxdp)` | `pub(super)` |
| `drain_pending_tx_local_owner` | 633 | `pub(in crate::afxdp)` | `pub(super)` |

### Private helpers (6 items, all file-private in drain.rs)

| Item | Line | Reason in scope |
|---|---|---|
| `drop_cos_bound_prepared_leftovers` | 342 | called by drain_pending_tx |
| `partition_cos_bound_local_with_rescue` | 431 | called by drain_pending_tx (test pin at tx/mod.rs:1712, 1761 — see Tests below) |
| `drop_cos_bound_local_leftovers` | 459 | called by drain_pending_tx |
| `binding_has_pending_tx_work` | 625 | called by drain_pending_tx_local_owner |
| `ingest_cos_pending_tx` | 655 | called by drain_pending_tx_local_owner |
| `ingest_cos_pending_tx_with_provenance` | 685 | called by ingest_cos_pending_tx |

### Pending-queue helpers (3 items, included per R1-1)

| Item | Line | Reason in scope |
|---|---|---|
| `process_pending_queue_in_place<T,F>` | 1595 | called from ingest_* helpers |
| `take_pending_tx_requests` | 1610 | called by drain_pending_tx at 278 |
| `restore_pending_tx_requests` | 1620 | called by drain_pending_tx at 326 |

All 3 currently file-private. Moving them with drain keeps them
file-private in drain.rs (no external callers found).

### Constants (4 items)

| Item | Line | Source visibility | Facade re-export |
|---|---|---|---|
| `COS_GUARANTEE_VISIT_NS` | 853 | `pub(in crate::afxdp)` (preserved) | `pub(in crate::afxdp) use drain::COS_GUARANTEE_VISIT_NS;` |
| `COS_GUARANTEE_QUANTUM_MIN_BYTES` | 854 | same | same |
| `COS_GUARANTEE_QUANTUM_MAX_BYTES` | 855 | same | same |
| `COS_SURPLUS_ROUND_QUANTUM_BYTES` | 856 | same | same |

(cos/queue_service.rs imports the 4 constants via `crate::afxdp::tx::*`,
so the re-export is load-bearing.)

### Total

5 + 6 + 3 + 4 = **18 items, ~600 LOC**.

## NOT in P2c2 scope (deferred to P2d)

- `CoSTxSelection` (struct), `resolve_cached_cos_tx_selection`,
  `map_cached_forwarding_class_queue` — cached-selection logic, not
  drain.
- `cos_queue_dscp_rewrite` — CoS-side classification helper.
- `resolve_cos_queue_id`, `resolve_cos_tx_selection`,
  `resolve_cos_dscp_classifier_queue_id`,
  `resolve_cos_ieee8021_classifier_queue_id` — CoS classify.
- `enqueue_local_into_cos`, `enqueue_prepared_into_cos`,
  `enqueue_cos_item`, `prepare_local_request_for_cos`,
  `clone_prepared_request_for_cos`, `resolve_cos_queue_idx`,
  `demote_prepared_cos_queue_to_local`, `cos_queue_accepts_prepared`
  — CoS enqueue path.

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
    mod.rs       (~11830 LOC)
    stats.rs     (unchanged)
    rings.rs     (unchanged)
    transmit.rs  (unchanged)
    drain.rs     (~640 LOC)
```

## Imports for tx/drain.rs

The actual moved bodies are too large (~600 LOC across 14 fns + 3
generics + 4 constants) to enumerate the import block reliably in the
plan. The impl will source-verify against the moved bodies and
produce the import block as part of the v1 commit. Round-1 impl
review (Codex + Gemini) will verify it matches the moved-body deps.

This deferral is intentional and called out per the P2b/P2c lesson:
import-block precision is most reliably done at impl time, not in
the plan.

## tx/mod.rs changes

- Remove the 18 move-listed items (~600 LOC).
- Add `pub(super) mod drain;` next to existing `mod stats; mod rings;
  mod transmit;`.
- Add the re-export blocks:
  - `pub(super) use drain::{pending_tx_capacity, bound_pending_tx_local,
    bound_pending_tx_prepared, drain_pending_tx,
    drain_pending_tx_local_owner};` for sibling-visible items.
  - `pub(in crate::afxdp) use drain::{COS_GUARANTEE_VISIT_NS, ...};`
    for the 4 constants (load-bearing for cos/queue_service.rs).
- The 6 file-private helpers + 3 pending-queue helpers are NOT
  re-exported (sole callers move with them).

## Tests

Pre-existing test pins relevant to the moved items:
Tests that move to `drain.rs::tests` (since their target fns become
file-private in drain.rs after the move):
- `partition_cos_bound_local_with_rescue_*` tests at tx/mod.rs:1712,
  1761 — exercise `partition_cos_bound_local_with_rescue`.
- `process_pending_queue_in_place_preserves_failed_item_order` at
  tx/mod.rs:1795 — exercises `process_pending_queue_in_place`.

The chosen approach (moving tests with their fn) is cleaner than
bumping the private helpers to `pub(in crate::afxdp)` for cfg-test
re-export.

Round-2 reviewer: enumerate any other test pin I missed.

## Risk

**High.** ~600 LOC across 14 fns + 3 generics + 4 constants. This is
the densest carve in the sequence. The drain fns coordinate XSK ring
submit, CoS scheduling, frame recycling, and worker bookkeeping.
Single-writer (owner worker), all atomic ops `Ordering::Relaxed`.

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

P2d: extract the residual cached-selection + CoS classify/enqueue
cluster into `tx/cos_classify.rs` (or similar). Then collapse
`tx/mod.rs` to a thin facade.
