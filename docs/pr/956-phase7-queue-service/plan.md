# #956 Phase 7: extract cos/queue_service.rs from tx.rs

Plan v2 — 2026-04-30. Continues #956. Phases 1-6 merged at PRs
#976-#981.

Round-1 changelog (v1 → v2): Codex round-1 returned PLAN-NEEDS-MAJOR
with substantive scope incompleteness; Gemini round-1 returned
PLAN-NEEDS-MINOR pointing at the same submit_cos_batch / inline /
test-visibility concerns. v2 expands the move list to capture the
full dispatch + drain + submit + scheduler-helpers cluster.
This is the largest move of the campaign (~1900 LOC).

## Move list (v2 expanded)

### Types (6)
| Item | Line | Notes |
|---|---|---|
| `enum CoSServicePhase` | 771 | dispatch-internal |
| `enum CoSBatch` | 776 | pattern-matched in `submit_cos_batch` (moving) and TX-completion appliers (staying in tx.rs through future TX-completion phase) — needs `pub(in crate::afxdp)` plus cfg-gated re-export for tests |
| `enum ExactCoSQueueKind` | 792 | dispatch-internal, file-private after move |
| `struct ExactCoSQueueSelection` | 798 | tests access `.queue_idx` (12418, 12474) — `pub(in crate::afxdp)` + cfg-gated re-export |
| `struct DrainedQueueRef` | 1431 | currently `pub(super)`; consumers `cos_batch_queue_ref` + `submit_cos_batch` move with it |
| `enum ParkReason` | 3600 | dispatch-internal |

### Selector / dispatch (8)
| Item | Line |
|---|---|
| `drain_shaped_tx` | 1437 |
| `cos_batch_queue_ref` | 1490 |
| `build_nonexact_cos_batch` | 1520 |
| `service_exact_guarantee_queue_direct` | 1536 |
| `service_exact_guarantee_queue_direct_with_info` | 1560 |
| `select_cos_guarantee_batch` | 1612 |
| `select_cos_guarantee_batch_with_fast_path` | 1626 (`#[cfg(test)]`) |
| `select_exact_cos_guarantee_queue_with_fast_path` | 1717 |

### Selector / dispatch (cont.) (3)
| Item | Line |
|---|---|
| `select_nonexact_cos_guarantee_batch` | 1814 |
| `select_cos_surplus_batch` | 1876 |

### Service-direct paths (4)
| Item | Line |
|---|---|
| `service_exact_local_queue_direct` | 1932 |
| `service_exact_local_queue_direct_flow_fair` | 2091 |
| `service_exact_prepared_queue_direct` | 2240 |
| `service_exact_prepared_queue_direct_flow_fair` | 2395 |

### Scratch + drain helpers (4)
| Item | Line |
|---|---|
| `drain_exact_local_fifo_items_to_scratch` | 2547 |
| `drain_exact_local_items_to_scratch_flow_fair` | 2644 |
| `drain_exact_prepared_fifo_items_to_scratch` | 2764 |
| `drain_exact_prepared_items_to_scratch_flow_fair` | 2869 |

### Build / submit / accounting helpers (3)
| Item | Line |
|---|---|
| `subtract_direct_cos_queue_bytes` | 3153 |
| `build_cos_batch_from_queue` | 3231 |
| `submit_cos_batch` | 3325 |

### Scheduler helpers (5)
| Item | Line |
|---|---|
| `cos_surplus_quantum_bytes` | 3533 |
| `cos_guarantee_quantum_bytes` | 3537 |
| `estimate_cos_queue_wakeup_tick` | 3556 |
| `count_park_reason` | 3639 |
| `park_cos_queue` | 3658 |

**Total: 6 types + 27 fns ≈ 1900 LOC**

## What STAYS in tx.rs (Phase 7 deferrals)

These were considered for Phase 7 but architecturally belong to
later phases or are tightly coupled to non-CoS infrastructure:

- `restore_cos_local_items_inner` (4687) /
  `restore_cos_prepared_items_inner` (4702) — TX-completion
  rollback helpers, family with `apply_cos_*_result` (deferred
  to TX-completion phase).
- `apply_cos_send_result` / `apply_cos_prepared_result` /
  `apply_direct_exact_send_result` / `prime_cos_root_for_service` /
  `advance_cos_timer_wheel` — TX-completion family. Visibility
  bumped to `pub(in crate::afxdp)` so the moving code can call
  them via back-edge `cos/queue_service -> tx`. Documented as
  forward-debt for a future TX-completion phase.
- `transmit_batch`, `transmit_prepared_queue`, `reap_tx_completions`,
  `maybe_wake_tx`, `stamp_submits`, `monotonic_nanos`,
  `cos_queue_dscp_rewrite`, frame-rewrite + RST helpers —
  worker-binding / TX-ring infrastructure that doesn't belong in
  cos/.
- `refresh_cos_interface_activity` — coupled to interface-lifecycle
  bookkeeping in tx.rs.

For each back-referenced item, this PR bumps visibility from
`fn` (private) or `pub(super) fn` to `pub(in crate::afxdp) fn`
so `cos/queue_service.rs` can call it. The full back-edge set
(Codex round-1 #4):
1. `apply_cos_send_result` (tx.rs:4517 — verify line)
2. `apply_cos_prepared_result` (tx.rs:4578)
3. `apply_direct_exact_send_result` (tx.rs:3171)
4. `prime_cos_root_for_service` (tx.rs:1505)
5. `advance_cos_timer_wheel` (tx.rs:3707)
6. `restore_cos_local_items_inner` (tx.rs:4687)
7. `restore_cos_prepared_items_inner` (tx.rs:4702)
8. `transmit_batch` + `transmit_prepared_queue` + `reap_tx_completions`
   + `maybe_wake_tx` + `stamp_submits`
9. `cos_queue_dscp_rewrite`
10. `refresh_cos_interface_activity`
11. Frame-rewrite + RST helpers consumed by service-direct paths.

(Codex round-2 will verify the EXACT back-edge set by line — v2's
list is the broad shape; the implementation will pin every `use
crate::afxdp::tx::...` line.)

## Visibility classification

- **`pub(in crate::afxdp)`** (cross-module callers — production
  tx.rs entry points or test-required):
  - `drain_shaped_tx` (worker.rs reaches it via super::*)
  - `enum CoSBatch` (`submit_cos_batch` matches it; if
    `submit_cos_batch` moves WITH it as planned, this becomes
    file-private — but test sites at 12122/12189/12432/12852
    need access too, so cfg-gated `pub(in crate::afxdp)` it is)
  - `struct ExactCoSQueueSelection` (test access at
    12418/12474)
  - Test-touched selector variants: `select_exact_cos_guarantee_queue_with_fast_path`,
    `select_nonexact_cos_guarantee_batch`, `select_cos_surplus_batch`
    (cfg-gated)
- **File-private** (no callers outside the moving set):
  - `enum CoSServicePhase`, `enum ExactCoSQueueKind`,
    `enum ParkReason`
  - `cos_batch_queue_ref`, `build_nonexact_cos_batch`,
    `service_exact_guarantee_queue_direct(_with_info)`
  - `service_exact_local_queue_direct(_flow_fair)`,
    `service_exact_prepared_queue_direct(_flow_fair)`
  - All `drain_exact_*_to_scratch`
  - `subtract_direct_cos_queue_bytes`, `build_cos_batch_from_queue`,
    `submit_cos_batch`
  - `cos_surplus_quantum_bytes`, `cos_guarantee_quantum_bytes`,
    `estimate_cos_queue_wakeup_tick`, `count_park_reason`,
    `park_cos_queue`
  - `select_cos_guarantee_batch` + `_with_fast_path` (already
    `#[cfg(test)]` in source — preserve)

## #[inline] (Codex round-1 #5, Gemini round-1 #1)

None of the moving fns currently carry `#[inline]` in source.
Per the Phase 4-6 lesson — `pub(in crate::afxdp)` plus `#[inline]`
preserves cross-module inlining; absent `#[inline]` the compiler
falls back on heuristics that may not survive the cross-module
boundary. v2 commits to ADD `#[inline]` on these per-byte / per-
batch hot-path fns:

- `drain_shaped_tx` (per-poll-cycle entry)
- All `select_cos_*_batch` variants (per drain iteration)
- All `select_exact_cos_guarantee_queue_with_fast_path`
- All `service_exact_*_queue_direct(_flow_fair)` (per drain
  iteration; ~800+ LOC of hot-path code)
- `build_cos_batch_from_queue` (per batch)
- `cos_batch_queue_ref`, `build_nonexact_cos_batch`,
  `submit_cos_batch`
- `cos_guarantee_quantum_bytes`, `cos_surplus_quantum_bytes`
  (per dispatch tick)
- `subtract_direct_cos_queue_bytes` (per dequeue)

The non-hot-path helpers stay un-attributed:
- `select_cos_guarantee_batch_with_fast_path` (test-only)
- `count_park_reason`, `park_cos_queue` (per-park, not per-byte)
- `estimate_cos_queue_wakeup_tick` (per-park)
- The `drain_exact_*_to_scratch` helpers — these are per-drain
  but their bodies are large; LLVM's heuristic threshold should
  cover them. Add `#[inline]` only if a post-merge perf
  regression points at one of them.

## tx.rs changes

- Remove the 6 type definitions + 27 fn definitions (~1900 LOC).
- Bump visibility on the 11+ back-referenced helpers to
  `pub(in crate::afxdp)`.
- Extend cos:: import block with the 1+ production-callable
  re-exports + the cfg-gated set.

## cos/mod.rs additions

```rust
pub(super) mod queue_service;

pub(super) use queue_service::drain_shaped_tx;

#[cfg(test)]
pub(super) use queue_service::{
    select_cos_guarantee_batch, select_cos_guarantee_batch_with_fast_path,
    select_exact_cos_guarantee_queue_with_fast_path,
    select_nonexact_cos_guarantee_batch, select_cos_surplus_batch,
    CoSBatch, ExactCoSQueueSelection,
    // any other type/fn tests reach by name
};
```

(Codex round-2 verifies completeness.)

## worker.rs

- Already has `use super::*` glob plus explicit cos:: imports
  added in earlier phases. After this PR, add `drain_shaped_tx`
  to the explicit `use super::cos::{...}` block.

## Files touched

- **NEW** `userspace-dp/src/afxdp/cos/queue_service.rs`: ~1900 LOC.
- `userspace-dp/src/afxdp/cos/mod.rs`: register module + re-exports.
- `userspace-dp/src/afxdp/tx.rs`: -1900 LOC; bump visibility on
  ~11+ back-referenced helpers; extend cos:: imports.
- `userspace-dp/src/afxdp/worker.rs`: extend cos:: import for
  `drain_shaped_tx`.

## Risk

**High.** Largest move of the campaign (~1900 LOC, 27 fns + 6
types). Touches the absolute hot path: every TX byte goes through
`drain_shaped_tx -> select_cos_*_batch -> service_exact_*_queue_direct
-> drain_exact_*_to_scratch -> submit_cos_batch`.

Risks:
- **Hot-path inline.** v2 explicitly adds `#[inline]` on the
  per-byte/per-batch chain (Codex #5 + Gemini #1).
- **Back-edges.** ~11+ explicit `cos/queue_service -> tx` edges
  for TX-completion + worker-binding helpers. Documented as
  forward-debt.
- **Enum visibility.** `CoSBatch` and `ExactCoSQueueSelection`
  pattern-matched in tx.rs `submit_cos_batch` / TX-completion
  appliers / tests — visibility bumped, re-exports added.
- **Test surface.** ~30+ test sites reach moved fns by name;
  cfg-gated re-exports must cover them.
- **Single-PR size.** ~1900 LOC is a lot. The alternative is
  splitting Phase 7 into 7a (selectors) + 7b (drain/submit), but
  that breaks the policy/mechanism cohesion Gemini round-1
  flagged. Single-PR is the right call here.

## Acceptance

- `cargo build --bins` clean.
- `cargo test --bins` 865/0/2 baseline.
- Cluster smoke per the standard 7-class iperf3 + failover.
- Both reviewers (Codex hostile + Gemini adversarial) sign off.
