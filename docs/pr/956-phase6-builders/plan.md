# #956 Phase 6: extract cos/builders.rs from tx.rs

Plan v3 — 2026-04-30. Continues #956 (cos/ submodule decomposition).
Phases 1-5 merged at PRs #976-#980.

Round-2 changelog (v2 → v3): Codex round-2 returned PLAN-NEEDS-MAJOR
with 3 concrete fixes; Gemini round-2 returned PLAN-READY (accepting
the narrow approach):

- Codex #1 (#[inline]): v2 wrongly claimed both moved fns are
  bring-up-only. `ensure_cos_interface_runtime` sits on the
  steady-state enqueue path (callers at tx.rs:3948/4077/4298/4308)
  and already carries `#[inline]`. The move must preserve it. v3
  flips the inline note.
- Codex #2 (imports incomplete): the planned cos/builders.rs
  import block missed `BindingWorker`, `ForwardingState`,
  `FlowRrRing`, `CoSTimerWheelRuntime`, `CoSQueueDropCounters`,
  `CoSQueueOwnerProfile`, `COS_PRIORITY_LEVELS`,
  `COS_FLOW_FAIR_BUCKETS`, `TX_BATCH_SIZE`, `VecDeque`. Listed
  `WorkerCoSInterfaceFastPath` was unused. v3 has the complete
  surface.
- Codex #3 (Risk-section contradiction): v2's Risk text said "No
  new back-edges" while the import discussion documented the
  `cos_tick_for_ns` back-edge two paragraphs earlier. v3 reworded.

Round-1 changelog (v1 → v2): Codex round-1 returned PLAN-NEEDS-MAJOR
("scope too broad — narrow to interface-runtime") and Gemini round-1
returned PLAN-NEEDS-MAJOR ("expand scope to include the full CoS
runtime: timer wheel + activity refresh + completion helpers +
state management"). The two reviewers diverged.

v2 takes Codex's narrow-scope recommendation. Gemini's expand-scope
alternative would roll Phase 6 into ~Phase 6 + 7 + a deferred
drain-scheduler phase — a single ~1500+ LOC PR touching the absolute
hottest tx.rs paths. The narrow approach lands a clean 2-fn extraction
now, with the larger consolidation explicitly deferred.

The umbrella plan's 5-fn list mixed three architectural categories
together. v2 narrows Phase 6 to ONLY the interface-runtime
construction pair and defers the rest:

- **Drop `build_cos_batch_from_queue`** → defer to Phase 7
  (queue_service). It mutates the queue (`cos_queue_pop_front` +
  rollback push) and uses the private `CoSBatch` /
  `CoSServicePhase` enums (tx.rs:771, 776). Architecturally a
  queue-service primitive, not a builder. Co-move with the
  enums when Phase 7 lands.
- **Drop `apply_cos_send_result` + `apply_cos_prepared_result`**
  → keep in tx.rs. They depend on `refresh_cos_interface_activity`
  (tx.rs:4590), restore helpers (tx.rs:4805/4820), and pair with
  the un-listed `apply_direct_exact_send_result` (tx.rs:3171).
  Moving them in isolation would force moving 3+ neighboring
  helpers — scope creep. Defer to a future "TX-completion"
  extraction (likely between Phase 7 and Phase 8).
- **Drop `prime_cos_root_for_service`** → keep in tx.rs. It
  calls `advance_cos_timer_wheel` (tx.rs:3702 → uses private
  timer-wheel constants `COS_TIMER_WHEEL_TICK_NS` /
  `COS_TIMER_WHEEL_L0_HORIZON_TICKS` etc.). Codex Phase 4 noted
  the timer-wheel constants belong with the deferred
  drain-scheduler phase; this fn does too.

Phase 6 is now tight: 2 fns covering interface-runtime
construction.

## Goal

Move 2 builder fns out of tx.rs into
`userspace-dp/src/afxdp/cos/builders.rs`:

- `ensure_cos_interface_runtime` (tx.rs:4299) — production
  caller for binding lifecycle (binds new ifindex → constructs
  + promotes runtime). Calls `build_cos_interface_runtime` and
  `apply_cos_queue_flow_fair_promotion` (already in
  cos/admission.rs).
- `build_cos_interface_runtime` (tx.rs:4339) — pure constructor
  from `CoSInterfaceConfig`. Called once by
  `ensure_cos_interface_runtime` and 3 times in `tx::tests`
  (5972, 9124, 9169) — needs `pub(in crate::afxdp)` plus
  `#[cfg(test)]` re-export for the test sites.

This focused scope keeps the cos/builders.rs boundary clean:
"build a CoSInterfaceRuntime from config; promote queues onto
the flow-fair path." Nothing else.

## Investigation findings (Claude, on commit 78b68219)

**Move list (2 fns)**:

| Item | Line | Visibility | Production callers | Test callers |
|---|---|---|---|---|
| `ensure_cos_interface_runtime` | 4299 | private | tx.rs:3948, 4077 | none |
| `build_cos_interface_runtime` | 4339 | private | called by `ensure_cos_interface_runtime` (moving) at tx.rs:4324; production caller list contains only that one site | tx.rs:5972 / 9124 / 9169 (`#[cfg(test)] mod tests` at tx.rs:5425) |

**Imports needed in cos/builders.rs** (Codex round-2 verified the
full surface — v2's list was incomplete):

```rust
use std::collections::VecDeque;

use crate::afxdp::types::{
    BindingWorker, CoSInterfaceConfig, CoSInterfaceRuntime,
    CoSQueueDropCounters, CoSQueueOwnerProfile, CoSQueueRuntime,
    CoSTimerWheelRuntime, FlowRrRing, ForwardingState,
    COS_FLOW_FAIR_BUCKETS, COS_PRIORITY_LEVELS, TX_BATCH_SIZE,
};
use super::admission::apply_cos_queue_flow_fair_promotion;
// build_cos_interface_runtime calls cos_tick_for_ns. The helper
// stays in tx.rs through the drain-scheduler phase; this PR bumps
// its visibility to pub(in crate::afxdp) so cos/builders.rs can
// reach it. ONE explicit back-edge from cos -> tx, documented
// as drain-scheduler-phase forward-debt — same shape Phase 3
// originally had with COS_MIN_BURST_BYTES (which Phase 4 then
// resolved by relocating the constant).
use crate::afxdp::tx::cos_tick_for_ns;
```

`WorkerCoSInterfaceFastPath` was in v2's import list but is NOT
referenced by either moving fn (Codex round-2 catch). Removed.

## Approach

Visibility:
- `ensure_cos_interface_runtime` → `pub(in crate::afxdp)`
  (production callers stay in tx.rs).
- `build_cos_interface_runtime` → `pub(in crate::afxdp)` plus
  `#[cfg(test)] pub(super) use` re-export from `cos/mod.rs`
  (3 direct `tx::tests` callers; production caller is
  `ensure_cos_interface_runtime`, also moving).

`#[inline]` (Codex round-2 #1 corrected v2's wrong claim):
`ensure_cos_interface_runtime` is NOT bring-up-only. It sits on
the steady-state enqueue path — production callers at tx.rs:3948,
4077, 4298, 4308 — and already carries `#[inline]` in source.
The move MUST preserve that attribute (per the Phase 4/5 hot-path
inline lesson). `build_cos_interface_runtime` is a one-shot
constructor and stays without `#[inline]` (matches its current
state in tx.rs).

`tx.rs` import additions:
```rust
use super::cos::{ensure_cos_interface_runtime};
#[cfg(test)]
use super::cos::build_cos_interface_runtime;
```

## Files touched

- **NEW** `userspace-dp/src/afxdp/cos/builders.rs`: ~80-120 LOC.
- `userspace-dp/src/afxdp/cos/mod.rs`: register module + re-exports.
- `userspace-dp/src/afxdp/tx.rs`: -80-120 LOC; extend cos:: imports
  (production block + cfg-gated block).
- `userspace-dp/src/afxdp/tx.rs`: bump `cos_tick_for_ns` visibility
  to `pub(in crate::afxdp)` so `cos/builders.rs` can call it.

## Tests

No new tests required — pure structural refactor. The 3 direct
test sites at tx.rs:5972/9124/9169 reach `build_cos_interface_runtime`
through the cfg-gated re-export.

## Phase-1+2+3+4+5 stale-text cleanup

- `cos/mod.rs:1-7` — phase-order header. Update to call out
  Phase 6 as the current state.
- `tx.rs` cos-imports comment block — bump phase note.

## Risk

**Low.** Smallest move yet (~100 LOC vs 600-800 in earlier
phases). Forward dependencies clean: `cos/builders.rs` →
`cos/admission.rs` → `cos/queue_ops.rs` → `cos/flow_hash.rs`
+ `cos/token_bucket.rs`. ONE back-edge introduced
(`cos/builders -> tx::cos_tick_for_ns`), documented above as
drain-scheduler-phase forward-debt. Codex round-2 caught the
earlier "No new back-edges" wording in this section — it
contradicted the back-edge already documented in the import
discussion. Corrected.

The deferral of `build_cos_batch_from_queue`, `apply_cos_*_result`,
and `prime_cos_root_for_service` to later phases is documented
in this plan's changelog.

## Acceptance

- `cargo build --bins` clean (no Phase-6 unused-import warnings).
- `cargo test --bins` 865/0/2.
- Cluster smoke per the standard 7-class iperf3 + failover.
- Both reviewers (Codex hostile + Gemini adversarial) sign off.
