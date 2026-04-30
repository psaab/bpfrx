# #956 Phase 6: extract cos/builders.rs from tx.rs

Plan v2 — 2026-04-30. Continues #956 (cos/ submodule decomposition).
Phases 1-5 merged at PRs #976-#980.

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

**Imports needed in cos/builders.rs**:

```rust
use crate::afxdp::types::{
    CoSInterfaceConfig, CoSInterfaceRuntime, CoSQueueRuntime,
    WorkerCoSInterfaceFastPath,
};
use super::admission::apply_cos_queue_flow_fair_promotion;
// build_cos_interface_runtime currently calls cos_tick_for_ns;
// after the move it imports from crate::afxdp::tx
// (parent-module-internal helper, stays in tx.rs through the
// drain-scheduler phase).
use crate::afxdp::tx::cos_tick_for_ns;
```

(Codex round-1 will verify the exact import set — `cos_tick_for_ns`
visibility may need bumping if it's currently private.)

## Approach

Visibility:
- `ensure_cos_interface_runtime` → `pub(in crate::afxdp)`
  (production callers stay in tx.rs).
- `build_cos_interface_runtime` → `pub(in crate::afxdp)` plus
  `#[cfg(test)] pub(super) use` re-export from `cos/mod.rs`
  (3 direct `tx::tests` callers; production caller is
  `ensure_cos_interface_runtime`, also moving).

`#[inline]`: not warranted on either fn — both fire once per
interface bring-up, not on the per-byte path.

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
phases). Clean dependency graph: `cos/builders.rs` →
`cos/admission.rs` → `cos/queue_ops.rs` → `cos/flow_hash.rs`
+ `cos/token_bucket.rs`. No new back-edges.

The deferral of `build_cos_batch_from_queue`, `apply_cos_*_result`,
and `prime_cos_root_for_service` to later phases is documented
in this plan's changelog.

## Acceptance

- `cargo build --bins` clean (no Phase-6 unused-import warnings).
- `cargo test --bins` 865/0/2.
- Cluster smoke per the standard 7-class iperf3 + failover.
- Both reviewers (Codex hostile + Gemini adversarial) sign off.
