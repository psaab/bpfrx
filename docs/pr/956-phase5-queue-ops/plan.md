# #956 Phase 5: extract cos/queue_ops.rs from tx.rs

Plan v2 — 2026-04-29. Continues #956 (cos/ submodule decomposition).

Round-1 changelog (v1 → v2): Codex round-1 returned PLAN-NEEDS-MAJOR
with 3 substantive defects, all addressed in v2:

- R1-1 (visibility): `account_cos_queue_flow_enqueue` / `_dequeue`
  cannot be file-private after the move — `tx::tests` calls them
  directly at 10+ sites (enqueue at tx.rs:10047/10048/10052, 11183/
  11191/11199, 16400/16446/16447/16654; dequeue at tx.rs:10060,
  16402, 16453, 16460). Both are now `pub(in crate::afxdp)` with
  `#[cfg(test)] pub(super) use` re-export from cos/mod.rs (same
  pattern Phase 4 used for test-touched constants).

- R1-2 (back-edge): `cos_queue_v_min_continue` and the V-min
  helpers it uses cannot compile in cos/queue_ops.rs without the
  V-min lag-threshold constants and `compute_v_min_lag_threshold`.
  v2 expands the move list to include:
  - `compute_v_min_lag_threshold` (tx.rs:4987 — only called by
    `cos_queue_v_min_continue` at tx.rs:5086, file-private in cos/queue_ops.rs)
  - `V_MIN_READ_CADENCE` (tx.rs:4977)
  - `V_MIN_LAG_THRESHOLD_NS` (tx.rs:4981)
  - `V_MIN_MIN_LAG_BYTES` (tx.rs:4984)
  - `V_MIN_CONSECUTIVE_SKIP_HARD_CAP` (tx.rs:4996, currently `pub(super)`,
    test-referenced — needs `pub(in crate::afxdp)` + cfg-gated re-export)
  - `V_MIN_SUSPENSION_BATCHES` (tx.rs:5002, currently `pub(super)`,
    test-referenced — same treatment)

- R1-3 (missing cohesive lifecycle fns): two MQFQ/V-min-related
  helpers tightly coupled to the moving set were absent from v1's
  list:
  - `cos_queue_clear_orphan_snapshot_after_drop` (tx.rs:4065,
    private, called from production at tx.rs:2729/2748/2954/2985 —
    keeps snapshot-rollback invariant when bucket is dropped under
    pop/push). Cohesive with `pop_front_inner`. v2 includes it.
    Visibility: `pub(in crate::afxdp)` because all 4 production
    callers stay in tx.rs.
  - `cos_queue_restore_front` (tx.rs:4127, private, called from
    `demote_prepared_cos_queue_to_local` at tx.rs:4807/4811 — pushes
    drained items back when demotion fails). Cohesive with
    `cos_queue_push_front` (which it calls internally) and
    `cos_queue_drain_all`. v2 includes it. Visibility:
    `pub(in crate::afxdp)` because the caller stays in tx.rs.

Move list grew from 16 → 18 fns + 5 named constants + 1 helper fn
(compute_v_min_lag_threshold). Total ~700-800 LOC.


Phase 1 (cos/ecn.rs) shipped at PR #976; Phase 2 (cos/flow_hash.rs)
at PR #977; Phase 3 (cos/admission.rs) at PR #978; Phase 4
(cos/token_bucket.rs) at PR #979. Phase 5 = queue ops (push/pop/
selection) + MQFQ ordering bookkeeping + V-min slot lifecycle.

## Goal

Move 16 functions covering the queue-state lifecycle out of tx.rs
into `userspace-dp/src/afxdp/cos/queue_ops.rs`. Resolves the Phase 3
deferral: `account_cos_queue_flow_enqueue` / `_dequeue` (the MQFQ
finish-time bookkeeping + V-min slot vacate paths) move alongside
`cos_queue_push_back` / `cos_queue_pop_front_inner` so MQFQ and
V-min state stay cohesive in one file. Also moves the V-min publish
helper (`publish_committed_queue_vtime`) and the suspension /
continue gates (`cos_queue_v_min_consume_suspension`,
`cos_queue_v_min_continue`).

## Investigation findings (Claude, on commit ea726fb4)

**Move list (16 fns)** in tx.rs order:

| Item | Current line | Visibility | Production callers (non-test) | Test-only callers |
|---|---|---|---|---|
| `account_cos_queue_flow_enqueue` | 3546 | private | tx.rs:3716 (`cos_queue_push_back`), tx.rs:3738 / 3841 (`cos_queue_push_front`) — all moving | 10 direct sites in `tx::tests` (10047/10048/10052/11183/11191/11199/16400/16446/16447/16654) |
| `account_cos_queue_flow_dequeue` | 3596 | private | tx.rs:4068 (inside `cos_queue_pop_front_inner`, moving) | 4 direct sites in `tx::tests` (10060/16402/16453/16460) |
| `cos_queue_is_empty` | 3636 | `pub(super)` | tx.rs (multiple); admission gates short-circuit on it | none direct — used inside other moving fns |
| `cos_queue_len` | 3644 | `pub(super)` | worker.rs:1 (via super::* glob until Phase 5) | tx.rs tests |
| `cos_queue_min_finish_bucket` | 3671 | private | tx.rs:3949 (inside `cos_queue_pop_front_inner`, moving) | tests |
| `cos_queue_front` | 3685 | `pub(super)` | tx.rs (in select_cos_*_batch paths — staying through Phase 7) | tests |
| `cos_queue_push_back` | 3697 | `pub(super)` | tx.rs (many: enqueue paths) | tests |
| `cos_queue_push_front` | 3731 | `pub(super)` | tx.rs (rollback paths) | tests |
| `cos_queue_pop_front` | 3902 | `pub(super)` | tx.rs (drain paths) | tests |
| `cos_queue_pop_front_no_snapshot` | 3919 | `pub(super)` | worker.rs:1 (via glob); tx.rs | tests |
| `cos_queue_pop_front_inner` | 3926 | private | called by both `pop_front` and `pop_front_no_snapshot` (both moving) | none |
| `cos_queue_drain_all` | 4103 | private | tx.rs:4802 (`demote_prepared_cos_queue_to_local`, stays in tx) | tx.rs:12455 |
| `cos_queue_clear_orphan_snapshot_after_drop` | 4065 | private | tx.rs:2729/2748/2954/2985 (drain paths in tx.rs) | none |
| `cos_queue_restore_front` | 4127 | private | tx.rs:4807/4811 (`demote_prepared_cos_queue_to_local`, stays in tx) | none |
| `publish_committed_queue_vtime` | 4950 | private | tx.rs (TX commit boundaries) | tests |
| `cos_queue_v_min_consume_suspension` | 5015 | private | tx.rs (drain throttle gate) | tests |
| `cos_queue_v_min_continue` | 5051 | private | tx.rs:2693/2921 (drain throttle gate) | tx.rs:16039/16046/16495/16499/16535/16541/16545/16616/16621/16994 |
| `compute_v_min_lag_threshold` | 4987 | private | tx.rs:5086 (only `cos_queue_v_min_continue`, moving) — file-private after move | tx.rs (indirect via v_min_continue) |
| `cos_item_len` | 5409 | private | tx.rs (many — accessor on `CoSPendingTxItem`) | tests |

(Codex round-1 will verify the call-site accounting; the table is
based on a first-pass grep and may still mis-classify
`#[cfg(test)]`-gated sites — same lesson Phase 4 round-1 surfaced.)

**Constants used by the moved fns**:

External (stay in afxdp::types):
- `COS_FLOW_FAIR_BUCKET_MASK` (afxdp::types) — used by
  `cos_queue_push_back` and `pop_front_inner` for bucket-index
  arithmetic.

Moving with this phase (V-min throttle constants — Codex round-1
back-edge fix):

| Item | Line | Visibility | Use sites |
|---|---|---|---|
| `V_MIN_READ_CADENCE` | 4977 | private | only `cos_queue_v_min_continue` body — file-private after move |
| `V_MIN_LAG_THRESHOLD_NS` | 4981 | private | only `compute_v_min_lag_threshold` body — file-private after move |
| `V_MIN_MIN_LAG_BYTES` | 4984 | private | only `compute_v_min_lag_threshold` body — file-private after move |
| `V_MIN_CONSECUTIVE_SKIP_HARD_CAP` | 4996 | `pub(super)` | `cos_queue_v_min_continue` body + tx::tests (16494/16496) — needs `pub(in crate::afxdp)` + `#[cfg(test)] pub(super) use` re-export |
| `V_MIN_SUSPENSION_BATCHES` | 5002 | `pub(super)` | `cos_queue_v_min_continue` body + tx::tests (16502) — same treatment |

## Deferred to later phases

- **Enums `CoSBatch`, `CoSServicePhase`, `ExactCoSQueueKind`** (the
  umbrella plan listed them with Phase 5). They are used heavily by
  `select_cos_*_batch` / `service_exact_*_queue_direct` paths which
  belong to Phase 7 (queue_service). Moving them now without their
  consumers would force a temporary `tx -> queue_ops` import for
  every dispatch site. Phase 7 will move them alongside the
  service-path drain entry points.
- **`cos_item_flow_key`**: already moved to `cos/flow_hash.rs` in
  Phase 2 — referenced here only for completeness.

## Approach

Create `userspace-dp/src/afxdp/cos/queue_ops.rs` with all 16
functions. Visibility classification:

- **`pub(in crate::afxdp)` (cross-module callers)**:
  - `cos_queue_is_empty` (tx.rs production)
  - `cos_queue_len` (worker.rs + tx.rs)
  - `cos_queue_front` (tx.rs production)
  - `cos_queue_push_back` (tx.rs production, many sites)
  - `cos_queue_push_front` (tx.rs production)
  - `cos_queue_pop_front` (tx.rs production)
  - `cos_queue_pop_front_no_snapshot` (worker.rs + tx.rs)
  - `cos_queue_drain_all` (tx.rs production)
  - `publish_committed_queue_vtime` (tx.rs production at TX
    commit boundaries)
  - `cos_queue_v_min_consume_suspension` (tx.rs production drain
    throttle)
  - `cos_queue_v_min_continue` (tx.rs production drain throttle)
  - `cos_item_len` (tx.rs production — small accessor, hot path
    via every push/pop)

- **`pub(in crate::afxdp)` (test-touched — needs cfg-gated
  re-export from cos/mod.rs)** (Codex round-1 R1-1):
  - `account_cos_queue_flow_enqueue` (10 direct test sites)
  - `account_cos_queue_flow_dequeue` (4 direct test sites)
  - `V_MIN_CONSECUTIVE_SKIP_HARD_CAP` (test sites at 16494/16496)
  - `V_MIN_SUSPENSION_BATCHES` (test site at 16502)
  - `cos_queue_min_finish_bucket` (tests exercise directly)
  - `cos_queue_clear_orphan_snapshot_after_drop` (production
    callers all stay in tx.rs at 2729/2748/2954/2985)
  - `cos_queue_restore_front` (production caller
    `demote_prepared_cos_queue_to_local` stays in tx.rs)

- **File-private (post-move)**:
  - `cos_queue_pop_front_inner` (only called by `pop_front` and
    `pop_front_no_snapshot`, both moving)
  - `compute_v_min_lag_threshold` (only called by
    `cos_queue_v_min_continue`, both moving)
  - `V_MIN_READ_CADENCE`, `V_MIN_LAG_THRESHOLD_NS`,
    `V_MIN_MIN_LAG_BYTES` (only consumed inside the V-min
    helper bodies, all moving)

- **`#[inline]`** (Phase 4 lesson — hot-path moves get explicit
  inline hints):
  - All 12 cross-module-callable fns above EXCEPT
    `cos_queue_drain_all` (called once per queue-rebuild) and
    `cos_queue_v_min_consume_suspension` (called once per drain
    iteration) carry `#[inline]`. The 3 file-private helpers also
    carry `#[inline]` because they're inside per-byte hot paths
    (`account_*` is per-enqueue/dequeue; `pop_front_inner` is
    per-dequeue).

### Imports

```rust
// cos/queue_ops.rs prelude (subject to Codex round-1 verification)
use std::collections::VecDeque;

use crate::afxdp::types::{
    CoSPendingTxItem, CoSQueueRuntime, COS_FLOW_FAIR_BUCKET_MASK,
};
use crate::session::SessionKey;     // account_*, push_back, pop need
                                     // SessionKey for flow-key extraction
                                     // (cos_item_flow_key returns SessionKey)

use super::flow_hash::{cos_flow_bucket_index, cos_item_flow_key};
```

### cos/mod.rs additions

```rust
pub(super) mod queue_ops;

pub(super) use queue_ops::{
    cos_item_len, cos_queue_drain_all, cos_queue_front,
    cos_queue_is_empty, cos_queue_len, cos_queue_min_finish_bucket,
    cos_queue_pop_front, cos_queue_pop_front_no_snapshot,
    cos_queue_push_back, cos_queue_push_front,
    cos_queue_v_min_consume_suspension, cos_queue_v_min_continue,
    publish_committed_queue_vtime,
};
```

(The 12-entry `pub(super) use` block — `cos_queue_min_finish_bucket`
moves to a `#[cfg(test)] pub(super) use` block if the verification
shows no production caller.)

### tx.rs

- Remove the 16 fn definitions.
- Extend the existing `use super::cos::{...}` block to include the
  12 production-callable fns.
- Test-only fns (e.g., `cos_queue_min_finish_bucket` if test-only)
  go under the `#[cfg(test)]` import block already established
  by Phase 4.

### worker.rs

- worker.rs reaches `cos_queue_len` and `cos_queue_pop_front_no_snapshot`
  via the `use super::*;` glob today. After the move, add to the
  Phase 4 `use super::cos::{...}` line:
  ```rust
  use super::cos::{
      cos_queue_len, cos_queue_pop_front_no_snapshot,
      release_all_cos_queue_leases, release_all_cos_root_leases,
  };
  ```

## Files touched

- **NEW** `userspace-dp/src/afxdp/cos/queue_ops.rs`: ~600-700 LOC.
- `userspace-dp/src/afxdp/cos/mod.rs`: register new module + 12
  re-exports.
- `userspace-dp/src/afxdp/tx.rs`: -600-700 LOC; extend cos:: imports.
- `userspace-dp/src/afxdp/worker.rs`: extend cos:: imports.

## Tests

No new tests required — pure structural refactor. Existing
`tx::tests` exercise:
- The `account_cos_queue_flow_*` lifecycle (test sites at
  tx.rs:1654 / 1643 inside the `#[cfg(test)]` legacy selector at
  tx.rs:1625-1626).
- `cos_queue_push_back` / `pop_front` / `front` / `len` / `is_empty`
  via dozens of admission and CoS pacing tests.
- `cos_queue_min_finish_bucket` via the MQFQ head-ordering pin
  tests.
- `publish_committed_queue_vtime` / `cos_queue_v_min_*` via the
  V-min coordination tests added in #940-#942.

After the move, all tests reach the moved fns via the
`use super::cos::{...}` re-exports — same Phase 1+2+3+4 pattern.

## Phase-1+2+3+4 stale-text cleanup

- `cos/admission.rs:18-22` — Phase 3 deferred-rationale paragraph
  for `account_cos_queue_flow_*`. Switch to past tense: "Phase 5
  moved them into cos/queue_ops.rs alongside the rest of the MQFQ
  + V-min state, as planned."
- `cos/mod.rs:1-7` — phase-order header. Update to call out Phase 5
  as the current state.
- `tx.rs` cos-imports comment block (3472+) — bump phase note.

## Risk

**Medium-high.** Largest move so far (~600-700 LOC vs ~600 in
Phase 3 and ~175 in Phase 4) and touches the absolute hottest path
in the dataplane: every TX byte goes through
`cos_queue_push_back` (or `_front` on rollback) and
`cos_queue_pop_front_inner` on dequeue. Risks:

- **Hot-path inline cost.** Every per-byte fn that moves carries
  `#[inline]`; verify post-move that `cargo build --release`
  generates the same call-site inlining as pre-move (Phase 4's
  lesson — `pub(in crate::afxdp)` plus `#[inline]` should preserve
  cross-module inlining).
- **MQFQ + V-min state cohesion.** The `account_*` helpers maintain
  `flow_bucket_head/tail_finish_bytes` (MQFQ) and `vtime_floor`
  (V-min); they MUST land in the same file as `cos_queue_push_back`
  / `cos_queue_pop_front_inner` / `publish_committed_queue_vtime`
  to keep the invariants visible together. This is the cohesion
  Gemini round-1 of Phase 3 demanded.
- **Test surface.** `tx::tests` has ~30+ sites that call the moving
  fns by name; they all need to keep compiling via the cos:: re-
  exports. `cos_queue_min_finish_bucket` may need cfg-gated re-
  export if no production caller (Codex round-1 to verify).
- **Deferred enums.** Plan defers `CoSBatch`/`CoSServicePhase`/
  `ExactCoSQueueKind` to Phase 7. They don't appear in the moving
  fns' bodies — verify by grep before commit.

The core design is the same successful pattern Phases 1-4
validated: `pub(in crate::afxdp)` source items + `pub(super) use`
re-exports + tests stay in `tx::tests` with `#[cfg(test)]` gating
where appropriate.

## Acceptance criteria

- `cargo build --bins` clean (no Phase-5 unused-import warnings).
- `cargo test --bins` passes the same 865/0/2 baseline as Phase 4.
- `cluster-setup.sh deploy` rolls successfully on
  `loss-userspace-cluster.env`; `apply-cos-config.sh` applies the
  per-class iperf3 config.
- Per-CoS-class iperf3 smoke (memory: refactor PRs must validate
  every configured class):
  - port 5201 / iperf-a / 1G shaper: ≥ 0.85 Gbps, ≤ 50 retrans
  - port 5202 / iperf-b / 10G shaper: ≥ 8 Gbps, 0 retrans
  - port 5203 / iperf-c / 25G shaper: ≥ 10 Gbps, ≤ 1k retrans
  - port 5204 / iperf-d / 13G shaper: ≥ 10 Gbps
  - port 5205 / iperf-e / 16G shaper: ≥ 12 Gbps
  - port 5206 / iperf-f / 19G shaper: ≥ 12 Gbps
  - port 5207 / best-effort / 100M shaper: ≥ 0.07 Gbps
- Failover smoke (RG1 cycled twice): zero 0-bps SUM intervals;
  ≥ 95% of intervals at ≥ 3 Gbps.
- Plan + impl signed off by both Codex (`gpt-5.5` xhigh) and
  Gemini.
