# 039 — A1c CoS (queue_service + queue_ops + shared_cos_lease + types/cos) — Modularity Audit

**Date:** 2026-07-08
**Base:** f70146951583823a5ace87b0b11a2e58f46e8db9
**Batch:** A1c — CoS
**Auditor:** claude / automated
**Engineering style:** docs/engineering-style.md read

---

## 0. File-size / shape inventory

| File | LOC (prod) | LOC (test) | Notes |
|------|-----------|------------|-------|
| `userspace-dp/src/afxdp/types/cos.rs` | **1786** | 96 (inline tests) | 8 structs + 4 enums + constants; FlowFairState ~352 KB boxed; CoSInterfaceRuntime 28 fields |
| `userspace-dp/src/afxdp/types/shared_cos_lease/mod.rs` | 92 | — | Thin re-export shell (good) — post #2158 split |
| `shared_cos_lease/backlog.rs` | 210 | — | 1 public struct + 2 `#[repr(align(64))]` inner pads. Cohesive. |
| `shared_cos_lease/vtime.rs` | 238 | — | PaddedVtimeSlot + SharedCoSQueueVtimeFloor. Cohesive. |
| `shared_cos_lease/epoch.rs` | 565 | — | V8State, SharedCoSEpochState, PackedEpochGrant, PaddedAtomic*, V8EqualFlowSuppressState, V8RotationScratch, 2 enums, 9 consts. Mixed granularity. |
| `shared_cos_lease/lease.rs` | **1460** | — | Legacy lease + v8 fair-share + acquire_v8 + snapshot + equal-flow cap. God-file within the lease cluster. |
| `shared_cos_lease/rotate_epoch_v8.rs` | 446 | — | Seqlock rotation, 3 regime carry, bypass-grace, fair-share publish. Self-contained. |
| `shared_cos_lease/publish_equal_flow_epoch_v8.rs` | 247 | — | Equal-flow target calc. Self-contained. |
| `shared_cos_lease/shared_cos_lease_tests.rs` | — | 2511 | CoV + greps |
| `afxdp/cos/queue_service/mod.rs` | **2058** | — | drain_shaped_tx, selectors, waterfill (438 LOC), build_cos_batch, settle*, waterfill refund, quantum helpers |
| `queue_service/drain.rs` | 608 | — | drain_exact_*_to_scratch (4 variants) |
| `queue_service/service.rs` | 718 | — | service_exact_*_queue_direct |
| `queue_service/submit_local.rs` | 194 | — | submit_local |
| `queue_service/submit_prepared.rs` | 177 | — | submit_prepared |
| `queue_service/tests.rs` | — | 4384 | 2.1× prod (4384 vs 3755 prod total) |
| `afxdp/cos/queue_ops/mod.rs` | 408 | — | cos_queue_min_finish_bucket (both variants), peek, front, maybe_demote, constants, len/empty |
| `queue_ops/accounting.rs` | 188 | — | flow enqueue/dequeue accounting |
| `queue_ops/active_buckets.rs` | 110 | — | active-bucket transition helpers (single-writer-per-slot) |
| `queue_ops/drain.rs` | 107 | — | drain_all, clear_orphan, restore_front |
| `queue_ops/pop.rs` | 294 | — | pop_front, pop_front_no_snapshot, pop_known_bucket |
| `queue_ops/push.rs` | 506 | — | push_back, push_front |
| `queue_ops/v_min.rs` | 280 | — | v_min_continue, v_min_consume, publish_committed |
| `queue_ops/tests.rs` | — | 1749 | generic queue_ops tests |
| `queue_ops/pop_tests.rs` | — | 2060 | MQFQ flow-fair pinning |
| `queue_ops/v_min_tests.rs` | — | 1992 | V_min throttle / hard-cap |
| `queue_ops/fused_diff_tests.rs` | — | 687 | fused peek+pop vs double-scan differential oracle |
| **queue_ops prod total** | **1893** | **6488 test** | **3.4× test/prod** |
| `afxdp/cos/tx_completion.rs` | **1080** | — | timer-wheel + TX-completion apply + prime + restore + wake/cascade |

Modularity threshold per `engineering-style.md`: ~2,000 LOC prod is a smell, ~3,000 should split before next feature. `types/cos.rs` (1786) is under but trending, `queue_service/mod.rs` (2058) crosses, `lease.rs` (1460) under but within a 3258-LOC cluster that still has a god file.

---

## Finding 1 — CoSInterfaceRuntime god-struct (mixed hot/cold, no cache isolation) — (B) Should-Fix

**Severity:** Medium
**Confidence:** High
**Refactor class:** (B) — structural debt, not blocking, should split before next waterfill change

**Evidence:**

`types/cos.rs:556-709` — `CoSInterfaceRuntime` has 28 fields mixing 5 distinct lifecycles:

```rust
pub(in crate::afxdp) struct CoSInterfaceRuntime {
    pub(in crate::afxdp) shaping_rate_bytes: u64,
    pub(in crate::afxdp) burst_bytes: u64,
    pub(in crate::afxdp) tokens: u64,                                   // (1) token bucket
    pub(in crate::afxdp) nonexact_surplus_under_exact_tokens: u64,      // (1) residual surplus bucket
    pub(in crate::afxdp) nonexact_surplus_under_exact_last_refill_ns: u64,
    pub(in crate::afxdp) default_queue: u8,                             // (2) config/routing
    pub(in crate::afxdp) nonempty_queues: usize,                         // (2) bookkeeping
    pub(in crate::afxdp) runnable_queues: usize,
    pub(in crate::afxdp) oversubscription_policy: CoSOversubscriptionPolicy, // (3) waterfill policy
    pub(in crate::afxdp) oversubscription_guarantee_fraction: f64,
    pub(in crate::afxdp) priority_low_min_share_bytes: u64,             // WIRE-SURFACE-ONLY unused
    pub(in crate::afxdp) priority_low_reserved_tokens: u64,            // UNUSED reserved
    pub(in crate::afxdp) priority_low_last_refill_ns: u64,             // UNUSED reserved
    pub(in crate::afxdp) exact_queues_by_rate_ascending: Vec<usize>,    // (3) waterfill index
    pub(in crate::afxdp) waterfill_pass1_remaining_bytes: u64,          // (3) waterfill epoch
    pub(in crate::afxdp) waterfill_phase2_cursor: usize,
    pub(in crate::afxdp) waterfill_honored_epoch_bits: u64,
    pub(in crate::afxdp) waterfill_epochs: u64,
    pub(in crate::afxdp) waterfill_phase1_budget_breaks: u64,
    pub(in crate::afxdp) waterfill_epoch_start_ns: u64,
    pub(in crate::afxdp) waterfill_epoch_wrap_pending: bool,
    pub(in crate::afxdp) exact_guarantee_rr: usize,                     // (4) RR cursors
    pub(in crate::afxdp) nonexact_guarantee_rr: usize,
    pub(in crate::afxdp) queues: Vec<CoSQueueRuntime>,                  // (2)
    pub(in crate::afxdp) queue_indices_by_priority: [Vec<usize>; 6],    // (4) surplus DRR
    pub(in crate::afxdp) rr_index_by_priority: [usize; 6],
    pub(in crate::afxdp) timer_wheel: CoSTimerWheelRuntime,             // (5) timer wheel (cold)
}
```

- No `#[repr(align(64))]` or grouping. Contrast `SharedCoSLeaseState`, `PaddedBacklogSlot`, `PackedEpochGrant`, `PaddedVtimeSlot` — all `#[repr(align(64))]` with explicit padding to avoid false-sharing. `CoSInterfaceRuntime` is single-writer (owner worker) so cross-core false-sharing is not the issue, but intra-worker cache locality is: every `select_*` walk touches `tokens`, `waterfill_*`, `queues`, `queue_indices_by_priority` — 28 fields spanning >2 cache lines with dead `priority_low_*` (3 fields, 24 bytes) in the middle of the hot struct.
- 3 WIRE-SURFACE-ONLY / UNUSED fields (`priority_low_min_share_bytes`, `priority_low_reserved_tokens`, `priority_low_last_refill_ns`) are documented as `Currently UNUSED` in the same file (lines 573-588) and confirmed by grep: only referenced in `types/cos.rs` field defs + builder copy, never read on hot path. They occupy cache-line space in a hot struct for a deferred feature.
- `CoSInterfaceRuntime` combines token bucket, waterfill epoch, RR cursors, surplus DRR indices, timer wheel, and config — 5 responsibilities. The waterfill state alone is 7 fields + 1 Vec, moved as a unit across 3 sites (`select_exact_cos_guarantee_queue_waterfill`, `refund_phase1_waterfill_honor`, `apply_phase1_waterfill_honor_refund`).
- `FlowFairState` (`types/cos.rs:922-1095`) is correctly boxed via `new_boxed` to avoid 352 KB stack frames (#1755), but `CoSInterfaceRuntime` itself is not cache-line aware — its `Vec<CoSQueueRuntime>` lives on heap but the inline struct (tokens + waterfill + RR + timer_wheel) is contiguous and hot.

Count from `types/cos.rs`:
- `CoSInterfaceConfig`: 11 fields (ok)
- `CoSInterfaceRuntime`: 28 fields (god-struct)
- `CoSQueueConfigState`: 9 fields (ok)
- `CoSQueueHotState`: 9 fields + VecDeque (ok)
- `FlowFairState`: 13 fields + huge arrays (justified, boxed)
- `VMinQueueState`: 8 fields (ok)
- `CoSQueueTelemetry`: 4 sub-structs (ok)

**Proposed decomposition:**

1. Extract waterfill epoch state into a new `CoSInterfaceWaterfillState` struct (7 fields + Vec + counters) — lives in `types/cos/waterfill.rs` or inline in `types/cos.rs` as a named sub-struct:

```rust
pub(in crate::afxdp) struct CoSInterfaceWaterfillState {
    exact_queues_by_rate_ascending: Vec<usize>,
    pass1_remaining_bytes: u64,
    phase2_cursor: usize,
    honored_epoch_bits: u64,
    epochs: u64,
    phase1_budget_breaks: u64,
    epoch_start_ns: u64,
    epoch_wrap_pending: bool,
}
```

2. Group token-bucket fields into `CoSInterfaceTokenState` (tokens, burst, shaping_rate, nonexact_surplus bucket).

3. Group RR cursors into `CoSInterfaceRrState` (exact_guarantee_rr, nonexact_guarantee_rr, queue_indices_by_priority, rr_index_by_priority).

4. Remove or `#[cfg]`-gate the 3 `priority_low_*` UNUSED fields, or move them into a `CoSInterfaceReserved` cold struct behind a feature flag so they don't pollute cache lines.

5. Add `#[repr(C)]` field ordering comment documenting hot-fields-first (tokens, waterfill, queues, RR, timer_wheel last).

This keeps `CoSInterfaceRuntime` as a façade with 5 named sub-structs, each testable in isolation and each clearing one responsibility.

**Hot-path preservation:**

- Single-writer (owner worker) — plain `u64` counters stay plain, no atomics.
- No heap alloc on TX path: `exact_queues_by_rate_ascending` already `Vec` built at promotion time; waterfill state refactor does not add allocation.
- Waterfill epoch logic unchanged — only field path prefix changes (`root.waterfill.pass1_remaining` vs `root.waterfill_pass1_remaining_bytes`).
- `priority_low_*` removal is zero-behavior: grep confirms no hot-path reads; if kept, move to cold struct at end of `CoSInterfaceRuntime` so hot prefix fits in fewer cache lines.
- QoS guarantee-guard correctness (#4246): waterfill refund + Phase-1 honor bit semantics preserved byte-for-byte; only struct nesting changes. Differential test: `cargo test --lib -- cos::queue_service::tests::waterfill` must remain green; `fused_diff_tests` proves no selection drift.

**Tests + gate:**

- Unit: existing `queue_service/tests.rs` waterfill epoch tests (6 tests pinning Phase-1/Phase-2 interaction, honored bit persistence, time-tick vs pass1==0 refill, Phase-1 refund). Must stay green.
- New: unit test that `CoSInterfaceWaterfillState::default()` matches zeroed fields of old struct (field-equivalence guard like `flow_fair_state_tests::new_boxed_matches_new`).
- CoS smoke: `make test` (Go + Rust); `loss:xpf-userspace-fw0` CoS iperf `iperf3 -P 16 -t 30 -p 5203 → 172.16.80.200` ≥23 Gbit/s, no regression; `show class-of-service interface` `waterfill_counters` move in predicted direction per `cos-validation-notes.md`.

**Why it matters:**

- Next waterfill change will touch 3 fields in a 28-field struct with no grouping — review misses spillover. The 3 UNUSED fields already misled one diagnostic (thinking `priority_low_min_share_bytes` was enforced, while the only enforcement site was never wired — #4220 honest comment).
- Cache-line efficiency: hot `select_exact_cos_guarantee_queue_waterfill` loads 7 waterfill fields + tokens on every call; moving 3 dead fields out saves one cache-line load and clarifies what's actually read.

**Fix direction:** Extract `CoSInterfaceWaterfillState`, `CoSInterfaceTokenState`, `CoSInterfaceRrState` as plain `struct`s in `types/cos.rs` (or `types/cos/interface/*.rs` if file crosses 2000 LOC after). Gate `priority_low_*` behind `#[cfg(feature="priority-low-min-share")]` or move to end/cold struct. No behavior change.

**Labels:** `refactor`, `modularity`, `cos`, `B-priority`

**Dedup note:** Not filed before. Related: #4408 (waterfill god-func) touches the waterfill *selector* function; this filing touches the waterfill *state container* (god-struct). Complementary.

---

## Finding 2 — queue_service/mod.rs waterfill selector god-function — (D) Duplicate + new angle (well-split since #1035, remaining debt tracked)

**Severity:** Low (already filed)
**Confidence:** High
**Refactor class:** (D) — already tracked as #4408, no new filing needed; confirm and add decomposition hint

**Evidence:**

`queue_service/mod.rs:925-1357` — `select_exact_cos_guarantee_queue_waterfill` measures **432 LOC** (925→1357 inclusive) inside a 2058-LOC file:

```
880  // #1614 A1: two-phase waterfill selector ...
925  fn select_exact_cos_guarantee_queue_waterfill(
926      root: &mut CoSInterfaceRuntime,
...
932      ... // Phase 1 epoch refill + raw_pass1 calc + f64→u64 fraction math + clamp
1018     // Phase 1: ascending walk
1052     for i in 0..ascending_len {
...
1226     }
1227     // Phase 2: descending walk
1238     let mut phase2_idx = root.waterfill_phase2_cursor;
...
1345     }
1346     // Genuine Phase-2 WRAP
1353     root.waterfill_pass1_remaining_bytes = 0;
1354     root.waterfill_phase2_cursor = 0;
1355     root.waterfill_epoch_wrap_pending = true;
1356     None
1357 }
```

Counted responsibilities (all in one function):

1. Epoch refill trigger (time-based `elapsed >= COS_GUARANTEE_VISIT_NS` OR `pass1 == 0`)
2. `raw_pass1` computation — two branches (shaped root `cap_per_epoch * fraction` vs transparent `quantum_sum * fraction`), with `f64::floor() as u64` truncation
3. Clamp to `COS_GUARANTEE_QUANTUM_MIN_BYTES` (AGY RISK-1 fix)
4. Honored bitset clear gating (`epoch_boundary = time_refresh || wrap_pending`)
5. Phase-1 ascending walk (lease top-up, token gates, park, telemetry, honor + bit set, budget debit)
6. Phase-2 descending walk (honored skip, lease top-up, token gates, cursor advance, telemetry)
7. Phase-2 WRAP reset (zero budget, reset cursor, arm wrap_pending)

**Measurable sub-smell:** The `f64` fraction path (lines 965-1001) is 37 LOC of float math + comments that could be unit-tested in isolation; currently covered only indirectly via end-to-end waterfill tests.

**Proposed decomposition (if/when #4408 is implemented):**

- `queue_service/waterfill_refill.rs` — `fn refill_waterfill_epoch(root, now_ns) -> bool` (returns whether epoch_boundary); own the `raw_pass1` calc + clamp + bitset clear.
- `queue_service/waterfill_phase1.rs` — `fn waterfill_phase1_ascending(root, queue_fast_path, now_ns, telemetry) -> Option<Selection>`
- `queue_service/waterfill_phase2.rs` — `fn waterfill_phase2_descending(root, ...) -> Option<Selection>`
- `select_exact_cos_guarantee_queue_waterfill` becomes ~40 LOC orchestrator: `if refill { } ; phase1.or_else(phase2).or_else(wrap)`

This mirrors the existing `#1035 P2/P3` split pattern (`drain.rs`, `service.rs`, `submit_local.rs`, `submit_prepared.rs`) that already broke 800+ LOC off `queue_service/mod.rs`.

**Hot-path preservation:** All helpers `#[inline]`, take `&mut CoSInterfaceRuntime`, no alloc, no new atomic, `f64` math stays in refill (cold-ish epoch boundary, not per-packet).

**Tests+gate:** Existing waterfill tests must stay green; add unit test for `refill_waterfill_epoch` covering transparent vs shaped root, tiny-fraction clamp, `time_refresh` vs `exhausted` vs `wrap_pending` bitset clear matrix.

**Why this filing is (D):** #4408 already filed the same 438-LOC god-func. No new GitHub issue. This note adds the `f64` fraction extraction angle and confirms the measurement (432 LOC, not 438 — drift from subsequent livelock fixes #1743 r3). Modularity discipline says split before next waterfill feature; current file is 2058 LOC (just over 2000 smell line) but was  ~3000 before #1035 split, so trending correctly.

**Labels:** `modularity`, `cos`, `D-duplicate`

**Dedup note:** #4408 `cos/queue_service waterfill (438 LOC) — ALREADY FILED`. Confirm accurate, add refill-extraction nuance.

---

## Finding 3 — shared_cos_lease cluster: backlog + vtime well-split (D-good), lease.rs still monolithic (C) — Mixed

**Severity:** Low (lease.rs trending) + None (backlog/vtime good)
**Confidence:** High
**Refactor class:** (D) for backlog/vtime/rotate/publish — well-modularized, no action; (C) for lease.rs — nice-to-have split when next v8 feature lands

**Evidence:**

**Good — backlog.rs (210 LOC) + vtime.rs (238 LOC) are exemplary:**

```rust
// backlog.rs — single struct, self-contained, no sibling reach, two repr(align(64)) inner pads
pub(in crate::afxdp) struct SharedCoSExactBacklog {
    worker_bytes: Box<[PaddedBacklogSlot]>,
    residual_budget: PaddedResidualBudget,
}
// vtime.rs — single coordination struct, self-contained, 64-byte aligned slots, sentinel clamping
pub(in crate::afxdp) struct SharedCoSQueueVtimeFloor {
    slots: Box<[PaddedVtimeSlot]>,
}
```

- Each file: one public type, 2-3 `impl` methods, no visibility widening needed (split commit message says "no visibility widening" for both). This is the template for good splits.
- Size: 210 + 238 = textbook small modules. Retain this shape.

**Trending — lease.rs (1460 LOC) still carries two disjoint lifecycles:**

- Legacy lease (lines 1-330): `SharedCoSLeaseConfig`, `SharedCoSLeaseState`, `pack/unpack`, `shared_cos_lease_acquire/release/consume`, `SharedCoSRootLease`, `SharedCoSQueueLease::new`
- v8 fair-share (lines 349-1460): `new_v8*`, `matches_config_v8`, `acquire_v8`, `acquire_v8_with_cause`, `snapshot_epoch_v8`, `try_bump_outstanding`, `tag_checked_rollback`, `equal_flow_cap_v8`, `v8_worker_claim_flow`, 6 per-worker atomic arrays

The file header itself documents the tension:

> `lease.rs` — "the `SharedCoS{Queue,Root}Lease` token bucket + the v8 per-worker fair-share acquire path"

That's two modules described as one.

**Good — rotate_epoch_v8.rs (446 LOC) + publish_equal_flow_epoch_v8.rs (247 LOC) are well-scoped:**

- Each is a single `impl SharedCoSQueueLease` method extracted via pure code-motion (PR #1588), self-contained, no heap alloc on hot path, seqlock ordering preserved. Retain.

**Good — epoch.rs (565 LOC) is mixed but tolerable:**

- Contains `V8State` + `SharedCoSEpochState` + `PackedEpochGrant` + `PaddedAtomic*` + `V8EqualFlowSuppressState` + `V8RotationScratch` + enums + constants. All are epoch-state, so one file is defensible. Cold.

**Proposed decomposition (when next v8 feature pushes lease.rs over 2000):**

- `shared_cos_lease/lease_legacy.rs` — `SharedCoSLeaseConfig`, `SharedCoSLeaseState`, `pack/unpack`, legacy `acquire/release/consume`, `SharedCoSRootLease`, `SharedCoSQueueLease::new`
- `shared_cos_lease/lease_v8.rs` — `new_v8*`, `matches_config_v8`, `acquire_v8*`, snapshot, equal-flow cap, per-worker claim
- Keep `epoch.rs` as is (or extract `V8EqualFlowSuppressState` to `equal_flow.rs` if it grows).
- Keep `backlog.rs`, `vtime.rs`, `rotate_epoch_v8.rs`, `publish_equal_flow_epoch_v8.rs` untouched — they are the positive examples.

**Hot-path preservation:**

- `acquire_v8` is on the hot path (called from `select_exact_cos_guarantee_queue_waterfill` Phase-1/Phase-2 + RR fast path). Splitting files does not change inlining — keep `#[inline(always)]` on `pack/unpack`, `#[inline]` on `acquire_v8` (already there). Module boundary is `pub(in crate::afxdp)` not `pub`, so LLVM can still inline across `mod` in same crate.
- No new heap alloc: per-worker arrays already boxed at `new_v8_with_rate_mode_and_policy` time (cold path). Split does not add alloc.

**Tests+gate:**

- Existing `shared_cos_lease_tests.rs` (2511 LOC) covers seqlock tear detection, carry, stall, equal-flow fail-open, v8 shortfall cause attribution. Must stay green.
- CoS smoke: v8 fair-share correctness — small class guaranteed under BE flood (shaped-class-held-under-BE-flood #4246 class) must hold; `loss:xpf-userspace-fw0` iperf must not regress.

**Why it matters / why (C) not (B):**

- Current `lease.rs` 1460 LOC is under the 2000 smell line but trending (was part of 2121-LOC monolith pre-#2158, now 1460 of 3258 cluster). Next v8 feature (+200 LOC) will push it over. Splitting now is premature; splitting at next feature (per "Refactor with new features, not after") is right.
- `backlog.rs` + `vtime.rs` prove the team can split well — cite them as template in review.

**Labels:** `modularity`, `cos`, `shared-lease`, `C-nice-to-have` + `D-good-example`

**Dedup note:** #2158 P2 already split the original 2121-LOC `shared_cos_lease/mod.rs` into 4 submodules — this filing acknowledges that split as exemplary for backlog/vtime, and tracks the remaining lease.rs concentration as a (C) follow-up, not a new (A)/(B).

---

## Summary

| # | Area | LOC | Finding | Class | Action |
|---|------|-----|---------|-------|--------|
| 1 | `types/cos.rs` CoSInterfaceRuntime | 28 fields, 1786 LOC file | God-struct mixing 5 lifecycles, 3 UNUSED WIRE-SURFACE-ONLY fields in hot cache lines, no sub-struct grouping | **(B)** Should-fix | Extract `WaterfillState` / `TokenState` / `RrState` sub-structs, cold-move or cfg-gate `priority_low_*` |
| 2 | `queue_service/mod.rs` waterfill selector | 432 LOC fn inside 2058 LOC file | God-function with 7 responsibilities — already filed as #4408 | **(D)** Duplicate | No new issue; add refill-extraction note to #4408 |
| 3a | `shared_cos_lease/backlog.rs` + `vtime.rs` + `rotate` + `publish` | 210/238/446/247 LOC | Cohesive, self-contained, correct `#[repr(align(64))]`, no visibility widening — positive example | **(D)** Good | No action, cite as template |
| 3b | `shared_cos_lease/lease.rs` | 1460 LOC | Legacy lease + v8 fair-share mixed in one file | **(C)** Nice-to-have | Split into `lease_legacy.rs` + `lease_v8.rs` when next v8 feature lands |
| — | `queue_ops/` prod 1893 LOC, test 6488 LOC | 3.4× test/prod | Test-dominant but expected for MQFQ CoV gate; `mod.rs` mixes min-finish selection + demotion + constants — tolerable at current size | **(D)** Good | No action; demotion helper could move to `demote.rs` if mod.rs crosses 600 LOC |
| — | `cos/tx_completion.rs` 1080 LOC | timer-wheel + TX-completion apply + prime + restore | 3 responsibilities in one file — monitor, split if new timer-wheel feature added | **(C)** Watch | No immediate action |

**Overall A1c assessment:** The CoS subsystem shows good modularity trend — `queue_service/` was split from a larger monolith (#1035 P2/P3), `shared_cos_lease/` was split from 2121 LOC single file into 7 cohesive submodules (#2158 P2), `queue_ops/` was split into 7 files (#1034 P1-P3). The remaining debt concentrates in:
- `types/cos.rs` god-struct (28 fields) — (B) should-fix before next waterfill or priority-low feature
- `queue_service/mod.rs` god-function — (D) already tracked (#4408)
- `shared_cos_lease/lease.rs` 1460 LOC legacy+v8 mix — (C) split on next v8 feature

No (A) immediate-refactor required in this batch. The codebase is not monolithic in the pejorative sense — it is mid-refactor with clear trajectory and good examples (`backlog.rs`, `vtime.rs`) to follow.

---

## Verification performed (audit only — no code change)

- `wc -l` on all 14 prod + 5 test files in batch
- `grep -n "priority_low_"` — 3 UNUSED fields confirmed no hot-path readers
- `grep -n "select_exact_cos_guarantee_queue_waterfill"` — 432 LOC measured (925-1357)
- `grep -n "SharedCoSQueueLease\|SharedCoSRootLease"` — lease.rs carries both legacy + v8
- `ls -la` on `queue_service/` (6 files), `queue_ops/` (11 files), `shared_cos_lease/` (8 files) — split shape confirmed
- No `cargo test` run (audit only)
