# PR #796 — Phase 3 MQFQ — Rust/testing adversarial review

Second-reviewer pass alongside Codex (networking angle). Scope:
Rust idioms, test depth/isolation, hot-path allocations, doc
coverage, public-surface drift, D3 interaction.

Branch `pr/785-phase3-mqfq-vft`, commit `2a20cc8a`. Build green.
MQFQ-tagged tests green (9 flow-fair + 7 mqfq_* = 16 pins all
pass on `cargo test --release`).

## Findings

### 1. MEDIUM — `push_front` on drained bucket is not finish-time-neutral
`userspace-dp/src/afxdp/tx.rs:4037-4097`. The Codex round-2 HIGH
fix only handles the "bucket still non-empty" path. If the popped
item was the last in its bucket, `cos_queue_pop_front` drains the
bucket, `account_cos_queue_flow_dequeue` resets head=tail=0, and
`queue.vtime` already advanced by `bytes`. A subsequent
`push_front(same item)` now hits the `was_empty` branch and
re-anchors to `queue.vtime + bytes`, which is one packet-worth
*past* the pre-pop head. The TX-restore-on-ring-full path at
tx.rs:2874/2915 can trigger this when the popped item is the sole
packet on its bucket. Not a correctness hole (ordering still
converges), but advertised as "round-trip finish-time neutral".
Mitigation: add a pin covering the drain-then-push_front case; if
it fails, either suppress the pop-time vtime advance on
push_front-within-NAPI-batch, or document the asymmetry.

### 2. MEDIUM — `mqfq_finish_time_u64_has_decades_of_headroom` is a calculator, not a pin
`userspace-dp/src/afxdp/tx.rs:10788-10810`. The test recomputes
the overflow math in Rust and asserts `years_to_wrap > 40`. It
never drives `account_cos_queue_flow_enqueue` with near-wrap
`queue.vtime` to prove the `saturating_add` chain holds. A
regression that (say) changes the accumulator to `u32` or keeps
`u64` but swaps `saturating_add` for `+` would still pass — the
test never reads the actual field. Mitigation: set
`queue.queue_vtime = u64::MAX - 10_000`, enqueue a 9000-byte
item, assert the field did not wrap.

### 3. MEDIUM — `flow_fair_queue_mqfq_bytes_rate_fair_on_mixed_packet_sizes` only proves DRR inequality indirectly
`userspace-dp/src/afxdp/tx.rs:10355-10390`. The design's whole
win is mixed-size ordering vs DRR. The pin asserts
`order == [1112, 1113, 1111]` and says in comment that DRR would
produce `[1111, 1112, 1113]`, but never exercises the DRR code
path to prove the comparison. Mitigation acceptable as-is given
cost to compare to a dead code path, but a golden-vector test
table (sizes, flows, expected order) would harden against future
changes to `cos_queue_min_finish_bucket`'s tie-break rule.

### 4. LOW — `FlowRrRing::remove` is O(n) with an inner shift loop
`userspace-dp/src/afxdp/types.rs:757-777`. Worst-case O(n^2) on a
near-head drain at len=1024. Typical workload (2-16 active) is
fine; commit body acknowledges this. No change needed, tracked.

### 5. LOW — No idle-return anchor test
Neither `mqfq_queue_vtime_advances_by_drained_bytes` nor
`mqfq_bucket_drain_resets_finish_time` proves the *consequence*:
a flow that idles and returns anchors at the current frontier
instead of sweeping past established flows. Suggest a pin: drain
A for N bytes, idle B, re-enqueue B, assert B's head ==
`vtime + bytes`.

### 6. LOW — Back-reference missing in types.rs field docs
`userspace-dp/src/afxdp/types.rs:1050-1099`. A reader starting
from `flow_bucket_head_finish_bytes` learns the invariants but
not the consuming function. One-line "read by
`cos_queue_min_finish_bucket`" back-reference would close the
loop.

## Verified (no issue)

- **No hot-path allocation.** `cos_queue_min_finish_bucket`,
  `cos_queue_front`, `cos_queue_pop_front`, and
  `account_cos_queue_flow_{enqueue,dequeue}` are allocation-free;
  only `Vec::new()` and `String::new()` in added code live in
  tests or `test_cos_runtime_with_queues` (tx.rs:9665-9674,
  10315, etc.). Confirmed by grep on added lines.
- **No new `unsafe`, no new `unwrap`, no new `eprintln!` in
  hot-path code.** The lone `.unwrap_or(0)` added
  (tx.rs:4092) sits on a branch where the bucket was just proven
  non-empty, so it's defense-in-depth for a provably-unreachable
  None.
- **No `#[allow(...)]` suppressions introduced.**
- **Test isolation.** Every new pin calls
  `test_cos_runtime_with_queues` which builds a fresh
  `CoSInterfaceRuntime` via `build_cos_interface_runtime` — no
  shared state, safe under `cargo test`'s default parallel
  runner.
- **Test assertions are specific.** `assert_eq!(order, vec![...])`
  on ordering pins, `assert_eq!(queue.queue_vtime, 6000)` on
  vtime, `assert_eq!(queue.flow_bucket_head_finish_bytes[bucket],
  pre_pop_head)` on neutrality. No vague `assert!(x > 0)`
  ordering checks.
- **No public API removed.** `cos_queue_front`,
  `cos_queue_pop_front`, `cos_queue_push_front` keep their
  `pub(super)` signatures. `FlowRrRing::remove` is additive.
  Renamed tests (`..._round_robins_...` →
  `..._pops_in_virtual_finish_order_...`) are inside `mod tests`
  so visible only to the test harness.
- **Commit message explains WHY.** 122-line body with "What
  changes", "Codex adversarial review" (both HIGH findings traced
  end-to-end), "Tests", "Empirical measurements" table, and
  "Deferred for Phase 4" sections. `docs/785-cross-worker-drr-
  retrospective.md §4` referenced for the packet-count-vs-byte-
  rate argument. This is the strongest commit body on the branch.
- **No D3 (SetApplyConfigFn / apply_config) plumbing touched.**
  `git diff master..HEAD` has zero matches for `setapplyconfigfn`
  or `apply_config`. Phase 3 is orthogonal to the CLI apply-fn
  plumbing that just landed.
- **Struct-field additions in `CoSQueueRuntime`** have doc
  comments covering invariants (idle-bucket re-anchor, drain
  reset, overflow) — tx.rs:1050-1099 / types.rs:1047-1099.
- **Build clean** (`cargo build --release`, `cargo test --release
  --bin xpf-userspace-dp mqfq`) — 0 errors, 68-83 pre-existing
  warnings unchanged.

## Merge readiness

**YES**, with findings #1-#3 addressable as follow-ups (none
blocks merge). MQFQ correctness is pinned on the path that
actually ships, hot-path is allocation-free, test isolation is
clean, and the commit message and doc comments carry the
institutional context forward. #1 is the only one worth a
targeted pin before Phase 4 re-enters this code.

## Round 2 verification

**ROUND 2: merge-ready from Rust-quality angle.**

Verification of `4416eb27` + `ab8abb4d` against prior findings.

### Round 1 finding status

- **MED #1 (drained-bucket round-trip neutrality)** — CLOSED.
  Fixed by `CoSQueuePopSnapshot` mechanism (types.rs:999-1026):
  `cos_queue_pop_front` snapshots `{bucket, pre_pop_head_finish,
  pre_pop_tail_finish}` BEFORE any mutation (tx.rs:4165-4181).
  `cos_queue_push_front` consumes (takes) the snapshot and on
  bucket match restores head/tail EXACTLY (tx.rs:4093-4106). The
  snapshot is invalidated on any `cos_queue_push_back`
  (tx.rs:4023-4027), closing the stale-snapshot race.
  New pin `mqfq_push_front_is_neutral_on_drained_bucket_round_trip`
  (tx.rs:10640-10711) asserts full state restore (head, tail, bytes,
  vtime, active count, item length) across drain-pop/push_front.
  The Codex HIGH vtime-rewind fix and the Rust MED #1 snapshot fix
  compose correctly — the PR commit message explicitly calls out
  why per-item symmetric rewind is needed alongside the snapshot
  (partial-commit settle paths).

- **MED #2 (headroom-is-calculator)** — CLOSED.
  Rewritten. Test now drives `queue.queue_vtime = u64::MAX - 10_000`
  and calls the REAL `cos_queue_push_back` path twice:
  (1) verifies first enqueue anchors at `near_wrap + 9000` exactly,
  (2) verifies second enqueue saturates at `u64::MAX`
  (tx.rs:11232-11322). The old calculator block is kept as a
  commentary sanity assert, but the field-driving portion is what
  a u32 narrowing or `+` replacement regression would fail.

- **MED #3 (mixed-size golden vector)** — CLOSED.
  New pin `mqfq_golden_vector_pop_order_vs_drr` (tx.rs:10470-10578)
  adds a table of 3 rows (equal-1500, mixed-3000-1500,
  three-flows-progressive). MQFQ pop order is hard-coded in the
  `mqfq_order` column; DRR reference column is documented but not
  executed (old DRR path is gone). A closing `any_divergent` assert
  guarantees the table still demonstrates MQFQ-vs-DRR divergence
  even if someone later edits rows. If MQFQ regresses to
  packet-count fairness, at least one row's actual order will
  match the `drr_order` column and fail `assert_eq`.

### New-angle findings

4. **Snapshot implementation** (types.rs:999-1026): `Option<CoSQueuePopSnapshot>`
   — 24-byte POD (u16 + 2xu64) + Option discriminant. `Copy + Clone`, zero heap,
   lives inline on `CoSQueueRuntime`. Cleared on `push_back`, taken on
   `push_front`. No new pin leaks through — `push_back` already resets it,
   and `push_front` uses `Option::take()` so stale reuse is structurally
   impossible.

5. **Symmetric rewind arithmetic** (tx.rs:4068): uses
   `queue.queue_vtime.saturating_sub(item_len)`. If `queue_vtime <
   item_len` (only reachable if pop accounting is broken — normal pop
   advances vtime by `item_len`, so rewinding the same item cannot
   underflow), saturates to 0 cleanly. No `checked_sub + panic`, no
   wrapping surprise. Not separately unit-tested for the pathological
   `vtime < bytes` case, but by invariant this path is unreachable.

6. **New pin quality** — all pins verified:
   - `push_front_is_neutral_on_drained_bucket_round_trip`: asserts head,
     tail, bytes, vtime, active count, item length (6 fields) — full.
   - `brief_idle_reentry_exercises_both_max_arms`: NOT split, single-flow
     sequence exercising tail=0/vtime>0 (arm 1) then tail>vtime (arm 2)
     in order; clear arm-naming in assert messages.
   - `finish_time_u64_has_decades_of_headroom`: real push_back near
     `u64::MAX - 10_000`, two enqueues, asserts saturation on second.
   - `golden_vector_pop_order_vs_drr`: hard-coded `mqfq_order` array per
     row; DRR column documented-not-executed; `any_divergent` meta-assert.
   - `idle_flow_reanchors_at_frontier_not_zero`: checks exact non-zero
     anchor `5700 = queue_vtime(4500) + bytes(1200)`, not just
     `> bytes`.
   - Existing pin `push_front_is_finish_time_neutral_on_active_bucket`
     extended with `pre_pop_vtime == post_restore_vtime` assertion.

7. **New unsafe/unwrap/expect/eprintln/panic** — NONE in production.
   Diff sweep: two `.expect()` added (both in tests: `"flow key"` tie-break
   in golden vector; `"pop"` in drained-bucket pin). Zero production-path
   `unsafe`, `unwrap`, `expect`, `eprintln`. One `panic` mention in a
   comment explaining saturating_add semantics. Clean.

8. **Performance cost of the snapshot**: written on EVERY
   `cos_queue_pop_front` (tx.rs:4176-4181) regardless of caller. Cost:
   one `Option<(u16, u64, u64)>` struct write = 24 bytes + discriminant
   on the queue struct (no allocation, already-in-cache line). Cleared
   on every `push_back` (tx.rs:4023-4027) — one `Option::None` write.
   This is unavoidable given the TX-ring-full rollback contract (caller
   doesn't declare intent at pop time). Cheaper than the alternative
   (tracking rollback-intent via a separate API). Acceptable overhead
   for the correctness guarantee — matches engineering-style.md's
   "hot-path discipline, not hot-path absolutism".

### Final disposition

3 round-1 MEDIUMs all CLOSED with targeted pins that would fail on
regression. Snapshot mechanism is allocation-free, leak-free, and
composable with the Codex symmetric-rewind fix. No new Rust-quality
concerns introduced. 11 mqfq_* tests green (`cargo test --release
... mqfq`). Merge-ready.
