## 1. CACHELINE BUDGET
Severity: MEDIUM. Finding: “May push past” is wrong. Current size is 328 B raw / 384 B padded; +152 B makes it 480 B raw / 512 B padded, so the 448 B const-assert will fire. The separate align assert still preserves 64-byte alignment. Citation: plan §3.2; `userspace-dp/src/afxdp/umem.rs:223-294,318-332`.

## 2. record_kick_latency PLACEMENT
Severity: LOW. Finding: No circularity. `afxdp.rs` imports `umem::*` into the parent and `tx.rs` uses `super::*`, which is why `tx.rs` already calls `bucket_index_for_ns` and names `OwnerProfileOwnerWrites` today. Citation: plan §3.3; `userspace-dp/src/afxdp.rs:143`; `userspace-dp/src/afxdp/tx.rs:1,94-115`; `userspace-dp/src/afxdp/umem.rs:198-202,223`.

## 3. SENTINEL CHECK COVERAGE
Severity: LOW. Finding: The “mirrors `TX_SIDECAR_UNSTAMPED`” claim is false. #812 gates clock failure at stamp time and skips bad pairs via sentinel / `ts_completion >= ts_submit`; it does not do `start==0 || end==0` on every event. `kick_end < kick_start` would match the actual hazard better. Citation: plan §3.1, §3.3, §6; `userspace-dp/src/afxdp/tx.rs:54-56,113-119,163-173`.

## 4. BINDING ACCESSOR PATH
Severity: LOW. Finding: This path exists exactly as written: `BindingWorker -> live: Arc<BindingLiveState> -> owner_profile_owner`. Citation: plan §3.1, §3.3; `userspace-dp/src/afxdp/tx.rs:6429-6482`; `userspace-dp/src/afxdp/worker.rs:3-10`; `userspace-dp/src/afxdp/umem.rs:1496`.

## 5. From IMPL REF vs VALUE
Severity: LOW. Finding: No issue. The impl is `From<&BindingStatus>`, so `.clone()` is the correct owned-copy behavior. Citation: plan §3.6; `userspace-dp/src/protocol.rs:1455-1476`.

## 6. GO FIELD ORDERING
Severity: LOW. Finding: No order-sensitive consumer found. Go emits named keys and the Python reader uses `b.get(...)`, so field order should not matter. Citation: plan §3.8; `pkg/dataplane/userspace/protocol.go:682-684,697-728`; `test/incus/step1-histogram-classify.py:69-91`.

## 7. K_SKEW BOUND
Severity: LOW. Finding: Reusing `K_skew=3` is conservative, not derived. #812 computed it from `λ ≤ 3 Mpps` completions; #825 should say it is carrying over an upper bound, not reusing the derivation unchanged. Citation: plan §4; `docs/pr/812-tx-latency-histogram/plan.md:752-773`; `userspace-dp/src/afxdp/tx.rs:6432-6434`; `userspace-dp/src/afxdp.rs:201`.

## 8. OVERHEAD MATH
Severity: HIGH. Finding: The 45 ns arithmetic is fine: 30 ns for clocks, 9-15 ns for three atomics, negligible math. The plan then contradicts itself: §7 derives ~45 ns, but §3.10/§9 hard-gate p99 at 25 ns, and the “~1 kick per ~thousand packets” claim is not supported by the wake logic. Citation: plan §3.10, §7, §9; `docs/pr/812-tx-latency-histogram/plan.md:359-426,1158-1177`; `userspace-dp/src/afxdp/tx.rs:6432-6434`; `userspace-dp/src/afxdp.rs:201`.

## 9. MISSING TEST COVERAGE
Severity: HIGH. Finding: §3.9 never tests the actual T1-specific behavior: `EAGAIN/EWOULDBLOCK -> tx_kick_retry_count` in `maybe_wake_tx`. The plan also admits the caller-side sentinel stays untested, and the Criterion bench is not wired in this crate’s Cargo manifest. Citation: plan §3.9, §3.10; `userspace-dp/src/afxdp/tx.rs:6429-6453`; `userspace-dp/Cargo.toml:1-23`.

## 10. CONSTRUCTABILITY IN TESTS
Severity: LOW. Finding: The helper is testable, but not as a standalone owner-profile fixture. `OwnerProfileOwnerWrites::new()` is private; the existing working pattern is `BindingLiveState::new()` plus `live.owner_profile_owner`. Citation: plan §3.3, §3.9; `userspace-dp/src/afxdp/umem.rs:335-355,923-930,1496,1634`.

## 11. PRECEDENT ADHERENCE
Severity: MEDIUM. Finding: It mirrors two good #812 precedents: fresh `monotonic_nanos()` and the existing `'static + Send` / `From<&BindingStatus>` owned-copy path. It skips the hard precedent: #812 paired `K_skew` with a real cross-thread skew harness; #825 only plans single-thread pins. Citation: plan §3.3, §3.6, §3.9, §4; `docs/pr/812-tx-latency-histogram/plan.md:162-173,620-643,832-849`; `userspace-dp/src/protocol.rs:1446-1476`; `userspace-dp/src/afxdp/umem.rs:1098-1249`.

## 12. std::array::from_fn STABILITY
Severity: LOW. Finding: No blocker. Edition 2024 already implies a toolchain newer than Rust 1.63, and `std::array::from_fn` is already used in shipped code. MSRV is unpinned, but #825 adds no new compatibility risk. Citation: plan §3.2; `userspace-dp/Cargo.toml:1-4`; `userspace-dp/src/afxdp/umem.rs:342-346`; `userspace-dp/src/afxdp/worker.rs:1846-1858`; `userspace-dp/src/afxdp/coordinator.rs:104`.

## VERDICT
ROUND 1: OPEN ITEMS

- Overhead gates are internally contradictory: ~45 ns is derived, 25 ns is required, and the amortization claim is not justified by the current wake path.
- The plan does not test `EAGAIN/EWOULDBLOCK -> tx_kick_retry_count`, which is half of T1’s signal.
- §3.2 must stop hand-waving the struct growth; this change pushes `OwnerProfileOwnerWrites` to 512 B padded, so the cap raise has to be explicit in the plan, not conditional on “maybe”.

## Round 1 response

All 2 HIGH + 2 MED + 3 LOW addressed via direct plan edits:

### HIGH-8 (overhead contradiction) — CLOSED
§7 amortization claim "1 kick per thousand packets" withdrawn (unsupported by wake logic). §7 replaced with honest workload-dependent statement: per-call cost ~45ns, call rate varies, worst case 45/481 = 9.4% (same soft-gate ceiling as #812's submit-stamp partial-batch). §9 gate 4 + §10 stop 1 + §3.10 all raised to **p99 ≤ 60 ns** to match the 45 ns derivation plus 15 ns bench-jitter/cacheline headroom. Old 25 ns gate documented as gating only the atomic fast-path (excluded the two VDSO monotonic_nanos calls which are the dominant 30 ns); explicitly withdrawn.

### HIGH-9 (missing tests + bench wiring) — CLOSED
§3.9 adds test 4: EAGAIN retry-counter pin with mock-errno fixture, fallback to integration-level assertion during §9 gate 8 deploy smoke (non-zero `tx_kick_retry_count` after 60s iperf3 on p5201-fwd-with-cos). §3.9 test 3 sentinel split into 3a (delta=0) + 3b (end<start). §3.10 bench block adds explicit `[[bench]]` + `harness = false` Cargo.toml entry requirement (mirrors #812's bench wiring; implementor MUST add or `cargo bench` silently no-ops).

### MED-1 (cacheline hand-waving) — CLOSED
§3.2 rewritten. Explicit: current 328/384, new 480/512. Const-assert cap-raise from 448→512 in the same commit. `#[repr(align(64))]` unchanged; 512 B padded still fits ~8 cachelines.

### MED-11 (precedent adherence: cross-thread skew) — CLOSED
§3.9 adds test 6: cross-thread writer/reader pairs replicating #812 §620-643 pattern. Asserts (a) no data race via sanitizer/miri, (b) K_skew bound holds.

### LOW-3 (sentinel precedent) — CLOSED
§3.3 sentinel changed from `kick_start == 0 || kick_end == 0` to `kick_end < kick_start` — matches `record_tx_completions_with_stamp`'s `ts_completion >= ts_submit` pattern (`tx.rs:113-119`).

### LOW-7 (K_skew carry-over framing) — CLOSED
§4 doc-comment updated: K_skew from #812 is a **conservative upper bound**, not a re-derivation; true K_skew for kicks is orders of magnitude smaller (kicks rare vs 3 Mpps completions).

### LOW-10 (constructability) — CLOSED
§3.9 updated: tests use `BindingLiveState::new()` + `live.owner_profile_owner` (matches umem.rs:923-930, 1496 precedent); `OwnerProfileOwnerWrites::new()` is private and not used as a fixture.

### LOW items (2, 4, 5, 6, 12) — accepted as-is
All five were "no issue" or "no blocker" findings. No action required.

Requesting Round 2 review.

## Round 2 verification

VERDICT: ROUND 2: OPEN BLOCKERS — HIGH-8, LOW-7

| Fix | Status | Evidence |
|-----|--------|----------|
| HIGH-8 overhead | PARTIAL | §7 L275-282; §3.10 L221; §9 L307; §10 L319; §8 L296 still says `25 ns`. |
| HIGH-9 tests+bench | CONFIRMED | §3.9 L199-204; §3.10 L213-219. |
| MED-1 cacheline | CONFIRMED | §3.2 L71-81. |
| MED-11 skew harness | CONFIRMED | §3.9 L204-205. |
| LOW-3 sentinel | CONFIRMED | §3.3 L91-95. |
| LOW-7 K_skew | PARTIAL | §4 L234; framed as carry-over, but still says `N in thousands` after §7 withdrawal. |
| LOW-10 fixture | CONFIRMED | §3.9 L195-196. |

### Remaining issues
- HIGH: Fix §8 line 296 to `60 ns` so the bench gates stop contradicting each other.
- LOW: Remove §4 line 234 `N in thousands` wording or restate it as unmeasured.

## Round 2 response

Two R2 remaining items fixed:

### HIGH-8 R2 (stale 25 ns in execution matrix + RT-2)
**CLOSED.** §8 row 9 updated: `p99 ≤ 60 ns` (was `25 ns`); also appended the Cargo.toml [[bench]] requirement note for clarity. §16 RT-2 updated: `p99 > 60 ns` (was `25 ns`). The only remaining `25 ns` tokens are the two historical back-references in §3.10 and §7 that explicitly document the withdrawn value ("not the earlier 25 ns that gated only the atomic fast-path" / "The earlier 25 ns gate was an error"). Those are pedagogically useful (explain WHY the gate changed) and not contradictions with live values.

### LOW-7 R2 ("N in thousands" vs withdrawn amortization)
**CLOSED.** §4 doc-comment paragraph rewritten: removed the "N in thousands" number; replaced with "precise kick-per-packet rate is unmeasured pre-instrumentation and is workload-dependent." Cites #823's on-CPU observation + `TX_WAKE_MIN_INTERVAL_NS` gate at `tx.rs:6432-6434` as the workload-dependent rate driver; states `tx_kick_latency_count` becomes the post-instrumentation exact measure. Bound framing preserved ("strictly rarer than submits → #812's K_skew=3 is a conservative upper bound").

Requesting Round 3 review.

## Round 3 verification

VERDICT: ROUND 3: PLAN-READY YES

| Fix | Status | Evidence |
|-----|--------|----------|
| HIGH-8 R2 stale 25 ns | CONFIRMED | §3.10 L221; §7 L282; §8 L296; §16 L377. |
| LOW-7 R2 N-in-thousands | CONFIRMED | §4 L234. |
