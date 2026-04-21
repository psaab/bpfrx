## 1. Plan-vs-code drift

- SEVERITY: LOW
- Summary: The implementation stack mostly matches the six planned work items, but `plan.md` is now stale about the Go-side delta.
- Explanation: The planned submit stamping, reap fold, sidecar, and compile-time assert all landed where advertised: plan §3.1's six submit sites and reap site are in `docs/pr/812-tx-latency-histogram/plan.md:126-205`, with matching code in `userspace-dp/src/afxdp/tx.rs:1977-1992`, `userspace-dp/src/afxdp/tx.rs:2112-2124`, `userspace-dp/src/afxdp/tx.rs:2261-2273`, `userspace-dp/src/afxdp/tx.rs:2396-2408`, `userspace-dp/src/afxdp/tx.rs:6108-6120`, `userspace-dp/src/afxdp/tx.rs:6334-6346`, and `userspace-dp/src/afxdp/tx.rs:65-105`. Sidecar shape and the named `'static + Send` assert also match plan §3.3 / §3.5a at `docs/pr/812-tx-latency-histogram/plan.md:315-318` and `docs/pr/812-tx-latency-histogram/plan.md:631-643`, with code in `userspace-dp/src/afxdp/worker.rs:35-54`, `userspace-dp/src/afxdp/worker.rs:342-349`, and `userspace-dp/src/protocol.rs:1446-1449`. The drift is plan §3.5's claim that "No Go struct change needed" at `docs/pr/812-tx-latency-histogram/plan.md:578-582`, which is false in the landed tree because the wire commit added histogram fields to both Go structs in `pkg/dataplane/userspace/protocol.go:674-684` and `pkg/dataplane/userspace/protocol.go:718-728`.
- Mitigation: Update `plan.md` to name the actual shipped split (`ead10052`, `6a54be00`, `bafa0cf5`, `a5e9c159`, `6db62fd2`, `2cf2e327`) and stop pretending the Go half was free.

## 2. Hot-path discipline

- SEVERITY: LOW
- Summary: No dataplane allocator regression is visible; the sidecar is pre-sized once and touched by indexed stores only.
- Explanation: `BindingWorker` allocates `tx_submit_ns` once at construction with `vec![TX_SIDECAR_UNSTAMPED; total_frames as usize]` in `userspace-dp/src/afxdp/worker.rs:342-349`, and the submit path only mutates existing slots through `sidecar.get_mut(idx)` in `userspace-dp/src/afxdp/tx.rs:27-49`. The reap fold uses a fixed `[u64; TX_SUBMIT_LAT_BUCKETS]` stack array in `userspace-dp/src/afxdp/tx.rs:71-74`, not a growable heap object. The only new `Vec` resizing is the control-plane `BindingStatus` materialization in `userspace-dp/src/afxdp/coordinator.rs:1433-1438`, which is not on the packet path.
- Mitigation: No hot-path change required; if you want belt-and-suspenders, assert `tx_submit_ns.len() == total_frames as usize` during worker construction.

## 3. Timestamp stamping correctness

- SEVERITY: LOW
- Summary: The partial-batch contract is implemented correctly; all six sites stamp exactly the accepted prefix, not the requested batch.
- Explanation: Every submit site computes `inserted = writer.insert(...)`, then feeds `.take(inserted as usize)` into `stamp_submits` before `writer.commit()` in `userspace-dp/src/afxdp/tx.rs:1983-1991`, `userspace-dp/src/afxdp/tx.rs:2115-2123`, `userspace-dp/src/afxdp/tx.rs:2264-2272`, `userspace-dp/src/afxdp/tx.rs:2399-2407`, `userspace-dp/src/afxdp/tx.rs:6111-6119`, and `userspace-dp/src/afxdp/tx.rs:6337-6345`. The helper itself only writes the offsets it is handed in `userspace-dp/src/afxdp/tx.rs:27-49`, so the retry tail is not accidentally stamped.
- Mitigation: Keep this pattern; do not "simplify" any site to iterate the full scratch slice.

## 4. Sentinel handling

- SEVERITY: LOW
- Summary: Sentinel selection is sane; `u64::MAX` avoids a zero-stamp collision and the bucket math already saturates cleanly on max input.
- Explanation: The sidecar sentinel is explicitly `u64::MAX` in `userspace-dp/src/afxdp/umem.rs:154-166`, and `canonical_submit_stamp` maps `0` to that sentinel in `userspace-dp/src/afxdp/tx.rs:3-11`, so a clock failure does not masquerade as a real 0 ns sample. Even if `u64::MAX` reached `bucket_index_for_ns`, the formula clamps it to the top bucket rather than panicking in `userspace-dp/src/afxdp/umem.rs:190-193`; that behavior is already pinned by `userspace-dp/src/afxdp/umem.rs:630-632`.
- Mitigation: None; this is the least broken part of the patch.

## 5. Phantom completions / reap ordering

- SEVERITY: MEDIUM
- Summary: Phantom completions are dropped from the histogram, but they disappear silently, which is weak for an observability PR.
- Explanation: The reap fold clears the slot and skips histogram/count/sum updates for unstamped or time-regressed completions in `userspace-dp/src/afxdp/tx.rs:74-90`, matching plan §5.4 at `docs/pr/812-tx-latency-histogram/plan.md:993-1003`. `reap_tx_completions` still recycles every completed offset and decrements `outstanding_tx` for the full `reaped` batch in `userspace-dp/src/afxdp/tx.rs:145-154`, so forwarding-side accounting stays balanced. The gap is that there is no counter for "completion seen but sample skipped," so lost stamps and genuinely idle traffic both flatten into the same empty histogram.
- Mitigation: Add a monotonic `tx_submit_latency_skipped_completions` counter and surface it next to `tx_submit_latency_count`.

## 6. Memory ordering

- SEVERITY: LOW
- Summary: The code does what the plan said: `Relaxed` everywhere, with the owner-written group still 64-byte aligned.
- Explanation: The writer path updates histogram/count/sum with `Ordering::Relaxed` in `userspace-dp/src/afxdp/tx.rs:92-103`, and snapshot reads are likewise `Relaxed` in `userspace-dp/src/afxdp/umem.rs:1731-1748`, matching plan §3.6.a at `docs/pr/812-tx-latency-histogram/plan.md:701-724`. The owner profile remains `#[repr(align(64))]` in `userspace-dp/src/afxdp/umem.rs:214-246`, with compile-time alignment and size checks in `userspace-dp/src/afxdp/umem.rs:307-325`, so the owner-written telemetry block is still isolated from peer-writer cache traffic.
- Mitigation: None unless you intentionally want to pay the Release/Acquire cost the plan explicitly rejected.

## 7. Cross-thread snapshot

- SEVERITY: HIGH
- Summary: The new bounded-skew pin does not implement the plan's math and already fails locally.
- Explanation: Plan §6.1 says the harness should derive `λ_obs` from `count_final / elapsed_wall` at `docs/pr/812-tx-latency-histogram/plan.md:1054-1061`, but the landed test recomputes rate from the current snapshot's `count / elapsed_ns` inside the loop in `userspace-dp/src/afxdp/umem.rs:1125-1144` and asserts the bound immediately in `userspace-dp/src/afxdp/umem.rs:1148-1152`. That underestimates the writer rate during startup and makes `K_skew_i` nonsense; on this branch, `cargo test -q tx_latency_hist_ -- --nocapture` tripped that exact assertion in `tx_latency_hist_cross_thread_snapshot_skew_within_bound`. This is not a theoretical gripe; the branch's own new pin is red.
- Mitigation: Warm the writer before sampling, or compute the rate from the final count after stopping the writer, exactly as the plan specified.

## 8. Compile-time assert

- SEVERITY: LOW
- Summary: `_ASSERT_BINDING_COUNTERS_SNAPSHOT_IS_OWNED_STATIC_SEND` is a real compile-time guard, not fake safety theater.
- Explanation: The assert is a named const item in `userspace-dp/src/protocol.rs:1428-1449`, so a future `Rc<T>` or borrowed field on `BindingCountersSnapshot` will fail the build where the contract lives. The runtime helper in `userspace-dp/src/main.rs:1962-1974` is only a duplicate corollary; the actual enforcement is the const item.
- Mitigation: Keep the named const assert as the source of truth; if you trim anything, trim the runtime duplicate, not the compile-time guard.

## 9. Backward-compat

- SEVERITY: LOW
- Summary: The wire contract is probably compatible, but the PR never tests the actual Go decoder path.
- Explanation: Rust side did the additive part correctly with `#[serde(default)]` on all three new fields in `userspace-dp/src/protocol.rs:1333-1338` and `userspace-dp/src/protocol.rs:1420-1425`, and the Rust unit pin shows old JSON decoding to empty/zero in `userspace-dp/src/main.rs:1930-1958`. Go will also default missing fields to nil/zero because the consumer structs are ordinary tagged fields in `pkg/dataplane/userspace/protocol.go:697-729`, so no extra tag is needed. The weakness is coverage: the only compat proof shipped here is Rust serde, while the real consumer called out in the plan lives in Go.
- Mitigation: Add a minimal Go `json.Unmarshal` test for a pre-#812 snapshot payload.

## 10. Test quality

- SEVERITY: MEDIUM
- Summary: The two highest-risk new pins are weaker than advertised: one is synthetic at the wrong level, and one is basically a comment pretending to be a test.
- Explanation: The cross-thread pin bypasses the production reap helper and manually bumps atomics in `userspace-dp/src/afxdp/umem.rs:1108-1120` instead of driving `record_tx_completions_with_stamp` in `userspace-dp/src/afxdp/tx.rs:65-105`, so it is testing an invented concurrency model, not the shipped fold. The `tx_submit_ns_sidecar_single_writer_ownership_is_rc_not_arc` pin spends fifteen lines promising a runtime shared-allocation check, then only binds two function pointers in `userspace-dp/src/afxdp/umem.rs:1185-1199`; that would still compile after an `Rc` to `Arc` migration if the methods kept the same signatures.
- Mitigation: Drive the real reap helper from the concurrency pin, and either construct two real `WorkerUmem` clones for a runtime assertion or stop claiming the current function-pointer probe proves anything.

## 11. Missing test coverage

- SEVERITY: MEDIUM
- Summary: The PR never exercises the six real submit call sites or the actual retry/unwind path, so a site-specific omission would sail through CI.
- Explanation: The production submit sites live in `userspace-dp/src/afxdp/tx.rs:1977-1992`, `userspace-dp/src/afxdp/tx.rs:2112-2124`, `userspace-dp/src/afxdp/tx.rs:2261-2273`, `userspace-dp/src/afxdp/tx.rs:2396-2408`, `userspace-dp/src/afxdp/tx.rs:6108-6120`, and `userspace-dp/src/afxdp/tx.rs:6334-6346`, but the new pins only call `stamp_submits` or `record_tx_completions_with_stamp` directly in `userspace-dp/src/afxdp/umem.rs:953-1008`. Plan §6.1 test #3 also said to prove the `inserted == 0` path returns descriptors to `free_tx_frames` at `docs/pr/812-tx-latency-histogram/plan.md:1031-1035`; the landed test at `userspace-dp/src/afxdp/umem.rs:988-1008` checks only the empty-iterator helper case and never models the real unwind.
- Mitigation: Add submit-family tests that force `inserted < requested` and `inserted == 0` through the actual queue functions, then assert sidecar state and retry-tail ownership.

## 12. Histogram bucket off-by-one

- SEVERITY: LOW
- Summary: The bucket math is fine; `0` lands in bucket 0 and `u64::MAX` saturates to 15 without panic.
- Explanation: `bucket_index_for_ns` uses `(ns | 1).leading_zeros()`, clamps negative results to 0, and caps large values with `.min(DRAIN_HIST_BUCKETS - 1)` in `userspace-dp/src/afxdp/umem.rs:190-193`. The existing boundary pins already cover `0`, the `1024` transitions, and `u64::MAX` at `userspace-dp/src/afxdp/umem.rs:602-632`, so there is no off-by-one bug hiding in the bucket selector.
- Mitigation: None; leave this helper alone unless you are deliberately changing the wire contract.

## Round 2 verification

HIGH-1: CLOSED — At all six submit sites in `userspace-dp/src/afxdp/tx.rs` (`2006-2027`, `2147-2163`, `2299-2315`, `2437-2452`, `6151-6167`, `6380-6395`), `writer.commit(); drop(writer);` now happens before the single fresh `monotonic_nanos()` and `stamp_submits(...)`, so only the accepted prefix is stamped after the ring submit is made kernel-visible.
HIGH-2: PARTIAL — `tx_latency_hist_cross_thread_snapshot_skew_within_bound` in `userspace-dp/src/afxdp/umem.rs:1097-1266` now uses real writer and reader `std::thread::spawn` threads plus `Arc<Mutex<Vec<Sample>>>`, and the harness sleeps for `Duration::from_millis(200)` before shutdown, but the reader still exits after a fixed `5_000` iterations instead of sampling strictly for the full wall-duration window.
MEDIUM: CLOSED — In live code the sidecar sentinel is `u64::MAX` (`userspace-dp/src/afxdp/umem.rs:174`), `stamp_submits` now early-returns on `ts_submit == 0` without writing any slot (`userspace-dp/src/afxdp/tx.rs:40-56`), and I found no executable `canonical_submit_stamp` helper/call site or remaining use of `0` as the unstamped marker in the tx-latency path.
Rust HIGH-1: CLOSED — The two new tests at `userspace-dp/src/afxdp/umem.rs:1317-1392` call the production helpers `crate::afxdp::tx::stamp_submits` and `record_tx_completions_with_stamp` with genuinely out-of-bounds offsets, and they assert that the OOB stamp/reap paths silently drop those offsets without mutating in-range slots or bumping histogram/count/sum.
Round 2 new findings (if any): None; the post-commit move does not add an extra submit-side clock read in the current code because each submit site still takes exactly one `monotonic_nanos()` per `writer.commit()`, and sidecar access remains single-owner userspace code via `&mut BindingWorker` / `Rc` ownership rather than a competing reader on the same slots.

ROUND 2: MERGE NO

## Round 3 verification

HIGH-2: CLOSED — In `tx_latency_hist_cross_thread_snapshot_skew_within_bound`, the reader now runs `while !reader_stop.load(Ordering::Relaxed)` after warmup, the writer’s overlap phase likewise runs `while !writer_stop.load(Ordering::Relaxed)`, and the main thread ends that shared 200 ms window with `stop.store(true, Ordering::Relaxed)`, so the overlap is stop-flag-bounded rather than capped by the old fixed `for _ in 0..iterations`.
Round 3 new findings (if any): None; after the fixed `for _ in 0..10_000u64` warmup the writer polls the same `AtomicBool` the reader polls, both threads are joined only after `stop.store(true, ...)`, and `Vec::with_capacity(16_384)` is only pre-allocation for a growable `Vec`, so this rewrite does not show a new obvious infinite-loop, missed-stop, or fixed-buffer-overflow path in the test code.

ROUND 3: MERGE YES
