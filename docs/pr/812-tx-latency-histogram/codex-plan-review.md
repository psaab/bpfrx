# Plan Review: PR #812 TX Latency Histogram

## 1. HIGH — Relaxed snapshot reads do not support an exact `sum(hist) == count` hard stop
Summary: The plan promotes approximate diagnostic atomics into exact cross-CPU accounting without adding any snapshot ordering.

Explanation: The plan says the owner worker writes the histogram with `fetch_add(1, Relaxed)` and the control thread snapshots it with `load(Relaxed)`, explicitly mirroring the existing drain-histogram pattern (`docs/pr/812-tx-latency-histogram/plan.md:334-336`). Current code documents that pattern as intentionally tear-tolerant: `BindingLiveState::snapshot()` says bucket arrays are copied under `Relaxed`, read skew is acceptable, and even the existing `sum(hist) ≈ drain_invocations` relation only holds in steady-state (`userspace-dp/src/afxdp/umem.rs:1322-1329`). The same plan then turns `sum(buckets) == tx_submit_latency_count` into both a merge-blocking invariant and an integration hard stop (`docs/pr/812-tx-latency-histogram/plan.md:341-346`, `docs/pr/812-tx-latency-histogram/plan.md:487-488`), which is not defensible under relaxed cross-CPU reads.

Mitigation: Either add a real consistent-snapshot mechanism for the new histogram/count/sum trio, or downgrade the invariant to a single-thread/unit-test property and stop treating snapshot-time equality as production truth.

## 2. HIGH — The “no syscall” invariant depends on an unproven VDSO fast path
Summary: The plan treats `clock_gettime` as guaranteed user-space and low-latency, but the code does not prove that.

Explanation: The budget tables and invariant text assume `clock_gettime(MONOTONIC)` is a VDSO call at roughly 15 ns and therefore “NOT a syscall” (`docs/pr/812-tx-latency-histogram/plan.md:214-225`, `docs/pr/812-tx-latency-histogram/plan.md:322-324`). Current code calls plain `libc::clock_gettime(CLOCK_MONOTONIC, ...)` and returns `0` on failure; it does not verify VDSO availability or reject a kernel fallback path (`userspace-dp/src/afxdp/neighbor.rs:3-15`). The rollback table even models an “exotic kernel” failure mode, but incorrectly calls it a panic instead of what the helper actually does today: silent zero timestamps (`docs/pr/812-tx-latency-histogram/plan.md:463-465`, `userspace-dp/src/afxdp/neighbor.rs:8-10`).

Mitigation: Prove the fast path on the target kernel before claiming the invariant, or gate the feature off when `clock_gettime` is not demonstrably VDSO-backed on the deployment shape.

## 3. HIGH — Submit-side amortization collapses on the existing partial-batch paths
Summary: The plan prices the submit timestamp as a 256-way amortized cost, but current TX code already has accepted-prefix/retry-tail behavior where the batch can be effectively size 1.

Explanation: The design says one `monotonic_nanos()` call per submit commit is enough, and the cost table prices that as `15 ns / 256 = 0.06 ns` per packet (`docs/pr/812-tx-latency-histogram/plan.md:92-99`, `docs/pr/812-tx-latency-histogram/plan.md:208-217`). That is not a worst case: current `transmit_batch` and `transmit_prepared_batch` already support partial acceptance and explicitly peel the accepted prefix from the retry tail after `writer.commit()` (`userspace-dp/src/afxdp/tx.rs:5924-5960`, `userspace-dp/src/afxdp/tx.rs:6141-6175`). When `inserted == 1`, the submit clock read is per-packet, not amortized, so the advertised 1.1 ns submit subtotal is off by an order of magnitude.

Mitigation: Budget the feature against observed batch-size distributions, and publish a worst-case small-batch number separately instead of passing a 256-descriptor best case off as the hot-path cost.

## 4. HIGH — The overhead arithmetic is internally inconsistent even before benchmarking
Summary: The `0.13 %` claim uses the wrong divisor and forgets its own second completion-side atomic.

Explanation: The plan first states that 25 Gbps line rate is about 2.08 Mpps “per queue,” then immediately divides that by 16 workers to create a 130 Kpps and 7600 ns “per-packet CPU budget” (`docs/pr/812-tx-latency-histogram/plan.md:240-247`). That is a load-distribution assumption, not a property of the queue being instrumented, so it is the wrong denominator for a per-packet hot-path claim. The same section counts one completion-side atomic (`docs/pr/812-tx-latency-histogram/plan.md:223-229`), but §12 later says the exact `tx_submit_latency_sum_ns` requires an additional `fetch_add(delta, Relaxed)` and asserts that cost is somehow already included in the bucket increment line (`docs/pr/812-tx-latency-histogram/plan.md:631-636`), which is plainly false.

Mitigation: Recompute the budget per binding/worker using measured batch histograms, and count both completion-side atomics explicitly if the exact sum remains in scope.

## 5. MED — The phantom-completion mitigation is correct in spirit but still leaves a zero-value trap
Summary: The sentinel rule is the right idea, but the plan then weakens it with an ambiguous clear value that collides with the current clock helper.

Explanation: The plan correctly says missing submit stamps must use `u64::MAX` and be skipped, otherwise a bogus subtraction can bias the histogram (`docs/pr/812-tx-latency-histogram/plan.md:114-117`, `docs/pr/812-tx-latency-histogram/plan.md:386-394`). It then says the reap path may clear the sidecar slot by storing “0 or a tombstone” (`docs/pr/812-tx-latency-histogram/plan.md:112-117`). That is not robust, because the current `monotonic_nanos()` implementation already returns `0` on `clock_gettime` failure (`userspace-dp/src/afxdp/neighbor.rs:8-10`), so zero cannot safely mean both “cleared” and “measured.”

Mitigation: Make `u64::MAX` the only unstamped value on init and clear, and specify that a zero result from `monotonic_nanos()` causes the sample to be dropped rather than recorded.

## 6. MED — The sidecar indexing is mechanically valid, but the memory and cacheline story is sloppy
Summary: `offset / UMEM_FRAME_SIZE` works, yet the plan understates sidecar size and hand-waves cacheline placement.

Explanation: Current offsets do come from UMEM frames and are aligned to the fixed frame size, so a dense index is structurally sound (`userspace-dp/src/afxdp/umem.rs:21-27`, `userspace-dp/src/afxdp/umem.rs:76-82`, `userspace-dp/src/afxdp.rs:147`). The problem is cardinality: the plan sizes the sidecar to `total_frames` and claims `8192 × 8 B = 64 KiB` per binding (`docs/pr/812-tx-latency-histogram/plan.md:180-192`), but virtio bindings actually use `3 × ring_entries` frames (`userspace-dp/src/afxdp/bind.rs:37-43`) and `BindingWorker::new` uses that `total_frames` value when provisioning the binding (`userspace-dp/src/afxdp/worker.rs:213-216`, `userspace-dp/src/afxdp/worker.rs:303`). The plan also dismisses cross-worker contention on the histogram while only later hinting at cacheline isolation in the estimate table (`docs/pr/812-tx-latency-histogram/plan.md:201-204`, `docs/pr/812-tx-latency-histogram/plan.md:496`; `userspace-dp/src/afxdp/umem.rs:168-180`, `userspace-dp/src/afxdp/umem.rs:186-190`).

Mitigation: Size the sidecar to reserved TX frames or a precomputed dense TX-frame index, and state explicitly that the new histogram atomics live in a dedicated owner-only cacheline-isolated struct.

## 7. MED — Backward compatibility is fine; wire-size growth is not evaluated
Summary: `serde(default)` preserves decode compatibility, but the plan ignores the cost of bloating the compact `per_binding` status path.

Explanation: `BindingCountersSnapshot` exists as a focused per-binding view so `per_binding` can expose a small triage subset without forcing every poll through the full `BindingStatus` surface (`userspace-dp/src/protocol.rs:711-718`, `userspace-dp/src/protocol.rs:1367-1423`). The current tests pin exactly that compact wire contract and its backward-compatible extension pattern (`userspace-dp/src/main.rs:1747-1848`). The plan extends both `BindingCountersSnapshot` and `BindingStatus` with a 16-slot histogram plus two scalars, then says the existing status poll can just carry it (`docs/pr/812-tx-latency-histogram/plan.md:261-295`); that solves schema compatibility but says nothing about duplicated payload on every `status` response.

Mitigation: Estimate bytes per binding and either put the histogram on one surface only or introduce a dedicated heavy-telemetry request instead of inflating the compact poll path.

## 8. MED — §11 invokes Bonferroni without defining the actual hypothesis family
Summary: “Correct for 16 buckets” is not a valid decision rule when the proposed verdicts are shape tests across buckets, cells, and correlations.

Explanation: The existing Step 1 methodology insists on named thresholds and explicitly justified investigation-level rules (`docs/pr/line-rate-investigation/step1-plan.md:1128-1135`). The new plan instead says that because the rerun adds 16 bucket counts per cell, a Bonferroni or equivalent correction should be applied over the 16 buckets before any D-subdivision fires (`docs/pr/812-tx-latency-histogram/plan.md:585-591`). But the same section defines D1/D2/D3 as multi-bucket shape patterns and cross-signal correlations, not 16 independent single-bucket nulls (`docs/pr/812-tx-latency-histogram/plan.md:561-581`), so the stated correction family is almost certainly the wrong one.

Mitigation: Pre-register the exact statistics for D1, D2, and D3, then correct across the number of actual tests being run rather than the raw bucket count.

## 9. MED — The atomic-ordering unit test chases a bug class the design itself forbids
Summary: The proposed two-thread submit/completion test is symbolic theater, not validation of the real implementation risk.

Explanation: The plan says the sidecar is plain `Vec<u64>` state with a single owner thread handling both submit stamping and completion processing, so no atomic is required there (`docs/pr/812-tx-latency-histogram/plan.md:194-199`, `docs/pr/812-tx-latency-histogram/plan.md:334-336`). The unit test then proposes two threads racing `record_tx_submit` and `record_tx_completion` on the same offset (`docs/pr/812-tx-latency-histogram/plan.md:401-405`). That does not model production; it manufactures a race the design explicitly says cannot occur, while the actual cross-CPU risk lives in the histogram snapshot path.

Mitigation: Replace that test with single-thread frame-reuse/partial-batch tests and a separate snapshot-consistency test for the histogram/count/sum publication path.

## 10. LOW — Clock-domain consistency is fine only if the implementation forbids ambient `now_ns`
Summary: The plan is internally consistent on clock source, but the implementation surface invites accidental drift.

Explanation: The architect explicitly says all six submit sites and the reap site should use `monotonic_nanos()` for the measured delta (`docs/pr/812-tx-latency-histogram/plan.md:74-77`, `docs/pr/812-tx-latency-histogram/plan.md:101-111`), and the current helper is a single `CLOCK_MONOTONIC` implementation (`userspace-dp/src/afxdp/neighbor.rs:3-15`). The danger is that the TX functions already carry a different `now_ns` for wake/error bookkeeping (`userspace-dp/src/afxdp/tx.rs:1840-1844`, `userspace-dp/src/afxdp/tx.rs:1957-1960`). If an implementor reuses that ambient timestamp instead of taking a fresh submit/reap sample, the metric stops being submit-to-completion latency and starts including unrelated loop delay.

Mitigation: Hide all timestamping behind one helper that fetches its own monotonic clock, and ban caller-supplied timestamps for this metric.

## 11. LOW — The 1.024 µs bucket-0 cut is not the B-vs-D discriminator the narrative implies
Summary: Reusing the drain histogram boundary is defensible for compatibility, but the classifier rationale overclaims what bucket 0 can tell you.

Explanation: The bucket layout says bucket 0 is `[0, 1024 ns)` and calls that the “healthy” regime, while the same section also says typical AF_XDP completion latency is low single-digit microseconds (`docs/pr/812-tx-latency-histogram/plan.md:121-154`; `userspace-dp/src/afxdp/umem.rs:112-118`). Later, Verdict B is defined as mass in buckets 4-7 and D1/D2 as higher-order shifts or tails (`docs/pr/812-tx-latency-histogram/plan.md:564-568`). So the meaningful MQFQ-vs-shaper separation is in grouped tens-of-microseconds buckets, not in whether bucket 0 is sub-1 µs.

Mitigation: Keep the existing layout if wire compatibility matters, but describe the classifier in grouped ranges rather than pretending bucket 0 is load-bearing.

## 12. LOW — “Monotonic, no reset” is operationally sane, but `sum_ns` is the first wrap-limited field
Summary: The no-reset choice is reasonable; the plan just fails to document which counter actually becomes modulo-`u64` first.

Explanation: The plan makes the histogram, count, and exact latency sum all monotonic and explicitly forbids reset-on-snapshot (`docs/pr/812-tx-latency-histogram/plan.md:275-279`, `docs/pr/812-tx-latency-histogram/plan.md:300-315`). Using the plan’s own 130 Kpps per-worker figure and expected single-digit-µs live means (`docs/pr/812-tx-latency-histogram/plan.md:244-246`, `docs/pr/812-tx-latency-histogram/plan.md:380-382`), the packet count is effectively unbounded for operational purposes, but `tx_submit_latency_sum_ns` wraps vastly earlier by inference from those same numbers. That is still not a short-term blocker; it just means delta consumers need explicit modulo semantics.

Mitigation: Document `u64` wrap handling for `tx_submit_latency_sum_ns` and treat the field as modulo arithmetic in any downstream delta logic.

## 13. LOW — The compile-time assert checks bucket count, not the bucket contract
Summary: The proposed assert is worth keeping, but it is too anonymous and too weak to be the only layout guard.

Explanation: The plan proposes `const _: () = assert!(TX_SUBMIT_LAT_BUCKETS == DRAIN_HIST_BUCKETS);` as the compile-time wire-contract guard (`docs/pr/812-tx-latency-histogram/plan.md:160-168`). Current code says the real wire contract is the bucket layout produced by `bucket_index_for_ns`, not merely the fact that there are 16 slots (`userspace-dp/src/afxdp/umem.rs:124-127`, `userspace-dp/src/afxdp/umem.rs:162-165`). An anonymous const will trip the build on count drift, but it says nothing about boundary drift with the count still fixed at 16, and the resulting error message will be opaque.

Mitigation: Give the assert a named symbol and pair it with submit-hist boundary tests that reuse `bucket_index_for_ns` directly.

PLAN-READY: NO
