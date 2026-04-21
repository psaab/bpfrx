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

## Round 2 verification

ROUND 2: plan-ready NO
HIGH #1 — per-commit monotonic_nanos() VDSO latency: STILL PARTIAL — §3.1 fixes batch math, but §3.4/§4 still assume ~15 ns VDSO and "NOT a syscall"; only §7 covers a zero-return drop path, so syscall fallback/seccomp risk and fallback-cost budget remain unacknowledged (plan.md:119-151,351-405,594-596,792-793).
HIGH #2 — Relaxed atomics + bounded-skew invariant: STILL PARTIAL — the plan derives only "≤0.04 completions" of read skew yet hard-stops at 1%, and §11 still defers τ_D1/τ_D2/τ_D3 derivation, so 1% is arbitrary and signal-vs-noise under the 36-test family is unproven (plan.md:551-558,574-580,939-955).
HIGH #3 — per-binding single-writer claim: CLOSED — `WorkerUmem` is `Rc`, each binding is created from a fresh `WorkerUmemPool::new(..., shared_umem=false)`, and the only cross-thread path found is `live.snapshot()` over `BindingLiveState`; no off-thread writer to a worker-local sidecar was found (umem.rs:15-18,50-53; worker.rs:445-465; coordinator.rs:1318-1322; umem.rs:1182-1354; plan.md:319-330).
MED NEW #1 — Overhead budget breach: §8 no longer enforces the old 1% stop; it now allows 5% steady-state and a 10% small-batch soft-gate, while the table still admits 9.4% worst-case and 3.1% "typical" overhead (plan.md:385-405,816-817).
MED NEW #2 — Bucket-0 resolution (0–1 µs): not materially addressed; §12 explicitly defers the coarse low-end layout, and §11's B signature uses buckets 4-7 only, leaving 256-400 µs outside the stated MQFQ pattern (plan.md:194-199,893,987-992).
LOW NEW #3 — now_ns staleness rejection claim: `loop_now_ns` is refreshed once per worker loop, and the idle path can block for 1 ms, but the "~1 ms" number is inferred from constants rather than measured evidence (worker.rs:619,1423-1447; afxdp.rs:176-178; plan.md:141-152).
MED NEW #4 — 'typical inserted=64' justification: the operating-point table labels `inserted == 64` as "Typical" without any trace, batch histogram, or benchmark citation (plan.md:345-389).

## Round 2 verification

**HIGH #1**: PARTIAL — §3.1/§3.4 now fixes the small-batch math: submit stamps are taken once per `writer.commit()`, worst-case `inserted == 1`, and reused `now_ns` is explicitly rejected as stale (`docs/pr/812-tx-latency-histogram/plan.md:119-152`, `docs/pr/812-tx-latency-histogram/plan.md:333-417`). Current TX code really does peel accepted prefixes and retry tails, so that part is grounded (`userspace-dp/src/afxdp/tx.rs:5953-5960`, `userspace-dp/src/afxdp/tx.rs:6166-6173`). But the closure still smuggles in an unproven VDSO invariant: the actual helper is just `libc::clock_gettime(CLOCK_MONOTONIC, ...)`, with `rc != 0` falling back to `0` (`userspace-dp/src/afxdp/neighbor.rs:3-15`), while the plan still says "`clock_gettime` VDSO is NOT a syscall" (`docs/pr/812-tx-latency-histogram/plan.md:594-598`). I found no code here that proves user-space fast path on x86_64 or ARM, and no seccomp capability check; the documented fallback is merely "sample dropped" (`docs/pr/812-tx-latency-histogram/plan.md:792`). That closes the amortization bug, not the syscall/VDSO claim.

**HIGH #2**: OPEN — The author did rewrite the memory-ordering story: Relaxed loads/stores are now explicitly accepted, production equality is weakened to bounded skew, and §11 reduces the family to `3 x 12 = 36` composite tests (`docs/pr/812-tx-latency-histogram/plan.md:511-583`, `docs/pr/812-tx-latency-histogram/plan.md:918-944`). The problem is the number that matters: `|sum - count| / count <= 0.01`. That 1% appears as naked policy (`docs/pr/812-tx-latency-histogram/plan.md:575-577`, `docs/pr/812-tx-latency-histogram/plan.md:816-817`), while the proposed cross-thread test punts with `K` "chosen per §4 invariant 6" (`docs/pr/812-tx-latency-histogram/plan.md:737-744`). There is no code or comment deriving 1% from snapshot duration, expected counts, or the eventual classifier thresholds; those thresholds are still "derived from baseline-healthy step1 runs, not guessed" (`docs/pr/812-tx-latency-histogram/plan.md:941-944`). Existing code only supports the weaker statement that Relaxed histogram snapshots are tear-tolerant and approximate in steady state (`userspace-dp/src/afxdp/umem.rs:1323-1329`). Until the skew budget is quantitatively tied to the classifier thresholds, this is not closed.

**HIGH #3**: PARTIAL — The ownership story is much better grounded than before. `WorkerUmem` wraps `Rc<WorkerUmemInner>` (`userspace-dp/src/afxdp/umem.rs:15-18`), `BindingWorker` owns that `WorkerUmem` plus owner-local `free_tx_frames: VecDeque<u64>` (`userspace-dp/src/afxdp/worker.rs:3-16`), and bindings are constructed into a worker-local `Vec<BindingWorker>` with `shared_umem = false` in the current create path (`userspace-dp/src/afxdp/worker.rs:440-490`). The cross-thread object I can actually see is `Arc<BindingLiveState>` (`userspace-dp/src/afxdp/worker.rs:205`, `userspace-dp/src/afxdp/worker.rs:421`, `userspace-dp/src/afxdp/worker.rs:475-478`; `userspace-dp/src/main.rs:802-807`), not UMEM. That said, the closure still overclaims: there is no sidecar implementation yet, and the plan cites a supposed shared-UMEM production path via `shared_umem_group_key_for_device` even though that function is `#[cfg(test)]` only (`userspace-dp/src/afxdp/bind.rs:284-293`). Structural evidence exists; airtight proof does not.

**Round 2 new findings**:
  - [MED] §8 is not "the same hard stop." It was explicitly weakened from the old 1% story to `> 5%` steady-state plus a `10%` small-batch soft gate, while §3.4 still admits `3.1%` "typical" and `9.4%` worst-case overhead (`docs/pr/812-tx-latency-histogram/plan.md:396-405`, `docs/pr/812-tx-latency-histogram/plan.md:813-817`). This is a material acceptance-criteria regression. Mitigation: restore a measured hard stop tied to real batch histograms rather than relabeling the worst case as verdict C.
  - [MED] Bucket-0 coarseness was not addressed; it was deferred. The layout still collapses `[0, 1024)` ns into bucket 0 (`docs/pr/812-tx-latency-histogram/plan.md:188-205`), and §12 rebuts low-end asymmetry by appealing to the existing drain histogram rather than by proving MQFQ-vs-shaper discrimination with this bucket map (`docs/pr/812-tx-latency-histogram/plan.md:987-992`). Mitigation: either justify the low-end resolution with baseline captures or stop implying sub-1 us structure matters for verdict separation.

ROUND 2: plan-ready NO

## Round 3 verification

HIGH #1: CLOSED — `evidence/vm_xpf_userspace_fw0.txt` is finally the right target evidence: on `loss:xpf-userspace-fw0` it records a 10,000-iteration `clock_gettime(CLOCK_MONOTONIC)` run under `strace -c -e trace=clock_gettime` with `EXIT=0` and a summary file of `0 lines, 0 bytes`, i.e. zero observed `clock_gettime` syscalls. The same file also shows `/proc/self/maps` containing `7f13408a6000-7f13408a8000 ... [vdso]`. `evidence/vdso_evidence.md` says the host probe also made 10,000 calls and `strace_host.txt` contains only `+++ exited with 0 +++`. On this point, the round-2 closure is real.

HIGH #2: PARTIAL — §3.6 now at least writes the formula `K_skew = ceil(λ × W_read)`, but the chosen ceiling is still under-argued. The same plan's §3.4 says a single saturated 25 Gbps queue is `2.08 Mpps = 481 ns/packet`, and prior review text already cites "25 Gbps / 1500B = 2M pps" (`docs/pr/line-rate-investigation/systems-plan-review.md`). At `λ = 2 Mpps` and `W_read = 1 us`, `K_skew = ceil(2e6 × 1e-6) = 2`, not 1. §3.6 hard-claims "K_skew = 1 completion maximum" from a `λ <= 1 Mpps per worker` assumption, but does not prove that a worker can never own a saturated queue. Worse, §3.6 correctly notes a 4 ms preemption window can mean `4,000 / 100,000 = 4%`, while §8 hard-stop #4 later rewrites the same scenario as "still inside 1%." That contradiction means the closure is improved, not closed.

HIGH #3: CLOSED — §3.5a does not merely say "add a compile-time assert." It gives a concrete Rust pattern: `const _ASSERT_BINDING_COUNTERS_SNAPSHOT_IS_OWNED_STATIC_SEND: () = { const fn require_static_send<T: 'static + Send>() {} require_static_send::<BindingCountersSnapshot>(); };`. That is not the literal `fn assert_send_static` spelling, but it is an exact compile-time idiom with the actual bound and invocation, so this point is specific enough to implement and review.

Round 3 new findings:
  - [HIGH] §11.3's "block-permutation" section is still statistically hand-waved. It invokes "Fisher-Pitman style" but cites no reference, and the stated D1/D2 statistics are whole-window mass ratios (`mass(...)/count`) that are order-invariant. Permuting 1-second blocks does not change those totals, so the null distribution is either degenerate or underspecified. This is not a valid closure of the Bonferroni finding as written.
  - [MED] §6.1 test #7 still does not name a concrete Rust test function signature, and its assertion is looser than the derivation it claims to pin: it checks `|sum-count| <= ceil(λ_obs × W_read_i) + 2`, not the exact `ceil(λ × W_read)` bound from §3.6. That is directionally right, but not the exact invariant the closure summary claims.
  - [MED] §8.1 now openly acknowledges the instrumentation-surface trade-off and even names narrower alternatives (`rdtsc`, sampled batches, dropping exact `sum_ns`). That is better than the round-1 silence. The defense is still analytic rather than measured, though, and it explicitly accepts a `10%` soft-gate on instrumentation-only code. That is a policy choice, not proof that the chosen surface is the minimum necessary one.
  - [LOW] Bucket-0 deferral is actually explicit now. §12 item 8 says "Resolved: explicitly out of scope for #812," cites §11.1/§11.3 R2, and states that verdict B lives in buckets 4-7, C in 8+, D1 in 3-6, D2 in 6-9, D3 in 14-15, with "no classifier statistic reads from bucket 0 at all." This closure is present.

ROUND 3: plan-ready NO

## Round 4 verification

HIGH #2: PARTIAL — `ceil(2e6 × 1e-6) = 2` is correct, but the plan's own 64B/25Gbps/4-worker example implies `λ ≈ 3 Mpps` per worker, so the bound is still understated.
`2e6 × 1e-6 = 2.0`, so `ceil(2.0) = 2`; on the arithmetic alone, the revised `K_skew = 2` step is correct. The remaining problem is the rate premise: the same paragraph says 25 Gbps at 64B is about 48.8 Mpps aggregate, then about 12.2 Mpps across 4 workers, which is about 3.05 Mpps per worker, not 2 Mpps, so `λ = 2 Mpps` is not the conservative ceiling the text claims. If the intended upper bound is the plan's own small-packet line-rate case, the defensible bound is `λ ≈ 3 Mpps`, giving `K_skew = ceil(3e6 × 1e-6) = 3`. On the off-CPU gate, `4 ms × 2 Mpps = 8000` and `8000/200000 = 4%`, so a 1% gate would trip on a snapshot-thread preemption if the denominator were only a 77 ms accumulation window; that is scheduling jitter, not bucket-accounting corruption, so it would be a false positive in that short-window regime. The gate only makes sense as an integration-level check when `count` is the full long-run total, where a one-off 4 ms preemption is diluted well below 1%.

Round 4 new findings (if any): §11.3 still has the same structural problem from round 3: I do not see an "expected number of runs" formula in the current block-permutation text, and the specified D1/D2 cell statistics are whole-window mass ratios, so permuting 1-second blocks does not change them; the null is therefore degenerate or underspecified. The `const _ASSERT... = { const fn require_static_send<T: 'static + Send>() {} ... }` idiom is sound Rust for asserting `BindingCountersSnapshot: Send + 'static`, although it only proves those trait bounds, not every semantic ownership invariant.

ROUND 4: plan-ready NO

## Round 5 verification

HIGH #2: CLOSED — §3.6 now consistently derives `K_skew = 3` from `λ = 3 Mpps` and `W_read ≤ 1 µs`, and every live `K_skew` reference I found reuses that bound. I found no stale live `K_skew = 2` or active `λ = 2 Mpps` math; the only `2 Mpps` mentions left are explicitly historical ("earlier 2 Mpps", "from 2 Mpps to 3 Mpps"), not operative.

Preemption gate: PARTIAL — A single 4 ms CFS preemption contaminates one snapshot call, so in an `N = 20` harness it yields `1/20 = 5 %`, not `> 5 %`; the chronic-issue branch therefore requires at least 2 fired snapshots, so one-off preemption does not trip the hard stop. The math is sound, but the prose should say "2 of 20" explicitly because percentage shorthand obscures that the discriminator is a discrete count threshold.

§11.3 math: PARTIAL — The concrete SciPy call is mostly right: `permutation_type='independent'` matches an independent two-sample block-label permutation, `alternative='greater'` correctly tests whether the cell's pathological-block statistic exceeds baseline, `n_resamples=10_000` is adequate for a `p <= 0.05` gate, and the `p <= 0.05` rejection threshold is stated. The section still contradicts itself, though: it first defines the cell-level statistic as `T_v = max_b T_v,b` and then implements and justifies a mean-difference permutation test over the per-block arrays, so the actual test statistic is not crisply specified.

Round 5 new findings (if any):
- §11.3's sentence claiming "Peak-based reduction is order-sensitive" is wrong on its own terms: a max over a fixed set of block values is order-invariant, and the accompanying SciPy code does not use the max reduction anyway.

ROUND 5: plan-ready NO
