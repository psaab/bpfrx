# Claude SMR Plan Review — #1612 step-3 v1

**Role**: Domain SMR (network perf measurement, TSC vs clock_gettime,
AF_XDP cold-path instrumentation, Prometheus histogram design).

**Plan**: `docs/pr/1612-scale-target-measurement/plan.md` v1, 2026-05-28.

**Verdict**: PLAN-READY-WITH-NIT

This is the **step-3** implementation slice of the already-reviewed
parent plan in `docs/pr/1607-hw-ceiling-microbench/plan.md` v2-r4
(AGY + Claude SMR + Copilot all READY across 4 rounds; Codex
deterministically infra-blocked on every dispatch — `feedback_codex_infra_must_retry`
exception applies). The parent plan already settled the measurement
strategy (UDP randomized-source-port flooder, TSC 1-in-256, unbounded
cohort default, 16×24 histogram, AGY r3 axis 5 splitmix bijection,
SNAT-free synthetic policy default, TSC-only publication gate). This
step-3 plan inherits that contract verbatim and adds only the
implementation slice + measurement-run scope.

## Round 1 findings

### Pass

- **Scope correctly narrowed.** Plan §1 (8 items + Scale Target
  population) maps cleanly onto parent §4.3 (cold-path counters),
  §4.4 (16×24 histogram), §4.5 (harness), §4.6 (table population),
  §4.7 (wire protocol + Prometheus). Nothing in scope is novel.
- **Parent plan's hardest decisions inherited unchanged.** Sample
  mask = 0xff matches REDIRECT_SAMPLE_MASK at umem.rs:183. Bucket
  count = 24 matches parent §4.4. Slot count = 16 matches parent
  §4.3.4. Default regime = unbounded matches parent §4.2.0 AGY
  r3 axis 1.
- **Hot-path cost analysis sound.** §3.1 amortized 1.1 ns/packet at
  1-in-256 + non-sampled-path one branch + one Relaxed load is
  consistent with the existing REDIRECT_SAMPLE_MASK comparable site
  at umem.rs:923 (which costs the same). No new hot-path allocation.
- **Wire protocol both-sides discipline observed.** §1.5 + §3.5
  enumerate the Rust + Go fields with identical names and
  serde-default / omitempty semantics. New round-trip test in §4.1
  / §4.2 will catch drift. Matches `feedback_wire_protocol_both_sides`.
- **Smoke-runner serialization respected.** §3.6 acknowledges the
  two parallel sub-agents and STAGED-ship fallback when the cluster
  is contested. Per `feedback_smoke_serialized_single_agent`.
- **TSC-only publication gate is the canonical AGY r3 hazard-1
  fix.** §3.2 + §4.6 step 8 implement it as a per-worker post-hoc
  gate, which matches parent §4.6 verbatim.
- **Memory-ordering contract follows the WorkerRuntimeAtomics
  template.** §1.4 publish uses `fetch_add(AcqRel)` to bump
  generation odd, Relaxed stores in between, `fetch_add(Release)`
  back to even — same seqlock pattern at worker_runtime.rs:236-256
  that PR #1311 round-2 explicitly designed for the multi-Relaxed-
  field publish problem.

### Minor / NIT

1. **NIT — sample-gate counter source.** Plan §1.3 picks
   `telemetry.dbg.session_miss & 0xff == 0` as the sample gate.
   That counter is gated behind `cfg!(feature = "debug-log")` per
   poll_descriptor/mod.rs:1075 wrapping — in release builds without
   the debug-log feature, it may not increment, and the sample
   gate will never fire. The right counter source is a dedicated
   `WorkerColdPathCounters::cold_path_sample_phase: u64` that
   increments on every session-miss path through the policy-eval
   site (independently of the debug-log feature). Same 1-in-256
   `& 0xff` mask but with an always-on counter.

2. **NIT — wrapper baseline calibration site.** Plan §1.1 specifies
   calibration at "worker startup". The right entry point is
   `WorkerLoop::new()` *after* the `pthread_setaffinity_np` call
   that pins the worker to its core, NOT before. The latter risks
   the calibration running on the migrating-from-core and inflating
   the baseline. §5 question 7 acknowledges this — the **plan body**
   should fold the answer in rather than leaving it as a
   reviewer-challenge question.

3. **NIT — Prometheus cardinality is correct but the doc should
   record the exact comparable.** §1.6 says "comparable to
   drain_latency_hist". Actual comparable: `metrics_userspace.go`
   currently emits `xpf_userspace_drain_latency_ns_bucket` at 6
   workers × 12 queues × 16 buckets = 1152 series; the new cold-
   path bucket at 2304 series ~2× the existing precedent. Worth
   stating explicitly in the parent §4.7 cardinality table.

4. **NIT — `cold_path_clock_source` Prometheus encoding.** §1.6
   emits `xpf_userspace_worker_cold_path_clock_source{worker_id,
   source}` as a gauge with value 1 = active. This is fine but
   non-standard — Prometheus convention for enum state labels is a
   `_info` gauge constant-1 with a label. Alternative: pre-existing
   info-gauge pattern at `xpf_userspace_worker_info{worker_id,
   tid}`. Plan should pick one — either the current proposal with
   a comment justifying the deviation, or the info-gauge pattern.

### Out-of-band findings (none)

No fatal hazards. The plan respects:
- The parent §4.6 TSC-only gate.
- The AGY r3 axis 5 splitmix bijection.
- The AGY r3 axis 3 p9999-only-on-A1 statistical-budget rule
  (only Table A1 reports p9999; A2 stops at p999).
- The AGY r4 axis 1 SNAT-free default for synthetic-policy-gen.
- The AGY r4 axis 2 `duration_secs + warmup_secs < 60` harness gate.
- The AGY r4 axis 3 4096-flow-cache thrashing documentation.
- The AGY r4 axis 4 deferred-measurement-to-#1612 closure.

### TSC + virtualization risk model

Cross-checked against parent §4.3.2 hazard catalog. On the loss
Incus VM:

- `/proc/cpuinfo` flags: per Debian 13 Incus default kernel, the
  guest sees `constant_tsc nonstop_tsc` if the host CPU exports
  them (verified on a typical Intel Coffee Lake host). The current
  loss cluster runs on Intel CPUs — both flags present.
- `/sys/devices/system/clocksource/clocksource0/current_clocksource`:
  on a freshly booted Incus VM, this is usually `tsc` if the host
  TSC is stable. If kvm-clock takes precedence (e.g. on AMD hosts
  with TSC-scaling enabled), the worker will see clock_gettime as
  the fallback. **The post-hoc per-worker gate is the right hedge.**
- VDSO `__vdso_clock_gettime` on Linux >=4.20 takes ~50 ns vs
  TSC's ~12 ns. The 1-in-256 sampling rate means the worst-case
  amortized cost in the degraded mode is ~0.2 ns/packet — still
  acceptable.

### Histogram-bucket layout audit

24 power-of-two buckets. Bucket[0] = `[0, 1)` ns,
bucket[i] = `[2^(i-1), 2^i)` for i ≥ 1. Bucket[23] upper edge =
2^23 = 8.4 ms (NOT 4.3 s as plan §3.3 says — that's the **24-bit
multiplier** path; the parent §4.4 also says 4.3 s, so this is a
pre-existing prose error to fix in the parent plan, NOT a new
fatal). Even at 8.4 ms, 10K-rule linear-scan cold-path is bounded
above by ~2 ms per the parent §4.4 sizing-cliff estimate — bucket
saturation is not a real risk.

### Wire-protocol round-trip test sufficiency

Plan §4.1 + §4.2 say "round-trip test" but don't enumerate cases.
Recommend the new tests cover:
- All six fields populated (full 16×24 + 16+16+16 vectors).
- Empty fields (older daemon: `cold_path_hist = None`, all
  others default).
- Empty inner `Vec` (e.g. one slot has zero samples — `cold_path_hist[i] = []`).
- Round-trip Go → Rust → Go and Rust → Go → Rust to catch
  asymmetric encoding bugs.

Not blockers. Reviewers can demand specific cases at code-r1.

## Verdict: PLAN-READY-WITH-NIT (round 1)

The 4 NITs above are minor and can be folded into the plan body
in a v2 without requiring another review round. NIT 1 (sample-gate
counter source) is the one that has a real correctness implication
— the rest are doc-shape NITs.

**Folding recommendation**: lift NIT 1 into §1 verbatim, fix NIT 2
in §1.1, add NIT 3 cardinality table to §1.6, pick NIT 4
encoding and document the choice. Then implement.

## Codex-infra-blocked exception note

If Codex returns deterministic sandbox failure on round 1, retry
thrice per `feedback_codex_infra_must_retry`. On persistent failure,
proceed with 3-of-4 (Claude SMR + AGY + Copilot) and label the round.
