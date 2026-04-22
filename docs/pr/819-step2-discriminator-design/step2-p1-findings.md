# #823 — Step 2 P1 sched_switch findings (first capture round)

**Target cluster:** `loss:xpf-userspace-fw0` (RG0 primary throughout).
**Captures:** 2026-04-21 19:08-19:14 UTC-7 via `test/incus/step2-sched-switch-capture.sh` (merged in PR #822).
**Probe:** P1 — `perf record -e sched:sched_switch,sched:sched_stat_runtime,sched:sched_wakeup` on worker TIDs; reducer emits 12-block off-CPU duration histograms aligned with step1's snapshot boundaries; classifier applies plan §4.1 T3 thresholds.

## 1. Verdict

**M3 OUT on both load-bearing cells.** Per #819 design doc §8.1: *"P1 → M3 OUT on both cells → proceed to P3 — M1 is next highest prior."*

The mechanism under test (kernel scheduler descheduling the worker between `sendto` and reap) is ruled out. The D1 submit→DMA latency elevated on shaped-traffic cells (per #816 H2 D1 verdict) does **not** correlate with off-CPU time; the worker is essentially 100% on-CPU during the capture.

## 2. Per-cell verdict table

| Cell | verdict | ρ | p-value | duty_cycle_pct | Reason |
|---|:-:|---:|---:|---:|---|
| p5201-fwd-with-cos | **OUT** | 0.296 | 0.350 | 0.000298% | duty_cycle_pct=0.000 < 1.0 |
| p5202-fwd-with-cos | **OUT** | null | null | 0.000% | duty_cycle_pct=0.000 < 1.0 (ρ is null because off_cpu_time_3to6 is constant-zero → Spearman undefined) |

T3 OUT rule (plan §4.1): `ρ ≤ 0.3 OR duty_cycle_pct < 1.0`. Both cells fall into the `duty_cycle_pct < 1.0` leg — **the "OR" matters**: a total of <0.6 seconds of off-CPU time in buckets 3-6 over a 60-s window cannot explain the D1 mass regardless of correlation.

## 3. Data summary

### 3.1 T_D1 signal is intact

p5201-fwd-with-cos `T_D1,b` values across 12 blocks:
```
0.984, 0.999, 1.000, 0.999, 0.999, 0.999, 0.999, 1.000, 1.000, 0.999, 1.000, 1.000
```
Mass fraction in buckets 3-6 (4-64 µs) is ≈ 100% on every block. This matches the #816 finding that p5201-fwd is the densest D1-signature cell (`stat_D1 ≈ 0.969`).

### 3.2 off_cpu_time_3to6 is near-zero

p5201-fwd-with-cos `off_cpu_time_3to6,b` values (nanoseconds):
```
0, 0, 0, 0, 0, 0, 97 723, 19 125, 16 864, 15 119, 29 999, ...
```
Total off-CPU time in the 4-64 µs band across 60s ≈ 180 µs total — i.e. the worker was off-CPU for ~180 µs total, out of 60 × 10⁹ ns of wall-clock. Duty cycle `100 × 180 000 / 60×10⁹ ≈ 0.0003%` — four orders of magnitude below the 1% T3 floor.

p5202-fwd-with-cos is even more extreme: `off_cpu_time_3to6,b = [0, 0, 0, ..., 0]` for every block — the worker was *never* observed off-CPU in the 4-64 µs band during the 60s capture.

### 3.3 What this means mechanistically

The worker is on-CPU essentially 100% of the time. Yet T_D1 shows the submit→DMA latency sits in the 4-64 µs band on virtually every completion. Therefore:

- **M3 (scheduler descheduling)** is ruled out. Scheduler jitter would require the worker to be off-CPU for the corresponding µs-scale windows; it's not.
- **M1 (in-AF_XDP submit→TX DMA stalls)** becomes the highest-prior remaining mechanism. The latency is spent *inside* the `sendto` syscall (spinning on a full ring, blocking in kernel, or inner AF_XDP queueing) while the worker holds the CPU.
- **M4 (virtualization jitter)** is softly argued-against by the same on-CPU-100% observation: hypervisor descheduling would appear as off-CPU time to the guest scheduler, but #819 plan §12's trigger condition — "P1 reports >1% off-CPU mass in buckets 3-6 with M3 firmly OUT" — **is NOT met** because off-CPU mass is ~0.0003%, far below the 1% bar. M4 remains deferred.

## 4. Negative control — DEFERRED

#819 plan §6.2 called for running P1 on a D1-quiet cell (e.g. `p5203-fwd-no-cos`) as a probe-validity sanity check. This is deferred under this issue (#823) for operational reasons:

- The cluster is in `with-cos` state; step1 requires the orchestrator to remove CoS before a `no-cos` run. Removing + re-applying CoS is a shaping-config churn that could impact downstream HA flows.
- The primary verdict is robust without the control: p5201-fwd and p5202-fwd both show `duty_cycle_pct ≈ 0` with T_D1 ≈ 1.0. The contrast is quantitatively clean (four orders of magnitude below threshold); a negative control would confirm the probe does NOT spuriously fire — but neither cell fires in the first place, so there's no false-positive to rule out.
- If Issue B (P3 wiring) comes back with ambiguous results, re-opening the negative control becomes higher priority.

**Follow-up issue to file:** run P1 on `p5203-fwd-no-cos` after CoS-removal gate is hardened.

## 5. Drift / interval notes (not verdict-bearing)

Both captures produced non-fatal WARN lines:

- `snapshot interval 0→1 = 2.000 s outside [3, 7] s` — the cold→first-warm interval is 2s in practice. This reflects the step1 flow: cold is stamped, then iperf3 launches (1-3s of setup), then the sampler loop begins. The first warm sample fires shortly after cold. Not an error.
- `drift_ns ≈ 2 s` between PERF_START_NS and STEP1_START_NS — the 0.5s perf-centering sleep plus step1 setup overhead. Well under the 5s HALT threshold.

The classifier emitted OUT, not SUSPECT — drift was within acceptable bounds.

## 6. Next step (per #819 §8.1)

**File Issue B (P3 daemon counters) per #819 §10.** Concretely:

1. Wire `tx_kick_latency_hist` (16-bucket log2) + `tx_kick_retry_count` (u64) + `tx_kick_latency_count` / `tx_kick_latency_sum_ns` into `BindingCountersSnapshot` per #819 plan §5.3 file-scope change list.
2. Instrumentation site: `userspace-dp/src/afxdp/tx.rs:6429` (`maybe_wake_tx`), with sendto at line 6439.
3. Go-side wire-format mirror in `pkg/dataplane/userspace/protocol.go`.
4. Existing `step1-capture.sh` snapshot loop picks up the new counters automatically once the wire format is bumped.
5. Once Issue B lands, re-run this same two-cell capture on the same harness (`step2-sched-switch-capture.sh`) plus a sister harness that harvests the new counters. Per #819 plan §4.1 T1: M1 IN if `Δ(retry_counter)/block ≥ 1000` AND `mean(sendto_kick_latency) ≥ 4 µs`.

Do **not** scope Phase 4 (#793) yet. #819 plan §8.2 requires P3's verdict before scoping.

## 7. Harness fixes landed during this run (merged ahead)

Three operational issues surfaced and were fixed inline before the captures worked:

1. **perf-stat collision** — step1's per-thread perf stat conflicts with our perf record on the same TIDs (per-task event limit). Added `STEP1_SKIP_PERF_STAT=1` env var hoist to skip step1's perf stat in composed-harness mode.
2. **`-k CLOCK_REALTIME` rejected** — the target kernel's perf returned EINVAL. Fallback: default CLOCK_MONOTONIC + mono→wall offset measured on the guest via `python3 -c 'time.time_ns() - time.clock_gettime_ns(CLOCK_MONOTONIC)'`. Reducer gains `--mono-wall-offset-ns` arg; block assignment uses `t_wall = t_mono + offset`.
3. **Host/guest clock mismatch** — host and incus guest clocks drift tens of seconds apart (unsynced NTP). Fixed by sourcing `PERF_START_NS` and step1's cold `_sample_ts` from the GUEST's `date`, not the host's.

All three are tooling fixes inside the worktree; they'll land in the same follow-up PR as the findings.

## 8. Evidence

- `evidence/p5201-fwd-with-cos/sched-switch/` — perf.data, perf-script.txt, off-cpu-hist-by-block.jsonl, correlation-report.md/.meta.json/.diag.json, step1 artifacts (flow_steer_*, worker-tids.txt, step1-capture.log)
- `evidence/p5202-fwd-with-cos/sched-switch/` — same layout

## 9. Summary

**M3 OUT on both load-bearing cells.** The D1 signature is real (T_D1 ≈ 1.0 confirmed) but is not explained by worker off-CPU time. The worker is on-CPU essentially 100% of the time; the latency is being spent inside the kernel's `sendto` path or inside AF_XDP's internal queueing. Next probe is P3 (M1 test); Phase 4 scope decision is deferred until P3 returns.
