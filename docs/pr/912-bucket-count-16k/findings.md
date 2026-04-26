# #912 — Negative finding: raising COS_FLOW_FAIR_BUCKETS to 16384
# does NOT fix iperf-b same-class HOL; it makes it worse.

Issue: #912 (closed, reverted)
Plan: `docs/pr/912-bucket-count-16k/plan.md`
Umbrella: #911

## TL;DR

The implementation per the v3 plan (PLAN-READY YES at R4) was
deployed to the loss userspace cluster and **reverted** after
empirical testing showed mouse-latency tail at iperf-b same-class
got dramatically WORSE, not better.

| Configuration | Mouse p99 (iperf-b N=8 M=10, single 60s rep) |
|---|---:|
| Master baseline (1024 inline arrays) | **5.21 s**  ← measured today |
| Pre-#912 matrix data (1024 inline) — 3 hours earlier | 0.323 s (median of 10 reps) |
| #912 v3 (16384 + Box<[T;N]> heap) | **5.75 s** |
| #912 partial revert (1024 + Box) | **8.84 s** |
| #912 partial revert (16384 + inline) | **4.32 s** |

The bucket-count grow alone (16384 inline) regressed mouse p99
from ~323 ms to ~4.3 s — about 13× worse. The Box conversion
made it strictly worse still. Both directions of the change
hurt.

## What this tells us

1. **The bucket-collision diagnosis in #911 / 905-findings is
   incomplete.** Reducing collision probability by 16× did not
   fix the same-class HOL. Whatever mechanism is producing the
   tail is not primarily collision-driven.

2. **There is real cluster-state variability.** The same master
   binary measured ~323 ms p99 in the morning matrix and 5.21 s
   in the afternoon validation. The cross-class iperf-b case
   (mice on best-effort) stayed stable at ~7 ms p99 across both
   runs. So the variability is specific to same-class iperf-b
   under the configurable conditions present in our test
   harness — possibly echo-server load, conntrack accumulation,
   memory pressure, or something else outside the daemon.

3. **The Box<[T; N]> conversion appears to introduce a real
   regression.** At 1024 buckets, inline gave 0.32-5.21 s
   p99 (huge variance) while Box gave 8.84 s consistently. This
   is unexpected — Box auto-deref should be free or near-free
   on the hot path. Possibilities to investigate before
   re-attempting any boxed approach:
   - The Vec → Box<[T]> → try_into → Box<[T; N]> idiom may not
     compile to the same auto-deref pattern as a struct field.
   - Cache-line locality may be lost when bucket arrays are in
     separate heap regions vs. inline with other queue state.
   - `std::array::from_fn(|_| VecDeque::new())` and the boxed
     equivalent may not produce the same layout.

4. **The fix-direction was wrong.** The diagnosis pointed at
   bucket collision but raising buckets did not help. The actual
   mechanism is still unidentified. Candidate (B) — rate-aware
   per-flow admission cap — should not be attempted until we
   have a better diagnosis. A "raise the cap" change could
   easily fail the same way.

## What was reverted

Commit 06a6acd5 ("#912 userspace-dp: raise COS_FLOW_FAIR_BUCKETS
1024 → 16384, heap-Box bucket arrays") was reverted in full. The
plan doc at `docs/pr/912-bucket-count-16k/plan.md` and this
findings file remain as a record of the failed experiment.

## Engineering process notes

The full standard pipeline ran for this PR:

- 4 Codex hostile plan-review rounds (PLAN-READY YES at R4 after
  resolving HIGH issues around hard-pinned 1024 sites, memory
  estimate undercounting, stack-pressure mitigation, and helper
  visibility).
- 1 Codex hostile code-review round (returned MERGE NO with
  blockers around stale comments + weak hash-pin coverage).
- Cluster deploy + smoke test before opening PR.

The failure mode wasn't caught by any of these — only by
deploy + measure on the actual workload. That's the right
discipline; the engineering process worked even though the
hypothesis didn't.

## Recommended next steps

1. **Do not retry bucket-count grow** without first explaining
   today's empirical 5.21 s baseline at master. Until we
   understand WHY the same configuration measured 323 ms at
   ~17:00 and 5.21 s at ~21:00, no controlled experiment is
   possible.

2. **Investigate the cluster-state variability separately.** The
   echo-server side, conntrack table state, and any in-flight
   sessions across runs all need to be controlled before any
   subsequent same-class measurement is reliable.

3. **Avoid Box<[T; N]> for hot-path bucket storage** until the
   regression mechanism in this PR's #4 Box variant is
   understood. Inline may be slower in some way but it stays
   functional.

4. **The original #905 PASS gate verdicts (iperf-a PASS at 1.10×,
   iperf-b FAIL at 34.95×, iperf-c FAIL at 31.80×) remain the
   reference data.** They came from a single run on the same day
   and are internally consistent. They should be re-validated
   before any next algorithm investigation.

## Files

- `docs/pr/912-bucket-count-16k/plan.md` — v3 plan (preserved as
  design archive)
- `docs/pr/912-bucket-count-16k/findings.md` — this document
- Commit 06a6acd5 — reverted
