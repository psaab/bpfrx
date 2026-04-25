# #838 AFD-lite — Negative finding (plan-stage), and the broader fairness picture

## TL;DR

Five rounds of Codex plan review on #838 (AFD-lite, single-binding scope)
keep surfacing new architectural defects. R5 found a structural blocker
(Q9: selector blind during scratch-build) that would require another
round of redesign with no certainty of convergence at R6.

This is the third consecutive cross-binding/scheduler-state fairness
attempt to stall:

| Issue | Approach | Outcome |
|---|---|---|
| #836 | shared MQFQ HOL-finish-time array | Closed at R7 plan review (7 HIGH; non-commutative quantity) |
| #840 | RSS rebalance from per-binding RX signal | Implemented + reverted (`docs/pr/835-slice-d-rss/findings.md`); deploy CoV 37.7 % vs 18.5 % baseline; **made fairness worse** |
| #838 | per-flow bytes-served counter, periodic reset | 5 plan rounds, 14+ HIGH cumulatively; stuck at structural blocker |

**Empirical baseline (#900) shows the existing scheduler is acceptable
for the throughput-fairness problem.** The original "many streams
collapse to 0 bps" symptom does not reproduce under standard test
conditions. The 100E100M problem reduces to mouse-latency-tail
characterization, for which we now have infrastructure (operator
echo server on 172.16.80.200:7) but no measurement.

Recommendation: **stop algorithm work, do measurement.**

## What was actually built across the three attempts

### #836 — shared HOL-finish-time array
- Plan tried to share MQFQ virtual finish times across bindings via
  atomic head/tail per bucket.
- Codex review (`docs/pr/836-shared-flow-vtime/codex-plan-review.md`) found
  HOL-finish-time is **not commutative**: it's a per-packet timestamp,
  changes non-additively on every dequeue, rollback needs snapshot
  state, and concurrent writers can corrupt the ordering.
- Closed without implementation. Folded into the larger #837
  redesign.

### #840 — RSS rebalance from per-binding RX signal
- Implemented. Code review MERGE YES. 33+ unit tests pass.
- Deployed: 10-run CoV measurement.
- **Result: CoV 37.7 % enabled vs 18.5 % baseline** (`docs/pr/840-slice-d-v2/findings.md`).
- Root cause: the rebalance loop steers RSS hashes toward "underloaded"
  RX rings, but those rings are underloaded *because their flows are
  small*; moving the larger flows onto them creates oscillation and
  bigger swings between samples. Empirical evidence that "shift the
  hash" is not a substitute for per-flow scheduling.
- Reverted in commit `1c611d01`; kept atomics+locked-split scaffolding
  for #835 D3.

### #838 — AFD-lite, single-binding scope
- Plan only. v1 → v2 → v3 (single-binding) across 5 Codex rounds.
- v1+v2 (cross-binding): 14 HIGH findings on race ordering, period
  reset coherence, fair_share denominator staleness, and rollback
  semantics. User reduced scope to single-binding only.
- v3 R3-R4 (single-binding): closed most of those, but **R5 found
  Q9**: the selector runs during scratch-build (one decision per
  packet) but accounting happens at settle (one update per *batch*).
  TX_BATCH_SIZE up to 256; best-effort fair share at ~16 packets/period.
  In a single batch the selector can ship multiple periods' worth of
  packets while the per-flow counter still reads zero — AFD never
  engages.
- Fix would need provisional per-batch accounting at selection time
  with rollback on rejected-tail at settle. That is another structural
  redesign, with no R5-clean precedent giving us confidence R6 won't
  surface a different structural issue.

## The pattern

All three attempts share a structural assumption that has not held:

> "We can encode fairness as additional state read/written in the
> existing per-binding hot path."

What actually happens in this codebase:

1. The hot path is **batch-shaped** (TX_BATCH_SIZE ~256), so
   per-packet accounting that drives per-packet decisions has a
   one-batch latency — bigger than the period the algorithm assumes.
2. `flow_bucket_bytes` is a **queue-backlog** counter (bytes waiting),
   not a **bytes-served** counter. The two are different signals;
   #838 was trying to retrofit one as the other.
3. Cross-binding shared atomic state has at-least-three race
   surfaces (period reset, denominator update, rollback) and we keep
   discovering them by review one at a time.
4. The actual *symptom* people see — "stream collapses to zero" — is
   bound up with TCP cwnd dynamics under SFQ buckets, RSS-hash
   distribution, and head-of-line blocking inside a single AF_XDP
   ring. None of those are addressed by the scheduler-state changes
   that were tried.

## What the data actually says (#900)

Single iperf3 stream count varied; 1 Gb/s shaper (iperf-a class):

| streams | aggregate | CoV    | collapsed | within ±25 % of fair |
|--------:|----------:|-------:|----------:|---------------------:|
| 16      | 0.954 Gb  | 18.5 % | 0 / 16    | (baseline)           |
| 128     | 0.954 Gb  | 16.6 % | 0 / 128   | 119 / 128 (93 %)     |

CoV got *tighter* at 128 streams. Worst-case stream is 0.72× of mean
(vs 0.81 at 16 streams) — modest degradation, no collapse.

**The "elephant fairness" half of 100E100M is solved, empirically.**

## What we still don't know — the actual 100E100M gap

The 100E100M problem has two halves:
- **Throughput fairness across N elephants** — measured, acceptable
  at N=128, see above.
- **Latency tail across M mice during heavy elephant load** — never
  measured. Both attempts (hping3, Python TCP-connect) hit
  infrastructure walls (raw-socket scaling, SYN-cookie defense,
  iperf3 single-tenant accept).

We now have a way to measure mouse latency:
- Operator-enabled echo server on **172.16.80.200:7** (TCP+UDP) and
  **2001:559:8585:80::200:7** (v6).
- Per-port CoS classifiers (`test/incus/cos-iperf-config.set`) place
  echo on best-effort (port 7 is not 5201-5204), which is the
  workload we want — mice on best-effort, elephants on iperf-a/b/c.

A measurement here would give us:
- Mouse RTT p50, p95, p99 with N=0 elephants (idle baseline).
- Mouse RTT p50, p95, p99 with N=8, 32, 128 elephants on iperf-a.
- Mouse RTT impact of CoS class assignment (mice on best-effort vs
  mice on iperf-a alongside the elephants).
- Whether the existing SFQ buckets isolate mice from elephant HOL
  blocking, or whether they share queues and mice take the tail.

Without this data, we are guessing at which fairness algorithm is
worth implementing. Algorithm work is the wrong next step.

## What we should do

### Immediate (this PR / branch)

1. **Close #838** with reference to this finding. The branch
   (`pr/838-afd-lite`) holds plan-only commits; no implementation
   shipped. Drop the plan from the in-flight set.
2. **Do not retire #837.** It captures the larger redesign that
   would be needed for true cross-binding MQFQ; if mouse-latency
   data later shows we need it, the design context is preserved.
3. **Clean up the bucket-bytes naming confusion.** The
   `flow_bucket_bytes` field is queue-backlog; comments at
   `userspace-dp/src/afxdp/types.rs:1081` and the surrounding doc
   should call it that, not "bytes served". Future plans keep
   conflating the two.

### Next (new issue, not #838)

4. **File a measurement issue: "characterize mouse latency tail
   under elephant load using 172.16.80.200:7 echo server"**.
   Concrete deliverables:
   - Test harness that launches N (1, 8, 32, 128) iperf3 elephant
     streams on iperf-a (port 5201) and concurrently runs M
     paced TCP-connect+echo probes against port 7.
   - Per-probe RTT histogram exported as JSON.
   - Run matrix: { N ∈ {0, 8, 32, 128} } × { M ∈ {1, 10, 50} } ×
     { mouse_class ∈ {best-effort, iperf-a-shared} } = 24 cells.
   - PASS gate: mouse p99 ≤ 2× idle baseline at N=128, M=10,
     mice on best-effort.
5. **Only after measurement**, decide whether algorithm work is
   needed. If p99 is acceptable, fairness work is closed for now.
   If p99 is bad, the data tells us *which* mechanism to fix —
   per-flow XDP_REDIRECT, per-class queue isolation, AFD on the
   rejected-tail path, etc.

### Deferred

6. **Do not pursue #838 v3 R6+** without a concrete measurement
   that motivates AFD specifically. The Q9 fix (provisional
   per-batch accounting) is a real codebase change with real risk;
   we should not pay that cost speculatively.
7. **Do not reopen #840.** Empirical evidence (CoV 37.7 % vs 18.5 %)
   is conclusive that RSS-rebalance from queue-backlog signal makes
   things worse, regardless of follow-ups #897/#898/#899.

## Lessons we should carry forward

- **Plan reviews diverge when the architecture is wrong.** Five
  Codex rounds with new HIGH findings each round is the pattern of
  a structural mismatch, not a coverage gap. If R3 introduces new
  issues that R2 didn't have, the plan is being bent into a shape
  the codebase doesn't support.
- **"Commutative under races" is a real architectural property.**
  #836 failed because HOL-finish-time isn't. #838 R1+R2 (cross-binding)
  failed because the additional state (period reset, fair-share
  denominator) needed by the commutative `fetch_add` wasn't itself
  commutative.
- **Empirical baseline before algorithm work.** #900 took the same
  effort as one Codex round and produced more decision-relevant
  data than 5 rounds of #838 did.
- **Negative findings have value.** #835/#840/#900 finding files
  are referenced repeatedly and saved later attempts from the same
  trap. Keep writing them. (This file is one of those.)

## Files

- `docs/pr/838-afd-lite/plan.md` — five-round plan; preserved as
  design archive.
- `docs/pr/836-shared-flow-vtime/` — predecessor; HOL-finish
  closed-without-implementation.
- `docs/pr/835-slice-d-rss/findings.md` — RSS rebalance signal-dead
  empirical finding.
- `docs/pr/840-slice-d-v2/findings.md` — RSS rebalance with valid
  signal, CoV-worse-than-baseline empirical finding.
- `docs/pr/900-100e100m-harness/findings.md` — 128-stream baseline
  acceptable.
- `docs/pr/838-afd-lite/findings.md` — this document.
