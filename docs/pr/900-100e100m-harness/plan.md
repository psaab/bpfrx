# 100E100M Test Harness — Plan

Issue: #900

## 1. Goal

Empirically characterize how the existing `xpf-userspace-dp` SFQ
flow-fair scheduler behaves under the canonical
"100 elephants + 100 mice" workload, before designing any new
algorithm.

Specific questions:

1. **Elephant bandwidth fairness.** With 100 long-lived TCP
   streams in the same CoS class, what is per-flow CoV? Target
   ≤ 15% per #835 §6.4.
2. **Mouse latency tail.** With 100 short request/response flows
   competing for the same shaped class as 100 elephants, what is
   the latency delta from unloaded baseline? Target p99 within
   ≤ 200 µs of unloaded; p99.9 within ≤ 1 ms.
3. **SFQ bucket collisions.** 200 flows / 1024 buckets gives
   ~17% expected collision rate (birthday paradox). Does the
   resulting bucket-level head-of-line blocking visibly punish
   the colliding mice?

## 2. What this is NOT

- Not an algorithm change. The harness is a measurement tool.
- Not a HA failover test. Failover behavior is out of scope; we
  run on RG0-primary throughout.
- Not a flow-steering test (#899). RSS distribution is observed
  but not measured; we expect the SFQ inside the CoS queue to
  be the dominant fairness mechanism.

## 3. Test environment

- Cluster: `loss:xpf-userspace-fw0/fw1` (the standard userspace
  HA cluster).
- Source: `loss:cluster-userspace-host`.
- Target: 172.16.80.200 (the iperf3 server already used by
  `apply-cos-config.sh`).
- CoS class: **iperf-a** (1 Gb/s shaped). Choosing the
  bandwidth-constrained class so the shaper actually engages
  and the SFQ has work to do; iperf-b at 10 Gb/s might leave
  too much headroom.
- Workers=6, queue 4 owned by worker 1.

## 4. Workload definition

### 4.1 Elephants

100 long-lived TCP streams via `iperf3`:

```
iperf3 -c 172.16.80.200 -p 5201 -P 100 -t <duration> -J
```

`-P 100` forks 100 parallel TCP streams in a single iperf3
process. Each stream uses default cwnd / 16 KiB segments,
sustained for the test duration.

### 4.2 Mice

100 short request/response flows via `netperf TCP_RR`:

```
netperf -H 172.16.80.200 -p <netperf-port> -t TCP_RR -l <duration> \
    -- -r 64,64 -O min_latency,mean_latency,p50_latency,p90_latency,p99_latency,max_latency
```

`TCP_RR` ping-pongs 64-byte messages. `min/mean/p50/p90/p99/max`
percentiles come from netperf's omni output. To get **per-flow
distinct connections** (rather than 100 RR ops on one
connection), we run **100 concurrent netperf processes**, each
opening its own TCP connection. The aggregate of their
percentiles is the mouse latency profile.

**Why netperf, not ping/mtr:** ping is ICMP and would not be
classified into the same CoS class as iperf-a (DSCP rewrite
applies to TCP). TCP_RR keeps the classification consistent and
exercises the same shaper / SFQ path.

**Port choice:** netperf needs a service running on the iperf3
target. We run `netserver` alongside iperf3 on
`cluster-userspace-host` (or the target VM) on a port that
classifies into the iperf-a class.

### 4.3 Phases

1. **Baseline (unloaded mice).** Mice-only, no elephants.
   Duration: 60 s. Captures the floor latency under the same
   classification path.
2. **Loaded.** Elephants and mice start within 1 second of each
   other; both run for 60 s. The first 10 s of loaded
   measurement is **discarded** as warm-up (TCP cwnd settling,
   netperf process startup). Stats collected from the remaining
   50 s.
3. **Cool-down.** 10 s idle between phases so any CoS queue
   backlog drains.

### 4.4 Run count

5 repetitions. Per-repetition stats are collected; the harness
reports both per-repetition results and across-repetition
aggregate (median, min, max for each metric). 5 is a tradeoff
between measurement noise rejection and total runtime
(5 × (60 + 60 + 10) ≈ 11 minutes).

## 5. Metrics

### 5.1 Elephants

From iperf3 JSON, per-stream `sender.bits_per_second`:

- **Aggregate Gbps**: sum of all streams.
- **Per-flow CoV**: `stdev(rates) / mean(rates)` across the 100
  streams. Reported as a percentage.
- **Min/max stream Mbps**: range markers.
- **Total retransmits**: sanity check on link health.

### 5.2 Mice

From each of the 100 netperf processes:

- p50, p99, p99.9, max latency in microseconds.

Aggregate across the 100 mice: pool all per-flow samples and
compute global p50/p99/p99.9. (Each netperf reports its own
percentiles based on its own RR samples; pool them by taking
the percentile-of-percentiles, which is an approximation but
adequate for this measurement.)

### 5.3 Comparison

The headline numbers are **deltas**:

- `elephant_cov_loaded` (vs PASS gate 15%)
- `mouse_p99_loaded - mouse_p99_baseline` (vs PASS gate 200 µs)
- `mouse_p999_loaded - mouse_p999_baseline` (vs PASS gate 1 ms)

## 6. Implementation outline

`test/incus/test-100e100m.sh`:

```
1. preflight: verify both VMs are running, RG0-primary is fw0,
   CoS config is applied (idempotent re-apply), netserver is
   running on the iperf3 target with a port that classifies
   into iperf-a.
2. phase: baseline
   2a. start 100 netperf processes in background, capture per-flow
       latency to /tmp/100e100m/baseline-mice/
   2b. wait for all to finish
3. cool-down 10s
4. phase: loaded
   4a. start iperf3 elephants in background (single iperf3 -P 100)
   4b. start 100 netperf processes in background, same as 2a
   4c. wait for both
5. parse JSON output, emit summary
6. (per repetition) repeat steps 2-5
7. emit final aggregate summary
```

Helper: `iperf3-server` already runs on the target; we add
`netserver` setup as a one-shot in the preflight step.

## 7. Reproducibility + observability

- **Deterministic ports**: elephants on iperf3 port 5201
  (existing iperf-a class), mice on a port range
  `5201-5201` … wait, netperf needs its own port. We add a
  custom rule: TCP dst-port 12860 → iperf-a. Document this in
  the cos-iperf-config.set fixture or as a one-time cli command
  in the preflight.
- **Logging**: each phase writes `/tmp/100e100m/<rep>/<phase>/`
  with iperf3 JSON, all netperf stdout files, and a `summary.txt`.
- **Daemon log capture**: at end, fetch `journalctl -u xpfd
  --since=<start>` from fw0 and snapshot it alongside the
  metrics. This lets us see if any rebalance / SFQ / flow_share
  warnings fired.
- **CoS counters**: snapshot `show class-of-service interface`
  before and after each loaded phase. The `flow_share`,
  `ecn_marked`, `park_queue` counters tell us what SFQ + the
  shaper did.

## 8. Acceptance for this PR

- Script lands in `test/incus/test-100e100m.sh`, single-command
  run.
- Baseline measurement (with the **current** code, no algorithm
  change) is captured and committed to the PR description.
- One of these recommendations follows from the data:
  - **(a) SFQ is sufficient**: mouse p99 delta ≤ 200 µs and
    elephant CoV ≤ 15%. Close #897, #898, #899 with reference
    to this finding; no algorithm work needed.
  - **(b) Mouse latency degrades**: file follow-up issue with
    the candidate algorithm class (AFD vs MQFQ vs FQ-CoDel)
    based on what specifically degraded — bucket collisions vs
    drain-rate shortage vs queue depth blow-up.
  - **(c) Elephant CoV degrades**: file follow-up issue
    investigating SFQ DRR quantum or per-flow sketch.

## 9. Risks / open questions

1. **Port classifier scope**: classifying netperf into iperf-a
   requires either a port-range firewall rule or a separate
   class. If we put mice in iperf-b (10 Gb/s class), the
   "same-class contention" hypothesis isn't tested. Pin: mice
   and elephants MUST be in the same CoS queue.
2. **netperf RR rate**: each netperf TCP_RR runs as fast as it
   can. 100 concurrent processes might saturate CPU on the
   client container before the firewall is contended. Mitigation:
   verify aggregate mouse RPS isn't CPU-bound; if it is, drop
   per-mouse rate or raise total bandwidth.
3. **TCP cwnd + ECN dynamics**: even ideal per-packet fairness
   gives some CoV from TCP backoff. ECN is enabled (live
   counters show `ecn_marked=4975584`). Long-tail elephants may
   have larger cwnd and dominate.
4. **Run-to-run variance**: 5 reps may not be enough to detect
   small effects. If variance is too wide, expand to 10 reps
   in a follow-up.
5. **`netperf` install**: not in the standard cluster image.
   Add to the harness preflight: `apt-get install -y netperf`
   on the cluster-host.

## 10. Out-of-scope items captured for later

- Long-duration test (1 hr+) to detect drift / leak.
- Tail latency under HA failover.
- Per-binding load skew (would need eBPF tracing or a per-
  binding histogram in the daemon).
- Comparison against a "no SFQ" baseline (would require
  disabling flow-fair via config; not currently exposed).
