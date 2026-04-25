# 100E100M Test Harness — Plan

Issue: #900

## 1. Goal

Empirically characterize how the existing `xpf-userspace-dp` SFQ
flow-fair scheduler behaves under the canonical
"100 elephants + 100 mice" workload, before designing any new
algorithm.

Specific questions:

1. **Elephant bandwidth fairness.** With 100 long-lived TCP
   streams in the same CoS class, what is per-flow CoV? PASS
   reference value 15% from #835 §6.4 (cited as comparison, not
   a hard product gate — see §9 for why all gate values in this
   plan are reporting thresholds, not product decisions).
2. **Mouse latency tail.** With 100 short request/response flows
   competing for the same shaped class as 100 elephants, what
   is the latency delta from unloaded baseline? Reporting only;
   no SLO baseline exists yet to gate against.
3. **SFQ bucket collisions.** 100 elephant + 100 mouse flows
   over 1024 buckets gives negligible collision probability,
   but a broken flow-key hash would silently degrade fairness;
   capture `admission_flow_share_drops`, `admission_ecn_marked`,
   and queue-runtime peak active bucket count as observability
   to detect that.

## 2. What this is NOT

- Not an algorithm change. The harness is a measurement tool.
- Not a HA failover test. We monitor RG state across the run
  and INVALIDATE any rep where the primary changes; failover
  itself is out of scope.
- Not a flow-steering test (#899). RSS distribution is observed
  but not measured; we expect the SFQ inside the CoS queue to
  be the dominant fairness mechanism.
- Not an issue-closer for #897/#898/#899. This PR reports data;
  whether to close those issues happens in a follow-up after
  product decides what mouse-latency budget is acceptable.

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
- Both elephants and mice MUST classify into queue 4
  (iperf-a). See §4.4 for the firewall-filter fix that makes
  this happen for netperf's default port 12865.

## 4. Workload definition

### 4.1 Elephants

100 long-lived TCP streams via `iperf3`:

```
iperf3 -c 172.16.80.200 -p 5201 -P 100 -t <duration> -J
```

`-P 100` forks 100 parallel TCP streams in a single iperf3
process. Each stream uses default cwnd / 16 KiB segments,
sustained for the test duration. 100 distinct ephemeral source
ports give 100 distinct 5-tuples for the SFQ hash, fanning into
1024 buckets with negligible collision probability.

### 4.2 Mice

100 paced TCP_RR streams via `netperf`. **Paced** is critical
(Codex finding #6): unpaced 100×TCP_RR can deliver tens of
Gbps of offered load, making the mice indistinguishable from
elephants. We pace each mouse at **1000 RR/s**, giving aggregate
offered mouse load of ~51 Mbps (100 × 1000 × 64 B × 8) ≈ 5%
of the 1 Gb/s class shaper — clearly distinguishable from
elephant load.

```
netperf -H 172.16.80.200 -p 12866 -t TCP_RR -l <duration> \
    -- -r 64,64 -P 12865 -O \
       min_latency,p50_latency,p90_latency,p99_latency,mean_latency,max_latency \
       -b 1 -w 1000  # max 1 burst per 1000us = 1000 RR/s
```

(`-b` and `-w` form netperf's burst-mode pacing — verify in
implementation; if the version available doesn't support pacing,
wrap with `taskset` + sleep loop in the harness.)

Each of 100 mice runs as a separate netperf process (per-process
TCP connection ⇒ per-mouse 5-tuple).

**Why netperf, not ping/mtr/wrk2:** ping is ICMP (separate CoS
classifier path); wrk2 is HTTP (extra application stack noise).
TCP_RR keeps classification tight to the firewall's CoS path
and exercises the same shaper / SFQ that elephants hit.

**Aggregating per-mouse percentiles (Codex finding #2):**
percentile-of-percentiles is biased when per-process sample
counts differ. Netperf does NOT emit per-transaction samples
through `-O`, only summary statistics from its internal
histogram. Two options:

- Option A: netperf `-V` (verbose) + custom histogram parser.
  Each process emits a histogram; we sum histograms across
  processes and compute global p50/p99 from the merged
  distribution. This requires per-version netperf compatibility
  testing.
- Option B: drop p99.9 from reporting; report **median-of-p99**
  across the 100 mice as a robust summary. Acknowledge this
  approximates the actual p99-across-all-samples and document
  the bias direction (median-of-p99 ≤ true global p99).

Implementation will start with **Option B** and revisit if the
results are inconclusive. p99 deltas of ≥ 1 ms will be visible
under either method; sub-100 µs deltas may need Option A.

### 4.3 Phases

1. **Cluster preflight** (§6.1). Asserts and resets
   environmental state.
2. **Baseline (unloaded mice).** Mice-only, no elephants.
   Duration: 60 s. Captures the floor latency under the same
   classification path.
3. **Cool-down.** 10 s idle between phases so any CoS queue
   backlog drains.
4. **Loaded — proper warm-up sequencing (Codex finding #1):**
   - Start iperf3 elephants.
   - Wait 10 s for elephant TCP cwnd to settle (verify by
     reading per-second iperf3 intervals via `-i 1 -J`; require
     two consecutive seconds within 10% of each other before
     starting mice).
   - Start 100 paced netperf mice for 50 s.
   - Stop elephants when mice finish.
5. **Cool-down.** 10 s idle.
6. **Repeat steps 2-5** per repetition.

### 4.4 Class collision fix (Codex finding #3)

The current `test/incus/cos-iperf-config.set` only classifies
TCP destination port 5201 into `iperf-a`. Netperf-default port
12865 misses the classifier and lands in best-effort (queue 0,
100 Mb/s), defeating the test.

We run netperf with **explicit ports**:
- Control port: 12866 (matches our firewall filter)
- Data port: 12865 (passed via `-P` to netperf, also matches)

The harness extends the existing CoS classifier filter with a
single Junos set-line idempotent re-apply at preflight:

```
set firewall family inet filter bandwidth-output term mouse \
    from destination-port 12865-12866
set firewall family inet filter bandwidth-output term mouse \
    then forwarding-class iperf-a
```

Mice and elephants now both land in queue 4 (iperf-a). This is
inserted via `apply-cos-config.sh` style atomic commit so a
failure rolls back to the previous good config.

`netserver` is started on the iperf3 target on port 12866 by
the harness preflight if not already running.

## 5. Metrics

### 5.1 Elephants

From iperf3 JSON, per-stream `sender.bits_per_second`:

- **Aggregate Gbps**: sum of all streams.
- **Per-flow CoV**: `stdev(rates) / mean(rates)` across the 100
  streams. Reported as a percentage.
- **Min/max stream Mbps**: range markers.
- **Total retransmits**: sanity check on link health.

### 5.2 Mice

Per-mouse from netperf:
- min, p50, p90, p99, mean, max latency in µs (from netperf's
  `-O` summary).
- transactions/sec achieved (compare to 1000 target — if
  below, that mouse was bottlenecked).

Across 100 mice:
- **median-of-p99** µs (the headline percentile).
- min, max, IQR (25th–75th percentile across the 100 mice's
  reported p99 values).

### 5.3 Comparison

The headline numbers are **deltas from baseline**:

- `elephant_cov_loaded` (%, vs reporting reference 15%)
- `mouse_p99_loaded - mouse_p99_baseline` (µs)
- `mouse_p99_loaded / mouse_p99_baseline` (× factor)

These are reporting thresholds only. No issue is closed against
them by this PR (Codex finding #9). A follow-up issue with a
product-defined SLO will use this baseline data to make
algorithm decisions.

### 5.4 Per-rep validity flags

A rep is **invalidated** (excluded from the aggregate) if any of:

1. **Source CPU saturated** (Codex finding #4): `mpstat 1` on
   `cluster-userspace-host` shows user+system+softirq CPU > 90%
   for any 1 s window during the loaded phase. Set this as a
   per-rep flag; harness reports loaded reps where this fired.
2. **HA primary changed** (Codex finding #10): `cli show
   chassis cluster status` polled every 5 s on fw0 — if `node0`
   stops being RG0-primary at any point during the rep,
   invalidate.
3. **CoS counter regression** (Codex finding #7): any monotonic
   counter (`admission_flow_share_drops`, `admission_ecn_marked`,
   `park_queue_tokens`) decreases between before-snapshot and
   after-snapshot. Indicates daemon restart mid-rep.
4. **Elephant aggregate < 0.5 Gb/s**: indicates the firewall is
   not actually engaging the iperf-a shaper, so any mouse
   coexistence story is meaningless. Threshold conservative —
   shaper rate is 1 Gb/s, healthy aggregate should be ~0.95.

All invalidations are reported in the summary; the test
fails if more than 30% of reps are invalidated (signals
environmental issue requiring fix before continuing).

## 6. Implementation outline

### 6.1 Preflight (Codex finding #8)

```
1. Verify both firewall VMs RUNNING via `incus list`.
2. SSH into fw0: assert `systemctl is-active xpfd` returns
   "active". Same for fw1.
3. Verify RG0 primary == node0 via cli on fw0; fail loudly
   if not (manual operator action needed).
4. Kill any stale iperf3 / netperf / netserver processes on
   `cluster-userspace-host` and on the iperf3 target VM
   (`pkill -9` then sleep 1).
5. Apply CoS config via `apply-cos-config.sh` (idempotent).
6. Apply mouse classifier extension (§4.4).
7. Start netserver on iperf3 target on port 12866 if not
   running.
8. Verify `cli show class-of-service interface` reports
   queue 4 owner=1, exact=yes, transmit-rate=1Gb/s. Fail if
   not.
9. Assert iperf-a queue runtime backlog == 0 (queued_pkts == 0
   in the show output) — if non-zero, sleep 5 s and retry up
   to 3 times.
10. Install netperf on the source container if missing
    (`apt-get install -y netperf`).
```

### 6.2 Per-rep loop

```
1. Mark T0 = now.
2. Snapshot CoS counters via cli on fw0.
3. Start mpstat 1 in background on source, redirected to
   /tmp/100e100m/<rep>/baseline-mpstat.log.
4. Start RG-watcher in background polling `cli show chassis
   cluster status` every 5 s.
5. Run 100 netperf mice for 60 s; capture each stdout to
   /tmp/100e100m/<rep>/baseline-mice/<i>.txt
6. Sleep 10 s cool-down.
7. Snapshot CoS counters (mid).
8. Restart mpstat for loaded phase.
9. Start iperf3 -P 100 -i 1 -J for ~80 s in background to
   /tmp/100e100m/<rep>/loaded-elephants.json.
10. Wait for cwnd settle: poll iperf3 stderr or read JSON
    progress; require 10 s of stable per-stream rate.
11. Run 100 netperf mice for 50 s; capture as in step 5.
12. Wait for iperf3 to finish (will exit after ~80 s).
13. Snapshot CoS counters (after).
14. Stop RG-watcher and mpstat.
15. Compute per-rep validity flags (§5.4).
16. Compute per-rep summary (elephant CoV, mouse median p99,
    deltas).
17. Sleep 10 s cool-down.
```

### 6.3 Aggregation

```
1. For each rep, compute the metrics in §5.1 and §5.2.
2. Drop invalid reps per §5.4 flags.
3. Across the valid reps, report median, IQR, min, max for
   each headline metric.
4. Emit a single-screen summary AND a JSON dump for archival.
5. Print the rep validity table (which reps were dropped and
   why).
```

### 6.4 Run count (Codex finding #1)

**Default 10 reps.** Total runtime ≈ 10 × (60 + 10 + 80 + 10) =
~27 min. Plan §3 reports use 10 reps minimum. If the variance
across the 10 reps gives an IQR > 50% of the median for any
headline metric, the harness emits a warning recommending
re-running with `--reps 20`.

A future enhancement (out of scope for this PR) is to support
adaptive bootstrap with a 95% CI stopping rule; for now we
stick with fixed-N reps and explicit IQR reporting.

## 7. Reproducibility + observability

- **Deterministic ports**: elephants 5201 (iperf-a), mice
  12865/12866 (iperf-a after the §4.4 filter extension).
- **Logging**: each rep writes
  `/tmp/100e100m/<timestamp>/<rep>/<phase>/` with iperf3 JSON,
  100 netperf stdout files, mpstat log, RG-watcher log, and
  computed `summary.txt`.
- **Daemon log capture**: at end of run, fetch
  `journalctl -u xpfd --since=<run-T0>` from fw0 and fw1 and
  snapshot alongside the metrics. Captures any rebalance / SFQ
  / flow_share warnings.
- **CoS counter deltas** (Codex finding #7): parse before/mid/
  after snapshots into per-counter deltas (after − before for
  loaded phase, mid − before for baseline phase). Emit deltas
  in the summary; invalidate the rep if any decreases.
- **mpstat per rep** (Codex finding #4): captured in
  background; 90% CPU saturation detection from this log
  drives the per-rep validity flag.

## 8. Acceptance for this PR

- Script lands in `test/incus/test-100e100m.sh`, single-command
  run with optional `--reps N` flag.
- Baseline measurement (with the **current** code, no algorithm
  change) is captured and committed to the PR description as a
  table:
  - elephant aggregate Gbps (median, IQR)
  - elephant per-flow CoV (median, IQR)
  - mouse median-p99 baseline µs
  - mouse median-p99 loaded µs
  - mouse median-p99 delta (µs and × factor)
- Rep validity table showing which reps were valid and why any
  were dropped.
- The PR body explicitly says "this PR does not close
  #897/#898/#899; algorithm decisions require a product-defined
  mouse-latency budget which is out of scope." (Codex finding
  #9).
- All 880+ Go tests pass; `make test-failover` not required (the
  harness doesn't change daemon behavior).

## 9. Acceptance gate caveats (Codex finding #9)

The CoV and latency thresholds in §5.3 are **reporting
references only**, not product gates:

- Elephant CoV 15% comes from #835 §6.4 (an internal
  measurement convention, not a customer SLO).
- Mouse p99 / p99.9 thresholds in the original plan draft were
  uncited; removed from this revision. We report deltas, not
  pass/fail.

Closing #897/#898/#899 or filing follow-up algorithm work
requires a separate decision based on whether the measured
deltas are tolerable for the product use case. That decision is
out of scope for this PR.

## 10. Risks / open questions

1. **netperf pacing precision** (Codex finding #6 mitigation):
   `-b 1 -w 1000` should pace at ~1000 RR/s but the precise
   semantics depend on netperf version. Verify in
   implementation; if the installed version doesn't support
   `-w` or the pacing drifts, wrap netperf in a
   `taskset` + `sleep` driver script.
2. **Aggregate mouse RPS verification**: the harness MUST
   confirm achieved aggregate mouse RPS ≈ 100 × 1000. If
   significantly lower, mice are CPU-bottlenecked client-side
   (Codex finding #4) — invalidate.
3. **iperf3 -P 100 single-process**: 100 streams in one process
   share the same iperf3 thread for stats aggregation. Ramp-up
   may be slower than 100 parallel iperf3 instances. The
   `cwnd settle` check in §6.2 step 10 mitigates this.
4. **Run-to-run variance on shared cluster**: the `loss:`
   remote may have other tenants. Variance check (IQR > 50% of
   median) signals this.
5. **netperf install** in the cluster image: not guaranteed.
   Preflight handles via `apt-get install -y netperf`.

## 11. Out-of-scope items captured for later

- Long-duration test (1 hr+) to detect drift / leak.
- Tail latency under HA failover.
- Per-binding load skew (would need eBPF tracing or a per-
  binding histogram in the daemon).
- Comparison against a "no SFQ" baseline (would require
  disabling flow-fair via config; not currently exposed).
- Histogram-based mouse latency aggregation (Option A in §4.2)
  for sub-100 µs delta resolution.
- Adaptive bootstrap CI for variable rep count.

## 12. Codex round 1 review responses

| # | Severity | Topic                         | Resolution |
|---|----------|-------------------------------|------------|
| 1 | HIGH     | Methodology rigor             | Bumped to 10 reps default; warm-up uses cwnd-settle gate; report median/IQR |
| 2 | HIGH     | Mouse percentile aggregation  | Drop p99.9 from headline; report median-of-p99 with documented bias |
| 3 | HIGH     | Class collision               | Add 12865/12866 to firewall classifier in §4.4 |
| 4 | HIGH     | Source CPU bottleneck         | mpstat collection + 90% CPU validity flag |
| 5 | LOW      | Per-flow distinction          | Sufficient (100 < 1024 buckets, negligible collision); record bucket-peak as observability |
| 6 | HIGH     | Per-mouse RR rate             | Pace at 1000 RR/s = ~51 Mbps aggregate; verify achieved RPS |
| 7 | MED      | CoS counter delta             | Parse before/after into deltas; invalidate on counter regression |
| 8 | MED      | Reproducibility after fail    | Preflight kills stale procs, asserts xpfd healthy, checks queue backlog |
| 9 | HIGH     | Acceptance gate values        | Demoted to reporting thresholds; explicit caveat that PR does not close #897/#898/#899 |
| 10| MED      | HA failover protection        | RG-watcher polls every 5 s; per-rep validity flag on primary change |
