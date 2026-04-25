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
(Codex R1#6): unpaced 100×TCP_RR can deliver tens of Gbps of
offered load, making the mice indistinguishable from elephants.
We pace each mouse at **1000 RR/s**.

**Wire load (Codex R2 A4)**: each TCP_RR transaction is
REQ(64B payload) + RESP(64B payload) + 2 × ACK. Including
TCP/IP/Eth headers (~54 B), each transaction puts on the wire
roughly 64+54 (REQ) + 64+54 (RESP) + 40+40 (ACKs) ≈ 316 B,
or ~288 B if delayed-ACK coalesces some ACKs (Codex's
arithmetic). Per-mouse wire rate at 1000 RR/s is
~2.3-2.5 Mbps. Aggregate across 100 mice ≈ 230-250 Mbps,
which is **23-25% of the 1 Gb/s shaper** — still meaningfully
under the elephants' demand and well below saturation, but
NOT the 5% the prior plan stated. The test is a coexistence
test, not a tiny-mice-vs-fat-elephants test; both classes
contend for shaped capacity.

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

**Aggregating per-mouse percentiles (Codex R1#2 / R2 A2):**
percentile-of-percentiles is biased. Counterexample: with 49
of 100 mice at L+1ms p99 and 51 at L p99, median-of-p99 reports
L — a 1 ms regression on half the mice would be invisible.

Netperf does NOT emit per-transaction samples through `-O`
(only summary statistics from its internal histogram). The
aggregation strategy is: report the **full distribution** of
per-mouse p99 values, exposing four order statistics so a
regression on any minority of mice surfaces:

- `p99_min` = min across the 100 mice's p99 values
- `p99_p50` = median
- `p99_p90` = 90th percentile (catches the 49/100 case above:
  90th of {L×51, (L+1ms)×49} = L+1ms)
- `p99_max` = max (worst-flow watermark)

Plus archive the full sorted list of 100 p99 values per phase
per rep. Headline reports `p99_p90` and `p99_max` as deltas
vs baseline.

**Sub-100 µs deltas remain out of scope** (Codex R2 A2): the
netperf histogram bin width is on the order of 100 µs in
default mode, so claims below that resolution are not
defensible from this data. A future enhancement could add
histogram-merge via netperf `-V`.

### 4.3 Phases

1. **Cluster preflight** (§6.1). Asserts and resets
   environmental state.
2. **Baseline (unloaded mice).** Mice-only, no elephants.
   Duration: 60 s. Captures the floor latency under the same
   classification path.
3. **Cool-down.** 10 s idle between phases so any CoS queue
   backlog drains.
4. **Loaded — proper warm-up sequencing (Codex R1#1 / R2 A1
   / R3#1):**
   - Start `iperf3 -c <target> -p 5201 -P 100 -t 90 -i 1 -J`
     in background. The `-t 90` is a safety upper bound: the
     harness will SIGTERM iperf3 when mice finish (R3#1 fix:
     prior plan had a fixed -t conflicting with variable
     gate-firing time).
   - **Cwnd-settle gate**: poll the iperf3 JSON output for
     completed `intervals[]` entries (each represents a 1 s
     summary). Compute `agg_t = intervals[t].sum.bits_per_second`
     (the 100-stream aggregate at second `t`). Mice start
     when **3 consecutive `agg_t` samples are within ±10% of
     their median AND that median is ≥ 0.5 Gb/s**. If the gate
     doesn't fire within 20 s, abort the rep and mark it
     invalid.
   - Record `t_g` = the iperf3 elapsed second when the gate
     passed (typically ~3-10 s).
   - Start 100 paced netperf mice for 50 s.
   - When mice finish at `t_g + 50` (iperf3-clock), SIGTERM
     iperf3.
   - Elephant CoV is computed using ONLY iperf3 per-stream
     `intervals[]` entries within `[t_g, t_g + 50]` — this
     excludes the warm-up and any post-mice tail (R3#1 +
     R2 B5 closure).
5. **Cool-down.** 10 s idle. Drain math: queue 4 buffer is
   1.19 MiB observed live; at 1 Gb/s drain rate the time to
   drain a full buffer is ≈ 10 ms. 10 s is ~1000× the worst-
   case drain time — generous to accommodate any TCP
   teardown / FIN / TIME_WAIT settling.
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

Across the 100 mice's per-process p99 values, report the
**full distribution** (R2 A2):
- `p99_min` (best-flow watermark)
- `p99_p50` (median)
- `p99_p90` (catches the 49/100 mice regression case)
- `p99_max` (worst-flow watermark)
- raw sorted list archived per phase per rep

Headline reports `p99_p90` AND `p99_max` as deltas vs baseline.

### 5.3 Comparison

The headline numbers are **deltas from baseline**:

- `elephant_cov_loaded` (%, vs reporting reference 15%)
- `mouse_p99_p90_loaded - mouse_p99_p90_baseline` (µs)
- `mouse_p99_max_loaded - mouse_p99_max_baseline` (µs)

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

### 6.0 Remote-process management mechanics (R3#4-#9, MED#10/14)

**Container processes (mpstat, netperf, iperf3, netserver)**
run inside `loss:cluster-userspace-host` (mice, mpstat) or the
iperf3-target instance (netserver). The harness orchestrates
from the bpfrx-fw0 host (the dev machine where this script
runs).

For each backgrounded container process, the launch pattern is:

```bash
incus exec ${instance} -- bash -c '
    <cmd> > /tmp/${out} 2>&1 &
    echo $! > /tmp/${pidfile}
'
```

The `$!` captures the **container-namespace PID**. To stop:

```bash
incus exec ${instance} -- bash -c 'kill -TERM $(cat /tmp/${pidfile}) 2>/dev/null'
incus exec ${instance} -- rm -f /tmp/${pidfile}
```

To collect output back to the host:

```bash
incus file pull ${instance}/tmp/${out} ${HOST_OUT_DIR}/${out}
```

This pattern is used uniformly for every remote backgrounded
process. The harness tracks the (instance, pidfile, out-path)
tuple per process so cleanup can iterate them.

**100 concurrent netperf launch** (R3 MED#10): use a
controlled-startup pattern to minimize stagger:

```bash
# Stage 1: write 100 pidfile names + commands to a job-list
# Stage 2: launch all 100 in a single bash invocation that
# backgrounds each and captures the PID:
incus exec ${SOURCE_INSTANCE} -- bash -c '
    declare -a PIDS
    for i in $(seq 1 100); do
        netperf -H 172.16.80.200 -p 12866 -t TCP_RR -l 50 \
            -- -r 64,64 -P 12865 -O <fields> -b 1 -w 1000 \
            > /tmp/100e100m/mouse-${i}.txt 2>&1 &
        PIDS[i]=$!
    done
    # Write all PIDs to one file the harness can read
    printf "%s\n" "${PIDS[@]}" > /tmp/100e100m/mouse-pids.txt
    # Wait for all
    wait "${PIDS[@]}"
'
```

The 100 backgrounds inside ONE `bash -c` minimize
startup-time variance (no per-iteration `incus exec` overhead).

**cli binary path** (R3 MED#14): use `/usr/local/sbin/cli` —
that is the path the cluster-deploy script installs to
(`test/incus/cluster-setup.sh:644`) and the path on the
production-deployed VMs. `/usr/local/bin/cli` may shadow on
some hosts (per global memory) but on the firewall instances
the sbin path is canonical.

**cli config-mode transactions** (R3#4-5): `cli rollback`
without an enclosing `configure ... commit ... exit` does NOT
activate the rollback (per `pkg/configstore/store.go:893-909`,
rollback only mutates candidate state). All harness cli
config-mode operations use the heredoc pattern:

```bash
incus exec loss:xpf-userspace-fw0 -- bash -c "/usr/local/sbin/cli <<'EOF'
configure
<set/delete commands>
commit
exit
EOF"
```

For rollback specifically:

```bash
incus exec loss:xpf-userspace-fw0 -- bash -c "/usr/local/sbin/cli <<'EOF'
configure
rollback 1
commit
exit
EOF"
```

`cli -c <single-cmd>` is reserved for **operational** commands
only (e.g. `cli -c 'show class-of-service interface'`).



### 6.1 Preflight

Order matters (R3#7): register the EXIT trap BEFORE any
mutation, so a failure between step 1 and step N still leaves
the system in a clean state.

```
1. Capture run timestamp <run-ts>; create
   /tmp/100e100m/<run-ts>/.
2. Set tracker variables: MOUSE_FILTER_APPLIED=0,
   PIDFILES_TO_CLEAN=() (an array of (instance, pidfile)
   tuples), HARNESS_PGID=$(setsid bash -c 'echo $$').
3. Register EXIT trap (R3#7 / R2 C2). Trap actions, in order:
   a. For each tracked (instance, pidfile): `incus exec
      ${instance} -- bash -c 'kill -TERM $(cat /tmp/${pf})
      2>/dev/null; rm -f /tmp/${pf}'`.
   b. If MOUSE_FILTER_APPLIED == 1: roll back via the
      heredoc pattern in §6.0 (configure / rollback 1 /
      commit / exit). Do NOT touch the base CoS — that is
      intentionally persistent post-harness.
   c. Pull any container output files the harness recorded
      so a debug snapshot is preserved on partial failure.
4. Verify both firewall VMs RUNNING via `incus list`.
5. Assert `systemctl is-active xpfd` returns "active" on
   fw0 AND fw1 (R3 finding closure for incomplete daemon
   state).
6. Verify RG0 primary == node0 via the operational cli
   (`/usr/local/sbin/cli -c 'show chassis cluster status'`);
   fail loudly if not.
7. Resolve iperf3 target instance (R3#6): read
   `IPERF3_TARGET_INSTANCE` from
   `loss-userspace-cluster.env` (which the harness PR
   adds — see §13). If unset or instance not RUNNING,
   abort with "iperf3 target instance not configured;
   add IPERF3_TARGET_INSTANCE to env" message.
8. Install required tools (R3 MED#11 fix: explicit `if`,
   not `||/&&`):
   a. On iperf3 target instance:
      ```
      if ! incus exec ${IPERF3_TARGET_INSTANCE} -- \
           command -v netserver >/dev/null 2>&1; then
          incus exec ${IPERF3_TARGET_INSTANCE} -- \
              apt-get update -qq 2>/tmp/apt-update.err || \
              { echo "apt-get update failed: $(cat /tmp/apt-update.err)" >&2; exit 1; }
          incus exec ${IPERF3_TARGET_INSTANCE} -- \
              apt-get install -y netperf || \
              { echo "netperf install failed on target" >&2; exit 1; }
      fi
      ```
   b. Same pattern on `cluster-userspace-host` for
      `netperf` and `sysstat` (provides `mpstat`).
9. On iperf3 target: start netserver on port 12866 using
   the pidfile pattern from §6.0. Verify with
   `nc -zv 172.16.80.200 12866` from the source.
10. Apply base CoS via `apply-cos-config.sh` (idempotent).
11. Apply mouse classifier extension (§4.4) via heredoc:
    ```
    /usr/local/sbin/cli <<'EOF'
    configure
    set firewall family inet filter bandwidth-output term mouse from destination-port 12865-12866
    set firewall family inet filter bandwidth-output term mouse then forwarding-class iperf-a
    commit check
    commit
    exit
    EOF
    ```
    On success, set MOUSE_FILTER_APPLIED=1. On failure,
    abort (the EXIT trap will not roll back since the
    flag is still 0).
12. Verify `cli -c 'show class-of-service interface'`
    reports queue 4 owner=1, exact=yes, transmit-rate=
    1 Gb/s. Fail if not.
13. Assert iperf-a queue runtime backlog == 0 (queued_pkts
    == 0) — if non-zero, sleep 5 s and retry up to 3 times.
14. Capture journalctl baseline timestamp for fw0 and fw1
    so per-rep failover detection (R2 A7) can grep
    `journalctl --since=<rep_T0>` for cluster transition
    lines.
```

### 6.2 Per-rep loop

Output paths use the form `/tmp/100e100m/<run-ts>/<rep-N>/<phase>/`
where `<run-ts>` is a single timestamp captured at harness
start, so re-runs do not overwrite (R2 B3).

```
1. Mark rep_T0 = now.
2. Snapshot CoS counters via cli on fw0 (before).
3. Start `mpstat 1 -o JSON` in background on source,
   redirected to <rep>/baseline-mpstat.json. Track the pid.
4. Run 100 netperf mice for 60 s; capture each stdout to
   <rep>/baseline-mice/<i>.txt. Track aggregate netperf pids
   in the harness pgid.
5. Stop mpstat (kill the tracked pid).
6. Sleep 10 s cool-down.
7. Snapshot CoS counters (mid).
8. Start mpstat 1 -o JSON for loaded phase.
9. Start `iperf3 -c <target> -p 5201 -P 100 -t 60 -i 1 -J`
   in background, output to <rep>/loaded-elephants.json.
10. Apply cwnd-settle gate (§4.3 step 4): poll the JSON for
    `intervals[]` entries every 500 ms. Compute
    `agg_t = intervals[t].sum.bits_per_second`. Pass when
    3 consecutive `agg_t` are within ±10% of their median
    AND median ≥ 0.5 Gb/s. Abort + invalidate rep if no pass
    within 20 s.
11. Run 100 netperf mice for 50 s; capture as in step 4.
12. Wait for iperf3 to finish (-t 60, will end ~10 s after
    mice start, so finishes roughly when mice finish).
13. Snapshot CoS counters (after).
14. Stop loaded-phase mpstat.
15. Pull `journalctl -u xpfd --since=<rep_T0>` from fw0 and
    fw1 (R2 A7); grep for cluster transition lines.
    Invalidate rep if any "cluster: primary transition",
    "cluster: secondary transition", or
    "RG readiness: not-ready" appears.
16. Compute per-rep validity flags (§5.4).
17. Compute per-rep summary (elephant CoV, mouse p99
    distribution, deltas).
18. Sleep 10 s cool-down.
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

### 6.4 Run count, IQR, and auto-extension

**Default 10 reps.** Total runtime ≈ 10 × (60 + 10 + 70 + 10)
≈ 25 min.

**IQR definition** (R3 MED#12): all percentile reporting uses
**nearest-rank percentiles**:
- `p25 = sorted_values[ceil(0.25 × N) − 1]`
- `p50 = sorted_values[ceil(0.50 × N) − 1]`
- `p75 = sorted_values[ceil(0.75 × N) − 1]`
- `p90 = sorted_values[ceil(0.90 × N) − 1]`
- `IQR = p75 − p25`

This convention is applied consistently:
- Across the 100 mice's per-process p99 values within a phase
  (10 reps × 100 mice values).
- Across reps for any metric (e.g. across-reps median elephant
  CoV).

**Minimum-valid-rep auto-extension** (R3 MED#13): if fewer
than **7 reps are valid** after the initial 10, the harness
runs additional reps in batches of 5 until at least 7 reps
are valid OR until 20 reps total have been attempted. If 20
reps still don't yield 7 valid, the harness emits FAIL and
the operator must investigate environmental issues (see §5.4
validity flags).

**IQR warning destination** (R3 LOW#15): if IQR > 50% of
median for any headline metric, the harness emits a
human-readable warning to **stderr** (not affecting exit
status) AND records `iqr_warning: true` per-metric in the
JSON summary. Operator decides whether to re-run with more
reps; the test does not auto-fail on high IQR.

**Artifact retention** (R3 LOW#16):
- Default: keep the most recent 5 run directories under
  `/tmp/100e100m/`; older runs auto-pruned at start.
- `--keep-artifacts` flag disables auto-pruning.
- Per-run directory size is bounded (~6 MB max with 10 reps)
  so 5 runs ≤ 30 MB.

A future enhancement (out of scope) is adaptive bootstrap
with a 95% CI stopping rule.

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
  run with optional `--reps N` and `--dry-run` flags. The
  `--dry-run` flag (R2 C3) executes preflight, validates the
  classifier extension applies and rolls back cleanly, but
  does NOT run the elephant/mouse phases — for fast harness
  debugging without paying the full 27-minute test cost.
- Baseline measurement (with the **current** code, no algorithm
  change) is captured and committed to the PR description as a
  table (R3#2/3 fix: aligned with §5.2/§5.3):
  - elephant aggregate Gbps (median, IQR)
  - elephant per-flow CoV (median, IQR)
  - mouse `p99_p90` baseline µs (median across reps, IQR)
  - mouse `p99_p90` loaded µs (median across reps, IQR)
  - mouse `p99_p90` delta (µs)
  - mouse `p99_max` baseline / loaded / delta (µs)
  - rep validity table (which reps were valid; reasons for
    any drops)
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

## 12. Review responses

### Round 1 (9 findings)

| # | Sev | Topic                         | Resolution |
|---|-----|-------------------------------|------------|
| 1 | HIGH| Methodology rigor             | 10 reps default; cwnd-settle gate; median+IQR |
| 2 | HIGH| Mouse percentile aggregation  | report full p99 distribution (min/p50/p90/max) |
| 3 | HIGH| Class collision               | 12865/12866 firewall filter in §4.4 |
| 4 | HIGH| Source CPU bottleneck         | mpstat + 90% CPU validity flag |
| 5 | LOW | Per-flow distinction          | record bucket-peak as observability |
| 6 | HIGH| Per-mouse RR rate             | pace 1000 RR/s; verify achieved RPS |
| 7 | MED | CoS counter delta             | per-counter deltas; invalidate on regression |
| 8 | MED | Reproducibility after fail    | preflight kills stale procs in our pgid |
| 9 | HIGH| Acceptance gate values        | reporting thresholds; PR doesn't close #897-899 |
| 10| MED | HA failover protection        | RG-watcher + journalctl grep |

### Round 2 (12 findings)

| # | Sev | Topic                         | Resolution |
|---|-----|-------------------------------|------------|
| A1| HIGH| Cwnd-settle gate ambiguity    | Pinned: 3 consecutive `intervals[].sum.bits_per_second` within ±10% of median, ≥0.5 Gb/s, 20s timeout |
| A2| HIGH| Median-of-p99 hides regression| Report full p99 distribution: p99_min/p99_p50/p99_p90/p99_max + sorted list archive |
| A3| -   | Port-range syntax check       | CLOSED — confirmed supported per `lexer.go:235`, `parser_security_test.go:337` |
| A4| LOW | Wire-load math                | Corrected to ~230-250 Mbps aggregate (TCP_RR with headers + ACKs); 23-25% of shaper |
| A5| -   | Plan honesty on no-SLO closure| CLOSED — §9 explicit |
| A6| MED | Global pkill kills tenants    | Track harness pgid; kill only ours via `kill -KILL -<pgid>` |
| A7| MED | 5s RG poll misses sub-second  | Cross-check journalctl cluster transition messages since `rep_T0` |
| B1| HIGH| sysstat not installed         | Preflight `command -v mpstat` || `apt-get install -y sysstat` |
| B2| MED | iperf3 -t 80 inconsistency    | Fixed to `-t 60` (10s warm-up + 50s mouse window) |
| B3| LOW | Output path inconsistency     | Standardized: `/tmp/100e100m/<run-ts>/<rep-N>/<phase>/` |
| B4| LOW | Cool-down drain math          | Documented: 1.19 MiB / 1 Gb/s ≈ 10 ms drain; 10s is 1000× margin |
| B5| MED | Elephants-only tail inflates CoV| Eliminated by trimming to -t 60 (no tail) |
| C1| MED | apt-get error path missing    | `apt-get update -qq` + exit-code check + abort with logged error |
| C2| HIGH| No EXIT trap for filter teardown| EXIT trap in step 10 of preflight: cli rollback removes mouse classifier term, kills pgid |
| C3| LOW | No --dry-run for development  | `--dry-run` flag added: runs preflight + filter apply + rollback only |
| N1| HIGH| netserver target undefined    | Preflight reads target from env, `incus exec` for management, fails clearly if not present |

### Round 3 (16 findings)

| # | Sev | Topic                            | Resolution |
|---|-----|----------------------------------|------------|
| 1 | HIGH| Variable cwnd-settle vs fixed -t | iperf3 -t 90 (safety upper bound); harness SIGTERMs when mice finish; CoV computed only over [t_g, t_g+50] window |
| 2 | HIGH| §8 acceptance contradicts §5.2/3 | §8 table now uses p99_p90 + p99_max (median-of-p99 removed everywhere) |
| 3 | HIGH| Median-p99 still in headline     | Median removed from headline; only p99_p90 + p99_max reported as deltas |
| 4 | HIGH| `cli rollback` non-interactive   | Heredoc pattern (`configure / rollback 1 / commit / exit`) documented in §6.0 |
| 5 | HIGH| `cli -c 'rollback'` doesn't work | Same fix as #4; -c reserved for operational commands only |
| 6 | HIGH| env file lacks IPERF3_TARGET     | Add `IPERF3_TARGET_INSTANCE` to `loss-userspace-cluster.env` (§13) |
| 7 | HIGH| EXIT trap registered too late    | Trap registered in step 3 of preflight, BEFORE any cli mutation. Tracker flag MOUSE_FILTER_APPLIED gates rollback |
| 8 | HIGH| Container output collection      | §6.0 pins `incus file pull` from container `/tmp/...` to host `/tmp/100e100m/<run-ts>/...` |
| 9 | HIGH| mpstat PID is container-side     | §6.0 pins pidfile-on-container pattern: write `$!` from `incus exec`, kill via `incus exec ... kill -TERM $(cat pidfile)` |
| 10| MED | 100 netperf launch primitive     | §6.0 pins single-`bash -c` background-loop pattern; minimizes startup stagger |
| 11| MED | apt-get precedence bug           | §6.1 step 8 uses explicit `if ! command -v ...; then ... fi` with stderr capture |
| 12| MED | IQR not formally defined         | §6.4 defines nearest-rank percentiles + IQR = p75 − p25 |
| 13| MED | 7 valid reps borderline          | §6.4 auto-extends in batches of 5 up to 20 total if <7 valid |
| 14| MED | cli binary path unspecified      | §6.0 pins `/usr/local/sbin/cli`; -c only for operational commands |
| 15| LOW | IQR-warning action               | §6.4: stderr warning + `iqr_warning: true` in JSON summary; no exit-status change |
| 16| LOW | No artifact cleanup              | §6.4: keep last 5 run dirs by default; `--keep-artifacts` flag |

## 13. Environmental config addition

This PR adds one variable to `test/incus/loss-userspace-cluster.env`:

```
# iperf3 / netperf target instance (must be RUNNING and have
# 172.16.80.200 reachable). Required by test-100e100m.sh.
IPERF3_TARGET_INSTANCE=<name>
```

The harness sources the env file via the standard
`BPFRX_CLUSTER_ENV` mechanism used by `cluster-setup.sh`.
