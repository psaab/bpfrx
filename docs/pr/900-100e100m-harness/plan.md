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

100 concurrent TCP-SYN probe streams via **hping3** (replaces
netperf TCP_RR). Reasoning for the swap (R6 self-audit):

1. **No daemon needed on the iperf3 target.** hping3 sends
   raw TCP SYN packets to any listening TCP port; the
   target's kernel replies SYN-ACK from its existing
   listening socket (the iperf3 server already bound on
   port 5201). The prior netperf-based plan required
   installing + running netserver on 172.16.80.200, which is
   operator-provisioned and outside our incus management.
2. **Same forwarding-class as elephants for free.** Mice hit
   port 5201 just like elephants, so the existing
   `cos-iperf-config.set` classifier puts them in `iperf-a`.
   **No firewall-filter extension needed** — the entire §4.4
   "class collision fix" + corresponding EXIT trap rollback
   complexity drops from the plan.
3. **Per-packet RTT samples in stdout.** hping3 emits one
   `rtt=N.N ms` line per probe, giving raw per-sample
   latency data — better than netperf's omni summary, which
   was histogram-binned with ~100 µs resolution. With raw
   samples we can compute honest p99 and p99.9.

**Pacing**: per-mouse rate **10 SYN/s** (`-i u100000` =
100 ms gap). Aggregate across 100 mice = 1000 SYN/s.
Intentionally lower than the prior netperf-based 1000 RR/s
per mouse because each SYN with a fresh seq creates a
half-open conntrack entry on the firewall and we do not
want to fill conntrack during the test (conntrack saturation
is a different question, see §10).

**Wire load**: each transaction is one SYN out (~64 B with
headers) + one SYN-ACK back (~64 B) + nothing else (no ACK,
no FIN — half-open ages out at the target). At 10/s/mouse ×
64 B × 8 = ~5 Kbps/mouse; aggregate 100 × 5 Kbps =
**500 Kbps total mouse load**, ~0.05 % of the 1 Gb/s shaper.
Mice are genuinely tiny relative to elephants — the
canonical 100E100M shape (latency-sensitive small flows
vs bandwidth-hungry elephants).

Per-mouse invocation:

```
hping3 -S -p 5201 -c 600 -i u100000 \
    -k -s <unique-source-port> 172.16.80.200
```

Flags:
- `-S` send SYN, `-p 5201` destination port (already in
  iperf-a class)
- `-c 600` count = 10/s × 60 s
- `-i u100000` 100 000 µs interval = 10 packets/s
- `-k` keep source port across the run (so all SYNs from
  one mouse appear as duplicate-SYNs on the firewall and
  create exactly ONE half-open conntrack entry per mouse —
  not one per packet)
- `-s <port>` unique-per-mouse source port from the
  ephemeral range; harness allocates 100 distinct values

Each of 100 mice runs as a separate hping3 process (per-
mouse 5-tuple via fixed source port).

**Why not ping/mtr/wrk2/netperf:** ping is ICMP (separate
classifier path); wrk2 needs an HTTP server; netperf needs
netserver on the target. hping3 SYNs traverse the firewall's
TCP CoS path and exercise the same shaper / SFQ that
elephants hit, with no server-side daemon required.

**Aggregating per-mouse percentiles (Codex R1#2 / R2 A2):**
percentile-of-percentiles is biased. Counterexample: with
49 of 100 mice at L+1 ms p99 and 51 at L p99, median-of-p99
reports L — a 1 ms regression on half the mice would be
invisible.

hping3 emits per-packet RTT samples in stdout — unlike
netperf's omni summary, we have **all 60 000 individual
samples per phase** (100 mice × 600 packets/mouse). The
aggregation strategy:

- Pool all per-packet RTT samples across the 100 mice into
  one global distribution per phase. Compute global
  p50/p90/p99/p99.9 from the merged sample set.
- Also report the per-mouse p99 distribution (min/p50/p90/
  max) so a localized degradation on a minority of mice
  surfaces.

Headline reports both:
- `pooled_p99` and `pooled_p999` (true percentiles across
  all 60 000 samples — newly possible with raw hping3
  output)
- `per_mouse_p99_p90` and `per_mouse_p99_max` (the order
  statistics from R2 A2)

### 4.3 Phases

1. **Cluster preflight** (§6.1). Asserts and resets
   environmental state.
2. **Baseline (unloaded mice).** Mice-only, no elephants.
   Duration: 60 s. Captures the floor latency under the same
   classification path.
3. **Cool-down.** 10 s idle between phases so any CoS queue
   backlog drains.
4. **Loaded — proper warm-up sequencing (Codex R1#1 / R2 A1
   / R3#1 / R4#1+#2):**
   - Start `iperf3 -c <target> -p 5201 -P 100 -t 90 -i 1`
     **WITHOUT `-J`** (R4#2: `-J` only emits JSON at process
     end, breaking live polling). Stream text stdout into a
     log file the gate can `tail -F` while iperf3 is running.
     The `-t 90` is a safety upper bound: the harness will
     SIGTERM iperf3 when mice finish.
   - **Cwnd-settle gate** (text-mode parser): tail the
     stdout log; iperf3 `-i 1` emits per-stream `[ID]` lines
     and a `[SUM]` line per second. Parse `[SUM]` aggregate
     bits/sec values. Gate passes when **3 consecutive
     `[SUM]` aggregate samples are within ±10% of their
     median AND that median is ≥ 0.5 Gb/s**. If the gate
     doesn't fire within 20 s, abort the rep and mark it
     invalid.
   - Record `t_g` = the iperf3 elapsed second when the gate
     passed (typically ~3-10 s).
   - Start 100 paced hping3 mice for 60 s (10 SYN/s × 60 s
     × 100 mice = 60 000 RTT samples).
   - When mice finish at `t_g + 60` (iperf3-clock), SIGTERM
     iperf3. iperf3's text output already includes per-second
     intervals on stdout; no JSON to truncate.
   - Elephant CoV is computed by post-parsing the text log:
     filter to per-stream lines with `[ID]` rows
     timestamped within `[t_g, t_g + 50]`, sum bytes per
     stream, divide by 50 s for per-stream rate. This
     excludes warm-up and any post-mice tail.
5. **Cool-down.** 10 s idle. Drain math: queue 4 buffer is
   1.19 MiB observed live; at 1 Gb/s drain rate the time to
   drain a full buffer is ≈ 10 ms. 10 s is ~1000× the worst-
   case drain time — generous to accommodate any TCP
   teardown / FIN / TIME_WAIT settling.
6. **Repeat steps 2-5** per repetition.

### 4.4 Class collision

(Removed in R6 self-audit: hping3 mice target port 5201, the
same port elephants use. The existing `cos-iperf-config.set`
classifier already maps port 5201 → iperf-a. No firewall-
filter extension is needed; the entire classifier-rollback
EXIT-trap branch from prior plan revisions also drops.)

## 5. Metrics

### 5.1 Elephants

From iperf3 JSON, per-stream `sender.bits_per_second`:

- **Aggregate Gbps**: sum of all streams.
- **Per-flow CoV**: `stdev(rates) / mean(rates)` across the 100
  streams. Reported as a percentage.
- **Min/max stream Mbps**: range markers.
- **Total retransmits**: sanity check on link health.

### 5.2 Mice

Per-mouse from hping3 stdout. Each line of the form
`len=44 ip=... rtt=N.N ms` contributes one RTT sample.
Per-mouse aggregate:
- count of received samples (compare to 600 target — if
  fewer, that mouse had drops/timeouts).

**Pooled distribution** across all 100 mice's samples (R6
self-audit: now possible because hping3 emits raw samples,
unlike netperf):
- `pooled_p50` µs (median across all 60 000 samples)
- `pooled_p90` µs
- `pooled_p99` µs
- `pooled_p999` µs (newly attainable)

**Per-mouse p99 order statistics** (R2 A2 — still useful
to catch localized degradations):
- `per_mouse_p99_p50` (median across 100 mice)
- `per_mouse_p99_p90` (catches the 49/100 mice regression)
- `per_mouse_p99_max` (worst-flow watermark)
- raw sorted list archived per phase per rep

Headline reports `pooled_p99`, `pooled_p999`,
`per_mouse_p99_p90`, and `per_mouse_p99_max`, all as
deltas vs baseline.

### 5.3 Comparison

The headline numbers are **deltas from baseline**:

- `elephant_cov_loaded` (%, vs reporting reference 15%)
- `pooled_p99_loaded - pooled_p99_baseline` (µs)
- `pooled_p999_loaded - pooled_p999_baseline` (µs)
- `per_mouse_p99_p90_loaded - per_mouse_p99_p90_baseline` (µs)
- `per_mouse_p99_max_loaded - per_mouse_p99_max_baseline` (µs)

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
   `drain_park_queue_tokens`, `drain_park_root_tokens`,
   `root_token_starvation_parks`, `queue_token_starvation_parks`
   per `pkg/dataplane/userspace/protocol.go:503`) decreases
   between before-snapshot and
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

For each backgrounded container process, the launch pattern is
(R4#4 + R5 self-audit: variables passed as positional args so
they expand on the host side BEFORE single-quoted-body reaches
the remote shell, AND the body uses `shift 2` to consume the
two metadata args before `"$@"` expands to the actual command):

```bash
incus exec ${instance} -- bash -c '
    out_path="$1"; pidfile_path="$2"; shift 2
    "$@" > "${out_path}" 2>&1 &
    echo $! > "${pidfile_path}"
' _ "/tmp/${out}" "/tmp/${pidfile}" ${cmd_args[@]}
```

`_` is `$0` (script-name slot), `/tmp/${out}` is `$1` (out
path), `/tmp/${pidfile}` is `$2` (pid file), `${cmd_args[@]}`
becomes `$3+`. Inside the body, `shift 2` removes the two
metadata args so `"$@"` expands to ONLY the cmd_args (R5#5
fix: prior pattern had `"$@"` see all 4+ args including the
path-args, running the wrong command).

For commands with embedded shell metacharacters (pipes,
redirects, complex quoting) where positional pass-through is
awkward, use the double-quoted alternative below.

**When to use which pattern (R5#6):**

- **Positional pass-through (preferred)**: simple invocations
  like `mpstat 1 60 -o JSON`, `netserver -p 12866`. Args don't
  contain shell metacharacters; the `shift 2` + `"$@"` shape
  is clean.
- **Double-quoted body (fallback)**: when the command is a
  template containing pipes (`cmd1 | cmd2`) or shell builtins
  that can't survive the positional split. Carefully escape
  any `$` that should expand on the remote (`\$!`, `\$(...)`).

Double-quoted form:

```bash
incus exec ${instance} -- bash -c \
    "${cmd_template} > /tmp/${out} 2>&1 &
     echo \$! > /tmp/${pidfile}"
```

Host vars (`${cmd_template}`, `${out}`, `${pidfile}`) expand
on the host; `\$!` survives unexpanded into the remote shell.

To stop:

```bash
incus exec ${instance} -- bash -c \
    "kill -TERM \$(cat /tmp/${pidfile}) 2>/dev/null; \
     rm -f /tmp/${pidfile}"
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
config-mode operations are issued via the cli on the firewall
instance using the `incus exec ... bash -c "<cli ...>"` pattern
(R4 MED#5 fix: prior plan example omitted the `incus exec`
wrapper, which would have run cli locally on the orchestrator
host where xpfd doesn't run). The cli reads from `os.Stdin`
without requiring a tty, so a heredoc piped into the cli
works:

```bash
incus exec loss:xpf-userspace-fw0 -- bash -c "/usr/local/sbin/cli" <<'EOF'
configure
<set/delete commands>
commit
exit
EOF
```

The heredoc lives on the host side; bash sends the heredoc
contents to `incus exec`'s stdin, which forwards to the
remote `cli` process's stdin. (R4 MED comment: cli stdin is
fine; `pkg/cli/` reads from `os.Stdin` with no TTY check.)

For rollback specifically:

```bash
incus exec loss:xpf-userspace-fw0 -- bash -c "/usr/local/sbin/cli" <<'EOF'
configure
rollback 1
commit
exit
EOF
```

`cli -c <single-cmd>` is reserved for **operational** commands
only (e.g. `incus exec loss:xpf-userspace-fw0 -- /usr/local/sbin/cli -c 'show class-of-service interface'`).



### 6.1 Preflight

Order matters (R3#7): register the EXIT trap BEFORE any
mutation, so a failure between step 1 and step N still leaves
the system in a clean state.

```
1. Capture run timestamp <run-ts>; create
   /tmp/100e100m/<run-ts>/.
2. Set tracker variables: PIDFILES_TO_CLEAN=() (an array
   of (instance, pidfile) tuples),
   HARNESS_PGID=$(setsid bash -c 'echo $$'). (R6 self-audit:
   MOUSE_FILTER_APPLIED tracker dropped — no classifier
   extension.)
3. Register EXIT trap (R3#7 / R2 C2 / R4#3).
   The trap function MUST start with `set +e` and capture the
   original exit status via `local original_status=$?`,
   restoring it at the end with `return $original_status`.
   This ensures every cleanup sub-step runs even when the
   one before it fails (e.g. incus unreachable mid-cleanup).
   Trap actions, in order:
   a. For each tracked (instance, pidfile): run
      `incus exec ${instance} -- bash -c \
       "kill -TERM \$(cat /tmp/${pidfile}) 2>/dev/null;
        rm -f /tmp/${pidfile}"` (host-side var expansion via
      double-quoted body, R4#4). Each sub-step suffixed with
      `|| :` so a single failure doesn't propagate.
   b. Pull any container output files the harness recorded
      so a debug snapshot is preserved on partial failure.
      Suffix `|| :`.
   (R6 self-audit: classifier-rollback branch dropped — no
   firewall mutation to undo.)
4. Verify both firewall VMs RUNNING via `incus list`.
5. Assert `systemctl is-active xpfd` returns "active" on
   fw0 AND fw1.
6. Verify RG0 primary == node0 via the operational cli
   (`/usr/local/sbin/cli -c 'show chassis cluster status'`);
   fail loudly if not.
7. Verify iperf3 target reachable: from
   `cluster-userspace-host`,
   `bash -c '</dev/tcp/172.16.80.200/5201'` should succeed.
   The target instance is operator-provisioned and
   intentionally NOT under harness control (R6 self-audit:
   IPERF3_TARGET_INSTANCE env-file change dropped).
8. Install required tools on `cluster-userspace-host`
   (R3 MED#11 explicit `if` pattern):
   ```
   if ! incus exec loss:cluster-userspace-host -- \
        command -v hping3 >/dev/null 2>&1; then
       incus exec loss:cluster-userspace-host -- \
           apt-get update -qq 2>/tmp/apt-update.err || \
           { echo "apt-get update failed: $(cat /tmp/apt-update.err)" >&2; exit 1; }
       incus exec loss:cluster-userspace-host -- \
           apt-get install -y hping3 || \
           { echo "hping3 install failed" >&2; exit 1; }
   fi
   if ! incus exec loss:cluster-userspace-host -- \
        command -v mpstat >/dev/null 2>&1; then
       incus exec loss:cluster-userspace-host -- \
           apt-get install -y sysstat || exit 1
   fi
   ```
9. Apply base CoS via `apply-cos-config.sh` (idempotent).
10. Verify `cli -c 'show class-of-service interface'`
    reports queue 4 owner=1, exact=yes, transmit-rate=
    1 Gb/s. Fail if not.
11. Assert iperf-a queue runtime backlog == 0 (queued_pkts
    == 0) — if non-zero, sleep 5 s and retry up to 3 times.
12. Capture journalctl baseline timestamp for fw0 and fw1
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
3. Start `mpstat 1 60 -o JSON` for baseline phase in
   background on source, output to
   `/tmp/<container-rep-dir>/baseline-mpstat.json`.
   Track via pidfile.
4. Run 100 hping3 mice for 60 s (10 SYN/s × 60 s = 600
   packets/mouse × 100 mice = 60 000 RTT samples).
   Per-mouse stdout captured to
   <rep>/baseline-mice/<i>.txt. Each mouse runs as a
   separate `incus exec ... bash -c '...'` background
   inside one outer `incus exec` (single-bash-c launch
   pattern from §6.0 to minimize startup stagger).
   Source ports allocated from `32768+i` for mouse `i`.
5. Wait for all 100 hping3 mice to exit (each runs `-c 600
   -i u100000`, deterministic 60 s).
6. Wait for baseline mpstat to complete via pidfile poll;
   pull JSON.
7. Sleep 10 s cool-down.
8. Snapshot CoS counters (mid).
9. Start `mpstat 1 90 -o JSON` for loaded phase, output to
   `/tmp/<container-rep-dir>/loaded-mpstat.json` (R6
   self-audit: 90-sample count covers the full elephant
   run window of `t_g` warm-up + 60 s mice + a few seconds
   of slack).
10. Start `iperf3 -c 172.16.80.200 -p 5201 -P 100 -t 90 -i 1`
    (text mode, R4#1+#2) in background, output to
    <rep>/loaded-elephants.txt.
11. Apply cwnd-settle gate (§4.3 step 4): tail the text log
    every 500 ms. Parse `[SUM]` lines for aggregate
    bits/sec. Pass when 3 consecutive `[SUM]` aggregate
    samples are within ±10% of their median AND median ≥
    0.5 Gb/s. Abort + invalidate rep if no pass within 20 s.
12. Run 100 hping3 mice for 60 s (same pattern as step 4).
13. Wait for all hping3 mice to exit.
14. SIGTERM iperf3 (mice are done).
15. Snapshot CoS counters (after).
16. Wait for loaded mpstat to complete via pidfile poll
    (`kill -0` test every 1 s); pull JSON.
17. Pull `journalctl -u xpfd --since=<rep_T0>` from fw0 and
    fw1 (R2 A7); grep for cluster transition lines.
    Invalidate rep if any "cluster: primary transition",
    "cluster: secondary transition", or
    "RG readiness: not-ready" appears.
18. Compute per-rep validity flags (§5.4).
19. Compute per-rep summary (elephant CoV, pooled mouse
    p99/p999, per-mouse p99 distribution, deltas).
20. Sleep 10 s cool-down.
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
≈ 25 min for measurement work, plus ~3-5 min for `incus exec`
overhead (R5 self-audit #8: a single rep does ~50-100 incus
exec round trips for mpstat start/stop, netperf launch, file
pulls, cli queries; over 10 reps that's 500-1000 round trips
at typically ~10-50 ms each = 5-50 s of overhead per rep).
Total realistic runtime: **~28-30 min** for the default 10
reps; up to **~60 min** if auto-extension to 20 reps fires.

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

**Minimum-valid-rep auto-extension** (R3 MED#13 / R4 LOW#10).
Pinned loop:

```
attempted_reps = 0
valid_reps = 0
while valid_reps < 7 && attempted_reps < 20:
    batch = min(5, 20 - attempted_reps)
    if attempted_reps == 0:
        batch = 10  # initial
    run `batch` reps
    attempted_reps += batch
    valid_reps += <number valid in last batch>
if valid_reps < 7:
    FAIL "environmental — operator investigation required"
```

Strict-less-than gates ensure exactly 20 attempts max, never
more.

**IQR warning destination** (R3 LOW#15): if IQR > 50% of
median for any headline metric, the harness emits a
human-readable warning to **stderr** (not affecting exit
status) AND records `iqr_warning: true` per-metric in the
JSON summary. Operator decides whether to re-run with more
reps; the test does not auto-fail on high IQR.

**Artifact retention** (R3 LOW#16 / R4 LOW#11):
- Default: keep the most recent 5 run directories under
  `/tmp/100e100m/`; older runs auto-pruned.
- **Pruning order** (R4 LOW#11): pruning runs as the FIRST
  step inside preflight AFTER the EXIT trap is registered
  (preflight step 4 onward), and BEFORE any cli/CoS
  mutation. Concretely: insert prune as preflight step 3.5
  between trap-registration (step 3) and VM-RUNNING check
  (step 4). If pruning is interrupted mid-rm-rf, the EXIT
  trap is already armed so the partial state is logged but
  no system mutation has happened.
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
- **CoS counter deltas** (Codex finding #7 + R5 self-audit
  #7): parse before/mid/after snapshots into per-counter
  deltas (after − before for loaded, mid − before for
  baseline). Emit deltas; invalidate the rep on regression.

  **Parsing approach**: `cli show class-of-service interface`
  emits text, not JSON. Sample from the live cluster:
  ```
      4   1   iperf-a   5   yes   1.00 Gb/s  ...
          Drops: flow_share=944  buffer=0  ecn_marked=4975584
          DrainShape: sent_bytes=151885438893  park_root=0  park_queue=24292230
  ```
  Regex captures (Python `re.findall`):
  - `flow_share=(\d+)`   → admission_flow_share_drops
  - `ecn_marked=(\d+)`   → admission_ecn_marked
  - `park_root=(\d+)`    → drain_park_root_tokens
  - `park_queue=(\d+)`   → drain_park_queue_tokens
  - `sent_bytes=(\d+)`   → sanity-check on shaper output
    (~ class shaper × phase duration)

  These show-output field names are shorter than the wire
  field names in `pkg/dataplane/userspace/protocol.go`. If a
  future xpfd version renames any, the harness will silently
  fail to parse — the harness MUST emit a clear warning if
  any expected regex returns zero matches across all queues
  in any snapshot.
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

### Round 4 (11 findings)

| # | Sev | Topic                            | Resolution |
|---|-----|----------------------------------|------------|
| 1 | HIGH| Cross-section iperf3 -t inconsistency | §6.2 step 9 + §12 R3 row updated; -t 90 + SIGTERM at mice-finish is the canonical model |
| 2 | HIGH| iperf3 -J only emits at end      | Switched to text mode (`-i 1` no `-J`), parse `[SUM]` lines for live gate; post-parse text log for per-stream rates |
| 3 | HIGH| EXIT trap with `set -e` aborts mid-cleanup | Trap function starts with `set +e` and saves `$?`; every sub-step suffixed `\|\| :` |
| 4 | HIGH| Single-quoted bash -c bodies don't expand host vars | Two patterns documented in §6.0: positional-arg pass-through `bash -c '...$1...' _ "$host_var"`, and double-quoted body with `\$!` escape |
| 5 | MED | §6.1 heredoc missing incus exec wrapper | Step 11 now uses `incus exec ... bash -c "/usr/local/sbin/cli" <<'EOF'` form |
| 6 | MED | mpstat SIGTERM partial JSON      | Use count-bounded `mpstat 1 60 -o JSON` — exits cleanly after 60 samples |
| 7 | MED | netperf -O missing transaction_rate | Added `transaction_rate,throughput,throughput_units` to the -O field list |
| 8 | MED | Wrong CoS counter name           | Corrected to `drain_park_queue_tokens` etc. per `protocol.go:503` |
| 9 | MED | Env file placeholder invalid shell | Use `IPERF3_TARGET_INSTANCE="cluster-userspace-host"` (real value committed in the harness PR) |
| 10| LOW | Auto-extension loop unpinned     | §6.4 specifies the exact while/break conditions with strict-less-than gates |
| 11| LOW | Pruning step order unpinned      | Pruning is preflight step 3.5: AFTER trap registration, BEFORE any cli mutation |

### Round 5 (Codex CLI runtime unavailable; Claude self-audit)

Codex runtime returned a CLI-not-installed error during R5;
self-audit applied for the questions queued for that round.

| # | Sev | Topic                            | Resolution |
|---|-----|----------------------------------|------------|
| 1 | -   | Consistency sweep                | CLEAN — only explanatory mentions of "median-of-p99" remain in §4.2 (counterexample explanation) and §12 history |
| 2 | MED | mpstat completion barrier        | §6.2 step 14 now waits for mpstat pidfile to clear before pulling output and advancing rep |
| 3 | LOW | mpstat output path parameterized | §6.2 step 8 specifies per-rep path `/tmp/<container-rep-dir>/loaded-mpstat.json` |
| 4 | -   | Auto-extend math                 | CLEAN — strict-less-than gates verified: 10 + 5 + 5 = 20 max attempts |
| 5 | HIGH| `bash -c "$@"` includes ALL args | §6.0 fixed: `shift 2` consumes the two metadata args before `"$@"` expands to the actual command |
| 6 | MED | Pattern-selection ambiguity      | §6.0 now pins: positional pass-through for simple invocations, double-quoted body for templates with shell metacharacters |
| 7 | MED | CoS counter parsing approach     | §7 now specifies regex captures from `cli show class-of-service interface` text output, mapping to protocol.go fields |
| 8 | LOW | Incus exec runtime overhead      | §6.4 runtime estimate now includes 3-5 min overhead acknowledgment; total realistic runtime ~28-30 min for 10 reps |

### Round 6 (operator pushback: drop netperf, drop netserver)

Operator observed that the prior plan required netserver
running on 172.16.80.200, which is operator-provisioned and
outside our incus management. Switched mice tool to hping3
SYN probes against the existing iperf3:5201 endpoint —
removing the entire netserver dependency.

| # | Topic                                  | Resolution |
|---|----------------------------------------|------------|
| 1 | Mice tool: netperf TCP_RR → hping3 SYN | §4.2 rewritten; raw SYN to existing iperf3:5201 |
| 2 | No netserver on target                 | Dropped from §6.1 preflight |
| 3 | No firewall classifier extension       | §4.4 reduced to "removed" stub; both elephants and mice already classify into iperf-a via port 5201 |
| 4 | No EXIT-trap rollback for classifier   | Trap branch dropped; trap now only kills container pidfiles + pulls debug artifacts |
| 5 | Per-mouse rate 1000 → 10 RR/s          | hping3 SYN with `-k` (keep source port) creates one half-open conntrack entry per mouse, not per packet; lower rate reduces conntrack pressure |
| 6 | Mouse metrics: pooled distribution     | §5.2: now reports `pooled_p99` and `pooled_p999` (true global percentiles across 60 000 raw samples per phase), in addition to per-mouse p99 order statistics |
| 7 | Env file change reverted               | §13 dropped IPERF3_TARGET_INSTANCE — target IP hardcoded as 172.16.80.200, which is the existing iperf3 endpoint; preflight only verifies TCP reachability |

## 13. Environmental config

(R6 self-audit: prior plan revisions added an
`IPERF3_TARGET_INSTANCE` variable to
`test/incus/loss-userspace-cluster.env` to support netserver
management on the iperf3 target. With the hping3 swap in R6,
no harness-side management of the target is needed —
preflight only TCP-probes 172.16.80.200:5201 to verify
reachability. The env-file change is dropped.)

The harness uses `BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env`
solely for resolving the firewall instance names (`xpf-userspace-fw0/fw1`)
and the source container (`cluster-userspace-host`) — variables
the env file already contains.
