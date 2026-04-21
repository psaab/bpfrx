# Phase B Step 1 — HFT execution plan

> **Scope.** Capture userspace-dp per-binding ring-pressure counters
> (PR #804) during a live `iperf3 -P 16 -t 60` run, before / during
> / after, per-direction, per-port, cross-correlated with per-CPU
> utilization, per-worker `perf stat`, and concurrent dual-size ICMP
> latency probes. The output is a classification: which of the three
> root causes the remaining 11-25 % CoV on shaped forward cells comes
> from.
>
> **Non-goal.** Fixing anything. Step 1 produces a verdict; Step 2+
> turns the verdict into work.

## 0. Candidate root causes under test

| # | Name | One-line |
|---|------|----------|
| A | cross-worker-imbalance | RSS put uneven flow counts on the 4 XDP workers; tail worker is CPU-bound and drags the aggregate |
| B | within-worker-unfairness | Per-worker MQFQ admission ↔ CoS shaper token bucket interaction gives per-flow rates inside one worker that don't match the byte-rate-fair target |
| C | tx-path-jitter | A worker's TX ring (XSK TX or kernel produce path) fills intermittently; packets drop at the ring boundary even though that worker isn't pinned at 100 % CPU |
| D | npbt | Nothing provable below the measurement noise floor (explicit option so we don't force a verdict) |

Step 1 classifies each of the (port × direction) cells into one of
A / B / C / D and produces a per-cell single-line verdict with the
counter math that justifies it.

## 1. Measurement matrix

For each combination:

- **CoS state**: `with-cos` (canonical `full-cos.set` applied) vs
  `no-cos` (configs deleted).
- **Port**: `5201` / `5202` / `5203` / `5204`.
- **Direction**: `fwd` (iperf3 client → server) vs `rev`
  (`iperf3 -R`, server → client).

Full matrix = 2 × 4 × 2 = **16 cells**.

**Reverse cells on all four ports are kept in the matrix but
deprioritized, and the four reverse cells in the `no-cos` half are
explicitly SKIPPED.** Rationale, from `8matrix-findings.md`:

- The `bandwidth-output` filter in the canonical config is only
  attached to `reth0 unit 80` output (fwd direction). Reverse
  traffic exits on `ge-0-0-1`, which has no filter, so reverse
  traffic in `with-cos` mode is **not classified** and is shaped
  only by the 25 G interface shaping rate. It hits ~19-20 Gbps on
  every port uniformly (see the `1998 % / 197 % / 19287 %` rows in
  that doc).
- `no-cos` reverse therefore measures the same thing the `with-cos`
  reverse already measures (unshaped forwarding capacity). Zero new
  signal; strict duplication. SKIPPED under §9 "no wasted cycles".

**Kept reverse cells (`with-cos`, all 4 ports, 4 cells):** reverse
is still in the matrix because the remaining-gaps doc shows
aggregate REV retransmits (~29k on p5201) that do NOT have an
obvious explanation in the forward-direction analysis. The 4
kept reverse cells test H-REV-6 (MQFQ small-ACK / bulk
interleaving, `plan.md` Step 7) as a by-product, and give us a
baseline against which any later -R config change can be compared.

**Total executed cells: 12.** (8 with-cos + 4 no-cos-fwd.)

## 2. Per-cell data capture protocol

All commands run on `loss:xpf-userspace-fw0` (primary) unless stated
otherwise. iperf3 client runs on `loss:cluster-userspace-host`.
iperf3 server is the external `172.16.80.200`.

### 2.1 Pre-run (cold — system idle)

1. **Drain in-flight iperf3.** On both the firewall and the client:
   - `ss -tnH 'sport = :5201 or sport = :5202 or sport = :5203 or
     sport = :5204 or dport = :5201 or dport = :5202 or dport =
     :5203 or dport = :5204' | wc -l` must equal 0. If non-zero,
     kill the offending processes and re-check; retry up to 3
     times, else mark the cell SUSPECT and go to the next cell.
2. **Cluster-state snapshot.** Capture on the primary:
   - `cli -c "show chassis cluster status"` → save as
     `cluster-status-pre.txt`.
3. **Cold per-binding snapshot.** Via the daemon control socket
   (`/run/xpf/userspace-dp.sock`):
   - `echo '{"request_type":"status"}' | socat -t 5 - UNIX-CONNECT:
     /run/xpf/userspace-dp.sock | jq . > flow_steer_cold.json`
   - The `per_binding` array carries the PR #804 counters:
     `dbg_tx_ring_full`, `dbg_sendto_enobufs`,
     `dbg_bound_pending_overflow`, `dbg_cos_queue_overflow`,
     `rx_fill_ring_empty_descs`, `outstanding_tx`, `tx_errors`,
     `tx_submit_error_drops`, `pending_tx_local_overflow_drops`.
   - The full `BindingStatus` carries per-worker / per-binding
     `rx_packets`, `rx_bytes`, `tx_packets`, `tx_bytes`,
     `flow_cache_hits`, `flow_cache_misses`,
     `redirect_inbox_overflow_drops`, `direct_tx_packets`,
     `copy_tx_packets`, `in_place_tx_packets` — these are our
     proxies for per-worker load and the cross-worker imbalance
     classifier (no `local_hit_count` / `redirect_hit_count` named
     fields in the current tree — rx_packets per binding is the
     load-bearing per-worker delivery count).
4. **Cold NIC counters.** On the firewall:
   - `ethtool -S ge-0-0-1 | grep -vE ' 0$' > nic-counters-cold-ge-0-0-1.txt`
   - `ethtool -S ge-0-0-2 | grep -vE ' 0$' > nic-counters-cold-ge-0-0-2.txt`
   - (Subinterface `ge-0-0-2.80` shares driver counters with the
     parent. Both are captured.)
5. **CoS shaper state.** `cli -c "show class-of-service interface"`
   → save. Confirms the filter ↔ scheduler map is live on `reth0.80`
   for the `with-cos` half, empty for `no-cos`.

### 2.2 During run (live — load applied)

- **iperf3 client** (from `cluster-userspace-host`):
  ```
  iperf3 -c 172.16.80.200 -P 16 -t 60 -p $port -J $maybe_R \
    > iperf3.json
  ```
  `$maybe_R = -R` for the reverse cells, empty otherwise. The `-J`
  output is the primary throughput + retransmit record.

- **Concurrent, on the firewall**, all started AFTER the iperf3
  handshake lands (~200 ms after `iperf3 -c` launch):

  (a) **`flow_steer_snapshot` sampler.** Twelve 5-second-spaced
      samples over the 60 s window:
      ```
      for i in $(seq 0 11); do
        echo '{"request_type":"status"}' \
          | socat -t 5 - UNIX-CONNECT:/run/xpf/userspace-dp.sock \
          | jq -c . >> flow_steer_samples.jsonl
        sleep 5
      done
      ```
      Each line is one full-status snapshot with timestamp.

  (b) **`mpstat -P ALL 1 60 > mpstat.txt`.** Per-CPU per-second
      `%usr / %sys / %soft / %irq`. Break-out is mandatory — the
      classifier below uses `%soft` separately from `%sys`.

  (c) **`perf stat --per-thread -p $WORKER_PIDS -e
      task-clock,cycles,instructions,cache-references,cache-misses,
      L1-dcache-load-misses,LLC-loads -- sleep 60 > perf-stat.txt
      2>&1`.** `WORKER_PIDS` is obtained ~500 ms before `perf stat`
      starts via `pgrep -f 'xpf-userspace-w' | paste -sd,` so
      `perf` is scoped to the 4 worker threads only, NOT system-
      wide (a system-wide sample averages away the bottleneck
      worker).

  (d) **`ss -ti 'dport = :$port' -H` every 5 s** (same cadence as
      the snapshot sampler, interleaved):
      ```
      for i in $(seq 0 11); do
        ss -tiH "dport = :$port" \
          | awk 'BEGIN{print "{\"t\":'$(date +%s)'"}'}
                 {printf ",\"%d\":\"%s\"\n", NR, $0}
                 END{print "}"}' >> ss-samples.jsonl
        sleep 5
      done
      ```
      (Rough shape; the real sampler emits one JSON object per
      sample with every flow's RTT / cwnd / retrans / pacing_rate
      / cc_algo.)

- **Concurrent, from `cluster-userspace-host`**, two pinned ICMP
  probes for the full 60 s window. Each pinned to a CPU that is
  NOT the iperf3 client CPU and NOT a worker CPU (0-3):
  ```
  taskset -c 4 ping -i 0.01 -s 56   -D -q -w 60 172.16.80.200 \
    > ping-small.txt 2>&1 &
  taskset -c 5 ping -i 0.01 -s 1400 -D -q -w 60 172.16.80.200 \
    > ping-large.txt 2>&1 &
  ```
  Both probes are started 200 ms BEFORE the `iperf3 -c` invocation
  and run past the iperf3 end (`-w 60`). Post-processing extracts
  p50 / p99 from the `-D` timestamped output for both sizes
  independently — four numbers per cell: `small-p50`, `small-p99`,
  `large-p50`, `large-p99`.

### 2.3 Post-run (cooldown)

1. `echo '{"request_type":"status"}' | socat -t 5 - UNIX-CONNECT:
   /run/xpf/userspace-dp.sock | jq . > flow_steer_post.json`.
2. `ethtool -S ge-0-0-1 | grep -vE ' 0$' > nic-counters-post-ge-0-0-1.txt`
   and the same for `ge-0-0-2`.
3. `cli -c "show chassis cluster status" > cluster-status-post.txt`.
4. `dmesg -T | tail -50 > dmesg-tail.txt` (captures any softlockup,
   OOM, mlx5 error, or AF_XDP warning kernel dropped during the
   run).
5. **Deltas.** Compute `flow_steer_post − flow_steer_cold`
   per-binding, and `nic post − nic cold` per-interface. These are
   the load-induced counter changes.

## 3. Data layout on disk

Each cell is one directory. Path template:

```
docs/pr/line-rate-investigation/step1-evidence/
  <cos-state>/                       # with-cos | no-cos
    p<port>-<dir>/                   # p5201-fwd, p5203-rev, ...
      iperf3.json
      flow_steer_cold.json
      flow_steer_post.json
      flow_steer_samples.jsonl       # 12 lines (5 s × 12 = 60 s)
      mpstat.txt                     # 60 per-CPU samples
      perf-stat.txt                  # 1 summary, 4 thread lines
      ping-small.txt                 # raw ping -D output
      ping-large.txt
      ss-samples.jsonl               # 12 samples
      nic-counters-cold-ge-0-0-1.txt
      nic-counters-post-ge-0-0-1.txt
      nic-counters-cold-ge-0-0-2.txt
      nic-counters-post-ge-0-0-2.txt
      cluster-status-pre.txt
      cluster-status-post.txt
      dmesg-tail.txt
      verdict.txt                    # one-line classifier output
```

Evidence directory is gitignored-in-principle (too large to commit
all 12 cells raw), but `verdict.txt` per cell IS committed along
with the summary table in §4.5.

## 4. Analysis per-cell — hypothesis classification

### 4.1 Inputs derived from the raw captures

Per cell, compute the following from the sampler snapshots:

- **Per-worker load share `load_w`** = `rx_packets_w / Σ_w rx_packets_w`
  for each of 4 workers, computed from `flow_steer_post − cold`
  deltas. Nominal fair share at 4 workers is 0.25 per worker.
- **Per-worker CPU `cpu_w`** = mean of `%usr + %sys + %soft + %irq`
  from `mpstat` for the CPU the worker is pinned to, over the 60 s
  window. Capped at 100.
- **Per-flow rate `rate_f`** = each iperf3 stream's `sum_bits_per_second`.
- **Per-flow worker assignment `worker_of(f)`** = derived from the
  `ss -ti` 5-tuple ↔ RSS hash computation. On mlx5 we use
  Toeplitz + the 40-byte indirection key read once via
  `ethtool -x ge-0-0-1`. This gives us {f → queue} → {queue → worker}.
- **TX-ring-pressure `ring_w`** = per-worker sum over the 60 s
  window of `dbg_tx_ring_full_w` + `pending_tx_local_overflow_drops_w`
  + `tx_submit_error_drops_w` + `dbg_sendto_enobufs_w`.
- **Fill-ring starvation `fill_w`** = per-worker sum of
  `rx_fill_ring_empty_descs_w` delta.

### 4.2 Thresholds (with justification — no magic numbers)

- **X — cross-worker-imbalance threshold.** `max_w load_w −
  min_w load_w > 0.15`. Justification: with 16 flows over 4 workers
  and RSS-hashed 5-tuples, a balanced RSS delivers 4 flows / worker
  expected with stddev ≈ √(16 · 0.25 · 0.75) / 16 ≈ 0.108 per worker
  (binomial). `0.15` = ~1.4 × stddev — above the binomial noise
  floor by a comfortable margin, below the 0.25 "one worker has
  double its share" range that would be visibly catastrophic. CoV
  gap to target (25 % → target ≤ 10 %) is 15 pp, so a 15 pp load
  imbalance is the right order of magnitude.

- **Y — within-worker-unfairness threshold.** Inside a single
  worker, `max_f rate_f / min_f rate_f > 1.5` across the flows
  mapped to that worker (ignoring flows whose `rate_f < 0.5 ×
  median` — slow-start / startup tails, not steady state). `1.5`
  justification: the shaped cells hit ~95 % of shaper at
  11-25 % CoV aggregate; within-one-worker fairness should be
  tighter than aggregate (MQFQ is a per-worker mechanism). A 1.5×
  spread = 20 % CoV inside a single worker = worse than aggregate,
  which means MQFQ is demonstrably not producing fair per-flow
  rates under the shaper token bucket.

- **Z — tx-path-jitter threshold.** `ring_w > 1000` on ANY worker
  whose `cpu_w < 85 %`. Justification: `dbg_tx_ring_full` is a
  discrete event counter (one increment per full ring detection
  at the XSK TX produce site). Over a 60 s window at 16384-slot
  rings and ~1.5 Mpps / worker, a healthy reap cadence yields
  low double-digit full-ring events per worker. `1000` is ~3
  orders above healthy baseline and well below "pathologically
  broken" (~100k/s). A simultaneous `cpu_w < 85 %` requirement
  distinguishes jitter from CPU saturation: if the worker CPU is
  maxed, of course the TX ring fills — that's cause C only if
  the CPU has headroom. The 15 % slack on CPU tolerates small
  sampling artefacts from `mpstat`'s 1-sec granularity.

- **Verdict `npbt`** when no threshold above fires AND the cell's
  SUM is within 2 Gbps of the theoretical-max for that shaper.
  Otherwise, we return the tightest threshold that fires; if
  multiple fire, we record all and pick the dominant one
  (argmax normalized distance from threshold).

### 4.3 Single-line verdict format

`verdict.txt` is exactly one line:

```
p<port>-<dir>-<cos>: <A|B|C|D> load_spread=<pct>% within_worker_ratio=<float> worst_ring_w=<int>@<cpu_pct>% small_p99=<us> large_p99=<us> sum=<gbps> retr=<int>
```

Example:
```
p5201-fwd-with-cos: A load_spread=22.4% within_worker_ratio=1.12 worst_ring_w=84@97% small_p99=185 large_p99=220 sum=0.949 retr=274
```

Reads left-to-right: port+dir+cos, verdict letter, then the six
scalars that justify the verdict. The verdict letter is derivable
from the scalars via the §4.2 rules — no additional hidden state.

### 4.4 Tie-breaks and escalations

- If BOTH A and C fire: A wins (it's causal; C is a symptom of CPU
  saturation on the imbalanced worker).
- If B fires alone: report B.
- If C fires alone AND `outstanding_tx` is monotonic through the
  run (per §2.2's 12 samples), the ACCEPT-PROXY disposition for
  `completion_reap_max_batch` is exhausted per `plan.md` §Phase C
  "Instrumentation pre-work" — file a follow-up issue and note it
  in the Step 1 findings doc. Step 1 proceeds with C as the
  verdict; the follow-up PR lands in Phase C.
- If `rx_fill_ring_empty_descs` is non-zero AND `fill_w` varies
  > 4× across workers: same proxy-exhaustion rule fires for
  `fill_batch_starved`.

### 4.5 Summary output

After all 12 cells: `docs/pr/line-rate-investigation/step1-findings.md`
with one table + a text conclusion. Table columns:

| cell | verdict | load_spread | within_ratio | worst_ring | small_p99 | large_p99 | SUM | retr |

Plus a paragraph per distinct verdict group summarizing the
evidence and naming the Step 2 follow-up.

## 5. Capture-validity invariants (pre-declared pass/fail ON THE CAPTURE)

Each cell is declared VALID only if ALL invariants hold:

| # | Invariant | Why |
|---|-----------|-----|
| I1 | Every file in §3's cell directory exists, size > 0 | "Missing" is not a signal |
| I2 | `iperf3.json` SUM for the cell is within ±10 % of the 8-matrix baseline (`8matrix-findings.md` for the `with-cos` half; pre-PR #804 mean-SUM for the `no-cos` half) | Sanity — cluster hasn't drifted since last measurement |
| I3 | Between every pair of cells: smoke `iperf3 -c 172.16.80.200 -P 4 -t 5 -p 5203` passes with 0 retransmits | Forwarding healthy — measurement didn't break the firewall |
| I4 | `cluster-status-pre.txt` and `cluster-status-post.txt` report the SAME node as RG0 primary | No failover mid-cell |
| I5 | `dmesg-tail.txt` contains zero `softlockup`, `mlx5` error, `BUG:` | Kernel healthy |
| I6 | `flow_steer_samples.jsonl` has exactly 12 lines, each parseable JSON, each with a non-empty `per_binding` array of length ≥ 8 (3 ifaces × ≥ 3 bindings min) | Snapshot sampler ran end-to-end |

On any invariant failure the cell is re-run up to **twice**. After
two failures the cell is marked `SUSPECT` in the summary and the
investigation proceeds without it; the final findings doc names the
missing cell(s) and explains what it would have shown.

## 6. Forwarding validation between CoS state transitions

Switching `no-cos` ↔ `with-cos` may briefly disrupt forwarding. The
protocol below is non-negotiable:

1. **Before applying with-cos.** On the primary:
   `cli -c "iperf3 -c 172.16.80.200 -P 4 -t 5 -p 5203"`-equivalent
   smoke (actually run from `cluster-userspace-host` —
   `iperf3 -c 172.16.80.200 -P 4 -t 5 -p 5203`) must pass with 0
   retransmits.
2. **Apply with-cos** via the existing helper:
   `test/incus/apply-cos-config.sh loss:xpf-userspace-fw0`.
3. **Immediately after commit.** Smoke again. Must pass, 0 retr.
4. **Run the 8 with-cos cells.**
5. **Before removing with-cos.** Smoke. Must pass.
6. **Remove with-cos.** On the primary:
   ```
   echo -e 'configure\ndelete class-of-service\ndelete firewall family inet filter bandwidth-output\ndelete interfaces reth0 unit 80 family inet filter output\ncommit\nexit' \
     | incus exec loss:xpf-userspace-fw0 -- /usr/local/sbin/cli
   ```
7. **Immediately after commit.** Smoke. Must pass.
8. **Run the 4 no-cos-fwd cells.**

If any smoke fails: **HALT.** Write a state dump (`show
configuration`, `journalctl -u xpfd -n 200`, `show chassis cluster
status`, `ip route show`) to `step1-evidence/halt-<ts>/` and stop.
Do not auto-recover; this is a supervised halt so the root cause
of the forwarding break is visible.

## 7. Runtime budget

| Activity | Per-cell | Cells | Total |
|---|---|---|---|
| Setup + cold captures | 30 s | 12 | 6 min |
| iperf3 + concurrent captures | 60 s | 12 | 12 min |
| Teardown + deltas + verdict.txt | 30 s | 12 | 6 min |
| Inter-cell smoke (one between each) | 5 s | 11 | ~1 min |
| CoS apply / remove | 2 × ~90 s | — | 3 min |
| Cold-to-cold switchover settling | ~30 s | 2 | 1 min |
| Analysis write-up (findings.md) | — | — | 10-20 min |
| Buffer for a re-run or two | — | — | ~10 min |

**Total target: 60-90 minutes wall clock.** Hard ceiling 120 min
before we rescope (skip a reverse cell, tighten the per-cell
timeout, etc.). The analysis write-up is included in the budget —
not a separate phase.

## 8. Explicit deferrals — what's NOT in Step 1

Step 1 produces a **classification only**, NOT a fix. Sequels:

- If verdict is **A (cross-worker-imbalance)** on ≥ 50 % of cells:
  Step 2 is D1'-class work (flow-to-worker LB). Big. Gated
  behind a separate design doc; do not kick off implementation.
- If verdict is **B (within-worker-unfairness)** on ≥ 50 % of
  cells: Step 2 is AFD / Phase 5 MQFQ ↔ shaper-interaction work.
  Likely one medium PR.
- If verdict is **C (tx-path-jitter)**: Step 2 is targeted
  reap-cadence + produce-path TX-ring-size tuning. Smaller PR,
  guarded by the existing `mqfq_*` pins + the new ring-pressure
  counters (regression gate trivially available via PR #804).
- If verdict is **D (npbt)** on > 75 % of cells: we exhausted the
  current hypothesis set. Step 2 is the design doc for a new
  hypothesis tier — NOT more measurement.

Step 1 MUST NOT commit to Step 2 scope in the findings doc. It
names the direction, not the shape.

## 9. Non-negotiables

- **Zero per-packet measurement overhead.** We are reading
  existing counters (pre-populated by the hot-path TX produce /
  reap sites and published at the ~1 s debug tick). No new probes,
  no tracepoints, no `perf record -g`. `perf stat` is counter-
  level only.
- **Statistical validity.** Each cell's `flow_steer_samples.jsonl`
  contains 12 samples — enough to compute a per-counter mean +
  stddev and reject single-sample noise. Any classifier threshold
  is evaluated on the *mean* across samples, not a single instant.
  N=12 is below textbook (N=30) but far above N=1 — and 12
  samples × 4 workers gives 48 per-worker observations per cell,
  which is sufficient for the imbalance test.
- **Named thresholds.** §4.2 names X, Y, Z and justifies the
  number each. No bare "5 %" or "high" in the classifier rules.
- **Reproducibility.** The measurement is driven by a committed
  script — `test/incus/step1-capture.sh` — added in the same PR
  as the plan. The script enforces the protocol; the plan doc
  describes what the script does. Humans run the script, not the
  protocol by hand.
- **No fixes during Step 1.** If we notice a fix-able bug mid-
  capture (say, a clearly broken `.link` file, a misconfigured
  sysctl), we DO NOT fix it in-band. We note it in the cell's
  `verdict.txt` prefix and file a follow-up issue. Changing the
  system mid-measurement invalidates the comparison.

## 10. Risks + rollback

| Risk | Mitigation / Rollback |
|---|---|
| CoS apply breaks forwarding | §6 protocol halts. State dump captured; investigator re-measures the no-cos baseline from a fresh start. |
| Primary failover mid-capture | Detected via §5 I4. Cell marked SUSPECT and re-run. If failover repeats across re-runs, STOP — the cluster has a separate bug that invalidates the measurement. |
| iperf3 server (172.16.80.200) unresponsive | First ping-small / ping-large probe shows it. Re-check cluster connectivity (`cli -c "show route 172.16.80.200"`); if dead, Step 1 can't proceed and we halt. |
| Counter snapshot missing a field | Means PR #804 didn't cover that counter. Check §4.4 escalation rule; file a one-commit instrumentation PR; don't block Step 1 on a non-essential field. The essential fields are listed in §2.1 step 3. |
| Measurement-script bug | Protocol-level — captured cells go through the invariants in §5. Any `SUSPECT` cell ≥ 2 in the same column = script bug, not system bug. |
| Cluster state drift between `no-cos` and `with-cos` halves | Reflected in §2.1 step 2 cluster-state snapshot; §2.1 step 5 CoS shaper state snapshot. Findings doc notes any drift and how it was handled. |

## Appendix A — counter inventory (from PR #804, live in the code)

Verified present in `userspace-dp/src/protocol.rs` and populated
from `userspace-dp/src/afxdp/worker.rs` / `tx.rs`:

| Counter | Struct location | Used by classifier for |
|---|---|---|
| `dbg_tx_ring_full` | `BindingCountersSnapshot` | C (tx-path-jitter) |
| `dbg_sendto_enobufs` | `BindingCountersSnapshot` | C |
| `dbg_bound_pending_overflow` | `BindingCountersSnapshot` (PR #804 split) | C (bound-pending FIFO overflow) |
| `dbg_cos_queue_overflow` | `BindingCountersSnapshot` (PR #804 split) | B (CoS admission rejecting under shaper token contention) |
| `rx_fill_ring_empty_descs` | `BindingCountersSnapshot` | C (fill-ring starvation — proxy for `fill_batch_starved`) |
| `outstanding_tx` | `BindingCountersSnapshot` | C (reap-lag — proxy for `completion_reap_max_batch`) |
| `tx_errors`, `tx_submit_error_drops`, `pending_tx_local_overflow_drops` | `BindingCountersSnapshot` | C (aggregate TX drops) |
| `rx_packets`, `rx_bytes` | `BindingStatus` (pre-existing) | A (per-worker load share) |
| `tx_packets`, `tx_bytes` | `BindingStatus` (pre-existing) | A |
| `redirect_inbox_overflow_drops` | `BindingStatus` (pre-existing) | A (cross-worker redirect overload) |

The classifier **critically depends on** `dbg_cos_queue_overflow`
(PR #804 split from the old conflated `dbg_pending_overflow`) to
distinguish verdict B from verdict C. Without the split, "CoS
admission rejected an item" would be indistinguishable from "the
bound-pending FIFO evicted an item", and the B/C verdicts would
collapse into one. PR #804's split is the single load-bearing PR
for this plan.
