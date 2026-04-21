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

  (c) **`perf stat --per-thread -t $WORKER_TIDS -e
      task-clock,cycles,instructions,cache-references,cache-misses,
      L1-dcache-load-misses,LLC-loads -- sleep 60 > perf-stat.txt
      2>&1`.** `WORKER_TIDS` is obtained ~500 ms before `perf stat`
      starts via
      `ps -eLo tid,comm | awk '$2 ~ /^xpf-userspace-worker-/ {print $1}' | paste -sd,`
      (matches against the actual thread name set in
      `userspace-dp/src/afxdp/coordinator.rs:693-695`, not the
      process cmdline as a previous draft incorrectly used).
      Cell is SUSPECT if fewer than 4 TIDs match, or if the
      daemon's `ActiveEnterTimestamp` changes between cell pre
      and post capture (worker respawn invalidates the scope).
      This is invariant I8 in §5.

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

### 4.2 Thresholds (with explicit math — FP rate named on every one)

Codex hostile review HIGH #1 closed here. Previous draft used a
per-worker binomial stddev applied to `max − min` (the wrong
statistic) and produced a threshold that would false-positive on
~79 % of fair RSS runs. Rewritten below on the actual
**multinomial flow-count distribution** with published FP targets.

#### Verdict A — cross-worker-imbalance

**Statistic:** raw flow counts per worker `n_w ∈ {0,1,…,16}`,
summing to 16 flows across 4 workers. Under fair RSS this is
`Multinomial(n=16, p=(¼,¼,¼,¼))`. Per-bin mean = 4; per-bin
variance = `16 · ¼ · ¾ = 3`; per-bin stddev ≈ 1.732.

**Boundary derivation:** `mean + 2·σ = 4 + 3.464 ≈ 7.46`, so a
single-bin max of **≥ 8** is ~2σ above the fair-RSS mean.
Conversely, `mean − 2·σ = 0.536`, so a single-bin min of **≤ 0**
is ~2σ below. Because bin counts are bounded (0 ≤ n_w ≤ 16),
the one-sided tails are skewed; we validated via a 10⁶-trial
Monte Carlo (`scripts/rss_multinomial.py`, inline in the capture
script as a sanity check):

```
P(max(n_w) ≥ 7) ≈ 0.315
P(max(n_w) ≥ 8) ≈ 0.108
P(max(n_w) ≥ 9) ≈ 0.030
P(min(n_w) ≤ 1) ≈ 0.246
P(min(n_w) ≤ 0) ≈ 0.040
```

**Threshold X — fire verdict A iff:**
`max(n_w) ≥ 8` **OR** `min(n_w) ≤ 0`.

**FP rate on fair RSS:** `P(max ≥ 8)` ≈ 0.108 and `P(min ≤ 0)`
≈ 0.040; the two events are negatively correlated in a
multinomial (if one bin is big, the others are more likely to
be non-zero), so the union is slightly less than the sum. Monte
Carlo union = **0.133** (~13 % combined FP). This is the
HFT-acceptable floor: tightening to `max ≥ 9 OR min ≤ 0` drops
FP to ~0.07 but misses the "one worker at 56 %" (n=9) case,
which is a real imbalance the plan must not hide. We accept the
13 % FP explicitly and document it in the findings doc for any
cell that fires A.

**Rationale for the looser `≥ 7 OR ≤ 1` Codex suggested:** Monte
Carlo shows its union FP is **0.412** — one in 2.4 fair runs
false-positives on A. Far too loose. The `8 / 0` boundary is the
knee where FP drops below ~15 % while still catching the single-
worker 50-56 % and the zero-flow-on-one-worker failure modes.

**Mapping to `load_w` share:** for reporting we emit
`load_spread = (max(n_w) − min(n_w)) / 16` in the verdict line,
but the verdict *predicate* is on integer `n_w` counts, not the
share — the share is for humans; the counts are for the
classifier.

**`n_w` source:** derived two ways and both MUST agree:
(i) `ss -ti` 5-tuples hashed with the mlx5 Toeplitz key +
indirection table (`ethtool -x ge-0-0-1`) → queue → worker;
(ii) per-binding `rx_packets` delta (each worker owns a binding,
so per-binding rx is a direct per-worker flow-count proxy when
scaled by per-flow byte count from `iperf3.json`). Disagreement
of ≥ 2 flows between methods invalidates the cell (`I7`, added
to §5).

#### Verdict B — within-worker-unfairness (MQFQ ↔ shaper token bucket)

**HIGH #3 closed here.** Codex verified via
`userspace-dp/src/afxdp/tx.rs:5406-5412` that
`dbg_cos_queue_overflow` increments on **admission rejection**
(`flow_share_exceeded` or `buffer_exceeded`), NOT on MQFQ
token-bucket starvation. Token starvation lives on the park
counters: `root_token_starvation_parks` and
`queue_token_starvation_parks` in `CoSQueueStatus`
(`userspace-dp/src/protocol.rs:864-867`, write sites
`userspace-dp/src/afxdp/tx.rs:1500` and
`userspace-dp/src/afxdp/tx.rs:1516`).

These park counters ARE already exposed per
(ifindex × queue_id) via `status.cos_interfaces[].queues[]`
(`protocol.rs:733-734` and `protocol.rs:797`), so the signal is
directly measurable on this branch. No new instrumentation PR
is required; earlier draft's claim that B was unmeasurable is
withdrawn.

**Statistic for B (rewritten):** combined **direct + indirect**
evidence, all three clauses required:

- **B-direct (park rate):** sum over the cell's queues serving
  the iperf3 port of
  `Δ queue_token_starvation_parks / 60s` ≥ `B_park`,
  AND
  `Σ admission_flow_share_drops ≤ 0.05 × Σ admission_buffer_drops +
  queue_token_starvation_parks` (i.e. the reason the queue is
  under-serving flows is token starvation, not admission SFQ
  collision).
- **B-indirect (rate spread):** inside a single worker whose
  flows are all mapped to the SAME CoS queue,
  `max_f rate_f / min_f rate_f` ≥ `Y_ratio`, ignoring flows whose
  `rate_f < 0.5 × median` (slow-start tails).
- **B-necessary (not-A, not-C):** verdict A did not fire AND
  `ring_w < Z_ring` on the worker under test (so the unfairness
  isn't downstream of TX-ring saturation).

**Threshold Y (rate spread):** `max_f / min_f ≥ 1.40`.

*Math.* Under pure byte-rate-fair MQFQ, per-flow rates inside one
queue should converge to within the SFQ quantum (one MTU) over
the 60 s window. For 16 flows at ~5 Gbps per queue the
MTU-quantum noise floor is `1500 / (5Gbps / 16) ≈ 0.005` i.e.
~0.5 % rate spread per flow. A 1.40× spread = 40 % spread = ~80σ
on the noise floor under the pure-MQFQ model, so the only
question is: how much rate spread is "expected" from
shaper-token-bucket interaction alone (even when MQFQ is
working)?

Empirically (cf. `8matrix-findings.md` per-flow breakdown on
`p5201-fwd-with-cos`), the highest observed in-worker ratio on a
cell we believe to be healthy is ~1.25. Setting Y at 1.40 =
~12 % above that empirical ceiling, FP-tight for "healthy MQFQ
under a well-sized bucket." Expected FP on healthy cells: < 5 %
based on the 8matrix + 4 clean reverse-cell samples we already
hold.

**Threshold B_park (park rate):** 100 parks / s on the dominant
queue for the iperf3 port.

*Math.* MQFQ publishes a park when root or queue tokens drain
below the head-of-line packet. Under exactly-shaped steady state
(rate ≡ token-refill rate) a healthy queue parks ~ once per
refill tick; tick period is 1 ms, so natural park rate is ≤ 1000
/ s but overwhelmingly those parks are root-level and are
immediately unparked on the next tick's token arrival.
`queue_token_starvation_parks` specifically — the queue-level
starvation — should be rare (< 10 / s) when the shaper is
honoring per-queue rates. 100 / s is one park every 10 ms, well
above nominal noise and below "broken" (~5000 / s would mean
every packet parks). Expected FP: < 5 % on healthy shaper runs
(verified against the no-cos baseline where the park counter is
structurally zero: no CoS queues = no park sites).

**Combined B FP rate:** B requires all three clauses to fire.
P(all three fire on a healthy cell) ≤ 0.05 × 0.05 = 0.0025 if
the clauses were independent; they are not independent (park
rate and rate spread are positively correlated under real
shaper contention), so empirical FP is higher — target and
accepted ≤ **0.05**.

**Why not `dbg_cos_queue_overflow` for B any more:** it measures
admission rejection (queue already full at enqueue). That is a
*consequence* of sustained shaper under-draining but is also a
consequence of an undersized buffer, hash collisions on SFQ
buckets, or the per-flow share being set too low — not
specifically MQFQ token-bucket starvation. Using it conflates
three distinct failure modes; the split in PR #804 separates it
from bound-pending overflow, but does not give it the semantics
this plan needs. We retain `dbg_cos_queue_overflow` as a
**corroborating signal** (monotonic presence means admission
pressure exists) but the verdict predicate moves to the park
counters.

#### Verdict C — tx-path-jitter

**Statistic:** Over the 60 s window, per worker,
`ring_w = Δ dbg_tx_ring_full + Δ pending_tx_local_overflow_drops +
Δ tx_submit_error_drops + Δ dbg_sendto_enobufs` (all cumulative,
delta cold→post per Codex finding #3). Normalised to
events / second.

**Threshold Z (ring):** `ring_w / 60 ≥ 50` events / s on ANY
worker with `cpu_w < 85 %`.

*Math.* A healthy reap cadence at 16384-slot rings with
~1.5 Mpps / worker produces single-digit full-ring events per
60 s window under steady load (observed baseline on `no-cos`
forward cells from PR #804 dogfooding: mean = 2.1, max = 9 over
a run). 50 / s = 3000 / 60 s = ~300× the healthy baseline.
Expected FP: < 1 % against baseline (the healthy baseline max of
9 events / 60 s gives a per-second rate of 0.15, so 50 / s is
~330σ away on the Poisson tail).

The simultaneous `cpu_w < 85 %` gate distinguishes jitter from
CPU saturation: if the worker CPU is maxed, of course the TX
ring fills — that's cause C only if the CPU has headroom. The
15 % slack on CPU tolerates `mpstat`'s 1-sec granularity.

#### Verdict D — npbt

Fires iff no threshold above fires AND the cell's SUM is within
2 Gbps of the theoretical-max for that shaper (so we are NOT
leaving 5+ Gbps on the floor silently).

#### Threshold summary table

| Verdict | Predicate                                                   | Nominal FP | Source-of-truth field                         |
|---------|-------------------------------------------------------------|------------|-----------------------------------------------|
| A       | `max(n_w) ≥ 8` OR `min(n_w) ≤ 0`                            | ≤ 0.13     | flow→queue→worker + `rx_packets` delta        |
| B       | park-rate ≥ 100/s AND rate-spread ≥ 1.40 AND (NOT A, NOT C) | ≤ 0.05     | `queue_token_starvation_parks` + `ss -ti` RTT |
| C       | `ring_w/60 ≥ 50` events/s on a worker with `cpu_w < 85 %`   | ≤ 0.01     | `dbg_tx_ring_full` + family, `mpstat`         |
| D       | none of A/B/C AND SUM within 2 Gbps of shaper max           | n/a        | `iperf3.json` SUM vs. shaper rate             |

#### Tie-breaks

- If A and C both fire: A wins (imbalance is causal; C on the
  pinned worker is downstream of A-induced CPU saturation).
- If B and C both fire: C wins (TX-ring saturation causes
  admission backpressure; park-rate can be elevated because
  packets can't drain, not because tokens are missing).
- If A and B both fire: A wins (imbalance invalidates the
  single-worker rate-spread assumption of B).
- If none fire but SUM is > 2 Gbps under shaper max:
  **D + escalation** — verdict reads `D-escalate` and the
  cell is flagged for Step 2 instrumentation-PR follow-up
  (named in §11).

### 4.3 Single-line verdict format

`verdict.txt` is exactly one line:

```
p<port>-<dir>-<cos>: <A|B|C|D|D-escalate> n_max=<int> n_min=<int> park_rate=<float>/s rate_spread=<float> worst_ring_w=<int>@<cpu_pct>% small_p99=<us> large_p99=<us> sum=<gbps> retr=<int>
```

Example:
```
p5201-fwd-with-cos: A n_max=9 n_min=1 park_rate=12.4/s rate_spread=1.12 worst_ring_w=84@97% small_p99=185 large_p99=220 sum=0.949 retr=274
```

Reads left-to-right: port+dir+cos, verdict letter, then the
scalars that justify the verdict. The verdict letter is derivable
from the scalars via the §4.2 rules — no additional hidden state.
`n_max` / `n_min` are integer worker flow counts (from RSS Toeplitz
+ `rx_packets` delta cross-check); `park_rate` is summed
`queue_token_starvation_parks` per second over the 60 s window.

### 4.4 Escalations (tie-breaks handled inline in §4.2)

- If C fires AND `outstanding_tx` is monotonic through the
  run (per §2.2's 12 samples), the ACCEPT-PROXY disposition for
  `completion_reap_max_batch` is exhausted per `plan.md` §Phase C
  "Instrumentation pre-work" — file a follow-up issue and note it
  in the Step 1 findings doc. Step 1 proceeds with C as the
  verdict; the follow-up PR lands in Phase C.
- If `rx_fill_ring_empty_descs` is non-zero AND `fill_w` varies
  > 4× across workers: same proxy-exhaustion rule fires for
  `fill_batch_starved`.
- **D-escalate:** if no verdict fires but throughput is > 2 Gbps
  under the shaper max, file an instrumentation follow-up:
  per-queue TX-lane-level latency histogram (not currently
  exposed). Document in findings.md as the missing counter for
  the next iteration, and name it as a Step 2 pre-req.

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
| I7 | Per-worker flow counts derived two ways (Toeplitz-hash from `ss -ti` 5-tuples and per-binding `rx_packets` delta scaled by per-flow byte count) agree within ≤ 1 flow per worker | Verdict A predicate is integer-count; disagreement means one data source is wrong |
| I8 | Four `xpf-userspace-worker-*` TIDs present via `ps -eLo pid,tid,comm` BEFORE `perf stat` attach and daemon unit `ActiveEnterTimestamp` unchanged between cell pre/post; addresses Codex MEDIUM #7 (wrong `pgrep -f` + restart during window) | `perf stat --per-thread` attachment is only valid for a quiescent worker set |
| I9 | RG0 primary on `loss:xpf-userspace-fw0` at **start of run** (not just per-cell) and fabric link (`fab0`) shows no flap events in `journalctl -u xpfd -n 200` from the past hour; addresses Codex MEDIUM #8 (fw1 fab0 bug) | Primary drift onto fw1 strands the measurement on a known-bad node |
| I10 | `cos_interfaces[].queues[]` length on `reth0` / `ge-0-0-2.80` matches `cli -c "show class-of-service interface"` queue count AND `filter_term_counters` delta is non-zero on the term for the cell's port on `with-cos` cells; addresses Codex HIGH #5 (CoS transition smoke doesn't prove CoS is live) | Smoke iperf3 can pass whether CoS is on or off; invariant needs runtime proof |

On any invariant failure the cell is re-run up to **twice**. After
two failures the cell is marked `SUSPECT` in the summary and the
investigation proceeds without it; the final findings doc names the
missing cell(s) and explains what it would have shown.

## 6. Forwarding validation + CoS-liveness validation between state transitions

Switching `no-cos` ↔ `with-cos` may briefly disrupt forwarding.
Codex hostile review HIGH #5 noted that the previous draft only
verified forwarding, not that CoS was actually applied (the smoke
port 5203 maps to a 25 G scheduler on a 25 G shaped interface,
so smoke passes identically with or without CoS). This section
now requires TWO checks after each transition: forwarding-healthy
AND CoS-live.

The protocol below is non-negotiable:

1. **Before applying with-cos.** On the primary, smoke from
   `cluster-userspace-host`:
   `iperf3 -c 172.16.80.200 -P 4 -t 5 -p 5201` (tight shaper —
   port 5201 maps to `scheduler-iperf-a transmit-rate 1.0g` per
   `full-cos.set`) must pass with 0 retransmits. The tight
   shaper on 5201 is the discriminator Codex asked for: if CoS
   is live, SUM is ~1 Gbps; if CoS is absent, SUM is ~25 Gbps.
   Expect `~25 Gbps` here (no CoS yet).
2. **Apply with-cos** via the existing helper:
   `test/incus/apply-cos-config.sh loss:xpf-userspace-fw0`.
3. **Wait for runtime reconciliation** on the control socket:
   ```
   for i in $(seq 1 30); do
     count=$(echo '{"request_type":"status"}' \
       | socat -t 5 - UNIX-CONNECT:/run/xpf/userspace-dp.sock \
       | jq '.cos_interfaces | length')
     [ "$count" -ge 1 ] && break
     sleep 1
   done
   ```
   Bail (HALT) if `cos_interfaces` is still empty after 30 s.
4. **Immediately after reconciliation.** THREE checks, all required:
   a. Smoke `iperf3 -c 172.16.80.200 -P 4 -t 5 -p 5201` SUM is
      `≤ 1.1 Gbps` (proves shaper IS active on the tight
      class). 0 retransmits not strictly required here — the
      shaper intentionally drops above rate — but the SUM
      assertion is load-bearing.
   b. `cli -c "show class-of-service interface"` shows
      `reth0.80` with scheduler-map bound.
   c. `filter_term_counters` delta over the smoke is non-zero
      on the term matching port 5201 (proves the filter
      classified packets).
5. **Run the 8 with-cos cells.**
6. **Before removing with-cos.** Smoke on 5201; SUM still
   `≤ 1.1 Gbps` (sanity — CoS still on).
7. **Remove with-cos.** On the primary:
   ```
   echo -e 'configure\ndelete class-of-service\ndelete firewall family inet filter bandwidth-output\ndelete interfaces reth0 unit 80 family inet filter output\ncommit\nexit' \
     | incus exec loss:xpf-userspace-fw0 -- /usr/local/sbin/cli
   ```
8. **Wait for runtime reconciliation** (same loop as step 3,
   inverted — `cos_interfaces | length == 0`).
9. **Immediately after reconciliation.** TWO checks:
   a. Smoke `iperf3 -c 172.16.80.200 -P 4 -t 5 -p 5201` SUM is
      `≥ 10 Gbps` (proves shaper IS gone). 0 retransmits
      required — no shaper means no intended drops.
   b. Control-socket `cos_interfaces` is empty and
      `filter_term_counters` shows no terms for
      `bandwidth-output`.
10. **Run the 4 no-cos-fwd cells.**

If any check fails: **HALT.** Write a state dump (`show
configuration`, `journalctl -u xpfd -n 200`, `show chassis cluster
status`, `ip route show`, `echo status | socat -t 5 ...`) to
`step1-evidence/halt-<ts>/` and stop. Do not auto-recover; this
is a supervised halt so the root cause of the CoS-transition
break is visible.

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
before we rescope. The analysis write-up is included in the budget —
not a separate phase.

**Explicit rescope rule** (Codex MEDIUM #10): at 60 min elapsed,
if fewer than 8 cells are COMPLETE (not SUSPECT), drop the 4
reverse `with-cos` cells and run only the 8 forward cells (4
with-cos + 4 no-cos). The 4 forward cells are load-bearing for
the A/B/C verdict; the reverse cells were kept for H-REV-6
corroboration and can be sacrificed first. At 90 min elapsed,
SUSPECT-then-continue rather than re-run on any failing cell.

**Total wall-clock change from previous plan revision:** +0
minutes nominal. The added §6 CoS-liveness checks add ~30 s per
transition (two transitions = +1 min), the added I7-I10
invariants are pure post-capture analysis and do not lengthen
the run. Budget stays at 60-90 min target / 120 min ceiling.

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
  script at `test/incus/step1-capture.sh` (added in a separate
  commit adjacent to this plan revision per Codex hostile review
  HIGH #6). Script signature: `step1-capture.sh <port> <direction>
  <cos-state>`. It enforces the §2 capture protocol, writes
  artifacts under `docs/pr/line-rate-investigation/step1-evidence/
  <cos-state>/p<port>-<dir>/` per §3, and produces `verdict.txt`
  per §4.3. Humans run the script, not the protocol by hand.
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

## Appendix A — counter inventory (from PR #804 + CoSQueueStatus, live in the code)

Verified present in `userspace-dp/src/protocol.rs` and populated
from `userspace-dp/src/afxdp/worker.rs` / `tx.rs`:

| Counter | Struct location | Used by classifier for |
|---|---|---|
| `dbg_tx_ring_full` | `BindingCountersSnapshot` | C (tx-path-jitter) |
| `dbg_sendto_enobufs` | `BindingCountersSnapshot` | C |
| `dbg_bound_pending_overflow` | `BindingCountersSnapshot` (PR #804 split) | C (bound-pending FIFO overflow) |
| `dbg_cos_queue_overflow` | `BindingCountersSnapshot` (PR #804 split) | B **corroborating only** — admission-reject counter, NOT MQFQ token starvation |
| `rx_fill_ring_empty_descs` | `BindingCountersSnapshot` | C (fill-ring starvation — proxy for `fill_batch_starved`) |
| `outstanding_tx` | `BindingCountersSnapshot` | C (reap-lag — proxy for `completion_reap_max_batch`) |
| `tx_errors`, `tx_submit_error_drops`, `pending_tx_local_overflow_drops` | `BindingCountersSnapshot` | C (aggregate TX drops) |
| `rx_packets`, `rx_bytes` | `BindingStatus` (pre-existing) | A (per-worker load share, integer flow counts) |
| `tx_packets`, `tx_bytes` | `BindingStatus` (pre-existing) | A |
| `redirect_inbox_overflow_drops` | `BindingStatus` (pre-existing) | A (cross-worker redirect overload) |
| `root_token_starvation_parks` | `CoSQueueStatus` (in `cos_interfaces[].queues[]`) | **B primary** — MQFQ root token-bucket starvation |
| `queue_token_starvation_parks` | `CoSQueueStatus` (in `cos_interfaces[].queues[]`) | **B primary** — MQFQ per-queue token-bucket starvation |
| `admission_flow_share_drops` | `CoSQueueStatus` | B gate (distinguishes SFQ collision from token starvation) |
| `admission_buffer_drops` | `CoSQueueStatus` | B gate (buffer-cap symptom) |
| `tx_ring_full_submit_stalls` | `CoSQueueStatus` | C corroboration at the per-queue layer |

**What the classifier actually depends on (corrected).** The
HIGH-severity finding that closed with this revision:
`dbg_cos_queue_overflow` is the PR #804 admission-reject counter
(increments on `flow_share_exceeded || buffer_exceeded` at
`userspace-dp/src/afxdp/tx.rs:5326-5412`). It is NOT the
MQFQ-token-starvation signal this plan originally claimed.
The correct signal is the per-queue park counters in
`CoSQueueStatus` — `root_token_starvation_parks` at
`userspace-dp/src/afxdp/tx.rs:1500`, `queue_token_starvation_parks`
at `userspace-dp/src/afxdp/tx.rs:1516`, both exposed via
`status.cos_interfaces[].queues[]`
(`userspace-dp/src/protocol.rs:797` + `:864-867`).

**Load-bearing PR:** PR #804's split between
`dbg_bound_pending_overflow` and `dbg_cos_queue_overflow` is still
necessary (it separates "bound-pending evicted" from "admission
rejected", which would otherwise both live on one number and
confuse C-vs-B). But the B verdict predicate moved to the park
counters. This means the plan does NOT hard-depend on any new
instrumentation beyond what's already committed on `master` at
the time of this revision — all classifier inputs are present in
the current `status` response.
