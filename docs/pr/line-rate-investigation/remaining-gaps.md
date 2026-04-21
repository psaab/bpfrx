# Line-rate investigation — remaining gaps

Status as of 2026-04-21, after PRs #796, #797, #803, #804 merged and
issues #799, #800 closed.

## Stated target

`iperf3 -c 172.16.80.200 -P 16 -t 60 -p <port>` (both directions)
on the `loss-userspace` test cluster (mlx5 25 Gbps) for **all four
scheduled ports under the canonical CoS config**:

| Port | CoS class    | Shaper | Line target per shaper |
|------|--------------|--------|------------------------|
| 5201 | iperf-a      | 1.0 G  | ≥ 0.96 Gbps            |
| 5202 | iperf-b      | 10 G   | ≥ 9.6 Gbps             |
| 5203 | iperf-c      | 25 G   | ≥ 24 Gbps              |
| 5204 | best-effort  | 100 M  | ≥ 96 Mbps              |

Canonical CoS config: stored in `docs/pr/line-rate-investigation/
full-cos.set` (4 forwarding classes, strict scheduler-map,
bandwidth-output filter with port-to-FC classification, 25 G
shaping-rate on reth0 unit 80).

**Validation matrix (MANDATORY):**

8 runs total — for each of ports `5201/5202/5203/5204`:
- `iperf3 -c 172.16.80.200 -P 16 -t60 -p <port>` (forward)
- `iperf3 -c 172.16.80.200 -P 16 -t60 -p <port> -R` (reverse)

Success criteria for each cell:
- Mean SUM ≥ 0.96 × shaper rate for that port
- ≤ 100 retransmits over the 60 s window
- Fairness (per-flow CoV) not regressed vs the Phase 3 baseline on
  that shaper (baseline measured separately per shaper rate —
  tighter shapers have tighter CoV expectations)

Additional regression gates (unchanged from prior plan):
- 13 `mqfq_*` pins passing
- `flow_steer_*` pins passing
- D3 knob semantics still work
- Forwarding healthy (ping, smoke iperf3) throughout

## What landed this session

| PR    | Issue      | Gist                                                        |
|-------|------------|-------------------------------------------------------------|
| #796  | #785       | Phase 3 MQFQ VFT — byte-rate-fair dequeue                   |
| #797  | #785       | D3 mlx5 RSS indirection + `rss-indirection` opt-in knob     |
| #803  | #801       | Zero-code tunables — coalescence always-on, host opt-in     |
| #804  | #802       | Per-binding ring-pressure counters via `flow_steer_snapshot`|

Closed with no code:
- #799: 55 M `rx_steer_missed_packets` = LAN broadcast/multicast
  noise, not data path.
- #800: `--workers 6` vs `ethtool -L combined 4` — neither clears
  the plan's "+2 Gbps no-fairness-regression" gate.

## Best measurements to date

| Test                      | Mean SUM  | Mean CoV | Mean retr |
|---------------------------|-----------|----------|-----------|
| P=16 t=60 p=5201 FWD      | 22.94     | 0.21 %   | 2683      |
| P=16 t=60 p=5201 REV      | 20.66     | 1.50 %   | 29736     |
| P=12 t=20 p=5203 FWD      | 22.80     | 1.20 %   | 792       |

REV fairness improved 4× (7.68 % → 1.50 %) between pre-PR #803 and
post. Retransmit counts vary with cluster state (deploy churn, VM
jitter).

## Gap to target

- **FWD**: ~1 Gbps short (22.94 → 24+), retransmits 27× over budget
  (2683 → 100).
- **REV**: ~3.3 Gbps short (20.66 → 24+), retransmits 297× over
  budget (29736 → 100).

Target unmet in both directions. Fairness non-regression protected
(unchanged through the entire cycle).

## Remaining hypotheses (live, not yet falsified)

From the plan's §Hypotheses, these are still open after Step 0
findings closed:

### H-FWD-1: TX ring overrun at the dataplane

**Evidence available now** (via PR #804): `dbg_tx_ring_full`,
`dbg_sendto_enobufs`, `dbg_bound_pending_overflow`,
`dbg_cos_queue_overflow`, `pending_tx_local_overflow_drops`,
`tx_submit_error_drops`, `outstanding_tx` (proxy for
`completion_reap_max_batch`).

**Why still open**: Step 1 of the plan (capture these counters
during a P=16 t=60 run) was gated behind PR #804 landing. That gate
is now lifted; the capture hasn't been done.

### H-FWD-2: per-worker CPU saturation on a bottleneck worker

**Evidence available now**: `mpstat -P ALL 1` during the run
(documented in plan Step 0/3). Per-CPU `%usr/%sys/%soft/%irq`
breakout. Worker PIDs via `pgrep -f xpf-userspace-dp` for
`perf stat --per-thread`.

**Why still open**: also gated to Step 1/3 execution.

### H-FWD-3: conntrack / session-table miss storm on flow start

**Evidence**: session-install counters in the existing snapshot.
**Why still open**: not yet correlated with the retransmit-burst
timing (first 1-2 s of the test).

### H-FWD-5: NAPI budget / coalescence mismatch

**Evidence**: PR #803 already disables adaptive coalescing and sets
`rx-usecs=tx-usecs=8` when claim-host-tunables is true
(`netdev_budget=600`). Default deploy has coalescence fixed but
NOT netdev_budget (netdev_budget gated on the opt-in).
**Why still open**: no A/B comparison with claim-host-tunables on
vs off after the 4-PR stack, on the same cluster state.

### H-REV-1: firewall's TX-side bottleneck on return path

**Evidence**: ge-0-0-1 TX counters during -R test.
**Why still open**: the -R path traverses a different worker
assignment pattern; not measured post-merge.

### H-REV-6: MQFQ small-ACK / bulk-data interleaving pathology

**Evidence**: jumbo-MSS test described in plan Step 7.
**Why still open**: not yet executed.

## Counters still deferred (ACCEPT-PROXY)

Per the plan's per-counter disposition table:

| Counter                       | Proxy used              | Escalation trigger                                                 |
|-------------------------------|-------------------------|--------------------------------------------------------------------|
| `fill_batch_starved`          | `rx_fill_ring_empty_descs` | non-zero AND can't disambiguate "UMEM dry" from "top-up missed" |
| `completion_reap_max_batch`   | `outstanding_tx` gauge  | monotonically rising AND can't tell "busy worker" from "reap late" |

If Step 1's counter data triggers either escalation, file a one-
commit instrumentation PR before continuing.

## Adjacent bugs filed during the cycle

- **#805**: D3 RSS indirection doesn't refresh when worker count
  changes to equal queue count. One-line fix; out-of-scope for
  #800 where it was discovered.

## Phase map — what's left to do

Ordered by blast radius × signal:

1. **Re-run Phase B Step 1 with PR #804 counters**. Capture
   `flow_steer_snapshot` pre/during/post a P=16 t=60 run each
   direction. Quantify which of `dbg_tx_ring_full`,
   `dbg_sendto_enobufs`, `outstanding_tx`, `rx_fill_ring_empty_descs`
   spike under load. This is the highest-signal remaining step.
2. **Re-run with `claim-host-tunables=true`** (so `netdev_budget=600`
   and governor=`performance` on bare metal). Do A/B on the same
   cluster state.
3. **Phase B Step 2-3** per plan: `mpstat -P ALL`, `perf stat
   --per-thread -p $WORKER_PIDS`, `ping -s 56` + `ping -s 1400`
   latency probes during each 60 s run. p50/p99 captures.
4. **Jumbo-MSS reverse test** (H-REV-6) — change ACK:bulk ratio,
   see if REV closes to line rate.
5. **Fix #805** (D3 refresh-on-worker-change) — low-risk, obvious.
6. Based on counter evidence, decide next: deeper dataplane work
   (TX ring tuning, MPSC inbox tuning), RSS re-tuning with
   instrumentation, or acceptance.

## Exit criteria for this investigation

When any of:
- P=16 t=60 p=5201 mean SUM ≥ 24 Gbps both directions AND
  retransmits ≤ 100 AND CoV ≤ 2× pre-change
- OR we demonstrably exhaust the plan's hypotheses without hitting
  the target (new design work required, not just tuning)
- OR operator decides current numbers are acceptable

...then file a final report doc and close the parent issue #798.

## Review rigor carried through

Four PRs, 16 review rounds total (Codex + second reviewer per PR,
multiple rounds each). Catches this session:

| PR   | Caught during review                                             |
|------|------------------------------------------------------------------|
| #796 | HIGH queue_vtime not restored on push_front retry; MED batched-rollback LIFO bound; MED brief-idle re-entry pin missing |
| #797 | HIGH overbroad interface scope; HIGH workers-count-change not reapplied via CLI path                                    |
| #803 | BLOCKER global scope without opt-in; BLOCKER no restore-on-disable; BLOCKER coalescence gated off by opt-in            |
| #804 | MAJOR `dbg_pending_overflow` conflated FIFO vs CoS admission                                                           |

These are all bugs that unit tests did not catch. Review cycle was
the load-bearing catch surface.
