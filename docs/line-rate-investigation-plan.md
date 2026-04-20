# Line-rate investigation — plan

> **Revision note (adversarial-review fold-in).** This plan has been
> updated to address two adversarial reviews:
> `docs/line-rate-investigation-plan-review.md` (Codex, plan /
> architecture angle) and
> `docs/line-rate-investigation-plan-review-systems.md`
> (systems / OS / driver / affinity / cache angle). Each finding is
> either folded into a concrete revision in the sections below, or
> explicitly deferred with rationale in "Deferred findings" at the
> end.

## Problem statement

`iperf3 -c 172.16.80.200 -P 16 -t60 -p 5201` and the `-R` variant
both fall short of line rate on the `loss-userspace` test cluster
(mlx5 25 Gbps):

| Direction | SUM Gbps | % of line | Retransmits |
|-----------|----------|-----------|-------------|
| Forward   | 21.35    | 85 %      | **933**     |
| Reverse   | 19.10    | 76 %      | 0           |

Target: **≥ 24 Gbps (96 % of line) on both directions, ≤ 100
retransmits total across 16 flows over 60 s**. Forwarding must stay
healthy throughout any change we land. **Per-flow fairness** (CoV)
must not regress vs the current Phase 3 MQFQ + D3 baseline.
**Latency** (p50/p99, measured via concurrent low-rate probe) must
not regress either — added as a first-class gate in this revision
(systems S-2 / HIGH #2).

## Fairness non-regression constraint (FIRST-CLASS)

The preceding PRs (#795, #796, #797) delivered measurable fairness
improvements:

- **Pre-Phase-3 baseline**: mean CoV 54.7 % on `iperf3 -P 12 -t 20
  -p 5203`
- **Post-Phase-3 + D3 (current master)**: mean CoV ~ 38 %, with
  favorable runs under 20 %

That work established byte-rate-fair MQFQ ordering (Phase 3),
mlx5 RSS indirection narrowing (D3), and extensive test pins for
both. Any line-rate fix in this investigation MUST preserve those
gains. Specifically:

1. **CoV is a first-class validation metric**, alongside SUM,
   retransmits, **and latency p50/p99**. Every validation capture
   records mean CoV, median CoV, per-flow min/max spread, AND
   probe-flow p50/p99 — not just aggregate throughput.
2. **If a fix adds throughput at the cost of CoV, it doesn't
   ship.** A 24 Gbps SUM with 60 % CoV is a regression vs 21 Gbps
   SUM with 38 % CoV for the 12-flow test — we'd be trading the
   recent fairness win for throughput. Unacceptable without
   explicit re-prioritization.
3. **The 16-flow test MUST ALSO be measured against the 12-flow
   test** we optimized. 12-flow is the shipped-regression target;
   16-flow is the new requirement. A fix that only helps 16-flow
   and breaks 12-flow is a net loss.
4. **Phase 3 MQFQ pins MUST keep passing** after any change. 13
   `mqfq_*` tests in `userspace-dp/src/afxdp/tx.rs` are load-
   bearing. The `pop_snapshot_stack` bound, the vtime round-trip
   neutrality, the drained-bucket re-anchor — all documented in
   commit history across rounds 1-4 of the Phase 3 review cycle.
5. **D3 knob semantics must keep working.** `rss-indirection
   enable|disable` must still toggle correctly; the allowlist
   must still scope only to userspace-bound mlx5 interfaces.
6. **`flow_steer_*` tests** must also keep passing — see hard stops.

## Test environment ground truth (measured, not assumed)

- NIC: Mellanox (mlx5_core), 25 Gbps, MTU 1500, 6 RX queues,
  D3 indirection locks traffic to queues 0-3 (4 XDP-bound workers).
- xpfd dataplane: userspace-dp with 4 workers. Flag-off = Phase 3
  MQFQ + D3 (currently merged to master).
- Single-flow ceiling: 6.83 Gbps FWD, 6.14 Gbps REV. At 4 workers,
  ideal P=16 aggregate = 4 × 6.83 = 27.3 Gbps FWD, 4 × 6.14 = 24.6
  Gbps REV. Neither is currently achieved.
- No CoS classifier on port 5201 at the moment (verified via
  `show configuration`). So rate is NOT being artificially limited
  by CoS.

## Hypotheses for the forward-direction gap (21 Gbps / 933 retransmits)

The 933 retransmits are the loudest clue. A healthy pipeline at
steady state has ≤ 10s of retransmits over 60 s. Candidate causes:

**H-FWD-1: TX ring overrun at the dataplane.** When 4 workers each
push ~6 Gbps, the AF_XDP TX ring (sized at 16384 descriptors per
binding) can fill if `sendto()` wakeups or `reap_tx_completions`
lag. Packets get dropped at the ring boundary → TCP retransmit.
**Evidence is userspace-side first**: `dbg_tx_ring_full`,
`dbg_sendto_enobufs`, `dbg_pending_overflow`,
`pending_tx_local_overflow_drops`, `tx_submit_error_drops`,
`outstanding_tx`. NIC counters (`tx_dropped`, ring errors) are
secondary and can stay silent while the userspace ring thrashes —
see Step 1 ordering below (Codex HIGH #1).

**H-FWD-2: Per-worker CPU saturation on a bottleneck worker.** If
RSS puts 5+ flows on one worker, that worker hits ~100 % CPU and
starts dropping. The 933 retransmits could cluster on the
per-flow rates of the busiest worker. Must break out
`%usr / %sys / %soft / %irq` separately — aggregated "CPU %" is
not sufficient to distinguish user-space pipeline work from NAPI
softirq cost (systems S-3).

**H-FWD-3: Conntrack / session table miss storm.** On the forward
path, new flows install sessions. If session creation rate is
high (16 flows starting simultaneously), first-packet-drop or
DNS/NAT contention could cause burst retransmits during SYN/early
congestion window. Would show as retransmits concentrated in the
first 1-2 seconds.

**H-FWD-4: CPU thermal / mlx5 fill-ring starvation.** On high-
duration runs (60 s), NIC fill-ring may not be refilled fast
enough. Shows up as `rx_fifo_errors` on the NIC.

**H-FWD-5: NAPI budget / coalescence mismatch.** `SO_BUSY_POLL =
1µs` interacts with `netdev_budget` and mlx5 interrupt coalescence.
If `netdev_budget=300` and `rx-usecs` is at kernel default, NAPI
caps at 300 packets per iteration then yields to `ksoftirqd` on
the same pinned CPU, contending with the worker. Added per
systems S-3 / HIGH #3.

## Hypotheses for the reverse-direction gap (19 Gbps / 0 retransmits)

Different shape: lower throughput but ZERO retransmits. That
rules out loss. Candidates:

**H-REV-1: TX-side bottleneck on the firewall's RETURN path.**
Reverse = iperf3 server (172.16.80.200) pushes to client
(10.0.61.102). Return traffic: server → fw ingress (ge-0-0-2.80)
→ fw egress (ge-0-0-1) → client. The fw TX on ge-0-0-1 is the
workers' TX path for the reverse direction. Different MTU,
different ring? Needs verification.

**H-REV-2: mlx5 RX on ge-0-0-2.80 under-provisioned.** If the
VLAN sub-interface ge-0-0-2.80 has fewer RX queues than
ge-0-0-1, the reverse-direction ingress has less parallelism.
Would show in `ethtool -l ge-0-0-2.80` and per-queue counters.

**H-REV-3: Small-ring scratch buffer on redirected path.** With
MQFQ+Phase 3, shared_exact queues still have scratch arrays
(`scratch_local_tx`, `scratch_prepared_tx`) sized at
`TX_BATCH_SIZE` = 256. If the reverse path takes a different code
path (e.g., TC-classified differently), batching may be smaller.
Observable: TX-ring-full events, overflow drops, queue path
selection counters, and the exact restore helpers used on reverse
traffic (Codex MED clarification).

**H-REV-4: TCP flow control on the server side.** iperf3 server's
socket buffers or TCP send queue might cap throughput. That would
be a test-setup artifact, not a firewall issue. Verify by running
the same -R test OUT OF the firewall (direct server-to-client on
the same L2) for a control.

**H-REV-5: Single-flow ceiling dominates the arithmetic.** Single
REV = 6.14; 4 workers × 6.14 = 24.6 theoretical max. 19 actual =
77 % of that. Gap is real but smaller once the single-flow limit
is accounted for.

**H-REV-6: MQFQ small-ACK / bulk-data interleaving pathology.**
Reverse direction = bulk from server toward client + 16 small-ACK
streams in the other direction. MQFQ finish is
`max(tail, queue_vtime) + bytes`. A 60-byte ACK flow finish
advances by 60/packet; a 1500-byte bulk by 1500. Head-finish
selection then favours the ACK flow on every pop decision,
producing interleaved serialisation of bulk behind ACK storms.
Existing `mqfq_*` pins validate correctness, not combined 16-flow
throughput. 19 Gbps REV + 0 retransmits is *consistent* with this
pathology. Diagnostic (new, systems S-6): run the reverse test
with jumbo MSS (or 9000 MTU end-to-end if feasible) to change the
ACK:bulk byte ratio — if throughput closes to line, root cause is
MQFQ small-packet interaction in `tx.rs`, not ring size or CPU.

## Investigation plan (before any code)

Each step produces evidence that closes or keeps a hypothesis. Run
before any fix. **Step ordering reflects Codex HIGH #1**: the most
direct userspace evidence is captured BEFORE NIC counters, so a
quiet NIC cannot falsely acquit a ring-full scenario.

### Step 0: zero-code audit (NEW — Phase B, runs first)

This step exists specifically because several items below are
sysctl / affinity / driver-knob-level and a misconfiguration here
can be the entire answer. Any finding that fires at Step 0 is
addressed *first*, before any code change, and may eliminate the
need for further investigation.

**0.1 NIC IRQ ↔ worker CPU alignment** (systems S-1 / HIGH #1).
- `ethtool -x <iface>` to map RSS queues → queue indices.
- `cat /proc/interrupts | grep mlx5` and
  `cat /proc/irq/<N>/smp_affinity_list` for each mlx5 queue IRQ.
- Cross-reference: XDP-bound worker N is pinned to CPU N; queue N's
  IRQ MUST land on CPU N (or a same-L2/L3 sibling).
- **Gate**: misalignment must be fixed at this step (zero-code
  `echo <cpu> > /proc/irq/<N>/smp_affinity_list`) before
  proceeding. Re-measure baseline afterwards.

**0.2 NAPI / coalescence / busy-poll audit** (systems S-3 / HIGH
#3).
- `ethtool -c <iface>` — record `rx-usecs`, `tx-usecs`, adaptive
  coalescing on/off, `rx-frames`, `tx-frames`.
- `sysctl net.core.netdev_budget net.core.netdev_budget_usecs`.
- `/sys/class/net/<iface>/gro_flush_timeout`.
- Confirm `SO_BUSY_POLL` / `SO_PREFER_BUSY_POLL` values actually
  present on the XSK sockets (read from process state or
  binding snapshot).
- **Gate**: if any value is clearly pathological (e.g., adaptive
  coalescing forcing high rx-usecs under load, `netdev_budget`
  too low for 2M pps), tune at sysctl / ethtool level first.

**0.3 TCP congestion control pinning** (Codex MEDIUM).
- Record `sysctl net.ipv4.tcp_congestion_control` on BOTH iperf3
  client and server. Different algorithms (cubic / bbr / reno)
  produce wildly different retransmit profiles; without pinning,
  run-to-run variance is confounded.
- Pin explicitly to a single algorithm (default `cubic` unless a
  specific test case demands otherwise) on both ends.
- Verify during runs via `ss -ti` on at least one sample flow to
  confirm the algorithm actually in effect.

**0.4 Ring-quadruple audit** (systems S-4 / MEDIUM).
- `ethtool -g ge-0-0-1` and ge-0-0-2.80: current vs max for RX,
  TX, **fill, and completion** rings. `ring_entries` (default
  4096) sets all four equally at bind; if any of the four is the
  bottleneck the symptom differs (TX-ring-full on produce vs
  completion starvation on reap with no TX-full signal).
- Record pre-run; this step is cheap and frames H-FWD-1 correctly.

**0.5 CPU frequency / C-states** (systems LOW).
- `cpupower frequency-info` — governor MUST be `performance` on
  worker CPUs. `turbostat --interval 1` for 65 s during each
  validation run (see Step 3) to confirm `Bzy_MHz` doesn't drop
  below base clock and `CPU%c6` stays near zero on worker CPUs.
- Treat as a diagnostic observable, not an immediate gate —
  frequency throttling is highlighted in the findings table only
  if it actually correlates with throughput loss.

**0.6 Bind-mode / XDP fallback audit** (Codex MEDIUM).
- `xsk_bind_mode`, zero-copy vs copy, `XDP_FALLBACK` stats from
  `BindingLiveSnapshot`. Capture once per binding pre-run.

### Step 1: capture userspace-dp counters during both directions (was Step 3)

Runs BEFORE NIC counters (Codex HIGH #1) because userspace
AF_XDP ring pressure can be invisible at the NIC counter layer.

- `flow_steer_snapshot` via control socket (pre-existing from
  D1'-infra).
- Per-binding: `dbg_tx_ring_full`, `dbg_sendto_enobufs`,
  `dbg_pending_overflow`, `tx_errors`,
  `pending_tx_local_overflow_drops`, `tx_submit_error_drops`,
  `outstanding_tx`.
- Worker summary: `XDP_FALLBACK` stats, `xsk_bind_mode`,
  zero-copy flag.
- CoS-drop counters (even though no classifier is set — sanity).
- Run 60 s test (180 s for latency gate — see Step 3).
- Capture after.
- **Expected signal**: H-FWD-1 = `dbg_tx_ring_full` or
  `pending_tx_local_overflow_drops` > 0; H-FWD-3 = session-install
  counters spike; H-REV-3 = queue-restore / overflow counters on
  reverse path.

### Step 2: capture NIC + driver counters during both directions (was Step 1)

Now runs AFTER the userspace-side capture.

- Reset counters: `ethtool -S <iface> | grep -E 'err|drop|discard' > before`
- Run the P=16 t=60 test (same window as Step 1 if paired).
- Capture again, diff.
- Interfaces to watch: ge-0-0-1 (client-side), ge-0-0-2 / ge-0-0-2.80
  (server-side). Both directions exercise both ingress and egress
  counters.
- **Expected signal**: H-FWD-1 secondary corroboration via
  `tx_dropped` / ring-related error; H-FWD-4 shows `rx_fifo_errors`
  or `rx_missed_errors`.

### Step 3: capture per-worker CPU + softirq + latency + L1d during the tests

- `mpstat -P ALL 1` on the fw for 65 s (or 185 s for the long
  variant) during each direction. **Break out `%usr`, `%sys`,
  `%soft`, `%irq`** — not aggregate (systems S-3).
- Record peak per-CPU %; which CPUs are pinned to the 4 workers?
- **Latency probe** (systems S-2 / HIGH #2): concurrently run
  `ping -i 0.01 <dst>` during the iperf3 window, or
  `sockperf under-load` if available. Capture p50/p99 from the
  probe. Also extract iperf3 client-side TCP RTT via `ss -ti`
  samples at 5 s intervals.
- **Cache-pressure sampling** (systems S-5 / MEDIUM): run
  `perf stat -e L1-dcache-load-misses,LLC-loads` on worker PIDs
  during the same window. If L1d miss rate on
  `cos_queue_min_finish_bucket` > 10 %, lane-compaction /
  dirty-bucket-bitmap may be a separate unlock.
- `turbostat --interval 1` also runs in this window (see 0.5).
- **Expected signals**: H-FWD-2 = one CPU at 100 % while others
  < 80 %, broken out into `%sys` vs `%soft` to implicate pipeline
  vs NAPI; H-FWD-5 = softirq dominates when NAPI yields early.

### Step 4: single-flow direct test WITHOUT the firewall

- `iperf3 -c <server> -P 1 -t 10` directly, bypassing the fw if
  possible. Establishes the true single-flow ceiling.
- If single-flow direct = single-flow via fw, the fw is not the
  bottleneck per flow. H-REV-4 becomes non-primary.

### Step 5: ring size + queue count audit

- Confirms Step 0.4 inline with the investigation; extends to:
- `ethtool -g ge-0-0-1` / `ge-0-0-2.80` — **all four rings** (RX,
  TX, fill, completion) current vs max (systems S-4).
- `ethtool -l` — combined queue counts.
- Compare to D3's indirection — are the same queues both AF_XDP-
  bound AND large enough?
- **Distinguish TX descriptor starvation (ring full on produce)
  from completion starvation (reap lags behind driver)** — the
  two look different in userspace counters.

### Step 6: reverse-direction topology walk

- Trace the reverse path: what code path handles server → fw
  ingress on ge-0-0-2.80 → fw egress on ge-0-0-1 → client?
- Is it the same shared_exact / owner-local-exact / surplus path
  as forward?
- Which worker handles the reverse flow? (Hash is of 5-tuple
  regardless of direction; so a symmetric hash + direction ends up
  on different workers.)

### Step 7: MQFQ small-ACK pathology diagnostic (new, H-REV-6)

- Run `iperf3 -P 16 -t 60 -R` with jumbo MSS (or 9000 MTU
  end-to-end if feasible) to change the ACK:bulk byte ratio. If
  reverse throughput closes to line rate, root cause is MQFQ
  small-packet interaction in `tx.rs`, not ring size / CPU / NAPI.
- Also: record per-worker `flow_bucket_bytes` /
  `flow_bucket_head_finish_bytes` histogram to see whether the
  ACK bucket dominates pop selection.

## Expected fixes per hypothesis

To be decided AFTER Steps 0-7 findings. Premature, but sketched:

- If Step 0 finding (IRQ / sysctl / governor): zero-code fix.
- If H-FWD-1: tune TX ring size, `reap_tx_completions` cadence,
  batch-send timing — distinguishing TX-produce from completion-
  reap bottleneck per Step 5.
- If H-FWD-2: adjust RSS indirection weights to redistribute
  flows (extend D3), or add flow-to-worker LB (D1' territory).
- If H-FWD-3: pre-install session entries for the flow 5-tuple, or
  batch session installs.
- If H-FWD-4: increase NIC RX buffer size, pin worker to a
  dedicated CPU.
- If H-FWD-5: tune `netdev_budget` / coalescence; potentially
  disable adaptive coalescing.
- If H-REV-1: match forward-path TX-ring tuning to reverse path.
- If H-REV-2: bring up additional queues on ge-0-0-2.80 + rebind
  workers.
- If H-REV-3: restate with queue-restore / overflow counters;
  increase scratch buffer size only if those counters implicate.
- If H-REV-6: targeted MQFQ change for small-ACK / bulk
  interleaving — a separate PR with its own fairness gate.

Each fix will be its own PR, each with:
- A Rust/Go HFT-mindset impl (no hot-path alloc, no lock
  contention, atomic where possible, cache-line-aligned contended
  state)
- Measurement: matched 5-run before/after (statistical protocol
  below)
- Codex adversarial review loop to merge-ready

## Validation at every step

After ANY change that modifies xpfd, before commit:
- `cargo build --release && cargo test --release --bin xpf-userspace-dp`
  → all tests pass, including 13 `mqfq_*` pins and all
  `flow_steer_*` pins
- `make test` (Go)
- Deploy to loss-userspace cluster
- Smoke: `iperf3 -c 172.16.80.200 -P 4 -t 5 -p 5201` — positive
  throughput, 0 retransmits, flag-OFF and flag-ON if D1'-flag is
  relevant

### Statistical protocol (Codex HIGH #2 + systems S-2)

Single-run comparisons are not sufficient: CoV, retransmits, and
now latency all have run-to-run variance that rivals the change
signal we're trying to measure.

**Matched 5-run comparison, paired in time:**

1. **Immediately before the change**: run 5× `iperf3 -P 16 -t 60
   -p 5201 -J` (both directions). Also run 5× `iperf3 -P 12 -t 20
   -p 5203 -J` (both directions). Each iperf3 invocation is
   accompanied by a concurrent `ping -i 0.01` latency probe on
   the same path.
2. **Apply the change.**
3. **Immediately after the change**, in the same session, repeat
   the identical 5-run battery.
4. For every metric below, compute mean and stddev across the 5
   pre-change runs and the 5 post-change runs.

**Metrics captured per run:**
- Mean SUM Gbps (both directions)
- Total retransmits (forward direction)
- Mean CoV (per-flow), median CoV, per-flow min/max spread
  (both 16-flow and 12-flow tests)
- Latency p50 and p99 from the concurrent probe (both directions)

**Rollback gate — any ONE of the following triggers rollback:**
- **CoV regression**: `mean(post-CoV) − mean(pre-CoV) > 2 ×
  stddev(pre-CoV)` on the 16-flow OR 12-flow test
- **Retransmit regression**: `mean(post-retr) − mean(pre-retr) >
  100`, OR `mean(post-retr) > 2 × mean(pre-retr)` (the doubling
  rule, whichever is tighter)
- **Latency regression**: `mean(post-p99) − mean(pre-p99) > 2 ×
  stddev(pre-p99)`
- **Throughput regression**: `mean(post-SUM) < mean(pre-SUM) − 1
  Gbps` in either direction

This replaces the previous single "> 5 percentage points" absolute
threshold, which was a single-point rule measured against a frozen
baseline whose own documented variance overlapped the threshold.

**Target — success criteria for the overall investigation goal:**
Five measured runs per direction after one discarded warm-up run.
Mean SUM ≥ 24 Gbps, no individual run < 23 Gbps, total
retransmits mean ≤ 100, no CoV regression on either the 16-flow
or 12-flow gates, and no p99 latency regression.

Forwarding health: `ping 172.16.80.200` passes during test (the
same latency-probe ping serves double duty).

## Hard stops

- **Any iperf3 shows 0 Gbps or hangs**: rollback, forwarding is
  broken.
- **Rollback gate fires** (as defined in the statistical protocol
  above): rollback that commit.
- **Any `mqfq_*` unit test regression**: the Phase 3 load-bearing
  invariants are broken. Rollback. *No exceptions, no "fix
  forward" on this one.*
- **Any `flow_steer_*` unit test regression**: D3 / flow-steering
  load-bearing invariants are broken. Rollback.
- **NIC link drops / systemd service failure**: kill switch.
- **CPU softlockup / kernel oops**: hard rollback, debug offline.

## Out of scope for this effort

- D1' work (flow-to-worker LB). That's a separate multi-week
  design; documented on `pr/785-d1-flow-worker-lb`. If our fixes
  can't close to line rate and the bottleneck is RSS distribution,
  we'll flag it and stop.
- fw1's pre-existing fab0 compile bug. Separate issue.
- Non-iperf3 traffic patterns. Only the two commands the user
  specified are in scope.

## Phasing

Five serialized phases:

1. **Phase A**: plan + adversarial review until both reviewers
   agree (no code).
2. **Phase B**: investigation. Runs **Step 0** (zero-code audit)
   FIRST; any finding there is addressed before any dataplane
   change. Then Steps 1-7. Produces an updated findings doc naming
   the root cause(s).
3. **Phase C**: per-finding GitHub issue filed. Scope + fix
   proposal per issue.
4. **Phase D**: one PR per issue. HFT-mindset implementation.
   Adversarial review loop per PR until merge-ready.
5. **Phase E**: final validation — both directions at line rate,
   forwarding stable, latency and CoV non-regressing. Document
   outcome.

Stop conditions per phase: a phase doesn't start until the prior
one is complete + documented + reviewed.

## Deferred findings (explicit, with rationale)

Not every reviewer finding lands as a step in this plan. The ones
below are explicitly deferred with reasoning — NONE are silently
dropped.

- **Codex MED #3 (interval-level retransmit / warm-up run for
  H-FWD-3)**: folded implicitly into Step 3's 5-run protocol — the
  statistical gate already requires a discarded warm-up run, and
  iperf3's `-i 1` interval output is captured by default, giving
  per-second granularity. Not called out as a separate step
  because it's table stakes for the statistical protocol.
- **Codex MED #4 partial (XSK bind-mode / fallback capture)**:
  covered in Step 0.6. TCP CC pinning (the other half) is
  Step 0.3.
- **Codex MED #6 (success criteria inconsistency)**: resolved —
  single definition in "Validation at every step → Target".
- **Codex LOW #7 (rollback mechanics / last-known-green tag)**:
  deferred. The statistical-protocol rollback rule is precise
  enough for the current branch; formal "last-known-green tag"
  machinery is overhead we'll add only if we end up with multiple
  concurrent root causes merging onto the branch.
- **Codex MED #5 (H-REV-3 observables)**: restated in hypothesis
  text and in "Expected fixes" — observables tied to TX-ring-full
  / overflow drops / queue path selection / restore helpers.
- **Systems S-7 (CPU freq / C-states)**: folded as Step 0.5 +
  diagnostic observable in Step 3; not a blocking gate.

## Risks

- **Cluster state drift during long investigation**. Mitigation:
  statistical protocol pairs every change with its OWN pre-run
  baseline, so drift across sessions doesn't confound individual
  gates.
- **Forwarding break during experimentation**. Mitigation: every
  change gated on the validation checklist; rollback commits
  preserved in branch history.
- **RSS distribution luck**. CoV varies run-to-run because RSS
  hashing 16 flows into 4 bins is stochastic. Mitigation: 5-run
  means + stddev, with rollback gates expressed relative to
  pre-change stddev (not absolute pp thresholds).
- **Unrelated bugs surface during investigation**. If we hit
  fw1's fab0 bug or a D1' infrastructure issue, file a separate
  issue and continue on the main investigation.
