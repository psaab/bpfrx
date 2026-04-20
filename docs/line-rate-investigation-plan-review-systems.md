# Line-rate investigation plan — systems / OS review

**ROUND 3: plan-ready YES from systems angle** (tip `dd6234b7`).


Reviewer focus: OS, driver, NIC, syscall, affinity, cache. Codex is
handling plan-structure / architecture. No duplicate findings.

Plan under review: `docs/line-rate-investigation-plan.md` on
branch `pr/line-rate-investigation`, commit `ff5f7c8b`.

---

## S-1 — HIGH: NIC IRQ affinity → worker CPU alignment missing

**Summary.** Plan pins worker threads but never checks that the
NIC's RX-completion IRQs land on a CPU topologically close to the
worker that polls that queue.

**Explanation.** `pin_current_thread`
(`userspace-dp/src/afxdp/neighbor.rs:531`) picks CPU N for worker N
from the inherited mask. D3 constrains RSS to queues 0..workers-1.
But nothing asserts `/proc/irq/<N>/smp_affinity_list` for each mlx5
queue-N IRQ. If queue 2's IRQ fires on CPU 0 while worker 2 busy-polls
on CPU 4, NAPI runs remote and `reap_tx_completions` (`tx.rs:10`)
pulls frames a remote CPU filled. `docs/712-cpu-pinning-recipe.md`
asserts this is set at boot; the plan does not verify it on the
loss-userspace cluster.

**Plan revision.** Step 2 must sample `/proc/irq/*/smp_affinity_list`
and map `ethtool -x` queue → IRQ → CPU. Gate: each XDP-bound queue's
IRQ MUST be on the same CPU (or same L2/L3) as its worker. This is
a potential zero-code fix the plan currently cannot reach.

## S-2 — HIGH: No latency (p50/p99) metric alongside throughput

**Summary.** Plan grades on Gbps + retransmits + CoV only.

**Explanation.** The fairness constraint (§19) is a throughput-
distribution metric. MQFQ + SFQ collisions can push tail latency
materially while CoV looks healthy — see S-6. For `-R` (no
retransmit) the 19 Gbps ceiling could already be TCP receive-window
limited by RTT jitter from in-queue delay, not fw CPU. Without
latency measurement you cannot distinguish throughput-cost fixes
from throughput-neutral ones. Also: 60s does not reach TCP
steady-state under loss recovery — 180s is safer.

**Plan revision.** Step 3 adds `sockperf under-load` or a parallel
low-rate probe flow with p50/p99 in the 5-run table. Gate: p99 MUST
NOT increase > 10 % vs pre-change. Bump duration to 180s.

## S-3 — HIGH: `SO_BUSY_POLL` / NAPI budget / coalescence unaudited

**Summary.** `SO_BUSY_POLL` = 1µs interrupt / 50µs (`bind.rs:385`).
Plan never checks the interaction with `netdev_budget` or mlx5
coalescence.

**Explanation.** At 1µs busy-poll each `poll()` drives one
`napi_busy_loop` iteration. With `netdev_budget=300` (default) and
mlx5 `rx-usecs` at kernel default, NAPI processes ≤300 packets then
yields to softirq — which on a worker-pinned CPU contends with
`ksoftirqd`. The plan's H-FWD-2 ("CPU saturation") collapses this
into "one CPU at 100%" without separating user / softirq / sys time.

**Plan revision.** Step 2: `mpstat -P ALL 1` must break out `%usr`,
`%sys`, `%soft`, `%irq` — not total. Capture `netdev_budget`,
`netdev_budget_usecs`, `ethtool -c <iface>`, and
`/sys/class/net/<iface>/gro_flush_timeout` pre-run. Add
**H-FWD-5: NAPI budget / coalescence mismatch**.

## S-4 — MEDIUM: RX/TX/fill/comp ring sizes are one knob

**Summary.** `ring_entries` (default 4096, `main.rs:297`) sets RX,
TX, fill, comp all to the same size. Plan fixes TX only.

**Explanation.** `xsk_ffi.rs:923-924` + libxdp size all four alike.
At 25 Gbps / 1500B = 2M pps, 4096 entries ≈ 2 ms of burst absorption.
TX_RING_FULL fires if a poll cycle stretches > 2 ms. The completion
ring is equally sized — if the driver completes faster than userspace
reaps, completions stall silently (no TX_RING_FULL but frames don't
recycle to fill). Plan's H-FWD-1 conflates the two.

**Plan revision.** Rename Step 5 to "RX/TX/fill/comp ring audit";
capture all four per binding. Distinguish TX descriptor starvation
(ring full on produce) from completion starvation (reap lags).

## S-5 — MEDIUM: `CoSQueueRuntime` cache-line cost at P=16

**Summary.** Phase 3 added 3×1024×u64 per queue runtime. No
hypothesis in plan for cache pressure.

**Explanation.** `flow_bucket_bytes`, `flow_bucket_head_finish_bytes`,
`flow_bucket_tail_finish_bytes` (`types.rs:1079-1120`) = 24 KB per
queue. Typical L1d is 32–48 KB. Two queues per worker + `pop_snapshot_stack`
(TX_BATCH_SIZE=256) + `scratch_local_tx` (256) + flow cache quickly
fills L1d. L1 miss rate on MQFQ pop could itself cap throughput
before TX ring pressure shows.

**Plan revision.** Step 2: `perf stat -e L1-dcache-load-misses,LLC-loads`
during the run. If L1d misses on `cos_queue_min_finish_bucket` > 10%,
lane-compaction / dirty-bucket-bitmap may be the unlock (separate PR).

## S-6 — MEDIUM: Reverse-path small-ACK / bulk interleaving pathology

**Summary.** Reverse direction = bulk from server toward client +
16 small-ACK streams in the other direction. MQFQ byte-rate-fair
can be pathological for this shape. Plan's H-REV-4 ("test-setup
artifact") dismisses it too quickly.

**Explanation.** MQFQ finish = `max(tail, queue_vtime) + bytes`.
60-byte ACK flow finish advances by 60/packet; 1500-byte bulk by
1500. Head-finish selection favors the ACK flow on selection,
producing interleaved serialisation of bulk behind ACK storms.
Existing `mqfq_*` pins validate correctness, not combined 16-flow
throughput. 19 Gbps REV + 0 retransmits is *consistent* with
this pathology.

**Plan revision.** Add Step 7: `iperf3 -P 16 -t 60 -R` with jumbo
MSS (or 9000 MTU end-to-end if feasible) to change the ACK:bulk
byte ratio. If throughput closes to line, root cause is MQFQ
small-packet interaction in `tx.rs`, not ring size.

## S-7 — LOW: CPU frequency governor + C-states not measured

**Summary.** `cpupower frequency-info` and `turbostat` are standard
HFT measurements. Missing.

**Explanation.** `PollMode::Interrupt` with 1µs busy-poll yields
often. C-state > C1 adds ~10µs per wake. At 2M pps, 10µs/wake =
20% packet budget. A governor not in `performance` throttles under
short idle windows.

**Plan revision.** Step 2: `turbostat --interval 1` for 65 s both
runs. Capture `CPU%c1`, `CPU%c6`, `Bzy_MHz`. If Bzy_MHz drops below
base clock during run, frequency scaling is an unlock.

---

Plan-readiness from systems angle: **NO** — 3 HIGH + 3 MEDIUM. S-1
and S-3 are potential zero-code fixes; must validate before any
dataplane change.

---

## Round 2 verification

Revision tip `b3559a7e`. Plan now 522 lines.

Round-1 findings:
- S-1 (IRQ affinity): **RESOLVED.** Step 0.1 reads
  `/proc/irq/<N>/smp_affinity_list` per mlx5 queue, names the
  zero-code fix (`echo <cpu> > ...`), gates before proceeding.
- S-2 (latency): **RESOLVED.** Step 3 + Validation capture
  concurrent `ping -i 0.01` p50/p99 AND `ss -ti` RTT every run;
  rollback gate `post-p99 − pre-p99 > 2×stddev(pre-p99)`.
- S-3 (NAPI/coalescence/busy-poll): **RESOLVED.** Step 0.2 covers
  `ethtool -c`, `netdev_budget{,_usecs}`, `gro_flush_timeout`,
  `SO_BUSY_POLL` readback. H-FWD-5 promoted to real hypothesis
  with Step 3 `%usr/%sys/%soft/%irq` diagnostic.
- S-4 (ring quad): **RESOLVED.** Step 0.4 + Step 5 audit RX/TX/
  fill/completion separately; plan explicitly distinguishes
  TX-produce from completion-reap starvation.
- S-5 (L1d): **RESOLVED.** Step 3 runs `perf stat -e
  L1-dcache-load-misses,LLC-loads` on worker PIDs.
- S-6 (small-ACK): **RESOLVED.** H-REV-6 added; Step 7 jumbo-MSS
  diagnostic + ACK-bucket histogram.
- S-7 (C-states): **RESOLVED.** Step 0.5 captures `cpupower` +
  `turbostat`, treated as diagnostic not gate (acceptable).

Round-2 new findings:

- **R2-1 MEDIUM — ping probe packet size.** Step 3 specifies
  `ping -i 0.01` but not `-s`. Default 64 B ICMP may traverse a
  different worker / cache footprint than 1500 B TCP data frames.
  **Fix:** run concurrent probes at two sizes, `ping -i 0.01 -s
  56` AND `ping -i 0.01 -s 1400`, keep both in the p50/p99 table.
- **R2-2 LOW — `ss -ti` cadence unspecified.** Plan says "5 s
  intervals" in Step 3; acceptable, but clarify that it runs for
  the full window and all flows are captured (not just sample
  flow). Not blocking.
- **R2-3 MEDIUM — `perf stat` scope ambiguous.** Step 3 says
  "on worker PIDs" which is correct, but `perf stat` defaults to
  per-thread when given `-p`. Explicitly specify `perf stat -p
  <worker_pids> --per-thread` OR `perf stat -C <worker_cpus>` so
  results are not conflated across the 4 workers — system-wide
  would hide the bottleneck worker.

Plan-ready: **YES with R2-1 and R2-3 folded in** (both one-line
edits in Step 3). Zero-code gates in Step 0 remain the correct
first action.

---

ROUND 3: plan-ready YES from systems angle (with one residual nit).

## Round 3 verification

Revision tip `dd6234b7`. Plan now 781 lines.

- **R2-1 dual ping size** (lines 409-416): RESOLVED. Two pinned
  `taskset -c` ping procs, `-s 56` and `-s 1400`, full window,
  separate p50/p99 per size land in capture. Rollback gate
  (lines 575-579) applied independently to each p99.
- **R2-2 `ss -ti` cadence** (lines 420-425): RESOLVED. Explicit
  "every 5 s for full window, capture ALL flows, port-filtered to
  iperf3". Stronger than a sample.
- **R2-3 `perf stat` scope** (lines 426-435): RESOLVED.
  `perf stat --per-thread -p $WORKER_PIDS` with
  `WORKER_PIDS=$(pgrep -f xpf-userspace-dp)`, explicit
  "NOT system-wide" rationale.

Round-3 angles:
- **Proxy semantics** (lines 674-706): `rx_fill_ring_empty_descs`
  vs `fill_batch_starved`, and `outstanding_tx` vs
  `completion_reap_max_batch` are explicitly NOT claimed equivalent.
  Phase C start forces (a) document proxy OR (b) land one-commit
  instrumentation PR. Row marked `DEFERRED-INSTRUMENTATION` until
  decided. Well-handled.
- **R3-1 LOW — IRQ → queue correlation method underspecified.**
  Step 0.1 reads `smp_affinity_list` and greps `mlx5` from
  `/proc/interrupts`, but mlx5 IRQ names encode queue as
  `mlx5_comp<N>@pci:<bdf>` — the plan never pins the parser
  (e.g. "IRQ line whose name matches `mlx5_comp<queue>@` for the
  BDF of `ge-0-0-1`"). On a multi-NIC box, grep mlx5 matches all
  PFs/VFs. Add one sentence in Step 0.1:
  `grep -E "mlx5_comp[0-9]+@pci:$(basename $(readlink /sys/class/net/<iface>/device))"`
  to scope to the right PF. Non-blocking; a one-line fix.
- **S-7 (C-states) promotion.** Still LOW. For a time-bounded
  investigation, if Bzy_MHz scales down during runs it invalidates
  every throughput number silently. Worth promoting to a Step 0
  gate (require `performance` governor + `intel_idle.max_cstate=1`
  or `processor.max_cstate=1` kernel arg; `turbostat` verifies),
  NOT just a Step 0.5 diagnostic. Recommend promote to MEDIUM gate
  before Phase A tuning starts — otherwise governor-induced noise
  will show up as phantom regressions in the 5-run deltas.

Both round-3 findings are diagnostic improvements, not blockers.
Plan-ready from systems angle: **YES**. Proceed with Phase C
pre-work (instrumentation decision) then Step 0 gates.
