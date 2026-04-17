# CoS admission validation — methodology and current baseline

This file documents how to validate changes to the userspace-dp CoS admission path
(anything that touches `cos_flow_aware_buffer_limit`,
`cos_queue_flow_share_limit`, `apply_cos_admission_ecn_policy`, or the
admission block in `enqueue_cos_item`). Read it before opening a PR that
claims to move TCP fairness, retransmit count, or cwnd-collapse numbers on
the 16-flow iperf3 workload — otherwise you are likely to repeat the
mistake described in #725 or the VLAN-offset bug resolved in #728.

## How to read admission drop counters live

Since #724, `show class-of-service interface` renders three per-queue
counters on an indented `Drops:` line:

```
Queue  Owner  Class    ...  Buffer     Queued pkts  Queued bytes  ...
4      1      iperf-a  ...  1.19 MiB   299          443.24 KiB    ...
       Drops: flow_share=1923  buffer=0  ecn_marked=0
```

Definitions (from `CoSQueueDropCounters` in `userspace-dp/src/afxdp/types.rs`):

- `flow_share` — packets dropped because a single flow's bucket already holds
  its entire `share_cap` worth of bytes. The dominant failure mode on
  flow-fair exact queues under multi-flow load **before** ECN marking
  landed end-to-end.
- `buffer` — packets dropped because aggregate queue depth exceeded
  `buffer_limit`. Usually zero because #716 + #720 keep the aggregate
  nowhere near the cap.
- `ecn_marked` — count of successful ECN CE marks. Zero when either
  (a) the threshold never trips, or (b) no ECT packets reach the
  firewall, or (c) the marker is reading the wrong byte (see #728 —
  the VLAN-offset bug made the marker dormant even with ECT(0)
  on the wire).

Zero-valued counters are still printed. That is deliberate: an operator
needs to see the zero to confirm the counter is wired and the drop path
simply is not firing, versus the telemetry being broken.

### Reading them during an iperf3 run

```bash
# 16-flow iperf3 in background
incus exec loss:cluster-userspace-host -- \
  iperf3 -c 172.16.80.200 -P 16 -t 30 -p 5201 -i 0 >/dev/null 2>&1 &

sleep 10   # let the queue fill and the counters move

# Read the live counters mid-test
incus exec loss:xpf-userspace-fw0 -- \
  /usr/local/sbin/cli -c "show class-of-service interface"

wait   # let iperf3 finish
```

The counters are monotonic from process start. For a delta over a run,
snapshot before and after and subtract.

## gRPC server-side capture

AF_XDP bypasses the kernel network stack, so `tcpdump` on the firewall
netdev (`reth0`, `reth0.80`, physical member `ge-0-0-0`) **does not see
bulk data-plane traffic** — it only sees slow-path packets that fell back
through the kernel. This makes firewall-side netdev captures useless for
confirming what reached or left the dataplane on the hot path.

The `iperf-grpc-tcpdump` skill in `.codex/skills/iperf-grpc-tcpdump/SKILL.md`
solves this by running `tcpdump` on the iperf3 **server** over a gRPC
capture endpoint at `172.16.80.200:50051`, synchronised with LAN/WAN
captures on the active firewall and an iperf3 run from the client.

Ad-hoc capture (no iperf3 coordination) looks like:

```bash
grpcurl -plaintext -d '{"iface":"eth0","duration_s":30,"filter":"tcp port 5201"}' \
  172.16.80.200:50051 capture.CaptureService/Run > server-grpc.txt
```

For the full orchestrated run (server + LAN + WAN + iperf3 + stats
before/after), use the skill's helper:

```bash
.codex/skills/iperf-grpc-tcpdump/scripts/capture_iperf.sh --family 4 --parallel 16 --duration 30
```

This capture path is how #728 was diagnosed: server-side tcpdump
confirmed ECT(0) bits were present on ingress frames **before** the
firewall's marker ran, which ruled out "the endpoint doesn't negotiate
ECN" and pointed directly at the marker's L3 offset. Without the gRPC
capture we would have spent another round chasing phantom endpoint
problems. Use it whenever a local tcpdump shows `tos 0x0` on a VLAN
subinterface before concluding "ECN isn't negotiating" — the real packet
on the wire may say otherwise.

## Choosing a fix path

When the counters show something different from the current baseline
(see below), the pathology and the right fix may be different. The
decision tree:

| `flow_share` | `buffer` | `ecn_marked` | Interpretation | Likely fix |
|---|---|---|---|---|
| low (~10s/flow/30s) | 0 | high (~100k/30s) | Current post-#728 baseline. ECN holds cwnd at the knee; residual drops are microburst arrivals the marker couldn't catch in time. | #709 owner-worker hotspot / #718 Option B CoDel for the microburst residual. |
| high | low | 0 | Per-flow cap too tight; no ECN to soften it. Before concluding "endpoint doesn't negotiate ECN", run a gRPC server-side capture (see above) — #728 was this symptom caused by a VLAN-offset bug, not by the endpoint. | Confirm ECT on the wire via gRPC capture, then: fix marker if ECT present; otherwise ECN end-to-end, or CoDel (non-ECN AQM), or relax per-flow cap. |
| high | low | high | ECN fires but TCP still drops — ECN signal not enough | Lower ECN threshold, or combine with rate-based pacing |
| low | high | any | Aggregate cap tripping — bufferbloat | Revisit #720 clamp; look at operator `buffer-size` setting |
| 0 | 0 | 0 | Nothing is dropping; problem is elsewhere | Look at #709 (owner worker), #712 (CPU pinning), or network-layer loss |

## Current dominant failure mode on this workload

**Observed 2026-04-17, post-#728.** This is a dated snapshot, not
timeless methodology. Re-measure before citing these numbers in a new PR.

Fixture: `test/incus/cos-iperf-config.set`, 1 Gbps exact queue on queue 4,
16-flow iperf3, `net.ipv4.tcp_ecn=1` end-to-end, 30-second runs.

| Counter | Value |
|---|---|
| Rate ratio (max/min across flows) | 1.28× |
| Retransmits / 30 s | ~114 k |
| `flow_share_drops` / 30 s | ~75 (≈12 per flow) |
| `buffer_drops` / 30 s | 0 |
| `ecn_marked` / 30 s | ~97,349 |
| cwnd steady state | 8–17 KB |
| Queue depth steady state | ~150 KB (≈1.5 ms queueing latency) |

The admission path is doing what it was designed to do: ECN holds every
flow at the fairness knee (cwnd ≈ 12 KB), aggregate queueing stays around
1.5 ms, and packet drops are rare.

The residual ~12 `flow_share` drops per flow per 30 s are not the
RTO-driven collapse #704 was about — they come from microburst arrivals
where several packets from the same flow land in the same enqueue tick
faster than CE marks can propagate back through the TCP ack clock. The
remaining levers for this residual are the ones already tracked:

- **#709 (owner-worker hotspot)** — pinning the admission path to a
  dedicated worker reduces enqueue-tick variance, which reduces the
  microburst window.
- **#718 Option B (CoDel)** — adds a second AQM dimension that reacts
  to sojourn time, catching bursts that ECN threshold-based marking
  misses.

Neither is structurally required. The current baseline is a healthy,
fair, ECN-paced queue; the residual is the tail of what AQM can do
without rate pacing on the sender.

## History: the "ECN never negotiated" fire drill

**Resolved 2026-04-17 via #728 (VLAN-aware L3 offset).**

An earlier version of this doc documented a "limitation" that the
iperf3 server at `172.16.80.200` did not negotiate ECN, leaving
`ecn_marked=0` regardless of client/firewall `tcp_ecn` settings. That
was wrong. The server negotiates ECN correctly and ECT(0) packets were
reaching the firewall. The real bug was a hard-coded `TX_L3_OFFSET = 14`
in both Local and Prepared markers; on a VLAN subinterface
(`reth0 unit 80`) the frame carries an 802.1Q tag and L3 lives at
offset 18. The marker was reading the VLAN TCI byte, which rarely
matches ECT(0)/ECT(1), so the RFC 3168 NOT-ECT early-return fired on
every packet.

The lesson: **do not conclude "ECN isn't negotiated" from a
firewall-side tcpdump that shows `tos 0x0`**. AF_XDP means the
firewall-side capture doesn't see dataplane traffic at all, and even a
local client-side capture can be misleading if the path crosses a VLAN
boundary. Use the gRPC server-side capture at `172.16.80.200:50051` to
disambiguate where in the chain the ECT bits are being lost (or
mis-read).

The verification command still works — the conclusion to draw from it
is narrower than before:

```bash
# Capture 4 packets from an in-progress iperf3 run and look at tos.
# tos 0x0 in both directions does NOT by itself mean ECN is not
# negotiating — it may mean you are reading the wrong interface or
# hitting the #728 class of bug. Cross-check with a server-side gRPC
# capture before committing to that conclusion.
incus exec <client> -- tcpdump -v -c 4 -n 'tcp port 5201'
```

## Reading the owner-profile counters

Since #709 (Option E), `show class-of-service interface` renders a
second indented line under each queue row whose owner is a single
worker. This gives operators a latency view of the owner-worker
drain path without having to scrape Prometheus or attach perf:

```
Queue  Owner  Class    ...  Buffer     Queued pkts  Queued bytes  ...
4      1      iperf-a  ...  1.19 MiB   299          443.24 KiB    ...
       Drops: flow_share=75  buffer=0  ecn_marked=97349
       OwnerProfile: drain_p50=1us  drain_p99=16us  redirect_p99=2us  owner_pps=12345  peer_pps=6789
```

Field meanings (from `BindingLiveState` in `userspace-dp/src/afxdp/umem.rs`):

- `drain_p50 / drain_p99` — p50/p99 of the time spent inside
  `drain_shaped_tx` across its servicing tick. Sampled on EVERY
  invocation, bucketed into power-of-two ns buckets from 1 µs to
  ~16 ms. Lower bound of the bucket containing the Nth percentile
  sample is reported — it is a ballpark, not an exact stat.
- `redirect_p99` — p99 of the time spent in
  `BindingLiveState::enqueue_tx_owned` (the redirect-inbox push path
  peer workers use to deliver packets to the owner). Sampled 1-in-256
  on each producer to keep the common case allocation- and
  timer-free.
- `owner_pps` — packets the owner sourced itself on the window
  (accumulator, cleared by
  `clear statistics class-of-service`).
- `peer_pps` — packets peer workers redirected into the owner's
  MPSC inbox on the same window. Ratio tells the operator whether
  the owner is sourcing the bulk of the work itself or acting
  mostly as a fan-in point for peer redirects.

### What the shape means for #709

The plan (`docs/709-owner-hotspot-plan.md` §3) lays out a decision
tree that converts these counters into a fix path:

- **drain_p99 ≈ drain_p50 (flat right tail).** The owner drain is
  not the bottleneck. Close #709 as not-needed; keep #712 for CPU
  jitter.
- **drain_p99 ≥ 10× drain_p50 (fat right tail).** The owner has a
  head-of-line stall — most drains finish fast but a long tail of
  slow ones accumulates. Data supports Option B (work-stealing
  off-owner drain). The structural fix is worth the complexity.
- **drain_p99 is fine but redirect_p99 > 1 ms.** Unusual post-#715
  (the MPSC inbox is lock-free); if seen, pivot to a smaller
  producer-side fix rather than Option B.
- **drain_p99 ~ µs but owner_pps >> peer_pps.** The owner is
  overloaded with its own RX/forward/NAT work and only does a small
  amount of cross-worker redirect drain — Option C (RSS retargeting)
  or Option D (owner rotation) becomes more justified because the
  issue is "owner doing 2× work" not "inbox latency".

The guideline is the same one `engineering-style.md` sets out for
all perf PRs: read the counters, then decide. Iterating on fixes
without reading them is how we ship dormant code.

### Operational gotchas

- **Non-exact / shared_exact queues have NO OwnerProfile line.**
  The telemetry is per-binding on the owner's `BindingLiveState`;
  if there is no single owner binding (shared_exact at ≥ 2.5 Gbps,
  or non-exact queues), the CLI suppresses the row. An operator
  wanting the same view for a high-rate shared queue must wait for
  a sharded-per-worker histogram to land (not planned).
- **The counters are process-monotonic.** For a windowed delta on
  live traffic, snapshot before and after and subtract — same as
  the `Drops:` line.
- **Prometheus:** the same data flows out as
  `xpf_cos_drain_latency_ns_bucket{ifindex, queue_id, bucket_hi_ns}`,
  `xpf_cos_redirect_acquire_ns_bucket{...}`,
  `xpf_cos_drain_invocations_total{ifindex, queue_id}`,
  `xpf_cos_owner_pps{ifindex, queue_id}`, and `xpf_cos_peer_pps{...}`.
  Expected cardinality per the plan: ≤ 8192 series per histogram.

## CPU pinning layout for the loss lab

**Measured 2026-04-17 for #712 Option A.** Conclusion: the
`CPUAffinity=` directive on `xpfd.service` is a no-op on the 6-core
loss userspace lab because `userspace-dp` re-pins its workers inside
the process after systemd's mask is applied. Keep this section dated;
re-measure if any of the three blockers below move.

### Intended layout on the 6-core lab

The host is a 6-CPU VM. NIC IRQ distribution on fw0 under 16-flow
iperf3 load, sampled from `/proc/interrupts`:

- mlx5_comp0 (WAN VF RX q0) → CPU 0, ~800 M interrupts
- mlx5_comp1 (WAN VF RX q1) → CPU 1, ~900 M interrupts
- mlx5_comp2..5 (WAN VF RX q2..5) → CPUs 2..5, ~500-900 M each
- virtio-input/output q0..5 → pinned 1-per-CPU across CPUs 0..5

Each CPU carries NIC IRQ load; CPUs 0-1 are the hottest. The recipe in
`docs/712-cpu-pinning-recipe.md` §"6-core host" reserves CPUs 0-1 for
IRQ + housekeeping and gives xpfd and its four dp workers CPUs 2-5:

```
[Service]
CPUAffinity=2 3 4 5
```

### Why that recipe is a no-op today

`xpf-userspace-dp` calls `pin_current_thread(worker_id)` in
`userspace-dp/src/afxdp/neighbor.rs`, which issues
`sched_setaffinity(0, CPU_SET(worker_id % nproc))` per worker **after**
systemd has installed the unit mask. `nproc` (via
`std::thread::available_parallelism()`) correctly reports 4 when the
process is launched with `CPUAffinity=2 3 4 5`, but the call pins each
worker to absolute CPU `worker_id % 4` — i.e. CPU 0, 1, 2, 3 — not to
the 0th..3rd CPU of the allowed set. Result: the four hot-path workers
land on CPUs 0-3 regardless, colliding with `mlx5_comp0` and
`mlx5_comp1`. The Go main and the dp aux threads (state-writer,
event-stream, slowpath, neigh-monitor) do honour the mask and run on
CPUs 2-5.

### Measurement

16-flow iperf3 × 30 s × 3 runs, client
`cluster-userspace-host`, target `172.16.80.200`, CoS fixture
`test/incus/cos-iperf-config.set` applied, fw0 primary. Computed with
`/tmp/712-pinning/analyze.py` (iperf3 `-J` on the client; per-flow CoV
is the standard deviation of the per-second bps samples on each stream,
divided by that stream's mean).

| Metric | Pre-pin mean | Post-pin mean | Δ |
|---|---|---|---|
| Rate ratio (max/min per-flow) | 1.39× | 1.45× | +4% (worse) |
| Retransmits / 30 s | 181 k | 204 k | +13% (worse) |
| Per-flow CoV mean | 14.3% | 15.9% | +1.6 pp (worse) |
| Per-flow CoV max | 25.4% | 26.4% | +1.0 pp (flat) |

All deltas within run-to-run noise. No metric moved in a good
direction. Acceptance criterion from #712 — per-flow stdev/mean ≤ 10% —
was not met pre-pin (~14%) and not closer post-pin. Per
`engineering-style.md` §"Hot-path coding discipline", the directive
was reverted in the same PR; the recipe doc lives on as design intent.

### Blockers before Option A can land as a win

1. `pin_current_thread` must pick the Nth allowed CPU, not absolute
   CPU N. One-line follow-up in `userspace-dp/src/afxdp/neighbor.rs`.
2. Option B (kernel cmdline `isolcpus=`+`nohz_full=`) would remove
   kernel timers and RCU callbacks from worker CPUs entirely. It
   requires a cmdline edit and reboot, so deployment shape has to opt
   in. Tracked as a follow-up to #712.
3. Option D (cgroup cpuset) is softer and does not require a cmdline
   change but needs operator decisions about which cpuset holds which
   non-xpfd process. Tracked as a follow-up to #712.

Until one of these lands, the 14% per-flow CoV on this lab is the
floor — Option A alone does not move it.

## Gotchas the deploy wipes

The cluster deploy path (`cluster-setup.sh deploy`) wipes the CoS
config every run — the bootstrapped `xpf.conf` does not carry the
iperf CoS fixture. After every deploy, re-apply:

```bash
./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0
```

The loader script lives at `test/incus/apply-cos-config.sh` and is
documented inline. It is intentionally strict on `load merge` / `commit`
since #716 — if you see a validation error, stop and investigate rather
than re-running. The accompanying fixture at
`test/incus/cos-iperf-config.set` covers both `family inet` and
`family inet6` classifier state.

See also the "CoS deploy preserves config" bullet in
[`engineering-style.md`](engineering-style.md#project-specific-reminders).

## Refs

- #704 — umbrella cwnd-collapse symptom
- #709 — owner-worker hotspot (remaining lever for microburst residual)
- #716 — flow-aware admission cap
- #718 — ECN CE marking at CoS admission (Local variant) + Option B CoDel tracker
- #720 — latency-envelope clamp
- #721 — aggregate ECN threshold
- #722 — per-flow ECN mark threshold
- #724 — surface admission drop counters (unblocked this methodology)
- #725 — validation-pipeline gap findings (live data + path forward)
- #727 — ECN marking on Prepared CoS variant (closed the Local-only gap)
- #728 — VLAN-aware L3 offset + threshold tune (resolved the dormant-marker symptom)
- #712 — CPU pinning + IRQ isolation (Option A measured no-op on this lab; see "CPU pinning layout for the loss lab")
