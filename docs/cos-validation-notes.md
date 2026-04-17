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
