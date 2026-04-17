# CoS admission validation — methodology and current limitations

This file documents how to validate changes to the userspace-dp CoS admission path
(anything that touches `cos_flow_aware_buffer_limit`,
`cos_queue_flow_share_limit`, `apply_cos_admission_ecn_policy`, or the
admission block in `enqueue_cos_item`). Read it before opening a PR that
claims to move TCP fairness, retransmit count, or cwnd-collapse numbers on
the 16-flow iperf3 workload — otherwise you are likely to repeat the
mistake described in #725.

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
  flow-fair exact queues under multi-flow load.
- `buffer` — packets dropped because aggregate queue depth exceeded
  `buffer_limit`. Usually zero because #716 + #720 keep the aggregate
  nowhere near the cap.
- `ecn_marked` — count of successful ECN CE marks. Zero when either
  (a) the threshold never trips, or (b) no ECT packets reach the
  firewall. Look at both before drawing a conclusion.

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

## Current test-env limitation: ECN never negotiated

**Observed state 2026-04-17** — this is not timeless methodology, it
is a lab-setup snapshot that will rot as endpoints, kernels, and
network segments change. Re-run the verification commands below before
trusting anything in this section.

The iperf3 server at `172.16.80.200` (at time of writing) does not
respond with ECN-negotiated SYN-ACKs. That means, regardless of
`net.ipv4.tcp_ecn` settings on the client and firewalls:

- Every packet arrives at the firewall with `tos 0x0` (NOT-ECT).
- `maybe_mark_ecn_ce` correctly early-returns per RFC 3168 §6.1.1.1
  (the firewall must not unilaterally force ECN on a flow that did not
  opt in).
- `ecn_marked` stays at zero for the life of the connection.

**Implication**: #721 (aggregate ECN threshold) and #722 (per-flow
ECN threshold) are structurally correct but dormant on this workload.
They would fire as designed if packets were ECT.

### Verify the current state

```bash
# Capture 4 packets from an in-progress iperf3 run and look at tos.
# tos 0x0 on both directions == no ECN negotiation == ECN-path code dormant.
incus exec <client> -- tcpdump -v -c 4 -n 'tcp port 5201'
```

If the verification shows `tos != 0x0` on both directions, ECN is
live and this section is stale — update it.

### Controlling the endpoint for ECN validation

To exercise #721/#722 end-to-end, stand up a controllable iperf3
server:

1. Run an iperf3 server on a VM where both endpoints can set
   `tcp_ecn=1` (e.g., reuse `cluster-userspace-host` as the server
   and point a second client at it through the firewall, or add a new
   VM on the WAN side).
2. Verify ECT bits show up on the wire with the tcpdump above.
3. Re-run the iperf3 load and watch `ecn_marked` bump during the run.

## Current dominant failure mode on this workload

With #716 and #720 (latency clamp from issue #717) landed, the
16-flow / 1 Gbps exact queue workload sits at ~31% aggregate buffer
utilisation (~378 KB of a 1.19 MiB buffer) during steady state. The
dominant drop source is:

- `flow_share_drops`: ~190/sec on queue 4.
- `buffer_drops`: 0.
- `ecn_marked`: 0 (see above).

At 190 drops/sec distributed across 16 flows, each flow sees
~12 drops/sec on average — one drop every ~80 ms. That is much
faster than the 1–2 s this file previously claimed. At ~80 ms
between drops the flow never gets a clean RTT to re-open cwnd
past ~5–6 MSS before the next drop lands; drops also arrive in
bursts (tail-drop on microbursts), so many of the 12/sec do not
produce the 3 dupacks needed for TCP fast-retransmit and the flow
takes RTO instead, collapsing cwnd to 1 MSS. That is the
10–15/16-flows-collapsed pattern in #704/#722.

## Choosing a fix path

When the counters show something different from "`flow_share` dominant, `buffer` zero, `ecn_marked` zero", the pathology and the right fix may be different. The decision tree:

| `flow_share` | `buffer` | `ecn_marked` | Interpretation | Likely fix |
|---|---|---|---|---|
| high | low | 0 | Per-flow cap too tight; no ECN to soften it | ECN end-to-end (test-env fix), or CoDel (non-ECN AQM), or relax per-flow cap |
| high | low | high | ECN fires but TCP still drops — ECN signal not enough | Lower ECN threshold, or combine with rate-based pacing |
| low | high | any | Aggregate cap tripping — bufferbloat | Revisit #720 clamp; look at operator `buffer-size` setting |
| 0 | 0 | 0 | Nothing is dropping; problem is elsewhere | Look at #709 (owner worker), #712 (CPU pinning), or network-layer loss |

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
- #716 — flow-aware admission cap
- #720 — latency-envelope clamp
- #721 — ECN CE marking at CoS admission
- #722 — per-flow ECN mark threshold
- #724 — surface admission drop counters (unblocked this methodology)
- #725 — validation-pipeline gap findings (live data + path forward)
