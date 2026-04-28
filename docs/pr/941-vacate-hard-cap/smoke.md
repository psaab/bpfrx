# #941 cluster smoke evidence

Captured 2026-04-28 on `loss:xpf-userspace-fw0/fw1` userspace cluster
during the implementation of PR #952.

## Setup

- Branch: `sprint/941-vacate-hard-cap` (commit at smoke time: `4d72a7f2`).
- Cluster: 2-node HA (xpf-userspace-fw0 primary, xpf-userspace-fw1
  secondary).
- Source: cluster-userspace-host (10.0.61.102).
- Target: 172.16.80.200.
- Deploy: `BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env
  ./test/incus/cluster-setup.sh deploy`.
- CoS config: `./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0`
  (the post-#951 7-class config).

## Acceptance gates (per plan v7)

| Test | Gate | Command | Result |
|---|---|---|---|
| iperf-c P=12 throughput | ≥ 22 Gb/s | `iperf3 -c 172.16.80.200 -p 5203 -P 12 -t 10` | **23.4 Gb/s, 4840 retx** ✓ |
| iperf-c P=1 throughput  | ≥ 6 Gb/s  | `iperf3 -c 172.16.80.200 -p 5203 -P 1 -t 5`   | **6.95 Gb/s, 0 retx** ✓ |
| iperf-b P=12 throughput | ≥ 9.5 Gb/s, 0 retx | `iperf3 -c 172.16.80.200 -p 5202 -P 12 -t 10` | **9.58 Gb/s, 0 retx** ✓ |

All sender from cluster-userspace-host. Mouse-latency p99 not
measured in this round (deferred to a full mouse-latency run before
final merge).

## #942 unblock verification

Per plan v7 acceptance criterion: "temporarily add the
`cos_queue_v_min_continue` call back into
`drain_exact_prepared_items_to_scratch_flow_fair` and run iperf-c
P=12 cluster smoke. Must pass at ≥ 22 Gb/s."

The temporary wiring was added (matching the original #942 hunk) and
the smoke ran:

| Test | Result |
|---|---|
| iperf-c P=12 with #942 wiring re-enabled | **23.1 Gb/s, 10199 retx** ✓ |
| iperf-c P=1 with #942 wiring re-enabled | **7.02 Gb/s, 0 retx** ✓ |

The 23.1 Gb/s clears the 22 Gb/s gate. The retx count (10K) is higher
than #941-only (4840), which is expected: with the #942 wiring, V_min
throttle fires until hard-cap activates suspension, and during the
brief 8-batch throttle window before suspension, packets queue up and
some get dropped. The hard-cap suspension recovers throughput
(23.1 Gb/s) but at the cost of some retransmissions during the
transition. Acceptable per the design.

The temporary wiring was reverted in commit `4d72a7f2` before the PR
was opened. The wiring will land in #942's separate PR.

## Comparison to pre-#941 state

For reference, the pre-#941 broken state on the same workload:

| Test | Pre-#941 (original #942 attempt, eeade5e2) | Post-#941 (this PR + temp wiring) |
|---|---|---|
| iperf-c P=12 | Connection timeouts; 7/12 streams connected | 23.1 Gb/s |
| iperf-c P=1 | 4.4 Mb/s, cwnd stuck at 1.41 KB | 7.02 Gb/s |

#941 unblocks #942.

## Hard-cap counter observation

The new `v_min_throttle_hard_cap_overrides` counter on
`BindingLiveState` was not yet exposed via the gRPC snapshot (#943
will surface it). During the smoke runs, the counter incremented on
the primary's bindings as expected — visible in journald via
`debug-log` build feature, but not surfaced through CLI in this
round.

## Test command transcripts

```
$ sg incus-admin -c "incus exec loss:cluster-userspace-host -- bash -c 'iperf3 -c 172.16.80.200 -p 5203 -P 12 -t 10'"
[SUM]   0.00-10.00  sec  27.3 GBytes  23.4 Gbits/sec  4840             sender
[SUM]   0.00-10.01  sec  27.3 GBytes  23.4 Gbits/sec                  receiver

$ sg incus-admin -c "incus exec loss:cluster-userspace-host -- bash -c 'iperf3 -c 172.16.80.200 -p 5203 -P 1 -t 5'"
[  5]   0.00-5.00   sec  4.05 GBytes  6.95 Gbits/sec    0            sender

$ sg incus-admin -c "incus exec loss:cluster-userspace-host -- bash -c 'iperf3 -c 172.16.80.200 -p 5202 -P 12 -t 10'"
[SUM]   0.00-10.00  sec  11.2 GBytes  9.58 Gbits/sec    0             sender
```
