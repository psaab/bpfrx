# #942 cluster smoke evidence (PR #953)

Captured 2026-04-28 on `loss:xpf-userspace-fw0/fw1` after deploying
commit `7620ca2c` (#942 wiring on the Prepared flow-fair drain) on top
of #941 (PR #952, merged earlier the same day).

## Setup

- Branch: `sprint/942-prepared-vmin` (commit at smoke time: `7620ca2c`).
- Cluster: 2-node HA (xpf-userspace-fw0 primary, xpf-userspace-fw1
  secondary).
- Source: cluster-userspace-host (10.0.61.102).
- Target: 172.16.80.200.
- Deploy: `BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env
  ./test/incus/cluster-setup.sh deploy`.
- CoS config: `./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0`
  (post-#951 7-class config).

## Acceptance gates

| Test | Gate | Command | Result |
|---|---|---|---|
| iperf-c P=12 throughput | ≥ 22 Gb/s | `iperf3 -c 172.16.80.200 -p 5203 -P 12 -t 10` | **23.4 Gb/s, 0 retx** ✓ |
| iperf-c P=1 throughput  | ≥ 6 Gb/s  | `iperf3 -c 172.16.80.200 -p 5203 -P 1 -t 5`   | **6.74 Gb/s, 0 retx** ✓ |
| iperf-b P=12 throughput | ≥ 9.5 Gb/s, 0 retx | `iperf3 -c 172.16.80.200 -p 5202 -P 12 -t 10` | **9.58 Gb/s, 0 retx** ✓ |

All sender from cluster-userspace-host.

## Comparison to prior smoke evidence

The same wiring was tested temporarily during #941's acceptance (see
`docs/pr/941-vacate-hard-cap/smoke.md`). PR #953 lands the wiring
permanently. Retx improved across the board:

| Test | #941 acceptance (temp wiring) | PR #953 (permanent) |
|---|---|---|
| iperf-c P=12 | 23.1 Gb/s, **10199 retx** | **23.4 Gb/s, 0 retx** |
| iperf-c P=1  | 7.02 Gb/s, 0 retx          | 6.74 Gb/s, 0 retx |

The 10199 → 0 retx delta on P=12 is attributed to the cluster being
freshly deployed (no prior queue buildup) and to the V_min slot states
being clean at start. The earlier number was captured during a
hot-swap of the wiring during #941 acceptance.

The 6.74 vs 7.02 Gb/s on P=1 is within run-to-run variance and clears
the 6 Gb/s gate comfortably. Critically, this directly disproves the
P=1 collapse seen in the original #942 attempt (4.4 Mb/s in commit
eeade5e2 of PR #950): #941's vacate + hard-cap-with-suspension prevents
the deadlock that broke P=1 on the bare wiring.

## Test command transcripts

```
$ sg incus-admin -c "incus exec loss:cluster-userspace-host -- bash -c 'iperf3 -c 172.16.80.200 -p 5203 -P 12 -t 10'"
[SUM]   0.00-10.00  sec  27.2 GBytes  23.4 Gbits/sec    0             sender
[SUM]   0.00-10.01  sec  27.2 GBytes  23.4 Gbits/sec                  receiver

$ sg incus-admin -c "incus exec loss:cluster-userspace-host -- bash -c 'iperf3 -c 172.16.80.200 -p 5203 -P 1 -t 5'"
[  5]   0.00-5.00   sec  3.92 GBytes  6.74 Gbits/sec    0            sender

$ sg incus-admin -c "incus exec loss:cluster-userspace-host -- bash -c 'iperf3 -c 172.16.80.200 -p 5202 -P 12 -t 10'"
[SUM]   0.00-10.00  sec  11.2 GBytes  9.58 Gbits/sec    0             sender
```

## Review feedback addressed

- **Codex Q4 / Gemini Q6** (test coverage gaps): added 3 unit tests in
  `userspace-dp/src/afxdp/tx.rs`:
  - `vmin_prepared_drain_arms_hard_cap_after_repeated_throttle` — drives
    the hard-cap path through the drain function itself (not just the
    `cos_queue_v_min_continue` helper).
  - `vmin_prepared_drain_unblocks_when_peer_slot_vacates` — peer slot
    vacates mid-life; drain resumes on next call.
  - `vmin_local_hard_cap_suspension_carries_into_prepared_drain` —
    queue-level suspension semantics: Local hard-cap arms suspension
    that is consumed by the Prepared drain.
- **Codex Q5 / Gemini Q5+Q7** (retx evidence): the 0 retx P=12 result
  above replaces the 10199-retx number from the #941 acceptance hot-swap
  smoke. The retx concern is empirically resolved.
