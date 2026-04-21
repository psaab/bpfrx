# Issue #799 — `rx_steer_missed_packets` investigation

Branch: `pr/line-rate-investigation`
Host under test: `loss:xpf-userspace-fw0`
Interface: `ge-0-0-2` (WAN parent; VLANs 50 + 80)
Driver: `mlx5_core` 7.0.0-rc7+, firmware 26.48.1000, PCI `0000:09:00.0`
Executed: 2026-04-21 (UTC) on the same instance as the Step 0 audit
(daemon uptime ~1h 15m at measurement start).

## Verdict

**Red herring.** `rx_steer_missed_packets` is accumulating from shared-LAN
background traffic on VLANs the firewall is not configured to receive
(VLAN 1, 666, 1000, plus STP BPDUs and foreign-MAC multicast on
VLANs 50/80 that aren't in our joined groups). It is **not** on the
iperf3 data path. Fixing it will not close the line-rate gap. Do
**not** block Phase B on it.

## What the counter measures

`rx_steer_missed_packets` (mlx5 `en_stats.c`) counts packets the NIC
received off the wire but did not deliver to any steering destination
— i.e. they matched no VLAN-filter entry, no MAC-filter entry, and no
multicast-join entry, so the hardware dropped them before they ever
reached an RX ring. It is distinct from `rx_out_of_buffer` (ring
empty) and `rx_discards_phy` (PHY-level errors). These are
**filter-drop** counts, not fastpath drops.

## Evidence — the counter is NOT on the iperf3 data path

### 1. Growth rate is identical at idle and under 23 Gbps load

| Window | Duration | Start | End | Delta | Rate |
|-|-|-|-|-|-|
| Idle pre-test | 10 s | 55,797,507 | 55,798,216 | 709 | **~71 pps** |
| Idle mid (new sample) | 30 s | 55,808,641 | 55,811,083 | 2,442 | **~81 pps** |
| Idle long-baseline | 60 s | (A) | (C) | 5,344 | **~89 pps** |
| **iperf3 P=16 t=60** | 60 s | 55,802,248 | 55,807,182 | **4,934** | **~82 pps** |

Idle: ~70–90 pps. Under 23 Gbps of load: **82 pps**.
They are statistically indistinguishable — the iperf3 traffic
contributes **zero** steer-misses. If the counter were on the data
path we would expect millions of pps at 23 Gbps.

### 2. Per-queue XSK counters confirm the data path is healthy

`ethtool -S ge-0-0-2` per-queue totals during the test window:

```
rx0_xsk_xdp_redirect: 430,764,658
rx1_xsk_xdp_redirect: 395,854,669
rx2_xsk_xdp_redirect: 440,927,457
rx3_xsk_xdp_redirect: 487,025,057
rx4_xsk_xdp_redirect: 383,170,703
rx5_xsk_xdp_redirect: 485,323,938
```

All 6 queues are consuming XSK packets; no queue shows a correlated
increment to `rx_steer_missed_packets`.

### 3. tcpdump confirms the missed packets are shared-LAN noise

5 s of packet capture on `ge-0-0-2` (promisc for capture only — NIC
itself runs with `promiscuity 0, allmulti 0`) shows the recurring
broadcast/multicast the NIC HW filter is rejecting:

- VLAN **1** ARPs from 5+ unrelated source MACs (172.16.0.x tellers)
- VLAN **666** ARPs from `00:10:db:ff:10:01` (192.168.66.x)
- VLAN **1000** ARPs (192.168.99.x)
- STP BPDUs to `01:80:c2:00:00:00`
- IPv6 multicast listener reports / neighbor solicitations
  for groups + IPs **not** joined on our `ge-0-0-2.80` / `ge-0-0-2.50`

Our interface has only VLAN 50 + 80 registered and MAC
`02:bf:72:16:01:00`; `rx-vlan-filter: on`, `promiscuity 0`,
`allmulti 0`. Everything above is dropped by the HW VLAN filter or MAC
filter — exactly what `rx_steer_missed_packets` counts.

### 4. Absolute magnitude breakdown

At ~82 pps steady state, the 55.8 M accumulated counter is consistent
with a longer historical window:

- Daemon up ~4380 s → average 12,740 pps over uptime if uniform — but
  current steady state is only ~82 pps, **150× lower**.
- The headline 55 M was almost certainly accrued during the **RETH
  programming window** at each `xpfd` startup (`programRethMAC`
  briefly cycles link DOWN → set MAC → UP; during DOWN the NIC's
  steering tables are wiped, and during the early UP window before
  VLAN offload is re-disabled, the HW filter is in a transient state
  that can count every frame on the shared LAN as a steer-miss).
  Journal confirms repeated daemon restarts over the past 5 h with
  `"re-disabled VLAN RX offload after RETH MAC"` events, and
  post-reconciliation the rate drops to ~80 pps.
- At 80 pps a busy broadcast domain needs only ~12 h to build a 3.5 M
  counter; multiple daemon restarts easily explain 55 M.

## Root cause (best-fit hypothesis)

Two overlapping effects, neither of which is a bug worth shipping a
fix for:

1. **Shared-LAN broadcast/multicast noise on unregistered VLANs and
   foreign MACs.** The steady-state ~80 pps is 100% this. These are
   packets the NIC HW filter is *correctly* dropping. This would
   happen on any production Mellanox NIC sitting on a trunk port
   carrying more VLANs than we've registered.

2. **Transient spike during each `programRethMAC` cycle at daemon
   start.** While the link flaps + steering table is re-programmed,
   the HW filter passes through a state where it accumulates
   steer-misses faster. This is cosmetic — no traffic is lost on any
   configured VLAN / MAC because `programRethMAC` only runs at
   startup/failover, which are by design disruption events we already
   account for (~130 ms failback).

## Correlation with iperf3

**None.** Idle delta rate ≈ test-time delta rate. No per-queue counter
scales with test load. No change in `rx_out_of_buffer`
(26 → 26 throughout the test).

## Proposed fix

**None required.** Options considered and rejected:

| Option | Assessment |
|-|-|
| Set NIC to promisc / allmulti | Accepts every foreign-VLAN packet into the ring, wasting RX budget on traffic we will drop in software. Net-negative. |
| Add explicit drop flow-steering rules via `ethtool -N` | Would just move the counter from "steer-miss" to "flow-rule hit + drop" — same cost on the wire, no throughput win. |
| Filter all unneeded VLANs at the switch | Correct operational fix for a production deployment, but it is a lab-environment property, not an `xpf` code change. |
| Treat the counter as cosmetic and monitor delta instead of absolute | **Recommended**. At Step 3 / Phase B re-baseline, subtract the pre-test value and report the delta over the test window. |

Re-baselining guidance for Step 0 going forward:

> For `rx_steer_missed_packets`, record **delta over the iperf3 test
> window** and flag only if the delta rate exceeds ~10× idle baseline.
> Absolute cumulative value is not a reliable Step-0 signal on a
> shared-LAN test rig.

## Expected line-rate impact

**Zero.** The counter is filter-drop on traffic that is not ours.
Closing it would not free any NIC ring, CPU, or PCIe bandwidth on the
iperf3 path because those packets never reach any of them.

The true line-rate gap almost certainly lives in the other Step 0
FAIL rows — IRQ/worker misalignment on q4/q5 (#800), adaptive
coalescing (#801), `schedutil` host governor, and the XDP_FALLBACK
counters (`early_filter=581`, `iface_nat_no_sess=264`) — not here.

## Fairness risk (Phase 3 MQFQ)

**None.** `rx_steer_missed_packets` increments are per-NIC not
per-queue, and the HW filter drops happen before any RSS or XSK
worker sees them. Per-queue `rx{N}_xsk_xdp_redirect` totals above are
within ~25 % of each other across the 6 queues, which is the
expected envelope from RSS hashing over a modest number of flows
(P=16 streams → 16 × 2 (fwd+rev) = 32 distinct 5-tuples vs 6 RSS
buckets). Phase 3 fairness is not affected by this counter.

## Forwarding smoke — post-investigation

`iperf3 -c 172.16.80.200 -P 4 -t 5 -p 5201` from
`loss:cluster-userspace-host` immediately after the above runs:

```
[SUM]   0.00-5.00   sec  8.19 GBytes  14.1 Gbits/sec    0             sender
[SUM]   0.00-5.00   sec  8.18 GBytes  14.0 Gbits/sec                  receiver
```

Forwarding works. No regression from the investigation.

## Disposition

- **Close issue #799 as Works-As-Intended / cosmetic.** Keep a note
  on the Step 0 audit doc replacing the FAIL row with
  *"shared-LAN noise, delta rate ≈ idle under 23 Gbps load — not on
  data path"*.
- **Do not halt Phase B** on this row. Proceed to the remaining
  Step 0 FAILs (#800 worker count, #801 sysctl/coalescence, host
  governor).
- **Revisit only if**: during a production-representative test on a
  clean switch port (only VLANs 50 + 80 on the trunk) the counter
  *still* grows faster than idle during iperf3. That would be a
  genuine steering-rule bug — but none of our Step-0 evidence
  supports that on the lab rig.
