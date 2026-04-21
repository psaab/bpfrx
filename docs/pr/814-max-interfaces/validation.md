# #814 validation

## Target cluster
`loss:xpf-userspace-fw0` / `loss:xpf-userspace-fw1` / `loss:cluster-userspace-host`.
Per `docs/development-workflow.md:188-194`, `bpfrx-fw0/fw1` is NOT a supported surface for this PR.

## Pre-deploy baseline

Max ifindex on fw0: 1800 (`xpf-usp0`). Max ifindex on fw1: 2566 (`fab1@ge-7-0-0`).
fw1 `fab0` = 2561 — the trigger ifindex for #814.

fw1 pre-deploy: xpfd running but dataplane compile failing:
```
level=WARN msg="failed to compile dataplane"
  err="compile zones: add tx port fab0: update: key too big for map: argument list too long"
  attempt=1 ever_ok=false
level=WARN msg="cluster: event stream bulk export failed, falling back to BulkSync"
  err="userspace dataplane helper not running"
```

Pre-deploy iperf3 -c 172.16.80.200 -P 4 -t 5 -p 5203 (from cluster-userspace-host):
**14.1 Gbits/sec, 0 retransmits.**

## Gate A — fw0 no-regression

Deploy: `BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env ./test/incus/cluster-setup.sh deploy 0`.

- `systemctl is-active xpfd` on fw0: **active**
- `/run/xpf/userspace-dp.sock`: exists
- `pidof xpf-userspace-dp`: 430289
- `journalctl -u xpfd` grep for `SEG_MISS|failed to compile|key too big|ever_ok=false`: **0 matches**
- `dmesg` grep for `mlx5|bpf|oom|allocation failure`: no new errors (only expected link up/down around restart)
- iperf3 `-P 4 -t 5` post-failback to fw0: **21.8 Gbits/sec, 0 retransmits**.

Gate A: **PASS**.

## Gate B — fw1 compile succeeds

Deploy: `BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env ./test/incus/cluster-setup.sh deploy 1`.

- `systemctl is-active xpfd` on fw1: **active**
- `/run/xpf/userspace-dp.sock`: exists
- `pidof xpf-userspace-dp`: 139223
- `journalctl -u xpfd` grep for `ever_ok=false|failed to compile|key too big`: **0 matches**
- `dmesg`: clean

Gate B: **PASS**. fw1's `fab0` at ifindex 2561 no longer overflows the tx_ports cap.

## Gate C — HA failover both directions

fw0 primary / fw1 secondary pre-failover. All 3 RGs `Takeover ready: yes`.

`iperf3 -c 172.16.80.200 -P 4 -t 30 -p 5203` launched from cluster-userspace-host. At t=5s, manual failover fw0→fw1 triggered on RGs 0/1/2. At t=20s, failback fw1→fw0 triggered on RGs 0/1/2.

Iperf result (30-second run spanning both transitions):
- Aggregate: 58.8 GB / 16.8 Gbits/sec.
- Final 1-second slice (t=29-30s, post-convergence): **18.2 Gbits/sec, 0 retransmits**.
- Transition retrans (across failover + failback windows): 22722 total. Observational only per plan (no sourced threshold for transition window).

Post-Gate-C steady-state `iperf3 -P 4 -t 5`: **17.6 Gbits/sec, 0 retransmits**.

No SEG_MISS, BPF errors, mlx5 errors, or OOM on either node throughout.

Gate C: **PASS**.

## Summary

All three gates pass. #814 resolved.
