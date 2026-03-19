---
name: userspace-native-gre-iperf
description: Validate native GRE userspace dataplane stability with ping, TCP connect, iperf3, and RG failover on the isolated loss userspace cluster. Use this when checking that GRE transit stays on the WAN path, gr-0-0-0 stays out of transit, and long-lived traffic does not collapse during failover.
---

# Userspace Native GRE iperf Validation

Use this skill when the task is to validate native GRE dataplane behavior on the isolated `loss` userspace cluster.

Primary inputs:
- env: `test/incus/loss-userspace-cluster.env`
- config: `docs/ha-cluster-userspace.conf`
- validator: `scripts/userspace-native-gre-validation.sh`
- iperf parser: `scripts/iperf-json-metrics.py`
- design/status: `docs/userspace-native-gre-plan.md`

What this skill is for:
- proving GRE transit is on the physical WAN path
- proving `gr-0-0-0` is only an anchor and not the transit dataplane path
- checking that long-lived TCP stays up under steady load
- checking that manual RG failover does not produce zero-throughput intervals

Baseline workflow:
1. Pin the preferred active node and wait for userspace forwarding to arm.
2. Run GRE ICMP transit from `cluster-userspace-host` to `10.255.192.41`.
3. Verify outer GRE traffic moves on the WAN interface and tagged transit does not appear on `gr-0-0-0`.
4. Run GRE TCP connect to `10.255.192.41:22`.
5. Run `iperf3` with `--json-stream` and parse it with `scripts/iperf-json-metrics.py`.
6. For failover, move RG1 with `request chassis cluster failover redundancy-group 1 node ...` while the GRE `iperf3` flow is active.
7. Treat zero-throughput intervals as the failure signal. High retransmits are a quality issue, but flow collapse is the primary gate.

Core commands:
```bash
./scripts/userspace-native-gre-validation.sh --iperf --count 2
PREFERRED_ACTIVE_RGS=1 PREFERRED_ACTIVE_NODE=0 ./scripts/userspace-native-gre-validation.sh --iperf --failover --count 2
PREFERRED_ACTIVE_RGS=1 PREFERRED_ACTIVE_NODE=1 ./scripts/userspace-native-gre-validation.sh --iperf --failover --count 2
```

Important interpretation:
- `gr-0-0-0` may exist as a `dummy` anchor.
- Transit must stay off that device.
- The validator proves transit behavior. It does not prove firewall-originated tunnel traffic unless `GRE_VALIDATE_HOST_PROBES=1` is set and that path is intentionally supported.
- For the exact HA repro, use RG1 failover, not a simultaneous multi-RG move.

When debugging:
- Capture WAN GRE on the active firewall.
- Capture any inner traffic on `gr-0-0-0` only to prove leakage.
- Compare `iperf3` JSON-stream intervals before and after failover.
- Read `docs/userspace-native-gre-plan.md` for the validated scope and remaining gaps.
