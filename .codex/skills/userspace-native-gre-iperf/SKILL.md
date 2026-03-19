---
name: userspace-native-gre-iperf
description: Validate native GRE userspace dataplane stability with ping, TCP connect, iperf3, UDP, traceroute, and RG failover on the isolated loss userspace cluster. Use this when checking that GRE transit stays on the WAN path, gr-0-0-0 stays out of transit, and long-lived traffic does not collapse during failover.
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
- proving `gr-0-0-0` is only a persistent TUN anchor and not the transit dataplane path
- checking that long-lived TCP stays up under steady load
- checking that UDP transit still stays on the WAN path
- checking that traceroute/mtr resolves over GRE without leaking onto `gr-0-0-0`
- checking that manual RG failover does not produce zero-throughput intervals
- checking that firewall-originated GRE traffic still works when `GRE_VALIDATE_HOST_PROBES=1`

Baseline workflow:
1. Pin the preferred active node and wait for userspace forwarding to arm.
2. Run GRE ICMP transit from `cluster-userspace-host` to `10.255.192.41`.
3. Verify outer GRE traffic moves on the WAN interface and tagged transit does not appear on `gr-0-0-0`.
4. Run GRE TCP connect to `10.255.192.41:22`.
5. Run `iperf3` with `--json-stream` and parse it with `scripts/iperf-json-metrics.py` when the remote `5201` server is available.
6. Run the native GRE UDP burst gate and the GRE traceroute/mtr gate.
7. For failover, move RG1 with `request chassis cluster failover redundancy-group 1 node ...` while the GRE `iperf3` flow is active.
8. Treat zero-throughput intervals as the failure signal. High retransmits are a quality issue, but flow collapse is the primary gate.
9. When validating firewall-originated support, set `GRE_VALIDATE_HOST_PROBES=1` and require host-originated ping, TCP connect, and optional `iperf3` to work on the active node and after failover.

Core commands:
```bash
./scripts/userspace-native-gre-validation.sh --udp --traceroute --count 2
./scripts/userspace-native-gre-validation.sh --iperf --count 2
GRE_VALIDATE_HOST_PROBES=1 ./scripts/userspace-native-gre-validation.sh --iperf --count 2
PREFERRED_ACTIVE_RGS=1 PREFERRED_ACTIVE_NODE=0 ./scripts/userspace-native-gre-validation.sh --udp --traceroute --failover --count 2
PREFERRED_ACTIVE_RGS=1 PREFERRED_ACTIVE_NODE=0 ./scripts/userspace-native-gre-validation.sh --iperf --failover --count 2
GRE_VALIDATE_HOST_PROBES=1 PREFERRED_ACTIVE_RGS=1 PREFERRED_ACTIVE_NODE=0 ./scripts/userspace-native-gre-validation.sh --iperf --failover --count 2
```

Important interpretation:
- `gr-0-0-0` may exist as a persistent `tun` anchor for host-originated traffic.
- Transit must stay off that device.
- Set `GRE_VALIDATE_HOST_PROBES=1` when you need to prove the host-originated handoff path.
- When `--iperf` and `GRE_VALIDATE_HOST_PROBES=1` are both set, the validator should prove host-originated GRE `iperf3` on the active firewall too.
- For the exact HA repro, use RG1 failover, not a simultaneous multi-RG move.
- UDP validation is currently a deterministic one-way burst plus path checks, not a remote `iperf3 -u` dependency.
- If the remote `iperf3` server on `10.255.192.41:5201` is down, use `--udp --traceroute` first and treat missing TCP `iperf3` as an external lab dependency, not a dataplane conclusion.

When debugging:
- Capture WAN GRE on the active firewall.
- Capture any inner traffic on `gr-0-0-0` only to prove leakage.
- Compare `iperf3` JSON-stream intervals before and after failover.
- Read `docs/userspace-native-gre-plan.md` for the validated scope and remaining gaps.
