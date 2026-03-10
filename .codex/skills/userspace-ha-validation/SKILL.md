---
name: userspace-ha-validation
description: Validate the isolated loss userspace HA cluster, including HA owner detection, IPv6 router advertisements, repeated IPv4/IPv6 iperf3 runs, and optional perf capture on the active userspace firewall.
---

# Userspace HA Validation

Use this skill when the task is to validate the isolated userspace HA cluster on
`loss`, especially after dataplane or HA changes.

Cluster inputs:
- env file: `test/incus/loss-userspace-cluster.env`
- config: `docs/ha-cluster-userspace.conf`
- script: `scripts/userspace-ha-validation.sh`
- phase cycle: `scripts/userspace-phase-cycle.sh`

Workflow:

1. After each userspace dataplane phase, run the phase-cycle script from the repo root.
2. The phase-cycle script pushes the current branch, deploys `bpfrx-userspace-fw0/1`, and then runs the validation script.
3. Use `--perf` when the phase needs fresh `perf` profiles on whichever userspace firewall is active after deploy.

Commands:

```bash
./scripts/userspace-phase-cycle.sh
./scripts/userspace-phase-cycle.sh --perf
```

What the script enforces:

- `bpfrxd` is reachable on both isolated firewalls before validation samples dataplane state
- the active HA owner is detected instead of assuming `fw0`
- supported userspace configs auto-arm forwarding on the active owner
- if auto-arm does not settle, the script forces one `forwarding arm` on the active owner and rechecks
- `cluster-userspace-host` has an IPv6 default route from RA
- if the IPv6 default route is missing, repeated `rdisc6 -1 eth0` is run before tests
- one unmeasured warm-up `iperf3` pass is run for each address family
- repeated IPv4 `iperf3` to `172.16.80.200` must stay above threshold
- repeated IPv6 `iperf3` to `2001:559:8585:80::200` must stay above threshold
- one marginal near-threshold miss is retried once before the run is treated as failed
- optional `perf` capture runs on the active userspace firewall, not a hardcoded node

Use `scripts/userspace-ha-validation.sh` directly only when you are debugging the validator itself.

If the script fails on IPv6 route state:

1. check `show ipv6 router-advertisement` on `bpfrx-userspace-fw0`
2. verify the running config came from `docs/ha-cluster-userspace.conf`
3. do not treat `/tmp/ha-cluster-userspace.conf` as authoritative
