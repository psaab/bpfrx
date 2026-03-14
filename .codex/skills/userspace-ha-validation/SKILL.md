---
name: userspace-ha-validation
description: Validate the isolated loss userspace HA cluster, including fallback-state checks, IPv6 router advertisements, repeated IPv4/IPv6 iperf3 runs, and optional perf capture on the active firewall.
---

# Userspace HA Validation

Use this skill when the task is to validate the isolated userspace HA cluster on
`loss`, especially after dataplane or HA changes.

Cluster inputs:
- env file: `test/incus/loss-userspace-cluster.env`
- config: `docs/ha-cluster-userspace.conf`
- script: `scripts/userspace-ha-validation.sh`
- phase cycle: `scripts/userspace-phase-cycle.sh`
- perf compare: `scripts/userspace-perf-compare.sh`

Workflow:

1. After each userspace dataplane phase, run the phase-cycle script from the repo root.
2. The phase-cycle script pushes the current branch, deploys `bpfrx-userspace-fw0/1`, and then runs the validation script.
3. Use `--perf` when the phase needs fresh `perf` profiles on whichever userspace firewall is active after deploy.
4. Treat the validator threshold as the target for the branch, not as proof that the
   current branch head already meets it.

Commands:

```bash
./scripts/userspace-phase-cycle.sh
./scripts/userspace-phase-cycle.sh --perf
./scripts/userspace-perf-compare.sh
```

What the script enforces:

- `bpfrxd` is reachable on both isolated firewalls before validation samples dataplane state
- the runtime must settle cleanly into either supported userspace forwarding or legacy fallback
- `cluster-userspace-host` is forced to keep accepting IPv6 RAs before route checks
- `cluster-userspace-host` has an IPv6 default route from RA
- if the IPv6 default route is missing, repeated `rdisc6 -1 eth0` is run before tests
- one unmeasured warm-up `iperf3` pass is run for each address family
- repeated IPv4 `iperf3` to `172.16.80.200` must stay above threshold
- repeated IPv6 `iperf3` to `2001:559:8585:80::200` must stay above threshold
- per-interval `iperf3 -J` output is parsed and a run fails if it starts fast and then collapses
- one marginal near-threshold miss is retried once before the run is treated as failed
- optional `perf` capture runs on the active userspace firewall, not a hardcoded node

Use `scripts/userspace-ha-validation.sh` directly only when you are debugging the validator itself.

Use `scripts/userspace-perf-compare.sh` when validation is failing or when you need fresh IPv4/IPv6 hotspot data without the validator's throughput gates. Read [docs/userspace-perf-compare.md](/home/ps/git/codex-bpfrx-userspace-wip/docs/userspace-perf-compare.md) for the exact artifact layout and interpretation.

The current branch reality is:

- the Rust userspace dataplane is real and deployed on the isolated `loss` userspace lab
- the validator must distinguish between intentional fallback and real userspace forwarding
- the legacy XDP dataplane is still the correctness and performance reference
- `22-23 Gbps` is the target, not the guaranteed result of every current branch head

If the script fails on IPv6 route state:

1. check `show ipv6 router-advertisement` on `bpfrx-userspace-fw0`
2. verify the running config came from `docs/ha-cluster-userspace.conf`
3. do not treat `/tmp/ha-cluster-userspace.conf` as authoritative
