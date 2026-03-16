# Userspace HA Validation

Date: 2026-03-14

This document captures the current repeatable validation path for the isolated
userspace cluster on `loss`:

- `loss:bpfrx-userspace-fw0`
- `loss:bpfrx-userspace-fw1`
- `loss:cluster-userspace-host`

Tracked inputs:
- env: [loss-userspace-cluster.env](../test/incus/loss-userspace-cluster.env)
- config: [ha-cluster-userspace.conf](../docs/ha-cluster-userspace.conf)
- validator: [userspace-ha-validation.sh](../scripts/userspace-ha-validation.sh)
- failover validator: [userspace-ha-failover-validation.sh](../scripts/userspace-ha-failover-validation.sh)
- phase cycle: [userspace-phase-cycle.sh](../scripts/userspace-phase-cycle.sh)
- perf compare: [userspace-perf-compare.sh](../scripts/userspace-perf-compare.sh)
- failover parity plan: [userspace-ha-failover-parity-plan.md](../docs/userspace-ha-failover-parity-plan.md)

## Current Model

The isolated userspace cluster is a userspace forwarding development lab. The
validation workflow has to catch two classes of failure:

- hard failures: reachability, RA/default-route, helper/runtime readiness
- soft failures: a run starts fast, then drops to near-zero after the first one or
  two seconds

On `cluster-userspace-host`, the minimum correctness bar remains:
- IPv4 reachability to `172.16.80.200`
- IPv6 reachability to `2001:559:8585:80::200`
- IPv6 default route learned from RA on `eth0`

## Repeatable Validation

Run:

```bash
./scripts/userspace-ha-validation.sh
```

Optional redeploy before test:

```bash
./scripts/userspace-ha-validation.sh --deploy
```

Optional perf capture on the active userspace firewall:

```bash
./scripts/userspace-ha-validation.sh --perf
```

Perf-only compare workflow:

```bash
./scripts/userspace-perf-compare.sh
```

Dedicated RG failover survivability workflow:

```bash
./scripts/userspace-ha-failover-validation.sh
```

Standard phase workflow:

```bash
./scripts/userspace-phase-cycle.sh
./scripts/userspace-phase-cycle.sh --perf
```

This is the required sequence after each userspace dataplane phase:

1. commit the phase
2. push the current branch to GitHub
3. deploy to:
   - `loss:bpfrx-userspace-fw0`
   - `loss:bpfrx-userspace-fw1`
4. run the isolated userspace HA validation script

For failover-specific HA/session work, also run the dedicated RG failover
validator. The steady-state validator is not enough to prove that an existing
TCP flow survives a manual RG ownership move.

If the validation script is failing and you still need current performance data,
run the perf-compare workflow next. It captures IPv4/IPv6 `iperf3` and `perf`
artifacts without treating current tree instability as a hard blocker.

## What The Validator Enforces

The validator does this in order:

1. uses the tracked env/config in the repo, not `/tmp`
2. waits for CLI availability on both firewalls
3. checks whether the runtime settled into supported userspace forwarding or legacy fallback
4. forces `cluster-userspace-host` to keep accepting IPv6 RAs (`accept_ra=2`)
5. verifies an IPv6 default route on `cluster-userspace-host`
6. if needed, runs repeated `rdisc6 -1 eth0` to force fresh RA convergence
7. derives the active WAN test interface from the current primary node's route table
8. runs deterministic TTL-expired probes to:
   - IPv4 `1.1.1.1`
   - IPv6 `2607:f8b0:4005:814::200e`
   - the validator treats `ping` exit status `1` as expected for these probes
     when the returned output contains the native time-exceeded response
9. records one-cycle `mtr` reports to those same public IPv4/IPv6 targets
10. fails if the first hop is unresolved or the destination hop is unresolved
11. runs one unmeasured warm-up `iperf3` pass for IPv4 and IPv6
12. runs repeated IPv4 `iperf3` to `172.16.80.200`
13. runs repeated IPv6 `iperf3` to `2001:559:8585:80::200`
14. pulls `iperf3 -J` JSON back to the repo host, parses it locally, and fails
    if throughput cliffs after startup
15. retries one marginal near-threshold miss once
16. optionally records `perf` data on the active firewall

## Target And Interpretation

Validation target for the active userspace forwarding path:

- IPv4 `iperf3 -P 4 -t 5`: `22-23 Gbps`
- IPv6 `iperf3 -P 4 -t 5`: `22-23 Gbps`
- Retransmits: `0`
- Sustained transfer: no “fast first second, then collapse to 0 bps” interval pattern

That is the target, not a guarantee of the current tree state.

Current `master` reality:

- the isolated HA lab is used for both active userspace-forwarding work and
  safe fallback verification, depending on the active config and runtime gate
- the validator must therefore first determine whether the node settled into:
  - active userspace forwarding, or
  - legacy eBPF fallback
- the tree is still under active forwarding-correctness and performance work on
  the AF_XDP fast path
- it is normal for the validator to fail while a phase is in progress
- a failing validation run is signal; do not “fix” it by lowering the threshold

Use [userspace-perf-compare.md](../docs/userspace-perf-compare.md)
for the current measured numbers and current hot-path deltas. This document defines
the required workflow and the target, not the current performance claim for every
tree state.

The validator now treats interval collapse as a separate failure mode from average
Gbps. A run that peaks high and then drops near zero is a failure even if the short
overall average still looks superficially acceptable.

The validator also treats traceroute visibility as a standard correctness gate.
It does not require every internet hop to answer. It does require:

- the firewall hop to answer TTL-expired probes
- the final destination hop in `mtr` to resolve for both:
  - `1.1.1.1`
  - `2607:f8b0:4005:814::200e`

For the TTL / hop-limit probes, a non-zero `ping` exit code is not itself a
failure. The validator accepts the probe when the returned output contains the
expected native time-exceeded text from the userspace firewall.

Artifacts kept on `cluster-userspace-host`:

- `/tmp/userspace-ttl-v4.txt`
- `/tmp/userspace-ttl-v6.txt`
- `/tmp/userspace-mtr-v4.txt`
- `/tmp/userspace-mtr-v6.txt`
- `/tmp/ipv4-*.json`
- `/tmp/ipv6-*.json`

The `cluster-userspace-host` only needs the runtime tools used to generate the
artifacts:

- `ping`
- `mtr`
- `iperf3`

The interval-collapse analysis runs on the repo host using
[iperf-json-metrics.py](../scripts/iperf-json-metrics.py),
so the cluster test host does not need `python3`.

Short-lived outliers can still happen immediately after rolling deploy while HA
ownership and RA converge. That is why the validator explicitly waits for IPv6
route state before throughput checks.

## Operational Rule

For the isolated userspace cluster, do not use `/tmp` cluster env/config files
as the source of truth.

Use:

- [loss-userspace-cluster.env](../test/incus/loss-userspace-cluster.env)
- [ha-cluster-userspace.conf](../docs/ha-cluster-userspace.conf)
- [userspace-phase-cycle.sh](../scripts/userspace-phase-cycle.sh)
