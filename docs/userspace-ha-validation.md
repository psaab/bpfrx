# Userspace HA Validation

Date: 2026-03-09

This document captures the current repeatable validation path for the isolated
userspace cluster on `loss`:

- `loss:bpfrx-userspace-fw0`
- `loss:bpfrx-userspace-fw1`
- `loss:cluster-userspace-host`

Tracked inputs:
- env: [loss-userspace-cluster.env](/home/ps/git/codex-bpfrx-userspace-wip/test/incus/loss-userspace-cluster.env)
- config: [ha-cluster-userspace.conf](/home/ps/git/codex-bpfrx-userspace-wip/docs/ha-cluster-userspace.conf)
- validator: [userspace-ha-validation.sh](/home/ps/git/codex-bpfrx-userspace-wip/scripts/userspace-ha-validation.sh)
- phase cycle: [userspace-phase-cycle.sh](/home/ps/git/codex-bpfrx-userspace-wip/scripts/userspace-phase-cycle.sh)
- perf compare: [userspace-perf-compare.sh](/home/ps/git/codex-bpfrx-userspace-wip/scripts/userspace-perf-compare.sh)

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

If the validation script is failing and you still need current performance data,
run the perf-compare workflow next. It captures IPv4/IPv6 `iperf3` and `perf`
artifacts without treating the current branch instability as a hard blocker.

## What The Validator Enforces

The validator does this in order:

1. uses the tracked env/config in the repo, not `/tmp`
2. waits for CLI availability on both firewalls
3. checks whether the runtime settled into supported userspace forwarding or legacy fallback
4. forces `cluster-userspace-host` to keep accepting IPv6 RAs (`accept_ra=2`)
5. verifies an IPv6 default route on `cluster-userspace-host`
6. if needed, runs repeated `rdisc6 -1 eth0` to force fresh RA convergence
7. runs one unmeasured warm-up `iperf3` pass for IPv4 and IPv6
8. runs repeated IPv4 `iperf3` to `172.16.80.200`
9. runs repeated IPv6 `iperf3` to `2001:559:8585:80::200`
10. parses per-interval `iperf3 -J` output and fails if throughput cliffs after startup
11. retries one marginal near-threshold miss once
12. optionally records `perf` data on the active firewall

## Target And Interpretation

Validation target for this branch:

- IPv4 `iperf3 -P 4 -t 5`: `22-23 Gbps`
- IPv6 `iperf3 -P 4 -t 5`: `22-23 Gbps`
- Retransmits: `0`
- Sustained transfer: no “fast first second, then collapse to 0 bps” interval pattern

That is the target, not a guarantee of the current branch head.

Current branch reality:

- the isolated HA/fabric lab currently validates the safe fallback path, not Rust
  userspace forwarding for real traffic
- the branch is still under active forwarding-correctness and performance work on
  supported userspace-forwarding paths
- it is normal for the validator to fail while a phase is in progress
- a failing validation run is signal; do not “fix” it by lowering the threshold

Use [userspace-perf-compare.md](/home/ps/git/codex-bpfrx-userspace-wip/docs/userspace-perf-compare.md)
for the current measured numbers and current hot-path deltas. This document defines
the required workflow and the target, not the current performance claim for every
branch head.

The validator now treats interval collapse as a separate failure mode from average
Gbps. A run that peaks high and then drops near zero is a failure even if the short
overall average still looks superficially acceptable.

Short-lived outliers can still happen immediately after rolling deploy while HA
ownership and RA converge. That is why the validator explicitly waits for IPv6
route state before throughput checks.

## Operational Rule

For the isolated userspace cluster, do not use `/tmp/bpfrx-loss-userspace.env`
or `/tmp/ha-cluster-userspace.conf` as the source of truth.

Use:

- [loss-userspace-cluster.env](/home/ps/git/codex-bpfrx-userspace-wip/test/incus/loss-userspace-cluster.env)
- [ha-cluster-userspace.conf](/home/ps/git/codex-bpfrx-userspace-wip/docs/ha-cluster-userspace.conf)
- [userspace-phase-cycle.sh](/home/ps/git/codex-bpfrx-userspace-wip/scripts/userspace-phase-cycle.sh)
