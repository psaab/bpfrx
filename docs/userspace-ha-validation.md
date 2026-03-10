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

The isolated userspace cluster is no longer a legacy-only fallback case, but it is
still an experimental branch-only environment.

Current expected behavior:
- the Rust userspace dataplane is supported on this isolated cluster
- the active HA owner should auto-arm userspace forwarding
- the standby node should keep userspace forwarding disabled
- the validator should follow the active node, not assume `fw0` stays primary

The active firewall should show:
- `Forwarding supported: true`
- `Enabled: true`
- `Forwarding armed: true`
- `Ready bindings: <non-zero>`
- `HA groups: ... rg1 active=true ...` or another active data RG

The standby firewall should show:
- `Enabled: false`
- `Forwarding armed: false`

On `cluster-userspace-host`:
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
3. determines whether the runtime is in `supported` or `legacy` mode
4. for supported mode:
   - pins the isolated validation run to the preferred active node (`node0` by default for RGs 1 and 2)
   - forces `cluster-userspace-host` to keep accepting IPv6 RAs (`accept_ra=2`)
   - waits for userspace forwarding to auto-arm on the active node
   - if auto-arm does not settle, forces `request chassis cluster data-plane userspace forwarding arm` on the active owner once
   - records the active firewall and uses it for `perf`
5. for legacy mode:
   - validates the fallback state instead of trying to arm userspace
6. verifies an IPv6 default route on `cluster-userspace-host`
7. if needed, runs repeated `rdisc6 -1 eth0` to force fresh RA convergence
8. runs one unmeasured warm-up `iperf3` pass for IPv4 and IPv6
9. runs repeated IPv4 `iperf3` to `172.16.80.200`
10. runs repeated IPv6 `iperf3` to `2001:559:8585:80::200`
11. retries one marginal near-threshold miss once
12. optionally records `perf` data on the active userspace firewall

## Target And Interpretation

Validation target for this branch:

- IPv4 `iperf3 -P 4 -t 5`: `22-23 Gbps`
- IPv6 `iperf3 -P 4 -t 5`: `22-23 Gbps`
- Retransmits: `0`

That is the target, not a guarantee of the current branch head.

Current branch reality:

- userspace forwarding is real and repeatable on the isolated lab
- the branch is still under active forwarding-correctness and performance work
- it is normal for the validator to fail while a phase is in progress
- a failing validation run is signal; do not “fix” it by lowering the threshold

Use [userspace-perf-compare.md](/home/ps/git/codex-bpfrx-userspace-wip/docs/userspace-perf-compare.md)
for the current measured numbers and current hot-path deltas. This document defines
the required workflow and the target, not the current performance claim for every
branch head.

Short-lived outliers can still happen immediately after rolling deploy while HA
ownership and RA converge. That is why the validator follows the active node,
pins the preferred validation owner, and explicitly waits for IPv6 route state.

## Preferred Active Node

The isolated userspace lab currently runs most reliably when `node0` owns the
data RGs during automated validation. The validator now enforces that as part of
the repeatable cycle instead of depending on whatever node happened to be active
after the rolling deploy.

This is controlled by:

- `PREFERRED_ACTIVE_NODE` (default `0`)
- `PREFERRED_ACTIVE_RGS` (default `1 2`)

## Operational Rule

For the isolated userspace cluster, do not use `/tmp/bpfrx-loss-userspace.env`
or `/tmp/ha-cluster-userspace.conf` as the source of truth.

Use:

- [loss-userspace-cluster.env](/home/ps/git/codex-bpfrx-userspace-wip/test/incus/loss-userspace-cluster.env)
- [ha-cluster-userspace.conf](/home/ps/git/codex-bpfrx-userspace-wip/docs/ha-cluster-userspace.conf)
- [userspace-phase-cycle.sh](/home/ps/git/codex-bpfrx-userspace-wip/scripts/userspace-phase-cycle.sh)
