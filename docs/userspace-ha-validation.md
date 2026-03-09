# Userspace HA Validation

Date: 2026-03-09

This document captures the current validation path for the isolated userspace
cluster on `loss`:

- `loss:bpfrx-userspace-fw0`
- `loss:bpfrx-userspace-fw1`
- `loss:cluster-userspace-host`

Tracked cluster env:
- [loss-userspace-cluster.env](/home/ps/git/codex-bpfrx-userspace-wip/test/incus/loss-userspace-cluster.env)

Tracked cluster config:
- [ha-cluster-userspace.conf](/home/ps/git/codex-bpfrx-userspace-wip/docs/ha-cluster-userspace.conf)

Validation script:
- [userspace-ha-validation.sh](/home/ps/git/codex-bpfrx-userspace-wip/scripts/userspace-ha-validation.sh)

Phase-cycle script:
- [userspace-phase-cycle.sh](/home/ps/git/codex-bpfrx-userspace-wip/scripts/userspace-phase-cycle.sh)

## Root Cause

The unstable `iperf3` behavior on the isolated userspace cluster had two
separate causes:

1. Unsupported userspace dataplane configs were still attaching the
   `xdp_userspace` entry program and binding AF_XDP sockets.
   - The current HA config is not supported by the Rust forwarding path yet.
   - Those configs must stay on the legacy XDP dataplane.
   - Fixed in commit `7afd67f` on branch `userspace-dataplane-rust-wip`.

2. The isolated userspace cluster was sometimes redeployed from a stale temp
   config at `/tmp/ha-cluster-userspace.conf`.
   - That older file dropped the fast router-advertisement settings for
     `reth1`.
   - Result: `cluster-userspace-host` could start a test without an IPv6
     default route.
   - The tracked repo config has the correct RA settings:
     - `default-lifetime 180`
     - `max-advertisement-interval 30`
     - `min-advertisement-interval 10`

## Current Expected State

On `bpfrx-userspace-fw0`:

- data interfaces are attached to `xdp_main_prog`, not `xdp_userspace_prog`
- `show chassis cluster data-plane statistics` includes:
  - `Forwarding supported: false`
  - `Enabled: false`
  - `Bound bindings: 0/8`

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

Optional perf capture on `bpfrx-userspace-fw0`:

```bash
./scripts/userspace-ha-validation.sh --perf
```

Standard phase workflow:

```bash
./scripts/userspace-phase-cycle.sh
./scripts/userspace-phase-cycle.sh --perf
```

This is the required sequence after each userspace dataplane phase:

1. push the current branch to GitHub
2. deploy to:
   - `loss:bpfrx-userspace-fw0`
   - `loss:bpfrx-userspace-fw1`
3. run the isolated userspace HA validation script

The script does this in order:

1. uses the tracked env file, not `/tmp`
2. checks that `fw0` is on `xdp_main_prog`
3. checks that userspace forwarding is not enabled for the unsupported HA config
4. verifies an IPv6 default route on `cluster-userspace-host`
5. if the default route is missing, runs `rdisc6 -1 eth0`
6. runs one unmeasured warm-up `iperf3` pass for IPv4 and IPv6
7. runs repeated IPv4 `iperf3` to `172.16.80.200`
8. runs repeated IPv6 `iperf3` to `2001:559:8585:80::200`
9. optionally records `perf` data on `bpfrx-userspace-fw0`

## Current Baseline

After redeploying from the tracked config and keeping unsupported configs on
the legacy dataplane:

- IPv4 `iperf3 -P 4 -t 5`: about `22.1-22.4 Gbps`
- IPv6 `iperf3 -P 4 -t 5`: about `21.9-22.2 Gbps`
- Retransmits: `0`

## Operational Rule

For the isolated userspace cluster, do not use `/tmp/bpfrx-loss-userspace.env`
or `/tmp/ha-cluster-userspace.conf` as the authoritative source of truth.

Use:

- [loss-userspace-cluster.env](/home/ps/git/codex-bpfrx-userspace-wip/test/incus/loss-userspace-cluster.env)
- [ha-cluster-userspace.conf](/home/ps/git/codex-bpfrx-userspace-wip/docs/ha-cluster-userspace.conf)
- [userspace-phase-cycle.sh](/home/ps/git/codex-bpfrx-userspace-wip/scripts/userspace-phase-cycle.sh)
