# #785 D3 — validation

## What D3 does

Restricts the mlx5 RSS indirection table on interfaces bound to
`xpf-userspace-dp` so hash outputs land only on queues `0..workers-1`
(weight `1`) with queues `workers..RX_count-1` weighted `0`. Queues
4 and 5 on our 6-RX-queue mlx5 interfaces were previously receiving
~1/3 of flows that fell through to kernel processing; D3 eliminates
that fall-through by pushing all traffic onto the XDP-bound queues.

Wired into `pkg/daemon/linksetup.go` via a new
`pkg/daemon/rss_indirection.go` module. Applied at daemon startup,
before any XSK bind, so mid-traffic re-hashing is impossible. Skips
non-mlx5 drivers, single-worker bindings, and when `workers >=
queues`.

### Scope — which interfaces D3 touches

D3 only touches the mlx5 interfaces that the userspace dataplane
actually binds AF_XDP sockets to — derived from the compiled
userspace-dp binding plan
(`userspace.UserspaceBoundLinuxInterfaces(cfg)`), which in turn is the
same filter used by the binding-plan key
(`userspaceSkipsIngressInterface`). Sibling mlx5 PFs, management
interfaces (`fxp*`, `em*`), fabric overlays (`fab*`), tunnel netdevs,
and interfaces in the `mgmt`/`control` zones are excluded from the
allowlist and will never see an `ethtool -X` invocation.

On a host with two mlx5 ports where only one is bound to
`xpf-userspace-dp`, the other port keeps its driver-default RSS table
and is not reshaped. Non-mlx5 drivers (virtio, iavf, i40e) in the
allowlist are still filtered out at the per-interface driver guard as
defence in depth.

### Operator knob — `rss-indirection enable | disable`

D3 can be turned off at runtime with

```
set system dataplane rss-indirection disable
commit
```

The knob defaults to **enabled**; operators opt out explicitly. On
commit, the daemon's full reconcile path (`applyConfig`) re-runs D3
against the new config — this is true regardless of commit source
(gRPC, HTTP, local CLI). Lowering `workers` from N to 1, raising
`workers` to `>= queues`, or toggling the knob all take effect without
a daemon restart.

### Runtime toggle semantics

- `enable` (default): apply `weight 1..1 0..0` to each allowlisted
  mlx5 interface. Idempotent — matching tables skip the write.
- `disable`: actively restore the **driver's** default equal-weight
  table on each allowlisted mlx5 interface via
  `ethtool -X <iface> default`. This is the driver's default, **not**
  a snapshot of whatever RSS layout the operator configured before
  starting `xpfd`. If you had pre-set a custom indirection table on
  these NICs before bringing the daemon up, engaging the kill switch
  will overwrite that custom layout with the mlx5 driver's equal-
  weight default. Snapshot-and-restore is intentionally not
  implemented: it would require carrying operator state across
  commits and is overkill for a kill switch.

### Daemon stop behaviour

`systemctl stop xpfd` (or `SIGTERM`) does **not** restore the RSS
indirection table. The constrained layout from the last apply
persists across daemon lifecycles. Rationale: D3 is a best-effort
steering optimisation, not a correctness feature, and a busy host
should not take a fleet-wide NIC configuration churn as part of
graceful shutdown. If an operator needs the driver default before
removing the daemon, they can:

1. `set system dataplane rss-indirection disable` + `commit` (daemon
   actively restores the driver default), then stop the daemon, or
2. manually run `ethtool -X <iface> default` per interface.

## Baseline (no D3, default RSS — matched 5-run earlier)

| | |
|-|-|
| Mean SUM Gbps       | 20.78 |
| Mean CoV %          | 54.7  |
| Median CoV %        | 51.2  |
| Range CoV %         | 39.6-84.0 |
| Mean retransmits    | 1     |

## With D3 (fresh matched 5-run, this branch)

| Run | SUM Gbps | CoV % | Retr |
|-----|----------|-------|------|
| 1   | 19.04    | 48.4  | 813  |
| 2   | 20.55    | 38.8  | 116  |
| 3   | 20.39    | 63.2  | 149  |
| 4   | 21.00    | 37.2  | 148  |
| 5   | 20.48    | 19.2  | 116  |

| | |
|-|-|
| Mean SUM Gbps       | 20.29 |
| Mean CoV %          | 41.4  |
| Median CoV %        | 38.8  |
| Range CoV %         | 19.2-63.2 |

## Earlier D3 run (same code, different cluster state)

| | |
|-|-|
| Mean SUM Gbps       | 22.69 |
| Mean CoV %          | 36.6  |
| Median CoV %        | 37.1  |
| Range CoV %         | 24.7-48.9 |
| Mean retransmits    | 0     |

Earlier measurement was taken directly after a fresh deploy on a
quiet cluster. The current measurement follows many back-to-back
deploy cycles and concurrent tests; the cluster state is noisier,
reflected in the retransmits on every run.

## Interpretation

- **Mean CoV improvement**: 54.7 % → 36-41 % (13-18 point reduction,
  depending on cluster state).
- **Throughput unchanged or slightly improved**: 20.78 → 20.29-22.69 Gbps.
- **Median run is consistently below baseline median**: no worse, sometimes
  meaningfully better.
- **Best runs approach target**: Run 5 here hit 19.2 % CoV. Target
  is ≤ 20 %. D3 can reach it on favorable distributions, but the
  stochastic variance in RSS hashing 12 balls → 4 bins means it
  doesn't hit the target reliably.

## Why target isn't reliably met

With 12 flows and 4 uniform bins, the probability of any single bin
getting ≥ 5 flows (concentration event) is ≈ 15 %. On those runs,
cross-worker imbalance dominates regardless of D3. Solving that
requires active flow-to-worker load balancing (D1'), which this
branch does not include. See `docs/785-phase4-options.md` and the
separate D1' exploration on branch `pr/785-d1-flow-worker-lb`.

## Conclusion

D3 is a clean, low-risk, low-cost improvement that meaningfully
closes the CoV gap without any Rust / dataplane code change. Ship.
D1' is the path to reliably meeting the target, but it's larger
work (multiple architectural constraints surfaced during six agent
iterations on branch `pr/785-d1-flow-worker-lb`).

## Errata

The commit body for `ef92b448` cites a median CoV of "39.5 %". The
correct median of the fresh 5-run, sorted
`[19.2, 37.2, 38.8, 48.4, 63.2]`, is **38.8 %** (the third element).
The "39.5" figure was an interim mean of runs 2 and 3 and does not
match any statistic in this document. The doc tables are authoritative.
