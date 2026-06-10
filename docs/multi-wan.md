# Multi-WAN failover (services rpm + services ip-monitoring)

Status: PR-1 of the #1827 multi-WAN program (plan:
`docs/research/1827-multiwan/plan.md`). PR-1 delivers probe-driven
route failover with Junos syntax; per-policy uplink selection (FBF
composition), NAT interplay, and health-gated load-sharing are later
PRs (§5 of the plan).

xpf models multi-WAN the way real SRX does — as the composition of
existing subsystems, not an invented `services multi-wan` tree:

1. `services rpm` health probes, pinned to a specific uplink;
2. `services ip-monitoring` policies that inject preferred routes while
   the matched probe is FAILED;
3. (PR-2) filter-based forwarding for per-policy uplink selection.

## Probe configuration (PR-1a)

```
set services rpm probe WAN test wan-a probe-type icmp-ping
set services rpm probe WAN test wan-a target address 1.1.1.1
set services rpm probe WAN test wan-a destination-interface reth0.50
set services rpm probe WAN test wan-a next-hop 172.16.50.1
set services rpm probe WAN test wan-a thresholds successive-loss 3
```

- **icmp-ping is a real ICMP echo** (id/seq matched, 3 s timeout).
  Before #1827 it never sent a packet and always passed — upgrading
  makes dead-path probes start failing, which can trigger existing
  event-options policies. This is the intended fix.
- `destination-interface` pins the probe socket to the unit's device
  (`SO_BINDTODEVICE`; RETH names resolve to the local physical member).
- `next-hop` pins the probe's route with **zero transit impact**: the
  test gets a reserved per-test fwmark (0x1000+idx) + kernel table
  (7000-7049) + ip rule (priority band 50-99), and only the probe
  socket carries the mark (`SO_MARK`). Transit traffic, FRR, and the
  dataplane snapshot never see the pin. This makes "same target via
  two uplinks" the natural dual-WAN pattern. Limits: at most 50 pinned
  tests; the pinned test needs an IP-literal target of the same family
  and a `destination-interface`.
- Probe config re-applies on commit, gated on the rendered RPM stanza
  hash — unrelated commits never reset probe state.
- **Environment errors never move routes**: a probe-socket setup
  failure (e.g. CAP_NET_RAW lost) holds the test's last state and logs
  a rate-limited warning instead of marking the test FAILED, so a
  capability regression cannot inject/withdraw preferred routes
  fleet-wide. Only genuine on-the-wire failures (timeout, unreachable)
  drive ip-monitoring.

## Failover policy (PR-1b)

```
set services ip-monitoring policy wan-failover match rpm-probe WAN
set services ip-monitoring policy wan-failover then preferred-route route 0.0.0.0/0 next-hop 172.16.80.1
set services ip-monitoring policy wan-failover then preferred-route route 0.0.0.0/0 preferred-metric 10
set services ip-monitoring policy wan-failover then preferred-route routing-instance ISP-B route 0.0.0.0/0 next-hop 172.16.80.1
set services ip-monitoring policy wan-failover hold-down 5
```

Semantics (verified against Junos in the plan's research rounds):

- While **any** test of the matched probe is FAILED, the policy is FAIL
  and its preferred routes are injected; on recovery they are
  withdrawn.
- The injected route has **route preference 1** (`Static/1`) — that is
  what makes it "preferred" over static (AD 5) and DHCP (AD 200)
  routes.
- `preferred-metric` is the tie-break **among injected routes for the
  same prefix** (two policies in FAIL both injecting 0/0): lowest
  metric wins, then lexicographic policy name. The engine resolves the
  winner; FRR and the dataplane snapshot both receive exactly one
  effective route per (table, prefix).
- `hold-down <secs>` (extension; default 0 = Junos parity) damps
  recovery only — failures always act at the next debounce tick.
  **Operator guidance: set a non-zero hold-down (e.g. 5 s) on
  known-flappy links.** With hold-down 0 a sustained flapper produces
  one FRR reload + one snapshot push per throttle window (3 s)
  indefinitely — bounded, and visible as a climbing
  `xpf_ipmon_policy_transitions_total`.
- A commit while a policy is FAILED **preserves** the injected route:
  the full apply path consumes the same overlay as the failover
  actuator.
- Commit checks: the matched probe must exist; at least one
  preferred-route; destination/next-hop families must match;
  `routing-instance` must exist and must NOT be `instance-type
  forwarding` (FBF composition is PR-2).

## Observability

- `show services ip-monitoring status` (local CLI, remote CLI, gRPC).
- Prometheus: `xpf_ipmon_policy_failed{policy}`,
  `xpf_ipmon_policy_transitions_total{policy}`,
  `xpf_ipmon_routes_applied`.
- Transitions log at Info; per-probe detail at Debug.

## HA model (chassis cluster)

Primary-only probing, scoped (plan §4.4): only probes that are (a)
referenced by an ip-monitoring policy or (b) bound via
`destination-interface`/`source-address` to a VIP-owned RETH interface
are gated — they run only on the node that is primary for the data RG
(uplink addresses are VRRP VIPs; a standby probe would fail
structurally). All other RPM probes keep run-everywhere behavior.
Overlay publication follows the same gate. Known v1 coarseness: the
publication gate keys on primaryship of the LOWEST data RG only — in
a multi-data-RG cluster with split primaryship, per-policy/per-RETH
publication gating is not yet differentiated (probe gating IS
per-probe). Overlay publication gating refinement rides the later
program PRs if a split-RG deployment materializes. The overlay is
runtime state and never syncs — on takeover the new primary publishes the
config baseline, runs a fresh probe cycle, and re-derives the overlay
from fresh results (at most one fast probe cycle of config-default
routing, and only on double fault).

## v1 limitations

- **Static uplink next-hops required.** The dataplane FIB is
  config-derived and carries no DHCP-learned routes, so a
  DHCP-addressed WAN cannot carry fast-path transit without a static
  default; ip-monitoring next-hops are explicit by design. DHCP-uplink
  support is a follow-up (filed alongside PR-1b per the plan).
- `preferred-route routing-instance` into `instance-type forwarding`
  is commit-rejected until the PR-2 FBF work lands.
- Failover actuation is a differential frr-reload + one snapshot push
  per debounce window; detection time (probe interval × threshold)
  dominates end-to-end failover latency.
