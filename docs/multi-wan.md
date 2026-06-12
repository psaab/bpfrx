# Multi-WAN failover (services rpm + services ip-monitoring)

Status: the #1827 multi-WAN program is COMPLETE at PR-1 + PR-2 + PR-3
(plan: `docs/research/1827-multiwan/plan.md`). PR-1 delivers
probe-driven route failover with Junos syntax; PR-2 adds per-policy
uplink selection (FBF composition); PR-3 defines the NAT interplay
(per-uplink SNAT pools via existing matchers + session-transition
semantics, mini-plan: `docs/pr/1827-pr3-nat/plan.md`). The PR-4
weights/load-share stage was KILLED by its own research-gate criteria
(audit of record: `docs/research/1827-pr4-loadshare/plan.md` on the
`research/1827-pr4-loadshare` branch): the userspace dataplane has no
ECMP next-hop selection to weight — the FIB flattens multi-next-hop
routes to the first entry at build time — so any per-flow load-share
(weighted or equal-cost) would be a new Rust hot-path program with new
cross-node hash-symmetry invariants, unjustified at 2 uplinks given
the FBF steering recipe below. Equal-cost or weighted per-flow
load-balance parity remains unimplemented; if demand materializes it
is its own issue with its own value case — it is not a multi-WAN
failover deliverable.

xpf models multi-WAN the way real SRX does — as the composition of
existing subsystems, not an invented `services multi-wan` tree:

1. `services rpm` health probes, pinned to a specific uplink;
2. `services ip-monitoring` policies that inject preferred routes while
   the matched probe is FAILED;
3. filter-based forwarding (FBF) for per-policy uplink selection
   (PR-2, below).

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
- **Pin install failures hold state too (#1895)**: when a pin's kernel
  programming fails (missing egress link at boot, rule/route add
  error), the test does NOT probe — an unbacked `SO_MARK` would fall
  through to the main table and report the *default* path's health as
  the pinned uplink's (false PASS, failover suppression). The test
  holds its prior state exactly like other setup errors, a partial
  install is rolled back (no rule without its route), and the daemon
  retries the pin install on any subsequent commit or RG transition
  while it stays failed. Observability: rate-limited probe-loop
  warning, per-pin install warnings, and the
  `xpf_rpm_probe_pin_install_failures` gauge (nonzero = those uplinks
  are not being health-checked).

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
  preferred-route; destination/next-hop families must match; a
  `routing-instance` target must exist (PR-2 lifted the PR-1b
  rejection of `instance-type forwarding` targets — see the FBF
  section below).

## Per-policy uplink selection — FBF composition (PR-2)

Filter-based forwarding steers a CLASS of traffic onto a specific
uplink regardless of the master routing table, using an
`instance-type forwarding` routing instance — exactly the Junos FBF
pattern. Operator recipe (two uplinks, ISP-A = master default via
`reth0.50`, ISP-B = `reth0.80`):

```
# 1. Forwarding instance for the alternate uplink. No VRF device, no
#    interfaces — just a routing table.
set routing-instances ISP-B instance-type forwarding
set routing-instances ISP-B routing-options static route 0.0.0.0/0 next-hop 172.16.80.1
set routing-instances ISP-B routing-options rib ISP-B.inet6.0 static route ::/0 next-hop 2001:db8:80::1

# 2. Steering filter on the LAN ingress. `then count` gives the
#    per-policy counter operators use to verify steering.
set firewall family inet filter fbf-steer term to-isp-b from dscp af31
set firewall family inet filter fbf-steer term to-isp-b then count fbf-isp-b
set firewall family inet filter fbf-steer term to-isp-b then routing-instance ISP-B
set firewall family inet filter fbf-steer term default then accept
set interfaces reth1 unit 0 family inet filter input fbf-steer

# 3. Health-gate the steered path: while the ISP-B gateway probe is
#    FAILED, repoint ISP-B's default at the ISP-A gateway (distance 1)
#    so steered traffic falls back instead of blackholing.
set services rpm probe FBF-ISP-B test gw probe-type icmp-ping
set services rpm probe FBF-ISP-B test gw target address 172.16.80.1
set services rpm probe FBF-ISP-B test gw destination-interface reth0.80
set services ip-monitoring policy fbf-fallback match rpm-probe FBF-ISP-B
set services ip-monitoring policy fbf-fallback then preferred-route routing-instance ISP-B route 0.0.0.0/0 next-hop 172.16.50.1
set services ip-monitoring policy fbf-fallback hold-down 5
```

How it lands (the `instance-type forwarding` divergence fix):

- **FRR/kernel**: forwarding-instance statics render with a trailing
  `table <id>` (the instance's auto-assigned kernel table, IDs from
  100) instead of a `vrf` qualifier — there is no VRF device to bind.
  Before PR-2 these statics leaked into the DEFAULT table (polluting
  master routing) and the instance's kernel table stayed empty, so
  kernel-path FBF silently no-opped while the dataplane steered.
- **Kernel steering**: the existing PBR machinery emits `ip rule`s
  (priority band 31000+) matching the term's DSCP/addresses into the
  instance's table — now populated, so the kernel slow path agrees
  with the fast path.
- **Dataplane**: filter evaluation returns the term's
  routing-instance; the route lookup targets `ISP-B.inet.0` /
  `ISP-B.inet6.0`, where the snapshot builder files the instance's
  statics (no instance-type branch — this predates PR-2). Next-hop
  egress resolves against global connected prefixes.
- **ip-monitoring into FBF instances**: a `preferred-route
  routing-instance <fbf>` entry renders as a distance-1 static in the
  instance's kernel table and replaces the matching
  (table, family, prefix) snapshot entry — same whole-entry
  replacement rule as virtual-router targets.

Per-policy counters: `then count <name>` on the steering term is
counted on the PBR fast path and exported as
`xpf_filter_hits_total{filter,family,term}` — the steering-volume
counter per FBF policy.

### Two-upstream lab (test/incus)

`test/incus/fbf-two-upstream-config.set` layers the recipe above onto
the loss userspace cluster baseline (`docs/ha-cluster-userspace.conf`),
using the two WAN VLANs as distinguishable egress paths: ISP-A =
`reth0.50` (gw 172.16.50.1, baseline master default), ISP-B =
`reth0.80` (gw 172.16.80.1 / 2001:559:8585:80::1, FBF instance).
`test/incus/test-fbf-steering.sh` applies it atomically (commit check
→ commit → validate → rollback), then asserts: the ISP-B kernel table
(discovered via the 31000+ PBR rule band) holds the instance default;
the main table is not polluted; DSCP-af31 pings from the LAN host move
the `fbf-steer`/`to-isp-b` hit counter while unmarked control pings do
not; and `show services ip-monitoring status` lists `fbf-fallback`.
Override `FBF_ISP_B_GW4` when 172.16.80.1 is not a live router in the
target environment. Uplink-failure path divergence (blackhole the
ISP-B gateway upstream, watch `fbf-fallback` repoint `ISP-B.inet.0`)
remains a manual smoke step — the harness cannot mutate the provider
side.

## NAT interplay (PR-3)

### Per-uplink SNAT pools — existing matchers suffice

No new NAT matcher exists or is needed. SNAT rule-set selection keys
on the zone pair, and the **to-zone of every new flow is derived from
its resolved egress interface** (the session-miss path resolves the
route first, then maps `resolution.egress_ifindex` to the zone pair
fed into source-NAT matching). When ip-monitoring flips the preferred
route — or an FBF term steers a flow into an uplink's
routing-instance — new flows resolve onto the other uplink's
interface, the to-zone follows, and that uplink's rule-set/pool is
chosen automatically.

Recommended recipe — one zone, one rule-set, one pool per uplink:

```
set security zones security-zone untrust-a interfaces reth0.50
set security zones security-zone untrust-b interfaces reth0.80
set security nat source pool isp-a-pool address 203.0.113.10/32
set security nat source pool isp-b-pool address 198.51.100.10/32
set security nat source rule-set to-isp-a from zone trust
set security nat source rule-set to-isp-a to zone untrust-a
set security nat source rule-set to-isp-a rule snat-a match source-address 10.0.0.0/8
set security nat source rule-set to-isp-a rule snat-a then source-nat pool isp-a-pool
set security nat source rule-set to-isp-b from zone trust
set security nat source rule-set to-isp-b to zone untrust-b
set security nat source rule-set to-isp-b rule snat-b match source-address 10.0.0.0/8
set security nat source rule-set to-isp-b rule snat-b then source-nat pool isp-b-pool
```

Alternative: `then source-nat interface` translates to the resolved
egress interface's primary address — per-uplink by construction, even
when both uplinks share one zone.

Limitation (documented, not built): Junos additionally allows source
NAT rule-sets scoped `to interface <if>` / `to routing-instance <ri>`;
xpf rule-sets carry from-zone/to-zone only. Pool-mode SNAT with BOTH
uplinks in a single shared zone therefore has no per-uplink rule-set
discriminator — use zone-per-uplink (above) or interface SNAT.

### Session behavior on uplink transition

What happens to ESTABLISHED sessions when ip-monitoring fails over:

1. The actuator publishes the overlay snapshot, then bumps the FIB
   generation (order is load-bearing, PR-1b).
2. The bump invalidates per-worker flow-cache entries; the session
   table is untouched. On the next packet, a **locally-created**
   session's stored forwarding resolution is reused in preference to a
   fresh FIB lookup (`cached_session_resolution` on the session-hit
   path), so the flow cache re-fills with the OLD egress under the new
   generation.
3. ⇒ Established locally-created sessions stay **pinned to the failed
   uplink entirely** — old egress interface, old neighbor, and the
   immutable NAT binding. Their traffic keeps leaving the dead path
   and blackholes until the inactivity timeout or an operator clear.
   New flows resolve via the injected route and are correct
   immediately. (Two exceptions DO move onto the injected route:
   peer-synced sessions, which resolve lookup-first; and tunnel-backed
   sessions, whose OUTER path re-resolves before the stored-resolution
   fast path. The pinning above is the ordinary direct-uplink case the
   SNAT recipes produce.)

This is Junos parity in substance: SRX likewise does not re-route or
re-NAT established sessions on a route change by default. Junos
ip-monitoring has no session-clear action, and neither does xpf's
(deliberately — a flapping probe must never mass-clear healthy
sessions). The operator clear below is therefore THE mechanism for
moving established flows to the surviving uplink. The operator
decides:

- **Do nothing** — pinned sessions age out at their inactivity
  timeout; new flows are correct immediately.
- **Clear by pool** (Junos 23.4R1 syntax):

  ```
  show services ip-monitoring status                              # confirm FAIL + applied routes
  show security flow session source-nat-pool isp-a-pool           # list pinned sessions
  clear security flow session source-nat-pool isp-a-pool          # release them
  ```

  (The clear prints per-family cleared counts. In the local CLI,
  `... source-nat-pool isp-a-pool summary` gives a filtered count;
  the remote CLI's `summary` keyword shows the unfiltered table
  summary — a pre-existing remote-CLI behavior for all filters.)

  Cleared flows re-establish via the surviving uplink and match the
  new egress zone's rule-set/pool. The filter matches sessions whose
  TRANSLATED source lies in the named pool's address set (SNAT
  sessions only; pre-NAT tuples never match). An unknown pool name is
  a command error — never an empty (clear-all) filter. On an HA pair
  the filtered clear is forwarded to the peer with the SAME filter.
  Interface-mode SNAT bindings are not pool-named; clear those by
  uplink zone (`clear security flow session zone untrust-a`) instead.

Pool overlap caveat: membership is by translated address. If two
source pools overlap (itself a misconfiguration), a pool-filtered
clear can match sessions allocated from the other pool.

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

- **DHCP-tracked next-hops (#1844, shipped).** A preferred-route
  next-hop may name a DHCP interface unit instead of a literal IP:

  ```
  set services ip-monitoring policy wan-failover then preferred-route route 0.0.0.0/0 next-hop ge-0/0/3.0
  ```

  The named unit must be configured with `family inet dhcp` (Junos
  configured name, `<ifd>.<unit>`; v4 destinations only; management
  interfaces rejected). The injected route then tracks the unit's
  DHCP-learned gateway: the ipmon engine resolves it at every overlay
  computation, and lease events (first lease, gateway change on
  renewal, lease-record removal) re-actuate through the routes-only
  actuator. While the unit has no lease/gateway, the candidate is
  skipped BEFORE winner selection — a resolvable losing candidate for
  the same prefix wins instead — and surfaces in `show services
  ip-monitoring status` plus the `xpf_ipmon_unresolved_next_hops`
  gauge. During a DHCP re-acquisition window (T2 rebind failed, fresh
  DORA in progress) the last-known gateway is kept — deliberate parity
  with the AD-200 FRR DHCP default route in the same window. A manual
  `request dhcp client renew` removes the lease record first, so an
  active failover route is withdrawn and re-injected once the new
  lease lands.
- **DHCP uplink as PRIMARY fast-path uplink still needs a static
  default.** The dataplane FIB baseline is config-derived and carries
  no DHCP-learned routes; #1844 makes a DHCP uplink usable as the
  *failover target* (the overlay carries the resolved next-hop into
  both FRR and the snapshot), not as the primary fast-path uplink
  without a static default.
- Failover actuation is a differential frr-reload + one snapshot push
  per debounce window; detection time (probe interval × threshold)
  dominates end-to-end failover latency.
