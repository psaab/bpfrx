# Multi-WAN failover (services rpm + services ip-monitoring)

Status: the #1827 multi-WAN program is COMPLETE at PR-1 + PR-2 + PR-3
(plan: `docs/research/1827-multiwan/plan.md`). PR-1 delivers
probe-driven route failover with Junos syntax; PR-2 adds per-policy
uplink selection (FBF composition); PR-3 defines the NAT interplay
(per-uplink SNAT pools via existing matchers + session-transition
semantics, mini-plan: `docs/pr/1827-pr3-nat/plan.md`). The PR-4
weights/load-share stage was KILLED by its own research-gate criteria
(audit of record: `docs/research/1827-pr4-loadshare/plan.md` on the
`research/1827-pr4-loadshare` branch): at the time, the userspace
dataplane had no ECMP next-hop selection to weight — the FIB flattened
multi-next-hop routes to the first entry at build time. That premise has
since shifted: #2389 retained the full equal-cost candidate vector
(`Vec<RouteNextHopV4>`) with dead-NH fallback, and **#2734 added
EQUAL-COST per-FLOW selection** — the session resolution path hashes the
forward 5-tuple (the per-boot seeded `ecmp_hash_flow`) to pick a member,
so distinct flows spread across equal-cost uplinks while a single flow
stays pinned (flow-consistent). The seed is node-local (ECMP picks among
THIS node's members, not wire/HA state), so there are no cross-node
hash-symmetry invariants to maintain. **WEIGHTED** per-flow load-share
(unequal-cost ratios) remains unimplemented; if demand materializes it is
its own issue with its own value case — it is not a multi-WAN failover
deliverable.

**#2922 — single liveness snapshot in `select_route_next_hop`.** The
equal-cost member picker (`select_route_next_hop`,
`userspace-dp/src/afxdp/forwarding/mod.rs`) now evaluates the liveness
predicate exactly ONCE per candidate. The predicate probes the shared
dynamic-neighbor map, which the neighbor-monitor thread mutates
concurrently, so it is not pure. The old two-pass form (`count()` the live
members, then `nth()` to select) ran the predicate twice and a neighbor
removed between the passes made the count see `live > 0` while the select
pass yielded `None` → a spurious no-route despite a live member existing at
count time, plus doubled hot-path neighbor probes. The picker now collects
the live candidate references into a stack `SmallVec` in one pass and
indexes into that materialized snapshot, so count and selection always
agree. Selection semantics are unchanged: `ip_hash % live_count` over the
live set in candidate order (flow-pinned), with the hashed full-vector
fallback when no member is live.

**#2923 — type-aware ECMP candidate liveness (direct vs tunnel).** The
liveness predicate `select_route_next_hop` evaluates was written for direct
next-hops only: a candidate is live iff `ifindex > 0` AND the destination
resolves to a neighbor entry on that ifindex. A TUNNEL next-hop (a route
next-hop pointing at a GRE/WireGuard/IPIP tunnel interface, carrying a
non-zero `tunnel_endpoint_id`) is the LOGICAL tunnel ifindex and has no
neighbor for the inner destination, so it always failed that gate. In a
MIXED direct+tunnel ECMP group a live direct member made `live > 0`, which
restricted selection to the direct members and STARVED the tunnel path —
the tunnel endpoint was never selected even when its underlay was fully up.
(A tunnel-only group still worked: with `live == 0` the fallback picks from
all candidates.) The picker now branches on `tunnel_endpoint_id`: a tunnel
candidate is live when its endpoint resolves a usable OUTER underlay
(`resolve_tunnel_outer` — endpoint present, outer not local-delivery, outer
not a tunnel-interface recursion loop), the same SSOT selection later uses
in `resolve_tunnel_forwarding_resolution`, so a candidate marked live here
never blackholes on selection. Direct-hop liveness is unchanged. This
restores full equal-cost participation for multi-WAN and route-leak designs
that mix a physical uplink with a tunnel transport.

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
- `source-address` selects the probe's source IP (the dialer's
  `LocalAddr`). It is validated at commit (#2492): a non-empty but
  unparseable `source-address` is **rejected** on the strict commit /
  commit-check path — a malformed value would otherwise `net.ParseIP`
  to nil and silently degrade the tcp-ping/http-get probe to a
  wildcard/kernel-chosen source bind, so the probe would measure the
  **default** uplink instead of the source-specific path and publish
  PASS/FAIL for the wrong uplink. When the target is an IP literal the
  `source-address` family must match it (a v6 source cannot bind a v4
  target connection); a hostname target skips the family check (its
  family is unknown until DNS resolves). An **empty** `source-address`
  is legitimate — it means "default source". On the tolerant load /
  peer-sync path the same malformed value is downgraded to a warning so
  a persisted/peer-synced config still boots (#1960 no-brick); the
  runtime dialer guard then returns the same setup error, so the test
  holds state (below) rather than measuring the wrong path.
- **Scoped tests resolve their hostname in-scope (#2493 → #2614).** A
  *scoped* test — one with `routing-instance`, `destination-interface`,
  or `next-hop` set — binds its probe **data** socket to a specific VRF /
  egress device (`SO_BINDTODEVICE`) or path (`SO_MARK`). Originally
  (#2493) a **hostname** target on a scoped test was *rejected at commit*
  because hostname resolution ran through the process-default resolver
  (the data-socket bind is applied in the per-connection `Control` hook,
  which fires **after** name resolution), so DNS escaped the configured
  scope — with split-horizon / per-WAN DNS the probe measured resolver
  context, not path health.
  - **#2614 lifts that restriction with a VRF-bound resolver.** The
    runtime now resolves a scoped hostname **inside the probe's
    VRF/path scope**: it builds a `net.Resolver{PreferGo: true}` whose
    `Dial` applies the *same* `applyVRFBind` (`SO_BINDTODEVICE` +
    `SO_MARK`) the probe data socket uses, so the DNS query egresses the
    VRF and hits the VRF's DNS servers. icmp-ping resolves through
    `rpm.resolveProbeTarget(target, opts)`; tcp-ping / http-get set the
    dialer's `Resolver` (`probeDialer.Resolver = vrfBoundResolver(opts)`)
    so the dialer's own name lookup is bound too. (Since #2647
    `resolveProbeTarget(ctx, target, opts)` threads the probe-cycle
    context into the lookup — see the cancellation note below.) A hostname inside an
    isolated VRF therefore resolves correctly instead of through the
    main table / default DNS (or failing when DNS is reachable only
    inside the VRF). `applyVRFBind` is the single source of truth for the
    pin, shared by the data socket and the DNS socket.
  - The **#2493 commit gate (`validateRPMScopedHostnameStrict`) is
    removed** — a scoped hostname is now a legitimate configuration on
    both the strict and tolerant paths. An **IP-literal** target on a
    scoped test still short-circuits DNS entirely (no resolver consulted),
    and a hostname on an **unscoped** test uses the process-default
    resolver unchanged. `PreferGo` is required: the cgo resolver path
    ignores the `Dial` hook, so the bind would be silently dropped.
  - *Lab-bound verify.* The end-to-end "scoped hostname resolves through
    VRF DNS" path needs a multi-VRF DNS lab; the gate in CI is the
    construction/seam test (`pkg/rpm`
    `TestVRFBoundResolverIsBuiltForScope` /
    `TestScopedHostnameResolvesInScope`): a scoped probe gets a bound
    (`PreferGo` + `Dial`) resolver and the probe's `BindDevice`/`Mark`
    reach the resolver, while an unscoped probe keeps the default
    resolver. Reverting to the unbound `net.ResolveIPAddr` path turns
    those tests red.
  - **Resolution honors the probe-cycle context (#2647).** Hostname
    resolution for an icmp-ping target now runs under the probe ctx:
    `resolveProbeTarget(ctx, target, opts)` passes that ctx to the
    resolver's `LookupIPAddr(ctx, target)` (and, for a VRF-bound
    resolver, on into its `Dial`). A stuck DNS query therefore aborts on
    the cycle's cancellation/deadline (config reload, service stop)
    instead of running under `context.Background()` and outliving the
    cycle — matching the ctx-bound tcp-ping `DialContext(ctx, …)` and
    http-get `NewRequestWithContext`. An IP-literal target returns before
    the lookup, so the ctx never gates it. Gate in CI:
    `pkg/rpm/TestResolveProbeTargetHonorsCanceledCtx` /
    `…HonorsDeadline` — a blocking-lookup seam under a canceled/expired
    ctx returns promptly; reverting the call to `context.Background()`
    hangs them red.
- **IPv6 link-local targets need a scope (#2494).** A link-local target
  (`fe80::/10`) is unprobeable without an egress link: the kernel cannot
  pick the link, so the ICMP echo goes nowhere. The scope can come from
  an explicit `%zone` on the literal (`target fe80::1%ge-0/0/3`) or be
  derived from the test's `destination-interface` — both resolve to the
  same kernel interface name the probe data socket binds via
  `SO_BINDTODEVICE`. A **bare link-local with neither a `%zone` nor a
  `destination-interface` is rejected at commit**
  (`validateRPMLinkLocalZoneStrict`); a link-local **with** either is
  accepted. The send path preserves the zone into the ICMP destination
  (`net.IPAddr{IP, Zone}`) so the echo leaves the right link; a bare
  `fe80::1` with a `destination-interface` defaults its zone to that
  device. Global IPv6 and IPv4 targets are unaffected. On the tolerant
  load / peer-sync path the rejection is downgraded to a warning (#1960
  no-brick); the runtime prober then returns the probe-setup error for
  the same scopeless link-local, so it **holds state** rather than
  actuating off a dead probe.
  - *Honoring an explicit `%zone`:* the zone string is normalized for the
    Junos slash form (`ge-0/0/3` → `ge-0-0-3`) but is **not** run through
    the RETH-member translation that `destination-interface` gets — for a
    RETH base name use `destination-interface` (fully resolved through the
    RETH map) rather than a raw `%zone`.
  - *Reply-match:* the echo-reply match compares the peer **IP** only, not
    the zone (id/seq already disambiguate the exchange, and the kernel may
    not populate the reply's zone). The send-side zone is the correctness
    fix; the reply-match stays zone-agnostic by design.
- **http-get targets are http/https only (#2495).** An `http-get` test's
  `target` may be a bare hostname, IP literal, or `host:port` (the prober
  prepends the default `http://`), or it may carry an explicit `http://`
  or `https://` scheme. A scheme is detected by the `://` separator, so a
  bare `host:port` is correctly treated as schemeless — never mistaken for
  a scheme. The previous canonicalizer used a first-character heuristic
  (prefix `http://` only when the target did **not** start with `h`), which
  wrongly assumed any `h`-leading bare host (`host.example.com`, `h2.lan`)
  was already schemed; the resulting schemeless URL was rejected by the
  HTTP client before a packet was sent, so a healthy `h`-host probe never
  ran. A target carrying any other scheme (`ftp://`, `gopher://`) is
  **rejected at commit** (`validateRPMHTTPGetSchemeStrict`) — only http and
  https are meaningful for an http-get probe. On the tolerant load /
  peer-sync path the rejection is downgraded to a warning (#1960 no-brick);
  the runtime `canonicalizeHTTPTarget` guard returns the same error for the
  bad scheme, so the test **holds state** rather than actuating off a probe
  that can never run.
- **`routing-instance` must name a configured instance (#2496).** When a
  test sets `routing-instance <name>`, the runtime binds the probe data
  socket to that instance's VRF device (`vrf-<name>`) via
  `SO_BINDTODEVICE`. A typo'd / nonexistent instance has no such kernel
  device, so the bind fails `ENODEV`: the probe never sends a packet and
  the test **holds its state forever** (no PASS, no FAIL), starving any
  ip-monitoring / event-options policy keyed off it of a failover signal.
  A non-empty `routing-instance` that does not match a configured instance
  is therefore **rejected at commit** (`validateRPMRoutingInstanceStrict`,
  mirroring the ip-monitoring preferred-route `routing-instance` check in
  `validateIPMonitoringStrict`). An empty `routing-instance` is the default
  (master) context and is always accepted. On the tolerant load / peer-sync
  path the rejection is downgraded to a warning (#1960 no-brick); the
  runtime VRF bind returns the same `ENODEV`, so the test holds state.
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
  install is rolled back (best-effort — a failed rollback is swept by
  the next band reprogram; the pin reports failed either way), and the
  daemon retries the pin install while it stays failed: on every
  commit or RG transition AND autonomously every 30 s (so a pin that
  failed during boot recovers on a quiet box with no commits — the
  recovery logs "probe pin install recovered on retry"). Pinned
  probes are also pre-held while the band is being reprogrammed, and
  pins are marked failed wholesale when no routing manager exists to
  install them. Observability: rate-limited probe-loop
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
  (priority band 31000+) matching the term's addresses / DSCP /
  `protocol` / `source-port` / `destination-port` into the instance's
  table — now populated, so the kernel slow path agrees with the fast
  path. Protocol and port predicates map onto `FRA_IP_PROTO`,
  `FRA_SPORT_RANGE` and `FRA_DPORT_RANGE` (#3730). A term carrying a
  predicate an `ip rule` cannot express (`*-port-except`, `tcp-flags`,
  `icmp-type`/`icmp-code`, `is-fragment`, `flexible-match-range`, or a
  DSCP-0 / non-empty address `except` match) FAILS CLOSED: the kernel
  mirror drops the whole term (fail-safe under-steer to the main table)
  and marks the build degraded rather than widening a constrained term
  to an address-only rule that would steer traffic the operator
  excluded. The userspace fast path still enforces the term exactly.
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
- **Consistency + autonomous self-heal (#3757).** The actuator's two
  consumers commit together or not at all: the FRR reload runs FIRST,
  and a HARD FRR reload failure (the manager's "nothing converged"
  outcome) ABORTS the actuation before the userspace snapshot is
  published — so the kernel FIB and the dataplane FIB never diverge into
  a split-brain (kernel on the old route, dataplane on the failover
  route). A degraded reload (#1880, additive `vtysh -f` applied) is
  treated as success because the new routes are already live in the
  kernel. On any consumer failure (FRR reload, snapshot publish, or the
  FIB-generation bump) the engine keeps the overlay **dirty** and
  retries on the next throttle-paced sweep until it converges — recovery
  is autonomous and does not wait for an unrelated commit, lease, or
  probe transition. The dirty bit clears only after a fully consistent
  actuation, and a change that lands mid-actuation is preserved
  (last-writer-wins). The manager's cached desired overlay
  (`m.routeOverlay`, read by every full snapshot build) is advanced
  **only after `apply_snapshot` succeeds** (#3760, mutate-after-success
  like #3766/#3742): a rejected publish leaves the cache at the
  last-applied overlay, so the retry above rebuilds the same routes, sees
  a content-hash mismatch against the still-old published snapshot, and
  re-publishes — the cache never records an overlay the dataplane never
  accepted, and a full apply during the dirty window rebuilds routes that
  match what is actually live rather than the failed target.
- **Per-cycle transition evaluation (#2527).** An RPM test's pass/fail
  status is a per-test aggregate, evaluated once across the whole probe
  set (`probe-count` probes per cycle), Junos ip-monitoring style. The
  successive-loss threshold is applied during the cycle but the test
  transitions **at most once per cycle** — the sensor edge that drives
  static-route preference fires after the full cycle completes, never
  per probe. A single transient mid-cycle success therefore cannot flip
  the test fail→pass→fail and flap the route tables within one cycle;
  the consecutive-loss counter still carries across cycle boundaries, so
  a `threshold` larger than `probe-count` trips on the cycle where the
  running run finally crosses the bar. Coarser per-probe
  `ping_probe_failed` events still fire per lost probe (eventengine
  signal only; they do not actuate routes).
