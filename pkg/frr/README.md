# pkg/frr

FRR (FRRouting) integration. Generates a managed section inside
`/etc/frr/frr.conf` from the typed config (static routes, OSPF, BGP,
ISIS, RIP, BFD profiles, multi-VRF instances) and queries protocol state
via `vtysh`.

This package is the only place in the codebase that's allowed to touch
kernel routes — and it doesn't, directly. It writes config and reloads
FRR, which then owns the kernel route table.

`frr.conf` is DurableState (#1894): `atomicWriteFile` delegates to
`fsatomic.WriteFileDurable` with `WithPreserveExisting` +
`WithResolveSymlinks` (the #1883 mode/owner/symlink semantics were
lifted into that package), gaining the parent-dir fsync the local
writer lacked. The file carries operator content outside the managed
section, so it must survive power loss.

## File layout

The package is split across five sibling `.go` files (no sub-packages,
no filename prefixes):

| File | Owns |
|---|---|
| `manager.go` | `Manager` struct + lifecycle (`New`, `ApplyFull`, `Clear`, `writeManagedSection`, `reload`), top-level types (`InstanceConfig`, `DHCPRoute`, `FullConfig`), package constants, and the zero-value-safe `executor()` accessor. The legacy `Apply`/`ApplyWithInstances` partial constructors were deleted (#1827 AGY F1, PR #1843): they bypassed `assembleFRRConfig` and would have wiped an active failover overlay. |
| `config_render.go` | Non-protocol config rendering: `generateInterfaceSettings`, `generateStaticRoute` (+ `generateStaticRouteInTable`, the table-suffix variant for `instance-type forwarding` instances, #1827 PR-2), named `ApplyFull` extractors (`renderGenerateRoutes`, `renderDHCPDefaults`, `renderBackupRouter`, `renderPreferredRoutes` — the #1827 ip-monitoring overlay as distance-1 statics, emission step 7 — `renderClusterModeDefaults`), and `resolveECMP` (which has a documented side effect: mutates `fc.ConsistentHash`). |
| `policy_render.go` | **Protocols + policy rendering** (despite the filename — `generateProtocols` for OSPF/OSPFv3/BGP/RIP/ISIS, `generatePolicyOptions` for prefix-lists/route-maps/communities, `resolveRedistribute`, BFD profile + peer dedup). **All BFD is consolidated into a SINGLE top-level `bfd { ... }` block emitted exactly once** by `manager.go`'s `buildManagedSection` (#2550). FRR's `bfdd` is one global daemon, so a per-routing-instance `bfd` block produced redundant blocks and repeated profile definitions in the consolidated `frr.conf` (frr-reload parse-warning risk) once BFD was configured in more than one routing instance. The manager creates one `*bfdSection` accumulator (`newBFDSection`) and passes it to every `generateProtocols` call (default instance + each VRF); each call ACCUMULATES its OSPFv2/OSPFv3/ISIS interface profiles (`addProfile`, dedup by profile name) and BGP BFD peers (`addPeer`, in instance order) into the shared section and emits NO `bfd` block itself. After all instances render, `bfdSection.render()` emits one block — all peers first (instance order), then all profiles (sorted by name for determinism) — outside any `router`/instance scope. When `generateProtocols` is called WITHOUT a shared section (direct callers / unit tests, the optional `shared ...*bfdSection` variadic param is absent), it falls back to a function-local section emitted at the end: byte-identical per-stanza output, so only the block COUNT changes (one global block instead of one per instance). Each `peer` line still carries the in-scope `vrf <name>` suffix when the owning instance is VRF-scoped — `peer 10.1.1.2 vrf vrf-1`. FRR's `bfdd` is a single daemon: a bare `peer <addr>` line lands in the DEFAULT VRF and never associates with the VRF-bound BGP session, so the BFD session would stay permanently DOWN and sub-second failover would never work for VRF BGP peers (#2489). Default-instance peers (`vrfName == ""`) get NO suffix. `buildManagedSection` is the pure assembly half of `ApplyFull` (split out so whole-section invariants like the single-`bfd`-block property are unit-testable via the real assemble path). OSPFv2 area membership is rendered per-interface as `ip ospf area <id>` under `interface <name>` (matching the OSPFv3 idiom), never as a global `network <prefix> area` statement — see #1712. **Route-filter match-types** (the `from route-filter <prefix> <match-type>` switch in `generatePolicyOptions`) render to FRR prefix-list entries as: `exact` → bare prefix (no `le`/`ge`); `orlonger` → default `le 32`/`le 128` (`le == prefix-len` on a `/32`/`/128` is FRR-VALID — only `ge`/`le` *strictly less than* the prefix length is rejected); `longer` → `ge <plen+1> le max`; `upto /N` → bare `le N` (NO `ge`), with `upto /N == prefix-len` — and any `upto` on a max-length host prefix (`/32`/`/128`) — rendering as **exact** (bare prefix, no `le`/`ge`), since a max-length prefix has no more-specifics (#2072). For `longer`, a max-length prefix (`/32`/`/128`) has no strictly-more-specific routes at all — the empty set — so the entry is **skipped entirely** rather than emitting the FRR-invalid `ge <plen+1> le max` (e.g. `ge 33 le 32`, which fails FRR's YANG range `0..32` and `ge > le`); the boundary skips ONLY `plen == max`, so `/31 longer` still emits the valid `ge 32 le 32` (#2103). When a term's route-filters are ALL skipped (or all malformed), the renderer emits no `ip/ipv6 prefix-list` entry lines (a materialised count==0 prefix-list is FRR `PREFIX_PERMIT`/match-ALL, so the list name must NEVER be created) but STILL emits the `match … prefix-list <name>` line referencing the now-undefined list: FRR resolves an undefined prefix-list to NULL → `RMAP_NOMATCH` (DENY), so the term matches NOTHING and stays fail-closed. The match line must NOT be suppressed — a `route-map … permit <seq>` with no `match` clauses is treated by FRR as match-ALL, which would flip a `/32 longer` empty-set term to permit-everything (Copilot #2110). This mirrors the `from prefix-list` branch, which likewise emits a `match` line for an unknown/empty list. The `match`-line address family is derived from the first *emitted* entry, else the first *parseable* route-filter (a skipped `/32 longer` still names a real family), else IPv4 (#2103/#2105). **Mixed-family route-filter terms (#2607):** a single term whose route-filters mix IPv4 AND IPv6 prefixes (a legitimate dual-stack export/import) is rendered as **TWO route-map sequences** — one per family — each with its own seq slot, a single-family `match ip|ipv6 address prefix-list` line over a per-family list (`<policy>-<term>_v4` / `<policy>-<term>_v6`), and the full term body (`set`/action, plus `on-match next` when non-terminating). This is required because FRR ANDs match clauses of DIFFERENT types within ONE route-map index (`lib/routemap.c route_map_apply_match` invokes every match rule with no address-family pre-filter): emitting both `match ip` and `match ipv6` in one sequence would make a v4 route NOMATCH the ipv6 clause and a v6 route NOMATCH the ip clause → `MATCH + NOMATCH = NOMATCH` ANDs the index to a silent deny for BOTH families (the same AND finding that drove #2071's single-matcher decision). The pre-#2607 renderer compressed the term into ONE `matchV6` boolean and emitted a single match line, so the OTHER family's prefix-list entries were written but never matched and those routes silently failed the term. The two per-family lists carry distinct NAMEs so neither match line can pick up an off-family entry, and a co-resident `from prefix-list` match clause is emitted ONLY in the sequence whose family matches the referenced list (so it never AND-NOMATCHes the off-family sequence — the #2071 co-resident collision, avoided by construction). A **homogeneous** (single-family) or empty route-filter term is UNCHANGED: ONE sequence, the historical un-suffixed `<policy>-<term>` list name, ONE match line — byte-identical to the pre-#2607 render (no churn for the common case). Per-entry seq slots keep each route-filter's ORIGINAL index across the split, so a split term's v4 and v6 entries occupy the same seq numbers (with FRR-legal gaps where the other family's entries sit) they would have in a combined list. The `ge` value used in a rendered line is ALWAYS strictly greater than the prefix length, and `le` is ALWAYS >= the prefix length (never strictly less — `orlonger`/`upto` may emit `le == prefix-len`, which is FRR-valid), and a rejected line can fail the whole `frr-reload` (`frr-reload.py` applies the add-batch via a single `vtysh -f` and exits non-zero on any `CMD_WARNING_CONFIG_FAILED`) — that is why `longer` uses `plen+1`/skips at max, and `upto` emits a bare `le N`. `upto` lengths < prefix-len, 0/unset (the compiler rejects `upto /0` so 0 means unset), or > family-max degrade safely to a valid `le family-max` (orlonger-equivalent superset) when the prefix is not max-length, never an invalid line. The **route-filter prefix is CIDR-validated at commit** (`ValidateRouteFilterArg` keyValidator, `pkg/config`): a malformed prefix is rejected at commit/commit-check (strict) but tolerated on load/HA-sync (lenient, #1960); the renderer carries a belt-and-suspenders skip for any malformed prefix that reaches it via the lenient path (#2105). `prefix-length-range /lo-/hi` renders as FRR `ge lo le hi` (#2525); the `/lo-/hi` bounds are parsed into `RouteFilter.RangeLow`/`RangeHigh` and semantically validated at commit (`validateRouteFilterMatchTypesStrict`, `pkg/config`): low<=high, both within the family max (`32`/`128`), and low **strictly greater than** the base prefix length (FRR requires `len < ge-value`; a `ge <= base` line is rejected and would fail the whole `frr-reload`, #1880-class). The renderer re-derives the base length and SKIPS the entry (match-nothing) on the lenient path when `low <= base`, so a downgraded-to-warning range never emits an FRR-invalid `ge <= base` line. `through <p2>` has NO lossless FRR prefix-list (ge/le) equivalent — it matches a two-prefix radix-tree containment path, not a length range — so it is **hard-rejected at commit** (lenient-warn on load/HA-sync per #1960); the renderer carries a belt-and-suspenders skip for both a stored `through` and a malformed/out-of-bounds `prefix-length-range` that reach it via the lenient path, and the `switch` has a `default` arm so NO unhandled match-type can ever fall through to the open-ended `le 32`/`le 128` default again (the #2525 silent-leak bug). **Multi-term fall-through (`on-match next`, #2451):** Junos evaluates a policy-statement's terms sequentially — a term whose `then` carries ONLY modifications (`community`, `local-preference`, …) and NO `then accept`/`then reject` (`PolicyTerm.Action == ""`) APPLIES its `set` clauses and FALLS THROUGH to the next term. FRR otherwise STOPS a route-map after the first matching `permit` sequence runs its `set` clauses, silently truncating every later term. `generatePolicyOptions` therefore appends ` on-match next` to each non-terminating term's sequence (rendered `permit`, `Action != accept/reject`), making FRR run the `set` clauses then continue evaluating subsequent sequences. A terminating term — `then accept` (permit, stop) or `then reject` (deny, stop) — gets NO `on-match next`, matching Junos terminating semantics. `on-match next` only fires on a MATCHED sequence (a non-matching term advances regardless), and falling off the end still hits the policy `default-action` sequence emitted after the term loop, so the overall default behavior is preserved. **Next-hop address family (#2403):** `then next-hop <addr>` is rendered with the FRR set-clause matching the literal's family — an IPv6 next-hop (detected by `strings.Contains(addr, ":")`, the same AF probe the prefix-list path uses) renders `set ipv6 next-hop global <ip>`, NOT `set ip next-hop <ip>` (FRR rejects a v6 address on the v4 clause with a syntax error that fails the WHOLE route-map parse and can brick a reload); a v4 literal keeps `set ip next-hop <ip>`. `next-hop peer-address` emits BOTH `set ip next-hop peer-address` and `set ipv6 next-hop peer-address` since the carrying BGP session's family is unknown at render time and FRR applies each clause only to the matching family; `next-hop self` emits nothing (eBGP default). |
| `vtysh.go` | `frrExecutor` interface (Vtysh / FrrReloadPy / VtyshLoad), `realExecutor` (production exec.Command implementation), `ExecVtysh`, and all raw-output Get* shells (`GetBFDPeers`, `GetRouteMapList`, `GetISIS*Detail`/`Database`/`Routes`, `GetOSPF*Detail`/`Database`/`Interface`/`Routes`, `GetBGPNeighbor*`). |
| `status_parse.go` | Parsed Get* methods + their public types (`RIPRouteEntry`, `ISISAdjacency`, `OSPFNeighbor`, `BGPPeerSummary`, `BGPRoute`, `FRRRouteDetail`, `FRRNextHop`) + `parseRouteJSON`, `FormatRouteDetail`. |

## Entry points

- `Manager` — `manager.go`.
- `New() *Manager` — `manager.go`. Defaults to `/etc/frr/frr.conf` and
  to a real `os/exec`-backed `frrExecutor`.
- `ApplyFull(fc *FullConfig) error` — `manager.go`. Apply full config
  (idempotent diff against on-disk).
- `FullConfig`, `InstanceConfig`, `DHCPRoute` — `manager.go`.
- State queries: raw-text shells in `vtysh.go`, parsed `Get*` methods
  in `status_parse.go`. All shell-outs route through `m.executor()`
  so they can be faked in tests (see `executor_test.go`).

## Callers

`pkg/daemon` (lifecycle), `pkg/grpcapi` (show commands).

`FullConfig.PreferredRoutes` (#1827) carries the ip-monitoring
effective-route overlay; the daemon's `assembleFRRConfig` is the sole
`FullConfig` constructor for both the full apply path and the
routes-only actuator, so an operator commit can never wipe an active
failover route. The `ApplyFull` emission-order contract comment lists
the overlay as step 7.

## Dependencies

`pkg/config` only.

## Managed-section markers

`! BEGIN BPFRX MANAGED CONFIG` … `! END BPFRX MANAGED CONFIG`. User-edited
content **outside** the markers is preserved across `ApplyFull`. Don't
move or rename the markers — they're literal strings.

## Gotchas

- Static routes have RETH names (`reth0`) but FRR wants the physical
  member name in cluster mode. The package translates via `RethMap` from
  the typed config.
- `InstanceConfig` has two rendering modes (#1827 PR-2):
  `VRFName != ""` renders `vrf <name>` (virtual-router instances);
  `VRFName == ""` with `TableID > 0` renders `table <id>`
  (`instance-type forwarding` instances — no VRF device exists, and the
  table must match the FBF/PBR `ip rule` target and the dataplane's
  `<ri>.inet.0`). `renderPreferredRoutes` resolves an overlay entry's
  instance via `InstanceConfig.Name`; legacy callers that never set
  `Name` keep the historical `vrf-<name>` rendering.
- IPv6 next-hops without an explicit interface require `IPv6NextHopInterfaces`
  for link-local resolution — link-local addresses alone are ambiguous to
  FRR. The map is built by `inferIPv6StaticNextHopInterfaces`
  (`pkg/daemon/daemon_run.go`); `generateStaticRoute` uses an explicit
  `NextHopEntry.Interface` first and falls back to this map only for an
  unqualified next-hop.
- **Link-local (`fe80::/64`) static next-hops (#2452).** A link-local
  next-hop is interface-scoped and FRR rejects `ipv6 route <dst> fe80::x`
  without a trailing `<iface>`. Link-local addresses are never declared
  under `unit.Addresses` (the kernel auto-assigns them), so
  `inferIPv6StaticNextHopInterfaces` adds a synthetic `fe80::/64` candidate
  per IPv6-capable logical interface. Disambiguation rule for an
  **unqualified** link-local next-hop: (1) if the operator wrote
  `qualified-next-hop fe80::x interface <if>` / `next-hop fe80::x interface
  <if>` the explicit interface is used directly and inference is skipped;
  (2) otherwise it resolves only when exactly ONE IPv6-capable interface is
  in scope (the single defensible answer); (3) with multiple IPv6
  interfaces and no qualifier the next-hop is genuinely ambiguous — the
  inference refuses to guess (leaves it unresolved) rather than route to the
  wrong link, and the operator must add an interface qualifier.
- **VRRP-VIP-only subnets (#2452 secondary).** A bondless-RETH member that
  carries only a VRRP virtual address (no matching `unit.Addresses` entry)
  also contributes its VIP subnet as a connected prefix, so a static
  next-hop inside the VIP subnet resolves to that member interface. The VIP
  is read from `VRRPGroup.VirtualAddresses` (the `unit.VRRPGroups` map
  VALUE, a CIDR string — the same field `pkg/vrrp` feeds to
  `netlink.ParseAddr`); the map KEY is `"<CIDR>_grp<id>"`
  (`compiler_interfaces.go`) and is deliberately NOT parsed as an address.
- In cluster mode the package emits a blackhole default at admin distance
  250 so traffic to the active fabric peer survives a brief
  active/active overlap.
- **DHCP default routes bind the originating interface for BOTH families
  (#2547).** `renderDHCPDefaults` (admin distance 200) emits `ip route
  0.0.0.0/0 <gw> <iface> 200` / `ipv6 route ::/0 <gw> <iface> 200` whenever
  the lease records an interface (`DHCPRoute.Interface != ""`, populated by
  `collectDHCPRoutes` in `pkg/daemon/daemon_flow.go` for v4 and v6 alike),
  falling back to the gateway-only form when it is empty. The IPv4 branch
  previously dropped the interface — an unintended asymmetry that left the
  kernel unable to pick the correct egress in multi-WAN / shared-gateway-IP
  deployments (default-route conflicts / blackholing).
- **Export references are validated at commit (#2144).** A dynamic-protocol
  `export` (OSPF/OSPFv3/BGP/IS-IS), a RIP `redistribute`, a BGP
  group/neighbor `export`, and a `routing-options forwarding-table export`
  are checked against the defined policy-statement set (and, for the
  redistribute-backed exports — OSPF/OSPFv3/RIP/IS-IS, plus a global
  `protocols bgp export` whose token is a bare protocol; a global BGP
  export that names a policy-statement renders as peer-level `route-map
  out` instead, see #2473 below — the known protocol tokens
  `connected`/`direct`/`static`/`kernel`/`ospf`/`bgp`/`rip`/`isis`) by
  `validateRoutingExportReferencesStrict` in `pkg/config/compiler.go`.
  Strict on commit/commit-check; lenient (warn) on load/HA-sync (#1960).
  This closes the render-side fail-open paths that previously turned a typo
  into broken or silent config: a BGP group/neighbor export renders
  `route-map <name> out`, where a missing route-map resolves to permit-all
  (silently advertises everything); and `resolveECMP` returns 0 max-paths
  for a missing forwarding-table policy (silently disables
  ECMP/consistent-hash). Those render fallbacks remain as
  belt-and-suspenders for a config that reaches the renderer via the
  lenient path (an older-binary persisted config or a peer-synced one). The
  bare-protocol render path also normalizes the Junos `direct` token to the
  FRR `redistribute connected` keyword (`export direct` previously rendered
  the FRR-invalid `redistribute direct`, failing the reload) — matching the
  policy-term `FromProtocols` normalization and keeping the commit gate's
  acceptance of `direct` honest.
- **A global `protocols bgp export <token>` is split by token shape
  (#2473).** The render classifies each entry by the SAME
  policy-statement-exists predicate the commit-time validator uses
  (`checkRedist`/`checkPolicyRef`, `pkg/config`), via
  `isDefinedPolicyStatement`:
  - **A DEFINED policy-statement name** is a Junos DEFAULT export policy
    applied to every peer (a group/global default), NOT redistribution.
    The old render routed ALL of `bgp.Export` through
    `resolveRedistribute`, which for such a policy produced `redistribute
    ospf route-map ...` under `router bgp` — actively ANNOUNCING the
    OSPF/connected RIB into BGP (route leak: internal subnets advertised
    to external peers, failure mode 1) — and for a prefix/community-only
    policy with no `from protocol` returned `""`, SILENTLY DROPPING the
    operator's advertise filter (failure mode 2). `generateProtocols` now
    applies a policy-statement export as a peer-level `neighbor <X>
    route-map <name> out` per neighbor/address-family (`bgpEffectiveExport`
    + `lastNonEmpty` helpers), referencing the same route-map
    `generatePolicyOptions` already emits. Neighbors with no explicit
    `family` are routed into the ipv4-unicast block when such a global
    export is set (FRR default-activates them there) so the default
    reaches every peer.
  - **A BARE PROTOCOL TOKEN** (`connected`/`direct`/`static`/`kernel`/
    `ospf`/`bgp`/`rip`/`isis` — NOT a defined policy-statement) is this
    firewall's redistribution shorthand and KEEPS rendering as
    `redistribute <proto>` via `resolveRedistribute`. A bare token has no
    route-map to reference; rendering it as `neighbor X route-map
    connected out` would point at a non-existent route-map, which FRR
    resolves to PERMIT-ALL — advertising the entire table (a leak). The
    split keeps the bare-token redistribute correct while the
    policy-statement path filters advertisements.

  **Coexistence (Junos most-specific-wins)** applies ONLY among the
  policy-statement-name route-map-out exports: a per-neighbor
  (group/neighbor) `export` OVERRIDES the global default for that neighbor
  — FRR accepts a single `route-map out` per neighbor/AF, so exactly one
  is emitted (the neighbor's own when present, else the global default);
  the two never compete on one peer. A bare-token redistribute is a GLOBAL
  redistribute verb, not per-neighbor, emitted once under `router bgp`.
  `resolveRedistribute` is still called on the BGP export path, but ONLY
  for bare tokens — never for a policy-statement name (that was the leak).
  Both `route-map out` emit sites (ipv4 + ipv6 AF) are guarded by
  `isDefinedPolicyStatement` (#2539, sibling of the #2490 inbound guard):
  `globalExport` is already restricted to defined policy-statements, but a
  per-neighbor `export` (parseable as of #2490) can carry a bare token or an
  undefined ref that slipped the strict validator on the lenient load/HA-sync
  path. The guard skips it (fail-closed) instead of emitting a dangling
  `route-map out` = FRR permit-all OUTBOUND. Bare tokens never reach here as a
  defined name, so the bare-token→redistribute path is unchanged.
- **`protocols bgp ... import <policy>` renders inbound `route-map in`
  (#2490).** BGP neighbors/groups now carry an `Import []string` symmetric
  to `Export`. A global `protocols bgp import`, a group `import`, and a
  per-neighbor `import` are parsed (`compiler_protocols.go`) and rendered as
  `neighbor <X> route-map <name> in` per neighbor/address-family
  (`bgpEffectiveImport` + `lastNonEmpty`, symmetric to `bgpEffectiveExport`).
  Before #2490 the `import` clause parsed to NOTHING — inbound route
  filtering on a BGP peer was a silent no-op. **Coexistence (most-specific-
  wins):** a per-neighbor import overrides the group/global default import;
  FRR accepts exactly one `route-map in` per neighbor/AF, so the neighbor's
  own policy wins when present. **#2473-lesson guard (inbound direction):**
  unlike export, import has NO redistribute equivalent — inbound filtering is
  route-map-only — so an import ref MUST name a DEFINED policy-statement. An
  undefined/bare-token ref is REJECTED at commit (`checkPolicyRef` in
  `validateRoutingExportReferencesStrict`, strict) and SKIPPED on the lenient
  load/HA-sync path (the render guards with `isDefinedPolicyStatement` before
  emitting `route-map <name> in`). Rendering a dangling `route-map <token>
  in` would resolve to PERMIT-ALL in FRR — accepting every inbound
  advertisement and defeating the operator's filter (the #2473 leak, inbound
  side). The referenced route-map is the same block `generatePolicyOptions`
  already emits for the policy-statement.
- **Group address-family flags are gated by neighbor address version
  (#2454).** When `compiler_protocols.go` copies a BGP group's `family inet`
  / `family inet6` flags down to each neighbor, it parses the neighbor's
  address (`net.ParseIP`) and inherits ONLY the matching family: an
  IPv4-addressed neighbor gets `FamilyInet` (never `FamilyInet6`), an
  IPv6-addressed neighbor gets `FamilyInet6` (never `FamilyInet`). Before
  this gate, a dual-stack group (`family inet` AND `family inet6`) marked
  BOTH flags on every neighbor regardless of its IP version, so the render's
  `inet4Neighbors`/`inet6Neighbors` partition put a bare IPv4 neighbor into
  the ipv6 set and emitted `neighbor <ipv4> activate` under
  `address-family ipv6 unicast`. Activating an IPv4 address for IPv6 unicast
  is invalid without RFC 5549 extended-nexthop (this config model has no
  such knob), and FRR rejects/ignores the activation — breaking the peer's
  AF setup. Edge cases: an address that is not a literal IP (a hostname or
  peer-group template) cannot be classified, so it preserves the prior
  behavior of inheriting BOTH group flags (no silent family drop, no crash);
  a per-neighbor explicit `family` clause is operator-authoritative and is
  applied as-is after the inherited flags. The gate does not over-restrict:
  an IPv4 neighbor in a v4-only or family-less group still establishes — FRR
  default `bgp default ipv4-unicast` auto-activates it, and an explicit
  `family inet` group still surfaces `FamilyInet`.
- **`resolveRedistribute` never emits an invalid `redistribute <name>`
  line (#2223).** FRR's `redistribute` requires a source-protocol token
  (`connected`/`static`/`ospf`/`bgp`/`rip`/`isis`/`kernel`); a bare
  policy-statement name or a typo is rejected by `frr-reload.py`, and
  because the line lives in the xpf-managed section that ONE rejected line
  degrades the WHOLE reload (`frr-reload.py` exits non-zero on any
  `CMD_WARNING_CONFIG_FAILED`, then the additive `vtysh -f` fallback
  rejects it too) — every managed route/redistribute is lost, not just the
  bad stanza. The commit-time strict validator accepts any DEFINED
  policy-statement for a redistribute-backed export; it does NOT require the
  policy to carry a `from protocol`. So a policy that matches only `from
  community` / `from prefix-list` / `from as-path` passes commit but yields
  zero `FromProtocols` at render time. In that case — and for any token that
  is neither a known protocol nor a defined policy-statement (a name slipped
  past validation on a lenient load/HA-sync path) — `resolveRedistribute`
  now SKIPS emission and logs a `slog.Warn` (returns `""`) rather than
  falling back to the FRR-invalid bare-name line. Redistribute has no
  construct to express "redistribute whatever this policy matches" without a
  source protocol, so skipping is the only correct outcome; the operator is
  warned to add a `from protocol <proto>` (or use a bare protocol token).
  This is the load-bearing invariant: a single unresolvable export can never
  poison the entire managed-section reload.
- **Community-lists: `standard` vs `expanded` is per-DEFINITION (#2643).**
  An FRR `standard` community-list accepts ONLY literal community values
  (`ASN:VALUE`, or a well-known name such as `no-export` /
  `no-advertise` / `internet` / `local-AS`); it REJECTS any POSIX-regex /
  wildcard member (`65000:*`, `.*`, `65001:1..`) at config load, and a
  single rejected line fails the whole `frr-reload` of the managed
  section, leaving the routing daemon stale/unconfigured for the entire
  commit. An `expanded` community-list accepts a POSIX regex per member.
  `generatePolicyOptions` therefore inspects every member of a named
  community definition: a member containing any of
  `* . + ? ^ $ [ ] ( ) | \ { }` (`communityMemberIsRegex` —
  the braces cover POSIX-ERE interval bounds like `65000:1{2,3}`) is
  regex; a plain `digits:digits` or well-known name is literal. If ANY
  member is regex, the WHOLE definition renders as
  `bgp community-list expanded <name> …`; otherwise it stays
  `bgp community-list standard <name> …`. FRR forbids the same list NAME
  from being declared both standard and expanded, so a MIXED
  literal+regex definition CANNOT be split across the two kinds — it is
  rendered entirely as `expanded`. Members are written as-is (the
  wildcard `65000:*` becomes the FRR regex verbatim, matching Junos
  intent). NUANCE: FRR matches expanded community-list members
  UNANCHORED, so a literal value folded into an expanded list (the MIXED
  case) matches as a substring — `65000:100` would also match
  `65000:1000` / `165000:100`. This only affects MIXED definitions
  (uncommon); a literal-only definition stays `standard` (anchored exact
  match) and is unaffected. This is the same fail-closed-the-whole-reload
  class as the route-filter `ge`/`le` bounds above (#1880).
- `vtysh -c` is run synchronously in batch mode for state queries. There
  is no streaming; long output is buffered.
- All `vtysh` and `frr-reload.py` shell-outs route through the
  package-private `frrExecutor` interface. Tests inject a fake;
  production uses `realExecutor{}` (which `exec.Command`s the real
  binary). A zero-value `Manager{}` is tolerated via the `executor()`
  accessor — useful for same-package literals.
- Reload mechanism (#1880): the primary reload is a DIRECT bounded
  `/usr/lib/frr/frr-reload.py --reload <frr.conf>` — NEVER
  `systemctl reload frr`. On FRR 10.6 the unit's ExecReload
  (frrinit.sh reload) unconditionally restarts watchfrr, the
  Type=forking unit's MainPID, so every systemd-mediated reload cancels
  its own job, parks frr.service in `stop-sigterm` for 2 minutes, and
  ends with systemd SIGKILLing all FRR daemons. The direct invocation
  keeps the unit state untouched and restores stale-config REMOVAL on
  commit (the systemctl branch had been 100%-failing, so every reload
  silently ran the additive fallback).
- Each reload leg gets its OWN 15-second `context.WithTimeout`: the
  primary and, when it fails (any cause, including timeout), a FRESH
  context for the additive `vtysh -f` fallback. The real executor runs
  frr-reload.py in its own process group and SIGKILLs the group on
  cancel (`Setpgid` + `cmd.Cancel`), so no child `vtysh` writer can
  survive a timeout and race the fallback. Worst case on the apply
  path: ≤40s (2×15s + up to two 5s WaitDelay windows; an apply also
  waits at most one teardown window behind a pre-cancelled in-flight
  retry, ≤45s total).
- Degraded mode: fallback success returns `ErrFRRReloadDegraded`
  (wrapping the primary cause). A single-flight in-manager retry loop
  re-runs the primary at 15s/30s/60s then every 5min until a full diff
  converges (`frr.conf` on disk is the SSOT; a newer apply supersedes
  and a fully-successful reload cancels the episode). All reloads —
  applies AND the retry — serialize under `reloadMu`; `confGen` guards
  against a stale success clearing the state. The condition is exported
  via `Manager.ReloadDegraded()` → `xpf_frr_reload_degraded` (0/1
  gauge). `frr-pythontools` missing is classified explicitly
  (warn-once, slow-cadence retry). `Manager.Stop()` (wired into daemon
  shutdown) cancels in-flight process groups and reaps the retry
  goroutine; `DisableDegradedRetry()` is the one-shot (`xpfd cleanup`)
  configuration.
