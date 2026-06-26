# userspace-dp/src/afxdp/forwarding/

The "decide where this packet goes" stage. Validates the parsed
packet metadata against the live `ValidationState` (snapshot
installed, config generation matches, FIB generation matches), then
runs FIB lookup, next-hop selection, VRF / next-table inter-VRF
leaking traversal, and produces a `ForwardingResolution` for the TX
side.

Packets that fail validation never reach FIB lookup — they get a
`PacketDisposition` (`NoSnapshot`, `ConfigGenerationMismatch`,
`FibGenerationMismatch`, `UnsupportedPacket`) and are dropped or
slow-path-injected.

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | `classify_metadata` + the FIB / next-hop traversal entry points. |
| `host_inbound.rs` | #3070 host-inbound-traffic admission: classifies a zone's Junos `system-services` / `protocols` tokens into a `ZoneHostInbound` set and provides `host_inbound_admits` for the local-delivery path. |
| `tests.rs` | Co-located unit tests covering classify, FIB lookup, multi-table next-table leaking. |

## Constants

- `DEFAULT_V4_TABLE = "inet.0"`, `DEFAULT_V6_TABLE = "inet6.0"` —
  the default routing tables a packet starts in when no
  routing-instance scopes it.
- `MAX_NEXT_TABLE_DEPTH = 8` — bounded recursion across `next-table`
  chains to keep a misconfigured loop from running forever.

## FIB route model

Route metadata crosses the Go→Rust snapshot boundary as `RouteSnapshot`
(`protocol/snapshot.rs`) and is built into per-table FIBs by
`forwarding_build/fib.rs`. Three correctness rules govern selection:

- **Connected routes are table-scoped (#2388).** Connected prefixes are
  rebuilt from interface addresses into the global `connected_v[46]`
  vectors, but each entry carries its routing-table name
  (`ConnectedRouteV4::table`), derived from the interface's
  `routing_instance` (`""` = default → `inet.0`/`inet6.0`; a named
  instance → `<ri>.inet.0`/`<ri>.inet6.0`). The lookup filters connected
  candidates on the resolving table, so a per-VRF / `next-table` lookup
  never matches another routing-instance's connected prefix. (Gateway →
  egress inference at build time, `infer_connected_route_target_*`,
  stays global — that resolves "which interface reaches this gateway IP",
  not a destination egress.)
  - **Local-delivery (to-self) attribution is table-scoped too (#3151).**
    The `lookup_forwarding_resolution_inner_ecmp` shortcut for a
    destination in `local_v[46]` resolves `local_ifindex` /
    `egress_ifindex` / `tx_ifindex` by scanning `connected_v[46]`. That
    scan applies the SAME `entry.table == table` filter as the route path
    (canonicalizing the ingress table FIRST, before the local-address
    check). Without it, when the same local IP is configured in more than
    one routing-instance, a to-self packet in VRF A could attribute its
    local/egress/tx ifindex to VRF B's interface — mis-feeding
    zone/security-policy selection and HA RG ownership
    (`owner_rg_for_flow(egress_ifindex)`). The default routing-instance
    (`inet.0`/`inet6.0`) case still matches default-table connected
    routes.
- **ECMP: all next-hops retained, dead ones skipped (#2389), per-FLOW
  spread (#2734).** A static route keeps EVERY configured next-hop
  (`RouteEntryV4::next_hops: Vec<RouteNextHopV4>`). `select_route_next_hop`
  prefers a candidate with a resolved neighbor (so a dead first next-hop
  no longer blackholes a route with a healthy alternate), then distributes
  across the live candidates by a spread hash. **#2734: the spread key is
  per-FLOW.** The session resolution path
  (`lookup_forwarding_resolution_with_dynamic_for_flow`) hashes the forward
  5-tuple with `ecmp_hash_flow` — the SAME per-boot seeded `FxHasher` the
  flow cache uses (`hot_hash_seed::hot_path_hash_seed`, #2364), so distinct
  flows to the same destination spread across equal-cost members while
  every packet of one flow pins to one member (flow-consistent, no
  intra-flow reordering; the resolution is cached on the session entry).
  The hash reduces modulo the LIVE-member count, so the spread tracks the
  live pool and the dead-NH fallback is preserved. Callers without a flow
  context (tunnel/WG outer resolution, `inject`, bare-dst lookups) pass
  `ecmp_flow_hash = None`, which falls back to the per-DESTINATION hash
  (`ecmp_hash_v4`/`ecmp_hash_v6`, the #2389 behavior). The seed is
  node-local (ECMP picks among THIS node's members and is not wire/HA
  state), so an HA peer re-derives its own pick under its own seed — the
  same property the flow cache and fabric-queue hash already rely on. The
  legacy `RouteEntryV4::{ifindex,next_hop,tunnel_endpoint_id}` accessors
  return the FIRST candidate for non-multipath call sites.
- **Preference tie-break before insertion order (#2390).**
  `RouteSnapshot.preference` (Junos admin distance; lower = more
  preferred, default 5) is carried on the wire and used as the secondary
  sort key in `sort_routes` (descending prefix length, then ascending
  preference). Two same-prefix routes in a table select by operator
  preference, not insertion order; same-prefix/same-preference routes
  keep insertion order (stable sort).

All three wire fields (`routing_instance`, `next_hops`, `preference`)
are additive: an old Rust helper ignores them (pre-fix behavior) and an
old Go binary omits them (serde defaults: default instance, empty
next-hops, preference 0). The wire specimen lives in
`tests/fixtures/protocol_wire_v1.json`.

## Where it sits

- Reads the live snapshot Arcs (FIB, NAT, neighbor table) supplied
  by `worker_loop`.
- Output (`ForwardingResolution`) is consumed by the TX path
  (`tx/dispatch.rs`, `tx/transmit.rs`) to pick the egress binding
  and encode the L2 header.
- Has no cross-binding back-edges — the per-worker hot path stays
  on its own UMEM.

## Host-inbound-traffic enforcement (#3070)

`security zones <z> host-inbound-traffic { system-services ...; protocols
...; }` controls which host-bound services are admitted to a firewall-local
interface IP (SSH, ping, routing protocols on the box itself).

**Two enforcement layers — kernel is primary, this userspace check is the
secondary edge-case path.** Ordinary host-bound traffic to an interface IP /
VRRP VIP is shunted to the LINUX KERNEL by the XDP shim
(`is_local_destination` → `cpumap_or_pass`/`PASS_TO_KERNEL` in
`userspace-xdp/src/lib.rs`) BEFORE it reaches userspace-dp, so the
authoritative host-inbound enforcement for those packets lives in the kernel
`chain input` (table `inet xpf_hostinbound`, built in
`pkg/daemon/daemon_nft.go` from `userspace.BuildZoneHostInboundViews`,
mirroring the lo0-filter precedent). The userspace LocalDelivery check below
covers only the subset that actually reaches the XSK — DNAT-to-self,
static-NAT to a firewall service, embedded-ICMP, DNS edge cases. **Both layers
share the same per-zone token set; keep the Go nft token→match mapping
(`hostInboundServiceMatches`/`hostInboundProtocolMatches`) in sync with the
Rust classifier here.**

The set is parsed and modeled in Go
(`config.ZoneConfig.HostInboundTraffic`) and crosses the snapshot boundary on
`ZoneSnapshot`
(`host_inbound_configured` + the raw `host_inbound_system_services` /
`host_inbound_protocols` token slices — JSON keys byte-identical on both
sides per #1961). `forwarding_build::zones::populate_zones` classifies the
tokens into a `ZoneHostInbound` (`host_inbound.rs`) keyed by the same
validated zone id and stores it in `ForwardingState::zone_host_inbound`.

Enforcement runs on the **local-delivery admit path only** (transit
traffic never pays for it), at BOTH sites in `poll_descriptor`:

- **session miss** — a host-bound packet whose service/protocol is not in
  the ingress zone's set is dropped and never cached.
- **session hit** — re-checked every packet (mirroring the lo0-filter
  re-check) so a tightened host-inbound config tears down an
  already-established host-bound session WITHOUT an explicit purge.

`host_inbound_admits` returns admit when the zone has **no** stanza (the
zone is absent from `zone_host_inbound`), preserving the pre-#3070
admit-all behaviour — a deliberate, zero-regression deviation from strict
Junos (which denies host-bound traffic to an unconfigured zone). Token
classification covers the common Junos `system-services` (ssh, ping, dns,
dhcp/dhcpv6, ike, ntp, snmp, ...) and `protocols` (ospf, bgp,
router-discovery, ...) names; `system-services all` / `any-service`
short-circuit to a full admit; an unrecognised token contributes nothing
(fail-closed). ICMP-based services (`ping`, `router-discovery`) admit echo /
solicitation at L4-protocol granularity, not ICMP sub-type.

**Service/protocol matches are address-family aware (#3225).** Several Junos
host-inbound tokens are family-SPECIFIC in intent: `system-services dhcp` is
DHCPv4 (udp 67/68 over IPv4) while `dhcpv6` is DHCPv6 (udp 546/547 over IPv6);
`protocols rip` is RIPv2 (IPv4) and `ripng` is RIPng (IPv6); `protocols ospf` is
OSPFv2 (IPv4) and `ospf3` is OSPFv3 (IPv6) — both ride IP protocol 89 but on
different families; `igmp` is IPv4 group membership (the IPv6 equivalent is MLD,
carried over ICMPv6 / the always-accepted ND set). Before #3225 both enforcement
layers compiled these into family-NEUTRAL matches, so a v4-only `dhcp` opened
udp/67-68 on the IPv6 path and `ripng` opened udp/521 on IPv4 — wrong-family host
exposure. `ZoneHostInbound` now carries family-scoped sets (`udp_ports_v4` /
`udp_ports_v6`, `ip_protocols_v4` / `ip_protocols_v6`) alongside the dual-family
`udp_ports` / `ip_protocols`; `admits(protocol, port, is_v6)` consults the
dual-family set OR the set matching the packet's family. The single source of
truth for a token's family is `config.HostInboundServiceFamily` /
`config.HostInboundProtocolFamily` (Go side): the nft kernel mirror gates
`hostInboundServiceMatches` / `hostInboundProtocolMatches` on it directly, and
the Rust classifier mirrors the same families into the scoped sets — so both
layers agree exactly. Dual-family services (ssh/https/ping/dns/bgp/...) are
absent from the maps and admit on both families as before. `protocols all`
expands to the routing set INCLUDING both `ospf` and `ospf3`, so it admits proto
89 on each family (and rip on v4, ripng on v6).

**ICMP error / PMTUD control messages are always admitted (#3171).** Before
the per-zone lookup, `host_inbound_admits` exempts ICMP/ICMPv6 *error* subtypes
(`is_icmp_host_inbound_error`: ICMPv4 destination-unreachable/time-exceeded/
parameter-problem, ICMPv6 type 1/2/3/4) regardless of whether the ingress zone
lists `ping`. This mirrors the kernel `chain input` global ICMP-error accept
(`pkg/daemon/daemon_nft.go`) so the embedded-ICMP / DNAT-to-self subset listed
above — e.g. a PMTUD packet-too-big or traceroute time-exceeded landing on the
XSK LocalDelivery path — is no longer fail-toward-dropped on a configured
ping-less zone. ECHO-REQUEST (v4 type 8 / v6 type 128) is **not** in the error
set, so a ping-less zone still drops echo. Keep `is_icmp_host_inbound_error` in
lock-step with the kernel chain's `icmp`/`icmpv6` accept lines.

**`protocols all` is scoped, NOT a blanket bypass (#3199).** In Junos
`host-inbound-traffic protocols all` admits every supported ROUTING protocol
(the entries under the `protocols` stanza) — it is NOT `system-services all`
and NOT a blanket accept. The classifier expands the `all` token to the
concrete routing-protocol set (`ROUTING_PROTOCOL_TOKENS`:
ospf/ospf3/bgp/rip/ripng/igmp/pim/vrrp/bfd/ldp/msdp/nhrp/router-discovery,
each family-scoped per #3225) instead
of setting a short-circuit flag, so a `protocols all` zone admits routing
protocols but still DENIES SSH/HTTPS/SNMP/NETCONF unless the matching
`system-services` token is also present. The Go nft mirror
(`hostInboundProtocolMatches("all", ...)` over
`hostInboundRoutingProtocolTokens`) expands the same set and still emits the
per-zone catch-all drop, so the kernel and userspace decisions stay
consistent.

## `junos-host` self-traffic security policy (#3019)

Host-bound (LocalDelivery) traffic is also subject to the Junos
`from-zone <z> to-zone junos-host` security policy. Junos order is
**host-inbound admission FIRST, then security policy** — so the
`junos_host_policy_drops` gate runs immediately AFTER `host_inbound_admits`
at BOTH local-delivery sites in `poll_descriptor` (session miss and session
hit). A packet host-inbound already rejected never reaches policy, so a
`to-zone junos-host then permit` cannot re-admit it.

`policy::evaluate_junos_host_policy` resolves the reserved `junos-host` zone
name to `JUNOS_HOST_ZONE_ID` (`u16::MAX-1`, the bottom of the reserved range,
never on the wire because zone ids are u8) and looks up the
`(ingress_zone_id, JUNOS_HOST_ZONE_ID)` zone pair in the SAME `zone_pair_index`
as transit rules — `parse_policy_state_with_counters` now INDEXES junos-host rules
via `resolve_policy_zone_id` (pre-#3019 they were kept-but-not-indexed, like the
wildcard-`any` case). A matched deny/reject drops the packet, emits the
policy-deny RT_FLOW (egress zone reported as `0`/host since the synthetic id
does not fit the u8 wire slot), synthesizes a `reject`/zone-`tcp-rst` reply, and
on the hit path tears down the cached host-local session.

Enforcement is MATCH-DRIVEN and fail-safe: the gate is a NO-OP unless
`PolicyState::has_junos_host_rules` is set (some junos-host rule configured),
and a no-match falls through to today's behavior (local delivery proceeds).
There is NO implicit junos-host default-deny — the deliberate lifeline
guarantee that configuring junos-host policy can never silently brick
management/host traffic. `from-zone junos-host` (host-ORIGINATED) rules are
indexed but not consulted here (locally-generated traffic does not traverse
this ingress path) — a documented follow-up.

## Host-terminated IPsec passthrough

`is_ipsec_traffic(protocol, dst_port)` recognizes packets destined for
the local kernel XFRM stack so the IPsec passthrough stage
(`poll_stages::stage_ipsec_passthrough_check`) reinjects them via the
slow-path TUN device instead of running them through ordinary transit
forwarding. The recognized set is:

- ESP — protocol 50 (`PROTO_ESP`)
- AH — protocol 51 (`PROTO_AH`)
- IKE / NAT-T — UDP destination port 500 or 4500

ESP and AH carry no transport port, so only the protocol-number arm
applies to them. The predicate keys solely on `meta.protocol` and is
therefore family-symmetric in form — but `meta.protocol == PROTO_AH`
(51) only ever occurs for **IPv4 AH**. The XDP shim's IPv6 parser
treats AH as an extension header and walks THROUGH it (the
`NEXTHDR_AUTH` arm in `userspace-xdp/src/lib.rs`), setting
`meta.protocol` to AH's inner next-header rather than 51. So the AH arm
is a **v4-only backstop**; it never fires for IPv6 AH. ESP (proto 50)
is parsed as a terminal protocol on both families, so ESP is recognized
for v4 and v6 alike.

This is not a functional gap. IPv6 host-terminated AH-to-self still
reaches the kernel XFRM stack via the shim's `is_local_destination`
shunt, which fires for any local-destination packet *before* the
userspace dataplane runs this predicate; transit AH (v4 or v6) takes
ordinary forwarding. AH was omitted entirely before #2385, which
silently broke host-terminated **IPv4** AH SAs (configurable via
`set security ipsec proposal ... protocol ah`); the AH arm is
regression-guarded in `tests.rs`. Giving this predicate true IPv6 AH
coverage would require the shim to surface an "AH present" signal
instead of walking past the header — out of scope here, and
unnecessary given the local-dest shunt.
