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
- **ECMP: all next-hops retained, dead ones skipped (#2389).** A static
  route keeps EVERY configured next-hop (`RouteEntryV4::next_hops:
  Vec<RouteNextHopV4>`). `select_route_next_hop` prefers a candidate with
  a resolved neighbor (so a dead first next-hop no longer blackholes a
  route with a healthy alternate), then distributes across the live
  candidates by a fixed-seed hash of the destination IP (`ecmp_hash_*`).
  Distribution is per-DESTINATION today — the 5-tuple flow hash is not
  plumbed into the resolution layer; true per-flow ECMP spread is a
  localized follow-up enabled by the retained candidate vector. The
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
