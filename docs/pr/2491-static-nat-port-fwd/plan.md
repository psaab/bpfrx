# #2491 — static NAT port / mapped-port forwarding

## Gap

`StaticNATRule` supports only whole-address 1:1 NAT. Junos static-NAT
also supports translating the destination port on a 1:1 host:

```
set security nat static rule-set rs1 rule r1 match destination-address 203.0.113.1/32
set security nat static rule-set rs1 rule r1 match destination-port 8080
set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.5/32 mapped-port 80
```

This lets multiple services live behind one public IP. xpf parses
`match destination-port` nowhere for static NAT, and `then static-nat
prefix` ignores any trailing `mapped-port` token, so the capability is
inexpressible.

## Approach (minimal, mirrors DNAT which already has port translation)

1. **Go types** (`pkg/config/types_security.go`): add to `StaticNATRule`
   - `MatchDestinationPort int` (0 = any / no port match)
   - `MappedPort int` (0 = no port translation)
2. **Compiler** (`pkg/config/compiler_nat.go` `compileNATStatic`):
   - parse `match destination-port`
   - parse the trailing `mapped-port <port>` token on
     `then static-nat prefix <ip> mapped-port <port>` (both flat-set
     `Keys` and hierarchical `prefix { ... } mapped-port { ... }`).
   - Fail-closed: a `mapped-port`/`destination-port` outside 1..65535 is
     a commit-check error (SchemaValidate typed leaf).
3. **Schema** (`pkg/config/schema_security.go`): add typed leaves
   `match destination-port` and (under `then static-nat`) `prefix` +
   `mapped-port`, with port validation (#1319 SSOT).
4. **Snapshot wire** (`pkg/dataplane/userspace/protocol.go` +
   `nat.go`): add `MatchDestinationPort uint16` + `MappedPort uint16`
   to `StaticNATRuleSnapshot` (Go `omitempty`). Mirror on the Rust side
   (`userspace-dp/src/protocol/nat.rs`, `#[serde(default)]`). Regenerate
   `tests/fixtures/protocol_wire_v1.json`. Backward compatible (new
   optional fields default 0).
5. **Rust dataplane** (`userspace-dp/src/nat/static_nat.rs`):
   - `StaticNatEntry` gains `match_dst_port: Option<u16>` (external
     port the inbound packet must carry) and `mapped_port: Option<u16>`
     (internal port to rewrite to).
   - Key the DNAT map by `(external_ip, Option<u16> match-port)` and the
     SNAT map by `(internal_ip, Option<u16> mapped-port)` so a single
     external IP can host several per-port mappings AND a port-less 1:1
     mapping. Lookup falls back: try the port-specific entry first, then
     the port-less (any-port) entry.
   - Forward (DNAT, inbound): `match_dnat_with_counter(dst_ip, dst_port,
     zone)` → `rewrite_dst = internal_ip`, and if `mapped_port` set,
     `rewrite_dst_port = mapped_port`.
   - Reverse (SNAT, outbound return): `match_snat_with_counter(src_ip,
     src_port, zone)` → `rewrite_src = external_ip`, and if `mapped_port`
     set and the packet's src port == mapped_port, `rewrite_src_port =
     match_dst_port` (the external port).
   - `NatDecision` already carries `rewrite_src_port`/`rewrite_dst_port`
     and `.reverse()` already mirrors them — no decision-type change.
6. **Callers** thread the port:
   - `poll_descriptor/mod.rs` inbound: pass `flow.forward_key.dst_port`.
   - `nat_exception.rs` SNAT: pass `flow.forward_key.src_port`.

## Alternatives rejected

- *Fold into DNAT table*: would lose the static-NAT bidirectional
  semantics (the reverse SNAT that rewrites the source back to the
  external IP). Static NAT is its own table by design; extend it.
- *Key DNAT by IP only, store a Vec of port-mappings per IP*: more
  allocation + a linear scan; the (IP, Option<port>) composite key is
  O(1) and matches the existing FxHashMap shape.

## Files touched

- pkg/config/types_security.go
- pkg/config/compiler_nat.go
- pkg/config/schema_security.go (+ schema_walk typed-leaf validation)
- pkg/dataplane/userspace/protocol.go
- pkg/dataplane/userspace/nat.go
- userspace-dp/src/protocol/nat.rs
- userspace-dp/src/nat/static_nat.rs
- userspace-dp/src/afxdp/poll_descriptor/mod.rs
- userspace-dp/src/afxdp/poll_descriptor/nat_exception.rs
- userspace-dp/tests/fixtures/protocol_wire_v1.json (regen)
- docs/config-schema.md, docs/ (NAT)

## Test strategy (fail-on-revert)

- Go: flat-set `ParseSetCommand`+`SetPath` compiles a rule with
  `match destination-port` + `then static-nat prefix … mapped-port …`;
  assert `StaticNATRule.MatchDestinationPort`/`MappedPort`; assert the
  snapshot carries them. Revert (drop the parse) → RED.
- Go schema: invalid port (0, 70000) rejected by SchemaValidate.
- Rust: `from_snapshots` builds the port-keyed entry; `match_dnat`
  rewrites dst + dst_port on the matching port and MISSES a
  non-matching port; `match_snat` un-translates the source port on the
  return packet. Revert (drop the mapped-port rewrite) → RED.
- Rust wire: protocol-wire fixture regenerated, round-trip green.
