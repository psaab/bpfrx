# Userspace Dataplane: Destination NAT Implementation Plan

## 1. Background and Motivation

The eBPF dataplane already supports full DNAT via `dnat_table`/`dnat_table_v6` hash maps. The Go compiler (`pkg/dataplane/compiler.go`) populates these from `DestinationNATConfig` rules at commit time. The Rust AF_XDP userspace dataplane currently supports only interface-mode source NAT and static 1:1 NAT. This plan adds DNAT with port rewriting — the primary missing NAT feature.

### What DNAT Does

DNAT rewrites the destination IP and/or port of incoming packets **before routing** (pre-routing). Use cases:
- **Port forwarding**: `external_ip:port` → `internal_ip:port`
- **Service publishing**: expose internal services on public IPs
- **Load balancing**: redirect to different backend

Key differences from Static NAT:
- Unidirectional (only rewrites destination on inbound; return traffic uses conntrack)
- Can change ports (static NAT doesn't)
- Matches on protocol + port (static NAT matches any protocol)
- Has zone-pair matching (from_zone → to_zone)

## 2. Files to Modify

| File | Change |
|------|--------|
| `pkg/dataplane/userspace/protocol.go` | Add `DestinationNATRuleSnapshot`, field on `ConfigSnapshot`, port fields on sync types |
| `pkg/dataplane/userspace/manager.go` | Add `buildDestinationNATSnapshots()`, wire into snapshot builder |
| `userspace-dp/src/main.rs` | Add `DestinationNATRuleSnapshot` struct, `ConfigSnapshot` field |
| `userspace-dp/src/nat.rs` | Add port fields to `NatDecision`, add `merge()`, add `DnatKey`/`DnatValue`/`DnatTable` |
| `userspace-dp/src/session.rs` | Update `reverse_wire_key()` for port translation |
| `userspace-dp/src/afxdp.rs` | Add `dnat_table` to `ForwardingState`, DNAT lookup in session-miss, port rewriting in `apply_nat_*()` |

No new files needed — all changes are additions to existing files.

## 3. Go Side

### Step 1: Snapshot Type (`protocol.go`)

```go
type DestinationNATRuleSnapshot struct {
    Name               string `json:"name"`
    FromZone           string `json:"from_zone,omitempty"`
    DestinationAddress string `json:"destination_address"`
    DestinationPrefix  string `json:"destination_prefix,omitempty"` // #3164: non-host CIDR; empty for a host
    DestinationPort    uint16 `json:"destination_port,omitempty"`
    Protocol           string `json:"protocol,omitempty"`       // "tcp", "udp", or ""
    PoolAddress        string `json:"pool_address"`
    PoolPort           uint16 `json:"pool_port,omitempty"`
}
```

Each snapshot entry is a pre-expanded table entry: one per (protocol, destination IP, destination port) tuple. The Go builder handles multi-port expansion.

Add to `ConfigSnapshot`:
```go
DestinationNAT []DestinationNATRuleSnapshot `json:"destination_nat_rules,omitempty"`
```

### Step 2: Session Sync Port Fields (`protocol.go`)

Add to `SessionSyncRequest` and `SessionDeltaInfo`:
```go
NATSrcPort uint16 `json:"nat_src_port,omitempty"`
NATDstPort uint16 `json:"nat_dst_port,omitempty"`
```

### Step 3: Snapshot Builder (`manager.go`)

`buildDestinationNATSnapshots(cfg)` follows the same expansion logic as `pkg/dataplane/compiler.go:compileDNAT()`:

1. Iterate `cfg.Security.NAT.Destination.RuleSets`
2. For each rule: resolve match (dst address, protocol, ports) and pool (address, port)
3. If application specified, resolve via `config.ResolveApplication()` to get protocol+ports
4. Expand to one snapshot per (protocol, port) combination
5. Include `from_zone` for zone filtering

Wire into snapshot builder alongside `buildSourceNATSnapshots()`.

## 4. Rust Side

### Step 4: NatDecision Port Fields (`nat.rs`)

```rust
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct NatDecision {
    pub(crate) rewrite_src: Option<IpAddr>,
    pub(crate) rewrite_dst: Option<IpAddr>,
    pub(crate) rewrite_src_port: Option<u16>,
    pub(crate) rewrite_dst_port: Option<u16>,
    pub(crate) nat64: bool,
}
```

Update `reverse()` to accept and reverse ports:
```rust
pub(crate) fn reverse(self, original_src: IpAddr, original_dst: IpAddr,
                       original_src_port: u16, original_dst_port: u16) -> Self {
    Self {
        rewrite_src: self.rewrite_dst.map(|_| original_dst),
        rewrite_dst: self.rewrite_src.map(|_| original_src),
        rewrite_src_port: self.rewrite_dst_port.map(|_| original_dst_port),
        rewrite_dst_port: self.rewrite_src_port.map(|_| original_src_port),
        nat64: self.nat64,
    }
}
```

Add `merge()` for combining DNAT + SNAT:
```rust
pub(crate) fn merge(self, other: NatDecision) -> Self {
    Self {
        rewrite_src: self.rewrite_src.or(other.rewrite_src),
        rewrite_dst: self.rewrite_dst.or(other.rewrite_dst),
        rewrite_src_port: self.rewrite_src_port.or(other.rewrite_src_port),
        rewrite_dst_port: self.rewrite_dst_port.or(other.rewrite_dst_port),
        nat64: self.nat64 || other.nat64,
    }
}
```

### Step 5: DNAT Table (`nat.rs`)

```rust
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) struct DnatKey {
    pub protocol: u8,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct DnatValue {
    pub new_dst_ip: IpAddr,
    pub new_dst_port: u16,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct DnatTable {
    entries: FxHashMap<DnatKey, DnatValue>,
}
```

Lookup strategy:
1. Exact match on `(protocol, dst_ip, dst_port)`
2. Wildcard port fallback: `(protocol, dst_ip, 0)` for IP-only DNAT rules
3. Protocol expansion: `protocol=""` entries expand to both TCP(6) and UDP(17) at parse time

### Step 6: Reverse Wire Key (`session.rs`)

```rust
fn reverse_wire_key(forward_key: &SessionKey, nat: NatDecision) -> SessionKey {
    let (src_port, dst_port) = if matches!(forward_key.protocol, PROTO_ICMP | PROTO_ICMPV6) {
        (forward_key.src_port, forward_key.dst_port)
    } else {
        (
            nat.rewrite_dst_port.unwrap_or(forward_key.dst_port),
            nat.rewrite_src_port.unwrap_or(forward_key.src_port),
        )
    };
    SessionKey {
        addr_family: forward_key.addr_family,
        protocol: forward_key.protocol,
        src_ip: nat.rewrite_dst.unwrap_or(forward_key.dst_ip),
        dst_ip: nat.rewrite_src.unwrap_or(forward_key.src_ip),
        src_port,
        dst_port,
    }
}
```

Logic: when DNAT translates `forward_key.dst_port` to `new_dst_port`, the reply from the server uses `new_dst_port` as its source port. So in the reverse key, `src_port = nat.rewrite_dst_port` (the translated port the server sees).

### Step 7: Session-Miss Path Integration (`afxdp.rs`)

The critical design point: **DNAT must happen before routing** because the translated destination affects the FIB lookup result.

New sequence in session-miss path (~line 2310):
```
1. Extract packet 5-tuple
2. DNAT table lookup by (protocol, dst_ip, dst_port)
3. If no DNAT match: static NAT DNAT lookup
4. If DNAT/static match: use translated destination for FIB lookup
5. FIB lookup (with translated destination)
6. Zone pair determination
7. Policy evaluation
8. Source NAT matching
9. MERGE DNAT + SNAT decisions (fix existing overwrite bug)
10. Session creation with merged NatDecision
```

**Bug fix**: The current code at `afxdp.rs:2449` overwrites any pre-routing DNAT decision when SNAT matches:
```rust
// Before (BUG: overwrites DNAT):
decision.nat = match_source_nat_for_flow(...).unwrap_or_default();

// After (CORRECT: merge DNAT + SNAT):
let snat_decision = match_source_nat_for_flow(...).unwrap_or_default();
decision.nat = decision.nat.merge(snat_decision);
```

### Step 8: Port Rewriting in `apply_nat_*()` (`afxdp.rs`)

After IP rewriting, add L4 port rewriting:
```rust
if let Some(new_dst_port) = nat.rewrite_dst_port {
    if matches!(protocol, PROTO_TCP | PROTO_UDP) {
        let port_offset = l4_offset + 2;  // TCP/UDP dest port at offset +2
        let old_port = u16::from_be_bytes([packet[port_offset], packet[port_offset + 1]]);
        if old_port != new_dst_port {
            packet[port_offset..port_offset + 2].copy_from_slice(&new_dst_port.to_be_bytes());
            adjust_l4_checksum_port(packet, l4_offset, protocol, old_port, new_dst_port)?;
        }
    }
}
```

Port changes only affect L4 checksum (not IP header checksum). The incremental update is a simple 16-bit ones-complement subtraction/addition — same math as IP address changes. Port rewriting must happen AFTER IP rewriting to avoid double-counting in the checksum.

### Step 9: Local Address Registration

DNAT destination IPs must be recognized as locally-owned (otherwise traffic to those IPs gets forwarded elsewhere instead of being processed):
```rust
for dst_ip in state.dnat_table.destination_ips() {
    match dst_ip {
        IpAddr::V4(v4) => { state.local_v4.insert(v4); }
        IpAddr::V6(v6) => { state.local_v6.insert(v6); }
    }
}
```

## 5. Session Sync and HA

Session deltas and sync messages need the new port fields so DNAT state survives failover:
- Build: include `nat_src_port`/`nat_dst_port` in `SessionDeltaInfo`
- Parse: reconstruct port fields in `NatDecision` from sync request

## 6. Hit Counters

Initial implementation: use the existing per-binding `dnat_packets` counter (already in `BindingStatus`). Per-rule counters can be added later via a `Vec<u64>` in `DnatTable` indexed by rule position.

## 7. Testing Strategy

### Unit Tests

| # | Test | Location |
|---|------|----------|
| 1 | Basic DNAT lookup (TCP:203.0.113.10:80 → 192.168.1.10:8080) | `nat.rs` |
| 2 | Wildcard port fallback (port=0 matches any) | `nat.rs` |
| 3 | Protocol specificity (TCP entry, UDP miss) | `nat.rs` |
| 4 | IPv6 DNAT | `nat.rs` |
| 5 | Multiple entries, each matches correctly | `nat.rs` |
| 6 | No match returns None | `nat.rs` |
| 7 | Port-aware reverse (DNAT port rewrite) | `nat.rs` |
| 8 | DNAT+SNAT merge preserves both translations | `nat.rs` |
| 9 | Default NatDecision unchanged | `nat.rs` |
| 10 | DNAT port in reverse wire key | `session.rs` |
| 11 | DNAT+SNAT ports in reverse key | `session.rs` |
| 12 | ICMP port handling unchanged | `session.rs` |
| 13 | TCP checksum after port rewrite | `afxdp.rs` |
| 14 | IP + port combined rewrite checksum | `afxdp.rs` |
| 15 | UDP zero-checksum skip | `afxdp.rs` |

### Integration Tests

| # | Test |
|---|------|
| 16 | Port forwarding: external:8080 → internal:80, verify DNAT and session |
| 17 | DNAT + SNAT combination (port forwarding with interface SNAT) |
| 18 | Return traffic hits reverse session with correct reverse NAT |
| 19 | Multi-port DNAT (same IP, different port mappings) |
| 20 | IP-only DNAT (port=0 wildcard) |

## 8. Implementation Sequence

1. `NatDecision` port fields + `merge()` + `reverse()` update (`nat.rs`)
2. `DnatTable` structures + unit tests (`nat.rs`)
3. `reverse_wire_key` port handling (`session.rs`, `afxdp.rs`)
4. Go snapshot types (`protocol.go`)
5. Go snapshot builder (`manager.go`)
6. Rust snapshot parsing (`main.rs`)
7. `ForwardingState` + snapshot application (`afxdp.rs`)
8. Session-miss path integration + SNAT overwrite fix (`afxdp.rs`)
9. Port rewriting in `apply_nat_*()` (`afxdp.rs`)
10. Session sync protocol port fields (`protocol.go`, `afxdp.rs`)
11. End-to-end testing

## 9. Risks and Considerations

1. **SNAT overwrite bug (existing)**: Current code at `afxdp.rs:2449` overwrites any pre-routing DNAT decision when SNAT matches. The `merge()` fix resolves this for both static NAT and new DNAT.

2. **ICMP / non-TCP-UDP DNAT** (corrected #2396): ICMP has no ports, so
   port-matching DNAT doesn't apply to it. An IP-only DNAT (no protocol, no
   port) now genuinely covers ALL L4 protocols including ICMP/ICMPv6/GRE: the
   builder emits it with an empty `protocol` and zero port, and the Rust table
   keys it under a protocol WILDCARD sentinel, with
   `DnatTable::lookup_with_counter` falling back to that wildcard after the
   concrete-protocol and wildcard-port lookups miss. A DNAT rule that names a
   concrete non-TCP/UDP protocol (`protocol gre`, `application junos-icmp-all`,
   ...) resolves through `ip_proto::proto_number` (mirrors the Go SSOT
   `appid.ProtocolNumber`) and installs a protocol-scoped entry. The token is
   normalized (trim + lower-case) on both sides, and an unresolvable
   `match protocol` token is hard-rejected at commit by
   `validateDestinationNATProtocolStrict` (lenient-warn on tolerant load)
   rather than silently dropped.

   The wildcard sentinel is `PROTO_ANY = 256` — `DnatKey.protocol` is a `u16`
   so the sentinel sits OUTSIDE the 0-255 IANA range and is DISTINCT from every
   real protocol, including protocol `0` (HOPOPT). The first cut used
   `PROTO_ANY = 0`, which COLLIDED with HOPOPT: a `protocol 0` DNAT would have
   keyed under the wildcard and broadened to match every protocol. With the u16
   key, `protocol 0` is a normal exact match and only `""` (no protocol, no
   port) uses the wildcard. Before #2396 the Rust builder recognized only
   `tcp`/`udp`/`""` and SILENTLY DROPPED everything else (`_ => continue`), and
   `""`+port-0 expanded to TCP+UDP only — so a GRE/ICMP DNAT committed but never
   reached the dataplane, and an IP-only DNAT did NOT cover ICMP, contradicting
   the original claim here.

3. **Session key stability**: Forward session key uses the ORIGINAL 5-tuple (pre-DNAT). The translation is carried in `NatDecision`. Matches static NAT pattern.

4. **Worker isolation**: Each worker has its own `ForwardingState` snapshot with cloned `DnatTable`. No locking needed.

5. **Backward compatibility**: New `destination_nat_rules` JSON field defaults to empty array. Old binaries ignore it (serde `default`).

6. **Checksum ordering**: Port rewriting must happen AFTER IP rewriting. Both are independent incremental updates to the L4 checksum.

## 10. Source-address constraint (#2394)

Junos DNAT `match source-address` restricts which source IPs the destination
translation applies to. The original DNAT implementation parsed the constraint
into the typed rule but dropped it at the Go->Rust snapshot boundary, so the
helper installed a destination-only entry that DNAT'd traffic from ANY source —
a fail-open that published the internal service to sources the operator scoped
out.

#2394 carries the constraint end to end:

- `DestinationNATRuleSnapshot.SourceAddresses` (Go, `protocol.go`) /
  `source_addresses` (Rust, `protocol/nat.rs`) — a new wire field
  (`json:"source_addresses,omitempty"`, serde `default`). Old binaries ignore
  it; an absent/empty list means "match any source" so unscoped DNAT is
  unchanged. The default-specimen wire fixture (`protocol_wire_v1.json`) was
  regenerated.
- `buildDestinationNATSnapshots` (`nat.go`) populates the field from
  `rule.Match.SourceAddresses` with a singular `SourceAddress` fallback,
  mirroring the SNAT builder.
- `DnatEntry.{source_constrained, source_v4, source_v6}`
  (`nat/destination.rs`) hold whether the rule was scoped and the parsed
  prefixes. `DnatEntry::source_matches(src_ip)` returns: unscoped
  (`source_constrained == false`) -> match any; scoped but all entries
  unparseable (both prefix vecs empty) -> match NOTHING (fail closed); else
  the packet source must fall in a parsed prefix of its own family. The lookup
  takes `src_ip` and filters on both zone and source. The per-key dedup keys on
  `(from_zone, source_constrained, source_v4, source_v6)` so two distinct
  source-scoped rules on the same destination both survive (and an unscoped
  rule never collapses onto a fully-malformed scoped rule).
- The session-miss caller (`afxdp/poll_descriptor/mod.rs`) passes
  `flow.forward_key.src_ip`.

### Bare-host source + all-malformed (Copilot fold)

Junos carries `match source-address` verbatim and the Go compiler does NOT
normalize it, so a bare host (`set ... match source-address 198.51.100.42`,
no `/prefix`) reaches the wire without a mask. `IpNet::from_str` REQUIRES
`addr/prefix` form and rejects a bare IP. The first cut skipped any entry that
failed `IpNet` parse, so a bare-host source-scoped DNAT left its prefix lists
empty and matched ANY source — the #2394 fail-open reintroduced for bare IPs.

Two robustness fixes (the DNAT sibling of #2398 SNAT):

1. **Bare-IP fallback** — each source entry is parsed as `IpNet`; on failure it
   falls back to a bare `IpAddr` -> /32 (v4) or /128 (v6). So `198.51.100.42`
   matches only that host and the doc claim ("a bare host parses as /32/128")
   is now true.
2. **All-malformed -> fail-closed** — `source_constrained` (set when the
   snapshot source list is non-empty) distinguishes "unscoped rule -> match
   any" from "scoped rule, zero entries parsed -> match none". A scoped rule
   whose entries all fail to parse matches nothing rather than reverting to
   match-any. A mix of valid + garbage entries keeps the valid prefixes.

### Address-book-name source scope (#2416)

`match source-address` (#2394) takes literal prefixes; the sibling
`match source-address-name <book-entry>` takes an **address-book reference**.
The compiler parsed it into `NATMatch.SourceAddressName` but never resolved it
into the source list `buildDestinationNATSnapshots` reads, so a name-scoped DNAT
published an EMPTY `source_addresses` = `source_constrained == false` = match
ANY source — the same fail-open as #2394 for the named variant. SNAT shared the
gap (its match switch did not even parse the keyword, and the schema did not
expose it).

#2416 closes it:

- `appendNATSourceAddressName` (`nat.go`) resolves the name via
  `resolveUserspaceAddressBookEntry` — the same global-address-book expander the
  security-policy snapshot path uses — and appends the concrete prefixes to the
  rule's source list. Both `buildDestinationNATSnapshots` and
  `buildSourceNATSnapshots` call it.
- Fail-closed on an unknown / unresolvable name: the raw token is appended so
  the source list stays non-empty (`source_constrained` stays true) while the
  token fails `IpAddr`/`IpNet` parse and contributes no prefix — the rule
  matches NOTHING, never collapsing back to match-any. This reuses the existing
  #2394/#2398 all-malformed -> fail-closed Rust path; no wire change.
- The SNAT match parser (`compiler_nat.go`) now reads `source-address-name`, and
  the SNAT `match` schema (`schema_security.go`) exposes the keyword (DNAT
  already did).
- `validateNATSourceAddressNameReferencesStrict` (`compiler_validate_strict.go`)
  hard-rejects an undefined reference at commit / commit-check so the typo is
  operator-visible; the tolerant load / peer-sync path downgrades to a warning
  (`lenientFirewallRefs`, #1960) and the dataplane backstop fails closed. Mirrors
  the firewall prefix-list / policer reference gates.

### Static-NAT source-address (#3435)

`match source-address` on a **static** NAT rule is the bidirectional 1:1/DNAT
analog of the DNAT constraint above. It was accepted by the schema and stored
by the compiler, but dropped before runtime — the static snapshot had no source
field and the Rust matcher never checked source, so a rule meant to expose an
internal host only to selected client prefixes installed as an all-source
mapping (fail-open exposure broadening, H01). Separately the typed value was
truncated to a single scalar despite the schema's `multi: true`, so
bracket/repeated lists lost every prefix after the first (M02).

#3435 mirrors #2394 end to end:

- `StaticNATRule.SourceAddresses` (`types_security.go`) holds the full list;
  `compileNATStatic` (`compiler_nat.go`) appends `m.Keys[1:]` + child names
  (closing M02) and keeps the singular `SourceAddress` as the first element for
  back-compat (the NAT64 `::/0` readers, peer sync).
- `StaticNATRuleSnapshot.SourceAddresses` (Go `protocol.go` /
  `source_addresses` Rust `protocol/nat.rs`) — a new additive wire field
  (`json:"source_addresses,omitempty"`, serde `default`). Empty = match any
  source (unscoped, unchanged). `protocol_wire_v1.json` was regenerated.
- `buildStaticNATSnapshots` (`nat.go`) populates it from `rule.SourceAddresses`
  with the singular `SourceAddress` fallback.
- `static_nat.rs` parses the list into a `SourceConstraint`
  (`{constrained, v4, v6}`) on each `StaticNatEntry` and `StaticNatBlock`
  (host AND #3031 block paths). `SourceConstraint::matches`: unconstrained ->
  match any; constrained but zero entries parsed -> match NOTHING (fail closed,
  the #2394/#3435 guard); else the peer must fall in a parsed prefix of its
  family. Bare-host fallback to /32 /128 (IpNet rejects a bare IP) is shared
  with the DNAT path.
- **Direction.** The inbound `match_dnat_with_counter_scoped` gates on the
  packet SOURCE (`flow.forward_key.src_ip`, `poll_descriptor/mod.rs`); the
  reverse `match_snat_with_counter_scoped` gates on the packet DESTINATION (the
  original client, `flow.forward_key.dst_ip`, `nat_exception.rs`), symmetric
  with the #2871 egress-zone gate. The new peer argument is `Option<IpAddr>`;
  the non-scoped / test wrappers pass `None` (source gate skipped), the
  production scoped callers pass `Some(..)`.

## 11. Multiple destination-addresses (#2395)

Junos DNAT `match destination-address [ A B C ]` publishes the SAME
translation for several external destinations. The compiler already parsed the
full list into `rule.Match.DestinationAddresses` (with `DestinationAddress`
mirroring the first element), but `buildDestinationNATSnapshots` iterated only
the singular `DestinationAddress`. The rule therefore collapsed to its FIRST
destination — traffic to B and C was forwarded untranslated (configured
translation silently not applied; HIGH).

The DNAT table is keyed by exact destination IP (`DnatKey.dst_ip`,
`nat/destination.rs`), so the natural fix is **one snapshot entry per
destination** sharing the rule's pool/port/counter — no wire change (the
existing scalar `destination_address` field is reused; `protocol_wire_v1.json`
is unchanged).

- `buildDestinationNATSnapshots` (`nat.go`) now builds `destAddrs` from
  `rule.Match.DestinationAddresses` with a singular `DestinationAddress`
  fallback (mirrors the #2394 source-address idiom), then emits one
  `DestinationNATRuleSnapshot` per destination inside the existing
  app-term/port loop. Each destination has its CIDR suffix stripped (DNAT
  matches exact host IPs) and is validated with `net.ParseIP`.
- **Fail-closed on all-malformed** — a destination that is empty or not a bare
  host IP is skipped. If a rule has destinations but EVERY one is malformed, no
  snapshot row is emitted, so the rule matches NOTHING rather than broadening
  to match-any. (The Rust `from_snapshots` also `continue`s on a destination it
  cannot `IpAddr::parse`, so the fail-closed posture holds on both sides.)
- **Composition with #2394** — the per-destination loop is nested inside the
  source-constraint setup, so every emitted per-destination snapshot carries
  the same `SourceAddresses`. A source-scoped multi-destination DNAT fires for
  each destination only when the source also matches; neither constraint is
  regressed.

The rewrite target (translated destination/port from the pool) is unchanged —
only the MATCH set grows from one destination to all configured destinations.

### 11.1 Per-entry commit gate on a partial-valid list (#3228)

The all-malformed fail-closed posture above (no snapshot row when EVERY
destination is malformed) is caught at commit by
`validateDestinationNATAddressesStrict` (`compiler_validate_strict.go`). That
gate originally used an `anyGood` break: it passed commit as long as AT LEAST
ONE destination parsed. But the builder skips malformed entries PER-ENTRY, so a
MIXED list such as `match destination-address [ 192.0.2.1 web-server ]`
committed clean (one good entry satisfied `anyGood`) while `web-server` was
silently dropped from the installed DNAT table — traffic to it was never
translated, a partial, silent drop of a forwarding-relevant config (#3228).

The gate now rejects the rule if ANY listed destination-address fails to parse,
mirroring the builder's exact skip predicate (`natCIDRIPPart` CIDR strip, then
empty / `net.ParseIP` check). Validator and dataplane view agree: anything the
builder would drop, the validator rejects, naming the offending entry. An
all-valid list still compiles byte-identical and installs every entry (the
multi-destination behavior above is unchanged). On the tolerant load / peer-sync
path the rejection is downgraded to a `destination-nat address` warning (#1960
no-brick), consistent with the all-malformed (#2396(c)) gate that shares this
validator. (The multi-host-prefix reject — #3029 — was removed by #3164, which
implements prefix matching; see §12.)

## 12. Multi-host-prefix destination matching (#3164)

Junos DNAT `match destination-address` accepts a non-host CIDR prefix
(`198.51.100.0/24`): every host in the block is translated to the rule's pool.
Before #3164 the builder STRIPPED the `/mask` and emitted only the network base
as an exact host, and the Rust `DnatTable` keyed on an exact `IpAddr` — so only
the network address translated and every other host in the block bypassed DNAT
(silent under-translation). #3029 (PR #3162) closed the fail-open by REJECTING a
multi-host prefix at commit; #3164 implements the feature and removes that
reject.

**Scope.** A prefix destination is a many:1 MATCH to the configured pool (the
same translation the host case uses). Block-mapping semantics — a 1:1
host-N->host-N offset map between a destination prefix and a pool prefix — are
the unsettled design fork called out in #3164 and remain OUT OF SCOPE; the pool
is a single address (range support is the existing pool behavior, unchanged).

**Wire (additive, #1961).** A new `destination_prefix` field on
`DestinationNATRuleSnapshot` carries the canonical masked CIDR for a non-host
prefix; `destination_address` keeps the network base. For a host (bare IP, /32,
/128) `destination_prefix` is empty and the exact `destination_address` path is
used, byte-identical to pre-#3164. An older helper ignores the new field and
keys only `destination_address` (the network base) — the pre-#3164 narrowed
behavior, never a crash. `protocol_wire_v1.json` gains exactly the one
`destination_prefix: ""` key.

- `dnatDestinationParts` (`nat.go`) is the single host-vs-prefix classifier: a
  bare IP or a canonical host mask (/32, /128) is a HOST (base = address, prefix
  = ""); a non-host CIDR is a BLOCK (base = network address, prefix = canonical
  masked CIDR). It normalizes a non-canonical input (`198.51.100.7/24` ->
  base `198.51.100.0`, prefix `198.51.100.0/24`). An unparseable token returns
  `ok == false` and is skipped (fail-closed, same as before).
- The Rust `DnatTable` keeps the O(1) exact-host `entries` map for hosts and adds
  a `prefix_entries` map keyed by `(protocol, dst_port)` whose value is a vec of
  prefix slots. `lookup_with_counter` probes the exact map first (a host is the
  longest possible prefix, so it always wins), then falls back to a
  longest-prefix-match scan over `prefix_entries` using the SAME three proto/port
  tiers (exact proto+port, wildcard port, `PROTO_ANY`). Within a tier the LONGEST
  matching prefix wins; zone-specific entries beat zone-wildcard entries and the
  `match source-address` constraint (#2394) is enforced unchanged.

**Local-address registration is bounded.** `destination_ips()` (consumed by
`forwarding_build` to populate `local_v4`/`local_v6` for proxy-ARP/ND) expands a
prefix host-by-host only when the block is at or below `MAX_LOCAL_PREFIX_HOSTS`
(4096 usable hosts — a v4 /20 or longer; a v6 block must be host-scale). A larger
block registers only its network base and must be ROUTED to the firewall. The
DNAT MATCH is independent of this set (the pre-routing lookup keys on the packet
destination directly), so a large block is still translated in full — only
on-segment proxy-ARP for the whole block is bounded.

## 13. `match destination-port` range validation (#3446)

Source- and destination-NAT `match destination-port` had NO range validation
(unlike static NAT, which validates its typed `destination-port` leaf 1..65535
at commit — #2491). The parser (`parseDNATPortList`, `compiler_nat.go`) used a
bare `strconv.Atoi` with no bound check and dropped a non-numeric token
silently; the snapshot builders cast the value straight to `uint16`. The result
was three silent failure modes:

- **H12** — `match destination-port 0` installed the WILDCARD port (Rust treats
  `dst_port == 0` as "match any"), so the rule translated EVERY port.
- **H13** — `70000` wrapped to `4464` and `-1` to `65535` on the `uint16` cast,
  so the rule DNAT'd the wrong external port.
- **H14** — a non-numeric token (`http`) failed `Atoi`, was dropped, left an
  empty port list, and fell back to the wildcard port — again translating every
  port instead of failing closed.

**Commit gate.** `validateNATMatchDestinationPortStrict` (`compiler_validate_strict.go`)
hard-rejects a source- or destination-NAT rule whose `match destination-port`
carries a 0/negative/>65535 number or a non-numeric token. It runs after the
DNAT match-protocol gate and shares the `lenientDestNATAddresses` flag, so on
the tolerant load / peer-sync path (#1960) it downgrades to a warning rather
than bricking a config persisted before the gate existed. To see a non-numeric
token at commit (it never parses to an int), `parseDNATPortList` now returns the
unparseable raw tokens alongside the numeric ports; the compiler stores them on
`NATMatch.InvalidDestinationPorts` (the `to` range keyword and `[`/`]`
bracket-list delimiters are never reported). Out-of-range NUMBERS still flow
through `DestinationPorts` and are range-checked directly.

**Dataplane fail-closed (lenient backstop).** The source-NAT builder was already
fail-closed (`coalescePortRanges` / `sourceNATDestPortRanges` skip out-of-range
values and emit the `natNeverMatchPortRange` sentinel when a configured list
coalesces to nothing — #3429). The destination-NAT builder
(`buildDestinationNATSnapshotsWithFeeds`) now matches that doctrine: it filters
each term's ports to 1..65535, and when a port WAS configured (numeric list
non-empty, or `InvalidDestinationPorts` non-empty on the explicit-match
fallback) but no valid port survives, it emits NO snapshot for the term so the
rule matches NOTHING — it never widens to the wildcard port. A rule with no
`destination-port` at all still emits the genuine wildcard (`destination_port:
0`), unchanged.

**Wire.** No new wire field. `InvalidDestinationPorts` is compiler-internal
(never serialized to the helper); the builder uses the existing
`destination_port` slot and simply drops a term that would have wildcarded, so
`protocol_wire_v1.json` is unchanged.

## 14. DNAT pool port/address validation (#3450)

A destination-NAT **pool**'s translated `port` and `address` had NO strict
commit validation (the analog of §13, which validates the rule's `match`
ports). The pool parser (`compileNATDestination`, `compiler_nat.go`) used a bare
`strconv.Atoi` for the port (no bound check, non-numeric silently dropped to
`Port == 0`) and stored the address verbatim; the snapshot builder
(`buildDestinationNATSnapshotsWithFeeds`) cast the port to `uint16` and stripped
any CIDR suffix from the address. Junos expresses the pool port as `address port
<N>` (nested under the address leaf), which the pre-#3450 parser mis-handled —
it set `Address` to the literal `"port"` and dropped the port entirely. The
result was four silent failure modes:

- **M03** — `port 70000` wrapped to `4464` (and `-1` to `65535`) on the `uint16`
  cast, so traffic was rewritten to an unintended backend port.
- **M04** — `port 0` / `port httpp` collapsed to `Port == 0`, which the Rust
  DNAT path treats as "preserve the destination port" — the requested rewrite
  was silently a no-op.
- **M05** — `address 10.0.0.0/24` had its CIDR stripped to the network base
  `10.0.0.0`, so all matching traffic was translated to the network base (no
  pool/range semantics).
- **M06** — `address web-server` (an address-book name) committed clean but the
  Rust `DnatTable` failed to parse it and `continue`d, so the rule installed NO
  entry and the VIP was silently untranslated.

**Parser.** `parseDNATPoolAddress` now walks every token of an `address`
statement (and its children for the hierarchical shape), capturing the
translated address AND a nested `port <N>` separately — so `address 10.0.1.100/32`
plus `address port 80` yields `Address = 10.0.1.100/32`, `Port = 80` instead of
`Address = "port"`. The raw port token is preserved on `NATPool.PortRaw` so a
configured port (which must be 1..65535) is distinguishable from no `port` leaf
at all (`Port == 0` = the legitimate preserve-destination-port mode). The
top-level `port <N>` form is still accepted.

**Commit gate.** `validateDNATPoolStrict` (`compiler_validate_strict.go`)
hard-rejects a DNAT pool whose configured port is 0/negative/>65535/non-numeric
(only when `PortRaw` is set — no port leaf is left untouched) or whose address
is empty or not a single host (a bare IP, /32, or /128 — `isHostMaskAddress`,
the same predicate static NAT uses). It runs after the §13 match-dest-port gate
and shares the `lenientDestNATAddresses` flag, so on the tolerant load /
peer-sync path (#1960) it downgrades to a warning rather than bricking a config
persisted before the gate existed.

**Dataplane fail-closed (lenient backstop).** The builder now resolves the pool
address through `dnatPoolHostIP` (bare IP / /32 / /128 → the bare host string;
non-host CIDR or non-IP token → not ok) and skips the whole rule when the
address is unusable or when a configured pool port is out of 1..65535. So a
leniently-loaded bad pool installs NO entry (matches nothing) rather than
wrapping the port, coercing the address to a network base, or emitting an entry
the Rust side drops. A pool with a valid host address and no port leaf still
emits the genuine preserve-destination-port entry, unchanged.

**Wire.** No new wire field. `PortRaw` is compiler-internal (never serialized);
the builder uses the existing `pool_address` / `pool_port` slots and simply
drops a rule that would have translated wrongly, so `protocol_wire_v1.json` is
unchanged.
