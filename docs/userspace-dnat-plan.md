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
   keys it under the protocol WILDCARD (`PROTO_ANY = 0`), with
   `DnatTable::lookup_with_counter` falling back to that wildcard after the
   concrete-protocol and wildcard-port lookups miss. A DNAT rule that names a
   concrete non-TCP/UDP protocol (`protocol gre`, `application junos-icmp-all`,
   ...) resolves through `ip_proto::proto_number` (mirrors the Go SSOT
   `appid.ProtocolNumber`) and installs a protocol-scoped entry. Before #2396
   the Rust builder recognized only `tcp`/`udp`/`""` and SILENTLY DROPPED
   everything else (`_ => continue`), and `""`+port-0 expanded to TCP+UDP only
   — so a GRE/ICMP DNAT committed but never reached the dataplane, and an
   IP-only DNAT did NOT cover ICMP, contradicting the original claim here.

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
