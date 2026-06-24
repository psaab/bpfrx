//! Security-policy DTOs (screens, firewall filters, policers, three-color
//! policers, flow-export, zone policy rules, policy applications) plus
//! their runtime counter twins. Leaf module — no cross-domain protocol
//! refs.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct ScreenProfileSnapshot {
    pub zone: String,
    #[serde(default)]
    pub land: bool,
    #[serde(rename = "syn_fin", default)]
    pub syn_fin: bool,
    #[serde(rename = "tcp_no_flag", default)]
    pub tcp_no_flag: bool,
    #[serde(rename = "fin_no_ack", default)]
    pub fin_no_ack: bool,
    #[serde(default)]
    pub winnuke: bool,
    #[serde(rename = "ping_death", default)]
    pub ping_death: bool,
    #[serde(default)]
    pub teardrop: bool,
    #[serde(rename = "icmp_fragment", default)]
    pub icmp_fragment: bool,
    /// #1137: TCP SYN packet that's also the first fragment of a
    /// fragmented datagram — a fragmentation-based attack signature.
    #[serde(rename = "syn_frag", default)]
    pub syn_frag: bool,
    #[serde(rename = "source_route", default)]
    pub source_route: bool,
    #[serde(rename = "icmp_flood_threshold", default)]
    pub icmp_flood_threshold: u32,
    #[serde(rename = "udp_flood_threshold", default)]
    pub udp_flood_threshold: u32,
    #[serde(rename = "syn_flood_threshold", default)]
    pub syn_flood_threshold: u32,
    #[serde(rename = "syn_cookie", default)]
    pub syn_cookie: bool,
    #[serde(rename = "session_limit_src", default)]
    pub session_limit_src: u32,
    #[serde(rename = "session_limit_dst", default)]
    pub session_limit_dst: u32,
    #[serde(rename = "port_scan_threshold", default)]
    pub port_scan_threshold: u32,
    #[serde(rename = "ip_sweep_threshold", default)]
    pub ip_sweep_threshold: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct FirewallFilterSnapshot {
    pub name: String,
    #[serde(default)]
    pub family: String,
    // #2214: null-tolerant. A filter declared with zero terms makes the Go
    // builder emit `terms:null` (nil slice, no `,omitempty`); plain `default`
    // only covers an ABSENT key, so an explicit null would abort the whole
    // snapshot decode (#1961 no-transit).
    #[serde(default, deserialize_with = "crate::protocol::null_tolerant_vec")]
    pub terms: Vec<FirewallTermSnapshot>,
}

// ============================================================
// CACHE-KEY INVARIANT (#1431) — read before adding a match field
//
// Every match criterion on FirewallTermSnapshot (and its runtime
// twin FilterTerm in userspace-dp/src/filter/mod.rs) MUST be
// classified as either:
//
//   (a) IN cache key — extend SessionKey in session/key.rs AND
//       prove key stability for HA sync (pkg/cluster/),
//       session-table reverse/NAT/forward-wire indices, flow_cache
//       key derivation, expiry hash bucket math, and reverse-NAT
//       lookup. File a tracker issue against session/key.rs.
//
//   (b) NOT in cache key (cache-sensitive) — wire the #1430
//       runbook: per-interface FilterState.iface_filter_v{4,6}_has_<X>_match
//       set, Filter.has_<X>_match_terms aggregate flag, flow-cache
//       insertion gate at afxdp/flow_cache.rs:297-309, established-
//       session re-evaluation at afxdp/poll_descriptor/mod.rs:217-244,
//       forwarding rotation purge at afxdp/worker/loop_body/mod.rs:295-330,
//       and tests at afxdp/flow_cache_tests.rs.
//
// Skipping this classification SILENTLY breaks flow-cache: a
// first-packet decision gets reused for later packets that can
// differ on the new field. PR #1430 fixed this for DSCP; the same
// class of bug applies to any future per-packet match.
//
// See userspace-dp/src/filter/README.md
//   "Cache-key invariants for per-packet match fields (#1431)"
// for the classification table, the path (a) / path (b) recipes,
// and the canonical reference tests.
// ============================================================
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct FirewallTermSnapshot {
    pub name: String,
    #[serde(rename = "source_addresses", default)]
    pub source_addresses: Vec<String>,
    #[serde(rename = "destination_addresses", default)]
    pub destination_addresses: Vec<String>,
    // #2506: invert the source/destination address match. When true, the term
    // matches every address NOT in source_addresses / destination_addresses
    // (Junos `from source-prefix-list NAME except` / `destination-prefix-list
    // NAME except`). The matcher evaluates `(addr ∈ prefixes) XOR except`.
    // serde(default) keeps wire parity with an older Go control plane that omits
    // the field (#1961).
    #[serde(rename = "source_except", default)]
    pub source_except: bool,
    #[serde(rename = "destination_except", default)]
    pub destination_except: bool,
    #[serde(default)]
    pub protocols: Vec<String>,
    #[serde(rename = "source_ports", default)]
    pub source_ports: Vec<String>,
    #[serde(rename = "destination_ports", default)]
    pub destination_ports: Vec<String>,
    #[serde(rename = "dscp_values", default)]
    pub dscp_values: Vec<u8>,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub count: String,
    #[serde(default)]
    pub log: bool,
    #[serde(default)]
    pub policer: String,
    #[serde(rename = "routing_instance", default)]
    pub routing_instance: String,
    #[serde(rename = "forwarding_class", default)]
    pub forwarding_class: String,
    #[serde(rename = "dscp_rewrite", default)]
    pub dscp_rewrite: Option<u8>,
    // Per-packet L4 match conditions (#2362). Mirror of the Go
    // FirewallTermSnapshot fields. These are NOT in SessionKey, so a filter
    // carrying any of them is cache-sensitive — see the #1431 invariant above
    // and the path-(b) wiring in afxdp/flow_cache.rs.
    //
    // tcp_flags is a required-bits mask over the TCP flags byte (FIN=0x01,
    // SYN=0x02, RST=0x04, PSH=0x08, ACK=0x10, URG=0x20): a TCP packet matches
    // when (flags & mask) == mask. None = no constraint; a non-TCP packet
    // never matches a term that sets it.
    #[serde(rename = "tcp_flags", default)]
    pub tcp_flags: Option<u8>,
    // is_fragment matches any IP fragment (IPv4 MF set OR non-zero offset;
    // IPv6 fragment extension header present).
    #[serde(rename = "is_fragment", default)]
    pub is_fragment: bool,
    // icmp_type / icmp_code match the ICMP/ICMPv6 type and code bytes. None =
    // no constraint; a non-ICMP(v6) packet never matches a term that sets them.
    #[serde(rename = "icmp_type", default)]
    pub icmp_type: Option<u8>,
    #[serde(rename = "icmp_code", default)]
    pub icmp_code: Option<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct PolicerSnapshot {
    pub name: String,
    #[serde(rename = "bandwidth_bps", default)]
    pub bandwidth_bps: u64,
    #[serde(rename = "burst_bytes", default)]
    pub burst_bytes: u64,
    #[serde(rename = "discard_excess", default)]
    pub discard_excess: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct ThreeColorPolicerSnapshot {
    pub name: String,
    #[serde(default)]
    pub mode: String,
    #[serde(rename = "color_blind", default)]
    pub color_blind: bool,
    #[serde(rename = "committed_rate_bytes_per_sec", default)]
    pub committed_rate_bytes_per_sec: u64,
    #[serde(rename = "committed_burst_bytes", default)]
    pub committed_burst_bytes: u64,
    #[serde(rename = "peak_or_excess_rate_bytes_per_sec", default)]
    pub peak_or_excess_rate_bytes_per_sec: u64,
    #[serde(rename = "peak_or_excess_burst_bytes", default)]
    pub peak_or_excess_burst_bytes: u64,
    #[serde(rename = "then_action", default)]
    pub then_action: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct FlowExportSnapshot {
    #[serde(rename = "collector_address", default)]
    pub collector_address: String,
    #[serde(rename = "collector_port", default)]
    pub collector_port: u16,
    #[serde(rename = "sampling_rate", default)]
    pub sampling_rate: u32,
    #[serde(rename = "active_timeout", default)]
    pub active_timeout: u32,
    #[serde(rename = "inactive_timeout", default)]
    pub inactive_timeout: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct PolicyRuleSnapshot {
    #[serde(rename = "rule_id", default)]
    pub rule_id: String,
    #[serde(rename = "policy_id", default)]
    pub policy_id: u32,
    pub name: String,
    #[serde(rename = "from_zone", default)]
    pub from_zone: String,
    #[serde(rename = "to_zone", default)]
    pub to_zone: String,
    #[serde(rename = "scheduler_name", default)]
    pub scheduler_name: String,
    #[serde(default)]
    pub inactive: bool,
    /// Legacy back-compat field (kept on v3 wire). Carries the
    /// FULLY EXPANDED literal CIDRs (union of book content + free
    /// CIDRs). Old Rust uses ONLY this field. New Rust uses ONLY
    /// `source_literals` / `source_book_ids` when the rule is
    /// v3-shaped (see #1606).
    #[serde(rename = "source_addresses", default)]
    pub source_addresses: Vec<String>,
    #[serde(rename = "destination_addresses", default)]
    pub destination_addresses: Vec<String>,
    /// #1606: dense u32 IDs of address books cited by this rule.
    #[serde(rename = "source_book_ids", default)]
    pub source_book_ids: Vec<u32>,
    #[serde(rename = "destination_book_ids", default)]
    pub destination_book_ids: Vec<u32>,
    /// #1606: free-form CIDR / "any" literals the operator wrote
    /// inline in the rule match (NOT via a named address book).
    /// New Rust reads these via the v3-shaped predicate.
    #[serde(rename = "source_literals", default)]
    pub source_literals: Vec<String>,
    #[serde(rename = "destination_literals", default)]
    pub destination_literals: Vec<String>,
    #[serde(default)]
    pub applications: Vec<String>,
    #[serde(rename = "application_terms", default)]
    pub application_terms: Vec<PolicyApplicationSnapshot>,
    #[serde(default)]
    pub action: String,
    /// #2008 H2: invert the source/destination match sense. When set,
    /// the rule matches every address EXCEPT those in the source /
    /// destination set (Junos `source-address-excluded` /
    /// `destination-address-excluded`).
    #[serde(rename = "source_address_excluded", default)]
    pub source_address_excluded: bool,
    #[serde(rename = "destination_address_excluded", default)]
    pub destination_address_excluded: bool,
}

/// #1606: snapshot row for a unique address-book content.
/// Multiple Junos-declared book names whose canonical CIDR sets
/// are identical share one row + one ID. `name` is diagnostic-
/// only (lexicographically smallest declaring name).
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct AddressBookSnapshot {
    /// Stable u32 ID assigned by content-only hashing on the Go
    /// side. ID 0 is reserved as "unused" sentinel.
    pub id: u32,
    #[serde(default)]
    pub name: String,
    #[serde(rename = "prefixes_v4", default)]
    pub prefixes_v4: Vec<String>,
    #[serde(rename = "prefixes_v6", default)]
    pub prefixes_v6: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct PolicyApplicationSnapshot {
    pub name: String,
    #[serde(default)]
    pub protocol: String,
    #[serde(rename = "source_port", default)]
    pub source_port: String,
    #[serde(rename = "destination_port", default)]
    pub destination_port: String,
}

/// One row of the L3/L4 application-identification catalog (#2008 M5). Mirrors
/// the Go `AppCatalogEntrySnapshot` (`pkg/dataplane/userspace/protocol.go`). The
/// dataplane scans these on session create and stamps the matching `app_id` on
/// the conntrack session so `show security flow session` resolves a real
/// application name. Inclusive port boundaries; a `(0, 0)` dst-port pair means
/// "no destination-port constraint" (match on protocol alone, e.g. ICMP) and a
/// `(0, 0)` src-port pair means "no source-port constraint". `app_id` is never
/// 0 (0 is the reserved unknown sentinel). All numeric fields default so a
/// snapshot omitting `app_catalog` (old Go binary) decodes to an empty catalog.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct AppCatalogEntry {
    #[serde(rename = "app_id", default)]
    pub app_id: u16,
    #[serde(default)]
    pub protocol: u8,
    #[serde(rename = "dst_port_low", default)]
    pub dst_port_low: u16,
    #[serde(rename = "dst_port_high", default)]
    pub dst_port_high: u16,
    #[serde(rename = "src_port_low", default)]
    pub src_port_low: u16,
    #[serde(rename = "src_port_high", default)]
    pub src_port_high: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct PolicyRuleCounterStatus {
    #[serde(rename = "rule_id", default)]
    pub rule_id: String,
    #[serde(default)]
    pub packets: u64,
    #[serde(default)]
    pub bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct FirewallFilterTermCounterStatus {
    #[serde(default)]
    pub family: String,
    #[serde(rename = "filter_name", default)]
    pub filter_name: String,
    #[serde(rename = "term_name", default)]
    pub term_name: String,
    #[serde(default)]
    pub packets: u64,
    #[serde(default)]
    pub bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct ThreeColorPolicerStatus {
    #[serde(default)]
    pub id: u32,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub mode: String,
    #[serde(rename = "color_blind", default)]
    pub color_blind: bool,
    #[serde(rename = "green_packets", default)]
    pub green_packets: u64,
    #[serde(rename = "green_bytes", default)]
    pub green_bytes: u64,
    #[serde(rename = "yellow_packets", default)]
    pub yellow_packets: u64,
    #[serde(rename = "yellow_bytes", default)]
    pub yellow_bytes: u64,
    #[serde(rename = "red_packets", default)]
    pub red_packets: u64,
    #[serde(rename = "red_bytes", default)]
    pub red_bytes: u64,
    #[serde(rename = "drop_packets", default)]
    pub drop_packets: u64,
    #[serde(rename = "drop_bytes", default)]
    pub drop_bytes: u64,
}
