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
    // #2506 (Copilot): the term SPECIFIED a source/destination address scope
    // (any literal address OR any prefix-list reference), INDEPENDENT of whether
    // it resolved to any prefixes. The matcher derives "constrained" from THIS,
    // not the resolved list length, so a `from source-prefix-list X` whose X is
    // defined-but-empty or lenient-unresolved (empty list) does not collapse to
    // match-ANY. A constrained direction with an empty positive set matches
    // NOTHING (fail-closed); with `except` set, matches ALL (Junos "not in {}").
    // serde(default) keeps wire parity with an older Go control plane that omits
    // the field (#1961). When BOTH this and the addr list are absent/false, the
    // direction is unconstrained (match-any) — unchanged legacy behavior.
    #[serde(rename = "source_constrained", default)]
    pub source_constrained: bool,
    #[serde(rename = "destination_constrained", default)]
    pub destination_constrained: bool,
    #[serde(default)]
    pub protocols: Vec<String>,
    #[serde(rename = "source_ports", default)]
    pub source_ports: Vec<String>,
    #[serde(rename = "destination_ports", default)]
    pub destination_ports: Vec<String>,
    // #2622: NEGATED port match sets (Junos `from source-port-except` /
    // `destination-port-except`) — match every port EXCEPT these. The compiler
    // turns a non-empty list into a port matcher plus a per-direction `except`
    // flag, and the evaluator computes `(port ∈ ranges) XOR except` with the
    // same fail-closed-on-all-malformed semantics as the address except. These
    // are distinct from the positive source_ports / destination_ports (Junos
    // treats positive and `-except` as mutually-exclusive criteria).
    // serde(default) keeps wire parity with an older Go control plane that omits
    // the field (#1961).
    #[serde(rename = "source_ports_except", default)]
    pub source_ports_except: Vec<String>,
    #[serde(rename = "destination_ports_except", default)]
    pub destination_ports_except: Vec<String>,
    #[serde(rename = "dscp_values", default)]
    pub dscp_values: Vec<u8>,
    #[serde(default)]
    pub action: String,
    // #2544: fall-through. A term whose `then` carries NO terminating action
    // (explicit `then next term` OR a modifier-only term) must APPLY its
    // modifiers (count/log/forwarding-class/policer/dscp) and FALL THROUGH to
    // the next term instead of terminating as Accept (Junos semantics). The Go
    // control plane sets this true for both cases (Action left empty). The
    // compiler maps it to FilterTerm.continue_term; the evaluator continues to
    // the next term on a match instead of returning. serde(default) keeps wire
    // parity with an older Go control plane that omits the field (#1961).
    #[serde(rename = "next_term", default)]
    pub next_term: bool,
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
    // icmp_types / icmp_codes match the ICMP/ICMPv6 type and code bytes (#2545,
    // multi-value). An empty vec = no constraint. A non-empty vec matches if the
    // packet's type/code byte is in the set (match-ANY). A non-ICMP(v6) packet
    // never matches a term that sets them. Previously scalar (`icmp_type`,
    // `icmp_code`): a term carrying two `from icmp-type` values kept only the
    // last, silently dropping the earlier constraint.
    #[serde(rename = "icmp_types", default)]
    pub icmp_types: Vec<u8>,
    #[serde(rename = "icmp_codes", default)]
    pub icmp_codes: Vec<u8>,
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
    /// #2508: per-policy Junos `then log session-init` / `session-close`
    /// selection. Stamped onto the session metadata at install so the
    /// per-policy RT_FLOW SYSLOG records can be emitted only for the
    /// policies the operator configured with `then log`. serde(default)
    /// keeps wire parity with an older Go control plane that omits them.
    #[serde(rename = "log_session_init", default)]
    pub log_session_init: bool,
    #[serde(rename = "log_session_close", default)]
    pub log_session_close: bool,
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
