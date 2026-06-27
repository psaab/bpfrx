//! NAT rule snapshots (Source/Destination/Static/NAT64/Nptv6) and
//! per-pool status (`SourceNatPoolStatus`). Leaf module — no cross-domain
//! protocol refs.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct SourceNATRuleSnapshot {
    pub name: String,
    /// #2218: compiler-assigned per-rule translation hit-counter id (non-zero;
    /// 0 = no per-rule counter). Mirrors the policy rule_id -> PolicyRuleCounter
    /// design; the helper resolves an `Arc<NatRuleCounter>` from the
    /// coordinator's `NatCounterStore` and increments it once per committed
    /// translated forward flow. #2255: the id is a STABLE key-derived hash, so
    /// it is u32-wide and survives a config reorder/removal — the cumulative
    /// store stays correctly attributed. The JSON wire is unchanged (a number).
    #[serde(rename = "counter_id", default)]
    pub counter_id: u32,
    #[serde(rename = "from_zone", default)]
    pub from_zone: String,
    #[serde(rename = "to_zone", default)]
    pub to_zone: String,
    /// #3096: interface-/routing-instance-scoped rule-set matching. A
    /// non-empty value restricts the rule to flows ingressing/egressing the
    /// named logical interface (config name) or in the named
    /// ingress/egress routing instance (VRF). Empty = unscoped on that axis
    /// (pre-#3096 behavior). The match path AND-s every non-empty scope.
    /// Additive wire fields (#1961): an older control plane omits them; this
    /// helper defaults them to empty (zone-only scope).
    #[serde(rename = "from_interface", default)]
    pub from_interface: String,
    #[serde(rename = "to_interface", default)]
    pub to_interface: String,
    #[serde(rename = "from_routing_instance", default)]
    pub from_routing_instance: String,
    #[serde(rename = "to_routing_instance", default)]
    pub to_routing_instance: String,
    #[serde(rename = "source_addresses", default)]
    pub source_addresses: Vec<String>,
    #[serde(rename = "destination_addresses", default)]
    pub destination_addresses: Vec<String>,
    #[serde(rename = "interface_mode", default)]
    pub interface_mode: bool,
    #[serde(default)]
    pub off: bool,
    #[serde(rename = "pool_name", default)]
    pub pool_name: String,
    #[serde(rename = "pool_addresses", default)]
    pub pool_addresses: Vec<String>,
    #[serde(rename = "port_low", default)]
    pub port_low: u16,
    #[serde(rename = "port_high", default)]
    pub port_high: u16,
    #[serde(rename = "address_persistent", default)]
    pub address_persistent: bool,
    #[serde(rename = "persistent_nat", default)]
    pub persistent_nat: bool,
    #[serde(rename = "persistent_nat_permit_any_remote_host", default)]
    pub persistent_nat_permit_any_remote_host: bool,
    /// #2823: full three-way Junos `persistent-nat permit` enum as a string
    /// ("any-remote-host" | "target-host" | "target-host-port"). Empty =>
    /// fall back to `persistent_nat_permit_any_remote_host` for wire skew
    /// against an older control plane that predates this field.
    #[serde(rename = "persistent_nat_permit", default)]
    pub persistent_nat_permit: String,
    #[serde(rename = "persistent_nat_inactivity_timeout", default)]
    pub persistent_nat_inactivity_timeout: i64,
    #[serde(rename = "pool_unusable", default)]
    pub pool_unusable: bool,
    #[serde(rename = "pool_unusable_reason", default)]
    pub pool_unusable_reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct StaticNATRuleSnapshot {
    pub name: String,
    /// #2218: per-rule translation hit-counter id (see SourceNATRuleSnapshot).
    #[serde(rename = "counter_id", default)]
    pub counter_id: u32,
    #[serde(rename = "from_zone", default)]
    pub from_zone: String,
    /// #3096: interface-/routing-instance-scoped static NAT. Enforced on the
    /// inbound (DNAT) direction against the ingress interface/VRF and on the
    /// reverse (SNAT) direction against the egress interface/VRF. Empty =
    /// unscoped on that axis. Additive wire fields (#1961).
    #[serde(rename = "from_interface", default)]
    pub from_interface: String,
    #[serde(rename = "from_routing_instance", default)]
    pub from_routing_instance: String,
    #[serde(rename = "external_ip", default)]
    pub external_ip: String,
    #[serde(rename = "internal_ip", default)]
    pub internal_ip: String,
    /// #2491: external (pre-translation) destination port the inbound packet
    /// must carry for a port-mapped static-NAT rule. 0 = match any port
    /// (whole-address 1:1, the legacy behaviour).
    #[serde(rename = "match_destination_port", default)]
    pub match_destination_port: u16,
    /// #2491: internal (post-translation) destination port the 1:1 host
    /// receives (`then static-nat prefix <ip> mapped-port <port>`). 0 = no
    /// port translation. When set, the inbound DNAT rewrites the destination
    /// port to this value and the reverse-path SNAT un-translates it back to
    /// `match_destination_port`.
    #[serde(rename = "mapped_port", default)]
    pub mapped_port: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct DestinationNATRuleSnapshot {
    pub name: String,
    /// #2218: per-rule translation hit-counter id (see SourceNATRuleSnapshot).
    #[serde(rename = "counter_id", default)]
    pub counter_id: u32,
    #[serde(rename = "from_zone", default)]
    pub from_zone: String,
    /// #3096: interface-/routing-instance-scoped DNAT, enforced against the
    /// INGRESS interface/VRF (DNAT translates the destination on inbound).
    /// Empty = unscoped on that axis. Additive wire fields (#1961).
    #[serde(rename = "from_interface", default)]
    pub from_interface: String,
    #[serde(rename = "from_routing_instance", default)]
    pub from_routing_instance: String,
    /// #2394: the DNAT rule's `match source-address` constraint. Junos DNAT
    /// `source-address` restricts which source IPs the destination translation
    /// applies to; before #2394 the Go snapshot dropped it, so the helper built
    /// a destination-only entry that DNAT'd traffic from ANY source (fail-open).
    /// Each entry is either a CIDR prefix (`198.51.100.0/24`) or a bare host IP
    /// (`198.51.100.42`); the Go compiler carries the value verbatim. The DNAT
    /// table parser (`nat/destination.rs`) tries `IpNet` first and falls back to
    /// a bare `IpAddr` -> /32 or /128, since `IpNet::from_str` rejects a bare IP.
    /// An empty vec = unscoped DNAT (match any source, unchanged behavior). A
    /// non-empty list whose entries ALL fail to parse fails CLOSED (matches no
    /// source) rather than reverting to match-any.
    #[serde(rename = "source_addresses", default)]
    pub source_addresses: Vec<String>,
    #[serde(rename = "destination_address", default)]
    pub destination_address: String,
    /// #3164: a non-host DNAT `match destination-address` prefix
    /// (`198.51.100.0/24`). ADDITIVE over `destination_address` (#1961): for a
    /// host destination (bare IP, /32, /128) this is empty and the table keys
    /// the O(1) exact `destination_address` map (unchanged fast path). For a
    /// non-host prefix the Go compiler sets this to the canonical masked CIDR
    /// and puts the prefix network address in `destination_address`; the DNAT
    /// table installs a longest-prefix-match entry so every host in the block
    /// is translated to the rule's pool (many:1). An older helper that does not
    /// know this field ignores it and keys only `destination_address` (the
    /// network base) — the pre-#3164 narrowed behavior, never a crash.
    #[serde(rename = "destination_prefix", default)]
    pub destination_prefix: String,
    #[serde(rename = "destination_port", default)]
    pub destination_port: u16,
    #[serde(default)]
    pub protocol: String,
    #[serde(rename = "pool_address", default)]
    pub pool_address: String,
    #[serde(rename = "pool_port", default)]
    pub pool_port: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct NAT64RuleSnapshot {
    pub name: String,
    #[serde(default)]
    pub prefix: String,
    // #2214: null-tolerant. A NAT64 rule with no resolvable source pool
    // makes the Go builder emit `pool_addresses:null` (nil slice, no
    // `,omitempty`); plain `default` would only cover an ABSENT key, so an
    // explicit null would abort the whole snapshot decode (#1961 no-transit).
    #[serde(
        rename = "pool_addresses",
        default,
        deserialize_with = "crate::protocol::null_tolerant_vec"
    )]
    pub pool_addresses: Vec<String>,
    /// Mirrors `security nat natv6v4 no-v6-frag-header`. This is an
    /// option-gated LOCAL DF policy (not the size-driven RFC 7915 5.1
    /// selection): when set, the IPv6->IPv4 translator clears DF so the
    /// translated IPv4 packet stays fragmentable (DF=0, non-atomic) and carries
    /// a generated non-zero, non-repeating Identification (RFC 6864 4.1),
    /// instead of the default DF=1 atomic framing.
    #[serde(rename = "no_v6_frag_header", default)]
    pub no_v6_frag_header: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct Nptv6RuleSnapshot {
    pub name: String,
    #[serde(rename = "from_zone", default)]
    pub from_zone: String,
    #[serde(rename = "internal_prefix", default)]
    pub internal_prefix: String,
    #[serde(rename = "external_prefix", default)]
    pub external_prefix: String,
}

/// #2218: one per-rule NAT translation hit-counter row reported back to the
/// Go control plane inside `ProcessStatus.nat_rule_counters`. Mirrors
/// `PolicyRuleCounterStatus` (security.rs) but keys on the compiler-assigned
/// `counter_id` rather than a rule_id string. The Go struct is
/// `NATRuleCounterStatus` with json tags `counter_id`/`packets`/`bytes`.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct NatRuleCounterStatus {
    #[serde(rename = "counter_id", default)]
    pub counter_id: u32,
    #[serde(rename = "packets", default)]
    pub packets: u64,
    #[serde(rename = "bytes", default)]
    pub bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub(crate) struct SourceNatPoolStatus {
    #[serde(rename = "rule_name", default)]
    pub rule_name: String,
    #[serde(rename = "pool_name", default)]
    pub pool_name: String,
    #[serde(rename = "address_count", default)]
    pub address_count: usize,
    #[serde(rename = "port_low", default)]
    pub port_low: u16,
    #[serde(rename = "port_high", default)]
    pub port_high: u16,
    #[serde(rename = "persistent_nat", default)]
    pub persistent_nat: bool,
    #[serde(rename = "persistent_nat_permit_any_remote_host", default)]
    pub persistent_nat_permit_any_remote_host: bool,
    /// #3193: the full three-way Junos `persistent-nat permit` mode
    /// ("any-remote-host" / "target-host" / "target-host-port"). An empty
    /// string (older helper) falls back to the binary flag above on the
    /// control-plane render side.
    #[serde(rename = "persistent_nat_permit", default)]
    pub persistent_nat_permit: String,
    #[serde(rename = "persistent_nat_inactivity_timeout", default)]
    pub persistent_nat_inactivity_timeout: i64,
    #[serde(rename = "live_flows", default)]
    pub live_flows: u64,
    #[serde(rename = "used_ports", default)]
    pub used_ports: u64,
    #[serde(rename = "persistent_leases", default)]
    pub persistent_leases: u64,
    #[serde(rename = "max_tracked_flows", default)]
    pub max_tracked_flows: u64,
    #[serde(rename = "allocations_total", default)]
    pub allocations_total: u64,
    #[serde(rename = "reuses_total", default)]
    pub reuses_total: u64,
    #[serde(rename = "exhaustion_total", default)]
    pub exhaustion_total: u64,
}
