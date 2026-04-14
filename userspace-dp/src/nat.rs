use crate::prefix::{PrefixV4, PrefixV6};
use crate::{DestinationNATRuleSnapshot, SourceNATRuleSnapshot, StaticNATRuleSnapshot};
use ipnet::IpNet;
use rustc_hash::FxHashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU32, Ordering};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct NatDecision {
    pub(crate) rewrite_src: Option<IpAddr>,
    pub(crate) rewrite_dst: Option<IpAddr>,
    pub(crate) rewrite_src_port: Option<u16>,
    pub(crate) rewrite_dst_port: Option<u16>,
    /// When true, this is a NAT64 cross-address-family translation.
    /// The forward session key is IPv6 and the reverse session key is IPv4
    /// (or vice versa for the return direction).
    pub(crate) nat64: bool,
    /// When true, this is an NPTv6 (RFC 6296) stateless prefix translation.
    /// No L4 checksum update is needed -- the prefix rewrite is checksum-neutral.
    pub(crate) nptv6: bool,
}

impl NatDecision {
    pub(crate) fn reverse(
        self,
        original_src: IpAddr,
        original_dst: IpAddr,
        original_src_port: u16,
        original_dst_port: u16,
    ) -> Self {
        Self {
            rewrite_src: self.rewrite_dst.map(|_| original_dst),
            rewrite_dst: self.rewrite_src.map(|_| original_src),
            rewrite_src_port: self.rewrite_dst_port.map(|_| original_dst_port),
            rewrite_dst_port: self.rewrite_src_port.map(|_| original_src_port),
            nat64: self.nat64,
            nptv6: self.nptv6,
        }
    }

    /// Merge two NAT decisions, preferring fields already set in `self`.
    /// Used to combine a pre-routing DNAT decision with a post-policy SNAT decision.
    pub(crate) fn merge(self, other: NatDecision) -> Self {
        Self {
            rewrite_src: self.rewrite_src.or(other.rewrite_src),
            rewrite_dst: self.rewrite_dst.or(other.rewrite_dst),
            rewrite_src_port: self.rewrite_src_port.or(other.rewrite_src_port),
            rewrite_dst_port: self.rewrite_dst_port.or(other.rewrite_dst_port),
            nat64: self.nat64 || other.nat64,
            nptv6: self.nptv6 || other.nptv6,
        }
    }
}

/// Round-robin port allocator for pool-mode SNAT.
///
/// Each pool address gets its own atomic counter. Ports are allocated by
/// incrementing the counter and wrapping within [port_low, port_high].
/// No per-port tracking — session expiry naturally frees ports.
#[derive(Debug)]
pub(crate) struct PortAllocator {
    /// One atomic counter per pool address, used for round-robin port allocation.
    counters: Vec<AtomicU32>,
    /// Index for round-robin address selection.
    addr_counter: AtomicU32,
    pub(crate) port_low: u16,
    pub(crate) port_high: u16,
}

impl Clone for PortAllocator {
    fn clone(&self) -> Self {
        Self {
            counters: self
                .counters
                .iter()
                .map(|c| AtomicU32::new(c.load(Ordering::Relaxed)))
                .collect(),
            addr_counter: AtomicU32::new(self.addr_counter.load(Ordering::Relaxed)),
            port_low: self.port_low,
            port_high: self.port_high,
        }
    }
}

impl Default for PortAllocator {
    fn default() -> Self {
        Self {
            counters: Vec::new(),
            addr_counter: AtomicU32::new(0),
            port_low: 1024,
            port_high: 65535,
        }
    }
}

impl PortAllocator {
    pub(crate) fn new(num_addresses: usize, port_low: u16, port_high: u16) -> Self {
        let counters = (0..num_addresses).map(|_| AtomicU32::new(0)).collect();
        Self {
            counters,
            addr_counter: AtomicU32::new(0),
            port_low,
            port_high,
        }
    }

    /// Pick the next pool address index (round-robin).
    pub(crate) fn next_address_index(&self) -> usize {
        if self.counters.is_empty() {
            return 0;
        }
        let idx = self.addr_counter.fetch_add(1, Ordering::Relaxed);
        (idx as usize) % self.counters.len()
    }

    /// Allocate the next port for the given address index.
    pub(crate) fn next_port(&self, addr_index: usize) -> u16 {
        let range = (self.port_high as u32).saturating_sub(self.port_low as u32) + 1;
        if range == 0 || addr_index >= self.counters.len() {
            return self.port_low;
        }
        let counter = &self.counters[addr_index];
        let val = counter.fetch_add(1, Ordering::Relaxed);
        self.port_low + (val % range) as u16
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct SourceNatRule {
    pub(crate) from_zone: String,
    pub(crate) to_zone: String,
    pub(crate) source_v4: Vec<PrefixV4>,
    pub(crate) source_v6: Vec<PrefixV6>,
    pub(crate) destination_v4: Vec<PrefixV4>,
    pub(crate) destination_v6: Vec<PrefixV6>,
    pub(crate) interface_mode: bool,
    pub(crate) off: bool,
    pub(crate) pool_addresses_v4: Vec<Ipv4Addr>,
    pub(crate) pool_addresses_v6: Vec<Ipv6Addr>,
    pub(crate) pool_allocator: PortAllocator,
}

impl SourceNatRule {
    fn matches(&self, from_zone: &str, to_zone: &str, src_ip: IpAddr, dst_ip: IpAddr) -> bool {
        if !self.from_zone.is_empty() && self.from_zone != from_zone {
            return false;
        }
        if !self.to_zone.is_empty() && self.to_zone != to_zone {
            return false;
        }
        match (src_ip, dst_ip) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                nets_match_v4(&self.source_v4, src) && nets_match_v4(&self.destination_v4, dst)
            }
            (IpAddr::V6(src), IpAddr::V6(dst)) => {
                nets_match_v6(&self.source_v6, src) && nets_match_v6(&self.destination_v6, dst)
            }
            _ => false,
        }
    }
}

pub(crate) fn parse_source_nat_rules(snaps: &[SourceNATRuleSnapshot]) -> Vec<SourceNatRule> {
    let mut out = Vec::with_capacity(snaps.len());
    for snap in snaps {
        let mut rule = SourceNatRule {
            from_zone: snap.from_zone.clone(),
            to_zone: snap.to_zone.clone(),
            interface_mode: snap.interface_mode,
            off: snap.off,
            ..SourceNatRule::default()
        };
        for prefix in &snap.source_addresses {
            match prefix.parse::<IpNet>() {
                Ok(IpNet::V4(net)) => rule.source_v4.push(PrefixV4::from_net(net)),
                Ok(IpNet::V6(net)) => rule.source_v6.push(PrefixV6::from_net(net)),
                Err(_) => {}
            }
        }
        for prefix in &snap.destination_addresses {
            match prefix.parse::<IpNet>() {
                Ok(IpNet::V4(net)) => rule.destination_v4.push(PrefixV4::from_net(net)),
                Ok(IpNet::V6(net)) => rule.destination_v6.push(PrefixV6::from_net(net)),
                Err(_) => {}
            }
        }
        // Parse pool addresses and port range for pool-mode SNAT.
        for addr_str in &snap.pool_addresses {
            // Pool addresses may be bare IPs or /32 CIDRs — strip the mask.
            let ip_str = addr_str.split('/').next().unwrap_or(addr_str);
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                match ip {
                    IpAddr::V4(v4) => rule.pool_addresses_v4.push(v4),
                    IpAddr::V6(v6) => rule.pool_addresses_v6.push(v6),
                }
            }
        }
        let total_pool = rule.pool_addresses_v4.len() + rule.pool_addresses_v6.len();
        if total_pool > 0 {
            let port_low = if snap.port_low > 0 {
                snap.port_low
            } else {
                1024
            };
            let port_high = if snap.port_high > 0 {
                snap.port_high
            } else {
                65535
            };
            rule.pool_allocator = PortAllocator::new(total_pool, port_low, port_high);
        }
        out.push(rule);
    }
    out
}

pub(crate) fn match_source_nat(
    rules: &[SourceNatRule],
    from_zone: &str,
    to_zone: &str,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    egress_v4: Option<Ipv4Addr>,
    egress_v6: Option<Ipv6Addr>,
) -> Option<NatDecision> {
    for rule in rules {
        if !rule.matches(from_zone, to_zone, src_ip, dst_ip) {
            continue;
        }
        if rule.off {
            return Some(NatDecision::default());
        }
        if rule.interface_mode {
            let rewrite_src = match src_ip {
                IpAddr::V4(_) => egress_v4.map(IpAddr::V4),
                IpAddr::V6(_) => egress_v6.map(IpAddr::V6),
            };
            return Some(NatDecision {
                rewrite_src,
                rewrite_dst: None,
                ..NatDecision::default()
            });
        }
        // Pool-mode SNAT: pick address round-robin, allocate port.
        match src_ip {
            IpAddr::V4(_) if !rule.pool_addresses_v4.is_empty() => {
                let addr_idx = rule.pool_allocator.next_address_index();
                // addr_idx is mod total_pool; v4 addresses are at indices 0..v4_len
                let v4_idx = addr_idx % rule.pool_addresses_v4.len();
                let pool_addr = rule.pool_addresses_v4[v4_idx];
                let port = rule.pool_allocator.next_port(addr_idx);
                return Some(NatDecision {
                    rewrite_src: Some(IpAddr::V4(pool_addr)),
                    rewrite_dst: None,
                    rewrite_src_port: Some(port),
                    rewrite_dst_port: None,
                    ..NatDecision::default()
                });
            }
            IpAddr::V6(_) if !rule.pool_addresses_v6.is_empty() => {
                let addr_idx = rule.pool_allocator.next_address_index();
                // v6 addresses are stored after v4 addresses in the allocator
                let v6_offset = rule.pool_addresses_v4.len();
                let v6_idx = (addr_idx.wrapping_sub(v6_offset)) % rule.pool_addresses_v6.len();
                let pool_addr = rule.pool_addresses_v6[v6_idx];
                let port = rule.pool_allocator.next_port(addr_idx);
                return Some(NatDecision {
                    rewrite_src: Some(IpAddr::V6(pool_addr)),
                    rewrite_dst: None,
                    rewrite_src_port: Some(port),
                    rewrite_dst_port: None,
                    ..NatDecision::default()
                });
            }
            _ => {}
        }
        return Some(NatDecision::default());
    }
    None
}

/// Static 1:1 NAT entry (bidirectional).
#[derive(Clone, Debug)]
pub(crate) struct StaticNatEntry {
    pub(crate) external_ip: IpAddr,
    pub(crate) internal_ip: IpAddr,
    pub(crate) from_zone: String,
}

/// Lookup table for static NAT -- indexed by IP for O(1) matching.
#[derive(Clone, Debug, Default)]
pub(crate) struct StaticNatTable {
    /// external_ip -> entry (for inbound DNAT)
    dnat: FxHashMap<IpAddr, StaticNatEntry>,
    /// internal_ip -> entry (for outbound SNAT)
    snat: FxHashMap<IpAddr, StaticNatEntry>,
}

impl StaticNatTable {
    pub(crate) fn from_snapshots(snaps: &[StaticNATRuleSnapshot]) -> Self {
        let mut table = StaticNatTable::default();
        for snap in snaps {
            let external_ip: IpAddr = match snap.external_ip.parse() {
                Ok(ip) => ip,
                Err(_) => continue,
            };
            let internal_ip: IpAddr = match snap.internal_ip.parse() {
                Ok(ip) => ip,
                Err(_) => continue,
            };
            let entry = StaticNatEntry {
                external_ip,
                internal_ip,
                from_zone: snap.from_zone.clone(),
            };
            table.dnat.insert(external_ip, entry.clone());
            table.snat.insert(internal_ip, entry);
        }
        table
    }

    /// Match inbound: if dst_ip is an external IP, return DNAT decision.
    pub(crate) fn match_dnat(&self, dst_ip: IpAddr, ingress_zone: &str) -> Option<NatDecision> {
        let entry = self.dnat.get(&dst_ip)?;
        if !entry.from_zone.is_empty() && entry.from_zone != ingress_zone {
            return None;
        }
        Some(NatDecision {
            rewrite_src: None,
            rewrite_dst: Some(entry.internal_ip),
            ..NatDecision::default()
        })
    }

    /// Match outbound: if src_ip is an internal IP, return SNAT decision.
    ///
    /// Note: from_zone is NOT checked for SNAT. The zone constraint on the
    /// static NAT rule set (`from zone X`) controls which ingress zone
    /// triggers DNAT only. For SNAT (outbound), the internal IP match is
    /// sufficient -- the traffic originates from the internal host regardless
    /// of which zone it enters through.
    pub(crate) fn match_snat(&self, src_ip: IpAddr, _ingress_zone: &str) -> Option<NatDecision> {
        let entry = self.snat.get(&src_ip)?;
        Some(NatDecision {
            rewrite_src: Some(entry.external_ip),
            rewrite_dst: None,
            ..NatDecision::default()
        })
    }

    /// Returns true if the table has any entries.
    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        self.dnat.is_empty()
    }

    /// Returns all external IPs (for local delivery recognition).
    pub(crate) fn external_ips(&self) -> impl Iterator<Item = &IpAddr> {
        self.dnat.keys()
    }
}

fn nets_match_v4(nets: &[PrefixV4], ip: Ipv4Addr) -> bool {
    nets.is_empty() || nets.iter().any(|net| net.contains(ip))
}

fn nets_match_v6(nets: &[PrefixV6], ip: Ipv6Addr) -> bool {
    nets.is_empty() || nets.iter().any(|net| net.contains(ip))
}

// ---------------------------------------------------------------------------
// Destination NAT (DNAT) table — O(1) lookup by (protocol, dst_ip, dst_port)
// ---------------------------------------------------------------------------

const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;

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

#[derive(Clone, Debug)]
struct DnatEntry {
    from_zone: Box<str>,
    value: DnatValue,
}

/// Destination NAT lookup table.
///
/// Entries are keyed by `(protocol, dst_ip, dst_port)`. A wildcard port
/// entry (`dst_port = 0`) matches any destination port when no exact-port
/// entry exists.
#[derive(Clone, Debug, Default)]
pub(crate) struct DnatTable {
    entries: FxHashMap<DnatKey, Vec<DnatEntry>>,
}

impl DnatTable {
    pub(crate) fn from_snapshots(snaps: &[DestinationNATRuleSnapshot]) -> Self {
        let mut table = DnatTable::default();
        for snap in snaps {
            let dst_ip: IpAddr = match snap.destination_address.parse() {
                Ok(ip) => ip,
                Err(_) => continue,
            };
            let pool_ip: IpAddr = match snap.pool_address.parse() {
                Ok(ip) => ip,
                Err(_) => continue,
            };
            // Determine protocol(s) to insert entries for.
            let protos: Vec<u8> = match snap.protocol.as_str() {
                "tcp" => vec![PROTO_TCP],
                "udp" => vec![PROTO_UDP],
                "" => {
                    if snap.destination_port != 0 {
                        // Port-based rule with no explicit protocol: default TCP
                        vec![PROTO_TCP]
                    } else {
                        // No protocol, no port: expand to both TCP and UDP
                        vec![PROTO_TCP, PROTO_UDP]
                    }
                }
                _ => continue,
            };
            for proto in protos {
                Self::insert_entry(
                    table.entries.entry(DnatKey {
                        protocol: proto,
                        dst_ip,
                        dst_port: snap.destination_port,
                    }),
                    DnatEntry {
                        from_zone: snap.from_zone.clone().into_boxed_str(),
                        value: DnatValue {
                            new_dst_ip: pool_ip,
                            new_dst_port: if snap.pool_port != 0 {
                                snap.pool_port
                            } else {
                                snap.destination_port
                            },
                        },
                    },
                );
            }
        }
        table
    }

    /// Look up a DNAT entry for the given packet fields.
    ///
    /// 1. Exact match: `(protocol, dst_ip, dst_port)`
    /// 2. Wildcard port fallback: `(protocol, dst_ip, 0)`
    pub(crate) fn lookup(
        &self,
        protocol: u8,
        dst_ip: IpAddr,
        dst_port: u16,
        ingress_zone: &str,
    ) -> Option<NatDecision> {
        let value = self
            .match_entries(
                self.entries.get(&DnatKey {
                    protocol,
                    dst_ip,
                    dst_port,
                }),
                ingress_zone,
            )
            .or_else(|| {
                self.match_entries(
                    self.entries.get(&DnatKey {
                        protocol,
                        dst_ip,
                        dst_port: 0,
                    }),
                    ingress_zone,
                )
            })?;
        let rewrite_dst_port = if value.new_dst_port != 0 && value.new_dst_port != dst_port {
            Some(value.new_dst_port)
        } else {
            None
        };
        Some(NatDecision {
            rewrite_src: None,
            rewrite_dst: Some(value.new_dst_ip),
            rewrite_src_port: None,
            rewrite_dst_port,
            nat64: false,
            nptv6: false,
        })
    }

    fn match_entries(
        &self,
        entries: Option<&Vec<DnatEntry>>,
        ingress_zone: &str,
    ) -> Option<DnatValue> {
        let entries = entries?;
        entries
            .iter()
            .find(|entry| !entry.from_zone.is_empty() && entry.from_zone.as_ref() == ingress_zone)
            .map(|entry| entry.value)
            .or_else(|| {
                entries
                    .iter()
                    .find(|entry| entry.from_zone.is_empty())
                    .map(|entry| entry.value)
            })
    }

    fn insert_entry(
        slot: std::collections::hash_map::Entry<'_, DnatKey, Vec<DnatEntry>>,
        entry: DnatEntry,
    ) {
        let entries = slot.or_default();
        if let Some(existing) = entries
            .iter_mut()
            .find(|existing| existing.from_zone == entry.from_zone)
        {
            *existing = entry;
            return;
        }
        entries.push(entry);
    }

    /// Returns true if the table has any entries.
    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns all destination IPs (the external/public IPs that DNAT rules match on).
    /// These must be registered as local addresses so traffic to them is recognized.
    pub(crate) fn destination_ips(&self) -> impl Iterator<Item = IpAddr> + '_ {
        // Deduplicate by collecting unique dst_ip values.
        let mut seen = FxHashMap::default();
        for key in self.entries.keys() {
            seen.entry(key.dst_ip).or_insert(());
        }
        seen.into_keys()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_source_nat_matches_v4_rule() {
        let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
            name: "snat".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            interface_mode: true,
            ..SourceNATRuleSnapshot::default()
        }]);
        let decision = match_source_nat(
            &rules,
            "lan",
            "wan",
            "10.0.61.102".parse().expect("src"),
            "172.16.80.200".parse().expect("dst"),
            Some("172.16.80.8".parse().expect("egress")),
            None,
        );
        assert_eq!(
            decision,
            Some(NatDecision {
                rewrite_src: Some("172.16.80.8".parse().expect("snat")),
                rewrite_dst: None,
                ..NatDecision::default()
            })
        );
    }

    #[test]
    fn interface_source_nat_matches_v6_rule() {
        let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
            name: "snat6".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["::/0".to_string()],
            interface_mode: true,
            ..SourceNATRuleSnapshot::default()
        }]);
        let decision = match_source_nat(
            &rules,
            "lan",
            "wan",
            "2001:559:8585:ef00::100".parse().expect("src"),
            "2001:559:8585:80::200".parse().expect("dst"),
            None,
            Some("2001:559:8585:80::8".parse().expect("egress")),
        );
        assert_eq!(
            decision,
            Some(NatDecision {
                rewrite_src: Some("2001:559:8585:80::8".parse().expect("snat")),
                rewrite_dst: None,
                ..NatDecision::default()
            })
        );
    }

    #[test]
    fn off_rule_short_circuits_translation() {
        let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
            name: "no-nat".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["10.0.61.0/24".to_string()],
            off: true,
            ..SourceNATRuleSnapshot::default()
        }]);
        assert_eq!(
            match_source_nat(
                &rules,
                "lan",
                "wan",
                "10.0.61.102".parse().expect("src"),
                "172.16.80.200".parse().expect("dst"),
                Some("172.16.80.8".parse().expect("egress")),
                None,
            ),
            Some(NatDecision::default())
        );
    }

    #[test]
    fn reverse_decision_turns_snat_into_reply_dnat() {
        let decision = NatDecision {
            rewrite_src: Some("172.16.80.8".parse().expect("snat")),
            rewrite_dst: None,
            ..NatDecision::default()
        };
        assert_eq!(
            decision.reverse(
                "10.0.61.102".parse().expect("orig src"),
                "172.16.80.200".parse().expect("orig dst"),
                12345,
                443,
            ),
            NatDecision {
                rewrite_src: None,
                rewrite_dst: Some("10.0.61.102".parse().expect("orig src")),
                ..NatDecision::default()
            }
        );
    }

    #[test]
    fn static_nat_dnat_matches_external_ip_v4() {
        let table = StaticNatTable::from_snapshots(&[StaticNATRuleSnapshot {
            name: "static-1".to_string(),
            from_zone: "untrust".to_string(),
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "192.168.1.10".to_string(),
        }]);
        let decision = table.match_dnat("203.0.113.10".parse().expect("ext"), "untrust");
        assert_eq!(
            decision,
            Some(NatDecision {
                rewrite_src: None,
                rewrite_dst: Some("192.168.1.10".parse().expect("int")),
                ..NatDecision::default()
            })
        );
    }

    #[test]
    fn static_nat_snat_matches_internal_ip_v4() {
        let table = StaticNatTable::from_snapshots(&[StaticNATRuleSnapshot {
            name: "static-1".to_string(),
            from_zone: "trust".to_string(),
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "192.168.1.10".to_string(),
        }]);
        let decision = table.match_snat("192.168.1.10".parse().expect("int"), "trust");
        assert_eq!(
            decision,
            Some(NatDecision {
                rewrite_src: Some("203.0.113.10".parse().expect("ext")),
                rewrite_dst: None,
                ..NatDecision::default()
            })
        );
    }

    #[test]
    fn static_nat_dnat_matches_external_ip_v6() {
        let table = StaticNatTable::from_snapshots(&[StaticNATRuleSnapshot {
            name: "static-v6".to_string(),
            from_zone: "untrust".to_string(),
            external_ip: "2001:db8::1".to_string(),
            internal_ip: "fd00::1".to_string(),
        }]);
        let decision = table.match_dnat("2001:db8::1".parse().expect("ext"), "untrust");
        assert_eq!(
            decision,
            Some(NatDecision {
                rewrite_src: None,
                rewrite_dst: Some("fd00::1".parse().expect("int")),
                ..NatDecision::default()
            })
        );
    }

    #[test]
    fn static_nat_snat_matches_internal_ip_v6() {
        let table = StaticNatTable::from_snapshots(&[StaticNATRuleSnapshot {
            name: "static-v6".to_string(),
            from_zone: "trust".to_string(),
            external_ip: "2001:db8::1".to_string(),
            internal_ip: "fd00::1".to_string(),
        }]);
        let decision = table.match_snat("fd00::1".parse().expect("int"), "trust");
        assert_eq!(
            decision,
            Some(NatDecision {
                rewrite_src: Some("2001:db8::1".parse().expect("ext")),
                rewrite_dst: None,
                ..NatDecision::default()
            })
        );
    }

    #[test]
    fn static_nat_zone_mismatch_returns_none_for_dnat() {
        let table = StaticNatTable::from_snapshots(&[StaticNATRuleSnapshot {
            name: "static-1".to_string(),
            from_zone: "untrust".to_string(),
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "192.168.1.10".to_string(),
        }]);
        // DNAT from wrong zone should fail
        assert!(
            table
                .match_dnat("203.0.113.10".parse().expect("ext"), "trust")
                .is_none()
        );
        // SNAT does not check from_zone -- internal IP match is sufficient.
        // Traffic from internal host gets SNAT regardless of ingress zone.
        assert!(
            table
                .match_snat("192.168.1.10".parse().expect("int"), "dmz")
                .is_some()
        );
    }

    #[test]
    fn static_nat_empty_zone_matches_any() {
        let table = StaticNatTable::from_snapshots(&[StaticNATRuleSnapshot {
            name: "static-any".to_string(),
            from_zone: String::new(),
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "192.168.1.10".to_string(),
        }]);
        assert!(
            table
                .match_dnat("203.0.113.10".parse().expect("ext"), "untrust")
                .is_some()
        );
        assert!(
            table
                .match_dnat("203.0.113.10".parse().expect("ext"), "trust")
                .is_some()
        );
        assert!(
            table
                .match_snat("192.168.1.10".parse().expect("int"), "trust")
                .is_some()
        );
    }

    #[test]
    fn static_nat_bidirectional_reverse() {
        let table = StaticNatTable::from_snapshots(&[StaticNATRuleSnapshot {
            name: "static-1".to_string(),
            from_zone: "untrust".to_string(),
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "192.168.1.10".to_string(),
        }]);
        // Inbound DNAT: external -> internal
        let dnat = table
            .match_dnat("203.0.113.10".parse().expect("ext"), "untrust")
            .expect("dnat");
        assert_eq!(
            dnat,
            NatDecision {
                rewrite_src: None,
                rewrite_dst: Some("192.168.1.10".parse().expect("int")),
                ..NatDecision::default()
            }
        );
        // The reverse of DNAT should produce SNAT: on reply packets from
        // the internal host, rewrite src back to the external IP.
        // reverse().rewrite_src = self.rewrite_dst.map(|_| original_dst) = Some(external)
        // reverse().rewrite_dst = self.rewrite_src.map(|_| original_src) = None
        let original_src: IpAddr = "198.51.100.1".parse().expect("peer");
        let original_dst: IpAddr = "203.0.113.10".parse().expect("ext");
        let reverse = dnat.reverse(original_src, original_dst, 54321, 80);
        assert_eq!(
            reverse,
            NatDecision {
                rewrite_src: Some(original_dst),
                rewrite_dst: None,
                ..NatDecision::default()
            }
        );
    }

    #[test]
    fn static_nat_no_match_returns_none() {
        let table = StaticNatTable::from_snapshots(&[StaticNATRuleSnapshot {
            name: "static-1".to_string(),
            from_zone: "untrust".to_string(),
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "192.168.1.10".to_string(),
        }]);
        assert!(
            table
                .match_dnat("203.0.113.99".parse().expect("unknown"), "untrust")
                .is_none()
        );
        assert!(
            table
                .match_snat("192.168.1.99".parse().expect("unknown"), "trust")
                .is_none()
        );
    }

    #[test]
    fn static_nat_invalid_ip_skipped() {
        let table = StaticNatTable::from_snapshots(&[
            StaticNATRuleSnapshot {
                name: "bad".to_string(),
                from_zone: String::new(),
                external_ip: "not-an-ip".to_string(),
                internal_ip: "192.168.1.10".to_string(),
            },
            StaticNATRuleSnapshot {
                name: "good".to_string(),
                from_zone: String::new(),
                external_ip: "203.0.113.10".to_string(),
                internal_ip: "192.168.1.10".to_string(),
            },
        ]);
        // The bad entry should be skipped, the good one should work
        assert!(
            table
                .match_dnat("203.0.113.10".parse().expect("ext"), "any")
                .is_some()
        );
    }

    #[test]
    fn static_nat_external_ips_iterator() {
        let table = StaticNatTable::from_snapshots(&[
            StaticNATRuleSnapshot {
                name: "s1".to_string(),
                from_zone: String::new(),
                external_ip: "203.0.113.10".to_string(),
                internal_ip: "192.168.1.10".to_string(),
            },
            StaticNATRuleSnapshot {
                name: "s2".to_string(),
                from_zone: String::new(),
                external_ip: "203.0.113.20".to_string(),
                internal_ip: "192.168.1.20".to_string(),
            },
        ]);
        let mut ips: Vec<IpAddr> = table.external_ips().copied().collect();
        ips.sort_by(|a, b| a.to_string().cmp(&b.to_string()));
        assert_eq!(ips.len(), 2);
        assert!(ips.contains(&"203.0.113.10".parse::<IpAddr>().unwrap()));
        assert!(ips.contains(&"203.0.113.20".parse::<IpAddr>().unwrap()));
    }

    // --- DNAT table tests ---

    #[test]
    fn dnat_basic_lookup_tcp() {
        let table = DnatTable::from_snapshots(&[DestinationNATRuleSnapshot {
            name: "web".to_string(),
            destination_address: "203.0.113.10".to_string(),
            destination_port: 80,
            protocol: "tcp".to_string(),
            pool_address: "192.168.1.10".to_string(),
            pool_port: 8080,
            ..DestinationNATRuleSnapshot::default()
        }]);
        let decision = table.lookup(PROTO_TCP, "203.0.113.10".parse().unwrap(), 80, "");
        assert_eq!(
            decision,
            Some(NatDecision {
                rewrite_dst: Some("192.168.1.10".parse().unwrap()),
                rewrite_dst_port: Some(8080),
                ..NatDecision::default()
            })
        );
    }

    #[test]
    fn dnat_wildcard_port_fallback() {
        // port=0 entry matches any destination port
        let table = DnatTable::from_snapshots(&[DestinationNATRuleSnapshot {
            name: "any-port".to_string(),
            destination_address: "203.0.113.10".to_string(),
            destination_port: 0,
            protocol: "tcp".to_string(),
            pool_address: "192.168.1.10".to_string(),
            pool_port: 0,
            ..DestinationNATRuleSnapshot::default()
        }]);
        // Any port should match via wildcard
        let decision = table.lookup(PROTO_TCP, "203.0.113.10".parse().unwrap(), 12345, "");
        assert!(decision.is_some());
        let d = decision.unwrap();
        assert_eq!(d.rewrite_dst, Some("192.168.1.10".parse().unwrap()));
        // port=0 wildcard: no port rewrite
        assert_eq!(d.rewrite_dst_port, None);
    }

    #[test]
    fn dnat_protocol_specificity() {
        // TCP entry should not match UDP lookups
        let table = DnatTable::from_snapshots(&[DestinationNATRuleSnapshot {
            name: "tcp-only".to_string(),
            destination_address: "203.0.113.10".to_string(),
            destination_port: 80,
            protocol: "tcp".to_string(),
            pool_address: "192.168.1.10".to_string(),
            pool_port: 8080,
            ..DestinationNATRuleSnapshot::default()
        }]);
        assert!(
            table
                .lookup(PROTO_TCP, "203.0.113.10".parse().unwrap(), 80, "")
                .is_some()
        );
        assert!(
            table
                .lookup(PROTO_UDP, "203.0.113.10".parse().unwrap(), 80, "")
                .is_none()
        );
    }

    #[test]
    fn dnat_ipv6_lookup() {
        let table = DnatTable::from_snapshots(&[DestinationNATRuleSnapshot {
            name: "web-v6".to_string(),
            destination_address: "2001:db8::1".to_string(),
            destination_port: 443,
            protocol: "tcp".to_string(),
            pool_address: "fd00::1".to_string(),
            pool_port: 8443,
            ..DestinationNATRuleSnapshot::default()
        }]);
        let decision = table.lookup(PROTO_TCP, "2001:db8::1".parse().unwrap(), 443, "");
        assert_eq!(
            decision,
            Some(NatDecision {
                rewrite_dst: Some("fd00::1".parse().unwrap()),
                rewrite_dst_port: Some(8443),
                ..NatDecision::default()
            })
        );
    }

    #[test]
    fn dnat_multiple_entries() {
        let table = DnatTable::from_snapshots(&[
            DestinationNATRuleSnapshot {
                name: "http".to_string(),
                destination_address: "203.0.113.10".to_string(),
                destination_port: 80,
                protocol: "tcp".to_string(),
                pool_address: "192.168.1.10".to_string(),
                pool_port: 8080,
                ..DestinationNATRuleSnapshot::default()
            },
            DestinationNATRuleSnapshot {
                name: "https".to_string(),
                destination_address: "203.0.113.10".to_string(),
                destination_port: 443,
                protocol: "tcp".to_string(),
                pool_address: "192.168.1.10".to_string(),
                pool_port: 8443,
                ..DestinationNATRuleSnapshot::default()
            },
        ]);
        let http = table.lookup(PROTO_TCP, "203.0.113.10".parse().unwrap(), 80, "");
        assert_eq!(http.unwrap().rewrite_dst_port, Some(8080));
        let https = table.lookup(PROTO_TCP, "203.0.113.10".parse().unwrap(), 443, "");
        assert_eq!(https.unwrap().rewrite_dst_port, Some(8443));
    }

    #[test]
    fn dnat_no_match_returns_none() {
        let table = DnatTable::from_snapshots(&[DestinationNATRuleSnapshot {
            name: "web".to_string(),
            destination_address: "203.0.113.10".to_string(),
            destination_port: 80,
            protocol: "tcp".to_string(),
            pool_address: "192.168.1.10".to_string(),
            pool_port: 8080,
            ..DestinationNATRuleSnapshot::default()
        }]);
        // Different IP
        assert!(
            table
                .lookup(PROTO_TCP, "203.0.113.99".parse().unwrap(), 80, "")
                .is_none()
        );
        // Different port (no wildcard entry)
        assert!(
            table
                .lookup(PROTO_TCP, "203.0.113.10".parse().unwrap(), 443, "")
                .is_none()
        );
    }

    #[test]
    fn dnat_port_aware_reverse() {
        // DNAT: rewrite dst to internal, rewrite dst_port from 80 to 8080
        let decision = NatDecision {
            rewrite_src: None,
            rewrite_dst: Some("192.168.1.10".parse().unwrap()),
            rewrite_src_port: None,
            rewrite_dst_port: Some(8080),
            nat64: false,
            nptv6: false,
        };
        // Reverse should turn rewrite_dst -> rewrite_src and port mapping too
        let reversed = decision.reverse(
            "198.51.100.1".parse().unwrap(), // original src
            "203.0.113.10".parse().unwrap(), // original dst
            54321,                           // original src_port
            80,                              // original dst_port
        );
        assert_eq!(reversed.rewrite_src, Some("203.0.113.10".parse().unwrap()));
        assert_eq!(reversed.rewrite_dst, None);
        assert_eq!(reversed.rewrite_src_port, Some(80));
        assert_eq!(reversed.rewrite_dst_port, None);
    }

    #[test]
    fn dnat_snat_merge_preserves_both() {
        let dnat = NatDecision {
            rewrite_dst: Some("192.168.1.10".parse().unwrap()),
            rewrite_dst_port: Some(8080),
            ..NatDecision::default()
        };
        let snat = NatDecision {
            rewrite_src: Some("10.0.0.1".parse().unwrap()),
            ..NatDecision::default()
        };
        let merged = dnat.merge(snat);
        assert_eq!(merged.rewrite_dst, Some("192.168.1.10".parse().unwrap()));
        assert_eq!(merged.rewrite_dst_port, Some(8080));
        assert_eq!(merged.rewrite_src, Some("10.0.0.1".parse().unwrap()));
        assert_eq!(merged.rewrite_src_port, None);
    }

    #[test]
    fn default_nat_decision_unchanged() {
        let d = NatDecision::default();
        assert_eq!(d.rewrite_src, None);
        assert_eq!(d.rewrite_dst, None);
        assert_eq!(d.rewrite_src_port, None);
        assert_eq!(d.rewrite_dst_port, None);
        assert!(!d.nat64);
    }

    #[test]
    fn dnat_empty_protocol_expands_to_both() {
        let table = DnatTable::from_snapshots(&[DestinationNATRuleSnapshot {
            name: "both".to_string(),
            destination_address: "203.0.113.10".to_string(),
            destination_port: 0,
            protocol: String::new(),
            pool_address: "192.168.1.10".to_string(),
            pool_port: 0,
            ..DestinationNATRuleSnapshot::default()
        }]);
        // Both TCP and UDP should match
        assert!(
            table
                .lookup(PROTO_TCP, "203.0.113.10".parse().unwrap(), 53, "")
                .is_some()
        );
        assert!(
            table
                .lookup(PROTO_UDP, "203.0.113.10".parse().unwrap(), 53, "")
                .is_some()
        );
    }

    #[test]
    fn dnat_same_port_no_port_rewrite() {
        // When pool_port == destination_port, no port rewrite needed
        let table = DnatTable::from_snapshots(&[DestinationNATRuleSnapshot {
            name: "same-port".to_string(),
            destination_address: "203.0.113.10".to_string(),
            destination_port: 80,
            protocol: "tcp".to_string(),
            pool_address: "192.168.1.10".to_string(),
            pool_port: 80,
            ..DestinationNATRuleSnapshot::default()
        }]);
        let decision = table
            .lookup(PROTO_TCP, "203.0.113.10".parse().unwrap(), 80, "")
            .unwrap();
        assert_eq!(decision.rewrite_dst, Some("192.168.1.10".parse().unwrap()));
        // Same port: no rewrite needed
        assert_eq!(decision.rewrite_dst_port, None);
    }

    #[test]
    fn dnat_destination_ips_iterator() {
        let table = DnatTable::from_snapshots(&[
            DestinationNATRuleSnapshot {
                name: "web".to_string(),
                destination_address: "203.0.113.10".to_string(),
                destination_port: 80,
                protocol: "tcp".to_string(),
                pool_address: "192.168.1.10".to_string(),
                pool_port: 8080,
                ..DestinationNATRuleSnapshot::default()
            },
            DestinationNATRuleSnapshot {
                name: "ssh".to_string(),
                destination_address: "203.0.113.20".to_string(),
                destination_port: 22,
                protocol: "tcp".to_string(),
                pool_address: "192.168.1.20".to_string(),
                pool_port: 22,
                ..DestinationNATRuleSnapshot::default()
            },
        ]);
        let mut ips: Vec<IpAddr> = table.destination_ips().collect();
        ips.sort_by(|a, b| a.to_string().cmp(&b.to_string()));
        assert_eq!(ips.len(), 2);
        assert!(ips.contains(&"203.0.113.10".parse::<IpAddr>().unwrap()));
        assert!(ips.contains(&"203.0.113.20".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn dnat_exact_port_beats_wildcard() {
        let table = DnatTable::from_snapshots(&[
            DestinationNATRuleSnapshot {
                name: "wildcard".to_string(),
                destination_address: "203.0.113.10".to_string(),
                destination_port: 0,
                protocol: "tcp".to_string(),
                pool_address: "192.168.1.100".to_string(),
                pool_port: 0,
                ..DestinationNATRuleSnapshot::default()
            },
            DestinationNATRuleSnapshot {
                name: "exact".to_string(),
                destination_address: "203.0.113.10".to_string(),
                destination_port: 80,
                protocol: "tcp".to_string(),
                pool_address: "192.168.1.10".to_string(),
                pool_port: 8080,
                ..DestinationNATRuleSnapshot::default()
            },
        ]);
        // Exact match should win over wildcard
        let decision = table
            .lookup(PROTO_TCP, "203.0.113.10".parse().unwrap(), 80, "")
            .unwrap();
        assert_eq!(decision.rewrite_dst, Some("192.168.1.10".parse().unwrap()));
        assert_eq!(decision.rewrite_dst_port, Some(8080));
        // Non-matching port should fall through to wildcard
        let decision = table
            .lookup(PROTO_TCP, "203.0.113.10".parse().unwrap(), 443, "")
            .unwrap();
        assert_eq!(decision.rewrite_dst, Some("192.168.1.100".parse().unwrap()));
        assert_eq!(decision.rewrite_dst_port, None);
    }

    #[test]
    fn dnat_prefers_exact_from_zone_over_any_zone() {
        let table = DnatTable::from_snapshots(&[
            DestinationNATRuleSnapshot {
                name: "any-zone".to_string(),
                destination_address: "203.0.113.10".to_string(),
                destination_port: 443,
                protocol: "tcp".to_string(),
                pool_address: "192.168.1.200".to_string(),
                pool_port: 9443,
                ..DestinationNATRuleSnapshot::default()
            },
            DestinationNATRuleSnapshot {
                name: "wan-only".to_string(),
                from_zone: "wan".to_string(),
                destination_address: "203.0.113.10".to_string(),
                destination_port: 443,
                protocol: "tcp".to_string(),
                pool_address: "192.168.1.10".to_string(),
                pool_port: 8443,
                ..DestinationNATRuleSnapshot::default()
            },
        ]);
        let decision = table
            .lookup(PROTO_TCP, "203.0.113.10".parse().unwrap(), 443, "wan")
            .unwrap();
        assert_eq!(decision.rewrite_dst, Some("192.168.1.10".parse().unwrap()));
        assert_eq!(decision.rewrite_dst_port, Some(8443));
    }

    #[test]
    fn dnat_zone_mismatch_falls_back_to_any_zone_rule() {
        let table = DnatTable::from_snapshots(&[
            DestinationNATRuleSnapshot {
                name: "wan-only".to_string(),
                from_zone: "wan".to_string(),
                destination_address: "203.0.113.10".to_string(),
                destination_port: 443,
                protocol: "tcp".to_string(),
                pool_address: "192.168.1.10".to_string(),
                pool_port: 8443,
                ..DestinationNATRuleSnapshot::default()
            },
            DestinationNATRuleSnapshot {
                name: "any-zone".to_string(),
                destination_address: "203.0.113.10".to_string(),
                destination_port: 443,
                protocol: "tcp".to_string(),
                pool_address: "192.168.1.200".to_string(),
                pool_port: 9443,
                ..DestinationNATRuleSnapshot::default()
            },
        ]);
        let decision = table
            .lookup(PROTO_TCP, "203.0.113.10".parse().unwrap(), 443, "dmz")
            .unwrap();
        assert_eq!(decision.rewrite_dst, Some("192.168.1.200".parse().unwrap()));
        assert_eq!(decision.rewrite_dst_port, Some(9443));
    }

    #[test]
    fn dnat_zone_mismatch_without_wildcard_returns_none() {
        let table = DnatTable::from_snapshots(&[DestinationNATRuleSnapshot {
            name: "wan-only".to_string(),
            from_zone: "wan".to_string(),
            destination_address: "203.0.113.10".to_string(),
            destination_port: 443,
            protocol: "tcp".to_string(),
            pool_address: "192.168.1.10".to_string(),
            pool_port: 8443,
            ..DestinationNATRuleSnapshot::default()
        }]);
        assert!(
            table
                .lookup(PROTO_TCP, "203.0.113.10".parse().unwrap(), 443, "dmz")
                .is_none()
        );
    }

    #[test]
    fn dnat_duplicate_same_zone_last_rule_wins() {
        let table = DnatTable::from_snapshots(&[
            DestinationNATRuleSnapshot {
                name: "first".to_string(),
                from_zone: "wan".to_string(),
                destination_address: "203.0.113.10".to_string(),
                destination_port: 443,
                protocol: "tcp".to_string(),
                pool_address: "192.168.1.101".to_string(),
                pool_port: 8443,
                ..DestinationNATRuleSnapshot::default()
            },
            DestinationNATRuleSnapshot {
                name: "second".to_string(),
                from_zone: "wan".to_string(),
                destination_address: "203.0.113.10".to_string(),
                destination_port: 443,
                protocol: "tcp".to_string(),
                pool_address: "192.168.1.102".to_string(),
                pool_port: 9443,
                ..DestinationNATRuleSnapshot::default()
            },
        ]);
        let decision = table
            .lookup(PROTO_TCP, "203.0.113.10".parse().unwrap(), 443, "wan")
            .unwrap();
        assert_eq!(decision.rewrite_dst, Some("192.168.1.102".parse().unwrap()));
        assert_eq!(decision.rewrite_dst_port, Some(9443));
    }

    #[test]
    fn dnat_duplicate_any_zone_last_rule_wins() {
        let table = DnatTable::from_snapshots(&[
            DestinationNATRuleSnapshot {
                name: "first".to_string(),
                destination_address: "203.0.113.10".to_string(),
                destination_port: 443,
                protocol: "tcp".to_string(),
                pool_address: "192.168.1.101".to_string(),
                pool_port: 8443,
                ..DestinationNATRuleSnapshot::default()
            },
            DestinationNATRuleSnapshot {
                name: "second".to_string(),
                destination_address: "203.0.113.10".to_string(),
                destination_port: 443,
                protocol: "tcp".to_string(),
                pool_address: "192.168.1.102".to_string(),
                pool_port: 9443,
                ..DestinationNATRuleSnapshot::default()
            },
        ]);
        let decision = table
            .lookup(PROTO_TCP, "203.0.113.10".parse().unwrap(), 443, "wan")
            .unwrap();
        assert_eq!(decision.rewrite_dst, Some("192.168.1.102".parse().unwrap()));
        assert_eq!(decision.rewrite_dst_port, Some(9443));
    }

    // --- Pool-mode SNAT tests ---

    #[test]
    fn pool_snat_single_address_rewrites_src_and_port() {
        let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
            name: "pool-snat".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            pool_name: "my-pool".to_string(),
            pool_addresses: vec!["203.0.113.1/32".to_string()],
            port_low: 1024,
            port_high: 65535,
            ..SourceNATRuleSnapshot::default()
        }]);
        let decision = match_source_nat(
            &rules,
            "lan",
            "wan",
            "10.0.1.100".parse().expect("src"),
            "8.8.8.8".parse().expect("dst"),
            None,
            None,
        );
        let d = decision.expect("should match pool rule");
        assert_eq!(d.rewrite_src, Some("203.0.113.1".parse().unwrap()));
        assert!(d.rewrite_src_port.is_some());
        let port = d.rewrite_src_port.unwrap();
        assert!(port >= 1024, "port {} out of range", port);
        assert_eq!(d.rewrite_dst, None);
        assert_eq!(d.rewrite_dst_port, None);
    }

    #[test]
    fn pool_snat_multiple_addresses_round_robin() {
        let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
            name: "pool-multi".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            pool_name: "multi-pool".to_string(),
            pool_addresses: vec![
                "203.0.113.1".to_string(),
                "203.0.113.2".to_string(),
                "203.0.113.3".to_string(),
            ],
            port_low: 1024,
            port_high: 65535,
            ..SourceNATRuleSnapshot::default()
        }]);
        let mut seen_addrs = std::collections::HashSet::new();
        for _ in 0..6 {
            let d = match_source_nat(
                &rules,
                "lan",
                "wan",
                "10.0.1.100".parse().unwrap(),
                "8.8.8.8".parse().unwrap(),
                None,
                None,
            )
            .expect("should match");
            if let Some(IpAddr::V4(addr)) = d.rewrite_src {
                seen_addrs.insert(addr);
            }
        }
        // After 6 allocations across 3 addresses, all should have been used.
        assert_eq!(
            seen_addrs.len(),
            3,
            "expected round-robin across all 3 addresses, got {:?}",
            seen_addrs
        );
    }

    #[test]
    fn pool_snat_port_range_wrapping() {
        let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
            name: "small-range".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            pool_name: "small".to_string(),
            pool_addresses: vec!["203.0.113.1".to_string()],
            port_low: 10000,
            port_high: 10002,
            ..SourceNATRuleSnapshot::default()
        }]);
        let mut ports = Vec::new();
        for _ in 0..6 {
            let d = match_source_nat(
                &rules,
                "lan",
                "wan",
                "10.0.1.100".parse().unwrap(),
                "8.8.8.8".parse().unwrap(),
                None,
                None,
            )
            .expect("should match");
            ports.push(d.rewrite_src_port.unwrap());
        }
        // With range [10000, 10002] (3 ports), allocations should wrap.
        assert_eq!(ports[0], 10000);
        assert_eq!(ports[1], 10001);
        assert_eq!(ports[2], 10002);
        assert_eq!(ports[3], 10000);
        assert_eq!(ports[4], 10001);
        assert_eq!(ports[5], 10002);
    }

    #[test]
    fn pool_snat_combined_with_dnat() {
        // Pre-routing DNAT decision
        let dnat = NatDecision {
            rewrite_dst: Some("192.168.1.10".parse().unwrap()),
            rewrite_dst_port: Some(8080),
            ..NatDecision::default()
        };
        // Post-policy pool SNAT decision
        let snat = NatDecision {
            rewrite_src: Some("203.0.113.1".parse().unwrap()),
            rewrite_src_port: Some(40000),
            ..NatDecision::default()
        };
        let merged = dnat.merge(snat);
        assert_eq!(merged.rewrite_dst, Some("192.168.1.10".parse().unwrap()));
        assert_eq!(merged.rewrite_dst_port, Some(8080));
        assert_eq!(merged.rewrite_src, Some("203.0.113.1".parse().unwrap()));
        assert_eq!(merged.rewrite_src_port, Some(40000));
    }

    #[test]
    fn pool_snat_reverse_session_key() {
        let decision = NatDecision {
            rewrite_src: Some("203.0.113.1".parse().unwrap()),
            rewrite_src_port: Some(40000),
            ..NatDecision::default()
        };
        let reversed = decision.reverse(
            "10.0.1.100".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
            12345,
            443,
        );
        assert_eq!(reversed.rewrite_src, None);
        assert_eq!(reversed.rewrite_dst, Some("10.0.1.100".parse().unwrap()));
        assert_eq!(reversed.rewrite_src_port, None);
        assert_eq!(reversed.rewrite_dst_port, Some(12345));
    }

    #[test]
    fn pool_snat_v6_single_address() {
        let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
            name: "pool-v6".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["::/0".to_string()],
            pool_name: "v6-pool".to_string(),
            pool_addresses: vec!["2001:db8::1".to_string()],
            port_low: 2000,
            port_high: 3000,
            ..SourceNATRuleSnapshot::default()
        }]);
        let decision = match_source_nat(
            &rules,
            "lan",
            "wan",
            "fd00::100".parse().expect("src"),
            "2001:db8:1::1".parse().expect("dst"),
            None,
            None,
        );
        let d = decision.expect("should match pool v6 rule");
        assert_eq!(d.rewrite_src, Some("2001:db8::1".parse().unwrap()));
        assert!(d.rewrite_src_port.is_some());
        let port = d.rewrite_src_port.unwrap();
        assert!(port >= 2000 && port <= 3000, "port {} out of range", port);
    }

    #[test]
    fn pool_snat_default_port_range() {
        // When port_low and port_high are 0, defaults to 1024..65535
        let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
            name: "default-range".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            pool_name: "default".to_string(),
            pool_addresses: vec!["203.0.113.1".to_string()],
            port_low: 0,
            port_high: 0,
            ..SourceNATRuleSnapshot::default()
        }]);
        let d = match_source_nat(
            &rules,
            "lan",
            "wan",
            "10.0.1.100".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
            None,
            None,
        )
        .expect("should match");
        let port = d.rewrite_src_port.unwrap();
        assert!(port >= 1024, "port {} out of default range", port);
    }

    #[test]
    fn pool_snat_zone_mismatch_returns_none() {
        let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
            name: "pool-zone".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            pool_name: "p".to_string(),
            pool_addresses: vec!["203.0.113.1".to_string()],
            port_low: 1024,
            port_high: 65535,
            ..SourceNATRuleSnapshot::default()
        }]);
        assert!(
            match_source_nat(
                &rules,
                "dmz", // wrong from_zone
                "wan",
                "10.0.1.100".parse().unwrap(),
                "8.8.8.8".parse().unwrap(),
                None,
                None,
            )
            .is_none()
        );
    }

    #[test]
    fn port_allocator_basic() {
        let alloc = PortAllocator::new(2, 5000, 5002);
        // Address selection round-robin
        assert_eq!(alloc.next_address_index(), 0);
        assert_eq!(alloc.next_address_index(), 1);
        assert_eq!(alloc.next_address_index(), 0);
        // Port allocation for address 0
        assert_eq!(alloc.next_port(0), 5000);
        assert_eq!(alloc.next_port(0), 5001);
        assert_eq!(alloc.next_port(0), 5002);
        assert_eq!(alloc.next_port(0), 5000); // wraps
    }
}
