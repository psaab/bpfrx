// Static 1:1 NAT table — bidirectional internal↔external mapping.

use super::NatDecision;
use crate::StaticNATRuleSnapshot;
use rustc_hash::FxHashMap;
use std::net::IpAddr;

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
