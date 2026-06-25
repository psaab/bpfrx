// Static 1:1 NAT table — bidirectional internal↔external mapping.

use super::{NatCounterStore, NatDecision, NatRuleCounter};
use crate::StaticNATRuleSnapshot;
use rustc_hash::FxHashMap;
use std::net::IpAddr;
use std::sync::Arc;

/// Static 1:1 NAT entry (bidirectional).
#[derive(Clone, Debug)]
pub(crate) struct StaticNatEntry {
    pub(crate) external_ip: IpAddr,
    pub(crate) internal_ip: IpAddr,
    pub(crate) from_zone: String,
    /// #2491: external (pre-translation) destination port the inbound packet
    /// must carry for a port-mapped rule. `None` = whole-address 1:1 (match
    /// any port, the legacy behaviour).
    pub(crate) match_dst_port: Option<u16>,
    /// #2491: internal (post-translation) destination port to rewrite to.
    /// `None` = no port translation (whole-address 1:1).
    pub(crate) mapped_port: Option<u16>,
    /// #2218: per-rule translation hit counter (None for counter_id 0).
    pub(crate) hit_counter: Option<Arc<NatRuleCounter>>,
}

/// Lookup table for static NAT -- indexed by (IP, Option<port>) for O(1)
/// matching. #2491: a single external IP can host several per-port mappings
/// (`mapped-port`) AND a port-less whole-address 1:1 mapping, so the key
/// carries the matched port. The port-less entry uses `None` and is the
/// fallback when no port-specific entry matches.
#[derive(Clone, Debug, Default)]
pub(crate) struct StaticNatTable {
    /// (external_ip, match-port) -> entry (for inbound DNAT). The match-port
    /// is the external destination port (`Some` for a port-mapped rule,
    /// `None` for a whole-address rule).
    dnat: FxHashMap<(IpAddr, Option<u16>), StaticNatEntry>,
    /// (internal_ip, mapped-port) -> entry (for outbound SNAT). The mapped-port
    /// is the internal source port of the return packet (`Some` for a
    /// port-mapped rule, `None` for a whole-address rule).
    snat: FxHashMap<(IpAddr, Option<u16>), StaticNatEntry>,
}

/// Parse a static-NAT address that may carry a canonical host mask
/// (`x.x.x.x/32`, `addr/128`). Junos emits static-NAT match/then in
/// canonical prefix form, and the Go compiler copies that mask verbatim
/// into the snapshot; `IpAddr::from_str` REJECTS CIDR notation, so the mask
/// must be stripped before the parse or the rule is silently dropped (#2122).
///
/// Static NAT is an exact `IpAddr -> IpAddr` 1:1 mapping, so the ONLY
/// meaningful mask is the host mask. We accept a bare address or a host mask
/// (`/32` for v4, `/128` for v6) and reject any other suffix — a non-host
/// prefix (`/24`), a non-numeric mask, a trailing/empty/double slash etc.
/// would silently translate the wrong scope, so it is a misconfiguration to
/// surface (skip), not to coerce to a host route. A genuinely-malformed
/// address likewise returns `None`, preserving the caller's skip-on-invalid
/// behavior.
fn parse_nat_addr(s: &str) -> Option<IpAddr> {
    let mut parts = s.splitn(2, '/');
    let addr: IpAddr = parts.next()?.parse().ok()?;
    match parts.next() {
        // Bare address — no mask.
        None => Some(addr),
        // Host mask only: /32 for v4, /128 for v6. Anything else is rejected.
        Some(mask) => {
            let host_len = match addr {
                IpAddr::V4(_) => "32",
                IpAddr::V6(_) => "128",
            };
            if mask == host_len { Some(addr) } else { None }
        }
    }
}

impl StaticNatTable {
    pub(crate) fn from_snapshots(
        snaps: &[StaticNATRuleSnapshot],
        nat_counters: &NatCounterStore,
    ) -> Self {
        let mut table = StaticNatTable::default();
        for snap in snaps {
            let external_ip: IpAddr = match parse_nat_addr(&snap.external_ip) {
                Some(ip) => ip,
                None => continue,
            };
            let internal_ip: IpAddr = match parse_nat_addr(&snap.internal_ip) {
                Some(ip) => ip,
                None => continue,
            };
            // #2491: a `mapped_port` without a `match_destination_port` has no
            // inbound trigger (no external port to match) and the reverse SNAT
            // cannot recover the original port, so fail CLOSED: drop the port
            // translation and treat the rule as a whole-address 1:1. The Go
            // compiler already rejects this at strict commit-check; this is the
            // lenient-load / peer-sync backstop.
            let (match_dst_port, mapped_port) = match (snap.match_destination_port, snap.mapped_port)
            {
                (0, _) => (None, None),
                (m, 0) => (Some(m), None),
                (m, p) => (Some(m), Some(p)),
            };
            let entry = StaticNatEntry {
                external_ip,
                internal_ip,
                from_zone: snap.from_zone.clone(),
                match_dst_port,
                mapped_port,
                hit_counter: nat_counters.rule_counter(snap.counter_id),
            };
            // DNAT keyed by the external (pre-translation) destination port.
            table.dnat.insert((external_ip, match_dst_port), entry.clone());
            // #2769: SNAT key scoping. The reverse key is the internal-host
            // source port of the return packet.
            //   * mapped-port rule:   return packets leave on the `mapped_port`
            //     (the inbound DNAT rewrote the destination port to it), so the
            //     SNAT key is `Some(mapped_port)`.
            //   * port-scoped 1:1 rule (`match destination-port` WITHOUT a
            //     `mapped-port`): NO port translation happens, so the internal
            //     service runs on — and its return packets leave from — the
            //     matched external port. The SNAT key MUST be
            //     `Some(match_dst_port)`, NOT `None`. Keying on `None` (the
            //     pre-#2769 bug) made the reverse SNAT match ANY source port on
            //     the internal host, source-translating every service on the
            //     box, not just the one port that was port-scoped inbound.
            //   * whole-address 1:1 rule: no port match at all, keys on `None`.
            let snat_port = mapped_port.or(match_dst_port);
            table.snat.insert((internal_ip, snat_port), entry);
        }
        table
    }

    /// Match inbound: if dst_ip is an external IP, return DNAT decision.
    ///
    /// Returns just the decision; existing callers/tests keep their
    /// `Option<NatDecision>` shape. The cold path uses
    /// [`match_dnat_with_counter`] (#2218) for the per-rule hit counter.
    ///
    /// #2491: the test-only port-less wrapper looks up the whole-address
    /// entry (port `0` exercises only the `None` fallback). The production
    /// path uses [`match_dnat_with_counter`] with the packet's destination
    /// port so a port-mapped rule can be matched.
    #[cfg(test)]
    pub(crate) fn match_dnat(&self, dst_ip: IpAddr, ingress_zone: &str) -> Option<NatDecision> {
        self.match_dnat_with_counter(dst_ip, 0, ingress_zone)
            .map(|(decision, _)| decision)
    }

    /// #2218: as [`match_dnat`] but also returns the matched entry's
    /// per-rule hit counter (if any).
    ///
    /// #2491: `dst_port` is the inbound packet's destination port. A
    /// port-mapped entry keyed on `Some(match_dst_port)` is tried first; on a
    /// miss the whole-address entry keyed on `None` is the fallback. When the
    /// matched entry carries a `mapped_port`, the decision rewrites the
    /// destination port too.
    pub(crate) fn match_dnat_with_counter(
        &self,
        dst_ip: IpAddr,
        dst_port: u16,
        ingress_zone: &str,
    ) -> Option<(NatDecision, Option<Arc<NatRuleCounter>>)> {
        // Port-specific entry takes precedence over the whole-address entry.
        let entry = self
            .dnat
            .get(&(dst_ip, Some(dst_port)))
            .or_else(|| self.dnat.get(&(dst_ip, None)))?;
        if !entry.from_zone.is_empty() && entry.from_zone != ingress_zone {
            return None;
        }
        Some((
            NatDecision {
                rewrite_src: None,
                rewrite_dst: Some(entry.internal_ip),
                rewrite_dst_port: entry.mapped_port,
                ..NatDecision::default()
            },
            entry.hit_counter.clone(),
        ))
    }

    /// Match outbound: if src_ip is an internal IP, return SNAT decision.
    ///
    /// Note: from_zone is NOT checked for SNAT. The zone constraint on the
    /// static NAT rule set (`from zone X`) controls which ingress zone
    /// triggers DNAT only. For SNAT (outbound), the internal IP match is
    /// sufficient -- the traffic originates from the internal host regardless
    /// of which zone it enters through.
    ///
    /// Returns just the decision; the cold path uses
    /// [`match_snat_with_counter`] (#2218) for the per-rule hit counter.
    ///
    /// #2491: the test-only port-less wrapper looks up the whole-address
    /// entry (port `0` exercises only the `None` fallback).
    #[cfg(test)]
    pub(crate) fn match_snat(&self, src_ip: IpAddr, ingress_zone: &str) -> Option<NatDecision> {
        self.match_snat_with_counter(src_ip, 0, ingress_zone)
            .map(|(decision, _)| decision)
    }

    /// #2218: as [`match_snat`] but also returns the matched entry's
    /// per-rule hit counter (if any).
    ///
    /// #2491: `src_port` is the return packet's source port — for a
    /// port-mapped flow this is the internal `mapped_port`. A port-specific
    /// entry keyed on `Some(src_port)` is tried first; on a miss the
    /// whole-address entry keyed on `None` is the fallback. When the matched
    /// entry carries a `mapped_port`, the decision un-translates the source
    /// port back to the external `match_dst_port`.
    pub(crate) fn match_snat_with_counter(
        &self,
        src_ip: IpAddr,
        src_port: u16,
        _ingress_zone: &str,
    ) -> Option<(NatDecision, Option<Arc<NatRuleCounter>>)> {
        let entry = self
            .snat
            .get(&(src_ip, Some(src_port)))
            .or_else(|| self.snat.get(&(src_ip, None)))?;
        // For a port-mapped rule, un-translate the source port back to the
        // external (pre-translation) port; for a whole-address rule this is
        // `None` (no port rewrite).
        let rewrite_src_port = entry.mapped_port.and(entry.match_dst_port);
        Some((
            NatDecision {
                rewrite_src: Some(entry.external_ip),
                rewrite_dst: None,
                rewrite_src_port,
                ..NatDecision::default()
            },
            entry.hit_counter.clone(),
        ))
    }

    /// Returns true if the table has any entries.
    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        self.dnat.is_empty()
    }

    /// Returns all external IPs (for local delivery recognition). #2491: the
    /// DNAT map is now keyed by `(IpAddr, Option<u16>)`; project the IP out.
    /// A given external IP appears once per distinct port mapping, which is
    /// fine for the consumers (they dedup or only test membership).
    pub(crate) fn external_ips(&self) -> impl Iterator<Item = &IpAddr> {
        self.dnat.keys().map(|(ip, _)| ip)
    }
}
