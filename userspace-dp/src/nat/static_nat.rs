// Static 1:1 NAT table — bidirectional internal↔external mapping.

use super::{NatCounterStore, NatDecision, NatRuleCounter};
use crate::StaticNATRuleSnapshot;
use rustc_hash::FxHashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
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
    /// #3031: block-to-block (subnet) static-NAT rules. A source prefix maps
    /// 1:1 by offset to an equal-length destination prefix. These cannot be
    /// keyed by exact IP, so they are scanned linearly on the session-miss
    /// cold path (block rules are rare). Exact host entries above take
    /// precedence over an overlapping block.
    blocks: Vec<StaticNatBlock>,
}

/// #3031: a block-to-block static-NAT rule. `external` (the public side) and
/// `internal` (the private side) are equal-length prefixes; a host H in one
/// block maps to the same offset in the other (network bits replaced, host
/// bits preserved). Bidirectional, exactly like the host [`StaticNatEntry`].
#[derive(Clone, Debug)]
pub(crate) struct StaticNatBlock {
    /// External (public) prefix — matched on inbound DNAT (`dst_ip`).
    external: NatPrefix,
    /// Internal (private) prefix — matched on outbound SNAT (`src_ip`).
    internal: NatPrefix,
    /// Rule's `from zone` external-zone constraint (empty = any zone),
    /// gated exactly like the host entry's `from_zone`.
    from_zone: String,
    /// Per-rule translation hit counter (#2218); None for counter_id 0.
    hit_counter: Option<Arc<NatRuleCounter>>,
}

/// Host mask (the low `32-len` bits set) for an IPv4 prefix of `len`
/// network bits. Guards the `len >= 32` shift: `u32::MAX >> 32` is UB
/// (release-mode masks the shift amount to 0, a no-op) so a host route
/// (`len == 32`, no host bits) returns `0` explicitly.
fn host_mask_v4(len: u8) -> u32 {
    if len >= 32 {
        0
    } else {
        u32::MAX >> len
    }
}

/// Host mask for an IPv6 prefix of `len` network bits. Same `len >= 128`
/// shift guard as [`host_mask_v4`].
fn host_mask_v6(len: u8) -> u128 {
    if len >= 128 {
        0
    } else {
        u128::MAX >> len
    }
}

/// A parsed static-NAT prefix: a canonical network base plus the prefix
/// length. A host route (bare address, `/32`, `/128`) has `len == max` for
/// its family.
#[derive(Clone, Copy, Debug)]
struct NatPrefix {
    base: IpAddr,
    len: u8,
}

impl NatPrefix {
    /// Maximum prefix length for the address family (32 v4 / 128 v6).
    fn max_len(&self) -> u8 {
        match self.base {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        }
    }

    /// True when this is a host route (`/32` v4, `/128` v6) — the legacy
    /// exact 1:1 static-NAT case.
    fn is_host(&self) -> bool {
        self.len == self.max_len()
    }

    /// True when `addr` falls within this prefix (same family, network bits
    /// equal). A cross-family compare is never in-prefix.
    fn contains(&self, addr: IpAddr) -> bool {
        match (self.base, addr) {
            (IpAddr::V4(b), IpAddr::V4(a)) => {
                let hm = host_mask_v4(self.len);
                (u32::from(a) & !hm) == u32::from(b)
            }
            (IpAddr::V6(b), IpAddr::V6(a)) => {
                let hm = host_mask_v6(self.len);
                (u128::from(a) & !hm) == u128::from(b)
            }
            _ => false,
        }
    }
}

/// Remap `addr` (which lives in the `src` prefix) into the `dst` prefix,
/// preserving the host bits (offset within the block) and replacing the
/// network bits: `dst_base | (addr & host_mask(src.len))`. `src.len` and
/// `dst.len` are equal by construction (enforced in `from_snapshots`), so
/// the host mask is shared. Returns `None` only on a family mismatch
/// (never happens for a validated block rule).
fn remap_addr(addr: IpAddr, src: &NatPrefix, dst: &NatPrefix) -> Option<IpAddr> {
    match (addr, dst.base) {
        (IpAddr::V4(a), IpAddr::V4(d)) => {
            let hm = host_mask_v4(src.len);
            Some(IpAddr::V4(Ipv4Addr::from(
                (u32::from(d) & !hm) | (u32::from(a) & hm),
            )))
        }
        (IpAddr::V6(a), IpAddr::V6(d)) => {
            let hm = host_mask_v6(src.len);
            Some(IpAddr::V6(Ipv6Addr::from(
                (u128::from(d) & !hm) | (u128::from(a) & hm),
            )))
        }
        _ => None,
    }
}

/// Parse a static-NAT address that may carry a canonical host mask
/// (`x.x.x.x/32`, `addr/128`) OR a block prefix (`198.51.100.0/24`). Junos
/// emits static-NAT match/then in canonical prefix form and the Go compiler
/// copies that mask verbatim into the snapshot; `IpAddr::from_str` REJECTS
/// CIDR notation, so the mask must be stripped before the parse or the rule
/// is silently dropped (#2122).
///
/// #3031: a non-host prefix is no longer rejected. A bare address / `/32` /
/// `/128` parses to a host route (`len == max`, the legacy exact 1:1 case);
/// a shorter prefix parses to a block (`len < max`) whose base is
/// canonicalized to the network address (host bits beyond the prefix length
/// are masked off so the offset remap and `contains` use a clean base even
/// if the operator authored host bits). A non-numeric mask, an out-of-range
/// length (`/33`, `/129`), or a malformed address still returns `None`,
/// preserving the caller's skip-on-invalid behavior. Whether a parsed
/// block is INSTALLED is decided in `from_snapshots` (equal-length 1:1
/// pairs only).
fn parse_nat_prefix(s: &str) -> Option<NatPrefix> {
    let mut parts = s.splitn(2, '/');
    let addr: IpAddr = parts.next()?.parse().ok()?;
    let max = match addr {
        IpAddr::V4(_) => 32u8,
        IpAddr::V6(_) => 128u8,
    };
    let len = match parts.next() {
        // Bare address — a host route.
        None => max,
        Some(mask) => {
            let len: u8 = mask.parse().ok()?;
            if len > max {
                return None;
            }
            len
        }
    };
    let base = match addr {
        IpAddr::V4(a) => IpAddr::V4(Ipv4Addr::from(u32::from(a) & !host_mask_v4(len))),
        IpAddr::V6(a) => IpAddr::V6(Ipv6Addr::from(u128::from(a) & !host_mask_v6(len))),
    };
    Some(NatPrefix { base, len })
}

impl StaticNatTable {
    pub(crate) fn from_snapshots(
        snaps: &[StaticNATRuleSnapshot],
        nat_counters: &NatCounterStore,
    ) -> Self {
        let mut table = StaticNatTable::default();
        for snap in snaps {
            let ext_prefix = match parse_nat_prefix(&snap.external_ip) {
                Some(p) => p,
                None => continue,
            };
            let int_prefix = match parse_nat_prefix(&snap.internal_ip) {
                Some(p) => p,
                None => continue,
            };
            // #3031: a non-host prefix on EITHER side is a block-to-block
            // (subnet) static-NAT rule. A valid block map needs equal-length
            // prefixes of the SAME family (1:1 by offset). A host-vs-block or
            // mismatched-length or mixed-family pair is a genuine misconfig —
            // skip it with the #2122 rationale (the Go strict commit-check
            // rejects it; this is the lenient-load / peer-sync backstop). The
            // legacy host (both `/32`/`/128`/bare) case falls through to the
            // exact-IP map path below, byte-identical to pre-#3031.
            if !ext_prefix.is_host() || !int_prefix.is_host() {
                if ext_prefix.base.is_ipv4() != int_prefix.base.is_ipv4()
                    || ext_prefix.len != int_prefix.len
                {
                    continue;
                }
                table.blocks.push(StaticNatBlock {
                    external: ext_prefix,
                    internal: int_prefix,
                    from_zone: snap.from_zone.clone(),
                    hit_counter: nat_counters.rule_counter(snap.counter_id),
                });
                continue;
            }
            let external_ip: IpAddr = ext_prefix.base;
            let internal_ip: IpAddr = int_prefix.base;
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
    ///
    /// #2864: the zone constraint is evaluated PER CANDIDATE, not once after
    /// the `(port, None)` precedence is resolved. Otherwise a port-specific
    /// entry whose `from_zone` does not match the packet's ingress zone would
    /// short-circuit to `None` and never try the whole-address `(dst_ip, None)`
    /// fallback, silently bypassing a legitimate whole-address DNAT rule. The
    /// port-specific entry still wins when its zone DOES match; only on a
    /// zone-fail (or a port miss) do we fall back to the whole-address entry
    /// and validate ITS zone.
    pub(crate) fn match_dnat_with_counter(
        &self,
        dst_ip: IpAddr,
        dst_port: u16,
        ingress_zone: &str,
    ) -> Option<(NatDecision, Option<Arc<NatRuleCounter>>)> {
        // Per-candidate zone gate: an entry matches only when its zone
        // constraint is empty (any zone) or equals the packet's ingress zone.
        let zone_ok = |entry: &&StaticNatEntry| {
            entry.from_zone.is_empty() || entry.from_zone == ingress_zone
        };
        // Port-specific entry takes precedence over the whole-address entry,
        // but only if its OWN zone check passes. On a port miss OR a
        // port-specific zone mismatch, fall back to the whole-address entry
        // (which is then zone-checked on its own).
        if let Some(entry) = self
            .dnat
            .get(&(dst_ip, Some(dst_port)))
            .filter(zone_ok)
            .or_else(|| self.dnat.get(&(dst_ip, None)).filter(zone_ok))
        {
            return Some((
                NatDecision {
                    rewrite_src: None,
                    rewrite_dst: Some(entry.internal_ip),
                    rewrite_dst_port: entry.mapped_port,
                    ..NatDecision::default()
                },
                entry.hit_counter.clone(),
            ));
        }
        // #3031: block-to-block DNAT. Exact host entries above take
        // precedence; on a miss, scan the (rare) block rules. `dst_ip` in the
        // external prefix translates to the same offset in the internal
        // prefix (network bits replaced, host bits preserved). The decision
        // carries only `rewrite_dst` (an `IpAddr`), so the existing host
        // static-NAT checksum fixup path applies unchanged.
        for blk in &self.blocks {
            if (blk.from_zone.is_empty() || blk.from_zone == ingress_zone)
                && blk.external.contains(dst_ip)
            {
                if let Some(translated) = remap_addr(dst_ip, &blk.external, &blk.internal) {
                    return Some((
                        NatDecision {
                            rewrite_src: None,
                            rewrite_dst: Some(translated),
                            ..NatDecision::default()
                        },
                        blk.hit_counter.clone(),
                    ));
                }
            }
        }
        None
    }

    /// Match outbound: if src_ip is an internal IP, return SNAT decision.
    ///
    /// #2871: the egress (destination) zone IS checked for SNAT, mirroring the
    /// #2864 DNAT-direction zone gate. Static NAT is bidirectional but, per
    /// Junos/vSRX parity, the reverse (source) translation applies only when
    /// the packet egresses TOWARD the rule-set's external zone — the rule's
    /// `from zone` (`entry.from_zone`). The DNAT direction matches the external
    /// zone on INGRESS (`from_zone == ingress_zone`); the SNAT direction
    /// symmetrically matches it on EGRESS (`from_zone == egress_zone`).
    ///
    /// Without this gate, an outbound packet sourced from a static-NAT internal
    /// IP but destined for ANOTHER internal zone (trust↔dmz east-west,
    /// peer-to-peer on internal segments) was source-translated to the public
    /// `external_ip`, breaking internal routing, internal security-policy match
    /// (which then saw the translated source), and intra-site connectivity —
    /// a cross-zone leak.
    ///
    /// An empty `from_zone` ("any zone") matches every egress zone, preserving
    /// the wildcard rule behaviour.
    ///
    /// Returns just the decision; the cold path uses
    /// [`match_snat_with_counter`] (#2218) for the per-rule hit counter.
    ///
    /// #2491: the test-only port-less wrapper looks up the whole-address
    /// entry (port `0` exercises only the `None` fallback).
    #[cfg(test)]
    pub(crate) fn match_snat(&self, src_ip: IpAddr, egress_zone: &str) -> Option<NatDecision> {
        self.match_snat_with_counter(src_ip, 0, egress_zone)
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
        egress_zone: &str,
    ) -> Option<(NatDecision, Option<Arc<NatRuleCounter>>)> {
        // #2871: per-candidate egress-zone gate, the SNAT-direction analog of
        // the #2864 DNAT ingress-zone gate. An entry matches only when its
        // external-zone constraint is empty (any zone) or equals the packet's
        // egress (destination) zone. Evaluate the zone PER CANDIDATE so a
        // port-specific entry whose zone does not match falls back to the
        // whole-address entry (validated on its own zone) rather than
        // short-circuiting to None.
        let zone_ok = |entry: &&StaticNatEntry| {
            entry.from_zone.is_empty() || entry.from_zone == egress_zone
        };
        if let Some(entry) = self
            .snat
            .get(&(src_ip, Some(src_port)))
            .filter(zone_ok)
            .or_else(|| self.snat.get(&(src_ip, None)).filter(zone_ok))
        {
            // For a port-mapped rule, un-translate the source port back to the
            // external (pre-translation) port; for a whole-address rule this is
            // `None` (no port rewrite).
            let rewrite_src_port = entry.mapped_port.and(entry.match_dst_port);
            return Some((
                NatDecision {
                    rewrite_src: Some(entry.external_ip),
                    rewrite_dst: None,
                    rewrite_src_port,
                    ..NatDecision::default()
                },
                entry.hit_counter.clone(),
            ));
        }
        // #3031: block-to-block reverse SNAT — the inverse of the DNAT
        // offset map. `src_ip` in the internal prefix translates back to the
        // same offset in the external prefix, so the return path's source is
        // un-NAT'd to the public block and the reverse session key matches.
        for blk in &self.blocks {
            if (blk.from_zone.is_empty() || blk.from_zone == egress_zone)
                && blk.internal.contains(src_ip)
            {
                if let Some(translated) = remap_addr(src_ip, &blk.internal, &blk.external) {
                    return Some((
                        NatDecision {
                            rewrite_src: Some(translated),
                            rewrite_dst: None,
                            ..NatDecision::default()
                        },
                        blk.hit_counter.clone(),
                    ));
                }
            }
        }
        None
    }

    /// Returns true if the table has any entries.
    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        self.dnat.is_empty() && self.blocks.is_empty()
    }

    /// Returns all external IPs (for local delivery recognition). #2491: the
    /// DNAT map is now keyed by `(IpAddr, Option<u16>)`; project the IP out.
    /// A given external IP appears once per distinct port mapping, which is
    /// fine for the consumers (they dedup or only test membership).
    ///
    /// #3031: also yields each block rule's external network base. A block's
    /// inbound DNAT match is NOT gated on `local_v4`/`local_v6` membership
    /// (the cold-path `match_dnat_with_counter` runs on transit regardless),
    /// so emitting only the base — rather than expanding a whole (possibly
    /// /16 or v6-huge) prefix into the local set — is sufficient parity for
    /// the network address without an unbounded blow-up.
    pub(crate) fn external_ips(&self) -> impl Iterator<Item = &IpAddr> {
        self.dnat
            .keys()
            .map(|(ip, _)| ip)
            .chain(self.blocks.iter().map(|b| &b.external.base))
    }
}
