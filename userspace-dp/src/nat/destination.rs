// Destination NAT (DNAT) table — O(1) lookup by (protocol, dst_ip, dst_port).

use super::{NatCounterStore, NatDecision, NatRuleCounter};
use crate::DestinationNATRuleSnapshot;
use crate::prefix::{PrefixV4, PrefixV6};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use rustc_hash::FxHashMap;
use std::net::IpAddr;
use std::sync::Arc;

pub(super) use crate::ip_proto::{PROTO_TCP, PROTO_UDP};

/// #2396: protocol-wildcard sentinel for an IP-only / any-protocol DNAT rule
/// (Junos `match destination-address <ip>` with no application and no port).
/// Such a rule translates traffic to the destination REGARDLESS of L4
/// protocol, including ICMP/ICMPv6/GRE. The IP-only case keys under this
/// sentinel and `lookup_with_counter` falls back to it after the
/// concrete-protocol and wildcard-port lookups miss.
///
/// #2396 (Copilot fold): the sentinel is `256`, OUTSIDE the 0-255 IANA
/// protocol range, so it is DISTINCT from every real protocol — including
/// protocol 0 (HOPOPT), which is a legitimate value in the SSOT
/// (`appid.ProtocolNumber`/`proto_number`). The earlier `PROTO_ANY = 0`
/// collided with HOPOPT: a DNAT rule with `protocol 0` would have keyed under
/// the wildcard and broadened to match ALL protocols. `DnatKey.protocol` is
/// therefore a `u16`: real protocol bytes widen losslessly to 0..=255 and the
/// wildcard is the unreachable 256th value.
pub(crate) const PROTO_ANY: u16 = 256;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) struct DnatKey {
    /// IANA protocol number widened to u16 (0..=255), or `PROTO_ANY` (256) for
    /// the IP-only / any-protocol wildcard entry. u16 so the wildcard is
    /// distinct from protocol 0 (HOPOPT) — see `PROTO_ANY`.
    pub protocol: u16,
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
    /// #2394: whether the DNAT rule was scoped to a `match source-address` at
    /// all (snapshot list non-empty). This is independent of how many entries
    /// PARSED: it stays true even when every source entry was unparseable, so
    /// `source_matches` can fail closed (match nothing) for a scoped rule whose
    /// entries all failed rather than silently reverting to match-any (the
    /// #2394 fail-open). `false` = unscoped rule -> match any source (unchanged
    /// behavior).
    source_constrained: bool,
    /// #2394: parsed source-address prefixes (CIDR or bare-host /32 /128). A
    /// packet source must fall in one of these for the entry to fire.
    source_v4: Vec<PrefixV4>,
    source_v6: Vec<PrefixV6>,
    value: DnatValue,
    /// #2218: per-rule translation hit counter (None for counter_id 0).
    hit_counter: Option<Arc<NatRuleCounter>>,
}

impl DnatEntry {
    /// #2394: does the packet source IP satisfy this entry's source-address
    /// constraint?
    ///
    /// - Unscoped rule (`source_constrained == false`): match any source.
    /// - Scoped rule whose entries ALL failed to parse (constrained but both
    ///   prefix vecs empty): match NOTHING — fail closed, never fall back to
    ///   match-any (the #2394 fail-open). This is the DNAT sibling of #2398.
    /// - Otherwise: the packet source must fall in one of the parsed prefixes
    ///   of its own address family.
    fn source_matches(&self, src_ip: IpAddr) -> bool {
        if !self.source_constrained {
            return true;
        }
        if self.source_v4.is_empty() && self.source_v6.is_empty() {
            // Scoped but no entry parsed -> fail closed.
            return false;
        }
        match src_ip {
            IpAddr::V4(v4) => self.source_v4.iter().any(|net| net.contains(v4)),
            IpAddr::V6(v6) => self.source_v6.iter().any(|net| net.contains(v6)),
        }
    }
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
    pub(crate) fn from_snapshots(
        snaps: &[DestinationNATRuleSnapshot],
        nat_counters: &NatCounterStore,
    ) -> Self {
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
            // Determine the protocol key to insert this entry under.
            //
            // #2396: previously only `"tcp"`/`"udp"`/`""` were recognized and
            // everything else hit `_ => continue` — a GRE/ICMP/ICMPv6 DNAT
            // rule compiled and committed but was SILENTLY DROPPED here, never
            // reaching the dataplane (fail-open: configured translation
            // absent). And an IP-only rule (`""` + no port) expanded to
            // TCP+UDP only, so an IP-only DNAT did NOT cover ICMP/GRE despite
            // the closeout doc claiming "IP-only DNAT works for ICMP via
            // wildcard lookup".
            //
            // Now:
            //  - a concrete protocol token resolves through the shared SSOT
            //    (`proto_number`, mirrors Go's `appid.ProtocolNumber`) to its
            //    IANA number (widened to u16) — a single keyed entry covering
            //    exactly that protocol. This INCLUDES `"0"` (HOPOPT), which is
            //    a real, exact protocol — NOT the wildcard.
            //  - `""` + a destination port is still a port-based rule and
            //    defaults to TCP (the Go builder already rewrites `""`->`"tcp"`
            //    for a non-zero port; we keep the fallback for robustness).
            //  - `""` + NO port is a true IP-only / any-protocol DNAT: it is
            //    keyed under the protocol WILDCARD (`PROTO_ANY = 256`, distinct
            //    from every real protocol incl. HOPOPT), and the lookup falls
            //    back to that wildcard so it covers ALL protocols INCLUDING
            //    ICMP/ICMPv6/GRE — honoring the doc.
            //
            // An unresolvable token still drops the entry, but the Go commit
            // gate (validateDestinationNATProtocolStrict) rejects an
            // unresolvable DNAT protocol before it can reach the wire on the
            // commit path (#2396); a tolerant load downgrades to a warning, so
            // this `continue` is the dataplane backstop for a leniently-loaded
            // bad config, not the operator-facing failure mode.
            let proto: u16 = match snap.protocol.as_str() {
                "" => {
                    if snap.destination_port != 0 {
                        u16::from(PROTO_TCP)
                    } else {
                        PROTO_ANY
                    }
                }
                token => match crate::ip_proto::proto_number(token) {
                    Some(p) => u16::from(p),
                    None => continue,
                },
            };
            let hit_counter = nat_counters.rule_counter(snap.counter_id);
            // #2394 (Copilot fold): parse the source-address constraint once per
            // rule. Each entry may be a CIDR prefix (`198.51.100.0/24`) OR a bare
            // host IP (`198.51.100.42`) — Junos carries source-address verbatim
            // and the Go compiler does NOT normalize it, so a bare host reaches
            // the wire with no `/prefix`. `IpNet::from_str` REQUIRES `addr/prefix`
            // form and rejects a bare IP, so we fall back to parsing a bare
            // `IpAddr` -> /32 (v4) or /128 (v6). Without this fallback a bare-host
            // source-scoped DNAT would skip its only entry, leave the source
            // lists empty, and silently match ANY source — the exact #2394
            // fail-open reintroduced for bare-IP sources.
            //
            // `source_constrained` records whether the rule HAD a source
            // constraint at all (snapshot list non-empty), independent of how
            // many entries parsed. It drives the fail-closed distinction in
            // `source_matches`: a rule that WAS scoped but whose entries ALL
            // failed to parse must match NOTHING, not everything.
            let source_constrained = !snap.source_addresses.is_empty();
            let mut source_v4: Vec<PrefixV4> = Vec::new();
            let mut source_v6: Vec<PrefixV6> = Vec::new();
            for prefix in &snap.source_addresses {
                match prefix.parse::<IpNet>() {
                    Ok(IpNet::V4(net)) => source_v4.push(PrefixV4::from_net(net)),
                    Ok(IpNet::V6(net)) => source_v6.push(PrefixV6::from_net(net)),
                    // Bare host IP fallback -> /32 or /128.
                    Err(_) => match prefix.parse::<IpAddr>() {
                        Ok(IpAddr::V4(v4)) => {
                            if let Ok(net) = Ipv4Net::new(v4, 32) {
                                source_v4.push(PrefixV4::from_net(net));
                            }
                        }
                        Ok(IpAddr::V6(v6)) => {
                            if let Ok(net) = Ipv6Net::new(v6, 128) {
                                source_v6.push(PrefixV6::from_net(net));
                            }
                        }
                        Err(_) => {}
                    },
                }
            }
            {
                Self::insert_entry(
                    table.entries.entry(DnatKey {
                        protocol: proto,
                        dst_ip,
                        dst_port: snap.destination_port,
                    }),
                    DnatEntry {
                        from_zone: snap.from_zone.clone().into_boxed_str(),
                        source_constrained,
                        source_v4: source_v4.clone(),
                        source_v6: source_v6.clone(),
                        value: DnatValue {
                            new_dst_ip: pool_ip,
                            new_dst_port: if snap.pool_port != 0 {
                                snap.pool_port
                            } else {
                                snap.destination_port
                            },
                        },
                        hit_counter: hit_counter.clone(),
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
    /// 3. #2396 protocol-wildcard fallback: `(PROTO_ANY, dst_ip, 0)` — an
    ///    IP-only / any-protocol DNAT rule that covers ALL L4 protocols
    ///    (incl. ICMP/ICMPv6/GRE). Tried last so a concrete-protocol or
    ///    concrete-port rule always wins over the catch-all.
    ///
    /// Returns just the decision; existing callers/tests keep their
    /// `Option<NatDecision>` shape. The cold path uses
    /// [`lookup_with_counter`] (#2218) to also obtain the matched rule's
    /// per-rule hit counter — `NatDecision` (wire-frozen over HA) does NOT
    /// grow a field.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn lookup(
        &self,
        protocol: u8,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        dst_port: u16,
        ingress_zone: &str,
    ) -> Option<NatDecision> {
        self.lookup_with_counter(protocol, src_ip, dst_ip, dst_port, ingress_zone)
            .map(|(decision, _)| decision)
    }

    /// #2218: as [`lookup`] but also returns the matched entry's per-rule
    /// hit counter (if any), for the cold-path commit site.
    pub(crate) fn lookup_with_counter(
        &self,
        protocol: u8,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        dst_port: u16,
        ingress_zone: &str,
    ) -> Option<(NatDecision, Option<Arc<NatRuleCounter>>)> {
        // The inbound packet protocol is a real IANA byte; widen it to the
        // u16 key space. The wildcard sentinel (PROTO_ANY = 256) is OUTSIDE
        // this range, so a real packet — even one carrying protocol 0 (HOPOPT)
        // — can never alias the wildcard entry on the exact/port-wildcard
        // probes; the wildcard is only reached via the explicit final fallback.
        let protocol = u16::from(protocol);
        let (value, hit_counter) = self
            .match_entries(
                self.entries.get(&DnatKey {
                    protocol,
                    dst_ip,
                    dst_port,
                }),
                src_ip,
                ingress_zone,
            )
            .or_else(|| {
                self.match_entries(
                    self.entries.get(&DnatKey {
                        protocol,
                        dst_ip,
                        dst_port: 0,
                    }),
                    src_ip,
                    ingress_zone,
                )
            })
            .or_else(|| {
                // #2396: protocol-wildcard, IP-only DNAT — matches any L4
                // protocol (ICMP/ICMPv6/GRE/...) to this destination. Only
                // reached when no concrete (protocol, port) entry matched, so
                // a specific rule always wins. PROTO_ANY (256) is distinct
                // from every real protocol, so this probe targets exactly the
                // IP-only entries and a `protocol 0`/HOPOPT exact rule is never
                // conflated with the catch-all.
                self.match_entries(
                    self.entries.get(&DnatKey {
                        protocol: PROTO_ANY,
                        dst_ip,
                        dst_port: 0,
                    }),
                    src_ip,
                    ingress_zone,
                )
            })?;
        let rewrite_dst_port = if value.new_dst_port != 0 && value.new_dst_port != dst_port {
            Some(value.new_dst_port)
        } else {
            None
        };
        Some((
            NatDecision {
                rewrite_src: None,
                rewrite_dst: Some(value.new_dst_ip),
                rewrite_src_port: None,
                rewrite_dst_port,
                nat64: false,
                nptv6: false,
            },
            hit_counter,
        ))
    }

    fn match_entries(
        &self,
        entries: Option<&Vec<DnatEntry>>,
        src_ip: IpAddr,
        ingress_zone: &str,
    ) -> Option<(DnatValue, Option<Arc<NatRuleCounter>>)> {
        let entries = entries?;
        // #2394: an entry only fires when BOTH its zone and its source-address
        // constraint match. Zone-specific entries still win over zone-wildcard
        // entries, but within each tier the source-address constraint must hold
        // — an entry whose source does not contain the packet's source IP is
        // skipped (no fail-open to the wrong source).
        entries
            .iter()
            .find(|entry| {
                !entry.from_zone.is_empty()
                    && entry.from_zone.as_ref() == ingress_zone
                    && entry.source_matches(src_ip)
            })
            .map(|entry| (entry.value, entry.hit_counter.clone()))
            .or_else(|| {
                entries
                    .iter()
                    .find(|entry| entry.from_zone.is_empty() && entry.source_matches(src_ip))
                    .map(|entry| (entry.value, entry.hit_counter.clone()))
            })
    }

    fn insert_entry(
        slot: std::collections::hash_map::Entry<'_, DnatKey, Vec<DnatEntry>>,
        entry: DnatEntry,
    ) {
        let entries = slot.or_default();
        // #2394: dedup on (from_zone, source constraint). Two distinct
        // source-scoped DNAT rules in the same from-zone with the same
        // (proto, dst, port) are NOT the same entry — both must be retained so
        // each fires only for its configured source. Keying dedup on zone alone
        // would drop one and silently broaden/narrow the other. `source_constrained`
        // is part of the key so an UNSCOPED rule (match-any) and a fully-malformed
        // SCOPED rule (fail-closed) — both with empty prefix vecs — never collapse
        // onto each other.
        if let Some(existing) = entries.iter_mut().find(|existing| {
            existing.from_zone == entry.from_zone
                && existing.source_constrained == entry.source_constrained
                && existing.source_v4 == entry.source_v4
                && existing.source_v6 == entry.source_v6
        }) {
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
