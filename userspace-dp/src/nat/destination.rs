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
    /// #3096: interface-/routing-instance scope. DNAT translates on inbound,
    /// so these gate the entry against the packet's INGRESS interface
    /// config-name / routing-instance. Empty = unscoped on that axis (a
    /// zone-only or global DNAT rule is unaffected).
    from_interface: Box<str>,
    from_routing_instance: Box<str>,
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
    /// #3437 (H10): the source-port constraint of the DNAT rule's `match
    /// application` term as inclusive (low, high) ranges. Empty =
    /// source-port-unconstrained (match any source port, the pre-#3437
    /// behavior). Non-empty = the flow's source port MUST fall in one range or
    /// the entry does not fire — so an application-scoped DNAT no longer
    /// translates every source port. A low>high range never matches (the
    /// fail-CLOSED never-match sentinel) and is preserved verbatim.
    match_src_ports: Vec<(u16, u16)>,
    /// #3449: a MULTI-port `match destination-port` range as inclusive
    /// (low, high) ranges. Empty = no range constraint — the entry's exact
    /// `DnatKey.dst_port` (or the wildcard-port=0 catch-all) governs, unchanged.
    /// Non-empty: the entry is keyed under the wildcard port (dst_port=0) and
    /// the flow's destination port MUST fall in one of these ranges, otherwise
    /// the entry does not fire. This lets `destination-port 20000 to 30000`
    /// install ONE wildcard-port entry with a [20000,30000] range instead of
    /// 10 001 exact-port entries (the control-plane amplification #3449 closes).
    /// A low>high range never matches (preserved verbatim), like the source-port
    /// never-match sentinel. AND-ed with `match_src_ports` and the ICMP
    /// type/code constraint in `l4_extra_matches`.
    match_dst_ports: Vec<(u16, u16)>,
    /// #3437 (H11): the ICMP/ICMPv6 type[,code] constraint of the DNAT rule's
    /// `match application` term. `None` = unconstrained (match every type/code
    /// of the protocol). `Some(type)` requires the packet's ICMP type to equal
    /// it; when `match_icmp_code` is also `Some` the code must equal it too. A
    /// non-ICMP packet (no `(type, code)` supplied) never satisfies an
    /// ICMP-type-constrained entry (fail closed).
    match_icmp_type: Option<u8>,
    match_icmp_code: Option<u8>,
    value: DnatValue,
    /// #2218: per-rule translation hit counter (None for counter_id 0).
    hit_counter: Option<Arc<NatRuleCounter>>,
}

impl DnatEntry {
    /// #3096: does the packet's ingress interface / routing-instance satisfy
    /// this entry's `from interface` / `from routing-instance` scope? Empty
    /// fields are wildcards; present fields are AND-ed.
    fn scope_ok(&self, ingress_ifname: &str, ingress_routing_instance: &str) -> bool {
        (self.from_interface.is_empty() || self.from_interface.as_ref() == ingress_ifname)
            && (self.from_routing_instance.is_empty()
                || self.from_routing_instance.as_ref() == ingress_routing_instance)
    }

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

    /// #3437: does the flow satisfy this entry's application-derived L4 match
    /// constraints — `source-port` (H10) and ICMP `type[,code]` (H11)?
    ///
    /// - An empty `match_src_ports` is a source-port wildcard (unchanged
    ///   behavior); a non-empty set requires `src_port` to fall in one range.
    /// - `match_icmp_type == None` is an ICMP-type wildcard; `Some(t)` requires
    ///   the packet's ICMP type to equal `t` (and, if `match_icmp_code` is also
    ///   `Some`, its code to equal that). `packet_icmp == None` (a non-ICMP
    ///   packet) can never satisfy an ICMP-type-constrained entry — fail closed.
    ///
    /// #3449: a non-empty `match_dst_ports` requires `dst_port` to fall in one
    /// range (the wide-range DNAT representation); empty is a wildcard.
    ///
    /// All axes are AND-ed (mirroring Junos and the source-NAT path #3429).
    fn l4_extra_matches(&self, src_port: u16, dst_port: u16, packet_icmp: Option<(u8, u8)>) -> bool {
        if !self.match_dst_ports.is_empty() && !port_in_ranges(dst_port, &self.match_dst_ports) {
            return false;
        }
        if !self.match_src_ports.is_empty() && !port_in_ranges(src_port, &self.match_src_ports) {
            return false;
        }
        if let Some(want_type) = self.match_icmp_type {
            match packet_icmp {
                Some((typ, code)) => {
                    if typ != want_type {
                        return false;
                    }
                    if let Some(want_code) = self.match_icmp_code {
                        if code != want_code {
                            return false;
                        }
                    }
                }
                None => return false,
            }
        }
        true
    }
}

/// #3164: protocol+port key for the prefix (longest-prefix-match) DNAT entries.
/// Mirrors `DnatKey` minus the destination IP — the IP is matched by prefix
/// containment, not hashed.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) struct DnatProtoPortKey {
    pub protocol: u16,
    pub dst_port: u16,
}

/// #3164: one non-host DNAT destination prefix and its translation entry. The
/// prefix is stored in its address family (exactly one of `v4`/`v6` is set);
/// `contains`/`prefix_len` dispatch on the family.
#[derive(Clone, Debug)]
struct DnatPrefixSlot {
    v4: Option<PrefixV4>,
    v6: Option<PrefixV6>,
    entry: DnatEntry,
}

impl DnatPrefixSlot {
    fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.v4.is_some_and(|p| p.contains(v4)),
            IpAddr::V6(v6) => self.v6.is_some_and(|p| p.contains(v6)),
        }
    }

    fn prefix_len(&self) -> u8 {
        self.v4
            .map(|p| p.prefix_len())
            .or_else(|| self.v6.map(|p| p.prefix_len()))
            .unwrap_or(0)
    }

    /// The prefix network address, for local-address registration.
    fn network(&self) -> Option<IpAddr> {
        self.v4
            .map(|p| IpAddr::V4(p.addr()))
            .or_else(|| self.v6.map(|p| IpAddr::V6(p.addr())))
    }
}

/// Destination NAT lookup table.
///
/// Host destinations (a bare IP, /32, or /128) are keyed by
/// `(protocol, dst_ip, dst_port)` in the exact `entries` map — the O(1) fast
/// path. A wildcard port entry (`dst_port = 0`) matches any destination port
/// when no exact-port entry exists.
///
/// #3164: non-host destination PREFIXES (`198.51.100.0/24`) live in
/// `prefix_entries`, keyed by `(protocol, dst_port)` only, and are matched by
/// longest-prefix containment. A host (/32, /128) is the longest possible
/// prefix, so the exact map is always probed first and wins; the prefix scan is
/// the fallback when no host entry matches.
#[derive(Clone, Debug, Default)]
pub(crate) struct DnatTable {
    entries: FxHashMap<DnatKey, Vec<DnatEntry>>,
    /// #3164: non-host prefix entries, keyed by protocol+port; the destination
    /// IP is matched by prefix containment (longest-prefix-match) within each
    /// slot vec.
    prefix_entries: FxHashMap<DnatProtoPortKey, Vec<DnatPrefixSlot>>,
}

/// #3164: a classified DNAT destination — a host (exact-map key) or a non-host
/// prefix (longest-prefix-match). Exactly one of `v4`/`v6` is set in `Prefix`.
enum DnatDest {
    Host(IpAddr),
    Prefix {
        v4: Option<PrefixV4>,
        v6: Option<PrefixV6>,
    },
}

impl DnatTable {
    pub(crate) fn from_snapshots(
        snaps: &[DestinationNATRuleSnapshot],
        nat_counters: &NatCounterStore,
    ) -> Self {
        let mut table = DnatTable::default();
        for snap in snaps {
            // #3164: classify the destination as a HOST (exact-map fast path) or
            // a non-host PREFIX (longest-prefix-match). `destination_prefix` is
            // the additive wire signal: non-empty => a non-host CIDR. A host
            // destination, or an older helper that never sets the field, leaves
            // it empty and we key the exact `destination_address`. A /32 or /128
            // prefix is itself a host and collapses back to the exact map.
            let dest: DnatDest = if !snap.destination_prefix.is_empty() {
                match snap.destination_prefix.parse::<IpNet>() {
                    Ok(IpNet::V4(net)) => {
                        if net.prefix_len() == 32 {
                            DnatDest::Host(IpAddr::V4(net.addr()))
                        } else {
                            DnatDest::Prefix {
                                v4: Some(PrefixV4::from_net(net)),
                                v6: None,
                            }
                        }
                    }
                    Ok(IpNet::V6(net)) => {
                        if net.prefix_len() == 128 {
                            DnatDest::Host(IpAddr::V6(net.addr()))
                        } else {
                            DnatDest::Prefix {
                                v4: None,
                                v6: Some(PrefixV6::from_net(net)),
                            }
                        }
                    }
                    // Unparseable prefix: fall back to the host
                    // `destination_address` if it parses, else drop the entry
                    // (fail-closed, like an unparseable host destination).
                    Err(_) => match snap.destination_address.parse::<IpAddr>() {
                        Ok(ip) => DnatDest::Host(ip),
                        Err(_) => continue,
                    },
                }
            } else {
                match snap.destination_address.parse::<IpAddr>() {
                    Ok(ip) => DnatDest::Host(ip),
                    Err(_) => continue,
                }
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
            // #3437: parse the application-derived L4 match constraints. A
            // source-port range with low > high is the never-match sentinel and
            // is preserved verbatim (it can never satisfy `port_in_ranges`).
            let mut match_src_ports: Vec<(u16, u16)> = Vec::with_capacity(snap.match_source_ports.len());
            for r in &snap.match_source_ports {
                match_src_ports.push((r.low, r.high));
            }
            // #3449: the multi-port destination-port range constraint. A low>high
            // range is the impossible never-match form and is preserved verbatim
            // (it can never satisfy `port_in_ranges`). Empty = no range
            // constraint — the entry's exact/wildcard `destination_port` governs.
            let mut match_dst_ports: Vec<(u16, u16)> =
                Vec::with_capacity(snap.match_destination_ports.len());
            for r in &snap.match_destination_ports {
                match_dst_ports.push((r.low, r.high));
            }
            let entry = DnatEntry {
                from_zone: snap.from_zone.clone().into_boxed_str(),
                from_interface: snap.from_interface.clone().into_boxed_str(),
                from_routing_instance: snap.from_routing_instance.clone().into_boxed_str(),
                source_constrained,
                source_v4,
                source_v6,
                match_src_ports,
                match_dst_ports,
                match_icmp_type: snap.match_icmp_type,
                match_icmp_code: snap.match_icmp_code,
                value: DnatValue {
                    new_dst_ip: pool_ip,
                    new_dst_port: if snap.pool_port != 0 {
                        snap.pool_port
                    } else {
                        snap.destination_port
                    },
                },
                hit_counter,
            };
            // #3164: route a host to the O(1) exact map and a non-host prefix to
            // the longest-prefix-match table. Both translate to the same pool
            // (many:1 for a prefix) — block-mapping (1:1 offset) is out of scope.
            match dest {
                DnatDest::Host(dst_ip) => {
                    Self::insert_entry(
                        table.entries.entry(DnatKey {
                            protocol: proto,
                            dst_ip,
                            dst_port: snap.destination_port,
                        }),
                        entry,
                    );
                }
                DnatDest::Prefix { v4, v6 } => {
                    Self::insert_prefix_slot(
                        table.prefix_entries.entry(DnatProtoPortKey {
                            protocol: proto,
                            dst_port: snap.destination_port,
                        }),
                        DnatPrefixSlot { v4, v6, entry },
                    );
                }
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
    /// Test/back-compat convenience wrapper: the original
    /// `(protocol, src_ip, dst_ip, dst_port, ingress_zone)` shape with no
    /// source-port and no ICMP type/code awareness (#3437). It supplies
    /// `src_port = 0` and `packet_icmp = None`, so a rule carrying an
    /// application source-port (H10) or ICMP type/code (H11) constraint fails
    /// closed here — exercise those via [`lookup_with_counter`]. Production
    /// uses [`lookup_with_counter_scoped`] with the real flow fields.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn lookup(
        &self,
        protocol: u8,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        dst_port: u16,
        ingress_zone: &str,
    ) -> Option<NatDecision> {
        self.lookup_with_counter(protocol, src_ip, dst_ip, 0, dst_port, ingress_zone, None)
            .map(|(decision, _)| decision)
    }

    /// #2218: as [`lookup`] but also returns the matched entry's per-rule
    /// hit counter (if any), for the cold-path commit site.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn lookup_with_counter(
        &self,
        protocol: u8,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        ingress_zone: &str,
        packet_icmp: Option<(u8, u8)>,
    ) -> Option<(NatDecision, Option<Arc<NatRuleCounter>>)> {
        // Unscoped wrapper: empty interface/RI scope = wildcard (pre-#3096).
        self.lookup_with_counter_scoped(
            protocol,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            ingress_zone,
            "",
            "",
            packet_icmp,
        )
    }

    /// #3096: as [`lookup_with_counter`] but additionally gates each candidate
    /// on the DNAT rule's `from interface` / `from routing-instance` scope
    /// against the packet's INGRESS interface config-name and routing-instance.
    /// Empty scope fields are wildcards. The zone-tier precedence (zone-
    /// specific wins over zone-wildcard) and #3164 LPM ordering are unchanged;
    /// the scope is an additional AND filter on eligibility.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn lookup_with_counter_scoped(
        &self,
        protocol: u8,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        ingress_zone: &str,
        ingress_ifname: &str,
        ingress_routing_instance: &str,
        packet_icmp: Option<(u8, u8)>,
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
                src_port,
                dst_port,
                ingress_zone,
                ingress_ifname,
                ingress_routing_instance,
                packet_icmp,
            )
            .or_else(|| {
                self.match_entries(
                    self.entries.get(&DnatKey {
                        protocol,
                        dst_ip,
                        dst_port: 0,
                    }),
                    src_ip,
                    src_port,
                    dst_port,
                    ingress_zone,
                    ingress_ifname,
                    ingress_routing_instance,
                    packet_icmp,
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
                    src_port,
                    dst_port,
                    ingress_zone,
                    ingress_ifname,
                    ingress_routing_instance,
                    packet_icmp,
                )
            })
            .or_else(|| {
                // #3164: longest-prefix-match fallback. Reached only when no
                // exact-host entry matched — a host (/32, /128) is the longest
                // possible prefix, so the exact map always wins. Within the
                // prefix table the same three proto/port tiers apply (exact
                // proto+port, then wildcard port, then PROTO_ANY), and within a
                // tier the LONGEST matching prefix wins.
                self.match_prefix_lpm(
                    protocol,
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    ingress_zone,
                    ingress_ifname,
                    ingress_routing_instance,
                    packet_icmp,
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

    #[allow(clippy::too_many_arguments)]
    fn match_entries(
        &self,
        entries: Option<&Vec<DnatEntry>>,
        src_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        ingress_zone: &str,
        ingress_ifname: &str,
        ingress_routing_instance: &str,
        packet_icmp: Option<(u8, u8)>,
    ) -> Option<(DnatValue, Option<Arc<NatRuleCounter>>)> {
        let entries = entries?;
        // #2394: an entry only fires when its zone, source-address, AND #3096
        // interface/routing-instance scope all match. #3437: the application's
        // source-port (H10) and ICMP type/code (H11) constraints are AND-ed in
        // too. Zone-specific entries still win over zone-wildcard entries, but
        // within each tier every constraint must hold — an entry whose source,
        // interface/RI scope, source-port, or ICMP type/code does not match the
        // packet is skipped (no fail-open).
        entries
            .iter()
            .find(|entry| {
                !entry.from_zone.is_empty()
                    && entry.from_zone.as_ref() == ingress_zone
                    && entry.scope_ok(ingress_ifname, ingress_routing_instance)
                    && entry.source_matches(src_ip)
                    && entry.l4_extra_matches(src_port, dst_port, packet_icmp)
            })
            .map(|entry| (entry.value, entry.hit_counter.clone()))
            .or_else(|| {
                entries
                    .iter()
                    .find(|entry| {
                        entry.from_zone.is_empty()
                            && entry.scope_ok(ingress_ifname, ingress_routing_instance)
                            && entry.source_matches(src_ip)
                            && entry.l4_extra_matches(src_port, dst_port, packet_icmp)
                    })
                    .map(|entry| (entry.value, entry.hit_counter.clone()))
            })
    }

    /// #3164: longest-prefix-match over the non-host prefix table. Mirrors the
    /// exact-host probe order — exact `(protocol, dst_port)`, then wildcard port
    /// `(protocol, 0)`, then `(PROTO_ANY, 0)` — so proto/port specificity is
    /// honored the same way for prefixes; within each tier the LONGEST matching
    /// prefix wins. Returns the first tier that yields a match.
    #[allow(clippy::too_many_arguments)]
    fn match_prefix_lpm(
        &self,
        protocol: u16,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        ingress_zone: &str,
        ingress_ifname: &str,
        ingress_routing_instance: &str,
        packet_icmp: Option<(u8, u8)>,
    ) -> Option<(DnatValue, Option<Arc<NatRuleCounter>>)> {
        self.match_prefix_slots(
            self.prefix_entries.get(&DnatProtoPortKey {
                protocol,
                dst_port,
            }),
            dst_ip,
            src_ip,
            src_port,
            dst_port,
            ingress_zone,
            ingress_ifname,
            ingress_routing_instance,
            packet_icmp,
        )
        .or_else(|| {
            self.match_prefix_slots(
                self.prefix_entries.get(&DnatProtoPortKey {
                    protocol,
                    dst_port: 0,
                }),
                dst_ip,
                src_ip,
                src_port,
                dst_port,
                ingress_zone,
                ingress_ifname,
                ingress_routing_instance,
                packet_icmp,
            )
        })
        .or_else(|| {
            self.match_prefix_slots(
                self.prefix_entries.get(&DnatProtoPortKey {
                    protocol: PROTO_ANY,
                    dst_port: 0,
                }),
                dst_ip,
                src_ip,
                src_port,
                dst_port,
                ingress_zone,
                ingress_ifname,
                ingress_routing_instance,
                packet_icmp,
            )
        })
    }

    /// #3164: pick the best prefix slot for a destination IP within one
    /// proto/port bucket. Zone-specific entries win over zone-wildcard entries
    /// (mirroring `match_entries`); within each zone tier the LONGEST matching
    /// prefix whose source-address constraint holds wins, and the FIRST such
    /// slot in insertion order breaks a same-length tie (deterministic).
    #[allow(clippy::too_many_arguments)]
    fn match_prefix_slots(
        &self,
        slots: Option<&Vec<DnatPrefixSlot>>,
        dst_ip: IpAddr,
        src_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        ingress_zone: &str,
        ingress_ifname: &str,
        ingress_routing_instance: &str,
        packet_icmp: Option<(u8, u8)>,
    ) -> Option<(DnatValue, Option<Arc<NatRuleCounter>>)> {
        let slots = slots?;
        let best_in_tier = |zone_specific: bool| -> Option<&DnatPrefixSlot> {
            let mut best: Option<&DnatPrefixSlot> = None;
            for slot in slots {
                let zone_ok = if zone_specific {
                    !slot.entry.from_zone.is_empty()
                        && slot.entry.from_zone.as_ref() == ingress_zone
                } else {
                    slot.entry.from_zone.is_empty()
                };
                if !zone_ok
                    || !slot.entry.scope_ok(ingress_ifname, ingress_routing_instance)
                    || !slot.contains(dst_ip)
                    || !slot.entry.source_matches(src_ip)
                    || !slot.entry.l4_extra_matches(src_port, dst_port, packet_icmp)
                {
                    continue;
                }
                // STRICTLY-greater replacement keeps the first slot among equal
                // prefix lengths (deterministic on overlap ambiguity).
                if best.is_none_or(|b| slot.prefix_len() > b.prefix_len()) {
                    best = Some(slot);
                }
            }
            best
        };
        best_in_tier(true)
            .or_else(|| best_in_tier(false))
            .map(|slot| (slot.entry.value, slot.entry.hit_counter.clone()))
    }

    /// #3164: dedup-insert a prefix slot. Like `insert_entry`, two slots with the
    /// same (from_zone, source constraint) AND the same prefix are the same rule
    /// and the later one replaces the earlier; distinct prefixes or distinct
    /// source scopes are retained.
    fn insert_prefix_slot(
        slot: std::collections::hash_map::Entry<'_, DnatProtoPortKey, Vec<DnatPrefixSlot>>,
        new_slot: DnatPrefixSlot,
    ) {
        let slots = slot.or_default();
        if let Some(existing) = slots.iter_mut().find(|existing| {
            existing.v4 == new_slot.v4
                && existing.v6 == new_slot.v6
                && existing.entry.from_zone == new_slot.entry.from_zone
                // #3096: scope-distinct rules (same zone/prefix/source but a
                // different interface/RI scope) are distinct entries.
                && existing.entry.from_interface == new_slot.entry.from_interface
                && existing.entry.from_routing_instance == new_slot.entry.from_routing_instance
                && existing.entry.source_constrained == new_slot.entry.source_constrained
                && existing.entry.source_v4 == new_slot.entry.source_v4
                && existing.entry.source_v6 == new_slot.entry.source_v6
                // #3437: the application-derived L4 match (source-port, ICMP
                // type/code) is part of the rule identity. Two terms of one
                // application-set can share (zone, prefix, source, proto, port)
                // yet differ only in ICMP type (e.g. echo-request vs reply) —
                // both must be retained, not deduped onto each other.
                && existing.entry.match_src_ports == new_slot.entry.match_src_ports
                // #3449: destination-port range is part of the rule identity.
                && existing.entry.match_dst_ports == new_slot.entry.match_dst_ports
                && existing.entry.match_icmp_type == new_slot.entry.match_icmp_type
                && existing.entry.match_icmp_code == new_slot.entry.match_icmp_code
        }) {
            *existing = new_slot;
            return;
        }
        slots.push(new_slot);
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
                // #3096: interface/RI scope is part of the rule identity.
                && existing.from_interface == entry.from_interface
                && existing.from_routing_instance == entry.from_routing_instance
                && existing.source_constrained == entry.source_constrained
                && existing.source_v4 == entry.source_v4
                && existing.source_v6 == entry.source_v6
                // #3437: application-derived L4 match (source-port, ICMP
                // type/code) is part of the rule identity — see
                // insert_prefix_slot.
                && existing.match_src_ports == entry.match_src_ports
                // #3449: the destination-port range is part of the rule
                // identity — two range rules sharing (zone, dst, proto) but a
                // different range are distinct entries, both retained.
                && existing.match_dst_ports == entry.match_dst_ports
                && existing.match_icmp_type == entry.match_icmp_type
                && existing.match_icmp_code == entry.match_icmp_code
        }) {
            *existing = entry;
            return;
        }
        entries.push(entry);
    }

    /// Returns true if the table has any entries (exact-host or prefix).
    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.prefix_entries.is_empty()
    }

    /// #3164: cold-path cap on whole-block proxy-ARP/ND expansion. A DNAT
    /// destination prefix whose usable-host count is at or below this bound is
    /// expanded host-by-host into the local-address set so the firewall answers
    /// for the entire block on a directly-connected segment; a larger block
    /// registers only its network base and relies on the block being ROUTED to
    /// the firewall (no proxy-ARP), which is the usual deployment. The bound
    /// keeps a fat /16-or-shorter from exploding `local_v4`/`local_v6` (a /20 is
    /// the smallest v4 prefix that still expands).
    pub(crate) const MAX_LOCAL_PREFIX_HOSTS: u32 = 4096;

    /// Returns all destination IPs (the external/public IPs that DNAT rules match on).
    /// These must be registered as local addresses so traffic to them is recognized.
    ///
    /// #3164: exact-host destinations contribute their IP. A non-host prefix
    /// contributes its usable hosts when the block is small enough
    /// (`MAX_LOCAL_PREFIX_HOSTS`) so proxy-ARP/ND works for a directly-connected
    /// DNAT block; a larger block contributes only its network base (it must be
    /// routed to the firewall). The DNAT MATCH itself is independent of this set
    /// (the pre-routing lookup keys on the packet destination directly), so a
    /// large block is still fully translated — only on-segment proxy-ARP is
    /// bounded.
    pub(crate) fn destination_ips(&self) -> impl Iterator<Item = IpAddr> {
        // Deduplicate by collecting unique dst_ip values. #3769: implemented
        // on top of `destination_ips_scoped` so the set of registered local
        // IPs (and the block-expansion bound) can never drift between the two
        // views.
        let mut seen: FxHashMap<IpAddr, ()> = FxHashMap::default();
        for (ip, _instance) in self.destination_ips_scoped() {
            seen.entry(ip).or_insert(());
        }
        seen.into_keys()
    }

    /// #3769: like [`destination_ips`], but pairs each destination IP with the
    /// `from routing-instance` scope of the owning DNAT rule ("" = the default
    /// instance / global). The forwarding-state builder converts the routing
    /// instance to a canonical route table and records the attribution in
    /// `local_nat_tables_v*`, so the local-delivery shortcut is gated on the
    /// resolving VRF rather than the global `local_v*` membership (the #3769
    /// cross-VRF local-delivery leak). Not deduplicated — a destination IP can
    /// legitimately be owned by DNAT rules in more than one routing-instance;
    /// the builder inserts into a per-IP set of tables. The same
    /// `MAX_LOCAL_PREFIX_HOSTS`-bounded prefix expansion as `destination_ips`
    /// is applied so on-segment proxy-ARP/ND parity is preserved.
    pub(crate) fn destination_ips_scoped(&self) -> Vec<(IpAddr, &str)> {
        let mut out: Vec<(IpAddr, &str)> = Vec::new();
        for (key, entries) in &self.entries {
            for entry in entries {
                out.push((key.dst_ip, entry.from_routing_instance.as_ref()));
            }
        }
        for slots in self.prefix_entries.values() {
            for slot in slots {
                let instance = slot.entry.from_routing_instance.as_ref();
                if let Some(net) = slot.network() {
                    out.push((net, instance));
                }
                match (slot.v4, slot.v6) {
                    (Some(p), _) => {
                        let hosts = host_count_v4(p.prefix_len());
                        if hosts <= Self::MAX_LOCAL_PREFIX_HOSTS {
                            if let Ok(net) =
                                Ipv4Net::new(p.addr(), p.prefix_len())
                            {
                                for host in net.hosts() {
                                    out.push((IpAddr::V4(host), instance));
                                }
                            }
                        }
                    }
                    (_, Some(p)) => {
                        // Only expand a v6 block that is itself host-scale;
                        // anything shorter is astronomically large.
                        let hosts = host_count_v6(p.prefix_len());
                        if hosts.is_some_and(|h| h <= u128::from(Self::MAX_LOCAL_PREFIX_HOSTS)) {
                            if let Ok(net) =
                                Ipv6Net::new(p.addr(), p.prefix_len())
                            {
                                for host in net.hosts() {
                                    out.push((IpAddr::V6(host), instance));
                                }
                            }
                        }
                    }
                    (None, None) => {}
                }
            }
        }
        out
    }
}

/// #3437: is `port` within any inclusive (low, high) range in `ranges`? A range
/// with low > high (the never-match sentinel) is never satisfied. Mirrors the
/// source-NAT `port_in_ranges` in `nat/source.rs`.
fn port_in_ranges(port: u16, ranges: &[(u16, u16)]) -> bool {
    ranges.iter().any(|&(lo, hi)| port >= lo && port <= hi)
}

/// #3164: usable host count of an IPv4 prefix (saturating; /0 -> u32::MAX).
fn host_count_v4(prefix_len: u8) -> u32 {
    match 32u32.checked_sub(u32::from(prefix_len)) {
        Some(host_bits) if host_bits < 32 => 1u32 << host_bits,
        _ => u32::MAX,
    }
}

/// #3164: usable host count of an IPv6 prefix; `None` if it overflows u128
/// (anything shorter than /1), which is always far above any local bound.
fn host_count_v6(prefix_len: u8) -> Option<u128> {
    match 128u32.checked_sub(u32::from(prefix_len)) {
        Some(host_bits) if host_bits < 128 => Some(1u128 << host_bits),
        _ => None,
    }
}
