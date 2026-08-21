//! Interface-state population for `build_forwarding_state`.
//!
//! Two passes:
//!
//! 1. [`populate_interfaces`] — walks `snapshot.interfaces`,
//!    populates `state.ifindex_to_*`, `state.ifindex_to_zone_id`,
//!    `state.ifindex_unambiguous_zone_id` (#6722 — the Go builder's
//!    `egress_zone` for that ifindex, admitted only when a row on it
//!    literally names that zone; the helper corroborates rather than
//!    adjudicates, see `ForwardingState::egress_zone_id` and the flush
//!    below),
//!    `state.tunnel_interfaces`, `state.local_v[46]`,
//!    `state.interface_nat_v[46]`, `state.connected_v[46]`. Returns
//!    an [`IfaceIndex`] context with `name_to_ifindex` /
//!    `linux_to_ifindex` / `mac_by_ifindex` carried across the
//!    later egress, route, and fabric passes.
//! 2. [`populate_egress`] — walks `snapshot.interfaces` a second
//!    time to build per-interface `EgressInterface` entries with
//!    the resolved `bind_ifindex`, MAC, and zone_id.

use super::super::*;
use ipnet::IpNet;
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Carry context built by [`populate_interfaces`] for downstream
/// passes (egress / fib / fabrics). Owned by the orchestrator;
/// passed by `&` to consumers.
pub(super) struct IfaceIndex {
    pub name_to_ifindex: BTreeMap<String, i32>,
    pub linux_to_ifindex: BTreeMap<String, i32>,
    pub mac_by_ifindex: BTreeMap<i32, [u8; 6]>,
}

/// What the snapshot rows on ONE ifindex say about that ifindex's EGRESS zone
/// (#6722).
///
/// The Go builder (`stampEgressZones`, `pkg/dataplane/userspace/interfaces.go`)
/// decides the answer and stamps it on every row of an ifindex, so a well-formed
/// snapshot yields `Decided` with one value. `Conflicting` is the only other
/// state, and it is version drift or a hostile snapshot.
///
/// There is deliberately NO "the field was absent" variant. `egress_zone`
/// carries `#[serde(default)]`, so an absent key decodes to `""` — the same
/// state as a builder that decided the ifindex identifies no zone, and the same
/// answer. That collapse is what the v5 protocol bump bought: an old control
/// plane's snapshot is refused at `apply_snapshot`'s exact-equality version gate
/// and never reaches this builder, so "absent" and "decided none" no longer need
/// to be told apart. Round 10 briefly carried an `Option` and an `Absent` arm
/// that fell back to row unanimity; the bump made that arm production-
/// unreachable (measured: every non-test path here is behind the version gate,
/// and the helper never replays a persisted snapshot — `write_state` is
/// write-only), so it was removed rather than left as dead code that 54 tests
/// pretended to cover.
#[derive(Clone, Debug, PartialEq, Eq)]
enum EgressZoneClaim {
    /// Every row on the ifindex carried this value. Empty means no zone.
    Decided(String),
    /// Rows on one ifindex carried DIFFERENT values. The builder stamps them
    /// identically, so this is drift or a hostile snapshot; it fails closed.
    Conflicting,
}

impl EgressZoneClaim {
    fn merge(&self, egress_zone: &str) -> Self {
        match self {
            Self::Decided(have) if have == egress_zone => self.clone(),
            _ => Self::Conflicting,
        }
    }

    /// The zone name this ifindex egresses into, or `None` for the 0 sentinel.
    /// `carried` is the set of zone names the ifindex's rows literally hold; a
    /// nonempty answer is honoured only if one of them names it.
    fn resolve(&self, carried: Option<&std::collections::BTreeSet<String>>) -> Option<String> {
        let carried = carried?;
        match self {
            Self::Conflicting => None,
            Self::Decided(zone) if zone.is_empty() => None,
            // CORROBORATION: honour the builder's answer only where a row on the
            // ifindex literally names that zone.
            Self::Decided(zone) if carried.contains(zone) => Some(zone.clone()),
            Self::Decided(_) => None,
        }
    }
}

pub(super) fn populate_interfaces(
    snapshot: &ConfigSnapshot,
    state: &mut ForwardingState,
    excluded_local_v4: &FastSet<Ipv4Addr>,
    excluded_local_v6: &FastSet<Ipv6Addr>,
) -> Result<IfaceIndex, crate::policy::SnapshotIntegrityError> {
    let mut name_to_ifindex = BTreeMap::new();
    let mut linux_to_ifindex = BTreeMap::new();
    let mut mac_by_ifindex = BTreeMap::new();
    // #6722: ifindex → the EGRESS zone name the Go builder stamped on its rows,
    // or `None` once two rows on one ifindex claimed different ones (drift; Go
    // stamps them identically). Flushed into
    // `state.ifindex_unambiguous_zone_id` after the walk, alongside
    // `zones_carried` — ifindex → the zone names its rows literally carry, which
    // is what corroborates the claim.
    let mut egress_zone_claim: BTreeMap<i32, EgressZoneClaim> = BTreeMap::new();
    let mut zones_carried: BTreeMap<i32, std::collections::BTreeSet<String>> = BTreeMap::new();

    for iface in &snapshot.interfaces {
        if iface.ifindex <= 0 {
            continue;
        }
        let label = if iface.linux_name.is_empty() {
            iface.name.clone()
        } else {
            iface.linux_name.clone()
        };
        state.ifindex_to_name.insert(iface.ifindex, label);
        state
            .ifindex_to_config_name
            .insert(iface.ifindex, iface.name.clone());
        // #3096: record the interface's routing instance for NAT rule-set
        // `from`/`to routing-instance` scope matching ("" = default VRF).
        state
            .ifindex_to_routing_instance
            .insert(iface.ifindex, iface.routing_instance.clone());
        name_to_ifindex.insert(iface.name.clone(), iface.ifindex);
        if !iface.linux_name.is_empty() {
            linux_to_ifindex.insert(iface.linux_name.clone(), iface.ifindex);
        }
        // #921: resolve zone NAME → u16 once at config build, so every read on
        // the hot path is one HashMap lookup (ifindex → u16). An unzoned row
        // resolves to 0, the "no zone" sentinel.
        // #2391: a non-empty zone NAME that is not in the zone table
        // (dropped at populate_zones for a u8-overflow id, or a
        // version-drifted/hostile snapshot) must FAIL CLOSED instead of
        // collapsing to zone 0 — collapsing bypasses every zone-pair policy
        // (fail-open under a permit default). The Go commit-time cap is the
        // primary gate; this is the helper-boundary backstop.
        let row_zone_id: u16 = if iface.zone.is_empty() {
            0
        } else {
            match state.zone_name_to_id.get(&iface.zone).copied() {
                Some(id) => id,
                None => {
                    return Err(crate::policy::SnapshotIntegrityError::InterfaceUnknownZone {
                        interface: iface.name.clone(),
                        zone: iface.zone.clone(),
                    });
                }
            }
        };
        // #6722: record the Go builder's EGRESS answer for this ifindex, and
        // (separately) the zone this row literally carries.
        //
        // The helper does not adjudicate. `stampEgressZones`
        // (`pkg/dataplane/userspace/interfaces.go`) decides which zone an
        // ifindex egresses into, because that decision needs two things the
        // rows do not carry: the operator's AUTHORED
        // `security-zone <z> interfaces <ref>` bindings before
        // `buildInterfaceZoneMap` fanned them UP to bases (a bare reference's
        // fan-DOWN onto its units is kept — that is what the reference means),
        // and `snapshotLinuxName`, the function that collapses several
        // configured identities onto one netdev. A row's `zone` is the OUTCOME
        // of that derivation, and the outcome does not say whether the operator
        // zoned THIS identity or whether the row inherited another's words.
        //
        // That is why the row-classifying ledger this replaced kept getting
        // holed. It asked "do the rows sharing this ifindex agree?" and then
        // grew an exemption list for the rows whose agreement or dissent was an
        // artefact rather than an observation — a RETH member's projection row,
        // then a multi-unit base row carrying a fanned-up zone, then an authored
        // dotted name aliasing another interface's VLAN unit. Nine spellings
        // across #6722's life, each closed by adding a case. Provenance is not
        // reconstructible from the outcome, so it is carried instead.
        //
        // What remains here is a CORROBORATION, not a decision, and it needs no
        // predicate over rows: an ifindex takes `egress_zone` only if some row
        // on it literally names that zone. A drifted or hostile snapshot can
        // therefore never conjure a zone no row on the ifindex named — the
        // helper-boundary property (#2391/#2409/#2706) the previous mark
        // argued for, now with nothing left to disagree about. `None` means the
        // rows disagreed about the answer itself (Go stamps every row on an
        // ifindex identically, so this is drift) and fails closed.
        match egress_zone_claim.entry(iface.ifindex) {
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(EgressZoneClaim::Decided(iface.egress_zone.clone()));
            }
            std::collections::btree_map::Entry::Occupied(mut slot) => {
                let merged = slot.get().merge(&iface.egress_zone);
                slot.insert(merged);
            }
        }
        zones_carried
            .entry(iface.ifindex)
            .or_default()
            .insert(iface.zone.clone());
        // `row_zone_id != 0` is EXACTLY the pre-#6722 `!iface.zone.is_empty()`
        // condition, not a narrowing of it: `zone_name_to_id_from_snapshot`
        // (`policy.rs`) skips `zone.id == 0` outright, so a zone NAME that
        // resolves at all resolves nonzero, and one that does not resolve
        // already returned `InterfaceUnknownZone` above. `ifindex_to_zone_id`
        // therefore receives the identical entries it did before this change.
        if row_zone_id != 0 {
            state.ifindex_to_zone_id.insert(iface.ifindex, row_zone_id);
            // Propagate a zoned child unit's zone onto its parent's ifindex so
            // a packet ARRIVING on a trunk parent with no zone of its own is
            // attributed to its unit's zone (#921/#3618). This is REACHABLE for
            // a Go-produced snapshot even though `buildInterfaceZoneMap`
            // (`pkg/dataplane/userspace/zones.go`) writes `out[base]` for a
            // unit-suffixed zone reference: the StableZoneID quarantine
            // (`pkg/dataplane/userspace/zones_quarantine.go`) runs AFTER
            // `buildInterfaceSnapshots` and blanks `Zone` on every row bound to
            // a quarantined zone, so a base whose zone lost a collision arrives
            // UNZONED beside a surviving zoned child and this arm fires.
            //
            // #6722: that is exactly why `egress_zone_id` must not read
            // `ifindex_to_zone_id` — the quarantine unzoned those interfaces to
            // make them fail CLOSED, and propagating a survivor's zone onto the
            // parent would hand the egress half a zone the operator never
            // configured there. The egress half reads
            // `ifindex_unambiguous_zone_id` instead, which this arm never
            // touches.
            if iface.parent_ifindex > 0 {
                match state.ifindex_to_zone_id.get(&iface.parent_ifindex) {
                    Some(existing) if *existing != row_zone_id => {}
                    _ => {
                        state
                            .ifindex_to_zone_id
                            .insert(iface.parent_ifindex, row_zone_id);
                    }
                }
            }
        }
        // #3362: per-interface host-inbound OVERRIDE. When the control plane
        // marked this interface host-inbound-configured, classify its EFFECTIVE
        // (zone ∪ interface) token set and key it by ifindex so the
        // local-delivery admit path prefers it over the from-zone's set. A
        // present-but-empty override classifies to an empty ZoneHostInbound =
        // fail-closed deny-all (matching the zone-level semantics and the nft
        // primary path's per-interface drop).
        if iface.host_inbound_configured {
            state.ifindex_host_inbound.insert(
                iface.ifindex,
                crate::afxdp::forwarding::zone_host_inbound_from_tokens(
                    &iface.host_inbound_system_services,
                    &iface.host_inbound_protocols,
                ),
            );
        }
        if iface.tunnel {
            state.tunnel_interfaces.insert(iface.ifindex);
        }
        if let Some(mac) = parse_mac(&iface.hardware_addr) {
            mac_by_ifindex.insert(iface.ifindex, mac);
        }
        let tunnel_endpoint_id = state
            .tunnel_endpoint_by_ifindex
            .get(&iface.ifindex)
            .copied()
            .unwrap_or(0);
        // #2388: canonical connected-route table names for this interface's
        // routing-instance. "" (default instance) → inet.0 / inet6.0; a
        // named instance → "<ri>.inet.0" / "<ri>.inet6.0". The lookup
        // filters connected routes by the canonical table it is resolving
        // in, so a per-VRF / next-table lookup never matches a connected
        // prefix owned by a different routing-instance.
        let (connected_table_v4, connected_table_v6) =
            connected_route_tables(&iface.routing_instance);
        // #5659: track whether this interface registered at least one
        // local-delivery target (an address that landed in local_v4/local_v6,
        // NOT one routed into interface_nat_*). Only such an addressed
        // local-delivery target is a host-inbound exposure worth the empty-zone
        // fail-closed sentinel installed after this loop.
        let mut registered_local = false;
        for addr in &iface.addresses {
            // #2409: fail CLOSED on an unparseable interface address rather
            // than silently `continue`-ing past it. The pre-fix skip lost the
            // connected route / local-address / interface-NAT material for
            // that address while the apply still succeeded — silent
            // connectivity loss in a retired-eBPF world. The Go commit-time
            // validation is the primary gate; this is the helper-boundary
            // backstop (the preflight keeps the previous good state).
            let net = addr.address.parse::<IpNet>().map_err(|_| {
                crate::policy::SnapshotIntegrityError::InterfaceAddressUnparseable {
                    interface: iface.name.clone(),
                    address: addr.address.clone(),
                }
            })?;
            match net {
                IpNet::V4(v4) => {
                    // #3182: record EVERY configured interface IP in the
                    // NAT-decoupled set BEFORE the NAT-exclusion branch, so the
                    // anti-poison `owns_configured_ip` gate protects the
                    // SNAT/WAN interface IP that the exclusion routes into
                    // `interface_nat_v4` (out of `local_v4`).
                    state.configured_iface_v4.insert(v4.addr());
                    if excluded_local_v4.contains(&v4.addr()) {
                        state.interface_nat_v4.insert(v4.addr(), iface.ifindex);
                    } else {
                        state.local_v4.insert(v4.addr());
                        registered_local = true;
                        // #3769: record the interface host address's owning
                        // table for the table-scoped local-delivery DECISION.
                        // Keyed by the HOST `.addr()`, NOT the (masked)
                        // connected prefix, so a non-/32 interface IP is
                        // recognised as locally-owned in its own VRF.
                        state
                            .local_tables_v4
                            .entry(v4.addr())
                            .or_default()
                            .insert(connected_table_v4.clone());
                    }
                    state.connected_v4.push(ConnectedRouteV4 {
                        prefix: PrefixV4::from_net(v4),
                        ifindex: iface.ifindex,
                        tunnel_endpoint_id,
                        table: connected_table_v4.clone(),
                    });
                }
                IpNet::V6(v6) => {
                    // #3182: NAT-decoupled full interface-IP set (see the V4
                    // arm above) — protects the SNAT/WAN IPv6 interface IP too.
                    state.configured_iface_v6.insert(v6.addr());
                    if excluded_local_v6.contains(&v6.addr()) {
                        state.interface_nat_v6.insert(v6.addr(), iface.ifindex);
                    } else {
                        state.local_v6.insert(v6.addr());
                        registered_local = true;
                        // #3769: record the interface host address's owning
                        // table (see the v4 arm).
                        state
                            .local_tables_v6
                            .entry(v6.addr())
                            .or_default()
                            .insert(connected_table_v6.clone());
                    }
                    state.connected_v6.push(ConnectedRouteV6 {
                        prefix: PrefixV6::from_net(v6),
                        ifindex: iface.ifindex,
                        tunnel_endpoint_id,
                        table: connected_table_v6.clone(),
                    });
                }
            }
        }
        // #5659: empty-zone host-inbound fail-closed backstop — SYMMETRY with
        // the #2391 non-empty-unknown-zone backstop above. That backstop is
        // guarded by `!iface.zone.is_empty()`, so an ADDRESSED interface with an
        // EMPTY security-zone string is skipped: no `ifindex_to_zone_id` entry ->
        // ingress resolves to zone_id 0, while its IP is STILL registered into
        // local_v4/local_v6 as a local-delivery target. `host_inbound_admits(0)`
        // then hits the `None => true` global-zone admit arm and would admit
        // every host-bound service (SSH/NETCONF/BGP/SNMP...), breaking the
        // fail-closed symmetry #2391/#3405 established.
        //
        // Fix: insert an EMPTY `ZoneHostInbound` sentinel keyed by this
        // interface's LOGICAL ifindex, so the ingress-interface-keyed
        // `host_inbound_admits_iface` (the local-delivery poll path's entry
        // point) DENIES host-bound services for a packet ingressing on it. The
        // global ICMP/ND/PMTUD accepts (`is_icmp_host_inbound_global_accept`,
        // checked BEFORE the set in `host_inbound_admits_iface`) still deliver
        // control traffic. Keying by ifindex — NOT by inserting zone_host_inbound
        // at id 0 — deliberately leaves the genuinely-global zone_id 0 path
        // (`host_inbound_admits` with no matching ifindex override) untouched, so
        // a legitimately-zoneless NON-addressed control interface keeps its admit
        // default.
        //
        // Scope guards:
        //   - registered_local: only an interface that actually registered a
        //     local_v4/local_v6 target is a host-inbound exposure. A fully
        //     NAT-excluded (interface_nat only) or address-less interface is not.
        //   - !iface.host_inbound_configured: an explicit per-interface override
        //     already inserted its own (possibly deny-all) `ifindex_host_inbound`
        //     entry above; never clobber the operator's configured admit set.
        //   - !is_host_inbound_lifeline: fxp0/em0/fab* are served UNCONDITIONALLY
        //     (kernel path, excluded from the AF_XDP deny sets). Never arm a deny
        //     sentinel for a lifeline — doing so would strand management / break
        //     HA heartbeat the moment a future change bound one.
        //
        // Reachability today is bind-gated (`buildUserspaceBindNetdevs` skips a
        // zoneless interface), so this is a fail-closed-SYMMETRY / defense-in-
        // depth hardening, not a live bypass: it closes the asymmetry so any
        // future change that binds a zoneless-addressed interface (or a quarantine
        // path, cf. #3719, that keeps an interface bound while stripping its zone)
        // cannot silently become a host-inbound bypass.
        if iface.zone.is_empty()
            && registered_local
            && !iface.host_inbound_configured
            && !is_host_inbound_lifeline(&iface.name)
        {
            state
                .ifindex_host_inbound
                .entry(iface.ifindex)
                .or_default();
        }
    }

    // #6722: flush the Go builder's egress answer, admitting an ifindex only
    // when a row on it CORROBORATES the claim by literally naming that zone.
    //
    // Every failure resolves the 0 sentinel — the pre-#6713 answer, against
    // which `evaluate_policy_result_l3_aware` matches no rule and the default
    // policy decides:
    //
    //   - `Decided("")`: the Go builder decided the ifindex identifies no single
    //     zone (contested ownership, conflicting authored bindings, or none).
    //   - `Conflicting`: rows on ONE ifindex disagreed about the answer itself.
    //     The builder stamps every row on an ifindex identically, so this is
    //     version drift or a hostile snapshot.
    //   - uncorroborated: no row on the ifindex carries that zone name. This is
    //     the whole of the helper-side check on a field it otherwise trusts, and
    //     it is what keeps a drifted claim from CONJURING a zone.
    //   - unknown name: `zone_name_to_id` has no entry, so the zone was dropped
    //     at `populate_zones` (u8-overflow id) or never existed. Corroboration
    //     makes this unreachable in practice — a row carrying an unresolvable
    //     zone already returned `InterfaceUnknownZone` above — but a failed
    //     lookup must not default to a real zone id.
    for (ifindex, claim) in egress_zone_claim {
        let Some(zone) = claim.resolve(zones_carried.get(&ifindex)) else {
            continue;
        };
        match state.zone_name_to_id.get(&zone).copied() {
            Some(zone_id) if zone_id != 0 => {
                state.ifindex_unambiguous_zone_id.insert(ifindex, zone_id);
            }
            _ => {}
        }
    }

    Ok(IfaceIndex {
        name_to_ifindex,
        linux_to_ifindex,
        mac_by_ifindex,
    })
}

pub(super) fn populate_egress(
    snapshot: &ConfigSnapshot,
    state: &mut ForwardingState,
    iface_ctx: &IfaceIndex,
) -> Result<(), crate::policy::SnapshotIntegrityError> {
    for iface in &snapshot.interfaces {
        if iface.ifindex <= 0 {
            continue;
        }
        let bind_ifindex = if iface.parent_ifindex > 0 {
            iface.parent_ifindex
        } else {
            iface.ifindex
        };
        // #2410: validate the VLAN id ONCE here instead of narrowing it with
        // an unchecked `iface.vlan_id.max(0) as u16` at both the ingress-key
        // and the EgressInterface.vlan_id site. An out-of-range value
        // (> 65535) fails the snapshot closed rather than wrapping to a
        // different VLAN (a different L2 domain).
        let vlan_id = super::validated::VlanId::try_from_snapshot(iface.vlan_id, &iface.name)?.get();
        // #2706: validate the MTU ONCE here instead of narrowing it with an
        // unchecked `iface.mtu.max(0) as usize`. A NEGATIVE value fails the
        // snapshot closed rather than collapsing to 0 — which the egress MTU
        // guard treats as "unknown; forward", silently disabling PTB/drop
        // enforcement. 0 (the legitimate "unknown MTU" sentinel) stays
        // permissive.
        let mtu = super::validated::InterfaceMtu::try_from_snapshot(iface.mtu, &iface.name)?.get();
        let ingress_key = (bind_ifindex, vlan_id);
        if iface.parent_ifindex > 0 {
            state
                .ingress_logical_ifindex
                .insert(ingress_key, iface.ifindex);
        } else {
            state
                .ingress_logical_ifindex
                .entry(ingress_key)
                .or_insert(iface.ifindex);
        }
        let src_mac = match parse_mac(&iface.hardware_addr)
            .or_else(|| iface_ctx.mac_by_ifindex.get(&bind_ifindex).copied())
            .or_else(|| iface.tunnel.then_some([0; 6]))
        {
            Some(mac) => mac,
            None => continue,
        };
        // #921: resolve zone name → u16 at build time.
        // #2391: a non-empty zone name absent from the zone table fails CLOSED
        // (consistent with populate_interfaces); an empty zone (unzoned
        // interface) maps to 0, the legitimate "no zone" case. Kept as the
        // integrity check even though the value below comes from the ledger:
        // an unresolvable zone NAME must still reject the snapshot here.
        if !iface.zone.is_empty() && !state.zone_name_to_id.contains_key(&iface.zone) {
            return Err(crate::policy::SnapshotIntegrityError::InterfaceUnknownZone {
                interface: iface.name.clone(),
                zone: iface.zone.clone(),
            });
        }
        // #6722: take the row's zone from the LEDGER, not from the row itself.
        // `state.egress` is keyed by ifindex and written last-write-wins, so
        // several identities sharing one ifindex each overwrite the previous
        // row's zone and the FINAL row decides. Sourcing it from the row would
        // let whichever identity sorts last name the zone — which is how
        // `origin/master` behaved, and why its answers here were a function of
        // interface NAMING (measured: for `ge-0/0/1` with unit 0 in `lan` and
        // unit 1 in `dmz`, master's egress zone is unit 0's `lan` only because
        // "ge-0/0/1.0" sorts after "ge-0/0/1").
        //
        // The ledger is absent for an ifindex Go declared no single zone for,
        // and for one whose claim no row corroborated; both must resolve 0, so a
        // plain `unwrap_or(0)` is exactly right.
        let zone_id = state
            .ifindex_unambiguous_zone_id
            .get(&iface.ifindex)
            .copied()
            .unwrap_or(0);
        state.egress.insert(
            iface.ifindex,
            EgressInterface {
                bind_ifindex,
                vlan_id,
                mtu,
                src_mac,
                zone_id,
                redundancy_group: iface.redundancy_group,
                primary_v4: pick_interface_v4(iface),
                primary_v6: pick_interface_v6(iface),
            },
        );
    }
    Ok(())
}

/// #6458: build `state.zone_to_rgs` — zone ID → deduplicated
/// redundancy-group IDs (> 0) of the zone's member interfaces. Runs after
/// [`populate_egress`] so both inputs (`ifindex_to_zone_id` and
/// `EgressInterface.redundancy_group`) are final. A zone whose members are
/// all RG-unbound (mgmt/fxp0, control/em0+fab, node-specific physical
/// interfaces) or that has no members is ABSENT from the map; the
/// fabric-ingress zone-stamp validation
/// (`forwarding::fabric::zone_encoded_fabric_stamp_valid`) treats an absent
/// zone as "can never be legitimately stamped" — a zone-encoded stamp
/// claims the packet ingressed the PEER in that zone, which is only
/// possible when the zone participates in RG ownership.
pub(super) fn populate_zone_to_rgs(state: &mut ForwardingState) {
    for (ifindex, zone_id) in state.ifindex_to_zone_id.iter() {
        if *zone_id == 0 {
            continue;
        }
        let rg = state
            .egress
            .get(ifindex)
            .map(|iface| iface.redundancy_group)
            .unwrap_or(0);
        if rg <= 0 {
            continue;
        }
        let rgs = state.zone_to_rgs.entry(*zone_id).or_default();
        if !rgs.contains(&rg) {
            rgs.push(rg);
        }
    }
}

/// #2388: canonical (v4, v6) connected-route table names for a routing
/// instance. The empty instance name is the default instance
/// (inet.0 / inet6.0); a named instance maps to "<ri>.inet.0" /
/// "<ri>.inet6.0". These match the names the lookup canonicalizes the
/// queried table to (`canonical_route_table`), so a connected entry is
/// only matched when the lookup is resolving in the owning table.
pub(in crate::afxdp) fn connected_route_tables(routing_instance: &str) -> (String, String) {
    if routing_instance.is_empty() {
        ("inet.0".to_string(), "inet6.0".to_string())
    } else {
        (
            format!("{routing_instance}.inet.0"),
            format!("{routing_instance}.inet6.0"),
        )
    }
}

/// #5659: base-name lifeline match, mirroring the NAME/prefix exclusions of the
/// authoritative Go SSOT `userspaceSkipsIngressInterface`
/// (pkg/dataplane/userspace/maps_sync.go): the `fxp*` / `em*` / `fab*` prefixes
/// plus `lo0`. A lifeline interface's host-bound traffic is served
/// UNCONDITIONALLY by the kernel path (excluded from the AF_XDP host-inbound
/// deny sets), so the empty-zone fail-closed backstop in [`populate_interfaces`]
/// must never arm a deny sentinel for one — that would strand management / break
/// the HA heartbeat the moment a future change bound it.
///
/// The earlier form matched only the exact `fxp0` / `em0` names, which was
/// NARROWER than the SSOT and would arm a deny sentinel on an unzoned+addressed
/// `lo0` (a router-id / BGP `update-source` loopback) or an `fxp1` / `em1` in
/// the exact future case this backstop hardens — reintroducing a
/// management-strand. The remaining arms of `userspaceSkipsIngressInterface` are
/// handled elsewhere or moot here:
///   - the mgmt/control-ZONE arm is unreachable — the sentinel branch already
///     requires an EMPTY zone;
///   - the `LocalFabric != ""` (fabric parent) arm is subsumed by the `fab*`
///     prefix, so a fabric parent that gains an L3 address stays exempt;
///   - the `Tunnel` arm is inert — a tunnel interface is likewise excluded from
///     the AF_XDP ingress-ifindex map by the same SSOT, so a sentinel on one is
///     never consulted.
///
/// The config-derived control/fabric names (#3277: a renamed `control-interface`
/// / non-default fabric) are still NOT mirrored here because the snapshot does
/// not carry them; that stays safe only because such a renamed lifeline is
/// zoneless and thus not AF_XDP-bound today (`buildUserspaceBindNetdevs` skips a
/// zoneless interface), so a missed match leaves an INERT sentinel that is never
/// consulted. If a future change binds a zoneless interface, this predicate MUST
/// be reconciled with `userspaceSkipsIngressInterface` (add a parity test). The
/// unit suffix is stripped so `em0.0` / `fab1.0` / `lo0.0` match too.
fn is_host_inbound_lifeline(name: &str) -> bool {
    let base = match name.split_once('.') {
        Some((b, _)) => b,
        None => name,
    }
    .trim();
    base.starts_with("fxp") || base.starts_with("em") || base.starts_with("fab") || base == "lo0"
}

pub(in crate::afxdp) fn pick_interface_v4(iface: &InterfaceSnapshot) -> Option<Ipv4Addr> {
    let mut fallback = None;
    for addr in &iface.addresses {
        if addr.family != "inet" {
            continue;
        }
        let Ok(net) = addr.address.parse::<ipnet::Ipv4Net>() else {
            continue;
        };
        let ip = net.addr();
        if fallback.is_none() {
            fallback = Some(ip);
        }
        if !ip.is_link_local() {
            return Some(ip);
        }
    }
    fallback
}

pub(in crate::afxdp) fn pick_interface_v6(iface: &InterfaceSnapshot) -> Option<Ipv6Addr> {
    let mut fallback = None;
    for addr in &iface.addresses {
        if addr.family != "inet6" {
            continue;
        }
        let Ok(net) = addr.address.parse::<ipnet::Ipv6Net>() else {
            continue;
        };
        let ip = net.addr();
        if fallback.is_none() {
            fallback = Some(ip);
        }
        if !ip.is_unicast_link_local() {
            return Some(ip);
        }
    }
    fallback
}
