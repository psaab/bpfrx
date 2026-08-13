//! Interface-state population for `build_forwarding_state`.
//!
//! Two passes:
//!
//! 1. [`populate_interfaces`] — walks `snapshot.interfaces`,
//!    populates `state.ifindex_to_*`, `state.ifindex_to_zone_id`,
//!    `state.ifindex_unambiguous_zone_id` (#6722 — an ifindex only when
//!    EVERY row sharing it named the same nonzero zone; see
//!    `ForwardingState::egress_zone_id`),
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

pub(super) fn populate_interfaces(
    snapshot: &ConfigSnapshot,
    state: &mut ForwardingState,
    excluded_local_v4: &FastSet<Ipv4Addr>,
    excluded_local_v6: &FastSet<Ipv6Addr>,
) -> Result<IfaceIndex, crate::policy::SnapshotIntegrityError> {
    let mut name_to_ifindex = BTreeMap::new();
    let mut linux_to_ifindex = BTreeMap::new();
    let mut mac_by_ifindex = BTreeMap::new();
    // #6722: ifindex → the zone every row on it agrees on, or `None` once two
    // rows disagreed. Flushed into `state.ifindex_unambiguous_zone_id` after
    // the walk, because a conflict can be introduced by ANY later row.
    let mut zone_agreement: BTreeMap<i32, Option<u16>> = BTreeMap::new();

    // #6722 B1: every row name that lands on each ifindex, so the projection
    // gate below can require a real parent row rather than trusting the
    // `redundant_parent` string. Built in a pre-pass because a projection's
    // parent row can be emitted either before or after it — the Go builder
    // walks names sorted, so `ge-0/0/1` precedes `reth1` but `st0` does not
    // precede `reth1`, and a gate that only looked backwards would be
    // order-dependent. Rows are 2-3 per ifindex, so the linear scan below is
    // cheaper than another map.
    let mut names_by_ifindex: BTreeMap<i32, Vec<&str>> = BTreeMap::new();
    for iface in &snapshot.interfaces {
        if iface.ifindex <= 0 {
            continue;
        }
        names_by_ifindex
            .entry(iface.ifindex)
            .or_default()
            .push(iface.name.as_str());
    }

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
        // #6722: record what THIS row says about its ifindex, for every row —
        // an unzoned row's "no zone" is an opinion that must be able to
        // conflict with a zoned sibling's. `zone_agreement[ifx] == None` means
        // the rows sharing `ifx` disagree, so the ifindex identifies no single
        // zone and `ForwardingState::egress_zone_id` must refuse to guess one.
        // Recording unzoned rows is LOAD-BEARING, and proven so: skip them and
        // `unzoned_macless_unit_does_not_inherit_a_zoned_siblings_zone_6722`,
        // `divergently_zoned_sibling_units_do_not_pick_a_zone_6722` and both
        // filter-log siblings go red, because the shared ifindex's only
        // surviving opinion is the zoned base row's.
        //
        // `None` is ABSORBING: the `!=` below is deliberately written against
        // the whole `Option`, not against an unwrapped zone id, so a later row
        // that happens to agree with the FIRST one cannot re-arm an ifindex
        // already known ambiguous. Rewriting it as
        // `if let Some(existing) = *slot.get() { ... } else { re-arm }` is
        // green on every TWO-row fixture — two rows can only ENTER the state,
        // never attempt to re-arm it — and reinstates the #6722 fail-open on a
        // three-row one. The interface-level WireGuard fixtures are the
        // three-row shapes that catch it
        // (`unzoned_iface_tunnel_unit_does_not_inherit_a_siblings_zone_via_egress_row_6722`,
        // `vpnb` -> unzoned -> `vpnb` on one ifindex).
        //
        // The ledger is fed ONLY by what a row literally carries, never by the
        // child→parent propagation below, so it says what the SNAPSHOT said
        // rather than what the ingress map was derived to hold. That exclusion
        // is a design property, not a demonstrated guard: teaching the ledger
        // from the propagation arm too leaves every test in this issue green,
        // because the arm is skipped whenever the parent already disagrees and
        // a parent with no snapshot row of its own also has no child pointing
        // at it (an unresolvable link yields `ifindex == 0` on both rows).
        // #6722 B2: a ledger is only sound if every row is an INDEPENDENT
        // observer of its ifindex. An UNZONED physical RETH member's row is
        // not — it is a PROJECTION of the RETH's own netdev.
        //
        // `ResolveReth` (`pkg/config/types.go`) resolves a RETH to its member,
        // and `snapshotLinuxName` (`pkg/dataplane/userspace/interfaces.go`)
        // applies it to the reth base row AND its units, so `ge-0/0/1`,
        // `reth1` and `reth1.0` are ONE kernel netdev. A member's own units
        // alias the matching reth unit the same way — a VLAN unit resolves to
        // `LinuxIfName(ResolveReth(base)).<vlan>`, putting `ge-0/0/1.100` on
        // `reth1.100`'s netdev — which is why the Go builder stamps
        // `redundant_parent` on the member's unit rows too, not just its base.
        //
        // Junos configs conventionally zone the RETH rather than the member, so
        // `buildInterfaceZoneMap` usually leaves the member's rows unzoned and
        // `buildInterfaceSnapshots` emits them unfiltered. That is CONVENTION,
        // not a code property: `buildInterfaceZoneMap`
        // (pkg/dataplane/userspace/zones.go) enforces no such rule, and a config
        // that zones the member really does produce a zoned member row —
        // measured, `zoneByInterface[ge-0/0/1] = "z214"`. Nothing here depends
        // on the convention holding: the `zone.is_empty()` half of the gate
        // below is exactly what handles the exception (#6722 re-gate). Counting that "no zone" as a dissenting vote makes
        // the RETH's own zone ambiguous: measured through the full
        // `buildSnapshot` on `docs/ha-cluster-userspace.conf` (node 0 — the
        // topology `test/incus/loss-userspace-cluster.env` points every HA
        // smoke test at), `ifindex 24: [ge-0/0/1="" reth1="lan" reth1.0="lan"]`
        // and `ifindex 25: [ge-0/0/2="" reth0="wan"]` under `default-policy
        // deny-all`. That collapses the EGRESS zone to the 0 sentinel, against
        // which `evaluate_policy_result_l3_aware` matches no rule at all
        // (`policy.rs`, the `from_id != 0 && to_id != 0` gate), so every
        // WAN->LAN, sfmix->LAN and tunnel->LAN transit flow on a bondless-RETH
        // cluster blackholes. LAN->WAN survives because its egress ifindex has
        // a single row, which is exactly why an iperf3 smoke in the usual
        // direction comes back green.
        //
        // The `zone.is_empty()` half of the gate is LOAD-BEARING, not
        // defensive. A member the operator EXPLICITLY zoned into a different
        // zone than its RETH is a real statement about a real conflict, not an
        // artefact of one device described by several rows, and it must keep
        // failing closed. `explicitly_zoned_reth_member_still_makes_the_
        // ifindex_ambiguous_6722` reds if this half is dropped.
        //
        // SCOPE, deliberately narrow. The other ways two rows share an ifindex
        // are all genuine independent observers and still vote:
        // the non-VLAN unit-0 collapse (`st0` / `st0.0`), interface-level
        // tunnels (`wg0` / `wg0.0` / `wg0.1` via `TunnelNameMap`), and a
        // recycled ifindex across two unrelated interfaces. `fab0` is NOT one
        // of them — the fabric IPVLAN is its own netdev with its own ifindex
        // (`snapshotLinuxName` never calls `ResolveFab`), so it never shares
        // one with its physical parent.
        // The gate requires a PARENT ROW, not just the parent's NAME. #6722 B1:
        // `redundant_parent` is an unvalidated operator string. The Go builder
        // copies it onto every row of any interface carrying `gigether-options
        // redundant-parent` (`interfaces.go:245`, `:318`), and no compiler pass
        // requires the named parent to exist, to be a `reth*`, or to resolve
        // back to this interface — `schema_interfaces.go` accepts
        // `gigether-options` under ANY interface name, and grepping
        // `compiler_validate_strict*.go` / `*_warn*.go` for it returns nothing.
        //
        // So `!redundant_parent.is_empty()` means "this interface MENTIONED a
        // redundant-parent", which is not the same as "this row is a projection
        // of another row's netdev" — and the operator controls the difference.
        // Measured: `set interfaces st0 gigether-options redundant-parent reth1`
        // is ACCEPTED by strict `CompileConfig`, and without the parent-row
        // requirement it silences `st0.0`'s vote and flips `egress_zone_id`
        // from the fail-closed 0 to a resolved zone — re-opening the exact
        // fail-open this exemption was written to close, on the very shape
        // `reth_exemption_does_not_leak_to_iface_tunnel_units_6722` guards.
        // A dangling parent (`reth1` never defined) does the same, and there
        // master answers 0, so the unguarded form would REGRESS master.
        //
        // Requiring a co-resident row named `<parent>` or `<parent>.<unit>`
        // encodes the actual invariant: this netdev is described by another
        // row that IS the parent. That is what makes the projection a
        // projection. `other != iface.name` keeps a self-referential
        // `redundant-parent` naming its own interface from matching itself.
        // Checked here rather than in Go because this function already treats
        // the helper boundary as a fail-closed backstop (#2391/#2409/#2706),
        // so the gate stays sound against a drifted or hostile snapshot.
        let row_is_reth_member_projection = !iface.redundant_parent.is_empty()
            && iface.zone.is_empty()
            && names_by_ifindex.get(&iface.ifindex).is_some_and(|names| {
                names.iter().any(|other| {
                    *other != iface.name.as_str()
                        && (*other == iface.redundant_parent.as_str()
                            || other
                                .strip_prefix(iface.redundant_parent.as_str())
                                .is_some_and(|rest| rest.starts_with('.')))
                })
            });
        if !row_is_reth_member_projection {
            match zone_agreement.entry(iface.ifindex) {
                std::collections::btree_map::Entry::Vacant(slot) => {
                    slot.insert(Some(row_zone_id));
                }
                std::collections::btree_map::Entry::Occupied(mut slot) => {
                    if *slot.get() != Some(row_zone_id) {
                        slot.insert(None);
                    }
                }
            }
        }
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

    // #6722: flush the agreement ledger. An ifindex lands here only when every
    // row on it named the SAME nonzero zone; a conflict (`None`) and a
    // unanimous "no zone" (`Some(0)`) are both left absent, and
    // `ForwardingState::egress_zone_id` then resolves that ifindex to the 0
    // sentinel — the pre-#6713 answer, against which no policy rule matches.
    //
    // The `zone_id != 0` skip is a map-size choice, NOT a safety gate, and is
    // labelled as such so nobody mutates it expecting a red: `egress_zone_id`
    // ends in `.unwrap_or(0)`, so a stored `Some(0)` and an absent key resolve
    // identically. Keeping the key out confines the map to interfaces that
    // actually name a zone.
    for (ifindex, agreed) in zone_agreement {
        if let Some(zone_id) = agreed {
            if zone_id != 0 {
                state.ifindex_unambiguous_zone_id.insert(ifindex, zone_id);
            }
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
        // #6722 B1: take the row's zone from the AGREEMENT LEDGER, not from the
        // row itself. `state.egress` is keyed by ifindex and written
        // last-write-wins, so several units sharing one ifindex each overwrite
        // the previous row's zone and the FINAL row decides — and
        // `ForwardingState::egress_zone_id` reads this map BEFORE the ledger.
        // Sourcing it from the row would therefore let a zoned sibling re-arm
        // an ifindex the ledger holds ambiguous, entirely bypassing the #6722
        // gate.
        //
        // That is not hypothetical and it is not limited to MAC-less xfrmis. An
        // interface-level WireGuard tunnel maps EVERY unit onto the base device
        // (`TunnelNameMap`, `pkg/config/types.go` — the branch admits WireGuard
        // despite its empty GRE-style `source`), and those rows carry
        // `tunnel = true`, so the `src_mac` gate above admits them via
        // `iface.tunnel.then_some([0; 6])` and they DO get egress rows. Zone
        // only `wg0.1` and the last write puts its zone on the ifindex that
        // unzoned `wg0.0` shares.
        //
        // The ledger is absent for an ifindex whose rows disagree AND for one
        // whose rows unanimously name no zone; both must resolve 0, so a plain
        // `unwrap_or(0)` is exactly right. Where the rows AGREE the value is
        // identical to the row's own zone, so an ordinary single-unit interface
        // is unaffected.
        //
        // #6722 B2, stated carefully because the earlier spelling of that last
        // sentence was FALSE. "Single-unit" is a claim about the CONFIG, not
        // about how many snapshot rows land on the netdev, and a bondless RETH
        // is the counterexample: `reth1` with one unit still puts THREE rows on
        // ifindex 24 (`ge-0/0/1`, `reth1`, `reth1.0`), because `ResolveReth`
        // collapses the RETH onto its physical member. Before the projection
        // exemption above, the member's unzoned row dissented and the ledger
        // held the ifindex ambiguous, so that interface was very much affected
        // — every WAN->LAN transit flow on the reference HA cluster blackholed.
        // It is unaffected NOW for a specific reason: the member's rows cast no
        // vote at all, so the surviving rows are unanimous and the ledger value
        // is once again identical to the row's own zone.
        //
        // PROVENANCE, so a bisect is not misled: this ambiguity was already
        // latent in the index-keyed `egress` map BEFORE #6713/#6722. On
        // `origin/master` `egress_zone_id` was an `egress`-only read and
        // `populate_egress` already took the row's own zone last-write-wins, so
        // the WireGuard shape above already adjudicated `vpnb` there. #6713 did
        // not create the defect; it added the fallback and routed more
        // consumers through the same incomplete resolver. This change is what
        // enforces the invariant across BOTH arms.
        //
        // This also makes the `Some(0)` short-circuit in `egress_zone_id`
        // correct BY CONSTRUCTION rather than by emission-order luck. The
        // pre-#6722 behaviour pinned by
        // `unzoned_interface_with_egress_row_stays_zone_zero_6713` — a zoned
        // trunk with an unzoned unit 0 landing on 0 — held only because the
        // unzoned row happened to be emitted last. Reverse the order, as the
        // WireGuard shape does, and the zone won instead.
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
