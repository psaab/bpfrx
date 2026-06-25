use super::*;

const DEFAULT_V4_TABLE: &str = "inet.0";
const DEFAULT_V6_TABLE: &str = "inet6.0";
const MAX_NEXT_TABLE_DEPTH: usize = 8;

pub(super) fn classify_metadata(
    meta: UserspaceDpMeta,
    validation: ValidationState,
) -> PacketDisposition {
    if !validation.snapshot_installed {
        return PacketDisposition::NoSnapshot;
    }
    if meta.config_generation != validation.config_generation {
        return PacketDisposition::ConfigGenerationMismatch;
    }
    if meta.fib_generation != validation.fib_generation {
        return PacketDisposition::FibGenerationMismatch;
    }
    match meta.addr_family as i32 {
        libc::AF_INET | libc::AF_INET6 => PacketDisposition::Valid,
        _ => PacketDisposition::UnsupportedPacket,
    }
}

pub(super) fn canonical_route_table(table: &str, is_ipv6: bool) -> String {
    if is_ipv6 {
        if table == "inet.0" {
            return "inet6.0".to_string();
        }
        if let Some(prefix) = table.strip_suffix(".inet.0") {
            return format!("{prefix}.inet6.0");
        }
        return table.to_string();
    }
    if table == "inet6.0" {
        return "inet.0".to_string();
    }
    if let Some(prefix) = table.strip_suffix(".inet6.0") {
        return format!("{prefix}.inet.0");
    }
    table.to_string()
}

pub(super) fn neighbor_state_usable(state: &str) -> bool {
    let normalized = state.to_ascii_lowercase();
    !(normalized.contains("failed") || normalized.contains("incomplete"))
}

pub(super) fn parse_packet_destination(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
) -> Option<IpAddr> {
    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
    let l3 = meta.l3_offset as usize;
    match meta.addr_family as i32 {
        libc::AF_INET => {
            let end = l3.checked_add(20)?;
            if end > frame.len() {
                return None;
            }
            Some(IpAddr::V4(Ipv4Addr::new(
                frame[l3 + 16],
                frame[l3 + 17],
                frame[l3 + 18],
                frame[l3 + 19],
            )))
        }
        libc::AF_INET6 => {
            let end = l3.checked_add(40)?;
            if end > frame.len() {
                return None;
            }
            Some(IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&frame[l3 + 24..l3 + 40]).ok()?,
            )))
        }
        _ => None,
    }
}

pub(super) fn resolve_forwarding(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    state: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
) -> ForwardingResolution {
    let Some(dst) = parse_packet_destination(area, desc, meta) else {
        return ForwardingResolution {
            disposition: ForwardingDisposition::NoRoute,
            local_ifindex: 0,
            egress_ifindex: 0,
            tx_ifindex: 0,
            tunnel_endpoint_id: 0,
            next_hop: None,
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        };
    };
    lookup_forwarding_resolution_with_dynamic(state, dynamic_neighbors, dst)
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn match_source_nat_for_flow(
    forwarding: &ForwardingState,
    from_zone: &str,
    to_zone: &str,
    egress_ifindex: i32,
    flow: &SessionFlow,
) -> Option<NatDecision> {
    let egress = forwarding.egress.get(&egress_ifindex)?;
    match_source_nat(
        &forwarding.source_nat_rules,
        from_zone,
        to_zone,
        flow.src_ip,
        flow.dst_ip,
        egress.primary_v4,
        egress.primary_v6,
    )
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn match_source_nat_for_flow_result(
    forwarding: &ForwardingState,
    from_zone: &str,
    to_zone: &str,
    egress_ifindex: i32,
    flow: &SessionFlow,
) -> SourceNatLookup {
    let mut counter = None;
    match_source_nat_for_flow_result_at(
        forwarding,
        from_zone,
        to_zone,
        egress_ifindex,
        flow,
        0,
        false,
        &mut counter,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn match_source_nat_for_flow_result_at(
    forwarding: &ForwardingState,
    from_zone: &str,
    to_zone: &str,
    egress_ifindex: i32,
    flow: &SessionFlow,
    now_ns: u64,
    // #1852: gate pool-mode SNAT allocation for non-first fragments.
    non_first_fragment: bool,
    // #2218: out-param — the matched SNAT rule's per-rule hit counter.
    matched_counter: &mut Option<std::sync::Arc<crate::nat::NatRuleCounter>>,
) -> SourceNatLookup {
    let Some(egress) = forwarding.egress.get(&egress_ifindex) else {
        return SourceNatLookup::NoMatch;
    };
    crate::nat::match_source_nat_result_for_tuple(
        &forwarding.source_nat_rules,
        from_zone,
        to_zone,
        flow.src_ip,
        flow.dst_ip,
        flow.forward_key.protocol,
        flow.forward_key.src_port,
        flow.forward_key.dst_port,
        egress.primary_v4,
        egress.primary_v6,
        now_ns,
        non_first_fragment,
        matched_counter,
    )
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn zone_pair_for_flow(
    forwarding: &ForwardingState,
    ingress_ifindex: i32,
    egress_ifindex: i32,
) -> (String, String) {
    zone_pair_for_flow_with_override(forwarding, ingress_ifindex, None, egress_ifindex)
}

pub(super) fn zone_pair_for_flow_with_override(
    forwarding: &ForwardingState,
    ingress_ifindex: i32,
    ingress_zone_override: Option<&str>,
    egress_ifindex: i32,
) -> (String, String) {
    // #921: this helper is `#[cfg_attr(not(test), allow(dead_code))]`
    // (see zone_pair_for_flow above) and is only called from tests.
    // After #921, `ifindex_to_zone_id` and `EgressInterface.zone_id`
    // are u16. Resolve back to the name via `zone_id_to_name` for
    // the test-only String API. Slow path; allocations are fine.
    let from_zone = ingress_zone_override
        .map(|zone| zone.to_string())
        .or_else(|| {
            forwarding
                .ifindex_to_zone_id
                .get(&ingress_ifindex)
                .and_then(|id| forwarding.zone_id_to_name.get(id).cloned())
        })
        .unwrap_or_default();
    let to_zone = forwarding
        .egress
        .get(&egress_ifindex)
        .and_then(|iface| forwarding.zone_id_to_name.get(&iface.zone_id).cloned())
        .unwrap_or_default();
    (from_zone, to_zone)
}

/// #919/#922: zero-allocation production zone-pair resolver. Returns
/// `(from_id, to_id)` u16 pair directly without `String` materialisation.
/// `ingress_zone_override` is `Option<u16>` (parsed from fabric MAC),
/// not `Option<&str>` — callers no longer round-trip through names.
/// Returns `(0, 0)` segments for ifindexes not in the zone maps; the
/// caller treats `0` as "unknown" and falls back to default policy.
#[inline]
pub(super) fn zone_pair_ids_for_flow_with_override(
    forwarding: &ForwardingState,
    ingress_ifindex: i32,
    ingress_zone_override: Option<u16>,
    egress_ifindex: i32,
) -> (u16, u16) {
    // #921: single-hop direct lookup. Was two HashMap lookups
    // (ifindex → String → u16) and one String hash; now one
    // (ifindex → u16) for ingress and a struct field load for egress.
    let from_id = ingress_zone_override
        .or_else(|| forwarding.ifindex_to_zone_id.get(&ingress_ifindex).copied())
        .unwrap_or(0);
    let to_id = forwarding
        .egress
        .get(&egress_ifindex)
        .map(|iface| iface.zone_id)
        .unwrap_or(0);
    (from_id, to_id)
}

/// #919/#922 test convenience: ID-pair without override.
#[cfg(test)]
pub(super) fn zone_pair_ids_for_flow(
    forwarding: &ForwardingState,
    ingress_ifindex: i32,
    egress_ifindex: i32,
) -> (u16, u16) {
    zone_pair_ids_for_flow_with_override(forwarding, ingress_ifindex, None, egress_ifindex)
}

pub(super) fn allow_unsolicited_dns_reply(
    forwarding: &ForwardingState,
    flow: &SessionFlow,
) -> bool {
    forwarding.allow_dns_reply
        && flow.forward_key.protocol == PROTO_UDP
        && flow.forward_key.src_port == 53
}

pub(super) fn owner_rg_for_flow(forwarding: &ForwardingState, egress_ifindex: i32) -> i32 {
    forwarding
        .egress
        .get(&egress_ifindex)
        .map(|iface| iface.redundancy_group.max(0))
        .unwrap_or_default()
}

pub(super) fn owner_rg_for_resolution(
    forwarding: &ForwardingState,
    resolution: ForwardingResolution,
) -> i32 {
    if resolution.tunnel_endpoint_id != 0 {
        return forwarding
            .tunnel_endpoints
            .get(&resolution.tunnel_endpoint_id)
            // #1873 (Codex code r3): a stored tunnel resolution whose
            // egress_ifindex (= the owning netdev's logical_ifindex at
            // resolve time) does not match the CURRENT row belongs to a
            // re-owned id — attributing the NEW owner's RG to it would
            // re-home a stale, drop-only session under the new tunnel
            // in HA metadata/indexes. Return 0 (unknown owner) so
            // callers keep the existing attribution. Fresh resolutions
            // always match (same state), so this only fires for stale
            // stored/synced entries.
            .filter(|endpoint| {
                resolution.egress_ifindex <= 0
                    || endpoint.logical_ifindex == resolution.egress_ifindex
            })
            .map(|endpoint| endpoint.redundancy_group.max(0))
            .unwrap_or_default();
    }
    owner_rg_for_flow(forwarding, resolution.egress_ifindex)
}

pub(super) fn ingress_is_fabric(forwarding: &ForwardingState, ingress_ifindex: i32) -> bool {
    forwarding.fabrics.iter().any(|fabric| {
        fabric.parent_ifindex == ingress_ifindex || fabric.overlay_ifindex == ingress_ifindex
    })
}

pub(super) fn ingress_is_fabric_overlay(
    forwarding: &ForwardingState,
    ingress_ifindex: i32,
) -> bool {
    forwarding
        .fabrics
        .iter()
        .any(|fabric| fabric.overlay_ifindex == ingress_ifindex)
}

pub(super) fn resolve_fabric_links_from_snapshots(
    snapshots: &[crate::FabricSnapshot],
    egress: &FastMap<i32, EgressInterface>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
) -> Vec<FabricLink> {
    let mut out = Vec::with_capacity(snapshots.len());
    for fabric in snapshots {
        if fabric.parent_ifindex <= 0 {
            continue;
        }
        let Ok(peer_addr) = fabric.peer_address.parse::<IpAddr>() else {
            continue;
        };
        let local_mac = parse_mac(&fabric.local_mac)
            .or_else(|| egress.get(&fabric.parent_ifindex).map(|e| e.src_mac));
        let Some(local_mac) = local_mac else { continue };
        let peer_mac = parse_mac(&fabric.peer_mac).or_else(|| {
            dynamic_neighbors
                .get(&(fabric.overlay_ifindex, peer_addr))
                .or_else(|| dynamic_neighbors.get(&(fabric.parent_ifindex, peer_addr)))
                .map(|e| e.mac)
        });
        let Some(peer_mac) = peer_mac else { continue };
        out.push(FabricLink {
            parent_ifindex: fabric.parent_ifindex,
            overlay_ifindex: fabric.overlay_ifindex,
            peer_addr,
            peer_mac,
            local_mac,
        });
    }
    out
}

pub(super) fn resolve_fabric_redirect(
    forwarding: &ForwardingState,
) -> Option<ForwardingResolution> {
    resolve_fabric_redirect_from_list(&forwarding.fabrics)
}

pub(super) fn resolve_fabric_redirect_from_list(
    fabrics: &[FabricLink],
) -> Option<ForwardingResolution> {
    let fabric = fabrics
        .iter()
        .find(|fabric| fabric.parent_ifindex > 0)
        .copied()?;
    Some(ForwardingResolution {
        disposition: ForwardingDisposition::FabricRedirect,
        local_ifindex: 0,
        egress_ifindex: fabric.parent_ifindex,
        tx_ifindex: fabric.parent_ifindex,
        tunnel_endpoint_id: 0,
        next_hop: Some(fabric.peer_addr),
        neighbor_mac: Some(fabric.peer_mac),
        src_mac: Some(fabric.local_mac),
        tx_vlan_id: 0,
    })
}

pub(super) fn resolve_zone_encoded_fabric_redirect(
    forwarding: &ForwardingState,
    ingress_zone: &str,
) -> Option<ForwardingResolution> {
    let zone_id = forwarding.zone_name_to_id.get(ingress_zone).copied()?;
    resolve_zone_encoded_fabric_redirect_by_id(forwarding, zone_id)
}

/// #919/#922: ID-keyed variant of `resolve_zone_encoded_fabric_redirect`.
/// Avoids the name-string round-trip when the caller already has a u16
/// zone ID (e.g. from `SessionMetadata.ingress_zone`).
pub(super) fn resolve_zone_encoded_fabric_redirect_by_id(
    forwarding: &ForwardingState,
    zone_id: u16,
) -> Option<ForwardingResolution> {
    let mut resolution = resolve_fabric_redirect(forwarding)?;
    if zone_id == 0 || zone_id > u8::MAX as u16 {
        return None;
    }
    resolution.src_mac = Some([0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, zone_id as u8]);
    Some(resolution)
}

pub(super) fn redirect_via_fabric_if_needed(
    forwarding: &ForwardingState,
    resolution: ForwardingResolution,
    ingress_ifindex: i32,
) -> ForwardingResolution {
    if resolution.disposition != ForwardingDisposition::HAInactive {
        return resolution;
    }
    if ingress_is_fabric(forwarding, ingress_ifindex) {
        return resolution;
    }
    resolve_fabric_redirect(forwarding).unwrap_or(resolution)
}

pub(super) fn prefer_local_forward_candidate_for_fabric_ingress(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    now_secs: u64,
    fabric_ingress: bool,
    target_ip: IpAddr,
    resolution: ForwardingResolution,
) -> ForwardingResolution {
    if !fabric_ingress || matches!(resolution.disposition, ForwardingDisposition::LocalDelivery) {
        return resolution;
    }

    let current_owner_rg = owner_rg_for_resolution(forwarding, resolution);
    let current_egress_is_fabric =
        resolution.egress_ifindex > 0 && ingress_is_fabric(forwarding, resolution.egress_ifindex);
    if !current_egress_is_fabric
        && current_owner_rg > 0
        && resolution.disposition != ForwardingDisposition::FabricRedirect
    {
        return resolution;
    }

    let local_resolution = enforce_ha_resolution_snapshot(
        forwarding,
        ha_state,
        now_secs,
        lookup_forwarding_resolution_with_dynamic(forwarding, dynamic_neighbors, target_ip),
    );
    let local_owner_rg = owner_rg_for_resolution(forwarding, local_resolution);
    let local_egress_is_fabric = local_resolution.egress_ifindex > 0
        && ingress_is_fabric(forwarding, local_resolution.egress_ifindex);
    if matches!(
        local_resolution.disposition,
        ForwardingDisposition::ForwardCandidate | ForwardingDisposition::MissingNeighbor
    ) && local_owner_rg > 0
        && !local_egress_is_fabric
    {
        return local_resolution;
    }

    resolution
}

pub(super) fn cluster_peer_return_fast_path(
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    packet_frame: &[u8],
    meta: UserspaceDpMeta,
    ingress_zone_override: Option<u16>,
    resolution_target: IpAddr,
) -> Option<(SessionDecision, SessionMetadata)> {
    if !ingress_is_fabric(forwarding, meta.ingress_ifindex as i32) {
        return None;
    }
    let ingress_zone = ingress_zone_override?;
    if is_icmp_echo_request(packet_frame, meta) {
        return None;
    }
    // #2151: `is_initial_syn` == the prior
    // `(tcp_flags & SYN) != 0 && (tcp_flags & ACK) == 0` — a bare
    // connection-opening SYN has no peer-owned session to return for.
    if meta.protocol == PROTO_TCP && crate::tcp_flags::is_initial_syn(meta.tcp_flags) {
        return None;
    }

    let fabric_return_resolution =
        lookup_forwarding_resolution_with_dynamic(forwarding, dynamic_neighbors, resolution_target);
    if fabric_return_resolution.disposition != ForwardingDisposition::ForwardCandidate {
        return None;
    }
    // #921: direct ifindex → u16 lookup (was a two-hop name round-trip).
    let egress_zone = forwarding
        .ifindex_to_zone_id
        .get(&fabric_return_resolution.egress_ifindex)
        .copied()?;
    let metadata = SessionMetadata {
        ingress_zone,
        egress_zone,
        owner_rg_id: owner_rg_for_resolution(forwarding, fabric_return_resolution),
        fabric_ingress: true,
        is_reverse: true,
        nat64_reverse: None,
        // #2508: fabric-return reverse seed carries no local per-policy
        // `then log` selection (the admitting node logs).
        log_session_init: false,
        log_session_close: false,
    };
    Some((
        SessionDecision {
            resolution: fabric_return_resolution,
            nat: NatDecision::default(),
        },
        metadata,
    ))
}

pub(super) fn is_icmp_echo_request(packet_frame: &[u8], meta: UserspaceDpMeta) -> bool {
    if !matches!(meta.protocol, PROTO_ICMP | PROTO_ICMPV6) {
        return false;
    }
    packet_frame
        .get(meta.l4_offset as usize)
        .copied()
        .map(|icmp_type| {
            matches!(
                (meta.protocol, icmp_type),
                (PROTO_ICMP, 8) | (PROTO_ICMPV6, 128)
            )
        })
        .unwrap_or(false)
}

pub(super) fn resolve_ingress_logical_ifindex(
    forwarding: &ForwardingState,
    ingress_ifindex: i32,
    ingress_vlan_id: u16,
) -> Option<i32> {
    forwarding
        .ingress_logical_ifindex
        .get(&(ingress_ifindex, ingress_vlan_id))
        .copied()
}

pub(super) fn enforce_ha_resolution(
    forwarding: &ForwardingState,
    ha_state: &Arc<ArcSwap<BTreeMap<i32, HAGroupRuntime>>>,
    resolution: ForwardingResolution,
) -> ForwardingResolution {
    enforce_ha_resolution_at(
        forwarding,
        ha_state,
        monotonic_nanos() / 1_000_000_000,
        resolution,
    )
}

pub(super) fn enforce_ha_resolution_at(
    forwarding: &ForwardingState,
    ha_state: &Arc<ArcSwap<BTreeMap<i32, HAGroupRuntime>>>,
    now_secs: u64,
    resolution: ForwardingResolution,
) -> ForwardingResolution {
    let state = ha_state.load();
    enforce_ha_resolution_snapshot(forwarding, state.as_ref(), now_secs, resolution)
}

pub(super) fn enforce_ha_resolution_snapshot(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    now_secs: u64,
    resolution: ForwardingResolution,
) -> ForwardingResolution {
    if !matches!(
        resolution.disposition,
        ForwardingDisposition::ForwardCandidate
            | ForwardingDisposition::MissingNeighbor
            | ForwardingDisposition::LocalDelivery
    ) {
        return resolution;
    }
    if resolution.disposition == ForwardingDisposition::LocalDelivery && ha_state.is_empty() {
        return resolution;
    }
    let owner_rg_id = owner_rg_for_resolution(forwarding, resolution);
    if owner_rg_id <= 0 {
        // In cluster mode, rg=0 on a ForwardCandidate to an egress interface
        // means the forwarding snapshot predates the RETH RG propagation fix.
        // Treat as invalid (force re-resolution through the slow path) rather
        // than "always active" which would let stale cached entries bypass
        // HA checks after RG failover.
        if resolution.disposition != ForwardingDisposition::LocalDelivery
            && !ha_state.is_empty()
            && resolution.egress_ifindex > 0
        {
            return ForwardingResolution {
                disposition: ForwardingDisposition::HAInactive,
                ..resolution
            };
        }
        return resolution;
    }
    let Some(group) = ha_state.get(&owner_rg_id) else {
        return ForwardingResolution {
            disposition: ForwardingDisposition::HAInactive,
            ..resolution
        };
    };
    if !group.is_forwarding_active(now_secs) {
        return ForwardingResolution {
            disposition: ForwardingDisposition::HAInactive,
            ..resolution
        };
    }
    resolution
}

pub(super) fn cached_flow_decision_valid(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    now_secs: u64,
    cached_owner_rg_id: i32,
    fabric_ingress: bool,
    target_ip: IpAddr,
    resolution: ForwardingResolution,
) -> bool {
    if enforce_ha_resolution_snapshot(forwarding, ha_state, now_secs, resolution) != resolution {
        return false;
    }
    // RG-stamped redirect hits are the common split-RG cache case. Once the
    // cached owner RG becomes locally active again, invalidate immediately and
    // let the slow path recompute the current local/fabric decision instead of
    // taking a neighbor-map lock on every cache hit.
    if cached_owner_rg_id > 0
        && ha_state
            .get(&cached_owner_rg_id)
            .is_some_and(|group| group.is_forwarding_active(now_secs))
        && (resolution.disposition == ForwardingDisposition::FabricRedirect || fabric_ingress)
    {
        return false;
    }
    if resolution.disposition == ForwardingDisposition::FabricRedirect {
        let local_resolution = enforce_ha_resolution_snapshot(
            forwarding,
            ha_state,
            now_secs,
            lookup_forwarding_resolution_with_dynamic(forwarding, dynamic_neighbors, target_ip),
        );
        let local_owner_rg = owner_rg_for_resolution(forwarding, local_resolution);
        let local_egress_is_fabric = local_resolution.egress_ifindex > 0
            && ingress_is_fabric(forwarding, local_resolution.egress_ifindex);
        if matches!(
            local_resolution.disposition,
            ForwardingDisposition::ForwardCandidate | ForwardingDisposition::MissingNeighbor
        ) && local_owner_rg > 0
            && !local_egress_is_fabric
        {
            return false;
        }
    }
    if fabric_ingress
        && prefer_local_forward_candidate_for_fabric_ingress(
            forwarding,
            ha_state,
            dynamic_neighbors,
            now_secs,
            true,
            target_ip,
            resolution,
        ) != resolution
    {
        return false;
    }
    true
}

pub(super) fn finalize_new_flow_ha_resolution(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    now_secs: u64,
    resolution: ForwardingResolution,
    fabric_ingress: bool,
    ingress_ifindex: i32,
    ingress_zone: u16,
    ha_startup_grace_until_secs: u64,
) -> ForwardingResolution {
    let enforced = super::session_glue::enforce_session_ha_resolution(
        forwarding,
        ha_state,
        now_secs,
        resolution,
        ingress_ifindex,
        ha_startup_grace_until_secs,
    );
    if fabric_ingress && enforced.disposition == ForwardingDisposition::HAInactive {
        return resolution;
    }
    super::session_glue::redirect_session_via_fabric_if_needed(
        forwarding,
        enforced,
        fabric_ingress,
        ingress_zone,
    )
}

pub(super) fn demoted_owner_rgs(
    previous: &BTreeMap<i32, HAGroupRuntime>,
    current: &BTreeMap<i32, HAGroupRuntime>,
) -> Vec<i32> {
    previous
        .iter()
        .filter_map(|(rg_id, old)| {
            let became_inactive = match current.get(rg_id) {
                Some(new) => old.active && !new.active,
                None => old.active,
            };
            became_inactive.then_some(*rg_id)
        })
        .collect()
}

pub(super) fn activated_owner_rgs(
    previous: &BTreeMap<i32, HAGroupRuntime>,
    current: &BTreeMap<i32, HAGroupRuntime>,
) -> Vec<i32> {
    current
        .iter()
        .filter_map(|(rg_id, new)| {
            let became_active = match previous.get(rg_id) {
                Some(old) => !old.active && new.active,
                None => new.active,
            };
            became_active.then_some(*rg_id)
        })
        .collect()
}

/// Return the `security flow tcp-mss all-tcp` clamp value (0 = unset).
///
/// #2486: `all-tcp` is the context-agnostic clamp — it applies to every
/// forwarded TCP SYN regardless of tunnel context, and also serves as
/// the fallback for the per-context selectors (`gre-in`, tunnel egress)
/// below. `ipsec-vpn` is NOT read here: there is no IPsec context in the
/// userspace forward-build path (ESP/AH/IKE is local-delivered to the
/// kernel XFRM stack and the decrypted inner packets re-enter as plain
/// traffic with no IPsec marker), so `security flow tcp-mss ipsec-vpn`
/// is rejected at commit (pkg/config compiler) rather than carried as
/// dead config.
pub(super) fn effective_tcp_mss(forwarding: &ForwardingState) -> u16 {
    forwarding.tcp_mss_all_tcp
}

pub(super) fn native_gre_inner_mtu(
    forwarding: &ForwardingState,
    decision: &SessionDecision,
) -> usize {
    if decision.resolution.tunnel_endpoint_id == 0 {
        return 0;
    }
    let Some(endpoint) = forwarding
        .tunnel_endpoints
        .get(&decision.resolution.tunnel_endpoint_id)
    else {
        return 0;
    };
    // #2517: resolve the outer/transport MTU through the SAME #2300 SSOT
    // helper the WireGuard MSS clamp uses (`tunnel_outer_mtu`) so the two
    // tunnel MSS paths cannot drift. That helper falls back to the
    // standard 1500 underlay MTU when EVERY egress lookup misses (a
    // transient egress-map miss during re-reconciliation / interface
    // bringup) instead of the old `unwrap_or_default()` → 0, which made
    // `native_gre_tcp_mss` return 0 and silently DISABLE a configured GRE
    // outbound TCP MSS clamp until the next reconcile. `tunnel_outer_mtu`
    // also filters out an explicitly-zero stored egress MTU, so it never
    // returns 0; `transport_mtu` here is therefore always >= 1500.
    let transport_mtu = tunnel_outer_mtu(forwarding, decision, endpoint);
    let outer_ip_header_len = match endpoint.outer_family {
        libc::AF_INET => 20usize,
        libc::AF_INET6 => 40usize,
        _ => return 0,
    };
    let gre_header_len = 4usize + if endpoint.key != 0 { 4 } else { 0 };
    transport_mtu
        .checked_sub(outer_ip_header_len + gre_header_len)
        .unwrap_or_default()
}

pub(super) fn native_gre_tcp_mss(
    forwarding: &ForwardingState,
    decision: &SessionDecision,
    addr_family: u8,
) -> u16 {
    if decision.resolution.tunnel_endpoint_id == 0 {
        return 0;
    }
    if forwarding.tcp_mss_gre_out > 0 {
        return forwarding.tcp_mss_gre_out;
    }
    let mtu = native_gre_inner_mtu(forwarding, decision);
    if mtu == 0 {
        return 0;
    }
    let ip_header_len = match addr_family as i32 {
        libc::AF_INET => 20usize,
        libc::AF_INET6 => 40usize,
        _ => return 0,
    };
    let Some(max_mss) = mtu.checked_sub(ip_header_len + 20) else {
        return 0;
    };
    u16::try_from(max_mss).unwrap_or_default()
}

/// Resolve the real outer-link (transport) MTU for a tunnel endpoint —
/// the egress interface the OUTER encapped datagram leaves on, NOT the
/// tunnel device. This is the #2300 SSOT resolver shared by BOTH tunnel
/// MSS-clamp paths: the WireGuard clamp (#2299) and the native-GRE
/// clamp (`native_gre_inner_mtu`, #2517). Resolution chain: transport
/// ifindex → stored resolution egress → endpoint logical ifindex;
/// `unwrap_or(1500)` only when every lookup misses (a transient
/// egress-map miss must NOT zero the clamp). The `.filter(|m| *m > 0)`
/// also coerces an explicitly-zero stored egress MTU to the 1500
/// fallback, so this helper never returns 0.
pub(super) fn tunnel_outer_mtu(
    forwarding: &ForwardingState,
    decision: &SessionDecision,
    endpoint: &TunnelEndpoint,
) -> usize {
    let transport_ifindex = resolve_ingress_logical_ifindex(
        forwarding,
        decision.resolution.tx_ifindex,
        decision.resolution.tx_vlan_id,
    )
    .unwrap_or(decision.resolution.tx_ifindex);
    forwarding
        .egress
        .get(&transport_ifindex)
        .or_else(|| forwarding.egress.get(&decision.resolution.egress_ifindex))
        .or_else(|| forwarding.egress.get(&endpoint.logical_ifindex))
        .map(|egress| egress.mtu)
        .filter(|m| *m > 0)
        .unwrap_or(1500)
}

/// Dispatch the per-tunnel TCP MSS clamp by tunnel kind (#2299).
///
/// For a `mode == "wireguard"` endpoint the GRE MSS formula
/// (`native_gre_tcp_mss`) is ~36-60 bytes too high — it ignores
/// UDP(8) + WG data header(16) + Poly1305 tag(16) + §5.4.6 padding(≤15).
/// A SYN clamped with the GRE value lets the peer send full-MSS data
/// segments that the WG encap MTU guard then silently drops
/// (`encap_mtu_drops`). Route WG-bound SYNs through `wg::mss::wg_tcp_mss`
/// instead, derived from `tunnel_outer_mtu` (resolve the transport
/// `tx_ifindex`/`tx_vlan` → egress, falling back to `egress_ifindex`
/// then the endpoint's `logical_ifindex`, with a 1500 floor).
///
/// NOTE (#2715): this is NOT the same path the encap MTU guard now
/// reads. Post-#2715 the encap guard route-resolves the physical egress
/// via the peer endpoint address; the MSS clamp still uses the
/// `tunnel_outer_mtu` (tx_ifindex→egress→logical) chain above. That
/// divergence is safe here, not a live bug: a route-resolved WG endpoint
/// returns NoRoute on this AF_XDP builder (no synthetic egress to read),
/// and the clamp errs toward a SMALLER MSS, so it can never advertise an
/// MSS larger than the encap guard tolerates — it cannot reintroduce
/// `encap_mtu_drops`.
///
/// Non-WG endpoints (and the plain-forward path, `tunnel_endpoint_id ==
/// 0`) keep the GRE formula bit-for-bit. No new branch on the
/// plain-forward fast path: the `tunnel_endpoint_id == 0` early-out
/// short-circuits before the endpoint lookup, exactly as
/// `native_gre_tcp_mss` does today.
pub(super) fn tunnel_tcp_mss(
    forwarding: &ForwardingState,
    decision: &SessionDecision,
    addr_family: u8,
) -> u16 {
    if decision.resolution.tunnel_endpoint_id == 0 {
        return 0;
    }
    let Some(endpoint) = forwarding
        .tunnel_endpoints
        .get(&decision.resolution.tunnel_endpoint_id)
    else {
        return 0;
    };
    if endpoint.mode == "wireguard" {
        // outer family from the endpoint; inner family from the packet
        // being forwarded; outer MTU from the real egress interface.
        let outer_mtu = tunnel_outer_mtu(forwarding, decision, endpoint);
        return crate::afxdp::wg::mss::wg_tcp_mss(
            endpoint.outer_family,
            addr_family as i32,
            outer_mtu,
        );
    }
    native_gre_tcp_mss(forwarding, decision, addr_family)
}

/// #2486: select the per-packet TCP MSS clamp value by forwarding
/// context. The three enforceable `security flow tcp-mss` contexts
/// (all-tcp, gre-in, gre-out/WG) are resolved here at frame-build time so
/// an accepted clamp is actually enforced; `ipsec-vpn` is rejected at
/// commit and never reaches this path
/// (previously only tunnel egress clamped — `all-tcp` / `gre-in` were
/// dead config and `gre-in` produced a silent full-MSS blackhole on the
/// GRE return path).
///
/// Priority (most specific wins, `all-tcp` is the universal fallback):
///   1. Tunnel egress (`tunnel_endpoint_id != 0`): the GRE/WG
///      overhead-aware value via `tunnel_tcp_mss` (gre-out, or the
///      MTU-derived formula). Falls back to `all-tcp` only when that
///      yields 0 (no gre-out and no MTU available).
///   2. GRE-decapped ingress (`GRE_DECAP_INGRESS_FLAG`): `gre-in`,
///      falling back to `all-tcp`.
///   3. Plain forwarded packet: `all-tcp`.
///
/// `ipsec-vpn` is intentionally absent — it is rejected at commit (no
/// IPsec context reaches this path; see `effective_tcp_mss`).
pub(super) fn select_tcp_mss(
    forwarding: &ForwardingState,
    decision: &SessionDecision,
    meta: &ForwardPacketMeta,
) -> u16 {
    if decision.resolution.tunnel_endpoint_id != 0 {
        let tunnel = tunnel_tcp_mss(forwarding, decision, meta.addr_family);
        if tunnel > 0 {
            return tunnel;
        }
        return forwarding.tcp_mss_all_tcp;
    }
    if (meta.meta_flags & GRE_DECAP_INGRESS_FLAG) != 0 && forwarding.tcp_mss_gre_in > 0 {
        return forwarding.tcp_mss_gre_in;
    }
    effective_tcp_mss(forwarding)
}

// #989: clamp_tcp_mss / clamp_tcp_mss_frame relocated to `frame/tcp.rs`.

#[allow(dead_code)]
const ICMP_TE_MAX_PER_SEC: u32 = 100;

/// Rate limiter for ICMP Time Exceeded messages.
#[allow(dead_code)]
struct IcmpTeRateLimiter {
    max_per_sec: u32,
    count: u32,
    window_start_ns: u64,
}

#[allow(dead_code)]
impl IcmpTeRateLimiter {
    fn new(max_per_sec: u32) -> Self {
        Self {
            max_per_sec,
            count: 0,
            window_start_ns: 0,
        }
    }

    fn allow(&mut self, now_ns: u64) -> bool {
        let window = now_ns / 1_000_000_000;
        let prev_window = self.window_start_ns / 1_000_000_000;
        if window != prev_window {
            self.count = 0;
            self.window_start_ns = now_ns;
        }
        if self.count >= self.max_per_sec {
            return false;
        }
        self.count += 1;
        true
    }
}

/// Returns true if the packet is IPsec traffic (ESP protocol 50, AH protocol
/// 51, or IKE UDP ports 500/4500) that should be passed to the kernel for
/// XFRM processing.
///
/// AH (Authentication Header, proto 51) is a configurable host-terminated
/// IPsec protocol (`set security ipsec proposal ... protocol ah`,
/// pkg/config/schema_security.go). Like ESP it carries no transport port, so
/// only the protocol-number arm applies.
///
/// The predicate is family-symmetric — it keys solely on `meta.protocol` —
/// but in practice `meta.protocol == PROTO_AH` only ever occurs for **IPv4
/// AH**. The XDP shim's IPv6 parser treats AH as an extension header and
/// walks THROUGH it (`NEXTHDR_AUTH` arm in `userspace-xdp/src/lib.rs`),
/// setting `meta.protocol` to AH's inner next-header rather than 51. So the
/// `PROTO_AH` arm is a v4-only backstop; it never fires for IPv6 AH.
///
/// This is not a functional gap. IPv6 host-terminated AH-to-self still
/// reaches the kernel XFRM stack via the shim's `is_local_destination`
/// shunt, which fires for any local-destination packet *before* the
/// userspace dataplane runs this predicate; transit AH (v4 or v6) takes
/// ordinary forwarding. ESP (proto 50) is parsed as a terminal protocol on
/// both families, so ESP is recognized here for v4 and v6 alike. Giving this
/// predicate true IPv6 AH coverage would require the shim to surface an
/// "AH present" signal instead of walking past the header — out of scope
/// here, and unnecessary given the local-dest shunt.
#[inline]
pub(super) fn is_ipsec_traffic(protocol: u8, dst_port: u16) -> bool {
    protocol == PROTO_ESP
        || protocol == PROTO_AH
        || (protocol == PROTO_UDP && (dst_port == 500 || dst_port == 4500))
}

#[cfg(test)]
pub(super) fn lookup_forwarding_for_ip(
    state: &ForwardingState,
    dst: IpAddr,
) -> ForwardingDisposition {
    lookup_forwarding_resolution(state, dst).disposition
}

pub(super) fn lookup_forwarding_resolution(
    state: &ForwardingState,
    dst: IpAddr,
) -> ForwardingResolution {
    lookup_forwarding_resolution_inner(state, None, dst, None)
}

pub(super) fn lookup_forwarding_resolution_with_dynamic(
    state: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    dst: IpAddr,
) -> ForwardingResolution {
    lookup_forwarding_resolution_inner(state, Some(dynamic_neighbors), dst, None)
}

/// #2734: like `lookup_forwarding_resolution_with_dynamic`, but selects an
/// equal-cost next-hop by the per-FLOW 5-tuple hash (from the session
/// forward key) so distinct flows to the same destination spread across
/// ECMP members. Used by the session forwarding-resolution path.
pub(super) fn lookup_forwarding_resolution_with_dynamic_for_flow(
    state: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    dst: IpAddr,
    flow_key: &crate::session::SessionKey,
) -> ForwardingResolution {
    lookup_forwarding_resolution_inner_ecmp(
        state,
        Some(dynamic_neighbors),
        dst,
        None,
        Some(ecmp_hash_flow(flow_key)),
    )
}

pub(super) fn lookup_forwarding_resolution_in_table_with_dynamic(
    state: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    dst: IpAddr,
    table: Option<&str>,
) -> ForwardingResolution {
    lookup_forwarding_resolution_inner(state, Some(dynamic_neighbors), dst, table)
}

pub(super) fn lookup_forwarding_resolution_inner(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<ShardedNeighborMap>>,
    dst: IpAddr,
    table: Option<&str>,
) -> ForwardingResolution {
    lookup_forwarding_resolution_inner_ecmp(state, dynamic_neighbors, dst, table, None)
}

/// #2734: as `lookup_forwarding_resolution_inner`, plus an optional
/// per-flow ECMP spread key. `ecmp_flow_hash = Some(h)` selects the
/// equal-cost member by the 5-tuple flow hash (per-flow spread); `None`
/// falls back to the per-destination hash (#2389 behavior) for callers
/// without a flow context.
pub(super) fn lookup_forwarding_resolution_inner_ecmp(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<ShardedNeighborMap>>,
    dst: IpAddr,
    table: Option<&str>,
    ecmp_flow_hash: Option<u64>,
) -> ForwardingResolution {
    match dst {
        IpAddr::V4(ip) => {
            if state.local_v4.contains(&ip) {
                let local_ifindex = state
                    .connected_v4
                    .iter()
                    .find(|entry| entry.prefix.addr() == ip)
                    .map(|entry| entry.ifindex)
                    .unwrap_or(0);
                return ForwardingResolution {
                    disposition: ForwardingDisposition::LocalDelivery,
                    local_ifindex,
                    egress_ifindex: local_ifindex,
                    tx_ifindex: local_ifindex,
                    tunnel_endpoint_id: 0,
                    next_hop: None,
                    neighbor_mac: None,
                    src_mac: None,
                    tx_vlan_id: 0,
                };
            }
            let table = table
                .map(|table| canonical_route_table(table, false))
                .unwrap_or_else(|| DEFAULT_V4_TABLE.to_string());
            lookup_forwarding_resolution_v4(
                state,
                dynamic_neighbors,
                ip,
                &table,
                0,
                true,
                ecmp_flow_hash,
            )
        }
        IpAddr::V6(ip) => {
            if state.local_v6.contains(&ip) {
                let local_ifindex = state
                    .connected_v6
                    .iter()
                    .find(|entry| entry.prefix.addr() == ip)
                    .map(|entry| entry.ifindex)
                    .unwrap_or(0);
                return ForwardingResolution {
                    disposition: ForwardingDisposition::LocalDelivery,
                    local_ifindex,
                    egress_ifindex: local_ifindex,
                    tx_ifindex: local_ifindex,
                    tunnel_endpoint_id: 0,
                    next_hop: None,
                    neighbor_mac: None,
                    src_mac: None,
                    tx_vlan_id: 0,
                };
            }
            let table = table
                .map(|table| canonical_route_table(table, true))
                .unwrap_or_else(|| DEFAULT_V6_TABLE.to_string());
            lookup_forwarding_resolution_v6(
                state,
                dynamic_neighbors,
                ip,
                &table,
                0,
                true,
                ecmp_flow_hash,
            )
        }
    }
}

pub(super) fn ingress_route_table_override(
    forwarding: &ForwardingState,
    frame: &[u8],
    meta: UserspaceDpMeta,
    flow: &SessionFlow,
    ingress_zone_override: Option<u16>,
    event_stream: Option<&crate::event_stream::EventStreamWorkerHandle>,
    now_ns: u64,
) -> Option<String> {
    let ingress_ifindex = resolve_ingress_logical_ifindex(
        forwarding,
        meta.ingress_ifindex as i32,
        meta.ingress_vlan_id,
    )
    .unwrap_or(meta.ingress_ifindex as i32);
    let is_v6 = matches!(flow.dst_ip, IpAddr::V6(_));
    if !crate::filter::interface_filter_affects_route_lookup(
        &forwarding.filter_state,
        ingress_ifindex,
        is_v6,
    ) {
        return None;
    }
    // #2362: PBR terms may carry per-packet L4 match conditions (tcp-flags /
    // is-fragment / icmp-type / icmp-code); build the extra inputs so a
    // `from { tcp-flags ...; } then routing-instance ...` term matches exactly
    // the authored packets.
    let extra = crate::afxdp::frame::term_match_extra_from_frame(frame, meta);
    let routing_result = crate::filter::evaluate_interface_filter_routing_instance_event_counted(
        &forwarding.filter_state,
        ingress_ifindex,
        is_v6,
        flow.src_ip,
        flow.dst_ip,
        meta.protocol,
        flow.forward_key.src_port,
        flow.forward_key.dst_port,
        meta.dscp,
        extra,
        meta.pkt_len as u64,
    )?;
    // #2619: emit the accumulated log_match — it captures fall-through
    // `then { log; next term; }` terms ahead of the routing-instance term that
    // the PBR path previously dropped, AND the routing-instance term's own log
    // (latest matched wins). Its action is already normalized to the verdict the
    // packet receives (#2616). Falls back to nothing when no matched term logged.
    if let Some(log_match) = routing_result.log_match {
        let ingress_zone_id = ingress_zone_override
            .filter(|id| forwarding.zone_id_to_name.contains_key(id))
            .or_else(|| forwarding.ifindex_to_zone_id.get(&ingress_ifindex).copied())
            .or_else(|| {
                forwarding
                    .ifindex_to_zone_id
                    .get(&(meta.ingress_ifindex as i32))
                    .copied()
            })
            .unwrap_or(0);
        emit_filter_log_event(
            event_stream,
            flow,
            meta,
            ingress_zone_id,
            0,
            log_match.filter_id,
            log_match.term_id,
            log_match.action,
            FilterLogSource::Pbr,
            // #2520: AppID via the hot-path app_catalog.lookup.
            resolve_flow_app_id(&forwarding.app_catalog, flow),
            now_ns,
        );
    }
    let routing_instance = routing_result.routing_instance;
    Some(if is_v6 {
        format!("{routing_instance}.inet6.0")
    } else {
        format!("{routing_instance}.inet.0")
    })
}

pub(super) fn interface_nat_local_resolution(
    state: &ForwardingState,
    dst: IpAddr,
) -> Option<ForwardingResolution> {
    match dst {
        IpAddr::V4(ip) => state
            .interface_nat_v4
            .get(&ip)
            .copied()
            .map(|local_ifindex| ForwardingResolution {
                disposition: ForwardingDisposition::LocalDelivery,
                local_ifindex,
                egress_ifindex: local_ifindex,
                tx_ifindex: local_ifindex,
                tunnel_endpoint_id: state
                    .tunnel_endpoint_by_ifindex
                    .get(&local_ifindex)
                    .copied()
                    .unwrap_or_default(),
                next_hop: None,
                neighbor_mac: None,
                src_mac: None,
                tx_vlan_id: 0,
            }),
        IpAddr::V6(ip) => state
            .interface_nat_v6
            .get(&ip)
            .copied()
            .map(|local_ifindex| ForwardingResolution {
                disposition: ForwardingDisposition::LocalDelivery,
                local_ifindex,
                egress_ifindex: local_ifindex,
                tx_ifindex: local_ifindex,
                tunnel_endpoint_id: state
                    .tunnel_endpoint_by_ifindex
                    .get(&local_ifindex)
                    .copied()
                    .unwrap_or_default(),
                next_hop: None,
                neighbor_mac: None,
                src_mac: None,
                tx_vlan_id: 0,
            }),
    }
}

pub(super) fn interface_nat_local_resolution_on_session_miss(
    state: &ForwardingState,
    dst: IpAddr,
    _protocol: u8,
) -> Option<ForwardingResolution> {
    interface_nat_local_resolution(state, dst)
}

pub(super) fn should_cache_local_delivery_session_on_miss(
    state: &ForwardingState,
    resolution_target: IpAddr,
    resolution: ForwardingResolution,
    protocol: u8,
    tcp_flags: u8,
) -> bool {
    if resolution.disposition != ForwardingDisposition::LocalDelivery {
        return false;
    }
    if !matches!(protocol, PROTO_TCP) {
        return true;
    }
    // #2151: prior inline `(tcp_flags & ACK) != 0 && (tcp_flags & SYN) == 0`
    // — do not cache a local-delivery session off a bare/established ACK
    // (no SYN), only off the handshake.
    if crate::tcp_flags::has_ack(tcp_flags) && !crate::tcp_flags::has_syn(tcp_flags) {
        return false;
    }
    let _ = state;
    let _ = resolution_target;
    true
}

pub(super) fn install_helper_local_session_on_miss(
    sessions: &mut SessionTable,
    session_map_fd: c_int,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    key: &SessionKey,
    decision: SessionDecision,
    metadata: SessionMetadata,
    origin: SessionOrigin,
    now_ns: u64,
    protocol: u8,
    tcp_flags: u8,
) -> bool {
    if let Some(previous) = sessions.take_synced_local(key) {
        remove_shared_session(
            shared_sessions,
            shared_nat_sessions,
            shared_forward_wire_sessions,
            shared_owner_rg_indexes,
            key,
        );
        delete_session_map_entry_for_removed_session(
            session_map_fd,
            key,
            previous.decision,
            &previous.metadata,
        );
    }
    if !sessions.install_with_protocol_with_origin(
        key.clone(),
        decision,
        metadata.clone(),
        origin,
        now_ns,
        protocol,
        tcp_flags,
    ) {
        return false;
    }
    let local_entry = SyncedSessionEntry {
        key: key.clone(),
        decision,
        metadata,
        origin,
        protocol,
        tcp_flags,
        // Local forwarding-learn entry: no peer install generation (#2170).
        generation: 0,
    };
    // #1789: count a failed helper-local session publish (same
    // shim-missing-key consequence as every other publish site).
    if publish_session_map_entry_for_session(session_map_fd, key, decision, &local_entry.metadata)
        .is_err()
    {
        crate::afxdp::bpf_map::SESSION_PUBLISH_ERRORS_SHARED
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    true
}

pub(super) fn should_block_tunnel_interface_nat_session_miss(
    state: &ForwardingState,
    dst: IpAddr,
    protocol: u8,
) -> bool {
    matches!(protocol, PROTO_TCP | PROTO_UDP | PROTO_ICMP | PROTO_ICMPV6)
        && matches!(
            interface_nat_local_resolution(state, dst),
            Some(local) if local.tunnel_endpoint_id != 0
        )
}

pub(super) fn ingress_interface_local_resolution(
    state: &ForwardingState,
    ingress_ifindex: i32,
    ingress_vlan_id: u16,
    dst: IpAddr,
) -> Option<ForwardingResolution> {
    let logical_ifindex = resolve_ingress_logical_ifindex(state, ingress_ifindex, ingress_vlan_id)
        .or_else(|| {
            state.egress.iter().find_map(|(ifindex, iface)| {
                ((iface.bind_ifindex == ingress_ifindex || *ifindex == ingress_ifindex)
                    && iface.vlan_id == ingress_vlan_id)
                    .then_some(*ifindex)
            })
        })
        .filter(|ifindex| *ifindex > 0)
        .unwrap_or(ingress_ifindex);
    let iface = state.egress.get(&logical_ifindex)?;
    let matches_local = match dst {
        IpAddr::V4(ip) => iface.primary_v4 == Some(ip),
        IpAddr::V6(ip) => iface.primary_v6 == Some(ip),
    };
    if !matches_local {
        return None;
    }
    Some(ForwardingResolution {
        disposition: ForwardingDisposition::LocalDelivery,
        local_ifindex: logical_ifindex,
        egress_ifindex: logical_ifindex,
        tx_ifindex: logical_ifindex,
        tunnel_endpoint_id: state
            .tunnel_endpoint_by_ifindex
            .get(&logical_ifindex)
            .copied()
            .unwrap_or_default(),
        next_hop: None,
        neighbor_mac: None,
        src_mac: None,
        tx_vlan_id: 0,
    })
}

pub(super) fn ingress_interface_local_resolution_on_session_miss(
    state: &ForwardingState,
    ingress_ifindex: i32,
    ingress_vlan_id: u16,
    dst: IpAddr,
    _protocol: u8,
) -> Option<ForwardingResolution> {
    ingress_interface_local_resolution(state, ingress_ifindex, ingress_vlan_id, dst)
}

pub(super) fn lookup_forwarding_resolution_v4(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<ShardedNeighborMap>>,
    ip: Ipv4Addr,
    table: &str,
    depth: usize,
    allow_tunnels: bool,
    ecmp_flow_hash: Option<u64>,
) -> ForwardingResolution {
    if depth >= MAX_NEXT_TABLE_DEPTH {
        return ForwardingResolution {
            disposition: ForwardingDisposition::NextTableUnsupported,
            local_ifindex: 0,
            egress_ifindex: 0,
            tx_ifindex: 0,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(ip)),
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        };
    }
    let static_match = state
        .routes_v4
        .get(table)
        .and_then(|routes| routes.iter().find(|entry| entry.prefix.contains(ip)));
    // #2388: connected routes are table-scoped — only consider a connected
    // prefix that belongs to the table being resolved, so a per-VRF /
    // next-table lookup never matches another routing-instance's connected
    // prefix. The vec is sorted longest-prefix-first, so the first matching
    // in-table entry is the most specific.
    let connected_match = state
        .connected_v4
        .iter()
        .find(|entry| entry.table == table && entry.prefix.contains(ip));
    match choose_v4_route(static_match, connected_match) {
        Some(ResolvedRouteV4::Connected {
            ifindex,
            tunnel_endpoint_id,
        }) => {
            if tunnel_endpoint_id != 0 {
                return if allow_tunnels {
                    resolve_tunnel_forwarding_resolution(
                        state,
                        dynamic_neighbors,
                        tunnel_endpoint_id,
                        depth,
                    )
                } else {
                    no_route_resolution(Some(IpAddr::V4(ip)))
                };
            }
            let neighbor = lookup_neighbor_entry(state, dynamic_neighbors, ifindex, IpAddr::V4(ip));
            let mut resolution = ForwardingResolution {
                disposition: if neighbor.is_some() {
                    ForwardingDisposition::ForwardCandidate
                } else {
                    ForwardingDisposition::MissingNeighbor
                },
                local_ifindex: 0,
                egress_ifindex: ifindex,
                tx_ifindex: ifindex,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(ip)),
                neighbor_mac: neighbor.map(|entry| entry.mac),
                src_mac: None,
                tx_vlan_id: 0,
            };
            populate_egress_resolution(state, ifindex, &mut resolution);
            resolution
        }
        Some(ResolvedRouteV4::Static(route)) => {
            if route.discard {
                return ForwardingResolution {
                    disposition: ForwardingDisposition::DiscardRoute,
                    local_ifindex: 0,
                    egress_ifindex: 0,
                    tx_ifindex: 0,
                    tunnel_endpoint_id: 0,
                    next_hop: None,
                    neighbor_mac: None,
                    src_mac: None,
                    tx_vlan_id: 0,
                };
            }
            if !route.next_table.is_empty() {
                let next_table_name = route.next_table.as_str();
                if next_table_name == table {
                    return ForwardingResolution {
                        disposition: ForwardingDisposition::NextTableUnsupported,
                        local_ifindex: 0,
                        egress_ifindex: 0,
                        tx_ifindex: 0,
                        tunnel_endpoint_id: 0,
                        next_hop: Some(IpAddr::V4(ip)),
                        neighbor_mac: None,
                        src_mac: None,
                        tx_vlan_id: 0,
                    };
                }
                // Clone needed: the recursive call borrows `state` again.
                let next_table_name = route.next_table.clone();
                return lookup_forwarding_resolution_v4(
                    state,
                    dynamic_neighbors,
                    ip,
                    &next_table_name,
                    depth + 1,
                    allow_tunnels,
                    ecmp_flow_hash,
                );
            }
            // #2389/#2734: select one equal-cost next-hop, skipping a dead
            // one. Spread by the per-flow 5-tuple hash when supplied,
            // else fall back to the per-destination hash.
            let spread_hash = ecmp_flow_hash.unwrap_or_else(|| ecmp_hash_v4(ip));
            let selected = select_route_next_hop(&route.next_hops, spread_hash, |nh| {
                let target = nh.next_hop.unwrap_or(ip);
                nh.ifindex > 0
                    && lookup_neighbor_entry(state, dynamic_neighbors, nh.ifindex, IpAddr::V4(target))
                        .is_some()
            });
            let (next_hop, ifindex, tunnel_endpoint_id) = match selected {
                Some(nh) => (nh.next_hop, nh.ifindex, nh.tunnel_endpoint_id),
                None => (None, 0, 0),
            };
            if tunnel_endpoint_id != 0 {
                return if allow_tunnels {
                    resolve_tunnel_forwarding_resolution(
                        state,
                        dynamic_neighbors,
                        tunnel_endpoint_id,
                        depth,
                    )
                } else {
                    no_route_resolution(next_hop.map(IpAddr::V4).or(Some(IpAddr::V4(ip))))
                };
            }
            if ifindex <= 0 {
                return no_route_resolution(next_hop.map(IpAddr::V4));
            }
            let target = next_hop.unwrap_or(ip);
            let neighbor =
                lookup_neighbor_entry(state, dynamic_neighbors, ifindex, IpAddr::V4(target));
            let mut resolution = ForwardingResolution {
                disposition: if neighbor.is_some() {
                    ForwardingDisposition::ForwardCandidate
                } else {
                    ForwardingDisposition::MissingNeighbor
                },
                local_ifindex: 0,
                egress_ifindex: ifindex,
                tx_ifindex: ifindex,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(target)),
                neighbor_mac: neighbor.map(|entry| entry.mac),
                src_mac: None,
                tx_vlan_id: 0,
            };
            populate_egress_resolution(state, ifindex, &mut resolution);
            resolution
        }
        None => no_route_resolution(None),
    }
}

pub(super) fn lookup_forwarding_resolution_v6(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<ShardedNeighborMap>>,
    ip: Ipv6Addr,
    table: &str,
    depth: usize,
    allow_tunnels: bool,
    ecmp_flow_hash: Option<u64>,
) -> ForwardingResolution {
    if depth >= MAX_NEXT_TABLE_DEPTH {
        return ForwardingResolution {
            disposition: ForwardingDisposition::NextTableUnsupported,
            local_ifindex: 0,
            egress_ifindex: 0,
            tx_ifindex: 0,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V6(ip)),
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        };
    }
    let static_match = state
        .routes_v6
        .get(table)
        .and_then(|routes| routes.iter().find(|entry| entry.prefix.contains(ip)));
    // #2388: connected routes are table-scoped (see the v4 lookup).
    let connected_match = state
        .connected_v6
        .iter()
        .find(|entry| entry.table == table && entry.prefix.contains(ip));
    match choose_v6_route(static_match, connected_match) {
        Some(ResolvedRouteV6::Connected {
            ifindex,
            tunnel_endpoint_id,
        }) => {
            if tunnel_endpoint_id != 0 {
                return if allow_tunnels {
                    resolve_tunnel_forwarding_resolution(
                        state,
                        dynamic_neighbors,
                        tunnel_endpoint_id,
                        depth,
                    )
                } else {
                    no_route_resolution(Some(IpAddr::V6(ip)))
                };
            }
            let neighbor = lookup_neighbor_entry(state, dynamic_neighbors, ifindex, IpAddr::V6(ip));
            let mut resolution = ForwardingResolution {
                disposition: if neighbor.is_some() {
                    ForwardingDisposition::ForwardCandidate
                } else {
                    ForwardingDisposition::MissingNeighbor
                },
                local_ifindex: 0,
                egress_ifindex: ifindex,
                tx_ifindex: ifindex,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V6(ip)),
                neighbor_mac: neighbor.map(|entry| entry.mac),
                src_mac: None,
                tx_vlan_id: 0,
            };
            populate_egress_resolution(state, ifindex, &mut resolution);
            resolution
        }
        Some(ResolvedRouteV6::Static(route)) => {
            if route.discard {
                return ForwardingResolution {
                    disposition: ForwardingDisposition::DiscardRoute,
                    local_ifindex: 0,
                    egress_ifindex: 0,
                    tx_ifindex: 0,
                    tunnel_endpoint_id: 0,
                    next_hop: None,
                    neighbor_mac: None,
                    src_mac: None,
                    tx_vlan_id: 0,
                };
            }
            if !route.next_table.is_empty() {
                let next_table_name = route.next_table.as_str();
                if next_table_name == table {
                    return ForwardingResolution {
                        disposition: ForwardingDisposition::NextTableUnsupported,
                        local_ifindex: 0,
                        egress_ifindex: 0,
                        tx_ifindex: 0,
                        tunnel_endpoint_id: 0,
                        next_hop: Some(IpAddr::V6(ip)),
                        neighbor_mac: None,
                        src_mac: None,
                        tx_vlan_id: 0,
                    };
                }
                let next_table_name = route.next_table.clone();
                return lookup_forwarding_resolution_v6(
                    state,
                    dynamic_neighbors,
                    ip,
                    &next_table_name,
                    depth + 1,
                    allow_tunnels,
                    ecmp_flow_hash,
                );
            }
            // #2389/#2734: select one equal-cost next-hop, skipping a dead
            // one. Spread by the per-flow 5-tuple hash when supplied,
            // else fall back to the per-destination hash.
            let spread_hash = ecmp_flow_hash.unwrap_or_else(|| ecmp_hash_v6(ip));
            let selected = select_route_next_hop(&route.next_hops, spread_hash, |nh| {
                let target = nh.next_hop.unwrap_or(ip);
                nh.ifindex > 0
                    && lookup_neighbor_entry(state, dynamic_neighbors, nh.ifindex, IpAddr::V6(target))
                        .is_some()
            });
            let (next_hop, ifindex, tunnel_endpoint_id) = match selected {
                Some(nh) => (nh.next_hop, nh.ifindex, nh.tunnel_endpoint_id),
                None => (None, 0, 0),
            };
            if tunnel_endpoint_id != 0 {
                return if allow_tunnels {
                    resolve_tunnel_forwarding_resolution(
                        state,
                        dynamic_neighbors,
                        tunnel_endpoint_id,
                        depth,
                    )
                } else {
                    no_route_resolution(next_hop.map(IpAddr::V6).or(Some(IpAddr::V6(ip))))
                };
            }
            if ifindex <= 0 {
                return no_route_resolution(next_hop.map(IpAddr::V6));
            }
            let target = next_hop.unwrap_or(ip);
            let neighbor =
                lookup_neighbor_entry(state, dynamic_neighbors, ifindex, IpAddr::V6(target));
            let mut resolution = ForwardingResolution {
                disposition: if neighbor.is_some() {
                    ForwardingDisposition::ForwardCandidate
                } else {
                    ForwardingDisposition::MissingNeighbor
                },
                local_ifindex: 0,
                egress_ifindex: ifindex,
                tx_ifindex: ifindex,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V6(target)),
                neighbor_mac: neighbor.map(|entry| entry.mac),
                src_mac: None,
                tx_vlan_id: 0,
            };
            populate_egress_resolution(state, ifindex, &mut resolution);
            resolution
        }
        None => no_route_resolution(None),
    }
}

pub(super) fn no_route_resolution(next_hop: Option<IpAddr>) -> ForwardingResolution {
    ForwardingResolution {
        disposition: ForwardingDisposition::NoRoute,
        local_ifindex: 0,
        egress_ifindex: 0,
        tx_ifindex: 0,
        tunnel_endpoint_id: 0,
        next_hop,
        neighbor_mac: None,
        src_mac: None,
        tx_vlan_id: 0,
    }
}

/// Resolve a tunnel endpoint's OUTER transport destination.
///
/// Shared SSOT for the outer-hop lookup: returns the OUTER
/// `ForwardingResolution` (whose `egress_ifindex` is the OUTER L3 egress
/// interface where the outer next-hop neighbor is keyed, NOT the tunnel
/// logical ifindex), or `None` when the endpoint id is unknown OR the
/// outer destination resolves to local delivery / a tunnel interface (the
/// recursion guard). `resolve_tunnel_forwarding_resolution` re-maps the
/// returned resolution onto the tunnel logical ifindex; the cold-path
/// `outer_neighbor_ifindex` helper reads `egress_ifindex` straight off it
/// to key the outer-hop ARP/NDP probe + neighbor map + neg-cache.
pub(super) fn resolve_tunnel_outer(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<ShardedNeighborMap>>,
    tunnel_endpoint_id: u16,
    depth: usize,
) -> Option<ForwardingResolution> {
    let endpoint = state.tunnel_endpoints.get(&tunnel_endpoint_id)?;
    let outer = match endpoint.destination {
        // #2734: tunnel OUTER resolution is per-tunnel-endpoint, not
        // per-inner-flow — no 5-tuple flow hash applies here, so pass
        // None (per-destination spread across outer-transport ECMP).
        IpAddr::V4(ip) => lookup_forwarding_resolution_v4(
            state,
            dynamic_neighbors,
            ip,
            &endpoint.transport_table,
            depth + 1,
            false,
            None,
        ),
        IpAddr::V6(ip) => lookup_forwarding_resolution_v6(
            state,
            dynamic_neighbors,
            ip,
            &endpoint.transport_table,
            depth + 1,
            false,
            None,
        ),
    };
    if outer.disposition == ForwardingDisposition::LocalDelivery
        || state.tunnel_interfaces.contains(&outer.egress_ifindex)
    {
        return None;
    }
    Some(outer)
}

pub(super) fn resolve_tunnel_forwarding_resolution(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<ShardedNeighborMap>>,
    tunnel_endpoint_id: u16,
    depth: usize,
) -> ForwardingResolution {
    let Some(endpoint) = state.tunnel_endpoints.get(&tunnel_endpoint_id) else {
        return no_route_resolution(None);
    };
    let logical_ifindex = endpoint.logical_ifindex;
    let destination = endpoint.destination;
    let Some(outer) = resolve_tunnel_outer(state, dynamic_neighbors, tunnel_endpoint_id, depth)
    else {
        return no_route_resolution(Some(destination));
    };
    ForwardingResolution {
        disposition: outer.disposition,
        local_ifindex: outer.local_ifindex,
        egress_ifindex: logical_ifindex,
        tx_ifindex: outer.tx_ifindex,
        tunnel_endpoint_id,
        next_hop: outer.next_hop,
        neighbor_mac: outer.neighbor_mac,
        src_mac: outer.src_mac,
        tx_vlan_id: outer.tx_vlan_id,
    }
}

/// The ifindex on which `resolution.next_hop` must be neighbor-resolved
/// (ARP/NDP probe + neighbor-map key + negative-cache key) on the cold
/// path. For a normal (non-tunnel) resolution this is `egress_ifindex`.
/// For a tunnel-marked resolution it is the OUTER transport's L3 egress
/// ifindex — where the outer next-hop neighbor (e.g. the GRE outer hop)
/// actually lives — which differs from `resolution.egress_ifindex` (the
/// tunnel LOGICAL ifindex, used for zone/policy/CoS) and from
/// `resolution.tx_ifindex` (the VLAN PARENT for a VLAN outer transport;
/// neighbors are keyed by the L3 subif, so `tx_ifindex` would be the wrong
/// key).
///
/// Computed from LIVE forwarding state at use time, so it is inherently
/// peer-local and needs no wire field / HA-sync trust — synced sessions
/// re-resolve on upsert. The outer re-resolution reuses the shared
/// `resolve_tunnel_outer` SSOT (the same lookup the original resolution
/// ran), so there is no logic duplication. Cold-path only (MissingNeighbor
/// arm), never the fast path.
///
/// The `> 0` guard (vs `== 0`) is the conservative fallback: if the
/// endpoint vanished or the re-resolved outer egress is non-positive, fall
/// back to `resolution.egress_ifindex` rather than emit a probe on ifindex
/// 0.
pub(super) fn outer_neighbor_ifindex(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<ShardedNeighborMap>>,
    resolution: &ForwardingResolution,
) -> i32 {
    if resolution.tunnel_endpoint_id == 0 {
        return resolution.egress_ifindex;
    }
    match resolve_tunnel_outer(state, dynamic_neighbors, resolution.tunnel_endpoint_id, 0) {
        Some(outer) if outer.egress_ifindex > 0 => outer.egress_ifindex,
        _ => resolution.egress_ifindex,
    }
}

pub(super) fn lookup_neighbor_entry(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<ShardedNeighborMap>>,
    ifindex: i32,
    target: IpAddr,
) -> Option<NeighborEntry> {
    if let Some(entry) = state.neighbors.get(&(ifindex, target)).copied() {
        return Some(entry);
    }
    let Some(dynamic_neighbors) = dynamic_neighbors else {
        return None;
    };
    if let Some(entry) = dynamic_neighbors.get(&(ifindex, target)) {
        return Some(entry);
    }
    // The worker hot path must not block on shelling out to `ip neigh` or
    // active probes. Runtime neighbor discovery is maintained asynchronously
    // by the helper's own netlink dump+subscribe path.
    None
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn parse_neighbor_entries(output: &str) -> Vec<(IpAddr, NeighborEntry)> {
    let mut out = Vec::new();
    for line in output.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.is_empty() {
            continue;
        }
        if fields.iter().any(|field| !neighbor_state_usable(field)) {
            continue;
        }
        let Ok(ip) = fields[0].parse::<IpAddr>() else {
            continue;
        };
        let Some(lladdr) = fields.iter().position(|field| *field == "lladdr") else {
            continue;
        };
        let Some(candidate) = fields.get(lladdr + 1) else {
            continue;
        };
        let Some(mac) = parse_mac(candidate).or_else(|| parse_mac(candidate.trim())) else {
            continue;
        };
        out.push((ip, NeighborEntry { mac }));
    }
    out
}

enum ResolvedRouteV4<'a> {
    Connected {
        ifindex: i32,
        tunnel_endpoint_id: u16,
    },
    Static(&'a RouteEntryV4),
}

enum ResolvedRouteV6<'a> {
    Connected {
        ifindex: i32,
        tunnel_endpoint_id: u16,
    },
    Static(&'a RouteEntryV6),
}

fn choose_v4_route<'a>(
    static_match: Option<&'a RouteEntryV4>,
    connected_match: Option<&'a ConnectedRouteV4>,
) -> Option<ResolvedRouteV4<'a>> {
    match (static_match, connected_match) {
        (Some(route), Some(conn)) if conn.prefix.prefix_len() >= route.prefix.prefix_len() => {
            Some(ResolvedRouteV4::Connected {
                ifindex: conn.ifindex,
                tunnel_endpoint_id: conn.tunnel_endpoint_id,
            })
        }
        (Some(route), _) => Some(ResolvedRouteV4::Static(route)),
        (None, Some(conn)) => Some(ResolvedRouteV4::Connected {
            ifindex: conn.ifindex,
            tunnel_endpoint_id: conn.tunnel_endpoint_id,
        }),
        (None, None) => None,
    }
}

fn choose_v6_route<'a>(
    static_match: Option<&'a RouteEntryV6>,
    connected_match: Option<&'a ConnectedRouteV6>,
) -> Option<ResolvedRouteV6<'a>> {
    match (static_match, connected_match) {
        (Some(route), Some(conn)) if conn.prefix.prefix_len() >= route.prefix.prefix_len() => {
            Some(ResolvedRouteV6::Connected {
                ifindex: conn.ifindex,
                tunnel_endpoint_id: conn.tunnel_endpoint_id,
            })
        }
        (Some(route), _) => Some(ResolvedRouteV6::Static(route)),
        (None, Some(conn)) => Some(ResolvedRouteV6::Connected {
            ifindex: conn.ifindex,
            tunnel_endpoint_id: conn.tunnel_endpoint_id,
        }),
        (None, None) => None,
    }
}

/// #2389/#2734: select one equal-cost next-hop candidate for a forwarding
/// static route. Prefers a candidate whose neighbor is resolved (skips a
/// dead/unresolved first next-hop — the load-bearing correctness fix); if
/// several resolve, distributes deterministically by the supplied
/// `flow_hash`; if none resolve, falls back to the same hashed pick so the
/// kernel slow-path can drive ARP/NDP.
///
/// #2734: the spread key is now per-FLOW. The session resolution path
/// threads the 5-tuple flow hash (`ecmp_hash_flow`, the same seeded
/// FxHasher the flow cache already feeds the session 5-tuple — see
/// `ecmp_hash_flow`) into `select_route_next_hop`, so distinct flows to
/// the SAME destination spread across equal-cost members while every
/// packet of a single flow pins to one member (flow-consistent — no
/// intra-flow reordering). Callers without a flow context (tunnel outer
/// resolution, `inject`, bare-dst lookups) pass `None`, which falls back
/// to the per-DESTINATION hash (`ecmp_hash_v4`/`ecmp_hash_v6`) — the
/// #2389 behavior. The retained candidate vector (Vec<RouteNextHop>) is
/// what makes per-flow selection a localized runtime change.
/// Deterministic ECMP spread mixer. A fixed-seed splitmix64 finalizer over
/// the input word — used for the per-destination fallback. Stable across
/// reloads and workers so every worker maps the same input to the same
/// equal-cost path (a flow's packets never split across paths). Not a
/// security hash.
fn ecmp_hash_bytes(seed: u64) -> u64 {
    let mut z = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

fn ecmp_hash_v4(ip: Ipv4Addr) -> u64 {
    ecmp_hash_bytes(u32::from(ip) as u64)
}

fn ecmp_hash_v6(ip: Ipv6Addr) -> u64 {
    let bits = u128::from(ip);
    ecmp_hash_bytes((bits as u64) ^ ((bits >> 64) as u64))
}

/// #2734: per-FLOW ECMP spread key over the full 5-tuple.
///
/// Hashes the session forward 5-tuple (`addr_family`/`protocol`/`src_ip`/
/// `dst_ip`/`src_port`/`dst_port`) with the SAME per-boot, per-process
/// seeded `FxHasher` the flow cache uses (`hot_hash_seed::hot_path_hash_seed`
/// — #2364), so the cost is one already-vetted hash and the per-flow
/// mapping reshuffles each restart (defeats offline collision construction)
/// while staying stable for a flow's lifetime within a boot. The seed is
/// node-local: ECMP selection picks among THIS node's equal-cost members
/// and is not part of any wire/HA-synced structure, so a per-node seed is
/// correct (HA peers re-derive their own pick under their own seed, exactly
/// as the flow cache and fabric-queue hash do). Determinism within a boot
/// guarantees flow consistency — every packet of one flow hashes to the
/// same member, no intra-flow reordering. `select_route_next_hop` reduces
/// this modulo the live-member count, so the spread tracks the live pool.
fn ecmp_hash_flow(key: &crate::session::SessionKey) -> u64 {
    ecmp_hash_flow_seeded(crate::hot_hash_seed::hot_path_hash_seed(), key)
}

/// Seed-parameterized core of `ecmp_hash_flow`. Split out so tests can pin
/// the seed and assert (a) intra-seed stability (flow consistency) and
/// (b) that distinct 5-tuples spread. Production calls through
/// `ecmp_hash_flow`, which supplies the per-boot process seed.
fn ecmp_hash_flow_seeded(seed: u64, key: &crate::session::SessionKey) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = rustc_hash::FxHasher::with_seed(seed as usize);
    key.hash(&mut hasher);
    hasher.finish()
}

fn select_route_next_hop<'a, T: Copy>(
    candidates: &'a [T],
    ip_hash: u64,
    is_live: impl Fn(&T) -> bool,
) -> Option<&'a T> {
    if candidates.is_empty() {
        return None;
    }
    let live: usize = candidates.iter().filter(|c| is_live(c)).count();
    let pool_len = if live > 0 { live } else { candidates.len() };
    let pick = (ip_hash % pool_len as u64) as usize;
    if live > 0 {
        candidates.iter().filter(|c| is_live(c)).nth(pick)
    } else {
        candidates.get(pick)
    }
}

#[cfg(test)]
mod tests;
