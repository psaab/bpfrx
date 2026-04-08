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
    dynamic_neighbors: &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
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
    let from_zone = ingress_zone_override
        .map(|zone| zone.to_string())
        .or_else(|| forwarding.ifindex_to_zone.get(&ingress_ifindex).cloned())
        .unwrap_or_default();
    let to_zone = forwarding
        .egress
        .get(&egress_ifindex)
        .map(|iface| iface.zone.clone())
        .unwrap_or_default();
    (from_zone, to_zone)
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
    dynamic_neighbors: &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
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
            dynamic_neighbors.lock().ok().and_then(|n| {
                n.get(&(fabric.overlay_ifindex, peer_addr))
                    .or_else(|| n.get(&(fabric.parent_ifindex, peer_addr)))
                    .map(|e| e.mac)
            })
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
    let mut resolution = resolve_fabric_redirect(forwarding)?;
    let zone_id = forwarding.zone_name_to_id.get(ingress_zone).copied()?;
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
    dynamic_neighbors: &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
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
    dynamic_neighbors: &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
    packet_frame: &[u8],
    meta: UserspaceDpMeta,
    ingress_zone_override: Option<&str>,
    resolution_target: IpAddr,
) -> Option<(SessionDecision, SessionMetadata)> {
    if !ingress_is_fabric(forwarding, meta.ingress_ifindex as i32) {
        return None;
    }
    let ingress_zone = ingress_zone_override?;
    if is_icmp_echo_request(packet_frame, meta) {
        return None;
    }
    if meta.protocol == PROTO_TCP
        && (meta.tcp_flags & TCP_FLAG_SYN) != 0
        && (meta.tcp_flags & 0x10) == 0
    {
        return None;
    }

    let fabric_return_resolution =
        lookup_forwarding_resolution_with_dynamic(forwarding, dynamic_neighbors, resolution_target);
    if fabric_return_resolution.disposition != ForwardingDisposition::ForwardCandidate {
        return None;
    }
    let egress_zone = forwarding
        .ifindex_to_zone
        .get(&fabric_return_resolution.egress_ifindex)?
        .clone();
    let metadata = SessionMetadata {
        ingress_zone: Arc::<str>::from(ingress_zone),
        egress_zone: Arc::<str>::from(egress_zone),
        owner_rg_id: owner_rg_for_resolution(forwarding, fabric_return_resolution),
        fabric_ingress: true,
        is_reverse: true,
        nat64_reverse: None,
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
    forwarding.egress.iter().find_map(|(ifindex, iface)| {
        if iface.bind_ifindex == ingress_ifindex && iface.vlan_id == ingress_vlan_id {
            Some(*ifindex)
        } else {
            None
        }
    })
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
        ForwardingDisposition::ForwardCandidate | ForwardingDisposition::MissingNeighbor
    ) {
        return resolution;
    }
    let owner_rg_id = owner_rg_for_resolution(forwarding, resolution);
    if owner_rg_id <= 0 {
        // In cluster mode, rg=0 on a ForwardCandidate to an egress interface
        // means the forwarding snapshot predates the RETH RG propagation fix.
        // Treat as invalid (force re-resolution through the slow path) rather
        // than "always active" which would let stale cached entries bypass
        // HA checks after RG failover.
        if !ha_state.is_empty() && resolution.egress_ifindex > 0 {
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
    dynamic_neighbors: &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
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
    ingress_zone: &str,
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

/// Return the effective TCP MSS clamp value for the current config.
/// Returns 0 if MSS clamping is disabled.
#[allow(dead_code)]
pub(super) fn effective_tcp_mss(forwarding: &ForwardingState) -> u16 {
    if forwarding.tcp_mss_all_tcp > 0 {
        return forwarding.tcp_mss_all_tcp;
    }
    // IPsec VPN and GRE MSS values are returned when configured;
    // the caller is responsible for checking the tunnel context.
    if forwarding.tcp_mss_ipsec_vpn > 0 {
        return forwarding.tcp_mss_ipsec_vpn;
    }
    0
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
        .cloned()
    else {
        return 0;
    };
    let transport_ifindex = resolve_ingress_logical_ifindex(
        forwarding,
        decision.resolution.tx_ifindex,
        decision.resolution.tx_vlan_id,
    )
    .unwrap_or(decision.resolution.tx_ifindex);
    let transport_mtu = forwarding
        .egress
        .get(&transport_ifindex)
        .or_else(|| forwarding.egress.get(&decision.resolution.egress_ifindex))
        .or_else(|| forwarding.egress.get(&endpoint.logical_ifindex))
        .map(|egress| egress.mtu)
        .unwrap_or_default();
    if transport_mtu == 0 {
        return 0;
    }
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

/// Clamp TCP MSS option in-place in an L3 packet (starting at IP header).
/// `max_mss` is the maximum allowed MSS value.
/// Returns true if the MSS was clamped.
#[allow(dead_code)]
pub(super) fn clamp_tcp_mss(packet: &mut [u8], max_mss: u16) -> bool {
    if max_mss == 0 {
        return false;
    }
    // Determine L3 header length and protocol.
    if packet.is_empty() {
        return false;
    }
    let version = packet[0] >> 4;
    let (l4_offset, protocol) = match version {
        4 => {
            if packet.len() < 20 {
                return false;
            }
            let ihl = (packet[0] & 0x0F) as usize * 4;
            (ihl, packet[9])
        }
        6 => {
            if packet.len() < 40 {
                return false;
            }
            (40, packet[6])
        }
        _ => return false,
    };
    if protocol != PROTO_TCP {
        return false;
    }
    let tcp = match packet.get_mut(l4_offset..) {
        Some(s) if s.len() >= 20 => s,
        _ => return false,
    };
    let flags = tcp[13];
    // Only clamp on SYN or SYN+ACK
    if (flags & 0x02) == 0 {
        return false;
    }
    let data_offset = ((tcp[12] >> 4) as usize) * 4;
    if data_offset < 20 || tcp.len() < data_offset {
        return false;
    }
    // Walk TCP options looking for MSS (kind=2, len=4)
    let mut pos = 20;
    while pos + 4 <= data_offset {
        let kind = tcp[pos];
        if kind == 0 {
            break; // end of options
        }
        if kind == 1 {
            pos += 1; // NOP
            continue;
        }
        let opt_len = tcp[pos + 1] as usize;
        if opt_len < 2 || pos + opt_len > data_offset {
            break;
        }
        if kind == 2 && opt_len == 4 {
            let current_mss = u16::from_be_bytes([tcp[pos + 2], tcp[pos + 3]]);
            if current_mss > max_mss {
                // Clamp MSS and adjust TCP checksum
                let old_bytes = [tcp[pos + 2], tcp[pos + 3]];
                tcp[pos + 2..pos + 4].copy_from_slice(&max_mss.to_be_bytes());
                // Incremental checksum update
                let old_val = u16::from_be_bytes(old_bytes) as u32;
                let new_val = max_mss as u32;
                let old_csum = u16::from_be_bytes([tcp[16], tcp[17]]) as u32;
                let mut sum = (!old_csum & 0xFFFF) + old_val + (!new_val & 0xFFFF);
                sum = (sum & 0xFFFF) + (sum >> 16);
                sum = (sum & 0xFFFF) + (sum >> 16);
                tcp[16..18].copy_from_slice(&(!(sum as u16)).to_be_bytes());
                return true;
            }
            return false;
        }
        pos += opt_len;
    }
    false
}

/// Clamp TCP MSS in a full Ethernet frame starting at `l3_offset`.
#[allow(dead_code)]
pub(super) fn clamp_tcp_mss_frame(frame: &mut [u8], l3_offset: usize, max_mss: u16) -> bool {
    if max_mss == 0 || l3_offset >= frame.len() {
        return false;
    }
    clamp_tcp_mss(&mut frame[l3_offset..], max_mss)
}

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

/// Returns true if the packet is IPsec traffic (ESP protocol 50 or IKE UDP
/// ports 500/4500) that should be passed to the kernel for XFRM processing.
#[inline]
pub(super) fn is_ipsec_traffic(protocol: u8, dst_port: u16) -> bool {
    protocol == PROTO_ESP || (protocol == PROTO_UDP && (dst_port == 500 || dst_port == 4500))
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
    dynamic_neighbors: &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
    dst: IpAddr,
) -> ForwardingResolution {
    lookup_forwarding_resolution_inner(state, Some(dynamic_neighbors), dst, None)
}

pub(super) fn lookup_forwarding_resolution_in_table_with_dynamic(
    state: &ForwardingState,
    dynamic_neighbors: &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
    dst: IpAddr,
    table: Option<&str>,
) -> ForwardingResolution {
    lookup_forwarding_resolution_inner(state, Some(dynamic_neighbors), dst, table)
}

pub(super) fn lookup_forwarding_resolution_inner(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>>,
    dst: IpAddr,
    table: Option<&str>,
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
            lookup_forwarding_resolution_v4(state, dynamic_neighbors, ip, &table, 0, true)
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
            lookup_forwarding_resolution_v6(state, dynamic_neighbors, ip, &table, 0, true)
        }
    }
}

pub(super) fn ingress_route_table_override(
    forwarding: &ForwardingState,
    meta: UserspaceDpMeta,
    flow: &SessionFlow,
) -> Option<String> {
    let ingress_ifindex = resolve_ingress_logical_ifindex(
        forwarding,
        meta.ingress_ifindex as i32,
        meta.ingress_vlan_id,
    )
    .unwrap_or(meta.ingress_ifindex as i32);
    let is_v6 = matches!(flow.dst_ip, IpAddr::V6(_));
    let result = crate::filter::evaluate_interface_filter(
        &forwarding.filter_state,
        ingress_ifindex,
        is_v6,
        flow.src_ip,
        flow.dst_ip,
        meta.protocol,
        flow.forward_key.src_port,
        flow.forward_key.dst_port,
        meta.dscp,
    );
    if result.routing_instance.is_empty() {
        return None;
    }
    Some(if is_v6 {
        format!("{}.inet6.0", result.routing_instance)
    } else {
        format!("{}.inet.0", result.routing_instance)
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
    const TCP_SYN_FLAG: u8 = 0x02;
    const TCP_ACK_FLAG: u8 = 0x10;
    if (tcp_flags & TCP_ACK_FLAG) != 0 && (tcp_flags & TCP_SYN_FLAG) == 0 {
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
    };
    let _ =
        publish_session_map_entry_for_session(session_map_fd, key, decision, &local_entry.metadata);
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
    dynamic_neighbors: Option<&Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>>,
    ip: Ipv4Addr,
    table: &str,
    depth: usize,
    allow_tunnels: bool,
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
    let connected_match = state
        .connected_v4
        .iter()
        .find(|entry| entry.prefix.contains(ip));
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
        Some(ResolvedRouteV4::Static {
            ifindex,
            tunnel_endpoint_id,
            next_hop,
            discard,
            next_table,
        }) => {
            if discard {
                return ForwardingResolution {
                    disposition: ForwardingDisposition::DiscardRoute,
                    local_ifindex: 0,
                    egress_ifindex: ifindex,
                    tx_ifindex: ifindex,
                    tunnel_endpoint_id,
                    next_hop: next_hop.map(IpAddr::V4),
                    neighbor_mac: None,
                    src_mac: None,
                    tx_vlan_id: 0,
                };
            }
            if let Some(next_table_name) = next_table {
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
                return lookup_forwarding_resolution_v4(
                    state,
                    dynamic_neighbors,
                    ip,
                    &next_table_name,
                    depth + 1,
                    allow_tunnels,
                );
            }
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
    dynamic_neighbors: Option<&Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>>,
    ip: Ipv6Addr,
    table: &str,
    depth: usize,
    allow_tunnels: bool,
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
    let connected_match = state
        .connected_v6
        .iter()
        .find(|entry| entry.prefix.contains(ip));
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
        Some(ResolvedRouteV6::Static {
            ifindex,
            tunnel_endpoint_id,
            next_hop,
            discard,
            next_table,
        }) => {
            if discard {
                return ForwardingResolution {
                    disposition: ForwardingDisposition::DiscardRoute,
                    local_ifindex: 0,
                    egress_ifindex: ifindex,
                    tx_ifindex: ifindex,
                    tunnel_endpoint_id,
                    next_hop: next_hop.map(IpAddr::V6),
                    neighbor_mac: None,
                    src_mac: None,
                    tx_vlan_id: 0,
                };
            }
            if let Some(next_table_name) = next_table {
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
                return lookup_forwarding_resolution_v6(
                    state,
                    dynamic_neighbors,
                    ip,
                    &next_table_name,
                    depth + 1,
                    allow_tunnels,
                );
            }
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

pub(super) fn resolve_tunnel_forwarding_resolution(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>>,
    tunnel_endpoint_id: u16,
    depth: usize,
) -> ForwardingResolution {
    let Some(endpoint) = state.tunnel_endpoints.get(&tunnel_endpoint_id) else {
        return no_route_resolution(None);
    };
    let outer = match endpoint.destination {
        IpAddr::V4(ip) => lookup_forwarding_resolution_v4(
            state,
            dynamic_neighbors,
            ip,
            &endpoint.transport_table,
            depth + 1,
            false,
        ),
        IpAddr::V6(ip) => lookup_forwarding_resolution_v6(
            state,
            dynamic_neighbors,
            ip,
            &endpoint.transport_table,
            depth + 1,
            false,
        ),
    };
    if outer.disposition == ForwardingDisposition::LocalDelivery
        || state.tunnel_interfaces.contains(&outer.egress_ifindex)
    {
        return no_route_resolution(Some(endpoint.destination));
    }
    ForwardingResolution {
        disposition: outer.disposition,
        local_ifindex: outer.local_ifindex,
        egress_ifindex: endpoint.logical_ifindex,
        tx_ifindex: outer.tx_ifindex,
        tunnel_endpoint_id,
        next_hop: outer.next_hop,
        neighbor_mac: outer.neighbor_mac,
        src_mac: outer.src_mac,
        tx_vlan_id: outer.tx_vlan_id,
    }
}

pub(super) fn lookup_neighbor_entry(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>>,
    ifindex: i32,
    target: IpAddr,
) -> Option<NeighborEntry> {
    if let Some(entry) = state.neighbors.get(&(ifindex, target)).copied() {
        return Some(entry);
    }
    let Some(dynamic_neighbors) = dynamic_neighbors else {
        return None;
    };
    if let Ok(cache) = dynamic_neighbors.lock() {
        if let Some(entry) = cache.get(&(ifindex, target)).copied() {
            return Some(entry);
        }
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

enum ResolvedRouteV4 {
    Connected {
        ifindex: i32,
        tunnel_endpoint_id: u16,
    },
    Static {
        ifindex: i32,
        tunnel_endpoint_id: u16,
        next_hop: Option<Ipv4Addr>,
        discard: bool,
        next_table: Option<String>,
    },
}

enum ResolvedRouteV6 {
    Connected {
        ifindex: i32,
        tunnel_endpoint_id: u16,
    },
    Static {
        ifindex: i32,
        tunnel_endpoint_id: u16,
        next_hop: Option<Ipv6Addr>,
        discard: bool,
        next_table: Option<String>,
    },
}

fn choose_v4_route(
    static_match: Option<&RouteEntryV4>,
    connected_match: Option<&ConnectedRouteV4>,
) -> Option<ResolvedRouteV4> {
    match (static_match, connected_match) {
        (Some(route), Some(conn)) if conn.prefix.prefix_len() >= route.prefix.prefix_len() => {
            Some(ResolvedRouteV4::Connected {
                ifindex: conn.ifindex,
                tunnel_endpoint_id: conn.tunnel_endpoint_id,
            })
        }
        (Some(route), _) => Some(ResolvedRouteV4::Static {
            ifindex: route.ifindex,
            tunnel_endpoint_id: route.tunnel_endpoint_id,
            next_hop: route.next_hop,
            discard: route.discard,
            next_table: if route.next_table.is_empty() {
                None
            } else {
                Some(route.next_table.clone())
            },
        }),
        (None, Some(conn)) => Some(ResolvedRouteV4::Connected {
            ifindex: conn.ifindex,
            tunnel_endpoint_id: conn.tunnel_endpoint_id,
        }),
        (None, None) => None,
    }
}

fn choose_v6_route(
    static_match: Option<&RouteEntryV6>,
    connected_match: Option<&ConnectedRouteV6>,
) -> Option<ResolvedRouteV6> {
    match (static_match, connected_match) {
        (Some(route), Some(conn)) if conn.prefix.prefix_len() >= route.prefix.prefix_len() => {
            Some(ResolvedRouteV6::Connected {
                ifindex: conn.ifindex,
                tunnel_endpoint_id: conn.tunnel_endpoint_id,
            })
        }
        (Some(route), _) => Some(ResolvedRouteV6::Static {
            ifindex: route.ifindex,
            tunnel_endpoint_id: route.tunnel_endpoint_id,
            next_hop: route.next_hop,
            discard: route.discard,
            next_table: if route.next_table.is_empty() {
                None
            } else {
                Some(route.next_table.clone())
            },
        }),
        (None, Some(conn)) => Some(ResolvedRouteV6::Connected {
            ifindex: conn.ifindex,
            tunnel_endpoint_id: conn.tunnel_endpoint_id,
        }),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::super::forwarding_build::*;
    use super::super::test_fixtures::*;
    use super::*;
    use crate::{FabricSnapshot, NeighborSnapshot, SourceNATRuleSnapshot};

    fn active_ha_runtime(now_secs: u64) -> HAGroupRuntime {
        HAGroupRuntime {
            active: true,
            watchdog_timestamp: now_secs,
            lease: HAGroupRuntime::active_lease_until(now_secs, now_secs),
        }
    }

    fn inactive_ha_runtime(watchdog_timestamp: u64) -> HAGroupRuntime {
        HAGroupRuntime {
            active: false,
            watchdog_timestamp,
            lease: HAForwardingLease::Inactive,
        }
    }

    #[test]
    fn metadata_classification_accepts_matching_generations() {
        let validation = ValidationState {
            snapshot_installed: true,
            config_generation: 11,
            fib_generation: 7,
        };
        assert_eq!(
            classify_metadata(valid_meta(), validation),
            PacketDisposition::Valid
        );
    }

    #[test]
    fn metadata_classification_rejects_generation_mismatch() {
        let validation = ValidationState {
            snapshot_installed: true,
            config_generation: 22,
            fib_generation: 9,
        };
        assert_eq!(
            classify_metadata(valid_meta(), validation),
            PacketDisposition::ConfigGenerationMismatch
        );
        let validation = ValidationState {
            snapshot_installed: true,
            config_generation: 11,
            fib_generation: 9,
        };
        assert_eq!(
            classify_metadata(valid_meta(), validation),
            PacketDisposition::FibGenerationMismatch
        );
    }

    #[test]
    fn metadata_classification_rejects_unknown_address_family() {
        let validation = ValidationState {
            snapshot_installed: true,
            config_generation: 11,
            fib_generation: 7,
        };
        let mut meta = valid_meta();
        meta.addr_family = 0;
        assert_eq!(
            classify_metadata(meta, validation),
            PacketDisposition::UnsupportedPacket
        );
    }
    #[test]
    fn ha_resolution_blocks_inactive_owner_rg() {
        let state = build_forwarding_state(&nat_snapshot());
        let ha_state = Arc::new(ArcSwap::from_pointee(BTreeMap::from([(
            1,
            inactive_ha_runtime(monotonic_nanos() / 1_000_000_000),
        )])));
        let resolved = enforce_ha_resolution(
            &state,
            &ha_state,
            lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        );
        assert_eq!(resolved.disposition, ForwardingDisposition::HAInactive);
    }

    #[test]
    fn ha_resolution_allows_fresh_active_owner_rg() {
        let state = build_forwarding_state(&nat_snapshot());
        let ha_state = Arc::new(ArcSwap::from_pointee(BTreeMap::from([(
            1,
            active_ha_runtime(monotonic_nanos() / 1_000_000_000),
        )])));
        let resolved = enforce_ha_resolution(
            &state,
            &ha_state,
            lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        );
        assert_eq!(
            resolved.disposition,
            ForwardingDisposition::ForwardCandidate
        );
    }

    #[test]
    fn cached_flow_decision_invalidates_when_owner_rg_is_demoted() {
        let state = build_forwarding_state(&nat_snapshot());
        let active = BTreeMap::from([(1, active_ha_runtime(monotonic_nanos() / 1_000_000_000))]);
        let demoted = BTreeMap::from([(1, inactive_ha_runtime(monotonic_nanos() / 1_000_000_000))]);
        let resolution =
            lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        let now_secs = monotonic_nanos() / 1_000_000_000;
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));

        assert!(cached_flow_decision_valid(
            &state,
            &active,
            &dynamic_neighbors,
            now_secs,
            1,
            false,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            resolution
        ));
        assert!(!cached_flow_decision_valid(
            &state,
            &demoted,
            &dynamic_neighbors,
            now_secs,
            1,
            false,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            resolution
        ));
    }

    #[test]
    fn cached_flow_decision_invalidates_fabric_redirect_on_fabric_ingress_when_local_owner_active()
    {
        let state = build_forwarding_state(&nat_snapshot_with_fabric());
        let now_secs = monotonic_nanos() / 1_000_000_000;
        let ha_state = BTreeMap::from([(1, active_ha_runtime(now_secs))]);
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));
        let resolution = resolve_fabric_redirect(&state).expect("fabric redirect");

        assert!(!cached_flow_decision_valid(
            &state,
            &ha_state,
            &dynamic_neighbors,
            now_secs,
            1,
            true,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            resolution
        ));
    }

    #[test]
    fn cached_flow_decision_invalidates_fabric_redirect_on_non_fabric_ingress_when_local_owner_active()
     {
        let state = build_forwarding_state(&nat_snapshot_with_fabric());
        let now_secs = monotonic_nanos() / 1_000_000_000;
        let ha_state = BTreeMap::from([(1, active_ha_runtime(now_secs))]);
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));
        let resolution = resolve_fabric_redirect(&state).expect("fabric redirect");

        assert!(!cached_flow_decision_valid(
            &state,
            &ha_state,
            &dynamic_neighbors,
            now_secs,
            1,
            false,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            resolution
        ));
    }

    #[test]
    fn cached_flow_decision_keeps_fabric_redirect_on_fabric_ingress_when_local_owner_inactive() {
        let state = build_forwarding_state(&nat_snapshot_with_fabric());
        let now_secs = monotonic_nanos() / 1_000_000_000;
        let ha_state = BTreeMap::from([(1, inactive_ha_runtime(now_secs))]);
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));
        let resolution = resolve_fabric_redirect(&state).expect("fabric redirect");

        assert!(cached_flow_decision_valid(
            &state,
            &ha_state,
            &dynamic_neighbors,
            now_secs,
            1,
            true,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            resolution
        ));
    }

    #[test]
    fn cached_flow_decision_keeps_fabric_redirect_on_non_fabric_ingress_when_local_owner_inactive()
    {
        let state = build_forwarding_state(&nat_snapshot_with_fabric());
        let now_secs = monotonic_nanos() / 1_000_000_000;
        let ha_state = BTreeMap::from([(1, inactive_ha_runtime(now_secs))]);
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));
        let resolution = resolve_fabric_redirect(&state).expect("fabric redirect");

        assert!(cached_flow_decision_valid(
            &state,
            &ha_state,
            &dynamic_neighbors,
            now_secs,
            1,
            false,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            resolution
        ));
    }

    #[test]
    fn inactive_owner_rg_redirects_established_session_to_fabric() {
        let state = build_forwarding_state(&nat_snapshot_with_fabric());
        let ha_state = Arc::new(ArcSwap::from_pointee(BTreeMap::from([(
            1,
            inactive_ha_runtime(monotonic_nanos() / 1_000_000_000),
        )])));
        let blocked = enforce_ha_resolution(
            &state,
            &ha_state,
            lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        );
        assert_eq!(blocked.disposition, ForwardingDisposition::HAInactive);
        let redirected = redirect_via_fabric_if_needed(&state, blocked, 24);
        assert_eq!(
            redirected.disposition,
            ForwardingDisposition::FabricRedirect
        );
        assert_eq!(redirected.egress_ifindex, 21);
        assert_eq!(redirected.tx_ifindex, 21);
        assert_eq!(
            redirected.next_hop,
            Some(IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2)))
        );
        assert_eq!(
            redirected.neighbor_mac,
            Some([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee])
        );
        assert_eq!(
            redirected.src_mac,
            Some([0x02, 0xbf, 0x72, 0xff, 0x00, 0x01])
        );
    }

    #[test]
    fn inactive_owner_missing_neighbor_redirects_to_fabric() {
        let mut snapshot = nat_snapshot_with_fabric();
        snapshot
            .neighbors
            .retain(|neighbor| neighbor.ip != "172.16.80.1");
        let state = build_forwarding_state(&snapshot);
        let ha_state = Arc::new(ArcSwap::from_pointee(BTreeMap::from([(
            1,
            inactive_ha_runtime(monotonic_nanos() / 1_000_000_000),
        )])));
        let blocked = enforce_ha_resolution(
            &state,
            &ha_state,
            lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        );
        assert_eq!(blocked.disposition, ForwardingDisposition::HAInactive);
        let redirected = redirect_via_fabric_if_needed(&state, blocked, 24);
        assert_eq!(
            redirected.disposition,
            ForwardingDisposition::FabricRedirect
        );
        assert_eq!(redirected.egress_ifindex, 21);
        assert_eq!(redirected.tx_ifindex, 21);
        assert_eq!(
            redirected.next_hop,
            Some(IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2)))
        );
    }

    #[test]
    fn fabric_ingress_prefers_local_active_owner_resolution_over_fabric_redirect() {
        let state = build_forwarding_state(&nat_snapshot_with_fabric());
        let now_secs = monotonic_nanos() / 1_000_000_000;
        let ha_state = BTreeMap::from([(1, active_ha_runtime(now_secs))]);
        let redirected = resolve_fabric_redirect(&state).expect("fabric redirect");
        let preferred = prefer_local_forward_candidate_for_fabric_ingress(
            &state,
            &ha_state,
            &Default::default(),
            now_secs,
            true,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            redirected,
        );
        assert_eq!(
            preferred.disposition,
            ForwardingDisposition::ForwardCandidate
        );
        assert_eq!(preferred.egress_ifindex, 12);
        assert_eq!(owner_rg_for_resolution(&state, preferred), 1);
    }

    #[test]
    fn build_forwarding_state_uses_fabric_snapshot_macs_without_parent_interface() {
        let mut snapshot = nat_snapshot();
        snapshot.fabrics = vec![FabricSnapshot {
            name: "fab0".to_string(),
            parent_interface: "ge-0/0/0".to_string(),
            parent_linux_name: "ge-0-0-0".to_string(),
            parent_ifindex: 21,
            overlay_linux_name: "fab0".to_string(),
            overlay_ifindex: 101,
            rx_queues: 2,
            peer_address: "10.99.13.2".to_string(),
            local_mac: "02:bf:72:ff:00:01".to_string(),
            peer_mac: "00:aa:bb:cc:dd:ee".to_string(),
        }];
        let state = build_forwarding_state(&snapshot);
        let redirect = resolve_fabric_redirect(&state).expect("fabric redirect");
        assert_eq!(redirect.egress_ifindex, 21);
        assert_eq!(redirect.tx_ifindex, 21);
        assert_eq!(
            redirect.neighbor_mac,
            Some([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee])
        );
        assert_eq!(redirect.src_mac, Some([0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]));
    }

    #[test]
    fn zone_encoded_fabric_redirect_preserves_ingress_zone() {
        let state = build_forwarding_state(&nat_snapshot_with_fabric());
        let redirected =
            resolve_zone_encoded_fabric_redirect(&state, "lan").expect("zone-encoded redirect");
        assert_eq!(
            redirected.disposition,
            ForwardingDisposition::FabricRedirect
        );
        assert_eq!(redirected.egress_ifindex, 21);
        assert_eq!(redirected.tx_ifindex, 21);
        assert_eq!(
            redirected.src_mac,
            Some([0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x01])
        );
    }

    #[test]
    fn parse_zone_encoded_fabric_ingress_uses_zone_override() {
        let state = build_forwarding_state(&nat_snapshot_with_fabric());
        let mut frame = vec![0u8; 64];
        frame[6..12].copy_from_slice(&[0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x01]);
        let mut area = MmapArea::new(4096).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            ingress_ifindex: 21,
            ..UserspaceDpMeta::default()
        };
        assert_eq!(
            parse_zone_encoded_fabric_ingress(
                &area,
                XdpDesc {
                    addr: 0,
                    len: frame.len() as u32,
                    options: 0,
                },
                meta,
                &state,
            ),
            Some("lan".to_string())
        );
    }

    #[test]
    fn zone_encoded_fabric_ingress_skips_dynamic_neighbor_learning() {
        let state = build_forwarding_state(&nat_snapshot_with_fabric());
        let mut frame = vec![0u8; 64];
        frame[6..12].copy_from_slice(&[0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x01]);
        let mut area = MmapArea::new(4096).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let neighbors = Arc::new(Mutex::new(FastMap::default()));
        let mut last_learned = None;
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            ingress_ifindex: 21,
            ..UserspaceDpMeta::default()
        };
        learn_dynamic_neighbor_from_packet(
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            &mut last_learned,
            &state,
            &neighbors,
        );
        assert!(neighbors.lock().expect("neighbors").is_empty());
    }

    #[test]
    fn manager_neighbor_replace_preserves_packet_learned_entries() {
        let mut coordinator = Coordinator::new();
        {
            let mut neighbors = coordinator
                .dynamic_neighbors_ref()
                .lock()
                .expect("neighbors");
            neighbors.insert(
                (
                    5,
                    IpAddr::V6(Ipv6Addr::new(
                        0x2001, 0x559, 0x8585, 0xef00, 0x1266, 0x6aff, 0xfe0b, 0xd017,
                    )),
                ),
                NeighborEntry {
                    mac: [0x10, 0x66, 0x6a, 0x0b, 0xd0, 0x17],
                },
            );
        }

        coordinator.apply_manager_neighbors(
            true,
            &[(
                13,
                IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
                NeighborEntry {
                    mac: [0x56, 0x4a, 0xe8, 0x1e, 0xa8, 0x32],
                },
            )],
        );

        let neighbors = coordinator
            .dynamic_neighbors_ref()
            .lock()
            .expect("neighbors");
        assert_eq!(neighbors.len(), 2);
        assert!(neighbors.contains_key(&(
            5,
            IpAddr::V6(Ipv6Addr::new(
                0x2001, 0x559, 0x8585, 0xef00, 0x1266, 0x6aff, 0xfe0b, 0xd017,
            ))
        )));
        assert!(neighbors.contains_key(&(13, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)))));
    }

    #[test]
    fn manager_neighbor_replace_overrides_snapshot_neighbor_entry() {
        let mut coordinator = Coordinator::new();
        let target = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200));
        coordinator.refresh_runtime_snapshot(&ConfigSnapshot {
            neighbors: vec![NeighborSnapshot {
                ifindex: 13,
                family: "inet".to_string(),
                ip: target.to_string(),
                mac: "00:11:22:33:44:55".to_string(),
                state: "reachable".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        });

        let before = lookup_neighbor_entry(
            &coordinator.forwarding,
            Some(coordinator.dynamic_neighbors_ref()),
            13,
            target,
        )
        .expect("snapshot neighbor");
        assert_eq!(before.mac, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        coordinator.apply_manager_neighbors(
            true,
            &[(
                13,
                target,
                NeighborEntry {
                    mac: [0x56, 0x4a, 0xe8, 0x1e, 0xa8, 0x32],
                },
            )],
        );

        let after = lookup_neighbor_entry(
            &coordinator.forwarding,
            Some(coordinator.dynamic_neighbors_ref()),
            13,
            target,
        )
        .expect("updated manager neighbor");
        assert_eq!(after.mac, [0x56, 0x4a, 0xe8, 0x1e, 0xa8, 0x32]);
    }

    #[test]
    fn manager_neighbor_replace_removes_snapshot_seeded_neighbor_entry() {
        let mut coordinator = Coordinator::new();
        let target = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200));
        coordinator.refresh_runtime_snapshot(&ConfigSnapshot {
            neighbors: vec![NeighborSnapshot {
                ifindex: 13,
                family: "inet".to_string(),
                ip: target.to_string(),
                mac: "00:11:22:33:44:55".to_string(),
                state: "reachable".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        });

        coordinator.apply_manager_neighbors(true, &[]);

        assert!(
            lookup_neighbor_entry(
                &coordinator.forwarding,
                Some(coordinator.dynamic_neighbors_ref()),
                13,
                target,
            )
            .is_none()
        );
    }

    #[test]
    fn refresh_runtime_snapshot_clears_old_manager_neighbor_cache_entries() {
        let mut coordinator = Coordinator::new();
        let target = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200));
        coordinator.apply_manager_neighbors(
            true,
            &[(
                13,
                target,
                NeighborEntry {
                    mac: [0x56, 0x4a, 0xe8, 0x1e, 0xa8, 0x32],
                },
            )],
        );
        assert!(
            coordinator
                .dynamic_neighbors_ref()
                .lock()
                .expect("neighbors")
                .contains_key(&(13, target))
        );

        coordinator.refresh_runtime_snapshot(&ConfigSnapshot::default());

        assert!(
            !coordinator
                .dynamic_neighbors_ref()
                .lock()
                .expect("neighbors")
                .contains_key(&(13, target))
        );
        assert!(
            lookup_neighbor_entry(
                &coordinator.forwarding,
                Some(coordinator.dynamic_neighbors_ref()),
                13,
                target,
            )
            .is_none()
        );
    }

    #[test]
    fn new_flow_to_inactive_owner_rg_uses_zone_encoded_fabric_redirect() {
        let state = build_forwarding_state(&nat_snapshot_with_fabric());
        let now_secs = monotonic_nanos() / 1_000_000_000;
        let ha_state = BTreeMap::from([(1, inactive_ha_runtime(now_secs))]);
        let routed = lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        let (from_zone, _) = zone_pair_for_flow(&state, 24, routed.egress_ifindex);
        let redirected = finalize_new_flow_ha_resolution(
            &state, &ha_state, now_secs, routed, false, 24, &from_zone, 0,
        );
        assert_eq!(
            redirected.disposition,
            ForwardingDisposition::FabricRedirect
        );
        assert_eq!(
            redirected.src_mac,
            Some([0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x01])
        );
    }

    #[test]
    fn new_flow_from_fabric_keeps_forward_candidate_when_owner_rg_inactive() {
        let state = build_forwarding_state(&nat_snapshot_with_fabric());
        let now_secs = monotonic_nanos() / 1_000_000_000;
        let ha_state = BTreeMap::from([(1, inactive_ha_runtime(now_secs))]);
        let routed = lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        let resolved = finalize_new_flow_ha_resolution(
            &state, &ha_state, now_secs, routed, true, 21, "lan", 0,
        );
        assert_eq!(
            resolved.disposition,
            ForwardingDisposition::ForwardCandidate
        );
        assert_eq!(resolved.egress_ifindex, routed.egress_ifindex);
    }

    #[test]
    fn fabric_originated_reverse_session_prefers_local_client_delivery_when_rg_active() {
        let state = build_forwarding_state(&nat_snapshot_with_fabric());
        let ha_state = BTreeMap::from([(2, active_ha_runtime(monotonic_nanos() / 1_000_000_000))]);
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));
        dynamic_neighbors.lock().expect("neighbors").insert(
            (24, IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
            NeighborEntry {
                mac: [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01],
            },
        );

        let resolved = reverse_resolution_for_session(
            &state,
            &ha_state,
            &dynamic_neighbors,
            IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            "lan",
            true,
            monotonic_nanos() / 1_000_000_000,
            false,
        );

        assert_eq!(
            resolved.disposition,
            ForwardingDisposition::ForwardCandidate
        );
        assert_eq!(resolved.egress_ifindex, 24);
        assert_eq!(resolved.tx_ifindex, 24);
    }

    #[test]
    fn fabric_originated_reverse_session_uses_zone_encoded_fabric_redirect_when_client_rg_inactive()
    {
        let state = build_forwarding_state(&nat_snapshot_with_fabric());
        let ha_state =
            BTreeMap::from([(2, inactive_ha_runtime(monotonic_nanos() / 1_000_000_000))]);
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));

        let resolved = reverse_resolution_for_session(
            &state,
            &ha_state,
            &dynamic_neighbors,
            IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            "lan",
            true,
            monotonic_nanos() / 1_000_000_000,
            false,
        );

        assert_eq!(resolved.disposition, ForwardingDisposition::FabricRedirect);
        assert_eq!(resolved.egress_ifindex, 21);
        assert_eq!(resolved.tx_ifindex, 21);
        assert_eq!(
            resolved.src_mac,
            Some([0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x01])
        );
    }

    #[test]
    fn cluster_peer_return_fast_path_allows_sfmix_to_lan_reply() {
        let mut state = build_forwarding_state(&native_gre_pbr_snapshot(true));
        state.fabrics.push(FabricLink {
            parent_ifindex: 4,
            overlay_ifindex: 104,
            peer_addr: IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2)),
            peer_mac: [0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee],
            local_mac: [0x02, 0xbf, 0x72, 0xff, 0x00, 0x01],
        });
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));
        dynamic_neighbors.lock().expect("neighbors").insert(
            (5, IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
            NeighborEntry {
                mac: [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01],
            },
        );
        let meta = UserspaceDpMeta {
            ingress_ifindex: 4,
            protocol: PROTO_ICMP,
            l4_offset: 0,
            ..UserspaceDpMeta::default()
        };
        let packet_frame = [0u8];

        let (decision, metadata) = cluster_peer_return_fast_path(
            &state,
            &dynamic_neighbors,
            &packet_frame,
            meta,
            Some("sfmix"),
            IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        )
        .expect("fabric return fast path");

        assert_eq!(
            decision.resolution.disposition,
            ForwardingDisposition::ForwardCandidate
        );
        assert_eq!(decision.resolution.egress_ifindex, 5);
        assert_eq!(metadata.ingress_zone.as_ref(), "sfmix");
        assert_eq!(metadata.egress_zone.as_ref(), "lan");
        assert!(metadata.fabric_ingress);
        assert!(metadata.is_reverse);
    }

    #[test]
    fn cluster_peer_return_fast_path_skips_pure_tcp_syn() {
        let mut state = build_forwarding_state(&native_gre_pbr_snapshot(true));
        state.fabrics.push(FabricLink {
            parent_ifindex: 4,
            overlay_ifindex: 104,
            peer_addr: IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2)),
            peer_mac: [0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee],
            local_mac: [0x02, 0xbf, 0x72, 0xff, 0x00, 0x01],
        });
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));
        let meta = UserspaceDpMeta {
            ingress_ifindex: 4,
            protocol: PROTO_TCP,
            tcp_flags: TCP_FLAG_SYN,
            ..UserspaceDpMeta::default()
        };

        assert!(
            cluster_peer_return_fast_path(
                &state,
                &dynamic_neighbors,
                &[],
                meta,
                Some("sfmix"),
                IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            )
            .is_none()
        );
    }

    #[test]
    fn cluster_peer_return_fast_path_skips_icmp_echo_request() {
        let mut state = build_forwarding_state(&native_gre_pbr_snapshot(true));
        state.fabrics.push(FabricLink {
            parent_ifindex: 4,
            overlay_ifindex: 104,
            peer_addr: IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2)),
            peer_mac: [0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee],
            local_mac: [0x02, 0xbf, 0x72, 0xff, 0x00, 0x01],
        });
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));
        let meta = UserspaceDpMeta {
            ingress_ifindex: 4,
            protocol: PROTO_ICMP,
            l4_offset: 0,
            ..UserspaceDpMeta::default()
        };
        let packet_frame = [8u8];

        assert!(
            cluster_peer_return_fast_path(
                &state,
                &dynamic_neighbors,
                &packet_frame,
                meta,
                Some("lan"),
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            )
            .is_none()
        );
    }

    #[test]
    fn cluster_peer_return_fast_path_skips_icmpv6_echo_request() {
        let mut state = build_forwarding_state(&native_gre_pbr_snapshot(true));
        state.fabrics.push(FabricLink {
            parent_ifindex: 4,
            overlay_ifindex: 104,
            peer_addr: IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2)),
            peer_mac: [0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee],
            local_mac: [0x02, 0xbf, 0x72, 0xff, 0x00, 0x01],
        });
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));
        let meta = UserspaceDpMeta {
            ingress_ifindex: 4,
            protocol: PROTO_ICMPV6,
            l4_offset: 0,
            ..UserspaceDpMeta::default()
        };
        let packet_frame = [128u8];

        assert!(
            cluster_peer_return_fast_path(
                &state,
                &dynamic_neighbors,
                &packet_frame,
                meta,
                Some("lan"),
                IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
            )
            .is_none()
        );
    }

    #[test]
    fn missing_neighbor_session_metadata_preserves_fabric_ingress() {
        let mut state = build_forwarding_state(&native_gre_pbr_snapshot(false));
        state.fabrics.push(FabricLink {
            parent_ifindex: 4,
            overlay_ifindex: 104,
            peer_addr: IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2)),
            peer_mac: [0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee],
            local_mac: [0x02, 0xbf, 0x72, 0xff, 0x00, 0x01],
        });
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::MissingNeighbor,
                local_ifindex: 0,
                egress_ifindex: 13,
                tx_ifindex: 13,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V6(Ipv6Addr::new(
                    0x2001, 0x559, 0x8585, 0x50, 0, 0, 0, 0x1,
                ))),
                neighbor_mac: None,
                src_mac: None,
                tx_vlan_id: 0,
            },
            nat: NatDecision::default(),
        };

        let ingress_zone = Arc::<str>::from("lan");
        let egress_zone = Arc::<str>::from("wan");
        let metadata = build_missing_neighbor_session_metadata(
            &state,
            &ingress_zone,
            &egress_zone,
            true,
            decision,
        );

        assert_eq!(metadata.ingress_zone.as_ref(), "lan");
        assert_eq!(metadata.egress_zone.as_ref(), "wan");
        assert!(metadata.fabric_ingress);
        assert!(!metadata.is_reverse);
    }

    #[test]
    fn reverse_session_prefers_interface_snat_ipv4_local_delivery() {
        let state = build_forwarding_state(&nat_snapshot());
        let ha_state = BTreeMap::new();
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));

        let resolved = reverse_resolution_for_session(
            &state,
            &ha_state,
            &dynamic_neighbors,
            IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
            "wan",
            false,
            monotonic_nanos() / 1_000_000_000,
            false,
        );

        assert_eq!(resolved.disposition, ForwardingDisposition::LocalDelivery);
        assert_eq!(resolved.local_ifindex, 12);
        assert_eq!(resolved.egress_ifindex, 12);
        assert_eq!(resolved.tx_ifindex, 12);
    }

    #[test]
    fn reverse_session_prefers_interface_snat_ipv6_local_delivery() {
        let state = build_forwarding_state(&nat_snapshot());
        let ha_state = BTreeMap::new();
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));

        let resolved = reverse_resolution_for_session(
            &state,
            &ha_state,
            &dynamic_neighbors,
            "2001:559:8585:80::8".parse().expect("dst"),
            "wan",
            false,
            monotonic_nanos() / 1_000_000_000,
            false,
        );

        assert_eq!(resolved.disposition, ForwardingDisposition::LocalDelivery);
        assert_eq!(resolved.local_ifindex, 12);
        assert_eq!(resolved.egress_ifindex, 12);
        assert_eq!(resolved.tx_ifindex, 12);
    }

    #[test]
    fn session_hit_keeps_interface_snat_ipv4_local_delivery() {
        let state = build_forwarding_state(&nat_snapshot());
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));
        let flow = SessionFlow {
            src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
            forward_key: SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
                src_port: 5201,
                dst_port: 43600,
            },
        };
        let decision = SessionDecision {
            resolution: interface_nat_local_resolution(&state, flow.dst_ip)
                .expect("interface nat local delivery"),
            nat: NatDecision::default(),
        };

        let resolved =
            lookup_forwarding_resolution_for_session(&state, &dynamic_neighbors, &flow, decision);

        assert_eq!(resolved.disposition, ForwardingDisposition::LocalDelivery);
        assert_eq!(resolved.local_ifindex, 12);
    }

    #[test]
    fn session_hit_keeps_interface_snat_ipv6_local_delivery() {
        let state = build_forwarding_state(&nat_snapshot());
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));
        let flow = SessionFlow {
            src_ip: "2001:559:8585:80::200".parse().expect("src"),
            dst_ip: "2001:559:8585:80::8".parse().expect("dst"),
            forward_key: SessionKey {
                addr_family: libc::AF_INET6 as u8,
                protocol: PROTO_TCP,
                src_ip: "2001:559:8585:80::200".parse().expect("src"),
                dst_ip: "2001:559:8585:80::8".parse().expect("dst"),
                src_port: 5201,
                dst_port: 43600,
            },
        };
        let decision = SessionDecision {
            resolution: interface_nat_local_resolution(&state, flow.dst_ip)
                .expect("interface nat local delivery"),
            nat: NatDecision::default(),
        };

        let resolved =
            lookup_forwarding_resolution_for_session(&state, &dynamic_neighbors, &flow, decision);

        assert_eq!(resolved.disposition, ForwardingDisposition::LocalDelivery);
        assert_eq!(resolved.local_ifindex, 12);
    }

    #[test]
    fn embedded_icmp_to_inactive_owner_rg_uses_zone_encoded_fabric_redirect() {
        let state = build_forwarding_state(&nat_snapshot_with_fabric());
        let ha_state =
            BTreeMap::from([(2, inactive_ha_runtime(monotonic_nanos() / 1_000_000_000))]);
        let icmp_match = EmbeddedIcmpMatch {
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                ..NatDecision::default()
            },
            original_src: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            original_src_port: 33434,
            embedded_proto: PROTO_UDP,
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 24,
                tx_ifindex: 24,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
                neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x01, 0x00, 0x01]),
                tx_vlan_id: 0,
            },
            metadata: SessionMetadata {
                ingress_zone: Arc::<str>::from("wan"),
                egress_zone: Arc::<str>::from("lan"),
                owner_rg_id: 2,
                fabric_ingress: false,
                is_reverse: false,
                nat64_reverse: None,
            },
        };

        let resolved = finalize_embedded_icmp_resolution(
            &state,
            &ha_state,
            monotonic_nanos() / 1_000_000_000,
            12,
            &icmp_match,
        );
        assert_eq!(resolved.disposition, ForwardingDisposition::FabricRedirect);
        assert_eq!(resolved.egress_ifindex, 21);
        assert_eq!(resolved.tx_ifindex, 21);
        assert_eq!(
            resolved.src_mac,
            Some([0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x02])
        );
    }

    #[test]
    fn embedded_icmp_no_route_uses_zone_encoded_fabric_redirect() {
        let state = build_forwarding_state(&nat_snapshot_with_fabric());
        let ha_state = BTreeMap::new();
        let icmp_match = EmbeddedIcmpMatch {
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                ..NatDecision::default()
            },
            original_src: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            original_src_port: 33434,
            embedded_proto: PROTO_UDP,
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::NoRoute,
                local_ifindex: 0,
                egress_ifindex: 0,
                tx_ifindex: 0,
                tunnel_endpoint_id: 0,
                next_hop: None,
                neighbor_mac: None,
                src_mac: None,
                tx_vlan_id: 0,
            },
            metadata: SessionMetadata {
                ingress_zone: Arc::<str>::from("wan"),
                egress_zone: Arc::<str>::from("lan"),
                owner_rg_id: 2,
                fabric_ingress: false,
                is_reverse: false,
                nat64_reverse: None,
            },
        };

        let resolved = finalize_embedded_icmp_resolution(
            &state,
            &ha_state,
            monotonic_nanos() / 1_000_000_000,
            12,
            &icmp_match,
        );
        assert_eq!(resolved.disposition, ForwardingDisposition::FabricRedirect);
        assert_eq!(resolved.egress_ifindex, 21);
        assert_eq!(resolved.tx_ifindex, 21);
        assert_eq!(
            resolved.src_mac,
            Some([0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x02])
        );
    }

    #[test]
    fn embedded_icmp_discard_route_uses_zone_encoded_fabric_redirect() {
        let state = build_forwarding_state(&nat_snapshot_with_fabric());
        let ha_state = BTreeMap::new();
        let icmp_match = EmbeddedIcmpMatch {
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                ..NatDecision::default()
            },
            original_src: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            original_src_port: 33434,
            embedded_proto: PROTO_UDP,
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::DiscardRoute,
                local_ifindex: 0,
                egress_ifindex: 24,
                tx_ifindex: 24,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
                neighbor_mac: None,
                src_mac: None,
                tx_vlan_id: 0,
            },
            metadata: SessionMetadata {
                ingress_zone: Arc::<str>::from("wan"),
                egress_zone: Arc::<str>::from("lan"),
                owner_rg_id: 2,
                fabric_ingress: false,
                is_reverse: false,
                nat64_reverse: None,
            },
        };

        let resolved = finalize_embedded_icmp_resolution(
            &state,
            &ha_state,
            monotonic_nanos() / 1_000_000_000,
            12,
            &icmp_match,
        );
        assert_eq!(resolved.disposition, ForwardingDisposition::FabricRedirect);
        assert_eq!(resolved.egress_ifindex, 21);
        assert_eq!(resolved.tx_ifindex, 21);
    }

    #[test]
    fn embedded_icmp_from_fabric_does_not_redirect_back_to_fabric() {
        let state = build_forwarding_state(&nat_snapshot_with_fabric());
        let ha_state =
            BTreeMap::from([(2, inactive_ha_runtime(monotonic_nanos() / 1_000_000_000))]);
        let icmp_match = EmbeddedIcmpMatch {
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                ..NatDecision::default()
            },
            original_src: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            original_src_port: 33434,
            embedded_proto: PROTO_UDP,
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 24,
                tx_ifindex: 24,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
                neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x01, 0x00, 0x01]),
                tx_vlan_id: 0,
            },
            metadata: SessionMetadata {
                ingress_zone: Arc::<str>::from("wan"),
                egress_zone: Arc::<str>::from("lan"),
                owner_rg_id: 2,
                fabric_ingress: false,
                is_reverse: false,
                nat64_reverse: None,
            },
        };

        let resolved = finalize_embedded_icmp_resolution(
            &state,
            &ha_state,
            monotonic_nanos() / 1_000_000_000,
            21,
            &icmp_match,
        );
        assert_eq!(resolved.disposition, ForwardingDisposition::HAInactive);
    }

    #[test]
    fn fabric_ingress_does_not_redirect_back_to_fabric() {
        let state = build_forwarding_state(&nat_snapshot_with_fabric());
        let blocked = ForwardingResolution {
            disposition: ForwardingDisposition::HAInactive,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 12,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            src_mac: None,
            tx_vlan_id: 80,
        };
        assert_eq!(
            redirect_via_fabric_if_needed(&state, blocked, 21).disposition,
            ForwardingDisposition::HAInactive
        );
    }

    #[test]
    fn source_nat_selection_uses_interface_addresses() {
        let state = build_forwarding_state(&nat_snapshot());
        let flow = SessionFlow {
            src_ip: "10.0.61.102".parse().expect("src"),
            dst_ip: "172.16.80.200".parse().expect("dst"),
            forward_key: SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip: "10.0.61.102".parse().expect("src"),
                dst_ip: "172.16.80.200".parse().expect("dst"),
                src_port: 12345,
                dst_port: 5201,
            },
        };
        let (from_zone, to_zone) = zone_pair_for_flow(&state, 24, 12);
        assert_eq!(
            match_source_nat_for_flow(&state, &from_zone, &to_zone, 12, &flow),
            Some(NatDecision {
                rewrite_src: Some("172.16.80.8".parse().expect("snat")),
                rewrite_dst: None,
                ..NatDecision::default()
            })
        );
    }

    #[test]
    fn source_nat_selection_uses_interface_addresses_v6() {
        let state = build_forwarding_state(&nat_snapshot());
        let flow = SessionFlow {
            src_ip: "2001:559:8585:ef00::100".parse().expect("src"),
            dst_ip: "2001:559:8585:80::200".parse().expect("dst"),
            forward_key: SessionKey {
                addr_family: libc::AF_INET6 as u8,
                protocol: PROTO_TCP,
                src_ip: "2001:559:8585:ef00::100".parse().expect("src"),
                dst_ip: "2001:559:8585:80::200".parse().expect("dst"),
                src_port: 12345,
                dst_port: 5201,
            },
        };
        let (from_zone, to_zone) = zone_pair_for_flow(&state, 24, 12);
        assert_eq!(
            match_source_nat_for_flow(&state, &from_zone, &to_zone, 12, &flow),
            Some(NatDecision {
                rewrite_src: Some("2001:559:8585:80::8".parse().expect("snat")),
                rewrite_dst: None,
                ..NatDecision::default()
            })
        );
    }

    #[test]
    fn interface_snat_addresses_are_not_treated_as_local_delivery() {
        let state = build_forwarding_state(&nat_snapshot());
        let resolved_v4 = lookup_forwarding_resolution(&state, "172.16.80.8".parse().expect("v4"));
        assert_ne!(
            resolved_v4.disposition,
            ForwardingDisposition::LocalDelivery
        );
        let resolved_v6 =
            lookup_forwarding_resolution(&state, "2001:559:8585:80::8".parse().expect("v6"));
        assert_ne!(
            resolved_v6.disposition,
            ForwardingDisposition::LocalDelivery
        );
    }

    #[test]
    fn interface_snat_addresses_are_local_delivered_on_session_miss() {
        let state = build_forwarding_state(&nat_snapshot());
        let resolved_v4 =
            interface_nat_local_resolution(&state, "172.16.80.8".parse().expect("v4"))
                .expect("v4 nat local delivery");
        assert_eq!(
            resolved_v4.disposition,
            ForwardingDisposition::LocalDelivery
        );
        assert_eq!(resolved_v4.local_ifindex, 12);

        let resolved_v6 =
            interface_nat_local_resolution(&state, "2001:559:8585:80::8".parse().expect("v6"))
                .expect("v6 nat local delivery");
        assert_eq!(
            resolved_v6.disposition,
            ForwardingDisposition::LocalDelivery
        );
        assert_eq!(resolved_v6.local_ifindex, 12);
    }

    #[test]
    fn icmp_session_miss_resolution_prefers_frame_destination_for_interface_nat_local_delivery() {
        let state = build_forwarding_state(&nat_snapshot());
        let frame = vlan_icmp_reply_frame();
        let mut area = MmapArea::new(4096).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let mut meta = valid_meta();
        meta.l3_offset = 18;
        meta.l4_offset = 38;
        meta.flow_src_addr[..4].copy_from_slice(&[172, 16, 80, 201]);
        // Deliberately poison the metadata tuple to model a stamped-dst mismatch.
        meta.flow_dst_addr[..4].copy_from_slice(&[10, 0, 61, 1]);

        let flow = parse_session_flow(
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
        )
        .expect("flow");
        assert_eq!(flow.dst_ip, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)));

        let resolution_target = parse_packet_destination(
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
        )
        .expect("frame destination");
        assert_eq!(resolution_target, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)));

        let resolved =
            interface_nat_local_resolution_on_session_miss(&state, resolution_target, PROTO_ICMP)
                .expect("nat local delivery");
        assert_eq!(resolved.disposition, ForwardingDisposition::LocalDelivery);
        assert_eq!(resolved.local_ifindex, 12);
    }

    #[test]
    fn tcp_session_miss_local_delivers_interface_nat_address() {
        let state = build_forwarding_state(&nat_snapshot());
        let resolved_v4 = interface_nat_local_resolution_on_session_miss(
            &state,
            "172.16.80.8".parse().expect("v4"),
            PROTO_TCP,
        )
        .expect("tcp v4 nat local delivery");
        assert_eq!(
            resolved_v4.disposition,
            ForwardingDisposition::LocalDelivery
        );
        assert_eq!(resolved_v4.local_ifindex, 12);

        let resolved_v6 = interface_nat_local_resolution_on_session_miss(
            &state,
            "2001:559:8585:80::8".parse().expect("v6"),
            PROTO_UDP,
        )
        .expect("udp v6 nat local delivery");
        assert_eq!(
            resolved_v6.disposition,
            ForwardingDisposition::LocalDelivery
        );
        assert_eq!(resolved_v6.local_ifindex, 12);
    }

    #[test]
    fn tcp_ack_session_miss_does_not_cache_interface_nat_local_delivery() {
        let state = build_forwarding_state(&nat_snapshot());
        let resolution = interface_nat_local_resolution_on_session_miss(
            &state,
            "172.16.80.8".parse().expect("v4"),
            PROTO_TCP,
        )
        .expect("tcp nat local delivery");
        assert!(!should_cache_local_delivery_session_on_miss(
            &state,
            "172.16.80.8".parse().expect("v4"),
            resolution,
            PROTO_TCP,
            0x10,
        ));
    }

    #[test]
    fn tcp_syn_session_miss_still_caches_interface_nat_local_delivery() {
        let state = build_forwarding_state(&nat_snapshot());
        let resolution = interface_nat_local_resolution_on_session_miss(
            &state,
            "172.16.80.8".parse().expect("v4"),
            PROTO_TCP,
        )
        .expect("tcp nat local delivery");
        assert!(should_cache_local_delivery_session_on_miss(
            &state,
            "172.16.80.8".parse().expect("v4"),
            resolution,
            PROTO_TCP,
            0x02,
        ));
    }

    #[test]
    fn tunnel_session_miss_blocks_interface_nat_local_delivery() {
        let mut snapshot = native_gre_snapshot(true);
        snapshot.source_nat_rules = vec![SourceNATRuleSnapshot {
            name: "lan-to-sfmix".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "sfmix".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            interface_mode: true,
            ..Default::default()
        }];
        let state = build_forwarding_state(&snapshot);
        let tunnel_snat_ip = "10.255.192.42".parse().expect("tunnel snat");
        assert!(should_block_tunnel_interface_nat_session_miss(
            &state,
            tunnel_snat_ip,
            PROTO_TCP,
        ));
        assert!(should_block_tunnel_interface_nat_session_miss(
            &state,
            tunnel_snat_ip,
            PROTO_UDP,
        ));
        assert!(should_block_tunnel_interface_nat_session_miss(
            &state,
            tunnel_snat_ip,
            PROTO_ICMP,
        ));
    }

    #[test]
    fn ingress_interface_local_resolution_matches_vlan_local_address() {
        let state = build_forwarding_state(&nat_snapshot());
        let resolved =
            ingress_interface_local_resolution(&state, 11, 80, "172.16.80.8".parse().expect("dst"))
                .expect("ingress local delivery");
        assert_eq!(resolved.disposition, ForwardingDisposition::LocalDelivery);
        assert_eq!(resolved.local_ifindex, 12);
    }

    #[test]
    fn tcp_session_miss_local_delivers_ingress_vlan_address() {
        let state = build_forwarding_state(&nat_snapshot());
        let resolved_v4 = ingress_interface_local_resolution_on_session_miss(
            &state,
            11,
            80,
            "172.16.80.8".parse().expect("dst"),
            PROTO_TCP,
        )
        .expect("tcp ingress local delivery");
        assert_eq!(
            resolved_v4.disposition,
            ForwardingDisposition::LocalDelivery
        );
        assert_eq!(resolved_v4.local_ifindex, 12);

        let resolved_v6 = ingress_interface_local_resolution_on_session_miss(
            &state,
            11,
            80,
            "2001:559:8585:80::8".parse().expect("dst"),
            PROTO_UDP,
        )
        .expect("udp ingress local delivery");
        assert_eq!(
            resolved_v6.disposition,
            ForwardingDisposition::LocalDelivery
        );
        assert_eq!(resolved_v6.local_ifindex, 12);
    }

    #[test]
    fn tcp_ack_session_miss_does_not_cache_ingress_local_delivery() {
        let state = build_forwarding_state(&nat_snapshot());
        let resolution = ingress_interface_local_resolution_on_session_miss(
            &state,
            11,
            80,
            "172.16.80.8".parse().expect("dst"),
            PROTO_TCP,
        )
        .expect("tcp ingress local delivery");
        assert!(!should_cache_local_delivery_session_on_miss(
            &state,
            "172.16.80.8".parse().expect("dst"),
            resolution,
            PROTO_TCP,
            0x10,
        ));
    }

    #[test]
    fn tcp_syn_session_miss_still_caches_ingress_local_delivery() {
        let state = build_forwarding_state(&nat_snapshot());
        let resolution = ingress_interface_local_resolution_on_session_miss(
            &state,
            11,
            80,
            "172.16.80.8".parse().expect("dst"),
            PROTO_TCP,
        )
        .expect("tcp ingress local delivery");
        assert!(should_cache_local_delivery_session_on_miss(
            &state,
            "172.16.80.8".parse().expect("dst"),
            resolution,
            PROTO_TCP,
            0x02,
        ));
    }

    #[test]
    fn helper_local_session_on_miss_stays_out_of_shared_alias_maps() {
        let mut sessions = SessionTable::new();
        let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
        let state = build_forwarding_state(&nat_snapshot());
        let key = SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: "172.16.80.8".parse().expect("src"),
            dst_ip: "172.16.80.200".parse().expect("dst"),
            src_port: 40278,
            dst_port: 5201,
        };
        let decision = SessionDecision {
            resolution: ingress_interface_local_resolution_on_session_miss(
                &state, 11, 80, key.src_ip, PROTO_TCP,
            )
            .expect("tcp ingress local delivery"),
            nat: NatDecision::default(),
        };
        let metadata = SessionMetadata {
            ingress_zone: Arc::<str>::from("lan"),
            egress_zone: Arc::<str>::from("wan"),
            owner_rg_id: 0,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
        };

        assert!(install_helper_local_session_on_miss(
            &mut sessions,
            -1,
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            &key,
            decision,
            metadata,
            SessionOrigin::LocalMiss,
            1_000_000,
            PROTO_TCP,
            0x10,
        ));
        assert!(sessions.lookup(&key, 1_000_000, 0x10).is_some());
        assert!(
            shared_sessions
                .lock()
                .expect("shared lock")
                .get(&key)
                .is_none()
        );
        assert!(shared_nat_sessions.lock().expect("nat lock").is_empty());
        assert!(
            shared_forward_wire_sessions
                .lock()
                .expect("forward wire lock")
                .is_empty()
        );
    }

    #[test]
    fn helper_local_session_on_miss_clears_stale_shared_aliases() {
        let mut sessions = SessionTable::new();
        let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
        let state = build_forwarding_state(&nat_snapshot());
        let key = SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: "172.16.80.8".parse().expect("src"),
            dst_ip: "172.16.80.200".parse().expect("dst"),
            src_port: 40278,
            dst_port: 5201,
        };
        let decision = SessionDecision {
            resolution: ingress_interface_local_resolution_on_session_miss(
                &state, 11, 80, key.src_ip, PROTO_TCP,
            )
            .expect("tcp ingress local delivery"),
            nat: NatDecision::default(),
        };
        let metadata = SessionMetadata {
            ingress_zone: Arc::<str>::from("lan"),
            egress_zone: Arc::<str>::from("wan"),
            owner_rg_id: 0,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
        };
        let entry = SyncedSessionEntry {
            key: key.clone(),
            decision,
            metadata: metadata.clone(),
            origin: SessionOrigin::SyncImport,
            protocol: PROTO_TCP,
            tcp_flags: 0x10,
        };

        // Install with SyncImport origin so take_synced_local recognizes
        // this as a peer-synced session.
        assert!(sessions.install_with_protocol_with_origin(
            key.clone(),
            decision,
            metadata,
            SessionOrigin::SyncImport,
            1_000_000,
            PROTO_TCP,
            0x10,
        ));
        publish_shared_session(
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            &entry,
        );

        assert!(install_helper_local_session_on_miss(
            &mut sessions,
            -1,
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            &key,
            decision,
            entry.metadata.clone(),
            SessionOrigin::LocalMiss,
            2_000_000,
            PROTO_TCP,
            0x10,
        ));
        assert!(
            shared_sessions
                .lock()
                .expect("shared lock")
                .get(&key)
                .is_none()
        );
        assert!(shared_nat_sessions.lock().expect("nat lock").is_empty());
        assert!(
            shared_forward_wire_sessions
                .lock()
                .expect("forward wire lock")
                .is_empty()
        );
    }

    #[test]
    fn unsolicited_dns_reply_respects_flow_knob() {
        let mut state = build_forwarding_state(&nat_snapshot());
        let flow = SessionFlow {
            src_ip: "172.16.80.53".parse().expect("src"),
            dst_ip: "10.0.61.102".parse().expect("dst"),
            forward_key: SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_UDP,
                src_ip: "172.16.80.53".parse().expect("src"),
                dst_ip: "10.0.61.102".parse().expect("dst"),
                src_port: 53,
                dst_port: 5353,
            },
        };
        state.allow_dns_reply = true;
        assert!(allow_unsolicited_dns_reply(&state, &flow));
        state.allow_dns_reply = false;
        assert!(!allow_unsolicited_dns_reply(&state, &flow));
    }

    #[test]
    fn policy_selection_permits_matching_zone_pair() {
        let state = build_forwarding_state(&nat_snapshot());
        let flow = SessionFlow {
            src_ip: "10.0.61.102".parse().expect("src"),
            dst_ip: "172.16.80.200".parse().expect("dst"),
            forward_key: SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip: "10.0.61.102".parse().expect("src"),
                dst_ip: "172.16.80.200".parse().expect("dst"),
                src_port: 12345,
                dst_port: 5201,
            },
        };
        let (from_zone, to_zone) = zone_pair_for_flow(&state, 24, 12);
        assert_eq!(
            evaluate_policy(
                &state.policy,
                &from_zone,
                &to_zone,
                flow.src_ip,
                flow.dst_ip,
                flow.forward_key.protocol,
                flow.forward_key.src_port,
                flow.forward_key.dst_port,
            ),
            PolicyAction::Permit
        );
    }

    #[test]
    fn policy_selection_denies_on_default_policy() {
        let state = build_forwarding_state(&policy_deny_snapshot());
        let flow = SessionFlow {
            src_ip: "10.0.61.102".parse().expect("src"),
            dst_ip: "172.16.80.200".parse().expect("dst"),
            forward_key: SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip: "10.0.61.102".parse().expect("src"),
                dst_ip: "172.16.80.200".parse().expect("dst"),
                src_port: 12345,
                dst_port: 5201,
            },
        };
        let (from_zone, to_zone) = zone_pair_for_flow(&state, 24, 12);
        assert_eq!(
            evaluate_policy(
                &state.policy,
                &from_zone,
                &to_zone,
                flow.src_ip,
                flow.dst_ip,
                flow.forward_key.protocol,
                flow.forward_key.src_port,
                flow.forward_key.dst_port,
            ),
            PolicyAction::Deny
        );
    }

    #[test]
    fn forwarding_resolution_reports_egress_and_neighbor() {
        let state = build_forwarding_state(&forwarding_snapshot(true));
        let resolved = lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(
            resolved.disposition,
            ForwardingDisposition::ForwardCandidate
        );
        assert_eq!(resolved.egress_ifindex, 12);
        assert_eq!(
            resolved.next_hop,
            Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1)))
        );
        assert_eq!(
            resolved.neighbor_mac,
            Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
        );
    }

    #[test]
    fn forwarding_resolution_supports_next_table_recursion() {
        let state = build_forwarding_state(&forwarding_snapshot_with_next_table(true));
        let resolved = lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(
            resolved.disposition,
            ForwardingDisposition::ForwardCandidate
        );
        assert_eq!(resolved.egress_ifindex, 12);
        assert_eq!(
            resolved.next_hop,
            Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1)))
        );

        let resolved_v6 = lookup_forwarding_resolution(
            &state,
            IpAddr::V6("2606:4700:4700::1111".parse().expect("ipv6")),
        );
        assert_eq!(
            resolved_v6.disposition,
            ForwardingDisposition::ForwardCandidate
        );
        assert_eq!(resolved_v6.egress_ifindex, 12);
        assert_eq!(
            resolved_v6.next_hop,
            Some(IpAddr::V6("2001:559:8585:50::1".parse().expect("v6 nh")))
        );
    }

    #[test]
    fn forwarding_state_normalizes_ipv6_routes_emitted_in_inet_table() {
        let mut snapshot = forwarding_snapshot(true);
        snapshot.routes[1].table = "inet.0".to_string();
        snapshot.routes[1].family = "inet".to_string();
        let state = build_forwarding_state(&snapshot);
        let resolved = lookup_forwarding_resolution(
            &state,
            IpAddr::V6("2606:4700:4700::1111".parse().expect("ipv6")),
        );
        assert_eq!(
            resolved.disposition,
            ForwardingDisposition::ForwardCandidate
        );
        assert_eq!(resolved.egress_ifindex, 12);
        assert_eq!(
            resolved.next_hop,
            Some(IpAddr::V6("2001:559:8585:50::1".parse().expect("v6 nh")))
        );
    }

    #[test]
    fn dynamic_neighbor_cache_enables_forward_candidate() {
        let state = build_forwarding_state(&forwarding_snapshot(false));
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::from_iter([(
            (12, IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1))),
            NeighborEntry {
                mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            },
        )])));
        let resolved = lookup_forwarding_resolution_with_dynamic(
            &state,
            &dynamic_neighbors,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        );
        assert_eq!(
            resolved.disposition,
            ForwardingDisposition::ForwardCandidate
        );
        assert_eq!(
            resolved.neighbor_mac,
            Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
        );
    }

    #[test]
    fn parse_neighbor_entries_accepts_stale_ipv4_and_ipv6_rows() {
        let parsed = parse_neighbor_entries(
            "172.16.80.200 lladdr ba:86:e9:f6:4b:d5 STALE\n2001:559:8585:80::200 lladdr ba:86:e9:f6:4b:d5 STALE\n",
        );
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].0, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)));
        assert_eq!(
            parsed[1].0,
            IpAddr::V6("2001:559:8585:80::200".parse().expect("ipv6"))
        );
        assert_eq!(parsed[0].1.mac, [0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]);
        assert_eq!(parsed[1].1.mac, [0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]);
    }

    #[test]
    fn learned_ingress_neighbor_enables_reverse_lan_resolution() {
        let state = build_forwarding_state(&nat_snapshot());
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));
        learn_dynamic_neighbor(
            &state,
            &dynamic_neighbors,
            24,
            0,
            IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        );
        let resolved = lookup_forwarding_resolution_with_dynamic(
            &state,
            &dynamic_neighbors,
            IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
        );
        assert_eq!(
            resolved.disposition,
            ForwardingDisposition::ForwardCandidate
        );
        assert_eq!(resolved.egress_ifindex, 24);
        assert_eq!(
            resolved.neighbor_mac,
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
    }

    #[test]
    fn learned_vlan_ingress_neighbor_maps_to_logical_ifindex() {
        let state = build_forwarding_state(&nat_snapshot());
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));
        learn_dynamic_neighbor(
            &state,
            &dynamic_neighbors,
            11,
            80,
            IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01],
        );
        let resolved = lookup_forwarding_resolution_with_dynamic(
            &state,
            &dynamic_neighbors,
            IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        );
        assert_eq!(
            resolved.disposition,
            ForwardingDisposition::ForwardCandidate
        );
        assert_eq!(resolved.egress_ifindex, 12);
        assert_eq!(
            resolved.neighbor_mac,
            Some([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01])
        );
    }

    #[test]
    fn forwarding_resolution_rejects_next_table_loop() {
        let state = build_forwarding_state(&forwarding_snapshot_with_next_table_loop());
        let resolved = lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(
            resolved.disposition,
            ForwardingDisposition::NextTableUnsupported
        );
    }

    #[test]
    fn tx_binding_resolution_prefers_bind_ifindex_for_vlan_units() {
        let state = build_forwarding_state(&nat_snapshot());
        assert_eq!(resolve_tx_binding_ifindex(&state, 12), 11);
    }

    #[test]
    fn tx_binding_resolution_uses_fabric_parent_ifindex() {
        let state = build_forwarding_state(&nat_snapshot_with_fabric());
        assert_eq!(resolve_tx_binding_ifindex(&state, 21), 21);
    }
}
