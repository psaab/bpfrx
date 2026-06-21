//! #946 Phase 1 — per-packet pipeline stages.
//!
//! Pure code-motion extraction of seven sub-stages out of the
//! `poll_binding_process_descriptor` while-let body. No batch
//! reordering, no behavioral change. Each helper here is the
//! direct semantic equivalent of the inline block it replaces.
//!
//! Stages owned by Phase 1:
//! - stage 5: link-layer (ARP/NDP) classify  → [stage_link_layer_classify]
//! - stage 6: native GRE decap               → [stage_native_gre_decap]
//! - stage 7+8: parse flow + learn neighbor  → [stage_parse_flow_and_learn]
//! - stage 9: fabric-ingress classification  → [stage_classify_fabric_ingress]
//! - stage 10: screen / IDS slow-path        → [stage_screen_check]
//! - stage 11: IPsec passthrough             → [stage_ipsec_passthrough_check]
//!
//! Stages NOT in scope (kept inline in `poll_descriptor.rs` for
//! Phase 1; will be tackled in follow-up phases):
//! - stages 1-4: rx telemetry, parse meta, classify, slice
//! - stages 12+: flow-cache fast path, session lookup, slow-path
//!   policy/NAT/forwarding, reverse-NAT/ICMP, MissingNeighbor
//!
//! See `docs/pr/946-pipeline-phase1/plan.md` for the full plan,
//! the 9-continue table, and the hidden-invariants list.

use super::*;
use crate::screen::{SynCookieAckVerdict, SynCookieChallenge};

/// Generic outcome for a per-packet stage. The `RecycleAndContinue`
/// arm signals that the caller should push `desc.addr` to
/// `binding.scratch.scratch_recycle` and `continue` the while-let.
/// `Continue(T)` carries the stage's output to the next stage.
pub(super) enum StageOutcome<T> {
    RecycleAndContinue,
    Continue(T),
}

pub(super) enum ScreenCheckOutcome {
    Pass,
    SynCookieChallenge(SynCookieChallenge),
}

pub(super) enum SynCookieAckOutcome {
    Pass,
    Validated,
}

/// Output of `stage_classify_fabric_ingress`. The stage *also*
/// mutates `meta.meta_flags` to set `FABRIC_INGRESS_FLAG`; this
/// struct carries the two return values the caller needs separately.
pub(super) struct FabricIngressOutcome {
    pub(super) ingress_zone_override: Option<u16>,
    pub(super) packet_fabric_ingress: bool,
}

/// Stage 5 — ARP / NDP link-layer classification.
///
/// ARP frames (Reply / Request / Other) are recycled without
/// flowing through the rest of the pipeline. ARP Reply additionally
/// learns a dynamic neighbor and adds a kernel ARP entry.
///
/// NDP NA with a Target Link-Layer Address option learns a dynamic
/// neighbor and adds a kernel neighbor entry, then falls through to
/// normal IPv6 forwarding (the NA frame itself transits the
/// firewall).
///
/// Plain non-link-layer packets fall through unchanged.
///
/// Side effects on `worker_ctx.dynamic_neighbors` (interior
/// mutability behind `Arc`) and the kernel ARP/NDP table are kept
/// inside this helper — the caller does not need visibility into
/// the learned neighbor for the same packet.
#[inline]
pub(super) fn stage_link_layer_classify(
    raw_frame: &[u8],
    meta: UserspaceDpMeta,
    worker_ctx: &WorkerContext,
) -> StageOutcome<()> {
    match parser::classify_arp(raw_frame) {
        parser::ArpClassification::Reply(arp) => {
            worker_ctx.dynamic_neighbors.insert(
                (meta.ingress_ifindex as i32, arp.sender_ip),
                NeighborEntry {
                    mac: arp.sender_mac,
                },
            );
            let neigh_ifindex = resolve_ingress_logical_ifindex(
                worker_ctx.forwarding,
                meta.ingress_ifindex as i32,
                meta.ingress_vlan_id,
            )
            .unwrap_or(meta.ingress_ifindex as i32);
            add_kernel_neighbor(neigh_ifindex, arp.sender_ip, arp.sender_mac);
            return StageOutcome::RecycleAndContinue;
        }
        parser::ArpClassification::OtherArp => {
            return StageOutcome::RecycleAndContinue;
        }
        parser::ArpClassification::NotArp => {}
    }
    if let Some(na) = parser::parse_ndp_neighbor_advert(raw_frame)
        && let Some(mac) = na.target_mac
    {
        worker_ctx.dynamic_neighbors.insert(
            (meta.ingress_ifindex as i32, na.target_ip),
            NeighborEntry { mac },
        );
        let neigh_ifindex = resolve_ingress_logical_ifindex(
            worker_ctx.forwarding,
            meta.ingress_ifindex as i32,
            meta.ingress_vlan_id,
        )
        .unwrap_or(meta.ingress_ifindex as i32);
        add_kernel_neighbor(neigh_ifindex, na.target_ip, mac);
    }
    StageOutcome::Continue(())
}

/// Stage 6 — native GRE decapsulation.
///
/// Returns the (possibly-updated) `meta` and the optional owned
/// decap frame. Caller binds the active slice locally:
///
/// ```text
/// let (meta, owned) = stage_native_gre_decap(raw_frame, meta, ...);
/// let packet_frame = owned.as_deref().unwrap_or(raw_frame);
/// ```
///
/// `owned_packet_frame: Option<Vec<u8>>` MUST be a `mut` binding at
/// the call site because the deferred stage-12+ code in
/// `poll_descriptor.rs` calls `.take()` on it (grep
/// `owned_packet_frame.take(` — the deferred flow-cache,
/// session-hit reverse-NAT, and missing-neighbor side-queue paths
/// each move the owned decap frame out before pushing the
/// resulting forward request). Symbol references rather than line
/// numbers because the line numbers drift any time a stage above
/// is touched.
///
/// The helper does NOT return the active slice — that would be a
/// self-referential return type (the slice would borrow from the
/// returned `Vec`).
#[inline]
pub(super) fn stage_native_gre_decap(
    raw_frame: &[u8],
    meta: UserspaceDpMeta,
    forwarding: &ForwardingState,
) -> (UserspaceDpMeta, Option<Vec<u8>>) {
    let native_gre_packet = try_native_gre_decap_from_frame(raw_frame, meta, forwarding);
    let new_meta = native_gre_packet
        .as_ref()
        .map(|packet| packet.meta)
        .unwrap_or(meta);
    let owned_packet_frame = native_gre_packet.map(|packet| packet.frame);
    (new_meta, owned_packet_frame)
}

/// Stage 7+8 — parse session flow and learn the source-side
/// dynamic neighbor.
///
/// `learn_from_live_frame` MUST be `owned_packet_frame.is_none()`
/// at the call site. Mirrors the GRE guard at
/// poll_descriptor.rs:113 — neighbor learning uses the un-decapped
/// raw_frame (via `area`/`desc`) so the source MAC comes from the
/// live UMEM Ethernet frame; learning from a decapped GRE inner
/// frame would record the GRE tunnel's egress MAC instead of the
/// outer host's.
///
/// Side effects: `worker_ctx.dynamic_neighbors` (interior mut),
/// `last_learned_neighbor` (caller's &mut), kernel neighbor table.
#[inline]
pub(super) fn stage_parse_flow_and_learn(
    area: &MmapArea,
    desc: XdpDesc,
    packet_frame: &[u8],
    meta: UserspaceDpMeta,
    learn_from_live_frame: bool,
    last_learned_neighbor: &mut Option<LearnedNeighborKey>,
    worker_ctx: &WorkerContext,
) -> Option<SessionFlow> {
    let flow = parse_session_flow_from_bytes(packet_frame, meta);
    if learn_from_live_frame
        && let Some(flow) = flow.as_ref()
    {
        learn_dynamic_neighbor_from_packet(
            area,
            desc,
            meta,
            flow.src_ip,
            last_learned_neighbor,
            worker_ctx.forwarding,
            worker_ctx.dynamic_neighbors,
        );
    }
    flow
}

/// Stage 9 — fabric-ingress classification.
///
/// Mutates `meta.meta_flags` to set `FABRIC_INGRESS_FLAG` when the
/// packet's ingress is a fabric overlay or carries a zone-encoded
/// fabric ingress marker. Returns the discovered zone override
/// (used by the screen stage) and the fabric flag (used by
/// downstream forwarding).
///
/// This stage MUST run before screen / IPsec / flow-cache because
/// those downstream stages read `meta.meta_flags` and the
/// `FABRIC_INGRESS_FLAG` is required to skip TTL decrement on
/// fabric-traversed packets (the sending peer already decremented
/// TTL when forwarding across the fabric link).
#[inline]
pub(super) fn stage_classify_fabric_ingress(
    packet_frame: &[u8],
    meta: &mut UserspaceDpMeta,
    worker_ctx: &WorkerContext,
) -> FabricIngressOutcome {
    let ingress_zone_override =
        parse_zone_encoded_fabric_ingress_from_frame(packet_frame, *meta, worker_ctx.forwarding);
    let packet_fabric_ingress = ingress_zone_override.is_some()
        || ingress_is_fabric_overlay(worker_ctx.forwarding, meta.ingress_ifindex as i32);
    if packet_fabric_ingress {
        meta.meta_flags |= FABRIC_INGRESS_FLAG;
    }
    FabricIngressOutcome {
        ingress_zone_override,
        packet_fabric_ingress,
    }
}

/// Stage 10 — screen / IDS slow-path check.
///
/// Only runs when screen profiles are configured (the `has_profiles`
/// gate). Resolves the ingress zone name (preferring the
/// fabric-zone override from stage 9), extracts a `ScreenPacketInfo`
/// from the packet, and runs `screen.check_packet`. On a Drop
/// verdict, bumps `counters.screen_drops` (batched, not direct
/// to `BindingLiveState` — #1187 DDoS-resilience: SYN flood is the
/// primary screen_drops trigger; unbatched atomics here would cause
/// MESI ping-pong with the coordinator's status reads under
/// volumetric attack) and returns `RecycleAndContinue`.
#[inline]
pub(super) fn stage_screen_check(
    flow: Option<&SessionFlow>,
    packet_frame: &[u8],
    meta: UserspaceDpMeta,
    ingress_zone_override: Option<u16>,
    now_secs: u64,
    screen: &mut ScreenState,
    counters: &mut BatchCounters,
    worker_ctx: &WorkerContext,
) -> StageOutcome<ScreenCheckOutcome> {
    if !screen.has_profiles() {
        return StageOutcome::Continue(ScreenCheckOutcome::Pass);
    }
    let Some(flow) = flow else {
        return StageOutcome::Continue(ScreenCheckOutcome::Pass);
    };
    let zone_id = ingress_zone_override
        .filter(|id| worker_ctx.forwarding.zone_id_to_name.contains_key(id))
        .or_else(|| {
            worker_ctx
                .forwarding
                .ifindex_to_zone_id
                .get(&(meta.ingress_ifindex as i32))
                .copied()
        });
    let Some(zone_id) = zone_id else {
        return StageOutcome::Continue(ScreenCheckOutcome::Pass);
    };
    let Some(zone_name) = worker_ctx
        .forwarding
        .zone_id_to_name
        .get(&zone_id)
        .map(|s| s.as_str())
    else {
        return StageOutcome::Continue(ScreenCheckOutcome::Pass);
    };
    // L3 starts after the 802.1Q tag whenever a tag is PRESENT, not
    // only when the VID is non-zero. 802.1p priority-tagged frames
    // carry a real tag (TPID 0x8100 + PCP bits) with VID 0, so a
    // `vlan_id > 0` test would read the IP header at offset 14 and
    // parse the tag's TPID/TCI bytes as the IPv4/IPv6 header — the
    // #2145 misclassification. `ingress_vlan_present` is the
    // tag-presence signal the shim already sets (mirrors the CoS path
    // in tx/cos_classify.rs).
    let l3_off = if meta.ingress_vlan_present != 0 { 18 } else { 14 };
    let screen_pkt = extract_screen_info(
        packet_frame,
        meta.addr_family,
        meta.protocol,
        meta.tcp_flags,
        meta.pkt_len,
        flow.src_ip,
        flow.dst_ip,
        flow.forward_key.src_port,
        flow.forward_key.dst_port,
        l3_off,
    );
    match screen.check_packet_with_zone_id(zone_name, zone_id, &screen_pkt, now_secs) {
        ScreenVerdict::Pass => StageOutcome::Continue(ScreenCheckOutcome::Pass),
        ScreenVerdict::SynCookieBypass => {
            counters.touched = true;
            counters.syn_cookie_bypass += 1;
            StageOutcome::Continue(ScreenCheckOutcome::Pass)
        }
        ScreenVerdict::Drop(reason) => {
            emit_screen_drop_event(
                worker_ctx.event_stream,
                &screen_pkt,
                meta,
                zone_id,
                reason,
                event_now_ns_from_secs(now_secs),
            );
            counters.touched = true;
            counters.screen_drops += 1;
            if reason == "syn-cookie-unavailable" {
                counters.syn_cookie_secret_unavailable += 1;
            }
            StageOutcome::RecycleAndContinue
        }
        ScreenVerdict::SynCookieChallenge(challenge) => {
            emit_screen_drop_event(
                worker_ctx.event_stream,
                &screen_pkt,
                meta,
                zone_id,
                "syn-cookie",
                event_now_ns_from_secs(now_secs),
            );
            counters.touched = true;
            counters.screen_drops += 1;
            counters.syn_cookie_challenges += 1;
            StageOutcome::Continue(ScreenCheckOutcome::SynCookieChallenge(challenge))
        }
    }
}

/// SYN-cookie returning ACK validation on the session-miss path.
///
/// This runs after normal session lookup has failed, so established ACK traffic
/// keeps its normal fast/session path. A valid cookie ACK is consumed without
/// creating a session; the caller turns the `Validated` outcome into a bounded
/// RST reply and the validated-client cache lets the client's next SYN traverse
/// the ordinary policy/NAT/session path. Invalid cookie ACKs are dropped while
/// cookie mode is active. Poll-stage coverage intentionally pins only the
/// operational drop/bypass behavior here; the lower screen runtime owns cache
/// mechanics. `screen_tests.rs` covers bounded 4-way replacement, explicit
/// cache expiration, and current/previous secret-epoch validation.
#[inline]
pub(super) fn stage_screen_syn_cookie_ack_on_session_miss(
    flow: Option<&SessionFlow>,
    packet_frame: &[u8],
    meta: UserspaceDpMeta,
    ingress_zone_override: Option<u16>,
    now_secs: u64,
    screen: &mut ScreenState,
    counters: &mut BatchCounters,
    worker_ctx: &WorkerContext,
) -> StageOutcome<SynCookieAckOutcome> {
    if !screen.has_profiles() {
        return StageOutcome::Continue(SynCookieAckOutcome::Pass);
    }
    let Some(flow) = flow else {
        return StageOutcome::Continue(SynCookieAckOutcome::Pass);
    };
    let zone_id = ingress_zone_override
        .filter(|id| worker_ctx.forwarding.zone_id_to_name.contains_key(id))
        .or_else(|| {
            worker_ctx
                .forwarding
                .ifindex_to_zone_id
                .get(&(meta.ingress_ifindex as i32))
                .copied()
        });
    let Some(zone_id) = zone_id else {
        return StageOutcome::Continue(SynCookieAckOutcome::Pass);
    };
    let Some(zone_name) = worker_ctx
        .forwarding
        .zone_id_to_name
        .get(&zone_id)
        .map(|s| s.as_str())
    else {
        return StageOutcome::Continue(SynCookieAckOutcome::Pass);
    };
    // See `stage_screen_check`: decide L3 offset on tag PRESENCE, not
    // VID > 0, so a priority-tagged VID-0 cookie ACK is parsed at the
    // correct offset (18) instead of mis-reading the tag bytes (#2145).
    let l3_off = if meta.ingress_vlan_present != 0 { 18 } else { 14 };
    let screen_pkt = extract_screen_info(
        packet_frame,
        meta.addr_family,
        meta.protocol,
        meta.tcp_flags,
        meta.pkt_len,
        flow.src_ip,
        flow.dst_ip,
        flow.forward_key.src_port,
        flow.forward_key.dst_port,
        l3_off,
    );
    match screen.validate_syn_cookie_ack_on_session_miss(zone_name, zone_id, &screen_pkt, now_secs)
    {
        SynCookieAckVerdict::NotApplicable => StageOutcome::Continue(SynCookieAckOutcome::Pass),
        SynCookieAckVerdict::Validated => {
            counters.touched = true;
            counters.syn_cookie_ack_valid += 1;
            StageOutcome::Continue(SynCookieAckOutcome::Validated)
        }
        SynCookieAckVerdict::Invalid => {
            emit_screen_drop_event(
                worker_ctx.event_stream,
                &screen_pkt,
                meta,
                zone_id,
                "syn-cookie",
                event_now_ns_from_secs(now_secs),
            );
            counters.touched = true;
            counters.screen_drops += 1;
            counters.syn_cookie_ack_invalid += 1;
            StageOutcome::RecycleAndContinue
        }
    }
}

/// Stage 11 — IPsec passthrough.
///
/// ESP (proto 50) and IKE (UDP 500/4500) must transit the kernel
/// XFRM subsystem. On a match, this stage builds a synthetic
/// `SessionDecision` with `LocalDelivery` disposition and
/// reinjects the packet via the slow-path TUN device, then signals
/// `RecycleAndContinue` so the caller drops the UMEM frame.
///
/// Non-IPsec packets fall through unchanged.
#[inline]
pub(super) fn stage_ipsec_passthrough_check(
    flow: Option<&SessionFlow>,
    packet_frame: &[u8],
    meta: UserspaceDpMeta,
    binding_live: &BindingLiveState,
    worker_ctx: &WorkerContext,
) -> StageOutcome<()> {
    let Some(flow) = flow else {
        return StageOutcome::Continue(());
    };
    if !is_ipsec_traffic(meta.protocol, flow.forward_key.dst_port) {
        return StageOutcome::Continue(());
    }
    let ipsec_decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::LocalDelivery,
            local_ifindex: 0,
            egress_ifindex: 0,
            tx_ifindex: 0,
            tunnel_endpoint_id: 0,
            next_hop: None,
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        },
        nat: NatDecision::default(),
    };
    maybe_reinject_slow_path_from_frame(
        &worker_ctx.ident,
        binding_live,
        worker_ctx.slow_path,
        worker_ctx.local_tunnel_deliveries,
        packet_frame,
        meta,
        ipsec_decision,
        worker_ctx.recent_exceptions,
        "slow_path",
        worker_ctx.forwarding,
    );
    StageOutcome::RecycleAndContinue
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_stream::DataplaneEventRateLimitConfig;
    use crate::event_stream::codec::DataplaneEventKind;
    use crate::test_zone_ids::TEST_LAN_ZONE_ID;

    const TEST_NOW_SECS: u64 = 128;
    const TCP_FLAG_ACK: u8 = 0x10;

    fn tcp_v4_frame(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        flags: u8,
        seq: u32,
        ack: u32,
    ) -> Vec<u8> {
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
            0,
            0x0800,
        );
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00,
        ]);
        frame.extend_from_slice(&src.octets());
        frame.extend_from_slice(&dst.octets());
        let ip_csum = checksum16(&frame[14..34]);
        frame[24..26].copy_from_slice(&ip_csum.to_be_bytes());
        frame.extend_from_slice(&src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&seq.to_be_bytes());
        frame.extend_from_slice(&ack.to_be_bytes());
        frame.extend_from_slice(&[0x50, flags, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00]);
        recompute_l4_checksum_ipv4(&mut frame[14..], 20, PROTO_TCP, false).expect("tcp checksum");
        frame
    }

    fn tcp_v4_meta(frame: &[u8], flags: u8) -> UserspaceDpMeta {
        UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            ingress_ifindex: 24,
            l3_offset: 14,
            l4_offset: 34,
            payload_offset: 54,
            pkt_len: (frame.len() - 14) as u16,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            tcp_flags: flags,
            ..UserspaceDpMeta::default()
        }
    }

    /// Build an IPv4 TCP SYN with the L2 header chosen by `vlan`:
    /// `Vlan::None` → 14-byte untagged header; `Vlan::PriorityTagged`
    /// → an 802.1p priority tag (TPID 0x8100, PCP 5, **VID 0**), so the
    /// L3 header starts at offset 18 while `ingress_vlan_id` is 0. The
    /// IPv4 header is built with `ihl` 32-bit words (5 = no options;
    /// 6 = one option word, which trips the `ip-source-route` screen).
    fn tcp_v4_syn_frame_with_l2(vlan: Vlan, ihl: u8) -> Vec<u8> {
        let mut frame = Vec::new();
        let dst_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let src_mac = [0x00, 0x25, 0x90, 0x12, 0x34, 0x56];
        frame.extend_from_slice(&dst_mac);
        frame.extend_from_slice(&src_mac);
        if let Vlan::PriorityTagged = vlan {
            // 802.1Q TPID + TCI. TCI = PCP(3) | DEI(1) | VID(12); here
            // PCP=5, DEI=0, VID=0 — the priority-tagged-VLAN-0 shape
            // that #2145 mis-parsed.
            frame.extend_from_slice(&0x8100u16.to_be_bytes());
            frame.extend_from_slice(&(0x5u16 << 13).to_be_bytes());
        }
        frame.extend_from_slice(&0x0800u16.to_be_bytes());
        let l3 = frame.len();
        let ihl_bytes = ihl as usize * 4;
        // IPv4 header: version/IHL, then the fixed 20-byte base header,
        // then `ihl_bytes - 20` NOP option bytes.
        frame.push(0x40 | ihl);
        frame.push(0x00);
        let total_len = (ihl_bytes + 20) as u16; // IP header + 20-byte TCP
        frame.extend_from_slice(&total_len.to_be_bytes());
        frame.extend_from_slice(&[0x00, 0x01, 0x40, 0x00, 64, PROTO_TCP, 0x00, 0x00]);
        frame.extend_from_slice(&Ipv4Addr::new(192, 0, 2, 10).octets());
        frame.extend_from_slice(&Ipv4Addr::new(198, 51, 100, 20).octets());
        // IPv4 options as NOP (0x01) to reach `ihl_bytes`.
        frame.resize(l3 + ihl_bytes, 0x01);
        let ip_csum = checksum16(&frame[l3..l3 + ihl_bytes]);
        frame[l3 + 10..l3 + 12].copy_from_slice(&ip_csum.to_be_bytes());
        // TCP SYN.
        let l4 = frame.len();
        frame.extend_from_slice(&49152u16.to_be_bytes());
        frame.extend_from_slice(&443u16.to_be_bytes());
        frame.extend_from_slice(&1u32.to_be_bytes()); // seq
        frame.extend_from_slice(&0u32.to_be_bytes()); // ack
        frame.extend_from_slice(&[0x50, TCP_FLAG_SYN, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00]);
        recompute_l4_checksum_ipv4(&mut frame[l3..], ihl_bytes, PROTO_TCP, false)
            .expect("tcp checksum");
        let _ = l4;
        frame
    }

    #[derive(Clone, Copy)]
    enum Vlan {
        None,
        PriorityTagged,
    }

    /// Metadata mirroring the shim contract for the frame built above:
    /// tagged frames carry `ingress_vlan_present = 1` with
    /// `ingress_vlan_id = 0` (priority tag) and `l3_offset = 18`;
    /// untagged frames carry `present = 0`, `l3_offset = 14`.
    fn tcp_v4_syn_meta_with_l2(frame: &[u8], vlan: Vlan) -> UserspaceDpMeta {
        let (l3, present): (u16, u8) = match vlan {
            Vlan::None => (14, 0),
            Vlan::PriorityTagged => (18, 1),
        };
        UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            ingress_ifindex: 24,
            ingress_vlan_id: 0,
            ingress_pcp: if present != 0 { 5 } else { 0 },
            ingress_vlan_present: present,
            l3_offset: l3,
            l4_offset: l3 + 20,
            payload_offset: l3 + 40,
            pkt_len: frame.len() as u16 - l3,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            tcp_flags: TCP_FLAG_SYN,
            ..UserspaceDpMeta::default()
        }
    }

    /// Screen state with only the IP source-route check armed. The
    /// check fires purely on `ip_ihl > 5` read from the frame at the
    /// computed L3 offset, so the verdict is a direct probe of whether
    /// the screen stage parsed the IP header at the right offset.
    fn source_route_screen() -> ScreenState {
        let mut profiles = FxHashMap::default();
        profiles.insert(
            "lan".to_string(),
            ScreenProfile {
                source_route: true,
                ..ScreenProfile::default()
            },
        );
        let mut screen = ScreenState::new();
        screen.update_profiles(profiles);
        screen
    }

    fn syn_cookie_screen() -> ScreenState {
        let mut profiles = FxHashMap::default();
        profiles.insert(
            "lan".to_string(),
            ScreenProfile {
                syn_flood_threshold: 1,
                syn_cookie: true,
                ..ScreenProfile::default()
            },
        );
        let mut screen = ScreenState::new();
        screen.update_profiles(profiles);
        screen.update_syn_cookie_master_key(Some([0x42; 16]));
        screen
    }

    #[test]
    fn session_miss_ack_stage_invokes_syn_cookie_runtime_validation() {
        let mut screen = syn_cookie_screen();
        let forwarding = build_forwarding_state(&super::super::test_fixtures::nat_snapshot());
        let ident = BindingIdentity {
            slot: 0,
            queue_id: 0,
            worker_id: 0,
            interface: Arc::<str>::from("reth1.0"),
            ifindex: 24,
        };
        let binding_lookup = WorkerBindingLookup::default();
        let mirror_targets = MirrorTargetMap::default();
        let ha_state = BTreeMap::new();
        let dynamic_neighbors = Arc::new(ShardedNeighborMap::default());
        let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
        let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
        let recent_exceptions = Arc::new(Mutex::new(VecDeque::new()));
        let last_resolution = Arc::new(Mutex::new(None));
        let peer_worker_commands = Vec::new();
        let dnat_fds = DnatTableFds::default();
        let rg_epochs = std::array::from_fn(|_| AtomicU32::new(0));
        let (event_handle, event_rx) = crate::event_stream::test_worker_handle(
            8,
            DataplaneEventRateLimitConfig {
                events_per_second: 0,
                burst: 0,
            },
        );
        let worker_ctx = WorkerContext {
            ident: &ident,
            binding_lookup: &binding_lookup,
            mirror_targets: &mirror_targets,
            forwarding: &forwarding,
            ha_state: &ha_state,
            dynamic_neighbors: &dynamic_neighbors,
            neighbor_resolver: None,
            shared_sessions: &shared_sessions,
            shared_nat_sessions: &shared_nat_sessions,
            shared_forward_wire_sessions: &shared_forward_wire_sessions,
            shared_owner_rg_indexes: &shared_owner_rg_indexes,
            slow_path: None,
            event_stream: Some(&event_handle),
            local_tunnel_deliveries: &local_tunnel_deliveries,
            recent_exceptions: &recent_exceptions,
            last_resolution: &last_resolution,
            peer_worker_commands: &peer_worker_commands,
            dnat_fds: &dnat_fds,
            rg_epochs: &rg_epochs,
        cold_path_sample_mask: 0xff,
        };

        let client = Ipv4Addr::new(192, 0, 2, 10);
        let server = Ipv4Addr::new(198, 51, 100, 20);
        let syn_frame = tcp_v4_frame(client, server, 49152, 443, TCP_FLAG_SYN, 1, 0);
        let syn_meta = tcp_v4_meta(&syn_frame, TCP_FLAG_SYN);
        let syn_flow =
            parse_session_flow_from_bytes(&syn_frame, syn_meta).expect("session flow from SYN");
        let syn_info = extract_screen_info(
            &syn_frame,
            syn_meta.addr_family,
            syn_meta.protocol,
            syn_meta.tcp_flags,
            syn_meta.pkt_len,
            syn_flow.src_ip,
            syn_flow.dst_ip,
            syn_flow.forward_key.src_port,
            syn_flow.forward_key.dst_port,
            syn_meta.l3_offset as usize,
        );

        assert_eq!(
            screen.check_packet_with_zone_id("lan", TEST_LAN_ZONE_ID, &syn_info, TEST_NOW_SECS),
            ScreenVerdict::Pass
        );
        let _challenge = match screen.check_packet_with_zone_id(
            "lan",
            TEST_LAN_ZONE_ID,
            &syn_info,
            TEST_NOW_SECS,
        ) {
            ScreenVerdict::SynCookieChallenge(challenge) => challenge,
            other => panic!("expected SYN-cookie challenge, got {other:?}"),
        };

        let invalid_ack_frame = tcp_v4_frame(
            client,
            server,
            49152,
            443,
            TCP_FLAG_ACK,
            2,
            0xdead_beef,
        );
        let invalid_ack_meta = tcp_v4_meta(&invalid_ack_frame, TCP_FLAG_ACK);
        let invalid_ack_flow =
            parse_session_flow_from_bytes(&invalid_ack_frame, invalid_ack_meta)
                .expect("session flow from invalid ACK");
        let mut invalid_counters = BatchCounters::default();

        assert!(matches!(
            stage_screen_syn_cookie_ack_on_session_miss(
                Some(&invalid_ack_flow),
                &invalid_ack_frame,
                invalid_ack_meta,
                None,
                TEST_NOW_SECS,
                &mut screen,
                &mut invalid_counters,
                &worker_ctx,
            ),
            StageOutcome::RecycleAndContinue
        ));
        assert!(
            invalid_counters.touched,
            "invalid cookie ACK must be counted as a screen drop"
        );
        assert_eq!(invalid_counters.screen_drops, 1);
        assert_eq!(invalid_counters.syn_cookie_ack_invalid, 1);
        let screen_event = event_rx
            .try_recv()
            .expect("screen-drop event")
            .decode_dataplane_event()
            .expect("screen-drop payload");
        assert_eq!(screen_event.kind, DataplaneEventKind::ScreenDrop);
        assert_eq!(screen_event.ingress_zone_id, TEST_LAN_ZONE_ID);
        assert_eq!(screen_event.ingress_ifindex, 24);
        assert_eq!(screen_event.screen_id, 1 << 14);
        assert_eq!(event_handle.dataplane_event_stats().screen_drop.sent, 1);

        let challenge = match screen.check_packet_with_zone_id(
            "lan",
            TEST_LAN_ZONE_ID,
            &syn_info,
            TEST_NOW_SECS,
        ) {
            ScreenVerdict::SynCookieChallenge(challenge) => challenge,
            other => panic!("invalid ACK must not install SYN-cookie bypass, got {other:?}"),
        };

        let ack_frame = tcp_v4_frame(
            client,
            server,
            49152,
            443,
            TCP_FLAG_ACK,
            2,
            challenge.cookie_isn.wrapping_add(1),
        );
        let ack_meta = tcp_v4_meta(&ack_frame, TCP_FLAG_ACK);
        let ack_flow =
            parse_session_flow_from_bytes(&ack_frame, ack_meta).expect("session flow from ACK");
        let mut counters = BatchCounters::default();

        assert!(matches!(
            stage_screen_syn_cookie_ack_on_session_miss(
                Some(&ack_flow),
                &ack_frame,
                ack_meta,
                None,
                TEST_NOW_SECS,
                &mut screen,
                &mut counters,
                &worker_ctx,
            ),
            StageOutcome::Continue(SynCookieAckOutcome::Validated)
        ));
        assert!(
            counters.touched,
            "valid cookie ACK must be counted without counting a screen drop"
        );
        assert_eq!(counters.screen_drops, 0);
        assert_eq!(counters.syn_cookie_ack_valid, 1);
        assert!(
            event_rx.try_recv().is_err(),
            "valid cookie ACK must not emit a screen-drop event"
        );

        assert_eq!(
            screen.check_packet_with_zone_id("lan", TEST_LAN_ZONE_ID, &syn_info, TEST_NOW_SECS),
            ScreenVerdict::SynCookieBypass,
            "poll-stage session-miss ACK handling must invoke SYN-cookie validation"
        );
        assert!(
            matches!(
                screen.check_packet_with_zone_id("lan", TEST_LAN_ZONE_ID, &syn_info, TEST_NOW_SECS),
                ScreenVerdict::SynCookieChallenge(_)
            ),
            "validated SYN-cookie bypass must be single-use"
        );
    }

    /// #2145 regression: a priority-tagged VLAN-0 SYN
    /// (`ingress_vlan_present = 1`, `ingress_vlan_id = 0`) must have its
    /// IP header parsed at offset 18 by the screen + SYN-cookie stages,
    /// not at the untagged offset 14. The screen carries an IPv4 header
    /// with IHL = 6, so the `ip-source-route` check fires *iff* the
    /// stage reads `ip_ihl` from the real header at offset 18. Pre-fix
    /// (`ingress_vlan_id > 0`) the stage used offset 14, read the
    /// 802.1Q TPID byte (0x81) as the IP header → `ip_ihl = 1`,
    /// source-route did NOT fire, and the SYN passed. An untagged
    /// control frame (with the same IHL-6 header at offset 14) keeps
    /// dropping, proving the assertion is not tautological.
    #[test]
    fn priority_tagged_vlan0_screen_stage_parses_l3_at_offset_18() {
        let forwarding = build_forwarding_state(&super::super::test_fixtures::nat_snapshot());
        let ident = BindingIdentity {
            slot: 0,
            queue_id: 0,
            worker_id: 0,
            interface: Arc::<str>::from("reth1.0"),
            ifindex: 24,
        };
        let binding_lookup = WorkerBindingLookup::default();
        let mirror_targets = MirrorTargetMap::default();
        let ha_state = BTreeMap::new();
        let dynamic_neighbors = Arc::new(ShardedNeighborMap::default());
        let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
        let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
        let recent_exceptions = Arc::new(Mutex::new(VecDeque::new()));
        let last_resolution = Arc::new(Mutex::new(None));
        let peer_worker_commands = Vec::new();
        let dnat_fds = DnatTableFds::default();
        let rg_epochs = std::array::from_fn(|_| AtomicU32::new(0));
        let (event_handle, _event_rx) = crate::event_stream::test_worker_handle(
            8,
            DataplaneEventRateLimitConfig {
                events_per_second: 0,
                burst: 0,
            },
        );
        let worker_ctx = WorkerContext {
            ident: &ident,
            binding_lookup: &binding_lookup,
            mirror_targets: &mirror_targets,
            forwarding: &forwarding,
            ha_state: &ha_state,
            dynamic_neighbors: &dynamic_neighbors,
            neighbor_resolver: None,
            shared_sessions: &shared_sessions,
            shared_nat_sessions: &shared_nat_sessions,
            shared_forward_wire_sessions: &shared_forward_wire_sessions,
            shared_owner_rg_indexes: &shared_owner_rg_indexes,
            slow_path: None,
            event_stream: Some(&event_handle),
            local_tunnel_deliveries: &local_tunnel_deliveries,
            recent_exceptions: &recent_exceptions,
            last_resolution: &last_resolution,
            peer_worker_commands: &peer_worker_commands,
            dnat_fds: &dnat_fds,
            rg_epochs: &rg_epochs,
            cold_path_sample_mask: 0xff,
        };

        // Run one SYN through stage_screen_check and return the verdict
        // (true = dropped) plus the screen_drops delta.
        let run_screen = |vlan: Vlan| -> bool {
            let mut screen = source_route_screen();
            let frame = tcp_v4_syn_frame_with_l2(vlan, 6);
            let meta = tcp_v4_syn_meta_with_l2(&frame, vlan);
            let flow =
                parse_session_flow_from_bytes(&frame, meta).expect("session flow from tagged SYN");
            let mut counters = BatchCounters::default();
            let outcome = stage_screen_check(
                Some(&flow),
                &frame,
                meta,
                None,
                TEST_NOW_SECS,
                &mut screen,
                &mut counters,
                &worker_ctx,
            );
            matches!(outcome, StageOutcome::RecycleAndContinue)
        };

        // Priority-tagged VID-0 frame: real IP header (IHL 6) sits at
        // offset 18. Post-fix the stage reads it and source-route fires.
        assert!(
            run_screen(Vlan::PriorityTagged),
            "priority-tagged VLAN-0 SYN with IHL=6 must be parsed at \
             offset 18 and dropped by ip-source-route (#2145)"
        );
        // Untagged control: same IHL-6 header at offset 14, still dropped.
        assert!(
            run_screen(Vlan::None),
            "untagged SYN with IHL=6 must still be parsed at offset 14 \
             and dropped by ip-source-route"
        );

        // The same offset bug lives in the SYN-cookie ACK stage. The
        // returning cookie ACK's TCP acknowledgement number is read
        // from the frame at l3_off + ihl*4 + 8; if l3_off is wrong, the
        // cookie ack is read from the wrong bytes and validation fails.
        // Drive a real challenge/validate cycle with priority-tagged
        // VID-0 frames (IHL 5, so the TCP ack sits at offset 18+20+8 =
        // 46). Post-fix the stage reads the correct cookie+1 and
        // returns Validated; pre-fix it read offset 14, parsed garbage,
        // and returned Invalid → RecycleAndContinue.
        let mut cookie_screen = syn_cookie_screen();
        let syn_frame = tcp_v4_syn_frame_with_l2(Vlan::PriorityTagged, 5);
        let syn_meta = tcp_v4_syn_meta_with_l2(&syn_frame, Vlan::PriorityTagged);
        let syn_flow = parse_session_flow_from_bytes(&syn_frame, syn_meta)
            .expect("session flow from tagged SYN");
        let syn_info = extract_screen_info(
            &syn_frame,
            syn_meta.addr_family,
            syn_meta.protocol,
            syn_meta.tcp_flags,
            syn_meta.pkt_len,
            syn_flow.src_ip,
            syn_flow.dst_ip,
            syn_flow.forward_key.src_port,
            syn_flow.forward_key.dst_port,
            syn_meta.l3_offset as usize,
        );
        // First SYN passes; second crosses the flood threshold and
        // mints the cookie challenge (mirrors the SYN-cookie test).
        assert_eq!(
            cookie_screen.check_packet_with_zone_id(
                "lan",
                TEST_LAN_ZONE_ID,
                &syn_info,
                TEST_NOW_SECS
            ),
            ScreenVerdict::Pass
        );
        let challenge = match cookie_screen.check_packet_with_zone_id(
            "lan",
            TEST_LAN_ZONE_ID,
            &syn_info,
            TEST_NOW_SECS,
        ) {
            ScreenVerdict::SynCookieChallenge(challenge) => challenge,
            other => panic!("expected SYN-cookie challenge, got {other:?}"),
        };

        // Returning ACK: priority-tagged VID-0, ack = cookie + 1, with
        // the TCP ack field written at the correct offset-18 layout.
        let ack_frame = {
            let mut f = tcp_v4_syn_frame_with_l2(Vlan::PriorityTagged, 5);
            // l3=18, ihl=20 → TCP at 38, flags byte at 38+13=51, ack
            // field at 38+8=46.
            f[51] = TCP_FLAG_ACK;
            f[46..50].copy_from_slice(&challenge.cookie_isn.wrapping_add(1).to_be_bytes());
            recompute_l4_checksum_ipv4(&mut f[18..], 20, PROTO_TCP, false)
                .expect("tcp checksum");
            f
        };
        let ack_meta = tcp_v4_syn_meta_with_l2(&ack_frame, Vlan::PriorityTagged);
        // The shim contract reports the real protocol/flags; flip the
        // meta's TCP flag to ACK so the stage routes this as a returning
        // ACK (the meta tcp_flags field is set by the parser, not read
        // from the frame's l3 offset).
        let ack_meta = UserspaceDpMeta {
            tcp_flags: TCP_FLAG_ACK,
            ..ack_meta
        };
        let ack_flow = parse_session_flow_from_bytes(&ack_frame, ack_meta)
            .expect("session flow from tagged ACK");
        let mut counters = BatchCounters::default();
        assert!(
            matches!(
                stage_screen_syn_cookie_ack_on_session_miss(
                    Some(&ack_flow),
                    &ack_frame,
                    ack_meta,
                    None,
                    TEST_NOW_SECS,
                    &mut cookie_screen,
                    &mut counters,
                    &worker_ctx,
                ),
                StageOutcome::Continue(SynCookieAckOutcome::Validated)
            ),
            "priority-tagged VLAN-0 cookie ACK must be parsed at offset \
             18 by the SYN-cookie stage so its TCP ack matches cookie+1 \
             (#2145); pre-fix it read offset 14 and rejected the cookie"
        );
        assert_eq!(
            counters.syn_cookie_ack_valid, 1,
            "the tagged cookie ACK must validate exactly once"
        );
    }
}
