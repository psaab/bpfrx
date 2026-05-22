use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use ipnet::IpNet;
use rustc_hash::FxHashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use zeroize::{Zeroize, Zeroizing};

use super::packet;
use super::prefix_map::PrefixMap;
use crate::afxdp::frame::{frame_l3_offset, write_eth_header_slice};
use crate::afxdp::neighbor::monotonic_nanos;
use crate::afxdp::{UserspaceDpMeta, USERSPACE_META_MAGIC, USERSPACE_META_VERSION};

const WG_RECEIVER_INDEX_MASK: u32 = 0x00FF_FFFF;
const WG_TRIAL_DECAP_BUDGET: u32 = 32;
const WG_TOKEN_REFILL_NS: u64 = 1_000_000;

pub(crate) struct WireGuardDecapResult {
    pub decap_len: usize,
    pub meta: UserspaceDpMeta,
    pub control_frame: Option<Vec<u8>>,
    pub is_control: bool,
}

pub(crate) enum WireGuardDecapOutcome {
    Decapped(WireGuardDecapResult),
    None,
}

enum TunnPhase2 {
    Control(WireGuardDecapResult),
    InnerData {
        inner_pkt_len: usize,
        inner_family: u8,
        inner_meta: UserspaceDpMeta,
    },
}

fn complete_tunn_phase2(
    frame: &mut [u8],
    phase2: TunnPhase2,
    scratch: &[u8],
) -> WireGuardDecapOutcome {
    match phase2 {
        TunnPhase2::Control(r) => WireGuardDecapOutcome::Decapped(r),
        TunnPhase2::InnerData {
            inner_pkt_len,
            inner_family,
            inner_meta,
        } => {
            let inner_packet = &scratch[..inner_pkt_len];
            let total_inner = 14 + inner_packet.len();
            if total_inner > frame.len() {
                return WireGuardDecapOutcome::None;
            }
            frame[..6].copy_from_slice(&[0x02, 0xbf, 0x72, 0x00, 0x00, 0x01]);
            frame[6..12].copy_from_slice(&[0x02, 0xbf, 0x72, 0x00, 0x00, 0x02]);
            let eth_type: u16 = if inner_family == libc::AF_INET as u8 {
                0x0800
            } else {
                0x86dd
            };
            frame[12..14].copy_from_slice(&eth_type.to_be_bytes());
            frame[14..total_inner].copy_from_slice(inner_packet);
            WireGuardDecapOutcome::Decapped(WireGuardDecapResult {
                decap_len: total_inner,
                meta: inner_meta,
                control_frame: None,
                is_control: false,
            })
        }
    }
}

struct PeerState {
    tunn: Tunn,
    endpoint: Option<(IpAddr, u16)>,
    local_ip: Option<IpAddr>,
    receiver_index: u32,
}

pub(crate) struct WireGuardEngine {
    peers: FxHashMap<[u8; 32], PeerState>,
    endpoint_to_peer: FxHashMap<(IpAddr, u16), [u8; 32]>,
    index_to_peer: FxHashMap<u32, [u8; 32]>,
    allowed_ip_to_peer: PrefixMap<[u8; 32]>,
    listen_port: u16,
    static_private: Option<Zeroizing<[u8; 32]>>,
    next_index: u32,
    virtual_ifindex: Option<u32>,
    decap_budget: u32,
    last_budget_refill_ns: u64,
    rr_cursor: usize,
}

impl WireGuardEngine {
    pub(crate) fn new() -> Self {
        Self {
            peers: FxHashMap::default(),
            endpoint_to_peer: FxHashMap::default(),
            index_to_peer: FxHashMap::default(),
            allowed_ip_to_peer: PrefixMap::new(),
            listen_port: 0,
            static_private: None,
            next_index: 1,
            virtual_ifindex: None,
            decap_budget: WG_TRIAL_DECAP_BUDGET,
            last_budget_refill_ns: 0,
            rr_cursor: 0,
        }
    }

    fn allocate_receiver_index(&mut self) -> u32 {
        // NOTE: wraps after 16M peers (WG_RECEIVER_INDEX_MASK).
        // No collision check against index_to_peer — a wrap collision
        // would require 16M concurrent peers, which is beyond any
        // practical deployment. If the daemon stays up long enough to
        // exhaust the space, a stale peer would briefly register a
        // duplicate index; boringtun rejects invalid messages silently,
        // so the window is self-healing on the next handshake.
        let idx = self.next_index;
        self.next_index = self.next_index.wrapping_add(1) & WG_RECEIVER_INDEX_MASK;
        if self.next_index == 0 {
            self.next_index = 1;
        }
        idx.max(1)
    }

    fn acquire_decap_budget(&mut self, now_ns: u64) -> bool {
        let elapsed = now_ns.saturating_sub(self.last_budget_refill_ns);
        if elapsed >= WG_TOKEN_REFILL_NS {
            let tokens = (elapsed / WG_TOKEN_REFILL_NS) as u32;
            self.decap_budget = (self.decap_budget + tokens).min(WG_TRIAL_DECAP_BUDGET);
            self.last_budget_refill_ns = now_ns;
        }
        if self.decap_budget > 0 {
            self.decap_budget -= 1;
            true
        } else {
            false
        }
    }

    pub(crate) fn try_decap(
        &mut self,
        frame: &mut [u8],
        meta: &UserspaceDpMeta,
        scratch: &mut Vec<u8>,
    ) -> WireGuardDecapOutcome {
        if meta.protocol != packet::PROTO_UDP || meta.flow_dst_port != self.listen_port {
            return WireGuardDecapOutcome::None;
        }

        let payload_offset = meta.payload_offset as usize;
        if payload_offset >= frame.len() {
            return WireGuardDecapOutcome::None;
        }
        let outer_payload = &frame[payload_offset..];

        if outer_payload.len() < 4 {
            return WireGuardDecapOutcome::None;
        }

        let msg_type = outer_payload[0];
        let peer_ip = packet::src_ip_from_meta(meta);
        let local_ip = packet::dst_ip_from_meta(meta);
        let endpoint_port = meta.flow_src_port;

        match msg_type {
            1 => {
                if outer_payload.len() < 148 {
                    return WireGuardDecapOutcome::None;
                }
                let phase2 = self.handle_handshake_initiation(meta, outer_payload, peer_ip, local_ip, endpoint_port, scratch);
                match phase2 {
                    Some(p2) => complete_tunn_phase2(frame, p2, scratch),
                    None => WireGuardDecapOutcome::None,
                }
            }
            2 | 3 | 4 => {
                // WireGuard wire format uses little-endian u32 fields.
                // For msg types 3 (cookie reply) and 4 (transport data),
                // the receiver index is at bytes 4..8. For type 2
                // (handshake response), bytes 4..8 are the SENDER index
                // and the receiver index is at bytes 8..12.
                let receiver_idx = if msg_type == 2 {
                    if outer_payload.len() < 12 {
                        return WireGuardDecapOutcome::None;
                    }
                    u32::from_le_bytes([
                        outer_payload[8],
                        outer_payload[9],
                        outer_payload[10],
                        outer_payload[11],
                    ])
                } else {
                    if outer_payload.len() < 8 {
                        return WireGuardDecapOutcome::None;
                    }
                    u32::from_le_bytes([
                        outer_payload[4],
                        outer_payload[5],
                        outer_payload[6],
                        outer_payload[7],
                    ])
                };
                let phase2 = self.handle_other_message(meta, outer_payload, msg_type, receiver_idx, peer_ip, local_ip, endpoint_port, scratch);
                match phase2 {
                    Some(p2) => complete_tunn_phase2(frame, p2, scratch),
                    None => WireGuardDecapOutcome::None,
                }
            }
            _ => WireGuardDecapOutcome::None,
        }
    }

    fn handle_handshake_initiation(
        &mut self,
        meta: &UserspaceDpMeta,
        outer_payload: &[u8],
        peer_ip: IpAddr,
        local_ip: IpAddr,
        endpoint_port: u16,
        scratch: &mut Vec<u8>,
    ) -> Option<TunnPhase2> {
        let endpoint_key = (peer_ip, endpoint_port);

        if let Some(pk) = self.endpoint_to_peer.get(&endpoint_key).copied() {
            if let Some(p2) = self.process_tunn_result(
                meta, &pk, outer_payload, 1, peer_ip, local_ip, endpoint_port, scratch,
            ) {
                return Some(p2);
            }
        }

        let now_ns = monotonic_nanos();
        if !self.acquire_decap_budget(now_ns) {
            return None;
        }

        let peer_keys: Vec<[u8; 32]> = self.peers.keys().copied().collect();
        if peer_keys.is_empty() {
            return None;
        }

        let start = self.rr_cursor % peer_keys.len();
        for i in 0..peer_keys.len().min(WG_TRIAL_DECAP_BUDGET as usize) {
            let idx = (start + i) % peer_keys.len();
            let pk = &peer_keys[idx];
            if let Some(p2) = self.process_tunn_result(
                meta, pk, outer_payload, 1, peer_ip, local_ip, endpoint_port, scratch,
            ) {
                self.rr_cursor = (idx + 1) % peer_keys.len();
                return Some(p2);
            }
        }

        None
    }

    fn handle_other_message(
        &mut self,
        meta: &UserspaceDpMeta,
        outer_payload: &[u8],
        _msg_type_val: u8,
        receiver_idx: u32,
        peer_ip: IpAddr,
        local_ip: IpAddr,
        endpoint_port: u16,
        scratch: &mut Vec<u8>,
    ) -> Option<TunnPhase2> {
        // boringtun internally shifts the receiver index left by 8
        // (id << 8 in Tunn::new), then uses the low 8 bits as a
        // cyclic session counter.  The wire-format receiver index
        // therefore has the peer identifier in bits 31..8 and the
        // session counter in bits 7..0.  Shift right by 8 to recover
        // the peer identifier for our index_to_peer lookup.
        let lookup_key = receiver_idx >> 8;
        let pk = self
            .index_to_peer
            .get(&lookup_key)
            .copied()
            .or_else(|| {
                let ek = (peer_ip, endpoint_port);
                self.endpoint_to_peer.get(&ek).copied()
            });

        let pk = pk?;

        self.process_tunn_result(meta, &pk, outer_payload, _msg_type_val, peer_ip, local_ip, endpoint_port, scratch)
    }

    fn process_tunn_result(
        &mut self,
        meta: &UserspaceDpMeta,
        peer_key: &[u8; 32],
        outer_payload: &[u8],
        _msg_type_val: u8,
        peer_ip: IpAddr,
        local_ip: IpAddr,
        endpoint_port: u16,
        scratch: &mut Vec<u8>,
    ) -> Option<TunnPhase2> {
        let peer = self.peers.get_mut(peer_key)?;

        let wg_result = {
            if scratch.len() < 65535 {
                scratch.resize(65535, 0);
            }
            peer.tunn.decapsulate(None, outer_payload, &mut scratch[..])
        };

        let update_endpoint = |this: &mut Self, ep: (IpAddr, u16), pk: &[u8; 32]| {
            match this.peers.get_mut(pk) {
                Some(ps) if ps.endpoint != Some(ep) => {
                    if let Some(old) = ps.endpoint {
                        this.endpoint_to_peer.remove(&old);
                    }
                    this.endpoint_to_peer.insert(ep, *pk);
                    ps.endpoint = Some(ep);
                }
                _ => {}
            }
        };

        match wg_result {
            TunnResult::Err(_) => None,
            TunnResult::Done => {
                update_endpoint(self, (peer_ip, endpoint_port), peer_key);
                None
            }
            TunnResult::WriteToNetwork(p) => {
                update_endpoint(self, (peer_ip, endpoint_port), peer_key);
                let is_handshake_response =
                    p.first().copied() == Some(2) || p.first().copied() == Some(3);

                if is_handshake_response {
                    let vlan_id = meta.ingress_vlan_id;
                    let outer_eth_len = if vlan_id > 0 { 18 } else { 14 };
                    let outer_ip_len = if local_ip.is_ipv4() { 20 } else { 40 };
                    let header_len = outer_eth_len + outer_ip_len + 8;
                    let total_len = header_len + p.len();

                    let mut control_frame = vec![0u8; total_len];
                    control_frame[header_len..total_len].copy_from_slice(p);

                    let dst_mac = [0x02, 0xbf, 0x72, 0x00, 0x00, 0x01];
                    let src_mac = [0x02, 0xbf, 0x72, 0x00, 0x00, 0x02];
                    let eth_type = if local_ip.is_ipv4() { 0x0800 } else { 0x86dd };

                    write_eth_header_slice(
                        &mut control_frame[..outer_eth_len],
                        dst_mac, src_mac, vlan_id, eth_type,
                    )?;

                    let inner_dscp = 0;
                    let mut outer_meta = packet::build_outer_headers(
                        &mut control_frame, outer_eth_len, local_ip, peer_ip,
                        self.listen_port, endpoint_port, p.len(), inner_dscp, p,
                    )?;
                    outer_meta.ingress_ifindex = meta.ingress_ifindex;
                    outer_meta.ingress_vlan_id = vlan_id;

                    Some(TunnPhase2::Control(WireGuardDecapResult {
                        decap_len: total_len,
                        meta: outer_meta,
                        control_frame: Some(control_frame),
                        is_control: true,
                    }))
                } else {
                    None
                }
            }
            TunnResult::WriteToTunnelV4(p, _) | TunnResult::WriteToTunnelV6(p, _) => {
                update_endpoint(self, (peer_ip, endpoint_port), peer_key);

                let inner_family = if p.first().copied().map(|v| v >> 4) == Some(4) {
                    libc::AF_INET as u8
                } else {
                    libc::AF_INET6 as u8
                };

                let inner_pkt_len = packet::packet_trimmed_len(p, inner_family)?;
                let inner_packet = &p[..inner_pkt_len];

                let (protocol, rel_l4_offset, payload_offset) =
                    packet::parse_inner_protocol_and_offsets(inner_packet, inner_family)?;

                let mut flow_src_addr = [0u8; 16];
                let mut flow_dst_addr = [0u8; 16];

                // AllowedIPs inbound enforcement (WireGuard cryptokey routing):
                // The inner source IP must fall within the allowed-IPs set
                // configured for this peer.  Drop packets whose source is not
                // covered — prevents an authenticated peer from injecting traffic
                // with an arbitrary source into the trusted zone.
                let inner_src_ip: IpAddr;
                if inner_family == libc::AF_INET as u8 {
                    if inner_packet.len() < 20 {
                        return None;
                    }
                    let src = Ipv4Addr::new(
                        inner_packet[12], inner_packet[13], inner_packet[14], inner_packet[15],
                    );
                    let dst = Ipv4Addr::new(
                        inner_packet[16], inner_packet[17], inner_packet[18], inner_packet[19],
                    );
                    inner_src_ip = IpAddr::V4(src);
                    flow_src_addr[..4].copy_from_slice(&src.octets());
                    flow_dst_addr[..4].copy_from_slice(&dst.octets());
                } else {
                    if inner_packet.len() < 40 {
                        return None;
                    }
                    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&inner_packet[8..24]).ok()?);
                    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&inner_packet[24..40]).ok()?);
                    inner_src_ip = IpAddr::V6(src);
                    flow_src_addr.copy_from_slice(&src.octets());
                    flow_dst_addr.copy_from_slice(&dst.octets());
                }

                if !self.allowed_ip_to_peer
                    .longest_match(inner_src_ip)
                    .is_some_and(|k| k == peer_key) {
                    return None;
                }

                let inner_meta = UserspaceDpMeta {
                    magic: USERSPACE_META_MAGIC,
                    version: USERSPACE_META_VERSION,
                    length: std::mem::size_of::<UserspaceDpMeta>() as u16,
                    ingress_ifindex: self.virtual_ifindex.unwrap_or(meta.ingress_ifindex),
                    rx_queue_index: meta.rx_queue_index,
                    ingress_vlan_id: 0,
                    ingress_zone: 0,
                    l3_offset: 14,
                    l4_offset: 14 + rel_l4_offset,
                    payload_offset: 14 + payload_offset,
                    pkt_len: inner_packet.len() as u16,
                    addr_family: inner_family,
                    protocol,
                    tcp_flags: packet::packet_tcp_flags(inner_packet, inner_family, protocol, rel_l4_offset),
                    flow_src_port: 0,
                    flow_dst_port: 0,
                    flow_src_addr,
                    flow_dst_addr,
                    config_generation: meta.config_generation,
                    fib_generation: meta.fib_generation,
                    ..UserspaceDpMeta::default()
                };

                Some(TunnPhase2::InnerData {
                    inner_pkt_len,
                    inner_family,
                    inner_meta,
                })
            }
        }
    }

    pub(crate) fn try_encap(
        &mut self,
        inner_frame: &[u8],
        addr_family: u8,
        ingress_ifindex: u32,
        vlan_id: u16,
        preferred_local_ip: Option<IpAddr>,
        meta_dscp: u8,
    ) -> Option<(Vec<u8>, UserspaceDpMeta)> {
        let inner_l3 = frame_l3_offset(inner_frame)?;

        let inner_ip = inner_frame.get(inner_l3..)?;
        let trimmed_len = packet::packet_trimmed_len(inner_ip, addr_family)?;
        let inner_ip_packet = &inner_ip[..trimmed_len];

        let inner_dst = match addr_family as i32 {
            libc::AF_INET => {
                if inner_ip_packet.len() < 20 {
                    return None;
                }
                IpAddr::V4(Ipv4Addr::new(
                    inner_ip_packet[16], inner_ip_packet[17], inner_ip_packet[18], inner_ip_packet[19],
                ))
            }
            libc::AF_INET6 => {
                if inner_ip_packet.len() < 40 {
                    return None;
                }
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&inner_ip_packet[24..40]).ok()?))
            }
            _ => return None,
        };

        let peer_key = self.allowed_ip_to_peer.longest_match(inner_dst)?.clone();
        let peer = self.peers.get_mut(&peer_key)?;

        let (outer_dst_ip, outer_dst_port) = peer.endpoint?;

        let outer_ip_len = if outer_dst_ip.is_ipv4() { 20 } else { 40 };
        let outer_eth_len = if vlan_id > 0 { 18 } else { 14 };
        let header_len = outer_eth_len + outer_ip_len + 8;

        let trimmed = trimmed_len + 512;
        let total = outer_eth_len + outer_ip_len + 8 + trimmed;
        let mut frame = vec![0u8; total];

        let (header_area, wg_area) = frame.split_at_mut(header_len);

        let result = peer.tunn.encapsulate(inner_ip_packet, wg_area);

        match result {
            TunnResult::WriteToNetwork(wg_payload) => {
                let total_payload_len = wg_payload.len();
                let total_len = outer_eth_len + outer_ip_len + 8 + total_payload_len;

                let outer_ip_start = outer_eth_len;

                let src_ip = preferred_local_ip.unwrap_or_else(|| match outer_dst_ip {
                    IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                });

                let dst_mac = [0x02, 0xbf, 0x72, 0x00, 0x00, 0x01];
                let src_mac = [0x02, 0xbf, 0x72, 0x00, 0x00, 0x02];
                let eth_type = if outer_dst_ip.is_ipv4() { 0x0800 } else { 0x86dd };

                write_eth_header_slice(
                    &mut header_area[..outer_eth_len],
                    dst_mac,
                    src_mac,
                    vlan_id,
                    eth_type,
                )?;

                let mut outer_meta = packet::build_outer_headers(
                    header_area,
                    outer_ip_start,
                    src_ip,
                    outer_dst_ip,
                    self.listen_port,
                    outer_dst_port,
                    total_payload_len,
                    meta_dscp,   // full TOS/TC byte (DSCP + ECN) from caller
                    wg_payload,
                )?;

                outer_meta.ingress_ifindex = ingress_ifindex;
                outer_meta.pkt_len = u16::try_from(outer_ip_len + 8 + total_payload_len).ok()?;

                frame.truncate(total_len);
                Some((frame, outer_meta))
            }
            _ => None,
        }
    }

    pub(crate) fn apply_snapshot(
        &mut self,
        private_key_b64: &str,
        public_key_b64: &str,
        listen_port: u16,
        peers: &[WireGuardPeerSnapshot],
        virtual_ifindex: Option<u32>,
    ) {
        self.listen_port = listen_port;
        self.virtual_ifindex = virtual_ifindex;

        let private_key = {
            if private_key_b64.is_empty() || private_key_b64.chars().all(|c| c == '0') {
                None
            } else {
                match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, private_key_b64) {
                    Ok(mut key_bytes) if key_bytes.len() == 32 => {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&key_bytes);
                        key_bytes.zeroize();
                        Some(Zeroizing::new(arr))
                    }
                    _ => {
                        let all_zero = [0u8; 32];
                        let z = Zeroizing::new(all_zero);
                        self.peers.clear();
                        self.endpoint_to_peer.clear();
                        self.index_to_peer.clear();
                        self.allowed_ip_to_peer = PrefixMap::new();
                        self.static_private = Some(z);
                        return;
                    }
                }
            }
        };

        let key_changed = match (&self.static_private, &private_key) {
            (Some(old), Some(new)) => **old != **new,
            (None, Some(_)) | (Some(_), None) => true,
            (None, None) => false,
        };

        if key_changed || private_key.is_some() {
            self.static_private = private_key;
        }

        // Key removal (transition from Some to None): clear all peer
        // state.  Existing Tunn objects were created with the old
        // static_secret and cannot be reused without a valid key.
        if self.static_private.is_none() {
            self.peers.clear();
            self.endpoint_to_peer.clear();
            self.index_to_peer.clear();
            self.allowed_ip_to_peer = PrefixMap::new();
            return;
        }

        // When the private key changes, all existing Tunn objects must be
        // recreated — each Tunn embeds the static_secret at construction
        // time and does not update it on key rotation. Retaining stale
        // Tunn objects means old sessions remain valid, which violates
        // the WireGuard key-compromise property (old key material should
        // be unusable after rotation).
        let force_tunn_rebuild = key_changed;

        let mut new_peers: FxHashMap<[u8; 32], PeerState> = FxHashMap::default();
        let mut new_endpoint_to_peer: FxHashMap<(IpAddr, u16), [u8; 32]> = FxHashMap::default();
        let mut new_index_to_peer: FxHashMap<u32, [u8; 32]> = FxHashMap::default();
        let mut new_allowed_ip_to_peer: PrefixMap<[u8; 32]> = PrefixMap::new();

        for peer_snap in peers {
            let pub_key_bytes = match base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                &peer_snap.public_key,
            ) {
                Ok(bytes) if bytes.len() == 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    arr
                }
                _ => continue,
            };

            let endpoint = packet::parse_endpoint(&peer_snap.endpoint);

            let peer_state = if let Some(existing) = self.peers.remove(&pub_key_bytes) {
                if force_tunn_rebuild {
                    let Some(ref static_private) = self.static_private else {
                        continue;
                    };
                    let static_secret = StaticSecret::from(**static_private);
                    let public_key = PublicKey::from(pub_key_bytes);
                    let Ok(tunn) = Tunn::new(static_secret, public_key, None, None, existing.receiver_index, None) else { continue; };
                    PeerState {
                        tunn,
                        endpoint: endpoint.or(existing.endpoint),
                        local_ip: existing.local_ip,
                        receiver_index: existing.receiver_index,
                    }
                } else {
                    PeerState {
                        tunn: existing.tunn,
                        endpoint: endpoint.or(existing.endpoint),
                        local_ip: existing.local_ip,
                        receiver_index: existing.receiver_index,
                    }
                }
            } else {
                let Some(ref static_private) = self.static_private else {
                    continue;
                };
                let static_secret = StaticSecret::from(**static_private);
                let public_key = PublicKey::from(pub_key_bytes);
                let receiver_index = self.allocate_receiver_index();
                let Ok(tunn) = Tunn::new(static_secret, public_key, None, None, receiver_index, None) else { continue; };
                PeerState {
                    tunn,
                    endpoint,
                    local_ip: None,
                    receiver_index,
                }
            };

            let pk_key = pub_key_bytes;
            if let Some(ep) = peer_state.endpoint {
                new_endpoint_to_peer.insert(ep, pk_key);
            }
            new_index_to_peer.insert(peer_state.receiver_index, pk_key);

            for allowed_ip_str in &peer_snap.allowed_ips {
                if let Ok(net) = allowed_ip_str.parse::<IpNet>() {
                    new_allowed_ip_to_peer.insert(net, pk_key);
                }
            }

            new_peers.insert(pk_key, peer_state);
        }

        self.peers = new_peers;
        self.endpoint_to_peer = new_endpoint_to_peer;
        self.index_to_peer = new_index_to_peer;
        self.allowed_ip_to_peer = new_allowed_ip_to_peer;
    }
}

#[derive(Clone, Debug)]
pub(crate) struct WireGuardPeerSnapshot {
    pub public_key: String,
    pub endpoint: String,
    pub allowed_ips: Vec<String>,
    pub persistent_keepalive: u32,
}
