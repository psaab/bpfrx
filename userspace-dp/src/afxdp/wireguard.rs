use super::*;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{StaticSecret, PublicKey};
use rustc_hash::FxHashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

const RECEIVER_INDEX_MASK: u32 = 0x00FF_FFFF;

pub(super) struct WireGuardEngine {
    // Peers indexed by their public key, only peers owned by THIS worker
    peers: FxHashMap<[u8; 32], PeerState>,
    // Mapping from outer (encrypted) flow to peer
    endpoint_to_peer: FxHashMap<(IpAddr, u16), [u8; 32]>,
    // Mapping from local receiver index back to peer public key
    index_to_peer: FxHashMap<u32, [u8; 32]>,
    // Mapping from inner destination IP to peer (allowed-ips) via LPM trie
    allowed_ip_to_peer: PrefixMap<[u8; 32]>,
    // Local listen port for this interface
    listen_port: u16,
    // Raw representation of local private key (to check for rotation)
    static_private_raw: Option<[u8; 32]>,
    // Cyclic/monotonically increasing local index generator for unique receiver keys
    next_local_index: u32,
    // Token-bucket rate limiter for trial-decapsulations (DoS prevention)
    trial_decap_tokens: u32,
    last_token_refill_ns: u64,
}

struct PeerState {
    tunn: Tunn,
    endpoint: Option<(IpAddr, u16)>,
    local_ip: Option<IpAddr>,
    local_index: u32,
}

pub(super) struct WireGuardDecapResult {
    pub decapsulated_len: usize,
    pub meta: UserspaceDpMeta,
    pub is_control: bool,
    pub control_frame: Option<Vec<u8>>,
}

pub(super) enum WireGuardDecapOutcome {
    Decapped(WireGuardDecapResult),
    DispatchToWorker(u32),
    None,
}

impl WireGuardEngine {
    pub(super) fn new() -> Self {
        Self {
            peers: FxHashMap::default(),
            endpoint_to_peer: FxHashMap::default(),
            index_to_peer: FxHashMap::default(),
            allowed_ip_to_peer: PrefixMap::new(),
            listen_port: 0,
            static_private_raw: None,
            next_local_index: 0,
            trial_decap_tokens: 32,
            last_token_refill_ns: 0,
        }
    }

    fn acquire_trial_decap_token(&mut self, now_ns: u64) -> bool {
        let elapsed = now_ns.saturating_sub(self.last_token_refill_ns);
        if elapsed >= 1_000_000 {
            let tokens_to_add = (elapsed / 1_000_000) as u32;
            self.trial_decap_tokens = std::cmp::min(32, self.trial_decap_tokens + tokens_to_add);
            self.last_token_refill_ns = now_ns;
        }
        if self.trial_decap_tokens > 0 {
            self.trial_decap_tokens -= 1;
            true
        } else {
            false
        }
    }

    fn encode_receiver_index(&self, local_index: u32) -> u32 {
        local_index & RECEIVER_INDEX_MASK
    }

    pub(super) fn try_decap(&mut self, raw_frame_mut: &mut [u8], meta: &UserspaceDpMeta, scratch_wg_in: &mut Vec<u8>) -> WireGuardDecapOutcome {
        if meta.protocol != 17 || meta.flow_dst_port != self.listen_port {
            return WireGuardDecapOutcome::None;
        }
        
        let outer_payload = match raw_frame_mut.get(meta.payload_offset as usize..) {
            Some(p) => p,
            None => return WireGuardDecapOutcome::None,
        };
        
        if outer_payload.len() < 4 {
            return WireGuardDecapOutcome::None;
        }

        let msg_type = outer_payload[0];
        let endpoint_ip = meta.src_ip();
        let endpoint_port = meta.flow_src_port;

        let mut roamed_key = None;
        let mut cached_result = None;

        let peer = if msg_type == 1 {
            if outer_payload.len() < 148 {
                return WireGuardDecapOutcome::None;
            }
            
            let mut tried_key = None;
            let mut found_peer_key = None;

            // 1. Try decapsulation with the mapped peer first
            if let Some(key) = self.endpoint_to_peer.get(&(endpoint_ip, endpoint_port)) {
                tried_key = Some(*key);
                if let Some(peer_state) = self.peers.get_mut(key) {
                    scratch_wg_in.resize(outer_payload.len(), 0);
                    let res = peer_state.tunn.decapsulate(Some(endpoint_ip), outer_payload, scratch_wg_in);
                    if matches!(&res, TunnResult::WriteToNetwork(_)) {
                        found_peer_key = Some(*key);
                        let res_static: TunnResult<'static> = unsafe { std::mem::transmute(res) };
                        cached_result = Some(res_static);
                    }
                }
            }

            // 2. If decapsulation failed or no mapped peer, try other active peers with rate-limiting
            if found_peer_key.is_none() {
                let now_ns = super::neighbor::monotonic_nanos();
                if !self.acquire_trial_decap_token(now_ns) {
                    return WireGuardDecapOutcome::None;
                }

                scratch_wg_in.resize(outer_payload.len(), 0);
                // Safety: transmute scratch_wg_in's slice to bypass borrow checker
                let scratch_slice: &'static mut [u8] = unsafe {
                    std::mem::transmute(scratch_wg_in.as_mut_slice())
                };

                for (key, peer_state) in &mut self.peers {
                    if Some(*key) == tried_key {
                        continue;
                    }
                    let res = peer_state.tunn.decapsulate(Some(endpoint_ip), outer_payload, scratch_slice);
                    if matches!(&res, TunnResult::WriteToNetwork(_)) {
                        found_peer_key = Some(*key);
                        let res_static: TunnResult<'static> = unsafe { std::mem::transmute(res) };
                        cached_result = Some(res_static);
                        break;
                    }
                }
            }

            if let Some(key) = found_peer_key {
                roamed_key = Some(key);
                self.peers.get_mut(&key)
            } else {
                None
            }
        } else if msg_type == 4 || msg_type == 2 || msg_type == 3 {
            if outer_payload.len() < 8 {
                None
            } else {
                let mut idx_bytes = [0u8; 4];
                idx_bytes.copy_from_slice(&outer_payload[4..8]);
                let receiver_index = u32::from_le_bytes(idx_bytes);
                let local_index = (receiver_index >> 8) & RECEIVER_INDEX_MASK;
                if let Some(key) = self.index_to_peer.get(&local_index) {
                    roamed_key = Some(*key);
                    self.peers.get_mut(key)
                } else {
                    self.endpoint_to_peer.get(&(endpoint_ip, endpoint_port)).and_then(|key| {
                        roamed_key = Some(*key);
                        self.peers.get_mut(key)
                    })
                }
            }
        } else {
            self.endpoint_to_peer.get(&(endpoint_ip, endpoint_port)).and_then(|key| {
                roamed_key = Some(*key);
                self.peers.get_mut(key)
            })
        };

        let (outcome, roamed_update) = {
            let peer = match peer {
                Some(p) => p,
                None => return WireGuardDecapOutcome::None,
            };
            
            let res = if let Some(cached) = cached_result {
                // Safety: transmute TunnResult<'static> back to TunnResult<'_>
                let res_back: TunnResult<'_> = unsafe { std::mem::transmute(cached) };
                res_back
            } else {
                scratch_wg_in.resize(outer_payload.len(), 0);
                peer.tunn.decapsulate(Some(endpoint_ip), outer_payload, scratch_wg_in)
            };
            
            // Check if the packet is authentic (WriteToNetwork, WriteToTunnelV4, WriteToTunnelV6)
            let is_authentic = match &res {
                TunnResult::WriteToNetwork(_) | TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _) => true,
                _ => false,
            };

            let old_endpoint = peer.endpoint;
            if is_authentic {
                // Update peer endpoint in case it changed (roaming)
                peer.endpoint = Some((endpoint_ip, endpoint_port));
                // Also update local IP from the packet's destination IP
                peer.local_ip = Some(meta.dst_ip());
            }

            let roamed = if is_authentic && old_endpoint != peer.endpoint {
                Some((old_endpoint, peer.endpoint))
            } else {
                None
            };

            let outcome = match res {
                TunnResult::WriteToNetwork(packet) => {
                    let mut src_mac = [0u8; 6];
                    let mut dst_mac = [0u8; 6];
                    if raw_frame_mut.len() >= 12 {
                        src_mac.copy_from_slice(&raw_frame_mut[0..6]);
                        dst_mac.copy_from_slice(&raw_frame_mut[6..12]);
                    }
                    let (frame, outer_meta) = match Self::construct_outer_frame_allocated(
                        self.listen_port,
                        packet,
                        peer,
                        meta.ingress_ifindex,
                        meta.rx_queue_index,
                        src_mac,
                        dst_mac,
                    ) {
                        Some(val) => val,
                        None => return WireGuardDecapOutcome::None,
                    };
                    WireGuardDecapOutcome::Decapped(WireGuardDecapResult {
                        decapsulated_len: frame.len(),
                        meta: outer_meta,
                        is_control: true,
                        control_frame: Some(frame),
                    })
                }
                TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
                    let (protocol, l4_offset, _) = match parse_inner_protocol_and_offsets(packet, meta.addr_family) {
                        Some(val) => val,
                        None => return WireGuardDecapOutcome::None,
                    };
                    let inner_payload_rel = get_inner_payload_offset(packet, l4_offset, protocol);
                    
                    let total_len = 14 + packet.len();
                    if raw_frame_mut.len() < total_len {
                        return WireGuardDecapOutcome::None;
                    }
                    
                    // Write synthetic Ethernet frame directly back into the UMEM memory in-place!
                    raw_frame_mut[0..6].copy_from_slice(&[0x02, 0xbf, 0x72, 0x00, 0x00, 0x00]);
                    raw_frame_mut[6..12].copy_from_slice(&[0x02, 0xbf, 0x72, 0x00, 0x00, 0x00]);
                    raw_frame_mut[12..14].copy_from_slice(&(if packet[0] >> 4 == 4 { 0x0800u16 } else { 0x86ddu16 }).to_be_bytes());
                    raw_frame_mut[14..total_len].copy_from_slice(packet);
                    
                    let inner_meta = UserspaceDpMeta {
                        magic: super::USERSPACE_META_MAGIC,
                        version: super::USERSPACE_META_VERSION,
                        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
                        ingress_ifindex: meta.ingress_ifindex,
                        rx_queue_index: meta.rx_queue_index,
                        l3_offset: 14,
                        l4_offset: 14 + l4_offset,
                        payload_offset: 14 + inner_payload_rel,
                        pkt_len: total_len as u16,
                        addr_family: if packet[0] >> 4 == 4 { libc::AF_INET as u8 } else { libc::AF_INET6 as u8 },
                        protocol,
                        ..UserspaceDpMeta::default()
                    };
                    
                    WireGuardDecapOutcome::Decapped(WireGuardDecapResult {
                        decapsulated_len: total_len,
                        meta: inner_meta,
                        is_control: false,
                        control_frame: None,
                    })
                }
                _ => WireGuardDecapOutcome::None,
            };

            (outcome, roamed)
        };

        if let Some((old_endpoint, new_endpoint)) = roamed_update {
            if let Some(key) = roamed_key {
                if let Some((old_ip, old_port)) = old_endpoint {
                    self.endpoint_to_peer.remove(&(old_ip, old_port));
                }
                if let Some((new_ip, new_port)) = new_endpoint {
                    self.endpoint_to_peer.insert((new_ip, new_port), key);
                }
            }
        }

        outcome
    }

    pub(super) fn try_encap(
        &mut self,
        inner_frame: &[u8],
        addr_family: u8,
        ingress_ifindex: u32,
        rx_queue_index: u32,
        explicit_peer: Option<[u8; 32]>,
        preferred_local_ip: Option<IpAddr>,
        scratch_out: &mut Vec<u8>,
    ) -> Option<(usize, usize, UserspaceDpMeta)> {
        let peer_pub_key = if let Some(key) = explicit_peer {
            key
        } else {
            // Need to parse inner IP to find peer
            let inner_packet = &inner_frame[14..]; // Assume Ethernet
            if addr_family as i32 == libc::AF_INET {
                if inner_packet.len() < 20 {
                    return None;
                }
                let mut octets = [0u8; 4];
                octets.copy_from_slice(&inner_packet[16..20]);
                let dst_ip = IpAddr::V4(Ipv4Addr::from(octets));
                *self.allowed_ip_to_peer.longest_match(dst_ip)?
            } else if addr_family as i32 == libc::AF_INET6 {
                if inner_packet.len() < 40 {
                    return None;
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&inner_packet[24..40]);
                let dst_ip = IpAddr::V6(Ipv6Addr::from(octets));
                *self.allowed_ip_to_peer.longest_match(dst_ip)?
            } else {
                return None;
            }
        };

        let peer = self.peers.get_mut(&peer_pub_key)?;
        
        // Learn preferred local IP from control-plane tunnel source.
        if let Some(local_ip) = preferred_local_ip {
            if !local_ip.is_unspecified() {
                peer.local_ip = Some(local_ip);
            }
        }

        let mut src_mac = [0u8; 6];
        let mut dst_mac = [0u8; 6];
        if inner_frame.len() >= 12 {
            src_mac.copy_from_slice(&inner_frame[6..12]);
            dst_mac.copy_from_slice(&inner_frame[0..6]);
        }

        let inner_packet = &inner_frame[14..];
        
        let (outer_dst_ip, outer_dst_port) = peer.endpoint?;
        let outer_src_ip = peer.local_ip.unwrap_or_else(|| {
            if outer_dst_ip.is_ipv4() {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            } else {
                IpAddr::V6(Ipv6Addr::UNSPECIFIED)
            }
        });

        if outer_src_ip.is_unspecified() {
            return None;
        }

        let header_len = match outer_dst_ip {
            IpAddr::V4(_) => 42,
            IpAddr::V6(_) => 62,
        };

        // Align the packet start to a 32-byte boundary to avoid SIMD unaligned load penalties
        let base_ptr = scratch_out.as_ptr() as usize;
        let padding = (32 - (base_ptr % 32)) % 32;
        let encap_start = padding + header_len;

        scratch_out.resize(encap_start + inner_packet.len() + 128, 0);

        let (payload_slice, encap_ok) = {
            let out_buf = &mut scratch_out[encap_start..];
            match peer.tunn.encapsulate(inner_packet, out_buf) {
                TunnResult::WriteToNetwork(p) => (p as &[u8], true),
                _ => (&[][..], false),
            }
        };

        if !encap_ok {
            return None;
        }

        let wg_payload_len = payload_slice.len();
        let total_len = header_len + wg_payload_len;

        // Construct outer headers in-place directly in scratch_out
        let packet_start = padding;
        let ip_start = packet_start + 14;
        let udp_start = ip_start + (if outer_dst_ip.is_ipv4() { 20 } else { 40 });

        scratch_out[packet_start .. packet_start + 6].copy_from_slice(&dst_mac);
        scratch_out[packet_start + 6 .. packet_start + 12].copy_from_slice(&src_mac);
        let eth_proto: u16 = if outer_dst_ip.is_ipv4() { 0x0800 } else { 0x86dd };
        scratch_out[packet_start + 12 .. packet_start + 14].copy_from_slice(&eth_proto.to_be_bytes());

        let udp_len = 8 + wg_payload_len;
        let ip_len = match outer_dst_ip {
            IpAddr::V4(_) => 20 + udp_len,
            IpAddr::V6(_) => 40 + udp_len,
        };

        if outer_dst_ip.is_ipv4() {
            let dst_v4 = match outer_dst_ip { IpAddr::V4(v) => v, _ => unreachable!() };
            let src_v4 = match outer_src_ip { IpAddr::V4(v) => v, _ => Ipv4Addr::UNSPECIFIED };
            scratch_out[ip_start] = 0x45;
            scratch_out[ip_start + 1] = 0; // TOS
            scratch_out[ip_start + 2 .. ip_start + 4].copy_from_slice(&(ip_len as u16).to_be_bytes());
            scratch_out[ip_start + 4 .. ip_start + 8].fill(0); // ID, Flags, Fragment offset
            scratch_out[ip_start + 8] = 64; // TTL
            scratch_out[ip_start + 9] = 17; // UDP
            scratch_out[ip_start + 10 .. ip_start + 12].fill(0); // Clear checksum first
            scratch_out[ip_start + 12 .. ip_start + 16].copy_from_slice(&src_v4.octets());
            scratch_out[ip_start + 16 .. ip_start + 20].copy_from_slice(&dst_v4.octets());
            
            // Set UDP header fields
            scratch_out[udp_start .. udp_start + 2].copy_from_slice(&self.listen_port.to_be_bytes());
            scratch_out[udp_start + 2 .. udp_start + 4].copy_from_slice(&outer_dst_port.to_be_bytes());
            scratch_out[udp_start + 4 .. udp_start + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
            scratch_out[udp_start + 6 .. udp_start + 8].fill(0); // Clear checksum first
            
            // Compute outer UDP checksum using SIMD helper
            let udp_csum = super::checksum16_ipv4(src_v4, dst_v4, 17, &scratch_out[udp_start .. udp_start + udp_len]);
            let udp_csum = if udp_csum == 0 { 0xffff } else { udp_csum };
            scratch_out[udp_start + 6 .. udp_start + 8].copy_from_slice(&udp_csum.to_be_bytes());
            
            // Compute outer IPv4 header checksum using SIMD helper
            let ip_csum = super::checksum16(&scratch_out[ip_start .. ip_start + 20]);
            scratch_out[ip_start + 10 .. ip_start + 12].copy_from_slice(&ip_csum.to_be_bytes());
        } else {
            let dst_v6 = match outer_dst_ip { IpAddr::V6(v) => v, _ => unreachable!() };
            let src_v6 = match outer_src_ip { IpAddr::V6(v) => v, _ => Ipv6Addr::UNSPECIFIED };
            scratch_out[ip_start] = 0x60;
            scratch_out[ip_start + 1 .. ip_start + 4].fill(0); // Flow label, Traffic class
            scratch_out[ip_start + 4 .. ip_start + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
            scratch_out[ip_start + 6] = 17; // UDP
            scratch_out[ip_start + 7] = 64; // Hop Limit
            scratch_out[ip_start + 8 .. ip_start + 24].copy_from_slice(&src_v6.octets());
            scratch_out[ip_start + 24 .. ip_start + 40].copy_from_slice(&dst_v6.octets());
            
            // Set UDP header fields
            scratch_out[udp_start .. udp_start + 2].copy_from_slice(&self.listen_port.to_be_bytes());
            scratch_out[udp_start + 2 .. udp_start + 4].copy_from_slice(&outer_dst_port.to_be_bytes());
            scratch_out[udp_start + 4 .. udp_start + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
            scratch_out[udp_start + 6 .. udp_start + 8].fill(0); // Clear checksum first
            
            // Compute outer UDP checksum using SIMD helper (mandatory for IPv6)
            let udp_csum = super::checksum16_ipv6(src_v6, dst_v6, 17, &scratch_out[udp_start .. udp_start + udp_len]);
            let udp_csum = if udp_csum == 0 { 0xffff } else { udp_csum };
            scratch_out[udp_start + 6 .. udp_start + 8].copy_from_slice(&udp_csum.to_be_bytes());
        }

        let meta = UserspaceDpMeta {
            magic: super::USERSPACE_META_MAGIC,
            version: super::USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            ingress_ifindex,
            rx_queue_index,
            l3_offset: (ip_start - packet_start) as u16,
            l4_offset: (udp_start - packet_start) as u16,
            payload_offset: (udp_start + 8 - packet_start) as u16,
            pkt_len: total_len as u16,
            addr_family: if outer_dst_ip.is_ipv4() { libc::AF_INET as u8 } else { libc::AF_INET6 as u8 },
            protocol: 17, // UDP
            ..UserspaceDpMeta::default()
        };

        Some((packet_start, total_len, meta))
    }

    fn construct_outer_frame_allocated(
        listen_port: u16,
        wg_payload: &[u8],
        peer: &PeerState,
        ingress_ifindex: u32,
        rx_queue_index: u32,
        src_mac: [u8; 6],
        dst_mac: [u8; 6],
    ) -> Option<(Vec<u8>, UserspaceDpMeta)> {
        let (outer_dst_ip, outer_dst_port) = peer.endpoint?;
        let outer_src_ip = peer.local_ip.unwrap_or_else(|| {
            if outer_dst_ip.is_ipv4() {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            } else {
                IpAddr::V6(Ipv6Addr::UNSPECIFIED)
            }
        });
        
        let udp_len = 8 + wg_payload.len();
        let ip_len = match outer_dst_ip {
            IpAddr::V4(_) => 20 + udp_len,
            IpAddr::V6(_) => 40 + udp_len,
        };
        
        let mut out = vec![0u8; 14 + ip_len];
        out[0..6].copy_from_slice(&dst_mac);
        out[6..12].copy_from_slice(&src_mac);
        let eth_proto: u16 = if outer_dst_ip.is_ipv4() { 0x0800 } else { 0x86dd };
        out[12..14].copy_from_slice(&eth_proto.to_be_bytes());
        
        let ip_start = 14;
        let udp_start = ip_start + (if outer_dst_ip.is_ipv4() { 20 } else { 40 });
        
        if outer_dst_ip.is_ipv4() {
            let dst_v4 = match outer_dst_ip { IpAddr::V4(v) => v, _ => unreachable!() };
            let src_v4 = match outer_src_ip { IpAddr::V4(v) => v, _ => Ipv4Addr::UNSPECIFIED };
            out[ip_start] = 0x45;
            out[ip_start + 2..ip_start + 4].copy_from_slice(&(ip_len as u16).to_be_bytes());
            out[ip_start + 8] = 64; // TTL
            out[ip_start + 9] = 17; // UDP
            out[ip_start + 12..ip_start + 16].copy_from_slice(&src_v4.octets());
            out[ip_start + 16..ip_start + 20].copy_from_slice(&dst_v4.octets());
            
            // Set UDP header fields
            out[udp_start..udp_start + 2].copy_from_slice(&listen_port.to_be_bytes());
            out[udp_start + 2..udp_start + 4].copy_from_slice(&outer_dst_port.to_be_bytes());
            out[udp_start + 4..udp_start + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
            out[udp_start + 8..udp_start + 8 + wg_payload.len()].copy_from_slice(wg_payload);
            
            // Compute outer UDP checksum using SIMD helper
            let udp_csum = super::checksum16_ipv4(src_v4, dst_v4, 17, &out[udp_start..]);
            let udp_csum = if udp_csum == 0 { 0xffff } else { udp_csum };
            out[udp_start + 6..udp_start + 8].copy_from_slice(&udp_csum.to_be_bytes());
            
            // Compute outer IPv4 header checksum using SIMD helper
            let ip_csum = super::checksum16(&out[ip_start..ip_start + 20]);
            out[ip_start + 10..ip_start + 12].copy_from_slice(&ip_csum.to_be_bytes());
        } else {
            let dst_v6 = match outer_dst_ip { IpAddr::V6(v) => v, _ => unreachable!() };
            let src_v6 = match outer_src_ip { IpAddr::V6(v) => v, _ => Ipv6Addr::UNSPECIFIED };
            out[ip_start] = 0x60;
            out[ip_start + 4..ip_start + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
            out[ip_start + 6] = 17; // UDP
            out[ip_start + 7] = 64; // Hop Limit
            out[ip_start + 8..ip_start + 24].copy_from_slice(&src_v6.octets());
            out[ip_start + 24..ip_start + 40].copy_from_slice(&dst_v6.octets());
            
            // Set UDP header fields
            out[udp_start..udp_start + 2].copy_from_slice(&listen_port.to_be_bytes());
            out[udp_start + 2..udp_start + 4].copy_from_slice(&outer_dst_port.to_be_bytes());
            out[udp_start + 4..udp_start + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
            out[udp_start + 8..udp_start + 8 + wg_payload.len()].copy_from_slice(wg_payload);
            
            // Compute outer UDP checksum using SIMD helper (mandatory for IPv6)
            let udp_csum = super::checksum16_ipv6(src_v6, dst_v6, 17, &out[udp_start..]);
            let udp_csum = if udp_csum == 0 { 0xffff } else { udp_csum };
            out[udp_start + 6..udp_start + 8].copy_from_slice(&udp_csum.to_be_bytes());
        }

        let meta = UserspaceDpMeta {
            magic: super::USERSPACE_META_MAGIC,
            version: super::USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            ingress_ifindex,
            rx_queue_index,
            l3_offset: ip_start as u16,
            l4_offset: udp_start as u16,
            payload_offset: (udp_start + 8) as u16,
            pkt_len: (14 + ip_len) as u16,
            addr_family: if outer_dst_ip.is_ipv4() { libc::AF_INET as u8 } else { libc::AF_INET6 as u8 },
            protocol: 17, // UDP
            ..UserspaceDpMeta::default()
        };
        
        Some((out, meta))
    }

    pub(super) fn apply_snapshot(&mut self, snap: &crate::protocol::WireGuardInterfaceSnapshot) {
        self.listen_port = snap.listen_port;

        let mut private_key = [0u8; 32];
        let trimmed_private_key = snap.private_key.trim();
        let key = match BASE64.decode(trimmed_private_key) {
            Ok(key) if key.len() == 32 => key,
            _ => {
                self.peers.clear();
                self.allowed_ip_to_peer = PrefixMap::new();
                self.endpoint_to_peer.clear();
                self.index_to_peer.clear();
                self.static_private_raw = None;
                return;
            }
        };
        private_key.copy_from_slice(&key);
        if private_key.iter().all(|&b| b == 0) {
            self.peers.clear();
            self.allowed_ip_to_peer = PrefixMap::new();
            self.endpoint_to_peer.clear();
            self.index_to_peer.clear();
            self.static_private_raw = None;
            return;
        }

        let key_changed = Some(private_key) != self.static_private_raw;
        if key_changed {
            self.static_private_raw = Some(private_key);
        }

        let mut current_peers = FxHashMap::default();
        let mut new_allowed_ip_to_peer = PrefixMap::new();
        let mut new_endpoint_to_peer = FxHashMap::default();
        let mut new_index_to_peer = FxHashMap::default();

        for peer_snap in &snap.peers {
            let mut public_key = [0u8; 32];
            let trimmed_peer_key = peer_snap.public_key.trim();
            if let Ok(key) = BASE64.decode(trimmed_peer_key) {
                if key.len() == 32 {
                    public_key.copy_from_slice(&key);
                } else {
                    continue; // Skip invalid peer
                }
            } else {
                continue; // Skip invalid peer
            }

            let endpoint = if !peer_snap.endpoint.is_empty() {
                let trimmed_endpoint = peer_snap.endpoint.trim();
                if let Ok(addr) = trimmed_endpoint.parse::<std::net::SocketAddr>() {
                    Some((addr.ip(), addr.port()))
                } else {
                    None
                }
            } else {
                None
            };

            // Reuse existing PeerState if we have it, to preserve the Tunn session
            let peer_state = if let Some(mut existing) = self.peers.remove(&public_key) {
                existing.endpoint = endpoint;
                if key_changed {
                    existing.tunn = Tunn::new(
                        StaticSecret::from(private_key),
                        PublicKey::from(public_key),
                        None, // preshared key
                        Some(peer_snap.persistent_keepalive.min(u16::MAX as u32) as u16),
                        self.encode_receiver_index(existing.local_index),
                        None, // logger
                    );
                }
                existing
            } else {
                let local_index = stable_local_index(&public_key, &new_index_to_peer, &self.peers);
                let tunn = Tunn::new(
                    StaticSecret::from(private_key),
                    PublicKey::from(public_key),
                    None, // preshared key
                    Some(peer_snap.persistent_keepalive.min(u16::MAX as u32) as u16),
                    self.encode_receiver_index(local_index),
                    None, // logger
                );

                PeerState {
                    tunn,
                    endpoint,
                    local_ip: None,
                    local_index,
                }
            };

            new_index_to_peer.insert(peer_state.local_index, public_key);
            current_peers.insert(public_key, peer_state);

            if let Some((ip, port)) = endpoint {
                new_endpoint_to_peer.insert((ip, port), public_key);
            }

            for allowed_ip in &peer_snap.allowed_ips {
                let trimmed_ip = allowed_ip.trim();
                if let Ok(net) = trimmed_ip.parse::<ipnet::IpNet>() {
                    new_allowed_ip_to_peer.insert(net, public_key);
                }
            }
        }

        self.peers = current_peers;
        self.allowed_ip_to_peer = new_allowed_ip_to_peer;
        self.endpoint_to_peer = new_endpoint_to_peer;
        self.index_to_peer = new_index_to_peer;
    }
}

fn parse_inner_protocol_and_offsets(packet: &[u8], _addr_family: u8) -> Option<(u8, u16, u16)> {
    if packet.len() < 20 {
        return None;
    }
    match packet[0] >> 4 {
        4 => {
            let ihl = (packet[0] & 0x0f) * 4;
            let protocol = packet[9];
            Some((protocol, ihl as u16, ihl as u16))
        }
        6 => {
            if packet.len() < 40 { return None; }
            let protocol = packet[6];
            Some((protocol, 40, 40))
        }
        _ => None,
    }
}

fn stable_local_index(
    public_key: &[u8; 32],
    occupied: &FxHashMap<u32, [u8; 32]>,
    remaining_peers: &FxHashMap<[u8; 32], PeerState>,
) -> u32 {
    let mut idx = u32::from_le_bytes([public_key[0], public_key[1], public_key[2], 0]) & RECEIVER_INDEX_MASK;
    if idx == 0 {
        idx = 1;
    }
    loop {
        let in_occupied = occupied.contains_key(&idx);
        let in_remaining = remaining_peers.values().any(|p| p.local_index == idx);
        if !in_occupied && !in_remaining {
            break;
        }
        idx = (idx + 1) & RECEIVER_INDEX_MASK;
        if idx == 0 {
            idx = 1;
        }
    }
    idx
}

fn get_inner_payload_offset(packet: &[u8], l4_offset: u16, protocol: u8) -> u16 {
    let l4_idx = l4_offset as usize;
    match protocol {
        6 => { // TCP
            if packet.len() >= l4_idx + 13 {
                let data_offset = ((packet[l4_idx + 12] >> 4) * 4) as u16;
                if data_offset >= 20 && l4_idx + (data_offset as usize) <= packet.len() {
                    return l4_offset + data_offset;
                }
            }
            l4_offset + 20
        }
        17 | 1 | 58 => l4_offset + 8, // UDP, ICMP, ICMPv6
        _ => l4_offset,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inner_payload_offset_tcp() {
        // TCP packet: l4_offset is 0, protocol is 6 (TCP).
        // TCP data offset is in the 13th byte (index 12 of TCP header), high 4 bits.
        // Let's create a minimal TCP header (20 bytes).
        let mut packet = vec![0u8; 20];
        packet[12] = 5 << 4; // 5 * 4 = 20 bytes data offset
        assert_eq!(get_inner_payload_offset(&packet, 0, 6), 20);

        // TCP header of 32 bytes (options present)
        let mut packet2 = vec![0u8; 32];
        packet2[12] = 8 << 4; // 8 * 4 = 32 bytes data offset
        assert_eq!(get_inner_payload_offset(&packet2, 0, 6), 32);
    }

    #[test]
    fn test_inner_payload_offset_udp_icmp() {
        // UDP (17), ICMP (1), ICMPv6 (58) -> l4_offset + 8
        assert_eq!(get_inner_payload_offset(&[], 0, 17), 8);
        assert_eq!(get_inner_payload_offset(&[], 10, 1), 18);
        assert_eq!(get_inner_payload_offset(&[], 20, 58), 28);
    }

    #[test]
    fn test_inner_payload_offset_other() {
        // Others -> l4_offset
        assert_eq!(get_inner_payload_offset(&[], 15, 99), 15);
    }

    #[test]
    fn test_wireguard_receiver_index_encoding() {
        let engine = WireGuardEngine::new();
        // encode receiver index
        let supplied_index = engine.encode_receiver_index(123);
        // boringtun shifts it by 8 left and overlays counter
        let receiver_idx = (supplied_index << 8) | 45; // 45 is the cyclic session counter

        assert_eq!((receiver_idx >> 8) & RECEIVER_INDEX_MASK, 123);
    }

    #[test]
    fn test_peer_reorder_and_index_collision_avoidance() {
        use crate::protocol::{WireGuardInterfaceSnapshot, WireGuardPeerSnapshot};
        let mut engine = WireGuardEngine::new();

        let private_key = BASE64.encode(&[1u8; 32]);
        let mut key_a = [0u8; 32]; key_a[0] = 10;
        let mut key_b = [0u8; 32]; key_b[0] = 20;
        let mut key_c = [0u8; 32]; key_c[0] = 30;

        let pub_a = BASE64.encode(&key_a);
        let pub_b = BASE64.encode(&key_b);
        let pub_c = BASE64.encode(&key_c);

        let snap1 = WireGuardInterfaceSnapshot {
            private_key: private_key.clone(),
            public_key: "".to_string(),
            listen_port: 51820,
            peers: vec![
                WireGuardPeerSnapshot { public_key: pub_a.clone(), endpoint: "".to_string(), allowed_ips: vec![], persistent_keepalive: 0 },
                WireGuardPeerSnapshot { public_key: pub_b.clone(), endpoint: "".to_string(), allowed_ips: vec![], persistent_keepalive: 0 },
            ],
        };

        engine.apply_snapshot(&snap1);
        assert_eq!(engine.peers.len(), 2);
        let idx_a = engine.peers.get(&key_a).unwrap().local_index;
        let idx_b = engine.peers.get(&key_b).unwrap().local_index;
        assert_ne!(idx_a, idx_b);

        let snap2 = WireGuardInterfaceSnapshot {
            private_key: private_key.clone(),
            public_key: "".to_string(),
            listen_port: 51820,
            peers: vec![
                WireGuardPeerSnapshot { public_key: pub_b.clone(), endpoint: "".to_string(), allowed_ips: vec![], persistent_keepalive: 0 },
                WireGuardPeerSnapshot { public_key: pub_c.clone(), endpoint: "".to_string(), allowed_ips: vec![], persistent_keepalive: 0 },
            ],
        };

        engine.apply_snapshot(&snap2);
        assert_eq!(engine.peers.len(), 2);
        let new_idx_b = engine.peers.get(&key_b).unwrap().local_index;
        let idx_c = engine.peers.get(&key_c).unwrap().local_index;

        assert_eq!(new_idx_b, idx_b);
        assert_ne!(idx_c, new_idx_b);
    }

    #[test]
    fn test_private_key_rotation_rebuilds_tunn() {
        use crate::protocol::{WireGuardInterfaceSnapshot, WireGuardPeerSnapshot};
        let mut engine = WireGuardEngine::new();

        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let private_key1 = BASE64.encode(&key1);
        let private_key2 = BASE64.encode(&key2);

        let mut peer_key = [0u8; 32]; peer_key[0] = 99;
        let pub_peer = BASE64.encode(&peer_key);

        let snap1 = WireGuardInterfaceSnapshot {
            private_key: private_key1,
            public_key: "".to_string(),
            listen_port: 51820,
            peers: vec![WireGuardPeerSnapshot { public_key: pub_peer.clone(), endpoint: "".to_string(), allowed_ips: vec![], persistent_keepalive: 0 }],
        };

        engine.apply_snapshot(&snap1);
        let idx_before = engine.peers.get(&peer_key).unwrap().local_index;

        let snap2 = WireGuardInterfaceSnapshot {
            private_key: private_key2,
            public_key: "".to_string(),
            listen_port: 51820,
            peers: vec![WireGuardPeerSnapshot { public_key: pub_peer.clone(), endpoint: "".to_string(), allowed_ips: vec![], persistent_keepalive: 0 }],
        };

        engine.apply_snapshot(&snap2);
        let peer_after = engine.peers.get(&peer_key).unwrap();
        assert_eq!(peer_after.local_index, idx_before);
    }

    #[test]
    fn test_try_decap_packet_bounds_check_panic_prevention() {
        let mut engine = WireGuardEngine::new();
        engine.listen_port = 51820;

        let meta = UserspaceDpMeta {
            protocol: 17,
            flow_dst_port: 51820,
            payload_offset: 0,
            ..UserspaceDpMeta::default()
        };

        let mut raw_packet = vec![2u8, 0, 0, 0, 0, 0];
        let mut scratch = vec![];
        let outcome = engine.try_decap(&mut raw_packet, &meta, &mut scratch);
        assert!(matches!(outcome, WireGuardDecapOutcome::None));
    }

    #[test]
    fn test_trial_decap_rate_limiting() {
        let mut engine = WireGuardEngine::new();
        assert_eq!(engine.trial_decap_tokens, 32);

        for _ in 0..32 {
            assert!(engine.acquire_trial_decap_token(0));
        }
        assert!(!engine.acquire_trial_decap_token(0));
        assert!(engine.acquire_trial_decap_token(1_000_000));
        assert!(!engine.acquire_trial_decap_token(1_000_000));
    }
}
