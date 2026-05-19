use super::*;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{StaticSecret, PublicKey};
use std::sync::{Arc, Mutex};
use rustc_hash::FxHashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

pub(super) struct WireGuardEngine {
    // Peers indexed by their public key
    peers: FxHashMap<[u8; 32], Arc<Mutex<PeerState>>>,
    // Mapping from outer (encrypted) flow to peer
    endpoint_to_peer: FxHashMap<(IpAddr, u16), [u8; 32]>,
    // Mapping from inner destination IP to peer (allowed-ips)
    allowed_ip_to_peer: FxHashMap<IpAddr, [u8; 32]>,
    // Local listen port for this interface
    listen_port: u16,
}

struct PeerState {
    tunn: Tunn,
    endpoint: Option<(IpAddr, u16)>,
    local_ip: Option<IpAddr>,
}

pub(super) struct WireGuardDecapResult {
    pub frame: Vec<u8>,
    pub meta: UserspaceDpMeta,
    pub is_control: bool,
}

pub(super) struct WireGuardEncapResult {
    pub frame: Vec<u8>,
    pub meta: UserspaceDpMeta,
    pub is_control: bool,
}

impl WireGuardEngine {
    pub(super) fn new() -> Self {
        Self {
            peers: FxHashMap::default(),
            endpoint_to_peer: FxHashMap::default(),
            allowed_ip_to_peer: FxHashMap::default(),
            listen_port: 0,
        }
    }

    pub(super) fn try_decap(&self, outer_frame: &[u8], meta: &UserspaceDpMeta) -> Option<WireGuardDecapResult> {
        if meta.protocol != 17 || meta.flow_dst_port != self.listen_port {
            return None;
        }
        
        let outer_payload = outer_frame.get(meta.payload_offset as usize..)?;
        let endpoint_ip = meta.src_ip();
        let endpoint_port = meta.flow_src_port;

        let peer_key = self.endpoint_to_peer.get(&(endpoint_ip, endpoint_port))?;
        let peer = self.peers.get(peer_key)?;
        
        let mut peer_lock = peer.lock().ok()?;
        // Update peer endpoint in case it changed (roaming)
        peer_lock.endpoint = Some((endpoint_ip, endpoint_port));
        // Also update local IP from the packet's destination IP
        peer_lock.local_ip = Some(meta.dst_ip());
        
        let mut out_payload = vec![0u8; outer_payload.len()];
        match peer_lock.tunn.decapsulate(Some(endpoint_ip), outer_payload, &mut out_payload) {
            TunnResult::WriteToNetwork(packet) => {
                // Handshake/control response
                let (frame, meta) = self.construct_outer_frame(
                    packet,
                    &peer_lock,
                    meta.ingress_ifindex,
                    meta.rx_queue_index,
                )?;
                Some(WireGuardDecapResult { frame, meta, is_control: true })
            }
            TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
                let (protocol, l4_offset, _payload_offset) = parse_inner_protocol_and_offsets(packet, meta.addr_family)?;
                
                // Construct synthetic Ethernet frame
                let mut synthetic = vec![0u8; 14 + packet.len()];
                synthetic[12..14].copy_from_slice(&(if packet[0] >> 4 == 4 { 0x0800u16 } else { 0x86ddu16 }).to_be_bytes());
                synthetic[14..].copy_from_slice(packet);
                
                let inner_meta = UserspaceDpMeta {
                    magic: super::USERSPACE_META_MAGIC,
                    version: super::USERSPACE_META_VERSION,
                    length: std::mem::size_of::<UserspaceDpMeta>() as u16,
                    ingress_ifindex: meta.ingress_ifindex,
                    rx_queue_index: meta.rx_queue_index,
                    l3_offset: 14,
                    l4_offset: 14 + l4_offset,
                    payload_offset: 14 + l4_offset + 8, // Assume UDP/TCP for now
                    pkt_len: (14 + packet.len()) as u16,
                    addr_family: if packet[0] >> 4 == 4 { libc::AF_INET as u8 } else { libc::AF_INET6 as u8 },
                    protocol,
                    ..UserspaceDpMeta::default()
                };
                
                Some(WireGuardDecapResult {
                    frame: synthetic,
                    meta: inner_meta,
                    is_control: false,
                })
            }
            _ => None,
        }
    }

    pub(super) fn try_encap(
        &self,
        inner_frame: &[u8],
        addr_family: u8,
        ingress_ifindex: u32,
        rx_queue_index: u32,
        explicit_peer: Option<[u8; 32]>,
    ) -> Option<WireGuardEncapResult> {
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
                *self.allowed_ip_to_peer.get(&dst_ip)?
            } else if addr_family as i32 == libc::AF_INET6 {
                if inner_packet.len() < 40 {
                    return None;
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&inner_packet[24..40]);
                let dst_ip = IpAddr::V6(Ipv6Addr::from(octets));
                *self.allowed_ip_to_peer.get(&dst_ip)?
            } else {
                return None;
            }
        };

        let peer = self.peers.get(&peer_pub_key)?;
        let inner_packet = &inner_frame[14..];
        let mut peer_lock = peer.lock().ok()?;
        let mut out_payload = vec![0u8; inner_packet.len() + 128];
        match peer_lock.tunn.encapsulate(inner_packet, &mut out_payload) {
            TunnResult::WriteToNetwork(packet) => {
                let (frame, meta) = self.construct_outer_frame(
                    packet,
                    &peer_lock,
                    ingress_ifindex,
                    rx_queue_index,
                )?;
                Some(WireGuardEncapResult {
                    frame,
                    meta,
                    is_control: false,
                })
            }
            _ => None,
        }
    }

    fn construct_outer_frame(
        &self,
        wg_payload: &[u8],
        peer: &PeerState,
        ingress_ifindex: u32,
        rx_queue_index: u32,
    ) -> Option<(Vec<u8>, UserspaceDpMeta)> {
        let (outer_dst_ip, outer_dst_port) = peer.endpoint?;
        let outer_src_ip = peer.local_ip.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        
        let udp_len = 8 + wg_payload.len();
        let ip_len = match outer_dst_ip {
            IpAddr::V4(_) => 20 + udp_len,
            IpAddr::V6(_) => 40 + udp_len,
        };
        
        let mut out = vec![0u8; 14 + ip_len];
        let eth_proto: u16 = if outer_dst_ip.is_ipv4() { 0x0800 } else { 0x86dd };
        out[12..14].copy_from_slice(&eth_proto.to_be_bytes());
        
        let ip_start = 14;
        if outer_dst_ip.is_ipv4() {
            let dst_v4 = match outer_dst_ip { IpAddr::V4(v) => v, _ => unreachable!() };
            let src_v4 = match outer_src_ip { IpAddr::V4(v) => v, _ => Ipv4Addr::UNSPECIFIED };
            out[ip_start] = 0x45;
            out[ip_start + 2..ip_start + 4].copy_from_slice(&(ip_len as u16).to_be_bytes());
            out[ip_start + 8] = 64; // TTL
            out[ip_start + 9] = 17; // UDP
            out[ip_start + 12..ip_start + 16].copy_from_slice(&src_v4.octets());
            out[ip_start + 16..ip_start + 20].copy_from_slice(&dst_v4.octets());
        } else {
            let dst_v6 = match outer_dst_ip { IpAddr::V6(v) => v, _ => unreachable!() };
            let src_v6 = match outer_src_ip { IpAddr::V6(v) => v, _ => Ipv6Addr::UNSPECIFIED };
            out[ip_start] = 0x60;
            out[ip_start + 4..ip_start + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
            out[ip_start + 6] = 17; // UDP
            out[ip_start + 7] = 64; // Hop Limit
            out[ip_start + 8..ip_start + 24].copy_from_slice(&src_v6.octets());
            out[ip_start + 24..ip_start + 40].copy_from_slice(&dst_v6.octets());
        }
        
        let udp_start = ip_start + (if outer_dst_ip.is_ipv4() { 20 } else { 40 });
        out[udp_start..udp_start + 2].copy_from_slice(&self.listen_port.to_be_bytes());
        out[udp_start + 2..udp_start + 4].copy_from_slice(&outer_dst_port.to_be_bytes());
        out[udp_start + 4..udp_start + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
        out[udp_start + 8..udp_start + 8 + wg_payload.len()].copy_from_slice(wg_payload);

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
        if let Ok(key) = BASE64.decode(&snap.private_key) {
            if key.len() == 32 {
                private_key.copy_from_slice(&key);
            }
        }

        let mut current_peers = FxHashMap::default();
        let mut new_allowed_ip_to_peer = FxHashMap::default();
        let mut new_endpoint_to_peer = FxHashMap::default();

        for peer_snap in &snap.peers {
            let mut public_key = [0u8; 32];
            if let Ok(key) = BASE64.decode(&peer_snap.public_key) {
                if key.len() == 32 {
                    public_key.copy_from_slice(&key);
                } else {
                    continue; // Skip invalid peer
                }
            } else {
                continue; // Skip invalid peer
            }

            let endpoint = if !peer_snap.endpoint.is_empty() {
                if let Ok(addr) = peer_snap.endpoint.parse::<std::net::SocketAddr>() {
                    Some((addr.ip(), addr.port()))
                } else {
                    None
                }
            } else {
                None
            };

            // Reuse existing PeerState if we have it, to preserve the Tunn session
            let peer_state = if let Some(existing) = self.peers.remove(&public_key) {
                {
                    if let Ok(mut lock) = existing.lock() {
                        lock.endpoint = endpoint;
                    }
                }
                existing
            } else {
                let tunn = Tunn::new(
                    StaticSecret::from(private_key),
                    PublicKey::from(public_key),
                    None, // preshared key
                    Some(peer_snap.persistent_keepalive as u16),
                    0,    // index
                    None, // logger
                )
                .expect("failed to create Tunn");

                Arc::new(Mutex::new(PeerState {
                    tunn,
                    endpoint,
                    local_ip: None,
                }))
            };

            current_peers.insert(public_key, peer_state);

            if let Some((ip, port)) = endpoint {
                new_endpoint_to_peer.insert((ip, port), public_key);
            }

            for allowed_ip in &peer_snap.allowed_ips {
                if let Ok(net) = allowed_ip.parse::<ipnet::IpNet>() {
                    new_allowed_ip_to_peer.insert(net.addr(), public_key);
                }
            }
        }

        self.peers = current_peers;
        self.allowed_ip_to_peer = new_allowed_ip_to_peer;
        self.endpoint_to_peer = new_endpoint_to_peer;
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
