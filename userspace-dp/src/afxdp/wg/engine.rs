//! WgEngine: the per-WG-interface state container and API surface.
//!
//! The engine owns:
//!   - The local static key (X25519 private).
//!   - The peer table, keyed by peer pubkey.
//!   - The AllowedIPs LPM trie (used ONLY for inbound src-IP gate).
//!   - The session-by-receiver-index demux map for inbound.
//!
//! API shape:
//!   - `try_encap` — egress fast path. Caller supplies peer pubkey
//!     explicitly (from the forwarding decision). Engine does NOT
//!     consult AllowedIPs for peer selection. This is the
//!     cryptokey-routing safety property the prior PR violated.
//!   - `try_decap` — ingress fast path. Engine demuxes by
//!     `(receiver_index)`, finds the session, decrypts, then checks
//!     the decrypted inner src IP against the owning peer's
//!     AllowedIPs.
//!   - `complete_handshake_initiator` / `complete_handshake_responder`
//!     — slow path. Drive a snow `HandshakeState` to completion and
//!     install the resulting `StatelessTransportState` on the peer.
//!
//! Hot path discipline:
//!   - No allocations. snow's `write_message` / `read_message` take
//!     pre-sized slices.
//!   - No locks held across crypto operations on the encrypt path
//!     (we clone the `Arc<WgSession>` and release the peer lock).
//!   - Decrypt path takes a per-session replay-window lock only on
//!     the cold (Repeat / OutOfWindow) arms.

use super::allowed_ips::AllowedIps;
use super::framing::{encode_data_header, parse_data_header};
use super::peer::Peer;
use super::session::{ReplayDecision, WgSession};
use super::{POLY1305_TAG_LEN, WG_DATA_HEADER_LEN, WG_NOISE_PATTERN};
use rustc_hash::FxHashMap;
use snow::{Builder, HandshakeState};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, RwLock};

/// Errors that can fail the egress path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EncapError {
    /// The caller-supplied peer pubkey is not in the engine table.
    UnknownPeer,
    /// The peer has no completed handshake yet. The caller should
    /// kick the slow path to initiate a handshake.
    NoSession,
    /// The output buffer is too small for the encapsulated frame.
    BufferTooSmall,
    /// snow rejected the encryption — most likely nonce exhaustion
    /// (counter approaching 2^64). Caller MUST drop and re-key.
    CryptoFailed,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct EncapOutcome {
    /// Number of bytes written to the output buffer. The
    /// encapsulated wire image starts at offset 0.
    pub(crate) len: usize,
    /// The receiver_index used (peer-chosen). Useful for tracing.
    pub(crate) receiver_index: u32,
    /// The counter value used (engine-chosen). Useful for tracing.
    pub(crate) counter: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DecapError {
    /// Header was malformed (too short, wrong type, etc.)
    MalformedHeader,
    /// No session with the parsed receiver_index.
    UnknownSession,
    /// snow rejected the decryption — tag verify or nonce reuse.
    CryptoFailed,
    /// Replay window said this counter is a duplicate.
    ReplayDuplicate,
    /// Replay window said this counter is too old.
    ReplayOutOfWindow,
    /// Decrypted plaintext did not parse as IPv4/IPv6.
    MalformedInner,
    /// Inner src IP is not in this peer's AllowedIPs — cryptokey-
    /// routing violation; drop per WG spec §5.4.6.
    AllowedIpsViolation,
    /// Output buffer too small for plaintext.
    BufferTooSmall,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct DecapOutcome {
    /// Number of bytes of decrypted inner-IP plaintext written.
    pub(crate) len: usize,
    /// The peer that owned this session (so the caller can route
    /// the inner packet onward — typically into the LAN-side
    /// pipeline as if it had arrived on the WG virtual interface).
    pub(crate) peer_pubkey: [u8; 32],
}

/// Per-peer config passed to `WgEngine::reconcile`.
#[derive(Debug, Clone)]
pub(crate) struct WgPeerConfig {
    pub(crate) pubkey: [u8; 32],
    pub(crate) endpoint: Option<std::net::SocketAddr>,
    pub(crate) persistent_keepalive: u16,
    pub(crate) allowed_ips: Vec<ipnet::IpNet>,
}

/// Per-engine config.
#[derive(Debug, Clone)]
pub(crate) struct WgEngineConfig {
    pub(crate) local_private_key: [u8; 32],
    pub(crate) listen_port: u16,
    pub(crate) peers: Vec<WgPeerConfig>,
}

/// The engine.
pub(crate) struct WgEngine {
    /// Local X25519 private key. Held in the engine because every
    /// slow-path handshake needs it.
    local_private_key: [u8; 32],
    /// UDP port we listen on for inbound. Stored for diagnostics
    /// and for the slow-path responder.
    listen_port: u16,
    /// peer_pubkey → index in `peers`.
    peer_index_by_pubkey: RwLock<FxHashMap<[u8; 32], u32>>,
    /// peer slab — one entry per configured peer. Indexed by the
    /// `peer_index` referenced from `allowed_ips`.
    peers: RwLock<Vec<Arc<Peer>>>,
    /// AllowedIPs LPM. Only consulted on the decap path.
    allowed_ips: RwLock<AllowedIps>,
    /// Demux map: receiver_index → session. Receiver indices are
    /// chosen locally at handshake time so they uniquely identify
    /// a session for as long as it lives.
    sessions_by_local_index: RwLock<FxHashMap<u32, Arc<WgSession>>>,
}

impl WgEngine {
    pub(crate) fn new(config: WgEngineConfig) -> Self {
        let engine = Self {
            local_private_key: config.local_private_key,
            listen_port: config.listen_port,
            peer_index_by_pubkey: RwLock::new(FxHashMap::default()),
            peers: RwLock::new(Vec::new()),
            allowed_ips: RwLock::new(AllowedIps::new()),
            sessions_by_local_index: RwLock::new(FxHashMap::default()),
        };
        engine.reconcile_peers(&config.peers);
        engine
    }

    pub(crate) fn listen_port(&self) -> u16 {
        self.listen_port
    }

    /// Reconcile the engine's peer table against a new config
    /// snapshot. Slow path only.
    pub(crate) fn reconcile_peers(&self, configs: &[WgPeerConfig]) {
        let mut peers = self.peers.write().unwrap();
        let mut index_by_pubkey = self.peer_index_by_pubkey.write().unwrap();
        let mut allowed = self.allowed_ips.write().unwrap();
        // Build a fresh AllowedIPs from scratch. Old peer Arcs are
        // preserved where pubkeys overlap, which preserves the
        // post-handshake session state across config refreshes.
        let mut new_peers: Vec<Arc<Peer>> = Vec::with_capacity(configs.len());
        let mut new_index: FxHashMap<[u8; 32], u32> = FxHashMap::default();
        let mut new_allowed = AllowedIps::new();
        for (i, cfg) in configs.iter().enumerate() {
            let idx = i as u32;
            let existing = index_by_pubkey
                .get(&cfg.pubkey)
                .and_then(|old_idx| peers.get(*old_idx as usize).cloned());
            let peer = match existing {
                Some(p) => p,
                None => Arc::new(Peer::new(
                    cfg.pubkey,
                    cfg.endpoint,
                    cfg.persistent_keepalive,
                )),
            };
            new_peers.push(peer);
            new_index.insert(cfg.pubkey, idx);
            for cidr in &cfg.allowed_ips {
                new_allowed.insert(*cidr, idx);
            }
        }
        *peers = new_peers;
        *index_by_pubkey = new_index;
        *allowed = new_allowed;
    }

    fn peer_arc(&self, pubkey: &[u8; 32]) -> Option<Arc<Peer>> {
        let idx_map = self.peer_index_by_pubkey.read().unwrap();
        let idx = *idx_map.get(pubkey)?;
        let peers = self.peers.read().unwrap();
        peers.get(idx as usize).cloned()
    }

    fn peer_index(&self, pubkey: &[u8; 32]) -> Option<u32> {
        self.peer_index_by_pubkey
            .read()
            .unwrap()
            .get(pubkey)
            .copied()
    }

    /// Install a freshly-completed transport session on a peer and
    /// register it for inbound demux. Called from the slow-path
    /// handshake-complete code.
    pub(crate) fn install_session(&self, pubkey: &[u8; 32], session: Arc<WgSession>) {
        // Register for inbound demux first — the worker may start
        // receiving traffic immediately on this new session.
        self.sessions_by_local_index
            .write()
            .unwrap()
            .insert(session.local_index, session.clone());
        // Then rotate it onto the peer. The previous session (if
        // any) lives on as `peer.previous` for in-flight tail
        // decrypts.
        if let Some(peer) = self.peer_arc(pubkey) {
            peer.rotate_session(session);
        }
    }

    /// Hot-path encap.
    ///
    /// `inner_ip` is the inner IP packet (starts at the IP header;
    /// no L2). `out` is the worker's preallocated scratch buffer;
    /// the WG transport record (header + ciphertext + tag) is
    /// written starting at `out[0]`. Outer L2/L3/L4 headers are
    /// the caller's responsibility (`outer.rs` builders).
    pub(crate) fn try_encap(
        &self,
        peer_pubkey: &[u8; 32],
        inner_ip: &[u8],
        out: &mut [u8],
    ) -> Result<EncapOutcome, EncapError> {
        // Cryptokey-routing safety: the forwarding decision tells
        // us which peer to encrypt to. We do NOT consult
        // AllowedIPs to pick a peer on egress.
        let peer = self.peer_arc(peer_pubkey).ok_or(EncapError::UnknownPeer)?;
        let session = peer
            .current
            .read()
            .unwrap()
            .clone()
            .ok_or(EncapError::NoSession)?;

        let required = WG_DATA_HEADER_LEN + inner_ip.len() + POLY1305_TAG_LEN;
        if out.len() < required {
            return Err(EncapError::BufferTooSmall);
        }
        let counter = session.next_tx_counter();
        let _ = encode_data_header(out, session.peer_index, counter)
            .ok_or(EncapError::BufferTooSmall)?;
        // snow writes ciphertext||tag into the payload region.
        let (_hdr, payload) = out.split_at_mut(WG_DATA_HEADER_LEN);
        let n = session
            .transport
            .write_message(counter, inner_ip, payload)
            .map_err(|_| EncapError::CryptoFailed)?;
        Ok(EncapOutcome {
            len: WG_DATA_HEADER_LEN + n,
            receiver_index: session.peer_index,
            counter,
        })
    }

    /// Hot-path decap.
    ///
    /// `wg_record` is the WG transport record extracted from the
    /// outer UDP payload (starts at the WG type byte). `out` is
    /// the worker's preallocated scratch; decrypted inner-IP
    /// plaintext is written starting at `out[0]`.
    pub(crate) fn try_decap(
        &self,
        wg_record: &[u8],
        out: &mut [u8],
    ) -> Result<DecapOutcome, DecapError> {
        let hdr = parse_data_header(wg_record).ok_or(DecapError::MalformedHeader)?;
        let session = self
            .sessions_by_local_index
            .read()
            .unwrap()
            .get(&hdr.receiver_index)
            .cloned()
            .ok_or(DecapError::UnknownSession)?;
        let plaintext_len_max = hdr.ciphertext.len().saturating_sub(POLY1305_TAG_LEN);
        if out.len() < plaintext_len_max {
            return Err(DecapError::BufferTooSmall);
        }
        let n = session
            .transport
            .read_message(hdr.counter, hdr.ciphertext, out)
            .map_err(|_| DecapError::CryptoFailed)?;
        // Check the replay window AFTER successful decrypt — per
        // RFC 6479 / the WG paper, we mustn't update the window
        // for packets that fail authentication, or an attacker
        // could DoS the window by injecting bogus high-counter
        // ciphertexts.
        {
            let mut replay = session.replay.lock().unwrap();
            match replay.check_and_update(hdr.counter) {
                ReplayDecision::Accept => {}
                ReplayDecision::Repeat => return Err(DecapError::ReplayDuplicate),
                ReplayDecision::OutOfWindow => return Err(DecapError::ReplayOutOfWindow),
            }
        }
        // AllowedIPs gate on the inner src IP. WG spec §5.4.6:
        // "After decryption, the receiver verifies that the source
        // IP of the inner packet belongs to the peer who sent it.
        // If not, drop." This is the cryptokey-routing safety
        // invariant on the receive side.
        let inner_src = inner_src_ip(&out[..n]).ok_or(DecapError::MalformedInner)?;
        let peer_idx = self
            .peer_index(&session.peer_pubkey)
            .ok_or(DecapError::UnknownSession)?;
        let allowed = self.allowed_ips.read().unwrap();
        if !allowed.matches_for_peer(inner_src, peer_idx) {
            return Err(DecapError::AllowedIpsViolation);
        }
        Ok(DecapOutcome {
            len: n,
            peer_pubkey: session.peer_pubkey,
        })
    }

    /// Build a snow `HandshakeState` configured as the initiator
    /// toward `peer_pubkey`. The caller drives the handshake to
    /// completion (write init, read response) and then uses
    /// `into_stateless_transport_mode` to obtain the
    /// `StatelessTransportState` that `install_session` wraps.
    ///
    /// Slow path only.
    pub(crate) fn build_initiator_handshake(
        &self,
        peer_pubkey: &[u8; 32],
    ) -> Result<HandshakeState, snow::Error> {
        Builder::new(WG_NOISE_PATTERN.parse()?)
            .local_private_key(&self.local_private_key)?
            .remote_public_key(peer_pubkey)?
            .build_initiator()
    }

    /// Build a snow `HandshakeState` configured as the responder.
    /// Slow path only.
    pub(crate) fn build_responder_handshake(&self) -> Result<HandshakeState, snow::Error> {
        Builder::new(WG_NOISE_PATTERN.parse()?)
            .local_private_key(&self.local_private_key)?
            .build_responder()
    }
}

/// Extract the source IP from the front of an inner-IP packet.
/// Used for the AllowedIPs receive-side gate. Returns `None` for
/// unsupported / malformed inputs.
fn inner_src_ip(pkt: &[u8]) -> Option<IpAddr> {
    let version = pkt.first()? >> 4;
    match version {
        4 => {
            if pkt.len() < 20 {
                return None;
            }
            Some(IpAddr::V4(Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15])))
        }
        6 => {
            if pkt.len() < 40 {
                return None;
            }
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&pkt[8..24]);
            Some(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
        _ => None,
    }
}

#[cfg(test)]
mod engine_internal_tests {
    use super::*;

    #[test]
    fn inner_src_ip_v4() {
        let mut pkt = [0u8; 40];
        pkt[0] = 0x45;
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        assert_eq!(
            inner_src_ip(&pkt),
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        );
    }

    #[test]
    fn inner_src_ip_v6() {
        let mut pkt = [0u8; 40];
        pkt[0] = 0x60;
        pkt[8] = 0xfe;
        pkt[9] = 0x80;
        let got = inner_src_ip(&pkt).unwrap();
        match got {
            IpAddr::V6(v6) => assert_eq!(v6.segments()[0], 0xfe80),
            _ => panic!("expected v6"),
        }
    }

    #[test]
    fn inner_src_ip_rejects_short() {
        assert!(inner_src_ip(&[0x45u8; 10]).is_none());
        assert!(inner_src_ip(&[0x60u8; 20]).is_none());
        assert!(inner_src_ip(&[]).is_none());
    }

    #[test]
    fn inner_src_ip_rejects_unknown_version() {
        assert!(inner_src_ip(&[0x05u8; 40]).is_none()); // bogus version 0
    }
}
