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
use super::session::{REJECT_AFTER_MESSAGES, ReplayDecision, WgSession};
use super::{POLY1305_TAG_LEN, WG_DATA_HEADER_LEN, WG_NOISE_PATTERN, WG_ZERO_PSK};
use rustc_hash::FxHashMap;
use snow::{Builder, HandshakeState};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, RwLock};
use zeroize::Zeroizing;

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
    /// Session exceeded WG's reject-after-messages bound.
    RekeyRequired,
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

/// Errors that can fail the slow-path session install.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InstallSessionError {
    /// The caller-supplied peer pubkey is not in the engine table.
    UnknownPeer,
    /// The caller-supplied `local_index` is already mapped to a
    /// different live session. The caller must retry handshake
    /// completion with a fresh `local_index`. Silently overwriting
    /// the existing session would blackhole its inbound traffic.
    LocalIndexCollision,
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
    /// Counter is at or above `REJECT_AFTER_MESSAGES`. Per WG spec
    /// §6.5 the receiver MUST reject these without attempting AEAD.
    CounterRejectAfterMessages,
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

/// Stack scratch for the padded plaintext on the encap path. Sized
/// to cover a 4 KiB jumbo-MTU inner packet plus the worst-case 15
/// bytes of padding. We use a fixed stack buffer rather than the
/// caller's `out` because `out` is the post-AEAD destination — snow
/// requires non-overlapping plaintext/ciphertext slices. Stack
/// allocation has zero per-packet cost.
const PADDED_PLAINTEXT_MAX: usize = 4096 + 16;

/// Round `n` up to the nearest multiple of 16. WG spec §5.4.6.
#[inline]
const fn pad_to_16(n: usize) -> usize {
    (n + 15) & !15
}

/// The engine.
pub(crate) struct WgEngine {
    /// Local X25519 private key. Held in the engine because every
    /// slow-path handshake needs it. Wrapped in `Zeroizing` so the
    /// 32 bytes of key material are wiped on engine drop — kernel
    /// WG and wireguard-go both do this. snow internally zeroizes
    /// its own copies; this is for the engine's persistent copy.
    local_private_key: Zeroizing<[u8; 32]>,
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
            local_private_key: Zeroizing::new(config.local_private_key),
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
    ///
    /// Returns `Err(InstallSessionError::LocalIndexCollision)` if the
    /// caller's chosen `local_index` is already in the demux map for
    /// a *different* session (different `Arc` identity). The slow-path
    /// integration must retry handshake completion with a fresh
    /// receiver_index when this fires; silently overwriting an
    /// existing session would blackhole all of its inbound traffic.
    /// See `try_decap` path for why the demux key must be unique
    /// across live sessions.
    pub(crate) fn install_session(
        &self,
        pubkey: &[u8; 32],
        session: Arc<WgSession>,
    ) -> Result<(), InstallSessionError> {
        let Some(peer) = self.peer_arc(pubkey) else {
            return Err(InstallSessionError::UnknownPeer);
        };
        // Register for inbound demux BEFORE rotation so decap can
        // resolve the new local index immediately (closes the decap-
        // blackhole window that earlier rotate-first ordering had).
        //
        // Three concerns:
        //   (a) If the same `local_index` is already mapped to a
        //       different session, refuse the install rather than
        //       silently overwriting it.
        //   (b) After rotation, the dropped-previous session must be
        //       removed from the demux map — but ONLY if its
        //       `local_index` differs from the new session's (the
        //       re-handshake-on-same-index case), otherwise the
        //       remove kills the entry we just inserted.
        //   (c) The demux insert and rotate must be visible together.
        //       Holding the demux write lock across rotate_session is
        //       safe (peer.current/previous have separate locks) and
        //       gives a single atomic transition.
        let new_local_index = session.local_index;
        let mut by_index = self.sessions_by_local_index.write().unwrap();
        // Collision check: an existing entry with the same local_index
        // is only acceptable if it belongs to the SAME peer (i.e. a
        // re-handshake / rekey landed on the same caller-chosen
        // receiver_index, which is benign — the new session simply
        // replaces the old one). An entry owned by a DIFFERENT peer
        // is a real collision and we must refuse the install rather
        // than silently overwrite the other peer's live session.
        if let Some(existing) = by_index.get(&new_local_index)
            && existing.peer_pubkey != session.peer_pubkey
        {
            return Err(InstallSessionError::LocalIndexCollision);
        }
        by_index.insert(new_local_index, session.clone());
        let dropped_previous = peer.rotate_session(session);
        if let Some(old) = dropped_previous
            && old.local_index != new_local_index
        {
            by_index.remove(&old.local_index);
        }
        Ok(())
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

        // WG spec §5.4.6 mandates the plaintext be zero-padded to a
        // 16-byte multiple before AEAD. This obscures inner packet
        // lengths and is required for wire interoperability with
        // kernel WG / wireguard-go. Compute the padded length and
        // ensure the output buffer can hold header + ciphertext +
        // tag at the padded size.
        let padded_len = pad_to_16(inner_ip.len());
        let required = WG_DATA_HEADER_LEN + padded_len + POLY1305_TAG_LEN;
        if out.len() < required {
            return Err(EncapError::BufferTooSmall);
        }
        let counter = session.next_tx_counter().ok_or(EncapError::RekeyRequired)?;
        let _ = encode_data_header(out, session.peer_index, counter)
            .ok_or(EncapError::BufferTooSmall)?;
        // Stage the padded plaintext in the output buffer immediately
        // after the (eventual) ciphertext region. We do NOT allocate;
        // we reuse a scratch zone at the END of `out` that is past
        // `required`. If the caller sized `out` exactly to `required`
        // (the worker scratch path always does this), we instead pad
        // in-place at the front of the payload region BEFORE handing
        // it to snow. Strategy: write zeros after `inner_ip` into the
        // pre-AEAD slot, then have snow encrypt the padded region.
        //
        // Implementation: pre-AEAD plaintext lives in `out[WG_DATA_HEADER_LEN..WG_DATA_HEADER_LEN+padded_len]`.
        // We can't overlap with snow's output of the same range, so
        // we use a small stack-allocated scratch for the padded
        // plaintext. The WG MTU bound puts the inner packet at
        // <=1500 bytes; we use a 4 KiB stack buffer to cover jumbo
        // MTU configurations comfortably.
        let mut plaintext = [0u8; PADDED_PLAINTEXT_MAX];
        if padded_len > plaintext.len() {
            return Err(EncapError::BufferTooSmall);
        }
        plaintext[..inner_ip.len()].copy_from_slice(inner_ip);
        // Bytes [inner_ip.len()..padded_len] are already zero from
        // the array initializer.
        let (_hdr, payload) = out.split_at_mut(WG_DATA_HEADER_LEN);
        let n = session
            .transport
            .write_message(counter, &plaintext[..padded_len], payload)
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
        // WG spec §6.5: drop inbound data packets whose counter is
        // at or above REJECT_AFTER_MESSAGES without doing AEAD. The
        // counter-space ceiling is symmetric across encap/decap;
        // the encap-side guard alone is not sufficient because a
        // malicious or buggy sender may send arbitrary high counters.
        if hdr.counter >= REJECT_AFTER_MESSAGES {
            return Err(DecapError::CounterRejectAfterMessages);
        }
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
        {
            let replay = session.replay.lock().unwrap();
            if replay.definitely_out_of_window(hdr.counter) {
                return Err(DecapError::ReplayOutOfWindow);
            }
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
                ReplayDecision::Repeat => {
                    // Authentic but replayed: snow has already written
                    // plaintext into `out[..n]`. Zero the staging
                    // region before returning so a caller that
                    // mishandles the error path cannot leak the
                    // plaintext upstream. Cost is one memset per
                    // replay-reject — the rare path.
                    out[..n].fill(0);
                    return Err(DecapError::ReplayDuplicate);
                }
                ReplayDecision::OutOfWindow => {
                    out[..n].fill(0);
                    return Err(DecapError::ReplayOutOfWindow);
                }
            }
        }
        // AllowedIPs gate on the inner src IP. WG spec §5.4.6:
        // "After decryption, the receiver verifies that the source
        // IP of the inner packet belongs to the peer who sent it.
        // If not, drop." This is the cryptokey-routing safety
        // invariant on the receive side.
        //
        // WG transport messages are zero-padded to 16-byte multiples
        // before AEAD on send; strip trailing zero padding before we
        // hand the plaintext to the inner-IP parser, otherwise an
        // IPv4 packet whose `total_length` is shorter than the
        // padded ciphertext will still parse correctly (we parse the
        // src IP from the IPv4 header at byte offset 12..16, which
        // is well before any padding) but downstream consumers will
        // see trailing zero bytes that aren't part of the original
        // packet. We do not truncate `n` here — the caller is
        // expected to consult the inner IP header's length field —
        // but the parse below is robust to extra trailing bytes.
        let inner_src = inner_src_ip(&out[..n]).ok_or(DecapError::MalformedInner)?;
        let peer_idx = self
            .peer_index(&session.peer_pubkey)
            .ok_or(DecapError::UnknownSession)?;
        let allowed = self.allowed_ips.read().unwrap();
        if !allowed.matches_for_peer(inner_src, peer_idx) {
            // Defensive: zero the plaintext we just authenticated
            // but cannot deliver, to keep the contract "on Err the
            // caller MUST NOT inspect `out`" tight.
            out[..n].fill(0);
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
            .local_private_key(self.local_private_key.as_slice())?
            .remote_public_key(peer_pubkey)?
            .psk(2, &WG_ZERO_PSK)?
            .build_initiator()
    }

    /// Build a snow `HandshakeState` configured as the responder.
    /// Slow path only.
    ///
    /// TODO(#1499 r4 / responder-peer-id): the integration layer
    /// needs a thin helper that (a) builds this responder state,
    /// (b) reads the init message, (c) calls
    /// `HandshakeState::get_remote_static` to learn which peer sent
    /// the init, and (d) looks up the peer in the engine table.
    /// snow already supports step (c); we just haven't surfaced a
    /// convenience API yet. Adding it here would couple the engine
    /// to the snow message-bytes parser which is integration-layer
    /// concern. Tracked for the integration PR.
    pub(crate) fn build_responder_handshake(&self) -> Result<HandshakeState, snow::Error> {
        Builder::new(WG_NOISE_PATTERN.parse()?)
            .local_private_key(self.local_private_key.as_slice())?
            .psk(2, &WG_ZERO_PSK)?
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
            Some(IpAddr::V4(Ipv4Addr::new(
                pkt[12], pkt[13], pkt[14], pkt[15],
            )))
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
    use std::str::FromStr;
    use std::sync::atomic::Ordering;

    fn keypair() -> ([u8; 32], [u8; 32]) {
        let kp = Builder::new(WG_NOISE_PATTERN.parse().unwrap())
            .generate_keypair()
            .unwrap();
        let mut priv_k = [0u8; 32];
        let mut pub_k = [0u8; 32];
        priv_k.copy_from_slice(&kp.private);
        pub_k.copy_from_slice(&kp.public);
        (priv_k, pub_k)
    }

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

    /// Drive a real IK handshake between two engines and return the
    /// initiator-side transport session. Helper used by the
    /// install_session unit tests below — going through snow is
    /// cheaper than a separate mock and keeps the test honest.
    fn make_session_for(
        engine: &WgEngine,
        peer_pub: [u8; 32],
        peer_engine: &WgEngine,
        local_index: u32,
        peer_index: u32,
    ) -> Arc<WgSession> {
        let mut init_hs = engine.build_initiator_handshake(&peer_pub).unwrap();
        let mut resp_hs = peer_engine.build_responder_handshake().unwrap();
        let mut buf = [0u8; 1024];
        let mut sink = [0u8; 1024];
        let n1 = init_hs.write_message(&[], &mut buf).unwrap();
        resp_hs.read_message(&buf[..n1], &mut sink).unwrap();
        let n2 = resp_hs.write_message(&[], &mut buf).unwrap();
        init_hs.read_message(&buf[..n2], &mut sink).unwrap();
        let xport = init_hs.into_stateless_transport_mode().unwrap();
        Arc::new(WgSession::new(xport, local_index, peer_index, peer_pub))
    }

    /// Regression: re-handshake on the SAME `local_index` must keep
    /// the new session in the demux map, not get it nuked by the
    /// dropped-previous cleanup. r3 introduced a same-index aliasing
    /// bug where remove(&old.local_index) silently deleted the entry
    /// the new session had just installed.
    #[test]
    fn install_session_same_local_index_keeps_new_session_in_demux() {
        let (init_priv, _init_pub) = keypair();
        let (peer_priv, peer_pub) = keypair();
        let engine = WgEngine::new(WgEngineConfig {
            local_private_key: init_priv,
            listen_port: 51820,
            peers: vec![WgPeerConfig {
                pubkey: peer_pub,
                endpoint: None,
                persistent_keepalive: 0,
                allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
            }],
        });
        let peer_engine = WgEngine::new(WgEngineConfig {
            local_private_key: peer_priv,
            listen_port: 51820,
            peers: vec![WgPeerConfig {
                pubkey: [0u8; 32],
                endpoint: None,
                persistent_keepalive: 0,
                allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
            }],
        });
        let s1 = make_session_for(&engine, peer_pub, &peer_engine, 0xaaaa_0001, 2);
        engine.install_session(&peer_pub, s1).unwrap();
        // Re-handshake with the SAME local_index (e.g. rekey
        // happened to land on the same caller-chosen receiver_index).
        let s2 = make_session_for(&engine, peer_pub, &peer_engine, 0xaaaa_0001, 3);
        let s2_ptr = Arc::as_ptr(&s2);
        engine.install_session(&peer_pub, s2).unwrap();
        let by_index = engine.sessions_by_local_index.read().unwrap();
        let live = by_index
            .get(&0xaaaa_0001)
            .expect("new session must still be in demux map");
        assert_eq!(Arc::as_ptr(live), s2_ptr);
    }

    /// Collision detection: installing two distinct sessions with the
    /// same `local_index` for DIFFERENT peers (or stale handshake
    /// race) must return LocalIndexCollision rather than silently
    /// overwriting the existing entry.
    #[test]
    fn install_session_rejects_local_index_collision_across_peers() {
        let (init_priv, _init_pub) = keypair();
        let (peer_a_priv, peer_a_pub) = keypair();
        let (peer_b_priv, peer_b_pub) = keypair();
        let engine = WgEngine::new(WgEngineConfig {
            local_private_key: init_priv,
            listen_port: 51820,
            peers: vec![
                WgPeerConfig {
                    pubkey: peer_a_pub,
                    endpoint: None,
                    persistent_keepalive: 0,
                    allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
                },
                WgPeerConfig {
                    pubkey: peer_b_pub,
                    endpoint: None,
                    persistent_keepalive: 0,
                    allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
                },
            ],
        });
        let peer_a_engine = WgEngine::new(WgEngineConfig {
            local_private_key: peer_a_priv,
            listen_port: 51820,
            peers: vec![WgPeerConfig {
                pubkey: [0u8; 32],
                endpoint: None,
                persistent_keepalive: 0,
                allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
            }],
        });
        let peer_b_engine = WgEngine::new(WgEngineConfig {
            local_private_key: peer_b_priv,
            listen_port: 51820,
            peers: vec![WgPeerConfig {
                pubkey: [0u8; 32],
                endpoint: None,
                persistent_keepalive: 0,
                allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
            }],
        });
        let sa = make_session_for(&engine, peer_a_pub, &peer_a_engine, 0x1234_5678, 2);
        let sa_ptr = Arc::as_ptr(&sa);
        engine.install_session(&peer_a_pub, sa).unwrap();
        let sb = make_session_for(&engine, peer_b_pub, &peer_b_engine, 0x1234_5678, 3);
        let err = engine.install_session(&peer_b_pub, sb).unwrap_err();
        assert_eq!(err, InstallSessionError::LocalIndexCollision);
        // Peer A's session must still be the one in the demux map.
        let by_index = engine.sessions_by_local_index.read().unwrap();
        assert_eq!(
            Arc::as_ptr(by_index.get(&0x1234_5678).unwrap()),
            sa_ptr,
            "collision must NOT overwrite the existing session"
        );
    }

    #[test]
    fn encap_rejects_after_message_limit() {
        let (init_priv, _init_pub) = keypair();
        let (peer_priv, peer_pub) = keypair();
        let engine = WgEngine::new(WgEngineConfig {
            local_private_key: init_priv,
            listen_port: 51820,
            peers: vec![WgPeerConfig {
                pubkey: peer_pub,
                endpoint: None,
                persistent_keepalive: 0,
                allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
            }],
        });
        let resp = WgEngine::new(WgEngineConfig {
            local_private_key: peer_priv,
            listen_port: 51820,
            peers: vec![WgPeerConfig {
                pubkey: [0u8; 32],
                endpoint: None,
                persistent_keepalive: 0,
                allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
            }],
        });
        let mut init_hs = engine.build_initiator_handshake(&peer_pub).unwrap();
        let mut resp_hs = resp.build_responder_handshake().unwrap();
        let mut buf = [0u8; 1024];
        let mut sink = [0u8; 1024];
        let n1 = init_hs.write_message(&[], &mut buf).unwrap();
        resp_hs.read_message(&buf[..n1], &mut sink).unwrap();
        let n2 = resp_hs.write_message(&[], &mut buf).unwrap();
        init_hs.read_message(&buf[..n2], &mut sink).unwrap();
        let session = Arc::new(WgSession::new(
            init_hs.into_stateless_transport_mode().unwrap(),
            1,
            2,
            peer_pub,
        ));
        session.tx_counter.store(
            super::super::session::REJECT_AFTER_MESSAGES,
            Ordering::Relaxed,
        );
        engine.install_session(&peer_pub, session).unwrap();
        let inner = [
            0x45u8, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
        ];
        let mut out = [0u8; 128];
        let err = engine.try_encap(&peer_pub, &inner, &mut out).unwrap_err();
        assert_eq!(err, EncapError::RekeyRequired);
    }
}
