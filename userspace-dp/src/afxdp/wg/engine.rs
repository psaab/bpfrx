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
use std::mem::MaybeUninit;
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
    /// live session (any peer). The caller must retry handshake
    /// completion with a fresh `local_index`. Silently overwriting
    /// the existing session — even for the same peer — would
    /// blackhole the in-flight ciphertexts of the rotated-out
    /// `previous` session, which the demux map would no longer be
    /// able to resolve.
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
    /// Length of the un-padded inner-IP packet written at the front
    /// of the caller's `out` buffer. This is the IPv4 `total_length`
    /// / IPv6 `40 + payload_length`, NOT the WG §5.4.6 padded
    /// plaintext length that snow authenticated. The bytes beyond
    /// `len` and before `len + padding` (0..15 bytes) are zero
    /// padding bytes that the receive path has already verified.
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

/// Stack scratch capacity for the padded plaintext on the encap
/// path. Sized to cover an inner IP packet up to `PADDED_PLAINTEXT_MAX
/// - 15` bytes plus the worst-case 15 bytes of WG spec §5.4.6
/// padding. We stage the padded plaintext on the stack rather than
/// inside the caller's `out` buffer because snow's `write_message`
/// requires non-overlapping plaintext and ciphertext slices.
///
/// The buffer is materialized as `MaybeUninit<[u8; PADDED_PLAINTEXT_MAX]>`
/// and only the bytes that snow actually reads are initialized
/// (the `inner_ip.len()` bytes copied from the caller plus the
/// trailing 0..15 padding bytes). This avoids the 4112-byte memset
/// per call that a `[0u8; N]` array-init would force LLVM to emit
/// (LLVM cannot elide the zero-init because snow reads the trailing
/// pad bytes, which must be zero by spec).
///
/// Note on jumbo MTU: the value is 4080 + 16 padding = 4096. Inner
/// packets larger than 4080 bytes will return `EncapError::BufferTooSmall`.
/// Jumbo MTU configurations (>4080 inner) are not currently
/// supported by this engine; raising the bound is a one-line change
/// when the integration layer needs it.
const PADDED_PLAINTEXT_MAX: usize = 4080 + 16;

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
    /// any live session — regardless of which peer owns the existing
    /// entry. WG local indices must be globally unique across every
    /// live (current, previous) session this engine owns; same-peer
    /// rekey collisions are just as fatal as cross-peer collisions
    /// because rotation moves the existing current into `previous`,
    /// and the demux map can only carry one entry per index. The
    /// slow-path installer must retry handshake completion with a
    /// fresh receiver_index when this fires.
    pub(crate) fn install_session(
        &self,
        pubkey: &[u8; 32],
        session: Arc<WgSession>,
    ) -> Result<(), InstallSessionError> {
        let Some(peer) = self.peer_arc(pubkey) else {
            return Err(InstallSessionError::UnknownPeer);
        };
        // Refuse ANY same-key collision in the demux map. Local
        // indices must be unique across every live session this
        // engine owns — same-peer collisions are just as fatal as
        // cross-peer ones because rotation moves the existing
        // current session into `previous`, and inbound packets that
        // still address the previous session would demux to the new
        // session, fail AEAD, and silently drop. The slow-path
        // session installer is responsible for picking a fresh
        // `local_index` (the 32-bit random allocator already does
        // this trivially in expectation; a collision means the
        // caller must regenerate and retry).
        //
        // After the demux insert, rotate_session() returns whichever
        // session falls off the (current, previous) pair. That
        // dropped session MUST then be removed from the demux map,
        // and because the new session's local_index is now unique by
        // construction, the remove cannot accidentally evict the
        // entry we just inserted. The single-locked-region pattern
        // keeps the (demux, current, previous) triple visible
        // together to any subsequent decap.
        let new_local_index = session.local_index;
        let mut by_index = self.sessions_by_local_index.write().unwrap();
        if by_index.contains_key(&new_local_index) {
            return Err(InstallSessionError::LocalIndexCollision);
        }
        by_index.insert(new_local_index, session.clone());
        let dropped_previous = peer.rotate_session(session);
        if let Some(old) = dropped_previous {
            // `old.local_index != new_local_index` is guaranteed by
            // the uniqueness check above; the explicit assert keeps
            // the invariant visible if a future change ever relaxes
            // the collision rule.
            debug_assert_ne!(old.local_index, new_local_index);
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
        // Stage the padded plaintext on the stack. We use
        // `MaybeUninit` and only initialize the bytes snow will read
        // (`inner_ip.len()` of payload + the worst-case 15 padding
        // bytes), which avoids the 4112-byte memset-per-call that a
        // `[0u8; N]` array initializer would force LLVM to emit on
        // the hot path. snow's `write_message` requires
        // non-overlapping plaintext and ciphertext slices, so we
        // cannot stage the plaintext inside `out`.
        if padded_len > PADDED_PLAINTEXT_MAX {
            return Err(EncapError::BufferTooSmall);
        }
        let mut plaintext_uninit: MaybeUninit<[u8; PADDED_PLAINTEXT_MAX]> = MaybeUninit::uninit();
        // SAFETY: we cast the `MaybeUninit<[u8; N]>` to `&mut [u8; N]`
        // before writing every byte we intend to read. The bytes
        // outside `[0..padded_len]` are never read (snow only
        // touches `[..padded_len]`), so leaving them uninitialized
        // is sound. We initialize:
        //   - `[0..inner_ip.len()]` with the caller's payload
        //   - `[inner_ip.len()..padded_len]` with zeros (WG spec
        //     §5.4.6 requires the padding be zero bytes)
        let plaintext_ref: &mut [u8; PADDED_PLAINTEXT_MAX] =
            unsafe { &mut *plaintext_uninit.as_mut_ptr() };
        plaintext_ref[..inner_ip.len()].copy_from_slice(inner_ip);
        // Trailing padding: at most 15 bytes. WG spec §5.4.6 requires
        // the padding be zero.
        for b in &mut plaintext_ref[inner_ip.len()..padded_len] {
            *b = 0;
        }
        // SAFETY: `[0..padded_len]` is fully initialized (payload +
        // zero padding above); we hand snow a slice limited to that
        // range, which is the only memory it reads.
        let plaintext = &plaintext_ref[..padded_len];
        let (_hdr, payload) = out.split_at_mut(WG_DATA_HEADER_LEN);
        let n = session
            .transport
            .write_message(counter, plaintext, payload)
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
        // Every error arm past `read_message` MUST zero `out[..n]`
        // before returning so the contract "on Err the caller MUST
        // NOT inspect `out`" is structurally enforced. We use a
        // single fall-through with the helper below; adding a new
        // post-AEAD error arm cannot accidentally skip the wipe.
        //
        // The plaintext is the padded form (WG §5.4.6 zero-padded
        // to a 16-byte multiple at the sender). We parse src IP
        // from the IPv4/IPv6 header's fixed offset, which is well
        // before any padding bytes. The returned `inner_ip_len`
        // truncates `n` down to the real inner-IP packet length;
        // see `inner_ip_len_after_decap` for the IPv4
        // `total_length` / IPv6 `payload_length` math. The caller
        // sees only the un-padded inner-IP packet.
        let outcome = (|| -> Result<(IpAddr, u32, usize), DecapError> {
            let inner_src = inner_src_ip(&out[..n]).ok_or(DecapError::MalformedInner)?;
            let peer_idx = self
                .peer_index(&session.peer_pubkey)
                .ok_or(DecapError::UnknownSession)?;
            let allowed = self.allowed_ips.read().unwrap();
            if !allowed.matches_for_peer(inner_src, peer_idx) {
                return Err(DecapError::AllowedIpsViolation);
            }
            let inner_len = inner_ip_len_after_decap(&out[..n])
                .ok_or(DecapError::MalformedInner)?;
            Ok((inner_src, peer_idx, inner_len))
        })();
        match outcome {
            Ok((_inner_src, _peer_idx, inner_len)) => {
                debug_assert!(inner_len <= n);
                Ok(DecapOutcome {
                    len: inner_len,
                    peer_pubkey: session.peer_pubkey,
                })
            }
            Err(e) => {
                // Defensive: zero the plaintext we just authenticated
                // but cannot deliver. Covers MalformedInner,
                // UnknownSession, and AllowedIpsViolation uniformly.
                out[..n].fill(0);
                Err(e)
            }
        }
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

/// Read the inner-IP packet's total length from its own header, so
/// the caller of `try_decap` receives the un-padded inner-IP packet
/// length (not the §5.4.6 padded plaintext length that snow
/// authenticated). The decrypted plaintext is `padded_inner_ip ||
/// zeros_up_to_16_byte_multiple`; trimming to the on-the-wire
/// inner-IP length here means downstream consumers never see WG's
/// padding bytes.
///
/// Returns `None` if:
///   - the buffer is too short for an IPv4/IPv6 header,
///   - the IP `version` nibble is something other than 4 or 6,
///   - the header-declared length exceeds the decrypted buffer
///     (the sender lied or the AEAD verified a malformed packet —
///     either way, drop).
fn inner_ip_len_after_decap(pkt: &[u8]) -> Option<usize> {
    let version = pkt.first()? >> 4;
    let claimed = match version {
        4 => {
            if pkt.len() < 20 {
                return None;
            }
            u16::from_be_bytes([pkt[2], pkt[3]]) as usize
        }
        6 => {
            if pkt.len() < 40 {
                return None;
            }
            // IPv6 header fixed at 40; payload_length is bytes 4..6.
            40 + u16::from_be_bytes([pkt[4], pkt[5]]) as usize
        }
        _ => return None,
    };
    // The claimed length must fit inside what we decrypted, and the
    // remaining bytes (the §5.4.6 padding) must all be zero.
    if claimed > pkt.len() {
        return None;
    }
    if pkt[claimed..].iter().any(|&b| b != 0) {
        return None;
    }
    Some(claimed)
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

    /// Same-peer same-local-index collision must be refused. Letting
    /// it through would move the existing current session into
    /// `previous`, but rewrite its demux entry to point at the new
    /// session — in-flight ciphertexts addressed to the previous
    /// session (which legitimately still decode against its key
    /// during the rotation grace window) would demux to the new
    /// session, fail AEAD, and drop silently. Codex r4 finding 1 /
    /// Gemini r4 finding B. r3's test (now removed) blessed this
    /// wrong behavior.
    #[test]
    fn install_session_same_peer_same_local_index_is_collision() {
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
        let s1_ptr = Arc::as_ptr(&s1);
        engine.install_session(&peer_pub, s1).unwrap();
        // Re-handshake with the SAME local_index for the SAME peer
        // must be rejected with LocalIndexCollision.
        let s2 = make_session_for(&engine, peer_pub, &peer_engine, 0xaaaa_0001, 3);
        let err = engine.install_session(&peer_pub, s2).unwrap_err();
        assert_eq!(err, InstallSessionError::LocalIndexCollision);
        // The original session must still be the demux target.
        let by_index = engine.sessions_by_local_index.read().unwrap();
        assert_eq!(
            Arc::as_ptr(by_index.get(&0xaaaa_0001).unwrap()),
            s1_ptr,
            "collision must NOT overwrite the existing same-peer session"
        );
    }

    /// Successful same-peer rekey on a FRESH `local_index` must:
    ///   (a) succeed,
    ///   (b) leave the new session as the demux target for the new
    ///       index,
    ///   (c) leave the old session still demuxable on its old index
    ///       (it has rotated to `previous` and continues to receive
    ///       in-flight ciphertexts until the next rotation).
    #[test]
    fn install_session_fresh_index_rekey_preserves_previous_demux() {
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
        let s1_ptr = Arc::as_ptr(&s1);
        engine.install_session(&peer_pub, s1).unwrap();
        let s2 = make_session_for(&engine, peer_pub, &peer_engine, 0xaaaa_0002, 3);
        let s2_ptr = Arc::as_ptr(&s2);
        engine.install_session(&peer_pub, s2).unwrap();
        let by_index = engine.sessions_by_local_index.read().unwrap();
        // New session is demuxable on the new index.
        assert_eq!(Arc::as_ptr(by_index.get(&0xaaaa_0002).unwrap()), s2_ptr);
        // Old session is still demuxable on the old index (rotated
        // to `previous`, not dropped yet).
        assert_eq!(Arc::as_ptr(by_index.get(&0xaaaa_0001).unwrap()), s1_ptr);
    }

    /// A second rekey (s3 on a third fresh index) drops s1 out of
    /// (current, previous). The engine must then remove s1's demux
    /// entry so its index can be reused for future handshakes.
    #[test]
    fn install_session_second_rekey_evicts_dropped_session() {
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
        let s2 = make_session_for(&engine, peer_pub, &peer_engine, 0xaaaa_0002, 3);
        engine.install_session(&peer_pub, s2).unwrap();
        let s3 = make_session_for(&engine, peer_pub, &peer_engine, 0xaaaa_0003, 4);
        engine.install_session(&peer_pub, s3).unwrap();
        let by_index = engine.sessions_by_local_index.read().unwrap();
        assert!(
            by_index.get(&0xaaaa_0001).is_none(),
            "s1 must be evicted from demux after second rotation drops it"
        );
        assert!(by_index.get(&0xaaaa_0002).is_some());
        assert!(by_index.get(&0xaaaa_0003).is_some());
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
