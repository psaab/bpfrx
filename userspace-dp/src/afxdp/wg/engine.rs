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
//!   - `build_initiator_handshake` / `build_responder_handshake` —
//!     slow path. Construct a snow `HandshakeState` configured with
//!     the WG protocol prologue and (for the initiator) the peer's
//!     remote static key. The caller pumps the handshake by feeding
//!     wire bytes through `read_message` / `write_message`, converts
//!     to a `StatelessTransportState` via `into_stateless_transport_mode`,
//!     and installs the resulting session via `install_session`.
//!
//! Out of scope for this engine (integration PR owns these):
//!   - Building / parsing the on-wire WG handshake framing
//!     (MessageInitiation/MessageResponse: MAC1 over a hash of the
//!     responder's public key, MAC2 cookie reply when under load,
//!     TAI64N timestamp inside the IK payload). This engine only
//!     builds and consumes the snow sub-message bytes — the integration
//!     PR will wrap them in the WG type-1/type-2 outer framing.
//!   - Data-record on-wire framing extras beyond `framing.rs`
//!     (cookie messages, keepalives that double as data records).
//!   - Outer-UDP IO and routing.
//!
//! Hot path discipline:
//!   - No allocations. snow's `write_message` / `read_message` take
//!     pre-sized slices.
//!   - No locks held across crypto operations on the encrypt path
//!     (we clone the `Arc<WgSession>` and release the peer lock).
//!   - Decrypt path takes the per-session replay-window mutex twice:
//!     once for the pre-AEAD `definitely_out_of_window` precheck, and
//!     once for the post-AEAD `check_and_update`. The precheck is
//!     held to avoid paying for a snow decrypt on counters that are
//!     already provably stale — a hostile or replayed flood would
//!     otherwise burn the AEAD cost per packet. Contention is bounded
//!     because each session is demuxed onto a single worker, so the
//!     mutex is effectively a per-session-per-worker SPSC lock with
//!     no cross-worker traffic. (An earlier draft of this comment
//!     claimed the precheck-lock was taken "only on cold arms"; that
//!     was wrong — `try_decap` unconditionally locks the replay
//!     mutex before snow.read_message.)

use super::allowed_ips::AllowedIps;
use super::framing::{encode_data_header, parse_data_header};
use super::peer::Peer;
use super::session::{REJECT_AFTER_MESSAGES, ReplayDecision, WgSession};
use super::{
    POLY1305_TAG_LEN, WG_DATA_HEADER_LEN, WG_NOISE_PATTERN, WG_PROTOCOL_ID_BYTES, WG_ZERO_PSK,
};
use arc_swap::ArcSwap;
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
    /// Record's ciphertext field is shorter than the Poly1305 tag
    /// length. Snow's AEAD decrypt has no short-tag guard internally;
    /// passing a sub-tag ciphertext underflows `ciphertext.len() -
    /// TAGLEN` and panics on the subsequent slice op (release build)
    /// or directly via `usize` underflow assert (debug). Reject the
    /// record before invoking snow so a hostile peer cannot crash the
    /// AF_XDP worker by sending 16..31-byte UDP datagrams with a
    /// valid `receiver_index`.
    ShortRecord,
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

/// Atomically-swappable triple of peer-routing tables. The three
/// fields are reconciled together (a new config snapshot rebuilds
/// all three) and a hot-path reader must observe them as a unit, or
/// else it can pair a `peer_index` from the old map with a `peers`
/// entry from the new vec and route to the wrong peer. Holding three
/// independent RwLocks does NOT give that property: a reader can
/// release the index lock, the reconciler can swap, and then the
/// reader can acquire the peers lock on the new state. Bundling all
/// three behind a single `ArcSwap<PeerTable>` gives the reader an
/// atomic snapshot — every load returns an `Arc<PeerTable>` that is
/// internally consistent for its lifetime, and the writer publishes
/// the next snapshot in one release-store.
pub(crate) struct PeerTable {
    /// peer slab — one entry per configured peer. Indexed by the
    /// `peer_index` referenced from `allowed_ips`.
    pub(crate) peers: Vec<Arc<Peer>>,
    /// peer_pubkey → index in `peers`.
    pub(crate) peer_index_by_pubkey: FxHashMap<[u8; 32], u32>,
    /// AllowedIPs LPM. Only consulted on the decap path.
    pub(crate) allowed_ips: AllowedIps,
}

impl PeerTable {
    fn empty() -> Self {
        Self {
            peers: Vec::new(),
            peer_index_by_pubkey: FxHashMap::default(),
            allowed_ips: AllowedIps::new(),
        }
    }
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
    /// Combined peer-routing table behind a single ArcSwap. See
    /// `PeerTable` doc for the atomicity rationale.
    table: ArcSwap<PeerTable>,
    /// Slow-path serialization lock for peer-table mutation.
    /// `reconcile_peers` and `install_session` both take it to
    /// prevent stale-Arc install races across peer removal. Hot path
    /// does NOT take this lock — readers only touch `table` via
    /// `.load()`.
    reconcile_lock: std::sync::Mutex<()>,
    /// Demux map: receiver_index → session. Receiver indices are
    /// chosen locally at handshake time so they uniquely identify
    /// a session for as long as it lives. Kept out of `PeerTable`
    /// because session install / rotation is independent of peer
    /// reconcile; only peer REMOVAL touches both (we drain a
    /// dropped peer's sessions out of this map during reconcile).
    sessions_by_local_index: RwLock<FxHashMap<u32, Arc<WgSession>>>,
}

impl WgEngine {
    pub(crate) fn new(config: WgEngineConfig) -> Self {
        let engine = Self {
            local_private_key: Zeroizing::new(config.local_private_key),
            listen_port: config.listen_port,
            table: ArcSwap::from_pointee(PeerTable::empty()),
            reconcile_lock: std::sync::Mutex::new(()),
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
    ///
    /// Atomicity contract:
    ///   1. Build a fresh `PeerTable` off-line (no readers see partial
    ///      state).
    ///   2. Identify peers present in the old table but absent in the
    ///      new one. Drain their `(current, previous)` session
    ///      `local_index` entries from `sessions_by_local_index`
    ///      before publishing the new table — otherwise an inbound
    ///      packet targeting a removed peer's session would decrypt
    ///      successfully (the session Arc is still in the demux map),
    ///      then fail the AllowedIPs gate because the peer is no
    ///      longer in the index, and the demux entry would leak
    ///      forever.
    ///   3. `ArcSwap::store` publishes the new `PeerTable` in one
    ///      release-store. Subsequent `.load()` calls observe either
    ///      the entire old table or the entire new one — never a mix.
    pub(crate) fn reconcile_peers(&self, configs: &[WgPeerConfig]) {
        // Serialize concurrent reconciles. The lock does NOT gate the
        // hot path (readers take only the ArcSwap load).
        let _guard = self.reconcile_lock.lock().unwrap();
        let old = self.table.load_full();
        let mut new_peers: Vec<Arc<Peer>> = Vec::with_capacity(configs.len());
        let mut new_index: FxHashMap<[u8; 32], u32> = FxHashMap::default();
        let mut new_allowed = AllowedIps::new();
        for (i, cfg) in configs.iter().enumerate() {
            let idx = i as u32;
            let existing = old
                .peer_index_by_pubkey
                .get(&cfg.pubkey)
                .and_then(|old_idx| old.peers.get(*old_idx as usize).cloned());
            let peer = match existing {
                Some(p) => {
                    // Apply mutable-field updates in place. The peer
                    // Arc is reused so the (current, previous) session
                    // pair survives the commit. Without this in-place
                    // update, config changes to endpoint or persistent-
                    // keepalive on an existing pubkey would be silently
                    // ignored until the integration layer dropped and
                    // recreated the peer (which it does not). Codex
                    // final pre-merge finding 3.
                    p.update_config(cfg.endpoint, cfg.persistent_keepalive);
                    p
                }
                None => Arc::new(Peer::new(
                    cfg.pubkey,
                    cfg.endpoint,
                    cfg.persistent_keepalive,
                )),
            };
            new_peers.push(peer);
            // r7 Codex/Claude nit: duplicate pubkeys in `configs`
            // leave an orphan `Peer` in `new_peers` (unreachable via
            // pubkey lookup) and make `new_allowed` carry entries
            // indexed at the earlier duplicate's slot. The Go control
            // plane is supposed to reject duplicate pubkeys at config
            // validation; this `debug_assert` keeps the engine-side
            // invariant visible during development without panicking
            // production builds if the validation layer is bypassed.
            let prior = new_index.insert(cfg.pubkey, idx);
            debug_assert!(
                prior.is_none(),
                "duplicate peer pubkey in reconcile_peers configs (prior idx={prior:?}, new idx={idx})"
            );
            for cidr in &cfg.allowed_ips {
                new_allowed.insert(*cidr, idx);
            }
        }
        // Drain demux entries for peers that exist in `old` but not
        // in `new`. Walk old peers and check absence from new_index.
        // We collect `local_index` values under read locks on the
        // peer's `current`/`previous`, then drop those locks before
        // taking the demux write lock — this keeps the demux write
        // hold short and avoids any lock-order coupling with peer
        // session rotation.
        let mut dropped_indices: Vec<u32> = Vec::new();
        for (pubkey, old_idx) in old.peer_index_by_pubkey.iter() {
            if new_index.contains_key(pubkey) {
                continue;
            }
            let Some(peer) = old.peers.get(*old_idx as usize) else {
                continue;
            };
            if let Some(cur) = peer.current.read().unwrap().as_ref() {
                dropped_indices.push(cur.local_index);
            }
            if let Some(prev) = peer.previous.read().unwrap().as_ref() {
                dropped_indices.push(prev.local_index);
            }
        }
        if !dropped_indices.is_empty() {
            let mut by_index = self.sessions_by_local_index.write().unwrap();
            for li in &dropped_indices {
                by_index.remove(li);
            }
        }
        // Publish the new table. Atomic release-store; any reader
        // doing `.load()` after this point sees the new table whole.
        self.table.store(Arc::new(PeerTable {
            peers: new_peers,
            peer_index_by_pubkey: new_index,
            allowed_ips: new_allowed,
        }));
    }

    /// Take an atomic snapshot of the peer-routing table. Hot path.
    /// The returned `Arc<PeerTable>` is internally consistent for as
    /// long as the caller holds it.
    fn load_table(&self) -> Arc<PeerTable> {
        self.table.load_full()
    }

    /// Test-only accessor: same as `load_table`, exposed at module
    /// visibility so tests can reach `peer.endpoint()` /
    /// `peer.persistent_keepalive()` for the reconcile-updates-
    /// existing-peer regression. Not used on the hot path.
    #[cfg(test)]
    pub(crate) fn table_for_test(&self) -> Arc<PeerTable> {
        self.load_table()
    }

    fn peer_arc(&self, pubkey: &[u8; 32]) -> Option<Arc<Peer>> {
        let table = self.load_table();
        let idx = *table.peer_index_by_pubkey.get(pubkey)?;
        table.peers.get(idx as usize).cloned()
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
        // Serialize session installs with reconcile to avoid the
        // stale-Arc orphaning race:
        //   1) install loads `peer` from old snapshot
        //   2) reconcile removes that peer and publishes new snapshot
        //   3) install inserts demux entry against orphan peer Arc
        // Without serialization, that orphan demux entry can survive
        // future reconciles because the peer pubkey no longer exists
        // in published tables. This is slow path, so mutex cost is
        // acceptable and keeps install/reconcile linearizable.
        let _reconcile_guard = self.reconcile_lock.lock().unwrap();
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
        // WG key-confirmation: the responder MUST NOT send transport
        // data on a fresh session until it has authenticated the
        // initiator's first data packet. Treat an unconfirmed session
        // as `NoSession` so the caller falls through to its slow path
        // (typically: queue the packet, wait for the initiator to
        // send first). Initiator-role sessions are installed
        // pre-confirmed, so this gate only fires on the responder
        // side and only until the first valid inbound record. See
        // `WgSession::confirmed` doc for the rationale and Codex
        // final pre-merge finding 2 for the missed invariant.
        if !session.is_confirmed() {
            return Err(EncapError::NoSession);
        }

        // WG spec §5.4.6 mandates the plaintext be zero-padded to a
        // 16-byte multiple before AEAD. This obscures inner packet
        // lengths and is required for wire interoperability with
        // kernel WG / wireguard-go. Compute the padded length and
        // ensure the output buffer can hold header + ciphertext +
        // tag at the padded size.
        //
        // All bound checks fire BEFORE any observable side effect
        // (counter advance, header write into `out`). Callers can
        // therefore rely on the contract "on Err, the output buffer
        // and the session's tx_counter are untouched". An oversized
        // `out` paired with an oversized `inner_ip` previously tripped
        // the PADDED_PLAINTEXT_MAX guard AFTER `next_tx_counter()`
        // had already advanced the counter; the staging guard is
        // hoisted above the counter consume to close that hole.
        let padded_len = pad_to_16(inner_ip.len());
        let required = WG_DATA_HEADER_LEN + padded_len + POLY1305_TAG_LEN;
        if out.len() < required {
            return Err(EncapError::BufferTooSmall);
        }
        if padded_len > PADDED_PLAINTEXT_MAX {
            return Err(EncapError::BufferTooSmall);
        }
        let counter = session.next_tx_counter().ok_or(EncapError::RekeyRequired)?;
        let _ = encode_data_header(out, session.peer_index, counter)
            .ok_or(EncapError::BufferTooSmall)?;
        // Stage the padded plaintext on the stack. We use
        // `MaybeUninit` to skip the 4096-byte zero-init that a
        // `[0u8; PADDED_PLAINTEXT_MAX]` literal would force on every
        // call. snow's `write_message` requires non-overlapping
        // plaintext and ciphertext slices, so we cannot stage the
        // plaintext inside `out`.
        //
        // Soundness: we NEVER materialize a `&mut [u8; N]` (or
        // `&mut [u8]`) over the uninitialized backing store —
        // creating a Rust reference to uninitialized memory is UB
        // even if the bytes are never read, because references carry
        // a validity invariant over their entire pointee. We only
        // write through the raw `*mut u8` returned by
        // `MaybeUninit::as_mut_ptr`, initializing exactly
        // `[0..padded_len]`. Once that range is initialized via raw
        // pointer writes, we hand snow a `&[u8]` (read-only slice)
        // limited to that initialized range — at which point the
        // reference covers fully-initialized memory and is sound.
        let mut plaintext_uninit: MaybeUninit<[u8; PADDED_PLAINTEXT_MAX]> = MaybeUninit::uninit();
        let plaintext_ptr = plaintext_uninit.as_mut_ptr() as *mut u8;
        // SAFETY:
        //   - `plaintext_ptr` is the start of a writable, properly
        //     aligned `[u8; PADDED_PLAINTEXT_MAX]` backing store on
        //     the current stack frame; it is unique (no aliasing
        //     reference exists — we never created one).
        //   - `inner_ip.len() <= padded_len <= PADDED_PLAINTEXT_MAX`,
        //     so `[0..inner_ip.len())` and
        //     `[inner_ip.len()..padded_len)` are non-overlapping
        //     in-bounds ranges of that store.
        //   - `inner_ip` is `&[u8]`, distinct from our local
        //     `plaintext_uninit`, so the copy source/dest do not
        //     alias.
        //   - After both calls, bytes `[0..padded_len)` are fully
        //     initialized: the payload from `inner_ip`, then
        //     `(padded_len - inner_ip.len()) <= 15` zero bytes (WG
        //     spec §5.4.6 padding).
        //   - Bytes `[padded_len..PADDED_PLAINTEXT_MAX)` remain
        //     uninitialized but are never read: we only borrow the
        //     initialized prefix below, and `plaintext_uninit` is
        //     dropped at end of scope without any further access.
        unsafe {
            std::ptr::copy_nonoverlapping(inner_ip.as_ptr(), plaintext_ptr, inner_ip.len());
            std::ptr::write_bytes(
                plaintext_ptr.add(inner_ip.len()),
                0u8,
                padded_len - inner_ip.len(),
            );
        }
        // SAFETY: `plaintext_ptr` is valid for `padded_len` bytes
        // (proved above) and those bytes are now initialized
        // (`copy_nonoverlapping` + `write_bytes`). Building a `&[u8]`
        // (immutable) over an initialized range is the standard
        // MaybeUninit "assume_init_ref-equivalent" pattern; we use
        // `from_raw_parts` here rather than `MaybeUninit::slice_assume_init_ref`
        // because the latter wants a `&[MaybeUninit<u8>]` source
        // slice which itself crosses the same validity boundary we
        // are avoiding. The returned slice is read-only and lives
        // only until snow consumes it on this line.
        let plaintext: &[u8] = unsafe { std::slice::from_raw_parts(plaintext_ptr, padded_len) };
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
        // Truncated-record DoS guard. `parse_data_header` only checks
        // that the buffer has at least WG_DATA_HEADER_LEN (16) bytes;
        // it does not enforce that the trailing ciphertext field is
        // at least one Poly1305 tag wide. Snow 0.10's ChaCha-Poly1305
        // decrypt computes `ciphertext.len() - TAGLEN` with no short-
        // tag guard — for `ciphertext.len() < POLY1305_TAG_LEN` this
        // wraps to a huge usize and panics on the subsequent slice op
        // (or underflows directly in debug builds). A hostile peer
        // with a known live `receiver_index` could crash the AF_XDP
        // worker by sending 16..31-byte UDP datagrams; remote
        // dataplane DoS. Reject sub-tag records here, before any of
        // the replay-window / snow code runs. Caught by Codex on the
        // r-final-2 review (the truncated-record class was missed by
        // all 9 prior review rounds).
        if hdr.ciphertext.len() < POLY1305_TAG_LEN {
            return Err(DecapError::ShortRecord);
        }
        let plaintext_len_max = hdr.ciphertext.len() - POLY1305_TAG_LEN;
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
        // WG key-confirmation: a successful AEAD authenticate is
        // proof that the peer has the session keys, so a responder-
        // role session can now be used for egress. Initiator-role
        // sessions install pre-confirmed; this is a no-op for them.
        // Set the flag BEFORE the replay/LPM gates so a packet that
        // authenticates but fails AllowedIPs still flips the
        // confirmation — the authentication is what the WG spec
        // ties confirmation to, not downstream policy gates.
        session.mark_confirmed();
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
            // Single atomic snapshot for both peer-index lookup and
            // AllowedIPs gate. Taking these from separate ArcSwap
            // loads would re-introduce the reconcile race window
            // — between the two loads, a config refresh could swap
            // the peer table and we'd pair a peer_idx from the old
            // snapshot with allowed_ips from the new one.
            let table = self.load_table();
            let peer_idx = *table
                .peer_index_by_pubkey
                .get(&session.peer_pubkey)
                .ok_or(DecapError::UnknownSession)?;
            if !table.allowed_ips.matches_for_peer(inner_src, peer_idx) {
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
        // `.prologue(WG_PROTOCOL_ID_BYTES)` is mandatory for wire
        // interoperability with kernel WireGuard and wireguard-go. The
        // WG protocol mixes the ASCII identifier
        // "WireGuard v1 zx2c4 Jason@zx2c4.com" into the initial Noise
        // hash. Omitting the prologue produces a "WireGuard-shaped"
        // transcript that no real peer will authenticate. Codex final
        // pre-merge review caught this after nine prior review rounds
        // missed it; see WG_PROTOCOL_ID_BYTES doc in mod.rs.
        Builder::new(WG_NOISE_PATTERN.parse()?)
            .prologue(WG_PROTOCOL_ID_BYTES)?
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
        // See `build_initiator_handshake` for the prologue rationale.
        // Both sides must mix the same identifier into the Noise
        // initial hash or the transcripts diverge from byte one.
        Builder::new(WG_NOISE_PATTERN.parse()?)
            .prologue(WG_PROTOCOL_ID_BYTES)?
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
            // RFC 791: IHL is the IP header length in 32-bit words.
            // Valid values are 5..=15 (20..=60 bytes of header). An
            // IHL < 5 means there isn't even room for the fixed IPv4
            // header. Copilot inline review: an AEAD-authenticated
            // payload with a bogus IHL would otherwise let
            // `total_length` claim a value < ihl*4 and `DecapOutcome
            // .len` could be < 20 — a downstream parser that
            // assumes "len >= 20 ⇒ valid IPv4 header" would
            // mis-interpret the bytes. Reject these here so the
            // post-decap consumer never sees a structurally bogus
            // inner header.
            let ihl = (pkt[0] & 0x0f) as usize;
            if ihl < 5 {
                return None;
            }
            let header_len = ihl * 4;
            let total_length = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
            if total_length < header_len {
                return None;
            }
            total_length
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

    /// r5 regression: when `reconcile_peers` drops a peer whose
    /// pubkey is absent in the new config, the peer's
    /// `(current, previous)` session entries MUST be drained from
    /// `sessions_by_local_index`. Codex r5 finding: without the
    /// drain, every config refresh that removes a peer leaks that
    /// peer's session Arcs in the demux map forever (until engine
    /// drop). The Arcs also keep `WgSession` (transport key
    /// material) alive past peer removal, which violates the
    /// expectation that removing a peer immediately revokes its
    /// session material from the live state.
    #[test]
    fn reconcile_peers_drains_dropped_peer_sessions_from_demux() {
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
        // Install two sessions on the peer (current + previous).
        let s1 = make_session_for(&engine, peer_pub, &peer_engine, 0xaaaa_0001, 2);
        engine.install_session(&peer_pub, s1).unwrap();
        let s2 = make_session_for(&engine, peer_pub, &peer_engine, 0xaaaa_0002, 3);
        engine.install_session(&peer_pub, s2).unwrap();
        // Both indices must be in the demux pre-reconcile.
        {
            let by_index = engine.sessions_by_local_index.read().unwrap();
            assert!(by_index.contains_key(&0xaaaa_0001));
            assert!(by_index.contains_key(&0xaaaa_0002));
        }
        // Reconcile with the peer removed.
        engine.reconcile_peers(&[]);
        // Both demux entries must now be gone — the leak is fixed.
        let by_index = engine.sessions_by_local_index.read().unwrap();
        assert!(
            !by_index.contains_key(&0xaaaa_0001),
            "dropped peer's `previous` session must be drained from demux"
        );
        assert!(
            !by_index.contains_key(&0xaaaa_0002),
            "dropped peer's `current` session must be drained from demux"
        );
        assert!(
            by_index.is_empty(),
            "no stray demux entries should remain after peer removal"
        );
    }

    /// r5 regression: peer removal must NOT touch unrelated peers'
    /// sessions. A reconcile that drops peer A while keeping peer B
    /// must drain A's demux entries and leave B's intact.
    #[test]
    fn reconcile_peers_leaves_kept_peer_sessions_intact() {
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
                    allowed_ips: vec![ipnet::IpNet::from_str("10.0.1.0/24").unwrap()],
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
                allowed_ips: vec![ipnet::IpNet::from_str("10.0.1.0/24").unwrap()],
            }],
        });
        let s_a = make_session_for(&engine, peer_a_pub, &peer_a_engine, 0xaaaa_0001, 2);
        engine.install_session(&peer_a_pub, s_a).unwrap();
        let s_b = make_session_for(&engine, peer_b_pub, &peer_b_engine, 0xbbbb_0001, 4);
        engine.install_session(&peer_b_pub, s_b).unwrap();
        // Reconcile dropping only peer A.
        engine.reconcile_peers(&[WgPeerConfig {
            pubkey: peer_b_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![ipnet::IpNet::from_str("10.0.1.0/24").unwrap()],
        }]);
        let by_index = engine.sessions_by_local_index.read().unwrap();
        assert!(
            !by_index.contains_key(&0xaaaa_0001),
            "peer A's session must be drained"
        );
        assert!(
            by_index.contains_key(&0xbbbb_0001),
            "peer B's session must remain — unrelated peer reconcile must not touch it"
        );
    }

    /// r5 regression: hot-path readers must observe a torn-free
    /// snapshot across `reconcile_peers`. A concurrent
    /// reconcile/hot-read interleaving where the reader sees
    /// `peer_index_by_pubkey` from the new snapshot but `peers`
    /// from the old (or vice versa) would route to the wrong peer.
    /// We hammer reconcile in one thread and assert internal
    /// consistency from another.
    ///
    /// Invariant verified: every snapshot returned by `load_table()`
    /// is internally consistent — for every (pubkey, idx) entry in
    /// `peer_index_by_pubkey`, `peers[idx].pubkey == pubkey`. The
    /// invariant would fail under torn snapshots if reconcile
    /// published the index map and peer vec via separate stores.
    #[test]
    fn reconcile_peers_snapshot_is_atomic_under_concurrent_load() {
        use std::sync::atomic::{AtomicBool, Ordering as AOrd};
        use std::thread;
        let (init_priv, _init_pub) = keypair();
        let (peer_a_priv, peer_a_pub) = keypair();
        let (peer_b_priv, peer_b_pub) = keypair();
        let (_peer_c_priv, peer_c_pub) = keypair();
        let _ = (peer_a_priv, peer_b_priv);
        let engine = Arc::new(WgEngine::new(WgEngineConfig {
            local_private_key: init_priv,
            listen_port: 51820,
            peers: vec![WgPeerConfig {
                pubkey: peer_a_pub,
                endpoint: None,
                persistent_keepalive: 0,
                allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
            }],
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let config_alt = vec![
            WgPeerConfig {
                pubkey: peer_b_pub,
                endpoint: None,
                persistent_keepalive: 0,
                allowed_ips: vec![ipnet::IpNet::from_str("10.0.1.0/24").unwrap()],
            },
            WgPeerConfig {
                pubkey: peer_c_pub,
                endpoint: None,
                persistent_keepalive: 0,
                allowed_ips: vec![ipnet::IpNet::from_str("10.0.2.0/24").unwrap()],
            },
        ];
        let config_orig = vec![WgPeerConfig {
            pubkey: peer_a_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
        }];
        let writer = {
            let engine = engine.clone();
            let stop = stop.clone();
            thread::spawn(move || {
                for i in 0..2000 {
                    if i % 2 == 0 {
                        engine.reconcile_peers(&config_alt);
                    } else {
                        engine.reconcile_peers(&config_orig);
                    }
                }
                stop.store(true, AOrd::Relaxed);
            })
        };
        let reader = {
            let engine = engine.clone();
            let stop = stop.clone();
            thread::spawn(move || {
                let mut observed = 0u64;
                while !stop.load(AOrd::Relaxed) {
                    let snapshot = engine.load_table();
                    // The invariant: every (pubkey, idx) pair in
                    // the index map must map to a peer in `peers`
                    // whose pubkey matches. A torn snapshot would
                    // pair an old-config pubkey with a new-config
                    // peer slot (or vice versa) — different pubkey.
                    for (pubkey, idx) in snapshot.peer_index_by_pubkey.iter() {
                        let peer = snapshot
                            .peers
                            .get(*idx as usize)
                            .expect("idx must be in bounds within a snapshot");
                        assert_eq!(
                            &peer.pubkey, pubkey,
                            "torn snapshot: index map and peer vec disagree"
                        );
                    }
                    observed += 1;
                }
                observed
            })
        };
        writer.join().unwrap();
        let n = reader.join().unwrap();
        // Sanity: the reader must have done at least one full pass.
        // (On a heavily loaded CI box this could be 1; we don't
        // tighten it.)
        assert!(n >= 1, "reader thread observed no snapshots");
    }

    /// r6 regression: `install_session` and `reconcile_peers` must
    /// serialize so a removed peer cannot orphan a freshly-installed
    /// demux entry.
    ///
    /// Race (pre-fix):
    ///   1. install_session(P) loads `peer` via `peer_arc(P)` from
    ///      `PeerTable_v1` and drops the snapshot reference.
    ///   2. reconcile_peers(&[]) publishes `PeerTable_v2` without P.
    ///      Its drain loop reads `peer.current.read()` and
    ///      `peer.previous.read()` — both `None` because step (1)
    ///      hasn't called `rotate_session` yet.
    ///   3. install_session continues against the orphan Arc<Peer>,
    ///      inserts the demux entry, and calls rotate_session. The
    ///      demux entry now references a peer pubkey absent from
    ///      every future `peer_index_by_pubkey`, so subsequent
    ///      reconciles cannot drain it.
    ///
    /// Fix: `install_session` takes `reconcile_lock` for the entire
    /// critical region. The lookup-then-mutate sequence is then
    /// serialized against any concurrent `reconcile_peers`, and if
    /// the peer is removed before the install acquires the lock, the
    /// `peer_arc(pubkey)` lookup returns None and the install fails
    /// with `UnknownPeer` — no demux mutation occurs.
    ///
    /// Invariant verified across the race: every entry in
    /// `sessions_by_local_index` has its `session.peer_pubkey`
    /// present in the currently published `peer_index_by_pubkey`.
    /// Under the pre-fix code path, this invariant would fail
    /// whenever the orphan interleaving fires.
    #[test]
    fn install_session_serializes_with_reconcile_removal() {
        use std::sync::atomic::{AtomicBool, Ordering as AOrd};
        use std::thread;
        let (init_priv, _init_pub) = keypair();
        let (peer_priv, peer_pub) = keypair();
        let engine = Arc::new(WgEngine::new(WgEngineConfig {
            local_private_key: init_priv,
            listen_port: 51820,
            peers: vec![WgPeerConfig {
                pubkey: peer_pub,
                endpoint: None,
                persistent_keepalive: 0,
                allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
            }],
        }));
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
        let cfg_with_peer = vec![WgPeerConfig {
            pubkey: peer_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
        }];
        // Pre-build a batch of sessions off the hot path. Each one
        // gets a fresh local_index so installs never collide on the
        // demux map for the wrong reason.
        let iterations = 400u32;
        let mut sessions: Vec<Arc<WgSession>> = Vec::with_capacity(iterations as usize);
        for i in 0..iterations {
            sessions.push(make_session_for(
                &engine,
                peer_pub,
                &peer_engine,
                0xcafe_0000 + i,
                100 + i,
            ));
        }
        let stop = Arc::new(AtomicBool::new(false));
        // Thread A: install_session in a tight loop, alternating
        // with reconciles that re-add the peer so installs can
        // succeed sometimes.
        let installer = {
            let engine = engine.clone();
            thread::spawn(move || {
                let mut ok = 0u32;
                let mut unknown = 0u32;
                let mut collision = 0u32;
                for s in sessions {
                    match engine.install_session(&peer_pub, s) {
                        Ok(()) => ok += 1,
                        Err(InstallSessionError::UnknownPeer) => unknown += 1,
                        Err(InstallSessionError::LocalIndexCollision) => collision += 1,
                    }
                    thread::yield_now();
                }
                (ok, unknown, collision)
            })
        };
        // Thread B: alternate removing and re-adding the peer.
        let reconciler = {
            let engine = engine.clone();
            let stop = stop.clone();
            let cfg = cfg_with_peer.clone();
            thread::spawn(move || {
                let mut iters = 0u32;
                while !stop.load(AOrd::Relaxed) {
                    engine.reconcile_peers(&[]);
                    engine.reconcile_peers(&cfg);
                    iters += 1;
                    thread::yield_now();
                }
                iters
            })
        };
        let (ok, unknown, collision) = installer.join().unwrap();
        stop.store(true, AOrd::Relaxed);
        let reconcile_iters = reconciler.join().unwrap();
        // We made progress on both sides — otherwise the test is
        // not actually exercising the race window.
        assert!(
            ok + unknown + collision == iterations,
            "every install attempt accounted for"
        );
        assert!(
            reconcile_iters >= 1,
            "reconcile loop must have completed at least one full add/remove cycle"
        );
        // r7 Codex hostile finding: a tautological pass shape exists
        // if the reconciler always wins the lock — every install
        // returns UnknownPeer, demux stays empty, and the post-loop
        // invariants are trivially satisfied even with the lock
        // removed. Require at least one Ok install so the lock-
        // protected path (peer_arc-then-rotate_session under the
        // same guard) is actually exercised. With 400 iterations and
        // reconcile alternating add/remove on a separate thread, the
        // installer typically lands 50-300 Ok results in practice;
        // requiring just `ok > 0` is conservative against schedule
        // skew while keeping the gate non-vacuous.
        assert!(
            ok > 0,
            "race regression must exercise at least one successful install \
             (ok={ok}, unknown={unknown}, collision={collision}); without an \
             Ok the lock-protected demux insert path is not on the test \
             trajectory and the gate is tautological"
        );
        // Post-condition invariant: every entry in
        // `sessions_by_local_index` must reference a peer pubkey
        // that is present in the currently published table. An
        // orphan demux entry (the race the fix closes) would have a
        // `session.peer_pubkey` that is not in the index map of any
        // future snapshot — and we can detect it by re-reconciling
        // the peer back in and checking the index map directly.
        engine.reconcile_peers(&cfg_with_peer);
        let table = engine.load_table();
        let by_index = engine.sessions_by_local_index.read().unwrap();
        for (local_index, session) in by_index.iter() {
            assert!(
                table.peer_index_by_pubkey.contains_key(&session.peer_pubkey),
                "demux entry {local_index:#x} references unknown peer pubkey \
                 — orphan from install/reconcile race"
            );
        }
        // Now flip the peer out one more time. Reconcile's drain
        // path must remove every session belonging to that peer; any
        // surviving entry would prove the orphan slipped through.
        engine.reconcile_peers(&[]);
        let by_index = engine.sessions_by_local_index.read().unwrap();
        assert!(
            by_index.is_empty(),
            "after removing the only peer, no demux entries should remain; \
             found {} — install/reconcile race left orphans",
            by_index.len()
        );
    }

    /// r6 regression for the MINOR Codex finding: `try_encap` must
    /// not consume a tx counter (or write the WG header) when it
    /// returns `BufferTooSmall` because the inner IP would overflow
    /// the PADDED_PLAINTEXT_MAX staging buffer.
    ///
    /// Pre-fix sequence at engine.rs:
    ///   1. `out.len() < required` check (fires for small `out`).
    ///   2. `next_tx_counter()` — counter advances.
    ///   3. `encode_data_header(out, ...)` — 16 bytes written.
    ///   4. `padded_len > PADDED_PLAINTEXT_MAX` check — fires here.
    /// Result on the failure path: counter consumed, header dirty,
    /// and the caller sees BufferTooSmall but cannot rely on
    /// "Err leaves state untouched".
    ///
    /// Post-fix: the PADDED_PLAINTEXT_MAX guard is hoisted above
    /// `next_tx_counter()` (and above the header write), so the
    /// failure path leaves both the counter and `out` untouched.
    #[test]
    fn encap_padded_plaintext_overflow_leaves_counter_and_buffer_untouched() {
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
        let session = make_session_for(&engine, peer_pub, &peer_engine, 0xdead_0001, 2);
        engine.install_session(&peer_pub, session).unwrap();
        // inner_ip = 4097 bytes → pad_to_16(4097) = 4112 >
        // PADDED_PLAINTEXT_MAX (4096). `out` is sized large enough to
        // hold header + 4112 + 16 so it cleanly passes the
        // `out.len() < required` guard and only the staging guard
        // can fire.
        let inner = vec![0x45u8; 4097];
        let mut out = vec![0xa5u8; WG_DATA_HEADER_LEN + 4112 + POLY1305_TAG_LEN];
        // Snapshot the per-session counter pre-encap.
        let counter_before = session_tx_counter(&engine, &peer_pub);
        let err = engine.try_encap(&peer_pub, &inner, &mut out).unwrap_err();
        assert_eq!(err, EncapError::BufferTooSmall);
        let counter_after = session_tx_counter(&engine, &peer_pub);
        assert_eq!(
            counter_before, counter_after,
            "BufferTooSmall on PADDED_PLAINTEXT_MAX overflow must NOT advance tx counter"
        );
        // First 16 bytes of `out` must remain the 0xa5 sentinel — no
        // partial header write on the failure path.
        assert!(
            out[..WG_DATA_HEADER_LEN].iter().all(|&b| b == 0xa5),
            "BufferTooSmall must NOT write the WG header into `out`"
        );
    }

    /// Helper for the BufferTooSmall counter-leak test: read the
    /// `current` session's tx_counter for `pubkey`.
    fn session_tx_counter(engine: &WgEngine, pubkey: &[u8; 32]) -> u64 {
        let table = engine.load_table();
        let idx = *table.peer_index_by_pubkey.get(pubkey).unwrap();
        let peer = table.peers[idx as usize].clone();
        let cur = peer.current.read().unwrap().clone().unwrap();
        cur.tx_counter.load(Ordering::Relaxed)
    }
}
