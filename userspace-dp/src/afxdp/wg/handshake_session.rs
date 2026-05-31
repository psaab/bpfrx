//! WireGuard handshake orchestration on `WgEngine` (#1709 S1).
//!
//! This file holds the slow-path, control-thread-only handshake driver: the
//! `HandshakeError` enum, the `PendingHandshake` reservation record, the
//! two-phase index reservation, and the four engine entry points that
//! compose `snow` + the `handshake` framing module + the `Tai64nClock` into
//! the full on-wire WireGuard handshake in both roles.
//!
//! It is split out of `engine.rs` (which holds the `WgEngine` struct, the
//! peer table, and the hot encap/decap paths) purely for modularity — these
//! methods are `impl WgEngine` blocks in the same `wg` module and reach the
//! engine's private fields directly. Keeping them here keeps `engine.rs`
//! under the 2000-LOC refactor threshold and the security-critical handshake
//! orchestration auditable in one place.
//!
//! None of this runs on the AF_XDP poll worker: the hot encap/decap paths in
//! `engine.rs` never build a `HandshakeState`. Handshake construction +
//! MAC1 keyed-BLAKE2s + X25519 happen on the control/coordinator thread.

use super::engine::{InstallSessionError, WgEngine};
use super::handshake::{self, FramingError, MSG_INIT_NOISE_LEN, MSG_RESPONSE_NOISE_LEN};
use super::session::{SessionRole, WgSession};
use super::tai64n::TAI64N_LEN;
use super::{WG_KEY_LEN, WG_MSG_INIT_LEN, WG_MSG_RESPONSE_LEN};
use snow::HandshakeState;
use std::sync::Arc;

/// Errors that can fail the slow-path WG handshake build / consume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HandshakeError {
    /// The caller-supplied peer pubkey is not in the engine table.
    UnknownPeer,
    /// The on-wire framing was malformed or its MAC1 did not verify.
    Framing(FramingError),
    /// snow rejected the Noise message (bad AEAD tag, wrong key, etc.).
    Crypto,
    /// The responder's msg2 `receiver_index` did not match the
    /// `sender_index` we reserved for this handshake — a spoofed or
    /// misrouted response; drop it.
    ReceiverIndexMismatch,
    /// No pending handshake reservation matched the response's
    /// `receiver_index`. Either the response is stale (the handshake
    /// timed out and its reservation was released) or spoofed.
    NoPendingHandshake,
    /// snow `read_message` recovered the peer's static public key, but
    /// it is not a configured peer in the engine table. (Responder path.)
    UnknownInitiator,
    /// Could not allocate a fresh, collision-free local index after
    /// several attempts (astronomically unlikely with a 32-bit space).
    IndexExhausted,
    /// The output buffer was too small for the framed handshake message.
    OutputTooSmall,
    /// Internal snow / engine error building the handshake state.
    Internal,
}

impl From<FramingError> for HandshakeError {
    fn from(e: FramingError) -> Self {
        HandshakeError::Framing(e)
    }
}

/// A handshake in progress: the snow `HandshakeState` plus the metadata
/// needed to promote it to a live session once the exchange completes.
///
/// Held in the engine keyed by OUR locally-chosen `sender_index` (the
/// reserved index). Keeping `HandshakeState` engine-internal (rather than
/// handed back to the caller and re-supplied) keeps the public API trading
/// only byte slices / `[u8;32]` and pre-stages the S3 integration where the
/// coordinator thread owns pending handshakes (SMR-6).
///
/// `pub(in crate::afxdp::wg)` so `engine.rs`'s `WgEngine` struct can name the
/// type in its `pending: RwLock<FxHashMap<u32, PendingHandshake>>` field; the
/// fields stay module-private (only this file's methods read them).
pub(in crate::afxdp::wg) struct PendingHandshake {
    /// snow state, pumped to completion on the second message. `Some` for
    /// an initiator handshake that must resume across the
    /// `create_initiation` → `consume_response` call boundary; `None` for
    /// a responder reservation, which completes synchronously inside
    /// `consume_initiation_create_response` (the snow state never needs to
    /// outlive that call, so the pending entry is a bare reservation
    /// marker).
    state: Option<HandshakeState>,
    /// The peer this handshake is with (its static public key).
    peer_pubkey: [u8; WG_KEY_LEN],
    /// Our locally-chosen index (the reservation key). The peer echoes
    /// it as the `receiver_index` of the message it sends back.
    local_index: u32,
    /// The peer's index, learned from the message it sent us. For the
    /// responder path this is msg1.sender_index (known at reserve time);
    /// for the initiator path it is filled in from msg2.sender_index on
    /// completion.
    peer_index: u32,
    /// Initiator or responder — determines the session-confirmation gate
    /// (see `WgSession`).
    role: SessionRole,
}

impl WgEngine {
    // ===================================================================
    // WireGuard handshake — framed, both roles (#1709 S1)
    //
    // These compose snow + handshake.rs framing + the TAI64N clock into the
    // full on-wire WG handshake. They run on the CONTROL/coordinator thread
    // only — never the AF_XDP poll worker (the hot encap/decap paths never
    // build a HandshakeState). Index allocation follows the two-phase
    // reservation discipline: an index is reserved in `sessions_by_local_index`
    // (as a placeholder via `pending`) BEFORE the message carrying it is
    // emitted, so a concurrent handshake cannot steal it and blackhole the
    // resulting session.
    // ===================================================================

    /// Reserve a fresh, collision-free local index and register a pending
    /// handshake under it. Holds the `reconcile_lock` (serialized with
    /// `install_session` / `reconcile_peers`) so the reservation is atomic
    /// w.r.t. session install and peer removal.
    ///
    /// Enforces the at-most-one-pending-per-peer cap: if the peer already
    /// has a pending reservation, it is aborted (removed from `pending` and
    /// its placeholder dropped from the demux map) before the new one is
    /// installed. Returns the reserved local index.
    fn reserve_pending(
        &self,
        peer_pubkey: [u8; WG_KEY_LEN],
        state: Option<HandshakeState>,
        peer_index: u32,
        role: SessionRole,
    ) -> Result<u32, HandshakeError> {
        let _guard = self.reconcile_lock.lock().unwrap();
        let by_index = self.sessions_by_local_index.read().unwrap();
        let mut pending = self.pending.write().unwrap();
        let mut by_peer = self.pending_by_peer.write().unwrap();

        // Abort any prior PENDING (not-yet-completed) handshake for this
        // peer (DoS bound: at most one pending reservation per peer). The
        // `pending_by_peer` marker is cleared by `promote_pending` on
        // completion, so a still-present marker can only point at an
        // incomplete reservation living in `pending` — NOT at a live
        // session in `by_index`. We therefore drop only the `pending`
        // entry and the marker; we must NOT touch `by_index`, or we would
        // blackhole an already-established session for this peer that a
        // prior completed handshake legitimately installed there.
        if let Some(old_idx) = by_peer.remove(&peer_pubkey) {
            pending.remove(&old_idx);
        }

        // Pick a fresh index not present as a live session OR a pending
        // reservation. 32-bit space; a handful of tries is plenty.
        let mut local_index = 0u32;
        let mut found = false;
        for _ in 0..8 {
            let cand = rand_u32_nonzero();
            if !by_index.contains_key(&cand) && !pending.contains_key(&cand) {
                local_index = cand;
                found = true;
                break;
            }
        }
        if !found {
            return Err(HandshakeError::IndexExhausted);
        }

        // Reserve the index by recording the pending handshake. The
        // reservation lives in `pending` (NOT in the live-session demux
        // map): the index allocator above rejects any candidate already
        // present in `pending` OR `by_index`, and the whole reserve/promote
        // sequence is serialized by `reconcile_lock`, so a concurrent
        // handshake or `install_session` cannot claim this index until we
        // either promote it (insert the live session) or release it. decap
        // never sees a half-built session because the live entry is only
        // inserted by `promote_pending` → `install_session` on completion.
        pending.insert(
            local_index,
            PendingHandshake {
                state,
                peer_pubkey,
                local_index,
                peer_index,
                role,
            },
        );
        by_peer.insert(peer_pubkey, local_index);
        Ok(local_index)
    }

    /// Release a pending reservation (handshake failed before completion).
    /// Removes it from `pending` and clears the `pending_by_peer` marker if
    /// it still points at this index. A pending reservation lives only in
    /// `pending` (never in the live-session demux map), so there is nothing
    /// to undo in `sessions_by_local_index`. Idempotent.
    fn release_pending(&self, local_index: u32) {
        let _guard = self.reconcile_lock.lock().unwrap();
        let mut pending = self.pending.write().unwrap();
        if let Some(ph) = pending.remove(&local_index) {
            let mut by_peer = self.pending_by_peer.write().unwrap();
            // Only clear the peer→index map if it still points at us.
            if by_peer.get(&ph.peer_pubkey) == Some(&local_index) {
                by_peer.remove(&ph.peer_pubkey);
            }
        }
    }

    /// Number of in-flight (reserved-but-not-completed) handshakes. Test /
    /// diagnostic accessor.
    #[cfg(test)]
    pub(crate) fn pending_count(&self) -> usize {
        self.pending.read().unwrap().len()
    }

    /// Build a framed WG type-1 initiation toward `peer_pubkey`.
    ///
    /// Reserves a local sender_index FIRST, builds the snow msg1 body with
    /// a fresh monotonic TAI64N as the Noise payload, and frames it (type,
    /// reserved, sender_index, body, mac1 over the responder pubkey, mac2
    /// zeros). On any failure after reservation the reservation is released.
    /// Writes the 148-byte message at `out[0..148]` and returns the chosen
    /// sender_index.
    pub(crate) fn create_initiation(
        &self,
        peer_pubkey: &[u8; WG_KEY_LEN],
        out: &mut [u8],
    ) -> Result<u32, HandshakeError> {
        if out.len() < WG_MSG_INIT_LEN {
            return Err(HandshakeError::OutputTooSmall);
        }
        // Confirm the peer is configured before doing any work.
        if self.peer_arc(peer_pubkey).is_none() {
            return Err(HandshakeError::UnknownPeer);
        }
        let mut state = self
            .build_initiator_handshake(peer_pubkey)
            .map_err(|_| HandshakeError::Internal)?;

        // Reserve the local index + register the pending handshake BEFORE
        // emitting the message (two-phase reservation). For the initiator
        // the peer_index is not yet known (filled from msg2); use 0 as a
        // placeholder. The snow state is stashed after we write msg1 (which
        // mutates it) so it can resume in `consume_response`.
        let local_index =
            self.reserve_pending(*peer_pubkey, None, 0, SessionRole::Initiator)?;

        // Build the snow msg1 body with the TAI64N as the Noise payload.
        let tai64n = self.tai64n_clock.now();
        debug_assert_eq!(tai64n.len(), TAI64N_LEN);
        let mut noise_body = [0u8; MSG_INIT_NOISE_LEN];
        let n = match state.write_message(&tai64n, &mut noise_body) {
            Ok(n) => n,
            Err(_) => {
                self.release_pending(local_index);
                return Err(HandshakeError::Crypto);
            }
        };
        if n != MSG_INIT_NOISE_LEN {
            self.release_pending(local_index);
            return Err(HandshakeError::Crypto);
        }
        // Frame it.
        if let Err(e) = handshake::build_initiation(out, local_index, &noise_body, peer_pubkey) {
            self.release_pending(local_index);
            return Err(e.into());
        }
        // Stash the real (post-write) snow state into the pending entry so
        // `consume_response` can resume it.
        {
            let mut pending = self.pending.write().unwrap();
            if let Some(ph) = pending.get_mut(&local_index) {
                ph.state = Some(state);
            } else {
                // Reservation vanished (aborted by a concurrent init for the
                // same peer). Treat as a failed build.
                return Err(HandshakeError::NoPendingHandshake);
            }
        }
        Ok(local_index)
    }

    /// Consume a peer's framed WG type-2 response, complete the initiator
    /// handshake, and install the derived transport session.
    ///
    /// Verifies the framing (mac1 over OUR public key) and that the
    /// response's `receiver_index` matches a pending reservation we hold.
    /// On success the pending handshake is promoted to a live `WgSession`
    /// (initiator role, confirmed at install) and registered for inbound
    /// demux. Returns the local index of the installed session.
    pub(crate) fn consume_response(&self, msg: &[u8]) -> Result<u32, HandshakeError> {
        let parsed = handshake::parse_response(msg, &self.local_public_key)?;
        // Take the pending handshake addressed by receiver_index.
        let mut ph = {
            let mut pending = self.pending.write().unwrap();
            pending
                .remove(&parsed.receiver_index)
                .ok_or(HandshakeError::NoPendingHandshake)?
        };
        // Copy the metadata out before consuming `ph.state` (avoids a
        // partial-move borrow conflict).
        let local_index = ph.local_index;
        let peer_pubkey = ph.peer_pubkey;
        let role = ph.role;
        // It must be an initiator-role handshake (we sent msg1).
        if role != SessionRole::Initiator || local_index != parsed.receiver_index {
            // A mismatched role/index means this response does not belong to
            // this reservation; drop it and release the now-removed entry's
            // peer marker.
            self.release_pending(parsed.receiver_index);
            return Err(HandshakeError::ReceiverIndexMismatch);
        }
        // Recover the resumable initiator snow state.
        let mut state = match ph.state.take() {
            Some(s) => s,
            None => {
                // An initiator reservation must carry its snow state. A
                // missing state means the reservation was never completed by
                // create_initiation (e.g. aborted mid-build); drop it.
                self.release_pending(parsed.receiver_index);
                return Err(HandshakeError::NoPendingHandshake);
            }
        };
        // Drive snow to completion with the peer's msg2 body.
        let mut sink = [0u8; MSG_RESPONSE_NOISE_LEN];
        if state.read_message(parsed.noise_body, &mut sink).is_err() {
            self.release_pending(parsed.receiver_index);
            return Err(HandshakeError::Crypto);
        }
        let transport = match state.into_stateless_transport_mode() {
            Ok(t) => t,
            Err(_) => {
                self.release_pending(parsed.receiver_index);
                return Err(HandshakeError::Crypto);
            }
        };
        let session = Arc::new(WgSession::new_with_role(
            transport,
            local_index,
            parsed.sender_index,
            peer_pubkey,
            SessionRole::Initiator,
        ));
        self.promote_pending(local_index, peer_pubkey, session)
    }

    /// Responder path: parse a peer's framed WG type-1 initiation, run snow
    /// to recover the peer's static key + TAI64N, identify the configured
    /// peer, build a framed WG type-2 response, reserve our responder
    /// sender_index, and install the derived (unconfirmed) transport
    /// session. Writes the 92-byte response at `out[0..92]` and returns
    /// `(our_sender_index, peer_pubkey)`.
    pub(crate) fn consume_initiation_create_response(
        &self,
        msg: &[u8],
        out: &mut [u8],
    ) -> Result<([u8; WG_KEY_LEN], u32), HandshakeError> {
        if out.len() < WG_MSG_RESPONSE_LEN {
            return Err(HandshakeError::OutputTooSmall);
        }
        // Verify framing (mac1 over OUR public key) and recover the body.
        let parsed = handshake::parse_initiation(msg, &self.local_public_key)?;
        let peer_sender_index = parsed.sender_index;

        // Run the responder Noise read to recover the peer static key.
        let mut state = self
            .build_responder_handshake()
            .map_err(|_| HandshakeError::Internal)?;
        let mut ts_sink = [0u8; TAI64N_LEN];
        // snow writes the recovered Noise payload (the peer's TAI64N) into
        // ts_sink; the value is used by a compliant responder for handshake
        // anti-replay. S1 derives the session and (per the (b+) boundary)
        // does not yet enforce per-peer TAI64N anti-replay — that rides
        // with the responder-hardening step. We still must READ it so snow
        // advances the transcript.
        if state.read_message(parsed.noise_body, &mut ts_sink).is_err() {
            return Err(HandshakeError::Crypto);
        }
        // Identify the initiator from the recovered static key.
        let peer_pubkey = {
            let rs = state.get_remote_static().ok_or(HandshakeError::Crypto)?;
            if rs.len() != WG_KEY_LEN {
                return Err(HandshakeError::Crypto);
            }
            let mut pk = [0u8; WG_KEY_LEN];
            pk.copy_from_slice(rs);
            pk
        };
        if self.peer_arc(&peer_pubkey).is_none() {
            return Err(HandshakeError::UnknownInitiator);
        }

        // Reserve our responder sender_index BEFORE emitting msg2. The
        // responder completes synchronously in this call, so the pending
        // entry is a bare reservation marker (state = None).
        let local_index = self.reserve_pending(
            peer_pubkey,
            None,
            peer_sender_index,
            SessionRole::Responder,
        )?;

        // Build the snow msg2 body (empty Noise payload).
        let mut noise_body = [0u8; MSG_RESPONSE_NOISE_LEN];
        let n = match state.write_message(&[], &mut noise_body) {
            Ok(n) => n,
            Err(_) => {
                self.release_pending(local_index);
                return Err(HandshakeError::Crypto);
            }
        };
        if n != MSG_RESPONSE_NOISE_LEN {
            self.release_pending(local_index);
            return Err(HandshakeError::Crypto);
        }
        // Frame the response: receiver_index echoes the initiator's
        // sender_index; mac1 keys on the INITIATOR's public key (recipient).
        if let Err(e) = handshake::build_response(
            out,
            local_index,
            peer_sender_index,
            &noise_body,
            &peer_pubkey,
        ) {
            self.release_pending(local_index);
            return Err(e.into());
        }

        // The handshake is complete on our side after writing msg2.
        let transport = match state.into_stateless_transport_mode() {
            Ok(t) => t,
            Err(_) => {
                self.release_pending(local_index);
                return Err(HandshakeError::Crypto);
            }
        };
        let session = Arc::new(WgSession::new_with_role(
            transport,
            local_index,
            peer_sender_index,
            peer_pubkey,
            SessionRole::Responder,
        ));
        // Promote the reservation to a live session (clears the pending
        // marker + per-peer marker, installs for demux). The responder
        // session installs UNCONFIRMED — egress is gated until the first
        // authenticated inbound transport record (WgSession key-confirmation).
        self.promote_pending(local_index, peer_pubkey, session)?;
        Ok((peer_pubkey, local_index))
    }

    /// Promote a completed pending handshake to a live session: install the
    /// session for inbound demux + on the peer, then clear the reservation
    /// bookkeeping. Returns the session's local index.
    ///
    /// Ordering matters: we `install_session` (which inserts the live entry
    /// into `sessions_by_local_index` under `reconcile_lock`) BEFORE removing
    /// the `pending` reservation. While install runs, the index is present
    /// in BOTH `pending` and (newly) `by_index`; the index allocator in
    /// `reserve_pending` rejects any candidate present in EITHER map (all
    /// under `reconcile_lock`), so no concurrent handshake can claim this
    /// index during the hand-off. Removing the reservation first would open
    /// a window where the index is in neither map and a concurrent reserve
    /// could collide.
    fn promote_pending(
        &self,
        local_index: u32,
        peer_pubkey: [u8; WG_KEY_LEN],
        session: Arc<WgSession>,
    ) -> Result<u32, HandshakeError> {
        // Install the live session first. The reservation guaranteed
        // `local_index` was free of any LIVE session; `install_session`
        // re-checks under the reconcile lock and a same-index live collision
        // here would be an engine bug.
        let result = match self.install_session(&peer_pubkey, session) {
            Ok(()) => Ok(local_index),
            Err(InstallSessionError::UnknownPeer) => Err(HandshakeError::UnknownPeer),
            Err(InstallSessionError::LocalIndexCollision) => Err(HandshakeError::Internal),
        };
        // Clear the reservation bookkeeping regardless of install outcome:
        // on success the live entry now owns the index; on failure the
        // reservation must not linger.
        {
            let mut pending = self.pending.write().unwrap();
            pending.remove(&local_index);
            let mut by_peer = self.pending_by_peer.write().unwrap();
            if by_peer.get(&peer_pubkey) == Some(&local_index) {
                by_peer.remove(&peer_pubkey);
            }
        }
        result
    }
}

/// Allocate a non-zero pseudo-random u32 for a handshake index. WG indices
/// are opaque demux tags; uniqueness (not unpredictability) is what matters
/// for correctness, but a random draw keeps collisions astronomically rare.
/// Uses the OS RNG via `getrandom` (pulled in transitively); falls back to a
/// time-seeded value only if that fails (never expected on Linux).
fn rand_u32_nonzero() -> u32 {
    let mut buf = [0u8; 4];
    let v = if getrandom::getrandom(&mut buf).is_ok() {
        u32::from_ne_bytes(buf)
    } else {
        // Extremely unlikely fallback; still non-zero below.
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0x9e37_79b9)
    };
    if v == 0 { 0x9e37_79b9 } else { v }
}
