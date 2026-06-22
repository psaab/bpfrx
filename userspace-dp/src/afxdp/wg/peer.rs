//! Per-peer state.
//!
//! A peer holds:
//!   - Its static public key (the identity used by the engine table).
//!   - Optionally an endpoint (UDP `IP:port`) for outbound handshake.
//!   - Active and previous transport sessions (current + prior, to
//!     allow in-flight rekey handover).
//!
//! Reconciliation: the engine rebuilds the peer set from the config
//! snapshot whenever a new snapshot lands. Existing peer state is
//! preserved across snapshots (same pubkey → same `Arc<Peer>`); the
//! AllowedIPs trie is rebuilt fresh because its index space is
//! tied to the snapshot.

use super::session::WgSession;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

pub(crate) struct Peer {
    pub(crate) pubkey: [u8; 32],
    /// Optional outbound endpoint. `None` means responder-only.
    ///
    /// Interior-mutable so `WgEngine::reconcile_peers` can update an
    /// existing peer's endpoint when the control plane commits a new
    /// config without forcing the engine to drop and recreate the
    /// peer Arc (which would tear down active sessions). Codex final
    /// pre-merge finding 3: prior revisions kept this immutable, so
    /// config commits that changed the endpoint silently kept the
    /// stale value once the integration layer started forwarding
    /// config updates.
    ///
    /// TODO(#1499 r4 / roaming): the WG spec mandates that when a
    /// peer sends a valid authenticated packet from a new source
    /// IP:port the receiver MUST update its known endpoint to that
    /// source so subsequent egress traffic follows the roam. This
    /// requires an `update_endpoint_if_verified` API on `Peer` and a
    /// call site in `WgEngine::try_decap` after the AllowedIPs gate
    /// passes. The interior mutability here makes that future
    /// in-place update possible; the data path to invoke it requires
    /// the integration layer to thread the outer UDP source through
    /// to the engine. Tracked as part of the integration PR.
    pub(crate) endpoint: RwLock<Option<SocketAddr>>,
    /// Optional keepalive interval in seconds (per WG: 0 = off).
    /// Interior-mutable so config updates apply in place — see the
    /// `endpoint` doc for the rationale. Consumed by the #1888 S5
    /// timer pass (`WgEngine::timer_pass` T8 — see wg/timers.rs).
    pub(crate) persistent_keepalive: AtomicU16,
    /// #1888 S5 activity stamps + armed timers, all CLOCK_MONOTONIC ns
    /// relaxed atomics, 0 = never/unarmed. Peer-resident (NOT
    /// session-resident) so a rekey does not reset keepalive pacing or
    /// the dead-peer detector — matching wireguard-go, where all
    /// timers hang off the peer. Semantics are pinned in
    /// `docs/research/1888-wg-timers/plan.md` §3.
    ///
    /// Any authenticated packet SENT: transport data, keepalive, or a
    /// handshake message we emitted. Paces T8 (persistent keepalive).
    pub(crate) last_send_any_ns: AtomicU64,
    /// Any authenticated packet RECEIVED: transport data, keepalive,
    /// or a valid handshake message. Paces T8.
    pub(crate) last_recv_any_ns: AtomicU64,
    /// T6 (passive keepalive) ARMED timer — Linux pending-timer model:
    /// SET only when currently 0 (CAS) on an authenticated,
    /// replay-accepted, NON-EMPTY transport plaintext; CLEARED by any
    /// authenticated send; fires at `armed + KEEPALIVE_TIMEOUT`. A
    /// received keepalive does NOT arm it (no keepalive ping-pong).
    pub(crate) t6_armed_recv_ns: AtomicU64,
    /// T7 (no-reply reinit) ARMED timer: SET only when currently 0 on
    /// a successful NON-EMPTY data encap; CLEARED by any authenticated
    /// receive and by handshake-attempt start; fires at
    /// `armed + NO_REPLY_REINIT_NS`. An armed-not-latest stamp is
    /// load-bearing: a latest-send stamp would be refreshed by every
    /// outbound packet and never accrue 15s under continuous
    /// outbound-only traffic (Codex r3 F1).
    pub(crate) t7_armed_send_ns: AtomicU64,
    /// T8 skip/fail pacing anchor: advanced whenever the control loop
    /// ACTS on a T8 due-tick (send attempt, initiate, or skip), so a
    /// peer with no endpoint cannot leave a past-due deadline spinning
    /// the poll loop (AGY r3 G1).
    pub(crate) t8_last_attempt_ns: AtomicU64,
    /// The current transport session, if a handshake has completed.
    /// RwLock because rekey is a slow-path replacement and the hot
    /// path only takes a read guard to encrypt/decrypt.
    pub(crate) current: RwLock<Option<Arc<WgSession>>>,
    /// The previous transport session, retained across rekey so
    /// in-flight ciphertexts decrypt successfully. Same lock
    /// discipline as `current`.
    pub(crate) previous: RwLock<Option<Arc<WgSession>>>,
    /// Per-peer preshared key (#1434 B2). 32 zero bytes = no PSK
    /// (semantically identical to the all-zero key in Noise IKpsk2).
    /// Interior-mutable so a config commit that reuses the peer Arc can
    /// rotate the PSK in place (same rationale as `endpoint`). SECRET:
    /// redacted in the manual Debug impl below; never logged.
    pub(crate) preshared_key: RwLock<[u8; 32]>,
}

impl std::fmt::Debug for Peer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redact the preshared key. The pubkey/endpoint/keepalive are
        // not secret and are useful for triage.
        let psk_set = self
            .preshared_key
            .read()
            .map(|k| *k != [0u8; 32])
            .unwrap_or(false);
        f.debug_struct("Peer")
            .field("pubkey", &self.pubkey)
            .field("endpoint", &self.endpoint)
            .field("persistent_keepalive", &self.persistent_keepalive)
            .field("preshared_key", &if psk_set { "<redacted>" } else { "<unset>" })
            .field("current", &self.current)
            .field("previous", &self.previous)
            .finish()
    }
}

impl Peer {
    pub(crate) fn new(
        pubkey: [u8; 32],
        endpoint: Option<SocketAddr>,
        persistent_keepalive: u16,
        preshared_key: [u8; 32],
    ) -> Self {
        Self {
            pubkey,
            endpoint: RwLock::new(endpoint),
            persistent_keepalive: AtomicU16::new(persistent_keepalive),
            last_send_any_ns: AtomicU64::new(0),
            last_recv_any_ns: AtomicU64::new(0),
            t6_armed_recv_ns: AtomicU64::new(0),
            t7_armed_send_ns: AtomicU64::new(0),
            t8_last_attempt_ns: AtomicU64::new(0),
            current: RwLock::new(None),
            previous: RwLock::new(None),
            preshared_key: RwLock::new(preshared_key),
        }
    }

    /// Record any authenticated packet SENT (transport data,
    /// keepalive, or handshake message). Clears the T6 passive-
    /// keepalive arm — we just proved liveness to the peer.
    #[inline]
    pub(crate) fn note_authenticated_send(&self, now_ns: u64) {
        self.last_send_any_ns.store(now_ns, Ordering::Relaxed);
        self.t6_armed_recv_ns.store(0, Ordering::Relaxed);
    }

    /// Record a NON-EMPTY transport data send: authenticated-send
    /// bookkeeping plus arm-if-unarmed of the T7 no-reply detector
    /// (CAS from 0 so subsequent sends cannot push the deadline —
    /// Linux pending-timer parity).
    #[inline]
    pub(crate) fn note_data_send(&self, now_ns: u64) {
        self.note_authenticated_send(now_ns);
        let _ = self.t7_armed_send_ns.compare_exchange(
            0,
            now_ns.max(1),
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
    }

    /// Record any authenticated packet RECEIVED (transport data,
    /// keepalive, or valid handshake message). Clears the T7 arm —
    /// the peer just proved it is alive.
    #[inline]
    pub(crate) fn note_authenticated_recv(&self, now_ns: u64) {
        self.last_recv_any_ns.store(now_ns, Ordering::Relaxed);
        self.t7_armed_send_ns.store(0, Ordering::Relaxed);
    }

    /// Record an authenticated, replay-accepted, NON-EMPTY transport
    /// plaintext: authenticated-recv bookkeeping plus arm-if-unarmed
    /// of the T6 passive-keepalive timer.
    #[inline]
    pub(crate) fn note_data_recv(&self, now_ns: u64) {
        self.note_authenticated_recv(now_ns);
        let _ = self.t6_armed_recv_ns.compare_exchange(
            0,
            now_ns.max(1),
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
    }

    /// Update the mutable per-peer config fields in place. Called
    /// from `WgEngine::reconcile_peers` when the new config snapshot
    /// reuses an existing peer Arc (same pubkey). Keeping the peer
    /// Arc alive preserves the (current, previous) session pair across
    /// the commit; only the operator-facing fields shift.
    pub(crate) fn update_config(
        &self,
        endpoint: Option<SocketAddr>,
        persistent_keepalive: u16,
        preshared_key: [u8; 32],
    ) {
        *self.endpoint.write().unwrap() = endpoint;
        self.persistent_keepalive
            .store(persistent_keepalive, Ordering::Relaxed);
        *self.preshared_key.write().unwrap() = preshared_key;
    }

    /// Snapshot the current endpoint. Slow path only.
    #[allow(dead_code)] // Consumed by integration PR + tests.
    pub(crate) fn endpoint(&self) -> Option<SocketAddr> {
        *self.endpoint.read().unwrap()
    }

    /// Snapshot the current preshared key (#1434 B2). Slow path only —
    /// consumed by the handshake builders. 32 zero bytes = no PSK.
    pub(crate) fn preshared_key(&self) -> [u8; 32] {
        *self.preshared_key.read().unwrap()
    }

    /// Snapshot the current persistent-keepalive interval. Slow path.
    #[allow(dead_code)] // Consumed by integration PR + tests.
    pub(crate) fn persistent_keepalive(&self) -> u16 {
        self.persistent_keepalive.load(Ordering::Relaxed)
    }

    /// Replace `current` with `new`, moving the old current to
    /// `previous`. Called from the slow-path handshake-complete code.
    pub(crate) fn rotate_session(&self, new: Arc<WgSession>) -> Option<Arc<WgSession>> {
        let old_current = {
            let mut cur = self.current.write().unwrap();
            cur.replace(new)
        };
        let mut prev = self.previous.write().unwrap();
        std::mem::replace(&mut *prev, old_current)
    }
}
