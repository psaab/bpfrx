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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

/// Immutable per-snapshot peer config tuple (#2836).
///
/// `endpoint`, `persistent_keepalive`, and `preshared_key` are
/// operator-facing fields that change only on a config commit. They
/// USED to be interior-mutable on `Peer` and rewritten in place by
/// `reconcile_peers` on the reused peer Arc. That defeated the
/// documented `PeerTable` atomicity invariant: because the SAME peer
/// Arc is shared between the old and the new published table, an
/// in-place write was instantly visible to a reader still holding the
/// OLD table snapshot — so an old-prefix packet (matched against the
/// old AllowedIPs) could read the NEW endpoint and be encrypted to the
/// wrong underlay, and the endpoint/keepalive/PSK could be observed as
/// a torn mix of old and new.
///
/// The config is now an immutable bundle owned by the `PeerTable`
/// snapshot (one `Arc<PeerConfig>` per `PeerEntry`). `reconcile_peers`
/// builds a FRESH `PeerConfig` for every commit and the whole table is
/// published in a single `ArcSwap::store`, so a reader sees the
/// fully-old or the fully-new tuple, never a mix. The hot egress path
/// reads the endpoint straight from the loaded snapshot — no per-packet
/// `RwLock` (folds codex-049-04).
///
/// Roaming (#1499 r4) is unaffected: a learned-endpoint update would
/// still go through a reconcile (or a future table re-publish), which
/// builds a new immutable bundle and swaps it atomically.
pub(crate) struct PeerConfig {
    /// Optional outbound endpoint. `None` means responder-only.
    pub(crate) endpoint: Option<SocketAddr>,
    /// Optional keepalive interval in seconds (per WG: 0 = off).
    /// Consumed by the #1888 S5 timer pass (`WgEngine::timer_pass` T8 —
    /// see wg/timers.rs).
    pub(crate) persistent_keepalive: u16,
    /// Per-peer preshared key (#1434 B2). 32 zero bytes = no PSK
    /// (semantically identical to the all-zero key in Noise IKpsk2).
    /// SECRET: `Zeroizing` so the key material is wiped when the bundle
    /// drops (i.e. when the snapshot that owns it is freed); redacted in
    /// the manual Debug impl below; never logged. A config commit that
    /// rotates the PSK drops the old bundle, wiping the superseded key.
    pub(crate) preshared_key: zeroize::Zeroizing<[u8; 32]>,
}

impl PeerConfig {
    pub(crate) fn new(
        endpoint: Option<SocketAddr>,
        persistent_keepalive: u16,
        preshared_key: [u8; 32],
    ) -> Self {
        Self {
            endpoint,
            persistent_keepalive,
            preshared_key: zeroize::Zeroizing::new(preshared_key),
        }
    }

    /// Plain copy of the preshared key for the handshake builders (they
    /// hand it straight to snow's `psk`/`set_psk`). 32 zero bytes = no
    /// PSK. The snapshot-resident master copy stays `Zeroizing`.
    pub(crate) fn preshared_key(&self) -> [u8; 32] {
        *self.preshared_key
    }
}

impl std::fmt::Debug for PeerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let psk_set = *self.preshared_key != [0u8; 32];
        f.debug_struct("PeerConfig")
            .field("endpoint", &self.endpoint)
            .field("persistent_keepalive", &self.persistent_keepalive)
            .field("preshared_key", &if psk_set { "<redacted>" } else { "<unset>" })
            .finish()
    }
}

/// A peer's long-lived, config-independent state: its identity, its
/// transport sessions, and its timer bookkeeping. Reused across config
/// commits (same pubkey → same `Arc<Peer>`) so the (current, previous)
/// session pair and timer pacing survive a commit. The operator-facing
/// config tuple lives in the per-snapshot `PeerConfig` (#2836), NOT
/// here, so config changes are observed atomically with the table swap.
pub(crate) struct Peer {
    pub(crate) pubkey: [u8; 32],
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
}

impl std::fmt::Debug for Peer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The operator-facing config (endpoint/keepalive/PSK) now lives
        // in the per-snapshot `PeerConfig`, not on `Peer`.
        f.debug_struct("Peer")
            .field("pubkey", &self.pubkey)
            .field("current", &self.current)
            .field("previous", &self.previous)
            .finish()
    }
}

impl Peer {
    pub(crate) fn new(pubkey: [u8; 32]) -> Self {
        Self {
            pubkey,
            last_send_any_ns: AtomicU64::new(0),
            last_recv_any_ns: AtomicU64::new(0),
            t6_armed_recv_ns: AtomicU64::new(0),
            t7_armed_send_ns: AtomicU64::new(0),
            t8_last_attempt_ns: AtomicU64::new(0),
            current: RwLock::new(None),
            previous: RwLock::new(None),
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
