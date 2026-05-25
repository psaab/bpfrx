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
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, RwLock};

#[derive(Debug)]
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
    /// `endpoint` doc for the rationale.
    ///
    /// TODO(#1499 r4 / timers): paired with `REJECT_AFTER_TIME` and
    /// `REKEY_AFTER_TIME`, persistent-keepalive needs a timer-driven
    /// slow-path worker. Currently the engine has zero time-based
    /// state; the integration PR will introduce a coordinator-side
    /// ticker that calls into the engine to (a) emit keepalive
    /// records, (b) tear down sessions past REJECT_AFTER_TIME, and
    /// (c) request rekey at REKEY_AFTER_TIME. Forward secrecy is
    /// degraded until that timer ships — sessions live until counter
    /// exhaustion (2^64-2^13-1 packets ≈ 39 thousand years at
    /// 10 Gbps line rate, but the AEAD key never rotates without
    /// the timer).
    pub(crate) persistent_keepalive: AtomicU16,
    /// The current transport session, if a handshake has completed.
    /// RwLock because rekey is a slow-path replacement and the hot
    /// path only takes a read guard to encrypt/decrypt.
    pub(crate) current: RwLock<Option<Arc<WgSession>>>,
    /// The previous transport session, retained across rekey so
    /// in-flight ciphertexts decrypt successfully. Same lock
    /// discipline as `current`.
    pub(crate) previous: RwLock<Option<Arc<WgSession>>>,
}

impl Peer {
    pub(crate) fn new(
        pubkey: [u8; 32],
        endpoint: Option<SocketAddr>,
        persistent_keepalive: u16,
    ) -> Self {
        Self {
            pubkey,
            endpoint: RwLock::new(endpoint),
            persistent_keepalive: AtomicU16::new(persistent_keepalive),
            current: RwLock::new(None),
            previous: RwLock::new(None),
        }
    }

    /// Update the mutable per-peer config fields in place. Called
    /// from `WgEngine::reconcile_peers` when the new config snapshot
    /// reuses an existing peer Arc (same pubkey). Keeping the peer
    /// Arc alive preserves the (current, previous) session pair across
    /// the commit; only the operator-facing fields shift.
    pub(crate) fn update_config(&self, endpoint: Option<SocketAddr>, persistent_keepalive: u16) {
        *self.endpoint.write().unwrap() = endpoint;
        self.persistent_keepalive
            .store(persistent_keepalive, Ordering::Relaxed);
    }

    /// Snapshot the current endpoint. Slow path only.
    #[allow(dead_code)] // Consumed by integration PR + tests.
    pub(crate) fn endpoint(&self) -> Option<SocketAddr> {
        *self.endpoint.read().unwrap()
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
