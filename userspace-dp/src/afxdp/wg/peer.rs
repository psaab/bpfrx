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
use std::sync::{Arc, RwLock};

#[derive(Debug)]
pub(crate) struct Peer {
    pub(crate) pubkey: [u8; 32],
    /// Optional outbound endpoint. None means responder-only.
    pub(crate) endpoint: Option<SocketAddr>,
    /// Optional keepalive interval in seconds (per WG: 0 = off).
    pub(crate) persistent_keepalive: u16,
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
            endpoint,
            persistent_keepalive,
            current: RwLock::new(None),
            previous: RwLock::new(None),
        }
    }

    /// Replace `current` with `new`, moving the old current to
    /// `previous`. Called from the slow-path handshake-complete code.
    pub(crate) fn rotate_session(&self, new: Arc<WgSession>) {
        let old_current = {
            let mut cur = self.current.write().unwrap();
            cur.replace(new)
        };
        let mut prev = self.previous.write().unwrap();
        *prev = old_current;
    }
}
