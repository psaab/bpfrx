//! WireGuard engine instantiation for `build_forwarding_state` (#1432
//! S2a). Builds one `Arc<WgEngine>` per `mode == "wireguard"` tunnel
//! endpoint and stores it in `ForwardingState.wg_engines`, keyed by
//! tunnel_endpoint_id.
//!
//! ## Reload stability (plan §4.2)
//!
//! A fresh `WgEngine` per commit resets its `Tai64nClock` and drops all
//! live transport sessions. A kernel WG peer rejects any handshake whose
//! TAI64N is `<=` the last it accepted, so naively rebuilding the engine
//! on every reload causes a re-handshake storm and can permanently
//! black-hole a tunnel.
//!
//! Two cases, both driven off the `previous` `ForwardingState`:
//!
//!   - **Identity unchanged** — if the previous state holds an engine for
//!     the same endpoint and the WG identity tuple (listen_port,
//!     local_privkey, peer_pubkey, allowed_ips, endpoint, keepalive) is
//!     byte-for-byte unchanged, **clone the existing `Arc<WgEngine>` and
//!     do NOT call `reconcile_peers`.** Workers across the reload window
//!     still hold the old `ForwardingState` Arc (and thus the same engine
//!     Arc); mutating shared engine state here would be observed by those
//!     workers. Cloning the Arc keeps the TAI64N clock and live sessions
//!     and avoids any cross-reload engine mutation.
//!
//!   - **Identity changed (or new)** — construct a fresh `WgEngine` (which
//!     reconciles the new peer set at construction) and **seed its TAI64N
//!     high-water from the prior engine** so initiator-timestamp
//!     monotonicity survives the rebuild. Live sessions are dropped (a
//!     real config change re-handshakes once, seeded so the peer accepts
//!     it); S5 adds session migration if needed.

use super::super::wg::{WgEngine, WgEngineConfig, WgPeerConfig};
use super::super::*;
use std::sync::Arc;

pub(super) fn populate_wg_engines(
    state: &mut ForwardingState,
    previous: Option<&ForwardingState>,
) {
    if !state.has_wg_tunnels {
        return;
    }
    for (&id, endpoint) in state.tunnel_endpoints.iter() {
        if endpoint.mode != "wireguard" {
            continue;
        }
        let peer = WgPeerConfig {
            pubkey: endpoint.wg_peer_pubkey,
            endpoint: endpoint.wg_endpoint,
            persistent_keepalive: endpoint.wg_keepalive_secs,
            allowed_ips: endpoint.wg_allowed_ips.clone(),
        };
        // Identity-stable reuse: same endpoint id with an unchanged WG
        // identity tuple reuses the prior engine Arc verbatim.
        if let Some(prev_state) = previous {
            if let (Some(prev_engine), Some(prev_endpoint)) = (
                prev_state.wg_engines.get(&id),
                prev_state.tunnel_endpoints.get(&id),
            ) {
                if wg_identity_unchanged(prev_endpoint, endpoint) {
                    state.wg_engines.insert(id, prev_engine.clone());
                    continue;
                }
            }
        }
        // Config changed or new: fresh engine, seeded from the prior
        // engine's TAI64N high-water (if any) so monotonicity survives.
        let engine = WgEngine::new(WgEngineConfig {
            local_private_key: *endpoint.wg_local_privkey,
            listen_port: endpoint.wg_listen_port,
            peers: vec![peer],
        });
        if let Some(prev_state) = previous {
            if let Some(prev_engine) = prev_state.wg_engines.get(&id) {
                if let Some(hw) = prev_engine.tai64n_high_water() {
                    engine.seed_tai64n_high_water(hw);
                }
            }
        }
        state.wg_engines.insert(id, Arc::new(engine));
    }
}

/// Whether two WG endpoints have a byte-identical WG identity tuple, so
/// the engine Arc can be reused across a reload without `reconcile_peers`.
fn wg_identity_unchanged(prev: &TunnelEndpoint, next: &TunnelEndpoint) -> bool {
    prev.wg_listen_port == next.wg_listen_port
        && *prev.wg_local_privkey == *next.wg_local_privkey
        && prev.wg_peer_pubkey == next.wg_peer_pubkey
        && prev.wg_allowed_ips == next.wg_allowed_ips
        && prev.wg_endpoint == next.wg_endpoint
        && prev.wg_keepalive_secs == next.wg_keepalive_secs
}
