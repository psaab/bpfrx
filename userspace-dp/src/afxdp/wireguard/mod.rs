mod engine;
mod packet;
mod prefix_map;

pub(super) use engine::WireGuardDecapOutcome;
pub(super) use engine::WireGuardEngine;
pub(super) use engine::WireGuardPeerSnapshot;

use rustc_hash::FxHashMap;
use std::net::IpAddr;

/// Per-worker WireGuard state.
///
/// Owns engines (keyed by listen port), interface-name→port map,
/// and the decap scratch buffer. All bindings on the same worker
/// share the same engines (via `Arc<Mutex<>>`) to keep the boringtun
/// replay window, nonce counter, and handshake state consistent
/// across all ingress NICs. Scratch buffers are per-binding and not
/// shared.
///
/// When `num_bindings > 1`, each binding's `apply_snapshot` locks the
/// shared engines and updates them identically — the operation is
/// idempotent.
pub(super) struct WireguardBindingState {
    engines: std::sync::Arc<std::sync::Mutex<FxHashMap<u16, engine::WireGuardEngine>>>,
    interfaces: FxHashMap<String, u16>,
    scratch_in: Vec<u8>,
}

impl WireguardBindingState {
    pub fn new() -> Self {
        Self {
            engines: std::sync::Arc::new(std::sync::Mutex::new(FxHashMap::default())),
            interfaces: FxHashMap::default(),
            scratch_in: Vec::with_capacity(65536),
        }
    }

    /// Create a new `WireguardBindingState` that shares the same
    /// engine map as `self`. Use when multiple bindings need to
    /// operate on the same WireGuard peer state.
    pub fn new_sharing(&self) -> Self {
        Self {
            engines: self.engines.clone(),
            interfaces: FxHashMap::default(),
            scratch_in: Vec::with_capacity(65536),
        }
    }

    pub fn apply_snapshot(
        &mut self,
        ifname: &str,
        private_key: &str,
        public_key: &str,
        listen_port: u16,
        peers: &[WireGuardPeerSnapshot],
        virtual_ifindex: Option<u32>,
    ) {
        self.interfaces.insert(ifname.to_string(), listen_port);
        let mut engines = self.engines.lock().unwrap();
        engines
            .entry(listen_port)
            .or_insert_with(WireGuardEngine::new)
            .apply_snapshot(private_key, public_key, listen_port, peers, virtual_ifindex);
    }

    pub fn remove_snapshot(&mut self, ifname: &str) {
        if let Some(port) = self.interfaces.remove(ifname) {
            let mut engines = self.engines.lock().unwrap();
            if !self.interfaces.values().any(|p| *p == port) {
                engines.remove(&port);
            }
        }
    }

    /// Reconcile the engine set from a full snapshot.
    ///
    /// Removes engines for interfaces that were present in `before`
    /// but absent from `after`, so stale peer state doesn't linger
    /// after a config commit drops a WG interface.
    pub fn reconcile_snapshots(
        &mut self,
        before: &FxHashMap<String, u16>,
        after: &[(String, u16)],
    ) {
        let after_ports: std::collections::BTreeSet<u16> =
            after.iter().map(|(_, p)| *p).collect();
        let mut engines = self.engines.lock().unwrap();
        for (_ifname, port) in before {
            if !after_ports.contains(port) {
                engines.remove(port);
            }
        }
    }

    /// Attempt WireGuard decapsulation for a packet on this binding.
    ///
    /// Looks up the engine by `meta.flow_dst_port` and delegates to
    /// `WireGuardEngine::try_decap`. Returns `WireGuardDecapOutcome::None`
    /// when no engine matches or the packet is not a WireGuard message.
    pub fn try_decap(
        &mut self,
        frame: &mut [u8],
        meta: &super::UserspaceDpMeta,
    ) -> engine::WireGuardDecapOutcome {
        if meta.protocol != packet::PROTO_UDP {
            return engine::WireGuardDecapOutcome::None;
        }
        let mut engines = self.engines.lock().unwrap();
        let Some(engine) = engines.get_mut(&meta.flow_dst_port) else {
            return engine::WireGuardDecapOutcome::None;
        };
        engine.try_decap(frame, meta, &mut self.scratch_in)
    }

    /// Attempt WireGuard encapsulation for an inner frame.
    ///
    /// Looks up the engine by `listen_port` and delegates to
    /// `WireGuardEngine::try_encap`. Returns `None` when no engine
    /// matches or the inner frame has no matching peer.
    pub fn try_encap(
        &mut self,
        inner_frame: &[u8],
        addr_family: u8,
        ingress_ifindex: u32,
        vlan_id: u16,
        preferred_local_ip: Option<IpAddr>,
        meta_dscp: u8,
        listen_port: u16,
    ) -> Option<(Vec<u8>, super::UserspaceDpMeta)> {
        let mut engines = self.engines.lock().unwrap();
        let engine = engines.get_mut(&listen_port)?;
        engine.try_encap(
            inner_frame,
            addr_family,
            ingress_ifindex,
            vlan_id,
            preferred_local_ip,
            meta_dscp,
        )
    }
}
