//! #1328 Phase 2 — snapshot apply phase.
//!
//! Pure code motion from the middle of the pre-#1328 monolithic
//! `Coordinator::reconcile` body (lines 400–528 of the old
//! `mod.rs`): install validation/forwarding state, re-arm slow
//! path, publish HA-fabrics snapshot, then open the required BPF
//! map FDs (xsk/heartbeat/sessions) plus the optional ones
//! (conntrack v4/v6, dnat tables).
//!
//! On any missing-pin or open-failure, sets `last_reconcile_stage`
//! plus per-registered-binding `last_error` (matching the
//! pre-#1328 messages verbatim) and returns `None`. The orchestrator
//! bails on `None`.
use super::ReconcileSnapshotFds;
// Re-use afxdp scope (coordinator/mod.rs uses the same pattern).
use super::super::super::*;
use super::super::Coordinator;
use std::collections::BTreeMap;
use std::sync::Arc;

pub(super) fn apply_snapshot(
    coord: &mut Coordinator,
    snapshot: &ConfigSnapshot,
    bindings: &mut [BindingStatus],
    preserved_slow_path: Option<Arc<SlowPathReinjector>>,
) -> Option<ReconcileSnapshotFds> {
    coord.validation = ValidationState {
        snapshot_installed: true,
        config_generation: snapshot.generation,
        fib_generation: snapshot.fib_generation,
    };
    coord.policy_counters.reconcile_rules(&snapshot.policies);
    coord.forwarding = build_forwarding_state_with_policy_counters_and_previous(
        snapshot,
        &coord.policy_counters,
        Some(&coord.forwarding),
    );
    coord.shared_validation.store(Arc::new(coord.validation));
    coord
        .ha
        .forwarding
        .store(Arc::new(coord.forwarding.clone()));
    coord.slow_path = if let Some(slow_path) = preserved_slow_path {
        coord.last_slow_path_status = slow_path.status();
        Some(slow_path)
    } else {
        match SlowPathReinjector::new(DEFAULT_SLOW_PATH_TUN) {
            Ok(reinjector) => {
                coord.last_slow_path_status = reinjector.status();
                Some(Arc::new(reinjector))
            }
            Err(err) => {
                coord.last_slow_path_status = SlowPathStatus {
                    last_error: err,
                    ..SlowPathStatus::default()
                };
                None
            }
        }
    };
    coord
        .local_tunnel_deliveries
        .store(Arc::new(BTreeMap::new()));
    coord
        .ha
        .fabrics
        .store(Arc::new(coord.forwarding.fabrics.clone()));
    if snapshot.map_pins.xsk.is_empty() {
        coord.last_reconcile_stage = "missing_xsk_pin".to_string();
        for binding in bindings.iter_mut() {
            if binding.registered {
                binding.last_error = "missing XSK map pin path".to_string();
            }
        }
        return None;
    }
    if snapshot.map_pins.heartbeat.is_empty() {
        coord.last_reconcile_stage = "missing_heartbeat_pin".to_string();
        for binding in bindings.iter_mut() {
            if binding.registered {
                binding.last_error = "missing heartbeat map pin path".to_string();
            }
        }
        return None;
    }
    if snapshot.map_pins.sessions.is_empty() {
        coord.last_reconcile_stage = "missing_session_pin".to_string();
        for binding in bindings.iter_mut() {
            if binding.registered {
                binding.last_error = "missing session map pin path".to_string();
            }
        }
        return None;
    }
    let map_fd = match OwnedFd::open_bpf_map(&snapshot.map_pins.xsk) {
        Ok(fd) => fd,
        Err(err) => {
            coord.last_reconcile_stage = format!("open_xsk_map_failed:{err}");
            for binding in bindings.iter_mut() {
                if binding.registered {
                    binding.last_error = format!("open XSK map: {err}");
                }
            }
            return None;
        }
    };
    let heartbeat_map_fd = match OwnedFd::open_bpf_map(&snapshot.map_pins.heartbeat) {
        Ok(fd) => fd,
        Err(err) => {
            coord.last_reconcile_stage = format!("open_heartbeat_map_failed:{err}");
            for binding in bindings.iter_mut() {
                if binding.registered {
                    binding.last_error = format!("open heartbeat map: {err}");
                }
            }
            return None;
        }
    };
    let session_map_fd = match OwnedFd::open_bpf_map(&snapshot.map_pins.sessions) {
        Ok(fd) => fd,
        Err(err) => {
            coord.last_reconcile_stage = format!("open_session_map_failed:{err}");
            for binding in bindings.iter_mut() {
                if binding.registered {
                    binding.last_error = format!("open session map: {err}");
                }
            }
            return None;
        }
    };
    // Open BPF conntrack maps (sessions, sessions_v6) so the helper can
    // publish session entries that "show security flow session" reads.
    // Non-fatal: if the maps don't exist, session display will lack
    // zone/interface info.
    let conntrack_v4_fd = if !snapshot.map_pins.conntrack_v4.is_empty() {
        OwnedFd::open_bpf_map(&snapshot.map_pins.conntrack_v4).ok()
    } else {
        None
    };
    let conntrack_v6_fd = if !snapshot.map_pins.conntrack_v6.is_empty() {
        OwnedFd::open_bpf_map(&snapshot.map_pins.conntrack_v6).ok()
    } else {
        None
    };
    // Open dnat_table BPF map for embedded ICMP NAT reversal support.
    // Non-fatal: if the map doesn't exist, embedded ICMP won't work
    // but normal forwarding is unaffected.
    let dnat_table_fd = if !snapshot.map_pins.dnat_table.is_empty() {
        OwnedFd::open_bpf_map(&snapshot.map_pins.dnat_table).ok()
    } else {
        None
    };
    let dnat_table_v6_fd = if !snapshot.map_pins.dnat_table_v6.is_empty() {
        OwnedFd::open_bpf_map(&snapshot.map_pins.dnat_table_v6).ok()
    } else {
        None
    };
    let dnat_fds = DnatTableFds {
        v4: dnat_table_fd.as_ref().map(|f| f.fd),
        v6: dnat_table_v6_fd.as_ref().map(|f| f.fd),
    };
    Some(ReconcileSnapshotFds {
        map_fd,
        heartbeat_map_fd,
        session_map_fd,
        conntrack_v4_fd,
        conntrack_v6_fd,
        dnat_table_fd,
        dnat_table_v6_fd,
        dnat_fds,
    })
}
