//! #1328 Phase 2 — snapshot apply phase.
//!
//! Originally pure code motion from the middle of the pre-#1328
//! monolithic `Coordinator::reconcile` body: install
//! validation/forwarding state, re-arm slow path, publish HA-fabrics
//! snapshot, then open the required BPF map FDs.
//!
//! #2440 ordering invariant: the mandatory BPF map FDs
//! (xsk/heartbeat/sessions) — the real correctness boundary — are now
//! opened by [`preflight_map_fds`], which the orchestrator
//! (`reconcile/mod.rs`) runs BEFORE worker teardown and BEFORE any
//! publish. `apply_snapshot` therefore receives the already-secured
//! FDs and only runs once bring-up is guaranteed possible. A
//! mandatory-FD failure aborts in the preflight WITHOUT tearing down
//! the prior workers or publishing a newer forwarding generation, so a
//! snapshot whose required pins are missing/unopenable can never strand
//! the helper advertising a data-plane view backed by no workers
//! (fail-open partial apply). On any missing-pin or open-failure
//! `preflight_map_fds` sets `last_reconcile_stage` plus
//! per-registered-binding `last_error` (matching the pre-#1328 messages
//! verbatim) and returns `None`; the orchestrator bails before
//! `tear_down`.
use super::ReconcileSnapshotFds;
// Re-use afxdp scope (coordinator/mod.rs uses the same pattern).
use super::super::super::*;
use super::super::Coordinator;
use std::collections::BTreeMap;
use std::sync::Arc;

/// #2440: open the mandatory + optional BPF map FDs and surface any
/// missing-pin / open-failure BEFORE the orchestrator tears down the
/// current workers or `apply_snapshot` publishes a newer forwarding
/// generation. The mandatory map open (xsk/heartbeat/sessions) is the
/// real correctness boundary: if any of the three is missing or fails
/// to open, this returns `None` after setting `last_reconcile_stage` +
/// per-registered-binding `last_error` (verbatim pre-#1328 messages),
/// and the orchestrator aborts WITHOUT teardown or publish — the prior
/// generation stays published and the prior workers keep running.
///
/// The optional maps (conntrack v4/v6, dnat tables) are best-effort:
/// they never gate the reconcile, matching the historical behavior.
pub(super) fn preflight_map_fds(
    coord: &mut Coordinator,
    snapshot: &ConfigSnapshot,
    bindings: &mut [BindingStatus],
) -> Option<ReconcileSnapshotFds> {
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

pub(super) fn apply_snapshot(
    coord: &mut Coordinator,
    snapshot: &ConfigSnapshot,
    preserved_slow_path: Option<Arc<SlowPathReinjector>>,
    prior_tunnel_owners: &[(u16, String)],
    snapshot_was_installed: bool,
    preserved_synced_sessions: &mut Vec<SyncedSessionEntry>,
    fds: ReconcileSnapshotFds,
) -> Option<ReconcileSnapshotFds> {
    // #1606: preflight policy build BEFORE any side-effecting
    // mutation. Surfaces address-book integrity errors (id=0,
    // duplicate ids, unknown rule references) before
    // ValidationState, policy_counters, or coord.forwarding is
    // mutated.
    let new_forwarding = match build_forwarding_state_with_policy_counters_and_previous(
        snapshot,
        &coord.policy_counters,
        &coord.nat_counters,
        Some(&coord.forwarding),
    ) {
        Ok(fwd) => fwd,
        Err(err) => {
            // #2440 (Copilot follow-up): record the stage so the
            // integrity failure is observable via status.rs
            // (last_reconcile_stage), matching the descriptive-stage
            // pattern the preflight_map_fds legs use. Without this the
            // field retained a stale value from a prior reconcile.
            coord.last_reconcile_stage = "snapshot_integrity_error".to_string();
            eprintln!(
                "xpf-userspace-dp: snapshot integrity error during reconcile: {} — keeping previous forwarding state",
                err
            );
            return None;
        }
    };

    coord.validation = ValidationState {
        snapshot_installed: true,
        config_generation: snapshot.generation,
        fib_generation: snapshot.fib_generation,
    };
    coord.policy_counters.reconcile_rules(&snapshot.policies);
    // #2218: drop hit counters for NAT rules removed by this config.
    coord
        .nat_counters
        .reconcile_ids(&super::super::snapshot_active_nat_counter_ids(snapshot));
    // #1866 D3: WG endpoint-set transition log at the reconcile apply
    // boundary (mirrors refresh_runtime_snapshot).
    super::super::log_wg_endpoint_set_transition("reconcile", &coord.forwarding, &new_forwarding);
    // #1873 R-D: the purge diff runs against the tunnel-owner map
    // captured BEFORE teardown (AGY code r3) — stop_inner(false) has
    // already defaulted coord.forwarding, so diffing the live state
    // here would make every purge arm inert across a reconcile
    // boundary while the preserved shared maps still hold the old
    // entries. The purge is cleanup, not the correctness boundary —
    // re-resolution and the encap builders refuse an id whose owning
    // netdev ifindex differs from the session's stored one (Codex
    // code-review r2; replaces the unsound r1 defer + rotation-barrier
    // design). New-appearance purging is gated on the GENUINE first
    // apply of the helper's life (flag captured before teardown).
    let tunnel_purge_ids = super::super::tunnel_remap_purge_ids_from_owners(
        prior_tunnel_owners,
        &new_forwarding,
        snapshot_was_installed,
    );
    coord.purge_remapped_tunnel_sessions(&tunnel_purge_ids);
    // The bringup phase replays `preserved_synced_sessions` (captured
    // BEFORE this purge) into the shared maps — filter the purged ids
    // AND their derived reverse companions out so the replay cannot
    // resurrect them, whole or as half-dead pairs (code r3; companion
    // semantics per AGY code r4).
    super::super::filter_replayed_synced_sessions(preserved_synced_sessions, &tunnel_purge_ids);
    coord.forwarding = new_forwarding;
    coord.shared_validation.store(Arc::new(coord.validation));
    coord
        .ha
        .forwarding
        .store(Arc::new(coord.forwarding.clone()));
    coord.slow_path = if let Some(slow_path) = preserved_slow_path {
        // #2408: the live TUN keeps the MTU it was created with — the
        // preserved reinjector is NOT re-opened, so a config MTU increase
        // applied after the daemon is running does not reprogram the running
        // TUN until the slow path is recreated (process restart, or the slow
        // path going inactive->active). First-boot jumbo configs ARE covered
        // (they hit the else branch below). Warn once per distinct value so a
        // steady-state reconcile loop does not flood.
        let desired_mtu = snapshot.slow_path_mtu();
        if desired_mtu != slow_path.mtu() && desired_mtu != coord.last_slow_path_mtu_warned {
            eprintln!(
                "xpf-ha: slow-path TUN MTU stays {} (config now wants {}); the live TUN is not reprogrammed until the slow path is recreated (xpfd restart). Reinjected frames larger than {} will drop on the slow path until then.",
                slow_path.mtu(),
                desired_mtu,
                slow_path.mtu()
            );
            coord.last_slow_path_mtu_warned = desired_mtu;
        }
        coord.last_slow_path_status = slow_path.status();
        Some(slow_path)
    } else {
        // #2408: size the slow-path TUN to the largest configured
        // data-interface MTU so reinjected jumbo frames are not dropped on
        // the TUN egress (default kernel TUN MTU is 1500).
        match SlowPathReinjector::new(DEFAULT_SLOW_PATH_TUN, snapshot.slow_path_mtu()) {
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
    // #2440: the mandatory + optional map FDs were already opened by
    // `preflight_map_fds` BEFORE teardown/publish. By the time we get
    // here bring-up is guaranteed possible, so the publish above is
    // never stranded behind an FD-open failure. Hand the secured FDs to
    // the bring-up phase.
    Some(fds)
}
