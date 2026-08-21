// Status projection helpers (#6234 split out of the former monolithic
// `server/helpers.rs`).
//
// `refresh_status` is the single cold-path orchestration that projects
// worker, neighbor, session, NAT, CoS, tunnel, HA, queue, exception, and
// debug state onto the mutable `ProcessStatus`. It runs on control
// responses and state snapshots, never per packet. Ordering + side-effect
// cadence are preserved exactly: the WG/GRE liveness self-heal stays gated
// on `should_run_afxdp`, the high-cardinality per-key dynamic-neighbor
// dump stays gated on `XPF_DEBUG_NEIGHBOR_KEYS`, bindings are refreshed
// before the queue/per-binding projections, and worker snapshots are read
// before the aggregates derived from them. No added coordinator
// traversal, status clone, or allocation. Bodies byte-for-byte identical
// to the pre-split source.

use super::summarize_queues;
use crate::afxdp;
use crate::protocol::{BindingCountersSnapshot, ProcessStatus, UserspaceCapabilities};
use crate::server::ServerState;
use chrono::Utc;

pub(crate) fn refresh_status(state: &mut ServerState) {
    state.afxdp.refresh_bindings(&mut state.status.bindings);
    // #1866 Change 2: WG control-thread self-heal. Tombstone-only +
    // snapshot-coherent (see Coordinator::reconcile_wg_control_liveness)
    // and gated on should_run_afxdp so a disarmed/stopped helper never
    // re-binds WG ports (the stop-gate — Claude SMR r1 F1). Runs on
    // every non-suppressed control response; the per-id 3s backoff and
    // the ≤1-spawn-per-invocation bound keep the cadence trivial.
    if should_run_afxdp(&state.status) {
        state
            .afxdp
            .reconcile_wg_control_liveness(state.snapshot.as_ref());
        // #1881: GRE local-origin self-heal — tombstone-only +
        // snapshot-coherent + worker-gated, ≤1 spawn per invocation;
        // republishes the delivery map when the set changed.
        state
            .afxdp
            .reconcile_local_tunnel_liveness(state.snapshot.as_ref());
    }
    let writer_status = state.state_writer.status();
    state.status.io_uring_active = writer_status.active;
    state.status.io_uring_mode = writer_status.mode;
    state.status.io_uring_last_error = writer_status.last_error;
    state.status.interface_addresses = state
        .snapshot
        .as_ref()
        .map(|s| s.interfaces.iter().map(|iface| iface.addresses.len()).sum())
        .unwrap_or(0);
    let (neighbor_entries, neighbor_generation) = state.afxdp.dynamic_neighbor_status();
    state.status.neighbor_entries = neighbor_entries;
    state.status.neighbor_generation = neighbor_generation;
    // #6034: ACK the highest applied authoritative manager-neighbor replace
    // generation so the Go manager can confirm a clear/replace landed.
    state.status.manager_neighbor_generation =
        state.afxdp.last_applied_manager_neighbor_generation();
    // #710: cluster-wide aggregate of cross-worker CoS no-owner-binding
    // drops. The per-binding increment site is mechanical; this is the
    // only operator-facing surface for the counter.
    state.status.cos_no_owner_binding_drops_total = state.afxdp.cos_no_owner_binding_drops_total();
    // #1636 option C: proactive-neighbor-warm telemetry surfaced to the
    // daemon's Prometheus collector.
    let (warm_drops, warm_disconnected) = state.afxdp.neighbor_warm_counters();
    state.status.neighbor_warm_drops_total = warm_drops;
    state.status.neighbor_warm_disconnected_total = warm_disconnected;
    // #1782 cold-start capture instrumentation: per-binding-summed
    // neg-neigh fast-fail (H1) and pending_neigh duplicate-drop (H5)
    // counters, plus a debug dump of the dynamic_neighbors key set so the
    // capture harness can confirm the t0' next-hop miss (H2).
    state.status.neg_neigh_fast_fail_total = state.afxdp.neg_neigh_fast_fail_total();
    state.status.pending_neigh_duplicate_drops_total =
        state.afxdp.pending_neigh_duplicate_drops_total();
    // #1902: decap-refusal gate at pending_neigh admission (the
    // outer-frame/inner-meta pairing must never reach the in-place
    // retry TX path).
    state.status.pending_neigh_decap_drops_total = state.afxdp.pending_neigh_decap_drops_total();
    // #2375: distinct-hop capacity-drop gate at pending_neigh admission
    // (a NEW unresolved hop refused because the map is at
    // MAX_PENDING_NEIGH) — the scan/upstream-outage failure mode, kept
    // separate from the duplicate-drop counter.
    state.status.pending_neigh_capacity_drops_total =
        state.afxdp.pending_neigh_capacity_drops_total();
    // #5673: data-path neighbor learns refused by the aggregate
    // dynamic-neighbor map cap. A rising value means a spoofed-source
    // pre-policy flood (source learning runs on RX before screen/policy) is
    // being bounded rather than inflating the shared map.
    state.status.dynamic_neighbor_learn_cap_drops_total =
        state.afxdp.dynamic_neighbor_learn_cap_drops_total();
    // #1789: total failed USERSPACE_SESSIONS BPF-map publishes
    // (per-binding worker-poll sites + shared no-binding sites). The
    // cause-side signal for rising XDP-shim NO_SESSION fallbacks.
    state.status.session_publish_errors_total = state.afxdp.session_publish_errors_total();
    // #4800: new-flow-install contention surface — the publish and
    // replication legs. The NAT-allocator leg rides source_nat_pools.
    state.status.shared_session_publishes_total = state.afxdp.shared_session_publishes_total();
    state.status.shared_session_publish_lock_acquisitions_total =
        state.afxdp.shared_session_publish_lock_acquisitions_total();
    state.status.shared_session_publish_lock_contended_total =
        state.afxdp.shared_session_publish_lock_contended_total();
    state.status.session_replication_upserts_total =
        state.afxdp.session_replication_upserts_total();
    state.status.session_replication_enqueued_total =
        state.afxdp.session_replication_enqueued_total();
    state.status.session_replication_lock_contended_total =
        state.afxdp.session_replication_lock_contended_total();
    state.status.session_replication_queue_depth_sum =
        state.afxdp.session_replication_queue_depth_sum();
    state.status.session_replication_queue_depth_max =
        state.afxdp.session_replication_queue_depth_max();
    // #2244: total failed dnat_table reverse-SNAT BPF-map publishes. The
    // cause-side signal for dnat_table capacity pressure that silently
    // breaks embedded-ICMP NAT reversal (PMTUD / traceroute).
    state.status.dnat_publish_errors_total = state.afxdp.dnat_publish_errors_total();
    // #5674: peer-synced session imports rejected by the coordinator's
    // aggregate admission bound — the availability/DoS ceiling that keeps a
    // peer under session-table pressure (or a compromised peer) from driving
    // this node past its own aggregate session ceiling and multiplying that
    // state across every worker.
    state.status.synced_import_cap_drops_total = state.afxdp.synced_import_cap_drops_total();
    // #1760 W3': shared-map NAT reverse-key displacement events — the
    // authoritative collision watch (covers MissingNeighborSeed installs
    // the per-worker counter cannot see).
    state.status.nat_reverse_key_shared_displacements_total =
        state.afxdp.nat_reverse_key_shared_displacements_total();
    // #1807: worker-command-queue poison recoveries (committed-prefix +
    // clear_poison policy in afxdp/worker_queue.rs). Nonzero = a worker
    // panic poisoned a command queue and it was recovered.
    state.status.worker_command_queue_poison_recoveries =
        state.afxdp.worker_command_queue_poison_recoveries_total();
    // #2315: GRE-decap RFC 6040 §4.2 illegal-combination drops (outer CE
    // over a Not-ECT inner). Nonzero = a misbehaving tunnel ingress
    // ECT-marked the outer for un-ECN inner traffic on a congested path.
    state.status.gre_decap_ecn_illegal_drops_total =
        state.afxdp.gre_decap_ecn_illegal_drops_total();
    // #2317: WG-decap RFC 6040 §4.2 illegal-combination drops (outer CE,
    // captured via recvmsg IP_RECVTOS/IPV6_RECVTCLASS, over a Not-ECT
    // inner). Nonzero = a misbehaving WG ingress CE-marked the outer for
    // un-ECN inner traffic on a congested path.
    state.status.wg_decap_ecn_illegal_drops_total =
        state.afxdp.wg_decap_ecn_illegal_drops_total();
    // #2331: native-GRE encap DF-set oversized-outer drops. Nonzero =
    // inner flows whose encapped size exceeds the tunnel path MTU; the
    // builder refused to emit the un-fragmentable DF outer (blackhole)
    // rather than silently dropping it downstream.
    state.status.gre_encap_df_oversize_drops_total =
        state.afxdp.gre_encap_df_oversize_drops_total();
    // #2782: native-GRE decap checksum-invalid drops (C bit set but the
    // GRE checksum failed to verify, or the header was truncated past the
    // Checksum+Reserved1 field). Nonzero = a checksummed GRE peer
    // delivering corrupt frames / a truncated GRE header. A verified
    // checksummed frame forwards (RFC 2784 §2.1 / RFC 2890); only the
    // corrupt residue is counted here.
    state.status.gre_decap_checksum_invalid_drops_total =
        state.afxdp.gre_decap_checksum_invalid_drops_total();
    // #2472: locally-generated error-reply per-reason token-bucket drops.
    // Nonzero = an error-amplification / reflection flood (or a routing loop)
    // being clamped before it emits unbounded generated ICMP/RST errors.
    state.status.time_exceeded_rate_limited_total =
        state.afxdp.time_exceeded_rate_limited_total();
    state.status.packet_too_big_rate_limited_total =
        state.afxdp.packet_too_big_rate_limited_total();
    state.status.reject_rate_limited_total = state.afxdp.reject_rate_limited_total();
    // The per-key dynamic_neighbors dump is a high-cardinality
    // (ifindex,ip)-labelled debug surface used only by the #1782 cold-start
    // capture. Gate it behind XPF_DEBUG_NEIGHBOR_KEYS so it is OFF by default:
    // unset -> empty field -> no Prometheus series AND no additional
    // dynamic_neighbor_keys() all-shard traversal here. (The scalar
    // neighbor_entries count above still takes the pre-existing len() shard
    // path regardless — this gate only removes the new per-key dump's
    // traversal + cardinality.) The operator launches the daemon with the env
    // set for the overnight capture only (review consensus: Codex + AGY +
    // Claude SMR all asked for this to be gated, not permanent on /metrics).
    state.status.dynamic_neighbor_keys = if std::env::var_os("XPF_DEBUG_NEIGHBOR_KEYS").is_some() {
        state
            .afxdp
            .dynamic_neighbor_keys()
            .into_iter()
            .map(|(ifindex, ip)| format!("{ifindex} {ip}"))
            .collect()
    } else {
        Vec::new()
    };
    // #1769: on-demand neighbor-resolver telemetry. Previously the only
    // neighbor metrics were the two warm counters; this surfaces the
    // stuck-state surface (pending depth, GET attempts/resolutions/
    // failures, probe-on-stale, epoch rejects, enqueue drops).
    let r = state.afxdp.neighbor_resolver_counters();
    state.status.neighbor_resolver_queue_depth = r.queue_depth;
    state.status.neighbor_resolver_enqueue_drops_total = r.enqueue_drops;
    state.status.neighbor_resolver_disconnected_total = r.disconnected;
    state.status.neighbor_resolver_get_attempts_total = r.get_attempts;
    state.status.neighbor_resolver_get_resolved_total = r.get_resolved;
    state.status.neighbor_resolver_probe_on_stale_total = r.probe_on_stale;
    state.status.neighbor_resolver_get_failures_total = r.get_failures;
    state.status.neighbor_resolver_epoch_rejects_total = r.epoch_rejects;
    // #1771 §2.6: backoff-retry GETs + the monitor thread's ENOBUFS /
    // upsert-only re-dump telemetry (§2.5 mechanism, previously blind).
    state.status.neighbor_resolver_get_backoff_attempts_total = r.get_backoff_attempts;
    state.status.neighbor_netlink_enobufs_total = r.netlink_enobufs;
    state.status.neighbor_netlink_redumps_total = r.netlink_redumps;
    state.status.neighbor_netlink_redump_upserts_total = r.netlink_redump_upserts;
    // #1771 §2.6: per-binding-summed gauges — distinct unresolved
    // next-hop keys in pending_neigh + keys in the negative caches.
    state.status.neighbor_pending_keys = state.afxdp.neighbor_pending_keys_total();
    state.status.neg_neigh_keys = state.afxdp.neg_neigh_keys_total();
    // #1772: neighbor/ARP resolution LATENCY telemetry (pending-dwell +
    // resolver GETNEIGH-RTT histograms + timeout-drop / max-depth).
    let lat = state.afxdp.neighbor_latency_telemetry();
    state.status.neighbor_pending_dwell_buckets = lat.pending_dwell.buckets.to_vec();
    state.status.neighbor_pending_dwell_sum_ns = lat.pending_dwell.sum_ns;
    state.status.neighbor_pending_dwell_count = lat.pending_dwell.count;
    state.status.neighbor_resolver_get_rtt_buckets = lat.resolver_get_rtt.buckets.to_vec();
    state.status.neighbor_resolver_get_rtt_sum_ns = lat.resolver_get_rtt.sum_ns;
    state.status.neighbor_resolver_get_rtt_count = lat.resolver_get_rtt.count;
    // #1865: per-WG-tunnel telemetry rows (empty — and omitted from
    // the wire — when no WG tunnel is configured).
    state.status.wg_tunnels = state.afxdp.wg_tunnel_statuses();
    state.status.neighbor_pending_timeout_drops_total = lat.pending_timeout_drops;
    state.status.neighbor_pending_max_depth = lat.pending_max_depth;
    state.status.route_entries = state.snapshot.as_ref().map(|s| s.routes.len()).unwrap_or(0);
    state.status.fabrics = state
        .snapshot
        .as_ref()
        .map(|s| s.fabrics.clone())
        .unwrap_or_default();
    state.status.worker_heartbeats = state.afxdp.worker_heartbeats();
    // #869: per-worker busy/idle runtime telemetry.
    state.status.worker_runtime = state.afxdp.worker_runtime_snapshots();
    state.status.session_table_entries = state
        .status
        .worker_runtime
        .iter()
        .map(|w| w.session_table_entries as usize)
        .sum();
    // #1760: aggregate the per-worker NAT reverse-key displacement
    // counters into the top-level status for operator visibility.
    state.status.nat_reverse_key_collisions = state
        .status
        .worker_runtime
        .iter()
        .map(|w| w.nat_reverse_key_collisions)
        .sum();
    // #1861: aggregate the per-worker install-refusal trio.
    state.status.session_create_drops = state
        .status
        .worker_runtime
        .iter()
        .map(|w| w.session_create_drops)
        .sum();
    state.status.session_install_admission_refused = state
        .status
        .worker_runtime
        .iter()
        .map(|w| w.session_install_admission_refused)
        .sum();
    state.status.session_install_partial = state
        .status
        .worker_runtime
        .iter()
        .map(|w| w.session_install_partial)
        .sum();
    state.status.max_sessions = state
        .status
        .worker_runtime
        .iter()
        .map(|w| w.max_sessions as usize)
        .sum();
    if state.status.max_sessions == 0 {
        state.status.max_sessions = state
            .afxdp
            .worker_count()
            .saturating_mul(crate::session::default_max_sessions());
    }
    state.status.debug_worker_threads = state.afxdp.worker_count();
    state.status.debug_identity_slots = state.afxdp.identity_count();
    state.status.debug_live_slots = state.afxdp.live_count();
    let (planned_workers, planned_bindings) = state.afxdp.planned_counts();
    state.status.debug_planned_workers = planned_workers;
    state.status.debug_planned_bindings = planned_bindings;
    let (reconcile_calls, reconcile_stage) = state.afxdp.reconcile_debug();
    state.status.debug_reconcile_calls = reconcile_calls;
    state.status.debug_reconcile_stage = reconcile_stage;
    state.status.ha_groups = state.afxdp.ha_groups();
    // Report enabled when all bindings are registered+armed (XSKMAP slots
    // populated). The per-queue xsk_rx_confirmed heartbeat gating handles
    // queues whose XSK RQ hasn't been bootstrapped yet — those get XDP_PASS
    // until they bootstrap naturally from background traffic.
    // Previously this required all bindings to be `ready` (first RX packet
    // received), which created a deadlock: ctrl=0 → XDP_PASS → no XSK RX
    // → not ready → ctrl stays 0.
    state.status.enabled = state.status.forwarding_armed
        && state.status.capabilities.forwarding_supported
        && !state.status.bindings.is_empty()
        && state
            .status
            .bindings
            .iter()
            .all(|b| b.registered && b.armed);
    state.status.queues = summarize_queues(&state.status.bindings);
    // #802: focused per-binding ring-pressure snapshot. Projected from
    // the freshly-refreshed BindingStatus entries so this field tracks
    // the same data source the richer `bindings[]` view exposes.
    state.status.per_binding = state
        .status
        .bindings
        .iter()
        .map(BindingCountersSnapshot::from)
        .collect();
    state.status.flow_cache_capacity = state
        .status
        .per_binding
        .iter()
        .map(|b| b.flow_cache_capacity as usize)
        .sum();
    // The dynamic neighbor cache is intentionally growable today. Keep
    // the field explicit and zero so Go renders it as a counter rather
    // than inventing a utilization denominator.
    state.status.neighbor_cache_capacity = 0;
    state.status.recent_session_deltas = state.afxdp.recent_session_deltas();
    state.status.recent_exceptions = state.afxdp.recent_exceptions();
    state.status.cos_interfaces = state.afxdp.cos_statuses();
    state.status.policy_rule_counters = state.afxdp.policy_rule_counters();
    state.status.nat_rule_counters = state.afxdp.nat_rule_counters();
    state.status.filter_term_counters = state.afxdp.filter_term_counters();
    // #3651: publish the pre-summed per-zone traffic block. Stamp the layout
    // version only when there is data (rows or overflow) so a helper with no
    // configured/active zones keeps the wire omitted (cold-path convention).
    state.status.zone_traffic_counters = state.afxdp.zone_traffic_counters();
    state.status.zone_counter_overflow_active = state.afxdp.zone_counter_overflow_active();
    state.status.zone_counter_layout_version = if state.status.zone_traffic_counters.is_empty()
        && !state.status.zone_counter_overflow_active
    {
        0
    } else {
        state.afxdp.zone_counter_layout_version()
    };
    // #3651: and the pre-summed per-zone FLOOD-event block, same convention.
    state.status.zone_flood_counters = state.afxdp.zone_flood_counters();
    state.status.flood_counter_overflow_active = state.afxdp.flood_counter_overflow_active();
    state.status.flood_counter_layout_version = if state.status.zone_flood_counters.is_empty()
        && !state.status.flood_counter_overflow_active
    {
        0
    } else {
        state.afxdp.flood_counter_layout_version()
    };
    state.status.three_color_policer_counters = state.afxdp.three_color_policer_counters();
    state.status.source_nat_pools = state.afxdp.source_nat_pool_statuses();
    let (flow_worker_map, flow_worker_map_truncated) = state.afxdp.flow_worker_map();
    state.status.flow_worker_map = flow_worker_map;
    state.status.flow_worker_map_truncated = flow_worker_map_truncated;
    let (cos_active_flow_counts, cos_active_flow_counts_truncated) =
        state.afxdp.cos_active_flow_counts();
    state.status.cos_active_flow_counts = cos_active_flow_counts;
    state.status.cos_active_flow_counts_truncated = cos_active_flow_counts_truncated;
    state.status.last_resolution = state.afxdp.last_resolution();
    state.status.slow_path = state.afxdp.slow_path_status().into();
    if let Some(es_stats) = state.afxdp.event_stream_stats() {
        state.status.event_stream_connected = es_stats.connected;
        state.status.event_stream_seq = es_stats.seq;
        state.status.event_stream_acked = es_stats.acked_seq;
        state.status.event_stream_sent = es_stats.sent;
        state.status.event_stream_dropped = es_stats.dropped;
        state.status.event_stream_write_stalls = es_stats.write_stalls;
        state.status.event_stream_replay_evictions = es_stats.replay_evictions;
        state.status.event_stream_invalid_acks = es_stats.invalid_acks;
        // #2512: surface the per-kind SESSION_CLOSE / SESSION_CREATE
        // producer-side sent/dropped counters so a rate-limited or
        // budget-shed close/create is observable in `show` / Prometheus.
        state.status.event_stream_session_close_sent = es_stats.dataplane_events.session_close.sent;
        state.status.event_stream_session_close_dropped =
            es_stats.dataplane_events.session_close.dropped;
        state.status.event_stream_session_create_sent =
            es_stats.dataplane_events.session_create.sent;
        state.status.event_stream_session_create_dropped =
            es_stats.dataplane_events.session_create.dropped;
    }
    state.status.last_cache_flush_at = state.afxdp.last_cache_flush_at();
    // #3773 (M13): surface the cumulative fabric-skip diagnostic atomics so an
    // operator (and Prometheus) sees a silently-unresolved HA cross-chassis
    // fabric link. Malformed = a config/environment fault; unresolved-peer =
    // the expected late-resolution transient (distinct counter).
    state.status.fabric_link_skipped_malformed_total =
        state.afxdp.fabric_link_skipped_malformed_total();
    state.status.fabric_link_unresolved_peer_total =
        state.afxdp.fabric_link_unresolved_peer_total();
}

pub(crate) fn forwarding_unsupported_error(cap: &UserspaceCapabilities) -> String {
    if cap.unsupported_reasons.is_empty() {
        return "userspace live forwarding is not supported for the current configuration"
            .to_string();
    }
    format!(
        "userspace live forwarding is not supported: {}",
        cap.unsupported_reasons.join("; ")
    )
}

pub(crate) fn reconcile_status_bindings(
    state: &mut ServerState,
) -> Result<(), afxdp::ReconcileError> {
    if !should_run_afxdp(&state.status) {
        state.afxdp.stop();
        // #2794: route the disarmed-forwarding teardown through
        // `refresh_bindings` rather than hand-clearing a SUBSET of the
        // per-binding fields. `stop()` (above) emptied `workers.live` and
        // cleared the CoS owner maps, so `refresh_bindings` routes every
        // now-workerless slot through `zero_unbound_slot` — clearing the
        // FULL survivor set (`socket_ifindex`/`socket_queue_id`/
        // `socket_bind_flags`, `flow_cache_capacity`, `active_flow_count`,
        // every counter gauge, the latency histograms, and the
        // `bound`/`xsk_registered`/`xsk_bind_mode`/`zero_copy`/`socket_fd`/
        // `ready`/`last_error` fields the old hand-clear touched) AND
        // rebuilds the CoS owner->worker map empty. This is the same tail
        // the no_snapshot reconcile arm now runs (#2515): previously this
        // sibling path left `socket_ifindex`/`queue_id`/`bind_flags` +
        // `flow_cache_capacity`/`active_flow_count` stale, so status
        // commands reported a disarmed slot as if still bound on its old
        // queue.
        let mut bindings = std::mem::take(&mut state.status.bindings);
        state.afxdp.refresh_bindings(&mut bindings);
        state.status.bindings = bindings;
        // A disarmed reconcile is a stop/teardown — always successful.
        return Ok(());
    }
    let snapshot = state.snapshot.clone();
    let ring_entries = state.status.ring_entries;
    let mut bindings = std::mem::take(&mut state.status.bindings);
    // #3789: propagate the reconcile outcome. A pre-teardown abort
    // (integrity / mandatory-map failure) leaves the prior workers +
    // forwarding + generation live (#2440/#2484); the caller uses the
    // Err to fail closed instead of persisting a rejected snapshot.
    let result = state
        .afxdp
        .reconcile(snapshot.as_ref(), &mut bindings, ring_entries);
    state.status.bindings = bindings;
    result
}

pub(crate) fn should_run_afxdp(status: &ProcessStatus) -> bool {
    status.forwarding_armed && status.capabilities.forwarding_supported
}

pub(crate) fn set_bindings_forwarding_armed(status: &mut ProcessStatus, armed: bool) {
    for binding in &mut status.bindings {
        binding.armed = armed && binding.registered;
        binding.last_change = Some(Utc::now());
    }
}
