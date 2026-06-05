use super::*;

/// Operator-status surface split out of `coordinator/mod.rs` to keep
/// the gRPC / HTTP status methods in one place. Most are pure-read
/// snapshots (e.g. `cos_statuses` loads ArcSwap values and aggregates
/// them); the one exception is `drain_session_deltas`, which mutates
/// per-binding state by popping entries off `pending_session_deltas`
/// and bumping `session_delta_drained`. Coordinator lifecycle
/// (worker spawn / shutdown / reconcile) and HA reconciliation state
/// stay in mod.rs and ha.rs.
impl super::Coordinator {
    pub fn dynamic_neighbor_status(&self) -> (usize, u64) {
        let entries = self.neighbors.dynamic.len();
        let generation = self.neighbors.generation.load(Ordering::Relaxed);
        (entries, generation)
    }

    /// #710: sum of `no_owner_binding_drops` across every binding's
    /// `BindingLiveState`. The per-binding increment site lives in
    /// `apply_worker_shaped_tx_requests` and mechanically lands on
    /// `bindings.first_mut()` (there is no binding to attribute to —
    /// the whole point of the counter is that the request's egress
    /// has no binding on this worker). Summing across every binding's
    /// live state gives the cluster-wide total regardless of which
    /// worker's "first binding" the increments landed on. This is the
    /// only operator-facing surface for this counter.
    pub fn cos_no_owner_binding_drops_total(&self) -> u64 {
        self.workers
            .live
            .values()
            .map(|live| live.no_owner_binding_drops.load(Ordering::Relaxed))
            .sum()
    }

    /// #1636 option C: proactive-neighbor-warm telemetry. `warm_drops`
    /// is incremented when the bounded warmer queue is full (transient);
    /// `warm_disconnected` when the warmer worker died (fatal). Both are
    /// surfaced to the daemon's Prometheus collector.
    pub fn neighbor_warm_counters(&self) -> (u64, u64) {
        (
            self.neighbors.warm_drops.load(Ordering::Relaxed),
            self.neighbors.warm_disconnected.load(Ordering::Relaxed),
        )
    }

    /// #1769: on-demand neighbor-resolver telemetry. Returns the live
    /// queue-depth gauge (clamped to >= 0) plus the monotonic GET/probe/
    /// epoch counters. Exposes the previously-invisible stuck-state
    /// surface: pending depth, GET attempts/resolutions/failures,
    /// probe-on-stale rate, epoch-guard rejects, and enqueue
    /// drops/disconnects.
    pub fn neighbor_resolver_counters(&self) -> NeighborResolverCounters {
        let c = &self.neighbors.resolver_counters;
        NeighborResolverCounters {
            queue_depth: c.queue_depth.load(Ordering::Relaxed).max(0) as u64,
            enqueue_drops: c.enqueue_drops.load(Ordering::Relaxed),
            disconnected: c.disconnected.load(Ordering::Relaxed),
            get_attempts: c.get_attempts.load(Ordering::Relaxed),
            get_resolved: c.get_resolved.load(Ordering::Relaxed),
            probe_on_stale: c.probe_on_stale.load(Ordering::Relaxed),
            get_failures: c.get_failures.load(Ordering::Relaxed),
            epoch_rejects: c.epoch_rejects.load(Ordering::Relaxed),
        }
    }

    pub fn recent_exceptions(&self) -> Vec<ExceptionStatus> {
        self.recent_exceptions
            .lock()
            .map(|recent| recent.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn recent_session_deltas(&self) -> Vec<SessionDeltaInfo> {
        self.recent_session_deltas
            .lock()
            .map(|recent| recent.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn last_resolution(&self) -> Option<PacketResolution> {
        self.last_resolution
            .lock()
            .ok()
            .and_then(|last| last.clone())
    }

    pub fn slow_path_status(&self) -> SlowPathStatus {
        self.slow_path
            .as_ref()
            .map(|slow| slow.status())
            .unwrap_or_else(|| self.last_slow_path_status.clone())
    }

    pub fn cos_statuses(&self) -> Vec<crate::protocol::CoSInterfaceStatus> {
        let snapshots: Vec<Vec<_>> = self
            .workers
            .handles
            .values()
            .map(|worker| worker.cos_status.load().iter().cloned().collect())
            .collect();
        let mut statuses =
            aggregate_cos_statuses_across_workers(&snapshots, &self.cos_owner_worker_by_queue);
        let queue_leases = self.cos.queue_leases.load();
        overlay_shared_cos_queue_lease_statuses(&mut statuses, queue_leases.as_ref());
        statuses
    }

    pub fn filter_term_counters(&self) -> Vec<crate::protocol::FirewallFilterTermCounterStatus> {
        let mut filter_keys = self
            .forwarding
            .filter_state
            .filters
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        filter_keys.sort();
        let mut out = Vec::new();
        for key in filter_keys {
            let Some(filter) = self.forwarding.filter_state.filters.get(&key) else {
                continue;
            };
            for term in &filter.terms {
                out.push(crate::protocol::FirewallFilterTermCounterStatus {
                    family: filter.family.clone(),
                    filter_name: filter.name.clone(),
                    term_name: term.name.clone(),
                    packets: term.counter.packets.load(Ordering::Relaxed),
                    bytes: term.counter.bytes.load(Ordering::Relaxed),
                });
            }
        }
        out
    }

    pub fn three_color_policer_counters(&self) -> Vec<crate::protocol::ThreeColorPolicerStatus> {
        self.forwarding.filter_state.three_color_policer_statuses()
    }

    pub fn source_nat_pool_statuses(&self) -> Vec<crate::protocol::SourceNatPoolStatus> {
        crate::nat::source_nat_pool_statuses(&self.forwarding.source_nat_rules)
    }

    #[cfg(test)]
    pub(crate) fn test_match_source_nat_result_for_tuple(
        &self,
        from_zone: &str,
        to_zone: &str,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        protocol: u8,
        src_port: u16,
        dst_port: u16,
        egress_v4: Option<Ipv4Addr>,
        egress_v6: Option<Ipv6Addr>,
        now_ns: u64,
    ) -> crate::nat::SourceNatLookup {
        crate::nat::match_source_nat_result_for_tuple(
            &self.forwarding.source_nat_rules,
            from_zone,
            to_zone,
            src_ip,
            dst_ip,
            protocol,
            src_port,
            dst_port,
            egress_v4,
            egress_v6,
            now_ns,
        )
    }

    #[cfg(test)]
    pub(crate) fn test_release_source_nat_allocation(
        &self,
        key: &crate::session::SessionKey,
        nat: crate::nat::NatDecision,
        now_ns: u64,
    ) {
        crate::nat::release_source_nat_allocation(
            &self.forwarding.source_nat_rules,
            key,
            nat,
            false,
            now_ns,
        );
    }

    pub fn flow_worker_map(&self) -> (Vec<crate::protocol::FlowWorkerStatus>, bool) {
        const FLOW_WORKER_MAP_MAX_ROWS: usize = 4096;
        let mut out = Vec::new();
        let mut truncated = false;
        for live in self.workers.live.values() {
            if out.len() >= FLOW_WORKER_MAP_MAX_ROWS {
                truncated = true;
                break;
            }
            let (rows, binding_truncated) = live.flow_worker_map_snapshot();
            truncated |= binding_truncated;
            for row in rows {
                if out.len() >= FLOW_WORKER_MAP_MAX_ROWS {
                    truncated = true;
                    break;
                }
                out.push(row);
            }
        }
        (out, truncated)
    }

    pub fn cos_active_flow_counts(&self) -> (Vec<crate::protocol::CoSActiveFlowCountStatus>, bool) {
        const COS_ACTIVE_FLOW_COUNT_MAX_ROWS: usize = 4096;
        let mut counts = std::collections::BTreeMap::<(i32, u8, u32), u32>::new();
        for live in self.workers.live.values() {
            for row in live.cos_active_flow_counts_snapshot() {
                let key = (row.ifindex, row.queue_id, row.worker_id);
                let count = counts.entry(key).or_insert(0);
                *count = count.saturating_add(row.active_flow_count);
            }
        }
        let truncated = counts.len() > COS_ACTIVE_FLOW_COUNT_MAX_ROWS;
        let out = counts
            .into_iter()
            .take(COS_ACTIVE_FLOW_COUNT_MAX_ROWS)
            .map(|((ifindex, queue_id, worker_id), active_flow_count)| {
                crate::protocol::CoSActiveFlowCountStatus {
                    ifindex,
                    queue_id,
                    worker_id,
                    active_flow_count,
                }
            })
            .collect();
        (out, truncated)
    }

    pub fn drain_session_deltas(&self, max: usize) -> Vec<SessionDeltaInfo> {
        let mut remaining = max.max(1);
        let mut out = Vec::new();
        for live in self.workers.live.values() {
            if remaining == 0 {
                break;
            }
            let drained = live.drain_session_deltas(remaining);
            remaining = remaining.saturating_sub(drained.len());
            out.extend(drained);
        }
        out
    }

    pub fn worker_heartbeats(&self) -> Vec<chrono::DateTime<Utc>> {
        let now_wall = Utc::now();
        let now_mono = monotonic_nanos();
        self.workers
            .handles
            .iter()
            .map(|(_, handle)| {
                monotonic_timestamp_to_datetime(
                    handle.heartbeat.load(Ordering::Relaxed),
                    now_mono,
                    now_wall,
                )
                .unwrap_or(now_wall)
            })
            .collect()
    }

    pub fn worker_count(&self) -> usize {
        self.workers.handles.len()
    }

    /// #869: snapshot per-worker busy/idle runtime counters.  Each row is
    /// the current `WorkerRuntimeAtomics` publish, most recently written
    /// on the worker's ~1s publish cadence.
    /// #925: also surfaces `dead` (one-shot AtomicBool set when the
    /// supervisor catches a worker_loop panic) and the rendered panic
    /// payload from the per-worker slot in `worker_panics`.
    pub fn worker_runtime_snapshots(&self) -> Vec<crate::protocol::WorkerRuntimeStatus> {
        self.workers
            .handles
            .iter()
            .map(|(worker_id, handle)| {
                let s = handle.runtime_atomics.snapshot();
                let w = handle.runtime_atomics.snapshot_window();
                let dead = handle
                    .runtime_atomics
                    .dead
                    .load(std::sync::atomic::Ordering::Relaxed);
                let panic_message = if dead {
                    self.worker_panics
                        .get(worker_id)
                        .and_then(|slot| match slot.lock() {
                            Ok(g) => g.clone(),
                            Err(poisoned) => poisoned.into_inner().clone(),
                        })
                        .unwrap_or_default()
                } else {
                    String::new()
                };
                // #1621: snapshot the sibling cold_path_atomics under
                // its cold_window_gen seqlock. Copilot code-r1 C2+C5
                // catch: distinguishing snapshot=None from
                // snapshot=Some(default) is load-bearing for the wire
                // omitempty contract.
                //
                // Behavior:
                //   - snapshot() = None (retry exhausted): emit EMPTY
                //     Vec fields so Vec::is_empty omits them from the
                //     wire entirely; clock_source = ""; STILL stamp
                //     snapshot_failed (operator starvation signal).
                //   - snapshot() = Some(snap) but never-sampled
                //     (sample_phase == 0 AND all-zero samples/alias):
                //     also emit empty Vecs — there's no data to expose.
                //   - snapshot() = Some(snap) with data: populated Vecs.
                //
                // Result: a worker that has never sampled emits a
                // WorkerRuntimeStatus byte-identical to a pre-#1621
                // daemon's output, validating the wire-invariant
                // contract (and the protocol_wire_v1.json fixture).
                // ORDER MATTERS (Claude SMR code-r1 catch): call
                // snapshot() FIRST so any retry-exhaust fetch_add inside
                // snapshot() is visible to the snapshot_failed_count()
                // read below. Without this order, a failure on THIS
                // scrape would only show up on the NEXT scrape (1-tick
                // lag), making the operator's starvation-alert dashboard
                // one cycle late.
                let cold_opt = handle.cold_path_atomics.snapshot();
                let cold_snapshot_failed =
                    handle.cold_path_atomics.snapshot_failed_count();
                let has_data = cold_opt
                    .as_ref()
                    .map(|c| {
                        c.sample_phase != 0
                            || c.samples.iter().any(|&v| v != 0)
                            || c.builder_collision.iter().any(|&v| v)
                    })
                    .unwrap_or(false);
                let cold = cold_opt.unwrap_or_default();
                // #1635: SPARSE wire encoding. Only slots with a live
                // zone-pair assignment AND samples > 0 ride the wire.
                // The slot→(from,to) mapping comes from the per-config
                // slot map's inverse table; the worker's local buckets
                // index by slot. A worker that never sampled emits zero
                // new wire bytes (Vec::is_empty omits the fields).
                let slot_map = &self.forwarding.cold_path_slot_map;
                let mut active_slot_ids: Vec<u32> = Vec::new();
                let mut active_zone_from: Vec<u32> = Vec::new();
                let mut active_zone_to: Vec<u32> = Vec::new();
                let mut active_samples: Vec<u64> = Vec::new();
                let mut active_sum_ns: Vec<u64> = Vec::new();
                let mut active_buckets: Vec<Vec<u64>> = Vec::new();
                let mut active_builder_collision: Vec<bool> = Vec::new();
                if has_data {
                    for slot in 0..crate::afxdp::cold_path_hist::POLICY_COLD_PATH_ZONE_PAIR_SLOTS {
                        if cold.samples[slot] == 0 {
                            continue;
                        }
                        let Some((from, to)) =
                            slot_map.inverse.get(slot).copied().flatten()
                        else {
                            // Sampled into a slot with no live mapping
                            // (config rotated mid-window). Skip — the
                            // next publish after the worker's zero-out
                            // tick clears it.
                            continue;
                        };
                        // Codex code-r1 finding 3: the coordinator
                        // publishes the new slot-map BEFORE workers
                        // necessarily load it and zero reused slots, so
                        // for up to one publish tick the atomics can
                        // carry the PREVIOUS pair's counts under the
                        // NEW slot. Validate the recorded first_key
                        // against the live mapping; on mismatch the
                        // counts belong to the old pair — skip them
                        // rather than relabel stale samples as the new
                        // (from_zone, to_zone).
                        let expected_key =
                            crate::afxdp::cold_path_hist::zone_pair_packed_key(from, to);
                        if cold.first_key[slot] != 0
                            && cold.first_key[slot] != expected_key
                        {
                            continue;
                        }
                        active_slot_ids.push(slot as u32);
                        active_zone_from.push(from as u32);
                        active_zone_to.push(to as u32);
                        active_samples.push(cold.samples[slot]);
                        active_sum_ns.push(cold.sum_ns[slot]);
                        active_buckets.push(cold.buckets[slot].to_vec());
                        active_builder_collision.push(cold.builder_collision[slot]);
                    }
                }
                crate::protocol::WorkerRuntimeStatus {
                    worker_id: *worker_id,
                    tid: handle.runtime_atomics.tid(),
                    wall_ns: s.wall_ns,
                    active_ns: s.active_ns,
                    idle_spin_ns: s.idle_spin_ns,
                    idle_block_ns: s.idle_block_ns,
                    thread_cpu_ns: s.thread_cpu_ns,
                    work_loops: s.work_loops,
                    idle_loops: s.idle_loops,
                    cos_queue_lease_acquire_v8_calls: s.cos_queue_lease_acquire_v8_calls,
                    cos_queue_lease_acquire_v8_granted_bytes: s
                        .cos_queue_lease_acquire_v8_granted_bytes,
                    session_table_entries: s.session_table_entries,
                    max_sessions: s.max_sessions,
                    nat_reverse_key_collisions: s.nat_reverse_key_collisions,
                    dead,
                    panic_message,
                    thread_cpu_ns_60s: w.thread_cpu_ns,
                    wall_ns_60s: w.wall_ns,
                    active_ns_60s: w.active_ns,
                    window_ns: w.window_ns,
                    // #1635 cold-path histogram fields: SPARSE
                    // active-slot-only encoding (Vec::is_empty omits an
                    // empty worker's fields, preserving wire-compat with
                    // pre-#1635 Go readers per feedback_wire_protocol_both_sides).
                    // Stamp v3 when there is data OR when the slot map
                    // overflowed (Copilot code-r2: an overflow with no
                    // samples yet must still route the Go collector to
                    // the v3 emitter so the overflow gauge is visible —
                    // version 0 would route to the legacy v1 path and
                    // hide it).
                    cold_path_layout_version: if has_data || slot_map.overflow_active {
                        crate::afxdp::cold_path_hist::COLD_PATH_LAYOUT_VERSION
                    } else {
                        0
                    },
                    cold_path_active_slot_ids: active_slot_ids,
                    cold_path_active_zone_from: active_zone_from,
                    cold_path_active_zone_to: active_zone_to,
                    cold_path_active_samples: active_samples,
                    cold_path_active_sum_ns: active_sum_ns,
                    cold_path_active_buckets: active_buckets,
                    cold_path_active_builder_collision: active_builder_collision,
                    cold_path_overflow_active: slot_map.overflow_active,
                    // Scalars: u64_is_zero in serde skips them on
                    // the wire when 0; safe to write the raw value
                    // (clock_source.as_str() returns "" for Unset
                    // which String::is_empty skip will also omit).
                    cold_path_sample_phase: cold.sample_phase,
                    cold_path_wrapper_underflow_count: cold
                        .wrapper_underflow_count,
                    cold_path_ns_per_tsc_q32: cold.ns_per_tsc_q32,
                    cold_path_wrapper_ns_baseline: cold.wrapper_ns_baseline,
                    cold_path_clock_source: cold.clock_source.as_str().to_string(),
                    cold_path_snapshot_failed: cold_snapshot_failed,
                }
            })
            .collect()
    }

    pub fn identity_count(&self) -> usize {
        self.workers.identities.len()
    }

    pub fn live_count(&self) -> usize {
        self.workers.live.len()
    }

    pub fn planned_counts(&self) -> (usize, usize) {
        (
            self.workers.last_planned_workers(),
            self.workers.last_planned_bindings(),
        )
    }

    pub fn reconcile_debug(&self) -> (u64, String) {
        (self.reconcile_calls, self.last_reconcile_stage.clone())
    }
}

fn overlay_shared_cos_queue_lease_statuses(
    statuses: &mut [crate::protocol::CoSInterfaceStatus],
    queue_leases: &BTreeMap<(i32, u8), Arc<SharedCoSQueueLease>>,
) {
    for iface in statuses {
        for queue in &mut iface.queues {
            let Some(lease) = queue_leases.get(&(iface.ifindex, queue.queue_id)) else {
                continue;
            };
            if !lease.v8_equal_flow_active() {
                continue;
            }
            queue.equal_flow_enforcement = true;
            queue.equal_flow_enforced = lease.v8_equal_flow_enforced();
            queue.equal_flow_target_per_flow_bps = lease.v8_equal_flow_target_per_flow_bps();
            queue.equal_flow_max_worker_cap_bytes = lease.v8_equal_flow_worker_cap();
            queue.equal_flow_cap_hit_events = lease.v8_equal_flow_cap_hit_events();
            queue.equal_flow_suppressed_grant_bytes = lease.v8_equal_flow_suppressed_grant_bytes();
            queue.equal_flow_stale_or_tag_mismatch_events =
                lease.v8_equal_flow_stale_or_tag_mismatch_events();
            queue.equal_flow_fail_open_reason =
                lease.v8_equal_flow_fail_open_reason_label().to_string();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::afxdp::types::V8RateMode;
    use crate::protocol::{CoSInterfaceStatus, CoSQueueStatus};

    #[test]
    fn equal_flow_overlay_skips_non_equal_flow_v8_leases() {
        let mut statuses = vec![CoSInterfaceStatus {
            ifindex: 80,
            queues: vec![CoSQueueStatus {
                queue_id: 4,
                ..Default::default()
            }],
            ..Default::default()
        }];
        let leases = BTreeMap::from([(
            (80, 4),
            Arc::new(SharedCoSQueueLease::new_v8(50_000_000, 256 * 1024, 8, 1)),
        )]);

        overlay_shared_cos_queue_lease_statuses(&mut statuses, &leases);

        let queue = &statuses[0].queues[0];
        assert!(!queue.equal_flow_enforcement);
        assert!(queue.equal_flow_fail_open_reason.is_empty());
    }

    #[test]
    fn equal_flow_overlay_populates_active_equal_flow_leases() {
        let mut statuses = vec![CoSInterfaceStatus {
            ifindex: 80,
            queues: vec![CoSQueueStatus {
                queue_id: 4,
                ..Default::default()
            }],
            ..Default::default()
        }];
        let lease = Arc::new(SharedCoSQueueLease::new_v8_with_rate_mode(
            50_000_000,
            256 * 1024,
            8,
            1,
            V8RateMode::EqualFlowSuppress,
        ));
        let leases = BTreeMap::from([((80, 4), lease)]);

        overlay_shared_cos_queue_lease_statuses(&mut statuses, &leases);

        let queue = &statuses[0].queues[0];
        assert!(queue.equal_flow_enforcement);
        assert_eq!(queue.equal_flow_fail_open_reason, "disabled");
        assert_eq!(queue.equal_flow_stale_or_tag_mismatch_events, 0);
    }
}
