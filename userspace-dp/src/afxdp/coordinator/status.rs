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

    /// #1782: sum of per-binding `neg_neigh_fast_fail` across every
    /// `BindingLiveState`. Mirrors `cos_no_owner_binding_drops_total`:
    /// the increment lands on whichever binding owns the worker that
    /// fast-failed, and summing across all live states gives the
    /// cluster-wide total. Surfaced as
    /// `xpf_userspace_neg_neigh_fast_fail_total`.
    pub fn neg_neigh_fast_fail_total(&self) -> u64 {
        self.workers
            .live
            .values()
            .map(|live| live.neg_neigh_fast_fail.load(Ordering::Relaxed))
            .sum()
    }

    /// #1782: sum of per-binding `pending_neigh_duplicate_drops` across
    /// every `BindingLiveState`. Counts ONLY the H5 sibling drops where
    /// the `(egress_ifindex, next_hop)` key was already pending — not
    /// the capacity-drop case. Surfaced as
    /// `xpf_userspace_pending_neigh_duplicate_drops_total`.
    pub fn pending_neigh_duplicate_drops_total(&self) -> u64 {
        self.workers
            .live
            .values()
            .map(|live| live.pending_neigh_duplicate_drops.load(Ordering::Relaxed))
            .sum()
    }

    /// #1902: sum of per-binding `pending_neigh_decap_drops` across
    /// every `BindingLiveState`. Counts GRE-decapped MissingNeighbor
    /// packets refused pending_neigh admission (the buffered desc/meta
    /// pairing would retry-TX a mis-rewritten outer frame). Surfaced as
    /// `xpf_userspace_pending_neigh_decap_drops_total`.
    pub fn pending_neigh_decap_drops_total(&self) -> u64 {
        self.workers
            .live
            .values()
            .map(|live| live.pending_neigh_decap_drops.load(Ordering::Relaxed))
            .sum()
    }

    /// #1771 §2.6: distinct unresolved `(egress_ifindex, next_hop)` keys
    /// currently buffered across every binding's `pending_neigh` map
    /// (gauge). Each per-binding value is a `len()` snapshot published
    /// by the owning worker at its ~65ms debug-state tick; the sum is
    /// the cluster-wide count of next-hops with a packet parked waiting
    /// for neighbor resolution. Surfaced as
    /// `xpf_userspace_neighbor_pending_keys`.
    pub fn neighbor_pending_keys_total(&self) -> u64 {
        self.workers
            .live
            .values()
            .map(|live| live.pending_neigh_keys.load(Ordering::Relaxed))
            .sum()
    }

    /// #1771 §2.6: keys currently held across every binding's negative
    /// neighbor cache (gauge; lazy-TTL upper bound — see the
    /// `BindingLiveState::neg_neigh_keys` doc). Surfaced as
    /// `xpf_userspace_neg_neigh_keys`.
    pub fn neg_neigh_keys_total(&self) -> u64 {
        self.workers
            .live
            .values()
            .map(|live| live.neg_neigh_keys.load(Ordering::Relaxed))
            .sum()
    }

    /// #1789: total failed USERSPACE_SESSIONS BPF-map publishes. Sum of
    /// the per-binding `session_publish_errors` atomics (worker poll
    /// sites, mirroring `neg_neigh_fast_fail_total`) plus the shared
    /// `SESSION_PUBLISH_ERRORS_SHARED` static (HA upsert, session-glue
    /// worker publish, post-reconcile replay, activation/reverse prewarm
    /// — sites with no binding context). A nonzero value is the
    /// cause-side signal for rising XDP-shim NO_SESSION degraded-path
    /// fallbacks (session map at capacity, stale/invalid fd after
    /// reconcile). Surfaced as
    /// `xpf_userspace_session_publish_errors_total`.
    pub fn session_publish_errors_total(&self) -> u64 {
        let per_binding: u64 = self
            .workers
            .live
            .values()
            .map(|live| live.session_publish_errors.load(Ordering::Relaxed))
            .sum();
        per_binding.saturating_add(SESSION_PUBLISH_ERRORS_SHARED.load(Ordering::Relaxed))
    }

    /// #2244: total failed `dnat_table` reverse-SNAT BPF-map publishes.
    /// Sum of the per-binding `dnat_publish_errors` atomics bumped on the
    /// two worker poll-path `publish_dnat_table_entry` call sites whose
    /// `bpf_map_update_elem` return code was previously discarded. The
    /// `dnat_table` backs embedded-ICMP NAT reversal (PMTUD / traceroute
    /// inbound ICMP errors mapped back to the pre-NAT source); a failed
    /// publish silently drops the reverse record, so a nonzero value is
    /// the cause-side signal for `dnat_table` capacity pressure or kernel
    /// resource exhaustion. Surfaced as
    /// `xpf_userspace_dnat_publish_errors_total`.
    pub fn dnat_publish_errors_total(&self) -> u64 {
        self.workers
            .live
            .values()
            .map(|live| live.dnat_publish_errors.load(Ordering::Relaxed))
            .sum()
    }

    /// #2170: total stale-generation installs refused by the helper's
    /// in-memory SyncedSessionEntry guard (the delayed-stale-install
    /// variant). The authoritative guard is in the Go cluster apply layer;
    /// this is the helper-side back-stop counter.
    pub fn session_install_stale_ignored_total(&self) -> u64 {
        SESSION_INSTALL_STALE_IGNORED.load(Ordering::Relaxed)
    }

    /// #2170: total stale-generation deletes refused by the helper's
    /// in-memory SyncedSessionEntry guard (belt-and-suspenders for any
    /// helper-side generation-aware delete).
    pub fn session_delete_stale_ignored_total(&self) -> u64 {
        SESSION_DELETE_STALE_IGNORED.load(Ordering::Relaxed)
    }

    /// #1760 W3': shared-map NAT reverse-key displacement events — a
    /// `publish_shared_session` insert into `shared_nat_sessions`
    /// displaced a DIFFERENT forward session's entry at the same reverse
    /// key. The shared map is the single choke point every transit
    /// forward NAT session passes through (including
    /// `MissingNeighborSeed` installs, which never replicate to sibling
    /// workers and are invisible to the per-worker
    /// `nat_reverse_key_collisions` counter), so this is the
    /// authoritative collision watch. Event count, not a pair census
    /// (docs/research/1760-reverse-key-v2/plan.md §2.3). Surfaced as
    /// `xpf_userspace_session_nat_reverse_key_shared_displacements_total`.
    pub fn nat_reverse_key_shared_displacements_total(&self) -> u64 {
        crate::afxdp::shared_ops::NAT_REVERSE_KEY_SHARED_DISPLACEMENTS.load(Ordering::Relaxed)
    }

    /// #1807: total worker-command-queue poison recoveries across every
    /// producer/consumer site (worker poll peek + apply, HA enqueues,
    /// session replication, activation prewarm, tunnel install/drain-wait,
    /// cross-binding shaped-TX redirect). Each recovery means a thread
    /// panicked while holding a command-queue mutex and the committed
    /// queue was recovered + the poison cleared (worker_queue.rs policy,
    /// extends #1790). Surfaced as
    /// `xpf_userspace_worker_command_queue_poison_recoveries_total`; a
    /// nonzero value says a worker panic happened (see #925 supervisor)
    /// and the queues kept flowing.
    pub fn worker_command_queue_poison_recoveries_total(&self) -> u64 {
        crate::afxdp::worker_queue::WORKER_COMMAND_QUEUE_POISON_RECOVERIES.load(Ordering::Relaxed)
    }

    /// #2315: GRE-decap frames dropped by the RFC 6040 §4.2 decap-side
    /// ECN combine because the outer header carried a CE mark over an
    /// inner packet that was Not-ECT (the illegal combination — a
    /// congested router CE-marked a packet whose endpoints never
    /// negotiated ECN). RFC 6040 mandates a drop here. Surfaced as
    /// `xpf_userspace_gre_decap_ecn_illegal_drops_total`; a nonzero
    /// value flags a misbehaving tunnel ingress (it copied ECT onto the
    /// outer for un-ECN-marked inner traffic) on a congested path.
    pub fn gre_decap_ecn_illegal_drops_total(&self) -> u64 {
        crate::afxdp::gre::GRE_DECAP_ECN_ILLEGAL_DROPS.load(Ordering::Relaxed)
    }

    /// #2317: WireGuard-decap inner packets dropped by the RFC 6040 §4.2
    /// decap-side ECN combine because the (recvmsg-captured) outer ECN
    /// was CE over a Not-ECT inner — the illegal combination. RFC 6040
    /// mandates a drop here. Surfaced as
    /// `xpf_userspace_wg_decap_ecn_illegal_drops_total`; a nonzero value
    /// flags a misbehaving WG ingress / congested path that CE-marked the
    /// outer of un-ECN inner traffic.
    pub fn wg_decap_ecn_illegal_drops_total(&self) -> u64 {
        crate::afxdp::gre::WG_DECAP_ECN_ILLEGAL_DROPS.load(Ordering::Relaxed)
    }

    /// #2331: native-GRE encap frames dropped because the fully built
    /// outer datagram exceeded the resolved transport/egress MTU while
    /// the IPv4 outer carries DF=1 (the only outer the native builder
    /// emits). A DF-set oversized outer cannot be fragmented downstream
    /// and would silently blackhole every inner flow over the tunnel
    /// with no PMTUD signal — so the builder refuses to emit it. Surfaced
    /// as `xpf_userspace_gre_encap_df_oversize_drops_total`; a nonzero
    /// value flags inner flows whose encapped size exceeds the tunnel
    /// path MTU (a missing/too-high inner MSS clamp, or a non-TCP inner
    /// with no segmentation lever). PMTUD/PTB signalling is deferred to
    /// #2330.
    pub fn gre_encap_df_oversize_drops_total(&self) -> u64 {
        crate::afxdp::gre::GRE_ENCAP_DF_OVERSIZE_DROPS.load(Ordering::Relaxed)
    }

    /// #1782: debug dump of every key currently present in the userspace
    /// `dynamic_neighbors` mirror, as `(ifindex, ip)` pairs. The
    /// cold-start capture harness reads this at the pre-connect t0'
    /// sample to confirm whether the data-path next-hop is ABSENT from
    /// the mirror (the H2 fingerprint) while the kernel still shows it
    /// DELAY/STALE-usable. `NeighborEntry` carries only the MAC, not the
    /// kernel NUD state, so the harness pairs this membership check with
    /// `ip neigh` for the NUD state. Locks all shards once (same cost as
    /// `len()`); capped at `MAX` rows so a pathological table cannot bloat
    /// the status message. Debug/diagnostic surface only.
    pub fn dynamic_neighbor_keys(&self) -> Vec<(i32, std::net::IpAddr)> {
        const MAX: usize = 4096;
        self.neighbors.dynamic.with_all_shards(|bulk| {
            let mut out: Vec<(i32, std::net::IpAddr)> = Vec::new();
            for shard in bulk.each_shard_ref() {
                for (key, _entry) in shard.iter() {
                    if out.len() >= MAX {
                        return out;
                    }
                    out.push(*key);
                }
            }
            out
        })
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
            // #1771 §2.6: backoff-retry GETs + the monitor thread's
            // ENOBUFS / upsert-only re-dump telemetry (§2.5 mechanism).
            get_backoff_attempts: c.get_backoff_attempts.load(Ordering::Relaxed),
            netlink_enobufs: c.netlink_enobufs.load(Ordering::Relaxed),
            netlink_redumps: c.netlink_redumps.load(Ordering::Relaxed),
            netlink_redump_upserts: c.netlink_redump_upserts.load(Ordering::Relaxed),
        }
    }

    /// #1772: neighbor/ARP resolution LATENCY telemetry. Returns the
    /// pending-dwell + resolver GETNEIGH-RTT histogram snapshots plus the
    /// pending-neigh timeout-drop count and queue-depth high-water mark.
    /// Complements the #1769 count-only `neighbor_resolver_counters` with
    /// timing so the intermittent slow-new-connection symptom is visible.
    pub fn neighbor_latency_telemetry(&self) -> NeighborLatencyTelemetry {
        NeighborLatencyTelemetry {
            pending_dwell: self.neighbors.pending_dwell_hist.snapshot(),
            resolver_get_rtt: self.neighbors.resolver_get_rtt_hist.snapshot(),
            pending_timeout_drops: self.neighbors.pending_timeout_drops.load(Ordering::Relaxed),
            pending_max_depth: self.neighbors.pending_max_depth.load(Ordering::Relaxed),
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
        // #1830 (g): overlay the flow-cache active-flow counts onto the
        // queue rows so each row carries BOTH halves of the
        // collision-vs-demand ratio (flow_fair_flows_active alongside
        // the worker-snapshot-summed flow_fair_buckets_occupied). Same
        // per-binding source as `cos_active_flow_counts`, re-keyed per
        // (ifindex, queue_id) by summing across workers.
        let mut flow_counts = BTreeMap::<(i32, u8), u64>::new();
        for live in self.workers.live.values() {
            for row in live.cos_active_flow_counts_snapshot() {
                let count = flow_counts.entry((row.ifindex, row.queue_id)).or_insert(0);
                *count = count.saturating_add(u64::from(row.active_flow_count));
            }
        }
        overlay_cos_flow_fair_flow_counts(&mut statuses, &flow_counts);
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
        let mut counter = None;
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
            false,
            &mut counter,
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
                let cold_snapshot_failed = handle.cold_path_atomics.snapshot_failed_count();
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
                        let Some((from, to)) = slot_map.inverse.get(slot).copied().flatten() else {
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
                        if cold.first_key[slot] != 0 && cold.first_key[slot] != expected_key {
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
                    // #1782 Step-1: wheel catch-up + per-cause v8
                    // under-grant attribution.
                    cos_wheel_ticks_advanced_total: s.cos_wheel_ticks_advanced_total,
                    cos_wheel_ticks_advanced_max: s.cos_wheel_ticks_advanced_max,
                    cos_queue_lease_undergrant_seqlock_give_up: s
                        .cos_queue_lease_undergrant
                        .seqlock_give_up,
                    cos_queue_lease_undergrant_cap_zero: s.cos_queue_lease_undergrant.cap_zero,
                    cos_queue_lease_undergrant_epoch_rotated: s
                        .cos_queue_lease_undergrant
                        .epoch_rotated,
                    cos_queue_lease_undergrant_share_exhausted: s
                        .cos_queue_lease_undergrant
                        .share_exhausted,
                    cos_queue_lease_undergrant_class_cap: s.cos_queue_lease_undergrant.class_cap,
                    cos_queue_lease_undergrant_outstanding_cap: s
                        .cos_queue_lease_undergrant
                        .outstanding_cap,
                    session_table_entries: s.session_table_entries,
                    max_sessions: s.max_sessions,
                    nat_reverse_key_collisions: s.nat_reverse_key_collisions,
                    session_create_drops: s.session_create_drops,
                    session_install_admission_refused: s.session_install_admission_refused,
                    session_install_partial: s.session_install_partial,
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
                    cold_path_wrapper_underflow_count: cold.wrapper_underflow_count,
                    cold_path_ns_per_tsc_q32: cold.ns_per_tsc_q32,
                    cold_path_wrapper_ns_baseline: cold.wrapper_ns_baseline,
                    cold_path_clock_source: cold.clock_source.as_str().to_string(),
                    cold_path_snapshot_failed: cold_snapshot_failed,
                }
            })
            .collect()
    }

    /// #1865: per-WG-tunnel telemetry rows for `ProcessStatus.wg_tunnels`.
    /// One row per `mode == "wireguard"` tunnel endpoint with a live
    /// engine, sorted by endpoint id for deterministic wire output but
    /// KEYED by tunnel name (`ifindex_to_name`; positional ids renumber
    /// across commits — #1873). A missing name falls back to
    /// `wg-endpoint-<id>` rather than dropping the row: broken bring-up
    /// is exactly when telemetry matters. Counter loads are relaxed and
    /// NOT transactional across fields (each atomic is read
    /// independently while the control thread increments — fine for
    /// observability, same posture as every other counter family).
    pub fn wg_tunnel_statuses(&self) -> Vec<crate::protocol::WgTunnelStatus> {
        let mut ids: Vec<u16> = self
            .forwarding
            .tunnel_endpoints
            .iter()
            .filter(|(_, ep)| ep.mode == "wireguard")
            .map(|(id, _)| *id)
            .collect();
        ids.sort_unstable();
        if ids.is_empty() {
            return Vec::new();
        }
        let now_wall = Utc::now();
        let now_mono = monotonic_nanos();
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            let Some(endpoint) = self.forwarding.tunnel_endpoints.get(&id) else {
                continue;
            };
            let Some(engine) = self.forwarding.wg_engines.get(&id) else {
                continue;
            };
            // Name fallback chain (plan §3.2 / Codex code-r1 F1):
            // ifindex_to_name → the snapshot row's attachment label →
            // wg-endpoint-<id>. A row is never dropped, and the
            // stable logical name wins over the positional id even
            // when the live ifindex map has no entry (broken
            // bring-up — exactly when telemetry matters).
            let tunnel = self
                .forwarding
                .ifindex_to_name
                .get(&endpoint.logical_ifindex)
                .cloned()
                .or_else(|| {
                    (!endpoint.interface_label.is_empty()).then(|| endpoint.interface_label.clone())
                })
                .unwrap_or_else(|| format!("wg-endpoint-{id}"));
            let c = engine.counters();
            // Stamp-0 guard (plan §3.3 / SMR r2): a zero stamp means
            // "never" and must NOT run through the monotonic→wall
            // conversion (which would render ~boot time as a
            // valid-looking date). A pre-epoch/failed conversion also
            // maps to 0, never a wrapped huge value (Codex r2 note).
            let stamp = c.last_handshake_complete_ns.load(Ordering::Relaxed);
            let last_handshake_unix_secs = if stamp == 0 {
                0
            } else {
                monotonic_timestamp_to_datetime(stamp, now_mono, now_wall)
                    .map(|dt| dt.timestamp().max(0) as u64)
                    .unwrap_or(0)
            };
            // #1434 multi-peer: one status row per configured peer. The
            // endpoint is read from the ENGINE table (so a runtime-learned
            // endpoint surfaces, not just the configured one), and the
            // confirmed-session flag is per-peer.
            let engine_endpoints: std::collections::HashMap<[u8; 32], Option<std::net::SocketAddr>> =
                engine.peer_endpoints().into_iter().collect();
            let peers = endpoint
                .wg_peers
                .iter()
                .map(|p| crate::protocol::WgPeerStatus {
                    peer_pubkey_hex: crate::afxdp::wg::encode_wg_key_hex(&p.pubkey),
                    peer_endpoint: engine_endpoints
                        .get(&p.pubkey)
                        .copied()
                        .flatten()
                        .map(|ep| ep.to_string())
                        .unwrap_or_default(),
                    session_confirmed: engine.peer_has_confirmed_session(&p.pubkey),
                })
                .collect();
            out.push(crate::protocol::WgTunnelStatus {
                tunnel,
                tunnel_endpoint_id: id,
                listen_port: endpoint.wg_listen_port,
                // #1434 Increment 1: surface our local static public key
                // (the key an operator hands to the peer). Sourced from
                // the engine, not the snapshot — the snapshot redacts the
                // local PRIVATE key (`skip_serializing`), so the public
                // key derived at engine construction is the only place to
                // read it. Hex string on the wire (MEMORY #1961).
                local_pubkey_hex: crate::afxdp::wg::encode_wg_key_hex(&engine.local_public_key()),
                peers,
                last_handshake_unix_secs,
                hs_initiations_created: c.hs_initiations_created.load(Ordering::Relaxed),
                hs_initiation_build_failures: c
                    .hs_initiation_build_failures
                    .load(Ordering::Relaxed),
                hs_responses_created: c.hs_responses_created.load(Ordering::Relaxed),
                hs_completions_initiator: c.hs_completions_initiator.load(Ordering::Relaxed),
                hs_rx_drops_mac1_mismatch: c.hs_rx_drops_mac1_mismatch.load(Ordering::Relaxed),
                hs_rx_drops_malformed: c.hs_rx_drops_malformed.load(Ordering::Relaxed),
                hs_rx_drops_crypto: c.hs_rx_drops_crypto.load(Ordering::Relaxed),
                hs_rx_drops_unknown_peer: c.hs_rx_drops_unknown_peer.load(Ordering::Relaxed),
                hs_rx_drops_stale_response: c.hs_rx_drops_stale_response.load(Ordering::Relaxed),
                hs_rx_drops_index_exhausted: c.hs_rx_drops_index_exhausted.load(Ordering::Relaxed),
                hs_rx_cookie_unsupported: c.hs_rx_cookie_unsupported.load(Ordering::Relaxed),
                rx_unknown_type: c.rx_unknown_type.load(Ordering::Relaxed),
                hs_send_errors: c.hs_send_errors.load(Ordering::Relaxed),
                hs_requests_armed: c.hs_requests_armed.load(Ordering::Relaxed),
                decap_packets: c.decap_packets.load(Ordering::Relaxed),
                decap_bytes: c.decap_bytes.load(Ordering::Relaxed),
                decap_keepalives: c.decap_keepalives.load(Ordering::Relaxed),
                decap_drops_malformed_header: c
                    .decap_drops_malformed_header
                    .load(Ordering::Relaxed),
                decap_drops_unknown_session: c.decap_drops_unknown_session.load(Ordering::Relaxed),
                decap_drops_counter_ceiling: c.decap_drops_counter_ceiling.load(Ordering::Relaxed),
                decap_drops_crypto: c.decap_drops_crypto.load(Ordering::Relaxed),
                decap_drops_replay: c.decap_drops_replay.load(Ordering::Relaxed),
                decap_drops_allowed_ips: c.decap_drops_allowed_ips.load(Ordering::Relaxed),
                decap_drops_malformed_inner: c.decap_drops_malformed_inner.load(Ordering::Relaxed),
                decap_drops_buffer: c.decap_drops_buffer.load(Ordering::Relaxed),
                encap_packets: c.encap_packets.load(Ordering::Relaxed),
                encap_bytes: c.encap_bytes.load(Ordering::Relaxed),
                encap_drops_no_session: c.encap_drops_no_session.load(Ordering::Relaxed),
                encap_drops_unconfirmed: c.encap_drops_unconfirmed.load(Ordering::Relaxed),
                encap_drops_rekey_required: c.encap_drops_rekey_required.load(Ordering::Relaxed),
                encap_drops_other: c.encap_drops_other.load(Ordering::Relaxed),
                encap_mtu_drops: c.encap_mtu_drops.load(Ordering::Relaxed),
                transport_send_errors: c.transport_send_errors.load(Ordering::Relaxed),
                tun_write_errors: c.tun_write_errors.load(Ordering::Relaxed),
                tun_rx_drops_no_endpoint: c.tun_rx_drops_no_endpoint.load(Ordering::Relaxed),
                encap_drops_expired: c.encap_drops_expired.load(Ordering::Relaxed),
                decap_drops_expired: c.decap_drops_expired.load(Ordering::Relaxed),
                sessions_expired: c.sessions_expired.load(Ordering::Relaxed),
                rekeys_initiated_age: c.rekeys_initiated_age.load(Ordering::Relaxed),
                rekeys_initiated_dead_peer: c.rekeys_initiated_dead_peer.load(Ordering::Relaxed),
                rekeys_initiated_keepalive_no_session: c
                    .rekeys_initiated_keepalive_no_session
                    .load(Ordering::Relaxed),
                keepalives_tx_passive: c.keepalives_tx_passive.load(Ordering::Relaxed),
                keepalives_tx_persistent: c.keepalives_tx_persistent.load(Ordering::Relaxed),
                pending_aborted_attempt_window: c
                    .pending_aborted_attempt_window
                    .load(Ordering::Relaxed),
            });
        }
        out
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

/// #1830 (g): write the per-(ifindex, queue) flow-cache active-flow sums
/// onto the aggregated queue status rows. A queue with no flow-cache
/// rows keeps the serde default 0 (idle / not flow-classified), so
/// older consumers and idle queues are indistinguishable from the
/// pre-#1830 wire — the field is purely additive.
fn overlay_cos_flow_fair_flow_counts(
    statuses: &mut [crate::protocol::CoSInterfaceStatus],
    flow_counts: &BTreeMap<(i32, u8), u64>,
) {
    for iface in statuses {
        for queue in &mut iface.queues {
            if let Some(count) = flow_counts.get(&(iface.ifindex, queue.queue_id)) {
                queue.flow_fair_flows_active = *count;
            }
        }
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
            // #1863 Step-0: per-worker claim-flow counters for every v8
            // lease — BEFORE the equal-flow gate below (these are not
            // equal-flow state; they attribute the honored-realization
            // gap per docs/research/1863-realization-gap/plan.md §5).
            if let Some((requested, granted)) = lease.v8_worker_claim_flow() {
                queue.lease_v8_worker_requested_bytes = requested;
                queue.lease_v8_worker_granted_bytes = granted;
            }
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
            // #1746: surface which target policy the lease enforces.
            queue.equal_flow_target_policy = lease.v8_equal_flow_target_policy_label().to_string();
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
    fn claim_flow_overlay_populates_every_v8_lease() {
        // #1863 Step-0: the per-worker claim-flow vectors are populated
        // for ANY v8 lease — including non-equal-flow ones the
        // equal-flow gate below skips.
        let mut statuses = vec![CoSInterfaceStatus {
            ifindex: 80,
            queues: vec![CoSQueueStatus {
                queue_id: 4,
                ..Default::default()
            }],
            ..Default::default()
        }];
        let lease = Arc::new(SharedCoSQueueLease::new_v8(50_000_000, 256 * 1024, 8, 1));
        lease.rehydrate_worker_active_count(0, 1);
        let granted = lease.acquire_v8(0, 200_000, 512);
        assert!(granted > 0, "test premise: the ask grants");
        let leases = BTreeMap::from([((80, 4), lease)]);

        overlay_shared_cos_queue_lease_statuses(&mut statuses, &leases);

        let queue = &statuses[0].queues[0];
        assert_eq!(queue.lease_v8_worker_requested_bytes, vec![512, 0]);
        assert_eq!(queue.lease_v8_worker_granted_bytes[0], granted);
        assert!(!queue.equal_flow_enforcement, "equal-flow gate untouched");
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
        // #1746: default-policy lease surfaces the "slowest" label.
        assert_eq!(queue.equal_flow_target_policy, "slowest");
    }

    /// #1746: a Mean-policy lease surfaces "mean" on the status row,
    /// and non-equal-flow leases leave the field empty (wire
    /// byte-identical for non-equal-flow queues).
    #[test]
    fn equal_flow_overlay_populates_target_policy_label() {
        let mut statuses = vec![CoSInterfaceStatus {
            ifindex: 80,
            queues: vec![CoSQueueStatus {
                queue_id: 4,
                ..Default::default()
            }],
            ..Default::default()
        }];
        let lease = Arc::new(SharedCoSQueueLease::new_v8_with_rate_mode_and_policy(
            50_000_000,
            256 * 1024,
            8,
            1,
            V8RateMode::EqualFlowSuppress,
            crate::afxdp::types::EqualFlowTargetPolicy::Mean,
        ));
        let leases = BTreeMap::from([((80, 4), lease)]);

        overlay_shared_cos_queue_lease_statuses(&mut statuses, &leases);

        let queue = &statuses[0].queues[0];
        assert!(queue.equal_flow_enforcement);
        assert_eq!(queue.equal_flow_target_policy, "mean");
    }

    /// #1830 (g): the flow-count overlay writes only matching
    /// (ifindex, queue) rows and leaves non-matching rows at the serde
    /// default 0 (idle / no flow-cache rows), never touching
    /// flow_fair_buckets_occupied (the worker-snapshot half).
    #[test]
    fn flow_fair_flow_count_overlay_targets_matching_queue_rows() {
        let mut statuses = vec![CoSInterfaceStatus {
            ifindex: 80,
            queues: vec![
                CoSQueueStatus {
                    queue_id: 4,
                    flow_fair_buckets_occupied: 6,
                    ..Default::default()
                },
                CoSQueueStatus {
                    queue_id: 5,
                    ..Default::default()
                },
            ],
            ..Default::default()
        }];
        // Sums across workers were pre-aggregated by the caller.
        let flow_counts = BTreeMap::from([((80, 4u8), 12u64), ((81, 4u8), 99u64)]);

        overlay_cos_flow_fair_flow_counts(&mut statuses, &flow_counts);

        let q4 = &statuses[0].queues[0];
        assert_eq!(q4.flow_fair_flows_active, 12);
        assert_eq!(
            q4.flow_fair_buckets_occupied, 6,
            "overlay must not disturb the worker-snapshot bucket half"
        );
        let q5 = &statuses[0].queues[1];
        assert_eq!(
            q5.flow_fair_flows_active, 0,
            "queue with no flow-cache rows stays at the serde default"
        );
    }
}
