use super::*;

impl super::Coordinator {
    pub fn update_ha_state(&self, groups: &[HAGroupStatus]) -> Result<(), String> {
        let previous = self.ha.rg_runtime.load();
        let now_secs = monotonic_nanos() / 1_000_000_000;
        let mut state = BTreeMap::new();
        for group in groups {
            // Treat every active HA state update as a lease refresh. Packet-time
            // HA now consults a single applied lease state: active-until
            // or inactive.
            let lease = if group.active {
                HAGroupRuntime::active_lease_until(group.watchdog_timestamp, now_secs)
            } else {
                HAForwardingLease::Inactive
            };
            state.insert(
                group.rg_id,
                HAGroupRuntime {
                    active: group.active,
                    watchdog_timestamp: group.watchdog_timestamp,
                    lease,
                },
            );
        }
        let demoted_rgs = demoted_owner_rgs(previous.as_ref(), &state);
        let activated_rgs = activated_owner_rgs(previous.as_ref(), &state);
        // Debug: log state comparison for RGs 0-2
        for rg_id in 0..=2i32 {
            let prev_active = previous.get(&rg_id).map(|r| r.active);
            let curr_active = state.get(&rg_id).map(|r| r.active);
            if prev_active != curr_active {
                eprintln!(
                    "xpf-ha: RG{} state changed: {:?} -> {:?} (demoted={:?} activated={:?})",
                    rg_id, prev_active, curr_active, demoted_rgs, activated_rgs
                );
            }
        }
        // #2120 (MANDATORY): bump rg_epochs for every demoted AND
        // activated RG, plus the node-level rg_epochs[0] on ANY
        // activation, BEFORE publishing the new rg_runtime. This makes
        // the standby-retention self-heal edge airtight: a worker that
        // observes the active rg_runtime (ArcSwap acquire) is guaranteed
        // to also observe the bumped epoch (the Release store below is
        // ordered before the runtime publish), so the expire pass never
        // sees new-rg + old-epoch (the "AGE a session this node now
        // forwards" hole). The flow-cache invalidation these bumps also
        // drive is unaffected by the earlier timing — workers re-stamp on
        // the next lookup. The node-level rg_epochs[0] edge lets the
        // self-heal fire for owner_rg_id==0 fabric/reverse entries.
        //
        // These bumps replace the previously-after-store demote loop and
        // the handle_activated_rgs activation loop (removed below) so each
        // RG is incremented exactly once per transition.
        for rg_id in &demoted_rgs {
            let idx = *rg_id as usize;
            if idx > 0 && idx < MAX_RG_EPOCHS {
                self.rg_epochs[idx].fetch_add(1, Ordering::Release);
            }
        }
        for rg_id in &activated_rgs {
            let idx = *rg_id as usize;
            if idx > 0 && idx < MAX_RG_EPOCHS {
                self.rg_epochs[idx].fetch_add(1, Ordering::Release);
            }
        }
        if !activated_rgs.is_empty() {
            // Node-level "started forwarding something" edge so the
            // standby self-heal can release HELD owner_rg_id==0 entries.
            self.rg_epochs[0].fetch_add(1, Ordering::Release);
        }
        self.ha.rg_runtime.store(Arc::new(state));
        if !demoted_rgs.is_empty() {
            for handle in self.workers.handles.values() {
                // #1790/#1807: recover from a poisoned worker command mutex
                // instead of early-returning. The new HA state was already
                // published via rg_runtime.store above, so an Err here would
                // make a retry diff against the demoted state (empty
                // demoted_rgs) and permanently skip the remaining workers'
                // demote commands, demote_shared_owner_rgs, and the
                // rg_epochs bumps. lock_recover applies the uniform
                // committed-prefix + clear_poison policy (worker_queue.rs).
                let mut pending = worker_queue::lock_recover(&handle.commands);
                pending.push_back(WorkerCommand::DemoteOwnerRGS {
                    owner_rgs: demoted_rgs.clone(),
                });
                // #941 Work item C: vacate V_min slots on demotion.
                // Stale-low slot values would cause peer workers to
                // throttle unnecessarily until the first post-settle
                // publish from this worker after re-promotion.
                pending.push_back(WorkerCommand::VacateAllSharedExactSlots);
            }
            demote_shared_owner_rgs(
                &self.sessions.synced,
                &self.sessions.nat,
                &self.sessions.forward_wire,
                &self.sessions.owner_rg_indexes,
                &self.forwarding,
                self.dynamic_neighbors_ref(),
                &demoted_rgs,
            );
            // #2120: the demote rg_epochs bump moved BEFORE rg_runtime.store
            // above (epoch-before-publish ordering). O(1) flow-cache
            // invalidation is preserved — only the timing changed.
            // Record cache flush timestamp for observability (#312).
            self.last_cache_flush_at.store(now_secs, Ordering::Relaxed);
        }
        if !activated_rgs.is_empty() {
            eprintln!(
                "xpf-ha: RG activation detected: {:?}, workers={}, shared_sessions={}",
                activated_rgs,
                self.workers.handles.len(),
                self.sessions.synced.lock().map(|s| s.len()).unwrap_or(0),
            );
            self.handle_activated_rgs(&activated_rgs, now_secs);
        }
        Ok(())
    }

    fn handle_activated_rgs(&self, activated_rgs: &[i32], now_secs: u64) {
        if activated_rgs.is_empty() {
            return;
        }
        // #2120: the activated rg_epochs bump (and the node-level
        // rg_epochs[0] edge) moved to update_ha_state BEFORE
        // rg_runtime.store, so it is NOT repeated here — a double
        // increment would still invalidate correctly but is avoided for
        // clarity and to keep each transition a single epoch step.

        let worker_commands = self
            .workers
            .handles
            .values()
            .map(|handle| handle.commands.clone())
            .collect::<Vec<_>>();
        for commands in &worker_commands {
            // #1790/#1807: uniform poison recovery (worker_queue.rs).
            let mut pending = worker_queue::lock_recover(commands);
            pending.push_back(WorkerCommand::RefreshOwnerRGS {
                owner_rgs: activated_rgs.to_vec(),
            });
        }
        let current = self.ha.rg_runtime.load();
        let session_map_fd = self.bpf_maps.session_map_fd.as_ref().map(|fd| fd.fd).unwrap_or(-1);

        // RG activation is still allowed to be a narrow ownership transition,
        // but split-RG continuity depends on rewarming the derived reverse
        // entries and restoring any redirect aliases that were removed during
        // demotion. This is not the old worker-wide HA refresh scan.
        prewarm_reverse_synced_sessions_for_owner_rgs(
            &self.sessions.synced,
            &self.sessions.nat,
            &self.sessions.forward_wire,
            &self.sessions.owner_rg_indexes,
            &worker_commands,
            session_map_fd,
            &self.forwarding,
            current.as_ref(),
            self.dynamic_neighbors_ref(),
            activated_rgs,
            now_secs,
        );
        if session_map_fd >= 0 {
            let republished = republish_bpf_session_entries_for_owner_rgs(
                &self.sessions.synced,
                &self.sessions.owner_rg_indexes,
                session_map_fd,
                activated_rgs,
            );
            if republished > 0 {
                eprintln!(
                    "xpf-ha: republished {} USERSPACE_SESSIONS entries for activated RGs {:?}",
                    republished, activated_rgs
                );
            }
        }
        // #1636 option C: an RG just became forwarding-active on this
        // node. Repopulate the kernel neighbor cache for the now-active
        // next-hops (entries may have aged to NUD_FAILED while this node
        // was standby). Clears the per-key rate-limit and fires a forced
        // warm pass so this does not wait for the next snapshot apply.
        // queue_warm_pass re-checks each next-hop's RG via the freshly
        // stored rg_runtime, so standby RGs are not warmed.
        self.on_rg_promote_active();
    }

    pub fn export_owner_rg_sessions(
        &self,
        owner_rgs: &[i32],
        max: usize,
    ) -> Result<Vec<SessionDeltaInfo>, String> {
        if owner_rgs.is_empty() {
            return Ok(Vec::new());
        }
        let sequence = self
            .sessions.export_seq
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        for handle in self.workers.handles.values() {
            // #1790/#1807: recover, don't early-return — one dead worker's
            // poisoned queue must not block session export for every
            // HEALTHY worker (the export-ack timeout handles dead workers
            // at the caller). Same policy as update_ha_state above.
            let mut pending = worker_queue::lock_recover(&handle.commands);
            pending.push_back(WorkerCommand::ExportOwnerRGSessions {
                sequence,
                owner_rgs: owner_rgs.to_vec(),
            });
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        loop {
            if self
                .workers
                .handles
                .values()
                .all(|handle| handle.session_export_ack.load(Ordering::Acquire) >= sequence)
            {
                break;
            }
            if std::time::Instant::now() >= deadline {
                return Err(format!(
                    "timed out waiting for session export ack seq={sequence}"
                ));
            }
            thread::sleep(Duration::from_millis(5));
        }
        let mut out = Vec::new();
        let mut remaining = if max == 0 { usize::MAX } else { max.max(1) };
        while remaining > 0 {
            let batch_size = remaining.min(1024);
            let drained = self.drain_session_deltas(batch_size);
            if drained.is_empty() {
                break;
            }
            remaining = remaining.saturating_sub(drained.len());
            out.extend(drained);
        }
        Ok(out)
    }

    pub fn ha_groups(&self) -> Vec<HAGroupStatus> {
        let now_secs = monotonic_nanos() / 1_000_000_000;
        self.ha.rg_runtime
            .load()
            .iter()
            .map(|(rg_id, runtime)| {
                let (lease_state, lease_until) = match runtime.lease {
                    HAForwardingLease::Inactive => ("inactive".to_string(), 0),
                    HAForwardingLease::ActiveUntil(until) => ("active".to_string(), until),
                };
                HAGroupStatus {
                    rg_id: *rg_id,
                    active: runtime.active,
                    watchdog_timestamp: runtime.watchdog_timestamp,
                    forwarding_active: runtime.is_forwarding_active(now_secs),
                    lease_state,
                    lease_until,
                }
            })
            .collect()
    }

    /// Returns the monotonic timestamp (secs) of the last HA flow cache flush.
    pub fn last_cache_flush_at(&self) -> u64 {
        self.last_cache_flush_at.load(Ordering::Relaxed)
    }

    pub fn upsert_synced_session(&self, entry: SyncedSessionEntry) {
        let now_secs = monotonic_nanos() / 1_000_000_000;
        let ha_state = self.ha.rg_runtime.load();
        let previous_entry = self
            .sessions.synced
            .lock()
            .ok()
            .and_then(|sessions| sessions.get(&entry.key).cloned());
        // #2170 install-side guard (SMR C3): refuse a strictly-older-
        // generation install so the per-key stored generation never
        // regresses (closes the delayed-stale-install variant on the
        // helper). Only acts when BOTH the stored and incoming generations
        // are non-zero — local-origin entries (generation 0) and legacy
        // peers fall back to today's unconditional upsert.
        if let Some(previous) = previous_entry.as_ref()
            && previous.generation != 0
            && entry.generation != 0
            && entry.generation < previous.generation
        {
            SESSION_INSTALL_STALE_IGNORED.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let reverse_entry = if !entry.metadata.is_reverse {
            synthesized_synced_reverse_entry(
                &self.forwarding,
                ha_state.as_ref(),
                self.dynamic_neighbors_ref(),
                &entry,
                now_secs,
            )
        } else {
            None
        };
        publish_shared_session(
            &self.sessions.synced,
            &self.sessions.nat,
            &self.sessions.forward_wire,
            &self.sessions.owner_rg_indexes,
            &entry,
        );
        // Keep the immediate BPF publish aligned with the worker-side
        // ownership guard so XSK redirect state cannot get ahead of what
        // the local SessionTable would actually accept.
        if synced_entry_allows_local_replace(
            ha_state.as_ref(),
            entry.metadata.owner_rg_id,
            now_secs,
        ) && let Some(session_map_fd) = self.bpf_maps.session_map_fd.as_ref()
        {
            // #1789: a failed HA-upsert publish silently loses synced
            // state (the shim takes the NO_SESSION degraded path). No
            // binding context here, so bump the shared counter.
            if publish_live_session_entry(
                session_map_fd.fd,
                &entry.key,
                entry.decision.nat,
                entry.metadata.is_reverse,
            )
            .is_err()
            {
                SESSION_PUBLISH_ERRORS_SHARED.fetch_add(1, Ordering::Relaxed);
            }
        }
        refresh_reverse_prewarm_owner_rg_indexes(
            &self.sessions.owner_rg_indexes.reverse_prewarm_sessions,
            &self.forwarding,
            self.dynamic_neighbors_ref(),
            previous_entry.as_ref(),
            Some(&entry),
        );
        if let Some(reverse) = &reverse_entry {
            publish_shared_session(
                &self.sessions.synced,
                &self.sessions.nat,
                &self.sessions.forward_wire,
                &self.sessions.owner_rg_indexes,
                reverse,
            );
            if synced_entry_allows_local_replace(
                ha_state.as_ref(),
                reverse.metadata.owner_rg_id,
                now_secs,
            ) && let Some(session_map_fd) = self.bpf_maps.session_map_fd.as_ref()
            {
                // #1789: same accounting for the synthesized reverse
                // entry (was `let _ =`).
                if publish_live_session_entry(
                    session_map_fd.fd,
                    &reverse.key,
                    reverse.decision.nat,
                    true,
                )
                .is_err()
                {
                    SESSION_PUBLISH_ERRORS_SHARED.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        for handle in self.workers.handles.values() {
            // #1790/#1807: recover-and-push instead of silently skipping a
            // poisoned queue (same policy as update_ha_state).
            let mut pending = worker_queue::lock_recover(&handle.commands);
            pending.push_back(WorkerCommand::UpsertSynced(entry.clone()));
            if let Some(reverse) = &reverse_entry {
                pending.push_back(WorkerCommand::UpsertSynced(reverse.clone()));
            }
        }
    }

    pub fn delete_synced_session(&self, key: SessionKey) {
        // Helper-local deletes (tunnel-remap purge, GC) are authoritative and
        // carry no peer install generation — apply unconditionally.
        self.delete_synced_session_gen(key, 0);
    }

    /// #2170 delete-side guard (belt-and-suspenders for any helper-side delete
    /// that carries a peer install generation): refuse to remove a stored
    /// entry whose generation is strictly NEWER than the delete's, so a stale
    /// delete cannot kill a same-key replacement the helper already mirrored.
    /// The authoritative guard lives in the Go cluster apply layer
    /// (deleteClusterSynced*) — that short-circuits both the BPF map delete and
    /// this helper path, so the cluster-delete path never reaches here with a
    /// non-zero delete_gen today; the seam exists for future helper-originated
    /// generation-aware deletes. A delete_gen of 0, or a stored generation of
    /// 0, falls back to unconditional delete (rolling-upgrade safe).
    pub fn delete_synced_session_gen(&self, key: SessionKey, delete_gen: u64) {
        let removed_entry = self
            .sessions.synced
            .lock()
            .ok()
            .and_then(|sessions| sessions.get(&key).cloned());
        if let Some(entry) = removed_entry.as_ref()
            && entry.generation != 0
            && delete_gen != 0
            && delete_gen < entry.generation
        {
            SESSION_DELETE_STALE_IGNORED.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let reverse_key = removed_entry.as_ref().and_then(|entry| {
            if entry.metadata.is_reverse {
                None
            } else {
                Some(reverse_session_key(&entry.key, entry.decision.nat))
            }
        });
        if let Some(entry) = removed_entry.as_ref() {
            if let Some(session_map_fd) = self.bpf_maps.session_map_fd.as_ref() {
                delete_session_map_entry_for_removed_session(
                    session_map_fd.fd,
                    &entry.key,
                    entry.decision,
                    &entry.metadata,
                );
            }
        }
        remove_shared_session(
            &self.sessions.synced,
            &self.sessions.nat,
            &self.sessions.forward_wire,
            &self.sessions.owner_rg_indexes,
            &key,
        );
        refresh_reverse_prewarm_owner_rg_indexes(
            &self.sessions.owner_rg_indexes.reverse_prewarm_sessions,
            &self.forwarding,
            self.dynamic_neighbors_ref(),
            removed_entry.as_ref(),
            None,
        );
        if let Some(reverse_key) = &reverse_key {
            remove_shared_session(
                &self.sessions.synced,
                &self.sessions.nat,
                &self.sessions.forward_wire,
                &self.sessions.owner_rg_indexes,
                reverse_key,
            );
        }
        for handle in self.workers.handles.values() {
            // #1790/#1807: recover-and-push instead of silently skipping a
            // poisoned queue (same policy as update_ha_state).
            let mut pending = worker_queue::lock_recover(&handle.commands);
            pending.push_back(WorkerCommand::DeleteSynced(key.clone()));
            if let Some(reverse_key) = &reverse_key {
                pending.push_back(WorkerCommand::DeleteSynced(reverse_key.clone()));
            }
        }
    }

    /// #1873 R-D: purge every session whose stored tunnel_endpoint_id
    /// was REMAPPED by a snapshot apply — the id is absent from the
    /// new forwarding state, or it now belongs to a DIFFERENT logical
    /// tunnel name (temporal hash reuse, or the one-time
    /// positional->hash upgrade re-id). Without the purge a live
    /// session would re-resolve its stored id into the WRONG tunnel
    /// (cross-tunnel encap) or permanently dead-end on the R-C gate.
    ///
    /// Each purged forward session goes through delete_synced_session
    /// (shared maps + indexes + kernel session map + reverse companion
    /// + worker DeleteSynced broadcast) and emits a Close delta on the
    /// event stream so the Go shadow conntrack and the HA peer
    /// delete-sync stay coherent (the standby additionally runs its
    /// own purge when IT applies the snapshot).
    pub(crate) fn purge_remapped_tunnel_sessions(&self, purge_ids: &[u16]) -> usize {
        if purge_ids.is_empty() {
            return 0;
        }
        let mut keys = Vec::new();
        let mut deltas = Vec::new();
        {
            let Ok(sessions) = self.sessions.synced.lock() else {
                return 0;
            };
            for entry in sessions.values() {
                let id = entry.decision.resolution.tunnel_endpoint_id;
                if id == 0 || !purge_ids.contains(&id) {
                    continue;
                }
                // Reverse entries are purged too: in an asymmetric
                // topology the REVERSE resolution can be the
                // tunnel-marked one while the forward entry is not in
                // the purge set, so relying on the forward pass's
                // companion removal alone would leave the reverse
                // entry dangling on the remapped id (Claude SMR code
                // review r1). delete_synced_session handles a reverse
                // key as a standalone removal. Close deltas are
                // emitted for FORWARD entries only (matching
                // emit_close_delta_with_origin's is_reverse skip — the
                // Go shadow keys off the forward delta).
                keys.push(entry.key.clone());
                if !entry.metadata.is_reverse {
                    deltas.push(crate::session::SessionDelta {
                        kind: crate::session::SessionDeltaKind::Close,
                        key: entry.key.clone(),
                        decision: entry.decision,
                        metadata: entry.metadata.clone(),
                        origin: entry.origin,
                        fabric_redirect_sync: false,
                        // #2465: the shared SyncedSessionEntry carries no
                        // creation instant, and this purge path uses
                        // push_delta_lossless (NOT emit_session_close_rt_flow),
                        // so these are 0/unknown.
                        created_ns: 0,
                        last_seen_ns: 0,
                        // #2501: the shared SyncedSessionEntry carries no
                        // per-direction counters, and this purge uses
                        // push_delta_lossless (not the RT_FLOW exporter), so
                        // volume is 0/unknown here.
                        counters: crate::session::SessionCounters::default(),
                    });
                }
            }
        }
        for key in &keys {
            self.delete_synced_session(key.clone());
        }
        if let Some(es) = self.event_stream.as_ref() {
            let handle = es.worker_handle();
            let zone_name_to_id = &self.forwarding.zone_name_to_id;
            for delta in &deltas {
                let _ = handle.push_delta_lossless(delta, zone_name_to_id);
            }
        }
        if !keys.is_empty() {
            eprintln!(
                "xpf-userspace-dp: purged {} session(s) on tunnel-endpoint id remap (ids {:?}) (#1873)",
                keys.len(),
                purge_ids
            );
        }
        keys.len()
    }

    /// Export all locally-owned forward sessions through the event stream.
    ///
    /// Called on peer connect instead of the old BulkSync path. Iterates the
    /// shared session table and pushes each qualifying session as an Open event
    /// through the event stream, where the Go daemon's handleEventStreamDelta
    /// callback will queue it to the peer via QueueSessionV4/V6.
    ///
    /// Returns the number of sessions exported.
    pub fn export_all_sessions_to_event_stream(&self) -> Result<usize, String> {
        let es = self
            .event_stream
            .as_ref()
            .ok_or_else(|| "event stream not started".to_string())?;
        let handle = es.worker_handle();

        let zone_name_to_id = &self.forwarding.zone_name_to_id;

        let sessions = self
            .sessions.synced
            .lock()
            .map_err(|_| "shared sessions lock poisoned".to_string())?;

        let ha_state = self.ha.rg_runtime.load();
        let mut deltas = Vec::new();
        for entry in sessions.values() {
            // Only forward (non-reverse), locally-originated sessions.
            if entry.metadata.is_reverse {
                continue;
            }
            if entry.origin.is_peer_synced() {
                continue;
            }
            // Skip fabric-ingress sessions (same exclusion as export_forward_sessions_for_owner_rgs).
            if entry.metadata.fabric_ingress {
                continue;
            }
            // Only export for active RGs. Missing HA state entry = inactive.
            let rg_active = entry.metadata.owner_rg_id > 0
                && ha_state
                    .get(&entry.metadata.owner_rg_id)
                    .map(|r| r.active)
                    .unwrap_or(false);
            if !rg_active && entry.metadata.owner_rg_id > 0 {
                continue;
            }
            // Only exportable dispositions.
            if !matches!(
                entry.decision.resolution.disposition,
                ForwardingDisposition::ForwardCandidate | ForwardingDisposition::FabricRedirect
            ) {
                continue;
            }

            deltas.push(crate::session::SessionDelta {
                kind: crate::session::SessionDeltaKind::Open,
                key: entry.key.clone(),
                decision: entry.decision,
                metadata: entry.metadata.clone(),
                origin: entry.origin,
                fabric_redirect_sync: true,
                // #2465: Open delta from the HA bulk export — the synced entry
                // carries no creation instant. The SESSION_CREATE frame reports
                // no duration, so 0/unknown is correct here.
                created_ns: 0,
                last_seen_ns: 0,
                // #2501: HA bulk-export Open delta; no volume yet (and the
                // synced entry carries no per-direction counters).
                counters: crate::session::SessionCounters::default(),
            });
        }
        drop(sessions);

        let count = deltas.len();
        for delta in &deltas {
            handle.push_delta_lossless(delta, zone_name_to_id)?;
        }
        eprintln!(
            "xpf-ha: exported {} sessions to event stream for bulk sync",
            count
        );
        Ok(count)
    }
}

#[cfg(test)]
#[path = "ha_tests.rs"]
mod tests;

