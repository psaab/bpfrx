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
        self.ha.rg_runtime.store(Arc::new(state));
        if !demoted_rgs.is_empty() {
            for handle in self.workers.handles.values() {
                let mut pending = handle.commands.lock().map_err(|_| {
                    format!(
                        "failed to enqueue DemoteOwnerRGS for demoted RGs {:?}: worker command queue lock poisoned",
                        demoted_rgs
                    )
                })?;
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
            // Bump RG epochs atomically — O(1) invalidation. Workers will
            // treat flow cache entries with stale epochs as misses.
            for rg_id in &demoted_rgs {
                let idx = *rg_id as usize;
                if idx > 0 && idx < MAX_RG_EPOCHS {
                    self.rg_epochs[idx].fetch_add(1, Ordering::Release);
                }
            }
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
        // Bump RG epochs for activated RGs so flow cache entries with
        // stale HA state are invalidated.
        for rg_id in activated_rgs {
            let idx = *rg_id as usize;
            if idx > 0 && idx < MAX_RG_EPOCHS {
                self.rg_epochs[idx].fetch_add(1, Ordering::Release);
            }
        }

        let worker_commands = self
            .workers
            .handles
            .values()
            .map(|handle| handle.commands.clone())
            .collect::<Vec<_>>();
        for commands in &worker_commands {
            let mut pending = match commands.lock() {
                Ok(pending) => pending,
                Err(poisoned) => {
                    eprintln!(
                        "xpf-ha: worker command queue lock poisoned while refreshing activated RGs {:?}; recovering inner queue",
                        activated_rgs
                    );
                    poisoned.into_inner()
                }
            };
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
            let mut pending = handle
                .commands
                .lock()
                .map_err(|_| "worker command queue poisoned".to_string())?;
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
            let _ = publish_live_session_entry(
                session_map_fd.fd,
                &entry.key,
                entry.decision.nat,
                entry.metadata.is_reverse,
            );
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
                let _ = publish_live_session_entry(
                    session_map_fd.fd,
                    &reverse.key,
                    reverse.decision.nat,
                    true,
                );
            }
        }
        for handle in self.workers.handles.values() {
            if let Ok(mut pending) = handle.commands.lock() {
                pending.push_back(WorkerCommand::UpsertSynced(entry.clone()));
                if let Some(reverse) = &reverse_entry {
                    pending.push_back(WorkerCommand::UpsertSynced(reverse.clone()));
                }
            }
        }
    }

    pub fn delete_synced_session(&self, key: SessionKey) {
        let removed_entry = self
            .sessions.synced
            .lock()
            .ok()
            .and_then(|sessions| sessions.get(&key).cloned());
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
            if let Ok(mut pending) = handle.commands.lock() {
                pending.push_back(WorkerCommand::DeleteSynced(key.clone()));
                if let Some(reverse_key) = &reverse_key {
                    pending.push_back(WorkerCommand::DeleteSynced(reverse_key.clone()));
                }
            }
        }
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

