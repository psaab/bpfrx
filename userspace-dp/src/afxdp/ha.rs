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

    /// Phase 1 of the owner-RG session export (#2962): enqueue the export
    /// command to every worker and capture the lock-free handles the
    /// ack-wait needs, then RETURN immediately. The blocking ack-wait runs
    /// in [`OwnerRgExportWait::wait_and_collect`] AFTER the caller releases
    /// the global `ServerState` mutex, so a slow/stalled worker can no
    /// longer freeze the whole control plane (status poll, session
    /// installs, snapshot/FIB bumps, HA state updates) for up to 15 s.
    ///
    /// This method MUST be called under the `ServerState` lock: it reads
    /// `workers.handles` / `workers.live` and bumps `export_seq`. Those
    /// collections are only mutated by other control-socket handlers, which
    /// all hold the same lock, so snapshotting the per-worker ack atomics
    /// (`Arc<AtomicU64>`) and the per-binding delta buffers
    /// (`Arc<BindingLiveState>`) here is equivalent to re-reading them live:
    /// the worker SET cannot change while the export waits lock-free
    /// (no TOCTOU). The worker THREADS only bump their ack atomics and push
    /// into their delta buffers — both `Arc`-shared and lock-free — so the
    /// wait observes their progress without the global lock.
    pub fn kick_owner_rg_export(&self, owner_rgs: &[i32], max: usize) -> OwnerRgExportWait {
        // Snapshot the per-binding delta buffers (same Arcs as
        // `drain_session_deltas` iterates) so the post-lock drain reads
        // exactly the buffers that existed at kick time.
        let live: Vec<Arc<BindingLiveState>> = self.workers.live.values().cloned().collect();
        if owner_rgs.is_empty() {
            // Preserve the pre-split early return: no export is kicked and
            // no sequence is consumed, and the wait drains nothing.
            return OwnerRgExportWait {
                sequence: 0,
                max,
                skip: true,
                ack_atomics: Vec::new(),
                live,
            };
        }
        let sequence = self
            .sessions
            .export_seq
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        let mut ack_atomics = Vec::with_capacity(self.workers.handles.len());
        for handle in self.workers.handles.values() {
            // #1790/#1807: recover, don't early-return — one dead worker's
            // poisoned queue must not block session export for every
            // HEALTHY worker (the export-ack timeout handles dead workers
            // in the wait). Same policy as update_ha_state above.
            let mut pending = worker_queue::lock_recover(&handle.commands);
            pending.push_back(WorkerCommand::ExportOwnerRGSessions {
                sequence,
                owner_rgs: owner_rgs.to_vec(),
            });
            drop(pending);
            ack_atomics.push(handle.session_export_ack.clone());
        }
        OwnerRgExportWait {
            sequence,
            max,
            skip: false,
            ack_atomics,
            live,
        }
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

    /// #5674: this appliance's aggregate synced-session ENTRY ceiling. The
    /// LOGICAL ceiling is `worker_count * DEFAULT_MAX_SESSIONS` (each worker
    /// table caps locally-created sessions at `DEFAULT_MAX_SESSIONS`), but the
    /// shared `synced` map holds TWO entries per admitted forward logical
    /// session: the forward key AND a synthesized reverse companion.
    /// `synthesized_synced_reverse_entry` returns `Some` for EVERY non-reverse
    /// import, and `upsert_synced_session` publishes both into `sessions.synced`
    /// via `publish_shared_session`. So the ENTRY cap must be 2× the logical
    /// ceiling. A symmetric HA pair holds up to `N = worker_count *
    /// DEFAULT_MAX_SESSIONS` logical sessions, which arrive here as 2N entries
    /// and EXACTLY fit this 2N cap — a legitimate full-peer failover import
    /// always fits, and only a peer EXCEEDING its own logical ceiling (a
    /// malicious/compromised peer) is rejected. Sizing the cap to the LOGICAL
    /// ceiling (the pre-fix bug) while counting ENTRIES rejected ~half of a
    /// legitimate symmetric-peer import above ~50% peer load — a 2× shortfall,
    /// not the "±1 pair overshoot" the old comment claimed. Bounds the shared
    /// `synced` map so a peer cannot drive this node past its aggregate session
    /// ceiling via the uncapped sync-import fan-out. Zero when no workers are
    /// registered (early boot / teardown) — the caller treats a zero ceiling as
    /// "bound disabled" so a transient window never rejects legitimate imports.
    fn synced_import_cap(&self) -> usize {
        #[cfg(test)]
        if self.synced_import_cap_override != 0 {
            // The override expresses a LOGICAL session ceiling; double it to the
            // ENTRY cap (fwd + synthesized reverse per logical session), matching
            // the production formula below so tests exercise the real arithmetic.
            return self.synced_import_cap_override.saturating_mul(2);
        }
        self.workers
            .handles
            .len()
            .saturating_mul(crate::session::default_max_sessions())
            .saturating_mul(2)
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
        // #5674: aggregate synced-import admission bound. Locally-created
        // sessions are capped per worker at `DEFAULT_MAX_SESSIONS`
        // (`install_with_protocol_with_origin`), but peer-synced sessions were
        // imported with NO cap and fanned out to EVERY worker command queue +
        // table below, so a peer under session-table pressure — or a
        // malicious/compromised peer — could drive this node past its own
        // aggregate session ceiling and multiply that state across all workers
        // (the availability/DoS root of #5674). Bound the SHARED synced map
        // (the single fan-out choke point) at this appliance's OWN aggregate
        // ENTRY ceiling, `2 * worker_count * DEFAULT_MAX_SESSIONS`
        // (`synced_import_cap`). The 2× is load-bearing: each admitted forward
        // logical session publishes TWO keys into `sessions.synced` — the
        // forward key and a synthesized reverse companion — so K admitted
        // forwards occupy 2K entries. With the entry cap at 2N (N = the logical
        // ceiling), a NEW forward is rejected exactly when 2K >= 2N ⇔ K >= N:
        // a full symmetric-peer set (N logical → 2N entries) EXACTLY fits and
        // only a peer EXCEEDING its own logical ceiling is rejected. Gate ONLY
        // FORWARD new keys (`!entry.metadata.is_reverse`): a synthesized reverse
        // always rides with its forward (a rejected forward `return`s BEFORE
        // publishing its reverse, so no half-sync), and a lone reverse import
        // off the wire (`is_reverse` set by a peer) is never independently
        // rejected at a boundary slot — it inserts one entry that its forward
        // already accounted for. Drop-NEWEST: reject a NEW forward key at/above
        // the ceiling (never enqueue it to any worker), but ALWAYS allow a
        // REPLACE of an existing synced key (`previous_entry.is_some()` — it
        // does not grow the map) so an in-flight synced session keeps
        // refreshing. Never evict an existing synced session to make room; that
        // would drop a legitimate failover session. A zero ceiling (no workers
        // registered yet — early boot / teardown) disables the bound so a
        // transient window never rejects legitimate imports.
        if previous_entry.is_none() && !entry.metadata.is_reverse {
            let synced_cap = self.synced_import_cap();
            let synced_len = self
                .sessions
                .synced
                .lock()
                .map(|sessions| sessions.len())
                .unwrap_or(0);
            if synced_cap != 0 && synced_len >= synced_cap {
                SYNCED_IMPORT_CAP_DROPS.fetch_add(1, Ordering::Relaxed);
                return;
            }
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
        // #4393: publish the reverse-SNAT `dnat_table` BPF-map entry for a
        // peer-synced forward SNAT session. The active node populates this
        // steering map from the worker poll path when it forwards the first
        // SNAT'd packet (`poll_descriptor`), but the standby never forwards
        // that packet — it imports the pre-computed NAT decision here. Without
        // this publish the standby has no `dnat_table` entry, so after failover
        // the shim does not steer an inbound embedded-ICMP error (PMTUD
        // Too-Big / traceroute Time-Exceeded) whose quoted inner packet carries
        // the SNAT pool `(addr, port)` into the helper's slow path — the error
        // is passed to the kernel (no NAT state) instead of reverse-NAT'd back
        // to the original client, so the client never learns the PMTU (TCP
        // stalls on large packets) and traceroute breaks. Mirrors the primary's
        // `publish_dnat_table_entry` call site exactly (forward entry only; a
        // reverse companion carries no SNAT source rewrite). Published
        // unconditionally (NOT gated on `synced_entry_allows_local_replace`,
        // unlike the forward session-map publish below): the `dnat_table` is a
        // passive reverse-NAT steering map that must be ready the instant this
        // node becomes active, and inbound SNAT-return traffic does not reach
        // the standby anyway, so an early entry is inert until failover. The
        // matching delete is `delete_synced_session_gen`'s teardown. The
        // process-global `dnat_table` map is a single shared object, so this
        // once-per-synced-session publish (not per worker) mirrors the primary.
        if !entry.metadata.is_reverse {
            let dnat_fds = DnatTableFds {
                v4: self.bpf_maps.dnat_table_fd.as_ref().map(|fd| fd.fd),
                v6: self.bpf_maps.dnat_table_v6_fd.as_ref().map(|fd| fd.fd),
            };
            if !publish_dnat_table_entry(&dnat_fds, &entry.key, entry.decision.nat) {
                // #4393/#2244: a failed publish (map at capacity / kernel
                // resource exhaustion) silently loses the reverse-NAT steering
                // entry. Count it via the shared static (no per-binding context
                // here) so `dnat_publish_errors_total` stays honest.
                DNAT_PUBLISH_ERRORS_SHARED.fetch_add(1, Ordering::Relaxed);
            }
        }
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
            // #4393: release the reverse-SNAT `dnat_table` entry published for
            // this peer-synced forward SNAT session at `upsert_synced_session`
            // so it does not leak (the maps are non-LRU HASH with
            // `max_entries = MAX_SESSIONS`; every un-deleted entry burns a slot
            // until publishes start failing) or steer a stale inbound ICMP
            // error after the session is gone. Keyed on the SAME
            // `dnat_v4_key_bytes` / `dnat_v6_key_bytes` helpers the publish path
            // used, so it byte-matches the insert key; a non-SNAT / reverse
            // entry is a no-op.
            if !entry.metadata.is_reverse {
                let dnat_fds = DnatTableFds {
                    v4: self.bpf_maps.dnat_table_fd.as_ref().map(|fd| fd.fd),
                    v6: self.bpf_maps.dnat_table_v6_fd.as_ref().map(|fd| fd.fd),
                };
                delete_dnat_table_entry(&dnat_fds, &entry.key, entry.decision.nat);
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
                        // #2749: shared purge path; no observed ToS / TCP
                        // flags in hand (and not routed through the RT_FLOW
                        // exporter).
                        observed_tos: 0,
                        observed_tcp_flags: 0,
                        // #4915: HA purge close delta — feeds push_purge_close_
                        // deltas (session-sync), NOT the RT_FLOW exporter, and the
                        // SyncedSessionEntry carries no session id. 0 (unknown).
                        session_id: 0,
                    });
                }
            }
        }
        for key in &keys {
            self.delete_synced_session(key.clone());
        }
        if let Some(es) = self.event_stream.as_ref() {
            let handle = es.worker_handle();
            // #2880: push the close deltas through the LOSSLESS producer and
            // RECORD any that cannot be queued (event stream disconnected /
            // saturated) instead of silently swallowing the error with the old
            // `let _ =`. This is error HYGIENE, not a leak fix: the purge is
            // CLEANUP, not a correctness boundary. Re-resolution and the encap
            // builders refuse a tunnel id whose owning netdev ifindex differs
            // from the one stored in the session's resolution (see the
            // call-site comments in coordinator/snapshot_refresh.rs and
            // coordinator/reconcile/snapshot.rs), so a surviving stale entry
            // can never mis-encapsulate; it self-heals — the standby runs its
            // OWN snapshot-apply purge and idle GC reaps it. A full owner-RG
            // re-export would NOT recover an undelivered close anyway: the
            // userspace cold-sync ships sessions as incremental Opens with
            // EMPTY bulk markers, and the peer's reconcileStaleSessions
            // short-circuits on an empty bulk (pkg/cluster/sync_bulk.go,
            // pkg/cluster/sync.go) — re-emitting Opens cannot convey a delete.
            // A disconnected stream additionally triggers a fresh resync on
            // reconnect (#2874) independently. So the honest minimal fix is to
            // surface the drop in the event-stream drop metric + a one-shot
            // log, not to drive a heavy resync.
            let _dropped = self.push_purge_close_deltas(&handle, &deltas);
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

    /// #2880: push the tunnel-remap purge Close deltas through the LOSSLESS
    /// event-stream producer, returning the number that could NOT be queued.
    /// Each undelivered delta is recorded in the event-stream dropped-frames
    /// metric (`record_dropped_frames`) so a disconnected / saturated stream
    /// surfaces in observability instead of being silently swallowed by the
    /// old `let _ =`. Stops on the first failure — a disconnected stream fails
    /// every subsequent push immediately, and a saturated one would otherwise
    /// burn one lossless-queue timeout per remaining delta — and counts the
    /// undelivered remainder. Cleanup-only error hygiene: it does NOT trigger a
    /// resync (the caller comment explains why a re-export cannot recover a
    /// missed close, and why the surviving entry is harmless + self-healing).
    pub(crate) fn push_purge_close_deltas(
        &self,
        handle: &crate::event_stream::EventStreamWorkerHandle,
        deltas: &[crate::session::SessionDelta],
    ) -> usize {
        let zone_name_to_id = &self.forwarding.zone_name_to_id;
        for (delivered, delta) in deltas.iter().enumerate() {
            if let Err(err) = handle.push_delta_lossless(delta, zone_name_to_id) {
                let dropped = deltas.len() - delivered;
                handle.record_dropped_frames(dropped as u64);
                eprintln!(
                    "xpf-userspace-dp: tunnel-remap purge could not queue {dropped}/{} close delta(s) losslessly ({err}); recorded as dropped frames — surviving peer/Go-shadow entries are harmless (encap ifindex guard) and self-heal via the standby snapshot-apply purge + idle GC (#2880)",
                    deltas.len()
                );
                return dropped;
            }
        }
        0
    }

    /// Snapshot all locally-owned forward sessions for a bulk HA export
    /// WITHOUT pushing them (#4054).
    ///
    /// Called on peer connect instead of the old BulkSync path. Iterates the
    /// shared session table once under a BRIEF `sessions.synced` lock, copies
    /// each qualifying session into an Open [`SessionDelta`], and captures the
    /// (Arc-cheap) event-stream handle plus an OWNED clone of the zone-name→id
    /// map. The returned [`AllSessionsExport`] carries everything the push loop
    /// needs, so the caller can run the potentially-blocking
    /// `push_delta_lossless` serialization with the global `ServerState` lock
    /// RELEASED — mirroring the owner-RG two-phase split (#2962). Before #4054
    /// the whole export (iteration + serialization + up to a 5 s per-delta
    /// lossless-queue backpressure wait) ran under the global lock, so a large
    /// bulk export at failover could starve the status poll / trip the control
    /// plane's liveness deadline and self-inflict a needless helper restart.
    ///
    /// The exported set is a consistent point-in-time snapshot: the delta
    /// vector is built under the `sessions.synced` lock, and the zone map is
    /// cloned within the same locked dispatcher phase, so a session or zone
    /// mutation racing the subsequent push is simply not reflected in THIS bulk
    /// export (it rides the incremental delta stream instead) — identical
    /// semantics to the pre-#4054 code, which likewise snapshotted the deltas
    /// under the same lock before serializing. Event-stream ordering is still
    /// governed by `producer_seq_lock` inside `push_delta_lossless`, not the
    /// `ServerState` lock, so releasing the latter does not affect the lossless
    /// seq contract (#2874 / #3878).
    pub fn snapshot_all_sessions_export(&self) -> Result<AllSessionsExport, String> {
        let es = self
            .event_stream
            .as_ref()
            .ok_or_else(|| "event stream not started".to_string())?;
        let handle = es.worker_handle();

        // Clone the zone map so the push loop can run off the global lock:
        // `push_delta_lossless` borrows it, and a borrow of `self.forwarding`
        // would otherwise pin coordinator state across the (blocking) push.
        let zone_name_to_id = self.forwarding.zone_name_to_id.clone();

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
                // #2749: HA bulk-export Open delta; no observed ToS / TCP
                // flags (and not routed through the RT_FLOW close exporter).
                observed_tos: 0,
                observed_tcp_flags: 0,
                // #4915: HA bulk-export Open delta — feeds the session-sync
                // dispatcher, NOT the RT_FLOW exporter, and the SyncedSessionEntry
                // carries no session id. 0 (unknown).
                session_id: 0,
            });
        }
        drop(sessions);

        Ok(AllSessionsExport {
            handle,
            zone_name_to_id,
            deltas,
        })
    }

    /// #4054 test seam: install a qualifying LOCAL forward session (owner-RG 0
    /// so the RG-active gate is bypassed, `ForwardCandidate` disposition, local
    /// `ForwardFlow` origin so it is not skipped as peer-synced) so a dispatcher
    /// test can drive a non-empty bulk export against a backpressured event
    /// stream. `idx` gives each call a distinct 5-tuple.
    #[cfg(test)]
    pub(crate) fn test_install_local_forward_session(&self, idx: u16) {
        use std::net::{IpAddr, Ipv4Addr};
        let key = SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 40000 + idx,
            dst_port: 5201,
        };
        let resolution = ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 12,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1))),
            neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
            src_mac: Some([6, 7, 8, 9, 10, 11]),
            tx_vlan_id: 0,
        };
        let metadata = SessionMetadata {
            ingress_zone: 1,
            egress_zone: 3,
            owner_rg_id: 0,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
            log_session_init: false,
            log_session_close: false,
            policy_id: 0,
            inactivity_timeout_ns: None,
            policy_counter_idx: 0,
            policy_counter: None,
        };
        self.upsert_synced_session(SyncedSessionEntry {
            key,
            decision: SessionDecision {
                resolution,
                nat: NatDecision::default(),
            },
            metadata,
            origin: SessionOrigin::ForwardFlow,
            protocol: PROTO_TCP,
            tcp_flags: 0,
            generation: 0,
        });
    }
}

/// A prepared bulk session export captured by
/// [`Coordinator::snapshot_all_sessions_export`] under the global
/// `ServerState` lock, so the (potentially blocking) lossless push loop can
/// run with that lock RELEASED (#4054). Mirrors [`OwnerRgExportWait`]'s
/// off-lock design (#2962): everything the push needs — the Arc-cheap
/// event-stream worker handle, an OWNED zone-name→id map, and the point-in-time
/// session-delta snapshot — is captured by value, so no coordinator borrow is
/// held across `push`.
pub struct AllSessionsExport {
    handle: crate::event_stream::EventStreamWorkerHandle,
    zone_name_to_id: FxHashMap<String, u16>,
    deltas: Vec<crate::session::SessionDelta>,
}

impl AllSessionsExport {
    /// Push the snapshotted Open deltas through the lossless event-stream
    /// producer. Runs WITHOUT the global `ServerState` lock (#4054), so a large
    /// or backpressured bulk export (each `push_delta_lossless` retries up to
    /// the 5 s lossless-queue timeout) can no longer freeze status polls,
    /// session installs, or HA state updates on that lock. Returns the number
    /// of sessions pushed on success.
    pub fn push(self) -> Result<usize, String> {
        let count = self.deltas.len();
        for delta in &self.deltas {
            self.handle
                .push_delta_lossless(delta, &self.zone_name_to_id)?;
        }
        eprintln!("xpf-ha: exported {count} sessions to event stream for bulk sync");
        Ok(count)
    }
}

/// Lock-free handle returned by [`Coordinator::kick_owner_rg_export`] so
/// the control-socket dispatcher can release the global `ServerState`
/// mutex BEFORE blocking on the per-worker export ack-wait (#2962).
///
/// At construction the export command has already been enqueued to every
/// worker; the only state the wait still needs is the per-worker ack
/// atomics (`ack_atomics`) and the per-binding delta buffers (`live`),
/// all `Arc`-shared and advanced by the worker threads without the global
/// lock. Holding these `Arc` clones lets the wait + drain run entirely
/// off the `ServerState` lock.
pub struct OwnerRgExportWait {
    sequence: u64,
    max: usize,
    /// `true` when no export was kicked (empty owner-RG set):
    /// `wait_and_collect` returns an empty delta set without touching the
    /// per-binding buffers, byte-identical to the pre-split early return.
    skip: bool,
    /// Per-worker `session_export_ack` atomics captured at kick time. The
    /// worker SET is stable for the lock-free wait window (every mutator
    /// holds the `ServerState` lock), so this snapshot is equivalent to
    /// re-reading `workers.handles` live.
    ack_atomics: Vec<Arc<AtomicU64>>,
    /// Per-binding delta buffers (`workers.live` values) captured at kick
    /// time; drained after all workers ack.
    live: Vec<Arc<BindingLiveState>>,
}

impl OwnerRgExportWait {
    /// Phase 2 of the owner-RG export (#2962): block up to 15 s for every
    /// worker to ack the export sequence, then drain the produced session
    /// deltas. Runs WITHOUT the global `ServerState` lock, so concurrent
    /// control RPCs (status poll, session installs, snapshot/FIB bumps, HA
    /// state updates) stay responsive while one export drains. Preserves
    /// the original 15 s deadline and timeout error.
    pub fn wait_and_collect(self) -> Result<Vec<SessionDeltaInfo>, String> {
        if self.skip {
            return Ok(Vec::new());
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        loop {
            if self
                .ack_atomics
                .iter()
                .all(|ack| ack.load(Ordering::Acquire) >= self.sequence)
            {
                break;
            }
            if std::time::Instant::now() >= deadline {
                return Err(format!(
                    "timed out waiting for session export ack seq={}",
                    self.sequence
                ));
            }
            thread::sleep(Duration::from_millis(5));
        }
        let mut out = Vec::new();
        let mut remaining = if self.max == 0 { usize::MAX } else { self.max.max(1) };
        // #5290: thread the fair-drain cursor across the batched export so a
        // low-slot binding cannot hog every 1024-batch and starve higher-slot
        // bindings within one capped export.
        let mut cursor = 0usize;
        while remaining > 0 {
            let batch_size = remaining.min(1024);
            let (drained, next_cursor) =
                drain_session_deltas_from_live(&self.live, batch_size, cursor);
            cursor = next_cursor;
            if drained.is_empty() {
                break;
            }
            remaining = remaining.saturating_sub(drained.len());
            out.extend(drained);
        }
        Ok(out)
    }
}

/// Drain up to `max` session deltas across the captured per-binding buffers,
/// starting the fair round-robin at `start_cursor` and returning the cursor to
/// resume from. Mirrors `Coordinator::drain_session_deltas`'s fair rotating
/// drain (#5290), but over an owned snapshot of the `Arc<BindingLiveState>`
/// values so it needs no `&Coordinator` (and therefore no `ServerState` lock).
///
/// Unlike the steady-state fallback drain, this bulk owner-RG export path does
/// NOT arm the overflow loss-of-sync latch: this export IS the resync/snapshot
/// mechanism, and its completeness is governed by the caller-supplied `max`
/// (the outer `wait_and_collect` loop drains to empty when `max == 0`). Arming
/// a worker resync from inside a resync export would be circular.
fn drain_session_deltas_from_live(
    live: &[Arc<BindingLiveState>],
    max: usize,
    start_cursor: usize,
) -> (Vec<SessionDeltaInfo>, usize) {
    let bindings: Vec<&BindingLiveState> = live.iter().map(|b| b.as_ref()).collect();
    let (out, cursor, _overflow) =
        crate::afxdp::session_delta::drain_session_deltas_fair(&bindings, max, start_cursor);
    (out, cursor)
}

#[cfg(test)]
#[path = "ha_tests.rs"]
mod tests;

