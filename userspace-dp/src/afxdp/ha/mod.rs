use super::*;

mod state;
mod export;

pub(crate) use self::export::{AllSessionsExport, OwnerRgExportWait};
#[cfg(test)]
pub(crate) use self::export::drain_session_deltas_from_live;

impl super::Coordinator {
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
            session_id: 0,
        });
    }
}

#[cfg(test)]
#[path = "../ha_tests.rs"]
mod tests;
