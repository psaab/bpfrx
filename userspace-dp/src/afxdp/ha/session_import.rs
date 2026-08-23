use crate::afxdp::*;

/// The outcome of an HA synced-session import (#6785).
///
/// `upsert_synced_session` used to return `()`. It has three SEMANTIC refusal
/// paths — a stale generation (#2170), the aggregate import cap (#5674), and a
/// translated-tuple reservation refusal (#6600) — and each one `return`ed
/// silently after bumping a counter. The control handler therefore answered
/// `ok = true`, so Go's `SetClusterSyncedSessionV4`/`V6` reported success and
/// LEFT its BPF mirror row in place for a session the helper had refused. That
/// is exactly the split truth #5305's transactional install exists to prevent —
/// its rollback machinery was already built and simply never reached, because
/// the only failure it could observe was an IPC error.
///
/// Reporting the refusal is therefore the whole fix on the helper side: the Go
/// compensation already exists.
///
/// The distinction between `Rejected*` and an IPC/transport failure matters on
/// the Go side and must not be collapsed. A transport failure means the session
/// socket is unhealthy and gates takeover-readiness (#5247); a semantic refusal
/// is an EXPECTED answer from a healthy helper (the peer sent something stale,
/// or this node is at its own ceiling) and marking the mirror unhealthy for it
/// would block failover on a node that is working correctly. Go discriminates on
/// the `SYNCED_IMPORT_REFUSED_PREFIX` token below.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncedImportOutcome {
    /// The entry was published (new key, or a replace of an existing one).
    Applied,
    /// #2170: a strictly-older generation than the stored entry.
    RejectedStaleGeneration,
    /// #5674: the aggregate synced-import entry ceiling is full.
    RejectedCapacity,
    /// #6600: the translated NAT tuple could not be reserved for this import.
    RejectedReserve,
}

/// The machine-readable prefix every semantic refusal carries in the control
/// response's `error` field. Go matches on THIS, not on the human-readable
/// remainder, so the sentence can be reworded without silently reclassifying a
/// refusal as a transport failure.
pub const SYNCED_IMPORT_REFUSED_PREFIX: &str = "synced-import-refused:";

impl SyncedImportOutcome {
    /// The stable reason token, or `None` when the import applied.
    pub fn refusal_reason(self) -> Option<&'static str> {
        match self {
            SyncedImportOutcome::Applied => None,
            SyncedImportOutcome::RejectedStaleGeneration => Some("stale-generation"),
            SyncedImportOutcome::RejectedCapacity => Some("capacity"),
            SyncedImportOutcome::RejectedReserve => Some("reserve"),
        }
    }
}

impl crate::afxdp::Coordinator {
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
    /// Visible to `ha::tests` (#6819 §7) so the PRODUCTION arithmetic below can
    /// be asserted directly. Both admission tests set
    /// `synced_import_cap_override`, which returns from the `#[cfg(test)]`
    /// branch BEFORE this function's production expression is ever evaluated —
    /// a test-only seam shadowing the real formula. With only those tests,
    /// deleting the trailing `.saturating_mul(2)` here leaves every cap
    /// assertion green.
    pub(super) fn synced_import_cap(&self) -> usize {
        #[cfg(test)]
        if self.synced_import_cap_override != 0 {
            // The override expresses a LOGICAL session ceiling; double it to the
            // ENTRY cap (fwd + synthesized reverse per logical session), matching
            // the production formula below so tests exercise the real arithmetic.
            return self.synced_import_cap_override.saturating_mul(2);
        }
        self.workers
            .records
            .len()
            .saturating_mul(crate::session::default_max_sessions())
            .saturating_mul(2)
    }

    /// #6600: take this node's reservation on a peer-synced forward entry's
    /// translated NAT identity. Returns false when the node cannot own it.
    ///
    /// The zone pair is resolved through the SAME helper the worker-side upsert
    /// uses, so the coordinator and the workers cannot land on different
    /// allocators — a coordinator that reserved elsewhere would report success
    /// while the port the session actually names stayed free.
    ///
    /// The NAT64 twin is taken second and ROLLED BACK on failure of neither
    /// half being enough on its own: a NAT64 decision carries both a v4 pool
    /// source (source-NAT allocator) and a translated `(pool v4, port)` (the
    /// per-prefix allocator), so a session can be admissible to one and not the
    /// other. Leaving a half-taken reservation behind would be a leak no worker
    /// ever releases, because no session gets published to reap.

    fn reserve_synced_translation(&self, entry: &SyncedSessionEntry) -> bool {
        let now_ns = monotonic_nanos();
        let zones = crate::afxdp::session_glue::synced_source_nat_zone_pair(
            &self.forwarding,
            &entry.metadata,
        );
        if !crate::nat::reserve_synced_source_nat_allocation_untracked(
            &self.forwarding.iface_nat_allocators,
            &self.forwarding.source_nat_rules,
            &entry.key,
            entry.decision.nat,
            entry.metadata.is_reverse,
            zones,
            now_ns,
        ) {
            return false;
        }
        if !crate::nat64::reserve_synced_nat64_allocation(
            &self.forwarding.nat64,
            &entry.key,
            entry.decision.nat,
            entry.metadata.is_reverse,
            now_ns,
        ) {
            crate::nat::release_source_nat_allocation(
                &self.forwarding.iface_nat_allocators,
                &self.forwarding.source_nat_rules,
                &entry.key,
                entry.decision.nat,
                entry.metadata.is_reverse,
                now_ns,
            );
            return false;
        }
        true
    }

    pub fn upsert_synced_session(&self, entry: SyncedSessionEntry) -> SyncedImportOutcome {
        let now_secs = monotonic_nanos() / 1_000_000_000;
        let ha_state = self.ha.rg_runtime.load();
        // #5154: read the stored entry AND the map length under ONE RECOVERED
        // critical section. Both reads feed a REFUSAL decision (the #2170
        // generation guard and the #5674 admission bound), and every write
        // below commits through `lock_shared_recover`. Reading with
        // `.lock().ok()` / `.lock().map(..).unwrap_or(0)` applied the OPPOSITE
        // poison policy to the validation half: after a contained worker panic
        // (#925 supervisor) poisoned this mutex, the stored entry read as None
        // and the length read as 0, so BOTH guards silently evaluated
        // "no previous entry, empty map" and fell through — while the
        // recovering write then committed the very install they exist to
        // refuse. A stale-generation import regressed the stored generation and
        // an over-ceiling import bypassed the aggregate bound, on a code path
        // the system is explicitly designed to SURVIVE. Recovering here (the
        // #2402 / #1807 module policy, `lock_shared_recover`: keep the
        // committed map, clear the poison, count + log the recovery) makes
        // validation and mutation agree. Refusing the WRITE on poison instead
        // is not a coherent alternative: `lock_shared_recover` CLEARS poison,
        // so the poisoned window closes the instant any other shared-session
        // path (publish, lookup, remove, prewarm) touches this mutex — a
        // refuse-on-poison write would fire or not fire depending on which
        // thread locked first, and would wedge HA session sync after a panic
        // the supervisor already contained. Folding the two reads into one
        // guard also removes a real TOCTOU: they were separate locks, so the
        // ceiling could be evaluated against a map that changed (including one
        // that had gained this very key) between them.
        let (previous_entry, synced_len) = {
            let sessions = lock_shared_recover(&self.sessions.synced);
            (sessions.get(&entry.key).cloned(), sessions.len())
        };
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
            self.sessions
                .install_stale_ignored
                .fetch_add(1, Ordering::Relaxed);
            return SyncedImportOutcome::RejectedStaleGeneration;
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
        // publishing its reverse, so no half-sync), and a lone reverse import is
        // never independently rejected at a boundary slot — it inserts one entry
        // that its forward already accounted for.
        //
        // #6413: that lone reverse does NOT arrive "off the wire from a peer" —
        // a peer-received reverse never reaches this function at all. Go's
        // `SetClusterSyncedSessionV4`/`V6` (`pkg/dataplane/userspace/
        // manager_sessions.go`) early-returns on `!shouldMirrorUserspaceSession(
        // val.IsReverse)` and writes ONLY the BPF mirror, so only FORWARD peer
        // imports transit the helper — which then synthesizes their reverse
        // companion locally (`synthesized_synced_reverse_entry`). The only
        // `is_reverse=1` entry that reaches this gate is the LOCAL mirror
        // companion `mirrorSessionPairV4`/`V6` (#310) pre-install as a
        // SEPARATE upsert, dispatched through
        // `server/handlers/sync_session.rs`, which calls
        // `upsert_synced_session` unconditionally for any `is_reverse`.
        //
        // #6413 corner, documented rather than implied away: if the shared
        // `synced` map is AT the 2N entry cap and that local mirror's FORWARD is
        // cap-rejected, its separate `is_reverse=1` companion still skips this
        // forward-only gate and publishes as a bounded **+1 orphan** entry with
        // no matching forward. Self-inflicted and bounded by the local session
        // rate, low-harm, and explicitly NOT the peer-DoS vector this cap
        // targets — the Go reverse filter above already excludes the peer path.
        // So fwd/rev pairing at this boundary is not perfect, by construction.
        //
        // Drop-NEWEST: reject a NEW forward key at/above
        // the ceiling (never enqueue it to any worker), but ALWAYS allow a
        // REPLACE of an existing synced key (`previous_entry.is_some()` — it
        // does not grow the map) so an in-flight synced session keeps
        // refreshing. Never evict an existing synced session to make room; that
        // would drop a legitimate failover session. A zero ceiling (no workers
        // registered yet — early boot / teardown) disables the bound so a
        // transient window never rejects legitimate imports.
        if previous_entry.is_none() && !entry.metadata.is_reverse {
            let synced_cap = self.synced_import_cap();
            if synced_cap != 0 && synced_len >= synced_cap {
                self.sessions
                    .import_cap_drops
                    .fetch_add(1, Ordering::Relaxed);
                return SyncedImportOutcome::RejectedCapacity;
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
        // #6600: RESERVE THE TRANSLATED NAT PORT BEFORE PUBLISHING.
        //
        // The publish below makes the entry visible on every packet-path lookup
        // surface at once (`synced`, `nat`, `forward_wire`), and
        // `materialize_shared_session_hit` forwards on `replica.decision`
        // — including `decision.nat` — without reserving anything. The
        // reservation used to happen ONLY inside the worker-local upsert, which
        // is driven by a command enqueued AFTER this publish; a worker that
        // sampled an empty queue just before that push proceeds straight into
        // `poll_binding` with the entry already live. In that window a local
        // flow can allocate the same port, and `reserve_flow` REFUSES to steal
        // it — correctly — after which the imported session went on advertising
        // a translation this node does not own, with the refusal returned by
        // nothing and counted by nothing.
        //
        // Taking the reservation here closes the window at its source rather
        // than trying to observe it afterwards. It is also the only thing that
        // COULD make the refusal reachable by the import outcome at all: the
        // worker-side reserve runs long after the control RPC has answered, so
        // propagating from there was never possible.
        //
        // `Untracked` contributes no holder bit, so the per-worker reservations
        // that follow are absorbed rather than doubled — `reserve_flow` finds
        // the identical `(flow, translated)` already live and takes its
        // idempotent early return, OR-ing each worker's bit in — and the last
        // worker's release still empties the mask and frees the port.
        //
        // Skipped when NO worker is registered: nothing polls, so there is no
        // racing local allocation to guard against, and an `Untracked`
        // reservation that no worker ever adopts has no one to release it. Same
        // shape as the zero-ceiling carve-out above, and for the same reason.
        if entry.origin.is_peer_synced()
            && !entry.metadata.is_reverse
            && !self.workers.records.is_empty()
            && !self.reserve_synced_translation(&entry)
        {
            self.sessions
                .import_reserve_refused
                .fetch_add(1, Ordering::Relaxed);
            return SyncedImportOutcome::RejectedReserve;
        }
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
        // #6242: fan out to each worker's command queue via its runtime record.
        for rec in self.workers.records.values() {
            // #1790/#1807: recover-and-push instead of silently skipping a
            // poisoned queue (same policy as update_ha_state).
            let mut pending = worker_queue::lock_recover(&rec.handle.commands);
            pending.push_back(WorkerCommand::UpsertSynced(entry.clone()));
            if let Some(reverse) = &reverse_entry {
                pending.push_back(WorkerCommand::UpsertSynced(reverse.clone()));
            }
        }
        SyncedImportOutcome::Applied
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
        // #5154: RECOVER the poison on this read (same policy as the write
        // below, which reaches the map through `remove_shared_session` ->
        // `lock_shared_recover`). With `.lock().ok()` a poisoned mutex read as
        // None, so the delete-side generation guard never evaluated — and the
        // recovering `remove_shared_session` then deleted the entry anyway.
        // That is a stale delete killing a NEWER same-key replacement the
        // helper had already mirrored: exactly the outcome this guard exists
        // to prevent, reachable via a contained worker panic.
        let removed_entry = lock_shared_recover(&self.sessions.synced)
            .get(&key)
            .cloned();
        if let Some(entry) = removed_entry.as_ref()
            && entry.generation != 0
            && delete_gen != 0
            && delete_gen < entry.generation
        {
            self.sessions
                .delete_stale_ignored
                .fetch_add(1, Ordering::Relaxed);
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
        // #6242: fan out to each worker's command queue via its runtime record.
        for rec in self.workers.records.values() {
            // #1790/#1807: recover-and-push instead of silently skipping a
            // poisoned queue (same policy as update_ha_state).
            let mut pending = worker_queue::lock_recover(&rec.handle.commands);
            pending.push_back(WorkerCommand::DeleteSynced(key.clone()));
            if let Some(reverse_key) = &reverse_key {
                pending.push_back(WorkerCommand::DeleteSynced(reverse_key.clone()));
            }
        }
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
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
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
        let _ = self.upsert_synced_session(SyncedSessionEntry {
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
