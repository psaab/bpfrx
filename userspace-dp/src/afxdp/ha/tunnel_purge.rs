// This submodule references shared types only through fully-qualified
// `crate::` paths, so it needs no `use crate::afxdp::*` glob.
impl crate::afxdp::Coordinator {
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
            // #6653 sweep: RECOVERING lock. `let Ok(..) else { return 0 }`
            // made the #1873 R-D purge SILENTLY DO NOTHING on a poisoned
            // mutex -- and this purge is what stops a live session
            // re-resolving a remapped tunnel_endpoint_id into the WRONG
            // tunnel (cross-tunnel encap) or dead-ending on the R-C gate.
            // Not named by #6652/#6653/#6654; found by sweeping the predicate
            // rather than the three cited sites.
            let sessions = crate::afxdp::shared_ops::lock_shared_recover(&self.sessions.synced);
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
}
