use super::super::*;

/// Apply `WorkerCommand::DeleteSynced`: drop the session and either
/// republish the kernel session-map alias (if the session table had
/// an entry to inspect) or just delete the live entry.
///
/// Lifted verbatim from `apply_worker_commands` at the
/// `WorkerCommand::DeleteSynced` match arm.
///
/// #6457: the deleted key is ALSO pushed onto `deleted_keys` so the worker
/// loop (which owns the per-binding flow caches `apply_worker_commands`
/// cannot see) invalidates every flow-cache slot backing it. The key is
/// recorded UNCONDITIONALLY — even when this worker's session table has no
/// entry (`delete_alias` is `None`): a stale cached `RewriteDescriptor`
/// outlives the table entry it was seeded from (that survival is exactly
/// the bug), so gating the record on the table lookup would leave the
/// stale permit in place. A superfluous record costs one no-op
/// `invalidate_slot` per binding (key+ifindex mismatch) — bounded by the
/// control-plane delete rate, never per-packet.
pub(in crate::afxdp::session_glue) fn handle_delete_synced(
    sessions: &mut SessionTable,
    session_map_fd: c_int,
    forwarding: &ForwardingState,
    key: SessionKey,
    now_ns: u64,
    deleted_keys: &mut Vec<SessionKey>,
    // #6211 F2: THIS worker's id. `DeleteSynced` is replicated to EVERY worker
    // queue (`replicate_session_delete`), so each worker drops its own holder
    // bit and the port is freed by whichever worker happens to be last.
    worker_id: u32,
) {
    let delete_alias = sessions.lookup(&key, now_ns, 0);
    sessions.delete(&key);
    deleted_keys.push(key.clone());
    if let Some(lookup) = delete_alias {
        // #4388: release the NAT pool port reserved for this peer-synced
        // session at install (`handle_upsert_synced` /
        // `reserve_synced_source_nat_allocation`) so the standby's local
        // allocator can reuse it. This is the same-key mirror of the
        // reservation and a no-op for a non-pool / non-reserved session
        // (`release_flow` returns false when the flow was never tracked).
        release_source_nat_allocation_for_worker(
            &forwarding.source_nat_rules,
            &key,
            lookup.decision.nat,
            lookup.metadata.is_reverse,
            now_ns,
            worker_id,
        );
        // #4512: mirror for NAT64. `handle_upsert_synced` now RESERVES a
        // peer-synced NAT64 forward flow's translated pool port in this node's
        // local allocator (`reserve_synced_nat64_allocation`), so this release
        // frees it on delete-sync with the same flow key — the standby-side
        // reserve/release pair that stops a post-failover local flow from
        // reusing the synced port (a no-op for a non-NAT64 / non-reserved
        // session, mirroring the source-NAT release above).
        crate::nat64::release_nat64_allocation_for_worker(
            &forwarding.nat64,
            &key,
            lookup.decision.nat,
            lookup.metadata.is_reverse,
            now_ns,
            worker_id,
        );
        delete_session_map_entry_for_removed_session(
            session_map_fd,
            &key,
            lookup.decision,
            &lookup.metadata,
        );
    } else {
        delete_live_session_key(session_map_fd, &key);
    }
}
