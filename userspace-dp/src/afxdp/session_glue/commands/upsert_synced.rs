use super::super::*;

/// Apply `WorkerCommand::UpsertSynced`: re-resolve the synced
/// forward session with local egress (regardless of HA state — #326),
/// upsert into the session table, and publish the kernel session-map
/// entry if the upsert took.
///
/// Lifted verbatim from `apply_worker_commands` at the
/// `WorkerCommand::UpsertSynced` match arm.
///
/// Synced sessions arrive with the remote node's interface indices
/// and MACs which don't work on this node. By resolving on receipt
/// (even on standby), sessions are immediately forwarding-ready at
/// activation — the helper no longer needs a second activation-time
/// forward scan to fix them up. HA enforcement still happens at
/// packet time via flow cache validation
/// (`enforce_ha_resolution_snapshot`).
pub(in crate::afxdp::session_glue) fn handle_upsert_synced(
    sessions: &mut SessionTable,
    session_map_fd: c_int,
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    mut entry: SyncedSessionEntry,
    now_ns: u64,
    now_secs: u64,
) {
    let key = entry.key.clone();
    let allow_replace_local =
        synced_entry_allows_local_replace(ha_state, entry.metadata.owner_rg_id, now_secs);
    let is_active = !allow_replace_local;

    if !entry.metadata.is_reverse {
        let flow = SessionFlow {
            src_ip: key.src_ip,
            dst_ip: key.dst_ip,
            forward_key: key.clone(),
        };
        let re_resolved = lookup_forwarding_resolution_for_session(
            forwarding,
            dynamic_neighbors,
            &flow,
            entry.decision,
        );
        // On active node, enforce HA snapshot to filter out sessions
        // for inactive RGs. On standby, skip HA enforcement — store
        // the resolved ForwardCandidate so the session is ready when
        // activation happens. The packet path enforces HA state via
        // flow cache validation.
        let re_resolved = if is_active {
            enforce_ha_resolution_snapshot(forwarding, ha_state, now_secs, re_resolved)
        } else {
            re_resolved
        };
        if re_resolved.disposition != ForwardingDisposition::HAInactive {
            entry.decision.resolution = re_resolved;
            let new_owner = owner_rg_for_resolution(forwarding, re_resolved);
            if new_owner > 0 {
                entry.metadata.owner_rg_id = new_owner;
            }
        }
    }

    let metadata = entry.metadata.clone();
    if sessions.upsert_synced_with_origin(
        SessionInstall {
            key: entry.key,
            decision: entry.decision,
            metadata: entry.metadata,
            origin: entry.origin,
            now_ns,
            protocol: entry.protocol,
            tcp_flags: entry.tcp_flags,
        },
        allow_replace_local,
    ) {
        publish_worker_session_map_entry(
            session_map_fd,
            forwarding,
            &key,
            entry.decision,
            &metadata,
            entry.origin,
            allow_replace_local,
        );
    }
}
