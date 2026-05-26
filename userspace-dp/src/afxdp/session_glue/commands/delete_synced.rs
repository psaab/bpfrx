use super::super::*;

/// Apply `WorkerCommand::DeleteSynced`: drop the session and either
/// republish the kernel session-map alias (if the session table had
/// an entry to inspect) or just delete the live entry.
///
/// Lifted verbatim from `apply_worker_commands` at the
/// `WorkerCommand::DeleteSynced` match arm.
pub(in crate::afxdp::session_glue) fn handle_delete_synced(
    sessions: &mut SessionTable,
    session_map_fd: c_int,
    key: SessionKey,
    now_ns: u64,
) {
    let delete_alias = sessions.lookup(&key, now_ns, 0);
    sessions.delete(&key);
    if let Some(lookup) = delete_alias {
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
