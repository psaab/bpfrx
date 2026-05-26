use super::super::*;

/// Apply `WorkerCommand::ExportOwnerRGSessions`: walk the session
/// table for the given owner RGs and push their sequence onto the
/// exported-sequences accumulator.
///
/// Lifted verbatim from `apply_worker_commands` at the
/// `WorkerCommand::ExportOwnerRGSessions` match arm. Takes the
/// narrow `&mut Vec<u64>` instead of `&mut WorkerCommandResults`
/// because the dispatcher constructs the results struct after the
/// loop (per #1346 plan v2).
pub(in crate::afxdp::session_glue) fn handle_export_owner_rg_sessions(
    sessions: &mut SessionTable,
    exported_sequences: &mut Vec<u64>,
    sequence: u64,
    owner_rgs: Vec<i32>,
) {
    export_forward_sessions_for_owner_rgs(sessions, &owner_rgs);
    exported_sequences.push(sequence);
}
