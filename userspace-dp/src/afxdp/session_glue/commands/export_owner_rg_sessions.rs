use super::super::*;

/// Apply `WorkerCommand::ExportOwnerRGSessions`: record the requested owner
/// RGs for a chunked, drain-as-you-export re-emit by the worker loop, and
/// push the command sequence onto the exported-sequences accumulator so the
/// `session_export_ack` advances once the export has shipped.
///
/// #2653: this handler used to call `export_forward_sessions_for_owner_rgs`
/// inline, which pushed the ENTIRE owned-session set (up to
/// `DEFAULT_MAX_SESSIONS` = 131072 = 32x the 4096-slot delta ring) into the
/// ring in one shot. With no interleaved drain, the ring overflowed at delta
/// 4097 and `push_delta` silently dropped sessions 4097..N, so the HA peer
/// received an INCOMPLETE bulk snapshot on rejoin / RG transition.
///
/// `apply_worker_commands` has no `BindingWorker`/flush access, so it cannot
/// drain the ring to the peer mid-export. The fix mirrors the #2442
/// loss-of-sync resync: the handler only RECORDS the owner RGs here; the
/// worker loop (`worker::loop_body`), which holds the binding + flush
/// machinery, performs the same chunked drain-as-you-export (collect
/// candidates -> emit in < cap chunks -> drain between chunks) so the complete
/// snapshot ships without ever overflowing the ring. The sequence is acked
/// only after that chunked export drains to empty.
pub(in crate::afxdp::session_glue) fn handle_export_owner_rg_sessions(
    exported_sequences: &mut Vec<u64>,
    export_owner_rgs: &mut Vec<i32>,
    sequence: u64,
    owner_rgs: Vec<i32>,
) {
    for rg in owner_rgs {
        if !export_owner_rgs.contains(&rg) {
            export_owner_rgs.push(rg);
        }
    }
    exported_sequences.push(sequence);
}
