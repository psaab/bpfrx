// #1345: per-verb handlers for export_owner_rg_sessions and
// export_all_sessions. Both verbs produce session deltas.
//
// #2962: export_owner_rg_sessions is now a TWO-PHASE handler. `owner_rg_kick`
// runs the LOCKED phase — it enqueues the export command to every worker and
// returns an `OwnerRgExportWait`. The control-socket dispatcher
// (server/handlers/mod.rs) then RELEASES the global `ServerState` mutex and
// runs `OwnerRgExportWait::wait_and_collect` (the blocking 15 s ack-wait)
// lock-free, so a slow worker can no longer freeze the whole control plane.

use super::super::ServerState;
use crate::afxdp::{AllSessionsExport, OwnerRgExportWait};
use crate::{ControlResponse, SessionExportRequest};

/// Locked phase: enqueue the owner-RG export to every worker and capture the
/// lock-free wait handle. Returns the handle to the dispatcher, which runs
/// the blocking ack-wait AFTER dropping the `ServerState` lock (#2962).
pub(super) fn owner_rg_kick(
    guard: &mut ServerState,
    session_export: Option<SessionExportRequest>,
) -> OwnerRgExportWait {
    let export_req = session_export.unwrap_or_default();
    guard.afxdp.kick_owner_rg_export(
        &export_req.owner_rgs,
        export_req.max as usize,
        export_req.continuation,
    )
}

/// Lock-free phase: block for the worker acks, drain the deltas, and fold the
/// result into the response. Called by the dispatcher with the `ServerState`
/// lock RELEASED. Mirrors the pre-split `Ok`/`Err` handling (deltas + persist
/// on success; ok/error on timeout).
pub(super) fn owner_rg_collect(
    wait: OwnerRgExportWait,
    response: &mut ControlResponse,
    persist_state: &mut bool,
) {
    match wait.wait_and_collect() {
        Ok((deltas, more)) => {
            response.session_deltas = deltas;
            // #9344: the caller pages until this is false. It is set even when
            // `session_deltas` is empty, so "capped at zero with a remainder"
            // and "nothing left" cannot read alike.
            response.session_export_more = more;
            *persist_state = true;
        }
        Err(err) => {
            response.ok = false;
            response.error = err;
        }
    }
}

/// Locked phase of `export_all_sessions` (#4054): snapshot the bulk export
/// under the global `ServerState` lock and return the lock-free push handle.
/// The (potentially blocking) `push_delta_lossless` loop runs in `all_push`
/// AFTER the dispatcher drops the lock — mirroring the owner-RG `owner_rg_kick`
/// split (#2962) — so a large or backpressured bulk export can no longer starve
/// the status poll / trip the control plane's liveness deadline and self-inflict
/// a needless helper restart. On error (event stream not started) the error is
/// folded into `response` and `None` is returned, so the dispatcher runs no
/// push phase.
pub(super) fn all_kick(
    guard: &mut ServerState,
    response: &mut ControlResponse,
) -> Option<AllSessionsExport> {
    match guard.afxdp.snapshot_all_sessions_export() {
        Ok(export) => Some(export),
        Err(err) => {
            response.ok = false;
            response.error = err;
            None
        }
    }
}

/// Lock-free phase of `export_all_sessions` (#4054): run the lossless push loop
/// with the global `ServerState` lock RELEASED. Called by the dispatcher after
/// it drops the lock. Mirrors `owner_rg_collect`.
pub(super) fn all_push(export: AllSessionsExport, response: &mut ControlResponse) {
    if let Err(err) = export.push() {
        response.ok = false;
        response.error = err;
    }
}
