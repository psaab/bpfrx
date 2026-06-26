// #1345: per-verb handlers for export_owner_rg_sessions and
// export_all_sessions. Both verbs produce session deltas.
//
// #2962: export_owner_rg_sessions is now a TWO-PHASE handler. `owner_rg_kick`
// runs the LOCKED phase — it enqueues the export command to every worker and
// returns an `OwnerRgExportWait`. The control-socket dispatcher
// (server/handlers/mod.rs) then RELEASES the global `ServerState` mutex and
// runs `OwnerRgExportWait::wait_and_collect` (the blocking 15 s ack-wait)
// lock-free, so a slow worker can no longer freeze the whole control plane.

use super::super::helpers::refresh_status;
use super::super::ServerState;
use crate::afxdp::OwnerRgExportWait;
use crate::{ControlResponse, SessionExportRequest};

/// Locked phase: enqueue the owner-RG export to every worker and capture the
/// lock-free wait handle. Returns the handle to the dispatcher, which runs
/// the blocking ack-wait AFTER dropping the `ServerState` lock (#2962).
pub(super) fn owner_rg_kick(
    guard: &mut ServerState,
    session_export: Option<SessionExportRequest>,
) -> OwnerRgExportWait {
    let export_req = session_export.unwrap_or_default();
    guard
        .afxdp
        .kick_owner_rg_export(&export_req.owner_rgs, export_req.max as usize)
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
        Ok(deltas) => {
            response.session_deltas = deltas;
            *persist_state = true;
        }
        Err(err) => {
            response.ok = false;
            response.error = err;
        }
    }
}

pub(super) fn all(guard: &mut ServerState, response: &mut ControlResponse) {
    match guard.afxdp.export_all_sessions_to_event_stream() {
        Ok(_count) => {
            refresh_status(guard);
        }
        Err(err) => {
            response.ok = false;
            response.error = err;
        }
    }
}
