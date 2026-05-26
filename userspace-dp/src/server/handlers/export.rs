// #1345: per-verb handlers for export_owner_rg_sessions and
// export_all_sessions. Both verbs produce session deltas. Bodies
// byte-identical to handlers.rs lines 354-370 and 371-379.

use super::super::helpers::refresh_status;
use super::super::ServerState;
use crate::{ControlResponse, SessionExportRequest};

pub(super) fn owner_rg(
    guard: &mut ServerState,
    session_export: Option<SessionExportRequest>,
    response: &mut ControlResponse,
    persist_state: &mut bool,
) {
    let export_req = session_export.unwrap_or_default();
    match guard
        .afxdp
        .export_owner_rg_sessions(&export_req.owner_rgs, export_req.max as usize)
    {
        Ok(deltas) => {
            response.session_deltas = deltas;
            refresh_status(guard);
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
