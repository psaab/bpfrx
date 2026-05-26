// #1345: per-verb handler for sync_session. Body byte-identical to
// handlers.rs lines 309-342 (preserves the nested match on
// sync_req.operation).

use super::super::helpers::{build_synced_session_entry, build_synced_session_key};
use super::super::ServerState;
use crate::{ControlResponse, SessionSyncRequest};

pub(super) fn handle(
    guard: &mut ServerState,
    session_sync: Option<SessionSyncRequest>,
    response: &mut ControlResponse,
) {
    let Some(sync_req) = session_sync else {
        response.ok = false;
        response.error = "missing session sync request".to_string();
        return;
    };
    match sync_req.operation.as_str() {
        "upsert" => match build_synced_session_entry(&sync_req, guard.afxdp.zone_name_to_id_ref()) {
            Ok(entry) => {
                guard.afxdp.upsert_synced_session(entry);
            }
            Err(err) => {
                response.ok = false;
                response.error = err;
            }
        },
        "delete" => match build_synced_session_key(&sync_req) {
            Ok(key) => {
                guard.afxdp.delete_synced_session(key);
            }
            Err(err) => {
                response.ok = false;
                response.error = err;
            }
        },
        other => {
            response.ok = false;
            response.error = format!("unknown session sync operation {other}");
        }
    }
}
