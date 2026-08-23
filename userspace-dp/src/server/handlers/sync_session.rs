// #1345: per-verb handler for sync_session. Body byte-identical to
// handlers.rs lines 309-342 (preserves the nested match on
// sync_req.operation).

use super::super::helpers::{build_synced_session_entry, build_synced_session_key};
use super::super::ServerState;
use crate::afxdp::SYNCED_IMPORT_REFUSED_PREFIX;
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
                // #6785: a SEMANTIC refusal (stale generation / import cap /
                // translated-tuple reserve) used to return `()` and leave
                // `response.ok` true, so Go recorded a success and kept the BPF
                // mirror row for a session this helper never took — the split
                // truth #5305's transactional install already knows how to
                // compensate, but could not, because the only failure it could
                // see was an IPC error. Report the refusal so that rollback runs.
                //
                // The reason token is prefixed so Go can tell a refusal from a
                // transport failure. That distinction is load-bearing, not
                // cosmetic: a transport failure means the session socket is sick
                // and gates takeover-readiness (#5247), whereas a refusal is the
                // correct answer from a HEALTHY helper and must not block
                // failover on a node that is working.
                let outcome = guard.afxdp.upsert_synced_session(entry);
                if let Some(reason) = outcome.refusal_reason() {
                    response.ok = false;
                    response.error =
                        format!("{SYNCED_IMPORT_REFUSED_PREFIX}{reason}");
                }
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
