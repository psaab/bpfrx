// #1345: per-verb handler for update_ha_state. Body byte-identical to
// handlers.rs lines 156-179.

use super::super::helpers::refresh_status;
use super::super::ServerState;
use crate::{ControlResponse, HAStateUpdateRequest};

pub(super) fn update(
    guard: &mut ServerState,
    ha_state: Option<HAStateUpdateRequest>,
    response: &mut ControlResponse,
    persist_state: &mut bool,
) {
    let Some(ha_req) = ha_state else {
        response.ok = false;
        response.error = "missing HA state".to_string();
        return;
    };
    #[cfg(feature = "debug-log")]
    eprintln!(
        "CTRL_REQ: update_ha_state groups={} forwarding_armed={}",
        ha_req.groups.len(),
        guard.status.forwarding_armed
    );
    guard.status.ha_groups = ha_req.groups.clone();
    match guard.afxdp.update_ha_state(&ha_req.groups) {
        Ok(()) => {
            refresh_status(guard);
            *persist_state = true;
        }
        Err(err) => {
            response.ok = false;
            response.error = err;
        }
    }
}
