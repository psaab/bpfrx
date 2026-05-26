// #1345: per-verb handler for set_forwarding_state. Body byte-identical
// to handlers.rs lines 132-155.

use super::super::helpers::{
    forwarding_unsupported_error, reconcile_status_bindings, refresh_status,
    set_bindings_forwarding_armed, wait_for_binding_settle,
};
use super::super::ServerState;
use crate::{ControlResponse, ForwardingControlRequest};
use std::time::Duration;

pub(super) fn set(
    guard: &mut ServerState,
    forwarding: Option<ForwardingControlRequest>,
    response: &mut ControlResponse,
    persist_state: &mut bool,
) {
    let Some(forwarding_req) = forwarding else {
        response.ok = false;
        response.error = "missing forwarding state".to_string();
        return;
    };
    eprintln!(
        "CTRL_REQ: set_forwarding_state armed={} forwarding_armed_before={}",
        forwarding_req.armed, guard.status.forwarding_armed
    );
    if forwarding_req.armed && !guard.status.capabilities.forwarding_supported {
        response.ok = false;
        response.error = forwarding_unsupported_error(&guard.status.capabilities);
        return;
    }
    guard.status.forwarding_armed = forwarding_req.armed;
    set_bindings_forwarding_armed(&mut guard.status, forwarding_req.armed);
    reconcile_status_bindings(guard);
    if forwarding_req.armed {
        wait_for_binding_settle(guard, Duration::from_secs(2));
    }
    refresh_status(guard);
    *persist_state = true;
}
