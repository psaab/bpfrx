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
    // #3789: arming/disarming reconciles the ALREADY-ACCEPTED stored
    // snapshot (a forwarding-state toggle, not a new config), so a build
    // reject cannot introduce a rejected snapshot here.
    //
    // #6135 (4th site of #5621): the reconcile itself can still FAIL — the
    // mandatory-pin preflight can fault, or the forwarding build can hit a
    // non-policy integrity error on the already-accepted snapshot. Discarding
    // that Err made this handler ack ok=true while the AF_XDP sockets were NOT
    // actually reconciled to the new forwarding state, so the control-socket
    // caller believed the reconcile succeeded when it did not. Surface the
    // failure: report ok=false + the error, refresh status so `show` reflects
    // the real per-binding state, and do NOT persist a success we didn't
    // achieve (return BEFORE wait_for_binding_settle / persist_state=true).
    if let Err(err) = reconcile_status_bindings(guard) {
        response.ok = false;
        response.error = format!("forwarding reconcile failed: {err}");
        refresh_status(guard);
        return;
    }
    if forwarding_req.armed {
        wait_for_binding_settle(guard, Duration::from_secs(2));
    }
    refresh_status(guard);
    *persist_state = true;
}
