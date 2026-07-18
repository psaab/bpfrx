// #1345: per-verb handler for set_queue_state. Body byte-identical to
// handlers.rs lines 231-264.

use super::super::helpers::{reconcile_status_bindings, refresh_status, wait_for_binding_settle};
use super::super::ServerState;
use chrono::Utc;
use crate::{ControlResponse, QueueControlRequest};
use std::time::Duration;

pub(super) fn set(
    guard: &mut ServerState,
    queue: Option<QueueControlRequest>,
    response: &mut ControlResponse,
    persist_state: &mut bool,
) {
    let Some(queue_req) = queue else {
        response.ok = false;
        response.error = "missing queue state".to_string();
        return;
    };
    let mut found = false;
    let mut registration_changed = false;
    for binding in guard
        .status
        .bindings
        .iter_mut()
        .filter(|b| b.queue_id == queue_req.queue_id)
    {
        if binding.registered != queue_req.registered {
            registration_changed = true;
        }
        binding.registered = queue_req.registered;
        binding.armed = queue_req.armed && queue_req.registered;
        binding.last_change = Some(Utc::now());
        found = true;
    }
    if found {
        if registration_changed {
            // #3789: this reconcile re-binds the ALREADY-ACCEPTED stored
            // snapshot (a queue registration toggle, not a new config), so
            // a build reject cannot introduce a rejected snapshot here.
            //
            // #5621: the reconcile itself can still FAIL — the mandatory-pin
            // preflight can fault, or the forwarding build can hit a
            // non-policy integrity error on the already-accepted snapshot.
            // Discarding that Err made the handler ack ok=true while the
            // AF_XDP sockets were NOT actually rebound, so the control-socket
            // caller believed the reconcile succeeded when it did not.
            // Surface the failure: report ok=false + the error, refresh
            // status so `show` reflects the real per-binding state, and do
            // NOT persist a success we didn't achieve.
            if let Err(err) = reconcile_status_bindings(guard) {
                response.ok = false;
                response.error = format!("queue reconcile failed: {err}");
                refresh_status(guard);
                return;
            }
            wait_for_binding_settle(guard, Duration::from_secs(2));
        }
        refresh_status(guard);
        *persist_state = true;
    } else {
        response.ok = false;
        response.error = format!("unknown queue {}", queue_req.queue_id);
    }
}
