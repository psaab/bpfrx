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
            reconcile_status_bindings(guard);
            wait_for_binding_settle(guard, Duration::from_secs(2));
        }
        refresh_status(guard);
        *persist_state = true;
    } else {
        response.ok = false;
        response.error = format!("unknown queue {}", queue_req.queue_id);
    }
}
