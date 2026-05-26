// #1345: per-verb handler for set_binding_state. Body byte-identical to
// handlers.rs lines 265-291.

use super::super::helpers::{reconcile_status_bindings, refresh_status, wait_for_binding_settle};
use super::super::ServerState;
use chrono::Utc;
use crate::{BindingControlRequest, ControlResponse};
use std::time::Duration;

pub(super) fn set(
    guard: &mut ServerState,
    binding: Option<BindingControlRequest>,
    response: &mut ControlResponse,
    persist_state: &mut bool,
) {
    let Some(binding_req) = binding else {
        response.ok = false;
        response.error = "missing binding state".to_string();
        return;
    };
    if let Some(binding) = guard
        .status
        .bindings
        .iter_mut()
        .find(|b| b.slot == binding_req.slot)
    {
        let registration_changed = binding.registered != binding_req.registered;
        binding.registered = binding_req.registered;
        binding.armed = binding_req.armed && binding_req.registered;
        binding.last_change = Some(Utc::now());
        if registration_changed {
            reconcile_status_bindings(guard);
            wait_for_binding_settle(guard, Duration::from_secs(2));
        }
        refresh_status(guard);
        *persist_state = true;
    } else {
        response.ok = false;
        response.error = format!("unknown binding slot {}", binding_req.slot);
    }
}
