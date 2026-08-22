// #1345: per-verb handler for set_binding_state. Body byte-identical to
// handlers.rs lines 265-291.

use super::super::helpers::{reconcile_status_bindings, refresh_status};
use super::super::ServerState;
use chrono::Utc;
use crate::{BindingControlRequest, ControlResponse};
use std::time::Duration;

pub(super) fn set(
    guard: &mut ServerState,
    binding: Option<BindingControlRequest>,
    response: &mut ControlResponse,
    persist_state: &mut bool,
    // #5862: where the caller records that a binding-settle wait is owed. The
    // wait itself runs in handlers::handle_request AFTER the global ServerState
    // lock is dropped — the same locked-kick / unlocked-wait split #2962 and
    // #4054 use. Holding the lock across a 2 s settle stalled every HA
    // `sync_session` on the "dedicated" session socket, which shares this mutex.
    settle_wait: &mut Option<Duration>,
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
            // #3789: re-binds the ALREADY-ACCEPTED stored snapshot (a
            // binding registration toggle, not a new config), so a build
            // reject cannot introduce a rejected snapshot here.
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
                response.error = format!("binding reconcile failed: {err}");
                refresh_status(guard);
                return;
            }
            *settle_wait = Some(Duration::from_secs(2));
        }
        refresh_status(guard);
        *persist_state = true;
    } else {
        response.ok = false;
        response.error = format!("unknown binding slot {}", binding_req.slot);
    }
}
