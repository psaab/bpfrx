// #1345: per-verb handlers for apply_snapshot and bump_fib_generation.
// Both verbs pivot on request.snapshot. Bodies are byte-identical
// to handlers.rs lines 53-131 (apply_snapshot) and 209-225
// (bump_fib_generation) modulo the per-handler parameter-passing
// substitution described in docs/pr/1345-server-handlers-split/plan.md.

use super::super::helpers::{
    reconcile_status_bindings, refresh_status, replan_queues,
    same_plan_apply_needs_binding_reconcile, snapshot_binding_plan_key,
};
use super::super::ServerState;
use crate::{ConfigSnapshot, ControlResponse, CONFIG_SNAPSHOT_PROTOCOL_VERSION};

pub(super) fn apply(
    guard: &mut ServerState,
    snapshot: Option<ConfigSnapshot>,
    response: &mut ControlResponse,
    persist_state: &mut bool,
) {
    let Some(snapshot) = snapshot else {
        response.ok = false;
        response.error = "missing snapshot".to_string();
        return;
    };
    if snapshot.version != CONFIG_SNAPSHOT_PROTOCOL_VERSION {
        response.ok = false;
        response.error = format!(
            "unsupported snapshot protocol version {} (want {})",
            snapshot.version, CONFIG_SNAPSHOT_PROTOCOL_VERSION
        );
        return;
    }
    eprintln!(
        "CTRL_REQ: apply_snapshot generation={} fib_generation={} forwarding_armed_before={}",
        snapshot.generation, snapshot.fib_generation, guard.status.forwarding_armed
    );
    guard.status.last_snapshot_generation = snapshot.generation;
    guard.status.last_fib_generation = snapshot.fib_generation;
    guard.status.last_snapshot_at = Some(snapshot.generated_at);
    guard.status.capabilities = snapshot.capabilities.clone();
    let existing_bindings = guard.status.bindings.clone();
    let previous_defer_workers = guard
        .snapshot
        .as_ref()
        .is_some_and(|prev| prev.defer_workers);
    let same_plan = guard.snapshot.as_ref().is_some_and(|prev| {
        let prev_key = snapshot_binding_plan_key(prev);
        let next_key = snapshot_binding_plan_key(&snapshot);
        let same = prev_key == next_key;
        if !same {
            eprintln!(
                "CTRL_REQ: binding plan changed prev_key={} next_key={}",
                prev_key, next_key
            );
        }
        same
    });
    if same_plan {
        let needs_reconcile = same_plan_apply_needs_binding_reconcile(
            guard,
            previous_defer_workers,
            snapshot.defer_workers,
        );
        if needs_reconcile {
            eprintln!("CTRL_REQ: same-plan apply_snapshot reconciling deferred bindings");
            guard.snapshot = Some(snapshot);
            reconcile_status_bindings(guard);
        } else {
            guard.afxdp.refresh_runtime_snapshot(&snapshot);
            guard.snapshot = Some(snapshot);
        }
        refresh_status(guard);
        *persist_state = true;
    } else {
        let defer_workers = snapshot.defer_workers;
        guard.snapshot = Some(snapshot);
        let replanned = replan_queues(
            guard.snapshot.as_ref(),
            guard.status.workers,
            &existing_bindings,
        );
        guard.status.bindings = replanned;
        if defer_workers {
            eprintln!(
                "CTRL_REQ: apply_snapshot defer_workers=true — skipping worker spawn (RETH MAC pending)"
            );
        } else {
            reconcile_status_bindings(guard);
        }
        refresh_status(guard);
        *persist_state = true;
    }
}

pub(super) fn bump_fib(
    guard: &mut ServerState,
    snapshot: Option<&ConfigSnapshot>,
    response: &mut ControlResponse,
) {
    // Lightweight FIB generation bump without a full snapshot.
    // Updates the generation counter so workers invalidate stale
    // flow cache entries, without the cost of rebuilding and
    // transmitting the entire config snapshot.
    let Some(snapshot) = snapshot else {
        response.ok = false;
        response.error = "missing snapshot".to_string();
        return;
    };
    guard.status.last_fib_generation = snapshot.fib_generation;
    if let Some(ref mut snap) = guard.snapshot {
        snap.fib_generation = snapshot.fib_generation;
    }
    guard.afxdp.bump_fib_generation(snapshot.fib_generation);
    refresh_status(guard);
}
