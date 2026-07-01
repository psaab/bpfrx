// #1345: per-verb handlers for apply_snapshot and bump_fib_generation.
// Both verbs pivot on request.snapshot. Bodies are byte-identical
// to handlers.rs lines 53-131 (apply_snapshot) and 209-225
// (bump_fib_generation) modulo the per-handler parameter-passing
// substitution described in docs/pr/1345-server-handlers-split/plan.md.

use super::super::helpers::{
    reconcile_status_bindings, refresh_status, replan_queues,
    same_plan_apply_needs_binding_reconcile, should_run_afxdp, snapshot_binding_plan_key,
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
    // #1606 (AGY r2 finding 4.1): preflight policy-state validation
    // BEFORE any guard.status mutation. If the snapshot has
    // duplicate / zero / unknown book IDs, reject WITHOUT touching
    // any guard fields. The existing snapshot + workers stay
    // running on the previous good config.
    //
    // Uses a scratch counter store so we don't leak Arc entries on
    // rejected snapshots.
    {
        let preflight_counters = crate::policy::PolicyCounterStore::default();
        // #3402: resolve policy zones against the INCOMING snapshot's own zones,
        // NOT the live forwarding table (empty on a fresh boot, stale on a
        // new-zone apply) — populate_zones(snapshot) runs only later inside
        // build_forwarding_state. Using the live table here would flag every
        // concrete-zone policy as UnresolvableZoneReference and reject the whole
        // boot snapshot.
        let preflight_zones = crate::policy::zone_name_to_id_from_snapshot(&snapshot.zones);
        if let Err(err) = crate::policy::parse_policy_state_with_counters(
            &snapshot.default_policy,
            &snapshot.policies,
            &preflight_zones,
            &snapshot.address_books,
            &preflight_counters,
        ) {
            response.ok = false;
            response.error = format!("snapshot integrity error: {}", err);
            eprintln!(
                "CTRL_REQ: apply_snapshot rejected (integrity preflight): {}",
                err
            );
            return;
        }
    }
    eprintln!(
        "CTRL_REQ: apply_snapshot generation={} fib_generation={} forwarding_armed_before={}",
        snapshot.generation, snapshot.fib_generation, guard.status.forwarding_armed
    );
    // #3766: capture the prior status-reporting fields BEFORE the bump
    // so the same-plan refresh leg can restore them if the fallible
    // forwarding build rejects the snapshot (fail closed — a rejected
    // snapshot must not advance the reported generation/capabilities
    // against the still-live prior forwarding table).
    let prev_last_snapshot_generation = guard.status.last_snapshot_generation;
    let prev_last_fib_generation = guard.status.last_fib_generation;
    let prev_last_snapshot_at = guard.status.last_snapshot_at;
    guard.status.last_snapshot_generation = snapshot.generation;
    guard.status.last_fib_generation = snapshot.fib_generation;
    guard.status.last_snapshot_at = Some(snapshot.generated_at);
    let prev_capabilities =
        std::mem::replace(&mut guard.status.capabilities, snapshot.capabilities.clone());
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
            // #1866 (PR-review Codex r1 F1 + r2): refresh_runtime_snapshot
            // reconciles WG control threads for the running case
            // (Copilot C1, #1432) — but a DISARMED helper must not
            // spawn/bind them even transiently (the control loop binds
            // and may emit a handshake initiation before its first
            // stop check). The disarmed variant refreshes the same
            // forwarding/validation state with the WG spawn pass
            // replaced by a stop, mirroring reconcile_status_bindings.
            // #3766: the same-plan refresh is a FALLIBLE ATOMIC SWAP.
            // A snapshot that passed the policy preflight above can
            // still fail the full forwarding build (invalid interface
            // address, CoS queue, NAT64 / NPTv6 rule, ...). On that
            // error the coordinator left the prior good state fully
            // intact (build-first / atomic-swap), so the handler MUST
            // fail closed too: report ok=false, keep the previously
            // stored snapshot as the boot baseline, and do NOT set
            // persist_state. Advancing guard.snapshot / status
            // generation / persisted state here would report a
            // rejected snapshot as the running config.
            let refresh_result = if should_run_afxdp(&guard.status) {
                guard.afxdp.refresh_runtime_snapshot(&snapshot)
            } else {
                guard.afxdp.refresh_runtime_snapshot_disarmed(&snapshot)
            };
            if let Err(err) = refresh_result {
                // Restore the status reporting fields bumped at the top
                // of `apply` so `show`/status never advertise the
                // rejected snapshot's generation against the still-live
                // prior forwarding table.
                guard.status.last_snapshot_generation = prev_last_snapshot_generation;
                guard.status.last_fib_generation = prev_last_fib_generation;
                guard.status.last_snapshot_at = prev_last_snapshot_at;
                guard.status.capabilities = prev_capabilities;
                response.ok = false;
                response.error = format!("snapshot integrity error: {}", err);
                eprintln!(
                    "CTRL_REQ: same-plan apply_snapshot rejected (integrity build): {} — keeping previous state",
                    err
                );
                return;
            }
            guard.snapshot = Some(snapshot);
        }
        refresh_status(guard);
        *persist_state = true;
    } else {
        let defer_workers = snapshot.defer_workers;
        if defer_workers {
            // #1866 Change 2b (D4): the defer branch stores the snapshot
            // WITHOUT reconciling, leaving the coordinator's forwarding
            // (and so its WG desired set) stale until the deferred
            // bring-up. A WG endpoint REMOVED by this apply must still
            // release its control thread + UDP port NOW — narrow
            // prune-only reconcile against the new snapshot (no spawn,
            // no forwarding mutation).
            guard.afxdp.prune_wg_control_threads_for_snapshot(&snapshot);
            // #1881: same removal propagation for GRE local-origin
            // threads — a removed/mode-flipped tunnel's thread must
            // release its TUN reader fd NOW, not at the deferred
            // bring-up (the Go side is deleting the netdev).
            guard
                .afxdp
                .prune_local_tunnel_sources_for_snapshot(&snapshot);
        }
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
