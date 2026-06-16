// #1345: per-verb handler for rebind. Body byte-identical to
// handlers.rs lines 380-408.

use super::super::helpers::{reconcile_status_bindings, refresh_status};
use super::super::ServerState;

pub(super) fn handle(guard: &mut ServerState, persist_state: &mut bool) {
    // After a link DOWN/UP cycle (e.g. RETH MAC programming),
    // the kernel destroys the XSK receive queue.  Clear binding
    // state and reconcile to recreate the AF_XDP sockets from
    // scratch.
    //
    // #1921: do NOT call guard.afxdp.stop() here. reconcile (via
    // reconcile_status_bindings -> tear_down) already stops + joins the
    // workers, and it gates a 500ms zero-copy teardown quiesce on
    // `had_live_workers = !coord.workers.handles.is_empty()`
    // (coordinator/reconcile/teardown.rs). An explicit stop() runs
    // stop_inner(true) which clears coord.workers.handles BEFORE tear_down
    // samples them, so had_live_workers reads false, the quiesce is
    // BYPASSED, and the freshly-recreated sockets race the kernel's still
    // pending xsk_pool teardown -> EBUSY. The busy-binding watchdog then
    // re-triggers rebind, bypassing the quiesce again -> an infinite
    // EBUSY/rebind loop (the live virtio multi-queue forwarding outage).
    // Letting tear_down own the stop also avoids stop_inner(true)'s extra
    // side effects that are wrong for a rebind: wiping the in-memory synced
    // session map (which should be replayed into BPF maps on bringup) and
    // defaulting coord.forwarding/coord.validation before tear_down
    // captures tunnel_owners/snapshot_was_installed (which blinds the
    // tunnel-owner remap purge in apply_snapshot). The RETH-MAC link-cycle
    // path is unaffected: Go sends a separate stop_workers request before
    // the link cycle and only sends rebind after link-up.
    //
    // No settle wait — worker threads create sockets async.
    // The response returns immediately; sockets become ready
    // within ~100ms as worker threads complete binding.
    eprintln!("rebind: recreating AF_XDP sockets (reconcile owns worker stop + ZC quiesce)");
    for binding in &mut guard.status.bindings {
        binding.bound = false;
        binding.xsk_registered = false;
        binding.xsk_bind_mode.clear();
        binding.zero_copy = false;
        binding.socket_fd = 0;
        binding.ready = false;
        binding.last_error.clear();
    }
    reconcile_status_bindings(guard);
    refresh_status(guard);
    *persist_state = true;
    eprintln!(
        "rebind: initiated, forwarding_armed={} bindings={}",
        guard.status.forwarding_armed,
        guard.status.bindings.len()
    );
}
