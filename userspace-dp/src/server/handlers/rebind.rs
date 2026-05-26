// #1345: per-verb handler for rebind. Body byte-identical to
// handlers.rs lines 380-408.

use super::super::helpers::{reconcile_status_bindings, refresh_status};
use super::super::ServerState;

pub(super) fn handle(guard: &mut ServerState, persist_state: &mut bool) {
    // After a link DOWN/UP cycle (e.g. RETH MAC programming),
    // the kernel destroys the XSK receive queue.  Stop all
    // workers, clear binding state, and reconcile to recreate
    // the AF_XDP sockets from scratch.
    //
    // No settle wait — worker threads create sockets async.
    // The response returns immediately; sockets become ready
    // within ~100ms as worker threads complete binding.
    eprintln!("rebind: stopping workers and recreating AF_XDP sockets");
    guard.afxdp.stop();
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
