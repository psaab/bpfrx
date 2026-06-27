// Control-socket request dispatcher.
//
// #1345 split: the original 415-LOC `handle_stream` body has been
// decomposed into per-verb files in this directory module. This
// `mod.rs` retains only:
//   - Stream timeout setup
//   - BufReader / size-capped read_until / decode (#2523)
//   - `state.lock()` critical section
//   - `match request.request_type.as_str()` dispatch into per-verb
//     handlers (substantive verbs) or inline bodies (trivial arms:
//     `ping`/`status`, `update_fabrics`, `clear_policy_counters`,
//     `clear_nat_counters`, `shutdown`, catch-all)
//   - Post-match `refresh_status` + status attach (gated by
//     `!suppress_status`)
//   - Post-lock `write_state` (when `persist_state` is set)
//   - BufWriter / serde_json / newline / flush
//
// All per-verb files are byte-identical to the corresponding match
// arm in the pre-split `handlers.rs` modulo the `&mut ServerState`
// parameter substitution. See
// `docs/pr/1345-server-handlers-split/plan.md` for the full design.

mod binding;
mod export;
mod forwarding;
mod ha;
mod inject_packet;
mod neighbors;
mod queue;
mod rebind;
mod session_deltas;
mod snapshot;
mod stop_workers;
mod sync_session;

use super::super::*;
use super::helpers::{refresh_status, write_state};
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub(crate) fn handle_stream(
    stream: UnixStream,
    state_file: &str,
    state: Arc<Mutex<ServerState>>,
    running: Arc<AtomicBool>,
) -> Result<(), String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| format!("set read timeout: {e}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| format!("set write timeout: {e}"))?;

    // Read one newline-delimited request body, capped at
    // MAX_CONTROL_REQUEST_BYTES (#2523). A malformed or compromised local
    // caller could otherwise stream a very large unterminated line and
    // force the read buffer to grow unbounded — the 5 s read timeout
    // bounds the worst case in time but not in allocation. `take` limits
    // the reader to the cap + 1 byte, so the read can never allocate
    // beyond that ceiling. The largest legitimate request is a body of up
    // to MAX bytes plus its single terminating newline (the Go encoder
    // always appends one), i.e. MAX+1 bytes ending in '\n'. If the read
    // stops at the cap WITHOUT a terminating newline the body is, by
    // construction, oversize: reject it before any decode and keep the
    // daemon alive (fail-closed).
    let mut reader = BufReader::new(
        stream
            .try_clone()
            .map_err(|e| format!("clone stream for read: {e}"))?
            .take(MAX_CONTROL_REQUEST_BYTES as u64 + 1),
    );
    let mut line: Vec<u8> = Vec::new();
    let n = reader
        .read_until(b'\n', &mut line)
        .map_err(|e| format!("read request: {e}"))?;
    if n > MAX_CONTROL_REQUEST_BYTES && line.last() != Some(&b'\n') {
        return Err(format!(
            "control request exceeds maximum size of {MAX_CONTROL_REQUEST_BYTES} bytes; rejecting before decode"
        ));
    }
    let body = match line.last() {
        Some(&b'\n') => &line[..line.len() - 1],
        _ => &line[..],
    };
    let request: ControlRequest =
        serde_json::from_slice(body).map_err(|e| format!("decode request: {e}"))?;

    let mut response = ControlResponse {
        ok: true,
        error: String::new(),
        status: None,
        session_deltas: Vec::new(),
    };
    let mut persist_state = false;
    // Capture suppress_status before the match — bool is Copy so this
    // is byte-identical, but reading it up front insulates the
    // dispatcher from future partial-move concerns on `request`.
    let suppress_status = request.suppress_status;
    let neighbor_replace = request.neighbor_replace;

    // #2962: the owner-RG session export must NOT block under the global
    // ServerState lock. The locked `match` arm only KICKS the export
    // (enqueues the per-worker command + captures the lock-free ack/delta
    // handles); the blocking 15 s ack-wait runs here, AFTER the lock is
    // dropped, so a slow/stalled worker can no longer freeze status polls,
    // session installs, snapshot/FIB bumps, and HA state updates. When set,
    // the post-match status attach is also deferred until after the wait so
    // the reported status reflects the drained state.
    let mut export_wait: Option<crate::afxdp::OwnerRgExportWait> = None;

    {
        let mut guard = state.lock().expect("server state poisoned");
        match request.request_type.as_str() {
            "ping" | "status" => {}
            "apply_snapshot" => snapshot::apply(
                &mut guard,
                request.snapshot,
                &mut response,
                &mut persist_state,
            ),
            "set_forwarding_state" => forwarding::set(
                &mut guard,
                request.forwarding,
                &mut response,
                &mut persist_state,
            ),
            "update_ha_state" => ha::update(
                &mut guard,
                request.ha_state,
                &mut response,
                &mut persist_state,
            ),
            "update_fabrics" => {
                if let Some(fabrics) = request.fabrics.as_ref() {
                    guard.afxdp.refresh_fabric_links(fabrics);
                    refresh_status(&mut guard);
                }
            }
            "update_neighbors" => {
                neighbors::update(&mut guard, request.neighbors.as_ref(), neighbor_replace)
            }
            "bump_fib_generation" => {
                snapshot::bump_fib(&mut guard, request.snapshot.as_ref(), &mut response)
            }
            "clear_policy_counters" => {
                guard.afxdp.clear_policy_counters();
                refresh_status(&mut guard);
                persist_state = true;
            }
            // #2218: reset the helper-side NAT translation hit atomics. This is
            // the LOAD-BEARING half of the operator clear: the Go side also
            // zeroes its offset map, but the helper reports cumulative-since-
            // start totals on every status poll and the Go side mirrors them
            // ABSOLUTELY (SetNATRuleCounterOffset overwrites). Without resetting
            // this store the cleared total would snap back on the next poll.
            "clear_nat_counters" => {
                guard.afxdp.clear_nat_counters();
                refresh_status(&mut guard);
                persist_state = true;
            }
            "set_queue_state" => {
                queue::set(&mut guard, request.queue, &mut response, &mut persist_state)
            }
            "set_binding_state" => binding::set(
                &mut guard,
                request.binding,
                &mut response,
                &mut persist_state,
            ),
            "inject_packet" => inject_packet::handle(
                &mut guard,
                request.packet,
                &mut response,
                &mut persist_state,
            ),
            "sync_session" => sync_session::handle(&mut guard, request.session_sync, &mut response),
            "drain_session_deltas" => session_deltas::drain(
                &mut guard,
                request.session_deltas.as_ref(),
                &mut response,
                &mut persist_state,
            ),
            "export_owner_rg_sessions" => {
                // #2962: locked phase only — enqueue + capture the wait
                // handle. The blocking ack-wait runs after the lock drops.
                export_wait = Some(export::owner_rg_kick(&mut guard, request.session_export));
            }
            "export_all_sessions" => export::all(&mut guard, &mut response),
            "rebind" => rebind::handle(&mut guard, &mut persist_state),
            "stop_workers" => stop_workers::handle(&mut guard, &mut persist_state),
            "shutdown" => {
                guard.afxdp.stop_with_event_stream();
                running.store(false, Ordering::SeqCst);
                persist_state = true;
            }
            other => {
                response.ok = false;
                response.error = format!("unknown request type {other}");
            }
        }
        // #2962: defer status attach for the export verb — it is computed
        // after the lock-free ack-wait below so it reflects the drained
        // state (and is not produced while holding the lock across a wait).
        if export_wait.is_none() && !suppress_status {
            refresh_status(&mut guard);
            response.status = Some(guard.status.clone());
        }
    }

    // #2962: blocking owner-RG export ack-wait runs here, with the global
    // ServerState lock RELEASED, so the control plane stays responsive while
    // one export drains. Status is then re-derived under a fresh short-lived
    // lock acquisition (the wait is already done).
    if let Some(wait) = export_wait {
        export::owner_rg_collect(wait, &mut response, &mut persist_state);
        if !suppress_status {
            let mut guard = state.lock().expect("server state poisoned");
            refresh_status(&mut guard);
            response.status = Some(guard.status.clone());
        }
    }

    if persist_state {
        write_state(state_file, &state)?;
    }

    let mut writer = BufWriter::new(stream);
    serde_json::to_writer(&mut writer, &response).map_err(|e| format!("encode response: {e}"))?;
    writer
        .write_all(b"\n")
        .map_err(|e| format!("write response newline: {e}"))?;
    writer.flush().map_err(|e| format!("flush response: {e}"))?;
    Ok(())
}
