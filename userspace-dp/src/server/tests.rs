// Colocated unit tests for the server/ control-plane handlers and
// helpers (#1653 Tier B / §3.1). Prior to this module `server/` had
// zero tests of its own — the only handler coverage lived in
// main_tests.rs and exercised apply_snapshot / queue-planner /
// session-sync paths. The #1642 status-field-parity drift lived in
// exactly this untested glue, so these tests assert handler behavior
// at the real `handle_stream` call site (not trivial getters): error
// arms, status-field population, HA gating, and the pure helper
// predicates.

use super::helpers::{
    bindings_settled, build_synced_session_entry, clear_pre_persist_lock_probe,
    forwarding_unsupported_error, parse_session_sync_mac, reconcile_status_bindings,
    set_bindings_forwarding_armed, should_run_afxdp, take_pre_persist_lock_free, write_state,
};
use super::{handle_stream, ServerState};
use crate::state_writer::StateWriter;
use crate::{
    afxdp, BindingControlRequest, BindingStatus, ControlRequest, ControlResponse, ForwardingControlRequest,
    HAGroupStatus, HAStateUpdateRequest, ProcessStatus, QueueControlRequest, SessionExportRequest,
    SessionSyncRequest, UserspaceCapabilities, MAX_CONTROL_REQUEST_BYTES,
};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

// --- harness ------------------------------------------------------------

fn unique_state_file(tag: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    format!(
        "{}/xpf-server-test-{}-{}-{}.json",
        std::env::temp_dir().display(),
        tag,
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    )
}

fn new_state(status: ProcessStatus) -> Arc<Mutex<ServerState>> {
    Arc::new(Mutex::new(ServerState {
        status,
        snapshot: None,
        afxdp: afxdp::Coordinator::new(),
        state_writer: Arc::new(StateWriter::new()),
    }))
}

/// Drive a single control request through the real `handle_stream`
/// dispatcher over a socketpair, exactly as the daemon's accept loop
/// does. Returns the decoded `ControlResponse`.
fn run_request(state: Arc<Mutex<ServerState>>, request: ControlRequest) -> ControlResponse {
    let state_file = unique_state_file(&request.request_type);
    let (mut client, server) =
        std::os::unix::net::UnixStream::pair().expect("control socket pair");
    let running = Arc::new(AtomicBool::new(true));
    let handle = {
        let state_file = state_file.clone();
        std::thread::spawn(move || handle_stream(server, &state_file, state, running))
    };

    serde_json::to_writer(&mut client, &request).expect("write request");
    std::io::Write::write_all(&mut client, b"\n").expect("newline");

    let response: ControlResponse =
        serde_json::from_reader(std::io::BufReader::new(client)).expect("read response");
    handle
        .join()
        .expect("handler thread")
        .expect("handler result");
    let _ = std::fs::remove_file(&state_file);
    response
}

/// Like `run_request` but drives against a caller-supplied `state_file`
/// and does NOT remove it, so a test can assert what the handler persisted
/// to disk (used by the #3767 M2 bump-persistence test).
fn run_request_on_file(
    state: Arc<Mutex<ServerState>>,
    request: ControlRequest,
    state_file: &str,
) -> ControlResponse {
    let (mut client, server) =
        std::os::unix::net::UnixStream::pair().expect("control socket pair");
    let running = Arc::new(AtomicBool::new(true));
    let handle = {
        let state_file = state_file.to_string();
        std::thread::spawn(move || handle_stream(server, &state_file, state, running))
    };

    serde_json::to_writer(&mut client, &request).expect("write request");
    std::io::Write::write_all(&mut client, b"\n").expect("newline");

    let response: ControlResponse =
        serde_json::from_reader(std::io::BufReader::new(client)).expect("read response");
    handle
        .join()
        .expect("handler thread")
        .expect("handler result");
    response
}

fn req(request_type: &str) -> ControlRequest {
    ControlRequest {
        request_type: request_type.to_string(),
        ..ControlRequest::default()
    }
}

/// Drive a RAW byte payload through `handle_stream` and return the
/// handler's `Result<(), String>` directly. Unlike `run_request`, this
/// does not assume the handler replies — an oversize/undecodable request
/// is rejected before the reply is written, so the caller inspects the
/// returned error string. The client half writes `payload` then shuts
/// down the write side so a body WITHOUT a terminating newline still
/// reaches EOF (the `take` cap, not the missing newline, must be what
/// bounds the read).
fn run_raw(state: Arc<Mutex<ServerState>>, payload: &[u8]) -> Result<(), String> {
    use std::io::Write as _;
    let state_file = unique_state_file("raw");
    let (mut client, server) =
        std::os::unix::net::UnixStream::pair().expect("control socket pair");
    let running = Arc::new(AtomicBool::new(true));
    let handle = {
        let state_file = state_file.clone();
        std::thread::spawn(move || handle_stream(server, &state_file, state, running))
    };
    client.write_all(payload).expect("write raw payload");
    // Drop the write half so the handler sees EOF; an oversize body with
    // no newline must still be bounded by the read cap, not block.
    client
        .shutdown(std::net::Shutdown::Write)
        .expect("shutdown write");
    // Drain any response the handler may write so it never blocks on a
    // full socket buffer, then collect the handler result.
    let mut sink = Vec::new();
    let _ = std::io::Read::read_to_end(&mut client, &mut sink);
    let result = handle.join().expect("handler thread");
    let _ = std::fs::remove_file(&state_file);
    result
}

// --- request byte cap (#2523) -------------------------------------------

#[test]
fn oversize_request_is_rejected_before_decode() {
    // A body one byte past the cap with NO terminating newline. The cap
    // must reject it before the (unbounded) decode allocation; the read
    // itself is bounded to MAX+1 by the `take` in handle_stream.
    let payload = vec![b'a'; MAX_CONTROL_REQUEST_BYTES + 1];
    let err = run_raw(new_state(ProcessStatus::default()), &payload)
        .expect_err("oversize request must be rejected");
    assert!(
        err.contains("exceeds maximum size"),
        "expected oversize rejection, got: {err}"
    );
    // Fail-on-revert pin: if the cap is removed, `read_until` would slurp
    // all MAX+1 'a' bytes and serde would fail with a DECODE error, not an
    // "exceeds maximum size" error — so this assertion goes RED on revert.
}

#[test]
fn max_size_legitimate_request_still_succeeds() {
    // A real request padded with a large (but legal) field up to just
    // under the cap, terminated by the single newline the Go encoder
    // appends. The body is <= MAX bytes, so MAX+1 bytes on the wire ending
    // in '\n' — the largest legitimate read. It must decode and succeed.
    // Pad the request_type string so the serialized body approaches the
    // cap without crossing it (leave generous slack for the JSON
    // envelope). The body decodes as valid JSON and the dispatcher runs
    // its catch-all arm — handle_stream completes with Ok(()), proving a
    // max-size body is read, decoded, and handled rather than rejected.
    let pad_len = MAX_CONTROL_REQUEST_BYTES - 4096;
    let request = req(&"x".repeat(pad_len));
    let mut payload = serde_json::to_vec(&request).expect("serialize");
    assert!(
        payload.len() <= MAX_CONTROL_REQUEST_BYTES,
        "test payload {} must stay within the cap {}",
        payload.len(),
        MAX_CONTROL_REQUEST_BYTES
    );
    payload.push(b'\n');
    run_raw(new_state(ProcessStatus::default()), &payload)
        .expect("max-size legitimate request must succeed");
}

// --- #2744: feed-dimension cap raise (fail-on-revert) -------------------

/// The pre-#2744 ceiling. A legitimate feed-heavy apply_snapshot can
/// serialize past this (the #2744 case cited ~500K prefixes ≈ 20+ MiB);
/// such a request must now be ACCEPTED, not rejected. This constant is
/// hard-coded (NOT derived from MAX_CONTROL_REQUEST_BYTES) so the test
/// goes RED if the cap is reverted to 16 MiB.
const OLD_CONTROL_REQUEST_CAP_BYTES: usize = 16 * 1024 * 1024;

#[test]
fn legitimate_feed_above_old_16mib_cap_is_now_accepted() {
    // Build a body comfortably above the OLD 16 MiB ceiling but within the
    // raised cap — this models a large-but-legitimate feed-backed snapshot.
    // It must be read, decoded, and handled (not rejected at the cap).
    assert!(
        OLD_CONTROL_REQUEST_CAP_BYTES < MAX_CONTROL_REQUEST_BYTES,
        "cap must be raised above the old 16 MiB ceiling (got {MAX_CONTROL_REQUEST_BYTES})"
    );
    // 4 MiB above the old cap, with envelope slack below the new cap.
    let pad_len = OLD_CONTROL_REQUEST_CAP_BYTES + 4 * 1024 * 1024;
    assert!(
        pad_len < MAX_CONTROL_REQUEST_BYTES - 4096,
        "test body {pad_len} must stay within the raised cap {MAX_CONTROL_REQUEST_BYTES}"
    );
    let request = req(&"x".repeat(pad_len));
    let mut payload = serde_json::to_vec(&request).expect("serialize");
    assert!(
        payload.len() > OLD_CONTROL_REQUEST_CAP_BYTES,
        "test body {} must exceed the old 16 MiB cap to prove the raise",
        payload.len()
    );
    assert!(
        payload.len() <= MAX_CONTROL_REQUEST_BYTES,
        "test body {} must stay within the raised cap {}",
        payload.len(),
        MAX_CONTROL_REQUEST_BYTES
    );
    payload.push(b'\n');
    // Under the old 16 MiB cap this would be rejected with "exceeds
    // maximum size"; under #2744 it must read/decode/handle cleanly.
    run_raw(new_state(ProcessStatus::default()), &payload)
        .expect("a legitimate feed-heavy request above the old 16 MiB cap must now be accepted");
}

#[test]
fn request_above_new_cap_is_still_rejected() {
    // The DoS guard must still bound allocation: one byte past the raised
    // cap with no terminating newline is rejected before decode.
    let payload = vec![b'a'; MAX_CONTROL_REQUEST_BYTES + 1];
    let err = run_raw(new_state(ProcessStatus::default()), &payload)
        .expect_err("a request past the raised cap must still be rejected");
    assert!(
        err.contains("exceeds maximum size"),
        "expected oversize rejection past the raised cap, got: {err}"
    );
}

// --- dispatcher: ping / status / unknown --------------------------------

#[test]
fn ping_returns_ok_and_attaches_status() {
    let response = run_request(new_state(ProcessStatus::default()), req("ping"));
    assert!(response.ok, "ping should succeed: {}", response.error);
    assert!(
        response.status.is_some(),
        "ping must attach status when suppress_status is false"
    );
}

#[test]
fn unknown_request_type_is_rejected_with_message() {
    let response = run_request(new_state(ProcessStatus::default()), req("does_not_exist"));
    assert!(!response.ok);
    assert!(
        response.error.contains("unknown request type does_not_exist"),
        "unexpected error: {}",
        response.error
    );
}

#[test]
fn suppress_status_omits_status_payload() {
    let mut request = req("ping");
    request.suppress_status = true;
    let response = run_request(new_state(ProcessStatus::default()), request);
    assert!(response.ok);
    assert!(
        response.status.is_none(),
        "suppress_status=true must not attach a status payload"
    );
}

// --- update_ha_state (handler glue; coordinator logic is in ha_tests) ---

#[test]
fn update_ha_state_missing_payload_is_rejected() {
    let response = run_request(new_state(ProcessStatus::default()), req("update_ha_state"));
    assert!(!response.ok);
    assert!(
        response.error.contains("missing HA state"),
        "unexpected error: {}",
        response.error
    );
}

#[test]
fn update_ha_state_populates_status_ha_groups() {
    let groups = vec![HAGroupStatus {
        rg_id: 1,
        active: true,
        ..HAGroupStatus::default()
    }];
    let mut request = req("update_ha_state");
    request.ha_state = Some(HAStateUpdateRequest {
        groups: groups.clone(),
    });
    let response = run_request(new_state(ProcessStatus::default()), request);
    assert!(response.ok, "unexpected error: {}", response.error);
    let status = response.status.expect("status payload");
    // The handler copies the request groups into status.ha_groups, then
    // refresh_status re-reads ha_groups() from the coordinator. The
    // operator-facing rg_id must survive that round-trip — this is the
    // exact status-field-parity surface #1642 regressed in.
    assert_eq!(status.ha_groups.len(), 1, "expected one HA group");
    assert_eq!(status.ha_groups[0].rg_id, 1);
}

// --- set_forwarding_state ----------------------------------------------

#[test]
fn set_forwarding_state_missing_payload_is_rejected() {
    let response = run_request(
        new_state(ProcessStatus::default()),
        req("set_forwarding_state"),
    );
    assert!(!response.ok);
    assert!(
        response.error.contains("missing forwarding state"),
        "unexpected error: {}",
        response.error
    );
}

#[test]
fn set_forwarding_state_arm_without_support_is_rejected() {
    // forwarding_supported defaults false; arming must be refused and
    // forwarding_armed must NOT flip.
    let mut request = req("set_forwarding_state");
    request.forwarding = Some(ForwardingControlRequest { armed: true });
    let state = new_state(ProcessStatus::default());
    let response = run_request(state.clone(), request);
    assert!(!response.ok);
    assert!(
        response.error.contains("not supported"),
        "unexpected error: {}",
        response.error
    );
    assert!(
        !state.lock().expect("state").status.forwarding_armed,
        "rejected arm must not flip forwarding_armed"
    );
}

#[test]
fn set_forwarding_state_unarm_clears_armed_flag() {
    let state = new_state(ProcessStatus {
        forwarding_armed: true,
        capabilities: UserspaceCapabilities {
            forwarding_supported: true,
            unsupported_reasons: Vec::new(),
        },
        ..ProcessStatus::default()
    });
    let mut request = req("set_forwarding_state");
    request.forwarding = Some(ForwardingControlRequest { armed: false });
    let response = run_request(state.clone(), request);
    assert!(response.ok, "unexpected error: {}", response.error);
    assert!(
        !state.lock().expect("state").status.forwarding_armed,
        "unarm must clear forwarding_armed"
    );
}

// --- sync_session -------------------------------------------------------

#[test]
fn sync_session_missing_request_is_rejected() {
    let response = run_request(new_state(ProcessStatus::default()), req("sync_session"));
    assert!(!response.ok);
    assert!(
        response.error.contains("missing session sync request"),
        "unexpected error: {}",
        response.error
    );
}

#[test]
fn sync_session_unknown_operation_is_rejected() {
    let mut request = req("sync_session");
    request.session_sync = Some(SessionSyncRequest {
        operation: "frobnicate".to_string(),
        ..SessionSyncRequest::default()
    });
    let response = run_request(new_state(ProcessStatus::default()), request);
    assert!(!response.ok);
    assert!(
        response
            .error
            .contains("unknown session sync operation frobnicate"),
        "unexpected error: {}",
        response.error
    );
}

#[test]
fn sync_session_delete_with_valid_key_succeeds() {
    let mut request = req("sync_session");
    request.session_sync = Some(SessionSyncRequest {
        operation: "delete".to_string(),
        addr_family: 2, // AF_INET
        protocol: 6,    // TCP
        src_ip: "10.0.0.1".to_string(),
        dst_ip: "10.0.0.2".to_string(),
        src_port: 1234,
        dst_port: 80,
        ..SessionSyncRequest::default()
    });
    let response = run_request(new_state(ProcessStatus::default()), request);
    assert!(response.ok, "unexpected error: {}", response.error);
}

#[test]
fn sync_session_upsert_with_valid_entry_succeeds() {
    let mut request = req("sync_session");
    request.session_sync = Some(SessionSyncRequest {
        operation: "upsert".to_string(),
        addr_family: 2,
        protocol: 6,
        src_ip: "10.0.0.1".to_string(),
        dst_ip: "10.0.0.2".to_string(),
        src_port: 1234,
        dst_port: 80,
        egress_ifindex: 7,
        neighbor_mac: "02:bf:72:01:02:03".to_string(),
        src_mac: "02:bf:72:0a:0b:0c".to_string(),
        ..SessionSyncRequest::default()
    });
    let response = run_request(new_state(ProcessStatus::default()), request);
    assert!(response.ok, "unexpected error: {}", response.error);
}

#[test]
fn sync_session_upsert_with_malformed_mac_is_rejected() {
    let mut request = req("sync_session");
    request.session_sync = Some(SessionSyncRequest {
        operation: "upsert".to_string(),
        addr_family: 2,
        protocol: 6,
        src_ip: "10.0.0.1".to_string(),
        dst_ip: "10.0.0.2".to_string(),
        neighbor_mac: "zz:zz:zz:zz:zz:zz".to_string(),
        ..SessionSyncRequest::default()
    });
    let response = run_request(new_state(ProcessStatus::default()), request);
    assert!(!response.ok);
    assert!(
        response.error.contains("parse neighbor_mac"),
        "unexpected error: {}",
        response.error
    );
}

#[test]
fn sync_session_delete_with_unparseable_ip_is_rejected() {
    let mut request = req("sync_session");
    request.session_sync = Some(SessionSyncRequest {
        operation: "delete".to_string(),
        addr_family: 2,
        protocol: 6,
        src_ip: "not-an-ip".to_string(),
        dst_ip: "10.0.0.2".to_string(),
        ..SessionSyncRequest::default()
    });
    let response = run_request(new_state(ProcessStatus::default()), request);
    assert!(!response.ok);
    assert!(
        response.error.contains("parse src_ip"),
        "unexpected error: {}",
        response.error
    );
}

// --- rebind (#1921) -----------------------------------------------------

#[test]
fn rebind_preserves_synced_sessions() {
    // #1921 regression. `rebind::handle` must NOT call `guard.afxdp.stop()`:
    // that runs `stop_inner(true)`, which clears `coord.workers.records`
    // before `tear_down` samples them (so the 500ms zero-copy teardown
    // quiesce is bypassed -> EBUSY/rebind loop) AND wipes the in-memory
    // synced-session map (mod.rs:488). The reconcile pipeline's `tear_down`
    // owns the worker stop via `stop_inner(false)`, which preserves synced
    // state for replay. This test pins the observable consequence: a synced
    // session installed before a rebind must survive it. If someone re-adds
    // the explicit stop to rebind::handle, the synced map is wiped and this
    // fails.
    //
    // Forwarding must be armed + supported so reconcile_status_bindings takes
    // the real afxdp.reconcile() path (tear_down -> stop_inner(false), which
    // preserves synced state). Its OTHER branch — the `!should_run_afxdp`
    // early return at helpers.rs — itself calls afxdp.stop() (stop_inner(true))
    // and would wipe synced regardless of rebind::handle, so an unarmed status
    // would not isolate the rebind path.
    let state = new_state(ProcessStatus {
        forwarding_armed: true,
        capabilities: UserspaceCapabilities {
            forwarding_supported: true,
            unsupported_reasons: Vec::new(),
        },
        ..ProcessStatus::default()
    });

    let mut upsert = req("sync_session");
    upsert.session_sync = Some(SessionSyncRequest {
        operation: "upsert".to_string(),
        addr_family: 2,
        protocol: 6,
        src_ip: "10.0.0.1".to_string(),
        dst_ip: "10.0.0.2".to_string(),
        src_port: 1234,
        dst_port: 80,
        egress_ifindex: 7,
        neighbor_mac: "02:bf:72:01:02:03".to_string(),
        src_mac: "02:bf:72:0a:0b:0c".to_string(),
        ..SessionSyncRequest::default()
    });
    let upsert_resp = run_request(state.clone(), upsert);
    assert!(upsert_resp.ok, "upsert failed: {}", upsert_resp.error);
    assert!(
        !state
            .lock()
            .unwrap()
            .afxdp
            .snapshot_shared_session_entries()
            .is_empty(),
        "synced session should be present after upsert"
    );

    let rebind_resp = run_request(state.clone(), req("rebind"));
    assert!(rebind_resp.ok, "rebind failed: {}", rebind_resp.error);
    assert!(
        !state
            .lock()
            .unwrap()
            .afxdp
            .snapshot_shared_session_entries()
            .is_empty(),
        "#1921: rebind wiped the synced-session map — did rebind::handle \
         regain a guard.afxdp.stop() call before reconcile_status_bindings?"
    );
}

// --- bump_fib_generation ------------------------------------------------

#[test]
fn bump_fib_generation_missing_snapshot_is_rejected() {
    let response = run_request(
        new_state(ProcessStatus::default()),
        req("bump_fib_generation"),
    );
    assert!(!response.ok);
    assert!(
        response.error.contains("missing snapshot"),
        "unexpected error: {}",
        response.error
    );
}

#[test]
fn bump_fib_generation_updates_status_and_stored_snapshot() {
    use crate::{ConfigSnapshot, CONFIG_SNAPSHOT_PROTOCOL_VERSION};
    let state = new_state(ProcessStatus::default());
    // Seed a stored snapshot via apply_snapshot first.
    {
        let mut request = req("apply_snapshot");
        request.snapshot = Some(ConfigSnapshot {
            version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
            generation: 1,
            fib_generation: 1,
            generated_at: chrono::Utc::now(),
            ..ConfigSnapshot::default()
        });
        let response = run_request(state.clone(), request);
        assert!(response.ok, "seed apply_snapshot: {}", response.error);
    }
    let mut request = req("bump_fib_generation");
    request.snapshot = Some(ConfigSnapshot {
        version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
        fib_generation: 7,
        generated_at: chrono::Utc::now(),
        ..ConfigSnapshot::default()
    });
    let response = run_request(state.clone(), request);
    assert!(response.ok, "unexpected error: {}", response.error);
    let status = response.status.expect("status payload");
    assert_eq!(status.last_fib_generation, 7);
    assert_eq!(
        state
            .lock()
            .expect("state")
            .snapshot
            .as_ref()
            .expect("stored snapshot")
            .fib_generation,
        7,
        "bump must rewrite the stored snapshot's fib_generation"
    );
}

/// #3767 H4: bump_fib_generation must version-gate exactly like
/// apply_snapshot. A mixed-version / corrupt client (version != protocol)
/// must be REJECTED before mutating any validation state — status,
/// stored snapshot, and worker FIB generation all stay at the prior value.
#[test]
fn bump_fib_generation_rejects_wrong_protocol_version() {
    use crate::{ConfigSnapshot, CONFIG_SNAPSHOT_PROTOCOL_VERSION};
    let state = new_state(ProcessStatus::default());
    // Seed a stored snapshot at fib_generation 1.
    {
        let mut request = req("apply_snapshot");
        request.snapshot = Some(ConfigSnapshot {
            version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
            generation: 1,
            fib_generation: 1,
            generated_at: chrono::Utc::now(),
            ..ConfigSnapshot::default()
        });
        assert!(run_request(state.clone(), request).ok);
    }
    let worker_fib_before = state.lock().expect("state").afxdp.fib_generation();
    let mut request = req("bump_fib_generation");
    request.snapshot = Some(ConfigSnapshot {
        version: CONFIG_SNAPSHOT_PROTOCOL_VERSION - 1,
        fib_generation: 7,
        generated_at: chrono::Utc::now(),
        ..ConfigSnapshot::default()
    });
    let response = run_request(state.clone(), request);
    assert!(!response.ok, "wrong-version bump must be rejected");
    assert!(
        response
            .error
            .contains("unsupported snapshot protocol version"),
        "unexpected error: {}",
        response.error
    );
    let guard = state.lock().expect("state");
    assert_eq!(
        guard.status.last_fib_generation, 1,
        "rejected bump must not advance last_fib_generation"
    );
    assert_eq!(
        guard.snapshot.as_ref().expect("stored snapshot").fib_generation,
        1,
        "rejected bump must not rewrite the stored snapshot"
    );
    assert_eq!(
        guard.afxdp.fib_generation(),
        worker_fib_before,
        "rejected bump must not advance the worker FIB generation"
    );
}

/// #3767 H5: bump_fib_generation must refuse a generation ROLLBACK. Flow-
/// cache validation is equality based, so publishing a strictly-lower
/// fib_generation would revive cache entries a prior bump invalidated
/// (stale forwarding after a route withdrawal / failover). The rejected
/// bump must leave status, stored snapshot, and worker FIB generation at
/// the last accepted value.
#[test]
fn bump_fib_generation_rejects_generation_rollback() {
    use crate::{ConfigSnapshot, CONFIG_SNAPSHOT_PROTOCOL_VERSION};
    let state = new_state(ProcessStatus::default());
    // Seed a stored snapshot at fib_generation 5.
    {
        let mut request = req("apply_snapshot");
        request.snapshot = Some(ConfigSnapshot {
            version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
            generation: 1,
            fib_generation: 5,
            generated_at: chrono::Utc::now(),
            ..ConfigSnapshot::default()
        });
        assert!(run_request(state.clone(), request).ok);
    }
    // A forward bump to 7 is accepted (monotone).
    {
        let mut request = req("bump_fib_generation");
        request.snapshot = Some(ConfigSnapshot {
            version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
            fib_generation: 7,
            generated_at: chrono::Utc::now(),
            ..ConfigSnapshot::default()
        });
        assert!(run_request(state.clone(), request).ok);
    }
    // A rollback to 3 (< current 7) must be refused.
    let mut request = req("bump_fib_generation");
    request.snapshot = Some(ConfigSnapshot {
        version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
        fib_generation: 3,
        generated_at: chrono::Utc::now(),
        ..ConfigSnapshot::default()
    });
    let response = run_request(state.clone(), request);
    assert!(!response.ok, "rollback bump must be rejected");
    assert!(
        response.error.contains("fib generation rollback rejected"),
        "unexpected error: {}",
        response.error
    );
    let guard = state.lock().expect("state");
    assert_eq!(
        guard.status.last_fib_generation, 7,
        "rejected rollback must not lower last_fib_generation"
    );
    assert_eq!(
        guard.snapshot.as_ref().expect("stored snapshot").fib_generation,
        7,
        "rejected rollback must not rewrite the stored snapshot"
    );
    assert_eq!(
        guard.afxdp.fib_generation(),
        7,
        "rejected rollback must not revive an old worker FIB generation"
    );
}

/// #3767 M2: an accepted bump_fib_generation must PERSIST the new
/// generation. Previously the handler mutated status + stored snapshot in
/// RAM only (no persist_state), so a route-only overlay bump to gen N left
/// the on-disk state at gen N-1 and a restart booted from a stale FIB
/// generation the control plane already considered applied.
#[test]
fn bump_fib_generation_persists_bumped_generation() {
    use crate::{ConfigSnapshot, CONFIG_SNAPSHOT_PROTOCOL_VERSION};
    let state = new_state(ProcessStatus::default());
    let state_file = unique_state_file("bump-persist");
    // Seed apply persists the state file at fib_generation 1.
    {
        let mut request = req("apply_snapshot");
        request.snapshot = Some(ConfigSnapshot {
            version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
            generation: 1,
            fib_generation: 1,
            generated_at: chrono::Utc::now(),
            ..ConfigSnapshot::default()
        });
        assert!(run_request_on_file(state.clone(), request, &state_file).ok);
    }
    // Route-only bump to 7.
    {
        let mut request = req("bump_fib_generation");
        request.snapshot = Some(ConfigSnapshot {
            version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
            fib_generation: 7,
            generated_at: chrono::Utc::now(),
            ..ConfigSnapshot::default()
        });
        assert!(run_request_on_file(state.clone(), request, &state_file).ok);
    }
    // The on-disk state a restart would boot from must carry gen 7, not the
    // seed apply's stale gen 1.
    let bytes = std::fs::read(&state_file).expect("read persisted state file");
    let persisted: serde_json::Value =
        serde_json::from_slice(&bytes).expect("parse persisted state file");
    assert_eq!(
        persisted["snapshot"]["fib_generation"].as_u64(),
        Some(7),
        "persisted snapshot must carry the bumped fib_generation"
    );
    assert_eq!(
        persisted["status"]["last_fib_generation"].as_u64(),
        Some(7),
        "persisted status must carry the bumped fib_generation"
    );
    let _ = std::fs::remove_file(&state_file);
}

// --- apply_snapshot integrity preflight (#1606 / #1642 class) -----------

#[test]
fn apply_snapshot_missing_payload_is_rejected() {
    let response = run_request(new_state(ProcessStatus::default()), req("apply_snapshot"));
    assert!(!response.ok);
    assert!(
        response.error.contains("missing snapshot"),
        "unexpected error: {}",
        response.error
    );
}

#[test]
fn apply_snapshot_integrity_preflight_rejects_without_mutating_state() {
    use crate::{AddressBookSnapshot, ConfigSnapshot, CONFIG_SNAPSHOT_PROTOCOL_VERSION};
    // A reserved-sentinel address-book id (0) must fail the #1606
    // integrity preflight BEFORE any guard.status / guard.snapshot
    // mutation. The previous good config must survive intact.
    let state = new_state(ProcessStatus::default());
    let mut request = req("apply_snapshot");
    request.snapshot = Some(ConfigSnapshot {
        version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
        generation: 5,
        fib_generation: 5,
        generated_at: chrono::Utc::now(),
        address_books: vec![AddressBookSnapshot {
            id: 0, // reserved sentinel -> AddressBookIdZero
            name: "bad".to_string(),
            ..AddressBookSnapshot::default()
        }],
        ..ConfigSnapshot::default()
    });
    let response = run_request(state.clone(), request);
    assert!(!response.ok);
    assert!(
        response.error.contains("snapshot integrity error"),
        "unexpected error: {}",
        response.error
    );
    let guard = state.lock().expect("state");
    assert!(
        guard.snapshot.is_none(),
        "rejected snapshot must not be stored"
    );
    assert_eq!(
        guard.status.last_snapshot_generation, 0,
        "rejected snapshot must not bump last_snapshot_generation"
    );
    assert_eq!(
        guard.status.last_fib_generation, 0,
        "rejected snapshot must not bump last_fib_generation"
    );
}

/// #3766 fail-closed same-plan refresh at the handler boundary: a
/// same-plan apply_snapshot that PASSES the policy preflight but whose full
/// forwarding build FAILS (here an unparseable interface address) must
/// report ok=false, keep the previously-stored snapshot as the persisted
/// baseline, and NOT advance the reported generation. The disarmed helper
/// (default ProcessStatus) takes the fallible refresh_runtime_snapshot_
/// disarmed leg.
///
/// Fail-on-revert: pre-#3766 the disarmed refresh returned () and the
/// handler unconditionally stored the snapshot, refreshed status, and set
/// persist_state=true — so response.ok stayed true (M1), the rejected
/// snapshot overwrote guard.snapshot as the persisted baseline, and
/// last_snapshot_generation advanced. Every assertion below flips.
#[test]
fn apply_snapshot_same_plan_build_failure_rejects_and_keeps_prior_3766() {
    use crate::{ConfigSnapshot, CONFIG_SNAPSHOT_PROTOCOL_VERSION};

    // A tunnel interface is excluded from the binding plan, so both applies
    // share an (empty) binding-plan key -> the second apply takes the
    // same-plan refresh leg. Only the address differs (NOT a plan-key
    // input): valid on apply 1, unparseable on apply 2.
    let iface = |address: &str| crate::protocol::snapshot::InterfaceSnapshot {
        name: "gr-0/0/0".to_string(),
        linux_name: "gr-0-0-0".to_string(),
        ifindex: 4300,
        tunnel: true,
        hardware_addr: "02:00:00:00:43:00".to_string(),
        addresses: vec![crate::protocol::snapshot::InterfaceAddressSnapshot {
            family: "inet".to_string(),
            address: address.to_string(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let snapshot = |generation: u64, address: &str| ConfigSnapshot {
        version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
        generation,
        fib_generation: generation as u32,
        generated_at: chrono::Utc::now(),
        interfaces: vec![iface(address)],
        ..ConfigSnapshot::default()
    };

    // forwarding_armed defaults false -> the disarmed refresh leg.
    let state = new_state(ProcessStatus::default());

    // Apply 1 (first apply, NOT same-plan): valid baseline, generation 1.
    let mut first = req("apply_snapshot");
    first.snapshot = Some(snapshot(1, "10.0.0.1/24"));
    let response = run_request(state.clone(), first);
    assert!(response.ok, "baseline apply must succeed: {}", response.error);

    // Apply 2 (same-plan refresh leg): unparseable address -> build fails.
    let mut second = req("apply_snapshot");
    second.snapshot = Some(snapshot(2, "10.0.0.0/33"));
    let response = run_request(state.clone(), second);
    assert!(
        !response.ok,
        "a same-plan refresh whose forwarding build fails must report ok=false"
    );
    assert!(
        response.error.contains("snapshot integrity error"),
        "unexpected error: {}",
        response.error
    );

    let guard = state.lock().expect("state");
    assert_eq!(
        guard.snapshot.as_ref().map(|s| s.generation),
        Some(1),
        "the rejected snapshot must not overwrite the persisted baseline"
    );
    assert_eq!(
        guard.status.last_snapshot_generation, 1,
        "rejected same-plan refresh must not bump last_snapshot_generation"
    );
    assert_eq!(
        guard.status.last_fib_generation, 1,
        "rejected same-plan refresh must not bump last_fib_generation"
    );
}

/// Sentinel-OK map pins for the ARMED reconcile legs. The literal mirrors
/// `afxdp::TEST_MAP_PIN_OK` (pub(in crate::afxdp), not reachable here); the
/// `#[cfg(test)]` seam in `OwnedFd::open_bpf_map` short-circuits these to a
/// dummy fd so the reconcile passes `preflight_map_fds` and reaches the
/// fallible forwarding build without a real bpffs.
fn ok_map_pins() -> crate::protocol::snapshot::MapPins {
    crate::protocol::snapshot::MapPins {
        xsk: "test-map-pin-ok://xsk".to_string(),
        heartbeat: "test-map-pin-ok://heartbeat".to_string(),
        sessions: "test-map-pin-ok://sessions".to_string(),
        ..Default::default()
    }
}

fn forwarding_caps() -> UserspaceCapabilities {
    UserspaceCapabilities {
        forwarding_supported: true,
        ..Default::default()
    }
}

/// A zoned, non-tunnel DATA interface — the binding-plan candidate the
/// tunnel helper is NOT. `include_userspace_binding_interface` admits it
/// (non-empty data zone, non-tunnel, `ge-*` name), so `replan_queues`
/// plans exactly one worker for it (rx_queues=1 -> queue_count=1, ifindex>0
/// -> registered). Changing `name`/`linux_name`/`ifindex` between two
/// snapshots therefore CHANGES the binding plan key, selecting the
/// FULL-APPLY leg (not the address-only same-plan leg the tunnel helper
/// drives). A valid inet address keeps the pre-teardown forwarding build
/// green so the reconcile REACHES the post-teardown worker spawn.
fn data_iface_6140(name: &str, linux_name: &str, ifindex: i32) -> crate::protocol::snapshot::InterfaceSnapshot {
    crate::protocol::snapshot::InterfaceSnapshot {
        name: name.to_string(),
        linux_name: linux_name.to_string(),
        zone: "trust".to_string(),
        ifindex,
        rx_queues: 1,
        hardware_addr: "02:00:00:00:00:01".to_string(),
        addresses: vec![crate::protocol::snapshot::InterfaceAddressSnapshot {
            family: "inet".to_string(),
            address: "10.0.1.1/24".to_string(),
            ..Default::default()
        }],
        ..Default::default()
    }
}

/// The `trust` zone the data interface references. The forwarding build
/// REFUSES an interface whose zone is absent from the zone table (it will
/// not fail open by collapsing to the unknown zone 0), so the snapshot must
/// declare it for the pre-teardown build to succeed and the reconcile to
/// reach the worker spawn.
fn trust_zone_6140() -> crate::protocol::snapshot::ZoneSnapshot {
    crate::protocol::snapshot::ZoneSnapshot {
        name: "trust".to_string(),
        id: 1,
        ..Default::default()
    }
}

/// A tunnel interface is excluded from the binding plan, so applies that
/// differ only in this interface's ADDRESS share a plan key. `address`
/// controls whether the forwarding build succeeds ("10.0.0.1/24") or fails
/// ("10.0.0.0/33", unparseable — a NON-policy integrity fault).
fn tunnel_iface_3789(address: &str) -> crate::protocol::snapshot::InterfaceSnapshot {
    crate::protocol::snapshot::InterfaceSnapshot {
        name: "gr-0/0/0".to_string(),
        linux_name: "gr-0-0-0".to_string(),
        ifindex: 4300,
        tunnel: true,
        hardware_addr: "02:00:00:00:43:00".to_string(),
        addresses: vec![crate::protocol::snapshot::InterfaceAddressSnapshot {
            family: "inet".to_string(),
            address: address.to_string(),
            ..Default::default()
        }],
        ..Default::default()
    }
}

/// #3789 fail-closed FULL-APPLY leg (the non-same-plan branch, the #2484
/// domain out of #3766's same-plan-refresh scope): an ARMED
/// forwarding-supported helper's first apply takes the else full-apply
/// leg -> reconcile_status_bindings -> the fallible afxdp.reconcile. A
/// snapshot that passes the policy preflight but whose forwarding build
/// FAILS (unparseable interface address) must report ok=false, NOT store
/// the rejected snapshot as the boot baseline, and NOT advance the
/// reported generation.
///
/// Fail-on-revert: before #3789 `afxdp.reconcile` returned () and the
/// handler unconditionally stored the snapshot, refreshed status, and set
/// persist_state=true -> response.ok stayed true (M1), the rejected
/// snapshot became guard.snapshot, and last_snapshot_generation advanced.
/// Every assertion below flips.
#[test]
fn apply_snapshot_full_reconcile_build_failure_rejects_and_keeps_prior_3789() {
    use crate::{ConfigSnapshot, CONFIG_SNAPSHOT_PROTOCOL_VERSION};

    // Armed so the reconcile takes the real afxdp.reconcile path (not the
    // disarmed stop arm). forwarding_supported comes from the snapshot.
    let state = new_state(ProcessStatus {
        forwarding_armed: true,
        ..ProcessStatus::default()
    });

    let mut request = req("apply_snapshot");
    request.snapshot = Some(ConfigSnapshot {
        version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
        generation: 5,
        fib_generation: 5,
        generated_at: chrono::Utc::now(),
        capabilities: forwarding_caps(),
        map_pins: ok_map_pins(),
        interfaces: vec![tunnel_iface_3789("10.0.0.0/33")],
        ..ConfigSnapshot::default()
    });

    let response = run_request(state.clone(), request);
    assert!(
        !response.ok,
        "a full-apply reconcile whose forwarding build fails must report ok=false"
    );
    assert!(
        response.error.contains("snapshot integrity error"),
        "unexpected error: {}",
        response.error
    );

    let guard = state.lock().expect("state");
    assert!(
        guard.snapshot.is_none(),
        "rejected snapshot must not be stored as the boot baseline"
    );
    assert_eq!(
        guard.status.last_snapshot_generation, 0,
        "rejected full-apply must not bump last_snapshot_generation"
    );
    assert_eq!(
        guard.status.last_fib_generation, 0,
        "rejected full-apply must not bump last_fib_generation"
    );
}

/// #3789 fail-closed SAME-PLAN NEEDS-RECONCILE leg: when the prior apply
/// deferred workers, the next same-plan apply reconciles the deferred
/// bindings via afxdp.reconcile (NOT the same-plan refresh leg #3766
/// fixed). A build failure on that reconcile must restore the prior
/// (deferred) snapshot, report ok=false, and NOT advance the generation.
///
/// Fail-on-revert: pre-#3789 this leg stored the snapshot then called
/// reconcile_status_bindings (returning ()) and fell through to
/// refresh_status + persist_state=true with ok=true — so the rejected
/// gen-2 snapshot overwrote the gen-1 baseline and last_snapshot_generation
/// advanced to 2. The generation/defer_workers assertions flip.
#[test]
fn apply_snapshot_same_plan_needs_reconcile_build_failure_rejects_and_keeps_prior_3789() {
    use crate::{ConfigSnapshot, CONFIG_SNAPSHOT_PROTOCOL_VERSION};

    // Prior snapshot deferred workers -> previous_defer_workers=true makes
    // same_plan_apply_needs_binding_reconcile return true on the next
    // (non-defer) same-plan apply. Tunnel-only interface set -> the plan
    // key is address-independent, so gen-1 and gen-2 are same-plan.
    let prior = ConfigSnapshot {
        version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
        generation: 1,
        fib_generation: 1,
        generated_at: chrono::Utc::now(),
        defer_workers: true,
        capabilities: forwarding_caps(),
        map_pins: ok_map_pins(),
        interfaces: vec![tunnel_iface_3789("10.0.0.1/24")],
        ..ConfigSnapshot::default()
    };

    // Armed + supported + one runnable binding (registered, ifindex>0) so
    // the needs-reconcile runnable_bindings>0 gate holds.
    let status = ProcessStatus {
        forwarding_armed: true,
        capabilities: forwarding_caps(),
        last_snapshot_generation: 1,
        last_fib_generation: 1,
        bindings: vec![BindingStatus {
            slot: 0,
            registered: true,
            ifindex: 10,
            ..BindingStatus::default()
        }],
        ..ProcessStatus::default()
    };

    let state = Arc::new(Mutex::new(ServerState {
        status,
        snapshot: Some(prior),
        afxdp: afxdp::Coordinator::new(),
        state_writer: Arc::new(StateWriter::new()),
    }));

    // New same-plan apply: defer_workers=false, unparseable address -> the
    // deferred-binding reconcile's forwarding build fails.
    let mut request = req("apply_snapshot");
    request.snapshot = Some(ConfigSnapshot {
        version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
        generation: 2,
        fib_generation: 2,
        generated_at: chrono::Utc::now(),
        defer_workers: false,
        capabilities: forwarding_caps(),
        map_pins: ok_map_pins(),
        interfaces: vec![tunnel_iface_3789("10.0.0.0/33")],
        ..ConfigSnapshot::default()
    });

    let response = run_request(state.clone(), request);
    assert!(
        !response.ok,
        "a same-plan needs-reconcile apply whose build fails must report ok=false"
    );
    assert!(
        response.error.contains("snapshot integrity error"),
        "unexpected error: {}",
        response.error
    );

    let guard = state.lock().expect("state");
    assert_eq!(
        guard.snapshot.as_ref().map(|s| s.generation),
        Some(1),
        "the rejected snapshot must not overwrite the persisted baseline"
    );
    assert!(
        guard.snapshot.as_ref().is_some_and(|s| s.defer_workers),
        "the prior (deferred) snapshot must be restored intact"
    );
    assert_eq!(
        guard.status.last_snapshot_generation, 1,
        "rejected same-plan needs-reconcile must not bump last_snapshot_generation"
    );
    assert_eq!(
        guard.status.last_fib_generation, 1,
        "rejected same-plan needs-reconcile must not bump last_fib_generation"
    );
}

/// #4952 POST-TEARDOWN worker-spawn failure fails closed and does NOT
/// persist. The same-plan-needs-reconcile leg reconciles the ALREADY
/// registered binding directly (no replan_queues), so with all mandatory
/// pins open and a buildable snapshot the reconcile clears the pre-teardown
/// integrity legs, tears down the old workers, and REACHES the fallible
/// worker spawn. The per-instance `force_worker_spawn_fail` seam forces that
/// spawn to return EAGAIN/ENOMEM (a real pthread_create failure is not
/// provokable in-process), leaving the queue set with NO XSK-bound worker.
///
/// The handler MUST: (a) report ok=false with a descriptive error, (b) NOT
/// persist the broken snapshot as the boot baseline (persist_state stays
/// false -> the state file is never written), and (c) the coordinator's
/// `last_reconcile_stage` MUST retain the `spawn_worker_failed:..`
/// descriptor (NOT `spawned:workers=..`).
///
/// Fail-on-revert: before #4952 `bring_up_workers` returned () and swallowed
/// the spawn error (overwriting the stage with `spawned:..`), so
/// `afxdp.reconcile` returned Ok, the handler acked ok=true, PERSISTED the
/// snapshot (the state file appears), and advanced the stored baseline to
/// gen 2. Every assertion below flips.
#[test]
fn post_teardown_spawn_failure_fails_closed_no_persist_4952() {
    use crate::{ConfigSnapshot, CONFIG_SNAPSHOT_PROTOCOL_VERSION};

    // Prior snapshot deferred workers -> previous_defer_workers=true makes
    // same_plan_apply_needs_binding_reconcile return true on the next
    // (non-defer) same-plan apply. Tunnel-only interface set -> the plan
    // key is address-independent, so gen-1 and gen-2 are same-plan.
    let prior = ConfigSnapshot {
        version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
        generation: 1,
        fib_generation: 1,
        generated_at: chrono::Utc::now(),
        defer_workers: true,
        capabilities: forwarding_caps(),
        map_pins: ok_map_pins(),
        interfaces: vec![tunnel_iface_3789("10.0.0.1/24")],
        ..ConfigSnapshot::default()
    };

    // Armed + supported + one runnable binding (registered, ifindex>0) so
    // the needs-reconcile gate fires AND bring_up plans exactly one worker.
    let status = ProcessStatus {
        forwarding_armed: true,
        capabilities: forwarding_caps(),
        last_snapshot_generation: 1,
        last_fib_generation: 1,
        bindings: vec![BindingStatus {
            slot: 0,
            registered: true,
            ifindex: 10,
            ..BindingStatus::default()
        }],
        ..ProcessStatus::default()
    };

    let state = Arc::new(Mutex::new(ServerState {
        status,
        snapshot: Some(prior),
        afxdp: afxdp::Coordinator::new(),
        state_writer: Arc::new(StateWriter::new()),
    }));

    // Force the single planned worker's spawn to fail on the post-teardown
    // path (the destructive step the fix guards).
    state.lock().expect("state").afxdp.force_worker_spawn_fail = 1;

    // New same-plan apply: defer_workers=false, VALID address so the
    // forwarding build SUCCEEDS and the reconcile reaches the worker spawn.
    let mut request = req("apply_snapshot");
    request.snapshot = Some(ConfigSnapshot {
        version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
        generation: 2,
        fib_generation: 2,
        generated_at: chrono::Utc::now(),
        defer_workers: false,
        capabilities: forwarding_caps(),
        map_pins: ok_map_pins(),
        interfaces: vec![tunnel_iface_3789("10.0.0.1/24")],
        ..ConfigSnapshot::default()
    });

    let state_file = unique_state_file("spawn_fail_4952");
    assert!(
        !std::path::Path::new(&state_file).exists(),
        "precondition: state file must not exist before the request"
    );

    let response = run_request_on_file(state.clone(), request, &state_file);

    // (a) fail closed with a non-empty, descriptive error.
    assert!(
        !response.ok,
        "a post-teardown worker-spawn failure must report ok=false"
    );
    assert!(
        !response.error.is_empty() && response.error.contains("worker spawn failed"),
        "unexpected error: {}",
        response.error
    );

    // (b) persist_state was NOT set -> the state file was never written.
    assert!(
        !std::path::Path::new(&state_file).exists(),
        "a post-teardown spawn failure must NOT persist the broken snapshot as the boot baseline"
    );

    let guard = state.lock().expect("state");
    // The prior (gen 1, deferred) snapshot is still the boot baseline.
    assert_eq!(
        guard.snapshot.as_ref().map(|s| s.generation),
        Some(1),
        "the rejected snapshot must not overwrite the persisted baseline"
    );
    assert!(
        guard.snapshot.as_ref().is_some_and(|s| s.defer_workers),
        "the prior (deferred) snapshot must be restored intact"
    );
    assert_eq!(
        guard.status.last_snapshot_generation, 1,
        "rejected apply must not bump last_snapshot_generation"
    );
    // (c) last_reconcile_stage retains the spawn_worker_failed descriptor.
    assert!(
        matches!(
            guard.afxdp.last_reconcile_stage,
            crate::afxdp::ReconcileStage::SpawnWorkerFailed { .. }
        ),
        "the spawn-failure stage must be preserved (not the Spawned variant), got {:?}",
        guard.afxdp.last_reconcile_stage
    );
    // #6244: legacy operator string preserved byte-for-byte.
    assert!(
        guard
            .afxdp
            .last_reconcile_stage
            .to_string()
            .starts_with("spawn_worker_failed:")
    );

    let _ = std::fs::remove_file(&state_file);
}

/// #6140 (test-coverage follow-up to #4952): a dedicated regression for the
/// FULL-APPLY leg (`handlers/snapshot.rs` else branch, ~:341-369), the
/// PLAN-CHANGE path. The merged #4952 gates cover the coordinator
/// (`reconcile_post_teardown_worker_spawn_failure_fails_closed_4952`) and the
/// SAME-PLAN-needs_reconcile handler leg
/// (`post_teardown_spawn_failure_fails_closed_no_persist_4952`, ~:208). The
/// full-apply arm's WorkerSpawn handling (~:342-369) was covered only
/// TRANSITIVELY — verified equivalent to the same-plan arm by inspection, but
/// with no test asserting the full-apply leg SPECIFICALLY fails closed. This
/// closes that gap.
///
/// The two legs are selected by the binding PLAN KEY: same key -> same-plan
/// leg; changed key -> full-apply leg. This test installs a prior snapshot
/// whose sole binding interface (`ge-0/0/1`, ifindex 11) differs from the new
/// snapshot's (`ge-0/0/2`, ifindex 12), so `snapshot_binding_plan_key` differs
/// and `same_plan` is FALSE — the else full-apply branch runs `replan_queues`
/// (installing the NEW interface as the binding set), then
/// `reconcile_status_bindings` -> `afxdp.reconcile`. All mandatory pins open
/// and the address parses, so the reconcile clears the pre-teardown integrity
/// legs, tears down, and REACHES the fallible worker spawn. The
/// `force_worker_spawn_fail` seam forces that (unprovokable in-process)
/// EAGAIN/ENOMEM, leaving the queue set with NO XSK-bound worker.
///
/// The full-apply WorkerSpawn arm MUST: (a) report ok=false with a descriptive
/// error, (b) NOT persist the broken snapshot as the boot baseline
/// (persist_state stays false -> the state file is never written), (c) roll
/// the in-memory baseline back to the prior good snapshot + status generation
/// (guard.snapshot gen 1, last_snapshot/fib_generation 1), and (d) preserve the
/// coordinator's `spawn_worker_failed:..` stage (NOT overwritten with
/// `spawned:..`).
///
/// LEG PROOF: two observables pin this to the full-apply leg, not same-plan.
/// (1) `same_binding_plan(prior, next)` is asserted FALSE up front — the
/// handler's `same_plan` gate reads exactly that key, so a false key forces
/// the else branch. (2) The full-apply leg is the ONLY leg that runs
/// `replan_queues`, which rewrites `status.bindings` to the NEW snapshot's
/// interface; the WorkerSpawn arm deliberately does NOT restore
/// `existing_bindings`, so after the failure the surviving binding carries
/// `ge-0-0-2`/ifindex 12 (the new plan), which the same-plan leg — never
/// calling `replan_queues` — could not produce.
///
/// Fail-on-revert: neutralize the full-apply WorkerSpawn arm (drop the
/// ok=false + no-persist + baseline-rollback so it falls through to
/// refresh_status + persist_state=true with ok=true, exactly as pre-#4952
/// `bring_up_workers` swallowed the spawn error). Assertions (a)/(b)/(c)/(d)
/// all flip as ASSERTION failures.
#[test]
fn full_apply_post_teardown_spawn_failure_fails_closed_no_persist_6140() {
    use crate::{ConfigSnapshot, CONFIG_SNAPSHOT_PROTOCOL_VERSION};

    // Prior snapshot: one binding interface (ge-0/0/1, ifindex 11). NOT
    // deferred — a normal prior apply. Its only role here is to make
    // guard.snapshot Some with a DISTINCT plan key.
    let prior = ConfigSnapshot {
        version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
        generation: 1,
        fib_generation: 1,
        generated_at: chrono::Utc::now(),
        defer_workers: false,
        capabilities: forwarding_caps(),
        map_pins: ok_map_pins(),
        interfaces: vec![data_iface_6140("ge-0/0/1", "ge-0-0-1", 11)],
        zones: vec![trust_zone_6140()],
        ..ConfigSnapshot::default()
    };

    // New apply: a DIFFERENT binding interface (ge-0/0/2, ifindex 12) -> the
    // plan key changes -> the full-apply (non-same-plan) leg is taken.
    let next = ConfigSnapshot {
        version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
        generation: 2,
        fib_generation: 2,
        generated_at: chrono::Utc::now(),
        defer_workers: false,
        capabilities: forwarding_caps(),
        map_pins: ok_map_pins(),
        interfaces: vec![data_iface_6140("ge-0/0/2", "ge-0-0-2", 12)],
        zones: vec![trust_zone_6140()],
        ..ConfigSnapshot::default()
    };

    // LEG PROOF (1): a differing plan key is precisely what selects the
    // full-apply leg. `same_plan` in the handler reads this same key.
    assert!(
        !super::helpers::same_binding_plan(&prior, &next),
        "the prior/new binding plan keys MUST differ so the handler takes the \
         full-apply (non-same-plan) leg"
    );

    // Armed + supported so `should_run_afxdp` holds and the reconcile takes
    // the real afxdp.reconcile path (not the disarmed stop arm).
    let status = ProcessStatus {
        forwarding_armed: true,
        capabilities: forwarding_caps(),
        last_snapshot_generation: 1,
        last_fib_generation: 1,
        ..ProcessStatus::default()
    };

    let state = Arc::new(Mutex::new(ServerState {
        status,
        snapshot: Some(prior),
        afxdp: afxdp::Coordinator::new(),
        state_writer: Arc::new(StateWriter::new()),
    }));

    // Force the single planned worker's spawn to fail on the post-teardown
    // path (the destructive step the fix guards).
    state.lock().expect("state").afxdp.force_worker_spawn_fail = 1;

    let mut request = req("apply_snapshot");
    request.snapshot = Some(next);

    let state_file = unique_state_file("full_apply_spawn_fail_6140");
    assert!(
        !std::path::Path::new(&state_file).exists(),
        "precondition: state file must not exist before the request"
    );

    let response = run_request_on_file(state.clone(), request, &state_file);

    // (a) fail closed with a non-empty, descriptive error.
    assert!(
        !response.ok,
        "a post-teardown worker-spawn failure on the full-apply leg must report ok=false"
    );
    assert!(
        !response.error.is_empty() && response.error.contains("worker spawn failed"),
        "unexpected error: {}",
        response.error
    );

    // (b) persist_state was NOT set -> the state file was never written.
    assert!(
        !std::path::Path::new(&state_file).exists(),
        "a full-apply post-teardown spawn failure must NOT persist the broken snapshot"
    );

    let guard = state.lock().expect("state");
    // (c) the prior (gen 1) snapshot is still the boot baseline; the reported
    // generation rolled back.
    assert_eq!(
        guard.snapshot.as_ref().map(|s| s.generation),
        Some(1),
        "the rejected snapshot must not overwrite the persisted baseline"
    );
    assert_eq!(
        guard.snapshot.as_ref().map(|s| s.interfaces[0].linux_name.as_str()),
        Some("ge-0-0-1"),
        "the prior snapshot (ge-0-0-1) must be restored intact as the baseline"
    );
    assert_eq!(
        guard.status.last_snapshot_generation, 1,
        "rejected full-apply must not bump last_snapshot_generation"
    );
    assert_eq!(
        guard.status.last_fib_generation, 1,
        "rejected full-apply must not bump last_fib_generation"
    );
    // (d) last_reconcile_stage retains the spawn_worker_failed descriptor.
    assert!(
        matches!(
            guard.afxdp.last_reconcile_stage,
            crate::afxdp::ReconcileStage::SpawnWorkerFailed { .. }
        ),
        "the spawn-failure stage must be preserved (not the Spawned variant), got {:?}",
        guard.afxdp.last_reconcile_stage
    );
    // #6244: legacy operator string preserved byte-for-byte.
    assert!(
        guard
            .afxdp
            .last_reconcile_stage
            .to_string()
            .starts_with("spawn_worker_failed:")
    );
    // LEG PROOF (2): only the full-apply leg runs replan_queues, which
    // rewrites status.bindings to the NEW snapshot's interface. The
    // WorkerSpawn arm does NOT restore existing_bindings, so the surviving
    // binding carries the new plan (ge-0-0-2 / ifindex 12) — an outcome the
    // same-plan leg (never calling replan_queues) cannot produce.
    assert_eq!(guard.status.bindings.len(), 1, "one worker was planned");
    assert_eq!(
        guard.status.bindings[0].interface, "ge-0-0-2",
        "the full-apply leg must have replanned onto the NEW snapshot's interface"
    );
    assert_eq!(
        guard.status.bindings[0].ifindex, 12,
        "the replanned binding must carry the new interface's ifindex"
    );

    let _ = std::fs::remove_file(&state_file);
}

/// #5143: the FULL-APPLY handler leg must fail closed on a POST-SPAWN in-thread
/// worker BIND failure — distinct from the #4952/#6140 SPAWN failure. A worker
/// that spawns but binds an INCOMPLETE queue set (a live-but-unbound worker
/// heartbeating past a broken bring-up) surfaces as
/// `ReconcileError::WorkerBindIncomplete`, which the handler special-cases the
/// SAME way as `WorkerSpawn`: report ok=false + "worker bring-up failed after
/// teardown", NOT persist the broken snapshot as the boot baseline, and roll
/// the in-memory baseline back to the prior good snapshot + generation. The
/// `force_worker_bind_incomplete` seam spawns a joinable stub worker that
/// reports a bound set missing one planned slot (a real XSK cannot bind
/// in-process), which the readiness barrier catches and fails closed.
///
/// Fail-on-revert: neutralize the barrier (the worker binds partially but the
/// reconcile commits Ok) OR drop the handler's `WorkerBindIncomplete` arm (so
/// it falls through to refresh_status + persist_state=true with ok=true).
/// Assertions (a)/(b)/(c)/(d) all flip as ASSERTION failures.
#[test]
fn full_apply_post_spawn_inthread_bind_failure_fails_closed_no_persist_5143() {
    use crate::{ConfigSnapshot, CONFIG_SNAPSHOT_PROTOCOL_VERSION};

    // Prior snapshot: one binding interface (ge-0/0/1, ifindex 11). Its only
    // role is to make guard.snapshot Some with a DISTINCT plan key so the new
    // apply takes the full-apply (non-same-plan) leg.
    let prior = ConfigSnapshot {
        version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
        generation: 1,
        fib_generation: 1,
        generated_at: chrono::Utc::now(),
        defer_workers: false,
        capabilities: forwarding_caps(),
        map_pins: ok_map_pins(),
        interfaces: vec![data_iface_6140("ge-0/0/1", "ge-0-0-1", 11)],
        zones: vec![trust_zone_6140()],
        ..ConfigSnapshot::default()
    };

    // New apply: a DIFFERENT binding interface (ge-0/0/2, ifindex 12) -> the
    // plan key changes -> the full-apply leg runs.
    let next = ConfigSnapshot {
        version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
        generation: 2,
        fib_generation: 2,
        generated_at: chrono::Utc::now(),
        defer_workers: false,
        capabilities: forwarding_caps(),
        map_pins: ok_map_pins(),
        interfaces: vec![data_iface_6140("ge-0/0/2", "ge-0-0-2", 12)],
        zones: vec![trust_zone_6140()],
        ..ConfigSnapshot::default()
    };

    assert!(
        !super::helpers::same_binding_plan(&prior, &next),
        "the prior/new binding plan keys MUST differ so the handler takes the \
         full-apply (non-same-plan) leg"
    );

    let status = ProcessStatus {
        forwarding_armed: true,
        capabilities: forwarding_caps(),
        last_snapshot_generation: 1,
        last_fib_generation: 1,
        ..ProcessStatus::default()
    };

    let state = Arc::new(Mutex::new(ServerState {
        status,
        snapshot: Some(prior),
        afxdp: afxdp::Coordinator::new(),
        state_writer: Arc::new(StateWriter::new()),
    }));

    // Force the single planned worker to SPAWN but report an INCOMPLETE bound
    // set (the post-spawn in-thread bind failure the fix guards).
    state
        .lock()
        .expect("state")
        .afxdp
        .force_worker_bind_incomplete = 1;

    let mut request = req("apply_snapshot");
    request.snapshot = Some(next);

    let state_file = unique_state_file("full_apply_bind_incomplete_5143");
    assert!(
        !std::path::Path::new(&state_file).exists(),
        "precondition: state file must not exist before the request"
    );

    let response = run_request_on_file(state.clone(), request, &state_file);

    // (a) fail closed with a descriptive post-teardown bring-up error.
    assert!(
        !response.ok,
        "a post-spawn in-thread bind failure on the full-apply leg must report ok=false"
    );
    assert!(
        response.error.contains("worker bind incomplete"),
        "unexpected error: {}",
        response.error
    );

    // (b) persist_state was NOT set -> the state file was never written.
    assert!(
        !std::path::Path::new(&state_file).exists(),
        "a full-apply post-spawn bind failure must NOT persist the broken snapshot"
    );

    let guard = state.lock().expect("state");
    // (d) the prior (gen 1) snapshot is still the boot baseline; the reported
    // generation rolled back.
    assert_eq!(
        guard.snapshot.as_ref().map(|s| s.generation),
        Some(1),
        "the rejected snapshot must not overwrite the persisted baseline"
    );
    assert_eq!(
        guard.status.last_snapshot_generation, 1,
        "rejected full-apply must not bump last_snapshot_generation"
    );
    assert_eq!(
        guard.status.last_fib_generation, 1,
        "rejected full-apply must not bump last_fib_generation"
    );
    // (c) the coordinator recorded the bind-incomplete verdict (not a spawn
    // success) and stopped/joined the partially-bound worker.
    assert!(
        matches!(
            guard.afxdp.last_reconcile_stage,
            crate::afxdp::ReconcileStage::WorkerBindIncomplete(_)
        ),
        "the bind-incomplete stage must be preserved (not the Spawned variant), got {:?}",
        guard.afxdp.last_reconcile_stage
    );
    // #6244: legacy operator string preserved byte-for-byte.
    assert!(
        guard
            .afxdp
            .last_reconcile_stage
            .to_string()
            .starts_with("worker_bind_incomplete:")
    );

    let _ = std::fs::remove_file(&state_file);
}

// --- apply_snapshot deferred-activation integrity build (#5171) ---------

/// #5171 fail-closed DEFERRED apply — MISSING MANDATORY MAP PIN: a
/// `defer_workers=true` apply skips worker bring-up (RETH MAC pending) but
/// still ACKs + persists the snapshot as the boot baseline. Before #5171 it
/// did so WITHOUT the mandatory-map + forwarding integrity build the
/// non-defer reconcile path runs, so a snapshot with NO xsk map pin was
/// acked ok=true and persisted, only to fail-OPEN at the later deferred
/// bring-up. The new `validate_snapshot_buildable` gate rejects it up front.
///
/// The helper is DISARMED (forwarding_armed=false), the realistic deferred
/// state — arming follows the deferred worker bring-up. This proves the gate
/// runs independent of arm state (a disarmed defer apply cannot borrow
/// reconcile_status_bindings, which would take the disarmed stop path with
/// no integrity build).
///
/// RED-on-revert: without the validate call the defer branch prunes, swaps
/// the snapshot in, replans, skips the spawn, refreshes, and sets
/// persist_state — acking ok=true and persisting the non-buildable config.
/// Every assertion below flips.
#[test]
fn apply_snapshot_defer_workers_missing_map_pin_fails_closed_5171() {
    use crate::{ConfigSnapshot, CONFIG_SNAPSHOT_PROTOCOL_VERSION};

    // Disarmed helper (the realistic deferred state). No prior snapshot.
    let state = new_state(ProcessStatus::default());

    let mut request = req("apply_snapshot");
    request.snapshot = Some(ConfigSnapshot {
        version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
        generation: 5,
        fib_generation: 5,
        generated_at: chrono::Utc::now(),
        capabilities: forwarding_caps(),
        // map_pins default -> empty xsk -> mandatory-map integrity failure.
        interfaces: vec![tunnel_iface_3789("10.0.0.1/24")], // config itself valid
        defer_workers: true,
        ..ConfigSnapshot::default()
    });

    let response = run_request(state.clone(), request);
    assert!(
        !response.ok,
        "a deferred apply of a config with a MISSING mandatory map pin must fail closed"
    );
    assert!(
        response.error.contains("missing_xsk_pin"),
        "unexpected error: {}",
        response.error
    );

    let guard = state.lock().expect("state");
    assert!(
        guard.snapshot.is_none(),
        "rejected deferred snapshot must not be stored as the boot baseline"
    );
    assert_eq!(
        guard.status.last_snapshot_generation, 0,
        "rejected deferred apply must not bump last_snapshot_generation"
    );
    assert_eq!(
        guard.status.last_fib_generation, 0,
        "rejected deferred apply must not bump last_fib_generation"
    );
}

/// #5171 fail-closed DEFERRED apply — FORWARDING-BUILD INTEGRITY FAULT: a
/// `defer_workers=true` apply whose mandatory pins all open but whose full
/// forwarding build FAILS (here an unparseable interface address) must fail
/// closed too — the build fault the pre-#5171 defer path never surfaced.
///
/// RED-on-revert: as above, without the gate the defer branch acks ok=true
/// and persists the non-buildable config.
#[test]
fn apply_snapshot_defer_workers_forwarding_integrity_fails_closed_5171() {
    use crate::{ConfigSnapshot, CONFIG_SNAPSHOT_PROTOCOL_VERSION};

    let state = new_state(ProcessStatus::default());

    let mut request = req("apply_snapshot");
    request.snapshot = Some(ConfigSnapshot {
        version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
        generation: 7,
        fib_generation: 7,
        generated_at: chrono::Utc::now(),
        capabilities: forwarding_caps(),
        map_pins: ok_map_pins(), // all mandatory pins open
        interfaces: vec![tunnel_iface_3789("10.0.0.0/33")], // unparseable addr
        defer_workers: true,
        ..ConfigSnapshot::default()
    });

    let response = run_request(state.clone(), request);
    assert!(
        !response.ok,
        "a deferred apply whose forwarding build fails must fail closed"
    );
    assert!(
        response.error.contains("snapshot integrity error"),
        "unexpected error: {}",
        response.error
    );

    let guard = state.lock().expect("state");
    assert!(
        guard.snapshot.is_none(),
        "rejected deferred snapshot must not be stored as the boot baseline"
    );
    assert_eq!(
        guard.status.last_snapshot_generation, 0,
        "rejected deferred apply must not bump last_snapshot_generation"
    );
}

/// #5171 defer semantics preserved: a `defer_workers=true` apply of a
/// fully-BUILDABLE config (all mandatory pins open, valid addresses) still
/// applies + persists + ACKs ok=true, and STILL does NOT spawn workers
/// (`debug_reconcile_calls` stays 0). The gate adds integrity VALIDATION,
/// not activation.
#[test]
fn apply_snapshot_defer_workers_valid_config_applies_without_spawning_5171() {
    use crate::{ConfigSnapshot, CONFIG_SNAPSHOT_PROTOCOL_VERSION};

    let state = new_state(ProcessStatus::default());

    let mut request = req("apply_snapshot");
    request.snapshot = Some(ConfigSnapshot {
        version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
        generation: 4,
        fib_generation: 4,
        generated_at: chrono::Utc::now(),
        capabilities: forwarding_caps(),
        map_pins: ok_map_pins(),
        interfaces: vec![tunnel_iface_3789("10.0.0.1/24")], // valid, buildable
        defer_workers: true,
        ..ConfigSnapshot::default()
    });

    let response = run_request(state.clone(), request);
    assert!(
        response.ok,
        "a deferred apply of a fully-buildable config must succeed: {}",
        response.error
    );
    let status = response.status.expect("status response");
    assert_eq!(
        status.debug_reconcile_calls, 0,
        "the deferred apply must NOT run the worker-spawning reconcile"
    );

    let guard = state.lock().expect("state");
    assert_eq!(
        guard.snapshot.as_ref().map(|s| s.generation),
        Some(4),
        "the buildable deferred snapshot must be stored as the boot baseline"
    );
    assert!(
        guard.snapshot.as_ref().is_some_and(|s| s.defer_workers),
        "the stored deferred snapshot keeps defer_workers set"
    );
    assert_eq!(
        guard.status.last_snapshot_generation, 4,
        "the accepted deferred apply advances last_snapshot_generation"
    );
}

// --- apply_snapshot generation monotonicity (#5169) ---------------------

/// #5169 fail-CLOSED: a ROLLED-BACK apply_snapshot generation must be refused.
/// The FULL apply path published (config_generation, fib_generation) VERBATIM
/// with no monotonicity gate, so re-publishing a pair a later apply already
/// superseded revived flow-cache entries that later generation invalidated —
/// a stale cached ALLOW (fail-open), because flow-cache validation is EQUALITY
/// based on the pair. This mirrors the #3767 H5 rollback guard on bump_fib.
///
/// RED-on-revert: without the guard the rollback publishes (5, 5) — the stored
/// snapshot, last_snapshot_generation, and persisted state all roll back to the
/// prior generation, so an entry stamped by that generation equality-matches
/// the published pair again and the cached ALLOW is revived. Every assertion
/// below flips.
#[test]
fn apply_snapshot_rejects_generation_rollback_5169() {
    use crate::{ConfigSnapshot, CONFIG_SNAPSHOT_PROTOCOL_VERSION};
    let state = new_state(ProcessStatus::default());
    let state_file = unique_state_file("apply-rollback-5169");

    // Apply gen (config=5, fib=5): first apply, publishes the baseline pair.
    {
        let mut request = req("apply_snapshot");
        request.snapshot = Some(ConfigSnapshot {
            version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
            generation: 5,
            fib_generation: 5,
            generated_at: chrono::Utc::now(),
            ..ConfigSnapshot::default()
        });
        assert!(run_request_on_file(state.clone(), request, &state_file).ok);
    }
    // Advance to gen (config=6, fib=5): strictly monotonic, applies — this is
    // the apply that logically invalidates any (5, 5)-stamped flow-cache entry.
    {
        let mut request = req("apply_snapshot");
        request.snapshot = Some(ConfigSnapshot {
            version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
            generation: 6,
            fib_generation: 5,
            generated_at: chrono::Utc::now(),
            ..ConfigSnapshot::default()
        });
        assert!(run_request_on_file(state.clone(), request, &state_file).ok);
    }
    // Rollback to gen (config=5, fib=5) — a reused/rolled-back pair equal to a
    // prior published pair. Must be refused fail-closed.
    let mut request = req("apply_snapshot");
    request.snapshot = Some(ConfigSnapshot {
        version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
        generation: 5,
        fib_generation: 5,
        generated_at: chrono::Utc::now(),
        ..ConfigSnapshot::default()
    });
    let response = run_request_on_file(state.clone(), request, &state_file);
    assert!(!response.ok, "rolled-back apply_snapshot must be rejected");
    assert!(
        response
            .error
            .contains("snapshot generation rollback rejected"),
        "unexpected error: {}",
        response.error
    );

    let guard = state.lock().expect("state");
    // The published pair must NOT roll back.
    assert_eq!(
        guard.status.last_snapshot_generation, 6,
        "rejected rollback must not lower last_snapshot_generation"
    );
    assert_eq!(
        guard.status.last_fib_generation, 5,
        "rejected rollback must not lower last_fib_generation"
    );
    // The stored snapshot (boot baseline) must NOT roll back.
    assert_eq!(
        guard.snapshot.as_ref().map(|s| s.generation),
        Some(6),
        "rejected rollback must not overwrite the stored snapshot"
    );

    // Assert the ACTUAL defect via the flow-cache equality contract: an entry
    // stamped by the prior generation is a HIT only when the published pair
    // equals its stamp (afxdp/flow_cache.rs `lookup`; see
    // `stale_config_generation_causes_miss`). A lazily-unevicted cached ALLOW
    // stamped (5, 5) is revived iff the published pair rolls back to (5, 5).
    // The guard keeps the published pair at the post-invalidation (6, 5), so
    // the stale (5, 5)-stamped entry can NEVER equality-match — it stays
    // evicted and the cached ALLOW is not revived (no fail-open).
    let stale_entry_stamp = (5u64, 5u32);
    let published_pair = (
        guard.status.last_snapshot_generation,
        guard.status.last_fib_generation,
    );
    assert_ne!(
        published_pair, stale_entry_stamp,
        "published pair must NOT roll back to the stale entry's stamp — else the \
         flow-cache equality check revives the cached ALLOW (fail-open)"
    );
    drop(guard);

    // persist_state must NOT have been set by the rejected rollback: the
    // on-disk state a restart boots from stays at the last accepted (6, 5),
    // not the rolled-back (5, 5).
    let bytes = std::fs::read(&state_file).expect("read persisted state file");
    let persisted: serde_json::Value =
        serde_json::from_slice(&bytes).expect("parse persisted state file");
    assert_eq!(
        persisted["snapshot"]["generation"].as_u64(),
        Some(6),
        "rejected rollback must not persist the rolled-back generation"
    );
    assert_eq!(
        persisted["status"]["last_snapshot_generation"].as_u64(),
        Some(6),
        "rejected rollback must not persist a rolled-back last_snapshot_generation"
    );
    let _ = std::fs::remove_file(&state_file);
}

/// #5169 (review fold): an EXACT-EQUAL apply_snapshot (the new (config, fib)
/// pair equals the last published pair) must be ADMITTED, not refused. An equal
/// pair equality-matches only the CURRENT published pair, whose cache entries
/// are already valid, so re-publishing it revives NOTHING — refusing it buys no
/// security and breaks the #4036 "timeout-but-landed" idempotent retry (the
/// partial-republish Go paths recompute the SAME generation after a timed-out
/// apply that actually landed and must be ACKed ok, not fail-closed into a
/// non-converging loop). This mirrors `bump_fib`, which admits an equal fib.
#[test]
fn apply_snapshot_admits_generation_reuse_5169() {
    use crate::{ConfigSnapshot, CONFIG_SNAPSHOT_PROTOCOL_VERSION};
    let state = new_state(ProcessStatus::default());

    // Apply gen (config=6, fib=5).
    {
        let mut request = req("apply_snapshot");
        request.snapshot = Some(ConfigSnapshot {
            version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
            generation: 6,
            fib_generation: 5,
            generated_at: chrono::Utc::now(),
            ..ConfigSnapshot::default()
        });
        assert!(run_request(state.clone(), request).ok);
    }
    // Re-apply the identical pair (6, 5) — the idempotent-retry path: admitted.
    let mut request = req("apply_snapshot");
    request.snapshot = Some(ConfigSnapshot {
        version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
        generation: 6,
        fib_generation: 5,
        generated_at: chrono::Utc::now(),
        ..ConfigSnapshot::default()
    });
    let response = run_request(state.clone(), request);
    assert!(
        response.ok,
        "an exact-equal re-apply (idempotent retry) must be admitted: {}",
        response.error
    );
    let guard = state.lock().expect("state");
    assert_eq!(guard.status.last_snapshot_generation, 6);
    assert_eq!(guard.status.last_fib_generation, 5);
    assert_eq!(guard.snapshot.as_ref().map(|s| s.generation), Some(6));
}

/// #5169 (review fold): a FIB ROLLBACK under a reused config (config == cur,
/// fib < cur_fib) must be REFUSED. This is the second rollback axis — the fib
/// half of the pair rolling back re-publishes a superseded pair whose stale
/// flow-cache entries would be revived, exactly the fail-open on the fib
/// dimension (the full-apply analogue of the #3767 H5 bump_fib rollback).
///
/// RED-on-revert: neutralize the guard and the (6, 6) rollback publishes over
/// the (6, 7) baseline — the assertions below flip.
#[test]
fn apply_snapshot_rejects_fib_rollback_5169() {
    use crate::{ConfigSnapshot, CONFIG_SNAPSHOT_PROTOCOL_VERSION};
    let state = new_state(ProcessStatus::default());

    // Baseline (config=6, fib=5).
    {
        let mut request = req("apply_snapshot");
        request.snapshot = Some(ConfigSnapshot {
            version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
            generation: 6,
            fib_generation: 5,
            generated_at: chrono::Utc::now(),
            ..ConfigSnapshot::default()
        });
        assert!(run_request(state.clone(), request).ok);
    }
    // Fib advances 5 -> 7 (config reused at 6): admitted.
    {
        let mut request = req("apply_snapshot");
        request.snapshot = Some(ConfigSnapshot {
            version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
            generation: 6,
            fib_generation: 7,
            generated_at: chrono::Utc::now(),
            ..ConfigSnapshot::default()
        });
        assert!(run_request(state.clone(), request).ok);
    }
    // Fib rolls back 7 -> 6 under the reused config 6: must be refused.
    let mut request = req("apply_snapshot");
    request.snapshot = Some(ConfigSnapshot {
        version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
        generation: 6,
        fib_generation: 6,
        generated_at: chrono::Utc::now(),
        ..ConfigSnapshot::default()
    });
    let response = run_request(state.clone(), request);
    assert!(!response.ok, "a fib rollback under a reused config must be rejected");
    assert!(
        response
            .error
            .contains("snapshot generation rollback rejected"),
        "unexpected error: {}",
        response.error
    );
    let guard = state.lock().expect("state");
    assert_eq!(
        guard.status.last_snapshot_generation, 6,
        "rejected fib rollback keeps the published config generation"
    );
    assert_eq!(
        guard.status.last_fib_generation, 7,
        "rejected fib rollback must not lower last_fib_generation"
    );
    assert_eq!(guard.snapshot.as_ref().map(|s| s.fib_generation), Some(7));
}

/// #5169: a strictly-monotonic apply_snapshot whose CONFIG generation advances
/// (the normal full-apply path) must apply exactly as before — the guard must
/// not regress legitimate applies.
#[test]
fn apply_snapshot_monotonic_config_advance_applies_5169() {
    use crate::{ConfigSnapshot, CONFIG_SNAPSHOT_PROTOCOL_VERSION};
    let state = new_state(ProcessStatus::default());

    // Baseline (config=5, fib=5).
    {
        let mut request = req("apply_snapshot");
        request.snapshot = Some(ConfigSnapshot {
            version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
            generation: 5,
            fib_generation: 5,
            generated_at: chrono::Utc::now(),
            ..ConfigSnapshot::default()
        });
        assert!(run_request(state.clone(), request).ok);
    }
    // Config advances 5 -> 6 (fib carried forward at 5): admitted.
    let mut request = req("apply_snapshot");
    request.snapshot = Some(ConfigSnapshot {
        version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
        generation: 6,
        fib_generation: 5,
        generated_at: chrono::Utc::now(),
        ..ConfigSnapshot::default()
    });
    let response = run_request(state.clone(), request);
    assert!(
        response.ok,
        "strictly-monotonic config advance must apply: {}",
        response.error
    );
    let guard = state.lock().expect("state");
    assert_eq!(guard.status.last_snapshot_generation, 6);
    assert_eq!(guard.status.last_fib_generation, 5);
    assert_eq!(guard.snapshot.as_ref().map(|s| s.generation), Some(6));
}

/// #5169: a FIB-ONLY advance via apply_snapshot (config REUSED, fib
/// incremented) is LEGITIMATE — the route-only overlay case that `bump_fib`
/// handles — and must be ADMITTED, not falsely refused by an over-strict
/// guard. The pair-monotonicity relation is lexicographic strict-greater, so
/// (config==cur && fib>cur.fib) applies. Any advance of either generation
/// changes the flow-cache equality key and correctly invalidates the cache.
#[test]
fn apply_snapshot_fib_only_advance_admitted_5169() {
    use crate::{ConfigSnapshot, CONFIG_SNAPSHOT_PROTOCOL_VERSION};
    let state = new_state(ProcessStatus::default());

    // Baseline (config=6, fib=5).
    {
        let mut request = req("apply_snapshot");
        request.snapshot = Some(ConfigSnapshot {
            version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
            generation: 6,
            fib_generation: 5,
            generated_at: chrono::Utc::now(),
            ..ConfigSnapshot::default()
        });
        assert!(run_request(state.clone(), request).ok);
    }
    // Config REUSED at 6, fib advances 5 -> 6: admitted (route-only overlay).
    let mut request = req("apply_snapshot");
    request.snapshot = Some(ConfigSnapshot {
        version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
        generation: 6,
        fib_generation: 6,
        generated_at: chrono::Utc::now(),
        ..ConfigSnapshot::default()
    });
    let response = run_request(state.clone(), request);
    assert!(
        response.ok,
        "a fib-only advance (config reused, fib incremented) must be admitted: {}",
        response.error
    );
    let guard = state.lock().expect("state");
    assert_eq!(
        guard.status.last_snapshot_generation, 6,
        "fib-only advance keeps the reused config generation"
    );
    assert_eq!(
        guard.status.last_fib_generation, 6,
        "fib-only advance publishes the incremented fib generation"
    );
    assert_eq!(guard.snapshot.as_ref().map(|s| s.fib_generation), Some(6));
}

// --- set_binding_state / set_queue_state error arms ---------------------

#[test]
fn set_binding_state_missing_payload_is_rejected() {
    let response = run_request(new_state(ProcessStatus::default()), req("set_binding_state"));
    assert!(!response.ok);
    assert!(
        response.error.contains("missing binding state"),
        "unexpected error: {}",
        response.error
    );
}

#[test]
fn set_binding_state_unknown_slot_is_rejected() {
    let mut request = req("set_binding_state");
    request.binding = Some(BindingControlRequest {
        slot: 999,
        registered: true,
        armed: false,
    });
    let response = run_request(new_state(ProcessStatus::default()), request);
    assert!(!response.ok);
    assert!(
        response.error.contains("unknown binding slot 999"),
        "unexpected error: {}",
        response.error
    );
}

#[test]
fn set_binding_state_toggles_registered_and_armed_on_known_slot() {
    // Seed one registered binding; arm it via set_binding_state and
    // assert the success arm flips armed (forwarding unarmed so the
    // reconcile is a safe no-op teardown).
    let state = new_state(ProcessStatus {
        bindings: vec![BindingStatus {
            slot: 3,
            registered: true,
            armed: false,
            ..BindingStatus::default()
        }],
        ..ProcessStatus::default()
    });
    let mut request = req("set_binding_state");
    request.binding = Some(BindingControlRequest {
        slot: 3,
        registered: true,
        armed: true,
    });
    let response = run_request(state.clone(), request);
    assert!(response.ok, "unexpected error: {}", response.error);
    let guard = state.lock().expect("state");
    let binding = guard
        .status
        .bindings
        .iter()
        .find(|b| b.slot == 3)
        .expect("seeded slot 3");
    assert!(binding.registered);
    assert!(binding.armed, "armed flag must flip on the known slot");
}

#[test]
fn set_queue_state_missing_payload_is_rejected() {
    let response = run_request(new_state(ProcessStatus::default()), req("set_queue_state"));
    assert!(!response.ok);
    assert!(
        response.error.contains("missing queue state"),
        "unexpected error: {}",
        response.error
    );
}

#[test]
fn set_queue_state_unknown_queue_is_rejected() {
    let mut request = req("set_queue_state");
    request.queue = Some(QueueControlRequest {
        queue_id: 42,
        registered: true,
        armed: false,
    });
    let response = run_request(new_state(ProcessStatus::default()), request);
    assert!(!response.ok);
    assert!(
        response.error.contains("unknown queue 42"),
        "unexpected error: {}",
        response.error
    );
}

#[test]
fn set_queue_state_toggles_armed_on_known_queue() {
    let state = new_state(ProcessStatus {
        bindings: vec![BindingStatus {
            slot: 0,
            queue_id: 2,
            registered: true,
            armed: false,
            ..BindingStatus::default()
        }],
        ..ProcessStatus::default()
    });
    let mut request = req("set_queue_state");
    request.queue = Some(QueueControlRequest {
        queue_id: 2,
        registered: true,
        armed: true,
    });
    let response = run_request(state.clone(), request);
    assert!(response.ok, "unexpected error: {}", response.error);
    let guard = state.lock().expect("state");
    assert!(
        guard
            .status
            .bindings
            .iter()
            .find(|b| b.queue_id == 2)
            .expect("seeded queue 2")
            .armed,
        "armed flag must flip on the known queue"
    );
}

// --- #5621: control-socket handlers must SURFACE a failed reconcile ------
//
// binding.rs / queue.rs / rebind.rs used to `let _ =
// reconcile_status_bindings(guard)` — discarding the `Result`. When the
// reconcile FAILED (a mandatory-pin preflight fault, or a forwarding-build
// integrity error on the ALREADY-ACCEPTED snapshot) the handler still acked
// ok=true, so the control-socket caller believed the AF_XDP sockets were
// (re)bound when they were not. These tests fault the reconcile with a stored
// snapshot whose forwarding build fails (an unparseable /33 interface address —
// the #3789 fixture) and pin ok=false + the surfaced error. Reverting the
// matching site to `let _ = reconcile_status_bindings(...)` flips the
// assertion RED (target-count 1 per site): the discard restores ok=true.
// Distinct from #5143 (that was the apply_snapshot rejected-snapshot leg).

/// A stored snapshot whose forwarding build FAILS (unparseable `/33` address).
/// With `forwarding_armed` + `forwarding_supported`, `reconcile_status_bindings`
/// takes the armed arm and `afxdp.reconcile` returns `Err` on this snapshot —
/// the same fault the #3789 apply-leg tests use.
fn failing_reconcile_snapshot() -> crate::ConfigSnapshot {
    use crate::{ConfigSnapshot, CONFIG_SNAPSHOT_PROTOCOL_VERSION};
    ConfigSnapshot {
        version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
        generation: 7,
        fib_generation: 7,
        generated_at: chrono::Utc::now(),
        capabilities: forwarding_caps(),
        map_pins: ok_map_pins(),
        interfaces: vec![tunnel_iface_3789("10.0.0.0/33")],
        ..ConfigSnapshot::default()
    }
}

/// Armed + forwarding-supported helper carrying a stored snapshot that will
/// fault the reconcile. The already-accepted snapshot models the #5621
/// scenario: a registration toggle / rebind re-runs the reconcile, which
/// faults, and the handler must NOT report success.
fn armed_state_with_failing_reconcile(bindings: Vec<BindingStatus>) -> Arc<Mutex<ServerState>> {
    Arc::new(Mutex::new(ServerState {
        status: ProcessStatus {
            forwarding_armed: true,
            capabilities: forwarding_caps(),
            bindings,
            ..ProcessStatus::default()
        },
        snapshot: Some(failing_reconcile_snapshot()),
        afxdp: afxdp::Coordinator::new(),
        state_writer: Arc::new(StateWriter::new()),
    }))
}

#[test]
fn set_binding_state_failed_reconcile_reports_error_5621() {
    // registered toggles false -> true so `registration_changed` fires the
    // reconcile; the stored bad snapshot makes that reconcile return Err.
    let state = armed_state_with_failing_reconcile(vec![BindingStatus {
        slot: 0,
        registered: false,
        ifindex: 10,
        ..BindingStatus::default()
    }]);
    let mut request = req("set_binding_state");
    request.binding = Some(BindingControlRequest {
        slot: 0,
        registered: true,
        armed: true,
    });
    let response = run_request(state, request);
    assert!(
        !response.ok,
        "#5621: set_binding_state must report ok=false when the reconcile fails"
    );
    assert!(
        response.error.contains("binding reconcile failed"),
        "unexpected error: {}",
        response.error
    );
}

#[test]
fn set_queue_state_failed_reconcile_reports_error_5621() {
    // registered toggles false -> true so `registration_changed` fires the
    // reconcile; the stored bad snapshot makes that reconcile return Err.
    let state = armed_state_with_failing_reconcile(vec![BindingStatus {
        slot: 0,
        queue_id: 2,
        registered: false,
        ifindex: 10,
        ..BindingStatus::default()
    }]);
    let mut request = req("set_queue_state");
    request.queue = Some(QueueControlRequest {
        queue_id: 2,
        registered: true,
        armed: true,
    });
    let response = run_request(state, request);
    assert!(
        !response.ok,
        "#5621: set_queue_state must report ok=false when the reconcile fails"
    );
    assert!(
        response.error.contains("queue reconcile failed"),
        "unexpected error: {}",
        response.error
    );
}

#[test]
fn rebind_failed_reconcile_reports_error_5621() {
    // rebind unconditionally reconciles; the stored bad snapshot makes that
    // reconcile return Err. Before #5621 rebind::handle took no `response`
    // and always acked ok=true.
    let state = armed_state_with_failing_reconcile(vec![BindingStatus {
        slot: 0,
        registered: true,
        ifindex: 10,
        ..BindingStatus::default()
    }]);
    let response = run_request(state, req("rebind"));
    assert!(
        !response.ok,
        "#5621: rebind must report ok=false when the reconcile fails"
    );
    assert!(
        response.error.contains("rebind reconcile failed"),
        "unexpected error: {}",
        response.error
    );
}

#[test]
fn set_forwarding_state_failed_reconcile_reports_error_6135() {
    // #6135 (the 4th site of #5621, excluded from the #6134 fix): the
    // set_forwarding_state handler used to `let _ =
    // reconcile_status_bindings(guard)`, acking ok=true even when the reconcile
    // of the ALREADY-ACCEPTED snapshot FAILED (a mandatory-pin preflight fault
    // or a forwarding-build integrity error). Arm forwarding on a registered
    // binding so the handler keeps forwarding_armed=true; the stored bad
    // snapshot (unparseable /33 interface address) makes
    // reconcile_status_bindings take the armed arm and return Err. Reverting
    // the matching site to `let _ = reconcile_status_bindings(...)` restores
    // ok=true and flips this assertion RED (target-count 1).
    let state = armed_state_with_failing_reconcile(vec![BindingStatus {
        slot: 0,
        registered: true,
        ifindex: 10,
        ..BindingStatus::default()
    }]);
    let mut request = req("set_forwarding_state");
    request.forwarding = Some(ForwardingControlRequest { armed: true });
    let response = run_request(state, request);
    assert!(
        !response.ok,
        "#6135: set_forwarding_state must report ok=false when the reconcile fails"
    );
    assert!(
        response.error.contains("forwarding reconcile failed"),
        "unexpected error: {}",
        response.error
    );
}

#[test]
fn stop_workers_clears_socket_fields_on_all_bindings() {
    // stop_workers must tear down per-binding socket state so the
    // subsequent rebind recreates fresh AF_XDP sockets.
    let mut seeded = BindingStatus {
        slot: 0,
        registered: true,
        bound: true,
        xsk_registered: true,
        zero_copy: true,
        socket_fd: 42,
        ready: true,
        ..BindingStatus::default()
    };
    seeded.xsk_bind_mode = "zerocopy".to_string();
    seeded.last_error = "stale".to_string();
    let state = new_state(ProcessStatus {
        bindings: vec![seeded],
        ..ProcessStatus::default()
    });
    let response = run_request(state.clone(), req("stop_workers"));
    assert!(response.ok, "unexpected error: {}", response.error);
    let guard = state.lock().expect("state");
    let binding = &guard.status.bindings[0];
    assert!(!binding.bound);
    assert!(!binding.xsk_registered);
    assert!(binding.xsk_bind_mode.is_empty());
    assert!(!binding.zero_copy);
    assert_eq!(binding.socket_fd, 0);
    assert!(!binding.ready);
    assert!(binding.last_error.is_empty());
}

#[test]
fn inject_packet_missing_payload_is_rejected() {
    let response = run_request(new_state(ProcessStatus::default()), req("inject_packet"));
    assert!(!response.ok);
    assert!(
        response.error.contains("missing packet injection request"),
        "unexpected error: {}",
        response.error
    );
}

// --- pure helper predicates --------------------------------------------

#[test]
fn forwarding_unsupported_error_uses_generic_text_without_reasons() {
    let cap = UserspaceCapabilities {
        forwarding_supported: false,
        unsupported_reasons: Vec::new(),
    };
    let msg = forwarding_unsupported_error(&cap);
    assert_eq!(
        msg,
        "userspace live forwarding is not supported for the current configuration"
    );
}

#[test]
fn forwarding_unsupported_error_joins_reasons() {
    let cap = UserspaceCapabilities {
        forwarding_supported: false,
        unsupported_reasons: vec!["reason a".to_string(), "reason b".to_string()],
    };
    let msg = forwarding_unsupported_error(&cap);
    assert!(msg.contains("reason a; reason b"), "got: {msg}");
}

#[test]
fn parse_session_sync_mac_round_trips_valid_mac() {
    let parsed = parse_session_sync_mac("02:bf:72:01:02:03").expect("valid mac");
    assert_eq!(parsed, Some([0x02, 0xbf, 0x72, 0x01, 0x02, 0x03]));
}

#[test]
fn parse_session_sync_mac_empty_is_none() {
    assert_eq!(parse_session_sync_mac("").expect("empty ok"), None);
}

#[test]
fn parse_session_sync_mac_rejects_short_mac() {
    assert!(parse_session_sync_mac("02:bf:72").is_err());
}

#[test]
fn parse_session_sync_mac_rejects_long_mac() {
    assert!(parse_session_sync_mac("02:bf:72:01:02:03:04").is_err());
}

#[test]
fn parse_session_sync_mac_rejects_non_hex() {
    assert!(parse_session_sync_mac("zz:bf:72:01:02:03").is_err());
}

#[test]
fn should_run_afxdp_requires_armed_and_supported() {
    let mut status = ProcessStatus {
        forwarding_armed: true,
        ..ProcessStatus::default()
    };
    status.capabilities.forwarding_supported = false;
    assert!(!should_run_afxdp(&status), "unsupported must not run");
    status.capabilities.forwarding_supported = true;
    assert!(should_run_afxdp(&status), "armed + supported must run");
    status.forwarding_armed = false;
    assert!(!should_run_afxdp(&status), "unarmed must not run");
}

#[test]
fn reconcile_disarmed_clears_full_stale_binding_survivors() {
    // #2794 fail-on-revert. When `should_run_afxdp` goes false
    // (forwarding disarmed), `reconcile_status_bindings` takes the early
    // return arm. Before #2794 that arm hand-cleared only a SUBSET of the
    // per-binding fields (`bound`/`xsk_registered`/`xsk_bind_mode`/
    // `zero_copy`/`socket_fd`/`ready`/`last_error`) and left the SAME
    // survivor class #2515 fixed on the no_snapshot reconcile arm stale:
    // `socket_ifindex`/`socket_queue_id`/`socket_bind_flags`,
    // `flow_cache_capacity`, and `active_flow_count`. Routing the arm
    // through `refresh_bindings` (which sends every now-workerless slot
    // through `zero_unbound_slot`) clears the FULL set.
    //
    // Seed a slot that looks like it was actively bound + forwarding, then
    // disarm and reconcile. If someone reverts to the partial hand-clear,
    // the survivor assertions below FAIL (the socket/flow-cache fields
    // stay non-zero).
    let state = new_state(ProcessStatus {
        // forwarding_armed = false -> should_run_afxdp() false -> early arm.
        forwarding_armed: false,
        capabilities: UserspaceCapabilities {
            forwarding_supported: true,
            unsupported_reasons: Vec::new(),
        },
        bindings: vec![BindingStatus {
            slot: 0,
            registered: true,
            // --- the subset the old hand-clear DID reset ---
            bound: true,
            xsk_registered: true,
            xsk_bind_mode: "zero-copy".to_string(),
            zero_copy: true,
            socket_fd: 42,
            ready: true,
            last_error: "stale".to_string(),
            // --- the #2794 survivor class the old hand-clear LEFT STALE ---
            socket_ifindex: 7,
            socket_queue_id: 3,
            socket_bind_flags: 0x4,
            flow_cache_capacity: 65536,
            active_flow_count: 123,
            // a representative counter gauge, also a survivor pre-#2794
            rx_packets: 999,
            ..BindingStatus::default()
        }],
        ..ProcessStatus::default()
    });

    {
        let mut guard = state.lock().expect("state");
        // #3789: disarmed reconcile is a teardown — always Ok.
        reconcile_status_bindings(&mut guard).expect("disarmed reconcile is infallible");
    }

    let guard = state.lock().expect("state");
    let b = &guard.status.bindings[0];
    // Subset the old arm already cleared (regression guard).
    assert!(!b.bound, "bound must be cleared");
    assert!(!b.xsk_registered, "xsk_registered must be cleared");
    assert!(b.xsk_bind_mode.is_empty(), "xsk_bind_mode must be cleared");
    assert!(!b.zero_copy, "zero_copy must be cleared");
    assert_eq!(b.socket_fd, 0, "socket_fd must be cleared");
    assert!(!b.ready, "ready must be cleared");
    assert!(b.last_error.is_empty(), "last_error must be cleared");
    // The #2794 survivor class — THESE go RED if the fix is reverted.
    assert_eq!(b.socket_ifindex, 0, "#2794: socket_ifindex left stale");
    assert_eq!(b.socket_queue_id, 0, "#2794: socket_queue_id left stale");
    assert_eq!(b.socket_bind_flags, 0, "#2794: socket_bind_flags left stale");
    assert_eq!(b.flow_cache_capacity, 0, "#2794: flow_cache_capacity left stale");
    assert_eq!(b.active_flow_count, 0, "#2794: active_flow_count left stale");
    assert_eq!(b.rx_packets, 0, "#2794: rx_packets counter left stale");
}

#[test]
fn set_bindings_forwarding_armed_only_arms_registered_bindings() {
    let mut status = ProcessStatus {
        bindings: vec![
            BindingStatus {
                slot: 0,
                registered: true,
                ..BindingStatus::default()
            },
            BindingStatus {
                slot: 1,
                registered: false,
                ..BindingStatus::default()
            },
        ],
        ..ProcessStatus::default()
    };
    set_bindings_forwarding_armed(&mut status, true);
    assert!(status.bindings[0].armed, "registered binding must arm");
    assert!(
        !status.bindings[1].armed,
        "unregistered binding must not arm"
    );
}

#[test]
fn bindings_settled_unregistered_settled_only_when_torn_down() {
    let settled = vec![BindingStatus {
        registered: false,
        bound: false,
        xsk_registered: false,
        ..BindingStatus::default()
    }];
    assert!(bindings_settled(&settled));

    let unsettled = vec![BindingStatus {
        registered: false,
        bound: true,
        ..BindingStatus::default()
    }];
    assert!(
        !bindings_settled(&unsettled),
        "unregistered-but-still-bound is not settled"
    );
}

#[test]
fn bindings_settled_registered_needs_ready_or_error() {
    let pending = vec![BindingStatus {
        registered: true,
        ready: false,
        ..BindingStatus::default()
    }];
    assert!(!bindings_settled(&pending), "registered + not ready is pending");

    let ready = vec![BindingStatus {
        registered: true,
        ready: true,
        ..BindingStatus::default()
    }];
    assert!(bindings_settled(&ready));

    let mut errored = BindingStatus {
        registered: true,
        ready: false,
        ..BindingStatus::default()
    };
    errored.last_error = "bind failed".to_string();
    assert!(
        bindings_settled(&[errored]),
        "registered with a terminal error counts as settled"
    );
}

// --- #1866: disarmed same-plan apply must not hold WG ports --------------

/// PR #1872 Codex code-r1 F1 regression: with forwarding DISARMED, a
/// same-plan apply_snapshot takes the refresh_runtime_snapshot leg
/// (needs_reconcile is false while disarmed), which reconciles WG
/// control threads for the running case — the handler must then stop
/// them so a disarmed helper never holds WG listen ports (mirrors the
/// reconcile_status_bindings → stop() semantics of the
/// NOT-same-plan path).
#[test]
fn wg1866_disarmed_same_plan_apply_does_not_hold_wg_ports() {
    use crate::{ConfigSnapshot, CONFIG_SNAPSHOT_PROTOCOL_VERSION};
    let port: u16 = 51879;
    let wg_snapshot = |generation: u64| ConfigSnapshot {
        version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
        generation,
        interfaces: vec![crate::protocol::snapshot::InterfaceSnapshot {
            name: "wgt1866srv".to_string(),
            linux_name: "wgt1866srv".to_string(),
            ifindex: 4250,
            tunnel: true,
            ..Default::default()
        }],
        tunnel_endpoints: vec![crate::protocol::snapshot::TunnelEndpointSnapshot {
            id: 1,
            interface: "wgt1866srv".to_string(),
            linux_name: "wgt1866srv".to_string(),
            ifindex: 4250,
            mode: "wireguard".to_string(),
            wg_listen_port: port,
            wg_local_privkey_hex:
                "a01010101010101010101010101010101010101010101010101010101010101a"
                    .to_string(),
            wg_peers: vec![crate::protocol::snapshot::TunnelWgPeerSnapshot {
                wg_peer_pubkey_hex:
                    "b02020202020202020202020202020202020202020202020202020202020202b"
                        .to_string(),
                wg_allowed_ips: vec!["10.77.0.0/24".to_string()],
                ..Default::default()
            }],
            ..Default::default()
        }],
        ..Default::default()
    };
    // forwarding_armed defaults to false: disarmed throughout.
    let state = new_state(ProcessStatus::default());
    // Pre-bind the WG port for the whole test: a disarmed helper must
    // not even ATTEMPT a bind (Codex code-r2 — the transient
    // spawn/bind would surface here as a wg_bind_listen_port
    // exception), so this blocker must never be hit.
    let _blocker = std::net::UdpSocket::bind(("::", port)).expect("pre-bind");
    // Codex code-r3 portability nit: on bindv6only=1 hosts the v6
    // blocker does not cover the v4 fallback bind — add a v4 blocker
    // opportunistically (it fails AddrInUse on dual-stack hosts, which
    // is fine: the v6 blocker already covers both there).
    let _blocker_v4 = std::net::UdpSocket::bind(("0.0.0.0", port)).ok();
    // Apply 1: NOT-same-plan (no previous snapshot) — the disarmed
    // reconcile path stops everything.
    let mut first = req("apply_snapshot");
    first.snapshot = Some(wg_snapshot(1));
    let response = run_request(state.clone(), first);
    assert!(response.ok, "first apply: {}", response.error);
    // Apply 2: same-plan — takes the (disarmed) refresh leg.
    let mut second = req("apply_snapshot");
    second.snapshot = Some(wg_snapshot(2));
    let response = run_request(state.clone(), second);
    assert!(response.ok, "second apply: {}", response.error);
    let guard = state.lock().expect("state");
    assert!(
        guard.afxdp.wg_control_threads.is_empty(),
        "disarmed helper must hold no WG control entries after a same-plan apply"
    );
    let exceptions = guard
        .afxdp
        .recent_exceptions
        .lock()
        .expect("exceptions")
        .iter()
        .filter(|e| e.reason().contains("wg_bind_listen_port"))
        .count();
    assert_eq!(
        exceptions, 0,
        "disarmed helper must not even attempt a WG bind (no transient spawn)"
    );
}

// --- #2962: owner-RG export must not hold the ServerState lock ----------

/// Fail-on-revert: the owner-RG session export must run its blocking 15 s
/// ack-wait WITHOUT holding the global `ServerState` lock, so a slow/stalled
/// worker cannot freeze the rest of the control plane. This test installs a
/// worker that never acks on its own, kicks an export (which blocks in
/// `wait_and_collect`), and proves a concurrent `status` poll is still served
/// promptly. If the wait runs under the lock again (the bug), the status poll
/// blocks until the ack arrives and this assertion goes RED.
#[test]
fn export_owner_rg_does_not_hold_state_lock_during_ack_wait() {
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};

    let state = new_state(ProcessStatus::default());

    // Install a worker whose export ack never advances on its own. A timer
    // thread acks it after 800ms so the export wait stays bounded in BOTH
    // the fixed and the reverted code paths (no 15 s hang on revert).
    let ack = {
        let mut guard = state.lock().expect("lock state");
        guard.afxdp.test_install_export_worker(0)
    };
    let ack_thread = {
        let ack = ack.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(800));
            ack.store(u64::MAX, Ordering::Release);
        })
    };

    // Run the export in the background: it kicks under the lock, releases the
    // lock, then blocks in the ack-wait until the timer thread acks (~800ms).
    let export_state = state.clone();
    let export_thread = std::thread::spawn(move || {
        let mut r = req("export_owner_rg_sessions");
        r.session_export = Some(SessionExportRequest {
            owner_rgs: vec![1],
            max: 0,
        });
        run_request(export_state, r)
    });

    // Let the export reach its wait.
    std::thread::sleep(Duration::from_millis(150));

    // The control plane MUST answer a status poll WHILE the export waits.
    // With the lock held across the wait (the #2962 bug) this would block
    // until the 800ms ack releases it (~650ms after t0).
    let t0 = Instant::now();
    let resp = run_request(state.clone(), req("status"));
    let elapsed = t0.elapsed();
    assert!(resp.ok, "status poll failed: {}", resp.error);
    assert!(
        elapsed < Duration::from_millis(400),
        "status poll blocked {elapsed:?} during owner-RG export — \
         ServerState lock held across the ack-wait (#2962 regression)"
    );

    let export_resp = export_thread.join().expect("export thread");
    assert!(export_resp.ok, "export failed: {}", export_resp.error);
    ack_thread.join().expect("ack thread");
}

// --- #4054: all-sessions bulk export must not hold the ServerState lock ----

/// Fail-on-revert: the all-sessions bulk export (`export_all_sessions`) must run
/// its (potentially blocking) `push_delta_lossless` serialization WITHOUT
/// holding the global `ServerState` lock, so a large or backpressured bulk
/// export at failover cannot freeze the control plane and self-inflict a
/// needless helper restart. This installs a CONNECTED event stream whose
/// channel holds a single slot and several qualifying local forward sessions,
/// so after the first delta the push loop blocks against the full channel (up
/// to the 5 s lossless-queue timeout). It then proves a concurrent `status`
/// poll is still served promptly. If the push runs under the lock again (the
/// bug), the status poll blocks until the push drains/times out — RED.
#[test]
fn export_all_sessions_does_not_hold_state_lock_during_push() {
    use crate::event_stream::EventStreamSender;
    use std::time::{Duration, Instant};

    let state = new_state(ProcessStatus::default());

    // Connected event stream, single-slot channel: the first pushed delta fills
    // it, and every later delta retries against the full channel. Keep `rx`
    // alive — dropping it disconnects the channel, which makes push fail
    // IMMEDIATELY instead of blocking (and would mask the bug on revert).
    let rx = {
        let mut guard = state.lock().expect("lock state");
        let (sender, rx) = EventStreamSender::test_sender(true, 1);
        guard.afxdp.event_stream = Some(sender);
        for i in 0..4u16 {
            guard.afxdp.test_install_local_forward_session(i);
        }
        rx
    };

    // Kick the bulk export in the background: it snapshots the session set under
    // a BRIEF lock, releases the global ServerState lock, then blocks in the
    // push loop against the full channel.
    let export_state = state.clone();
    let export_thread =
        std::thread::spawn(move || run_request(export_state, req("export_all_sessions")));

    // Let the export reach its (blocked) push.
    std::thread::sleep(Duration::from_millis(150));

    // The control plane MUST answer a status poll WHILE the export's push loop
    // is blocked. With the push under the global lock (the #4054 bug) this
    // blocks until the 5 s lossless timeout releases the lock → RED.
    let t0 = Instant::now();
    let resp = run_request(state.clone(), req("status"));
    let elapsed = t0.elapsed();
    assert!(resp.ok, "status poll failed: {}", resp.error);
    assert!(
        elapsed < Duration::from_millis(1000),
        "status poll blocked {elapsed:?} during all-sessions bulk export — \
         ServerState lock held across push_delta_lossless (#4054 regression)"
    );

    // Drain the channel so the blocked push loop makes progress and the export
    // thread finishes promptly instead of waiting the full 5 s per-delta
    // timeout. Stop once no frame arrives for a short grace period (export done
    // pushing).
    let drainer = std::thread::spawn(move || {
        while rx.recv_timeout(Duration::from_millis(300)).is_ok() {}
    });

    let export_resp = export_thread.join().expect("export thread");
    drainer.join().expect("drainer thread");
    assert!(
        export_resp.ok,
        "bulk export failed: {}",
        export_resp.error
    );
}

/// #3773 (L4): an `update_fabrics` that CHANGES the fabric set must fold the
/// freshly-resolved FabricSnapshots into the STORED snapshot AND persist. The
/// helper starts with `snapshot: None` and never self-restores, so the
/// published state file (read by the Go control plane's `show` surface, and
/// the last-written record a consumer sees) is the observability SSOT. Before
/// #3773 the `update_fabrics` arm neither updated the stored snapshot nor set
/// `persist_state`, so a late-resolved peer/local MAC from the SyncFabricState
/// path lived only in the coordinator's in-memory forwarding state — the
/// persisted fabrics kept the stale apply-time (unresolved) values.
/// fail-on-revert: dropping the snapshot fold + `persist_state` leaves the
/// persisted `snapshot.fabrics` at the empty apply-time set (RED).
#[test]
fn update_fabrics_persists_resolved_fabric_set() {
    use crate::{ConfigSnapshot, FabricSnapshot, CONFIG_SNAPSHOT_PROTOCOL_VERSION};
    let state = new_state(ProcessStatus::default());
    let state_file = unique_state_file("fabric-persist");
    // Seed an apply_snapshot with NO fabrics (initial build before the peer
    // MAC resolved). This persists the state file with an empty fabric set.
    {
        let mut request = req("apply_snapshot");
        request.snapshot = Some(ConfigSnapshot {
            version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
            generation: 1,
            fib_generation: 1,
            generated_at: chrono::Utc::now(),
            ..ConfigSnapshot::default()
        });
        assert!(run_request_on_file(state.clone(), request, &state_file).ok);
    }
    // SyncFabricState resolves a peer MAC and pushes it via update_fabrics.
    let resolved = FabricSnapshot {
        parent_unbindable: false,
        name: "fab0".into(),
        parent_interface: "ge-0/0/0".into(),
        parent_linux_name: "ge-0-0-0".into(),
        parent_ifindex: 21,
        overlay_linux_name: "fab0".into(),
        overlay_ifindex: 101,
        rx_queues: 2,
        peer_address: "10.99.13.2".into(),
        local_mac: "02:bf:72:ff:00:01".into(),
        peer_mac: "00:aa:bb:cc:dd:ee".into(),
        up: true,
    };
    {
        let mut request = req("update_fabrics");
        request.fabrics = Some(vec![resolved.clone()]);
        assert!(run_request_on_file(state.clone(), request, &state_file).ok);
    }
    // The stored (in-RAM) snapshot must now carry the resolved fabric.
    assert_eq!(
        state
            .lock()
            .expect("state")
            .snapshot
            .as_ref()
            .expect("stored snapshot")
            .fabrics,
        vec![resolved.clone()],
        "update_fabrics must fold the resolved fabric into the stored snapshot"
    );
    // The on-disk state a `show` reads (and the last record a restart-time
    // consumer sees) must carry the resolved peer MAC, not the empty
    // apply-time set.
    let bytes = std::fs::read(&state_file).expect("read persisted state file");
    let persisted: serde_json::Value =
        serde_json::from_slice(&bytes).expect("parse persisted state file");
    assert_eq!(
        persisted["snapshot"]["fabrics"][0]["peer_mac"].as_str(),
        Some("00:aa:bb:cc:dd:ee"),
        "persisted snapshot must carry the resolved fabric peer MAC (#3773 L4)"
    );
    let _ = std::fs::remove_file(&state_file);
}

/// #3773 (L4): an `update_fabrics` whose fabric set is UNCHANGED from the
/// stored snapshot must NOT rewrite the state file — the 30s periodic
/// SyncFabricState refresh must not churn the disk on every unchanged tick.
#[test]
fn update_fabrics_unchanged_set_does_not_rewrite_state_file() {
    use crate::{ConfigSnapshot, FabricSnapshot, CONFIG_SNAPSHOT_PROTOCOL_VERSION};
    let resolved = FabricSnapshot {
        parent_unbindable: false,
        name: "fab0".into(),
        parent_interface: "ge-0/0/0".into(),
        parent_linux_name: "ge-0-0-0".into(),
        parent_ifindex: 21,
        overlay_linux_name: "fab0".into(),
        overlay_ifindex: 101,
        rx_queues: 2,
        peer_address: "10.99.13.2".into(),
        local_mac: "02:bf:72:ff:00:01".into(),
        peer_mac: "00:aa:bb:cc:dd:ee".into(),
        up: true,
    };
    let state = new_state(ProcessStatus::default());
    let state_file = unique_state_file("fabric-nochurn");
    // Seed a snapshot that ALREADY carries the resolved fabric.
    {
        let mut request = req("apply_snapshot");
        request.snapshot = Some(ConfigSnapshot {
            version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
            generation: 1,
            fib_generation: 1,
            generated_at: chrono::Utc::now(),
            fabrics: vec![resolved.clone()],
            ..ConfigSnapshot::default()
        });
        assert!(run_request_on_file(state.clone(), request, &state_file).ok);
    }
    let before = std::fs::metadata(&state_file)
        .expect("state file exists after seed apply")
        .modified()
        .expect("mtime");
    // A same-set update_fabrics: nothing changed, so no rewrite.
    std::thread::sleep(std::time::Duration::from_millis(10));
    {
        let mut request = req("update_fabrics");
        request.fabrics = Some(vec![resolved.clone()]);
        assert!(run_request_on_file(state.clone(), request, &state_file).ok);
    }
    let after = std::fs::metadata(&state_file)
        .expect("state file still exists")
        .modified()
        .expect("mtime");
    assert_eq!(
        before, after,
        "an unchanged update_fabrics must not rewrite the state file"
    );
    let _ = std::fs::remove_file(&state_file);
}

/// #5469 fail-on-revert: `write_state` must hold the `ServerState` lock ONLY
/// long enough to refresh status and clone the owned payload — the expensive
/// serialization and the `persist` fsync must run with the lock RELEASED. The
/// pre-persist probe records, on `write_state`'s own thread, whether the lock
/// was free at the persist point (std `Mutex` is non-reentrant, so a same-thread
/// `try_lock` succeeds only if the guard was dropped). Revert the guard back
/// across `persist` (the lock-convoy bug) and the probe records `false`, turning
/// this test RED.
#[test]
fn write_state_releases_lock_before_persist() {
    let state = new_state(ProcessStatus::default());
    let state_file = unique_state_file("lock-free-persist");
    clear_pre_persist_lock_probe();
    write_state(&state_file, &state).expect("write_state must succeed");
    let lock_free =
        take_pre_persist_lock_free().expect("write_state must run the pre-persist lock probe");
    assert!(
        lock_free,
        "write_state must drop the ServerState guard before serialization + persist (#5469)"
    );
    let _ = std::fs::remove_file(&state_file);
}

// #4565: a peer-PROMOTED NAT64 session must rebuild its RFC 6146 reverse BIB
// from the wire-carried translated pool source (`nat64_snat_v4`) + the synced
// forward v6 key. Before #4565 `build_synced_session_entry` set `nat64: false`
// and `nat64_reverse: None`, so a promoted NAT64 session (a) never reached the
// NAT64 frame builder (tx dispatch keys `is_nat64` off `nat.nat64`), (b) could
// not translate the v4 reply back to IPv6 (the frame builder hard-requires
// `nat64_reverse`), and (c) synthesized a WRONG (v6-family) reverse companion
// key so the server's v4 reply never matched. RED-on-revert: dropping the
// helpers.rs reconstruction makes every NAT64 assertion below fail.
#[test]
fn nat64_synced_entry_rebuilds_reverse_bib_4565() {
    use crate::nat64::Nat64ReverseInfo;
    use crate::session::reverse_session_key;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    let zones = rustc_hash::FxHashMap::default();

    // NAT64 forward flow: v6 client -> synthetic 64:ff9b::192.168.1.1
    // (dst_v4 = 192.168.1.1 by RFC 6052 /96), translated to pool source
    // 203.0.113.5:40000 on the active node.
    let req = SessionSyncRequest {
        operation: "upsert".to_string(),
        addr_family: libc::AF_INET6 as u8,
        protocol: crate::ip_proto::PROTO_TCP,
        src_ip: "2001:db8::1".to_string(),
        dst_ip: "64:ff9b::c0a8:101".to_string(),
        src_port: 5001,
        dst_port: 80,
        ingress_zone_id: 2,
        egress_zone_id: 3,
        egress_ifindex: 12,
        // The generic NAT fields carry the mangled cross-family remnants on the
        // real wire; the NAT64 path must OVERRIDE them from nat64_snat_v4.
        nat_src_ip: "2001:db8:dead:beef::".to_string(),
        nat_src_port: 40000,
        nat64_snat_v4: "203.0.113.5".to_string(),
        ..SessionSyncRequest::default()
    };
    let entry = build_synced_session_entry(&req, &zones).expect("build nat64 entry");

    // (a) NAT64 cross-family bit set -> tx dispatch reverse-translates + #4564
    // reserve arms.
    assert!(entry.decision.nat.nat64, "nat64 bit must be set");
    // (b) forward NAT decision rebuilt to the v4 pool binding (NOT the mangled
    // generic nat_src).
    assert_eq!(
        entry.decision.nat.rewrite_src,
        Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5))),
        "rewrite_src must be the translated pool source snat_v4"
    );
    assert_eq!(
        entry.decision.nat.rewrite_dst,
        Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
        "rewrite_dst must be the /96-embedded v4 destination"
    );
    assert_eq!(
        entry.decision.nat.rewrite_src_port,
        Some(40000),
        "translated port rides nat_src_port"
    );
    // (c) original v6 src/dst captured for the reverse (v4->v6) translation.
    assert_eq!(
        entry.metadata.nat64_reverse,
        Some(Nat64ReverseInfo {
            orig_src_v6: "2001:db8::1".parse::<Ipv6Addr>().unwrap(),
            orig_dst_v6: "64:ff9b::c0a8:101".parse::<Ipv6Addr>().unwrap(),
        }),
        "nat64_reverse must carry the original v6 endpoints"
    );

    // (d) the synthesized reverse companion key is the v4 reply tuple
    // (server_v4 -> snat_v4), so the server's IPv4 reply matches after failover.
    let rk = reverse_session_key(&entry.key, entry.decision.nat);
    assert_eq!(rk.addr_family, libc::AF_INET as u8, "reverse key must be v4");
    assert_eq!(rk.src_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
    assert_eq!(rk.dst_ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)));
    assert_eq!(rk.dst_port, 40000, "reply dst port is the translated port");

    // A non-NAT64 synced session (empty nat64_snat_v4) is unaffected: no nat64
    // bit, no reverse info, generic nat_src preserved.
    let plain = SessionSyncRequest {
        operation: "upsert".to_string(),
        addr_family: libc::AF_INET as u8,
        protocol: crate::ip_proto::PROTO_TCP,
        src_ip: "10.0.0.1".to_string(),
        dst_ip: "10.0.0.2".to_string(),
        src_port: 1234,
        dst_port: 80,
        ingress_zone_id: 2,
        egress_zone_id: 3,
        egress_ifindex: 12,
        nat_src_ip: "203.0.113.9".to_string(),
        nat_src_port: 50000,
        ..SessionSyncRequest::default()
    };
    let plain_entry = build_synced_session_entry(&plain, &zones).expect("build plain entry");
    assert!(!plain_entry.decision.nat.nat64, "non-nat64 stays non-nat64");
    assert_eq!(plain_entry.metadata.nat64_reverse, None);
    assert_eq!(
        plain_entry.decision.nat.rewrite_src,
        Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))),
        "non-nat64 keeps the generic SNAT source"
    );
}

// --- #5864: authoritative empty NeighborReplace clears the table --------

/// Seed exactly one publishable manager neighbor through the real
/// `update_neighbors` handler path and return the driven state.
fn seed_one_manager_neighbor() -> Arc<Mutex<ServerState>> {
    let state = new_state(ProcessStatus::default());
    let mut seed = req("update_neighbors");
    seed.neighbor_replace = true;
    seed.neighbors = Some(vec![crate::NeighborSnapshot {
        interface: "ge-0-0-1".to_string(),
        ifindex: 7,
        family: "inet".to_string(),
        ip: "10.0.0.1".to_string(),
        mac: "02:00:00:00:00:01".to_string(),
        state: "REACHABLE".to_string(),
        ..crate::NeighborSnapshot::default()
    }]);
    let resp = run_request(state.clone(), seed);
    assert!(resp.ok, "seed update_neighbors failed: {}", resp.error);
    assert_eq!(
        state
            .lock()
            .expect("state")
            .afxdp
            .dynamic_neighbor_status()
            .0,
        1,
        "seed must install exactly one manager neighbor"
    );
    state
}

/// #5864 fail-on-revert: an authoritative NeighborReplace with the field
/// ABSENT on the wire (Go drops the empty slice under omitempty →
/// neighbors=None) must CLEAR the manager-neighbor table, not early-return
/// and leave the stale entry installed. Reverting the None/empty handling
/// in `handlers::neighbors::update` (restoring `let Some(..) else return`)
/// makes the final assertion go RED — the stale neighbor survives.
#[test]
fn update_neighbors_absent_replace_clears_table_5864() {
    let state = seed_one_manager_neighbor();

    let mut clear = req("update_neighbors");
    clear.neighbor_replace = true;
    clear.neighbors = None;
    let resp = run_request(state.clone(), clear);
    assert!(resp.ok, "empty replace failed: {}", resp.error);

    assert_eq!(
        state
            .lock()
            .expect("state")
            .afxdp
            .dynamic_neighbor_status()
            .0,
        0,
        "authoritative replace with neighbors=None must clear the table"
    );
}

/// #5864 companion: an explicit present-but-empty slice (the post-fix Go
/// wire, `\"neighbors\":[]`) under NeighborReplace must clear identically.
#[test]
fn update_neighbors_explicit_empty_replace_clears_table_5864() {
    let state = seed_one_manager_neighbor();

    let mut clear = req("update_neighbors");
    clear.neighbor_replace = true;
    clear.neighbors = Some(Vec::new());
    let resp = run_request(state.clone(), clear);
    assert!(resp.ok, "empty-slice replace failed: {}", resp.error);

    assert_eq!(
        state
            .lock()
            .expect("state")
            .afxdp
            .dynamic_neighbor_status()
            .0,
        0,
        "authoritative replace with neighbors=[] must clear the table"
    );
}

/// #5864 guard: a NON-replace update with no neighbors must remain a
/// no-op — it carries nothing to add and must NOT touch the existing
/// table. Guards against the clear-on-empty fix over-reaching into the
/// (defensive) non-replace path.
#[test]
fn update_neighbors_none_without_replace_is_noop_5864() {
    let state = seed_one_manager_neighbor();

    let mut noop = req("update_neighbors");
    noop.neighbor_replace = false;
    noop.neighbors = None;
    let resp = run_request(state.clone(), noop);
    assert!(resp.ok, "noop update failed: {}", resp.error);

    assert_eq!(
        state
            .lock()
            .expect("state")
            .afxdp
            .dynamic_neighbor_status()
            .0,
        1,
        "non-replace update with no neighbors must not clear the table"
    );
}

// -------------------------------------------------------------
// #5294: a state-file write failure must NOT lose a drained
// session-delta batch (pop-then-fallible-write transactionality).
// -------------------------------------------------------------

/// #5294 fail-on-revert: `drain_session_deltas` DESTRUCTIVELY pops deltas out of
/// the per-binding RPC-fallback buffers into `response.session_deltas` and marks
/// `persist_state`. With the pre-#5294 pop-then-fallible-write order — the
/// dispatcher ran `write_state(...)?` BEFORE encoding the response — a local
/// state-file write error short-circuited the send via `?`: the deltas were
/// already gone from the queue yet never reached the peer AND were not persisted,
/// a PERMANENT HA session divergence (the standby never learns those open/close
/// events, the local copy is lost, and no loss-of-sync latch is armed for a
/// write_state failure). The fix always encodes+flushes the response (carrying
/// the drained deltas) BEFORE surfacing a persist error, so the peer still
/// receives every drained delta.
///
/// The owner-RG export mirror (`export_owner_rg_sessions` → `owner_rg_collect`)
/// populates `response.session_deltas` + `persist_state` and flows through the
/// SAME dispatcher tail, so this single test pins both paths.
///
/// Reverting the dispatcher to `write_state(state_file, &state)?` before the send
/// makes the handler return Err with NOTHING written, so the client read below
/// hits EOF and the decode `expect` panics — the RED signal.
#[test]
fn drain_session_deltas_survive_write_state_failure_5294() {
    let mut coord = afxdp::Coordinator::new();
    coord.seed_pending_session_deltas_for_test(0, 5);
    let state = Arc::new(Mutex::new(ServerState {
        status: ProcessStatus::default(),
        snapshot: None,
        afxdp: coord,
        state_writer: Arc::new(StateWriter::new()),
    }));

    // A state_file inside a directory that does not exist makes write_state's
    // temp-file open fail => write_state returns Err (the local state-file
    // problem the bug is about), while the ServerState stays otherwise healthy.
    let bad_state_file = format!(
        "/nonexistent-xpf-5294-dir-{}/state.json",
        std::process::id()
    );

    let mut request = req("drain_session_deltas");
    request.session_deltas = Some(crate::SessionDeltaDrainRequest { max: 256 });

    let (mut client, server) =
        std::os::unix::net::UnixStream::pair().expect("control socket pair");
    let running = Arc::new(AtomicBool::new(true));
    let handle = {
        let bad = bad_state_file.clone();
        std::thread::spawn(move || handle_stream(server, &bad, state, running))
    };

    serde_json::to_writer(&mut client, &request).expect("write request");
    std::io::Write::write_all(&mut client, b"\n").expect("newline");

    // The response MUST be delivered even though the persist will fail. On the
    // pre-#5294 pop-then-fallible-write order the handler returns Err before
    // writing anything, so this read hits EOF and the decode fails — the RED
    // signal that a drained delta batch was silently lost.
    let response: ControlResponse = serde_json::from_reader(std::io::BufReader::new(&client))
        .expect("drained deltas must reach the peer despite the write_state failure (#5294)");

    let handler_result = handle.join().expect("handler thread");

    // Test premise: write_state actually failed (else we would not be exercising
    // the failure path at all). The error is surfaced to the accept loop, but
    // only AFTER the response was flushed.
    let err = handler_result.expect_err("write_state must fail on a missing state dir");
    assert!(
        err.contains("write state file"),
        "expected a state-file persist error, got: {err}"
    );

    // The deltas were NOT lost: every drained delta reached the peer.
    assert!(response.ok, "drained-batch response must report ok");
    assert_eq!(
        response.session_deltas.len(),
        5,
        "all 5 drained deltas must reach the peer even though the persist failed \
         — the pre-#5294 pop-then-fallible-write order dropped the whole batch"
    );
}
