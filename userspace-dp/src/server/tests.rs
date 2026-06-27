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
    bindings_settled, forwarding_unsupported_error, parse_session_sync_mac,
    reconcile_status_bindings, set_bindings_forwarding_armed, should_run_afxdp,
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
    // that runs `stop_inner(true)`, which clears `coord.workers.handles`
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
        reconcile_status_bindings(&mut guard);
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
        .filter(|e| e.reason.contains("wg_bind_listen_port"))
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
