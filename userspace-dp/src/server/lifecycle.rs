// Daemon lifecycle: argument parsing, control-socket setup, daemon
// supervision loop. Extracted from main.rs (Issue 69.2).
//
// `run` is the main daemon driver — initializes Args, builds the
// initial Coordinator + ServerState, opens the control socket, and
// runs the accept-and-dispatch loop forever.
// `parse_args` parses the command-line into Args.
// `derive_session_socket_path` / `derive_event_socket_path` are
// small helpers that derive companion socket paths from the
// primary control-socket path.
//
// Pure relocation. Bodies byte-for-byte identical; visibility
// widened from file-private to `pub(crate)` so main.rs's `fn main()`
// shell can call into `server::lifecycle::run`.

use super::super::*;

pub(crate) fn run() -> Result<(), String> {
    // Increase socket receive buffer defaults — needed for AF_XDP copy mode
    // to avoid drops when the kernel backlog is large.
    for sysctl in &[
        "/proc/sys/net/core/rmem_default",
        "/proc/sys/net/core/rmem_max",
    ] {
        if let Err(e) = fs::write(sysctl, "16777216") {
            eprintln!("warn: set {sysctl}: {e}");
        } else {
            eprintln!("set {sysctl}=16777216");
        }
    }
    let args = parse_args()?;
    // Enable NAPI busy polling sysctls only in busy-poll mode.
    // In interrupt mode, skip these so the kernel uses normal interrupt delivery.
    if args.poll_mode == PollMode::BusyPoll {
        for (path, val) in &[
            ("/proc/sys/net/core/busy_poll", "50"),
            ("/proc/sys/net/core/busy_read", "50"),
        ] {
            if let Err(e) = fs::write(path, val) {
                eprintln!("warn: set {path}: {e}");
            } else {
                eprintln!("set {path}={val}");
            }
        }
    } else {
        eprintln!("xpf-userspace-dp: interrupt mode — skipping busy_poll sysctls");
    }
    if let Some(parent) = Path::new(&args.control_socket).parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create control dir: {e}"))?;
    }
    if let Some(parent) = Path::new(&args.state_file).parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create state dir: {e}"))?;
    }
    let _ = fs::remove_file(&args.control_socket);
    let session_socket = derive_session_socket_path(&args.control_socket);
    let _ = fs::remove_file(&session_socket);

    let listener = UnixListener::bind(&args.control_socket)
        .map_err(|e| format!("listen {}: {e}", args.control_socket))?;
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("set nonblocking listener: {e}"))?;

    let session_listener = UnixListener::bind(&session_socket)
        .map_err(|e| format!("listen session {}: {e}", session_socket))?;
    session_listener
        .set_nonblocking(true)
        .map_err(|e| format!("set nonblocking session listener: {e}"))?;
    eprintln!("xpf-userspace-dp: session socket at {}", session_socket);

    let state_writer = Arc::new(StateWriter::new());
    let running = Arc::new(AtomicBool::new(true));
    let state = Arc::new(Mutex::new(ServerState {
        status: ProcessStatus {
            pid: std::process::id() as i32,
            config_snapshot_protocol_version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
            inject_packet_tuple_protocol_version: INJECT_PACKET_TUPLE_PROTOCOL_VERSION,
            started_at: Utc::now(),
            control_socket: args.control_socket.clone(),
            state_file: args.state_file.clone(),
            workers: args.workers,
            ring_entries: args.ring_entries,
            helper_mode: "rust-afxdp-bootstrap".to_string(),
            io_uring_planned: true,
            io_uring_active: false,
            io_uring_mode: String::new(),
            io_uring_last_error: String::new(),
            enabled: false,
            forwarding_armed: false,
            capabilities: UserspaceCapabilities::default(),
            last_snapshot_generation: 0,
            last_fib_generation: 0,
            last_snapshot_at: None,
            interface_addresses: 0,
            neighbor_entries: 0,
            session_table_entries: 0,
            max_sessions: 0,
            nat_reverse_key_collisions: 0,
            session_create_drops: 0,
            session_install_admission_refused: 0,
            session_install_partial: 0,
            flow_cache_capacity: 0,
            neighbor_cache_capacity: 0,
            neighbor_generation: 0,
            route_entries: 0,
            worker_heartbeats: Vec::new(),
            worker_runtime: Vec::new(),
            cos_no_owner_binding_drops_total: 0,
            neighbor_warm_drops_total: 0,
            neighbor_warm_disconnected_total: 0,
            neg_neigh_fast_fail_total: 0,
            pending_neigh_duplicate_drops_total: 0,
            pending_neigh_decap_drops_total: 0,
            pending_neigh_capacity_drops_total: 0,
            session_publish_errors_total: 0,
            dnat_publish_errors_total: 0,
            nat_reverse_key_shared_displacements_total: 0,
            worker_command_queue_poison_recoveries: 0,
            gre_decap_ecn_illegal_drops_total: 0,
            wg_decap_ecn_illegal_drops_total: 0,
            gre_encap_df_oversize_drops_total: 0,
            gre_decap_checksum_invalid_drops_total: 0,
            time_exceeded_rate_limited_total: 0,
            packet_too_big_rate_limited_total: 0,
            reject_rate_limited_total: 0,
            dynamic_neighbor_keys: Vec::new(),
            neighbor_resolver_queue_depth: 0,
            neighbor_resolver_enqueue_drops_total: 0,
            neighbor_resolver_disconnected_total: 0,
            neighbor_resolver_get_attempts_total: 0,
            neighbor_resolver_get_resolved_total: 0,
            neighbor_resolver_probe_on_stale_total: 0,
            neighbor_resolver_get_failures_total: 0,
            neighbor_resolver_epoch_rejects_total: 0,
            neighbor_pending_dwell_buckets: Vec::new(),
            neighbor_pending_dwell_sum_ns: 0,
            neighbor_pending_dwell_count: 0,
            neighbor_resolver_get_rtt_buckets: Vec::new(),
            neighbor_resolver_get_rtt_sum_ns: 0,
            neighbor_resolver_get_rtt_count: 0,
            neighbor_pending_timeout_drops_total: 0,
            neighbor_pending_max_depth: 0,
            neighbor_resolver_get_backoff_attempts_total: 0,
            neighbor_netlink_enobufs_total: 0,
            neighbor_netlink_redumps_total: 0,
            neighbor_netlink_redump_upserts_total: 0,
            neighbor_pending_keys: 0,
            neg_neigh_keys: 0,
            // #1865: WG telemetry rows arrive on the first
            // refresh_status; empty start keeps the wire omitted.
            wg_tunnels: Vec::new(),
            per_binding: Vec::new(),
            flow_worker_map: Vec::new(),
            flow_worker_map_truncated: false,
            cos_active_flow_counts: Vec::new(),
            cos_active_flow_counts_truncated: false,
            ha_groups: Vec::new(),
            fabrics: Vec::new(),
            queues: Vec::new(),
            bindings: Vec::new(),
            recent_session_deltas: Vec::new(),
            recent_exceptions: Vec::new(),
            cos_interfaces: Vec::new(),
            policy_rule_counters: Vec::new(),
            nat_rule_counters: Vec::new(),
            filter_term_counters: Vec::new(),
            three_color_policer_counters: Vec::new(),
            source_nat_pools: Vec::new(),
            last_resolution: None,
            slow_path: SlowPathStatus::default(),
            debug_worker_threads: 0,
            debug_identity_slots: 0,
            debug_live_slots: 0,
            debug_planned_workers: 0,
            debug_planned_bindings: 0,
            debug_reconcile_calls: 0,
            debug_reconcile_stage: String::new(),
            event_stream_connected: false,
            event_stream_seq: 0,
            event_stream_acked: 0,
            event_stream_sent: 0,
            event_stream_dropped: 0,
            event_stream_write_stalls: 0,
            event_stream_replay_evictions: 0,
            event_stream_session_close_sent: 0,
            event_stream_session_close_dropped: 0,
            event_stream_session_create_sent: 0,
            event_stream_session_create_dropped: 0,
            last_cache_flush_at: 0,
        },
        snapshot: None,
        afxdp: {
            let mut c = afxdp::Coordinator::new();
            c.poll_mode = args.poll_mode;
            c
        },
        state_writer: state_writer.clone(),
    }));
    eprintln!("xpf-userspace-dp: poll_mode={:?}", args.poll_mode);

    // Start the event stream sender (connects to daemon's event listener socket).
    {
        let event_socket_path = derive_event_socket_path(&args.control_socket);
        let mut guard = state.lock().expect("state poisoned");
        guard.afxdp.start_event_stream(&event_socket_path);
        eprintln!(
            "xpf-userspace-dp: event stream targeting {}",
            event_socket_path
        );
    }

    {
        let running = running.clone();
        ctrlc::set_handler(move || {
            running.store(false, Ordering::SeqCst);
        })
        .map_err(|e| format!("install ctrlc handler: {e}"))?;
    }

    write_state(&args.state_file, &state)?;

    // Spawn a dedicated thread for the session socket so session installs
    // (HA sync path) proceed concurrently with main socket operations
    // (status polls, snapshot publishes). The shared `state` mutex already
    // protects concurrent access. Fixes #452.
    let session_thread = {
        let state = state.clone();
        let running = running.clone();
        let state_file = args.state_file.clone();
        thread::Builder::new()
            .name("session-socket".to_string())
            .spawn(move || {
                while running.load(Ordering::SeqCst) {
                    match session_listener.accept() {
                        Ok((stream, _)) => {
                            // Log handle_stream failures rather than discarding
                            // them: a request that fails to decode (e.g. a
                            // wire-type mismatch) closes the socket with no
                            // response, and the Go side sees only a bare EOF.
                            // Surfacing the error here turns a silent
                            // multi-session debugging chase into one log line
                            // (#1961).
                            if let Err(err) =
                                handle_stream(stream, &state_file, state.clone(), running.clone())
                            {
                                eprintln!("xpf-userspace-dp: session request failed: {err}");
                            }
                        }
                        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(err) => {
                            eprintln!("xpf-userspace-dp: accept session: {err}");
                            continue;
                        }
                    }
                }
            })
            .map_err(|e| format!("spawn session thread: {e}"))?
    };

    while running.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                // See the session-socket note above: surface decode/handler
                // failures instead of discarding them. This is the socket that
                // carries apply_snapshot, where a wire-type mismatch silently
                // left the helper disabled and forwarding nothing (#1961).
                if let Err(err) =
                    handle_stream(stream, &args.state_file, state.clone(), running.clone())
                {
                    eprintln!("xpf-userspace-dp: control request failed: {err}");
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(err) => return Err(format!("accept: {err}")),
        }
    }

    // Wait for the session thread to finish.
    if let Err(panic) = session_thread.join() {
        eprintln!("xpf-userspace-dp: session thread panicked: {panic:?}");
    }
    {
        let mut guard = state.lock().expect("state poisoned");
        guard.afxdp.stop_with_event_stream();
        refresh_status(&mut guard);
    }
    afxdp::remove_kernel_rst_suppression();
    write_state(&args.state_file, &state)?;
    let _ = fs::remove_file(&args.control_socket);
    let _ = fs::remove_file(&session_socket);
    Ok(())
}

/// Derive the session socket path from the control socket path.
/// `/run/xpf/userspace-dp.sock` -> `/run/xpf/userspace-dp-sessions.sock`
pub(crate) fn derive_session_socket_path(control_socket: &str) -> String {
    match control_socket.rsplit_once('/') {
        Some((dir, _)) => format!("{}/userspace-dp-sessions.sock", dir),
        None => "userspace-dp-sessions.sock".to_string(),
    }
}

/// Derive the event socket path from the control socket path.
/// `/run/xpf/control.sock` -> `/run/xpf/userspace-dp-events.sock`
pub(crate) fn derive_event_socket_path(control_socket: &str) -> String {
    match control_socket.rsplit_once('/') {
        Some((dir, _)) => format!("{dir}/userspace-dp-events.sock"),
        None => "userspace-dp-events.sock".to_string(),
    }
}

/// #2524: parse and bound the `--ring-entries` CLI value. Accepts a power
/// of two in [1..MAX_RING_ENTRIES]; otherwise returns a clean startup error
/// so an out-of-range value cannot drive an enormous per-binding UMEM
/// preallocation (binding_frame_count_for_driver ~3×ring_entries frames).
/// Independent backstop for the Go commit-time gate (ValidateRingEntries).
fn validate_ring_entries_arg(val: &str) -> Result<usize, String> {
    let parsed = val
        .parse::<usize>()
        .map_err(|e| format!("parse --ring-entries: {e}"))?;
    let max = crate::afxdp::MAX_RING_ENTRIES as usize;
    if parsed < 1 || parsed > max {
        return Err(format!(
            "--ring-entries out of range [1..{max}] (got {parsed})"
        ));
    }
    if parsed & (parsed - 1) != 0 {
        return Err(format!(
            "--ring-entries must be a power of two in [1..{max}] (got {parsed})"
        ));
    }
    Ok(parsed)
}

pub(crate) fn parse_args() -> Result<Args, String> {
    let mut control_socket = env::temp_dir()
        .join("xpf-userspace-dp")
        .join("control.sock")
        .to_string_lossy()
        .to_string();
    let mut state_file = env::temp_dir()
        .join("xpf-userspace-dp")
        .join("state.json")
        .to_string_lossy()
        .to_string();
    let mut workers = 1usize;
    let mut ring_entries = 4096usize;
    let mut poll_mode = PollMode::BusyPoll;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        let val = args
            .next()
            .ok_or_else(|| format!("missing value for argument {arg}"))?;
        match arg.as_str() {
            "--control-socket" => control_socket = val,
            "--state-file" => state_file = val,
            "--workers" => {
                workers = val
                    .parse::<usize>()
                    .map_err(|e| format!("parse --workers: {e}"))?
                    .max(1)
            }
            // #2524: fail-closed at the CLI boundary — reject an
            // out-of-range or non-power-of-two value with a clean startup
            // error instead of letting it drive an enormous per-binding
            // UMEM preallocation. Mirrors the Go commit gate (pkg/config
            // ValidateRingEntries, MaxRingEntries).
            "--ring-entries" => ring_entries = validate_ring_entries_arg(&val)?,
            "--poll-mode" => poll_mode = PollMode::from_str(&val),
            other => return Err(format!("unknown argument {other}")),
        }
    }

    Ok(Args {
        control_socket,
        state_file,
        workers,
        ring_entries,
        poll_mode,
    })
}

#[cfg(test)]
mod ring_entries_tests {
    use super::validate_ring_entries_arg;

    #[test]
    fn accepts_powers_of_two_in_range() {
        for v in ["1", "2", "1024", "4096", "8192", "16384"] {
            assert!(
                validate_ring_entries_arg(v).is_ok(),
                "expected {v} to be accepted"
            );
        }
    }

    #[test]
    fn rejects_over_max() {
        // 16385 = max+1; 32768 / 65536 powers of two above the ceiling.
        for v in ["16385", "32768", "65536"] {
            let err = validate_ring_entries_arg(v).unwrap_err();
            assert!(err.contains("out of range"), "got: {err}");
        }
    }

    #[test]
    fn rejects_non_power_of_two() {
        for v in ["3", "1000", "1023", "12345"] {
            let err = validate_ring_entries_arg(v).unwrap_err();
            assert!(err.contains("power of two"), "got: {err}");
        }
    }

    #[test]
    fn rejects_zero_and_garbage() {
        assert!(validate_ring_entries_arg("0").is_err());
        assert!(validate_ring_entries_arg("asd").is_err());
    }
}
