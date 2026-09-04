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

// Target for the kernel socket-buffer sysctls, in bytes. MUST match the Go
// control plane's `tuneSocketBuffers` target (`pkg/dataplane/userspace/
// process.go`, `const desired = 67108864`). Both components raise these
// host-global sysctls so AF_XDP copy-mode sockets can receive at line rate;
// keeping the targets identical means whichever runs second is a no-op rather
// than a fight (#2970).
const SOCKBUF_TARGET: i64 = 67108864; // 64 MiB

/// Raise-only sysctl computation (#2970): given the current sysctl contents
/// and a target, return `Some(target)` if the target is strictly higher than
/// the current value, otherwise `None` (already >= target, or unparseable —
/// never lower a value an operator or the Go control plane set higher).
///
/// Pure function so it can be unit-tested without touching real `/proc`.
fn raise_only_value(current: &str, target: i64) -> Option<i64> {
    let cur: i64 = current.trim().parse().ok()?;
    if cur >= target { None } else { Some(target) }
}

/// Apply `raise_only_value` to a real sysctl path: read the current value and
/// only write the target when it would raise (never lower). Host-global
/// rmem/wmem ceilings must never be clobbered downward — the Go control plane
/// already raises these to 64 MiB before launching us, and an operator may
/// have tuned them even higher (#2970).
fn raise_sysctl(path: &str, target: i64) {
    let current = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("warn: read {path}: {e}");
            return;
        }
    };
    match raise_only_value(&current, target) {
        Some(val) => {
            if let Err(e) = fs::write(path, val.to_string()) {
                eprintln!("warn: set {path}: {e}");
            } else {
                eprintln!("set {path}={val} (raised from {})", current.trim());
            }
        }
        None => {
            eprintln!("keep {path}={} (>= target {target})", current.trim());
        }
    }
}

/// Human-readable file-type label for a diagnostic, so a refusal names what
/// was actually found at the path rather than a bare errno.
fn describe_file_type(ft: &std::fs::FileType) -> &'static str {
    use std::os::unix::fs::FileTypeExt;
    if ft.is_file() {
        "regular file"
    } else if ft.is_dir() {
        "directory"
    } else if ft.is_symlink() {
        "symlink"
    } else if ft.is_fifo() {
        "fifo"
    } else if ft.is_block_device() {
        "block device"
    } else if ft.is_char_device() {
        "char device"
    } else if ft.is_socket() {
        "socket"
    } else {
        "unknown"
    }
}

/// Remove a stale Unix-domain socket at `path`, failing closed on a non-socket
/// (#2974). The helper runs as root and takes `--control-socket` as an
/// argument; the historical behavior was an unconditional `remove_file`, which
/// would silently delete a regular file (or any other object) if the helper
/// were pointed at a wrong path. Guard the unlink:
///   * path absent (`NotFound`) -> `Ok(())` (nothing to remove; bind creates it)
///   * path is a socket -> `remove_file` (clean up a stale socket from a prior
///     run — the normal happy path)
///   * path is anything else (regular file, dir, symlink, fifo, ...) -> refuse
///     and return an error naming the path and observed type, so the caller
///     fails closed instead of destroying it.
///
/// `symlink_metadata` is used so the path's own type is inspected without
/// following symlinks: a symlink reports as `is_symlink()` (not `is_socket()`)
/// and is therefore refused rather than followed — a deliberately conservative
/// fail-closed choice. The subsequent `bind` then surfaces a clear error.
fn remove_stale_socket(path: &str) -> std::io::Result<()> {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    use std::os::unix::fs::FileTypeExt;
    let ft = meta.file_type();
    if ft.is_socket() {
        fs::remove_file(path)
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!(
                "refusing to unlink {path}: existing path is a {}, not a Unix socket",
                describe_file_type(&ft)
            ),
        ))
    }
}

pub(crate) fn run() -> Result<(), String> {
    // Increase socket buffer ceilings — needed for AF_XDP copy mode to avoid
    // drops when the kernel backlog is large. Raise-only: never lower a value
    // the Go control plane (64 MiB) or an operator already set higher (#2970).
    // Cover both rmem and wmem to match the Go side.
    for sysctl in &[
        "/proc/sys/net/core/rmem_default",
        "/proc/sys/net/core/rmem_max",
        "/proc/sys/net/core/wmem_default",
        "/proc/sys/net/core/wmem_max",
    ] {
        raise_sysctl(sysctl, SOCKBUF_TARGET);
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
    // Only unlink a stale Unix socket left by a prior run — never blindly
    // delete a regular file or other object at these privileged paths (#2974).
    // A non-socket aborts bind with a diagnostic instead of being destroyed.
    remove_stale_socket(&args.control_socket)
        .map_err(|e| format!("control socket {}: {e}", args.control_socket))?;
    let session_socket = derive_session_socket_path(&args.control_socket);
    remove_stale_socket(&session_socket)
        .map_err(|e| format!("session socket {session_socket}: {e}"))?;

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
            session_delta_schema_fingerprint:
                crate::protocol::session_delta_schema::session_delta_schema_fingerprint(),
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
            nat_reverse_key_collisions_distinct_src: 0,
            session_create_drops: 0,
            session_install_admission_refused: 0,
            session_install_partial: 0,
            flow_cache_capacity: 0,
            neighbor_cache_capacity: 0,
            neighbor_generation: 0,
            manager_neighbor_generation: 0,
            route_entries: 0,
            worker_heartbeats: Vec::new(),
            worker_runtime: Vec::new(),
            cos_no_owner_binding_drops_total: 0,
            neighbor_warm_drops_total: 0,
            neighbor_warm_disconnected_total: 0,
            neg_neigh_fast_fail_total: 0,
            pending_neigh_duplicate_drops_total: 0,
            pending_neigh_decap_drops_total: 0,
            source_nat_match_consulted_total: 0,
            source_nat_match_matched_total: 0,
            source_nat_match_unavailable_total: 0,
            source_nat_match_no_match_total: 0,
            io_uring_retained_buffers_total: 0,
            io_uring_retained_bytes_total: 0,
            io_uring_write_refused_total: 0,
            io_uring_write_refused_bytes_total: 0,
            pending_neigh_capacity_drops_total: 0,
            dynamic_neighbor_learn_cap_drops_total: 0,
            session_publish_errors_total: 0,
            // #4800 new-flow-install contention surface.
            shared_session_publishes_total: 0,
            owner_rg_filings_declined_total: 0,
            shared_session_publish_lock_acquisitions_total: 0,
            shared_session_publish_lock_contended_total: 0,
            session_replication_upserts_total: 0,
            session_replication_enqueued_total: 0,
            session_replication_lock_contended_total: 0,
            session_replication_queue_depth_sum: 0,
            session_replication_queue_depth_max: 0,
            dnat_publish_errors_total: 0,
            synced_import_cap_drops_total: 0,
            nat_reverse_key_shared_displacements_total: 0,
            // #6751 PR 2/3: interface-mode SNAT identity registry counters.
            interface_snat_pat_collisions_total: 0,
            nat64_frag_cross_domain_misses_total: 0,
            nat64_frag_protocol_alias_misses_total: 0,
            interface_snat_identity_exhaustion_total: 0,
            interface_snat_sync_identity_conflict_drops_total: 0,
            interface_snat_registry_cap_exhaustion_total: 0,
            worker_command_queue_poison_recoveries: 0,
            worker_command_queue_drops: 0,
            shared_session_poison_recoveries: 0,
            session_install_stale_ignored: 0,
            session_delete_stale_ignored: 0,
            session_delete_dropped_released: 0,
            tunnel_purge_reservations_released: 0,
            synced_import_reserve_refused: 0,
            synced_import_unknown_routing_domain: 0,
            synced_import_zone_unresolved: 0,
            synced_import_unpublished: 0,
            synced_reverse_rederived: 0,
            gre_decap_ecn_illegal_drops_total: 0,
            wg_decap_ecn_illegal_drops_total: 0,
            gre_encap_df_oversize_drops_total: 0,
            gre_decap_checksum_invalid_drops_total: 0,
            gre_decap_unsupported_version_refusals_total: 0,
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
            // #3651: per-zone traffic block is empty until the first status
            // refresh reads the helper's zone-counter store.
            zone_counter_layout_version: 0,
            zone_counter_overflow_active: false,
            zone_traffic_counters: Vec::new(),
            // #3651: per-zone flood-event block is empty until the first status
            // refresh reads the helper's flood-counter store.
            flood_counter_layout_version: 0,
            flood_counter_overflow_active: false,
            zone_flood_counters: Vec::new(),
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
            event_stream_invalid_acks: 0,
            event_stream_session_close_sent: 0,
            event_stream_session_close_dropped: 0,
            event_stream_session_create_sent: 0,
            event_stream_session_create_dropped: 0,
            last_cache_flush_at: 0,
            fabric_link_skipped_malformed_total: 0,
            fabric_link_unresolved_peer_total: 0,
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
    // Shutdown cleanup mirrors the startup guard: remove only our own stale
    // sockets, never a non-socket object (#2974). Keep the existing
    // best-effort posture — a cleanup failure logs a warning and does not
    // fail shutdown.
    if let Err(e) = remove_stale_socket(&args.control_socket) {
        eprintln!(
            "xpf-userspace-dp: control socket cleanup {}: {e}",
            args.control_socket
        );
    }
    if let Err(e) = remove_stale_socket(&session_socket) {
        eprintln!("xpf-userspace-dp: session socket cleanup {session_socket}: {e}");
    }
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

#[cfg(test)]
mod stale_socket_guard_tests {
    // #2974 fail-on-revert: the helper must unlink ONLY a stale Unix socket,
    // never a regular file (or other object) at the configured control/session
    // socket path. Before #2974 the startup/shutdown cleanup did an
    // unconditional `fs::remove_file`, which would silently delete a regular
    // file if the root helper were pointed at a wrong path. The regular-file
    // test below goes RED (the file is deleted, no error) if reverted.
    use super::remove_stale_socket;
    use std::fs;
    use std::os::unix::net::UnixListener;

    fn unique_path(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "xpf-2974-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ))
    }

    #[test]
    fn removes_a_real_socket_and_allows_rebind() {
        let path = unique_path("sock");
        let p = path.to_str().unwrap();
        let _ = fs::remove_file(p);
        // Bind a real Unix socket, then drop the listener so only the inode
        // remains — a stale socket from a "prior run".
        let listener = UnixListener::bind(p).expect("bind socket");
        drop(listener);
        assert!(fs::symlink_metadata(p).is_ok(), "socket inode should exist");

        remove_stale_socket(p).expect("stale socket should be removed");

        assert!(
            fs::symlink_metadata(p).is_err(),
            "stale socket must be gone after remove_stale_socket"
        );
        // A subsequent bind must succeed on the freed path (the happy path).
        let relisten = UnixListener::bind(p).expect("rebind after cleanup");
        drop(relisten);
        let _ = fs::remove_file(p);
    }

    #[test]
    fn refuses_to_delete_a_regular_file() {
        let path = unique_path("regfile");
        let p = path.to_str().unwrap();
        fs::write(p, b"precious operator data").expect("write file");

        let err =
            remove_stale_socket(p).expect_err("a regular file must NOT be removed — fail closed");

        // The core regression assertion: the file must still exist.
        assert!(
            fs::symlink_metadata(p).is_ok(),
            "remove_stale_socket must not delete a regular file"
        );
        let body = fs::read_to_string(p).expect("file readable");
        assert_eq!(body, "precious operator data", "file contents intact");
        let msg = err.to_string();
        assert!(
            msg.contains("regular file") && msg.contains(p),
            "diagnostic must name the path and type, got: {msg}"
        );
        let _ = fs::remove_file(p);
    }

    #[test]
    fn missing_path_is_ok() {
        let path = unique_path("absent");
        let p = path.to_str().unwrap();
        let _ = fs::remove_file(p);
        assert!(fs::symlink_metadata(p).is_err(), "path must be absent");
        remove_stale_socket(p).expect("absent path is a no-op Ok");
    }

    #[test]
    fn refuses_to_delete_a_directory() {
        let path = unique_path("dir");
        let p = path.to_str().unwrap();
        let _ = fs::remove_dir_all(p);
        fs::create_dir_all(p).expect("mkdir");

        let err = remove_stale_socket(p).expect_err("a directory must NOT be removed");
        assert!(fs::symlink_metadata(p).is_ok(), "directory must survive");
        assert!(err.to_string().contains("directory"), "got: {err}");
        let _ = fs::remove_dir_all(p);
    }
}

#[cfg(test)]
mod sockbuf_raise_only_tests {
    // #2970 fail-on-revert: the helper must NEVER lower a socket-buffer
    // sysctl below its current value. Before #2970 `run()` unconditionally
    // wrote 16 MiB to rmem_default/rmem_max, clobbering the 64 MiB the Go
    // control plane had just raised them to. These tests pin the raise-only
    // contract: revert to the unconditional write and they go RED.
    use super::{raise_only_value, raise_sysctl, SOCKBUF_TARGET};
    use std::fs;

    // 16 MiB — the value the pre-#2970 helper unconditionally forced.
    const OLD_FORCED: i64 = 16_777_216;

    #[test]
    fn target_matches_go_control_plane() {
        // Must equal the Go `tuneSocketBuffers` desired (64 MiB) so whichever
        // component runs second is a no-op rather than a downgrade.
        assert_eq!(SOCKBUF_TARGET, 67_108_864);
        // And the old forced value is strictly smaller — the whole point.
        assert!(OLD_FORCED < SOCKBUF_TARGET);
    }

    #[test]
    fn does_not_lower_a_higher_existing_value() {
        // Go raised it to 64 MiB; helper must leave it alone.
        assert_eq!(raise_only_value("67108864", SOCKBUF_TARGET), None);
        // Operator tuned it even higher (128 MiB); must not be lowered.
        assert_eq!(raise_only_value("134217728", SOCKBUF_TARGET), None);
        // Exactly at target — no write.
        assert_eq!(raise_only_value(" 67108864\n", SOCKBUF_TARGET), None);
    }

    #[test]
    fn raises_a_lower_value_to_target() {
        // Kernel default 208 KiB → raised to 64 MiB.
        assert_eq!(raise_only_value("212992", SOCKBUF_TARGET), Some(SOCKBUF_TARGET));
        // The pre-#2970 forced 16 MiB is itself below target → would be raised.
        assert_eq!(raise_only_value("16777216", SOCKBUF_TARGET), Some(SOCKBUF_TARGET));
    }

    #[test]
    fn unparseable_current_is_left_alone() {
        assert_eq!(raise_only_value("garbage", SOCKBUF_TARGET), None);
        assert_eq!(raise_only_value("", SOCKBUF_TARGET), None);
    }

    // End-to-end against a real file: the strongest fail-on-revert guard.
    // If `run()`'s sysctl loop is reverted to an unconditional 16 MiB write,
    // a path pre-seeded with 64 MiB would be clobbered to 16 MiB and this
    // assertion fails.
    #[test]
    fn raise_sysctl_preserves_higher_value_on_disk() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "xpf-2970-rmem-{}-{}",
            std::process::id(),
            // distinguish from the lower-value test below
            "hi"
        ));
        let p = path.to_str().unwrap();
        // Simulate the Go control plane having already raised it to 64 MiB.
        fs::write(p, "67108864").unwrap();

        raise_sysctl(p, SOCKBUF_TARGET);

        let after: i64 = fs::read_to_string(p).unwrap().trim().parse().unwrap();
        let _ = fs::remove_file(p);
        assert_eq!(
            after, 67_108_864,
            "raise_sysctl must NOT lower a value the Go side already raised"
        );
        assert_ne!(
            after, OLD_FORCED,
            "regression: helper lowered rmem back to the pre-#2970 16 MiB"
        );
    }

    #[test]
    fn raise_sysctl_raises_a_low_value() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("xpf-2970-rmem-{}-lo", std::process::id()));
        let p = path.to_str().unwrap();
        // Kernel default, well below target.
        fs::write(p, "212992").unwrap();

        raise_sysctl(p, SOCKBUF_TARGET);

        let after: i64 = fs::read_to_string(p).unwrap().trim().parse().unwrap();
        let _ = fs::remove_file(p);
        assert_eq!(after, SOCKBUF_TARGET, "raise_sysctl must raise a low value to target");
    }
}
