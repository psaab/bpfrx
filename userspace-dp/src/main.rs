mod afxdp;
mod event_stream;
mod filter;
mod flowexport;
mod nat;
mod nat64;
mod nptv6;
mod policy;
mod prefix;
mod prefix_set;
mod screen;
mod session;
mod slowpath;
#[cfg(test)]
mod test_zone_ids;
mod state_writer;
#[allow(dead_code)]
mod xsk_ffi;

mod protocol;
mod server;
use server::handle_stream;

use afxdp::SyncedSessionEntry;
use chrono::Utc;
use protocol::*;
use serde::Serialize;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use state_writer::StateWriter;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollMode {
    BusyPoll,
    Interrupt,
}

impl PollMode {
    fn from_str(s: &str) -> Self {
        match s {
            "interrupt" => PollMode::Interrupt,
            _ => PollMode::BusyPoll,
        }
    }
}

#[derive(Debug)]
struct Args {
    control_socket: String,
    state_file: String,
    workers: usize,
    ring_entries: usize,
    poll_mode: PollMode,
}

struct ServerState {
    status: ProcessStatus,
    snapshot: Option<ConfigSnapshot>,
    afxdp: afxdp::Coordinator,
    state_writer: Arc<StateWriter>,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("xpf-userspace-dp: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
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
            neighbor_generation: 0,
            route_entries: 0,
            worker_heartbeats: Vec::new(),
            worker_runtime: Vec::new(),
            cos_no_owner_binding_drops_total: 0,
            per_binding: Vec::new(),
            ha_groups: Vec::new(),
            fabrics: Vec::new(),
            queues: Vec::new(),
            bindings: Vec::new(),
            recent_session_deltas: Vec::new(),
            recent_exceptions: Vec::new(),
            cos_interfaces: Vec::new(),
            filter_term_counters: Vec::new(),
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
                            let _ =
                                handle_stream(stream, &state_file, state.clone(), running.clone());
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
                let _ = handle_stream(stream, &args.state_file, state.clone(), running.clone());
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
fn derive_session_socket_path(control_socket: &str) -> String {
    match control_socket.rsplit_once('/') {
        Some((dir, _)) => format!("{}/userspace-dp-sessions.sock", dir),
        None => "userspace-dp-sessions.sock".to_string(),
    }
}

/// Derive the event socket path from the control socket path.
/// `/run/xpf/control.sock` -> `/run/xpf/userspace-dp-events.sock`
fn derive_event_socket_path(control_socket: &str) -> String {
    match control_socket.rsplit_once('/') {
        Some((dir, _)) => format!("{dir}/userspace-dp-events.sock"),
        None => "userspace-dp-events.sock".to_string(),
    }
}

fn parse_args() -> Result<Args, String> {
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
            "--ring-entries" => {
                ring_entries = val
                    .parse::<usize>()
                    .map_err(|e| format!("parse --ring-entries: {e}"))?
                    .max(1)
            }
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


fn refresh_status(state: &mut ServerState) {
    state.afxdp.refresh_bindings(&mut state.status.bindings);
    let writer_status = state.state_writer.status();
    state.status.io_uring_active = writer_status.active;
    state.status.io_uring_mode = writer_status.mode;
    state.status.io_uring_last_error = writer_status.last_error;
    state.status.interface_addresses = state
        .snapshot
        .as_ref()
        .map(|s| s.interfaces.iter().map(|iface| iface.addresses.len()).sum())
        .unwrap_or(0);
    let (neighbor_entries, neighbor_generation) = state.afxdp.dynamic_neighbor_status();
    state.status.neighbor_entries = neighbor_entries;
    state.status.neighbor_generation = neighbor_generation;
    // #710: cluster-wide aggregate of cross-worker CoS no-owner-binding
    // drops. The per-binding increment site is mechanical; this is the
    // only operator-facing surface for the counter.
    state.status.cos_no_owner_binding_drops_total = state.afxdp.cos_no_owner_binding_drops_total();
    state.status.route_entries = state.snapshot.as_ref().map(|s| s.routes.len()).unwrap_or(0);
    state.status.fabrics = state
        .snapshot
        .as_ref()
        .map(|s| s.fabrics.clone())
        .unwrap_or_default();
    state.status.worker_heartbeats = state.afxdp.worker_heartbeats();
    // #869: per-worker busy/idle runtime telemetry.
    state.status.worker_runtime = state.afxdp.worker_runtime_snapshots();
    state.status.debug_worker_threads = state.afxdp.worker_count();
    state.status.debug_identity_slots = state.afxdp.identity_count();
    state.status.debug_live_slots = state.afxdp.live_count();
    let (planned_workers, planned_bindings) = state.afxdp.planned_counts();
    state.status.debug_planned_workers = planned_workers;
    state.status.debug_planned_bindings = planned_bindings;
    let (reconcile_calls, reconcile_stage) = state.afxdp.reconcile_debug();
    state.status.debug_reconcile_calls = reconcile_calls;
    state.status.debug_reconcile_stage = reconcile_stage;
    state.status.ha_groups = state.afxdp.ha_groups();
    // Report enabled when all bindings are registered+armed (XSKMAP slots
    // populated). The per-queue xsk_rx_confirmed heartbeat gating handles
    // queues whose XSK RQ hasn't been bootstrapped yet — those get XDP_PASS
    // until they bootstrap naturally from background traffic.
    // Previously this required all bindings to be `ready` (first RX packet
    // received), which created a deadlock: ctrl=0 → XDP_PASS → no XSK RX
    // → not ready → ctrl stays 0.
    state.status.enabled = state.status.forwarding_armed
        && state.status.capabilities.forwarding_supported
        && !state.status.bindings.is_empty()
        && state
            .status
            .bindings
            .iter()
            .all(|b| b.registered && b.armed);
    state.status.queues = summarize_queues(&state.status.bindings);
    // #802: focused per-binding ring-pressure snapshot. Projected from
    // the freshly-refreshed BindingStatus entries so this field tracks
    // the same data source the richer `bindings[]` view exposes.
    state.status.per_binding = state
        .status
        .bindings
        .iter()
        .map(BindingCountersSnapshot::from)
        .collect();
    state.status.recent_session_deltas = state.afxdp.recent_session_deltas();
    state.status.recent_exceptions = state.afxdp.recent_exceptions();
    state.status.cos_interfaces = state.afxdp.cos_statuses();
    state.status.filter_term_counters = state.afxdp.filter_term_counters();
    state.status.last_resolution = state.afxdp.last_resolution();
    state.status.slow_path = state.afxdp.slow_path_status().into();
    if let Some(es_stats) = state.afxdp.event_stream_stats() {
        state.status.event_stream_connected = es_stats.connected;
        state.status.event_stream_seq = es_stats.seq;
        state.status.event_stream_acked = es_stats.acked_seq;
        state.status.event_stream_sent = es_stats.sent;
        state.status.event_stream_dropped = es_stats.dropped;
    }
    state.status.last_cache_flush_at = state.afxdp.last_cache_flush_at();
}

fn forwarding_unsupported_error(cap: &UserspaceCapabilities) -> String {
    if cap.unsupported_reasons.is_empty() {
        return "userspace live forwarding is not supported for the current configuration"
            .to_string();
    }
    format!(
        "userspace live forwarding is not supported: {}",
        cap.unsupported_reasons.join("; ")
    )
}

fn build_synced_session_key(
    req: &SessionSyncRequest,
) -> Result<crate::session::SessionKey, String> {
    Ok(crate::session::SessionKey {
        addr_family: req.addr_family,
        protocol: req.protocol,
        src_ip: req
            .src_ip
            .parse()
            .map_err(|e| format!("parse src_ip {}: {e}", req.src_ip))?,
        dst_ip: req
            .dst_ip
            .parse()
            .map_err(|e| format!("parse dst_ip {}: {e}", req.dst_ip))?,
        src_port: req.src_port,
        dst_port: req.dst_port,
    })
}

fn build_synced_session_entry(
    req: &SessionSyncRequest,
    zone_name_to_id: &rustc_hash::FxHashMap<String, u16>,
) -> Result<SyncedSessionEntry, String> {
    let key = build_synced_session_key(req)?;
    let next_hop = if req.next_hop.is_empty() {
        None
    } else {
        Some(
            req.next_hop
                .parse()
                .map_err(|e| format!("parse next_hop {}: {e}", req.next_hop))?,
        )
    };
    let neighbor_mac = parse_session_sync_mac(&req.neighbor_mac)
        .map_err(|e| format!("parse neighbor_mac {}: {e}", req.neighbor_mac))?;
    let src_mac = parse_session_sync_mac(&req.src_mac)
        .map_err(|e| format!("parse src_mac {}: {e}", req.src_mac))?;
    let tx_ifindex = if req.tunnel_endpoint_id != 0 {
        req.tx_ifindex.max(0)
    } else if req.tx_ifindex > 0 {
        req.tx_ifindex
    } else {
        req.egress_ifindex
    };
    let nat_src = if req.nat_src_ip.is_empty() {
        None
    } else {
        Some(
            req.nat_src_ip
                .parse()
                .map_err(|e| format!("parse nat_src_ip {}: {e}", req.nat_src_ip))?,
        )
    };
    let nat_dst = if req.nat_dst_ip.is_empty() {
        None
    } else {
        Some(
            req.nat_dst_ip
                .parse()
                .map_err(|e| format!("parse nat_dst_ip {}: {e}", req.nat_dst_ip))?,
        )
    };
    let nat_src_port = if req.nat_src_port != 0 {
        Some(req.nat_src_port)
    } else {
        None
    };
    let nat_dst_port = if req.nat_dst_port != 0 {
        Some(req.nat_dst_port)
    } else {
        None
    };
    Ok(SyncedSessionEntry {
        protocol: req.protocol,
        tcp_flags: 0,
        key,
        decision: crate::session::SessionDecision {
            resolution: afxdp::ForwardingResolution {
                disposition: if req.egress_ifindex > 0
                    || req.tx_ifindex > 0
                    || req.tunnel_endpoint_id != 0
                {
                    afxdp::ForwardingDisposition::ForwardCandidate
                } else {
                    afxdp::ForwardingDisposition::NoRoute
                },
                local_ifindex: 0,
                egress_ifindex: req.egress_ifindex,
                tx_ifindex,
                tunnel_endpoint_id: req.tunnel_endpoint_id,
                next_hop,
                neighbor_mac,
                src_mac,
                tx_vlan_id: req.tx_vlan_id,
            },
            nat: crate::nat::NatDecision {
                rewrite_src: nat_src,
                rewrite_dst: nat_dst,
                rewrite_src_port: nat_src_port,
                rewrite_dst_port: nat_dst_port,
                ..crate::nat::NatDecision::default()
            },
        },
        metadata: crate::session::SessionMetadata {
            // #919: prefer the wire u16 IDs when populated; fall back
            // to name lookup for older peers that only sent strings.
            ingress_zone: if req.ingress_zone_id != 0 {
                req.ingress_zone_id
            } else {
                zone_name_to_id
                    .get(req.ingress_zone.as_str())
                    .copied()
                    .unwrap_or(0)
            },
            egress_zone: if req.egress_zone_id != 0 {
                req.egress_zone_id
            } else {
                zone_name_to_id
                    .get(req.egress_zone.as_str())
                    .copied()
                    .unwrap_or(0)
            },
            owner_rg_id: req.owner_rg_id,
            fabric_ingress: req.fabric_ingress,
            is_reverse: req.is_reverse,
            nat64_reverse: None,
        },
        origin: crate::session::SessionOrigin::SyncImport,
    })
}

fn parse_session_sync_mac(value: &str) -> Result<Option<[u8; 6]>, String> {
    if value.is_empty() {
        return Ok(None);
    }
    let mut out = [0u8; 6];
    let mut count = 0usize;
    for (i, part) in value.split(':').enumerate() {
        if i >= out.len() {
            return Err("too many octets".to_string());
        }
        out[i] = u8::from_str_radix(part, 16).map_err(|e| e.to_string())?;
        count += 1;
    }
    if count != out.len() {
        return Err("expected 6 octets".to_string());
    }
    Ok(Some(out))
}

fn reconcile_status_bindings(state: &mut ServerState) {
    if !should_run_afxdp(&state.status) {
        state.afxdp.stop();
        state.status.bindings.iter_mut().for_each(|binding| {
            binding.bound = false;
            binding.xsk_registered = false;
            binding.xsk_bind_mode.clear();
            binding.zero_copy = false;
            binding.socket_fd = 0;
            binding.ready = false;
            binding.last_error.clear();
        });
        return;
    }
    let snapshot = state.snapshot.clone();
    let ring_entries = state.status.ring_entries;
    let mut bindings = std::mem::take(&mut state.status.bindings);
    state
        .afxdp
        .reconcile(snapshot.as_ref(), &mut bindings, ring_entries);
    state.status.bindings = bindings;
}

fn should_run_afxdp(status: &ProcessStatus) -> bool {
    status.forwarding_armed && status.capabilities.forwarding_supported
}

fn set_bindings_forwarding_armed(status: &mut ProcessStatus, armed: bool) {
    for binding in &mut status.bindings {
        binding.armed = armed && binding.registered;
        binding.last_change = Some(Utc::now());
    }
}

fn wait_for_binding_settle(state: &mut ServerState, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        refresh_status(state);
        if bindings_settled(&state.status.bindings) || Instant::now() >= deadline {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn bindings_settled(bindings: &[BindingStatus]) -> bool {
    bindings.iter().all(|binding| {
        if !binding.registered {
            return !binding.bound && !binding.xsk_registered;
        }
        binding.ready || !binding.last_error.is_empty()
    })
}

#[cfg(test)]
fn same_binding_plan(current: &ConfigSnapshot, next: &ConfigSnapshot) -> bool {
    snapshot_binding_plan_key(current) == snapshot_binding_plan_key(next)
}

fn snapshot_binding_plan_key(snapshot: &ConfigSnapshot) -> String {
    let mut out = String::new();
    let workers = snapshot
        .userspace
        .get("workers")
        .and_then(|v| v.as_u64())
        .unwrap_or_default();
    let ring_entries = snapshot
        .userspace
        .get("ring_entries")
        .and_then(|v| v.as_u64())
        .unwrap_or_default();
    out.push_str(&format!("workers={workers};ring={ring_entries};"));
    for iface in snapshot
        .interfaces
        .iter()
        .filter(|iface| include_userspace_binding_interface(iface))
    {
        out.push_str(&format!(
            "iface={}/{}/{}/{}/{}/{};",
            iface.name,
            iface.linux_name,
            iface.ifindex,
            iface.parent_ifindex,
            iface.rx_queues,
            iface.tunnel
        ));
    }
    for fab in &snapshot.fabrics {
        out.push_str(&format!(
            "fabric={}/{}/{}/{};",
            fab.name, fab.parent_linux_name, fab.parent_ifindex, fab.rx_queues
        ));
    }
    out
}

fn include_userspace_binding_interface(iface: &InterfaceSnapshot) -> bool {
    if iface.zone.is_empty() {
        return false;
    }
    if iface.tunnel {
        return false;
    }
    if !iface.local_fabric_member.is_empty() {
        return false;
    }
    let base = iface.name.split('.').next().unwrap_or(iface.name.as_str());
    if base.starts_with("fxp") || base.starts_with("em") || base.starts_with("fab") || base == "lo0"
    {
        return false;
    }
    !matches!(iface.zone.as_str(), "mgmt" | "control")
}

fn replan_queues(
    snapshot: Option<&ConfigSnapshot>,
    workers: usize,
    existing: &[BindingStatus],
) -> Vec<BindingStatus> {
    let mut candidates: Vec<(String, usize)> = Vec::new();
    let mut ifindex_by_name: BTreeMap<String, i32> = BTreeMap::new();
    let mut seen_linux: std::collections::HashSet<String> = std::collections::HashSet::new();
    if let Some(snapshot) = snapshot {
        for iface in &snapshot.interfaces {
            if !is_userspace_candidate_interface(&iface.name) {
                continue;
            }
            let linux_name = if iface.linux_name.is_empty() {
                linux_ifname(&iface.name)
            } else {
                iface.linux_name.clone()
            };
            let rx_queues = if iface.rx_queues > 0 {
                iface.rx_queues
            } else {
                rx_queue_count(&linux_name)
            };
            if rx_queues > 0 {
                ifindex_by_name.insert(linux_name.clone(), iface.ifindex);
                seen_linux.insert(linux_name.clone());
                candidates.push((linux_name, rx_queues));
            }
        }
        // Include fabric parent interfaces so the userspace DP can transmit
        // fabric-redirect packets via XSK TX (and receive fabric ingress).
        for fabric in &snapshot.fabrics {
            if fabric.parent_ifindex <= 0 || fabric.parent_linux_name.is_empty() {
                continue;
            }
            if seen_linux.contains(&fabric.parent_linux_name) {
                continue;
            }
            let rx_queues = if fabric.rx_queues > 0 {
                fabric.rx_queues
            } else {
                rx_queue_count(&fabric.parent_linux_name)
            };
            let rx_queues = rx_queues.max(1); // fabric needs at least 1 queue for TX
            ifindex_by_name.insert(fabric.parent_linux_name.clone(), fabric.parent_ifindex);
            seen_linux.insert(fabric.parent_linux_name.clone());
            candidates.push((fabric.parent_linux_name.clone(), rx_queues));
        }
    }
    replan_bindings_from_candidates(workers, existing, candidates, ifindex_by_name)
}

fn replan_bindings_from_candidates(
    workers: usize,
    existing: &[BindingStatus],
    candidates: Vec<(String, usize)>,
    ifindex_by_name: BTreeMap<String, i32>,
) -> Vec<BindingStatus> {
    let mut existing_by_slot = BTreeMap::new();
    for binding in existing {
        existing_by_slot.insert(binding.slot, binding.clone());
    }
    if candidates.is_empty() {
        return Vec::new();
    }
    let queue_count = candidates.iter().map(|(_, rx)| *rx).min().unwrap_or(0);
    let interfaces = candidates
        .iter()
        .map(|(name, _)| name.clone())
        .collect::<Vec<_>>();
    let mut out = Vec::with_capacity(queue_count * interfaces.len());
    let mut slot = 0u32;
    for queue_id in 0..queue_count {
        for iface in &interfaces {
            let mut binding = existing_by_slot.remove(&slot).unwrap_or_default();
            let had_existing = binding.last_change.is_some()
                || binding.registered
                || binding.armed
                || binding.ready
                || binding.bound
                || binding.xsk_registered;
            binding.slot = slot;
            binding.queue_id = queue_id as u32;
            binding.worker_id = (queue_id % workers.max(1)) as u32;
            binding.interface = iface.clone();
            binding.ifindex = *ifindex_by_name.get(iface).unwrap_or(&0);
            if binding.ifindex <= 0 {
                binding.registered = false;
                binding.armed = false;
                binding.ready = false;
            } else if !had_existing {
                binding.registered = true;
            }
            if binding.last_change.is_none() {
                binding.last_change = Some(Utc::now());
            }
            out.push(binding);
            slot += 1;
        }
    }
    out
}

fn summarize_queues(bindings: &[BindingStatus]) -> Vec<QueueStatus> {
    let mut by_queue: BTreeMap<u32, Vec<&BindingStatus>> = BTreeMap::new();
    for binding in bindings {
        by_queue.entry(binding.queue_id).or_default().push(binding);
    }
    let mut out = Vec::with_capacity(by_queue.len());
    for (queue_id, group) in by_queue {
        let worker_id = group.first().map(|b| b.worker_id).unwrap_or(0);
        let interfaces = group
            .iter()
            .map(|b| b.interface.clone())
            .collect::<Vec<_>>();
        let registered = !group.is_empty() && group.iter().all(|b| b.registered);
        let armed = !group.is_empty() && group.iter().all(|b| b.registered && b.armed);
        let ready = !group.is_empty() && group.iter().all(|b| b.registered && b.ready);
        let last_change = group.iter().filter_map(|b| b.last_change).max();
        out.push(QueueStatus {
            queue_id,
            worker_id,
            interfaces,
            registered,
            armed,
            ready,
            last_change,
        });
    }
    out
}

fn is_userspace_candidate_interface(name: &str) -> bool {
    name.starts_with("ge-") || name.starts_with("xe-") || name.starts_with("et-")
}

fn linux_ifname(name: &str) -> String {
    name.replace('/', "-")
}

fn rx_queue_count(name: &str) -> usize {
    let path = format!("/sys/class/net/{name}/queues");
    let Ok(entries) = fs::read_dir(path) else {
        return 0;
    };
    let count = entries
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|entry| entry.starts_with("rx-"))
        .count();
    count.max(1)
}

fn write_state(state_file: &str, state: &Arc<Mutex<ServerState>>) -> Result<(), String> {
    #[derive(Serialize)]
    struct Payload<'a> {
        status: &'a ProcessStatus,
        snapshot: &'a Option<ConfigSnapshot>,
    }

    let mut guard = state.lock().expect("state poisoned");
    refresh_status(&mut guard);
    let payload = Payload {
        status: &guard.status,
        snapshot: &guard.snapshot,
    };
    let data = serde_json::to_vec_pretty(&payload).map_err(|e| format!("encode state: {e}"))?;
    let mut bytes = data;
    bytes.push(b'\n');
    guard
        .state_writer
        .persist(state_file, bytes)
        .map_err(|e| format!("write state file: {e}"))?;
    Ok(())
}

#[cfg(test)]
#[path = "main_tests.rs"]
mod tests;
