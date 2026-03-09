mod afxdp;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct SnapshotSummary {
    #[serde(rename = "host_name")]
    host_name: String,
    #[serde(rename = "dataplane_type")]
    dataplane_type: String,
    #[serde(rename = "interface_count")]
    interface_count: usize,
    #[serde(rename = "zone_count")]
    zone_count: usize,
    #[serde(rename = "policy_count")]
    policy_count: usize,
    #[serde(rename = "scheduler_count")]
    scheduler_count: usize,
    #[serde(rename = "ha_enabled")]
    ha_enabled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct InterfaceSnapshot {
    name: String,
    #[serde(rename = "linux_name", default)]
    linux_name: String,
    #[serde(default)]
    ifindex: i32,
    #[serde(rename = "rx_queues", default)]
    rx_queues: usize,
    #[serde(rename = "local_fabric_member", default)]
    local_fabric_member: String,
    #[serde(rename = "redundancy_group", default)]
    redundancy_group: i32,
    #[serde(rename = "unit_count", default)]
    unit_count: usize,
    #[serde(default)]
    tunnel: bool,
    #[serde(default)]
    mtu: i32,
    #[serde(rename = "hardware_addr", default)]
    hardware_addr: String,
    #[serde(default)]
    addresses: Vec<InterfaceAddressSnapshot>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct InterfaceAddressSnapshot {
    family: String,
    address: String,
    #[serde(default)]
    scope: i32,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct RouteSnapshot {
    table: String,
    family: String,
    destination: String,
    #[serde(rename = "next_hops", default)]
    next_hops: Vec<String>,
    #[serde(default)]
    discard: bool,
    #[serde(rename = "next_table", default)]
    next_table: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct NeighborSnapshot {
    #[serde(default)]
    interface: String,
    #[serde(default)]
    ifindex: i32,
    family: String,
    ip: String,
    #[serde(default)]
    mac: String,
    #[serde(default)]
    state: String,
    #[serde(default)]
    router: bool,
    #[serde(rename = "link_local", default)]
    link_local: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct ConfigSnapshot {
    version: i32,
    generation: u64,
    #[serde(rename = "fib_generation", default)]
    fib_generation: u32,
    #[serde(rename = "generated_at")]
    generated_at: DateTime<Utc>,
    summary: SnapshotSummary,
    #[serde(rename = "map_pins", default)]
    map_pins: MapPins,
    #[serde(default)]
    interfaces: Vec<InterfaceSnapshot>,
    #[serde(default)]
    neighbors: Vec<NeighborSnapshot>,
    #[serde(default)]
    routes: Vec<RouteSnapshot>,
    #[serde(default)]
    userspace: serde_json::Value,
    #[serde(default)]
    config: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct MapPins {
    #[serde(default)]
    ctrl: String,
    #[serde(default)]
    bindings: String,
    #[serde(default)]
    xsk: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct ControlRequest {
    #[serde(rename = "type")]
    request_type: String,
    #[serde(default)]
    snapshot: Option<ConfigSnapshot>,
    #[serde(default)]
    queue: Option<QueueControlRequest>,
    #[serde(default)]
    binding: Option<BindingControlRequest>,
    #[serde(default)]
    packet: Option<InjectPacketRequest>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct ProcessStatus {
    pid: i32,
    #[serde(rename = "started_at")]
    started_at: DateTime<Utc>,
    #[serde(rename = "control_socket")]
    control_socket: String,
    #[serde(rename = "state_file")]
    state_file: String,
    workers: usize,
    #[serde(rename = "ring_entries")]
    ring_entries: usize,
    #[serde(rename = "helper_mode")]
    helper_mode: String,
    #[serde(rename = "io_uring_planned")]
    io_uring_planned: bool,
    #[serde(default)]
    enabled: bool,
    #[serde(rename = "last_snapshot_generation")]
    last_snapshot_generation: u64,
    #[serde(rename = "last_fib_generation", default)]
    last_fib_generation: u32,
    #[serde(rename = "last_snapshot_at", skip_serializing_if = "Option::is_none")]
    last_snapshot_at: Option<DateTime<Utc>>,
    #[serde(rename = "interface_addresses", default)]
    interface_addresses: usize,
    #[serde(rename = "neighbor_entries", default)]
    neighbor_entries: usize,
    #[serde(rename = "route_entries", default)]
    route_entries: usize,
    #[serde(rename = "worker_heartbeats", default)]
    worker_heartbeats: Vec<DateTime<Utc>>,
    #[serde(default)]
    queues: Vec<QueueStatus>,
    #[serde(default)]
    bindings: Vec<BindingStatus>,
    #[serde(rename = "recent_exceptions", default)]
    recent_exceptions: Vec<ExceptionStatus>,
    #[serde(rename = "debug_worker_threads", default)]
    debug_worker_threads: usize,
    #[serde(rename = "debug_identity_slots", default)]
    debug_identity_slots: usize,
    #[serde(rename = "debug_live_slots", default)]
    debug_live_slots: usize,
    #[serde(rename = "debug_planned_workers", default)]
    debug_planned_workers: usize,
    #[serde(rename = "debug_planned_bindings", default)]
    debug_planned_bindings: usize,
    #[serde(rename = "debug_reconcile_calls", default)]
    debug_reconcile_calls: u64,
    #[serde(rename = "debug_reconcile_stage", default)]
    debug_reconcile_stage: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct ControlResponse {
    ok: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<ProcessStatus>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct QueueControlRequest {
    #[serde(rename = "queue_id")]
    queue_id: u32,
    #[serde(default)]
    registered: bool,
    #[serde(default)]
    ready: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct BindingControlRequest {
    slot: u32,
    #[serde(default)]
    registered: bool,
    #[serde(default)]
    ready: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct QueueStatus {
    #[serde(rename = "queue_id")]
    queue_id: u32,
    #[serde(rename = "worker_id")]
    worker_id: u32,
    #[serde(default)]
    interfaces: Vec<String>,
    #[serde(default)]
    registered: bool,
    #[serde(default)]
    ready: bool,
    #[serde(rename = "last_change", skip_serializing_if = "Option::is_none")]
    last_change: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct BindingStatus {
    slot: u32,
    #[serde(rename = "queue_id")]
    queue_id: u32,
    #[serde(rename = "worker_id")]
    worker_id: u32,
    #[serde(default)]
    interface: String,
    #[serde(default)]
    ifindex: i32,
    #[serde(default)]
    registered: bool,
    #[serde(default)]
    ready: bool,
    #[serde(default)]
    bound: bool,
    #[serde(rename = "xsk_registered", default)]
    xsk_registered: bool,
    #[serde(rename = "socket_fd", default)]
    socket_fd: i32,
    #[serde(rename = "rx_packets", default)]
    rx_packets: u64,
    #[serde(rename = "rx_bytes", default)]
    rx_bytes: u64,
    #[serde(rename = "rx_batches", default)]
    rx_batches: u64,
    #[serde(rename = "rx_wakeups", default)]
    rx_wakeups: u64,
    #[serde(rename = "metadata_packets", default)]
    metadata_packets: u64,
    #[serde(rename = "metadata_errors", default)]
    metadata_errors: u64,
    #[serde(rename = "validated_packets", default)]
    validated_packets: u64,
    #[serde(rename = "validated_bytes", default)]
    validated_bytes: u64,
    #[serde(rename = "exception_packets", default)]
    exception_packets: u64,
    #[serde(rename = "config_gen_mismatches", default)]
    config_gen_mismatches: u64,
    #[serde(rename = "fib_gen_mismatches", default)]
    fib_gen_mismatches: u64,
    #[serde(rename = "unsupported_packets", default)]
    unsupported_packets: u64,
    #[serde(rename = "kernel_rx_dropped", default)]
    kernel_rx_dropped: u64,
    #[serde(rename = "kernel_rx_invalid_descs", default)]
    kernel_rx_invalid_descs: u64,
    #[serde(rename = "last_error", default)]
    last_error: String,
    #[serde(rename = "last_change", skip_serializing_if = "Option::is_none")]
    last_change: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct ExceptionStatus {
    timestamp: DateTime<Utc>,
    slot: u32,
    #[serde(rename = "queue_id")]
    queue_id: u32,
    #[serde(rename = "worker_id")]
    worker_id: u32,
    #[serde(default)]
    interface: String,
    #[serde(default)]
    ifindex: i32,
    reason: String,
    #[serde(rename = "packet_length", default)]
    packet_length: u32,
    #[serde(rename = "addr_family", default)]
    addr_family: u8,
    #[serde(default)]
    protocol: u8,
    #[serde(rename = "config_generation", default)]
    config_generation: u64,
    #[serde(rename = "fib_generation", default)]
    fib_generation: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct InjectPacketRequest {
    slot: u32,
    #[serde(rename = "packet_length", default)]
    packet_length: u32,
    #[serde(rename = "addr_family", default)]
    addr_family: u8,
    #[serde(default)]
    protocol: u8,
    #[serde(rename = "config_generation", default)]
    config_generation: u64,
    #[serde(rename = "fib_generation", default)]
    fib_generation: u32,
    #[serde(rename = "metadata_valid", default)]
    metadata_valid: bool,
}

#[derive(Debug)]
struct Args {
    control_socket: String,
    state_file: String,
    workers: usize,
    ring_entries: usize,
}

struct ServerState {
    status: ProcessStatus,
    snapshot: Option<ConfigSnapshot>,
    afxdp: afxdp::Coordinator,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("bpfrx-userspace-dp: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = parse_args()?;
    if let Some(parent) = Path::new(&args.control_socket).parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create control dir: {e}"))?;
    }
    if let Some(parent) = Path::new(&args.state_file).parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create state dir: {e}"))?;
    }
    let _ = fs::remove_file(&args.control_socket);

    let listener = UnixListener::bind(&args.control_socket)
        .map_err(|e| format!("listen {}: {e}", args.control_socket))?;
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("set nonblocking listener: {e}"))?;

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
            enabled: false,
            last_snapshot_generation: 0,
            last_fib_generation: 0,
            last_snapshot_at: None,
            interface_addresses: 0,
            neighbor_entries: 0,
            route_entries: 0,
            worker_heartbeats: Vec::new(),
            queues: Vec::new(),
            bindings: Vec::new(),
            recent_exceptions: Vec::new(),
            debug_worker_threads: 0,
            debug_identity_slots: 0,
            debug_live_slots: 0,
            debug_planned_workers: 0,
            debug_planned_bindings: 0,
            debug_reconcile_calls: 0,
            debug_reconcile_stage: String::new(),
        },
        snapshot: None,
        afxdp: afxdp::Coordinator::new(),
    }));

    {
        let running = running.clone();
        ctrlc::set_handler(move || {
            running.store(false, Ordering::SeqCst);
        })
        .map_err(|e| format!("install ctrlc handler: {e}"))?;
    }

    write_state(&args.state_file, &state)?;

    while running.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                let _ = handle_stream(stream, &args.state_file, state.clone(), running.clone());
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(100));
            }
            Err(err) => return Err(format!("accept: {err}")),
        }
    }
    {
        let mut guard = state.lock().expect("state poisoned");
        guard.afxdp.stop();
        refresh_status(&mut guard);
    }
    write_state(&args.state_file, &state)?;
    let _ = fs::remove_file(&args.control_socket);
    Ok(())
}

fn parse_args() -> Result<Args, String> {
    let mut control_socket = env::temp_dir()
        .join("bpfrx-userspace-dp")
        .join("control.sock")
        .to_string_lossy()
        .to_string();
    let mut state_file = env::temp_dir()
        .join("bpfrx-userspace-dp")
        .join("state.json")
        .to_string_lossy()
        .to_string();
    let mut workers = 1usize;
    let mut ring_entries = 1024usize;

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
            other => return Err(format!("unknown argument {other}")),
        }
    }

    Ok(Args {
        control_socket,
        state_file,
        workers,
        ring_entries,
    })
}

fn handle_stream(
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

    let mut reader = BufReader::new(
        stream
            .try_clone()
            .map_err(|e| format!("clone stream for read: {e}"))?,
    );
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| format!("read request: {e}"))?;
    let request: ControlRequest =
        serde_json::from_str(line.trim_end()).map_err(|e| format!("decode request: {e}"))?;

    let mut response = ControlResponse {
        ok: true,
        error: String::new(),
        status: None,
    };
    let mut persist_state = false;

    {
        let mut guard = state.lock().expect("server state poisoned");
        match request.request_type.as_str() {
            "ping" | "status" => {}
            "apply_snapshot" => {
                if let Some(snapshot) = request.snapshot {
                    guard.status.last_snapshot_generation = snapshot.generation;
                    guard.status.last_fib_generation = snapshot.fib_generation;
                    guard.status.last_snapshot_at = Some(snapshot.generated_at);
                    guard.snapshot = Some(snapshot);
                    let existing_bindings = guard.status.bindings.clone();
                    let replanned = replan_queues(
                        guard.snapshot.as_ref(),
                        guard.status.workers,
                        &existing_bindings,
                    );
                    guard.status.bindings = replanned;
                    let snapshot = guard.snapshot.clone();
                    let ring_entries = guard.status.ring_entries;
                    let mut bindings = std::mem::take(&mut guard.status.bindings);
                    guard
                        .afxdp
                        .reconcile(snapshot.as_ref(), &mut bindings, ring_entries);
                    guard.status.bindings = bindings;
                    refresh_status(&mut guard);
                    persist_state = true;
                } else {
                    response.ok = false;
                    response.error = "missing snapshot".to_string();
                }
            }
            "set_queue_state" => {
                if let Some(queue_req) = request.queue {
                    let mut found = false;
                    for binding in guard
                        .status
                        .bindings
                        .iter_mut()
                        .filter(|b| b.queue_id == queue_req.queue_id)
                    {
                        binding.registered = queue_req.registered;
                        binding.ready = queue_req.ready
                            && queue_req.registered
                            && binding.bound
                            && binding.xsk_registered;
                        binding.last_change = Some(Utc::now());
                        found = true;
                    }
                    if found {
                        refresh_status(&mut guard);
                        persist_state = true;
                    } else {
                        response.ok = false;
                        response.error = format!("unknown queue {}", queue_req.queue_id);
                    }
                } else {
                    response.ok = false;
                    response.error = "missing queue state".to_string();
                }
            }
            "set_binding_state" => {
                if let Some(binding_req) = request.binding {
                    if let Some(binding) = guard
                        .status
                        .bindings
                        .iter_mut()
                        .find(|b| b.slot == binding_req.slot)
                    {
                        binding.registered = binding_req.registered;
                        binding.ready = binding_req.ready
                            && binding_req.registered
                            && binding.bound
                            && binding.xsk_registered;
                        binding.last_change = Some(Utc::now());
                        refresh_status(&mut guard);
                        persist_state = true;
                    } else {
                        response.ok = false;
                        response.error = format!("unknown binding slot {}", binding_req.slot);
                    }
                } else {
                    response.ok = false;
                    response.error = "missing binding state".to_string();
                }
            }
            "inject_packet" => {
                if let Some(packet_req) = request.packet {
                    match guard.afxdp.inject_test_packet(packet_req) {
                        Ok(()) => {
                            refresh_status(&mut guard);
                            persist_state = true;
                        }
                        Err(err) => {
                            response.ok = false;
                            response.error = err;
                        }
                    }
                } else {
                    response.ok = false;
                    response.error = "missing packet injection request".to_string();
                }
            }
            "shutdown" => {
                guard.afxdp.stop();
                running.store(false, Ordering::SeqCst);
                persist_state = true;
            }
            other => {
                response.ok = false;
                response.error = format!("unknown request type {other}");
            }
        }
        refresh_status(&mut guard);
        response.status = Some(guard.status.clone());
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

fn refresh_status(state: &mut ServerState) {
    state.afxdp.refresh_bindings(&mut state.status.bindings);
    state.status.interface_addresses = state
        .snapshot
        .as_ref()
        .map(|s| s.interfaces.iter().map(|iface| iface.addresses.len()).sum())
        .unwrap_or(0);
    state.status.neighbor_entries = state
        .snapshot
        .as_ref()
        .map(|s| s.neighbors.len())
        .unwrap_or(0);
    state.status.route_entries = state.snapshot.as_ref().map(|s| s.routes.len()).unwrap_or(0);
    state.status.worker_heartbeats = state.afxdp.worker_heartbeats();
    state.status.debug_worker_threads = state.afxdp.worker_count();
    state.status.debug_identity_slots = state.afxdp.identity_count();
    state.status.debug_live_slots = state.afxdp.live_count();
    let (planned_workers, planned_bindings) = state.afxdp.planned_counts();
    state.status.debug_planned_workers = planned_workers;
    state.status.debug_planned_bindings = planned_bindings;
    let (reconcile_calls, reconcile_stage) = state.afxdp.reconcile_debug();
    state.status.debug_reconcile_calls = reconcile_calls;
    state.status.debug_reconcile_stage = reconcile_stage;
    state.status.enabled = state
        .status
        .bindings
        .iter()
        .any(|b| b.registered && b.ready);
    state.status.queues = summarize_queues(&state.status.bindings);
    state.status.recent_exceptions = state.afxdp.recent_exceptions();
}

fn replan_queues(
    snapshot: Option<&ConfigSnapshot>,
    workers: usize,
    existing: &[BindingStatus],
) -> Vec<BindingStatus> {
    let mut candidates: Vec<(String, usize)> = Vec::new();
    let mut ifindex_by_name: BTreeMap<String, i32> = BTreeMap::new();
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
                candidates.push((linux_name, rx_queues));
            }
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
            binding.slot = slot;
            binding.queue_id = queue_id as u32;
            binding.worker_id = (queue_id % workers.max(1)) as u32;
            binding.interface = iface.clone();
            binding.ifindex = *ifindex_by_name.get(iface).unwrap_or(&0);
            binding.registered = binding.ifindex > 0;
            if !binding.registered {
                binding.ready = false;
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
        let ready = !group.is_empty() && group.iter().all(|b| b.registered && b.ready);
        let last_change = group.iter().filter_map(|b| b.last_change).max();
        out.push(QueueStatus {
            queue_id,
            worker_id,
            interfaces,
            registered,
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
    fs::write(state_file, [data, vec![b'\n']].concat())
        .map_err(|e| format!("write state file: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_planner_filters_non_data_interfaces() {
        let snapshot = ConfigSnapshot {
            interfaces: vec![
                InterfaceSnapshot {
                    name: "ge-0/0/1".to_string(),
                    linux_name: "ge-0-0-1".to_string(),
                    ifindex: 11,
                    rx_queues: 1,
                    ..Default::default()
                },
                InterfaceSnapshot {
                    name: "xe-0/0/0".to_string(),
                    linux_name: "xe-0-0-0".to_string(),
                    ifindex: 12,
                    rx_queues: 1,
                    ..Default::default()
                },
                InterfaceSnapshot {
                    name: "fab0".to_string(),
                    linux_name: "fab0".to_string(),
                    ifindex: 13,
                    rx_queues: 4,
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let bindings = replan_queues(Some(&snapshot), 2, &[]);
        assert_eq!(bindings.len(), 2);
        assert!(bindings.iter().all(|b| {
            b.interface.starts_with("ge-")
                || b.interface.starts_with("xe-")
                || b.interface.starts_with("et-")
        }));
        assert!(bindings.iter().all(|b| b.registered));
    }

    #[test]
    fn queue_planner_preserves_existing_state() {
        let existing = vec![BindingStatus {
            slot: 0,
            queue_id: 0,
            worker_id: 0,
            interface: "ge-0-0-1".to_string(),
            ifindex: 11,
            registered: true,
            ready: true,
            last_change: Some(Utc::now()),
            ..Default::default()
        }];
        let bindings = replan_bindings_from_candidates(
            1,
            &existing,
            vec![("ge-0-0-1".to_string(), 1)],
            BTreeMap::from([("ge-0-0-1".to_string(), 11)]),
        );
        if let Some(b0) = bindings.iter().find(|b| b.slot == 0) {
            assert!(b0.registered);
            assert!(b0.ready);
        } else {
            panic!("binding 0 missing");
        }
    }

    #[test]
    fn queue_planner_uses_smallest_queue_count() {
        let snapshot = ConfigSnapshot {
            interfaces: vec![
                InterfaceSnapshot {
                    name: "ge-0/0/1".to_string(),
                    linux_name: "ge-0-0-1".to_string(),
                    rx_queues: 4,
                    ..Default::default()
                },
                InterfaceSnapshot {
                    name: "ge-0/0/2".to_string(),
                    linux_name: "ge-0-0-2".to_string(),
                    rx_queues: 2,
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let bindings = replan_queues(Some(&snapshot), 2, &[]);
        assert_eq!(bindings.len(), 4);
        let queues = summarize_queues(&bindings);
        assert_eq!(queues.len(), 2);
        for (idx, q) in queues.iter().enumerate() {
            assert_eq!(q.queue_id, idx as u32);
            assert_eq!(
                q.interfaces,
                vec!["ge-0-0-1".to_string(), "ge-0-0-2".to_string()]
            );
            assert!(!q.registered);
        }
    }
}
