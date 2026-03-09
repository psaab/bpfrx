use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
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
struct ConfigSnapshot {
    version: i32,
    generation: u64,
    #[serde(rename = "generated_at")]
    generated_at: DateTime<Utc>,
    summary: SnapshotSummary,
    #[serde(rename = "map_pins", default)]
    map_pins: MapPins,
    #[serde(default)]
    interfaces: Vec<InterfaceSnapshot>,
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
    #[serde(rename = "last_snapshot_at", skip_serializing_if = "Option::is_none")]
    last_snapshot_at: Option<DateTime<Utc>>,
    #[serde(rename = "worker_heartbeats", default)]
    worker_heartbeats: Vec<DateTime<Utc>>,
    #[serde(default)]
    queues: Vec<QueueStatus>,
    #[serde(default)]
    bindings: Vec<BindingStatus>,
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
    #[serde(rename = "last_change", skip_serializing_if = "Option::is_none")]
    last_change: Option<DateTime<Utc>>,
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
    heartbeats: Vec<Arc<AtomicI64>>,
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
            helper_mode: "rust-bootstrap".to_string(),
            io_uring_planned: true,
            enabled: false,
            last_snapshot_generation: 0,
            last_snapshot_at: None,
            worker_heartbeats: Vec::new(),
            queues: Vec::new(),
            bindings: Vec::new(),
        },
        snapshot: None,
        heartbeats: Vec::new(),
    }));

    {
        let running = running.clone();
        ctrlc::set_handler(move || {
            running.store(false, Ordering::SeqCst);
        })
        .map_err(|e| format!("install ctrlc handler: {e}"))?;
    }

    spawn_workers(&state, &running, args.workers);
    write_state(&args.state_file, &state)?;

    while running.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                let running = running.clone();
                let state = state.clone();
                let state_file = args.state_file.clone();
                thread::spawn(move || {
                    let _ = handle_stream(stream, &state_file, state, running);
                });
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(100));
            }
            Err(err) => return Err(format!("accept: {err}")),
        }
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

fn spawn_workers(state: &Arc<Mutex<ServerState>>, running: &Arc<AtomicBool>, count: usize) {
    let mut beats = Vec::with_capacity(count);
    for _ in 0..count {
        let beat = Arc::new(AtomicI64::new(
            Utc::now().timestamp_nanos_opt().unwrap_or(0),
        ));
        beats.push(beat.clone());
        let running = running.clone();
        thread::spawn(move || {
            while running.load(Ordering::SeqCst) {
                beat.store(
                    Utc::now().timestamp_nanos_opt().unwrap_or(0),
                    Ordering::Relaxed,
                );
                thread::sleep(Duration::from_millis(250));
            }
        });
    }
    let mut guard = state.lock().expect("worker state poisoned");
    guard.heartbeats = beats;
    refresh_status(&mut guard);
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
                    guard.status.last_snapshot_at = Some(snapshot.generated_at);
                    guard.snapshot = Some(snapshot);
                    let existing_bindings = guard.status.bindings.clone();
                    let replanned = replan_queues(
                        guard.snapshot.as_ref(),
                        guard.status.workers,
                        &existing_bindings,
                    );
                    guard.status.bindings = replanned;
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
                        binding.ready = queue_req.ready && queue_req.registered;
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
            "shutdown" => {
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
    state.status.worker_heartbeats = collect_heartbeats(&state.heartbeats);
    state.status.enabled = state
        .status
        .bindings
        .iter()
        .any(|b| b.registered && b.ready);
    state.status.queues = summarize_queues(&state.status.bindings);
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

fn collect_heartbeats(beats: &[Arc<AtomicI64>]) -> Vec<DateTime<Utc>> {
    let mut out = Vec::with_capacity(beats.len());
    for beat in beats {
        let ns = beat.load(Ordering::Relaxed);
        let dt = DateTime::<Utc>::from_timestamp_nanos(ns);
        out.push(dt);
    }
    out
}

fn write_state(state_file: &str, state: &Arc<Mutex<ServerState>>) -> Result<(), String> {
    #[derive(Serialize)]
    struct Payload<'a> {
        status: &'a ProcessStatus,
        snapshot: &'a Option<ConfigSnapshot>,
    }

    let guard = state.lock().expect("state poisoned");
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
