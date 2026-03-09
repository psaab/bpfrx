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
    #[serde(rename = "queue_ready", default)]
    queue_ready: String,
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
                    let existing_queues = guard.status.queues.clone();
                    let replanned = replan_queues(
                        guard.snapshot.as_ref(),
                        guard.status.workers,
                        &existing_queues,
                    );
                    guard.status.queues = replanned;
                    refresh_status(&mut guard);
                    persist_state = true;
                } else {
                    response.ok = false;
                    response.error = "missing snapshot".to_string();
                }
            }
            "set_queue_state" => {
                if let Some(queue_req) = request.queue {
                    if let Some(queue) = guard
                        .status
                        .queues
                        .iter_mut()
                        .find(|q| q.queue_id == queue_req.queue_id)
                    {
                        queue.registered = queue_req.registered;
                        queue.ready = queue_req.ready && queue_req.registered;
                        queue.last_change = Some(Utc::now());
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
    state.status.enabled = state.status.queues.iter().any(|q| q.registered && q.ready);
}

fn replan_queues(
    snapshot: Option<&ConfigSnapshot>,
    workers: usize,
    existing: &[QueueStatus],
) -> Vec<QueueStatus> {
    let mut candidates: Vec<(String, usize)> = Vec::new();
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
                candidates.push((linux_name, rx_queues));
            }
        }
    }
    let mut queue_ifaces: BTreeMap<u32, Vec<String>> = BTreeMap::new();
    if !candidates.is_empty() {
        let queue_count = candidates.iter().map(|(_, rx)| *rx).min().unwrap_or(0);
        let interfaces = candidates
            .iter()
            .map(|(name, _)| name.clone())
            .collect::<Vec<_>>();
        for qid in 0..queue_count {
            queue_ifaces.insert(qid as u32, interfaces.clone());
        }
    }
    replan_queues_from_layout(workers, existing, queue_ifaces)
}

fn replan_queues_from_layout(
    workers: usize,
    existing: &[QueueStatus],
    queue_ifaces: BTreeMap<u32, Vec<String>>,
) -> Vec<QueueStatus> {
    let mut existing_by_queue = BTreeMap::new();
    for q in existing {
        existing_by_queue.insert(q.queue_id, q.clone());
    }
    let mut out = Vec::with_capacity(queue_ifaces.len());
    for (queue_id, interfaces) in queue_ifaces {
        let mut queue = existing_by_queue.remove(&queue_id).unwrap_or_default();
        queue.queue_id = queue_id;
        queue.worker_id = queue_id % workers.max(1) as u32;
        queue.interfaces = interfaces;
        queue.registered = !queue.interfaces.is_empty();
        if !queue.registered {
            queue.ready = false;
        }
        if queue.last_change.is_none() {
            queue.last_change = Some(Utc::now());
        }
        out.push(queue);
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
        let mut layout = BTreeMap::new();
        layout.insert(0, vec!["ge-0-0-1".to_string()]);
        layout.insert(1, vec!["xe-0-0-0".to_string()]);
        let queues = replan_queues_from_layout(2, &[], layout);
        assert!(queues.iter().all(|q| {
            q.interfaces.iter().all(|name| {
                name.starts_with("ge-") || name.starts_with("xe-") || name.starts_with("et-")
            })
        }));
        assert!(queues.iter().all(|q| q.registered));
    }

    #[test]
    fn queue_planner_preserves_existing_state() {
        let existing = vec![QueueStatus {
            queue_id: 0,
            worker_id: 0,
            interfaces: vec!["ge-0-0-1".to_string()],
            registered: true,
            ready: true,
            last_change: Some(Utc::now()),
        }];
        let mut layout = BTreeMap::new();
        layout.insert(0, vec!["ge-0-0-1".to_string()]);
        let queues = replan_queues_from_layout(1, &existing, layout);
        if let Some(q0) = queues.iter().find(|q| q.queue_id == 0) {
            assert!(q0.registered);
            assert!(q0.ready);
        } else {
            panic!("queue 0 missing");
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
        let queues = replan_queues(Some(&snapshot), 2, &[]);
        assert_eq!(queues.len(), 2);
        for (idx, q) in queues.iter().enumerate() {
            assert_eq!(q.queue_id, idx as u32);
            assert_eq!(
                q.interfaces,
                vec!["ge-0-0-1".to_string(), "ge-0-0-2".to_string()]
            );
            assert!(q.registered);
        }
    }
}
