use super::{
    BindingStatus, ConfigSnapshot, ExceptionStatus, HAGroupStatus, InjectPacketRequest,
    InterfaceSnapshot, PacketResolution, SessionDeltaInfo,
};
use crate::nat::{DnatTable, NatDecision, SourceNatRule, StaticNatTable, match_source_nat, parse_source_nat_rules};
use crate::nat64::{Nat64ReverseInfo, Nat64State};
use crate::nptv6::Nptv6State;
use crate::policy::{PolicyAction, PolicyState, evaluate_policy, parse_policy_state};
use crate::screen::{ScreenPacketInfo, ScreenProfile, ScreenState, ScreenVerdict, extract_screen_info};
use crate::prefix::{PrefixV4, PrefixV6};
use crate::session::{
    ForwardSessionMatch, SessionDecision, SessionDelta, SessionDeltaKind, SessionKey,
    SessionLookup, SessionMetadata, SessionTable, reply_matches_forward_nat,
};
use crate::slowpath::{EnqueueOutcome, SlowPathReinjector, SlowPathStatus};
use arc_swap::ArcSwap;
use chrono::Utc;
use core::ffi::{c_int, c_void};
use core::num::NonZeroU32;
use core::ptr::NonNull;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::{BTreeMap, VecDeque};
use std::ffi::CString;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;
use xdpilone::xdp::XdpDesc;
use xdpilone::{BufIdx, IfInfo, Socket, SocketConfig, Umem, UmemConfig, User};

/// Hot-path debug logging — compiled out unless `debug-log` feature is enabled.
#[allow(unused_macros)]
macro_rules! debug_log {
    ($($arg:tt)*) => {
        #[cfg(feature = "debug-log")]
        eprintln!($($arg)*);
    };
}

const USERSPACE_META_MAGIC: u32 = 0x4250_5553;
const USERSPACE_META_VERSION: u16 = 4;
const UMEM_FRAME_SIZE: u32 = 4096;
const UMEM_HEADROOM: u32 = 256;
const RX_BATCH_SIZE: u32 = 256;
const MIN_RESERVED_TX_FRAMES: u32 = 256;
const MAX_RESERVED_TX_FRAMES: u32 = 4096;
const TX_BATCH_SIZE: usize = 256;
const PENDING_TX_LIMIT_MULTIPLIER: usize = 2;
const FILL_BATCH_SIZE: usize = 1024;
const MAX_RX_BATCHES_PER_POLL: usize = 4;
/*
 * Force XDP_COPY mode for AF_XDP sockets. In zero-copy mode on mlx5, XDP_PASS
 * (used for ARP, host-bound management traffic, and fallback paths) permanently
 * consumes fill ring frames — the kernel holds the UMEM frame in an SKB and
 * never returns it to userspace's fill ring. This drains all 12K+ RX frames
 * within seconds of sustained traffic, causing permanent rx_xsk_buff_alloc_err.
 *
 * In copy mode, XDP_PASS operates on kernel DMA buffers, not UMEM frames, so
 * the fill ring is only consumed by XDP_REDIRECT→XSK (which userspace always
 * recycles). The cost is one memcpy per redirected packet.
 *
 * Zero-copy is now restored (#209): the XDP shim replaces all XDP_PASS paths
 * with cpumap redirect (USERSPACE_CPUMAP), which frees the XSK frame
 * immediately while still delivering the packet to the kernel stack.
 * The bind flags try zero-copy first and fall back to copy mode if the
 * driver doesn't support it.
 */
const XSK_BIND_FLAGS_ZEROCOPY: u16 =
    SocketConfig::XDP_BIND_NEED_WAKEUP | SocketConfig::XDP_BIND_ZEROCOPY;
const XSK_BIND_FLAGS_COPY: u16 =
    SocketConfig::XDP_BIND_NEED_WAKEUP | SocketConfig::XDP_BIND_COPY;
const IDLE_SPIN_ITERS: u32 = 256;
const IDLE_SLEEP_US: u64 = 1;
const RX_WAKE_IDLE_POLLS: u32 = 32;
const RX_WAKE_MIN_INTERVAL_NS: u64 = 200_000;
/// Safety-net interval for fill ring wakes when needs_wakeup is clear.
/// Prevents lost-wakeup stalls from the race: commit() → check needs_wakeup
/// (clear) → kernel exhausts cache → sets needs_wakeup → userspace doesn't see it.
const FILL_WAKE_SAFETY_INTERVAL_NS: u64 = 500_000; // 500µs
const HEARTBEAT_UPDATE_INTERVAL_NS: u64 = 250_000_000;
const TX_WAKE_MIN_INTERVAL_NS: u64 = 50_000;
const HEARTBEAT_STALE_AFTER: Duration = Duration::from_secs(5);
const MAX_RECENT_EXCEPTIONS: usize = 32;
const MAX_RECENT_SESSION_DELTAS: usize = 64;
const MAX_PENDING_SESSION_DELTAS: usize = 4096;
const BIND_RETRY_ATTEMPTS: usize = 10;
const BIND_RETRY_DELAY: Duration = Duration::from_millis(50);
const DEFAULT_SLOW_PATH_TUN: &str = "bpfrx-usp0";

type FastMap<K, V> = FxHashMap<K, V>;
type FastSet<T> = FxHashSet<T>;
const HA_WATCHDOG_STALE_AFTER_SECS: u64 = 2;
const FABRIC_ZONE_MAC_MAGIC: u8 = 0xfe;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const PROTO_ICMP: u8 = 1;
const PROTO_ICMPV6: u8 = 58;
const PROTO_GRE: u8 = 47;
const PROTO_ESP: u8 = 50;
const TCP_FLAG_FIN: u8 = 0x01;
const TCP_FLAG_RST: u8 = 0x04;
const TCP_FLAG_PSH: u8 = 0x08;
const TCP_FLAG_SYN: u8 = 0x02;
const SOL_XDP: c_int = 283;
const XDP_OPTIONS: c_int = 8;
const XDP_OPTIONS_ZEROCOPY: u32 = 1;

#[inline]
const fn tx_frame_capacity() -> usize {
    UMEM_FRAME_SIZE as usize
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct UserspaceDpMeta {
    magic: u32,
    version: u16,
    length: u16,
    ingress_ifindex: u32,
    rx_queue_index: u32,
    ingress_vlan_id: u16,
    ingress_zone: u16,
    routing_table: u32,
    l3_offset: u16,
    l4_offset: u16,
    payload_offset: u16,
    pkt_len: u16,
    addr_family: u8,
    protocol: u8,
    tcp_flags: u8,
    meta_flags: u8,
    dscp: u8,
    dscp_rewrite: u8,
    reserved: u16,
    flow_src_port: u16,
    flow_dst_port: u16,
    flow_src_addr: [u8; 16],
    flow_dst_addr: [u8; 16],
    config_generation: u64,
    fib_generation: u32,
    reserved2: u32,
}

#[repr(C)]
struct XdpOptions {
    flags: u32,
}

pub struct Coordinator {
    map_fd: Option<OwnedFd>,
    heartbeat_map_fd: Option<OwnedFd>,
    session_map_fd: Option<OwnedFd>,
    slow_path: Option<Arc<SlowPathReinjector>>,
    last_slow_path_status: SlowPathStatus,
    ha_state: Arc<ArcSwap<BTreeMap<i32, HAGroupRuntime>>>,
    dynamic_neighbors: Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
    shared_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    live: BTreeMap<u32, Arc<BindingLiveState>>,
    identities: BTreeMap<u32, BindingIdentity>,
    workers: BTreeMap<u32, WorkerHandle>,
    forwarding: ForwardingState,
    recent_exceptions: Arc<Mutex<VecDeque<ExceptionStatus>>>,
    recent_session_deltas: Arc<Mutex<VecDeque<SessionDeltaInfo>>>,
    last_resolution: Arc<Mutex<Option<PacketResolution>>>,
    validation: ValidationState,
    last_planned_workers: usize,
    last_planned_bindings: usize,
    reconcile_calls: u64,
    last_reconcile_stage: String,
}

impl Coordinator {
    pub fn new() -> Self {
        Self {
            map_fd: None,
            heartbeat_map_fd: None,
            session_map_fd: None,
            slow_path: None,
            last_slow_path_status: SlowPathStatus::default(),
            ha_state: Arc::new(ArcSwap::from_pointee(BTreeMap::new())),
            dynamic_neighbors: Arc::new(Mutex::new(FastMap::default())),
            shared_sessions: Arc::new(Mutex::new(FastMap::default())),
            shared_nat_sessions: Arc::new(Mutex::new(FastMap::default())),
            live: BTreeMap::new(),
            identities: BTreeMap::new(),
            workers: BTreeMap::new(),
            forwarding: ForwardingState::default(),
            recent_exceptions: Arc::new(Mutex::new(VecDeque::with_capacity(MAX_RECENT_EXCEPTIONS))),
            recent_session_deltas: Arc::new(Mutex::new(VecDeque::with_capacity(
                MAX_RECENT_SESSION_DELTAS,
            ))),
            last_resolution: Arc::new(Mutex::new(None)),
            validation: ValidationState::default(),
            last_planned_workers: 0,
            last_planned_bindings: 0,
            reconcile_calls: 0,
            last_reconcile_stage: "idle".to_string(),
        }
    }

    pub fn stop(&mut self) {
        for handle in self.workers.values_mut() {
            handle.stop.store(true, Ordering::Relaxed);
        }
        for (_, handle) in self.workers.iter_mut() {
            if let Some(join) = handle.join.take() {
                let _ = join.join();
            }
        }
        if let Some(map_fd) = self.map_fd.as_ref() {
            for slot in self.live.keys().copied().collect::<Vec<_>>() {
                let _ = delete_xsk_slot(map_fd.fd, slot);
            }
        }
        if let Some(map_fd) = self.heartbeat_map_fd.as_ref() {
            for slot in self.live.keys().copied().collect::<Vec<_>>() {
                let _ = delete_heartbeat_slot(map_fd.fd, slot);
            }
        }
        self.workers.clear();
        self.identities.clear();
        self.live.clear();
        self.last_slow_path_status = self
            .slow_path
            .as_ref()
            .map(|slow| slow.status())
            .unwrap_or_default();
        self.slow_path = None;
        self.map_fd = None;
        self.heartbeat_map_fd = None;
        self.session_map_fd = None;
        self.forwarding = ForwardingState::default();
        if let Ok(mut neighbors) = self.dynamic_neighbors.lock() {
            neighbors.clear();
        }
        if let Ok(mut sessions) = self.shared_sessions.lock() {
            sessions.clear();
        }
        if let Ok(mut nat_sessions) = self.shared_nat_sessions.lock() {
            nat_sessions.clear();
        }
        if let Ok(mut recent) = self.recent_exceptions.lock() {
            recent.clear();
        }
        if let Ok(mut recent) = self.recent_session_deltas.lock() {
            recent.clear();
        }
        if let Ok(mut last) = self.last_resolution.lock() {
            *last = None;
        }
        self.validation = ValidationState::default();
        self.last_planned_workers = 0;
        self.last_planned_bindings = 0;
        self.last_reconcile_stage = "stopped".to_string();
    }

    pub fn reconcile(
        &mut self,
        snapshot: Option<&ConfigSnapshot>,
        bindings: &mut [BindingStatus],
        ring_entries: usize,
    ) {
        self.reconcile_calls += 1;
        self.last_reconcile_stage = "start".to_string();
        self.stop();
        for binding in bindings.iter_mut() {
            binding.bound = false;
            binding.xsk_registered = false;
            binding.socket_fd = 0;
            binding.rx_packets = 0;
            binding.rx_bytes = 0;
            binding.rx_batches = 0;
            binding.rx_wakeups = 0;
            binding.metadata_packets = 0;
            binding.metadata_errors = 0;
            binding.validated_packets = 0;
            binding.validated_bytes = 0;
            binding.local_delivery_packets = 0;
            binding.forward_candidate_packets = 0;
            binding.route_miss_packets = 0;
            binding.neighbor_miss_packets = 0;
            binding.discard_route_packets = 0;
            binding.next_table_packets = 0;
            binding.exception_packets = 0;
            binding.config_gen_mismatches = 0;
            binding.fib_gen_mismatches = 0;
            binding.unsupported_packets = 0;
            binding.session_hits = 0;
            binding.session_misses = 0;
            binding.session_creates = 0;
            binding.session_expires = 0;
            binding.session_delta_pending = 0;
            binding.session_delta_generated = 0;
            binding.session_delta_dropped = 0;
            binding.session_delta_drained = 0;
            binding.policy_denied_packets = 0;
            binding.snat_packets = 0;
            binding.dnat_packets = 0;
            binding.slow_path_packets = 0;
            binding.slow_path_bytes = 0;
            binding.slow_path_drops = 0;
            binding.slow_path_rate_limited = 0;
            binding.kernel_rx_dropped = 0;
            binding.kernel_rx_invalid_descs = 0;
            binding.last_error.clear();
            binding.ready = false;
        }
        let Some(snapshot) = snapshot else {
            self.last_reconcile_stage = "no_snapshot".to_string();
            return;
        };
        self.validation = ValidationState {
            snapshot_installed: true,
            config_generation: snapshot.generation,
            fib_generation: snapshot.fib_generation,
        };
        self.forwarding = build_forwarding_state(snapshot);
        self.slow_path = match SlowPathReinjector::new(DEFAULT_SLOW_PATH_TUN) {
            Ok(reinjector) => {
                self.last_slow_path_status = reinjector.status();
                Some(Arc::new(reinjector))
            }
            Err(err) => {
                self.last_slow_path_status = SlowPathStatus {
                    last_error: err,
                    ..SlowPathStatus::default()
                };
                None
            }
        };
        let forwarding = Arc::new(self.forwarding.clone());
        if snapshot.map_pins.xsk.is_empty() {
            self.last_reconcile_stage = "missing_xsk_pin".to_string();
            for binding in bindings.iter_mut() {
                if binding.registered {
                    binding.last_error = "missing XSK map pin path".to_string();
                }
            }
            return;
        }
        if snapshot.map_pins.heartbeat.is_empty() {
            self.last_reconcile_stage = "missing_heartbeat_pin".to_string();
            for binding in bindings.iter_mut() {
                if binding.registered {
                    binding.last_error = "missing heartbeat map pin path".to_string();
                }
            }
            return;
        }
        if snapshot.map_pins.sessions.is_empty() {
            self.last_reconcile_stage = "missing_session_pin".to_string();
            for binding in bindings.iter_mut() {
                if binding.registered {
                    binding.last_error = "missing session map pin path".to_string();
                }
            }
            return;
        }
        let map_fd = match OwnedFd::open_bpf_map(&snapshot.map_pins.xsk) {
            Ok(fd) => fd,
            Err(err) => {
                self.last_reconcile_stage = format!("open_xsk_map_failed:{err}");
                for binding in bindings.iter_mut() {
                    if binding.registered {
                        binding.last_error = format!("open XSK map: {err}");
                    }
                }
                return;
            }
        };
        let heartbeat_map_fd = match OwnedFd::open_bpf_map(&snapshot.map_pins.heartbeat) {
            Ok(fd) => fd,
            Err(err) => {
                self.last_reconcile_stage = format!("open_heartbeat_map_failed:{err}");
                for binding in bindings.iter_mut() {
                    if binding.registered {
                        binding.last_error = format!("open heartbeat map: {err}");
                    }
                }
                return;
            }
        };
        let session_map_fd = match OwnedFd::open_bpf_map(&snapshot.map_pins.sessions) {
            Ok(fd) => fd,
            Err(err) => {
                self.last_reconcile_stage = format!("open_session_map_failed:{err}");
                for binding in bindings.iter_mut() {
                    if binding.registered {
                        binding.last_error = format!("open session map: {err}");
                    }
                }
                return;
            }
        };
        let ring_entries = ring_entries.max(64).min(u32::MAX as usize) as u32;
        let mut workers: BTreeMap<u32, Vec<BindingPlan>> = BTreeMap::new();
        for binding in bindings.iter_mut() {
            if !binding.registered || binding.ifindex <= 0 {
                binding.ready = false;
                continue;
            }
            let live = Arc::new(BindingLiveState::new());
            self.live.insert(binding.slot, live.clone());
            let identity = BindingIdentity {
                slot: binding.slot,
                queue_id: binding.queue_id,
                worker_id: binding.worker_id,
                interface: Arc::<str>::from(binding.interface.as_str()),
                ifindex: binding.ifindex,
            };
            self.identities.insert(binding.slot, identity);
            workers
                .entry(binding.worker_id)
                .or_default()
                .push(BindingPlan {
                    status: binding.clone(),
                    live,
                    xsk_map_fd: map_fd.fd,
                    heartbeat_map_fd: heartbeat_map_fd.fd,
                    session_map_fd: session_map_fd.fd,
                    ring_entries,
                    shared_owner: false,
                });
        }
        for plans in workers.values_mut() {
            plans.sort_by_key(|plan| (plan.status.queue_id, plan.status.ifindex, plan.status.slot));
            // Each binding creates its own WorkerUmem (own AF_XDP socket FD).
            // Socket::with_shared() clones the UMEM's FD, so socket == UMEM FD.
            // bind() without SHARED_UMEM directly binds this socket to (ifindex, queue).
            // Each binding is fully independent with its own UMEM/socket/rings.
            // poll() on each binding's device triggers NAPI for that specific queue.
            for plan in plans.iter_mut() {
                plan.shared_owner = true;
            }
        }
        let planned_bindings: usize = workers.values().map(|group| group.len()).sum();
        self.last_planned_workers = workers.len();
        self.last_planned_bindings = planned_bindings;
        self.last_reconcile_stage = format!(
            "planned:workers={}:bindings={}:live={}",
            self.last_planned_workers,
            self.last_planned_bindings,
            self.live.len()
        );
        eprintln!(
            "bpfrx-userspace-dp: reconcile planned_workers={} planned_bindings={} live_slots={}",
            workers.len(),
            planned_bindings,
            self.live.len()
        );
        self.map_fd = Some(map_fd);
        self.heartbeat_map_fd = Some(heartbeat_map_fd);
        self.session_map_fd = Some(session_map_fd);
        let worker_command_queues: BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>> = workers
            .keys()
            .copied()
            .map(|worker_id| (worker_id, Arc::new(Mutex::new(VecDeque::new()))))
            .collect();
        for (worker_id, binding_plans) in workers {
            let plan_count = binding_plans.len();
            let stop = Arc::new(AtomicBool::new(false));
            let heartbeat = Arc::new(AtomicU64::new(monotonic_nanos()));
            let commands = worker_command_queues
                .get(&worker_id)
                .cloned()
                .unwrap_or_else(|| Arc::new(Mutex::new(VecDeque::new())));
            let recent_exceptions = self.recent_exceptions.clone();
            let recent_session_deltas = self.recent_session_deltas.clone();
            let last_resolution = self.last_resolution.clone();
            let slow_path = self.slow_path.clone();
            let shared_sessions = self.shared_sessions.clone();
            let shared_nat_sessions = self.shared_nat_sessions.clone();
            let stop_clone = stop.clone();
            let heartbeat_clone = heartbeat.clone();
            let commands_clone = commands.clone();
            let peer_commands_clone = worker_command_queues
                .iter()
                .filter(|(id, _)| **id != worker_id)
                .map(|(_, queue)| queue.clone())
                .collect::<Vec<_>>();
            let validation = self.validation;
            let forwarding = forwarding.clone();
            let ha_state = self.ha_state.clone();
            let dynamic_neighbors = self.dynamic_neighbors.clone();
            let join = thread::Builder::new()
                .name(format!("bpfrx-userspace-worker-{worker_id}"))
                .spawn(move || {
                    worker_loop(
                        worker_id,
                        binding_plans,
                        validation,
                        forwarding,
                        ha_state,
                        dynamic_neighbors,
                        shared_sessions,
                        shared_nat_sessions,
                        slow_path,
                        recent_exceptions,
                        recent_session_deltas,
                        last_resolution,
                        commands_clone,
                        peer_commands_clone,
                        stop_clone,
                        heartbeat_clone,
                    );
                });
            match join {
                Ok(join) => {
                    eprintln!(
                        "bpfrx-userspace-dp: started worker thread worker_id={} planned_bindings={}",
                        worker_id, plan_count
                    );
                    self.workers.insert(
                        worker_id,
                        WorkerHandle {
                            stop,
                            heartbeat,
                            commands,
                            join: Some(join),
                        },
                    );
                }
                Err(err) => {
                    eprintln!(
                        "bpfrx-userspace-dp: failed to start worker thread worker_id={} err={}",
                        worker_id, err
                    );
                    self.last_reconcile_stage = format!("spawn_worker_failed:{worker_id}:{err}");
                    if let Ok(mut recent) = self.recent_exceptions.lock() {
                        push_recent_exception(
                            &mut recent,
                            ExceptionStatus {
                                timestamp: Utc::now(),
                                reason: format!("spawn_worker_failed:{worker_id}:{err}"),
                                ..ExceptionStatus::default()
                            },
                        );
                    }
                }
            }
        }
        self.last_reconcile_stage = format!(
            "spawned:workers={}:identities={}:live={}",
            self.workers.len(),
            self.identities.len(),
            self.live.len()
        );
        self.refresh_bindings(bindings);
    }

    pub fn recent_exceptions(&self) -> Vec<ExceptionStatus> {
        self.recent_exceptions
            .lock()
            .map(|recent| recent.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn recent_session_deltas(&self) -> Vec<SessionDeltaInfo> {
        self.recent_session_deltas
            .lock()
            .map(|recent| recent.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn last_resolution(&self) -> Option<PacketResolution> {
        self.last_resolution
            .lock()
            .ok()
            .and_then(|last| last.clone())
    }

    pub fn slow_path_status(&self) -> SlowPathStatus {
        self.slow_path
            .as_ref()
            .map(|slow| slow.status())
            .unwrap_or_else(|| self.last_slow_path_status.clone())
    }

    pub fn drain_session_deltas(&self, max: usize) -> Vec<SessionDeltaInfo> {
        let mut remaining = max.max(1);
        let mut out = Vec::new();
        for live in self.live.values() {
            if remaining == 0 {
                break;
            }
            let drained = live.drain_session_deltas(remaining);
            remaining = remaining.saturating_sub(drained.len());
            out.extend(drained);
        }
        out
    }

    pub fn update_ha_state(&self, groups: &[HAGroupStatus]) {
        let mut state = BTreeMap::new();
        for group in groups {
            state.insert(
                group.rg_id,
                HAGroupRuntime {
                    active: group.active,
                    watchdog_timestamp: group.watchdog_timestamp,
                },
            );
        }
        self.ha_state.store(Arc::new(state));
    }

    pub fn ha_groups(&self) -> Vec<HAGroupStatus> {
        self.ha_state
            .load()
            .iter()
            .map(|(rg_id, runtime)| HAGroupStatus {
                rg_id: *rg_id,
                active: runtime.active,
                watchdog_timestamp: runtime.watchdog_timestamp,
            })
            .collect()
    }

    pub fn upsert_synced_session(&self, entry: SyncedSessionEntry) {
        publish_shared_session(&self.shared_sessions, &self.shared_nat_sessions, &entry);
        for handle in self.workers.values() {
            if let Ok(mut pending) = handle.commands.lock() {
                pending.push_back(WorkerCommand::UpsertSynced(entry.clone()));
            }
        }
    }

    pub fn delete_synced_session(&self, key: SessionKey) {
        remove_shared_session(&self.shared_sessions, &self.shared_nat_sessions, &key);
        for handle in self.workers.values() {
            if let Ok(mut pending) = handle.commands.lock() {
                pending.push_back(WorkerCommand::DeleteSynced(key.clone()));
            }
        }
    }

    pub fn worker_heartbeats(&self) -> Vec<chrono::DateTime<Utc>> {
        let now_wall = Utc::now();
        let now_mono = monotonic_nanos();
        self.workers
            .iter()
            .map(|(_, handle)| {
                monotonic_timestamp_to_datetime(
                    handle.heartbeat.load(Ordering::Relaxed),
                    now_mono,
                    now_wall,
                )
                .unwrap_or(now_wall)
            })
            .collect()
    }

    pub fn worker_count(&self) -> usize {
        self.workers.len()
    }

    pub fn identity_count(&self) -> usize {
        self.identities.len()
    }

    pub fn live_count(&self) -> usize {
        self.live.len()
    }

    pub fn planned_counts(&self) -> (usize, usize) {
        (self.last_planned_workers, self.last_planned_bindings)
    }

    pub fn reconcile_debug(&self) -> (u64, String) {
        (self.reconcile_calls, self.last_reconcile_stage.clone())
    }

    pub fn inject_test_packet(&mut self, req: InjectPacketRequest) -> Result<(), String> {
        let binding = self
            .identities
            .get(&req.slot)
            .ok_or_else(|| format!("unknown binding slot {}", req.slot))?;
        let live = self
            .live
            .get(&req.slot)
            .ok_or_else(|| format!("binding slot {} has no live state", req.slot))?;
        let ident = binding.clone();
        let packet_length = req.packet_length.max(64);

        if req.metadata_valid {
            let meta = UserspaceDpMeta {
                magic: USERSPACE_META_MAGIC,
                version: USERSPACE_META_VERSION,
                length: std::mem::size_of::<UserspaceDpMeta>() as u16,
                ingress_ifindex: ident.ifindex as u32,
                rx_queue_index: ident.queue_id,
                pkt_len: packet_length.min(u16::MAX as u32) as u16,
                addr_family: req.addr_family,
                protocol: req.protocol,
                config_generation: req.config_generation,
                fib_generation: req.fib_generation,
                ..UserspaceDpMeta::default()
            };
            live.metadata_packets.fetch_add(1, Ordering::Relaxed);
            let disposition = classify_metadata(meta, self.validation);
            record_disposition(
                &ident,
                live,
                disposition,
                packet_length,
                Some(meta),
                &self.recent_exceptions,
            );
            if disposition == PacketDisposition::Valid && !req.destination_ip.is_empty() {
                if let Ok(dst) = req.destination_ip.parse::<IpAddr>() {
                    let resolution = enforce_ha_resolution(
                        &self.forwarding,
                        &self.ha_state,
                        lookup_forwarding_resolution(&self.forwarding, dst),
                    );
                    record_forwarding_disposition(
                        &ident,
                        live,
                        resolution,
                        packet_length,
                        Some(meta),
                        None,
                        &self.recent_exceptions,
                        &self.last_resolution,
                    );
                    if req.emit_on_wire {
                        let Some(egress) = self.forwarding.egress.get(&resolution.egress_ifindex)
                        else {
                            return Err(format!(
                                "no egress interface metadata for ifindex {}",
                                resolution.egress_ifindex
                            ));
                        };
                        if resolution.disposition != ForwardingDisposition::ForwardCandidate {
                            return Err(format!(
                                "destination is not forwardable via userspace TX: {}",
                                resolution.status(None).disposition
                            ));
                        }
                        let target_slot = self
                            .identities
                            .values()
                            .find(|candidate| {
                                candidate.ifindex == egress.bind_ifindex
                                    && candidate.queue_id == ident.queue_id
                            })
                            .or_else(|| {
                                self.identities
                                    .values()
                                    .find(|candidate| candidate.ifindex == egress.bind_ifindex)
                            })
                            .map(|candidate| candidate.slot)
                            .ok_or_else(|| {
                                format!(
                                    "no bound userspace slot for egress ifindex {}",
                                    egress.bind_ifindex
                                )
                            })?;
                        let target_live = self.live.get(&target_slot).ok_or_else(|| {
                            format!("binding slot {} has no live state", target_slot)
                        })?;
                        let frame = build_injected_packet(&req, dst, resolution, egress)?;
                        target_live.enqueue_tx(TxRequest {
                            bytes: frame,
                            expected_ports: None,
                            expected_addr_family: 0,
                            expected_protocol: 0,
                            flow_key: None,
                        })?;
                    }
                } else {
                    record_exception(
                        &self.recent_exceptions,
                        &ident,
                        "invalid_destination_ip",
                        packet_length,
                        Some(meta),
                        None,
                    );
                }
            } else if req.emit_on_wire {
                return Err("emit-on-wire requires destination-ip and valid metadata".to_string());
            }
            return Ok(());
        }

        live.metadata_errors.fetch_add(1, Ordering::Relaxed);
        record_exception(
            &self.recent_exceptions,
            &ident,
            "metadata_parse",
            packet_length,
            None,
            None,
        );
        Ok(())
    }

    pub fn refresh_bindings(&self, bindings: &mut [BindingStatus]) {
        for binding in bindings.iter_mut() {
            if let Some(live) = self.live.get(&binding.slot) {
                let snap = live.snapshot();
                binding.bound = snap.bound;
                binding.xsk_registered = snap.xsk_registered;
                binding.xsk_bind_mode = snap.xsk_bind_mode;
                binding.zero_copy = snap.zero_copy;
                binding.socket_fd = snap.socket_fd;
                binding.socket_ifindex = snap.socket_ifindex;
                binding.socket_queue_id = snap.socket_queue_id;
                binding.socket_bind_flags = snap.socket_bind_flags;
                binding.rx_packets = snap.rx_packets;
                binding.rx_bytes = snap.rx_bytes;
                binding.rx_batches = snap.rx_batches;
                binding.rx_wakeups = snap.rx_wakeups;
                binding.metadata_packets = snap.metadata_packets;
                binding.metadata_errors = snap.metadata_errors;
                binding.validated_packets = snap.validated_packets;
                binding.validated_bytes = snap.validated_bytes;
                binding.local_delivery_packets = snap.local_delivery_packets;
                binding.forward_candidate_packets = snap.forward_candidate_packets;
                binding.route_miss_packets = snap.route_miss_packets;
                binding.neighbor_miss_packets = snap.neighbor_miss_packets;
                binding.discard_route_packets = snap.discard_route_packets;
                binding.next_table_packets = snap.next_table_packets;
                binding.exception_packets = snap.exception_packets;
                binding.config_gen_mismatches = snap.config_gen_mismatches;
                binding.fib_gen_mismatches = snap.fib_gen_mismatches;
                binding.unsupported_packets = snap.unsupported_packets;
                binding.session_hits = snap.session_hits;
                binding.session_misses = snap.session_misses;
                binding.session_creates = snap.session_creates;
                binding.session_expires = snap.session_expires;
                binding.session_delta_pending = snap.session_delta_pending;
                binding.session_delta_generated = snap.session_delta_generated;
                binding.session_delta_dropped = snap.session_delta_dropped;
                binding.session_delta_drained = snap.session_delta_drained;
                binding.policy_denied_packets = snap.policy_denied_packets;
                binding.screen_drops = snap.screen_drops;
                binding.snat_packets = snap.snat_packets;
                binding.dnat_packets = snap.dnat_packets;
                binding.slow_path_packets = snap.slow_path_packets;
                binding.slow_path_bytes = snap.slow_path_bytes;
                binding.slow_path_drops = snap.slow_path_drops;
                binding.slow_path_rate_limited = snap.slow_path_rate_limited;
                binding.kernel_rx_dropped = snap.kernel_rx_dropped;
                binding.kernel_rx_invalid_descs = snap.kernel_rx_invalid_descs;
                binding.tx_packets = snap.tx_packets;
                binding.tx_bytes = snap.tx_bytes;
                binding.tx_completions = snap.tx_completions;
                binding.tx_errors = snap.tx_errors;
                binding.in_place_tx_packets = snap.in_place_tx_packets;
                binding.debug_pending_fill_frames = snap.debug_pending_fill_frames;
                binding.debug_spare_fill_frames = 0;
                binding.debug_free_tx_frames = snap.debug_free_tx_frames;
                binding.debug_pending_tx_prepared = snap.debug_pending_tx_prepared;
                binding.debug_pending_tx_local = snap.debug_pending_tx_local;
                binding.debug_outstanding_tx = snap.debug_outstanding_tx;
                binding.debug_in_flight_recycles = snap.debug_in_flight_recycles;
                binding.last_heartbeat = snap.last_heartbeat;
                binding.last_error = snap.last_error;
                binding.ready = binding.registered
                    && binding.bound
                    && binding.xsk_registered
                    && heartbeat_fresh(snap.last_heartbeat);
            } else {
                binding.bound = false;
                binding.xsk_registered = false;
                binding.xsk_bind_mode.clear();
                binding.zero_copy = false;
                binding.socket_fd = 0;
                binding.socket_ifindex = 0;
                binding.socket_queue_id = 0;
                binding.socket_bind_flags = 0;
                binding.rx_packets = 0;
                binding.rx_bytes = 0;
                binding.rx_batches = 0;
                binding.rx_wakeups = 0;
                binding.metadata_packets = 0;
                binding.metadata_errors = 0;
                binding.validated_packets = 0;
                binding.validated_bytes = 0;
                binding.local_delivery_packets = 0;
                binding.forward_candidate_packets = 0;
                binding.route_miss_packets = 0;
                binding.neighbor_miss_packets = 0;
                binding.discard_route_packets = 0;
                binding.next_table_packets = 0;
                binding.exception_packets = 0;
                binding.config_gen_mismatches = 0;
                binding.fib_gen_mismatches = 0;
                binding.unsupported_packets = 0;
                binding.session_hits = 0;
                binding.session_misses = 0;
                binding.session_creates = 0;
                binding.session_expires = 0;
                binding.session_delta_pending = 0;
                binding.session_delta_generated = 0;
                binding.session_delta_dropped = 0;
                binding.session_delta_drained = 0;
                binding.policy_denied_packets = 0;
                binding.snat_packets = 0;
                binding.dnat_packets = 0;
                binding.slow_path_packets = 0;
                binding.slow_path_bytes = 0;
                binding.slow_path_drops = 0;
                binding.slow_path_rate_limited = 0;
                binding.kernel_rx_dropped = 0;
                binding.kernel_rx_invalid_descs = 0;
                binding.tx_packets = 0;
                binding.tx_bytes = 0;
                binding.tx_completions = 0;
                binding.tx_errors = 0;
                binding.in_place_tx_packets = 0;
                binding.debug_pending_fill_frames = 0;
                binding.debug_spare_fill_frames = 0;
                binding.debug_free_tx_frames = 0;
                binding.debug_pending_tx_prepared = 0;
                binding.debug_pending_tx_local = 0;
                binding.debug_outstanding_tx = 0;
                binding.debug_in_flight_recycles = 0;
                binding.last_heartbeat = None;
                binding.last_error.clear();
                binding.ready = false;
            }
        }
    }
}

struct WorkerHandle {
    stop: Arc<AtomicBool>,
    heartbeat: Arc<AtomicU64>,
    commands: Arc<Mutex<VecDeque<WorkerCommand>>>,
    join: Option<JoinHandle<()>>,
}

struct BindingPlan {
    status: BindingStatus,
    live: Arc<BindingLiveState>,
    xsk_map_fd: c_int,
    heartbeat_map_fd: c_int,
    session_map_fd: c_int,
    ring_entries: u32,
    shared_owner: bool,
}

#[derive(Clone, Copy, Debug, Default)]
struct ValidationState {
    snapshot_installed: bool,
    config_generation: u64,
    fib_generation: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PacketDisposition {
    Valid,
    NoSnapshot,
    ConfigGenerationMismatch,
    FibGenerationMismatch,
    UnsupportedPacket,
}

#[derive(Clone, Debug, Default)]
struct ForwardingState {
    local_v4: FastSet<Ipv4Addr>,
    local_v6: FastSet<Ipv6Addr>,
    interface_nat_v4: FastMap<Ipv4Addr, i32>,
    interface_nat_v6: FastMap<Ipv6Addr, i32>,
    connected_v4: Vec<ConnectedRouteV4>,
    connected_v6: Vec<ConnectedRouteV6>,
    routes_v4: FastMap<String, Vec<RouteEntryV4>>,
    routes_v6: FastMap<String, Vec<RouteEntryV6>>,
    neighbors: FastMap<(i32, IpAddr), NeighborEntry>,
    ifindex_to_name: FastMap<i32, String>,
    ifindex_to_zone: FastMap<i32, String>,
    zone_name_to_id: FastMap<String, u16>,
    zone_id_to_name: FastMap<u16, String>,
    egress: FastMap<i32, EgressInterface>,
    fabrics: Vec<FabricLink>,
    allow_dns_reply: bool,
    allow_embedded_icmp: bool,
    session_timeouts: crate::session::SessionTimeouts,
    policy: PolicyState,
    source_nat_rules: Vec<SourceNatRule>,
    static_nat: StaticNatTable,
    dnat_table: DnatTable,
    nat64: Nat64State,
    nptv6: Nptv6State,
    screen_profiles: FastMap<String, ScreenProfile>,
    /// Ifindexes of tunnel interfaces (GRE, ip6gre, XFRM) that deliver raw IP.
    tunnel_interfaces: FastSet<i32>,
    /// Firewall filter state for input filtering.
    filter_state: crate::filter::FilterState,
    /// GRE performance acceleration: extract GRE key into session ports.
    gre_acceleration: bool,
    /// Flow export configuration (NetFlow v9).
    flow_export_config: Option<crate::flowexport::FlowExportConfig>,
    /// TCP MSS clamping: max MSS for all TCP SYN/SYN-ACK packets (0 = disabled).
    tcp_mss_all_tcp: u16,
    /// TCP MSS clamping for IPsec VPN traffic (0 = disabled).
    tcp_mss_ipsec_vpn: u16,
    /// TCP MSS clamping for GRE ingress traffic (0 = disabled).
    tcp_mss_gre_in: u16,
    /// TCP MSS clamping for GRE egress traffic (0 = disabled).
    tcp_mss_gre_out: u16,
}

#[derive(Clone, Copy, Debug, Default)]
struct HAGroupRuntime {
    active: bool,
    watchdog_timestamp: u64,
}

#[derive(Clone, Copy, Debug)]
struct ConnectedRouteV4 {
    prefix: PrefixV4,
    ifindex: i32,
}

#[derive(Clone, Copy, Debug)]
struct ConnectedRouteV6 {
    prefix: PrefixV6,
    ifindex: i32,
}

#[derive(Clone, Debug)]
struct RouteEntryV4 {
    prefix: PrefixV4,
    ifindex: i32,
    next_hop: Option<Ipv4Addr>,
    discard: bool,
    next_table: String,
}

#[derive(Clone, Debug)]
struct RouteEntryV6 {
    prefix: PrefixV6,
    ifindex: i32,
    next_hop: Option<Ipv6Addr>,
    discard: bool,
    next_table: String,
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
struct NeighborEntry {
    mac: [u8; 6],
}

#[derive(Clone, Debug)]
struct EgressInterface {
    bind_ifindex: i32,
    vlan_id: u16,
    mtu: usize,
    src_mac: [u8; 6],
    zone: String,
    redundancy_group: i32,
    primary_v4: Option<Ipv4Addr>,
    primary_v6: Option<Ipv6Addr>,
}

#[derive(Clone, Copy, Debug)]
struct FabricLink {
    parent_ifindex: i32,
    overlay_ifindex: i32,
    peer_addr: IpAddr,
    peer_mac: [u8; 6],
    local_mac: [u8; 6],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ForwardingDisposition {
    LocalDelivery,
    ForwardCandidate,
    FabricRedirect,
    HAInactive,
    PolicyDenied,
    NoRoute,
    MissingNeighbor,
    DiscardRoute,
    NextTableUnsupported,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ForwardingResolution {
    pub(crate) disposition: ForwardingDisposition,
    pub(crate) local_ifindex: i32,
    pub(crate) egress_ifindex: i32,
    pub(crate) tx_ifindex: i32,
    pub(crate) next_hop: Option<IpAddr>,
    pub(crate) neighbor_mac: Option<[u8; 6]>,
    pub(crate) src_mac: Option<[u8; 6]>,
    pub(crate) tx_vlan_id: u16,
}

impl ForwardingResolution {
    fn status(self, debug: Option<&ResolutionDebug>) -> PacketResolution {
        PacketResolution {
            disposition: match self.disposition {
                ForwardingDisposition::LocalDelivery => "local_delivery",
                ForwardingDisposition::ForwardCandidate => "forward_candidate",
                ForwardingDisposition::FabricRedirect => "fabric_redirect",
                ForwardingDisposition::HAInactive => "ha_inactive",
                ForwardingDisposition::PolicyDenied => "policy_denied",
                ForwardingDisposition::NoRoute => "no_route",
                ForwardingDisposition::MissingNeighbor => "missing_neighbor",
                ForwardingDisposition::DiscardRoute => "discard_route",
                ForwardingDisposition::NextTableUnsupported => "next_table_unsupported",
            }
            .to_string(),
            local_ifindex: self.local_ifindex,
            egress_ifindex: self.egress_ifindex,
            ingress_ifindex: debug.map(|d| d.ingress_ifindex).unwrap_or_default(),
            next_hop: self.next_hop.map(|ip| ip.to_string()).unwrap_or_default(),
            neighbor_mac: self.neighbor_mac.map(format_mac).unwrap_or_default(),
            src_ip: debug
                .and_then(|d| d.src_ip)
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            dst_ip: debug
                .and_then(|d| d.dst_ip)
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            src_port: debug.map(|d| d.src_port).unwrap_or_default(),
            dst_port: debug.map(|d| d.dst_port).unwrap_or_default(),
            from_zone: debug
                .and_then(|d| d.from_zone.as_ref().map(|zone| zone.to_string()))
                .unwrap_or_default(),
            to_zone: debug
                .and_then(|d| d.to_zone.as_ref().map(|zone| zone.to_string()))
                .unwrap_or_default(),
        }
    }
}

const DEFAULT_V4_TABLE: &str = "inet.0";
const DEFAULT_V6_TABLE: &str = "inet6.0";
const MAX_NEXT_TABLE_DEPTH: usize = 8;

struct BindingWorker {
    slot: u32,
    queue_id: u32,
    worker_id: u32,
    interface: Arc<str>,
    ifindex: i32,
    umem: WorkerUmem,
    live: Arc<BindingLiveState>,
    user: User,
    device: xdpilone::DeviceQueue,
    rx: xdpilone::RingRx,
    tx: xdpilone::RingTx,
    free_tx_frames: VecDeque<u64>,
    pending_tx_prepared: VecDeque<PreparedTxRequest>,
    pending_tx_local: VecDeque<TxRequest>,
    max_pending_tx: usize,
    pending_fill_frames: VecDeque<u64>,
    scratch_recycle: Vec<u64>,
    scratch_forwards: Vec<PendingForwardRequest>,
    scratch_fill: Vec<u64>,
    scratch_prepared_tx: Vec<PreparedTxRequest>,
    scratch_local_tx: Vec<(u64, TxRequest)>,
    in_flight_forward_recycles: FastMap<u64, u32>,
    heartbeat_map_fd: c_int,
    session_map_fd: c_int,
    last_heartbeat_update_ns: u64,
    debug_state_counter: u32,
    last_rx_wake_ns: u64,
    last_tx_wake_ns: u64,
    outstanding_tx: u32,
    empty_rx_polls: u32,
    last_learned_neighbor: Option<LearnedNeighborKey>,
    dbg_fill_submitted: u64,
    dbg_fill_failed: u64,
    dbg_poll_cycles: u64,
    dbg_backpressure: u64,
    dbg_rx_empty: u64,
    dbg_rx_wakeups: u64,
    // TX pipeline debug counters
    dbg_tx_ring_submitted: u64,   // descriptors inserted into TX ring
    dbg_tx_ring_full: u64,        // times TX ring insert returned 0
    dbg_completions_reaped: u64,  // completion descriptors read
    dbg_sendto_calls: u64,        // number of sendto/wake calls
    dbg_sendto_err: u64,          // sendto returned error (non-EAGAIN/ENOBUFS)
    dbg_sendto_eagain: u64,       // sendto returned EAGAIN/EWOULDBLOCK
    dbg_sendto_enobufs: u64,      // sendto returned ENOBUFS (kernel TX drop)
    dbg_pending_overflow: u64,    // drops from bound_pending overflow
    dbg_tx_tcp_rst: u64,          // TCP RST packets transmitted
    // Ring diagnostics — raw values from xdpilone API
    dbg_rx_avail_nonzero: u64,    // times rx.available() > 0
    dbg_rx_avail_max: u32,        // max rx.available() seen this interval
    dbg_fill_pending: u32,        // fill ring: userspace produced - kernel consumed
    dbg_device_avail: u32,        // device queue available (completion ring pending)
    dbg_rx_wake_sendto_ok: u64,   // sendto() returned >= 0 in maybe_wake_rx
    dbg_rx_wake_sendto_err: u64,  // sendto() returned < 0 in maybe_wake_rx
    dbg_rx_wake_sendto_errno: i32,// last errno from sendto in maybe_wake_rx
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum XskBindMode {
    Unknown,
    Copy,
    ZeroCopy,
}

impl XskBindMode {
    fn as_u8(self) -> u8 {
        match self {
            Self::Unknown => 0,
            Self::Copy => 1,
            Self::ZeroCopy => 2,
        }
    }

    fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Copy,
            2 => Self::ZeroCopy,
            _ => Self::Unknown,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "",
            Self::Copy => "copy",
            Self::ZeroCopy => "zerocopy",
        }
    }

    fn is_zerocopy(self) -> bool {
        matches!(self, Self::ZeroCopy)
    }
}

#[derive(Clone, Debug)]
struct BindingIdentity {
    slot: u32,
    queue_id: u32,
    worker_id: u32,
    interface: Arc<str>,
    ifindex: i32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SessionFlow {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    forward_key: SessionKey,
}

impl SessionFlow {
    fn reverse_key_with_nat(&self, nat: NatDecision) -> SessionKey {
        reverse_session_key(&self.forward_key, nat)
    }
}

#[derive(Clone, Debug, Default)]
struct ResolutionDebug {
    ingress_ifindex: i32,
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    from_zone: Option<Arc<str>>,
    to_zone: Option<Arc<str>>,
}

impl ResolutionDebug {
    fn from_flow(ingress_ifindex: i32, flow: &SessionFlow) -> Self {
        Self {
            ingress_ifindex,
            src_ip: Some(flow.src_ip),
            dst_ip: Some(flow.dst_ip),
            src_port: flow.forward_key.src_port,
            dst_port: flow.forward_key.dst_port,
            from_zone: None,
            to_zone: None,
        }
    }
}

#[derive(Clone, Debug)]
struct TxRequest {
    bytes: Vec<u8>,
    expected_ports: Option<(u16, u16)>,
    expected_addr_family: u8,
    expected_protocol: u8,
    flow_key: Option<SessionKey>,
}

struct PendingForwardRequest {
    target_ifindex: i32,
    ingress_queue_id: u32,
    source_offset: u64,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    decision: SessionDecision,
    expected_ports: Option<(u16, u16)>,
    flow_key: Option<SessionKey>,
    /// NAT64 reverse info for cross-AF translation (IPv4 reply → IPv6).
    nat64_reverse: Option<Nat64ReverseInfo>,
    /// Pre-built frame bytes that bypass normal frame building.
    /// Used for ICMP error NAT reversal where the embedded packet
    /// rewrites are already applied and the frame is ready for TX.
    prebuilt_frame: Option<Vec<u8>>,
}

struct PreparedTxRequest {
    offset: u64,
    len: u32,
    recycle_slot: Option<u32>,
    expected_ports: Option<(u16, u16)>,
    expected_addr_family: u8,
    expected_protocol: u8,
    flow_key: Option<SessionKey>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LearnedNeighborKey {
    ingress_ifindex: i32,
    ingress_vlan_id: u16,
    src_ip: IpAddr,
    src_mac: [u8; 6],
}

#[derive(Clone, Debug)]
pub(crate) struct SyncedSessionEntry {
    pub(crate) key: SessionKey,
    pub(crate) decision: SessionDecision,
    pub(crate) metadata: SessionMetadata,
    pub(crate) protocol: u8,
    pub(crate) tcp_flags: u8,
}

#[derive(Clone, Debug)]
enum WorkerCommand {
    UpsertSynced(SyncedSessionEntry),
    DeleteSynced(SessionKey),
}

impl BindingWorker {
    fn create(
        binding: &BindingStatus,
        ring_entries: u32,
        xsk_map_fd: c_int,
        heartbeat_map_fd: c_int,
        session_map_fd: c_int,
        live: Arc<BindingLiveState>,
        shared_owner: bool,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let total_frames = binding_frame_count(ring_entries).max(1);
        let worker_umem =
            WorkerUmem::new(total_frames).map_err(|err| format!("create binding umem: {err}"))?;
        let reserved_tx = reserved_tx_frames(ring_entries);
        let mut reserved_tx_frames = VecDeque::with_capacity(reserved_tx as usize);
        for idx in 0..reserved_tx {
            if let Some(frame) = worker_umem.umem.frame(BufIdx(idx)) {
                reserved_tx_frames.push_back(frame.offset);
            }
        }
        // Pre-populate fill ring with ALL remaining frames — no spare held back.
        // This maximizes the kernel's ability to place received packets and
        // prevents fill ring starvation under burst conditions (copy-mode fix).
        let mut initial_fill_frames = Vec::with_capacity((total_frames - reserved_tx) as usize);
        for idx in reserved_tx..total_frames {
            if let Some(frame) = worker_umem.umem.frame(BufIdx(idx)) {
                initial_fill_frames.push(frame.offset);
            }
        }
        let info = ifinfo_from_binding(binding)?;
        let (user, rx, tx, bind_mode, mut device) =
            open_binding_worker_rings(&worker_umem, &info, ring_entries, shared_owner)
                .map_err(|err| format!("configure AF_XDP rings: {err}"))?;
        prime_fill_ring_offsets(&mut device, &initial_fill_frames)?;

        let user_fd = user.as_raw_fd();
        live.set_bound(user_fd);
        live.set_bind_mode(bind_mode);
        let bound_info = query_bound_xsk_socket(user_fd);
        if let Some((ifindex, queue_id, flags)) = bound_info {
            live.set_socket_binding(ifindex, queue_id, flags);
            eprintln!(
                "bpfrx-userspace-dp: binding slot={} fd={} shared_owner={} bound if{}q{} flags=0x{:x} mode={:?} (expected if{}q{})",
                binding.slot, user_fd, shared_owner, ifindex, queue_id, flags, bind_mode,
                binding.ifindex, binding.queue_id,
            );
            if ifindex != binding.ifindex || queue_id != binding.queue_id {
                live.set_error(format!(
                    "socket bound to ifindex {ifindex} queue {queue_id} flags 0x{flags:x}, expected ifindex {} queue {}",
                    binding.ifindex, binding.queue_id
                ));
            }
        } else {
            eprintln!(
                "bpfrx-userspace-dp: binding slot={} fd={} shared_owner={} getsockname FAILED — socket not bound!",
                binding.slot, user_fd, shared_owner,
            );
        }
        if let Err(err) = register_xsk_slot(xsk_map_fd, binding.slot, user_fd) {
            eprintln!(
                "bpfrx-userspace-dp: ERROR register_xsk_slot slot={} fd={}: {}",
                binding.slot, user_fd, err,
            );
            live.set_error(format!("register XSK slot: {err}"));
        } else {
            eprintln!(
                "bpfrx-userspace-dp: registered slot={} fd={} in XSKMAP",
                binding.slot, user_fd,
            );
            live.set_xsk_registered(true);
            if binding.ifindex == live.socket_ifindex.load(Ordering::Relaxed)
                && binding.queue_id == live.socket_queue_id.load(Ordering::Relaxed)
            {
                live.clear_error();
            }
        }
        let init_now = monotonic_nanos();
        let max_pending_tx = pending_tx_capacity(ring_entries);
        if let Err(err) = touch_heartbeat(heartbeat_map_fd, binding.slot, &live, init_now) {
            live.set_error(format!("update heartbeat slot: {err}"));
        }
        live.set_max_pending_tx(max_pending_tx);
        let mut binding = Self {
            slot: binding.slot,
            queue_id: binding.queue_id,
            worker_id: binding.worker_id,
            interface: Arc::<str>::from(binding.interface.as_str()),
            ifindex: binding.ifindex,
            umem: worker_umem,
            live,
            user,
            device,
            rx,
            tx,
            free_tx_frames: reserved_tx_frames,
            pending_tx_prepared: VecDeque::new(),
            pending_tx_local: VecDeque::new(),
            max_pending_tx,
            pending_fill_frames: VecDeque::new(),
            scratch_recycle: Vec::with_capacity(RX_BATCH_SIZE as usize),
            scratch_forwards: Vec::with_capacity(RX_BATCH_SIZE as usize),
            scratch_fill: Vec::with_capacity(FILL_BATCH_SIZE),
            scratch_prepared_tx: Vec::with_capacity(TX_BATCH_SIZE),
            scratch_local_tx: Vec::with_capacity(TX_BATCH_SIZE),
            in_flight_forward_recycles: FastMap::default(),
            heartbeat_map_fd,
            session_map_fd,
            last_heartbeat_update_ns: init_now,
            debug_state_counter: 0,
            last_rx_wake_ns: init_now,
            last_tx_wake_ns: init_now,
            outstanding_tx: 0,
            empty_rx_polls: 0,
            last_learned_neighbor: None,
            dbg_fill_submitted: 0,
            dbg_fill_failed: 0,
            dbg_poll_cycles: 0,
            dbg_backpressure: 0,
            dbg_rx_empty: 0,
            dbg_rx_wakeups: 0,
            dbg_tx_ring_submitted: 0,
            dbg_tx_ring_full: 0,
            dbg_completions_reaped: 0,
            dbg_sendto_calls: 0,
            dbg_sendto_err: 0,
            dbg_sendto_eagain: 0,
            dbg_sendto_enobufs: 0,
            dbg_pending_overflow: 0,
            dbg_tx_tcp_rst: 0,
            dbg_rx_avail_nonzero: 0,
            dbg_rx_avail_max: 0,
            dbg_fill_pending: 0,
            dbg_device_avail: 0,
            dbg_rx_wake_sendto_ok: 0,
            dbg_rx_wake_sendto_err: 0,
            dbg_rx_wake_sendto_errno: 0,
        };
        update_binding_debug_state(&mut binding);
        Ok(binding)
    }

    fn identity(&self) -> BindingIdentity {
        BindingIdentity {
            slot: self.slot,
            queue_id: self.queue_id,
            worker_id: self.worker_id,
            interface: self.interface.clone(),
            ifindex: self.ifindex,
        }
    }
}

struct WorkerUmem {
    area: MmapArea,
    umem: Umem,
    total_frames: u32,
}

impl WorkerUmem {
    fn new(total_frames: u32) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let area = MmapArea::new((total_frames as usize) * (UMEM_FRAME_SIZE as usize))?;
        let ring_size = umem_ring_size(total_frames);
        let umem_cfg = UmemConfig {
            fill_size: ring_size,
            complete_size: ring_size,
            frame_size: UMEM_FRAME_SIZE,
            headroom: UMEM_HEADROOM,
            flags: 0,
        };
        let umem = unsafe { Umem::new(umem_cfg, area.as_nonnull_slice()) }
            .map_err(|e| format!("create umem: {e}"))?;
        Ok(Self { area, umem, total_frames })
    }
}

fn open_binding_worker_rings(
    worker_umem: &WorkerUmem,
    info: &IfInfo,
    ring_entries: u32,
    shared_owner: bool,
) -> Result<
    (
        User,
        xdpilone::RingRx,
        xdpilone::RingTx,
        XskBindMode,
        xdpilone::DeviceQueue,
    ),
    Box<dyn std::error::Error + Send + Sync>,
> {
    // Try zero-copy first, fall back to copy mode if the driver doesn't support it.
    match try_open_bind(worker_umem, info, ring_entries, shared_owner, XSK_BIND_FLAGS_ZEROCOPY) {
        Ok(result) => return Ok(result),
        Err(e) => {
            eprintln!(
                "bpfrx-userspace-dp: zero-copy bind failed: {e} — falling back to copy mode"
            );
        }
    }
    try_open_bind(worker_umem, info, ring_entries, shared_owner, XSK_BIND_FLAGS_COPY)
}

fn try_open_bind(
    worker_umem: &WorkerUmem,
    info: &IfInfo,
    ring_entries: u32,
    shared_owner: bool,
    flags: u16,
) -> Result<
    (
        User,
        xdpilone::RingRx,
        xdpilone::RingTx,
        XskBindMode,
        xdpilone::DeviceQueue,
    ),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let sock = if shared_owner {
        Socket::with_shared(info, &worker_umem.umem)
            .map_err(|e| format!("create shared socket: {e}"))?
    } else {
        Socket::new(info).map_err(|e| format!("create socket: {e}"))?
    };
    let device = worker_umem
        .umem
        .fq_cq(&sock)
        .map_err(|e| format!("create fq/cq: {e}"))?;
    let (user, rx, tx, bind_mode) = open_user_rings(
        &worker_umem.umem,
        &sock,
        ring_entries,
        flags,
    )?;
    let bind_mode = match bind_user_rings(&worker_umem.umem, &device, &user, shared_owner) {
        Ok(mode) => mode,
        Err(e) => {
            return Err(e);
        }
    };
    Ok((user, rx, tx, bind_mode, device))
}

fn reserved_tx_frames(ring_entries: u32) -> u32 {
    ring_entries
        .saturating_div(2)
        .clamp(MIN_RESERVED_TX_FRAMES, MAX_RESERVED_TX_FRAMES)
        .min(ring_entries.saturating_sub(1))
        .max(1)
}

fn binding_frame_count(ring_entries: u32) -> u32 {
    // Allocate 2× ring_entries for fill ring so the NIC always has ample
    // frames to place received packets into, even under burst conditions.
    // This is the "Increase Fill Ring Size + Pre-populate UMEM" fix for
    // copy-mode AF_XDP throughput stalls.
    reserved_tx_frames(ring_entries)
        .saturating_add(ring_entries.saturating_mul(2).max(1))
}

fn umem_ring_size(entries: u32) -> u32 {
    entries
        .max(64)
        .checked_next_power_of_two()
        .unwrap_or(entries.max(64))
}

fn open_user_rings(
    umem: &Umem,
    sock: &Socket,
    ring_entries: u32,
    bind_flags: u16,
) -> Result<
    (User, xdpilone::RingRx, xdpilone::RingTx, XskBindMode),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let user = umem
        .rx_tx(
            sock,
            &SocketConfig {
                rx_size: NonZeroU32::new(ring_entries),
                tx_size: NonZeroU32::new(ring_entries),
                bind_flags,
            },
        )
        .map_err(|e| format!("configure rx/tx rings: {e}"))?;
    let rx = user.map_rx().map_err(|e| format!("map rx ring: {e}"))?;
    let tx = user.map_tx().map_err(|e| format!("map tx ring: {e}"))?;
    let bind_mode = if (bind_flags & SocketConfig::XDP_BIND_ZEROCOPY) != 0 {
        XskBindMode::ZeroCopy
    } else {
        XskBindMode::Copy
    };
    Ok((user, rx, tx, bind_mode))
}

fn query_bound_xsk_mode(fd: c_int) -> Option<XskBindMode> {
    let mut opt = XdpOptions { flags: 0 };
    let mut optlen = core::mem::size_of::<XdpOptions>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            SOL_XDP,
            XDP_OPTIONS,
            (&mut opt as *mut XdpOptions).cast::<c_void>(),
            &mut optlen,
        )
    };
    if rc != 0 || optlen as usize != core::mem::size_of::<XdpOptions>() {
        return None;
    }
    Some(if (opt.flags & XDP_OPTIONS_ZEROCOPY) != 0 {
        XskBindMode::ZeroCopy
    } else {
        XskBindMode::Copy
    })
}

#[repr(C)]
struct SockaddrXdp {
    sxdp_family: u16,
    sxdp_flags: u16,
    sxdp_ifindex: u32,
    sxdp_queue_id: u32,
    sxdp_shared_umem_fd: u32,
}

fn query_bound_xsk_socket(fd: c_int) -> Option<(i32, u32, u32)> {
    let mut addr = SockaddrXdp {
        sxdp_family: 0,
        sxdp_flags: 0,
        sxdp_ifindex: 0,
        sxdp_queue_id: 0,
        sxdp_shared_umem_fd: 0,
    };
    let mut addrlen = core::mem::size_of::<SockaddrXdp>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockname(
            fd,
            (&mut addr as *mut SockaddrXdp).cast::<libc::sockaddr>(),
            &mut addrlen,
        )
    };
    if rc != 0 {
        let err = io::Error::last_os_error();
        eprintln!(
            "bpfrx-userspace-dp: getsockname(fd={}) failed: rc={} err={} addrlen={}",
            fd, rc, err, addrlen,
        );
        return None;
    }
    if addrlen as usize != core::mem::size_of::<SockaddrXdp>() {
        eprintln!(
            "bpfrx-userspace-dp: getsockname(fd={}) size mismatch: got {} expected {} family={} ifindex={} queue={}",
            fd, addrlen, core::mem::size_of::<SockaddrXdp>(), addr.sxdp_family, addr.sxdp_ifindex, addr.sxdp_queue_id,
        );
        return None;
    }
    Some((
        addr.sxdp_ifindex as i32,
        addr.sxdp_queue_id,
        addr.sxdp_flags as u32,
    ))
}

fn bind_user_with_retry(
    umem: &Umem,
    user: &User,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    for attempt in 0..BIND_RETRY_ATTEMPTS {
        match umem.bind(user) {
            Ok(()) => return Ok(()),
            Err(err) => {
                let msg = err.to_string();
                if attempt + 1 < BIND_RETRY_ATTEMPTS && msg.contains("Device or resource busy") {
                    thread::sleep(BIND_RETRY_DELAY);
                    continue;
                }
                return Err(format!("bind AF_XDP socket: {msg}").into());
            }
        }
    }
    Err("bind AF_XDP socket: exhausted retries".into())
}

fn bind_user_rings(
    umem: &Umem,
    _device: &xdpilone::DeviceQueue,
    user: &User,
    shared_owner: bool,
) -> Result<XskBindMode, Box<dyn std::error::Error + Send + Sync>> {
    let user_fd = user.as_raw_fd();
    for attempt in 0..BIND_RETRY_ATTEMPTS {
        let bind_result = umem.bind(user);
        match bind_result {
            Ok(()) => {
                let bind_mode = query_bound_xsk_mode(user_fd).unwrap_or(XskBindMode::Copy);
                // Enable per-socket NAPI busy polling for lower-latency
                // packet delivery. The kernel will spin-poll the NIC's NAPI
                // context from sendto()/poll() instead of waiting for softirq.
                set_busy_poll_opts(user_fd);
                eprintln!(
                    "bpfrx-userspace-dp: umem.bind(fd={}) OK on attempt {} mode={:?} shared_owner={}",
                    user_fd, attempt, bind_mode, shared_owner,
                );
                return Ok(bind_mode);
            }
            Err(err) => {
                let msg = err.to_string();
                if attempt + 1 < BIND_RETRY_ATTEMPTS && msg.contains("Device or resource busy") {
                    thread::sleep(BIND_RETRY_DELAY);
                    continue;
                }
                let binder = if shared_owner {
                    "umem.bind(shared-root)"
                } else {
                    "umem.bind(owner)"
                };
                return Err(format!("bind AF_XDP socket via {binder}: {msg}").into());
            }
        }
    }
    let binder = if shared_owner {
        "umem.bind(shared-root)"
    } else {
        "umem.bind(owner)"
    };
    Err(format!("bind AF_XDP socket via {binder}: exhausted retries").into())
}

/// Set per-socket busy-poll options for NAPI affinity. When the kernel's
/// `net.core.busy_poll` sysctl is also non-zero, sendto() on this socket
/// will busy-poll the NIC's NAPI context instead of relying on softirq
/// scheduling, reducing the user↔softirq context switch overhead.
fn set_busy_poll_opts(fd: c_int) {
    const SO_BUSY_POLL: c_int = 46;
    const SO_PREFER_BUSY_POLL: c_int = 69;
    const SO_BUSY_POLL_BUDGET: c_int = 70;
    // busy_poll timeout in µs — how long sendto() will spin-poll NAPI
    let busy_poll_us: c_int = 50;
    let prefer: c_int = 1;
    let budget: c_int = 256;
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            SO_BUSY_POLL,
            &busy_poll_us as *const _ as *const libc::c_void,
            core::mem::size_of::<c_int>() as u32,
        );
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            SO_PREFER_BUSY_POLL,
            &prefer as *const _ as *const libc::c_void,
            core::mem::size_of::<c_int>() as u32,
        );
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            SO_BUSY_POLL_BUDGET,
            &budget as *const _ as *const libc::c_void,
            core::mem::size_of::<c_int>() as u32,
        );
    }
}

#[derive(Default)]
struct DebugPollCounters {
    rx: u64,
    tx: u64,
    forward: u64,
    local: u64,
    session_hit: u64,
    session_miss: u64,
    session_create: u64,
    no_route: u64,
    missing_neigh: u64,
    policy_deny: u64,
    ha_inactive: u64,
    no_egress_binding: u64,
    build_fail: u64,
    tx_err: u64,
    metadata_err: u64,
    disposition_other: u64,
    enqueue_ok: u64,        // forwards successfully enqueued to target binding TX
    enqueue_inplace: u64,   // in-place TX rewrites (same UMEM)
    enqueue_direct: u64,    // direct-to-UMEM TX (cross binding)
    enqueue_copy: u64,      // Vec copy-path TX
    // Direction-specific counters
    rx_from_trust: u64,     // packets received from trust-side interfaces
    rx_from_wan: u64,       // packets received from wan-side interfaces
    fwd_trust_to_wan: u64,  // forwards from trust to wan
    fwd_wan_to_trust: u64,  // forwards from wan to trust
    nat_applied_snat: u64,  // SNAT rewrites applied
    nat_applied_dnat: u64,  // DNAT (reverse-SNAT) rewrites applied
    nat_applied_none: u64,  // no NAT rewrite
    frame_build_none: u64,  // build_forwarded_frame returned None (why?)
    rx_tcp_rst: u64,        // TCP RST flags seen in RX frames
    tx_tcp_rst: u64,        // TCP RST flags seen in TX frames (forwarded)
    rx_bytes_total: u64,    // total RX bytes (for avg frame size calculation)
    tx_bytes_total: u64,    // total TX bytes submitted to ring
    rx_oversized: u64,      // RX frames where desc.len > 1514
    rx_max_frame: u32,      // max desc.len seen in RX
    tx_max_frame: u32,      // max frame len submitted to TX
    seg_needed_but_none: u64, // oversized frames where segmentation returned None
    wan_return_hits: u64,   // session hits for WAN return traffic (first N logged)
    wan_return_misses: u64, // session misses for WAN return traffic
    rx_tcp_fin: u64,        // TCP FIN flags seen in RX
    rx_tcp_synack: u64,     // TCP SYN+ACK seen in RX
    rx_tcp_zero_window: u64, // TCP zero-window seen in RX (forwarded frames)
    fwd_tcp_fin: u64,       // TCP FIN in forwarded frames
    fwd_tcp_rst: u64,       // TCP RST in forwarded frames
    fwd_tcp_zero_window: u64, // zero-window in forwarded frames
}

fn poll_binding(
    binding_index: usize,
    bindings: &mut [BindingWorker],
    sessions: &mut SessionTable,
    screen: &mut ScreenState,
    validation: ValidationState,
    now_ns: u64,
    now_secs: u64,
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    slow_path: Option<&Arc<SlowPathReinjector>>,
    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
    _recent_session_deltas: &Arc<Mutex<VecDeque<SessionDeltaInfo>>>,
    last_resolution: &Arc<Mutex<Option<PacketResolution>>>,
    peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    shared_recycles: &mut Vec<(u32, u64)>,
    dbg: &mut DebugPollCounters,
) -> bool {
    #[derive(Default)]
    struct BatchCounters {
        rx_packets: u64,
        rx_bytes: u64,
        rx_batches: u64,
        metadata_packets: u64,
        validated_packets: u64,
        validated_bytes: u64,
        forward_candidate_packets: u64,
        session_hits: u64,
        session_misses: u64,
        session_creates: u64,
        snat_packets: u64,
        dnat_packets: u64,
    }

    impl BatchCounters {
        fn flush(&mut self, live: &BindingLiveState) {
            if self.rx_packets != 0 {
                live.rx_packets
                    .fetch_add(self.rx_packets, Ordering::Relaxed);
                self.rx_packets = 0;
            }
            if self.rx_bytes != 0 {
                live.rx_bytes
                    .fetch_add(self.rx_bytes, Ordering::Relaxed);
                self.rx_bytes = 0;
            }
            if self.rx_batches != 0 {
                live.rx_batches
                    .fetch_add(self.rx_batches, Ordering::Relaxed);
                self.rx_batches = 0;
            }
            if self.metadata_packets != 0 {
                live.metadata_packets
                    .fetch_add(self.metadata_packets, Ordering::Relaxed);
                self.metadata_packets = 0;
            }
            if self.validated_packets != 0 {
                live.validated_packets
                    .fetch_add(self.validated_packets, Ordering::Relaxed);
                self.validated_packets = 0;
            }
            if self.validated_bytes != 0 {
                live.validated_bytes
                    .fetch_add(self.validated_bytes, Ordering::Relaxed);
                self.validated_bytes = 0;
            }
            if self.forward_candidate_packets != 0 {
                live.forward_candidate_packets
                    .fetch_add(self.forward_candidate_packets, Ordering::Relaxed);
                self.forward_candidate_packets = 0;
            }
            if self.session_hits != 0 {
                live.session_hits
                    .fetch_add(self.session_hits, Ordering::Relaxed);
                self.session_hits = 0;
            }
            if self.session_misses != 0 {
                live.session_misses
                    .fetch_add(self.session_misses, Ordering::Relaxed);
                self.session_misses = 0;
            }
            if self.session_creates != 0 {
                live.session_creates
                    .fetch_add(self.session_creates, Ordering::Relaxed);
                self.session_creates = 0;
            }
            if self.snat_packets != 0 {
                live.snat_packets
                    .fetch_add(self.snat_packets, Ordering::Relaxed);
                self.snat_packets = 0;
            }
            if self.dnat_packets != 0 {
                live.dnat_packets
                    .fetch_add(self.dnat_packets, Ordering::Relaxed);
                self.dnat_packets = 0;
            }
        }
    }

    let (left, rest) = bindings.split_at_mut(binding_index);
    let Some((binding, right)) = rest.split_first_mut() else {
        return false;
    };
    update_binding_debug_state(binding);
    let area = (&binding.umem.area) as *const MmapArea;
    let ident = binding.identity();
    maybe_touch_heartbeat(binding, now_ns);
    let tx_work = drain_pending_tx(binding, now_ns, shared_recycles);
    apply_shared_recycles(left, binding, right, shared_recycles);
    let fill_work = drain_pending_fill(binding, now_ns);
    let mut did_work = tx_work || fill_work;
    binding.dbg_poll_cycles += 1;
    for _ in 0..MAX_RX_BATCHES_PER_POLL {
        // Backpressure: skip RX when TX queues are heavily loaded to prevent
        // fill ring exhaustion. The NIC holds packets until we refill (#201).
        let tx_backlog = binding.pending_tx_local.len() + binding.pending_tx_prepared.len();
        if tx_backlog >= binding.max_pending_tx {
            binding.dbg_backpressure += 1;
            // Try to drain TX first — completions free frames for both TX and fill.
            let _ = drain_pending_tx(binding, now_ns, shared_recycles);
            apply_shared_recycles(left, binding, right, shared_recycles);
            // Critical: drain fill ring even under backpressure so the NIC can
            // still receive packets. Without this, fill ring starvation causes
            // mlx5 to fall back to non-XSK NAPI, leaking packets to the kernel.
            let _ = drain_pending_fill(binding, now_ns);
            return did_work;
        }

        let raw_avail = binding.rx.available();
        let available = raw_avail.min(RX_BATCH_SIZE);
        if raw_avail > 0 {
            binding.dbg_rx_avail_nonzero += 1;
            if raw_avail > binding.dbg_rx_avail_max {
                binding.dbg_rx_avail_max = raw_avail;
            }
        }
        // Snapshot ring state for diagnostics
        binding.dbg_fill_pending = binding.device.pending();
        binding.dbg_device_avail = binding.device.available();
        if available == 0 {
            binding.dbg_rx_empty += 1;
            maybe_wake_rx(binding, false, now_ns);
            return did_work;
        }
        binding.empty_rx_polls = 0;

        let mut received = binding.rx.receive(available);
        binding.scratch_recycle.clear();
        binding.scratch_forwards.clear();
        let mut rst_teardowns: Vec<(SessionKey, NatDecision)> = Vec::new();
        let mut counters = BatchCounters::default();
        while let Some(desc) = received.read() {
            counters.rx_packets += 1;
            counters.rx_bytes += desc.len as u64;
            dbg.rx += 1;
            dbg.rx_bytes_total += desc.len as u64;
            if desc.len > dbg.rx_max_frame {
                dbg.rx_max_frame = desc.len;
            }
            if desc.len > 1514 {
                dbg.rx_oversized += 1;
                if cfg!(feature = "debug-log") {
                    thread_local! {
                        static OVERSIZED_RX_LOG: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
                    }
                    OVERSIZED_RX_LOG.with(|c| {
                        let n = c.get();
                        if n < 20 {
                            c.set(n + 1);
                            eprintln!(
                                "DBG OVERSIZED_RX[{}]: if={} q={} desc.len={} (exceeds ETH+MTU 1514)",
                                n, ident.ifindex, ident.queue_id, desc.len,
                            );
                        }
                    });
                }
            }
            // TCP flag detection on RX
            if cfg!(feature = "debug-log") {
                if desc.len >= 54 {
                    if let Some(rx_frame) = unsafe { &*area }.slice(desc.addr as usize, desc.len as usize) {
                        // Check for FIN, SYN+ACK, zero-window
                        if let Some(tcp_info) = extract_tcp_flags_and_window(rx_frame) {
                            if (tcp_info.0 & 0x01) != 0 { // FIN
                                dbg.rx_tcp_fin += 1;
                            }
                            if (tcp_info.0 & 0x12) == 0x12 { // SYN+ACK
                                dbg.rx_tcp_synack += 1;
                            }
                            if tcp_info.1 == 0 && (tcp_info.0 & 0x02) == 0 { // zero window, not SYN
                                dbg.rx_tcp_zero_window += 1;
                                if dbg.rx_tcp_zero_window <= 10 {
                                    eprintln!(
                                        "RX_TCP_ZERO_WIN[{}]: if={} q={} len={} flags=0x{:02x}",
                                        dbg.rx_tcp_zero_window, ident.ifindex, ident.queue_id,
                                        desc.len, tcp_info.0,
                                    );
                                }
                            }
                        }
                        if frame_has_tcp_rst(rx_frame) {
                            dbg.rx_tcp_rst += 1;
                            thread_local! {
                                static RX_RST_LOG_COUNT: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
                            }
                            RX_RST_LOG_COUNT.with(|c| {
                                let n = c.get();
                                if n < 50 {
                                    c.set(n + 1);
                                    let summary = decode_frame_summary(rx_frame);
                                    eprintln!(
                                        "RST_DETECT RX[{}]: if={} q={} len={} {}",
                                        n, ident.ifindex, ident.queue_id, desc.len, summary,
                                    );
                                    if n < 5 {
                                        let hex_len = (desc.len as usize).min(rx_frame.len()).min(80);
                                        let hex: String = rx_frame[..hex_len]
                                            .iter()
                                            .map(|b| format!("{:02x}", b))
                                            .collect::<Vec<_>>()
                                            .join(" ");
                                        eprintln!("RST_DETECT RX_HEX[{n}]: {hex}");
                                    }
                                }
                            });
                        }
                    }
                }
            }
            // Poison check: detect if kernel recycled descriptor without writing data
            if cfg!(feature = "debug-log") {
                if desc.len >= 8 {
                    if let Some(first8) = unsafe { &*area }.slice(desc.addr as usize, 8) {
                        if first8 == &0xDEAD_BEEF_DEAD_BEEFu64.to_ne_bytes() {
                            eprintln!(
                                "DBG POISON_DETECTED: if={} q={} desc.addr={:#x} desc.len={} — kernel returned poisoned frame!",
                                ident.ifindex, ident.queue_id, desc.addr, desc.len,
                            );
                        }
                    }
                }
            }
            if cfg!(feature = "debug-log") {
                if dbg.rx <= 10 {
                    if let Some(rx_frame) = unsafe { &*area }.slice(desc.addr as usize, desc.len as usize) {
                        // Decode IP+TCP details from the frame
                        let pkt_detail = decode_frame_summary(rx_frame);
                        eprintln!(
                            "DBG RX_ETH[{}]: if={} q={} len={} {}",
                            dbg.rx, ident.ifindex, ident.queue_id, desc.len, pkt_detail,
                        );
                        // Full hex dump for first 3 packets
                        if dbg.rx <= 3 {
                            let dump_len = (desc.len as usize).min(rx_frame.len()).min(80);
                            let hex: String = rx_frame[..dump_len].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
                            eprintln!("DBG RX_HEX[{}]: {}", dbg.rx, hex);
                        }
                    }
                }
            }
            let mut recycle_now = true;
            if let Some(meta) = try_parse_metadata(unsafe { &*area }, desc) {
                counters.metadata_packets += 1;
                // DEBUG: log ALL packets on WAN interface (ifindex 6)
                if meta.ingress_ifindex == 6 || matches!(meta.protocol, 1 | 58) {
                    static ICMP_RX_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                    let c = ICMP_RX_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if c < 100 {
                        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open("/tmp/icmp_rx_debug.log") {
                            use std::io::Write;
                            let icmp_type = unsafe { &*area }.slice(desc.addr as usize, desc.len as usize)
                                .and_then(|fr| fr.get(meta.l4_offset as usize).copied()).unwrap_or(255);
                            let _ = writeln!(f, "ICMP_RX[{}]: proto={} af={} l4_off={} icmp_type={} len={} if={} slot={}",
                                c, meta.protocol, meta.addr_family, meta.l4_offset, icmp_type, desc.len, meta.ingress_ifindex, binding.slot);
                        }
                    }
                }
                let disposition = classify_metadata(meta, validation);
                if disposition == PacketDisposition::Valid {
                    counters.validated_packets += 1;
                    counters.validated_bytes += desc.len as u64;
                    let flow = parse_session_flow(unsafe { &*area }, desc, meta);
                    if let Some(flow) = flow.as_ref() {
                        learn_dynamic_neighbor_from_packet(
                            unsafe { &*area },
                            desc,
                            meta,
                            flow.src_ip,
                            &mut binding.last_learned_neighbor,
                            forwarding,
                            dynamic_neighbors,
                        );
                    }
                    let ingress_zone_override = parse_zone_encoded_fabric_ingress(
                        unsafe { &*area },
                        desc,
                        meta,
                        forwarding,
                    );
                    // Screen/IDS check — runs BEFORE session lookup.
                    // Resolve ingress zone name for screen profile lookup.
                    if screen.has_profiles() {
                        if let Some(flow) = flow.as_ref() {
                            let zone_name = ingress_zone_override
                                .as_deref()
                                .or_else(|| forwarding.ifindex_to_zone.get(&(meta.ingress_ifindex as i32)).map(|s| s.as_str()));
                            if let Some(zone_name) = zone_name {
                                let l3_off = if meta.ingress_vlan_id > 0 {
                                    18
                                } else {
                                    14 // default Ethernet header
                                };
                                let screen_pkt = if let Some(rx_frame) = unsafe { &*area }.slice(desc.addr as usize, desc.len as usize) {
                                    extract_screen_info(
                                        rx_frame,
                                        meta.addr_family,
                                        meta.protocol,
                                        meta.tcp_flags,
                                        meta.pkt_len,
                                        flow.src_ip,
                                        flow.dst_ip,
                                        flow.forward_key.src_port,
                                        flow.forward_key.dst_port,
                                        l3_off,
                                    )
                                } else {
                                    ScreenPacketInfo {
                                        addr_family: meta.addr_family,
                                        protocol: meta.protocol,
                                        tcp_flags: meta.tcp_flags,
                                        src_ip: flow.src_ip,
                                        dst_ip: flow.dst_ip,
                                        src_port: flow.forward_key.src_port,
                                        dst_port: flow.forward_key.dst_port,
                                        pkt_len: meta.pkt_len,
                                        is_fragment: false,
                                        ip_ihl: 5,
                                        ip_frag_off: 0,
                                        ip_total_len: 0,
                                    }
                                };
                                if let ScreenVerdict::Drop(_reason) = screen.check_packet(zone_name, &screen_pkt, now_secs) {
                                    binding.live.screen_drops.fetch_add(1, Ordering::Relaxed);
                                    binding.scratch_recycle.push(desc.addr);
                                    continue;
                                }
                            }
                        }
                    }
                    // IPsec passthrough: ESP (proto 50) and IKE (UDP 500/4500)
                    // must be handled by the kernel XFRM subsystem. Send these
                    // packets to the slow-path TUN device so the kernel can
                    // encrypt/decrypt via XFRM, then recycle the UMEM frame.
                    if let Some(flow) = flow.as_ref() {
                        if is_ipsec_traffic(meta.protocol, flow.forward_key.dst_port) {
                            let ipsec_decision = SessionDecision {
                                resolution: ForwardingResolution {
                                    disposition: ForwardingDisposition::LocalDelivery,
                                    local_ifindex: 0,
                                    egress_ifindex: 0,
                                    tx_ifindex: 0,
                                    next_hop: None,
                                    neighbor_mac: None,
                                    src_mac: None,
                                    tx_vlan_id: 0,
                                },
                                nat: NatDecision::default(),
                            };
                            maybe_reinject_slow_path(
                                &ident,
                                &binding.live,
                                slow_path,
                                unsafe { &*area },
                                desc,
                                meta,
                                ipsec_decision,
                                recent_exceptions,
                            );
                            binding.scratch_recycle.push(desc.addr);
                            continue;
                        }
                    }
                    let mut debug = flow
                        .as_ref()
                        .map(|flow| ResolutionDebug::from_flow(meta.ingress_ifindex as i32, flow));
                    let decision = if let Some(flow) = flow.as_ref() {
                        if let Some(hit) =
                            sessions.lookup(&flow.forward_key, now_ns, meta.tcp_flags)
                        {
                            counters.session_hits += 1;
                            dbg.session_hit += 1;
                            // Log first N session hits from WAN (return path)
                            if cfg!(feature = "debug-log") && meta.ingress_ifindex == 6 && dbg.wan_return_hits < 5 {
                                dbg.wan_return_hits += 1;
                                debug_log!(
                                    "DBG WAN_RETURN_HIT[{}]: {}:{} -> {}:{} proto={} tcp_flags=0x{:02x} nat=({:?},{:?}) rev={}",
                                    dbg.wan_return_hits,
                                    flow.src_ip, flow.forward_key.src_port,
                                    flow.dst_ip, flow.forward_key.dst_port,
                                    meta.protocol, meta.tcp_flags,
                                    hit.decision.nat.rewrite_src, hit.decision.nat.rewrite_dst,
                                    hit.metadata.is_reverse,
                                );
                            }
                            let mut decision = hit.decision;
                            if let Some(debug) = debug.as_mut() {
                                debug.from_zone = Some(hit.metadata.ingress_zone.clone());
                                debug.to_zone = Some(hit.metadata.egress_zone.clone());
                            }
                            decision.resolution = redirect_via_fabric_if_needed(
                                forwarding,
                                enforce_ha_resolution_snapshot(
                                    forwarding,
                                    ha_state,
                                    now_secs,
                                    lookup_forwarding_resolution_for_session(
                                        forwarding,
                                        dynamic_neighbors,
                                        flow,
                                        decision,
                                    ),
                                ),
                                meta.ingress_ifindex as i32,
                            );
                            if hit.metadata.synced
                                && decision.resolution.disposition
                                    == ForwardingDisposition::ForwardCandidate
                            {
                                let mut promoted = hit.metadata.clone();
                                promoted.synced = false;
                                if promoted.owner_rg_id <= 0 {
                                    promoted.owner_rg_id = owner_rg_for_flow(
                                        forwarding,
                                        decision.resolution.egress_ifindex,
                                    );
                                }
                                if sessions.promote_synced(
                                    &flow.forward_key,
                                    decision,
                                    promoted.clone(),
                                    now_ns,
                                    meta.protocol,
                                    meta.tcp_flags,
                                ) {
                                    let _ = publish_live_session_key(
                                        binding.session_map_fd,
                                        &flow.forward_key,
                                    );
                                    let promoted_entry = SyncedSessionEntry {
                                        key: flow.forward_key.clone(),
                                        decision,
                                        metadata: promoted,
                                        protocol: meta.protocol,
                                        tcp_flags: meta.tcp_flags,
                                    };
                                    publish_shared_session(
                                        shared_sessions,
                                        shared_nat_sessions,
                                        &promoted_entry,
                                    );
                                    replicate_session_upsert(peer_worker_commands, &promoted_entry);
                                }
                            }
                            decision
                        } else if let Some(shared) =
                            lookup_shared_session(shared_sessions, &flow.forward_key)
                        {
                            counters.session_hits += 1;
                            dbg.session_hit += 1;
                            let replica = synced_replica_entry(&shared);
                            sessions.upsert_synced(
                                replica.key.clone(),
                                replica.decision,
                                replica.metadata.clone(),
                                now_ns,
                                replica.protocol,
                                meta.tcp_flags,
                            );
                            if let Some(debug) = debug.as_mut() {
                                debug.from_zone = Some(replica.metadata.ingress_zone.clone());
                                debug.to_zone = Some(replica.metadata.egress_zone.clone());
                            }
                            let mut decision = replica.decision;
                            decision.resolution = redirect_via_fabric_if_needed(
                                forwarding,
                                enforce_ha_resolution_snapshot(
                                    forwarding,
                                    ha_state,
                                    now_secs,
                                    lookup_forwarding_resolution_for_session(
                                        forwarding,
                                        dynamic_neighbors,
                                        flow,
                                        decision,
                                    ),
                                ),
                                meta.ingress_ifindex as i32,
                            );
                            if decision.resolution.disposition
                                == ForwardingDisposition::ForwardCandidate
                            {
                                let mut promoted = replica.metadata.clone();
                                promoted.synced = false;
                                if promoted.owner_rg_id <= 0 {
                                    promoted.owner_rg_id = owner_rg_for_flow(
                                        forwarding,
                                        decision.resolution.egress_ifindex,
                                    );
                                }
                                if sessions.promote_synced(
                                    &flow.forward_key,
                                    decision,
                                    promoted.clone(),
                                    now_ns,
                                    meta.protocol,
                                    meta.tcp_flags,
                                ) {
                                    let _ = publish_live_session_key(
                                        binding.session_map_fd,
                                        &flow.forward_key,
                                    );
                                    let promoted_entry = SyncedSessionEntry {
                                        key: flow.forward_key.clone(),
                                        decision,
                                        metadata: promoted,
                                        protocol: meta.protocol,
                                        tcp_flags: meta.tcp_flags,
                                    };
                                    publish_shared_session(
                                        shared_sessions,
                                        shared_nat_sessions,
                                        &promoted_entry,
                                    );
                                    replicate_session_upsert(peer_worker_commands, &promoted_entry);
                                }
                            }
                            decision
                        } else if let Some(repaired) = repair_reverse_session_from_forward(
                            sessions,
                            binding.session_map_fd,
                            shared_sessions,
                            shared_nat_sessions,
                            peer_worker_commands,
                            forwarding,
                            ha_state,
                            dynamic_neighbors,
                            flow,
                            now_ns,
                            now_secs,
                            meta.protocol,
                            meta.tcp_flags,
                        ) {
                            counters.session_hits += 1;
                            counters.session_creates += 1;
                            dbg.session_hit += 1;
                            dbg.session_create += 1;
                            if let Some(debug) = debug.as_mut() {
                                debug.from_zone = Some(repaired.metadata.ingress_zone.clone());
                                debug.to_zone = Some(repaired.metadata.egress_zone.clone());
                            }
                            let mut decision = repaired.decision;
                            decision.resolution = redirect_via_fabric_if_needed(
                                forwarding,
                                enforce_ha_resolution_snapshot(
                                    forwarding,
                                    ha_state,
                                    now_secs,
                                    lookup_forwarding_resolution_for_session(
                                        forwarding,
                                        dynamic_neighbors,
                                        flow,
                                        decision,
                                    ),
                                ),
                                meta.ingress_ifindex as i32,
                            );
                            decision
                        } else {
                            counters.session_misses += 1;
                            dbg.session_miss += 1;
                            let resolution_target =
                                parse_packet_destination(unsafe { &*area }, desc, meta)
                                    .unwrap_or(flow.dst_ip);

                            // --- DNAT pre-routing ---
                            // Check DNAT table first (port-based DNAT), then
                            // fall back to static NAT DNAT (IP-only 1:1).
                            // The translated destination affects FIB lookup.
                            let ingress_zone_name = ingress_zone_override
                                .as_deref()
                                .or_else(|| {
                                    forwarding
                                        .ifindex_to_zone
                                        .get(&(meta.ingress_ifindex as i32))
                                        .map(|s| s.as_str())
                                })
                                .unwrap_or("");
                            let dnat_decision = if !forwarding.dnat_table.is_empty() {
                                forwarding.dnat_table.lookup(
                                    meta.protocol,
                                    resolution_target,
                                    flow.forward_key.dst_port,
                                )
                            } else {
                                None
                            };
                            let static_dnat_decision = if dnat_decision.is_none() {
                                forwarding.static_nat.match_dnat(resolution_target, ingress_zone_name)
                            } else {
                                None
                            };
                            let pre_routing_dnat = dnat_decision.or(static_dnat_decision);

                            // --- NPTv6 inbound pre-routing ---
                            // If dst matches an external NPTv6 prefix, translate the
                            // destination to the internal prefix. This is stateless
                            // prefix translation (RFC 6296) -- no L4 checksum update.
                            let nptv6_inbound = if pre_routing_dnat.is_none() {
                                if let IpAddr::V6(mut dst_v6) = resolution_target {
                                    if forwarding.nptv6.translate_inbound(&mut dst_v6) {
                                        Some(dst_v6)
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                }
                            } else {
                                None
                            };

                            // --- NAT64 pre-routing ---
                            // If dst is IPv6 matching a NAT64 prefix, extract IPv4
                            // dest and allocate an IPv4 SNAT address. Route lookup
                            // must use the IPv4 destination.
                            let nat64_match = if pre_routing_dnat.is_none() && nptv6_inbound.is_none() {
                                if let IpAddr::V6(dst_v6) = resolution_target {
                                    forwarding.nat64.match_ipv6_dest(dst_v6).and_then(|(idx, dst_v4)| {
                                        let snat_v4 = forwarding.nat64.allocate_v4_source(idx)?;
                                        Some((idx, dst_v4, snat_v4, dst_v6))
                                    })
                                } else {
                                    None
                                }
                            } else {
                                None
                            };

                            let effective_resolution_target = if let Some((_, dst_v4, _, _)) = &nat64_match {
                                IpAddr::V4(*dst_v4)
                            } else if let Some(internal_dst) = nptv6_inbound {
                                IpAddr::V6(internal_dst)
                            } else {
                                match &pre_routing_dnat {
                                    Some(d) => d.rewrite_dst.unwrap_or(resolution_target),
                                    None => resolution_target,
                                }
                            };

                            let resolution = ingress_interface_local_resolution_on_session_miss(
                                forwarding,
                                meta.ingress_ifindex as i32,
                                meta.ingress_vlan_id,
                                effective_resolution_target,
                                meta.protocol,
                            )
                            .or_else(|| {
                                interface_nat_local_resolution_on_session_miss(
                                    forwarding,
                                    effective_resolution_target,
                                    meta.protocol,
                                )
                            })
                            .unwrap_or_else(|| {
                                enforce_ha_resolution_snapshot(
                                    forwarding,
                                    ha_state,
                                    now_secs,
                                    lookup_forwarding_resolution_with_dynamic(
                                        forwarding,
                                        dynamic_neighbors,
                                        effective_resolution_target,
                                    ),
                                )
                            });
                            let nptv6_nat = nptv6_inbound.map(|internal_dst| NatDecision {
                                rewrite_src: None,
                                rewrite_dst: Some(IpAddr::V6(internal_dst)),
                                nat64: false,
                                nptv6: true,
                                ..NatDecision::default()
                            });
                            let mut decision = SessionDecision {
                                resolution,
                                nat: nptv6_nat.or(pre_routing_dnat).unwrap_or_default(),
                            };
                            let (from_zone, to_zone) = zone_pair_for_flow_with_override(
                                forwarding,
                                meta.ingress_ifindex as i32,
                                ingress_zone_override.as_deref(),
                                resolution.egress_ifindex,
                            );
                            let from_zone_arc = Arc::<str>::from(from_zone.as_str());
                            let to_zone_arc = Arc::<str>::from(to_zone.as_str());
                            // Always log trust/lan traffic (iperf3) regardless of throttle
                            let is_trust_flow = meta.ingress_ifindex == 5
                                || from_zone == "lan"
                                || matches!(flow.src_ip, IpAddr::V4(ip) if ip.octets()[0] == 10);
                            // Debug: log session miss with flow details (throttled)
                            if cfg!(feature = "debug-log") {
                                if dbg.session_miss <= 10 || is_trust_flow {
                                    eprintln!(
                                        "DBG SESS_MISS[{}]: {}:{} -> {}:{} proto={} tcp_flags=0x{:02x} ingress_if={} disp={:?} egress_if={} neigh={:?} zone={}->{}",
                                        dbg.session_miss,
                                        flow.src_ip, flow.forward_key.src_port,
                                        flow.dst_ip, flow.forward_key.dst_port,
                                        meta.protocol, meta.tcp_flags,
                                        meta.ingress_ifindex,
                                        resolution.disposition,
                                        resolution.egress_ifindex,
                                        resolution.neighbor_mac.map(|m| format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", m[0],m[1],m[2],m[3],m[4],m[5])),
                                        from_zone, to_zone,
                                    );
                                    // If from WAN (if6), dump what session key was tried
                                    if meta.ingress_ifindex == 6 {
                                        eprintln!(
                                            "DBG SESS_MISS_KEY: af={} proto={} key={}:{}->{}:{} bpf_entries={} local_sessions={}",
                                            flow.forward_key.addr_family, flow.forward_key.protocol,
                                            flow.forward_key.src_ip, flow.forward_key.src_port,
                                            flow.forward_key.dst_ip, flow.forward_key.dst_port,
                                            count_bpf_session_entries(binding.session_map_fd),
                                            sessions.len(),
                                        );
                                        // Dump all local sessions to compare
                                        if dbg.session_miss <= 3 {
                                            let mut sess_dump = String::new();
                                            let mut count = 0;
                                            sessions.iter(|key, decision, metadata| {
                                                if count < 30 {
                                                    use std::fmt::Write;
                                                    let _ = write!(sess_dump,
                                                        "\n  LOCAL_SESS: af={} proto={} {}:{}->{}:{} nat=({:?},{:?}) rev={} synced={}",
                                                        key.addr_family, key.protocol,
                                                        key.src_ip, key.src_port, key.dst_ip, key.dst_port,
                                                        decision.nat.rewrite_src, decision.nat.rewrite_dst,
                                                        metadata.is_reverse, metadata.synced,
                                                    );
                                                    count += 1;
                                                }
                                            });
                                            if !sess_dump.is_empty() {
                                                eprintln!("DBG SESS_MISS_DUMP:{sess_dump}");
                                            }
                                        }
                                    }
                                }
                            }
                            if let Some(debug) = debug.as_mut() {
                                debug.from_zone = Some(from_zone_arc.clone());
                                debug.to_zone = Some(to_zone_arc.clone());
                            }
                            // Embedded ICMP NAT reversal applies only to actual ICMP error
                            // packets. Echo and other non-error ICMP traffic should follow
                            // the ordinary policy/session path.
                            let is_embedded_icmp_error = if forwarding.allow_embedded_icmp
                                && matches!(meta.protocol, PROTO_ICMP | PROTO_ICMPV6)
                            {
                                unsafe { &*area }
                                    .slice(desc.addr as usize, desc.len as usize)
                                    .and_then(|fr| fr.get(meta.l4_offset as usize).copied())
                                    .map(|icmp_type| is_icmp_error(meta.protocol, icmp_type))
                                    .unwrap_or(false)
                            } else {
                                false
                            };
                            if is_embedded_icmp_error {
                                    if let Some(icmp_match) = try_embedded_icmp_nat_match(
                                        unsafe { &*area },
                                        desc,
                                        meta,
                                        sessions,
                                        forwarding,
                                        dynamic_neighbors,
                                        shared_nat_sessions,
                                        now_ns,
                                    ) {
                                        if icmp_match.nat.rewrite_src.is_some() {
                                            let icmp_resolution = finalize_embedded_icmp_resolution(
                                                forwarding,
                                                ha_state,
                                                now_secs,
                                                meta.ingress_ifindex as i32,
                                                &icmp_match,
                                            );
                                            let frame_data = unsafe { &*area }
                                                .slice(desc.addr as usize, desc.len as usize);
                                            let rewritten = frame_data.and_then(|frame| {
                                                match meta.addr_family as i32 {
                                                    libc::AF_INET => {
                                                        build_nat_reversed_icmp_error_v4(
                                                            frame, meta, &icmp_match,
                                                        )
                                                    }
                                                    libc::AF_INET6 => {
                                                        build_nat_reversed_icmp_error_v6(
                                                            frame, meta, &icmp_match,
                                                        )
                                                    }
                                                    _ => None,
                                                }
                                            });
                                            if let Some(rewritten_frame) = rewritten {
                                                let icmp_decision = SessionDecision {
                                                    resolution: icmp_resolution,
                                                    nat: NatDecision::default(),
                                                };
                                                let target_ifindex =
                                                    if icmp_decision.resolution.tx_ifindex > 0 {
                                                        icmp_decision.resolution.tx_ifindex
                                                    } else {
                                                        resolve_tx_binding_ifindex(
                                                            forwarding,
                                                            icmp_decision.resolution.egress_ifindex,
                                                        )
                                                    };
                                                binding.scratch_forwards.push(
                                                    PendingForwardRequest {
                                                        target_ifindex,
                                                        ingress_queue_id: ident.queue_id,
                                                        source_offset: desc.addr,
                                                        desc,
                                                        meta,
                                                        decision: icmp_decision,
                                                        expected_ports: None,
                                                        flow_key: None,
                                                        nat64_reverse: None,
                                                        prebuilt_frame: Some(rewritten_frame),
                                                    },
                                                );
                                                recycle_now = false;
                                            }
                                        }
                                    }
                                    // Permit without policy check or session install.
                                    // If NAT reversal was applied, the prebuilt frame
                                    // is already queued. If not, fall through to slow-path.
                                } else if resolution.disposition == ForwardingDisposition::ForwardCandidate {
                                let owner_rg_id =
                                    owner_rg_for_flow(forwarding, resolution.egress_ifindex);
                                if allow_unsolicited_dns_reply(forwarding, flow) {
                                    // Match the XDP fast path: unsolicited DNS replies bypass
                                    // policy/session install when the flow knob is enabled.
                                } else if let PolicyAction::Permit = evaluate_policy(
                                    &forwarding.policy,
                                    &from_zone,
                                    &to_zone,
                                    flow.src_ip,
                                    flow.dst_ip,
                                    flow.forward_key.protocol,
                                    flow.forward_key.src_port,
                                    flow.forward_key.dst_port,
                                ) {
                                    // NAT64: cross-family translation takes
                                    // priority over same-family SNAT.
                                    let nat64_info = if let Some((_, dst_v4, snat_v4, orig_dst_v6)) = nat64_match {
                                        decision.nat = Nat64State::forward_decision(snat_v4, dst_v4);
                                        Some(Nat64ReverseInfo {
                                            orig_src_v6: match flow.src_ip {
                                                IpAddr::V6(v6) => v6,
                                                _ => std::net::Ipv6Addr::UNSPECIFIED,
                                            },
                                            orig_dst_v6: orig_dst_v6,
                                        })
                                    } else {
                                        // Check NPTv6 outbound, then static NAT SNAT, then interface SNAT.
                                        // Use merge() to combine with any pre-routing DNAT
                                        // decision rather than overwriting it.
                                        if decision.nat.rewrite_dst.is_none() {
                                            // Try NPTv6 outbound: if src matches an internal prefix,
                                            // translate to external prefix (stateless, no L4 csum update).
                                            let nptv6_snat = if let IpAddr::V6(mut src_v6) = flow.src_ip {
                                                if forwarding.nptv6.translate_outbound(&mut src_v6) {
                                                    Some(NatDecision {
                                                        rewrite_src: Some(IpAddr::V6(src_v6)),
                                                        rewrite_dst: None,
                                                        nat64: false,
                                                        nptv6: true,
                                                        ..NatDecision::default()
                                                    })
                                                } else {
                                                    None
                                                }
                                            } else {
                                                None
                                            };
                                            decision.nat = nptv6_snat
                                                .or_else(|| forwarding
                                                    .static_nat
                                                    .match_snat(flow.src_ip, &from_zone))
                                                .or_else(|| {
                                                    match_source_nat_for_flow(
                                                        forwarding,
                                                        &from_zone,
                                                        &to_zone,
                                                        resolution.egress_ifindex,
                                                        flow,
                                                    )
                                                })
                                                .unwrap_or_default();
                                        } else {
                                            let snat_decision = forwarding
                                                .static_nat
                                                .match_snat(flow.src_ip, &from_zone)
                                                .or_else(|| {
                                                    match_source_nat_for_flow(
                                                        forwarding,
                                                        &from_zone,
                                                        &to_zone,
                                                        resolution.egress_ifindex,
                                                        flow,
                                                    )
                                                })
                                                .unwrap_or_default();
                                            decision.nat = decision.nat.merge(snat_decision);
                                        }
                                        None
                                    };
                                    let local_icmp_te = unsafe { &*area }
                                        .slice(desc.addr as usize, desc.len as usize)
                                        .and_then(|frame| {
                                            build_local_time_exceeded_request(
                                                frame,
                                                desc,
                                                meta,
                                                &ident,
                                                flow,
                                                forwarding,
                                                dynamic_neighbors,
                                                ha_state,
                                                now_secs,
                                            )
                                        });
                                    if let Some(request) = local_icmp_te {
                                        binding.scratch_forwards.push(request);
                                        recycle_now = false;
                                    } else {
                                        let mut created = 0u64;
                                        let forward_metadata = SessionMetadata {
                                            ingress_zone: from_zone_arc.clone(),
                                            egress_zone: to_zone_arc.clone(),
                                            owner_rg_id,
                                            is_reverse: false,
                                            synced: false,
                                            nat64_reverse: nat64_info,
                                        };
                                        if sessions.install_with_protocol(
                                            flow.forward_key.clone(),
                                            decision,
                                            forward_metadata.clone(),
                                            now_ns,
                                            meta.protocol,
                                            meta.tcp_flags,
                                        ) {
                                            let _ = publish_live_session_key(
                                                binding.session_map_fd,
                                                &flow.forward_key,
                                            );
                                            created += 1;
                                            let forward_entry = SyncedSessionEntry {
                                                key: flow.forward_key.clone(),
                                                decision,
                                                metadata: forward_metadata,
                                                protocol: meta.protocol,
                                                tcp_flags: meta.tcp_flags,
                                            };
                                            publish_shared_session(
                                                shared_sessions,
                                                shared_nat_sessions,
                                                &forward_entry,
                                            );
                                            replicate_session_upsert(
                                                peer_worker_commands,
                                                &forward_entry,
                                            );
                                        }
                                        let reverse_resolution = enforce_ha_resolution_snapshot(
                                            forwarding,
                                            ha_state,
                                            now_secs,
                                            lookup_forwarding_resolution_with_dynamic(
                                                forwarding,
                                                dynamic_neighbors,
                                                flow.src_ip,
                                            ),
                                        );
                                        // Install the reverse entry even if the initial reply-side
                                        // resolution is not immediately usable. On live traffic the
                                        // first server reply can arrive before the reverse neighbor
                                        // state has converged on every worker, and dropping the reverse
                                        // entry creation turns that race into a hard policy miss. The
                                        // hit path re-resolves on demand and can fall back to the
                                        // cached decision when neighbor convergence is still in flight.
                                        let reverse_decision = SessionDecision {
                                            resolution: reverse_resolution,
                                            nat: decision.nat.reverse(
                                                flow.src_ip,
                                                flow.dst_ip,
                                                flow.forward_key.src_port,
                                                flow.forward_key.dst_port,
                                            ),
                                        };
                                        // For NAT64: the reverse key is IPv4 (different AF
                                        // from the forward IPv6 key). The reply arrives as
                                        // IPv4: src=dst_v4, dst=snat_v4.
                                        let (reverse_key, reverse_protocol) = if let Some(ref info) = nat64_info {
                                            let nat = decision.nat;
                                            let dst_v4 = match nat.rewrite_dst {
                                                Some(IpAddr::V4(v4)) => v4,
                                                _ => Ipv4Addr::UNSPECIFIED,
                                            };
                                            let snat_v4 = match nat.rewrite_src {
                                                Some(IpAddr::V4(v4)) => v4,
                                                _ => Ipv4Addr::UNSPECIFIED,
                                            };
                                            // Map protocol: ICMPv6→ICMP for the reverse key.
                                            let rev_proto = match meta.protocol {
                                                PROTO_ICMPV6 => PROTO_ICMP,
                                                p => p,
                                            };
                                            let (src_port, dst_port) = if matches!(meta.protocol, PROTO_ICMP | PROTO_ICMPV6) {
                                                (flow.forward_key.src_port, flow.forward_key.dst_port)
                                            } else {
                                                (flow.forward_key.dst_port, flow.forward_key.src_port)
                                            };
                                            (SessionKey {
                                                addr_family: libc::AF_INET as u8,
                                                protocol: rev_proto,
                                                src_ip: IpAddr::V4(dst_v4),
                                                dst_ip: IpAddr::V4(snat_v4),
                                                src_port,
                                                dst_port,
                                            }, rev_proto)
                                        } else {
                                            (flow.reverse_key_with_nat(decision.nat), meta.protocol)
                                        };
                                        let _ = reverse_protocol; // used below for install
                                        let reverse_metadata = SessionMetadata {
                                            ingress_zone: to_zone_arc,
                                            egress_zone: from_zone_arc,
                                            owner_rg_id,
                                            is_reverse: true,
                                            synced: false,
                                            nat64_reverse: nat64_info,
                                        };
                                        if sessions.install_with_protocol(
                                            reverse_key.clone(),
                                            reverse_decision,
                                            reverse_metadata.clone(),
                                            now_ns,
                                            meta.protocol,
                                            meta.tcp_flags,
                                        ) {
                                            let _ = publish_live_session_key(
                                                binding.session_map_fd,
                                                &reverse_key,
                                            );
                                            // Verify session keys and log creations (debug-only: BPF syscalls)
                                            if cfg!(feature = "debug-log") {
                                                if verify_session_key_in_bpf(binding.session_map_fd, &reverse_key) {
                                                    SESSION_PUBLISH_VERIFY_OK.fetch_add(1, Ordering::Relaxed);
                                                } else {
                                                    SESSION_PUBLISH_VERIFY_FAIL.fetch_add(1, Ordering::Relaxed);
                                                    debug_log!(
                                                        "SESS_VERIFY_FAIL: reverse key NOT found after publish! \
                                                         af={} proto={} {}:{} -> {}:{} (map_fd={})",
                                                        reverse_key.addr_family, reverse_key.protocol,
                                                        reverse_key.src_ip, reverse_key.src_port,
                                                        reverse_key.dst_ip, reverse_key.dst_port,
                                                        binding.session_map_fd,
                                                    );
                                                }
                                                if !verify_session_key_in_bpf(binding.session_map_fd, &flow.forward_key) {
                                                    debug_log!(
                                                        "SESS_VERIFY_FAIL: forward key NOT found! \
                                                         af={} proto={} {}:{} -> {}:{}",
                                                        flow.forward_key.addr_family, flow.forward_key.protocol,
                                                        flow.forward_key.src_ip, flow.forward_key.src_port,
                                                        flow.forward_key.dst_ip, flow.forward_key.dst_port,
                                                    );
                                                }
                                                let logged = SESSION_CREATIONS_LOGGED.fetch_add(1, Ordering::Relaxed);
                                                if logged < 10 {
                                                    let fwd = &flow.forward_key;
                                                    debug_log!(
                                                        "SESS_CREATE[{}]: FWD af={} proto={} {}:{} -> {}:{} \
                                                         | REV af={} proto={} {}:{} -> {}:{} \
                                                         | NAT src={:?} dst={:?} \
                                                         | map_fd={} bpf_entries={}",
                                                        logged, fwd.addr_family, fwd.protocol,
                                                        fwd.src_ip, fwd.src_port, fwd.dst_ip, fwd.dst_port,
                                                        reverse_key.addr_family, reverse_key.protocol,
                                                        reverse_key.src_ip, reverse_key.src_port,
                                                        reverse_key.dst_ip, reverse_key.dst_port,
                                                        decision.nat.rewrite_src, decision.nat.rewrite_dst,
                                                        binding.session_map_fd,
                                                        count_bpf_session_entries(binding.session_map_fd),
                                                    );
                                                    dump_bpf_session_entries(binding.session_map_fd, 20);
                                                }
                                            }
                                            created += 1;
                                            let reverse_entry = SyncedSessionEntry {
                                                key: reverse_key,
                                                decision: reverse_decision,
                                                metadata: reverse_metadata,
                                                protocol: meta.protocol,
                                                tcp_flags: meta.tcp_flags,
                                            };
                                            publish_shared_session(
                                                shared_sessions,
                                                shared_nat_sessions,
                                                &reverse_entry,
                                            );
                                            replicate_session_upsert(
                                                peer_worker_commands,
                                                &reverse_entry,
                                            );
                                        }
                                        if created > 0 {
                                            counters.session_creates += created;
                                            dbg.session_create += created;
                                        }
                                    }
                                } else {
                                    dbg.policy_deny += 1;
                                    if cfg!(feature = "debug-log") && (dbg.policy_deny <= 3 || is_trust_flow) {
                                        debug_log!(
                                            "DBG POLICY_DENY[{}]: {}:{} -> {}:{} proto={} zone={}->{}  ingress_if={} egress_if={}",
                                            dbg.policy_deny,
                                            flow.src_ip, flow.forward_key.src_port,
                                            flow.dst_ip, flow.forward_key.dst_port,
                                            meta.protocol,
                                            from_zone, to_zone,
                                            meta.ingress_ifindex,
                                            resolution.egress_ifindex,
                                        );
                                    }
                                    decision.resolution.disposition =
                                        ForwardingDisposition::PolicyDenied;
                                }
                            } else if resolution.disposition == ForwardingDisposition::HAInactive
                                && !ingress_is_fabric(forwarding, meta.ingress_ifindex as i32)
                            {
                                if let Some((Some(from_zone), _)) = debug
                                    .as_ref()
                                    .map(|debug| (debug.from_zone.clone(), debug.to_zone.clone()))
                                {
                                    if let Some(redirect) = resolve_zone_encoded_fabric_redirect(
                                        forwarding,
                                        from_zone.as_ref(),
                                    ) {
                                        decision.resolution = redirect;
                                    }
                                }
                            }
                            decision
                        }
                    } else {
                        SessionDecision {
                            resolution: enforce_ha_resolution_snapshot(
                                forwarding,
                                ha_state,
                                now_secs,
                                resolve_forwarding(
                                    unsafe { &*area },
                                    desc,
                                    meta,
                                    forwarding,
                                    dynamic_neighbors,
                                ),
                            ),
                            nat: NatDecision::default(),
                        }
                    };
                    if matches!(
                        decision.resolution.disposition,
                        ForwardingDisposition::ForwardCandidate
                            | ForwardingDisposition::FabricRedirect
                    ) {
                        dbg.forward += 1;
                        // Direction-specific tracking
                        let ingress_if = meta.ingress_ifindex as i32;
                        let egress_if = decision.resolution.egress_ifindex;
                        if ingress_if == 5 {
                            dbg.rx_from_trust += 1;
                            dbg.fwd_trust_to_wan += 1;
                        } else if ingress_if == 6 {
                            dbg.rx_from_wan += 1;
                            dbg.fwd_wan_to_trust += 1;
                        }
                        // NAT decision tracking
                        if decision.nat.rewrite_src.is_some() && decision.nat.rewrite_dst.is_some() {
                            dbg.nat_applied_snat += 1;
                            dbg.nat_applied_dnat += 1;
                        } else if decision.nat.rewrite_src.is_some() {
                            dbg.nat_applied_snat += 1;
                        } else if decision.nat.rewrite_dst.is_some() {
                            dbg.nat_applied_dnat += 1;
                        } else {
                            dbg.nat_applied_none += 1;
                        }
                        // Log NAT details for first few forward-candidate packets
                        if cfg!(feature = "debug-log") {
                            if dbg.forward <= 10 {
                                let flow_str = flow.as_ref().map(|f| format!("{}:{} -> {}:{}", f.src_ip, f.forward_key.src_port, f.dst_ip, f.forward_key.dst_port)).unwrap_or_else(|| "no-flow".into());
                                let nat_str = format!(
                                    "snat={:?} dnat={:?}",
                                    decision.nat.rewrite_src, decision.nat.rewrite_dst,
                                );
                                eprintln!(
                                    "DBG FWD_DECISION[{}]: ingress_if={} egress_if={} {} {} proto={}",
                                    dbg.forward, ingress_if, egress_if, flow_str, nat_str, meta.protocol,
                                );
                            }
                        }
                        // TCP flag tracking on forwarded frames
                        if cfg!(feature = "debug-log") {
                            if meta.protocol == 6 {
                                // Compare meta.tcp_flags from BPF shim with raw frame TCP flags
                                let frame_data = unsafe { &*area }.slice(desc.addr as usize, desc.len as usize);
                                let raw_tcp_info = frame_data.and_then(|data| extract_tcp_flags_and_window(data));
                                let raw_flags = raw_tcp_info.map(|(f, _)| f);
                                let raw_window = raw_tcp_info.map(|(_, w)| w);
                                // Log first 20 forwarded TCP packets: compare meta vs raw
                                if dbg.forward <= 20 {
                                    let flow_str = flow.as_ref().map(|f| format!("{}:{} -> {}:{}", f.src_ip, f.forward_key.src_port, f.dst_ip, f.forward_key.dst_port)).unwrap_or_else(|| "no-flow".into());
                                    eprintln!(
                                        "FWD_TCP_CMP[{}]: meta_flags=0x{:02x} raw_flags={} raw_win={} len={} l4_off={} {}",
                                        dbg.forward, meta.tcp_flags,
                                        raw_flags.map(|f| format!("0x{:02x}", f)).unwrap_or_else(|| "NONE".into()),
                                        raw_window.map(|w| format!("{}", w)).unwrap_or_else(|| "NONE".into()),
                                        desc.len, meta.l4_offset, flow_str,
                                    );
                                    // Hex dump bytes around TCP flags position in raw frame
                                    if let Some(data) = frame_data {
                                        let l4 = meta.l4_offset as usize;
                                        if data.len() > l4 + 20 {
                                            let tcp_hdr: String = data[l4..l4+20].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
                                            eprintln!("FWD_TCP_HDR[{}]: offset={} {}", dbg.forward, l4, tcp_hdr);
                                        }
                                    }
                                }
                                if (meta.tcp_flags & 0x04) != 0 { // RST
                                    dbg.fwd_tcp_rst += 1;
                                    if dbg.fwd_tcp_rst <= 5 {
                                        let flow_str = flow.as_ref().map(|f| format!("{}:{} -> {}:{}", f.src_ip, f.forward_key.src_port, f.dst_ip, f.forward_key.dst_port)).unwrap_or_else(|| "no-flow".into());
                                        eprintln!(
                                            "FWD_TCP_RST_DETECT[{}]: meta_flags=0x{:02x} raw_flags={} raw_win={} len={} fwd#={} {}",
                                            dbg.fwd_tcp_rst, meta.tcp_flags,
                                            raw_flags.map(|f| format!("0x{:02x}", f)).unwrap_or_else(|| "NONE".into()),
                                            raw_window.map(|w| format!("{}", w)).unwrap_or_else(|| "NONE".into()),
                                            desc.len, dbg.forward, flow_str,
                                        );
                                        // Hex dump TCP header when RST detected
                                        if let Some(data) = frame_data {
                                            let l4 = meta.l4_offset as usize;
                                            if data.len() > l4 + 20 {
                                                let tcp_hdr: String = data[l4..l4+20].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
                                                eprintln!("FWD_TCP_RST_HDR[{}]: meta_off={} raw_off={} {}", dbg.fwd_tcp_rst, l4, frame_l3_offset(data).unwrap_or(0), tcp_hdr);
                                            }
                                        }
                                    }
                                }
                                if (meta.tcp_flags & 0x01) != 0 { // FIN
                                    dbg.fwd_tcp_fin += 1;
                                    if dbg.fwd_tcp_fin <= 5 {
                                        let flow_str = flow.as_ref().map(|f| format!("{}:{} -> {}:{}", f.src_ip, f.forward_key.src_port, f.dst_ip, f.forward_key.dst_port)).unwrap_or_else(|| "no-flow".into());
                                        eprintln!(
                                            "FWD_TCP_FIN[{}]: ingress_if={} {} tcp_flags=0x{:02x}",
                                            dbg.fwd_tcp_fin, meta.ingress_ifindex, flow_str, meta.tcp_flags,
                                        );
                                    }
                                }
                                // Detect zero-window in TCP frames by inspecting raw packet
                                if let Some(win) = raw_window {
                                    if win == 0 {
                                        dbg.fwd_tcp_zero_window += 1;
                                        if dbg.fwd_tcp_zero_window <= 10 {
                                            let flow_str = flow.as_ref().map(|f| format!("{}:{} -> {}:{}", f.src_ip, f.forward_key.src_port, f.dst_ip, f.forward_key.dst_port)).unwrap_or_else(|| "no-flow".into());
                                            eprintln!(
                                                "FWD_TCP_ZERO_WIN[{}]: ingress_if={} {} meta_flags=0x{:02x} raw_flags={}",
                                                dbg.fwd_tcp_zero_window, meta.ingress_ifindex, flow_str, meta.tcp_flags,
                                                raw_flags.map(|f| format!("0x{:02x}", f)).unwrap_or_else(|| "NONE".into()),
                                            );
                                        }
                                    }
                                }
                            }
                        }
                        if should_teardown_tcp_rst(meta, flow.as_ref())
                            && let Some(flow) = flow.as_ref()
                        {
                            rst_teardowns.push((flow.forward_key.clone(), decision.nat));
                        }
                        counters.forward_candidate_packets += 1;
                        if decision.nat.rewrite_src.is_some() {
                            counters.snat_packets += 1;
                        }
                        if decision.nat.rewrite_dst.is_some() {
                            counters.dnat_packets += 1;
                        }
                        if let Some(request) = build_live_forward_request(
                            unsafe { &*area },
                            &ident,
                            desc,
                            meta,
                            &decision,
                            forwarding,
                            flow.as_ref(),
                        ) {
                            dbg.tx += 1; // track forward requests queued
                            if cfg!(feature = "debug-log") {
                                if dbg.tx <= 5 {
                                    let dst_mac_str = decision.resolution.neighbor_mac.map(|m| format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", m[0],m[1],m[2],m[3],m[4],m[5])).unwrap_or_else(|| "NONE".into());
                                    let src_mac_str = decision.resolution.src_mac.map(|m| format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", m[0],m[1],m[2],m[3],m[4],m[5])).unwrap_or_else(|| "NONE".into());
                                    let flow_str = flow.as_ref().map(|f| format!("{}:{} -> {}:{}", f.src_ip, f.forward_key.src_port, f.dst_ip, f.forward_key.dst_port)).unwrap_or_else(|| "no-flow".into());
                                    eprintln!(
                                        "DBG FWD_REQ: target_if={} egress_if={} tx_if={} len={} proto={} vlan={} dst_mac={} src_mac={} flow={}",
                                        request.target_ifindex,
                                        decision.resolution.egress_ifindex,
                                        decision.resolution.tx_ifindex,
                                        desc.len,
                                        meta.protocol,
                                        decision.resolution.tx_vlan_id,
                                        dst_mac_str,
                                        src_mac_str,
                                        flow_str,
                                    );
                                }
                            }
                            binding.scratch_forwards.push(request);
                            recycle_now = false;
                        } else {
                            dbg.build_fail += 1;
                            if cfg!(feature = "debug-log") {
                                if dbg.build_fail <= 3 {
                                    eprintln!(
                                        "DBG FWD_BUILD_NONE: egress_if={} tx_if={} neigh={:?} src_mac={:?} len={} proto={}",
                                        decision.resolution.egress_ifindex,
                                        decision.resolution.tx_ifindex,
                                        decision.resolution.neighbor_mac.map(|m| format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", m[0],m[1],m[2],m[3],m[4],m[5])),
                                        decision.resolution.src_mac.map(|m| format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", m[0],m[1],m[2],m[3],m[4],m[5])),
                                        desc.len,
                                        meta.protocol,
                                    );
                                }
                            }
                        }
                    } else {
                        // Debug: count non-forward dispositions
                        match decision.resolution.disposition {
                            ForwardingDisposition::LocalDelivery => dbg.local += 1,
                            ForwardingDisposition::NoRoute => {
                                dbg.no_route += 1;
                                if cfg!(feature = "debug-log") {
                                    if dbg.no_route <= 3 {
                                        if let Some(flow) = flow.as_ref() {
                                            eprintln!(
                                                "DBG NO_ROUTE: {}:{} -> {}:{} proto={} ingress_if={}",
                                                flow.src_ip, flow.forward_key.src_port,
                                                flow.dst_ip, flow.forward_key.dst_port,
                                                meta.protocol, meta.ingress_ifindex,
                                            );
                                        }
                                    }
                                }
                            }
                            ForwardingDisposition::MissingNeighbor => {
                                dbg.missing_neigh += 1;
                                if cfg!(feature = "debug-log") {
                                    if dbg.missing_neigh <= 3 {
                                        if let Some(flow) = flow.as_ref() {
                                            eprintln!(
                                                "DBG MISS_NEIGH: {}:{} -> {}:{} proto={} egress_if={} next_hop={:?}",
                                                flow.src_ip, flow.forward_key.src_port,
                                                flow.dst_ip, flow.forward_key.dst_port,
                                                meta.protocol,
                                                decision.resolution.egress_ifindex,
                                                decision.resolution.next_hop,
                                            );
                                        }
                                    }
                                }
                            }
                            ForwardingDisposition::PolicyDenied => dbg.policy_deny += 1,
                            ForwardingDisposition::HAInactive => dbg.ha_inactive += 1,
                            _ => dbg.disposition_other += 1,
                        }
                        record_forwarding_disposition(
                            &ident,
                            &binding.live,
                            decision.resolution,
                            desc.len as u32,
                            Some(meta),
                            debug.as_ref(),
                            recent_exceptions,
                            last_resolution,
                        );
                        maybe_reinject_slow_path(
                            &ident,
                            &binding.live,
                            slow_path,
                            unsafe { &*area },
                            desc,
                            meta,
                            decision,
                            recent_exceptions,
                        );
                    }
                } else {
                    record_disposition(
                        &ident,
                        &binding.live,
                        disposition,
                        desc.len as u32,
                        Some(meta),
                        recent_exceptions,
                    );
                }
            } else {
                dbg.metadata_err += 1;
                binding.live.metadata_errors.fetch_add(1, Ordering::Relaxed);
                record_exception(
                    recent_exceptions,
                    &ident,
                    "metadata_parse",
                    desc.len as u32,
                    None,
                    None,
                );
            }
            if recycle_now {
                binding.scratch_recycle.push(desc.addr);
            }
        }
        received.release();
        drop(received);
        let mut pending_forwards = core::mem::take(&mut binding.scratch_forwards);
        for (forward_key, nat) in rst_teardowns {
            teardown_tcp_rst_flow(
                left,
                binding,
                right,
                sessions,
                shared_sessions,
                shared_nat_sessions,
                peer_worker_commands,
                &forward_key,
                nat,
                &mut pending_forwards,
            );
        }
        // Use raw pointer to avoid Arc::clone (~5% CPU from lock incq).
        // Safety: the Arc<BindingLiveState> outlives this function call;
        // binding is borrowed mutably by enqueue_pending_forwards but
        // ingress_live is only used for read-only error logging inside it.
        let ingress_live: *const BindingLiveState = &*binding.live;
        enqueue_pending_forwards(
            left,
            binding,
            right,
            &mut pending_forwards,
            now_ns,
            forwarding,
            &ident,
            unsafe { &*ingress_live },
            slow_path,
            recent_exceptions,
            dbg,
        );
        binding.scratch_forwards = pending_forwards;
        // Eager TX completion reaping: free TX frames immediately after
        // enqueueing forwards so they can be recycled to fill ring within
        // the same poll cycle. Without this, completions wait until next
        // poll entry, starving the fill ring during sustained forwarding.
        reap_tx_completions(binding, shared_recycles);
        // Also reap completions on the egress bindings that just transmitted.
        for other in left.iter_mut().chain(right.iter_mut()) {
            reap_tx_completions(other, shared_recycles);
        }
        apply_shared_recycles(left, binding, right, shared_recycles);
        if !binding.scratch_recycle.is_empty() {
            binding
                .pending_fill_frames
                .extend(binding.scratch_recycle.drain(..));
        }
        let _ = drain_pending_fill(binding, now_ns);
        counters.rx_batches += 1;
        counters.flush(&binding.live);
        update_binding_debug_state(binding);
        did_work = true;
    }
    update_binding_debug_state(binding);
    did_work
}

fn build_live_forward_request(
    area: &MmapArea,
    ingress_ident: &BindingIdentity,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    decision: &SessionDecision,
    forwarding: &ForwardingState,
    flow: Option<&SessionFlow>,
) -> Option<PendingForwardRequest> {
    let target_ifindex = if decision.resolution.tx_ifindex > 0 {
        decision.resolution.tx_ifindex
    } else {
        resolve_tx_binding_ifindex(forwarding, decision.resolution.egress_ifindex)
    };
    // Verify the UMEM slice is accessible (validates addr/len).
    let _ = area.slice(desc.addr as usize, desc.len as usize)?;
    // Prefer session flow ports (set by conntrack, immune to DMA races),
    // then live frame ports (lazy — only parsed if session ports unavailable),
    // then metadata as last resort.
    let session_ports = flow.and_then(|f| {
        if f.forward_key.src_port != 0 && f.forward_key.dst_port != 0 {
            Some((f.forward_key.src_port, f.forward_key.dst_port))
        } else {
            None
        }
    });
    let meta_ports = if meta.flow_src_port != 0 && meta.flow_dst_port != 0 {
        Some((meta.flow_src_port, meta.flow_dst_port))
    } else {
        None
    };
    let expected_ports = session_ports
        .or_else(|| live_frame_ports(area, desc, meta))
        .or(meta_ports);
    Some(PendingForwardRequest {
        target_ifindex,
        ingress_queue_id: ingress_ident.queue_id,
        source_offset: desc.addr,
        desc,
        meta,
        decision: *decision,
        expected_ports,
        flow_key: flow.map(|flow| flow.forward_key.clone()),
        nat64_reverse: None,
        prebuilt_frame: None,
    })
}

// Superseded by inline logic in build_live_forward_request() that reads ports
// from the live UMEM area before .to_vec() copy (fixes #199).  Retained for
// its unit test and potential future use.
#[allow(dead_code)]
fn authoritative_forward_ports(
    frame: &[u8],
    meta: UserspaceDpMeta,
    flow: Option<&SessionFlow>,
) -> Option<(u16, u16)> {
    if !matches!(meta.protocol, PROTO_TCP | PROTO_UDP) {
        return None;
    }
    let flow_ports = flow.and_then(|flow| {
        if flow.forward_key.src_port != 0 && flow.forward_key.dst_port != 0 {
            Some((flow.forward_key.src_port, flow.forward_key.dst_port))
        } else {
            None
        }
    });
    let meta_ports = if meta.flow_src_port != 0 && meta.flow_dst_port != 0 {
        Some((meta.flow_src_port, meta.flow_dst_port))
    } else {
        None
    };
    let frame_ports = live_frame_ports_bytes(frame, meta.addr_family, meta.protocol);
    flow_ports.or(meta_ports).or(frame_ports)
}

fn live_frame_ports(area: &MmapArea, desc: XdpDesc, meta: UserspaceDpMeta) -> Option<(u16, u16)> {
    if !matches!(meta.protocol, PROTO_TCP | PROTO_UDP) {
        return None;
    }
    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
    live_frame_ports_bytes(frame, meta.addr_family, meta.protocol)
}

fn live_frame_ports_bytes(frame: &[u8], addr_family: u8, protocol: u8) -> Option<(u16, u16)> {
    if !matches!(protocol, PROTO_TCP | PROTO_UDP) {
        return None;
    }
    let l4 = frame_l4_offset(frame, addr_family)?;
    parse_flow_ports(frame, l4, protocol)
}

fn forward_tuple_mismatch_reason(
    source_ports: Option<(u16, u16)>,
    expected_ports: Option<(u16, u16)>,
    built_ports: Option<(u16, u16)>,
) -> Option<String> {
    let expected = expected_ports.or(source_ports)?;
    let built = built_ports?;
    if built == expected {
        return None;
    }
    let source = source_ports.unwrap_or((0, 0));
    Some(format!(
        "forward_tuple_mismatch:src={}:{} expected={}:{} built={}:{}",
        source.0, source.1, expected.0, expected.1, built.0, built.1
    ))
}

fn enqueue_pending_forwards(
    left: &mut [BindingWorker],
    ingress_binding: &mut BindingWorker,
    right: &mut [BindingWorker],
    pending_forwards: &mut Vec<PendingForwardRequest>,
    now_ns: u64,
    forwarding: &ForwardingState,
    ingress_ident: &BindingIdentity,
    ingress_live: &BindingLiveState,
    slow_path: Option<&Arc<SlowPathReinjector>>,
    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
    dbg: &mut DebugPollCounters,
) {
    let ingress_area = (&ingress_binding.umem.area) as *const MmapArea;
    let mut post_recycles: Vec<(u32, u64)> = Vec::new();
    for request in pending_forwards.drain(..) {
        let source_offset = request.source_offset;
        let ingress_slot = ingress_binding.slot;

        // Fast path: prebuilt frame (e.g. ICMP error NAT reversal).
        // The frame is already fully rewritten — just enqueue for TX.
        if let Some(prebuilt) = request.prebuilt_frame {
            let Some(target_binding) = find_target_binding_mut(
                left,
                ingress_binding,
                request.ingress_queue_id,
                right,
                request.target_ifindex,
            ) else {
                ingress_binding.pending_fill_frames.push_back(source_offset);
                continue;
            };
            let frame_len = prebuilt.len();
            target_binding.pending_tx_local.push_back(TxRequest {
                bytes: prebuilt,
                expected_ports: None,
                expected_addr_family: request.meta.addr_family,
                expected_protocol: request.meta.protocol,
                flow_key: None,
            });
            bound_pending_tx_local(target_binding);
            bound_pending_tx_prepared(target_binding);
            dbg.enqueue_ok += 1;
            dbg.enqueue_copy += 1;
            dbg.tx_bytes_total += frame_len as u64;
            if (frame_len as u32) > dbg.tx_max_frame {
                dbg.tx_max_frame = frame_len as u32;
            }
            ingress_binding.pending_fill_frames.push_back(source_offset);
            continue;
        }

        // Read source frame directly from ingress UMEM — no heap copy needed.
        // The frame is safe to read: RX ring released but frame not yet returned
        // to fill ring (that happens after this function completes).
        let Some(source_frame) = (unsafe { &*ingress_area })
            .slice(request.source_offset as usize, request.desc.len as usize)
        else {
            ingress_binding.pending_fill_frames.push_back(source_offset);
            continue;
        };
        let expected_ports = request.expected_ports;
        let Some(target_binding) = find_target_binding_mut(
            left,
            ingress_binding,
            request.ingress_queue_id,
            right,
            request.target_ifindex,
        ) else {
            dbg.no_egress_binding += 1;
            if cfg!(feature = "debug-log") && dbg.no_egress_binding <= 3 {
                debug_log!(
                    "DBG NO_EGRESS_BINDING: target_ifindex={} ingress_if={} ingress_q={}",
                    request.target_ifindex, ingress_ident.ifindex, request.ingress_queue_id,
                );
            }
            record_exception(
                recent_exceptions,
                ingress_ident,
                "missing_egress_binding",
                request.desc.len,
                None,
                None,
            );
            ingress_binding.pending_fill_frames.push_back(source_offset);
            continue;
        };
        post_recycles.clear();
        let mut build_failed = false;
        let mut fallback_to_slow_path = false;
        let mut copied_source_frame = false;
        let mut retained_source_frame = false;
        {
            if let Some(segmented) = segment_forwarded_tcp_frames_from_frame(
                source_frame,
                request.meta,
                &request.decision,
                forwarding,
                expected_ports,
            ) {
                for frame in segmented {
                    if cfg!(feature = "debug-log") {
                        if let Some(reason) = forward_tuple_mismatch_reason(
                            live_frame_ports_bytes(
                                source_frame,
                                request.meta.addr_family,
                                request.meta.protocol,
                            ),
                            expected_ports,
                            live_frame_ports_bytes(
                                &frame,
                                request.meta.addr_family,
                                request.meta.protocol,
                            ),
                        ) {
                            record_exception(
                                recent_exceptions,
                                ingress_ident,
                                &reason,
                                frame.len() as u32,
                                Some(request.meta),
                                None,
                            );
                            build_failed = true;
                            copied_source_frame = true;
                            break;
                        }
                    }
                    let seg_frame_len = frame.len();
                    target_binding.pending_tx_local.push_back(TxRequest {
                        bytes: frame,
                        expected_ports,
                        expected_addr_family: request.meta.addr_family,
                        expected_protocol: request.meta.protocol,
                        flow_key: request.flow_key.clone(),
                    });
                    bound_pending_tx_local(target_binding);
                    bound_pending_tx_prepared(target_binding);
                    dbg.enqueue_ok += 1;
                    dbg.enqueue_copy += 1;
                    dbg.tx_bytes_total += seg_frame_len as u64;
                    if (seg_frame_len as u32) > dbg.tx_max_frame {
                        dbg.tx_max_frame = seg_frame_len as u32;
                    }
                }
                copied_source_frame = true;
                if target_binding.pending_tx_local.len() >= TX_BATCH_SIZE {
                    let _ = drain_pending_tx(target_binding, now_ns, &mut post_recycles);
                }
            }
            // Track when segmentation was needed but returned None
            if !copied_source_frame && source_frame.len() > 1514 {
                dbg.seg_needed_but_none += 1;
                thread_local! {
                    static SEG_MISS_LOG: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
                }
                SEG_MISS_LOG.with(|c| {
                    let n = c.get();
                    if n < 20 {
                        c.set(n + 1);
                        let egress_mtu = forwarding
                            .egress
                            .get(&request.decision.resolution.egress_ifindex)
                            .or_else(|| forwarding.egress.get(&request.decision.resolution.tx_ifindex))
                            .map(|e| e.mtu);
                        eprintln!(
                            "DBG SEG_MISS[{}]: frame_len={} proto={} egress_if={} tx_if={} egress_mtu={:?} \
                             target_if={} src_frame_bytes={}",
                            n, source_frame.len(), request.meta.protocol,
                            request.decision.resolution.egress_ifindex,
                            request.decision.resolution.tx_ifindex,
                            egress_mtu, request.target_ifindex,
                            source_frame.len(),
                        );
                    }
                });
            }
            if !copied_source_frame {
                // NAT64: header size changes prevent in-place rewrite.
                // Always use copy path with NAT64-specific frame builder.
                let is_nat64 = request.decision.nat.nat64;

                /*
                 * In-place TX optimization: rewrite the ingress frame directly in UMEM
                 * and submit it to the TX ring without copying. This avoids a memcpy but
                 * only works when ingress and egress share the same UMEM — which currently
                 * means same-interface hairpin only (each binding owns its own UMEM).
                 * Cross-interface forwards always take the copy path below.
                 *
                 * TODO(#205): extend to cross-interface by using shared UMEM across bindings.
                 */
                let can_rewrite_in_place = target_binding.slot == ingress_slot && !is_nat64;
                if can_rewrite_in_place {
                    match rewrite_forwarded_frame_in_place(
                        unsafe { &*ingress_area },
                        request.desc,
                        request.meta,
                        &request.decision,
                        expected_ports,
                    ) {
                        Some(frame_len) => {
                            target_binding
                                .pending_tx_prepared
                                .push_back(PreparedTxRequest {
                                    offset: source_offset,
                                    len: frame_len,
                                    recycle_slot: Some(ingress_slot),
                                    expected_ports,
                                    expected_addr_family: request.meta.addr_family,
                                    expected_protocol: request.meta.protocol,
                                    flow_key: request.flow_key.clone(),
                                });
                            bound_pending_tx_prepared(target_binding);
                            target_binding.live.in_place_tx_packets.fetch_add(1, Ordering::Relaxed);
                            dbg.enqueue_ok += 1;
                            dbg.enqueue_inplace += 1;
                            dbg.tx_bytes_total += frame_len as u64;
                            if frame_len > dbg.tx_max_frame {
                                dbg.tx_max_frame = frame_len;
                            }
                            retained_source_frame = true;
                        }
                        None => match if is_nat64 {
                            build_nat64_forwarded_frame(
                                source_frame,
                                request.meta,
                                &request.decision,
                                request.nat64_reverse.as_ref(),
                            )
                        } else {
                            build_forwarded_frame_from_frame(
                                source_frame,
                                request.meta,
                                &request.decision,
                                forwarding,
                                expected_ports,
                            )
                        } {
                            Some(frame) => {
                                if cfg!(feature = "debug-log") {
                                    if let Some(reason) = forward_tuple_mismatch_reason(
                                        live_frame_ports_bytes(
                                            source_frame,
                                            request.meta.addr_family,
                                            request.meta.protocol,
                                        ),
                                        expected_ports,
                                        live_frame_ports_bytes(
                                            &frame,
                                            request.meta.addr_family,
                                            request.meta.protocol,
                                        ),
                                    ) {
                                        record_exception(
                                            recent_exceptions,
                                            ingress_ident,
                                            &reason,
                                            frame.len() as u32,
                                            Some(request.meta),
                                            None,
                                        );
                                        build_failed = true;
                                        continue;
                                    }
                                }
                                let cp1_len = frame.len();
                                if cp1_len > tx_frame_capacity() {
                                    record_exception(
                                        recent_exceptions,
                                        ingress_ident,
                                        "oversized_forward_frame",
                                        cp1_len as u32,
                                        Some(request.meta),
                                        None,
                                    );
                                    continue;
                                }
                                target_binding.pending_tx_local.push_back(TxRequest {
                                    bytes: frame,
                                    expected_ports,
                                    expected_addr_family: request.meta.addr_family,
                                    expected_protocol: request.meta.protocol,
                                    flow_key: request.flow_key.clone(),
                                });
                                bound_pending_tx_local(target_binding);
                                bound_pending_tx_prepared(target_binding);
                                dbg.enqueue_ok += 1;
                                dbg.enqueue_copy += 1;
                                dbg.tx_bytes_total += cp1_len as u64;
                                if (cp1_len as u32) > dbg.tx_max_frame {
                                    dbg.tx_max_frame = cp1_len as u32;
                                }
                            }
                            None => {
                                build_failed = true;
                                fallback_to_slow_path = true;
                            }
                        },
                    }
                } else {
                    // Direct TX build: write the forwarded frame directly into
                    // the target binding's UMEM TX frame, eliminating the
                    // intermediate Vec allocation and one memcpy.
                    // NAT64 cannot use direct TX (header size changes), so
                    // it falls through to the copy path below.
                    let direct_built = if is_nat64 {
                        false
                    } else if let Some(tx_offset) = target_binding.free_tx_frames.pop_front() {
                        let target_area = &target_binding.umem.area;
                        let written = unsafe {
                            target_area.slice_mut_unchecked(tx_offset as usize, tx_frame_capacity())
                        }
                        .and_then(|out| {
                            build_forwarded_frame_into_from_frame(
                                out,
                                source_frame,
                                request.meta,
                                &request.decision,
                                expected_ports,
                            )
                        });
                        if let Some(written) = written {
                            // Debug-only: validate built frame ports match expected.
                            // enforce_expected_ports() in build_forwarded_frame_into_from_frame
                            // already ensures correctness; this catches builder bugs.
                            if cfg!(feature = "debug-log") {
                                let built_ports = unsafe {
                                    target_area.slice_mut_unchecked(tx_offset as usize, written)
                                }
                                .and_then(|f| {
                                    live_frame_ports_bytes(
                                        f,
                                        request.meta.addr_family,
                                        request.meta.protocol,
                                    )
                                });
                                if let Some(reason) = forward_tuple_mismatch_reason(
                                    live_frame_ports_bytes(
                                        source_frame,
                                        request.meta.addr_family,
                                        request.meta.protocol,
                                    ),
                                    expected_ports,
                                    built_ports,
                                ) {
                                    target_binding.free_tx_frames.push_front(tx_offset);
                                    record_exception(
                                        recent_exceptions,
                                        ingress_ident,
                                        &reason,
                                        written as u32,
                                        Some(request.meta),
                                        None,
                                    );
                                    build_failed = true;
                                }
                            }
                            if build_failed {
                                target_binding.free_tx_frames.push_front(tx_offset);
                                true
                            } else if written > tx_frame_capacity() {
                                target_binding.free_tx_frames.push_front(tx_offset);
                                record_exception(
                                    recent_exceptions,
                                    ingress_ident,
                                    "oversized_forward_frame",
                                    written as u32,
                                    Some(request.meta),
                                    None,
                                );
                                true
                            } else {
                                target_binding
                                    .pending_tx_prepared
                                    .push_back(PreparedTxRequest {
                                        offset: tx_offset,
                                        len: written as u32,
                                        recycle_slot: None,
                                        expected_ports,
                                        expected_addr_family: request.meta.addr_family,
                                        expected_protocol: request.meta.protocol,
                                        flow_key: request.flow_key.clone(),
                                    });
                                bound_pending_tx_prepared(target_binding);
                                dbg.enqueue_ok += 1;
                                dbg.enqueue_direct += 1;
                                dbg.tx_bytes_total += written as u64;
                                if (written as u32) > dbg.tx_max_frame {
                                    dbg.tx_max_frame = written as u32;
                                }
                                true
                            }
                        } else {
                            target_binding.free_tx_frames.push_front(tx_offset);
                            false
                        }
                    } else {
                        false
                    };
                    // Fallback: Vec copy path when direct build unavailable.
                    if !direct_built {
                        match if is_nat64 {
                            build_nat64_forwarded_frame(
                                source_frame,
                                request.meta,
                                &request.decision,
                                request.nat64_reverse.as_ref(),
                            )
                        } else {
                            build_forwarded_frame_from_frame(
                                source_frame,
                                request.meta,
                                &request.decision,
                                forwarding,
                                expected_ports,
                            )
                        } {
                            Some(frame) => {
                                if cfg!(feature = "debug-log") {
                                    if let Some(reason) = forward_tuple_mismatch_reason(
                                        live_frame_ports_bytes(
                                            source_frame,
                                            request.meta.addr_family,
                                            request.meta.protocol,
                                        ),
                                        expected_ports,
                                        live_frame_ports_bytes(
                                            &frame,
                                            request.meta.addr_family,
                                            request.meta.protocol,
                                        ),
                                    ) {
                                        record_exception(
                                            recent_exceptions,
                                            ingress_ident,
                                            &reason,
                                            frame.len() as u32,
                                            Some(request.meta),
                                            None,
                                        );
                                        build_failed = true;
                                        continue;
                                    }
                                }
                                let cp2_len = frame.len();
                                if cp2_len > tx_frame_capacity() {
                                    record_exception(
                                        recent_exceptions,
                                        ingress_ident,
                                        "oversized_forward_frame",
                                        cp2_len as u32,
                                        Some(request.meta),
                                        None,
                                    );
                                    continue;
                                }
                                target_binding.pending_tx_local.push_back(TxRequest {
                                    bytes: frame,
                                    expected_ports,
                                    expected_addr_family: request.meta.addr_family,
                                    expected_protocol: request.meta.protocol,
                                    flow_key: request.flow_key.clone(),
                                });
                                bound_pending_tx_local(target_binding);
                                bound_pending_tx_prepared(target_binding);
                                dbg.enqueue_ok += 1;
                                dbg.enqueue_copy += 1;
                                dbg.tx_bytes_total += cp2_len as u64;
                                if (cp2_len as u32) > dbg.tx_max_frame {
                                    dbg.tx_max_frame = cp2_len as u32;
                                }
                            }
                            None => {
                                build_failed = true;
                                fallback_to_slow_path = true;
                            }
                        }
                    }
                }
            }
            if target_binding.pending_tx_prepared.len() >= TX_BATCH_SIZE
                || target_binding.pending_tx_local.len() >= TX_BATCH_SIZE
            {
                let _ = drain_pending_tx(target_binding, now_ns, &mut post_recycles);
            }
        }
        apply_shared_recycles(left, ingress_binding, right, &mut post_recycles);
        update_binding_debug_state(ingress_binding);
        if build_failed {
            dbg.build_fail += 1;
            if dbg.build_fail <= 3 {
                eprintln!(
                    "DBG BUILD_FAIL: target_ifindex={} len={} fallback_slow={}",
                    request.target_ifindex, request.desc.len, fallback_to_slow_path,
                );
            }
            record_exception(
                recent_exceptions,
                ingress_ident,
                "forward_build_failed",
                request.desc.len,
                Some(request.meta),
                None,
            );
            if fallback_to_slow_path {
                maybe_reinject_slow_path_from_frame(
                    ingress_ident,
                    ingress_live,
                    slow_path,
                    source_frame,
                    request.meta,
                    request.decision,
                    recent_exceptions,
                    "forward_build_slow_path",
                );
            }
            if !retained_source_frame {
                ingress_binding.pending_fill_frames.push_back(source_offset);
            }
            continue;
        }
        if !retained_source_frame {
            ingress_binding.pending_fill_frames.push_back(source_offset);
        }
        // Always drain fill immediately — no watermark delay. In copy mode,
        // the kernel queues packets in the socket buffer when the fill ring
        // is low, causing latency spikes that stall TCP.
        if !ingress_binding.pending_fill_frames.is_empty() {
            let _ = drain_pending_fill(ingress_binding, now_ns);
        }
        update_binding_debug_state(ingress_binding);
    }
}

fn apply_shared_recycles(
    left: &mut [BindingWorker],
    current: &mut BindingWorker,
    right: &mut [BindingWorker],
    shared_recycles: &mut Vec<(u32, u64)>,
) {
    for (slot, offset) in shared_recycles.drain(..) {
        if current.slot == slot {
            current.pending_fill_frames.push_back(offset);
            update_binding_debug_state(current);
            continue;
        }
        if let Some(binding) = left.iter_mut().find(|binding| binding.slot == slot) {
            binding.pending_fill_frames.push_back(offset);
            update_binding_debug_state(binding);
            continue;
        }
        if let Some(binding) = right.iter_mut().find(|binding| binding.slot == slot) {
            binding.pending_fill_frames.push_back(offset);
            update_binding_debug_state(binding);
            continue;
        }
        current.pending_fill_frames.push_back(offset);
        update_binding_debug_state(current);
    }
}

fn resolve_tx_binding_ifindex(forwarding: &ForwardingState, egress_ifindex: i32) -> i32 {
    if let Some(fabric) = forwarding
        .fabrics
        .iter()
        .find(|fabric| fabric.parent_ifindex == egress_ifindex)
    {
        return fabric.parent_ifindex;
    }
    forwarding
        .egress
        .get(&egress_ifindex)
        .map(|iface| iface.bind_ifindex)
        .filter(|ifindex| *ifindex > 0)
        .unwrap_or(egress_ifindex)
}

fn maybe_reinject_slow_path(
    binding: &BindingIdentity,
    live: &BindingLiveState,
    slow_path: Option<&Arc<SlowPathReinjector>>,
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    decision: SessionDecision,
    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
) {
    if !matches!(
        decision.resolution.disposition,
        ForwardingDisposition::LocalDelivery
            | ForwardingDisposition::NoRoute
            | ForwardingDisposition::MissingNeighbor
            | ForwardingDisposition::NextTableUnsupported
    ) {
        return;
    }
    let Some(frame) = area.slice(desc.addr as usize, desc.len as usize) else {
        live.slow_path_drops.fetch_add(1, Ordering::Relaxed);
        record_exception(
            recent_exceptions,
            binding,
            "slow_path_extract_failed",
            desc.len as u32,
            Some(meta),
            None,
        );
        return;
    };
    maybe_reinject_slow_path_from_frame(
        binding,
        live,
        slow_path,
        frame,
        meta,
        decision,
        recent_exceptions,
        "slow_path",
    );
}

fn maybe_reinject_slow_path_from_frame(
    binding: &BindingIdentity,
    live: &BindingLiveState,
    slow_path: Option<&Arc<SlowPathReinjector>>,
    frame: &[u8],
    meta: UserspaceDpMeta,
    decision: SessionDecision,
    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
    reason: &str,
) {
    let Some(packet) = extract_l3_packet_with_nat(frame, meta, decision.nat) else {
        live.slow_path_drops.fetch_add(1, Ordering::Relaxed);
        record_exception(
            recent_exceptions,
            binding,
            "slow_path_prepare_failed",
            frame.len() as u32,
            Some(meta),
            None,
        );
        return;
    };
    let packet_len = packet.len() as u64;
    let Some(slow_path) = slow_path else {
        live.slow_path_drops.fetch_add(1, Ordering::Relaxed);
        record_exception(
            recent_exceptions,
            binding,
            "slow_path_unavailable",
            frame.len() as u32,
            Some(meta),
            None,
        );
        return;
    };
    match slow_path.enqueue(packet) {
        Ok(EnqueueOutcome::Accepted) => {
            live.slow_path_packets.fetch_add(1, Ordering::Relaxed);
            live.slow_path_bytes
                .fetch_add(packet_len, Ordering::Relaxed);
        }
        Ok(EnqueueOutcome::RateLimited) => {
            live.slow_path_drops.fetch_add(1, Ordering::Relaxed);
            live.slow_path_rate_limited.fetch_add(1, Ordering::Relaxed);
            record_exception(
                recent_exceptions,
                binding,
                &format!("{reason}_rate_limited"),
                frame.len() as u32,
                Some(meta),
                None,
            );
        }
        Ok(EnqueueOutcome::QueueFull) => {
            live.slow_path_drops.fetch_add(1, Ordering::Relaxed);
            record_exception(
                recent_exceptions,
                binding,
                &format!("{reason}_queue_full"),
                frame.len() as u32,
                Some(meta),
                None,
            );
        }
        Err(err) => {
            live.slow_path_drops.fetch_add(1, Ordering::Relaxed);
            live.set_error(err);
            record_exception(
                recent_exceptions,
                binding,
                &format!("{reason}_enqueue_failed"),
                frame.len() as u32,
                Some(meta),
                None,
            );
        }
    }
}

fn extract_l3_packet(area: &MmapArea, desc: XdpDesc, meta: UserspaceDpMeta) -> Option<Vec<u8>> {
    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
    extract_l3_packet_from_frame(frame, meta)
}

fn extract_l3_packet_from_frame(frame: &[u8], meta: UserspaceDpMeta) -> Option<Vec<u8>> {
    let l3 = meta.l3_offset as usize;
    if l3 >= frame.len() {
        return None;
    }
    Some(frame[l3..].to_vec())
}

fn extract_l3_packet_with_nat(
    frame: &[u8],
    meta: UserspaceDpMeta,
    nat: NatDecision,
) -> Option<Vec<u8>> {
    let mut packet = extract_l3_packet_from_frame(frame, meta)?;
    match meta.addr_family as i32 {
        libc::AF_INET => apply_nat_ipv4(&mut packet, meta.protocol, nat)?,
        libc::AF_INET6 => apply_nat_ipv6(&mut packet, meta.protocol, nat)?,
        _ => return None,
    }
    Some(packet)
}

fn parse_session_flow(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
) -> Option<SessionFlow> {
    // Fast path: for TCP/UDP with complete metadata tuple, use meta directly
    // without parsing the frame. This avoids UMEM reads and L3/L4 header
    // parsing for every established-flow packet. ICMP is excluded because
    // BPF may stamp outer-header IPs that differ from the session key
    // (e.g., ICMP error messages with embedded inner headers).
    if matches!(meta.protocol, PROTO_TCP | PROTO_UDP)
        && let Some(meta_flow) = parse_session_flow_from_meta(meta)
        && metadata_tuple_complete(meta, &meta_flow)
    {
        return Some(meta_flow);
    }

    // Slow path: meta incomplete or non-TCP/UDP — parse from the actual frame
    // and cross-reference with meta.
    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
    let frame_flow = if matches!(meta.addr_family as i32, libc::AF_INET) {
        parse_ipv4_session_flow_from_frame(frame, meta)
    } else {
        parse_session_flow_from_frame(frame, meta)
    };

    // For non-TCP/UDP (e.g. ICMP): when meta is complete, prefer meta unless
    // frame IPs disagree (e.g. ICMP error with embedded inner header).
    if let Some(meta_flow) = parse_session_flow_from_meta(meta)
        && metadata_tuple_complete(meta, &meta_flow)
    {
        if let Some(ref frame_flow) = frame_flow {
            if frame_flow.src_ip == meta_flow.src_ip && frame_flow.dst_ip == meta_flow.dst_ip {
                return Some(meta_flow);
            }
            return Some(frame_flow.clone());
        }
        return Some(meta_flow);
    }

    if let Some(flow) = frame_flow {
        return Some(flow);
    }

    // Final defensive fallback for malformed metadata where the frame parser
    // could not recover either.
    let l3 = meta.l3_offset as usize;
    let l4 = meta.l4_offset as usize;
    match meta.addr_family as i32 {
        libc::AF_INET => {
            if frame.len() < l3 + 20 || frame.len() < l4 {
                return None;
            }
            let src_ip = IpAddr::V4(Ipv4Addr::new(
                frame[l3 + 12],
                frame[l3 + 13],
                frame[l3 + 14],
                frame[l3 + 15],
            ));
            let dst_ip = IpAddr::V4(Ipv4Addr::new(
                frame[l3 + 16],
                frame[l3 + 17],
                frame[l3 + 18],
                frame[l3 + 19],
            ));
            let (src_port, dst_port) = parse_flow_ports(frame, l4, meta.protocol)?;
            Some(SessionFlow {
                src_ip,
                dst_ip,
                forward_key: SessionKey {
                    addr_family: meta.addr_family,
                    protocol: meta.protocol,
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                },
            })
        }
        libc::AF_INET6 => {
            if frame.len() < l3 + 40 || frame.len() < l4 {
                return None;
            }
            let src_ip = IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&frame[l3 + 8..l3 + 24]).ok()?,
            ));
            let dst_ip = IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&frame[l3 + 24..l3 + 40]).ok()?,
            ));
            let (src_port, dst_port) = parse_flow_ports(frame, l4, meta.protocol)?;
            Some(SessionFlow {
                src_ip,
                dst_ip,
                forward_key: SessionKey {
                    addr_family: meta.addr_family,
                    protocol: meta.protocol,
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                },
            })
        }
        _ => None,
    }
}

/// Check if a frame contains a TCP RST flag. Returns (is_rst, summary) for logging.
fn frame_has_tcp_rst(frame: &[u8]) -> bool {
    let l3 = match frame_l3_offset(frame) {
        Some(off) => off,
        None => return false,
    };
    let ip = match frame.get(l3..) {
        Some(ip) if ip.len() >= 20 => ip,
        _ => return false,
    };
    let (protocol, l4_offset) = match ip[0] >> 4 {
        4 => {
            let ihl = ((ip[0] & 0x0f) as usize) * 4;
            (ip[9], ihl)
        }
        6 if ip.len() >= 40 => (ip[6], 40usize),
        _ => return false,
    };
    if protocol != PROTO_TCP {
        return false;
    }
    let tcp = match ip.get(l4_offset..) {
        Some(t) if t.len() >= 14 => t,
        _ => return false,
    };
    // TCP flags at offset 13: RST = 0x04
    (tcp[13] & 0x04) != 0
}

/// Extract TCP flags and window from raw frame, auto-detecting L3 from Ethernet header.
/// Returns (tcp_flags, tcp_window) or None.
fn extract_tcp_flags_and_window(frame: &[u8]) -> Option<(u8, u16)> {
    let l3 = frame_l3_offset(frame)?;
    let ip = frame.get(l3..)?;
    let (protocol, l4_offset) = match ip.first()? >> 4 {
        4 => {
            if ip.len() < 20 { return None; }
            let ihl = ((ip[0] & 0x0f) as usize) * 4;
            (ip[9], ihl)
        }
        6 => {
            if ip.len() < 40 { return None; }
            (ip[6], 40usize)
        }
        _ => return None,
    };
    if protocol != PROTO_TCP {
        return None;
    }
    let tcp = ip.get(l4_offset..)?;
    if tcp.len() < 16 {
        return None;
    }
    let flags = tcp[13];
    let window = u16::from_be_bytes([tcp[14], tcp[15]]);
    Some((flags, window))
}

/// Extract TCP window size from raw frame data.
/// Returns None if not a TCP frame or if frame is too short.
fn extract_tcp_window(frame: &[u8], addr_family: u8) -> Option<u16> {
    let l3 = match frame_l3_offset(frame) {
        Some(off) => off,
        None => return None,
    };
    let ip = frame.get(l3..)?;
    let (protocol, l4_offset) = match addr_family as i32 {
        libc::AF_INET => {
            if ip.len() < 20 { return None; }
            let ihl = ((ip[0] & 0x0f) as usize) * 4;
            (ip[9], ihl)
        }
        libc::AF_INET6 => {
            if ip.len() < 40 { return None; }
            (ip[6], 40usize)
        }
        _ => return None,
    };
    if protocol != PROTO_TCP {
        return None;
    }
    let tcp = ip.get(l4_offset..)?;
    if tcp.len() < 16 {
        return None;
    }
    // TCP window is at offset 14-15 (big-endian)
    Some(u16::from_be_bytes([tcp[14], tcp[15]]))
}

fn frame_l3_offset(frame: &[u8]) -> Option<usize> {
    if frame.len() < 14 {
        return None;
    }
    let eth_proto = u16::from_be_bytes([frame[12], frame[13]]);
    if matches!(eth_proto, 0x8100 | 0x88a8) {
        if frame.len() < 18 {
            return None;
        }
        return Some(18);
    }
    Some(14)
}

/// Decode an Ethernet frame into a human-readable summary showing IP src/dst,
/// TCP/UDP ports, TCP flags, and checksums. For debugging packet forwarding.
fn decode_frame_summary(frame: &[u8]) -> String {
    let l3 = match frame_l3_offset(frame) {
        Some(off) => off,
        None => return String::new(),
    };
    let ip = &frame[l3..];
    if ip.len() < 20 {
        return String::new();
    }
    let version = ip[0] >> 4;
    if version == 4 {
        let ihl = ((ip[0] & 0x0f) as usize) * 4;
        let total_len = u16::from_be_bytes([ip[2], ip[3]]);
        let protocol = ip[9];
        let ip_csum = u16::from_be_bytes([ip[10], ip[11]]);
        let src = format!("{}.{}.{}.{}", ip[12], ip[13], ip[14], ip[15]);
        let dst = format!("{}.{}.{}.{}", ip[16], ip[17], ip[18], ip[19]);
        let ttl = ip[8];
        if matches!(protocol, PROTO_TCP | PROTO_UDP) && ip.len() >= ihl + 8 {
            let l4 = &ip[ihl..];
            let sport = u16::from_be_bytes([l4[0], l4[1]]);
            let dport = u16::from_be_bytes([l4[2], l4[3]]);
            if protocol == PROTO_TCP && ip.len() >= ihl + 20 {
                let seq = u32::from_be_bytes([l4[4], l4[5], l4[6], l4[7]]);
                let ack = u32::from_be_bytes([l4[8], l4[9], l4[10], l4[11]]);
                let flags = l4[13];
                let tcp_csum = u16::from_be_bytes([l4[16], l4[17]]);
                let flag_str = tcp_flags_str(flags);
                format!(
                    "IPv4 {}:{} -> {}:{} TCP [{flag_str}] seq={seq} ack={ack} ttl={ttl} ip_csum={ip_csum:#06x} tcp_csum={tcp_csum:#06x} ip_len={total_len}",
                    src, sport, dst, dport,
                )
            } else if protocol == PROTO_UDP {
                let udp_csum = u16::from_be_bytes([l4[6], l4[7]]);
                format!(
                    "IPv4 {}:{} -> {}:{} UDP ttl={ttl} ip_csum={ip_csum:#06x} udp_csum={udp_csum:#06x} ip_len={total_len}",
                    src, sport, dst, dport,
                )
            } else {
                format!("IPv4 {} -> {} proto={protocol} ttl={ttl} ip_len={total_len}", src, dst)
            }
        } else {
            format!("IPv4 {} -> {} proto={protocol} ttl={ttl} ip_len={total_len}", src, dst)
        }
    } else if version == 6 && ip.len() >= 40 {
        let payload_len = u16::from_be_bytes([ip[4], ip[5]]);
        let next_header = ip[6];
        let hop_limit = ip[7];
        let src = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&ip[8..24]).unwrap_or([0; 16]));
        let dst = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&ip[24..40]).unwrap_or([0; 16]));
        if matches!(next_header, PROTO_TCP | PROTO_UDP) && ip.len() >= 48 {
            let l4 = &ip[40..];
            let sport = u16::from_be_bytes([l4[0], l4[1]]);
            let dport = u16::from_be_bytes([l4[2], l4[3]]);
            if next_header == PROTO_TCP && ip.len() >= 60 {
                let flags = l4[13];
                let flag_str = tcp_flags_str(flags);
                format!("IPv6 [{src}]:{sport} -> [{dst}]:{dport} TCP [{flag_str}] hop={hop_limit} pl={payload_len}")
            } else {
                format!("IPv6 [{src}]:{sport} -> [{dst}]:{dport} proto={next_header} hop={hop_limit} pl={payload_len}")
            }
        } else {
            format!("IPv6 [{src}] -> [{dst}] proto={next_header} hop={hop_limit} pl={payload_len}")
        }
    } else {
        String::new()
    }
}

fn tcp_flags_str(flags: u8) -> String {
    let mut s = String::with_capacity(12);
    if flags & 0x02 != 0 { s.push_str("SYN "); }
    if flags & 0x10 != 0 { s.push_str("ACK "); }
    if flags & 0x01 != 0 { s.push_str("FIN "); }
    if flags & 0x04 != 0 { s.push_str("RST "); }
    if flags & 0x08 != 0 { s.push_str("PSH "); }
    if flags & 0x20 != 0 { s.push_str("URG "); }
    if s.ends_with(' ') { s.truncate(s.len() - 1); }
    if s.is_empty() { s.push_str("none"); }
    s
}

fn frame_l4_offset(frame: &[u8], addr_family: u8) -> Option<usize> {
    let l3 = frame_l3_offset(frame)?;
    match addr_family as i32 {
        libc::AF_INET => {
            if frame.len() < l3 + 20 {
                return None;
            }
            let ihl = usize::from(frame[l3] & 0x0f) * 4;
            if ihl < 20 || frame.len() < l3 + ihl {
                return None;
            }
            Some(l3 + ihl)
        }
        libc::AF_INET6 => {
            if frame.len() < l3 + 40 {
                return None;
            }
            let mut protocol = *frame.get(l3 + 6)?;
            let mut offset = l3 + 40;
            for _ in 0..6 {
                match protocol {
                    0 | 43 | 60 => {
                        let opt = frame.get(offset..offset + 2)?;
                        protocol = opt[0];
                        offset = offset.checked_add((usize::from(opt[1]) + 1) * 8)?;
                        if frame.len() < offset {
                            return None;
                        }
                    }
                    51 => {
                        let opt = frame.get(offset..offset + 2)?;
                        protocol = opt[0];
                        offset = offset.checked_add((usize::from(opt[1]) + 2) * 4)?;
                        if frame.len() < offset {
                            return None;
                        }
                    }
                    44 => {
                        let frag = frame.get(offset..offset + 8)?;
                        protocol = frag[0];
                        offset = offset.checked_add(8)?;
                        if frame.len() < offset {
                            return None;
                        }
                    }
                    59 => return None,
                    _ => return Some(offset),
                }
            }
            Some(offset)
        }
        _ => None,
    }
}

fn packet_rel_l4_offset(packet: &[u8], addr_family: u8) -> Option<usize> {
    match addr_family as i32 {
        libc::AF_INET => {
            if packet.len() < 20 {
                return None;
            }
            let ihl = usize::from(packet[0] & 0x0f) * 4;
            if ihl < 20 || packet.len() < ihl {
                return None;
            }
            Some(ihl)
        }
        libc::AF_INET6 => {
            if packet.len() < 40 {
                return None;
            }
            let mut protocol = *packet.get(6)?;
            let mut offset = 40usize;
            for _ in 0..6 {
                match protocol {
                    0 | 43 | 60 => {
                        let opt = packet.get(offset..offset + 2)?;
                        protocol = opt[0];
                        offset = offset.checked_add((usize::from(opt[1]) + 1) * 8)?;
                        if packet.len() < offset {
                            return None;
                        }
                    }
                    51 => {
                        let opt = packet.get(offset..offset + 2)?;
                        protocol = opt[0];
                        offset = offset.checked_add((usize::from(opt[1]) + 2) * 4)?;
                        if packet.len() < offset {
                            return None;
                        }
                    }
                    44 => {
                        let frag = packet.get(offset..offset + 8)?;
                        protocol = frag[0];
                        offset = offset.checked_add(8)?;
                        if packet.len() < offset {
                            return None;
                        }
                    }
                    59 => return None,
                    _ => return Some(offset),
                }
            }
            Some(offset)
        }
        _ => None,
    }
}

fn metadata_tuple_complete(meta: UserspaceDpMeta, flow: &SessionFlow) -> bool {
    if flow.src_ip.is_unspecified() || flow.dst_ip.is_unspecified() {
        return false;
    }
    match meta.protocol {
        PROTO_TCP | PROTO_UDP => flow.forward_key.src_port != 0 && flow.forward_key.dst_port != 0,
        _ => true,
    }
}

fn parse_session_flow_from_frame(frame: &[u8], meta: UserspaceDpMeta) -> Option<SessionFlow> {
    match meta.addr_family as i32 {
        libc::AF_INET => parse_ipv4_session_flow_from_frame(frame, meta),
        libc::AF_INET6 => {
            let l3 = frame_l3_offset(frame)?;
            let l4 = frame_l4_offset(frame, meta.addr_family)?;
            if frame.len() < l3 + 40 || frame.len() < l4 {
                return None;
            }
            let src_ip = IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&frame[l3 + 8..l3 + 24]).ok()?,
            ));
            let dst_ip = IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&frame[l3 + 24..l3 + 40]).ok()?,
            ));
            let (src_port, dst_port) = parse_flow_ports(frame, l4, meta.protocol)?;
            Some(SessionFlow {
                src_ip,
                dst_ip,
                forward_key: SessionKey {
                    addr_family: meta.addr_family,
                    protocol: meta.protocol,
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                },
            })
        }
        _ => None,
    }
}

fn parse_session_flow_from_meta(meta: UserspaceDpMeta) -> Option<SessionFlow> {
    let (src_ip, dst_ip) = match meta.addr_family as i32 {
        libc::AF_INET => {
            let src = meta.flow_src_addr.get(..4)?;
            let dst = meta.flow_dst_addr.get(..4)?;
            (
                IpAddr::V4(Ipv4Addr::new(src[0], src[1], src[2], src[3])),
                IpAddr::V4(Ipv4Addr::new(dst[0], dst[1], dst[2], dst[3])),
            )
        }
        libc::AF_INET6 => (
            IpAddr::V6(Ipv6Addr::from(meta.flow_src_addr)),
            IpAddr::V6(Ipv6Addr::from(meta.flow_dst_addr)),
        ),
        _ => return None,
    };
    if src_ip.is_unspecified() || dst_ip.is_unspecified() {
        return None;
    }
    Some(SessionFlow {
        src_ip,
        dst_ip,
        forward_key: SessionKey {
            addr_family: meta.addr_family,
            protocol: meta.protocol,
            src_ip,
            dst_ip,
            src_port: meta.flow_src_port,
            dst_port: meta.flow_dst_port,
        },
    })
}

fn parse_ipv4_session_flow_from_frame(frame: &[u8], meta: UserspaceDpMeta) -> Option<SessionFlow> {
    let mut l3 = 14usize;
    if frame.len() < l3 {
        return None;
    }
    let mut eth_proto = u16::from_be_bytes([*frame.get(12)?, *frame.get(13)?]);
    if matches!(eth_proto, 0x8100 | 0x88a8) {
        if frame.len() < l3 + 4 {
            return None;
        }
        eth_proto = u16::from_be_bytes([*frame.get(16)?, *frame.get(17)?]);
        l3 += 4;
    }
    if eth_proto != 0x0800 || frame.len() < l3 + 20 {
        return None;
    }
    let ihl = usize::from(frame[l3] & 0x0f) * 4;
    if ihl < 20 || frame.len() < l3 + ihl {
        return None;
    }
    let protocol = frame[l3 + 9];
    let l4 = l3 + ihl;
    let src_ip = IpAddr::V4(Ipv4Addr::new(
        frame[l3 + 12],
        frame[l3 + 13],
        frame[l3 + 14],
        frame[l3 + 15],
    ));
    let dst_ip = IpAddr::V4(Ipv4Addr::new(
        frame[l3 + 16],
        frame[l3 + 17],
        frame[l3 + 18],
        frame[l3 + 19],
    ));
    let (src_port, dst_port) = parse_flow_ports(frame, l4, protocol)?;
    Some(SessionFlow {
        src_ip,
        dst_ip,
        forward_key: SessionKey {
            addr_family: meta.addr_family,
            protocol,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
        },
    })
}

fn parse_flow_ports(frame: &[u8], l4: usize, protocol: u8) -> Option<(u16, u16)> {
    match protocol {
        PROTO_TCP | PROTO_UDP => {
            let bytes = frame.get(l4..l4 + 4)?;
            Some((
                u16::from_be_bytes([bytes[0], bytes[1]]),
                u16::from_be_bytes([bytes[2], bytes[3]]),
            ))
        }
        PROTO_ICMP | PROTO_ICMPV6 => {
            let bytes = frame.get(l4 + 4..l4 + 6)?;
            let ident = u16::from_be_bytes([bytes[0], bytes[1]]);
            Some((ident, 0))
        }
        _ => None,
    }
}

fn parse_zone_encoded_fabric_ingress(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    forwarding: &ForwardingState,
) -> Option<String> {
    if !ingress_is_fabric(forwarding, meta.ingress_ifindex as i32) {
        return None;
    }
    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
    if frame.len() < 12 {
        return None;
    }
    if frame[6] != 0x02
        || frame[7] != 0xbf
        || frame[8] != 0x72
        || frame[9] != FABRIC_ZONE_MAC_MAGIC
        || frame[10] != 0x00
    {
        return None;
    }
    forwarding.zone_id_to_name.get(&(frame[11] as u16)).cloned()
}

fn learn_dynamic_neighbor_from_packet(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    src_ip: IpAddr,
    last_learned_neighbor: &mut Option<LearnedNeighborKey>,
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
) {
    let Some(frame) = area.slice(desc.addr as usize, desc.len as usize) else {
        return;
    };
    if frame.len() < 12 {
        return;
    }
    if frame[6] == 0x02
        && frame[7] == 0xbf
        && frame[8] == 0x72
        && frame[9] == FABRIC_ZONE_MAC_MAGIC
        && frame[10] == 0x00
    {
        return;
    }
    let mut src_mac = [0u8; 6];
    src_mac.copy_from_slice(&frame[6..12]);
    if src_mac == [0; 6] || (src_mac[0] & 1) != 0 {
        return;
    }
    let learned = LearnedNeighborKey {
        ingress_ifindex: meta.ingress_ifindex as i32,
        ingress_vlan_id: meta.ingress_vlan_id,
        src_ip,
        src_mac,
    };
    if last_learned_neighbor.as_ref() == Some(&learned) {
        return;
    }
    learn_dynamic_neighbor(
        forwarding,
        dynamic_neighbors,
        meta.ingress_ifindex as i32,
        meta.ingress_vlan_id,
        src_ip,
        src_mac,
    );
    *last_learned_neighbor = Some(learned);
}

fn learn_dynamic_neighbor(
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
    ingress_ifindex: i32,
    ingress_vlan_id: u16,
    src_ip: IpAddr,
    src_mac: [u8; 6],
) {
    let mut ifindexes = vec![ingress_ifindex];
    if let Some(logical_ifindex) =
        resolve_ingress_logical_ifindex(forwarding, ingress_ifindex, ingress_vlan_id)
    {
        if logical_ifindex > 0 && logical_ifindex != ingress_ifindex {
            ifindexes.push(logical_ifindex);
        }
    }
    if let Ok(mut cache) = dynamic_neighbors.lock() {
        for ifindex in ifindexes {
            cache.insert((ifindex, src_ip), NeighborEntry { mac: src_mac });
        }
    }
}

fn find_target_binding_mut<'a>(
    left: &'a mut [BindingWorker],
    ingress_binding: &'a mut BindingWorker,
    ingress_queue_id: u32,
    right: &'a mut [BindingWorker],
    egress_ifindex: i32,
) -> Option<&'a mut BindingWorker> {
    if ingress_binding.ifindex == egress_ifindex {
        return Some(ingress_binding);
    }
    if let Some(pos) = left.iter().position(|binding| {
        binding.ifindex == egress_ifindex && binding.queue_id == ingress_queue_id
    }) {
        return Some(&mut left[pos]);
    }
    if let Some(pos) = right.iter().position(|binding| {
        binding.ifindex == egress_ifindex && binding.queue_id == ingress_queue_id
    }) {
        return Some(&mut right[pos]);
    }
    if let Some(pos) = left
        .iter()
        .position(|binding| binding.ifindex == egress_ifindex)
    {
        return Some(&mut left[pos]);
    }
    if let Some(pos) = right
        .iter()
        .position(|binding| binding.ifindex == egress_ifindex)
    {
        return Some(&mut right[pos]);
    }
    None
}

fn purge_queued_flows_for_closed_deltas(bindings: &mut [BindingWorker], deltas: &[SessionDelta]) {
    for delta in deltas {
        if delta.kind != SessionDeltaKind::Close {
            continue;
        }
        let reverse_key = reverse_session_key(&delta.key, delta.decision.nat);
        for binding in bindings.iter_mut() {
            cancel_queued_flow_on_binding(binding, &delta.key, &reverse_key);
        }
    }
}

fn flush_session_deltas(
    ident: &BindingIdentity,
    live: &BindingLiveState,
    session_map_fd: c_int,
    deltas: &[SessionDelta],
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    recent_session_deltas: &Arc<Mutex<VecDeque<SessionDeltaInfo>>>,
    peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
) {
    for delta in deltas {
        let info = SessionDeltaInfo {
            timestamp: Utc::now(),
            slot: ident.slot,
            queue_id: ident.queue_id,
            worker_id: ident.worker_id,
            interface: ident.interface.to_string(),
            ifindex: ident.ifindex,
            event: session_delta_event(delta.kind).to_string(),
            addr_family: delta.key.addr_family,
            protocol: delta.key.protocol,
            src_ip: delta.key.src_ip.to_string(),
            dst_ip: delta.key.dst_ip.to_string(),
            src_port: delta.key.src_port,
            dst_port: delta.key.dst_port,
            ingress_zone: delta.metadata.ingress_zone.to_string(),
            egress_zone: delta.metadata.egress_zone.to_string(),
            owner_rg_id: delta.metadata.owner_rg_id,
            egress_ifindex: delta.decision.resolution.egress_ifindex,
            next_hop: delta
                .decision
                .resolution
                .next_hop
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            nat_src_ip: delta
                .decision
                .nat
                .rewrite_src
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            nat_dst_ip: delta
                .decision
                .nat
                .rewrite_dst
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            nat_src_port: delta.decision.nat.rewrite_src_port.unwrap_or(0),
            nat_dst_port: delta.decision.nat.rewrite_dst_port.unwrap_or(0),
        };
        live.push_session_delta(info.clone());
        if let Ok(mut recent) = recent_session_deltas.lock() {
            push_recent_session_delta(&mut recent, info);
        }
        if delta.kind == SessionDeltaKind::Close {
            if cfg!(feature = "debug-log") {
                debug_log!(
                    "SESS_DELETE: proto={} {}:{} -> {}:{} nat_src={:?} nat_dst={:?} bpf_entries_before={}",
                    delta.key.protocol,
                    delta.key.src_ip, delta.key.src_port,
                    delta.key.dst_ip, delta.key.dst_port,
                    delta.decision.nat.rewrite_src, delta.decision.nat.rewrite_dst,
                    count_bpf_session_entries(session_map_fd),
                );
            }
            delete_live_session_key(session_map_fd, &delta.key);
            remove_shared_session(shared_sessions, shared_nat_sessions, &delta.key);
            let reverse_key = reverse_session_key(&delta.key, delta.decision.nat);
            delete_live_session_key(session_map_fd, &reverse_key);
            remove_shared_session(shared_sessions, shared_nat_sessions, &reverse_key);
            replicate_session_delete(peer_worker_commands, &delta.key);
            replicate_session_delete(
                peer_worker_commands,
                &reverse_session_key(&delta.key, delta.decision.nat),
            );
            if cfg!(feature = "debug-log") {
                debug_log!(
                    "SESS_DELETE_DONE: bpf_entries_after={}",
                    count_bpf_session_entries(session_map_fd),
                );
            }
        }
    }
}

fn session_delta_event(kind: SessionDeltaKind) -> &'static str {
    match kind {
        SessionDeltaKind::Open => "open",
        SessionDeltaKind::Close => "close",
    }
}

fn reap_tx_completions(binding: &mut BindingWorker, shared_recycles: &mut Vec<(u32, u64)>) -> u32 {
    if binding.outstanding_tx == 0 {
        return 0;
    }
    let available = binding.device.available();
    if available == 0 {
        return 0;
    }
    let mut reaped = 0u32;
    let mut completed = binding.device.complete(available);
    while let Some(offset) = completed.read() {
        if let Some(recycle_slot) = binding.in_flight_forward_recycles.remove(&offset) {
            shared_recycles.push((recycle_slot, offset));
        } else {
            binding.free_tx_frames.push_back(offset);
        }
        reaped += 1;
    }
    completed.release();
    drop(completed);
    binding.outstanding_tx = binding.outstanding_tx.saturating_sub(reaped);
    binding.dbg_completions_reaped += reaped as u64;
    binding
        .live
        .tx_completions
        .fetch_add(reaped as u64, Ordering::Relaxed);
    update_binding_debug_state(binding);
    reaped
}

fn drain_pending_fill(binding: &mut BindingWorker, now_ns: u64) -> bool {
    if binding.pending_fill_frames.is_empty() {
        return false;
    }
    let batch_size = binding.pending_fill_frames.len().min(FILL_BATCH_SIZE);
    binding.scratch_fill.clear();
    while binding.scratch_fill.len() < batch_size {
        let Some(offset) = binding.pending_fill_frames.pop_front() else {
            break;
        };
        // Poison the frame before submitting to fill ring — the kernel should
        // overwrite this with real packet data on RX. If we ever read back the
        // poison pattern in the RX path, it means the kernel recycled a
        // descriptor without writing packet data (stale/uninit frame).
        if cfg!(feature = "debug-log") {
            if let Some(frame) = unsafe {
                binding.umem.area.slice_mut_unchecked(offset as usize, 8)
            } {
                frame.copy_from_slice(&0xDEAD_BEEF_DEAD_BEEFu64.to_ne_bytes());
            }
        }
        binding.scratch_fill.push(offset);
    }
    if binding.scratch_fill.is_empty() {
        return false;
    }
    let inserted = {
        let mut fill = binding.device.fill(binding.scratch_fill.len() as u32);
        let inserted = fill.insert(binding.scratch_fill.iter().copied());
        fill.commit();
        inserted
    };
    if inserted == 0 {
        binding.dbg_fill_failed += binding.scratch_fill.len() as u64;
        for offset in binding.scratch_fill.drain(..).rev() {
            binding.pending_fill_frames.push_front(offset);
        }
        return false;
    }
    binding.dbg_fill_submitted += inserted as u64;
    if inserted < binding.scratch_fill.len() as u32 {
        binding.dbg_fill_failed += (binding.scratch_fill.len() as u32 - inserted) as u64;
        for offset in binding.scratch_fill.drain(inserted as usize..).rev() {
            binding.pending_fill_frames.push_front(offset);
        }
    }
    binding.scratch_fill.clear();
    // Only wake NAPI when the kernel signals it needs fill ring entries,
    // or as a safety net every FILL_WAKE_SAFETY_INTERVAL_NS to prevent
    // lost-wakeup stalls from the race between commit() and needs_wakeup.
    // Without the needs_wakeup gate, every drain triggers a sendto() syscall
    // (142K/sec at line rate), spending ~20% CPU in syscall entry/exit.
    if binding.device.needs_wakeup()
        || now_ns.saturating_sub(binding.last_rx_wake_ns) >= FILL_WAKE_SAFETY_INTERVAL_NS
    {
        maybe_wake_rx(binding, true, now_ns);
    }
    update_binding_debug_state(binding);
    true
}

fn maybe_wake_rx(binding: &mut BindingWorker, force: bool, now_ns: u64) {
    // After submitting fill ring entries, we must kick NAPI so the driver
    // consumes them and posts new RX WQEs. Without this, mlx5 increments
    // rx_xsk_buff_alloc_err and silently drops all incoming packets.
    //
    // DeviceQueue::wake() calls poll(fd, events=0, timeout=0) — a literal
    // no-op that does NOT trigger NAPI. We use sendto() instead, which
    // triggers NAPI processing of both fill ring and TX ring entries.
    if !force {
        binding.empty_rx_polls = binding.empty_rx_polls.saturating_add(1);
        if binding.empty_rx_polls < RX_WAKE_IDLE_POLLS {
            return;
        }
        if now_ns.saturating_sub(binding.last_rx_wake_ns) < RX_WAKE_MIN_INTERVAL_NS {
            return;
        }
    }
    let fd = binding.device.as_raw_fd();
    let rc = unsafe {
        libc::sendto(
            fd,
            core::ptr::null_mut(),
            0,
            libc::MSG_DONTWAIT,
            core::ptr::null_mut(),
            0,
        )
    };
    if rc >= 0 {
        binding.dbg_rx_wake_sendto_ok += 1;
    } else {
        binding.dbg_rx_wake_sendto_err += 1;
        binding.dbg_rx_wake_sendto_errno = unsafe { *libc::__errno_location() };
    }
    binding.dbg_rx_wakeups += 1;
    binding.live.rx_wakeups.fetch_add(1, Ordering::Relaxed);
    binding.last_rx_wake_ns = now_ns;
    binding.empty_rx_polls = 0;
}

fn pending_tx_capacity(ring_entries: u32) -> usize {
    (ring_entries as usize)
        .saturating_mul(PENDING_TX_LIMIT_MULTIPLIER)
        .max(TX_BATCH_SIZE.saturating_mul(2))
}

fn bound_pending_tx_local(binding: &mut BindingWorker) {
    while binding.pending_tx_local.len() > binding.max_pending_tx {
        if binding.pending_tx_local.pop_front().is_some() {
            binding.dbg_pending_overflow += 1;
            binding.live.tx_errors.fetch_add(1, Ordering::Relaxed);
            binding
                .live
                .set_error(format!("pending TX local overflow on slot {}", binding.slot));
        }
    }
}

fn bound_pending_tx_prepared(binding: &mut BindingWorker) {
    let limit = binding.max_pending_tx;
    while binding.pending_tx_prepared.len() > limit {
        if let Some(req) = binding.pending_tx_prepared.pop_front() {
            binding.dbg_pending_overflow += 1;
            recycle_cancelled_prepared(binding, &req);
            binding.live.tx_errors.fetch_add(1, Ordering::Relaxed);
            binding
                .live
                .set_error(format!("pending TX prepared overflow on slot {}", binding.slot));
        }
    }
}

fn drain_pending_tx(
    binding: &mut BindingWorker,
    now_ns: u64,
    shared_recycles: &mut Vec<(u32, u64)>,
) -> bool {
    if binding.outstanding_tx == 0
        && binding.pending_tx_prepared.is_empty()
        && binding.pending_tx_local.is_empty()
        && binding.live.pending_tx_empty()
    {
        return false;
    }
    let mut did_work = reap_tx_completions(binding, shared_recycles) > 0;
    // In copy mode, the kernel needs sendto() to process TX ring entries.
    // If outstanding entries remain after reaping (kernel didn't finish in
    // the previous kick), re-kick now so they don't stall forever.
    if binding.outstanding_tx > 0
        && binding.pending_tx_prepared.is_empty()
        && binding.pending_tx_local.is_empty()
    {
        maybe_wake_tx(binding, false, now_ns);
    }
    while !binding.pending_tx_prepared.is_empty() {
        match transmit_prepared_batch(binding, now_ns) {
            Ok((packets, bytes)) => {
                if packets == 0 {
                    break;
                }
                did_work = true;
                binding
                    .live
                    .tx_packets
                    .fetch_add(packets, Ordering::Relaxed);
                binding.live.tx_bytes.fetch_add(bytes, Ordering::Relaxed);
            }
            Err(TxError::Retry(err)) => {
                binding.live.set_error(err);
                return true;
            }
            Err(TxError::Drop(err)) => {
                binding.live.tx_errors.fetch_add(1, Ordering::Relaxed);
                binding.live.set_error(err);
            }
        }
    }
    let mut pending = if binding.pending_tx_local.is_empty() {
        binding.live.take_pending_tx()
    } else {
        core::mem::take(&mut binding.pending_tx_local)
    };
    if !binding.live.pending_tx_empty() {
        let mut shared = binding.live.take_pending_tx();
        if pending.is_empty() {
            pending = shared;
        } else if !shared.is_empty() {
            pending.append(&mut shared);
        }
    }
    if pending.is_empty() {
        return did_work || !binding.pending_tx_prepared.is_empty();
    }
    let mut retry = VecDeque::new();
    while let Some(req) = pending.pop_front() {
        retry.push_back(req);
        if retry.len() >= TX_BATCH_SIZE || binding.free_tx_frames.is_empty() || pending.is_empty() {
            match transmit_batch(binding, &mut retry, now_ns, shared_recycles) {
                Ok((packets, bytes)) => {
                    if packets > 0 {
                        did_work = true;
                        binding
                            .live
                            .tx_packets
                            .fetch_add(packets, Ordering::Relaxed);
                        binding.live.tx_bytes.fetch_add(bytes, Ordering::Relaxed);
                    }
                }
                Err(TxError::Retry(err)) => {
                    binding.live.set_error(err);
                    retry.append(&mut pending);
                    break;
                }
                Err(TxError::Drop(err)) => {
                    binding.live.tx_errors.fetch_add(1, Ordering::Relaxed);
                    binding.live.set_error(err);
                }
            }
        }
    }
    if !retry.is_empty() {
        retry.append(&mut binding.pending_tx_local);
        binding.pending_tx_local = retry;
        bound_pending_tx_local(binding);
    }
    bound_pending_tx_prepared(binding);
    update_binding_debug_state(binding);
    did_work
        || !binding.pending_tx_prepared.is_empty()
        || !binding.pending_tx_local.is_empty()
        || !binding.live.pending_tx_empty()
}

enum TxError {
    Retry(String),
    Drop(String),
}

fn transmit_batch(
    binding: &mut BindingWorker,
    pending: &mut VecDeque<TxRequest>,
    now_ns: u64,
    shared_recycles: &mut Vec<(u32, u64)>,
) -> Result<(u64, u64), TxError> {
    if pending.is_empty() {
        return Ok((0, 0));
    }
    if binding.free_tx_frames.is_empty() {
        let _ = reap_tx_completions(binding, shared_recycles);
    }
    let batch_size = pending
        .len()
        .min(binding.free_tx_frames.len())
        .min(TX_BATCH_SIZE);
    if batch_size == 0 {
        maybe_wake_tx(binding, true, now_ns);
        return Err(TxError::Retry("no free TX frame available".to_string()));
    }

    binding.scratch_local_tx.clear();
    while binding.scratch_local_tx.len() < batch_size {
        let Some(mut req) = pending.pop_front() else {
            break;
        };
        if req.bytes.len() > tx_frame_capacity() {
            return Err(TxError::Drop(format!(
                "local tx frame exceeds UMEM frame capacity: len={} cap={}",
                req.bytes.len(),
                tx_frame_capacity()
            )));
        }
        let Some(offset) = binding.free_tx_frames.pop_front() else {
            pending.push_front(req);
            break;
        };
        let Some(frame) = (unsafe {
            binding
                .umem
                .area
                .slice_mut_unchecked(offset as usize, req.bytes.len())
        }) else {
            binding.free_tx_frames.push_front(offset);
            return Err(TxError::Drop(format!(
                "tx frame slice out of range: offset={offset} len={}",
                req.bytes.len()
            )));
        };
        frame.copy_from_slice(&req.bytes);
        // RST detection: log when we're about to transmit a TCP RST
        if cfg!(feature = "debug-log") {
            if frame_has_tcp_rst(&req.bytes) {
                binding.dbg_tx_tcp_rst += 1;
                thread_local! {
                    static TX_RST_LOG_COUNT: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
                }
                TX_RST_LOG_COUNT.with(|c| {
                    let n = c.get();
                    if n < 50 {
                        c.set(n + 1);
                        let summary = decode_frame_summary(&req.bytes);
                        eprintln!(
                            "RST_DETECT TX[{}]: slot={} len={} {}",
                            n,
                            binding.slot,
                            req.bytes.len(),
                            summary,
                        );
                        if n < 5 {
                            let hex_len = req.bytes.len().min(80);
                            let hex: String = req.bytes[..hex_len]
                                .iter()
                                .map(|b| format!("{:02x}", b))
                                .collect::<Vec<_>>()
                                .join(" ");
                            eprintln!("RST_DETECT TX_HEX[{n}]: {hex}");
                        }
                    }
                });
            }
        }
        binding.scratch_local_tx.push((offset, req));
    }

    if binding.scratch_local_tx.is_empty() {
        maybe_wake_tx(binding, true, now_ns);
        return Err(TxError::Retry("no prepared TX frame available".to_string()));
    }

    let mut writer = binding.tx.transmit(binding.scratch_local_tx.len() as u32);
    let inserted = writer.insert(
        binding
            .scratch_local_tx
            .iter()
            .map(|(offset, req)| XdpDesc {
                addr: *offset,
                len: req.bytes.len() as u32,
                options: 0,
            }),
    );
    writer.commit();
    drop(writer);

    if inserted == 0 {
        binding.dbg_tx_ring_full += 1;
        maybe_wake_tx(binding, true, now_ns);
        while let Some((offset, req)) = binding.scratch_local_tx.pop() {
            binding.free_tx_frames.push_front(offset);
            pending.push_front(req);
        }
        return Err(TxError::Retry("tx ring insert failed".to_string()));
    }
    binding.dbg_tx_ring_submitted += inserted as u64;
    binding.outstanding_tx = binding.outstanding_tx.saturating_add(inserted);

    let mut sent_packets = 0u64;
    let mut sent_bytes = 0u64;
    let mut retry_tail = Vec::new();
    for (idx, (offset, req)) in binding.scratch_local_tx.drain(..).enumerate() {
        if idx < inserted as usize {
            sent_packets += 1;
            sent_bytes += req.bytes.len() as u64;
        } else {
            binding.free_tx_frames.push_front(offset);
            retry_tail.push(req);
        }
    }
    for req in retry_tail.into_iter().rev() {
        pending.push_front(req);
    }

    // Latency-sensitive reply traffic can stall indefinitely on otherwise idle zerocopy
    // bindings unless we explicitly kick TX after committing descriptors.
    maybe_wake_tx(binding, true, now_ns);
    Ok((sent_packets, sent_bytes))
}

fn transmit_prepared_batch(
    binding: &mut BindingWorker,
    now_ns: u64,
) -> Result<(u64, u64), TxError> {
    if binding.pending_tx_prepared.is_empty() {
        return Ok((0, 0));
    }
    let batch_size = binding.pending_tx_prepared.len().min(TX_BATCH_SIZE);
    binding.scratch_prepared_tx.clear();
    while binding.scratch_prepared_tx.len() < batch_size {
        let Some(req) = binding.pending_tx_prepared.pop_front() else {
            break;
        };
        if req.len as usize > tx_frame_capacity() {
            let orphaned: Vec<_> = binding.scratch_prepared_tx.drain(..).collect();
            recycle_cancelled_prepared(binding, &req);
            for r in &orphaned {
                recycle_cancelled_prepared(binding, r);
            }
            return Err(TxError::Drop(format!(
                "prepared tx frame exceeds UMEM frame capacity: len={} cap={}",
                req.len,
                tx_frame_capacity()
            )));
        }
        binding.scratch_prepared_tx.push(req);
    }
    if binding.scratch_prepared_tx.is_empty() {
        return Ok((0, 0));
    }
    for req in &binding.scratch_prepared_tx {
        if binding.umem.area.slice(req.offset as usize, req.len as usize).is_none() {
            let err_offset = req.offset;
            let err_len = req.len;
            let orphaned: Vec<_> = binding.scratch_prepared_tx.drain(..).collect();
            for r in &orphaned {
                recycle_cancelled_prepared(binding, r);
            }
            return Err(TxError::Drop(format!(
                "prepared tx frame slice out of range: offset={} len={}",
                err_offset, err_len
            )));
        }
    }

    // RST detection on prepared TX path: check UMEM frames before submitting to TX ring
    if cfg!(feature = "debug-log") {
        for req in &binding.scratch_prepared_tx {
            if let Some(frame_data) = binding.umem.area.slice(req.offset as usize, req.len as usize) {
                if frame_has_tcp_rst(frame_data) {
                    binding.dbg_tx_tcp_rst += 1;
                    thread_local! {
                        static PREP_TX_RST_LOG_COUNT: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
                    }
                    PREP_TX_RST_LOG_COUNT.with(|c| {
                        let n = c.get();
                        if n < 50 {
                            c.set(n + 1);
                            let summary = decode_frame_summary(frame_data);
                            eprintln!(
                                "RST_DETECT PREP_TX[{}]: if={} q={} len={} {}",
                                n, binding.identity().ifindex, binding.identity().queue_id,
                                req.len, summary,
                            );
                            if n < 5 {
                                let hex_len = (req.len as usize).min(frame_data.len()).min(80);
                                let hex: String = frame_data[..hex_len]
                                    .iter()
                                    .map(|b| format!("{:02x}", b))
                                    .collect::<Vec<_>>()
                                    .join(" ");
                                eprintln!("RST_DETECT PREP_TX_HEX[{n}]: {hex}");
                            }
                        }
                    });
                }
            }
        }
    }

    let mut writer = binding
        .tx
        .transmit(binding.scratch_prepared_tx.len() as u32);
    let inserted = writer.insert(binding.scratch_prepared_tx.iter().map(|req| XdpDesc {
        addr: req.offset,
        len: req.len,
        options: 0,
    }));
    writer.commit();
    drop(writer);

    if inserted == 0 {
        binding.dbg_tx_ring_full += 1;
        maybe_wake_tx(binding, true, now_ns);
        while let Some(req) = binding.scratch_prepared_tx.pop() {
            binding.pending_tx_prepared.push_front(req);
        }
        return Err(TxError::Retry("prepared tx ring insert failed".to_string()));
    }
    binding.dbg_tx_ring_submitted += inserted as u64;
    binding.outstanding_tx = binding.outstanding_tx.saturating_add(inserted);

    let mut sent_packets = 0u64;
    let mut sent_bytes = 0u64;
    let mut retry_tail = Vec::new();
    for (idx, req) in binding.scratch_prepared_tx.drain(..).enumerate() {
        if idx < inserted as usize {
            if let Some(recycle_slot) = req.recycle_slot {
                binding
                    .in_flight_forward_recycles
                    .insert(req.offset, recycle_slot);
            }
            sent_packets += 1;
            sent_bytes += req.len as u64;
        } else {
            retry_tail.push(req);
        }
    }
    for req in retry_tail.into_iter().rev() {
        binding.pending_tx_prepared.push_front(req);
    }

    // Prepared cross-binding forwards need the same explicit TX kick.
    maybe_wake_tx(binding, true, now_ns);
    Ok((sent_packets, sent_bytes))
}

fn maybe_wake_tx(binding: &mut BindingWorker, force: bool, now_ns: u64) {
    let bind_mode = XskBindMode::from_u8(binding.live.bind_mode.load(Ordering::Relaxed));
    if !bind_mode.is_zerocopy()
        || binding.tx.needs_wakeup()
        || force
        || now_ns.saturating_sub(binding.last_tx_wake_ns) >= TX_WAKE_MIN_INTERVAL_NS
    {
        // Use direct sendto() instead of binding.tx.wake() so we can capture errors.
        let fd = binding.tx.as_raw_fd();
        let rc = unsafe {
            libc::sendto(
                fd,
                core::ptr::null_mut(),
                0,
                libc::MSG_DONTWAIT,
                core::ptr::null_mut(),
                0,
            )
        };
        binding.dbg_sendto_calls += 1;
        if rc < 0 {
            let errno = unsafe { *libc::__errno_location() };
            // EAGAIN/EWOULDBLOCK is normal for MSG_DONTWAIT; ENOBUFS means kernel dropped.
            if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
                binding.dbg_sendto_eagain += 1;
            } else if errno == libc::ENOBUFS {
                binding.dbg_sendto_enobufs += 1;
                if binding.dbg_sendto_enobufs <= 10 {
                    eprintln!(
                        "TX_ENOBUFS: slot={} if={} q={} outstanding_tx={} free_tx={}",
                        binding.slot, binding.ifindex, binding.queue_id,
                        binding.outstanding_tx, binding.free_tx_frames.len(),
                    );
                }
            } else {
                binding.dbg_sendto_err += 1;
                if binding.dbg_sendto_err <= 5 {
                    eprintln!(
                        "DBG SENDTO_ERR: slot={} if={} q={} errno={} outstanding_tx={} free_tx={}",
                        binding.slot, binding.ifindex, binding.queue_id,
                        errno, binding.outstanding_tx, binding.free_tx_frames.len(),
                    );
                }
            }
        }
        binding.last_tx_wake_ns = now_ns;
    }
}

fn record_exception(
    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
    binding: &BindingIdentity,
    reason: &str,
    packet_length: u32,
    meta: Option<UserspaceDpMeta>,
    debug: Option<&ResolutionDebug>,
) {
    if let Ok(mut recent) = recent_exceptions.lock() {
        push_recent_exception(
            &mut recent,
            ExceptionStatus {
                timestamp: Utc::now(),
                slot: binding.slot,
                queue_id: binding.queue_id,
                worker_id: binding.worker_id,
                interface: binding.interface.to_string(),
                ifindex: binding.ifindex,
                ingress_ifindex: debug.map(|d| d.ingress_ifindex).unwrap_or_default(),
                reason: reason.to_string(),
                packet_length,
                addr_family: meta.map(|m| m.addr_family).unwrap_or(0),
                protocol: meta.map(|m| m.protocol).unwrap_or(0),
                config_generation: meta.map(|m| m.config_generation).unwrap_or(0),
                fib_generation: meta.map(|m| m.fib_generation).unwrap_or(0),
                src_ip: debug
                    .and_then(|d| d.src_ip)
                    .map(|ip| ip.to_string())
                    .unwrap_or_default(),
                dst_ip: debug
                    .and_then(|d| d.dst_ip)
                    .map(|ip| ip.to_string())
                    .unwrap_or_default(),
                src_port: debug.map(|d| d.src_port).unwrap_or_default(),
                dst_port: debug.map(|d| d.dst_port).unwrap_or_default(),
                from_zone: debug
                    .and_then(|d| d.from_zone.as_ref().map(|zone| zone.to_string()))
                    .unwrap_or_default(),
                to_zone: debug
                    .and_then(|d| d.to_zone.as_ref().map(|zone| zone.to_string()))
                    .unwrap_or_default(),
            },
        );
    }
}

fn record_disposition(
    binding: &BindingIdentity,
    live: &BindingLiveState,
    disposition: PacketDisposition,
    packet_length: u32,
    meta: Option<UserspaceDpMeta>,
    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
) {
    match disposition {
        PacketDisposition::Valid => {
            live.validated_packets.fetch_add(1, Ordering::Relaxed);
            live.validated_bytes
                .fetch_add(packet_length as u64, Ordering::Relaxed);
        }
        PacketDisposition::NoSnapshot => {
            live.exception_packets.fetch_add(1, Ordering::Relaxed);
            record_exception(
                recent_exceptions,
                binding,
                "no_snapshot",
                packet_length,
                meta,
                None,
            );
        }
        PacketDisposition::ConfigGenerationMismatch => {
            live.exception_packets.fetch_add(1, Ordering::Relaxed);
            live.config_gen_mismatches.fetch_add(1, Ordering::Relaxed);
            record_exception(
                recent_exceptions,
                binding,
                "config_generation_mismatch",
                packet_length,
                meta,
                None,
            );
        }
        PacketDisposition::FibGenerationMismatch => {
            live.exception_packets.fetch_add(1, Ordering::Relaxed);
            live.fib_gen_mismatches.fetch_add(1, Ordering::Relaxed);
            record_exception(
                recent_exceptions,
                binding,
                "fib_generation_mismatch",
                packet_length,
                meta,
                None,
            );
        }
        PacketDisposition::UnsupportedPacket => {
            live.exception_packets.fetch_add(1, Ordering::Relaxed);
            live.unsupported_packets.fetch_add(1, Ordering::Relaxed);
            record_exception(
                recent_exceptions,
                binding,
                "unsupported_packet",
                packet_length,
                meta,
                None,
            );
        }
    }
}

fn record_forwarding_disposition(
    binding: &BindingIdentity,
    live: &BindingLiveState,
    resolution: ForwardingResolution,
    packet_length: u32,
    meta: Option<UserspaceDpMeta>,
    debug: Option<&ResolutionDebug>,
    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
    last_resolution: &Arc<Mutex<Option<PacketResolution>>>,
) {
    match resolution.disposition {
        ForwardingDisposition::LocalDelivery => {
            live.local_delivery_packets.fetch_add(1, Ordering::Relaxed);
        }
        ForwardingDisposition::ForwardCandidate | ForwardingDisposition::FabricRedirect => {
            live.forward_candidate_packets
                .fetch_add(1, Ordering::Relaxed);
        }
        ForwardingDisposition::HAInactive => {
            update_last_resolution(last_resolution, resolution, debug);
            live.exception_packets.fetch_add(1, Ordering::Relaxed);
            record_exception(
                recent_exceptions,
                binding,
                "ha_inactive",
                packet_length,
                meta,
                debug,
            );
        }
        ForwardingDisposition::PolicyDenied => {
            update_last_resolution(last_resolution, resolution, debug);
            live.policy_denied_packets.fetch_add(1, Ordering::Relaxed);
            record_exception(
                recent_exceptions,
                binding,
                "policy_denied",
                packet_length,
                meta,
                debug,
            );
        }
        ForwardingDisposition::NoRoute => {
            update_last_resolution(last_resolution, resolution, debug);
            live.route_miss_packets.fetch_add(1, Ordering::Relaxed);
            record_exception(
                recent_exceptions,
                binding,
                "no_route",
                packet_length,
                meta,
                debug,
            );
        }
        ForwardingDisposition::MissingNeighbor => {
            update_last_resolution(last_resolution, resolution, debug);
            live.neighbor_miss_packets.fetch_add(1, Ordering::Relaxed);
            record_exception(
                recent_exceptions,
                binding,
                "missing_neighbor",
                packet_length,
                meta,
                debug,
            );
        }
        ForwardingDisposition::DiscardRoute => {
            update_last_resolution(last_resolution, resolution, debug);
            live.discard_route_packets.fetch_add(1, Ordering::Relaxed);
            record_exception(
                recent_exceptions,
                binding,
                "discard_route",
                packet_length,
                meta,
                debug,
            );
        }
        ForwardingDisposition::NextTableUnsupported => {
            update_last_resolution(last_resolution, resolution, debug);
            live.next_table_packets.fetch_add(1, Ordering::Relaxed);
            record_exception(
                recent_exceptions,
                binding,
                "next_table_unsupported",
                packet_length,
                meta,
                debug,
            );
        }
    }
}

fn update_last_resolution(
    last_resolution: &Arc<Mutex<Option<PacketResolution>>>,
    resolution: ForwardingResolution,
    debug: Option<&ResolutionDebug>,
) {
    if let Ok(mut last) = last_resolution.lock() {
        *last = Some(resolution.status(debug));
    }
}

fn reverse_session_key(key: &SessionKey, nat: NatDecision) -> SessionKey {
    let (src_port, dst_port) = if matches!(key.protocol, PROTO_ICMP | PROTO_ICMPV6) {
        (key.src_port, key.dst_port)
    } else {
        (
            nat.rewrite_dst_port.unwrap_or(key.dst_port),
            nat.rewrite_src_port.unwrap_or(key.src_port),
        )
    };
    let wire_src = nat.rewrite_dst.unwrap_or(key.dst_ip);
    let wire_dst = nat.rewrite_src.unwrap_or(key.src_ip);
    let (addr_family, protocol) = if nat.nat64 {
        let af = match wire_src {
            IpAddr::V4(_) => libc::AF_INET as u8,
            IpAddr::V6(_) => libc::AF_INET6 as u8,
        };
        let proto = if af == libc::AF_INET as u8 && key.protocol == PROTO_ICMPV6 {
            PROTO_ICMP
        } else if af == libc::AF_INET6 as u8 && key.protocol == PROTO_ICMP {
            PROTO_ICMPV6
        } else {
            key.protocol
        };
        (af, proto)
    } else {
        (key.addr_family, key.protocol)
    };
    SessionKey {
        addr_family,
        protocol,
        src_ip: wire_src,
        dst_ip: wire_dst,
        src_port,
        dst_port,
    }
}

fn resolution_target_for_session(flow: &SessionFlow, decision: SessionDecision) -> IpAddr {
    decision.nat.rewrite_dst.unwrap_or(flow.dst_ip)
}

fn cached_session_resolution(
    forwarding: &ForwardingState,
    cached: ForwardingResolution,
) -> Option<ForwardingResolution> {
    if cached.egress_ifindex <= 0 || cached.neighbor_mac.is_none() {
        return None;
    }
    let mut fallback = cached;
    fallback.disposition = ForwardingDisposition::ForwardCandidate;
    if fallback.tx_ifindex <= 0 {
        fallback.tx_ifindex = resolve_tx_binding_ifindex(forwarding, fallback.egress_ifindex);
    }
    if let Some(egress) = forwarding.egress.get(&fallback.egress_ifindex) {
        if fallback.src_mac.is_none() {
            fallback.src_mac = Some(egress.src_mac);
        }
        if fallback.tx_vlan_id == 0 {
            fallback.tx_vlan_id = egress.vlan_id;
        }
    }
    Some(fallback)
}

fn populate_egress_resolution(
    state: &ForwardingState,
    egress_ifindex: i32,
    resolution: &mut ForwardingResolution,
) {
    if egress_ifindex <= 0 {
        return;
    }
    if let Some(egress) = state.egress.get(&egress_ifindex) {
        resolution.tx_ifindex = if egress.bind_ifindex > 0 {
            egress.bind_ifindex
        } else {
            egress_ifindex
        };
        resolution.src_mac = Some(egress.src_mac);
        resolution.tx_vlan_id = egress.vlan_id;
    } else if resolution.tx_ifindex <= 0 {
        resolution.tx_ifindex = egress_ifindex;
    }
}

fn lookup_forwarding_resolution_for_session(
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
    flow: &SessionFlow,
    decision: SessionDecision,
) -> ForwardingResolution {
    if let Some(cached) = cached_session_resolution(forwarding, decision.resolution) {
        return cached;
    }
    let target = resolution_target_for_session(flow, decision);
    let resolved = lookup_forwarding_resolution_with_dynamic(forwarding, dynamic_neighbors, target);
    match resolved.disposition {
        ForwardingDisposition::NoRoute | ForwardingDisposition::MissingNeighbor => {
            cached_session_resolution(forwarding, decision.resolution).unwrap_or(resolved)
        }
        _ => resolved,
    }
}

fn apply_worker_commands(
    commands: &Arc<Mutex<VecDeque<WorkerCommand>>>,
    sessions: &mut SessionTable,
    session_map_fd: c_int,
) {
    // Hot path: try_lock avoids blocking on the mutex when another thread
    // holds it (rare) and avoids the cost of lock+unlock on empty queues
    // when there's nothing to do (common case during steady-state forwarding).
    let pending = match commands.try_lock() {
        Ok(mut pending) => {
            if pending.is_empty() {
                return;
            }
            core::mem::take(&mut *pending)
        }
        Err(_) => return,
    };
    let now_ns = monotonic_nanos();
    for cmd in pending {
        match cmd {
            WorkerCommand::UpsertSynced(entry) => {
                sessions.upsert_synced(
                    entry.key,
                    entry.decision,
                    entry.metadata,
                    now_ns,
                    entry.protocol,
                    entry.tcp_flags,
                );
            }
            WorkerCommand::DeleteSynced(key) => {
                sessions.delete(&key);
                delete_live_session_key(session_map_fd, &key);
            }
        }
    }
}

fn replicate_session_upsert(
    worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    entry: &SyncedSessionEntry,
) {
    let replica = synced_replica_entry(entry);
    for commands in worker_commands {
        if let Ok(mut pending) = commands.lock() {
            pending.push_back(WorkerCommand::UpsertSynced(replica.clone()));
        }
    }
}

fn replicate_session_delete(
    worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    key: &SessionKey,
) {
    for commands in worker_commands {
        if let Ok(mut pending) = commands.lock() {
            pending.push_back(WorkerCommand::DeleteSynced(key.clone()));
        }
    }
}

fn synced_replica_entry(entry: &SyncedSessionEntry) -> SyncedSessionEntry {
    let mut replica = entry.clone();
    replica.metadata.synced = true;
    replica
}

fn should_teardown_tcp_rst(_meta: UserspaceDpMeta, _flow: Option<&SessionFlow>) -> bool {
    // Do not immediately delete live sessions on an observed TCP RST.
    //
    // On the current HA userspace dataplane, stray or misclassified reply-side
    // RSTs can appear while the real flow is still active. Immediate teardown
    // removes the pinned live-session keys from USERSPACE_SESSIONS, which then
    // causes userspace-xdp to stop redirecting valid reply traffic and the
    // kernel to emit follow-on RSTs that collapse the connection entirely.
    //
    // The session table already marks TCP entries as closing when FIN/RST is
    // seen and ages them on the shorter TCP_CLOSING timeout. Rely on that
    // path for now until RST provenance is made trustworthy again.
    false
}

fn teardown_tcp_rst_flow(
    left: &mut [BindingWorker],
    current: &mut BindingWorker,
    right: &mut [BindingWorker],
    sessions: &mut SessionTable,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    forward_key: &SessionKey,
    nat: NatDecision,
    pending_forwards: &mut Vec<PendingForwardRequest>,
) {
    let reverse_key = reverse_session_key(forward_key, nat);
    sessions.delete(forward_key);
    sessions.delete(&reverse_key);
    delete_live_session_key(current.session_map_fd, forward_key);
    delete_live_session_key(current.session_map_fd, &reverse_key);
    remove_shared_session(shared_sessions, shared_nat_sessions, forward_key);
    remove_shared_session(shared_sessions, shared_nat_sessions, &reverse_key);
    replicate_session_delete(peer_worker_commands, forward_key);
    replicate_session_delete(peer_worker_commands, &reverse_key);
    cancel_pending_forwards(current, pending_forwards, forward_key, &reverse_key);
    cancel_queued_flow(left, current, right, forward_key, &reverse_key);
}

fn cancel_queued_flow(
    left: &mut [BindingWorker],
    current: &mut BindingWorker,
    right: &mut [BindingWorker],
    forward_key: &SessionKey,
    reverse_key: &SessionKey,
) {
    for binding in left.iter_mut() {
        cancel_queued_flow_on_binding(binding, forward_key, reverse_key);
    }
    cancel_queued_flow_on_binding(current, forward_key, reverse_key);
    for binding in right.iter_mut() {
        cancel_queued_flow_on_binding(binding, forward_key, reverse_key);
    }
}

fn cancel_queued_flow_on_binding(
    binding: &mut BindingWorker,
    forward_key: &SessionKey,
    reverse_key: &SessionKey,
) {
    let mut kept_local = VecDeque::with_capacity(binding.pending_tx_local.len());
    while let Some(req) = binding.pending_tx_local.pop_front() {
        if tx_request_matches_flow(&req, forward_key, reverse_key) {
            continue;
        }
        kept_local.push_back(req);
    }
    binding.pending_tx_local = kept_local;

    let mut kept_prepared = VecDeque::with_capacity(binding.pending_tx_prepared.len());
    while let Some(req) = binding.pending_tx_prepared.pop_front() {
        if prepared_request_matches_flow(&req, forward_key, reverse_key) {
            recycle_cancelled_prepared(binding, &req);
            continue;
        }
        kept_prepared.push_back(req);
    }
    binding.pending_tx_prepared = kept_prepared;

    if let Ok(mut pending) = binding.live.pending_tx.lock() {
        let mut kept_shared = VecDeque::with_capacity(pending.len());
        while let Some(req) = pending.pop_front() {
            if tx_request_matches_flow(&req, forward_key, reverse_key) {
                continue;
            }
            kept_shared.push_back(req);
        }
        binding
            .live
            .pending_tx_len
            .store(kept_shared.len() as u32, Ordering::Relaxed);
        *pending = kept_shared;
    }

    update_binding_debug_state(binding);
}

fn cancel_pending_forwards(
    binding: &mut BindingWorker,
    pending_forwards: &mut Vec<PendingForwardRequest>,
    forward_key: &SessionKey,
    reverse_key: &SessionKey,
) {
    let mut kept = Vec::with_capacity(pending_forwards.len());
    for req in pending_forwards.drain(..) {
        if pending_forward_matches_flow(&req, forward_key, reverse_key) {
            binding.pending_fill_frames.push_back(req.source_offset);
            continue;
        }
        kept.push(req);
    }
    *pending_forwards = kept;
}

fn recycle_cancelled_prepared(binding: &mut BindingWorker, req: &PreparedTxRequest) {
    if matches!(req.recycle_slot, Some(slot) if slot == binding.slot) {
        binding.pending_fill_frames.push_back(req.offset);
    } else {
        binding.free_tx_frames.push_back(req.offset);
    }
}

fn tx_request_matches_flow(
    req: &TxRequest,
    forward_key: &SessionKey,
    reverse_key: &SessionKey,
) -> bool {
    matches!(
        req.flow_key.as_ref(),
        Some(key) if key == forward_key || key == reverse_key
    )
}

fn prepared_request_matches_flow(
    req: &PreparedTxRequest,
    forward_key: &SessionKey,
    reverse_key: &SessionKey,
) -> bool {
    matches!(
        req.flow_key.as_ref(),
        Some(key) if key == forward_key || key == reverse_key
    )
}

fn pending_forward_matches_flow(
    req: &PendingForwardRequest,
    forward_key: &SessionKey,
    reverse_key: &SessionKey,
) -> bool {
    matches!(
        req.flow_key.as_ref(),
        Some(key) if key == forward_key || key == reverse_key
    )
}

fn lookup_shared_session(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    key: &SessionKey,
) -> Option<SyncedSessionEntry> {
    shared_sessions
        .lock()
        .ok()
        .and_then(|sessions| sessions.get(key).cloned())
}

fn lookup_shared_forward_nat_match(
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    reply_key: &SessionKey,
) -> Option<SyncedSessionEntry> {
    shared_nat_sessions
        .lock()
        .ok()
        .and_then(|sessions| sessions.get(reply_key).cloned())
}

fn repair_reverse_session_from_forward(
    sessions: &mut SessionTable,
    session_map_fd: c_int,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
    flow: &SessionFlow,
    now_ns: u64,
    now_secs: u64,
    protocol: u8,
    tcp_flags: u8,
) -> Option<SessionLookup> {
    let forward_match = sessions
        .find_forward_nat_match(&flow.forward_key)
        .or_else(|| {
            lookup_shared_forward_nat_match(shared_nat_sessions, &flow.forward_key).map(|entry| {
                ForwardSessionMatch {
                    key: entry.key,
                    decision: entry.decision,
                    metadata: entry.metadata,
                }
            })
        })?;

    let reverse_decision = SessionDecision {
        resolution: enforce_ha_resolution_snapshot(
            forwarding,
            ha_state,
            now_secs,
            lookup_forwarding_resolution_with_dynamic(
                forwarding,
                dynamic_neighbors,
                forward_match.key.src_ip,
            ),
        ),
        nat: forward_match
            .decision
            .nat
            .reverse(
                forward_match.key.src_ip,
                forward_match.key.dst_ip,
                forward_match.key.src_port,
                forward_match.key.dst_port,
            ),
    };
    let reverse_metadata = SessionMetadata {
        ingress_zone: forward_match.metadata.egress_zone.clone(),
        egress_zone: forward_match.metadata.ingress_zone.clone(),
        owner_rg_id: forward_match.metadata.owner_rg_id,
        is_reverse: true,
        synced: false,
        nat64_reverse: None,
    };
    if sessions.install_with_protocol(
        flow.forward_key.clone(),
        reverse_decision,
        reverse_metadata.clone(),
        now_ns,
        protocol,
        tcp_flags,
    ) {
        let _ = publish_live_session_key(session_map_fd, &flow.forward_key);
        let reverse_entry = SyncedSessionEntry {
            key: flow.forward_key.clone(),
            decision: reverse_decision,
            metadata: reverse_metadata.clone(),
            protocol,
            tcp_flags,
        };
        publish_shared_session(shared_sessions, shared_nat_sessions, &reverse_entry);
        replicate_session_upsert(peer_worker_commands, &reverse_entry);
    }
    Some(SessionLookup {
        decision: reverse_decision,
        metadata: reverse_metadata,
    })
}

fn publish_shared_session(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    entry: &SyncedSessionEntry,
) {
    if let Ok(mut sessions) = shared_sessions.lock() {
        sessions.insert(entry.key.clone(), entry.clone());
    }
    if !entry.metadata.is_reverse
        && let Ok(mut sessions) = shared_nat_sessions.lock()
    {
        sessions.insert(reverse_session_key(&entry.key, entry.decision.nat), entry.clone());
    }
}

fn remove_shared_session(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    key: &SessionKey,
) {
    if let Ok(mut sessions) = shared_sessions.lock()
        && let Some(entry) = sessions.remove(key)
        && !entry.metadata.is_reverse
        && let Ok(mut nat_sessions) = shared_nat_sessions.lock()
    {
        nat_sessions.remove(&reverse_session_key(&entry.key, entry.decision.nat));
    }
}

fn worker_loop(
    worker_id: u32,
    binding_plans: Vec<BindingPlan>,
    validation: ValidationState,
    forwarding: Arc<ForwardingState>,
    ha_state: Arc<ArcSwap<BTreeMap<i32, HAGroupRuntime>>>,
    dynamic_neighbors: Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
    shared_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    slow_path: Option<Arc<SlowPathReinjector>>,
    recent_exceptions: Arc<Mutex<VecDeque<ExceptionStatus>>>,
    recent_session_deltas: Arc<Mutex<VecDeque<SessionDeltaInfo>>>,
    last_resolution: Arc<Mutex<Option<PacketResolution>>>,
    commands: Arc<Mutex<VecDeque<WorkerCommand>>>,
    peer_worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>>,
    stop: Arc<AtomicBool>,
    heartbeat: Arc<AtomicU64>,
) {
    pin_current_thread(worker_id);
    let mut sessions = SessionTable::new();
    let mut screen_state = ScreenState::new();
    screen_state.update_profiles(forwarding.screen_profiles.clone());
    sessions.set_timeouts(forwarding.session_timeouts);
    let mut bindings = Vec::with_capacity(binding_plans.len());
    for plan in binding_plans {
        match BindingWorker::create(
            &plan.status,
            plan.ring_entries,
            plan.xsk_map_fd,
            plan.heartbeat_map_fd,
            plan.session_map_fd,
            plan.live.clone(),
            plan.shared_owner,
        ) {
            Ok(binding) => bindings.push(binding),
            Err(err) => plan.live.set_error(err.to_string()),
        }
    }
    // DEBUG: verify file writes work from worker thread
    {
        use std::io::Write;
        match std::fs::OpenOptions::new().create(true).append(true).open("/tmp/worker_startup.log") {
            Ok(mut f) => { let _ = writeln!(f, "worker {} started with {} bindings", worker_id, bindings.len()); }
            Err(e) => eprintln!("WORKER {} CANNOT WRITE /tmp/: {}", worker_id, e),
        }
    }
    let mut idle_iters = 0u32;
    let mut poll_start = 0usize;
    let mut shared_recycles = Vec::with_capacity((RX_BATCH_SIZE as usize).saturating_mul(2));
    // Debug: periodic summary counters
    let mut dbg_last_report_ns = monotonic_nanos();
    let mut dbg_rx_total = 0u64;
    let mut dbg_tx_total = 0u64;
    let mut dbg_forward_total = 0u64;
    let mut dbg_local_total = 0u64;
    let mut dbg_session_hit = 0u64;
    let mut dbg_session_miss = 0u64;
    let mut dbg_session_create = 0u64;
    let mut dbg_no_route = 0u64;
    let mut dbg_missing_neigh = 0u64;
    let mut dbg_policy_deny = 0u64;
    let mut dbg_ha_inactive = 0u64;
    let mut dbg_no_egress_binding = 0u64;
    let mut dbg_build_fail = 0u64;
    let mut dbg_tx_err = 0u64;
    let mut dbg_metadata_err = 0u64;
    let mut dbg_disposition_other = 0u64;
    let mut dbg_enqueue_ok = 0u64;
    let mut dbg_enqueue_inplace = 0u64;
    let mut dbg_enqueue_direct = 0u64;
    let mut dbg_enqueue_copy = 0u64;
    let mut dbg_rx_from_trust = 0u64;
    let mut dbg_rx_from_wan = 0u64;
    let mut dbg_fwd_trust_to_wan = 0u64;
    let mut dbg_fwd_wan_to_trust = 0u64;
    let mut dbg_nat_snat = 0u64;
    let mut dbg_nat_dnat = 0u64;
    let mut dbg_nat_none = 0u64;
    let mut dbg_frame_build_none = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_rx_tcp_rst = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_tx_tcp_rst = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_rx_tcp_fin = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_rx_tcp_synack = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_rx_tcp_zero_window = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_fwd_tcp_fin = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_fwd_tcp_rst = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_fwd_tcp_zero_window = 0u64;
    let mut dbg_rx_bytes_total = 0u64;
    let mut dbg_tx_bytes_total = 0u64;
    let mut dbg_rx_oversized = 0u64;
    let mut dbg_rx_max_frame = 0u32;
    let mut dbg_tx_max_frame = 0u32;
    let mut dbg_seg_needed_but_none = 0u64;
    let mut prev_rx_total = 0u64;
    let mut prev_fwd_total = 0u64;
    let mut stall_prev_fwd = 0u64;
    let mut stall_reported = false;
    const DBG_REPORT_INTERVAL_NS: u64 = 1_000_000_000; // 1 second
    while !stop.load(Ordering::Relaxed) {
        let session_map_fd = bindings
            .first()
            .map(|binding| binding.session_map_fd)
            .unwrap_or(-1);
        apply_worker_commands(&commands, &mut sessions, session_map_fd);
        let loop_now_ns = monotonic_nanos();
        let loop_now_secs = loop_now_ns / 1_000_000_000;
        let ha_runtime = ha_state.load();
        heartbeat.store(loop_now_ns, Ordering::Relaxed);
        let expired = sessions.expire_stale(loop_now_ns);
        if expired > 0 {
            if let Some(binding) = bindings.first() {
                binding
                    .live
                    .session_expires
                    .fetch_add(expired, Ordering::Relaxed);
            }
        }
        let mut did_work = false;
        let mut dbg_poll = DebugPollCounters::default();
        for offset in 0..bindings.len() {
            let idx = if bindings.is_empty() {
                0
            } else {
                (poll_start + offset) % bindings.len()
            };
            if poll_binding(
                idx,
                &mut bindings,
                &mut sessions,
                &mut screen_state,
                validation,
                loop_now_ns,
                loop_now_secs,
                &forwarding,
                ha_runtime.as_ref(),
                &dynamic_neighbors,
                &shared_sessions,
                &shared_nat_sessions,
                slow_path.as_ref(),
                &recent_exceptions,
                &recent_session_deltas,
                &last_resolution,
                &peer_worker_commands,
                &mut shared_recycles,
                &mut dbg_poll,
            ) {
                did_work = true;
            }
        }
        dbg_rx_total += dbg_poll.rx;
        dbg_tx_total += dbg_poll.tx;
        dbg_forward_total += dbg_poll.forward;
        dbg_local_total += dbg_poll.local;
        dbg_session_hit += dbg_poll.session_hit;
        dbg_session_miss += dbg_poll.session_miss;
        dbg_session_create += dbg_poll.session_create;
        dbg_no_route += dbg_poll.no_route;
        dbg_missing_neigh += dbg_poll.missing_neigh;
        dbg_policy_deny += dbg_poll.policy_deny;
        dbg_ha_inactive += dbg_poll.ha_inactive;
        dbg_no_egress_binding += dbg_poll.no_egress_binding;
        dbg_build_fail += dbg_poll.build_fail;
        dbg_tx_err += dbg_poll.tx_err;
        dbg_metadata_err += dbg_poll.metadata_err;
        dbg_disposition_other += dbg_poll.disposition_other;
        dbg_enqueue_ok += dbg_poll.enqueue_ok;
        dbg_enqueue_inplace += dbg_poll.enqueue_inplace;
        dbg_enqueue_direct += dbg_poll.enqueue_direct;
        dbg_enqueue_copy += dbg_poll.enqueue_copy;
        dbg_rx_from_trust += dbg_poll.rx_from_trust;
        dbg_rx_from_wan += dbg_poll.rx_from_wan;
        dbg_fwd_trust_to_wan += dbg_poll.fwd_trust_to_wan;
        dbg_fwd_wan_to_trust += dbg_poll.fwd_wan_to_trust;
        dbg_nat_snat += dbg_poll.nat_applied_snat;
        dbg_nat_dnat += dbg_poll.nat_applied_dnat;
        dbg_nat_none += dbg_poll.nat_applied_none;
        dbg_frame_build_none += dbg_poll.frame_build_none;
        #[cfg(feature = "debug-log")]
        {
            dbg_rx_tcp_rst += dbg_poll.rx_tcp_rst;
            dbg_rx_tcp_fin += dbg_poll.rx_tcp_fin;
            dbg_rx_tcp_synack += dbg_poll.rx_tcp_synack;
            dbg_rx_tcp_zero_window += dbg_poll.rx_tcp_zero_window;
            dbg_fwd_tcp_fin += dbg_poll.fwd_tcp_fin;
            dbg_fwd_tcp_rst += dbg_poll.fwd_tcp_rst;
            dbg_fwd_tcp_zero_window += dbg_poll.fwd_tcp_zero_window;
        }
        dbg_rx_bytes_total += dbg_poll.rx_bytes_total;
        dbg_tx_bytes_total += dbg_poll.tx_bytes_total;
        dbg_rx_oversized += dbg_poll.rx_oversized;
        if dbg_poll.rx_max_frame > dbg_rx_max_frame {
            dbg_rx_max_frame = dbg_poll.rx_max_frame;
        }
        if dbg_poll.tx_max_frame > dbg_tx_max_frame {
            dbg_tx_max_frame = dbg_poll.tx_max_frame;
        }
        dbg_seg_needed_but_none += dbg_poll.seg_needed_but_none;
        if !bindings.is_empty() {
            poll_start = (poll_start + 1) % bindings.len();
        }
        if sessions.has_pending_deltas() {
            let deltas = sessions.drain_deltas(256);
            purge_queued_flows_for_closed_deltas(&mut bindings, &deltas);
            if let Some(binding) = bindings.first() {
                let ident = binding.identity();
                flush_session_deltas(
                    &ident,
                    &binding.live,
                    binding.session_map_fd,
                    &deltas,
                    &shared_sessions,
                    &shared_nat_sessions,
                    &recent_session_deltas,
                    &peer_worker_commands,
                );
            }
        }
        // Debug: periodic summary report
        {
            let elapsed = loop_now_ns.saturating_sub(dbg_last_report_ns);
            if elapsed >= DBG_REPORT_INTERVAL_NS {
                let secs = elapsed as f64 / 1_000_000_000.0;
                let session_count = sessions.len();
                let mut binding_summary = String::new();
                for (i, b) in bindings.iter().enumerate() {
                    use std::fmt::Write;
                    let fill_pending = b.device.pending();
                    let rx_avail = b.rx.available();
                    let xsk_stats = b.device.statistics_v2().ok();
                    let inflight_recycles = b.in_flight_forward_recycles.len() as u32;
                    let scratch_recycle_len = b.scratch_recycle.len() as u32;
                    let ptx_prepared = b.pending_tx_prepared.len() as u32;
                    let ptx_local = b.pending_tx_local.len() as u32;
                    let total_accounted = b.pending_fill_frames.len() as u32
                        + fill_pending
                        + rx_avail
                        + b.free_tx_frames.len() as u32
                        + b.outstanding_tx
                        + inflight_recycles
                        + scratch_recycle_len
                        + ptx_prepared; // prepared TX holds UMEM frames
                    let expected_total = b.umem.total_frames;
                    let _ = write!(
                        binding_summary,
                        " [{}:if{}q{} pfill={} fring={} rxring={} free_tx={} otx={} ifl={} scr={} ptxp={} ptxl={} total={}/{} fill_ok={} polls={} bp={} rx_empty={} wake={}",
                        i,
                        b.ifindex,
                        b.queue_id,
                        b.pending_fill_frames.len(),
                        fill_pending,
                        rx_avail,
                        b.free_tx_frames.len(),
                        b.outstanding_tx,
                        inflight_recycles,
                        scratch_recycle_len,
                        ptx_prepared,
                        ptx_local,
                        total_accounted,
                        expected_total,
                        b.dbg_fill_submitted,
                        b.dbg_poll_cycles,
                        b.dbg_backpressure,
                        b.dbg_rx_empty,
                        b.dbg_rx_wakeups,
                    );
                    // TX pipeline debug counters
                    #[cfg(feature = "debug-log")]
                    { dbg_tx_tcp_rst += b.dbg_tx_tcp_rst; }
                    let _ = write!(
                        binding_summary,
                        " TX:ring_sub={}/ring_full={}/compl={}/sendto={}/err={}/eagain={}/enobufs={}/overflow={}",
                        b.dbg_tx_ring_submitted, b.dbg_tx_ring_full, b.dbg_completions_reaped,
                        b.dbg_sendto_calls, b.dbg_sendto_err, b.dbg_sendto_eagain, b.dbg_sendto_enobufs,
                        b.dbg_pending_overflow,
                    );
                    #[cfg(feature = "debug-log")]
                    let _ = write!(binding_summary, "/rst={}", b.dbg_tx_tcp_rst);
                    if let Some(s) = xsk_stats {
                        let _ = write!(
                            binding_summary,
                            " xsk:drop={}/inv={}/rfull={}/fempty={}/tinv={}/tempty={}",
                            s.rx_dropped, s.rx_invalid_descs, s.rx_ring_full,
                            s.rx_fill_ring_empty_descs, s.tx_invalid_descs, s.tx_ring_empty_descs,
                        );
                    }
                    // Socket error check (SO_ERROR) — detect kernel-side errors
                    {
                        let fd = b.rx.as_raw_fd();
                        let mut so_err: c_int = 0;
                        let mut so_err_len: libc::socklen_t = core::mem::size_of::<c_int>() as _;
                        let rc = unsafe {
                            libc::getsockopt(
                                fd,
                                libc::SOL_SOCKET,
                                libc::SO_ERROR,
                                &mut so_err as *mut c_int as *mut c_void,
                                &mut so_err_len,
                            )
                        };
                        if rc == 0 && so_err != 0 {
                            let _ = write!(binding_summary, " SO_ERR={so_err}");
                        }
                    }
                    // Ring diagnostics from xdpilone API
                    if cfg!(feature = "debug-log") {
                        let _ = write!(
                            binding_summary,
                            " RING:rx_nz={}/rx_max={}/fill_pend={}/dev_avail={} RX_WAKE:ok={}/err={}/errno={}",
                            b.dbg_rx_avail_nonzero, b.dbg_rx_avail_max,
                            b.dbg_fill_pending, b.dbg_device_avail,
                            b.dbg_rx_wake_sendto_ok, b.dbg_rx_wake_sendto_err, b.dbg_rx_wake_sendto_errno,
                        );
                        // Direct mmap diagnosis: read raw ring producer/consumer
                        if let Some((rxp, rxc, frp, frc, txp, txc, crp, crc)) =
                            diagnose_raw_ring_state(b.rx.as_raw_fd())
                        {
                            let _ = write!(
                                binding_summary,
                                " RAW:rxP={rxp}/rxC={rxc}/frP={frp}/frC={frc}/txP={txp}/txC={txc}/crP={crp}/crC={crc}"
                            );
                        }
                    }
                    // Frame leak detection
                    if total_accounted != expected_total {
                        let _ = write!(
                            binding_summary,
                            " FRAME_LEAK:{}",
                            expected_total as i64 - total_accounted as i64,
                        );
                    }
                    binding_summary.push(']');
                }
                #[cfg(feature = "debug-log")]
                eprintln!(
                    "DBG w{}: {:.1}s rx={} tx={} fwd={} local={} sess_hit={} sess_miss={} sess_create={} \
                     no_route={} miss_neigh={} pol_deny={} ha_inact={} no_egress={} build_fail={} \
                     tx_err={} meta_err={} other={} enq_ok={} enq_ip={} enq_dir={} enq_cp={} sessions={} \
                     DIR:trust_rx={}/wan_rx={}/t2w={}/w2t={} NAT:snat={}/dnat={}/none={}/bld_none={} RST:rx={}/tx={} \
                     SIZE:rx_avg={}/rx_max={}/tx_avg={}/tx_max={}/rx_over={}/seg_miss={} \
                     TCP_RX:fin={}/synack={}/zwin={} TCP_FWD:fin={}/rst={}/zwin={} \
                     CSUM:verified={}/bad_ip={}/bad_l4={} \
                     SESS_BPF:verify_ok={}/verify_fail={}/bpf_entries={} bindings:{}",
                    worker_id,
                    secs,
                    dbg_rx_total,
                    dbg_tx_total,
                    dbg_forward_total,
                    dbg_local_total,
                    dbg_session_hit,
                    dbg_session_miss,
                    dbg_session_create,
                    dbg_no_route,
                    dbg_missing_neigh,
                    dbg_policy_deny,
                    dbg_ha_inactive,
                    dbg_no_egress_binding,
                    dbg_build_fail,
                    dbg_tx_err,
                    dbg_metadata_err,
                    dbg_disposition_other,
                    dbg_enqueue_ok,
                    dbg_enqueue_inplace,
                    dbg_enqueue_direct,
                    dbg_enqueue_copy,
                    session_count,
                    dbg_rx_from_trust, dbg_rx_from_wan,
                    dbg_fwd_trust_to_wan, dbg_fwd_wan_to_trust,
                    dbg_nat_snat, dbg_nat_dnat, dbg_nat_none, dbg_frame_build_none,
                    dbg_rx_tcp_rst, dbg_tx_tcp_rst,
                    if dbg_rx_total > 0 { dbg_rx_bytes_total / dbg_rx_total } else { 0 },
                    dbg_rx_max_frame,
                    if dbg_enqueue_ok > 0 { dbg_tx_bytes_total / dbg_enqueue_ok } else { 0 },
                    dbg_tx_max_frame,
                    dbg_rx_oversized,
                    dbg_seg_needed_but_none,
                    dbg_rx_tcp_fin, dbg_rx_tcp_synack, dbg_rx_tcp_zero_window,
                    dbg_fwd_tcp_fin, dbg_fwd_tcp_rst, dbg_fwd_tcp_zero_window,
                    CSUM_VERIFIED_TOTAL.swap(0, Ordering::Relaxed),
                    CSUM_BAD_IP_TOTAL.swap(0, Ordering::Relaxed),
                    CSUM_BAD_L4_TOTAL.swap(0, Ordering::Relaxed),
                    SESSION_PUBLISH_VERIFY_OK.swap(0, Ordering::Relaxed),
                    SESSION_PUBLISH_VERIFY_FAIL.swap(0, Ordering::Relaxed),
                    if let Some(b) = bindings.first() {
                        count_bpf_session_entries(b.session_map_fd)
                    } else { 0 },
                    binding_summary,
                );
                // Non-debug builds: no per-second stats dump (use debug-log feature for verbose output).
                // Print XDP shim fallback stats — tells us WHY packets stop
                // being redirected to XSK.
                if cfg!(feature = "debug-log") {
                    if let Some(stats) = read_fallback_stats() {
                        if !stats.is_empty() {
                            let s: Vec<String> = stats.iter().map(|(n, v)| format!("{n}={v}")).collect();
                            eprintln!("DBG w{}: XDP_FALLBACK: {}", worker_id, s.join(" "));
                        }
                    }
                }
                // Save prev counters BEFORE reset for stall detection below
                if cfg!(feature = "debug-log") {
                    prev_rx_total = dbg_rx_total;
                    prev_fwd_total = dbg_forward_total;
                }
                dbg_last_report_ns = loop_now_ns;
                dbg_rx_total = 0;
                dbg_tx_total = 0;
                dbg_forward_total = 0;
                dbg_local_total = 0;
                dbg_session_hit = 0;
                dbg_session_miss = 0;
                dbg_session_create = 0;
                dbg_no_route = 0;
                dbg_missing_neigh = 0;
                dbg_policy_deny = 0;
                dbg_ha_inactive = 0;
                dbg_no_egress_binding = 0;
                dbg_build_fail = 0;
                dbg_tx_err = 0;
                dbg_metadata_err = 0;
                dbg_disposition_other = 0;
                dbg_enqueue_ok = 0;
                dbg_enqueue_inplace = 0;
                dbg_enqueue_direct = 0;
                dbg_enqueue_copy = 0;
                dbg_rx_from_trust = 0;
                dbg_rx_from_wan = 0;
                dbg_fwd_trust_to_wan = 0;
                dbg_fwd_wan_to_trust = 0;
                dbg_rx_bytes_total = 0;
                dbg_tx_bytes_total = 0;
                dbg_rx_oversized = 0;
                dbg_rx_max_frame = 0;
                dbg_tx_max_frame = 0;
                dbg_seg_needed_but_none = 0;
                // Stall detection: stall_prev_fwd is PREVIOUS interval's fwd count,
                // prev_fwd_total is THIS interval's fwd count (saved before reset).
                if cfg!(feature = "debug-log") {
                    if stall_prev_fwd > 10 && prev_fwd_total == 0 && !stall_reported {
                        stall_reported = true;
                        eprintln!("DBG STALL_DETECTED: w{} two_ago_fwd={} this_interval_fwd={} this_interval_rx={} sessions={}",
                            worker_id, stall_prev_fwd, prev_fwd_total, prev_rx_total, session_count);
                        // Dump comprehensive per-binding state at stall moment
                        for (si, sb) in bindings.iter().enumerate() {
                            use std::fmt::Write;
                            let fill_p = sb.device.pending();
                            let rx_a = sb.rx.available();
                            let ifl = sb.in_flight_forward_recycles.len() as u32;
                            let ptxp = sb.pending_tx_prepared.len() as u32;
                            let ptxl = sb.pending_tx_local.len() as u32;
                            let total = sb.pending_fill_frames.len() as u32
                                + fill_p + rx_a + sb.free_tx_frames.len() as u32
                                + sb.outstanding_tx + ifl + sb.scratch_recycle.len() as u32 + ptxp;
                            let raw = diagnose_raw_ring_state(sb.rx.as_raw_fd());
                            let mut stall_line = format!(
                                "DBG STALL_BINDING[{}]: if={} q={} pfill={} fring={} rxring={} free_tx={} otx={} ifl={} ptxp={} ptxl={} total={}/{}",
                                si, sb.ifindex, sb.queue_id,
                                sb.pending_fill_frames.len(), fill_p, rx_a,
                                sb.free_tx_frames.len(), sb.outstanding_tx, ifl,
                                ptxp, ptxl, total, sb.umem.total_frames,
                            );
                            if let Some((rxp, rxc, frp, frc, txp, txc, crp, crc)) = raw {
                                let _ = write!(stall_line,
                                    " RAW:rxP={rxp}/rxC={rxc}/frP={frp}/frC={frc}/txP={txp}/txC={txc}/crP={crp}/crC={crc}");
                            }
                            if let Ok(Some(stats)) = sb.device.statistics_v2().map(Some) {
                                let _ = write!(stall_line,
                                    " xsk:drop={}/rfull={}/fempty={}/tempty={}",
                                    stats.rx_dropped, stats.rx_ring_full,
                                    stats.rx_fill_ring_empty_descs, stats.tx_ring_empty_descs);
                            }
                            eprintln!("{stall_line}");
                        }
                        // Dump all session keys for this worker
                        let mut sess_dump = String::new();
                        let mut count = 0;
                        sessions.iter(|key, decision, metadata| {
                            if count < 20 {
                                use std::fmt::Write;
                                let _ = write!(sess_dump,
                                    "\n  SESS: {}:{} -> {}:{} proto={} nat=({:?},{:?}) is_rev={}",
                                    key.src_ip, key.src_port, key.dst_ip, key.dst_port,
                                    key.protocol, decision.nat.rewrite_src, decision.nat.rewrite_dst,
                                    metadata.is_reverse,
                                );
                                count += 1;
                            }
                        });
                        if !sess_dump.is_empty() {
                            eprintln!("DBG STALL_SESSIONS:{sess_dump}");
                        }
                        // Dump fallback stats at stall time
                        if let Some(stats) = read_fallback_stats() {
                            if !stats.is_empty() {
                                let s: Vec<String> = stats.iter().map(|(n, v)| format!("{n}={v}")).collect();
                                eprintln!("DBG STALL_FALLBACK: {}", s.join(" "));
                            }
                        }
                        // Also dump BPF session count
                        if let Some(b) = bindings.first() {
                            eprintln!("DBG STALL_BPF_SESSIONS: entries={}", count_bpf_session_entries(b.session_map_fd));
                        }
                    } else if prev_fwd_total > 0 {
                        stall_reported = false;
                    }
                    stall_prev_fwd = prev_fwd_total;
                }
                dbg_nat_snat = 0;
                dbg_nat_dnat = 0;
                dbg_nat_none = 0;
                dbg_frame_build_none = 0;
                #[cfg(feature = "debug-log")]
                {
                    dbg_rx_tcp_rst = 0;
                    dbg_tx_tcp_rst = 0;
                    dbg_rx_tcp_fin = 0;
                    dbg_rx_tcp_synack = 0;
                    dbg_rx_tcp_zero_window = 0;
                    dbg_fwd_tcp_fin = 0;
                    dbg_fwd_tcp_rst = 0;
                    dbg_fwd_tcp_zero_window = 0;
                }
                for b in bindings.iter_mut() {
                    b.dbg_fill_submitted = 0;
                    b.dbg_fill_failed = 0;
                    b.dbg_poll_cycles = 0;
                    b.dbg_backpressure = 0;
                    b.dbg_rx_empty = 0;
                    b.dbg_rx_wakeups = 0;
                    b.dbg_tx_ring_submitted = 0;
                    b.dbg_tx_ring_full = 0;
                    b.dbg_completions_reaped = 0;
                    b.dbg_sendto_calls = 0;
                    b.dbg_sendto_err = 0;
                    b.dbg_sendto_eagain = 0;
                    b.dbg_sendto_enobufs = 0;
                    b.dbg_pending_overflow = 0;
                    #[cfg(feature = "debug-log")]
                    { b.dbg_tx_tcp_rst = 0; }
                    b.dbg_rx_avail_nonzero = 0;
                    b.dbg_rx_avail_max = 0;
                    b.dbg_rx_wake_sendto_ok = 0;
                    b.dbg_rx_wake_sendto_err = 0;
                    b.dbg_rx_wake_sendto_errno = 0;
                }
            }
        }
        if did_work {
            idle_iters = 0;
            continue;
        }
        idle_iters = idle_iters.saturating_add(1);
        if idle_iters <= IDLE_SPIN_ITERS {
            std::hint::spin_loop();
        } else {
            thread::sleep(Duration::from_micros(IDLE_SLEEP_US));
        }
    }
    heartbeat.store(monotonic_nanos(), Ordering::Relaxed);
}

fn push_recent_exception(
    recent_exceptions: &mut VecDeque<ExceptionStatus>,
    exception: ExceptionStatus,
) {
    if recent_exceptions.len() >= MAX_RECENT_EXCEPTIONS {
        recent_exceptions.pop_front();
    }
    recent_exceptions.push_back(exception);
}

fn push_recent_session_delta(
    recent_session_deltas: &mut VecDeque<SessionDeltaInfo>,
    delta: SessionDeltaInfo,
) {
    if recent_session_deltas.len() >= MAX_RECENT_SESSION_DELTAS {
        recent_session_deltas.pop_front();
    }
    recent_session_deltas.push_back(delta);
}

fn monotonic_nanos() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    if rc != 0 || ts.tv_sec < 0 || ts.tv_nsec < 0 {
        return 0;
    }
    (ts.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64)
}

fn monotonic_timestamp_to_datetime(
    last_nanos: u64,
    now_mono: u64,
    now_wall: chrono::DateTime<Utc>,
) -> Option<chrono::DateTime<Utc>> {
    if last_nanos == 0 {
        return None;
    }
    let age_ns = now_mono.saturating_sub(last_nanos).min(i64::MAX as u64) as i64;
    now_wall.checked_sub_signed(chrono::TimeDelta::nanoseconds(age_ns))
}

fn pin_current_thread(worker_id: u32) {
    #[cfg(target_os = "linux")]
    unsafe {
        let cpus = thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        let cpu = (worker_id as usize) % cpus.max(1);
        let mut set: libc::cpu_set_t = core::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(cpu, &mut set);
        let _ = libc::sched_setaffinity(0, core::mem::size_of::<libc::cpu_set_t>(), &set);
    }
}

fn classify_metadata(meta: UserspaceDpMeta, validation: ValidationState) -> PacketDisposition {
    if !validation.snapshot_installed {
        return PacketDisposition::NoSnapshot;
    }
    if meta.config_generation != validation.config_generation {
        return PacketDisposition::ConfigGenerationMismatch;
    }
    if meta.fib_generation != validation.fib_generation {
        return PacketDisposition::FibGenerationMismatch;
    }
    match meta.addr_family as i32 {
        libc::AF_INET | libc::AF_INET6 => PacketDisposition::Valid,
        _ => PacketDisposition::UnsupportedPacket,
    }
}

fn prime_fill_ring_offsets(
    device: &mut xdpilone::DeviceQueue,
    offsets: &[u64],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let inserted = {
        let mut fill = device.fill(offsets.len() as u32);
        let inserted = fill.insert(offsets.iter().copied());
        fill.commit();
        inserted
    };
    if inserted != offsets.len() as u32 {
        return Err(format!("prefill fill ring inserted {inserted}/{}", offsets.len()).into());
    }
    if device.needs_wakeup() {
        device.wake();
    }
    Ok(())
}

fn ifinfo_from_binding(
    binding: &BindingStatus,
) -> Result<IfInfo, Box<dyn std::error::Error + Send + Sync>> {
    let mut info = IfInfo::invalid();
    info.from_ifindex(binding.ifindex as u32)
        .map_err(|e| format!("lookup ifindex {}: {e}", binding.ifindex))?;
    info.set_queue(binding.queue_id);
    Ok(info)
}

fn build_screen_profiles(snapshot: &ConfigSnapshot) -> FxHashMap<String, ScreenProfile> {
    let mut profiles = FxHashMap::default();
    for sp in &snapshot.screens {
        if sp.zone.is_empty() {
            continue;
        }
        profiles.insert(
            sp.zone.clone(),
            ScreenProfile {
                land: sp.land,
                syn_fin: sp.syn_fin,
                no_flag: sp.tcp_no_flag,
                fin_no_ack: sp.fin_no_ack,
                winnuke: sp.winnuke,
                ping_death: sp.ping_death,
                teardrop: sp.teardrop,
                icmp_fragment: sp.icmp_fragment,
                source_route: sp.source_route,
                icmp_flood_threshold: sp.icmp_flood_threshold,
                udp_flood_threshold: sp.udp_flood_threshold,
                syn_flood_threshold: sp.syn_flood_threshold,
                session_limit_src: sp.session_limit_src,
                session_limit_dst: sp.session_limit_dst,
                port_scan_threshold: sp.port_scan_threshold,
                ip_sweep_threshold: sp.ip_sweep_threshold,
            },
        );
    }
    profiles
}

fn build_forwarding_state(snapshot: &ConfigSnapshot) -> ForwardingState {
    let mut state = ForwardingState::default();
    let mut name_to_ifindex = BTreeMap::new();
    let mut linux_to_ifindex = BTreeMap::new();
    let mut mac_by_ifindex = BTreeMap::new();
    let (excluded_local_v4, excluded_local_v6) = nat_translated_local_exclusions(snapshot);

    for zone in &snapshot.zones {
        if zone.id == 0 || zone.name.is_empty() {
            continue;
        }
        state.zone_name_to_id.insert(zone.name.clone(), zone.id);
        state.zone_id_to_name.insert(zone.id, zone.name.clone());
    }

    for iface in &snapshot.interfaces {
        if iface.ifindex <= 0 {
            continue;
        }
        let label = if iface.linux_name.is_empty() {
            iface.name.clone()
        } else {
            iface.linux_name.clone()
        };
        state.ifindex_to_name.insert(iface.ifindex, label);
        name_to_ifindex.insert(iface.name.clone(), iface.ifindex);
        if !iface.linux_name.is_empty() {
            linux_to_ifindex.insert(iface.linux_name.clone(), iface.ifindex);
        }
        if !iface.zone.is_empty() {
            state
                .ifindex_to_zone
                .insert(iface.ifindex, iface.zone.clone());
            if iface.parent_ifindex > 0 {
                match state.ifindex_to_zone.get(&iface.parent_ifindex) {
                    Some(existing) if existing != &iface.zone => {}
                    _ => {
                        state
                            .ifindex_to_zone
                            .insert(iface.parent_ifindex, iface.zone.clone());
                    }
                }
            }
        }
        if iface.tunnel {
            state.tunnel_interfaces.insert(iface.ifindex);
        }
        if let Some(mac) = parse_mac(&iface.hardware_addr) {
            mac_by_ifindex.insert(iface.ifindex, mac);
        }
        for addr in &iface.addresses {
            let Ok(net) = addr.address.parse::<IpNet>() else {
                continue;
            };
            match net {
                IpNet::V4(v4) => {
                    if excluded_local_v4.contains(&v4.addr()) {
                        state.interface_nat_v4.insert(v4.addr(), iface.ifindex);
                    } else {
                        state.local_v4.insert(v4.addr());
                    }
                    state.connected_v4.push(ConnectedRouteV4 {
                        prefix: PrefixV4::from_net(v4),
                        ifindex: iface.ifindex,
                    });
                }
                IpNet::V6(v6) => {
                    if excluded_local_v6.contains(&v6.addr()) {
                        state.interface_nat_v6.insert(v6.addr(), iface.ifindex);
                    } else {
                        state.local_v6.insert(v6.addr());
                    }
                    state.connected_v6.push(ConnectedRouteV6 {
                        prefix: PrefixV6::from_net(v6),
                        ifindex: iface.ifindex,
                    });
                }
            }
        }
    }

    for iface in &snapshot.interfaces {
        if iface.ifindex <= 0 {
            continue;
        }
        let bind_ifindex = if iface.parent_ifindex > 0 {
            iface.parent_ifindex
        } else {
            iface.ifindex
        };
        let src_mac = match parse_mac(&iface.hardware_addr)
            .or_else(|| mac_by_ifindex.get(&bind_ifindex).copied())
        {
            Some(mac) => mac,
            None => continue,
        };
        state.egress.insert(
            iface.ifindex,
            EgressInterface {
                bind_ifindex,
                vlan_id: iface.vlan_id.max(0) as u16,
                mtu: iface.mtu.max(0) as usize,
                src_mac,
                zone: iface.zone.clone(),
                redundancy_group: iface.redundancy_group,
                primary_v4: pick_interface_v4(iface),
                primary_v6: pick_interface_v6(iface),
            },
        );
    }

    state
        .connected_v4
        .sort_by(|a, b| b.prefix.prefix_len().cmp(&a.prefix.prefix_len()));
    state
        .connected_v6
        .sort_by(|a, b| b.prefix.prefix_len().cmp(&a.prefix.prefix_len()));

    for route in &snapshot.routes {
        if let Ok(prefix) = route.destination.parse::<Ipv4Net>() {
            let (next_hop, ifindex) =
                resolve_route_target_v4(route, &name_to_ifindex, &linux_to_ifindex, &state);
            let table = canonical_route_table(&route.table, false);
            state
                .routes_v4
                .entry(table)
                .or_default()
                .push(RouteEntryV4 {
                    prefix: PrefixV4::from_net(prefix),
                    ifindex,
                    next_hop,
                    discard: route.discard,
                    next_table: route.next_table.clone(),
                });
            continue;
        }
        if let Ok(prefix) = route.destination.parse::<Ipv6Net>() {
            let (next_hop, ifindex) =
                resolve_route_target_v6(route, &name_to_ifindex, &linux_to_ifindex, &state);
            let table = canonical_route_table(&route.table, true);
            state
                .routes_v6
                .entry(table)
                .or_default()
                .push(RouteEntryV6 {
                    prefix: PrefixV6::from_net(prefix),
                    ifindex,
                    next_hop,
                    discard: route.discard,
                    next_table: route.next_table.clone(),
                });
        }
    }
    for routes in state.routes_v4.values_mut() {
        routes.sort_by(|a, b| b.prefix.prefix_len().cmp(&a.prefix.prefix_len()));
    }
    for routes in state.routes_v6.values_mut() {
        routes.sort_by(|a, b| b.prefix.prefix_len().cmp(&a.prefix.prefix_len()));
    }

    for neigh in &snapshot.neighbors {
        if neigh.ifindex <= 0 || !neighbor_state_usable(&neigh.state) {
            continue;
        }
        let Ok(ip) = neigh.ip.parse::<IpAddr>() else {
            continue;
        };
        let Some(mac) = parse_mac(&neigh.mac) else {
            continue;
        };
        state
            .neighbors
            .insert((neigh.ifindex, ip), NeighborEntry { mac });
    }
    for fabric in &snapshot.fabrics {
        if fabric.parent_ifindex <= 0 {
            continue;
        }
        let Ok(peer_addr) = fabric.peer_address.parse::<IpAddr>() else {
            continue;
        };
        let local_mac = match mac_by_ifindex.get(&fabric.parent_ifindex).copied() {
            Some(mac) => mac,
            None => continue,
        };
        let peer_mac = state
            .neighbors
            .get(&(fabric.overlay_ifindex, peer_addr))
            .or_else(|| state.neighbors.get(&(fabric.parent_ifindex, peer_addr)))
            .map(|entry| entry.mac);
        let Some(peer_mac) = peer_mac else {
            continue;
        };
        state.fabrics.push(FabricLink {
            parent_ifindex: fabric.parent_ifindex,
            overlay_ifindex: fabric.overlay_ifindex,
            peer_addr,
            peer_mac,
            local_mac,
        });
    }
    state.policy = parse_policy_state(&snapshot.default_policy, &snapshot.policies);
    state.allow_dns_reply = snapshot.flow.allow_dns_reply;
    state.allow_embedded_icmp = snapshot.flow.allow_embedded_icmp;
    state.session_timeouts = crate::session::SessionTimeouts::from_seconds(
        snapshot.flow.tcp_session_timeout,
        snapshot.flow.udp_session_timeout,
        snapshot.flow.icmp_session_timeout,
    );
    state.source_nat_rules = parse_source_nat_rules(&snapshot.source_nat_rules);
    state.static_nat = StaticNatTable::from_snapshots(&snapshot.static_nat_rules);
    state.dnat_table = DnatTable::from_snapshots(&snapshot.destination_nat_rules);
    state.nat64 = Nat64State::from_snapshots(&snapshot.nat64_rules);
    state.nptv6 = Nptv6State::from_snapshots(&snapshot.nptv6_rules);
    state.screen_profiles = build_screen_profiles(snapshot);
    state.tcp_mss_all_tcp = snapshot.flow.tcp_mss_all_tcp;
    state.tcp_mss_ipsec_vpn = snapshot.flow.tcp_mss_ipsec_vpn;
    state.tcp_mss_gre_in = snapshot.flow.tcp_mss_gre_in;
    state.tcp_mss_gre_out = snapshot.flow.tcp_mss_gre_out;
    // Build filter state from snapshot
    state.filter_state = crate::filter::parse_filter_state(&snapshot.filters, &snapshot.policers, &snapshot.interfaces, &snapshot.flow.lo0_filter_input_v4, &snapshot.flow.lo0_filter_input_v6);
    // Build flow export config from snapshot
    state.flow_export_config = snapshot.flow_export.as_ref().and_then(|fe| {
        let addr = format!("{}:{}", fe.collector_address, fe.collector_port);
        addr.parse::<std::net::SocketAddr>().ok().map(|collector| crate::flowexport::FlowExportConfig {
            collector,
            sampling_rate: fe.sampling_rate,
            active_timeout_secs: fe.active_timeout as u64,
            inactive_timeout_secs: fe.inactive_timeout as u64,
        })
    });

    // Add static NAT external IPs as local delivery targets so inbound
    // traffic destined to external IPs is recognized by the firewall.
    for ext_ip in state.static_nat.external_ips() {
        match ext_ip {
            IpAddr::V4(v4) => {
                state.local_v4.insert(*v4);
            }
            IpAddr::V6(v6) => {
                state.local_v6.insert(*v6);
            }
        }
    }

    // Add DNAT destination IPs as local delivery targets so traffic
    // to those IPs is recognized as locally-destined and processed.
    for dst_ip in state.dnat_table.destination_ips() {
        match dst_ip {
            IpAddr::V4(v4) => {
                state.local_v4.insert(v4);
            }
            IpAddr::V6(v6) => {
                state.local_v6.insert(v6);
            }
        }
    }

    // Debug: dump zone mappings and policy rules
    if cfg!(feature = "debug-log") {
        eprintln!("FWD_STATE: ifindex_to_zone={:?}", state.ifindex_to_zone);
        eprintln!("FWD_STATE: egress keys={:?}", state.egress.keys().collect::<Vec<_>>());
        for (ifidx, eg) in &state.egress {
            eprintln!(
                "FWD_STATE: egress[{}] bind={} zone={} vlan={} mtu={}",
                ifidx, eg.bind_ifindex, eg.zone, eg.vlan_id, eg.mtu,
            );
        }
        eprintln!(
            "FWD_STATE: policy default={:?} rules={}",
            state.policy.default_action,
            state.policy.rules.len(),
        );
        for (i, rule) in state.policy.rules.iter().enumerate() {
            eprintln!(
                "FWD_STATE: policy[{}] {}->{}  action={:?} src_v4={} dst_v4={} apps={}",
                i, rule.from_zone, rule.to_zone, rule.action,
                rule.source_v4.len(), rule.destination_v4.len(),
                rule.applications.len(),
            );
        }
        eprintln!(
            "FWD_STATE: local_v4={:?} interface_nat_v4={:?}",
            state.local_v4, state.interface_nat_v4,
        );
        eprintln!(
            "FWD_STATE: snat_rules={} static_nat={} dnat_table={} nptv6={} connected_v4={} routes_v4={}",
            state.source_nat_rules.len(),
            if state.static_nat.is_empty() { 0 } else { state.static_nat.external_ips().count() },
            if state.dnat_table.is_empty() { 0 } else { state.dnat_table.destination_ips().count() },
            if state.nptv6.is_empty() { 0 } else { state.nptv6.external_prefixes().len() },
            state.connected_v4.len(),
            state.routes_v4.values().map(|v| v.len()).sum::<usize>(),
        );
    }

    // Install nftables rules to suppress kernel TCP RSTs from SNAT IPs.
    //
    // When the AF_XDP fill ring momentarily runs dry under high load,
    // the mlx5 driver falls back to the regular RX path. Those leaked
    // packets reach the kernel TCP stack which — having no matching
    // socket — sends RSTs to the server, killing the connection.
    // Blocking outgoing RSTs for SNAT-managed IPs is a targeted fix:
    // the DP handles all TCP state for those addresses.
    install_kernel_rst_suppression(&state);

    state
}

/// Install nftables rules to DROP outgoing TCP RSTs from interface-NAT
/// (SNAT) addresses.  These addresses are owned by the userspace
/// dataplane; the kernel has no sockets for them and should never emit
/// RSTs.
fn install_kernel_rst_suppression(state: &ForwardingState) {
    use nftables::batch::Batch;
    use nftables::expr::{BinaryOperation, Expression, NamedExpression, Payload, PayloadField};
    use nftables::schema::{Chain, NfListObject, Rule, Table};
    use nftables::stmt::{Counter, Match, Operator, Statement};
    use nftables::types::{NfChainPolicy, NfChainType, NfFamily, NfHook};

    let v4_addrs: Vec<String> = state.interface_nat_v4.keys().map(|ip| ip.to_string()).collect();
    let v6_addrs: Vec<String> = state.interface_nat_v6.keys().map(|ip| ip.to_string()).collect();

    let table_name = "bpfrx_dp_rst";
    let chain_name = "output";

    // Delete existing table (ignore error if it doesn't exist).
    {
        let mut batch = Batch::new();
        batch.delete(NfListObject::Table(Table {
            family: NfFamily::INet,
            name: table_name.into(),
            handle: None,
        }));
        let _ = nftables::helper::apply_ruleset(&batch.to_nftables());
    }

    if v4_addrs.is_empty() && v6_addrs.is_empty() {
        return;
    }

    // Build fresh table + chain + rules.
    let mut batch = Batch::new();
    batch.add(NfListObject::Table(Table {
        family: NfFamily::INet,
        name: table_name.into(),
        handle: None,
    }));
    batch.add(NfListObject::Chain(Chain {
        family: NfFamily::INet,
        table: table_name.into(),
        name: chain_name.into(),
        newname: None,
        handle: None,
        _type: Some(NfChainType::Filter),
        hook: Some(NfHook::Output),
        prio: Some(0),
        dev: None,
        policy: Some(NfChainPolicy::Accept),
    }));

    // Helper: build rule statements for "proto saddr X tcp flags & rst != 0 counter drop".
    let rst_drop_rule = |proto: &'static str, addr: &str| -> Vec<Statement<'static>> {
        vec![
            Statement::Match(Match {
                left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                    PayloadField {
                        protocol: proto.into(),
                        field: "saddr".into(),
                    },
                ))),
                right: Expression::String(addr.to_string().into()),
                op: Operator::EQ,
            }),
            Statement::Match(Match {
                left: Expression::BinaryOperation(Box::new(BinaryOperation::AND(
                    Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                        PayloadField {
                            protocol: "tcp".into(),
                            field: "flags".into(),
                        },
                    ))),
                    Expression::Number(4), // RST flag
                ))),
                right: Expression::Number(0),
                op: Operator::NEQ,
            }),
            Statement::Counter(Counter::Anonymous(None)),
            Statement::Drop(None),
        ]
    };

    for addr in &v4_addrs {
        batch.add(NfListObject::Rule(Rule {
            family: NfFamily::INet,
            table: table_name.into(),
            chain: chain_name.into(),
            expr: rst_drop_rule("ip", addr).into(),
            handle: None,
            index: None,
            comment: None,
        }));
    }
    for addr in &v6_addrs {
        batch.add(NfListObject::Rule(Rule {
            family: NfFamily::INet,
            table: table_name.into(),
            chain: chain_name.into(),
            expr: rst_drop_rule("ip6", addr).into(),
            handle: None,
            index: None,
            comment: None,
        }));
    }

    match nftables::helper::apply_ruleset(&batch.to_nftables()) {
        Ok(()) => {
            eprintln!(
                "RST_SUPPRESS: installed nftables rules for {} v4 + {} v6 SNAT addresses",
                v4_addrs.len(),
                v6_addrs.len()
            );
        }
        Err(err) => {
            eprintln!("RST_SUPPRESS: failed to apply nftables rules: {err}");
        }
    }
}

/// Remove the nftables RST suppression table on shutdown.
pub(crate) fn remove_kernel_rst_suppression() {
    use nftables::batch::Batch;
    use nftables::schema::{NfListObject, Table};
    use nftables::types::NfFamily;

    let mut batch = Batch::new();
    batch.delete(NfListObject::Table(Table {
        family: NfFamily::INet,
        name: "bpfrx_dp_rst".into(),
        handle: None,
    }));
    let _ = nftables::helper::apply_ruleset(&batch.to_nftables());
}

fn nat_translated_local_exclusions(
    snapshot: &ConfigSnapshot,
) -> (FastSet<Ipv4Addr>, FastSet<Ipv6Addr>) {
    let mut excluded_v4 = FastSet::default();
    let mut excluded_v6 = FastSet::default();
    let mut to_zones = FastSet::default();
    for rule in &snapshot.source_nat_rules {
        if rule.interface_mode && !rule.off && !rule.to_zone.is_empty() {
            to_zones.insert(rule.to_zone.clone());
        }
    }
    if to_zones.is_empty() {
        return (excluded_v4, excluded_v6);
    }
    for iface in &snapshot.interfaces {
        if iface.zone.is_empty() || !to_zones.contains(&iface.zone) {
            continue;
        }
        if let Some(v4) = pick_interface_v4(iface) {
            excluded_v4.insert(v4);
        }
        if let Some(v6) = pick_interface_v6(iface) {
            excluded_v6.insert(v6);
        }
    }
    (excluded_v4, excluded_v6)
}

fn canonical_route_table(table: &str, is_ipv6: bool) -> String {
    if is_ipv6 {
        if table == "inet.0" {
            return "inet6.0".to_string();
        }
        if let Some(prefix) = table.strip_suffix(".inet.0") {
            return format!("{prefix}.inet6.0");
        }
        return table.to_string();
    }
    if table == "inet6.0" {
        return "inet.0".to_string();
    }
    if let Some(prefix) = table.strip_suffix(".inet6.0") {
        return format!("{prefix}.inet.0");
    }
    table.to_string()
}

fn pick_interface_v4(iface: &InterfaceSnapshot) -> Option<Ipv4Addr> {
    let mut fallback = None;
    for addr in &iface.addresses {
        if addr.family != "inet" {
            continue;
        }
        let Ok(net) = addr.address.parse::<Ipv4Net>() else {
            continue;
        };
        let ip = net.addr();
        if fallback.is_none() {
            fallback = Some(ip);
        }
        if !ip.is_link_local() {
            return Some(ip);
        }
    }
    fallback
}

fn pick_interface_v6(iface: &InterfaceSnapshot) -> Option<Ipv6Addr> {
    let mut fallback = None;
    for addr in &iface.addresses {
        if addr.family != "inet6" {
            continue;
        }
        let Ok(net) = addr.address.parse::<Ipv6Net>() else {
            continue;
        };
        let ip = net.addr();
        if fallback.is_none() {
            fallback = Some(ip);
        }
        if !ip.is_unicast_link_local() {
            return Some(ip);
        }
    }
    fallback
}

fn resolve_route_target_v4(
    route: &super::RouteSnapshot,
    names: &BTreeMap<String, i32>,
    linux_names: &BTreeMap<String, i32>,
    state: &ForwardingState,
) -> (Option<Ipv4Addr>, i32) {
    if route.discard || !route.next_table.is_empty() {
        return (None, 0);
    }
    let Some((next_hop, interface)) = route
        .next_hops
        .first()
        .map(|nh| parse_route_next_hop(nh.as_str()))
    else {
        return (None, 0);
    };
    let egress = interface
        .as_deref()
        .and_then(|name| resolve_ifindex(name, names, linux_names))
        .or_else(|| next_hop.and_then(|ip| infer_connected_ifindex_v4(state, ip)));
    (next_hop, egress.unwrap_or(0))
}

fn resolve_route_target_v6(
    route: &super::RouteSnapshot,
    names: &BTreeMap<String, i32>,
    linux_names: &BTreeMap<String, i32>,
    state: &ForwardingState,
) -> (Option<Ipv6Addr>, i32) {
    if route.discard || !route.next_table.is_empty() {
        return (None, 0);
    }
    let Some((next_hop, interface)) = route
        .next_hops
        .first()
        .map(|nh| parse_route_next_hop_v6(nh.as_str()))
    else {
        return (None, 0);
    };
    let egress = interface
        .as_deref()
        .and_then(|name| resolve_ifindex(name, names, linux_names))
        .or_else(|| next_hop.and_then(|ip| infer_connected_ifindex_v6(state, ip)));
    (next_hop, egress.unwrap_or(0))
}

fn parse_route_next_hop(spec: &str) -> (Option<Ipv4Addr>, Option<String>) {
    let (ip_part, if_part) = if let Some((lhs, rhs)) = spec.split_once('@') {
        (lhs, rhs)
    } else {
        (spec, "")
    };
    let ip = if ip_part.is_empty() {
        None
    } else {
        ip_part.parse::<Ipv4Addr>().ok()
    };
    let iface = if if_part.is_empty() {
        None
    } else {
        Some(if_part.to_string())
    };
    (ip, iface)
}

fn parse_route_next_hop_v6(spec: &str) -> (Option<Ipv6Addr>, Option<String>) {
    let (ip_part, if_part) = if let Some((lhs, rhs)) = spec.split_once('@') {
        (lhs, rhs)
    } else {
        (spec, "")
    };
    let ip = if ip_part.is_empty() {
        None
    } else {
        ip_part.parse::<Ipv6Addr>().ok()
    };
    let iface = if if_part.is_empty() {
        None
    } else {
        Some(if_part.to_string())
    };
    (ip, iface)
}

fn resolve_ifindex(
    name: &str,
    names: &BTreeMap<String, i32>,
    linux_names: &BTreeMap<String, i32>,
) -> Option<i32> {
    names
        .get(name)
        .copied()
        .or_else(|| linux_names.get(name).copied())
}

fn infer_connected_ifindex_v4(state: &ForwardingState, ip: Ipv4Addr) -> Option<i32> {
    state
        .connected_v4
        .iter()
        .find(|entry| entry.prefix.contains(ip))
        .map(|entry| entry.ifindex)
}

fn infer_connected_ifindex_v6(state: &ForwardingState, ip: Ipv6Addr) -> Option<i32> {
    state
        .connected_v6
        .iter()
        .find(|entry| entry.prefix.contains(ip))
        .map(|entry| entry.ifindex)
}

fn neighbor_state_usable(state: &str) -> bool {
    let normalized = state.to_ascii_lowercase();
    !(normalized.contains("failed") || normalized.contains("incomplete"))
}

fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut parts = s.split(':');
    for byte in &mut out {
        *byte = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(out)
}

fn format_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

fn parse_packet_destination(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
) -> Option<IpAddr> {
    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
    let l3 = meta.l3_offset as usize;
    match meta.addr_family as i32 {
        libc::AF_INET => {
            let end = l3.checked_add(20)?;
            if end > frame.len() {
                return None;
            }
            Some(IpAddr::V4(Ipv4Addr::new(
                frame[l3 + 16],
                frame[l3 + 17],
                frame[l3 + 18],
                frame[l3 + 19],
            )))
        }
        libc::AF_INET6 => {
            let end = l3.checked_add(40)?;
            if end > frame.len() {
                return None;
            }
            Some(IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&frame[l3 + 24..l3 + 40]).ok()?,
            )))
        }
        _ => None,
    }
}

fn resolve_forwarding(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    state: &ForwardingState,
    dynamic_neighbors: &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
) -> ForwardingResolution {
    let Some(dst) = parse_packet_destination(area, desc, meta) else {
        return ForwardingResolution {
            disposition: ForwardingDisposition::NoRoute,
            local_ifindex: 0,
            egress_ifindex: 0,
            tx_ifindex: 0,
            next_hop: None,
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        };
    };
    lookup_forwarding_resolution_with_dynamic(state, dynamic_neighbors, dst)
}

fn match_source_nat_for_flow(
    forwarding: &ForwardingState,
    from_zone: &str,
    to_zone: &str,
    egress_ifindex: i32,
    flow: &SessionFlow,
) -> Option<NatDecision> {
    let egress = forwarding.egress.get(&egress_ifindex)?;
    match_source_nat(
        &forwarding.source_nat_rules,
        from_zone,
        to_zone,
        flow.src_ip,
        flow.dst_ip,
        egress.primary_v4,
        egress.primary_v6,
    )
}

fn zone_pair_for_flow(
    forwarding: &ForwardingState,
    ingress_ifindex: i32,
    egress_ifindex: i32,
) -> (String, String) {
    zone_pair_for_flow_with_override(forwarding, ingress_ifindex, None, egress_ifindex)
}

fn zone_pair_for_flow_with_override(
    forwarding: &ForwardingState,
    ingress_ifindex: i32,
    ingress_zone_override: Option<&str>,
    egress_ifindex: i32,
) -> (String, String) {
    let from_zone = ingress_zone_override
        .map(|zone| zone.to_string())
        .or_else(|| forwarding.ifindex_to_zone.get(&ingress_ifindex).cloned())
        .unwrap_or_default();
    let to_zone = forwarding
        .egress
        .get(&egress_ifindex)
        .map(|iface| iface.zone.clone())
        .unwrap_or_default();
    (from_zone, to_zone)
}

/// Information returned from an embedded ICMP error session match that includes
/// NAT reversal data needed to rewrite the ICMP error packet back to the
/// original pre-NAT client.
#[derive(Clone, Debug)]
struct EmbeddedIcmpMatch {
    /// The forward session's NAT decision (has rewrite_src for SNAT).
    nat: NatDecision,
    /// The original (pre-NAT) source IP of the client.
    original_src: IpAddr,
    /// The original source port (if port SNAT was applied).
    original_src_port: u16,
    /// The embedded packet's L4 protocol.
    embedded_proto: u8,
    /// Forwarding resolution toward the original client.
    resolution: ForwardingResolution,
    /// Session metadata (zones, RG).
    metadata: SessionMetadata,
}

fn packet_ttl_would_expire(frame: &[u8], meta: UserspaceDpMeta) -> Option<bool> {
    let l3 = match meta.l3_offset {
        14 | 18 => meta.l3_offset as usize,
        _ => frame_l3_offset(frame)?,
    };
    match meta.addr_family as i32 {
        libc::AF_INET => Some(*frame.get(l3 + 8)? <= 1),
        libc::AF_INET6 => Some(*frame.get(l3 + 7)? <= 1),
        _ => None,
    }
}

fn build_local_time_exceeded_request(
    frame: &[u8],
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    ingress_ident: &BindingIdentity,
    _flow: &SessionFlow,
    forwarding: &ForwardingState,
    _dynamic_neighbors: &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
    _ha_state: &BTreeMap<i32, HAGroupRuntime>,
    _now_secs: u64,
) -> Option<PendingForwardRequest> {
    if !matches!(packet_ttl_would_expire(frame, meta), Some(true)) {
        return None;
    }

    let egress = forwarding.egress.get(&ingress_ident.ifindex)?;
    let target_ifindex = if egress.bind_ifindex > 0 {
        egress.bind_ifindex
    } else {
        ingress_ident.ifindex
    };
    let prebuilt_frame = match meta.addr_family as i32 {
        libc::AF_INET => build_local_time_exceeded_v4(frame, meta, ingress_ident.ifindex, forwarding),
        libc::AF_INET6 => build_local_time_exceeded_v6(frame, meta, ingress_ident.ifindex, forwarding),
        _ => return None,
    }?;

    Some(PendingForwardRequest {
        target_ifindex,
        ingress_queue_id: ingress_ident.queue_id,
        source_offset: desc.addr,
        desc,
        meta,
        decision: SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: ingress_ident.ifindex,
                tx_ifindex: target_ifindex,
                next_hop: None,
                neighbor_mac: None,
                src_mac: Some(egress.src_mac),
                tx_vlan_id: egress.vlan_id,
            },
            nat: NatDecision::default(),
        },
        expected_ports: None,
        flow_key: None,
        nat64_reverse: None,
        prebuilt_frame: Some(prebuilt_frame),
    })
}

fn ingress_reply_l2(frame: &[u8]) -> Option<([u8; 6], [u8; 6], u16)> {
    if frame.len() < 14 {
        return None;
    }
    let dst_mac = <[u8; 6]>::try_from(frame.get(0..6)?).ok()?;
    let src_mac = <[u8; 6]>::try_from(frame.get(6..12)?).ok()?;
    let eth_proto = u16::from_be_bytes([frame[12], frame[13]]);
    let vlan_id = if matches!(eth_proto, 0x8100 | 0x88a8) {
        let tci = u16::from_be_bytes([*frame.get(14)?, *frame.get(15)?]);
        tci & 0x0fff
    } else {
        0
    };
    Some((src_mac, dst_mac, vlan_id))
}

fn build_local_time_exceeded_v4(
    frame: &[u8],
    meta: UserspaceDpMeta,
    ingress_ifindex: i32,
    forwarding: &ForwardingState,
) -> Option<Vec<u8>> {
    let egress = forwarding.egress.get(&ingress_ifindex)?;
    let (dst_mac, fallback_src_mac, ingress_vlan_id) = ingress_reply_l2(frame)?;
    let src_ip = egress.primary_v4?;
    let src_mac = egress.src_mac;
    let l3 = match meta.l3_offset {
        14 | 18 => meta.l3_offset as usize,
        _ => frame_l3_offset(frame)?,
    };
    let packet = frame.get(l3..)?;
    if packet.len() < 20 {
        return None;
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < 20 || packet.len() < ihl {
        return None;
    }
    let dst_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    let packet_len = total_len.min(packet.len());
    let quoted_len = packet_len.min(ihl.saturating_add(8));
    let vlan_id = if ingress_vlan_id > 0 {
        ingress_vlan_id
    } else {
        egress.vlan_id
    };
    let eth_len = if vlan_id > 0 { 18 } else { 14 };
    let total_len = 20usize.checked_add(8)?.checked_add(quoted_len)?;
    let mut out = Vec::with_capacity(eth_len + total_len);
    write_eth_header(
        &mut out,
        dst_mac,
        if src_mac == [0; 6] { fallback_src_mac } else { src_mac },
        vlan_id,
        0x0800,
    );
    let ip_start = out.len();
    out.extend_from_slice(&[
        0x45,
        0x00,
        ((total_len as u16) >> 8) as u8,
        (total_len as u16) as u8,
        0x00,
        0x00,
        0x00,
        0x00,
        64,
        PROTO_ICMP,
        0,
        0,
    ]);
    out.extend_from_slice(&src_ip.octets());
    out.extend_from_slice(&dst_ip.octets());
    let ip_sum = checksum16(&out[ip_start..ip_start + 20]);
    out[ip_start + 10..ip_start + 12].copy_from_slice(&ip_sum.to_be_bytes());
    let icmp_start = out.len();
    out.extend_from_slice(&[11, 0, 0, 0, 0, 0, 0, 0]);
    out.extend_from_slice(packet.get(..quoted_len)?);
    let icmp_sum = checksum16(&out[icmp_start..]);
    out[icmp_start + 2..icmp_start + 4].copy_from_slice(&icmp_sum.to_be_bytes());
    Some(out)
}

fn build_local_time_exceeded_v6(
    frame: &[u8],
    meta: UserspaceDpMeta,
    ingress_ifindex: i32,
    forwarding: &ForwardingState,
) -> Option<Vec<u8>> {
    let egress = forwarding.egress.get(&ingress_ifindex)?;
    let (dst_mac, fallback_src_mac, ingress_vlan_id) = ingress_reply_l2(frame)?;
    let src_ip = egress.primary_v6?;
    let src_mac = egress.src_mac;
    let l3 = match meta.l3_offset {
        14 | 18 => meta.l3_offset as usize,
        _ => frame_l3_offset(frame)?,
    };
    let packet = frame.get(l3..)?;
    if packet.len() < 40 {
        return None;
    }
    let dst_ip = Ipv6Addr::from(<[u8; 16]>::try_from(packet.get(8..24)?).ok()?);
    let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let packet_len = (40 + payload_len).min(packet.len());
    let quoted_len = packet_len.min(48);
    let vlan_id = if ingress_vlan_id > 0 {
        ingress_vlan_id
    } else {
        egress.vlan_id
    };
    let eth_len = if vlan_id > 0 { 18 } else { 14 };
    let outer_payload_len = 8usize.checked_add(quoted_len)?;
    let mut out = Vec::with_capacity(eth_len + 40 + outer_payload_len);
    write_eth_header(
        &mut out,
        dst_mac,
        if src_mac == [0; 6] { fallback_src_mac } else { src_mac },
        vlan_id,
        0x86dd,
    );
    out.extend_from_slice(&[
        0x60,
        0x00,
        0x00,
        0x00,
        ((outer_payload_len as u16) >> 8) as u8,
        (outer_payload_len as u16) as u8,
        PROTO_ICMPV6,
        64,
    ]);
    out.extend_from_slice(&src_ip.octets());
    out.extend_from_slice(&dst_ip.octets());
    let icmp_start = out.len();
    out.extend_from_slice(&[3, 0, 0, 0, 0, 0, 0, 0]);
    out.extend_from_slice(packet.get(..quoted_len)?);
    let icmp_sum = checksum16_ipv6(src_ip, dst_ip, PROTO_ICMPV6, &out[icmp_start..]);
    out[icmp_start + 2..icmp_start + 4].copy_from_slice(&icmp_sum.to_be_bytes());
    Some(out)
}

/// Returns true if the protocol and ICMP type indicate an ICMP error message
/// (Destination Unreachable, Time Exceeded, Parameter Problem, Packet Too Big).
fn is_icmp_error(protocol: u8, icmp_type: u8) -> bool {
    match protocol {
        PROTO_ICMP => matches!(icmp_type, 3 | 11 | 12), // Dest Unreach, Time Exceeded, Param Problem
        PROTO_ICMPV6 => matches!(icmp_type, 1 | 2 | 3 | 4), // Dest Unreach, Packet Too Big, Time Exceeded, Param Problem
        _ => false,
    }
}

/// Parse the embedded IP+L4 headers from an ICMP error payload and look up the
/// corresponding session. Returns the session lookup if found.
///
/// ICMP error format (after outer IP header):
///   [type(1)][code(1)][checksum(2)][unused(4)][ embedded IP header ... ]
///
/// The embedded IP header contains the original packet's src/dst and the first
/// 8 bytes of the original L4 header (enough for ports).
fn try_embedded_icmp_session_match(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    sessions: &mut SessionTable,
    now_ns: u64,
) -> Option<SessionLookup> {
    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
    try_embedded_icmp_session_match_from_frame(frame, meta, sessions, now_ns)
}

/// Core embedded ICMP session match logic operating on a frame slice.
fn try_embedded_icmp_session_match_from_frame(
    frame: &[u8],
    meta: UserspaceDpMeta,
    sessions: &mut SessionTable,
    now_ns: u64,
) -> Option<SessionLookup> {
    let l4 = meta.l4_offset as usize;

    // Read ICMP type (first byte of L4 header)
    let icmp_type = *frame.get(l4)?;
    if !is_icmp_error(meta.protocol, icmp_type) {
        return None;
    }

    // ICMP error header is 8 bytes: type(1) + code(1) + checksum(2) + unused(4)
    let embedded_ip_start = l4 + 8;

    match meta.protocol {
        PROTO_ICMP => {
            // Embedded IPv4 header
            if frame.len() < embedded_ip_start + 28 {
                // Need at least 20 byte IP header + 8 bytes L4
                return None;
            }
            let ihl = ((frame[embedded_ip_start] & 0x0F) as usize) * 4;
            if ihl < 20 || frame.len() < embedded_ip_start + ihl + 4 {
                return None;
            }
            let emb_protocol = frame[embedded_ip_start + 9];
            let emb_src = IpAddr::V4(Ipv4Addr::new(
                frame[embedded_ip_start + 12],
                frame[embedded_ip_start + 13],
                frame[embedded_ip_start + 14],
                frame[embedded_ip_start + 15],
            ));
            let emb_dst = IpAddr::V4(Ipv4Addr::new(
                frame[embedded_ip_start + 16],
                frame[embedded_ip_start + 17],
                frame[embedded_ip_start + 18],
                frame[embedded_ip_start + 19],
            ));
            let emb_l4 = embedded_ip_start + ihl;
            let (emb_src_port, emb_dst_port) = if matches!(emb_protocol, PROTO_TCP | PROTO_UDP) {
                let bytes = frame.get(emb_l4..emb_l4 + 4)?;
                (
                    u16::from_be_bytes([bytes[0], bytes[1]]),
                    u16::from_be_bytes([bytes[2], bytes[3]]),
                )
            } else if matches!(emb_protocol, PROTO_ICMP) {
                let bytes = frame.get(emb_l4 + 4..emb_l4 + 6)?;
                (u16::from_be_bytes([bytes[0], bytes[1]]), 0)
            } else {
                (0, 0)
            };
            let embedded_key = SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: emb_protocol,
                src_ip: emb_src,
                dst_ip: emb_dst,
                src_port: emb_src_port,
                dst_port: emb_dst_port,
            };
            // Try direct lookup first (embedded packet matches a session key).
            // If that fails, try the reversed key (embedded packet is the
            // outgoing SNAT'd packet, so reverse matches the NAT reverse index).
            sessions.lookup(&embedded_key, now_ns, 0).or_else(|| {
                let reversed = SessionKey {
                    addr_family: libc::AF_INET as u8,
                    protocol: emb_protocol,
                    src_ip: emb_dst,
                    dst_ip: emb_src,
                    src_port: if matches!(emb_protocol, PROTO_ICMP) { emb_src_port } else { emb_dst_port },
                    dst_port: if matches!(emb_protocol, PROTO_ICMP) { emb_dst_port } else { emb_src_port },
                };
                sessions.lookup(&reversed, now_ns, 0)
            }).or_else(|| {
                // NAT reverse index: swap to reply format
                let reply_key = SessionKey {
                    addr_family: libc::AF_INET as u8,
                    protocol: emb_protocol,
                    src_ip: emb_dst,
                    dst_ip: emb_src,
                    src_port: if matches!(emb_protocol, PROTO_ICMP) { emb_src_port } else { emb_dst_port },
                    dst_port: if matches!(emb_protocol, PROTO_ICMP) { emb_dst_port } else { emb_src_port },
                };
                sessions.find_forward_nat_match(&reply_key).map(|m| {
                    SessionLookup { decision: m.decision, metadata: m.metadata }
                })
            })
        }
        PROTO_ICMPV6 => {
            // Embedded IPv6 header
            if frame.len() < embedded_ip_start + 48 {
                // 40 byte IPv6 header + 8 bytes L4
                return None;
            }
            let emb_protocol = frame[embedded_ip_start + 6]; // next header
            let emb_src = IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&frame[embedded_ip_start + 8..embedded_ip_start + 24]).ok()?,
            ));
            let emb_dst = IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&frame[embedded_ip_start + 24..embedded_ip_start + 40]).ok()?,
            ));
            let emb_l4 = embedded_ip_start + 40;
            let (emb_src_port, emb_dst_port) = if matches!(emb_protocol, PROTO_TCP | PROTO_UDP) {
                let bytes = frame.get(emb_l4..emb_l4 + 4)?;
                (
                    u16::from_be_bytes([bytes[0], bytes[1]]),
                    u16::from_be_bytes([bytes[2], bytes[3]]),
                )
            } else if matches!(emb_protocol, PROTO_ICMPV6) {
                let bytes = frame.get(emb_l4 + 4..emb_l4 + 6)?;
                (u16::from_be_bytes([bytes[0], bytes[1]]), 0)
            } else {
                (0, 0)
            };
            let embedded_key = SessionKey {
                addr_family: libc::AF_INET6 as u8,
                protocol: emb_protocol,
                src_ip: emb_src,
                dst_ip: emb_dst,
                src_port: emb_src_port,
                dst_port: emb_dst_port,
            };
            sessions.lookup(&embedded_key, now_ns, 0).or_else(|| {
                let reversed = SessionKey {
                    addr_family: libc::AF_INET6 as u8,
                    protocol: emb_protocol,
                    src_ip: emb_dst,
                    dst_ip: emb_src,
                    src_port: if matches!(emb_protocol, PROTO_ICMPV6) { emb_src_port } else { emb_dst_port },
                    dst_port: if matches!(emb_protocol, PROTO_ICMPV6) { emb_dst_port } else { emb_src_port },
                };
                sessions.lookup(&reversed, now_ns, 0)
            }).or_else(|| {
                // NAT reverse index: swap to reply format
                let reply_key = SessionKey {
                    addr_family: libc::AF_INET6 as u8,
                    protocol: emb_protocol,
                    src_ip: emb_dst,
                    dst_ip: emb_src,
                    src_port: if matches!(emb_protocol, PROTO_ICMPV6) { emb_src_port } else { emb_dst_port },
                    dst_port: if matches!(emb_protocol, PROTO_ICMPV6) { emb_dst_port } else { emb_src_port },
                };
                sessions.find_forward_nat_match(&reply_key).map(|m| {
                    SessionLookup { decision: m.decision, metadata: m.metadata }
                })
            })
        }
        _ => None,
    }
}

/// Extended embedded ICMP session match that returns full NAT reversal info.
///
/// Unlike `try_embedded_icmp_session_match` which only confirms a match exists,
/// this function extracts the original (pre-NAT) source IP and port from the
/// matched session, and resolves forwarding toward the original client.
///
/// The embedded packet in an ICMP error from an intermediate router looks like:
///   [outer IP: src=router, dst=SNAT'd addr] [ICMP error] [embedded: src=SNAT'd addr, dst=server]
///
/// The forward session has: src=original_client, dst=server, nat_src=SNAT'd addr.
/// We reverse this: outer dst -> original_client, embedded src -> original_client.
fn try_embedded_icmp_nat_match(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    now_ns: u64,
) -> Option<EmbeddedIcmpMatch> {
    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
    try_embedded_icmp_nat_match_from_frame(frame, meta, sessions, forwarding, dynamic_neighbors, shared_nat_sessions, now_ns)
}

/// Core implementation of embedded ICMP NAT match operating on a frame slice.
fn try_embedded_icmp_nat_match_from_frame(
    frame: &[u8],
    meta: UserspaceDpMeta,
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    now_ns: u64,
) -> Option<EmbeddedIcmpMatch> {
    let l4 = meta.l4_offset as usize;
    let icmp_type = *frame.get(l4)?;
    if !is_icmp_error(meta.protocol, icmp_type) {
        return None;
    }

    let embedded_ip_start = l4 + 8;

    match meta.protocol {
        PROTO_ICMP => {
            if frame.len() < embedded_ip_start + 28 {
                return None;
            }
            let ihl = ((frame[embedded_ip_start] & 0x0F) as usize) * 4;
            if ihl < 20 || frame.len() < embedded_ip_start + ihl + 4 {
                return None;
            }
            let emb_protocol = frame[embedded_ip_start + 9];
            let emb_src_v4 = Ipv4Addr::new(
                frame[embedded_ip_start + 12],
                frame[embedded_ip_start + 13],
                frame[embedded_ip_start + 14],
                frame[embedded_ip_start + 15],
            );
            let emb_dst_v4 = Ipv4Addr::new(
                frame[embedded_ip_start + 16],
                frame[embedded_ip_start + 17],
                frame[embedded_ip_start + 18],
                frame[embedded_ip_start + 19],
            );
            let emb_src = IpAddr::V4(emb_src_v4);
            let emb_dst = IpAddr::V4(emb_dst_v4);
            let emb_l4 = embedded_ip_start + ihl;
            let (emb_src_port, emb_dst_port) = if matches!(emb_protocol, PROTO_TCP | PROTO_UDP) {
                let bytes = frame.get(emb_l4..emb_l4 + 4)?;
                (
                    u16::from_be_bytes([bytes[0], bytes[1]]),
                    u16::from_be_bytes([bytes[2], bytes[3]]),
                )
            } else if matches!(emb_protocol, PROTO_ICMP) {
                let bytes = frame.get(emb_l4 + 4..emb_l4 + 6)?;
                (u16::from_be_bytes([bytes[0], bytes[1]]), 0)
            } else {
                (0, 0)
            };
            // The embedded packet is the original outgoing packet (post-SNAT).
            let embedded_key = SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: emb_protocol,
                src_ip: emb_src,
                dst_ip: emb_dst,
                src_port: emb_src_port,
                dst_port: emb_dst_port,
            };
            // The NAT reverse index is keyed by the *reply* tuple
            // (src=remote, dst=SNAT'd), so swap src/dst.
            let reply_key = SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: emb_protocol,
                src_ip: emb_dst,
                dst_ip: emb_src,
                src_port: if matches!(emb_protocol, PROTO_ICMP) { emb_src_port } else { emb_dst_port },
                dst_port: if matches!(emb_protocol, PROTO_ICMP) { emb_dst_port } else { emb_src_port },
            };
            // Try per-worker NAT reverse index first.
            let forward_match = sessions.find_forward_nat_match(&reply_key);
            if let Some(fwd) = forward_match {
                let nat = fwd.decision.nat;
                let original_src = fwd.key.src_ip;
                let original_src_port = fwd.key.src_port;
                let resolution = lookup_forwarding_resolution_with_dynamic(
                    forwarding, dynamic_neighbors, original_src,
                );
                return Some(EmbeddedIcmpMatch {
                    nat,
                    original_src,
                    original_src_port,
                    embedded_proto: emb_protocol,
                    resolution,
                    metadata: fwd.metadata,
                });
            }
            // Cross-worker fallback: the outbound session may be on a different
            // worker (RSS distributes ICMP TE replies differently than the
            // original probes). Check the shared NAT session table.
            if let Ok(nat_sessions) = shared_nat_sessions.lock() {
                if let Some(entry) = nat_sessions.get(&reply_key) {
                    let nat = entry.decision.nat;
                    let original_src = entry.key.src_ip;
                    let original_src_port = entry.key.src_port;
                    let resolution = lookup_forwarding_resolution_with_dynamic(
                        forwarding, dynamic_neighbors, original_src,
                    );
                    return Some(EmbeddedIcmpMatch {
                        nat,
                        original_src,
                        original_src_port,
                        embedded_proto: emb_protocol,
                        resolution,
                        metadata: entry.metadata.clone(),
                    });
                }
            }
            // Fallback: direct/reversed session lookup (non-NAT case or
            // session key matches directly).
            let lookup = sessions.lookup(&embedded_key, now_ns, 0).or_else(|| {
                let reversed = SessionKey {
                    addr_family: libc::AF_INET as u8,
                    protocol: emb_protocol,
                    src_ip: emb_dst,
                    dst_ip: emb_src,
                    src_port: emb_dst_port,
                    dst_port: emb_src_port,
                };
                sessions.lookup(&reversed, now_ns, 0)
            });
            lookup.map(|sl| {
                // No NAT reversal needed — the embedded packet's source is
                // already the original client.
                let resolution = lookup_forwarding_resolution_with_dynamic(
                    forwarding, dynamic_neighbors, emb_src,
                );
                EmbeddedIcmpMatch {
                    nat: NatDecision::default(),
                    original_src: emb_src,
                    original_src_port: emb_src_port,
                    embedded_proto: emb_protocol,
                    resolution,
                    metadata: sl.metadata,
                }
            })
        }
        PROTO_ICMPV6 => {
            if frame.len() < embedded_ip_start + 48 {
                return None;
            }
            let emb_protocol = frame[embedded_ip_start + 6];
            let emb_src = IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&frame[embedded_ip_start + 8..embedded_ip_start + 24]).ok()?,
            ));
            let emb_dst = IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&frame[embedded_ip_start + 24..embedded_ip_start + 40]).ok()?,
            ));
            let emb_l4 = embedded_ip_start + 40;
            let (emb_src_port, emb_dst_port) = if matches!(emb_protocol, PROTO_TCP | PROTO_UDP) {
                let bytes = frame.get(emb_l4..emb_l4 + 4)?;
                (
                    u16::from_be_bytes([bytes[0], bytes[1]]),
                    u16::from_be_bytes([bytes[2], bytes[3]]),
                )
            } else if matches!(emb_protocol, PROTO_ICMPV6) {
                let bytes = frame.get(emb_l4 + 4..emb_l4 + 6)?;
                (u16::from_be_bytes([bytes[0], bytes[1]]), 0)
            } else {
                (0, 0)
            };
            let embedded_key = SessionKey {
                addr_family: libc::AF_INET6 as u8,
                protocol: emb_protocol,
                src_ip: emb_src,
                dst_ip: emb_dst,
                src_port: emb_src_port,
                dst_port: emb_dst_port,
            };
            // Swap to reply key format (NAT reverse index is keyed by reply tuple)
            let reply_key = SessionKey {
                addr_family: libc::AF_INET6 as u8,
                protocol: emb_protocol,
                src_ip: emb_dst,
                dst_ip: emb_src,
                src_port: if matches!(emb_protocol, PROTO_ICMPV6) { emb_src_port } else { emb_dst_port },
                dst_port: if matches!(emb_protocol, PROTO_ICMPV6) { emb_dst_port } else { emb_src_port },
            };
            let forward_match = sessions.find_forward_nat_match(&reply_key);
            if let Some(fwd) = forward_match {
                let nat = fwd.decision.nat;
                let original_src = fwd.key.src_ip;
                let original_src_port = fwd.key.src_port;
                let resolution = lookup_forwarding_resolution_with_dynamic(
                    forwarding, dynamic_neighbors, original_src,
                );
                return Some(EmbeddedIcmpMatch {
                    nat,
                    original_src,
                    original_src_port,
                    embedded_proto: emb_protocol,
                    resolution,
                    metadata: fwd.metadata,
                });
            }
            // Cross-worker fallback via shared NAT sessions.
            if let Ok(nat_sessions) = shared_nat_sessions.lock() {
                if let Some(entry) = nat_sessions.get(&reply_key) {
                    let nat = entry.decision.nat;
                    let original_src = entry.key.src_ip;
                    let original_src_port = entry.key.src_port;
                    let resolution = lookup_forwarding_resolution_with_dynamic(
                        forwarding, dynamic_neighbors, original_src,
                    );
                    return Some(EmbeddedIcmpMatch {
                        nat,
                        original_src,
                        original_src_port,
                        embedded_proto: emb_protocol,
                        resolution,
                        metadata: entry.metadata.clone(),
                    });
                }
            }
            let lookup = sessions.lookup(&embedded_key, now_ns, 0).or_else(|| {
                let reversed = SessionKey {
                    addr_family: libc::AF_INET6 as u8,
                    protocol: emb_protocol,
                    src_ip: emb_dst,
                    dst_ip: emb_src,
                    src_port: emb_dst_port,
                    dst_port: emb_src_port,
                };
                sessions.lookup(&reversed, now_ns, 0)
            });
            lookup.map(|sl| {
                let resolution = lookup_forwarding_resolution_with_dynamic(
                    forwarding, dynamic_neighbors, emb_src,
                );
                EmbeddedIcmpMatch {
                    nat: NatDecision::default(),
                    original_src: emb_src,
                    original_src_port: emb_src_port,
                    embedded_proto: emb_protocol,
                    resolution,
                    metadata: sl.metadata,
                }
            })
        }
        _ => None,
    }
}

/// Build a NAT-reversed ICMP error frame for IPv4.
///
/// Rewrites:
/// 1. Outer IP dst: SNAT'd address -> original client IP
/// 2. Embedded IP src: SNAT'd address -> original client IP
/// 3. Embedded L4 src port: SNAT'd port -> original port (if port NAT)
/// 4. Embedded IP header checksum (incremental for src change)
/// 5. Outer ICMP checksum (recomputed from scratch since embedded bytes changed)
/// 6. Outer IP header checksum (recomputed from scratch since dst changed)
/// 7. New Ethernet header with correct dst MAC from FIB lookup
///
/// Returns the complete rewritten Ethernet frame, or None on parse failure.
fn build_nat_reversed_icmp_error_v4(
    frame: &[u8],
    meta: UserspaceDpMeta,
    icmp_match: &EmbeddedIcmpMatch,
) -> Option<Vec<u8>> {
    let l3 = meta.l3_offset as usize;
    let l4 = meta.l4_offset as usize;
    if l3 >= frame.len() || l4 >= frame.len() || l3 >= l4 {
        return None;
    }
    let packet = frame.get(l3..)?;
    if packet.len() < 20 {
        return None;
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < 20 || packet.len() < ihl + 8 {
        return None;
    }

    let original_client = match icmp_match.original_src {
        IpAddr::V4(v4) => v4,
        _ => return None,
    };

    // Compute Ethernet header size from L3 offset.
    let eth_len = l3;
    let dst_mac = icmp_match.resolution.neighbor_mac?;
    let src_mac = icmp_match.resolution.src_mac?;
    let vlan_id = icmp_match.resolution.tx_vlan_id;

    // Trim incoming payload to IP total length (strip Ethernet padding).
    let ip_total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    let payload = if ip_total_len > 0 && ip_total_len < packet.len() {
        &packet[..ip_total_len]
    } else {
        packet
    };

    // Build output frame: new Ethernet header + modified IP payload.
    let out_eth_len = if vlan_id > 0 { 18 } else { 14 };
    let mut out = vec![0u8; out_eth_len + payload.len()];
    write_eth_header_slice(out.get_mut(..out_eth_len)?, dst_mac, src_mac, vlan_id, 0x0800)?;
    out.get_mut(out_eth_len..)?.copy_from_slice(payload);

    let pkt = &mut out[out_eth_len..];

    // --- Step 1: Rewrite outer IP dst ---
    pkt.get_mut(16..20)?.copy_from_slice(&original_client.octets());

    // --- Step 2+3: Rewrite embedded packet ---
    let icmp_offset = ihl; // ICMP header starts at IHL
    let emb_ip_offset = icmp_offset + 8; // Embedded IP starts 8 bytes into ICMP
    if pkt.len() < emb_ip_offset + 20 {
        return None;
    }
    let emb_ihl = ((pkt[emb_ip_offset] & 0x0f) as usize) * 4;
    if emb_ihl < 20 || pkt.len() < emb_ip_offset + emb_ihl {
        return None;
    }

    // Rewrite embedded src IP.
    pkt.get_mut(emb_ip_offset + 12..emb_ip_offset + 16)?
        .copy_from_slice(&original_client.octets());

    // Update embedded IP header checksum incrementally for src change.
    // Read old checksum, zero it, recompute from scratch (simpler, ICMP errors are rare).
    {
        pkt.get_mut(emb_ip_offset + 10..emb_ip_offset + 12)?
            .copy_from_slice(&[0, 0]);
        let emb_ip_header = pkt.get(emb_ip_offset..emb_ip_offset + emb_ihl)?;
        let csum = checksum16(emb_ip_header);
        pkt.get_mut(emb_ip_offset + 10..emb_ip_offset + 12)?
            .copy_from_slice(&csum.to_be_bytes());
    }

    // Rewrite embedded L4 src port if port NAT was applied.
    let emb_l4_offset = emb_ip_offset + emb_ihl;
    if icmp_match.nat.rewrite_src_port.is_some() || icmp_match.nat.rewrite_src.is_some() {
        let emb_proto = icmp_match.embedded_proto;
        if matches!(emb_proto, PROTO_TCP | PROTO_UDP) && pkt.len() >= emb_l4_offset + 2 {
            pkt.get_mut(emb_l4_offset..emb_l4_offset + 2)?
                .copy_from_slice(&icmp_match.original_src_port.to_be_bytes());
        } else if emb_proto == PROTO_ICMP && pkt.len() >= emb_l4_offset + 6 {
            // ICMP echo ID is at offset +4 in the embedded ICMP header.
            let old_id_bytes = pkt.get(emb_l4_offset + 4..emb_l4_offset + 6)?;
            let old_id = u16::from_be_bytes([old_id_bytes[0], old_id_bytes[1]]);
            if old_id != icmp_match.original_src_port {
                pkt.get_mut(emb_l4_offset + 4..emb_l4_offset + 6)?
                    .copy_from_slice(&icmp_match.original_src_port.to_be_bytes());
                // Embedded ICMP checksum covers echo ID — update it.
                if pkt.len() >= emb_l4_offset + 4 {
                    let old_csum = u16::from_be_bytes([
                        pkt[emb_l4_offset + 2],
                        pkt[emb_l4_offset + 3],
                    ]);
                    let new_csum = checksum16_adjust(
                        old_csum,
                        &[old_id],
                        &[icmp_match.original_src_port],
                    );
                    pkt.get_mut(emb_l4_offset + 2..emb_l4_offset + 4)?
                        .copy_from_slice(&new_csum.to_be_bytes());
                }
            }
        }
    }

    // --- Step 5: Recompute outer ICMP checksum from scratch ---
    // The ICMP checksum covers: type(1) + code(1) + checksum(2) + unused(4) + payload.
    // Zero checksum field, then compute over the entire ICMP message.
    pkt.get_mut(icmp_offset + 2..icmp_offset + 4)?
        .copy_from_slice(&[0, 0]);
    let icmp_data = pkt.get(icmp_offset..)?;
    let icmp_csum = checksum16(icmp_data);
    pkt.get_mut(icmp_offset + 2..icmp_offset + 4)?
        .copy_from_slice(&icmp_csum.to_be_bytes());

    // --- Step 6: Recompute outer IP header checksum from scratch ---
    pkt.get_mut(10..12)?.copy_from_slice(&[0, 0]);
    let ip_header = pkt.get(..ihl)?;
    let ip_csum = checksum16(ip_header);
    pkt.get_mut(10..12)?.copy_from_slice(&ip_csum.to_be_bytes());

    Some(out)
}

/// Build a NAT-reversed ICMPv6 error frame for IPv6.
///
/// Rewrites:
/// 1. Outer IPv6 dst: SNAT'd address -> original client IPv6
/// 2. Embedded IPv6 src: SNAT'd address -> original client IPv6
/// 3. Embedded L4 src port: SNAT'd port -> original port (if port NAT)
/// 4. Outer ICMPv6 checksum (recomputed from scratch — covers pseudo-header)
/// 5. New Ethernet header with correct dst MAC from FIB lookup
///
/// IPv6 has no IP header checksum, simplifying the rewrite vs IPv4.
fn build_nat_reversed_icmp_error_v6(
    frame: &[u8],
    meta: UserspaceDpMeta,
    icmp_match: &EmbeddedIcmpMatch,
) -> Option<Vec<u8>> {
    let l3 = meta.l3_offset as usize;
    let l4 = meta.l4_offset as usize;
    if l3 >= frame.len() || l4 >= frame.len() || l3 >= l4 {
        return None;
    }
    let packet = frame.get(l3..)?;
    if packet.len() < 40 {
        return None;
    }

    let original_client_bytes = match icmp_match.original_src {
        IpAddr::V6(v6) => v6.octets(),
        _ => return None,
    };

    let dst_mac = icmp_match.resolution.neighbor_mac?;
    let src_mac = icmp_match.resolution.src_mac?;
    let vlan_id = icmp_match.resolution.tx_vlan_id;

    // Trim to IPv6 total length (40 header + payload_len).
    let ipv6_payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let ip6_total = 40 + ipv6_payload_len;
    let payload = if ip6_total > 0 && ip6_total < packet.len() {
        &packet[..ip6_total]
    } else {
        packet
    };

    let out_eth_len = if vlan_id > 0 { 18 } else { 14 };
    let mut out = vec![0u8; out_eth_len + payload.len()];
    write_eth_header_slice(out.get_mut(..out_eth_len)?, dst_mac, src_mac, vlan_id, 0x86dd)?;
    out.get_mut(out_eth_len..)?.copy_from_slice(payload);

    let pkt = &mut out[out_eth_len..];

    // --- Step 1: Rewrite outer IPv6 dst (bytes 24..40) ---
    pkt.get_mut(24..40)?.copy_from_slice(&original_client_bytes);

    // --- Step 2: Rewrite embedded IPv6 src ---
    let icmp_offset = 40; // ICMPv6 starts after fixed IPv6 header
    let emb_ip_offset = icmp_offset + 8; // Embedded IPv6 starts 8 bytes into ICMPv6
    if pkt.len() < emb_ip_offset + 40 {
        return None;
    }
    // Embedded IPv6 src is at emb_ip_offset + 8..+24
    pkt.get_mut(emb_ip_offset + 8..emb_ip_offset + 24)?
        .copy_from_slice(&original_client_bytes);

    // --- Step 3: Rewrite embedded L4 src port ---
    let emb_l4_offset = emb_ip_offset + 40;
    if icmp_match.nat.rewrite_src_port.is_some() || icmp_match.nat.rewrite_src.is_some() {
        let emb_proto = icmp_match.embedded_proto;
        if matches!(emb_proto, PROTO_TCP | PROTO_UDP) && pkt.len() >= emb_l4_offset + 2 {
            pkt.get_mut(emb_l4_offset..emb_l4_offset + 2)?
                .copy_from_slice(&icmp_match.original_src_port.to_be_bytes());
        } else if emb_proto == PROTO_ICMPV6 && pkt.len() >= emb_l4_offset + 6 {
            // ICMPv6 echo ID is at offset +4 in the embedded ICMPv6 header.
            let old_id_bytes = pkt.get(emb_l4_offset + 4..emb_l4_offset + 6)?;
            let old_id = u16::from_be_bytes([old_id_bytes[0], old_id_bytes[1]]);
            if old_id != icmp_match.original_src_port {
                pkt.get_mut(emb_l4_offset + 4..emb_l4_offset + 6)?
                    .copy_from_slice(&icmp_match.original_src_port.to_be_bytes());
                // Update embedded ICMPv6 checksum for echo ID change.
                if pkt.len() >= emb_l4_offset + 4 {
                    let old_csum = u16::from_be_bytes([
                        pkt[emb_l4_offset + 2],
                        pkt[emb_l4_offset + 3],
                    ]);
                    let new_csum = checksum16_adjust(
                        old_csum,
                        &[old_id],
                        &[icmp_match.original_src_port],
                    );
                    pkt.get_mut(emb_l4_offset + 2..emb_l4_offset + 4)?
                        .copy_from_slice(&new_csum.to_be_bytes());
                }
            }
        }
    }

    // --- Step 4: Recompute outer ICMPv6 checksum from scratch ---
    // ICMPv6 checksum covers pseudo-header (src, dst, length, next_header=58)
    // plus the entire ICMPv6 message.
    pkt.get_mut(icmp_offset + 2..icmp_offset + 4)?
        .copy_from_slice(&[0, 0]);
    let src_v6 = Ipv6Addr::from(<[u8; 16]>::try_from(pkt.get(8..24)?).ok()?);
    let dst_v6 = Ipv6Addr::from(<[u8; 16]>::try_from(pkt.get(24..40)?).ok()?);
    let icmp6_data = pkt.get(icmp_offset..)?;
    let icmp6_csum = checksum16_ipv6(src_v6, dst_v6, PROTO_ICMPV6, icmp6_data);
    pkt.get_mut(icmp_offset + 2..icmp_offset + 4)?
        .copy_from_slice(&icmp6_csum.to_be_bytes());

    Some(out)
}

fn allow_unsolicited_dns_reply(forwarding: &ForwardingState, flow: &SessionFlow) -> bool {
    forwarding.allow_dns_reply
        && flow.forward_key.protocol == PROTO_UDP
        && flow.forward_key.src_port == 53
}

fn owner_rg_for_flow(forwarding: &ForwardingState, egress_ifindex: i32) -> i32 {
    forwarding
        .egress
        .get(&egress_ifindex)
        .map(|iface| iface.redundancy_group.max(0))
        .unwrap_or_default()
}

fn ingress_is_fabric(forwarding: &ForwardingState, ingress_ifindex: i32) -> bool {
    forwarding.fabrics.iter().any(|fabric| {
        fabric.parent_ifindex == ingress_ifindex || fabric.overlay_ifindex == ingress_ifindex
    })
}

fn resolve_fabric_redirect(forwarding: &ForwardingState) -> Option<ForwardingResolution> {
    let fabric = forwarding
        .fabrics
        .iter()
        .find(|fabric| fabric.parent_ifindex > 0)
        .copied()?;
    Some(ForwardingResolution {
        disposition: ForwardingDisposition::FabricRedirect,
        local_ifindex: 0,
        egress_ifindex: fabric.parent_ifindex,
        tx_ifindex: fabric.parent_ifindex,
        next_hop: Some(fabric.peer_addr),
        neighbor_mac: Some(fabric.peer_mac),
        src_mac: Some(fabric.local_mac),
        tx_vlan_id: 0,
    })
}

fn resolve_zone_encoded_fabric_redirect(
    forwarding: &ForwardingState,
    ingress_zone: &str,
) -> Option<ForwardingResolution> {
    let mut resolution = resolve_fabric_redirect(forwarding)?;
    let zone_id = forwarding.zone_name_to_id.get(ingress_zone).copied()?;
    if zone_id == 0 || zone_id > u8::MAX as u16 {
        return None;
    }
    resolution.src_mac = Some([0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, zone_id as u8]);
    Some(resolution)
}

fn finalize_embedded_icmp_resolution(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    now_secs: u64,
    ingress_ifindex: i32,
    icmp_match: &EmbeddedIcmpMatch,
) -> ForwardingResolution {
    let enforced =
        enforce_ha_resolution_snapshot(forwarding, ha_state, now_secs, icmp_match.resolution);
    if !ingress_is_fabric(forwarding, ingress_ifindex)
        && matches!(
            enforced.disposition,
            ForwardingDisposition::HAInactive
                | ForwardingDisposition::NoRoute
                | ForwardingDisposition::DiscardRoute
        )
    {
        if let Some(redirect) = resolve_zone_encoded_fabric_redirect(
            forwarding,
            icmp_match.metadata.ingress_zone.as_ref(),
        ) {
            return redirect;
        }
    }
    redirect_via_fabric_if_needed(forwarding, enforced, ingress_ifindex)
}

fn redirect_via_fabric_if_needed(
    forwarding: &ForwardingState,
    resolution: ForwardingResolution,
    ingress_ifindex: i32,
) -> ForwardingResolution {
    if resolution.disposition != ForwardingDisposition::HAInactive {
        return resolution;
    }
    if ingress_is_fabric(forwarding, ingress_ifindex) {
        return resolution;
    }
    resolve_fabric_redirect(forwarding).unwrap_or(resolution)
}

fn resolve_ingress_logical_ifindex(
    forwarding: &ForwardingState,
    ingress_ifindex: i32,
    ingress_vlan_id: u16,
) -> Option<i32> {
    forwarding.egress.iter().find_map(|(ifindex, iface)| {
        if iface.bind_ifindex == ingress_ifindex && iface.vlan_id == ingress_vlan_id {
            Some(*ifindex)
        } else {
            None
        }
    })
}

fn enforce_ha_resolution(
    forwarding: &ForwardingState,
    ha_state: &Arc<ArcSwap<BTreeMap<i32, HAGroupRuntime>>>,
    resolution: ForwardingResolution,
) -> ForwardingResolution {
    enforce_ha_resolution_at(
        forwarding,
        ha_state,
        monotonic_nanos() / 1_000_000_000,
        resolution,
    )
}

fn enforce_ha_resolution_at(
    forwarding: &ForwardingState,
    ha_state: &Arc<ArcSwap<BTreeMap<i32, HAGroupRuntime>>>,
    now_secs: u64,
    resolution: ForwardingResolution,
) -> ForwardingResolution {
    let state = ha_state.load();
    enforce_ha_resolution_snapshot(forwarding, state.as_ref(), now_secs, resolution)
}

fn enforce_ha_resolution_snapshot(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    now_secs: u64,
    resolution: ForwardingResolution,
) -> ForwardingResolution {
    if resolution.disposition != ForwardingDisposition::ForwardCandidate {
        return resolution;
    }
    let owner_rg_id = owner_rg_for_flow(forwarding, resolution.egress_ifindex);
    if owner_rg_id <= 0 {
        return resolution;
    }
    let Some(group) = ha_state.get(&owner_rg_id) else {
        return ForwardingResolution {
            disposition: ForwardingDisposition::HAInactive,
            ..resolution
        };
    };
    if !group.active {
        return ForwardingResolution {
            disposition: ForwardingDisposition::HAInactive,
            ..resolution
        };
    }
    if group.watchdog_timestamp == 0
        || now_secs < group.watchdog_timestamp
        || now_secs.saturating_sub(group.watchdog_timestamp) > HA_WATCHDOG_STALE_AFTER_SECS
    {
        return ForwardingResolution {
            disposition: ForwardingDisposition::HAInactive,
            ..resolution
        };
    }
    resolution
}

/// Return the effective TCP MSS clamp value for the current config.
/// Returns 0 if MSS clamping is disabled.
fn effective_tcp_mss(forwarding: &ForwardingState) -> u16 {
    if forwarding.tcp_mss_all_tcp > 0 {
        return forwarding.tcp_mss_all_tcp;
    }
    // IPsec VPN and GRE MSS values are returned when configured;
    // the caller is responsible for checking the tunnel context.
    if forwarding.tcp_mss_ipsec_vpn > 0 {
        return forwarding.tcp_mss_ipsec_vpn;
    }
    0
}

/// Clamp TCP MSS option in-place in an L3 packet (starting at IP header).
/// `max_mss` is the maximum allowed MSS value.
/// Returns true if the MSS was clamped.
fn clamp_tcp_mss(packet: &mut [u8], max_mss: u16) -> bool {
    if max_mss == 0 {
        return false;
    }
    // Determine L3 header length and protocol.
    if packet.is_empty() {
        return false;
    }
    let version = packet[0] >> 4;
    let (l4_offset, protocol) = match version {
        4 => {
            if packet.len() < 20 {
                return false;
            }
            let ihl = (packet[0] & 0x0F) as usize * 4;
            (ihl, packet[9])
        }
        6 => {
            if packet.len() < 40 {
                return false;
            }
            (40, packet[6])
        }
        _ => return false,
    };
    if protocol != PROTO_TCP {
        return false;
    }
    let tcp = match packet.get_mut(l4_offset..) {
        Some(s) if s.len() >= 20 => s,
        _ => return false,
    };
    let flags = tcp[13];
    // Only clamp on SYN or SYN+ACK
    if (flags & 0x02) == 0 {
        return false;
    }
    let data_offset = ((tcp[12] >> 4) as usize) * 4;
    if data_offset < 20 || tcp.len() < data_offset {
        return false;
    }
    // Walk TCP options looking for MSS (kind=2, len=4)
    let mut pos = 20;
    while pos + 4 <= data_offset {
        let kind = tcp[pos];
        if kind == 0 {
            break; // end of options
        }
        if kind == 1 {
            pos += 1; // NOP
            continue;
        }
        let opt_len = tcp[pos + 1] as usize;
        if opt_len < 2 || pos + opt_len > data_offset {
            break;
        }
        if kind == 2 && opt_len == 4 {
            let current_mss = u16::from_be_bytes([tcp[pos + 2], tcp[pos + 3]]);
            if current_mss > max_mss {
                // Clamp MSS and adjust TCP checksum
                let old_bytes = [tcp[pos + 2], tcp[pos + 3]];
                tcp[pos + 2..pos + 4].copy_from_slice(&max_mss.to_be_bytes());
                // Incremental checksum update
                let old_val = u16::from_be_bytes(old_bytes) as u32;
                let new_val = max_mss as u32;
                let old_csum = u16::from_be_bytes([tcp[16], tcp[17]]) as u32;
                let mut sum = (!old_csum & 0xFFFF) + old_val + (!new_val & 0xFFFF);
                sum = (sum & 0xFFFF) + (sum >> 16);
                sum = (sum & 0xFFFF) + (sum >> 16);
                tcp[16..18].copy_from_slice(&(!(sum as u16)).to_be_bytes());
                return true;
            }
            return false;
        }
        pos += opt_len;
    }
    false
}

/// Clamp TCP MSS in a full Ethernet frame starting at `l3_offset`.
fn clamp_tcp_mss_frame(frame: &mut [u8], l3_offset: usize, max_mss: u16) -> bool {
    if max_mss == 0 || l3_offset >= frame.len() {
        return false;
    }
    clamp_tcp_mss(&mut frame[l3_offset..], max_mss)
}

const ICMP_TE_MAX_PER_SEC: u32 = 100;

/// Rate limiter for ICMP Time Exceeded messages.
struct IcmpTeRateLimiter {
    max_per_sec: u32,
    count: u32,
    window_start_ns: u64,
}

impl IcmpTeRateLimiter {
    fn new(max_per_sec: u32) -> Self {
        Self {
            max_per_sec,
            count: 0,
            window_start_ns: 0,
        }
    }

    fn allow(&mut self, now_ns: u64) -> bool {
        let window = now_ns / 1_000_000_000;
        let prev_window = self.window_start_ns / 1_000_000_000;
        if window != prev_window {
            self.count = 0;
            self.window_start_ns = now_ns;
        }
        if self.count >= self.max_per_sec {
            return false;
        }
        self.count += 1;
        true
    }
}

/// Returns true if the packet is IPsec traffic (ESP protocol 50 or IKE UDP
/// ports 500/4500) that should be passed to the kernel for XFRM processing.
#[inline]
fn is_ipsec_traffic(protocol: u8, dst_port: u16) -> bool {
    protocol == PROTO_ESP || (protocol == PROTO_UDP && (dst_port == 500 || dst_port == 4500))
}

#[cfg(test)]
fn lookup_forwarding_for_ip(state: &ForwardingState, dst: IpAddr) -> ForwardingDisposition {
    lookup_forwarding_resolution(state, dst).disposition
}

fn lookup_forwarding_resolution(state: &ForwardingState, dst: IpAddr) -> ForwardingResolution {
    lookup_forwarding_resolution_inner(state, None, dst)
}

fn lookup_forwarding_resolution_with_dynamic(
    state: &ForwardingState,
    dynamic_neighbors: &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
    dst: IpAddr,
) -> ForwardingResolution {
    lookup_forwarding_resolution_inner(state, Some(dynamic_neighbors), dst)
}

fn lookup_forwarding_resolution_inner(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>>,
    dst: IpAddr,
) -> ForwardingResolution {
    let mut resolution = match dst {
        IpAddr::V4(ip) => {
            if state.local_v4.contains(&ip) {
                let local_ifindex = state
                    .connected_v4
                    .iter()
                    .find(|entry| entry.prefix.addr() == ip)
                    .map(|entry| entry.ifindex)
                    .unwrap_or(0);
                return ForwardingResolution {
                    disposition: ForwardingDisposition::LocalDelivery,
                    local_ifindex,
                    egress_ifindex: local_ifindex,
                    tx_ifindex: local_ifindex,
                    next_hop: None,
                    neighbor_mac: None,
                    src_mac: None,
                    tx_vlan_id: 0,
                };
            }
            lookup_forwarding_resolution_v4(state, dynamic_neighbors, ip, DEFAULT_V4_TABLE, 0)
        }
        IpAddr::V6(ip) => {
            if state.local_v6.contains(&ip) {
                let local_ifindex = state
                    .connected_v6
                    .iter()
                    .find(|entry| entry.prefix.addr() == ip)
                    .map(|entry| entry.ifindex)
                    .unwrap_or(0);
                return ForwardingResolution {
                    disposition: ForwardingDisposition::LocalDelivery,
                    local_ifindex,
                    egress_ifindex: local_ifindex,
                    tx_ifindex: local_ifindex,
                    next_hop: None,
                    neighbor_mac: None,
                    src_mac: None,
                    tx_vlan_id: 0,
                };
            }
            lookup_forwarding_resolution_v6(state, dynamic_neighbors, ip, DEFAULT_V6_TABLE, 0)
        }
    };
    // Tunnel interfaces (GRE, ip6gre, XFRM) can't be reached via AF_XDP TX.
    // Route these to slow-path so the kernel handles encapsulation.
    if matches!(resolution.disposition, ForwardingDisposition::ForwardCandidate | ForwardingDisposition::MissingNeighbor)
        && state.tunnel_interfaces.contains(&resolution.egress_ifindex)
    {
        resolution.disposition = ForwardingDisposition::MissingNeighbor;
    }
    resolution
}

fn interface_nat_local_resolution(
    state: &ForwardingState,
    dst: IpAddr,
) -> Option<ForwardingResolution> {
    match dst {
        IpAddr::V4(ip) => state
            .interface_nat_v4
            .get(&ip)
            .copied()
            .map(|local_ifindex| ForwardingResolution {
                disposition: ForwardingDisposition::LocalDelivery,
                local_ifindex,
                egress_ifindex: local_ifindex,
                tx_ifindex: local_ifindex,
                next_hop: None,
                neighbor_mac: None,
                src_mac: None,
                tx_vlan_id: 0,
            }),
        IpAddr::V6(ip) => state
            .interface_nat_v6
            .get(&ip)
            .copied()
            .map(|local_ifindex| ForwardingResolution {
                disposition: ForwardingDisposition::LocalDelivery,
                local_ifindex,
                egress_ifindex: local_ifindex,
                tx_ifindex: local_ifindex,
                next_hop: None,
                neighbor_mac: None,
                src_mac: None,
                tx_vlan_id: 0,
            }),
    }
}

fn interface_nat_local_resolution_on_session_miss(
    state: &ForwardingState,
    dst: IpAddr,
    protocol: u8,
) -> Option<ForwardingResolution> {
    if !matches!(protocol, PROTO_ICMP | PROTO_ICMPV6) {
        return None;
    }
    interface_nat_local_resolution(state, dst)
}

fn ingress_interface_local_resolution(
    state: &ForwardingState,
    ingress_ifindex: i32,
    ingress_vlan_id: u16,
    dst: IpAddr,
) -> Option<ForwardingResolution> {
    let logical_ifindex = resolve_ingress_logical_ifindex(state, ingress_ifindex, ingress_vlan_id)
        .or_else(|| {
            state.egress.iter().find_map(|(ifindex, iface)| {
                ((iface.bind_ifindex == ingress_ifindex || *ifindex == ingress_ifindex)
                    && iface.vlan_id == ingress_vlan_id)
                    .then_some(*ifindex)
            })
        })
        .filter(|ifindex| *ifindex > 0)
        .unwrap_or(ingress_ifindex);
    let iface = state.egress.get(&logical_ifindex)?;
    let matches_local = match dst {
        IpAddr::V4(ip) => iface.primary_v4 == Some(ip),
        IpAddr::V6(ip) => iface.primary_v6 == Some(ip),
    };
    if !matches_local {
        return None;
    }
    Some(ForwardingResolution {
        disposition: ForwardingDisposition::LocalDelivery,
        local_ifindex: logical_ifindex,
        egress_ifindex: logical_ifindex,
        tx_ifindex: logical_ifindex,
        next_hop: None,
        neighbor_mac: None,
        src_mac: None,
        tx_vlan_id: 0,
    })
}

fn ingress_interface_local_resolution_on_session_miss(
    state: &ForwardingState,
    ingress_ifindex: i32,
    ingress_vlan_id: u16,
    dst: IpAddr,
    protocol: u8,
) -> Option<ForwardingResolution> {
    if !matches!(protocol, PROTO_ICMP | PROTO_ICMPV6) {
        return None;
    }
    ingress_interface_local_resolution(state, ingress_ifindex, ingress_vlan_id, dst)
}

fn lookup_forwarding_resolution_v4(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>>,
    ip: Ipv4Addr,
    table: &str,
    depth: usize,
) -> ForwardingResolution {
    if depth >= MAX_NEXT_TABLE_DEPTH {
        return ForwardingResolution {
            disposition: ForwardingDisposition::NextTableUnsupported,
            local_ifindex: 0,
            egress_ifindex: 0,
            tx_ifindex: 0,
            next_hop: Some(IpAddr::V4(ip)),
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        };
    }
    let static_match = state
        .routes_v4
        .get(table)
        .and_then(|routes| routes.iter().find(|entry| entry.prefix.contains(ip)));
    let connected_match = state
        .connected_v4
        .iter()
        .find(|entry| entry.prefix.contains(ip));
    match choose_v4_route(static_match, connected_match) {
        Some(ResolvedRouteV4::Connected { ifindex }) => {
            let neighbor = lookup_neighbor_entry(state, dynamic_neighbors, ifindex, IpAddr::V4(ip));
            let mut resolution = ForwardingResolution {
                disposition: if neighbor.is_some() {
                    ForwardingDisposition::ForwardCandidate
                } else {
                    ForwardingDisposition::MissingNeighbor
                },
                local_ifindex: 0,
                egress_ifindex: ifindex,
                tx_ifindex: ifindex,
                next_hop: Some(IpAddr::V4(ip)),
                neighbor_mac: neighbor.map(|entry| entry.mac),
                src_mac: None,
                tx_vlan_id: 0,
            };
            populate_egress_resolution(state, ifindex, &mut resolution);
            resolution
        }
        Some(ResolvedRouteV4::Static {
            ifindex,
            next_hop,
            discard,
            next_table,
        }) => {
            if discard {
                return ForwardingResolution {
                    disposition: ForwardingDisposition::DiscardRoute,
                    local_ifindex: 0,
                    egress_ifindex: ifindex,
                    tx_ifindex: ifindex,
                    next_hop: next_hop.map(IpAddr::V4),
                    neighbor_mac: None,
                    src_mac: None,
                    tx_vlan_id: 0,
                };
            }
            if let Some(next_table_name) = next_table {
                if next_table_name == table {
                    return ForwardingResolution {
                        disposition: ForwardingDisposition::NextTableUnsupported,
                        local_ifindex: 0,
                        egress_ifindex: 0,
                        tx_ifindex: 0,
                        next_hop: Some(IpAddr::V4(ip)),
                        neighbor_mac: None,
                        src_mac: None,
                        tx_vlan_id: 0,
                    };
                }
                return lookup_forwarding_resolution_v4(
                    state,
                    dynamic_neighbors,
                    ip,
                    &next_table_name,
                    depth + 1,
                );
            }
            if ifindex <= 0 {
                return ForwardingResolution {
                    disposition: ForwardingDisposition::NoRoute,
                    local_ifindex: 0,
                    egress_ifindex: 0,
                    tx_ifindex: 0,
                    next_hop: next_hop.map(IpAddr::V4),
                    neighbor_mac: None,
                    src_mac: None,
                    tx_vlan_id: 0,
                };
            }
            let target = next_hop.unwrap_or(ip);
            let neighbor =
                lookup_neighbor_entry(state, dynamic_neighbors, ifindex, IpAddr::V4(target));
            let mut resolution = ForwardingResolution {
                disposition: if neighbor.is_some() {
                    ForwardingDisposition::ForwardCandidate
                } else {
                    ForwardingDisposition::MissingNeighbor
                },
                local_ifindex: 0,
                egress_ifindex: ifindex,
                tx_ifindex: ifindex,
                next_hop: Some(IpAddr::V4(target)),
                neighbor_mac: neighbor.map(|entry| entry.mac),
                src_mac: None,
                tx_vlan_id: 0,
            };
            populate_egress_resolution(state, ifindex, &mut resolution);
            resolution
        }
        None => ForwardingResolution {
            disposition: ForwardingDisposition::NoRoute,
            local_ifindex: 0,
            egress_ifindex: 0,
            tx_ifindex: 0,
            next_hop: None,
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        },
    }
}

fn lookup_forwarding_resolution_v6(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>>,
    ip: Ipv6Addr,
    table: &str,
    depth: usize,
) -> ForwardingResolution {
    if depth >= MAX_NEXT_TABLE_DEPTH {
        return ForwardingResolution {
            disposition: ForwardingDisposition::NextTableUnsupported,
            local_ifindex: 0,
            egress_ifindex: 0,
            tx_ifindex: 0,
            next_hop: Some(IpAddr::V6(ip)),
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        };
    }
    let static_match = state
        .routes_v6
        .get(table)
        .and_then(|routes| routes.iter().find(|entry| entry.prefix.contains(ip)));
    let connected_match = state
        .connected_v6
        .iter()
        .find(|entry| entry.prefix.contains(ip));
    match choose_v6_route(static_match, connected_match) {
        Some(ResolvedRouteV6::Connected { ifindex }) => {
            let neighbor = lookup_neighbor_entry(state, dynamic_neighbors, ifindex, IpAddr::V6(ip));
            let mut resolution = ForwardingResolution {
                disposition: if neighbor.is_some() {
                    ForwardingDisposition::ForwardCandidate
                } else {
                    ForwardingDisposition::MissingNeighbor
                },
                local_ifindex: 0,
                egress_ifindex: ifindex,
                tx_ifindex: ifindex,
                next_hop: Some(IpAddr::V6(ip)),
                neighbor_mac: neighbor.map(|entry| entry.mac),
                src_mac: None,
                tx_vlan_id: 0,
            };
            populate_egress_resolution(state, ifindex, &mut resolution);
            resolution
        }
        Some(ResolvedRouteV6::Static {
            ifindex,
            next_hop,
            discard,
            next_table,
        }) => {
            if discard {
                return ForwardingResolution {
                    disposition: ForwardingDisposition::DiscardRoute,
                    local_ifindex: 0,
                    egress_ifindex: ifindex,
                    tx_ifindex: ifindex,
                    next_hop: next_hop.map(IpAddr::V6),
                    neighbor_mac: None,
                    src_mac: None,
                    tx_vlan_id: 0,
                };
            }
            if let Some(next_table_name) = next_table {
                if next_table_name == table {
                    return ForwardingResolution {
                        disposition: ForwardingDisposition::NextTableUnsupported,
                        local_ifindex: 0,
                        egress_ifindex: 0,
                        tx_ifindex: 0,
                        next_hop: Some(IpAddr::V6(ip)),
                        neighbor_mac: None,
                        src_mac: None,
                        tx_vlan_id: 0,
                    };
                }
                return lookup_forwarding_resolution_v6(
                    state,
                    dynamic_neighbors,
                    ip,
                    &next_table_name,
                    depth + 1,
                );
            }
            if ifindex <= 0 {
                return ForwardingResolution {
                    disposition: ForwardingDisposition::NoRoute,
                    local_ifindex: 0,
                    egress_ifindex: 0,
                    tx_ifindex: 0,
                    next_hop: next_hop.map(IpAddr::V6),
                    neighbor_mac: None,
                    src_mac: None,
                    tx_vlan_id: 0,
                };
            }
            let target = next_hop.unwrap_or(ip);
            let neighbor =
                lookup_neighbor_entry(state, dynamic_neighbors, ifindex, IpAddr::V6(target));
            let mut resolution = ForwardingResolution {
                disposition: if neighbor.is_some() {
                    ForwardingDisposition::ForwardCandidate
                } else {
                    ForwardingDisposition::MissingNeighbor
                },
                local_ifindex: 0,
                egress_ifindex: ifindex,
                tx_ifindex: ifindex,
                next_hop: Some(IpAddr::V6(target)),
                neighbor_mac: neighbor.map(|entry| entry.mac),
                src_mac: None,
                tx_vlan_id: 0,
            };
            populate_egress_resolution(state, ifindex, &mut resolution);
            resolution
        }
        None => ForwardingResolution {
            disposition: ForwardingDisposition::NoRoute,
            local_ifindex: 0,
            egress_ifindex: 0,
            tx_ifindex: 0,
            next_hop: None,
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        },
    }
}

fn lookup_neighbor_entry(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>>,
    ifindex: i32,
    target: IpAddr,
) -> Option<NeighborEntry> {
    if let Some(entry) = state.neighbors.get(&(ifindex, target)).copied() {
        return Some(entry);
    }
    let Some(dynamic_neighbors) = dynamic_neighbors else {
        return None;
    };
    if let Ok(cache) = dynamic_neighbors.lock() {
        if let Some(entry) = cache.get(&(ifindex, target)).copied() {
            return Some(entry);
        }
    }
    let ifname = state.ifindex_to_name.get(&ifindex)?.clone();
    let entry = refresh_dynamic_neighbor(&ifname, target)?;
    if let Ok(mut cache) = dynamic_neighbors.lock() {
        cache.insert((ifindex, target), entry);
    }
    Some(entry)
}

fn sync_dynamic_neighbors(
    state: &ForwardingState,
    dynamic_neighbors: &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
) {
    let mut updates = Vec::new();
    for (ifindex, iface) in &state.egress {
        let Some(ifname) = state.ifindex_to_name.get(ifindex) else {
            continue;
        };
        updates.extend(
            read_neighbor_entries(ifname)
                .into_iter()
                .map(|(ip, entry)| ((*ifindex, ip), entry)),
        );
        if iface.bind_ifindex > 0 && iface.bind_ifindex != *ifindex {
            updates.extend(
                read_neighbor_entries(ifname)
                    .into_iter()
                    .map(|(ip, entry)| ((iface.bind_ifindex, ip), entry)),
            );
        }
    }
    if updates.is_empty() {
        return;
    }
    if let Ok(mut cache) = dynamic_neighbors.lock() {
        for (key, entry) in updates {
            cache.insert(key, entry);
        }
    }
}

fn refresh_dynamic_neighbor(ifname: &str, target: IpAddr) -> Option<NeighborEntry> {
    if let Some(entry) = read_neighbor_entry(ifname, target) {
        return Some(entry);
    }
    trigger_neighbor_probe(ifname, target);
    read_neighbor_entry(ifname, target)
}

fn read_neighbor_entry(ifname: &str, target: IpAddr) -> Option<NeighborEntry> {
    let family = match target {
        IpAddr::V4(_) => "-4",
        IpAddr::V6(_) => "-6",
    };
    let output = Command::new("ip")
        .args([
            family,
            "neigh",
            "show",
            "to",
            &target.to_string(),
            "dev",
            ifname,
        ])
        .output()
        .ok()?;
    if output.status.success() {
        if let Some(entry) =
            parse_neighbor_output(String::from_utf8_lossy(&output.stdout).as_ref(), target)
        {
            return Some(entry);
        }
    }
    read_neighbor_entries(ifname)
        .into_iter()
        .find_map(|(ip, entry)| if ip == target { Some(entry) } else { None })
}

fn read_neighbor_entries(ifname: &str) -> Vec<(IpAddr, NeighborEntry)> {
    let mut out = Vec::new();
    for family in ["-4", "-6"] {
        let Ok(output) = Command::new("ip")
            .args([family, "neigh", "show", "dev", ifname])
            .output()
        else {
            continue;
        };
        if !output.status.success() {
            continue;
        }
        out.extend(parse_neighbor_entries(
            String::from_utf8_lossy(&output.stdout).as_ref(),
        ));
    }
    out
}

fn trigger_neighbor_probe(ifname: &str, target: IpAddr) {
    let mut cmd = Command::new("ping");
    match target {
        IpAddr::V4(_) => {
            cmd.args([
                "-4",
                "-c",
                "1",
                "-W",
                "1",
                "-I",
                ifname,
                &target.to_string(),
            ]);
        }
        IpAddr::V6(_) => {
            cmd.args([
                "-6",
                "-c",
                "1",
                "-W",
                "1",
                "-I",
                ifname,
                &target.to_string(),
            ]);
        }
    }
    let _ = cmd.output();
}

fn parse_neighbor_output(output: &str, target: IpAddr) -> Option<NeighborEntry> {
    parse_neighbor_entries(output)
        .into_iter()
        .find_map(|(ip, entry)| if ip == target { Some(entry) } else { None })
}

fn parse_neighbor_entries(output: &str) -> Vec<(IpAddr, NeighborEntry)> {
    let mut out = Vec::new();
    for line in output.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.is_empty() {
            continue;
        }
        if fields.iter().any(|field| !neighbor_state_usable(field)) {
            continue;
        }
        let Ok(ip) = fields[0].parse::<IpAddr>() else {
            continue;
        };
        let Some(lladdr) = fields.iter().position(|field| *field == "lladdr") else {
            continue;
        };
        let Some(candidate) = fields.get(lladdr + 1) else {
            continue;
        };
        let Some(mac) = parse_mac(candidate).or_else(|| parse_mac(candidate.trim())) else {
            continue;
        };
        out.push((ip, NeighborEntry { mac }));
    }
    out
}

fn build_injected_packet(
    req: &InjectPacketRequest,
    dst: IpAddr,
    resolution: ForwardingResolution,
    egress: &EgressInterface,
) -> Result<Vec<u8>, String> {
    let dst_mac = resolution
        .neighbor_mac
        .ok_or_else(|| "missing neighbor MAC".to_string())?;
    match dst {
        IpAddr::V4(dst_v4) => build_injected_ipv4(req, dst_mac, dst_v4, egress),
        IpAddr::V6(dst_v6) => build_injected_ipv6(req, dst_mac, dst_v6, egress),
    }
}

/// Build a forwarded frame for NAT64 packets. NAT64 changes the IP address
/// family so the frame size changes (IPv6→IPv4 shrinks by 20, IPv4→IPv6 grows
/// by 20). This always uses a copy path — in-place rewrite is not possible.
fn build_nat64_forwarded_frame(
    frame: &[u8],
    meta: UserspaceDpMeta,
    decision: &SessionDecision,
    nat64_reverse: Option<&Nat64ReverseInfo>,
) -> Option<Vec<u8>> {
    let dst_mac = decision.resolution.neighbor_mac?;
    let src_mac = decision.resolution.src_mac?;
    let vlan_id = decision.resolution.tx_vlan_id;

    match meta.addr_family as i32 {
        libc::AF_INET6 => {
            // Forward direction: IPv6 → IPv4.
            let snat_v4 = match decision.nat.rewrite_src {
                Some(IpAddr::V4(v4)) => v4,
                _ => return None,
            };
            let dst_v4 = match decision.nat.rewrite_dst {
                Some(IpAddr::V4(v4)) => v4,
                _ => return None,
            };
            crate::nat64::build_nat64_v6_to_v4_frame(
                frame, snat_v4, dst_v4, dst_mac, src_mac, vlan_id,
            )
        }
        libc::AF_INET => {
            // Reverse direction: IPv4 → IPv6 (reply from server).
            let info = nat64_reverse?;
            // Reply: src_v6 = original dst (NAT64 prefix + server), dst_v6 = original client
            crate::nat64::build_nat64_v4_to_v6_frame(
                frame, info.orig_dst_v6, info.orig_src_v6, dst_mac, src_mac, vlan_id,
            )
        }
        _ => None,
    }
}

fn build_forwarded_frame_from_frame(
    frame: &[u8],
    meta: UserspaceDpMeta,
    decision: &SessionDecision,
    _forwarding: &ForwardingState,
    expected_ports: Option<(u16, u16)>,
) -> Option<Vec<u8>> {
    let mut out = vec![0u8; frame.len().saturating_add(4)];
    let written =
        build_forwarded_frame_into_from_frame(&mut out, frame, meta, decision, expected_ports)?;
    out.truncate(written);
    Some(out)
}

fn segment_forwarded_tcp_frames_from_frame(
    frame: &[u8],
    meta: UserspaceDpMeta,
    decision: &SessionDecision,
    forwarding: &ForwardingState,
    expected_ports: Option<(u16, u16)>,
) -> Option<Vec<Vec<u8>>> {
    if meta.protocol != PROTO_TCP {
        return None;
    }
    let egress = forwarding
        .egress
        .get(&decision.resolution.egress_ifindex)
        .or_else(|| forwarding.egress.get(&decision.resolution.tx_ifindex))?;
    let mtu = egress.mtu.max(1280);
    let l3 = frame_l3_offset(frame)?;
    if l3 >= frame.len() {
        return None;
    }
    let payload = &frame[l3..];
    if payload.len() <= mtu {
        return None;
    }
    let tcp_offset = frame_l4_offset(frame, meta.addr_family)?.checked_sub(l3)?;
    let (ip_header_len, tcp_offset) = match meta.addr_family as i32 {
        libc::AF_INET => {
            if payload.len() < 20 {
                return None;
            }
            let ihl = ((payload[0] & 0x0f) as usize) * 4;
            if ihl < 20 || payload.len() < ihl + 20 {
                return None;
            }
            (ihl, ihl)
        }
        libc::AF_INET6 => {
            let ip_header_len = tcp_offset;
            if ip_header_len < 40 || payload.len() < ip_header_len + 20 {
                return None;
            }
            (ip_header_len, ip_header_len)
        }
        _ => return None,
    };
    let tcp_header_len = ((payload.get(tcp_offset + 12)? >> 4) as usize) * 4;
    if tcp_header_len < 20 || payload.len() < tcp_offset + tcp_header_len {
        return None;
    }
    let tcp_flags = *payload.get(tcp_offset + 13)?;
    if (tcp_flags & (TCP_FLAG_SYN | TCP_FLAG_FIN | TCP_FLAG_RST)) != 0 {
        return None;
    }
    let segment_payload_max = mtu.checked_sub(ip_header_len + tcp_header_len)?;
    if segment_payload_max == 0 {
        return None;
    }
    let data = payload.get(tcp_offset + tcp_header_len..)?;
    if data.len() <= segment_payload_max {
        return None;
    }

    let dst_mac = decision.resolution.neighbor_mac?;
    let (src_mac, vlan_id, apply_nat) =
        if decision.resolution.disposition == ForwardingDisposition::FabricRedirect {
            (
                decision.resolution.src_mac?,
                decision.resolution.tx_vlan_id,
                false,
            )
        } else {
            (
                decision.resolution.src_mac?,
                decision.resolution.tx_vlan_id,
                true,
            )
        };
    let eth_len = if vlan_id > 0 { 18 } else { 14 };
    let ether_type = match meta.addr_family as i32 {
        libc::AF_INET => 0x0800,
        libc::AF_INET6 => 0x86dd,
        _ => return None,
    };
    let original_seq = u32::from_be_bytes([
        *payload.get(tcp_offset + 4)?,
        *payload.get(tcp_offset + 5)?,
        *payload.get(tcp_offset + 6)?,
        *payload.get(tcp_offset + 7)?,
    ]);
    let enforced_ports = expected_ports.or(live_frame_ports_bytes(
        frame,
        meta.addr_family,
        meta.protocol,
    ));
    let tcp_header = payload.get(tcp_offset..tcp_offset + tcp_header_len)?;
    let ip_header = payload.get(..ip_header_len)?;
    let mut out = Vec::with_capacity((data.len() / segment_payload_max) + 1);
    let mut data_offset = 0usize;
    while data_offset < data.len() {
        let chunk_len = (data.len() - data_offset).min(segment_payload_max);
        let is_last = data_offset + chunk_len == data.len();
        let total_ip_len = ip_header_len + tcp_header_len + chunk_len;
        let mut frame_out = vec![0u8; eth_len + total_ip_len];
        write_eth_header_slice(
            frame_out.get_mut(..eth_len)?,
            dst_mac,
            src_mac,
            vlan_id,
            ether_type,
        )?;
        {
            let packet = frame_out.get_mut(eth_len..)?;
            packet.get_mut(..ip_header_len)?.copy_from_slice(ip_header);
            packet
                .get_mut(ip_header_len..ip_header_len + tcp_header_len)?
                .copy_from_slice(tcp_header);
            packet
                .get_mut(ip_header_len + tcp_header_len..total_ip_len)?
                .copy_from_slice(data.get(data_offset..data_offset + chunk_len)?);

            let tcp = packet.get_mut(tcp_offset..)?;
            let seq = original_seq.wrapping_add(data_offset as u32);
            tcp.get_mut(4..8)?.copy_from_slice(&seq.to_be_bytes());
            if !is_last {
                tcp[13] &= !TCP_FLAG_PSH;
            }
        }

        match meta.addr_family as i32 {
            libc::AF_INET => {
                {
                    let packet = frame_out.get_mut(eth_len..)?;
                    packet
                        .get_mut(2..4)?
                        .copy_from_slice(&(total_ip_len as u16).to_be_bytes());
                    if packet[8] <= 1 {
                        return None;
                    }
                    if apply_nat {
                        apply_nat_ipv4(packet, meta.protocol, decision.nat)?;
                    }
                    packet[8] -= 1;
                }
                let _ = enforce_expected_ports(
                    &mut frame_out,
                    meta.addr_family,
                    meta.protocol,
                    enforced_ports,
                )?;
                let packet = frame_out.get_mut(eth_len..)?;
                packet.get_mut(10..12)?.copy_from_slice(&[0, 0]);
                let ip_sum = checksum16(packet.get(..ip_header_len)?);
                packet
                    .get_mut(10..12)?
                    .copy_from_slice(&ip_sum.to_be_bytes());
                recompute_l4_checksum_ipv4(packet, ip_header_len, meta.protocol, false)?;
            }
            libc::AF_INET6 => {
                {
                    let packet = frame_out.get_mut(eth_len..)?;
                    packet
                        .get_mut(4..6)?
                        .copy_from_slice(&((tcp_header_len + chunk_len) as u16).to_be_bytes());
                    if packet[7] <= 1 {
                        return None;
                    }
                    if apply_nat {
                        apply_nat_ipv6(packet, meta.protocol, decision.nat)?;
                    }
                    packet[7] -= 1;
                }
                let _ = enforce_expected_ports(
                    &mut frame_out,
                    meta.addr_family,
                    meta.protocol,
                    enforced_ports,
                )?;
                let packet = frame_out.get_mut(eth_len..)?;
                recompute_l4_checksum_ipv6(packet, meta.protocol)?;
            }
            _ => return None,
        }
        out.push(frame_out);
        data_offset += chunk_len;
    }
    Some(out)
}

fn build_forwarded_frame_into_from_frame(
    out: &mut [u8],
    frame: &[u8],
    meta: UserspaceDpMeta,
    decision: &SessionDecision,
    expected_ports: Option<(u16, u16)>,
) -> Option<usize> {
    let dst_mac = decision.resolution.neighbor_mac?;
    let enforced_ports = expected_ports;
    // Use meta L3 offset when it's a valid Ethernet header size (14 or 18),
    // otherwise re-derive from the frame's ethertype.
    let l3 = match meta.l3_offset {
        14 | 18 => meta.l3_offset as usize,
        _ => frame_l3_offset(frame)?,
    };
    if l3 >= frame.len() {
        return None;
    }
    let raw_payload = &frame[l3..];
    // Trim Ethernet padding: use ip_total_len so we don't carry trailing
    // pad bytes (small frames padded to 60/64 by hardware).
    let payload = if raw_payload.len() >= 4 {
        let ip_version = raw_payload[0] >> 4;
        if ip_version == 4 {
            let ip_total_len =
                u16::from_be_bytes([raw_payload[2], raw_payload[3]]) as usize;
            if ip_total_len > 0 && ip_total_len < raw_payload.len() {
                &raw_payload[..ip_total_len]
            } else {
                raw_payload
            }
        } else if ip_version == 6 && raw_payload.len() >= 40 {
            let ipv6_payload_len =
                u16::from_be_bytes([raw_payload[4], raw_payload[5]]) as usize;
            let ip6_total = 40 + ipv6_payload_len;
            if ip6_total > 0 && ip6_total < raw_payload.len() {
                &raw_payload[..ip6_total]
            } else {
                raw_payload
            }
        } else {
            raw_payload
        }
    } else {
        raw_payload
    };
    let (src_mac, vlan_id, apply_nat) =
        if decision.resolution.disposition == ForwardingDisposition::FabricRedirect {
            (
                decision.resolution.src_mac?,
                decision.resolution.tx_vlan_id,
                false,
            )
        } else {
            (
                decision.resolution.src_mac?,
                decision.resolution.tx_vlan_id,
                true,
            )
        };
    let eth_len = if vlan_id > 0 { 18 } else { 14 };
    let ether_type = match meta.addr_family as i32 {
        libc::AF_INET => 0x0800,
        libc::AF_INET6 => 0x86dd,
        _ => return None,
    };
    let frame_len = eth_len + payload.len();
    if frame_len > out.len() {
        return None;
    }
    write_eth_header_slice(
        out.get_mut(..eth_len)?,
        dst_mac,
        src_mac,
        vlan_id,
        ether_type,
    )?;
    out.get_mut(eth_len..frame_len)?.copy_from_slice(payload);
    let out = &mut out[..frame_len];
    let ip_start = eth_len;
    match meta.addr_family as i32 {
        libc::AF_INET => {
            if out.len() < ip_start + 20 {
                return None;
            }
            let ihl = ((out[ip_start] & 0x0f) as usize) * 4;
            if ihl < 20 || out.len() < ip_start + ihl {
                return None;
            }
            if out[ip_start + 8] <= 1 {
                return None;
            }
            let old_src = Ipv4Addr::new(
                out[ip_start + 12],
                out[ip_start + 13],
                out[ip_start + 14],
                out[ip_start + 15],
            );
            let old_dst = Ipv4Addr::new(
                out[ip_start + 16],
                out[ip_start + 17],
                out[ip_start + 18],
                out[ip_start + 19],
            );
            let old_ttl = out[ip_start + 8];
            // IHL already computed above — use directly instead of re-parsing.
            let rel_l4 = ihl;
            let repaired_ports =
                restore_l4_tuple_from_meta(&mut out[ip_start..], meta, rel_l4).unwrap_or(false);
            if apply_nat {
                apply_nat_ipv4(&mut out[ip_start..], meta.protocol, decision.nat)?;
            }
            out[ip_start + 8] -= 1;
            let enforced =
                enforce_expected_ports_at(out, ip_start, ip_start + rel_l4, meta.addr_family, meta.protocol, enforced_ports)
                    .unwrap_or(false);
            adjust_ipv4_header_checksum(
                &mut out[ip_start..ip_start + ihl],
                old_src,
                old_dst,
                old_ttl,
            )?;
            if repaired_ports && !enforced {
                recompute_l4_checksum_ipv4(&mut out[ip_start..], ihl, meta.protocol, true)?;
            }
        }
        libc::AF_INET6 => {
            if out.len() < ip_start + 40 {
                return None;
            }
            if out[ip_start + 7] <= 1 {
                return None;
            }
            // Use meta-derived L4 offset when valid (>= 40 for IPv6 base header,
            // avoids walking extension headers). Fall back to parsing otherwise.
            let meta_rel = meta.l4_offset.wrapping_sub(meta.l3_offset) as usize;
            let rel_l4 = if meta_rel >= 40 && meta.l4_offset > meta.l3_offset {
                meta_rel
            } else {
                packet_rel_l4_offset(&out[ip_start..], meta.addr_family)?
            };
            let repaired_ports =
                restore_l4_tuple_from_meta(&mut out[ip_start..], meta, rel_l4).unwrap_or(false);
            if apply_nat {
                apply_nat_ipv6(&mut out[ip_start..], meta.protocol, decision.nat)?;
            }
            out[ip_start + 7] -= 1;
            let enforced =
                enforce_expected_ports_at(out, ip_start, ip_start + rel_l4, meta.addr_family, meta.protocol, enforced_ports)
                    .unwrap_or(false);
            if repaired_ports && !enforced {
                recompute_l4_checksum_ipv6(&mut out[ip_start..], meta.protocol)?;
            }
        }
        _ => return None,
    }
    // Debug: dump first N built frames' Ethernet + IP headers to see post-NAT on wire
    if cfg!(feature = "debug-log") {
        thread_local! {
            static BUILD_FWD_DBG_COUNT: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
        }
        BUILD_FWD_DBG_COUNT.with(|c| {
            let n = c.get();
            if n < 30 {
                c.set(n + 1);
                let pkt_detail = decode_frame_summary(out);
                eprintln!(
                    "DBG BUILT_ETH[{}]: vlan={} frame_len={} proto={} {}",
                    n, vlan_id, frame_len, meta.protocol, pkt_detail,
                );
                // For the first 3 frames, also dump the full IP+TCP header hex
                if n < 3 {
                    let dump_len = frame_len.min(out.len()).min(eth_len + 60);
                    let hex: String = out[..dump_len].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
                    eprintln!("DBG BUILT_HEX[{n}]: {hex}");
                }
            }
        });
    }
    // Checksum verification: recompute from scratch and compare to incremental update.
    if cfg!(feature = "debug-log") {
        verify_built_frame_checksums(&out[..frame_len]);
    }

    // RST corruption check: detect if frame building introduced a TCP RST
    // that wasn't in the source frame.
    if cfg!(feature = "debug-log") {
        let out_has_rst = frame_has_tcp_rst(&out[..frame_len]);
        let in_has_rst = frame_has_tcp_rst(frame);
        if out_has_rst && !in_has_rst {
            thread_local! {
                static BUILD_RST_CORRUPT_COUNT: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
            }
            BUILD_RST_CORRUPT_COUNT.with(|c| {
                let n = c.get();
                if n < 20 {
                    c.set(n + 1);
                    let in_summary = decode_frame_summary(frame);
                    let out_summary = decode_frame_summary(&out[..frame_len]);
                    eprintln!(
                        "RST_CORRUPT BUILD[{}]: frame build INTRODUCED RST! in=[{}] out=[{}]",
                        n, in_summary, out_summary,
                    );
                    let in_hex_len = frame.len().min(80);
                    let in_hex: String = frame[..in_hex_len].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
                    let out_hex_len = frame_len.min(out.len()).min(80);
                    let out_hex: String = out[..out_hex_len].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
                    eprintln!("RST_CORRUPT IN_HEX[{n}]: {in_hex}");
                    eprintln!("RST_CORRUPT OUT_HEX[{n}]: {out_hex}");
                }
            });
        }
    }
    Some(frame_len)
}

fn build_forwarded_frame(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    decision: &SessionDecision,
    forwarding: &ForwardingState,
    expected_ports: Option<(u16, u16)>,
) -> Option<Vec<u8>> {
    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
    build_forwarded_frame_from_frame(frame, meta, decision, forwarding, expected_ports)
}

fn segment_forwarded_tcp_frames(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    decision: &SessionDecision,
    forwarding: &ForwardingState,
    expected_ports: Option<(u16, u16)>,
) -> Option<Vec<Vec<u8>>> {
    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
    segment_forwarded_tcp_frames_from_frame(frame, meta, decision, forwarding, expected_ports)
}

fn build_forwarded_frame_into(
    out: &mut [u8],
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    decision: &SessionDecision,
    expected_ports: Option<(u16, u16)>,
) -> Option<usize> {
    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
    build_forwarded_frame_into_from_frame(out, frame, meta, decision, expected_ports)
}

fn rewrite_forwarded_frame_in_place(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    decision: &SessionDecision,
    expected_ports: Option<(u16, u16)>,
) -> Option<u32> {
    let dst_mac = decision.resolution.neighbor_mac?;
    let enforced_ports = expected_ports;
    let frame = unsafe { area.slice_mut_unchecked(desc.addr as usize, UMEM_FRAME_SIZE as usize)? };
    let current_len = desc.len as usize;
    let l3 = match meta.l3_offset {
        14 | 18 => meta.l3_offset as usize,
        _ => frame_l3_offset(&frame[..current_len])?,
    };
    if l3 >= current_len {
        return None;
    }
    let mut payload_len = current_len.checked_sub(l3)?;
    // Trim Ethernet padding: use ip_total_len when available so we don't
    // carry trailing pad bytes (small frames padded to 60/64 by hardware).
    if payload_len >= 4 {
        let ip_version = frame[l3] >> 4;
        if ip_version == 4 {
            let ip_total_len =
                u16::from_be_bytes([frame[l3 + 2], frame[l3 + 3]]) as usize;
            if ip_total_len > 0 && ip_total_len < payload_len {
                payload_len = ip_total_len;
            }
        } else if ip_version == 6 && payload_len >= 40 {
            let ipv6_payload_len =
                u16::from_be_bytes([frame[l3 + 4], frame[l3 + 5]]) as usize;
            let ip6_total = 40 + ipv6_payload_len;
            if ip6_total > 0 && ip6_total < payload_len {
                payload_len = ip6_total;
            }
        }
    }
    let (src_mac, vlan_id, apply_nat) =
        if decision.resolution.disposition == ForwardingDisposition::FabricRedirect {
            (
                decision.resolution.src_mac?,
                decision.resolution.tx_vlan_id,
                false,
            )
        } else {
            (
                decision.resolution.src_mac?,
                decision.resolution.tx_vlan_id,
                true,
            )
        };
    let eth_len = if vlan_id > 0 { 18usize } else { 14usize };
    let ether_type = match meta.addr_family as i32 {
        libc::AF_INET => 0x0800,
        libc::AF_INET6 => 0x86dd,
        _ => return None,
    };
    let frame_len = eth_len.checked_add(payload_len)?;
    if frame_len > frame.len() {
        return None;
    }
    if eth_len != l3 {
        frame.copy_within(l3..l3 + payload_len, eth_len);
    }
    write_eth_header_slice(
        frame.get_mut(..eth_len)?,
        dst_mac,
        src_mac,
        vlan_id,
        ether_type,
    )?;
    let packet = &mut frame[..frame_len];
    let ip_start = eth_len;
    match meta.addr_family as i32 {
        libc::AF_INET => {
            if packet.len() < ip_start + 20 {
                return None;
            }
            let ihl = ((packet[ip_start] & 0x0f) as usize) * 4;
            if ihl < 20 || packet.len() < ip_start + ihl {
                return None;
            }
            if packet[ip_start + 8] <= 1 {
                return None;
            }
            let old_src = Ipv4Addr::new(
                packet[ip_start + 12],
                packet[ip_start + 13],
                packet[ip_start + 14],
                packet[ip_start + 15],
            );
            let old_dst = Ipv4Addr::new(
                packet[ip_start + 16],
                packet[ip_start + 17],
                packet[ip_start + 18],
                packet[ip_start + 19],
            );
            let old_ttl = packet[ip_start + 8];
            let rel_l4 = ihl;
            let repaired_ports =
                restore_l4_tuple_from_meta(&mut packet[ip_start..], meta, rel_l4).unwrap_or(false);
            if apply_nat {
                apply_nat_ipv4(&mut packet[ip_start..], meta.protocol, decision.nat)?;
            }
            packet[ip_start + 8] -= 1;
            adjust_ipv4_header_checksum(
                &mut packet[ip_start..ip_start + ihl],
                old_src,
                old_dst,
                old_ttl,
            )?;
            let enforced =
                enforce_expected_ports(packet, meta.addr_family, meta.protocol, enforced_ports)
                    .unwrap_or(false);
            if repaired_ports && !enforced {
                recompute_l4_checksum_ipv4(&mut packet[ip_start..], ihl, meta.protocol, true)?;
            }
        }
        libc::AF_INET6 => {
            if packet.len() < ip_start + 40 {
                return None;
            }
            if packet[ip_start + 7] <= 1 {
                return None;
            }
            let meta_rel = meta.l4_offset.wrapping_sub(meta.l3_offset) as usize;
            let rel_l4 = if meta_rel >= 40 && meta.l4_offset > meta.l3_offset {
                meta_rel
            } else {
                packet_rel_l4_offset(&packet[ip_start..], meta.addr_family)?
            };
            let repaired_ports =
                restore_l4_tuple_from_meta(&mut packet[ip_start..], meta, rel_l4).unwrap_or(false);
            if apply_nat {
                apply_nat_ipv6(&mut packet[ip_start..], meta.protocol, decision.nat)?;
            }
            packet[ip_start + 7] -= 1;
            let enforced =
                enforce_expected_ports(packet, meta.addr_family, meta.protocol, enforced_ports)
                    .unwrap_or(false);
            if repaired_ports && !enforced {
                recompute_l4_checksum_ipv6(&mut packet[ip_start..], meta.protocol)?;
            }
        }
        _ => return None,
    }
    // Debug: dump first N in-place rewritten frames' Ethernet headers
    if cfg!(feature = "debug-log") {
        thread_local! {
            static INPLACE_FWD_DBG_COUNT: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
        }
        INPLACE_FWD_DBG_COUNT.with(|c| {
            let n = c.get();
            if n < 10 {
                c.set(n + 1);
                let hdr_len = eth_len.min(packet.len()).min(22);
                let hdr_hex: String = packet[..hdr_len].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
                let ip_info = if meta.addr_family as i32 == libc::AF_INET && packet.len() >= ip_start + 20 {
                    format!("src={}.{}.{}.{} dst={}.{}.{}.{}",
                        packet[ip_start+12], packet[ip_start+13], packet[ip_start+14], packet[ip_start+15],
                        packet[ip_start+16], packet[ip_start+17], packet[ip_start+18], packet[ip_start+19])
                } else if meta.addr_family as i32 == libc::AF_INET6 && packet.len() >= ip_start + 40 {
                    let s = &packet[ip_start+8..ip_start+24];
                    let d = &packet[ip_start+24..ip_start+40];
                    format!("src={:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x} dst={:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                        s[0],s[1],s[2],s[3],s[4],s[5],s[6],s[7],s[8],s[9],s[10],s[11],s[12],s[13],s[14],s[15],
                        d[0],d[1],d[2],d[3],d[4],d[5],d[6],d[7],d[8],d[9],d[10],d[11],d[12],d[13],d[14],d[15])
                } else {
                    "unknown-af".to_string()
                };
                eprintln!(
                    "DBG INPLACE_ETH[{}]: eth=[{}] vlan={} frame_len={} proto={} {}",
                    n, hdr_hex, vlan_id, frame_len, meta.protocol, ip_info,
                );
            }
        });
    }
    // Checksum verification for in-place path.
    if cfg!(feature = "debug-log") {
        verify_built_frame_checksums(&packet[..frame_len]);
    }
    Some(frame_len as u32)
}

fn apply_nat_ipv4(packet: &mut [u8], protocol: u8, nat: NatDecision) -> Option<()> {
    if nat == NatDecision::default() {
        return Some(());
    }
    if packet.len() < 20 {
        return None;
    }
    let old_src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let old_dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let new_src = nat.rewrite_src.and_then(|ip| match ip {
        IpAddr::V4(ip) => Some(ip),
        _ => None,
    });
    let new_dst = nat.rewrite_dst.and_then(|ip| match ip {
        IpAddr::V4(ip) => Some(ip),
        _ => None,
    });
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < 20 || packet.len() < ihl {
        return None;
    }

    // --- IP address rewriting ---
    if new_src.is_some() && new_dst.is_none() {
        let new_src = new_src?;
        packet.get_mut(12..16)?.copy_from_slice(&new_src.octets());
        adjust_l4_checksum_ipv4_src(packet, ihl, protocol, old_src, new_src)?;
    } else if new_dst.is_some() && new_src.is_none() {
        let new_dst = new_dst?;
        packet.get_mut(16..20)?.copy_from_slice(&new_dst.octets());
        adjust_l4_checksum_ipv4_dst(packet, ihl, protocol, old_dst, new_dst)?;
    } else if new_src.is_some() || new_dst.is_some() {
        if let Some(ip) = new_src {
            packet.get_mut(12..16)?.copy_from_slice(&ip.octets());
        }
        if let Some(ip) = new_dst {
            packet.get_mut(16..20)?.copy_from_slice(&ip.octets());
        }
        let new_src = new_src.unwrap_or(old_src);
        let new_dst = new_dst.unwrap_or(old_dst);
        match protocol {
            PROTO_TCP => {
                adjust_l4_checksum_ipv4(packet, ihl, protocol, old_src, new_src, old_dst, new_dst)?
            }
            PROTO_UDP => {
                let checksum_offset = ihl.checked_add(6)?;
                let keep_zero = packet
                    .get(checksum_offset..checksum_offset + 2)
                    .map(|bytes| bytes == [0, 0])
                    .unwrap_or(false);
                if !keep_zero {
                    adjust_l4_checksum_ipv4(packet, ihl, protocol, old_src, new_src, old_dst, new_dst)?;
                }
            }
            _ => {}
        }
    }

    // --- L4 port rewriting (after IP rewriting) ---
    apply_nat_port_rewrite(packet, ihl, protocol, nat)?;

    Some(())
}

fn apply_nat_ipv6(packet: &mut [u8], protocol: u8, nat: NatDecision) -> Option<()> {
    if nat == NatDecision::default() {
        return Some(());
    }
    if packet.len() < 40 {
        return None;
    }
    let new_src = nat.rewrite_src.and_then(|ip| match ip {
        IpAddr::V6(ip) => Some(ip.octets()),
        _ => None,
    });
    let new_dst = nat.rewrite_dst.and_then(|ip| match ip {
        IpAddr::V6(ip) => Some(ip.octets()),
        _ => None,
    });

    // NPTv6 (RFC 6296): prefix translation is checksum-neutral by design --
    // the adjustment word preserves the ones-complement sum of the full address.
    // Skip L4 checksum updates entirely for NPTv6 rewrites.
    let skip_l4_csum = nat.nptv6;
    if new_src.is_some() && new_dst.is_none() {
        let new_src = new_src?;
        let old_src_words = ipv6_words_from_slice(packet.get(8..24)?)?;
        packet.get_mut(8..24)?.copy_from_slice(&new_src);
        if !skip_l4_csum {
            let new_src_words = ipv6_words_from_octets(new_src);
            adjust_l4_checksum_ipv6_words(packet, protocol, &old_src_words, &new_src_words)?;
        }
    } else if new_dst.is_some() && new_src.is_none() {
        let new_dst = new_dst?;
        let old_dst_words = ipv6_words_from_slice(packet.get(24..40)?)?;
        packet.get_mut(24..40)?.copy_from_slice(&new_dst);
        if !skip_l4_csum {
            let new_dst_words = ipv6_words_from_octets(new_dst);
            adjust_l4_checksum_ipv6_words(packet, protocol, &old_dst_words, &new_dst_words)?;
        }
    } else if new_src.is_some() || new_dst.is_some() {
        let old_src_words = ipv6_words_from_slice(packet.get(8..24)?)?;
        let old_dst_words = ipv6_words_from_slice(packet.get(24..40)?)?;
        if let Some(ip) = new_src {
            packet.get_mut(8..24)?.copy_from_slice(&ip);
        }
        if let Some(ip) = new_dst {
            packet.get_mut(24..40)?.copy_from_slice(&ip);
        }
        if !skip_l4_csum {
            let new_src_words = new_src.map(ipv6_words_from_octets).unwrap_or(old_src_words);
            let new_dst_words = new_dst.map(ipv6_words_from_octets).unwrap_or(old_dst_words);
            match protocol {
                PROTO_TCP | PROTO_UDP | PROTO_ICMPV6 => {
                    adjust_l4_checksum_ipv6_words(packet, protocol, &old_src_words, &new_src_words)?;
                    adjust_l4_checksum_ipv6_words(packet, protocol, &old_dst_words, &new_dst_words)?;
                }
                _ => {}
            }
        }
    }

    // --- L4 port rewriting (after IP rewriting) ---
    // IPv6 header is always 40 bytes (no IHL).
    apply_nat_port_rewrite(packet, 40, protocol, nat)?;

    Some(())
}

/// Rewrite L4 source/destination ports and incrementally update the L4 checksum.
/// Port rewriting MUST happen AFTER IP address rewriting to avoid double-counting
/// in the checksum. Skips ICMP (no ports).
fn apply_nat_port_rewrite(
    packet: &mut [u8],
    l4_offset: usize,
    protocol: u8,
    nat: NatDecision,
) -> Option<()> {
    if !matches!(protocol, PROTO_TCP | PROTO_UDP) {
        return Some(());
    }
    if packet.len() < l4_offset + 4 {
        return Some(());
    }

    if let Some(new_src_port) = nat.rewrite_src_port {
        let port_offset = l4_offset; // TCP/UDP src port at offset +0
        let old_port = u16::from_be_bytes([packet[port_offset], packet[port_offset + 1]]);
        if old_port != new_src_port {
            packet[port_offset..port_offset + 2].copy_from_slice(&new_src_port.to_be_bytes());
            adjust_l4_checksum_port(packet, l4_offset, protocol, old_port, new_src_port)?;
        }
    }

    if let Some(new_dst_port) = nat.rewrite_dst_port {
        let port_offset = l4_offset + 2; // TCP/UDP dst port at offset +2
        let old_port = u16::from_be_bytes([packet[port_offset], packet[port_offset + 1]]);
        if old_port != new_dst_port {
            packet[port_offset..port_offset + 2].copy_from_slice(&new_dst_port.to_be_bytes());
            adjust_l4_checksum_port(packet, l4_offset, protocol, old_port, new_dst_port)?;
        }
    }

    Some(())
}

/// Incremental L4 checksum update for a single 16-bit port change.
fn adjust_l4_checksum_port(
    packet: &mut [u8],
    l4_offset: usize,
    protocol: u8,
    old_port: u16,
    new_port: u16,
) -> Option<()> {
    let checksum_offset = match protocol {
        PROTO_TCP => l4_offset.checked_add(16)?,
        PROTO_UDP => l4_offset.checked_add(6)?,
        _ => return Some(()),
    };
    let current = u16::from_be_bytes([
        *packet.get(checksum_offset)?,
        *packet.get(checksum_offset + 1)?,
    ]);
    // Skip UDP IPv4 checksum update when checksum is 0 (optional for IPv4 UDP)
    if matches!(protocol, PROTO_UDP) && current == 0 {
        return Some(());
    }
    let mut updated = checksum16_adjust(current, &[old_port], &[new_port]);
    if matches!(protocol, PROTO_UDP) && updated == 0 {
        updated = 0xffff;
    }
    packet
        .get_mut(checksum_offset..checksum_offset + 2)?
        .copy_from_slice(&updated.to_be_bytes());
    Some(())
}

fn enforce_expected_ports(
    frame: &mut [u8],
    addr_family: u8,
    protocol: u8,
    expected_ports: Option<(u16, u16)>,
) -> Option<bool> {
    let Some((expected_src, expected_dst)) = expected_ports else {
        return Some(false);
    };
    if !matches!(protocol, PROTO_TCP | PROTO_UDP) {
        return Some(false);
    }
    let l3 = frame_l3_offset(frame)?;
    let l4 = frame_l4_offset(frame, addr_family)?;
    let ports = frame.get(l4..l4 + 4)?;
    let current_src = u16::from_be_bytes([ports[0], ports[1]]);
    let current_dst = u16::from_be_bytes([ports[2], ports[3]]);
    if current_src == expected_src && current_dst == expected_dst {
        return Some(false);
    }
    frame
        .get_mut(l4..l4 + 2)?
        .copy_from_slice(&expected_src.to_be_bytes());
    frame
        .get_mut(l4 + 2..l4 + 4)?
        .copy_from_slice(&expected_dst.to_be_bytes());
    match addr_family as i32 {
        libc::AF_INET => {
            let packet = frame.get_mut(l3..)?;
            let ihl = packet_rel_l4_offset(packet, addr_family)?;
            recompute_l4_checksum_ipv4(packet, ihl, protocol, true)?;
        }
        libc::AF_INET6 => {
            let packet = frame.get_mut(l3..)?;
            recompute_l4_checksum_ipv6(packet, protocol)?;
        }
        _ => return Some(false),
    }
    Some(true)
}

/// Like enforce_expected_ports, but takes pre-computed L3/L4 offsets to avoid
/// redundant header parsing in the hot path.
#[inline]
fn enforce_expected_ports_at(
    frame: &mut [u8],
    l3: usize,
    l4: usize,
    addr_family: u8,
    protocol: u8,
    expected_ports: Option<(u16, u16)>,
) -> Option<bool> {
    let Some((expected_src, expected_dst)) = expected_ports else {
        return Some(false);
    };
    if !matches!(protocol, PROTO_TCP | PROTO_UDP) {
        return Some(false);
    }
    let ports = frame.get(l4..l4 + 4)?;
    let current_src = u16::from_be_bytes([ports[0], ports[1]]);
    let current_dst = u16::from_be_bytes([ports[2], ports[3]]);
    if current_src == expected_src && current_dst == expected_dst {
        return Some(false);
    }
    frame
        .get_mut(l4..l4 + 2)?
        .copy_from_slice(&expected_src.to_be_bytes());
    frame
        .get_mut(l4 + 2..l4 + 4)?
        .copy_from_slice(&expected_dst.to_be_bytes());
    match addr_family as i32 {
        libc::AF_INET => {
            let packet = frame.get_mut(l3..)?;
            let ihl = packet_rel_l4_offset(packet, addr_family)?;
            recompute_l4_checksum_ipv4(packet, ihl, protocol, true)?;
        }
        libc::AF_INET6 => {
            let packet = frame.get_mut(l3..)?;
            recompute_l4_checksum_ipv6(packet, protocol)?;
        }
        _ => return Some(false),
    }
    Some(true)
}

fn restore_l4_tuple_from_meta(
    packet: &mut [u8],
    meta: UserspaceDpMeta,
    rel_l4: usize,
) -> Option<bool> {
    match meta.protocol {
        PROTO_TCP | PROTO_UDP => Some(false),
        PROTO_ICMP | PROTO_ICMPV6 => {
            let ident = packet.get_mut(rel_l4 + 4..rel_l4 + 6)?;
            let expected = meta.flow_src_port.to_be_bytes();
            let repaired = *ident != expected;
            if repaired {
                ident.copy_from_slice(&expected);
            }
            Some(repaired)
        }
        _ => Some(false),
    }
}

fn build_injected_ipv4(
    req: &InjectPacketRequest,
    dst_mac: [u8; 6],
    dst_ip: Ipv4Addr,
    egress: &EgressInterface,
) -> Result<Vec<u8>, String> {
    let src_ip = egress
        .primary_v4
        .ok_or_else(|| "egress interface has no IPv4 source address".to_string())?;
    let eth_len = if egress.vlan_id > 0 { 18 } else { 14 };
    let min_total = eth_len + 20 + 8 + 16;
    let target_len = req.packet_length.max(min_total as u32) as usize;
    let payload_len = target_len.saturating_sub(eth_len + 20 + 8);

    let mut frame = Vec::with_capacity(target_len);
    write_eth_header(&mut frame, dst_mac, egress.src_mac, egress.vlan_id, 0x0800);

    let total_len = (20 + 8 + payload_len) as u16;
    let ip_start = frame.len();
    frame.extend_from_slice(&[
        0x45,
        0x00,
        (total_len >> 8) as u8,
        total_len as u8,
        0x00,
        0x01,
        0x00,
        0x00,
        64,
        1,
        0,
        0,
    ]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    let ip_sum = checksum16(&frame[ip_start..ip_start + 20]);
    frame[ip_start + 10] = (ip_sum >> 8) as u8;
    frame[ip_start + 11] = ip_sum as u8;

    let icmp_start = frame.len();
    frame.extend_from_slice(&[8, 0, 0, 0]);
    frame.extend_from_slice(&(req.slot as u16).to_be_bytes());
    frame.extend_from_slice(&1u16.to_be_bytes());
    for i in 0..payload_len {
        frame.push((i & 0xff) as u8);
    }
    let icmp_sum = checksum16(&frame[icmp_start..]);
    frame[icmp_start + 2] = (icmp_sum >> 8) as u8;
    frame[icmp_start + 3] = icmp_sum as u8;
    Ok(frame)
}

fn build_injected_ipv6(
    req: &InjectPacketRequest,
    dst_mac: [u8; 6],
    dst_ip: Ipv6Addr,
    egress: &EgressInterface,
) -> Result<Vec<u8>, String> {
    let src_ip = egress
        .primary_v6
        .ok_or_else(|| "egress interface has no IPv6 source address".to_string())?;
    let eth_len = if egress.vlan_id > 0 { 18 } else { 14 };
    let min_total = eth_len + 40 + 8 + 16;
    let target_len = req.packet_length.max(min_total as u32) as usize;
    let payload_len = target_len.saturating_sub(eth_len + 40 + 8);

    let mut frame = Vec::with_capacity(target_len);
    write_eth_header(&mut frame, dst_mac, egress.src_mac, egress.vlan_id, 0x86dd);
    let plen = (8 + payload_len) as u16;
    frame.extend_from_slice(&[
        0x60,
        0x00,
        0x00,
        0x00,
        (plen >> 8) as u8,
        plen as u8,
        58,
        64,
    ]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());

    let icmp_start = frame.len();
    frame.extend_from_slice(&[128, 0, 0, 0]);
    frame.extend_from_slice(&(req.slot as u16).to_be_bytes());
    frame.extend_from_slice(&1u16.to_be_bytes());
    for i in 0..payload_len {
        frame.push((i & 0xff) as u8);
    }
    let icmp_sum = checksum16_ipv6(src_ip, dst_ip, PROTO_ICMPV6, &frame[icmp_start..]);
    frame[icmp_start + 2] = (icmp_sum >> 8) as u8;
    frame[icmp_start + 3] = icmp_sum as u8;
    Ok(frame)
}

fn write_eth_header(buf: &mut Vec<u8>, dst: [u8; 6], src: [u8; 6], vlan_id: u16, ether_type: u16) {
    buf.extend_from_slice(&dst);
    buf.extend_from_slice(&src);
    if vlan_id > 0 {
        buf.extend_from_slice(&0x8100u16.to_be_bytes());
        buf.extend_from_slice(&(vlan_id & 0x0fff).to_be_bytes());
    }
    buf.extend_from_slice(&ether_type.to_be_bytes());
}

fn write_eth_header_slice(
    buf: &mut [u8],
    dst: [u8; 6],
    src: [u8; 6],
    vlan_id: u16,
    ether_type: u16,
) -> Option<()> {
    let eth_len = if vlan_id > 0 { 18 } else { 14 };
    if buf.len() < eth_len {
        return None;
    }
    buf.get_mut(0..6)?.copy_from_slice(&dst);
    buf.get_mut(6..12)?.copy_from_slice(&src);
    if vlan_id > 0 {
        buf.get_mut(12..14)?
            .copy_from_slice(&0x8100u16.to_be_bytes());
        buf.get_mut(14..16)?
            .copy_from_slice(&(vlan_id & 0x0fff).to_be_bytes());
        buf.get_mut(16..18)?
            .copy_from_slice(&ether_type.to_be_bytes());
    } else {
        buf.get_mut(12..14)?
            .copy_from_slice(&ether_type.to_be_bytes());
    }
    Some(())
}

fn checksum16(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(last) = chunks.remainder().first() {
        sum += (*last as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn checksum16_finish(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn checksum16_adjust(checksum: u16, old_words: &[u16], new_words: &[u16]) -> u16 {
    let mut sum = (!checksum as u32) & 0xffff;
    for word in old_words {
        sum += (!u32::from(*word)) & 0xffff;
    }
    for word in new_words {
        sum += u32::from(*word);
    }
    checksum16_finish(sum)
}

fn ipv4_words(ip: Ipv4Addr) -> [u16; 2] {
    let octets = ip.octets();
    [
        u16::from_be_bytes([octets[0], octets[1]]),
        u16::from_be_bytes([octets[2], octets[3]]),
    ]
}

fn ipv6_words(ip: Ipv6Addr) -> [u16; 8] {
    ipv6_words_from_octets(ip.octets())
}

fn ipv6_words_from_octets(octets: [u8; 16]) -> [u16; 8] {
    [
        u16::from_be_bytes([octets[0], octets[1]]),
        u16::from_be_bytes([octets[2], octets[3]]),
        u16::from_be_bytes([octets[4], octets[5]]),
        u16::from_be_bytes([octets[6], octets[7]]),
        u16::from_be_bytes([octets[8], octets[9]]),
        u16::from_be_bytes([octets[10], octets[11]]),
        u16::from_be_bytes([octets[12], octets[13]]),
        u16::from_be_bytes([octets[14], octets[15]]),
    ]
}

fn ipv6_words_from_slice(bytes: &[u8]) -> Option<[u16; 8]> {
    let octets: [u8; 16] = bytes.get(..16)?.try_into().ok()?;
    Some(ipv6_words_from_octets(octets))
}

fn adjust_ipv4_header_checksum(
    packet: &mut [u8],
    old_src: Ipv4Addr,
    old_dst: Ipv4Addr,
    old_ttl: u8,
) -> Option<()> {
    if packet.len() < 20 {
        return None;
    }
    let current = u16::from_be_bytes([packet[10], packet[11]]);
    let new_src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let new_dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let old_ttl_word = u16::from_be_bytes([old_ttl, packet[9]]);
    let new_ttl_word = u16::from_be_bytes([packet[8], packet[9]]);
    let mut updated = checksum16_adjust(current, &ipv4_words(old_src), &ipv4_words(new_src));
    updated = checksum16_adjust(updated, &ipv4_words(old_dst), &ipv4_words(new_dst));
    updated = checksum16_adjust(updated, &[old_ttl_word], &[new_ttl_word]);
    packet
        .get_mut(10..12)?
        .copy_from_slice(&updated.to_be_bytes());
    Some(())
}

fn checksum16_ipv6(src: Ipv6Addr, dst: Ipv6Addr, next_header: u8, payload: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + payload.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, next_header]);
    pseudo.extend_from_slice(payload);
    checksum16(&pseudo)
}

fn checksum16_ipv4(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, payload: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + payload.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(protocol);
    pseudo.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(payload);
    checksum16(&pseudo)
}

fn adjust_l4_checksum_ipv4(
    packet: &mut [u8],
    ihl: usize,
    protocol: u8,
    old_src: Ipv4Addr,
    new_src: Ipv4Addr,
    old_dst: Ipv4Addr,
    new_dst: Ipv4Addr,
) -> Option<()> {
    let checksum_offset = match protocol {
        PROTO_TCP => ihl.checked_add(16)?,
        PROTO_UDP => ihl.checked_add(6)?,
        _ => return Some(()),
    };
    let current = u16::from_be_bytes([
        *packet.get(checksum_offset)?,
        *packet.get(checksum_offset + 1)?,
    ]);
    let mut updated = checksum16_adjust(current, &ipv4_words(old_src), &ipv4_words(new_src));
    updated = checksum16_adjust(updated, &ipv4_words(old_dst), &ipv4_words(new_dst));
    if matches!(protocol, PROTO_UDP) && updated == 0 {
        updated = 0xffff;
    }
    packet
        .get_mut(checksum_offset..checksum_offset + 2)?
        .copy_from_slice(&updated.to_be_bytes());
    Some(())
}

fn adjust_l4_checksum_ipv6(
    packet: &mut [u8],
    protocol: u8,
    old_src: Ipv6Addr,
    new_src: Ipv6Addr,
    old_dst: Ipv6Addr,
    new_dst: Ipv6Addr,
) -> Option<()> {
    let checksum_offset = match protocol {
        PROTO_TCP => 40usize.checked_add(16)?,
        PROTO_UDP | PROTO_ICMPV6 => 40usize.checked_add(6)?,
        _ => return Some(()),
    };
    let current = u16::from_be_bytes([
        *packet.get(checksum_offset)?,
        *packet.get(checksum_offset + 1)?,
    ]);
    let mut updated = checksum16_adjust(current, &ipv6_words(old_src), &ipv6_words(new_src));
    updated = checksum16_adjust(updated, &ipv6_words(old_dst), &ipv6_words(new_dst));
    if matches!(protocol, PROTO_UDP | PROTO_ICMPV6) && updated == 0 {
        updated = 0xffff;
    }
    packet
        .get_mut(checksum_offset..checksum_offset + 2)?
        .copy_from_slice(&updated.to_be_bytes());
    Some(())
}

fn adjust_l4_checksum_ipv4_src(
    packet: &mut [u8],
    ihl: usize,
    protocol: u8,
    old_src: Ipv4Addr,
    new_src: Ipv4Addr,
) -> Option<()> {
    adjust_l4_checksum_ipv4_words(
        packet,
        ihl,
        protocol,
        &ipv4_words(old_src),
        &ipv4_words(new_src),
    )
}

fn adjust_l4_checksum_ipv4_dst(
    packet: &mut [u8],
    ihl: usize,
    protocol: u8,
    old_dst: Ipv4Addr,
    new_dst: Ipv4Addr,
) -> Option<()> {
    adjust_l4_checksum_ipv4_words(
        packet,
        ihl,
        protocol,
        &ipv4_words(old_dst),
        &ipv4_words(new_dst),
    )
}

fn adjust_l4_checksum_ipv4_words(
    packet: &mut [u8],
    ihl: usize,
    protocol: u8,
    old_words: &[u16],
    new_words: &[u16],
) -> Option<()> {
    let checksum_offset = match protocol {
        PROTO_TCP => ihl.checked_add(16)?,
        PROTO_UDP => ihl.checked_add(6)?,
        _ => return Some(()),
    };
    let current = u16::from_be_bytes([
        *packet.get(checksum_offset)?,
        *packet.get(checksum_offset + 1)?,
    ]);
    if matches!(protocol, PROTO_UDP) && current == 0 {
        return Some(());
    }
    let updated = checksum16_adjust(current, old_words, new_words);
    let updated = if matches!(protocol, PROTO_UDP) && updated == 0 {
        0xffff
    } else {
        updated
    };
    packet
        .get_mut(checksum_offset..checksum_offset + 2)?
        .copy_from_slice(&updated.to_be_bytes());
    Some(())
}

fn adjust_l4_checksum_ipv6_src(
    packet: &mut [u8],
    protocol: u8,
    old_src: Ipv6Addr,
    new_src: Ipv6Addr,
) -> Option<()> {
    adjust_l4_checksum_ipv6_words(packet, protocol, &ipv6_words(old_src), &ipv6_words(new_src))
}

fn adjust_l4_checksum_ipv6_dst(
    packet: &mut [u8],
    protocol: u8,
    old_dst: Ipv6Addr,
    new_dst: Ipv6Addr,
) -> Option<()> {
    adjust_l4_checksum_ipv6_words(packet, protocol, &ipv6_words(old_dst), &ipv6_words(new_dst))
}

fn adjust_l4_checksum_ipv6_words(
    packet: &mut [u8],
    protocol: u8,
    old_words: &[u16],
    new_words: &[u16],
) -> Option<()> {
    let checksum_offset = match protocol {
        PROTO_TCP => 40usize.checked_add(16)?,
        PROTO_UDP | PROTO_ICMPV6 => 40usize.checked_add(6)?,
        _ => return Some(()),
    };
    let current = u16::from_be_bytes([
        *packet.get(checksum_offset)?,
        *packet.get(checksum_offset + 1)?,
    ]);
    let mut updated = checksum16_adjust(current, old_words, new_words);
    if matches!(protocol, PROTO_UDP | PROTO_ICMPV6) && updated == 0 {
        updated = 0xffff;
    }
    packet
        .get_mut(checksum_offset..checksum_offset + 2)?
        .copy_from_slice(&updated.to_be_bytes());
    Some(())
}

fn recompute_l4_checksum_ipv4(
    packet: &mut [u8],
    ihl: usize,
    protocol: u8,
    zero_offset: bool,
) -> Option<()> {
    let segment = packet.get(ihl..)?;
    match protocol {
        PROTO_TCP => {
            if segment.len() < 20 {
                return None;
            }
            packet.get_mut(ihl + 16..ihl + 18)?.copy_from_slice(&[0, 0]);
            let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
            let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
            let sum = checksum16_ipv4(src, dst, protocol, packet.get(ihl..)?);
            packet
                .get_mut(ihl + 16..ihl + 18)?
                .copy_from_slice(&sum.to_be_bytes());
        }
        PROTO_UDP => {
            if segment.len() < 8 {
                return None;
            }
            packet.get_mut(ihl + 6..ihl + 8)?.copy_from_slice(&[0, 0]);
            let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
            let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
            let sum = checksum16_ipv4(src, dst, protocol, packet.get(ihl..)?);
            let sum = if zero_offset && sum == 0 { 0xffff } else { sum };
            packet
                .get_mut(ihl + 6..ihl + 8)?
                .copy_from_slice(&sum.to_be_bytes());
        }
        _ => {}
    }
    Some(())
}

fn recompute_l4_checksum_ipv6(packet: &mut [u8], protocol: u8) -> Option<()> {
    let payload = packet.get(40..)?;
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(packet.get(8..24)?).ok()?);
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(packet.get(24..40)?).ok()?);
    match protocol {
        PROTO_TCP => {
            if payload.len() < 20 {
                return None;
            }
            packet.get_mut(40 + 16..40 + 18)?.copy_from_slice(&[0, 0]);
            let sum = checksum16_ipv6(src, dst, PROTO_TCP, packet.get(40..)?);
            packet
                .get_mut(40 + 16..40 + 18)?
                .copy_from_slice(&sum.to_be_bytes());
        }
        PROTO_UDP => {
            if payload.len() < 8 {
                return None;
            }
            packet.get_mut(40 + 6..40 + 8)?.copy_from_slice(&[0, 0]);
            let sum = checksum16_ipv6(src, dst, PROTO_UDP, packet.get(40..)?);
            let sum = if sum == 0 { 0xffff } else { sum };
            packet
                .get_mut(40 + 6..40 + 8)?
                .copy_from_slice(&sum.to_be_bytes());
        }
        PROTO_ICMPV6 => {
            if payload.len() < 4 {
                return None;
            }
            packet.get_mut(40 + 2..40 + 4)?.copy_from_slice(&[0, 0]);
            let sum = checksum16_ipv6(src, dst, PROTO_ICMPV6, packet.get(40..)?);
            packet
                .get_mut(40 + 2..40 + 4)?
                .copy_from_slice(&sum.to_be_bytes());
        }
        _ => {}
    }
    Some(())
}

/// Verify IP + TCP/UDP checksums on a fully-built forwarded frame.
/// Returns (ip_ok, l4_ok). Logs mismatches for the first N frames.
static CSUM_VERIFIED_TOTAL: AtomicU64 = AtomicU64::new(0);
static CSUM_BAD_IP_TOTAL: AtomicU64 = AtomicU64::new(0);
static CSUM_BAD_L4_TOTAL: AtomicU64 = AtomicU64::new(0);

fn verify_built_frame_checksums(frame: &[u8]) -> (bool, bool) {
    let l3 = match frame_l3_offset(frame) {
        Some(o) => o,
        None => return (true, true),
    };
    let packet = match frame.get(l3..) {
        Some(p) if p.len() >= 20 => p,
        _ => return (true, true),
    };
    // Only handle IPv4 TCP for now (main traffic under test).
    if (packet[0] >> 4) != 4 {
        return (true, true);
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < 20 || packet.len() < ihl {
        return (true, true);
    }
    let protocol = packet[9];
    // --- IP header checksum verification ---
    let ip_header = match packet.get(..ihl) {
        Some(h) => h,
        None => return (true, true),
    };
    let ip_csum_in_frame = u16::from_be_bytes([ip_header[10], ip_header[11]]);
    // Compute from scratch: zero out checksum field, compute, compare.
    let mut ip_scratch = [0u8; 60]; // max IHL = 60
    let scratch = &mut ip_scratch[..ihl];
    scratch.copy_from_slice(ip_header);
    scratch[10] = 0;
    scratch[11] = 0;
    let expected_ip_csum = checksum16(scratch);
    let ip_ok = ip_csum_in_frame == expected_ip_csum;

    // --- IP total length consistency ---
    let ip_total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    let actual_l3_len = packet.len();
    if ip_total_len != actual_l3_len {
        thread_local! {
            static IP_LEN_MISMATCH_LOG: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
        }
        IP_LEN_MISMATCH_LOG.with(|c| {
            let n = c.get();
            if n < 20 {
                c.set(n + 1);
                let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
                let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
                eprintln!(
                    "IP_LEN_MISMATCH[{}]: ip_total_len={} actual_l3_len={} frame_len={} l3={} src={} dst={} proto={}",
                    n, ip_total_len, actual_l3_len, frame.len(), l3, src, dst, protocol,
                );
            }
        });
    }

    // --- L4 checksum verification (TCP or UDP) ---
    // Use ip_total_len to bound the L4 segment — Ethernet padding bytes beyond
    // ip_total_len must NOT be included in the checksum pseudo-header or payload.
    let l4_len = if ip_total_len > ihl { ip_total_len - ihl } else { 0 };
    let l4_ok = if protocol == PROTO_TCP {
        let segment = match packet.get(ihl..ihl + l4_len) {
            Some(s) if s.len() >= 20 => s,
            _ => return (ip_ok, true),
        };
        let tcp_csum_in_frame = u16::from_be_bytes([segment[16], segment[17]]);
        let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
        let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
        // Build pseudo-header + TCP with checksum zeroed.
        let mut pseudo = Vec::with_capacity(12 + segment.len());
        pseudo.extend_from_slice(&src.octets());
        pseudo.extend_from_slice(&dst.octets());
        pseudo.push(0);
        pseudo.push(PROTO_TCP);
        pseudo.extend_from_slice(&(segment.len() as u16).to_be_bytes());
        pseudo.extend_from_slice(segment);
        // Zero the checksum field in pseudo buffer (offset 12 + 16 = 28..30).
        let csum_off = 12 + 16;
        if pseudo.len() > csum_off + 1 {
            pseudo[csum_off] = 0;
            pseudo[csum_off + 1] = 0;
        }
        let expected_tcp_csum = checksum16(&pseudo);
        tcp_csum_in_frame == expected_tcp_csum
    } else if protocol == PROTO_UDP {
        let segment = match packet.get(ihl..ihl + l4_len) {
            Some(s) if s.len() >= 8 => s,
            _ => return (ip_ok, true),
        };
        let udp_csum_in_frame = u16::from_be_bytes([segment[6], segment[7]]);
        if udp_csum_in_frame == 0 {
            true // zero = no checksum
        } else {
            let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
            let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
            let mut pseudo = Vec::with_capacity(12 + segment.len());
            pseudo.extend_from_slice(&src.octets());
            pseudo.extend_from_slice(&dst.octets());
            pseudo.push(0);
            pseudo.push(PROTO_UDP);
            pseudo.extend_from_slice(&(segment.len() as u16).to_be_bytes());
            pseudo.extend_from_slice(segment);
            let csum_off = 12 + 6;
            if pseudo.len() > csum_off + 1 {
                pseudo[csum_off] = 0;
                pseudo[csum_off + 1] = 0;
            }
            let expected_udp_csum = checksum16(&pseudo);
            let expected_udp_csum = if expected_udp_csum == 0 { 0xffff } else { expected_udp_csum };
            udp_csum_in_frame == expected_udp_csum
        }
    } else {
        true
    };

    CSUM_VERIFIED_TOTAL.fetch_add(1, Ordering::Relaxed);
    if !ip_ok {
        CSUM_BAD_IP_TOTAL.fetch_add(1, Ordering::Relaxed);
    }
    if !l4_ok {
        CSUM_BAD_L4_TOTAL.fetch_add(1, Ordering::Relaxed);
    }

    thread_local! {
        static CSUM_VERIFY_COUNT: std::cell::Cell<(u64, u64)> = const { std::cell::Cell::new((0, 0)) };
    }
    if !ip_ok || !l4_ok {
        CSUM_VERIFY_COUNT.with(|c| {
            let (total_bad, logged) = c.get();
            c.set((total_bad + 1, logged));
            if logged < 30 {
                c.set((total_bad + 1, logged + 1));
                let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
                let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
                eprintln!(
                    "CSUM_BAD[{}]: ip_ok={} l4_ok={} proto={} ip_in={:#06x} ip_exp={:#06x} \
                     src={} dst={} frame_len={} l3={} ihl={}",
                    total_bad, ip_ok, l4_ok, protocol,
                    ip_csum_in_frame, expected_ip_csum,
                    src, dst, frame.len(), l3, ihl,
                );
                if !l4_ok && protocol == PROTO_TCP {
                    let segment = &packet[ihl..];
                    let tcp_csum = u16::from_be_bytes([segment[16], segment[17]]);
                    let tcp_src = u16::from_be_bytes([segment[0], segment[1]]);
                    let tcp_dst = u16::from_be_bytes([segment[2], segment[3]]);
                    // Recompute to show expected
                    let mut pseudo = Vec::with_capacity(12 + segment.len());
                    pseudo.extend_from_slice(&src.octets());
                    pseudo.extend_from_slice(&dst.octets());
                    pseudo.push(0);
                    pseudo.push(PROTO_TCP);
                    pseudo.extend_from_slice(&(segment.len() as u16).to_be_bytes());
                    pseudo.extend_from_slice(segment);
                    pseudo[12 + 16] = 0;
                    pseudo[12 + 17] = 0;
                    let expected = checksum16(&pseudo);
                    eprintln!(
                        "CSUM_BAD_TCP[{}]: sport={} dport={} csum_in={:#06x} csum_exp={:#06x} seg_len={}",
                        total_bad, tcp_src, tcp_dst, tcp_csum, expected, segment.len(),
                    );
                    // Hex dump of first 60 bytes of frame for deep debug
                    if logged < 5 {
                        let hex_len = frame.len().min(80);
                        let hex: String = frame[..hex_len].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
                        eprintln!("CSUM_BAD_HEX[{}]: {}", total_bad, hex);
                    }
                }
            }
        });
    }
    (ip_ok, l4_ok)
}

enum ResolvedRouteV4 {
    Connected {
        ifindex: i32,
    },
    Static {
        ifindex: i32,
        next_hop: Option<Ipv4Addr>,
        discard: bool,
        next_table: Option<String>,
    },
}

enum ResolvedRouteV6 {
    Connected {
        ifindex: i32,
    },
    Static {
        ifindex: i32,
        next_hop: Option<Ipv6Addr>,
        discard: bool,
        next_table: Option<String>,
    },
}

fn choose_v4_route(
    static_match: Option<&RouteEntryV4>,
    connected_match: Option<&ConnectedRouteV4>,
) -> Option<ResolvedRouteV4> {
    match (static_match, connected_match) {
        (Some(route), Some(conn)) if conn.prefix.prefix_len() >= route.prefix.prefix_len() => {
            Some(ResolvedRouteV4::Connected {
                ifindex: conn.ifindex,
            })
        }
        (Some(route), _) => Some(ResolvedRouteV4::Static {
            ifindex: route.ifindex,
            next_hop: route.next_hop,
            discard: route.discard,
            next_table: if route.next_table.is_empty() {
                None
            } else {
                Some(route.next_table.clone())
            },
        }),
        (None, Some(conn)) => Some(ResolvedRouteV4::Connected {
            ifindex: conn.ifindex,
        }),
        (None, None) => None,
    }
}

fn choose_v6_route(
    static_match: Option<&RouteEntryV6>,
    connected_match: Option<&ConnectedRouteV6>,
) -> Option<ResolvedRouteV6> {
    match (static_match, connected_match) {
        (Some(route), Some(conn)) if conn.prefix.prefix_len() >= route.prefix.prefix_len() => {
            Some(ResolvedRouteV6::Connected {
                ifindex: conn.ifindex,
            })
        }
        (Some(route), _) => Some(ResolvedRouteV6::Static {
            ifindex: route.ifindex,
            next_hop: route.next_hop,
            discard: route.discard,
            next_table: if route.next_table.is_empty() {
                None
            } else {
                Some(route.next_table.clone())
            },
        }),
        (None, Some(conn)) => Some(ResolvedRouteV6::Connected {
            ifindex: conn.ifindex,
        }),
        (None, None) => None,
    }
}

fn try_parse_metadata(area: &MmapArea, desc: XdpDesc) -> Option<UserspaceDpMeta> {
    let meta_len = std::mem::size_of::<UserspaceDpMeta>();
    if (desc.addr as usize) < meta_len {
        return None;
    }
    let meta_offset = (desc.addr as usize).checked_sub(meta_len)?;
    let bytes = area.slice(meta_offset, meta_len)?;
    let meta = unsafe { *(bytes.as_ptr() as *const UserspaceDpMeta) };
    if meta.magic != USERSPACE_META_MAGIC || meta.version != USERSPACE_META_VERSION {
        return None;
    }
    if meta.length as usize != meta_len {
        return None;
    }
    Some(meta)
}

/// Read raw RX ring producer/consumer and fill ring producer/consumer directly
/// from the kernel's shared memory, bypassing xdpilone's caching. Uses a
/// separate getsockopt + mmap to independently verify the ring state.
/// Raw ring state: (rxP, rxC, frP, frC, txP, txC, crP, crC)
fn diagnose_raw_ring_state(sock_fd: c_int) -> Option<(u32, u32, u32, u32, u32, u32, u32, u32)> {
    // SOL_XDP = 283, XDP_MMAP_OFFSETS = 1
    const SOL_XDP: i32 = 283;
    const XDP_MMAP_OFFSETS: i32 = 1;
    const XDP_PGOFF_RX_RING: i64 = 0;
    const XDP_PGOFF_TX_RING: i64 = 0x80000000;
    const XDP_UMEM_PGOFF_FILL_RING: i64 = 0x100000000;
    const XDP_UMEM_PGOFF_COMPLETION_RING: i64 = 0x180000000;

    // xdp_mmap_offsets_v2 (kernel >= 5.4): 4 rings × 4 fields × u64 each
    #[repr(C)]
    #[derive(Default)]
    struct XdpRingOffset {
        producer: u64,
        consumer: u64,
        desc: u64,
        flags: u64,
    }
    #[repr(C)]
    #[derive(Default)]
    struct XdpMmapOffsets {
        rx: XdpRingOffset,
        tx: XdpRingOffset,
        fr: XdpRingOffset,
        cr: XdpRingOffset,
    }

    let mut off = XdpMmapOffsets::default();
    let mut optlen = core::mem::size_of::<XdpMmapOffsets>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            sock_fd,
            SOL_XDP,
            XDP_MMAP_OFFSETS,
            (&mut off as *mut XdpMmapOffsets).cast::<libc::c_void>(),
            &mut optlen,
        )
    };
    if rc != 0 {
        return None;
    }

    fn read_ring_pair(sock_fd: c_int, off: &XdpRingOffset, pgoff: i64) -> (u32, u32) {
        let map_len = (off.desc.max(off.consumer).max(off.producer) + 8) as usize;
        let mmap_ptr = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                map_len,
                libc::PROT_READ,
                libc::MAP_SHARED,
                sock_fd,
                pgoff,
            )
        };
        if mmap_ptr == libc::MAP_FAILED {
            return (0, 0);
        }
        let prod = unsafe { *(mmap_ptr.byte_add(off.producer as usize) as *const u32) };
        let cons = unsafe { *(mmap_ptr.byte_add(off.consumer as usize) as *const u32) };
        unsafe { libc::munmap(mmap_ptr, map_len) };
        (prod, cons)
    }

    let (rx_prod, rx_cons) = read_ring_pair(sock_fd, &off.rx, XDP_PGOFF_RX_RING);
    let (fr_prod, fr_cons) = read_ring_pair(sock_fd, &off.fr, XDP_UMEM_PGOFF_FILL_RING);
    let (tx_prod, tx_cons) = read_ring_pair(sock_fd, &off.tx, XDP_PGOFF_TX_RING);
    let (cr_prod, cr_cons) = read_ring_pair(sock_fd, &off.cr, XDP_UMEM_PGOFF_COMPLETION_RING);

    Some((rx_prod, rx_cons, fr_prod, fr_cons, tx_prod, tx_cons, cr_prod, cr_cons))
}

fn register_xsk_slot(map_fd: c_int, slot: u32, sock_fd: c_int) -> io::Result<()> {
    let rc = unsafe {
        libbpf_sys::bpf_map_update_elem(
            map_fd,
            (&slot as *const u32).cast::<c_void>(),
            (&sock_fd as *const c_int).cast::<c_void>(),
            libbpf_sys::BPF_ANY as u64,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn update_heartbeat_slot(map_fd: c_int, slot: u32, timestamp_ns: u64) -> io::Result<()> {
    let rc = unsafe {
        libbpf_sys::bpf_map_update_elem(
            map_fd,
            (&slot as *const u32).cast::<c_void>(),
            (&timestamp_ns as *const u64).cast::<c_void>(),
            libbpf_sys::BPF_ANY as u64,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn delete_xsk_slot(map_fd: c_int, slot: u32) -> io::Result<()> {
    let rc =
        unsafe { libbpf_sys::bpf_map_delete_elem(map_fd, (&slot as *const u32).cast::<c_void>()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn delete_heartbeat_slot(map_fd: c_int, slot: u32) -> io::Result<()> {
    let rc =
        unsafe { libbpf_sys::bpf_map_delete_elem(map_fd, (&slot as *const u32).cast::<c_void>()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn maybe_touch_heartbeat(binding: &mut BindingWorker, now_ns: u64) {
    let age_ns = now_ns.saturating_sub(binding.last_heartbeat_update_ns);
    if age_ns < HEARTBEAT_UPDATE_INTERVAL_NS {
        return;
    }
    match touch_heartbeat(
        binding.heartbeat_map_fd,
        binding.slot,
        &binding.live,
        now_ns,
    ) {
        Ok(()) => {
            if cfg!(feature = "debug-log") {
                thread_local! {
                    static HB_LOG_COUNT: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
                }
                let age_ms = age_ns / 1_000_000;
                if age_ms > 1000 {
                    eprintln!(
                        "HB_UPDATE slot={} fd={} age={}ms now_ns={} LATE",
                        binding.slot, binding.heartbeat_map_fd, age_ms, now_ns,
                    );
                }
                HB_LOG_COUNT.with(|c| {
                    let n = c.get();
                    if n < 5 {
                        c.set(n + 1);
                        eprintln!(
                            "HB_UPDATE[{}] slot={} fd={} age={}ms now_ns={} OK",
                            n, binding.slot, binding.heartbeat_map_fd, age_ms, now_ns,
                        );
                    }
                });
            }
            binding.last_heartbeat_update_ns = now_ns;
        }
        Err(err) => {
            eprintln!(
                "HB_UPDATE_ERR slot={} fd={} age={}ms err={}",
                binding.slot, binding.heartbeat_map_fd, age_ns / 1_000_000, err,
            );
            binding.live.set_error(format!("update heartbeat slot: {err}"));
        }
    }
}

fn touch_heartbeat(
    map_fd: c_int,
    slot: u32,
    live: &BindingLiveState,
    now_ns: u64,
) -> io::Result<()> {
    update_heartbeat_slot(map_fd, slot, now_ns)?;
    live.set_last_heartbeat_at(now_ns);
    Ok(())
}

fn heartbeat_fresh(last_heartbeat: Option<chrono::DateTime<Utc>>) -> bool {
    match last_heartbeat {
        Some(last) => Utc::now()
            .signed_duration_since(last)
            .to_std()
            .map(|age| age <= HEARTBEAT_STALE_AFTER)
            .unwrap_or(true),
        None => false,
    }
}

struct OwnedFd {
    fd: c_int,
}

impl OwnedFd {
    fn open_bpf_map(path: &str) -> io::Result<Self> {
        let path = CString::new(path)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid map path"))?;
        let fd = unsafe { libbpf_sys::bpf_obj_get(path.as_ptr()) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd })
    }
}

impl Drop for OwnedFd {
    fn drop(&mut self) {
        let _ = unsafe { libc::close(self.fd) };
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct UserspaceSessionMapKey {
    addr_family: u8,
    protocol: u8,
    pad: u16,
    src_port: u16,
    dst_port: u16,
    src_addr: [u8; 16],
    dst_addr: [u8; 16],
}

fn session_map_key(key: &SessionKey) -> UserspaceSessionMapKey {
    fn encode_ip(ip: &IpAddr) -> [u8; 16] {
        match ip {
            IpAddr::V4(v4) => {
                let mut out = [0u8; 16];
                out[..4].copy_from_slice(&v4.octets());
                out
            }
            IpAddr::V6(v6) => v6.octets(),
        }
    }
    UserspaceSessionMapKey {
        addr_family: key.addr_family,
        protocol: key.protocol,
        pad: 0,
        src_port: key.src_port,
        dst_port: key.dst_port,
        src_addr: encode_ip(&key.src_ip),
        dst_addr: encode_ip(&key.dst_ip),
    }
}

fn publish_live_session_key(map_fd: c_int, key: &SessionKey) -> io::Result<()> {
    let map_key = session_map_key(key);
    let value = 1u8;
    let rc = unsafe {
        libbpf_sys::bpf_map_update_elem(
            map_fd,
            (&map_key as *const UserspaceSessionMapKey).cast::<c_void>(),
            (&value as *const u8).cast::<c_void>(),
            libbpf_sys::BPF_ANY as u64,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Verify a session key exists in the BPF map (read-back after publish).
fn verify_session_key_in_bpf(map_fd: c_int, key: &SessionKey) -> bool {
    let map_key = session_map_key(key);
    let mut value = 0u8;
    let rc = unsafe {
        libbpf_sys::bpf_map_lookup_elem(
            map_fd,
            (&map_key as *const UserspaceSessionMapKey).cast::<c_void>(),
            (&mut value as *mut u8).cast::<c_void>(),
        )
    };
    rc == 0
}

/// Count total entries in the BPF USERSPACE_SESSIONS map.
fn count_bpf_session_entries(map_fd: c_int) -> u32 {
    let mut count = 0u32;
    let key_size = core::mem::size_of::<UserspaceSessionMapKey>();
    let mut key = vec![0u8; key_size];
    let mut next_key = vec![0u8; key_size];
    // First key
    let rc = unsafe {
        libbpf_sys::bpf_map_get_next_key(
            map_fd,
            core::ptr::null(),
            next_key.as_mut_ptr().cast::<c_void>(),
        )
    };
    if rc != 0 {
        return 0;
    }
    count += 1;
    key.copy_from_slice(&next_key);
    loop {
        let rc = unsafe {
            libbpf_sys::bpf_map_get_next_key(
                map_fd,
                key.as_ptr().cast::<c_void>(),
                next_key.as_mut_ptr().cast::<c_void>(),
            )
        };
        if rc != 0 {
            break;
        }
        count += 1;
        key.copy_from_slice(&next_key);
        if count > 10000 {
            break; // safety limit
        }
    }
    count
}

/// Dump first N entries from the BPF USERSPACE_SESSIONS map for debugging.
fn dump_bpf_session_entries(map_fd: c_int, max_entries: u32) {
    let key_size = core::mem::size_of::<UserspaceSessionMapKey>();
    let mut key_bytes = vec![0u8; key_size];
    let mut next_key_bytes = vec![0u8; key_size];
    let mut value = 0u8;
    let mut count = 0u32;
    // First key
    let rc = unsafe {
        libbpf_sys::bpf_map_get_next_key(
            map_fd,
            core::ptr::null(),
            next_key_bytes.as_mut_ptr().cast::<c_void>(),
        )
    };
    if rc != 0 {
        eprintln!("BPF_MAP_DUMP: empty (no entries)");
        return;
    }
    loop {
        // Read the key as UserspaceSessionMapKey
        let map_key: UserspaceSessionMapKey =
            unsafe { core::ptr::read(next_key_bytes.as_ptr().cast()) };
        let _ = unsafe {
            libbpf_sys::bpf_map_lookup_elem(
                map_fd,
                next_key_bytes.as_ptr().cast::<c_void>(),
                (&mut value as *mut u8).cast::<c_void>(),
            )
        };
        let src_ip = if map_key.addr_family == libc::AF_INET as u8 {
            format!(
                "{}.{}.{}.{}",
                map_key.src_addr[0], map_key.src_addr[1],
                map_key.src_addr[2], map_key.src_addr[3]
            )
        } else {
            format!("v6[{:02x}{:02x}::{:02x}{:02x}]",
                map_key.src_addr[0], map_key.src_addr[1],
                map_key.src_addr[14], map_key.src_addr[15])
        };
        let dst_ip = if map_key.addr_family == libc::AF_INET as u8 {
            format!(
                "{}.{}.{}.{}",
                map_key.dst_addr[0], map_key.dst_addr[1],
                map_key.dst_addr[2], map_key.dst_addr[3]
            )
        } else {
            format!("v6[{:02x}{:02x}::{:02x}{:02x}]",
                map_key.dst_addr[0], map_key.dst_addr[1],
                map_key.dst_addr[14], map_key.dst_addr[15])
        };
        eprintln!(
            "BPF_MAP_DUMP[{}]: af={} proto={} {}:{} -> {}:{} val={}",
            count, map_key.addr_family, map_key.protocol,
            src_ip, map_key.src_port, dst_ip, map_key.dst_port, value,
        );
        count += 1;
        if count >= max_entries {
            break;
        }
        key_bytes.copy_from_slice(&next_key_bytes);
        let rc = unsafe {
            libbpf_sys::bpf_map_get_next_key(
                map_fd,
                key_bytes.as_ptr().cast::<c_void>(),
                next_key_bytes.as_mut_ptr().cast::<c_void>(),
            )
        };
        if rc != 0 {
            break;
        }
    }
    eprintln!("BPF_MAP_DUMP: total={count} entries");
}

static SESSION_PUBLISH_VERIFY_OK: AtomicU64 = AtomicU64::new(0);
static SESSION_PUBLISH_VERIFY_FAIL: AtomicU64 = AtomicU64::new(0);
static SESSION_CREATIONS_LOGGED: AtomicU64 = AtomicU64::new(0);

const FALLBACK_STATS_PIN_PATH: &str = "/sys/fs/bpf/bpfrx/userspace_fallback_stats";
const FALLBACK_REASON_NAMES: &[&str] = &[
    "ctrl_disabled",    // 0
    "parse_fail",       // 1
    "binding_missing",  // 2
    "binding_not_ready",// 3
    "hb_missing",       // 4
    "hb_stale",         // 5
    "icmp",             // 6
    "early_filter",     // 7
    "adjust_meta",      // 8
    "meta_bounds",      // 9
    "redirect_err",     // 10
    "iface_nat_no_sess",// 11
    "no_session",       // 12
];

fn read_fallback_stats() -> Option<Vec<(String, u64)>> {
    let fd = OwnedFd::open_bpf_map(FALLBACK_STATS_PIN_PATH).ok()?;
    let mut result = Vec::new();
    for idx in 0u32..16 {
        let mut value = 0u64;
        let rc = unsafe {
            libbpf_sys::bpf_map_lookup_elem(
                fd.fd,
                (&idx as *const u32).cast::<c_void>(),
                (&mut value as *mut u64).cast::<c_void>(),
            )
        };
        if rc == 0 && value > 0 {
            let name = FALLBACK_REASON_NAMES
                .get(idx as usize)
                .copied()
                .unwrap_or("unknown");
            result.push((name.to_string(), value));
        }
    }
    Some(result)
}

fn delete_live_session_key(map_fd: c_int, key: &SessionKey) {
    let map_key = session_map_key(key);
    let _ = unsafe {
        libbpf_sys::bpf_map_delete_elem(
            map_fd,
            (&map_key as *const UserspaceSessionMapKey).cast::<c_void>(),
        )
    };
}

struct MmapArea {
    ptr: NonNull<u8>,
    len: usize,
}

impl MmapArea {
    fn new(len: usize) -> io::Result<Self> {
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let ptr =
            NonNull::new(ptr.cast::<u8>()).ok_or_else(|| io::Error::other("null mmap pointer"))?;
        Ok(Self { ptr, len })
    }

    fn as_nonnull_slice(&self) -> NonNull<[u8]> {
        NonNull::from(unsafe {
            &mut *std::ptr::slice_from_raw_parts_mut(self.ptr.as_ptr(), self.len)
        })
    }

    fn slice(&self, offset: usize, len: usize) -> Option<&[u8]> {
        let end = offset.checked_add(len)?;
        if end > self.len {
            return None;
        }
        Some(unsafe { std::slice::from_raw_parts(self.ptr.as_ptr().add(offset), len) })
    }

    fn slice_mut(&mut self, offset: usize, len: usize) -> Option<&mut [u8]> {
        unsafe { self.slice_mut_unchecked(offset, len) }
    }

    unsafe fn slice_mut_unchecked(&self, offset: usize, len: usize) -> Option<&mut [u8]> {
        let end = offset.checked_add(len)?;
        if end > self.len {
            return None;
        }
        Some(unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr().add(offset), len) })
    }
}

impl Drop for MmapArea {
    fn drop(&mut self) {
        let _ = unsafe { libc::munmap(self.ptr.as_ptr().cast::<c_void>(), self.len) };
    }
}

struct BindingLiveState {
    bound: AtomicBool,
    xsk_registered: AtomicBool,
    bind_mode: AtomicU8,
    socket_fd: AtomicI32,
    socket_ifindex: AtomicI32,
    socket_queue_id: AtomicU32,
    socket_bind_flags: AtomicU32,
    rx_packets: AtomicU64,
    rx_bytes: AtomicU64,
    rx_batches: AtomicU64,
    rx_wakeups: AtomicU64,
    metadata_packets: AtomicU64,
    metadata_errors: AtomicU64,
    validated_packets: AtomicU64,
    validated_bytes: AtomicU64,
    local_delivery_packets: AtomicU64,
    forward_candidate_packets: AtomicU64,
    route_miss_packets: AtomicU64,
    neighbor_miss_packets: AtomicU64,
    discard_route_packets: AtomicU64,
    next_table_packets: AtomicU64,
    exception_packets: AtomicU64,
    config_gen_mismatches: AtomicU64,
    fib_gen_mismatches: AtomicU64,
    unsupported_packets: AtomicU64,
    session_hits: AtomicU64,
    session_misses: AtomicU64,
    session_creates: AtomicU64,
    session_expires: AtomicU64,
    session_delta_generated: AtomicU64,
    session_delta_dropped: AtomicU64,
    session_delta_drained: AtomicU64,
    policy_denied_packets: AtomicU64,
    screen_drops: AtomicU64,
    snat_packets: AtomicU64,
    dnat_packets: AtomicU64,
    slow_path_packets: AtomicU64,
    slow_path_bytes: AtomicU64,
    slow_path_drops: AtomicU64,
    slow_path_rate_limited: AtomicU64,
    kernel_rx_dropped: AtomicU64,
    kernel_rx_invalid_descs: AtomicU64,
    tx_packets: AtomicU64,
    tx_bytes: AtomicU64,
    tx_completions: AtomicU64,
    tx_errors: AtomicU64,
    in_place_tx_packets: AtomicU64,
    debug_pending_fill_frames: AtomicU32,
    debug_spare_fill_frames: AtomicU32,
    debug_free_tx_frames: AtomicU32,
    debug_pending_tx_prepared: AtomicU32,
    debug_pending_tx_local: AtomicU32,
    debug_outstanding_tx: AtomicU32,
    debug_in_flight_recycles: AtomicU32,
    last_heartbeat: AtomicU64,
    max_pending_tx: AtomicU32,
    pending_tx_len: AtomicU32,
    last_error: Mutex<String>,
    pending_tx: Mutex<VecDeque<TxRequest>>,
    pending_session_deltas: Mutex<VecDeque<SessionDeltaInfo>>,
}

impl BindingLiveState {
    fn new() -> Self {
        Self {
            bound: AtomicBool::new(false),
            xsk_registered: AtomicBool::new(false),
            bind_mode: AtomicU8::new(XskBindMode::Unknown.as_u8()),
            socket_fd: AtomicI32::new(0),
            socket_ifindex: AtomicI32::new(0),
            socket_queue_id: AtomicU32::new(0),
            socket_bind_flags: AtomicU32::new(0),
            rx_packets: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            rx_batches: AtomicU64::new(0),
            rx_wakeups: AtomicU64::new(0),
            metadata_packets: AtomicU64::new(0),
            metadata_errors: AtomicU64::new(0),
            validated_packets: AtomicU64::new(0),
            validated_bytes: AtomicU64::new(0),
            local_delivery_packets: AtomicU64::new(0),
            forward_candidate_packets: AtomicU64::new(0),
            route_miss_packets: AtomicU64::new(0),
            neighbor_miss_packets: AtomicU64::new(0),
            discard_route_packets: AtomicU64::new(0),
            next_table_packets: AtomicU64::new(0),
            exception_packets: AtomicU64::new(0),
            config_gen_mismatches: AtomicU64::new(0),
            fib_gen_mismatches: AtomicU64::new(0),
            unsupported_packets: AtomicU64::new(0),
            session_hits: AtomicU64::new(0),
            session_misses: AtomicU64::new(0),
            session_creates: AtomicU64::new(0),
            session_expires: AtomicU64::new(0),
            session_delta_generated: AtomicU64::new(0),
            session_delta_dropped: AtomicU64::new(0),
            session_delta_drained: AtomicU64::new(0),
            policy_denied_packets: AtomicU64::new(0),
            screen_drops: AtomicU64::new(0),
            snat_packets: AtomicU64::new(0),
            dnat_packets: AtomicU64::new(0),
            slow_path_packets: AtomicU64::new(0),
            slow_path_bytes: AtomicU64::new(0),
            slow_path_drops: AtomicU64::new(0),
            slow_path_rate_limited: AtomicU64::new(0),
            kernel_rx_dropped: AtomicU64::new(0),
            kernel_rx_invalid_descs: AtomicU64::new(0),
            tx_packets: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            tx_completions: AtomicU64::new(0),
            tx_errors: AtomicU64::new(0),
            in_place_tx_packets: AtomicU64::new(0),
            debug_pending_fill_frames: AtomicU32::new(0),
            debug_spare_fill_frames: AtomicU32::new(0),
            debug_free_tx_frames: AtomicU32::new(0),
            debug_pending_tx_prepared: AtomicU32::new(0),
            debug_pending_tx_local: AtomicU32::new(0),
            debug_outstanding_tx: AtomicU32::new(0),
            debug_in_flight_recycles: AtomicU32::new(0),
            last_heartbeat: AtomicU64::new(0),
            max_pending_tx: AtomicU32::new(0),
            pending_tx_len: AtomicU32::new(0),
            last_error: Mutex::new(String::new()),
            pending_tx: Mutex::new(VecDeque::new()),
            pending_session_deltas: Mutex::new(VecDeque::new()),
        }
    }

    fn set_bound(&self, socket_fd: c_int) {
        self.bound.store(true, Ordering::Relaxed);
        self.socket_fd.store(socket_fd, Ordering::Relaxed);
    }

    fn set_socket_binding(&self, ifindex: i32, queue_id: u32, flags: u32) {
        self.socket_ifindex.store(ifindex, Ordering::Relaxed);
        self.socket_queue_id.store(queue_id, Ordering::Relaxed);
        self.socket_bind_flags.store(flags, Ordering::Relaxed);
    }

    fn set_xsk_registered(&self, value: bool) {
        self.xsk_registered.store(value, Ordering::Relaxed);
    }

    fn set_bind_mode(&self, mode: XskBindMode) {
        self.bind_mode.store(mode.as_u8(), Ordering::Relaxed);
    }

    fn set_last_heartbeat_at(&self, now_ns: u64) {
        self.last_heartbeat.store(now_ns, Ordering::Relaxed);
    }

    fn set_max_pending_tx(&self, max_pending: usize) {
        self.max_pending_tx
            .store(max_pending.min(u32::MAX as usize) as u32, Ordering::Relaxed);
    }

    fn clear_error(&self) {
        if let Ok(mut err) = self.last_error.lock() {
            err.clear();
        }
    }

    fn set_error(&self, msg: String) {
        if let Ok(mut err) = self.last_error.lock() {
            *err = msg;
        }
    }

    fn snapshot(&self) -> BindingLiveSnapshot {
        let now_wall = Utc::now();
        let now_mono = monotonic_nanos();
        let session_delta_pending = self
            .pending_session_deltas
            .lock()
            .map(|pending| pending.len() as u64)
            .unwrap_or(0);
        BindingLiveSnapshot {
            bound: self.bound.load(Ordering::Relaxed),
            xsk_registered: self.xsk_registered.load(Ordering::Relaxed),
            xsk_bind_mode: XskBindMode::from_u8(self.bind_mode.load(Ordering::Relaxed))
                .as_str()
                .to_string(),
            zero_copy: XskBindMode::from_u8(self.bind_mode.load(Ordering::Relaxed)).is_zerocopy(),
            socket_fd: self.socket_fd.load(Ordering::Relaxed),
            socket_ifindex: self.socket_ifindex.load(Ordering::Relaxed),
            socket_queue_id: self.socket_queue_id.load(Ordering::Relaxed),
            socket_bind_flags: self.socket_bind_flags.load(Ordering::Relaxed),
            rx_packets: self.rx_packets.load(Ordering::Relaxed),
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
            rx_batches: self.rx_batches.load(Ordering::Relaxed),
            rx_wakeups: self.rx_wakeups.load(Ordering::Relaxed),
            metadata_packets: self.metadata_packets.load(Ordering::Relaxed),
            metadata_errors: self.metadata_errors.load(Ordering::Relaxed),
            validated_packets: self.validated_packets.load(Ordering::Relaxed),
            validated_bytes: self.validated_bytes.load(Ordering::Relaxed),
            local_delivery_packets: self.local_delivery_packets.load(Ordering::Relaxed),
            forward_candidate_packets: self.forward_candidate_packets.load(Ordering::Relaxed),
            route_miss_packets: self.route_miss_packets.load(Ordering::Relaxed),
            neighbor_miss_packets: self.neighbor_miss_packets.load(Ordering::Relaxed),
            discard_route_packets: self.discard_route_packets.load(Ordering::Relaxed),
            next_table_packets: self.next_table_packets.load(Ordering::Relaxed),
            exception_packets: self.exception_packets.load(Ordering::Relaxed),
            config_gen_mismatches: self.config_gen_mismatches.load(Ordering::Relaxed),
            fib_gen_mismatches: self.fib_gen_mismatches.load(Ordering::Relaxed),
            unsupported_packets: self.unsupported_packets.load(Ordering::Relaxed),
            session_hits: self.session_hits.load(Ordering::Relaxed),
            session_misses: self.session_misses.load(Ordering::Relaxed),
            session_creates: self.session_creates.load(Ordering::Relaxed),
            session_expires: self.session_expires.load(Ordering::Relaxed),
            session_delta_pending,
            session_delta_generated: self.session_delta_generated.load(Ordering::Relaxed),
            session_delta_dropped: self.session_delta_dropped.load(Ordering::Relaxed),
            session_delta_drained: self.session_delta_drained.load(Ordering::Relaxed),
            policy_denied_packets: self.policy_denied_packets.load(Ordering::Relaxed),
            screen_drops: self.screen_drops.load(Ordering::Relaxed),
            snat_packets: self.snat_packets.load(Ordering::Relaxed),
            dnat_packets: self.dnat_packets.load(Ordering::Relaxed),
            slow_path_packets: self.slow_path_packets.load(Ordering::Relaxed),
            slow_path_bytes: self.slow_path_bytes.load(Ordering::Relaxed),
            slow_path_drops: self.slow_path_drops.load(Ordering::Relaxed),
            slow_path_rate_limited: self.slow_path_rate_limited.load(Ordering::Relaxed),
            kernel_rx_dropped: self.kernel_rx_dropped.load(Ordering::Relaxed),
            kernel_rx_invalid_descs: self.kernel_rx_invalid_descs.load(Ordering::Relaxed),
            tx_packets: self.tx_packets.load(Ordering::Relaxed),
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
            tx_completions: self.tx_completions.load(Ordering::Relaxed),
            tx_errors: self.tx_errors.load(Ordering::Relaxed),
            in_place_tx_packets: self.in_place_tx_packets.load(Ordering::Relaxed),
            debug_pending_fill_frames: self.debug_pending_fill_frames.load(Ordering::Relaxed),
            debug_spare_fill_frames: self.debug_spare_fill_frames.load(Ordering::Relaxed),
            debug_free_tx_frames: self.debug_free_tx_frames.load(Ordering::Relaxed),
            debug_pending_tx_prepared: self.debug_pending_tx_prepared.load(Ordering::Relaxed),
            debug_pending_tx_local: self.debug_pending_tx_local.load(Ordering::Relaxed),
            debug_outstanding_tx: self.debug_outstanding_tx.load(Ordering::Relaxed),
            debug_in_flight_recycles: self.debug_in_flight_recycles.load(Ordering::Relaxed),
            last_heartbeat: monotonic_timestamp_to_datetime(
                self.last_heartbeat.load(Ordering::Relaxed),
                now_mono,
                now_wall,
            ),
            last_error: self
                .last_error
                .lock()
                .map(|v| v.clone())
                .unwrap_or_default(),
        }
    }

    fn enqueue_tx(&self, req: TxRequest) -> Result<(), String> {
        match self.pending_tx.lock() {
            Ok(mut pending) => {
                let max_pending = self.max_pending_tx.load(Ordering::Relaxed) as usize;
                if max_pending > 0 && pending.len() >= max_pending {
                    if pending.pop_front().is_some() {
                        self.tx_errors.fetch_add(1, Ordering::Relaxed);
                    }
                }
                pending.push_back(req);
                self.pending_tx_len
                    .store(pending.len().min(u32::MAX as usize) as u32, Ordering::Relaxed);
                Ok(())
            }
            Err(_) => Err("pending_tx lock poisoned".to_string()),
        }
    }

    fn take_pending_tx(&self) -> VecDeque<TxRequest> {
        if self.pending_tx_len.load(Ordering::Relaxed) == 0 {
            return VecDeque::new();
        }
        match self.pending_tx.lock() {
            Ok(mut pending) => {
                let drained = core::mem::take(&mut *pending);
                self.pending_tx_len.store(0, Ordering::Relaxed);
                drained
            }
            Err(_) => VecDeque::new(),
        }
    }

    fn pending_tx_empty(&self) -> bool {
        self.pending_tx_len.load(Ordering::Relaxed) == 0
    }

    fn push_session_delta(&self, delta: SessionDeltaInfo) {
        self.session_delta_generated.fetch_add(1, Ordering::Relaxed);
        match self.pending_session_deltas.lock() {
            Ok(mut pending) => {
                if pending.len() >= MAX_PENDING_SESSION_DELTAS {
                    self.session_delta_dropped.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                pending.push_back(delta);
            }
            Err(_) => {
                self.session_delta_dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn drain_session_deltas(&self, max: usize) -> Vec<SessionDeltaInfo> {
        let drain = max.max(1);
        match self.pending_session_deltas.lock() {
            Ok(mut pending) => {
                let count = drain.min(pending.len());
                let mut out = Vec::with_capacity(count);
                for _ in 0..count {
                    if let Some(delta) = pending.pop_front() {
                        out.push(delta);
                    }
                }
                self.session_delta_drained
                    .fetch_add(out.len() as u64, Ordering::Relaxed);
                out
            }
            Err(_) => Vec::new(),
        }
    }
}

fn update_binding_debug_state(binding: &mut BindingWorker) {
    // Use a simple modular counter to avoid 7 atomic stores on every call.
    // At ~1M calls/sec, checking every 65536 calls ≈ every 65ms.
    binding.debug_state_counter = binding.debug_state_counter.wrapping_add(1);
    if binding.debug_state_counter & 0xFFFF != 0 {
        return;
    }
    binding
        .live
        .debug_pending_fill_frames
        .store(binding.pending_fill_frames.len() as u32, Ordering::Relaxed);
    binding
        .live
        .debug_spare_fill_frames
        .store(0, Ordering::Relaxed);
    binding
        .live
        .debug_free_tx_frames
        .store(binding.free_tx_frames.len() as u32, Ordering::Relaxed);
    binding
        .live
        .debug_pending_tx_prepared
        .store(binding.pending_tx_prepared.len() as u32, Ordering::Relaxed);
    binding
        .live
        .debug_pending_tx_local
        .store(binding.pending_tx_local.len() as u32, Ordering::Relaxed);
    binding
        .live
        .debug_outstanding_tx
        .store(binding.outstanding_tx, Ordering::Relaxed);
    binding.live.debug_in_flight_recycles.store(
        binding.in_flight_forward_recycles.len() as u32,
        Ordering::Relaxed,
    );
}

struct BindingLiveSnapshot {
    bound: bool,
    xsk_registered: bool,
    xsk_bind_mode: String,
    zero_copy: bool,
    socket_fd: c_int,
    socket_ifindex: i32,
    socket_queue_id: u32,
    socket_bind_flags: u32,
    rx_packets: u64,
    rx_bytes: u64,
    rx_batches: u64,
    rx_wakeups: u64,
    metadata_packets: u64,
    metadata_errors: u64,
    validated_packets: u64,
    validated_bytes: u64,
    local_delivery_packets: u64,
    forward_candidate_packets: u64,
    route_miss_packets: u64,
    neighbor_miss_packets: u64,
    discard_route_packets: u64,
    next_table_packets: u64,
    exception_packets: u64,
    config_gen_mismatches: u64,
    fib_gen_mismatches: u64,
    unsupported_packets: u64,
    session_hits: u64,
    session_misses: u64,
    session_creates: u64,
    session_expires: u64,
    session_delta_pending: u64,
    session_delta_generated: u64,
    session_delta_dropped: u64,
    session_delta_drained: u64,
    policy_denied_packets: u64,
    screen_drops: u64,
    snat_packets: u64,
    dnat_packets: u64,
    slow_path_packets: u64,
    slow_path_bytes: u64,
    slow_path_drops: u64,
    slow_path_rate_limited: u64,
    kernel_rx_dropped: u64,
    kernel_rx_invalid_descs: u64,
    tx_packets: u64,
    tx_bytes: u64,
    tx_completions: u64,
    tx_errors: u64,
    in_place_tx_packets: u64,
    debug_pending_fill_frames: u32,
    debug_spare_fill_frames: u32,
    debug_free_tx_frames: u32,
    debug_pending_tx_prepared: u32,
    debug_pending_tx_local: u32,
    debug_outstanding_tx: u32,
    debug_in_flight_recycles: u32,
    last_heartbeat: Option<chrono::DateTime<Utc>>,
    last_error: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        FabricSnapshot, InterfaceAddressSnapshot, InterfaceSnapshot, NeighborSnapshot,
        PolicyRuleSnapshot, RouteSnapshot, SourceNATRuleSnapshot, StaticNATRuleSnapshot,
        ZoneSnapshot,
    };

    fn forwarding_snapshot(include_neighbor: bool) -> ConfigSnapshot {
        ConfigSnapshot {
            zones: vec![ZoneSnapshot {
                name: "wan".to_string(),
                id: 1,
            }],
            interfaces: vec![InterfaceSnapshot {
                name: "ge-0/0/0.50".to_string(),
                zone: "wan".to_string(),
                linux_name: "ge-0-0-0.50".to_string(),
                ifindex: 12,
                hardware_addr: "02:bf:72:00:50:08".to_string(),
                addresses: vec![
                    InterfaceAddressSnapshot {
                        family: "inet".to_string(),
                        address: "172.16.50.8/24".to_string(),
                        scope: 0,
                    },
                    InterfaceAddressSnapshot {
                        family: "inet6".to_string(),
                        address: "2001:559:8585:50::8/64".to_string(),
                        scope: 0,
                    },
                ],
                ..Default::default()
            }],
            routes: vec![
                RouteSnapshot {
                    table: "inet.0".to_string(),
                    family: "inet".to_string(),
                    destination: "0.0.0.0/0".to_string(),
                    next_hops: vec!["172.16.50.1@ge-0/0/0.50".to_string()],
                    discard: false,
                    next_table: String::new(),
                },
                RouteSnapshot {
                    table: "inet6.0".to_string(),
                    family: "inet6".to_string(),
                    destination: "::/0".to_string(),
                    next_hops: vec!["2001:559:8585:50::1@ge-0/0/0.50".to_string()],
                    discard: false,
                    next_table: String::new(),
                },
            ],
            neighbors: if include_neighbor {
                vec![
                    NeighborSnapshot {
                        interface: "ge-0-0-0.50".to_string(),
                        ifindex: 12,
                        family: "inet".to_string(),
                        ip: "172.16.50.1".to_string(),
                        mac: "00:11:22:33:44:55".to_string(),
                        state: "reachable".to_string(),
                        router: true,
                        link_local: false,
                    },
                    NeighborSnapshot {
                        interface: "ge-0-0-0.50".to_string(),
                        ifindex: 12,
                        family: "inet6".to_string(),
                        ip: "2001:559:8585:50::1".to_string(),
                        mac: "00:11:22:33:44:55".to_string(),
                        state: "reachable".to_string(),
                        router: true,
                        link_local: false,
                    },
                ]
            } else {
                vec![]
            },
            source_nat_rules: vec![SourceNATRuleSnapshot {
                name: "snat".to_string(),
                from_zone: "lan".to_string(),
                to_zone: "wan".to_string(),
                source_addresses: vec!["0.0.0.0/0".to_string(), "::/0".to_string()],
                interface_mode: true,
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    fn forwarding_snapshot_with_next_table(include_neighbor: bool) -> ConfigSnapshot {
        ConfigSnapshot {
            interfaces: vec![InterfaceSnapshot {
                name: "ge-0/0/0.50".to_string(),
                zone: "wan".to_string(),
                linux_name: "ge-0-0-0.50".to_string(),
                ifindex: 12,
                hardware_addr: "02:bf:72:00:50:08".to_string(),
                addresses: vec![
                    InterfaceAddressSnapshot {
                        family: "inet".to_string(),
                        address: "172.16.50.8/24".to_string(),
                        scope: 0,
                    },
                    InterfaceAddressSnapshot {
                        family: "inet6".to_string(),
                        address: "2001:559:8585:50::8/64".to_string(),
                        scope: 0,
                    },
                ],
                ..Default::default()
            }],
            routes: vec![
                RouteSnapshot {
                    table: "inet.0".to_string(),
                    family: "inet".to_string(),
                    destination: "8.8.8.0/24".to_string(),
                    next_hops: vec![],
                    discard: false,
                    next_table: "blue.inet.0".to_string(),
                },
                RouteSnapshot {
                    table: "blue.inet.0".to_string(),
                    family: "inet".to_string(),
                    destination: "8.8.8.0/24".to_string(),
                    next_hops: vec!["172.16.50.1@ge-0/0/0.50".to_string()],
                    discard: false,
                    next_table: String::new(),
                },
                RouteSnapshot {
                    table: "inet6.0".to_string(),
                    family: "inet6".to_string(),
                    destination: "2606:4700:4700::/48".to_string(),
                    next_hops: vec![],
                    discard: false,
                    next_table: "blue.inet6.0".to_string(),
                },
                RouteSnapshot {
                    table: "blue.inet6.0".to_string(),
                    family: "inet6".to_string(),
                    destination: "2606:4700:4700::/48".to_string(),
                    next_hops: vec!["2001:559:8585:50::1@ge-0/0/0.50".to_string()],
                    discard: false,
                    next_table: String::new(),
                },
            ],
            neighbors: if include_neighbor {
                vec![
                    NeighborSnapshot {
                        interface: "ge-0-0-0.50".to_string(),
                        ifindex: 12,
                        family: "inet".to_string(),
                        ip: "172.16.50.1".to_string(),
                        mac: "00:11:22:33:44:55".to_string(),
                        state: "reachable".to_string(),
                        router: true,
                        link_local: false,
                    },
                    NeighborSnapshot {
                        interface: "ge-0-0-0.50".to_string(),
                        ifindex: 12,
                        family: "inet6".to_string(),
                        ip: "2001:559:8585:50::1".to_string(),
                        mac: "00:11:22:33:44:55".to_string(),
                        state: "reachable".to_string(),
                        router: true,
                        link_local: false,
                    },
                ]
            } else {
                vec![]
            },
            ..Default::default()
        }
    }

    fn forwarding_snapshot_with_next_table_loop() -> ConfigSnapshot {
        ConfigSnapshot {
            routes: vec![RouteSnapshot {
                table: "inet.0".to_string(),
                family: "inet".to_string(),
                destination: "0.0.0.0/0".to_string(),
                next_hops: vec![],
                discard: false,
                next_table: "inet.0".to_string(),
            }],
            ..Default::default()
        }
    }

    fn nat_snapshot() -> ConfigSnapshot {
        ConfigSnapshot {
            zones: vec![
                ZoneSnapshot {
                    name: "lan".to_string(),
                    id: 1,
                },
                ZoneSnapshot {
                    name: "wan".to_string(),
                    id: 2,
                },
            ],
            interfaces: vec![
                InterfaceSnapshot {
                    name: "reth1.0".to_string(),
                    zone: "lan".to_string(),
                    linux_name: "ge-0-0-1".to_string(),
                    ifindex: 24,
                    redundancy_group: 2,
                    hardware_addr: "02:bf:72:01:00:01".to_string(),
                    addresses: vec![
                        InterfaceAddressSnapshot {
                            family: "inet".to_string(),
                            address: "10.0.61.1/24".to_string(),
                            scope: 0,
                        },
                        InterfaceAddressSnapshot {
                            family: "inet6".to_string(),
                            address: "2001:559:8585:ef00::1/64".to_string(),
                            scope: 0,
                        },
                    ],
                    ..Default::default()
                },
                InterfaceSnapshot {
                    name: "reth0.80".to_string(),
                    zone: "wan".to_string(),
                    linux_name: "ge-0-0-0.80".to_string(),
                    ifindex: 12,
                    parent_ifindex: 11,
                    redundancy_group: 1,
                    vlan_id: 80,
                    hardware_addr: "02:bf:72:00:80:08".to_string(),
                    addresses: vec![
                        InterfaceAddressSnapshot {
                            family: "inet".to_string(),
                            address: "172.16.80.8/24".to_string(),
                            scope: 0,
                        },
                        InterfaceAddressSnapshot {
                            family: "inet6".to_string(),
                            address: "2001:559:8585:80::8/64".to_string(),
                            scope: 0,
                        },
                    ],
                    ..Default::default()
                },
            ],
            routes: vec![
                RouteSnapshot {
                    table: "inet.0".to_string(),
                    family: "inet".to_string(),
                    destination: "0.0.0.0/0".to_string(),
                    next_hops: vec!["172.16.80.1@reth0.80".to_string()],
                    discard: false,
                    next_table: String::new(),
                },
                RouteSnapshot {
                    table: "inet6.0".to_string(),
                    family: "inet6".to_string(),
                    destination: "::/0".to_string(),
                    next_hops: vec!["2001:559:8585:80::1@reth0.80".to_string()],
                    discard: false,
                    next_table: String::new(),
                },
            ],
            source_nat_rules: vec![
                SourceNATRuleSnapshot {
                    name: "snat".to_string(),
                    from_zone: "lan".to_string(),
                    to_zone: "wan".to_string(),
                    source_addresses: vec!["0.0.0.0/0".to_string()],
                    interface_mode: true,
                    ..Default::default()
                },
                SourceNATRuleSnapshot {
                    name: "snat6".to_string(),
                    from_zone: "lan".to_string(),
                    to_zone: "wan".to_string(),
                    source_addresses: vec!["::/0".to_string()],
                    interface_mode: true,
                    ..Default::default()
                },
            ],
            default_policy: "deny".to_string(),
            policies: vec![PolicyRuleSnapshot {
                name: "allow-all".to_string(),
                from_zone: "lan".to_string(),
                to_zone: "wan".to_string(),
                source_addresses: vec!["any".to_string()],
                destination_addresses: vec!["any".to_string()],
                applications: vec!["any".to_string()],
                application_terms: Vec::new(),
                action: "permit".to_string(),
            }],
            neighbors: vec![
                NeighborSnapshot {
                    interface: "ge-0-0-0.80".to_string(),
                    ifindex: 12,
                    family: "inet".to_string(),
                    ip: "172.16.80.1".to_string(),
                    mac: "00:11:22:33:44:55".to_string(),
                    state: "reachable".to_string(),
                    router: true,
                    link_local: false,
                },
                NeighborSnapshot {
                    interface: "ge-0-0-0.80".to_string(),
                    ifindex: 12,
                    family: "inet6".to_string(),
                    ip: "2001:559:8585:80::1".to_string(),
                    mac: "00:11:22:33:44:55".to_string(),
                    state: "reachable".to_string(),
                    router: true,
                    link_local: false,
                },
            ],
            ..Default::default()
        }
    }

    fn nat_snapshot_with_fabric() -> ConfigSnapshot {
        let mut snapshot = nat_snapshot();
        snapshot.interfaces.push(InterfaceSnapshot {
            name: "ge-0/0/0".to_string(),
            linux_name: "ge-0-0-0".to_string(),
            ifindex: 21,
            hardware_addr: "02:bf:72:ff:00:01".to_string(),
            ..Default::default()
        });
        snapshot.fabrics = vec![FabricSnapshot {
            name: "fab0".to_string(),
            parent_interface: "ge-0/0/0".to_string(),
            parent_linux_name: "ge-0-0-0".to_string(),
            parent_ifindex: 21,
            overlay_linux_name: "fab0".to_string(),
            overlay_ifindex: 101,
            rx_queues: 2,
            peer_address: "10.99.13.2".to_string(),
        }];
        snapshot.neighbors.push(NeighborSnapshot {
            interface: "fab0".to_string(),
            ifindex: 101,
            family: "inet".to_string(),
            ip: "10.99.13.2".to_string(),
            mac: "00:aa:bb:cc:dd:ee".to_string(),
            state: "reachable".to_string(),
            router: false,
            link_local: false,
        });
        snapshot
    }

    fn policy_deny_snapshot() -> ConfigSnapshot {
        ConfigSnapshot {
            interfaces: vec![
                InterfaceSnapshot {
                    name: "reth1.0".to_string(),
                    zone: "lan".to_string(),
                    linux_name: "ge-0-0-1".to_string(),
                    ifindex: 24,
                    ..Default::default()
                },
                InterfaceSnapshot {
                    name: "reth0.80".to_string(),
                    zone: "wan".to_string(),
                    linux_name: "ge-0-0-0.80".to_string(),
                    ifindex: 12,
                    parent_ifindex: 11,
                    vlan_id: 80,
                    hardware_addr: "02:bf:72:00:80:08".to_string(),
                    addresses: vec![InterfaceAddressSnapshot {
                        family: "inet".to_string(),
                        address: "172.16.80.8/24".to_string(),
                        scope: 0,
                    }],
                    ..Default::default()
                },
            ],
            default_policy: "deny".to_string(),
            policies: vec![PolicyRuleSnapshot {
                name: "allow-other".to_string(),
                from_zone: "dmz".to_string(),
                to_zone: "wan".to_string(),
                source_addresses: vec!["any".to_string()],
                destination_addresses: vec!["any".to_string()],
                applications: vec!["any".to_string()],
                application_terms: Vec::new(),
                action: "permit".to_string(),
            }],
            ..Default::default()
        }
    }

    fn valid_meta() -> UserspaceDpMeta {
        UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_ICMP,
            flow_src_port: 0x1234,
            flow_src_addr: [172, 16, 80, 200, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            flow_dst_addr: [172, 16, 80, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            config_generation: 11,
            fib_generation: 7,
            ..UserspaceDpMeta::default()
        }
    }

    fn vlan_icmp_reply_frame() -> Vec<u8> {
        let mut frame = vec![
            0x02, 0xbf, 0x72, 0x16, 0x02, 0x00, 0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5, 0x81, 0x00,
            0x00, 0x50, 0x08, 0x00, 0x45, 0x00, 0x00, 0x54, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01,
            0x00, 0x00, 0xac, 0x10, 0x50, 0xc8, 0xac, 0x10, 0x50, 0x08, 0x00, 0x00, 0x00, 0x00,
            0x12, 0x34, 0x00, 0x01,
        ];
        frame.resize(98, 0);
        frame
    }

    #[test]
    fn metadata_classification_accepts_matching_generations() {
        let validation = ValidationState {
            snapshot_installed: true,
            config_generation: 11,
            fib_generation: 7,
        };
        assert_eq!(
            classify_metadata(valid_meta(), validation),
            PacketDisposition::Valid
        );
    }

    #[test]
    fn metadata_classification_rejects_generation_mismatch() {
        let validation = ValidationState {
            snapshot_installed: true,
            config_generation: 22,
            fib_generation: 9,
        };
        assert_eq!(
            classify_metadata(valid_meta(), validation),
            PacketDisposition::ConfigGenerationMismatch
        );
        let validation = ValidationState {
            snapshot_installed: true,
            config_generation: 11,
            fib_generation: 9,
        };
        assert_eq!(
            classify_metadata(valid_meta(), validation),
            PacketDisposition::FibGenerationMismatch
        );
    }

    #[test]
    fn metadata_classification_rejects_unknown_address_family() {
        let validation = ValidationState {
            snapshot_installed: true,
            config_generation: 11,
            fib_generation: 7,
        };
        let mut meta = valid_meta();
        meta.addr_family = 0;
        assert_eq!(
            classify_metadata(meta, validation),
            PacketDisposition::UnsupportedPacket
        );
    }

    #[test]
    fn parse_session_flow_reparses_vlan_ipv4_reply_without_meta_offsets() {
        let frame = vlan_icmp_reply_frame();
        let mut area = MmapArea::new(4096).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_ICMP,
            l3_offset: 14,
            l4_offset: 34,
            ..UserspaceDpMeta::default()
        };
        let flow = parse_session_flow(
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
        )
        .expect("flow");
        assert_eq!(flow.src_ip, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)));
        assert_eq!(flow.dst_ip, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)));
        assert_eq!(flow.forward_key.src_port, 0x1234);
        assert_eq!(flow.forward_key.dst_port, 0);
    }

    #[test]
    fn parse_session_flow_prefers_tuple_stamped_in_metadata() {
        let mut area = MmapArea::new(256).expect("mmap");
        area.slice_mut(0, 64).expect("slice").fill(0xaa);
        let meta = valid_meta();
        let flow = parse_session_flow(
            &area,
            XdpDesc {
                addr: 0,
                len: 64,
                options: 0,
            },
            meta,
        )
        .expect("flow");
        assert_eq!(flow.src_ip, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)));
        assert_eq!(flow.dst_ip, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)));
        assert_eq!(flow.forward_key.src_port, 0x1234);
        assert_eq!(flow.forward_key.dst_port, 0);
    }

    #[test]
    fn parse_session_flow_prefers_frame_tuple_when_metadata_disagrees() {
        let frame = vlan_icmp_reply_frame();
        let mut area = MmapArea::new(4096).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let mut meta = valid_meta();
        meta.l3_offset = 18;
        meta.l4_offset = 38;
        meta.flow_src_addr[..4].copy_from_slice(&[10, 0, 61, 102]);
        meta.flow_dst_addr[..4].copy_from_slice(&[172, 16, 80, 200]);
        meta.flow_src_port = 0xbeef;
        meta.flow_dst_port = 0;
        let flow = parse_session_flow(
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
        )
        .expect("flow");
        assert_eq!(flow.src_ip, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)));
        assert_eq!(flow.dst_ip, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)));
        assert_eq!(flow.forward_key.src_port, 0x1234);
        assert_eq!(flow.forward_key.dst_port, 0);
    }

    #[test]
    fn parse_session_flow_prefers_ipv6_metadata_ports_when_frame_ports_disagree() {
        let src_ip: Ipv6Addr = "2001:559:8585:ef00::102".parse().expect("src");
        let dst_ip: Ipv6Addr = "2001:559:8585:80::200".parse().expect("dst");
        let src_port = 50662u16;
        let dst_port = 5201u16;
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0u8; 6]);
        frame.extend_from_slice(&[0u8; 6]);
        frame.extend_from_slice(&0x8100u16.to_be_bytes());
        frame.extend_from_slice(&80u16.to_be_bytes());
        frame.extend_from_slice(&0x86ddu16.to_be_bytes());
        frame.extend_from_slice(&[0x60, 0, 0, 0, 0, 20, PROTO_TCP, 64]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&0u32.to_be_bytes());
        frame.extend_from_slice(&0u32.to_be_bytes());
        frame.extend_from_slice(&[0x50, 0x10, 0, 64, 0, 0, 0, 0]);

        let mut area = MmapArea::new(512).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);

        let mut meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            l3_offset: 18,
            l4_offset: 58,
            payload_offset: 78,
            flow_src_port: 1026,
            flow_dst_port: dst_port,
            flow_src_addr: src_ip.octets(),
            flow_dst_addr: dst_ip.octets(),
            ..UserspaceDpMeta::default()
        };
        let flow = parse_session_flow(
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
        )
        .expect("flow");
        assert_eq!(flow.src_ip, IpAddr::V6(src_ip));
        assert_eq!(flow.dst_ip, IpAddr::V6(dst_ip));
        assert_eq!(flow.forward_key.src_port, 1026);
        assert_eq!(flow.forward_key.dst_port, dst_port);
    }

    #[test]
    fn parse_session_flow_reparses_ipv6_when_metadata_l4_offset_is_bad() {
        let src_ip: Ipv6Addr = "2001:559:8585:ef00::102".parse().expect("src");
        let dst_ip: Ipv6Addr = "2001:559:8585:80::200".parse().expect("dst");
        let src_port = 50662u16;
        let dst_port = 5201u16;
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0u8; 6]);
        frame.extend_from_slice(&[0u8; 6]);
        frame.extend_from_slice(&0x8100u16.to_be_bytes());
        frame.extend_from_slice(&80u16.to_be_bytes());
        frame.extend_from_slice(&0x86ddu16.to_be_bytes());
        frame.extend_from_slice(&[0x60, 0, 0, 0, 0, 20, PROTO_TCP, 64]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&0u32.to_be_bytes());
        frame.extend_from_slice(&0u32.to_be_bytes());
        frame.extend_from_slice(&[0x50, 0x10, 0, 64, 0, 0, 0, 0]);

        let mut area = MmapArea::new(512).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);

        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            l3_offset: 18,
            l4_offset: 22,
            payload_offset: 78,
            flow_src_port: 1025,
            flow_dst_port: dst_port,
            flow_src_addr: src_ip.octets(),
            flow_dst_addr: dst_ip.octets(),
            ..UserspaceDpMeta::default()
        };
        let flow = parse_session_flow(
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
        )
        .expect("flow");
        assert_eq!(flow.src_ip, IpAddr::V6(src_ip));
        assert_eq!(flow.dst_ip, IpAddr::V6(dst_ip));
        // When IPs match, parse_session_flow prefers metadata ports over
        // frame-parsed ports (metadata is stamped by BPF before any DMA
        // corruption). The meta port (1025) wins over the frame port (50662).
        assert_eq!(flow.forward_key.src_port, 1025);
        assert_eq!(flow.forward_key.dst_port, dst_port);
    }

    #[test]
    fn forwarding_lookup_prefers_local_delivery() {
        let mut snapshot = forwarding_snapshot(true);
        snapshot.source_nat_rules.clear();
        let state = build_forwarding_state(&snapshot);
        assert_eq!(
            lookup_forwarding_for_ip(&state, IpAddr::V4(Ipv4Addr::new(172, 16, 50, 8))),
            ForwardingDisposition::LocalDelivery
        );
        assert_eq!(
            lookup_forwarding_for_ip(
                &state,
                IpAddr::V6("2001:559:8585:50::8".parse().expect("ipv6")),
            ),
            ForwardingDisposition::LocalDelivery
        );
    }

    #[test]
    fn forwarding_lookup_requires_neighbor_for_forward_candidate() {
        let good = build_forwarding_state(&forwarding_snapshot(true));
        assert_eq!(
            lookup_forwarding_for_ip(&good, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            ForwardingDisposition::ForwardCandidate
        );
        assert_eq!(
            lookup_forwarding_for_ip(
                &good,
                IpAddr::V6("2606:4700:4700::1111".parse().expect("ipv6")),
            ),
            ForwardingDisposition::ForwardCandidate
        );

        let missing_neighbor = build_forwarding_state(&forwarding_snapshot(false));
        assert_eq!(
            lookup_forwarding_for_ip(&missing_neighbor, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),),
            ForwardingDisposition::MissingNeighbor
        );
    }

    #[test]
    fn ha_resolution_blocks_inactive_owner_rg() {
        let state = build_forwarding_state(&nat_snapshot());
        let ha_state = Arc::new(ArcSwap::from_pointee(BTreeMap::from([(
            1,
            HAGroupRuntime {
                active: false,
                watchdog_timestamp: monotonic_nanos() / 1_000_000_000,
            },
        )])));
        let resolved = enforce_ha_resolution(
            &state,
            &ha_state,
            lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        );
        assert_eq!(resolved.disposition, ForwardingDisposition::HAInactive);
    }

    #[test]
    fn ha_resolution_allows_fresh_active_owner_rg() {
        let state = build_forwarding_state(&nat_snapshot());
        let ha_state = Arc::new(ArcSwap::from_pointee(BTreeMap::from([(
            1,
            HAGroupRuntime {
                active: true,
                watchdog_timestamp: monotonic_nanos() / 1_000_000_000,
            },
        )])));
        let resolved = enforce_ha_resolution(
            &state,
            &ha_state,
            lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        );
        assert_eq!(
            resolved.disposition,
            ForwardingDisposition::ForwardCandidate
        );
    }

    #[test]
    fn inactive_owner_rg_redirects_established_session_to_fabric() {
        let state = build_forwarding_state(&nat_snapshot_with_fabric());
        let ha_state = Arc::new(ArcSwap::from_pointee(BTreeMap::from([(
            1,
            HAGroupRuntime {
                active: false,
                watchdog_timestamp: monotonic_nanos() / 1_000_000_000,
            },
        )])));
        let blocked = enforce_ha_resolution(
            &state,
            &ha_state,
            lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        );
        assert_eq!(blocked.disposition, ForwardingDisposition::HAInactive);
        let redirected = redirect_via_fabric_if_needed(&state, blocked, 24);
        assert_eq!(
            redirected.disposition,
            ForwardingDisposition::FabricRedirect
        );
        assert_eq!(redirected.egress_ifindex, 21);
        assert_eq!(redirected.tx_ifindex, 21);
        assert_eq!(
            redirected.next_hop,
            Some(IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2)))
        );
        assert_eq!(
            redirected.neighbor_mac,
            Some([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee])
        );
        assert_eq!(
            redirected.src_mac,
            Some([0x02, 0xbf, 0x72, 0xff, 0x00, 0x01])
        );
    }

    #[test]
    fn zone_encoded_fabric_redirect_preserves_ingress_zone() {
        let state = build_forwarding_state(&nat_snapshot_with_fabric());
        let redirected =
            resolve_zone_encoded_fabric_redirect(&state, "lan").expect("zone-encoded redirect");
        assert_eq!(
            redirected.disposition,
            ForwardingDisposition::FabricRedirect
        );
        assert_eq!(redirected.egress_ifindex, 21);
        assert_eq!(redirected.tx_ifindex, 21);
        assert_eq!(
            redirected.src_mac,
            Some([0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x01])
        );
    }

    #[test]
    fn parse_zone_encoded_fabric_ingress_uses_zone_override() {
        let state = build_forwarding_state(&nat_snapshot_with_fabric());
        let mut frame = vec![0u8; 64];
        frame[6..12].copy_from_slice(&[0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x01]);
        let mut area = MmapArea::new(4096).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            ingress_ifindex: 21,
            ..UserspaceDpMeta::default()
        };
        assert_eq!(
            parse_zone_encoded_fabric_ingress(
                &area,
                XdpDesc {
                    addr: 0,
                    len: frame.len() as u32,
                    options: 0,
                },
                meta,
                &state,
            ),
            Some("lan".to_string())
        );
    }

    #[test]
    fn zone_encoded_fabric_ingress_skips_dynamic_neighbor_learning() {
        let state = build_forwarding_state(&nat_snapshot_with_fabric());
        let mut frame = vec![0u8; 64];
        frame[6..12].copy_from_slice(&[0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x01]);
        let mut area = MmapArea::new(4096).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let neighbors = Arc::new(Mutex::new(FastMap::default()));
        let mut last_learned = None;
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            ingress_ifindex: 21,
            ..UserspaceDpMeta::default()
        };
        learn_dynamic_neighbor_from_packet(
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            &mut last_learned,
            &state,
            &neighbors,
        );
        assert!(neighbors.lock().expect("neighbors").is_empty());
    }

    #[test]
    fn new_flow_to_inactive_owner_rg_uses_zone_encoded_fabric_redirect() {
        let state = build_forwarding_state(&nat_snapshot_with_fabric());
        let ha_state = Arc::new(ArcSwap::from_pointee(BTreeMap::from([(
            1,
            HAGroupRuntime {
                active: false,
                watchdog_timestamp: monotonic_nanos() / 1_000_000_000,
            },
        )])));
        let blocked = enforce_ha_resolution(
            &state,
            &ha_state,
            lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        );
        assert_eq!(blocked.disposition, ForwardingDisposition::HAInactive);
        let (from_zone, _) = zone_pair_for_flow(&state, 24, blocked.egress_ifindex);
        let redirected =
            resolve_zone_encoded_fabric_redirect(&state, &from_zone).expect("fabric redirect");
        assert_eq!(
            redirected.disposition,
            ForwardingDisposition::FabricRedirect
        );
        assert_eq!(
            redirected.src_mac,
            Some([0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x01])
        );
    }

    #[test]
    fn embedded_icmp_to_inactive_owner_rg_uses_zone_encoded_fabric_redirect() {
        let state = build_forwarding_state(&nat_snapshot_with_fabric());
        let ha_state = BTreeMap::from([(
            2,
            HAGroupRuntime {
                active: false,
                watchdog_timestamp: monotonic_nanos() / 1_000_000_000,
            },
        )]);
        let icmp_match = EmbeddedIcmpMatch {
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                ..NatDecision::default()
            },
            original_src: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            original_src_port: 33434,
            embedded_proto: PROTO_UDP,
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 24,
                tx_ifindex: 24,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
                neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x01, 0x00, 0x01]),
                tx_vlan_id: 0,
            },
            metadata: SessionMetadata {
                ingress_zone: Arc::<str>::from("wan"),
                egress_zone: Arc::<str>::from("lan"),
                owner_rg_id: 2,
                is_reverse: false,
                synced: false,
                nat64_reverse: None,
            },
        };

        let resolved = finalize_embedded_icmp_resolution(
            &state,
            &ha_state,
            monotonic_nanos() / 1_000_000_000,
            12,
            &icmp_match,
        );
        assert_eq!(resolved.disposition, ForwardingDisposition::FabricRedirect);
        assert_eq!(resolved.egress_ifindex, 21);
        assert_eq!(resolved.tx_ifindex, 21);
        assert_eq!(
            resolved.src_mac,
            Some([0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x02])
        );
    }

    #[test]
    fn embedded_icmp_no_route_uses_zone_encoded_fabric_redirect() {
        let state = build_forwarding_state(&nat_snapshot_with_fabric());
        let ha_state = BTreeMap::new();
        let icmp_match = EmbeddedIcmpMatch {
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                ..NatDecision::default()
            },
            original_src: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            original_src_port: 33434,
            embedded_proto: PROTO_UDP,
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::NoRoute,
                local_ifindex: 0,
                egress_ifindex: 0,
                tx_ifindex: 0,
                next_hop: None,
                neighbor_mac: None,
                src_mac: None,
                tx_vlan_id: 0,
            },
            metadata: SessionMetadata {
                ingress_zone: Arc::<str>::from("wan"),
                egress_zone: Arc::<str>::from("lan"),
                owner_rg_id: 2,
                is_reverse: false,
                synced: false,
                nat64_reverse: None,
            },
        };

        let resolved = finalize_embedded_icmp_resolution(
            &state,
            &ha_state,
            monotonic_nanos() / 1_000_000_000,
            12,
            &icmp_match,
        );
        assert_eq!(resolved.disposition, ForwardingDisposition::FabricRedirect);
        assert_eq!(resolved.egress_ifindex, 21);
        assert_eq!(resolved.tx_ifindex, 21);
        assert_eq!(
            resolved.src_mac,
            Some([0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x02])
        );
    }

    #[test]
    fn embedded_icmp_discard_route_uses_zone_encoded_fabric_redirect() {
        let state = build_forwarding_state(&nat_snapshot_with_fabric());
        let ha_state = BTreeMap::new();
        let icmp_match = EmbeddedIcmpMatch {
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                ..NatDecision::default()
            },
            original_src: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            original_src_port: 33434,
            embedded_proto: PROTO_UDP,
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::DiscardRoute,
                local_ifindex: 0,
                egress_ifindex: 24,
                tx_ifindex: 24,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
                neighbor_mac: None,
                src_mac: None,
                tx_vlan_id: 0,
            },
            metadata: SessionMetadata {
                ingress_zone: Arc::<str>::from("wan"),
                egress_zone: Arc::<str>::from("lan"),
                owner_rg_id: 2,
                is_reverse: false,
                synced: false,
                nat64_reverse: None,
            },
        };

        let resolved = finalize_embedded_icmp_resolution(
            &state,
            &ha_state,
            monotonic_nanos() / 1_000_000_000,
            12,
            &icmp_match,
        );
        assert_eq!(resolved.disposition, ForwardingDisposition::FabricRedirect);
        assert_eq!(resolved.egress_ifindex, 21);
        assert_eq!(resolved.tx_ifindex, 21);
    }

    #[test]
    fn embedded_icmp_from_fabric_does_not_redirect_back_to_fabric() {
        let state = build_forwarding_state(&nat_snapshot_with_fabric());
        let ha_state = BTreeMap::from([(
            2,
            HAGroupRuntime {
                active: false,
                watchdog_timestamp: monotonic_nanos() / 1_000_000_000,
            },
        )]);
        let icmp_match = EmbeddedIcmpMatch {
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                ..NatDecision::default()
            },
            original_src: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            original_src_port: 33434,
            embedded_proto: PROTO_UDP,
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 24,
                tx_ifindex: 24,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
                neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x01, 0x00, 0x01]),
                tx_vlan_id: 0,
            },
            metadata: SessionMetadata {
                ingress_zone: Arc::<str>::from("wan"),
                egress_zone: Arc::<str>::from("lan"),
                owner_rg_id: 2,
                is_reverse: false,
                synced: false,
                nat64_reverse: None,
            },
        };

        let resolved = finalize_embedded_icmp_resolution(
            &state,
            &ha_state,
            monotonic_nanos() / 1_000_000_000,
            21,
            &icmp_match,
        );
        assert_eq!(resolved.disposition, ForwardingDisposition::HAInactive);
    }

    #[test]
    fn fabric_ingress_does_not_redirect_back_to_fabric() {
        let state = build_forwarding_state(&nat_snapshot_with_fabric());
        let blocked = ForwardingResolution {
            disposition: ForwardingDisposition::HAInactive,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 12,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            src_mac: None,
            tx_vlan_id: 80,
        };
        assert_eq!(
            redirect_via_fabric_if_needed(&state, blocked, 21).disposition,
            ForwardingDisposition::HAInactive
        );
    }

    #[test]
    fn source_nat_selection_uses_interface_addresses() {
        let state = build_forwarding_state(&nat_snapshot());
        let flow = SessionFlow {
            src_ip: "10.0.61.102".parse().expect("src"),
            dst_ip: "172.16.80.200".parse().expect("dst"),
            forward_key: SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip: "10.0.61.102".parse().expect("src"),
                dst_ip: "172.16.80.200".parse().expect("dst"),
                src_port: 12345,
                dst_port: 5201,
            },
        };
        let (from_zone, to_zone) = zone_pair_for_flow(&state, 24, 12);
        assert_eq!(
            match_source_nat_for_flow(&state, &from_zone, &to_zone, 12, &flow),
            Some(NatDecision { 
                rewrite_src: Some("172.16.80.8".parse().expect("snat")),
                rewrite_dst: None,
             ..NatDecision::default() })
        );
    }

    #[test]
    fn source_nat_selection_uses_interface_addresses_v6() {
        let state = build_forwarding_state(&nat_snapshot());
        let flow = SessionFlow {
            src_ip: "2001:559:8585:ef00::100".parse().expect("src"),
            dst_ip: "2001:559:8585:80::200".parse().expect("dst"),
            forward_key: SessionKey {
                addr_family: libc::AF_INET6 as u8,
                protocol: PROTO_TCP,
                src_ip: "2001:559:8585:ef00::100".parse().expect("src"),
                dst_ip: "2001:559:8585:80::200".parse().expect("dst"),
                src_port: 12345,
                dst_port: 5201,
            },
        };
        let (from_zone, to_zone) = zone_pair_for_flow(&state, 24, 12);
        assert_eq!(
            match_source_nat_for_flow(&state, &from_zone, &to_zone, 12, &flow),
            Some(NatDecision { 
                rewrite_src: Some("2001:559:8585:80::8".parse().expect("snat")),
                rewrite_dst: None,
             ..NatDecision::default() })
        );
    }

    #[test]
    fn interface_snat_addresses_are_not_treated_as_local_delivery() {
        let state = build_forwarding_state(&nat_snapshot());
        let resolved_v4 = lookup_forwarding_resolution(&state, "172.16.80.8".parse().expect("v4"));
        assert_ne!(
            resolved_v4.disposition,
            ForwardingDisposition::LocalDelivery
        );
        let resolved_v6 =
            lookup_forwarding_resolution(&state, "2001:559:8585:80::8".parse().expect("v6"));
        assert_ne!(
            resolved_v6.disposition,
            ForwardingDisposition::LocalDelivery
        );
    }

    #[test]
    fn interface_snat_addresses_are_local_delivered_on_session_miss() {
        let state = build_forwarding_state(&nat_snapshot());
        let resolved_v4 =
            interface_nat_local_resolution(&state, "172.16.80.8".parse().expect("v4"))
                .expect("v4 nat local delivery");
        assert_eq!(
            resolved_v4.disposition,
            ForwardingDisposition::LocalDelivery
        );
        assert_eq!(resolved_v4.local_ifindex, 12);

        let resolved_v6 =
            interface_nat_local_resolution(&state, "2001:559:8585:80::8".parse().expect("v6"))
                .expect("v6 nat local delivery");
        assert_eq!(
            resolved_v6.disposition,
            ForwardingDisposition::LocalDelivery
        );
        assert_eq!(resolved_v6.local_ifindex, 12);
    }

    #[test]
    fn icmp_session_miss_resolution_prefers_frame_destination_for_interface_nat_local_delivery() {
        let state = build_forwarding_state(&nat_snapshot());
        let frame = vlan_icmp_reply_frame();
        let mut area = MmapArea::new(4096).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let mut meta = valid_meta();
        meta.l3_offset = 18;
        meta.l4_offset = 38;
        meta.flow_src_addr[..4].copy_from_slice(&[172, 16, 80, 201]);
        // Deliberately poison the metadata tuple to model a stamped-dst mismatch.
        meta.flow_dst_addr[..4].copy_from_slice(&[10, 0, 61, 1]);

        let flow = parse_session_flow(
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
        )
        .expect("flow");
        assert_eq!(flow.dst_ip, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)));

        let resolution_target = parse_packet_destination(
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
        )
        .expect("frame destination");
        assert_eq!(resolution_target, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)));

        let resolved =
            interface_nat_local_resolution_on_session_miss(&state, resolution_target, PROTO_ICMP)
                .expect("nat local delivery");
        assert_eq!(resolved.disposition, ForwardingDisposition::LocalDelivery);
        assert_eq!(resolved.local_ifindex, 12);
    }

    #[test]
    fn tcp_session_miss_does_not_local_deliver_interface_nat_address() {
        let state = build_forwarding_state(&nat_snapshot());
        assert!(
            interface_nat_local_resolution_on_session_miss(
                &state,
                "172.16.80.8".parse().expect("v4"),
                PROTO_TCP,
            )
            .is_none()
        );
        assert!(
            interface_nat_local_resolution_on_session_miss(
                &state,
                "2001:559:8585:80::8".parse().expect("v6"),
                PROTO_UDP,
            )
            .is_none()
        );
    }

    #[test]
    fn ingress_interface_local_resolution_matches_vlan_local_address() {
        let state = build_forwarding_state(&nat_snapshot());
        let resolved =
            ingress_interface_local_resolution(&state, 11, 80, "172.16.80.8".parse().expect("dst"))
                .expect("ingress local delivery");
        assert_eq!(resolved.disposition, ForwardingDisposition::LocalDelivery);
        assert_eq!(resolved.local_ifindex, 12);
    }

    #[test]
    fn tcp_session_miss_does_not_local_deliver_ingress_vlan_address() {
        let state = build_forwarding_state(&nat_snapshot());
        assert!(
            ingress_interface_local_resolution_on_session_miss(
                &state,
                11,
                80,
                "172.16.80.8".parse().expect("dst"),
                PROTO_TCP,
            )
            .is_none()
        );
        assert!(
            ingress_interface_local_resolution_on_session_miss(
                &state,
                11,
                80,
                "2001:559:8585:80::8".parse().expect("dst"),
                PROTO_UDP,
            )
            .is_none()
        );
    }

    #[test]
    fn unsolicited_dns_reply_respects_flow_knob() {
        let mut state = build_forwarding_state(&nat_snapshot());
        let flow = SessionFlow {
            src_ip: "172.16.80.53".parse().expect("src"),
            dst_ip: "10.0.61.102".parse().expect("dst"),
            forward_key: SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_UDP,
                src_ip: "172.16.80.53".parse().expect("src"),
                dst_ip: "10.0.61.102".parse().expect("dst"),
                src_port: 53,
                dst_port: 5353,
            },
        };
        state.allow_dns_reply = true;
        assert!(allow_unsolicited_dns_reply(&state, &flow));
        state.allow_dns_reply = false;
        assert!(!allow_unsolicited_dns_reply(&state, &flow));
    }

    #[test]
    fn policy_selection_permits_matching_zone_pair() {
        let state = build_forwarding_state(&nat_snapshot());
        let flow = SessionFlow {
            src_ip: "10.0.61.102".parse().expect("src"),
            dst_ip: "172.16.80.200".parse().expect("dst"),
            forward_key: SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip: "10.0.61.102".parse().expect("src"),
                dst_ip: "172.16.80.200".parse().expect("dst"),
                src_port: 12345,
                dst_port: 5201,
            },
        };
        let (from_zone, to_zone) = zone_pair_for_flow(&state, 24, 12);
        assert_eq!(
            evaluate_policy(
                &state.policy,
                &from_zone,
                &to_zone,
                flow.src_ip,
                flow.dst_ip,
                flow.forward_key.protocol,
                flow.forward_key.src_port,
                flow.forward_key.dst_port,
            ),
            PolicyAction::Permit
        );
    }

    #[test]
    fn policy_selection_denies_on_default_policy() {
        let state = build_forwarding_state(&policy_deny_snapshot());
        let flow = SessionFlow {
            src_ip: "10.0.61.102".parse().expect("src"),
            dst_ip: "172.16.80.200".parse().expect("dst"),
            forward_key: SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip: "10.0.61.102".parse().expect("src"),
                dst_ip: "172.16.80.200".parse().expect("dst"),
                src_port: 12345,
                dst_port: 5201,
            },
        };
        let (from_zone, to_zone) = zone_pair_for_flow(&state, 24, 12);
        assert_eq!(
            evaluate_policy(
                &state.policy,
                &from_zone,
                &to_zone,
                flow.src_ip,
                flow.dst_ip,
                flow.forward_key.protocol,
                flow.forward_key.src_port,
                flow.forward_key.dst_port,
            ),
            PolicyAction::Deny
        );
    }

    #[test]
    fn forwarding_resolution_reports_egress_and_neighbor() {
        let state = build_forwarding_state(&forwarding_snapshot(true));
        let resolved = lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(
            resolved.disposition,
            ForwardingDisposition::ForwardCandidate
        );
        assert_eq!(resolved.egress_ifindex, 12);
        assert_eq!(
            resolved.next_hop,
            Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1)))
        );
        assert_eq!(
            resolved.neighbor_mac,
            Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
        );
    }

    #[test]
    fn forwarding_resolution_supports_next_table_recursion() {
        let state = build_forwarding_state(&forwarding_snapshot_with_next_table(true));
        let resolved = lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(
            resolved.disposition,
            ForwardingDisposition::ForwardCandidate
        );
        assert_eq!(resolved.egress_ifindex, 12);
        assert_eq!(
            resolved.next_hop,
            Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1)))
        );

        let resolved_v6 = lookup_forwarding_resolution(
            &state,
            IpAddr::V6("2606:4700:4700::1111".parse().expect("ipv6")),
        );
        assert_eq!(
            resolved_v6.disposition,
            ForwardingDisposition::ForwardCandidate
        );
        assert_eq!(resolved_v6.egress_ifindex, 12);
        assert_eq!(
            resolved_v6.next_hop,
            Some(IpAddr::V6("2001:559:8585:50::1".parse().expect("v6 nh")))
        );
    }

    #[test]
    fn forwarding_state_normalizes_ipv6_routes_emitted_in_inet_table() {
        let mut snapshot = forwarding_snapshot(true);
        snapshot.routes[1].table = "inet.0".to_string();
        snapshot.routes[1].family = "inet".to_string();
        let state = build_forwarding_state(&snapshot);
        let resolved = lookup_forwarding_resolution(
            &state,
            IpAddr::V6("2606:4700:4700::1111".parse().expect("ipv6")),
        );
        assert_eq!(
            resolved.disposition,
            ForwardingDisposition::ForwardCandidate
        );
        assert_eq!(resolved.egress_ifindex, 12);
        assert_eq!(
            resolved.next_hop,
            Some(IpAddr::V6("2001:559:8585:50::1".parse().expect("v6 nh")))
        );
    }

    #[test]
    fn dynamic_neighbor_cache_enables_forward_candidate() {
        let state = build_forwarding_state(&forwarding_snapshot(false));
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::from_iter([(
            (12, IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1))),
            NeighborEntry {
                mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            },
        )])));
        let resolved = lookup_forwarding_resolution_with_dynamic(
            &state,
            &dynamic_neighbors,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        );
        assert_eq!(
            resolved.disposition,
            ForwardingDisposition::ForwardCandidate
        );
        assert_eq!(
            resolved.neighbor_mac,
            Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
        );
    }

    #[test]
    fn parse_neighbor_entries_accepts_stale_ipv4_and_ipv6_rows() {
        let parsed = parse_neighbor_entries(
            "172.16.80.200 lladdr ba:86:e9:f6:4b:d5 STALE\n2001:559:8585:80::200 lladdr ba:86:e9:f6:4b:d5 STALE\n",
        );
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].0, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)));
        assert_eq!(
            parsed[1].0,
            IpAddr::V6("2001:559:8585:80::200".parse().expect("ipv6"))
        );
        assert_eq!(parsed[0].1.mac, [0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]);
        assert_eq!(parsed[1].1.mac, [0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]);
    }

    #[test]
    fn learned_ingress_neighbor_enables_reverse_lan_resolution() {
        let state = build_forwarding_state(&nat_snapshot());
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));
        learn_dynamic_neighbor(
            &state,
            &dynamic_neighbors,
            24,
            0,
            IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        );
        let resolved = lookup_forwarding_resolution_with_dynamic(
            &state,
            &dynamic_neighbors,
            IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
        );
        assert_eq!(
            resolved.disposition,
            ForwardingDisposition::ForwardCandidate
        );
        assert_eq!(resolved.egress_ifindex, 24);
        assert_eq!(
            resolved.neighbor_mac,
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
    }

    #[test]
    fn learned_vlan_ingress_neighbor_maps_to_logical_ifindex() {
        let state = build_forwarding_state(&nat_snapshot());
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));
        learn_dynamic_neighbor(
            &state,
            &dynamic_neighbors,
            11,
            80,
            IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01],
        );
        let resolved = lookup_forwarding_resolution_with_dynamic(
            &state,
            &dynamic_neighbors,
            IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        );
        assert_eq!(
            resolved.disposition,
            ForwardingDisposition::ForwardCandidate
        );
        assert_eq!(resolved.egress_ifindex, 12);
        assert_eq!(
            resolved.neighbor_mac,
            Some([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01])
        );
    }

    #[test]
    fn forwarding_resolution_rejects_next_table_loop() {
        let state = build_forwarding_state(&forwarding_snapshot_with_next_table_loop());
        let resolved = lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(
            resolved.disposition,
            ForwardingDisposition::NextTableUnsupported
        );
    }

    #[test]
    fn tx_binding_resolution_prefers_bind_ifindex_for_vlan_units() {
        let state = build_forwarding_state(&nat_snapshot());
        assert_eq!(resolve_tx_binding_ifindex(&state, 12), 11);
    }

    #[test]
    fn tx_binding_resolution_uses_fabric_parent_ifindex() {
        let state = build_forwarding_state(&nat_snapshot_with_fabric());
        assert_eq!(resolve_tx_binding_ifindex(&state, 21), 21);
    }

    #[test]
    fn icmp_reverse_key_keeps_identifier_position() {
        let flow = SessionFlow {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            forward_key: SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_ICMP,
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
                src_port: 0x1234,
                dst_port: 0,
            },
        };
        let reverse = flow.reverse_key_with_nat(NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            ..NatDecision::default()
        });
        assert_eq!(reverse.src_ip, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)));
        assert_eq!(reverse.dst_ip, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)));
        assert_eq!(reverse.src_port, 0x1234);
        assert_eq!(reverse.dst_port, 0);
    }

    #[test]
    fn synced_replica_entry_marks_replica_synced() {
        let entry = SyncedSessionEntry {
            key: SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
                src_port: 12345,
                dst_port: 5201,
            },
            decision: SessionDecision {
                resolution: lookup_forwarding_resolution(
                    &build_forwarding_state(&nat_snapshot()),
                    IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
                ),
                nat: NatDecision {
                    rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                    ..NatDecision::default()
                },
            },
            metadata: SessionMetadata {
                ingress_zone: Arc::<str>::from("lan"),
                egress_zone: Arc::<str>::from("wan"),
                owner_rg_id: 1,
                is_reverse: false,
                synced: false,
                nat64_reverse: None,
            },
            protocol: PROTO_TCP,
            tcp_flags: 0,
        };
        let replica = synced_replica_entry(&entry);
        assert!(replica.metadata.synced);
        assert_eq!(replica.key, entry.key);
        assert_eq!(replica.decision, entry.decision);
    }

    #[test]
    fn resolution_target_uses_rewritten_destination_for_reverse_dnat() {
        let flow = SessionFlow {
            src_ip: IpAddr::V6("2001:559:8585:80::200".parse().expect("src")),
            dst_ip: IpAddr::V6("2001:559:8585:80::8".parse().expect("dst")),
            forward_key: SessionKey {
                addr_family: libc::AF_INET6 as u8,
                protocol: PROTO_ICMPV6,
                src_ip: IpAddr::V6("2001:559:8585:80::200".parse().expect("src")),
                dst_ip: IpAddr::V6("2001:559:8585:80::8".parse().expect("dst")),
                src_port: 0x1234,
                dst_port: 0,
            },
        };
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 5,
                tx_ifindex: 5,
                next_hop: Some(IpAddr::V6(
                    "2001:559:8585:ef00::100".parse().expect("next hop"),
                )),
                neighbor_mac: Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
                src_mac: None,
                tx_vlan_id: 0,
            },
            nat: NatDecision {
                rewrite_src: None,
                rewrite_dst: Some(IpAddr::V6("2001:559:8585:ef00::100".parse().expect("lan"))),
                ..NatDecision::default()
            },
        };
        assert_eq!(
            resolution_target_for_session(&flow, decision),
            IpAddr::V6("2001:559:8585:ef00::100".parse().expect("lan"))
        );
    }

    #[test]
    fn session_resolution_falls_back_to_cached_neighbor_on_miss() {
        let mut state = build_forwarding_state(&nat_snapshot());
        state.neighbors.clear();
        let flow = SessionFlow {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            forward_key: SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
                src_port: 12345,
                dst_port: 5201,
            },
        };
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))),
                neighbor_mac: Some([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]),
                src_mac: None,
                tx_vlan_id: 0,
            },
            nat: NatDecision::default(),
        };
        let resolved = lookup_forwarding_resolution_for_session(
            &state,
            &Arc::new(Mutex::new(FastMap::default())),
            &flow,
            decision,
        );
        let expected_src = state
            .egress
            .get(&12)
            .map(|egress| egress.src_mac)
            .expect("egress src mac");
        assert_eq!(
            resolved.disposition,
            ForwardingDisposition::ForwardCandidate
        );
        assert_eq!(resolved.egress_ifindex, 12);
        assert_eq!(resolved.tx_ifindex, 11);
        assert_eq!(resolved.neighbor_mac, decision.resolution.neighbor_mac);
        assert_eq!(resolved.src_mac, Some(expected_src));
        assert_eq!(resolved.tx_vlan_id, 80);
    }

    #[test]
    fn build_forwarded_frame_rewrites_l2_and_decrements_ttl() {
        let state = build_forwarding_state(&forwarding_snapshot(true));
        let resolution =
            lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(
            resolution.disposition,
            ForwardingDisposition::ForwardCandidate
        );

        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
            0,
            0x0800,
        );
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 64, 1, 0, 0, 192, 0, 2, 10, 8, 8, 8, 8,
            8, 0, 0, 0, 0x12, 0x34, 0x00, 0x01,
        ]);
        let sum = checksum16(&frame[14..34]);
        frame[24] = (sum >> 8) as u8;
        frame[25] = sum as u8;

        let mut area = MmapArea::new(4096).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            addr_family: libc::AF_INET as u8,
            ..UserspaceDpMeta::default()
        };
        let out = build_forwarded_frame(
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            &SessionDecision {
                resolution,
                nat: NatDecision::default(),
            },
            &state,
            None,
        )
        .expect("forwarded frame");
        assert_eq!(&out[0..6], &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(&out[6..12], &[0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]);
        assert_eq!(out[22], 63);
    }

    #[test]
    fn rewrite_forwarded_frame_in_place_reuses_rx_frame() {
        let state = build_forwarding_state(&forwarding_snapshot(true));
        let resolution =
            lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
            0,
            0x0800,
        );
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 64, 1, 0, 0, 192, 0, 2, 10, 8, 8, 8, 8,
            8, 0, 0, 0, 0x12, 0x34, 0x00, 0x01,
        ]);
        let sum = checksum16(&frame[14..34]);
        frame[24] = (sum >> 8) as u8;
        frame[25] = sum as u8;

        let mut area = MmapArea::new(4096).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            addr_family: libc::AF_INET as u8,
            ..UserspaceDpMeta::default()
        };
        let frame_len = rewrite_forwarded_frame_in_place(
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            &SessionDecision {
                resolution,
                nat: NatDecision::default(),
            },
            None,
        )
        .expect("in-place forward");
        let out = area.slice(0, frame_len as usize).expect("rewritten frame");
        assert_eq!(&out[0..6], &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(&out[6..12], &[0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]);
        assert_eq!(u16::from_be_bytes([out[12], out[13]]), 0x0800);
        assert_eq!(out[22], 63);
    }

    #[test]
    fn build_forwarded_frame_uses_fabric_header_without_nat() {
        let state = build_forwarding_state(&nat_snapshot_with_fabric());
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
            0,
            0x0800,
        );
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 64, 1, 0, 0, 10, 0, 61, 100, 172, 16,
            80, 200, 8, 0, 0, 0, 0x12, 0x34, 0x00, 0x01,
        ]);
        let sum = checksum16(&frame[14..34]);
        frame[24] = (sum >> 8) as u8;
        frame[25] = sum as u8;

        let mut area = MmapArea::new(4096).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            addr_family: libc::AF_INET as u8,
            ..UserspaceDpMeta::default()
        };
        let out = build_forwarded_frame(
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            &SessionDecision {
                resolution: ForwardingResolution {
                    disposition: ForwardingDisposition::FabricRedirect,
                    local_ifindex: 0,
                    egress_ifindex: 21,
                    tx_ifindex: 21,
                    next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2))),
                    neighbor_mac: Some([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]),
                    src_mac: Some([0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]),
                    tx_vlan_id: 0,
                },
                nat: NatDecision {
                    rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                    ..NatDecision::default()
                },
            },
            &state,
            None,
        )
        .expect("fabric frame");
        assert_eq!(&out[0..6], &[0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
        assert_eq!(&out[6..12], &[0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]);
        assert_eq!(&out[26..30], &[10, 0, 61, 100]);
        assert_eq!(out[22], 63);
    }

    fn tcp_checksum_ok_ipv4(packet: &[u8]) -> bool {
        let ihl = usize::from(packet[0] & 0x0f) * 4;
        let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
        let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
        checksum16_ipv4(src, dst, PROTO_TCP, &packet[ihl..]) == 0
    }

    fn icmpv6_checksum_ok(packet: &[u8]) -> bool {
        let src = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).expect("src"));
        let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).expect("dst"));
        checksum16_ipv6(src, dst, PROTO_ICMPV6, &packet[40..]) == 0
    }

    #[test]
    fn apply_nat_ipv4_recomputes_tcp_checksum() {
        let mut packet = vec![
            0x45, 0x00, 0x00, 0x30, 0x00, 0x01, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00, 10, 0, 61,
            102, 172, 16, 80, 200, 0x9c, 0x40, 0x14, 0x51, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x01, 0x50, 0x18, 0x20, 0x00, 0x00, 0x00, 0x00, b't', b'e', b's', b't', b'd',
            b'a', b't', b'a',
        ];
        let ip_sum = checksum16(&packet[..20]);
        packet[10] = (ip_sum >> 8) as u8;
        packet[11] = ip_sum as u8;
        recompute_l4_checksum_ipv4(&mut packet, 20, PROTO_TCP, false).expect("initial tcp sum");
        assert!(tcp_checksum_ok_ipv4(&packet));

        apply_nat_ipv4(
            &mut packet,
            PROTO_TCP,
            NatDecision { 
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                rewrite_dst: None,
             ..NatDecision::default() },
        )
        .expect("apply nat");

        assert_eq!(&packet[12..16], &[172, 16, 80, 8]);
        assert!(tcp_checksum_ok_ipv4(&packet));
    }

    #[test]
    fn extract_l3_packet_with_nat_rewrites_reverse_snat_reply_v4() {
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5],
            [0x02, 0xbf, 0x72, 0x00, 0x50, 0x08],
            80,
            0x0800,
        );
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x30, 0x00, 0x01, 0x00, 0x00, 63, PROTO_TCP, 0x00, 0x00, 172, 16, 80,
            200, 172, 16, 80, 8, 0x14, 0x51, 0x9c, 0x40, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x01, 0x50, 0x10, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, b't', b'e', b's', b't', b'd',
            b'a', b't', b'a',
        ]);
        let ip_sum = checksum16(&frame[18..38]);
        frame[28] = (ip_sum >> 8) as u8;
        frame[29] = ip_sum as u8;
        recompute_l4_checksum_ipv4(&mut frame[18..], 20, PROTO_TCP, false).expect("tcp sum");

        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 18,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            ..UserspaceDpMeta::default()
        };
        let packet = extract_l3_packet_with_nat(
            &frame,
            meta,
            NatDecision {
                rewrite_src: None,
                rewrite_dst: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
                ..NatDecision::default()
            },
        )
        .expect("slow-path packet");
        assert_eq!(&packet[12..16], &[172, 16, 80, 200]);
        assert_eq!(&packet[16..20], &[10, 0, 61, 102]);
        assert!(tcp_checksum_ok_ipv4(&packet));
    }

    #[test]
    fn extract_l3_packet_with_nat_rewrites_reverse_snat_reply_v6() {
        let src_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
        let dst_ip = "2001:559:8585:80::8".parse::<Ipv6Addr>().unwrap();
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5],
            [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
            80,
            0x86dd,
        );
        frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x20, PROTO_TCP, 63]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&[
            0x14, 0x51, 0x95, 0x2c, 0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x10,
            0x00, 0x40, 0x00, 0x00, 0x00, 0x00, b't', b'e', b's', b't', b'd', b'a', b't', b'a',
            b't', b'e', b's', b't',
        ]);
        recompute_l4_checksum_ipv6(&mut frame[18..], PROTO_TCP).expect("tcp sum");

        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 18,
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            ..UserspaceDpMeta::default()
        };
        let packet = extract_l3_packet_with_nat(
            &frame,
            meta,
            NatDecision {
                rewrite_src: None,
                rewrite_dst: Some(IpAddr::V6("2001:559:8585:ef00::102".parse().unwrap())),
                ..NatDecision::default()
            },
        )
        .expect("slow-path packet");
        assert_eq!(
            Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).unwrap()),
            src_ip
        );
        assert_eq!(
            Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).unwrap()),
            "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap()
        );
        assert!(tcp_checksum_ok_ipv6(&packet));
    }

    #[test]
    fn build_forwarded_frame_keeps_tcp_checksum_valid_after_snat() {
        let state = build_forwarding_state(&nat_snapshot());
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
            0,
            0x0800,
        );
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x30, 0x00, 0x01, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00, 10, 0, 61,
            102, 172, 16, 80, 200, 0x9c, 0x40, 0x14, 0x51, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x01, 0x50, 0x18, 0x20, 0x00, 0x00, 0x00, 0x00, b't', b'e', b's', b't', b'd',
            b'a', b't', b'a',
        ]);
        let ip_sum = checksum16(&frame[14..34]);
        frame[24] = (ip_sum >> 8) as u8;
        frame[25] = ip_sum as u8;
        recompute_l4_checksum_ipv4(&mut frame[14..], 20, PROTO_TCP, false).expect("tcp sum");

        let mut area = MmapArea::new(4096).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            ..UserspaceDpMeta::default()
        };
        let out = build_forwarded_frame(
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            &SessionDecision {
                resolution: ForwardingResolution {
                    disposition: ForwardingDisposition::ForwardCandidate,
                    local_ifindex: 0,
                    egress_ifindex: 12,
                    tx_ifindex: 11,
                    next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))),
                    neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
                    src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
                    tx_vlan_id: 80,
                },
                nat: NatDecision { 
                    rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                    rewrite_dst: None,
                 ..NatDecision::default() },
            },
            &state,
            None,
        )
        .expect("forwarded frame");

        assert_eq!(&out[30..34], &[172, 16, 80, 8]);
        assert_eq!(out[26], 63);
        assert!(tcp_checksum_ok_ipv4(&out[18..]));
    }

    #[test]
    fn rewrite_forwarded_frame_in_place_keeps_icmpv6_checksum_valid_after_snat() {
        let src_ip = "2001:559:8585:ef00::100".parse::<Ipv6Addr>().unwrap();
        let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();

        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
            0,
            0x86dd,
        );
        frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x08, PROTO_ICMPV6, 64]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&[128, 0, 0, 0, 0x12, 0x34, 0x00, 0x01]);
        let sum = checksum16_ipv6(src_ip, dst_ip, PROTO_ICMPV6, &frame[54..]);
        frame[56] = (sum >> 8) as u8;
        frame[57] = sum as u8;

        let mut area = MmapArea::new(4096).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_ICMPV6,
            ..UserspaceDpMeta::default()
        };
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 11,
                next_hop: Some(IpAddr::V6(dst_ip)),
                neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
                tx_vlan_id: 80,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V6("2001:559:8585:80::8".parse().unwrap())),
                ..NatDecision::default()
            },
        };
        let frame_len = rewrite_forwarded_frame_in_place(
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            &decision,
            None,
        )
        .expect("in-place v6 forward");
        let out = area.slice(0, frame_len as usize).expect("rewritten frame");
        assert_eq!(&out[0..6], &[0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]);
        assert_eq!(&out[6..12], &[0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]);
        assert_eq!(out[25], 63);
        assert_eq!(
            Ipv6Addr::from(<[u8; 16]>::try_from(&out[26..42]).unwrap()),
            "2001:559:8585:80::8".parse::<Ipv6Addr>().unwrap()
        );
        assert!(icmpv6_checksum_ok(&out[18..]));
    }

    fn tcp_ports_ipv6(packet: &[u8]) -> (u16, u16) {
        (
            u16::from_be_bytes([packet[40], packet[41]]),
            u16::from_be_bytes([packet[42], packet[43]]),
        )
    }

    fn tcp_checksum_ok_ipv6(packet: &[u8]) -> bool {
        let src = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).expect("v6 src"));
        let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).expect("v6 dst"));
        checksum16_ipv6(src, dst, PROTO_TCP, &packet[40..]) == 0
    }

    #[test]
    fn enforce_expected_ports_repairs_ipv6_tcp_ports_and_checksum() {
        let src_ip = "2001:559:8585:80::8".parse::<Ipv6Addr>().unwrap();
        let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5],
            [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
            80,
            0x86dd,
        );
        frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x20, PROTO_TCP, 63]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&[
            0x04, 0x01, 0x14, 0x51, // wrong src port 1025 -> 5201
            0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x18, 0x00, 0x40, 0x00, 0x00,
            0x00, 0x00, b't', b'e', b's', b't', b'd', b'a', b't', b'a', b't', b'e', b's', b't',
        ]);
        recompute_l4_checksum_ipv6(&mut frame[18..], PROTO_TCP).expect("initial checksum");
        assert!(tcp_checksum_ok_ipv6(&frame[18..]));

        let repaired = enforce_expected_ports(
            &mut frame,
            libc::AF_INET6 as u8,
            PROTO_TCP,
            Some((54688, 5201)),
        )
        .expect("repair");
        assert!(repaired);
        assert_eq!(tcp_ports_ipv6(&frame[18..]), (54688, 5201));
        assert!(tcp_checksum_ok_ipv6(&frame[18..]));
    }

    #[test]
    fn rewrite_forwarded_frame_in_place_keeps_ipv6_tcp_ports_after_vlan_snat() {
        let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
        let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
            0,
            0x86dd,
        );
        frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x20, PROTO_TCP, 64]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&[
            0xd5, 0xa0, 0x14, 0x51, // 54688 -> 5201
            0x31, 0x96, 0xc8, 0x32, // seq
            0x08, 0xf0, 0x5a, 0xc6, // ack
            0x50, 0x18, 0x00, 0x40, // data offset/flags/window
            0x00, 0x00, 0x00, 0x00, // checksum/urgent
            b't', b'e', b's', b't', b'd', b'a', b't', b'a', b't', b'e', b's', b't',
        ]);
        recompute_l4_checksum_ipv6(&mut frame[14..], PROTO_TCP).expect("tcp sum");
        assert!(tcp_checksum_ok_ipv6(&frame[14..]));

        let mut area = MmapArea::new(4096).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            l4_offset: 54,
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            flow_src_port: 54688,
            flow_dst_port: 5201,
            ..UserspaceDpMeta::default()
        };
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 11,
                next_hop: Some(IpAddr::V6(dst_ip)),
                neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
                tx_vlan_id: 80,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V6("2001:559:8585:80::8".parse().unwrap())),
                ..NatDecision::default()
            },
        };
        let frame_len = rewrite_forwarded_frame_in_place(
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            &decision,
            Some((54688, 5201)),
        )
        .expect("rewrite in place");
        let out = area.slice(0, frame_len as usize).expect("rewritten frame");
        assert_eq!(u16::from_be_bytes([out[12], out[13]]), 0x8100);
        assert_eq!(u16::from_be_bytes([out[14], out[15]]) & 0x0fff, 80);
        assert_eq!(u16::from_be_bytes([out[16], out[17]]), 0x86dd);
        assert_eq!(
            Ipv6Addr::from(<[u8; 16]>::try_from(&out[26..42]).unwrap()),
            "2001:559:8585:80::8".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(tcp_ports_ipv6(&out[18..]), (54688, 5201));
        assert!(tcp_checksum_ok_ipv6(&out[18..]));
    }

    #[test]
    fn build_forwarded_frame_into_keeps_ipv6_tcp_ports_after_vlan_snat() {
        let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
        let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
            0,
            0x86dd,
        );
        frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x20, PROTO_TCP, 64]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&[
            0xd5, 0xa0, 0x14, 0x51, // 54688 -> 5201
            0x31, 0x96, 0xc8, 0x32, // seq
            0x08, 0xf0, 0x5a, 0xc6, // ack
            0x50, 0x18, 0x00, 0x40, // data offset/flags/window
            0x00, 0x00, 0x00, 0x00, // checksum/urgent
            b't', b'e', b's', b't', b'd', b'a', b't', b'a', b't', b'e', b's', b't',
        ]);
        recompute_l4_checksum_ipv6(&mut frame[14..], PROTO_TCP).expect("tcp sum");
        assert!(tcp_checksum_ok_ipv6(&frame[14..]));

        let mut area = MmapArea::new(4096).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            l4_offset: 54,
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            flow_src_port: 54688,
            flow_dst_port: 5201,
            ..UserspaceDpMeta::default()
        };
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 11,
                next_hop: Some(IpAddr::V6(dst_ip)),
                neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
                tx_vlan_id: 80,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V6("2001:559:8585:80::8".parse().unwrap())),
                ..NatDecision::default()
            },
        };
        let mut out = [0u8; 256];
        let frame_len = build_forwarded_frame_into(
            &mut out,
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            &decision,
            Some((54688, 5201)),
        )
        .expect("build forwarded frame");
        let out = &out[..frame_len];
        assert_eq!(u16::from_be_bytes([out[12], out[13]]), 0x8100);
        assert_eq!(u16::from_be_bytes([out[14], out[15]]) & 0x0fff, 80);
        assert_eq!(u16::from_be_bytes([out[16], out[17]]), 0x86dd);
        assert_eq!(
            Ipv6Addr::from(<[u8; 16]>::try_from(&out[26..42]).unwrap()),
            "2001:559:8585:80::8".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(tcp_ports_ipv6(&out[18..]), (54688, 5201));
        assert!(tcp_checksum_ok_ipv6(&out[18..]));
    }

    #[test]
    fn build_forwarded_frame_into_ignores_ipv6_tcp_metadata_port_mismatch() {
        let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
        let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
        let real_src_port = 38276u16;
        let real_dst_port = 5201u16;
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
            0,
            0x86dd,
        );
        frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x20, PROTO_TCP, 64]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&real_src_port.to_be_bytes());
        frame.extend_from_slice(&real_dst_port.to_be_bytes());
        frame.extend_from_slice(&[
            0x31, 0x96, 0xc8, 0x32, // seq
            0x08, 0xf0, 0x5a, 0xc6, // ack
            0x50, 0x18, 0x00, 0x40, // data offset/flags/window
            0x00, 0x00, 0x00, 0x00, // checksum/urgent
            b't', b'e', b's', b't', b'd', b'a', b't', b'a', b't', b'e', b's', b't',
        ]);
        recompute_l4_checksum_ipv6(&mut frame[14..], PROTO_TCP).expect("tcp sum");

        let mut area = MmapArea::new(4096).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            l4_offset: 54,
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            flow_src_port: 1025,
            flow_dst_port: real_dst_port,
            ..UserspaceDpMeta::default()
        };
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 11,
                next_hop: Some(IpAddr::V6(dst_ip)),
                neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
                tx_vlan_id: 80,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V6("2001:559:8585:80::8".parse().unwrap())),
                ..NatDecision::default()
            },
        };
        let mut out = [0u8; 256];
        let frame_len = build_forwarded_frame_into(
            &mut out,
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            &decision,
            Some((real_src_port, real_dst_port)),
        )
        .expect("build forwarded frame");
        let out = &out[..frame_len];
        assert_eq!(tcp_ports_ipv6(&out[18..]), (real_src_port, real_dst_port));
        assert!(tcp_checksum_ok_ipv6(&out[18..]));
    }

    #[test]
    fn build_live_forward_request_prefers_session_flow_ports_over_frame() {
        let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
        let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
        let frame_src_port = 38276u16;
        let frame_dst_port = 5201u16;
        let session_src_port = 1025u16;
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
            0,
            0x86dd,
        );
        frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x20, PROTO_TCP, 64]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&frame_src_port.to_be_bytes());
        frame.extend_from_slice(&frame_dst_port.to_be_bytes());
        frame.extend_from_slice(&[
            0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x18, 0x00, 0x40, 0x00, 0x00,
            0x00, 0x00, b't', b'e', b's', b't', b'd', b'a', b't', b'a', b't', b'e', b's', b't',
        ]);
        recompute_l4_checksum_ipv6(&mut frame[14..], PROTO_TCP).expect("tcp sum");

        let mut area = MmapArea::new(4096).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            l4_offset: 54,
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            flow_src_port: session_src_port,
            flow_dst_port: frame_dst_port,
            ..UserspaceDpMeta::default()
        };
        // Session flow ports differ from frame ports — session is authoritative
        // because it is immune to UMEM DMA races.
        let session_flow = SessionFlow {
            src_ip: IpAddr::V6(src_ip),
            dst_ip: IpAddr::V6(dst_ip),
            forward_key: SessionKey {
                addr_family: libc::AF_INET6 as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V6(src_ip),
                dst_ip: IpAddr::V6(dst_ip),
                src_port: session_src_port,
                dst_port: frame_dst_port,
            },
        };
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 11,
                next_hop: Some(IpAddr::V6(dst_ip)),
                neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
                tx_vlan_id: 80,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V6("2001:559:8585:80::8".parse().unwrap())),
                ..NatDecision::default()
            },
        };
        let mut forwarding = ForwardingState::default();
        forwarding.egress.insert(
            12,
            EgressInterface {
                bind_ifindex: 11,
                vlan_id: 80,
                mtu: 1500,
                src_mac: [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
                zone: "wan".to_string(),
                redundancy_group: 1,
                primary_v4: None,
                primary_v6: Some("2001:559:8585:80::8".parse().unwrap()),
            },
        );
        let ingress = BindingIdentity {
            slot: 0,
            queue_id: 0,
            worker_id: 0,
            interface: Arc::<str>::from("ge-0-0-1"),
            ifindex: 10,
        };

        let req = build_live_forward_request(
            &area,
            &ingress,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            &decision,
            &forwarding,
            Some(&session_flow),
        )
        .expect("request");
        // Session flow ports (1025, 5201) take priority over frame ports (38276, 5201)
        assert_eq!(req.expected_ports, Some((session_src_port, frame_dst_port)));
    }

    #[test]
    fn build_live_forward_request_uses_live_frame_ports_when_no_session_flow() {
        let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
        let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
        let real_src_port = 38276u16;
        let real_dst_port = 5201u16;
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
            0,
            0x86dd,
        );
        frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x20, PROTO_TCP, 64]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&real_src_port.to_be_bytes());
        frame.extend_from_slice(&real_dst_port.to_be_bytes());
        frame.extend_from_slice(&[
            0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x18, 0x00, 0x40, 0x00, 0x00,
            0x00, 0x00, b't', b'e', b's', b't', b'd', b'a', b't', b'a', b't', b'e', b's', b't',
        ]);
        recompute_l4_checksum_ipv6(&mut frame[14..], PROTO_TCP).expect("tcp sum");

        let mut area = MmapArea::new(4096).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            l4_offset: 54,
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            flow_src_port: 1025,
            flow_dst_port: real_dst_port,
            ..UserspaceDpMeta::default()
        };
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 11,
                next_hop: Some(IpAddr::V6(dst_ip)),
                neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
                tx_vlan_id: 80,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V6("2001:559:8585:80::8".parse().unwrap())),
                ..NatDecision::default()
            },
        };
        let mut forwarding = ForwardingState::default();
        forwarding.egress.insert(
            12,
            EgressInterface {
                bind_ifindex: 11,
                vlan_id: 80,
                mtu: 1500,
                src_mac: [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
                zone: "wan".to_string(),
                redundancy_group: 1,
                primary_v4: None,
                primary_v6: Some("2001:559:8585:80::8".parse().unwrap()),
            },
        );
        let ingress = BindingIdentity {
            slot: 0,
            queue_id: 0,
            worker_id: 0,
            interface: Arc::<str>::from("ge-0-0-1"),
            ifindex: 10,
        };

        // No session flow — live frame ports should be used (over meta ports)
        let req = build_live_forward_request(
            &area,
            &ingress,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            &decision,
            &forwarding,
            None,
        )
        .expect("request");
        assert_eq!(req.expected_ports, Some((real_src_port, real_dst_port)));
    }

    #[test]
    fn build_live_forward_request_uses_flow_or_metadata_ports_when_frame_ports_unavailable() {
        let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
        let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
        let area = MmapArea::new(4096).expect("mmap");
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            l4_offset: 54,
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            flow_src_port: 1025,
            flow_dst_port: 5201,
            ..UserspaceDpMeta::default()
        };
        let flow = SessionFlow {
            src_ip: IpAddr::V6(src_ip),
            dst_ip: IpAddr::V6(dst_ip),
            forward_key: SessionKey {
                addr_family: libc::AF_INET6 as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V6(src_ip),
                dst_ip: IpAddr::V6(dst_ip),
                src_port: 54688,
                dst_port: 5201,
            },
        };
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 11,
                next_hop: Some(IpAddr::V6(dst_ip)),
                neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
                tx_vlan_id: 80,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V6("2001:559:8585:80::8".parse().unwrap())),
                ..NatDecision::default()
            },
        };
        let ingress_ident = BindingIdentity {
            slot: 0,
            queue_id: 0,
            worker_id: 0,
            interface: Arc::<str>::from("ge-0-0-1"),
            ifindex: 5,
        };
        let req = build_live_forward_request(
            &area,
            &ingress_ident,
            XdpDesc {
                addr: 0,
                len: 0,
                options: 0,
            },
            meta,
            &decision,
            &ForwardingState::default(),
            Some(&flow),
        )
        .expect("request");
        assert_eq!(req.expected_ports, Some((54688, 5201)));
    }

    #[test]
    fn build_forwarded_frame_into_keeps_ipv6_ports_when_frame_and_metadata_disagree() {
        let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
        let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
        let real_src_port = 0x0401u16;
        let real_dst_port = 5201u16;
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
            0,
            0x86dd,
        );
        frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x20, PROTO_TCP, 64]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&real_src_port.to_be_bytes());
        frame.extend_from_slice(&real_dst_port.to_be_bytes());
        frame.extend_from_slice(&[
            0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x18, 0x00, 0x40, 0x00, 0x00,
            0x00, 0x00, b't', b'e', b's', b't', b'd', b'a', b't', b'a', b't', b'e', b's', b't',
        ]);
        recompute_l4_checksum_ipv6(&mut frame[14..], PROTO_TCP).expect("tcp sum");

        let mut area = MmapArea::new(4096).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            l4_offset: 54,
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            flow_src_port: 54688,
            flow_dst_port: real_dst_port,
            ..UserspaceDpMeta::default()
        };
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 11,
                next_hop: Some(IpAddr::V6(dst_ip)),
                neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
                tx_vlan_id: 80,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V6("2001:559:8585:80::8".parse().unwrap())),
                ..NatDecision::default()
            },
        };
        let mut out = [0u8; 256];
        let frame_len = build_forwarded_frame_into(
            &mut out,
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            &decision,
            Some((real_src_port, real_dst_port)),
        )
        .expect("build forwarded frame");
        let out = &out[..frame_len];
        assert_eq!(tcp_ports_ipv6(&out[18..]), (real_src_port, real_dst_port));
        assert!(tcp_checksum_ok_ipv6(&out[18..]));
    }

    #[test]
    fn build_forwarded_frame_into_prefers_expected_ipv6_ports_over_wrong_live_ports() {
        let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
        let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
        let real_src_port = 42566u16;
        let real_dst_port = 5201u16;
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
            0,
            0x86dd,
        );
        frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x20, PROTO_TCP, 64]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&real_src_port.to_be_bytes());
        frame.extend_from_slice(&real_dst_port.to_be_bytes());
        frame.extend_from_slice(&[
            0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x18, 0x00, 0x40, 0x00, 0x00,
            0x00, 0x00, b't', b'e', b's', b't', b'd', b'a', b't', b'a', b't', b'e', b's', b't',
        ]);
        recompute_l4_checksum_ipv6(&mut frame[14..], PROTO_TCP).expect("tcp sum");

        let mut area = MmapArea::new(4096).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            l4_offset: 54,
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            flow_src_port: 1042,
            flow_dst_port: real_dst_port,
            ..UserspaceDpMeta::default()
        };
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 11,
                next_hop: Some(IpAddr::V6(dst_ip)),
                neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
                tx_vlan_id: 80,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V6("2001:559:8585:80::8".parse().unwrap())),
                ..NatDecision::default()
            },
        };
        let mut out = [0u8; 256];
        let frame_len = build_forwarded_frame_into(
            &mut out,
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            &decision,
            Some((1042, real_dst_port)),
        )
        .expect("build forwarded frame");
        let out = &out[..frame_len];
        assert_eq!(tcp_ports_ipv6(&out[18..]), (1042, real_dst_port));
        assert!(tcp_checksum_ok_ipv6(&out[18..]));
    }

    #[test]
    fn build_forwarded_frame_into_repairs_wrong_ipv6_frame_ports_from_expected_tuple() {
        let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
        let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
        let expected_src_port = 36394u16;
        let wrong_src_port = 1025u16;
        let dst_port = 5201u16;
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
            0,
            0x86dd,
        );
        frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x20, PROTO_TCP, 64]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&wrong_src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&[
            0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x18, 0x00, 0x40, 0x00, 0x00,
            0x00, 0x00, b't', b'e', b's', b't', b'd', b'a', b't', b'a', b't', b'e', b's', b't',
        ]);
        recompute_l4_checksum_ipv6(&mut frame[14..], PROTO_TCP).expect("tcp sum");

        let mut area = MmapArea::new(4096).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            l4_offset: 54,
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            flow_src_addr: src_ip.octets(),
            flow_dst_addr: dst_ip.octets(),
            flow_src_port: expected_src_port,
            flow_dst_port: dst_port,
            ..UserspaceDpMeta::default()
        };
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 11,
                next_hop: Some(IpAddr::V6(dst_ip)),
                neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
                tx_vlan_id: 80,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V6("2001:559:8585:80::8".parse().unwrap())),
                ..NatDecision::default()
            },
        };
        let mut out = [0u8; 256];
        let frame_len = build_forwarded_frame_into(
            &mut out,
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            &decision,
            Some((expected_src_port, dst_port)),
        )
        .expect("build forwarded frame");
        let out = &out[..frame_len];
        assert_eq!(tcp_ports_ipv6(&out[18..]), (expected_src_port, dst_port));
        assert!(tcp_checksum_ok_ipv6(&out[18..]));
    }

    #[test]
    fn build_forwarded_frame_into_ignores_wrong_ipv4_offsets() {
        let src_ip = Ipv4Addr::new(10, 0, 61, 102);
        let dst_ip = Ipv4Addr::new(172, 16, 80, 200);
        let real_src_port = 47032u16;
        let real_dst_port = 5201u16;
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
            0,
            0x0800,
        );
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x30, 0x12, 0x34, 0x00, 0x00, 64, PROTO_TCP, 0, 0,
        ]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&real_src_port.to_be_bytes());
        frame.extend_from_slice(&real_dst_port.to_be_bytes());
        frame.extend_from_slice(&[
            0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x18, 0x00, 0x40, 0x00, 0x00,
            0x00, 0x00, b't', b'e', b's', b't', b'd', b'a', b't', b'a',
        ]);
        let ip_sum = checksum16(&frame[14..34]);
        frame[24] = (ip_sum >> 8) as u8;
        frame[25] = ip_sum as u8;
        recompute_l4_checksum_ipv4(&mut frame[14..], 20, PROTO_TCP, false).expect("tcp sum");

        let mut area = MmapArea::new(4096).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 54,
            l4_offset: 74,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            flow_src_port: 1059,
            flow_dst_port: real_dst_port,
            ..UserspaceDpMeta::default()
        };
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 11,
                next_hop: Some(IpAddr::V4(dst_ip)),
                neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
                tx_vlan_id: 80,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                ..NatDecision::default()
            },
        };
        let mut out = [0u8; 256];
        let frame_len = build_forwarded_frame_into(
            &mut out,
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            &decision,
            Some((real_src_port, real_dst_port)),
        )
        .expect("build forwarded frame");
        let out = &out[..frame_len];
        let tcp = &out[18 + 20..];
        assert_eq!(
            (
                u16::from_be_bytes([tcp[0], tcp[1]]),
                u16::from_be_bytes([tcp[2], tcp[3]])
            ),
            (real_src_port, real_dst_port)
        );
    }

    #[test]
    fn segment_forwarded_tcp_frames_splits_ipv6_snat_payload_by_mtu() {
        let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
        let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
        let src_port = 54688u16;
        let dst_port = 5201u16;
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
            0,
            0x86dd,
        );
        let tcp_payload_len = 4096usize;
        let plen = (20 + tcp_payload_len) as u16;
        frame.extend_from_slice(&[
            0x60,
            0x00,
            0x00,
            0x00,
            (plen >> 8) as u8,
            plen as u8,
            PROTO_TCP,
            64,
        ]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&[
            0x31, 0x96, 0xc8, 0x32, // seq
            0x08, 0xf0, 0x5a, 0xc6, // ack
            0x50, 0x18, 0x00, 0x40, // data offset/flags/window
            0x00, 0x00, 0x00, 0x00, // checksum/urgent
        ]);
        frame.extend((0..tcp_payload_len).map(|i| (i & 0xff) as u8));
        recompute_l4_checksum_ipv6(&mut frame[14..], PROTO_TCP).expect("tcp sum");

        let mut area = MmapArea::new(8192).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            l4_offset: 54,
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            flow_src_port: 54688,
            flow_dst_port: 5201,
            ..UserspaceDpMeta::default()
        };
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 11,
                next_hop: Some(IpAddr::V6(dst_ip)),
                neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
                tx_vlan_id: 80,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V6("2001:559:8585:80::8".parse().unwrap())),
                ..NatDecision::default()
            },
        };
        let mut forwarding = ForwardingState::default();
        forwarding.egress.insert(
            12,
            EgressInterface {
                bind_ifindex: 11,
                vlan_id: 80,
                mtu: 1500,
                src_mac: [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
                zone: "wan".to_string(),
                redundancy_group: 1,
                primary_v4: None,
                primary_v6: Some("2001:559:8585:80::8".parse().unwrap()),
            },
        );

        let segments = segment_forwarded_tcp_frames(
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            &decision,
            &forwarding,
            Some((src_port, dst_port)),
        )
        .expect("segmented");
        assert!(segments.len() > 1);
        let mut expected_seq = 0x3196c832u32;
        let mut total_payload = 0usize;
        for (idx, seg) in segments.iter().enumerate() {
            assert!(seg.len() <= 18 + 1500);
            assert_eq!(tcp_ports_ipv6(&seg[18..]), (54688, 5201));
            assert!(tcp_checksum_ok_ipv6(&seg[18..]));
            let tcp = &seg[18 + 40..];
            let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
            assert_eq!(seq, expected_seq);
            let seg_payload = seg.len() - 18 - 40 - 20;
            total_payload += seg_payload;
            expected_seq = expected_seq.wrapping_add(seg_payload as u32);
            if idx + 1 != segments.len() {
                assert_eq!(tcp[13] & TCP_FLAG_PSH, 0);
            }
        }
        assert_eq!(total_payload, tcp_payload_len);
    }

    #[test]
    fn segment_forwarded_tcp_frames_repairs_ipv6_tcp_ports_when_metadata_disagrees() {
        let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
        let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
        let src_port = 38276u16;
        let dst_port = 5201u16;
        let tcp_payload_len = 4096usize;
        let plen = (20 + tcp_payload_len) as u16;
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
            0,
            0x86dd,
        );
        frame.extend_from_slice(&[
            0x60,
            0x00,
            0x00,
            0x00,
            (plen >> 8) as u8,
            plen as u8,
            PROTO_TCP,
            64,
        ]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&[
            0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x18, 0x00, 0x40, 0x00, 0x00,
            0x00, 0x00,
        ]);
        frame.extend((0..tcp_payload_len).map(|i| (i & 0xff) as u8));
        recompute_l4_checksum_ipv6(&mut frame[14..], PROTO_TCP).expect("tcp sum");

        let mut area = MmapArea::new(8192).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            l4_offset: 54,
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            flow_src_port: 1025,
            flow_dst_port: dst_port,
            ..UserspaceDpMeta::default()
        };
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 11,
                next_hop: Some(IpAddr::V6(dst_ip)),
                neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
                tx_vlan_id: 80,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V6("2001:559:8585:80::8".parse().unwrap())),
                ..NatDecision::default()
            },
        };
        let mut forwarding = ForwardingState::default();
        forwarding.egress.insert(
            12,
            EgressInterface {
                bind_ifindex: 11,
                vlan_id: 80,
                mtu: 1500,
                src_mac: [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
                zone: "wan".to_string(),
                redundancy_group: 1,
                primary_v4: None,
                primary_v6: Some("2001:559:8585:80::8".parse().unwrap()),
            },
        );
        let segments = segment_forwarded_tcp_frames(
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            &decision,
            &forwarding,
            Some((src_port, dst_port)),
        )
        .expect("segmented");
        assert!(segments.len() > 1);
        for seg in &segments {
            assert_eq!(tcp_ports_ipv6(&seg[18..]), (src_port, dst_port));
            assert!(tcp_checksum_ok_ipv6(&seg[18..]));
        }
    }

    #[test]
    fn segment_forwarded_tcp_frames_prefers_expected_ipv6_ports_over_wrong_live_ports() {
        let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
        let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
        let src_port = 42566u16;
        let dst_port = 5201u16;
        let tcp_payload_len = 4096usize;
        let plen = (20 + tcp_payload_len) as u16;
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
            0,
            0x86dd,
        );
        frame.extend_from_slice(&[
            0x60,
            0x00,
            0x00,
            0x00,
            (plen >> 8) as u8,
            plen as u8,
            PROTO_TCP,
            64,
        ]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&[
            0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x18, 0x00, 0x40, 0x00, 0x00,
            0x00, 0x00,
        ]);
        frame.extend((0..tcp_payload_len).map(|i| (i & 0xff) as u8));
        recompute_l4_checksum_ipv6(&mut frame[14..], PROTO_TCP).expect("tcp sum");

        let mut area = MmapArea::new(8192).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            l4_offset: 54,
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            flow_src_port: 1042,
            flow_dst_port: dst_port,
            ..UserspaceDpMeta::default()
        };
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 11,
                next_hop: Some(IpAddr::V6(dst_ip)),
                neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
                tx_vlan_id: 80,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V6("2001:559:8585:80::8".parse().unwrap())),
                ..NatDecision::default()
            },
        };
        let mut forwarding = ForwardingState::default();
        forwarding.egress.insert(
            12,
            EgressInterface {
                bind_ifindex: 11,
                vlan_id: 80,
                mtu: 1500,
                src_mac: [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
                zone: "wan".to_string(),
                redundancy_group: 1,
                primary_v4: None,
                primary_v6: Some("2001:559:8585:80::8".parse().unwrap()),
            },
        );
        let segments = segment_forwarded_tcp_frames(
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            &decision,
            &forwarding,
            Some((1042, dst_port)),
        )
        .expect("segmented");
        assert!(segments.len() > 1);
        for seg in &segments {
            assert_eq!(tcp_ports_ipv6(&seg[18..]), (1042, dst_port));
            assert!(tcp_checksum_ok_ipv6(&seg[18..]));
        }
    }

    #[test]
    fn segment_forwarded_tcp_frames_repairs_wrong_ipv6_frame_ports_from_expected_tuple() {
        let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
        let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
        let expected_src_port = 36394u16;
        let wrong_src_port = 1025u16;
        let dst_port = 5201u16;
        let tcp_payload_len = 4096usize;
        let plen = (20 + tcp_payload_len) as u16;
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
            0,
            0x86dd,
        );
        frame.extend_from_slice(&[
            0x60,
            0x00,
            0x00,
            0x00,
            (plen >> 8) as u8,
            plen as u8,
            PROTO_TCP,
            64,
        ]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&wrong_src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&[
            0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x18, 0x00, 0x40, 0x00, 0x00,
            0x00, 0x00,
        ]);
        frame.extend((0..tcp_payload_len).map(|i| (i & 0xff) as u8));
        recompute_l4_checksum_ipv6(&mut frame[14..], PROTO_TCP).expect("tcp sum");

        let mut area = MmapArea::new(8192).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            l4_offset: 54,
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            flow_src_addr: src_ip.octets(),
            flow_dst_addr: dst_ip.octets(),
            flow_src_port: expected_src_port,
            flow_dst_port: dst_port,
            ..UserspaceDpMeta::default()
        };
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 11,
                next_hop: Some(IpAddr::V6(dst_ip)),
                neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
                tx_vlan_id: 80,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V6("2001:559:8585:80::8".parse().unwrap())),
                ..NatDecision::default()
            },
        };
        let mut forwarding = ForwardingState::default();
        forwarding.egress.insert(
            12,
            EgressInterface {
                bind_ifindex: 11,
                vlan_id: 80,
                mtu: 1500,
                src_mac: [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
                zone: "wan".to_string(),
                redundancy_group: 1,
                primary_v4: None,
                primary_v6: Some("2001:559:8585:80::8".parse().unwrap()),
            },
        );
        let segments = segment_forwarded_tcp_frames(
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            &decision,
            &forwarding,
            Some((expected_src_port, dst_port)),
        )
        .expect("segmented");
        assert!(segments.len() > 1);
        for seg in &segments {
            assert_eq!(tcp_ports_ipv6(&seg[18..]), (expected_src_port, dst_port));
            assert!(tcp_checksum_ok_ipv6(&seg[18..]));
        }
    }

    #[test]
    fn authoritative_forward_ports_prefers_flow_tuple_when_frame_ports_mismatch() {
        let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
        let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
        let expected_src_port = 55068u16;
        let wrong_src_port = 1041u16;
        let dst_port = 5201u16;
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
            0,
            0x86dd,
        );
        frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x20, PROTO_TCP, 64]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&wrong_src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&[
            0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x18, 0x00, 0x40, 0x00, 0x00,
            0x00, 0x00, b't', b'e', b's', b't', b'd', b'a', b't', b'a', b't', b'e', b's', b't',
        ]);
        recompute_l4_checksum_ipv6(&mut frame[14..], PROTO_TCP).expect("tcp sum");

        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            l4_offset: 54,
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            flow_src_addr: src_ip.octets(),
            flow_dst_addr: dst_ip.octets(),
            flow_src_port: expected_src_port,
            flow_dst_port: dst_port,
            ..UserspaceDpMeta::default()
        };
        let flow = SessionFlow {
            src_ip: IpAddr::V6(src_ip),
            dst_ip: IpAddr::V6(dst_ip),
            forward_key: SessionKey {
                addr_family: libc::AF_INET6 as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V6(src_ip),
                dst_ip: IpAddr::V6(dst_ip),
                src_port: expected_src_port,
                dst_port,
            },
        };

        assert_eq!(
            authoritative_forward_ports(&frame, meta, Some(&flow)),
            Some((expected_src_port, dst_port))
        );
    }

    #[test]
    fn parse_session_flow_prefers_metadata_tuple_when_frame_ports_mismatch() {
        let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
        let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
        let expected_src_port = 55068u16;
        let wrong_src_port = 1041u16;
        let dst_port = 5201u16;
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
            0,
            0x86dd,
        );
        frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x20, PROTO_TCP, 64]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&wrong_src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&[
            0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x18, 0x00, 0x40, 0x00, 0x00,
            0x00, 0x00, b't', b'e', b's', b't', b'd', b'a', b't', b'a', b't', b'e', b's', b't',
        ]);
        recompute_l4_checksum_ipv6(&mut frame[14..], PROTO_TCP).expect("tcp sum");

        let mut area = MmapArea::new(4096).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            l4_offset: 54,
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            flow_src_addr: src_ip.octets(),
            flow_dst_addr: dst_ip.octets(),
            flow_src_port: expected_src_port,
            flow_dst_port: dst_port,
            ..UserspaceDpMeta::default()
        };
        let flow = parse_session_flow(
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
        )
        .expect("flow");
        assert_eq!(flow.forward_key.src_port, expected_src_port);
        assert_eq!(flow.forward_key.dst_port, dst_port);
    }

    #[test]
    fn segment_forwarded_tcp_frames_keeps_ipv4_tcp_ports_after_vlan_snat() {
        let src_ip = Ipv4Addr::new(10, 0, 61, 102);
        let dst_ip = Ipv4Addr::new(172, 16, 80, 200);
        let src_port = 47308u16;
        let dst_port = 5201u16;
        let tcp_payload_len = 30_408usize;
        let tcp_header_len = 32usize;
        let total_len = (20 + tcp_header_len + tcp_payload_len) as u16;

        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x36, 0xe4, 0x2b, 0xd5, 0x39, 0xe6],
            0,
            0x0800,
        );
        frame.extend_from_slice(&[
            0x45,
            0x00,
            (total_len >> 8) as u8,
            total_len as u8,
            0xd1,
            0x43,
            0x40,
            0x00,
            64,
            PROTO_TCP,
            0x00,
            0x00,
        ]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&[
            0x52, 0x04, 0xc1, 0xa3, // seq
            0x73, 0x7f, 0x63, 0x1c, // ack
            0x80, 0x10, 0x00, 0x3f, // data offset/flags/window
            0x00, 0x00, 0x00, 0x00, // checksum/urgent
            0x01, 0x01, 0x08, 0x0a, // TCP timestamp option
            0x91, 0x9b, 0x0d, 0x5f, 0xd3, 0x53, 0x0f, 0x7f,
        ]);
        frame.extend((0..tcp_payload_len).map(|i| (i & 0xff) as u8));
        let ip_sum = checksum16(&frame[14..34]);
        frame[24] = (ip_sum >> 8) as u8;
        frame[25] = ip_sum as u8;
        recompute_l4_checksum_ipv4(&mut frame[14..], 20, PROTO_TCP, false).expect("tcp sum");

        let mut area = MmapArea::new(65_536).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            l4_offset: 34,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            flow_src_port: 1041,
            flow_dst_port: dst_port,
            ..UserspaceDpMeta::default()
        };
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 11,
                next_hop: Some(IpAddr::V4(dst_ip)),
                neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x16, 0x01, 0x00]),
                tx_vlan_id: 80,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                ..NatDecision::default()
            },
        };
        let mut forwarding = ForwardingState::default();
        forwarding.egress.insert(
            12,
            EgressInterface {
                bind_ifindex: 11,
                vlan_id: 80,
                mtu: 1500,
                src_mac: [0x02, 0xbf, 0x72, 0x16, 0x01, 0x00],
                zone: "wan".to_string(),
                redundancy_group: 1,
                primary_v4: Some(Ipv4Addr::new(172, 16, 80, 8)),
                primary_v6: None,
            },
        );

        let segments = segment_forwarded_tcp_frames(
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            &decision,
            &forwarding,
            Some((src_port, dst_port)),
        )
        .expect("segmented");
        assert!(segments.len() > 1);
        let mut total_payload = 0usize;
        let mut expected_seq = 0x5204c1a3u32;
        for seg in &segments {
            assert!(seg.len() <= 18 + 1500);
            let tcp = &seg[18 + 20..];
            assert_eq!(
                (
                    u16::from_be_bytes([tcp[0], tcp[1]]),
                    u16::from_be_bytes([tcp[2], tcp[3]])
                ),
                (src_port, dst_port)
            );
            assert!(tcp_checksum_ok_ipv4(&seg[18..]));
            let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
            assert_eq!(seq, expected_seq);
            let seg_payload = seg.len() - 18 - 20 - tcp_header_len;
            total_payload += seg_payload;
            expected_seq = expected_seq.wrapping_add(seg_payload as u32);
        }
        assert_eq!(total_payload, tcp_payload_len);
    }

    #[test]
    fn rewrite_forwarded_frame_in_place_keeps_tcp_checksum_valid_after_vlan_snat() {
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
            0,
            0x0800,
        );
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x30, 0x00, 0x01, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00, 10, 0, 61,
            102, 172, 16, 80, 200, 0x9c, 0x40, 0x14, 0x51, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x50, 0x02, 0x20, 0x00, 0x00, 0x00, 0x00, b't', b'e', b's', b't', b'd',
            b'a', b't', b'a',
        ]);
        let ip_sum = checksum16(&frame[14..34]);
        frame[24] = (ip_sum >> 8) as u8;
        frame[25] = ip_sum as u8;
        recompute_l4_checksum_ipv4(&mut frame[14..], 20, PROTO_TCP, false).expect("tcp sum");
        assert!(tcp_checksum_ok_ipv4(&frame[14..]));

        let mut area = MmapArea::new(4096).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            ..UserspaceDpMeta::default()
        };
        let frame_len = rewrite_forwarded_frame_in_place(
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            &SessionDecision {
                resolution: ForwardingResolution {
                    disposition: ForwardingDisposition::ForwardCandidate,
                    local_ifindex: 0,
                    egress_ifindex: 12,
                    tx_ifindex: 11,
                    next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))),
                    neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
                    src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
                    tx_vlan_id: 80,
                },
                nat: NatDecision { 
                    rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                    rewrite_dst: None,
                 ..NatDecision::default() },
            },
            None,
        )
        .expect("rewrite in place");

        let out = area.slice(0, frame_len as usize).expect("rewritten frame");
        assert_eq!(u16::from_be_bytes([out[12], out[13]]), 0x8100);
        assert_eq!(u16::from_be_bytes([out[14], out[15]]) & 0x0fff, 80);
        assert_eq!(u16::from_be_bytes([out[16], out[17]]), 0x0800);
        assert_eq!(&out[30..34], &[172, 16, 80, 8]);
        assert_eq!(out[26], 63);
        assert!(tcp_checksum_ok_ipv4(&out[18..]));
    }

    #[test]
    fn rewrite_forwarded_frame_in_place_keeps_tcp_checksum_valid_after_vlan_dnat() {
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x10, 0xdb, 0xff, 0x10, 0x01],
            80,
            0x0800,
        );
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x30, 0x00, 0x02, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00, 172, 16, 80,
            200, 172, 16, 80, 8, 0x14, 0x51, 0x9c, 0x40, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
            0x02, 0x50, 0x12, 0x20, 0x00, 0x00, 0x00, 0x00, b't', b'e', b's', b't', b'd', b'a',
            b't', b'a',
        ]);
        let ip_sum = checksum16(&frame[18..38]);
        frame[28] = (ip_sum >> 8) as u8;
        frame[29] = ip_sum as u8;
        recompute_l4_checksum_ipv4(&mut frame[18..], 20, PROTO_TCP, false).expect("tcp sum");
        assert!(tcp_checksum_ok_ipv4(&frame[18..]));

        let mut area = MmapArea::new(4096).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 18,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            ..UserspaceDpMeta::default()
        };
        let frame_len = rewrite_forwarded_frame_in_place(
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            &SessionDecision {
                resolution: ForwardingResolution {
                    disposition: ForwardingDisposition::ForwardCandidate,
                    local_ifindex: 0,
                    egress_ifindex: 5,
                    tx_ifindex: 5,
                    next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
                    neighbor_mac: Some([0x02, 0x66, 0x6a, 0x82, 0xfb, 0x2f]),
                    src_mac: Some([0x02, 0xbf, 0x72, 0x01, 0x01, 0x00]),
                    tx_vlan_id: 0,
                },
                nat: NatDecision {
                    rewrite_src: None,
                    rewrite_dst: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
                    ..NatDecision::default()
                },
            },
            None,
        )
        .expect("rewrite in place");

        let out = area.slice(0, frame_len as usize).expect("rewritten frame");
        assert_eq!(u16::from_be_bytes([out[12], out[13]]), 0x0800);
        assert_eq!(&out[30..34], &[10, 0, 61, 102]);
        assert_eq!(out[22], 63);
        assert!(tcp_checksum_ok_ipv4(&out[14..]));
    }

    // --- Static NAT integration tests ---

    fn static_nat_snapshot() -> ConfigSnapshot {
        ConfigSnapshot {
            zones: vec![
                ZoneSnapshot {
                    name: "trust".to_string(),
                    id: 1,
                },
                ZoneSnapshot {
                    name: "untrust".to_string(),
                    id: 2,
                },
            ],
            interfaces: vec![
                InterfaceSnapshot {
                    name: "ge-0/0/0".to_string(),
                    zone: "trust".to_string(),
                    linux_name: "ge-0-0-0".to_string(),
                    ifindex: 5,
                    hardware_addr: "02:bf:72:01:00:00".to_string(),
                    addresses: vec![InterfaceAddressSnapshot {
                        family: "inet".to_string(),
                        address: "192.168.1.1/24".to_string(),
                        scope: 0,
                    }],
                    ..Default::default()
                },
                InterfaceSnapshot {
                    name: "ge-0/0/1".to_string(),
                    zone: "untrust".to_string(),
                    linux_name: "ge-0-0-1".to_string(),
                    ifindex: 6,
                    hardware_addr: "02:bf:72:01:00:01".to_string(),
                    addresses: vec![InterfaceAddressSnapshot {
                        family: "inet".to_string(),
                        address: "203.0.113.1/24".to_string(),
                        scope: 0,
                    }],
                    ..Default::default()
                },
            ],
            routes: vec![RouteSnapshot {
                table: "inet.0".to_string(),
                family: "inet".to_string(),
                destination: "0.0.0.0/0".to_string(),
                next_hops: vec!["203.0.113.254@ge-0/0/1".to_string()],
                discard: false,
                next_table: String::new(),
            }],
            static_nat_rules: vec![StaticNATRuleSnapshot {
                name: "web-server".to_string(),
                from_zone: "untrust".to_string(),
                external_ip: "203.0.113.10".to_string(),
                internal_ip: "192.168.1.10".to_string(),
            }],
            default_policy: "deny".to_string(),
            policies: vec![
                PolicyRuleSnapshot {
                    name: "allow-inbound".to_string(),
                    from_zone: "untrust".to_string(),
                    to_zone: "trust".to_string(),
                    source_addresses: vec!["any".to_string()],
                    destination_addresses: vec!["any".to_string()],
                    applications: vec!["any".to_string()],
                    action: "permit".to_string(),
                    ..Default::default()
                },
                PolicyRuleSnapshot {
                    name: "allow-outbound".to_string(),
                    from_zone: "trust".to_string(),
                    to_zone: "untrust".to_string(),
                    source_addresses: vec!["any".to_string()],
                    destination_addresses: vec!["any".to_string()],
                    applications: vec!["any".to_string()],
                    action: "permit".to_string(),
                    ..Default::default()
                },
            ],
            neighbors: vec![
                NeighborSnapshot {
                    interface: "ge-0-0-0".to_string(),
                    ifindex: 5,
                    family: "inet".to_string(),
                    ip: "192.168.1.10".to_string(),
                    mac: "aa:bb:cc:dd:ee:10".to_string(),
                    state: "reachable".to_string(),
                    ..Default::default()
                },
                NeighborSnapshot {
                    interface: "ge-0-0-1".to_string(),
                    ifindex: 6,
                    family: "inet".to_string(),
                    ip: "203.0.113.254".to_string(),
                    mac: "aa:bb:cc:dd:ee:fe".to_string(),
                    state: "reachable".to_string(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        }
    }

    #[test]
    fn static_nat_external_ip_recognized_as_local() {
        let state = build_forwarding_state(&static_nat_snapshot());
        // The external IP 203.0.113.10 should be in local_v4 so traffic
        // destined to it is recognized by the firewall.
        assert!(
            state.local_v4.contains(&"203.0.113.10".parse::<Ipv4Addr>().unwrap()),
            "static NAT external IP must be in local_v4"
        );
    }

    #[test]
    fn static_nat_dnat_routes_to_internal_ip() {
        let state = build_forwarding_state(&static_nat_snapshot());
        // Simulate inbound: packet from 198.51.100.1 -> 203.0.113.10
        // The static NAT DNAT should match and the resolution should route
        // to the internal host 192.168.1.10 (on trust interface ifindex=5).
        let dnat = state
            .static_nat
            .match_dnat("203.0.113.10".parse().unwrap(), "untrust");
        assert!(dnat.is_some(), "DNAT must match external IP from untrust");
        let dnat = dnat.unwrap();
        assert_eq!(
            dnat.rewrite_dst,
            Some("192.168.1.10".parse::<IpAddr>().unwrap())
        );

        // After DNAT translation, resolution target is internal IP
        let internal_ip: IpAddr = "192.168.1.10".parse().unwrap();
        let resolution =
            lookup_forwarding_resolution_with_dynamic(&state, &Default::default(), internal_ip);
        // Should resolve to trust interface (ifindex 5) via connected route
        assert_eq!(resolution.egress_ifindex, 5);
    }

    #[test]
    fn static_nat_snat_rewrites_outbound_source() {
        let state = build_forwarding_state(&static_nat_snapshot());
        // Simulate outbound: packet from 192.168.1.10 -> 198.51.100.1
        // coming from trust zone. Static NAT SNAT should rewrite src
        // to external IP 203.0.113.10.
        // SNAT does not check from_zone -- internal IP match is sufficient.
        let snat = state
            .static_nat
            .match_snat("192.168.1.10".parse().unwrap(), "trust");
        assert!(snat.is_some(), "SNAT should match internal IP regardless of zone");
        assert_eq!(
            snat.unwrap().rewrite_src,
            Some("203.0.113.10".parse::<IpAddr>().unwrap())
        );
    }

    #[test]
    fn static_nat_snat_matches_when_zone_is_empty() {
        // Create a snapshot where from_zone is empty (matches any zone)
        let mut snapshot = static_nat_snapshot();
        snapshot.static_nat_rules = vec![StaticNATRuleSnapshot {
            name: "web-server".to_string(),
            from_zone: String::new(), // matches any zone
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "192.168.1.10".to_string(),
        }];
        let state = build_forwarding_state(&snapshot);

        // Now SNAT should match from any zone
        let snat = state
            .static_nat
            .match_snat("192.168.1.10".parse().unwrap(), "trust");
        assert!(snat.is_some());
        let snat = snat.unwrap();
        assert_eq!(
            snat.rewrite_src,
            Some("203.0.113.10".parse::<IpAddr>().unwrap())
        );
        assert!(snat.rewrite_dst.is_none());
    }

    #[test]
    fn static_nat_takes_priority_over_interface_snat() {
        // Create snapshot with both static NAT and interface SNAT
        let mut snapshot = static_nat_snapshot();
        snapshot.static_nat_rules = vec![StaticNATRuleSnapshot {
            name: "static-web".to_string(),
            from_zone: String::new(),
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "192.168.1.10".to_string(),
        }];
        snapshot.source_nat_rules = vec![SourceNATRuleSnapshot {
            name: "interface-snat".to_string(),
            from_zone: "trust".to_string(),
            to_zone: "untrust".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            interface_mode: true,
            ..Default::default()
        }];
        let state = build_forwarding_state(&snapshot);

        // For src=192.168.1.10, static NAT should match first
        let static_match = state
            .static_nat
            .match_snat("192.168.1.10".parse().unwrap(), "trust");
        assert!(
            static_match.is_some(),
            "static NAT should match internal IP"
        );
        assert_eq!(
            static_match.unwrap().rewrite_src,
            Some("203.0.113.10".parse::<IpAddr>().unwrap())
        );
    }

    #[test]
    fn static_nat_v6_dnat_and_snat() {
        let mut snapshot = static_nat_snapshot();
        snapshot.static_nat_rules = vec![StaticNATRuleSnapshot {
            name: "v6-server".to_string(),
            from_zone: String::new(),
            external_ip: "2001:db8::10".to_string(),
            internal_ip: "fd00::10".to_string(),
        }];
        // Add v6 addresses to interfaces
        snapshot.interfaces[0].addresses.push(InterfaceAddressSnapshot {
            family: "inet6".to_string(),
            address: "fd00::1/64".to_string(),
            scope: 0,
        });
        snapshot.interfaces[1].addresses.push(InterfaceAddressSnapshot {
            family: "inet6".to_string(),
            address: "2001:db8::1/64".to_string(),
            scope: 0,
        });
        let state = build_forwarding_state(&snapshot);

        // External v6 IP should be in local_v6
        assert!(state
            .local_v6
            .contains(&"2001:db8::10".parse::<Ipv6Addr>().unwrap()));

        // DNAT match
        let dnat = state
            .static_nat
            .match_dnat("2001:db8::10".parse().unwrap(), "any-zone");
        assert!(dnat.is_some());
        assert_eq!(
            dnat.unwrap().rewrite_dst,
            Some("fd00::10".parse::<IpAddr>().unwrap())
        );

        // SNAT match
        let snat = state
            .static_nat
            .match_snat("fd00::10".parse().unwrap(), "trust");
        assert!(snat.is_some());
        assert_eq!(
            snat.unwrap().rewrite_src,
            Some("2001:db8::10".parse::<IpAddr>().unwrap())
        );
    }

    #[test]
    fn is_icmp_error_identifies_v4_types() {
        // ICMPv4 error types
        assert!(is_icmp_error(PROTO_ICMP, 3));  // Destination Unreachable
        assert!(is_icmp_error(PROTO_ICMP, 11)); // Time Exceeded
        assert!(is_icmp_error(PROTO_ICMP, 12)); // Parameter Problem
        // Non-error types
        assert!(!is_icmp_error(PROTO_ICMP, 0));  // Echo Reply
        assert!(!is_icmp_error(PROTO_ICMP, 8));  // Echo Request
    }

    #[test]
    fn is_icmp_error_identifies_v6_types() {
        // ICMPv6 error types
        assert!(is_icmp_error(PROTO_ICMPV6, 1)); // Destination Unreachable
        assert!(is_icmp_error(PROTO_ICMPV6, 2)); // Packet Too Big
        assert!(is_icmp_error(PROTO_ICMPV6, 3)); // Time Exceeded
        assert!(is_icmp_error(PROTO_ICMPV6, 4)); // Parameter Problem
        // Non-error types
        assert!(!is_icmp_error(PROTO_ICMPV6, 128)); // Echo Request
        assert!(!is_icmp_error(PROTO_ICMPV6, 129)); // Echo Reply
    }

    #[test]
    fn is_icmp_error_rejects_non_icmp_protocols() {
        assert!(!is_icmp_error(PROTO_TCP, 3));
        assert!(!is_icmp_error(PROTO_UDP, 3));
    }

    #[test]
    fn forwarding_state_includes_session_timeouts() {
        let snapshot = nat_snapshot();
        let state = build_forwarding_state(&snapshot);
        // Default timeouts when snapshot has 0 values
        assert_eq!(state.session_timeouts.tcp_established_ns, 300_000_000_000);
        assert_eq!(state.session_timeouts.udp_ns, 60_000_000_000);
        assert_eq!(state.session_timeouts.icmp_ns, 15_000_000_000);
    }

    #[test]
    fn forwarding_state_custom_session_timeouts() {
        let mut snapshot = nat_snapshot();
        snapshot.flow.tcp_session_timeout = 120;
        snapshot.flow.udp_session_timeout = 30;
        snapshot.flow.icmp_session_timeout = 5;
        let state = build_forwarding_state(&snapshot);
        assert_eq!(state.session_timeouts.tcp_established_ns, 120_000_000_000);
        assert_eq!(state.session_timeouts.udp_ns, 30_000_000_000);
        assert_eq!(state.session_timeouts.icmp_ns, 5_000_000_000);
    }

    #[test]
    fn forwarding_state_allow_embedded_icmp_wired() {
        let mut snapshot = nat_snapshot();
        assert!(!build_forwarding_state(&snapshot).allow_embedded_icmp);
        snapshot.flow.allow_embedded_icmp = true;
        assert!(build_forwarding_state(&snapshot).allow_embedded_icmp);
    }

    fn build_icmp_echo_frame_v4(src: Ipv4Addr, dst: Ipv4Addr, ttl: u8) -> Vec<u8> {
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
            0,
            0x0800,
        );
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, ttl, PROTO_ICMP, 0x00, 0x00,
        ]);
        frame.extend_from_slice(&src.octets());
        frame.extend_from_slice(&dst.octets());
        let ip_csum = checksum16(&frame[14..34]);
        frame[24..26].copy_from_slice(&ip_csum.to_be_bytes());
        let icmp_start = frame.len();
        frame.extend_from_slice(&[8, 0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x01]);
        let icmp_csum = checksum16(&frame[icmp_start..]);
        frame[icmp_start + 2..icmp_start + 4].copy_from_slice(&icmp_csum.to_be_bytes());
        frame
    }

    fn build_icmp_echo_frame_v6(src: Ipv6Addr, dst: Ipv6Addr, hop_limit: u8) -> Vec<u8> {
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
            0,
            0x86dd,
        );
        frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x08, PROTO_ICMPV6, hop_limit]);
        frame.extend_from_slice(&src.octets());
        frame.extend_from_slice(&dst.octets());
        let icmp_start = frame.len();
        frame.extend_from_slice(&[128, 0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x01]);
        let icmp_csum = checksum16_ipv6(src, dst, PROTO_ICMPV6, &frame[icmp_start..]);
        frame[icmp_start + 2..icmp_start + 4].copy_from_slice(&icmp_csum.to_be_bytes());
        frame
    }

    #[test]
    fn packet_ttl_would_expire_identifies_v4_and_v6() {
        let frame_v4 = build_icmp_echo_frame_v4(
            Ipv4Addr::new(10, 0, 61, 102),
            Ipv4Addr::new(1, 1, 1, 1),
            1,
        );
        let meta_v4 = UserspaceDpMeta {
            l3_offset: 14,
            addr_family: libc::AF_INET as u8,
            ..UserspaceDpMeta::default()
        };
        assert_eq!(packet_ttl_would_expire(&frame_v4, meta_v4), Some(true));

        let frame_v6 = build_icmp_echo_frame_v6(
            "2001:559:8585:ef00::102".parse().unwrap(),
            "2606:4700:4700::1111".parse().unwrap(),
            2,
        );
        let meta_v6 = UserspaceDpMeta {
            l3_offset: 14,
            addr_family: libc::AF_INET6 as u8,
            ..UserspaceDpMeta::default()
        };
        assert_eq!(packet_ttl_would_expire(&frame_v6, meta_v6), Some(false));
    }

    #[test]
    fn build_local_time_exceeded_v4_quotes_original_packet() {
        let client_ip = Ipv4Addr::new(10, 0, 61, 102);
        let dst_ip = Ipv4Addr::new(1, 1, 1, 1);
        let frame = build_icmp_echo_frame_v4(client_ip, dst_ip, 1);
        let meta = UserspaceDpMeta {
            l3_offset: 14,
            l4_offset: 34,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_ICMP,
            ..UserspaceDpMeta::default()
        };
        let mut forwarding = ForwardingState::default();
        forwarding.egress.insert(
            5,
            EgressInterface {
                bind_ifindex: 5,
                vlan_id: 0,
                mtu: 1500,
                src_mac: [0x02, 0xbf, 0x72, 0x00, 0x61, 0x01],
                zone: "lan".to_string(),
                redundancy_group: 1,
                primary_v4: Some(Ipv4Addr::new(10, 0, 61, 1)),
                primary_v6: None,
            },
        );
        let out = build_local_time_exceeded_v4(&frame, meta, 5, &forwarding)
            .expect("build local IPv4 TE");
        assert_eq!(&out[0..6], &[0x00, 0x25, 0x90, 0x12, 0x34, 0x56]);
        assert_eq!(&out[6..12], &[0x02, 0xbf, 0x72, 0x00, 0x61, 0x01]);
        assert_eq!(u16::from_be_bytes([out[12], out[13]]), 0x0800);
        assert_eq!(Ipv4Addr::new(out[26], out[27], out[28], out[29]), Ipv4Addr::new(10, 0, 61, 1));
        assert_eq!(Ipv4Addr::new(out[30], out[31], out[32], out[33]), client_ip);
        assert_eq!(out[34], 11);
        assert_eq!(out[35], 0);
        let quoted_ip_start = 42;
        assert_eq!(Ipv4Addr::new(out[quoted_ip_start + 12], out[quoted_ip_start + 13], out[quoted_ip_start + 14], out[quoted_ip_start + 15]), client_ip);
        assert_eq!(Ipv4Addr::new(out[quoted_ip_start + 16], out[quoted_ip_start + 17], out[quoted_ip_start + 18], out[quoted_ip_start + 19]), dst_ip);
        assert_eq!(out[quoted_ip_start + 8], 1);
    }

    #[test]
    fn build_local_time_exceeded_v6_quotes_original_packet() {
        let client_ip: Ipv6Addr = "2001:559:8585:ef00::102".parse().unwrap();
        let dst_ip: Ipv6Addr = "2606:4700:4700::1111".parse().unwrap();
        let frame = build_icmp_echo_frame_v6(client_ip, dst_ip, 1);
        let meta = UserspaceDpMeta {
            l3_offset: 14,
            l4_offset: 54,
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_ICMPV6,
            ..UserspaceDpMeta::default()
        };
        let mut forwarding = ForwardingState::default();
        forwarding.egress.insert(
            5,
            EgressInterface {
                bind_ifindex: 5,
                vlan_id: 0,
                mtu: 1500,
                src_mac: [0x02, 0xbf, 0x72, 0x00, 0x61, 0x01],
                zone: "lan".to_string(),
                redundancy_group: 1,
                primary_v4: None,
                primary_v6: Some("2001:559:8585:ef00::1".parse().unwrap()),
            },
        );
        let out = build_local_time_exceeded_v6(&frame, meta, 5, &forwarding)
            .expect("build local IPv6 TE");
        assert_eq!(&out[0..6], &[0x00, 0x25, 0x90, 0x12, 0x34, 0x56]);
        assert_eq!(&out[6..12], &[0x02, 0xbf, 0x72, 0x00, 0x61, 0x01]);
        assert_eq!(u16::from_be_bytes([out[12], out[13]]), 0x86dd);
        assert_eq!(Ipv6Addr::from(<[u8; 16]>::try_from(&out[22..38]).unwrap()), "2001:559:8585:ef00::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(Ipv6Addr::from(<[u8; 16]>::try_from(&out[38..54]).unwrap()), client_ip);
        assert_eq!(out[54], 3);
        assert_eq!(out[55], 0);
        let quoted_ip_start = 62;
        assert_eq!(Ipv6Addr::from(<[u8; 16]>::try_from(&out[quoted_ip_start + 8..quoted_ip_start + 24]).unwrap()), client_ip);
        assert_eq!(Ipv6Addr::from(<[u8; 16]>::try_from(&out[quoted_ip_start + 24..quoted_ip_start + 40]).unwrap()), dst_ip);
        assert_eq!(out[quoted_ip_start + 7], 1);
    }

    // --- ICMP error NAT reversal tests ---

    /// Build an IPv4 ICMP Time Exceeded frame with an embedded TCP packet.
    /// outer: [Eth][IP: src=router_ip, dst=snat_ip][ICMP type=11 code=0]
    ///        [Embedded: IP src=snat_ip, dst=server_ip, proto=TCP][TCP src=snat_port, dst=server_port]
    fn build_icmp_te_frame_v4(
        router_ip: Ipv4Addr,
        snat_ip: Ipv4Addr,
        server_ip: Ipv4Addr,
        snat_port: u16,
        server_port: u16,
        embedded_proto: u8,
    ) -> Vec<u8> {
        let mut frame = Vec::new();
        // Ethernet header
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], // dst MAC
            [0x00, 0x25, 0x90, 0x12, 0x34, 0x56], // src MAC
            0,
            0x0800,
        );
        let ip_start = frame.len(); // 14

        // Build embedded IP+L4 first to know sizes
        let mut embedded = Vec::new();
        // Embedded IPv4 header (20 bytes, IHL=5)
        embedded.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x00, // version/IHL, DSCP, total length (fill later)
            0x00, 0x01, 0x00, 0x00, // ID, flags, fragment offset
            64, embedded_proto, 0x00, 0x00, // TTL, protocol, checksum (fill later)
        ]);
        embedded.extend_from_slice(&snat_ip.octets()); // src
        embedded.extend_from_slice(&server_ip.octets()); // dst
        // Embedded L4: first 8 bytes
        if matches!(embedded_proto, PROTO_TCP | PROTO_UDP) {
            embedded.extend_from_slice(&snat_port.to_be_bytes());
            embedded.extend_from_slice(&server_port.to_be_bytes());
            embedded.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // seq/other
        } else if embedded_proto == PROTO_ICMP {
            embedded.extend_from_slice(&[8, 0, 0x00, 0x00]); // echo request, checksum
            embedded.extend_from_slice(&snat_port.to_be_bytes()); // echo ID
            embedded.extend_from_slice(&[0x00, 0x01]); // seq
        }
        // Fill embedded IP total length
        let emb_total = embedded.len() as u16;
        embedded[2..4].copy_from_slice(&emb_total.to_be_bytes());
        // Compute embedded IP checksum
        embedded[10..12].copy_from_slice(&[0, 0]);
        let emb_ip_csum = checksum16(&embedded[..20]);
        embedded[10..12].copy_from_slice(&emb_ip_csum.to_be_bytes());

        // Outer ICMP header: type=11 (Time Exceeded), code=0, checksum, unused
        let mut icmp = Vec::new();
        icmp.extend_from_slice(&[11, 0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // type, code, csum, unused
        icmp.extend_from_slice(&embedded);
        // Compute ICMP checksum
        icmp[2..4].copy_from_slice(&[0, 0]);
        let icmp_csum = checksum16(&icmp);
        icmp[2..4].copy_from_slice(&icmp_csum.to_be_bytes());

        // Outer IPv4 header
        let outer_total_len = (20 + icmp.len()) as u16;
        frame.extend_from_slice(&[
            0x45, 0x00, // version/IHL, DSCP
        ]);
        frame.extend_from_slice(&outer_total_len.to_be_bytes()); // total length
        frame.extend_from_slice(&[
            0x00, 0x02, 0x00, 0x00, // ID, flags
            64, PROTO_ICMP, 0x00, 0x00, // TTL, protocol, checksum
        ]);
        frame.extend_from_slice(&router_ip.octets()); // src
        frame.extend_from_slice(&snat_ip.octets()); // dst

        // Compute outer IP checksum
        frame[ip_start + 10..ip_start + 12].copy_from_slice(&[0, 0]);
        let ip_csum = checksum16(&frame[ip_start..ip_start + 20]);
        frame[ip_start + 10..ip_start + 12].copy_from_slice(&ip_csum.to_be_bytes());

        // Append ICMP payload
        frame.extend_from_slice(&icmp);

        frame
    }

    #[test]
    fn icmp_te_nat_reversal_v4_rewrites_outer_dst_and_embedded_src() {
        // Scenario: client 10.0.61.102 -> server 1.1.1.1, SNAT'd to 172.16.80.8
        // Router 10.0.0.1 sends ICMP Time Exceeded back to 172.16.80.8
        // NAT reversal: outer dst 172.16.80.8 -> 10.0.61.102,
        //               embedded src 172.16.80.8 -> 10.0.61.102
        let router_ip = Ipv4Addr::new(10, 0, 0, 1);
        let snat_ip = Ipv4Addr::new(172, 16, 80, 8);
        let client_ip = Ipv4Addr::new(10, 0, 61, 102);
        let server_ip = Ipv4Addr::new(1, 1, 1, 1);
        let snat_port: u16 = 40000;
        let client_port: u16 = 12345;

        let frame = build_icmp_te_frame_v4(
            router_ip, snat_ip, server_ip, snat_port, 80, PROTO_TCP,
        );

        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            l4_offset: 34,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_ICMP,
            ..UserspaceDpMeta::default()
        };

        let icmp_match = EmbeddedIcmpMatch {
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(snat_ip)),
                rewrite_src_port: Some(snat_port),
                ..NatDecision::default()
            },
            original_src: IpAddr::V4(client_ip),
            original_src_port: client_port,
            embedded_proto: PROTO_TCP,
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 5,
                tx_ifindex: 5,
                next_hop: Some(IpAddr::V4(client_ip)),
                neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
                tx_vlan_id: 0,
            },
            metadata: SessionMetadata {
                ingress_zone: Arc::<str>::from("untrust"),
                egress_zone: Arc::<str>::from("trust"),
                owner_rg_id: 0,
                is_reverse: false,
                synced: false,
                nat64_reverse: None,
            },
        };

        let result = build_nat_reversed_icmp_error_v4(&frame, meta, &icmp_match)
            .expect("should build NAT-reversed frame");

        // Verify Ethernet header
        assert_eq!(&result[0..6], &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // dst MAC
        assert_eq!(&result[6..12], &[0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]); // src MAC
        assert_eq!(&result[12..14], &[0x08, 0x00]); // ethertype IPv4

        // Verify outer IP dst is now the original client
        let outer_dst = Ipv4Addr::new(result[30], result[31], result[32], result[33]);
        assert_eq!(outer_dst, client_ip, "outer IP dst should be original client");

        // Verify outer IP src is still the router
        let outer_src = Ipv4Addr::new(result[26], result[27], result[28], result[29]);
        assert_eq!(outer_src, router_ip, "outer IP src should remain router");

        // Verify embedded IP src is now the original client
        // Embedded IP starts at: eth(14) + outer_ip(20) + icmp_hdr(8) = 42
        let emb_ip_start = 42;
        let emb_src = Ipv4Addr::new(
            result[emb_ip_start + 12],
            result[emb_ip_start + 13],
            result[emb_ip_start + 14],
            result[emb_ip_start + 15],
        );
        assert_eq!(emb_src, client_ip, "embedded src should be original client");

        // Verify embedded dst is still the server
        let emb_dst = Ipv4Addr::new(
            result[emb_ip_start + 16],
            result[emb_ip_start + 17],
            result[emb_ip_start + 18],
            result[emb_ip_start + 19],
        );
        assert_eq!(emb_dst, server_ip, "embedded dst should remain server");

        // Verify embedded TCP src port is now the original client port
        let emb_l4_start = emb_ip_start + 20; // IHL=5, so 20 bytes
        let emb_port = u16::from_be_bytes([result[emb_l4_start], result[emb_l4_start + 1]]);
        assert_eq!(emb_port, client_port, "embedded src port should be original");

        // Verify outer IP checksum is valid
        let outer_ihl = ((result[14] & 0x0f) as usize) * 4;
        let ip_csum_check = checksum16(&result[14..14 + outer_ihl]);
        assert_eq!(ip_csum_check, 0, "outer IP checksum should be valid (0)");

        // Verify outer ICMP checksum is valid
        let icmp_start = 14 + outer_ihl;
        let icmp_csum_check = checksum16(&result[icmp_start..]);
        assert_eq!(icmp_csum_check, 0, "outer ICMP checksum should be valid (0)");

        // Verify embedded IP checksum is valid
        let emb_ihl = ((result[emb_ip_start] & 0x0f) as usize) * 4;
        let emb_ip_csum_check = checksum16(&result[emb_ip_start..emb_ip_start + emb_ihl]);
        assert_eq!(emb_ip_csum_check, 0, "embedded IP checksum should be valid (0)");
    }

    #[test]
    fn icmp_te_nat_reversal_v4_with_port_snat() {
        // Same as above but verifying UDP port reversal specifically
        let router_ip = Ipv4Addr::new(10, 0, 0, 1);
        let snat_ip = Ipv4Addr::new(172, 16, 80, 8);
        let client_ip = Ipv4Addr::new(10, 0, 61, 102);
        let server_ip = Ipv4Addr::new(1, 1, 1, 1);
        let snat_port: u16 = 50000;
        let client_port: u16 = 5353;

        let frame = build_icmp_te_frame_v4(
            router_ip, snat_ip, server_ip, snat_port, 53, PROTO_UDP,
        );

        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            l4_offset: 34,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_ICMP,
            ..UserspaceDpMeta::default()
        };

        let icmp_match = EmbeddedIcmpMatch {
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(snat_ip)),
                rewrite_src_port: Some(snat_port),
                ..NatDecision::default()
            },
            original_src: IpAddr::V4(client_ip),
            original_src_port: client_port,
            embedded_proto: PROTO_UDP,
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 5,
                tx_ifindex: 5,
                next_hop: Some(IpAddr::V4(client_ip)),
                neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
                tx_vlan_id: 0,
            },
            metadata: SessionMetadata {
                ingress_zone: Arc::<str>::from("untrust"),
                egress_zone: Arc::<str>::from("trust"),
                owner_rg_id: 0,
                is_reverse: false,
                synced: false,
                nat64_reverse: None,
            },
        };

        let result = build_nat_reversed_icmp_error_v4(&frame, meta, &icmp_match)
            .expect("should build NAT-reversed frame");

        // Verify embedded UDP src port is now the original client port
        let emb_ip_start = 42; // eth(14) + outer_ip(20) + icmp_hdr(8)
        let emb_l4_start = emb_ip_start + 20;
        let emb_port = u16::from_be_bytes([result[emb_l4_start], result[emb_l4_start + 1]]);
        assert_eq!(emb_port, client_port, "embedded UDP src port should be original");

        // Verify all checksums
        let ip_csum_check = checksum16(&result[14..34]);
        assert_eq!(ip_csum_check, 0, "outer IP checksum should be valid");
        let icmp_csum_check = checksum16(&result[34..]);
        assert_eq!(icmp_csum_check, 0, "outer ICMP checksum should be valid");
    }

    #[test]
    fn icmp_dest_unreach_nat_reversal_v4() {
        // ICMP Destination Unreachable (type 3, code 1) with embedded TCP
        let router_ip = Ipv4Addr::new(10, 0, 0, 1);
        let snat_ip = Ipv4Addr::new(172, 16, 80, 8);
        let client_ip = Ipv4Addr::new(10, 0, 61, 102);
        let server_ip = Ipv4Addr::new(1, 1, 1, 1);

        // Build ICMP Destination Unreachable frame manually
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
            0,
            0x0800,
        );
        let ip_start = frame.len();

        // Embedded IP+TCP
        let mut embedded = Vec::new();
        embedded.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
            64, PROTO_TCP, 0x00, 0x00,
        ]);
        embedded.extend_from_slice(&snat_ip.octets());
        embedded.extend_from_slice(&server_ip.octets());
        let emb_total = (20 + 8) as u16;
        embedded[2..4].copy_from_slice(&emb_total.to_be_bytes());
        embedded.extend_from_slice(&40000u16.to_be_bytes()); // src port (SNAT'd)
        embedded.extend_from_slice(&80u16.to_be_bytes()); // dst port
        embedded.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // seq
        embedded[10..12].copy_from_slice(&[0, 0]);
        let emb_ip_csum = checksum16(&embedded[..20]);
        embedded[10..12].copy_from_slice(&emb_ip_csum.to_be_bytes());

        // ICMP type=3 (Dest Unreach), code=1 (Host Unreachable)
        let mut icmp = Vec::new();
        icmp.extend_from_slice(&[3, 1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        icmp.extend_from_slice(&embedded);
        icmp[2..4].copy_from_slice(&[0, 0]);
        let icmp_csum = checksum16(&icmp);
        icmp[2..4].copy_from_slice(&icmp_csum.to_be_bytes());

        // Outer IP
        let outer_total = (20 + icmp.len()) as u16;
        frame.extend_from_slice(&[0x45, 0x00]);
        frame.extend_from_slice(&outer_total.to_be_bytes());
        frame.extend_from_slice(&[0x00, 0x02, 0x00, 0x00, 64, PROTO_ICMP, 0x00, 0x00]);
        frame.extend_from_slice(&router_ip.octets());
        frame.extend_from_slice(&snat_ip.octets());
        frame[ip_start + 10..ip_start + 12].copy_from_slice(&[0, 0]);
        let ip_csum = checksum16(&frame[ip_start..ip_start + 20]);
        frame[ip_start + 10..ip_start + 12].copy_from_slice(&ip_csum.to_be_bytes());
        frame.extend_from_slice(&icmp);

        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            l4_offset: 34,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_ICMP,
            ..UserspaceDpMeta::default()
        };

        let icmp_match = EmbeddedIcmpMatch {
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(snat_ip)),
                rewrite_src_port: Some(40000),
                ..NatDecision::default()
            },
            original_src: IpAddr::V4(client_ip),
            original_src_port: 12345,
            embedded_proto: PROTO_TCP,
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 5,
                tx_ifindex: 5,
                next_hop: Some(IpAddr::V4(client_ip)),
                neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
                tx_vlan_id: 0,
            },
            metadata: SessionMetadata {
                ingress_zone: Arc::<str>::from("untrust"),
                egress_zone: Arc::<str>::from("trust"),
                owner_rg_id: 0,
                is_reverse: false,
                synced: false,
                nat64_reverse: None,
            },
        };

        let result = build_nat_reversed_icmp_error_v4(&frame, meta, &icmp_match)
            .expect("should build NAT-reversed frame");

        // Verify outer IP dst is client
        let outer_dst = Ipv4Addr::new(result[30], result[31], result[32], result[33]);
        assert_eq!(outer_dst, client_ip);

        // Verify ICMP type/code NOT modified
        assert_eq!(result[34], 3, "ICMP type must remain Dest Unreach");
        assert_eq!(result[35], 1, "ICMP code must remain Host Unreachable");

        // Verify checksums
        let ip_csum_check = checksum16(&result[14..34]);
        assert_eq!(ip_csum_check, 0);
        let icmp_csum_check = checksum16(&result[34..]);
        assert_eq!(icmp_csum_check, 0);
    }

    /// Build an IPv6 ICMPv6 Time Exceeded frame with an embedded TCP packet.
    fn build_icmpv6_te_frame(
        router_ip: Ipv6Addr,
        snat_ip: Ipv6Addr,
        server_ip: Ipv6Addr,
        snat_port: u16,
        server_port: u16,
        embedded_proto: u8,
    ) -> Vec<u8> {
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
            0,
            0x86dd,
        );

        // Build embedded IPv6+L4
        let mut embedded = Vec::new();
        // IPv6 header (40 bytes)
        embedded.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]); // version, traffic class, flow label
        let emb_payload_len = 8u16; // 8 bytes of L4
        embedded.extend_from_slice(&emb_payload_len.to_be_bytes());
        embedded.push(embedded_proto); // next header
        embedded.push(64); // hop limit
        embedded.extend_from_slice(&snat_ip.octets()); // src
        embedded.extend_from_slice(&server_ip.octets()); // dst
        // Embedded L4: first 8 bytes
        if matches!(embedded_proto, PROTO_TCP | PROTO_UDP) {
            embedded.extend_from_slice(&snat_port.to_be_bytes());
            embedded.extend_from_slice(&server_port.to_be_bytes());
            embedded.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        } else if embedded_proto == PROTO_ICMPV6 {
            embedded.extend_from_slice(&[128, 0, 0x00, 0x00]); // echo request, checksum
            embedded.extend_from_slice(&snat_port.to_be_bytes()); // echo ID
            embedded.extend_from_slice(&[0x00, 0x01]); // seq
        }

        // ICMPv6 header: type=3 (Time Exceeded), code=0, checksum, unused
        let mut icmp6 = Vec::new();
        icmp6.extend_from_slice(&[3, 0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        icmp6.extend_from_slice(&embedded);

        // Outer IPv6 header
        let payload_len = icmp6.len() as u16;
        frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
        frame.extend_from_slice(&payload_len.to_be_bytes());
        frame.push(PROTO_ICMPV6); // next header
        frame.push(64); // hop limit
        frame.extend_from_slice(&router_ip.octets()); // src
        frame.extend_from_slice(&snat_ip.octets()); // dst

        // Compute ICMPv6 checksum (covers pseudo-header)
        icmp6[2..4].copy_from_slice(&[0, 0]);
        let csum = checksum16_ipv6(router_ip, snat_ip, PROTO_ICMPV6, &icmp6);
        icmp6[2..4].copy_from_slice(&csum.to_be_bytes());

        frame.extend_from_slice(&icmp6);
        frame
    }

    #[test]
    fn icmpv6_te_nat_reversal_v6_rewrites_outer_dst_and_embedded_src() {
        let router_ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let snat_ip: Ipv6Addr = "2001:db8:1::100".parse().unwrap();
        let client_ip: Ipv6Addr = "fd00::102".parse().unwrap();
        let server_ip: Ipv6Addr = "2001:db8:2::1".parse().unwrap();
        let snat_port: u16 = 40000;
        let client_port: u16 = 12345;

        let frame = build_icmpv6_te_frame(
            router_ip, snat_ip, server_ip, snat_port, 80, PROTO_TCP,
        );

        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            l4_offset: 54,
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_ICMPV6,
            ..UserspaceDpMeta::default()
        };

        let icmp_match = EmbeddedIcmpMatch {
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V6(snat_ip)),
                rewrite_src_port: Some(snat_port),
                ..NatDecision::default()
            },
            original_src: IpAddr::V6(client_ip),
            original_src_port: client_port,
            embedded_proto: PROTO_TCP,
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 5,
                tx_ifindex: 5,
                next_hop: Some(IpAddr::V6(client_ip)),
                neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
                tx_vlan_id: 0,
            },
            metadata: SessionMetadata {
                ingress_zone: Arc::<str>::from("untrust"),
                egress_zone: Arc::<str>::from("trust"),
                owner_rg_id: 0,
                is_reverse: false,
                synced: false,
                nat64_reverse: None,
            },
        };

        let result = build_nat_reversed_icmp_error_v6(&frame, meta, &icmp_match)
            .expect("should build NAT-reversed ICMPv6 frame");

        // Verify Ethernet header
        assert_eq!(&result[0..6], &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // dst MAC
        assert_eq!(&result[12..14], &[0x86, 0xdd]); // ethertype IPv6

        // Verify outer IPv6 dst is now the original client (bytes 24..40 in IPv6)
        let outer_dst_bytes: [u8; 16] = result[38..54].try_into().unwrap();
        let outer_dst = Ipv6Addr::from(outer_dst_bytes);
        assert_eq!(outer_dst, client_ip, "outer IPv6 dst should be original client");

        // Verify outer IPv6 src is still the router (bytes 8..24 in IPv6)
        let outer_src_bytes: [u8; 16] = result[22..38].try_into().unwrap();
        let outer_src = Ipv6Addr::from(outer_src_bytes);
        assert_eq!(outer_src, router_ip, "outer IPv6 src should remain router");

        // Verify embedded IPv6 src is now the original client
        // Embedded IPv6 starts at: eth(14) + outer_ipv6(40) + icmpv6_hdr(8) = 62
        let emb_ip_start = 62;
        let emb_src_bytes: [u8; 16] = result[emb_ip_start + 8..emb_ip_start + 24]
            .try_into()
            .unwrap();
        let emb_src = Ipv6Addr::from(emb_src_bytes);
        assert_eq!(emb_src, client_ip, "embedded IPv6 src should be original client");

        // Verify embedded dst is still the server
        let emb_dst_bytes: [u8; 16] = result[emb_ip_start + 24..emb_ip_start + 40]
            .try_into()
            .unwrap();
        let emb_dst = Ipv6Addr::from(emb_dst_bytes);
        assert_eq!(emb_dst, server_ip, "embedded IPv6 dst should remain server");

        // Verify embedded TCP src port
        let emb_l4_start = emb_ip_start + 40;
        let emb_port = u16::from_be_bytes([result[emb_l4_start], result[emb_l4_start + 1]]);
        assert_eq!(emb_port, client_port, "embedded src port should be original");

        // Verify ICMPv6 checksum is valid
        let icmp6_start = 54; // eth(14) + ipv6(40)
        let src_v6 = Ipv6Addr::from(outer_src_bytes);
        let dst_v6 = Ipv6Addr::from(outer_dst_bytes);
        let icmp6_data = &result[icmp6_start..];
        // Zero checksum and recompute
        let mut icmp6_copy = icmp6_data.to_vec();
        icmp6_copy[2] = 0;
        icmp6_copy[3] = 0;
        let expected_csum = checksum16_ipv6(src_v6, dst_v6, PROTO_ICMPV6, &icmp6_copy);
        let actual_csum = u16::from_be_bytes([icmp6_data[2], icmp6_data[3]]);
        assert_eq!(actual_csum, expected_csum, "ICMPv6 checksum should be valid");
    }

    #[test]
    fn no_match_embedded_icmp_returns_none() {
        // An ICMP error with no matching session should return None
        let router_ip = Ipv4Addr::new(10, 0, 0, 1);
        let snat_ip = Ipv4Addr::new(172, 16, 80, 8);
        let server_ip = Ipv4Addr::new(1, 1, 1, 1);

        let frame = build_icmp_te_frame_v4(
            router_ip, snat_ip, server_ip, 40000, 80, PROTO_TCP,
        );

        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            l4_offset: 34,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_ICMP,
            ..UserspaceDpMeta::default()
        };

        let mut sessions = SessionTable::new();
        // Don't install any sessions
        let result = try_embedded_icmp_session_match_from_frame(&frame, meta, &mut sessions, 1_000_000);
        assert!(result.is_none(), "should return None when no session matches");
    }
}
