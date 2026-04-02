use super::{
    BindingStatus, ConfigSnapshot, ExceptionStatus, HAGroupStatus, InjectPacketRequest,
    InterfaceSnapshot, PacketResolution, SessionDeltaInfo,
};
use crate::nat::{
    DnatTable, NatDecision, SourceNatRule, StaticNatTable, match_source_nat, parse_source_nat_rules,
};
use crate::nat64::{Nat64ReverseInfo, Nat64State};
use crate::nptv6::Nptv6State;
use crate::policy::{PolicyAction, PolicyState, evaluate_policy, parse_policy_state};
use crate::prefix::{PrefixV4, PrefixV6};
use crate::screen::{ScreenProfile, ScreenState, ScreenVerdict, extract_screen_info};
use crate::session::{
    ForwardSessionMatch, SessionDecision, SessionDelta, SessionDeltaKind, SessionKey,
    SessionLookup, SessionMetadata, SessionOrigin, SessionTable, forward_wire_key,
    reverse_canonical_key,
};
use crate::slowpath::{EnqueueOutcome, SlowPathReinjector, SlowPathStatus, open_tun};
use crate::xsk_ffi::xdp::XdpDesc;
use crate::xsk_ffi::{BufIdx, SocketConfig, Umem, UmemConfig, User};
use arc_swap::ArcSwap;
use chrono::Utc;
use core::ffi::{c_int, c_void};
use core::ptr::NonNull;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::{BTreeMap, VecDeque};
use std::ffi::CString;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::AsRawFd;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;

const USERSPACE_SESSION_ACTION_REDIRECT: u8 = 1;
const USERSPACE_SESSION_ACTION_PASS_TO_KERNEL: u8 = 2;

/// Hot-path debug logging — compiled out unless `debug-log` feature is enabled.
#[allow(unused_macros)]
macro_rules! debug_log {
    ($($arg:tt)*) => {
        #[cfg(feature = "debug-log")]
        eprintln!($($arg)*);
    };
}

#[path = "afxdp/bind.rs"]
mod bind;
#[path = "afxdp/bpf_map.rs"]
mod bpf_map;
#[path = "afxdp/checksum.rs"]
mod checksum;
#[path = "afxdp/forwarding.rs"]
mod forwarding;
#[path = "afxdp/frame.rs"]
mod frame;
#[path = "afxdp/gre.rs"]
mod gre;
#[path = "afxdp/icmp.rs"]
mod icmp;
#[path = "afxdp/icmp_embed.rs"]
mod icmp_embed;
#[path = "afxdp/neighbor.rs"]
mod neighbor;
#[path = "afxdp/rst.rs"]
mod rst;
#[path = "afxdp/session_glue.rs"]
mod session_glue;
#[cfg(test)]
#[path = "afxdp/test_fixtures.rs"]
mod test_fixtures;
#[path = "afxdp/tunnel.rs"]
mod tunnel;
#[path = "afxdp/tx.rs"]
mod tx;
#[path = "afxdp/types.rs"]
mod types;
#[path = "afxdp/umem.rs"]
mod umem;

#[cfg(test)]
use self::bind::bind_flag_candidates_for_driver;
use self::bind::{
    AfXdpBindStrategy, binding_frame_count_for_driver, ifinfo_from_binding, interface_driver_name,
    open_binding_worker_rings, preferred_bind_strategy, reserved_tx_frames_for_driver,
    umem_ring_size,
};
#[cfg(test)]
use self::bind::{
    AfXdpBinder, alternate_bind_strategy, bind_strategy_for_driver, binder_for_strategy,
    shared_umem_group_key_for_device,
};
use self::bpf_map::*;
use self::checksum::*;
use self::forwarding::*;
use self::frame::*;
use self::gre::{encapsulate_native_gre_frame, try_native_gre_decap_from_frame};
use self::icmp::{build_local_time_exceeded_request, is_icmp_error};
#[cfg(test)]
use self::icmp::{
    build_local_time_exceeded_v4, build_local_time_exceeded_v6, packet_ttl_would_expire,
};
#[cfg(test)]
use self::icmp_embed::{
    EmbeddedIcmpMatch, try_embedded_icmp_nat_match_from_frame,
    try_embedded_icmp_session_match_from_frame,
};
use self::icmp_embed::{
    build_nat_reversed_icmp_error_v4, build_nat_reversed_icmp_error_v6,
    finalize_embedded_icmp_resolution, try_embedded_icmp_nat_match,
};
use self::neighbor::*;
pub use self::neighbor::{neighbor_state_usable_str, parse_mac_str};
pub(crate) use self::rst::remove_kernel_rst_suppression;
use self::rst::*;
use self::session_glue::*;
use self::tunnel::*;
use self::tx::*;
use self::types::*;
pub(crate) use self::types::{ForwardingDisposition, ForwardingResolution, NeighborEntry};
use self::umem::*;

const USERSPACE_META_MAGIC: u32 = 0x4250_5553;
const USERSPACE_META_VERSION: u16 = 4;
const UMEM_FRAME_SIZE: u32 = 4096;
const UMEM_HEADROOM: u32 = 256;
const RX_BATCH_SIZE: u32 = 256;
const MIN_RESERVED_TX_FRAMES: u32 = 256;
const MAX_RESERVED_TX_FRAMES: u32 = 8192;
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
const XSK_BIND_FLAGS_COPY: u16 = SocketConfig::XDP_BIND_NEED_WAKEUP | SocketConfig::XDP_BIND_COPY;
const IDLE_SPIN_ITERS: u32 = 256;
const IDLE_SLEEP_US: u64 = 1;
const INTERRUPT_POLL_TIMEOUT_MS: i32 = 1;
const RX_WAKE_IDLE_POLLS: u32 = 32;
const RX_WAKE_MIN_INTERVAL_NS: u64 = 200_000;
/// Safety-net interval for fill ring wakes when needs_wakeup is clear.
/// Prevents lost-wakeup stalls from the race: commit() → check needs_wakeup
/// (clear) → kernel exhausts cache → sets needs_wakeup → userspace doesn't see it.
const FILL_WAKE_SAFETY_INTERVAL_NS: u64 = 500_000; // 500µs
const HEARTBEAT_UPDATE_INTERVAL_NS: u64 = 250_000_000;
/// Grace period after binding before writing heartbeat. During this window
/// the XDP shim sees no heartbeat → XDP_PASS → kernel forwards packets AND
/// NAPI bootstraps the NIC's XSK receive queue from the fill ring. After
/// this period, heartbeat is written and the XDP shim redirects to XSK.
/// Must exceed the Go-side ctrl enable delay (3s) plus time for
/// NAPI to bootstrap the XSK RQ from the fill ring (~2-3 seconds).
const HEARTBEAT_GRACE_PERIOD_NS: u64 = 6_000_000_000; // 6 seconds
const TX_WAKE_MIN_INTERVAL_NS: u64 = 50_000;
const HEARTBEAT_STALE_AFTER: Duration = Duration::from_secs(5);
const MAX_RECENT_EXCEPTIONS: usize = 32;
const MAX_RECENT_SESSION_DELTAS: usize = 64;
const MAX_PENDING_SESSION_DELTAS: usize = 4096;
const BIND_RETRY_ATTEMPTS: usize = 20;
const BIND_RETRY_DELAY: Duration = Duration::from_millis(250);
const DEFAULT_SLOW_PATH_TUN: &str = "bpfrx-usp0";
const LOCAL_TUNNEL_DELIVERY_QUEUE_DEPTH: usize = 4096;
const HA_DEMOTION_PREP_LEASE_SECS: u64 = 5;

const HA_WATCHDOG_STALE_AFTER_SECS: u64 = 10;
const FABRIC_ZONE_MAC_MAGIC: u8 = 0xfe;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const PROTO_ICMP: u8 = 1;
const PROTO_ICMPV6: u8 = 58;
#[allow(dead_code)]
const PROTO_GRE: u8 = 47;
const PROTO_ESP: u8 = 50;
const TCP_FLAG_FIN: u8 = 0x01;
const TCP_FLAG_RST: u8 = 0x04;
const TCP_FLAG_PSH: u8 = 0x08;
const TCP_FLAG_SYN: u8 = 0x02;
const TUNNEL_HA_STARTUP_GRACE_SECS: u64 = 10;
const SOL_XDP: c_int = 283;
const XDP_OPTIONS: c_int = 8;
const XDP_OPTIONS_ZEROCOPY: u32 = 1;

const PENDING_NEIGH_TIMEOUT_NS: u64 = 2_000_000_000; // 2 seconds
const MAX_PENDING_NEIGH: usize = 64;

#[inline]
const fn tx_frame_capacity() -> usize {
    UMEM_FRAME_SIZE as usize
}

pub struct Coordinator {
    map_fd: Option<OwnedFd>,
    heartbeat_map_fd: Option<OwnedFd>,
    session_map_fd: Option<OwnedFd>,
    conntrack_v4_fd: Option<OwnedFd>,
    conntrack_v6_fd: Option<OwnedFd>,
    dnat_table_fd: Option<OwnedFd>,
    dnat_table_v6_fd: Option<OwnedFd>,
    slow_path: Option<Arc<SlowPathReinjector>>,
    local_tunnel_deliveries: Arc<ArcSwap<BTreeMap<i32, SyncSender<Vec<u8>>>>>,
    tunnel_sources: BTreeMap<u16, LocalTunnelSourceHandle>,
    last_slow_path_status: SlowPathStatus,
    ha_state: Arc<ArcSwap<BTreeMap<i32, HAGroupRuntime>>>,
    shared_fabrics: Arc<ArcSwap<Vec<FabricLink>>>,
    shared_forwarding: Arc<ArcSwap<ForwardingState>>,
    shared_validation: Arc<ArcSwap<ValidationState>>,
    dynamic_neighbors: Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
    neighbor_generation: Arc<AtomicU64>,
    manager_neighbor_keys: Arc<Mutex<FastSet<(i32, IpAddr)>>>,
    neigh_monitor_stop: Option<Arc<AtomicBool>>,
    shared_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    live: BTreeMap<u32, Arc<BindingLiveState>>,
    identities: BTreeMap<u32, BindingIdentity>,
    workers: BTreeMap<u32, WorkerHandle>,
    demotion_prepare_seq: AtomicU64,
    ha_state_apply_seq: AtomicU64,
    session_export_seq: AtomicU64,
    forwarding: ForwardingState,
    recent_exceptions: Arc<Mutex<VecDeque<ExceptionStatus>>>,
    recent_session_deltas: Arc<Mutex<VecDeque<SessionDeltaInfo>>>,
    last_resolution: Arc<Mutex<Option<PacketResolution>>>,
    validation: ValidationState,
    last_planned_workers: usize,
    last_planned_bindings: usize,
    reconcile_calls: u64,
    last_reconcile_stage: String,
    pub poll_mode: crate::PollMode,
    event_stream: Option<crate::event_stream::EventStreamSender>,
    /// Monotonic timestamp (secs) of the last HA flow cache flush (#312).
    last_cache_flush_at: Arc<AtomicU64>,
    /// Per-RG epoch counters for O(1) flow cache invalidation on demotion.
    /// Shared with all worker threads; bumped atomically on demotion/activation.
    rg_epochs: Arc<[AtomicU32; MAX_RG_EPOCHS]>,
}

impl Coordinator {
    pub fn new() -> Self {
        Self {
            map_fd: None,
            heartbeat_map_fd: None,
            session_map_fd: None,
            conntrack_v4_fd: None,
            conntrack_v6_fd: None,
            dnat_table_fd: None,
            dnat_table_v6_fd: None,
            slow_path: None,
            local_tunnel_deliveries: Arc::new(ArcSwap::from_pointee(BTreeMap::new())),
            tunnel_sources: BTreeMap::new(),
            last_slow_path_status: SlowPathStatus::default(),
            ha_state: Arc::new(ArcSwap::from_pointee(BTreeMap::new())),
            shared_fabrics: Arc::new(ArcSwap::from_pointee(Vec::new())),
            shared_forwarding: Arc::new(ArcSwap::from_pointee(ForwardingState::default())),
            shared_validation: Arc::new(ArcSwap::from_pointee(ValidationState::default())),
            dynamic_neighbors: Arc::new(Mutex::new(FastMap::default())),
            neighbor_generation: Arc::new(AtomicU64::new(0)),
            manager_neighbor_keys: Arc::new(Mutex::new(FastSet::default())),
            neigh_monitor_stop: None,
            shared_sessions: Arc::new(Mutex::new(FastMap::default())),
            shared_nat_sessions: Arc::new(Mutex::new(FastMap::default())),
            shared_forward_wire_sessions: Arc::new(Mutex::new(FastMap::default())),
            live: BTreeMap::new(),
            identities: BTreeMap::new(),
            workers: BTreeMap::new(),
            demotion_prepare_seq: AtomicU64::new(0),
            ha_state_apply_seq: AtomicU64::new(0),
            session_export_seq: AtomicU64::new(0),
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
            poll_mode: crate::PollMode::BusyPoll,
            event_stream: None,
            last_cache_flush_at: Arc::new(AtomicU64::new(0)),
            rg_epochs: Arc::new(std::array::from_fn(|_| AtomicU32::new(0))),
        }
    }

    pub fn stop(&mut self) {
        self.stop_inner(true);
        // NOTE: Do NOT tear down event_stream here. The event stream must
        // survive across XSK bind/unbind cycles (e.g. when forwarding_armed
        // is temporarily false during startup). Use stop_with_event_stream()
        // for final process shutdown.
    }

    /// Full shutdown including the event stream. Called only on process exit.
    pub fn stop_with_event_stream(&mut self) {
        self.stop_inner(true);
        if let Some(mut es) = self.event_stream.take() {
            es.stop();
        }
    }

    /// Start the event stream sender. The I/O thread connects to the daemon
    /// listener at `socket_path` and pushes binary-framed session events.
    pub fn start_event_stream(&mut self, socket_path: &str) {
        self.event_stream = Some(crate::event_stream::EventStreamSender::new(socket_path));
    }

    /// Get a lightweight handle for worker threads to push events.
    pub fn event_stream_worker_handle(
        &self,
    ) -> Option<crate::event_stream::EventStreamWorkerHandle> {
        self.event_stream.as_ref().map(|es| es.worker_handle())
    }

    /// Event stream statistics for status reporting.
    pub fn event_stream_stats(&self) -> Option<crate::event_stream::EventStreamStats> {
        self.event_stream.as_ref().map(|es| es.stats())
    }

    pub fn dynamic_neighbors_ref(&self) -> &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>> {
        &self.dynamic_neighbors
    }

    pub fn apply_manager_neighbors(
        &self,
        replace: bool,
        neighbors: &[(i32, IpAddr, NeighborEntry)],
    ) {
        let Ok(mut cache) = self.dynamic_neighbors.lock() else {
            return;
        };
        let Ok(mut manager_keys) = self.manager_neighbor_keys.lock() else {
            return;
        };
        if replace {
            for key in manager_keys.drain() {
                cache.remove(&key);
            }
        }
        for (ifindex, ip, entry) in neighbors {
            let key = (*ifindex, *ip);
            cache.insert(key, *entry);
            manager_keys.insert(key);
        }
        self.neighbor_generation.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dynamic_neighbor_status(&self) -> (usize, u64) {
        let entries = self.dynamic_neighbors.lock().map(|n| n.len()).unwrap_or(0);
        let generation = self.neighbor_generation.load(Ordering::Relaxed);
        (entries, generation)
    }

    fn stop_inner(&mut self, clear_synced_state: bool) {
        if let Some(stop) = self.neigh_monitor_stop.take() {
            stop.store(true, Ordering::Relaxed);
        }
        for handle in self.tunnel_sources.values_mut() {
            handle.stop.store(true, Ordering::Relaxed);
        }
        for (_, handle) in self.tunnel_sources.iter_mut() {
            if let Some(join) = handle.join.take() {
                let _ = join.join();
            }
        }
        self.tunnel_sources.clear();
        self.local_tunnel_deliveries
            .store(Arc::new(BTreeMap::new()));
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
        self.conntrack_v4_fd = None;
        self.conntrack_v6_fd = None;
        self.dnat_table_fd = None;
        self.dnat_table_v6_fd = None;
        self.forwarding = ForwardingState::default();
        self.shared_forwarding
            .store(Arc::new(ForwardingState::default()));
        self.shared_validation
            .store(Arc::new(ValidationState::default()));
        self.shared_fabrics.store(Arc::new(Vec::new()));
        self.neighbor_generation.store(0, Ordering::Relaxed);
        if let Ok(mut neighbors) = self.dynamic_neighbors.lock() {
            neighbors.clear();
        }
        if let Ok(mut manager_keys) = self.manager_neighbor_keys.lock() {
            manager_keys.clear();
        }
        if clear_synced_state {
            if let Ok(mut sessions) = self.shared_sessions.lock() {
                sessions.clear();
            }
            if let Ok(mut nat_sessions) = self.shared_nat_sessions.lock() {
                nat_sessions.clear();
            }
            if let Ok(mut forward_wire_sessions) = self.shared_forward_wire_sessions.lock() {
                forward_wire_sessions.clear();
            }
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

    fn snapshot_shared_session_entries(&self) -> Vec<SyncedSessionEntry> {
        self.shared_sessions
            .lock()
            .map(|sessions| sessions.values().cloned().collect())
            .unwrap_or_default()
    }

    fn replay_synced_sessions(
        &self,
        entries: &[SyncedSessionEntry],
        worker_command_queues: &BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
        session_map_fd: c_int,
    ) -> usize {
        if entries.is_empty() {
            return 0;
        }
        let worker_queues = worker_command_queues.values().cloned().collect::<Vec<_>>();
        for entry in entries {
            let _ = publish_live_session_entry(
                session_map_fd,
                &entry.key,
                entry.decision.nat,
                entry.metadata.is_reverse,
            );
            replicate_session_upsert(&worker_queues, entry);
        }
        entries.len()
    }

    pub fn reconcile(
        &mut self,
        snapshot: Option<&ConfigSnapshot>,
        bindings: &mut [BindingStatus],
        ring_entries: usize,
    ) {
        self.reconcile_calls += 1;
        self.last_reconcile_stage = "start".to_string();
        let had_live_workers = !self.workers.is_empty();
        let preserved_synced_sessions = self.snapshot_shared_session_entries();
        // Keep a healthy slow-path worker across back-to-back reconciles. The
        // userspace helper can receive multiple snapshot refreshes during HA
        // role changes; recreating the fixed-name TUN on every reconcile can
        // race with teardown and leave the new owner without bpfrx-usp0.
        let preserved_slow_path = self.slow_path.as_ref().and_then(|slow| {
            if slow.status().active {
                Some(slow.clone())
            } else {
                None
            }
        });
        self.stop_inner(false);
        if had_live_workers {
            // Zero-copy queue teardown is not synchronously reusable on mlx5.
            // A short quiesce avoids EBUSY when a later snapshot refresh
            // rebuilds the same queue set immediately after shutdown.
            thread::sleep(Duration::from_millis(500));
        }
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
            binding.flow_cache_hits = 0;
            binding.flow_cache_misses = 0;
            binding.flow_cache_evictions = 0;
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
            binding.slow_path_local_delivery_packets = 0;
            binding.slow_path_missing_neighbor_packets = 0;
            binding.slow_path_no_route_packets = 0;
            binding.slow_path_next_table_packets = 0;
            binding.slow_path_forward_build_packets = 0;
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
        self.shared_validation.store(Arc::new(self.validation));
        self.shared_forwarding
            .store(Arc::new(self.forwarding.clone()));
        self.slow_path = if let Some(slow_path) = preserved_slow_path {
            self.last_slow_path_status = slow_path.status();
            Some(slow_path)
        } else {
            match SlowPathReinjector::new(DEFAULT_SLOW_PATH_TUN) {
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
            }
        };
        self.local_tunnel_deliveries
            .store(Arc::new(BTreeMap::new()));
        self.shared_fabrics
            .store(Arc::new(self.forwarding.fabrics.clone()));
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
        // Open BPF conntrack maps (sessions, sessions_v6) so the helper can
        // publish session entries that "show security flow session" reads.
        // Non-fatal: if the maps don't exist, session display will lack zone/interface info.
        let conntrack_v4_fd = if !snapshot.map_pins.conntrack_v4.is_empty() {
            OwnedFd::open_bpf_map(&snapshot.map_pins.conntrack_v4).ok()
        } else {
            None
        };
        let conntrack_v6_fd = if !snapshot.map_pins.conntrack_v6.is_empty() {
            OwnedFd::open_bpf_map(&snapshot.map_pins.conntrack_v6).ok()
        } else {
            None
        };
        // Open dnat_table BPF map for embedded ICMP NAT reversal support.
        // Non-fatal: if the map doesn't exist, embedded ICMP won't work
        // but normal forwarding is unaffected.
        let dnat_table_fd = if !snapshot.map_pins.dnat_table.is_empty() {
            OwnedFd::open_bpf_map(&snapshot.map_pins.dnat_table).ok()
        } else {
            None
        };
        let dnat_table_v6_fd = if !snapshot.map_pins.dnat_table_v6.is_empty() {
            OwnedFd::open_bpf_map(&snapshot.map_pins.dnat_table_v6).ok()
        } else {
            None
        };
        let dnat_fds = DnatTableFds {
            v4: dnat_table_fd.as_ref().map(|f| f.fd),
            v6: dnat_table_v6_fd.as_ref().map(|f| f.fd),
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
                    conntrack_v4_fd: conntrack_v4_fd.as_ref().map(|f| f.fd).unwrap_or(-1),
                    conntrack_v6_fd: conntrack_v6_fd.as_ref().map(|f| f.fd).unwrap_or(-1),
                    ring_entries,
                    bind_strategy: preferred_bind_strategy(binding),
                    poll_mode: self.poll_mode,
                });
        }
        for plans in workers.values_mut() {
            plans.sort_by_key(|plan| (plan.status.queue_id, plan.status.ifindex, plan.status.slot));
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
        let session_map_raw_fd = session_map_fd.fd;
        self.map_fd = Some(map_fd);
        self.heartbeat_map_fd = Some(heartbeat_map_fd);
        self.session_map_fd = Some(session_map_fd);
        self.conntrack_v4_fd = conntrack_v4_fd;
        self.conntrack_v6_fd = conntrack_v6_fd;
        self.dnat_table_fd = dnat_table_fd;
        self.dnat_table_v6_fd = dnat_table_v6_fd;
        let worker_command_queues: BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>> = workers
            .keys()
            .copied()
            .map(|worker_id| (worker_id, Arc::new(Mutex::new(VecDeque::new()))))
            .collect();
        let replayed_synced_sessions = self.replay_synced_sessions(
            &preserved_synced_sessions,
            &worker_command_queues,
            session_map_raw_fd,
        );
        if replayed_synced_sessions > 0 {
            self.last_reconcile_stage = format!(
                "replayed_synced:{}:workers={}",
                replayed_synced_sessions,
                worker_command_queues.len()
            );
        }
        for (worker_id, binding_plans) in workers {
            let plan_count = binding_plans.len();
            let stop = Arc::new(AtomicBool::new(false));
            let heartbeat = Arc::new(AtomicU64::new(monotonic_nanos()));
            let demotion_prepare_ack = Arc::new(AtomicU64::new(0));
            let ha_state_apply_ack = Arc::new(AtomicU64::new(0));
            let session_export_ack = Arc::new(AtomicU64::new(0));
            let commands = worker_command_queues
                .get(&worker_id)
                .cloned()
                .unwrap_or_else(|| Arc::new(Mutex::new(VecDeque::new())));
            let recent_exceptions = self.recent_exceptions.clone();
            let recent_session_deltas = self.recent_session_deltas.clone();
            let last_resolution = self.last_resolution.clone();
            let slow_path = self.slow_path.clone();
            let local_tunnel_deliveries = self.local_tunnel_deliveries.clone();
            let shared_forwarding = self.shared_forwarding.clone();
            let shared_validation = self.shared_validation.clone();
            let shared_sessions = self.shared_sessions.clone();
            let shared_nat_sessions = self.shared_nat_sessions.clone();
            let shared_forward_wire_sessions = self.shared_forward_wire_sessions.clone();
            let stop_clone = stop.clone();
            let heartbeat_clone = heartbeat.clone();
            let demotion_prepare_ack_clone = demotion_prepare_ack.clone();
            let ha_state_apply_ack_clone = ha_state_apply_ack.clone();
            let session_export_ack_clone = session_export_ack.clone();
            let commands_clone = commands.clone();
            let peer_commands_clone = worker_command_queues
                .iter()
                .filter(|(id, _)| **id != worker_id)
                .map(|(_, queue)| queue.clone())
                .collect::<Vec<_>>();
            let ha_state = self.ha_state.clone();
            let dynamic_neighbors = self.dynamic_neighbors.clone();
            let worker_poll_mode = self.poll_mode;
            let shared_fabrics = self.shared_fabrics.clone();
            let rg_epochs = self.rg_epochs.clone();
            let event_stream_handle = self.event_stream_worker_handle();
            let join = thread::Builder::new()
                .name(format!("bpfrx-userspace-worker-{worker_id}"))
                .spawn(move || {
                    worker_loop(
                        worker_id,
                        binding_plans,
                        shared_validation,
                        shared_forwarding,
                        ha_state,
                        dynamic_neighbors,
                        shared_sessions,
                        shared_nat_sessions,
                        shared_forward_wire_sessions,
                        slow_path,
                        local_tunnel_deliveries,
                        recent_exceptions,
                        recent_session_deltas,
                        last_resolution,
                        commands_clone,
                        peer_commands_clone,
                        stop_clone,
                        heartbeat_clone,
                        demotion_prepare_ack_clone,
                        ha_state_apply_ack_clone,
                        session_export_ack_clone,
                        worker_poll_mode,
                        dnat_fds,
                        shared_fabrics,
                        event_stream_handle,
                        rg_epochs,
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
                            demotion_prepare_ack,
                            ha_state_apply_ack,
                            session_export_ack,
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
        // Start the helper-owned neighbor sync path. It does an initial
        // RTM_GETNEIGH dump so startup sees the existing kernel table, then
        // subscribes to RTM_{NEW,DEL}NEIGH for incremental updates.
        if self.neigh_monitor_stop.is_none() {
            let stop = Arc::new(AtomicBool::new(false));
            let stop_clone = stop.clone();
            let dynamic_neighbors = self.dynamic_neighbors.clone();
            let neighbor_generation = self.neighbor_generation.clone();
            thread::Builder::new()
                .name("neigh-monitor".to_string())
                .spawn(move || {
                    neigh_monitor_thread(stop_clone, dynamic_neighbors, neighbor_generation)
                })
                .ok();
            self.neigh_monitor_stop = Some(stop);
        }
        self.spawn_local_tunnel_sources();
        self.refresh_bindings(bindings);
    }

    fn spawn_local_tunnel_sources(&mut self) {
        let mut local_tunnel_deliveries = BTreeMap::new();
        for endpoint in self.forwarding.tunnel_endpoints.values() {
            if endpoint.mode != "gre" && endpoint.mode != "ip6gre" {
                continue;
            }
            let Some(tunnel_name) = self
                .forwarding
                .ifindex_to_name
                .get(&endpoint.logical_ifindex)
                .cloned()
            else {
                continue;
            };
            let stop = Arc::new(AtomicBool::new(false));
            let stop_clone = stop.clone();
            let forwarding = self.forwarding.clone();
            let ha_state = self.ha_state.clone();
            let dynamic_neighbors = self.dynamic_neighbors.clone();
            let live = self.live.clone();
            let identities = self.identities.clone();
            let shared_sessions = self.shared_sessions.clone();
            let shared_nat_sessions = self.shared_nat_sessions.clone();
            let shared_forward_wire_sessions = self.shared_forward_wire_sessions.clone();
            let worker_commands = self
                .workers
                .values()
                .map(|handle| handle.commands.clone())
                .collect::<Vec<_>>();
            let recent_exceptions = self.recent_exceptions.clone();
            let tunnel_endpoint_id = endpoint.id;
            let thread_tunnel_name = tunnel_name.clone();
            let logical_ifindex = endpoint.logical_ifindex;
            let (delivery_tx, delivery_rx) = mpsc::sync_channel(LOCAL_TUNNEL_DELIVERY_QUEUE_DEPTH);
            let join = thread::Builder::new()
                .name(format!("bpfrx-native-gre-origin-{}", tunnel_name))
                .spawn(move || {
                    local_tunnel_source_loop(
                        thread_tunnel_name,
                        tunnel_endpoint_id,
                        forwarding,
                        ha_state,
                        dynamic_neighbors,
                        live,
                        identities,
                        shared_sessions,
                        shared_nat_sessions,
                        shared_forward_wire_sessions,
                        worker_commands,
                        delivery_rx,
                        recent_exceptions,
                        stop_clone,
                    );
                });
            match join {
                Ok(join) => {
                    local_tunnel_deliveries.insert(logical_ifindex, delivery_tx);
                    self.tunnel_sources.insert(
                        tunnel_endpoint_id,
                        LocalTunnelSourceHandle {
                            stop,
                            join: Some(join),
                        },
                    );
                }
                Err(err) => {
                    if let Ok(mut recent) = self.recent_exceptions.lock() {
                        push_recent_exception(
                            &mut recent,
                            ExceptionStatus {
                                timestamp: Utc::now(),
                                interface: tunnel_name,
                                reason: format!(
                                    "spawn_local_tunnel_source_failed:{tunnel_endpoint_id}:{err}"
                                ),
                                ..ExceptionStatus::default()
                            },
                        );
                    }
                }
            }
        }
        self.local_tunnel_deliveries
            .store(Arc::new(local_tunnel_deliveries));
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

    /// Refresh fabric link info from updated snapshots. Called when the
    /// Go daemon's refreshFabricFwd resolves a peer MAC that wasn't
    /// available at initial snapshot build time.
    ///
    /// NOTE: this updates self.forwarding directly. Workers that were spawned
    /// with an Arc of the previous forwarding state won't see this change
    /// until the next full reconcile. This is acceptable because fabric
    /// redirects check the forwarding state on every packet — the workers
    /// will get the updated state on the next reconcile (which happens
    /// on config change or rebind).
    pub fn refresh_fabric_links(&mut self, snapshots: &[crate::FabricSnapshot]) {
        let new_fabrics = resolve_fabric_links_from_snapshots(
            snapshots,
            &self.forwarding.egress,
            &self.dynamic_neighbors,
        );
        if !new_fabrics.is_empty() {
            self.forwarding.fabrics = new_fabrics.clone();
            self.shared_fabrics.store(Arc::new(new_fabrics));
        }
    }

    pub fn refresh_runtime_snapshot(&mut self, snapshot: &crate::ConfigSnapshot) {
        self.validation = ValidationState {
            snapshot_installed: true,
            config_generation: snapshot.generation,
            fib_generation: snapshot.fib_generation,
        };
        self.forwarding = build_forwarding_state(snapshot);
        self.shared_validation.store(Arc::new(self.validation));
        self.shared_forwarding
            .store(Arc::new(self.forwarding.clone()));
        self.shared_fabrics
            .store(Arc::new(self.forwarding.fabrics.clone()));
    }

    pub fn update_ha_state(&self, groups: &[HAGroupStatus]) -> Result<(), String> {
        let previous = self.ha_state.load();
        let now_secs = monotonic_nanos() / 1_000_000_000;
        let mut state = BTreeMap::new();
        for group in groups {
            // Treat every active HA state update as a lease refresh. Watchdog-only
            // updates renew the same lease model, and full active-state updates seed
            // it immediately so packet-time HA checks do not depend on a second
            // follow-up watchdog round-trip.
            let lease_timestamp = if group.active {
                group.watchdog_timestamp.max(now_secs)
            } else {
                0
            };
            let (demoting, demoting_until_secs) = if group.active {
                previous
                    .as_ref()
                    .get(&group.rg_id)
                    .map(|runtime| {
                        let demoting = runtime.demoting
                            && runtime.demoting_until_secs != 0
                            && now_secs <= runtime.demoting_until_secs;
                        (
                            demoting,
                            if demoting {
                                runtime.demoting_until_secs
                            } else {
                                0
                            },
                        )
                    })
                    .unwrap_or((false, 0))
            } else {
                (false, 0)
            };
            state.insert(
                group.rg_id,
                HAGroupRuntime {
                    active: group.active,
                    watchdog_timestamp: group.watchdog_timestamp,
                    lease_timestamp,
                    demoting,
                    demoting_until_secs,
                },
            );
        }
        let demoted_rgs = demoted_owner_rgs(previous.as_ref(), &state);
        let activated_rgs = activated_owner_rgs(previous.as_ref(), &state);
        // Debug: log state comparison for RGs 0-2
        for rg_id in 0..=2i32 {
            let prev_active = previous.get(&rg_id).map(|r| r.active);
            let curr_active = state.get(&rg_id).map(|r| r.active);
            if prev_active != curr_active {
                eprintln!(
                    "bpfrx-ha: RG{} state changed: {:?} -> {:?} (demoted={:?} activated={:?})",
                    rg_id, prev_active, curr_active, demoted_rgs, activated_rgs
                );
            }
        }
        self.ha_state.store(Arc::new(state));
        if !demoted_rgs.is_empty() {
            // CRITICAL: Delete sessions from USERSPACE_SESSIONS BPF map
            // IMMEDIATELY, before workers process DemoteOwnerRG asynchronously.
            // Without this, there's a window where rg_active=0 but the XDP shim
            // still finds sessions in USERSPACE_SESSIONS and redirects to XSK,
            // bypassing the eBPF pipeline's fabric redirect for demoted RGs.
            if let Some(session_map_ref) = self.session_map_fd.as_ref() {
                let rg_set: std::collections::BTreeSet<i32> = demoted_rgs.iter().copied().collect();
                let mut deleted = 0u32;
                // Delete from shared_sessions (covers synced + promoted sessions)
                if let Ok(sessions) = self.shared_sessions.lock() {
                    for (key, entry) in sessions.iter() {
                        if rg_set.contains(&entry.metadata.owner_rg_id) {
                            delete_live_session_key(session_map_ref.fd, key);
                            deleted += 1;
                        }
                    }
                }
                // Delete alias keys from shared_nat_sessions (reverse-wire +
                // reverse-canonical aliases that are also in the BPF map).
                if let Ok(sessions) = self.shared_nat_sessions.lock() {
                    for (key, entry) in sessions.iter() {
                        if rg_set.contains(&entry.metadata.owner_rg_id) {
                            delete_live_session_key(session_map_ref.fd, key);
                            deleted += 1;
                        }
                    }
                }
                // Delete alias keys from shared_forward_wire_sessions
                // (translated forward-wire aliases that are also in the BPF map).
                if let Ok(sessions) = self.shared_forward_wire_sessions.lock() {
                    for (key, entry) in sessions.iter() {
                        if rg_set.contains(&entry.metadata.owner_rg_id) {
                            delete_live_session_key(session_map_ref.fd, key);
                            deleted += 1;
                        }
                    }
                }
                if deleted > 0 {
                    eprintln!(
                        "bpfrx-ha: immediate USERSPACE_SESSIONS cleanup for demoted RGs {:?}: {} entries",
                        demoted_rgs, deleted
                    );
                }
            }

            demote_shared_owner_rgs(
                &self.shared_sessions,
                &self.shared_nat_sessions,
                &self.shared_forward_wire_sessions,
                &demoted_rgs,
            );
            // Bump RG epochs atomically — O(1) invalidation. Workers will
            // treat flow cache entries with stale epochs as misses.
            for rg_id in &demoted_rgs {
                let idx = *rg_id as usize;
                if idx > 0 && idx < MAX_RG_EPOCHS {
                    self.rg_epochs[idx].fetch_add(1, Ordering::Release);
                }
            }
            for handle in self.workers.values() {
                if let Ok(mut pending) = handle.commands.lock() {
                    for rg_id in &demoted_rgs {
                        pending.push_back(WorkerCommand::DemoteOwnerRG(*rg_id));
                    }
                }
            }
            // Record cache flush timestamp for observability (#312).
            self.last_cache_flush_at.store(now_secs, Ordering::Relaxed);
        }
        if !activated_rgs.is_empty() {
            eprintln!(
                "bpfrx-ha: RG activation detected: {:?}, workers={}, shared_sessions={}",
                activated_rgs,
                self.workers.len(),
                self.shared_sessions.lock().map(|s| s.len()).unwrap_or(0),
            );
            let worker_commands = self
                .workers
                .values()
                .map(|handle| handle.commands.clone())
                .collect::<Vec<_>>();
            let Some(session_map_ref) = self.session_map_fd.as_ref() else {
                eprintln!("bpfrx-ha: no session_map_fd, skipping activation");
                return Ok(());
            };
            let session_map_fd = session_map_ref.fd;
            let now_secs = monotonic_nanos() / 1_000_000_000;
            let current = self.ha_state.load();
            prewarm_reverse_synced_sessions_for_owner_rgs(
                &self.shared_sessions,
                &self.shared_nat_sessions,
                &self.shared_forward_wire_sessions,
                &worker_commands,
                session_map_fd,
                &self.forwarding,
                current.as_ref(),
                &self.dynamic_neighbors,
                &activated_rgs,
                now_secs,
            );
            if !self.workers.is_empty() {
                let sequence = self
                    .ha_state_apply_seq
                    .fetch_add(1, Ordering::Relaxed)
                    .saturating_add(1);
                for handle in self.workers.values() {
                    let mut pending = handle
                        .commands
                        .lock()
                        .map_err(|_| "worker command queue poisoned".to_string())?;
                    // Queue the apply barrier after any reverse-prewarm upserts
                    // pushed above. Acking this sequence means the worker has
                    // applied the current HA generation and the activation-time
                    // helper work for it.
                    pending.push_back(WorkerCommand::ApplyHAState { sequence });
                }
                let deadline = std::time::Instant::now() + Duration::from_secs(2);
                loop {
                    if self
                        .workers
                        .values()
                        .all(|handle| handle.ha_state_apply_ack.load(Ordering::Acquire) >= sequence)
                    {
                        break;
                    }
                    if std::time::Instant::now() >= deadline {
                        return Err(format!(
                            "ha state apply seq={} timed out waiting for worker acks",
                            sequence
                        ));
                    }
                    thread::sleep(Duration::from_millis(1));
                }
            }
        }
        Ok(())
    }

    fn set_demoting_owner_rgs(&self, owner_rgs: &[i32], demoting: bool) {
        if owner_rgs.is_empty() {
            return;
        }
        let previous = self.ha_state.load();
        let mut state = previous.as_ref().clone();
        let mut changed = false;
        let now_secs = monotonic_nanos() / 1_000_000_000;
        for rg_id in owner_rgs {
            if let Some(runtime) = state.get_mut(rg_id) {
                let next_demoting = demoting && runtime.active;
                let next_deadline = if next_demoting {
                    now_secs.saturating_add(HA_DEMOTION_PREP_LEASE_SECS)
                } else {
                    0
                };
                if runtime.demoting != next_demoting || runtime.demoting_until_secs != next_deadline
                {
                    runtime.demoting = next_demoting;
                    runtime.demoting_until_secs = next_deadline;
                    changed = true;
                }
            }
        }
        if changed {
            self.ha_state.store(Arc::new(state));
        }
    }

    pub fn prepare_ha_demotion(&self, owner_rgs: &[i32]) -> Result<(), String> {
        if owner_rgs.is_empty() {
            return Ok(());
        }
        self.set_demoting_owner_rgs(owner_rgs, true);
        let sequence = self
            .demotion_prepare_seq
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        for handle in self.workers.values() {
            let mut pending = handle
                .commands
                .lock()
                .map_err(|_| "worker command queue poisoned".to_string())?;
            pending.push_back(WorkerCommand::PrepareDemoteOwnerRGs {
                sequence,
                owner_rgs: owner_rgs.to_vec(),
            });
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        loop {
            if self
                .workers
                .values()
                .all(|handle| handle.demotion_prepare_ack.load(Ordering::Acquire) >= sequence)
            {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                self.set_demoting_owner_rgs(owner_rgs, false);
                return Err(format!(
                    "timed out waiting for demotion prepare ack seq={sequence}"
                ));
            }
            thread::sleep(Duration::from_millis(5));
        }
    }

    /// Explicitly clear a stale demotion mark that was set by
    /// `prepare_ha_demotion` but never completed (e.g. Go-side timeout).
    /// The auto-expiry lease will eventually clear it, but this provides
    /// immediate cleanup so the helper stops treating the RG as demoting.
    pub fn clear_ha_demotion(&self, owner_rgs: &[i32]) {
        if owner_rgs.is_empty() {
            return;
        }
        self.set_demoting_owner_rgs(owner_rgs, false);
        eprintln!(
            "bpfrx-ha: cleared stale demotion mark for RGs {:?}",
            owner_rgs
        );
    }

    pub fn export_owner_rg_sessions(
        &self,
        owner_rgs: &[i32],
        max: usize,
    ) -> Result<Vec<SessionDeltaInfo>, String> {
        if owner_rgs.is_empty() {
            return Ok(Vec::new());
        }
        let sequence = self
            .session_export_seq
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        for handle in self.workers.values() {
            let mut pending = handle
                .commands
                .lock()
                .map_err(|_| "worker command queue poisoned".to_string())?;
            pending.push_back(WorkerCommand::ExportOwnerRGSessions {
                sequence,
                owner_rgs: owner_rgs.to_vec(),
            });
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        loop {
            if self
                .workers
                .values()
                .all(|handle| handle.session_export_ack.load(Ordering::Acquire) >= sequence)
            {
                break;
            }
            if std::time::Instant::now() >= deadline {
                return Err(format!(
                    "timed out waiting for session export ack seq={sequence}"
                ));
            }
            thread::sleep(Duration::from_millis(5));
        }
        let mut out = Vec::new();
        let mut remaining = if max == 0 { usize::MAX } else { max.max(1) };
        while remaining > 0 {
            let batch_size = remaining.min(1024);
            let drained = self.drain_session_deltas(batch_size);
            if drained.is_empty() {
                break;
            }
            remaining = remaining.saturating_sub(drained.len());
            out.extend(drained);
        }
        Ok(out)
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

    /// Returns the monotonic timestamp (secs) of the last HA flow cache flush.
    pub fn last_cache_flush_at(&self) -> u64 {
        self.last_cache_flush_at.load(Ordering::Relaxed)
    }

    pub fn upsert_synced_session(&self, entry: SyncedSessionEntry) {
        let now_secs = monotonic_nanos() / 1_000_000_000;
        let ha_state = self.ha_state.load();
        let reverse_entry = if !entry.metadata.is_reverse {
            synthesized_synced_reverse_entry(
                &self.forwarding,
                ha_state.as_ref(),
                &self.dynamic_neighbors,
                &entry,
                now_secs,
            )
        } else {
            None
        };
        publish_shared_session(
            &self.shared_sessions,
            &self.shared_nat_sessions,
            &self.shared_forward_wire_sessions,
            &entry,
        );
        if let Some(reverse) = &reverse_entry {
            publish_shared_session(
                &self.shared_sessions,
                &self.shared_nat_sessions,
                &self.shared_forward_wire_sessions,
                reverse,
            );
            if let Some(session_map_fd) = self.session_map_fd.as_ref() {
                let _ = publish_live_session_entry(
                    session_map_fd.fd,
                    &reverse.key,
                    reverse.decision.nat,
                    true,
                );
            }
        }
        for handle in self.workers.values() {
            if let Ok(mut pending) = handle.commands.lock() {
                pending.push_back(WorkerCommand::UpsertSynced(entry.clone()));
                if let Some(reverse) = &reverse_entry {
                    pending.push_back(WorkerCommand::UpsertSynced(reverse.clone()));
                }
            }
        }
    }

    pub fn delete_synced_session(&self, key: SessionKey) {
        let reverse_key = self
            .shared_sessions
            .lock()
            .ok()
            .and_then(|sessions| sessions.get(&key).cloned())
            .and_then(|entry| {
                if entry.metadata.is_reverse {
                    None
                } else {
                    Some(reverse_session_key(&entry.key, entry.decision.nat))
                }
            });
        remove_shared_session(
            &self.shared_sessions,
            &self.shared_nat_sessions,
            &self.shared_forward_wire_sessions,
            &key,
        );
        if let Some(reverse_key) = &reverse_key {
            remove_shared_session(
                &self.shared_sessions,
                &self.shared_nat_sessions,
                &self.shared_forward_wire_sessions,
                reverse_key,
            );
        }
        for handle in self.workers.values() {
            if let Ok(mut pending) = handle.commands.lock() {
                pending.push_back(WorkerCommand::DeleteSynced(key.clone()));
                if let Some(reverse_key) = &reverse_key {
                    pending.push_back(WorkerCommand::DeleteSynced(reverse_key.clone()));
                }
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
                if snap.bound && !binding.bound {
                    eprintln!(
                        "refresh_bindings: slot={} transitioning bound=false->true fd={}",
                        binding.slot, snap.socket_fd
                    );
                }
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
                binding.flow_cache_hits = snap.flow_cache_hits;
                binding.flow_cache_misses = snap.flow_cache_misses;
                binding.flow_cache_evictions = snap.flow_cache_evictions;
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
                binding.slow_path_local_delivery_packets = snap.slow_path_local_delivery_packets;
                binding.slow_path_missing_neighbor_packets =
                    snap.slow_path_missing_neighbor_packets;
                binding.slow_path_no_route_packets = snap.slow_path_no_route_packets;
                binding.slow_path_next_table_packets = snap.slow_path_next_table_packets;
                binding.slow_path_forward_build_packets = snap.slow_path_forward_build_packets;
                binding.slow_path_drops = snap.slow_path_drops;
                binding.slow_path_rate_limited = snap.slow_path_rate_limited;
                binding.kernel_rx_dropped = snap.kernel_rx_dropped;
                binding.kernel_rx_invalid_descs = snap.kernel_rx_invalid_descs;
                binding.tx_packets = snap.tx_packets;
                binding.tx_bytes = snap.tx_bytes;
                binding.tx_completions = snap.tx_completions;
                binding.tx_errors = snap.tx_errors;
                binding.direct_tx_packets = snap.direct_tx_packets;
                binding.copy_tx_packets = snap.copy_tx_packets;
                binding.in_place_tx_packets = snap.in_place_tx_packets;
                binding.direct_tx_no_frame_fallback_packets =
                    snap.direct_tx_no_frame_fallback_packets;
                binding.direct_tx_build_fallback_packets = snap.direct_tx_build_fallback_packets;
                binding.direct_tx_disallowed_fallback_packets =
                    snap.direct_tx_disallowed_fallback_packets;
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
                binding.flow_cache_hits = 0;
                binding.flow_cache_misses = 0;
                binding.flow_cache_evictions = 0;
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
                binding.slow_path_local_delivery_packets = 0;
                binding.slow_path_missing_neighbor_packets = 0;
                binding.slow_path_no_route_packets = 0;
                binding.slow_path_next_table_packets = 0;
                binding.slow_path_forward_build_packets = 0;
                binding.slow_path_drops = 0;
                binding.slow_path_rate_limited = 0;
                binding.kernel_rx_dropped = 0;
                binding.kernel_rx_invalid_descs = 0;
                binding.tx_packets = 0;
                binding.tx_bytes = 0;
                binding.tx_completions = 0;
                binding.tx_errors = 0;
                binding.direct_tx_packets = 0;
                binding.copy_tx_packets = 0;
                binding.in_place_tx_packets = 0;
                binding.direct_tx_no_frame_fallback_packets = 0;
                binding.direct_tx_build_fallback_packets = 0;
                binding.direct_tx_disallowed_fallback_packets = 0;
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

struct BindingWorker {
    slot: u32,
    queue_id: u32,
    worker_id: u32,
    interface: Arc<str>,
    ifindex: i32,
    umem: WorkerUmem,
    live: Arc<BindingLiveState>,
    #[allow(dead_code)]
    user: User,
    device: crate::xsk_ffi::DeviceQueue,
    rx: crate::xsk_ffi::RingRx,
    tx: crate::xsk_ffi::RingTx,
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
    scratch_completed_offsets: Vec<u64>,
    scratch_post_recycles: Vec<(u32, u64)>,
    /// Packets waiting for neighbor resolution. The UMEM frame is held
    /// (not recycled) until the neighbor resolves or the entry times out.
    pending_neigh: VecDeque<PendingNeighPacket>,
    /// Flow cache fast-path: cross-binding in-place rewrites deferred
    /// until after the RX batch (borrow checker prevents mutable access
    /// to two bindings simultaneously inside the RX loop).
    scratch_cross_binding_tx: Vec<(usize, PreparedTxRequest)>,
    scratch_rst_teardowns: Vec<(SessionKey, NatDecision)>,
    in_flight_prepared_recycles: FastMap<u64, PreparedTxRecycle>,
    heartbeat_map_fd: c_int,
    session_map_fd: c_int,
    conntrack_v4_fd: c_int,
    conntrack_v6_fd: c_int,
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
    dbg_tx_ring_submitted: u64,  // descriptors inserted into TX ring
    dbg_tx_ring_full: u64,       // times TX ring insert returned 0
    dbg_completions_reaped: u64, // completion descriptors read
    dbg_sendto_calls: u64,       // number of sendto/wake calls
    dbg_sendto_err: u64,         // sendto returned error (non-EAGAIN/ENOBUFS)
    dbg_sendto_eagain: u64,      // sendto returned EAGAIN/EWOULDBLOCK
    dbg_sendto_enobufs: u64,     // sendto returned ENOBUFS (kernel TX drop)
    dbg_pending_overflow: u64,   // drops from bound_pending overflow
    dbg_tx_tcp_rst: u64,         // TCP RST packets transmitted
    // Ring diagnostics — raw values from xsk_ffi API
    dbg_rx_avail_nonzero: u64,     // times rx.available() > 0
    dbg_rx_avail_max: u32,         // max rx.available() seen this interval
    dbg_fill_pending: u32,         // fill ring: userspace produced - kernel consumed
    dbg_device_avail: u32,         // device queue available (completion ring pending)
    dbg_rx_wake_sendto_ok: u64,    // sendto() returned >= 0 in maybe_wake_rx
    dbg_rx_wake_sendto_err: u64,   // sendto() returned < 0 in maybe_wake_rx
    dbg_rx_wake_sendto_errno: i32, // last errno from sendto in maybe_wake_rx
    pending_direct_tx_packets: u64,
    pending_copy_tx_packets: u64,
    pending_in_place_tx_packets: u64,
    pending_direct_tx_no_frame_fallback_packets: u64,
    pending_direct_tx_build_fallback_packets: u64,
    pending_direct_tx_disallowed_fallback_packets: u64,
    flow_cache: FlowCache,
    flow_cache_session_touch: u64,
    /// Timestamp when this binding was created.
    bind_time_ns: u64,
    /// Zero-copy vs copy mode (affects heartbeat gating).
    bind_mode: XskBindMode,
    /// Set true once the XSK RX ring has delivered at least one packet,
    /// proving the NIC's XSK receive queue is active for this binding.
    xsk_rx_confirmed: bool,
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

fn fabric_queue_hash(
    flow: Option<&SessionFlow>,
    expected_ports: Option<(u16, u16)>,
    meta: UserspaceDpMeta,
) -> u64 {
    fn mix(seed: &mut u64, value: u64) {
        *seed ^= value
            .wrapping_add(0x9e3779b97f4a7c15)
            .wrapping_add(*seed << 6)
            .wrapping_add(*seed >> 2);
    }

    let mut seed = meta.protocol as u64;
    if let Some(flow) = flow {
        match flow.src_ip {
            IpAddr::V4(ip) => mix(&mut seed, u32::from(ip) as u64),
            IpAddr::V6(ip) => {
                for chunk in ip.octets().chunks_exact(8) {
                    mix(&mut seed, u64::from_be_bytes(chunk.try_into().unwrap()));
                }
            }
        }
        match flow.dst_ip {
            IpAddr::V4(ip) => mix(&mut seed, u32::from(ip) as u64),
            IpAddr::V6(ip) => {
                for chunk in ip.octets().chunks_exact(8) {
                    mix(&mut seed, u64::from_be_bytes(chunk.try_into().unwrap()));
                }
            }
        }
        mix(&mut seed, flow.forward_key.src_port as u64);
        mix(&mut seed, flow.forward_key.dst_port as u64);
        return seed;
    }
    let (src_port, dst_port) = expected_ports.unwrap_or((meta.flow_src_port, meta.flow_dst_port));
    mix(&mut seed, src_port as u64);
    mix(&mut seed, dst_port as u64);
    seed
}

#[derive(Clone, Debug)]
pub(crate) struct SyncedSessionEntry {
    pub(crate) key: SessionKey,
    pub(crate) decision: SessionDecision,
    pub(crate) metadata: SessionMetadata,
    pub(crate) origin: SessionOrigin,
    pub(crate) protocol: u8,
    pub(crate) tcp_flags: u8,
}

impl BindingWorker {
    fn create(
        binding: &BindingStatus,
        ring_entries: u32,
        xsk_map_fd: c_int,
        heartbeat_map_fd: c_int,
        session_map_fd: c_int,
        conntrack_v4_fd: c_int,
        conntrack_v6_fd: c_int,
        live: Arc<BindingLiveState>,
        bind_strategy: AfXdpBindStrategy,
        poll_mode: crate::PollMode,
        mut worker_umem: WorkerUmem,
        frame_pool: &mut VecDeque<u64>,
        shared_umem: bool,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let driver_name = interface_driver_name(&binding.interface);
        let total_frames =
            binding_frame_count_for_driver(driver_name.as_deref(), ring_entries).max(1);
        let reserved_tx =
            reserved_tx_frames_for_driver(driver_name.as_deref(), ring_entries).min(total_frames);
        let mut reserved_tx_frames = VecDeque::with_capacity(reserved_tx as usize);
        for _ in 0..reserved_tx {
            let Some(offset) = frame_pool.pop_front() else {
                return Err(format!(
                    "insufficient shared UMEM frames for reserved TX on {} if{}q{}",
                    binding.interface, binding.ifindex, binding.queue_id
                )
                .into());
            };
            reserved_tx_frames.push_back(offset);
        }
        // Pre-populate fill ring with ALL remaining frames — no spare held back.
        // This maximizes the kernel's ability to place received packets and
        // prevents fill ring starvation under burst conditions (copy-mode fix).
        let mut initial_fill_frames = Vec::with_capacity((total_frames - reserved_tx) as usize);
        for _ in reserved_tx..total_frames {
            let Some(offset) = frame_pool.pop_front() else {
                return Err(format!(
                    "insufficient shared UMEM frames for fill ring on {} if{}q{}",
                    binding.interface, binding.ifindex, binding.queue_id
                )
                .into());
            };
            initial_fill_frames.push(offset);
        }
        let info = ifinfo_from_binding(binding)?;
        let (user, rx, tx, bind_mode, actual_bind_strategy, device) = open_binding_worker_rings(
            &mut worker_umem,
            &info,
            ring_entries,
            bind_strategy,
            driver_name.as_deref(),
            poll_mode,
            Some(&initial_fill_frames),
        )
        .map_err(|err| format!("configure AF_XDP rings: {err}"))?;

        let user_fd = user.as_raw_fd();
        live.set_bound(user_fd);
        live.set_bind_mode(bind_mode);
        // getsockname() returns ENOTSUP on AF_XDP sockets (kernel doesn't
        // implement it for this family).  Use the binding plan's expected
        // ifindex/queue_id directly — umem.bind() already validated these.
        live.set_socket_binding(binding.ifindex, binding.queue_id, 0);
        eprintln!(
            "bpfrx-userspace-dp: binding slot={} fd={} strategy={} bound if{}q{} mode={:?} shared_umem={}",
            binding.slot,
            user_fd,
            actual_bind_strategy.describe(),
            binding.ifindex,
            binding.queue_id,
            bind_mode,
            shared_umem,
        );
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
            live.clear_error();
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
            scratch_completed_offsets: Vec::with_capacity(ring_entries as usize),
            scratch_post_recycles: Vec::with_capacity(RX_BATCH_SIZE as usize),
            pending_neigh: VecDeque::with_capacity(MAX_PENDING_NEIGH),
            scratch_cross_binding_tx: Vec::with_capacity(RX_BATCH_SIZE as usize),
            scratch_rst_teardowns: Vec::with_capacity(16),
            in_flight_prepared_recycles: FastMap::default(),
            heartbeat_map_fd,
            session_map_fd,
            conntrack_v4_fd,
            conntrack_v6_fd,
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
            pending_direct_tx_packets: 0,
            pending_copy_tx_packets: 0,
            pending_in_place_tx_packets: 0,
            pending_direct_tx_no_frame_fallback_packets: 0,
            pending_direct_tx_build_fallback_packets: 0,
            pending_direct_tx_disallowed_fallback_packets: 0,
            flow_cache: FlowCache::new(),
            flow_cache_session_touch: 0,
            bind_time_ns: {
                let mut ts = libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                };
                unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
                ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
            },
            xsk_rx_confirmed: false,
            bind_mode,
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

fn poll_binding(
    binding_index: usize,
    bindings: &mut [BindingWorker],
    binding_lookup: &WorkerBindingLookup,
    sessions: &mut SessionTable,
    screen: &mut ScreenState,
    validation: ValidationState,
    now_ns: u64,
    now_secs: u64,
    ha_startup_grace_until_secs: u64,
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    slow_path: Option<&Arc<SlowPathReinjector>>,
    local_tunnel_deliveries: &Arc<ArcSwap<BTreeMap<i32, SyncSender<Vec<u8>>>>>,
    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
    _recent_session_deltas: &Arc<Mutex<VecDeque<SessionDeltaInfo>>>,
    last_resolution: &Arc<Mutex<Option<PacketResolution>>>,
    peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    shared_recycles: &mut Vec<(u32, u64)>,
    dnat_fds: &DnatTableFds,
    conntrack_v4_fd: c_int,
    conntrack_v6_fd: c_int,
    dbg: &mut DebugPollCounters,
    rg_epochs: &[AtomicU32; MAX_RG_EPOCHS],
) -> bool {
    #[derive(Default)]
    struct BatchCounters {
        touched: bool,
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
            if !self.touched {
                return;
            }
            if self.rx_packets != 0 {
                live.rx_packets
                    .fetch_add(self.rx_packets, Ordering::Relaxed);
                self.rx_packets = 0;
            }
            if self.rx_bytes != 0 {
                live.rx_bytes.fetch_add(self.rx_bytes, Ordering::Relaxed);
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
            self.touched = false;
        }
    }

    let (left, rest) = bindings.split_at_mut(binding_index);
    let Some((binding, right)) = rest.split_first_mut() else {
        return false;
    };
    let area = binding.umem.area() as *const MmapArea;
    maybe_touch_heartbeat(binding, now_ns);
    let tx_work = drain_pending_tx(binding, now_ns, shared_recycles);
    apply_shared_recycles(
        left,
        binding_index,
        binding,
        right,
        binding_lookup,
        shared_recycles,
    );
    let fill_work = drain_pending_fill(binding, now_ns);
    let mut did_work = tx_work || fill_work;
    binding.dbg_poll_cycles += 1;
    let mut counters = BatchCounters::default();
    let mut ident: Option<BindingIdentity> = None;
    for _ in 0..MAX_RX_BATCHES_PER_POLL {
        // Backpressure: skip RX when TX queues are heavily loaded to prevent
        // fill ring exhaustion. The NIC holds packets until we refill (#201).
        let tx_backlog = binding.pending_tx_local.len() + binding.pending_tx_prepared.len();
        if tx_backlog >= binding.max_pending_tx {
            binding.dbg_backpressure += 1;
            // Try to drain TX first — completions free frames for both TX and fill.
            let _ = drain_pending_tx(binding, now_ns, shared_recycles);
            apply_shared_recycles(
                left,
                binding_index,
                binding,
                right,
                binding_lookup,
                shared_recycles,
            );
            // Critical: drain fill ring even under backpressure so the NIC can
            // still receive packets. Without this, fill ring starvation causes
            // mlx5 to fall back to non-XSK NAPI, leaking packets to the kernel.
            let _ = drain_pending_fill(binding, now_ns);
            counters.flush(&binding.live);
            update_binding_debug_state(binding);
            return did_work;
        }

        let raw_avail = binding.rx.available();
        let available = raw_avail.min(RX_BATCH_SIZE);
        if raw_avail > 0 && !binding.xsk_rx_confirmed {
            binding.xsk_rx_confirmed = true;
        }
        if cfg!(feature = "debug-log") {
            if raw_avail > 0 {
                binding.dbg_rx_avail_nonzero += 1;
                if raw_avail > binding.dbg_rx_avail_max {
                    binding.dbg_rx_avail_max = raw_avail;
                }
            }
            // Ring diagnostics are only consumed by debug-log summaries.
            binding.dbg_fill_pending = binding.device.pending();
            binding.dbg_device_avail = binding.device.available();
        }
        if available == 0 {
            binding.dbg_rx_empty += 1;
            maybe_wake_rx(binding, false, now_ns);
            // Check pending neighbor buffer even when RX is empty.
            // Without this, buffered SYN packets wait until the next
            // RX packet arrives (TCP retransmit ~1s) instead of being
            // retried as soon as the netlink monitor resolves ARP.
            retry_pending_neigh(
                binding,
                left,
                binding_index,
                right,
                binding_lookup,
                forwarding,
                dynamic_neighbors,
                now_ns,
                unsafe { &*(binding.umem.area() as *const MmapArea) },
            );
            counters.flush(&binding.live);
            update_binding_debug_state(binding);
            return did_work;
        }
        binding.empty_rx_polls = 0;
        if ident.is_none() {
            ident = Some(binding.identity());
        }
        let ident = ident
            .as_ref()
            .expect("identity initialized when RX has work");

        let mut received = binding.rx.receive(available);
        binding.scratch_recycle.clear();
        binding.scratch_forwards.clear();
        binding.scratch_rst_teardowns.clear();
        while let Some(desc) = received.read() {
            // Prefetch frame data into L1 while processing counters.
            // UMEM frames are cold (last touched by NIC DMA); this hides
            // ~100ns DRAM latency before metadata parse.
            #[cfg(target_arch = "x86_64")]
            if let Some(pf) = unsafe { &*area }.slice(desc.addr as usize, 64.min(desc.len as usize))
            {
                unsafe {
                    core::arch::x86_64::_mm_prefetch(
                        pf.as_ptr() as *const i8,
                        core::arch::x86_64::_MM_HINT_T0,
                    );
                }
            }
            counters.touched = true;
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
                            eprintln!("DBG OVERSIZED_RX[{}]: if={} q={} desc.len={} (exceeds ETH+MTU 1514)",
                                n, ident.ifindex, ident.queue_id, desc.len,
                            );
                        }
                    });
                }
            }
            // TCP flag detection on RX
            if cfg!(feature = "debug-log") {
                if desc.len >= 54 {
                    if let Some(rx_frame) =
                        unsafe { &*area }.slice(desc.addr as usize, desc.len as usize)
                    {
                        // Check for FIN, SYN+ACK, zero-window
                        if let Some(tcp_info) = extract_tcp_flags_and_window(rx_frame) {
                            if (tcp_info.0 & 0x01) != 0 {
                                // FIN
                                dbg.rx_tcp_fin += 1;
                            }
                            if (tcp_info.0 & 0x12) == 0x12 {
                                // SYN+ACK
                                dbg.rx_tcp_synack += 1;
                            }
                            if tcp_info.1 == 0 && (tcp_info.0 & 0x02) == 0 {
                                // zero window, not SYN
                                dbg.rx_tcp_zero_window += 1;
                                if dbg.rx_tcp_zero_window <= 10 {
                                    eprintln!(
                                        "RX_TCP_ZERO_WIN[{}]: if={} q={} len={} flags=0x{:02x}",
                                        dbg.rx_tcp_zero_window,
                                        ident.ifindex,
                                        ident.queue_id,
                                        desc.len,
                                        tcp_info.0,
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
                                        let hex_len =
                                            (desc.len as usize).min(rx_frame.len()).min(80);
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
                    if let Some(rx_frame) =
                        unsafe { &*area }.slice(desc.addr as usize, desc.len as usize)
                    {
                        // Decode IP+TCP details from the frame
                        let pkt_detail = decode_frame_summary(rx_frame);
                        eprintln!(
                            "DBG RX_ETH[{}]: if={} q={} len={} {}",
                            dbg.rx, ident.ifindex, ident.queue_id, desc.len, pkt_detail,
                        );
                        // Full hex dump for first 3 packets
                        if dbg.rx <= 3 {
                            let dump_len = (desc.len as usize).min(rx_frame.len()).min(80);
                            let hex: String = rx_frame[..dump_len]
                                .iter()
                                .map(|b| format!("{:02x}", b))
                                .collect::<Vec<_>>()
                                .join(" ");
                            eprintln!("DBG RX_HEX[{}]: {}", dbg.rx, hex);
                        }
                    }
                }
            }
            let mut recycle_now = true;
            if let Some(meta) = try_parse_metadata(unsafe { &*area }, desc) {
                counters.metadata_packets += 1;
                let disposition = classify_metadata(meta, validation);
                if disposition == PacketDisposition::Valid {
                    counters.validated_packets += 1;
                    counters.validated_bytes += desc.len as u64;
                    let Some(raw_frame) =
                        unsafe { &*area }.slice(desc.addr as usize, desc.len as usize)
                    else {
                        binding.scratch_recycle.push(desc.addr);
                        continue;
                    };
                    // Check for ARP reply (ethertype 0x0806, opcode 0x0002).
                    // Parse it and update the dynamic neighbor cache.
                    // Handles both untagged and VLAN-tagged (802.1Q) ARP frames.
                    if raw_frame.len() >= 42 {
                        let (arp_start, ethertype) = if raw_frame.len() >= 18
                            && u16::from_be_bytes([raw_frame[12], raw_frame[13]]) == 0x8100
                        {
                            (18, u16::from_be_bytes([raw_frame[16], raw_frame[17]]))
                        } else {
                            (14, u16::from_be_bytes([raw_frame[12], raw_frame[13]]))
                        };
                        if ethertype == 0x0806 && raw_frame.len() >= arp_start + 28 {
                            let opcode = u16::from_be_bytes([
                                raw_frame[arp_start + 6],
                                raw_frame[arp_start + 7],
                            ]);
                            if opcode == 2 {
                                // ARP reply — extract sender MAC and IP
                                let sender_mac = [
                                    raw_frame[arp_start + 8],
                                    raw_frame[arp_start + 9],
                                    raw_frame[arp_start + 10],
                                    raw_frame[arp_start + 11],
                                    raw_frame[arp_start + 12],
                                    raw_frame[arp_start + 13],
                                ];
                                let sender_ip = IpAddr::V4(Ipv4Addr::new(
                                    raw_frame[arp_start + 14],
                                    raw_frame[arp_start + 15],
                                    raw_frame[arp_start + 16],
                                    raw_frame[arp_start + 17],
                                ));
                                // Update dynamic neighbor cache
                                if let Ok(mut neighbors) = dynamic_neighbors.lock() {
                                    neighbors.insert(
                                        (meta.ingress_ifindex as i32, sender_ip),
                                        NeighborEntry { mac: sender_mac },
                                    );
                                }
                                // Add learned ARP entry to kernel neighbor table
                                // via netlink. This keeps the kernel's ARP table
                                // in sync (needed for XDP_PASS fallback and
                                // kernel-originated traffic).
                                let neigh_ifindex = resolve_ingress_logical_ifindex(
                                    forwarding,
                                    meta.ingress_ifindex as i32,
                                    meta.ingress_vlan_id,
                                )
                                .unwrap_or(meta.ingress_ifindex as i32);
                                add_kernel_neighbor(neigh_ifindex, sender_ip, sender_mac);
                            }
                            // Recycle frame — ARP is not a transit packet
                            binding.scratch_recycle.push(desc.addr);
                            continue;
                        }
                    }
                    // Check for ICMPv6 Neighbor Advertisement (type 136).
                    // Parse the target address and target link-layer address option,
                    // then update the dynamic neighbor cache.
                    // Handles both untagged and VLAN-tagged (802.1Q) IPv6 frames.
                    if raw_frame.len() >= 78 {
                        let (l3_start, ethertype) = if raw_frame.len() >= 18
                            && u16::from_be_bytes([raw_frame[12], raw_frame[13]]) == 0x8100
                        {
                            (18, u16::from_be_bytes([raw_frame[16], raw_frame[17]]))
                        } else {
                            (14, u16::from_be_bytes([raw_frame[12], raw_frame[13]]))
                        };
                        if ethertype == 0x86dd && raw_frame.len() >= l3_start + 40 {
                            let next_header = raw_frame[l3_start + 6];
                            let l4_start = l3_start + 40;
                            // ICMPv6 NA: next_header=58, type=136, need at least 24 bytes of ICMPv6 body
                            if next_header == 58
                                && raw_frame.len() >= l4_start + 24
                                && raw_frame[l4_start] == 136
                            {
                                // Target address at ICMPv6 offset + 8 (after type/code/checksum/flags)
                                if let Ok(target_bytes) =
                                    <[u8; 16]>::try_from(&raw_frame[l4_start + 8..l4_start + 24])
                                {
                                    let target_ip = IpAddr::V6(Ipv6Addr::from(target_bytes));
                                    // Look for target link-layer address option (type 2)
                                    let mut opt_off = l4_start + 24;
                                    while opt_off + 2 <= raw_frame.len() {
                                        let opt_type = raw_frame[opt_off];
                                        let opt_len = raw_frame[opt_off + 1] as usize * 8;
                                        if opt_len == 0 {
                                            break;
                                        }
                                        if opt_type == 2
                                            && opt_len >= 8
                                            && opt_off + 8 <= raw_frame.len()
                                        {
                                            let mac = [
                                                raw_frame[opt_off + 2],
                                                raw_frame[opt_off + 3],
                                                raw_frame[opt_off + 4],
                                                raw_frame[opt_off + 5],
                                                raw_frame[opt_off + 6],
                                                raw_frame[opt_off + 7],
                                            ];
                                            if let Ok(mut neighbors) = dynamic_neighbors.lock() {
                                                neighbors.insert(
                                                    (meta.ingress_ifindex as i32, target_ip),
                                                    NeighborEntry { mac },
                                                );
                                            }
                                            // Add to kernel neighbor table via netlink.
                                            // Use the logical VLAN sub-interface ifindex
                                            // so the kernel associates it correctly.
                                            let neigh_ifindex = resolve_ingress_logical_ifindex(
                                                forwarding,
                                                meta.ingress_ifindex as i32,
                                                meta.ingress_vlan_id,
                                            )
                                            .unwrap_or(meta.ingress_ifindex as i32);
                                            add_kernel_neighbor(neigh_ifindex, target_ip, mac);
                                            break;
                                        }
                                        opt_off += opt_len;
                                    }
                                }
                                // Also let the NA fall through to normal processing.
                            }
                        }
                    }
                    let native_gre_packet =
                        try_native_gre_decap_from_frame(raw_frame, meta, forwarding);
                    let mut meta = native_gre_packet
                        .as_ref()
                        .map(|packet| packet.meta)
                        .unwrap_or(meta);
                    let mut owned_packet_frame = native_gre_packet.map(|packet| packet.frame);
                    let packet_frame = owned_packet_frame.as_deref().unwrap_or(raw_frame);
                    let flow = parse_session_flow_from_bytes(packet_frame, meta);
                    if owned_packet_frame.is_none()
                        && let Some(flow) = flow.as_ref()
                    {
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
                    let ingress_zone_override = parse_zone_encoded_fabric_ingress_from_frame(
                        packet_frame,
                        meta,
                        forwarding,
                    );
                    // Flag fabric-ingress packets so rewrite functions skip TTL
                    // decrement. The sending peer already decremented TTL when
                    // it forwarded the packet across the fabric link.
                    if ingress_zone_override.is_some()
                        || ingress_is_fabric(forwarding, meta.ingress_ifindex as i32)
                    {
                        meta.meta_flags |= 0x80; // FABRIC_INGRESS_FLAG
                    }
                    // Screen/IDS check — runs BEFORE session lookup.
                    // Resolve ingress zone name for screen profile lookup.
                    if screen.has_profiles() {
                        if let Some(flow) = flow.as_ref() {
                            let zone_name = ingress_zone_override.as_deref().or_else(|| {
                                forwarding
                                    .ifindex_to_zone
                                    .get(&(meta.ingress_ifindex as i32))
                                    .map(|s| s.as_str())
                            });
                            if let Some(zone_name) = zone_name {
                                let l3_off = if meta.ingress_vlan_id > 0 {
                                    18
                                } else {
                                    14 // default Ethernet header
                                };
                                let screen_pkt = extract_screen_info(
                                    packet_frame,
                                    meta.addr_family,
                                    meta.protocol,
                                    meta.tcp_flags,
                                    meta.pkt_len,
                                    flow.src_ip,
                                    flow.dst_ip,
                                    flow.forward_key.src_port,
                                    flow.forward_key.dst_port,
                                    l3_off,
                                );
                                if let ScreenVerdict::Drop(_reason) =
                                    screen.check_packet(zone_name, &screen_pkt, now_secs)
                                {
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
                                    tunnel_endpoint_id: 0,
                                    next_hop: None,
                                    neighbor_mac: None,
                                    src_mac: None,
                                    tx_vlan_id: 0,
                                },
                                nat: NatDecision::default(),
                            };
                            maybe_reinject_slow_path_from_frame(
                                &ident,
                                &binding.live,
                                slow_path,
                                local_tunnel_deliveries,
                                packet_frame,
                                meta,
                                ipsec_decision,
                                recent_exceptions,
                                "slow_path",
                            );
                            binding.scratch_recycle.push(desc.addr);
                            continue;
                        }
                    }
                    // ── Flow cache fast path ────────────────────────────
                    // For established TCP (ACK-only) and UDP, check the per-
                    // binding flow cache before the expensive session lookup
                    // + policy + NAT + FIB path. TCP SYN/FIN/RST skip the
                    // cache to ensure proper session lifecycle handling.
                    if FlowCacheEntry::packet_eligible(meta)
                        && let Some(flow) = flow.as_ref()
                    {
                        if let Some(cached) = binding.flow_cache.lookup(
                            &flow.forward_key,
                            FlowCacheLookup::for_packet(meta, validation),
                            &rg_epochs,
                        ) {
                            if !cached_flow_decision_valid(
                                forwarding,
                                ha_state,
                                now_secs,
                                cached.decision.resolution,
                            ) {
                                binding.flow_cache.invalidate_slot(
                                    &flow.forward_key,
                                    meta.ingress_ifindex as i32,
                                );
                                // Do NOT recycle/drop — fall through to the
                                // slow path so the packet gets full session
                                // lookup → HA resolution → fabric redirect.
                                // Before this fix, packets were silently
                                // dropped here, causing established flows to
                                // flatline after HA failover.
                            } else {
                                let cached_decision = cached.decision;
                                let cached_descriptor = cached.descriptor;
                                let cached_metadata = cached.metadata.clone();
                                // Amortize session timestamp touch — every 64 cache hits.
                                binding.flow_cache_session_touch += 1;
                                if binding.flow_cache_session_touch & 63 == 0 {
                                    sessions.touch(&flow.forward_key, now_ns);
                                }
                                if matches!(
                                    cached_decision.resolution.disposition,
                                    ForwardingDisposition::ForwardCandidate
                                        | ForwardingDisposition::FabricRedirect
                                ) {
                                    counters.forward_candidate_packets += 1;
                                    if cached_decision.nat.rewrite_src.is_some() {
                                        counters.snat_packets += 1;
                                    }
                                    if cached_decision.nat.rewrite_dst.is_some() {
                                        counters.dnat_packets += 1;
                                    }
                                    // ── Inline in-place rewrite fast path ──
                                    // Skip PendingForwardRequest + enqueue_pending_forwards entirely.
                                    // Resolve target binding, rewrite frame in UMEM, push PreparedTxRequest.
                                    let target_ifindex =
                                        if cached_decision.resolution.tx_ifindex > 0 {
                                            cached_decision.resolution.tx_ifindex
                                        } else {
                                            resolve_tx_binding_ifindex(
                                                forwarding,
                                                cached_decision.resolution.egress_ifindex,
                                            )
                                        };
                                    let expected_ports =
                                        authoritative_forward_ports(packet_frame, meta, Some(flow));
                                    let target_bi = if cached_decision.resolution.disposition
                                        == ForwardingDisposition::FabricRedirect
                                    {
                                        binding_lookup.fabric_target_index(
                                            target_ifindex,
                                            fabric_queue_hash(Some(flow), expected_ports, meta),
                                        )
                                    } else {
                                        binding_lookup.target_index(
                                            binding_index,
                                            ident.ifindex,
                                            ident.queue_id,
                                            target_ifindex,
                                        )
                                    };
                                    // Check if target is same binding (hairpin) or same-UMEM.
                                    // For simplicity, only do in-place fast path when target == self.
                                    let is_self_target = target_bi == Some(binding_index);
                                    if is_self_target && owned_packet_frame.is_none() {
                                        let ingress_slot = binding.slot;
                                        let flow_key = flow.forward_key.clone();
                                        // Try descriptor-based straight-line rewrite first (no branches
                                        // for AF, NAT type, or checksum recomputation).  Falls back to
                                        // generic rewrite on port mismatch, NAT64, or NPTv6.
                                        let frame_len = apply_rewrite_descriptor(
                                            unsafe { &*area },
                                            desc,
                                            meta,
                                            &cached_descriptor,
                                            expected_ports,
                                        )
                                        .or_else(|| {
                                            rewrite_forwarded_frame_in_place(
                                                unsafe { &*area },
                                                desc,
                                                meta,
                                                &cached_decision,
                                                expected_ports,
                                            )
                                        });
                                        if let Some(frame_len) = frame_len {
                                            binding.pending_tx_prepared.push_back(
                                                PreparedTxRequest {
                                                    offset: desc.addr,
                                                    len: frame_len,
                                                    recycle: PreparedTxRecycle::FillOnSlot(
                                                        ingress_slot,
                                                    ),
                                                    expected_ports,
                                                    expected_addr_family: meta.addr_family,
                                                    expected_protocol: meta.protocol,
                                                    flow_key: Some(flow_key),
                                                },
                                            );
                                            binding.pending_in_place_tx_packets += 1;
                                            dbg.forward += 1;
                                            dbg.tx += 1;
                                            recycle_now = false;
                                        }
                                    }
                                    // Fallback: use PendingForwardRequest path for cross-binding or failure.
                                    if recycle_now {
                                        if let Some(mut request) =
                                            build_live_forward_request_from_frame(
                                                binding_lookup,
                                                binding_index,
                                                ident,
                                                desc,
                                                packet_frame,
                                                meta,
                                                &cached_decision,
                                                forwarding,
                                                Some(flow),
                                                Some(&cached_metadata.ingress_zone),
                                                true,
                                            )
                                        {
                                            request.source_frame = owned_packet_frame.take();
                                            dbg.forward += 1;
                                            dbg.tx += 1;
                                            binding.scratch_forwards.push(request);
                                            recycle_now = false;
                                        }
                                    }
                                }
                                if recycle_now {
                                    binding.scratch_recycle.push(desc.addr);
                                }
                                continue;
                            } // else: cached HA-valid — fast path above
                        }
                    }
                    // ── End flow cache fast path ─────────────────────────
                    let mut debug = flow
                        .as_ref()
                        .map(|flow| ResolutionDebug::from_flow(meta.ingress_ifindex as i32, flow));
                    let mut session_ingress_zone: Option<Arc<str>> = None;
                    let mut apply_nat_on_fabric = false;
                    let decision = if let Some(flow) = flow.as_ref() {
                        if let Some(resolved) = resolve_flow_session_decision(
                            sessions,
                            binding.session_map_fd,
                            shared_sessions,
                            shared_nat_sessions,
                            shared_forward_wire_sessions,
                            peer_worker_commands,
                            forwarding,
                            ha_state,
                            dynamic_neighbors,
                            flow,
                            now_ns,
                            now_secs,
                            meta.protocol,
                            meta.tcp_flags,
                            meta.ingress_ifindex as i32,
                            ha_startup_grace_until_secs,
                        ) {
                            counters.session_hits += 1;
                            dbg.session_hit += 1;
                            if resolved.created {
                                counters.session_creates += 1;
                                dbg.session_create += 1;
                                // Mirror new session to BPF conntrack map for
                                // `show security flow session` zone/interface display.
                                publish_bpf_conntrack_entry(
                                    conntrack_v4_fd,
                                    conntrack_v6_fd,
                                    &flow.forward_key,
                                    resolved.decision,
                                    &resolved.metadata,
                                    &forwarding.zone_name_to_id,
                                );
                            }
                            // Log first N session hits from WAN (return path)
                            if cfg!(feature = "debug-log")
                                && meta.ingress_ifindex == 6
                                && dbg.wan_return_hits < 5
                            {
                                dbg.wan_return_hits += 1;
                                debug_log!(
                                    "DBG WAN_RETURN_HIT[{}]: {}:{} -> {}:{} proto={} tcp_flags=0x{:02x} nat=({:?},{:?}) rev={}",
                                    dbg.wan_return_hits,
                                    flow.src_ip,
                                    flow.forward_key.src_port,
                                    flow.dst_ip,
                                    flow.forward_key.dst_port,
                                    meta.protocol,
                                    meta.tcp_flags,
                                    resolved.decision.nat.rewrite_src,
                                    resolved.decision.nat.rewrite_dst,
                                    resolved.metadata.is_reverse,
                                );
                            }
                            if let Some(debug) = debug.as_mut() {
                                debug.from_zone = Some(resolved.metadata.ingress_zone.clone());
                                debug.to_zone = Some(resolved.metadata.egress_zone.clone());
                            }
                            session_ingress_zone = Some(resolved.metadata.ingress_zone.clone());
                            apply_nat_on_fabric = true;
                            resolved.decision
                        } else {
                            counters.session_misses += 1;
                            dbg.session_miss += 1;
                            let resolution_target =
                                parse_packet_destination_from_frame(packet_frame, meta)
                                    .unwrap_or(flow.dst_ip);
                            // Cluster peer return fast path:
                            // a packet arriving from zone-encoded fabric ingress has already
                            // been policy/NAT-validated by the active owner. Allow the inactive
                            // peer to hand it to the resolved local egress zone instead of
                            // treating it as a brand-new flow. Keep pure TCP SYN excluded so
                            // brand-new connects still require local session ownership.
                            if let Some((fabric_return_decision, fabric_return_metadata)) =
                                cluster_peer_return_fast_path(
                                    forwarding,
                                    dynamic_neighbors,
                                    packet_frame,
                                    meta,
                                    ingress_zone_override.as_deref(),
                                    resolution_target,
                                )
                            {
                                let ingress_ident = BindingIdentity {
                                    slot: binding.slot,
                                    queue_id: binding.queue_id,
                                    worker_id: binding.worker_id,
                                    interface: binding.interface.clone(),
                                    ifindex: binding.ifindex,
                                };
                                if let Some(mut request) = build_live_forward_request_from_frame(
                                    binding_lookup,
                                    binding_index,
                                    &ingress_ident,
                                    desc,
                                    packet_frame,
                                    meta,
                                    &fabric_return_decision,
                                    forwarding,
                                    Some(flow),
                                    None,
                                    false,
                                ) {
                                    request.source_frame = owned_packet_frame.take();
                                    if sessions.install_with_protocol_with_origin(
                                        flow.forward_key.clone(),
                                        fabric_return_decision,
                                        fabric_return_metadata,
                                        SessionOrigin::ReverseFlow,
                                        now_ns,
                                        meta.protocol,
                                        meta.tcp_flags,
                                    ) {
                                        let _ = publish_live_session_entry(
                                            binding.session_map_fd,
                                            &flow.forward_key,
                                            NatDecision::default(),
                                            true,
                                        );
                                    }
                                    binding.scratch_forwards.push(request);
                                    continue;
                                }
                            }

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
                                forwarding
                                    .static_nat
                                    .match_dnat(resolution_target, ingress_zone_name)
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
                            let nat64_match =
                                if pre_routing_dnat.is_none() && nptv6_inbound.is_none() {
                                    if let IpAddr::V6(dst_v6) = resolution_target {
                                        forwarding.nat64.match_ipv6_dest(dst_v6).and_then(
                                            |(idx, dst_v4)| {
                                                let snat_v4 =
                                                    forwarding.nat64.allocate_v4_source(idx)?;
                                                Some((idx, dst_v4, snat_v4, dst_v6))
                                            },
                                        )
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                };

                            let effective_resolution_target =
                                if let Some((_, dst_v4, _, _)) = &nat64_match {
                                    IpAddr::V4(*dst_v4)
                                } else if let Some(internal_dst) = nptv6_inbound {
                                    IpAddr::V6(internal_dst)
                                } else {
                                    match &pre_routing_dnat {
                                        Some(d) => d.rewrite_dst.unwrap_or(resolution_target),
                                        None => resolution_target,
                                    }
                                };
                            let route_table_override =
                                ingress_route_table_override(forwarding, meta, flow);

                            let resolution = if should_block_tunnel_interface_nat_session_miss(
                                forwarding,
                                effective_resolution_target,
                                meta.protocol,
                            ) {
                                no_route_resolution(Some(effective_resolution_target))
                            } else {
                                ingress_interface_local_resolution_on_session_miss(
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
                                        lookup_forwarding_resolution_in_table_with_dynamic(
                                            forwarding,
                                            dynamic_neighbors,
                                            effective_resolution_target,
                                            route_table_override.as_deref(),
                                        ),
                                    )
                                })
                            };
                            let fabric_ingress =
                                ingress_is_fabric(forwarding, meta.ingress_ifindex as i32);
                            let resolution = prefer_local_forward_candidate_for_fabric_ingress(
                                forwarding,
                                ha_state,
                                dynamic_neighbors,
                                now_secs,
                                fabric_ingress,
                                effective_resolution_target,
                                resolution,
                            );
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
                                        flow.src_ip,
                                        flow.forward_key.src_port,
                                        flow.dst_ip,
                                        flow.forward_key.dst_port,
                                        meta.protocol,
                                        meta.tcp_flags,
                                        meta.ingress_ifindex,
                                        resolution.disposition,
                                        resolution.egress_ifindex,
                                        resolution.neighbor_mac.map(|m| format!(
                                            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                            m[0], m[1], m[2], m[3], m[4], m[5]
                                        )),
                                        from_zone,
                                        to_zone,
                                    );
                                    // If from WAN (if6), dump what session key was tried
                                    if meta.ingress_ifindex == 6 {
                                        eprintln!(
                                            "DBG SESS_MISS_KEY: af={} proto={} key={}:{}->{}:{} bpf_entries={} local_sessions={}",
                                            flow.forward_key.addr_family,
                                            flow.forward_key.protocol,
                                            flow.forward_key.src_ip,
                                            flow.forward_key.src_port,
                                            flow.forward_key.dst_ip,
                                            flow.forward_key.dst_port,
                                            count_bpf_session_entries(binding.session_map_fd),
                                            sessions.len(),
                                        );
                                        // Dump all local sessions to compare
                                        if dbg.session_miss <= 3 {
                                            let mut sess_dump = String::new();
                                            let mut count = 0;
                                            sessions.iter_with_origin(|key, decision, metadata, origin| {
                                                if count < 30 {
                                                    use std::fmt::Write;
                                                    let _ = write!(sess_dump,
                                                        "\n  LOCAL_SESS: af={} proto={} {}:{}->{}:{} nat=({:?},{:?}) rev={} synced={} origin={}",
                                                        key.addr_family, key.protocol,
                                                        key.src_ip, key.src_port, key.dst_ip, key.dst_port,
                                                        decision.nat.rewrite_src, decision.nat.rewrite_dst,
                                                        metadata.is_reverse, origin.is_peer_synced(), origin.as_str(),
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
                            // Compute embedded ICMP error flag early so we can skip
                            // the BPF session map publish for ICMP errors. Publishing
                            // them as PASS_TO_KERNEL causes subsequent ICMP errors to
                            // bypass the userspace embedded ICMP NAT reversal.
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
                            if resolution.disposition == ForwardingDisposition::LocalDelivery
                                && !is_embedded_icmp_error
                                && should_cache_local_delivery_session_on_miss(
                                    forwarding,
                                    effective_resolution_target,
                                    resolution,
                                    meta.protocol,
                                    meta.tcp_flags,
                                )
                            {
                                let local_metadata = SessionMetadata {
                                    ingress_zone: from_zone_arc.clone(),
                                    egress_zone: to_zone_arc.clone(),
                                    owner_rg_id: 0,
                                    fabric_ingress: false,
                                    is_reverse: false,
                                    // Keep firewall-local sessions in the helper only for HA
                                    // state. Publish only the exact observed key back into the
                                    // BPF session map so subsequent established packets bypass
                                    // userspace and return directly to the kernel.
                                    nat64_reverse: None,
                                };
                                if install_helper_local_session_on_miss(
                                    sessions,
                                    binding.session_map_fd,
                                    shared_sessions,
                                    shared_nat_sessions,
                                    shared_forward_wire_sessions,
                                    &flow.forward_key,
                                    decision,
                                    local_metadata.clone(),
                                    SessionOrigin::LocalMiss,
                                    now_ns,
                                    meta.protocol,
                                    meta.tcp_flags,
                                ) {
                                    counters.session_creates += 1;
                                    dbg.session_create += 1;
                                    publish_bpf_conntrack_entry(
                                        conntrack_v4_fd,
                                        conntrack_v6_fd,
                                        &flow.forward_key,
                                        decision,
                                        &local_metadata,
                                        &forwarding.zone_name_to_id,
                                    );
                                }
                            }
                            if is_embedded_icmp_error {
                                #[cfg(feature = "debug-log")]
                                let icmpv6_trace = meta.protocol == PROTO_ICMPV6
                                    && ICMPV6_EMBED_LOGGED.fetch_add(1, Ordering::Relaxed) < 32;
                                if let Some(icmp_match) = try_embedded_icmp_nat_match(
                                    unsafe { &*area },
                                    desc,
                                    meta,
                                    sessions,
                                    forwarding,
                                    dynamic_neighbors,
                                    shared_sessions,
                                    shared_nat_sessions,
                                    shared_forward_wire_sessions,
                                    now_ns,
                                ) {
                                    #[cfg(feature = "debug-log")]
                                    if icmpv6_trace {
                                        debug_log!(
                                            "ICMPV6_EMBED: match orig_src={} orig_port={} nat={:?} resolution={:?} egress_if={} tx_if={} neigh={:?}",
                                            icmp_match.original_src,
                                            icmp_match.original_src_port,
                                            icmp_match.nat,
                                            icmp_match.resolution.disposition,
                                            icmp_match.resolution.egress_ifindex,
                                            icmp_match.resolution.tx_ifindex,
                                            icmp_match.resolution.neighbor_mac,
                                        );
                                    }
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
                                                libc::AF_INET => build_nat_reversed_icmp_error_v4(
                                                    frame,
                                                    meta,
                                                    &icmp_match,
                                                ),
                                                libc::AF_INET6 => build_nat_reversed_icmp_error_v6(
                                                    frame,
                                                    meta,
                                                    &icmp_match,
                                                ),
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
                                            binding.scratch_forwards.push(PendingForwardRequest {
                                                target_ifindex,
                                                target_binding_index: binding_lookup.target_index(
                                                    binding_index,
                                                    ident.ifindex,
                                                    ident.queue_id,
                                                    target_ifindex,
                                                ),
                                                ingress_queue_id: ident.queue_id,
                                                source_offset: desc.addr,
                                                desc,
                                                source_frame: None,
                                                meta,
                                                decision: icmp_decision,
                                                apply_nat_on_fabric: false,
                                                expected_ports: None,
                                                flow_key: None,
                                                nat64_reverse: None,
                                                prebuilt_frame: Some(rewritten_frame),
                                            });
                                            recycle_now = false;
                                            #[cfg(feature = "debug-log")]
                                            if icmpv6_trace {
                                                debug_log!(
                                                    "ICMPV6_EMBED: queued resolution={:?} egress_if={} tx_if={} target_if={}",
                                                    icmp_decision.resolution.disposition,
                                                    icmp_decision.resolution.egress_ifindex,
                                                    icmp_decision.resolution.tx_ifindex,
                                                    target_ifindex,
                                                );
                                            }
                                        } else {
                                            #[cfg(feature = "debug-log")]
                                            if icmpv6_trace {
                                                debug_log!(
                                                    "ICMPV6_EMBED: build_none resolution={:?} egress_if={} tx_if={} neigh={:?}",
                                                    icmp_resolution.disposition,
                                                    icmp_resolution.egress_ifindex,
                                                    icmp_resolution.tx_ifindex,
                                                    icmp_resolution.neighbor_mac,
                                                );
                                            }
                                        }
                                    } else {
                                        #[cfg(feature = "debug-log")]
                                        if icmpv6_trace {
                                            debug_log!(
                                                "ICMPV6_EMBED: no_rewrite nat={:?}",
                                                icmp_match.nat
                                            );
                                        }
                                    }
                                } else {
                                    #[cfg(feature = "debug-log")]
                                    if icmpv6_trace {
                                        debug_log!(
                                            "ICMPV6_EMBED: no_match outer={}:{} -> {}:{} ingress_if={} from_zone={} to_zone={}",
                                            flow.src_ip,
                                            flow.forward_key.src_port,
                                            flow.dst_ip,
                                            flow.forward_key.dst_port,
                                            meta.ingress_ifindex,
                                            from_zone,
                                            to_zone,
                                        );
                                    }
                                }
                                // Permit without policy check or session install.
                                // If NAT reversal was applied, the prebuilt frame
                                // is already queued. If not, fall through to slow-path.
                            } else if resolution.disposition
                                == ForwardingDisposition::ForwardCandidate
                            {
                                let owner_rg_id = owner_rg_for_resolution(forwarding, resolution);
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
                                    let nat64_info = if let Some((
                                        _,
                                        dst_v4,
                                        snat_v4,
                                        orig_dst_v6,
                                    )) = nat64_match
                                    {
                                        decision.nat =
                                            Nat64State::forward_decision(snat_v4, dst_v4);
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
                                            let nptv6_snat = if let IpAddr::V6(mut src_v6) =
                                                flow.src_ip
                                            {
                                                if forwarding.nptv6.translate_outbound(&mut src_v6)
                                                {
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
                                                .or_else(|| {
                                                    forwarding
                                                        .static_nat
                                                        .match_snat(flow.src_ip, &from_zone)
                                                })
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
                                        let track_in_userspace = decision.resolution.disposition
                                            != ForwardingDisposition::LocalDelivery;
                                        let forward_metadata = SessionMetadata {
                                            ingress_zone: from_zone_arc.clone(),
                                            egress_zone: to_zone_arc.clone(),
                                            owner_rg_id,
                                            fabric_ingress,
                                            is_reverse: false,
                                            nat64_reverse: nat64_info,
                                        };
                                        if track_in_userspace
                                            && sessions.install_with_protocol_with_origin(
                                                flow.forward_key.clone(),
                                                decision,
                                                forward_metadata.clone(),
                                                SessionOrigin::ForwardFlow,
                                                now_ns,
                                                meta.protocol,
                                                meta.tcp_flags,
                                            )
                                        {
                                            created += 1;
                                            let forward_entry = SyncedSessionEntry {
                                                key: flow.forward_key.clone(),
                                                decision,
                                                metadata: forward_metadata,
                                                origin: SessionOrigin::ForwardFlow,
                                                protocol: meta.protocol,
                                                tcp_flags: meta.tcp_flags,
                                            };
                                            let _ = publish_live_session_entry(
                                                binding.session_map_fd,
                                                &flow.forward_key,
                                                decision.nat,
                                                false,
                                            );
                                            publish_shared_session(
                                                shared_sessions,
                                                shared_nat_sessions,
                                                shared_forward_wire_sessions,
                                                &forward_entry,
                                            );
                                            // Populate BPF dnat_table for embedded ICMP NAT reversal.
                                            // Without this, mtr/traceroute intermediate hops are invisible.
                                            publish_dnat_table_entry(
                                                &dnat_fds,
                                                &flow.forward_key,
                                                decision.nat,
                                            );
                                            replicate_session_upsert(
                                                peer_worker_commands,
                                                &forward_entry,
                                            );
                                        }
                                        let reverse_resolution = reverse_resolution_for_session(
                                            forwarding,
                                            ha_state,
                                            dynamic_neighbors,
                                            flow.src_ip,
                                            from_zone_arc.as_ref(),
                                            fabric_ingress,
                                            now_secs,
                                            false,
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
                                        let (reverse_key, reverse_protocol) = if nat64_info
                                            .is_some()
                                        {
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
                                            let (src_port, dst_port) = if matches!(
                                                meta.protocol,
                                                PROTO_ICMP | PROTO_ICMPV6
                                            ) {
                                                (
                                                    flow.forward_key.src_port,
                                                    flow.forward_key.dst_port,
                                                )
                                            } else {
                                                (
                                                    flow.forward_key.dst_port,
                                                    flow.forward_key.src_port,
                                                )
                                            };
                                            (
                                                SessionKey {
                                                    addr_family: libc::AF_INET as u8,
                                                    protocol: rev_proto,
                                                    src_ip: IpAddr::V4(dst_v4),
                                                    dst_ip: IpAddr::V4(snat_v4),
                                                    src_port,
                                                    dst_port,
                                                },
                                                rev_proto,
                                            )
                                        } else {
                                            (flow.reverse_key_with_nat(decision.nat), meta.protocol)
                                        };
                                        let _ = reverse_protocol; // used below for install
                                        let reverse_metadata = SessionMetadata {
                                            ingress_zone: to_zone_arc,
                                            egress_zone: from_zone_arc,
                                            owner_rg_id,
                                            fabric_ingress,
                                            is_reverse: true,
                                            nat64_reverse: nat64_info,
                                        };
                                        if track_in_userspace
                                            && sessions.install_with_protocol_with_origin(
                                                reverse_key.clone(),
                                                reverse_decision,
                                                reverse_metadata.clone(),
                                                SessionOrigin::ReverseFlow,
                                                now_ns,
                                                meta.protocol,
                                                meta.tcp_flags,
                                            )
                                        {
                                            let _ = publish_live_session_key(
                                                binding.session_map_fd,
                                                &reverse_key,
                                            );
                                            // Verify session keys and log creations (debug-only: BPF syscalls)
                                            if cfg!(feature = "debug-log") {
                                                if verify_session_key_in_bpf(
                                                    binding.session_map_fd,
                                                    &reverse_key,
                                                ) {
                                                    SESSION_PUBLISH_VERIFY_OK
                                                        .fetch_add(1, Ordering::Relaxed);
                                                } else {
                                                    SESSION_PUBLISH_VERIFY_FAIL
                                                        .fetch_add(1, Ordering::Relaxed);
                                                    debug_log!(
                                                        "SESS_VERIFY_FAIL: reverse key NOT found after publish! \
                                                             af={} proto={} {}:{} -> {}:{} (map_fd={})",
                                                        reverse_key.addr_family,
                                                        reverse_key.protocol,
                                                        reverse_key.src_ip,
                                                        reverse_key.src_port,
                                                        reverse_key.dst_ip,
                                                        reverse_key.dst_port,
                                                        binding.session_map_fd,
                                                    );
                                                }
                                                if !verify_session_key_in_bpf(
                                                    binding.session_map_fd,
                                                    &flow.forward_key,
                                                ) {
                                                    debug_log!(
                                                        "SESS_VERIFY_FAIL: forward key NOT found! \
                                                             af={} proto={} {}:{} -> {}:{}",
                                                        flow.forward_key.addr_family,
                                                        flow.forward_key.protocol,
                                                        flow.forward_key.src_ip,
                                                        flow.forward_key.src_port,
                                                        flow.forward_key.dst_ip,
                                                        flow.forward_key.dst_port,
                                                    );
                                                }
                                                let logged = SESSION_CREATIONS_LOGGED
                                                    .fetch_add(1, Ordering::Relaxed);
                                                if logged < 10 {
                                                    debug_log!(
                                                        "SESS_CREATE[{}]: FWD af={} proto={} {}:{} -> {}:{} \
                                                             | REV af={} proto={} {}:{} -> {}:{} \
                                                             | NAT src={:?} dst={:?} \
                                                             | map_fd={} bpf_entries={}",
                                                        logged,
                                                        flow.forward_key.addr_family,
                                                        flow.forward_key.protocol,
                                                        flow.forward_key.src_ip,
                                                        flow.forward_key.src_port,
                                                        flow.forward_key.dst_ip,
                                                        flow.forward_key.dst_port,
                                                        reverse_key.addr_family,
                                                        reverse_key.protocol,
                                                        reverse_key.src_ip,
                                                        reverse_key.src_port,
                                                        reverse_key.dst_ip,
                                                        reverse_key.dst_port,
                                                        decision.nat.rewrite_src,
                                                        decision.nat.rewrite_dst,
                                                        binding.session_map_fd,
                                                        count_bpf_session_entries(
                                                            binding.session_map_fd
                                                        ),
                                                    );
                                                    dump_bpf_session_entries(
                                                        binding.session_map_fd,
                                                        20,
                                                    );
                                                }
                                            }
                                            created += 1;
                                            let reverse_entry = SyncedSessionEntry {
                                                key: reverse_key,
                                                decision: reverse_decision,
                                                metadata: reverse_metadata,
                                                origin: SessionOrigin::ReverseFlow,
                                                protocol: meta.protocol,
                                                tcp_flags: meta.tcp_flags,
                                            };
                                            publish_shared_session(
                                                shared_sessions,
                                                shared_nat_sessions,
                                                shared_forward_wire_sessions,
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
                                    if cfg!(feature = "debug-log")
                                        && (dbg.policy_deny <= 3 || is_trust_flow)
                                    {
                                        debug_log!(
                                            "DBG POLICY_DENY[{}]: {}:{} -> {}:{} proto={} zone={}->{}  ingress_if={} egress_if={}",
                                            dbg.policy_deny,
                                            flow.src_ip,
                                            flow.forward_key.src_port,
                                            flow.dst_ip,
                                            flow.forward_key.dst_port,
                                            meta.protocol,
                                            from_zone,
                                            to_zone,
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
                                // New flow to inactive RG: fabric-redirect to the peer
                                // that owns the egress RG.  Use from_zone_arc directly
                                // (always in scope) rather than going through the debug
                                // struct which may not have been populated.
                                if let Some(redirect) = resolve_zone_encoded_fabric_redirect(
                                    forwarding,
                                    from_zone_arc.as_ref(),
                                )
                                .or_else(|| resolve_fabric_redirect(forwarding))
                                {
                                    decision.resolution = redirect;
                                }
                            }
                            decision
                        }
                    } else {
                        let non_flow_resolution = enforce_ha_resolution_snapshot(
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
                        );
                        // For non-flow packets (no L4 ports), also attempt fabric
                        // redirect when the egress RG is inactive.
                        let final_resolution = if non_flow_resolution.disposition
                            == ForwardingDisposition::HAInactive
                            && !ingress_is_fabric(forwarding, meta.ingress_ifindex as i32)
                        {
                            resolve_fabric_redirect(forwarding).unwrap_or(non_flow_resolution)
                        } else {
                            non_flow_resolution
                        };
                        SessionDecision {
                            resolution: final_resolution,
                            nat: NatDecision::default(),
                        }
                    };
                    // NOTE: HAInactive fabric redirect is handled by the eBPF pipeline
                    // via rg_active checks + try_fabric_redirect(). The ctrl-disable
                    // on demotion ensures the eBPF pipeline handles the transition.
                    // Do NOT convert HAInactive→FabricRedirect here — it causes
                    // false redirects during startup when HA watchdog hasn't started.
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
                        if decision.nat.rewrite_src.is_some() && decision.nat.rewrite_dst.is_some()
                        {
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
                                let flow_str = flow
                                    .as_ref()
                                    .map(|f| {
                                        format!(
                                            "{}:{} -> {}:{}",
                                            f.src_ip,
                                            f.forward_key.src_port,
                                            f.dst_ip,
                                            f.forward_key.dst_port
                                        )
                                    })
                                    .unwrap_or_else(|| "no-flow".into());
                                let nat_str = format!(
                                    "snat={:?} dnat={:?}",
                                    decision.nat.rewrite_src, decision.nat.rewrite_dst,
                                );
                                eprintln!(
                                    "DBG FWD_DECISION[{}]: ingress_if={} egress_if={} {} {} proto={}",
                                    dbg.forward,
                                    ingress_if,
                                    egress_if,
                                    flow_str,
                                    nat_str,
                                    meta.protocol,
                                );
                            }
                        }
                        // TCP flag tracking on forwarded frames
                        if cfg!(feature = "debug-log") {
                            if meta.protocol == 6 {
                                // Compare meta.tcp_flags from BPF shim with raw frame TCP flags
                                let frame_data =
                                    unsafe { &*area }.slice(desc.addr as usize, desc.len as usize);
                                let raw_tcp_info =
                                    frame_data.and_then(|data| extract_tcp_flags_and_window(data));
                                let raw_flags = raw_tcp_info.map(|(f, _)| f);
                                let raw_window = raw_tcp_info.map(|(_, w)| w);
                                // Log first 20 forwarded TCP packets: compare meta vs raw
                                if dbg.forward <= 20 {
                                    let flow_str = flow
                                        .as_ref()
                                        .map(|f| {
                                            format!(
                                                "{}:{} -> {}:{}",
                                                f.src_ip,
                                                f.forward_key.src_port,
                                                f.dst_ip,
                                                f.forward_key.dst_port
                                            )
                                        })
                                        .unwrap_or_else(|| "no-flow".into());
                                    eprintln!(
                                        "FWD_TCP_CMP[{}]: meta_flags=0x{:02x} raw_flags={} raw_win={} len={} l4_off={} {}",
                                        dbg.forward,
                                        meta.tcp_flags,
                                        raw_flags
                                            .map(|f| format!("0x{:02x}", f))
                                            .unwrap_or_else(|| "NONE".into()),
                                        raw_window
                                            .map(|w| format!("{}", w))
                                            .unwrap_or_else(|| "NONE".into()),
                                        desc.len,
                                        meta.l4_offset,
                                        flow_str,
                                    );
                                    // Hex dump bytes around TCP flags position in raw frame
                                    if let Some(data) = frame_data {
                                        let l4 = meta.l4_offset as usize;
                                        if data.len() > l4 + 20 {
                                            let tcp_hdr: String = data[l4..l4 + 20]
                                                .iter()
                                                .map(|b| format!("{:02x}", b))
                                                .collect::<Vec<_>>()
                                                .join(" ");
                                            eprintln!(
                                                "FWD_TCP_HDR[{}]: offset={} {}",
                                                dbg.forward, l4, tcp_hdr
                                            );
                                        }
                                    }
                                }
                                if (meta.tcp_flags & 0x04) != 0 {
                                    // RST
                                    dbg.fwd_tcp_rst += 1;
                                    if dbg.fwd_tcp_rst <= 5 {
                                        let flow_str = flow
                                            .as_ref()
                                            .map(|f| {
                                                format!(
                                                    "{}:{} -> {}:{}",
                                                    f.src_ip,
                                                    f.forward_key.src_port,
                                                    f.dst_ip,
                                                    f.forward_key.dst_port
                                                )
                                            })
                                            .unwrap_or_else(|| "no-flow".into());
                                        eprintln!(
                                            "FWD_TCP_RST_DETECT[{}]: meta_flags=0x{:02x} raw_flags={} raw_win={} len={} fwd#={} {}",
                                            dbg.fwd_tcp_rst,
                                            meta.tcp_flags,
                                            raw_flags
                                                .map(|f| format!("0x{:02x}", f))
                                                .unwrap_or_else(|| "NONE".into()),
                                            raw_window
                                                .map(|w| format!("{}", w))
                                                .unwrap_or_else(|| "NONE".into()),
                                            desc.len,
                                            dbg.forward,
                                            flow_str,
                                        );
                                        // Hex dump TCP header when RST detected
                                        if let Some(data) = frame_data {
                                            let l4 = meta.l4_offset as usize;
                                            if data.len() > l4 + 20 {
                                                let tcp_hdr: String = data[l4..l4 + 20]
                                                    .iter()
                                                    .map(|b| format!("{:02x}", b))
                                                    .collect::<Vec<_>>()
                                                    .join(" ");
                                                eprintln!(
                                                    "FWD_TCP_RST_HDR[{}]: meta_off={} raw_off={} {}",
                                                    dbg.fwd_tcp_rst,
                                                    l4,
                                                    frame_l3_offset(data).unwrap_or(0),
                                                    tcp_hdr
                                                );
                                            }
                                        }
                                    }
                                }
                                if (meta.tcp_flags & 0x01) != 0 {
                                    // FIN
                                    dbg.fwd_tcp_fin += 1;
                                    if dbg.fwd_tcp_fin <= 5 {
                                        let flow_str = flow
                                            .as_ref()
                                            .map(|f| {
                                                format!(
                                                    "{}:{} -> {}:{}",
                                                    f.src_ip,
                                                    f.forward_key.src_port,
                                                    f.dst_ip,
                                                    f.forward_key.dst_port
                                                )
                                            })
                                            .unwrap_or_else(|| "no-flow".into());
                                        eprintln!(
                                            "FWD_TCP_FIN[{}]: ingress_if={} {} tcp_flags=0x{:02x}",
                                            dbg.fwd_tcp_fin,
                                            meta.ingress_ifindex,
                                            flow_str,
                                            meta.tcp_flags,
                                        );
                                    }
                                }
                                // Detect zero-window in TCP frames by inspecting raw packet
                                if let Some(win) = raw_window {
                                    if win == 0 {
                                        dbg.fwd_tcp_zero_window += 1;
                                        if dbg.fwd_tcp_zero_window <= 10 {
                                            let flow_str = flow
                                                .as_ref()
                                                .map(|f| {
                                                    format!(
                                                        "{}:{} -> {}:{}",
                                                        f.src_ip,
                                                        f.forward_key.src_port,
                                                        f.dst_ip,
                                                        f.forward_key.dst_port
                                                    )
                                                })
                                                .unwrap_or_else(|| "no-flow".into());
                                            eprintln!(
                                                "FWD_TCP_ZERO_WIN[{}]: ingress_if={} {} meta_flags=0x{:02x} raw_flags={}",
                                                dbg.fwd_tcp_zero_window,
                                                meta.ingress_ifindex,
                                                flow_str,
                                                meta.tcp_flags,
                                                raw_flags
                                                    .map(|f| format!("0x{:02x}", f))
                                                    .unwrap_or_else(|| "NONE".into()),
                                            );
                                        }
                                    }
                                }
                            }
                        }
                        if should_teardown_tcp_rst(meta, flow.as_ref())
                            && let Some(flow) = flow.as_ref()
                        {
                            binding
                                .scratch_rst_teardowns
                                .push((flow.forward_key.clone(), decision.nat));
                        }
                        counters.forward_candidate_packets += 1;
                        if decision.nat.rewrite_src.is_some() {
                            counters.snat_packets += 1;
                        }
                        if decision.nat.rewrite_dst.is_some() {
                            counters.dnat_packets += 1;
                        }
                        if let Some(mut request) = build_live_forward_request_from_frame(
                            binding_lookup,
                            binding_index,
                            &ident,
                            desc,
                            packet_frame,
                            meta,
                            &decision,
                            forwarding,
                            flow.as_ref(),
                            session_ingress_zone.as_ref(),
                            apply_nat_on_fabric,
                        ) {
                            request.source_frame = owned_packet_frame.take();
                            dbg.tx += 1; // track forward requests queued
                            if cfg!(feature = "debug-log") {
                                if dbg.tx <= 5 {
                                    let dst_mac_str = decision
                                        .resolution
                                        .neighbor_mac
                                        .map(|m| {
                                            format!(
                                                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                                m[0], m[1], m[2], m[3], m[4], m[5]
                                            )
                                        })
                                        .unwrap_or_else(|| "NONE".into());
                                    let src_mac_str = decision
                                        .resolution
                                        .src_mac
                                        .map(|m| {
                                            format!(
                                                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                                m[0], m[1], m[2], m[3], m[4], m[5]
                                            )
                                        })
                                        .unwrap_or_else(|| "NONE".into());
                                    let flow_str = flow
                                        .as_ref()
                                        .map(|f| {
                                            format!(
                                                "{}:{} -> {}:{}",
                                                f.src_ip,
                                                f.forward_key.src_port,
                                                f.dst_ip,
                                                f.forward_key.dst_port
                                            )
                                        })
                                        .unwrap_or_else(|| "no-flow".into());
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
                            // ── Flow cache population ────────────────────
                            // Cache ForwardCandidate decisions for established
                            // TCP/UDP flows. Skip NAT64/NPTv6 (non-cacheable).
                            if let Some(flow) = flow.as_ref()
                                && let Some(entry) = FlowCacheEntry::from_forward_decision(
                                    flow,
                                    meta,
                                    validation,
                                    decision,
                                    session_ingress_zone.as_ref().cloned(),
                                    forwarding,
                                    apply_nat_on_fabric,
                                    &rg_epochs,
                                )
                            {
                                binding.flow_cache.insert(entry);
                            }
                            // ── End flow cache population ────────────────
                        } else {
                            dbg.build_fail += 1;
                            if cfg!(feature = "debug-log") {
                                if dbg.build_fail <= 3 {
                                    eprintln!(
                                        "DBG FWD_BUILD_NONE: egress_if={} tx_if={} neigh={:?} src_mac={:?} len={} proto={}",
                                        decision.resolution.egress_ifindex,
                                        decision.resolution.tx_ifindex,
                                        decision.resolution.neighbor_mac.map(|m| format!(
                                            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                            m[0], m[1], m[2], m[3], m[4], m[5]
                                        )),
                                        decision.resolution.src_mac.map(|m| format!(
                                            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                            m[0], m[1], m[2], m[3], m[4], m[5]
                                        )),
                                        desc.len,
                                        meta.protocol,
                                    );
                                }
                            }
                        }
                    } else {
                        // Debug: count non-forward dispositions
                        match decision.resolution.disposition {
                            ForwardingDisposition::LocalDelivery => {
                                dbg.local += 1;
                                // Reinject to slow-path TUN so the kernel
                                // processes host-bound traffic (NDP, ICMP echo,
                                // BGP, etc.).  The first packet creates a BPF
                                // session map entry so subsequent packets bypass
                                // userspace entirely.
                                maybe_reinject_slow_path(
                                    ident,
                                    &binding.live,
                                    slow_path.as_deref(),
                                    local_tunnel_deliveries,
                                    unsafe { &*area },
                                    desc,
                                    meta,
                                    decision,
                                    recent_exceptions,
                                );
                                recycle_now = true;
                            }
                            ForwardingDisposition::NoRoute => {
                                dbg.no_route += 1;
                                if cfg!(feature = "debug-log") {
                                    if dbg.no_route <= 3 {
                                        if let Some(flow) = flow.as_ref() {
                                            eprintln!(
                                                "DBG NO_ROUTE: {}:{} -> {}:{} proto={} ingress_if={}",
                                                flow.src_ip,
                                                flow.forward_key.src_port,
                                                flow.dst_ip,
                                                flow.forward_key.dst_port,
                                                meta.protocol,
                                                meta.ingress_ifindex,
                                            );
                                        }
                                    }
                                }
                            }
                            ForwardingDisposition::MissingNeighbor => {
                                dbg.missing_neigh += 1;
                                let (from_zone, to_zone) = zone_pair_for_flow_with_override(
                                    forwarding,
                                    meta.ingress_ifindex as i32,
                                    ingress_zone_override.as_deref(),
                                    decision.resolution.egress_ifindex,
                                );
                                let from_zone_arc = Arc::<str>::from(from_zone.as_str());
                                let to_zone_arc = Arc::<str>::from(to_zone.as_str());
                                // Send ARP/NDP solicitation via RAW socket (not XSK)
                                // so the reply goes through the kernel's normal RX
                                // path (cpumap_or_pass), bypassing XSK fill ring issues.
                                // Also reinject original packet to slow-path for kernel
                                // to forward once the neighbor is resolved.
                                // Trigger ARP/NDP resolution via kernel netlink.
                                // Adding an INCOMPLETE neighbor entry makes the
                                // kernel send its own ARP/NDP solicitation through
                                // the normal stack, which correctly handles VLAN
                                // tagging and TX offload. The netlink monitor then
                                // picks up the resolved entry instantly.
                                if let Some(next_hop) = decision.resolution.next_hop {
                                    // Only spawn ping if we don't already have a
                                    // pending probe for this (ifindex, hop).
                                    let already_probing = binding.pending_neigh.iter().any(|p| {
                                        p.decision.resolution.egress_ifindex
                                            == decision.resolution.egress_ifindex
                                            && p.decision.resolution.next_hop == Some(next_hop)
                                    });
                                    if !already_probing {
                                        let iface_name = forwarding
                                            .ifindex_to_name
                                            .get(&decision.resolution.egress_ifindex)
                                            .cloned();
                                        if let Some(name) = iface_name {
                                            // Fast path: ICMP socket triggers kernel ARP
                                            // in microseconds (no fork/exec).
                                            trigger_kernel_arp_probe(&name, next_hop);
                                        }
                                    }
                                }
                                // Create the session NOW so the SYN-ACK (reverse
                                // direction) finds the forward NAT match and creates
                                // a reverse session. Without this, the SYN-ACK hits
                                // session miss → policy deny (no rule for WAN→LAN).
                                let mut pending_decision = decision;
                                if let Some(flow) = flow.as_ref() {
                                    if let PolicyAction::Permit = evaluate_policy(
                                        &forwarding.policy,
                                        &from_zone,
                                        &to_zone,
                                        flow.src_ip,
                                        flow.dst_ip,
                                        flow.forward_key.protocol,
                                        flow.forward_key.src_port,
                                        flow.forward_key.dst_port,
                                    ) {
                                        if pending_decision.nat.rewrite_dst.is_none() {
                                            pending_decision.nat = forwarding
                                                .static_nat
                                                .match_snat(flow.src_ip, &from_zone)
                                                .or_else(|| {
                                                    match_source_nat_for_flow(
                                                        forwarding,
                                                        &from_zone,
                                                        &to_zone,
                                                        pending_decision.resolution.egress_ifindex,
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
                                                        pending_decision.resolution.egress_ifindex,
                                                        flow,
                                                    )
                                                })
                                                .unwrap_or_default();
                                            pending_decision.nat =
                                                pending_decision.nat.merge(snat_decision);
                                        }
                                    }
                                    let sess_meta = build_missing_neighbor_session_metadata(
                                        forwarding,
                                        &from_zone_arc,
                                        &to_zone_arc,
                                        meta.ingress_ifindex as i32,
                                        pending_decision,
                                    );
                                    if sessions.install_with_protocol_with_origin(
                                        flow.forward_key.clone(),
                                        pending_decision,
                                        sess_meta.clone(),
                                        SessionOrigin::MissingNeighborSeed,
                                        now_ns,
                                        meta.protocol,
                                        meta.tcp_flags,
                                    ) {
                                        let entry = SyncedSessionEntry {
                                            key: flow.forward_key.clone(),
                                            decision: pending_decision,
                                            metadata: sess_meta,
                                            origin: SessionOrigin::MissingNeighborSeed,
                                            protocol: meta.protocol,
                                            tcp_flags: meta.tcp_flags,
                                        };
                                        publish_shared_session(
                                            shared_sessions,
                                            shared_nat_sessions,
                                            shared_forward_wire_sessions,
                                            &entry,
                                        );
                                        let _ = publish_session_map_entry_for_session(
                                            binding.session_map_fd,
                                            &flow.forward_key,
                                            pending_decision,
                                            &entry.metadata,
                                        );
                                        publish_bpf_conntrack_entry(
                                            conntrack_v4_fd,
                                            conntrack_v6_fd,
                                            &flow.forward_key,
                                            pending_decision,
                                            &entry.metadata,
                                            &forwarding.zone_name_to_id,
                                        );
                                        publish_dnat_table_entry(
                                            &dnat_fds,
                                            &flow.forward_key,
                                            pending_decision.nat,
                                        );
                                        counters.session_creates += 1;
                                    }
                                }
                                // Buffer the packet. The ICMP probe resolves ARP
                                // in ~1ms. The retry loop below re-forwards the
                                // buffered packet once the neighbor resolves via the
                                // netlink monitor. The session was already created
                                // above so the SYN-ACK reverse path works too.
                                // Total latency: ~2ms (ARP + netlink + retry).
                                //
                                // NOTE: we do NOT reinject to slow-path here because
                                // kernel ARP resolution via XDP_PASS breaks VLAN demux
                                // in zero-copy mode (mlx5). The ICMP probe + netlink
                                // monitor + buffer-retry path bypasses this issue.
                                if binding.pending_neigh.len() < MAX_PENDING_NEIGH {
                                    binding.pending_neigh.push_back(PendingNeighPacket {
                                        addr: desc.addr,
                                        desc,
                                        meta,
                                        decision: pending_decision,
                                        queued_ns: now_ns,
                                    });
                                    recycle_now = false;
                                }
                                if cfg!(feature = "debug-log") {
                                    if dbg.missing_neigh <= 3 {
                                        if let Some(flow) = flow.as_ref() {
                                            eprintln!(
                                                "DBG MISS_NEIGH→{}: {}:{} -> {}:{} proto={} egress_if={} next_hop={:?}",
                                                "SOLICIT+SLOW",
                                                flow.src_ip,
                                                flow.forward_key.src_port,
                                                flow.dst_ip,
                                                flow.forward_key.dst_port,
                                                meta.protocol,
                                                pending_decision.resolution.egress_ifindex,
                                                pending_decision.resolution.next_hop,
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
                        maybe_reinject_slow_path_from_frame(
                            &ident,
                            &binding.live,
                            slow_path,
                            local_tunnel_deliveries,
                            packet_frame,
                            meta,
                            decision,
                            recent_exceptions,
                            "slow_path",
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
        let mut rst_teardowns = core::mem::take(&mut binding.scratch_rst_teardowns);
        for (forward_key, nat) in rst_teardowns.drain(..) {
            // Evict from flow cache so stale entries aren't used after RST.
            let idx = FlowCache::slot(&forward_key, binding.ifindex);
            binding.flow_cache.entries[idx] = None;
            teardown_tcp_rst_flow(
                left,
                binding,
                right,
                sessions,
                shared_sessions,
                shared_nat_sessions,
                shared_forward_wire_sessions,
                peer_worker_commands,
                &forward_key,
                nat,
                &mut pending_forwards,
            );
        }
        binding.scratch_rst_teardowns = rst_teardowns;
        // Use raw pointer to avoid Arc::clone (~5% CPU from lock incq).
        // Safety: the Arc<BindingLiveState> outlives this function call;
        // binding is borrowed mutably by enqueue_pending_forwards but
        // ingress_live is only used for read-only error logging inside it.
        let ingress_live: *const BindingLiveState = &*binding.live;
        let mut scratch_post_recycles = core::mem::take(&mut binding.scratch_post_recycles);
        enqueue_pending_forwards(
            left,
            binding_index,
            binding,
            right,
            binding_lookup,
            &mut pending_forwards,
            &mut scratch_post_recycles,
            now_ns,
            forwarding,
            &ident,
            unsafe { &*ingress_live },
            slow_path,
            local_tunnel_deliveries,
            recent_exceptions,
            dbg,
        );
        binding.scratch_post_recycles = scratch_post_recycles;
        binding.scratch_forwards = pending_forwards;
        // Reserved: cross-binding in-place TX from flow cache fast path.
        // Currently only self-target (hairpin) uses the inline path;
        // cross-binding goes through enqueue_pending_forwards above.
        // Eager TX completion reaping: free TX frames immediately after
        // enqueueing forwards so they can be recycled to fill ring within
        // the same poll cycle. Without this, completions wait until next
        // poll entry, starving the fill ring during sustained forwarding.
        reap_tx_completions(binding, shared_recycles);
        // Also reap completions on the egress bindings that just transmitted.
        for other in left.iter_mut().chain(right.iter_mut()) {
            reap_tx_completions(other, shared_recycles);
        }
        apply_shared_recycles(
            left,
            binding_index,
            binding,
            right,
            binding_lookup,
            shared_recycles,
        );
        if !binding.scratch_recycle.is_empty() {
            binding
                .pending_fill_frames
                .extend(binding.scratch_recycle.drain(..));
        }
        let _ = drain_pending_fill(binding, now_ns);
        counters.rx_batches += 1;
        did_work = true;
    }
    retry_pending_neigh(
        binding,
        left,
        binding_index,
        right,
        binding_lookup,
        forwarding,
        dynamic_neighbors,
        now_ns,
        unsafe { &*area },
    );
    counters.flush(&binding.live);
    update_binding_debug_state(binding);
    did_work
}

fn retry_pending_neigh(
    binding: &mut BindingWorker,
    left: &mut [BindingWorker],
    binding_index: usize,
    right: &mut [BindingWorker],
    binding_lookup: &WorkerBindingLookup,
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
    now_ns: u64,
    area: &MmapArea,
) {
    if binding.pending_neigh.is_empty() {
        return;
    }
    {
        let mut i = 0;
        while i < binding.pending_neigh.len() {
            let pkt = &binding.pending_neigh[i];
            // Timeout: recycle frame and drop
            if now_ns.saturating_sub(pkt.queued_ns) > PENDING_NEIGH_TIMEOUT_NS {
                let addr = pkt.addr;
                binding.pending_neigh.remove(i);
                binding.pending_fill_frames.push_back(addr);
                continue;
            }
            // Check if neighbor MAC is now available, mirroring the lookup
            // order from lookup_neighbor_entry(): static/permanent neighbors
            // first, then dynamic_neighbors.
            let mac = if let Some(hop) = pkt.decision.resolution.next_hop {
                let neigh_key = (pkt.decision.resolution.egress_ifindex, hop);
                forwarding
                    .neighbors
                    .get(&neigh_key)
                    .map(|e| e.mac)
                    .or_else(|| {
                        dynamic_neighbors
                            .lock()
                            .ok()
                            .and_then(|n| n.get(&neigh_key).map(|e| e.mac))
                    })
            } else {
                None
            };
            if let Some(neighbor_mac) = mac {
                let ingress_slot = binding.slot;
                let ingress_ifindex = binding.ifindex;
                let ingress_queue = binding.queue_id;
                let pkt = binding.pending_neigh.remove(i).unwrap();
                let mut decision = pkt.decision;
                decision.resolution.neighbor_mac = Some(neighbor_mac);
                decision.resolution.disposition = ForwardingDisposition::ForwardCandidate;
                let expected_ports = None;
                if let Some(frame_len) = rewrite_forwarded_frame_in_place(
                    &*area,
                    pkt.desc,
                    pkt.meta,
                    &decision,
                    expected_ports,
                ) {
                    let target_ifindex = if decision.resolution.tx_ifindex > 0 {
                        decision.resolution.tx_ifindex
                    } else {
                        resolve_tx_binding_ifindex(forwarding, decision.resolution.egress_ifindex)
                    };
                    if let Some(target_idx) = binding_lookup.target_index(
                        binding_index,
                        ingress_ifindex,
                        ingress_queue,
                        target_ifindex,
                    ) {
                        let req = PreparedTxRequest {
                            offset: pkt.desc.addr,
                            len: frame_len,
                            recycle: PreparedTxRecycle::FillOnSlot(ingress_slot),
                            expected_ports: None,
                            expected_addr_family: pkt.meta.addr_family,
                            expected_protocol: pkt.meta.protocol,
                            flow_key: None,
                        };
                        if target_idx == binding_index {
                            binding.pending_tx_prepared.push_back(req);
                        } else if let Some(target) =
                            binding_by_index_mut(left, binding_index, binding, right, target_idx)
                        {
                            target.pending_tx_prepared.push_back(req);
                            bound_pending_tx_prepared(target);
                        } else {
                            binding.pending_fill_frames.push_back(pkt.addr);
                        }
                    } else {
                        binding.pending_fill_frames.push_back(pkt.addr);
                    }
                } else {
                    binding.pending_fill_frames.push_back(pkt.addr);
                }
                continue;
            }
            i += 1;
        }
    }
}

fn build_live_forward_request(
    area: &MmapArea,
    binding_lookup: &WorkerBindingLookup,
    current_binding_index: usize,
    ingress_ident: &BindingIdentity,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    decision: &SessionDecision,
    forwarding: &ForwardingState,
    flow: Option<&SessionFlow>,
    fabric_ingress_zone: Option<&Arc<str>>,
    apply_nat_on_fabric: bool,
) -> Option<PendingForwardRequest> {
    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
    build_live_forward_request_from_frame(
        binding_lookup,
        current_binding_index,
        ingress_ident,
        desc,
        frame,
        meta,
        decision,
        forwarding,
        flow,
        fabric_ingress_zone,
        apply_nat_on_fabric,
    )
}

fn build_live_forward_request_from_frame(
    binding_lookup: &WorkerBindingLookup,
    current_binding_index: usize,
    ingress_ident: &BindingIdentity,
    desc: XdpDesc,
    frame: &[u8],
    meta: UserspaceDpMeta,
    decision: &SessionDecision,
    forwarding: &ForwardingState,
    flow: Option<&SessionFlow>,
    fabric_ingress_zone: Option<&Arc<str>>,
    apply_nat_on_fabric: bool,
) -> Option<PendingForwardRequest> {
    let target_ifindex = if decision.resolution.tx_ifindex > 0 {
        decision.resolution.tx_ifindex
    } else {
        resolve_tx_binding_ifindex(forwarding, decision.resolution.egress_ifindex)
    };
    // Prefer session flow ports (set by conntrack, immune to DMA races),
    // then live frame ports (lazy — only parsed if session ports unavailable),
    // then metadata as last resort.
    let expected_ports = authoritative_forward_ports(frame, meta, flow);
    let target_binding_index =
        if decision.resolution.disposition == ForwardingDisposition::FabricRedirect {
            binding_lookup.fabric_target_index(
                target_ifindex,
                fabric_queue_hash(flow, expected_ports, meta),
            )
        } else {
            binding_lookup.target_index(
                current_binding_index,
                ingress_ident.ifindex,
                ingress_ident.queue_id,
                target_ifindex,
            )
        };
    let mut decision = *decision;
    if decision.resolution.disposition == ForwardingDisposition::FabricRedirect
        && let Some(ingress_zone) = fabric_ingress_zone
        && let Some(zone_redirect) =
            resolve_zone_encoded_fabric_redirect(forwarding, ingress_zone.as_ref())
    {
        decision.resolution.src_mac = zone_redirect.src_mac;
    }
    Some(PendingForwardRequest {
        target_ifindex,
        target_binding_index,
        ingress_queue_id: ingress_ident.queue_id,
        source_offset: desc.addr,
        desc,
        source_frame: None,
        meta,
        decision,
        apply_nat_on_fabric,
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

fn build_missing_neighbor_session_metadata(
    forwarding: &ForwardingState,
    ingress_zone: &Arc<str>,
    egress_zone: &Arc<str>,
    ingress_ifindex: i32,
    decision: SessionDecision,
) -> SessionMetadata {
    SessionMetadata {
        ingress_zone: ingress_zone.clone(),
        egress_zone: egress_zone.clone(),
        owner_rg_id: owner_rg_for_resolution(forwarding, decision.resolution),
        fabric_ingress: ingress_is_fabric(forwarding, ingress_ifindex),
        is_reverse: false,
        nat64_reverse: None,
    }
}

fn binding_by_index_mut<'a>(
    left: &'a mut [BindingWorker],
    current_index: usize,
    current: &'a mut BindingWorker,
    right: &'a mut [BindingWorker],
    target_index: usize,
) -> Option<&'a mut BindingWorker> {
    if target_index == current_index {
        return Some(current);
    }
    if target_index < current_index {
        return left.get_mut(target_index);
    }
    right.get_mut(target_index.saturating_sub(current_index + 1))
}

fn find_target_binding_mut<'a>(
    left: &'a mut [BindingWorker],
    current_index: usize,
    ingress_binding: &'a mut BindingWorker,
    ingress_queue_id: u32,
    right: &'a mut [BindingWorker],
    binding_lookup: &WorkerBindingLookup,
    egress_ifindex: i32,
) -> Option<&'a mut BindingWorker> {
    let target_index = binding_lookup.target_index(
        current_index,
        ingress_binding.ifindex,
        ingress_queue_id,
        egress_ifindex,
    )?;
    binding_by_index_mut(left, current_index, ingress_binding, right, target_index)
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
    conntrack_v4_fd: c_int,
    conntrack_v6_fd: c_int,
    deltas: &[SessionDelta],
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    recent_session_deltas: &Arc<Mutex<VecDeque<SessionDeltaInfo>>>,
    peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    event_stream: &Option<crate::event_stream::EventStreamWorkerHandle>,
    zone_name_to_id: &FastMap<String, u16>,
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
            disposition: match delta.decision.resolution.disposition {
                ForwardingDisposition::ForwardCandidate => "forward_candidate",
                ForwardingDisposition::LocalDelivery => "local_delivery",
                ForwardingDisposition::NoRoute => "no_route",
                ForwardingDisposition::MissingNeighbor => "missing_neighbor",
                ForwardingDisposition::PolicyDenied => "policy_denied",
                ForwardingDisposition::FabricRedirect => "fabric_redirect",
                ForwardingDisposition::HAInactive => "ha_inactive",
                ForwardingDisposition::DiscardRoute => "discard_route",
                ForwardingDisposition::NextTableUnsupported => "next_table_unsupported",
            }
            .to_string(),
            origin: delta.origin.as_str().to_string(),
            egress_ifindex: delta.decision.resolution.egress_ifindex,
            tx_ifindex: delta.decision.resolution.tx_ifindex,
            tunnel_endpoint_id: delta.decision.resolution.tunnel_endpoint_id,
            tx_vlan_id: delta.decision.resolution.tx_vlan_id,
            next_hop: delta
                .decision
                .resolution
                .next_hop
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            neighbor_mac: delta
                .decision
                .resolution
                .neighbor_mac
                .map(format_mac)
                .unwrap_or_default(),
            src_mac: delta
                .decision
                .resolution
                .src_mac
                .map(format_mac)
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
            fabric_redirect: delta.fabric_redirect_sync
                || delta.decision.resolution.disposition == ForwardingDisposition::FabricRedirect,
            fabric_ingress: delta.metadata.fabric_ingress,
        };
        live.push_session_delta(info.clone());
        // Push to event stream (new path) alongside existing RPC fallback.
        if let Some(es) = event_stream {
            es.push_delta(delta, zone_name_to_id);
        }
        if let Ok(mut recent) = recent_session_deltas.lock() {
            push_recent_session_delta(&mut recent, info);
        }
        if delta.kind == SessionDeltaKind::Close {
            if cfg!(feature = "debug-log") {
                debug_log!(
                    "SESS_DELETE: proto={} {}:{} -> {}:{} nat_src={:?} nat_dst={:?} bpf_entries_before={}",
                    delta.key.protocol,
                    delta.key.src_ip,
                    delta.key.src_port,
                    delta.key.dst_ip,
                    delta.key.dst_port,
                    delta.decision.nat.rewrite_src,
                    delta.decision.nat.rewrite_dst,
                    count_bpf_session_entries(session_map_fd),
                );
            }
            delete_live_session_entry(
                session_map_fd,
                &delta.key,
                delta.decision.nat,
                delta.metadata.is_reverse,
            );
            delete_bpf_conntrack_entry(conntrack_v4_fd, conntrack_v6_fd, &delta.key);
            remove_shared_session(
                shared_sessions,
                shared_nat_sessions,
                shared_forward_wire_sessions,
                &delta.key,
            );
            let reverse_key = reverse_session_key(&delta.key, delta.decision.nat);
            delete_live_session_entry(session_map_fd, &reverse_key, delta.decision.nat, true);
            delete_bpf_conntrack_entry(conntrack_v4_fd, conntrack_v6_fd, &reverse_key);
            remove_shared_session(
                shared_sessions,
                shared_nat_sessions,
                shared_forward_wire_sessions,
                &reverse_key,
            );
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

fn worker_loop(
    worker_id: u32,
    binding_plans: Vec<BindingPlan>,
    shared_validation: Arc<ArcSwap<ValidationState>>,
    shared_forwarding: Arc<ArcSwap<ForwardingState>>,
    ha_state: Arc<ArcSwap<BTreeMap<i32, HAGroupRuntime>>>,
    dynamic_neighbors: Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
    shared_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    slow_path: Option<Arc<SlowPathReinjector>>,
    local_tunnel_deliveries: Arc<ArcSwap<BTreeMap<i32, SyncSender<Vec<u8>>>>>,
    recent_exceptions: Arc<Mutex<VecDeque<ExceptionStatus>>>,
    recent_session_deltas: Arc<Mutex<VecDeque<SessionDeltaInfo>>>,
    last_resolution: Arc<Mutex<Option<PacketResolution>>>,
    commands: Arc<Mutex<VecDeque<WorkerCommand>>>,
    peer_worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>>,
    stop: Arc<AtomicBool>,
    heartbeat: Arc<AtomicU64>,
    demotion_prepare_ack: Arc<AtomicU64>,
    ha_state_apply_ack: Arc<AtomicU64>,
    session_export_ack: Arc<AtomicU64>,
    poll_mode: crate::PollMode,
    dnat_fds: DnatTableFds,
    shared_fabrics: Arc<ArcSwap<Vec<FabricLink>>>,
    event_stream: Option<crate::event_stream::EventStreamWorkerHandle>,
    rg_epochs: Arc<[AtomicU32; MAX_RG_EPOCHS]>,
) {
    pin_current_thread(worker_id);
    let ha_startup_grace_until_secs =
        (monotonic_nanos() / 1_000_000_000).saturating_add(TUNNEL_HA_STARTUP_GRACE_SECS);
    let mut validation = **shared_validation.load();
    let mut forwarding = shared_forwarding.load_full();
    let mut sessions = SessionTable::new();
    let mut screen_state = ScreenState::new();
    screen_state.update_profiles(forwarding.screen_profiles.clone());
    sessions.set_timeouts(forwarding.session_timeouts);
    let mut bindings = Vec::with_capacity(binding_plans.len());
    for plan in binding_plans {
        let driver_name = interface_driver_name(&plan.status.interface);
        let total_frames =
            binding_frame_count_for_driver(driver_name.as_deref(), plan.ring_entries).max(1);
        let binding = match WorkerUmemPool::new(total_frames)
            .map_err(|err| format!("create binding umem: {err}"))
        {
            Ok(WorkerUmemPool {
                umem,
                mut free_frames,
            }) => BindingWorker::create(
                &plan.status,
                plan.ring_entries,
                plan.xsk_map_fd,
                plan.heartbeat_map_fd,
                plan.session_map_fd,
                plan.conntrack_v4_fd,
                plan.conntrack_v6_fd,
                plan.live.clone(),
                plan.bind_strategy,
                plan.poll_mode,
                umem,
                &mut free_frames,
                false,
            ),
            Err(err) => Err(err.to_string().into()),
        };
        match binding {
            Ok(binding) => bindings.push(binding),
            Err(err) => plan.live.set_error(err.to_string()),
        }
    }
    let binding_lookup = WorkerBindingLookup::from_bindings(&bindings);
    let mut interrupt_poll_fds = if poll_mode == crate::PollMode::Interrupt {
        bindings
            .iter()
            .map(|binding| libc::pollfd {
                fd: binding.device.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let mut idle_iters = 0u32;
    let mut poll_start = 0usize;
    let mut shared_recycles = Vec::with_capacity((RX_BATCH_SIZE as usize).saturating_mul(2));
    // Debug: periodic summary counters
    let mut dbg_last_report_ns = monotonic_nanos();
    let mut dbg_rx_total = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_tx_total = 0u64;
    let mut dbg_forward_total = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_local_total = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_session_hit = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_session_miss = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_session_create = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_no_route = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_missing_neigh = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_policy_deny = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_ha_inactive = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_no_egress_binding = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_build_fail = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_tx_err = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_metadata_err = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_disposition_other = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_enqueue_ok = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_enqueue_inplace = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_enqueue_direct = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_enqueue_copy = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_rx_from_trust = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_rx_from_wan = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_fwd_trust_to_wan = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_fwd_wan_to_trust = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_nat_snat = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_nat_dnat = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_nat_none = 0u64;
    #[cfg(feature = "debug-log")]
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
    #[cfg(feature = "debug-log")]
    let mut dbg_rx_bytes_total = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_tx_bytes_total = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_rx_oversized = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_rx_max_frame = 0u32;
    #[cfg(feature = "debug-log")]
    let mut dbg_tx_max_frame = 0u32;
    #[cfg(feature = "debug-log")]
    let mut dbg_seg_needed_but_none = 0u64;
    let mut prev_rx_total = 0u64;
    let mut prev_fwd_total = 0u64;
    let mut stall_prev_fwd = 0u64;
    let mut stall_reported = false;
    const DBG_REPORT_INTERVAL_NS: u64 = 1_000_000_000; // 1 second
    // Throttle for BPF conntrack last_seen refresh (~10s).
    // Keeps `show security flow session` idle times accurate without
    // per-second syscall overhead per session.  See issue #333.
    const CT_REFRESH_INTERVAL_NS: u64 = 10_000_000_000;
    let mut last_ct_refresh_ns: u64 = 0;
    while !stop.load(Ordering::Relaxed) {
        let session_map_fd = bindings
            .first()
            .map(|binding| binding.session_map_fd)
            .unwrap_or(-1);
        let conntrack_v4_fd = bindings
            .first()
            .map(|binding| binding.conntrack_v4_fd)
            .unwrap_or(-1);
        let conntrack_v6_fd = bindings
            .first()
            .map(|binding| binding.conntrack_v6_fd)
            .unwrap_or(-1);
        let loop_now_ns = monotonic_nanos();
        let loop_now_secs = loop_now_ns / 1_000_000_000;
        let live_validation = shared_validation.load();
        if **live_validation != validation {
            validation = **live_validation;
        }
        let live_forwarding = shared_forwarding.load_full();
        if !Arc::ptr_eq(&forwarding, &live_forwarding) {
            forwarding = live_forwarding;
            screen_state.update_profiles(forwarding.screen_profiles.clone());
            sessions.set_timeouts(forwarding.session_timeouts);
        }
        let ha_runtime = ha_state.load();
        // Only apply commands when pending — avoids lock overhead on
        // every loop iteration in the common (empty-queue) case.
        let has_commands = commands.try_lock().map(|q| !q.is_empty()).unwrap_or(false);
        let command_results = if has_commands {
            apply_worker_commands(
                &commands,
                &mut sessions,
                session_map_fd,
                conntrack_v4_fd,
                conntrack_v6_fd,
                &forwarding,
                ha_runtime.as_ref(),
                &dynamic_neighbors,
            )
        } else {
            WorkerCommandResults {
                cancelled_keys: Vec::new(),
                prepared_sequences: Vec::new(),
                applied_sequences: Vec::new(),
                exported_sequences: Vec::new(),
            }
        };
        if !command_results.cancelled_keys.is_empty() {
            for key in &command_results.cancelled_keys {
                for binding in bindings.iter_mut() {
                    cancel_queued_flow_on_binding(binding, key, key);
                }
            }
        }
        heartbeat.store(loop_now_ns, Ordering::Relaxed);
        let expired_entries = sessions.expire_stale_entries(loop_now_ns);
        let expired = expired_entries.len() as u64;
        for expired_entry in expired_entries {
            delete_session_map_entry_for_removed_session_with_origin(
                session_map_fd,
                &expired_entry.key,
                expired_entry.decision,
                &expired_entry.metadata,
                expired_entry.origin,
                conntrack_v4_fd,
                conntrack_v6_fd,
            );
        }
        if expired > 0 {
            if let Some(binding) = bindings.first() {
                binding
                    .live
                    .session_expires
                    .fetch_add(expired, Ordering::Relaxed);
            }
        }
        // Periodically refresh last_seen in BPF conntrack entries so Go-side
        // callers of IterateSessions (CLI, gRPC, Prometheus) see accurate
        // session idle times.  Issue #333.
        if loop_now_ns.saturating_sub(last_ct_refresh_ns) >= CT_REFRESH_INTERVAL_NS {
            last_ct_refresh_ns = loop_now_ns;
            refresh_bpf_conntrack_last_seen(
                conntrack_v4_fd,
                conntrack_v6_fd,
                &sessions,
                loop_now_ns,
            );
        }
        // Check if fabric links were updated by the coordinator (e.g. after
        // RG failover when peer MAC was resolved). If so, rebuild the
        // forwarding Arc with the new fabric links so fabric redirect works.
        {
            let live_fabrics = shared_fabrics.load();
            if !live_fabrics.is_empty() && live_fabrics.as_ref() != &forwarding.fabrics {
                let mut updated = (*forwarding).clone();
                updated.fabrics = live_fabrics.as_ref().clone();
                forwarding = Arc::new(updated);
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
                &binding_lookup,
                &mut sessions,
                &mut screen_state,
                validation,
                loop_now_ns,
                loop_now_secs,
                ha_startup_grace_until_secs,
                &forwarding,
                ha_runtime.as_ref(),
                &dynamic_neighbors,
                &shared_sessions,
                &shared_nat_sessions,
                &shared_forward_wire_sessions,
                slow_path.as_ref(),
                &local_tunnel_deliveries,
                &recent_exceptions,
                &recent_session_deltas,
                &last_resolution,
                &peer_worker_commands,
                &mut shared_recycles,
                &dnat_fds,
                conntrack_v4_fd,
                conntrack_v6_fd,
                &mut dbg_poll,
                &rg_epochs,
            ) {
                did_work = true;
            }
        }
        dbg_rx_total += dbg_poll.rx;
        #[cfg(feature = "debug-log")]
        {
            dbg_tx_total += dbg_poll.tx;
        }
        dbg_forward_total += dbg_poll.forward;
        #[cfg(feature = "debug-log")]
        {
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
        }
        #[cfg(feature = "debug-log")]
        {
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
        }
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
        #[cfg(feature = "debug-log")]
        {
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
        }
        if !bindings.is_empty() {
            poll_start = (poll_start + 1) % bindings.len();
        }
        if let Some(sequence) = command_results.prepared_sequences.iter().copied().max() {
            // Demotion prepare only needs local worker state to be updated. Do
            // not block the ack on unrelated steady-state delta churn.
            demotion_prepare_ack.store(sequence, Ordering::Release);
        }
        if let Some(sequence) = command_results.applied_sequences.iter().copied().max() {
            ha_state_apply_ack.store(sequence, Ordering::Release);
        }
        if !command_results.prepared_sequences.is_empty()
            || !command_results.exported_sequences.is_empty()
        {
            while sessions.has_pending_deltas() {
                let deltas = sessions.drain_deltas(256);
                purge_queued_flows_for_closed_deltas(&mut bindings, &deltas);
                if let Some(binding) = bindings.first() {
                    let ident = binding.identity();
                    flush_session_deltas(
                        &ident,
                        &binding.live,
                        binding.session_map_fd,
                        conntrack_v4_fd,
                        conntrack_v6_fd,
                        &deltas,
                        &shared_sessions,
                        &shared_nat_sessions,
                        &shared_forward_wire_sessions,
                        &recent_session_deltas,
                        &peer_worker_commands,
                        &event_stream,
                        &forwarding.zone_name_to_id,
                    );
                }
            }
            if let Some(sequence) = command_results.exported_sequences.iter().copied().max() {
                session_export_ack.store(sequence, Ordering::Release);
            }
        } else if sessions.has_pending_deltas() {
            let deltas = sessions.drain_deltas(256);
            purge_queued_flows_for_closed_deltas(&mut bindings, &deltas);
            if let Some(binding) = bindings.first() {
                let ident = binding.identity();
                flush_session_deltas(
                    &ident,
                    &binding.live,
                    binding.session_map_fd,
                    conntrack_v4_fd,
                    conntrack_v6_fd,
                    &deltas,
                    &shared_sessions,
                    &shared_nat_sessions,
                    &shared_forward_wire_sessions,
                    &recent_session_deltas,
                    &peer_worker_commands,
                    &event_stream,
                    &forwarding.zone_name_to_id,
                );
            }
        }
        // Debug: periodic summary report
        {
            let elapsed = loop_now_ns.saturating_sub(dbg_last_report_ns);
            if elapsed >= DBG_REPORT_INTERVAL_NS {
                #[cfg(feature = "debug-log")]
                let secs = elapsed as f64 / 1_000_000_000.0;
                let session_count = sessions.len();
                let mut binding_summary = String::new();
                for (i, b) in bindings.iter().enumerate() {
                    use std::fmt::Write;
                    let fill_pending = b.device.pending();
                    let rx_avail = b.rx.available_relaxed();
                    let xsk_stats = b.device.statistics_v2().ok();
                    let inflight_recycles = b.in_flight_prepared_recycles.len() as u32;
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
                    let expected_total = b.umem.total_frames();
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
                    {
                        dbg_tx_tcp_rst += b.dbg_tx_tcp_rst;
                    }
                    let _ = write!(
                        binding_summary,
                        " TX:ring_sub={}/ring_full={}/compl={}/sendto={}/err={}/eagain={}/enobufs={}/overflow={}",
                        b.dbg_tx_ring_submitted,
                        b.dbg_tx_ring_full,
                        b.dbg_completions_reaped,
                        b.dbg_sendto_calls,
                        b.dbg_sendto_err,
                        b.dbg_sendto_eagain,
                        b.dbg_sendto_enobufs,
                        b.dbg_pending_overflow,
                    );
                    #[cfg(feature = "debug-log")]
                    let _ = write!(binding_summary, "/rst={}", b.dbg_tx_tcp_rst);
                    if let Some(s) = xsk_stats {
                        let _ = write!(
                            binding_summary,
                            " xsk:drop={}/inv={}/rfull={}/fempty={}/tinv={}/tempty={}",
                            s.rx_dropped,
                            s.rx_invalid_descs,
                            s.rx_ring_full,
                            s.rx_fill_ring_empty_descs,
                            s.tx_invalid_descs,
                            s.tx_ring_empty_descs,
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
                    // Ring diagnostics from xsk_ffi API
                    if cfg!(feature = "debug-log") {
                        let _ = write!(
                            binding_summary,
                            " RING:rx_nz={}/rx_max={}/fill_pend={}/dev_avail={} RX_WAKE:ok={}/err={}/errno={}",
                            b.dbg_rx_avail_nonzero,
                            b.dbg_rx_avail_max,
                            b.dbg_fill_pending,
                            b.dbg_device_avail,
                            b.dbg_rx_wake_sendto_ok,
                            b.dbg_rx_wake_sendto_err,
                            b.dbg_rx_wake_sendto_errno,
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
                    dbg_rx_from_trust,
                    dbg_rx_from_wan,
                    dbg_fwd_trust_to_wan,
                    dbg_fwd_wan_to_trust,
                    dbg_nat_snat,
                    dbg_nat_dnat,
                    dbg_nat_none,
                    dbg_frame_build_none,
                    dbg_rx_tcp_rst,
                    dbg_tx_tcp_rst,
                    if dbg_rx_total > 0 {
                        dbg_rx_bytes_total / dbg_rx_total
                    } else {
                        0
                    },
                    dbg_rx_max_frame,
                    if dbg_enqueue_ok > 0 {
                        dbg_tx_bytes_total / dbg_enqueue_ok
                    } else {
                        0
                    },
                    dbg_tx_max_frame,
                    dbg_rx_oversized,
                    dbg_seg_needed_but_none,
                    dbg_rx_tcp_fin,
                    dbg_rx_tcp_synack,
                    dbg_rx_tcp_zero_window,
                    dbg_fwd_tcp_fin,
                    dbg_fwd_tcp_rst,
                    dbg_fwd_tcp_zero_window,
                    CSUM_VERIFIED_TOTAL.swap(0, Ordering::Relaxed),
                    CSUM_BAD_IP_TOTAL.swap(0, Ordering::Relaxed),
                    CSUM_BAD_L4_TOTAL.swap(0, Ordering::Relaxed),
                    SESSION_PUBLISH_VERIFY_OK.swap(0, Ordering::Relaxed),
                    SESSION_PUBLISH_VERIFY_FAIL.swap(0, Ordering::Relaxed),
                    if let Some(b) = bindings.first() {
                        count_bpf_session_entries(b.session_map_fd)
                    } else {
                        0
                    },
                    binding_summary,
                );
                // Non-debug builds: no per-second stats dump (use debug-log feature for verbose output).
                // Print XDP shim fallback stats — tells us WHY packets stop
                // being redirected to XSK.
                if cfg!(feature = "debug-log") {
                    if let Some(stats) = read_fallback_stats() {
                        if !stats.is_empty() {
                            let s: Vec<String> =
                                stats.iter().map(|(n, v)| format!("{n}={v}")).collect();
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
                #[cfg(feature = "debug-log")]
                {
                    dbg_tx_total = 0;
                }
                dbg_forward_total = 0;
                #[cfg(feature = "debug-log")]
                {
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
                }
                #[cfg(feature = "debug-log")]
                {
                    dbg_disposition_other = 0;
                    dbg_enqueue_ok = 0;
                    dbg_enqueue_inplace = 0;
                    dbg_enqueue_direct = 0;
                    dbg_enqueue_copy = 0;
                    dbg_rx_from_trust = 0;
                    dbg_rx_from_wan = 0;
                    dbg_fwd_trust_to_wan = 0;
                    dbg_fwd_wan_to_trust = 0;
                }
                #[cfg(feature = "debug-log")]
                {
                    dbg_rx_bytes_total = 0;
                    dbg_tx_bytes_total = 0;
                    dbg_rx_oversized = 0;
                    dbg_rx_max_frame = 0;
                    dbg_tx_max_frame = 0;
                    dbg_seg_needed_but_none = 0;
                }
                // Stall detection: stall_prev_fwd is PREVIOUS interval's fwd count,
                // prev_fwd_total is THIS interval's fwd count (saved before reset).
                if cfg!(feature = "debug-log") {
                    if stall_prev_fwd > 10 && prev_fwd_total == 0 && !stall_reported {
                        stall_reported = true;
                        eprintln!(
                            "DBG STALL_DETECTED: w{} two_ago_fwd={} this_interval_fwd={} this_interval_rx={} sessions={}",
                            worker_id, stall_prev_fwd, prev_fwd_total, prev_rx_total, session_count
                        );
                        // Dump comprehensive per-binding state at stall moment
                        for (si, sb) in bindings.iter().enumerate() {
                            use std::fmt::Write;
                            let fill_p = sb.device.pending();
                            let rx_a = sb.rx.available_relaxed();
                            let ifl = sb.in_flight_prepared_recycles.len() as u32;
                            let ptxp = sb.pending_tx_prepared.len() as u32;
                            let ptxl = sb.pending_tx_local.len() as u32;
                            let total = sb.pending_fill_frames.len() as u32
                                + fill_p
                                + rx_a
                                + sb.free_tx_frames.len() as u32
                                + sb.outstanding_tx
                                + ifl
                                + sb.scratch_recycle.len() as u32
                                + ptxp;
                            let raw = diagnose_raw_ring_state(sb.rx.as_raw_fd());
                            let mut stall_line = format!(
                                "DBG STALL_BINDING[{}]: if={} q={} pfill={} fring={} rxring={} free_tx={} otx={} ifl={} ptxp={} ptxl={} total={}/{}",
                                si,
                                sb.ifindex,
                                sb.queue_id,
                                sb.pending_fill_frames.len(),
                                fill_p,
                                rx_a,
                                sb.free_tx_frames.len(),
                                sb.outstanding_tx,
                                ifl,
                                ptxp,
                                ptxl,
                                total,
                                sb.umem.total_frames(),
                            );
                            if let Some((rxp, rxc, frp, frc, txp, txc, crp, crc)) = raw {
                                let _ = write!(
                                    stall_line,
                                    " RAW:rxP={rxp}/rxC={rxc}/frP={frp}/frC={frc}/txP={txp}/txC={txc}/crP={crp}/crC={crc}"
                                );
                            }
                            if let Ok(Some(stats)) = sb.device.statistics_v2().map(Some) {
                                let _ = write!(
                                    stall_line,
                                    " xsk:drop={}/rfull={}/fempty={}/tempty={}",
                                    stats.rx_dropped,
                                    stats.rx_ring_full,
                                    stats.rx_fill_ring_empty_descs,
                                    stats.tx_ring_empty_descs
                                );
                            }
                            eprintln!("{stall_line}");
                        }
                        // Dump all session keys for this worker
                        let mut sess_dump = String::new();
                        let mut count = 0;
                        sessions.iter_with_origin(|key, decision, metadata, origin| {
                            if count < 20 {
                                use std::fmt::Write;
                                let _ = write!(
                                    sess_dump,
                                    "\n  SESS: {}:{} -> {}:{} proto={} nat=({:?},{:?}) is_rev={} origin={}",
                                    key.src_ip,
                                    key.src_port,
                                    key.dst_ip,
                                    key.dst_port,
                                    key.protocol,
                                    decision.nat.rewrite_src,
                                    decision.nat.rewrite_dst,
                                    metadata.is_reverse,
                                    origin.as_str(),
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
                                let s: Vec<String> =
                                    stats.iter().map(|(n, v)| format!("{n}={v}")).collect();
                                eprintln!("DBG STALL_FALLBACK: {}", s.join(" "));
                            }
                        }
                        // Also dump BPF session count
                        if let Some(b) = bindings.first() {
                            eprintln!(
                                "DBG STALL_BPF_SESSIONS: entries={}",
                                count_bpf_session_entries(b.session_map_fd)
                            );
                        }
                    } else if prev_fwd_total > 0 {
                        stall_reported = false;
                    }
                    stall_prev_fwd = prev_fwd_total;
                }
                #[cfg(feature = "debug-log")]
                {
                    dbg_nat_snat = 0;
                    dbg_nat_dnat = 0;
                    dbg_nat_none = 0;
                    dbg_frame_build_none = 0;
                }
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
                    {
                        b.dbg_tx_tcp_rst = 0;
                    }
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
        match poll_mode {
            crate::PollMode::BusyPoll => {
                if idle_iters <= IDLE_SPIN_ITERS {
                    std::hint::spin_loop();
                } else {
                    thread::sleep(Duration::from_micros(IDLE_SLEEP_US));
                }
            }
            crate::PollMode::Interrupt => {
                // Interrupt mode still needs a short local spin before blocking.
                // Firewall-local TCP flows are ACK-latency-sensitive; blocking
                // immediately on the first empty poll collapses cwnd badly.
                if idle_iters <= IDLE_SPIN_ITERS {
                    std::hint::spin_loop();
                } else if !interrupt_poll_fds.is_empty() {
                    for pfd in &mut interrupt_poll_fds {
                        pfd.revents = 0;
                    }
                    unsafe {
                        libc::poll(
                            interrupt_poll_fds.as_mut_ptr(),
                            interrupt_poll_fds.len() as libc::nfds_t,
                            INTERRUPT_POLL_TIMEOUT_MS,
                        );
                    }
                } else {
                    thread::sleep(Duration::from_millis(INTERRUPT_POLL_TIMEOUT_MS as u64));
                }
            }
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
    flow_cache_hits: u64,
    flow_cache_misses: u64,
    flow_cache_evictions: u64,
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
    slow_path_local_delivery_packets: u64,
    slow_path_missing_neighbor_packets: u64,
    slow_path_no_route_packets: u64,
    slow_path_next_table_packets: u64,
    slow_path_forward_build_packets: u64,
    slow_path_drops: u64,
    slow_path_rate_limited: u64,
    kernel_rx_dropped: u64,
    kernel_rx_invalid_descs: u64,
    tx_packets: u64,
    tx_bytes: u64,
    tx_completions: u64,
    tx_errors: u64,
    direct_tx_packets: u64,
    copy_tx_packets: u64,
    in_place_tx_packets: u64,
    direct_tx_no_frame_fallback_packets: u64,
    direct_tx_build_fallback_packets: u64,
    direct_tx_disallowed_fallback_packets: u64,
    debug_pending_fill_frames: u32,
    #[allow(dead_code)]
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
    use super::test_fixtures::*;
    use super::*;
    use crate::{InterfaceAddressSnapshot, SourceNATRuleSnapshot, StaticNATRuleSnapshot};

    #[test]
    fn mlx5_keeps_umem_owner_bind_strategy() {
        assert_eq!(
            bind_strategy_for_driver(Some("mlx5_core")),
            AfXdpBindStrategy::UmemOwnerSocket
        );
        assert_eq!(
            alternate_bind_strategy(Some("mlx5_core"), AfXdpBindStrategy::UmemOwnerSocket),
            None
        );
    }

    #[test]
    fn virtio_uses_auto_mode_umem_owner_strategy() {
        assert_eq!(
            bind_strategy_for_driver(Some("virtio_net")),
            AfXdpBindStrategy::UmemOwnerSocket
        );
        assert_eq!(
            alternate_bind_strategy(Some("virtio_net"), AfXdpBindStrategy::UmemOwnerSocket,),
            None
        );
        assert_eq!(
            binder_for_strategy(AfXdpBindStrategy::UmemOwnerSocket),
            AfXdpBinder::Umem
        );
        assert_eq!(bind_flag_candidates_for_driver(Some("virtio_net")), &[0]);
        assert_eq!(
            bind_flag_candidates_for_driver(Some("mlx5_core")),
            &[XSK_BIND_FLAGS_ZEROCOPY, XSK_BIND_FLAGS_COPY]
        );
    }

    #[test]
    fn shared_umem_group_key_is_same_device_mlx5_only() {
        assert_eq!(
            shared_umem_group_key_for_device(
                Some("mlx5_core"),
                Some("/sys/devices/pci0000:00/0000:08:00.0")
            ),
            Some("mlx5:/sys/devices/pci0000:00/0000:08:00.0".to_string())
        );
        assert_eq!(
            shared_umem_group_key_for_device(
                Some("virtio_net"),
                Some("/sys/devices/pci0000:00/0000:00:07.0")
            ),
            None
        );
        assert_eq!(
            shared_umem_group_key_for_device(Some("mlx5_core"), None),
            None
        );
    }

    #[test]
    fn cloned_worker_umem_shares_allocation_identity() {
        let shared = match WorkerUmem::new(64) {
            Ok(shared) => shared,
            Err(err) => {
                eprintln!("skipping UMEM identity test: {err}");
                return;
            }
        };
        let shared_clone = shared.clone();
        let private = match WorkerUmem::new(64) {
            Ok(private) => private,
            Err(err) => {
                eprintln!("skipping UMEM identity test: {err}");
                return;
            }
        };
        assert!(shared.shares_allocation_with(&shared_clone));
        assert!(!shared.shares_allocation_with(&private));
    }

    #[test]
    fn worker_binding_lookup_prefers_same_queue_binding() {
        let mut lookup = WorkerBindingLookup::default();
        lookup.by_if_queue.insert((5, 0), 0);
        lookup.by_if_queue.insert((5, 1), 1);
        lookup.first_by_if.insert(5, 0);
        lookup.all_by_if.insert(5, vec![0, 1]);

        assert_eq!(lookup.target_index(2, 7, 1, 5), Some(1));
        assert_eq!(lookup.target_index(2, 7, 3, 5), Some(0));
        assert_eq!(lookup.target_index(2, 5, 1, 5), Some(2));
    }

    #[test]
    fn worker_binding_lookup_hashes_fabric_target_across_queues() {
        let mut lookup = WorkerBindingLookup::default();
        lookup.all_by_if.insert(5, vec![10, 11, 12, 13]);

        let indices = [
            lookup.fabric_target_index(5, 0),
            lookup.fabric_target_index(5, 1),
            lookup.fabric_target_index(5, 2),
            lookup.fabric_target_index(5, 3),
        ];
        assert_eq!(indices, [Some(10), Some(11), Some(12), Some(13)]);
    }

    #[test]
    fn worker_binding_lookup_resolves_slot_index() {
        let mut lookup = WorkerBindingLookup::default();
        lookup.by_slot.insert(11, 3);
        assert_eq!(lookup.slot_index(11), Some(3));
        assert_eq!(lookup.slot_index(99), None);
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
                fabric_ingress: false,
                is_reverse: false,
                nat64_reverse: None,
            },
            origin: SessionOrigin::SyncImport,
            protocol: PROTO_TCP,
            tcp_flags: 0,
        };
        let replica = synced_replica_entry(&entry);
        assert!(replica.origin.is_peer_synced());
        assert_eq!(replica.key, entry.key);
        assert_eq!(replica.decision, entry.decision);
    }

    #[test]
    fn reconcile_stop_preserves_shared_synced_sessions() {
        let mut coordinator = Coordinator::new();
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
                fabric_ingress: false,
                is_reverse: false,
                nat64_reverse: None,
            },
            origin: SessionOrigin::SyncImport,
            protocol: PROTO_TCP,
            tcp_flags: 0,
        };
        publish_shared_session(
            &coordinator.shared_sessions,
            &coordinator.shared_nat_sessions,
            &coordinator.shared_forward_wire_sessions,
            &entry,
        );

        coordinator.stop_inner(false);

        let preserved = coordinator.snapshot_shared_session_entries();
        assert_eq!(preserved.len(), 1);
        assert_eq!(preserved[0].key, entry.key);
        assert_eq!(preserved[0].decision, entry.decision);

        coordinator.stop();
        assert!(coordinator.snapshot_shared_session_entries().is_empty());
    }

    #[test]
    fn replay_synced_sessions_requeues_preserved_entries_for_new_workers() {
        let coordinator = Coordinator::new();
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
                fabric_ingress: false,
                is_reverse: false,
                nat64_reverse: None,
            },
            origin: SessionOrigin::SyncImport,
            protocol: PROTO_TCP,
            tcp_flags: 0,
        };
        let worker_command_queues = BTreeMap::from([
            (0u32, Arc::new(Mutex::new(VecDeque::new()))),
            (1u32, Arc::new(Mutex::new(VecDeque::new()))),
        ]);

        let replayed =
            coordinator.replay_synced_sessions(&[entry.clone()], &worker_command_queues, -1);
        assert_eq!(replayed, 1);

        for commands in worker_command_queues.values() {
            let pending = commands.lock().expect("worker command queue");
            assert_eq!(pending.len(), 1);
            match pending.front().expect("queued command") {
                WorkerCommand::UpsertSynced(replayed_entry) => {
                    assert_eq!(replayed_entry.key, entry.key);
                    assert!(replayed_entry.origin.is_peer_synced());
                }
                other => panic!("unexpected command queued during replay: {other:?}"),
            }
        }
    }

    #[test]
    fn demoted_owner_rgs_detects_active_to_inactive_transitions() {
        let previous = BTreeMap::from([
            (
                1,
                HAGroupRuntime {
                    active: true,
                    watchdog_timestamp: 11,
                    lease_timestamp: 11,
                    demoting: false,
                    demoting_until_secs: 0,
                },
            ),
            (
                2,
                HAGroupRuntime {
                    active: true,
                    watchdog_timestamp: 12,
                    lease_timestamp: 12,
                    demoting: false,
                    demoting_until_secs: 0,
                },
            ),
        ]);
        let current = BTreeMap::from([
            (
                1,
                HAGroupRuntime {
                    active: false,
                    watchdog_timestamp: 21,
                    lease_timestamp: 21,
                    demoting: false,
                    demoting_until_secs: 0,
                },
            ),
            (
                2,
                HAGroupRuntime {
                    active: true,
                    watchdog_timestamp: 22,
                    lease_timestamp: 22,
                    demoting: false,
                    demoting_until_secs: 0,
                },
            ),
        ]);

        assert_eq!(demoted_owner_rgs(&previous, &current), vec![1]);
    }

    #[test]
    fn activated_owner_rgs_detects_inactive_to_active_transitions() {
        let previous = BTreeMap::from([
            (
                1,
                HAGroupRuntime {
                    active: false,
                    watchdog_timestamp: 11,
                    lease_timestamp: 11,
                    demoting: false,
                    demoting_until_secs: 0,
                },
            ),
            (
                2,
                HAGroupRuntime {
                    active: true,
                    watchdog_timestamp: 12,
                    lease_timestamp: 12,
                    demoting: false,
                    demoting_until_secs: 0,
                },
            ),
        ]);
        let current = BTreeMap::from([
            (
                1,
                HAGroupRuntime {
                    active: true,
                    watchdog_timestamp: 21,
                    lease_timestamp: 21,
                    demoting: false,
                    demoting_until_secs: 0,
                },
            ),
            (
                2,
                HAGroupRuntime {
                    active: true,
                    watchdog_timestamp: 22,
                    lease_timestamp: 22,
                    demoting: false,
                    demoting_until_secs: 0,
                },
            ),
        ]);

        assert_eq!(activated_owner_rgs(&previous, &current), vec![1]);
    }

    #[test]
    fn update_ha_state_clears_expired_demoting_lease_for_active_group() {
        let coordinator = Coordinator::new();
        let now_secs = monotonic_nanos() / 1_000_000_000;
        coordinator.ha_state.store(Arc::new(BTreeMap::from([(
            1,
            HAGroupRuntime {
                active: true,
                watchdog_timestamp: 11,
                lease_timestamp: 11,
                demoting: true,
                demoting_until_secs: now_secs.saturating_sub(1),
            },
        )])));

        coordinator
            .update_ha_state(&[HAGroupStatus {
                rg_id: 1,
                active: true,
                watchdog_timestamp: 22,
            }])
            .expect("update ha state");

        let state = coordinator.ha_state.load();
        let group = state.get(&1).expect("ha group");
        assert!(group.active);
        assert!(!group.demoting);
        assert_eq!(group.demoting_until_secs, 0);
        assert_eq!(group.watchdog_timestamp, 22);
    }

    #[test]
    fn update_ha_state_seeds_lease_for_active_group_without_watchdog() {
        let coordinator = Coordinator::new();
        let before = monotonic_nanos() / 1_000_000_000;

        coordinator
            .update_ha_state(&[HAGroupStatus {
                rg_id: 1,
                active: true,
                watchdog_timestamp: 0,
            }])
            .expect("update ha state");

        let after = monotonic_nanos() / 1_000_000_000;
        let state = coordinator.ha_state.load();
        let group = state.get(&1).expect("ha group");
        assert!(group.active);
        assert_eq!(group.watchdog_timestamp, 0);
        assert!(group.lease_timestamp >= before);
        assert!(group.lease_timestamp <= after);
        assert!(group.is_forwarding_active(after));
    }

    #[test]
    fn set_demoting_owner_rgs_sets_bounded_lease_for_active_group() {
        let coordinator = Coordinator::new();
        coordinator.ha_state.store(Arc::new(BTreeMap::from([(
            1,
            HAGroupRuntime {
                active: true,
                watchdog_timestamp: 11,
                lease_timestamp: 11,
                demoting: false,
                demoting_until_secs: 0,
            },
        )])));

        let before = monotonic_nanos() / 1_000_000_000;
        coordinator.set_demoting_owner_rgs(&[1], true);
        let after = monotonic_nanos() / 1_000_000_000;

        let state = coordinator.ha_state.load();
        let group = state.get(&1).expect("ha group");
        assert!(group.demoting);
        assert!(group.demoting_until_secs >= before + 1);
        assert!(group.demoting_until_secs <= after + HA_DEMOTION_PREP_LEASE_SECS);

        coordinator.set_demoting_owner_rgs(&[1], false);
        let state = coordinator.ha_state.load();
        let group = state.get(&1).expect("ha group");
        assert!(!group.demoting);
        assert_eq!(group.demoting_until_secs, 0);
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
                tunnel_endpoint_id: 0,
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
                tunnel_endpoint_id: 0,
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
                    tunnel_endpoint_id: 0,
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

    // --- Static NAT integration tests ---

    #[test]
    fn static_nat_external_ip_recognized_as_local() {
        let state = build_forwarding_state(&static_nat_snapshot());
        // The external IP 203.0.113.10 should be in local_v4 so traffic
        // destined to it is recognized by the firewall.
        assert!(
            state
                .local_v4
                .contains(&"203.0.113.10".parse::<Ipv4Addr>().unwrap()),
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
        assert!(
            snat.is_some(),
            "SNAT should match internal IP regardless of zone"
        );
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
        snapshot.interfaces[0]
            .addresses
            .push(InterfaceAddressSnapshot {
                family: "inet6".to_string(),
                address: "fd00::1/64".to_string(),
                scope: 0,
            });
        snapshot.interfaces[1]
            .addresses
            .push(InterfaceAddressSnapshot {
                family: "inet6".to_string(),
                address: "2001:db8::1/64".to_string(),
                scope: 0,
            });
        let state = build_forwarding_state(&snapshot);

        // External v6 IP should be in local_v6
        assert!(
            state
                .local_v6
                .contains(&"2001:db8::10".parse::<Ipv6Addr>().unwrap())
        );

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
        assert!(is_icmp_error(PROTO_ICMP, 3)); // Destination Unreachable
        assert!(is_icmp_error(PROTO_ICMP, 11)); // Time Exceeded
        assert!(is_icmp_error(PROTO_ICMP, 12)); // Parameter Problem
        // Non-error types
        assert!(!is_icmp_error(PROTO_ICMP, 0)); // Echo Reply
        assert!(!is_icmp_error(PROTO_ICMP, 8)); // Echo Request
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
        assert_eq!(state.session_timeouts.icmp_ns, 60_000_000_000);
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
        let frame_v4 =
            build_icmp_echo_frame_v4(Ipv4Addr::new(10, 0, 61, 102), Ipv4Addr::new(1, 1, 1, 1), 1);
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
        assert_eq!(
            Ipv4Addr::new(out[26], out[27], out[28], out[29]),
            Ipv4Addr::new(10, 0, 61, 1)
        );
        assert_eq!(Ipv4Addr::new(out[30], out[31], out[32], out[33]), client_ip);
        assert_eq!(out[34], 11);
        assert_eq!(out[35], 0);
        let quoted_ip_start = 42;
        assert_eq!(
            Ipv4Addr::new(
                out[quoted_ip_start + 12],
                out[quoted_ip_start + 13],
                out[quoted_ip_start + 14],
                out[quoted_ip_start + 15]
            ),
            client_ip
        );
        assert_eq!(
            Ipv4Addr::new(
                out[quoted_ip_start + 16],
                out[quoted_ip_start + 17],
                out[quoted_ip_start + 18],
                out[quoted_ip_start + 19]
            ),
            dst_ip
        );
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
        assert_eq!(
            Ipv6Addr::from(<[u8; 16]>::try_from(&out[22..38]).unwrap()),
            "2001:559:8585:ef00::1".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(
            Ipv6Addr::from(<[u8; 16]>::try_from(&out[38..54]).unwrap()),
            client_ip
        );
        assert_eq!(out[54], 3);
        assert_eq!(out[55], 0);
        let quoted_ip_start = 62;
        assert_eq!(
            Ipv6Addr::from(
                <[u8; 16]>::try_from(&out[quoted_ip_start + 8..quoted_ip_start + 24]).unwrap()
            ),
            client_ip
        );
        assert_eq!(
            Ipv6Addr::from(
                <[u8; 16]>::try_from(&out[quoted_ip_start + 24..quoted_ip_start + 40]).unwrap()
            ),
            dst_ip
        );
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
            0x45,
            0x00,
            0x00,
            0x00, // version/IHL, DSCP, total length (fill later)
            0x00,
            0x01,
            0x00,
            0x00, // ID, flags, fragment offset
            64,
            embedded_proto,
            0x00,
            0x00, // TTL, protocol, checksum (fill later)
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

        let frame = build_icmp_te_frame_v4(router_ip, snat_ip, server_ip, snat_port, 80, PROTO_TCP);

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
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(client_ip)),
                neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
                tx_vlan_id: 0,
            },
            metadata: SessionMetadata {
                ingress_zone: Arc::<str>::from("untrust"),
                egress_zone: Arc::<str>::from("trust"),
                owner_rg_id: 0,
                fabric_ingress: false,
                is_reverse: false,
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
        assert_eq!(
            outer_dst, client_ip,
            "outer IP dst should be original client"
        );

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
        assert_eq!(
            emb_port, client_port,
            "embedded src port should be original"
        );

        // Verify outer IP checksum is valid
        let outer_ihl = ((result[14] & 0x0f) as usize) * 4;
        let ip_csum_check = checksum16(&result[14..14 + outer_ihl]);
        assert_eq!(ip_csum_check, 0, "outer IP checksum should be valid (0)");

        // Verify outer ICMP checksum is valid
        let icmp_start = 14 + outer_ihl;
        let icmp_csum_check = checksum16(&result[icmp_start..]);
        assert_eq!(
            icmp_csum_check, 0,
            "outer ICMP checksum should be valid (0)"
        );

        // Verify embedded IP checksum is valid
        let emb_ihl = ((result[emb_ip_start] & 0x0f) as usize) * 4;
        let emb_ip_csum_check = checksum16(&result[emb_ip_start..emb_ip_start + emb_ihl]);
        assert_eq!(
            emb_ip_csum_check, 0,
            "embedded IP checksum should be valid (0)"
        );
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

        let frame = build_icmp_te_frame_v4(router_ip, snat_ip, server_ip, snat_port, 53, PROTO_UDP);

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
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(client_ip)),
                neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
                tx_vlan_id: 0,
            },
            metadata: SessionMetadata {
                ingress_zone: Arc::<str>::from("untrust"),
                egress_zone: Arc::<str>::from("trust"),
                owner_rg_id: 0,
                fabric_ingress: false,
                is_reverse: false,
                nat64_reverse: None,
            },
        };

        let result = build_nat_reversed_icmp_error_v4(&frame, meta, &icmp_match)
            .expect("should build NAT-reversed frame");

        // Verify embedded UDP src port is now the original client port
        let emb_ip_start = 42; // eth(14) + outer_ip(20) + icmp_hdr(8)
        let emb_l4_start = emb_ip_start + 20;
        let emb_port = u16::from_be_bytes([result[emb_l4_start], result[emb_l4_start + 1]]);
        assert_eq!(
            emb_port, client_port,
            "embedded UDP src port should be original"
        );

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
            0x45, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00,
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
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(client_ip)),
                neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
                tx_vlan_id: 0,
            },
            metadata: SessionMetadata {
                ingress_zone: Arc::<str>::from("untrust"),
                egress_zone: Arc::<str>::from("trust"),
                owner_rg_id: 0,
                fabric_ingress: false,
                is_reverse: false,
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

        let frame = build_icmpv6_te_frame(router_ip, snat_ip, server_ip, snat_port, 80, PROTO_TCP);

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
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V6(client_ip)),
                neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
                tx_vlan_id: 0,
            },
            metadata: SessionMetadata {
                ingress_zone: Arc::<str>::from("untrust"),
                egress_zone: Arc::<str>::from("trust"),
                owner_rg_id: 0,
                fabric_ingress: false,
                is_reverse: false,
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
        assert_eq!(
            outer_dst, client_ip,
            "outer IPv6 dst should be original client"
        );

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
        assert_eq!(
            emb_src, client_ip,
            "embedded IPv6 src should be original client"
        );

        // Verify embedded dst is still the server
        let emb_dst_bytes: [u8; 16] = result[emb_ip_start + 24..emb_ip_start + 40]
            .try_into()
            .unwrap();
        let emb_dst = Ipv6Addr::from(emb_dst_bytes);
        assert_eq!(emb_dst, server_ip, "embedded IPv6 dst should remain server");

        // Verify embedded TCP src port
        let emb_l4_start = emb_ip_start + 40;
        let emb_port = u16::from_be_bytes([result[emb_l4_start], result[emb_l4_start + 1]]);
        assert_eq!(
            emb_port, client_port,
            "embedded src port should be original"
        );

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
        assert_eq!(
            actual_csum, expected_csum,
            "ICMPv6 checksum should be valid"
        );
    }

    #[test]
    fn icmpv6_te_nptv6_reverse_lookup_restores_internal_client() {
        let router_ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let external_client: Ipv6Addr = "2602:fd41:70:100::102".parse().unwrap();
        let internal_client: Ipv6Addr = "fd35:1940:27:100::102".parse().unwrap();
        let server_ip: Ipv6Addr = "2607:f8b0:4005:814::200e".parse().unwrap();
        let echo_id: u16 = 0x8234;

        let frame = build_icmpv6_te_frame(
            router_ip,
            external_client,
            server_ip,
            echo_id,
            0,
            PROTO_ICMPV6,
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

        let mut forwarding = ForwardingState::default();
        forwarding.nptv6 = Nptv6State::from_snapshots(&[crate::Nptv6RuleSnapshot {
            name: "nptv6-test".to_string(),
            from_zone: "wan".to_string(),
            internal_prefix: "fd35:1940:0027::/48".to_string(),
            external_prefix: "2602:fd41:0070::/48".to_string(),
        }]);

        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 24,
                tx_ifindex: 24,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V6(internal_client)),
                neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
                tx_vlan_id: 0,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V6(external_client)),
                rewrite_dst: None,
                rewrite_src_port: None,
                rewrite_dst_port: None,
                nat64: false,
                nptv6: true,
            },
        };
        let metadata = SessionMetadata {
            ingress_zone: Arc::<str>::from("lan"),
            egress_zone: Arc::<str>::from("wan"),
            owner_rg_id: 0,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
        };
        let mut sessions = SessionTable::new();
        assert!(sessions.install_with_protocol(
            SessionKey {
                addr_family: libc::AF_INET6 as u8,
                protocol: PROTO_ICMPV6,
                src_ip: IpAddr::V6(internal_client),
                dst_ip: IpAddr::V6(server_ip),
                src_port: echo_id,
                dst_port: 0,
            },
            decision,
            metadata,
            1_000_000,
            PROTO_ICMPV6,
            0,
        ));

        let neighbors = Arc::new(Mutex::new(FastMap::default()));
        let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
        let icmp_match = try_embedded_icmp_nat_match_from_frame(
            &frame,
            meta,
            &mut sessions,
            &forwarding,
            &neighbors,
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            1_000_000,
        )
        .expect("should match embedded ICMPv6 error");

        assert_eq!(icmp_match.original_src, IpAddr::V6(internal_client));
        assert_eq!(icmp_match.original_src_port, echo_id);
        assert!(icmp_match.nat.nptv6);
        assert_eq!(
            icmp_match.nat.rewrite_src,
            Some(IpAddr::V6(external_client))
        );
    }

    #[test]
    fn icmpv6_te_prefers_reverse_session_resolution_for_client_return_path() {
        let router_ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let external_client: Ipv6Addr = "2602:fd41:70:100::102".parse().unwrap();
        let internal_client: Ipv6Addr = "fd35:1940:27:100::102".parse().unwrap();
        let server_ip: Ipv6Addr = "2607:f8b0:4005:814::200e".parse().unwrap();
        let echo_id: u16 = 0x8234;

        let frame = build_icmpv6_te_frame(
            router_ip,
            external_client,
            server_ip,
            echo_id,
            0,
            PROTO_ICMPV6,
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

        let mut forwarding = ForwardingState::default();
        forwarding.nptv6 = Nptv6State::from_snapshots(&[crate::Nptv6RuleSnapshot {
            name: "nptv6-test".to_string(),
            from_zone: "wan".to_string(),
            internal_prefix: "fd35:1940:0027::/48".to_string(),
            external_prefix: "2602:fd41:0070::/48".to_string(),
        }]);

        let forward_key = SessionKey {
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_ICMPV6,
            src_ip: IpAddr::V6(internal_client),
            dst_ip: IpAddr::V6(server_ip),
            src_port: echo_id,
            dst_port: 0,
        };
        let forward_decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 11,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V6(server_ip)),
                neighbor_mac: Some([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
                tx_vlan_id: 80,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V6(external_client)),
                rewrite_dst: None,
                rewrite_src_port: None,
                rewrite_dst_port: None,
                nat64: false,
                nptv6: true,
            },
        };
        let forward_metadata = SessionMetadata {
            ingress_zone: Arc::<str>::from("lan"),
            egress_zone: Arc::<str>::from("wan"),
            owner_rg_id: 0,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
        };

        let reverse_key = reverse_session_key(&forward_key, forward_decision.nat);
        let reverse_resolution = ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 24,
            tx_ifindex: 24,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V6(internal_client)),
            neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x61, 0x01]),
            tx_vlan_id: 0,
        };
        let reverse_decision = SessionDecision {
            resolution: reverse_resolution,
            nat: forward_decision.nat.reverse(
                forward_key.src_ip,
                forward_key.dst_ip,
                forward_key.src_port,
                forward_key.dst_port,
            ),
        };
        let reverse_metadata = SessionMetadata {
            ingress_zone: Arc::<str>::from("wan"),
            egress_zone: Arc::<str>::from("lan"),
            owner_rg_id: 0,
            fabric_ingress: false,
            is_reverse: true,
            nat64_reverse: None,
        };

        let mut sessions = SessionTable::new();
        assert!(sessions.install_with_protocol(
            forward_key.clone(),
            forward_decision,
            forward_metadata,
            1_000_000,
            PROTO_ICMPV6,
            0,
        ));
        assert!(sessions.install_with_protocol(
            reverse_key,
            reverse_decision,
            reverse_metadata,
            1_000_000,
            PROTO_ICMPV6,
            0,
        ));

        let neighbors = Arc::new(Mutex::new(FastMap::default()));
        let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
        let icmp_match = try_embedded_icmp_nat_match_from_frame(
            &frame,
            meta,
            &mut sessions,
            &forwarding,
            &neighbors,
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            1_000_000,
        )
        .expect("should match embedded ICMPv6 error");

        assert_eq!(icmp_match.original_src, IpAddr::V6(internal_client));
        assert_eq!(
            icmp_match.resolution.disposition,
            ForwardingDisposition::ForwardCandidate
        );
        assert_eq!(icmp_match.resolution.egress_ifindex, 24);
        assert_eq!(icmp_match.resolution.tx_ifindex, 24);
        assert_eq!(
            icmp_match.resolution.neighbor_mac,
            Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
        );
    }

    #[test]
    fn no_match_embedded_icmp_returns_none() {
        // An ICMP error with no matching session should return None
        let router_ip = Ipv4Addr::new(10, 0, 0, 1);
        let snat_ip = Ipv4Addr::new(172, 16, 80, 8);
        let server_ip = Ipv4Addr::new(1, 1, 1, 1);

        let frame = build_icmp_te_frame_v4(router_ip, snat_ip, server_ip, 40000, 80, PROTO_TCP);

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
        let result =
            try_embedded_icmp_session_match_from_frame(&frame, meta, &mut sessions, 1_000_000);
        assert!(
            result.is_none(),
            "should return None when no session matches"
        );
    }

    #[test]
    fn embedded_icmp_nat_match_uses_shared_nat_session_for_ipv4() {
        let router_ip = Ipv4Addr::new(10, 0, 0, 1);
        let snat_ip = Ipv4Addr::new(172, 16, 80, 8);
        let client_ip = Ipv4Addr::new(10, 0, 61, 102);
        let server_ip = Ipv4Addr::new(1, 1, 1, 1);
        let snat_port: u16 = 40000;
        let client_port: u16 = 12345;

        let frame = build_icmp_te_frame_v4(router_ip, snat_ip, server_ip, snat_port, 80, PROTO_TCP);
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
        let forwarding = build_forwarding_state(&nat_snapshot());
        let neighbors = Arc::new(Mutex::new(FastMap::default()));
        learn_dynamic_neighbor(
            &forwarding,
            &neighbors,
            24,
            0,
            IpAddr::V4(client_ip),
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        );
        let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));

        let entry = SyncedSessionEntry {
            key: SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V4(client_ip),
                dst_ip: IpAddr::V4(server_ip),
                src_port: client_port,
                dst_port: 80,
            },
            decision: SessionDecision {
                resolution: ForwardingResolution {
                    disposition: ForwardingDisposition::ForwardCandidate,
                    local_ifindex: 0,
                    egress_ifindex: 12,
                    tx_ifindex: 12,
                    tunnel_endpoint_id: 0,
                    next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 1))),
                    neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
                    src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
                    tx_vlan_id: 80,
                },
                nat: NatDecision {
                    rewrite_src: Some(IpAddr::V4(snat_ip)),
                    rewrite_dst: None,
                    rewrite_src_port: Some(snat_port),
                    rewrite_dst_port: None,
                    nat64: false,
                    nptv6: false,
                },
            },
            metadata: SessionMetadata {
                ingress_zone: Arc::<str>::from("lan"),
                egress_zone: Arc::<str>::from("wan"),
                owner_rg_id: 0,
                fabric_ingress: false,
                is_reverse: false,
                nat64_reverse: None,
            },
            origin: SessionOrigin::SyncImport,
            protocol: PROTO_TCP,
            tcp_flags: 0,
        };
        let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
        publish_shared_session(
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &entry,
        );

        let icmp_match = try_embedded_icmp_nat_match_from_frame(
            &frame,
            meta,
            &mut sessions,
            &forwarding,
            &neighbors,
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            1_000_000,
        )
        .expect("shared NAT session should match embedded ICMP");

        assert_eq!(icmp_match.original_src, IpAddr::V4(client_ip));
        assert_eq!(icmp_match.original_src_port, client_port);
        assert_eq!(icmp_match.nat.rewrite_src, Some(IpAddr::V4(snat_ip)));
        assert_eq!(icmp_match.resolution.egress_ifindex, 24);
        assert_eq!(icmp_match.resolution.tx_ifindex, 24);
        assert_eq!(
            icmp_match.resolution.neighbor_mac,
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
    }

    #[test]
    fn embedded_icmp_nat_match_ignores_non_error_echo() {
        let client_ip = Ipv4Addr::new(10, 0, 61, 102);
        let dst_ip = Ipv4Addr::new(1, 1, 1, 1);
        let frame = build_icmp_echo_frame_v4(client_ip, dst_ip, 64);

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
        let forwarding = ForwardingState::default();
        let neighbors = Arc::new(Mutex::new(FastMap::default()));
        let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));

        let result = try_embedded_icmp_nat_match_from_frame(
            &frame,
            meta,
            &mut sessions,
            &forwarding,
            &neighbors,
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            1_000_000,
        );
        assert!(
            result.is_none(),
            "non-error ICMP echo should not trigger embedded NAT reversal"
        );
    }

    #[test]
    fn maybe_reinject_slow_path_ignores_forward_candidate_disposition() {
        let frame =
            build_icmp_echo_frame_v4(Ipv4Addr::new(10, 0, 61, 102), Ipv4Addr::new(1, 1, 1, 1), 64);
        let mut area = MmapArea::new(4096).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let local_tunnel_reinjectors = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));

        let binding = BindingIdentity {
            slot: 3,
            queue_id: 2,
            worker_id: 1,
            interface: Arc::<str>::from("ge-0-0-1"),
            ifindex: 5,
        };
        let live = BindingLiveState::new();
        let recent_exceptions = Arc::new(Mutex::new(VecDeque::new()));
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
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 6,
                tx_ifindex: 6,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
                neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
                src_mac: Some([6, 7, 8, 9, 10, 11]),
                tx_vlan_id: 0,
            },
            nat: NatDecision::default(),
        };

        maybe_reinject_slow_path(
            &binding,
            &live,
            None,
            &local_tunnel_reinjectors,
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            decision,
            &recent_exceptions,
        );

        assert_eq!(live.slow_path_packets.load(Ordering::Relaxed), 0);
        assert_eq!(live.slow_path_drops.load(Ordering::Relaxed), 0);
        assert!(recent_exceptions.lock().expect("exceptions").is_empty());
    }

    #[test]
    fn maybe_reinject_slow_path_records_extract_failure_for_invalid_desc() {
        let area = MmapArea::new(128).expect("mmap");
        let local_tunnel_reinjectors = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
        let binding = BindingIdentity {
            slot: 3,
            queue_id: 2,
            worker_id: 1,
            interface: Arc::<str>::from("ge-0-0-1"),
            ifindex: 5,
        };
        let live = BindingLiveState::new();
        let recent_exceptions = Arc::new(Mutex::new(VecDeque::new()));
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
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::NoRoute,
                local_ifindex: 0,
                egress_ifindex: 0,
                tx_ifindex: 0,
                tunnel_endpoint_id: 0,
                next_hop: None,
                neighbor_mac: None,
                src_mac: None,
                tx_vlan_id: 0,
            },
            nat: NatDecision::default(),
        };

        maybe_reinject_slow_path(
            &binding,
            &live,
            None,
            &local_tunnel_reinjectors,
            &area,
            XdpDesc {
                addr: 512,
                len: 96,
                options: 0,
            },
            meta,
            decision,
            &recent_exceptions,
        );

        assert_eq!(live.slow_path_drops.load(Ordering::Relaxed), 1);
        let exceptions = recent_exceptions.lock().expect("exceptions");
        let last = exceptions.back().expect("exception recorded");
        assert_eq!(last.reason, "slow_path_extract_failed");
        assert_eq!(last.packet_length, 96);
    }

    #[test]
    fn maybe_reinject_slow_path_from_frame_records_unavailable() {
        let frame =
            build_icmp_echo_frame_v4(Ipv4Addr::new(10, 0, 61, 102), Ipv4Addr::new(1, 1, 1, 1), 64);
        let local_tunnel_reinjectors = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
        let binding = BindingIdentity {
            slot: 7,
            queue_id: 0,
            worker_id: 0,
            interface: Arc::<str>::from("ge-0-0-2"),
            ifindex: 6,
        };
        let live = BindingLiveState::new();
        let recent_exceptions = Arc::new(Mutex::new(VecDeque::new()));
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
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::NoRoute,
                local_ifindex: 0,
                egress_ifindex: 0,
                tx_ifindex: 0,
                tunnel_endpoint_id: 0,
                next_hop: None,
                neighbor_mac: None,
                src_mac: None,
                tx_vlan_id: 0,
            },
            nat: NatDecision::default(),
        };

        maybe_reinject_slow_path_from_frame(
            &binding,
            &live,
            None,
            &local_tunnel_reinjectors,
            &frame,
            meta,
            decision,
            &recent_exceptions,
            "forward_build_slow_path",
        );

        assert_eq!(live.slow_path_packets.load(Ordering::Relaxed), 0);
        assert_eq!(live.slow_path_drops.load(Ordering::Relaxed), 1);
        let exceptions = recent_exceptions.lock().expect("exceptions");
        let last = exceptions.back().expect("exception recorded");
        assert_eq!(last.reason, "slow_path_unavailable");
        assert_eq!(last.ifindex, 6);
    }

    #[test]
    fn handle_forward_build_failure_records_build_and_slow_path_failures() {
        let frame =
            build_icmp_echo_frame_v4(Ipv4Addr::new(10, 0, 61, 102), Ipv4Addr::new(1, 1, 1, 1), 64);
        let binding = BindingIdentity {
            slot: 7,
            queue_id: 0,
            worker_id: 0,
            interface: Arc::<str>::from("ge-0-0-2"),
            ifindex: 6,
        };
        let live = BindingLiveState::new();
        let recent_exceptions = Arc::new(Mutex::new(VecDeque::new()));
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
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::NoRoute,
                local_ifindex: 0,
                egress_ifindex: 0,
                tx_ifindex: 0,
                tunnel_endpoint_id: 0,
                next_hop: None,
                neighbor_mac: None,
                src_mac: None,
                tx_vlan_id: 0,
            },
            nat: NatDecision::default(),
        };
        let mut dbg = DebugPollCounters::default();
        let local_tunnel_reinjectors = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));

        handle_forward_build_failure(
            &binding,
            &live,
            None,
            &local_tunnel_reinjectors,
            &recent_exceptions,
            &mut dbg,
            6,
            frame.len() as u32,
            &frame,
            meta,
            decision,
            true,
        );

        assert_eq!(dbg.build_fail, 1);
        assert_eq!(live.slow_path_packets.load(Ordering::Relaxed), 0);
        assert_eq!(live.slow_path_drops.load(Ordering::Relaxed), 1);
        let reasons: Vec<String> = recent_exceptions
            .lock()
            .expect("exceptions")
            .iter()
            .map(|entry| entry.reason.clone())
            .collect();
        assert_eq!(
            reasons,
            vec!["forward_build_failed", "slow_path_unavailable"]
        );
    }

    #[test]
    fn handle_forward_build_failure_without_fallback_only_records_build_failure() {
        let frame =
            build_icmp_echo_frame_v4(Ipv4Addr::new(10, 0, 61, 102), Ipv4Addr::new(1, 1, 1, 1), 64);
        let binding = BindingIdentity {
            slot: 7,
            queue_id: 0,
            worker_id: 0,
            interface: Arc::<str>::from("ge-0-0-2"),
            ifindex: 6,
        };
        let live = BindingLiveState::new();
        let recent_exceptions = Arc::new(Mutex::new(VecDeque::new()));
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
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 12,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
                neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
                src_mac: Some([6, 7, 8, 9, 10, 11]),
                tx_vlan_id: 0,
            },
            nat: NatDecision::default(),
        };
        let mut dbg = DebugPollCounters::default();
        let local_tunnel_reinjectors = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));

        handle_forward_build_failure(
            &binding,
            &live,
            None,
            &local_tunnel_reinjectors,
            &recent_exceptions,
            &mut dbg,
            12,
            frame.len() as u32,
            &frame,
            meta,
            decision,
            false,
        );

        assert_eq!(dbg.build_fail, 1);
        assert_eq!(live.slow_path_packets.load(Ordering::Relaxed), 0);
        assert_eq!(live.slow_path_drops.load(Ordering::Relaxed), 0);
        let reasons: Vec<String> = recent_exceptions
            .lock()
            .expect("exceptions")
            .iter()
            .map(|entry| entry.reason.clone())
            .collect();
        assert_eq!(reasons, vec!["forward_build_failed"]);
    }

    #[test]
    fn slow_path_accept_is_categorized_by_reason_and_disposition() {
        let live = BindingLiveState::new();

        live.record_slow_path_accept(ForwardingDisposition::MissingNeighbor, "slow_path", 128);
        live.record_slow_path_accept(
            ForwardingDisposition::NoRoute,
            "forward_build_slow_path",
            64,
        );

        assert_eq!(live.slow_path_packets.load(Ordering::Relaxed), 2);
        assert_eq!(live.slow_path_bytes.load(Ordering::Relaxed), 192);
        assert_eq!(
            live.slow_path_missing_neighbor_packets
                .load(Ordering::Relaxed),
            1
        );
        assert_eq!(live.slow_path_no_route_packets.load(Ordering::Relaxed), 0);
        assert_eq!(
            live.slow_path_forward_build_packets.load(Ordering::Relaxed),
            1
        );
    }
}
