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
    SessionLookup, SessionMetadata, SessionTable, forward_wire_key, reverse_canonical_key,
};
use crate::slowpath::{EnqueueOutcome, SlowPathReinjector, SlowPathStatus, open_tun};
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
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;
use xdpilone::xdp::XdpDesc;
use xdpilone::{BufIdx, SocketConfig, Umem, UmemConfig, User};

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
#[path = "afxdp/frame.rs"]
mod frame;
#[path = "afxdp/gre.rs"]
mod gre;
#[path = "afxdp/icmp.rs"]
mod icmp;
#[path = "afxdp/icmp_embed.rs"]
mod icmp_embed;
#[path = "afxdp/session_glue.rs"]
mod session_glue;
#[path = "afxdp/tx.rs"]
mod tx;

#[cfg(test)]
use self::bind::bind_flag_candidates_for_driver;
use self::bind::{
    AfXdpBindStrategy, binding_frame_count, ifinfo_from_binding, interface_driver_name,
    open_binding_worker_rings, preferred_bind_strategy, prime_fill_ring_offsets,
    reserved_tx_frames, umem_ring_size,
};
#[cfg(test)]
use self::bind::{
    AfXdpBinder, alternate_bind_strategy, bind_strategy_for_driver, binder_for_strategy,
    shared_umem_group_key_for_device,
};
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
use self::session_glue::*;
use self::tx::*;

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
const BIND_RETRY_ATTEMPTS: usize = 10;
const BIND_RETRY_DELAY: Duration = Duration::from_millis(50);
const DEFAULT_SLOW_PATH_TUN: &str = "bpfrx-usp0";
const LOCAL_TUNNEL_DELIVERY_QUEUE_DEPTH: usize = 4096;

type FastMap<K, V> = FxHashMap<K, V>;
type FastSet<T> = FxHashSet<T>;
const HA_WATCHDOG_STALE_AFTER_SECS: u64 = 2;
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

// ── Flow Cache ──────────────────────────────────────────────────────────
// Per-worker direct-mapped cache that stores precomputed forwarding
// decisions for established TCP flows. On cache hit, the worker skips
// session lookup, policy evaluation, NAT decision, and FIB lookup —
// applying the cached RewriteDescriptor directly to the frame.
const FLOW_CACHE_SIZE: usize = 4096;
const FLOW_CACHE_MASK: usize = FLOW_CACHE_SIZE - 1;

/// Precomputed rewrite descriptor for an established flow.
/// All fields are constant for the lifetime of the session.
/// Per-packet cost: write MACs + TTL-- + apply precomputed csum deltas.
#[derive(Clone, Copy, Debug)]
struct RewriteDescriptor {
    // Ethernet
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    tx_vlan_id: u16,
    ether_type: u16,
    // NAT rewrites (0 = no rewrite for that field)
    rewrite_src_ip: Option<std::net::IpAddr>,
    rewrite_dst_ip: Option<std::net::IpAddr>,
    rewrite_src_port: Option<u16>,
    rewrite_dst_port: Option<u16>,
    // Precomputed incremental checksum deltas
    ip_csum_delta: u16,   // from SNAT+DNAT IP changes (constant per flow)
    l4_csum_delta: u16,   // pseudo-header delta from IP+port changes
    // Egress
    egress_ifindex: i32,
    tx_ifindex: i32,
    target_binding_index: Option<usize>,
    // Validation / invalidation
    config_generation: u64,
    fib_generation: u32,
    owner_rg_id: i32,
    // Flags
    nat64: bool,
    nptv6: bool,
    apply_nat_on_fabric: bool,
}

/// Per-flow cache entry with key validation.
#[derive(Clone)]
struct FlowCacheEntry {
    /// 5-tuple key for validation on hit.
    key: crate::session::SessionKey,
    /// Ingress interface (part of cache key for zone correctness).
    ingress_ifindex: i32,
    /// Precomputed forwarding decision.
    descriptor: RewriteDescriptor,
    /// Full session decision for fallback paths.
    decision: SessionDecision,
    /// Metadata for session sync/HA.
    metadata: SessionMetadata,
}

/// Per-worker flow cache. Direct-mapped, indexed by hash of 5-tuple.
struct FlowCache {
    entries: Vec<Option<FlowCacheEntry>>,
    hits: u64,
    misses: u64,
    evictions: u64,
}

impl FlowCache {
    fn new() -> Self {
        Self {
            entries: (0..FLOW_CACHE_SIZE).map(|_| None).collect(),
            hits: 0,
            misses: 0,
            evictions: 0,
        }
    }

    #[inline]
    fn slot(key: &crate::session::SessionKey, ingress_ifindex: i32) -> usize {
        use std::hash::{Hash, Hasher};
        let mut hasher = rustc_hash::FxHasher::default();
        key.hash(&mut hasher);
        (ingress_ifindex as u32).hash(&mut hasher);
        hasher.finish() as usize & FLOW_CACHE_MASK
    }

    #[inline]
    fn lookup(
        &mut self,
        key: &crate::session::SessionKey,
        ingress_ifindex: i32,
        config_generation: u64,
        fib_generation: u32,
    ) -> Option<&FlowCacheEntry> {
        let idx = Self::slot(key, ingress_ifindex);
        if let Some(entry) = &self.entries[idx] {
            if entry.key == *key
                && entry.ingress_ifindex == ingress_ifindex
                && entry.descriptor.config_generation == config_generation
                && entry.descriptor.fib_generation == fib_generation
            {
                self.hits += 1;
                return self.entries[idx].as_ref();
            }
        }
        self.misses += 1;
        None
    }

    fn insert(&mut self, entry: FlowCacheEntry) {
        let idx = Self::slot(&entry.key, entry.ingress_ifindex);
        if self.entries[idx].is_some() {
            self.evictions += 1;
        }
        self.entries[idx] = Some(entry);
    }

    fn invalidate_all(&mut self) {
        for entry in &mut self.entries {
            *entry = None;
        }
    }
}
// ── End Flow Cache ──────────────────────────────────────────────────────

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
    local_tunnel_deliveries: Arc<ArcSwap<BTreeMap<i32, SyncSender<Vec<u8>>>>>,
    tunnel_sources: BTreeMap<u16, LocalTunnelSourceHandle>,
    last_slow_path_status: SlowPathStatus,
    ha_state: Arc<ArcSwap<BTreeMap<i32, HAGroupRuntime>>>,
    dynamic_neighbors: Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
    shared_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
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
    pub poll_mode: crate::PollMode,
}

impl Coordinator {
    pub fn new() -> Self {
        Self {
            map_fd: None,
            heartbeat_map_fd: None,
            session_map_fd: None,
            slow_path: None,
            local_tunnel_deliveries: Arc::new(ArcSwap::from_pointee(BTreeMap::new())),
            tunnel_sources: BTreeMap::new(),
            last_slow_path_status: SlowPathStatus::default(),
            ha_state: Arc::new(ArcSwap::from_pointee(BTreeMap::new())),
            dynamic_neighbors: Arc::new(Mutex::new(FastMap::default())),
            shared_sessions: Arc::new(Mutex::new(FastMap::default())),
            shared_nat_sessions: Arc::new(Mutex::new(FastMap::default())),
            shared_forward_wire_sessions: Arc::new(Mutex::new(FastMap::default())),
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
            poll_mode: crate::PollMode::BusyPoll,
        }
    }

    pub fn stop(&mut self) {
        self.stop_inner(true);
    }

    pub fn dynamic_neighbors_ref(&self) -> &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>> {
        &self.dynamic_neighbors
    }

    fn stop_inner(&mut self, clear_synced_state: bool) {
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
        self.forwarding = ForwardingState::default();
        if let Ok(mut neighbors) = self.dynamic_neighbors.lock() {
            neighbors.clear();
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
        self.local_tunnel_deliveries.store(Arc::new(BTreeMap::new()));
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
            let commands = worker_command_queues
                .get(&worker_id)
                .cloned()
                .unwrap_or_else(|| Arc::new(Mutex::new(VecDeque::new())));
            let recent_exceptions = self.recent_exceptions.clone();
            let recent_session_deltas = self.recent_session_deltas.clone();
            let last_resolution = self.last_resolution.clone();
            let slow_path = self.slow_path.clone();
            let local_tunnel_deliveries = self.local_tunnel_deliveries.clone();
            let shared_sessions = self.shared_sessions.clone();
            let shared_nat_sessions = self.shared_nat_sessions.clone();
            let shared_forward_wire_sessions = self.shared_forward_wire_sessions.clone();
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
            let worker_poll_mode = self.poll_mode;
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
                        worker_poll_mode,
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

    pub fn update_ha_state(&self, groups: &[HAGroupStatus]) {
        let previous = self.ha_state.load();
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
        let demoted_rgs = demoted_owner_rgs(previous.as_ref(), &state);
        let activated_rgs = activated_owner_rgs(previous.as_ref(), &state);
        self.ha_state.store(Arc::new(state));
        if !demoted_rgs.is_empty() {
            demote_shared_owner_rgs(
                &self.shared_sessions,
                &self.shared_nat_sessions,
                &self.shared_forward_wire_sessions,
                &demoted_rgs,
            );
            for handle in self.workers.values() {
                if let Ok(mut pending) = handle.commands.lock() {
                    for rg_id in &demoted_rgs {
                        pending.push_back(WorkerCommand::DemoteOwnerRG(*rg_id));
                    }
                }
            }
        }
        if !activated_rgs.is_empty() {
            let worker_commands = self
                .workers
                .values()
                .map(|handle| handle.commands.clone())
                .collect::<Vec<_>>();
            let Some(session_map_ref) = self.session_map_fd.as_ref() else {
                return;
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
            for handle in self.workers.values() {
                if let Ok(mut pending) = handle.commands.lock() {
                    pending.push_back(WorkerCommand::RefreshOwnerRGs(activated_rgs.clone()));
                }
            }
        }
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
                binding.direct_tx_packets = snap.direct_tx_packets;
                binding.copy_tx_packets = snap.copy_tx_packets;
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
                binding.direct_tx_packets = 0;
                binding.copy_tx_packets = 0;
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

struct LocalTunnelSourceHandle {
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

struct BindingPlan {
    status: BindingStatus,
    live: Arc<BindingLiveState>,
    xsk_map_fd: c_int,
    heartbeat_map_fd: c_int,
    session_map_fd: c_int,
    ring_entries: u32,
    bind_strategy: AfXdpBindStrategy,
    poll_mode: crate::PollMode,
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
    tunnel_endpoints: FastMap<u16, TunnelEndpoint>,
    tunnel_endpoint_by_ifindex: FastMap<i32, u16>,
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
    #[allow(dead_code)]
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
    tunnel_endpoint_id: u16,
}

#[derive(Clone, Copy, Debug)]
struct ConnectedRouteV6 {
    prefix: PrefixV6,
    ifindex: i32,
    tunnel_endpoint_id: u16,
}

#[derive(Clone, Debug)]
struct RouteEntryV4 {
    prefix: PrefixV4,
    ifindex: i32,
    tunnel_endpoint_id: u16,
    next_hop: Option<Ipv4Addr>,
    discard: bool,
    next_table: String,
}

#[derive(Clone, Debug)]
struct RouteEntryV6 {
    prefix: PrefixV6,
    ifindex: i32,
    tunnel_endpoint_id: u16,
    next_hop: Option<Ipv6Addr>,
    discard: bool,
    next_table: String,
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
pub struct NeighborEntry {
    pub mac: [u8; 6],
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

#[allow(dead_code)]
#[derive(Clone, Debug)]
struct TunnelEndpoint {
    id: u16,
    logical_ifindex: i32,
    redundancy_group: i32,
    mode: String,
    outer_family: i32,
    source: IpAddr,
    destination: IpAddr,
    key: u32,
    ttl: u8,
    transport_table: String,
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
    pub(crate) tunnel_endpoint_id: u16,
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
    #[allow(dead_code)]
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
    scratch_completed_offsets: Vec<u64>,
    scratch_post_recycles: Vec<(u32, u64)>,
    /// Flow cache fast-path: cross-binding in-place rewrites deferred
    /// until after the RX batch (borrow checker prevents mutable access
    /// to two bindings simultaneously inside the RX loop).
    scratch_cross_binding_tx: Vec<(usize, PreparedTxRequest)>,
    scratch_rst_teardowns: Vec<(SessionKey, NatDecision)>,
    in_flight_prepared_recycles: FastMap<u64, PreparedTxRecycle>,
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
    dbg_tx_ring_submitted: u64,  // descriptors inserted into TX ring
    dbg_tx_ring_full: u64,       // times TX ring insert returned 0
    dbg_completions_reaped: u64, // completion descriptors read
    dbg_sendto_calls: u64,       // number of sendto/wake calls
    dbg_sendto_err: u64,         // sendto returned error (non-EAGAIN/ENOBUFS)
    dbg_sendto_eagain: u64,      // sendto returned EAGAIN/EWOULDBLOCK
    dbg_sendto_enobufs: u64,     // sendto returned ENOBUFS (kernel TX drop)
    dbg_pending_overflow: u64,   // drops from bound_pending overflow
    dbg_tx_tcp_rst: u64,         // TCP RST packets transmitted
    // Ring diagnostics — raw values from xdpilone API
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
    flow_cache: FlowCache,
    flow_cache_session_touch: u64,
    /// Timestamp when this binding was created, used to enforce a grace
    /// period before writing heartbeat (NAPI needs time to bootstrap).
    bind_time_ns: u64,
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

#[derive(Clone, Debug)]
struct BindingIdentity {
    slot: u32,
    queue_id: u32,
    worker_id: u32,
    interface: Arc<str>,
    ifindex: i32,
}

#[derive(Clone, Debug, Default)]
pub(super) struct WorkerBindingLookup {
    by_if_queue: FastMap<(i32, u32), usize>,
    first_by_if: FastMap<i32, usize>,
    by_slot: FastMap<u32, usize>,
}

impl WorkerBindingLookup {
    fn from_bindings(bindings: &[BindingWorker]) -> Self {
        let mut lookup = Self::default();
        for (index, binding) in bindings.iter().enumerate() {
            lookup
                .by_if_queue
                .insert((binding.ifindex, binding.queue_id), index);
            lookup.first_by_if.entry(binding.ifindex).or_insert(index);
            lookup.by_slot.insert(binding.slot, index);
        }
        lookup
    }

    fn target_index(
        &self,
        current_index: usize,
        current_ifindex: i32,
        ingress_queue_id: u32,
        egress_ifindex: i32,
    ) -> Option<usize> {
        if current_ifindex == egress_ifindex {
            return Some(current_index);
        }
        self.by_if_queue
            .get(&(egress_ifindex, ingress_queue_id))
            .copied()
            .or_else(|| self.first_by_if.get(&egress_ifindex).copied())
    }

    fn slot_index(&self, slot: u32) -> Option<usize> {
        self.by_slot.get(&slot).copied()
    }
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
    #[allow(dead_code)]
    expected_ports: Option<(u16, u16)>,
    #[allow(dead_code)]
    expected_addr_family: u8,
    #[allow(dead_code)]
    expected_protocol: u8,
    flow_key: Option<SessionKey>,
}

struct PendingForwardRequest {
    target_ifindex: i32,
    target_binding_index: Option<usize>,
    ingress_queue_id: u32,
    source_offset: u64,
    desc: XdpDesc,
    source_frame: Option<Vec<u8>>,
    meta: UserspaceDpMeta,
    decision: SessionDecision,
    apply_nat_on_fabric: bool,
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
    recycle: PreparedTxRecycle,
    #[allow(dead_code)]
    expected_ports: Option<(u16, u16)>,
    #[allow(dead_code)]
    expected_addr_family: u8,
    #[allow(dead_code)]
    expected_protocol: u8,
    flow_key: Option<SessionKey>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PreparedTxRecycle {
    FreeTxFrame,
    FillOnSlot(u32),
}

#[derive(Debug)]
struct LocalTunnelTxPlan {
    tx_ifindex: i32,
    tx_request: TxRequest,
    session_entry: SyncedSessionEntry,
    reverse_session_entry: Option<SyncedSessionEntry>,
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
    UpsertLocal(SyncedSessionEntry),
    DeleteSynced(SessionKey),
    DemoteOwnerRG(i32),
    RefreshOwnerRGs(Vec<i32>),
}

impl BindingWorker {
    fn create(
        binding: &BindingStatus,
        ring_entries: u32,
        xsk_map_fd: c_int,
        heartbeat_map_fd: c_int,
        session_map_fd: c_int,
        live: Arc<BindingLiveState>,
        bind_strategy: AfXdpBindStrategy,
        poll_mode: crate::PollMode,
        worker_umem: WorkerUmem,
        frame_pool: &mut VecDeque<u64>,
        shared_umem: bool,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let total_frames = binding_frame_count(ring_entries).max(1);
        let driver_name = interface_driver_name(&binding.interface);
        let reserved_tx = reserved_tx_frames(ring_entries).min(total_frames);
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
        let (user, rx, tx, bind_mode, actual_bind_strategy, mut device) =
            open_binding_worker_rings(
                &worker_umem,
                &info,
                ring_entries,
                bind_strategy,
                driver_name.as_deref(),
                poll_mode,
            )
            .map_err(|err| format!("configure AF_XDP rings: {err}"))?;
        prime_fill_ring_offsets(&mut device, &initial_fill_frames)?;

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
            scratch_cross_binding_tx: Vec::with_capacity(RX_BATCH_SIZE as usize),
            scratch_rst_teardowns: Vec::with_capacity(16),
            in_flight_prepared_recycles: FastMap::default(),
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
            pending_direct_tx_packets: 0,
            pending_copy_tx_packets: 0,
            pending_in_place_tx_packets: 0,
            flow_cache: FlowCache::new(),
            flow_cache_session_touch: 0,
            bind_time_ns: {
                let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
                unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
                ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
            },
            xsk_rx_confirmed: false,
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

struct WorkerUmemInner {
    area: MmapArea,
    umem: Umem,
    total_frames: u32,
}

#[derive(Clone)]
struct WorkerUmem {
    inner: Rc<WorkerUmemInner>,
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
        Ok(Self {
            inner: Rc::new(WorkerUmemInner {
                area,
                umem,
                total_frames,
            }),
        })
    }

    fn area(&self) -> &MmapArea {
        &self.inner.area
    }

    fn umem(&self) -> &Umem {
        &self.inner.umem
    }

    fn total_frames(&self) -> u32 {
        self.inner.total_frames
    }

    fn shares_allocation_with(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.inner, &other.inner)
    }

    fn allocation_ptr(&self) -> *const WorkerUmemInner {
        Rc::as_ptr(&self.inner)
    }
}

struct WorkerUmemPool {
    umem: WorkerUmem,
    free_frames: VecDeque<u64>,
}

impl WorkerUmemPool {
    fn new(total_frames: u32) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let umem = WorkerUmem::new(total_frames.max(1))?;
        let mut free_frames = VecDeque::with_capacity(total_frames.max(1) as usize);
        for idx in 0..total_frames.max(1) {
            if let Some(frame) = umem.umem().frame(BufIdx(idx)) {
                free_frames.push_back(frame.offset);
            }
        }
        Ok(Self { umem, free_frames })
    }
}

#[derive(Default)]
struct DebugPollCounters {
    rx: u64,
    #[allow(dead_code)]
    tx: u64,
    forward: u64,
    #[allow(dead_code)]
    local: u64,
    #[allow(dead_code)]
    session_hit: u64,
    #[allow(dead_code)]
    session_miss: u64,
    #[allow(dead_code)]
    session_create: u64,
    #[allow(dead_code)]
    no_route: u64,
    #[allow(dead_code)]
    missing_neigh: u64,
    #[allow(dead_code)]
    policy_deny: u64,
    #[allow(dead_code)]
    ha_inactive: u64,
    #[allow(dead_code)]
    no_egress_binding: u64,
    #[allow(dead_code)]
    build_fail: u64,
    #[allow(dead_code)]
    tx_err: u64,
    #[allow(dead_code)]
    metadata_err: u64,
    disposition_other: u64,
    enqueue_ok: u64,      // forwards successfully enqueued to target binding TX
    enqueue_inplace: u64, // in-place TX rewrites (same UMEM)
    enqueue_direct: u64,  // direct-to-UMEM TX (cross binding)
    enqueue_copy: u64,    // Vec copy-path TX
    // Direction-specific counters
    rx_from_trust: u64,    // packets received from trust-side interfaces
    rx_from_wan: u64,      // packets received from wan-side interfaces
    fwd_trust_to_wan: u64, // forwards from trust to wan
    fwd_wan_to_trust: u64, // forwards from wan to trust
    nat_applied_snat: u64, // SNAT rewrites applied
    nat_applied_dnat: u64, // DNAT (reverse-SNAT) rewrites applied
    nat_applied_none: u64, // no NAT rewrite
    #[allow(dead_code)]
    frame_build_none: u64, // build_forwarded_frame returned None (why?)
    rx_tcp_rst: u64,       // TCP RST flags seen in RX frames
    #[allow(dead_code)]
    tx_tcp_rst: u64, // TCP RST flags seen in TX frames (forwarded)
    rx_bytes_total: u64,   // total RX bytes (for avg frame size calculation)
    tx_bytes_total: u64,   // total TX bytes submitted to ring
    rx_oversized: u64,     // RX frames where desc.len > 1514
    rx_max_frame: u32,     // max desc.len seen in RX
    tx_max_frame: u32,     // max frame len submitted to TX
    seg_needed_but_none: u64, // oversized frames where segmentation returned None
    wan_return_hits: u64,  // session hits for WAN return traffic (first N logged)
    #[allow(dead_code)]
    wan_return_misses: u64, // session misses for WAN return traffic
    rx_tcp_fin: u64,       // TCP FIN flags seen in RX
    rx_tcp_synack: u64,    // TCP SYN+ACK seen in RX
    rx_tcp_zero_window: u64, // TCP zero-window seen in RX (forwarded frames)
    fwd_tcp_fin: u64,      // TCP FIN in forwarded frames
    fwd_tcp_rst: u64,      // TCP RST in forwarded frames
    fwd_tcp_zero_window: u64, // zero-window in forwarded frames
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
    dbg: &mut DebugPollCounters,
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
            if let Some(pf) = unsafe { &*area }.slice(desc.addr as usize, 64.min(desc.len as usize)) {
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
                        if ethertype == 0x0806
                            && raw_frame.len() >= arp_start + 28
                        {
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
                                ).unwrap_or(meta.ingress_ifindex as i32);
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
                                    let target_ip =
                                        IpAddr::V6(Ipv6Addr::from(target_bytes));
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
                                            if let Ok(mut neighbors) =
                                                dynamic_neighbors.lock()
                                            {
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
                                            ).unwrap_or(meta.ingress_ifindex as i32);
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
                    let meta = native_gre_packet
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
                    // For established TCP (ACK set, no SYN/FIN/RST), check
                    // the per-binding flow cache before the expensive session
                    // lookup + policy + NAT + FIB path.
                    if meta.protocol == PROTO_TCP
                        && (meta.tcp_flags & 0x17) == 0x10  // ACK only, no SYN/FIN/RST
                        && let Some(flow) = flow.as_ref()
                    {
                        if let Some(cached) = binding.flow_cache.lookup(
                            &flow.forward_key,
                            meta.ingress_ifindex as i32,
                            validation.config_generation,
                            validation.fib_generation,
                        ) {
                            let cached_decision = cached.decision;
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
                                let target_ifindex = if cached_decision.resolution.tx_ifindex > 0 {
                                    cached_decision.resolution.tx_ifindex
                                } else {
                                    resolve_tx_binding_ifindex(forwarding, cached_decision.resolution.egress_ifindex)
                                };
                                let target_bi = binding_lookup.target_index(
                                    binding_index,
                                    ident.ifindex,
                                    ident.queue_id,
                                    target_ifindex,
                                );
                                // Check if target is same binding (hairpin) or same-UMEM.
                                // For simplicity, only do in-place fast path when target == self.
                                let is_self_target = target_bi == Some(binding_index);
                                if is_self_target && owned_packet_frame.is_none() {
                                    let expected_ports = authoritative_forward_ports(packet_frame, meta, Some(flow));
                                    let ingress_slot = binding.slot;
                                    let flow_key = flow.forward_key.clone();
                                    if let Some(frame_len) = rewrite_forwarded_frame_in_place(
                                        unsafe { &*area },
                                        desc,
                                        meta,
                                        &cached_decision,
                                        expected_ports,
                                    ) {
                                        binding.pending_tx_prepared.push_back(PreparedTxRequest {
                                            offset: desc.addr,
                                            len: frame_len,
                                            recycle: PreparedTxRecycle::FillOnSlot(ingress_slot),
                                            expected_ports,
                                            expected_addr_family: meta.addr_family,
                                            expected_protocol: meta.protocol,
                                            flow_key: Some(flow_key),
                                        });
                                        binding.pending_in_place_tx_packets += 1;
                                        dbg.forward += 1;
                                        dbg.tx += 1;
                                        recycle_now = false;
                                    }
                                }
                                // Fallback: use PendingForwardRequest path for cross-binding or failure.
                                if recycle_now {
                                    if let Some(mut request) = build_live_forward_request_from_frame(
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
                                    ) {
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
                                        if sessions.install_with_protocol(
                                            flow.forward_key.clone(),
                                            fabric_return_decision,
                                            fabric_return_metadata,
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
                            if resolution.disposition == ForwardingDisposition::LocalDelivery {
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
                                    synced: true,
                                    nat64_reverse: None,
                                };
                                if let Some(previous) =
                                    sessions.take_synced_local(&flow.forward_key)
                                {
                                    delete_session_map_entry_for_removed_session(
                                        binding.session_map_fd,
                                        &flow.forward_key,
                                        previous.decision,
                                        &previous.metadata,
                                    );
                                }
                                if sessions.install_with_protocol(
                                    flow.forward_key.clone(),
                                    decision,
                                    local_metadata.clone(),
                                    now_ns,
                                    meta.protocol,
                                    meta.tcp_flags,
                                ) {
                                    let local_entry = SyncedSessionEntry {
                                        key: flow.forward_key.clone(),
                                        decision,
                                        metadata: local_metadata,
                                        protocol: meta.protocol,
                                        tcp_flags: meta.tcp_flags,
                                    };
                                    publish_shared_session(
                                        shared_sessions,
                                        shared_nat_sessions,
                                        shared_forward_wire_sessions,
                                        &local_entry,
                                    );
                                    let _ = publish_session_map_entry_for_session(
                                        binding.session_map_fd,
                                        &flow.forward_key,
                                        decision,
                                        &local_entry.metadata,
                                    );
                                    counters.session_creates += 1;
                                    dbg.session_create += 1;
                                }
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
                                        let fabric_ingress = ingress_is_fabric(
                                            forwarding,
                                            meta.ingress_ifindex as i32,
                                        );
                                        let forward_metadata = SessionMetadata {
                                            ingress_zone: from_zone_arc.clone(),
                                            egress_zone: to_zone_arc.clone(),
                                            owner_rg_id,
                                            fabric_ingress,
                                            is_reverse: false,
                                            synced: false,
                                            nat64_reverse: nat64_info,
                                        };
                                        if track_in_userspace
                                            && sessions.install_with_protocol(
                                                flow.forward_key.clone(),
                                                decision,
                                                forward_metadata.clone(),
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
                                            synced: false,
                                            nat64_reverse: nat64_info,
                                        };
                                        if track_in_userspace
                                            && sessions.install_with_protocol(
                                                reverse_key.clone(),
                                                reverse_decision,
                                                reverse_metadata.clone(),
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
                            binding.scratch_rst_teardowns.push((flow.forward_key.clone(), decision.nat));
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
                            // TCP flows. Skip NAT64/NPTv6 (non-cacheable).
                            if meta.protocol == PROTO_TCP
                                && !decision.nat.nat64
                                && !decision.nat.nptv6
                                && decision.resolution.disposition == ForwardingDisposition::ForwardCandidate
                                && let Some(flow) = flow.as_ref()
                            {
                                let ingress_zone = session_ingress_zone
                                    .as_ref()
                                    .cloned()
                                    .unwrap_or_else(|| Arc::from(""));
                                binding.flow_cache.insert(FlowCacheEntry {
                                    key: flow.forward_key.clone(),
                                    ingress_ifindex: meta.ingress_ifindex as i32,
                                    descriptor: RewriteDescriptor {
                                        dst_mac: decision.resolution.neighbor_mac.unwrap_or([0; 6]),
                                        src_mac: decision.resolution.src_mac.unwrap_or([0; 6]),
                                        tx_vlan_id: decision.resolution.tx_vlan_id,
                                        ether_type: if meta.addr_family as i32 == libc::AF_INET { 0x0800 } else { 0x86dd },
                                        rewrite_src_ip: decision.nat.rewrite_src,
                                        rewrite_dst_ip: decision.nat.rewrite_dst,
                                        rewrite_src_port: decision.nat.rewrite_src_port,
                                        rewrite_dst_port: decision.nat.rewrite_dst_port,
                                        ip_csum_delta: 0,
                                        l4_csum_delta: 0,
                                        egress_ifindex: decision.resolution.egress_ifindex,
                                        tx_ifindex: decision.resolution.tx_ifindex,
                                        target_binding_index: None,
                                        config_generation: validation.config_generation,
                                        fib_generation: validation.fib_generation,
                                        owner_rg_id: 0,
                                        nat64: false,
                                        nptv6: false,
                                        apply_nat_on_fabric,
                                    },
                                    decision,
                                    metadata: SessionMetadata {
                                        ingress_zone,
                                        egress_zone: Arc::from(""),
                                        owner_rg_id: 0,
                                        fabric_ingress: false,
                                        is_reverse: false,
                                        synced: false,
                                        nat64_reverse: None,
                                    },
                                });
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
                            ForwardingDisposition::LocalDelivery => dbg.local += 1,
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
                                // Send ARP/NDP solicitation via RAW socket (not XSK)
                                // so the reply goes through the kernel's normal RX
                                // path (cpumap_or_pass), bypassing XSK fill ring issues.
                                // Also reinject original packet to slow-path for kernel
                                // to forward once the neighbor is resolved.
                                if let Some(next_hop) = decision.resolution.next_hop {
                                    let egress_ifindex = decision.resolution.egress_ifindex;
                                    if let IpAddr::V4(target_v4) = next_hop {
                                        if let Some(egress) = forwarding.egress.get(&egress_ifindex) {
                                            if let Some(src_v4) = egress.primary_v4 {
                                                let arp = build_arp_request(egress.src_mac, src_v4, target_v4);
                                                send_raw_frame(egress_ifindex, &arp);
                                            }
                                        }
                                    } else if let IpAddr::V6(target_v6) = next_hop {
                                        if let Some(egress) = forwarding.egress.get(&egress_ifindex) {
                                            if let Some(src_v6) = egress.primary_v6 {
                                                let ns = build_ndp_neighbor_solicitation(egress.src_mac, src_v6, target_v6);
                                                send_raw_frame(egress_ifindex, &ns);
                                            }
                                        }
                                    }
                                }
                                // Always reinject to slow-path — kernel forwards
                                // the packet once ARP/NDP resolves via the raw
                                // socket solicitation above.
                                maybe_reinject_slow_path_from_frame(
                                    &ident,
                                    &binding.live,
                                    slow_path,
                                    local_tunnel_deliveries,
                                    packet_frame,
                                    meta,
                                    decision,
                                    recent_exceptions,
                                    "missing_neighbor_slow_path",
                                );
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
    counters.flush(&binding.live);
    update_binding_debug_state(binding);
    did_work
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
    let target_binding_index = binding_lookup.target_index(
        current_binding_index,
        ingress_ident.ifindex,
        ingress_ident.queue_id,
        target_ifindex,
    );
    // Prefer session flow ports (set by conntrack, immune to DMA races),
    // then live frame ports (lazy — only parsed if session ports unavailable),
    // then metadata as last resort.
    let expected_ports = authoritative_forward_ports(frame, meta, flow);
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
    deltas: &[SessionDelta],
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
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
            fabric_ingress: delta.metadata.fabric_ingress,
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
            remove_shared_session(
                shared_sessions,
                shared_nat_sessions,
                shared_forward_wire_sessions,
                &delta.key,
            );
            let reverse_key = reverse_session_key(&delta.key, delta.decision.nat);
            delete_live_session_entry(session_map_fd, &reverse_key, delta.decision.nat, true);
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
    validation: ValidationState,
    forwarding: Arc<ForwardingState>,
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
    poll_mode: crate::PollMode,
) {
    pin_current_thread(worker_id);
    let ha_startup_grace_until_secs = (monotonic_nanos() / 1_000_000_000)
        .saturating_add(TUNNEL_HA_STARTUP_GRACE_SECS);
    let mut sessions = SessionTable::new();
    let mut screen_state = ScreenState::new();
    screen_state.update_profiles(forwarding.screen_profiles.clone());
    sessions.set_timeouts(forwarding.session_timeouts);
    let mut bindings = Vec::with_capacity(binding_plans.len());
    for plan in binding_plans {
        let total_frames = binding_frame_count(plan.ring_entries).max(1);
        let mut private_pool =
            WorkerUmemPool::new(total_frames).map_err(|err| format!("create binding umem: {err}"));
        let binding = match private_pool.as_mut() {
            Ok(pool) => BindingWorker::create(
                &plan.status,
                plan.ring_entries,
                plan.xsk_map_fd,
                plan.heartbeat_map_fd,
                plan.session_map_fd,
                plan.live.clone(),
                plan.bind_strategy,
                plan.poll_mode,
                pool.umem.clone(),
                &mut pool.free_frames,
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
    while !stop.load(Ordering::Relaxed) {
        let session_map_fd = bindings
            .first()
            .map(|binding| binding.session_map_fd)
            .unwrap_or(-1);
        let loop_now_ns = monotonic_nanos();
        let loop_now_secs = loop_now_ns / 1_000_000_000;
        let ha_runtime = ha_state.load();
        apply_worker_commands(
            &commands,
            &mut sessions,
            session_map_fd,
            &forwarding,
            ha_runtime.as_ref(),
            &dynamic_neighbors,
        );
        heartbeat.store(loop_now_ns, Ordering::Relaxed);
        let expired_entries = sessions.expire_stale_entries(loop_now_ns);
        let expired = expired_entries.len() as u64;
        for expired_entry in expired_entries {
            delete_session_map_entry_for_removed_session(
                session_map_fd,
                &expired_entry.key,
                expired_entry.decision,
                &expired_entry.metadata,
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
                &mut dbg_poll,
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
                    &shared_forward_wire_sessions,
                    &recent_session_deltas,
                    &peer_worker_commands,
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
                    let rx_avail = b.rx.available();
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
                    // Ring diagnostics from xdpilone API
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
                            let rx_a = sb.rx.available();
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
                        sessions.iter(|key, decision, metadata| {
                            if count < 20 {
                                use std::fmt::Write;
                                let _ = write!(
                                    sess_dump,
                                    "\n  SESS: {}:{} -> {}:{} proto={} nat=({:?},{:?}) is_rev={}",
                                    key.src_ip,
                                    key.src_port,
                                    key.dst_ip,
                                    key.dst_port,
                                    key.protocol,
                                    decision.nat.rewrite_src,
                                    decision.nat.rewrite_dst,
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

fn local_tunnel_source_loop(
    tunnel_name: String,
    tunnel_endpoint_id: u16,
    forwarding: ForwardingState,
    ha_state: Arc<ArcSwap<BTreeMap<i32, HAGroupRuntime>>>,
    dynamic_neighbors: Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
    live: BTreeMap<u32, Arc<BindingLiveState>>,
    identities: BTreeMap<u32, BindingIdentity>,
    shared_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>>,
    delivery_rx: Receiver<Vec<u8>>,
    recent_exceptions: Arc<Mutex<VecDeque<ExceptionStatus>>>,
    stop: Arc<AtomicBool>,
) {
    let mut tun = match open_tun(&tunnel_name) {
        Ok((file, _actual_name)) => file,
        Err(err) => {
            record_local_tunnel_exception(&recent_exceptions, &tunnel_name, err);
            return;
        }
    };
    if let Err(err) = set_fd_nonblocking(tun.as_raw_fd()) {
        record_local_tunnel_exception(&recent_exceptions, &tunnel_name, err);
        return;
    }

    let mut packet = vec![0u8; 65_536];
    let mut next_slot = 0usize;
    let mut local_sessions = FastMap::<SessionKey, u64>::default();
    while !stop.load(Ordering::Relaxed) {
        loop {
            match delivery_rx.try_recv() {
                Ok(packet) => {
                    if let Err(err) = tun.write_all(&packet) {
                        record_local_tunnel_exception(
                            &recent_exceptions,
                            &tunnel_name,
                            format!("write_local_tunnel_delivery:{err}"),
                        );
                        break;
                    }
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => break,
            }
        }
        match tun.read(&mut packet) {
            Ok(0) => thread::sleep(Duration::from_millis(1)),
            Ok(len) => {
                let packet = &packet[..len];
                match build_local_origin_tunnel_tx_request(
                    packet,
                    tunnel_endpoint_id,
                    &forwarding,
                    &ha_state,
                    &dynamic_neighbors,
                ) {
                    Ok(plan) => {
                        maybe_enqueue_local_tunnel_session(
                            &shared_sessions,
                            &shared_nat_sessions,
                            &shared_forward_wire_sessions,
                            &worker_commands,
                            &mut local_sessions,
                            &plan,
                        );
                        if let Some(target_live) =
                            select_live_binding_for_ifindex(
                                &identities,
                                &live,
                                plan.tx_ifindex,
                                next_slot,
                            )
                        {
                            next_slot = next_slot.wrapping_add(1);
                            if let Err(err) = target_live.enqueue_tx(plan.tx_request) {
                                record_local_tunnel_exception(
                                    &recent_exceptions,
                                    &tunnel_name,
                                    format!("enqueue_local_tunnel_tx:{err}"),
                                );
                            }
                        } else {
                            record_local_tunnel_exception(
                                &recent_exceptions,
                                &tunnel_name,
                                format!("no_live_binding_for_tx_ifindex:{}", plan.tx_ifindex),
                            );
                        }
                    }
                    Err(err) => {
                        #[cfg(not(feature = "debug-log"))]
                        let _ = &err;
                        debug_log!(
                            "LOCAL_TUNNEL[{}]: drop endpoint={} reason={}",
                            tunnel_name,
                            tunnel_endpoint_id,
                            err
                        );
                    }
                }
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(1));
            }
            Err(err) => {
                record_local_tunnel_exception(
                    &recent_exceptions,
                    &tunnel_name,
                    format!("read_local_tunnel:{err}"),
                );
                thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

fn build_local_origin_tunnel_tx_request(
    packet: &[u8],
    tunnel_endpoint_id: u16,
    forwarding: &ForwardingState,
    ha_state: &Arc<ArcSwap<BTreeMap<i32, HAGroupRuntime>>>,
    dynamic_neighbors: &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
) -> Result<LocalTunnelTxPlan, String> {
    let mut meta =
        local_origin_packet_meta(packet).ok_or_else(|| "unsupported_local_origin_packet".to_string())?;
    let inner_frame = wrap_raw_ip_packet_for_tunnel(packet, meta.addr_family);
    meta.l3_offset = 14;
    meta.l4_offset = meta.l4_offset.saturating_add(14);
    meta.payload_offset = meta.payload_offset.saturating_add(14);
    let resolution = enforce_ha_resolution_at(
        forwarding,
        ha_state,
        monotonic_nanos() / 1_000_000_000,
        resolve_tunnel_forwarding_resolution(
            forwarding,
            Some(dynamic_neighbors),
            tunnel_endpoint_id,
            0,
        ),
    );
    if resolution.disposition != ForwardingDisposition::ForwardCandidate {
        return Err(format!(
            "local_tunnel_resolution:{}",
            resolution.status(None).disposition
        ));
    }
    let decision = SessionDecision {
        resolution,
        nat: NatDecision::default(),
    };
    let flow = parse_session_flow_from_bytes(&inner_frame, meta)
        .ok_or_else(|| "parse_local_origin_session_flow_failed".to_string())?;
    let zone = forwarding
        .egress
        .get(&decision.resolution.egress_ifindex)
        .map(|iface| Arc::<str>::from(iface.zone.as_str()))
        .unwrap_or_else(|| Arc::<str>::from(""));
    let bytes = encapsulate_native_gre_frame(&inner_frame, meta, &decision, forwarding)
        .ok_or_else(|| "encapsulate_native_gre_frame_failed".to_string())?;
    let session_entry = SyncedSessionEntry {
        key: flow.forward_key,
        decision,
        metadata: SessionMetadata {
            ingress_zone: zone.clone(),
            egress_zone: zone,
            owner_rg_id: owner_rg_for_resolution(forwarding, decision.resolution),
            fabric_ingress: false,
            is_reverse: false,
            synced: true,
            nat64_reverse: None,
        },
        protocol: meta.protocol,
        tcp_flags: if meta.protocol == PROTO_TCP {
            extract_tcp_flags_and_window(&inner_frame)
                .map(|(flags, _)| flags)
                .unwrap_or_default()
        } else {
            0
        },
    };
    let reverse_session_entry = synthesized_synced_reverse_entry(
        forwarding,
        ha_state.load().as_ref(),
        dynamic_neighbors,
        &session_entry,
        monotonic_nanos() / 1_000_000_000,
    );
    Ok(LocalTunnelTxPlan {
        tx_ifindex: decision.resolution.tx_ifindex,
        tx_request: TxRequest {
            bytes,
            expected_ports: None,
            expected_addr_family: 0,
            expected_protocol: 0,
            flow_key: None,
        },
        session_entry,
        reverse_session_entry,
    })
}

fn local_origin_packet_meta(packet: &[u8]) -> Option<UserspaceDpMeta> {
    let version = packet.first()? >> 4;
    let addr_family = match version {
        4 => libc::AF_INET as u8,
        6 => libc::AF_INET6 as u8,
        _ => return None,
    };
    let (l4_offset, protocol) = packet_rel_l4_offset_and_protocol(packet, addr_family)?;
    Some(UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l4_offset: l4_offset.min(u16::MAX as usize) as u16,
        payload_offset: l4_offset.min(u16::MAX as usize) as u16,
        pkt_len: packet.len().min(u16::MAX as usize) as u16,
        addr_family,
        protocol,
        ..UserspaceDpMeta::default()
    })
}

fn wrap_raw_ip_packet_for_tunnel(packet: &[u8], addr_family: u8) -> Vec<u8> {
    let mut frame = vec![0u8; 14 + packet.len()];
    frame[12..14].copy_from_slice(if addr_family as i32 == libc::AF_INET {
        &[0x08, 0x00]
    } else {
        &[0x86, 0xdd]
    });
    frame[14..].copy_from_slice(packet);
    frame
}

fn maybe_enqueue_local_tunnel_session(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    local_sessions: &mut FastMap<SessionKey, u64>,
    plan: &LocalTunnelTxPlan,
) {
    let now_ns = monotonic_nanos();
    let entry = &plan.session_entry;
    let refresh_after_ns = if matches!(entry.protocol, PROTO_TCP) {
        5_000_000_000
    } else {
        1_000_000_000
    };
    if matches!(
        local_sessions.get(&entry.key),
        Some(last) if now_ns.saturating_sub(*last) < refresh_after_ns
    ) {
        return;
    }
    local_sessions.insert(entry.key.clone(), now_ns);
    publish_shared_session(
        shared_sessions,
        shared_nat_sessions,
        shared_forward_wire_sessions,
        entry,
    );
    if let Some(reverse) = &plan.reverse_session_entry {
        publish_shared_session(
            shared_sessions,
            shared_nat_sessions,
            shared_forward_wire_sessions,
            reverse,
        );
    }
    for pending in worker_commands {
        if let Ok(mut pending) = pending.lock() {
            pending.push_back(WorkerCommand::UpsertLocal(entry.clone()));
            if let Some(reverse) = &plan.reverse_session_entry {
                pending.push_back(WorkerCommand::UpsertLocal(reverse.clone()));
            }
        }
    }
    wait_for_local_tunnel_session_install(worker_commands, now_ns + 1_000_000);
}

fn wait_for_local_tunnel_session_install(
    worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    deadline_ns: u64,
) {
    while monotonic_nanos() < deadline_ns {
        let all_drained = worker_commands
            .iter()
            .all(|pending| pending.lock().map(|pending| pending.is_empty()).unwrap_or(false));
        if all_drained {
            break;
        }
        std::hint::spin_loop();
        thread::sleep(Duration::from_micros(50));
    }
}

fn select_live_binding_for_ifindex(
    identities: &BTreeMap<u32, BindingIdentity>,
    live: &BTreeMap<u32, Arc<BindingLiveState>>,
    tx_ifindex: i32,
    next_slot: usize,
) -> Option<Arc<BindingLiveState>> {
    let candidates = identities
        .values()
        .filter_map(|identity| {
            if identity.ifindex != tx_ifindex {
                return None;
            }
            let live = live.get(&identity.slot)?;
            live.bound.load(Ordering::Relaxed).then_some(live.clone())
        })
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        return None;
    }
    Some(candidates[next_slot % candidates.len()].clone())
}

fn set_fd_nonblocking(fd: c_int) -> Result<(), String> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(format!(
            "fcntl(F_GETFL) failed: {}",
            io::Error::last_os_error()
        ));
    }
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        return Err(format!(
            "fcntl(F_SETFL,O_NONBLOCK) failed: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn record_local_tunnel_exception(
    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
    tunnel_name: &str,
    reason: String,
) {
    if let Ok(mut recent) = recent_exceptions.lock() {
        push_recent_exception(
            &mut recent,
            ExceptionStatus {
                timestamp: Utc::now(),
                interface: tunnel_name.to_string(),
                reason,
                ..ExceptionStatus::default()
            },
        );
    }
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

/// Send a raw Ethernet frame via AF_PACKET on the given interface.
/// Used for ARP/NDP solicitations that must bypass XSK (because the
/// XSK fill ring may not be bootstrapped on the egress interface).
fn send_raw_frame(ifindex: i32, frame: &[u8]) {
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return;
    }
    let mut addr: libc::sockaddr_ll = unsafe { core::mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as u16;
    addr.sll_ifindex = ifindex;
    addr.sll_halen = 6;
    if frame.len() >= 6 {
        addr.sll_addr[..6].copy_from_slice(&frame[..6]);
    }
    unsafe {
        libc::sendto(
            fd,
            frame.as_ptr() as *const libc::c_void,
            frame.len(),
            libc::MSG_DONTWAIT,
            &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
            core::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        );
        libc::close(fd);
    }
}

/// Add a neighbor entry to the kernel's neighbor table via raw netlink.
/// This ensures the kernel can forward IPv6 (and IPv4) traffic to hosts
/// whose ARP/NDP replies were captured by XSK instead of reaching the kernel.
fn add_kernel_neighbor(ifindex: i32, ip: IpAddr, mac: [u8; 6]) {
    // RTM_NEWNEIGH = 28, NLM_F_REQUEST=1, NLM_F_CREATE=0x400, NLM_F_REPLACE=0x100
    const RTM_NEWNEIGH: u16 = 28;
    const NLM_F_REQUEST: u16 = 1;
    const NLM_F_CREATE: u16 = 0x400;
    const NLM_F_REPLACE: u16 = 0x100;
    const NDA_DST: u16 = 1;
    const NDA_LLADDR: u16 = 2;
    const NUD_REACHABLE: u16 = 0x02;
    let (family, ip_bytes): (u8, Vec<u8>) = match ip {
        IpAddr::V4(v4) => (libc::AF_INET as u8, v4.octets().to_vec()),
        IpAddr::V6(v6) => (libc::AF_INET6 as u8, v6.octets().to_vec()),
    };
    let ip_attr_len = 4 + ip_bytes.len(); // NLA header (4) + payload
    let ip_attr_padded = (ip_attr_len + 3) & !3;
    let mac_attr_len = 4 + 6;
    let mac_attr_padded = (mac_attr_len + 3) & !3;
    // ndmsg: family(1) + pad1(1) + pad2(2) + ifindex(4) + state(2) + flags(1) + type(1) = 12
    let ndmsg_len = 12;
    let total_len = 16 + ndmsg_len + ip_attr_padded + mac_attr_padded; // nlmsghdr(16) + ndmsg + attrs
    let mut buf = vec![0u8; total_len];
    // nlmsghdr
    buf[0..4].copy_from_slice(&(total_len as u32).to_ne_bytes());
    buf[4..6].copy_from_slice(&RTM_NEWNEIGH.to_ne_bytes());
    buf[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE).to_ne_bytes());
    buf[8..12].copy_from_slice(&1u32.to_ne_bytes()); // seq
    buf[12..16].copy_from_slice(&0u32.to_ne_bytes()); // pid
    // ndmsg
    buf[16] = family;
    buf[20..24].copy_from_slice(&ifindex.to_ne_bytes());
    buf[24..26].copy_from_slice(&NUD_REACHABLE.to_ne_bytes());
    // NDA_DST attribute
    let off = 16 + ndmsg_len;
    buf[off..off + 2].copy_from_slice(&(ip_attr_len as u16).to_ne_bytes());
    buf[off + 2..off + 4].copy_from_slice(&NDA_DST.to_ne_bytes());
    buf[off + 4..off + 4 + ip_bytes.len()].copy_from_slice(&ip_bytes);
    // NDA_LLADDR attribute
    let off2 = off + ip_attr_padded;
    buf[off2..off2 + 2].copy_from_slice(&(mac_attr_len as u16).to_ne_bytes());
    buf[off2 + 2..off2 + 4].copy_from_slice(&NDA_LLADDR.to_ne_bytes());
    buf[off2 + 4..off2 + 10].copy_from_slice(&mac);
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return;
    }
    let mut sa: libc::sockaddr_nl = unsafe { core::mem::zeroed() };
    sa.nl_family = libc::AF_NETLINK as u16;
    unsafe {
        libc::sendto(
            fd,
            buf.as_ptr() as *const libc::c_void,
            buf.len(),
            libc::MSG_DONTWAIT,
            &sa as *const libc::sockaddr_nl as *const libc::sockaddr,
            core::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        );
        libc::close(fd);
    }
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

    for endpoint in &snapshot.tunnel_endpoints {
        if endpoint.id == 0 || endpoint.ifindex <= 0 {
            continue;
        }
        let Ok(source) = endpoint.source.parse::<IpAddr>() else {
            continue;
        };
        let Ok(destination) = endpoint.destination.parse::<IpAddr>() else {
            continue;
        };
        let outer_family = match (endpoint.outer_family.as_str(), destination) {
            ("inet6", _) => libc::AF_INET6,
            ("inet", _) => libc::AF_INET,
            (_, IpAddr::V6(_)) => libc::AF_INET6,
            _ => libc::AF_INET,
        };
        let transport_table =
            canonical_route_table(&endpoint.transport_table, outer_family == libc::AF_INET6);
        state.tunnel_endpoints.insert(
            endpoint.id,
            TunnelEndpoint {
                id: endpoint.id,
                logical_ifindex: endpoint.ifindex,
                redundancy_group: endpoint.redundancy_group,
                mode: endpoint.mode.clone(),
                outer_family,
                source,
                destination,
                key: endpoint.key,
                ttl: endpoint.ttl.max(0) as u8,
                transport_table,
            },
        );
        state
            .tunnel_endpoint_by_ifindex
            .insert(endpoint.ifindex, endpoint.id);
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
        let tunnel_endpoint_id = state
            .tunnel_endpoint_by_ifindex
            .get(&iface.ifindex)
            .copied()
            .unwrap_or(0);
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
                        tunnel_endpoint_id,
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
                        tunnel_endpoint_id,
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
            .or_else(|| iface.tunnel.then_some([0; 6]))
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
            let (next_hop, ifindex, tunnel_endpoint_id) =
                resolve_route_target_v4(route, &name_to_ifindex, &linux_to_ifindex, &state);
            let table = canonical_route_table(&route.table, false);
            state
                .routes_v4
                .entry(table)
                .or_default()
                .push(RouteEntryV4 {
                    prefix: PrefixV4::from_net(prefix),
                    ifindex,
                    tunnel_endpoint_id,
                    next_hop,
                    discard: route.discard,
                    next_table: route.next_table.clone(),
                });
            continue;
        }
        if let Ok(prefix) = route.destination.parse::<Ipv6Net>() {
            let (next_hop, ifindex, tunnel_endpoint_id) =
                resolve_route_target_v6(route, &name_to_ifindex, &linux_to_ifindex, &state);
            let table = canonical_route_table(&route.table, true);
            state
                .routes_v6
                .entry(table)
                .or_default()
                .push(RouteEntryV6 {
                    prefix: PrefixV6::from_net(prefix),
                    ifindex,
                    tunnel_endpoint_id,
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
        let local_mac = parse_mac(&fabric.local_mac)
            .or_else(|| mac_by_ifindex.get(&fabric.parent_ifindex).copied());
        let Some(local_mac) = local_mac else {
            continue;
        };
        let peer_mac = parse_mac(&fabric.peer_mac).or_else(|| {
            state
                .neighbors
                .get(&(fabric.overlay_ifindex, peer_addr))
                .or_else(|| state.neighbors.get(&(fabric.parent_ifindex, peer_addr)))
                .map(|entry| entry.mac)
        });
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
    state.filter_state = crate::filter::parse_filter_state(
        &snapshot.filters,
        &snapshot.policers,
        &snapshot.interfaces,
        &snapshot.flow.lo0_filter_input_v4,
        &snapshot.flow.lo0_filter_input_v6,
    );
    // Build flow export config from snapshot
    state.flow_export_config = snapshot.flow_export.as_ref().and_then(|fe| {
        let addr = format!("{}:{}", fe.collector_address, fe.collector_port);
        addr.parse::<std::net::SocketAddr>().ok().map(|collector| {
            crate::flowexport::FlowExportConfig {
                collector,
                sampling_rate: fe.sampling_rate,
                active_timeout_secs: fe.active_timeout as u64,
                inactive_timeout_secs: fe.inactive_timeout as u64,
            }
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
    #[cfg(feature = "debug-log")]
    {
        debug_log!("FWD_STATE: ifindex_to_zone={:?}", state.ifindex_to_zone);
        debug_log!(
            "FWD_STATE: egress keys={:?}",
            state.egress.keys().collect::<Vec<_>>()
        );
        for (ifidx, eg) in &state.egress {
            debug_log!(
                "FWD_STATE: egress[{}] bind={} zone={} vlan={} mtu={}",
                ifidx,
                eg.bind_ifindex,
                eg.zone,
                eg.vlan_id,
                eg.mtu,
            );
        }
        debug_log!(
            "FWD_STATE: policy default={:?} rules={}",
            state.policy.default_action,
            state.policy.rules.len(),
        );
        for (i, rule) in state.policy.rules.iter().enumerate() {
            debug_log!(
                "FWD_STATE: policy[{}] {}->{}  action={:?} src_v4={} dst_v4={} apps={}",
                i,
                rule.from_zone,
                rule.to_zone,
                rule.action,
                rule.source_v4.len(),
                rule.destination_v4.len(),
                rule.applications.len(),
            );
        }
        debug_log!(
            "FWD_STATE: local_v4={:?} interface_nat_v4={:?}",
            state.local_v4,
            state.interface_nat_v4,
        );
        debug_log!(
            "FWD_STATE: snat_rules={} static_nat={} dnat_table={} nptv6={} connected_v4={} routes_v4={}",
            state.source_nat_rules.len(),
            if state.static_nat.is_empty() {
                0
            } else {
                state.static_nat.external_ips().count()
            },
            if state.dnat_table.is_empty() {
                0
            } else {
                state.dnat_table.destination_ips().count()
            },
            if state.nptv6.is_empty() {
                0
            } else {
                state.nptv6.external_prefixes().len()
            },
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

    let v4_addrs: Vec<String> = state
        .interface_nat_v4
        .keys()
        .map(|ip| ip.to_string())
        .collect();
    let v6_addrs: Vec<String> = state
        .interface_nat_v6
        .keys()
        .map(|ip| ip.to_string())
        .collect();

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
) -> (Option<Ipv4Addr>, i32, u16) {
    if route.discard || !route.next_table.is_empty() {
        return (None, 0, 0);
    }
    let Some((next_hop, interface)) = route
        .next_hops
        .first()
        .map(|nh| parse_route_next_hop(nh.as_str()))
    else {
        return (None, 0, 0);
    };
    let target = interface
        .as_deref()
        .and_then(|name| resolve_ifindex(name, names, linux_names))
        .map(|ifindex| {
            (
                ifindex,
                state
                    .tunnel_endpoint_by_ifindex
                    .get(&ifindex)
                    .copied()
                    .unwrap_or(0),
            )
        })
        .or_else(|| next_hop.and_then(|ip| infer_connected_route_target_v4(state, ip)));
    let (ifindex, tunnel_endpoint_id) = target.unwrap_or((0, 0));
    (next_hop, ifindex, tunnel_endpoint_id)
}

fn resolve_route_target_v6(
    route: &super::RouteSnapshot,
    names: &BTreeMap<String, i32>,
    linux_names: &BTreeMap<String, i32>,
    state: &ForwardingState,
) -> (Option<Ipv6Addr>, i32, u16) {
    if route.discard || !route.next_table.is_empty() {
        return (None, 0, 0);
    }
    let Some((next_hop, interface)) = route
        .next_hops
        .first()
        .map(|nh| parse_route_next_hop_v6(nh.as_str()))
    else {
        return (None, 0, 0);
    };
    let target = interface
        .as_deref()
        .and_then(|name| resolve_ifindex(name, names, linux_names))
        .map(|ifindex| {
            (
                ifindex,
                state
                    .tunnel_endpoint_by_ifindex
                    .get(&ifindex)
                    .copied()
                    .unwrap_or(0),
            )
        })
        .or_else(|| next_hop.and_then(|ip| infer_connected_route_target_v6(state, ip)));
    let (ifindex, tunnel_endpoint_id) = target.unwrap_or((0, 0));
    (next_hop, ifindex, tunnel_endpoint_id)
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

fn infer_connected_route_target_v4(state: &ForwardingState, ip: Ipv4Addr) -> Option<(i32, u16)> {
    state
        .connected_v4
        .iter()
        .find(|entry| entry.prefix.contains(ip))
        .map(|entry| (entry.ifindex, entry.tunnel_endpoint_id))
}

fn infer_connected_route_target_v6(state: &ForwardingState, ip: Ipv6Addr) -> Option<(i32, u16)> {
    state
        .connected_v6
        .iter()
        .find(|entry| entry.prefix.contains(ip))
        .map(|entry| (entry.ifindex, entry.tunnel_endpoint_id))
}

fn neighbor_state_usable(state: &str) -> bool {
    let normalized = state.to_ascii_lowercase();
    !(normalized.contains("failed") || normalized.contains("incomplete"))
}

pub fn neighbor_state_usable_str(state: &str) -> bool {
    neighbor_state_usable(state)
}

pub fn parse_mac_str(s: &str) -> Option<[u8; 6]> {
    parse_mac(s)
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
            tunnel_endpoint_id: 0,
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

fn owner_rg_for_resolution(
    forwarding: &ForwardingState,
    resolution: ForwardingResolution,
) -> i32 {
    if resolution.tunnel_endpoint_id != 0 {
        return forwarding
            .tunnel_endpoints
            .get(&resolution.tunnel_endpoint_id)
            .map(|endpoint| endpoint.redundancy_group.max(0))
            .unwrap_or_default();
    }
    owner_rg_for_flow(forwarding, resolution.egress_ifindex)
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
        tunnel_endpoint_id: 0,
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

fn cluster_peer_return_fast_path(
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
    meta: UserspaceDpMeta,
    ingress_zone_override: Option<&str>,
    resolution_target: IpAddr,
) -> Option<(SessionDecision, SessionMetadata)> {
    if !ingress_is_fabric(forwarding, meta.ingress_ifindex as i32) {
        return None;
    }
    let ingress_zone = ingress_zone_override?;
    if meta.protocol == PROTO_TCP
        && (meta.tcp_flags & TCP_FLAG_SYN) != 0
        && (meta.tcp_flags & 0x10) == 0
    {
        return None;
    }

    let fabric_return_resolution =
        lookup_forwarding_resolution_with_dynamic(forwarding, dynamic_neighbors, resolution_target);
    if fabric_return_resolution.disposition != ForwardingDisposition::ForwardCandidate {
        return None;
    }
    let egress_zone = forwarding
        .ifindex_to_zone
        .get(&fabric_return_resolution.egress_ifindex)?
        .clone();
    let metadata = SessionMetadata {
        ingress_zone: Arc::<str>::from(ingress_zone),
        egress_zone: Arc::<str>::from(egress_zone),
        owner_rg_id: owner_rg_for_resolution(forwarding, fabric_return_resolution),
        fabric_ingress: true,
        is_reverse: true,
        synced: false,
        nat64_reverse: None,
    };
    Some((
        SessionDecision {
            resolution: fabric_return_resolution,
            nat: NatDecision::default(),
        },
        metadata,
    ))
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
    let owner_rg_id = owner_rg_for_resolution(forwarding, resolution);
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

fn demoted_owner_rgs(
    previous: &BTreeMap<i32, HAGroupRuntime>,
    current: &BTreeMap<i32, HAGroupRuntime>,
) -> Vec<i32> {
    previous
        .iter()
        .filter_map(|(rg_id, old)| {
            let became_inactive = match current.get(rg_id) {
                Some(new) => old.active && !new.active,
                None => old.active,
            };
            became_inactive.then_some(*rg_id)
        })
        .collect()
}

fn activated_owner_rgs(
    previous: &BTreeMap<i32, HAGroupRuntime>,
    current: &BTreeMap<i32, HAGroupRuntime>,
) -> Vec<i32> {
    current
        .iter()
        .filter_map(|(rg_id, new)| {
            let became_active = match previous.get(rg_id) {
                Some(old) => !old.active && new.active,
                None => new.active,
            };
            became_active.then_some(*rg_id)
        })
        .collect()
}

/// Return the effective TCP MSS clamp value for the current config.
/// Returns 0 if MSS clamping is disabled.
#[allow(dead_code)]
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

fn native_gre_inner_mtu(
    forwarding: &ForwardingState,
    decision: &SessionDecision,
) -> usize {
    if decision.resolution.tunnel_endpoint_id == 0 {
        return 0;
    }
    let Some(endpoint) = forwarding
        .tunnel_endpoints
        .get(&decision.resolution.tunnel_endpoint_id)
        .cloned()
    else {
        return 0;
    };
    let transport_ifindex = resolve_ingress_logical_ifindex(
        forwarding,
        decision.resolution.tx_ifindex,
        decision.resolution.tx_vlan_id,
    )
    .unwrap_or(decision.resolution.tx_ifindex);
    let transport_mtu = forwarding
        .egress
        .get(&transport_ifindex)
        .or_else(|| forwarding.egress.get(&decision.resolution.egress_ifindex))
        .or_else(|| forwarding.egress.get(&endpoint.logical_ifindex))
        .map(|egress| egress.mtu)
        .unwrap_or_default();
    if transport_mtu == 0 {
        return 0;
    }
    let outer_ip_header_len = match endpoint.outer_family {
        libc::AF_INET => 20usize,
        libc::AF_INET6 => 40usize,
        _ => return 0,
    };
    let gre_header_len = 4usize + if endpoint.key != 0 { 4 } else { 0 };
    transport_mtu
        .checked_sub(outer_ip_header_len + gre_header_len)
        .unwrap_or_default()
}

fn native_gre_tcp_mss(
    forwarding: &ForwardingState,
    decision: &SessionDecision,
    addr_family: u8,
) -> u16 {
    if decision.resolution.tunnel_endpoint_id == 0 {
        return 0;
    }
    if forwarding.tcp_mss_gre_out > 0 {
        return forwarding.tcp_mss_gre_out;
    }
    let mtu = native_gre_inner_mtu(forwarding, decision);
    if mtu == 0 {
        return 0;
    }
    let ip_header_len = match addr_family as i32 {
        libc::AF_INET => 20usize,
        libc::AF_INET6 => 40usize,
        _ => return 0,
    };
    let Some(max_mss) = mtu.checked_sub(ip_header_len + 20) else {
        return 0;
    };
    u16::try_from(max_mss).unwrap_or_default()
}

/// Clamp TCP MSS option in-place in an L3 packet (starting at IP header).
/// `max_mss` is the maximum allowed MSS value.
/// Returns true if the MSS was clamped.
#[allow(dead_code)]
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
#[allow(dead_code)]
fn clamp_tcp_mss_frame(frame: &mut [u8], l3_offset: usize, max_mss: u16) -> bool {
    if max_mss == 0 || l3_offset >= frame.len() {
        return false;
    }
    clamp_tcp_mss(&mut frame[l3_offset..], max_mss)
}

#[allow(dead_code)]
const ICMP_TE_MAX_PER_SEC: u32 = 100;

/// Rate limiter for ICMP Time Exceeded messages.
#[allow(dead_code)]
struct IcmpTeRateLimiter {
    max_per_sec: u32,
    count: u32,
    window_start_ns: u64,
}

#[allow(dead_code)]
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
    lookup_forwarding_resolution_inner(state, None, dst, None)
}

fn lookup_forwarding_resolution_with_dynamic(
    state: &ForwardingState,
    dynamic_neighbors: &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
    dst: IpAddr,
) -> ForwardingResolution {
    lookup_forwarding_resolution_inner(state, Some(dynamic_neighbors), dst, None)
}

fn lookup_forwarding_resolution_in_table_with_dynamic(
    state: &ForwardingState,
    dynamic_neighbors: &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
    dst: IpAddr,
    table: Option<&str>,
) -> ForwardingResolution {
    lookup_forwarding_resolution_inner(state, Some(dynamic_neighbors), dst, table)
}

fn lookup_forwarding_resolution_inner(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>>,
    dst: IpAddr,
    table: Option<&str>,
) -> ForwardingResolution {
    match dst {
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
                    tunnel_endpoint_id: 0,
                    next_hop: None,
                    neighbor_mac: None,
                    src_mac: None,
                    tx_vlan_id: 0,
                };
            }
            let table = table
                .map(|table| canonical_route_table(table, false))
                .unwrap_or_else(|| DEFAULT_V4_TABLE.to_string());
            lookup_forwarding_resolution_v4(state, dynamic_neighbors, ip, &table, 0, true)
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
                    tunnel_endpoint_id: 0,
                    next_hop: None,
                    neighbor_mac: None,
                    src_mac: None,
                    tx_vlan_id: 0,
                };
            }
            let table = table
                .map(|table| canonical_route_table(table, true))
                .unwrap_or_else(|| DEFAULT_V6_TABLE.to_string());
            lookup_forwarding_resolution_v6(state, dynamic_neighbors, ip, &table, 0, true)
        }
    }
}

fn ingress_route_table_override(
    forwarding: &ForwardingState,
    meta: UserspaceDpMeta,
    flow: &SessionFlow,
) -> Option<String> {
    let ingress_ifindex =
        resolve_ingress_logical_ifindex(forwarding, meta.ingress_ifindex as i32, meta.ingress_vlan_id)
            .unwrap_or(meta.ingress_ifindex as i32);
    let is_v6 = matches!(flow.dst_ip, IpAddr::V6(_));
    let result = crate::filter::evaluate_interface_filter(
        &forwarding.filter_state,
        ingress_ifindex,
        is_v6,
        flow.src_ip,
        flow.dst_ip,
        meta.protocol,
        flow.forward_key.src_port,
        flow.forward_key.dst_port,
        meta.dscp,
    );
    if result.routing_instance.is_empty() {
        return None;
    }
    Some(if is_v6 {
        format!("{}.inet6.0", result.routing_instance)
    } else {
        format!("{}.inet.0", result.routing_instance)
    })
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
                tunnel_endpoint_id: state
                    .tunnel_endpoint_by_ifindex
                    .get(&local_ifindex)
                    .copied()
                    .unwrap_or_default(),
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
                tunnel_endpoint_id: state
                    .tunnel_endpoint_by_ifindex
                    .get(&local_ifindex)
                    .copied()
                    .unwrap_or_default(),
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
    _protocol: u8,
) -> Option<ForwardingResolution> {
    interface_nat_local_resolution(state, dst)
}

fn should_block_tunnel_interface_nat_session_miss(
    state: &ForwardingState,
    dst: IpAddr,
    protocol: u8,
) -> bool {
    matches!(protocol, PROTO_TCP | PROTO_UDP | PROTO_ICMP | PROTO_ICMPV6)
        && matches!(
            interface_nat_local_resolution(state, dst),
            Some(local) if local.tunnel_endpoint_id != 0
        )
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
        tunnel_endpoint_id: state
            .tunnel_endpoint_by_ifindex
            .get(&logical_ifindex)
            .copied()
            .unwrap_or_default(),
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
    _protocol: u8,
) -> Option<ForwardingResolution> {
    ingress_interface_local_resolution(state, ingress_ifindex, ingress_vlan_id, dst)
}

fn lookup_forwarding_resolution_v4(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>>,
    ip: Ipv4Addr,
    table: &str,
    depth: usize,
    allow_tunnels: bool,
) -> ForwardingResolution {
    if depth >= MAX_NEXT_TABLE_DEPTH {
        return ForwardingResolution {
            disposition: ForwardingDisposition::NextTableUnsupported,
            local_ifindex: 0,
            egress_ifindex: 0,
            tx_ifindex: 0,
            tunnel_endpoint_id: 0,
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
        Some(ResolvedRouteV4::Connected {
            ifindex,
            tunnel_endpoint_id,
        }) => {
            if tunnel_endpoint_id != 0 {
                return if allow_tunnels {
                    resolve_tunnel_forwarding_resolution(
                        state,
                        dynamic_neighbors,
                        tunnel_endpoint_id,
                        depth,
                    )
                } else {
                    no_route_resolution(Some(IpAddr::V4(ip)))
                };
            }
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
                tunnel_endpoint_id: 0,
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
            tunnel_endpoint_id,
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
                    tunnel_endpoint_id,
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
                        tunnel_endpoint_id: 0,
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
                    allow_tunnels,
                );
            }
            if tunnel_endpoint_id != 0 {
                return if allow_tunnels {
                    resolve_tunnel_forwarding_resolution(
                        state,
                        dynamic_neighbors,
                        tunnel_endpoint_id,
                        depth,
                    )
                } else {
                    no_route_resolution(next_hop.map(IpAddr::V4).or(Some(IpAddr::V4(ip))))
                };
            }
            if ifindex <= 0 {
                return no_route_resolution(next_hop.map(IpAddr::V4));
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
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(target)),
                neighbor_mac: neighbor.map(|entry| entry.mac),
                src_mac: None,
                tx_vlan_id: 0,
            };
            populate_egress_resolution(state, ifindex, &mut resolution);
            resolution
        }
        None => no_route_resolution(None),
    }
}

fn lookup_forwarding_resolution_v6(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>>,
    ip: Ipv6Addr,
    table: &str,
    depth: usize,
    allow_tunnels: bool,
) -> ForwardingResolution {
    if depth >= MAX_NEXT_TABLE_DEPTH {
        return ForwardingResolution {
            disposition: ForwardingDisposition::NextTableUnsupported,
            local_ifindex: 0,
            egress_ifindex: 0,
            tx_ifindex: 0,
            tunnel_endpoint_id: 0,
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
        Some(ResolvedRouteV6::Connected {
            ifindex,
            tunnel_endpoint_id,
        }) => {
            if tunnel_endpoint_id != 0 {
                return if allow_tunnels {
                    resolve_tunnel_forwarding_resolution(
                        state,
                        dynamic_neighbors,
                        tunnel_endpoint_id,
                        depth,
                    )
                } else {
                    no_route_resolution(Some(IpAddr::V6(ip)))
                };
            }
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
                tunnel_endpoint_id: 0,
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
            tunnel_endpoint_id,
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
                    tunnel_endpoint_id,
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
                        tunnel_endpoint_id: 0,
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
                    allow_tunnels,
                );
            }
            if tunnel_endpoint_id != 0 {
                return if allow_tunnels {
                    resolve_tunnel_forwarding_resolution(
                        state,
                        dynamic_neighbors,
                        tunnel_endpoint_id,
                        depth,
                    )
                } else {
                    no_route_resolution(next_hop.map(IpAddr::V6).or(Some(IpAddr::V6(ip))))
                };
            }
            if ifindex <= 0 {
                return no_route_resolution(next_hop.map(IpAddr::V6));
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
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V6(target)),
                neighbor_mac: neighbor.map(|entry| entry.mac),
                src_mac: None,
                tx_vlan_id: 0,
            };
            populate_egress_resolution(state, ifindex, &mut resolution);
            resolution
        }
        None => no_route_resolution(None),
    }
}

fn no_route_resolution(next_hop: Option<IpAddr>) -> ForwardingResolution {
    ForwardingResolution {
        disposition: ForwardingDisposition::NoRoute,
        local_ifindex: 0,
        egress_ifindex: 0,
        tx_ifindex: 0,
        tunnel_endpoint_id: 0,
        next_hop,
        neighbor_mac: None,
        src_mac: None,
        tx_vlan_id: 0,
    }
}

fn resolve_tunnel_forwarding_resolution(
    state: &ForwardingState,
    dynamic_neighbors: Option<&Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>>,
    tunnel_endpoint_id: u16,
    depth: usize,
) -> ForwardingResolution {
    let Some(endpoint) = state.tunnel_endpoints.get(&tunnel_endpoint_id) else {
        return no_route_resolution(None);
    };
    let outer = match endpoint.destination {
        IpAddr::V4(ip) => lookup_forwarding_resolution_v4(
            state,
            dynamic_neighbors,
            ip,
            &endpoint.transport_table,
            depth + 1,
            false,
        ),
        IpAddr::V6(ip) => lookup_forwarding_resolution_v6(
            state,
            dynamic_neighbors,
            ip,
            &endpoint.transport_table,
            depth + 1,
            false,
        ),
    };
    if outer.disposition == ForwardingDisposition::LocalDelivery
        || state.tunnel_interfaces.contains(&outer.egress_ifindex)
    {
        return no_route_resolution(Some(endpoint.destination));
    }
    ForwardingResolution {
        disposition: outer.disposition,
        local_ifindex: outer.local_ifindex,
        egress_ifindex: endpoint.logical_ifindex,
        tx_ifindex: outer.tx_ifindex,
        tunnel_endpoint_id,
        next_hop: outer.next_hop,
        neighbor_mac: outer.neighbor_mac,
        src_mac: outer.src_mac,
        tx_vlan_id: outer.tx_vlan_id,
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
    // The worker hot path must not block on shelling out to `ip neigh` or
    // active probes. Neighbor discovery is refreshed asynchronously by the
    // manager snapshot path and the periodic update_neighbors control request.
    None
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

enum ResolvedRouteV4 {
    Connected {
        ifindex: i32,
        tunnel_endpoint_id: u16,
    },
    Static {
        ifindex: i32,
        tunnel_endpoint_id: u16,
        next_hop: Option<Ipv4Addr>,
        discard: bool,
        next_table: Option<String>,
    },
}

enum ResolvedRouteV6 {
    Connected {
        ifindex: i32,
        tunnel_endpoint_id: u16,
    },
    Static {
        ifindex: i32,
        tunnel_endpoint_id: u16,
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
                tunnel_endpoint_id: conn.tunnel_endpoint_id,
            })
        }
        (Some(route), _) => Some(ResolvedRouteV4::Static {
            ifindex: route.ifindex,
            tunnel_endpoint_id: route.tunnel_endpoint_id,
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
            tunnel_endpoint_id: conn.tunnel_endpoint_id,
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
                tunnel_endpoint_id: conn.tunnel_endpoint_id,
            })
        }
        (Some(route), _) => Some(ResolvedRouteV6::Static {
            ifindex: route.ifindex,
            tunnel_endpoint_id: route.tunnel_endpoint_id,
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
            tunnel_endpoint_id: conn.tunnel_endpoint_id,
        }),
        (None, None) => None,
    }
}

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

    Some((
        rx_prod, rx_cons, fr_prod, fr_cons, tx_prod, tx_cons, cr_prod, cr_cons,
    ))
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
    // Don't write heartbeat until either:
    // 1. XSK RX has delivered a packet (xsk_rx_confirmed), OR
    // 2. The grace period has elapsed (allows copy-mode and already-
    //    bootstrapped zero-copy bindings to start immediately)
    if !binding.xsk_rx_confirmed
        && now_ns.saturating_sub(binding.bind_time_ns) < HEARTBEAT_GRACE_PERIOD_NS
    {
        return;
    }
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
                    debug_log!(
                        "HB_UPDATE slot={} fd={} age={}ms now_ns={} LATE",
                        binding.slot,
                        binding.heartbeat_map_fd,
                        age_ms,
                        now_ns,
                    );
                }
                HB_LOG_COUNT.with(|c| {
                    let n = c.get();
                    if n < 5 {
                        c.set(n + 1);
                        debug_log!(
                            "HB_UPDATE[{}] slot={} fd={} age={}ms now_ns={} OK",
                            n,
                            binding.slot,
                            binding.heartbeat_map_fd,
                            age_ms,
                            now_ns,
                        );
                    }
                });
            }
            binding.last_heartbeat_update_ns = now_ns;
        }
        Err(err) => {
            eprintln!(
                "HB_UPDATE_ERR slot={} fd={} age={}ms err={}",
                binding.slot,
                binding.heartbeat_map_fd,
                age_ns / 1_000_000,
                err,
            );
            binding
                .live
                .set_error(format!("update heartbeat slot: {err}"));
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

fn publish_session_map_key(map_fd: c_int, key: &SessionKey, value: u8) -> io::Result<()> {
    let map_key = session_map_key(key);
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

fn publish_live_session_key(map_fd: c_int, key: &SessionKey) -> io::Result<()> {
    publish_session_map_key(map_fd, key, USERSPACE_SESSION_ACTION_REDIRECT)
}

fn publish_kernel_local_session_key(map_fd: c_int, key: &SessionKey) -> io::Result<()> {
    publish_session_map_key(map_fd, key, USERSPACE_SESSION_ACTION_PASS_TO_KERNEL)
}

fn publish_live_session_entry(
    map_fd: c_int,
    key: &SessionKey,
    nat: NatDecision,
    is_reverse: bool,
) -> io::Result<()> {
    publish_live_session_key(map_fd, key)?;
    if !is_reverse {
        let wire_key = forward_wire_key(key, nat);
        if wire_key != *key {
            publish_live_session_key(map_fd, &wire_key)?;
        }
        let reverse_wire = reverse_session_key(key, nat);
        if reverse_wire != *key {
            publish_live_session_key(map_fd, &reverse_wire)?;
        }
        let reverse_canonical = reverse_canonical_key(key, nat);
        if reverse_canonical != *key && reverse_canonical != reverse_wire {
            publish_live_session_key(map_fd, &reverse_canonical)?;
        }
    }
    Ok(())
}

fn publish_session_map_entry_for_session(
    map_fd: c_int,
    key: &SessionKey,
    decision: SessionDecision,
    metadata: &SessionMetadata,
) -> io::Result<()> {
    if metadata.synced
        && !metadata.is_reverse
        && decision.resolution.disposition == ForwardingDisposition::LocalDelivery
        && decision.resolution.tunnel_endpoint_id == 0
    {
        return publish_kernel_local_session_key(map_fd, key);
    }
    publish_live_session_entry(map_fd, key, decision.nat, metadata.is_reverse)
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
#[allow(unused_variables)]
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
        debug_log!("BPF_MAP_DUMP: empty (no entries)");
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
        #[cfg(feature = "debug-log")]
        {
            let src_ip = if map_key.addr_family == libc::AF_INET as u8 {
                format!(
                    "{}.{}.{}.{}",
                    map_key.src_addr[0],
                    map_key.src_addr[1],
                    map_key.src_addr[2],
                    map_key.src_addr[3]
                )
            } else {
                format!(
                    "v6[{:02x}{:02x}::{:02x}{:02x}]",
                    map_key.src_addr[0],
                    map_key.src_addr[1],
                    map_key.src_addr[14],
                    map_key.src_addr[15]
                )
            };
            let dst_ip = if map_key.addr_family == libc::AF_INET as u8 {
                format!(
                    "{}.{}.{}.{}",
                    map_key.dst_addr[0],
                    map_key.dst_addr[1],
                    map_key.dst_addr[2],
                    map_key.dst_addr[3]
                )
            } else {
                format!(
                    "v6[{:02x}{:02x}::{:02x}{:02x}]",
                    map_key.dst_addr[0],
                    map_key.dst_addr[1],
                    map_key.dst_addr[14],
                    map_key.dst_addr[15]
                )
            };
            debug_log!(
                "BPF_MAP_DUMP[{}]: af={} proto={} {}:{} -> {}:{} val={}",
                count,
                map_key.addr_family,
                map_key.protocol,
                src_ip,
                map_key.src_port,
                dst_ip,
                map_key.dst_port,
                value,
            );
        }
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
    debug_log!("BPF_MAP_DUMP: total={count} entries");
}

static SESSION_PUBLISH_VERIFY_OK: AtomicU64 = AtomicU64::new(0);
static SESSION_PUBLISH_VERIFY_FAIL: AtomicU64 = AtomicU64::new(0);
static SESSION_CREATIONS_LOGGED: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "debug-log")]
static ICMPV6_EMBED_LOGGED: AtomicU32 = AtomicU32::new(0);

const FALLBACK_STATS_PIN_PATH: &str = "/sys/fs/bpf/bpfrx/userspace_fallback_stats";
const FALLBACK_REASON_NAMES: &[&str] = &[
    "ctrl_disabled",     // 0
    "parse_fail",        // 1
    "binding_missing",   // 2
    "binding_not_ready", // 3
    "hb_missing",        // 4
    "hb_stale",          // 5
    "icmp",              // 6
    "early_filter",      // 7
    "adjust_meta",       // 8
    "meta_bounds",       // 9
    "redirect_err",      // 10
    "iface_nat_no_sess", // 11
    "no_session",        // 12
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

fn delete_live_session_entry(map_fd: c_int, key: &SessionKey, nat: NatDecision, is_reverse: bool) {
    delete_live_session_key(map_fd, key);
    if !is_reverse {
        let wire_key = forward_wire_key(key, nat);
        if wire_key != *key {
            delete_live_session_key(map_fd, &wire_key);
        }
        let reverse_wire = reverse_session_key(key, nat);
        if reverse_wire != *key {
            delete_live_session_key(map_fd, &reverse_wire);
        }
        let reverse_canonical = reverse_canonical_key(key, nat);
        if reverse_canonical != *key && reverse_canonical != reverse_wire {
            delete_live_session_key(map_fd, &reverse_canonical);
        }
    }
}

fn delete_session_map_entry_for_removed_session(
    map_fd: c_int,
    key: &SessionKey,
    decision: SessionDecision,
    metadata: &SessionMetadata,
) {
    if metadata.synced
        && !metadata.is_reverse
        && decision.resolution.disposition == ForwardingDisposition::LocalDelivery
    {
        delete_live_session_key(map_fd, key);
        return;
    }
    delete_live_session_entry(map_fd, key, decision.nat, metadata.is_reverse);
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
    direct_tx_packets: AtomicU64,
    copy_tx_packets: AtomicU64,
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
            direct_tx_packets: AtomicU64::new(0),
            copy_tx_packets: AtomicU64::new(0),
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
            direct_tx_packets: self.direct_tx_packets.load(Ordering::Relaxed),
            copy_tx_packets: self.copy_tx_packets.load(Ordering::Relaxed),
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
                self.pending_tx_len.store(
                    pending.len().min(u32::MAX as usize) as u32,
                    Ordering::Relaxed,
                );
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
    if binding.pending_direct_tx_packets != 0 {
        binding
            .live
            .direct_tx_packets
            .fetch_add(binding.pending_direct_tx_packets, Ordering::Relaxed);
        binding.pending_direct_tx_packets = 0;
    }
    if binding.pending_copy_tx_packets != 0 {
        binding
            .live
            .copy_tx_packets
            .fetch_add(binding.pending_copy_tx_packets, Ordering::Relaxed);
        binding.pending_copy_tx_packets = 0;
    }
    if binding.pending_in_place_tx_packets != 0 {
        binding
            .live
            .in_place_tx_packets
            .fetch_add(binding.pending_in_place_tx_packets, Ordering::Relaxed);
        binding.pending_in_place_tx_packets = 0;
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
        binding.in_flight_prepared_recycles.len() as u32,
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
    direct_tx_packets: u64,
    copy_tx_packets: u64,
    in_place_tx_packets: u64,
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
    use super::*;
    use crate::{
        FabricSnapshot, FirewallFilterSnapshot, FirewallTermSnapshot, InterfaceAddressSnapshot,
        InterfaceSnapshot, NeighborSnapshot, PolicyRuleSnapshot, RouteSnapshot,
        SourceNATRuleSnapshot, StaticNATRuleSnapshot, TunnelEndpointSnapshot, ZoneSnapshot,
    };

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

        assert_eq!(lookup.target_index(2, 7, 1, 5), Some(1));
        assert_eq!(lookup.target_index(2, 7, 3, 5), Some(0));
        assert_eq!(lookup.target_index(2, 5, 1, 5), Some(2));
    }

    #[test]
    fn worker_binding_lookup_resolves_slot_index() {
        let mut lookup = WorkerBindingLookup::default();
        lookup.by_slot.insert(11, 3);
        assert_eq!(lookup.slot_index(11), Some(3));
        assert_eq!(lookup.slot_index(99), None);
    }

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

    fn native_gre_snapshot(include_neighbor: bool) -> ConfigSnapshot {
        ConfigSnapshot {
            zones: vec![
                ZoneSnapshot {
                    name: "wan".to_string(),
                    id: 1,
                },
                ZoneSnapshot {
                    name: "sfmix".to_string(),
                    id: 2,
                },
            ],
            interfaces: vec![
                InterfaceSnapshot {
                    name: "reth0.80".to_string(),
                    zone: "wan".to_string(),
                    linux_name: "ge-0-0-2.80".to_string(),
                    ifindex: 12,
                    parent_ifindex: 6,
                    vlan_id: 80,
                    mtu: 1500,
                    redundancy_group: 1,
                    hardware_addr: "02:bf:72:00:50:08".to_string(),
                    addresses: vec![InterfaceAddressSnapshot {
                        family: "inet6".to_string(),
                        address: "2001:559:8585:80::8/64".to_string(),
                        scope: 0,
                    }],
                    ..Default::default()
                },
                InterfaceSnapshot {
                    name: "gr-0/0/0.0".to_string(),
                    zone: "sfmix".to_string(),
                    linux_name: "gr-0-0-0".to_string(),
                    ifindex: 362,
                    mtu: 1476,
                    redundancy_group: 1,
                    tunnel: true,
                    addresses: vec![InterfaceAddressSnapshot {
                        family: "inet".to_string(),
                        address: "10.255.192.42/30".to_string(),
                        scope: 0,
                    }],
                    ..Default::default()
                },
            ],
            tunnel_endpoints: vec![TunnelEndpointSnapshot {
                id: 1,
                interface: "gr-0/0/0.0".to_string(),
                linux_name: "gr-0-0-0".to_string(),
                ifindex: 362,
                zone: "sfmix".to_string(),
                redundancy_group: 1,
                mtu: 1476,
                mode: "gre".to_string(),
                outer_family: "inet6".to_string(),
                source: "2001:559:8585:80::8".to_string(),
                destination: "2602:ffd3:0:2::7".to_string(),
                key: 0,
                ttl: 64,
                transport_table: "inet6.0".to_string(),
            }],
            routes: vec![
                RouteSnapshot {
                    table: "inet6.0".to_string(),
                    family: "inet6".to_string(),
                    destination: "2602:ffd3:0:2::/64".to_string(),
                    next_hops: vec!["2001:559:8585:80::1@reth0.80".to_string()],
                    discard: false,
                    next_table: String::new(),
                },
                RouteSnapshot {
                    table: "sfmix.inet.0".to_string(),
                    family: "inet".to_string(),
                    destination: "0.0.0.0/0".to_string(),
                    next_hops: vec!["10.255.192.41".to_string()],
                    discard: false,
                    next_table: String::new(),
                },
            ],
            neighbors: if include_neighbor {
                vec![NeighborSnapshot {
                    interface: "ge-0-0-2.80".to_string(),
                    ifindex: 12,
                    family: "inet6".to_string(),
                    ip: "2001:559:8585:80::1".to_string(),
                    mac: "00:11:22:33:44:55".to_string(),
                    state: "reachable".to_string(),
                    router: true,
                    link_local: false,
                }]
            } else {
                vec![]
            },
            ..Default::default()
        }
    }

    fn native_gre_pbr_snapshot(include_neighbor: bool) -> ConfigSnapshot {
        let mut snapshot = native_gre_snapshot(include_neighbor);
        snapshot.zones.insert(
            0,
            ZoneSnapshot {
                name: "lan".to_string(),
                id: 3,
            },
        );
        snapshot.interfaces.push(InterfaceSnapshot {
            name: "reth1.0".to_string(),
            zone: "lan".to_string(),
            linux_name: "ge-0-0-1".to_string(),
            ifindex: 5,
            filter_input_v4: "sfmix-pbr".to_string(),
            addresses: vec![InterfaceAddressSnapshot {
                family: "inet".to_string(),
                address: "10.0.61.1/24".to_string(),
                scope: 0,
            }],
            ..Default::default()
        });
        snapshot.filters = vec![FirewallFilterSnapshot {
            name: "sfmix-pbr".to_string(),
            family: "inet".to_string(),
            terms: vec![
                FirewallTermSnapshot {
                    name: "sfmix-route".to_string(),
                    destination_addresses: vec!["10.255.192.40/30".to_string()],
                    routing_instance: "sfmix".to_string(),
                    ..Default::default()
                },
                FirewallTermSnapshot {
                    name: "default".to_string(),
                    action: "accept".to_string(),
                    ..Default::default()
                },
            ],
        }];
        snapshot
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
            local_mac: "02:bf:72:ff:00:01".to_string(),
            peer_mac: "00:aa:bb:cc:dd:ee".to_string(),
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

        let meta = UserspaceDpMeta {
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
    fn tunnel_route_resolves_to_logical_tunnel_and_physical_tx() {
        let state = build_forwarding_state(&native_gre_snapshot(true));
        let resolved = lookup_forwarding_resolution_v4(
            &state,
            None,
            Ipv4Addr::new(8, 8, 8, 8),
            "sfmix.inet.0",
            0,
            true,
        );
        assert_eq!(
            resolved.disposition,
            ForwardingDisposition::ForwardCandidate
        );
        assert_eq!(resolved.egress_ifindex, 362);
        assert_eq!(resolved.tx_ifindex, 6);
        assert_eq!(resolved.tunnel_endpoint_id, 1);
        assert_eq!(
            resolved.next_hop,
            Some(IpAddr::V6("2001:559:8585:80::1".parse().expect("outer nh")))
        );
        assert_eq!(
            resolved.neighbor_mac,
            Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
        );
        assert_eq!(resolved.src_mac, Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]));
        assert_eq!(resolved.tx_vlan_id, 80);
    }

    #[test]
    fn tunnel_route_preserves_logical_egress_on_outer_neighbor_miss() {
        let state = build_forwarding_state(&native_gre_snapshot(false));
        let resolved = lookup_forwarding_resolution_v4(
            &state,
            None,
            Ipv4Addr::new(8, 8, 8, 8),
            "sfmix.inet.0",
            0,
            true,
        );
        assert_eq!(resolved.disposition, ForwardingDisposition::MissingNeighbor);
        assert_eq!(resolved.egress_ifindex, 362);
        assert_eq!(resolved.tx_ifindex, 6);
        assert_eq!(resolved.tunnel_endpoint_id, 1);
        assert_eq!(resolved.src_mac, Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]));
        assert_eq!(resolved.tx_vlan_id, 80);
    }

    #[test]
    fn ingress_filter_routing_instance_steers_flow_into_native_gre_table() {
        let state = build_forwarding_state(&native_gre_pbr_snapshot(true));
        let flow = SessionFlow {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 255, 192, 41)),
            forward_key: SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_ICMP,
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(10, 255, 192, 41)),
                src_port: 0,
                dst_port: 0,
            },
        };
        let meta = UserspaceDpMeta {
            ingress_ifindex: 5,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_ICMP,
            ..Default::default()
        };
        let override_table = ingress_route_table_override(&state, meta, &flow);
        assert_eq!(override_table.as_deref(), Some("sfmix.inet.0"));
        let resolved = lookup_forwarding_resolution_in_table_with_dynamic(
            &state,
            &Default::default(),
            flow.dst_ip,
            override_table.as_deref(),
        );
        assert_eq!(resolved.disposition, ForwardingDisposition::ForwardCandidate);
        assert_eq!(resolved.egress_ifindex, 362);
        assert_eq!(resolved.tx_ifindex, 6);
        assert_eq!(resolved.tunnel_endpoint_id, 1);
    }

    #[test]
    fn native_gre_logical_egress_retains_zone_without_mac() {
        let state = build_forwarding_state(&native_gre_pbr_snapshot(true));
        let egress = state.egress.get(&362).expect("logical tunnel egress");
        assert_eq!(egress.zone, "sfmix");
        assert_eq!(egress.primary_v4, Some(Ipv4Addr::new(10, 255, 192, 42)));
    }

    #[test]
    fn owner_rg_for_resolution_uses_native_gre_endpoint_group() {
        let state = build_forwarding_state(&native_gre_snapshot(true));
        let resolved = lookup_forwarding_resolution_with_dynamic(
            &state,
            &Default::default(),
            IpAddr::V4(Ipv4Addr::new(10, 255, 192, 41)),
        );
        assert_eq!(resolved.tunnel_endpoint_id, 1);
        assert_eq!(owner_rg_for_resolution(&state, resolved), 1);
    }

    #[test]
    fn native_gre_decap_maps_inner_packet_to_logical_tunnel_ingress() {
        let state = build_forwarding_state(&native_gre_snapshot(true));
        let inner = build_icmp_echo_frame_v4(
            Ipv4Addr::new(10, 255, 192, 41),
            Ipv4Addr::new(10, 255, 192, 42),
            63,
        );
        let outer = build_ipv6_gre_frame(
            &inner[14..],
            "2602:ffd3:0:2::7".parse().unwrap(),
            "2001:559:8585:80::8".parse().unwrap(),
            None,
        );
        let packet = try_native_gre_decap_from_frame(&outer, native_gre_outer_meta(), &state)
            .expect("native gre decap");
        assert_eq!(packet.meta.ingress_ifindex, 362);
        assert_eq!(packet.meta.addr_family, libc::AF_INET as u8);
        assert_eq!(packet.meta.protocol, PROTO_ICMP);
        assert_eq!(packet.meta.l3_offset, 14);
        assert_eq!(&packet.frame[12..14], &[0x08, 0x00]);
        assert_eq!(&packet.frame[26..30], &[10, 255, 192, 41]);
        assert_eq!(&packet.frame[30..34], &[10, 255, 192, 42]);
    }

    #[test]
    fn build_forwarded_frame_from_frame_encapsulates_native_gre() {
        let state = build_forwarding_state(&native_gre_snapshot(true));
        let inner =
            build_icmp_echo_frame_v4(Ipv4Addr::new(10, 0, 61, 102), Ipv4Addr::new(8, 8, 8, 8), 64);
        let inner_meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            ingress_ifindex: 11,
            l3_offset: 14,
            l4_offset: 34,
            payload_offset: 42,
            pkt_len: (inner.len() - 14) as u16,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_ICMP,
            flow_src_addr: {
                let mut addr = [0u8; 16];
                addr[..4].copy_from_slice(&[10, 0, 61, 102]);
                addr
            },
            flow_dst_addr: {
                let mut addr = [0u8; 16];
                addr[..4].copy_from_slice(&[8, 8, 8, 8]);
                addr
            },
            flow_src_port: 0x1234,
            ..UserspaceDpMeta::default()
        };
        let decision = SessionDecision {
            resolution: lookup_forwarding_resolution_v4(
                &state,
                None,
                Ipv4Addr::new(8, 8, 8, 8),
                "sfmix.inet.0",
                0,
                true,
            ),
            nat: NatDecision::default(),
        };
        let built = build_forwarded_frame_from_frame(
            &inner,
            inner_meta,
            &decision,
            &state,
            false,
            Some((0x1234, 0)),
        )
        .expect("encapsulated gre frame");
        assert_eq!(&built[12..16], &[0x81, 0x00, 0x00, 0x50]);
        assert_eq!(&built[16..18], &[0x86, 0xdd]);
        assert_eq!(&built[22..24], &[0x00, 0x20]);
        assert_eq!(built[24], PROTO_GRE);
        assert_eq!(built[25], 64);
        assert_eq!(&built[60..62], &[0x08, 0x00]);
        assert_eq!(built[70], 63);
        assert_eq!(&built[74..78], &[10, 0, 61, 102]);
        assert_eq!(&built[78..82], &[8, 8, 8, 8]);
    }

    #[test]
    fn local_origin_tunnel_tx_request_encapsulates_raw_ip_for_active_owner() {
        let state = build_forwarding_state(&native_gre_snapshot(true));
        let ha_state = Arc::new(ArcSwap::from_pointee(BTreeMap::from([(
            1,
            HAGroupRuntime {
                active: true,
                watchdog_timestamp: monotonic_nanos() / 1_000_000_000,
            },
        )])));
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));
        let packet =
            build_icmp_echo_frame_v4(Ipv4Addr::new(10, 255, 192, 42), Ipv4Addr::new(10, 255, 192, 41), 64);
        let plan = build_local_origin_tunnel_tx_request(
            &packet[14..],
            1,
            &state,
            &ha_state,
            &dynamic_neighbors,
        )
        .expect("local-origin tunnel tx request");
        assert_eq!(plan.tx_ifindex, 6);
        assert_eq!(&plan.tx_request.bytes[12..16], &[0x81, 0x00, 0x00, 0x50]);
        assert_eq!(&plan.tx_request.bytes[16..18], &[0x86, 0xdd]);
        assert_eq!(plan.tx_request.bytes[24], PROTO_GRE);
        assert_eq!(&plan.tx_request.bytes[60..62], &[0x08, 0x00]);
        assert_eq!(&plan.tx_request.bytes[74..78], &[10, 255, 192, 42]);
        assert_eq!(&plan.tx_request.bytes[78..82], &[10, 255, 192, 41]);
        assert_eq!(plan.session_entry.key.protocol, PROTO_ICMP);
    }

    #[test]
    fn local_origin_tunnel_tx_request_rejects_inactive_owner() {
        let state = build_forwarding_state(&native_gre_snapshot(true));
        let ha_state = Arc::new(ArcSwap::from_pointee(BTreeMap::from([(
            1,
            HAGroupRuntime {
                active: false,
                watchdog_timestamp: monotonic_nanos() / 1_000_000_000,
            },
        )])));
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));
        let packet =
            build_icmp_echo_frame_v4(Ipv4Addr::new(10, 255, 192, 42), Ipv4Addr::new(10, 255, 192, 41), 64);
        let err = build_local_origin_tunnel_tx_request(
            &packet[14..],
            1,
            &state,
            &ha_state,
            &dynamic_neighbors,
        )
        .expect_err("inactive owner should not originate tunnel traffic");
        assert!(err.contains("ha_inactive"), "unexpected error: {err}");
    }

    #[test]
    fn build_forwarded_frame_from_frame_encapsulates_native_gre_after_ipv4_snat() {
        let state = build_forwarding_state(&native_gre_snapshot(true));
        let inner = build_icmp_echo_frame_v4(
            Ipv4Addr::new(10, 0, 61, 102),
            Ipv4Addr::new(10, 255, 192, 41),
            64,
        );
        let inner_meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            ingress_ifindex: 5,
            l3_offset: 14,
            l4_offset: 34,
            payload_offset: 42,
            pkt_len: (inner.len() - 14) as u16,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_ICMP,
            flow_src_addr: {
                let mut addr = [0u8; 16];
                addr[..4].copy_from_slice(&[10, 0, 61, 102]);
                addr
            },
            flow_dst_addr: {
                let mut addr = [0u8; 16];
                addr[..4].copy_from_slice(&[10, 255, 192, 41]);
                addr
            },
            flow_src_port: 0x1234,
            ..UserspaceDpMeta::default()
        };
        let decision = SessionDecision {
            resolution: lookup_forwarding_resolution_v4(
                &state,
                None,
                Ipv4Addr::new(10, 255, 192, 41),
                "sfmix.inet.0",
                0,
                true,
            ),
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(10, 255, 192, 42))),
                ..NatDecision::default()
            },
        };
        let built = build_forwarded_frame_from_frame(
            &inner,
            inner_meta,
            &decision,
            &state,
            false,
            Some((0x1234, 0)),
        )
        .expect("encapsulated native gre frame with snat");
        assert_eq!(&built[12..16], &[0x81, 0x00, 0x00, 0x50]);
        assert_eq!(&built[16..18], &[0x86, 0xdd]);
        assert_eq!(built[24], PROTO_GRE);
        assert_eq!(&built[74..78], &[10, 255, 192, 42]);
        assert_eq!(&built[78..82], &[10, 255, 192, 41]);
    }

    #[test]
    fn build_forwarded_frame_from_frame_recomputes_tcp_checksum_for_native_gre_snat() {
        let state = build_forwarding_state(&native_gre_snapshot(true));
        let src_ip = Ipv4Addr::new(10, 0, 61, 102);
        let dst_ip = Ipv4Addr::new(10, 255, 192, 41);
        let snat_ip = Ipv4Addr::new(10, 255, 192, 42);
        let src_port = 50420u16;
        let dst_port = 5201u16;

        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x36, 0xe4, 0x2b, 0xd5, 0x39, 0xe6],
            0,
            0x0800,
        );
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x30, 0x12, 0x34, 0x40, 0x00, 64, PROTO_TCP, 0x00, 0x00,
        ]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&[
            0x00, 0x00, 0x00, 0x01, // seq
            0x00, 0x00, 0x00, 0x01, // ack
            0x50, 0x18, 0x20, 0x00, // data offset/flags/window
            0x18, 0x29, 0x00, 0x00, // intentionally bogus partial/offload checksum + urg
            b't', b'e', b's', b't', b'd', b'a', b't', b'a',
        ]);
        let ip_sum = checksum16(&frame[14..34]);
        frame[24] = (ip_sum >> 8) as u8;
        frame[25] = ip_sum as u8;

        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            ingress_ifindex: 5,
            l3_offset: 14,
            l4_offset: 34,
            payload_offset: 54,
            pkt_len: (frame.len() - 14) as u16,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            flow_src_addr: {
                let mut addr = [0u8; 16];
                addr[..4].copy_from_slice(&src_ip.octets());
                addr
            },
            flow_dst_addr: {
                let mut addr = [0u8; 16];
                addr[..4].copy_from_slice(&dst_ip.octets());
                addr
            },
            flow_src_port: src_port,
            flow_dst_port: dst_port,
            ..UserspaceDpMeta::default()
        };
        let decision = SessionDecision {
            resolution: lookup_forwarding_resolution_v4(
                &state,
                None,
                dst_ip,
                "sfmix.inet.0",
                0,
                true,
            ),
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(snat_ip)),
                ..NatDecision::default()
            },
        };
        let built = build_forwarded_frame_from_frame(
            &frame,
            meta,
            &decision,
            &state,
            false,
            Some((src_port, dst_port)),
        )
        .expect("encapsulated native gre frame with tcp snat");
        let inner = &built[62..];
        assert_eq!(&inner[12..16], &snat_ip.octets());
        assert_eq!(&inner[16..20], &dst_ip.octets());
        assert!(tcp_checksum_ok_ipv4(inner));
    }

    #[test]
    fn build_forwarded_frame_from_frame_clamps_tcp_mss_for_native_gre() {
        let state = build_forwarding_state(&native_gre_snapshot(true));
        let src_ip = Ipv4Addr::new(10, 0, 61, 102);
        let dst_ip = Ipv4Addr::new(10, 255, 192, 41);
        let src_port = 44028u16;
        let dst_port = 5201u16;

        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x36, 0xe4, 0x2b, 0xd5, 0x39, 0xe6],
            0,
            0x0800,
        );
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x2c, 0x12, 0x34, 0x40, 0x00, 64, PROTO_TCP, 0x00, 0x00,
        ]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&[
            0x00, 0x00, 0x00, 0x01, // seq
            0x00, 0x00, 0x00, 0x00, // ack
            0x60, TCP_FLAG_SYN, 0xfa, 0xf0, // data offset / flags / window
            0x00, 0x00, 0x00, 0x00, // checksum + urg
            0x02, 0x04, 0x05, 0xb4, // MSS 1460
        ]);
        let ip_sum = checksum16(&frame[14..34]);
        frame[24] = (ip_sum >> 8) as u8;
        frame[25] = ip_sum as u8;

        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            ingress_ifindex: 5,
            l3_offset: 14,
            l4_offset: 34,
            payload_offset: 58,
            pkt_len: (frame.len() - 14) as u16,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            tcp_flags: TCP_FLAG_SYN,
            flow_src_addr: {
                let mut addr = [0u8; 16];
                addr[..4].copy_from_slice(&src_ip.octets());
                addr
            },
            flow_dst_addr: {
                let mut addr = [0u8; 16];
                addr[..4].copy_from_slice(&dst_ip.octets());
                addr
            },
            flow_src_port: src_port,
            flow_dst_port: dst_port,
            ..UserspaceDpMeta::default()
        };
        let decision = SessionDecision {
            resolution: lookup_forwarding_resolution_v4(
                &state,
                None,
                dst_ip,
                "sfmix.inet.0",
                0,
                true,
            ),
            nat: NatDecision::default(),
        };
        let built = build_forwarded_frame_from_frame(
            &frame,
            meta,
            &decision,
            &state,
            false,
            Some((src_port, dst_port)),
        )
        .expect("encapsulated native gre frame with tcp syn");
        let inner = &built[62..];
        assert_eq!(&inner[40..44], &[0x02, 0x04, 0x05, 0x88]);
        assert!(tcp_checksum_ok_ipv4(inner));
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
    fn build_forwarding_state_uses_fabric_snapshot_macs_without_parent_interface() {
        let mut snapshot = nat_snapshot();
        snapshot.fabrics = vec![FabricSnapshot {
            name: "fab0".to_string(),
            parent_interface: "ge-0/0/0".to_string(),
            parent_linux_name: "ge-0-0-0".to_string(),
            parent_ifindex: 21,
            overlay_linux_name: "fab0".to_string(),
            overlay_ifindex: 101,
            rx_queues: 2,
            peer_address: "10.99.13.2".to_string(),
            local_mac: "02:bf:72:ff:00:01".to_string(),
            peer_mac: "00:aa:bb:cc:dd:ee".to_string(),
        }];
        let state = build_forwarding_state(&snapshot);
        let redirect = resolve_fabric_redirect(&state).expect("fabric redirect");
        assert_eq!(redirect.egress_ifindex, 21);
        assert_eq!(redirect.tx_ifindex, 21);
        assert_eq!(
            redirect.neighbor_mac,
            Some([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee])
        );
        assert_eq!(redirect.src_mac, Some([0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]));
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
    fn fabric_originated_reverse_session_prefers_local_client_delivery_when_rg_active() {
        let state = build_forwarding_state(&nat_snapshot_with_fabric());
        let ha_state = BTreeMap::from([(
            2,
            HAGroupRuntime {
                active: true,
                watchdog_timestamp: monotonic_nanos() / 1_000_000_000,
            },
        )]);
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));
        dynamic_neighbors.lock().expect("neighbors").insert(
            (24, IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
            NeighborEntry {
                mac: [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01],
            },
        );

        let resolved = reverse_resolution_for_session(
            &state,
            &ha_state,
            &dynamic_neighbors,
            IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            "lan",
            true,
            monotonic_nanos() / 1_000_000_000,
            false,
        );

        assert_eq!(
            resolved.disposition,
            ForwardingDisposition::ForwardCandidate
        );
        assert_eq!(resolved.egress_ifindex, 24);
        assert_eq!(resolved.tx_ifindex, 24);
    }

    #[test]
    fn fabric_originated_reverse_session_uses_zone_encoded_fabric_redirect_when_client_rg_inactive()
    {
        let state = build_forwarding_state(&nat_snapshot_with_fabric());
        let ha_state = BTreeMap::from([(
            2,
            HAGroupRuntime {
                active: false,
                watchdog_timestamp: monotonic_nanos() / 1_000_000_000,
            },
        )]);
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));

        let resolved = reverse_resolution_for_session(
            &state,
            &ha_state,
            &dynamic_neighbors,
            IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            "lan",
            true,
            monotonic_nanos() / 1_000_000_000,
            false,
        );

        assert_eq!(resolved.disposition, ForwardingDisposition::FabricRedirect);
        assert_eq!(resolved.egress_ifindex, 21);
        assert_eq!(resolved.tx_ifindex, 21);
        assert_eq!(
            resolved.src_mac,
            Some([0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x01])
        );
    }

    #[test]
    fn cluster_peer_return_fast_path_allows_sfmix_to_lan_reply() {
        let mut state = build_forwarding_state(&native_gre_pbr_snapshot(true));
        state.fabrics.push(FabricLink {
            parent_ifindex: 4,
            overlay_ifindex: 104,
            peer_addr: IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2)),
            peer_mac: [0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee],
            local_mac: [0x02, 0xbf, 0x72, 0xff, 0x00, 0x01],
        });
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));
        dynamic_neighbors.lock().expect("neighbors").insert(
            (5, IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
            NeighborEntry {
                mac: [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01],
            },
        );
        let meta = UserspaceDpMeta {
            ingress_ifindex: 4,
            protocol: PROTO_ICMP,
            ..UserspaceDpMeta::default()
        };

        let (decision, metadata) = cluster_peer_return_fast_path(
            &state,
            &dynamic_neighbors,
            meta,
            Some("sfmix"),
            IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        )
        .expect("fabric return fast path");

        assert_eq!(
            decision.resolution.disposition,
            ForwardingDisposition::ForwardCandidate
        );
        assert_eq!(decision.resolution.egress_ifindex, 5);
        assert_eq!(metadata.ingress_zone.as_ref(), "sfmix");
        assert_eq!(metadata.egress_zone.as_ref(), "lan");
        assert!(metadata.fabric_ingress);
        assert!(metadata.is_reverse);
    }

    #[test]
    fn cluster_peer_return_fast_path_skips_pure_tcp_syn() {
        let mut state = build_forwarding_state(&native_gre_pbr_snapshot(true));
        state.fabrics.push(FabricLink {
            parent_ifindex: 4,
            overlay_ifindex: 104,
            peer_addr: IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2)),
            peer_mac: [0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee],
            local_mac: [0x02, 0xbf, 0x72, 0xff, 0x00, 0x01],
        });
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));
        let meta = UserspaceDpMeta {
            ingress_ifindex: 4,
            protocol: PROTO_TCP,
            tcp_flags: TCP_FLAG_SYN,
            ..UserspaceDpMeta::default()
        };

        assert!(
            cluster_peer_return_fast_path(
                &state,
                &dynamic_neighbors,
                meta,
                Some("sfmix"),
                IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            )
            .is_none()
        );
    }

    #[test]
    fn reverse_session_prefers_interface_snat_ipv4_local_delivery() {
        let state = build_forwarding_state(&nat_snapshot());
        let ha_state = BTreeMap::new();
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));

        let resolved = reverse_resolution_for_session(
            &state,
            &ha_state,
            &dynamic_neighbors,
            IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
            "wan",
            false,
            monotonic_nanos() / 1_000_000_000,
            false,
        );

        assert_eq!(resolved.disposition, ForwardingDisposition::LocalDelivery);
        assert_eq!(resolved.local_ifindex, 12);
        assert_eq!(resolved.egress_ifindex, 12);
        assert_eq!(resolved.tx_ifindex, 12);
    }

    #[test]
    fn reverse_session_prefers_interface_snat_ipv6_local_delivery() {
        let state = build_forwarding_state(&nat_snapshot());
        let ha_state = BTreeMap::new();
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));

        let resolved = reverse_resolution_for_session(
            &state,
            &ha_state,
            &dynamic_neighbors,
            "2001:559:8585:80::8".parse().expect("dst"),
            "wan",
            false,
            monotonic_nanos() / 1_000_000_000,
            false,
        );

        assert_eq!(resolved.disposition, ForwardingDisposition::LocalDelivery);
        assert_eq!(resolved.local_ifindex, 12);
        assert_eq!(resolved.egress_ifindex, 12);
        assert_eq!(resolved.tx_ifindex, 12);
    }

    #[test]
    fn session_hit_keeps_interface_snat_ipv4_local_delivery() {
        let state = build_forwarding_state(&nat_snapshot());
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));
        let flow = SessionFlow {
            src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
            forward_key: SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
                src_port: 5201,
                dst_port: 43600,
            },
        };
        let decision = SessionDecision {
            resolution: interface_nat_local_resolution(&state, flow.dst_ip)
                .expect("interface nat local delivery"),
            nat: NatDecision::default(),
        };

        let resolved =
            lookup_forwarding_resolution_for_session(&state, &dynamic_neighbors, &flow, decision);

        assert_eq!(resolved.disposition, ForwardingDisposition::LocalDelivery);
        assert_eq!(resolved.local_ifindex, 12);
    }

    #[test]
    fn session_hit_keeps_interface_snat_ipv6_local_delivery() {
        let state = build_forwarding_state(&nat_snapshot());
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));
        let flow = SessionFlow {
            src_ip: "2001:559:8585:80::200".parse().expect("src"),
            dst_ip: "2001:559:8585:80::8".parse().expect("dst"),
            forward_key: SessionKey {
                addr_family: libc::AF_INET6 as u8,
                protocol: PROTO_TCP,
                src_ip: "2001:559:8585:80::200".parse().expect("src"),
                dst_ip: "2001:559:8585:80::8".parse().expect("dst"),
                src_port: 5201,
                dst_port: 43600,
            },
        };
        let decision = SessionDecision {
            resolution: interface_nat_local_resolution(&state, flow.dst_ip)
                .expect("interface nat local delivery"),
            nat: NatDecision::default(),
        };

        let resolved =
            lookup_forwarding_resolution_for_session(&state, &dynamic_neighbors, &flow, decision);

        assert_eq!(resolved.disposition, ForwardingDisposition::LocalDelivery);
        assert_eq!(resolved.local_ifindex, 12);
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
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
                neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x01, 0x00, 0x01]),
                tx_vlan_id: 0,
            },
            metadata: SessionMetadata {
                ingress_zone: Arc::<str>::from("wan"),
                egress_zone: Arc::<str>::from("lan"),
                owner_rg_id: 2,
                fabric_ingress: false,
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
                tunnel_endpoint_id: 0,
                next_hop: None,
                neighbor_mac: None,
                src_mac: None,
                tx_vlan_id: 0,
            },
            metadata: SessionMetadata {
                ingress_zone: Arc::<str>::from("wan"),
                egress_zone: Arc::<str>::from("lan"),
                owner_rg_id: 2,
                fabric_ingress: false,
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
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
                neighbor_mac: None,
                src_mac: None,
                tx_vlan_id: 0,
            },
            metadata: SessionMetadata {
                ingress_zone: Arc::<str>::from("wan"),
                egress_zone: Arc::<str>::from("lan"),
                owner_rg_id: 2,
                fabric_ingress: false,
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
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
                neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x01, 0x00, 0x01]),
                tx_vlan_id: 0,
            },
            metadata: SessionMetadata {
                ingress_zone: Arc::<str>::from("wan"),
                egress_zone: Arc::<str>::from("lan"),
                owner_rg_id: 2,
                fabric_ingress: false,
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
            tunnel_endpoint_id: 0,
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
                ..NatDecision::default()
            })
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
                ..NatDecision::default()
            })
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
    fn tcp_session_miss_local_delivers_interface_nat_address() {
        let state = build_forwarding_state(&nat_snapshot());
        let resolved_v4 = interface_nat_local_resolution_on_session_miss(
            &state,
            "172.16.80.8".parse().expect("v4"),
            PROTO_TCP,
        )
        .expect("tcp v4 nat local delivery");
        assert_eq!(
            resolved_v4.disposition,
            ForwardingDisposition::LocalDelivery
        );
        assert_eq!(resolved_v4.local_ifindex, 12);

        let resolved_v6 = interface_nat_local_resolution_on_session_miss(
            &state,
            "2001:559:8585:80::8".parse().expect("v6"),
            PROTO_UDP,
        )
        .expect("udp v6 nat local delivery");
        assert_eq!(
            resolved_v6.disposition,
            ForwardingDisposition::LocalDelivery
        );
        assert_eq!(resolved_v6.local_ifindex, 12);
    }

    #[test]
    fn tunnel_session_miss_blocks_interface_nat_local_delivery() {
        let mut snapshot = native_gre_snapshot(true);
        snapshot.source_nat_rules = vec![SourceNATRuleSnapshot {
            name: "lan-to-sfmix".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "sfmix".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            interface_mode: true,
            ..Default::default()
        }];
        let state = build_forwarding_state(&snapshot);
        let tunnel_snat_ip = "10.255.192.42".parse().expect("tunnel snat");
        assert!(should_block_tunnel_interface_nat_session_miss(
            &state,
            tunnel_snat_ip,
            PROTO_TCP,
        ));
        assert!(should_block_tunnel_interface_nat_session_miss(
            &state,
            tunnel_snat_ip,
            PROTO_UDP,
        ));
        assert!(should_block_tunnel_interface_nat_session_miss(
            &state,
            tunnel_snat_ip,
            PROTO_ICMP,
        ));
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
    fn tcp_session_miss_local_delivers_ingress_vlan_address() {
        let state = build_forwarding_state(&nat_snapshot());
        let resolved_v4 = ingress_interface_local_resolution_on_session_miss(
            &state,
            11,
            80,
            "172.16.80.8".parse().expect("dst"),
            PROTO_TCP,
        )
        .expect("tcp ingress local delivery");
        assert_eq!(
            resolved_v4.disposition,
            ForwardingDisposition::LocalDelivery
        );
        assert_eq!(resolved_v4.local_ifindex, 12);

        let resolved_v6 = ingress_interface_local_resolution_on_session_miss(
            &state,
            11,
            80,
            "2001:559:8585:80::8".parse().expect("dst"),
            PROTO_UDP,
        )
        .expect("udp ingress local delivery");
        assert_eq!(
            resolved_v6.disposition,
            ForwardingDisposition::LocalDelivery
        );
        assert_eq!(resolved_v6.local_ifindex, 12);
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
                fabric_ingress: false,
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
                synced: true,
                nat64_reverse: None,
            },
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
                synced: true,
                nat64_reverse: None,
            },
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
                    assert!(replayed_entry.metadata.synced);
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
                },
            ),
            (
                2,
                HAGroupRuntime {
                    active: true,
                    watchdog_timestamp: 12,
                },
            ),
        ]);
        let current = BTreeMap::from([
            (
                1,
                HAGroupRuntime {
                    active: false,
                    watchdog_timestamp: 21,
                },
            ),
            (
                2,
                HAGroupRuntime {
                    active: true,
                    watchdog_timestamp: 22,
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
                },
            ),
            (
                2,
                HAGroupRuntime {
                    active: true,
                    watchdog_timestamp: 12,
                },
            ),
        ]);
        let current = BTreeMap::from([
            (
                1,
                HAGroupRuntime {
                    active: true,
                    watchdog_timestamp: 21,
                },
            ),
            (
                2,
                HAGroupRuntime {
                    active: true,
                    watchdog_timestamp: 22,
                },
            ),
        ]);

        assert_eq!(activated_owner_rgs(&previous, &current), vec![1]);
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
                ..NatDecision::default()
            },
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
                    tunnel_endpoint_id: 0,
                    next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))),
                    neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
                    src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
                    tx_vlan_id: 80,
                },
                nat: NatDecision {
                    rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                    rewrite_dst: None,
                    ..NatDecision::default()
                },
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
                tunnel_endpoint_id: 0,
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

    #[test]
    fn rewrite_forwarded_frame_in_place_keeps_icmpv6_echo_identifier_and_sequence() {
        let src_ip = "2001:559:8585:ef00::100".parse::<Ipv6Addr>().unwrap();
        let dst_ip = "2607:f8b0:4005:814::200e".parse::<Ipv6Addr>().unwrap();
        let echo_id = 0x3e0f;
        let echo_seq = 0x80e9;

        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
            0,
            0x86dd,
        );
        frame.extend_from_slice(&[0x60, 0x07, 0x9f, 0x9c, 0x00, 0x18, PROTO_ICMPV6, 2]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&[
            128,
            0,
            0,
            0,
            (echo_id >> 8) as u8,
            echo_id as u8,
            (echo_seq >> 8) as u8,
            echo_seq as u8,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ]);
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
            flow_src_port: echo_id,
            ..UserspaceDpMeta::default()
        };
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 11,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V6(dst_ip)),
                neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
                tx_vlan_id: 80,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V6("2001:559:8585:50::8".parse().unwrap())),
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
        .expect("in-place v6 echo forward");
        let out = area.slice(0, frame_len as usize).expect("rewritten frame");

        let packet = &out[18..];
        assert_eq!(packet[40], 128);
        assert_eq!(packet[41], 0);
        assert_eq!(u16::from_be_bytes([packet[44], packet[45]]), echo_id);
        assert_eq!(u16::from_be_bytes([packet[46], packet[47]]), echo_seq);
        assert!(icmpv6_checksum_ok(packet));
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
                tunnel_endpoint_id: 0,
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
                tunnel_endpoint_id: 0,
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
            &ForwardingState::default(),
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
                tunnel_endpoint_id: 0,
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
            &ForwardingState::default(),
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
                tunnel_endpoint_id: 0,
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
            &WorkerBindingLookup::default(),
            0,
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
            None,
            false,
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
                tunnel_endpoint_id: 0,
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
            &WorkerBindingLookup::default(),
            0,
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
            None,
            false,
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
                tunnel_endpoint_id: 0,
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
            &WorkerBindingLookup::default(),
            0,
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
            None,
            false,
        )
        .expect("request");
        assert_eq!(req.expected_ports, Some((54688, 5201)));
    }

    #[test]
    fn build_live_forward_request_marks_session_fabric_redirect_for_nat_and_zone() {
        let forwarding = build_forwarding_state(&nat_snapshot_with_fabric());
        let fabric_redirect = resolve_fabric_redirect(&forwarding).expect("fabric redirect");
        let zone_redirect =
            resolve_zone_encoded_fabric_redirect(&forwarding, "wan").expect("zone redirect");
        let mut area = MmapArea::new(256).expect("mmap");
        area.slice_mut(0, 64).expect("slice").fill(0xaa);
        let ingress_ident = BindingIdentity {
            slot: 0,
            queue_id: 0,
            worker_id: 0,
            interface: Arc::<str>::from("fab0"),
            ifindex: 21,
        };
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            l4_offset: 34,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            flow_src_port: 5201,
            flow_dst_port: 44278,
            ..UserspaceDpMeta::default()
        };
        let decision = SessionDecision {
            resolution: fabric_redirect,
            nat: NatDecision {
                rewrite_dst: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
                ..NatDecision::default()
            },
        };
        let flow = SessionFlow {
            src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
            forward_key: SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
                src_port: 5201,
                dst_port: 44278,
            },
        };

        let req = build_live_forward_request(
            &area,
            &WorkerBindingLookup::default(),
            0,
            &ingress_ident,
            XdpDesc {
                addr: 0,
                len: 64,
                options: 0,
            },
            meta,
            &decision,
            &forwarding,
            Some(&flow),
            Some(&Arc::<str>::from("wan")),
            true,
        )
        .expect("request");

        assert!(req.apply_nat_on_fabric);
        assert_eq!(
            req.decision.resolution.disposition,
            ForwardingDisposition::FabricRedirect
        );
        assert_eq!(req.decision.resolution.src_mac, zone_redirect.src_mac);
    }

    #[test]
    fn build_live_forward_request_caches_target_binding_index() {
        let mut area = MmapArea::new(256).expect("mmap");
        area.slice_mut(0, 64).expect("slice").fill(0xaa);
        let ingress_ident = BindingIdentity {
            slot: 7,
            queue_id: 3,
            worker_id: 0,
            interface: Arc::<str>::from("ge-0-0-1"),
            ifindex: 10,
        };
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            l4_offset: 34,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            flow_src_port: 12345,
            flow_dst_port: 5201,
            ..UserspaceDpMeta::default()
        };
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 11,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))),
                neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
                tx_vlan_id: 80,
            },
            nat: NatDecision::default(),
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
                primary_v4: Some(Ipv4Addr::new(172, 16, 80, 8)),
                primary_v6: None,
            },
        );
        let mut lookup = WorkerBindingLookup::default();
        lookup.by_if_queue.insert((11, 3), 5);
        lookup.first_by_if.insert(11, 4);

        let req = build_live_forward_request(
            &area,
            &lookup,
            2,
            &ingress_ident,
            XdpDesc {
                addr: 0,
                len: 64,
                options: 0,
            },
            meta,
            &decision,
            &forwarding,
            None,
            None,
            false,
        )
        .expect("request");

        assert_eq!(req.target_ifindex, 11);
        assert_eq!(req.target_binding_index, Some(5));
    }

    #[test]
    fn build_forwarded_frame_applies_nat_on_fabric_when_requested() {
        let forwarding = build_forwarding_state(&nat_snapshot_with_fabric());
        let fabric_redirect = resolve_fabric_redirect(&forwarding).expect("fabric redirect");
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x10, 0xdb, 0xff, 0x10, 0x01],
            0,
            0x0800,
        );
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x28, 0x00, 0x02, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00, 172, 16, 80,
            200, 172, 16, 80, 8, 0x14, 0x51, 0xac, 0xf6, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
            0x02, 0x50, 0x12, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        let ip_sum = checksum16(&frame[14..34]);
        frame[24] = (ip_sum >> 8) as u8;
        frame[25] = ip_sum as u8;
        recompute_l4_checksum_ipv4(&mut frame[14..], 20, PROTO_TCP, false).expect("tcp sum");
        assert!(tcp_checksum_ok_ipv4(&frame[14..]));
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            flow_src_port: 5201,
            flow_dst_port: 44278,
            ..UserspaceDpMeta::default()
        };
        let decision = SessionDecision {
            resolution: fabric_redirect,
            nat: NatDecision {
                rewrite_dst: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
                ..NatDecision::default()
            },
        };

        let no_nat = build_forwarded_frame_from_frame(
            &frame,
            meta,
            &decision,
            &forwarding,
            false,
            Some((5201, 44278)),
        )
        .expect("frame without nat");
        assert_eq!(&no_nat[30..34], &[172, 16, 80, 8]);

        let nat = build_forwarded_frame_from_frame(
            &frame,
            meta,
            &decision,
            &forwarding,
            true,
            Some((5201, 44278)),
        )
        .expect("frame with nat");
        assert_eq!(&nat[30..34], &[10, 0, 61, 102]);
        assert!(tcp_checksum_ok_ipv4(&nat[14..]));
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
                tunnel_endpoint_id: 0,
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
            &ForwardingState::default(),
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
                tunnel_endpoint_id: 0,
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
            &ForwardingState::default(),
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
                tunnel_endpoint_id: 0,
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
            &ForwardingState::default(),
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
                tunnel_endpoint_id: 0,
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
            &ForwardingState::default(),
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
                tunnel_endpoint_id: 0,
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
                tunnel_endpoint_id: 0,
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
                tunnel_endpoint_id: 0,
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
                tunnel_endpoint_id: 0,
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
    fn authoritative_forward_ports_prefers_frame_tuple_over_metadata_when_flow_missing() {
        let src_ip = Ipv4Addr::new(10, 0, 61, 102);
        let dst_ip = Ipv4Addr::new(172, 16, 80, 200);
        let frame_src_port = 1041u16;
        let meta_src_port = 55068u16;
        let dst_port = 5201u16;
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
            0,
            0x0800,
        );
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x30, 0x00, 0x01, 0x00, 0x00, 64, PROTO_TCP, 0x00, 0x00,
        ]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&frame_src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&[
            0x31, 0x96, 0xc8, 0x32, 0x08, 0xf0, 0x5a, 0xc6, 0x50, 0x18, 0x00, 0x40, 0x00, 0x00,
            0x00, 0x00, b't', b'e', b's', b't', b'd', b'a', b't', b'a',
        ]);
        let ip_csum = checksum16(&frame[14..34]);
        frame[24..26].copy_from_slice(&ip_csum.to_be_bytes());
        recompute_l4_checksum_ipv4(&mut frame[14..], 20, PROTO_TCP, false).expect("tcp sum");

        let mut flow_src_addr = [0u8; 16];
        flow_src_addr[..4].copy_from_slice(&src_ip.octets());
        let mut flow_dst_addr = [0u8; 16];
        flow_dst_addr[..4].copy_from_slice(&dst_ip.octets());
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            l4_offset: 34,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            flow_src_addr,
            flow_dst_addr,
            flow_src_port: meta_src_port,
            flow_dst_port: dst_port,
            ..UserspaceDpMeta::default()
        };

        // Live frame ports preferred over metadata (flow > frame > meta)
        assert_eq!(
            authoritative_forward_ports(&frame, meta, None),
            Some((frame_src_port, dst_port))
        );
    }

    #[test]
    fn authoritative_forward_ports_falls_back_to_live_frame_ports_when_metadata_missing() {
        let src_ip = "2001:559:8585:ef00::102".parse::<Ipv6Addr>().unwrap();
        let dst_ip = "2001:559:8585:80::200".parse::<Ipv6Addr>().unwrap();
        let src_port = 55068u16;
        let dst_port = 5201u16;
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
            0,
            0x86dd,
        );
        frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x14, PROTO_UDP, 64]);
        frame.extend_from_slice(&src_ip.octets());
        frame.extend_from_slice(&dst_ip.octets());
        frame.extend_from_slice(&src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&[0x00, 0x14, 0x00, 0x00]);
        frame.extend_from_slice(b"userspace-udp");
        recompute_l4_checksum_ipv6(&mut frame[14..], PROTO_UDP).expect("udp sum");

        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            l4_offset: 54,
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_UDP,
            ..UserspaceDpMeta::default()
        };

        assert_eq!(
            authoritative_forward_ports(&frame, meta, None),
            Some((src_port, dst_port))
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
                tunnel_endpoint_id: 0,
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
    fn segment_forwarded_tcp_frames_keeps_ipv4_snat_inside_native_gre() {
        let src_ip = Ipv4Addr::new(10, 0, 61, 102);
        let dst_ip = Ipv4Addr::new(10, 255, 192, 41);
        let snat_ip = Ipv4Addr::new(10, 255, 192, 42);
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
            0x52, 0x04, 0xc1, 0xa3, 0x73, 0x7f, 0x63, 0x1c, 0x80, 0x10, 0x00, 0x3f, 0x00, 0x00,
            0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x91, 0x9b, 0x0d, 0x5f, 0xd3, 0x53, 0x0f, 0x7f,
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
        let state = build_forwarding_state(&native_gre_snapshot(true));
        let decision = SessionDecision {
            resolution: lookup_forwarding_resolution_v4(
                &state,
                None,
                dst_ip,
                "sfmix.inet.0",
                0,
                true,
            ),
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(snat_ip)),
                ..NatDecision::default()
            },
        };

        let segments = segment_forwarded_tcp_frames(
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            &decision,
            &state,
            Some((src_port, dst_port)),
        )
        .expect("segmented native gre");
        assert!(segments.len() > 1);
        let outer_eth_len = 18usize;
        let outer_ip_len = 40usize;
        let gre_len = 4usize;
        let transport_mtu = 1500usize;
        let inner_start = outer_eth_len + outer_ip_len + gre_len;
        let mut total_payload = 0usize;
        let mut expected_seq = 0x5204c1a3u32;
        for seg in &segments {
            assert!(seg.len() >= outer_eth_len);
            assert!(
                seg.len() - outer_eth_len <= transport_mtu,
                "native GRE segment exceeds transport MTU: {}",
                seg.len() - outer_eth_len
            );
            assert_eq!(&seg[16..18], &[0x86, 0xdd]);
            assert_eq!(seg[24], PROTO_GRE);
            let inner = &seg[inner_start..];
            assert_eq!(&inner[12..16], &snat_ip.octets());
            assert_eq!(&inner[16..20], &dst_ip.octets());
            assert!(tcp_checksum_ok_ipv4(inner));
            let tcp = &inner[20..];
            assert_eq!(
                (
                    u16::from_be_bytes([tcp[0], tcp[1]]),
                    u16::from_be_bytes([tcp[2], tcp[3]])
                ),
                (src_port, dst_port)
            );
            let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
            assert_eq!(seq, expected_seq);
            let seg_payload = inner.len() - 20 - tcp_header_len;
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
                    tunnel_endpoint_id: 0,
                    next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))),
                    neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
                    src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
                    tx_vlan_id: 80,
                },
                nat: NatDecision {
                    rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                    rewrite_dst: None,
                    ..NatDecision::default()
                },
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
                    tunnel_endpoint_id: 0,
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

    fn build_ipv6_gre_frame(
        inner_packet: &[u8],
        src: Ipv6Addr,
        dst: Ipv6Addr,
        key: Option<u32>,
    ) -> Vec<u8> {
        let mut frame = Vec::new();
        write_eth_header(
            &mut frame,
            [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01],
            [0xde, 0xad, 0xbe, 0xef, 0x00, 0x02],
            0,
            0x86dd,
        );
        let gre_len = if key.is_some() { 8usize } else { 4usize };
        let payload_len = u16::try_from(gre_len + inner_packet.len()).unwrap();
        frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
        frame.extend_from_slice(&payload_len.to_be_bytes());
        frame.push(PROTO_GRE);
        frame.push(64);
        frame.extend_from_slice(&src.octets());
        frame.extend_from_slice(&dst.octets());
        let flags = if key.is_some() { 0x2000u16 } else { 0u16 };
        frame.extend_from_slice(&flags.to_be_bytes());
        frame.extend_from_slice(
            &(if inner_packet.first().map(|b| b >> 4) == Some(4) {
                0x0800u16
            } else {
                0x86ddu16
            })
            .to_be_bytes(),
        );
        if let Some(key) = key {
            frame.extend_from_slice(&key.to_be_bytes());
        }
        frame.extend_from_slice(inner_packet);
        frame
    }

    fn native_gre_outer_meta() -> UserspaceDpMeta {
        UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            ingress_ifindex: 6,
            rx_queue_index: 0,
            l3_offset: 14,
            l4_offset: 54,
            payload_offset: 58,
            pkt_len: 92,
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_GRE,
            ..UserspaceDpMeta::default()
        }
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
            synced: false,
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
            synced: false,
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
            synced: false,
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
                synced: true,
                nat64_reverse: None,
            },
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
}
