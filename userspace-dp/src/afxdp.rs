use super::{
    BindingStatus, ConfigSnapshot, ExceptionStatus, InjectPacketRequest, InterfaceSnapshot,
    PacketResolution,
};
use chrono::Utc;
use core::ffi::{c_int, c_void};
use core::num::NonZeroU32;
use core::ptr::NonNull;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use std::collections::{BTreeMap, VecDeque};
use std::ffi::CString;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use xdpilone::xdp::XdpDesc;
use xdpilone::{BufIdx, IfInfo, Socket, SocketConfig, Umem, UmemConfig, User};

const USERSPACE_META_MAGIC: u32 = 0x4250_5553;
const USERSPACE_META_VERSION: u16 = 2;
const UMEM_FRAME_SIZE: u32 = 4096;
const UMEM_HEADROOM: u32 = 256;
const RX_BATCH_SIZE: u32 = 64;
const RESERVED_TX_FRAMES: u32 = 64;
const STATS_POLL_INTERVAL: Duration = Duration::from_secs(1);
const HEARTBEAT_UPDATE_INTERVAL: Duration = Duration::from_millis(250);
const HEARTBEAT_STALE_AFTER: Duration = Duration::from_secs(5);
const MAX_RECENT_EXCEPTIONS: usize = 32;

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
    config_generation: u64,
    fib_generation: u32,
    reserved2: u32,
}

pub struct Coordinator {
    map_fd: Option<OwnedFd>,
    heartbeat_map_fd: Option<OwnedFd>,
    live: BTreeMap<u32, Arc<BindingLiveState>>,
    identities: BTreeMap<u32, BindingIdentity>,
    workers: BTreeMap<u32, WorkerHandle>,
    forwarding: ForwardingState,
    recent_exceptions: Arc<Mutex<VecDeque<ExceptionStatus>>>,
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
            live: BTreeMap::new(),
            identities: BTreeMap::new(),
            workers: BTreeMap::new(),
            forwarding: ForwardingState::default(),
            recent_exceptions: Arc::new(Mutex::new(VecDeque::with_capacity(MAX_RECENT_EXCEPTIONS))),
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
        self.map_fd = None;
        self.heartbeat_map_fd = None;
        self.forwarding = ForwardingState::default();
        if let Ok(mut recent) = self.recent_exceptions.lock() {
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
                interface: binding.interface.clone(),
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
                    ring_entries,
                });
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
        for (worker_id, binding_plans) in workers {
            let plan_count = binding_plans.len();
            let stop = Arc::new(AtomicBool::new(false));
            let heartbeat = Arc::new(AtomicI64::new(now_nanos()));
            let recent_exceptions = self.recent_exceptions.clone();
            let last_resolution = self.last_resolution.clone();
            let stop_clone = stop.clone();
            let heartbeat_clone = heartbeat.clone();
            let validation = self.validation;
            let forwarding = forwarding.clone();
            let join = thread::Builder::new()
                .name(format!("bpfrx-userspace-worker-{worker_id}"))
                .spawn(move || {
                    worker_loop(
                        worker_id,
                        binding_plans,
                        validation,
                        forwarding,
                        recent_exceptions,
                        last_resolution,
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

    pub fn last_resolution(&self) -> Option<PacketResolution> {
        self.last_resolution
            .lock()
            .ok()
            .and_then(|last| last.clone())
    }

    pub fn worker_heartbeats(&self) -> Vec<chrono::DateTime<Utc>> {
        self.workers
            .iter()
            .map(|(_, handle)| {
                chrono::DateTime::<Utc>::from_timestamp_nanos(
                    handle.heartbeat.load(Ordering::Relaxed),
                )
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
                    let resolution = lookup_forwarding_resolution(&self.forwarding, dst);
                    record_forwarding_disposition(
                        &ident,
                        live,
                        resolution,
                        packet_length,
                        Some(meta),
                        &self.recent_exceptions,
                        &self.last_resolution,
                    );
                    if req.emit_on_wire {
                        let Some(egress) = self.forwarding.egress.get(&resolution.egress_ifindex) else {
                            return Err(format!(
                                "no egress interface metadata for ifindex {}",
                                resolution.egress_ifindex
                            ));
                        };
                        if resolution.disposition != ForwardingDisposition::ForwardCandidate {
                            return Err(format!(
                                "destination is not forwardable via userspace TX: {}",
                                resolution.status().disposition
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
                        let target_live = self
                            .live
                            .get(&target_slot)
                            .ok_or_else(|| format!("binding slot {} has no live state", target_slot))?;
                        let frame = build_injected_packet(&req, dst, resolution, egress)?;
                        target_live.enqueue_tx(TxRequest { bytes: frame })?;
                    }
                } else {
                    record_exception(
                        &self.recent_exceptions,
                        &ident,
                        "invalid_destination_ip",
                        packet_length,
                        Some(meta),
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
        );
        Ok(())
    }

    pub fn refresh_bindings(&self, bindings: &mut [BindingStatus]) {
        for binding in bindings.iter_mut() {
            if let Some(live) = self.live.get(&binding.slot) {
                let snap = live.snapshot();
                binding.bound = snap.bound;
                binding.xsk_registered = snap.xsk_registered;
                binding.socket_fd = snap.socket_fd;
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
                binding.kernel_rx_dropped = snap.kernel_rx_dropped;
                binding.kernel_rx_invalid_descs = snap.kernel_rx_invalid_descs;
                binding.tx_packets = snap.tx_packets;
                binding.tx_bytes = snap.tx_bytes;
                binding.tx_errors = snap.tx_errors;
                binding.last_heartbeat = snap.last_heartbeat;
                binding.last_error = snap.last_error;
                binding.ready = binding.ready
                    && binding.registered
                    && binding.bound
                    && binding.xsk_registered
                    && heartbeat_fresh(snap.last_heartbeat);
            } else {
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
                binding.kernel_rx_dropped = 0;
                binding.kernel_rx_invalid_descs = 0;
                binding.tx_packets = 0;
                binding.tx_bytes = 0;
                binding.tx_errors = 0;
                binding.last_heartbeat = None;
                binding.last_error.clear();
                binding.ready = false;
            }
        }
    }
}

struct WorkerHandle {
    stop: Arc<AtomicBool>,
    heartbeat: Arc<AtomicI64>,
    join: Option<JoinHandle<()>>,
}

struct BindingPlan {
    status: BindingStatus,
    live: Arc<BindingLiveState>,
    xsk_map_fd: c_int,
    heartbeat_map_fd: c_int,
    ring_entries: u32,
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
    local_v4: Vec<Ipv4Addr>,
    local_v6: Vec<Ipv6Addr>,
    connected_v4: Vec<ConnectedRouteV4>,
    connected_v6: Vec<ConnectedRouteV6>,
    routes_v4: Vec<RouteEntryV4>,
    routes_v6: Vec<RouteEntryV6>,
    neighbors: BTreeMap<(i32, IpAddr), NeighborEntry>,
    ifindex_to_name: BTreeMap<i32, String>,
    egress: BTreeMap<i32, EgressInterface>,
}

#[derive(Clone, Copy, Debug)]
struct ConnectedRouteV4 {
    prefix: Ipv4Net,
    ifindex: i32,
}

#[derive(Clone, Copy, Debug)]
struct ConnectedRouteV6 {
    prefix: Ipv6Net,
    ifindex: i32,
}

#[derive(Clone, Copy, Debug)]
struct RouteEntryV4 {
    prefix: Ipv4Net,
    ifindex: i32,
    next_hop: Option<Ipv4Addr>,
    discard: bool,
    next_table: bool,
}

#[derive(Clone, Copy, Debug)]
struct RouteEntryV6 {
    prefix: Ipv6Net,
    ifindex: i32,
    next_hop: Option<Ipv6Addr>,
    discard: bool,
    next_table: bool,
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
struct NeighborEntry {
    mac: [u8; 6],
}

#[derive(Clone, Copy, Debug)]
struct EgressInterface {
    bind_ifindex: i32,
    vlan_id: u16,
    src_mac: [u8; 6],
    primary_v4: Option<Ipv4Addr>,
    primary_v6: Option<Ipv6Addr>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ForwardingDisposition {
    LocalDelivery,
    ForwardCandidate,
    NoRoute,
    MissingNeighbor,
    DiscardRoute,
    NextTableUnsupported,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ForwardingResolution {
    disposition: ForwardingDisposition,
    local_ifindex: i32,
    egress_ifindex: i32,
    next_hop: Option<IpAddr>,
    neighbor_mac: Option<[u8; 6]>,
}

impl ForwardingResolution {
    fn status(self) -> PacketResolution {
        PacketResolution {
            disposition: match self.disposition {
                ForwardingDisposition::LocalDelivery => "local_delivery",
                ForwardingDisposition::ForwardCandidate => "forward_candidate",
                ForwardingDisposition::NoRoute => "no_route",
                ForwardingDisposition::MissingNeighbor => "missing_neighbor",
                ForwardingDisposition::DiscardRoute => "discard_route",
                ForwardingDisposition::NextTableUnsupported => "next_table_unsupported",
            }
            .to_string(),
            local_ifindex: self.local_ifindex,
            egress_ifindex: self.egress_ifindex,
            next_hop: self.next_hop.map(|ip| ip.to_string()).unwrap_or_default(),
            neighbor_mac: self.neighbor_mac.map(format_mac).unwrap_or_default(),
        }
    }
}

struct BindingWorker {
    slot: u32,
    queue_id: u32,
    worker_id: u32,
    interface: String,
    ifindex: i32,
    live: Arc<BindingLiveState>,
    area: MmapArea,
    _umem: Umem,
    user: User,
    device: xdpilone::DeviceQueue,
    rx: xdpilone::RingRx,
    tx: xdpilone::RingTx,
    free_tx_frames: VecDeque<u64>,
    heartbeat_map_fd: c_int,
    last_heartbeat_update: Instant,
}

#[derive(Clone, Debug)]
struct BindingIdentity {
    slot: u32,
    queue_id: u32,
    worker_id: u32,
    interface: String,
    ifindex: i32,
}

#[derive(Clone, Debug)]
struct TxRequest {
    bytes: Vec<u8>,
}

impl BindingWorker {
    fn create(
        binding: &BindingStatus,
        ring_entries: u32,
        xsk_map_fd: c_int,
        heartbeat_map_fd: c_int,
        live: Arc<BindingLiveState>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let area = MmapArea::new((ring_entries as usize) * (UMEM_FRAME_SIZE as usize))?;
        let umem_cfg = UmemConfig {
            fill_size: ring_entries,
            complete_size: ring_entries,
            frame_size: UMEM_FRAME_SIZE,
            headroom: UMEM_HEADROOM,
            flags: 0,
        };
        let umem = unsafe { Umem::new(umem_cfg, area.as_nonnull_slice()) }
            .map_err(|e| format!("create umem: {e}"))?;
        let info = ifinfo_from_binding(binding)?;
        let sock = Socket::with_shared(&info, &umem).map_err(|e| format!("create socket: {e}"))?;
        let mut device = umem
            .fq_cq(&sock)
            .map_err(|e| format!("create fq/cq: {e}"))?;
        let user = umem
            .rx_tx(
                &sock,
                &SocketConfig {
                    rx_size: NonZeroU32::new(ring_entries),
                    tx_size: NonZeroU32::new(ring_entries),
                    bind_flags: SocketConfig::XDP_BIND_NEED_WAKEUP,
                },
            )
            .map_err(|e| format!("configure rx ring: {e}"))?;
        let rx = user.map_rx().map_err(|e| format!("map rx ring: {e}"))?;
        let tx = user.map_tx().map_err(|e| format!("map tx ring: {e}"))?;
        umem.bind(&user)
            .map_err(|e| format!("bind AF_XDP socket: {e}"))?;
        let reserved_tx = RESERVED_TX_FRAMES.min(ring_entries.saturating_sub(1)).max(1);
        prime_fill_ring(&umem, &mut device, reserved_tx)?;
        let mut free_tx_frames = VecDeque::with_capacity(reserved_tx as usize);
        for idx in 0..reserved_tx {
            if let Some(frame) = umem.frame(BufIdx(idx)) {
                free_tx_frames.push_back(frame.offset);
            }
        }

        live.set_bound(user.as_raw_fd());
        if let Err(err) = register_xsk_slot(xsk_map_fd, binding.slot, user.as_raw_fd()) {
            live.set_error(format!("register XSK slot: {err}"));
        } else {
            live.set_xsk_registered(true);
            live.clear_error();
        }
        if let Err(err) = touch_heartbeat(heartbeat_map_fd, binding.slot, &live) {
            live.set_error(format!("update heartbeat slot: {err}"));
        }
        Ok(Self {
            slot: binding.slot,
            queue_id: binding.queue_id,
            worker_id: binding.worker_id,
            interface: binding.interface.clone(),
            ifindex: binding.ifindex,
            live,
            area,
            _umem: umem,
            user,
            device,
            rx,
            tx,
            free_tx_frames,
            heartbeat_map_fd,
            last_heartbeat_update: Instant::now(),
        })
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
    binding: &mut BindingWorker,
    validation: ValidationState,
    forwarding: &ForwardingState,
    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
    last_resolution: &Arc<Mutex<Option<PacketResolution>>>,
    poll_stats: bool,
) -> bool {
    let ident = binding.identity();
    maybe_touch_heartbeat(binding);
    reap_tx_completions(binding);
    drain_pending_tx(binding);
    if binding.device.needs_wakeup() {
        binding.device.wake();
        binding.live.rx_wakeups.fetch_add(1, Ordering::Relaxed);
    }
    let available = binding.rx.available().min(RX_BATCH_SIZE);
    if available == 0 {
        if poll_stats {
            poll_kernel_stats(&binding.user, &binding.live);
        }
        return false;
    }

    let mut received = binding.rx.receive(available);
    let mut recycle = Vec::with_capacity(available as usize);
    let mut batch_packets = 0u64;
    let mut batch_bytes = 0u64;
    while let Some(desc) = received.read() {
        batch_packets += 1;
        batch_bytes += desc.len as u64;
        if let Some(meta) = try_parse_metadata(&binding.area, desc) {
            binding
                .live
                .metadata_packets
                .fetch_add(1, Ordering::Relaxed);
            let disposition = classify_metadata(meta, validation);
            record_disposition(
                &ident,
                &binding.live,
                disposition,
                desc.len as u32,
                Some(meta),
                recent_exceptions,
            );
            if disposition == PacketDisposition::Valid {
                record_forwarding_disposition(
                    &ident,
                    &binding.live,
                    resolve_forwarding(&binding.area, desc, meta, forwarding),
                    desc.len as u32,
                    Some(meta),
                    recent_exceptions,
                    last_resolution,
                );
            }
        } else {
            binding.live.metadata_errors.fetch_add(1, Ordering::Relaxed);
            record_exception(
                recent_exceptions,
                &ident,
                "metadata_parse",
                desc.len as u32,
                None,
            );
        }
        recycle.push(desc.addr);
    }
    received.release();
    if !recycle.is_empty() {
        let mut fill = binding.device.fill(recycle.len() as u32);
        let inserted = fill.insert(recycle.into_iter());
        fill.commit();
        if inserted == 0 {
            binding
                .live
                .set_error("fill ring insert returned 0".to_string());
        }
    }
    binding
        .live
        .rx_packets
        .fetch_add(batch_packets, Ordering::Relaxed);
    binding
        .live
        .rx_bytes
        .fetch_add(batch_bytes, Ordering::Relaxed);
    binding.live.rx_batches.fetch_add(1, Ordering::Relaxed);
    if poll_stats {
        poll_kernel_stats(&binding.user, &binding.live);
    }
    true
}

fn reap_tx_completions(binding: &mut BindingWorker) {
    let available = binding.device.available();
    if available == 0 {
        return;
    }
    let mut completed = binding.device.complete(available);
    while let Some(offset) = completed.read() {
        binding.free_tx_frames.push_back(offset);
    }
    completed.release();
}

fn drain_pending_tx(binding: &mut BindingWorker) {
    let mut pending = binding.live.take_pending_tx();
    if pending.is_empty() {
        return;
    }
    while let Some(req) = pending.pop_front() {
        match transmit_frame(binding, &req.bytes) {
            Ok(len) => {
                binding.live.tx_packets.fetch_add(1, Ordering::Relaxed);
                binding.live.tx_bytes.fetch_add(len as u64, Ordering::Relaxed);
            }
            Err(err) => {
                binding.live.tx_errors.fetch_add(1, Ordering::Relaxed);
                binding.live.set_error(err);
            }
        }
    }
}

fn transmit_frame(binding: &mut BindingWorker, frame: &[u8]) -> Result<usize, String> {
    let Some(offset) = binding.free_tx_frames.pop_front() else {
        return Err("no free TX frame available".to_string());
    };
    let Some(area) = binding.area.slice_mut(offset as usize, frame.len()) else {
        binding.free_tx_frames.push_front(offset);
        return Err(format!("tx frame slice out of range: offset={offset} len={}", frame.len()));
    };
    area.copy_from_slice(frame);
    let mut writer = binding.tx.transmit(1);
    let inserted = writer.insert(core::iter::once(XdpDesc {
        addr: offset,
        len: frame.len() as u32,
        options: 0,
    }));
    writer.commit();
    drop(writer);
    if inserted != 1 {
        binding.free_tx_frames.push_front(offset);
        return Err("tx ring insert failed".to_string());
    }
    if binding.tx.needs_wakeup() {
        binding.tx.wake();
    }
    Ok(frame.len())
}

fn record_exception(
    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
    binding: &BindingIdentity,
    reason: &str,
    packet_length: u32,
    meta: Option<UserspaceDpMeta>,
) {
    if let Ok(mut recent) = recent_exceptions.lock() {
        push_recent_exception(
            &mut recent,
            ExceptionStatus {
                timestamp: Utc::now(),
                slot: binding.slot,
                queue_id: binding.queue_id,
                worker_id: binding.worker_id,
                interface: binding.interface.clone(),
                ifindex: binding.ifindex,
                reason: reason.to_string(),
                packet_length,
                addr_family: meta.map(|m| m.addr_family).unwrap_or(0),
                protocol: meta.map(|m| m.protocol).unwrap_or(0),
                config_generation: meta.map(|m| m.config_generation).unwrap_or(0),
                fib_generation: meta.map(|m| m.fib_generation).unwrap_or(0),
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
    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
    last_resolution: &Arc<Mutex<Option<PacketResolution>>>,
) {
    if let Ok(mut last) = last_resolution.lock() {
        *last = Some(resolution.status());
    }
    match resolution.disposition {
        ForwardingDisposition::LocalDelivery => {
            live.local_delivery_packets.fetch_add(1, Ordering::Relaxed);
        }
        ForwardingDisposition::ForwardCandidate => {
            live.forward_candidate_packets
                .fetch_add(1, Ordering::Relaxed);
        }
        ForwardingDisposition::NoRoute => {
            live.route_miss_packets.fetch_add(1, Ordering::Relaxed);
            record_exception(recent_exceptions, binding, "no_route", packet_length, meta);
        }
        ForwardingDisposition::MissingNeighbor => {
            live.neighbor_miss_packets.fetch_add(1, Ordering::Relaxed);
            record_exception(
                recent_exceptions,
                binding,
                "missing_neighbor",
                packet_length,
                meta,
            );
        }
        ForwardingDisposition::DiscardRoute => {
            live.discard_route_packets.fetch_add(1, Ordering::Relaxed);
            record_exception(
                recent_exceptions,
                binding,
                "discard_route",
                packet_length,
                meta,
            );
        }
        ForwardingDisposition::NextTableUnsupported => {
            live.next_table_packets.fetch_add(1, Ordering::Relaxed);
            record_exception(
                recent_exceptions,
                binding,
                "next_table_unsupported",
                packet_length,
                meta,
            );
        }
    }
}

fn worker_loop(
    worker_id: u32,
    binding_plans: Vec<BindingPlan>,
    validation: ValidationState,
    forwarding: Arc<ForwardingState>,
    recent_exceptions: Arc<Mutex<VecDeque<ExceptionStatus>>>,
    last_resolution: Arc<Mutex<Option<PacketResolution>>>,
    stop: Arc<AtomicBool>,
    heartbeat: Arc<AtomicI64>,
) {
    pin_current_thread(worker_id);
    let mut bindings = Vec::with_capacity(binding_plans.len());
    for plan in binding_plans {
        match BindingWorker::create(
            &plan.status,
            plan.ring_entries,
            plan.xsk_map_fd,
            plan.heartbeat_map_fd,
            plan.live.clone(),
        ) {
            Ok(binding) => bindings.push(binding),
            Err(err) => plan.live.set_error(err.to_string()),
        }
    }
    let mut last_stats_poll = Instant::now();
    while !stop.load(Ordering::Relaxed) {
        heartbeat.store(now_nanos(), Ordering::Relaxed);
        let poll_stats = last_stats_poll.elapsed() >= STATS_POLL_INTERVAL;
        let mut did_work = false;
        for binding in bindings.iter_mut() {
            if poll_binding(
                binding,
                validation,
                &forwarding,
                &recent_exceptions,
                &last_resolution,
                poll_stats,
            ) {
                did_work = true;
            }
        }
        if poll_stats {
            last_stats_poll = Instant::now();
        }
        if !did_work {
            thread::sleep(Duration::from_millis(1));
        }
    }
    heartbeat.store(now_nanos(), Ordering::Relaxed);
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

fn now_nanos() -> i64 {
    Utc::now().timestamp_nanos_opt().unwrap_or(0)
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

fn timestamp_from_nanos(nanos: i64) -> Option<chrono::DateTime<Utc>> {
    if nanos <= 0 {
        return None;
    }
    Some(chrono::DateTime::<Utc>::from_timestamp_nanos(nanos))
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

fn poll_kernel_stats(user: &User, live: &BindingLiveState) {
    match user.statistics_v2() {
        Ok(stats) => {
            live.kernel_rx_dropped
                .store(stats.rx_dropped, Ordering::Relaxed);
            live.kernel_rx_invalid_descs
                .store(stats.rx_invalid_descs, Ordering::Relaxed);
        }
        Err(err) => live.set_error(format!("read XSK stats: {err}")),
    }
}

fn prime_fill_ring(
    umem: &Umem,
    device: &mut xdpilone::DeviceQueue,
    skip_frames: u32,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let frame_count = umem.len_frames();
    let inserted = {
        let available_frames = frame_count.saturating_sub(skip_frames);
        let mut fill = device.fill(available_frames);
        let inserted = fill.insert(
            (skip_frames..frame_count)
                .filter_map(|idx| umem.frame(BufIdx(idx)).map(|frame| frame.offset)),
        );
        fill.commit();
        inserted
    };
    let want = frame_count.saturating_sub(skip_frames);
    if inserted != want {
        return Err(format!("prefill fill ring inserted {inserted}/{want} frames").into());
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

fn build_forwarding_state(snapshot: &ConfigSnapshot) -> ForwardingState {
    let mut state = ForwardingState::default();
    let mut name_to_ifindex = BTreeMap::new();
    let mut linux_to_ifindex = BTreeMap::new();
    let mut mac_by_ifindex = BTreeMap::new();

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
        if let Some(mac) = parse_mac(&iface.hardware_addr) {
            mac_by_ifindex.insert(iface.ifindex, mac);
        }
        for addr in &iface.addresses {
            let Ok(net) = addr.address.parse::<IpNet>() else {
                continue;
            };
            match net {
                IpNet::V4(v4) => {
                    state.local_v4.push(v4.addr());
                    state.connected_v4.push(ConnectedRouteV4 {
                        prefix: v4,
                        ifindex: iface.ifindex,
                    });
                }
                IpNet::V6(v6) => {
                    state.local_v6.push(v6.addr());
                    state.connected_v6.push(ConnectedRouteV6 {
                        prefix: v6,
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
        let src_mac = match parse_mac(&iface.hardware_addr).or_else(|| mac_by_ifindex.get(&bind_ifindex).copied()) {
            Some(mac) => mac,
            None => continue,
        };
        state.egress.insert(
            iface.ifindex,
            EgressInterface {
                bind_ifindex,
                vlan_id: iface.vlan_id.max(0) as u16,
                src_mac,
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
            state.routes_v4.push(RouteEntryV4 {
                prefix,
                ifindex,
                next_hop,
                discard: route.discard,
                next_table: !route.next_table.is_empty(),
            });
            continue;
        }
        if let Ok(prefix) = route.destination.parse::<Ipv6Net>() {
            let (next_hop, ifindex) =
                resolve_route_target_v6(route, &name_to_ifindex, &linux_to_ifindex, &state);
            state.routes_v6.push(RouteEntryV6 {
                prefix,
                ifindex,
                next_hop,
                discard: route.discard,
                next_table: !route.next_table.is_empty(),
            });
        }
    }
    state
        .routes_v4
        .sort_by(|a, b| b.prefix.prefix_len().cmp(&a.prefix.prefix_len()));
    state
        .routes_v6
        .sort_by(|a, b| b.prefix.prefix_len().cmp(&a.prefix.prefix_len()));

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
    state
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
        .find(|entry| entry.prefix.contains(&ip))
        .map(|entry| entry.ifindex)
}

fn infer_connected_ifindex_v6(state: &ForwardingState, ip: Ipv6Addr) -> Option<i32> {
    state
        .connected_v6
        .iter()
        .find(|entry| entry.prefix.contains(&ip))
        .map(|entry| entry.ifindex)
}

fn neighbor_state_usable(state: &str) -> bool {
    !(state.contains("failed") || state.contains("incomplete"))
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
) -> ForwardingResolution {
    let Some(dst) = parse_packet_destination(area, desc, meta) else {
        return ForwardingResolution {
            disposition: ForwardingDisposition::NoRoute,
            local_ifindex: 0,
            egress_ifindex: 0,
            next_hop: None,
            neighbor_mac: None,
        };
    };
    lookup_forwarding_resolution(state, dst)
}

fn lookup_forwarding_for_ip(state: &ForwardingState, dst: IpAddr) -> ForwardingDisposition {
    lookup_forwarding_resolution(state, dst).disposition
}

fn lookup_forwarding_resolution(state: &ForwardingState, dst: IpAddr) -> ForwardingResolution {
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
                    next_hop: None,
                    neighbor_mac: None,
                };
            }
            let static_match = state
                .routes_v4
                .iter()
                .find(|entry| entry.prefix.contains(&ip));
            let connected_match = state
                .connected_v4
                .iter()
                .find(|entry| entry.prefix.contains(&ip));
            match choose_v4_route(static_match, connected_match) {
                Some(ResolvedRouteV4::Connected { ifindex }) => {
                    let neighbor = state.neighbors.get(&(ifindex, IpAddr::V4(ip)));
                    ForwardingResolution {
                        disposition: if neighbor.is_some() {
                            ForwardingDisposition::ForwardCandidate
                        } else {
                            ForwardingDisposition::MissingNeighbor
                        },
                        local_ifindex: 0,
                        egress_ifindex: ifindex,
                        next_hop: Some(IpAddr::V4(ip)),
                        neighbor_mac: neighbor.map(|entry| entry.mac),
                    }
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
                            next_hop: next_hop.map(IpAddr::V4),
                            neighbor_mac: None,
                        };
                    }
                    if next_table {
                        return ForwardingResolution {
                            disposition: ForwardingDisposition::NextTableUnsupported,
                            local_ifindex: 0,
                            egress_ifindex: ifindex,
                            next_hop: next_hop.map(IpAddr::V4),
                            neighbor_mac: None,
                        };
                    }
                    if ifindex <= 0 {
                        return ForwardingResolution {
                            disposition: ForwardingDisposition::NoRoute,
                            local_ifindex: 0,
                            egress_ifindex: 0,
                            next_hop: next_hop.map(IpAddr::V4),
                            neighbor_mac: None,
                        };
                    }
                    let target = next_hop.unwrap_or(ip);
                    let neighbor = state.neighbors.get(&(ifindex, IpAddr::V4(target)));
                    ForwardingResolution {
                        disposition: if neighbor.is_some() {
                            ForwardingDisposition::ForwardCandidate
                        } else {
                            ForwardingDisposition::MissingNeighbor
                        },
                        local_ifindex: 0,
                        egress_ifindex: ifindex,
                        next_hop: Some(IpAddr::V4(target)),
                        neighbor_mac: neighbor.map(|entry| entry.mac),
                    }
                }
                None => ForwardingResolution {
                    disposition: ForwardingDisposition::NoRoute,
                    local_ifindex: 0,
                    egress_ifindex: 0,
                    next_hop: None,
                    neighbor_mac: None,
                },
            }
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
                    next_hop: None,
                    neighbor_mac: None,
                };
            }
            let static_match = state
                .routes_v6
                .iter()
                .find(|entry| entry.prefix.contains(&ip));
            let connected_match = state
                .connected_v6
                .iter()
                .find(|entry| entry.prefix.contains(&ip));
            match choose_v6_route(static_match, connected_match) {
                Some(ResolvedRouteV6::Connected { ifindex }) => {
                    let neighbor = state.neighbors.get(&(ifindex, IpAddr::V6(ip)));
                    ForwardingResolution {
                        disposition: if neighbor.is_some() {
                            ForwardingDisposition::ForwardCandidate
                        } else {
                            ForwardingDisposition::MissingNeighbor
                        },
                        local_ifindex: 0,
                        egress_ifindex: ifindex,
                        next_hop: Some(IpAddr::V6(ip)),
                        neighbor_mac: neighbor.map(|entry| entry.mac),
                    }
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
                            next_hop: next_hop.map(IpAddr::V6),
                            neighbor_mac: None,
                        };
                    }
                    if next_table {
                        return ForwardingResolution {
                            disposition: ForwardingDisposition::NextTableUnsupported,
                            local_ifindex: 0,
                            egress_ifindex: ifindex,
                            next_hop: next_hop.map(IpAddr::V6),
                            neighbor_mac: None,
                        };
                    }
                    if ifindex <= 0 {
                        return ForwardingResolution {
                            disposition: ForwardingDisposition::NoRoute,
                            local_ifindex: 0,
                            egress_ifindex: 0,
                            next_hop: next_hop.map(IpAddr::V6),
                            neighbor_mac: None,
                        };
                    }
                    let target = next_hop.unwrap_or(ip);
                    let neighbor = state.neighbors.get(&(ifindex, IpAddr::V6(target)));
                    ForwardingResolution {
                        disposition: if neighbor.is_some() {
                            ForwardingDisposition::ForwardCandidate
                        } else {
                            ForwardingDisposition::MissingNeighbor
                        },
                        local_ifindex: 0,
                        egress_ifindex: ifindex,
                        next_hop: Some(IpAddr::V6(target)),
                        neighbor_mac: neighbor.map(|entry| entry.mac),
                    }
                }
                None => ForwardingResolution {
                    disposition: ForwardingDisposition::NoRoute,
                    local_ifindex: 0,
                    egress_ifindex: 0,
                    next_hop: None,
                    neighbor_mac: None,
                },
            }
        }
    }
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
        0x45, 0x00, (total_len >> 8) as u8, total_len as u8, 0x00, 0x01, 0x00, 0x00, 64, 1, 0, 0,
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
    frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, (plen >> 8) as u8, plen as u8, 58, 64]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());

    let icmp_start = frame.len();
    frame.extend_from_slice(&[128, 0, 0, 0]);
    frame.extend_from_slice(&(req.slot as u16).to_be_bytes());
    frame.extend_from_slice(&1u16.to_be_bytes());
    for i in 0..payload_len {
        frame.push((i & 0xff) as u8);
    }
    let icmp_sum = checksum16_ipv6(src_ip, dst_ip, &frame[icmp_start..]);
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

fn checksum16_ipv6(src: Ipv6Addr, dst: Ipv6Addr, payload: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + payload.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 58]);
    pseudo.extend_from_slice(payload);
    checksum16(&pseudo)
}

enum ResolvedRouteV4 {
    Connected {
        ifindex: i32,
    },
    Static {
        ifindex: i32,
        next_hop: Option<Ipv4Addr>,
        discard: bool,
        next_table: bool,
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
        next_table: bool,
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
            next_table: route.next_table,
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
            next_table: route.next_table,
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

fn maybe_touch_heartbeat(binding: &mut BindingWorker) {
    if binding.last_heartbeat_update.elapsed() < HEARTBEAT_UPDATE_INTERVAL {
        return;
    }
    match touch_heartbeat(binding.heartbeat_map_fd, binding.slot, &binding.live) {
        Ok(()) => binding.last_heartbeat_update = Instant::now(),
        Err(err) => binding
            .live
            .set_error(format!("update heartbeat slot: {err}")),
    }
}

fn touch_heartbeat(map_fd: c_int, slot: u32, live: &BindingLiveState) -> io::Result<()> {
    let monotonic = monotonic_nanos();
    update_heartbeat_slot(map_fd, slot, monotonic)?;
    live.set_last_heartbeat();
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
    socket_fd: AtomicI32,
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
    kernel_rx_dropped: AtomicU64,
    kernel_rx_invalid_descs: AtomicU64,
    tx_packets: AtomicU64,
    tx_bytes: AtomicU64,
    tx_errors: AtomicU64,
    last_heartbeat: AtomicI64,
    last_error: Mutex<String>,
    pending_tx: Mutex<VecDeque<TxRequest>>,
}

impl BindingLiveState {
    fn new() -> Self {
        Self {
            bound: AtomicBool::new(false),
            xsk_registered: AtomicBool::new(false),
            socket_fd: AtomicI32::new(0),
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
            kernel_rx_dropped: AtomicU64::new(0),
            kernel_rx_invalid_descs: AtomicU64::new(0),
            tx_packets: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            tx_errors: AtomicU64::new(0),
            last_heartbeat: AtomicI64::new(0),
            last_error: Mutex::new(String::new()),
            pending_tx: Mutex::new(VecDeque::new()),
        }
    }

    fn set_bound(&self, socket_fd: c_int) {
        self.bound.store(true, Ordering::Relaxed);
        self.socket_fd.store(socket_fd, Ordering::Relaxed);
    }

    fn set_xsk_registered(&self, value: bool) {
        self.xsk_registered.store(value, Ordering::Relaxed);
    }

    fn set_last_heartbeat(&self) {
        self.last_heartbeat.store(now_nanos(), Ordering::Relaxed);
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
        BindingLiveSnapshot {
            bound: self.bound.load(Ordering::Relaxed),
            xsk_registered: self.xsk_registered.load(Ordering::Relaxed),
            socket_fd: self.socket_fd.load(Ordering::Relaxed),
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
            kernel_rx_dropped: self.kernel_rx_dropped.load(Ordering::Relaxed),
            kernel_rx_invalid_descs: self.kernel_rx_invalid_descs.load(Ordering::Relaxed),
            tx_packets: self.tx_packets.load(Ordering::Relaxed),
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
            tx_errors: self.tx_errors.load(Ordering::Relaxed),
            last_heartbeat: timestamp_from_nanos(self.last_heartbeat.load(Ordering::Relaxed)),
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
                pending.push_back(req);
                Ok(())
            }
            Err(_) => Err("pending_tx lock poisoned".to_string()),
        }
    }

    fn take_pending_tx(&self) -> VecDeque<TxRequest> {
        match self.pending_tx.lock() {
            Ok(mut pending) => core::mem::take(&mut *pending),
            Err(_) => VecDeque::new(),
        }
    }
}

struct BindingLiveSnapshot {
    bound: bool,
    xsk_registered: bool,
    socket_fd: c_int,
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
    kernel_rx_dropped: u64,
    kernel_rx_invalid_descs: u64,
    tx_packets: u64,
    tx_bytes: u64,
    tx_errors: u64,
    last_heartbeat: Option<chrono::DateTime<Utc>>,
    last_error: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{InterfaceAddressSnapshot, InterfaceSnapshot, NeighborSnapshot, RouteSnapshot};

    fn forwarding_snapshot(include_neighbor: bool) -> ConfigSnapshot {
        ConfigSnapshot {
            interfaces: vec![InterfaceSnapshot {
                name: "ge-0/0/0.50".to_string(),
                linux_name: "ge-0-0-0.50".to_string(),
                ifindex: 12,
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
            ..Default::default()
        }
    }

    fn valid_meta() -> UserspaceDpMeta {
        UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            addr_family: libc::AF_INET as u8,
            config_generation: 11,
            fib_generation: 7,
            ..UserspaceDpMeta::default()
        }
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
    fn forwarding_lookup_prefers_local_delivery() {
        let state = build_forwarding_state(&forwarding_snapshot(true));
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
}
