use super::{BindingStatus, ConfigSnapshot, ExceptionStatus, InjectPacketRequest};
use chrono::Utc;
use core::ffi::{c_int, c_void};
use core::num::NonZeroU32;
use core::ptr::NonNull;
use std::collections::{BTreeMap, VecDeque};
use std::ffi::CString;
use std::io;
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
const STATS_POLL_INTERVAL: Duration = Duration::from_secs(1);
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
    live: BTreeMap<u32, Arc<BindingLiveState>>,
    identities: BTreeMap<u32, BindingIdentity>,
    workers: BTreeMap<u32, WorkerHandle>,
    recent_exceptions: Arc<Mutex<VecDeque<ExceptionStatus>>>,
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
            live: BTreeMap::new(),
            identities: BTreeMap::new(),
            workers: BTreeMap::new(),
            recent_exceptions: Arc::new(Mutex::new(VecDeque::with_capacity(MAX_RECENT_EXCEPTIONS))),
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
        self.workers.clear();
        self.identities.clear();
        self.live.clear();
        self.map_fd = None;
        if let Ok(mut recent) = self.recent_exceptions.lock() {
            recent.clear();
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
        if snapshot.map_pins.xsk.is_empty() {
            self.last_reconcile_stage = "missing_xsk_pin".to_string();
            for binding in bindings.iter_mut() {
                if binding.registered {
                    binding.last_error = "missing XSK map pin path".to_string();
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
        for (worker_id, binding_plans) in workers {
            let plan_count = binding_plans.len();
            let stop = Arc::new(AtomicBool::new(false));
            let heartbeat = Arc::new(AtomicI64::new(now_nanos()));
            let recent_exceptions = self.recent_exceptions.clone();
            let stop_clone = stop.clone();
            let heartbeat_clone = heartbeat.clone();
            let validation = self.validation;
            let join = thread::Builder::new()
                .name(format!("bpfrx-userspace-worker-{worker_id}"))
                .spawn(move || {
                    worker_loop(
                        worker_id,
                        binding_plans,
                        validation,
                        recent_exceptions,
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
            record_disposition(
                &ident,
                live,
                classify_metadata(meta, self.validation),
                packet_length,
                Some(meta),
                &self.recent_exceptions,
            );
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
                binding.exception_packets = snap.exception_packets;
                binding.config_gen_mismatches = snap.config_gen_mismatches;
                binding.fib_gen_mismatches = snap.fib_gen_mismatches;
                binding.unsupported_packets = snap.unsupported_packets;
                binding.kernel_rx_dropped = snap.kernel_rx_dropped;
                binding.kernel_rx_invalid_descs = snap.kernel_rx_invalid_descs;
                binding.last_error = snap.last_error;
                binding.ready =
                    binding.ready && binding.registered && binding.bound && binding.xsk_registered;
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
                binding.exception_packets = 0;
                binding.config_gen_mismatches = 0;
                binding.fib_gen_mismatches = 0;
                binding.unsupported_packets = 0;
                binding.kernel_rx_dropped = 0;
                binding.kernel_rx_invalid_descs = 0;
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
}

#[derive(Clone, Debug)]
struct BindingIdentity {
    slot: u32,
    queue_id: u32,
    worker_id: u32,
    interface: String,
    ifindex: i32,
}

impl BindingWorker {
    fn create(
        binding: &BindingStatus,
        ring_entries: u32,
        xsk_map_fd: c_int,
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
                    tx_size: None,
                    bind_flags: SocketConfig::XDP_BIND_NEED_WAKEUP,
                },
            )
            .map_err(|e| format!("configure rx ring: {e}"))?;
        let rx = user.map_rx().map_err(|e| format!("map rx ring: {e}"))?;
        umem.bind(&user)
            .map_err(|e| format!("bind AF_XDP socket: {e}"))?;
        prime_fill_ring(&umem, &mut device)?;

        live.set_bound(user.as_raw_fd());
        if let Err(err) = register_xsk_slot(xsk_map_fd, binding.slot, user.as_raw_fd()) {
            live.set_error(format!("register XSK slot: {err}"));
        } else {
            live.set_xsk_registered(true);
            live.clear_error();
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
    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
    poll_stats: bool,
) -> bool {
    let ident = binding.identity();
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
            record_disposition(
                &ident,
                &binding.live,
                classify_metadata(meta, validation),
                desc.len as u32,
                Some(meta),
                recent_exceptions,
            );
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

fn worker_loop(
    worker_id: u32,
    binding_plans: Vec<BindingPlan>,
    validation: ValidationState,
    recent_exceptions: Arc<Mutex<VecDeque<ExceptionStatus>>>,
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
            if poll_binding(binding, validation, &recent_exceptions, poll_stats) {
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
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let frame_count = umem.len_frames();
    let inserted = {
        let mut fill = device.fill(frame_count);
        let inserted = fill.insert(
            (0..frame_count).filter_map(|idx| umem.frame(BufIdx(idx)).map(|frame| frame.offset)),
        );
        fill.commit();
        inserted
    };
    if inserted != frame_count {
        return Err(format!("prefill fill ring inserted {inserted}/{frame_count} frames").into());
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

fn delete_xsk_slot(map_fd: c_int, slot: u32) -> io::Result<()> {
    let rc =
        unsafe { libbpf_sys::bpf_map_delete_elem(map_fd, (&slot as *const u32).cast::<c_void>()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
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
    exception_packets: AtomicU64,
    config_gen_mismatches: AtomicU64,
    fib_gen_mismatches: AtomicU64,
    unsupported_packets: AtomicU64,
    kernel_rx_dropped: AtomicU64,
    kernel_rx_invalid_descs: AtomicU64,
    last_error: Mutex<String>,
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
            exception_packets: AtomicU64::new(0),
            config_gen_mismatches: AtomicU64::new(0),
            fib_gen_mismatches: AtomicU64::new(0),
            unsupported_packets: AtomicU64::new(0),
            kernel_rx_dropped: AtomicU64::new(0),
            kernel_rx_invalid_descs: AtomicU64::new(0),
            last_error: Mutex::new(String::new()),
        }
    }

    fn set_bound(&self, socket_fd: c_int) {
        self.bound.store(true, Ordering::Relaxed);
        self.socket_fd.store(socket_fd, Ordering::Relaxed);
    }

    fn set_xsk_registered(&self, value: bool) {
        self.xsk_registered.store(value, Ordering::Relaxed);
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
            exception_packets: self.exception_packets.load(Ordering::Relaxed),
            config_gen_mismatches: self.config_gen_mismatches.load(Ordering::Relaxed),
            fib_gen_mismatches: self.fib_gen_mismatches.load(Ordering::Relaxed),
            unsupported_packets: self.unsupported_packets.load(Ordering::Relaxed),
            kernel_rx_dropped: self.kernel_rx_dropped.load(Ordering::Relaxed),
            kernel_rx_invalid_descs: self.kernel_rx_invalid_descs.load(Ordering::Relaxed),
            last_error: self
                .last_error
                .lock()
                .map(|v| v.clone())
                .unwrap_or_default(),
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
    exception_packets: u64,
    config_gen_mismatches: u64,
    fib_gen_mismatches: u64,
    unsupported_packets: u64,
    kernel_rx_dropped: u64,
    kernel_rx_invalid_descs: u64,
    last_error: String,
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
