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
#[path = "afxdp/flow_cache.rs"]
mod flow_cache;
#[path = "afxdp/forwarding.rs"]
mod forwarding;
#[path = "afxdp/forwarding_build.rs"]
mod forwarding_build;
#[path = "afxdp/frame.rs"]
mod frame;
#[path = "afxdp/frame_tx.rs"]
mod frame_tx;
#[path = "afxdp/mpsc_inbox.rs"]
mod mpsc_inbox;
#[path = "afxdp/gre.rs"]
mod gre;
#[path = "afxdp/ha.rs"]
mod ha;
#[path = "afxdp/icmp.rs"]
mod icmp;
#[path = "afxdp/icmp_embed.rs"]
mod icmp_embed;
#[path = "afxdp/ethernet.rs"]
mod ethernet;
#[path = "afxdp/neighbor.rs"]
mod neighbor;
#[path = "afxdp/parser.rs"]
mod parser;
#[path = "afxdp/rst.rs"]
mod rst;
#[path = "afxdp/sharded_neighbor.rs"]
mod sharded_neighbor;
#[path = "afxdp/session_glue.rs"]
mod session_glue;
#[path = "afxdp/cos/mod.rs"]
mod cos;
#[path = "afxdp/shared_ops.rs"]
mod shared_ops;
#[cfg(test)]
#[path = "afxdp/test_fixtures.rs"]
mod test_fixtures;
#[path = "afxdp/tunnel.rs"]
mod tunnel;
#[path = "afxdp/tx/mod.rs"]
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
use self::flow_cache::*;
use self::forwarding::*;
use self::forwarding_build::*;
use self::frame::*;
use self::frame_tx::*;
use self::gre::{encapsulate_native_gre_frame, try_native_gre_decap_from_frame};
use self::icmp::{FABRIC_INGRESS_FLAG, build_local_time_exceeded_request, is_icmp_error};
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
use self::sharded_neighbor::ShardedNeighborMap;
use self::rst::*;
use self::session_glue::*;
use self::shared_ops::*;
use self::tunnel::*;
use self::mpsc_inbox::MpscInbox;
use self::tx::*;
use self::types::*;
pub(crate) use self::types::{ForwardingDisposition, ForwardingResolution, NeighborEntry};
use self::umem::*;

const USERSPACE_META_MAGIC: u32 = 0x4250_5553;
const USERSPACE_META_VERSION: u16 = 4;
const UMEM_FRAME_SIZE: u32 = 4096;
/// #812: log2 of `UMEM_FRAME_SIZE`, used to index the per-binding
/// submit-timestamp sidecar (`BindingWorker::tx_submit_ns`). Paired
/// const-assert below keeps this wired to the frame size so a future
/// resize (e.g. 2 KiB frames) fails the build instead of silently
/// indexing the wrong slot.
const UMEM_FRAME_SHIFT: u32 = 12;
const _: () = assert!(1u32 << UMEM_FRAME_SHIFT == UMEM_FRAME_SIZE);
const UMEM_HEADROOM: u32 = 256;
// #920: batch sizes lowered from 256 to 64 to keep the per-batch
// working set within typical 32 KB L1d (~10-14 KB at 64 packets:
// 64 × 96 B `UserspaceDpMeta` + 64 × 64-128 B headers + scratch
// state) and reduce the worst-case head-of-line latency for a
// mouse packet trailing an elephant burst by 4× — at 25 Gb/s and
// 1500-byte MTU each packet is ~480 ns, so 63 packets ahead = 30 µs
// vs 122 µs at the prior batch of 256. Also caps the kernel-side
// NAPI busy-poll budget via SO_BUSY_POLL_BUDGET in bind.rs at 64.
//
// Tradeoff: per-poll throughput drops from
// `MAX_RX_BATCHES_PER_POLL × <pre-#920 RX_BATCH_SIZE = 256>`
// to `MAX_RX_BATCHES_PER_POLL × RX_BATCH_SIZE` packets per binding
// poll cycle (4 × 256 = 1024 → 4 × 64 = 256 at the current
// constants). Kept `MAX_RX_BATCHES_PER_POLL = 4` (rather than
// raising to 16) because the latency goal of #920 directly
// benefits from more frequent yields. Throughput
// regression-checked in cluster smoke.
//
// Future bumps require re-validating: (a) L1d footprint vs
// per-batch allocation; (b) per-poll budget interaction with
// `MAX_RX_BATCHES_PER_POLL`; (c) the rate-quantum test
// `guarantee_phase_*_visit_quantum` in tx.rs. The const_asserts
// below force the change to fail compilation rather than silently
// regress the validation surface.
const RX_BATCH_SIZE: u32 = 64;
const _: () = assert!(
    RX_BATCH_SIZE == 64,
    "changing RX_BATCH_SIZE requires re-validating L1d footprint and per-poll budget"
);
const MIN_RESERVED_TX_FRAMES: u32 = 256;
const MAX_RESERVED_TX_FRAMES: u32 = 8192;
const TX_BATCH_SIZE: usize = 64;
const _: () = assert!(
    TX_BATCH_SIZE == 64,
    "changing TX_BATCH_SIZE requires re-validating COS guarantee quantum + snapshot stack bound"
);
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
#[allow(dead_code)] // reserved for heartbeat gating logic
const HEARTBEAT_GRACE_PERIOD_NS: u64 = 6_000_000_000; // 6 seconds
const TX_WAKE_MIN_INTERVAL_NS: u64 = 50_000;
const HEARTBEAT_STALE_AFTER: Duration = Duration::from_secs(5);
const MAX_RECENT_EXCEPTIONS: usize = 32;
const MAX_RECENT_SESSION_DELTAS: usize = 64;
const MAX_PENDING_SESSION_DELTAS: usize = 4096;
const BIND_RETRY_ATTEMPTS: usize = 20;
const BIND_RETRY_DELAY: Duration = Duration::from_millis(250);
const DEFAULT_SLOW_PATH_TUN: &str = "xpf-usp0";
const LOCAL_TUNNEL_DELIVERY_QUEUE_DEPTH: usize = 4096;
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

#[path = "afxdp/coordinator.rs"]
mod coordinator;
#[cfg(test)]
#[path = "afxdp/tests.rs"]
mod tests;
#[path = "afxdp/worker.rs"]
mod worker;
#[path = "afxdp/worker_runtime.rs"]
mod worker_runtime;
pub use self::coordinator::Coordinator;
pub(crate) use self::worker::{
    BindingLiveSnapshot, BindingWorker, SyncedSessionEntry, XskBindMode, fabric_queue_hash,
    push_recent_exception, push_recent_session_delta, worker_loop,
};
fn should_install_local_reverse_session(decision: SessionDecision, fabric_ingress: bool) -> bool {
    let fabric_wire_placeholder =
        shared_ops::is_fabric_wire_placeholder(fabric_ingress, false, decision);
    decision.resolution.disposition != ForwardingDisposition::FabricRedirect
        || (fabric_ingress && !fabric_wire_placeholder)
}

// Lifted from `poll_binding` so the per-descriptor batch function
// (`poll_binding_process_descriptor`) can take `&mut BatchCounters`.
// Shape and semantics are byte-for-byte identical to the previous nested
// definition — see #678 poll_binding split.
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

// Pins the invariant that `poll_binding` relies on: the RX batch loop
// must run at least once. Cheap compile-time guard.
const _: () = assert!(MAX_RX_BATCHES_PER_POLL >= 1);

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
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    slow_path: Option<&Arc<SlowPathReinjector>>,
    local_tunnel_deliveries: &Arc<ArcSwap<BTreeMap<i32, SyncSender<Vec<u8>>>>>,
    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
    _recent_session_deltas: &Arc<Mutex<VecDeque<SessionDeltaInfo>>>,
    last_resolution: &Arc<Mutex<Option<PacketResolution>>>,
    peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    worker_id: u32,
    worker_commands_by_id: &BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
    shared_recycles: &mut Vec<(u32, u64)>,
    dnat_fds: &DnatTableFds,
    conntrack_v4_fd: c_int,
    conntrack_v6_fd: c_int,
    dbg: &mut DebugPollCounters,
    rg_epochs: &[AtomicU32; MAX_RG_EPOCHS],
    cos_owner_worker_by_queue: &BTreeMap<(i32, u8), u32>,
    cos_owner_live_by_queue: &BTreeMap<(i32, u8), Arc<BindingLiveState>>,
) -> bool {

    let (left, rest) = bindings.split_at_mut(binding_index);
    let Some((binding, right)) = rest.split_first_mut() else {
        return false;
    };
    let area = binding.umem.area() as *const MmapArea;
    maybe_touch_heartbeat(binding, now_ns);
    let tx_work = drain_pending_tx(
        binding,
        now_ns,
        shared_recycles,
        forwarding,
        worker_id,
        worker_commands_by_id,
        cos_owner_worker_by_queue,
        cos_owner_live_by_queue,
    );
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
            let _ = drain_pending_tx(
                binding,
                now_ns,
                shared_recycles,
                forwarding,
                worker_id,
                worker_commands_by_id,
                cos_owner_worker_by_queue,
                cos_owner_live_by_queue,
            );
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

        // #945: WorkerContext groups 16 shared/passed-through references
        // (interior mutability via locks is preserved). TelemetryContext
        // groups the two mutable counter sinks. Named-field shorthand
        // ensures the compiler verifies field name == local-variable
        // name; any swap of two shared-typed fields would require
        // renaming a local elsewhere and break compilation.
        let worker_ctx = WorkerContext {
            ident,
            binding_lookup,
            forwarding,
            ha_state,
            dynamic_neighbors,
            shared_sessions,
            shared_nat_sessions,
            shared_forward_wire_sessions,
            shared_owner_rg_indexes,
            slow_path,
            local_tunnel_deliveries,
            recent_exceptions,
            last_resolution,
            peer_worker_commands,
            dnat_fds,
            rg_epochs,
        };
        let mut telemetry = TelemetryContext {
            dbg,
            counters: &mut counters,
        };
        poll_binding_process_descriptor(
            binding,
            binding_index,
            area,
            available,
            sessions,
            screen,
            validation,
            now_ns,
            now_secs,
            ha_startup_grace_until_secs,
            worker_id,
            conntrack_v4_fd,
            conntrack_v6_fd,
            &worker_ctx,
            &mut telemetry,
        );
        let mut pending_forwards = core::mem::take(&mut binding.scratch_forwards);
        let mut rst_teardowns = core::mem::take(&mut binding.scratch_rst_teardowns);
        for (forward_key, nat) in rst_teardowns.drain(..) {
            // Evict from flow cache so stale entries aren't used after RST.
            // #918: 4-way set-associative cache requires walking the set
            // for the matching key — `invalidate_slot` does that.
            binding
                .flow_cache
                .invalidate_slot(&forward_key, binding.ifindex);
            teardown_tcp_rst_flow(
                left,
                binding,
                right,
                sessions,
                shared_sessions,
                shared_nat_sessions,
                shared_forward_wire_sessions,
                &shared_owner_rg_indexes,
                peer_worker_commands,
                &forward_key,
                nat,
                &mut pending_forwards,
            );
        }
        binding.scratch_rst_teardowns = rst_teardowns;
        if !pending_forwards.is_empty() {
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
                worker_id,
                worker_commands_by_id,
                cos_owner_worker_by_queue,
                cos_owner_live_by_queue,
            );
            binding.scratch_post_recycles = scratch_post_recycles;
        }
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
// Per-batch packet processing lifted from `poll_binding` (#678).
//
// Runs `binding.rx.receive(available)` + the descriptor while-let +
// `received.release(); drop(received);` as its own compilation unit so
// it surfaces under its own symbol in `perf top`. Body is byte-for-byte
// identical to the previous inner-loop content; only the enclosing
// function boundary is new.
#[allow(clippy::too_many_arguments)]
fn poll_binding_process_descriptor(
    binding: &mut BindingWorker,
    binding_index: usize,
    area: *const MmapArea,
    available: u32,
    sessions: &mut SessionTable,
    screen: &mut ScreenState,
    validation: ValidationState,
    now_ns: u64,
    now_secs: u64,
    ha_startup_grace_until_secs: u64,
    _worker_id: u32,
    conntrack_v4_fd: c_int,
    conntrack_v6_fd: c_int,
    worker_ctx: &WorkerContext,
    telemetry: &mut TelemetryContext,
) {
        let mut received = binding.rx.receive(available);
        binding.scratch_recycle.clear();
        binding.scratch_forwards.clear();
        binding.scratch_rst_teardowns.clear();
        while let Some(desc) = received.read() {
            // Prefetch the userspace-dp metadata header (96 bytes) at
            // desc.addr - meta_len. try_parse_metadata reads this
            // first, on the magic/version/length compare; before this
            // prefetch landed, that compare consumed ~33 % of
            // poll_binding_process_descriptor self-time on a perf
            // profile under iperf3 -P 128 / 25 Gb/s shaper (#909).
            //
            // The metadata is exactly 96 bytes (UserspaceDpMeta has a
            // const-asserted size; first field is `magic`) and starts
            // 96 bytes before the frame. UMEM frames are 4096-byte
            // aligned with a 256-byte headroom, so desc.addr is
            // 64-byte aligned by construction; the 96 bytes therefore
            // straddle exactly two cache lines and we issue two
            // prefetches.
            #[cfg(target_arch = "x86_64")]
            {
                debug_assert!(
                    desc.addr % 64 == 0,
                    "UMEM frame at desc.addr={} should be 64-byte aligned",
                    desc.addr,
                );
                let meta_len = std::mem::size_of::<UserspaceDpMeta>();
                if (desc.addr as usize) >= meta_len {
                    let meta_offset = (desc.addr as usize) - meta_len;
                    if let Some(pf_meta) =
                        unsafe { &*area }.slice(meta_offset, meta_len)
                    {
                        unsafe {
                            core::arch::x86_64::_mm_prefetch(
                                pf_meta.as_ptr() as *const i8,
                                core::arch::x86_64::_MM_HINT_T0,
                            );
                            core::arch::x86_64::_mm_prefetch(
                                pf_meta.as_ptr().add(64) as *const i8,
                                core::arch::x86_64::_MM_HINT_T0,
                            );
                        }
                    }
                }
            }

            // Prefetch frame data into L1 while processing telemetry.counters.
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
            telemetry.counters.touched = true;
            telemetry.counters.rx_packets += 1;
            telemetry.counters.rx_bytes += desc.len as u64;
            telemetry.dbg.rx += 1;
            telemetry.dbg.rx_bytes_total += desc.len as u64;
            if desc.len > telemetry.dbg.rx_max_frame {
                telemetry.dbg.rx_max_frame = desc.len;
            }
            if desc.len > 1514 {
                telemetry.dbg.rx_oversized += 1;
                if cfg!(feature = "debug-log") {
                    thread_local! {
                        static OVERSIZED_RX_LOG: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
                    }
                    OVERSIZED_RX_LOG.with(|c| {
                        let n = c.get();
                        if n < 20 {
                            c.set(n + 1);
                            eprintln!("DBG OVERSIZED_RX[{}]: if={} q={} desc.len={} (exceeds ETH+MTU 1514)",
                                n, worker_ctx.ident.ifindex, worker_ctx.ident.queue_id, desc.len,
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
                                telemetry.dbg.rx_tcp_fin += 1;
                            }
                            if (tcp_info.0 & 0x12) == 0x12 {
                                // SYN+ACK
                                telemetry.dbg.rx_tcp_synack += 1;
                            }
                            if tcp_info.1 == 0 && (tcp_info.0 & 0x02) == 0 {
                                // zero window, not SYN
                                telemetry.dbg.rx_tcp_zero_window += 1;
                                if telemetry.dbg.rx_tcp_zero_window <= 10 {
                                    eprintln!(
                                        "RX_TCP_ZERO_WIN[{}]: if={} q={} len={} flags=0x{:02x}",
                                        telemetry.dbg.rx_tcp_zero_window,
                                        worker_ctx.ident.ifindex,
                                        worker_ctx.ident.queue_id,
                                        desc.len,
                                        tcp_info.0,
                                    );
                                }
                            }
                        }
                        if frame_has_tcp_rst(rx_frame) {
                            telemetry.dbg.rx_tcp_rst += 1;
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
                                        n, worker_ctx.ident.ifindex, worker_ctx.ident.queue_id, desc.len, summary,
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
                                worker_ctx.ident.ifindex, worker_ctx.ident.queue_id, desc.addr, desc.len,
                            );
                        }
                    }
                }
            }
            if cfg!(feature = "debug-log") {
                if telemetry.dbg.rx <= 10 {
                    if let Some(rx_frame) =
                        unsafe { &*area }.slice(desc.addr as usize, desc.len as usize)
                    {
                        // Decode IP+TCP details from the frame
                        let pkt_detail = decode_frame_summary(rx_frame);
                        eprintln!(
                            "DBG RX_ETH[{}]: if={} q={} len={} {}",
                            telemetry.dbg.rx, worker_ctx.ident.ifindex, worker_ctx.ident.queue_id, desc.len, pkt_detail,
                        );
                        // Full hex dump for first 3 packets
                        if telemetry.dbg.rx <= 3 {
                            let dump_len = (desc.len as usize).min(rx_frame.len()).min(80);
                            let hex: String = rx_frame[..dump_len]
                                .iter()
                                .map(|b| format!("{:02x}", b))
                                .collect::<Vec<_>>()
                                .join(" ");
                            eprintln!("DBG RX_HEX[{}]: {}", telemetry.dbg.rx, hex);
                        }
                    }
                }
            }
            let mut recycle_now = true;
            if let Some(meta) = try_parse_metadata(unsafe { &*area }, desc) {
                telemetry.counters.metadata_packets += 1;
                let disposition = classify_metadata(meta, validation);
                if disposition == PacketDisposition::Valid {
                    telemetry.counters.validated_packets += 1;
                    telemetry.counters.validated_bytes += desc.len as u64;
                    let Some(raw_frame) =
                        unsafe { &*area }.slice(desc.addr as usize, desc.len as usize)
                    else {
                        binding.scratch_recycle.push(desc.addr);
                        continue;
                    };
                    // #947: ARP classification + reply parsing extracted to
                    // `parser.rs`. Any ARP frame (request/reply/etc.) is
                    // recycled — ARP does not transit the firewall. ARP
                    // replies additionally update the dynamic neighbor cache
                    // and the kernel's neighbor table.
                    match parser::classify_arp(raw_frame) {
                        parser::ArpClassification::Reply(arp) => {
                            worker_ctx.dynamic_neighbors.insert(
                                (meta.ingress_ifindex as i32, arp.sender_ip),
                                NeighborEntry {
                                    mac: arp.sender_mac,
                                },
                            );
                            let neigh_ifindex = resolve_ingress_logical_ifindex(
                                worker_ctx.forwarding,
                                meta.ingress_ifindex as i32,
                                meta.ingress_vlan_id,
                            )
                            .unwrap_or(meta.ingress_ifindex as i32);
                            add_kernel_neighbor(neigh_ifindex, arp.sender_ip, arp.sender_mac);
                            binding.scratch_recycle.push(desc.addr);
                            continue;
                        }
                        parser::ArpClassification::OtherArp => {
                            binding.scratch_recycle.push(desc.addr);
                            continue;
                        }
                        parser::ArpClassification::NotArp => {}
                    }
                    // #947: NDP Neighbor Advertisement parsing extracted to
                    // `parser.rs`. NA with a Target Link-Layer Address option
                    // updates the dynamic neighbor cache and the kernel's
                    // neighbor table. Unlike ARP, the NA frame falls through
                    // to normal IPv6 forwarding processing afterward.
                    if let Some(na) = parser::parse_ndp_neighbor_advert(raw_frame)
                        && let Some(mac) = na.target_mac
                    {
                        worker_ctx.dynamic_neighbors.insert(
                            (meta.ingress_ifindex as i32, na.target_ip),
                            NeighborEntry { mac },
                        );
                        let neigh_ifindex = resolve_ingress_logical_ifindex(
                            worker_ctx.forwarding,
                            meta.ingress_ifindex as i32,
                            meta.ingress_vlan_id,
                        )
                        .unwrap_or(meta.ingress_ifindex as i32);
                        add_kernel_neighbor(neigh_ifindex, na.target_ip, mac);
                    }
                    let native_gre_packet =
                        try_native_gre_decap_from_frame(raw_frame, meta, worker_ctx.forwarding);
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
                            worker_ctx.forwarding,
                            worker_ctx.dynamic_neighbors,
                        );
                    }
                    let ingress_zone_override = parse_zone_encoded_fabric_ingress_from_frame(
                        packet_frame,
                        meta,
                        worker_ctx.forwarding,
                    );
                    let packet_fabric_ingress = ingress_zone_override.is_some()
                        || ingress_is_fabric_overlay(worker_ctx.forwarding, meta.ingress_ifindex as i32);
                    // Flag fabric-ingress packets so rewrite functions skip TTL
                    // decrement. The sending peer already decremented TTL when
                    // it forwarded the packet across the fabric link.
                    if packet_fabric_ingress {
                        meta.meta_flags |= FABRIC_INGRESS_FLAG;
                    }
                    // Screen/IDS check — runs BEFORE session lookup.
                    // Resolve ingress zone name for screen profile lookup.
                    // Slow path — only runs when screen profiles configured.
                    // #919: ingress_zone_override is now Option<u16>; resolve
                    // ID → name via zone_id_to_name when present.
                    if screen.has_profiles() {
                        if let Some(flow) = flow.as_ref() {
                            let zone_name = ingress_zone_override
                                .and_then(|id| {
                                    worker_ctx.forwarding.zone_id_to_name.get(&id).map(|s| s.as_str())
                                })
                                .or_else(|| {
                                    // #921: ifindex → u16 → name via
                                    // zone_id_to_name. Slow path (only
                                    // when screen profiles configured).
                                    worker_ctx.forwarding
                                        .ifindex_to_zone_id
                                        .get(&(meta.ingress_ifindex as i32))
                                        .and_then(|id| worker_ctx.forwarding.zone_id_to_name.get(id))
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
                                &worker_ctx.ident,
                                &binding.live,
                                worker_ctx.slow_path,
                                worker_ctx.local_tunnel_deliveries,
                                packet_frame,
                                meta,
                                ipsec_decision,
                                worker_ctx.recent_exceptions,
                                "slow_path",
                                worker_ctx.forwarding,
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
                            now_secs,
                            &worker_ctx.rg_epochs,
                        ) {
                            if !cached_flow_decision_valid(
                                worker_ctx.forwarding,
                                worker_ctx.ha_state,
                                worker_ctx.dynamic_neighbors,
                                now_secs,
                                cached.stamp.owner_rg_id,
                                packet_fabric_ingress,
                                resolution_target_for_session(flow, cached.decision),
                                cached.decision.resolution,
                            ) {
                                binding.flow_cache.invalidate_slot(
                                    &flow.forward_key,
                                    meta.ingress_ifindex as i32,
                                );
                                // Fall through to slow path for full
                                // HA resolution → fabric redirect.
                            } else {
                                let cached_decision = cached.decision;
                                let cached_descriptor = &cached.descriptor;
                                let cached_metadata = &cached.metadata;
                                if let Some(counter) =
                                    cached_descriptor.tx_selection.filter_counter.as_ref()
                                {
                                    crate::filter::record_filter_counter(
                                        counter,
                                        meta.pkt_len as u64,
                                    );
                                }
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
                                    // TTL/hop-limit check on flow cache hit path:
                                    // generate ICMP Time Exceeded for packets that
                                    // would expire after decrement.
                                    let local_icmp_te = unsafe { &*area }
                                        .slice(desc.addr as usize, desc.len as usize)
                                        .and_then(|frame| {
                                            build_local_time_exceeded_request(
                                                frame,
                                                desc,
                                                meta,
                                                &worker_ctx.ident,
                                                flow,
                                                worker_ctx.forwarding,
                                                worker_ctx.dynamic_neighbors,
                                                worker_ctx.ha_state,
                                                now_secs,
                                            )
                                        });
                                    if let Some(request) = local_icmp_te {
                                        binding.scratch_forwards.push(request);
                                        // Don't recycle here — enqueue_pending_forwards
                                        // returns the frame via pending_fill_frames
                                        // when processing the prebuilt TE response.
                                        continue;
                                    }
                                    telemetry.counters.forward_candidate_packets += 1;
                                    if cached_decision.nat.rewrite_src.is_some() {
                                        telemetry.counters.snat_packets += 1;
                                    }
                                    if cached_decision.nat.rewrite_dst.is_some() {
                                        telemetry.counters.dnat_packets += 1;
                                    }
                                    // ── Inline in-place rewrite fast path ──
                                    // Skip PendingForwardRequest + enqueue_pending_forwards entirely.
                                    // Resolve target binding, rewrite frame in UMEM, push PreparedTxRequest.
                                    let target_ifindex =
                                        if cached_decision.resolution.tx_ifindex > 0 {
                                            cached_decision.resolution.tx_ifindex
                                        } else {
                                            resolve_tx_binding_ifindex(
                                                worker_ctx.forwarding,
                                                cached_decision.resolution.egress_ifindex,
                                            )
                                        };
                                    let expected_ports =
                                        authoritative_forward_ports(packet_frame, meta, Some(flow));
                                    let target_bi =
                                        cached_descriptor.target_binding_index.or_else(|| {
                                            if cached_decision.resolution.disposition
                                                == ForwardingDisposition::FabricRedirect
                                            {
                                                worker_ctx.binding_lookup.fabric_target_index(
                                                    target_ifindex,
                                                    fabric_queue_hash(
                                                        Some(flow),
                                                        expected_ports,
                                                        meta,
                                                    ),
                                                )
                                            } else {
                                                worker_ctx.binding_lookup.target_index(
                                                    binding_index,
                                                    worker_ctx.ident.ifindex,
                                                    worker_ctx.ident.queue_id,
                                                    target_ifindex,
                                                )
                                            }
                                        });
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
                                                cached_descriptor.apply_nat_on_fabric,
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
                                                    egress_ifindex: cached_decision
                                                        .resolution
                                                        .egress_ifindex,
                                                    cos_queue_id: cached_descriptor
                                                        .tx_selection
                                                        .queue_id,
                                                    dscp_rewrite: cached_descriptor
                                                        .tx_selection
                                                        .dscp_rewrite,
                                                },
                                            );
                                            binding.pending_in_place_tx_packets += 1;
                                            telemetry.dbg.forward += 1;
                                            telemetry.dbg.tx += 1;
                                            recycle_now = false;
                                        }
                                    }
                                    // Fallback: use PendingForwardRequest path for cross-binding or failure.
                                    if recycle_now {
                                        if let Some(mut request) =
                                            build_live_forward_request_from_frame(
                                                worker_ctx.binding_lookup,
                                                binding_index,
                                                worker_ctx.ident,
                                                desc,
                                                packet_frame,
                                                meta,
                                                &cached_decision,
                                                worker_ctx.forwarding,
                                                Some(flow),
                                                Some(cached_metadata.ingress_zone),
                                                cached_descriptor.apply_nat_on_fabric,
                                                Some(PendingForwardHints {
                                                    expected_ports,
                                                    target_binding_index: target_bi,
                                                }),
                                                Some(&cached_descriptor.tx_selection),
                                            )
                                        {
                                            request.frame = owned_packet_frame
                                                .take()
                                                .map(PendingForwardFrame::Owned)
                                                .unwrap_or(PendingForwardFrame::Live);
                                            telemetry.dbg.forward += 1;
                                            telemetry.dbg.tx += 1;
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
                    let mut session_ingress_zone: Option<u16> = None;
                    let mut flow_cache_owner_rg_id = 0i32;
                    let mut apply_nat_on_fabric = false;
                    let mut decision = if let Some(flow) = flow.as_ref() {
                        if let Some(resolved) = resolve_flow_session_decision(
                            sessions,
                            binding.session_map_fd,
                            worker_ctx.shared_sessions,
                            worker_ctx.shared_nat_sessions,
                            worker_ctx.shared_forward_wire_sessions,
                            &worker_ctx.shared_owner_rg_indexes,
                            worker_ctx.peer_worker_commands,
                            worker_ctx.forwarding,
                            worker_ctx.ha_state,
                            worker_ctx.dynamic_neighbors,
                            flow,
                            now_ns,
                            now_secs,
                            meta.protocol,
                            meta.tcp_flags,
                            meta.ingress_ifindex as i32,
                            packet_fabric_ingress,
                            ha_startup_grace_until_secs,
                        ) {
                            telemetry.counters.session_hits += 1;
                            telemetry.dbg.session_hit += 1;
                            if resolved.created {
                                telemetry.counters.session_creates += 1;
                                telemetry.dbg.session_create += 1;
                                // Mirror new session to BPF conntrack map for
                                // `show security flow session` zone/interface display.
                                publish_bpf_conntrack_entry(
                                    conntrack_v4_fd,
                                    conntrack_v6_fd,
                                    &flow.forward_key,
                                    resolved.decision,
                                    &resolved.metadata,
                                    &worker_ctx.forwarding.zone_name_to_id,
                                );
                            }
                            // Log first N session hits from WAN (return path)
                            if cfg!(feature = "debug-log")
                                && meta.ingress_ifindex == 6
                                && telemetry.dbg.wan_return_hits < 5
                            {
                                telemetry.dbg.wan_return_hits += 1;
                                debug_log!(
                                    "DBG WAN_RETURN_HIT[{}]: {}:{} -> {}:{} proto={} tcp_flags=0x{:02x} nat=({:?},{:?}) rev={}",
                                    telemetry.dbg.wan_return_hits,
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
                                debug.from_zone = Some(resolved.metadata.ingress_zone);
                                debug.to_zone = Some(resolved.metadata.egress_zone);
                            }
                            session_ingress_zone = Some(resolved.metadata.ingress_zone);
                            flow_cache_owner_rg_id = resolved.metadata.owner_rg_id;
                            apply_nat_on_fabric = true;
                            // TTL/hop-limit check on session-hit path: generate
                            // ICMP Time Exceeded for packets that would expire
                            // after decrement. The session-miss path handles this
                            // in build_local_time_exceeded_request(); the session-
                            // hit path previously silently dropped these packets
                            // (the rewrite functions return None for TTL<=1).
                            if matches!(
                                resolved.decision.resolution.disposition,
                                ForwardingDisposition::ForwardCandidate
                            ) {
                                let local_icmp_te = unsafe { &*area }
                                    .slice(desc.addr as usize, desc.len as usize)
                                    .and_then(|frame| {
                                        build_local_time_exceeded_request(
                                            frame,
                                            desc,
                                            meta,
                                            &worker_ctx.ident,
                                            flow,
                                            worker_ctx.forwarding,
                                            worker_ctx.dynamic_neighbors,
                                            worker_ctx.ha_state,
                                            now_secs,
                                        )
                                    });
                                if let Some(request) = local_icmp_te {
                                    binding.scratch_forwards.push(request);
                                    // Don't recycle: the TE response references
                                    // the original frame via desc.addr on the request.
                                    // The continue skips recycle_now handling.
                                    continue;
                                }
                            }
                            resolved.decision
                        } else {
                            telemetry.counters.session_misses += 1;
                            telemetry.dbg.session_miss += 1;
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
                                    worker_ctx.forwarding,
                                    worker_ctx.dynamic_neighbors,
                                    packet_frame,
                                    meta,
                                    ingress_zone_override,
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
                                    worker_ctx.binding_lookup,
                                    binding_index,
                                    &ingress_ident,
                                    desc,
                                    packet_frame,
                                    meta,
                                    &fabric_return_decision,
                                    worker_ctx.forwarding,
                                    Some(flow),
                                    None,
                                    false,
                                    None,
                                    None,
                                ) {
                                    request.frame = owned_packet_frame
                                        .take()
                                        .map(PendingForwardFrame::Owned)
                                        .unwrap_or(PendingForwardFrame::Live);
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
                            // #919: ingress_zone_override is now Option<u16>;
                            // DNAT/static NAT lookups still take zone names,
                            // so resolve ID→name lazily on this miss path.
                            let ingress_zone_name = ingress_zone_override
                                .and_then(|id| {
                                    worker_ctx.forwarding.zone_id_to_name.get(&id).map(|s| s.as_str())
                                })
                                .or_else(|| {
                                    // #921: ifindex → u16 → name (slow path; DNAT/static-NAT
                                    // takes &str names).
                                    worker_ctx.forwarding
                                        .ifindex_to_zone_id
                                        .get(&(meta.ingress_ifindex as i32))
                                        .and_then(|id| worker_ctx.forwarding.zone_id_to_name.get(id))
                                        .map(|s| s.as_str())
                                })
                                .unwrap_or("");
                            let dnat_decision = if !worker_ctx.forwarding.dnat_table.is_empty() {
                                worker_ctx.forwarding.dnat_table.lookup(
                                    meta.protocol,
                                    resolution_target,
                                    flow.forward_key.dst_port,
                                    ingress_zone_name,
                                )
                            } else {
                                None
                            };
                            let static_dnat_decision = if dnat_decision.is_none() {
                                worker_ctx.forwarding
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
                                    if worker_ctx.forwarding.nptv6.translate_inbound(&mut dst_v6) {
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
                                        worker_ctx.forwarding.nat64.match_ipv6_dest(dst_v6).and_then(
                                            |(idx, dst_v4)| {
                                                let snat_v4 =
                                                    worker_ctx.forwarding.nat64.allocate_v4_source(idx)?;
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
                                ingress_route_table_override(worker_ctx.forwarding, meta, flow);

                            let resolution = if should_block_tunnel_interface_nat_session_miss(
                                worker_ctx.forwarding,
                                effective_resolution_target,
                                meta.protocol,
                            ) {
                                no_route_resolution(Some(effective_resolution_target))
                            } else {
                                ingress_interface_local_resolution_on_session_miss(
                                    worker_ctx.forwarding,
                                    meta.ingress_ifindex as i32,
                                    meta.ingress_vlan_id,
                                    effective_resolution_target,
                                    meta.protocol,
                                )
                                .or_else(|| {
                                    interface_nat_local_resolution_on_session_miss(
                                        worker_ctx.forwarding,
                                        effective_resolution_target,
                                        meta.protocol,
                                    )
                                })
                                .unwrap_or_else(|| {
                                    enforce_ha_resolution_snapshot(
                                        worker_ctx.forwarding,
                                        worker_ctx.ha_state,
                                        now_secs,
                                        lookup_forwarding_resolution_in_table_with_dynamic(
                                            worker_ctx.forwarding,
                                            worker_ctx.dynamic_neighbors,
                                            effective_resolution_target,
                                            route_table_override.as_deref(),
                                        ),
                                    )
                                })
                            };
                            let fabric_ingress = packet_fabric_ingress;
                            let resolution = prefer_local_forward_candidate_for_fabric_ingress(
                                worker_ctx.forwarding,
                                worker_ctx.ha_state,
                                worker_ctx.dynamic_neighbors,
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
                            // #919/#922: zero-allocation zone-pair resolution
                            // direct from u16 IDs — no String materialisation
                            // on the per-flow miss path.
                            let (from_zone_id, to_zone_id) = zone_pair_ids_for_flow_with_override(
                                worker_ctx.forwarding,
                                meta.ingress_ifindex as i32,
                                ingress_zone_override,
                                resolution.egress_ifindex,
                            );
                            // Borrow zone names as &str for string-typed downstream
                            // callers (static_nat, match_source_nat_for_flow, debug
                            // log). No clone — the borrow lives only inside this
                            // miss-path block while `worker_ctx.forwarding` is held.
                            let from_zone: &str = worker_ctx
                                .forwarding
                                .zone_id_to_name
                                .get(&from_zone_id)
                                .map(|s| s.as_str())
                                .unwrap_or("");
                            let to_zone: &str = worker_ctx
                                .forwarding
                                .zone_id_to_name
                                .get(&to_zone_id)
                                .map(|s| s.as_str())
                                .unwrap_or("");
                            let is_trust_flow = meta.ingress_ifindex == 5
                                || from_zone == "lan"
                                || matches!(flow.src_ip, IpAddr::V4(ip) if ip.octets()[0] == 10);
                            decision.resolution = finalize_new_flow_ha_resolution(
                                worker_ctx.forwarding,
                                worker_ctx.ha_state,
                                now_secs,
                                decision.resolution,
                                packet_fabric_ingress,
                                meta.ingress_ifindex as i32,
                                from_zone_id,
                                ha_startup_grace_until_secs,
                            );
                            // Debug: log session miss with flow details (throttled)
                            if cfg!(feature = "debug-log") {
                                if telemetry.dbg.session_miss <= 10 || is_trust_flow {
                                    eprintln!(
                                        "DBG SESS_MISS[{}]: {}:{} -> {}:{} proto={} tcp_flags=0x{:02x} ingress_if={} disp={:?} egress_if={} neigh={:?} zone={}->{}",
                                        telemetry.dbg.session_miss,
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
                                        if telemetry.dbg.session_miss <= 3 {
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
                                debug.from_zone = Some(from_zone_id);
                                debug.to_zone = Some(to_zone_id);
                            }
                            // Compute embedded ICMP error flag early so we can skip
                            // the BPF session map publish for ICMP errors. Publishing
                            // them as PASS_TO_KERNEL causes subsequent ICMP errors to
                            // bypass the userspace embedded ICMP NAT reversal.
                            let is_embedded_icmp_error = if worker_ctx.forwarding.allow_embedded_icmp
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
                                    worker_ctx.forwarding,
                                    effective_resolution_target,
                                    resolution,
                                    meta.protocol,
                                    meta.tcp_flags,
                                )
                            {
                                let local_metadata = SessionMetadata {
                                    ingress_zone: from_zone_id,
                                    egress_zone: to_zone_id,
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
                                    worker_ctx.shared_sessions,
                                    worker_ctx.shared_nat_sessions,
                                    worker_ctx.shared_forward_wire_sessions,
                                    &worker_ctx.shared_owner_rg_indexes,
                                    &flow.forward_key,
                                    decision,
                                    local_metadata.clone(),
                                    SessionOrigin::LocalMiss,
                                    now_ns,
                                    meta.protocol,
                                    meta.tcp_flags,
                                ) {
                                    telemetry.counters.session_creates += 1;
                                    telemetry.dbg.session_create += 1;
                                    publish_bpf_conntrack_entry(
                                        conntrack_v4_fd,
                                        conntrack_v6_fd,
                                        &flow.forward_key,
                                        decision,
                                        &local_metadata,
                                        &worker_ctx.forwarding.zone_name_to_id,
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
                                    worker_ctx.forwarding,
                                    worker_ctx.dynamic_neighbors,
                                    worker_ctx.shared_sessions,
                                    worker_ctx.shared_nat_sessions,
                                    worker_ctx.shared_forward_wire_sessions,
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
                                            worker_ctx.forwarding,
                                            worker_ctx.ha_state,
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
                                                        worker_ctx.forwarding,
                                                        icmp_decision.resolution.egress_ifindex,
                                                    )
                                                };
                                            let cos = resolve_cos_tx_selection(
                                                worker_ctx.forwarding,
                                                icmp_decision.resolution.egress_ifindex,
                                                meta,
                                                None,
                                            );
                                            binding.scratch_forwards.push(PendingForwardRequest {
                                                target_ifindex,
                                                target_binding_index: worker_ctx.binding_lookup.target_index(
                                                    binding_index,
                                                    worker_ctx.ident.ifindex,
                                                    worker_ctx.ident.queue_id,
                                                    target_ifindex,
                                                ),
                                                ingress_queue_id: worker_ctx.ident.queue_id,
                                                desc,
                                                frame: PendingForwardFrame::Prebuilt(
                                                    rewritten_frame,
                                                ),
                                                meta: meta.into(),
                                                decision: icmp_decision,
                                                apply_nat_on_fabric: false,
                                                expected_ports: None,
                                                flow_key: None,
                                                nat64_reverse: None,
                                                cos_queue_id: cos.queue_id,
                                                dscp_rewrite: cos.dscp_rewrite,
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
                            } else if decision.resolution.disposition
                                == ForwardingDisposition::ForwardCandidate
                            {
                                let owner_rg_id =
                                    owner_rg_for_resolution(worker_ctx.forwarding, decision.resolution);
                                flow_cache_owner_rg_id = owner_rg_id;
                                // #850: allow-dns-reply admits sessionless DNS replies
                                // through policy (not around it). Always evaluate policy;
                                // the session-install step below is skipped only when
                                // the knob matches AND no NAT is required (to avoid
                                // orphan NAT state without a session anchor).
                                if let PolicyAction::Permit = evaluate_policy(
                                    &worker_ctx.forwarding.policy,
                                    from_zone_id,
                                    to_zone_id,
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
                                        let nat_match_flow =
                                            flow.with_destination(effective_resolution_target);
                                        if decision.nat.rewrite_dst.is_none() {
                                            // Try NPTv6 outbound: if src matches an internal prefix,
                                            // translate to external prefix (stateless, no L4 csum update).
                                            let nptv6_snat = if let IpAddr::V6(mut src_v6) =
                                                nat_match_flow.src_ip
                                            {
                                                if worker_ctx.forwarding.nptv6.translate_outbound(&mut src_v6)
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
                                                    worker_ctx.forwarding.static_nat.match_snat(
                                                        nat_match_flow.src_ip,
                                                        &from_zone,
                                                    )
                                                })
                                                .or_else(|| {
                                                    match_source_nat_for_flow(
                                                        worker_ctx.forwarding,
                                                        &from_zone,
                                                        &to_zone,
                                                        decision.resolution.egress_ifindex,
                                                        &nat_match_flow,
                                                    )
                                                })
                                                .unwrap_or_default();
                                        } else {
                                            let snat_decision = worker_ctx.forwarding
                                                .static_nat
                                                .match_snat(nat_match_flow.src_ip, &from_zone)
                                                .or_else(|| {
                                                    match_source_nat_for_flow(
                                                        worker_ctx.forwarding,
                                                        &from_zone,
                                                        &to_zone,
                                                        decision.resolution.egress_ifindex,
                                                        &nat_match_flow,
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
                                                &worker_ctx.ident,
                                                flow,
                                                worker_ctx.forwarding,
                                                worker_ctx.dynamic_neighbors,
                                                worker_ctx.ha_state,
                                                now_secs,
                                            )
                                        });
                                    if let Some(request) = local_icmp_te {
                                        binding.scratch_forwards.push(request);
                                        recycle_now = false;
                                    } else {
                                        let mut created = 0u64;
                                        // #850: DNS-reply fast-path skips session install
                                        // when no NAT is required.  If NAT is required, fall
                                        // through to normal session install so NAT state is
                                        // anchored for GC.
                                        let dns_fastpath_admit =
                                            allow_unsolicited_dns_reply(worker_ctx.forwarding, flow)
                                                && decision.nat.rewrite_src.is_none()
                                                && decision.nat.rewrite_dst.is_none()
                                                && !decision.nat.nat64
                                                && !decision.nat.nptv6;
                                        let track_in_userspace = decision.resolution.disposition
                                            != ForwardingDisposition::LocalDelivery
                                            && !dns_fastpath_admit;
                                        let install_local_reverse =
                                            should_install_local_reverse_session(
                                                decision,
                                                fabric_ingress,
                                            );
                                        let forward_metadata = SessionMetadata {
                                            ingress_zone: from_zone_id,
                                            egress_zone: to_zone_id,
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
                                                worker_ctx.shared_sessions,
                                                worker_ctx.shared_nat_sessions,
                                                worker_ctx.shared_forward_wire_sessions,
                                                &worker_ctx.shared_owner_rg_indexes,
                                                &forward_entry,
                                            );
                                            // Populate BPF dnat_table for embedded ICMP NAT reversal.
                                            // Without this, mtr/traceroute intermediate hops are invisible.
                                            publish_dnat_table_entry(
                                                &worker_ctx.dnat_fds,
                                                &flow.forward_key,
                                                decision.nat,
                                            );
                                            replicate_session_upsert(
                                                worker_ctx.peer_worker_commands,
                                                &forward_entry,
                                            );
                                        }
                                        let reverse_resolution = reverse_resolution_for_session(
                                            worker_ctx.forwarding,
                                            worker_ctx.ha_state,
                                            worker_ctx.dynamic_neighbors,
                                            flow.src_ip,
                                            from_zone_id,
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
                                            ingress_zone: to_zone_id,
                                            egress_zone: from_zone_id,
                                            owner_rg_id,
                                            fabric_ingress,
                                            is_reverse: true,
                                            nat64_reverse: nat64_info,
                                        };
                                        if track_in_userspace
                                            && install_local_reverse
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
                                                worker_ctx.shared_sessions,
                                                worker_ctx.shared_nat_sessions,
                                                worker_ctx.shared_forward_wire_sessions,
                                                &worker_ctx.shared_owner_rg_indexes,
                                                &reverse_entry,
                                            );
                                            replicate_session_upsert(
                                                worker_ctx.peer_worker_commands,
                                                &reverse_entry,
                                            );
                                        }
                                        if created > 0 {
                                            telemetry.counters.session_creates += created;
                                            telemetry.dbg.session_create += created;
                                        }
                                    }
                                } else {
                                    telemetry.dbg.policy_deny += 1;
                                    if cfg!(feature = "debug-log")
                                        && (telemetry.dbg.policy_deny <= 3 || is_trust_flow)
                                    {
                                        debug_log!(
                                            "DBG POLICY_DENY[{}]: {}:{} -> {}:{} proto={} zone={}->{}  ingress_if={} egress_if={}",
                                            telemetry.dbg.policy_deny,
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
                            } else if decision.resolution.disposition
                                == ForwardingDisposition::HAInactive
                                && !packet_fabric_ingress
                            {
                                let owner_rg_id =
                                    owner_rg_for_resolution(worker_ctx.forwarding, decision.resolution);
                                if owner_rg_id > 0 {
                                    flow_cache_owner_rg_id = owner_rg_id;
                                }
                                // New flow to inactive RG: fabric-redirect to the peer
                                // that owns the egress RG.  Use from_zone_arc directly
                                // (always in scope) rather than going through the debug
                                // struct which may not have been populated.
                                // #919/#922: ID-keyed redirect — no name lookup.
                                if let Some(redirect) = resolve_zone_encoded_fabric_redirect_by_id(
                                    worker_ctx.forwarding,
                                    from_zone_id,
                                )
                                .or_else(|| resolve_fabric_redirect(worker_ctx.forwarding))
                                {
                                    decision.resolution = redirect;
                                }
                            }
                            decision
                        }
                    } else {
                        let non_flow_resolution = enforce_ha_resolution_snapshot(
                            worker_ctx.forwarding,
                            worker_ctx.ha_state,
                            now_secs,
                            resolve_forwarding(
                                unsafe { &*area },
                                desc,
                                meta,
                                worker_ctx.forwarding,
                                worker_ctx.dynamic_neighbors,
                            ),
                        );
                        // For non-flow packets (no L4 ports), also attempt fabric
                        // redirect when the egress RG is inactive.
                        let final_resolution = if non_flow_resolution.disposition
                            == ForwardingDisposition::HAInactive
                            && !packet_fabric_ingress
                        {
                            resolve_fabric_redirect(worker_ctx.forwarding).unwrap_or(non_flow_resolution)
                        } else {
                            non_flow_resolution
                        };
                        SessionDecision {
                            resolution: final_resolution,
                            nat: NatDecision::default(),
                        }
                    };
                    // Safety net: convert any remaining HAInactive to fabric
                    // redirect. Session-hit and new-flow paths each attempt
                    // fabric redirect internally, but demoted sessions that
                    // arrive via DNAT/interface-NAT XDP shim paths can slip
                    // through with HAInactive when the inner conversion found
                    // no fabric link at the time. Anti-loop: never redirect
                    // packets that arrived on the fabric interface itself.
                    // Only redirect when the egress maps to a known RG.
                    // HAInactive with unknown ownership (rg=0) means unresolved
                    // — those should NOT be fabric-redirected.
                    let egress_rg = owner_rg_for_resolution(worker_ctx.forwarding, decision.resolution);
                    if decision.resolution.disposition == ForwardingDisposition::HAInactive
                        && egress_rg > 0
                        && !packet_fabric_ingress
                    {
                        if flow_cache_owner_rg_id <= 0 {
                            flow_cache_owner_rg_id = egress_rg;
                        }
                        // #919: prefer the cached u16 zone ID; fall back to
                        // looking up the ifindex's zone name and translating
                        // to an ID. resolve_zone_encoded_fabric_redirect_by_id
                        // skips the name round-trip.
                        // #921: direct ifindex → u16 (was a two-hop
                        // name round-trip).
                        let zone_id = session_ingress_zone.or_else(|| {
                            worker_ctx
                                .forwarding
                                .ifindex_to_zone_id
                                .get(&(meta.ingress_ifindex as i32))
                                .copied()
                        });
                        if let Some(redirect) = zone_id
                            .and_then(|id| {
                                resolve_zone_encoded_fabric_redirect_by_id(
                                    worker_ctx.forwarding,
                                    id,
                                )
                            })
                            .or_else(|| resolve_fabric_redirect(worker_ctx.forwarding))
                        {
                            decision.resolution = redirect;
                        }
                    }
                    if matches!(
                        decision.resolution.disposition,
                        ForwardingDisposition::ForwardCandidate
                            | ForwardingDisposition::FabricRedirect
                    ) {
                        telemetry.dbg.forward += 1;
                        // Direction-specific tracking
                        let ingress_if = meta.ingress_ifindex as i32;
                        let egress_if = decision.resolution.egress_ifindex;
                        if ingress_if == 5 {
                            telemetry.dbg.rx_from_trust += 1;
                            telemetry.dbg.fwd_trust_to_wan += 1;
                        } else if ingress_if == 6 {
                            telemetry.dbg.rx_from_wan += 1;
                            telemetry.dbg.fwd_wan_to_trust += 1;
                        }
                        // NAT decision tracking
                        if decision.nat.rewrite_src.is_some() && decision.nat.rewrite_dst.is_some()
                        {
                            telemetry.dbg.nat_applied_snat += 1;
                            telemetry.dbg.nat_applied_dnat += 1;
                        } else if decision.nat.rewrite_src.is_some() {
                            telemetry.dbg.nat_applied_snat += 1;
                        } else if decision.nat.rewrite_dst.is_some() {
                            telemetry.dbg.nat_applied_dnat += 1;
                        } else {
                            telemetry.dbg.nat_applied_none += 1;
                        }
                        // Log NAT details for first few forward-candidate packets
                        if cfg!(feature = "debug-log") {
                            if telemetry.dbg.forward <= 10 {
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
                                    telemetry.dbg.forward,
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
                                if telemetry.dbg.forward <= 20 {
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
                                        telemetry.dbg.forward,
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
                                                telemetry.dbg.forward, l4, tcp_hdr
                                            );
                                        }
                                    }
                                }
                                if (meta.tcp_flags & 0x04) != 0 {
                                    // RST
                                    telemetry.dbg.fwd_tcp_rst += 1;
                                    if telemetry.dbg.fwd_tcp_rst <= 5 {
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
                                            telemetry.dbg.fwd_tcp_rst,
                                            meta.tcp_flags,
                                            raw_flags
                                                .map(|f| format!("0x{:02x}", f))
                                                .unwrap_or_else(|| "NONE".into()),
                                            raw_window
                                                .map(|w| format!("{}", w))
                                                .unwrap_or_else(|| "NONE".into()),
                                            desc.len,
                                            telemetry.dbg.forward,
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
                                                    telemetry.dbg.fwd_tcp_rst,
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
                                    telemetry.dbg.fwd_tcp_fin += 1;
                                    if telemetry.dbg.fwd_tcp_fin <= 5 {
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
                                            telemetry.dbg.fwd_tcp_fin,
                                            meta.ingress_ifindex,
                                            flow_str,
                                            meta.tcp_flags,
                                        );
                                    }
                                }
                                // Detect zero-window in TCP frames by inspecting raw packet
                                if let Some(win) = raw_window {
                                    if win == 0 {
                                        telemetry.dbg.fwd_tcp_zero_window += 1;
                                        if telemetry.dbg.fwd_tcp_zero_window <= 10 {
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
                                                telemetry.dbg.fwd_tcp_zero_window,
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
                        telemetry.counters.forward_candidate_packets += 1;
                        if decision.nat.rewrite_src.is_some() {
                            telemetry.counters.snat_packets += 1;
                        }
                        if decision.nat.rewrite_dst.is_some() {
                            telemetry.counters.dnat_packets += 1;
                        }
                        if let Some(mut request) = build_live_forward_request_from_frame(
                            worker_ctx.binding_lookup,
                            binding_index,
                            &worker_ctx.ident,
                            desc,
                            packet_frame,
                            meta,
                            &decision,
                            worker_ctx.forwarding,
                            flow.as_ref(),
                            session_ingress_zone,
                            apply_nat_on_fabric,
                            None,
                            None,
                        ) {
                            request.frame = owned_packet_frame
                                .take()
                                .map(PendingForwardFrame::Owned)
                                .unwrap_or(PendingForwardFrame::Live);
                            telemetry.dbg.tx += 1; // track forward requests queued
                            if cfg!(feature = "debug-log") {
                                if telemetry.dbg.tx <= 5 {
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
                            let request_target_binding_index = request.target_binding_index;
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
                                    flow_cache_owner_rg_id,
                                    session_ingress_zone,
                                    request_target_binding_index,
                                    worker_ctx.forwarding,
                                    worker_ctx.ha_state,
                                    apply_nat_on_fabric,
                                    &worker_ctx.rg_epochs,
                                )
                            {
                                binding.flow_cache.insert(entry);
                            }
                            // ── End flow cache population ────────────────
                        } else {
                            telemetry.dbg.build_fail += 1;
                            if cfg!(feature = "debug-log") {
                                if telemetry.dbg.build_fail <= 3 {
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
                                telemetry.dbg.local += 1;
                                // Reinject to slow-path TUN so the kernel
                                // processes host-bound traffic (NDP, ICMP echo,
                                // BGP, etc.).  The first packet creates a BPF
                                // session map entry so subsequent packets bypass
                                // userspace entirely.
                                maybe_reinject_slow_path(
                                    worker_ctx.ident,
                                    &binding.live,
                                    worker_ctx.slow_path.as_deref(),
                                    worker_ctx.local_tunnel_deliveries,
                                    unsafe { &*area },
                                    desc,
                                    meta,
                                    decision,
                                    worker_ctx.recent_exceptions,
                                    worker_ctx.forwarding,
                                );
                                recycle_now = true;
                            }
                            ForwardingDisposition::NoRoute => {
                                telemetry.dbg.no_route += 1;
                                if cfg!(feature = "debug-log") {
                                    if telemetry.dbg.no_route <= 3 {
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
                                telemetry.dbg.missing_neigh += 1;
                                // #919/#922: zero-allocation ID-native resolution.
                                let (from_zone_id, to_zone_id) = zone_pair_ids_for_flow_with_override(
                                    worker_ctx.forwarding,
                                    meta.ingress_ifindex as i32,
                                    ingress_zone_override,
                                    decision.resolution.egress_ifindex,
                                );
                                // Borrow zone names as &str (no clone) for the
                                // string-typed downstream NAT helpers.
                                let from_zone: &str = worker_ctx
                                    .forwarding
                                    .zone_id_to_name
                                    .get(&from_zone_id)
                                    .map(|s| s.as_str())
                                    .unwrap_or("");
                                let to_zone: &str = worker_ctx
                                    .forwarding
                                    .zone_id_to_name
                                    .get(&to_zone_id)
                                    .map(|s| s.as_str())
                                    .unwrap_or("");
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
                                        let iface_name = worker_ctx.forwarding
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
                                        &worker_ctx.forwarding.policy,
                                        from_zone_id,
                                        to_zone_id,
                                        flow.src_ip,
                                        flow.dst_ip,
                                        flow.forward_key.protocol,
                                        flow.forward_key.src_port,
                                        flow.forward_key.dst_port,
                                    ) {
                                        let nat_match_flow = flow.with_destination(
                                            pending_decision.nat.rewrite_dst.unwrap_or(flow.dst_ip),
                                        );
                                        if pending_decision.nat.rewrite_dst.is_none() {
                                            pending_decision.nat = worker_ctx.forwarding
                                                .static_nat
                                                .match_snat(nat_match_flow.src_ip, &from_zone)
                                                .or_else(|| {
                                                    match_source_nat_for_flow(
                                                        worker_ctx.forwarding,
                                                        &from_zone,
                                                        &to_zone,
                                                        pending_decision.resolution.egress_ifindex,
                                                        &nat_match_flow,
                                                    )
                                                })
                                                .unwrap_or_default();
                                        } else {
                                            let snat_decision = worker_ctx.forwarding
                                                .static_nat
                                                .match_snat(nat_match_flow.src_ip, &from_zone)
                                                .or_else(|| {
                                                    match_source_nat_for_flow(
                                                        worker_ctx.forwarding,
                                                        &from_zone,
                                                        &to_zone,
                                                        pending_decision.resolution.egress_ifindex,
                                                        &nat_match_flow,
                                                    )
                                                })
                                                .unwrap_or_default();
                                            pending_decision.nat =
                                                pending_decision.nat.merge(snat_decision);
                                        }
                                    }
                                    let sess_meta = build_missing_neighbor_session_metadata(
                                        worker_ctx.forwarding,
                                        from_zone_id,
                                        to_zone_id,
                                        packet_fabric_ingress,
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
                                            worker_ctx.shared_sessions,
                                            worker_ctx.shared_nat_sessions,
                                            worker_ctx.shared_forward_wire_sessions,
                                            &worker_ctx.shared_owner_rg_indexes,
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
                                            &worker_ctx.forwarding.zone_name_to_id,
                                        );
                                        publish_dnat_table_entry(
                                            &worker_ctx.dnat_fds,
                                            &flow.forward_key,
                                            pending_decision.nat,
                                        );
                                        telemetry.counters.session_creates += 1;
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
                                    if telemetry.dbg.missing_neigh <= 3 {
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
                            ForwardingDisposition::PolicyDenied => telemetry.dbg.policy_deny += 1,
                            ForwardingDisposition::HAInactive => telemetry.dbg.ha_inactive += 1,
                            _ => telemetry.dbg.disposition_other += 1,
                        }
                        record_forwarding_disposition(
                            &worker_ctx.ident,
                            &binding.live,
                            decision.resolution,
                            desc.len as u32,
                            Some(meta),
                            debug.as_ref(),
                            worker_ctx.recent_exceptions,
                            worker_ctx.last_resolution,
                            worker_ctx.forwarding,
                        );
                        maybe_reinject_slow_path_from_frame(
                            &worker_ctx.ident,
                            &binding.live,
                            worker_ctx.slow_path,
                            worker_ctx.local_tunnel_deliveries,
                            packet_frame,
                            meta,
                            decision,
                            worker_ctx.recent_exceptions,
                            "slow_path",
                            worker_ctx.forwarding,
                        );
                    }
                } else {
                    record_disposition(
                        &worker_ctx.ident,
                        &binding.live,
                        disposition,
                        desc.len as u32,
                        Some(meta),
                        worker_ctx.recent_exceptions,
                        worker_ctx.forwarding,
                    );
                }
            } else {
                telemetry.dbg.metadata_err += 1;
                binding.live.metadata_errors.fetch_add(1, Ordering::Relaxed);
                record_exception(
                    worker_ctx.recent_exceptions,
                    &worker_ctx.ident,
                    "metadata_parse",
                    desc.len as u32,
                    None,
                    None,
                    worker_ctx.forwarding,
                );
            }
            if recycle_now {
                binding.scratch_recycle.push(desc.addr);
            }
        }
        received.release();
        drop(received);
}


fn retry_pending_neigh(
    binding: &mut BindingWorker,
    left: &mut [BindingWorker],
    binding_index: usize,
    right: &mut [BindingWorker],
    binding_lookup: &WorkerBindingLookup,
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
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
                    .or_else(|| dynamic_neighbors.get(&neigh_key).map(|e| e.mac))
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
                    false,
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
                        let cos = resolve_cos_tx_selection(
                            forwarding,
                            decision.resolution.egress_ifindex,
                            pkt.meta,
                            None,
                        );
                        let req = PreparedTxRequest {
                            offset: pkt.desc.addr,
                            len: frame_len,
                            recycle: PreparedTxRecycle::FillOnSlot(ingress_slot),
                            expected_ports: None,
                            expected_addr_family: pkt.meta.addr_family,
                            expected_protocol: pkt.meta.protocol,
                            flow_key: None,
                            egress_ifindex: decision.resolution.egress_ifindex,
                            cos_queue_id: cos.queue_id,
                            dscp_rewrite: cos.dscp_rewrite,
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

#[cfg_attr(not(test), allow(dead_code))]
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
    fabric_ingress_zone: Option<u16>,
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
        None,
        None,
    )
}

#[derive(Clone, Copy, Debug, Default)]
struct PendingForwardHints {
    expected_ports: Option<(u16, u16)>,
    target_binding_index: Option<usize>,
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
    fabric_ingress_zone: Option<u16>,
    apply_nat_on_fabric: bool,
    hints: Option<PendingForwardHints>,
    precomputed_tx_selection: Option<&CachedTxSelectionDescriptor>,
) -> Option<PendingForwardRequest> {
    let hints = hints.unwrap_or_default();
    let target_ifindex = if decision.resolution.tx_ifindex > 0 {
        decision.resolution.tx_ifindex
    } else {
        resolve_tx_binding_ifindex(forwarding, decision.resolution.egress_ifindex)
    };
    // Prefer session flow ports (set by conntrack, immune to DMA races),
    // then live frame ports (lazy — only parsed if session ports unavailable),
    // then metadata as last resort.
    let expected_ports = hints
        .expected_ports
        .or_else(|| authoritative_forward_ports(frame, meta, flow));
    let target_binding_index = hints.target_binding_index.or_else(|| {
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
        }
    });
    let mut decision = *decision;
    // #919/#922: ID-keyed redirect — no `zone_id_to_name` round-trip.
    if decision.resolution.disposition == ForwardingDisposition::FabricRedirect
        && let Some(ingress_zone_id) = fabric_ingress_zone
        && let Some(zone_redirect) =
            resolve_zone_encoded_fabric_redirect_by_id(forwarding, ingress_zone_id)
    {
        decision.resolution.src_mac = zone_redirect.src_mac;
    }
    let cos = precomputed_tx_selection
        .map(|selection| CoSTxSelection {
            queue_id: selection.queue_id,
            dscp_rewrite: selection.dscp_rewrite,
        })
        .unwrap_or_else(|| {
            resolve_cos_tx_selection(
                forwarding,
                decision.resolution.egress_ifindex,
                meta,
                flow.map(|flow| &flow.forward_key),
            )
        });
    Some(PendingForwardRequest {
        target_ifindex,
        target_binding_index,
        ingress_queue_id: ingress_ident.queue_id,
        desc,
        frame: PendingForwardFrame::Live,
        meta: meta.into(),
        decision,
        apply_nat_on_fabric,
        expected_ports,
        flow_key: flow.map(|flow| flow.forward_key.clone()),
        nat64_reverse: None,
        cos_queue_id: cos.queue_id,
        dscp_rewrite: cos.dscp_rewrite,
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
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
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
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
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
    // #949: multi-ifindex insert atomically vs readers — both
    // ingress_ifindex and the resolved logical (VLAN sub-) ifindex
    // get the same MAC under one bulk acquisition so a reader sees
    // either both or neither, never a stale half.
    dynamic_neighbors.with_all_shards(|bulk| {
        for ifindex in ifindexes {
            bulk.insert((ifindex, src_ip), NeighborEntry { mac: src_mac });
        }
    });
}

fn build_missing_neighbor_session_metadata(
    forwarding: &ForwardingState,
    ingress_zone: u16,
    egress_zone: u16,
    fabric_ingress: bool,
    decision: SessionDecision,
) -> SessionMetadata {
    SessionMetadata {
        ingress_zone,
        egress_zone,
        owner_rg_id: owner_rg_for_resolution(forwarding, decision.resolution),
        fabric_ingress,
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
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    recent_session_deltas: &Arc<Mutex<VecDeque<SessionDeltaInfo>>>,
    peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    event_stream: &Option<crate::event_stream::EventStreamWorkerHandle>,
    forwarding: &ForwardingState,
) {
    let zone_name_to_id = &forwarding.zone_name_to_id;
    let zone_id_to_name = &forwarding.zone_id_to_name;
    for delta in deltas {
        // #919/#922: emit both the resolved zone NAMES (legacy field,
        // empty when the ID is unknown) and the u16 IDs. New daemons
        // prefer the IDs; older daemons read the names. The previous
        // code wrote `metadata.ingress_zone.to_string()` here, which
        // produced "1"/"2" string literals that broke `zoneIDs[name]`
        // on the Go side.
        let ingress_name = zone_id_to_name
            .get(&delta.metadata.ingress_zone)
            .cloned()
            .unwrap_or_default();
        let egress_name = zone_id_to_name
            .get(&delta.metadata.egress_zone)
            .cloned()
            .unwrap_or_default();
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
            ingress_zone: ingress_name,
            egress_zone: egress_name,
            ingress_zone_id: delta.metadata.ingress_zone,
            egress_zone_id: delta.metadata.egress_zone,
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
                &shared_owner_rg_indexes,
                &delta.key,
            );
            let reverse_key = reverse_session_key(&delta.key, delta.decision.nat);
            delete_live_session_entry(session_map_fd, &reverse_key, delta.decision.nat, true);
            delete_bpf_conntrack_entry(conntrack_v4_fd, conntrack_v6_fd, &reverse_key);
            remove_shared_session(
                shared_sessions,
                shared_nat_sessions,
                shared_forward_wire_sessions,
                &shared_owner_rg_indexes,
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
    forwarding: &ForwardingState,
) {
    // #919: zone IDs render as zone names through `zone_id_to_name`;
    // unknown IDs render as the empty string (was the original
    // behaviour for unknown zone names too).
    let zone_name_for = |id: u16| -> String {
        forwarding
            .zone_id_to_name
            .get(&id)
            .cloned()
            .unwrap_or_default()
    };
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
                from_zone: debug.and_then(|d| d.from_zone).map(zone_name_for).unwrap_or_default(),
                to_zone: debug.and_then(|d| d.to_zone).map(zone_name_for).unwrap_or_default(),
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
    forwarding: &ForwardingState,
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
                forwarding,
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
                forwarding,
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
                forwarding,
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
                forwarding,
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
    forwarding: &ForwardingState,
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
            update_last_resolution(last_resolution, resolution, debug, forwarding);
            live.exception_packets.fetch_add(1, Ordering::Relaxed);
            record_exception(
                recent_exceptions,
                binding,
                "ha_inactive",
                packet_length,
                meta,
                debug,
                forwarding,
            );
        }
        ForwardingDisposition::PolicyDenied => {
            update_last_resolution(last_resolution, resolution, debug, forwarding);
            live.policy_denied_packets.fetch_add(1, Ordering::Relaxed);
            record_exception(
                recent_exceptions,
                binding,
                "policy_denied",
                packet_length,
                meta,
                debug,
                forwarding,
            );
        }
        ForwardingDisposition::NoRoute => {
            update_last_resolution(last_resolution, resolution, debug, forwarding);
            live.route_miss_packets.fetch_add(1, Ordering::Relaxed);
            record_exception(
                recent_exceptions,
                binding,
                "no_route",
                packet_length,
                meta,
                debug,
                forwarding,
            );
        }
        ForwardingDisposition::MissingNeighbor => {
            update_last_resolution(last_resolution, resolution, debug, forwarding);
            live.neighbor_miss_packets.fetch_add(1, Ordering::Relaxed);
            record_exception(
                recent_exceptions,
                binding,
                "missing_neighbor",
                packet_length,
                meta,
                debug,
                forwarding,
            );
        }
        ForwardingDisposition::DiscardRoute => {
            update_last_resolution(last_resolution, resolution, debug, forwarding);
            live.discard_route_packets.fetch_add(1, Ordering::Relaxed);
            record_exception(
                recent_exceptions,
                binding,
                "discard_route",
                packet_length,
                meta,
                debug,
                forwarding,
            );
        }
        ForwardingDisposition::NextTableUnsupported => {
            update_last_resolution(last_resolution, resolution, debug, forwarding);
            live.next_table_packets.fetch_add(1, Ordering::Relaxed);
            record_exception(
                recent_exceptions,
                binding,
                "next_table_unsupported",
                packet_length,
                meta,
                debug,
                forwarding,
            );
        }
    }
}

fn update_last_resolution(
    last_resolution: &Arc<Mutex<Option<PacketResolution>>>,
    resolution: ForwardingResolution,
    debug: Option<&ResolutionDebug>,
    forwarding: &ForwardingState,
) {
    if let Ok(mut last) = last_resolution.lock() {
        *last = Some(resolution.status(debug, forwarding));
    }
}
