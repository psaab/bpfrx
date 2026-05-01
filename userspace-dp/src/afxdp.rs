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
#[path = "afxdp/frame/mod.rs"]
mod frame;
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
#[path = "afxdp/types/mod.rs"]
mod types;
#[path = "afxdp/umem/mod.rs"]
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
use self::tx::dispatch::*;
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

#[path = "afxdp/coordinator/mod.rs"]
mod coordinator;
#[cfg(test)]
#[path = "afxdp/tests.rs"]
mod tests;
#[path = "afxdp/worker/mod.rs"]
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

mod poll_descriptor;
use poll_descriptor::poll_binding_process_descriptor;
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
