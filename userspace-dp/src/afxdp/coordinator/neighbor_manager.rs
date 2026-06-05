use super::*;

/// One proactive neighbor-warm request (#1636 option C). Carries the
/// egress ifindex + next-hop to solicit, the interface name used by
/// `trigger_kernel_arp_probe`, the snapshot `generation` it was queued
/// under (for generation-collapse on dequeue), and the owning routing
/// group `rg_id` (per-RG HA gate: only warm when this node is forwarding
/// for that RG).
#[derive(Clone, Debug)]
pub(crate) struct WarmItem {
    pub(in crate::afxdp) ifindex: i32,
    pub(in crate::afxdp) hop: IpAddr,
    pub(in crate::afxdp) iface_name: String,
    pub(in crate::afxdp) generation: u64,
    pub(in crate::afxdp) rg_id: i32,
}

/// Bounded depth of the warm queue. Exceeds typical FRR snapshot route
/// counts (a handful to dozens) by a wide margin; on overflow the new
/// item is dropped and `warm_drops` is incremented.
pub(in crate::afxdp) const WARM_QUEUE_DEPTH: usize = 4096;

/// Per-key rate-limit window: skip re-warming the same (ifindex, hop)
/// within this window. Bounds wire-side solicit storms and socket churn
/// for permanently-unreachable next-hops.
pub(in crate::afxdp) const WARM_PER_KEY_RATE_LIMIT_NS: u64 = 5_000_000_000;

/// Snapshot-level rate-limit: skip the whole warm sweep if the last
/// admitted (non-forced) sweep was within this window. Coalesces a
/// config storm down to at most one sweep per second.
pub(in crate::afxdp) const WARM_SWEEP_RATE_LIMIT_NS: u64 = 1_000_000_000;

/// `last_probed_at` GC cadence + max entry age. The warmer loop prunes
/// keys older than `WARM_GC_MAX_AGE_NS` every `WARM_GC_INTERVAL_NS`.
pub(in crate::afxdp) const WARM_GC_INTERVAL_NS: u64 = 60_000_000_000;
pub(in crate::afxdp) const WARM_GC_MAX_AGE_NS: u64 = 300_000_000_000;

pub(crate) struct NeighborManager {
    pub(crate) dynamic: Arc<ShardedNeighborMap>,
    pub(crate) generation: Arc<AtomicU64>,
    pub(crate) manager_keys: Arc<Mutex<FastSet<(i32, IpAddr)>>>,
    pub(crate) monitor_stop: Option<Arc<AtomicBool>>,
    // #1636 option C: proactive neighbor warming.
    /// Per-(ifindex, hop) last-probe timestamp (monotonic ns) for the
    /// 5s per-key rate-limit. Shared with the warmer worker thread.
    pub(crate) last_probed_at: Arc<Mutex<FastMap<(i32, IpAddr), u64>>>,
    /// Producer handle into the warmer worker's bounded queue. `None`
    /// until the worker is spawned at coordinator bring-up.
    pub(crate) warm_queue: Option<SyncSender<WarmItem>>,
    /// Stop flag for the warmer worker thread.
    pub(crate) warm_stop: Option<Arc<AtomicBool>>,
    /// Bumped on each admitted warm sweep; items tagged with a stale
    /// generation are dropped on dequeue (generation collapse).
    pub(crate) warm_generation: Arc<AtomicU64>,
    /// Monotonic ns of the last admitted (non-forced) warm sweep, for
    /// the 1s snapshot-level rate-limit. AtomicU64 so `queue_warm_pass`
    /// can take `&self` and be called from both `refresh_runtime_snapshot`
    /// (`&mut self`) and the RG-promote path.
    pub(crate) last_warm_sweep_ns: Arc<AtomicU64>,
    /// Channel-full drop telemetry (Prometheus `warm_drops`).
    pub(crate) warm_drops: Arc<AtomicU64>,
    /// Worker-disconnected telemetry (Prometheus `warm_disconnected`).
    pub(crate) warm_disconnected: Arc<AtomicU64>,
    /// Once-only operator-visible log gate for the disconnect transition.
    pub(crate) warned_disconnect: Arc<AtomicBool>,
    // #1769: shared on-demand neighbor resolver.
    /// Resolver handle (producer + counters) cloned into each worker so
    /// the negative-cache fast-fail can enqueue an on-demand GET/probe.
    /// `None` until the resolver thread is spawned at coordinator
    /// bring-up.
    pub(crate) resolver: Option<Arc<super::super::neighbor_resolver::NeighborResolver>>,
    /// Shared resolver counters (queue depth gauge + GET/probe/epoch
    /// telemetry), surfaced to Prometheus.
    pub(crate) resolver_counters: Arc<super::super::neighbor_resolver::ResolverCounters>,
    /// Stop flag for the resolver worker thread.
    pub(crate) resolver_stop: Option<Arc<AtomicBool>>,
}

impl NeighborManager {
    pub(super) fn new() -> Self {
        Self {
            dynamic: Arc::new(ShardedNeighborMap::new()),
            generation: Arc::new(AtomicU64::new(0)),
            manager_keys: Arc::new(Mutex::new(FastSet::default())),
            monitor_stop: None,
            last_probed_at: Arc::new(Mutex::new(FastMap::default())),
            warm_queue: None,
            warm_stop: None,
            warm_generation: Arc::new(AtomicU64::new(0)),
            last_warm_sweep_ns: Arc::new(AtomicU64::new(0)),
            warm_drops: Arc::new(AtomicU64::new(0)),
            warm_disconnected: Arc::new(AtomicU64::new(0)),
            warned_disconnect: Arc::new(AtomicBool::new(false)),
            resolver: None,
            resolver_counters: Arc::new(
                super::super::neighbor_resolver::ResolverCounters::default(),
            ),
            resolver_stop: None,
        }
    }
}
