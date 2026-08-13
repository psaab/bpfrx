// #6304: bind the LIVE established-flow mirror call site.
//
// `stage_flow_cache_hit` had NO test reference anywhere in the tree
// (`git grep stage_flow_cache_hit -- '*tests*'` returned zero). The two #6114
// fail-on-revert tests drive the sample-before-CAS ordering through the DEAD
// `enqueue_sampled_mirror_clone_to_live` wrapper, which shares
// `sample_then_admit_mirror_clone` with this live path. Both are therefore
// bound to the SHARED HELPER, not to the live call site: reverting ONLY the
// call site here — leaving `sample_then_admit_mirror_clone` correct — passed
// the entire suite.
//
// This module closes that gap by driving `stage_flow_cache_hit` itself.
//
// TOPOLOGY (the fold round): every ifindex here is DISTINCT, and the ingress
// is a real 802.1Q-tagged unit, so the two resolutions the live call site
// performs are observable rather than collapsed onto one constant:
//
//   wire VLAN 80 on physical ifindex 6  --(ingress_logical_ifindex)-->  20080
//     `resolve_mirror_config` is keyed by the LOGICAL unit, so dropping
//     `meta.ingress_vlan_id` resolves NO mirror configuration at all.
//
//   mirror output unit 200  --(forwarding.egress[200].bind_ifindex)-->  22
//     `MirrorTargetMap` is keyed by the PHYSICAL XSK bind port, so passing
//     `config.output_ifindex` through unresolved searches for 200 and reports
//     `NoBinding`.
//
// An earlier revision of this module set ingress == egress == 7 and mirror
// out == 22 with no VLAN or interface maps, which left both of those live
// call-site regressions green.

use super::*;
use crate::afxdp::flow_cache::{FlowCacheEntry, FlowCacheStamp};
use crate::afxdp::umem::MmapArea;
use crate::ip_proto::PROTO_TCP;
use crate::test_zone_ids::*;
use std::collections::{BTreeMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

/// PHYSICAL AF_XDP bind port this worker owns.
const PHYS_INGRESS_IFINDEX: i32 = 6;
/// 802.1Q VID carried on the wire (a real tag: `l3_offset` is 18, not 14).
const INGRESS_VLAN_ID: u16 = 80;
/// LOGICAL (VLAN-selecting) ingress unit that `(6, 80)` resolves to.
const LOGICAL_INGRESS_IFINDEX: i32 = 20080;
/// Forward egress for the cached decision.
const EGRESS_IFINDEX: i32 = 7;
/// `then port-mirror` output — a LOGICAL unit, as the compiler emits it.
const MIRROR_OUT_LOGICAL_IFINDEX: i32 = 200;
/// ...backed by THIS physical XSK bind port, which is what `MirrorTargetMap`
/// is keyed by.
const MIRROR_OUT_BIND_IFINDEX: i32 = 22;
const BINDING_INDEX: usize = 0;

fn test_key() -> crate::session::SessionKey {
    crate::session::SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 100)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 50, 200)),
        src_port: 45678,
        dst_port: 443,
    }
}

/// A VLAN-80-tagged IPv4/TCP ACK with a healthy TTL (64), so the #3779
/// TTL-expiry arm above the mirror block does not divert it into a Time
/// Exceeded reply.
///
/// `version_ihl` is the IPv4 version/IHL byte. `0x45` is the well-formed
/// packet every test but the rollback one uses; the rollback test passes an
/// IHL that overruns the frame so BOTH in-place rewriters decline.
///
/// The 802.1Q tag is PHYSICALLY present because the shim only ever reports a
/// non-zero `ingress_vlan_id` together with `ingress_vlan_present`, and the
/// whole dataplane then reads L3 at 18 (`parse_l2` in `userspace-xdp`,
/// `poll_stages.rs:551`, `rewrite_plan_eth_from_parts`). A fixture with
/// `ingress_vlan_id = 80` and an untagged frame is a meta/frame pair the wire
/// format cannot produce.
fn vlan_tagged_tcp_v4_frame(version_ihl: u8) -> Vec<u8> {
    let key = test_key();
    let (IpAddr::V4(src_ip), IpAddr::V4(dst_ip)) = (key.src_ip, key.dst_ip) else {
        unreachable!("test key is v4")
    };
    let mut frame = Vec::new();
    // Ethernet dst + src, then the 802.1Q TPID.
    frame.extend_from_slice(&[
        0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0xbf, 0x72, 0x00, 0x01, 0x01, 0x81, 0x00,
    ]);
    // 802.1Q TCI (PCP 0, DEI 0, VID 80), then the inner ether_type.
    frame.extend_from_slice(&INGRESS_VLAN_ID.to_be_bytes());
    frame.extend_from_slice(&[0x08, 0x00]);
    // IPv4: total len 40, TTL 64, proto TCP.
    frame.extend_from_slice(&[
        version_ihl, 0x00, 0x00, 0x28, 0x12, 0x34, 0x40, 0x00, 64, PROTO_TCP, 0x00, 0x00,
    ]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    // TCP: ports, seq, ack, offset 5 / ACK, window, csum, urg.
    frame.extend_from_slice(&key.src_port.to_be_bytes());
    frame.extend_from_slice(&key.dst_port.to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    frame.extend_from_slice(&[0x50, 0x10, 0xfa, 0xf0]);
    frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    frame
}

fn tcp_v4_ack_frame() -> Vec<u8> {
    vlan_tagged_tcp_v4_frame(0x45)
}

fn test_meta(frame: &[u8]) -> UserspaceDpMeta {
    let key = test_key();
    let (IpAddr::V4(src_ip), IpAddr::V4(dst_ip)) = (key.src_ip, key.dst_ip) else {
        unreachable!("test key is v4")
    };
    let mut src_addr = [0u8; 16];
    src_addr[..4].copy_from_slice(&src_ip.octets());
    let mut dst_addr = [0u8; 16];
    dst_addr[..4].copy_from_slice(&dst_ip.octets());
    UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: PHYS_INGRESS_IFINDEX as u32,
        ingress_vlan_id: INGRESS_VLAN_ID,
        ingress_vlan_present: 1,
        l3_offset: 18,
        l4_offset: 38,
        payload_offset: 58,
        // The shim reports the FULL wire length (`packet_len = data_end - data`,
        // `userspace-xdp/src/lib.rs:566`), and the reinject path agrees
        // (`coordinator/inject.rs:73` uses `frame_len`). `pkt_len` feeds the
        // filter/policy/zone byte counters and the session byte accounting, so
        // an L2-stripped value under-reports every one of them.
        pkt_len: frame.len() as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        flow_src_addr: src_addr,
        flow_dst_addr: dst_addr,
        flow_src_port: key.src_port,
        flow_dst_port: key.dst_port,
        ..UserspaceDpMeta::default()
    }
}

fn cached_entry() -> FlowCacheEntry {
    FlowCacheEntry {
        key: test_key(),
        // #5139: the cache identity is (PHYSICAL parent, LOGICAL unit). The
        // lookup rebuilds both from the packet via `FlowCacheLookup::for_packet`,
        // so these must match what `(6, VLAN 80)` resolves to or the hit never
        // happens and every test below silently exercises the miss path.
        ingress_ifindex: PHYS_INGRESS_IFINDEX,
        logical_ingress_ifindex: LOGICAL_INGRESS_IFINDEX,
        descriptor: RewriteDescriptor {
            dst_mac: [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01],
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x01, 0x01],
            fabric_redirect: false,
            // Egress keeps the tag, so `eth_len == l3 == 18` and the in-place
            // rewrite is a pure header overwrite with no payload memmove.
            tx_vlan_id: INGRESS_VLAN_ID,
            ether_type: 0x0800,
            rewrite_src_ip: None,
            rewrite_dst_ip: None,
            rewrite_src_port: None,
            rewrite_dst_port: None,
            ip_csum_delta: 0,
            l4_csum_delta: 0,
            egress_ifindex: EGRESS_IFINDEX,
            tx_ifindex: EGRESS_IFINDEX,
            // Hairpin: the forward target IS this binding, which is the arm
            // that carries the in-place rewrite + the live mirror block.
            target_binding_index: Some(BINDING_INDEX),
            input_filter_log: None,
            input_filter_counters: crate::filter::CachedFilterCounters::default(),
            tx_selection: CachedTxSelectionDescriptor::default(),
            nat64: false,
            nptv6: false,
            apply_nat_on_fabric: false,
        },
        decision: SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: EGRESS_IFINDEX,
                tx_ifindex: EGRESS_IFINDEX,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1))),
                neighbor_mac: Some([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x01, 0x01]),
                tx_vlan_id: INGRESS_VLAN_ID,
            },
            nat: NatDecision::default(),
        },
        metadata: SessionMetadata {
            ingress_zone: TEST_TRUST_ZONE_ID,
            egress_zone: TEST_UNTRUST_ZONE_ID,
            owner_rg_id: 0,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
            log_session_init: false,
            log_session_close: false,
            policy_id: 0,
            inactivity_timeout_ns: None,
            policy_counter_idx: 0,
            policy_counter: None,
        },
        stamp: FlowCacheStamp {
            config_generation: 0,
            fib_generation: 0,
            owner_rg_id: 0,
            owner_rg_epoch: 0,
            owner_rg_lease_until: 0,
        },
        observed_bytes: 0,
        last_used_epoch: 0,
        neighbor_mac_epoch: 0,
        neighbor_shard: crate::afxdp::flow_cache::NEIGHBOR_SHARD_NONE,
    }
}

fn tx_pipeline() -> WorkerTxPipeline {
    WorkerTxPipeline {
        free_tx_frames: (0..8u64).collect(),
        pending_tx_prepared: VecDeque::new(),
        pending_tx_local: VecDeque::new(),
        max_pending_tx: 64,
        outstanding_tx: 0,
        pending_fill_frames: VecDeque::new(),
        in_flight_prepared_recycles: FastMap::default(),
        tx_submit_ns: Vec::new().into_boxed_slice(),
    }
}

fn tx_counters() -> WorkerTxCounters {
    WorkerTxCounters {
        pending_direct_tx_packets: 0,
        pending_copy_tx_packets: 0,
        pending_in_place_tx_packets: 0,
        pending_in_place_vlan_push_desc_packets: 0,
        pending_in_place_vlan_pop_desc_packets: 0,
        pending_in_place_vlan_push_no_headroom_packets: 0,
        pending_in_place_l2_memmove_fallback_packets: 0,
        pending_direct_tx_no_frame_fallback_packets: 0,
        pending_direct_tx_build_fallback_packets: 0,
        pending_direct_tx_disallowed_fallback_packets: 0,
    }
}

fn scratch() -> WorkerScratch {
    WorkerScratch {
        scratch_recycle: Vec::new(),
        scratch_forwards: Vec::new(),
        scratch_fill: Vec::new(),
        scratch_prepared_tx: Vec::new(),
        scratch_local_tx: Vec::new(),
        scratch_committed_orig_idx: Vec::new(),
        scratch_exact_prepared_tx: Vec::new(),
        scratch_exact_local_tx: Vec::new(),
        scratch_completed_offsets: Vec::new(),
        scratch_post_recycles: Vec::new(),
        scratch_cross_binding_tx: Vec::new(),
        scratch_rst_teardowns: Vec::new(),
    }
}

/// How much room the cross-worker mirror clone queue has when the packet
/// reaches admission.
#[derive(Clone, Copy, PartialEq, Eq)]
enum MirrorTargetQueue {
    /// Admission succeeds. This is the correct fixture for a NON-sampled
    /// packet: at cap, `try_acquire_pending_tx_admission` returns `Err` from
    /// its relaxed `admitted >= admission_cap` load BEFORE reaching the
    /// `compare_exchange_weak(AcqRel)`, so "no shared-CAS side effect" holds
    /// for the trivial reason that no CAS was reachable, whatever the call
    /// site did.
    WithRoom,
    /// Driven to its cap, so admission reports `QueueFullCrossWorker`.
    AtCap,
}

/// Owns every referent a `WorkerContext` borrows so the four call-site tests
/// below share ONE wiring definition. Before the fold each test carried its
/// own ~200-line copy, and the mirror maps drifted apart from the ifindexes
/// the call site actually resolves.
struct LiveCallSiteFixture {
    ingress_live: Arc<BindingLiveState>,
    target_live: Arc<BindingLiveState>,
    ident: BindingIdentity,
    binding_lookup: WorkerBindingLookup,
    mirror_targets: MirrorTargetMap,
    forwarding: ForwardingState,
    ha_state: BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: Arc<ShardedNeighborMap>,
    shared_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: SharedSessionOwnerRgIndexes,
    ike_exchanges: crate::afxdp::forwarding::SharedIkeExchangeTable,
    local_tunnel_deliveries: Arc<ArcSwap<BTreeMap<i32, LocalTunnelDelivery>>>,
    recent_exceptions: Arc<Mutex<ExceptionEventRing>>,
    last_resolution: Arc<Mutex<Option<ResolutionEvent>>>,
    peer_worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>>,
    dnat_fds: DnatTableFds,
    rg_epochs: [AtomicU32; MAX_RG_EPOCHS],
}

impl LiveCallSiteFixture {
    fn new(queue: MirrorTargetQueue) -> Self {
        let target_live = Arc::new(BindingLiveState::new());
        if queue == MirrorTargetQueue::AtCap {
            target_live.set_max_pending_tx(1);
            assert!(
                target_live
                    .try_enqueue_tx_owned(TxRequest {
                        bytes: Vec::new(),
                        expected_ports: None,
                        expected_addr_family: 0,
                        expected_protocol: 0,
                        flow_key: None,
                        egress_ifindex: MIRROR_OUT_BIND_IFINDEX,
                        cos_queue_id: None,
                        dscp_rewrite: None,
                        mirror_clone: false,
                        enqueue_ns: 0,
                    })
                    .is_ok(),
                "precondition: the mirror target's clone queue is driven to its cap"
            );
        }

        // The mirror target is a DIFFERENT binding, keyed — as production keys
        // it — by the PHYSICAL bind ifindex + the ingress queue id.
        let mut mirror_targets = MirrorTargetMap::default();
        mirror_targets.insert(
            &BindingIdentity {
                slot: 9,
                queue_id: 0,
                worker_id: 1,
                interface: Arc::<str>::from("mirror-out"),
                ifindex: MIRROR_OUT_BIND_IFINDEX,
            },
            target_live.clone(),
        );

        let mut forwarding = ForwardingState::default();
        // (physical 6, VLAN 80) -> logical unit 20080.
        forwarding
            .ingress_logical_ifindex
            .insert((PHYS_INGRESS_IFINDEX, INGRESS_VLAN_ID), LOGICAL_INGRESS_IFINDEX);
        // The mirror config hangs off the LOGICAL unit. Deliberately NOT also
        // registered under the physical ifindex: `resolve_mirror_config` falls
        // back to `mirror_configs[ingress_ifindex]`, and a duplicate entry
        // there would rescue a call site that ignored the VLAN id.
        forwarding.mirror_configs.insert(
            LOGICAL_INGRESS_IFINDEX,
            MirrorRuntimeConfig {
                output_ifindex: MIRROR_OUT_LOGICAL_IFINDEX,
                rate: 2,
            },
        );
        // The mirror output unit 200 binds to physical XSK port 22.
        forwarding.egress.insert(
            MIRROR_OUT_LOGICAL_IFINDEX,
            EgressInterface {
                bind_ifindex: MIRROR_OUT_BIND_IFINDEX,
                vlan_id: 0,
                mtu: 1500,
                src_mac: [0x02, 0xbf, 0x72, 0x00, 0x16, 0x00],
                zone_id: TEST_UNTRUST_ZONE_ID,
                redundancy_group: 0,
                primary_v4: None,
                primary_v6: None,
            },
        );

        Self {
            ingress_live: Arc::new(BindingLiveState::new()),
            target_live,
            ident: BindingIdentity {
                slot: 0,
                queue_id: 0,
                worker_id: 0,
                interface: Arc::<str>::from("ge-0-0-2"),
                ifindex: PHYS_INGRESS_IFINDEX,
            },
            binding_lookup: WorkerBindingLookup::default(),
            mirror_targets,
            forwarding,
            ha_state: BTreeMap::new(),
            dynamic_neighbors: Arc::new(ShardedNeighborMap::default()),
            shared_sessions: Arc::new(Mutex::new(FastMap::default())),
            shared_nat_sessions: Arc::new(Mutex::new(FastMap::default())),
            shared_forward_wire_sessions: Arc::new(Mutex::new(FastMap::default())),
            shared_owner_rg_indexes: SharedSessionOwnerRgIndexes::default(),
            ike_exchanges: Arc::new(crate::afxdp::forwarding::IkeExchangeTable::new()),
            local_tunnel_deliveries: Arc::new(ArcSwap::from_pointee(BTreeMap::new())),
            recent_exceptions: Arc::new(Mutex::new(ExceptionEventRing::new())),
            last_resolution: Arc::new(Mutex::new(None)),
            peer_worker_commands: Vec::new(),
            dnat_fds: DnatTableFds::default(),
            rg_epochs: std::array::from_fn(|_| AtomicU32::new(0)),
        }
    }

    fn worker_ctx(&self) -> WorkerContext<'_> {
        WorkerContext {
            ident: &self.ident,
            binding_lookup: &self.binding_lookup,
            mirror_targets: &self.mirror_targets,
            forwarding: &self.forwarding,
            ha_state: &self.ha_state,
            dynamic_neighbors: &self.dynamic_neighbors,
            neighbor_resolver: None,
            shared_sessions: &self.shared_sessions,
            shared_nat_sessions: &self.shared_nat_sessions,
            shared_forward_wire_sessions: &self.shared_forward_wire_sessions,
            shared_owner_rg_indexes: &self.shared_owner_rg_indexes,
            ike_exchanges: &self.ike_exchanges,
            slow_path: None,
            event_stream: None,
            local_tunnel_deliveries: &self.local_tunnel_deliveries,
            recent_exceptions: &self.recent_exceptions,
            last_resolution: &self.last_resolution,
            peer_worker_commands: &self.peer_worker_commands,
            dnat_fds: &self.dnat_fds,
            rg_epochs: &self.rg_epochs,
            cold_path_sample_mask: 0xff,
        }
    }
}

/// What one `stage_flow_cache_hit` call did, with everything the tests assert
/// on lifted out of the UMEM's lifetime.
struct StageRun {
    outcome: FlowCacheOutcome,
    tx_pipeline: WorkerTxPipeline,
    tx_counters: WorkerTxCounters,
    scratch: WorkerScratch,
    mirror_sample_counter: u64,
}

/// Drive the LIVE call site once.
///
/// #6304 fidelity: production slices `raw_frame` straight out of the UMEM
/// (`poll_descriptor/mod.rs`: `unsafe { &*area }.slice(desc.addr, desc.len)`),
/// so `packet_frame` ALIASES the bytes `apply_rewrite_descriptor` then mutates
/// in place (TTL decrement + checksum delta). Handing a heap copy in here
/// instead would decouple the mirror clone from the rewrite and make "the
/// clone carries the PRE-rewrite frame" true for free — the
/// capture-before-rewrite ordering at `flow_cache_hit.rs` would be unbound.
/// The caller's `frame` stays pristine as the comparison value.
fn run_stage(
    fixture: &LiveCallSiteFixture,
    frame: &[u8],
    initial_sample_counter: u64,
) -> StageRun {
    let mut area = MmapArea::new(2 * 1024 * 1024).expect("umem mmap");
    let frame_offset: u64 = 4096;
    area.slice_mut(frame_offset as usize, frame.len())
        .expect("umem slice for the test frame")
        .copy_from_slice(frame);
    let desc = XdpDesc {
        addr: frame_offset,
        len: frame.len() as u32,
        options: 0,
    };
    let raw_frame = area
        .slice(frame_offset as usize, frame.len())
        .expect("raw frame must ALIAS the UMEM, as it does in production");

    let mut flow_state = WorkerFlowCacheState {
        flow_cache: FlowCache::new(),
    };
    flow_state.flow_cache.insert(cached_entry());

    let mut tx_pipeline_state = tx_pipeline();
    let mut tx_counters_state = tx_counters();
    let mut scratch_state = scratch();
    let mut sessions = SessionTable::new();
    let mut dbg = DebugPollCounters::default();
    let mut counters = BatchCounters::default();
    let mut telemetry = TelemetryContext {
        dbg: &mut dbg,
        counters: &mut counters,
    };

    let meta = test_meta(frame);
    let flow = SessionFlow {
        src_ip: test_key().src_ip,
        dst_ip: test_key().dst_ip,
        forward_key: test_key(),
    };
    let mut owned_packet_frame: Option<Vec<u8>> = None;
    let mut mirror_sample_counter = initial_sample_counter;

    let outcome = stage_flow_cache_hit(
        &mut flow_state,
        &mut tx_pipeline_state,
        &mut tx_counters_state,
        &mut scratch_state,
        &mut mirror_sample_counter,
        &fixture.ingress_live,
        0,
        BINDING_INDEX,
        desc,
        &area as *const MmapArea,
        raw_frame,
        &mut owned_packet_frame,
        meta,
        &flow,
        false,
        ValidationState::default(),
        &mut sessions,
        1_000_000,
        1,
        &fixture.worker_ctx(),
        &mut telemetry,
    );

    StageRun {
        outcome,
        tx_pipeline: tx_pipeline_state,
        tx_counters: tx_counters_state,
        scratch: scratch_state,
        mirror_sample_counter,
    }
}

/// #6304 FAIL-ON-REVERT (live call site): a NON-sampled packet on the
/// established-flow HOT path must not produce, reserve for, or account a
/// mirror clone.
///
/// The target here has ROOM. That is deliberate and load-bearing: with the
/// target AT CAP (the pre-fold fixture) `try_acquire_pending_tx_admission`
/// bails at its relaxed `admitted >= admission_cap` load before the
/// `compare_exchange_weak(AcqRel)` ever executes, so a zero drop counter was
/// satisfied by the queue being full rather than by the packet being declined
/// — the assertion could not tell the two apart. With room, a call site that
/// let an unsampled packet through to admission ENQUEUES a real clone, and the
/// target-queue assertion below fails.
///
/// The mirror result is recorded ONLY inside the successful in-place-rewrite
/// branch, so the positive controls are load-bearing too: without them a
/// fixture whose rewrite silently failed would report 0 under both the correct
/// and the reverted call site — a test that looks bound and is not.
#[test]
fn live_flow_cache_callsite_nonsampled_produces_no_clone_6304() {
    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    let frame = tcp_v4_ack_frame();
    // rate = 2 with counter = 1 -> `mirror_sample_allows` is FALSE.
    let run = run_stage(&fixture, &frame, 1);

    // --- POSITIVE CONTROLS: the fixture actually reached the recording point.
    assert!(
        matches!(run.outcome, FlowCacheOutcome::Consumed),
        "control: the cached flow must be consumed by the fast path"
    );
    assert_eq!(
        run.tx_counters.pending_in_place_tx_packets, 1,
        "control: the in-place hairpin rewrite must have SUCCEEDED — this is the \
         branch the mirror result is recorded in"
    );
    assert_eq!(
        run.tx_pipeline.pending_tx_prepared.len(),
        1,
        "control: the rewritten frame must be queued for TX"
    );

    // --- THE #6304 DISCRIMINATOR: nothing mirror-shaped happened at all.
    let mut queued = VecDeque::new();
    fixture.target_live.take_pending_tx_into(&mut queued);
    assert!(
        queued.is_empty(),
        "#6304: a NON-sampled packet must not enqueue a clone on the mirror \
         target — the target had ROOM, so a call site that admitted before \
         consulting the sampler lands a real frame here"
    );
    assert_eq!(
        fixture.ingress_live.mirrored_packets.load(Ordering::Relaxed),
        0,
        "#6304: and it must not be accounted as mirrored"
    );
    assert_eq!(
        fixture
            .ingress_live
            .mirror_drops_queue_full
            .load(Ordering::Relaxed),
        0,
        "#6304: a non-sampled packet must not report clone-queue pressure"
    );
    assert_eq!(
        fixture
            .ingress_live
            .mirror_drops_no_binding
            .load(Ordering::Relaxed),
        0,
        "#6304: nor a resolution failure it never attempted"
    );
    // The worker-local sampler still advances for the declined packet
    // (committed because the rewrite succeeded).
    assert_eq!(
        run.mirror_sample_counter, 2,
        "the worker-local sampler advances for the declined packet"
    );
}

/// #6304 companion (SELECTED arm, full queue): the test above pins
/// `mirror_sample_counter = 1` at `rate = 2`, so `mirror_sample_allows` is
/// FALSE and `MirrorSampleAdmission::NotSampled` short-circuits — everything
/// downstream of `Sampled(..)` at the live call site is left unbound by it.
/// Two mutations confirmed that firsthand, both leaving `mirror/resolver.rs`
/// byte-identical and the whole suite green:
///   - commit `mirror_next_counter` on `NotSampled`/`Sampled(Ok)` but NOT on
///     `Sampled(Err)` — the exact behavior #6114 adjudicated a bug. Under
///     sustained clone-queue pressure the hot path pins itself at the sampler's
///     first slot and hammers the shared `pending_tx_admitted` CAS at O(PPS)
///     instead of O(PPS/R).
///   - `Sampled(Ok(_)) => None` — every selected packet silently drops its
///     clone; port mirroring stops delivering on this path entirely.
///
/// This test binds the first: a SELECTED packet on a FULL cross-worker target
/// advances the sampler and THEN reports the pressure (#6114's sample-first
/// intent resolution), at the LIVE call site rather than through the dead
/// wrapper.
///
/// It also makes the mirror WIRING a standing assertion rather than a one-time
/// observation. Asserting a NON-zero `mirror_drops_queue_full_cross_worker`
/// fails loudly if the fixture ever stops reaching a resolved, cross-worker,
/// genuinely full target.
#[test]
fn live_flow_cache_callsite_selected_full_queue_advances_sampler_6304() {
    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::AtCap);
    let frame = tcp_v4_ack_frame();
    // rate = 2 with counter = 0 -> selected, so it reaches admission.
    let run = run_stage(&fixture, &frame, 0);

    // --- POSITIVE CONTROLS (same rationale as the non-sampled test).
    assert!(
        matches!(run.outcome, FlowCacheOutcome::Consumed),
        "control: the cached flow must be consumed by the fast path"
    );
    assert_eq!(
        run.tx_counters.pending_in_place_tx_packets, 1,
        "control: the in-place hairpin rewrite must have SUCCEEDED — this is the \
         branch the mirror result is recorded in"
    );
    assert_eq!(
        run.tx_pipeline.pending_tx_prepared.len(),
        1,
        "control: the rewritten frame must be queued for TX"
    );

    // --- WIRING, asserted rather than merely observed. A `NoBinding`
    // short-circuit — which is what dropping the `output_ifindex` resolution
    // produces — would read 0 here.
    assert_eq!(
        fixture
            .ingress_live
            .mirror_drops_queue_full
            .load(Ordering::Relaxed),
        1,
        "#6304: a SELECTED packet on a full cross-worker clone queue reports the \
         pressure; reading 0 means the fixture never reached a genuinely full \
         cross-worker target"
    );
    assert_eq!(
        fixture
            .ingress_live
            .mirror_drops_queue_full_cross_worker
            .load(Ordering::Relaxed),
        1,
        "#6304: and the pressure is attributed to the CROSS-WORKER counter"
    );

    // --- THE DISCRIMINATOR: sample-first means the sampler advanced BEFORE the
    // admission failed. Re-introducing the #6114-adjudicated bug at this call
    // site (commit the local counter on NotSampled/Sampled(Ok) but not on
    // Sampled(Err)) leaves it at 0.
    assert_eq!(
        run.mirror_sample_counter, 1,
        "#6304: the SELECTED packet advances the sampler before the full-queue \
         admit fails; deferring the commit on Sampled(Err) pins the hot path at \
         the sampler's first slot and restores the O(PPS) shared-CAS hit"
    );
    assert_eq!(
        fixture.ingress_live.mirrored_packets.load(Ordering::Relaxed),
        0,
        "a clone that was never admitted must not be counted as mirrored"
    );
}

/// #6304 companion (SELECTED arm, admittable target): binds the
/// `MirrorSampleAdmission::Sampled(Ok(..))` arm of the LIVE call site, which
/// the full-queue test never reaches. Mutating `Sampled(Ok(_)) => None` (every
/// selected packet silently drops its clone; port mirroring stops delivering
/// on this path) is green without it.
///
/// This is also the test that binds BOTH live-call-site resolutions, because
/// each collapses the clone to nothing:
///   - dropping `meta.ingress_vlan_id` from the `resolve_mirror_config` call
///     resolves logical unit 20080 -> nothing, so no mirror config is found
///     and no clone is emitted;
///   - passing `config.output_ifindex` (logical 200) to admission instead of
///     resolving it to the physical bind port 22 makes `MirrorTargetMap`
///     report `NoBinding`.
#[test]
fn live_flow_cache_callsite_selected_admitted_clone_reaches_target_6304() {
    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    let frame = tcp_v4_ack_frame();
    let run = run_stage(&fixture, &frame, 0);

    // --- POSITIVE CONTROLS.
    assert!(
        matches!(run.outcome, FlowCacheOutcome::Consumed),
        "control: the cached flow must be consumed by the fast path"
    );
    assert_eq!(
        run.tx_counters.pending_in_place_tx_packets, 1,
        "control: the in-place hairpin rewrite must have SUCCEEDED — this is the \
         branch the mirror clone is enqueued in"
    );

    // --- THE DISCRIMINATOR: the admitted clone must actually be delivered.
    assert_eq!(
        fixture.ingress_live.mirrored_packets.load(Ordering::Relaxed),
        1,
        "#6304: a SELECTED packet whose cross-worker target has room must have \
         its clone enqueued; dropping the Sampled(Ok) arm silently stops port \
         mirroring, and so does resolving either the ingress VLAN unit or the \
         mirror output ifindex incorrectly"
    );
    assert_eq!(
        fixture.ingress_live.mirrored_bytes.load(Ordering::Relaxed),
        frame.len() as u64,
        "#6304: the full-L2 frame length is accounted to the mirror byte counter"
    );
    assert_eq!(
        fixture
            .ingress_live
            .mirror_drops_no_binding
            .load(Ordering::Relaxed),
        0,
        "#6304: the mirror output unit resolves to a bound XSK port; a NoBinding \
         here means `config.output_ifindex` reached admission unresolved"
    );
    assert_eq!(
        fixture
            .ingress_live
            .mirror_drops_queue_full
            .load(Ordering::Relaxed),
        0,
        "an admittable target must not report clone-queue pressure"
    );
    assert_eq!(
        run.mirror_sample_counter, 1,
        "the sampler advances for the selected packet"
    );

    // The clone is a real full-L2 copy on the TARGET binding's queue, flagged
    // as a mirror clone and addressed to the mirror output interface.
    let mut queued = VecDeque::new();
    fixture.target_live.take_pending_tx_into(&mut queued);
    let clone = queued.pop_front().expect("the mirror clone must be queued");
    assert!(
        clone.mirror_clone,
        "the queued request must be flagged as a mirror clone"
    );
    assert_eq!(
        clone.egress_ifindex, MIRROR_OUT_LOGICAL_IFINDEX,
        "the clone egresses the mirror output interface"
    );
    assert_eq!(
        clone.bytes, frame,
        "the clone carries the full L2 frame verbatim, tag included, captured \
         BEFORE the in-place rewrite mutated the UMEM"
    );
    assert!(
        queued.is_empty(),
        "exactly one clone — the rewritten original goes out the ingress binding"
    );
}

/// #6304 (rewrite-failure rollback): sampling and admission run BEFORE the
/// in-place rewrite, but the sampler commit and the clone delivery are
/// deliberately deferred until the rewrite succeeds. Every other test in this
/// module requires a SUCCESSFUL rewrite, so hoisting
///
///     if let Some(next_counter) = mirror_next_counter { *mirror_sample_counter = next_counter; }
///
/// above the `if let Some(rewrite_result)` check is green under all three.
///
/// Here BOTH in-place rewriters decline and the packet takes the
/// `PendingForwardRequest` fallback, where `tx/dispatch` re-runs mirror
/// selection from scratch. Committing the sampler on this path would consume a
/// sampling slot for a packet this call site never mirrored, so the flow's
/// effective mirror rate silently halves whenever the fast path is missing.
///
/// The decline is driven by an IPv4 header whose IHL (15 -> 60 bytes) overruns
/// the 40-byte L3 payload. Both rewriters gate on exactly that, and both do so
/// BEFORE their first UMEM write (`validate_rewrite_descriptor_ipv4` for the
/// descriptor path, `validate_generic_rewrite_v4` for the generic one), so the
/// frame is still pristine when the fallback re-reads it — the #4965/#5466
/// preflight-then-commit contract. A port mismatch does NOT work here: the
/// generic path REPAIRS ports via `restore_l4_tuple_from_meta` /
/// `enforce_expected_ports` rather than declining, so only the descriptor path
/// would bail.
#[test]
fn live_flow_cache_callsite_rewrite_failure_rolls_back_sampler_6304() {
    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    // version 4, IHL 15 (= 60 bytes) over a 40-byte L3 payload.
    let frame = vlan_tagged_tcp_v4_frame(0x4f);
    // rate = 2 with counter = 0 -> SELECTED, so the sampler has something to
    // roll back and admission is genuinely taken and released.
    let run = run_stage(&fixture, &frame, 0);

    // --- POSITIVE CONTROLS: the packet really did take the fallback, and it
    // took it because the rewrite declined rather than because the flow-cache
    // lookup missed.
    assert!(
        matches!(run.outcome, FlowCacheOutcome::Consumed),
        "control: the cached flow must still be consumed by the fast path"
    );
    assert_eq!(
        run.tx_counters.pending_in_place_tx_packets, 0,
        "control: BOTH in-place rewriters must have declined — if either had \
         succeeded this test would be re-asserting the committed path"
    );
    assert_eq!(
        run.scratch.scratch_forwards.len(),
        1,
        "control: the packet falls through to the PendingForwardRequest path, \
         where tx/dispatch re-runs mirror selection"
    );
    assert!(
        run.scratch.scratch_recycle.is_empty(),
        "control: the fallback owns the frame, so it is not recycled here"
    );

    // --- THE DISCRIMINATOR: nothing about the abandoned mirror decision
    // survives. Hoisting the sampler commit above the rewrite check leaves
    // this at 1.
    assert_eq!(
        run.mirror_sample_counter, 0,
        "#6304: a mirror decision taken before a rewrite that then declined must \
         NOT advance the worker-local sampler — the fallback path re-runs mirror \
         selection, so committing here consumes a sampling slot for a clone this \
         call site never emitted"
    );

    // ...and no clone was delivered or accounted on the way out.
    let mut queued = VecDeque::new();
    fixture.target_live.take_pending_tx_into(&mut queued);
    assert!(
        queued.is_empty(),
        "#6304: the reserved admission is released, not spent — no clone reaches \
         the target from the declined fast path"
    );
    assert_eq!(
        fixture.ingress_live.mirrored_packets.load(Ordering::Relaxed),
        0,
        "#6304: and nothing is accounted as mirrored"
    );
}

/// #6304 (call-site delegation canary). The sample-before-reserve ORDERING is
/// a shared-cacheline property, not a functional one: inlining
/// `admit_mirror_clone_to_live` above the sampler at this call site and
/// discarding the reservation when the sampler declines produces byte-identical
/// observable behaviour — the reservation is taken with an AcqRel CAS and given
/// straight back by `PendingTxAdmission::drop`, so no counter, queue, or frame
/// differs. That was verified firsthand: the mutation compiles and every
/// behavioural test in this module stays green.
///
/// What CAN be pinned is that the call site does not open-code the reservation
/// at all. `sample_then_admit_mirror_clone` is the single home for the #6114
/// ordering invariant and is itself covered by the fail-on-revert tests in
/// `mirror/mod_tests.rs`; as long as this call site goes through it, the
/// ordering is inherited rather than restated.
///
/// Limits, stated plainly: this is a source-text canary, not a runtime
/// observation. It does not catch a reserve-before-sample introduced INSIDE
/// the shared helper (the #6114 tests do), and it would need updating if the
/// helper is legitimately renamed.
#[test]
fn live_flow_cache_callsite_delegates_to_the_shared_sampler_6304() {
    let src = include_str!("flow_cache_hit.rs");
    assert!(
        src.contains("sample_then_admit_mirror_clone("),
        "#6304: stage_flow_cache_hit must reach the mirror clone queue through \
         `sample_then_admit_mirror_clone`, the single home of the #6114 \
         sample-before-reserve ordering"
    );
    assert!(
        !src.contains("admit_mirror_clone_to_live("),
        "#6304: stage_flow_cache_hit must NOT call `admit_mirror_clone_to_live` \
         directly — open-coding the reservation at this call site reintroduces \
         the O(PPS) cross-core true-sharing #6114 removed, and does so without \
         changing any observable counter, so no behavioural test can catch it"
    );
}
