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
/// `option_words` is the number of 32-bit IPv4 option words, so the IHL nibble
/// is `5 + option_words` and the header is genuinely that long: `total_len`,
/// the frame length and the metadata offsets all follow from it. Every test
/// here uses a self-consistent frame; the rollback test corrupts ONE byte of
/// this frame AFTER construction, which is the only way that decline is
/// reachable (see `dma_raced_short_ihl_frame`).
///
/// The 802.1Q tag is PHYSICALLY present because the shim only ever reports a
/// non-zero `ingress_vlan_id` together with `ingress_vlan_present`, and the
/// whole dataplane then reads L3 at 18 (`parse_l2` in `userspace-xdp`,
/// `poll_stages.rs:551`, `rewrite_plan_eth_from_parts`). A fixture with
/// `ingress_vlan_id = 80` and an untagged frame is a meta/frame pair the wire
/// format cannot produce.
///
/// Both checksum fields (IPv4 header at [28..30], TCP at [50..52] of the
/// no-option frame) are left ZERO, which no correct sender emits. Nothing on
/// this path verifies either one — XDP receives whatever the NIC DMA'd, and
/// both rewriters only apply INCREMENTAL deltas
/// (`adjust_ipv4_header_checksum`, `recompute_l4_checksum_ipv4`) rather than
/// validating the inbound value — so the zero does not change any decision
/// under test. It does mean the frame is not a wire-valid packet end to end,
/// only in every field these tests read.
fn vlan_tagged_tcp_v4_frame(option_words: usize) -> Vec<u8> {
    let key = test_key();
    let (IpAddr::V4(src_ip), IpAddr::V4(dst_ip)) = (key.src_ip, key.dst_ip) else {
        unreachable!("test key is v4")
    };
    let ihl_words = 5 + option_words;
    assert!(ihl_words <= 15, "IPv4 IHL nibble is 4 bits");
    let total_len = (ihl_words * 4 + 20) as u16;
    let mut frame = Vec::new();
    // Ethernet dst + src, then the 802.1Q TPID.
    frame.extend_from_slice(&[
        0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0xbf, 0x72, 0x00, 0x01, 0x01, 0x81, 0x00,
    ]);
    // 802.1Q TCI (PCP 0, DEI 0, VID 80), then the inner ether_type.
    frame.extend_from_slice(&INGRESS_VLAN_ID.to_be_bytes());
    frame.extend_from_slice(&[0x08, 0x00]);
    // IPv4: version 4 + the declared IHL, TTL 64, proto TCP.
    frame.push(0x40 | ihl_words as u8);
    frame.push(0x00);
    frame.extend_from_slice(&total_len.to_be_bytes());
    frame.extend_from_slice(&[0x12, 0x34, 0x40, 0x00, 64, PROTO_TCP, 0x00, 0x00]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    // IPv4 options: one NOP (type 1) per byte. Padding a header out with NOPs
    // is legal per RFC 791 §3.1 and is what a router emits when it has to
    // preserve header length without carrying an option.
    frame.extend(std::iter::repeat_n(0x01u8, option_words * 4));
    // TCP: ports, seq, ack, offset 5 / ACK, window, csum, urg.
    frame.extend_from_slice(&key.src_port.to_be_bytes());
    frame.extend_from_slice(&key.dst_port.to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    frame.extend_from_slice(&[0x50, 0x10, 0xfa, 0xf0]);
    frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    assert_eq!(
        frame.len(),
        18 + total_len as usize,
        "the frame must carry exactly the datagram it declares"
    );
    frame
}

fn tcp_v4_ack_frame() -> Vec<u8> {
    vlan_tagged_tcp_v4_frame(0)
}

/// The rollback fixture: a frame whose IPv4 IHL nibble was overwritten to 15
/// (60 bytes) AFTER the shim parsed and described it, leaving an L3 payload
/// (40 bytes) shorter than the header the packet now declares.
///
/// DOMAIN PARITY, stated exactly. This is NOT a frame the parser could have
/// produced together with `test_meta`'s offsets: `parse_ipv4`
/// (`userspace-xdp/src/lib.rs`) does `read_bytes(data, data_end, l3_offset,
/// ihl)?` before deriving `l4_offset`, so a shim-delivered IPv4 packet ALWAYS
/// satisfies `frame.len() - l3 >= ihl`, and `ipv4_declared_l3_end` then clamps
/// the trimmed payload UP to at least `ihl`. Those two facts COMPOSE rather
/// than corroborate, and the shim leg is the load-bearing one: on exactly the
/// input it excludes (`frame.len() < l3 + ihl`) `ipv4_declared_l3_end` returns
/// `None` rather than clamping, and `trim_l3_payload` falls through to a
/// `meta.pkt_len`-derived length with no `ihl` relation at all. So the clamp
/// bites only where the shim leg already holds — do not lean on it alone.
/// Together they mean no self-consistent, shim-produced IPv4 frame can make
/// either in-place rewriter take its `l3_payload.len() < ihl` bail — verified
/// firsthand by
/// `live_flow_cache_callsite_ip_options_frame_takes_the_in_place_path_6304`,
/// which feeds the SELF-CONSISTENT IHL-15 packet (40 bytes of options, an
/// honest 80-byte datagram) and watches the rewrite succeed.
///
/// What IS reachable, and what this fixture models, is the frame changing
/// under the descriptor after the shim wrote the metadata — NIC DMA into a
/// recycled UMEM frame. That hazard is exactly why `expected_ports` exists as
/// a "DMA race guard" and why #5466/#4965 made both rewriters run every bail
/// gate against the PRISTINE frame before the first UMEM write. Under it the
/// metadata legitimately describes the packet the shim SAW, not the bytes now
/// in the buffer, so `test_meta`'s `l4_offset = 38` is correct provenance
/// rather than an impossible claim. The rollback branch it drives is therefore
/// defense-in-depth, not a hot-path case — which is precisely why nothing else
/// in the suite covered it.
fn dma_raced_short_ihl_frame() -> Vec<u8> {
    let mut frame = tcp_v4_ack_frame();
    // version 4, IHL 15 (= 60 bytes) over the 40-byte L3 payload actually
    // present. Only the version/IHL byte is disturbed: the ports at [38..42]
    // still match the flow tuple, so the descriptor path's DMA-race port gate
    // is NOT what declines here — the header-length gate is.
    frame[18] = 0x4f;
    frame
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
        // Derived from the frame the way `parse_ipv4` derives them — L4 starts
        // after the IHL the header declares, and the payload after the TCP data
        // offset. Hardcoding 38/58 silently detached the metadata from any
        // fixture carrying IPv4 options.
        l4_offset: 18 + ((frame[18] & 0x0f) as u16) * 4,
        payload_offset: frame.len() as u16,
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

/// `cached_entry` with an UNTAGGED egress: same VLAN-80-tagged ingress frame,
/// but the cached descriptor asks for no tag on the way out.
///
/// This is the only lever in this module that changes which `InPlaceL2Rewrite`
/// variant the rewrite reports. With `tx_vlan_id == INGRESS_VLAN_ID` the
/// target Ethernet length equals the ingress `l3_offset` (18 == 18) and
/// `classify_in_place_l2_rewrite` returns `SameLength`, whose arm in
/// `WorkerTxCounters::record_in_place_l2_rewrite` is empty — so every other
/// fixture here accounts NOTHING through that call and cannot tell whether it
/// runs. With `tx_vlan_id == 0` the target is 14, the 802.1Q tag is dropped by
/// sliding the descriptor 4 bytes forward inside the same UMEM frame, and the
/// call is `VlanPopDescriptor`.
///
/// `decision.resolution.tx_vlan_id` moves with it: the generic rewriter reads
/// the resolution where the descriptor path reads the descriptor, and this
/// module has already been bitten once by a fixture whose two halves
/// disagreed.
fn untagged_egress_entry() -> FlowCacheEntry {
    let mut entry = cached_entry();
    entry.descriptor.tx_vlan_id = 0;
    entry.decision.resolution.tx_vlan_id = 0;
    entry
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
    /// EMPTY, but with a soft cap of exactly one slot — so the target's
    /// `pending_tx_admitted` accounting becomes externally observable: any
    /// admission this call site holds or strands excludes an interleaving
    /// producer's `try_enqueue_tx_owned`, exactly as
    /// `mirror/mod_tests.rs::live_mirror_admission_reserves_slot_against_interleaving_producer`
    /// demonstrates.
    CapOneEmpty,
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
        if queue == MirrorTargetQueue::CapOneEmpty {
            target_live.set_max_pending_tx(1);
        }
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
    /// `telemetry.dbg` after the call. `run_stage` used to build this and drop
    /// it unread, which left `telemetry.dbg.forward += 1` / `.tx += 1` on BOTH
    /// staging arms deletable with the whole module green — an undercounted
    /// forward/tx debug counter on every successful in-place cache hit.
    dbg_forward: u64,
    dbg_tx: u64,
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
    let meta = test_meta(frame);
    run_stage_with_meta(fixture, frame, meta, initial_sample_counter)
}

/// `run_stage` with the shim metadata supplied explicitly, for the rollback
/// fixture — whose UMEM bytes changed AFTER the shim described them, so the
/// metadata must be the one derived from the PRISTINE frame.
fn run_stage_with_meta(
    fixture: &LiveCallSiteFixture,
    frame: &[u8],
    meta: UserspaceDpMeta,
    initial_sample_counter: u64,
) -> StageRun {
    run_stage_with_entry(fixture, frame, meta, cached_entry(), initial_sample_counter)
}

/// `run_stage_with_meta` with the cached flow-cache entry supplied explicitly,
/// so a test can vary the CACHED REWRITE DESCRIPTOR rather than the packet.
/// `live_flow_cache_callsite_accounts_vlan_pop_l2_rewrite_6304` uses it to
/// hand the same VLAN-tagged frame an UNTAGGED egress, which is the only way
/// to reach an `InPlaceL2Rewrite` variant other than `SameLength` from here.
fn run_stage_with_entry(
    fixture: &LiveCallSiteFixture,
    frame: &[u8],
    meta: UserspaceDpMeta,
    entry: FlowCacheEntry,
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
    flow_state.flow_cache.insert(entry);

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
        dbg_forward: dbg.forward,
        dbg_tx: dbg.tx,
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
/// DROPS the sampler and clones unconditionally lands a real frame on the
/// target and the queue assertion below fails.
///
/// Scope, precisely: that is the mutation this cell distinguishes. A call site
/// that still consults the sampler but consults it AFTER reserving — taking an
/// admission and handing it back on `NotSampled` — enqueues nothing and passes
/// every assertion here. See
/// `live_flow_cache_callsite_delegates_to_the_shared_sampler_6304` for what
/// covers that mutation and what it does not.
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
///
/// That decline is reachable ONLY for a frame whose bytes changed after the
/// shim described them, which is what `dma_raced_short_ihl_frame` builds and
/// documents — the metadata passed here is therefore the PRISTINE frame's, the
/// one the shim actually emitted.
#[test]
fn live_flow_cache_callsite_rewrite_failure_rolls_back_sampler_6304() {
    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    let pristine = tcp_v4_ack_frame();
    let frame = dma_raced_short_ihl_frame();
    // rate = 2 with counter = 0 -> SELECTED, so the sampler has something to
    // roll back and admission is genuinely taken and released.
    let run = run_stage_with_meta(&fixture, &frame, test_meta(&pristine), 0);

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

/// #6304 (call-site delegation canary). Inlining `admit_mirror_clone_to_live`
/// above the sampler at this call site and discarding the reservation when the
/// sampler declines is INDISTINGUISHABLE to a single-threaded observer of one
/// completed invocation: the reservation is taken with an AcqRel CAS and given
/// straight back by `PendingTxAdmission::drop` before the call returns, so
/// every counter, queue and frame this module can read afterwards is
/// unchanged. Verified firsthand — the mutation compiles and every behavioural
/// test in this module stays green.
///
/// That is a statement about what a COMPLETED call leaves behind, and nothing
/// more. The ordering is genuinely observable to a CONCURRENT producer: while
/// the transient reservation is held, the target's `pending_tx_admitted` is one
/// higher, so another worker pushing to the same mirror target sees the queue
/// full and its request is dropped —
/// `mirror/mod_tests.rs::live_mirror_admission_reserves_slot_against_interleaving_producer`
/// demonstrates exactly that exclusion. Reserve-first can therefore lose a
/// second producer's clone that sample-first would have admitted. The earlier
/// claim that no behavioural test COULD catch this mutation was a scope error:
/// state created and destroyed inside one call is invisible to that call by
/// construction, and visible to anyone racing it.
///
/// COVERAGE GAP, stated plainly rather than papered over. No test in this
/// module observes that transient window, and none here can observe THE WINDOW
/// deterministically: the window is a pair of atomic RMWs entirely inside
/// `stage_flow_cache_hit`, with no production hook a test could synchronise
/// against, so a racing-producer test would have to catch it open and would
/// fail only probabilistically — a flake, not a binding.
///
/// DETECTING THE MUTATION is strictly weaker than observing the window, and
/// that IS deterministically available: a `#[cfg(test)]`-gated cumulative
/// acquisition counter on `BindingLiveState`, bumped at the top of
/// `try_acquire_pending_tx_admission` (`afxdp/binding_state/tx_inbox.rs`),
/// reads ONE attempt under reserve-first and ZERO under sample-first for a
/// non-sampled packet — single-threaded, no race, because it counts the
/// ATTEMPT rather than catching the window open. Not taken here as a cost
/// judgement, not an impossibility: `BindingLiveState` is the struct whose
/// cross-core cacheline behaviour #6114 exists to fix, so a `#[cfg(test)]`
/// field means the layout under test is not the layout that ships. Recorded in
/// `docs/userspace-dataplane-gaps.md` so a later round can take it.
///
/// What IS bound deterministically is the pair of properties either side of
/// that window:
///   - the reservation the call site takes is externally visible and must be
///     handed back, not stranded —
///     `live_flow_cache_callsite_leaves_no_admission_stranded_on_target_6304`;
///   - the call site does not open-code the reservation at all, which is what
///     this canary pins. `sample_then_admit_mirror_clone` is the single home
///     for the #6114 ordering invariant, so going through it inherits the
///     ordering rather than restating it.
///
/// Limits of the canary itself, enumerated so the list is not mistaken for
/// completeness it does not have. It is source text, not a runtime
/// observation, and it would need updating if the helper is legitimately
/// renamed. It does NOT catch every reserve-before-sample defect inside the
/// shared helper — the #6114 tests catch the historical form, where the helper
/// returned early with the reservation already taken; a rewrite of the helper
/// that reserved first and then suppressed on a sampler decline would be
/// caught by neither. And the negative substring check is defeated by
/// RENAMING at the import — `use ...::admit_mirror_clone_to_live as admit;`
/// then `admit(...)` calls the reservation directly while the forbidden
/// spelling never appears in this file. That escape needs a deliberate alias,
/// not an accidental edit, so it is a bound on what this canary proves rather
/// than a regression it is expected to catch; a substring canary cannot close
/// it, only the runtime instrumentation described above can.
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
         the O(PPS) cross-core true-sharing #6114 removed, and — for a single \
         completed invocation — without changing any observable counter"
    );
}

/// #6304 (shared-capacity accounting). The mirror target's
/// `pending_tx_admitted` is not private bookkeeping: every OTHER producer of
/// that binding is gated on it, so an admission this call site holds is an
/// admission nobody else can use. `mirror/mod_tests.rs::
/// live_mirror_admission_reserves_slot_against_interleaving_producer` pins the
/// mechanism; this pins the consequence at the LIVE call site — after
/// `stage_flow_cache_hit` returns, the only capacity still consumed is
/// capacity a real clone occupies.
///
/// Driven at a soft cap of exactly ONE slot, so a single stranded admission is
/// the difference between an interleaving producer being served and being
/// dropped. The `admitted` cell is the positive control: it proves the cap is
/// genuinely binding, so the two `is_ok()` cells below are informative rather
/// than vacuously true of an unbounded queue.
///
/// This does NOT cover the transient reserve-then-release window (see
/// `live_flow_cache_callsite_delegates_to_the_shared_sampler_6304`); a call
/// site that reserved before sampling and correctly dropped the reservation
/// passes every cell here. What it does cover is the whole class where the
/// reservation is taken and never handed back — the sampler declines but the
/// admission outlives the call, the rewrite declines but the rollback leaks it,
/// or an `Err` admission is dropped without release — each of which silently
/// shrinks the mirror target's usable clone queue for every worker feeding it.
#[test]
fn live_flow_cache_callsite_leaves_no_admission_stranded_on_target_6304() {
    // --- NON-SAMPLED: rate = 2, counter = 1 -> declined by the sampler.
    let declined = LiveCallSiteFixture::new(MirrorTargetQueue::CapOneEmpty);
    let run = run_stage(&declined, &tcp_v4_ack_frame(), 1);
    assert_eq!(
        run.tx_counters.pending_in_place_tx_packets, 1,
        "control: the in-place hairpin rewrite must have SUCCEEDED"
    );
    assert!(
        declined
            .target_live
            .try_enqueue_tx_owned(probe_tx_request())
            .is_ok(),
        "#6304: a non-sampled packet must leave the mirror target's single \
         admission slot free for another producer"
    );

    // --- SELECTED but the rewrite declines: the admission is taken for real
    // and must be released on the rollback path.
    let rolled_back = LiveCallSiteFixture::new(MirrorTargetQueue::CapOneEmpty);
    let pristine = tcp_v4_ack_frame();
    let run = run_stage_with_meta(
        &rolled_back,
        &dma_raced_short_ihl_frame(),
        test_meta(&pristine),
        0,
    );
    assert_eq!(
        run.tx_counters.pending_in_place_tx_packets, 0,
        "control: both in-place rewriters must have declined"
    );
    assert!(
        rolled_back
            .target_live
            .try_enqueue_tx_owned(probe_tx_request())
            .is_ok(),
        "#6304: the admission reserved before a rewrite that then declined must \
         be RELEASED — stranding it permanently shrinks the mirror target's \
         clone queue by one slot per declined packet"
    );

    // --- POSITIVE CONTROL: the cap really is one slot. A SELECTED packet whose
    // clone IS admitted occupies it, and the same probe now fails; draining the
    // owner side gives the slot back.
    let admitted = LiveCallSiteFixture::new(MirrorTargetQueue::CapOneEmpty);
    let run = run_stage(&admitted, &tcp_v4_ack_frame(), 0);
    assert_eq!(
        run.tx_counters.pending_in_place_tx_packets, 1,
        "control: the in-place hairpin rewrite must have SUCCEEDED"
    );
    assert_eq!(
        admitted.ingress_live.mirrored_packets.load(Ordering::Relaxed),
        1,
        "control: the clone must have been admitted and enqueued"
    );
    assert!(
        admitted
            .target_live
            .try_enqueue_tx_owned(probe_tx_request())
            .is_err(),
        "control: a soft cap of one slot is genuinely binding — an ADMITTED \
         clone excludes the interleaving producer, which is what makes the two \
         `is_ok()` assertions above meaningful"
    );
    let mut queued = VecDeque::new();
    admitted.target_live.take_pending_tx_into(&mut queued);
    assert_eq!(queued.len(), 1, "control: the drained request is the clone");
    assert!(
        admitted
            .target_live
            .try_enqueue_tx_owned(probe_tx_request())
            .is_ok(),
        "control: draining the owner side releases the admission again"
    );
}

/// A stand-in for another worker pushing to the same mirror target.
fn probe_tx_request() -> TxRequest {
    TxRequest {
        bytes: vec![0x5a; 64],
        expected_ports: None,
        expected_addr_family: 0,
        expected_protocol: 0,
        flow_key: None,
        egress_ifindex: MIRROR_OUT_BIND_IFINDEX,
        cos_queue_id: None,
        dscp_rewrite: None,
        mirror_clone: false,
        enqueue_ns: 0,
    }
}

/// #6304 (over-reach guard / domain parity). The SELF-CONSISTENT counterpart of
/// the rollback fixture: an IPv4 header that honestly declares IHL 15, carries
/// 40 bytes of NOP options, and whose `total_len`, frame length and metadata
/// offsets all agree — i.e. exactly what `parse_ipv4` in the shim would deliver.
///
/// It must take the in-place path and COMMIT the sampler. That is the load
/// bearing half: it proves the rollback fixture's decline comes from the frame
/// having CHANGED after parse, not from "IHL 15" being intrinsically
/// unrewritable, and so proves the claim
/// `dma_raced_short_ihl_frame` makes about reachability rather than asserting
/// it. It also guards the option-carrying geometry itself — a rewrite that
/// assumed a fixed 20-byte IPv4 header would read the L4 ports out of the
/// option block and bail the DMA-race gate here.
///
/// Stays GREEN under every #6304 sampler revert — reserve-before-sample,
/// deferring the commit on `Sampled(Err)`, dropping the `Sampled(Ok)` arm,
/// hoisting the commit above the rewrite check, and leaking the reservation —
/// measured, not assumed. It is not inert, though: the sampler-commit
/// assertion below needs the mirror config to resolve, so it joins the
/// ingress-VLAN wiring binding and reds if that resolution is dropped.
#[test]
fn live_flow_cache_callsite_ip_options_frame_takes_the_in_place_path_6304() {
    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    // IHL 15: 10 option words on top of the 20-byte base header.
    let frame = vlan_tagged_tcp_v4_frame(10);
    assert_eq!(frame.len(), 98, "18 L2 + 60 IPv4 (options) + 20 TCP");
    assert_eq!(frame[18] & 0x0f, 15, "the IHL nibble the rollback frame fakes");
    let run = run_stage(&fixture, &frame, 0);

    assert!(
        matches!(run.outcome, FlowCacheOutcome::Consumed),
        "the cached flow must be consumed by the fast path"
    );
    assert_eq!(
        run.tx_counters.pending_in_place_tx_packets, 1,
        "#6304 domain parity: a SELF-CONSISTENT IHL-15 frame rewrites in place. \
         The rollback fixture declines because its bytes changed after the shim \
         described them — not because a long IPv4 header cannot be rewritten"
    );
    assert!(
        run.scratch.scratch_forwards.is_empty(),
        "and it does not take the PendingForwardRequest fallback"
    );
    assert_eq!(
        run.mirror_sample_counter, 1,
        "the sampler commits on the successful-rewrite path"
    );
}

/// #6304 (staging telemetry). Both staging arms bump the debug forward/tx
/// counters — the in-place arm at the end of the successful-rewrite branch, the
/// fallback arm after `build_live_forward_request_from_frame` succeeds. Neither
/// was read by any test, so both increments were deletable with the module
/// green: an undercounted forward-debug metric on every established-flow cache
/// hit, on whichever arm was cut.
#[test]
fn live_flow_cache_callsite_accounts_debug_forward_and_tx_6304() {
    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    let in_place = run_stage(&fixture, &tcp_v4_ack_frame(), 0);
    assert_eq!(
        in_place.tx_counters.pending_in_place_tx_packets, 1,
        "control: this is the in-place arm"
    );
    assert_eq!(
        in_place.dbg_forward, 1,
        "#6304: the in-place staging arm accounts one forwarded packet"
    );
    assert_eq!(
        in_place.dbg_tx, 1,
        "#6304: ...and one TX, on the same arm"
    );

    let fallback = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    let pristine = tcp_v4_ack_frame();
    let run = run_stage_with_meta(
        &fallback,
        &dma_raced_short_ihl_frame(),
        test_meta(&pristine),
        0,
    );
    assert_eq!(
        run.scratch.scratch_forwards.len(),
        1,
        "control: this is the PendingForwardRequest fallback arm"
    );
    assert_eq!(
        run.dbg_forward, 1,
        "#6304: the fallback staging arm accounts one forwarded packet too"
    );
    assert_eq!(run.dbg_tx, 1, "#6304: ...and one TX");
}

/// #6304 (staging telemetry, second line). The
/// `record_in_place_l2_rewrite(rewrite_result.l2_rewrite)` call sits two lines
/// above the debug counters bound just above, on a rationale that applies to
/// it verbatim — and it was deletable with the WHOLE CRATE green (4283 passed
/// / 0 failed / 2 ignored plus every integration target, measured), not merely
/// with the #6304 guards green.
///
/// The reason is a fixture property rather than an oversight in the assertions:
/// every other frame here egresses on the same VLAN it arrived on, so
/// `eth_len == current_l3 == 18`, the classification is
/// `InPlaceL2Rewrite::SameLength`, and THAT arm of
/// `record_in_place_l2_rewrite` is an empty block. The call ran on every
/// fixture and could not be observed by any of them. Nothing else in the tree
/// asserted `pending_in_place_vlan_push_desc_packets` or
/// `_pop_desc_packets` either, so deleting the call cost nothing anywhere.
///
/// Handing the same tagged frame an UNTAGGED egress makes the call
/// load-bearing: the tag is popped by sliding the TX descriptor 4 bytes forward
/// inside the same UMEM frame, `classify_in_place_l2_rewrite` returns
/// `VlanPopDescriptor`, and the operator-visible
/// `pending_in_place_vlan_pop_desc_packets` — drained to `BindingLiveState` on
/// the per-second debug tick — must move.
///
/// The three sibling counters are asserted ZERO as well, so the cell binds the
/// CLASSIFICATION and not merely "some counter advanced". Measured: rewiring
/// the `VlanPopDescriptor` arm of `record_in_place_l2_rewrite` to bump the PUSH
/// counter instead reds this test alone, with the other nine #6304 guards
/// green. Hardcoding the ARGUMENT to `SameLength` at the call site collapses
/// onto the deletion mutation — that arm is an empty block, so the pop counter
/// stays at 0 either way.
#[test]
fn live_flow_cache_callsite_accounts_vlan_pop_l2_rewrite_6304() {
    let fixture = LiveCallSiteFixture::new(MirrorTargetQueue::WithRoom);
    let frame = tcp_v4_ack_frame();
    // rate = 2 with counter = 1 -> NOT sampled: this cell is about the L2
    // rewrite accounting, so the mirror block stays out of the way.
    let run = run_stage_with_entry(
        &fixture,
        &frame,
        test_meta(&frame),
        untagged_egress_entry(),
        1,
    );

    // --- POSITIVE CONTROLS: the in-place arm ran, and it genuinely popped the
    // tag rather than taking the same-length path with a different label.
    assert!(
        matches!(run.outcome, FlowCacheOutcome::Consumed),
        "control: the cached flow must be consumed by the fast path"
    );
    assert_eq!(
        run.tx_counters.pending_in_place_tx_packets, 1,
        "control: the in-place hairpin rewrite must have SUCCEEDED — this is \
         the branch that records the L2 rewrite classification"
    );
    let prepared = run
        .tx_pipeline
        .pending_tx_prepared
        .front()
        .expect("control: the rewritten frame must be queued for TX");
    assert_eq!(
        prepared.len as usize,
        frame.len() - 4,
        "control: the TRANSMITTED extent is 4 bytes shorter than the ingress \
         frame — the 802.1Q tag really was popped, so `VlanPopDescriptor` is \
         the honest classification rather than a relabelled no-op"
    );

    // --- THE DISCRIMINATOR: the classification reaches the counters.
    let tx = &run.tx_counters;
    assert_eq!(
        tx.pending_in_place_vlan_pop_desc_packets, 1,
        "#6304: the in-place staging arm must account the descriptor VLAN pop \
         — this counter is the operator's only view of how the fast path is \
         rewriting L2, and without this cell the whole \
         `record_in_place_l2_rewrite` call deletes with the crate green"
    );
    assert_eq!(
        tx.pending_in_place_vlan_push_desc_packets, 0,
        "#6304: ...as a POP, not a push"
    );
    assert_eq!(
        tx.pending_in_place_vlan_push_no_headroom_packets, 0,
        "#6304: ...and not the no-headroom memmove variant"
    );
    assert_eq!(
        tx.pending_in_place_l2_memmove_fallback_packets, 0,
        "#6304: ...and not the unsupported-memmove fallback"
    );
}
