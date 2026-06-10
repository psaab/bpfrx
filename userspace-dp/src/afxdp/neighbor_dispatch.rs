// Neighbor-dispatch helpers extracted from afxdp.rs (Issue 67.2).
//
// `retry_pending_neigh` is the post-poll loop that walks the
// per-binding pending-neighbor queue, re-issues bpf_fib_lookup +
// neighbor lookups, and resumes any flow whose neighbor has now
// resolved (or drops it if the cap is exceeded).
//
// `learn_dynamic_neighbor*` are called from the RX descriptor
// path when an inbound ARP/NDP advert resolves a previously
// missing neighbor — they upsert into the dynamic neighbor map.
// #1787: the upsert is cheap-first — 1-2 single-shard reads elide
// the write entirely when every key already maps to src_mac, so
// the 64-shard bulk lock is only taken for genuine changes.
//
// `build_missing_neighbor_session_metadata` constructs the
// SessionMetadata stub used while the neighbor is unresolved
// so subsequent retries have the full forward context.
//
// Pure relocation. `use super::*;` brings every type, helper,
// and sibling-submodule item from afxdp.rs into scope.

use super::*;

/// GEMINI-NEXT.md Section 3 cold-start: re-fire ARP/NDP solicitation
/// at exponential intervals after the initial probe in
/// `poll_descriptor.rs`. Each entry is the cumulative ns delay from
/// `PendingNeighPacket::queued_ns` at which to issue the next
/// `trigger_kernel_arp_probe()`. After all entries elapse, no further
/// probes — the packet just waits for kernel resolution or the
/// PENDING_NEIGH_TIMEOUT.
///
/// 10/60/260 ms covers a 4-probe schedule (initial + 3 retries) over
/// 260 ms total. The deltas (10, 50, 200 ms) match the cold-start
/// exponential design in GEMINI-NEXT.md and give the kernel three
/// retransmits if the first solicitation is dropped.
const PROBE_SCHEDULE_NS: &[u64] = &[
    10_000_000,  // first retry at queued + 10 ms
    60_000_000,  // second retry at queued + 60 ms (delta 50 ms)
    260_000_000, // third retry at queued + 260 ms (delta 200 ms)
];

/// Returns true when the next scheduled probe is due. Pure function —
/// no side effects, easy to unit-test the schedule edges.
fn probe_due(elapsed_ns: u64, attempts: u8) -> bool {
    PROBE_SCHEDULE_NS
        .get(attempts as usize)
        .is_some_and(|&target| elapsed_ns >= target)
}

/// #1771 §2.2/§2.4: the pure `pending_neigh` buffer-admission decision
/// used at the `MissingNeighbor` handler in `poll_descriptor`. Extracted
/// (behavior-identical) so invariant N1's second half — "`pending_neigh`
/// admits at most ONE packet per `(egress_ifindex, next_hop)`" — is a
/// tested decision rather than an inline branch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PendingNeighAdmission {
    /// Key absent and below cap → buffer this packet (it becomes the
    /// per-key representative driving the probe/dwell clock).
    Buffer,
    /// Key already pending → duplicate sibling: drop + recycle now
    /// (keep-OLDEST; the buffered representative is never replaced, so
    /// each unresolved hop pins at most one UMEM frame).
    DuplicateDrop,
    /// New key but the map is at `MAX_PENDING_NEIGH` distinct hops →
    /// capacity drop (counted nowhere per the #1782 split; the
    /// duplicate counter must not conflate this case).
    CapacityDrop,
}

/// Pure admission decision over the two map facts the caller reads
/// (`contains_key`, `len`). `#[inline]` — compiles to the identical
/// branch pair the inline code had.
#[inline]
pub(super) fn pending_neigh_admission(already_pending: bool, len: usize) -> PendingNeighAdmission {
    if already_pending {
        PendingNeighAdmission::DuplicateDrop
    } else if len < MAX_PENDING_NEIGH {
        PendingNeighAdmission::Buffer
    } else {
        PendingNeighAdmission::CapacityDrop
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn retry_pending_neigh(
    binding: &mut BindingWorker,
    left: &mut [BindingWorker],
    binding_index: usize,
    right: &mut [BindingWorker],
    binding_lookup: &WorkerBindingLookup,
    mirror_targets: &MirrorTargetMap,
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    // #1772: optional latency-telemetry handle. `None` when the resolver
    // thread failed to spawn (telemetry simply not recorded; no
    // forwarding-behavior change). Recording fires only on the rare
    // retry-sweep events (timeout drop, successful resolve dispatch), all
    // off the per-packet forwarded fast path.
    neighbor_resolver: Option<&Arc<NeighborResolver>>,
    now_ns: u64,
    area: &MmapArea,
    shared_recycles: &mut Vec<(u32, u64)>,
) {
    if binding.pending_neigh.is_empty() {
        return;
    }
    // #1772: observe the pending-neigh queue depth at sweep entry for the
    // high-water gauge (after the empty-queue early-out so an idle binding
    // never touches the atomic).
    if let Some(resolver) = neighbor_resolver {
        resolver.observe_pending_depth(binding.pending_neigh.len() as u64);
    }
    let ingress_slot = binding.slot;
    let ingress_ifindex = binding.ifindex;
    let ingress_queue = binding.queue_id;
    // #1636 option D: the drop timeout is computed per snapshot from the
    // kernel retrans_time_ms sysctls (800ms when fast-retrans is
    // confirmed, else 2000ms). `0` means a snapshot that predates the
    // field (e.g. a test-built ForwardingState::default()) — fall back
    // to the compile-time PENDING_NEIGH_TIMEOUT_NS.
    let pending_neigh_timeout_ns = if forwarding.pending_neigh_timeout_ns != 0 {
        forwarding.pending_neigh_timeout_ns
    } else {
        PENDING_NEIGH_TIMEOUT_NS
    };
    // #1771 §2.2: pending_neigh is keyed by (egress_ifindex, next_hop) with
    // ONE representative packet per hop, so the per-sweep probe-dedup
    // BTreeSet is gone (each hop fires at most one probe naturally) and the
    // old O(n²) pop_front/push_back rotation is replaced by a key sweep.
    // Snapshot the keys (Copy; bounded by distinct unresolved next-hops, not
    // packet count — tiny on this cold path) so the map is not borrowed while
    // the resolved-dispatch tail needs `&mut binding`.
    let keys: Vec<(i32, IpAddr)> = binding.pending_neigh.keys().copied().collect();
    for key in keys {
        // Peek queued_ns / probe_attempts without holding a borrow across
        // the dispatch tail.
        let (queued_ns, probe_attempts) = match binding.pending_neigh.get(&key) {
            Some(p) => (p.queued_ns, p.probe_attempts),
            None => continue,
        };
        // Timeout: recycle frame and drop.
        if now_ns.saturating_sub(queued_ns) > pending_neigh_timeout_ns {
            // #1651 B3: this dst timed out after best-effort ARP/NDP probes
            // and never resolved — negatively cache (egress_ifindex,
            // next_hop) so subsequent cold packets fast-fail at the
            // MissingNeighbor buffer site instead of re-buffering for
            // another full PENDING_NEIGH_TIMEOUT. The timeout (not the probe
            // count) is the signal: the dst never landed in the neighbor
            // maps within the window. The map key IS (egress_ifindex,
            // next_hop) — the same lookup key the fast-fail gate uses.
            let pkt = binding
                .pending_neigh
                .remove(&key)
                .expect("key from this map");
            neg_neigh_record(&mut binding.neg_neigh_cache, key, now_ns);
            // #1772: count the never-resolved timeout drop.
            if let Some(resolver) = neighbor_resolver {
                resolver.record_pending_timeout_drop();
            }
            binding.tx_pipeline.pending_fill_frames.push_back(pkt.addr);
            continue;
        }
        // Check if neighbor MAC is now available, mirroring the lookup
        // order from lookup_neighbor_entry(): static/permanent neighbors
        // first, then dynamic_neighbors. The map key IS the neighbor key.
        let mac = forwarding
            .neighbors
            .get(&key)
            .map(|e| e.mac)
            .or_else(|| dynamic_neighbors.get(&key).map(|e| e.mac));
        let Some(neighbor_mac) = mac else {
            // Still pending — re-fire the ARP/NDP probe if the next slot in
            // the exponential schedule is due (GEMINI-NEXT.md Section 3
            // cold-start). One entry per (egress_ifindex, next_hop) means at
            // most one probe per hop per sweep with no extra dedup. Advance
            // probe_attempts in place so each schedule slot fires once.
            if probe_due(now_ns.saturating_sub(queued_ns), probe_attempts) {
                if let Some(name) = forwarding.ifindex_to_name.get(&key.0) {
                    trigger_kernel_arp_probe(name, key.1);
                    if let Some(p) = binding.pending_neigh.get_mut(&key) {
                        p.probe_attempts = p.probe_attempts.saturating_add(1);
                    }
                }
                // else: iface lookup miss → no probe fires, probe_attempts
                // NOT advanced; the key retries this slot next sweep.
            }
            continue;
        };
        // #1772: the neighbor is now usable — record the pending-neigh
        // dwell (`now_ns - queued_ns`). This is THE key metric: how long
        // the buffered packet waited for its neighbor to resolve. Both
        // timestamps come from the same CLOCK_MONOTONIC source so the
        // saturating_sub cannot underflow. Recorded at the resolved point
        // (not after the subsequent rare cos/slice/target early-outs) so
        // it measures resolution latency rather than dispatch success.
        if let Some(resolver) = neighbor_resolver {
            resolver.record_pending_dwell(now_ns.saturating_sub(queued_ns));
        }
        // Own the packet (removes it from the map) so the dispatch tail can
        // borrow `&mut binding` freely.
        let pkt = binding
            .pending_neigh
            .remove(&key)
            .expect("key from this map");
        let mut decision = pkt.decision;
        decision.resolution.neighbor_mac = Some(neighbor_mac);
        decision.resolution.disposition = ForwardingDisposition::ForwardCandidate;
        let expected_ports = None;
        let Some(source_frame) = area.slice(pkt.desc.addr as usize, pkt.desc.len as usize) else {
            binding.tx_pipeline.pending_fill_frames.push_back(pkt.addr);
            continue;
        };
        let cos = resolve_cos_tx_selection_at(
            forwarding,
            decision.resolution.egress_ifindex,
            pkt.meta,
            pkt.flow_key.as_ref(),
            now_ns,
        );
        if cos.drop {
            binding.tx_pipeline.pending_fill_frames.push_back(pkt.addr);
            continue;
        }
        if let Some(result) = enqueue_sampled_mirror_clone(
            left,
            binding_index,
            binding,
            right,
            binding_lookup,
            mirror_targets,
            forwarding,
            pkt.meta.ingress_ifindex as i32,
            pkt.meta.ingress_vlan_id,
            ingress_queue,
            source_frame,
            pkt.meta.into(),
            pkt.flow_key.as_ref(),
        ) {
            record_mirror_clone_result(&binding.live, result, source_frame.len());
        }
        let Some(rewrite_result) = rewrite_forwarded_frame_in_place(
            &*area,
            pkt.desc,
            pkt.meta,
            &decision,
            false,
            expected_ports,
        ) else {
            binding.tx_pipeline.pending_fill_frames.push_back(pkt.addr);
            continue;
        };
        let target_ifindex = if decision.resolution.tx_ifindex > 0 {
            decision.resolution.tx_ifindex
        } else {
            resolve_tx_binding_ifindex(forwarding, decision.resolution.egress_ifindex)
        };
        let Some(target_idx) = binding_lookup.target_index(
            binding_index,
            ingress_ifindex,
            ingress_queue,
            target_ifindex,
        ) else {
            binding.tx_pipeline.pending_fill_frames.push_back(pkt.addr);
            continue;
        };
        let req = PreparedTxRequest {
            offset: rewrite_result.offset,
            len: rewrite_result.len,
            recycle: PreparedTxRecycle::fill_on_slot(
                ingress_slot,
                rewrite_result.offset,
                pkt.desc.addr,
            ),
            expected_ports: None,
            expected_addr_family: pkt.meta.addr_family,
            expected_protocol: pkt.meta.protocol,
            flow_key: pkt.flow_key.clone(),
            egress_ifindex: decision.resolution.egress_ifindex,
            cos_queue_id: cos.queue_id,
            dscp_rewrite: cos.dscp_rewrite,
            mirror_clone: false,
        };
        if target_idx == binding_index {
            binding.tx_pipeline.pending_tx_prepared.push_back(req);
            binding.tx_counters.pending_in_place_tx_packets += 1;
            binding
                .tx_counters
                .record_in_place_l2_rewrite(rewrite_result.l2_rewrite);
        } else if let Some(target) =
            binding_by_index_mut(left, binding_index, binding, right, target_idx)
        {
            target.tx_pipeline.pending_tx_prepared.push_back(req);
            bound_pending_tx_prepared(target, Some(shared_recycles));
            target.tx_counters.pending_in_place_tx_packets += 1;
            target
                .tx_counters
                .record_in_place_l2_rewrite(rewrite_result.l2_rewrite);
        } else {
            binding.tx_pipeline.pending_fill_frames.push_back(pkt.addr);
        }
    }
    apply_shared_recycles(
        left,
        binding_index,
        binding,
        right,
        binding_lookup,
        shared_recycles,
    );
}

pub(super) fn learn_dynamic_neighbor_from_packet(
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

/// #1787: pure decision helper for the cheap-first RX learn pre-check.
/// `current` holds the pre-read MAC (or `None` on miss) for each
/// candidate key; a bulk write is needed iff ANY entry is missing or
/// differs from `src_mac`. Factored out so the elision decision is
/// unit-testable directly — an elided write and an idempotent
/// overwrite leave identical map contents (RX learn bumps no
/// generation), so map-state comparison alone cannot prove elision.
pub(super) fn pair_write_needed(current: &[Option<[u8; 6]>], src_mac: [u8; 6]) -> bool {
    current.iter().any(|mac| *mac != Some(src_mac))
}

pub(super) fn learn_dynamic_neighbor(
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    ingress_ifindex: i32,
    ingress_vlan_id: u16,
    src_ip: IpAddr,
    src_mac: [u8; 6],
) {
    // #1787: stack array, no per-packet heap alloc. At most 2 keys:
    // the physical ingress ifindex plus the resolved logical (VLAN
    // sub-) ifindex when it differs. keys[1] stays an unused
    // placeholder when n == 1.
    let mut keys: [(i32, IpAddr); 2] = [(ingress_ifindex, src_ip), (0, src_ip)];
    let mut n = 1usize;
    if let Some(logical_ifindex) =
        resolve_ingress_logical_ifindex(forwarding, ingress_ifindex, ingress_vlan_id)
    {
        if logical_ifindex > 0 && logical_ifindex != ingress_ifindex {
            keys[1] = (logical_ifindex, src_ip);
            n = 2;
        }
    }
    // #1787 cheap-first pre-check: 1-2 single-shard reads replace the
    // unconditional 64-shard bulk acquisition in the steady state
    // (every key already maps to src_mac → return with no write, no
    // bulk lock, no alloc).
    //
    // Linearization semantics: a no-op learn linearizes at this
    // pre-check read. A concurrent remove (netlink FAILED/delete,
    // resolver authoritative-FAILED revoke, manager replace/bulk
    // remove) that lands AFTER the read wins — the elided write does
    // not re-create the entry — and the next packet from this source
    // that REACHES this function pre-check-misses and re-learns via
    // the bulk path below.
    //
    // Dedup window: the caller sets the per-binding
    // last_learned_neighbor dedup after this returns (including after
    // an elided no-op), so identical follow-up packets may not reach
    // this function until the dedup key changes. That dedup-delayed
    // re-learn is PRE-EXISTING behavior — a write also set the dedup,
    // so a remove landing after the write was equally suppressed.
    // Recovery comes from the same paths as before: a second source
    // key evicting the 1-entry dedup, the ARP/NDP learn stage
    // (poll_stages.rs), and the #1769 resolver probe on forwarding
    // miss.
    let mut current: [Option<[u8; 6]>; 2] = [None, None];
    for (slot, key) in current.iter_mut().zip(keys[..n].iter()) {
        *slot = dynamic_neighbors.get(key).map(|entry| entry.mac);
    }
    if !pair_write_needed(&current[..n], src_mac) {
        return;
    }
    // #949: multi-ifindex insert atomically vs readers — both
    // ingress_ifindex and the resolved logical (VLAN sub-) ifindex
    // get the same MAC under one bulk acquisition so a reader sees
    // either both or neither, never a stale half. Genuine changes
    // (first sighting, MAC flip, removed key) keep this exact path.
    dynamic_neighbors.with_all_shards(|bulk| {
        for key in &keys[..n] {
            bulk.insert(*key, NeighborEntry { mac: src_mac });
        }
    });
}

pub(super) fn build_missing_neighbor_session_metadata(
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

#[cfg(test)]
mod mirror_tests {
    use super::*;
    use crate::afxdp::tx::test_support::{build_ipv4_test_packet, test_session_key};
    use std::sync::atomic::Ordering;

    /// #1771 §2.2: `pending_neigh` is keyed by `(egress_ifindex, next_hop)`.
    /// Test helper that buffers one packet under its derived key, preserving
    /// the old `push_back`-one-packet ergonomics for the retry-sweep tests.
    ///
    /// NOTE: this is single-entry seeding — it `insert`s (last-write-wins),
    /// NOT the production admission keep-oldest+recycle-duplicate semantics
    /// (poll_descriptor). Every test here seeds one packet per distinct key,
    /// so the distinction never bites; do not reuse this to model duplicate
    /// admission.
    fn push_pending(b: &mut BindingWorker, pkt: PendingNeighPacket) {
        let key = (
            pkt.decision.resolution.egress_ifindex,
            pkt.decision
                .resolution
                .next_hop
                .expect("test pending pkt has a next_hop"),
        );
        b.pending_neigh.insert(key, pkt);
    }

    fn resolved_neighbor_decision(next_hop: IpAddr) -> SessionDecision {
        SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::MissingNeighbor,
                local_ifindex: 0,
                egress_ifindex: 80,
                tx_ifindex: 22,
                tunnel_endpoint_id: 0,
                next_hop: Some(next_hop),
                neighbor_mac: None,
                src_mac: Some([0x02, 0xbf, 0x72, 0x16, 0x00, 0x01]),
                tx_vlan_id: 0,
            },
            nat: NatDecision::default(),
        }
    }

    fn pending_neighbor_meta(frame_len: usize) -> UserspaceDpMeta {
        UserspaceDpMeta {
            ingress_ifindex: 11,
            l3_offset: 14,
            l4_offset: 34,
            pkt_len: frame_len as u16,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            ..UserspaceDpMeta::default()
        }
    }

    #[test]
    fn retry_pending_neighbor_mirrors_original_frame_before_rewrite() {
        let mut bindings = vec![
            BindingWorker::new_for_mirror_test(0, 0, 11, 0),
            BindingWorker::new_for_mirror_test(1, 0, 22, 0),
            BindingWorker::new_for_mirror_test(2, 0, 33, 0),
        ];
        let original_frame = build_ipv4_test_packet(0);
        // SAFETY: single-threaded test over a UMEM created just above; no
        // other borrow into [0, len) exists and the mutable slice is
        // consumed by the immediate copy_from_slice before anything else
        // touches the area.
        unsafe {
            bindings[0]
                .umem
                .area()
                .slice_mut_unchecked(0, original_frame.len())
        }
        .expect("ingress frame")
        .copy_from_slice(&original_frame);

        let next_hop = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let meta = pending_neighbor_meta(original_frame.len());
        push_pending(&mut bindings[0], PendingNeighPacket {
            addr: 0,
            desc: XdpDesc {
                addr: 0,
                len: original_frame.len() as u32,
                options: 0,
            },
            meta,
            decision: resolved_neighbor_decision(next_hop),
            flow_key: Some(test_session_key(12345, 443)),
            queued_ns: 0,
            probe_attempts: 0,
        });

        let mut forwarding = ForwardingState::default();
        forwarding.neighbors.insert(
            (80, next_hop),
            NeighborEntry {
                mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            },
        );
        forwarding.mirror_configs.insert(
            11,
            MirrorRuntimeConfig {
                output_ifindex: 33,
                rate: 0,
            },
        );

        let lookup = WorkerBindingLookup::from_bindings(&bindings);
        let mirror_targets = MirrorTargetMap::default();
        let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
        let mut shared_recycles = Vec::new();
        let area = bindings[0].umem.area() as *const MmapArea;
        let (left, rest) = bindings.split_at_mut(0);
        let (binding, right) = rest.split_first_mut().expect("ingress binding");

        retry_pending_neigh(
            binding,
            left,
            0,
            right,
            &lookup,
            &mirror_targets,
            &forwarding,
            &dynamic_neighbors,
            None,
            1,
            // SAFETY: `area` was cast from `&MmapArea` borrowed out of
            // bindings[0].umem just above; the Rc-backed allocation lives
            // past this call, the split_at_mut borrows cover disjoint
            // binding state (not the umem area), and the test is
            // single-threaded.
            unsafe { &*area },
            &mut shared_recycles,
        );

        assert!(bindings[0].pending_neigh.is_empty());
        assert_eq!(bindings[0].live.mirrored_packets.load(Ordering::Relaxed), 1);
        assert_eq!(
            bindings[0].live.mirrored_bytes.load(Ordering::Relaxed),
            original_frame.len() as u64
        );

        let mirror_req = bindings[2]
            .tx_pipeline
            .pending_tx_prepared
            .front()
            .expect("mirror prepared request");
        assert!(mirror_req.mirror_clone);
        assert_eq!(mirror_req.egress_ifindex, 33);
        assert_eq!(mirror_req.len, original_frame.len() as u32);
        assert_eq!(
            bindings[2]
                .umem
                .area()
                .slice(mirror_req.offset as usize, mirror_req.len as usize)
                .expect("mirrored frame"),
            original_frame.as_slice(),
            "deferred neighbor path must mirror pre-rewrite L2 bytes",
        );

        let forwarded_req = bindings[1]
            .tx_pipeline
            .pending_tx_prepared
            .front()
            .expect("forwarded prepared request");
        assert!(
            !forwarded_req.mirror_clone,
            "primary forwarding request must not inherit mirror identity",
        );
    }

    /// #1651 B3: a never-resolving pending packet that crosses the timeout
    /// must (a) be dropped (recycled, removed from the queue) and (b) record
    /// its (egress_ifindex, next_hop) in the binding's negative cache so
    /// subsequent cold packets to the same dead host fast-fail.
    #[test]
    fn timed_out_pending_neighbor_records_negative_cache() {
        let mut bindings = vec![
            BindingWorker::new_for_mirror_test(0, 0, 11, 0),
            BindingWorker::new_for_mirror_test(1, 0, 22, 0),
        ];
        let original_frame = build_ipv4_test_packet(0);
        // SAFETY: single-threaded test over a UMEM created just above; no
        // other borrow into [0, len) exists and the mutable slice is
        // consumed by the immediate copy_from_slice before anything else
        // touches the area.
        unsafe {
            bindings[0]
                .umem
                .area()
                .slice_mut_unchecked(0, original_frame.len())
        }
        .expect("ingress frame")
        .copy_from_slice(&original_frame);

        let next_hop = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 137));
        let meta = pending_neighbor_meta(original_frame.len());
        push_pending(&mut bindings[0], PendingNeighPacket {
            addr: 0,
            desc: XdpDesc {
                addr: 0,
                len: original_frame.len() as u32,
                options: 0,
            },
            meta,
            decision: resolved_neighbor_decision(next_hop),
            flow_key: Some(test_session_key(12345, 443)),
            queued_ns: 0,
            // All probes already fired; the dst never resolved.
            probe_attempts: PROBE_SCHEDULE_NS.len() as u8,
        });

        // No neighbor for `next_hop` anywhere → unresolved. Use the
        // compile-time fallback timeout (default ForwardingState leaves
        // pending_neigh_timeout_ns == 0).
        let forwarding = ForwardingState::default();
        let lookup = WorkerBindingLookup::from_bindings(&bindings);
        let mirror_targets = MirrorTargetMap::default();
        let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
        let mut shared_recycles = Vec::new();
        let area = bindings[0].umem.area() as *const MmapArea;
        let (left, rest) = bindings.split_at_mut(0);
        let (binding, right) = rest.split_first_mut().expect("ingress binding");

        // now_ns just past the 2s fallback timeout.
        let now_ns = PENDING_NEIGH_TIMEOUT_NS + 1;
        retry_pending_neigh(
            binding,
            left,
            0,
            right,
            &lookup,
            &mirror_targets,
            &forwarding,
            &dynamic_neighbors,
            None,
            now_ns,
            // SAFETY: `area` was cast from `&MmapArea` borrowed out of
            // bindings[0].umem just above; the Rc-backed allocation lives
            // past this call, the split_at_mut borrows cover disjoint
            // binding state (not the umem area), and the test is
            // single-threaded.
            unsafe { &*area },
            &mut shared_recycles,
        );

        // The packet was dropped (recycled to fill ring, queue drained).
        assert!(
            bindings[0].pending_neigh.is_empty(),
            "timed-out pending packet must be dropped",
        );
        // The dead-host key was recorded and is active.
        let key = (80i32, next_hop); // egress_ifindex 80 per resolved_neighbor_decision
        assert!(
            crate::afxdp::neg_neigh::neg_neigh_active(
                &mut bindings[0].neg_neigh_cache,
                &key,
                now_ns,
            ),
            "timed-out dst must be negatively cached",
        );
    }

    /// #1772: build a worker-facing `NeighborResolver` handle wired to a
    /// fresh latency-telemetry set, so a test can pass it into
    /// `retry_pending_neigh` and read back the recorded dwell / drop /
    /// depth. The channel `rx` is returned so the producer end is not
    /// dropped (which would mark every enqueue Disconnected).
    fn resolver_with_latency() -> (
        Arc<NeighborResolver>,
        std::sync::mpsc::Receiver<crate::afxdp::neighbor_resolver::ResolveItem>,
        Arc<crate::afxdp::neighbor_latency::NeighborLatencyHist>,
        Arc<AtomicU64>,
        Arc<AtomicU64>,
    ) {
        let (tx, rx) = std::sync::mpsc::sync_channel::<crate::afxdp::neighbor_resolver::ResolveItem>(
            crate::afxdp::neighbor_resolver::RESOLVER_QUEUE_DEPTH,
        );
        let dwell = Arc::new(crate::afxdp::neighbor_latency::NeighborLatencyHist::default());
        let drops = Arc::new(AtomicU64::new(0));
        let depth = Arc::new(AtomicU64::new(0));
        let resolver = Arc::new(NeighborResolver::new(
            tx,
            Arc::new(crate::afxdp::neighbor_resolver::ResolverCounters::default()),
            Arc::new(AtomicU64::new(0)),
            dwell.clone(),
            drops.clone(),
            depth.clone(),
        ));
        (resolver, rx, dwell, drops, depth)
    }

    /// #1772 acceptance: a buffered packet with a known `queued_ns` that
    /// resolves at a later `now_ns` records its dwell into the histogram
    /// (correct bucket + count) AND the max-depth high-water gauge is set.
    #[test]
    fn resolved_pending_neighbor_records_dwell_and_depth() {
        let mut bindings = vec![
            BindingWorker::new_for_mirror_test(0, 0, 11, 0),
            BindingWorker::new_for_mirror_test(1, 0, 22, 0),
        ];
        let original_frame = build_ipv4_test_packet(0);
        // SAFETY: single-threaded test over a UMEM created just above; no
        // other borrow into [0, len) exists and the mutable slice is
        // consumed by the immediate copy_from_slice before anything else
        // touches the area.
        unsafe {
            bindings[0]
                .umem
                .area()
                .slice_mut_unchecked(0, original_frame.len())
        }
        .expect("ingress frame")
        .copy_from_slice(&original_frame);

        let next_hop = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200));
        let meta = pending_neighbor_meta(original_frame.len());
        // Buffered at queued_ns = 1_000_000 ns; resolves at a now_ns that
        // gives a 500 ms dwell — well under the 2 s PENDING_NEIGH_TIMEOUT
        // so the packet DISPATCHES (and records its dwell) rather than
        // timing out. The 3 s → tail-bucket mapping is covered by the
        // neighbor_latency unit tests; here we verify the record fires on
        // the real dispatch path with the correct sum + bucket.
        let queued_ns = 1_000_000u64;
        let dwell_ns = 500_000_000u64; // 500 ms
        push_pending(&mut bindings[0], PendingNeighPacket {
            addr: 0,
            desc: XdpDesc {
                addr: 0,
                len: original_frame.len() as u32,
                options: 0,
            },
            meta,
            decision: resolved_neighbor_decision(next_hop),
            flow_key: Some(test_session_key(12345, 443)),
            queued_ns,
            probe_attempts: 0,
        });

        let mut forwarding = ForwardingState::default();
        // Neighbor IS resolved now → the retry sweep dispatches it and
        // records the dwell.
        forwarding.neighbors.insert(
            (80, next_hop),
            NeighborEntry {
                mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            },
        );

        let lookup = WorkerBindingLookup::from_bindings(&bindings);
        let mirror_targets = MirrorTargetMap::default();
        let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
        let mut shared_recycles = Vec::new();
        let (resolver, _rx, dwell, _drops, depth) = resolver_with_latency();
        let area = bindings[0].umem.area() as *const MmapArea;
        let (left, rest) = bindings.split_at_mut(0);
        let (binding, right) = rest.split_first_mut().expect("ingress binding");

        let now_ns = queued_ns + dwell_ns;
        retry_pending_neigh(
            binding,
            left,
            0,
            right,
            &lookup,
            &mirror_targets,
            &forwarding,
            &dynamic_neighbors,
            Some(&resolver),
            now_ns,
            // SAFETY: `area` was cast from `&MmapArea` borrowed out of
            // bindings[0].umem just above; the Rc-backed allocation lives
            // past this call, the split_at_mut borrows cover disjoint
            // binding state (not the umem area), and the test is
            // single-threaded.
            unsafe { &*area },
            &mut shared_recycles,
        );

        assert!(bindings[0].pending_neigh.is_empty(), "packet must dispatch");
        let snap = dwell.snapshot();
        assert_eq!(snap.count, 1, "exactly one dwell sample recorded");
        assert_eq!(snap.sum_ns, dwell_ns, "sum is the recorded dwell");
        let expect_bucket = crate::afxdp::neighbor_latency::neigh_latency_bucket_index(dwell_ns);
        assert_eq!(
            snap.buckets[expect_bucket], 1,
            "500 ms dwell recorded into its pow2-ns bucket",
        );
        assert_eq!(
            depth.load(Ordering::Relaxed),
            1,
            "max-depth high-water must reflect the 1 queued packet",
        );
    }

    /// #1772: a never-resolving packet that crosses the timeout records a
    /// timeout-drop and records NO dwell sample.
    #[test]
    fn timed_out_pending_neighbor_records_timeout_drop_not_dwell() {
        let mut bindings = vec![
            BindingWorker::new_for_mirror_test(0, 0, 11, 0),
            BindingWorker::new_for_mirror_test(1, 0, 22, 0),
        ];
        let original_frame = build_ipv4_test_packet(0);
        // SAFETY: single-threaded test over a UMEM created just above; no
        // other borrow into [0, len) exists and the mutable slice is
        // consumed by the immediate copy_from_slice before anything else
        // touches the area.
        unsafe {
            bindings[0]
                .umem
                .area()
                .slice_mut_unchecked(0, original_frame.len())
        }
        .expect("ingress frame")
        .copy_from_slice(&original_frame);

        let next_hop = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 138));
        let meta = pending_neighbor_meta(original_frame.len());
        push_pending(&mut bindings[0], PendingNeighPacket {
            addr: 0,
            desc: XdpDesc {
                addr: 0,
                len: original_frame.len() as u32,
                options: 0,
            },
            meta,
            decision: resolved_neighbor_decision(next_hop),
            flow_key: Some(test_session_key(12345, 443)),
            queued_ns: 0,
            probe_attempts: PROBE_SCHEDULE_NS.len() as u8,
        });

        // No neighbor anywhere → never resolves → timeout drop.
        let forwarding = ForwardingState::default();
        let lookup = WorkerBindingLookup::from_bindings(&bindings);
        let mirror_targets = MirrorTargetMap::default();
        let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
        let mut shared_recycles = Vec::new();
        let (resolver, _rx, dwell, drops, _depth) = resolver_with_latency();
        let area = bindings[0].umem.area() as *const MmapArea;
        let (left, rest) = bindings.split_at_mut(0);
        let (binding, right) = rest.split_first_mut().expect("ingress binding");

        let now_ns = PENDING_NEIGH_TIMEOUT_NS + 1;
        retry_pending_neigh(
            binding,
            left,
            0,
            right,
            &lookup,
            &mirror_targets,
            &forwarding,
            &dynamic_neighbors,
            Some(&resolver),
            now_ns,
            // SAFETY: `area` was cast from `&MmapArea` borrowed out of
            // bindings[0].umem just above; the Rc-backed allocation lives
            // past this call, the split_at_mut borrows cover disjoint
            // binding state (not the umem area), and the test is
            // single-threaded.
            unsafe { &*area },
            &mut shared_recycles,
        );

        assert!(
            bindings[0].pending_neigh.is_empty(),
            "timed-out pkt dropped"
        );
        assert_eq!(
            drops.load(Ordering::Relaxed),
            1,
            "one timeout-drop must be counted",
        );
        assert_eq!(
            dwell.snapshot().count,
            0,
            "a timed-out (never-resolved) packet must NOT record a dwell sample",
        );
    }
}

#[cfg(test)]
mod cold_start_probe_schedule_tests {
    use super::{PROBE_SCHEDULE_NS, probe_due};

    #[test]
    fn schedule_values_match_design() {
        // Pin the exact schedule so accidental edits fail the build
        // rather than silently regressing the cold-start design from
        // GEMINI-NEXT.md Section 3.
        assert_eq!(
            PROBE_SCHEDULE_NS,
            &[10_000_000u64, 60_000_000u64, 260_000_000u64],
        );
    }

    #[test]
    fn schedule_is_strictly_monotonic() {
        for window in PROBE_SCHEDULE_NS.windows(2) {
            assert!(
                window[0] < window[1],
                "PROBE_SCHEDULE_NS must be strictly increasing: {:?}",
                PROBE_SCHEDULE_NS
            );
        }
    }

    #[test]
    fn probe_due_fires_only_at_or_after_schedule_boundary() {
        let first = PROBE_SCHEDULE_NS[0];
        assert!(!probe_due(first - 1, 0));
        assert!(probe_due(first, 0));
        assert!(probe_due(first + 1, 0));
    }

    #[test]
    fn probe_due_walks_each_schedule_slot() {
        // After attempts=0 fires, probe_due(elapsed, 1) must wait until
        // PROBE_SCHEDULE_NS[1]; same for each subsequent slot.
        for (idx, &target) in PROBE_SCHEDULE_NS.iter().enumerate() {
            let attempts = idx as u8;
            assert!(
                !probe_due(target.saturating_sub(1), attempts),
                "slot {idx} should not fire one ns before target",
            );
            assert!(
                probe_due(target, attempts),
                "slot {idx} should fire at target",
            );
        }
    }

    #[test]
    fn probe_due_returns_false_after_schedule_exhausted() {
        let exhausted = PROBE_SCHEDULE_NS.len() as u8;
        // Even with elapsed_ns = u64::MAX, no further probes once
        // every slot has fired.
        assert!(!probe_due(u64::MAX, exhausted));
        assert!(!probe_due(u64::MAX, exhausted.saturating_add(1)));
    }

    #[test]
    fn schedule_total_window_under_pending_neigh_timeout() {
        // The schedule must finish before the SMALLEST possible
        // PENDING_NEIGH_TIMEOUT so all 3 retries fire while the packet
        // is still queued, regardless of whether option D's fast 800ms
        // timeout (kernel retrans confirmed <=250ms) or the 2000ms
        // fallback is active (#1636). We gate on the 800ms fast value
        // minus a 100ms margin so the assertion holds under both paths.
        let last = *PROBE_SCHEDULE_NS.last().expect("schedule non-empty");
        let min_timeout = super::super::forwarding_build::PENDING_NEIGH_TIMEOUT_FAST_NS;
        assert!(
            min_timeout < super::PENDING_NEIGH_TIMEOUT_NS,
            "fast timeout must be below the 2s fallback",
        );
        assert!(
            last < min_timeout.saturating_sub(100_000_000),
            "last probe slot {last}ns must be < min PENDING_NEIGH_TIMEOUT ({min_timeout}ns) - 100ms",
        );
    }

    // #1771 §2.2: the former `simulate_sweep_for_neighbor` helper and its
    // `dedup_emits_one_probe_*` / `iface_miss_*` tests modeled the OLD
    // per-sweep BTreeSet probe-dedup over many packets sharing one
    // `(egress_ifindex, next_hop)`. That dedup no longer exists: the keyed
    // `pending_neigh` map holds exactly ONE entry per hop, so "one probe per
    // neighbor per slot" is now a structural invariant rather than a
    // runtime-deduped property. The probe schedule itself stays covered by
    // the `PROBE_SCHEDULE_NS` / `probe_due` bound tests above, and the live
    // sweep (incl. the iface-miss no-advance branch) by the
    // `retry_pending_*` dispatch tests in `mirror_tests`. Removed rather than
    // left asserting impossible multi-packet-same-key state (Codex r2).
}

#[cfg(test)]
mod learn_precheck_tests {
    use super::pair_write_needed;

    const MAC: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    const OTHER: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

    #[test]
    fn single_key_current_needs_no_write() {
        assert!(!pair_write_needed(&[Some(MAC)], MAC));
    }

    #[test]
    fn single_key_miss_needs_write() {
        assert!(pair_write_needed(&[None], MAC));
    }

    #[test]
    fn single_key_stale_needs_write() {
        assert!(pair_write_needed(&[Some(OTHER)], MAC));
    }

    #[test]
    fn pair_matrix_any_miss_or_stale_needs_write() {
        // Full 3x3 matrix over {current, stale, miss} per slot: a
        // write is needed unless BOTH slots already carry src_mac.
        let states: [Option<[u8; 6]>; 3] = [Some(MAC), Some(OTHER), None];
        for a in states {
            for b in states {
                let expected = !(a == Some(MAC) && b == Some(MAC));
                assert_eq!(
                    pair_write_needed(&[a, b], MAC),
                    expected,
                    "slots {a:?}/{b:?}",
                );
            }
        }
    }

    #[test]
    fn empty_slice_needs_no_write() {
        // Degenerate: learn_dynamic_neighbor always passes n >= 1.
        // Pinned so the `any`-over-slice semantics stay explicit.
        assert!(!pair_write_needed(&[], MAC));
    }
}

#[cfg(test)]
mod pending_admission_tests {
    use super::{PendingNeighAdmission, pending_neigh_admission};
    use crate::afxdp::MAX_PENDING_NEIGH;

    /// Invariant N1's buffering half (#1771 §2.4): exactly one buffered
    /// packet per `(egress_ifindex, next_hop)` — the first packet
    /// buffers, every same-key sibling is a DuplicateDrop regardless of
    /// how much room remains.
    #[test]
    fn first_packet_buffers_siblings_duplicate_drop() {
        assert_eq!(pending_neigh_admission(false, 0), PendingNeighAdmission::Buffer);
        assert_eq!(
            pending_neigh_admission(true, 1),
            PendingNeighAdmission::DuplicateDrop
        );
        // Duplicate wins even with plenty of room…
        assert_eq!(
            pending_neigh_admission(true, 10),
            PendingNeighAdmission::DuplicateDrop
        );
        // …and even at the cap (the duplicate counter must not be
        // conflated with the capacity case — #1782 split).
        assert_eq!(
            pending_neigh_admission(true, MAX_PENDING_NEIGH),
            PendingNeighAdmission::DuplicateDrop
        );
    }

    /// The cap applies only to NEW keys: the last slot below the cap
    /// buffers, at the cap a new key is a CapacityDrop.
    #[test]
    fn new_key_capacity_boundary() {
        assert_eq!(
            pending_neigh_admission(false, MAX_PENDING_NEIGH - 1),
            PendingNeighAdmission::Buffer
        );
        assert_eq!(
            pending_neigh_admission(false, MAX_PENDING_NEIGH),
            PendingNeighAdmission::CapacityDrop
        );
    }
}
