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
pub(super) const PROBE_SCHEDULE_NS: &[u64] = &[
    10_000_000,  // first retry at queued + 10 ms
    60_000_000,  // second retry at queued + 60 ms (delta 50 ms)
    260_000_000, // third retry at queued + 260 ms (delta 200 ms)
];

/// Returns true when the next scheduled probe is due. Pure function —
/// no side effects, easy to unit-test the schedule edges.
pub(super) fn probe_due(elapsed_ns: u64, attempts: u8) -> bool {
    PROBE_SCHEDULE_NS
        .get(attempts as usize)
        .is_some_and(|&target| elapsed_ns >= target)
}

pub(super) fn retry_pending_neigh(
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
    // GEMINI-NEXT.md Section 3 cold start: in-place pop_front/push_back
    // rotation. The previous version did `binding.pending_neigh.remove(i)`
    // inside a while-i-loop, which is O(n) per removal — scaled O(n²) in
    // the queue depth. With MAX_PENDING_NEIGH bumped to 4096 (was 64), the
    // quadratic cost becomes a real fairness hazard during connection
    // bursts; even at the 64-cap it was wasteful relative to the cap.
    //
    // We pop exactly the snapshotted-len items off the front and either
    // (a) drop the packet (recycle frame), (b) push it back on the SAME
    // VecDeque (FIFO order preserved for retained items), or (c) dispatch
    // it. Items pushed back go to the tail and are NOT re-visited in this
    // sweep because we iterate exactly `pending_len` times. Reusing the
    // existing backing buffer avoids per-sweep alloc/free churn that the
    // earlier `mem::take` + `reserve` draft would have introduced.
    let pending_len = binding.pending_neigh.len();
    let ingress_slot = binding.slot;
    let ingress_ifindex = binding.ifindex;
    let ingress_queue = binding.queue_id;
    for _ in 0..pending_len {
        let pkt = binding
            .pending_neigh
            .pop_front()
            .expect("pending_neigh shrank during retry sweep");
        // Timeout: recycle frame and drop.
        if now_ns.saturating_sub(pkt.queued_ns) > PENDING_NEIGH_TIMEOUT_NS {
            binding.pending_fill_frames.push_back(pkt.addr);
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
        let Some(neighbor_mac) = mac else {
            // Still pending — re-fire ARP/NDP probe if the next slot
            // in the exponential schedule is due (GEMINI-NEXT.md
            // Section 3 cold-start). Each retry advances
            // probe_attempts so each schedule entry fires at most
            // once. Iface-name lookup mirrors the initial probe site
            // in poll_descriptor.rs.
            let mut pkt = pkt;
            if probe_due(
                now_ns.saturating_sub(pkt.queued_ns),
                pkt.probe_attempts,
            ) {
                if let Some(hop) = pkt.decision.resolution.next_hop {
                    if let Some(name) = forwarding
                        .ifindex_to_name
                        .get(&pkt.decision.resolution.egress_ifindex)
                    {
                        trigger_kernel_arp_probe(name, hop);
                    }
                }
                pkt.probe_attempts = pkt.probe_attempts.saturating_add(1);
            }
            binding.pending_neigh.push_back(pkt);
            continue;
        };
        let mut decision = pkt.decision;
        decision.resolution.neighbor_mac = Some(neighbor_mac);
        decision.resolution.disposition = ForwardingDisposition::ForwardCandidate;
        let expected_ports = None;
        let Some(frame_len) = rewrite_forwarded_frame_in_place(
            &*area,
            pkt.desc,
            pkt.meta,
            &decision,
            false,
            expected_ports,
        ) else {
            binding.pending_fill_frames.push_back(pkt.addr);
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
            binding.pending_fill_frames.push_back(pkt.addr);
            continue;
        };
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
    }
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

pub(super) fn learn_dynamic_neighbor(
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
mod cold_start_probe_schedule_tests {
    use super::{PROBE_SCHEDULE_NS, probe_due};

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
        // The schedule must finish before PENDING_NEIGH_TIMEOUT_NS
        // (2 s, see types/mod.rs) so all 3 retries fire while the
        // packet is still queued. Otherwise the last retry is dead
        // code: the packet will already be expired by then.
        let last = *PROBE_SCHEDULE_NS.last().expect("schedule non-empty");
        assert!(
            last < super::PENDING_NEIGH_TIMEOUT_NS,
            "last probe slot {last}ns must be < PENDING_NEIGH_TIMEOUT_NS",
        );
    }
}
