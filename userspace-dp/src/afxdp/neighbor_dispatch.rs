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
    // GEMINI-NEXT.md Section 3 cold start: drain-classify-restore pattern.
    // The previous version did `binding.pending_neigh.remove(i)` inside the
    // walk loop, which is O(n) per removal — scaled O(n²) in the queue
    // depth. With MAX_PENDING_NEIGH bumped to 4096 (was 64), the quadratic
    // cost becomes a real fairness hazard during connection bursts; even
    // at the 64-cap it was wasteful relative to the cap.
    //
    // New pattern: take the entire VecDeque out via `mem::take`, walk it
    // once consuming each PendingNeighPacket, classify into one of three
    // outcomes (timeout-drop, neighbor-resolved-process, still-pending),
    // and push the still-pending items back to `binding.pending_neigh`.
    // Each item is touched exactly once → O(n).
    let pending = std::mem::take(&mut binding.pending_neigh);
    binding.pending_neigh.reserve(pending.len());
    let ingress_slot = binding.slot;
    let ingress_ifindex = binding.ifindex;
    let ingress_queue = binding.queue_id;
    for pkt in pending {
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
            // Still pending — keep for the next sweep.
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
