// Slow-path / exception / build-failure routing for the dispatch
// loop (#1443).
//
// Pure code motion from `dispatch/mod.rs`. Hot-path callers reach
// these helpers only on exception branches (build failure, missing
// egress binding, fabric-redirect fallback), so we tag the
// reinjection family `#[cold] #[inline(never)]` per AGY round-2
// finding D — `#[cold]` alone does not stop LLVM from inlining a
// single-caller helper and bloating the hot i-cache footprint;
// `#[inline(never)]` guarantees the cold body stays out-of-line.
//
// The dispatch `mod.rs` re-exports
// - `handle_forward_build_failure`,
// - `maybe_reinject_slow_path`,
// - `maybe_reinject_slow_path_from_frame`,
// - `extract_l3_packet_with_nat`
// at `pub(in crate::afxdp)`; `extract_l3_packet` and
// `extract_l3_packet_from_frame` keep their pre-split `pub(super)`
// (visible to all of `tx/`) via `pub(in crate::afxdp::tx)`.

use super::*;

#[cold]
#[inline(never)]
pub(in crate::afxdp) fn handle_forward_build_failure(
    binding: &BindingIdentity,
    live: &BindingLiveState,
    slow_path: Option<&Arc<SlowPathReinjector>>,
    local_tunnel_deliveries: &Arc<ArcSwap<BTreeMap<i32, SyncSender<Vec<u8>>>>>,
    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
    dbg: &mut DebugPollCounters,
    _target_ifindex: i32,
    packet_length: u32,
    frame: &[u8],
    meta: impl Into<UserspaceDpMeta>,
    decision: SessionDecision,
    fallback_to_slow_path: bool,
    forwarding: &ForwardingState,
) {
    let meta = meta.into();
    dbg.build_fail += 1;
    #[cfg(feature = "debug-log")]
    if dbg.build_fail <= 3 {
        debug_log!(
            "DBG BUILD_FAIL: target_ifindex={} len={} fallback_slow={}",
            _target_ifindex,
            packet_length,
            fallback_to_slow_path,
        );
    }
    record_exception(
        recent_exceptions,
        binding,
        "forward_build_failed",
        packet_length,
        Some(meta),
        None,
        forwarding,
    );
    if fallback_to_slow_path {
        maybe_reinject_slow_path_from_frame(
            binding,
            live,
            slow_path,
            local_tunnel_deliveries,
            frame,
            meta,
            decision,
            recent_exceptions,
            "forward_build_slow_path",
            forwarding,
        );
    }
}

#[cold]
#[inline(never)]
pub(in crate::afxdp) fn maybe_reinject_slow_path(
    binding: &BindingIdentity,
    live: &BindingLiveState,
    slow_path: Option<&Arc<SlowPathReinjector>>,
    local_tunnel_deliveries: &Arc<ArcSwap<BTreeMap<i32, SyncSender<Vec<u8>>>>>,
    area: &MmapArea,
    desc: XdpDesc,
    meta: impl Into<UserspaceDpMeta>,
    decision: SessionDecision,
    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
    forwarding: &ForwardingState,
) {
    let meta = meta.into();
    if !matches!(
        decision.resolution.disposition,
        ForwardingDisposition::LocalDelivery
            | ForwardingDisposition::NoRoute
            | ForwardingDisposition::MissingNeighbor
            | ForwardingDisposition::NextTableUnsupported
    ) {
        return;
    }
    let Some(frame) = area.slice(desc.addr as usize, desc.len as usize) else {
        live.slow_path_drops.fetch_add(1, Ordering::Relaxed);
        record_exception(
            recent_exceptions,
            binding,
            "slow_path_extract_failed",
            desc.len as u32,
            Some(meta),
            None,
            forwarding,
        );
        return;
    };
    maybe_reinject_slow_path_from_frame(
        binding,
        live,
        slow_path,
        local_tunnel_deliveries,
        frame,
        meta,
        decision,
        recent_exceptions,
        "slow_path",
        forwarding,
    );
}

#[cold]
#[inline(never)]
pub(in crate::afxdp) fn maybe_reinject_slow_path_from_frame(
    binding: &BindingIdentity,
    live: &BindingLiveState,
    slow_path: Option<&Arc<SlowPathReinjector>>,
    local_tunnel_deliveries: &Arc<ArcSwap<BTreeMap<i32, SyncSender<Vec<u8>>>>>,
    frame: &[u8],
    meta: impl Into<UserspaceDpMeta>,
    decision: SessionDecision,
    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
    reason: &str,
    forwarding: &ForwardingState,
) {
    let meta = meta.into();
    let Some(packet) = extract_l3_packet_with_nat(frame, meta, decision.nat) else {
        live.slow_path_drops.fetch_add(1, Ordering::Relaxed);
        record_exception(
            recent_exceptions,
            binding,
            "slow_path_prepare_failed",
            frame.len() as u32,
            Some(meta),
            None,
            forwarding,
        );
        return;
    };
    let packet_len = packet.len() as u64;
    let tunnel_delivery = if decision.resolution.disposition == ForwardingDisposition::LocalDelivery
        && decision.resolution.local_ifindex > 0
    {
        local_tunnel_deliveries
            .load()
            .get(&decision.resolution.local_ifindex)
            .cloned()
    } else {
        None
    };
    if let Some(delivery) = tunnel_delivery {
        match delivery.try_send(packet) {
            Ok(()) => {
                live.record_slow_path_accept(decision.resolution.disposition, reason, packet_len);
            }
            Err(std::sync::mpsc::TrySendError::Full(_)) => {
                live.slow_path_drops.fetch_add(1, Ordering::Relaxed);
                record_exception(
                    recent_exceptions,
                    binding,
                    "local_tunnel_delivery_queue_full",
                    frame.len() as u32,
                    Some(meta),
                    None,
                    forwarding,
                );
            }
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                live.slow_path_drops.fetch_add(1, Ordering::Relaxed);
                record_exception(
                    recent_exceptions,
                    binding,
                    "local_tunnel_delivery_unavailable",
                    frame.len() as u32,
                    Some(meta),
                    None,
                    forwarding,
                );
            }
        }
        return;
    }
    let selected_path = slow_path.cloned();
    let Some(slow_path) = selected_path else {
        live.slow_path_drops.fetch_add(1, Ordering::Relaxed);
        record_exception(
            recent_exceptions,
            binding,
            "slow_path_unavailable",
            frame.len() as u32,
            Some(meta),
            None,
            forwarding,
        );
        return;
    };
    match slow_path.enqueue(packet) {
        Ok(EnqueueOutcome::Accepted) => {
            live.record_slow_path_accept(decision.resolution.disposition, reason, packet_len);
        }
        Ok(EnqueueOutcome::RateLimited) => {
            live.slow_path_drops.fetch_add(1, Ordering::Relaxed);
            live.slow_path_rate_limited.fetch_add(1, Ordering::Relaxed);
            record_exception(
                recent_exceptions,
                binding,
                &format!("{reason}_rate_limited"),
                frame.len() as u32,
                Some(meta),
                None,
                forwarding,
            );
        }
        Ok(EnqueueOutcome::QueueFull) => {
            live.slow_path_drops.fetch_add(1, Ordering::Relaxed);
            record_exception(
                recent_exceptions,
                binding,
                &format!("{reason}_queue_full"),
                frame.len() as u32,
                Some(meta),
                None,
                forwarding,
            );
        }
        Err(err) => {
            live.slow_path_drops.fetch_add(1, Ordering::Relaxed);
            live.set_error(err);
            record_exception(
                recent_exceptions,
                binding,
                &format!("{reason}_enqueue_failed"),
                frame.len() as u32,
                Some(meta),
                None,
                forwarding,
            );
        }
    }
}

#[allow(dead_code)]
pub(in crate::afxdp::tx) fn extract_l3_packet(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
) -> Option<Vec<u8>> {
    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
    extract_l3_packet_from_frame(frame, meta)
}

pub(in crate::afxdp::tx) fn extract_l3_packet_from_frame(
    frame: &[u8],
    meta: impl Into<ForwardPacketMeta>,
) -> Option<Vec<u8>> {
    let meta = meta.into();
    let l3 = meta.l3_offset as usize;
    if l3 >= frame.len() {
        return None;
    }
    Some(frame[l3..].to_vec())
}

pub(in crate::afxdp) fn extract_l3_packet_with_nat(
    frame: &[u8],
    meta: impl Into<ForwardPacketMeta>,
    nat: NatDecision,
) -> Option<Vec<u8>> {
    let meta = meta.into();
    let mut packet = extract_l3_packet_from_frame(frame, meta)?;
    match meta.addr_family as i32 {
        libc::AF_INET => apply_nat_ipv4(&mut packet, meta.protocol, nat)?,
        libc::AF_INET6 => apply_nat_ipv6(&mut packet, meta.protocol, nat)?,
        _ => return None,
    }
    Some(packet)
}
