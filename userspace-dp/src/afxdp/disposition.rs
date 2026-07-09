// Disposition / telemetry recording extracted from afxdp.rs (Issue 67.3).
//
// `record_exception` (52 LOC) — emits an ExceptionStatus to the
// per-binding live counters when a packet hits an exception path
// (drop, kernel handoff, fabric redirect).
//
// `record_disposition` (68 LOC) — feeds the per-disposition
// PacketDisposition counters used by status queries.
//
// `record_forwarding_disposition` (99 LOC) — overlay used when
// the forwarding outcome itself (ForwardCandidate / FabricRedirect /
// LocalDelivery / etc.) is the dimension being recorded.
//
// `update_last_resolution` (~30 LOC) — caches the most recent
// ForwardingResolution / disposition per session for the inspect
// CLI / gRPC.
//
// Pure relocation. `use super::*;` brings every type and helper
// from afxdp.rs into scope.

use super::*;

/// #4743: classify a NoRoute destination as a MARTIAN address — one that a
/// firewall must never forward and that has no legitimate route. Mirrors the
/// neighbor-warm never-warm predicate (`coordinator::mod`): IPv4
/// unspecified/loopback/multicast/broadcast, IPv6
/// unspecified/loopback/multicast. IPv6 has no broadcast. Used only to
/// sub-classify an already-decided NoRoute drop; it does not itself drop.
pub(in crate::afxdp) fn is_martian_dst(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_unspecified() || v4.is_loopback() || v4.is_multicast() || v4.is_broadcast()
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_unspecified() || v6.is_loopback() || v6.is_multicast()
        }
    }
}

pub(super) fn record_exception(
    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
    binding: &BindingIdentity,
    reason: &str,
    packet_length: u32,
    meta: Option<UserspaceDpMeta>,
    debug: Option<&ResolutionDebug>,
    forwarding: &ForwardingState,
) {
    if let Ok(mut recent) = recent_exceptions.lock() {
        push_recent_exception(
            &mut recent,
            build_exception_status(binding, reason, packet_length, meta, debug, forwarding),
        );
    }
}

pub(super) fn record_source_nat_exception(
    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
    binding: &BindingIdentity,
    packet_length: u32,
    meta: Option<UserspaceDpMeta>,
    debug: Option<&ResolutionDebug>,
    forwarding: &ForwardingState,
    failure: &SourceNatFailure,
) {
    if let Ok(mut recent) = recent_exceptions.lock() {
        let mut exception = build_exception_status(
            binding,
            failure.exception_reason(),
            packet_length,
            meta,
            debug,
            forwarding,
        );
        exception.rule_name = failure.rule_name.clone();
        exception.pool_name = failure.pool_name.clone();
        push_recent_exception(&mut recent, exception);
    }
}

fn build_exception_status(
    binding: &BindingIdentity,
    reason: &str,
    packet_length: u32,
    meta: Option<UserspaceDpMeta>,
    debug: Option<&ResolutionDebug>,
    forwarding: &ForwardingState,
) -> ExceptionStatus {
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
        from_zone: debug
            .and_then(|d| d.from_zone)
            .map(zone_name_for)
            .unwrap_or_default(),
        to_zone: debug
            .and_then(|d| d.to_zone)
            .map(zone_name_for)
            .unwrap_or_default(),
        ..ExceptionStatus::default()
    }
}

/// #1187: counter sink for `record_disposition` /
/// `record_forwarding_disposition`. Hot callers (worker poll path)
/// pass `Hot(&mut BatchCounters)` so per-packet increments land in
/// the per-poll-tick batch and flush via `BatchCounters::flush()`.
/// Cold callers (coordinator/inject.rs RPC injection) pass
/// `Cold(&BindingLiveState)` and write directly to atomics — they're
/// not on the worker per-packet hot path so MESI thrash is not a
/// concern there.
pub(super) enum DispositionCounters<'a> {
    Hot(&'a mut BatchCounters),
    Cold(&'a BindingLiveState),
}

impl DispositionCounters<'_> {
    /// #3651: true on the worker per-packet hot path (`Hot`), false for the
    /// cold RPC-inject path (`Cold`). Per-zone traffic accounting only runs on
    /// `Hot` because the coalescer's thread-local is folded into the shared
    /// store from the worker RX-batch flush — the control thread that drives
    /// `Cold` never reaches that flush, so its accumulation would be lost.
    #[inline]
    fn is_hot(&self) -> bool {
        matches!(self, Self::Hot(_))
    }

    #[inline]
    fn bump_validated(&mut self, packet_length: u32) {
        match self {
            Self::Hot(c) => {
                c.touched = true;
                c.validated_packets += 1;
                c.validated_bytes += packet_length as u64;
            }
            Self::Cold(live) => {
                live.validated_packets.fetch_add(1, Ordering::Relaxed);
                live.validated_bytes
                    .fetch_add(packet_length as u64, Ordering::Relaxed);
            }
        }
    }
    #[inline]
    fn bump_exception(&mut self) {
        match self {
            Self::Hot(c) => {
                c.touched = true;
                c.exception_packets += 1;
            }
            Self::Cold(live) => {
                live.exception_packets.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    #[inline]
    fn bump_local_delivery(&mut self) {
        match self {
            Self::Hot(c) => {
                c.touched = true;
                c.local_delivery_packets += 1;
            }
            Self::Cold(live) => {
                live.local_delivery_packets.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    #[inline]
    fn bump_forward_candidate(&mut self) {
        match self {
            Self::Hot(c) => {
                c.touched = true;
                c.forward_candidate_packets += 1;
            }
            Self::Cold(live) => {
                live.forward_candidate_packets
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    #[inline]
    fn bump_policy_denied(&mut self) {
        match self {
            Self::Hot(c) => {
                c.touched = true;
                c.policy_denied_packets += 1;
            }
            Self::Cold(live) => {
                live.policy_denied_packets.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    #[inline]
    fn bump_route_miss(&mut self) {
        match self {
            Self::Hot(c) => {
                c.touched = true;
                c.route_miss_packets += 1;
            }
            Self::Cold(live) => {
                live.route_miss_packets.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    /// #4743: a NoRoute drop whose destination is a martian address. A strict
    /// sub-breakout of `bump_route_miss` — the caller bumps BOTH, so
    /// `martian_dropped <= route_miss_packets` always holds (mirrors how
    /// `screen_reason_drops` break out `screen_drops`).
    #[inline]
    fn bump_martian(&mut self) {
        match self {
            Self::Hot(c) => {
                c.touched = true;
                c.martian_dropped += 1;
            }
            Self::Cold(live) => {
                live.martian_dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    #[inline]
    fn bump_neighbor_miss(&mut self) {
        match self {
            Self::Hot(c) => {
                c.touched = true;
                c.neighbor_miss_packets += 1;
            }
            Self::Cold(live) => {
                live.neighbor_miss_packets.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    #[inline]
    fn bump_discard_route(&mut self) {
        match self {
            Self::Hot(c) => {
                c.touched = true;
                c.discard_route_packets += 1;
            }
            Self::Cold(live) => {
                live.discard_route_packets.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    #[inline]
    fn bump_next_table(&mut self) {
        match self {
            Self::Hot(c) => {
                c.touched = true;
                c.next_table_packets += 1;
            }
            Self::Cold(live) => {
                live.next_table_packets.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

pub(super) fn record_disposition(
    binding: &BindingIdentity,
    live: &BindingLiveState,
    mut counters: DispositionCounters<'_>,
    disposition: PacketDisposition,
    packet_length: u32,
    meta: Option<UserspaceDpMeta>,
    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
    forwarding: &ForwardingState,
) {
    match disposition {
        PacketDisposition::Valid => {
            counters.bump_validated(packet_length);
        }
        PacketDisposition::NoSnapshot => {
            counters.bump_exception();
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
            counters.bump_exception();
            // config_gen_mismatches is reconcile-only; deferred from
            // batch per plan §2. Direct atomic on `live`.
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
            counters.bump_exception();
            // fib_gen_mismatches is reconcile-only; deferred per plan §2.
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
            counters.bump_exception();
            // unsupported_packets is reconcile-/upgrade-window only;
            // deferred per plan §2.
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

pub(super) fn record_forwarding_disposition(
    binding: &BindingIdentity,
    mut counters: DispositionCounters<'_>,
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
            counters.bump_local_delivery();
        }
        ForwardingDisposition::ForwardCandidate | ForwardingDisposition::FabricRedirect => {
            counters.bump_forward_candidate();
            // #3651: per-zone traffic volume for forward paths that resolve
            // through record_forwarding_disposition (tunnel decap, next-table,
            // fabric redirect). Hot-path only (the Cold RPC-inject path's
            // thread-local coalescer is never flushed); needs the shim meta for
            // the ingress zone.
            if counters.is_hot()
                && let Some(m) = meta
            {
                crate::afxdp::zone_counters::record_zone_traffic(
                    &forwarding.zone_counter_slot_map,
                    m.ingress_zone,
                    forwarding.egress_zone_id(resolution.egress_ifindex),
                    m.pkt_len as u64,
                );
            }
        }
        ForwardingDisposition::HAInactive => {
            update_last_resolution(last_resolution, resolution, debug, forwarding);
            counters.bump_exception();
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
            counters.bump_policy_denied();
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
            counters.bump_route_miss();
            // #4743: a NoRoute drop whose destination is a martian address is
            // ALSO counted distinctly so an operator can tell it apart from an
            // ordinary route miss (and correlate it with the filter-`accept`
            // log). A martian dst simply misses the FIB and drops as NoRoute —
            // there is no separate martian rejection site — so this classifies
            // off the resolution's destination (from the debug tuple) and bumps
            // martian_dropped IN ADDITION to route_miss_packets.
            if debug
                .and_then(|d| d.dst_ip)
                .is_some_and(is_martian_dst)
            {
                counters.bump_martian();
            }
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
            counters.bump_neighbor_miss();
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
            counters.bump_discard_route();
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
            counters.bump_next_table();
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

pub(super) fn update_last_resolution(
    last_resolution: &Arc<Mutex<Option<PacketResolution>>>,
    resolution: ForwardingResolution,
    debug: Option<&ResolutionDebug>,
    forwarding: &ForwardingState,
) {
    if let Ok(mut last) = last_resolution.lock() {
        *last = Some(resolution.status(debug, forwarding));
    }
}
