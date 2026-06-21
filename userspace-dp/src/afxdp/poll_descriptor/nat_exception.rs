// #1697 cold-path extraction: source-NAT decision + failure recorder,
// lifted out of poll_descriptor/mod.rs.
//
// Both helpers run only on the session-miss slow path:
// source_nat_decision_for_flow is evaluated once per new flow when the
// session table misses, and record_source_nat_failure fires only on a
// genuine SNAT-exhaustion exception. Neither is reached on the
// established-flow transit fast path (stage_flow_cache_hit), so both are
// #[cold] #[inline(never)] — .text.unlikely placement keeps the
// exception bodies out of the hot ingress loop's codegen unit and
// cache lines.
//
// The bodies are byte-for-byte identical to their previous location in
// mod.rs; only the enclosing module and the inline attributes change.

use super::*;

#[cold]
#[inline(never)]
#[allow(clippy::too_many_arguments)]
pub(super) fn source_nat_decision_for_flow(
    forwarding: &ForwardingState,
    from_zone: &str,
    to_zone: &str,
    egress_ifindex: i32,
    flow: &SessionFlow,
    now_ns: u64,
    // #1852: gate pool-mode SNAT allocation for non-first fragments. The
    // static-NAT (address-only) match below is NOT gated — it rewrites
    // the IP on every fragment, which is correct.
    non_first_fragment: bool,
    // #2218: out-param — the matched SNAT/static-SNAT rule's per-rule hit
    // counter (None when no rule matched or the rule has no counter). The
    // caller increments it once per committed translated forward flow.
    matched_counter: &mut Option<std::sync::Arc<crate::nat::NatRuleCounter>>,
) -> Result<NatDecision, SourceNatFailure> {
    *matched_counter = None;
    if let Some((decision, counter)) = forwarding
        .static_nat
        .match_snat_with_counter(flow.src_ip, from_zone)
    {
        *matched_counter = counter;
        return Ok(decision);
    }
    match match_source_nat_for_flow_result_at(
        forwarding,
        from_zone,
        to_zone,
        egress_ifindex,
        flow,
        now_ns,
        non_first_fragment,
        matched_counter,
    ) {
        SourceNatLookup::Matched(decision) => Ok(decision),
        SourceNatLookup::NoMatch => {
            *matched_counter = None;
            Ok(NatDecision::default())
        }
        SourceNatLookup::Unavailable(failure) => {
            *matched_counter = None;
            Err(failure)
        }
    }
}

#[cold]
#[inline(never)]
pub(super) fn record_source_nat_failure(
    telemetry: &mut TelemetryContext,
    worker_ctx: &WorkerContext,
    meta: UserspaceDpMeta,
    flow: &SessionFlow,
    from_zone_id: u16,
    to_zone_id: u16,
    packet_length: u32,
    failure: &SourceNatFailure,
) {
    telemetry.counters.touched = true;
    telemetry.counters.exception_packets += 1;
    let mut debug = ResolutionDebug::from_flow(meta.ingress_ifindex as i32, flow);
    debug.from_zone = Some(from_zone_id);
    debug.to_zone = Some(to_zone_id);
    record_source_nat_exception(
        worker_ctx.recent_exceptions,
        &worker_ctx.ident,
        packet_length,
        Some(meta),
        Some(&debug),
        worker_ctx.forwarding,
        failure,
    );
}
