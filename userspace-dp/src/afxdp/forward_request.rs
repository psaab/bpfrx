// Forward-request builders extracted from afxdp.rs (Issue 67.4).
//
// `build_live_forward_request` and `build_live_forward_request_from_frame`
// pack a per-packet ForwardingResolution + SessionMetadata into the
// LiveForwardRequest descriptor that the dispatch path enqueues.
//
// `should_install_local_reverse_session` is the small predicate that
// decides whether the reverse-direction session entry should be
// pre-installed locally vs lazily on first reverse-direction packet.
//
// Pure relocation. `use super::*;` brings every type and helper from
// afxdp.rs into scope.

use super::*;

pub(super) fn should_install_local_reverse_session(
    decision: SessionDecision,
    fabric_ingress: bool,
) -> bool {
    let fabric_wire_placeholder =
        shared_ops::is_fabric_wire_placeholder(fabric_ingress, false, decision);
    decision.resolution.disposition != ForwardingDisposition::FabricRedirect
        || (fabric_ingress && !fabric_wire_placeholder)
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn build_live_forward_request(
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
    now_ns: u64,
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
        now_ns,
        None,
        None,
        None,
    )
}

pub(super) fn build_live_forward_request_from_frame(
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
    now_ns: u64,
    event_stream: Option<&crate::event_stream::EventStreamWorkerHandle>,
    hints: Option<PendingForwardHints>,
    precomputed_tx_selection: Option<&CachedTxSelectionDescriptor>,
) -> Option<PendingForwardRequest> {
    let hints = hints.unwrap_or_default();
    let target_ifindex = if decision.resolution.tx_ifindex > 0 {
        decision.resolution.tx_ifindex
    } else {
        resolve_tx_binding_ifindex(forwarding, decision.resolution.egress_ifindex)
    };
    // #2357: a forwarded non-first IP fragment carries no L4 header — its
    // post-IP-header bytes are payload, not ports. #2344 already made it
    // flowless on the policy/session path (`flow` is `None` here), but the
    // TX-CoS / fabric-queue selection below re-derives a ported tuple from
    // metadata/frame independently of that gate. Compute the non-first-
    // fragment predicate ONCE and suppress port synthesis for it so all
    // fragments of one datagram land on the interface default queue / a
    // fragment-stable (port-less) fabric hash and never hit a port-matching
    // output-filter term. The gate fires ONLY for an actual non-first
    // fragment with no real flow — a legitimate flowless TCP/UDP packet
    // (real L4 header, `flow` None) keeps its meta/frame-derived ports.
    let non_first_fragment = flow.is_none() && frame_is_non_first_fragment(frame, meta);
    // Prefer session flow ports (set by conntrack, immune to DMA races),
    // then live frame ports (lazy — only parsed if session ports unavailable),
    // then metadata as last resort.
    let expected_ports = if non_first_fragment {
        None
    } else {
        hints
            .expected_ports
            .or_else(|| authoritative_forward_ports(frame, meta, flow))
    };
    let target_binding_index = hints.target_binding_index.or_else(|| {
        if decision.resolution.disposition == ForwardingDisposition::FabricRedirect {
            binding_lookup.fabric_target_index(
                target_ifindex,
                fabric_queue_hash(flow, expected_ports, meta, non_first_fragment),
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
    let fallback_flow;
    let tx_selection_flow = if flow.is_some() {
        flow
    } else if non_first_fragment {
        // #2357: do NOT synthesize a ported tuple from metadata for a
        // non-first fragment. A `None` flow_key drives
        // `resolve_cos_tx_selection_at` to the interface default queue with
        // NO output-filter (port) evaluation (tx/cos_classify.rs early
        // `None` arm) — so a fragment is never misclassified by, or
        // spuriously dropped by, a port-matching terminal filter term.
        None
    } else if matches!(meta.protocol, PROTO_ICMP | PROTO_ICMPV6)
        && !meta_icmp_identifier_bearing(frame, meta)
    {
        // #3290: mirror the conntrack-side gate. The XDP shim stamps
        // `meta.flow_src_port` from bytes [l4+4..l4+6] for EVERY ICMP/ICMPv6
        // type with no query-type gate, so synthesizing a tuple here for a
        // non-query ICMP error/control packet (Dest-Unreachable,
        // Packet-Too-Big, Time-Exceeded, Parameter-Problem, Redirect, ND/MLD)
        // would feed a fabricated pseudo-port into TX selection AND CoS
        // output-filter evaluation (`tx/cos_classify.rs` reads
        // flow_key.src_port/dst_port) — and store it in the pending request's
        // `flow_key`. A `None` flow_key takes the same default, no-output-filter
        // path as the fragment case above, matching the flowless verdict
        // `parse_session_flow_from_bytes` produces for these packets on the
        // conntrack side. Identifier-bearing query types keep their tuple (and
        // for those the primary `flow` is already `Some`, so this arm is only
        // reached for the non-query / truncated case).
        None
    } else {
        fallback_flow = parse_session_flow_from_meta(meta);
        fallback_flow.as_ref()
    };
    let cos = precomputed_tx_selection
        .map(|selection| CoSTxSelection {
            queue_id: selection.queue_id,
            dscp_rewrite: selection.dscp_rewrite,
            drop: selection.drop,
            filter_log: selection.filter_log,
        })
        .unwrap_or_else(|| {
            resolve_cos_tx_selection_at(
                forwarding,
                decision.resolution.egress_ifindex,
                meta,
                tx_selection_flow.map(|flow| &flow.forward_key),
                // #2362 fold B: build the fragment-safe per-packet match inputs
                // from the live frame so a `from { tcp-flags ... } then
                // forwarding-class X` (or is-fragment / icmp-type) output filter
                // selects the class on exactly the authored packets on the
                // TX-selection / CoS leg, not every packet of the flow.
                crate::afxdp::frame::term_match_extra_from_frame(frame, meta),
                now_ns,
            )
        });
    if let (Some(filter_log), Some(flow)) = (cos.filter_log, tx_selection_flow) {
        let ingress_zone_id = fabric_ingress_zone
            .filter(|id| forwarding.zone_id_to_name.contains_key(id))
            .or_else(|| {
                forwarding
                    .ifindex_to_zone_id
                    .get(&(meta.ingress_ifindex as i32))
                    .copied()
            })
            .unwrap_or(0);
        let egress_zone_id = forwarding
            .egress
            .get(&decision.resolution.egress_ifindex)
            .map(|egress| egress.zone_id)
            .unwrap_or(0);
        emit_filter_log_event(
            event_stream,
            flow,
            meta,
            ingress_zone_id,
            egress_zone_id,
            filter_log.filter_id,
            filter_log.term_id,
            filter_log.action,
            FilterLogSource::Output,
            // #2520: AppID via the hot-path app_catalog.lookup.
            resolve_flow_app_id(&forwarding.app_catalog, flow),
            now_ns,
        );
    }
    if cos.drop {
        return None;
    }
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
        flow_key: tx_selection_flow.map(|flow| flow.forward_key.clone()),
        nat64_reverse: None,
        cos_queue_id: cos.queue_id,
        dscp_rewrite: cos.dscp_rewrite,
        cos_tx_selection_resolved: true,
        // #2362 fold B: snapshot the fragment-safe per-packet match inputs so a
        // later deferred TX-selection recompute keeps the same verdict even
        // after the UMEM frame is recycled.
        // #3077: stored on the deferred CoS/TX-selection path — strip the
        // borrowed frame slice (to_static) since the frame may be recycled
        // before this is consumed. The flex byte-offset term fails closed here.
        filter_match_extra: crate::afxdp::frame::term_match_extra_from_frame(frame, meta)
            .to_static(),
    })
}
