use super::*;

mod host_inbound;
mod fib;
pub(in crate::afxdp) use fib::*;
mod tunnel;
pub(in crate::afxdp) use tunnel::*;
mod local_delivery;
pub(in crate::afxdp) use local_delivery::*;
mod pbr;
pub(in crate::afxdp) use pbr::*;
mod ipsec;
pub(in crate::afxdp) use ipsec::*;
mod mss;
pub(in crate::afxdp) use mss::*;
mod ha;
pub(in crate::afxdp) use ha::*;
mod nat;
pub(in crate::afxdp) use nat::*;
mod fabric;
pub(in crate::afxdp) use fabric::*;
// #3070: re-export into the afxdp scope so the local-delivery admit path
// (poll_descriptor, via `use self::forwarding::*`) and the forwarding-state
// builder (forwarding_build::zones) can reach them.
pub(in crate::afxdp) use host_inbound::{
    host_inbound_admits, host_inbound_admits_iface, zone_host_inbound_from_snapshot,
    zone_host_inbound_from_tokens,
};

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn zone_pair_for_flow(
    forwarding: &ForwardingState,
    ingress_ifindex: i32,
    egress_ifindex: i32,
) -> (String, String) {
    zone_pair_for_flow_with_override(forwarding, ingress_ifindex, None, egress_ifindex)
}

pub(super) fn zone_pair_for_flow_with_override(
    forwarding: &ForwardingState,
    ingress_ifindex: i32,
    ingress_zone_override: Option<&str>,
    egress_ifindex: i32,
) -> (String, String) {
    // #921: this helper is `#[cfg_attr(not(test), allow(dead_code))]`
    // (see zone_pair_for_flow above) and is only called from tests.
    // After #921, `ifindex_to_zone_id` and `EgressInterface.zone_id`
    // are u16. Resolve back to the name via `zone_id_to_name` for
    // the test-only String API. Slow path; allocations are fine.
    let from_zone = ingress_zone_override
        .map(|zone| zone.to_string())
        .or_else(|| {
            forwarding
                .ifindex_to_zone_id
                .get(&ingress_ifindex)
                .and_then(|id| forwarding.zone_id_to_name.get(id).cloned())
        })
        .unwrap_or_default();
    // #6713: resolve through the shared `egress_zone_id` so this test-only
    // String twin cannot report a different to-zone than the production
    // u16 resolver below.
    let to_zone = match forwarding.egress_zone_id(egress_ifindex) {
        0 => String::new(),
        id => forwarding
            .zone_id_to_name
            .get(&id)
            .cloned()
            .unwrap_or_default(),
    };
    (from_zone, to_zone)
}

/// #919/#922: zero-allocation production zone-pair resolver. Returns
/// `(from_id, to_id)` u16 pair directly without `String` materialisation.
/// `ingress_zone_override` is `Option<u16>` (parsed from fabric MAC),
/// not `Option<&str>` — callers no longer round-trip through names.
/// Returns `(0, 0)` segments for ifindexes not in the zone maps; the
/// caller treats `0` as "unknown" and falls back to default policy.
#[inline]
pub(super) fn zone_pair_ids_for_flow_with_override(
    forwarding: &ForwardingState,
    ingress_ifindex: i32,
    ingress_zone_override: Option<u16>,
    egress_ifindex: i32,
) -> (u16, u16) {
    // #921: single-hop direct lookup. Was two HashMap lookups
    // (ifindex → String → u16) and one String hash; now one
    // (ifindex → u16) for ingress and a struct field load for egress.
    let from_id = ingress_zone_override
        .or_else(|| forwarding.ifindex_to_zone_id.get(&ingress_ifindex).copied())
        .unwrap_or(0);
    // #6713: the to-zone comes from `ForwardingState::egress_zone_id`, which
    // reads `ifindex_unambiguous_zone_id` — the ONLY map it reads; the `egress`
    // arm this comment once described was removed once `populate_egress` began
    // sourcing `EgressInterface::zone_id` from that same ledger, so the two arms
    // had become the same number (see that function's doc, "WHY THERE IS NO
    // LONGER AN `egress` ARM"). NOT `ifindex_to_zone_id` — that map is the from-zone source
    // and carries the LAST zoned row on an ifindex plus the child->parent
    // propagation, so reading it as the to-zone hands an interface a zone the
    // operator never configured on it (#6722). An IPsec secure tunnel (xfrmi) NEVER has one — it is
    // MAC-less, and `populate_egress` requires a resolvable link-layer address
    // — so before this the to-zone of a correctly-zoned tunnel resolved to the
    // "unknown" sentinel 0, against which policy evaluation refuses to match
    // any rule, and every LAN->tunnel packet fell to the default policy no
    // matter what the operator permitted.
    let to_id = forwarding.egress_zone_id(egress_ifindex);
    (from_id, to_id)
}

/// #919/#922 test convenience: ID-pair without override.
#[cfg(test)]
pub(super) fn zone_pair_ids_for_flow(
    forwarding: &ForwardingState,
    ingress_ifindex: i32,
    egress_ifindex: i32,
) -> (u16, u16) {
    zone_pair_ids_for_flow_with_override(forwarding, ingress_ifindex, None, egress_ifindex)
}

pub(super) fn allow_unsolicited_dns_reply(
    forwarding: &ForwardingState,
    flow: &SessionFlow,
) -> bool {
    forwarding.allow_dns_reply
        && flow.forward_key.protocol == PROTO_UDP
        && flow.forward_key.src_port == 53
}


pub(super) fn resolve_ingress_logical_ifindex(
    forwarding: &ForwardingState,
    ingress_ifindex: i32,
    ingress_vlan_id: u16,
) -> Option<i32> {
    forwarding
        .ingress_logical_ifindex
        .get(&(ingress_ifindex, ingress_vlan_id))
        .copied()
}

// #989: clamp_tcp_mss / clamp_tcp_mss_frame relocated to `frame/tcp.rs`.

#[cfg(test)]
mod tests;
// #7520: the ICMP global-accept family-pairing cells.
#[cfg(test)]
#[path = "tests_icmp_family_7520.rs"]
mod tests_icmp_family_7520;
