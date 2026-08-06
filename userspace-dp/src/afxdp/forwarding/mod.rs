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
    let to_zone = forwarding
        .egress
        .get(&egress_ifindex)
        .and_then(|iface| forwarding.zone_id_to_name.get(&iface.zone_id).cloned())
        .unwrap_or_default();
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
    let to_id = forwarding
        .egress
        .get(&egress_ifindex)
        .map(|iface| iface.zone_id)
        .unwrap_or(0);
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

/// #4983: resolve the CLUSTER-STABLE ingress-interface identity for a frame —
/// the id stamped onto a session as "the interface this flow arrived on".
///
/// It resolves the LOGICAL ingress unit first (so a tagged frame on a trunk
/// names `reth0.50`, not the parent NIC) and then maps that ifindex through
/// `ifindex_to_stable_iface_id`. Going via the logical unit is what makes a
/// bondless-RETH VLAN unit work: its ifindex may be SYNTHETIC, but both the
/// resolution and the id map are built from the same config snapshot, so they
/// agree by construction.
///
/// Returns `0` — the reserved "no ingress identity carried" sentinel — when the
/// interface is not in the map (an old Go binary that sends no `stable_id`, or
/// a binding with no config row). The CLI answers `0` from the zone
/// approximation, exactly as it did before #4983.
pub(super) fn resolve_ingress_iface_id(
    forwarding: &ForwardingState,
    ingress_ifindex: i32,
    ingress_vlan_id: u16,
) -> u32 {
    let logical = resolve_ingress_logical_ifindex(forwarding, ingress_ifindex, ingress_vlan_id)
        .unwrap_or(ingress_ifindex);
    forwarding
        .ifindex_to_stable_iface_id
        .get(&logical)
        .copied()
        .unwrap_or(0)
}

// #989: clamp_tcp_mss / clamp_tcp_mss_frame relocated to `frame/tcp.rs`.

#[cfg(test)]
mod tests;
