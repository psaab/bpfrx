//! #3070: host-inbound-traffic admission for host-bound (local-delivery)
//! traffic.
//!
//! `security zones <z> host-inbound-traffic { system-services ...; protocols
//! ...; }` is parsed and modeled in the Go control plane but, before #3070,
//! never reached the dataplane: host-bound traffic (SSH, ping, routing
//! protocols destined to a firewall-local interface IP) was admitted
//! regardless of the configured set. This module classifies the raw Junos
//! tokens carried on `ZoneSnapshot` into a `ZoneHostInbound` admission set and
//! provides the per-packet admit check used on the local-delivery path.
//!
//! Default posture: a zone is enforced only when it declared a
//! `host-inbound-traffic` stanza (`ZoneSnapshot::host_inbound_configured`). A
//! zone without a stanza is absent from `ForwardingState::zone_host_inbound`
//! and `host_inbound_admits` returns admit (preserving the pre-#3070
//! admit-all behaviour with zero regression for configs that never opted in).
//! This is a deliberate, safe deviation from strict Junos (which denies
//! host-bound traffic to an unconfigured zone): it closes the gap exactly
//! where the operator expressed intent without risking management/routing
//! lockout on existing deploys. Strict absent-zone deny can be layered on top
//! later behind an explicit knob.

use super::*;

// #3201/#3240: ICMP type numbers carried per-zone for subtype-specific
// host-inbound admission. These mirror the nft chain's named-type matches
// (`pkg/daemon/daemon_nft.go`): `ping` → echo-request, IPv4 `router-discovery`
// → router-advertisement/solicitation (types 9/10). Error/PMTUD and IPv6 ND
// subtypes are admitted globally instead (see `is_icmp_host_inbound_global_accept`).
const ICMP4_ECHO_REQUEST: u8 = 8;
const ICMP4_ROUTER_ADVERTISEMENT: u8 = 9;
const ICMP4_ROUTER_SOLICITATION: u8 = 10;
const ICMP6_ECHO_REQUEST: u8 = 128;

/// Build the per-zone host-inbound admission table from the snapshot. Only
/// zones with `host_inbound_configured == true` get an entry. The zone id used
/// as the key MUST be the same validated id `populate_zones` accepted (caller
/// passes it), so the two maps stay aligned.
pub(in crate::afxdp) fn zone_host_inbound_from_snapshot(zone: &ZoneSnapshot) -> ZoneHostInbound {
    let mut hi = ZoneHostInbound::default();
    for svc in &zone.host_inbound_system_services {
        classify_system_service(svc.trim().to_ascii_lowercase().as_str(), &mut hi);
    }
    for proto in &zone.host_inbound_protocols {
        classify_protocol(proto.trim().to_ascii_lowercase().as_str(), &mut hi);
    }
    hi
}

/// Classify one Junos `system-services` token into the admission set.
/// Unrecognised tokens are intentionally ignored (fail-closed: they do not
/// broaden admit). Covers the common Junos service set; the repo configs use
/// {all, ssh, ping, dhcp, dhcpv6, gre} and this is a comprehensive superset.
fn classify_system_service(token: &str, hi: &mut ZoneHostInbound) {
    match token {
        "all" | "any-service" => hi.all_services = true,
        "ssh" => {
            hi.tcp_ports.insert(22);
        }
        "telnet" => {
            hi.tcp_ports.insert(23);
        }
        "ftp" => {
            hi.tcp_ports.insert(21);
        }
        "http" | "webapi-clear-text" => {
            hi.tcp_ports.insert(80);
        }
        "https" | "webapi-ssl" => {
            hi.tcp_ports.insert(443);
        }
        // #3201/#3240: `ping` admits ICMP echo-request ONLY (v4 type 8, v6 type
        // 128), matching the nft chain (`hostInboundServiceMatches`:
        // `icmp/icmpv6 type echo-request`) — NOT the whole ICMP protocol. ICMP
        // error/PMTUD subtypes are admitted separately + globally (#3171).
        "ping" => {
            hi.icmp_types_v4.insert(ICMP4_ECHO_REQUEST);
            hi.icmp_types_v6.insert(ICMP6_ECHO_REQUEST);
        }
        "dns" => {
            hi.udp_ports.insert(53);
            hi.tcp_ports.insert(53);
        }
        // dhcp server listens on udp/67; client replies arrive on udp/68. Admit
        // both so a `dhcp-local-server` on the zone interface works. #3225:
        // DHCPv4 is IPv4-only — these ports must NOT open on the v6 path (the
        // family map config.HostInboundServiceFamily is the cross-layer SSOT).
        "dhcp" | "bootp" => {
            hi.udp_ports_v4.insert(67);
            hi.udp_ports_v4.insert(68);
        }
        // #3225: DHCPv6 is IPv6-only — these ports stay off the v4 path.
        "dhcpv6" => {
            hi.udp_ports_v6.insert(546);
            hi.udp_ports_v6.insert(547);
        }
        "ntp" => {
            hi.udp_ports.insert(123);
        }
        "snmp" => {
            hi.udp_ports.insert(161);
        }
        "snmp-trap" => {
            hi.udp_ports.insert(162);
        }
        // `ipsec` is the Junos system-service that permits host-terminated
        // IPsec. It opens IKE (udp 500 / NAT-T 4500); the raw ESP/AH data plane
        // is handled by the kernel XFRM stack / stage_ipsec_passthrough_check
        // before host-inbound enforcement, so `ipsec` is effectively a superset
        // of `ike`. Aliased to keep parity with the nft mirror + the #3200 SSOT.
        "ike" | "ipsec" => {
            hi.udp_ports.insert(500);
            hi.udp_ports.insert(4500);
        }
        "tftp" => {
            hi.udp_ports.insert(69);
        }
        "netconf" => {
            hi.tcp_ports.insert(830);
        }
        "ssh-netconf" | "netconf-ssh" => {
            hi.tcp_ports.insert(830);
            hi.tcp_ports.insert(22);
        }
        "finger" => {
            hi.tcp_ports.insert(79);
        }
        "ident-reset" => {
            hi.tcp_ports.insert(113);
        }
        "lsping" => {
            hi.udp_ports.insert(3503);
        }
        "sip" => {
            hi.udp_ports.insert(5060);
            hi.tcp_ports.insert(5060);
        }
        "r-login" | "rlogin" => {
            hi.tcp_ports.insert(513);
        }
        "r-sh" | "rsh" => {
            hi.tcp_ports.insert(514);
        }
        "r-exec" | "rexec" => {
            hi.tcp_ports.insert(512);
        }
        "xnm-clear-text" => {
            hi.tcp_ports.insert(3221);
        }
        "xnm-ssl" => {
            hi.tcp_ports.insert(3220);
        }
        "traceroute" => {
            // UDP probes land in the 33434..33523 range; admit it as a small
            // explicit set (kept short to avoid bloating the per-zone set).
            for p in 33434u16..=33523 {
                hi.udp_ports.insert(p);
            }
        }
        // Some operators list `gre` under system-services (see the repo
        // ha-cluster config wan zone). Treat it as IP protocol 47.
        "gre" => {
            hi.ip_protocols.insert(47);
        }
        // Unknown / unmapped service token: ignore (fail-closed).
        _ => {}
    }
}

/// The routing-protocol tokens that `protocols all` expands to (#3199). In
/// Junos `host-inbound-traffic protocols all` admits every supported ROUTING
/// protocol — NOT every system-service and NOT a blanket bypass. Expanding the
/// `all` token to this concrete set (rather than a short-circuit admit) keeps a
/// `protocols all` zone from opening SSH/HTTPS/SNMP/NETCONF on the box. One
/// entry per unique signature (`ospf3` aliases `ospf`); the caller dedups.
const ROUTING_PROTOCOL_TOKENS: &[&str] = &[
    // #3225: ospf (OSPFv2, IPv4) and ospf3 (OSPFv3, IPv6) are BOTH listed so
    // `protocols all` admits proto 89 on each family; classify_protocol scopes
    // each to its own family.
    "ospf",
    "ospf3",
    "bgp",
    "rip",
    "ripng",
    "igmp",
    "pim",
    "vrrp",
    "bfd",
    "ldp",
    "msdp",
    "nhrp",
    "router-discovery",
];

/// Classify one Junos `protocols` (routing-protocol) token. Port-based
/// protocols (bgp/ldp/msdp/rip) contribute TCP/UDP ports; IP-protocol-based
/// ones (ospf/pim/igmp/vrrp) contribute a protocol number; router-discovery is
/// ICMP/ICMPv6.
fn classify_protocol(token: &str, hi: &mut ZoneHostInbound) {
    match token {
        // `protocols all` admits only the routing-protocol set (#3199) — it
        // expands to every entry under the `protocols` stanza, NOT system
        // services and NOT a blanket accept. `ROUTING_PROTOCOL_TOKENS` never
        // contains "all", so this recursion terminates.
        "all" => {
            for tok in ROUTING_PROTOCOL_TOKENS {
                classify_protocol(tok, hi);
            }
        }
        // #3225: OSPFv2 (ospf) is IPv4-only, OSPFv3 (ospf3) is IPv6-only — both
        // ride IP protocol 89 but on different families (SSOT:
        // config.HostInboundProtocolFamily).
        "ospf" => {
            hi.ip_protocols_v4.insert(89);
        }
        "ospf3" => {
            hi.ip_protocols_v6.insert(89);
        }
        "bgp" => {
            hi.tcp_ports.insert(179);
        }
        // #3225: RIPv2 is IPv4-only, RIPng is IPv6-only.
        "rip" => {
            hi.udp_ports_v4.insert(520);
        }
        "ripng" => {
            hi.udp_ports_v6.insert(521);
        }
        // #3225: IGMP is IPv4 group membership; the IPv6 equivalent is MLD over
        // ICMPv6 (the always-accepted ND set), so igmp is IPv4-only here.
        "igmp" => {
            hi.ip_protocols_v4.insert(2);
        }
        "pim" => {
            hi.ip_protocols.insert(103);
        }
        "vrrp" => {
            hi.ip_protocols.insert(112);
        }
        // #3299: BFD admits single-hop control (3784) + echo (3785) AND
        // multi-hop control (4784, RFC 5883). Multi-hop is control-only; echo
        // stays single-hop on 3785. Keep this set in lockstep with the nft
        // host-inbound rule (`hostInboundProtocolMatches`, pkg/daemon).
        "bfd" => {
            hi.udp_ports.insert(3784);
            hi.udp_ports.insert(3785);
            hi.udp_ports.insert(4784);
        }
        "ldp" => {
            hi.tcp_ports.insert(646);
            hi.udp_ports.insert(646);
        }
        "msdp" => {
            hi.tcp_ports.insert(639);
        }
        "nhrp" => {
            hi.ip_protocols.insert(54);
        }
        // #3201/#3240: router-discovery admits ICMPv4 router-advertisement (9)
        // and router-solicitation (10) ONLY — matching the nft chain
        // (`hostInboundProtocolMatches`: `icmp type { 9, 10 }`). On v6, RS/RA
        // are part of the always-accepted ND set (types 133-137) handled
        // globally by `is_icmp_host_inbound_global_accept`, so router-discovery
        // contributes nothing per-zone on v6 — exactly as the nft chain returns
        // nil for v6 router-discovery and relies on the global ND accept.
        "router-discovery" => {
            hi.icmp_types_v4.insert(ICMP4_ROUTER_ADVERTISEMENT);
            hi.icmp_types_v4.insert(ICMP4_ROUTER_SOLICITATION);
        }
        // Unknown / unmapped protocol token: ignore (fail-closed).
        _ => {}
    }
}

/// #3171/#3201/#3240: ICMP/ICMPv6 subtypes that the host-inbound layer admits
/// UNCONDITIONALLY — regardless of which services/protocols the ingress zone
/// lists — so the userspace LocalDelivery classifier matches the kernel
/// host-inbound chain's GLOBAL accepts at the top of the chain
/// (`pkg/daemon/daemon_nft.go` `buildHostInboundFilterPayload`):
/// `icmp type { destination-unreachable, time-exceeded, parameter-problem }`
/// and `icmpv6 type { 1, 2, 3, 4, 133, 134, 135, 136, 137 }`.
///
/// Two categories ride this global accept:
///   1. ERROR / PMTUD control messages (#3171) — destination-unreachable,
///      packet-too-big, time-exceeded, parameter-problem — which carry PMTUD /
///      unreachable / traceroute-to-self signalling that must reach a
///      firewall-local address (e.g. a DNAT-to-self embedded ICMP error landing
///      on the XSK) even on a configured ping-less zone.
///   2. IPv6 Neighbor Discovery (#3201/#3240) — RS (133), RA (134), NS (135),
///      NA (136), Redirect (137). ND is core L3 operation, accepted globally by
///      the nft chain (never a per-service exposure). Admitting it here is what
///      lets the per-zone `router-discovery` token carry NOTHING on v6 while
///      still matching nft — i.e. v6 RS/RA reach the host via this global ND
///      accept on any host-inbound-configured zone, exactly as nft does.
///
/// The ICMPv4 set is deliberately NARROWER than `icmp::is_icmp_error` (the
/// embedded-NAT reversal set, which also includes v4 Source Quench (4) and
/// Redirect (5)): Source Quench is deprecated (RFC 6633) and v4 Redirect is
/// link-scoped — neither is a control message we admit to the host, and neither
/// is in the nft v4 global accept. ECHO REQUEST (v4 type 8 / v6 type 128) is NOT
/// here: it stays gated on the `ping` system-service (per-zone `icmp_types_*`),
/// so a ping-less zone still drops echo. IPv4 router-advertisement/solicitation
/// (9/10) are likewise NOT global — they are gated on `router-discovery` per
/// zone (nft `icmp type { 9, 10 }`).
///
/// Keep this set in lock-step with the kernel chain in
/// `pkg/daemon/daemon_nft.go` and its
/// `TestHostInboundFilterExemptsIPsecAndV6Errors` accept assertions.
fn is_icmp_host_inbound_global_accept(protocol: u8, icmp_type: u8) -> bool {
    match protocol {
        // ICMPv4: destination-unreachable (3, also carries PMTUD
        // "fragmentation needed" as code 4), time-exceeded (11),
        // parameter-problem (12).
        1 => matches!(icmp_type, 3 | 11 | 12),
        // ICMPv6 errors: destination-unreachable (1), packet-too-big (2,
        // PMTUD), time-exceeded (3), parameter-problem (4); PLUS the ND set:
        // RS (133), RA (134), NS (135), NA (136), Redirect (137).
        58 => matches!(icmp_type, 1 | 2 | 3 | 4 | 133 | 134 | 135 | 136 | 137),
        _ => false,
    }
}

/// Per-packet host-inbound admit check for a host-bound (local-delivery)
/// packet ingressing `ingress_zone_id`. Returns true (admit) when the packet is
/// an ICMP/ICMPv6 error/PMTUD control message (#3171 — always exempt, mirroring
/// the kernel chain), when the zone has no host-inbound stanza (absent from the
/// table — the admit-all default), or when the packet's service/protocol is in
/// the zone's set. Returns false (deny) only when the zone IS configured and the
/// packet matches nothing. `icmp_type` is the first L4 byte for ICMP/ICMPv6
/// packets and is ignored for every other protocol (pass 0).
pub(in crate::afxdp) fn host_inbound_admits(
    state: &ForwardingState,
    ingress_zone_id: u16,
    protocol: u8,
    dst_port: u16,
    is_v6: bool,
    icmp_type: u8,
) -> bool {
    // #3171/#3201/#3240: error/PMTUD control messages AND the IPv6 ND set are
    // admitted before the zone lookup so PMTUD / unreachable / traceroute-to-self
    // and v6 RS/RA work on a configured zone that omits `ping` / scopes
    // router-discovery, matching the kernel host-inbound chain's global accepts.
    // Echo-request and IPv4 router-advert/solicit are NOT in this set, so they
    // stay gated on the `ping` / `router-discovery` tokens below.
    if is_icmp_host_inbound_global_accept(protocol, icmp_type) {
        return true;
    }
    match state.zone_host_inbound.get(&ingress_zone_id) {
        None => true,
        Some(hi) => hi.admits(protocol, dst_port, is_v6, icmp_type),
    }
}
