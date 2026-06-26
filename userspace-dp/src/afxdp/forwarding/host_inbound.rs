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
        "ping" => {
            hi.icmp = true;
            hi.icmpv6 = true;
        }
        "dns" => {
            hi.udp_ports.insert(53);
            hi.tcp_ports.insert(53);
        }
        // dhcp server listens on udp/67; client replies arrive on udp/68. Admit
        // both so a `dhcp-local-server` on the zone interface works.
        "dhcp" | "bootp" => {
            hi.udp_ports.insert(67);
            hi.udp_ports.insert(68);
        }
        "dhcpv6" => {
            hi.udp_ports.insert(546);
            hi.udp_ports.insert(547);
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
    "ospf",
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
        "ospf" | "ospf3" => {
            hi.ip_protocols.insert(89);
        }
        "bgp" => {
            hi.tcp_ports.insert(179);
        }
        "rip" => {
            hi.udp_ports.insert(520);
        }
        "ripng" => {
            hi.udp_ports.insert(521);
        }
        "igmp" => {
            hi.ip_protocols.insert(2);
        }
        "pim" => {
            hi.ip_protocols.insert(103);
        }
        "vrrp" => {
            hi.ip_protocols.insert(112);
        }
        "bfd" => {
            hi.udp_ports.insert(3784);
            hi.udp_ports.insert(3785);
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
        // router-discovery is ICMP router solicitation/advertisement (v4) and
        // ND RS/RA (v6). Admit ICMP/ICMPv6 at the protocol granularity.
        "router-discovery" => {
            hi.icmp = true;
            hi.icmpv6 = true;
        }
        // Unknown / unmapped protocol token: ignore (fail-closed).
        _ => {}
    }
}

/// #3171: ICMP/ICMPv6 error (control) message subtypes that the host-inbound
/// layer admits UNCONDITIONALLY — regardless of whether the ingress zone lists
/// `ping` — so the userspace LocalDelivery classifier matches the kernel
/// host-inbound chain's global ICMP-error accept (`pkg/daemon/daemon_nft.go`:
/// `icmp type { destination-unreachable, time-exceeded, parameter-problem }`
/// and `icmpv6 type { 1, 2, 3, 4, 133..137 }`). These carry PMTUD / unreachable
/// / traceroute-to-self signalling that must reach a firewall-local address
/// (e.g. a DNAT-to-self embedded ICMP error landing on the XSK) even on a
/// configured ping-less zone. Without this exemption the userspace path dropped
/// them while the kernel chain accepted them — a fail-toward-drop edge and the
/// doc-vs-behavior inconsistency #3070's README flagged for embedded-ICMP.
///
/// This set is deliberately NARROWER than `icmp::is_icmp_error` (the
/// embedded-NAT reversal set, which also includes v4 Source Quench (4) and
/// Redirect (5)): Source Quench is deprecated (RFC 6633) and Redirect is
/// link-scoped — neither is a control message we admit to the host. ECHO
/// REQUEST (v4 type 8 / v6 type 128) is NOT here: it stays gated on the `ping`
/// system-service, so a ping-less zone still drops echo.
///
/// Keep this set in lock-step with the kernel chain in
/// `pkg/daemon/daemon_nft.go` and its
/// `TestHostInboundFilterExemptsIPsecAndV6Errors` accept assertions.
fn is_icmp_host_inbound_error(protocol: u8, icmp_type: u8) -> bool {
    match protocol {
        // ICMPv4: destination-unreachable (3, also carries PMTUD
        // "fragmentation needed" as code 4), time-exceeded (11),
        // parameter-problem (12).
        1 => matches!(icmp_type, 3 | 11 | 12),
        // ICMPv6: destination-unreachable (1), packet-too-big (2, PMTUD),
        // time-exceeded (3), parameter-problem (4).
        58 => matches!(icmp_type, 1 | 2 | 3 | 4),
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
    // #3171: error/PMTUD control messages are admitted before the zone lookup
    // so PMTUD / unreachable / traceroute-to-self works on a configured zone
    // that omits `ping`, matching the kernel host-inbound chain. Echo-request is
    // not in this set, so it stays gated on the `ping` system-service below.
    if is_icmp_host_inbound_error(protocol, icmp_type) {
        return true;
    }
    match state.zone_host_inbound.get(&ingress_zone_id) {
        None => true,
        Some(hi) => hi.admits(protocol, dst_port, is_v6),
    }
}
