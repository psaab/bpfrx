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
//! Default posture (#3405 — Junos/vSRX default-deny parity): EVERY configured
//! security zone is enforced. The Go control plane marks every zone
//! `host_inbound_configured == true` (`ZoneSnapshot::host_inbound_configured`),
//! so a zone with NO `host-inbound-traffic` stanza arrives with EMPTY token
//! sets and is inserted into `ForwardingState::zone_host_inbound` with an empty
//! [`ZoneHostInbound`] — `admits()` then returns false for every
//! service/protocol, i.e. default-deny, identical to an empty
//! `host-inbound-traffic { }` stanza. Before #3405 a no-stanza zone was absent
//! from the map and `host_inbound_admits` returned admit (`None => true`), a
//! permit-all management-plane exposure on any zone the operator never locked
//! down. The `None => true` arm now applies ONLY to a genuinely unknown / global
//! ingress zone (e.g. id 0), never to a configured zone. The global
//! ICMP/ND/PMTUD accepts (`is_icmp_host_inbound_global_accept`, #3171) still
//! precede the per-zone deny, and lifeline interfaces (fxp0/em0/fab*) never
//! reach this AF_XDP local-delivery classifier (their host-bound traffic is
//! served by the kernel, which excludes them from the deny address sets), so the
//! default-deny cannot strand management or break HA.
//!
//! The authoritative operator-facing token->port matrix across all three
//! surfaces (the Go SSOT allowlist, the nft kernel mirror, and this Rust
//! classifier) -- including the deliberate narrowings (sip UDP+TCP 5060 only,
//! tftp UDP 69 only, traceroute UDP-only, router-discovery v6 global,
//! ipsec=ike alias) and the ident-reset divergence -- lives in
//! docs/host-inbound-service-matrix.md (#3619).

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

/// Build the per-zone host-inbound admission table from the snapshot. Since
/// #3722 `populate_zones` inserts an entry for EVERY known security zone
/// regardless of `host_inbound_configured` — a no-stanza / nil / unconfigured
/// zone arrives with empty token sets -> empty `ZoneHostInbound` -> default-deny
/// (fail-closed). `host_inbound_configured` now only selects WHICH tokens a zone
/// admits (the #3405 no-stanza-vs-configured distinction), never WHETHER the
/// zone is enforced — a missing table entry means only a genuinely unknown /
/// global (id 0) ingress zone, which the classifier admits by design. The zone
/// id used as the key MUST be the same validated id `populate_zones` accepted
/// (caller passes it), so the two maps stay aligned.
pub(in crate::afxdp) fn zone_host_inbound_from_snapshot(zone: &ZoneSnapshot) -> ZoneHostInbound {
    zone_host_inbound_from_tokens(
        &zone.host_inbound_system_services,
        &zone.host_inbound_protocols,
    )
}

/// #3362: build a [`ZoneHostInbound`] from raw Junos host-inbound token slices.
/// Shared by the zone-level path ([`zone_host_inbound_from_snapshot`]) and the
/// per-interface OVERRIDE path (`InterfaceSnapshot.host_inbound_*`), so the two
/// classify identically. The interface-level token set carried on the wire is
/// already the EFFECTIVE union (zone ∪ interface) computed in Go, so this just
/// classifies it as-is.
pub(in crate::afxdp) fn zone_host_inbound_from_tokens(
    services: &[String],
    protocols: &[String],
) -> ZoneHostInbound {
    let mut hi = ZoneHostInbound::default();
    for svc in services {
        classify_system_service(svc.trim().to_ascii_lowercase().as_str(), &mut hi);
    }
    for proto in protocols {
        classify_protocol(proto.trim().to_ascii_lowercase().as_str(), &mut hi);
    }
    hi
}

/// Classify one Junos `system-services` token into the admission set.
/// Unrecognised tokens are intentionally ignored (fail-closed: they do not
/// broaden admit). Covers the common Junos service set; the repo configs use
/// {all, ssh, ping, dhcp, dhcpv6, gre} and this is a comprehensive superset.
///
/// The recognized token set here is a SECURITY allowlist and MUST stay in
/// lockstep with the Go SSOT config.KnownHostInboundSystemServices (#3200). A
/// Go parity test (config.TestHostInboundRustClassifierMatchesGoSSOT, #3486)
/// parses these match arms and fails the build if a token is added/removed on
/// only one side. Adding a service here without adding it to the Go SSOT (or
/// vice versa) turns that test RED.
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
        // #3310: Junos `system-services ident-reset` does NOT permit the ident
        // (auth/TCP-113) service — it actively RESETS inbound ident probes. The
        // PRIMARY enforcement path for direct host-bound traffic to an interface
        // IP / VRRP VIP is the kernel nft chain (the XDP shim shunts such
        // traffic to the kernel before userspace-dp sees it), which emits a
        // `reject with tcp reset` for TCP/113 (`hostInboundServiceAction`,
        // pkg/daemon/daemon_nft.go). This AF_XDP local-delivery classifier is
        // the SECONDARY edge-case path (reached only by DNAT/static-NAT-to-113,
        // an edge of an edge). It must NOT admit 113 — so this arm contributes
        // NOTHING to the admit set, and `admits()` returns false for TCP/113,
        // dropping the rare AF_XDP-reached ident packet (a documented
        // divergence from the kernel reset; strictly better than the prior plain
        // admit). The explicit arm is kept (rather than falling into `_ => {}`)
        // so the token stays recognized by the Go<->Rust parity test
        // (config.TestHostInboundRustClassifierMatchesGoSSOT) and so a future
        // secondary-path RST upgrade (plan Option A) has an obvious home.
        "ident-reset" => {}
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

/// Every recognized `protocols` token (mirror of the Go SSOT
/// config.KnownHostInboundProtocols minus the `all` meta-token). The
/// `protocols all` expansion is derived from this list MINUS the L2/non-IP set
/// (HOST_INBOUND_L2_PROTOCOLS) — see `routing_protocol_all_expansion`. Listing
/// IS-IS here (and excluding it via the L2 set) is what makes the L2 set
/// load-bearing on this surface (#3311): adding a new L2 protocol means adding
/// it to both lists, after which it is automatically kept out of the IP `all`
/// expansion with no edit to the expansion logic.
const KNOWN_ROUTING_PROTOCOL_TOKENS: &[&str] = &[
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
    // #3341: additional Junos/vSRX routing-control protocols. All ride IP, so
    // each contributes a concrete IP admit in classify_protocol: rsvp (proto 46,
    // dual), pgm (proto 113, dual), sap (UDP/9875, dual), dvmrp (proto 2 / IGMP,
    // IPv4-only). Mirror of config.KnownHostInboundProtocols.
    "rsvp",
    "pgm",
    "sap",
    "dvmrp",
    // #3311: IS-IS is a recognized protocol but rides L2 (OSI/CLNP), so it is
    // EXCLUDED from the IP `all` expansion below via HOST_INBOUND_L2_PROTOCOLS.
    "isis",
];

/// L2/non-IP host-inbound protocols — the Rust mirror of the Go SSOT
/// config.HostInboundL2Protocols (#3311). These ride directly over L2
/// (OSI/CLNP / LLC) and cannot be expressed as an IP host-inbound match, so
/// they are excluded from the `protocols all` IP expansion and contribute no
/// per-token IP admit. Keep in lockstep with the Go set (a Go parity intent +
/// the protocols_all_excludes_l2 test below guard this).
const HOST_INBOUND_L2_PROTOCOLS: &[&str] = &["isis"];

/// True if `token` is an L2/non-IP host-inbound protocol (excluded from the IP
/// `protocols all` expansion). #3311.
fn is_host_inbound_l2_protocol(token: &str) -> bool {
    HOST_INBOUND_L2_PROTOCOLS.contains(&token)
}

/// The routing-protocol tokens that `protocols all` expands to (#3199), derived
/// from KNOWN_ROUTING_PROTOCOL_TOKENS MINUS the L2/non-IP set (#3311). In Junos
/// `host-inbound-traffic protocols all` admits every supported ROUTING protocol
/// — NOT every system-service and NOT a blanket bypass. Expanding to a concrete
/// IP set (rather than a short-circuit admit) keeps a `protocols all` zone from
/// opening SSH/HTTPS/SNMP/NETCONF on the box; excluding L2 protocols keeps it
/// from listing a token that can produce no IP admit. ospf3 aliases ospf; the
/// caller dedups.
fn routing_protocol_all_expansion() -> impl Iterator<Item = &'static str> {
    KNOWN_ROUTING_PROTOCOL_TOKENS
        .iter()
        .copied()
        .filter(|t| !is_host_inbound_l2_protocol(t))
}

/// Classify one Junos `protocols` (routing-protocol) token. Port-based
/// protocols (bgp/ldp/msdp/rip) contribute TCP/UDP ports; IP-protocol-based
/// ones (ospf/pim/igmp/vrrp) contribute a protocol number; router-discovery is
/// ICMP/ICMPv6.
fn classify_protocol(token: &str, hi: &mut ZoneHostInbound) {
    match token {
        // `protocols all` admits only the routing-protocol set (#3199) — it
        // expands to every recognized routing protocol EXCEPT L2/non-IP ones
        // (IS-IS), via routing_protocol_all_expansion (= KNOWN_ROUTING_PROTOCOL_
        // TOKENS minus HOST_INBOUND_L2_PROTOCOLS, #3311), NOT system services
        // and NOT a blanket accept. The expansion never yields "all", so this
        // recursion terminates. Mirrors the Go nft `all` case, which derives the
        // same exclusion from config.HostInboundAllExpansionProtocols().
        "all" => {
            for tok in routing_protocol_all_expansion() {
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
        // #3341: RSVP rides directly over IP, protocol 46 (dual-family).
        "rsvp" => {
            hi.ip_protocols.insert(46);
        }
        // #3341: PGM (Pragmatic General Multicast) rides over IP, protocol 113
        // (dual-family).
        "pgm" => {
            hi.ip_protocols.insert(113);
        }
        // #3341: SAP (Session Announcement Protocol) is UDP/9875 (dual-family).
        "sap" => {
            hi.udp_ports.insert(9875);
        }
        // #3341: DVMRP is carried inside IGMP (IP protocol 2) and is an IPv4-only
        // multicast routing protocol (SSOT: config.HostInboundProtocolFamily
        // ["dvmrp"]="ip"), so it admits proto 2 on v4 only — matching igmp.
        "dvmrp" => {
            hi.ip_protocols_v4.insert(2);
        }
        // #3311: IS-IS rides OSI/CLNP directly over L2 (LLC-encapsulated, NOT
        // IP), so it cannot be expressed in this IP-keyed admit model (proto
        // number / TCP-UDP port / ICMP type). It is a recognized-but-no-op
        // host-inbound token (Go SSOT: config.HostInboundL2Protocols; Rust
        // mirror: HOST_INBOUND_L2_PROTOCOLS): the kernel delivers IS-IS PDUs to
        // FRR's isisd via an LLC packet socket, outside the IP host-inbound
        // filter (and the AF_XDP local-delivery path only ever classifies IP
        // packets). This explicit arm is DOCUMENTARY — the catch-all `_ => {}`
        // would no-op identically. The L2 set's load-bearing job is the
        // `protocols all` exclusion above (routing_protocol_all_expansion),
        // which is what the protocols_all_excludes_l2 test guards.
        "isis" => {}
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
/// the kernel chain), when the ingress zone is genuinely unknown / global (id
/// not in the table — see below), or when the packet's service/protocol is in
/// the zone's admission set. Returns false (deny) when the zone IS configured
/// and the packet matches nothing — which, since #3405, includes every
/// configured security zone with no `host-inbound-traffic` stanza (it arrives
/// with an empty set -> default-deny). `icmp_type` is the first L4 byte for
/// ICMP/ICMPv6 packets and is ignored for every other protocol (pass 0).
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
        // #3405: every configured security zone is in the table (the Go control
        // plane marks them all `host_inbound_configured`), so `None` is now only
        // a genuinely unknown / global ingress zone (e.g. id 0, no resolved
        // security zone). Such traffic keeps the admit default — narrowing it is
        // out of scope for the configured-zone default-deny fix and risks
        // breaking ND / control delivery on the global context.
        None => true,
        // A configured zone — including one with no `host-inbound-traffic` stanza
        // (empty set) — denies anything its set does not admit (#3405).
        Some(hi) => hi.admits(protocol, dst_port, is_v6, icmp_type),
    }
}

/// #3362: per-packet host-inbound admit keyed by INGRESS INTERFACE first. When
/// the ingress interface carries a per-interface host-inbound OVERRIDE
/// (`state.ifindex_host_inbound`), the packet is matched against that interface's
/// EFFECTIVE admission set (zone ∪ interface, pre-unioned in Go); otherwise it
/// falls back to the zone-keyed [`host_inbound_admits`]. The global
/// ICMP/PMTUD/ND accept (#3171) is applied first in BOTH branches so error / ND
/// delivery is never broken by a scoped override. This is the entry point the
/// local-delivery poll path uses; `host_inbound_admits` stays the zone-only
/// primitive (and the direct test target).
#[allow(clippy::too_many_arguments)]
pub(in crate::afxdp) fn host_inbound_admits_iface(
    state: &ForwardingState,
    ingress_ifindex: i32,
    ingress_zone_id: u16,
    protocol: u8,
    dst_port: u16,
    is_v6: bool,
    icmp_type: u8,
) -> bool {
    if let Some(hi) = state.ifindex_host_inbound.get(&ingress_ifindex) {
        if is_icmp_host_inbound_global_accept(protocol, icmp_type) {
            return true;
        }
        return hi.admits(protocol, dst_port, is_v6, icmp_type);
    }
    host_inbound_admits(state, ingress_zone_id, protocol, dst_port, is_v6, icmp_type)
}

#[cfg(test)]
mod tests {
    use super::*;

    // #3405: a CONFIGURED zone with an EMPTY admission set (the on-wire shape of a
    // security zone that declared no `host-inbound-traffic` stanza — the Go
    // control plane now marks every zone host_inbound_configured) must
    // default-DENY every host-bound service/protocol, while the global
    // ICMP/ND/PMTUD accept still admits error/PMTUD control. This pins the
    // load-bearing Rust half of the #3405 default-deny: `Some(empty) => deny`,
    // NOT the pre-#3405 admit. Fail-on-revert: change the `Some(hi)` arm of
    // host_inbound_admits to admit when the set is empty (or special-case an
    // empty zone back to admit) and the SSH assertion below flips RED.
    #[test]
    fn empty_configured_zone_default_denies() {
        const TCP: u8 = 6;
        const ZONE: u16 = 7;

        let mut state = ForwardingState::default();
        // A configured zone with NO tokens = the no-stanza / empty-stanza shape.
        state
            .zone_host_inbound
            .insert(ZONE, zone_host_inbound_from_tokens(&[], &[]));

        // SSH (tcp/22) to the host on this zone is DENIED — the zone opened
        // nothing. (Pre-#3405 a no-stanza zone was absent from the table and this
        // returned admit via `None => true`.)
        assert!(
            !host_inbound_admits(&state, ZONE, TCP, 22, false, 0),
            "empty configured zone must deny ssh (tcp/22) — #3405 default-deny",
        );
        // HTTPS (tcp/443) and an arbitrary UDP service are likewise denied.
        assert!(
            !host_inbound_admits(&state, ZONE, TCP, 443, false, 0),
            "empty configured zone must deny https (tcp/443)",
        );
        assert!(
            !host_inbound_admits(&state, ZONE, 17, 53, true, 0),
            "empty configured zone must deny udp/53 on v6",
        );

        // The global ICMP error/PMTUD accept (#3171) still fires: v4
        // destination-unreachable (type 3) and v6 packet-too-big (type 2) reach
        // the host even on a default-deny zone, so PMTUD is never black-holed.
        assert!(
            host_inbound_admits(&state, ZONE, 1, 0, false, 3),
            "ICMPv4 destination-unreachable must stay globally admitted",
        );
        assert!(
            host_inbound_admits(&state, ZONE, 58, 0, true, 2),
            "ICMPv6 packet-too-big (PMTUD) must stay globally admitted",
        );

        // A genuinely unknown / global ingress zone (id not in the table) keeps
        // the admit default — #3405 is scoped to configured zones only.
        assert!(
            host_inbound_admits(&state, 999, TCP, 22, false, 0),
            "unknown/global zone (absent from table) keeps the admit default",
        );
    }

    // #3310: `system-services ident-reset` must NOT admit TCP/113 on the AF_XDP
    // secondary path — Junos ident-reset resets ident probes, it does not permit
    // the service. The kernel nft chain emits the actual `reject with tcp reset`
    // (primary path); this classifier just stops admitting 113 so the rare
    // AF_XDP-reached ident packet (DNAT/static-NAT-to-113) is dropped. Co-declared
    // services on the SAME zone (ssh/http) must still admit (no over-removal), and
    // UDP/113 (not ident) is likewise not admitted. Fail-on-revert: restore
    // `hi.tcp_ports.insert(113)` in the ident-reset classifier arm and the
    // tcp/113-denied assertion flips RED.
    #[test]
    fn ident_reset_does_not_admit_113() {
        const TCP: u8 = 6;
        const UDP: u8 = 17;
        const ZONE: u16 = 11;

        let mut state = ForwardingState::default();
        // A zone that declares ident-reset ALONGSIDE ssh + http (so the test
        // proves ident-reset removes ONLY 113, not the co-declared services —
        // ssh/http admit only from their own classifier arms).
        state.zone_host_inbound.insert(
            ZONE,
            zone_host_inbound_from_tokens(
                &[
                    "ident-reset".to_string(),
                    "ssh".to_string(),
                    "http".to_string(),
                ],
                &[],
            ),
        );

        // TCP/113 is NOT admitted (dropped on the secondary path), v4 and v6.
        assert!(
            !host_inbound_admits(&state, ZONE, TCP, 113, false, 0),
            "ident-reset must NOT admit TCP/113 on v4 (#3310) — it resets, not permits",
        );
        assert!(
            !host_inbound_admits(&state, ZONE, TCP, 113, true, 0),
            "ident-reset must NOT admit TCP/113 on v6 (#3310)",
        );
        // UDP/113 (not ident) is not admitted either.
        assert!(
            !host_inbound_admits(&state, ZONE, UDP, 113, false, 0),
            "UDP/113 must not be admitted (ident is TCP-only)",
        );
        // The co-declared services on the same zone still admit (no over-removal).
        assert!(
            host_inbound_admits(&state, ZONE, TCP, 22, false, 0),
            "co-declared ssh (tcp/22) must still admit",
        );
        assert!(
            host_inbound_admits(&state, ZONE, TCP, 80, false, 0),
            "co-declared http (tcp/80) must still admit",
        );
    }

    // #3311: the `protocols all` expansion must EXCLUDE every L2/non-IP protocol
    // (IS-IS) — they cannot produce an IP host-inbound admit and are handled by
    // FRR over L2. This guards the SSOT-driven exclusion
    // (routing_protocol_all_expansion = KNOWN_ROUTING_PROTOCOL_TOKENS minus
    // HOST_INBOUND_L2_PROTOCOLS), the load-bearing job of the L2 set on this
    // surface. Fail-on-revert: remove "isis" from HOST_INBOUND_L2_PROTOCOLS and
    // isis (still in KNOWN_ROUTING_PROTOCOL_TOKENS) reappears in the expansion,
    // turning the exclusion assertion RED. Mirrors the Go
    // TestHostInboundProtocolsAllExcludesL2.
    #[test]
    fn protocols_all_excludes_l2() {
        let expansion: Vec<&str> = routing_protocol_all_expansion().collect();

        // Every L2 protocol is excluded from the IP `all` expansion.
        for l2 in HOST_INBOUND_L2_PROTOCOLS {
            assert!(
                !expansion.contains(l2),
                "L2 protocol {l2:?} must be excluded from the `protocols all` IP expansion",
            );
        }
        // IS-IS specifically: a recognized routing token that is nonetheless
        // kept out of the expansion BECAUSE it is in the L2 set.
        assert!(
            KNOWN_ROUTING_PROTOCOL_TOKENS.contains(&"isis"),
            "isis must be a recognized routing token (so the exclusion is meaningful)",
        );
        assert!(
            !expansion.contains(&"isis"),
            "isis (L2) must not appear in the `protocols all` IP expansion",
        );
        // Sanity: real IP routing protocols still expand.
        for p in ["ospf", "ospf3", "bgp", "bfd", "router-discovery"] {
            assert!(
                expansion.contains(&p),
                "IP routing protocol {p:?} must remain in the `protocols all` expansion",
            );
        }
    }

    // #3362: the per-interface host-inbound OVERRIDE keys the admit check by
    // ingress ifindex. An interface with an override is matched against ITS
    // effective set; an interface without one falls back to the from-zone set.
    // Fail-on-revert: make host_inbound_admits_iface ignore ifindex_host_inbound
    // (i.e. always defer to the zone) and the override-scoped assertions flip.
    #[test]
    fn per_interface_override_keys_by_ifindex() {
        const TCP: u8 = 6;
        const IFINDEX_UPLINK: i32 = 100; // ssh override
        const IFINDEX_OTHER: i32 = 200; // no override (zone fallback)
        const ZONE: u16 = 5; // zone-keyed set = ping only

        let mut state = ForwardingState::default();
        // Zone-level set: ping (ICMP echo) only — NO ssh.
        state.zone_host_inbound.insert(
            ZONE,
            zone_host_inbound_from_tokens(&["ping".to_string()], &[]),
        );
        // Per-interface override on the uplink: ssh only.
        state.ifindex_host_inbound.insert(
            IFINDEX_UPLINK,
            zone_host_inbound_from_tokens(&["ssh".to_string()], &[]),
        );

        // Uplink (override present): admits ssh, denies https, and does NOT
        // inherit the zone's ping (the override REPLACES the zone set on this
        // interface — its set is the Go-side effective union).
        assert!(
            host_inbound_admits_iface(&state, IFINDEX_UPLINK, ZONE, TCP, 22, false, 0),
            "uplink override must admit ssh (tcp/22)",
        );
        assert!(
            !host_inbound_admits_iface(&state, IFINDEX_UPLINK, ZONE, TCP, 443, false, 0),
            "uplink override (ssh only) must deny https (tcp/443)",
        );

        // Other interface (no override): falls back to the zone set — denies ssh,
        // admits the zone's ping echo-request (icmp v4 type 8).
        assert!(
            !host_inbound_admits_iface(&state, IFINDEX_OTHER, ZONE, TCP, 22, false, 0),
            "non-overridden interface must fall back to the zone set (no ssh)",
        );
        assert!(
            host_inbound_admits_iface(&state, IFINDEX_OTHER, ZONE, 1, 0, false, 8),
            "non-overridden interface must inherit the zone's ping admit",
        );

        // Global ICMP error/PMTUD accept (#3171) still applies on the override
        // path: destination-unreachable (v4 type 3) is admitted even though the
        // override set is ssh-only.
        assert!(
            host_inbound_admits_iface(&state, IFINDEX_UPLINK, ZONE, 1, 0, false, 3),
            "ICMP error/PMTUD must stay globally admitted on the override path",
        );
    }

    // #3311: a zone with `protocols all` must NOT admit IS-IS as an IP protocol
    // (proto 124, integrated IS-IS-over-IP), proving the L2 exclusion holds end
    // to end through classify_protocol. It must still admit a real expanded IP
    // protocol (OSPF, proto 89). Fail-on-revert: remove isis from
    // HOST_INBOUND_L2_PROTOCOLS — isis enters the expansion, but its
    // classify_protocol arm is a no-op, so this stays green; the
    // protocols_all_excludes_l2 token test above is the real RED-on-revert guard.
    // #3341: the routing-control tokens rsvp/pgm/sap/dvmrp must each classify to
    // the correct IP admit with the correct family scoping, mirroring the nft
    // matcher (hostInboundProtocolMatches) and the Go SSOT. Fail-on-revert:
    // before #3341 these hit the catch-all `_ => {}` no-op arm, so every admit
    // assertion below goes RED.
    #[test]
    fn routing_control_protocol_tokens_classify() {
        // rsvp — IP proto 46, dual-family.
        let mut hi = ZoneHostInbound::default();
        classify_protocol("rsvp", &mut hi);
        assert!(hi.admits(46, 0, false, 0), "rsvp must admit proto 46 on v4");
        assert!(hi.admits(46, 0, true, 0), "rsvp must admit proto 46 on v6 (dual)");

        // pgm — IP proto 113, dual-family.
        let mut hi = ZoneHostInbound::default();
        classify_protocol("pgm", &mut hi);
        assert!(hi.admits(113, 0, false, 0), "pgm must admit proto 113 on v4");
        assert!(hi.admits(113, 0, true, 0), "pgm must admit proto 113 on v6 (dual)");

        // sap — UDP/9875, dual-family.
        let mut hi = ZoneHostInbound::default();
        classify_protocol("sap", &mut hi);
        assert!(hi.admits(17, 9875, false, 0), "sap must admit udp/9875 on v4");
        assert!(hi.admits(17, 9875, true, 0), "sap must admit udp/9875 on v6 (dual)");

        // dvmrp — IGMP-encapsulated (proto 2), IPv4-only.
        let mut hi = ZoneHostInbound::default();
        classify_protocol("dvmrp", &mut hi);
        assert!(hi.admits(2, 0, false, 0), "dvmrp must admit proto 2 (IGMP) on v4");
        assert!(
            !hi.admits(2, 0, true, 0),
            "dvmrp must NOT admit proto 2 on v6 (IPv4-only)",
        );

        // All four are recognized routing tokens (so `protocols all` covers them)
        // and none are L2.
        for tok in ["rsvp", "pgm", "sap", "dvmrp"] {
            assert!(
                KNOWN_ROUTING_PROTOCOL_TOKENS.contains(&tok),
                "{tok} must be a recognized routing token",
            );
            assert!(
                !is_host_inbound_l2_protocol(tok),
                "{tok} rides IP, must not be an L2 protocol",
            );
        }
    }

    #[test]
    fn protocols_all_admits_ip_routing_not_l2() {
        let mut hi = ZoneHostInbound::default();
        classify_protocol("all", &mut hi);
        // OSPFv2 (proto 89) admitted on v4 via the expansion.
        assert!(
            hi.admits(89, 0, false, 0),
            "`protocols all` must admit OSPF (proto 89) on v4",
        );
        // Integrated IS-IS-over-IP (proto 124) is NOT admitted — isis is L2.
        assert!(
            !hi.admits(124, 0, false, 0),
            "`protocols all` must not admit IS-IS (proto 124) — L2/OSI, handled by FRR",
        );
    }
}
