package config

import (
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/webmgmt"
)

// host_inbound_tokens.go is the single source of truth (SSOT) for the set of
// recognized `security zones <z> host-inbound-traffic { system-services ...;
// protocols ...; }` tokens (#3200).
//
// Three independent layers must agree on which tokens are meaningful:
//
//  1. commit-time validation (validateHostInboundTokensStrict, this package),
//  2. the nftables KERNEL mirror that enforces host-inbound on the kernel input
//     hook (pkg/daemon hostInboundServiceMatches / hostInboundProtocolMatches),
//  3. the Rust AF_XDP classifier on the XSK local-delivery subset
//     (userspace-dp/src/afxdp/forwarding/host_inbound.rs
//     classify_system_service / classify_protocol).
//
// Before #3200 the schema declared system-services / protocols as untyped
// containers and the compiler copied every child token verbatim with no
// validation. A typo such as `system-services sssh` then committed cleanly and
// the two enforcement layers DISAGREED: the nft builder emitted no match for the
// unknown token and (for a stanza whose tokens were all unrecognized) fell
// OPEN, while the Rust classifier ignored the unknown token and so denied
// everything the zone did not explicitly admit — fail CLOSED. One typo silently
// produced a split-brain security posture.
//
// The fix makes unknown tokens fail at commit (strict) / warn on the tolerant
// load path (lenient, #1960 no-brick) so the runtime only ever sees a known
// token, and both enforcement layers therefore agree. The pkg/daemon nft
// matchers reference these sets for a parity test
// (TestHostInboundNftMatchesKnownTokens); the Rust classifier mirrors them and
// is held in lockstep by a Go parity test that parses host_inbound.rs and
// asserts its token sets EXACTLY equal these maps
// (TestHostInboundRustClassifierMatchesGoSSOT, #3486 — add a token to one side
// only and it goes RED). Tokens are matched
// case-sensitively against the canonical lowercase spellings. At runtime BOTH
// layers normalize case (the nft path lowercases via lowerTokens before its
// switch; the Rust classifier lowercases too), so a wrong-case token would in
// fact enforce identically on both — there is no runtime split-brain. We still
// reject wrong-case at commit for Junos-parity/typo-hygiene: Junos host-inbound
// keywords are lowercase-canonical, so wrong-case input is a typo worth flagging
// (lenient load only warns, so a persisted/sync'd config is never bricked).

// The authoritative operator-facing token->port matrix across all three
// surfaces (this SSOT allowlist, the nft kernel mirror, and the Rust AF_XDP
// classifier), including the deliberate narrowings (sip UDP+TCP 5060 only,
// tftp UDP 69 only, traceroute UDP-only, router-discovery v6 global,
// ipsec=ike alias) and the ident-reset divergence, is documented in
// docs/host-inbound-service-matrix.md (#3619).

// KnownHostInboundSystemServices is the canonical set of recognized
// host-inbound-traffic `system-services` tokens, including documented aliases
// (`webapi-clear-text`/`http`, `netconf-ssh`/`ssh-netconf`, `rlogin`/`r-login`,
// etc.) and the full-admit tokens `all` / `any-service`. Keep in lockstep with
// pkg/daemon hostInboundServiceMatches + hostInboundAllowsAll and the Rust
// classify_system_service.
var KnownHostInboundSystemServices = map[string]bool{
	"all":               true,
	"any-service":       true,
	"ssh":               true,
	"telnet":            true,
	"ftp":               true,
	"http":              true,
	"webapi-clear-text": true,
	"https":             true,
	"webapi-ssl":        true,
	"ping":              true,
	"dns":               true,
	"dhcp":              true,
	"bootp":             true,
	"dhcpv6":            true,
	"ntp":               true,
	"snmp":              true,
	"snmp-trap":         true,
	"ike":               true,
	"ipsec":             true,
	"tftp":              true,
	"netconf":           true,
	"ssh-netconf":       true,
	"netconf-ssh":       true,
	"finger":            true,
	"ident-reset":       true,
	"lsping":            true,
	"sip":               true,
	"r-login":           true,
	"rlogin":            true,
	"r-sh":              true,
	"rsh":               true,
	"r-exec":            true,
	"rexec":             true,
	"xnm-clear-text":    true,
	"xnm-ssl":           true,
	"traceroute":        true,
	// #3226 fold: four services Juniper documents on BOTH host-inbound
	// reference pages (`system-services (Security Zones Host Inbound Traffic)`
	// and `system-services (Security Zones Interfaces)`) that xpf did not
	// recognize at all. Their absence was a #3200-class parity gap on its own —
	// a valid vSRX `system-services r2cp` was hard-rejected at commit — and
	// #3226 made it load-bearing: scoping `all` to the recognized set meant an
	// authored `all` stopped admitting them AND the operator could not restore
	// them by naming the service, because strict validation rejects any token
	// outside this map. Ports are the Juniper-documented defaults:
	//   r2cp           — Radio Router Control Protocol, UDP 28762 (the
	//                    `server-port` default at [edit protocols r2cp]).
	//   reverse-telnet — console-server reverse Telnet, TCP 2900.
	//   reverse-ssh    — console-server reverse SSH, TCP 2901.
	//   rpm            — Real-time Performance Monitoring probe RECEIVER; the
	//                    `[edit services rpm probe-server]` tcp/udp port is
	//                    "7 or 49160 through 65535", so 7 (UDP-ECHO) is the
	//                    only fixed port and is what this admits on both L4s.
	"r2cp":           true,
	"reverse-ssh":    true,
	"reverse-telnet": true,
	"rpm":            true,
	"gre":            true,
}

// KnownHostInboundProtocols is the canonical set of recognized
// host-inbound-traffic `protocols` (routing-protocol) tokens, including `all`
// (which expands to the routing-protocol set, #3199) and the `ospf3` alias of
// `ospf`. Keep in lockstep with pkg/daemon hostInboundProtocolMatches and the
// Rust classify_protocol + KNOWN_ROUTING_PROTOCOL_TOKENS. The `protocols all`
// expansion is derived from this set via HostInboundAllExpansionProtocols
// (minus HostInboundL2Protocols).
var KnownHostInboundProtocols = map[string]bool{
	"all":              true,
	"ospf":             true,
	"ospf3":            true,
	"bgp":              true,
	"rip":              true,
	"ripng":            true,
	"igmp":             true,
	"pim":              true,
	"vrrp":             true,
	"bfd":              true,
	"ldp":              true,
	"msdp":             true,
	"nhrp":             true,
	"router-discovery": true,
	// #3341: additional routing-control protocols Junos/vSRX accepts under
	// host-inbound-traffic. All ride IP (none are L2), so each maps to a
	// concrete IP host-inbound match on both enforcement surfaces:
	//   rsvp  — Resource Reservation Protocol, IP protocol 46 (dual-family).
	//   pgm   — Pragmatic General Multicast, IP protocol 113 (dual-family).
	//   sap   — Session Announcement Protocol, UDP/9875 (dual-family).
	//   dvmrp — Distance Vector Multicast Routing Protocol, carried inside IGMP
	//           (IP protocol 2) and IPv4-only (see HostInboundProtocolFamily).
	// Before #3341 these were absent, so since #3200 made tokens typed a valid
	// vSRX config naming them was hard-rejected at commit. Keep in lockstep with
	// pkg/daemon hostInboundProtocolMatches and the Rust classify_protocol +
	// KNOWN_ROUTING_PROTOCOL_TOKENS.
	"rsvp":  true,
	"pgm":   true,
	"sap":   true,
	"dvmrp": true,
	// #3311: IS-IS is a recognized host-inbound protocol for vSRX parity, but
	// it rides OSI/CLNP directly over L2 (LLC-encapsulated, NOT IP) — see
	// HostInboundL2Protocols below. It admits at commit yet produces NO IP
	// host-inbound match on either enforcement surface (the kernel delivers
	// IS-IS PDUs to FRR's isisd via an LLC packet socket, outside the IP
	// host-inbound filter). Before #3311 it was hard-rejected at commit even
	// though IS-IS routing is supported via FRR — a fail-closed parity gap.
	"isis": true,
}

// HostInboundL2Protocols is the set of recognized `protocols` tokens that ride
// directly over L2 (OSI/CLNP / LLC encapsulation) rather than IP, and so cannot
// be expressed as an IP host-inbound match (a protocol number, a TCP/UDP port,
// or an ICMP type) on EITHER enforcement surface — the nftables `ip`/`ip6`
// input chains and the Rust AF_XDP IP-keyed classifier. A token in this set is
// VALID at commit (vSRX parity) but is a deliberate no-op on both surfaces:
// IS-IS adjacency PDUs are non-IP frames that never traverse the IP input
// chains and are never delivered to the XSK as IP packets — the kernel hands
// them to FRR's isisd via an LLC/SNAP packet socket, entirely outside the IP
// host-inbound filter. Both surfaces therefore agree (neither admits an IP
// match for an L2 token), so there is no split-brain. The Go nft parity test
// (TestHostInboundNftMatchesKnownTokens) skips these tokens in its
// every-known-token-produces-a-match assertion and instead asserts they
// produce NO IP match; the Rust classify_protocol mirrors this with an explicit
// no-op arm. Keep in lockstep with that arm. #3311.
var HostInboundL2Protocols = map[string]bool{
	"isis": true,
}

// HostInboundAllExpansionProtocols returns the routing-protocol tokens that
// `host-inbound-traffic protocols all` expands to (#3199): every recognized
// protocol (KnownHostInboundProtocols) EXCEPT the `all` meta-token itself and
// EXCEPT any L2/non-IP protocol (HostInboundL2Protocols). The L2 exclusion is
// what makes HostInboundL2Protocols load-bearing rather than decorative (#3311):
// adding a new L2 protocol to that set (and to KnownHostInboundProtocols) is the
// ONLY edit needed — it is then automatically kept out of the `all` IP
// expansion on BOTH enforcement surfaces (the nft builder's `all` case and the
// Rust classifier's `all` arm consume this contract; the Rust side mirrors it
// via HOST_INBOUND_L2_PROTOCOLS + a parity test). The result is sorted so the
// expansion is deterministic.
func HostInboundAllExpansionProtocols() []string {
	out := make([]string, 0, len(KnownHostInboundProtocols))
	for tok := range KnownHostInboundProtocols {
		if tok == "all" || HostInboundL2Protocols[tok] {
			continue
		}
		out = append(out, tok)
	}
	sort.Strings(out)
	return out
}

// HostInboundNonJunosSystemServices is the set of recognized `system-services`
// tokens that are an xpf EXTENSION rather than a Junos system service, and are
// therefore excluded from the `system-services all` expansion (#3226).
//
// Junos scopes `all` to "traffic from the DEFINED system services available on
// the Routing Engine" (Juniper, `system-services (Security Zones Host Inbound
// Traffic)`), and its documented service list contains no raw IP protocol —
// GRE/ESP/OSPF/PIM/VRRP are reached through `protocols` (or not at all), never
// through `system-services`. xpf additionally accepts `system-services gre`
// because some operator configs list it there (see the repo ha-cluster wan
// zone), mapping it to IP protocol 47. Folding that xpf-only token into the
// `all` expansion would make `all` silently open a raw IP protocol that Junos's
// `all` never opens — precisely the over-admit #3226 set out to close. The
// token stays fully usable; it just has to be listed EXPLICITLY.
//
// `r-exec`/`rexec` (TCP/512) is here for the same reason. Juniper's
// host-inbound service list — zone-level AND interface-level — documents
// `rlogin` and `rsh` but NOT rexec, so a Junos-correct `all` never opens
// TCP/512. Unlike the other xpf spellings the token is not a port-neutral
// alias: `webapi-clear-text`/`webapi-ssl` resolve to the same ports as
// `http`/`https`, and `ssh-netconf`/`netconf-ssh` to `ssh` ∪ `netconf`, so
// including them in the expansion widens nothing, whereas 512 is opened by no
// other token. (`sip` is NOT reclassified: it is a documented vSRX ALG service
// with its own #3619 disposition and a fail-on-revert port pin in
// pkg/daemon/host_inbound_parity_test.go.) Listing `r-exec` explicitly still
// opens 512 — the carve-out narrows `all`, it does not remove the token.
//
// This mirrors the HostInboundL2Protocols exclusion on the `protocols all`
// side (#3311): the set is load-bearing, not decorative — adding an xpf-only
// service token here (and to KnownHostInboundSystemServices) is the ONLY edit
// needed to keep it out of the `all` expansion on BOTH enforcement surfaces.
// The Rust classifier mirrors it via HOST_INBOUND_NON_JUNOS_SERVICES and the
// #3486 parity test asserts the two sets are equal.
var HostInboundNonJunosSystemServices = map[string]bool{
	"gre":    true,
	"r-exec": true,
	"rexec":  true,
}

// HostInboundAllExpansionServices returns the `system-services` tokens that
// `host-inbound-traffic system-services all` expands to (#3226): every
// recognized service (KnownHostInboundSystemServices) EXCEPT the two meta
// tokens (`all` itself and the `any-service` full-admit escape hatch) and
// EXCEPT any xpf-only extension token (HostInboundNonJunosSystemServices).
//
// Before #3226 `all` was a packet-wide admit on both enforcement surfaces: the
// nft mirror emitted a bare `<fam> daddr <addrs> accept` with NO catch-all
// drop and the Rust classifier short-circuited `admits()` to true, so a zone
// with `system-services all` accepted EVERY IP protocol and port to its local
// addresses — GRE/ESP/AH/OSPF/PIM/VRRP and any future protocol number
// included. Junos scopes `all` to the defined system services, so the blanket
// admit was a superset of the Junos meaning that could mask a missing explicit
// `protocols` entry. Expanding to a concrete service set (exactly how #3199
// scoped the sibling `protocols all`) restores the Junos semantics and, because
// the zone now falls through to the per-match path, re-arms the catch-all
// host-inbound drop for anything the expansion does not cover.
//
// Aliases (http/webapi-clear-text, ike/ipsec, rlogin/r-login, ...) are all
// included; they resolve to the same L4 tuples and both enforcement surfaces
// dedup. The one exception is `r-exec`/`rexec`, which is an xpf-only spelling
// with a port of its OWN (TCP/512, opened by no other token) rather than a
// port-neutral alias — it is therefore in HostInboundNonJunosSystemServices and
// excluded, so the expansion opens exactly the ports Juniper's documented
// service list opens. `ident-reset` is included and keeps its Junos RESET
// semantics (#3310) rather than becoming an admit. The result is sorted so the
// expansion — and therefore the rendered nft rule order — is deterministic.
func HostInboundAllExpansionServices() []string {
	out := make([]string, 0, len(KnownHostInboundSystemServices))
	for tok := range KnownHostInboundSystemServices {
		if HostInboundFullAdmitService(tok) || tok == "all" ||
			HostInboundNonJunosSystemServices[tok] {
			continue
		}
		out = append(out, tok)
	}
	sort.Strings(out)
	return out
}

// HostInboundServiceTokenExpansion returns the CONCRETE `system-services`
// tokens a single authored token stands for: the `all` meta-token expands to
// HostInboundAllExpansionServices (#3226); every other token — including the
// `any-service` full-admit, which is not a per-service union at all — stands
// only for itself.
//
// Consumers that ask "does this authored service set contain token X?" MUST go
// through this helper rather than comparing strings, or they will miss the
// tokens `all` now covers. The #4146 junos-host shield is the load-bearing
// caller: it has to know that `system-services all` still coarse-admits
// IKE/NAT-T and still RSTs ident, which before #3226 fell out of the
// full-admit short-circuit and now falls out of the expansion.
func HostInboundServiceTokenExpansion(token string) []string {
	if strings.ToLower(strings.TrimSpace(token)) == "all" {
		return HostInboundAllExpansionServices()
	}
	return []string{token}
}

// Address-family scoping for host-inbound tokens (#3225). Several Junos
// host-inbound tokens are family-SPECIFIC in intent: a `system-services dhcp`
// is DHCPv4 (udp 67/68 over IPv4), `dhcpv6` is DHCPv6 (udp 546/547 over IPv6);
// `protocols rip` is RIPv2 (IPv4), `ripng` is RIPng (IPv6); `protocols ospf` is
// OSPFv2 (IPv4) while `ospf3` is OSPFv3 (IPv6) — both ride IP protocol 89 but on
// different families; `igmp` is IPv4 group membership (the IPv6 equivalent is
// MLD, carried over ICMPv6 / the always-accepted ND set).
//
// Before #3225 both enforcement layers compiled these tokens into family-NEUTRAL
// matches, so e.g. `system-services dhcp` opened udp/67-68 on the IPv6 path too
// and `protocols ripng` opened udp/521 on IPv4 — a wrong-family host exposure
// diverging from vSRX semantics. These maps are the single source of truth for a
// token's family; BOTH enforcement layers consult them (the nft kernel mirror
// directly via HostInboundServiceFamily/HostInboundProtocolFamily; the Rust
// AF_XDP classifier mirrors them into family-scoped admit sets and is kept in
// lock-step by the comment + the Go parity test).
//
// A token ABSENT from the relevant map is dual-family (admitted on IPv4 AND
// IPv6, the common case — ssh/https/ping/dns/bgp/...). A token mapped to "ip"
// is IPv4-only; "ip6" is IPv6-only. The values use the same "ip"/"ip6" family
// spelling the nft builder threads through hostInboundServiceMatches /
// hostInboundProtocolMatches.

// HostInboundServiceFamily maps a family-SPECIFIC `system-services` token to its
// only valid address family. Dual-family services are absent.
var HostInboundServiceFamily = map[string]string{
	"dhcp":   "ip",
	"bootp":  "ip",
	"dhcpv6": "ip6",
}

// HostInboundProtocolFamily maps a family-SPECIFIC `protocols` (routing) token
// to its only valid address family. Dual-family protocols (bgp, pim, vrrp, bfd,
// ldp, msdp, nhrp, router-discovery, rsvp, pgm, sap) are absent. `ospf`/`ospf3`
// are split here even though both ride IP protocol 89: OSPFv2 is IPv4, OSPFv3 is
// IPv6.
var HostInboundProtocolFamily = map[string]string{
	"ospf":  "ip",
	"ospf3": "ip6",
	"rip":   "ip",
	"ripng": "ip6",
	"igmp":  "ip",
	// #3341: DVMRP is carried inside IGMP (IP protocol 2) and is an IPv4-only
	// multicast routing protocol — like igmp it must not open proto 2 on the v6
	// path. rsvp/pgm/sap are dual-family (absent here).
	"dvmrp": "ip",
}

// ---------------------------------------------------------------------------
// Structured token->tuple SSOT (#3627 B1a)
//
// Before #3627 the token->(proto, ports, icmp-type) mapping existed only as
// nft match STRINGS (pkg/daemon hostInboundServiceMatches / hostInboundProtocol
// Matches) and as the Rust classifier's per-CPU admit sets
// (userspace-dp/.../forwarding/host_inbound.rs). A THIRD consumer — the
// `request security match-policies` host-inbound simulator, which must report
// WHICH host-inbound-traffic token admits a queried host-bound tuple — needs the
// mapping in STRUCTURED form, not as nft syntax. Hand-writing a third table
// would let it drift from the nft/Rust truth (a token could claim it admits
// tcp/22 while a future edit moves the nft port). #3627 B1a extracts the single
// structured SSOT below: the pkg/daemon nft builder RENDERS its match fragments
// from this table (see renderHostInboundMatches) and the dataplane/userspace
// host-inbound classifier MATCHES a query tuple against it, so both read ONE
// table. The recognized-token allowlist (KnownHostInbound*), the family maps
// (HostInbound*Family), and the L2/full-admit predicates above remain the
// domain SSOT; this adds the per-token PORT/PROTO/ICMP truth.
//
// A per-tuple Rust parity test (host_inbound.rs admit-set == this table) is a
// deferred follow-up; the existing domain-parity tests
// (TestHostInboundNftMatchesKnownTokens, TestHostInboundRustClassifierMatchesGo
// SSOT) still guard the token SETS.

// IP protocol numbers the host-inbound token->tuple SSOT emits. Exported so the
// pkg/daemon nft renderer and the dataplane/userspace classifier can key on a
// match's L4 kind without re-deriving the numbers.
const (
	HostInboundProtoICMP   uint8 = 1
	HostInboundProtoTCP    uint8 = 6
	HostInboundProtoUDP    uint8 = 17
	HostInboundProtoICMPv6 uint8 = 58
)

// PortRange is an inclusive TCP/UDP destination-port range in a host-inbound
// L4Match. Lo == Hi is a single port (ssh -> {22,22}); Lo < Hi is a contiguous
// range (traceroute -> {33434,33523}). All ports are host byte order.
type PortRange struct {
	Lo, Hi uint16
}

// L4Match is one structured host-inbound admission tuple for a Junos
// host-inbound-traffic token in a given address family (#3627 B1a). Exactly one
// L4 shape is populated per match:
//
//   - TCP/UDP (Proto == HostInboundProtoTCP/UDP): Ports carries the destination
//     ports (single, set, or range). A zero-length Ports with a TCP/UDP proto is
//     not emitted by this SSOT.
//   - ICMP/ICMPv6 (Proto == HostInboundProtoICMP/ICMPv6): ICMPType carries the
//     single admitted type (ping -> echo-request; router-discovery -> 9 then
//     10 as two matches). nil ICMPType is not emitted for an ICMP proto.
//   - a bare IP protocol (gre=47, ospf=89, pim=103, ...): neither Ports nor
//     ICMPType is set; the protocol number alone is the match.
//
// Reject marks the lone non-admitting token `system-services ident-reset`
// (#3310): its match fragment IS tcp/113 (the nft chain emits it to attach a
// `reject with tcp reset` verdict), but it RESETS rather than admits, so the
// host-inbound classifier must NOT report ident-reset as admitting a tcp/113
// query. Every other token's matches admit (Reject == false).
type L4Match struct {
	Proto    uint8
	Ports    []PortRange
	ICMPType *uint8
	Reject   bool
}

func hiTCP(ports ...uint16) L4Match {
	return L4Match{Proto: HostInboundProtoTCP, Ports: hiPorts(ports)}
}
func hiUDP(ports ...uint16) L4Match {
	return L4Match{Proto: HostInboundProtoUDP, Ports: hiPorts(ports)}
}
func hiIPProto(n uint8) L4Match { return L4Match{Proto: n} }
func hiUDPRange(lo, hi uint16) L4Match {
	return L4Match{Proto: HostInboundProtoUDP, Ports: []PortRange{{Lo: lo, Hi: hi}}}
}

func hiPorts(ports []uint16) []PortRange {
	out := make([]PortRange, len(ports))
	for i, p := range ports {
		out[i] = PortRange{Lo: p, Hi: p}
	}
	return out
}

func hiICMP(proto, typ uint8) L4Match {
	t := typ
	return L4Match{Proto: proto, ICMPType: &t}
}

// HostInboundServiceMatch returns the structured admission tuples for a Junos
// `system-services` token in the given address family ("ip" / "ip6"), the
// STRUCTURED half of the #3627 B1a SSOT. It mirrors the pkg/daemon
// hostInboundServiceMatches switch and the Rust classify_system_service admit
// set exactly (docs/host-inbound-service-matrix.md), and applies the same family
// gate: a family-specific token (HostInboundServiceFamily) returns nil for the
// wrong family. Full-admit tokens (all / any-service, see
// HostInboundFullAdmitService) and unrecognised tokens return nil — they are not
// per-tuple matches. The nft builder renders these tuples back to byte-identical
// match fragments (renderHostInboundMatches); the host-inbound classifier tests
// each tuple against a queried packet tuple.
func HostInboundServiceMatch(token, family string) []L4Match {
	if fam, ok := HostInboundServiceFamily[token]; ok && fam != family {
		return nil
	}
	switch token {
	case "all":
		// #3226: `system-services all` is the union of the DEFINED system
		// services (Junos: "traffic from the defined system services available
		// on the Routing Engine"), NOT a packet-wide admit. It expands here —
		// exactly as `protocols all` does above — so every consumer of this
		// SSOT (the nft kernel mirror, the netlink builder, the match-policies
		// classifier) inherits the scoped set with no per-consumer edit, and
		// the zone falls through to the per-match path that re-arms the
		// catch-all drop. The expansion never yields `all` (it is filtered out
		// by HostInboundAllExpansionServices), so this recursion terminates.
		var out []L4Match
		for _, s := range HostInboundAllExpansionServices() {
			out = append(out, HostInboundServiceMatch(s, family)...)
		}
		return out
	case "ssh":
		return []L4Match{hiTCP(22)}
	case "telnet":
		return []L4Match{hiTCP(23)}
	case "ftp":
		return []L4Match{hiTCP(21)}
	case "http", "webapi-clear-text":
		// #5715: the admit port is the canonical web-management HTTP listener
		// port (webmgmt SSOT), the SAME constant pkg/daemon binds the listener
		// to — so the host-inbound admit and the actual listener are ONE
		// contract and cannot drift.
		return []L4Match{hiTCP(webmgmt.HTTPPort)}
	case "https", "webapi-ssl":
		return []L4Match{hiTCP(webmgmt.HTTPSPort)}
	case "ping":
		// #3201/#3240: echo-request only — v4 type 8, v6 type 128. Error/PMTUD +
		// ND subtypes are admitted globally, not per-token.
		if family == "ip6" {
			return []L4Match{hiICMP(HostInboundProtoICMPv6, 128)}
		}
		return []L4Match{hiICMP(HostInboundProtoICMP, 8)}
	case "dns":
		return []L4Match{hiUDP(53), hiTCP(53)}
	case "dhcp", "bootp":
		return []L4Match{hiUDP(67, 68)}
	case "dhcpv6":
		return []L4Match{hiUDP(546, 547)}
	case "ntp":
		return []L4Match{hiUDP(123)}
	case "snmp":
		return []L4Match{hiUDP(161)}
	case "snmp-trap":
		return []L4Match{hiUDP(162)}
	case "ike", "ipsec":
		// `ipsec` opens IKE (udp 500 / NAT-T 4500); the raw ESP/AH data plane is
		// accepted globally, so `ipsec` is a superset of `ike` — one case.
		return []L4Match{hiUDP(500, 4500)}
	case "tftp":
		return []L4Match{hiUDP(69)}
	case "netconf":
		return []L4Match{hiTCP(830)}
	case "ssh-netconf", "netconf-ssh":
		return []L4Match{hiTCP(22, 830)}
	case "finger":
		return []L4Match{hiTCP(79)}
	case "ident-reset":
		// #3310: matches tcp/113 (so the nft chain can attach `reject with tcp
		// reset`) but RESETS — Reject marks it as non-admitting for the classifier.
		m := hiTCP(113)
		m.Reject = true
		return []L4Match{m}
	case "lsping":
		return []L4Match{hiUDP(3503)}
	case "sip":
		return []L4Match{hiUDP(5060), hiTCP(5060)}
	case "r-login", "rlogin":
		return []L4Match{hiTCP(513)}
	case "r-sh", "rsh":
		return []L4Match{hiTCP(514)}
	case "r-exec", "rexec":
		return []L4Match{hiTCP(512)}
	// #3226 fold — Juniper-documented host-inbound services xpf previously did
	// not recognize. Ports are the Junos defaults (see the
	// KnownHostInboundSystemServices comment for provenance).
	case "r2cp":
		return []L4Match{hiUDP(28762)}
	case "reverse-telnet":
		return []L4Match{hiTCP(2900)}
	case "reverse-ssh":
		return []L4Match{hiTCP(2901)}
	case "rpm":
		// The RPM probe RECEIVER (`[edit services rpm probe-server]`) takes a
		// tcp and a udp port, each "7 or 49160 through 65535". Port 7
		// (UDP-ECHO) is the only value fixed by the platform — the high range
		// is operator-chosen per probe-server and xpf models no such stanza —
		// so `rpm` admits exactly tcp/7 + udp/7. A deployment using a high
		// probe-server port lists that port via a firewall filter or uses
		// `any-service`; admitting 49160-65535 here would open 16k ports on
		// every `all` zone.
		return []L4Match{hiTCP(7), hiUDP(7)}
	case "xnm-clear-text":
		return []L4Match{hiTCP(3221)}
	case "xnm-ssl":
		return []L4Match{hiTCP(3220)}
	case "traceroute":
		return []L4Match{hiUDPRange(33434, 33523)}
	case "gre":
		return []L4Match{hiIPProto(47)}
	default:
		return nil
	}
}

// HostInboundProtocolMatch returns the structured admission tuples for a Junos
// `protocols` (routing-protocol) token in the given family, the protocol half of
// the #3627 B1a SSOT. `all` expands to every routing protocol via
// HostInboundAllExpansionProtocols (#3199/#3311 — L2/non-IP protocols excluded),
// each family-gated, exactly like the pkg/daemon nft `all` case and the Rust
// routing_protocol_all_expansion. Family-specific tokens (HostInboundProtocol
// Family) return nil for the wrong family; L2 tokens (isis) and unrecognised
// tokens return nil (no IP match).
func HostInboundProtocolMatch(token, family string) []L4Match {
	if fam, ok := HostInboundProtocolFamily[token]; ok && fam != family {
		return nil
	}
	switch token {
	case "all":
		var out []L4Match
		for _, p := range HostInboundAllExpansionProtocols() {
			out = append(out, HostInboundProtocolMatch(p, family)...)
		}
		return out
	case "ospf", "ospf3":
		// Both ride IP protocol 89; the family gate above scopes each.
		return []L4Match{hiIPProto(89)}
	case "bgp":
		return []L4Match{hiTCP(179)}
	case "rip":
		return []L4Match{hiUDP(520)}
	case "ripng":
		return []L4Match{hiUDP(521)}
	case "igmp":
		return []L4Match{hiIPProto(2)}
	case "pim":
		return []L4Match{hiIPProto(103)}
	case "vrrp":
		return []L4Match{hiIPProto(112)}
	case "bfd":
		// #3299: single-hop control (3784) + echo (3785) + multi-hop control (4784).
		return []L4Match{hiUDP(3784, 3785, 4784)}
	case "ldp":
		return []L4Match{hiTCP(646), hiUDP(646)}
	case "msdp":
		return []L4Match{hiTCP(639)}
	case "nhrp":
		return []L4Match{hiIPProto(54)}
	case "rsvp":
		return []L4Match{hiIPProto(46)}
	case "pgm":
		return []L4Match{hiIPProto(113)}
	case "sap":
		return []L4Match{hiUDP(9875)}
	case "dvmrp":
		return []L4Match{hiIPProto(2)}
	case "isis":
		// #3311: rides L2 (OSI/CLNP), no IP match — handled by FRR over LLC.
		return nil
	case "router-discovery":
		if family == "ip6" {
			// v6 RS/RA are part of the always-accepted ND set (global accept).
			return nil
		}
		return []L4Match{hiICMP(HostInboundProtoICMP, 9), hiICMP(HostInboundProtoICMP, 10)}
	default:
		return nil
	}
}

// HostInboundFullAdmitService reports whether a `system-services` token opens
// the zone to EVERY host-bound packet regardless of service — since #3226 that
// is `any-service` ALONE. Such a token is not a per-tuple L4Match
// (HostInboundServiceMatch returns nil for it); the nft builder emits a bare
// `accept` with NO catch-all drop and the classifier reports admission
// regardless of the tuple.
//
// `all` is NO LONGER a full admit (#3226). Junos scopes it to "traffic from the
// defined system services available on the Routing Engine", so it expands to
// the named-service union via HostInboundAllExpansionServices — the same shape
// #3199 gave the sibling `protocols all`. Before #3226 both tokens
// short-circuited here, so a `system-services all` zone accepted every IP
// protocol/port (GRE/ESP/AH/OSPF/PIM/VRRP and arbitrary future protocol
// numbers) to its local addresses and emitted no deny at all.
//
// `any-service` deliberately stays a full admit: Junos defines it as "all
// system services on an entire port range INCLUDING the system services that
// are not defined", i.e. the explicit escape hatch for traffic the named set
// does not cover. xpf keeps it as the documented (and commit-warned, see
// compiler_validate_warn.go) packet-wide admit, which also gives operators who
// relied on the pre-#3226 `all` breadth a one-token migration. Treating it as a
// SUPERSET of the Junos entire-port-range meaning is the fail-safe direction: it
// can only over-admit on a token whose whole purpose is to over-admit, never
// silently deny.
//
// The token match is case-insensitive to stay in lockstep with enforcement: the
// dataplane snapshot (unionHostInboundTokens / lowerTokens in
// pkg/dataplane/userspace) and the Rust classifier
// (classify_system_service, host_inbound.rs) both lower-case every token before
// admitting. A predicate that only matched lower-case `any-service` would let a
// lenient-loaded upper-case `ANY-SERVICE` slip past this SSOT while enforcement
// still full-admits — the #5557 coarse-shield / commit-warning drift.
func HostInboundFullAdmitService(token string) bool {
	return strings.ToLower(strings.TrimSpace(token)) == "any-service"
}
