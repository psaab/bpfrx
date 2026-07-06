package config

import "sort"

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
	"gre":               true,
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
	case "ssh":
		return []L4Match{hiTCP(22)}
	case "telnet":
		return []L4Match{hiTCP(23)}
	case "ftp":
		return []L4Match{hiTCP(21)}
	case "http", "webapi-clear-text":
		return []L4Match{hiTCP(80)}
	case "https", "webapi-ssl":
		return []L4Match{hiTCP(443)}
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
// the zone to EVERY host-bound service (Junos `all` / `any-service`). Such a
// token is not a per-tuple L4Match (HostInboundServiceMatch returns nil for it);
// the nft builder emits a bare `accept` and the classifier reports admission
// regardless of the tuple. `protocols all` is deliberately NOT a full admit
// (#3199) — it expands to the routing-protocol set via HostInboundProtocolMatch.
func HostInboundFullAdmitService(token string) bool {
	return token == "all" || token == "any-service"
}
