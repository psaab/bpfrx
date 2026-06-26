package config

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
// matchers reference these sets for a parity test; the Rust classifier mirrors
// them (kept in sync by comment + the Go-side parity test). Tokens are matched
// case-sensitively against the canonical lowercase spellings. At runtime BOTH
// layers normalize case (the nft path lowercases via lowerTokens before its
// switch; the Rust classifier lowercases too), so a wrong-case token would in
// fact enforce identically on both — there is no runtime split-brain. We still
// reject wrong-case at commit for Junos-parity/typo-hygiene: Junos host-inbound
// keywords are lowercase-canonical, so wrong-case input is a typo worth flagging
// (lenient load only warns, so a persisted/sync'd config is never bricked).

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
// `ospf`. Keep in lockstep with pkg/daemon hostInboundProtocolMatches +
// hostInboundRoutingProtocolTokens and the Rust classify_protocol +
// ROUTING_PROTOCOL_TOKENS.
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
// ldp, msdp, nhrp, router-discovery) are absent. `ospf`/`ospf3` are split here
// even though both ride IP protocol 89: OSPFv2 is IPv4, OSPFv3 is IPv6.
var HostInboundProtocolFamily = map[string]string{
	"ospf":  "ip",
	"ospf3": "ip6",
	"rip":   "ip",
	"ripng": "ip6",
	"igmp":  "ip",
}
