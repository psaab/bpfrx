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
// case-sensitively against the canonical lowercase spellings: the nft matcher
// switch is case-sensitive, so accepting `SSH` at commit would itself reintroduce
// a split-brain (Rust lowercases, nft does not). Junos host-inbound keywords are
// lowercase, so this rejects only genuine typos / wrong-case input.

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
