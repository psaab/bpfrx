package config

// schema_security.go carries the `security` and `applications` subtrees
// of the config-mode grammar SSOT (#1891 domain split). The root
// composition, the schemaNode type, and the split rationale live in
// schema.go; this file is a sibling aspect file in package config — NOT
// a subpackage — because setSchema is unexported and consumed
// in-package by schema_complete.go / schema_walk.go (two-SSOT doctrine,
// #1319).

var schemaSecurity = &schemaNode{desc: "Security configuration", children: map[string]*schemaNode{
	"zones": {desc: "Security zones", children: map[string]*schemaNode{
		"security-zone": {desc: "Security zone name", args: 1, valueHint: ValueHintZoneName, placeholder: "<zone-name>", children: map[string]*schemaNode{
			"description": {desc: "Zone description", args: 1, placeholder: "<text>", children: nil},
			"interfaces":  {desc: "Interfaces in this zone", children: nil},
			"tcp-rst":     {desc: "Send TCP RST for denied traffic", children: nil},
			"screen":      {desc: "Screen profile name", args: 1, placeholder: "<screen-name>", children: nil},
			"host-inbound-traffic": {desc: "Host inbound traffic", children: map[string]*schemaNode{
				"system-services": {desc: "System services", children: nil},
				"protocols":       {desc: "Protocols", children: nil},
			}},
		}},
	}},
	"policies": {desc: "Security policies", children: map[string]*schemaNode{
		"from-zone": {desc: "From zone", args: 3, valueHint: ValueHintZoneName, midKeyword: "to-zone", midKeywordAt: 2, placeholder: "<zone-name>", children: map[string]*schemaNode{
			"policy": {desc: "Policy name", args: 1, valueHint: ValueHintPolicyName, placeholder: "<policy-name>", children: map[string]*schemaNode{
				"description": {desc: "Policy description", args: 1, placeholder: "<text>", children: nil},
				"match": {desc: "Match criteria", children: map[string]*schemaNode{
					"source-address":               {desc: "Source address", args: 1, multi: true, valueHint: ValueHintPolicyAddress, placeholder: "<address>", children: nil},
					"destination-address":          {desc: "Destination address", args: 1, multi: true, valueHint: ValueHintPolicyAddress, placeholder: "<address>", children: nil},
					"source-address-excluded":      {desc: "Match all sources except source-address", children: nil},
					"destination-address-excluded": {desc: "Match all destinations except destination-address", children: nil},
					"application":                  {desc: "Application", args: 1, multi: true, valueHint: ValueHintPolicyApp, placeholder: "<application>", children: nil},
				}},
				"then": {desc: "Action", children: map[string]*schemaNode{
					"log": {desc: "Log session", children: nil},
					// permit, deny, reject, count → leaf
				}},
			}},
		}},
		"global": {desc: "Global policies", children: map[string]*schemaNode{
			"policy": {desc: "Policy name", args: 1, valueHint: ValueHintPolicyName, placeholder: "<policy-name>", children: map[string]*schemaNode{
				"description": {desc: "Policy description", args: 1, placeholder: "<text>", children: nil},
				"match": {desc: "Match criteria", children: map[string]*schemaNode{
					"source-address":               {desc: "Source address", args: 1, multi: true, valueHint: ValueHintPolicyAddress, placeholder: "<address>", children: nil},
					"destination-address":          {desc: "Destination address", args: 1, multi: true, valueHint: ValueHintPolicyAddress, placeholder: "<address>", children: nil},
					"source-address-excluded":      {desc: "Match all sources except source-address", children: nil},
					"destination-address-excluded": {desc: "Match all destinations except destination-address", children: nil},
					"application":                  {desc: "Application", args: 1, multi: true, valueHint: ValueHintPolicyApp, placeholder: "<application>", children: nil},
				}},
				"then": {desc: "Action", children: map[string]*schemaNode{
					"log": {desc: "Log session", children: nil},
				}},
			}},
		}},
	}},
	"screen": {desc: "Screen options", children: map[string]*schemaNode{
		"ids-option": {desc: "Screen profile name", args: 1, valueHint: ValueHintScreenProfile, placeholder: "<screen-name>", children: map[string]*schemaNode{
			"icmp": {desc: "ICMP screening", children: nil},
			"tcp": {desc: "TCP screening", children: map[string]*schemaNode{
				"syn-flood": {desc: "SYN flood protection", children: nil},
				"port-scan": {desc: "Port scan protection", children: nil},
				// land, winnuke, syn-frag -> leaf
			}},
			"ip": {desc: "IP screening", children: map[string]*schemaNode{
				"ip-sweep": {desc: "IP sweep protection", children: nil},
				// source-route-option, tear-drop -> leaf
			}},
			"udp": {desc: "UDP screening", children: nil},
			"limit-session": {desc: "Session limits", children: map[string]*schemaNode{
				"source-ip-based":      {desc: "Source IP based limit", args: 1, placeholder: "<number>", children: nil},
				"destination-ip-based": {desc: "Destination IP based limit", args: 1, placeholder: "<number>", children: nil},
			}},
		}},
	}},
	"nat": {desc: "Network Address Translation", children: map[string]*schemaNode{
		"source": {desc: "Source NAT configuration", children: map[string]*schemaNode{
			"pool":               {desc: "Source NAT pool name", args: 1, valueHint: ValueHintPoolName, placeholder: "<pool-name>", children: nil},
			"address-persistent": {desc: "Always map a source IP to the same pool address", children: nil},
			"rule-set": {desc: "Source NAT rule-set name", args: 1, placeholder: "<rule-set-name>", children: map[string]*schemaNode{
				"from": {desc: "Source of traffic to match", children: map[string]*schemaNode{
					"zone": {desc: "Source zone name", args: 1, valueHint: ValueHintZoneName, placeholder: "<zone-name>", children: nil},
				}},
				"to": {desc: "Destination of traffic to match", children: map[string]*schemaNode{
					"zone": {desc: "Destination zone name", args: 1, valueHint: ValueHintZoneName, placeholder: "<zone-name>", children: nil},
				}},
				"rule": {desc: "Source NAT rule name", args: 1, placeholder: "<rule-name>", children: map[string]*schemaNode{
					"match": {desc: "Match criteria", children: map[string]*schemaNode{
						"source-address":      {desc: "Source address prefix to match", args: 1, multi: true, placeholder: "<prefix>", children: nil},
						"destination-address": {desc: "Destination address prefix to match", args: 1, multi: true, placeholder: "<prefix>", children: nil},
						"destination-port":    {desc: "Destination port to match", args: 1, multi: true, placeholder: "<port>", children: nil},
						"application":         {desc: "Application to match", args: 1, multi: true, placeholder: "<application>", children: nil},
					}},
					"then": {desc: "Source NAT action", children: map[string]*schemaNode{
						"source-nat": {desc: "Source NAT translation", children: map[string]*schemaNode{
							"interface": {desc: "Translate to the egress interface address", children: nil},
							"off":       {desc: "Disable source NAT for matching traffic", children: nil},
							"pool":      {desc: "Translate using a source NAT pool", args: 1, valueHint: ValueHintPoolName, placeholder: "<pool-name>", children: nil},
						}},
					}},
				}},
			}},
		}},
		"destination": {desc: "Destination NAT configuration", children: map[string]*schemaNode{
			"pool": {desc: "Destination NAT pool name", args: 1, valueHint: ValueHintPoolName, placeholder: "<pool-name>", children: nil},
			"rule-set": {desc: "Destination NAT rule-set name", args: 1, placeholder: "<rule-set-name>", children: map[string]*schemaNode{
				"from": {desc: "Source of traffic to match", children: map[string]*schemaNode{
					"zone": {desc: "Source zone name", args: 1, valueHint: ValueHintZoneName, placeholder: "<zone-name>", children: nil},
				}},
				"to": {desc: "Destination of traffic to match", children: map[string]*schemaNode{
					"zone": {desc: "Destination zone name", args: 1, valueHint: ValueHintZoneName, placeholder: "<zone-name>", children: nil},
				}},
				"rule": {desc: "Destination NAT rule name", args: 1, placeholder: "<rule-name>", children: map[string]*schemaNode{
					"match": {desc: "Match criteria", children: map[string]*schemaNode{
						"source-address":      {desc: "Source address prefix to match", args: 1, multi: true, placeholder: "<prefix>", children: nil},
						"source-address-name": {desc: "Source address book entry to match", args: 1, multi: true, placeholder: "<address-name>", children: nil},
						"destination-address": {desc: "Destination address prefix to match", args: 1, multi: true, placeholder: "<prefix>", children: nil},
						"destination-port":    {desc: "Destination port or range to match", args: 1, multi: true, placeholder: "<port>", children: nil},
						"protocol":            {desc: "IP protocol to match", args: 1, multi: true, placeholder: "<protocol>", children: nil},
						"application":         {desc: "Application to match", args: 1, multi: true, placeholder: "<application>", children: nil},
					}},
					"then": {desc: "Destination NAT action", children: map[string]*schemaNode{
						"destination-nat": {desc: "Destination NAT translation", children: map[string]*schemaNode{
							"pool": {desc: "Translate using a destination NAT pool", args: 1, valueHint: ValueHintPoolName, placeholder: "<pool-name>", children: nil},
						}},
					}},
				}},
			}},
		}},
		"static": {desc: "Static NAT configuration", children: map[string]*schemaNode{
			"rule-set": {desc: "Static NAT rule-set name", args: 1, placeholder: "<rule-set-name>", children: map[string]*schemaNode{
				// `from zone` scopes the rule-set to an ingress zone. The
				// dataplane enforces it on the inbound (DNAT) direction
				// (static_nat.rs match_dnat). Junos static NAT has no `to`
				// clause (unlike source/destination NAT) — only `from`
				// (zone | interface | routing-instance). xpf compiles the
				// zone scope; declaring it here restores commit-time
				// validation and CLI completion (#2008 H15).
				"from": {desc: "Source of traffic to match", children: map[string]*schemaNode{
					"zone": {desc: "Source zone name", args: 1, multi: true, valueHint: ValueHintZoneName, placeholder: "<zone-name>", children: nil},
				}},
				"rule": {desc: "Static NAT rule name", args: 1, placeholder: "<rule-name>", children: map[string]*schemaNode{
					// M3 (#2008): the static-NAT rule `match` reads
					// `destination-address` and `source-address` children
					// at compile (compiler_nat.go static loop ~762-771),
					// but the schema left `match.children: nil` — so those
					// keywords fell through with no structural completion
					// and schema_walk.go skipped the subtree entirely. The
					// values are address prefixes OR address-book names
					// (consumed verbatim by nodeVal), so they stay untyped
					// like the source/destination-NAT match leaves above.
					"match": {desc: "Match criteria", children: map[string]*schemaNode{
						"destination-address": {desc: "Destination address prefix to match", args: 1, multi: true, placeholder: "<prefix>", children: nil},
						"source-address":      {desc: "Source address prefix to match", args: 1, multi: true, placeholder: "<prefix>", children: nil},
					}},
					"then": {desc: "Static NAT action", children: map[string]*schemaNode{
						"static-nat": {desc: "Static NAT translation (prefix|nptv6-prefix|inet)", children: nil},
					}},
				}},
			}},
		}},
		"nat64": {desc: "NAT64 (IPv6-to-IPv4) translation", children: map[string]*schemaNode{
			"rule-set": {desc: "NAT64 rule-set name", args: 1, placeholder: "<rule-set-name>", children: map[string]*schemaNode{
				"prefix":      {desc: "NAT64 IPv6 prefix (must be /96)", args: 1, placeholder: "<ipv6-prefix>", children: nil},
				"source-pool": {desc: "Source NAT pool for the translated IPv4 source", args: 1, placeholder: "<pool-name>", children: nil},
			}},
		}},
		"natv6v4": {desc: "NAT64 IPv6-to-IPv4 options", children: map[string]*schemaNode{
			"no-v6-frag-header": {desc: "Omit the IPv6 fragment header in translated packets", children: nil},
		}},
		"proxy-arp": {desc: "Proxy ARP for NAT pool addresses", children: map[string]*schemaNode{
			"interface": {desc: "Interface to answer proxy ARP on", args: 1, valueHint: ValueHintInterfaceName, placeholder: "<interface-name>", children: map[string]*schemaNode{
				"address": {desc: "Address or range to answer ARP for", args: 1, multi: true, placeholder: "<address>", children: nil},
			}},
		}},
	}},
	"address-book": {desc: "Address books", children: map[string]*schemaNode{
		"global": {desc: "Global address book", children: map[string]*schemaNode{
			"address": {desc: "Named address (name and prefix)", args: 2, multi: true, placeholder: "<address-name>", children: nil},
			"address-set": {desc: "Address set name", args: 1, valueHint: ValueHintAddressName, placeholder: "<address-set-name>", children: map[string]*schemaNode{
				"address":     {desc: "Address to include in this set", args: 1, multi: true, placeholder: "<address-name>", children: nil},
				"address-set": {desc: "Nested address set to include", args: 1, multi: true, valueHint: ValueHintAddressName, placeholder: "<address-set-name>", children: nil},
				"description": {desc: "Address set description", args: 1, placeholder: "<text>", children: nil},
			}},
		}},
	}},
	"log": {desc: "Security logging configuration", children: map[string]*schemaNode{
		"mode":             {desc: "Logging mode (stream|event)", args: 1, placeholder: "<mode>", children: nil},
		"format":           {desc: "Log format (sd-syslog|syslog|binary|structured)", args: 1, placeholder: "<format>", children: nil},
		"source-interface": {desc: "Interface whose address is used as the syslog source", args: 1, valueHint: ValueHintInterfaceName, placeholder: "<interface-name>", children: nil},
		"stream": {desc: "Syslog stream name", args: 1, valueHint: ValueHintStreamName, placeholder: "<stream-name>", children: map[string]*schemaNode{
			"host":           {desc: "Syslog server address", args: 1, placeholder: "<address>", children: nil},
			"port":           {desc: "Syslog server port (default 514)", args: 1, placeholder: "<port>", children: nil},
			"severity":       {desc: "Severity filter (error|warning|info)", args: 1, placeholder: "<severity>", children: nil},
			"facility":       {desc: "Syslog facility (e.g. local0; default local0)", args: 1, placeholder: "<facility>", children: nil},
			"format":         {desc: "Per-stream format override", args: 1, placeholder: "<format>", children: nil},
			"category":       {desc: "Event category filter (all or a specific category)", args: 1, placeholder: "<category>", children: nil},
			"source-address": {desc: "Source IP for this stream", args: 1, placeholder: "<address>", children: nil},
			// H8 (#2008): transport is fully compiled
			// (compiler_security.go stream loop) and runtime-honored
			// (pkg/logging/syslog.go dial), but the schema declared no
			// `transport` child — so `protocol`/`tls-profile` got no
			// commit-time validation or `?` completion. The protocol enum
			// mirrors the runtime switch (tcp/tls handled, everything else
			// silently falls back to UDP), so a typo like `protocol tpc`
			// committed and then quietly used UDP. Validate it.
			"transport": {desc: "Stream transport (protocol + optional TLS profile)", children: map[string]*schemaNode{
				"protocol": {desc: "Transport protocol (udp|tcp|tls)", args: 1, placeholder: "<protocol>",
					valueType: ValueEnumOf, valueDesc: "syslog transport protocol",
					valueExamples: []string{"udp", "tcp", "tls"},
					validator:     ValidateEnum([]string{"udp", "tcp", "tls"}), children: nil},
				"tls-profile": {desc: "TLS profile name (for protocol tls)", args: 1, placeholder: "<tls-profile-name>", children: nil},
			}},
		}},
	}},
	"flow": {desc: "Flow and session settings", children: map[string]*schemaNode{
		"aging": {desc: "Aggressive session aging thresholds", children: nil},
		// #1979 Layer B (Tier 2): expand the opaque session-timeout
		// containers to real containers whose value-bearing sub-leaves are
		// typed. The compiler reads tcp-session's four `<kind>-timeout`
		// sub-leaves (compiler_security.go) + three presence flags;
		// EstablishedTimeout reaches the Rust u64 TCPSessionTimeout wire
		// field, the other three are stored only in TCPSessionConfig (not
		// wire-reaching) but share the same Duration-overflow ceiling and
		// declaring them is required for completion parity anyway. The bound
		// is MaxDurationSeconds (NOT u64-max): Rust SessionTimeouts::
		// from_seconds multiplies secs*1e9 unchecked (Layer A,
		// coerceWireSessionTimeout). The presence flags are declared
		// presence-only so completion still offers them.
		"tcp-session": {desc: "TCP session options (timeouts, SYN checks)", children: map[string]*schemaNode{
			"established-timeout": {desc: "Established TCP session timeout in seconds", args: 1, placeholder: "<seconds>",
				valueType: ValueInteger, valueDesc: "Established TCP session timeout in seconds (0..9223372036)",
				valueExamples: []string{"1800"}, validator: ValidateInteger(0, MaxDurationSeconds), children: nil},
			"initial-timeout": {desc: "Initial (pre-established) TCP session timeout in seconds", args: 1, placeholder: "<seconds>",
				valueType: ValueInteger, valueDesc: "Initial TCP session timeout in seconds (0..9223372036)",
				valueExamples: []string{"20"}, validator: ValidateInteger(0, MaxDurationSeconds), children: nil},
			"closing-timeout": {desc: "Closing TCP session timeout in seconds", args: 1, placeholder: "<seconds>",
				valueType: ValueInteger, valueDesc: "Closing TCP session timeout in seconds (0..9223372036)",
				valueExamples: []string{"4"}, validator: ValidateInteger(0, MaxDurationSeconds), children: nil},
			"time-wait-timeout": {desc: "TIME_WAIT TCP session timeout in seconds", args: 1, placeholder: "<seconds>",
				valueType: ValueInteger, valueDesc: "TIME_WAIT TCP session timeout in seconds (0..9223372036)",
				valueExamples: []string{"150"}, validator: ValidateInteger(0, MaxDurationSeconds), children: nil},
			"no-syn-check":           {desc: "Disable SYN check for TCP sessions", children: nil},
			"no-syn-check-in-tunnel": {desc: "Disable SYN check for tunneled TCP sessions", children: nil},
			"rst-invalidate-session": {desc: "Invalidate session on TCP RST", children: nil},
			"no-sequence-check":      {desc: "Disable TCP sequence-number checking for sessions", children: nil},
		}},
		"udp-session": {desc: "UDP session timeout (default 60 seconds)", children: map[string]*schemaNode{
			"timeout": {desc: "UDP session timeout in seconds", args: 1, placeholder: "<seconds>",
				valueType: ValueInteger, valueDesc: "UDP session timeout in seconds (0..9223372036)",
				valueExamples: []string{"60"}, validator: ValidateInteger(0, MaxDurationSeconds), children: nil},
		}},
		"icmp-session": {desc: "ICMP session timeout (default 60 seconds)", children: map[string]*schemaNode{
			"timeout": {desc: "ICMP session timeout in seconds", args: 1, placeholder: "<seconds>",
				valueType: ValueInteger, valueDesc: "ICMP session timeout in seconds (0..9223372036)",
				valueExamples: []string{"60"}, validator: ValidateInteger(0, MaxDurationSeconds), children: nil},
		}},
		// #1979 Layer B (Tier 3): tcp-mss stays OPAQUE here by design. Its
		// MSS value can live in EITHER position (flat `gre-in 1400` OR
		// hierarchical `gre-in { mss 1360; }`), which the declarative schema
		// walker cannot express. Validation runs in the compiler AST pre-walk
		// validateTCPMSSRanges (compiler.go), modeled on
		// validateVRRPTrackInterfaceAST. See compiler_security.go.
		"tcp-mss":                      {desc: "TCP MSS clamping (ipsec-vpn|gre-in|gre-out|all-tcp)", children: nil},
		"allow-dns-reply":              {desc: "Allow unsolicited DNS reply packets", children: nil},
		"allow-embedded-icmp":          {desc: "Allow ICMP error packets for existing sessions", children: nil},
		"gre-performance-acceleration": {desc: "Enable GRE performance acceleration", children: nil},
		"power-mode-disable":           {desc: "Disable power mode", children: nil},
		"traceoptions": {desc: "Flow trace debugging options", children: map[string]*schemaNode{
			"file": {desc: "Trace file name (with size/files options)", args: 1, placeholder: "<filename>", children: nil},
			"flag": {desc: "Trace flag (e.g. basic-datapath, session)", args: 1, placeholder: "<flag>", children: nil},
			"packet-filter": {desc: "Trace packet filter name", args: 1, placeholder: "<filter-name>", children: map[string]*schemaNode{
				"source-prefix":      {desc: "Source prefix to trace", args: 1, placeholder: "<prefix>", children: nil},
				"destination-prefix": {desc: "Destination prefix to trace", args: 1, placeholder: "<prefix>", children: nil},
			}},
		}},
	}},
	"alg": {desc: "ALG (application layer gateway) control", children: map[string]*schemaNode{
		"dns":  {desc: "DNS ALG (disable)", children: nil},
		"ftp":  {desc: "FTP ALG (disable)", children: nil},
		"sip":  {desc: "SIP ALG (disable)", children: nil},
		"tftp": {desc: "TFTP ALG (disable)", children: nil},
	}},
	"ike": {desc: "IKE (Phase 1) configuration", children: map[string]*schemaNode{
		// M2 (#2008): the IKE (Phase 1) proposal body is fully compiled
		// (compiler_ipsec.go compileIKE proposal loop) and rendered to
		// swanctl (pkg/ipsec/ipsec.go), but the schema left
		// `proposal.children: nil` — so authentication-method/dh-group/
		// lifetime-seconds got no commit-time validation or `?`
		// completion. A bad authentication-method errors only later at
		// swanctl-generation time (authMethodToSwan); a 0/garbage
		// dh-group or lifetime-seconds silently compiles to 0 and drops
		// the term. encryption/authentication-algorithm stay untyped:
		// the renderer normalizes arbitrary algorithm spellings by string
		// substitution, so an enum here would false-reject valid configs.
		//
		// dh-group uses ValidateDHGroup (both bare-integer and group<N>):
		// the IKE compiler loop (compiler_ipsec.go compileIKE) strips the
		// "group" prefix before strconv.Atoi, so both spellings compile
		// identically. This is the deliberate asymmetry with the Phase-2
		// IPsec proposal below, whose compiler does NOT strip the prefix
		// and therefore validates dh-group as a plain positive integer.
		"proposal": {desc: "IKE proposal name", args: 1, placeholder: "<proposal-name>", children: map[string]*schemaNode{
			"authentication-method": {desc: "IKE authentication method", args: 1, placeholder: "<method>",
				valueType: ValueEnumOf, valueDesc: "IKE phase 1 authentication method",
				valueExamples: []string{"pre-shared-keys", "rsa-signatures", "ecdsa-signatures"},
				validator:     ValidateEnum([]string{"pre-shared-keys", "rsa-signatures", "ecdsa-signatures"}), children: nil},
			"dh-group": {desc: "Diffie-Hellman group (e.g. 14 or group14)", args: 1, placeholder: "<dh-group>",
				valueType: ValueDHGroup, valueDesc: "Diffie-Hellman group",
				valueExamples: []string{"2", "14", "group19"}, validator: ValidateDHGroup, children: nil},
			"encryption-algorithm":     {desc: "Encryption algorithm (e.g. aes-256-cbc, aes-256-gcm)", args: 1, placeholder: "<algorithm>", children: nil},
			"authentication-algorithm": {desc: "Authentication/integrity algorithm (e.g. sha-256, hmac-sha-256-128)", args: 1, placeholder: "<algorithm>", children: nil},
			"lifetime-seconds": {desc: "IKE SA lifetime in seconds", args: 1, placeholder: "<seconds>",
				valueType: ValueInteger, valueDesc: "IKE SA lifetime in seconds",
				valueExamples: []string{"3600", "28800"}, validator: ValidateIntegerMin(1), children: nil},
		}},
		"policy": {desc: "IKE policy name", args: 1, placeholder: "<policy-name>", children: map[string]*schemaNode{
			"mode":           {desc: "IKE phase 1 mode (main|aggressive)", args: 1, placeholder: "<mode>", children: nil},
			"proposals":      {desc: "IKE proposal reference", args: 1, placeholder: "<proposal-name>", children: nil},
			"pre-shared-key": {desc: "Pre-shared key (ascii-text <key>)", children: nil},
		}},
		"gateway": {desc: "IKE gateway (VPN peer) name", args: 1, placeholder: "<gateway-name>", children: map[string]*schemaNode{
			"address":            {desc: "Remote gateway address", args: 1, placeholder: "<address>", children: nil},
			"local-address":      {desc: "Local IKE address", args: 1, placeholder: "<address>", children: nil},
			"ike-policy":         {desc: "IKE policy reference", args: 1, placeholder: "<policy-name>", children: nil},
			"external-interface": {desc: "External interface for IKE (derives local address)", args: 1, placeholder: "<interface-name>", children: nil},
			"local-certificate":  {desc: "Local certificate for IKE authentication", args: 1, placeholder: "<certificate-name>", children: nil},
			"version":            {desc: "IKE version (v1-only|v2-only)", args: 1, placeholder: "<version>", children: nil},
			"no-nat-traversal":   {desc: "Disable NAT traversal (UDP encapsulation)", children: nil},
			"nat-traversal":      {desc: "NAT traversal (enable|disable|force)", args: 1, placeholder: "<mode>", children: nil},
			"dead-peer-detection": {desc: "Dead peer detection", children: map[string]*schemaNode{
				"always-send":       {desc: "Send DPD probes regardless of traffic", children: nil},
				"optimized":         {desc: "Optimized DPD probing", children: nil},
				"probe-idle-tunnel": {desc: "Probe idle tunnels", children: nil},
				"interval":          {desc: "DPD probe interval in seconds (default 10)", args: 1, placeholder: "<seconds>", children: nil},
				"threshold":         {desc: "Failed-probe count before peer is dead (default 5)", args: 1, placeholder: "<count>", children: nil},
			}},
			"local-identity":  {desc: "Local IKE identity (type and value)", children: nil},
			"remote-identity": {desc: "Remote IKE identity (type and value)", children: nil},
			"dynamic":         {desc: "Dynamic peer (hostname <fqdn>)", children: nil},
		}},
	}},
	"ipsec": {desc: "IPsec configuration", children: map[string]*schemaNode{
		// M2 (#2008): IPsec (Phase 2) proposal mirror of the IKE proposal
		// above. The Phase 2 proposal carries `protocol` (esp|ah) instead
		// of authentication-method and has no DPD; it is compiled by
		// compiler_ipsec.go compileIPsec proposal loop and rendered by
		// buildESPProposal. Same typing rationale: validate dh-group and
		// lifetime-seconds (silent-zero footgun), leave the algorithm and
		// protocol spellings untyped (the renderer accepts a wide set).
		//
		// dh-group is validated as a PLAIN POSITIVE INTEGER here, NOT with
		// ValidateDHGroup. Unlike the IKE loop, the Phase-2 compiler
		// (compiler_ipsec.go compileIPsec proposal loop) parses dh-group
		// with a bare strconv.Atoi and does NOT strip the "group" prefix.
		// Accepting `group14` at commit would let it compile to DHGroup=0
		// and silently drop the PFS/modp term from the swanctl proposal —
		// the exact schema-only drift this sweep closes. Keep the gate
		// compiler-faithful: bare positive integer only for Phase-2 PFS.
		"proposal": {desc: "IPsec (Phase 2) proposal name", args: 1, placeholder: "<proposal-name>", children: map[string]*schemaNode{
			"protocol":                 {desc: "IPsec protocol (esp|ah)", args: 1, placeholder: "<protocol>", children: nil},
			"encryption-algorithm":     {desc: "Encryption algorithm (e.g. aes-256-cbc, aes-256-gcm)", args: 1, placeholder: "<algorithm>", children: nil},
			"authentication-algorithm": {desc: "Authentication/integrity algorithm (e.g. hmac-sha-256-128)", args: 1, placeholder: "<algorithm>", children: nil},
			"dh-group": {desc: "Diffie-Hellman group for PFS (bare integer, e.g. 14 — Phase-2 does NOT accept the group<N> spelling)", args: 1, placeholder: "<dh-group>",
				valueType: ValueInteger, valueDesc: "Diffie-Hellman group (PFS modp number)",
				valueExamples: []string{"2", "14", "19"}, validator: ValidateIntegerMin(1), children: nil},
			"lifetime-seconds": {desc: "IPsec SA lifetime in seconds", args: 1, placeholder: "<seconds>",
				valueType: ValueInteger, valueDesc: "IPsec SA lifetime in seconds",
				valueExamples: []string{"3600", "28800"}, validator: ValidateIntegerMin(1), children: nil},
		}},
		"policy": {desc: "IPsec policy name", args: 1, placeholder: "<policy-name>", children: map[string]*schemaNode{
			"perfect-forward-secrecy": {desc: "Perfect forward secrecy (keys group<N>)", children: nil},
			"proposals":               {desc: "IPsec proposal reference", args: 1, placeholder: "<proposal-name>", children: nil},
		}},
		"gateway": {desc: "IKE gateway (VPN peer) name", args: 1, placeholder: "<gateway-name>", children: map[string]*schemaNode{
			"address":            {desc: "Remote gateway address", args: 1, placeholder: "<address>", children: nil},
			"local-address":      {desc: "Local IKE address", args: 1, placeholder: "<address>", children: nil},
			"ike-policy":         {desc: "IKE policy reference", args: 1, placeholder: "<policy-name>", children: nil},
			"external-interface": {desc: "External interface for IKE (derives local address)", args: 1, placeholder: "<interface-name>", children: nil},
			"local-certificate":  {desc: "Local certificate for IKE authentication", args: 1, placeholder: "<certificate-name>", children: nil},
			"version":            {desc: "IKE version (v1-only|v2-only)", args: 1, placeholder: "<version>", children: nil},
			"no-nat-traversal":   {desc: "Disable NAT traversal (UDP encapsulation)", children: nil},
			"nat-traversal":      {desc: "NAT traversal (enable|disable|force)", args: 1, placeholder: "<mode>", children: nil},
			"dead-peer-detection": {desc: "Dead peer detection", children: map[string]*schemaNode{
				"always-send":       {desc: "Send DPD probes regardless of traffic", children: nil},
				"optimized":         {desc: "Optimized DPD probing", children: nil},
				"probe-idle-tunnel": {desc: "Probe idle tunnels", children: nil},
				"interval":          {desc: "DPD probe interval in seconds (default 10)", args: 1, placeholder: "<seconds>", children: nil},
				"threshold":         {desc: "Failed-probe count before peer is dead (default 5)", args: 1, placeholder: "<count>", children: nil},
			}},
			"local-identity":  {desc: "Local IKE identity (type and value)", children: nil},
			"remote-identity": {desc: "Remote IKE identity (type and value)", children: nil},
			"dynamic":         {desc: "Dynamic peer (hostname <fqdn>)", children: nil},
		}},
		"vpn": {desc: "IPsec VPN tunnel name", args: 1, placeholder: "<vpn-name>", children: map[string]*schemaNode{
			"bind-interface":    {desc: "XFRM tunnel interface to bind", args: 1, placeholder: "<interface-name>", children: nil},
			"df-bit":            {desc: "Outer-header DF bit handling (copy|set)", args: 1, placeholder: "<mode>", children: nil},
			"establish-tunnels": {desc: "Tunnel establishment (immediately = initiate at commit)", args: 1, placeholder: "<mode>", children: nil},
			"local-identity":    {desc: "Local identity (default local traffic selector)", args: 1, placeholder: "<identity>", children: nil},
			"remote-identity":   {desc: "Remote identity (default remote traffic selector)", args: 1, placeholder: "<identity>", children: nil},
			"pre-shared-key":    {desc: "Pre-shared key for this VPN", args: 1, placeholder: "<key>", children: nil},
			"local-address":     {desc: "Local tunnel endpoint address", args: 1, placeholder: "<address>", children: nil},
			"traffic-selector": {desc: "Traffic selector name", args: 1, placeholder: "<selector-name>", children: map[string]*schemaNode{
				"local-ip":  {desc: "Local traffic selector prefix", args: 1, placeholder: "<prefix>", children: nil},
				"remote-ip": {desc: "Remote traffic selector prefix", args: 1, placeholder: "<prefix>", children: nil},
			}},
			"ike": {desc: "IKE bindings for this VPN", children: map[string]*schemaNode{
				"gateway":      {desc: "IKE gateway reference", args: 1, placeholder: "<gateway-name>", children: nil},
				"ipsec-policy": {desc: "IPsec policy reference", args: 1, placeholder: "<policy-name>", children: nil},
			}},
		}},
	}},
	"dynamic-address": {desc: "Dynamic address feeds", children: map[string]*schemaNode{
		"feed-server": {desc: "Feed server name", args: 1, placeholder: "<server-name>", children: map[string]*schemaNode{
			"url":             {desc: "Feed URL (takes precedence over hostname)", args: 1, placeholder: "<url>", children: nil},
			"hostname":        {desc: "Server hostname for building per-feed URLs", args: 1, placeholder: "<hostname>", children: nil},
			"update-interval": {desc: "Feed refresh interval in seconds (default 3600)", args: 1, placeholder: "<seconds>", children: nil},
			"hold-interval":   {desc: "Drop a feed's last-good snapshot to empty after N seconds of fetch failure; omit to retain last-good forever (default)", args: 1, placeholder: "<seconds>", children: nil},
			"feed-name": {desc: "Named feed on this server", args: 1, placeholder: "<feed-name>", children: map[string]*schemaNode{
				"path": {desc: "Path on the feed server for this feed", args: 1, placeholder: "<path>", children: nil},
			}},
		}},
		"address-name": {desc: "Dynamic address name bound to feeds", args: 1, placeholder: "<address-name>", children: map[string]*schemaNode{
			"profile": {desc: "Feed binding profile", children: map[string]*schemaNode{
				"feed-name": {desc: "Feed to bind to this address name", args: 1, placeholder: "<feed-name>", children: nil},
			}},
		}},
	}},
	"ssh-known-hosts": {desc: "SSH known hosts (written to /etc/ssh/ssh_known_hosts)", children: map[string]*schemaNode{
		"host": {desc: "Known host name or address", args: 1, placeholder: "<hostname>", children: nil},
	}},
	"policy-stats": {desc: "Security policy statistics", children: map[string]*schemaNode{
		"system-wide": {desc: "System-wide policy statistics (enable|disable)", args: 1, placeholder: "<enable|disable>", children: nil},
	}},
	"pre-id-default-policy": {desc: "Default policy before application identification", children: map[string]*schemaNode{
		"then": {desc: "Action", children: map[string]*schemaNode{
			"log": {desc: "Logging options", children: map[string]*schemaNode{
				"session-init":  {desc: "Log session creation", children: nil},
				"session-close": {desc: "Log session close", children: nil},
			}},
		}},
	}},
}}

var schemaApplications = &schemaNode{desc: "Applications", children: map[string]*schemaNode{
	"application": {desc: "Application name", args: 1, valueHint: ValueHintAppName, placeholder: "<name>", children: map[string]*schemaNode{
		"protocol":           {desc: "Protocol", args: 1, placeholder: "<protocol>", children: nil},
		"destination-port":   {desc: "Destination port", args: 1, placeholder: "<port>", children: nil},
		"source-port":        {desc: "Source port", args: 1, placeholder: "<port>", children: nil},
		"inactivity-timeout": {desc: "Inactivity timeout", args: 1, placeholder: "<seconds>", children: nil},
		"timeout":            {desc: "Timeout", args: 1, placeholder: "<seconds>", children: nil},
		"alg":                {desc: "Application layer gateway", args: 1, placeholder: "<alg>", children: nil},
		"description":        {desc: "Description", args: 1, placeholder: "<text>", children: nil},
		"term":               {desc: "Term", args: 1, placeholder: "<term>", children: nil},
	}},
	"application-set": {desc: "Application set", args: 1, valueHint: ValueHintAppSetName, placeholder: "<name>", children: nil},
}}
