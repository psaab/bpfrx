package config

// schema_interfaces.go carries the `interfaces` subtree of the
// config-mode grammar SSOT (#1891 domain split), plus the shared
// tunnel/wireguard subtree constructors it composes. The root
// composition, the schemaNode type, and the split rationale live in
// schema.go.

// #1319 PR 3 typed leaves (interfaces subsystem). Same fields-only
// discipline as the chassis PR 2 block: no children/args/multi
// changes, ranges derived from what the runtime actually consumes
// (cited per leaf). The `address` nodes use the typed-KEY-slot
// feature (keyValidator) because their value is a named-instance
// identity token, not a leaf value. Deliberately NOT typed:
// `unit <n>` / `vrrp-group <id>` instance ids (same deferral class
// as the chassis PR-2 redundancy-group/node ids: garbage ids make
// the compiler silently drop the instance, but these ids are
// cross-referenced from other subsystems — e.g. class-of-service
// `interfaces <if> unit <n>` — and deserve one dedicated pass that
// types every referencing slot together), `track-interface
// priority-cost`
// (already strict-rejected by the #1814 AST pre-walk in the
// compiler — typing here would shadow those curated errors), the
// dhcp/dhcpv6 client knobs and tunnel keepalives (deferred:
// low-risk pass-through integers), `speed`/`duplex`/`encapsulation`
// (free-form pass-through strings).
var schemaInterfaces = &schemaNode{desc: "Interface configuration", wildcard: &schemaNode{desc: "Interface name", valueHint: ValueHintInterfaceName, placeholder: "<interface-name>", children: map[string]*schemaNode{
	"description": {desc: "Text description of interface", args: 1, children: nil},
	// Compiled verbatim (compiler_interfaces.go:44, Atoi with the
	// error swallowed → garbage silently means "MTU not set", the
	// zero-value sentinel) and passed through to networkd MTUBytes=
	// and the dataplane interface snapshot. Min-only per the
	// no-schema-only-caps doctrine: the kernel/driver owns the real
	// ceiling and rejects loudly.
	"mtu": {
		desc:          "Maximum transmit packet size",
		args:          1,
		valueType:     ValueInteger,
		valueDesc:     "MTU in bytes (>= 1; kernel/driver enforces its own ceiling)",
		valueExamples: []string{"1500", "9000"},
		validator:     ValidateIntegerMin(1),
		children:      nil,
	},
	"speed":                 {desc: "Link speed", args: 1, children: nil},
	"duplex":                {desc: "Link duplex mode", args: 1, children: nil},
	"bandwidth":             {desc: "Interface bandwidth", args: 1, children: nil},
	"disable":               {desc: "Disable this interface", children: nil},
	"vlan-tagging":          {desc: "Enable 802.1Q VLAN tagging", children: nil},
	"flexible-vlan-tagging": {desc: "Enable flexible 802.1Q VLAN tagging (QinQ)", children: nil},
	"encapsulation":         {desc: "Physical link-layer encapsulation", args: 1, children: nil},
	"gigether-options": {desc: "Gigabit Ethernet interface options", children: map[string]*schemaNode{
		"redundant-parent": {desc: "Parent of this redundant interface", args: 1, children: nil},
		"802.3ad":          {desc: "Link aggregation group", args: 1, children: nil},
	}},
	"aggregated-ether-options": {desc: "Aggregated Ethernet interface options", children: map[string]*schemaNode{
		"lacp": {desc: "LACP parameters", children: map[string]*schemaNode{
			"active":   {desc: "Active LACP mode", children: nil},
			"passive":  {desc: "Passive LACP mode", children: nil},
			"periodic": {desc: "LACP timer period", args: 1, children: nil},
		}},
		"link-speed":    {desc: "Member link speed", args: 1, children: nil},
		"minimum-links": {desc: "Minimum active member links", args: 1, children: nil},
	}},
	"redundant-ether-options": {desc: "Redundant Ethernet interface options", children: map[string]*schemaNode{
		"redundancy-group": {desc: "Redundancy group for this RETH", args: 1, children: nil},
	}},
	"fabric-options": {desc: "Fabric interface options", children: map[string]*schemaNode{
		"member-interfaces": {desc: "Member interfaces", children: nil},
	}},
	"tunnel": {desc: "Tunnel parameters", children: tunnelSchemaChildren()},
	"unit": {desc: "Logical unit number", args: 1, valueHint: ValueHintUnitNumber, placeholder: "<unit-number>", children: map[string]*schemaNode{
		"description":    {desc: "Text description", args: 1, placeholder: "<text>", children: nil},
		"point-to-point": {desc: "Point-to-point interface", children: nil},
		// 802.1Q VID is a 12-bit wire field: 0 is the compiler's
		// "untagged" zero-value sentinel and 4095 is reserved, so
		// 1..4094 is exactly the usable range — the runtime creates
		// the sub-interface via netlink.Vlan{VlanId} (pkg/dataplane/
		// compiler_iface.go:96) and the kernel 8021q layer rejects
		// anything outside it. Compiled with the Atoi error
		// swallowed (compiler_interfaces.go:293/:302) — garbage
		// silently meant "no VLAN" before this gate.
		"vlan-id": {
			desc:          "VLAN ID",
			args:          1,
			placeholder:   "<number>",
			valueType:     ValueInteger,
			valueDesc:     "802.1Q VLAN ID (1..4094)",
			valueExamples: []string{"50", "80"},
			validator:     ValidateInteger(1, 4094),
			children:      nil,
		},
		"inner-vlan-id": {
			desc:          "Inner VLAN ID",
			args:          1,
			placeholder:   "<number>",
			valueType:     ValueInteger,
			valueDesc:     "Inner (QinQ) 802.1Q VLAN ID (1..4094)",
			valueExamples: []string{"100"},
			validator:     ValidateInteger(1, 4094),
			children:      nil,
		},
		"tunnel": {desc: "Tunnel parameters", children: tunnelSchemaChildren()},
		"family": {desc: "Protocol family", compoundKey: true, children: map[string]*schemaNode{
			"inet": {desc: "IPv4 protocol", children: map[string]*schemaNode{
				// Compiled verbatim (compiler_interfaces.go:539); same
				// pass-through contract as the interface-level mtu.
				"mtu": {
					desc:          "Maximum transmit packet size",
					args:          1,
					placeholder:   "<size>",
					valueType:     ValueInteger,
					valueDesc:     "MTU in bytes (>= 1; kernel/driver enforces its own ceiling)",
					valueExamples: []string{"1500"},
					validator:     ValidateIntegerMin(1),
					children:      nil,
				},
				// Typed KEY slot: the address value is this container's
				// identity token. Every runtime consumer net.ParseCIDRs
				// configured addresses and SILENTLY SKIPS unparseable
				// ones (dataplane snapshot interfaces.go:391-394,
				// networkd Address= lines, RETH/VIP/RA walks), so a
				// bare IP or typo committed fine and then didn't exist.
				// Family rule mirrors the runtime ip.To4() split.
				"address": {
					desc:             "IPv4 address",
					args:             1,
					placeholder:      "<address>",
					keyValueType:     ValueCIDR,
					keyValueDesc:     "IPv4 address with prefix length (e.g. 10.0.1.10/24)",
					keyValueExamples: []string{"10.0.1.10/24"},
					keyValidator:     ValidateIPv4CIDR,
					children: map[string]*schemaNode{
						"primary":   {desc: "Primary address", children: nil},
						"preferred": {desc: "Preferred address", children: nil},
						"vrrp-group": {desc: "VRRP group", args: 1, placeholder: "<group-id>", children: map[string]*schemaNode{
							// xpf-DIVERGENT from Junos (bare IP): the VIP
							// string is netlink.ParseAddr'd verbatim when
							// the group masters (pkg/vrrp/instance.go:1076)
							// and that parser REQUIRES a /prefix — a bare
							// Junos-style virtual-address still gets
							// advertised (sendAdvert strips an optional
							// prefix, instance.go:897) but the address is
							// never installed on the interface: a silent
							// half-working group. VRRPConfig documents the
							// CIDR contract (pkg/vrrp/vrrp.go:20).
							"virtual-address": {
								desc:          "Virtual IP address",
								args:          1,
								multi:         true,
								placeholder:   "<address>",
								valueType:     ValueCIDR,
								valueDesc:     "Virtual IPv4 address with prefix length (e.g. 10.0.1.1/24; xpf requires the prefix, unlike Junos)",
								valueExamples: []string{"10.0.1.1/24"},
								validator:     ValidateIPv4CIDR,
								children:      nil,
							},
							// VRRP priority is one wire byte
							// (pkg/vrrp/instance.go:918 uint8); 0 is the
							// "unset → default 100" compiler sentinel and
							// also the RFC 5798 resignation value, 255 is
							// the valid IP-owner priority (instance.go:256).
							// Junos: 1..255 — identical.
							"priority": {
								desc:          "VRRP priority",
								args:          1,
								placeholder:   "<1..255>",
								valueType:     ValueInteger,
								valueDesc:     "VRRP priority (1..255; 255 = address owner)",
								valueExamples: []string{"100", "200", "255"},
								validator:     ValidateInteger(1, 255),
								children:      nil,
							},
							"preempt":     {desc: "Allow preemption", children: nil},
							"accept-data": {desc: "Accept packets sent to the virtual address", children: nil},
							// Seconds. xpf-DIVERGENT from Junos (1..255 s):
							// the value is converted seconds→ms
							// (pkg/vrrp/vrrp.go:58) then ms→centiseconds
							// (instance.go:915) into the 12-bit VRRPv3
							// Max Advert Int field, so 40 s (4000 cs) is
							// the last whole-second value that encodes;
							// 41 s (4100 cs) overflows the 0x0FFF wire
							// mask and aliases. 0 = unset → default 1 s
							// (vrrp.go:55).
							"advertise-interval": {
								desc:          "Advertisement interval",
								args:          1,
								placeholder:   "<seconds>",
								valueType:     ValueInteger,
								valueDesc:     "Advertisement interval in seconds (1..40; VRRPv3 12-bit centisecond wire field — Junos allows up to 255)",
								valueExamples: []string{"1", "5"},
								validator:     ValidateInteger(1, 40),
								children:      nil,
							},
							"authentication-type": {desc: "Authentication type", args: 1, placeholder: "<type>", children: nil},
							"authentication-key":  {desc: "Authentication key", args: 1, placeholder: "<key>", children: nil},
							// priority-cost stays untyped: the #1814 AST
							// pre-walk in the compiler already strict-
							// rejects out-of-range costs with curated
							// errors (validateVRRPTrackInterfaceAST /
							// parseTrackCost, compiler_interfaces.go:791);
							// typing it here would shadow them.
							"track-interface": {desc: "Interface to track", args: 1, placeholder: "<interface>", children: map[string]*schemaNode{
								"priority-cost": {desc: "Priority cost subtracted while the tracked interface is down", args: 1, placeholder: "<1..254>", children: nil},
							}},
							"track-priority-cost": {desc: "Priority cost when tracked interface fails", args: 1, placeholder: "<cost>", children: nil},
						}},
					},
				},
				"dhcp": {desc: "DHCP client", children: map[string]*schemaNode{
					"lease-time":              {desc: "Lease time", args: 1, placeholder: "<seconds>", children: nil},
					"retransmission-attempt":  {desc: "Retransmission attempts", args: 1, placeholder: "<number>", children: nil},
					"retransmission-interval": {desc: "Retransmission interval", args: 1, placeholder: "<seconds>", children: nil},
					"force-discover":          {desc: "Force DHCP discover", children: nil},
				}},
				"sampling": {desc: "Traffic sampling", children: map[string]*schemaNode{
					"input":  {desc: "Sample input traffic", children: nil},
					"output": {desc: "Sample output traffic", children: nil},
				}},
				"filter": {desc: "Firewall filter", children: map[string]*schemaNode{
					"input":  {desc: "Input filter", args: 1, placeholder: "<filter-name>", children: nil},
					"output": {desc: "Output filter", args: 1, placeholder: "<filter-name>", children: nil},
				}},
			}},
			"inet6": {desc: "IPv6 protocol", children: map[string]*schemaNode{
				// Compiled at compiler_interfaces.go:578 (the lower of
				// the per-family values wins); same pass-through
				// contract as the interface-level mtu.
				"mtu": {
					desc:          "Maximum transmit packet size",
					args:          1,
					placeholder:   "<size>",
					valueType:     ValueInteger,
					valueDesc:     "MTU in bytes (>= 1; kernel/driver enforces its own ceiling)",
					valueExamples: []string{"1500"},
					validator:     ValidateIntegerMin(1),
					children:      nil,
				},
				"dad-disable": {desc: "Disable duplicate address detection", children: nil},
				// Typed KEY slot — see the family inet address comment.
				"address": {
					desc:             "IPv6 address",
					args:             1,
					placeholder:      "<address>",
					keyValueType:     ValueCIDR,
					keyValueDesc:     "IPv6 address with prefix length (e.g. 2001:db8::1/64)",
					keyValueExamples: []string{"2001:db8::1/64"},
					keyValidator:     ValidateIPv6CIDR,
					children: map[string]*schemaNode{
						"primary":   {desc: "Primary address", children: nil},
						"preferred": {desc: "Preferred address", children: nil},
					},
				},
				"sampling": {desc: "Traffic sampling", children: map[string]*schemaNode{
					"input":  {desc: "Sample input traffic", children: nil},
					"output": {desc: "Sample output traffic", children: nil},
				}},
				"filter": {desc: "Firewall filter", children: map[string]*schemaNode{
					"input":  {desc: "Input filter", args: 1, placeholder: "<filter-name>", children: nil},
					"output": {desc: "Output filter", args: 1, placeholder: "<filter-name>", children: nil},
				}},
				"dhcpv6-client": {desc: "DHCPv6 client", children: map[string]*schemaNode{
					"client-type":    {desc: "Client type", args: 1, placeholder: "<type>", children: nil},
					"client-ia-type": {desc: "Client IA type", args: 1, placeholder: "<type>", children: nil},
					"prefix-delegating": {desc: "Prefix delegation", children: map[string]*schemaNode{
						"preferred-prefix-length": {desc: "Preferred prefix length", args: 1, placeholder: "<length>", children: nil},
						"sub-prefix-length":       {desc: "Sub-prefix length", args: 1, placeholder: "<length>", children: nil},
					}},
					"client-identifier": {desc: "Client identifier", children: map[string]*schemaNode{
						"duid-type": {desc: "DUID type", args: 1, placeholder: "<type>", children: nil},
					}},
					"req-option": {desc: "Request option", args: 1, placeholder: "<option>", children: nil},
					"update-router-advertisement": {desc: "Update router advertisement", children: map[string]*schemaNode{
						"interface": {desc: "Interface", args: 1, placeholder: "<interface>", children: nil},
					}},
				}},
			}},
		}},
	}},
}}}

// tunnelSchemaChildren returns the config-mode schema children for the
// `tunnel { ... }` stanza, shared between the physical-interface and
// unit-level positions (the compiler parses both with the same property
// switch, compiler_interfaces.go:153 / :241). #1319 PR 3 typed leaves:
//
//   - source / destination: the runtime net.ParseIPs both families
//     (pkg/routing/tunnel.go:194-195; Gretun auto-selects gre vs ip6gre)
//     and an unparseable address silently skips tunnel creation.
//   - ttl: stored verbatim by the compiler, then truncated to the
//     netlink uint8 Ttl field (tunnel.go:218/:226/:235) — 256 would
//     silently wrap to 0. 0 = unset; the runtime substitutes its
//     default of 64 (tunnel.go:202-205), not the kernel inherit
//     behaviour (AGY r1 Low on PR #1886).
//   - key: compiled via uint32(Atoi) (compiler_interfaces.go:168/:262),
//     so negatives and values past 2^32-1 silently wrap; the GRE key
//     wire field (IKey/OKey, tunnel.go:238-239) is exactly 32 bits.
//   - keepalive / keepalive-retry: deliberately untyped (pass-through
//     integers consumed by the keepalive prober only when > 0).
func tunnelSchemaChildren() map[string]*schemaNode {
	return map[string]*schemaNode{
		"source": {
			desc:          "Tunnel source address",
			args:          1,
			placeholder:   "<address>",
			valueType:     ValueIPAddress,
			valueDesc:     "Tunnel source IP address (IPv4 or IPv6)",
			valueExamples: []string{"10.0.2.10", "2001:db8::1"},
			validator:     ValidateIPAddress,
			children:      nil,
		},
		"destination": {
			desc:          "Tunnel destination address",
			args:          1,
			placeholder:   "<address>",
			valueType:     ValueIPAddress,
			valueDesc:     "Tunnel destination IP address (IPv4 or IPv6)",
			valueExamples: []string{"192.0.2.1", "2001:db8::2"},
			validator:     ValidateIPAddress,
			children:      nil,
		},
		"mode": {desc: "Tunnel mode", args: 1, placeholder: "<mode>", children: nil},
		"key": {
			desc:          "Tunnel key",
			args:          1,
			placeholder:   "<key>",
			valueType:     ValueInteger,
			valueDesc:     "GRE key (0..4294967295; 32-bit wire field)",
			valueExamples: []string{"100"},
			validator:     ValidateInteger(0, 4294967295),
			children:      nil,
		},
		"ttl": {
			desc:          "Time to live",
			args:          1,
			placeholder:   "<number>",
			valueType:     ValueInteger,
			valueDesc:     "Tunnel TTL (0..255; 0 = use the default 64, one wire byte)",
			valueExamples: []string{"64"},
			validator:     ValidateInteger(0, 255),
			children:      nil,
		},
		"keepalive":       {desc: "Keepalive interval", args: 1, placeholder: "<seconds>", children: nil},
		"keepalive-retry": {desc: "Keepalive retry count", args: 1, placeholder: "<number>", children: nil},
		"routing-instance": {desc: "Routing instance", children: map[string]*schemaNode{
			"destination": {desc: "Destination routing instance", args: 1, placeholder: "<name>", children: nil},
		}},
		"wireguard": wireguardSchemaNode(),
	}
}

// wireguardSchemaNode returns the config-mode schema subtree for the
// `tunnel wireguard { ... }` stanza (#1432 S2a). Minimal generic
// surface — listen-port / private-key / peer{public-key, allowed-ips,
// endpoint, persistent-keepalive}. See parseTunnelWireguard in
// compiler_interfaces.go for the matching parse.
//
// #1319 PR 3: listen-port and persistent-keepalive carry exactly the
// bounds the compiler enforces SILENTLY today — parseTunnelWireguard
// accepts only 1..65535 (compiler_interfaces.go:689) and
// parseTunnelWireguardPeer only 0..65535 (:720), dropping anything else
// without a trace. The typed leaves turn that silent drop into a commit
// rejection.
func wireguardSchemaNode() *schemaNode {
	return &schemaNode{
		desc: "WireGuard tunnel parameters",
		children: map[string]*schemaNode{
			"listen-port": {
				desc:          "UDP listen port",
				args:          1,
				placeholder:   "<port>",
				valueType:     ValueInteger,
				valueDesc:     "UDP listen port (1..65535)",
				valueExamples: []string{"51820"},
				validator:     ValidateInteger(1, 65535),
				children:      nil,
			},
			"private-key": {desc: "Local static private key (hex)", args: 1, placeholder: "<hex-key>", children: nil},
			// peer is a NAMED-INSTANCE container keyed by the peer's
			// public key (#1434 multi-peer): `peer <public-key> { ... }`.
			// Modeled on vrrp-group (args:1 with a child block). A WG
			// tunnel may carry N peers; the identity IS the pubkey, so
			// it moves to the instance arg (no separate public-key
			// child). The compiler hard-rejects duplicate pubkeys at
			// commit (schema_walk.go validateWireguardPeers).
			"peer": {desc: "WireGuard peer (keyed by public key)", args: 1, placeholder: "<public-key>", children: map[string]*schemaNode{
				"allowed-ips": {desc: "Peer allowed IPs (CIDR)", args: 1, multi: true, placeholder: "<prefix>", children: nil},
				"endpoint":    {desc: "Peer endpoint (ip:port)", args: 1, placeholder: "<ip:port>", children: nil},
				"persistent-keepalive": {
					desc:          "Persistent keepalive seconds",
					args:          1,
					placeholder:   "<seconds>",
					valueType:     ValueInteger,
					valueDesc:     "Persistent keepalive interval in seconds (0..65535; 0 = disabled)",
					valueExamples: []string{"25"},
					validator:     ValidateInteger(0, 65535),
					children:      nil,
				},
				"preshared-key": {desc: "Per-peer preshared key (hex)", args: 1, placeholder: "<hex-key>", children: nil},
			}},
		},
	}
}
