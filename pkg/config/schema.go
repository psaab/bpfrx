package config

// schema.go owns the config-mode `set`/`delete`/`show`/`edit` grammar
// definition — the single source of truth (SSOT) for the Junos
// configuration hierarchy. It defines the `schemaNode` container type and
// the `setSchema` literal that drives four things off one tree: structural
// completion, flat-set token grouping (SetPath, ast_edit.go), value-slot
// `?` completion (schema_complete.go), and commit-check typed-leaf
// validation (SchemaValidate, schema_walk.go). See docs/config-schema.md.
//
// This file was split out of ast.go in #1699: the AST node types and tree
// navigation (the parser's data model) stay in ast.go; the grammar SSOT
// lives here alongside the rest of the schema_* family (schema_walk.go,
// schema_validators.go, value_type.go); the procedural completion / path
// resolution helpers live in schema_complete.go.

// schemaNode defines a container keyword in the Junos config hierarchy.
// It tells SetPath how to group flat path tokens into the correct tree structure.
type schemaNode struct {
	args         int                    // extra tokens consumed as part of this node's key
	children     map[string]*schemaNode // known container children
	wildcard     *schemaNode            // matches any keyword not in children (for dynamic names)
	multi        bool                   // true = multiple leaf values allowed (e.g. source-address); false = replace on set
	valueHint    ValueHint              // hint for dynamic value completion (when args > 0)
	desc         string                 // description shown in completion help
	placeholder  string                 // Junos-style placeholder (e.g., "<interface-name>")
	midKeyword   string                 // fixed keyword in the middle of args (e.g., "to-zone")
	midKeywordAt int                    // 1-based arg position where midKeyword appears (e.g., 2 for "from-zone X to-zone Y")
	compoundKey  bool                   // children form compound key (e.g., "family inet6" → Keys=["family","inet6"])

	// Typed-leaf metadata (#1319). The zero value (valueType==ValueAny,
	// validator==nil) is the legacy behaviour: any string accepted, no
	// schema-time validation, no value-slot examples in `?` completion.
	// Setting valueType to a non-ValueAny value opts this leaf in to both
	// the completion path (CompleteSetPathWithValues surfaces valueDesc +
	// valueExamples + the placeholder) and the validation path
	// (SchemaValidate invokes validator at commit-check time). Because the
	// completion path and the validation path read the SAME node, the two
	// cannot drift — that is the central design property of Option A.
	//
	// IMPORTANT: adding these fields is additive and does not affect
	// SetPath grouping, which keys only on args/children/compoundKey/multi
	// (ast_edit.go). A schemaNode MUST NOT gain a children map purely to
	// carry typed-leaf metadata: SetPath's replace-vs-container decision
	// keys on children==nil (ast_edit.go:196), so flipping a leaf to a
	// container is a grouping regression. Type the value via these fields,
	// not via new children.
	valueType     ValueType     // non-ValueAny marks a typed value slot
	valueDesc     string        // one-line value-slot description for `?` help
	valueExamples []string      // illustrative values surfaced in `?` help
	validator     LeafValidator // commit-check validator for the value slot

	// treeValidator is the TREE-based cross-reference alternative to
	// validator (#1319 PR 3): it validates the value against
	// definitions collected from the candidate tree itself
	// (collectSchemaRefs → schemaRefs), because SchemaValidate's cfg is
	// always nil in production — validation runs BEFORE compile. A
	// typed leaf sets EITHER validator OR treeValidator, never both.
	treeValidator treeLeafValidator

	// Typed KEY slot (#1319 PR 3). A named-instance CONTAINER (args > 0
	// with a children map, e.g. `family inet address <cidr> { primary; }`)
	// carries its value in the IDENTITY token, not in a leaf value slot —
	// the walker consumes identity tokens without validation by default
	// (the compiler-faithful contract from PR 2). Setting keyValidator
	// opts the identity arg token(s) in to commit-check validation, and
	// keyValueType/keyValueDesc/keyValueExamples surface in `?` completion
	// for the empty key slot. The regular valueType/validator fields MUST
	// stay unset on such a node: setting valueType would flip the walker
	// into the typed-LEAF branch, which treats children as modifiers and
	// would mis-validate the container's real block children. Not
	// supported on midKeyword nodes (no current need).
	keyValueType     ValueType     // non-ValueAny marks a typed identity-arg slot
	keyValueDesc     string        // one-line key-slot description for `?` help
	keyValueExamples []string      // illustrative key values surfaced in `?` help
	keyValidator     LeafValidator // commit-check validator for identity arg tokens
}

// isTypedLeaf reports whether the node carries typed-value metadata
// (a non-default valueType), i.e. it expects exactly one typed value at
// its first non-modifier slot.
func (n *schemaNode) isTypedLeaf() bool {
	return n != nil && n.valueType != ValueAny
}

// setSchema defines the Junos configuration tree structure.
// Keywords present in the schema at a given depth are treated as containers.
// Keywords NOT in the schema become leaf nodes (all remaining tokens form the leaf's Keys).
var setSchema = &schemaNode{children: map[string]*schemaNode{
	"groups":       {wildcard: &schemaNode{}}, // children set in init()
	"apply-groups": {desc: "Groups from which to inherit configuration data", args: 1, multi: true, placeholder: "<group-name>", children: nil},
	"security": {desc: "Security configuration", children: map[string]*schemaNode{
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
						"source-address":      {desc: "Source address", args: 1, multi: true, valueHint: ValueHintPolicyAddress, placeholder: "<address>", children: nil},
						"destination-address": {desc: "Destination address", args: 1, multi: true, valueHint: ValueHintPolicyAddress, placeholder: "<address>", children: nil},
						"application":         {desc: "Application", args: 1, multi: true, valueHint: ValueHintPolicyApp, placeholder: "<application>", children: nil},
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
						"source-address":      {desc: "Source address", args: 1, multi: true, valueHint: ValueHintPolicyAddress, placeholder: "<address>", children: nil},
						"destination-address": {desc: "Destination address", args: 1, multi: true, valueHint: ValueHintPolicyAddress, placeholder: "<address>", children: nil},
						"application":         {desc: "Application", args: 1, multi: true, valueHint: ValueHintPolicyApp, placeholder: "<application>", children: nil},
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
		"nat": {children: map[string]*schemaNode{
			"source": {children: map[string]*schemaNode{
				"pool":               {args: 1, valueHint: ValueHintPoolName, children: nil},
				"address-persistent": {children: nil},
				"rule-set": {args: 1, children: map[string]*schemaNode{
					"from": {children: map[string]*schemaNode{
						"zone": {args: 1, valueHint: ValueHintZoneName, children: nil},
					}},
					"to": {children: map[string]*schemaNode{
						"zone": {args: 1, valueHint: ValueHintZoneName, children: nil},
					}},
					"rule": {args: 1, children: map[string]*schemaNode{
						"match": {children: map[string]*schemaNode{
							"source-address":      {args: 1, multi: true, children: nil},
							"destination-address": {args: 1, multi: true, children: nil},
							"destination-port":    {args: 1, multi: true, children: nil},
							"application":         {args: 1, multi: true, children: nil},
						}},
						"then": {children: map[string]*schemaNode{
							"source-nat": {children: map[string]*schemaNode{
								"interface": {children: nil},
								"off":       {children: nil},
								"pool":      {args: 1, valueHint: ValueHintPoolName, children: nil},
							}},
						}},
					}},
				}},
			}},
			"destination": {children: map[string]*schemaNode{
				"pool": {args: 1, valueHint: ValueHintPoolName, children: nil},
				"rule-set": {args: 1, children: map[string]*schemaNode{
					"from": {children: map[string]*schemaNode{
						"zone": {args: 1, valueHint: ValueHintZoneName, children: nil},
					}},
					"to": {children: map[string]*schemaNode{
						"zone": {args: 1, valueHint: ValueHintZoneName, children: nil},
					}},
					"rule": {args: 1, children: map[string]*schemaNode{
						"match": {children: map[string]*schemaNode{
							"source-address":      {args: 1, multi: true, children: nil},
							"source-address-name": {args: 1, multi: true, children: nil},
							"destination-address": {args: 1, multi: true, children: nil},
							"destination-port":    {args: 1, multi: true, children: nil},
							"protocol":            {args: 1, multi: true, children: nil},
							"application":         {args: 1, multi: true, children: nil},
						}},
						"then": {children: map[string]*schemaNode{
							"destination-nat": {children: map[string]*schemaNode{
								"pool": {args: 1, valueHint: ValueHintPoolName, children: nil},
							}},
						}},
					}},
				}},
			}},
			"static": {children: map[string]*schemaNode{
				"rule-set": {args: 1, children: map[string]*schemaNode{
					"rule": {args: 1, children: map[string]*schemaNode{
						"match": {children: nil},
						"then": {children: map[string]*schemaNode{
							"static-nat": {children: nil},
						}},
					}},
				}},
			}},
			"nat64": {children: map[string]*schemaNode{
				"rule-set": {args: 1, children: map[string]*schemaNode{
					"prefix":      {args: 1, children: nil},
					"source-pool": {args: 1, children: nil},
				}},
			}},
			"natv6v4": {children: map[string]*schemaNode{
				"no-v6-frag-header": {children: nil},
			}},
			"proxy-arp": {children: map[string]*schemaNode{
				"interface": {args: 1, valueHint: ValueHintInterfaceName, children: map[string]*schemaNode{
					"address": {args: 1, multi: true, children: nil},
				}},
			}},
		}},
		"address-book": {children: map[string]*schemaNode{
			"global": {children: map[string]*schemaNode{
				"address": {args: 2, multi: true, children: nil},
				"address-set": {args: 1, valueHint: ValueHintAddressName, children: map[string]*schemaNode{
					"address":     {args: 1, multi: true, children: nil},
					"address-set": {args: 1, multi: true, valueHint: ValueHintAddressName, children: nil},
					"description": {args: 1, children: nil},
				}},
			}},
		}},
		"log": {children: map[string]*schemaNode{
			"mode":             {args: 1, children: nil},
			"format":           {args: 1, children: nil},
			"source-interface": {args: 1, valueHint: ValueHintInterfaceName, children: nil},
			"stream": {args: 1, valueHint: ValueHintStreamName, children: map[string]*schemaNode{
				"host":           {args: 1, children: nil},
				"port":           {args: 1, children: nil},
				"severity":       {args: 1, children: nil},
				"facility":       {args: 1, children: nil},
				"format":         {args: 1, children: nil},
				"category":       {args: 1, children: nil},
				"source-address": {args: 1, children: nil},
			}},
		}},
		"flow": {children: map[string]*schemaNode{
			"aging":                        {children: nil},
			"tcp-session":                  {children: nil},
			"udp-session":                  {children: nil},
			"icmp-session":                 {children: nil},
			"tcp-mss":                      {children: nil},
			"allow-dns-reply":              {children: nil},
			"allow-embedded-icmp":          {children: nil},
			"gre-performance-acceleration": {children: nil},
			"power-mode-disable":           {children: nil},
			"traceoptions": {children: map[string]*schemaNode{
				"file": {args: 1, children: nil},
				"flag": {args: 1, children: nil},
				"packet-filter": {args: 1, children: map[string]*schemaNode{
					"source-prefix":      {args: 1, children: nil},
					"destination-prefix": {args: 1, children: nil},
				}},
			}},
		}},
		"alg": {children: map[string]*schemaNode{
			"dns":  {children: nil},
			"ftp":  {children: nil},
			"sip":  {children: nil},
			"tftp": {children: nil},
		}},
		"ike": {children: map[string]*schemaNode{
			"proposal": {args: 1, children: nil},
			"policy": {args: 1, children: map[string]*schemaNode{
				"mode":           {args: 1, children: nil},
				"proposals":      {args: 1, children: nil},
				"pre-shared-key": {children: nil},
			}},
			"gateway": {args: 1, children: map[string]*schemaNode{
				"address":            {args: 1, children: nil},
				"local-address":      {args: 1, children: nil},
				"ike-policy":         {args: 1, children: nil},
				"external-interface": {args: 1, children: nil},
				"local-certificate":  {args: 1, children: nil},
				"version":            {args: 1, children: nil},
				"no-nat-traversal":   {children: nil},
				"nat-traversal":      {args: 1, children: nil},
				"dead-peer-detection": {children: map[string]*schemaNode{
					"always-send":       {children: nil},
					"optimized":         {children: nil},
					"probe-idle-tunnel": {children: nil},
					"interval":          {args: 1, children: nil},
					"threshold":         {args: 1, children: nil},
				}},
				"local-identity":  {children: nil},
				"remote-identity": {children: nil},
				"dynamic":         {children: nil},
			}},
		}},
		"ipsec": {children: map[string]*schemaNode{
			"proposal": {args: 1, children: nil},
			"policy": {args: 1, children: map[string]*schemaNode{
				"perfect-forward-secrecy": {children: nil},
				"proposals":               {args: 1, children: nil},
			}},
			"gateway": {args: 1, children: map[string]*schemaNode{
				"address":            {args: 1, children: nil},
				"local-address":      {args: 1, children: nil},
				"ike-policy":         {args: 1, children: nil},
				"external-interface": {args: 1, children: nil},
				"local-certificate":  {args: 1, children: nil},
				"version":            {args: 1, children: nil},
				"no-nat-traversal":   {children: nil},
				"nat-traversal":      {args: 1, children: nil},
				"dead-peer-detection": {children: map[string]*schemaNode{
					"always-send":       {children: nil},
					"optimized":         {children: nil},
					"probe-idle-tunnel": {children: nil},
					"interval":          {args: 1, children: nil},
					"threshold":         {args: 1, children: nil},
				}},
				"local-identity":  {children: nil},
				"remote-identity": {children: nil},
				"dynamic":         {children: nil},
			}},
			"vpn": {args: 1, children: map[string]*schemaNode{
				"bind-interface":    {args: 1, children: nil},
				"df-bit":            {args: 1, children: nil},
				"establish-tunnels": {args: 1, children: nil},
				"local-identity":    {args: 1, children: nil},
				"remote-identity":   {args: 1, children: nil},
				"pre-shared-key":    {args: 1, children: nil},
				"local-address":     {args: 1, children: nil},
				"traffic-selector": {args: 1, children: map[string]*schemaNode{
					"local-ip":  {args: 1, children: nil},
					"remote-ip": {args: 1, children: nil},
				}},
				"ike": {children: map[string]*schemaNode{
					"gateway":      {args: 1, children: nil},
					"ipsec-policy": {args: 1, children: nil},
				}},
			}},
		}},
		"dynamic-address": {children: map[string]*schemaNode{
			"feed-server": {args: 1, children: map[string]*schemaNode{
				"url":             {args: 1, children: nil},
				"hostname":        {args: 1, children: nil},
				"update-interval": {args: 1, children: nil},
				"hold-interval":   {args: 1, children: nil},
				"feed-name": {args: 1, children: map[string]*schemaNode{
					"path": {args: 1, children: nil},
				}},
			}},
			"address-name": {args: 1, children: map[string]*schemaNode{
				"profile": {children: map[string]*schemaNode{
					"feed-name": {args: 1, children: nil},
				}},
			}},
		}},
		"ssh-known-hosts": {children: map[string]*schemaNode{
			"host": {args: 1, children: nil},
		}},
		"policy-stats": {children: map[string]*schemaNode{
			"system-wide": {args: 1, children: nil},
		}},
		"pre-id-default-policy": {children: map[string]*schemaNode{
			"then": {children: map[string]*schemaNode{
				"log": {children: map[string]*schemaNode{
					"session-init":  {children: nil},
					"session-close": {children: nil},
				}},
			}},
		}},
	}},
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
	"interfaces": {desc: "Interface configuration", wildcard: &schemaNode{desc: "Interface name", valueHint: ValueHintInterfaceName, placeholder: "<interface-name>", children: map[string]*schemaNode{
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
	}}},
	"applications": {desc: "Applications", children: map[string]*schemaNode{
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
	}},
	"routing-options": {desc: "Routing options", children: map[string]*schemaNode{
		"static": {desc: "Static routes", children: map[string]*schemaNode{
			"route": {desc: "Static route", args: 1, placeholder: "<destination>", children: nil},
		}},
		"rib": {desc: "Routing information base", args: 1, placeholder: "<rib-name>", children: map[string]*schemaNode{
			"static": {desc: "Static routes", children: map[string]*schemaNode{
				"route": {desc: "Static route", args: 1, placeholder: "<destination>", children: nil},
			}},
		}},
		"autonomous-system": {desc: "Autonomous system number", args: 1, placeholder: "<as-number>", children: nil},
		"forwarding-table": {desc: "Forwarding table", children: map[string]*schemaNode{
			"export": {desc: "Export policy", args: 1, multi: true, placeholder: "<policy>", children: nil},
		}},
		"rib-groups": {desc: "RIB groups", wildcard: &schemaNode{desc: "RIB group name", placeholder: "<group-name>", children: map[string]*schemaNode{
			"import-rib": {desc: "Import RIB", children: nil},
		}}},
		"interface-routes": {desc: "Interface routes", children: map[string]*schemaNode{
			"rib-group": {desc: "RIB group", children: map[string]*schemaNode{
				"inet":  {desc: "IPv4 RIB group", args: 1, placeholder: "<group-name>", children: nil},
				"inet6": {desc: "IPv6 RIB group", args: 1, placeholder: "<group-name>", children: nil},
			}},
		}},
		"generate": {desc: "Generated routes", children: map[string]*schemaNode{
			"route": {desc: "Generated route", args: 1, placeholder: "<destination>", children: map[string]*schemaNode{
				"policy":  {desc: "Policy", args: 1, placeholder: "<policy>", children: nil},
				"discard": {desc: "Discard route", children: nil},
			}},
		}},
	}},
	"snmp": {desc: "SNMP configuration", children: map[string]*schemaNode{
		"community": {desc: "SNMP community", args: 1, placeholder: "<community-name>", children: map[string]*schemaNode{
			"authorization": {desc: "Authorization level", args: 1, placeholder: "<level>", children: nil},
		}},
		"trap-group": {desc: "Trap group", args: 1, placeholder: "<group-name>", children: nil},
		"v3": {desc: "SNMPv3", children: map[string]*schemaNode{
			"usm": {desc: "USM", children: map[string]*schemaNode{
				"local-engine": {desc: "Local engine", children: map[string]*schemaNode{
					"user": {desc: "User name", args: 1, placeholder: "<user-name>", children: map[string]*schemaNode{
						"authentication-md5":    {desc: "MD5 authentication", children: map[string]*schemaNode{"authentication-password": {desc: "Password", args: 1, placeholder: "<password>", children: nil}}},
						"authentication-sha":    {desc: "SHA authentication", children: map[string]*schemaNode{"authentication-password": {desc: "Password", args: 1, placeholder: "<password>", children: nil}}},
						"authentication-sha256": {desc: "SHA256 authentication", children: map[string]*schemaNode{"authentication-password": {desc: "Password", args: 1, placeholder: "<password>", children: nil}}},
						"privacy-des":           {desc: "DES privacy", children: map[string]*schemaNode{"privacy-password": {desc: "Password", args: 1, placeholder: "<password>", children: nil}}},
						"privacy-aes128":        {desc: "AES128 privacy", children: map[string]*schemaNode{"privacy-password": {desc: "Password", args: 1, placeholder: "<password>", children: nil}}},
					}},
				}},
			}},
		}},
	}},
	"policy-options": {desc: "Policy options", children: map[string]*schemaNode{
		"prefix-list": {desc: "Prefix list", args: 1, placeholder: "<name>", children: nil},
		"community": {desc: "Community", args: 1, placeholder: "<name>", children: map[string]*schemaNode{
			"members": {desc: "Community members", args: 1, multi: true, placeholder: "<community>", children: nil},
		}},
		"as-path": {desc: "AS path", args: 2, multi: true, placeholder: "<name>", children: nil},
		"policy-statement": {desc: "Policy statement", args: 1, placeholder: "<name>", children: map[string]*schemaNode{
			"term": {desc: "Term name", args: 1, placeholder: "<term-name>", children: map[string]*schemaNode{
				"from": {desc: "Match condition", children: map[string]*schemaNode{
					"protocol":     {desc: "Protocol", args: 1, placeholder: "<protocol>", children: nil},
					"prefix-list":  {desc: "Prefix list", args: 1, placeholder: "<list-name>", children: nil},
					"route-filter": {desc: "Route filter", args: 2, placeholder: "<prefix>", children: nil},
					"community":    {desc: "Community", args: 1, placeholder: "<community>", children: nil},
					"as-path":      {desc: "AS path", args: 1, placeholder: "<name>", children: nil},
				}},
				"then": {desc: "Action", children: map[string]*schemaNode{
					"accept":           {desc: "Accept route", children: nil},
					"reject":           {desc: "Reject route", children: nil},
					"next-hop":         {desc: "Next hop", args: 1, placeholder: "<address>", children: nil},
					"load-balance":     {desc: "Load balance", args: 1, placeholder: "<policy>", children: nil},
					"local-preference": {desc: "Local preference", args: 1, placeholder: "<value>", children: nil},
					"metric":           {desc: "Metric", args: 1, placeholder: "<value>", children: nil},
					"metric-type":      {desc: "Metric type", args: 1, placeholder: "<type>", children: nil},
					"community":        {desc: "Community", args: 1, placeholder: "<community>", children: nil},
					"origin":           {desc: "Origin", args: 1, placeholder: "<origin>", children: nil},
				}},
			}},
			"then": {desc: "Default action", children: nil},
		}},
	}},
	"protocols": {desc: "Protocols configuration", children: map[string]*schemaNode{
		"ospf": {desc: "OSPF configuration", children: map[string]*schemaNode{
			"router-id":           {desc: "Router ID", args: 1, placeholder: "<address>", children: nil},
			"reference-bandwidth": {desc: "Reference bandwidth", args: 1, placeholder: "<bandwidth>", children: nil},
			"passive":             {desc: "Passive mode", children: nil},
			"export":              {desc: "Export policy", args: 1, multi: true, placeholder: "<policy-name>", children: nil},
			"area": {desc: "OSPF area", args: 1, placeholder: "<area-id>", children: map[string]*schemaNode{
				"interface": {desc: "Interface", args: 1, valueHint: ValueHintInterfaceName, placeholder: "<interface-name>", children: map[string]*schemaNode{
					"passive":        {desc: "Passive interface", children: nil},
					"no-passive":     {desc: "Non-passive interface", children: nil},
					"interface-type": {desc: "Interface type", args: 1, placeholder: "<type>", children: nil},
					"cost":           {desc: "Interface cost", args: 1, placeholder: "<cost>", children: nil},
					"authentication": {desc: "Authentication", children: map[string]*schemaNode{
						"md5": {desc: "MD5 authentication", args: 1, placeholder: "<key-id>", children: map[string]*schemaNode{
							"key": {desc: "Authentication key", args: 1, placeholder: "<key>", children: nil},
						}},
						"simple-password": {desc: "Simple password", args: 1, placeholder: "<password>", children: nil},
					}},
					"bfd-liveness-detection": {desc: "BFD liveness detection", children: map[string]*schemaNode{
						"minimum-interval": {desc: "Minimum interval", args: 1, placeholder: "<milliseconds>", children: nil},
						"multiplier":       {desc: "Multiplier", args: 1, placeholder: "<multiplier>", children: nil},
					}},
				}},
				"area-type": {desc: "Area type", children: map[string]*schemaNode{
					"stub": {desc: "Stub area", children: map[string]*schemaNode{
						"no-summaries": {desc: "No summaries", children: nil},
					}},
					"nssa": {desc: "NSSA area", children: map[string]*schemaNode{
						"no-summaries": {desc: "No summaries", children: nil},
					}},
				}},
				"virtual-link": {desc: "Virtual link", args: 1, placeholder: "<router-id>", children: map[string]*schemaNode{
					"transit-area": {desc: "Transit area", args: 1, placeholder: "<area-id>", children: nil},
				}},
			}},
		}},
		"ospf3": {desc: "OSPFv3 configuration", children: map[string]*schemaNode{
			"router-id": {desc: "Router ID", args: 1, placeholder: "<address>", children: nil},
			"export":    {desc: "Export policy", args: 1, multi: true, placeholder: "<policy-name>", children: nil},
			"area": {desc: "OSPFv3 area", args: 1, placeholder: "<area-id>", children: map[string]*schemaNode{
				"interface": {desc: "Interface", args: 1, valueHint: ValueHintInterfaceName, placeholder: "<interface-name>", children: map[string]*schemaNode{
					"passive": {desc: "Passive interface", children: nil},
					"cost":    {desc: "Interface cost", args: 1, placeholder: "<cost>", children: nil},
				}},
			}},
		}},
		"bgp": {desc: "BGP configuration", children: map[string]*schemaNode{
			"local-as":         {desc: "Local AS number", args: 1, placeholder: "<as-number>", children: nil},
			"router-id":        {desc: "Router ID", args: 1, placeholder: "<address>", children: nil},
			"cluster-id":       {desc: "Cluster ID", args: 1, placeholder: "<id>", children: nil},
			"graceful-restart": {desc: "Graceful restart", children: nil},
			"log-updown":       {desc: "Log up/down events", children: nil},
			"multipath": {desc: "Multipath", children: map[string]*schemaNode{
				"multiple-as": {desc: "Multiple AS", children: nil},
			}},
			"damping": {desc: "Route damping", children: map[string]*schemaNode{
				"half-life":    {desc: "Half life", args: 1, placeholder: "<minutes>", children: nil},
				"reuse":        {desc: "Reuse threshold", args: 1, placeholder: "<value>", children: nil},
				"suppress":     {desc: "Suppress threshold", args: 1, placeholder: "<value>", children: nil},
				"max-suppress": {desc: "Max suppress time", args: 1, placeholder: "<minutes>", children: nil},
			}},
			"export": {desc: "Export policy", args: 1, multi: true, placeholder: "<policy-name>", children: nil},
			"group": {desc: "BGP group", args: 1, placeholder: "<group-name>", children: map[string]*schemaNode{
				"peer-as":            {desc: "Peer AS number", args: 1, placeholder: "<as-number>", children: nil},
				"description":        {desc: "Description", args: 1, placeholder: "<text>", children: nil},
				"multihop":           {desc: "Multihop TTL", args: 1, placeholder: "<ttl>", children: nil},
				"export":             {desc: "Export policy", args: 1, multi: true, placeholder: "<policy-name>", children: nil},
				"authentication-key": {desc: "Authentication key", args: 1, placeholder: "<key>", children: nil},
				"default-originate":  {desc: "Default originate", children: nil},
				"loops":              {desc: "Loops", args: 1, placeholder: "<count>", children: nil},
				"remove-private":     {desc: "Remove private AS", children: nil},
				"family": {desc: "Address family", compoundKey: true, children: map[string]*schemaNode{
					"inet": {desc: "IPv4", children: map[string]*schemaNode{
						"unicast": {desc: "Unicast", children: map[string]*schemaNode{
							"prefix-limit": {desc: "Prefix limit", children: map[string]*schemaNode{
								"maximum": {desc: "Maximum prefixes", args: 1, placeholder: "<count>", children: nil},
							}},
						}},
					}},
					"inet6": {desc: "IPv6", children: map[string]*schemaNode{
						"unicast": {desc: "Unicast", children: map[string]*schemaNode{
							"prefix-limit": {desc: "Prefix limit", children: map[string]*schemaNode{
								"maximum": {desc: "Maximum prefixes", args: 1, placeholder: "<count>", children: nil},
							}},
						}},
					}},
				}},
				"bfd-liveness-detection": {desc: "BFD liveness detection", children: map[string]*schemaNode{
					"minimum-interval": {desc: "Minimum interval", args: 1, placeholder: "<milliseconds>", children: nil},
					"multiplier":       {desc: "Multiplier", args: 1, placeholder: "<multiplier>", children: nil},
				}},
				"neighbor": {desc: "BGP neighbor", args: 1, placeholder: "<address>", children: map[string]*schemaNode{
					"description":            {desc: "Description", args: 1, placeholder: "<text>", children: nil},
					"peer-as":                {desc: "Peer AS number", args: 1, placeholder: "<as-number>", children: nil},
					"multihop":               {desc: "Multihop TTL", args: 1, placeholder: "<ttl>", children: nil},
					"authentication-key":     {desc: "Authentication key", args: 1, placeholder: "<key>", children: nil},
					"route-reflector-client": {desc: "Route reflector client", children: nil},
					"default-originate":      {desc: "Default originate", children: nil},
					"loops":                  {desc: "Loops", args: 1, placeholder: "<count>", children: nil},
					"remove-private":         {desc: "Remove private AS", children: nil},
					"family": {desc: "Address family", compoundKey: true, children: map[string]*schemaNode{
						"inet": {desc: "IPv4", children: map[string]*schemaNode{
							"unicast": {desc: "Unicast", children: map[string]*schemaNode{
								"prefix-limit": {desc: "Prefix limit", children: map[string]*schemaNode{
									"maximum": {desc: "Maximum prefixes", args: 1, placeholder: "<count>", children: nil},
								}},
							}},
						}},
						"inet6": {desc: "IPv6", children: map[string]*schemaNode{
							"unicast": {desc: "Unicast", children: map[string]*schemaNode{
								"prefix-limit": {desc: "Prefix limit", children: map[string]*schemaNode{
									"maximum": {desc: "Maximum prefixes", args: 1, placeholder: "<count>", children: nil},
								}},
							}},
						}},
					}},
					"bfd-liveness-detection": {desc: "BFD liveness detection", children: map[string]*schemaNode{
						"minimum-interval": {desc: "Minimum interval", args: 1, placeholder: "<milliseconds>", children: nil},
						"multiplier":       {desc: "Multiplier", args: 1, placeholder: "<multiplier>", children: nil},
					}},
				}},
			}},
		}},
		"rip": {desc: "RIP configuration", children: map[string]*schemaNode{
			"group":               {desc: "Group", args: 1, placeholder: "<group-name>", children: nil},
			"neighbor":            {desc: "Neighbor", args: 1, valueHint: ValueHintInterfaceName, placeholder: "<interface-name>", children: nil},
			"passive-interface":   {desc: "Passive interface", args: 1, valueHint: ValueHintInterfaceName, placeholder: "<interface-name>", children: nil},
			"redistribute":        {desc: "Redistribute", args: 1, placeholder: "<protocol>", children: nil},
			"authentication-key":  {desc: "Authentication key", args: 1, placeholder: "<key>", children: nil},
			"authentication-type": {desc: "Authentication type", args: 1, placeholder: "<type>", children: nil},
		}},
		"isis": {desc: "IS-IS configuration", children: map[string]*schemaNode{
			"net":     {desc: "NET address", args: 1, placeholder: "<net-address>", children: nil},
			"level":   {desc: "Level", args: 1, placeholder: "<level>", children: nil},
			"is-type": {desc: "IS type", args: 1, placeholder: "<type>", children: nil},
			"export":  {desc: "Export policy", args: 1, multi: true, placeholder: "<policy-name>", children: nil},
			"interface": {desc: "Interface", args: 1, valueHint: ValueHintInterfaceName, placeholder: "<interface-name>", children: map[string]*schemaNode{
				"level":               {desc: "Level", args: 1, placeholder: "<level>", children: nil},
				"passive":             {desc: "Passive interface", children: nil},
				"metric":              {desc: "Metric", args: 1, placeholder: "<value>", children: nil},
				"authentication-key":  {desc: "Authentication key", args: 1, placeholder: "<key>", children: nil},
				"authentication-type": {desc: "Authentication type", args: 1, placeholder: "<type>", children: nil},
				"bfd-liveness-detection": {desc: "BFD liveness detection", children: map[string]*schemaNode{
					"minimum-interval": {desc: "Minimum interval", args: 1, placeholder: "<milliseconds>", children: nil},
					"multiplier":       {desc: "Multiplier", args: 1, placeholder: "<multiplier>", children: nil},
				}},
			}},
			"authentication-key":  {desc: "Authentication key", args: 1, placeholder: "<key>", children: nil},
			"authentication-type": {desc: "Authentication type", args: 1, placeholder: "<type>", children: nil},
			"wide-metrics-only":   {desc: "Wide metrics only", children: nil},
			"overload":            {desc: "Overload", children: nil},
		}},
		"router-advertisement": {desc: "Router advertisement", children: map[string]*schemaNode{
			"interface": {desc: "Interface", args: 1, valueHint: ValueHintInterfaceName, placeholder: "<interface-name>", children: map[string]*schemaNode{
				"prefix":     {desc: "Prefix", args: 1, placeholder: "<prefix>", children: nil}, // prefix <prefix/len>
				"preference": {desc: "Preference", args: 1, placeholder: "<preference>", children: nil},
				"nat-prefix": {desc: "NAT prefix", args: 1, placeholder: "<prefix>", children: map[string]*schemaNode{
					"lifetime": {desc: "Lifetime", args: 1, placeholder: "<seconds>", children: nil},
				}},
				"nat64prefix": {desc: "NAT64 prefix", args: 1, placeholder: "<prefix>", children: map[string]*schemaNode{
					"lifetime": {desc: "Lifetime", args: 1, placeholder: "<seconds>", children: nil},
				}},
			}},
		}},
		"lldp": {desc: "LLDP configuration", children: map[string]*schemaNode{
			"interface": {desc: "Interface", args: 1, valueHint: ValueHintInterfaceName, placeholder: "<interface-name>", children: map[string]*schemaNode{
				"disable": {desc: "Disable LLDP", children: nil},
			}},
			"transmit-interval": {desc: "Transmit interval", args: 1, placeholder: "<seconds>", children: nil},
			"hold-multiplier":   {desc: "Hold multiplier", args: 1, placeholder: "<multiplier>", children: nil},
			"disable":           {desc: "Disable LLDP", children: nil},
		}},
	}},
	"event-options": {children: map[string]*schemaNode{
		"policy": {args: 1, children: map[string]*schemaNode{
			"events": {children: nil},
			"within": {args: 1, children: map[string]*schemaNode{
				"trigger": {children: nil},
			}},
			"attributes-match": {children: nil},
			"then": {children: map[string]*schemaNode{
				"change-configuration": {children: map[string]*schemaNode{
					"commands": {children: nil},
				}},
			}},
		}},
	}},
	"chassis": {desc: "Chassis configuration", children: map[string]*schemaNode{
		// #1319 PR 2 typed leaves (chassis cluster subsystem). Fields-only
		// annotations — no children/args/multi changes, so SetPath flat-set
		// grouping is untouched (TestSetPathGrouping_Golden). Range policy:
		// the binding bound is what the xpf runtime actually consumes
		// (narrowest binary encoding / explicit clamp), checked against
		// Junos vSRX ranges second; deliberate Junos divergences are called
		// out per leaf because xpf's own defaults sit OUTSIDE the Junos
		// ranges for several knobs (the killed Phase-3a plan copied Junos
		// ranges blindly and would have rejected deployed configs).
		// Instance-name slots (`redundancy-group <id>`, the RG-scoped
		// `node <id>`) are NOT value slots — the walker's compiler-faithful
		// contract consumes identity tokens without validation; typing them
		// needs a new walker feature (deferred, see docs/config-schema.md).
		"cluster": {desc: "Chassis cluster (high-availability) configuration", children: map[string]*schemaNode{
			// One byte in the RETH virtual MAC 02:bf:72:CC:RR:NN
			// (cluster.RethMAC, pkg/cluster/reth.go:113) and in the stable
			// link-local (reth.go:124) — 256+ would silently alias MACs.
			// Heartbeat wire is uint16 (heartbeat.go:128), so the MAC byte
			// is the narrowest consumer. Junos vSRX: 0..255 (0 = disabled).
			// Deployed: 22 (docs/ha-cluster-userspace.conf:64).
			"cluster-id": {
				desc:          "Cluster identifier (0..255; one byte of the RETH virtual MAC)",
				args:          1,
				valueType:     ValueInteger,
				valueDesc:     "Cluster identifier (0..255; one byte of the RETH virtual MAC)",
				valueExamples: []string{"1"},
				validator:     ValidateInteger(0, 255),
				children:      nil,
			},
			// xpf clusters are strictly two-node: heartbeat NodeID is uint8
			// but every owner/peer decision (SlotToNodeID FPC mapping,
			// election peer model) assumes 0|1. Junos vSRX: node 0..1.
			"node": {
				desc:          "Node identifier (0..1)",
				args:          1,
				valueType:     ValueInteger,
				valueDesc:     "Node identifier (0..1)",
				valueExamples: []string{"0", "1"},
				validator:     ValidateInteger(0, 1),
				children:      nil,
			},
			// Junos vSRX reth-count range 1..128. Compiled verbatim
			// (compiler_system.go) and consumed for display (`show chassis
			// cluster information`, pkg/cli/cli_show_cluster.go:182).
			"reth-count": {
				desc:          "Number of RETH interfaces (1..128)",
				args:          1,
				valueType:     ValueInteger,
				valueDesc:     "Number of RETH interfaces (1..128)",
				valueExamples: []string{"2"},
				validator:     ValidateInteger(1, 128),
				children:      nil,
			},
			// Milliseconds. xpf-DIVERGENT from Junos (1000..2000 ms): the
			// xpf default is 100 ms (cluster.DefaultHeartbeatInterval,
			// pkg/cluster/heartbeat.go:38) and deployed clusters run 200 ms
			// (docs/ha-cluster-userspace.conf:66) — the Junos floor would
			// reject xpf's own default scale. Runtime truth: any value > 0
			// is honored (group_state.go:55); 0 is rejected here because
			// the runtime silently substitutes the default for it (the
			// silent-coerce trap this gate exists to close). Upper bound is
			// the only genuine runtime ceiling — MaxDurationMillis, above
			// which the time.Duration(ms)*time.Millisecond conversion
			// (group_state.go:56) overflows negative and the heartbeat
			// sender ticker panics. No schema-only cap (Codex, PR #1845).
			"heartbeat-interval": {
				desc:          "Heartbeat send interval in milliseconds (default 100)",
				args:          1,
				valueType:     ValueInteger,
				valueDesc:     "Heartbeat send interval in milliseconds (>= 1; xpf default 100, Junos allows 1000..2000)",
				valueExamples: []string{"100", "200", "1000"},
				validator:     ValidateInteger(1, MaxDurationMillis),
				children:      nil,
			},
			// Missed-heartbeat count before the peer is declared lost.
			// xpf-DIVERGENT from Junos (3..8): xpf's default is 5
			// (cluster.DefaultHeartbeatThreshold, heartbeat.go:41) and the
			// runtime honors any value > 0 (group_state.go:58) — a plain
			// int counter, never wire-encoded. Min-only per runtime truth
			// (Codex, PR #1845; the earlier 255 cap was schema-only). 0
			// rejected (silently means default at runtime).
			"heartbeat-threshold": {
				desc:          "Missed heartbeats before the peer is declared lost (default 5)",
				args:          1,
				valueType:     ValueInteger,
				valueDesc:     "Missed heartbeats before peer is declared lost (>= 1; xpf default 5, Junos allows 3..8)",
				valueExamples: []string{"3", "5", "8"},
				validator:     ValidateIntegerMin(1),
				children:      nil,
			},
			"control-link-recovery": {desc: "Control link recovery (accepted for Junos compatibility; no runtime effect)", children: nil},
			// control-ports fpc/port: NOT typed — compileChassis never
			// reads control-ports (compiled-leaf-only invariant).
			"control-ports": {desc: "Control port assignments (accepted for Junos compatibility; ignored)", children: map[string]*schemaNode{
				"fpc": {desc: "FPC slot for the control port (ignored)", args: 1, placeholder: "<slot>", children: map[string]*schemaNode{
					"port": {desc: "Control port number on the FPC (ignored)", args: 1, placeholder: "<port>", children: nil},
				}},
			}},
			// Interface / address leaves stay untyped until the interfaces
			// subsystem PR introduces the IP/identifier value types.
			"control-interface":             {desc: "Control link interface for heartbeats and cluster sync", args: 1, placeholder: "<interface>", children: nil},
			"peer-address":                  {desc: "Cluster peer IP address on the control link", args: 1, placeholder: "<address>", children: nil},
			"fabric-interface":              {desc: "Fabric link interface for session sync and cross-chassis forwarding", args: 1, placeholder: "<interface>", children: nil},
			"fabric-peer-address":           {desc: "Cluster peer IP address on the fabric link", args: 1, placeholder: "<address>", children: nil},
			"configuration-synchronize":     {desc: "Synchronize committed configuration from primary to secondary", children: nil},
			"nat-state-synchronization":     {desc: "NAT state synchronization (accepted for Junos compatibility; no runtime effect)", children: nil},
			"ipsec-session-synchronization": {desc: "Synchronize IPsec SAs to the cluster peer", children: nil},
			// Milliseconds, xpf extension (default 30, pkg/vrrp/vrrp.go).
			// Both bounds are runtime-derived from the VRRPv3 encoding:
			// the ms value is integer-divided to centiseconds
			// (pkg/vrrp/instance.go:915), so <10 ms encodes as Max Advert
			// Int 0 on the wire; the wire field is 12 bits (RFC 5798,
			// packet.go:48-49 masks with 0x0FFF), so the last value that
			// still encodes to the max 4095 cs is 40959 (40959/10 = 4095)
			// and 40960 is the first that aliases (4096 & 0x0FFF = 0).
			// 10..40959 is exactly the encodable range; non-multiples of
			// 10 floor to the same centisecond the runtime sends.
			"reth-advertise-interval": {
				desc:          "VRRP advertisement interval for RETH instances (milliseconds, default 30)",
				args:          1,
				valueType:     ValueInteger,
				valueDesc:     "RETH VRRP advertisement interval in milliseconds (10..40959; default 30)",
				valueExamples: []string{"30", "100"},
				validator:     ValidateInteger(10, 40959),
				children:      nil,
			},
			"hitless-restart": {desc: "Keep dataplane forwarding active during daemon shutdown (HA default is fail-closed)", children: nil},
			// xpf extension. Only "disable-rg" is acted on by the runtime
			// (pkg/cluster/heartbeat_manager.go:362, failover.go:166); any
			// other string compiled silently no-ops — the enum closes that.
			"peer-fencing": {
				desc:          "Fencing action sent to the peer when its heartbeats are lost (disable-rg)",
				args:          1,
				valueType:     ValueEnumOf,
				valueDesc:     "Fencing action on heartbeat timeout (disable-rg)",
				valueExamples: []string{"disable-rg"},
				validator:     ValidateEnum([]string{"disable-rg"}),
				children:      nil,
			},
			// Milliseconds, xpf extension. 0 = immediate takeover once
			// ready (cluster.DefaultTakeoverHoldTime, manager.go:243);
			// negative is warned-and-ignored at runtime (group_state.go:70)
			// and rejected here. Runtime truth: any positive duration is
			// honored (group_state.go:74), so the only ceiling is
			// MaxDurationMillis — the time.Duration(ms)*time.Millisecond
			// overflow point (group_state.go:75). The earlier 1 h cap was
			// schema-only and removed (Codex, PR #1845).
			"takeover-hold-time": {
				desc:          "Extra delay before takeover in milliseconds (0 = immediate)",
				args:          1,
				valueType:     ValueInteger,
				valueDesc:     "Extra delay before takeover in milliseconds (>= 0; 0 = immediate)",
				valueExamples: []string{"0", "5000"},
				validator:     ValidateInteger(0, MaxDurationMillis),
				children:      nil,
			},
			"no-reth-vrrp":           {desc: "Disable VRRP on RETH interfaces (election over the control link only)", children: nil},
			"private-rg-election":    {desc: "Elect RG primaries over the control link without RETH VRRP (default)", children: nil},
			"no-private-rg-election": {desc: "Disable private RG election (use legacy RETH VRRP election)", children: nil},
			"redundancy-group": {desc: "Redundancy group", args: 1, placeholder: "<group-id>", children: map[string]*schemaNode{
				"node": {desc: "Per-node settings for this redundancy group", args: 1, placeholder: "<node-id>", children: map[string]*schemaNode{
					// Junos vSRX: 1..254. Runtime-binding: the priority
					// feeds VRRP and is truncated to uint8 on the wire
					// (pkg/vrrp/instance.go:918); 255 is the RFC 5798
					// IP-owner reserved value (instance.go:256) and 0 is
					// treated as unset (vrrp.go pri==0 → default 100) —
					// both excluded. Heartbeat carries uint16 but VRRP is
					// the narrow consumer. Deployed: 200/100.
					"priority": {
						desc:          "Node priority for primary election (1..254; higher wins)",
						args:          1,
						valueType:     ValueInteger,
						valueDesc:     "Node priority for primary election (1..254; higher wins)",
						valueExamples: []string{"100", "200", "254"},
						validator:     ValidateInteger(1, 254),
						children:      nil,
					},
				}},
				// Runtime truth: any configured count > 0 is used verbatim
				// as the GARP/NA burst length (pkg/vrrp/instance.go GARP
				// loop, pkg/cluster/garp.go SendGratuitousARPBurst — both
				// only special-case <= 0 to the default), read via
				// daemon_ha_vip.go:475 and vrrp.go:94. Min-only per the
				// no-schema-only-caps doctrine (Codex, PR #1845) — Junos
				// caps at 16, but enforcing that here would reject configs
				// the runtime executes fine; a sanity cap belongs in the
				// runtime first. Deployed: 8.
				"gratuitous-arp-count": {
					desc:          "Gratuitous ARP/NA burst count on failover (default 3)",
					args:          1,
					valueType:     ValueInteger,
					valueDesc:     "Gratuitous ARP/NA burst count on failover (>= 1; default 3, Junos allows 1..16)",
					valueExamples: []string{"3", "8", "16"},
					validator:     ValidateIntegerMin(1),
					children:      nil,
				},
				"preempt": {desc: "Allow a higher-priority node to preempt the primary role", children: nil},
				// interface-monitor weight is NOT typed in PR 2: the
				// `<ifname> weight <n>` tokens pack inline into one leaf
				// (children==nil here); typing the weight would require a
				// children/wildcard map, which flips SetPath's
				// replace-vs-container grouping — forbidden by the
				// fields-only rule. Deferred (docs/config-schema.md).
				"interface-monitor": {desc: "Deduct weight from the redundancy group while a monitored interface is down", children: nil},
				"ip-monitoring": {desc: "Probe monitored IPs and deduct weight on failure", children: map[string]*schemaNode{
					// Junos vSRX: 0..255. Weight subtracted from the RG
					// weight, which starts at 255 (group_state.go:29,
					// SetMonitorWeight election.go:324); heartbeat monitor
					// entries carry weight as uint8.
					"global-weight": {
						desc:          "Default weight deducted when a monitored IP fails (0..255)",
						args:          1,
						valueType:     ValueInteger,
						valueDesc:     "Default weight deducted when a monitored IP fails (0..255)",
						valueExamples: []string{"255"},
						validator:     ValidateInteger(0, 255),
						children:      nil,
					},
					// Junos vSRX: 0..255. Compiled verbatim
					// (compiler_system.go IPMonitoring.GlobalThreshold).
					"global-threshold": {
						desc:          "Cumulative failure weight that triggers failover (0..255)",
						args:          1,
						valueType:     ValueInteger,
						valueDesc:     "Cumulative failure weight that triggers failover (0..255)",
						valueExamples: []string{"100"},
						validator:     ValidateInteger(0, 255),
						children:      nil,
					},
					"family": {desc: "Address family of monitored IPs", compoundKey: true, children: map[string]*schemaNode{
						"inet": {desc: "IPv4 monitored addresses", wildcard: &schemaNode{desc: "Monitored IPv4 address", placeholder: "<address>", children: map[string]*schemaNode{
							// Junos vSRX: 0..255. 0 = inherit global-weight
							// (pkg/cluster/monitor.go pollIPMonitors).
							"weight": {
								desc:          "Weight deducted when this IP fails (0 = use global-weight)",
								args:          1,
								valueType:     ValueInteger,
								valueDesc:     "Weight deducted when this IP fails (0..255; 0 = use global-weight)",
								valueExamples: []string{"100", "255"},
								validator:     ValidateInteger(0, 255),
								children:      nil,
							},
						}}},
					}},
				}},
			}},
		}},
	}},
	"class-of-service": {desc: "Class of service configuration", children: map[string]*schemaNode{
		"forwarding-classes": {desc: "Forwarding class definitions", children: map[string]*schemaNode{
			"queue": {desc: "Map a queue number to a forwarding-class name (one queue per class, one class per queue)", args: 2, multi: true, children: nil},
		}},
		"classifiers": {desc: "Classifiers mapping incoming code points to forwarding classes", children: map[string]*schemaNode{
			"dscp": {desc: "DSCP classifier", args: 1, multi: true, placeholder: "<classifier-name>", children: map[string]*schemaNode{
				"forwarding-class": {desc: "Forwarding class to assign to matching code points", args: 1, multi: true, placeholder: "<class-name>", children: map[string]*schemaNode{
					"loss-priority": {desc: "Loss priority (accepted for Junos compatibility; not enforced by the userspace dataplane)", args: 1, multi: true, placeholder: "<level>", children: map[string]*schemaNode{
						"code-points": {desc: "DSCP code points to match (alias such as ef, af11, cs6, or numeric 0..63)", args: 1, multi: true, placeholder: "<code-points>", children: nil},
					}},
				}},
			}},
			"ieee-802.1": {desc: "IEEE 802.1p classifier", args: 1, multi: true, placeholder: "<classifier-name>", children: map[string]*schemaNode{
				"forwarding-class": {desc: "Forwarding class to assign to matching code points", args: 1, multi: true, placeholder: "<class-name>", children: map[string]*schemaNode{
					"loss-priority": {desc: "Loss priority (accepted for Junos compatibility; not enforced by the userspace dataplane)", args: 1, multi: true, placeholder: "<level>", children: map[string]*schemaNode{
						"code-points": {desc: "IEEE 802.1p code points to match (0..7)", args: 1, multi: true, placeholder: "<code-points>", children: nil},
					}},
				}},
			}},
		}},
		"rewrite-rules": {desc: "Egress rewrite rules mapping forwarding classes to code points", children: map[string]*schemaNode{
			"dscp": {desc: "DSCP rewrite rule", args: 1, multi: true, placeholder: "<rewrite-rule-name>", children: map[string]*schemaNode{
				"forwarding-class": {desc: "Forwarding class whose packets get the rewritten code point", args: 1, multi: true, placeholder: "<class-name>", children: map[string]*schemaNode{
					"loss-priority": {desc: "Loss priority (accepted for Junos compatibility; not enforced by the userspace dataplane)", args: 1, multi: true, placeholder: "<level>", children: map[string]*schemaNode{
						"code-point":  {desc: "DSCP code point to write (alias such as ef, af11, cs6, or numeric 0..63)", args: 1, placeholder: "<code-point>", children: nil},
						"code-points": {desc: "DSCP code point to write (alias of code-point; first value is used)", args: 1, multi: true, placeholder: "<code-points>", children: nil},
					}},
				}},
			}},
		}},
		"schedulers": {desc: "Scheduler definitions (transmit rate, priority, buffer)", args: 1, multi: true, placeholder: "<scheduler-name>", children: map[string]*schemaNode{
			// #1319 typed leaves. Re-homed from the cmdtree overlay
			// (cmdtree.ConfigClassOfServiceSchedulers, retired in this PR)
			// onto setSchema so the live config-mode `set ... ?` completer
			// and the SchemaValidate commit-check gate read one tree. The
			// `exact` child predates #1319 and is unchanged — adding fields
			// to transmit-rate does not alter SetPath grouping.
			"transmit-rate": {
				desc:          "Transmit rate in bits per second (e.g. 100k, 10m, 1g)",
				args:          1,
				valueType:     ValueRate,
				valueDesc:     "Bandwidth (e.g. 100k, 10m, 1g) or bps integer; >= 8 bps",
				valueExamples: []string{"100k", "10m", "1g", "10g"},
				validator:     ValidateRate,
				children: map[string]*schemaNode{
					"exact": {desc: "Cap the queue at the configured rate (no surplus borrowing unless surplus-sharing is set)", children: nil},
				},
			},
			"priority": {
				desc:          "Scheduler priority level",
				args:          1,
				valueType:     ValueEnumOf,
				valueDesc:     "Scheduler priority (low | medium-low | medium-high | high | strict-high)",
				valueExamples: []string{"low", "medium-low", "medium-high", "high", "strict-high"},
				validator: ValidateEnum([]string{
					"low", "medium-low", "medium-high", "high", "strict-high",
				}),
				children: nil,
			},
			"buffer-size": {
				desc:          "Queue buffer size (bytes with k/m/g suffix, or percent of the interface buffer pool; percents in one scheduler-map must not exceed 100%)",
				args:          1,
				valueType:     ValueByteSizeOrPercent,
				valueDesc:     "Byte-size with explicit k/m/g suffix, or percent of interface CoS burst pool (e.g. 16m, 256k, 10%)",
				valueExamples: []string{"16m", "256k", "10%"},
				validator:     ValidateByteSizeOrPercent,
				children:      nil,
			},
			// `surplus-sharing` (#915) and `equal-flow-enforcement` are
			// presence-only flags — no value to validate.
			"surplus-sharing":        {desc: "Let this exact-rate queue draw surplus bandwidth once its own rate is exhausted (only meaningful with transmit-rate exact)", children: nil},
			"equal-flow-enforcement": {desc: "Enforce equal per-flow rates on this queue (requires positive transmit-rate exact; cannot be combined with surplus-sharing)", children: nil},
			// #1746: equal-flow target policy. Only meaningful with
			// `equal-flow-enforcement`; unset == `slowest` (the
			// byte-unchanged clip-to-slowest default). `mean` and
			// `slowest` are non-work-conserving (commit warning).
			"equal-flow-target-policy": {
				desc:          "Per-flow target policy for equal-flow enforcement (slowest | mean | ideal-share, unset = slowest)",
				args:          1,
				valueType:     ValueEnumOf,
				valueDesc:     "Equal-flow per-flow target policy (slowest | mean | ideal-share)",
				valueExamples: []string{"slowest", "mean", "ideal-share"},
				validator: ValidateEnum([]string{
					"slowest", "mean", "ideal-share",
				}),
				children: nil,
			},
		}},
		"scheduler-maps": {desc: "Scheduler map assigning schedulers to forwarding classes", args: 1, multi: true, placeholder: "<map-name>", children: map[string]*schemaNode{
			"forwarding-class": {desc: "Forwarding class entry in this map", args: 1, multi: true, placeholder: "<class-name>", children: map[string]*schemaNode{
				"scheduler": {desc: "Scheduler to apply to this forwarding class", args: 1, placeholder: "<scheduler-name>", children: nil},
			}},
		}},
		"interfaces": {desc: "Apply CoS to an interface", args: 1, multi: true, placeholder: "<interface-name>", children: map[string]*schemaNode{
			"unit": {desc: "Logical unit number", args: 1, multi: true, placeholder: "<unit-number>", children: map[string]*schemaNode{
				"classifiers": {desc: "Classifiers applied to traffic arriving on this unit", children: map[string]*schemaNode{
					"dscp":       {desc: "DSCP classifier to apply", args: 1, placeholder: "<classifier-name>", children: nil},
					"ieee-802.1": {desc: "IEEE 802.1p classifier to apply", args: 1, placeholder: "<classifier-name>", children: nil},
				}},
				"rewrite-rules": {desc: "Rewrite rules applied to traffic leaving this unit", children: map[string]*schemaNode{
					"dscp": {desc: "DSCP rewrite rule to apply", args: 1, placeholder: "<rewrite-rule-name>", children: nil},
				}},
				"shaping-rate": {desc: "Shaping rate for this unit in bits per second (k/m/g suffixes)", args: 1, placeholder: "<rate>", children: map[string]*schemaNode{
					"burst-size": {desc: "Shaping burst size in bytes (k/m/g suffixes)", args: 1, placeholder: "<bytes>", children: nil},
				}},
				"scheduler-map": {desc: "Scheduler map to apply to this unit", args: 1, placeholder: "<map-name>", children: nil},
			}},
		}},
		"fairness": {desc: "Dataplane fairness observability configuration", children: map[string]*schemaNode{
			"rss-expectation": {desc: "Declarative RSS flow-distribution expectations evaluated against live dataplane status (shown in fairness output and exported as Prometheus gauges)", children: map[string]*schemaNode{
				"ifindex": {desc: "Kernel interface index to evaluate (positive integer)", args: 1, multi: true, placeholder: "<ifindex>", children: map[string]*schemaNode{
					"queue": {desc: "CoS queue ID to evaluate (0..255; exactly one expectation per queue)", args: 1, multi: true, placeholder: "<queue-id>", children: map[string]*schemaNode{
						"any":                     {desc: "No expectation; always passes", children: nil},
						"balanced":                {desc: "Expect flows spread across min(flows, workers) workers with per-worker flow counts within 1", children: nil},
						"active-workers":          {desc: "Alias for at-least-active-workers", args: 1, placeholder: "<count>", children: nil},
						"at-least-active-workers": {desc: "Expect at least this many workers with active flows", args: 1, placeholder: "<count>", children: nil},
						"max-worker-flow-share":   {desc: "Expect the busiest worker's share of active flows to be at most this threshold (fraction 0..1 or percent)", args: 1, placeholder: "<share>", children: nil},
						"cstruct":                 {desc: "Alias for cstruct-max", args: 1, placeholder: "<threshold>", children: nil},
						"cstruct-max":             {desc: "Expect the structural CoV ceiling (Cstruct) of the observed flow distribution to be at most this threshold (non-negative number or percent)", args: 1, placeholder: "<threshold>", children: nil},
					}},
				}},
			}},
		}},
	}},
	"firewall": {children: map[string]*schemaNode{
		"policer": {args: 1, multi: true, children: map[string]*schemaNode{
			"if-exceeding": {children: map[string]*schemaNode{
				"bandwidth-limit":  {args: 1, children: nil},
				"burst-size-limit": {args: 1, children: nil},
			}},
			"logical-interface-policer": {children: nil},
			"then": {children: map[string]*schemaNode{
				"discard":       {children: nil},
				"loss-priority": {args: 1, children: nil},
			}},
		}},
		"three-color-policer": {args: 1, multi: true, children: map[string]*schemaNode{
			"single-rate": {children: map[string]*schemaNode{
				"color-blind":                {children: nil},
				"color-aware":                {children: nil},
				"committed-information-rate": {args: 1, children: nil},
				"committed-burst-size":       {args: 1, children: nil},
				"excess-burst-size":          {args: 1, children: nil},
			}},
			"two-rate": {children: map[string]*schemaNode{
				"color-blind":                {children: nil},
				"color-aware":                {children: nil},
				"committed-information-rate": {args: 1, children: nil},
				"committed-burst-size":       {args: 1, children: nil},
				"peak-information-rate":      {args: 1, children: nil},
				"peak-burst-size":            {args: 1, children: nil},
			}},
			"then": {children: map[string]*schemaNode{
				"discard":       {children: nil},
				"loss-priority": {args: 1, children: nil},
			}},
		}},
		"family": {compoundKey: true, children: map[string]*schemaNode{
			"inet": {children: map[string]*schemaNode{
				"filter": {args: 1, children: map[string]*schemaNode{
					"term": {args: 1, children: map[string]*schemaNode{
						"from": {children: map[string]*schemaNode{
							"source-address":          {args: 1, multi: true, children: nil},
							"destination-address":     {args: 1, multi: true, children: nil},
							"source-prefix-list":      {children: nil},
							"destination-prefix-list": {children: nil},
							"protocol":                {args: 1, multi: true, children: nil},
							"dscp":                    {args: 1, multi: true, children: nil},
							"destination-port":        {args: 1, multi: true, children: nil},
							"source-port":             {args: 1, multi: true, children: nil},
							"icmp-type":               {args: 1, multi: true, children: nil},
							"icmp-code":               {args: 1, multi: true, children: nil},
							"tcp-flags":               {args: 1, multi: true, children: nil},
							"is-fragment":             {children: nil},
							"flexible-match-range": {children: map[string]*schemaNode{
								"range": {args: 1, children: map[string]*schemaNode{
									"match-start": {args: 1, children: nil},
									"byte-offset": {args: 1, children: nil},
									"bit-length":  {args: 1, children: nil},
									"range":       {args: 1, children: nil},
									"match-value": {args: 1, children: nil},
									"match-mask":  {args: 1, children: nil},
								}},
							}},
						}},
						"then": {children: map[string]*schemaNode{
							"accept":           {children: nil},
							"reject":           {children: nil},
							"discard":          {children: nil},
							"log":              {children: nil},
							"syslog":           {children: nil},
							"routing-instance": {args: 1, children: nil},
							"count":            {args: 1, children: nil},
							// #1319 PR 3 tree-based cross-ref: the dataplane
							// resolves this name against the CONFIGURED
							// forwarding classes and silently defaults the
							// queue on a miss (see validateForwardingClassRef
							// for the runtime citations and the best-effort
							// special case).
							"forwarding-class": {
								args:          1,
								valueType:     ValueIdentifier,
								valueDesc:     "Forwarding class to assign (must be defined under class-of-service forwarding-classes, or best-effort)",
								valueExamples: []string{"best-effort"},
								treeValidator: validateForwardingClassRef,
								children:      nil,
							},
							"loss-priority": {args: 1, children: nil},
							"dscp":          {args: 1, children: nil},
							"traffic-class": {args: 1, children: nil},
							"policer":       {args: 1, children: nil},
						}},
					}},
				}},
			}},
			"inet6": {children: map[string]*schemaNode{
				"filter": {args: 1, children: map[string]*schemaNode{
					"term": {args: 1, children: map[string]*schemaNode{
						"from": {children: map[string]*schemaNode{
							"source-address":          {args: 1, multi: true, children: nil},
							"destination-address":     {args: 1, multi: true, children: nil},
							"source-prefix-list":      {children: nil},
							"destination-prefix-list": {children: nil},
							"protocol":                {args: 1, multi: true, children: nil},
							"traffic-class":           {args: 1, multi: true, children: nil},
							"destination-port":        {args: 1, multi: true, children: nil},
							"source-port":             {args: 1, multi: true, children: nil},
							"icmp-type":               {args: 1, multi: true, children: nil},
							"icmp-code":               {args: 1, multi: true, children: nil},
							"tcp-flags":               {args: 1, multi: true, children: nil},
							"is-fragment":             {children: nil},
							"flexible-match-range": {children: map[string]*schemaNode{
								"range": {args: 1, children: map[string]*schemaNode{
									"match-start": {args: 1, children: nil},
									"byte-offset": {args: 1, children: nil},
									"bit-length":  {args: 1, children: nil},
									"range":       {args: 1, children: nil},
									"match-value": {args: 1, children: nil},
									"match-mask":  {args: 1, children: nil},
								}},
							}},
						}},
						"then": {children: map[string]*schemaNode{
							"accept":           {children: nil},
							"reject":           {children: nil},
							"discard":          {children: nil},
							"log":              {children: nil},
							"syslog":           {children: nil},
							"routing-instance": {args: 1, children: nil},
							"count":            {args: 1, children: nil},
							// #1319 PR 3 tree-based cross-ref: the dataplane
							// resolves this name against the CONFIGURED
							// forwarding classes and silently defaults the
							// queue on a miss (see validateForwardingClassRef
							// for the runtime citations and the best-effort
							// special case).
							"forwarding-class": {
								args:          1,
								valueType:     ValueIdentifier,
								valueDesc:     "Forwarding class to assign (must be defined under class-of-service forwarding-classes, or best-effort)",
								valueExamples: []string{"best-effort"},
								treeValidator: validateForwardingClassRef,
								children:      nil,
							},
							"loss-priority": {args: 1, children: nil},
							"dscp":          {args: 1, children: nil},
							"traffic-class": {args: 1, children: nil},
							"policer":       {args: 1, children: nil},
						}},
					}},
				}},
			}},
		}},
	}},
	"system": {desc: "System configuration", children: map[string]*schemaNode{
		"host-name":     {desc: "System hostname", args: 1, placeholder: "<hostname>", children: nil},
		"domain-name":   {desc: "Domain name", args: 1, placeholder: "<domain>", children: nil},
		"domain-search": {desc: "Domain search list", args: 1, multi: true, placeholder: "<domain>", children: nil},
		"time-zone":     {desc: "System time zone", args: 1, placeholder: "<timezone>", children: nil},
		"no-redirects":  {desc: "Disable ICMP redirects", children: nil},
		// #1319 PR 3: compiled verbatim and written into the resolver
		// drop-in (pkg/daemon/daemon_dns.go:114) — a garbage server
		// string silently produced broken DNS configuration.
		"name-server": {
			desc:          "DNS name server",
			args:          1,
			multi:         true,
			placeholder:   "<address>",
			valueType:     ValueIPAddress,
			valueDesc:     "DNS server IP address (IPv4 or IPv6)",
			valueExamples: []string{"8.8.8.8", "2001:4860:4860::8888"},
			validator:     ValidateIPAddress,
			children:      nil,
		},
		"backup-router": {desc: "Backup router", args: 1, placeholder: "<address>", children: map[string]*schemaNode{
			"destination": {desc: "Destination network", args: 1, placeholder: "<network>", children: nil},
		}},
		"root-authentication": {desc: "Root authentication", children: map[string]*schemaNode{
			"encrypted-password": {desc: "Encrypted password", args: 1, placeholder: "<password>", children: nil},
			"ssh-ed25519":        {desc: "SSH ED25519 public key", args: 1, placeholder: "<key>", children: nil},
			"ssh-rsa":            {desc: "SSH RSA public key", args: 1, placeholder: "<key>", children: nil},
			"ssh-dsa":            {desc: "SSH DSA public key", args: 1, placeholder: "<key>", children: nil},
		}},
		"archival": {desc: "Configuration archival", children: map[string]*schemaNode{
			"configuration": {desc: "Configuration archival", children: map[string]*schemaNode{
				"transfer-on-commit": {desc: "Transfer on commit", children: nil},
				"archive-sites":      {desc: "Archive site URL", args: 1, placeholder: "<url>", children: nil},
			}},
		}},
		"master-password": {desc: "Master password", children: map[string]*schemaNode{
			"pseudorandom-function": {desc: "Pseudorandom function", args: 1, placeholder: "<function>", children: nil},
		}},
		"license": {desc: "License configuration", children: map[string]*schemaNode{
			"autoupdate": {desc: "Autoupdate", children: map[string]*schemaNode{
				"url": {desc: "Autoupdate URL", args: 1, placeholder: "<url>", children: nil},
			}},
		}},
		"processes": {desc: "Process information", children: nil},
		"internet-options": {desc: "Internet options", children: map[string]*schemaNode{
			"no-ipv6-reject-zero-hop-limit": {desc: "Do not reject IPv6 packets with zero hop limit", children: nil},
		}},
		"ntp": {desc: "NTP configuration", children: map[string]*schemaNode{
			"server": {desc: "NTP server", args: 1, placeholder: "<address>", children: nil},
			"threshold": {desc: "Threshold", args: 1, placeholder: "<seconds>", children: map[string]*schemaNode{
				"action": {desc: "Action on threshold", args: 1, placeholder: "<action>", children: nil},
			}},
		}},
		"syslog": {desc: "Syslog configuration", children: map[string]*schemaNode{
			"user": {desc: "Syslog user", args: 1, placeholder: "<user>", children: nil},
			"host": {desc: "Syslog host", args: 1, placeholder: "<host>", children: nil},
			"file": {desc: "Syslog file", args: 1, placeholder: "<filename>", children: nil},
		}},
		"login": {desc: "Login configuration", children: map[string]*schemaNode{
			"user": {desc: "User name", args: 1, placeholder: "<username>", children: map[string]*schemaNode{
				"uid":            {desc: "User ID", args: 1, placeholder: "<uid>", children: nil},
				"class":          {desc: "Login class", args: 1, placeholder: "<class>", children: nil},
				"authentication": {desc: "Authentication methods", children: nil},
			}},
		}},
		"dataplane-type": {desc: "Dataplane type", args: 1, placeholder: "<type>", children: nil},
		"dataplane": {desc: "Dataplane configuration", children: map[string]*schemaNode{
			// cores / memory / socket-mem / rx-mode / ports are DPDK-era
			// knobs whose consumer was deleted in the #1525 retirement —
			// compileUserspaceDataplane has no case for any of them. They
			// stay in the grammar for stored-config compatibility (never
			// break an existing stanza) but have NO effect; the compiler
			// emits a per-knob commit warning instead (#1892,
			// userspaceRetiredKnobWarnings).
			"cores":          {args: 1, desc: "Legacy DPDK core count (retired, ignored)", children: nil},
			"memory":         {args: 1, desc: "Legacy DPDK memory allocation (retired, ignored)", children: nil},
			"socket-mem":     {args: 1, desc: "Legacy DPDK socket memory (retired, ignored)", children: nil},
			"binary":         {args: 1, desc: "Userspace dataplane helper binary path", children: nil},
			"control-socket": {args: 1, desc: "Unix control socket path", children: nil},
			"state-file":     {args: 1, desc: "Helper state file path", children: nil},
			// #1319 PR 3 typed dataplane knobs. Each compiled with the
			// Atoi error swallowed (compileUserspaceDataplane), so
			// garbage silently fell back to the 0 zero-value, which the
			// manager coerces to the default (workers<=0 -> 1,
			// ring-entries<=0 -> 1024; pkg/dataplane/userspace/
			// manager.go:1347-1351). Min-only: the runtime owns any
			// ceiling, and the Rust helper rounds ring sizes up to a
			// power of two itself (afxdp/bind.rs
			// checked_next_power_of_two).
			"workers": {
				args:          1,
				desc:          "Worker thread count",
				valueType:     ValueInteger,
				valueDesc:     "Dataplane worker thread count (>= 1)",
				valueExamples: []string{"4", "6"},
				validator:     ValidateIntegerMin(1),
				children:      nil,
			},
			"ring-entries": {
				args:          1,
				desc:          "AF_XDP ring entries per queue",
				valueType:     ValueInteger,
				valueDesc:     "AF_XDP ring entries per queue (>= 1; rounded up to a power of two)",
				valueExamples: []string{"1024", "2048"},
				validator:     ValidateIntegerMin(1),
				children:      nil,
			},
			// Only these two strings are acted on; anything else was
			// silently ignored (compiler_system.go poll-mode case).
			"poll-mode": {
				args:          1,
				desc:          "Worker poll mode (busy-poll or interrupt)",
				valueType:     ValueEnumOf,
				valueDesc:     "Worker poll mode (busy-poll | interrupt)",
				valueExamples: []string{"busy-poll", "interrupt"},
				validator:     ValidateEnum([]string{"busy-poll", "interrupt"}),
				children:      nil,
			},
			"shared-umem": {desc: "AF_XDP shared-UMEM policy override", children: map[string]*schemaNode{
				"mode":                 {args: 1, desc: "Shared UMEM mode override (auto|off|same-device-debug|cross-nic)", children: nil},
				"interface":            {args: 1, multi: true, desc: "Optional participating Linux interface filter", children: nil},
				"phase0-artifact-file": {args: 1, desc: "Optional machine-readable Phase 0 audit artifact", children: nil},
				"artifact-file":        {args: 1, desc: "Alias for phase0-artifact-file", children: nil},
			}},
			// Only the literal "disable" acts; any other string
			// (including typos) silently meant the enabled default.
			"rss-indirection": {
				args:          1,
				desc:          "mlx5 RSS indirection reshaping (enable|disable)",
				valueType:     ValueEnumOf,
				valueDesc:     "RSS indirection reshaping (enable | disable; default enable)",
				valueExamples: []string{"enable", "disable"},
				validator:     ValidateEnum([]string{"enable", "disable"}),
				children:      nil,
			},
			// Only the literal "true" opts in (#801 B1 gate); any other
			// string silently meant false.
			"claim-host-tunables": {
				args:          1,
				desc:          "Allow xpfd to write host-scope tunables (true|false, default false)",
				valueType:     ValueBool,
				valueDesc:     "Write host-scope tunables (true | false; default false)",
				valueExamples: []string{"true", "false"},
				validator:     ValidateEnum([]string{"true", "false"}),
				children:      nil,
			},
			// cpu-governor stays untyped BY DESIGN: the compiler passes
			// unrecognised governors through so bare-metal operators can
			// request powersave/ondemand without a schema change
			// (compiler_system.go cpu-governor case).
			"cpu-governor": {args: 1, desc: "Host cpufreq governor (performance|schedutil|default)", children: nil},
			// 0 is the "use default" zero-value sentinel
			// (resolvedHostTunables, pkg/daemon/host_tunables.go:494),
			// so garbage silently meant the default budget.
			"netdev-budget": {
				args:          1,
				desc:          "net.core.netdev_budget value",
				valueType:     ValueInteger,
				valueDesc:     "net.core.netdev_budget (>= 1)",
				valueExamples: []string{"600"},
				validator:     ValidateIntegerMin(1),
				children:      nil,
			},
			"coalescence": {desc: "NIC interrupt-coalescence tuning (mlx5)", children: map[string]*schemaNode{
				// Anything but the literal "enable" silently meant
				// disable (compiler_system.go coalescence case); the
				// usec knobs treat <= 0 as "use default"
				// (pkg/daemon/coalescence.go:60-65), so garbage
				// silently fell back too.
				"adaptive": {
					args:          1,
					desc:          "Adaptive coalescing (enable|disable)",
					valueType:     ValueEnumOf,
					valueDesc:     "Adaptive interrupt coalescing (enable | disable)",
					valueExamples: []string{"enable", "disable"},
					validator:     ValidateEnum([]string{"enable", "disable"}),
					children:      nil,
				},
				"rx-usecs": {
					args:          1,
					desc:          "RX coalescing µs",
					valueType:     ValueInteger,
					valueDesc:     "RX interrupt coalescing in microseconds (>= 1)",
					valueExamples: []string{"8"},
					validator:     ValidateIntegerMin(1),
					children:      nil,
				},
				"tx-usecs": {
					args:          1,
					desc:          "TX coalescing µs",
					valueType:     ValueInteger,
					valueDesc:     "TX interrupt coalescing in microseconds (>= 1)",
					valueExamples: []string{"8"},
					validator:     ValidateIntegerMin(1),
					children:      nil,
				},
			}},
			"rx-mode": {desc: "Legacy DPDK adaptive RX mode (retired, ignored)", children: map[string]*schemaNode{
				"idle-threshold":   {args: 1, desc: "Legacy DPDK RX idle threshold (retired, ignored)", children: nil},
				"resume-threshold": {args: 1, desc: "Legacy DPDK RX resume threshold (retired, ignored)", children: nil},
				"sleep-timeout":    {args: 1, desc: "Legacy DPDK RX sleep timeout (retired, ignored)", children: nil},
			}},
			"ports": {desc: "Legacy DPDK per-port mapping (retired, ignored)", wildcard: &schemaNode{desc: "Legacy DPDK port name (retired, ignored)", placeholder: "<port-name>", children: map[string]*schemaNode{
				"interface": {args: 1, desc: "Legacy DPDK port interface binding (retired, ignored)", children: nil},
				"rx-mode":   {args: 1, desc: "Legacy DPDK per-port RX mode (retired, ignored)", children: nil},
				"cores":     {args: 1, desc: "Legacy DPDK per-port core list (retired, ignored)", children: nil},
			}}},
		}},
		"services": {desc: "System services", children: map[string]*schemaNode{
			"ssh": {desc: "SSH service", children: map[string]*schemaNode{
				// Only allow/deny/deny-password map to sshd
				// PermitRootLogin values; anything else was a silent
				// no-op (pkg/daemon/daemon_system.go:739-748). The old
				// "<permit|deny>" placeholder named values the runtime
				// never accepted.
				"root-login": {
					desc:          "Root login permission",
					args:          1,
					placeholder:   "<allow|deny|deny-password>",
					valueType:     ValueEnumOf,
					valueDesc:     "Root SSH login policy (allow | deny | deny-password)",
					valueExamples: []string{"allow", "deny", "deny-password"},
					validator:     ValidateEnum([]string{"allow", "deny", "deny-password"}),
					children:      nil,
				},
			}},
			"netconf": {desc: "NETCONF service", children: map[string]*schemaNode{
				"ssh": {desc: "NETCONF over SSH", children: nil},
			}},
			"web-management": {desc: "Web management", children: map[string]*schemaNode{
				"http": {desc: "HTTP service", children: map[string]*schemaNode{
					"interface": {desc: "Interface", args: 1, placeholder: "<interface>", children: nil},
				}},
				"https": {desc: "HTTPS service", children: map[string]*schemaNode{
					"system-generated-certificate": {desc: "Use system-generated certificate", children: nil},
					"interface":                    {desc: "Interface", args: 1, placeholder: "<interface>", children: nil},
				}},
				"api-auth": {desc: "API authentication", children: map[string]*schemaNode{
					"user": {desc: "User name", wildcard: &schemaNode{desc: "Basic-auth user name for the REST API", placeholder: "<username>", children: map[string]*schemaNode{
						"password": {desc: "Password", args: 1, placeholder: "<password>", children: nil},
					}}},
					"api-key": {desc: "API key", args: 1, placeholder: "<key>", children: nil},
				}},
			}},
			"dns": {desc: "DNS service", children: nil},
			"dhcp-local-server": {desc: "DHCP local server", children: map[string]*schemaNode{
				"group": {desc: "DHCP group", args: 1, placeholder: "<group-name>", children: map[string]*schemaNode{
					"pool": {desc: "Address pool", args: 1, placeholder: "<pool-name>", children: nil},
				}},
			}},
			"dhcpv6-local-server": {desc: "DHCPv6 local server", children: map[string]*schemaNode{
				"group": {desc: "DHCPv6 group", args: 1, placeholder: "<group-name>", children: map[string]*schemaNode{
					"pool": {desc: "Address pool", args: 1, placeholder: "<pool-name>", children: nil},
				}},
			}},
		}},
	}},
	"services": {desc: "Services configuration", children: map[string]*schemaNode{
		"rpm": {desc: "Real-time Performance Monitoring probes", children: map[string]*schemaNode{
			// #1319 PR 3: the rpm integer knobs already fail compile
			// loudly via parseRPMPositiveInt (> 0 enforced); typing them
			// surfaces the same bound at `?` completion and rejects in
			// the uniform schema-gate error shape before compile.
			"probe-limit": {
				args:          1,
				desc:          "Default maximum consecutive failed probes before stopping a test cycle",
				valueType:     ValueInteger,
				valueDesc:     "Maximum consecutive failed probes (>= 1)",
				valueExamples: []string{"3"},
				validator:     ValidateIntegerMin(1),
				children:      nil,
			},
			"probe": {args: 1, desc: "RPM probe name", children: map[string]*schemaNode{
				"test": {args: 1, desc: "RPM test name", children: map[string]*schemaNode{
					// Mirrors supportedRPMProbeTypes
					// (compiler_services.go:10) which the compiler
					// already rejects loudly.
					"probe-type": {
						args:          1,
						desc:          "Probe type: icmp-ping, tcp-ping, or http-get",
						valueType:     ValueEnumOf,
						valueDesc:     "Probe type (icmp-ping | tcp-ping | http-get)",
						valueExamples: []string{"icmp-ping", "tcp-ping", "http-get"},
						validator:     ValidateEnum([]string{"icmp-ping", "tcp-ping", "http-get"}),
						children:      nil,
					},
					"target":                {desc: "Target IP, hostname, or URL", wildcard: &schemaNode{placeholder: "<target>", desc: "Target IP, hostname, or URL"}, children: map[string]*schemaNode{"url": {args: 1, desc: "HTTP target URL", children: nil}, "address": {args: 1, desc: "Target IP address (canonical Junos form)", children: nil}}},
					"source-address":        {args: 1, desc: "Source address for the probe", children: nil},
					"routing-instance":      {args: 1, desc: "Routing instance / VRF for the probe", children: nil},
					"destination-interface": {args: 1, desc: "Egress interface to pin the probe to", children: nil},
					"next-hop":              {args: 1, desc: "Next-hop IP to pin the probe via (reserved probe routing table)", children: nil},
					"probe-interval": {
						args:          1,
						desc:          "Seconds between probes within a test",
						valueType:     ValueInteger,
						valueDesc:     "Seconds between probes (>= 1)",
						valueExamples: []string{"5"},
						validator:     ValidateIntegerMin(1),
						children:      nil,
					},
					"probe-count": {
						args:          1,
						desc:          "Number of probes per test cycle",
						valueType:     ValueInteger,
						valueDesc:     "Probes per test cycle (>= 1)",
						valueExamples: []string{"3"},
						validator:     ValidateIntegerMin(1),
						children:      nil,
					},
					"test-interval": {
						args:          1,
						desc:          "Seconds between test cycles",
						valueType:     ValueInteger,
						valueDesc:     "Seconds between test cycles (>= 1)",
						valueExamples: []string{"30"},
						validator:     ValidateIntegerMin(1),
						children:      nil,
					},
					"thresholds": {desc: "Failure thresholds for the test", children: map[string]*schemaNode{
						"successive-loss": {
							args:          1,
							desc:          "Consecutive losses before marking the test failed",
							valueType:     ValueInteger,
							valueDesc:     "Consecutive losses before failure (>= 1)",
							valueExamples: []string{"3"},
							validator:     ValidateIntegerMin(1),
							children:      nil,
						},
					}},
					"probe-limit": {
						args:          1,
						desc:          "Maximum consecutive failed probes before stopping the current test cycle",
						valueType:     ValueInteger,
						valueDesc:     "Maximum consecutive failed probes (>= 1)",
						valueExamples: []string{"3"},
						validator:     ValidateIntegerMin(1),
						children:      nil,
					},
					// The compiler only enforces > 0; the TCP port wire
					// encoding is 16 bits, so 65536+ dialed and failed
					// silently at probe runtime.
					"destination-port": {
						args:          1,
						desc:          "Destination TCP port for tcp-ping probes",
						valueType:     ValueInteger,
						valueDesc:     "Destination TCP port (1..65535)",
						valueExamples: []string{"443"},
						validator:     ValidateInteger(1, 65535),
						children:      nil,
					},
				}},
			}},
		}},
		"ip-monitoring": {desc: "IP monitoring: probe-driven preferred-route failover", children: map[string]*schemaNode{
			"policy": {args: 1, desc: "IP monitoring policy name", placeholder: "<policy-name>", children: map[string]*schemaNode{
				"match": {desc: "Match conditions", children: map[string]*schemaNode{
					"rpm-probe": {args: 1, desc: "RPM probe whose test failures trigger this policy", placeholder: "<probe-name>", children: nil},
				}},
				"then": {desc: "Actions while the matched probe is FAILED", children: map[string]*schemaNode{
					"preferred-route": {desc: "Preferred routes injected at route preference 1", children: map[string]*schemaNode{
						"route": {args: 1, desc: "Destination prefix to inject", placeholder: "<prefix>", children: map[string]*schemaNode{
							"next-hop": {args: 1, desc: "Next-hop IP for the injected route, or a DHCP interface unit (<ifd>.<unit>) to track its learned gateway", children: nil},
							// Min-only, mirroring the compiler's loud
							// >= 0 check; the metric is a pure in-memory
							// tie-break comparator (pkg/ipmon/ipmon.go:361),
							// never wire-encoded.
							"preferred-metric": {
								args:          1,
								desc:          "Metric among injected routes for the same prefix (tie-break)",
								valueType:     ValueInteger,
								valueDesc:     "Tie-break metric among injected routes (>= 0)",
								valueExamples: []string{"10"},
								validator:     ValidateIntegerMin(0),
								children:      nil,
							},
						}},
						"routing-instance": {args: 1, desc: "Inject into a routing instance", placeholder: "<instance>", children: map[string]*schemaNode{
							"route": {args: 1, desc: "Destination prefix to inject", placeholder: "<prefix>", children: map[string]*schemaNode{
								"next-hop": {args: 1, desc: "Next-hop IP for the injected route, or a DHCP interface unit (<ifd>.<unit>) to track its learned gateway", children: nil},
								// See the sibling preferred-metric note.
								"preferred-metric": {
									args:          1,
									desc:          "Metric among injected routes for the same prefix (tie-break)",
									valueType:     ValueInteger,
									valueDesc:     "Tie-break metric among injected routes (>= 0)",
									valueExamples: []string{"10"},
									validator:     ValidateIntegerMin(0),
									children:      nil,
								},
							}},
						}},
					}},
				}},
				// The compiler rejects negatives loudly; the runtime
				// converts to time.Duration (pkg/ipmon/ipmon.go:480), so
				// the only genuine ceiling is the Duration-overflow
				// point (MaxDurationSeconds) — past it the hold went
				// negative and silently inverted the damping.
				"hold-down": {
					args:          1,
					desc:          "Seconds to damp recovery before withdrawing routes (0 = immediate, Junos parity)",
					valueType:     ValueInteger,
					valueDesc:     "Recovery damping in seconds (>= 0; 0 = immediate)",
					valueExamples: []string{"0", "30"},
					validator:     ValidateInteger(0, MaxDurationSeconds),
					children:      nil,
				},
			}},
		}},
		"flow-monitoring": {desc: "Flow export (NetFlow v9 / IPFIX) template configuration", children: map[string]*schemaNode{
			"version9": {desc: "NetFlow version 9 export", children: map[string]*schemaNode{
				"template": {desc: "NetFlow v9 flow record template", args: 1, placeholder: "<template-name>", children: map[string]*schemaNode{
					"flow-active-timeout":   {desc: "Active flow export timeout in seconds (default 60)", args: 1, placeholder: "<seconds>", children: nil},
					"flow-inactive-timeout": {desc: "Inactive flow export timeout in seconds (default 15)", args: 1, placeholder: "<seconds>", children: nil},
					"template-refresh-rate": {desc: "Interval between template re-exports", children: map[string]*schemaNode{
						"seconds": {desc: "Template refresh interval in seconds (default 60)", args: 1, placeholder: "<seconds>", children: nil},
					}},
				}},
			}},
			"version-ipfix": {desc: "IPFIX flow export", children: map[string]*schemaNode{
				"template": {desc: "IPFIX flow record template", args: 1, placeholder: "<template-name>", children: map[string]*schemaNode{
					"flow-active-timeout":   {desc: "Active flow export timeout in seconds (default 60)", args: 1, placeholder: "<seconds>", children: nil},
					"flow-inactive-timeout": {desc: "Inactive flow export timeout in seconds (default 15)", args: 1, placeholder: "<seconds>", children: nil},
					"template-refresh-rate": {desc: "Interval between template re-exports", children: map[string]*schemaNode{
						"seconds": {desc: "Template refresh interval in seconds (default 60)", args: 1, placeholder: "<seconds>", children: nil},
					}},
					"ipv4-template": {desc: "IPv4 flow record template options", children: map[string]*schemaNode{
						"export-extension": {desc: "Export extension (accepted; not applied to IPFIX records)", args: 1, placeholder: "<extension>", children: nil},
					}},
					"ipv6-template": {desc: "IPv6 flow record template options", children: map[string]*schemaNode{
						"export-extension": {desc: "Export extension (accepted; not applied to IPFIX records)", args: 1, placeholder: "<extension>", children: nil},
					}},
				}},
			}},
		}},
		"application-identification": {desc: "Enable application identification against the predefined application catalog (port/protocol matching; no L7 DPI)", children: nil},
	}},
	"forwarding-options": {children: map[string]*schemaNode{
		"family": {compoundKey: true, children: map[string]*schemaNode{
			"inet6": {children: map[string]*schemaNode{
				"mode": {args: 1, children: nil},
			}},
		}},
		"sampling": {children: map[string]*schemaNode{
			"instance": {args: 1, children: map[string]*schemaNode{
				"input": {children: nil},
				"family": {compoundKey: true, children: map[string]*schemaNode{
					"inet": {children: map[string]*schemaNode{
						"output": {children: map[string]*schemaNode{
							"flow-server":  {args: 1, children: nil},
							"inline-jflow": {children: nil},
						}},
					}},
					"inet6": {children: map[string]*schemaNode{
						"output": {children: map[string]*schemaNode{
							"flow-server":  {args: 1, children: nil},
							"inline-jflow": {children: nil},
						}},
					}},
				}},
			}},
		}},
		"port-mirroring": {children: map[string]*schemaNode{
			"instance": {args: 1, children: map[string]*schemaNode{
				"input": {children: map[string]*schemaNode{
					"ingress": {children: nil},
				}},
				"output": {children: nil},
			}},
		}},
		"dhcp-relay": {desc: "DHCP relay", children: map[string]*schemaNode{
			// server-group is a named container whose children are the
			// free-form server address leaves (same modeling as the
			// sampling flow-server node above).
			"server-group": {desc: "DHCP server group", args: 1, placeholder: "<name>", children: nil},
			"group": {desc: "DHCP relay group", args: 1, placeholder: "<name>", children: map[string]*schemaNode{
				"active-server-group": {desc: "Active server group", args: 1, placeholder: "<server-group>", children: nil},
				"interface":           {desc: "Interface to relay on", args: 1, multi: true, placeholder: "<interface>", children: nil},
			}},
		}},
	}},
	"bridge-domains": {desc: "Bridge domain configuration", wildcard: &schemaNode{desc: "Bridge domain name", children: map[string]*schemaNode{
		"vlan-id-list":      {args: 1, multi: true, desc: "VLAN IDs in this bridge domain", children: nil},
		"routing-interface": {args: 1, desc: "IRB routing interface (e.g. irb.0)", children: nil},
		"domain-type":       {args: 1, desc: "Bridge domain type", children: nil},
	}}},
	"routing-instances": {desc: "Routing instance configuration", wildcard: &schemaNode{desc: "Routing instance name", placeholder: "<instance-name>", children: map[string]*schemaNode{
		// instance-type and interface are NOT listed here → they become leaf nodes
		// e.g. "instance-type virtual-router;" and "interface enp7s0;"
		"routing-options": {desc: "Routing options", children: map[string]*schemaNode{
			"static": {desc: "Static routes", children: map[string]*schemaNode{
				"route": {desc: "Static route", args: 1, placeholder: "<destination>", children: nil},
			}},
			"rib": {desc: "Routing information base", args: 1, placeholder: "<rib-name>", children: map[string]*schemaNode{
				"static": {desc: "Static routes", children: map[string]*schemaNode{
					"route": {desc: "Static route", args: 1, placeholder: "<destination>", children: nil},
				}},
			}},
			"interface-routes": {desc: "Interface routes", children: map[string]*schemaNode{
				"rib-group": {desc: "RIB group", children: map[string]*schemaNode{
					"inet":  {desc: "IPv4 RIB group", args: 1, placeholder: "<group-name>", children: nil},
					"inet6": {desc: "IPv6 RIB group", args: 1, placeholder: "<group-name>", children: nil},
				}},
			}},
		}},
		"protocols": {desc: "Protocols configuration", children: map[string]*schemaNode{
			"ospf": {desc: "OSPF configuration", children: map[string]*schemaNode{
				"reference-bandwidth": {desc: "Reference bandwidth", args: 1, placeholder: "<bandwidth>", children: nil},
				"passive":             {desc: "Passive mode", children: nil},
				"area": {desc: "OSPF area", args: 1, placeholder: "<area-id>", children: map[string]*schemaNode{
					"interface": {desc: "Interface", args: 1, valueHint: ValueHintInterfaceName, placeholder: "<interface-name>", children: map[string]*schemaNode{
						"passive":        {desc: "Passive interface", children: nil},
						"no-passive":     {desc: "Non-passive interface", children: nil},
						"interface-type": {desc: "Interface type", args: 1, placeholder: "<type>", children: nil},
						"cost":           {desc: "Interface cost", args: 1, placeholder: "<cost>", children: nil},
						"authentication": {desc: "Authentication", children: map[string]*schemaNode{
							"md5": {desc: "MD5 authentication", args: 1, placeholder: "<key-id>", children: map[string]*schemaNode{
								"key": {desc: "Authentication key", args: 1, placeholder: "<key>", children: nil},
							}},
							"simple-password": {desc: "Simple password", args: 1, placeholder: "<password>", children: nil},
						}},
						"bfd-liveness-detection": {desc: "BFD liveness detection", children: map[string]*schemaNode{
							"minimum-interval": {desc: "Minimum interval", args: 1, placeholder: "<milliseconds>", children: nil},
							"multiplier":       {desc: "Multiplier", args: 1, placeholder: "<multiplier>", children: nil},
						}},
					}},
					"area-type": {desc: "Area type", children: map[string]*schemaNode{
						"stub": {desc: "Stub area", children: map[string]*schemaNode{
							"no-summaries": {desc: "No summaries", children: nil},
						}},
						"nssa": {desc: "NSSA area", children: map[string]*schemaNode{
							"no-summaries": {desc: "No summaries", children: nil},
						}},
					}},
					"virtual-link": {desc: "Virtual link", args: 1, placeholder: "<router-id>", children: map[string]*schemaNode{
						"transit-area": {desc: "Transit area", args: 1, placeholder: "<area-id>", children: nil},
					}},
				}},
			}},
			"ospf3": {desc: "OSPFv3 configuration", children: map[string]*schemaNode{
				"router-id": {desc: "Router ID", args: 1, placeholder: "<address>", children: nil},
				"export":    {desc: "Export policy", args: 1, multi: true, placeholder: "<policy-name>", children: nil},
				"area": {desc: "OSPFv3 area", args: 1, placeholder: "<area-id>", children: map[string]*schemaNode{
					"interface": {desc: "Interface", args: 1, valueHint: ValueHintInterfaceName, placeholder: "<interface-name>", children: map[string]*schemaNode{
						"passive": {desc: "Passive interface", children: nil},
						"cost":    {desc: "Interface cost", args: 1, placeholder: "<cost>", children: nil},
					}},
				}},
			}},
			"bgp": {desc: "BGP configuration", children: map[string]*schemaNode{
				"graceful-restart": {desc: "Graceful restart", children: nil},
				"damping": {desc: "Route damping", children: map[string]*schemaNode{
					"half-life":    {desc: "Half life", args: 1, placeholder: "<minutes>", children: nil},
					"reuse":        {desc: "Reuse threshold", args: 1, placeholder: "<value>", children: nil},
					"suppress":     {desc: "Suppress threshold", args: 1, placeholder: "<value>", children: nil},
					"max-suppress": {desc: "Max suppress time", args: 1, placeholder: "<minutes>", children: nil},
				}},
				"group": {desc: "BGP group", args: 1, placeholder: "<group-name>", children: nil},
			}},
			"isis": {desc: "IS-IS configuration", children: map[string]*schemaNode{
				"net":     {desc: "NET address", args: 1, placeholder: "<net-address>", children: nil},
				"level":   {desc: "Level", args: 1, placeholder: "<level>", children: nil},
				"is-type": {desc: "IS type", args: 1, placeholder: "<type>", children: nil},
				"export":  {desc: "Export policy", args: 1, multi: true, placeholder: "<policy-name>", children: nil},
				"interface": {desc: "Interface", args: 1, valueHint: ValueHintInterfaceName, placeholder: "<interface-name>", children: map[string]*schemaNode{
					"level":               {desc: "Level", args: 1, placeholder: "<level>", children: nil},
					"passive":             {desc: "Passive interface", children: nil},
					"metric":              {desc: "Metric", args: 1, placeholder: "<value>", children: nil},
					"authentication-key":  {desc: "Authentication key", args: 1, placeholder: "<key>", children: nil},
					"authentication-type": {desc: "Authentication type", args: 1, placeholder: "<type>", children: nil},
					"bfd-liveness-detection": {desc: "BFD liveness detection", children: map[string]*schemaNode{
						"minimum-interval": {desc: "Minimum interval", args: 1, placeholder: "<milliseconds>", children: nil},
						"multiplier":       {desc: "Multiplier", args: 1, placeholder: "<multiplier>", children: nil},
					}},
				}},
				"authentication-key":  {desc: "Authentication key", args: 1, placeholder: "<key>", children: nil},
				"authentication-type": {desc: "Authentication type", args: 1, placeholder: "<type>", children: nil},
				"wide-metrics-only":   {desc: "Wide metrics only", children: nil},
				"overload":            {desc: "Overload", children: nil},
			}},
		}},
	}}},
}}

func init() {
	// Wire groups wildcard to mirror top-level schema children.
	// This allows "set groups <name> security ..." etc. to parse correctly.
	groupWild := setSchema.children["groups"].wildcard
	groupWild.children = make(map[string]*schemaNode)
	for k, v := range setSchema.children {
		if k == "groups" || k == "apply-groups" {
			continue
		}
		groupWild.children[k] = v
	}
}

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
			"peer": {desc: "WireGuard peer", children: map[string]*schemaNode{
				"public-key":  {desc: "Peer static public key (hex)", args: 1, placeholder: "<hex-key>", children: nil},
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
			}},
		},
	}
}
