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
	"groups":       {desc: "Configuration groups", wildcard: &schemaNode{desc: "Group name", placeholder: "<group-name>"}}, // wildcard children set in init()
	"apply-groups": {desc: "Groups from which to inherit configuration data", args: 1, multi: true, placeholder: "<group-name>", children: nil},
	"security":     schemaSecurity,
	"interfaces":   schemaInterfaces,
	"applications": schemaApplications,
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
	"event-options": {desc: "Event policies for automated configuration changes", children: map[string]*schemaNode{
		"policy": {desc: "Event policy", args: 1, placeholder: "<policy-name>", children: map[string]*schemaNode{
			"events": {desc: "Events that trigger this policy", children: nil},
			"within": {desc: "Time window for trigger evaluation", args: 1, placeholder: "<seconds>", children: map[string]*schemaNode{
				"trigger": {desc: "Trigger condition (on|until <count>)", children: nil},
			}},
			"attributes-match": {desc: "Match event attributes (<event>.<attribute> matches <value>)", children: nil},
			"then": {desc: "Actions when the policy triggers", children: map[string]*schemaNode{
				"change-configuration": {desc: "Apply configuration changes", children: map[string]*schemaNode{
					"commands": {desc: "Configuration commands to apply (set/delete)", children: nil},
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
	"firewall": {desc: "Firewall filters and policers", children: map[string]*schemaNode{
		"policer": {desc: "Traffic policer", args: 1, multi: true, placeholder: "<name>", children: map[string]*schemaNode{
			"if-exceeding": {desc: "Rate limits for the policer", children: map[string]*schemaNode{
				"bandwidth-limit":  {desc: "Bandwidth limit in bits per second (k|m|g suffix)", args: 1, placeholder: "<bps>", children: nil},
				"burst-size-limit": {desc: "Burst size limit in bytes (k|m|g suffix)", args: 1, placeholder: "<bytes>", children: nil},
			}},
			"logical-interface-policer": {desc: "Logical interface policer (shared across protocol families)", children: nil},
			"then": {desc: "Action for traffic exceeding the limits", children: map[string]*schemaNode{
				"discard":       {desc: "Discard excess traffic (default)", children: nil},
				"loss-priority": {desc: "Set loss priority for excess traffic (high|medium-high|medium-low|low)", args: 1, placeholder: "<priority>", children: nil},
			}},
		}},
		"three-color-policer": {desc: "Three-color policer", args: 1, multi: true, placeholder: "<name>", children: map[string]*schemaNode{
			"single-rate": {desc: "Single-rate three-color policer (CIR/CBS/EBS)", children: map[string]*schemaNode{
				"color-blind":                {desc: "Color-blind mode", children: nil},
				"color-aware":                {desc: "Color-aware mode", children: nil},
				"committed-information-rate": {desc: "Committed information rate in bits per second (k|m|g suffix)", args: 1, placeholder: "<bps>", children: nil},
				"committed-burst-size":       {desc: "Committed burst size in bytes (k|m|g suffix)", args: 1, placeholder: "<bytes>", children: nil},
				"excess-burst-size":          {desc: "Excess burst size in bytes (k|m|g suffix)", args: 1, placeholder: "<bytes>", children: nil},
			}},
			"two-rate": {desc: "Two-rate three-color policer (CIR/CBS/PIR/PBS)", children: map[string]*schemaNode{
				"color-blind":                {desc: "Color-blind mode", children: nil},
				"color-aware":                {desc: "Color-aware mode", children: nil},
				"committed-information-rate": {desc: "Committed information rate in bits per second (k|m|g suffix)", args: 1, placeholder: "<bps>", children: nil},
				"committed-burst-size":       {desc: "Committed burst size in bytes (k|m|g suffix)", args: 1, placeholder: "<bytes>", children: nil},
				"peak-information-rate":      {desc: "Peak information rate in bits per second (k|m|g suffix)", args: 1, placeholder: "<bps>", children: nil},
				"peak-burst-size":            {desc: "Peak burst size in bytes (k|m|g suffix)", args: 1, placeholder: "<bytes>", children: nil},
			}},
			"then": {desc: "Action for out-of-profile traffic", children: map[string]*schemaNode{
				"discard":       {desc: "Discard out-of-profile traffic (default)", children: nil},
				"loss-priority": {desc: "Set loss priority for out-of-profile traffic", args: 1, placeholder: "<priority>", children: nil},
			}},
		}},
		"family": {desc: "Protocol family for firewall filters", compoundKey: true, children: map[string]*schemaNode{
			"inet": {desc: "IPv4 firewall filters", children: map[string]*schemaNode{
				"filter": {desc: "Firewall filter", args: 1, placeholder: "<filter-name>", children: map[string]*schemaNode{
					"term": {desc: "Filter term", args: 1, placeholder: "<term-name>", children: map[string]*schemaNode{
						"from": {desc: "Match conditions", children: map[string]*schemaNode{
							"source-address":          {desc: "Match source address", args: 1, multi: true, placeholder: "<address>", children: nil},
							"destination-address":     {desc: "Match destination address", args: 1, multi: true, placeholder: "<address>", children: nil},
							"source-prefix-list":      {desc: "Match source addresses from a prefix list", children: nil},
							"destination-prefix-list": {desc: "Match destination addresses from a prefix list", children: nil},
							"protocol":                {desc: "Match IP protocol", args: 1, multi: true, placeholder: "<protocol>", children: nil},
							"dscp":                    {desc: "Match DSCP value (name or number)", args: 1, multi: true, placeholder: "<dscp>", children: nil},
							"destination-port":        {desc: "Match destination port", args: 1, multi: true, placeholder: "<port>", children: nil},
							"source-port":             {desc: "Match source port", args: 1, multi: true, placeholder: "<port>", children: nil},
							"icmp-type":               {desc: "Match ICMP type (numeric)", args: 1, multi: true, placeholder: "<type>", children: nil},
							"icmp-code":               {desc: "Match ICMP code (numeric)", args: 1, multi: true, placeholder: "<code>", children: nil},
							"tcp-flags":               {desc: "Match TCP flags", args: 1, multi: true, placeholder: "<flags>", children: nil},
							"is-fragment":             {desc: "Match fragmented packets", children: nil},
							"flexible-match-range": {desc: "Flexible packet field match", children: map[string]*schemaNode{
								"range": {desc: "Named flexible match range", args: 1, placeholder: "<name>", children: map[string]*schemaNode{
									"match-start": {desc: "Match start point (only layer-3 supported)", args: 1, placeholder: "<start>", children: nil},
									"byte-offset": {desc: "Byte offset from match start", args: 1, placeholder: "<bytes>", children: nil},
									"bit-length":  {desc: "Match length in bits (default 32)", args: 1, placeholder: "<bits>", children: nil},
									"range":       {desc: "Match value and mask (0xVALUE[/0xMASK])", args: 1, placeholder: "<value>", children: nil},
									"match-value": {desc: "Value to match (0xVALUE[/0xMASK])", args: 1, placeholder: "<value>", children: nil},
									"match-mask":  {desc: "Mask applied to the match value (hex)", args: 1, placeholder: "<mask>", children: nil},
								}},
							}},
						}},
						"then": {desc: "Actions for matching packets", children: map[string]*schemaNode{
							"accept":           {desc: "Accept the packet", children: nil},
							"reject":           {desc: "Reject the packet", children: nil},
							"discard":          {desc: "Discard the packet", children: nil},
							"log":              {desc: "Log matching packets", children: nil},
							"syslog":           {desc: "Log matching packets to the system log", children: nil},
							"routing-instance": {desc: "Forward via routing instance (filter-based forwarding)", args: 1, placeholder: "<instance>", children: nil},
							"count":            {desc: "Count matching packets in a named counter", args: 1, placeholder: "<counter-name>", children: nil},
							// #1319 PR 3 tree-based cross-ref: the dataplane
							// resolves this name against the CONFIGURED
							// forwarding classes and silently defaults the
							// queue on a miss (see validateForwardingClassRef
							// for the runtime citations and the best-effort
							// special case).
							"forwarding-class": {
								desc:          "Assign forwarding class",
								args:          1,
								valueType:     ValueIdentifier,
								valueDesc:     "Forwarding class to assign (must be defined under class-of-service forwarding-classes, or best-effort)",
								valueExamples: []string{"best-effort"},
								treeValidator: validateForwardingClassRef,
								children:      nil,
							},
							"loss-priority": {desc: "Set packet loss priority (low|medium-low|medium-high|high)", args: 1, placeholder: "<priority>", children: nil},
							"dscp":          {desc: "Rewrite the DSCP value (name or number)", args: 1, placeholder: "<dscp>", children: nil},
							"traffic-class": {desc: "Rewrite the traffic class (DSCP name or number)", args: 1, placeholder: "<traffic-class>", children: nil},
							"policer":       {desc: "Apply a policer to matching traffic", args: 1, placeholder: "<policer-name>", children: nil},
						}},
					}},
				}},
			}},
			"inet6": {desc: "IPv6 firewall filters", children: map[string]*schemaNode{
				"filter": {desc: "Firewall filter", args: 1, placeholder: "<filter-name>", children: map[string]*schemaNode{
					"term": {desc: "Filter term", args: 1, placeholder: "<term-name>", children: map[string]*schemaNode{
						"from": {desc: "Match conditions", children: map[string]*schemaNode{
							"source-address":          {desc: "Match source address", args: 1, multi: true, placeholder: "<address>", children: nil},
							"destination-address":     {desc: "Match destination address", args: 1, multi: true, placeholder: "<address>", children: nil},
							"source-prefix-list":      {desc: "Match source addresses from a prefix list", children: nil},
							"destination-prefix-list": {desc: "Match destination addresses from a prefix list", children: nil},
							"protocol":                {desc: "Match IP protocol", args: 1, multi: true, placeholder: "<protocol>", children: nil},
							"traffic-class":           {desc: "Match traffic class (DSCP name or number)", args: 1, multi: true, placeholder: "<traffic-class>", children: nil},
							"destination-port":        {desc: "Match destination port", args: 1, multi: true, placeholder: "<port>", children: nil},
							"source-port":             {desc: "Match source port", args: 1, multi: true, placeholder: "<port>", children: nil},
							"icmp-type":               {desc: "Match ICMP type (numeric)", args: 1, multi: true, placeholder: "<type>", children: nil},
							"icmp-code":               {desc: "Match ICMP code (numeric)", args: 1, multi: true, placeholder: "<code>", children: nil},
							"tcp-flags":               {desc: "Match TCP flags", args: 1, multi: true, placeholder: "<flags>", children: nil},
							"is-fragment":             {desc: "Match fragmented packets", children: nil},
							"flexible-match-range": {desc: "Flexible packet field match", children: map[string]*schemaNode{
								"range": {desc: "Named flexible match range", args: 1, placeholder: "<name>", children: map[string]*schemaNode{
									"match-start": {desc: "Match start point (only layer-3 supported)", args: 1, placeholder: "<start>", children: nil},
									"byte-offset": {desc: "Byte offset from match start", args: 1, placeholder: "<bytes>", children: nil},
									"bit-length":  {desc: "Match length in bits (default 32)", args: 1, placeholder: "<bits>", children: nil},
									"range":       {desc: "Match value and mask (0xVALUE[/0xMASK])", args: 1, placeholder: "<value>", children: nil},
									"match-value": {desc: "Value to match (0xVALUE[/0xMASK])", args: 1, placeholder: "<value>", children: nil},
									"match-mask":  {desc: "Mask applied to the match value (hex)", args: 1, placeholder: "<mask>", children: nil},
								}},
							}},
						}},
						"then": {desc: "Actions for matching packets", children: map[string]*schemaNode{
							"accept":           {desc: "Accept the packet", children: nil},
							"reject":           {desc: "Reject the packet", children: nil},
							"discard":          {desc: "Discard the packet", children: nil},
							"log":              {desc: "Log matching packets", children: nil},
							"syslog":           {desc: "Log matching packets to the system log", children: nil},
							"routing-instance": {desc: "Forward via routing instance (filter-based forwarding)", args: 1, placeholder: "<instance>", children: nil},
							"count":            {desc: "Count matching packets in a named counter", args: 1, placeholder: "<counter-name>", children: nil},
							// #1319 PR 3 tree-based cross-ref: the dataplane
							// resolves this name against the CONFIGURED
							// forwarding classes and silently defaults the
							// queue on a miss (see validateForwardingClassRef
							// for the runtime citations and the best-effort
							// special case).
							"forwarding-class": {
								desc:          "Assign forwarding class",
								args:          1,
								valueType:     ValueIdentifier,
								valueDesc:     "Forwarding class to assign (must be defined under class-of-service forwarding-classes, or best-effort)",
								valueExamples: []string{"best-effort"},
								treeValidator: validateForwardingClassRef,
								children:      nil,
							},
							"loss-priority": {desc: "Set packet loss priority (low|medium-low|medium-high|high)", args: 1, placeholder: "<priority>", children: nil},
							"dscp":          {desc: "Rewrite the DSCP value (name or number)", args: 1, placeholder: "<dscp>", children: nil},
							"traffic-class": {desc: "Rewrite the traffic class (DSCP name or number)", args: 1, placeholder: "<traffic-class>", children: nil},
							"policer":       {desc: "Apply a policer to matching traffic", args: 1, placeholder: "<policer-name>", children: nil},
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
			"cpu-governor": {args: 1, desc: "Host cpufreq governor (performance|schedutil|default; other governors pass through verbatim)", children: nil},
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
	"forwarding-options": {desc: "Packet forwarding options", children: map[string]*schemaNode{
		"family": {desc: "Protocol family forwarding options", compoundKey: true, children: map[string]*schemaNode{
			"inet6": {desc: "IPv6 forwarding options", children: map[string]*schemaNode{
				"mode": {desc: "IPv6 forwarding mode (flow-based|packet-based)", args: 1, placeholder: "<mode>", children: nil},
			}},
		}},
		"sampling": {desc: "Traffic sampling for flow export", children: map[string]*schemaNode{
			"instance": {desc: "Sampling instance", args: 1, placeholder: "<instance-name>", children: map[string]*schemaNode{
				"input": {desc: "Sampling input properties (rate)", children: nil},
				"family": {desc: "Address family to sample", compoundKey: true, children: map[string]*schemaNode{
					"inet": {desc: "IPv4 flow sampling", children: map[string]*schemaNode{
						"output": {desc: "Sampling output configuration", children: map[string]*schemaNode{
							"flow-server":  {desc: "Flow collector address", args: 1, placeholder: "<address>", children: nil},
							"inline-jflow": {desc: "Inline flow export (jflow)", children: nil},
						}},
					}},
					"inet6": {desc: "IPv6 flow sampling", children: map[string]*schemaNode{
						"output": {desc: "Sampling output configuration", children: map[string]*schemaNode{
							"flow-server":  {desc: "Flow collector address", args: 1, placeholder: "<address>", children: nil},
							"inline-jflow": {desc: "Inline flow export (jflow)", children: nil},
						}},
					}},
				}},
			}},
		}},
		"port-mirroring": {desc: "Port mirroring", children: map[string]*schemaNode{
			"instance": {desc: "Port mirroring instance", args: 1, placeholder: "<instance-name>", children: map[string]*schemaNode{
				"input": {desc: "Mirrored input traffic (rate, ingress interfaces)", children: map[string]*schemaNode{
					"ingress": {desc: "Interfaces to mirror at ingress", children: nil},
				}},
				"output": {desc: "Mirror destination interface", children: nil},
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
