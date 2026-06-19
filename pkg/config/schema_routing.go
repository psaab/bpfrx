package config

// schema_routing.go carries the routing/forwarding subtrees of the
// config-mode grammar SSOT (#1891 domain split): `routing-options`,
// `policy-options`, `protocols`, `forwarding-options`,
// `bridge-domains`, and `routing-instances`. The root composition, the
// schemaNode type, and the split rationale live in schema.go.

var schemaRoutingOptions = &schemaNode{desc: "Routing options", children: map[string]*schemaNode{
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
}}

var schemaPolicyOptions = &schemaNode{desc: "Policy options", children: map[string]*schemaNode{
	"prefix-list": {desc: "Prefix list", args: 1, placeholder: "<name>", children: nil},
	"community": {desc: "Community", args: 1, placeholder: "<name>", children: map[string]*schemaNode{
		"members": {desc: "Community members", args: 1, multi: true, placeholder: "<community>", children: nil},
	}},
	"as-path": {desc: "AS path", args: 2, multi: true, placeholder: "<name>", children: nil},
	"policy-statement": {desc: "Policy statement", args: 1, placeholder: "<name>", children: map[string]*schemaNode{
		"term": {desc: "Term name", args: 1, placeholder: "<term-name>", children: map[string]*schemaNode{
			"from": {desc: "Match condition", children: map[string]*schemaNode{
				// "from protocol" is a multi-value match: Junos accepts
				// "from protocol [ bgp ospf static ]" and, equivalently, a
				// sequence of separate "set ... from protocol <X>" commands.
				// Mark it multi so SetPath keeps every protocol as a sibling
				// leaf instead of replacing the previous one (#2008 H18 /
				// Copilot #2011). A single-value leaf collapses separate set
				// commands down to only the last protocol.
				"protocol":     {desc: "Protocol", args: 1, multi: true, placeholder: "<protocol>", children: nil},
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
}}

var schemaProtocols = &schemaNode{desc: "Protocols configuration", children: map[string]*schemaNode{
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
			// #2008 (LOW, RA schema-only): max/min-advertisement-interval,
			// default-lifetime, link-mtu, managed-configuration,
			// other-stateful-configuration and dns-server-address are all
			// compiled (compiler_protocols.go compileRouterAdvertisement)
			// and honored by the RA sender (pkg/ra), but the schema only
			// declared prefix/preference/nat-prefix/nat64prefix — the rest
			// fell through with no completion or commit-time validation. The
			// second-denominated leaves silently compile to 0 on garbage
			// (Atoi error path), so type them as positive integers.
			"managed-configuration":        {desc: "Set the Managed Address Configuration (M) flag", children: nil},
			"other-stateful-configuration": {desc: "Set the Other Stateful Configuration (O) flag", children: nil},
			"max-advertisement-interval": {desc: "Maximum time between unsolicited RAs (seconds)", args: 1, placeholder: "<seconds>",
				valueType: ValueInteger, valueDesc: "max RA interval in seconds",
				valueExamples: []string{"600", "1800"}, validator: ValidateIntegerMin(1), children: nil},
			"min-advertisement-interval": {desc: "Minimum time between unsolicited RAs (seconds)", args: 1, placeholder: "<seconds>",
				valueType: ValueInteger, valueDesc: "min RA interval in seconds",
				valueExamples: []string{"200", "600"}, validator: ValidateIntegerMin(1), children: nil},
			"default-lifetime": {desc: "Router lifetime advertised to hosts (seconds)", args: 1, placeholder: "<seconds>",
				valueType: ValueInteger, valueDesc: "router lifetime in seconds",
				valueExamples: []string{"1800", "9000"}, validator: ValidateIntegerMin(1), children: nil},
			"link-mtu": {desc: "Link MTU option advertised to hosts", args: 1, placeholder: "<mtu>",
				valueType: ValueInteger, valueDesc: "advertised link MTU",
				valueExamples: []string{"1280", "1500"}, validator: ValidateIntegerMin(1), children: nil},
			"dns-server-address": {desc: "RDNSS DNS server address advertised to hosts", args: 1, multi: true, placeholder: "<address>", children: nil},
			"preference":         {desc: "Default router preference (high|medium|low)", args: 1, placeholder: "<preference>", children: nil},
			"prefix": {desc: "Advertised on-link prefix", args: 1, placeholder: "<prefix>", children: map[string]*schemaNode{ // prefix <prefix/len>
				"on-link":            {desc: "Set the on-link (L) flag (default)", children: nil},
				"autonomous":         {desc: "Set the autonomous (A) flag (default)", children: nil},
				"no-onlink":          {desc: "Clear the on-link (L) flag", children: nil},
				"no-autonomous":      {desc: "Clear the autonomous (A) flag", children: nil},
				"valid-lifetime":     {desc: "Prefix valid lifetime (seconds)", args: 1, placeholder: "<seconds>", children: nil},
				"preferred-lifetime": {desc: "Prefix preferred lifetime (seconds)", args: 1, placeholder: "<seconds>", children: nil},
			}},
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
}}

var schemaForwardingOptions = &schemaNode{desc: "Packet forwarding options", children: map[string]*schemaNode{
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
}}

var schemaBridgeDomains = &schemaNode{desc: "Bridge domain configuration", wildcard: &schemaNode{desc: "Bridge domain name", children: map[string]*schemaNode{
	"vlan-id-list":      {args: 1, multi: true, desc: "VLAN IDs in this bridge domain", children: nil},
	"routing-interface": {args: 1, desc: "IRB routing interface (e.g. irb.0)", children: nil},
	"domain-type":       {args: 1, desc: "Bridge domain type", children: nil},
}}}

var schemaRoutingInstances = &schemaNode{desc: "Routing instance configuration", wildcard: &schemaNode{desc: "Routing instance name", placeholder: "<instance-name>", children: map[string]*schemaNode{
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
}}}
