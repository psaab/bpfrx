package config

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Node represents a node in the Junos configuration tree.
// It is either a leaf (terminated by ;) or a block (containing children in {}).
type Node struct {
	// Keys is the sequence of identifiers forming this node's identity.
	// Examples:
	//   "security" -> ["security"]
	//   "security-zone trust" -> ["security-zone", "trust"]
	//   "from-zone trust to-zone untrust" -> ["from-zone", "trust", "to-zone", "untrust"]
	//   "address 10.0.1.0/24" -> ["address", "10.0.1.0/24"]
	Keys []string

	// Children are the nodes within this block's braces.
	// nil for leaf nodes.
	Children []*Node

	// IsLeaf is true when the node is terminated by ; (no block body).
	IsLeaf bool

	// Line/Column where this node starts (for error reporting).
	Line   int
	Column int
}

// Name returns the first key of the node.
func (n *Node) Name() string {
	if len(n.Keys) == 0 {
		return ""
	}
	return n.Keys[0]
}

// KeyPath returns the full key path as a single string.
func (n *Node) KeyPath() string {
	return strings.Join(n.Keys, " ")
}

// FindChild returns the first child whose first key matches name.
func (n *Node) FindChild(name string) *Node {
	for _, child := range n.Children {
		if len(child.Keys) > 0 && child.Keys[0] == name {
			return child
		}
	}
	return nil
}

// FindChildren returns all children whose first key matches name.
func (n *Node) FindChildren(name string) []*Node {
	var result []*Node
	for _, child := range n.Children {
		if len(child.Keys) > 0 && child.Keys[0] == name {
			result = append(result, child)
		}
	}
	return result
}

// ConfigTree is the root of a parsed configuration.
type ConfigTree struct {
	Children []*Node
}

// FindChild returns the first top-level child matching name.
func (t *ConfigTree) FindChild(name string) *Node {
	for _, child := range t.Children {
		if len(child.Keys) > 0 && child.Keys[0] == name {
			return child
		}
	}
	return nil
}

// Clone creates a deep copy of the config tree.
func (t *ConfigTree) Clone() *ConfigTree {
	if t == nil {
		return nil
	}
	return &ConfigTree{
		Children: cloneNodes(t.Children),
	}
}

func cloneNodes(nodes []*Node) []*Node {
	if nodes == nil {
		return nil
	}
	result := make([]*Node, len(nodes))
	for i, n := range nodes {
		result[i] = &Node{
			Keys:     append([]string(nil), n.Keys...),
			Children: cloneNodes(n.Children),
			IsLeaf:   n.IsLeaf,
			Line:     n.Line,
			Column:   n.Column,
		}
	}
	return result
}

// ValueHint identifies what kind of dynamic value is expected at a schema position.
type ValueHint int

const (
	ValueHintNone          ValueHint = iota
	ValueHintZoneName                // security-zone <name>
	ValueHintAddressName             // address-set <name>
	ValueHintAppName                 // application <name>
	ValueHintPoolName                // pool <name>
	ValueHintInterfaceName           // interfaces <name>
	ValueHintScreenProfile           // ids-option <name>
	ValueHintStreamName              // stream <name>
	ValueHintAppSetName              // application-set <name>
)

// ValueProvider returns possible values for a given hint.
type ValueProvider func(hint ValueHint) []string

// schemaNode defines a container keyword in the Junos config hierarchy.
// It tells SetPath how to group flat path tokens into the correct tree structure.
type schemaNode struct {
	args      int                    // extra tokens consumed as part of this node's key
	children  map[string]*schemaNode // known container children
	wildcard  *schemaNode            // matches any keyword not in children (for dynamic names)
	valueHint ValueHint              // hint for dynamic value completion (when args > 0)
}

// setSchema defines the Junos configuration tree structure.
// Keywords present in the schema at a given depth are treated as containers.
// Keywords NOT in the schema become leaf nodes (all remaining tokens form the leaf's Keys).
var setSchema = &schemaNode{children: map[string]*schemaNode{
	"security": {children: map[string]*schemaNode{
		"zones": {children: map[string]*schemaNode{
			"security-zone": {args: 1, valueHint: ValueHintZoneName, children: map[string]*schemaNode{
				"interfaces": {children: nil},
				"tcp-rst":    {children: nil},
				"screen":     {args: 1, children: nil},
				"host-inbound-traffic": {children: map[string]*schemaNode{
					"system-services": {children: nil},
					"protocols":       {children: nil},
				}},
			}},
		}},
		"policies": {children: map[string]*schemaNode{
			"from-zone": {args: 3, children: map[string]*schemaNode{ // from-zone X to-zone Y
				"policy": {args: 1, children: map[string]*schemaNode{
					"match": {children: nil}, // match children are all leaves
					"then": {children: map[string]*schemaNode{
						"log": {children: nil},
						// permit, deny, reject, count → leaf
					}},
				}},
			}},
		}},
		"screen": {children: map[string]*schemaNode{
			"ids-option": {args: 1, valueHint: ValueHintScreenProfile, children: map[string]*schemaNode{
				"icmp": {children: nil},
				"tcp": {children: map[string]*schemaNode{
					"syn-flood": {children: nil},
					// land, winnuke, syn-frag → leaf
				}},
				"ip":  {children: nil},
				"udp": {children: nil},
			}},
		}},
		"nat": {children: map[string]*schemaNode{
			"source": {children: map[string]*schemaNode{
				"pool":              {args: 1, valueHint: ValueHintPoolName, children: nil},
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
							"source-address":      {args: 1, children: nil},
							"destination-address":  {args: 1, children: nil},
							"destination-port":     {args: 1, children: nil},
							"application":          {args: 1, children: nil},
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
							"source-address":       {args: 1, children: nil},
							"destination-address":  {args: 1, children: nil},
							"destination-port":     {args: 1, children: nil},
							"protocol":             {args: 1, children: nil},
							"application":          {args: 1, children: nil},
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
						"then":  {children: map[string]*schemaNode{
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
		}},
		"address-book": {children: map[string]*schemaNode{
			"global": {children: map[string]*schemaNode{
				"address-set": {args: 1, valueHint: ValueHintAddressName, children: map[string]*schemaNode{
					"address-set": {args: 1, valueHint: ValueHintAddressName, children: nil},
				}},
				// "address <name> <cidr>" not listed → leaf
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
			"tcp-session":                  {children: nil},
			"udp-session":                  {children: nil},
			"icmp-session":                 {children: nil},
			"tcp-mss":                      {children: nil},
			"allow-dns-reply":              {children: nil},
			"allow-embedded-icmp":          {children: nil},
			"gre-performance-acceleration": {children: nil},
			"power-mode-disable":           {children: nil},
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
				"address":              {args: 1, children: nil},
				"local-address":        {args: 1, children: nil},
				"ike-policy":           {args: 1, children: nil},
				"external-interface":   {args: 1, children: nil},
				"version":              {args: 1, children: nil},
				"no-nat-traversal":     {children: nil},
				"dead-peer-detection":  {args: 1, children: nil},
				"local-identity":       {children: nil},
				"remote-identity":      {children: nil},
				"dynamic":              {children: nil},
			}},
		}},
		"ipsec": {children: map[string]*schemaNode{
			"proposal": {args: 1, children: nil},
			"policy": {args: 1, children: map[string]*schemaNode{
				"perfect-forward-secrecy": {children: nil},
				"proposals":               {args: 1, children: nil},
			}},
			"gateway": {args: 1, children: map[string]*schemaNode{
				"address":              {args: 1, children: nil},
				"local-address":        {args: 1, children: nil},
				"ike-policy":           {args: 1, children: nil},
				"external-interface":   {args: 1, children: nil},
				"version":              {args: 1, children: nil},
				"no-nat-traversal":     {children: nil},
				"dead-peer-detection":  {args: 1, children: nil},
				"local-identity":       {children: nil},
				"remote-identity":      {children: nil},
				"dynamic":              {children: nil},
			}},
			"vpn": {args: 1, children: map[string]*schemaNode{
				"bind-interface":    {args: 1, children: nil},
				"df-bit":           {args: 1, children: nil},
				"establish-tunnels": {args: 1, children: nil},
				"ike": {children: map[string]*schemaNode{
					"gateway":      {args: 1, children: nil},
					"ipsec-policy": {args: 1, children: nil},
				}},
			}},
		}},
		"dynamic-address": {children: map[string]*schemaNode{
			"feed-server": {args: 1, children: nil},
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
	"interfaces": {wildcard: &schemaNode{valueHint: ValueHintInterfaceName, children: map[string]*schemaNode{
		"description":  {args: 1, children: nil},
		"vlan-tagging": {children: nil},
		"gigether-options": {children: map[string]*schemaNode{
			"redundant-parent": {args: 1, children: nil},
		}},
		"redundant-ether-options": {children: map[string]*schemaNode{
			"redundancy-group": {args: 1, children: nil},
		}},
		"fabric-options": {children: map[string]*schemaNode{
			"member-interfaces": {children: nil},
		}},
		"tunnel": {children: map[string]*schemaNode{
			"source":      {args: 1, children: nil},
			"destination": {args: 1, children: nil},
			"mode":        {args: 1, children: nil},
			"key":         {args: 1, children: nil},
			"ttl":         {args: 1, children: nil},
			"routing-instance": {children: map[string]*schemaNode{
				"destination": {args: 1, children: nil},
			}},
		}},
		"unit": {args: 1, children: map[string]*schemaNode{
			"description":    {args: 1, children: nil},
			"point-to-point": {children: nil},
			"vlan-id":        {args: 1, children: nil},
			"tunnel":         {children: nil},
			"family": {children: map[string]*schemaNode{
				"inet": {children: map[string]*schemaNode{
					"mtu":     {args: 1, children: nil},
					"address": {args: 1, children: map[string]*schemaNode{
						"primary":   {children: nil},
						"preferred": {children: nil},
					}},
					"dhcp": {children: map[string]*schemaNode{
						"lease-time":              {args: 1, children: nil},
						"retransmission-attempt":  {args: 1, children: nil},
						"retransmission-interval": {args: 1, children: nil},
						"force-discover":          {children: nil},
					}},
					"sampling": {children: map[string]*schemaNode{
						"input":  {children: nil},
						"output": {children: nil},
					}},
					"filter": {children: map[string]*schemaNode{
						"input":  {args: 1, children: nil},
						"output": {args: 1, children: nil},
					}},
				}},
				"inet6": {children: map[string]*schemaNode{
					"mtu":         {args: 1, children: nil},
					"dad-disable": {children: nil},
					"address":     {args: 1, children: map[string]*schemaNode{
						"primary":   {children: nil},
						"preferred": {children: nil},
					}},
					"sampling": {children: map[string]*schemaNode{
						"input":  {children: nil},
						"output": {children: nil},
					}},
					"filter": {children: map[string]*schemaNode{
						"input":  {args: 1, children: nil},
						"output": {args: 1, children: nil},
					}},
					"dhcpv6-client": {children: map[string]*schemaNode{
						"client-type":    {args: 1, children: nil},
						"client-ia-type": {args: 1, children: nil},
						"prefix-delegating": {children: map[string]*schemaNode{
							"preferred-prefix-length": {args: 1, children: nil},
							"sub-prefix-length":       {args: 1, children: nil},
						}},
						"client-identifier": {children: map[string]*schemaNode{
							"duid-type": {args: 1, children: nil},
						}},
						"req-option": {args: 1, children: nil},
						"update-router-advertisement": {children: map[string]*schemaNode{
							"interface": {args: 1, children: nil},
						}},
					}},
				}},
			}},
		}},
	}}},
	"applications": {children: map[string]*schemaNode{
		"application": {args: 1, valueHint: ValueHintAppName, children: map[string]*schemaNode{
			"protocol":           {args: 1, children: nil},
			"destination-port":   {args: 1, children: nil},
			"source-port":        {args: 1, children: nil},
			"inactivity-timeout": {args: 1, children: nil},
			"alg":                {args: 1, children: nil},
			"description":        {args: 1, children: nil},
			"term":               {args: 1, children: nil},
		}},
		"application-set": {args: 1, valueHint: ValueHintAppSetName, children: nil},
	}},
	"routing-options": {children: map[string]*schemaNode{
		"static": {children: map[string]*schemaNode{
			"route": {args: 1, children: nil},
		}},
		"rib": {args: 1, children: map[string]*schemaNode{
			"static": {children: map[string]*schemaNode{
				"route": {args: 1, children: nil},
			}},
		}},
		"autonomous-system": {args: 1, children: nil},
		"forwarding-table": {children: map[string]*schemaNode{
			"export": {args: 1, children: nil},
		}},
	}},
	"snmp": {children: map[string]*schemaNode{
		"community": {args: 1, children: map[string]*schemaNode{
			"authorization": {args: 1, children: nil},
		}},
		"trap-group": {args: 1, children: nil},
	}},
	"policy-options": {children: map[string]*schemaNode{
		"prefix-list": {args: 1, children: nil},
		"policy-statement": {args: 1, children: map[string]*schemaNode{
			"term": {args: 1, children: map[string]*schemaNode{
				"from": {children: map[string]*schemaNode{
					"protocol":     {args: 1, children: nil},
					"prefix-list":  {args: 1, children: nil},
					"route-filter": {args: 2, children: nil},
				}},
				"then": {children: map[string]*schemaNode{
					"accept":       {children: nil},
					"reject":       {children: nil},
					"next-hop":     {args: 1, children: nil},
					"load-balance": {args: 1, children: nil},
				}},
			}},
			"then": {children: nil},
		}},
	}},
	"protocols": {children: map[string]*schemaNode{
		"ospf": {children: map[string]*schemaNode{
			"router-id": {args: 1, children: nil},
			"export":    {args: 1, children: nil},
			"area": {args: 1, children: map[string]*schemaNode{
				"interface": {args: 1, valueHint: ValueHintInterfaceName, children: map[string]*schemaNode{
					"passive": {children: nil},
					"cost":    {args: 1, children: nil},
				}},
			}},
		}},
		"bgp": {children: map[string]*schemaNode{
			"local-as":  {args: 1, children: nil},
			"router-id": {args: 1, children: nil},
			"export":    {args: 1, children: nil},
			"group": {args: 1, children: map[string]*schemaNode{
				"peer-as":     {args: 1, children: nil},
				"description": {args: 1, children: nil},
				"multihop":    {args: 1, children: nil},
				"export":      {args: 1, children: nil},
				"family": {children: map[string]*schemaNode{
					"inet":  {children: nil},
					"inet6": {children: nil},
				}},
				"neighbor": {args: 1, children: map[string]*schemaNode{
					"description": {args: 1, children: nil},
					"peer-as":     {args: 1, children: nil},
					"multihop":    {args: 1, children: nil},
				}},
			}},
		}},
		"rip": {children: map[string]*schemaNode{
			"group":             {args: 1, children: nil},
			"neighbor":          {args: 1, valueHint: ValueHintInterfaceName, children: nil},
			"passive-interface": {args: 1, valueHint: ValueHintInterfaceName, children: nil},
			"redistribute":      {args: 1, children: nil},
		}},
		"isis": {children: map[string]*schemaNode{
			"net":       {args: 1, children: nil},
			"level":     {args: 1, children: nil},
			"is-type":   {args: 1, children: nil},
			"export":    {args: 1, children: nil},
			"interface": {args: 1, valueHint: ValueHintInterfaceName, children: nil},
		}},
		"router-advertisement": {children: map[string]*schemaNode{
			"interface": {args: 1, valueHint: ValueHintInterfaceName, children: map[string]*schemaNode{
				"prefix":     {args: 1, children: nil}, // prefix <prefix/len>
				"preference": {args: 1, children: nil},
				"nat-prefix":   {args: 1, children: map[string]*schemaNode{
					"lifetime": {args: 1, children: nil},
				}},
				"nat64prefix": {args: 1, children: map[string]*schemaNode{
					"lifetime": {args: 1, children: nil},
				}},
			}},
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
	"chassis": {children: map[string]*schemaNode{
		"cluster": {children: map[string]*schemaNode{
			"reth-count": {args: 1, children: nil},
			"redundancy-group": {args: 1, children: map[string]*schemaNode{
				"node": {args: 1, children: map[string]*schemaNode{
					"priority": {args: 1, children: nil},
				}},
				"gratuitous-arp-count": {args: 1, children: nil},
				"interface-monitor":    {children: nil},
			}},
		}},
	}},
	"firewall": {children: map[string]*schemaNode{
		"family": {children: map[string]*schemaNode{
			"inet": {children: map[string]*schemaNode{
				"filter": {args: 1, children: map[string]*schemaNode{
					"term": {args: 1, children: map[string]*schemaNode{
						"from": {children: map[string]*schemaNode{
							"source-address":          {children: nil},
							"destination-address":     {children: nil},
							"source-prefix-list":      {children: nil},
							"destination-prefix-list": {children: nil},
							"protocol":                {args: 1, children: nil},
							"dscp":                    {args: 1, children: nil},
							"destination-port":        {children: nil},
							"source-port":             {children: nil},
							"icmp-type":               {args: 1, children: nil},
							"icmp-code":               {args: 1, children: nil},
						}},
						"then": {children: map[string]*schemaNode{
							"accept":           {children: nil},
							"reject":           {children: nil},
							"discard":          {children: nil},
							"log":              {children: nil},
							"syslog":           {children: nil},
							"routing-instance": {args: 1, children: nil},
							"count":            {args: 1, children: nil},
							"forwarding-class": {args: 1, children: nil},
							"loss-priority":    {args: 1, children: nil},
						}},
					}},
				}},
			}},
			"inet6": {children: map[string]*schemaNode{
				"filter": {args: 1, children: map[string]*schemaNode{
					"term": {args: 1, children: map[string]*schemaNode{
						"from": {children: map[string]*schemaNode{
							"source-address":          {children: nil},
							"destination-address":     {children: nil},
							"source-prefix-list":      {children: nil},
							"destination-prefix-list": {children: nil},
							"protocol":                {args: 1, children: nil},
							"traffic-class":           {args: 1, children: nil},
							"destination-port":        {children: nil},
							"source-port":             {children: nil},
							"icmp-type":               {args: 1, children: nil},
							"icmp-code":               {args: 1, children: nil},
						}},
						"then": {children: map[string]*schemaNode{
							"accept":           {children: nil},
							"reject":           {children: nil},
							"discard":          {children: nil},
							"log":              {children: nil},
							"syslog":           {children: nil},
							"routing-instance": {args: 1, children: nil},
							"count":            {args: 1, children: nil},
							"forwarding-class": {args: 1, children: nil},
							"loss-priority":    {args: 1, children: nil},
						}},
					}},
				}},
			}},
		}},
	}},
	"system": {children: map[string]*schemaNode{
		"host-name":     {args: 1, children: nil},
		"time-zone":     {args: 1, children: nil},
		"no-redirects":  {children: nil},
		"name-server":   {children: nil},
		"backup-router": {args: 1, children: map[string]*schemaNode{
			"destination": {args: 1, children: nil},
		}},
		"root-authentication": {children: map[string]*schemaNode{
			"encrypted-password": {args: 1, children: nil},
			"ssh-ed25519":        {args: 1, children: nil},
			"ssh-rsa":            {args: 1, children: nil},
			"ssh-dsa":            {args: 1, children: nil},
		}},
		"archival": {children: map[string]*schemaNode{
			"configuration": {children: map[string]*schemaNode{
				"transfer-on-commit": {children: nil},
				"archive-sites":      {args: 1, children: nil},
			}},
		}},
		"master-password": {children: map[string]*schemaNode{
			"pseudorandom-function": {args: 1, children: nil},
		}},
		"license": {children: map[string]*schemaNode{
			"autoupdate": {children: map[string]*schemaNode{
				"url": {args: 1, children: nil},
			}},
		}},
		"processes": {children: nil},
		"internet-options": {children: map[string]*schemaNode{
			"no-ipv6-reject-zero-hop-limit": {children: nil},
		}},
		"ntp": {children: map[string]*schemaNode{
			"server": {args: 1, children: nil},
			"threshold": {args: 1, children: map[string]*schemaNode{
				"action": {args: 1, children: nil},
			}},
		}},
		"syslog": {children: map[string]*schemaNode{
			"user": {args: 1, children: nil},
			"host": {args: 1, children: nil},
			"file": {args: 1, children: nil},
		}},
		"login": {children: map[string]*schemaNode{
			"user": {args: 1, children: map[string]*schemaNode{
				"uid":            {args: 1, children: nil},
				"class":          {args: 1, children: nil},
				"authentication": {children: nil},
			}},
		}},
		"services": {children: map[string]*schemaNode{
			"ssh": {children: map[string]*schemaNode{
				"root-login": {args: 1, children: nil},
			}},
			"web-management": {children: map[string]*schemaNode{
				"http": {children: map[string]*schemaNode{
					"interface": {args: 1, children: nil},
				}},
				"https": {children: map[string]*schemaNode{
					"system-generated-certificate": {children: nil},
					"interface":                    {args: 1, children: nil},
				}},
			}},
			"dns":               {children: nil},
			"dhcp-local-server": {children: map[string]*schemaNode{
				"group": {args: 1, children: map[string]*schemaNode{
					"pool": {args: 1, children: nil},
				}},
			}},
			"dhcpv6-local-server": {children: map[string]*schemaNode{
				"group": {args: 1, children: map[string]*schemaNode{
					"pool": {args: 1, children: nil},
				}},
			}},
		}},
	}},
	"services": {children: map[string]*schemaNode{
		"rpm": {children: map[string]*schemaNode{
			"probe": {args: 1, children: map[string]*schemaNode{
				"test": {args: 1, children: nil},
			}},
		}},
		"flow-monitoring": {children: map[string]*schemaNode{
			"version9": {children: map[string]*schemaNode{
				"template": {args: 1, children: map[string]*schemaNode{
					"template-refresh-rate": {children: map[string]*schemaNode{
						"seconds": {args: 1, children: nil},
					}},
				}},
			}},
		}},
	}},
	"forwarding-options": {children: map[string]*schemaNode{
		"sampling": {children: map[string]*schemaNode{
			"instance": {args: 1, children: map[string]*schemaNode{
				"input": {children: nil},
				"family": {children: map[string]*schemaNode{
					"inet": {children: map[string]*schemaNode{
						"output": {children: map[string]*schemaNode{
							"flow-server": {args: 1, children: nil},
							"inline-jflow": {children: nil},
						}},
					}},
					"inet6": {children: map[string]*schemaNode{
						"output": {children: map[string]*schemaNode{
							"flow-server": {args: 1, children: nil},
							"inline-jflow": {children: nil},
						}},
					}},
				}},
			}},
		}},
	}},
	"routing-instances": {wildcard: &schemaNode{children: map[string]*schemaNode{
		// instance-type and interface are NOT listed here → they become leaf nodes
		// e.g. "instance-type virtual-router;" and "interface enp7s0;"
		"routing-options": {children: map[string]*schemaNode{
			"static": {children: map[string]*schemaNode{
				"route": {args: 1, children: nil},
			}},
		}},
		"protocols": {children: map[string]*schemaNode{
			"ospf": {children: map[string]*schemaNode{
				"area": {args: 1, children: map[string]*schemaNode{
					"interface": {args: 1, valueHint: ValueHintInterfaceName, children: map[string]*schemaNode{
						"passive": {children: nil},
						"cost":    {args: 1, children: nil},
					}},
				}},
			}},
			"bgp": {children: map[string]*schemaNode{
				"group": {args: 1, children: nil},
			}},
		}},
	}}},
}}

// SetPath inserts a leaf node at the given path in the tree.
// Intermediate block nodes are created as needed. The schema determines
// which keywords are containers (and how many extra args they consume)
// versus leaves (all remaining tokens form the leaf's Keys).
func (t *ConfigTree) SetPath(path []string) error {
	if len(path) == 0 {
		return fmt.Errorf("empty path")
	}

	current := &t.Children
	schema := setSchema
	i := 0

	for i < len(path) {
		keyword := path[i]

		// Look up keyword in current schema level.
		var childSchema *schemaNode
		if schema != nil {
			if s, ok := schema.children[keyword]; ok {
				childSchema = s
			} else if schema.wildcard != nil {
				childSchema = schema.wildcard
			}
		}

		if childSchema == nil {
			// No schema match: all remaining tokens form a leaf node.
			leaf := &Node{
				Keys:   append([]string(nil), path[i:]...),
				IsLeaf: true,
			}
			*current = append(*current, leaf)
			return nil
		}

		// Consume keyword + extra args as this node's keys.
		nodeKeyCount := 1 + childSchema.args
		if i+nodeKeyCount > len(path) {
			// Not enough tokens; treat remainder as leaf.
			leaf := &Node{
				Keys:   append([]string(nil), path[i:]...),
				IsLeaf: true,
			}
			*current = append(*current, leaf)
			return nil
		}

		nodeKeys := path[i : i+nodeKeyCount]
		i += nodeKeyCount

		if i >= len(path) {
			// No more tokens after this node: it's a leaf.
			leaf := &Node{
				Keys:   append([]string(nil), nodeKeys...),
				IsLeaf: true,
			}
			*current = append(*current, leaf)
			return nil
		}

		// More tokens follow: this is a container. Find or create matching node.
		found := false
		for _, n := range *current {
			if !n.IsLeaf && keysEqual(n.Keys, nodeKeys) {
				current = &n.Children
				found = true
				break
			}
		}
		if !found {
			newNode := &Node{
				Keys: append([]string(nil), nodeKeys...),
			}
			*current = append(*current, newNode)
			current = &newNode.Children
		}
		schema = childSchema
	}

	return nil
}

// DeletePath removes a node at the given path from the tree.
// Uses the same schema-driven traversal as SetPath to navigate the tree,
// then removes the target node from its parent's Children slice.
func (t *ConfigTree) DeletePath(path []string) error {
	if len(path) == 0 {
		return fmt.Errorf("empty path")
	}

	return deletePath(&t.Children, path, setSchema, 0)
}

func deletePath(current *[]*Node, path []string, schema *schemaNode, i int) error {
	if i >= len(path) {
		return fmt.Errorf("path not found")
	}

	keyword := path[i]

	// Look up keyword in current schema level.
	var childSchema *schemaNode
	if schema != nil {
		if s, ok := schema.children[keyword]; ok {
			childSchema = s
		} else if schema.wildcard != nil {
			childSchema = schema.wildcard
		}
	}

	if childSchema == nil {
		// No schema match: remaining tokens form leaf keys, remove matching node.
		leafKeys := path[i:]
		return removeMatchingNode(current, leafKeys)
	}

	// Consume keyword + extra args as this node's keys.
	nodeKeyCount := 1 + childSchema.args
	if i+nodeKeyCount > len(path) {
		// Not enough tokens; treat remainder as leaf keys.
		leafKeys := path[i:]
		return removeMatchingNode(current, leafKeys)
	}

	nodeKeys := path[i : i+nodeKeyCount]
	i += nodeKeyCount

	if i >= len(path) {
		// No more tokens: this container node itself is the target.
		return removeMatchingNode(current, nodeKeys)
	}

	// More tokens remain: find matching container and descend.
	for _, n := range *current {
		if !n.IsLeaf && keysEqual(n.Keys, nodeKeys) {
			return deletePath(&n.Children, path, childSchema, i)
		}
	}

	return fmt.Errorf("path not found: container %q does not exist", strings.Join(nodeKeys, " "))
}

// removeMatchingNode removes the first node whose keys match targetKeys
// (using prefix matching) from the nodes slice.
func removeMatchingNode(nodes *[]*Node, targetKeys []string) error {
	for i, n := range *nodes {
		if keysMatch(n.Keys, targetKeys) {
			*nodes = append((*nodes)[:i], (*nodes)[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("path not found: no node matching %q", strings.Join(targetKeys, " "))
}

// keysMatch returns true if nodeKeys starts with all elements of targetKeys.
// This allows "delete ... address srv1" to match a leaf ["address", "srv1", "10.0.1.0/32"].
func keysMatch(nodeKeys, targetKeys []string) bool {
	if len(targetKeys) > len(nodeKeys) {
		return false
	}
	for i, tk := range targetKeys {
		if nodeKeys[i] != tk {
			return false
		}
	}
	return true
}

// keysEqual returns true if two key slices are identical.
func keysEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// CompleteSetPath returns possible completions for a partial set/delete path.
// It walks setSchema consuming tokens; at the current position it returns
// child keyword names. If the current position expects a dynamic argument
// (wildcard or args > 0), it returns nil (user must type a name).
func CompleteSetPath(tokens []string) []string {
	return CompleteSetPathWithValues(tokens, nil)
}

// CompleteSetPathWithValues is like CompleteSetPath but uses a ValueProvider
// to suggest dynamic values at positions where schema expects a name argument.
func CompleteSetPathWithValues(tokens []string, provider ValueProvider) []string {
	schema := setSchema
	i := 0

	for i < len(tokens) {
		if schema == nil || schema.children == nil {
			return nil // at a leaf or no more schema
		}

		keyword := tokens[i]

		// Look up keyword in current schema level.
		var childSchema *schemaNode
		if s, ok := schema.children[keyword]; ok {
			childSchema = s
		} else if schema.wildcard != nil {
			childSchema = schema.wildcard
		} else {
			return nil // unknown keyword, no completions
		}

		// Consume keyword + extra args.
		nodeKeyCount := 1 + childSchema.args
		i += nodeKeyCount

		if i > len(tokens) {
			// Still consuming args for this node — user needs to type a value.
			// Try to provide dynamic values via the provider.
			if provider != nil && childSchema.valueHint != ValueHintNone {
				return provider(childSchema.valueHint)
			}
			return nil
		}

		schema = childSchema
	}

	// We've consumed all tokens. Return child keywords at this schema level.
	if schema == nil || schema.children == nil {
		return nil
	}

	var completions []string
	for name := range schema.children {
		completions = append(completions, name)
	}
	return completions
}

// Format renders the tree as Junos hierarchical configuration text.
func (t *ConfigTree) Format() string {
	var b strings.Builder
	formatNodes(&b, t.Children, 0)
	return b.String()
}

func formatNodes(b *strings.Builder, nodes []*Node, indent int) {
	prefix := strings.Repeat("    ", indent)
	for _, n := range nodes {
		if n.IsLeaf {
			fmt.Fprintf(b, "%s%s;\n", prefix, n.KeyPath())
		} else {
			fmt.Fprintf(b, "%s%s {\n", prefix, n.KeyPath())
			formatNodes(b, n.Children, indent+1)
			fmt.Fprintf(b, "%s}\n", prefix)
		}
	}
}

// FormatPath navigates to the given path and formats the subtree found there.
// Path components are matched against node keys. For example, FormatPath(["interfaces", "wan0"])
// navigates into the "interfaces" node, then into the child whose second key is "wan0",
// and formats that subtree. Returns "" if the path is not found.
func (t *ConfigTree) FormatPath(path []string) string {
	if len(path) == 0 {
		return t.Format()
	}

	// Navigate through the tree following path components.
	current := t.Children
	var lastNode *Node
	i := 0
	for i < len(path) {
		keyword := path[i]
		found := false
		for _, n := range current {
			if len(n.Keys) == 0 {
				continue
			}
			// Match first key (keyword)
			if n.Keys[0] != keyword {
				continue
			}
			// If path has more components and this node takes arguments,
			// try to match the argument too (e.g., "interfaces" "wan0" matches
			// a node with Keys=["interfaces","wan0"]).
			if i+1 < len(path) && len(n.Keys) >= 2 {
				if n.Keys[1] == path[i+1] {
					lastNode = n
					current = n.Children
					i += 2
					found = true
					break
				}
				continue
			}
			lastNode = n
			current = n.Children
			i++
			found = true
			break
		}
		if !found {
			return ""
		}
	}

	if lastNode == nil {
		return ""
	}

	// Format the found subtree.
	var b strings.Builder
	if lastNode.IsLeaf {
		fmt.Fprintf(&b, "%s;\n", lastNode.KeyPath())
	} else {
		fmt.Fprintf(&b, "%s {\n", lastNode.KeyPath())
		formatNodes(&b, lastNode.Children, 1)
		fmt.Fprintf(&b, "}\n")
	}
	return b.String()
}

// FormatSet renders the tree as flat "set" commands.
func (t *ConfigTree) FormatSet() string {
	var b strings.Builder
	formatSetNodes(&b, t.Children, nil)
	return b.String()
}

func formatSetNodes(b *strings.Builder, nodes []*Node, prefix []string) {
	for _, n := range nodes {
		path := append(prefix, n.Keys...)
		if n.IsLeaf {
			fmt.Fprintf(b, "set %s\n", strings.Join(path, " "))
		} else {
			formatSetNodes(b, n.Children, path)
		}
	}
}

// FormatJSON renders the tree as a JSON object.
func (t *ConfigTree) FormatJSON() string {
	obj := nodesToJSON(t.Children)
	data, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(data) + "\n"
}

// nodesToJSON converts a list of AST nodes to a nested map structure.
func nodesToJSON(nodes []*Node) map[string]interface{} {
	result := make(map[string]interface{})

	for _, n := range nodes {
		if n.IsLeaf {
			// Leaf node: key is first key, value is remaining keys joined
			if len(n.Keys) == 1 {
				result[n.Keys[0]] = true
			} else if len(n.Keys) == 2 {
				result[n.Keys[0]] = n.Keys[1]
			} else {
				result[n.Keys[0]] = strings.Join(n.Keys[1:], " ")
			}
		} else {
			name := n.Keys[0]
			qualifier := ""
			if len(n.Keys) > 1 {
				qualifier = strings.Join(n.Keys[1:], " ")
			}

			children := nodesToJSON(n.Children)

			if qualifier != "" {
				// Named instance: e.g. "interface trust0" → {"interface": {"trust0": {...}}}
				if existing, ok := result[name]; ok {
					if m, ok := existing.(map[string]interface{}); ok {
						m[qualifier] = children
					}
				} else {
					result[name] = map[string]interface{}{qualifier: children}
				}
			} else {
				result[name] = children
			}
		}
	}
	return result
}
