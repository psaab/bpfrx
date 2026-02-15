package config

import (
	"encoding/json"
	"encoding/xml"
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

	// Annotation is a user comment set via the "annotate" command.
	Annotation string

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
			Keys:       append([]string(nil), n.Keys...),
			Children:   cloneNodes(n.Children),
			IsLeaf:     n.IsLeaf,
			Annotation: n.Annotation,
			Line:       n.Line,
			Column:     n.Column,
		}
	}
	return result
}

// ExpandGroups resolves all "apply-groups" references in the tree.
// It collects group definitions from the "groups" stanza, then for each
// "apply-groups <name>" node, clones the referenced group's children and
// merges them into the parent. After expansion, both "groups" and
// "apply-groups" nodes are removed from the tree.
func (t *ConfigTree) ExpandGroups() error {
	// Collect group definitions: groups { <name> { ... } }
	groups := make(map[string]*Node)
	for _, child := range t.Children {
		if child.Name() == "groups" {
			for _, g := range child.Children {
				if len(g.Keys) < 1 {
					continue
				}
				name := g.Keys[0]
				if len(g.Keys) > 1 {
					name = g.Keys[1]
				}
				groups[name] = g
			}
		}
	}

	// If no groups defined, just strip any stale apply-groups references.
	if len(groups) == 0 {
		return t.stripApplyGroups()
	}

	// Resolve apply-groups at top level.
	if err := expandGroupsInNodes(&t.Children, groups, nil); err != nil {
		return err
	}

	// Remove the "groups" stanza itself.
	filtered := make([]*Node, 0, len(t.Children))
	for _, child := range t.Children {
		if child.Name() != "groups" {
			filtered = append(filtered, child)
		}
	}
	t.Children = filtered

	return nil
}

// stripApplyGroups removes apply-groups nodes and returns error if they
// reference undefined groups.
func (t *ConfigTree) stripApplyGroups() error {
	for _, child := range t.Children {
		if child.Name() == "apply-groups" {
			name := ""
			if len(child.Keys) > 1 {
				name = child.Keys[1]
			}
			return fmt.Errorf("apply-groups references undefined group %q", name)
		}
	}
	return nil
}

// expandGroupsInNodes processes apply-groups nodes within a node list.
// It merges referenced group children into the list, then removes apply-groups.
// seen tracks group names being expanded to detect circular references.
func expandGroupsInNodes(nodes *[]*Node, groups map[string]*Node, seen map[string]bool) error {
	// First, collect apply-groups references at this level.
	var applyNames []string
	for _, n := range *nodes {
		if n.Name() == "apply-groups" && len(n.Keys) > 1 {
			applyNames = append(applyNames, n.Keys[1])
		}
	}

	// Expand each referenced group.
	for _, name := range applyNames {
		g, ok := groups[name]
		if !ok {
			return fmt.Errorf("apply-groups references undefined group %q", name)
		}

		if seen == nil {
			seen = make(map[string]bool)
		}
		if seen[name] {
			return fmt.Errorf("apply-groups circular reference: group %q", name)
		}
		seen[name] = true

		// Clone group children and merge into current node list.
		cloned := cloneNodes(g.Children)
		mergeNodes(nodes, cloned)

		delete(seen, name)
	}

	// Remove apply-groups nodes.
	filtered := make([]*Node, 0, len(*nodes))
	for _, n := range *nodes {
		if n.Name() != "apply-groups" {
			filtered = append(filtered, n)
		}
	}
	*nodes = filtered

	return nil
}

// mergeNodes merges src nodes into dst. For container nodes with matching keys,
// children are merged recursively. For leaf nodes or new containers, they are
// appended (group values don't override existing explicit config — existing
// config takes precedence via ordering, since the compiler uses first-match).
func mergeNodes(dst *[]*Node, src []*Node) {
	for _, s := range src {
		if s.IsLeaf {
			// Only add leaf if no matching leaf exists.
			if !hasMatchingLeaf(*dst, s.Keys) {
				*dst = append(*dst, s)
			}
			continue
		}

		// Container node: find matching container in dst.
		found := false
		for _, d := range *dst {
			if !d.IsLeaf && keysEqual(d.Keys, s.Keys) {
				// Merge children recursively.
				mergeNodes(&d.Children, s.Children)
				found = true
				break
			}
		}
		if !found {
			*dst = append(*dst, s)
		}
	}
}

// hasMatchingLeaf returns true if nodes contains a leaf whose first key
// matches. This prevents group values from overriding explicit config
// (e.g., if "host-name explicit" already exists, "host-name group" is skipped).
func hasMatchingLeaf(nodes []*Node, keys []string) bool {
	if len(keys) == 0 {
		return false
	}
	for _, n := range nodes {
		if n.IsLeaf && len(n.Keys) > 0 && n.Keys[0] == keys[0] {
			return true
		}
	}
	return false
}

// matchNodeKeys checks if a node's Keys match path elements starting at pos.
// Returns the number of path elements consumed (len(node.Keys)) on match, 0 otherwise.
func matchNodeKeys(n *Node, path []string, pos int) int {
	if len(n.Keys) == 0 || pos >= len(path) {
		return 0
	}
	if n.Keys[0] != path[pos] {
		return 0
	}
	// First key matches; check remaining keys fit within path
	nk := len(n.Keys)
	if pos+nk > len(path) {
		// Partial match: node has more keys than remaining path.
		// Accept if we're at the last path segment (allows matching by first key only).
		return 1
	}
	for j := 1; j < nk; j++ {
		if n.Keys[j] != path[pos+j] {
			return 1 // first key matched but subsequent didn't; still a 1-key match
		}
	}
	return nk
}

// navigateToNode walks the tree following path, returning the target node.
// Multi-key nodes consume multiple path elements at once.
func navigateToNode(children []*Node, path []string) (*Node, error) {
	var current *Node
	pos := 0
	for pos < len(path) {
		found := false
		for _, child := range children {
			consumed := matchNodeKeys(child, path, pos)
			if consumed > 0 {
				current = child
				children = child.Children
				pos += consumed
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("path element %q not found", path[pos])
		}
	}
	return current, nil
}

// findNode navigates the tree to find a node at the given path.
// Handles multi-key nodes by consuming multiple path elements per node.
func (t *ConfigTree) findNode(path []string) (*Node, error) {
	return navigateToNode(t.Children, path)
}

// removeNode removes and returns a node at the given path.
func (t *ConfigTree) removeNode(path []string) (*Node, error) {
	if len(path) == 0 {
		return nil, fmt.Errorf("empty path")
	}
	// Navigate to the parent, then find and remove the target child.
	parentChildren := &t.Children
	pos := 0
	// We need to find where the last node starts.
	// Walk until we can identify the target node at the end.
	for pos < len(path) {
		// Try to match a child and see if it's the final node.
		var bestChild *Node
		bestConsumed := 0
		bestIdx := -1
		for i, child := range *parentChildren {
			consumed := matchNodeKeys(child, path, pos)
			if consumed > 0 {
				bestChild = child
				bestConsumed = consumed
				bestIdx = i
				break
			}
		}
		if bestChild == nil {
			return nil, fmt.Errorf("path element %q not found", path[pos])
		}
		if pos+bestConsumed >= len(path) {
			// This is the target node — remove it.
			*parentChildren = append((*parentChildren)[:bestIdx], (*parentChildren)[bestIdx+1:]...)
			return bestChild, nil
		}
		// Descend into this child's children.
		parentChildren = &bestChild.Children
		pos += bestConsumed
	}
	return nil, fmt.Errorf("path not found")
}

// insertNode inserts a node as a child at the given parent path.
func (t *ConfigTree) insertNode(parentPath []string, node *Node) error {
	children := &t.Children
	pos := 0
	for pos < len(parentPath) {
		found := false
		for _, child := range *children {
			consumed := matchNodeKeys(child, parentPath, pos)
			if consumed > 0 {
				children = &child.Children
				pos += consumed
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("destination parent path element %q not found", parentPath[pos])
		}
	}
	*children = append(*children, node)
	return nil
}

// findNodeWithParent navigates the tree and returns the target node
// plus the parent's children slice (for insertion/removal at the correct level).
func (t *ConfigTree) findNodeWithParent(path []string) (*Node, *[]*Node, error) {
	parentChildren := &t.Children
	pos := 0
	for pos < len(path) {
		found := false
		for _, child := range *parentChildren {
			consumed := matchNodeKeys(child, path, pos)
			if consumed > 0 {
				if pos+consumed >= len(path) {
					return child, parentChildren, nil
				}
				parentChildren = &child.Children
				pos += consumed
				found = true
				break
			}
		}
		if !found {
			return nil, nil, fmt.Errorf("path element %q not found", path[pos])
		}
	}
	return nil, nil, fmt.Errorf("path not found")
}

// CopyPath copies a subtree from src to dst path.
// The destination's last N keys (where N = len(sourceNode.Keys)) replace the source keys.
func (t *ConfigTree) CopyPath(src, dst []string) error {
	if len(src) == 0 || len(dst) == 0 {
		return fmt.Errorf("empty path")
	}
	srcNode, _, err := t.findNodeWithParent(src)
	if err != nil {
		return fmt.Errorf("source not found: %s", strings.Join(src, " "))
	}
	cloned := cloneNodes([]*Node{srcNode})[0]
	nk := len(srcNode.Keys)
	if len(dst) < nk {
		return fmt.Errorf("destination path too short")
	}
	cloned.Keys = append([]string(nil), dst[len(dst)-nk:]...)
	// Find the parent for the destination
	dstParentPath := dst[:len(dst)-nk]
	return t.insertNode(dstParentPath, cloned)
}

// RenamePath moves a subtree from src to dst path.
func (t *ConfigTree) RenamePath(src, dst []string) error {
	if len(src) == 0 || len(dst) == 0 {
		return fmt.Errorf("empty path")
	}
	srcNode, err := t.removeNode(src)
	if err != nil {
		return fmt.Errorf("source not found: %s", strings.Join(src, " "))
	}
	nk := len(srcNode.Keys)
	if len(dst) < nk {
		return fmt.Errorf("destination path too short")
	}
	srcNode.Keys = append([]string(nil), dst[len(dst)-nk:]...)
	dstParentPath := dst[:len(dst)-nk]
	return t.insertNode(dstParentPath, srcNode)
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
	ValueHintUnitNumber              // unit <number>
)

// SchemaCompletion is a completion candidate from the config schema.
type SchemaCompletion struct {
	Name string
	Desc string
}

// ValueProvider returns possible values for a given hint.
// The path parameter provides consumed tokens for context (e.g., interface name for unit completion).
type ValueProvider func(hint ValueHint, path []string) []SchemaCompletion

// schemaNode defines a container keyword in the Junos config hierarchy.
// It tells SetPath how to group flat path tokens into the correct tree structure.
type schemaNode struct {
	args        int                    // extra tokens consumed as part of this node's key
	children    map[string]*schemaNode // known container children
	wildcard    *schemaNode            // matches any keyword not in children (for dynamic names)
	valueHint   ValueHint              // hint for dynamic value completion (when args > 0)
	desc        string                 // description shown in completion help
	placeholder string                 // Junos-style placeholder (e.g., "<interface-name>")
}

// setSchema defines the Junos configuration tree structure.
// Keywords present in the schema at a given depth are treated as containers.
// Keywords NOT in the schema become leaf nodes (all remaining tokens form the leaf's Keys).
var setSchema = &schemaNode{children: map[string]*schemaNode{
	"groups":       {wildcard: &schemaNode{}}, // children set in init()
	"apply-groups": {args: 1, children: nil},
	"security": {children: map[string]*schemaNode{
		"zones": {children: map[string]*schemaNode{
			"security-zone": {args: 1, valueHint: ValueHintZoneName, children: map[string]*schemaNode{
				"description": {args: 1, children: nil},
				"interfaces":  {children: nil},
				"tcp-rst":     {children: nil},
				"screen":      {args: 1, children: nil},
				"host-inbound-traffic": {children: map[string]*schemaNode{
					"system-services": {children: nil},
					"protocols":       {children: nil},
				}},
			}},
		}},
		"policies": {children: map[string]*schemaNode{
			"from-zone": {args: 3, valueHint: ValueHintZoneName, children: map[string]*schemaNode{ // from-zone X to-zone Y
				"policy": {args: 1, children: map[string]*schemaNode{
					"description": {args: 1, children: nil},
					"match":       {children: nil}, // match children are all leaves
					"then": {children: map[string]*schemaNode{
						"log": {children: nil},
						// permit, deny, reject, count → leaf
					}},
				}},
			}},
			"global": {children: map[string]*schemaNode{
				"policy": {args: 1, children: map[string]*schemaNode{
					"description": {args: 1, children: nil},
					"match":       {children: nil},
					"then": {children: map[string]*schemaNode{
						"log": {children: nil},
					}},
				}},
			}},
		}},
		"screen": {children: map[string]*schemaNode{
			"ids-option": {args: 1, valueHint: ValueHintScreenProfile, children: map[string]*schemaNode{
				"icmp": {children: nil},
				"tcp": {children: map[string]*schemaNode{
					"syn-flood":  {children: nil},
					"port-scan":  {children: nil},
					// land, winnuke, syn-frag -> leaf
				}},
				"ip": {children: map[string]*schemaNode{
					"ip-sweep": {children: nil},
					// source-route-option, tear-drop -> leaf
				}},
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
							"source-address-name":  {args: 1, children: nil},
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
			"natv6v4": {children: map[string]*schemaNode{
				"no-v6-frag-header": {children: nil},
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
			"traceoptions": {children: map[string]*schemaNode{
				"file":          {args: 1, children: nil},
				"flag":          {args: 1, children: nil},
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
				"address":              {args: 1, children: nil},
				"local-address":        {args: 1, children: nil},
				"ike-policy":           {args: 1, children: nil},
				"external-interface":   {args: 1, children: nil},
				"version":              {args: 1, children: nil},
				"no-nat-traversal":     {children: nil},
				"nat-traversal":        {args: 1, children: nil},
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
				"nat-traversal":        {args: 1, children: nil},
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
	"interfaces": {desc: "Interface configuration", wildcard: &schemaNode{valueHint: ValueHintInterfaceName, placeholder: "<interface-name>", children: map[string]*schemaNode{
		"description":  {desc: "Text description of interface", args: 1, children: nil},
		"mtu":          {desc: "Maximum transmit packet size", args: 1, children: nil},
		"speed":        {desc: "Link speed", args: 1, children: nil},
		"duplex":       {desc: "Link duplex mode", args: 1, children: nil},
		"disable":      {desc: "Disable this interface", children: nil},
		"vlan-tagging": {desc: "Enable 802.1Q VLAN tagging", children: nil},
		"gigether-options": {desc: "Gigabit Ethernet interface options", children: map[string]*schemaNode{
			"redundant-parent": {desc: "Parent of this redundant interface", args: 1, children: nil},
		}},
		"redundant-ether-options": {desc: "Redundant Ethernet interface options", children: map[string]*schemaNode{
			"redundancy-group": {desc: "Redundancy group for this RETH", args: 1, children: nil},
		}},
		"fabric-options": {desc: "Fabric interface options", children: map[string]*schemaNode{
			"member-interfaces": {desc: "Member interfaces", children: nil},
		}},
		"tunnel": {desc: "Tunnel parameters", children: map[string]*schemaNode{
			"source":      {desc: "Tunnel source address", args: 1, children: nil},
			"destination": {desc: "Tunnel destination address", args: 1, children: nil},
			"mode":        {desc: "Tunnel mode", args: 1, children: nil},
			"key":         {desc: "Tunnel key", args: 1, children: nil},
			"ttl":         {desc: "Time to live", args: 1, children: nil},
			"keepalive":       {desc: "Keepalive interval", args: 1, children: nil},
			"keepalive-retry": {desc: "Keepalive retry count", args: 1, children: nil},
			"routing-instance": {desc: "Routing instance", children: map[string]*schemaNode{
				"destination": {desc: "Destination routing instance", args: 1, children: nil},
			}},
		}},
		"unit": {desc: "Logical unit number", args: 1, valueHint: ValueHintUnitNumber, placeholder: "<unit-number>", children: map[string]*schemaNode{
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
		"rib-groups": {wildcard: &schemaNode{children: map[string]*schemaNode{
			"import-rib": {children: nil},
		}}},
		"interface-routes": {children: map[string]*schemaNode{
			"rib-group": {children: map[string]*schemaNode{
				"inet":  {args: 1, children: nil},
				"inet6": {args: 1, children: nil},
			}},
		}},
		"generate": {children: map[string]*schemaNode{
			"route": {args: 1, children: map[string]*schemaNode{
				"policy":  {args: 1, children: nil},
				"discard": {children: nil},
			}},
		}},
	}},
	"snmp": {children: map[string]*schemaNode{
		"community": {args: 1, children: map[string]*schemaNode{
			"authorization": {args: 1, children: nil},
		}},
		"trap-group": {args: 1, children: nil},
		"v3": {children: map[string]*schemaNode{
			"usm": {children: map[string]*schemaNode{
				"local-engine": {children: map[string]*schemaNode{
					"user": {args: 1, children: map[string]*schemaNode{
						"authentication-md5":    {children: map[string]*schemaNode{"authentication-password": {args: 1, children: nil}}},
						"authentication-sha":    {children: map[string]*schemaNode{"authentication-password": {args: 1, children: nil}}},
						"authentication-sha256": {children: map[string]*schemaNode{"authentication-password": {args: 1, children: nil}}},
						"privacy-des":           {children: map[string]*schemaNode{"privacy-password": {args: 1, children: nil}}},
						"privacy-aes128":        {children: map[string]*schemaNode{"privacy-password": {args: 1, children: nil}}},
					}},
				}},
			}},
		}},
	}},
	"policy-options": {children: map[string]*schemaNode{
		"prefix-list": {args: 1, children: nil},
		"community": {args: 1, children: map[string]*schemaNode{
			"members": {args: 1, children: nil},
		}},
		"as-path": {args: 2, children: nil},
		"policy-statement": {args: 1, children: map[string]*schemaNode{
			"term": {args: 1, children: map[string]*schemaNode{
				"from": {children: map[string]*schemaNode{
					"protocol":     {args: 1, children: nil},
					"prefix-list":  {args: 1, children: nil},
					"route-filter": {args: 2, children: nil},
					"community":    {args: 1, children: nil},
					"as-path":      {args: 1, children: nil},
				}},
				"then": {children: map[string]*schemaNode{
					"accept":           {children: nil},
					"reject":           {children: nil},
					"next-hop":         {args: 1, children: nil},
					"load-balance":     {args: 1, children: nil},
					"local-preference": {args: 1, children: nil},
					"metric":           {args: 1, children: nil},
					"metric-type":      {args: 1, children: nil},
					"community":        {args: 1, children: nil},
					"origin":           {args: 1, children: nil},
				}},
			}},
			"then": {children: nil},
		}},
	}},
	"protocols": {children: map[string]*schemaNode{
		"ospf": {children: map[string]*schemaNode{
			"router-id":           {args: 1, children: nil},
			"reference-bandwidth": {args: 1, children: nil},
			"passive":             {children: nil},
			"export":              {args: 1, children: nil},
			"area": {args: 1, children: map[string]*schemaNode{
				"interface": {args: 1, valueHint: ValueHintInterfaceName, children: map[string]*schemaNode{
					"passive":        {children: nil},
					"no-passive":     {children: nil},
					"interface-type": {args: 1, children: nil},
					"cost":           {args: 1, children: nil},
					"authentication": {children: map[string]*schemaNode{
						"md5": {args: 1, children: map[string]*schemaNode{
							"key": {args: 1, children: nil},
						}},
						"simple-password": {args: 1, children: nil},
					}},
					"bfd-liveness-detection": {children: map[string]*schemaNode{
						"minimum-interval": {args: 1, children: nil},
					}},
				}},
				"area-type": {children: map[string]*schemaNode{
					"stub": {children: map[string]*schemaNode{
						"no-summaries": {children: nil},
					}},
					"nssa": {children: map[string]*schemaNode{
						"no-summaries": {children: nil},
					}},
				}},
				"virtual-link": {args: 1, children: map[string]*schemaNode{
					"transit-area": {args: 1, children: nil},
				}},
			}},
		}},
		"ospf3": {children: map[string]*schemaNode{
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
			"local-as":        {args: 1, children: nil},
			"router-id":       {args: 1, children: nil},
			"cluster-id":      {args: 1, children: nil},
			"graceful-restart": {children: nil},
			"log-updown":      {children: nil},
			"multipath": {children: map[string]*schemaNode{
				"multiple-as": {children: nil},
			}},
			"damping": {children: map[string]*schemaNode{
				"half-life":    {args: 1, children: nil},
				"reuse":        {args: 1, children: nil},
				"suppress":     {args: 1, children: nil},
				"max-suppress": {args: 1, children: nil},
			}},
			"export":          {args: 1, children: nil},
			"group": {args: 1, children: map[string]*schemaNode{
				"peer-as":            {args: 1, children: nil},
				"description":        {args: 1, children: nil},
				"multihop":           {args: 1, children: nil},
				"export":             {args: 1, children: nil},
				"authentication-key": {args: 1, children: nil},
				"default-originate":  {children: nil},
				"loops":              {args: 1, children: nil},
				"remove-private":     {children: nil},
				"family": {children: map[string]*schemaNode{
					"inet": {children: map[string]*schemaNode{
						"unicast": {children: map[string]*schemaNode{
							"prefix-limit": {children: map[string]*schemaNode{
								"maximum": {args: 1, children: nil},
							}},
						}},
					}},
					"inet6": {children: map[string]*schemaNode{
						"unicast": {children: map[string]*schemaNode{
							"prefix-limit": {children: map[string]*schemaNode{
								"maximum": {args: 1, children: nil},
							}},
						}},
					}},
				}},
				"bfd-liveness-detection": {children: map[string]*schemaNode{
					"minimum-interval": {args: 1, children: nil},
				}},
				"neighbor": {args: 1, children: map[string]*schemaNode{
					"description":            {args: 1, children: nil},
					"peer-as":               {args: 1, children: nil},
					"multihop":              {args: 1, children: nil},
					"authentication-key":    {args: 1, children: nil},
					"route-reflector-client": {children: nil},
					"default-originate":      {children: nil},
					"loops":                  {args: 1, children: nil},
					"remove-private":         {children: nil},
					"family": {children: map[string]*schemaNode{
						"inet": {children: map[string]*schemaNode{
							"unicast": {children: map[string]*schemaNode{
								"prefix-limit": {children: map[string]*schemaNode{
									"maximum": {args: 1, children: nil},
								}},
							}},
						}},
						"inet6": {children: map[string]*schemaNode{
							"unicast": {children: map[string]*schemaNode{
								"prefix-limit": {children: map[string]*schemaNode{
									"maximum": {args: 1, children: nil},
								}},
							}},
						}},
					}},
					"bfd-liveness-detection": {children: map[string]*schemaNode{
						"minimum-interval": {args: 1, children: nil},
					}},
				}},
			}},
		}},
		"rip": {children: map[string]*schemaNode{
			"group":               {args: 1, children: nil},
			"neighbor":            {args: 1, valueHint: ValueHintInterfaceName, children: nil},
			"passive-interface":   {args: 1, valueHint: ValueHintInterfaceName, children: nil},
			"redistribute":        {args: 1, children: nil},
			"authentication-key":  {args: 1, children: nil},
			"authentication-type": {args: 1, children: nil},
		}},
		"isis": {children: map[string]*schemaNode{
			"net":                 {args: 1, children: nil},
			"level":              {args: 1, children: nil},
			"is-type":            {args: 1, children: nil},
			"export":             {args: 1, children: nil},
			"interface": {args: 1, valueHint: ValueHintInterfaceName, children: map[string]*schemaNode{
				"level":               {args: 1, children: nil},
				"passive":             {children: nil},
				"metric":              {args: 1, children: nil},
				"authentication-key":  {args: 1, children: nil},
				"authentication-type": {args: 1, children: nil},
			}},
			"authentication-key":  {args: 1, children: nil},
			"authentication-type": {args: 1, children: nil},
			"wide-metrics-only":   {children: nil},
			"overload":            {children: nil},
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
		"lldp": {children: map[string]*schemaNode{
			"interface": {args: 1, valueHint: ValueHintInterfaceName, children: map[string]*schemaNode{
				"disable": {children: nil},
			}},
			"transmit-interval": {args: 1, children: nil},
			"hold-multiplier":   {args: 1, children: nil},
			"disable":           {children: nil},
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
			"cluster-id":           {args: 1, children: nil},
			"node":                 {args: 1, children: nil},
			"reth-count":           {args: 1, children: nil},
			"heartbeat-interval":   {args: 1, children: nil},
			"heartbeat-threshold":  {args: 1, children: nil},
			"control-link-recovery": {children: nil},
			"control-ports": {children: map[string]*schemaNode{
				"fpc": {args: 1, children: map[string]*schemaNode{
					"port": {args: 1, children: nil},
				}},
			}},
			"control-interface":          {args: 1, children: nil},
			"peer-address":              {args: 1, children: nil},
			"fabric-interface":          {args: 1, children: nil},
			"fabric-peer-address":       {args: 1, children: nil},
			"configuration-synchronize": {children: nil},
			"redundancy-group": {args: 1, children: map[string]*schemaNode{
				"node": {args: 1, children: map[string]*schemaNode{
					"priority": {args: 1, children: nil},
				}},
				"gratuitous-arp-count": {args: 1, children: nil},
				"preempt":              {children: nil},
				"interface-monitor":    {children: nil},
				"ip-monitoring": {children: map[string]*schemaNode{
					"global-weight":    {args: 1, children: nil},
					"global-threshold": {args: 1, children: nil},
					"family": {children: map[string]*schemaNode{
						"inet": {wildcard: &schemaNode{children: map[string]*schemaNode{
							"weight": {args: 1, children: nil},
						}}},
					}},
				}},
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
							"tcp-flags":               {children: nil},
							"is-fragment":             {children: nil},
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
							"dscp":             {args: 1, children: nil},
							"traffic-class":    {args: 1, children: nil},
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
							"tcp-flags":               {children: nil},
							"is-fragment":             {children: nil},
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
							"dscp":             {args: 1, children: nil},
							"traffic-class":    {args: 1, children: nil},
						}},
					}},
				}},
			}},
		}},
	}},
	"system": {children: map[string]*schemaNode{
		"host-name":     {args: 1, children: nil},
		"domain-name":   {args: 1, children: nil},
		"domain-search": {args: 1, children: nil},
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
		"dataplane-type": {args: 1, children: nil},
		"dataplane": {children: map[string]*schemaNode{
			"cores":      {args: 1, children: nil},
			"memory":     {args: 1, children: nil},
			"socket-mem": {args: 1, children: nil},
			"rx-mode": {children: map[string]*schemaNode{
				"idle-threshold":   {args: 1, children: nil},
				"resume-threshold": {args: 1, children: nil},
				"sleep-timeout":    {args: 1, children: nil},
			}},
			"ports": {wildcard: &schemaNode{children: map[string]*schemaNode{
				"interface": {args: 1, children: nil},
				"rx-mode":   {args: 1, children: nil},
				"cores":     {args: 1, children: nil},
			}}},
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
				"api-auth": {children: map[string]*schemaNode{
					"user": {wildcard: &schemaNode{children: map[string]*schemaNode{
						"password": {args: 1, children: nil},
					}}},
					"api-key": {args: 1, children: nil},
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
					"flow-active-timeout":  {args: 1, children: nil},
					"flow-inactive-timeout": {args: 1, children: nil},
					"template-refresh-rate": {children: map[string]*schemaNode{
						"seconds": {args: 1, children: nil},
					}},
				}},
			}},
			"version-ipfix": {children: map[string]*schemaNode{
				"template": {args: 1, children: map[string]*schemaNode{
					"flow-active-timeout":  {args: 1, children: nil},
					"flow-inactive-timeout": {args: 1, children: nil},
					"template-refresh-rate": {children: map[string]*schemaNode{
						"seconds": {args: 1, children: nil},
					}},
					"ipv4-template": {children: map[string]*schemaNode{
						"export-extension": {args: 1, children: nil},
					}},
					"ipv6-template": {children: map[string]*schemaNode{
						"export-extension": {args: 1, children: nil},
					}},
				}},
			}},
		}},
		"application-identification": {children: nil},
	}},
	"forwarding-options": {children: map[string]*schemaNode{
		"family": {children: map[string]*schemaNode{
			"inet6": {children: map[string]*schemaNode{
				"mode": {args: 1, children: nil},
			}},
		}},
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
		"port-mirroring": {children: map[string]*schemaNode{
			"instance": {args: 1, children: map[string]*schemaNode{
				"input": {children: map[string]*schemaNode{
					"ingress": {children: nil},
				}},
				"output": {children: nil},
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
			"interface-routes": {children: map[string]*schemaNode{
				"rib-group": {children: map[string]*schemaNode{
					"inet":  {args: 1, children: nil},
					"inet6": {args: 1, children: nil},
				}},
			}},
		}},
		"protocols": {children: map[string]*schemaNode{
			"ospf": {children: map[string]*schemaNode{
				"reference-bandwidth": {args: 1, children: nil},
				"passive":             {children: nil},
				"area": {args: 1, children: map[string]*schemaNode{
					"interface": {args: 1, valueHint: ValueHintInterfaceName, children: map[string]*schemaNode{
						"passive":        {children: nil},
						"no-passive":     {children: nil},
						"interface-type": {args: 1, children: nil},
						"cost":           {args: 1, children: nil},
						"authentication": {children: map[string]*schemaNode{
							"md5": {args: 1, children: map[string]*schemaNode{
								"key": {args: 1, children: nil},
							}},
							"simple-password": {args: 1, children: nil},
						}},
						"bfd-liveness-detection": {children: map[string]*schemaNode{
							"minimum-interval": {args: 1, children: nil},
						}},
					}},
					"area-type": {children: map[string]*schemaNode{
						"stub": {children: map[string]*schemaNode{
							"no-summaries": {children: nil},
						}},
						"nssa": {children: map[string]*schemaNode{
							"no-summaries": {children: nil},
						}},
					}},
					"virtual-link": {args: 1, children: map[string]*schemaNode{
						"transit-area": {args: 1, children: nil},
					}},
				}},
			}},
			"ospf3": {children: map[string]*schemaNode{
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
				"graceful-restart": {children: nil},
				"damping": {children: map[string]*schemaNode{
					"half-life":    {args: 1, children: nil},
					"reuse":        {args: 1, children: nil},
					"suppress":     {args: 1, children: nil},
					"max-suppress": {args: 1, children: nil},
				}},
				"group":            {args: 1, children: nil},
			}},
			"isis": {children: map[string]*schemaNode{
				"net":                 {args: 1, children: nil},
				"level":              {args: 1, children: nil},
				"is-type":            {args: 1, children: nil},
				"export":             {args: 1, children: nil},
				"interface": {args: 1, valueHint: ValueHintInterfaceName, children: map[string]*schemaNode{
					"level":               {args: 1, children: nil},
					"passive":             {children: nil},
					"metric":              {args: 1, children: nil},
					"authentication-key":  {args: 1, children: nil},
					"authentication-type": {args: 1, children: nil},
				}},
				"authentication-key":  {args: 1, children: nil},
				"authentication-type": {args: 1, children: nil},
				"wide-metrics-only":   {children: nil},
				"overload":            {children: nil},
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
	results := CompleteSetPathWithValues(tokens, nil)
	if results == nil {
		return nil
	}
	names := make([]string, len(results))
	for i, r := range results {
		names[i] = r.Name
	}
	return names
}

// CompleteSetPathWithValues is like CompleteSetPath but uses a ValueProvider
// to suggest dynamic values at positions where schema expects a name argument.
// Returns SchemaCompletion pairs with names and descriptions.
func CompleteSetPathWithValues(tokens []string, provider ValueProvider) []SchemaCompletion {
	schema := setSchema
	i := 0
	var path []string // consumed tokens for context

	for i < len(tokens) {
		if schema == nil {
			return nil
		}
		if schema.children == nil && schema.wildcard == nil {
			return nil // at a leaf with no further options
		}

		keyword := tokens[i]

		// Look up keyword in current schema level.
		var childSchema *schemaNode
		if schema.children != nil {
			if s, ok := schema.children[keyword]; ok {
				childSchema = s
			}
		}
		if childSchema == nil && schema.wildcard != nil {
			childSchema = schema.wildcard
		}
		if childSchema == nil {
			// Last token might be a partial prefix — return matching keywords.
			if i == len(tokens)-1 && schema.children != nil {
				var matches []SchemaCompletion
				for name, node := range schema.children {
					if strings.HasPrefix(name, keyword) {
						matches = append(matches, SchemaCompletion{Name: name, Desc: node.desc})
					}
				}
				if len(matches) > 0 {
					return matches
				}
			}
			return nil // unknown keyword, no completions
		}

		// Consume keyword + extra args.
		nodeKeyCount := 1 + childSchema.args
		end := i + nodeKeyCount
		if end > len(tokens) {
			end = len(tokens)
		}
		path = append(path, tokens[i:end]...)
		i += nodeKeyCount

		if i > len(tokens) {
			// Still consuming args for this node — user needs to type a value.
			// Try to provide dynamic values via the provider.
			if provider != nil && childSchema.valueHint != ValueHintNone {
				results := provider(childSchema.valueHint, path)
				// Add placeholder if available.
				if childSchema.placeholder != "" {
					results = append([]SchemaCompletion{{Name: childSchema.placeholder, Desc: childSchema.desc}}, results...)
				}
				return results
			}
			// No provider but have a placeholder — show it.
			if childSchema.placeholder != "" {
				return []SchemaCompletion{{Name: childSchema.placeholder, Desc: childSchema.desc}}
			}
			return nil
		}

		schema = childSchema
	}

	// We've consumed all tokens. Return child keywords at this schema level.
	if schema == nil {
		return nil
	}

	var completions []SchemaCompletion
	if schema.children != nil {
		for name, node := range schema.children {
			completions = append(completions, SchemaCompletion{Name: name, Desc: node.desc})
		}
	}
	// If this level accepts a wildcard name, provide dynamic values too.
	if schema.wildcard != nil {
		if provider != nil && schema.wildcard.valueHint != ValueHintNone {
			completions = append(completions, provider(schema.wildcard.valueHint, path)...)
		}
		// Add placeholder.
		if schema.wildcard.placeholder != "" {
			completions = append(completions, SchemaCompletion{Name: schema.wildcard.placeholder, Desc: schema.wildcard.desc})
		}
	}
	if len(completions) == 0 {
		return nil
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
		if n.Annotation != "" {
			fmt.Fprintf(b, "%s/* %s */\n", prefix, n.Annotation)
		}
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

// FormatXML renders the tree as Junos-style XML configuration.
func (t *ConfigTree) FormatXML() string {
	var b strings.Builder
	b.WriteString(xml.Header)
	b.WriteString("<configuration>\n")
	formatXMLNodes(&b, t.Children, 1)
	b.WriteString("</configuration>\n")
	return b.String()
}

func formatXMLNodes(b *strings.Builder, nodes []*Node, indent int) {
	prefix := strings.Repeat("    ", indent)
	for _, n := range nodes {
		if n.IsLeaf {
			formatXMLLeaf(b, n, prefix)
		} else {
			tag := xmlTag(n.Keys[0])
			fmt.Fprintf(b, "%s<%s>\n", prefix, tag)
			// Extra keys become <name> elements.
			for _, k := range n.Keys[1:] {
				fmt.Fprintf(b, "%s    <name>%s</name>\n", prefix, xmlEscape(k))
			}
			formatXMLNodes(b, n.Children, indent+1)
			fmt.Fprintf(b, "%s</%s>\n", prefix, tag)
		}
	}
}

func formatXMLLeaf(b *strings.Builder, n *Node, prefix string) {
	if len(n.Keys) == 1 {
		// Boolean leaf: <keyword/>
		fmt.Fprintf(b, "%s<%s/>\n", prefix, xmlTag(n.Keys[0]))
		return
	}
	// Leaf with value: <keyword>value</keyword>
	// For multi-key leaves like "address 10.0.1.0/24", emit
	// <keyword><name>val1</name></keyword>
	tag := xmlTag(n.Keys[0])
	if len(n.Keys) == 2 {
		fmt.Fprintf(b, "%s<%s>%s</%s>\n", prefix, tag, xmlEscape(n.Keys[1]), tag)
	} else {
		fmt.Fprintf(b, "%s<%s>\n", prefix, tag)
		for _, k := range n.Keys[1:] {
			fmt.Fprintf(b, "%s    <name>%s</name>\n", prefix, xmlEscape(k))
		}
		fmt.Fprintf(b, "%s</%s>\n", prefix, tag)
	}
}

// xmlTag sanitizes a Junos keyword into a valid XML element name.
func xmlTag(s string) string {
	// Junos keywords already use valid XML chars (letters, digits, hyphens).
	return s
}

// xmlEscape escapes special XML characters in text content.
func xmlEscape(s string) string {
	var b strings.Builder
	xml.EscapeText(&b, []byte(s))
	return b.String()
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
