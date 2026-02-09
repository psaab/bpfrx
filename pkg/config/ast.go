package config

import (
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
				"host-inbound-traffic": {children: map[string]*schemaNode{
					"system-services": {children: nil},
					"protocols":       {children: nil},
				}},
				// "screen <profile>" not listed here → becomes leaf
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
				"pool": {args: 1, valueHint: ValueHintPoolName, children: nil},
				"rule-set": {args: 1, children: map[string]*schemaNode{
					"rule": {args: 1, children: map[string]*schemaNode{
						"match": {children: nil},
						"then":  {children: nil},
					}},
					// from zone <zone>, to zone <zone> → leaves
				}},
			}},
			"destination": {children: map[string]*schemaNode{
				"pool": {args: 1, valueHint: ValueHintPoolName, children: nil},
				"rule-set": {args: 1, children: map[string]*schemaNode{
					"rule": {args: 1, children: map[string]*schemaNode{
						"match": {children: nil},
						"then":  {children: nil},
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
		}},
		"address-book": {children: map[string]*schemaNode{
			"global": {children: map[string]*schemaNode{
				"address-set": {args: 1, valueHint: ValueHintAddressName, children: nil},
				// "address <name> <cidr>" not listed → leaf
			}},
		}},
		"log": {children: map[string]*schemaNode{
			"stream": {args: 1, valueHint: ValueHintStreamName, children: nil},
		}},
	}},
	"interfaces": {wildcard: &schemaNode{valueHint: ValueHintInterfaceName, children: map[string]*schemaNode{
		"unit": {args: 1, children: map[string]*schemaNode{
			"family": {children: map[string]*schemaNode{
				"inet":  {children: nil},
				"inet6": {children: nil},
			}},
		}},
	}}},
	"applications": {children: map[string]*schemaNode{
		"application": {args: 1, valueHint: ValueHintAppName, children: nil},
	}},
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
