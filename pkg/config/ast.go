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

	// Annotation is a user comment set via the "annotate" command.
	Annotation string

	// InheritedFrom is the group name this node was inherited from.
	// Set during ExpandGroups when tagInherited is true.
	InheritedFrom string

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

// KeyPath returns the full key path as a single string (unquoted).
// Used for map lookups and comparison. For display/format output, use QuotedKeyPath.
func (n *Node) KeyPath() string {
	return strings.Join(n.Keys, " ")
}

// QuotedKeyPath returns the key path with keys quoted if they contain
// characters that aren't valid bare identifiers (e.g. ${node}).
func (n *Node) QuotedKeyPath() string {
	parts := make([]string, len(n.Keys))
	for i, k := range n.Keys {
		parts[i] = quoteKey(k)
	}
	return strings.Join(parts, " ")
}

// quoteKey wraps a key in double quotes if it contains characters that
// are not valid in bare Junos identifiers.
func quoteKey(s string) string {
	if s == "" {
		return `""`
	}
	for i := 0; i < len(s); i++ {
		if !isIdentChar(s[i]) {
			// Escape any internal quotes.
			return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
		}
	}
	return s
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
			Keys:          append([]string(nil), n.Keys...),
			Children:      cloneNodes(n.Children),
			IsLeaf:        n.IsLeaf,
			Annotation:    n.Annotation,
			InheritedFrom: n.InheritedFrom,
			Line:          n.Line,
			Column:        n.Column,
		}
	}
	return result
}

// navigatePath walks the tree following path components and returns matching nodes.
// When multiple sibling nodes share the same key prefix (e.g., path ["from-zone","untrust"]
// matching both ["from-zone","untrust","to-zone","trust"] and
// ["from-zone","untrust","to-zone","dmz"]), all matches are returned.
func navigatePath(nodes []*Node, path []string) []*Node {
	current := nodes
	i := 0
	for i < len(path) {
		keyword := path[i]
		// Try multi-key match (keyword + argument pairs).
		if i+1 < len(path) {
			var matched []*Node
			for _, n := range current {
				if len(n.Keys) >= 2 && n.Keys[0] == keyword && n.Keys[1] == path[i+1] {
					matched = append(matched, n)
				}
			}
			if len(matched) > 0 {
				consumed := 2
				// Continue consuming additional key-value pairs from the path
				// that match the node's remaining keys. E.g., path
				// ["from-zone","untrust","to-zone","trust"] consumes all 4 keys
				// of node Keys=["from-zone","untrust","to-zone","trust"].
				for consumed < len(matched[0].Keys) && i+consumed+1 < len(path) {
					nextKey := path[i+consumed]
					nextVal := path[i+consumed+1]
					var filtered []*Node
					for _, n := range matched {
						if len(n.Keys) > consumed+1 && n.Keys[consumed] == nextKey && n.Keys[consumed+1] == nextVal {
							filtered = append(filtered, n)
						}
					}
					if len(filtered) == 0 {
						break
					}
					matched = filtered
					consumed += 2
				}
				i += consumed
				if i >= len(path) {
					return matched
				}
				current = matched[0].Children
				continue
			}
		}
		// Single-key match.
		found := false
		for _, n := range current {
			if len(n.Keys) > 0 && n.Keys[0] == keyword {
				i++
				if i >= len(path) {
					return []*Node{n}
				}
				current = n.Children
				found = true
				break
			}
		}
		if !found {
			return nil
		}
	}
	return nil
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
		// Try all children; prefer full-key matches over partial ones.
		// This handles siblings like [policy first], [policy second], [policy third]
		// where the first key "policy" matches all but we need the full key match.
		var bestChild *Node
		bestConsumed := 0
		for _, child := range *parentChildren {
			consumed := matchNodeKeys(child, path, pos)
			if consumed > bestConsumed {
				bestChild = child
				bestConsumed = consumed
			}
		}
		if bestChild == nil {
			return nil, nil, fmt.Errorf("path element %q not found", path[pos])
		}
		if pos+bestConsumed >= len(path) {
			return bestChild, parentChildren, nil
		}
		parentChildren = &bestChild.Children
		pos += bestConsumed
	}
	return nil, nil, fmt.Errorf("path not found")
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
