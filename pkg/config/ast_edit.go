package config

import (
	"fmt"
	"strings"
)

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

// InsertBefore moves an existing element before another element in the same
// parent's children list. Both elements must exist under the same parent.
// elementPath is the full path to the element to move.
// refPath is the full path to the reference element.
func (t *ConfigTree) InsertBefore(elementPath, refPath []string) error {
	return t.insertRelative(elementPath, refPath, false)
}

// InsertAfter moves an existing element after another element in the same
// parent's children list.
func (t *ConfigTree) InsertAfter(elementPath, refPath []string) error {
	return t.insertRelative(elementPath, refPath, true)
}

func (t *ConfigTree) insertRelative(elementPath, refPath []string, after bool) error {
	if len(elementPath) == 0 || len(refPath) == 0 {
		return fmt.Errorf("empty path")
	}

	// Find the element and its parent children slice.
	elem, parentChildren, err := t.findNodeWithParent(elementPath)
	if err != nil {
		return fmt.Errorf("element not found: %s", strings.Join(elementPath, " "))
	}

	// Find the reference element — must be in the same parent.
	refNode, refParent, err := t.findNodeWithParent(refPath)
	if err != nil {
		return fmt.Errorf("reference not found: %s", strings.Join(refPath, " "))
	}

	// Both must share the same parent (same children slice).
	if parentChildren != refParent {
		return fmt.Errorf("elements must be siblings (same parent)")
	}

	if elem == refNode {
		return nil // already in position
	}

	// Find and remove the element from the children slice.
	elemIdx := -1
	for i, c := range *parentChildren {
		if c == elem {
			elemIdx = i
			break
		}
	}
	if elemIdx < 0 {
		return fmt.Errorf("element not found in parent")
	}
	*parentChildren = append((*parentChildren)[:elemIdx], (*parentChildren)[elemIdx+1:]...)

	// Find the reference's new index (may have shifted after removal).
	refIdx := -1
	for i, c := range *parentChildren {
		if c == refNode {
			refIdx = i
			break
		}
	}
	if refIdx < 0 {
		return fmt.Errorf("reference not found in parent")
	}

	// Insert before or after the reference.
	insertAt := refIdx
	if after {
		insertAt = refIdx + 1
	}

	// Grow and shift.
	*parentChildren = append(*parentChildren, nil)
	copy((*parentChildren)[insertAt+1:], (*parentChildren)[insertAt:])
	(*parentChildren)[insertAt] = elem
	return nil
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
			// Skip if exact duplicate already exists.
			remaining := path[i:]
			for _, n := range *current {
				if n.IsLeaf && keysEqual(n.Keys, remaining) {
					return nil
				}
			}
			leaf := &Node{
				Keys:   append([]string(nil), remaining...),
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

		// Compound key: children form part of the key rather than
		// separate hierarchy levels (e.g. "family inet6" is a single
		// node with Keys=["family","inet6"], not nested nodes).
		if childSchema.compoundKey && i < len(path) {
			if sub, ok := childSchema.children[path[i]]; ok {
				nodeKeys = append(append([]string(nil), nodeKeys...), path[i])
				i++
				childSchema = sub
			}
		}

		if i >= len(path) {
			// No more tokens after this node: it's a leaf.
			if childSchema.args > 0 && !childSchema.multi && childSchema.children == nil {
				// Single-value leaf with no sub-structure (e.g. host-name, description): replace existing.
				// Nodes with children are named containers that may appear as terminal leaves
				// with different values (e.g. "interface eth0", "interface eth1").
				// Replace the first match and remove all subsequent duplicates.
				replaced := false
				filtered := (*current)[:0] // reuse backing array
				for _, n := range *current {
					if n.IsLeaf && len(n.Keys) > 0 && n.Keys[0] == nodeKeys[0] {
						if !replaced {
							filtered = append(filtered, &Node{
								Keys:   append([]string(nil), nodeKeys...),
								IsLeaf: true,
							})
							replaced = true
						}
						// skip all duplicate entries
						continue
					}
					filtered = append(filtered, n)
				}
				if replaced {
					*current = filtered
					return nil
				}
			} else {
				// Flag leaf (args == 0) or multi-value leaf: skip if exact duplicate.
				for _, n := range *current {
					if n.IsLeaf && keysEqual(n.Keys, nodeKeys) {
						return nil
					}
				}
			}
			leaf := &Node{
				Keys:   append([]string(nil), nodeKeys...),
				IsLeaf: true,
			}
			*current = append(*current, leaf)
			return nil
		}

		// More tokens follow. If the schema says this is a multi-value leaf
		// with no children AND the next token is a known sibling keyword,
		// add it as a leaf and continue at the same level so remaining
		// tokens become siblings (e.g. "match" children:
		// destination-address any source-address any application any).
		// If the next token is NOT a known sibling, the remaining tokens
		// are trailing values for this leaf (e.g. "destination-port 20000 to 20003").
		if childSchema.children == nil && childSchema.multi && i < len(path) {
			nextToken := path[i]
			_, nextIsSibling := schema.children[nextToken]
			if !nextIsSibling && schema.wildcard != nil {
				nextIsSibling = true
			}
			if nextIsSibling {
				// Dedup: skip if exact leaf already exists.
				dup := false
				for _, n := range *current {
					if n.IsLeaf && keysEqual(n.Keys, nodeKeys) {
						dup = true
						break
					}
				}
				if !dup {
					*current = append(*current, &Node{
						Keys:   append([]string(nil), nodeKeys...),
						IsLeaf: true,
					})
				}
				// Don't descend — continue at same level for next sibling.
				continue
			}
		}

		// This is a container (or a leaf with trailing value tokens).
		// Find or create matching node.
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

	// Compound key: consume child token as part of key.
	if childSchema.compoundKey && i < len(path) {
		if sub, ok := childSchema.children[path[i]]; ok {
			nodeKeys = append(append([]string(nil), nodeKeys...), path[i])
			i++
			childSchema = sub
		}
	}

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
