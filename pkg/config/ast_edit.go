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
		// with no children, the remaining tokens are either sibling
		// statements at this level or trailing VALUE tokens belonging to
		// this leaf.
		//
		// (a) Next token is a known sibling keyword: emit this leaf and
		//     continue at the same level so remaining tokens become
		//     siblings (e.g. "match" children: destination-address any
		//     source-address any application any).
		//
		// (b) Next token is NOT a sibling: it is a trailing value for this
		//     same leaf. This is the flat-set bracket-list case (#2419):
		//     `set ... from protocol [ tcp udp icmp ]` arrives bracket-
		//     stripped as path [..., protocol, tcp, udp, icmp]. The
		//     hierarchical parser yields a SINGLE leaf
		//     Keys=[protocol tcp udp icmp]; the flat-set path must match
		//     that shape. Consume every following non-sibling token onto
		//     this node's keys and emit one leaf — never split the tail
		//     into an orphan child Keys=[udp icmp], which dropped all but
		//     the first list value at the compiler. A mid-key spelling like
		//     `destination-port 20000 to 20003` is handled the same way:
		//     none of "20000", "to", "20003" are siblings, so all land on
		//     the one leaf.
		// A multi leaf collapses a trailing value list onto ONE node. This
		// runs for a plain multi leaf (children == nil, the #2419 case) and,
		// via the valueList opt-in, for a multi leaf that ALSO declares
		// modifier children (the #3872 static `next-hop [ a b ]`, whose only
		// child is the `interface` modifier). A multi leaf WITH children that
		// does NOT opt in (every CoS named container) is untouched — the guard
		// keeps it on the container path below, exactly as before.
		if childSchema.multi && (childSchema.children == nil || childSchema.valueList) && i < len(path) {
			nextToken := path[i]
			_, nextIsSibling := schema.children[nextToken]
			if !nextIsSibling && schema.wildcard != nil {
				nextIsSibling = true
			}
			// When the next token names a known child of THIS node (only
			// possible for a valueList node — plain multi leaves have no
			// children, so indexing a nil map yields ok == false), the
			// occurrence is a CONTAINER: fall through to the container path so
			// the modifier attaches as a child rather than being absorbed as a
			// bogus extra value.
			if _, nextIsChild := childSchema.children[nextToken]; !nextIsChild {
				if !nextIsSibling {
					// Trailing values for this leaf: absorb every following
					// token that is neither a sibling keyword nor a known
					// child so the flat-set list collapses onto one node,
					// matching the hierarchical AST. (case (b) only runs when
					// schema.wildcard == nil — the wildcard check above forces
					// nextIsSibling=true otherwise.)
					nodeKeys = append([]string(nil), nodeKeys...)
					for i < len(path) {
						if _, sib := schema.children[path[i]]; sib {
							break
						}
						if _, ch := childSchema.children[path[i]]; ch {
							break
						}
						nodeKeys = append(nodeKeys, path[i])
						i++
					}
				}
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
				if i >= len(path) {
					return nil
				}
				// Don't descend — continue at same level for next sibling.
				continue
			}
			// nextIsChild: fall through to the container path so the modifier
			// child (e.g. `interface`) attaches under this node.
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

	// Value-list multi-leaf (a `multi: true` leaf with a single value slot and
	// no children): the bracket-list class fixed on the read side in #2419 —
	// `from protocol [ tcp udp icmp ]`, policy match
	// source-/destination-address/application, host-inbound-traffic
	// system-services/protocols, apply-groups, domain-search, and friends. The
	// leaf carries its members on Keys[1:] AND/OR one child node per member
	// (the dual AST shape). A `delete ... protocol tcp` names a MEMBER of the
	// list, not the whole node — remove ONLY that member and keep the rest,
	// mirroring firewallMatchValues on the read side. A bare `delete ...
	// protocol` (no trailing member) still clears the whole leaf. Without this
	// branch removeMatchingNode prefix-matches the leaf by its first key and
	// deletes the ENTIRE list (a config-integrity fail-wide, #3846), and a
	// non-first member is undeletable.
	//
	// Gate on args == 1 so keyed multi entries (address <name> <prefix>,
	// args == 2; named containers with children such as `interfaces <name>`)
	// keep whole-node delete semantics. The valueList opt-in (#3872 static
	// `next-hop`) extends member-delete to a multi leaf that ALSO carries
	// modifier children (its `interface`), mirroring the read/render-side gate
	// flip: without this, `delete ... next-hop <gw>` prefix-matched and deleted
	// the WHOLE next-hop leaf, so deleting one gateway of a `[ a b ]` ECMP list
	// silently blackholed the healthy other path (Null0), and a non-first
	// member was undeletable — the exact #3846 delete-side fail-wide.
	if childSchema.multi && (childSchema.children == nil || childSchema.valueList) && childSchema.args == 1 {
		return removeMultiLeafMembers(current, keyword, path[i+1:], childSchema.valueList)
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

// DeactivatePath marks the node at the given path inactive (#2008 H1),
// implementing the Junos `deactivate <path>` verb. The node keeps its
// identity and children — it is excluded from compilation/application until
// re-activated, exactly like an `inactive:` marker in hierarchical text.
// Navigation reuses the same schema-driven traversal as SetPath/DeletePath
// so the path tokenization matches `show | display set` output (which emits
// `deactivate <path>` for every inactive node), making that output
// round-trippable. The target node must already exist — `display set`
// always emits the node's `set` line(s) before its `deactivate` line, so on
// reload the node is present by the time this runs.
func (t *ConfigTree) DeactivatePath(path []string) error {
	if len(path) == 0 {
		return fmt.Errorf("empty path")
	}
	return setInactiveAtPath(&t.Children, path, setSchema, 0, true)
}

// ActivatePath clears the inactive marker on the node at the given path
// (#2008 H1), implementing the Junos `activate <path>` verb. The target
// node must already exist.
func (t *ConfigTree) ActivatePath(path []string) error {
	if len(path) == 0 {
		return fmt.Errorf("empty path")
	}
	return setInactiveAtPath(&t.Children, path, setSchema, 0, false)
}

// setInactiveAtPath navigates to the node identified by path (using the
// same schema-driven traversal as deletePath) and sets its Inactive flag to
// the requested value. It does NOT create missing nodes — deactivate /
// activate toggle an existing statement.
func setInactiveAtPath(current *[]*Node, path []string, schema *schemaNode, i int, inactive bool) error {
	if i >= len(path) {
		return fmt.Errorf("path not found")
	}

	keyword := path[i]

	var childSchema *schemaNode
	if schema != nil {
		if s, ok := schema.children[keyword]; ok {
			childSchema = s
		} else if schema.wildcard != nil {
			childSchema = schema.wildcard
		}
	}

	if childSchema == nil {
		// No schema match: remaining tokens form leaf keys.
		return markMatchingNodeInactive(current, path[i:], inactive)
	}

	nodeKeyCount := 1 + childSchema.args
	if i+nodeKeyCount > len(path) {
		return markMatchingNodeInactive(current, path[i:], inactive)
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
		// No more tokens: this node itself is the target.
		return markMatchingNodeInactive(current, nodeKeys, inactive)
	}

	// More tokens remain: find matching container and descend.
	for _, n := range *current {
		if !n.IsLeaf && keysEqual(n.Keys, nodeKeys) {
			return setInactiveAtPath(&n.Children, path, childSchema, i, inactive)
		}
	}

	return fmt.Errorf("path not found: container %q does not exist", strings.Join(nodeKeys, " "))
}

// markMatchingNodeInactive sets the Inactive flag on the first node whose
// keys match targetKeys (prefix matching, mirroring removeMatchingNode).
func markMatchingNodeInactive(nodes *[]*Node, targetKeys []string, inactive bool) error {
	for _, n := range *nodes {
		if keysMatch(n.Keys, targetKeys) {
			n.Inactive = inactive
			return nil
		}
	}
	return fmt.Errorf("path not found: no node matching %q", strings.Join(targetKeys, " "))
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

// removeMultiLeafMembers implements member-specific deletion for a value-list
// multi-leaf. keyword is the leaf's first key ("protocol", "next-hop"); members
// are the trailing tokens naming individual values to drop.
//
//   - members empty  → delete the whole leaf (mirrors removeMatchingNode's
//     prefix match), so `delete ... from protocol` still clears the list.
//   - members named  → drop ONLY those values from every node whose first key
//     is keyword, reading BOTH the flat Keys[1:] shape (bracket list / flat
//     set) AND, for a plain value-list leaf, the child-node shape (hierarchical
//     block) — the #2419 dual AST shape. A node left with no values is removed
//     entirely.
//
// modifierChildren distinguishes the two node classes:
//   - false — a plain value-list leaf (children == nil, e.g. `from protocol
//     [ tcp udp icmp ]`): child nodes ARE list members and are droppable.
//   - true  — a valueList leaf that ALSO declares MODIFIER children (#3872
//     static `next-hop <gw> { interface <if> }`): the children are modifiers
//     OF the value, never members, so they are never matched against the drop
//     set. When every value on Keys[1:] is dropped, the WHOLE entry — the
//     gateway AND its interface modifier — is removed, rather than left as a
//     gateway-less next-hop container that would render Null0/blackhole.
//
// Returns an error when no named member was found anywhere (mirroring
// removeMatchingNode's not-found contract), so deleting a member that is not
// present is reported rather than silently succeeding.
func removeMultiLeafMembers(nodes *[]*Node, keyword string, members []string, modifierChildren bool) error {
	if len(members) == 0 {
		return removeMatchingNode(nodes, []string{keyword})
	}
	drop := make(map[string]bool, len(members))
	for _, m := range members {
		drop[m] = true
	}
	removedAny := false
	out := (*nodes)[:0]
	for _, n := range *nodes {
		if len(n.Keys) == 0 || n.Keys[0] != keyword {
			out = append(out, n)
			continue
		}
		// Flat / bracket shape: members ride on Keys[1:].
		newKeys := append([]string(nil), n.Keys[:1]...)
		for _, v := range n.Keys[1:] {
			if drop[v] {
				removedAny = true
				continue
			}
			newKeys = append(newKeys, v)
		}
		if modifierChildren {
			// valueList node: children are MODIFIERS of the value, not members.
			// Drop the whole entry (gateway + interface modifier) once every
			// gateway on Keys[1:] is gone — a next-hop with no gateway is
			// meaningless and would render Null0.
			if len(newKeys) == 1 {
				continue
			}
			n.Keys = newKeys
			out = append(out, n)
			continue
		}
		// Block shape: one child node per member.
		newChildren := n.Children[:0]
		for _, c := range n.Children {
			if len(c.Keys) >= 1 && drop[c.Keys[0]] {
				removedAny = true
				continue
			}
			newChildren = append(newChildren, c)
		}
		// Leaf/container emptied of all members: drop it entirely.
		if len(newKeys) == 1 && len(newChildren) == 0 {
			continue
		}
		n.Keys = newKeys
		n.Children = newChildren
		out = append(out, n)
	}
	*nodes = out
	if !removedAny {
		return fmt.Errorf("path not found: no member %q of %q",
			strings.Join(members, " "), keyword)
	}
	return nil
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
