package config

import (
	"fmt"
	"strings"
)

// ExpandGroups resolves all "apply-groups" references in the tree.
// It collects group definitions from the "groups" stanza, then for each
// "apply-groups <name>" node, clones the referenced group's children and
// merges them into the parent. After expansion, both "groups" and
// "apply-groups" nodes are removed from the tree.
func (t *ConfigTree) ExpandGroups() error {
	return t.expandGroups(false, nil)
}

// ExpandGroupsTagged is like ExpandGroups but tags each inherited node
// with InheritedFrom set to the group name, for "| display inheritance".
func (t *ConfigTree) ExpandGroupsTagged() error {
	return t.expandGroups(true, nil)
}

// ExpandGroupsWithVars is like ExpandGroups but resolves ${var} references
// in apply-groups names before lookup. This supports Junos-style per-node
// group selection, e.g. apply-groups "${node}" with vars {"node": "node0"}.
func (t *ConfigTree) ExpandGroupsWithVars(vars map[string]string) error {
	return t.expandGroups(false, vars)
}

// resolveVars replaces ${key} placeholders in s with values from vars.
func resolveVars(s string, vars map[string]string) string {
	if vars == nil {
		return s
	}
	for k, v := range vars {
		s = strings.ReplaceAll(s, "${"+k+"}", v)
	}
	return s
}

func (t *ConfigTree) expandGroups(tagInherited bool, vars map[string]string) error {
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
		return t.stripApplyGroups(vars)
	}

	// Recursively resolve apply-groups at all levels.
	// The nil ancestorPath means we're at the top level.
	if err := expandGroupsRecursive(&t.Children, groups, nil, nil, tagInherited, vars); err != nil {
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

// tagNodesInherited recursively sets InheritedFrom on all nodes.
func tagNodesInherited(nodes []*Node, groupName string) {
	for _, n := range nodes {
		n.InheritedFrom = groupName
		tagNodesInherited(n.Children, groupName)
	}
}

// stripApplyGroups walks the tree after group expansion and returns an error
// if any apply-groups node still references an undefined group. vars is used
// to resolve ${var} placeholders in group names for error messages.
func (t *ConfigTree) stripApplyGroups(vars map[string]string) error {
	return stripApplyGroupsInNodes(t.Children, vars)
}

func stripApplyGroupsInNodes(nodes []*Node, vars map[string]string) error {
	for _, child := range nodes {
		if child.Name() == "apply-groups" {
			name := ""
			if len(child.Keys) > 1 {
				name = resolveVars(child.Keys[1], vars)
			}
			return fmt.Errorf("apply-groups references undefined group %q", name)
		}
		if !child.IsLeaf {
			if err := stripApplyGroupsInNodes(child.Children, vars); err != nil {
				return err
			}
		}
	}
	return nil
}

// walkGroupToContext walks a group definition's tree to match the ancestor
// context path. Each element of ancestorPath is the Keys slice of a parent
// node from root to the current level. Returns the children of the deepest
// matching node, or nil if the group has no matching subtree.
// Supports <*> wildcard matching in group keys.
func walkGroupToContext(groupChildren []*Node, ancestorPath [][]string) []*Node {
	current := groupChildren
	for _, pathKeys := range ancestorPath {
		var next []*Node
		for _, child := range current {
			if child.IsLeaf {
				continue
			}
			// Exact match or wildcard match (group keys may contain <*>).
			if keysEqual(child.Keys, pathKeys) || keysMatchWildcard(pathKeys, child.Keys) {
				next = child.Children
				break
			}
		}
		if next == nil {
			return nil // group doesn't have matching subtree at this context
		}
		current = next
	}
	return current
}

// expandGroupsRecursive processes apply-groups nodes within a node list,
// then recurses into all children to handle nested apply-groups.
// ancestorPath tracks the key path from root to the current level, enabling
// groups to be walked down to the matching context for nested apply-groups.
// seen tracks group names being expanded to detect circular references.
// If tagInherited is true, merged nodes get InheritedFrom set to the group name.
// vars provides ${var} replacements for group names (may be nil).
func expandGroupsRecursive(nodes *[]*Node, groups map[string]*Node, ancestorPath [][]string, seen map[string]bool, tagInherited bool, vars map[string]string) error {
	// First, collect apply-groups references at this level.
	// Support bracket-list syntax: apply-groups [ name1 name2 ] produces
	// Keys = ["apply-groups", "name1", "name2"].
	var applyNames []string
	for _, n := range *nodes {
		if n.Name() == "apply-groups" {
			for _, key := range n.Keys[1:] {
				applyNames = append(applyNames, resolveVars(key, vars))
			}
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

		// Walk the group tree to match the current context path.
		var srcChildren []*Node
		if len(ancestorPath) == 0 {
			// Top-level: merge group's direct children.
			srcChildren = g.Children
		} else {
			srcChildren = walkGroupToContext(g.Children, ancestorPath)
		}

		if srcChildren != nil {
			cloned := cloneNodes(srcChildren)
			if tagInherited {
				tagNodesInherited(cloned, name)
			}
			mergeNodes(nodes, cloned, ancestorPath)
		}

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

	// Recurse into children to handle nested apply-groups.
	for _, n := range *nodes {
		if !n.IsLeaf && len(n.Children) > 0 {
			childPath := make([][]string, len(ancestorPath)+1)
			copy(childPath, ancestorPath)
			childPath[len(ancestorPath)] = n.Keys
			if err := expandGroupsRecursive(&n.Children, groups, childPath, seen, tagInherited, vars); err != nil {
				return err
			}
		}
	}

	return nil
}

// mergeNodes merges src (apply-group) nodes into dst (inline stanza) at the
// schema level named by ancestorPath (the Keys path from root to this level,
// same convention expandGroupsRecursive threads for group context walking).
// For container nodes with matching keys, children are merged recursively.
//
// apply-groups inheritance is TYPED per Junos, not shape-based (#4070):
//   - LEAF-LIST statement (schema `multi:true && children==nil`, e.g.
//     name-server, policy `match application` / `source-address`, firewall
//     `from protocol`, routing export/import chains): the group's members are
//     inherited IN ADDITION to the inline members — UNION. Inline members keep
//     precedence and order; group members not already present are appended,
//     deduplicated. This holds across BOTH AST shapes (collapsed leaf and block
//     container) on either side, and yields exactly ONE node for the key.
//   - SCALAR leaf (host-name, ...): inline OVERRIDES the group value (the
//     explicit stanza wins via first-match ordering — unchanged).
//   - Unmodeled leaf (not resolvable in setSchema): OVERRIDE, the safe
//     non-regressing fallback (matches the incremental schema-coverage posture).
//
// Before #4070 the merge keyed on AST SHAPE — collapsed+collapsed OVERRODE,
// block+block UNIONED — so an inline `match application junos-http` that
// inherited a group's `match application junos-https` silently DROPPED
// junos-https (fable-164 L-8), narrowing a `then deny` to junos-http only.
func mergeNodes(dst *[]*Node, src []*Node, ancestorPath [][]string) {
	for _, s := range src {
		if s.IsLeaf {
			key := ""
			if len(s.Keys) > 0 {
				key = s.Keys[0]
			}
			if peer := leafListPeer(*dst, key); peer != nil {
				// A same-key node already exists inline. UNION when the
				// statement is a leaf-list; otherwise OVERRIDE (skip the
				// group value — inline wins).
				if isLeafListSchema(ancestorPath, key) {
					mergeLeafListInto(peer, s)
				}
				continue
			}
			// No inline value for this key: adopt the group leaf.
			*dst = append(*dst, s)
			continue
		}

		// Check if source keys contain wildcards (<*>).
		if keysContainWildcard(s.Keys) {
			// Wildcard merge: apply to all matching containers in dst.
			for _, d := range *dst {
				if !d.IsLeaf && keysMatchWildcard(d.Keys, s.Keys) {
					cloned := cloneNodes(s.Children)
					mergeNodes(&d.Children, cloned, appendPath(ancestorPath, d.Keys))
				}
			}
			continue
		}

		// A single-key group container that the schema classifies as a
		// leaf-list is the BLOCK shape of a leaf-list ("name-server { 1; 2; }").
		// UNION its members into an existing inline leaf-list (either shape),
		// rather than recursing as a real hierarchical container. Multi-key
		// containers (["family","inet"]) are never leaf-lists.
		if len(s.Keys) == 1 && isLeafListSchema(ancestorPath, s.Keys[0]) {
			if peer := leafListPeer(*dst, s.Keys[0]); peer != nil {
				mergeLeafListInto(peer, s)
			} else {
				*dst = append(*dst, s)
			}
			continue
		}

		// Container node: find matching container in dst.
		found := false
		for _, d := range *dst {
			if !d.IsLeaf && keysEqual(d.Keys, s.Keys) {
				// Merge children recursively.
				mergeNodes(&d.Children, s.Children, appendPath(ancestorPath, d.Keys))
				found = true
				break
			}
		}
		if !found {
			// Cross-shape guard (#4325): a single-key group container whose
			// leaf-list counterpart exists inline as a collapsed leaf sharing
			// Keys[0]. Leaf-list keys are handled by the union path above, so
			// this now only fires for a single-key container NOT modeled as a
			// leaf-list — keep the no-duplicate invariant (skip rather than
			// append a second node for the same key).
			if len(s.Keys) == 1 && hasMatchingLeaf(*dst, s.Keys) {
				continue
			}
			*dst = append(*dst, s)
		}
	}
}

// appendPath returns a fresh copy of base with keys appended, so recursive
// mergeNodes calls never alias or clobber a shared ancestorPath backing array.
func appendPath(base [][]string, keys []string) [][]string {
	out := make([][]string, len(base)+1)
	copy(out, base)
	out[len(base)] = keys
	return out
}

// leafListPeer returns the first dst node that expresses the leaf-list keyed
// by key — either a COLLAPSED leaf ("name-server 9.9.9.9") or a single-key
// BLOCK container ("name-server { 9.9.9.9; }"). It mirrors hasMatchingLeaf's
// match rule so union and override agree on what counts as "the same key".
func leafListPeer(dst []*Node, key string) *Node {
	if key == "" {
		return nil
	}
	for _, n := range dst {
		if len(n.Keys) == 0 || n.Keys[0] != key {
			continue
		}
		if n.IsLeaf || len(n.Keys) == 1 {
			return n
		}
	}
	return nil
}

// mergeLeafListInto unions the members of a group leaf-list node src into an
// existing inline leaf-list node dst. Members are read across both AST shapes
// via the #2419 firewallMatchValues SSOT (Keys[1:] AND child leaves). Inline
// members keep their position; group members not already present are appended
// in group order, deduplicated. The dst node's shape is preserved — a
// collapsed leaf grows on Keys, a block container gains one child leaf per
// added member — so the result is exactly ONE node for the key regardless of
// the two inputs' shapes.
func mergeLeafListInto(dst, src *Node) {
	seen := make(map[string]bool)
	for _, v := range firewallMatchValues(dst) {
		seen[v] = true
	}
	for _, v := range firewallMatchValues(src) {
		if seen[v] {
			continue
		}
		seen[v] = true
		if dst.IsLeaf {
			dst.Keys = append(dst.Keys, v)
		} else {
			dst.Children = append(dst.Children, &Node{
				Keys:          []string{v},
				IsLeaf:        true,
				InheritedFrom: src.InheritedFrom,
			})
		}
	}
}

// isLeafListSchema reports whether the leaf keyword key, resolved under the
// schema context ancestorPath, is a Junos leaf-list: a multi-value leaf that
// models no sub-structure (setSchema `multi:true && children==nil`). Such a
// statement UNIONs its members under apply-groups inheritance (#4070); a
// scalar leaf overrides. Returns false when the path or keyword is not modeled
// in setSchema, so an unmodeled leaf safely keeps the legacy override behavior.
//
// The multi:true discriminator already exists (169 leaf-list entries in
// setSchema), and children==nil excludes multi nodes that carry modifier
// sub-structure (CoS named containers, static `next-hop [ a b ] { interface
// x; }`) which are not plain leaf-lists.
func isLeafListSchema(ancestorPath [][]string, key string) bool {
	schema := setSchema
	for _, pk := range ancestorPath {
		if schema == nil || len(pk) == 0 {
			return false
		}
		child := resolveSchemaChild(schema, pk[0])
		if child == nil {
			return false
		}
		// consumeNodeKeys descends a compoundKey sub-token (family inet6) so
		// the leaf lookup lands at the correct level; args/midKeyword tokens
		// are identity values that do not change the schema level.
		_, child = consumeNodeKeys(pk, child)
		schema = child
	}
	if schema == nil {
		return false
	}
	leaf := resolveSchemaChild(schema, key)
	return leaf != nil && leaf.multi && leaf.children == nil
}

// keysContainWildcard returns true if any key is the Junos wildcard "<*>".
func keysContainWildcard(keys []string) bool {
	for _, k := range keys {
		if k == "<*>" {
			return true
		}
	}
	return false
}

// keysMatchWildcard checks if dst keys match src keys where "<*>" matches
// any value. Both slices must have the same length.
func keysMatchWildcard(dst, src []string) bool {
	if len(dst) != len(src) {
		return false
	}
	for i := range src {
		if src[i] != "<*>" && src[i] != dst[i] {
			return false
		}
	}
	return true
}

// hasMatchingLeaf returns true if nodes contains a leaf whose first key
// matches. This prevents group values from overriding explicit config
// (e.g., if "host-name explicit" already exists, "host-name group" is skipped).
//
// It ALSO matches a single-key CONTAINER whose Keys[0] equals keys[0]
// (#4070). A leaf-list can be expressed either as a collapsed leaf
// ("name-server 1.1.1.1 2.2.2.2", Keys[0]=="name-server") or as a block
// container ("name-server { 1.1.1.1; 2.2.2.2; }", Keys==["name-server"]).
// Recognizing the block container here lets a collapsed group leaf and an
// existing block stanza (or vice versa) be treated as the SAME leaf-list
// instead of emitting both a leaf AND a container for one key. Only
// single-key containers cross-match: multi-key containers (e.g.
// ["family","inet"]) are real hierarchical nodes, never leaf-lists, and a
// leaf sharing only Keys[0] must not be confused with them.
func hasMatchingLeaf(nodes []*Node, keys []string) bool {
	if len(keys) == 0 {
		return false
	}
	for _, n := range nodes {
		if len(n.Keys) == 0 || n.Keys[0] != keys[0] {
			continue
		}
		if n.IsLeaf {
			return true
		}
		if len(n.Keys) == 1 {
			return true
		}
	}
	return false
}
