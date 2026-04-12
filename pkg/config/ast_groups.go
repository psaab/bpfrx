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
			mergeNodes(nodes, cloned)
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

		// Check if source keys contain wildcards (<*>).
		if keysContainWildcard(s.Keys) {
			// Wildcard merge: apply to all matching containers in dst.
			for _, d := range *dst {
				if !d.IsLeaf && keysMatchWildcard(d.Keys, s.Keys) {
					cloned := cloneNodes(s.Children)
					mergeNodes(&d.Children, cloned)
				}
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
