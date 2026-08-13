package config

import (
	"fmt"
	"strings"
)

const (
	// maxGroupExpandDepth bounds the TRANSITIVE nested-group recursion —
	// apply-groups inside a group body inside a group body, a chain
	// g1->g2->...->gN (#5194 A3-b2-F1). The `seen` cycle guard only rejects a
	// group that references ITSELF (directly or via a cycle); the #4474 memo
	// only collapses a converging DAG. Neither bounds a shallow-syntax ACYCLIC
	// chain of distinct groups, which recurses one stack frame per link and can
	// exhaust the goroutine stack on commit / HA config-sync. A legitimate Junos
	// config nests apply-groups templates only a handful deep, so this cap sits
	// far above real use yet rejects a generated/pathological chain cleanly with
	// an error instead of crashing.
	maxGroupExpandDepth = 64
	// maxGroupExpandWork bounds the TOTAL number of group expansions performed
	// across one ExpandGroups call (every context, every nesting level). It
	// catches a wide shallow fan-out that stays under the depth cap but still
	// performs unbounded work, and is a backstop for the depth cap itself.
	maxGroupExpandWork = 100000
)

// groupExpandBudget carries the total-work counter shared across the whole
// expansion recursion (depth is passed by value per nested-group level).
type groupExpandBudget struct {
	work int // group expansions performed so far
}

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
	// The nil ancestorPath means we're at the top level. The memo map is
	// created once here and threaded through the whole recursion so a group
	// reachable via many paths (a converging DAG) is expanded ONCE (#4474).
	if err := expandGroupsRecursive(&t.Children, groups, nil, nil, make(map[string][]*Node), tagInherited, vars, 0, &groupExpandBudget{}); err != nil {
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

// ancestorPathKey serializes an ancestor context path ([][]string) into a
// stable string for the group-expansion memo (#4474). Control-char separators
// (\x1e between path elements, \x1f between the keys of one element) keep it
// collision-free — config tokens never contain those bytes.
func ancestorPathKey(ancestorPath [][]string) string {
	if len(ancestorPath) == 0 {
		return ""
	}
	var b strings.Builder
	for i, keys := range ancestorPath {
		if i > 0 {
			b.WriteByte('\x1e')
		}
		for j, k := range keys {
			if j > 0 {
				b.WriteByte('\x1f')
			}
			b.WriteString(k)
		}
	}
	return b.String()
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
// memo caches the fully-expanded body of a group keyed by (name, ancestor
// context) so a converging DAG expands each group once (#4474 fan-out fix).
// If tagInherited is true, merged nodes get InheritedFrom set to the group name.
// vars provides ${var} replacements for group names (may be nil).
func expandGroupsRecursive(nodes *[]*Node, groups map[string]*Node, ancestorPath [][]string, seen map[string]bool, memo map[string][]*Node, tagInherited bool, vars map[string]string, depth int, budget *groupExpandBudget) error {
	// #5194 A3-b2-F1: bound the nested-group recursion depth before it can
	// exhaust the goroutine stack on a deep acyclic chain g1->g2->...->gN.
	if depth > maxGroupExpandDepth {
		return fmt.Errorf("apply-groups nesting exceeds maximum depth of %d (possible generated or pathological config)", maxGroupExpandDepth)
	}
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

		// #5194 A3-b2-F1: bound the TOTAL expansion work so a wide shallow
		// fan-out (many groups, each referenced from many contexts) that stays
		// under the depth cap still cannot spin unbounded on commit / HA sync.
		budget.work++
		if budget.work > maxGroupExpandWork {
			return fmt.Errorf("apply-groups expansion exceeds maximum work budget of %d (possible generated or pathological config)", maxGroupExpandWork)
		}

		// Memoization (#4474 fan-out fix): the fully-expanded body of a group
		// is a function ONLY of (group name, ancestor context) within one
		// ExpandGroups call — walkGroupToContext AND the nested-expansion
		// context both depend on ancestorPath, while tagInherited/vars are
		// constant for the call. A completed memo entry is a fully-resolved,
		// cycle-free body (a cyclic expansion errors out before it is cached),
		// so reusing it is always correct. Without this, a converging DAG
		// re-expands a shared group once PER PATH — delete(seen,name) runs per
		// branch, so the `seen` cycle guard does NOT bound the fan-out — and a
		// machine-generated deep nested-group DAG goes exponential (~2x/level).
		// mergeNodes MUTATES its src argument, so store and hand out fresh
		// clones and keep the cached copy pristine.
		memoKey := name + "\x00" + ancestorPathKey(ancestorPath)
		if cached, hit := memo[memoKey]; hit {
			if cached != nil {
				mergeNodes(nodes, cloneNodes(cached), ancestorPath)
			}
			continue
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

		var expanded []*Node
		if srcChildren != nil {
			cloned := cloneNodes(srcChildren)
			if tagInherited {
				tagNodesInherited(cloned, name)
			}
			// Transitive apply-groups (#4474): a group body may itself say
			// `apply-groups G2` (a nested-group template, a standard Junos
			// idiom). Expand the group's OWN references to a fixed point BEFORE
			// merging its body, so G2's content is inherited rather than
			// silently dropped when the outer strip-and-recurse removes the
			// merged-in `apply-groups G2` node. The `seen` guard — `name` is
			// already marked above — breaks cycles (grpA->grpB->grpA returns a
			// circular-reference error, same as a direct self-cycle). Nodes
			// inherited FROM the nested group are tagged with THAT group's name:
			// tagNodesInherited above ran before this call, so it tags only the
			// outer group's own body and does not clobber the nested tags.
			if err := expandGroupsRecursive(&cloned, groups, ancestorPath, seen, memo, tagInherited, vars, depth+1, budget); err != nil {
				return err
			}
			expanded = cloned
		}

		// Cache a pristine copy of the completed expansion (even an empty one,
		// so a group with no matching context subtree is not re-walked), then
		// merge a SEPARATE clone into the parent so the cache is never mutated.
		memo[memoKey] = cloneNodes(expanded)
		if expanded != nil {
			mergeNodes(nodes, expanded, ancestorPath)
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
			// Descending the config TREE (not the nested-group chain), so depth
			// is unchanged — tree depth is already bounded by the parser
			// brace-depth cap (#4148). The shared work budget still applies.
			if err := expandGroupsRecursive(&n.Children, groups, childPath, seen, memo, tagInherited, vars, depth, budget); err != nil {
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
				// statement is a pure value-list leaf-list; otherwise OVERRIDE
				// (skip the group value — inline wins). Scalars, args>=2
				// multi-token leaves, groupReplace token-packed leaves, and
				// range-bearing leaves all take the override path.
				if leafListUnionEligible(ancestorPath, key, peer, s) {
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
				if leafListUnionEligible(ancestorPath, s.Keys[0], peer, s) {
					mergeLeafListInto(peer, s)
				}
				// else OVERRIDE: a range-bearing inline peer wins, group block
				// dropped (a groupReplace leaf never reaches here — its
				// isLeafListSchema is false, so it takes the container path).
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
			// #6673: the inherited member arrives as a VALUE with no authored
			// token of its own on dst. Extend the mask only when dst already
			// carries one, so the length invariant holds and the union never
			// upgrades an inherited value into an authored quote.
			if len(dst.KeysQuoted) == len(dst.Keys)-1 {
				dst.KeysQuoted = append(dst.KeysQuoted, false)
			}
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
// schema context ancestorPath, is a PURE single-token Junos leaf-list whose
// group + inline members UNION under apply-groups inheritance (#4070): a
// multi-value leaf that models no sub-structure, carries exactly one value
// token per member, and is not opted out. A scalar leaf, an args>=2 multi leaf
// (multi-token members), or a groupReplace leaf overrides instead. Returns
// false when the path or keyword is not modeled in setSchema, so an unmodeled
// leaf safely keeps the legacy override behavior.
//
// The gate is `multi:true && children==nil && args<=1 && !groupReplace`:
//   - multi + children==nil: the leaf-list discriminator (children==nil
//     excludes multi nodes carrying modifier sub-structure — CoS named
//     containers, static `next-hop [ a b ] { interface x; }`).
//   - args<=1: each member is a SINGLE token (application, source-address,
//     protocol, name-server, from community/as-path, export chains). An
//     args>=2 multi leaf packs multiple tokens per member (route-filter
//     `<prefix> <match-type>`, address-book `address <name> <prefix>`,
//     as-path `<name> <regex>`, CoS `queue <n> <class>`); token-level union
//     would mash the member tokens together, so it OVERRIDEs instead.
//   - !groupReplace: a token-packed args<=1 leaf that packs a SEPARATOR or
//     OPERATION keyword (port range `3000 to 4000`, `then community
//     add|set|delete|none`, `then as-path-prepend`) is explicitly opted out
//     (see the schemaNode.groupReplace doc) — union/dedup would corrupt it.
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
	return leaf != nil && leaf.multi && leaf.children == nil &&
		leaf.args <= 1 && !leaf.groupReplace
}

// leafListUnionEligible reports whether a group leaf-list node src should UNION
// into an existing inline node dst (both share Keys[0]==key at schema context
// ancestorPath), versus fall back to apply-groups OVERRIDE. Union requires the
// schema to classify key as a pure single-token value-list (isLeafListSchema)
// AND neither side to carry a range separator. A range like `3000 to 4000`
// packs the `to` separator onto the value list, so token-level union/dedup
// would corrupt it (a discard/reject port term would fail OPEN). The range
// check is a defensive net for any range-bearing leaf not explicitly marked
// groupReplace; the known port leaves already set the flag.
func leafListUnionEligible(ancestorPath [][]string, key string, dst, src *Node) bool {
	if !isLeafListSchema(ancestorPath, key) {
		return false
	}
	return !leafListCarriesRange(dst) && !leafListCarriesRange(src)
}

// leafListCarriesRange reports whether a leaf-list node packs a Junos range
// separator ("to", as in a port range `3000 to 4000`) onto its value list.
// Such a leaf is a range, not a set — union/dedup would corrupt it.
func leafListCarriesRange(n *Node) bool {
	for _, v := range firewallMatchValues(n) {
		if v == "to" {
			return true
		}
	}
	return false
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
