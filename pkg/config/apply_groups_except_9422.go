package config

// `apply-groups-except` — #9422.
//
// Junos: "Don't inherit configuration data from these groups"
// (docs/junos-config-display-reference.md:76). A stanza carrying
// `apply-groups-except <g>` does not inherit from group <g> at that point in
// the hierarchy, even though an ancestor applied it.
//
// Before this, the token was ACCEPTED by every config channel and consulted by
// NONE. `ConfigTree.expandGroups` collected only `apply-groups`; there was no
// `apply-groups-except` branch anywhere in expansion, `mergeNodes`,
// `walkGroupToContext` or `stripApplyGroups`. The five production references to
// the keyword were all of the form "skip this token so it is not misread as a
// sibling member" (#7029) — none of them an exclusion. Measured on the base
// revision, removing the `-except` line changed NOTHING:
//
//	groups { G { system { host-name FROM-GROUP; } } }
//	apply-groups G;
//	system { apply-groups-except G; domain-name example.com; }
//	  -> System.HostName = "FROM-GROUP", Warnings = []      (identical without it)
//
// The exclusion is enforced in `mergeNodes` rather than by pre-pruning the
// group body, because mergeNodes is the only place that already knows the
// DESTINATION each part of a group body lands in. That matters for a `<*>`
// group key, which fans one source subtree out into every matching destination
// container: two of those containers may disagree about whether they exclude
// the group, and a decision taken once against the group body cannot express
// that. Checking at each merge level gets it per-destination for free, and the
// level-scoped check inherits down the subtree exactly as the Junos statement
// reads — everything at and below the excluding stanza stops inheriting.
//
// The `apply-groups-except` node is deliberately LEFT in the tree, unlike
// `apply-groups` which expansion strips. It has no compiled meaning, so the
// #7029 skip lists that keep it from being read as a zone/interface member are
// still what stops that, and their fixtures stay non-vacuous.
//
// A name that matches no defined group is a no-op rather than an error: unlike
// `apply-groups`, which fails to ADD configuration and therefore has to say so,
// an exclusion that matches nothing removes nothing. Rejecting it would also
// break a shared cluster config that excludes a `${node}` group defined only in
// the peer's view.

// siblingsExcludeGroup reports whether ANY destination container sharing these
// keys carries the exclusion.
//
// It is used at the CONTAINER descent only. The wildcard branch does not need
// it: that branch already recurses into each matching destination separately,
// so the per-destination decision is taken by nodesExcludeGroup on entry to the
// recursive call — and a same-keyed duplicate under a wildcard-matched
// container is folded away by mergeDuplicateBlocks9023 before expansion runs.
// A copy of this check was written there first and MUTATION-TESTED AS DEAD
// (severing it killed nothing), which is what identified it as redundant rather
// than as an untested branch.
//
// It exists because one logical hierarchy level can be spread across several
// AST nodes — `system { host-name p; } … system { apply-groups-except G; }` is
// two top-level `system` nodes, and the compiler reads both — while mergeNodes
// merges a group's contribution into the FIRST matching container only. Asking
// only that container reads the exclusion out of a config that plainly carries
// it, which was measured: the same fixture honoured the statement with one
// `system` block and ignored it with two. The scan is over `keysEqual`
// siblings, the same identity mergeNodes itself uses to decide what "the same
// container" means, so the two cannot drift.
func siblingsExcludeGroup(dst []*Node, keys []string, group string, vars map[string]string) bool {
	for _, d := range dst {
		if d == nil || d.IsLeaf || !keysEqual(d.Keys, keys) {
			continue
		}
		if nodesExcludeGroup(d.Children, group, vars) {
			return true
		}
	}
	return false
}

// nodesExcludeGroup reports whether this hierarchy level carries an
// `apply-groups-except` naming group. Bracket lists
// (`apply-groups-except [ g1 g2 ]`) collapse onto one node's Keys, so every key
// past the keyword is a group name; `${var}` names resolve the same way
// `apply-groups` names do.
func nodesExcludeGroup(nodes []*Node, group string, vars map[string]string) bool {
	if group == "" {
		return false
	}
	for _, n := range nodes {
		if n == nil || n.Name() != "apply-groups-except" {
			continue
		}
		for _, key := range n.Keys[1:] {
			if resolveVars(key, vars) == group {
				return true
			}
		}
	}
	return false
}
