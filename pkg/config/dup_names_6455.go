package config

import (
	"fmt"
	"sort"
)

// This file holds the shared helpers that close the two limitations #6455 found
// common to the whole pre-expansion duplicate-name gate family:
//
//   - validateDuplicateNamedBlockAST      (#5180, dup_named_blocks.go)
//   - validateDuplicateNATRuleNamesAST    (#5649, dup_nat_rule_names.go)
//   - validateDuplicateNATRuleSetNamesAST (#6454, dup_nat_ruleset_names.go)
//
// Finding 1 (group-authored duplicates): all three gates historically scanned
// ONLY the top-level stanzas, deliberately skipping group bodies because
// apply-groups DEEP-MERGES a group-provided named block that has an inline
// top-level peer (mergeNodes coalesces same-key containers), so a pre-expansion
// top-level scan avoids a false positive there. But a duplicate authored ENTIRELY
// inside a group body with no inline peer survives expansion as two rows
// (ast_groups.go appends the parent container wholesale when dst has no matching
// container) — and no gate ran to catch it. scanNamespaces closes this WITHOUT
// re-introducing the deep-merge false positive: it treats each group body as a
// SEPARATE authoring namespace with its own fresh seen-set, so a group-vs-inline
// same name (which deep-merges to one node) is never cross-counted — only
// siblings authored WITHIN one namespace collide. This is strictly more complete
// than a post-expansion rescan (which would miss a group-internal duplicate that
// an inline peer coalesces, and would risk flagging the #3096 Cartesian
// bracket-list expansion that happens later, during compileExpanded).
//
// Finding 2 (quoted-empty names): all three gates `continue` on an empty name, so
// a quoted-empty name (`rule ""`, `rule-set ""`, `group ""`, `interface ""`) was
// neither rejected as a duplicate nor rejected as empty. An empty name is not a
// valid operational identity for any of the family's containers — the object
// cannot be referenced or shown by name (the CLI named-lookup surfaces key on the
// name), so it is an authoring error regardless of duplication. Each gate now
// records it as an emptyName6455 defect (strict rejects, lenient warns), mirroring
// the #5636 empty-credential rejection precedent.

// emptyName6455 is one detected empty ("") named-object name.
type emptyName6455 struct {
	kind     string // human category, e.g. "NAT source rule-set", "interface"
	groupCtx string // "" for a top-level defect, else the enclosing group name
}

// scanNamespaces invokes fn once for the top-level stanza list (groupCtx "") and
// once per DEFINED group body (groupCtx = the group's name). Each group body is a
// SEPARATE authoring namespace: a same-named block authored in a group and inline
// DEEP-MERGE under apply-groups (mergeNodes coalesces same-key containers), so
// they must not be cross-counted — the caller's fn must build a FRESH seen-set
// per invocation so only siblings WITHIN one namespace collide (#6455). Nested
// group definitions do not exist in Junos, so a group body is not recursed for a
// further `groups` stanza. groupDefinitionName mirrors ast_groups.go name
// extraction (Keys[1] for a merged two-key head, else Keys[0]).
func scanNamespaces(tree *ConfigTree, fn func(stanzas []*Node, groupCtx string)) {
	fn(tree.Children, "")
	for _, child := range tree.Children {
		if child.Name() != "groups" {
			continue
		}
		for _, g := range child.Children {
			fn(g.Children, groupDefinitionName(g))
		}
	}
}

// groupCtxSuffix renders the " in group %q" clause for a diagnostic when the
// defect was found inside a group body; it is empty for a top-level defect so the
// existing top-level messages are byte-identical to before #6455.
func groupCtxSuffix(groupCtx string) string {
	if groupCtx == "" {
		return ""
	}
	return fmt.Sprintf(" in group %q", groupCtx)
}

// emptyNameError builds the strict-path hard error for the first empty name.
func emptyNameError(e emptyName6455) error {
	return fmt.Errorf("empty %s name%s: an empty name is not a valid operational "+
		"identity — the object cannot be referenced or shown by name; name it or "+
		"remove it (#6455)", e.kind, groupCtxSuffix(e.groupCtx))
}

// emptyNameWarning builds the lenient-path warning for one empty name.
func emptyNameWarning(e emptyName6455) string {
	return fmt.Sprintf("empty %s name%s: an empty name is not a valid operational "+
		"identity — name it or remove it (#6455)", e.kind, groupCtxSuffix(e.groupCtx))
}

// sortEmptyNames orders empty-name defects deterministically (kind, then group).
func sortEmptyNames(empties []emptyName6455) {
	sort.Slice(empties, func(i, j int) bool {
		if empties[i].kind != empties[j].kind {
			return empties[i].kind < empties[j].kind
		}
		return empties[i].groupCtx < empties[j].groupCtx
	})
}
