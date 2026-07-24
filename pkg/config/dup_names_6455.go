package config

import "fmt"

// This file holds the shared quoted-empty-name diagnostics for the pre-expansion
// duplicate-name gate family:
//
//   - validateDuplicateNamedBlockAST      (#5180, dup_named_blocks.go)
//   - validateDuplicateNATRuleNamesAST    (#5649, dup_nat_rule_names.go)
//   - validateDuplicateNATRuleSetNamesAST (#6454, dup_nat_ruleset_names.go)
//
// #6455 Finding 2 (quoted-empty names) is closed here: all three gates used to
// `continue` on an empty name, so a quoted-empty name (`rule ""`, `rule-set ""`,
// `group ""`, `interface ""`, `ids-option ""`) was neither rejected as a
// duplicate nor rejected as empty. An empty name is not a valid operational
// identity for any of these containers — the object cannot be referenced or shown
// by name (the CLI named-lookup surfaces key on the name) — so it is an authoring
// error regardless of duplication (mirroring the #5636 empty-credential
// rejection). Each gate records it and rejects (strict) / warns (lenient).
//
// #6455 Finding 1 (group-authored duplicates — a duplicate authored ENTIRELY
// inside an applied group body) is NOT addressed here. A pre-expansion per-group-
// body scan false-rejects a legitimate apply-groups FRAGMENT config: fragments of
// one named object authored across repeated group roots (e.g. two `interfaces`
// roots each contributing a `ge-0/0/0` unit, or a screen profile split into an
// ICMP fragment + a TCP fragment) COALESCE into one object under `mergeNodes`
// during ExpandGroups, so a pre-expansion sibling-scan that cannot model that
// same-pass coalescing rejects a config that compiles to a single object. The
// correct detection point is AFTER ExpandGroups (the coalesced tree) but before
// the #3096 Cartesian bracket-list expansion in compileExpanded — and, to stay
// HA-symmetric like the sibling tunnel / zone / unit-alias gates, it must union
// the node0 and node1 expansions rather than scan a single node's view. That is a
// design pass tracked as the group-authored half of #6455, not shipped here.

// emptyNameError builds the strict-path hard error for a quoted-empty name of the
// given kind (e.g. "interface", "NAT source rule-set").
func emptyNameError(kind string) error {
	return fmt.Errorf("empty %s name: an empty name is not a valid operational "+
		"identity — the object cannot be referenced or shown by name; name it or "+
		"remove it (#6455)", kind)
}

// emptyNameWarning builds the lenient-path warning for a quoted-empty name.
func emptyNameWarning(kind string) string {
	return fmt.Sprintf("empty %s name: an empty name is not a valid operational "+
		"identity — name it or remove it (#6455)", kind)
}
