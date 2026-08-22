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
// inside an applied group body) is not addressed in THIS file, and cannot be: a
// pre-expansion per-group-body scan false-rejects a legitimate apply-groups
// FRAGMENT config, because fragments of one named object authored across
// repeated group roots (e.g. two `interfaces` roots each contributing a
// `ge-0/0/0` unit, or a screen profile split into an ICMP fragment + a TCP
// fragment) COALESCE into one object under `mergeNodes` during ExpandGroups.
//
// It is closed instead by validateDuplicateNamesExpandedAST
// (dup_names_expanded_6455.go), which re-runs these same three scanners on a
// group-EXPANDED clone — where the coalescing has already happened — once per
// cluster node so the verdict stays HA-symmetric.

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
