package config

import (
	"fmt"
	"sort"
)

// natRuleSubBlocks lists the NAT sub-blocks whose rule-sets carry named,
// ordered, first-match rules that share a per-rule operational identity
// (natType/ruleset/rule; see pkg/dataplane/compiler_nat.go). Keep in sync with
// compileNAT (compiler_nat_source.go), which iterates exactly these sub-blocks
// and whose per-type compilers read `rule-set` -> `rule` with namedInstances.
// nat64 / natv6v4 / proxy-arp are intentionally excluded: they carry no
// name-derived first-match rule identity of this shape.
var natRuleSubBlocks = []string{"source", "destination", "static"}

// dupNATRule is one detected duplicate rule name within a single NAT rule-set.
type dupNATRule struct {
	natType string // "source" | "destination" | "static"
	ruleSet string // the rule-set that owns the duplicated rule
	rule    string // the duplicated rule name
}

// validateDuplicateNATRuleNamesAST rejects (strict) or warns (lenient) when the
// candidate authors the SAME rule name twice inside one NAT rule-set.
//
// This is a DIFFERENT failure mode from #5180's last-writer-wins hierarchical
// blocks: duplicate NAT rules BOTH survive. namedInstances (the rule loop in
// compiler_nat_source.go / _destination.go / _static.go) appends each as a
// separate first-match row, so the first shadows the second while both map to
// the single natType/ruleset/rule counter identity (pkg/dataplane/
// compiler_nat.go). The operator gets order-dependent translation, an
// unreachable rule, and merged telemetry that show/counter surfaces cannot
// disambiguate.
//
// Runs PRE-expansion on top-level `security` stanzas only, exactly like
// validateDuplicateNamedBlockAST (#5180): apply-groups DEEP-MERGES a rule of
// the same name rather than duplicating it, and a rule authored once via flat
// `set` reuses its rule node, so only hierarchical duplicates authored
// directly reach here. The seen-set is keyed by (natType, ruleSet, rule) and
// unioned across repeated `security` / `nat` / `source|destination|static`
// blocks — compileNAT (#3915) merges those repeats — so a rule name split
// across two `source {}` blocks is caught too. Strict rejects on the operator
// commit / commit-check path; lenient (Load / peer-sync, #1960) warns and
// keeps the historical two-row behavior.
func validateDuplicateNATRuleNamesAST(tree *ConfigTree, lenient bool) ([]string, error) {
	if tree == nil {
		return nil, nil
	}
	var dups []dupNATRule
	seen := map[string]bool{}
	reported := map[string]bool{}
	for _, top := range tree.Children {
		if top.Name() != "security" {
			continue
		}
		for _, nat := range top.FindChildren("nat") {
			for _, natType := range natRuleSubBlocks {
				for _, sub := range nat.FindChildren(natType) {
					for _, rsInst := range namedInstances(sub.FindChildren("rule-set")) {
						if rsInst.name == "" {
							continue
						}
						for _, ruleInst := range namedInstances(rsInst.node.FindChildren("rule")) {
							if ruleInst.name == "" {
								continue
							}
							key := natType + "\x00" + rsInst.name + "\x00" + ruleInst.name
							if seen[key] {
								if !reported[key] {
									dups = append(dups, dupNATRule{natType, rsInst.name, ruleInst.name})
									reported[key] = true
								}
							} else {
								seen[key] = true
							}
						}
					}
				}
			}
		}
	}

	if len(dups) == 0 {
		return nil, nil
	}
	// Deterministic order: natType, then rule-set, then rule.
	sort.Slice(dups, func(i, j int) bool {
		if dups[i].natType != dups[j].natType {
			return dups[i].natType < dups[j].natType
		}
		if dups[i].ruleSet != dups[j].ruleSet {
			return dups[i].ruleSet < dups[j].ruleSet
		}
		return dups[i].rule < dups[j].rule
	})

	if !lenient {
		d := dups[0]
		return nil, fmt.Errorf("duplicate NAT %s rule %q in rule-set %q: two "+
			"same-named rules BOTH compile as separate first-match rows, so the "+
			"first shadows the second and both share the one %s/%s/%s counter "+
			"identity — author the rule once (flat `set` merges repeated "+
			"statements automatically) (#5649)",
			d.natType, d.rule, d.ruleSet, d.natType, d.ruleSet, d.rule)
	}

	warnings := make([]string, 0, len(dups))
	for _, d := range dups {
		warnings = append(warnings, fmt.Sprintf("duplicate NAT %s rule %q in "+
			"rule-set %q: the first same-named rule shadows the later one and "+
			"both share one counter identity — author it once to avoid "+
			"order-dependent translation and merged telemetry (#5649)",
			d.natType, d.rule, d.ruleSet))
	}
	return warnings, nil
}
