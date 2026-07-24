package config

import (
	"fmt"
	"sort"
)

// natRuleSubBlocks lists the NAT sub-blocks whose rule-sets carry named,
// ordered, first-match rules. Keep in sync with compileNAT
// (compiler_nat_source.go), which iterates exactly these sub-blocks and whose
// per-type compilers read `rule-set` -> `rule` with namedInstances. nat64 /
// natv6v4 / proxy-arp are intentionally excluded: they carry no name-derived
// first-match rule identity of this shape.
var natRuleSubBlocks = []string{"source", "destination", "static"}

// dupNATRule is one detected duplicate rule name within a single NAT rule-set.
type dupNATRule struct {
	natType string // "source" | "destination" | "static"
	ruleSet string // the rule-set that owns the duplicated rule
	rule    string // the duplicated rule name
	nptv6   bool   // static NPTv6 (RFC 6296) rule — counter-less, see reason()
}

// staticRuleIsNPTv6 reports whether a `security nat static` rule node carries a
// `then static-nat nptv6-prefix ...` translation, i.e. it is an NPTv6 (RFC
// 6296) rule. Mirrors the IsNPTv6 detection in compileNATStatic
// (compiler_nat_static.go): flat-set collapses `then static-nat nptv6-prefix
// PREFIX` onto the static-nat leaf's Keys, while the hierarchical form nests a
// `nptv6-prefix { PREFIX; }` child. NPTv6 rules matter here only because they
// are COUNTER-LESS (compileStaticNAT skips rule.IsNPTv6 before
// assignNATCounterID), so the duplicate diagnostic must not claim a shared
// counter identity for them.
func staticRuleIsNPTv6(ruleNode *Node) bool {
	for _, thenNode := range ruleNode.FindChildren("then") {
		for _, t := range thenNode.Children {
			if t.Name() != "static-nat" {
				continue
			}
			if len(t.Keys) >= 3 && t.Keys[1] == "nptv6-prefix" {
				return true
			}
			if t.FindChild("nptv6-prefix") != nil {
				return true
			}
		}
	}
	return false
}

// reason states WHY a duplicate NAT rule name is invalid, tailored to whether
// the rule carries a per-rule hit counter.
//
// Every ordinary NAT rule (source / destination / non-NPTv6 static) shares the
// natType/ruleset/rule counter identity (pkg/dataplane/compiler_nat.go
// NATCounterKey), so a duplicate name merges telemetry and shadows the second
// row. An NPTv6 static rule is COUNTER-LESS — compileStaticNAT skips
// rule.IsNPTv6 before assignNATCounterID and buildNptv6Snapshots appends each
// rule as its own snapshot — AND the #2241 NPTv6 overlap gate deliberately
// SKIPS same-(rule-set, rule) pairs (#4339, so a multi-from-scope rule is not
// flagged against itself). That skip means this gate is the ONLY one that
// catches a duplicate NPTv6 rule name, but the shared-counter wording does not
// apply; the harm is order-dependent first-match resolution between the two
// snapshots instead.
func (d dupNATRule) reason() string {
	if d.nptv6 {
		return "two same-named NPTv6 (RFC 6296) rules BOTH compile as separate " +
			"first-match snapshots (the overlap gate skips same-name pairs, " +
			"#4339), so first-match resolution is order-dependent and one prefix " +
			"silently shadows the other"
	}
	return fmt.Sprintf("two same-named rules BOTH compile as separate "+
		"first-match rows, so the first shadows the second and both share the "+
		"one %s/%s/%s counter identity", d.natType, d.ruleSet, d.rule)
}

// validateDuplicateNATRuleNamesAST rejects (strict) or warns (lenient) when the
// candidate authors the SAME rule name twice inside one NAT rule-set.
//
// This is a DIFFERENT failure mode from #5180's last-writer-wins hierarchical
// blocks: duplicate NAT rules BOTH survive. namedInstances (the rule loop in
// compiler_nat_source.go / _destination.go / _static.go) appends each as a
// separate first-match row, so the first shadows the second. For an ordinary
// rule both rows also map to the single natType/ruleset/rule counter identity;
// an NPTv6 static rule is counter-less but still ambiguous (see reason()).
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
	seenNPTv6 := map[string]bool{}
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
							// Only static rules can be NPTv6-shaped; the check is
							// cheap and scoped so source/destination never pay it.
							isNPT := natType == "static" && staticRuleIsNPTv6(ruleInst.node)
							if seen[key] {
								if !reported[key] {
									dups = append(dups, dupNATRule{
										natType: natType,
										ruleSet: rsInst.name,
										rule:    ruleInst.name,
										// Counter-less iff EITHER occurrence is
										// NPTv6-shaped (a mixed pair is still
										// ambiguous and at least one row is
										// counter-less).
										nptv6: seenNPTv6[key] || isNPT,
									})
									reported[key] = true
								}
							} else {
								seen[key] = true
								seenNPTv6[key] = isNPT
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
		return nil, fmt.Errorf("duplicate NAT %s rule %q in rule-set %q: %s — "+
			"author the rule once (flat `set` merges repeated statements "+
			"automatically) (#5649)", d.natType, d.rule, d.ruleSet, d.reason())
	}

	warnings := make([]string, 0, len(dups))
	for _, d := range dups {
		warnings = append(warnings, fmt.Sprintf("duplicate NAT %s rule %q in "+
			"rule-set %q: %s — author it once (#5649)",
			d.natType, d.rule, d.ruleSet, d.reason()))
	}
	return warnings, nil
}
