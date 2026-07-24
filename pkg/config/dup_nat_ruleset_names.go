package config

import (
	"fmt"
	"sort"
)

// natRuleSetSubBlocks lists the NAT sub-blocks whose rule-SETS carry a named
// operational identity that must be unique within the sub-block's natType
// namespace. It EXTENDS natRuleSubBlocks (source / destination / static — the
// rule-NAME axis of #5649) with nat64: a nat64 rule-set carries prefix /
// source-pool and NO `rule` nodes (correctly excluded from the #5649 rule-name
// gate), but its NAME is still the operational identity, so a duplicated nat64
// rule-set name is its own fail-open worth catching (#6454). natv6v4 /
// proxy-arp are excluded: neither is a named first-match rule-set.
var natRuleSetSubBlocks = []string{"source", "destination", "static", "nat64"}

// dupNATRuleSet is one detected duplicate rule-set name within one NAT type.
type dupNATRuleSet struct {
	natType string // "source" | "destination" | "static" | "nat64"
	ruleSet string // the duplicated rule-set name
}

// validateDuplicateNATRuleSetNamesAST rejects (strict) or warns (lenient) when
// the candidate authors the SAME rule-set name twice within one NAT type. This
// is the #5649 (C181-M18) duplicate-NAT-rule-name defect one level up — the
// rule-SET axis (#6454).
//
// A NAT rule-set name is its operational identity: the from/to scope binding
// and, for source / destination / static, the natType/ruleSet/rule counter
// namespace (pkg/dataplane/compiler_nat.go NATCounterKey — keyed by natType so
// the SAME rule-set name across DIFFERENT nat types is a distinct namespace and
// legitimate, but the same name WITHIN one nat type collides). Two same-named
// rule-sets do NOT reduce to last-writer-wins like a #5180 hierarchical block —
// they BOTH survive: compileNATSource / compileNATDestination / compileNATStatic
// / compileNAT64 each APPEND the rule-set (sec.NAT.Source / Destination.RuleSets
// / Static / NAT64), so both compile as separate first-match tables sharing one
// identity and per-rule telemetry MERGES across them (for the counted natTypes),
// with show / counter surfaces unable to disambiguate their rules. For a
// counter-less nat64 rule-set the name is still the show-surface identity, so
// the diagnostic is deliberately type-agnostic (it never claims a per-rule
// counter) — the genuine, type-independent defect is the shared name identity.
//
// Runs PRE-expansion on top-level `security` stanzas only, exactly like
// validateDuplicateNATRuleNamesAST (#5649) and validateDuplicateNamedBlockAST
// (#5180): apply-groups DEEP-MERGES a same-named rule-set rather than
// duplicating it, and a rule-set authored once via flat `set` reuses its
// rule-set node (tree.SetPath merges), so only a directly-authored hierarchical
// duplicate reaches here. The seen-set is keyed by (natType, ruleSet) and
// unioned across repeated `security` / `nat` / sub-block stanzas — compileNAT
// (#3915) merges those repeats — so a rule-set name split across two `source {}`
// blocks is caught too. Crucially the dedup is at the AST rule-set-INSTANCE
// level, NOT the compiled level: a single authored rule-set carrying a bracket
// list of from/to scopes (#3096) Cartesian-expands into MULTIPLE same-named
// NATRuleSet objects downstream — that legitimate expansion is one AST instance
// and is NOT flagged. Strict rejects on the operator commit / commit-check path;
// lenient (Load / peer-sync, #1960) warns and keeps the historical two-table
// behavior.
func validateDuplicateNATRuleSetNamesAST(tree *ConfigTree, lenient bool) ([]string, error) {
	if tree == nil {
		return nil, nil
	}
	var dups []dupNATRuleSet
	seen := map[string]bool{}
	reported := map[string]bool{}
	for _, top := range tree.Children {
		if top.Name() != "security" {
			continue
		}
		for _, nat := range top.FindChildren("nat") {
			for _, natType := range natRuleSetSubBlocks {
				for _, sub := range nat.FindChildren(natType) {
					for _, rsInst := range namedInstances(sub.FindChildren("rule-set")) {
						if rsInst.name == "" {
							continue
						}
						key := natType + "\x00" + rsInst.name
						if seen[key] {
							if !reported[key] {
								dups = append(dups, dupNATRuleSet{natType, rsInst.name})
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

	if len(dups) == 0 {
		return nil, nil
	}
	// Deterministic order: natType, then rule-set.
	sort.Slice(dups, func(i, j int) bool {
		if dups[i].natType != dups[j].natType {
			return dups[i].natType < dups[j].natType
		}
		return dups[i].ruleSet < dups[j].ruleSet
	})

	if !lenient {
		d := dups[0]
		return nil, fmt.Errorf("duplicate NAT %s rule-set %q: a NAT rule-set name "+
			"is its operational identity, so the same name authored twice compiles "+
			"both instances as separate first-match rule-sets sharing one identity "+
			"— operator show surfaces cannot disambiguate them; author the "+
			"rule-set once (flat `set` merges repeated statements automatically) "+
			"(#6454)", d.natType, d.ruleSet)
	}

	warnings := make([]string, 0, len(dups))
	for _, d := range dups {
		warnings = append(warnings, fmt.Sprintf("duplicate NAT %s rule-set %q: the "+
			"same name compiles both instances as separate rule-sets sharing one "+
			"operational identity — author it once (#6454)", d.natType, d.ruleSet))
	}
	return warnings, nil
}
