package cli

import (
	"fmt"
	"sort"

	"github.com/psaab/xpf/pkg/config"
)

// analyzePolicyShadowing runs a conservative shadow / redundancy pass over the
// configured zone-pair policies (fable-167 C-1c, #4314), mirroring Junos
// `request security policies check`. Within each ordered zone-pair list, an
// earlier policy shadows a later one when it matches a SUPERSET of the later
// policy's traffic — because policies are terminal (permit/deny/reject) and
// evaluated first-match, the later policy is then unreachable.
//
// The superset test is a NAME-SET containment on the match fields
// (source-address, destination-address, application), with "any" treated as
// the universal set. It deliberately does NOT resolve address-book names to
// prefixes — that would need the address-book expansion and risks false
// positives — so it is conservative: it reports only high-confidence
// wildcard-or-containment shadows, never a partial-overlap guess. Policies
// that invert a match sense (source/destination-address-excluded) or that are
// schedule-gated (scheduler-name — not always active) are never treated as
// shadowers, since their coverage is not a plain superset.
//
// A finding distinguishes a pure REDUNDANT rule (same action as its shadower —
// harmless but dead) from a SHADOWED rule whose distinct action never applies
// (the operationally dangerous case).
func analyzePolicyShadowing(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}
	var findings []string
	// Deterministic order: sort zone pairs by from/to zone.
	pairs := append([]*config.ZonePairPolicies(nil), cfg.Security.Policies...)
	sort.SliceStable(pairs, func(i, j int) bool {
		if pairs[i] == nil || pairs[j] == nil {
			return pairs[j] == nil
		}
		if pairs[i].FromZone != pairs[j].FromZone {
			return pairs[i].FromZone < pairs[j].FromZone
		}
		return pairs[i].ToZone < pairs[j].ToZone
	})
	for _, zpp := range pairs {
		if zpp == nil {
			continue
		}
		scope := fmt.Sprintf("from-zone %s to-zone %s", zpp.FromZone, zpp.ToZone)
		findings = analyzePolicyListShadowing(zpp.Policies, scope, nil, findings)
	}
	// codex-182 A10-b00-C01: global policies (`security policies global`) are
	// an ordered, terminal, first-match list too — an earlier global shadows a
	// later one on the same conservative name-set superset. The extra
	// globalScopeCovers gate additionally requires the earlier global's
	// from-zone/to-zone match context (#3148/#4626) to COVER the later's (an
	// empty zone set = all zones), so two globals narrowed to disjoint zone
	// contexts are never falsely reported as shadowing. Cross-tier shadowing
	// between a zone-pair policy and a global is deliberately NOT analyzed: the
	// global tier is reached only when no zone-pair policy matched, so a
	// zone-pair superset is not an unreachability proof for a global.
	findings = analyzePolicyListShadowing(cfg.Security.GlobalPolicies, "global", globalScopeCovers, findings)
	return findings
}

// analyzePolicyListShadowing runs the conservative shadow / redundancy pass
// over ONE ordered, terminal, first-match policy list (a single zone-pair list
// or the global list) and appends findings tagged with scope. extraSuperset,
// when non-nil, is an ADDITIONAL superset predicate that must also hold for a
// shadow to be reported (used by the global list to require zone-context
// containment on top of the address/application superset); it is nil for
// zone-pair lists, whose zone context is fixed by the surrounding stanza.
func analyzePolicyListShadowing(policies []*config.Policy, scope string, extraSuperset func(earlier, later *config.Policy) bool, findings []string) []string {
	for j := 1; j < len(policies); j++ {
		later := policies[j]
		if later == nil {
			continue
		}
		for i := 0; i < j; i++ {
			earlier := policies[i]
			if earlier == nil {
				continue
			}
			if !policyMatchIsSuperset(earlier, later) {
				continue
			}
			if extraSuperset != nil && !extraSuperset(earlier, later) {
				continue
			}
			if earlier.Action == later.Action &&
				policyMatchIsSuperset(later, earlier) &&
				(extraSuperset == nil || extraSuperset(later, earlier)) {
				findings = append(findings, fmt.Sprintf(
					"  [%s] policy %q is REDUNDANT: identical match and action to earlier policy %q",
					scope, later.Name, earlier.Name))
			} else if earlier.Action == later.Action {
				findings = append(findings, fmt.Sprintf(
					"  [%s] policy %q is REDUNDANT: earlier policy %q already matches a superset with the same action (%s)",
					scope, later.Name, earlier.Name, policyActionName(earlier.Action)))
			} else {
				findings = append(findings, fmt.Sprintf(
					"  [%s] policy %q is SHADOWED and UNREACHABLE: earlier policy %q matches a superset with a different action (%s vs %s)",
					scope, later.Name, earlier.Name,
					policyActionName(earlier.Action), policyActionName(later.Action)))
			}
			break // report the first shadower only
		}
	}
	return findings
}

// globalScopeCovers reports whether global policy a's from-zone/to-zone match
// context (#3148/#4626) covers b's — a's zone set must be a superset of b's on
// BOTH sides, where an empty set means "all zones" (the universal set). Two
// global policies narrowed to disjoint (or merely non-nesting) zone contexts
// never shadow each other even when their address/application match sets nest,
// so this gate keeps the global shadow pass free of that false positive.
func globalScopeCovers(a, b *config.Policy) bool {
	return zoneSetCovers(a.Match.FromZones, b.Match.FromZones) &&
		zoneSetCovers(a.Match.ToZones, b.Match.ToZones)
}

// zoneSetCovers reports whether zone set a covers zone set b: an empty a is the
// universal set and covers everything; a non-empty a covers b only when every
// zone in b is present in a. An empty b against a non-empty a is NOT covered —
// b ("all zones") is the broader context.
func zoneSetCovers(a, b []string) bool {
	if len(a) == 0 {
		return true
	}
	if len(b) == 0 {
		return false
	}
	set := make(map[string]struct{}, len(a))
	for _, z := range a {
		set[z] = struct{}{}
	}
	for _, z := range b {
		if _, ok := set[z]; !ok {
			return false
		}
	}
	return true
}

// policyMatchIsSuperset reports whether policy a matches a superset of the
// traffic policy b matches, using conservative name-set containment. It is
// disqualified (returns false, the safe no-shadow answer) whenever EITHER
// policy inverts a match sense, or a is schedule-gated.
//
// An excluded (`source-address-excluded` / `destination-address-excluded`)
// sense makes the match set the COMPLEMENT of the named set, so a plain
// name-set containment no longer proves coverage. It must disqualify on BOTH
// sides, not just a: if b (the later, candidate-shadowed policy) is excluded,
// the two match sets can be disjoint even when the named sets are identical —
// e.g. earlier `permit source-address [A]` vs later `deny source-address [A]
// source-address-excluded` matches src∈{A} vs src∉{A}, which is FULLY
// reachable, not shadowed. Ignoring b's excluded flags produced that false
// positive (fable-167 C-1c review MINOR); a lint that cries wolf on an
// advisory erodes trust, so the no-false-positive contract wins over
// completeness here.
func policyMatchIsSuperset(a, b *config.Policy) bool {
	if a == nil || b == nil {
		return false
	}
	// An inverted match sense on EITHER policy breaks plain name-set
	// containment; a schedule-gated shadower is not always active.
	if a.Match.SourceAddressExcluded || a.Match.DestinationAddressExcluded {
		return false
	}
	if b.Match.SourceAddressExcluded || b.Match.DestinationAddressExcluded {
		return false
	}
	if a.SchedulerName != "" {
		return false
	}
	return nameSetSuperset(a.Match.SourceAddresses, b.Match.SourceAddresses) &&
		nameSetSuperset(a.Match.DestinationAddresses, b.Match.DestinationAddresses) &&
		nameSetSuperset(a.Match.Applications, b.Match.Applications)
}

// nameSetSuperset reports whether super is a superset of sub as Junos match
// name sets: "any" in super is the universal set; otherwise every element of
// sub must appear in super. An "any" in sub that super lacks is NOT covered.
// An empty sub is treated as unconstrained (== "any") for safety, so it is
// covered only when super is also "any".
func nameSetSuperset(super, sub []string) bool {
	if containsAny(super) {
		return true
	}
	if len(sub) == 0 || containsAny(sub) {
		// sub is universal but super is not.
		return false
	}
	set := make(map[string]struct{}, len(super))
	for _, s := range super {
		set[s] = struct{}{}
	}
	for _, s := range sub {
		if _, ok := set[s]; !ok {
			return false
		}
	}
	return true
}

func containsAny(names []string) bool {
	for _, n := range names {
		if n == "any" {
			return true
		}
	}
	return false
}

func policyActionName(a config.PolicyAction) string {
	switch a {
	case config.PolicyPermit:
		return "permit"
	case config.PolicyDeny:
		return "deny"
	case config.PolicyReject:
		return "reject"
	default:
		return "unknown"
	}
}
