package config

// Source-NAT context-specificity tiers (#4161). LOWER = more specific = higher
// precedence, matching Junos rule-set selection (interface most specific).
//
// Lived in pkg/dataplane/userspace until #6812 F3; it moved here so the
// snapshot builder's emission order and the aggregate budget walk's first-fit
// order read ONE definition (see SourceNATScopeTier).
const (
	SourceNATTierInterface       = 0
	SourceNATTierZone            = 1
	SourceNATTierRoutingInstance = 2
	SourceNATTierUnscoped        = 3
)

// SourceNATScopeTier returns the Junos context-specificity tier of a source-NAT
// rule-set's from/to scope (#4161). A rule-set may carry both a `from` and a
// `to` context, and they may be of different kinds; either context narrows the
// match, so the MORE-SPECIFIC of the two governs the rule-set's precedence:
// tier = MIN(from-tier, to-tier). This MIN default is the vSRX-pinned semantic
// (confirmed by the L-9 overlap tests).
//
// TWO callers share it so they cannot drift (#6812 F3):
//
//  1. the userspace snapshot builder STABLE-SORTS its emitted rules by this
//     tier (pkg/dataplane/userspace/nat_source.go), which is the order the Rust
//     allocator resolver walks; and
//  2. sourceNATAggregateReferencedCharges walks referenced pools in this same
//     order, so the pool Go admits first is the pool the dataplane charges
//     first.
//
// (2) is the #6812 F3 fix. The walk previously ordered rule-sets by NAME, which
// is neither the emitted order nor any Junos semantic: with two pools that each
// fit alone but not together, an alphabetically-earlier ZONE-scoped rule-set
// took the budget and the more-specific INTERFACE-scoped rule-set was poisoned
// `aggregate_over_budget` — the reverse of the precedence the builder enforces
// for matching one function later, and it made the PR's own "same order as
// resolve_pool_allocators" claim false.
func SourceNATScopeTier(fromIface, fromZone, fromRI, toIface, toZone, toRI string) int {
	from := sourceNATScopeContextTier(fromIface, fromZone, fromRI)
	to := sourceNATScopeContextTier(toIface, toZone, toRI)
	if to < from {
		return to
	}
	return from
}

// natRuleSetScopeTier is SourceNATScopeTier over a rule-set, nil-safe. A nil
// rule-set sorts LAST (the budget walk skips it); it can never outrank a real
// rule-set for a budget slot.
func natRuleSetScopeTier(rs *NATRuleSet) int {
	if rs == nil {
		return SourceNATTierUnscoped + 1
	}
	return SourceNATScopeTier(
		rs.FromInterface, rs.FromZone, rs.FromRoutingInstance,
		rs.ToInterface, rs.ToZone, rs.ToRoutingInstance,
	)
}

// sourceNATScopeContextTier maps a single from/to context to its specificity
// tier (#4161): interface=0, zone=1, routing-instance=2.
//
// The wildcard / match-any context is the EMPTY string on every axis (all
// three args ""), which falls through to SourceNATTierUnscoped (3). That empty
// value is exactly what the compiler emits for an absent `from`/`to` clause:
// collectNATScopes (pkg/config/compiler_nat.go) defaults a missing side to
// {kind:"zone", value:""} → FromZone/ToZone "" — the legacy global/match-any
// scope. So "wildcard" here means empty, NOT a zone named "any": a NON-EMPTY
// zone (tier 1) is always a SPECIFIC zone, and a literal `from zone any` is
// FromZone="any", a specific zone literally named "any", not a wildcard. This
// is CONSISTENT with the Rust eligibility check (source.rs scope_matches:
// `!from_zone.is_empty() && from_zone != ingress`), which only special-cases
// the empty string and matches "any" literally. NAT rule-set from/to-contexts
// do NOT treat "any" as a wildcard (unlike security policies' from-zone/
// to-zone). A future maintainer must not special-case "any" as tier-unscoped —
// that would diverge from the matcher and mis-tier a legitimately-named zone.
//
// A Junos from/to clause names exactly one kind of context; a hostile config
// that sets more than one is ranked by its most-specific present field (the
// Rust scope_matches AND-filters every set field regardless, so this only
// affects precedence, never eligibility).
func sourceNATScopeContextTier(iface, zone, routingInstance string) int {
	switch {
	case iface != "":
		return SourceNATTierInterface
	case zone != "":
		return SourceNATTierZone
	case routingInstance != "":
		return SourceNATTierRoutingInstance
	default:
		return SourceNATTierUnscoped
	}
}
