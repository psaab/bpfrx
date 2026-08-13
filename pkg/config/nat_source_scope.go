package config

import (
	"fmt"
	"net/netip"
	"strings"
)

// leadingZeroPoolAddressReason renders the operator-facing reason for a pool
// member that is rejected ONLY because it spells an octet with a leading zero
// (#6812 F1 round 4).
//
// The generic reason ("is not a valid CIDR") is actively unhelpful here:
// `010.0.0.0/24` LOOKS like a valid CIDR, so an operator reading it has no way
// to see that the fix is deleting one character. This one names the canonical
// spelling and says why the ambiguous one is refused.
//
// It matters most on the TOLERANT path. A pool carrying such a member is
// marked unusable and stops translating, and the config reached that path
// precisely because it was persisted (or peer-synced from a primary) that
// predates the #5627 grammar gate — so the operator meets this as a NAT outage
// after an upgrade, not as a commit error they can iterate on.
func leadingZeroPoolAddressReason(addr, canonical string) string {
	return fmt.Sprintf(
		"spells an octet with a leading zero (%q); write it as %q — a leading zero is "+
			"octal to some parsers, so the dataplane refuses the ambiguous spelling rather "+
			"than guessing, and marks the whole pool unusable (this pool translates nothing "+
			"until the address is corrected)",
		addr, canonical)
}

// canonicalPoolAddressHint returns the canonical spelling of a pool address
// literal that differs from `addr` ONLY by leading zeros in its dotted-decimal
// octets, or "" when no such rewrite makes it parseable (#6812 F1 round 4).
//
// The result is a DIAGNOSTIC, never a substitution: nothing in the compiler or
// the snapshot builder installs it. #5875 settled that doctrine for the
// structurally identical `%zone` case — "stripping the %zone silently would
// change the modeled address, so the fix rejects rather than rewrites" — and a
// leading zero is the weaker case of the two, since `010` has two readings
// (decimal 10, octal 8) where `fe80::1%eth0` has one. Rewriting it silently
// would install a NAT pool on a guess that `show configuration` would never
// reveal.
//
// Only a rewrite that turns an UNPARSEABLE literal into a parseable one is
// reported, so the hint can never suggest a change to an address that already
// works, and never invents a suggestion for an unrelated malformation
// (`not-an-ip`, `10.0.0.256/24`, a bad mask).
func canonicalPoolAddressHint(addr string) string {
	if !strings.Contains(addr, ".") {
		return ""
	}
	addrPart, maskPart, hasMask := strings.Cut(addr, "/")
	fields := strings.Split(addrPart, ".")
	changed := false
	for i, f := range fields {
		// Strip leading zeros from the TRAILING digit run only, so the
		// `::ffff:010.0.0.0` form (whose first field carries the v6 prefix)
		// is handled without touching the hextets.
		start := len(f)
		for start > 0 && f[start-1] >= '0' && f[start-1] <= '9' {
			start--
		}
		digits := f[start:]
		if len(digits) < 2 || digits[0] != '0' {
			continue
		}
		trimmed := strings.TrimLeft(digits, "0")
		if trimmed == "" {
			trimmed = "0"
		}
		fields[i] = f[:start] + trimmed
		changed = true
	}
	if !changed {
		return ""
	}
	candidate := strings.Join(fields, ".")
	if hasMask {
		candidate += "/" + maskPart
	}
	// Report only if the rewrite is what made it parseable.
	if hasMask {
		if _, err := netip.ParsePrefix(addr); err == nil {
			return ""
		}
		if _, err := netip.ParsePrefix(candidate); err != nil {
			return ""
		}
		return candidate
	}
	if _, err := netip.ParseAddr(addr); err == nil {
		return ""
	}
	if _, err := netip.ParseAddr(candidate); err != nil {
		return ""
	}
	return candidate
}

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
