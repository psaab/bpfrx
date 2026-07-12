package config

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

// FRR route-map sequence numbers occupy the command range
// `route-map WORD <permit|deny> (1-65535)`. The pkg/frr renderer
// (renderPolicyTermSequences / renderComposedRouteMap) numbers each emitted
// term sequence in steps of routeMapSeqStep starting at routeMapSeqStep, then
// appends ONE trailing default-action sequence, so a policy that expands to N
// term sequences uses a highest sequence number of routeMapSeqStep*(N+1).
// Once that exceeds frrMaxRouteMapSeq FRR rejects the `route-map` line with
// CMD_WARNING_CONFIG_FAILED, and a single failed line makes the whole
// vtysh-batched frr-reload exit non-zero — poisoning the ENTIRE managed-section
// reload, not just this policy (#5701).
const (
	frrMaxRouteMapSeq = 65535
	routeMapSeqStep   = 10
	// MaxRouteMapSequences is the largest number of per-term route-map
	// sequences a single policy-statement may expand to before its highest FRR
	// sequence number (routeMapSeqStep*(N+1), including the trailing default)
	// would exceed frrMaxRouteMapSeq. 65535/10 - 1 = 6552.
	MaxRouteMapSequences = frrMaxRouteMapSeq/routeMapSeqStep - 1
)

// RouteMapSequenceCount returns the number of FRR route-map TERM sequences the
// pkg/frr renderer will emit for ps (EXCLUDING the single trailing
// default-action sequence). It mirrors the renderer's Cartesian expansion
// exactly: per term, (2 when the term's route-filters mix IPv4 and IPv6
// families, else 1) x max(1,|from prefix-list|) x max(1,|from community|) x
// max(1,|from as-path|), summed over terms.
//
// The count depends only on the term's OR-set lengths and route-filter family
// mix — NOT on the referenced list CONTENTS — because emitVariants emits one
// route-map sequence per NAME, not per prefix. Every multiply and the running
// sum are overflow-checked (checkedMulU64 / saturating add): a pathological
// crafted policy saturates to math.MaxUint64 rather than wrapping back down
// into the in-bound range, so it never under-reports an over-ceiling policy.
func RouteMapSequenceCount(ps *PolicyStatement) uint64 {
	if ps == nil {
		return 0
	}
	var total uint64
	for _, term := range ps.Terms {
		if term == nil {
			continue
		}
		fam := uint64(1)
		if termRouteFiltersMixFamily(term) {
			fam = 2
		}
		v := checkedMulU64(fam, orOneU64(len(term.PrefixList)))
		v = checkedMulU64(v, orOneU64(len(term.FromCommunity)))
		v = checkedMulU64(v, orOneU64(len(term.FromASPath)))
		if total > math.MaxUint64-v {
			return math.MaxUint64
		}
		total += v
	}
	return total
}

// orOneU64 clamps a slice length to a minimum of 1: a missing `from` OR-set
// still contributes one route-map sequence (the emitVariants "" sentinel).
func orOneU64(n int) uint64 {
	if n <= 0 {
		return 1
	}
	return uint64(n)
}

// termRouteFiltersMixFamily reports whether a term's route-filters carry BOTH
// an IPv4 and an IPv6 prefix — the condition under which the renderer SPLITS
// the term into a v4 sequence and a v6 sequence (#2607), doubling its
// per-term sequence count. Family is classified by the same `:` heuristic
// partitionRouteFiltersByFamily uses.
func termRouteFiltersMixFamily(term *PolicyTerm) bool {
	var v4, v6 bool
	for _, rf := range term.RouteFilters {
		if rf == nil {
			continue
		}
		if strings.Contains(rf.Prefix, ":") {
			v6 = true
		} else {
			v4 = true
		}
		if v4 && v6 {
			return true
		}
	}
	return false
}

// validatePolicyRouteMapSequenceBoundStrict rejects a policy-statement whose
// route-map term expansion would exceed the FRR route-map sequence-number
// ceiling. Rendering such a policy emits a `route-map <name> <action> <seq>`
// line with seq > 65535, which FRR rejects (CMD_WARNING_CONFIG_FAILED); a
// single failed line makes the vtysh add-batch of the frr-reload exit non-zero
// and POISONS the whole managed-section reload (#5701) — every route/policy in
// the section fails to apply, not just this one policy. Rejecting at commit
// keeps the overflow from ever reaching the renderer.
//
// Strict on commit / commit-check (hard reject so the operator sees which
// policy is oversized); downgraded to a warning on the tolerant load /
// peer-sync paths (opts.lenientPolicyRouteMapSeq, #1960 no-brick) — the
// renderer independently SKIPS an over-ceiling policy (generatePolicyOptions),
// so a leniently-loaded oversized policy renders nothing rather than poisoning
// the reload. Policy names are validated in sorted order for a deterministic
// first error. Mirrors validateNextTableTargetReferencesStrict.
func validatePolicyRouteMapSequenceBoundStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	pss := cfg.PolicyOptions.PolicyStatements
	if len(pss) == 0 {
		return nil
	}
	names := make([]string, 0, len(pss))
	for name := range pss {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		ps := pss[name]
		if ps == nil {
			continue
		}
		if n := RouteMapSequenceCount(ps); n > MaxRouteMapSequences {
			return fmt.Errorf(
				"policy-statement %q expands to %d route-map sequences, over the "+
					"FRR ceiling of %d (route-map sequence numbers are 1..%d in steps "+
					"of %d, one reserved for the trailing default) — rendering it would "+
					"emit a `route-map` line past sequence %d, which FRR rejects and "+
					"which poisons the ENTIRE frr-reload; reduce the number of `from "+
					"prefix-list` / `from community` / `from as-path` values (their "+
					"Cartesian product per term drives the count) or split the policy "+
					"across multiple policy-statements",
				name, n, MaxRouteMapSequences, frrMaxRouteMapSeq, routeMapSeqStep, frrMaxRouteMapSeq)
		}
	}
	return nil
}
