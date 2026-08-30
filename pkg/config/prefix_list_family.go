package config

import "strings"

// PrefixListFamilies reports which address families a prefix-list holds
// entries for (#7526).
//
// IT IS THE SINGLE SOURCE for a question two packages ask and used to answer
// separately. pkg/frr's renderer expands one referenced prefix-list NAME into
// one match line PER FAMILY it holds, so a mixed v4+v6 list produces TWO
// sequences where a single-family list produces one. The admission bound in
// routemap_seq_bound.go counted one per NAME, family-blind — so a policy
// referencing mixed-family lists rendered up to twice the sequences the bound
// admitted, and a config sitting just under MaxRouteMapSequences could exceed
// FRR's ceiling after rendering.
//
// The fix is not to teach the bound the renderer's rule; it is to have one
// rule. pkg/frr maps this to its own "ip"/"ipv6" match keywords, which are FRR
// spellings and stay there, but WHICH families a list holds is decided here.
//
// An empty or nil list reports IPv4 only. That mirrors the renderer's
// fail-closed default for an undefined or empty referenced list: it still emits
// exactly one match line, which NOMATCHes every route. Reporting zero families
// would make the bound count zero sequences for a term the renderer still emits
// one for.
func PrefixListFamilies(pl *PrefixList) (hasV4, hasV6 bool) {
	if pl != nil {
		for _, p := range pl.Prefixes {
			if strings.Contains(p, ":") {
				hasV6 = true
			} else {
				hasV4 = true
			}
		}
	}
	if !hasV4 && !hasV6 {
		return true, false
	}
	return hasV4, hasV6
}

// PrefixListFamilyCount returns how many sequences one reference to this
// prefix-list expands into: 1 for a single-family (or empty) list, 2 for a
// mixed v4+v6 one (#7526).
func PrefixListFamilyCount(pl *PrefixList) uint64 {
	v4, v6 := PrefixListFamilies(pl)
	if v4 && v6 {
		return 2
	}
	return 1
}

// TermPrefixListRefCount returns the number of from-prefix-list REFS a term
// expands into — the sum of each referenced list's family count, not the number
// of names (#7526).
//
// A term with no from-prefix-list yields 1, matching the renderer's "" sentinel
// which still emits exactly one sequence so the from-* cross-product is not
// multiplied by zero.
func TermPrefixListRefCount(po *PolicyOptionsConfig, names []string) uint64 {
	if len(names) == 0 {
		return 1
	}
	var total uint64
	for _, n := range names {
		var pl *PrefixList
		if po != nil {
			pl = po.PrefixLists[n]
		}
		c := PrefixListFamilyCount(pl)
		if total > ^uint64(0)-c {
			return ^uint64(0)
		}
		total += c
	}
	return total
}
