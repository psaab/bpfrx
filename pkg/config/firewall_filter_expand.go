package config

// FilterTermExpansionCount returns the number of dataplane filter rules a
// single firewall-filter term expands into: the cross-product
// (literal source addresses + every source-prefix-list prefix) ×
// (literal destination addresses + every destination-prefix-list prefix) ×
// destination-ports × source-ports, each factor clamped to a minimum of 1
// ("any").
//
// This is the SINGLE SOURCE OF TRUTH for the per-term counter-slot stride used
// by every counter reader — CLI `show firewall filter`, the gRPC text mirror,
// and the Prometheus xpf_filter_hits_total collector. A reader sums `count`
// consecutive slots from the term's RuleStart offset and advances by the same
// `count`, so the next term reads its OWN slots rather than a neighbour's
// (#3459). It lives here, in the config package, because it is pure
// config-field arithmetic with no dataplane dependency — all readers already
// import config, and it keeps the eBPF-retirement import boundary clean.
//
// It counts ALL prefix-list prefixes regardless of the `except` modifier,
// because the dataplane expansion (pkg/dataplane.expandFilterTerm) emits a
// (negated) rule for an except prefix too — excluding them would undercount
// the stride and drift the running offset. The drift-guard test
// TestFilterTermExpansionCountMatchesExpand pins this == len(expandFilterTerm).
func FilterTermExpansionCount(term *FirewallFilterTerm, prefixLists map[string]*PrefixList) uint32 {
	nSrc := len(term.SourceAddresses)
	for _, ref := range term.SourcePrefixLists {
		if pl, ok := prefixLists[ref.Name]; ok {
			nSrc += len(pl.Prefixes)
		}
	}
	if nSrc == 0 {
		nSrc = 1
	}
	nDst := len(term.DestAddresses)
	for _, ref := range term.DestPrefixLists {
		if pl, ok := prefixLists[ref.Name]; ok {
			nDst += len(pl.Prefixes)
		}
	}
	if nDst == 0 {
		nDst = 1
	}
	nDstPorts := len(term.DestinationPorts)
	if nDstPorts == 0 {
		nDstPorts = 1
	}
	nSrcPorts := len(term.SourcePorts)
	if nSrcPorts == 0 {
		nSrcPorts = 1
	}
	return uint32(nSrc * nDst * nDstPorts * nSrcPorts)
}
