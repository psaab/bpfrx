package config

import (
	"math"
	"math/bits"
)

// MaxFilterTermExpansion caps the number of dataplane filter rules a single
// firewall-filter term may expand into (its src×dst×dstPort×srcPort
// cross-product). A term that exceeds it is REJECTED at the strict commit gate
// (validateFilterTermExpansionBoundStrict) rather than installed.
//
// Two problems motivate the cap (#5456):
//
//   - Correctness: the expansion count is the per-term counter-slot STRIDE
//     every counter reader walks (see FilterTermExpansionCount). Before the
//     cap the product was cast straight to uint32, so a cross-product past
//     2^32 (e.g. a 5000-prefix source list × a 5000-prefix destination list ×
//     100 dest-ports × 100 src-ports = 2.5e11) WRAPPED to a small wrong value.
//     A wrapped stride makes `show firewall filter` / the Prometheus collector
//     read into a neighbouring term's counter slots and mis-attribute hits
//     (the #3459 drift class, but driven by silent truncation rather than a
//     count/layout mismatch).
//
//   - Commit-time DoS: the same unbounded product drives the actual term
//     expansion (pkg/dataplane.expandFilterTerm materializes one FilterRule
//     per cross-product entry; the per-rule counter-slot reader iterates the
//     stride). A config-driven 2.5e11-entry cross-product is a
//     memory/CPU-exhaustion attack surface at commit.
//
// The value (1<<20 = 1,048,576) is far beyond any legitimate single-term
// policy — a real firewall filter references a handful of prefixes and ports,
// and the retired-eBPF dataplane rule table is only MaxFilterRules (512)
// entries total — yet it stays well under 2^32 so the uint32 stride can never
// wrap. It is a resource bound, not a feature limit: a term that legitimately
// needs more rules should be split.
const MaxFilterTermExpansion = 1 << 20 // 1,048,576 dataplane rules per term

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
//
// #5456: the product is computed in uint64 (FilterTermExpansionCount64,
// overflow-checked) and NEVER cast through a wrapping uint32. A committed
// config can never carry a term whose product exceeds MaxFilterTermExpansion —
// the strict commit gate rejects it. This function is reached with an
// over-bound term only on the tolerant load / peer-sync path (an already-
// persisted or peer-synced config — #1960 no-brick), where it CLAMPS the
// stride to MaxFilterTermExpansion rather than silently wrapping. The clamp is
// consistent with expandFilterTerm, which caps its materialized rule slice at
// the same bound, so the drift-guard invariant (count == len(expandFilterTerm))
// holds even for an over-bound term. The normal (in-bound) case is unchanged
// bit-for-bit: the exact product is returned.
func FilterTermExpansionCount(term *FirewallFilterTerm, prefixLists map[string]*PrefixList) uint32 {
	c := FilterTermExpansionCount64(term, prefixLists)
	if c > MaxFilterTermExpansion {
		return MaxFilterTermExpansion
	}
	return uint32(c)
}

// FilterTermExpansionCount64 returns the exact src×dst×dstPort×srcPort
// cross-product of a firewall-filter term as a uint64, each factor clamped to a
// minimum of 1 ("any"). It is the overflow-safe core of FilterTermExpansionCount
// and the value the strict commit gate (validateFilterTermExpansionBoundStrict)
// compares against MaxFilterTermExpansion.
//
// Every multiply is checked (math/bits.Mul64): a product that would overflow
// uint64 saturates to math.MaxUint64 rather than wrapping. Overflow requires a
// pathological config far past MaxFilterTermExpansion, so the saturated value
// still lands the term squarely on the reject side of the cap — it never
// under-reports an over-bound term back down into the accepted range.
func FilterTermExpansionCount64(term *FirewallFilterTerm, prefixLists map[string]*PrefixList) uint64 {
	nSrc := uint64(len(term.SourceAddresses))
	for _, ref := range term.SourcePrefixLists {
		if pl, ok := prefixLists[ref.Name]; ok {
			nSrc += uint64(len(pl.Prefixes))
		}
	}
	if nSrc == 0 {
		nSrc = 1
	}
	nDst := uint64(len(term.DestAddresses))
	for _, ref := range term.DestPrefixLists {
		if pl, ok := prefixLists[ref.Name]; ok {
			nDst += uint64(len(pl.Prefixes))
		}
	}
	if nDst == 0 {
		nDst = 1
	}
	nDstPorts := uint64(len(term.DestinationPorts))
	if nDstPorts == 0 {
		nDstPorts = 1
	}
	nSrcPorts := uint64(len(term.SourcePorts))
	if nSrcPorts == 0 {
		nSrcPorts = 1
	}
	p := checkedMulU64(nSrc, nDst)
	p = checkedMulU64(p, nDstPorts)
	p = checkedMulU64(p, nSrcPorts)
	return p
}

// checkedMulU64 multiplies two uint64 values, saturating to math.MaxUint64 on
// overflow instead of wrapping.
func checkedMulU64(a, b uint64) uint64 {
	hi, lo := bits.Mul64(a, b)
	if hi != 0 {
		return math.MaxUint64
	}
	return lo
}
