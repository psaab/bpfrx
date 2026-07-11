package config

import (
	"math"
	"strings"
	"testing"
)

// #5456: FilterTermExpansionCount is the per-term counter-slot STRIDE every
// counter reader walks. It used to compute the src×dst×dstPort×srcPort
// cross-product as int products and cast the result straight to uint32 with NO
// overflow check. A term whose product exceeds 2^32 (a large prefix-list
// cross-product) therefore WRAPPED to a small wrong stride, making
// `show firewall filter` / the Prometheus collector read into a neighbouring
// term's counter slots (unbounded drift), and the same unbounded product drove
// a config-driven commit-time expansion DoS.
//
// The fix computes the product in overflow-checked uint64
// (FilterTermExpansionCount64), CLAMPS the uint32 stride to
// MaxFilterTermExpansion instead of wrapping, and REJECTS an over-cap term at
// the strict commit gate (validateFilterTermExpansionBoundStrict).

// bigPrefixList returns a PrefixList carrying n distinct-in-name (content is
// irrelevant to the count, which reads len(Prefixes)) prefixes. It builds the
// slice directly — no parsing — so a multi-thousand-entry list is cheap.
func bigPrefixList(name string, n int) *PrefixList {
	pfx := make([]string, n)
	for i := range pfx {
		pfx[i] = "10.0.0.0/32"
	}
	return &PrefixList{Name: name, Prefixes: pfx}
}

// TestFilterExpansionCount64ExceedsUint32NoWrap pins the core arithmetic: a
// cross-product past 2^32 is computed exactly in uint64 and the uint32 stride
// CLAMPS to the cap rather than wrapping.
//
// RED-ON-REVERT: restore `return uint32(nSrc * nDst * nDstPorts * nSrcPorts)`
// and FilterTermExpansionCount returns the WRAPPED value (uint32 of the true
// product), not the clamp — the wrapCheck assertion below fails.
func TestFilterExpansionCount64ExceedsUint32NoWrap(t *testing.T) {
	const n = 66000 // 66000 * 66000 = 4_356_000_000 > MaxUint32 (4_294_967_296)
	prefixLists := map[string]*PrefixList{
		"src": bigPrefixList("src", n),
		"dst": bigPrefixList("dst", n),
	}
	term := &FirewallFilterTerm{
		Name:              "t",
		Action:            "discard",
		SourcePrefixLists: []PrefixListRef{{Name: "src"}},
		DestPrefixLists:   []PrefixListRef{{Name: "dst"}},
	}

	want64 := uint64(n) * uint64(n)
	if got := FilterTermExpansionCount64(term, prefixLists); got != want64 {
		t.Fatalf("FilterTermExpansionCount64 = %d, want exact %d", got, want64)
	}
	if want64 <= math.MaxUint32 {
		t.Fatalf("test misconfigured: product %d does not exceed MaxUint32", want64)
	}

	got := FilterTermExpansionCount(term, prefixLists)
	if got != MaxFilterTermExpansion {
		t.Fatalf("FilterTermExpansionCount = %d, want clamp to MaxFilterTermExpansion (%d)",
			got, MaxFilterTermExpansion)
	}
	// The load-bearing assertion: the stride is NOT the silently-wrapped value
	// the old `uint32(product)` cast produced.
	if wrapped := uint32(want64); got == wrapped {
		t.Fatalf("FilterTermExpansionCount returned the WRAPPED value %d — the "+
			"uint32 truncation was not fixed", wrapped)
	}
}

// TestFilterExpansionBoundStrictRejectsOverCap proves the strict gate rejects a
// term whose cross-product exceeds the cap and names the term + the count.
//
// RED-ON-REVERT: remove the `if count > MaxFilterTermExpansion` reject and this
// commit is accepted (nil error).
func TestFilterExpansionBoundStrictRejectsOverCap(t *testing.T) {
	const n = 66000
	cfg := &Config{}
	cfg.PolicyOptions.PrefixLists = map[string]*PrefixList{
		"src": bigPrefixList("src", n),
		"dst": bigPrefixList("dst", n),
	}
	cfg.Firewall.FiltersInet = map[string]*FirewallFilter{
		"f": {Name: "f", Terms: []*FirewallFilterTerm{
			{
				Name:              "huge",
				Action:            "discard",
				SourcePrefixLists: []PrefixListRef{{Name: "src"}},
				DestPrefixLists:   []PrefixListRef{{Name: "dst"}},
			},
		}},
	}
	err := validateFilterTermExpansionBoundStrict(cfg)
	if err == nil {
		t.Fatal("expected reject for an over-cap firewall-filter term expansion, got nil")
	}
	if !strings.Contains(err.Error(), "huge") || !strings.Contains(err.Error(), "filter \"f\"") {
		t.Fatalf("error must name the offending filter/term: %v", err)
	}
}

// TestFilterExpansionBoundStrictAcceptsAtCap pins the boundary: a term whose
// product is exactly MaxFilterTermExpansion is accepted (the reject is strictly
// `>` the cap, not `>=`).
func TestFilterExpansionBoundStrictAcceptsAtCap(t *testing.T) {
	cfg := &Config{}
	cfg.PolicyOptions.PrefixLists = map[string]*PrefixList{
		"src": bigPrefixList("src", MaxFilterTermExpansion),
	}
	cfg.Firewall.FiltersInet = map[string]*FirewallFilter{
		"f": {Name: "f", Terms: []*FirewallFilterTerm{
			{
				Name:              "atcap",
				Action:            "discard",
				SourcePrefixLists: []PrefixListRef{{Name: "src"}}, // nSrc=cap, others=1
			},
		}},
	}
	if got := FilterTermExpansionCount64(cfg.Firewall.FiltersInet["f"].Terms[0], cfg.PolicyOptions.PrefixLists); got != MaxFilterTermExpansion {
		t.Fatalf("count64 at boundary = %d, want %d", got, MaxFilterTermExpansion)
	}
	if err := validateFilterTermExpansionBoundStrict(cfg); err != nil {
		t.Fatalf("a term expanding to exactly the cap must be accepted, got: %v", err)
	}
}

// TestFilterExpansionNormalTermUnchanged pins that the ordinary (small) case is
// bit-for-bit unchanged: the exact product is returned and the gate accepts.
func TestFilterExpansionNormalTermUnchanged(t *testing.T) {
	prefixLists := map[string]*PrefixList{
		"src": {Name: "src", Prefixes: []string{"10.1.0.0/24", "10.2.0.0/24"}},
	}
	term := &FirewallFilterTerm{
		Name:              "t",
		Action:            "accept",
		SourceAddresses:   []string{"192.0.2.1/32"},         // nSrc = 1 literal + 2 prefixes = 3
		SourcePrefixLists: []PrefixListRef{{Name: "src"}},   //
		DestinationPorts:  []string{"80", "443"},            // nDstPorts = 2
		SourcePorts:       []string{"1024", "2048", "4096"}, // nSrcPorts = 3
	}
	// nSrc(3) × nDst(1) × nDstPorts(2) × nSrcPorts(3) = 18
	if got := FilterTermExpansionCount(term, prefixLists); got != 18 {
		t.Fatalf("FilterTermExpansionCount = %d, want 18 (normal case unchanged)", got)
	}
	if got := FilterTermExpansionCount64(term, prefixLists); got != 18 {
		t.Fatalf("FilterTermExpansionCount64 = %d, want 18", got)
	}
	cfg := &Config{}
	cfg.PolicyOptions.PrefixLists = prefixLists
	cfg.Firewall.FiltersInet = map[string]*FirewallFilter{"f": {Name: "f", Terms: []*FirewallFilterTerm{term}}}
	if err := validateFilterTermExpansionBoundStrict(cfg); err != nil {
		t.Fatalf("a normal small term must be accepted, got: %v", err)
	}
}

// TestFilterExpansionCommitRejectsOverCap drives the FULL, WIRED commit path
// (CompileConfig → runUniformGates → validateFilterTermExpansionBoundStrict)
// with a real ConfigTree whose term cross-product exceeds 2^32
// (256×256×256×257 = 4_311_744_512), and asserts commit is REJECTED.
//
// RED-ON-REVERT (two independent regressions this catches):
//   - Remove the gate wiring in compiler_uniformgates.go → CompileConfig
//     returns nil here (the over-cap term commits).
//   - Restore the `uint32(...)` cast in FilterTermExpansionCount → the leniently
//     re-checked stride wraps to 16_777_216 instead of the clamp; the companion
//     unit test above goes RED.
//
// The lenient path (CompileConfigLenient) must still BOOT this config (#1960
// no-brick) with a downgraded warning.
func TestFilterExpansionCommitRejectsOverCap(t *testing.T) {
	var lines []string
	// 256 source prefixes, 256 destination prefixes.
	for i := 0; i < 256; i++ {
		lines = append(lines,
			"set policy-options prefix-list SRC 10."+itoa(i)+".0.0/24",
			"set policy-options prefix-list DST 172.16."+itoa(i)+".0/24",
		)
	}
	lines = append(lines,
		"set firewall family inet filter f term t from source-prefix-list SRC",
		"set firewall family inet filter f term t from destination-prefix-list DST",
	)
	// 256 destination ports + 257 source ports → product = 256*256*256*257.
	for i := 0; i < 256; i++ {
		lines = append(lines, "set firewall family inet filter f term t from destination-port "+itoa(1+i))
	}
	for i := 0; i < 257; i++ {
		lines = append(lines, "set firewall family inet filter f term t from source-port "+itoa(1+i))
	}
	lines = append(lines, "set firewall family inet filter f term t then discard")

	tree := buildTree(t, lines)

	// Sanity: the compiled term's exact cross-product exceeds 2^32 so the old
	// uint32 cast would have wrapped (this is what makes the RED-on-revert real).
	cfgLenient, lerr := CompileConfigLenient(tree)
	if lerr != nil {
		t.Fatalf("lenient path must still boot an over-cap config (#1960), got: %v", lerr)
	}
	term := cfgLenient.Firewall.FiltersInet["f"].Terms[0]
	prod := FilterTermExpansionCount64(term, cfgLenient.PolicyOptions.PrefixLists)
	if prod <= math.MaxUint32 {
		t.Fatalf("test misconfigured: compiled product %d does not exceed 2^32 "+
			"(nSrc=%d nDst=%d nDstPorts=%d nSrcPorts=%d)", prod,
			len(term.SourcePrefixLists), len(term.DestPrefixLists),
			len(term.DestinationPorts), len(term.SourcePorts))
	}
	// The lenient stride is clamped, never the wrapped value.
	if got := FilterTermExpansionCount(term, cfgLenient.PolicyOptions.PrefixLists); got != MaxFilterTermExpansion {
		t.Fatalf("lenient stride = %d, want clamp %d (never the wrap %d)",
			got, MaxFilterTermExpansion, uint32(prod))
	}
	if !anyWarningContains(cfgLenient, "term expansion") {
		t.Errorf("lenient path should carry a downgraded expansion warning; warnings=%v", cfgLenient.Warnings)
	}

	// Strict commit path REJECTS.
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("strict commit must reject an over-cap firewall-filter term, got nil")
	} else if !strings.Contains(err.Error(), "expands to") {
		t.Fatalf("commit error should describe the expansion, got: %v", err)
	}
}

func anyWarningContains(cfg *Config, sub string) bool {
	for _, w := range cfg.Warnings {
		if strings.Contains(w, sub) {
			return true
		}
	}
	return false
}
