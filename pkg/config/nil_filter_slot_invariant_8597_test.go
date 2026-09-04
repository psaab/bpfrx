package config

import (
	"fmt"
	"testing"
)

// #8597 (muse-spark-review-004 K90 / K91): the #6780 invariant, extended to
// firewall FILTERS and TERMS.
//
// WHY THIS EXISTS RATHER THAN THE FIX THOSE FINDINGS ASK FOR. Both prescribe
// adding consumer-side nil guards — `if filter == nil { continue }` in
// `pkg/api/metrics_counters.go`, and the same in its CLI twin. #6780 proved for
// interfaces, units and redundancy groups that such guards are dead code and
// that adding more is the wrong end of the problem: *"Fix the compiler write
// site, not the consumer."* Its invariant does NOT cover filters, which is why
// K90/K91 could not simply be closed against it and why the population had to
// be measured here rather than inherited.
//
// MEASURED, and the answer is the same. Each type has exactly ONE construction
// site in the compiler, and both are unconditionally non-nil:
//
//	compiler_firewall.go   filter := &FirewallFilter{Name: filterInst.name}
//	                       dest[filter.Name] = filter
//	compiler_firewall.go   term := &FirewallFilterTerm{...}
//	                       filter.Terms = append(filter.Terms, term)
//
// And the compiler is the only producer: no `*Config` is ever deserialized —
// `SyncApply` ships TEXT and persistence decodes a `*ConfigTree` — so a nil
// filter cannot enter from the HA or tolerant-load paths either. That is #6780's
// argument, checked against these types rather than assumed to transfer.
//
// So K90 and K91 are INVALID, and the ~12 existing `filter == nil` /
// `term == nil` guards scattered through pkg/config, pkg/routing, pkg/daemon and
// pkg/grpcapi are dead. This test is the standing form of that measurement, so
// the next finding of this shape is decidable by pointing at it instead of
// re-deriving it — which is the only reason a refutation is worth code.

// countNilFilterSlots returns the number of present-but-nil filter and term
// slots in a compiled config.
func countNilFilterSlots(cfg *Config) (nilFilter, nilTerm int, detail []string) {
	if cfg == nil {
		return 0, 0, nil
	}
	for family, filters := range map[string]map[string]*FirewallFilter{
		"inet":  cfg.Firewall.FiltersInet,
		"inet6": cfg.Firewall.FiltersInet6,
	} {
		for name, filter := range filters {
			if filter == nil {
				nilFilter++
				detail = append(detail, fmt.Sprintf("%s filter %q is a nil slot", family, name))
				continue
			}
			for i, term := range filter.Terms {
				if term == nil {
					nilTerm++
					detail = append(detail,
						fmt.Sprintf("%s filter %q term index %d is a nil slot", family, name, i))
				}
			}
		}
	}
	return nilFilter, nilTerm, detail
}

// nilFilterCorpus is weighted toward filter shapes the TOLERANT path admits and
// the strict path rejects, because those are the only branches where a
// partially-built filter or term could plausibly be left behind. A corpus of
// well-formed filters would pass vacuously.
func nilFilterCorpus() map[string][]string {
	return map[string][]string{
		"well-formed": {
			"set firewall family inet filter f1 term t1 from protocol tcp",
			"set firewall family inet filter f1 term t1 then accept",
			"set firewall family inet6 filter f6 term t1 then discard",
		},
		// #4953: an unparseable tcp-flags expression is strict-rejected and
		// tolerant-admitted, and the term KEEPS its raw value. If any branch
		// left a half-built term behind, this is where.
		"unparseable-tcp-flags": {
			"set firewall family inet filter f1 term t1 from tcp-flags \"(syn|ack\"",
			"set firewall family inet filter f1 term t1 then accept",
		},
		// A dangling prefix-list reference: strict rejects (#2506), tolerant
		// admits with the reference unresolved.
		"dangling-prefix-list": {
			"set firewall family inet filter f1 term t1 from source-prefix-list nope",
			"set firewall family inet filter f1 term t1 then discard",
		},
		// A term with a match and NO action — the actionless shape that has
		// produced real findings elsewhere in this review.
		"actionless-term": {
			"set firewall family inet filter f1 term t1 from protocol udp",
		},
		// A malformed port value on an otherwise valid term.
		"malformed-port": {
			"set firewall family inet filter f1 term t1 from destination-port abc",
			"set firewall family inet filter f1 term t1 then accept",
		},
		// Same filter name declared in BOTH families — the last-writer-wins /
		// dual-destination branch in compiler_firewall.go.
		"dual-family-same-name": {
			"set firewall family inet filter shared term t1 then accept",
			"set firewall family inet6 filter shared term t1 then discard",
		},
	}
}

func TestCompilerNeverEmitsNilFilterSlots_8597(t *testing.T) {
	for name, lines := range nilFilterCorpus() {
		t.Run(name, func(t *testing.T) {
			tree := buildTree(t, lines)
			compiled := 0
			sawFilter := false
			for _, mode := range []struct {
				name string
				fn   func(*ConfigTree) (*Config, error)
			}{
				{"strict", CompileConfig},
				{"lenient", CompileConfigLenient},
			} {
				cfg, err := mode.fn(tree)
				if err != nil || cfg == nil {
					// A rejected config emits nothing, so it cannot carry a nil
					// slot. The tolerant path must still compile (#1960).
					continue
				}
				compiled++
				if len(cfg.Firewall.FiltersInet)+len(cfg.Firewall.FiltersInet6) > 0 {
					sawFilter = true
				}
				nilFilter, nilTerm, detail := countNilFilterSlots(cfg)
				if nilFilter+nilTerm > 0 {
					t.Errorf("%s compile emitted present-but-nil filter slots "+
						"(filters=%d terms=%d): %v\n"+
						"Fix the compiler write site, not the consumer — adding another "+
						"`if filter == nil` at a reader is what #6780 exists to stop.",
						mode.name, nilFilter, nilTerm, detail)
				}
			}
			if compiled == 0 {
				t.Fatalf("neither the strict nor the tolerant path compiled %q, so this "+
					"corpus entry asserted nothing", name)
			}
			// Non-vacuity, per entry: a corpus entry that produced NO filters at
			// all would report zero nils for free.
			if !sawFilter {
				t.Fatalf("%q compiled but produced no filters, so the nil scan had nothing "+
					"to walk and its zero is not evidence", name)
			}
		})
	}
}

// TestNilFilterSlotCounterDetectsInjectedNils_8597 is the control on the
// INSTRUMENT. Without it, "zero nil slots" is equally explained by a counter
// that cannot see one — which is the failure a census is least able to notice
// about itself.
func TestNilFilterSlotCounterDetectsInjectedNils_8597(t *testing.T) {
	cfg := &Config{}
	cfg.Firewall.FiltersInet = map[string]*FirewallFilter{
		"nilslot": nil,
		"real":    {Name: "real", Terms: []*FirewallFilterTerm{nil, {Name: "t"}}},
	}
	nilFilter, nilTerm, detail := countNilFilterSlots(cfg)
	if nilFilter != 1 {
		t.Errorf("counter saw %d nil filters, want 1 (%v)", nilFilter, detail)
	}
	if nilTerm != 1 {
		t.Errorf("counter saw %d nil terms, want 1 (%v)", nilTerm, detail)
	}
	// And it must NOT invent nils on a clean config, or every corpus entry above
	// would fail for the wrong reason.
	clean := &Config{}
	clean.Firewall.FiltersInet = map[string]*FirewallFilter{
		"real": {Name: "real", Terms: []*FirewallFilterTerm{{Name: "t"}}},
	}
	if f, tm, d := countNilFilterSlots(clean); f+tm != 0 {
		t.Errorf("counter reported %d/%d nils on a clean config: %v", f, tm, d)
	}
}
