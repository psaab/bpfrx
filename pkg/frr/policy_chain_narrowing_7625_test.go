package frr

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #7625: `filterDefinedPolicies` returns the SURVIVING SUBSET of an authored
// policy chain, silently discarding any member that names a policy-statement
// which is not defined. That produces two materially different outcomes:
//
//	authored chain        after the drop   outcome
//	[undefined]           []               no attachment emitted -> PERMIT-ALL
//	[defined, undefined]  [defined]        attachment still emitted -> SILENT NARROWING
//
// The second is the more insidious, precisely because it is invisible: the
// neighbour still carries A filter, the session works, and `show route-map`
// shows a real, well-formed policy — it is simply not the policy the operator
// wrote. Nothing anywhere reports that a member of the authored chain was
// discarded.
//
// WHY THE EXISTING #6807 HELPER CANNOT SEE IT. `danglingRouteMapRefs6807`
// compares references emitted in the rendered section against definitions
// emitted in that same section. A NARROWED chain still references a route-map
// that really is defined, so the rendered section is perfectly self-consistent
// and the helper — correctly, for its own question — reports nothing. Detecting
// narrowing needs the AUTHORED chain, which the rendered text does not contain.
// `TestDanglingHelperIsBlindToNarrowing7625` proves that rather than asserting
// it.
//
// This detector is deliberately DECISION-INDEPENDENT. #7625 has an open
// behaviour choice (keep dropping / emit a bounded deny / split by direction),
// and its own text says whichever option is taken must cover BOTH shapes. This
// helper is what lets any of them be asserted; it changes no behaviour.

// chainDrop7625 records one attachment site where the resolved chain differs
// from the authored one.
type chainDrop7625 struct {
	Where    string
	Authored []string
	Kept     []string
	Dropped  []string
}

// Emptied reports the PERMIT-ALL shape: every authored member was discarded, so
// no attachment is emitted at all and FRR applies no filter in that direction.
// False means the SILENT-NARROWING shape — an attachment is still emitted, and
// it is not the one the operator wrote.
func (d chainDrop7625) Emptied() bool { return len(d.Kept) == 0 }

func (d chainDrop7625) String() string {
	shape := "narrowed"
	if d.Emptied() {
		shape = "emptied->permit-all"
	}
	return fmt.Sprintf("%s: authored=%v kept=%v dropped=%v (%s)",
		d.Where, d.Authored, d.Kept, d.Dropped, shape)
}

// droppedFrom7625 returns the authored names that filterDefinedPolicies would
// discard. It re-derives the drop rather than reaching into the production
// helper, so a change to that helper's contract shows up here as a difference
// rather than being mirrored silently.
func droppedFrom7625(authored []string, po *config.PolicyOptionsConfig) (kept, dropped []string) {
	for _, n := range authored {
		if n == "" {
			continue
		}
		if isDefinedPolicyStatement(n, po) {
			kept = append(kept, n)
		} else {
			dropped = append(dropped, n)
		}
	}
	return kept, dropped
}

// narrowedPolicyChains7625 walks every BGP policy-chain attachment site in the
// config and reports each one whose resolved chain differs from the authored
// chain. Sites with no authored chain, or whose chain survives intact, are not
// reported.
//
// Neighbour sites mirror bgpNeighborImportChain/bgpNeighborExportChain: a
// neighbour with ANY own entry suppresses the global default for that peer
// (#5277), so only its own list is examined; a neighbour with none inherits the
// global chain and is not a distinct site.
func narrowedPolicyChains7625(bgp *config.BGPConfig, po *config.PolicyOptionsConfig) []chainDrop7625 {
	var out []chainDrop7625
	add := func(where string, authored []string) {
		if len(authored) == 0 {
			return
		}
		kept, dropped := droppedFrom7625(authored, po)
		if len(dropped) == 0 {
			return
		}
		out = append(out, chainDrop7625{
			Where: where, Authored: authored, Kept: kept, Dropped: dropped,
		})
	}
	if bgp == nil {
		return nil
	}
	add("protocols bgp import", bgp.Import)
	add("protocols bgp export", bgp.Export)
	for _, n := range bgp.Neighbors {
		if n == nil {
			continue
		}
		if hasNonEmptyPolicy(n.Import) {
			add(fmt.Sprintf("neighbor %s import", n.Address), n.Import)
		}
		if hasNonEmptyPolicy(n.Export) {
			add(fmt.Sprintf("neighbor %s export", n.Address), n.Export)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Where < out[j].Where })
	return out
}

func definedPolicy7625(name string) *config.PolicyStatement {
	return &config.PolicyStatement{
		Name:  name,
		Terms: []*config.PolicyTerm{{Name: "t1", PrefixList: []string{"PL"}}},
	}
}

func policyOptions7625(defined ...string) *config.PolicyOptionsConfig {
	ps := map[string]*config.PolicyStatement{}
	for _, n := range defined {
		ps[n] = definedPolicy7625(n)
	}
	return &config.PolicyOptionsConfig{
		PolicyStatements: ps,
		PrefixLists:      map[string]*config.PrefixList{"PL": {Name: "PL", Prefixes: []string{"10.0.0.0/8"}}},
		Communities:      map[string]*config.CommunityDef{},
		ASPaths:          map[string]*config.ASPathDef{},
	}
}

// NEGATIVE CONTROL. A detector that reports nothing must mean the chains are
// intact, not that the walk found no sites — so this fixture has real chains
// and the assertion below requires the walk to have visited them.
func TestNarrowingDetectorIsSilentOnAnIntactConfig7625(t *testing.T) {
	po := policyOptions7625("A", "B")
	bgp := &config.BGPConfig{
		LocalAS: 65001, RouterID: "1.1.1.1",
		Import: []string{"A"},
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.2.1", PeerAS: 65002, FamilyInet: true, Import: []string{"A", "B"}, Export: []string{"B"}},
		},
	}
	if got := narrowedPolicyChains7625(bgp, po); len(got) != 0 {
		t.Fatalf("reported drops on an intact config: %v", got)
	}
	// Anti-vacuity: the walk must actually resolve those chains, or "no drops"
	// is the answer for a detector that looked at nothing.
	if kept, dropped := droppedFrom7625([]string{"A", "B"}, po); len(kept) != 2 || len(dropped) != 0 {
		t.Fatalf("the resolver did not see the defined chain: kept=%v dropped=%v", kept, dropped)
	}
}

// The two shapes, side by side. A single-shape test cannot show that they are
// DIFFERENT outcomes, which is the whole point of #7625's correction.
func TestNarrowingDetectorSeparatesEmptiedFromNarrowed7625(t *testing.T) {
	po := policyOptions7625("REAL")
	bgp := &config.BGPConfig{
		LocalAS: 65001, RouterID: "1.1.1.1",
		Neighbors: []*config.BGPNeighbor{
			// Shape 1: the only member is undefined -> chain empties -> permit-all.
			{Address: "10.0.2.1", PeerAS: 65002, FamilyInet: true, Import: []string{"GHOST"}},
			// Shape 2: one member survives -> attachment still emitted, but it is
			// not the authored policy. This is the shape nothing could see before.
			{Address: "10.0.2.2", PeerAS: 65003, FamilyInet: true, Import: []string{"REAL", "GHOST"}},
		},
	}
	got := narrowedPolicyChains7625(bgp, po)
	if len(got) != 2 {
		t.Fatalf("want 2 findings (one per shape), got %d: %v", len(got), got)
	}
	byWhere := map[string]chainDrop7625{}
	for _, d := range got {
		byWhere[d.Where] = d
	}

	emptied, ok := byWhere["neighbor 10.0.2.1 import"]
	if !ok {
		t.Fatalf("no finding for the emptied chain; got %v", got)
	}
	if !emptied.Emptied() {
		t.Errorf("a chain whose only member was dropped must report Emptied(): %v", emptied)
	}

	narrowed, ok := byWhere["neighbor 10.0.2.2 import"]
	if !ok {
		t.Fatalf("no finding for the narrowed chain; got %v", got)
	}
	if narrowed.Emptied() {
		t.Errorf("a chain that still emits an attachment must NOT report Emptied(): %v", narrowed)
	}
	if len(narrowed.Kept) != 1 || narrowed.Kept[0] != "REAL" {
		t.Errorf("narrowed chain kept %v, want [REAL]", narrowed.Kept)
	}
	if len(narrowed.Dropped) != 1 || narrowed.Dropped[0] != "GHOST" {
		t.Errorf("narrowed chain dropped %v, want [GHOST]", narrowed.Dropped)
	}
}

// The justification for this detector existing, PROVEN rather than asserted:
// the #6807 helper is blind to narrowing, because a narrowed chain leaves a
// rendered section that is internally consistent.
func TestDanglingHelperIsBlindToNarrowing7625(t *testing.T) {
	po := policyOptions7625("REAL")
	fc := &FullConfig{
		PolicyOptions: po,
		BGP: &config.BGPConfig{
			LocalAS: 65001, RouterID: "1.1.1.1",
			Neighbors: []*config.BGPNeighbor{
				{Address: "10.0.2.2", PeerAS: 65003, FamilyInet: true, Import: []string{"REAL", "GHOST"}},
			},
		},
	}
	section := New().buildManagedSection(fc)

	// The rendered section is self-consistent: no reference dangles.
	if dangling := danglingRouteMapRefs6807(section); len(dangling) != 0 {
		t.Fatalf("precondition failed — the narrowed render is supposed to be "+
			"internally consistent, but #6807's helper found %v. If this fires, "+
			"the renderer changed and this test's premise no longer holds", dangling)
	}
	// ...and yet an authored member was silently discarded.
	drops := narrowedPolicyChains7625(fc.BGP, po)
	if len(drops) != 1 || drops[0].Emptied() {
		t.Fatalf("the narrowing detector must report exactly one non-emptied "+
			"finding here; got %v", drops)
	}
	if !strings.Contains(drops[0].String(), "GHOST") {
		t.Errorf("the finding does not name the discarded policy: %v", drops[0])
	}
	t.Logf("#6807 helper: clean. #7625 detector: %v", drops[0])
}
