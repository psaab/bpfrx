package userspace

import (
	"fmt"
	"reflect"
	"sort"
	"testing"
)

// #6812 round 10: the axis sweep, CLOSED OVER THE STRUCT RATHER THAN OVER A
// LIST OF CALLS.
//
// Round 9 asked the anti-coincidence question "of every axis, in both
// directions" — but the axes were a hand-written sequence of helper calls, so a
// column nobody remembered to sweep was still silently unguarded. Round 9's own
// sentence about round 8 ("the answer was a list, and a list is exactly what
// failed") applied to round 9 too: it had moved the list up one level, from
// axis names to helper calls, not removed it.
//
// The concrete holes that closure at that level left open, all of them real:
//
//   - CounterID. The builder fixture called buildSourceNATSnapshots(cfg, nil),
//     so every emitted ID was zero while production supplies populated
//     FNV-derived IDs. A stable (tier, CounterID) tiebreak reorders production
//     and was invisible here.
//   - Pool cardinality and port capacity. Every pool had exactly one member and
//     the default 1024-65535 range, so a sort by len(PoolAddresses), by port
//     capacity, or by derived charge was a no-op on this fixture and not in
//     general.
//   - Anything else the author was not thinking about — which is the whole
//     failure mode, and the reason the answer cannot be another list.
//
// So the sweep walks the STRUCT. collectAxisKeys6812 reflects over every field
// of the value a comparator would read, recursing into nested structs and
// pointers, and emits one column per field plus a `.len` column per slice or
// map. A field added to SourceNATRuleSnapshot later joins the sweep with no
// edit here; a field whose type has no order-preserving encoding hard-FAILS
// rather than being skipped. That is closure at FIELD granularity, by
// construction.
//
// WHAT THIS IS STILL NOT CLOSED OVER, stated plainly rather than left for the
// next reviewer to find: keys DERIVED from fields by arithmetic. A comparator
// may key on (PortHigh-PortLow+1), on a computed budget charge, or on a prefix
// length — none of which is a field, and no reflective walk can enumerate the
// functions someone might write. Field-level closure does not imply derived-key
// coverage either: every pool member address can differ (column varies) while
// every pool has exactly one member (len constant). The two mitigations, both
// explicit:
//
//	(a) `.len` of every slice is swept mechanically, which covers the
//	    cardinality shape;
//	(b) the remaining derived keys a caller cares about are added as FIELDS OF A
//	    WRAPPER STRUCT that the sweep then treats like any other column. That
//	    wrapper's field list IS a list, and it is the only list left. It is one
//	    place, and it is visible.
//
// And the exemption round 9 got wrong. Round 9 skipped a CONSTANT column
// silently, on the argument that a stable sort keyed on a value identical for
// every element cannot permute anything. That argument is sound only when the
// column is invariant for every PRODUCTION input. Fixture-only constancy is not
// regression coverage — it is a blind spot. So a constant column is no longer
// skipped: it must be REGISTERED, and its registration records which of the two
// it is. An unregistered constant column fails; a registered column that turns
// out to vary everywhere fails as stale. The registries below are therefore the
// honest enumeration of what this fixture does not guard.

// axisExemption6812 records a column a fixture does not vary, and — the
// distinction round 10 turns on — whether it can vary in production at all.
type axisExemption6812 struct {
	// productionConstant is true ONLY when the column is invariant for every
	// input the production path can produce. A stable sort keyed on such a
	// column is a no-op everywhere, so there is genuinely nothing to be blind
	// to and the exemption costs no coverage.
	//
	// false records a real BLIND SPOT: the column varies in production but not
	// in this fixture, so a sort keyed on it would reorder production and stay
	// green here. Recording it is not the same as closing it; it is the
	// difference between a hole that is known and one that is not.
	productionConstant bool
	why                string
}

// fixtureConstantAxes6812 registers columns this fixture happens not to vary
// while production can. Each one is an admitted blind spot.
func fixtureConstantAxes6812(why string, cols ...string) map[string]axisExemption6812 {
	return newAxisExemptions6812(false, why, cols...)
}

// productionConstantAxes6812 registers columns that cannot vary for ANY
// production input, so exempting them costs nothing. Use it only where that is
// provable; the conservative direction is fixtureConstantAxes6812, which
// over-reports blindness rather than under-reporting it.
func productionConstantAxes6812(why string, cols ...string) map[string]axisExemption6812 {
	return newAxisExemptions6812(true, why, cols...)
}

func newAxisExemptions6812(production bool, why string, cols ...string) map[string]axisExemption6812 {
	out := make(map[string]axisExemption6812, len(cols))
	for _, c := range cols {
		out[c] = axisExemption6812{productionConstant: production, why: why}
	}
	return out
}

// mergeAxisExemptions6812 unions exemption tables, panicking on a duplicate
// column so one column cannot carry two contradictory classifications.
func mergeAxisExemptions6812(tables ...map[string]axisExemption6812) map[string]axisExemption6812 {
	out := map[string]axisExemption6812{}
	for _, tbl := range tables {
		for col, ex := range tbl {
			if prev, dup := out[col]; dup {
				panic(fmt.Sprintf("#6812 axis exemption %q registered twice (%q and %q)",
					col, prev.why, ex.why))
			}
			out[col] = ex
		}
	}
	return out
}

// axisGroup6812 is one sequence of declaration slots the sweep must find
// non-monotone. The production sorts under test are STABLE and keyed on the
// scope tier, so a tiebreak can only permute within one tier — and a
// within-block reorder can only permute within one rule-set. The property
// therefore has to hold per group, not over the whole emitted slice.
type axisGroup6812 struct {
	label string
	slots []any
}

const axisKeyMaxDepth6812 = 8

// collectAxisKeys6812 flattens v into every column a comparator could key on,
// calling add(column, key) once per column. The key encoding is chosen so that
// LEXICOGRAPHIC order of the key equals the field's NATURAL order — otherwise a
// numerically ascending column could read as non-monotone and the sweep would
// claim coverage it does not have.
func collectAxisKeys6812(t *testing.T, path string, v reflect.Value, depth int, add func(col, key string)) {
	t.Helper()
	if depth > axisKeyMaxDepth6812 {
		t.Fatalf("axis sweep: recursion past depth %d at %q — the sweep cannot enumerate a "+
			"cyclic or unexpectedly deep type, so it must not claim closure over it",
			axisKeyMaxDepth6812, path)
	}
	switch v.Kind() {
	case reflect.String:
		add(path, v.String())
	case reflect.Bool:
		if v.Bool() {
			add(path, "1")
		} else {
			add(path, "0")
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		add(path, fmt.Sprintf("%020d", v.Uint()))
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		// Offset binary: +2^63 maps the signed range onto the unsigned one
		// order-preservingly, so the zero-padded decimal sorts numerically
		// including negatives.
		add(path, fmt.Sprintf("%020d", uint64(v.Int())+1<<63))
	case reflect.Slice, reflect.Array, reflect.Map:
		add(path+".len", fmt.Sprintf("%020d", v.Len()))
		if v.Kind() != reflect.Map && v.Len() > 0 {
			// The first element is what a lexicographic sort of the slice
			// reads first. An EMPTY slice contributes no element column at
			// all; the `.len` registration is what records that the fixture
			// leaves this list unpopulated and every key derived from its
			// contents therefore unguarded.
			collectAxisKeys6812(t, path+"[0]", v.Index(0), depth+1, add)
		}
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			add(path+".nil", "1")
			return
		}
		add(path+".nil", "0")
		collectAxisKeys6812(t, path, v.Elem(), depth+1, add)
	case reflect.Struct:
		tp := v.Type()
		for i := 0; i < tp.NumField(); i++ {
			sub := tp.Field(i).Name
			if path != "" {
				sub = path + "." + sub
			}
			collectAxisKeys6812(t, sub, v.Field(i), depth+1, add)
		}
	default:
		t.Fatalf("axis sweep: field %q has kind %s, for which this sweep has no "+
			"ORDER-PRESERVING key encoding. Add one. Skipping it would drop a column "+
			"silently, which is the exact failure this sweep exists to prevent.",
			path, v.Kind())
	}
}

// sweepAxes6812 asserts the round-9 anti-coincidence property — declaration
// order is not sorted on this column, in EITHER direction — for every column
// every group's slots emit, and requires every constant column to be registered.
//
// `what` names the swept value in failure text; `exempt` is the honest record
// of what the fixture does not guard.
func sweepAxes6812(t *testing.T, what string, groups []axisGroup6812, exempt map[string]axisExemption6812) {
	t.Helper()
	if len(groups) == 0 {
		t.Fatalf("axis sweep %s: no groups — a sweep over nothing certifies nothing", what)
	}
	// PASS 1: project every group into its columns. Classification is GLOBAL,
	// not per group: a column can be constant in one grouping and vary in
	// another — Snapshot.FromInterface is empty for every zone-tier rule-set and
	// permuted across the interface-tier ones — and that is a registered blind
	// spot in the first group and a guarded axis in the second, not a defect.
	perGroup := make([]map[string][]string, len(groups))
	constantSomewhere := map[string]bool{}
	var unregistered []string
	for gi, g := range groups {
		if len(g.slots) < 3 {
			t.Fatalf("axis sweep %s / %s: %d slots; a sequence shorter than three is "+
				"ascending or descending by construction and cannot be de-correlated from "+
				"both sort directions", what, g.label, len(g.slots))
		}
		cols := map[string][]string{}
		for i, slot := range g.slots {
			seen := map[string]bool{}
			collectAxisKeys6812(t, "", reflect.ValueOf(slot), 0, func(col, key string) {
				if seen[col] {
					t.Fatalf("axis sweep %s / %s: column %q emitted twice for slot %d",
						what, g.label, col, i)
				}
				seen[col] = true
				// Back-fill slots that did not emit this column (a slice that
				// is empty in some slots and populated in others). "" sorts
				// below every encoded key, which keeps the comparison total.
				for len(cols[col]) < i {
					cols[col] = append(cols[col], "")
				}
				cols[col] = append(cols[col], key)
			})
		}
		for col, vals := range cols {
			for len(vals) < len(g.slots) {
				vals = append(vals, "")
			}
			cols[col] = vals
			if !axisIsConstant6812(vals) {
				continue
			}
			if _, registered := exempt[col]; !registered {
				unregistered = append(unregistered,
					fmt.Sprintf("%s in %s (constant %q)", col, g.label, vals[0]))
				continue
			}
			constantSomewhere[col] = true
		}
		perGroup[gi] = cols
	}
	var stale []string
	for col, ex := range exempt {
		if !constantSomewhere[col] {
			stale = append(stale, fmt.Sprintf("%s (registered %q)", col, ex.why))
		}
	}
	sort.Strings(unregistered)
	sort.Strings(stale)
	if len(unregistered) > 0 || len(stale) > 0 {
		t.Fatalf("axis sweep %s: the exemption table does not describe this fixture.\n"+
			"CONSTANT but unregistered (%d): %v\n"+
			"REGISTERED but constant in no group (%d): %v\n"+
			"A stable sort keyed on a constant column cannot permute anything HERE, so no "+
			"assertion in this fixture can see such a sort — but fixture-only constancy is "+
			"NOT regression coverage. If the column varies for any production input, a "+
			"tiebreak on it reorders production while this fixture stays green. Either VARY "+
			"the column, or register it with productionConstant set honestly: true only if "+
			"it cannot vary for ANY production input, false to record an admitted blind "+
			"spot. A stale entry means the field was renamed or removed, or the fixture now "+
			"varies it everywhere and it is guarded — delete it.",
			what, len(unregistered), unregistered, len(stale), stale)
	}

	// PASS 2: the round-9 property, on every column that actually varies in the
	// group — registered or not. A registered column is blind where it is
	// constant and must still be non-monotone where it moves.
	guarded := map[string]bool{}
	for gi, g := range groups {
		cols := perGroup[gi]
		names := make([]string, 0, len(cols))
		for col := range cols {
			names = append(names, col)
		}
		sort.Strings(names)
		for _, col := range names {
			if axisIsConstant6812(cols[col]) {
				continue
			}
			guarded[col] = true
			assertDeclarationOrderIsNotSortedBy6812(t,
				fmt.Sprintf("%s / %s / %s", what, g.label, col), cols[col])
		}
	}
	// Report the split rather than leaving it to be re-derived by whoever asks
	// next whether this fixture is closed. `go test -v` prints all three lists,
	// and the middle one is the answer to "what is still blind here".
	var guardedNames, blindNames, nonAxisNames []string
	for col := range guarded {
		guardedNames = append(guardedNames, col)
	}
	for col, ex := range exempt {
		if guarded[col] {
			continue
		}
		if ex.productionConstant {
			nonAxisNames = append(nonAxisNames, col)
			continue
		}
		blindNames = append(blindNames, col)
	}
	sort.Strings(guardedNames)
	sort.Strings(blindNames)
	sort.Strings(nonAxisNames)
	t.Logf("axis sweep %s: %d columns GUARDED in at least one group %v; %d FIXTURE-CONSTANT "+
		"and therefore unguarded %v; %d PRODUCTION-CONSTANT non-axes %v",
		what, len(guardedNames), guardedNames, len(blindNames), blindNames,
		len(nonAxisNames), nonAxisNames)
}

func axisIsConstant6812(vals []string) bool {
	for _, v := range vals {
		if v != vals[0] {
			return false
		}
	}
	return true
}

// snapshotAxisSlot6812 is what TestBuilderEmittedOrderIsStableWithinATier_6812
// sweeps: the emitted snapshot the production comparator reads, plus the
// DERIVED keys a comparator could compute from it that no reflective walk can
// enumerate.
//
// This struct's field list is the one list left, and it is deliberately here
// rather than spread across call sites. Reflection closes the FIELD axis; it
// cannot close the space of functions of fields. `.len` of every slice is swept
// mechanically, so cardinality is covered; port capacity is members × range
// width, which is neither a field nor a length, so it is spelled out.
type snapshotAxisSlot6812 struct {
	Snapshot            SourceNATRuleSnapshot
	DerivedPortCapacity int
}

// builderTierAxisExemptions6812 is the honest enumeration of what the builder
// fixture does NOT guard at the per-tier grouping: columns a (tier, X) tiebreak
// could key on that this fixture holds constant, so such a sort would be
// invisible here.
//
// Every entry is fixture-constant, not production-constant: no column of
// SourceNATRuleSnapshot is invariant for all production inputs, so there is
// nothing here that can be exempted for free. Round 9's silent skip treated
// this whole set as costless; it is not.
var builderTierAxisExemptions6812 = mergeAxisExemptions6812(
	fixtureConstantAxes6812(
		"the fixture's rule-sets carry a `from` clause only and no routing-instance "+
			"scope, so these stay empty for every slot. Production sets them and a "+
			"tiebreak keyed on one would reorder it.",
		"Snapshot.ToZone", "Snapshot.ToInterface",
		"Snapshot.FromRoutingInstance", "Snapshot.ToRoutingInstance",
	),
	fixtureConstantAxes6812(
		"constant only in the tier where that scope axis is unset — interface-tier "+
			"rule-sets carry no `from zone`, zone-tier ones no `from interface` — and "+
			"GUARDED in the other tier, which is why the entry is not stale. Production "+
			"can set both on one rule-set (the tier is the MIN of the two contexts), so "+
			"within a tier this remains a hole.",
		"Snapshot.FromZone", "Snapshot.FromInterface",
	),
	fixtureConstantAxes6812(
		"the fixture gives every rule exactly one match prefix and no destination, "+
			"port or application constraint, so these list lengths never move — and with "+
			"them every key derived from those lists' CONTENTS is unguarded too, not just "+
			"the lengths.",
		"Snapshot.SourceAddresses.len", "Snapshot.DestinationAddresses.len",
		"Snapshot.MatchDestinationPorts.len", "Snapshot.MatchApplications.len",
	),
	fixtureConstantAxes6812(
		"no interface-mode, no-NAT-off, persistent-NAT, address-persistent or "+
			"port-no-translation modifier is configured here, so each stays at its zero "+
			"value; all are per-rule-set settable in production.",
		"Snapshot.InterfaceMode", "Snapshot.Off", "Snapshot.PoolNoTranslation",
		"Snapshot.AddressPersistent", "Snapshot.PersistentNAT",
		"Snapshot.PersistentNATPermitAnyRemoteHost", "Snapshot.PersistentNATPermit",
		"Snapshot.PersistentNATInactivityTimeout",
	),
	fixtureConstantAxes6812(
		"every pool here is healthy and within budget, so the poison marker never "+
			"fires. A poisoned pool is precisely the state #6812 introduces, and a "+
			"tiebreak keyed on the marker would reorder such a config.",
		"Snapshot.PoolUnusable", "Snapshot.PoolUnusableReason",
	),
	fixtureConstantAxes6812(
		"no pool here is deterministic-CGNAT, so the whole #4559 block is zero.",
		"Snapshot.DeterministicMode", "Snapshot.DeterministicBlockSize",
		"Snapshot.DeterministicBlocksPerIP", "Snapshot.DeterministicHostBase",
		"Snapshot.DeterministicHostCount",
	),
)

// builderRuleSetAxisExemptions6812 is the same enumeration one nesting level
// in, for a reorder WITHIN one rule-set's block.
//
// The dominant hole is structural and worth naming: this fixture points every
// rule of a rule-set at the SAME pool, because assertions (1) and (2) identify
// a rule-set's block by PoolName. So no pool-derived within-set sort is caught
// here — not the pool name, not its members, not its port range, not the
// capacity derived from them. Junos lets each rule of a rule-set choose its own
// pool, so that is a real gap and not a non-axis.
var builderRuleSetAxisExemptions6812 = mergeAxisExemptions6812(
	fixtureConstantAxes6812(
		"one pool per rule-set here (assertions (1) and (2) key a rule-set's block on "+
			"PoolName), so every pool-derived column is constant within a block. Junos "+
			"allows a different pool per rule, so a within-set sort keyed on any of these "+
			"would reorder production and stay green here.",
		"Snapshot.PoolName", "Snapshot.PoolAddresses.len", "Snapshot.PoolAddresses[0]",
		"Snapshot.PortLow", "Snapshot.PortHigh", "DerivedPortCapacity",
		"Snapshot.PoolNoTranslation", "Snapshot.PoolUnusable", "Snapshot.PoolUnusableReason",
		"Snapshot.DeterministicMode", "Snapshot.DeterministicBlockSize",
		"Snapshot.DeterministicBlocksPerIP", "Snapshot.DeterministicHostBase",
		"Snapshot.DeterministicHostCount",
	),
	productionConstantAxes6812(
		"scope is a property of the RULE-SET: buildSourceNATSnapshotsWithFeeds stamps "+
			"all six from `rs` for every rule of that rule-set, so within one block they "+
			"are identical for EVERY config — not just this fixture. A within-block sort "+
			"keyed on any of them is a no-op in production too, so exempting them here "+
			"costs no coverage. (At the per-TIER grouping they are a different matter, "+
			"and that table records them honestly.)",
		"Snapshot.FromZone", "Snapshot.ToZone", "Snapshot.FromInterface",
		"Snapshot.ToInterface", "Snapshot.FromRoutingInstance", "Snapshot.ToRoutingInstance",
	),
	fixtureConstantAxes6812(
		"same list-shape and modifier gaps as the per-tier table, one level in.",
		"Snapshot.SourceAddresses.len", "Snapshot.DestinationAddresses.len",
		"Snapshot.MatchDestinationPorts.len", "Snapshot.MatchApplications.len",
		"Snapshot.InterfaceMode", "Snapshot.Off", "Snapshot.AddressPersistent",
		"Snapshot.PersistentNAT", "Snapshot.PersistentNATPermitAnyRemoteHost",
		"Snapshot.PersistentNATPermit", "Snapshot.PersistentNATInactivityTimeout",
	),
)
