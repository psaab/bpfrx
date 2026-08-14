package config

import (
	"fmt"
	"reflect"
	"sort"
	"testing"
)

// #6812 round 10: the axis sweep, CLOSED OVER THE STRUCT RATHER THAN OVER A
// LIST OF CALLS. Twin of pkg/dataplane/userspace/nat_source_axis_sweep_6812_test.go;
// a test helper cannot be shared across packages without exporting it from
// production, and the two fixtures sweep different types anyway.
//
// Round 9 asked the anti-coincidence question "of every axis, in both
// directions" — but through a hand-written sequence of helper calls, so a
// column nobody remembered to sweep was still silently unguarded. Round 9's own
// sentence about round 8 ("the answer was a list, and a list is exactly what
// failed") applied to round 9 too: it moved the list up one level, from axis
// names to helper calls, rather than removing it. On this side the four calls
// covered Rule.Name, Then.PoolName, Match.SourceAddress and the pool's first
// member — and nothing else, including the pool's CARDINALITY and PORT RANGE,
// both of which were identical for every pool so a sort keyed on either was a
// no-op here and not in general.
//
// So the sweep walks the STRUCT. collectAxisKeys6812 reflects over every field
// of the value a comparator would read, recursing into nested structs and
// pointers, and emits one column per field plus a `.len` column per slice or
// map. A field added to NATRule, NATMatch, NATThen or NATPool later joins the
// sweep with no edit here; a field whose type has no order-preserving encoding
// hard-FAILS rather than being skipped. That is closure at FIELD granularity,
// by construction.
//
// WHAT IT IS STILL NOT CLOSED OVER: keys DERIVED from fields by arithmetic. A
// comparator may key on the port-range width, on a computed budget charge, or
// on a prefix length — none of which is a field, and no reflective walk can
// enumerate the functions someone might write. Field-level closure does not
// imply derived-key coverage: every pool member can differ (column varies)
// while every pool has exactly one member (len constant). Two mitigations:
// `.len` of every slice is swept mechanically, and the remaining derived keys
// are declared as FIELDS OF A WRAPPER STRUCT that the sweep then treats like
// any other column. That wrapper's field list is a list — it is the only one
// left, it is in one place, and it is visible.
//
// And the exemption round 9 got wrong. Round 9 skipped a CONSTANT column
// silently, arguing that a stable sort keyed on a value identical for every
// element cannot permute anything. Sound only when the column is invariant for
// every PRODUCTION input; fixture-only constancy is a blind spot, not a
// non-axis. A constant column is therefore no longer skipped — it must be
// REGISTERED, and the registration records which of the two it is.

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
	// green here. Recording it is not closing it; it is the difference between
	// a hole that is known and one that is not.
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
// non-monotone. The walk sorts rule-sets STABLY by scope tier and then walks
// each rule-set's rules in order, so a tiebreak permutes only within one tier
// and a rule sort only within one rule-set: the property has to hold per group.
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
			// The first element is what a lexicographic sort of the slice reads
			// first. An EMPTY slice contributes no element column at all; the
			// `.len` registration is what records that the fixture leaves this
			// list unpopulated and every key derived from its CONTENTS is
			// therefore unguarded too.
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
// every group's slots emit, and requires every constant column to be
// registered.
func sweepAxes6812(t *testing.T, what string, groups []axisGroup6812, exempt map[string]axisExemption6812) {
	t.Helper()
	if len(groups) == 0 {
		t.Fatalf("axis sweep %s: no groups — a sweep over nothing certifies nothing", what)
	}
	// PASS 1: project every group into its columns. Classification is GLOBAL,
	// not per group: a column can be constant in one grouping and vary in
	// another, and that is a registered blind spot in the first and a guarded
	// axis in the second, not a defect.
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

// ruleAxisSlot6812 is what TestAggregateChargeOrderFollowsWithinRuleSetRuleOrder_6812
// sweeps: the rule the charge walk reads, the pool it resolves through
// Then.PoolName (a tiebreak can key on pool properties just as easily as on the
// rule's own), and the DERIVED keys neither struct carries as a field.
//
// This struct's field list is the one list left, and it is deliberately here
// rather than spread across call sites. Reflection closes the FIELD axis; it
// cannot close the space of functions of fields. `.len` of every slice is swept
// mechanically, so cardinality is covered; the port-range width and the
// allocator charge (members × width — what sourceNATAggregateReferencedCharges
// itself computes, so the most plausible derived tiebreak of all) are neither
// fields nor lengths, so they are spelled out.
type ruleAxisSlot6812 struct {
	Rule                *NATRule
	Pool                *NATPool
	DerivedPortWidth    int
	DerivedPortCapacity int
}

// walkRuleAxisExemptions6812 is the honest enumeration of what
// TestAggregateChargeOrderFollowsWithinRuleSetRuleOrder_6812 does NOT guard:
// columns a within-rule-set sort could key on that this fixture holds constant,
// so such a sort would be invisible here.
//
// Three of the twenty-nine are genuinely free — the walk itself has already
// filtered those variations out before the first charge, so there is nothing to
// discriminate. The other twenty-six are admitted blind spots.
var walkRuleAxisExemptions6812 = mergeAxisExemptions6812(
	productionConstantAxes6812(
		"sourceNATAggregateReferencedCharges SKIPS a nil rule, a rule with no pool "+
			"reference, and a pool name that resolves to nothing, all before it charges "+
			"anything — so within the charged sequence both pointers are non-nil by "+
			"construction, for every config, and a comparator cannot key on a variation "+
			"the walk removed.",
		"Rule.nil", "Pool.nil",
	),
	productionConstantAxes6812(
		"every rule reachable through cfg.Security.NAT.Source is produced by "+
			"compileNATSource, whose only write to this field is NATSource — and "+
			"NATSource is NATType's zero value, so an unwritten field carries it too. "+
			"The column is NATSource for every config the compiler can produce.",
		"Rule.Then.Type",
	),
	fixtureConstantAxes6812(
		"the fixture gives each rule ONE literal source prefix and no address-book "+
			"name, destination, port, protocol or application constraint, so these stay "+
			"at their zero value — and with them every key derived from those lists' "+
			"CONTENTS is unguarded too, not just the lengths. Production sets any of "+
			"them per rule.",
		"Rule.Match.SourceAddresses.len", "Rule.Match.SourceAddressName",
		"Rule.Match.SourceAddressNames.len", "Rule.Match.DestinationAddress",
		"Rule.Match.DestinationAddresses.len", "Rule.Match.DestinationAddressName",
		"Rule.Match.DestinationAddressNames.len", "Rule.Match.DestinationPort",
		"Rule.Match.DestinationPorts.len", "Rule.Match.InvalidDestinationPorts.len",
		"Rule.Match.ReversedDestinationPortRanges.len", "Rule.Match.Protocol",
		"Rule.Match.Protocols.len", "Rule.Match.Application", "Rule.Match.Applications.len",
	),
	fixtureConstantAxes6812(
		"every rule here is plain pool-mode source NAT: no `then source-nat interface` "+
			"and no `off` exemption. Both are per-rule settable in production.",
		"Rule.Then.Interface", "Rule.Then.Off",
	),
	fixtureConstantAxes6812(
		"pool fields this fixture never configures. Address/Port/PortRaw are the DNAT "+
			"compatibility scalars, PortRangeInvalidSpec is the #5457 rejected-range "+
			"marker (every range here is valid), and no pool is routing-instance-scoped, "+
			"port-overloaded, no-translation, persistent-NAT or deterministic-CGNAT. A "+
			"tiebreak keyed on any of them would reorder a config that sets it.",
		"Pool.Address", "Pool.Port", "Pool.PortRaw", "Pool.PortRangeInvalidSpec",
		"Pool.PortNoTranslation", "Pool.PortOverloadingFactor", "Pool.RoutingInstance",
		"Pool.PersistentNAT.nil", "Pool.Deterministic.nil",
	),
)
