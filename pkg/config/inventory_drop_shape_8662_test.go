package config

import "testing"

// #8662. The inventory records WHICH sites diverge; it did not record WHAT the
// compact spelling produced. That distinction is the normalizer's safety rule:
// truncating a folded tail is only safe when the tail reaches no reader, and
// "the compact spelling compiles to the same config as an EMPTY stanza" is that
// measurement. A site marked "partial" has something consuming part of the
// tail, so truncating it could remove a value that is currently read.
//
// It used to live in a scratch probe. Two lanes needing it would have built two
// instruments that can disagree; this is the one instrument.

func TestInventoryCarriesADropShapeForEverySite8662(t *testing.T) {
	sites, _ := readInventory(t)
	shapes := readInventoryShapes(t)
	if len(sites) == 0 {
		t.Fatal("inventory has no sites; this cell proves nothing")
	}
	var unmarked []string
	counts := map[string]int{}
	for _, s := range sites {
		shape, ok := shapes[s]
		if !ok {
			unmarked = append(unmarked, s)
			continue
		}
		switch shape {
		case "empty", "partial":
			counts[shape]++
		default:
			t.Errorf("site %q carries an unrecognised drop shape %q; a consumer that does not "+
				"understand it may read it as permission to normalize", s, shape)
		}
	}
	if len(unmarked) > 0 {
		t.Errorf("%d inventory sites carry no drop shape (e.g. %q). A missing shape is UNKNOWN, "+
			"not 'partial' and not 'empty' — regenerate the inventory rather than assuming",
			len(unmarked), unmarked[0])
	}
	// DEGENERACY CONTROL. A marker that were constant would satisfy every
	// assertion above and tell a widening lane nothing. Both values must occur,
	// or the classification is not discriminating.
	if counts["empty"] == 0 || counts["partial"] == 0 {
		t.Errorf("the drop shape is not discriminating: empty=%d partial=%d. If every site "+
			"has the same shape the marker carries no information and the safety rule it "+
			"exists to support cannot be checked", counts["empty"], counts["partial"])
	}
	t.Logf("#8662 drop shapes: empty=%d partial=%d", counts["empty"], counts["partial"])
}

// The shape must agree with the census that produced it. If the file and the
// live census disagree, the file is stale and a lane reading it is deciding on
// last week's measurement.
func TestInventoryDropShapeMatchesTheLiveCensus8662(t *testing.T) {
	res := runCompactBlockCensus(t)
	shapes := readInventoryShapes(t)
	mismatch := 0
	for site, want := range res.dropShape {
		got, ok := shapes[site]
		if !ok {
			continue // membership drift is the inventory gate's job, not this cell's
		}
		if got != want {
			mismatch++
			if mismatch <= 3 {
				t.Errorf("site %q: inventory says %q, the live census says %q — the file is "+
					"stale and the safety rule would be applied to the wrong measurement",
					site, got, want)
			}
		}
	}
	if len(res.dropShape) == 0 {
		t.Fatal("the census produced no drop shapes; this cell is blind")
	}
}

// The marker must not change what the gate compares. Membership is the gate's
// subject; the shape is metadata about a member.
func TestDropShapeMarkerDoesNotAffectMembership8662(t *testing.T) {
	for _, tc := range []struct{ line, site, shape string }{
		{"applications application\tempty", "applications application", "empty"},
		{"interfaces xpfname mtu\tpartial", "interfaces xpfname mtu", "partial"},
		{"a site with no marker", "a site with no marker", ""},
	} {
		site, shape := splitInventoryLine(tc.line)
		if site != tc.site || shape != tc.shape {
			t.Errorf("splitInventoryLine(%q) = (%q, %q), want (%q, %q)",
				tc.line, site, shape, tc.site, tc.shape)
		}
	}
}
