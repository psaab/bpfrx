package config

import (
	"errors"
	"strings"
	"testing"
)

// #8997 extends #8992's elided delete to BARE FLAGS and to nodes below the top
// level. Both were bounds nobody could see: #8992 was written against a VALUED
// leaf, where the value makes the node's Keys strictly longer than the path, so
// `len(Keys) > len(path)` looked like a description of the elided shape rather
// than a restriction to valued leaves.
//
// The delete path is where a fail-WIDE is worse than the defect it fixes, so
// the packed-run refusal is asserted here too — widening the match must not
// widen the removal.
func TestElidedBareFlagDelete8997(t *testing.T) {
	path := []string{"chassis", "cluster", "strict-session-auth"}
	for _, tc := range []struct {
		name     string
		text     string
		wantErr  bool
		wantLeft string // FormatSet of the tree afterwards, when the delete succeeds
	}{
		// #9126 CORRECTED THESE EXPECTATIONS, and the correction is the
		// interesting part. `want ""` was asserting a property of the SET VIEW,
		// not of the tree: deleting the leaf leaves its now-empty ancestor
		// containers behind, and FormatSet used to render an empty container as
		// NOTHING, so they were invisible here.
		//
		// `show configuration` always showed them -- measured, before this test
		// was ever written:
		//
		//	before  chassis { cluster { strict-session-auth; } }
		//	delete  err=<nil>
		//	after   chassis { cluster { } }          <- the braced view
		//	after   ""                               <- the set view, pre-#9126
		//
		// So the two views DISAGREED and this cell recorded the one that was
		// hiding something. The leftover empty containers are a real,
		// pre-existing question -- deletePath does not prune an ancestor it
		// emptied -- and are filed separately; they are not this fix's doing
		// and not this cell's subject.
		{"fully packed", `chassis cluster strict-session-auth;`, false, ""},
		{"cluster brace elided", `chassis { cluster strict-session-auth; }`, false, "set chassis"},
		{"fully braced (control — worked before)", `chassis { cluster { strict-session-auth; } }`, false, "set chassis cluster"},

		// The flag elided BESIDE a sibling that must survive.
		{
			"elided beside a braced sibling",
			`chassis { cluster { cluster-id 22; } cluster strict-session-auth; }`,
			false,
			"set chassis cluster cluster-id 22",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, perrs := NewParser(tc.text).Parse()
			if len(perrs) > 0 {
				t.Fatalf("parse: %v", perrs)
			}
			tr := &ConfigTree{Children: root.Children}
			err := tr.DeletePath(path)
			if (err != nil) != tc.wantErr {
				t.Fatalf("DeletePath err = %v, wantErr %v", err, tc.wantErr)
			}
			if err != nil {
				return
			}
			if got := strings.TrimSpace(tr.FormatSet()); got != tc.wantLeft {
				t.Errorf("after delete, tree = %q, want %q", got, tc.wantLeft)
			}
		})
	}
}

// TestElidedBareFlagDeleteRefusesAPackedRun8997 is the fail-wide guard. The
// node carries TWO statements; removing it to satisfy a delete of one would
// silently take the other, which is #3846's shape and the exact thing #8992's
// bound exists to prevent. Widening the MATCH to bare flags must not widen the
// REMOVAL.
func TestElidedBareFlagDeleteRefusesAPackedRun8997(t *testing.T) {
	root, perrs := NewParser(`chassis cluster strict-session-auth control-link-recovery;`).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	tr := &ConfigTree{Children: root.Children}
	before := strings.TrimSpace(tr.FormatSet())

	err := tr.DeletePath([]string{"chassis", "cluster", "strict-session-auth"})
	if err == nil {
		t.Fatalf("deleting one statement out of a PACKED RUN succeeded; the tree is now %q "+
			"and the operator lost a statement they did not name", strings.TrimSpace(tr.FormatSet()))
	}
	if !errors.Is(err, ErrPathNotFound) {
		t.Errorf("refusal does not wrap ErrPathNotFound: %v", err)
	}
	// The message must NAME the situation — a generic "does not exist" sends
	// the operator to re-check a spelling that is correct and on screen.
	if !strings.Contains(err.Error(), "ELIDED spelling packed together") {
		t.Errorf("refusal does not explain the packed run: %v", err)
	}
	if got := strings.TrimSpace(tr.FormatSet()); got != before {
		t.Errorf("a REFUSED delete still modified the tree:\n before %q\n after  %q", before, got)
	}
}
