package config

import (
	"strings"
	"testing"
)

// #8992: a fully elided stanza could not be deleted, and the error named the
// wrong thing -- `container "system" does not exist` while `show
// configuration` renders `system master-password ...` on screen.
//
// The five spellings are asserted together because FOUR OF THEM ARE CONTROLS,
// and each rules out a different wrong explanation:
//
//	fully braced      already worked -- so this is not "delete is broken"
//	child elided      already worked -- so this is not "elision breaks delete"
//	FULLY elided      the defect
//	elided + sibling  a braced `system` beside the elided one; the descent
//	                  SUCCEEDS into the sibling and fails deeper, so the error
//	                  changes to `no node matching "master-password"` and the
//	                  elided node is never examined. Without this row the fix
//	                  could be placed in the not-found branch and still miss it.
//	genuinely absent  gives a DIFFERENT message, so the defect is not the
//	                  generic not-found path
//
// The fixture uses `pseudorandom-function`, which is what `master-password`
// actually declares. An earlier version of this probe used `ascii-text`, which
// it does not -- so the schema walk stopped at an unknown token, the helper
// returned false for the wrong reason, and the fix read as not working. A
// synthetic config that is not a config measures the fixture.

func delete8992(t *testing.T, text string) (*ConfigTree, error) {
	t.Helper()
	root, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture does not parse: %v", perrs)
	}
	tr := &ConfigTree{Children: root.Children}
	return tr, tr.DeletePathGrouped([]string{"system", "master-password"}, nil)
}

func render8992(tr *ConfigTree) string {
	var out []string
	var walk func(n *Node)
	walk = func(n *Node) {
		out = append(out, strings.Join(n.Keys, " "))
		for _, c := range n.Children {
			walk(c)
		}
	}
	for _, c := range tr.Children {
		walk(c)
	}
	return strings.Join(out, " | ")
}

func TestElidedStanzaIsDeletable8992(t *testing.T) {
	for _, tc := range []struct {
		name, text  string
		wantErr     bool
		wantMPGone  bool
		wantSibling bool // a `host-name` in the fixture must survive
		hasSibling  bool
	}{
		{"CONTROL fully braced", `system { master-password { pseudorandom-function hmac-sha2-256; } host-name fw1; }`,
			false, true, true, true},
		{"CONTROL child elided", `system { master-password pseudorandom-function hmac-sha2-256; host-name fw1; }`,
			false, true, true, true},
		{"fully elided (#8992)", `system master-password pseudorandom-function hmac-sha2-256;`,
			false, true, false, false},
		{"elided beside a braced sibling", "system master-password pseudorandom-function hmac-sha2-256;\nsystem { host-name fw1; }",
			false, true, true, true},
		{"CONTROL genuinely absent", `system { host-name fw1; }`,
			true, true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr, err := delete8992(t, tc.text)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v, wantErr=%v", err, tc.wantErr)
			}
			got := render8992(tr)
			if strings.Contains(got, "master-password") == tc.wantMPGone {
				t.Errorf("master-password removed=%v, want removed=%v\ntree: %q",
					!strings.Contains(got, "master-password"), tc.wantMPGone, got)
			}
			if tc.hasSibling && strings.Contains(got, "host-name") != tc.wantSibling {
				t.Errorf("SIBLING LOST. host-name kept=%v, want %v\ntree: %q\n"+
					"Deleting one statement must never take a neighbour with it (#3846).",
					strings.Contains(got, "host-name"), tc.wantSibling, got)
			}
		})
	}
}

// TestElidedPackedRunIsRefusedNotDeleted8992 is the SAFETY half, and it is the
// reason the fix is bounded rather than general.
//
// A node's Keys can carry a packed RUN of several statements. Removing the
// whole node to satisfy a delete of ONE of them would silently take the others
// -- the #3846 config-integrity fail-wide. Splitting the run is
// `consumeNodeKeys` work that #8932 records as unfinished, so the run is
// REFUSED, and the message says which situation it is rather than falling
// through to "container does not exist" (the #9006 misdirecting-diagnostic
// shape).
func TestElidedPackedRunIsRefusedNotDeleted8992(t *testing.T) {
	tr, err := delete8992(t, `system master-password pseudorandom-function hmac-sha2-256 host-name fw1;`)
	if err == nil {
		t.Fatal("a packed run carrying TWO statements was DELETED. Removing the node " +
			"takes `host-name` with it, which is the #3846 fail-wide this bound exists " +
			"to prevent.")
	}
	got := render8992(tr)
	if !strings.Contains(got, "host-name") || !strings.Contains(got, "master-password") {
		t.Errorf("the refused run was modified anyway: %q", got)
	}
	for _, want := range []string{"ELIDED", "packed together", "would remove them too"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not explain itself (missing %q): %v\n"+
				"A message naming the wrong cause sends the operator to re-check a "+
				"spelling that is correct and on screen.", want, err)
		}
	}
}
