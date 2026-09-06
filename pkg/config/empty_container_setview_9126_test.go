package config

import (
	"strings"
	"testing"
)

// #9126: `show | display set` emitted a bare `deactivate <path>` with no
// preceding `set` for an empty inactive container, and dropped an empty ACTIVE
// container entirely.
//
// A non-leaf node recursed into its children and emitted no line of its own, so
// a container with NO children produced nothing — then the deactivate was
// emitted unconditionally. Replaying that output hits
// `setInactiveAtPath -> container %q does not exist`, and LoadSet/LoadMerge are
// ATOMIC, so one such line aborts the whole restore. It fails loudly and closed
// — nothing is silently mis-restored — but it costs the transaction, which on a
// restore path is an availability cost.
//
// THE TWO VIEWS DISAGREED, which is the framing that makes this a defect rather
// than a formatting preference: `show configuration` rendered
// `chassis { cluster { } }` for the same tree that `display set` rendered as
// nothing. Only one of them can be right about what the tree contains.
func TestEmptyContainerRoundTripsThroughSetView9126(t *testing.T) {
	for _, tc := range []struct {
		name     string
		inactive bool
		want     []string
	}{
		{
			name: "empty ACTIVE container",
			want: []string{"set protocols ospf area 0.0.0.0"},
		},
		{
			// The reported defect: without the `set` line this is a bare
			// `deactivate` that no replay can apply.
			name:     "empty INACTIVE container",
			inactive: true,
			want: []string{
				"set protocols ospf area 0.0.0.0",
				"deactivate protocols ospf area 0.0.0.0",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := &ConfigTree{}
			p, err := ParseSetCommand("set protocols ospf area 0.0.0.0")
			if err != nil {
				t.Fatal(err)
			}
			if err := tr.SetPath(p); err != nil {
				t.Fatal(err)
			}
			var target *Node
			var walk func([]*Node)
			walk = func(ns []*Node) {
				for _, n := range ns {
					if len(n.Keys) > 0 && n.Keys[0] == "area" {
						target = n
						return
					}
					walk(n.Children)
				}
			}
			walk(tr.Children)
			if target == nil {
				t.Fatal("fixture: no `area` node")
			}
			target.Children = nil
			target.IsLeaf = false
			target.Inactive = tc.inactive

			got := strings.Split(strings.TrimSpace(tr.FormatSet()), "\n")
			if len(got) != len(tc.want) {
				t.Fatalf("display set produced %d line(s), want %d:\n  got  %q\n  want %q",
					len(got), len(tc.want), got, tc.want)
			}
			for i := range got {
				if strings.TrimSpace(got[i]) != tc.want[i] {
					t.Errorf("line %d = %q, want %q", i, got[i], tc.want[i])
				}
			}

			// THE POINT OF THE FIX: the output must REPLAY. A `deactivate` with
			// no preceding `set` is what aborts a whole `load set`.
			replayed := &ConfigTree{}
			for _, line := range got {
				line = strings.TrimSpace(line)
				switch {
				case strings.HasPrefix(line, "set "):
					pp, err := ParseSetCommand(line)
					if err != nil {
						t.Fatalf("replay ParseSetCommand(%q): %v", line, err)
					}
					if err := replayed.SetPath(pp); err != nil {
						t.Fatalf("replay SetPath(%q): %v", line, err)
					}
				case strings.HasPrefix(line, "deactivate "):
					path := strings.Fields(strings.TrimPrefix(line, "deactivate "))
					if err := replayed.DeactivatePath(path); err != nil {
						t.Fatalf("replay DeactivatePath(%v): %v — this is the #9126 failure, "+
							"and LoadSet being atomic means it aborts the WHOLE restore", path, err)
					}
				}
			}
			if got, want := strings.TrimSpace(replayed.FormatSet()), strings.TrimSpace(tr.FormatSet()); got != want {
				t.Errorf("round trip is lossy:\n  original %q\n  replayed %q", want, got)
			}
		})
	}
}
