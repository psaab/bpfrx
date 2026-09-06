package config

import "testing"

// TestFlagSetAtPathSeesEverySpelling8997 is the reader's own cell. The table is
// the one measured on #8997, plus the two controls that make a `true` and a
// `false` mean something.
func TestFlagSetAtPathSeesEverySpelling8997(t *testing.T) {
	path := []string{"chassis", "cluster", "strict-session-auth"}
	for _, tc := range []struct {
		name string
		text string
		want bool
	}{
		{"fully braced", `chassis { cluster { strict-session-auth; } }`, true},
		{"cluster brace elided", `chassis { cluster strict-session-auth; }`, true},
		{"fully packed", `chassis cluster strict-session-auth;`, true},

		// A packed RUN carrying the flag alongside another statement. The flag
		// is present; a reader that required the Keys to END at the path would
		// miss it.
		{"packed run, flag first", `chassis cluster strict-session-auth control-link-recovery;`, true},

		// NEGATIVE CONTROLS. Without these a reader that returned true
		// unconditionally would pass every row above.
		{"absent entirely", `chassis { cluster { control-link-recovery; } }`, false},
		{"absent, empty tree", ``, false},
		{"wrong container", `chassis { redundancy-group 0 { strict-session-auth; } }`, false},
		{"prefix only, flag missing", `chassis cluster;`, false},

		// The flag name appearing as another leaf's VALUE must not read as the
		// flag being set. This is the row that makes the packed-run acceptance
		// above safe rather than merely permissive.
		{"appears as another leaf's value", `chassis { cluster { control-link-recovery strict-session-auth; } }`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var tr *ConfigTree
			if tc.text == "" {
				tr = &ConfigTree{}
			} else {
				root, perrs := NewParser(tc.text).Parse()
				if len(perrs) > 0 {
					t.Fatalf("parse: %v", perrs)
				}
				tr = &ConfigTree{Children: root.Children}
			}
			if got := tr.FlagSetAtPath(path); got != tc.want {
				t.Errorf("FlagSetAtPath(%v) = %v, want %v\n  text: %s", path, got, tc.want, tc.text)
			}
		})
	}
}

// TestFlagSetAtPathIgnoresInactive8997 pins that the reader answers "would the
// compiler see this", not "does the text contain it". An `inactive:` statement
// is stripped before compile, so defending it would defend a posture the
// operator deactivated.
func TestFlagSetAtPathIgnoresInactive8997(t *testing.T) {
	path := []string{"chassis", "cluster", "strict-session-auth"}
	root, perrs := NewParser(`chassis { cluster { strict-session-auth; } }`).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	tr := &ConfigTree{Children: root.Children}
	if !tr.FlagSetAtPath(path) {
		t.Fatal("control failed: the ACTIVE flag must read as set, or the inactive arm below proves nothing")
	}
	// Deactivate the leaf itself.
	tr.Children[0].Children[0].Children[0].Inactive = true
	if tr.FlagSetAtPath(path) {
		t.Error("an inactive leaf read as SET — the compiler strips it, so the posture is off")
	}
	// And deactivating an ANCESTOR must have the same effect.
	tr.Children[0].Children[0].Children[0].Inactive = false
	tr.Children[0].Children[0].Inactive = true
	if tr.FlagSetAtPath(path) {
		t.Error("a leaf under an inactive ANCESTOR read as SET")
	}
}

// TestFlagSetAtPathNilReceiver8997 pins the nil case the #7441 hook depends on:
// a node with nothing committed has no posture to defend.
func TestFlagSetAtPathNilReceiver8997(t *testing.T) {
	var tr *ConfigTree
	if tr.FlagSetAtPath([]string{"chassis", "cluster", "strict-session-auth"}) {
		t.Error("a nil tree reported the flag as set")
	}
	if (&ConfigTree{}).FlagSetAtPath(nil) {
		t.Error("an empty path reported true")
	}
}
