package config

import "testing"

// #5250 (A3-b3 F-03). expandAppSet dereferenced its *ApplicationsConfig without
// a nil check (apps.ApplicationSets, and memberIsNestedSet's two derefs one
// level down), so ExpandApplicationSet(name, nil) panicked. No production
// caller passes nil today — every one passes &cfg.Applications, the address of
// a struct field — so this is defensive hardening in the shape of the #5179 /
// #5671 present-but-nil VALUE guards beside it, and it goes RED with a panic,
// not a wrong answer, if the guard is removed.
func TestExpandApplicationSetNilConfigDoesNotPanic(t *testing.T) {
	// A predefined bundle needs no user config at all, so a nil
	// ApplicationsConfig must still expand it rather than erroring.
	const predefined = "junos-cifs"
	if _, ok := PredefinedApplicationSets[predefined]; !ok {
		t.Fatalf("fixture assumes %q is a predefined application-set", predefined)
	}
	got, err := ExpandApplicationSet(predefined, nil)
	if err != nil {
		t.Fatalf("ExpandApplicationSet(%q, nil) error = %v, want the predefined expansion", predefined, err)
	}
	if len(got) == 0 {
		t.Fatalf("ExpandApplicationSet(%q, nil) expanded to nothing", predefined)
	}

	// An unknown name is still a deterministic not-found error, not a panic.
	if _, err := ExpandApplicationSet("no-such-set-anywhere", nil); err == nil {
		t.Error("ExpandApplicationSet on an unknown name with a nil config must error")
	}
}
