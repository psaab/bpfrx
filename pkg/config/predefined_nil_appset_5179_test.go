package config

import (
	"strings"
	"testing"
)

// TestExpandApplicationSetNilValueNoPanic is the #5179 RED-on-revert proof.
//
// A present-but-nil application-set map value (ApplicationSets["x"] == nil) is
// admitted by the tolerant-load / peer-sync path (#1960). Before the fix
// lookupApplicationSet returned (nil, true) for such a slot, and expandAppSet
// then ranged over as.Applications on a nil *ApplicationSet — a nil-deref
// panic. The fix skips the nil slot so a deterministic "not found" expansion
// error is returned instead. Reverting the guard turns each sub-test RED: the
// call panics (recovered here) and the test fails on "unexpected panic".
func TestExpandApplicationSetNilValueNoPanic(t *testing.T) {
	t.Run("direct nil set", func(t *testing.T) {
		apps := &ApplicationsConfig{
			Applications:    map[string]*Application{},
			ApplicationSets: map[string]*ApplicationSet{"nilset": nil},
		}
		got, err := mustNotPanicExpand(t, "nilset", apps)
		if err == nil {
			t.Fatalf("ExpandApplicationSet(nil set) = %v, want a deterministic error", got)
		}
		if !strings.Contains(err.Error(), "not found") {
			t.Fatalf("ExpandApplicationSet(nil set) error = %q, want a fail-closed not-found error", err)
		}
	})

	t.Run("nested member references nil set", func(t *testing.T) {
		apps := &ApplicationsConfig{
			Applications: map[string]*Application{},
			ApplicationSets: map[string]*ApplicationSet{
				"parent": {Name: "parent", Applications: []string{"nilset"}},
				"nilset": nil,
			},
		}
		got, err := mustNotPanicExpand(t, "parent", apps)
		if err == nil {
			t.Fatalf("ExpandApplicationSet(parent->nil member) = %v, want a deterministic error", got)
		}
	})
}

// mustNotPanicExpand calls ExpandApplicationSet and converts a panic into a
// hard test failure (the pre-fix behavior) rather than crashing the whole
// package test binary.
func mustNotPanicExpand(t *testing.T, name string, apps *ApplicationsConfig) (result []string, err error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("ExpandApplicationSet(%q) panicked (nil application-set value must fail closed, not panic): %v", name, r)
		}
	}()
	result, err = ExpandApplicationSet(name, apps)
	return result, err
}
