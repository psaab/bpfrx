package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestCLIResolvesThroughTheSharedEvaluator_5561 binds the SHARING that #5561
// relies on, which its namesake in pkg/authz does not.
//
// TestResolveClassPermissionsIsSharedWithTheCLI_5561 calls
// config.ResolveClassPermissions directly and never enters pkg/cli at all, so
// it pins the shared helper's BEHAVIOUR while proving nothing about the CLI
// using it. Swap CLI.resolveClassPerms back to a duplicated evaluator and that
// test stays green — the name claims a factoring the assertions never touch.
//
// This one drives the CLI's own store-bound adapter and requires it to agree
// with the shared function for the same class and config. The #5561 gate's
// whole premise is that `curl` and the CLI cannot answer differently; if the
// CLI stops going through the shared evaluator, that premise fails silently.
//
// Custom classes carry the assertion, deliberately. A duplicated evaluator that
// only knew the four BUILT-IN classes would agree on every built-in and diverge
// exactly on the config-defined ones — which is the shape the #4304 fallback
// exists for, and the shape a built-ins-only fixture cannot see.
func TestCLIResolvesThroughTheSharedEvaluator_5561(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure(): %v", err)
	}
	sets := []string{
		"set system login class noc-admin permissions all",
		"set system login class viewer-plus permissions [ view clear ]",
		"set system login class nothing-at-all permissions view",
	}
	if _, err := store.LoadSet(strings.Join(sets, "\n")); err != nil {
		t.Fatalf("LoadSet(): %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit(): %v", err)
	}
	cfg := store.ActiveConfig()
	if cfg == nil {
		t.Fatal("no active config after commit")
	}

	// Built-ins AND config-defined classes AND an unknown one: the CLI's adapter
	// must return exactly what the shared evaluator returns for each.
	for _, class := range []string{
		"super-user", "operator", "read-only", "config-viewer", "unauthorized",
		"noc-admin", "viewer-plus", "nothing-at-all", "no-such-class",
	} {
		c := &CLI{store: store, userClass: class}
		gotPerms, gotKnown := c.resolveClassPerms(class)
		wantPerms, wantKnown := config.ResolveClassPermissions(cfg, class)

		if gotKnown != wantKnown {
			t.Errorf("class %q: CLI known=%v, shared evaluator known=%v — the CLI is not "+
				"resolving through config.ResolveClassPermissions, so `curl` and the CLI "+
				"can disagree about what a class may do", class, gotKnown, wantKnown)
			continue
		}
		if !samePerms(gotPerms, wantPerms) {
			t.Errorf("class %q: CLI resolved %v, shared evaluator resolved %v — same class, "+
				"same config, two answers", class, gotPerms, wantPerms)
		}
	}
}

// samePerms compares two permission sets as sets, since neither side promises
// an order.
func samePerms(a, b []config.LoginClassPermission) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[config.LoginClassPermission]int, len(a))
	for _, p := range a {
		seen[p]++
	}
	for _, p := range b {
		seen[p]--
		if seen[p] < 0 {
			return false
		}
	}
	return true
}
