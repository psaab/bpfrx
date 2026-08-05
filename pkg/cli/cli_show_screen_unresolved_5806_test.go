package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// danglingScreenRefStore reaches the #5806 state through the genuine TOLERANT
// LOAD path: strict commit REJECTS a zone whose screen profile is undefined, so
// a valid config is committed, the persisted active.json is externally modified
// so the profile DEFINITION no longer parses (the `ids-option` path token occurs
// exactly once and is renamed) while the zone's REFERENCE survives, and a fresh
// store re-Loads it. Mirrors the pkg/api fixture; see that file for the full
// rationale.
func danglingScreenRefStore(t *testing.T) *configstore.Store {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "xpf.conf")
	store, err := configstore.New(path)
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride(`
interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.1.10/24; } } } }
security {
    screen { ids-option alpha { icmp { ping-death; } } }
    zones { security-zone trust { screen alpha; interfaces { ge-0/0/0.0; } } }
}
`); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	dbPath := filepath.Join(dir, ".configdb", "active.json")
	rawBytes, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatalf("read persisted db: %v", err)
	}
	raw := string(rawBytes)
	if n := strings.Count(raw, "ids-option"); n != 1 {
		t.Fatalf("fixture assumption broken: %q occurs %d times, want 1", "ids-option", n)
	}
	mutated := strings.Replace(raw, "ids-option", "ids-optionz", 1)
	if err := os.WriteFile(dbPath, []byte(mutated), 0o644); err != nil {
		t.Fatalf("write mutated db: %v", err)
	}
	reloaded, err := configstore.New(path)
	if err != nil {
		t.Fatalf("configstore.New (reload): %v", err)
	}
	if err := reloaded.Load(); err != nil {
		t.Fatalf("tolerant Load: %v", err)
	}
	if reloaded.ActiveConfig() == nil {
		t.Fatal("tolerant Load produced a nil active config")
	}
	return reloaded
}

// TestShowScreenLocalCLIReportsUnresolvedReference is the #5806 fail-on-revert
// guard for the LOCAL-CLI renderer.
//
// The unresolved-reference block was added to both `show security screen`
// renderers, but only the gRPC one had a test — deleting the local-CLI emit
// passed the entire suite. This binds it, through the real tolerant-load path
// rather than a hand-built config, so it also exercises `c.store.ActiveConfig()`.
//
// RED on revert: delete the ScreenUnresolvedProfileLines loop from
// cli_show_security_screen.go and every assertion here fails.
func TestShowScreenLocalCLIReportsUnresolvedReference(t *testing.T) {
	c := &CLI{store: danglingScreenRefStore(t)}
	out := captureStdout(t, func() {
		if err := c.showScreen(); err != nil {
			t.Fatalf("showScreen() error = %v", err)
		}
	})

	if !strings.Contains(out, "trust") || !strings.Contains(out, "alpha") {
		t.Fatalf("local CLI must name the zone and the undefined profile; got:\n%s", out)
	}
	// The shared disposition string, so the CLI, the gRPC block and the metric
	// HELP cannot drift into describing the behaviour differently.
	if !strings.Contains(out, dpuserspace.ScreenUnresolvedDisposition) {
		t.Fatalf("local CLI must carry the shared disposition string; got:\n%s", out)
	}
	if !strings.Contains(out, "policy evaluation is unaffected") {
		t.Errorf("disposition must not read as a permit; got:\n%s", out)
	}
}

// TestShowScreenLocalCLISilentWhenResolved is the negative control: the block
// must not render for a healthy config, so the guard above cannot pass by the
// renderer emitting it unconditionally.
func TestShowScreenLocalCLISilentWhenResolved(t *testing.T) {
	store, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride(`
interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.1.10/24; } } } }
security {
    screen { ids-option alpha { icmp { ping-death; } } }
    zones { security-zone trust { screen alpha; interfaces { ge-0/0/0.0; } } }
}
`); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	c := &CLI{store: store}
	out := captureStdout(t, func() {
		if err := c.showScreen(); err != nil {
			t.Fatalf("showScreen() error = %v", err)
		}
	})
	if strings.Contains(out, "Unresolved screen profile references") {
		t.Fatalf("a resolved reference must not render the unresolved block; got:\n%s", out)
	}
}
