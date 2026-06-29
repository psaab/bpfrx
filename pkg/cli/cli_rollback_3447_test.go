// Tests for #3447: a malformed `rollback <arg>` in the local CLI must NOT
// silently fall through to rollback 0, which discards the candidate edits.
//
// Before the fix, dispatchConfig parsed the argument with fmt.Sscanf, which
// leaves n=0 on a parse failure (and accepts garbage suffixes like "1x").
// A user who mistyped a historical rollback (e.g. `rollback foo`) would
// silently discard their uncommitted candidate edits. The strict integer
// parse now rejects non-numeric, negative, and (via the store) out-of-range
// arguments with a clear error, leaving the candidate untouched.

package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// buildRollbackHistoryStore returns a config store in configuration mode with
// two committed revisions (so `rollback 1` targets a real history entry) and a
// dirty candidate edit on top of the active config.
func buildRollbackHistoryStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	store.SetFromInput("security zones security-zone trust interfaces eth0.0")
	if _, err := store.Commit(); err != nil {
		t.Fatalf("commit 1: %v", err)
	}
	store.SetFromInput("security zones security-zone untrust interfaces eth1.0")
	if _, err := store.Commit(); err != nil {
		t.Fatalf("commit 2: %v", err)
	}
	// Dirty candidate edit on top of active — this is what a malformed
	// rollback must NOT silently discard.
	store.SetFromInput("security zones security-zone dmz interfaces eth2.0")
	if !store.IsDirty() {
		t.Fatal("store should be dirty after candidate edit")
	}
	return store
}

// TestCLIRollbackMalformedRejected pins the #3447 fix: a non-numeric,
// suffixed, negative, or overflowing argument is rejected with an error AND
// the dirty candidate is preserved. Reverting the strict parse makes these
// cases silently succeed as rollback 0 (dirty cleared) — failing the test.
func TestCLIRollbackMalformedRejected(t *testing.T) {
	for _, arg := range []string{"foo", "1x", "-1", "abc", "99999999999999999999"} {
		t.Run(arg, func(t *testing.T) {
			store := buildRollbackHistoryStore(t)
			c := &CLI{store: store}
			err := c.dispatchConfig("rollback " + arg)
			if err == nil {
				t.Fatalf("rollback %q returned nil error; expected rejection "+
					"(must not silently fall through to rollback 0)", arg)
			}
			if !store.IsDirty() {
				t.Fatalf("rollback %q discarded the candidate (silent rollback 0); "+
					"dirty flag was cleared", arg)
			}
		})
	}
}

// TestCLIRollbackOutOfRangeRejected covers a syntactically valid integer that
// is beyond the available history depth — the store returns an out-of-range
// error and the candidate is preserved.
func TestCLIRollbackOutOfRangeRejected(t *testing.T) {
	store := buildRollbackHistoryStore(t)
	c := &CLI{store: store}
	err := c.dispatchConfig("rollback 99")
	if err == nil {
		t.Fatal("rollback 99 (beyond history depth) returned nil; expected out-of-range error")
	}
	if !store.IsDirty() {
		t.Fatal("rollback 99 discarded the candidate; expected the dirty candidate preserved")
	}
}

// TestCLIRollbackValid pins the preserved behaviors: `rollback 0` and the bare
// `rollback` alias discard the candidate (the only discard path), and a valid
// historical index reverts the candidate.
func TestCLIRollbackValid(t *testing.T) {
	t.Run("rollback 0 discards candidate", func(t *testing.T) {
		store := buildRollbackHistoryStore(t)
		c := &CLI{store: store}
		if err := c.dispatchConfig("rollback 0"); err != nil {
			t.Fatalf("rollback 0: %v", err)
		}
		if store.IsDirty() {
			t.Fatal("rollback 0 should clear the dirty flag (discard candidate)")
		}
	})

	t.Run("bare rollback discards candidate", func(t *testing.T) {
		store := buildRollbackHistoryStore(t)
		c := &CLI{store: store}
		if err := c.dispatchConfig("rollback"); err != nil {
			t.Fatalf("bare rollback: %v", err)
		}
		if store.IsDirty() {
			t.Fatal("bare rollback should discard the candidate (rollback 0 semantics)")
		}
	})

	t.Run("rollback 1 reverts to previous commit", func(t *testing.T) {
		store := buildRollbackHistoryStore(t)
		c := &CLI{store: store}
		if err := c.dispatchConfig("rollback 1"); err != nil {
			t.Fatalf("rollback 1: %v", err)
		}
		if !store.IsDirty() {
			t.Fatal("rollback 1 should mark the candidate dirty")
		}
		out := store.ShowCandidateSet()
		if strings.Contains(out, "dmz") {
			t.Fatalf("rollback 1 did not replace the candidate (dmz edit still present):\n%s", out)
		}
		if !strings.Contains(out, "trust") {
			t.Fatalf("rollback 1 lost the committed trust zone:\n%s", out)
		}
	})
}
