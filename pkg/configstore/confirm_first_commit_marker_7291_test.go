package configstore

import (
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #7291: commitConfirmedLocked recorded the rollback target's first-commit-ness
// from `s.compiled == nil`. That is an incidental proxy for the durable
// never-committed marker, and the two are independent state, so it was wrong in
// BOTH directions. Both are covered here.

// TestConfirmRollbackKeepsNeverCommittedAfterItem1bRestart is the issue's case,
// driven end to end through the REAL entry points — CommitConfirmed, the
// rollback promotion, and Store.Load — with no state poked directly.
//
// After a #1922 Item 1b first-commit rollback the DB holds committed=0 with the
// EMPTY tree. The empty tree COMPILES, so the next Load yields a store that is
// never-committed AND has a non-nil compiled config. The old proxy read that as
// "not a first commit", took the non-first rollback branch, and persisted
// committed=1 over a never-committed DB — the operator-committed-empty state,
// which computeBootClass resolves to NORMAL, putting the next restart into the
// positional claim-all interface rename on an empty config (#1922 Item 2
// case-5).
func TestConfirmRollbackKeepsNeverCommittedAfterItem1bRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xpf.conf")

	// Phase 1: a real first-commit-confirmed, rolled back on timeout. Persisted
	// for real so phase 2 reads what this actually left on disk.
	st1, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st1.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := st1.LoadOverride("system { host-name box; }"); err != nil {
		t.Fatal(err)
	}
	if _, err := st1.CommitConfirmed(1); err != nil {
		t.Fatal(err)
	}
	st1.ExitConfigure()
	if _, ok := st1.PromoteRollback(st1.ConfirmGenForTesting()); !ok {
		t.Fatal("phase 1 PromoteRollback: ok=false, want true (first-commit revert)")
	}
	if st1.EverCommitted() {
		t.Fatal("phase 1: EverCommitted=true after a first-commit rollback")
	}

	// Phase 2: restart. New() does NOT read the DB; Load() is the restart path.
	st2, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st2.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if st2.EverCommitted() {
		t.Fatal("phase 2: EverCommitted=true; the DB holds committed=0")
	}
	// This is the state that made the proxy wrong, and the fixture is worthless
	// without it: a never-committed store WITH a compiled config.
	if st2.ActiveConfig() == nil {
		t.Fatal("phase 2: ActiveConfig=nil; the empty tree must COMPILE or this " +
			"fixture does not exercise the everCommitted=false/compiled!=nil state")
	}

	// Phase 3: the operator's next commit confirmed, and its timeout.
	var markerWrites []bool
	plainWrites := 0
	st2.SetWriteActiveMarkerForTesting(func(_ *config.ConfigTree, committed bool) error {
		markerWrites = append(markerWrites, committed)
		return nil
	})
	st2.SetWriteActiveForTesting(func(_ *config.ConfigTree) error {
		plainWrites++
		return nil
	})
	if err := st2.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := st2.LoadOverride("system { host-name box2; }"); err != nil {
		t.Fatal(err)
	}
	if _, err := st2.CommitConfirmed(1); err != nil {
		t.Fatal(err)
	}
	st2.ExitConfigure()
	markerWrites, plainWrites = nil, 0

	if _, ok := st2.PromoteRollback(st2.ConfirmGenForTesting()); !ok {
		t.Fatal("phase 3 PromoteRollback: ok=false, want true")
	}
	if len(markerWrites) != 1 || markerWrites[0] {
		t.Errorf("rollback marker writes = %v, want exactly [false]: the rollback "+
			"target is the never-committed empty tree, so it must persist committed=0 "+
			"(plainWrites=%d)", markerWrites, plainWrites)
	}
	if st2.EverCommitted() {
		t.Error("after rollback: EverCommitted=true over a never-committed DB — a " +
			"restart resolves this to NORMAL and claims interfaces on an empty config")
	}
}

// TestConfirmRollbackDoesNotClearMarkerWhenCommittedButUncompiled is the OTHER
// direction, and it is why the fix is not simply "treat a nil compiled config as
// first commit".
//
// The #1960 broken-config load leaves everCommitted=true with compiled==nil: the
// bytes parsed but a previously-committed config no longer compiles, and
// store_persist.go keeps s.compiled nil deliberately so the daemon refuses
// takeover. If the operator then repairs the config and commits confirmed, the
// old proxy read nil-compiled as "first commit" and the rollback would write
// committed=0 over a box that HAS a committed config.
//
// The compiled==nil state is set directly rather than by persisting a config
// that fails lenient compile: this asserts the arm-site decision, and coupling
// the fixture to whichever config happens to fail the lenient validators today
// would make it fragile without making it stronger. everCommitted is reached
// through a real commit.
func TestConfirmRollbackDoesNotClearMarkerWhenCommittedButUncompiled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xpf.conf")
	st, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := st.LoadOverride("system { host-name box; }"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	st.ExitConfigure()
	if !st.EverCommitted() {
		t.Fatal("setup: EverCommitted=false after a real commit")
	}

	// Model the #1960 load outcome: committed on disk, active config uncompiled.
	st.mu.Lock()
	st.compiled = nil
	st.mu.Unlock()

	var markerWrites []bool
	st.SetWriteActiveMarkerForTesting(func(_ *config.ConfigTree, committed bool) error {
		markerWrites = append(markerWrites, committed)
		return nil
	})
	plainWrites := 0
	st.SetWriteActiveForTesting(func(_ *config.ConfigTree) error { plainWrites++; return nil })

	if err := st.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := st.LoadOverride("system { host-name repaired; }"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CommitConfirmed(1); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	st.ExitConfigure()
	markerWrites, plainWrites = nil, 0

	if _, ok := st.PromoteRollback(st.ConfirmGenForTesting()); !ok {
		t.Fatal("PromoteRollback: ok=false, want true")
	}
	// ANTI-VACUITY FLOOR. The correct outcome here is the NON-first branch,
	// which takes a plain writeActive and no marker write at all -- so
	// "markerWrites contains no false" is true of an empty slice and would pass
	// however the code behaved. The first version of this test asserted exactly
	// that and did NOT red when the arm site was mutated to always-first.
	// Requiring the plain write pins that the rollback ran and took the branch
	// this test is about.
	if plainWrites != 1 {
		t.Errorf("rollback plain writes = %d, want 1: the non-first branch must run "+
			"and persist the previous config (markerWrites=%v)", plainWrites, markerWrites)
	}
	if len(markerWrites) != 0 {
		t.Errorf("rollback wrote the never-committed marker %v over a store that HAS "+
			"committed; a nil compiled config is the #1960 broken-load state, not a "+
			"first commit", markerWrites)
	}
	if !st.EverCommitted() {
		t.Error("after rollback: EverCommitted=false on a store that had committed")
	}
}
