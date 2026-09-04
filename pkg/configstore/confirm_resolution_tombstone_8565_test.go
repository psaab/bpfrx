package configstore

import (
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// #8565: a RESOLVED commit-confirmed window whose confirm.json deletion did not
// become durable must not be resurrected on boot.
//
// # The defect
//
// "Window pending" and "window RESOLVED but the deletion failed" were the same
// bytes on disk. #5835's GuardedHash check separates them only when the
// resolution CHANGED the active config — and a confirmation changes nothing:
// `store_commit.go` states it directly, *"ConfirmCommit/ConfirmPendingOnDemotion
// do not replace the active config at all"*. So the hash still matched, recovery
// treated the record as live, and either re-armed the rollback over an
// already-confirmed config or — past the deadline — REVERTED it at Load.
//
// That is data loss of an explicit operator decision, and on two of the three
// resolution paths nobody is told: `ConfirmPendingOnDemotion` returns a bool,
// and the plain-commit/HA-sync paths discard `clearPendingConfirmLocked`'s
// error. `pkg/configstore/README.md` documented a residual here and called it
// safe, but its rationale — *"consistent with ConfirmCommit having returned an
// error"* — only covers the one path that has an error to return.
//
// # Which way the fix errs, and why that is the right way round
//
// A tombstoned record is IGNORED, so the confirmed config STANDS. #4577's
// protection is untouched: an UNRESOLVED record carries no tombstone and still
// reverts, which `TestUnresolvedRecordStillRollsBack_8565` binds. The tombstone
// is written only where the removal is actually reached — which #5473 already
// defers until the resolving write is durable — so it never marks a window
// whose resolution did not take effect. A tombstone write that itself fails
// degrades to exactly the pre-fix behaviour, so the fix can only shrink the
// window in which a resolved record looks pending, never widen it.
//
// A TRANSIENT removal failure and a PERMANENT one get the same answer, and that
// is deliberate: both mean the window is resolved. They differ in how long
// `ConfigPersistDegraded()` stays true — the retry loop clears it when the
// delete lands, and never for a permanent failure — so the box keeps reporting
// the undeleted record either way. The cells below assert that signal, because
// a fix that made the state recoverable but silent would be half a fix.

// resolvedButUndeleted arms a window, resolves it through `resolve` while the
// unlink is failing, and returns the confirmed active set. On return the
// resolved record is still on disk and the removal debt is retained.
func resolvedButUndeleted(t *testing.T, path string, resolve func(*testing.T, *Store)) string {
	t.Helper()
	var failUnlink atomic.Bool
	installConfirmDeleteSeams(t, &failUnlink, nil)

	s := newTestStoreAt(t, path)
	commitBaseline(t, s)
	s.SetPersistRetryBackoffForTesting(time.Hour, time.Hour) // no in-process heal
	stagePendingConfirmed(t, s, "eth1", "untrust")
	confirmed := s.ShowActiveSet()

	failUnlink.Store(true)
	resolve(t, s)

	rec, err := s.db.ReadConfirm()
	if err != nil || rec == nil {
		t.Fatalf("PREMISE: the resolved record must still be on disk (the injected unlink "+
			"failure is what this cell is about): rec=%v err=%v", rec, err)
	}
	if !s.ConfirmRemovalDegraded() {
		t.Fatal("PREMISE: the failed removal must retain retry debt (#5835)")
	}
	// The box must SAY something about it. This is the operator-visible half of
	// the fix: the record is no longer acted on, but its undeleted state is
	// still reported.
	if !s.ConfigPersistDegraded() {
		t.Fatal("#8565: an undeleted resolved record must keep /health degraded — a fix that " +
			"made the state harmless but silent would leave the operator with no signal")
	}
	failUnlink.Store(false) // the fresh store may delete the tombstone
	return confirmed
}

func TestResolvedRecordIsNotResurrected_8565(t *testing.T) {
	for _, tc := range []struct {
		name    string
		resolve func(*testing.T, *Store)
	}{
		{
			// No error channel AT ALL: returns a bool. This is the path the
			// README's "fails SAFE" rationale does not cover.
			name: "demotion",
			resolve: func(t *testing.T, s *Store) {
				if !s.ConfirmPendingOnDemotion() {
					t.Fatal("PREMISE: the demotion confirm must clear a pending window")
				}
			},
		},
		{
			// Returns the error (#5835), and was still resurrected.
			name: "explicit-confirm",
			resolve: func(t *testing.T, s *Store) {
				if err := s.ConfirmCommit(); err == nil {
					t.Fatal("PREMISE: ConfirmCommit must surface the injected unlink failure")
				}
			},
		},
	} {
		t.Run(tc.name+"/deadline-past", func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config")
			confirmed := resolvedButUndeleted(t, path, tc.resolve)
			forceConfirmDeadlinePast(t, path)

			s2 := newTestStoreAt(t, path)
			if err := s2.Load(); err != nil {
				t.Fatalf("boot Load: %v", err)
			}
			if got := s2.ShowActiveSet(); got != confirmed {
				t.Fatalf("#8565: boot REVERTED a config the operator had already confirmed. "+
					"The window was resolved and only the durable deletion was owed, but the "+
					"record on disk could not say so.\nwant %s\ngot  %s", confirmed, got)
			}
			if r, err := s2.db.ReadConfirm(); err != nil || r != nil {
				t.Fatalf("#8565: recovery must finish the owed deletion: rec=%v err=%v", r, err)
			}
		})

		t.Run(tc.name+"/deadline-future", func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config")
			confirmed := resolvedButUndeleted(t, path, tc.resolve)

			s2 := newTestStoreAt(t, path)
			if err := s2.Load(); err != nil {
				t.Fatalf("boot Load: %v", err)
			}
			if s2.IsConfirmPending() {
				t.Fatal("#8565: boot RE-ARMED the auto-rollback over an already-confirmed " +
					"config. The timer will fire and revert it, and until then the operator " +
					"sees a pending window they already closed.")
			}
			if got := s2.ShowActiveSet(); got != confirmed {
				t.Fatalf("#8565: the confirmed config must stand.\nwant %s\ngot  %s", confirmed, got)
			}
		})
	}
}

// TestUnresolvedRecordStillRollsBack_8565 is the control that fails on the
// OVER-BROAD fix. #4577's whole purpose is that an UNCONFIRMED config must not
// become permanent, so a genuinely pending window whose deadline passed during
// downtime must STILL revert on boot. A tombstone written at ARM time, or a
// recovery path that ignored every record, would satisfy every cell above while
// deleting the safety hatch outright.
func TestUnresolvedRecordStillRollsBack_8565(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	s := newTestStoreAt(t, path)
	commitBaseline(t, s)
	base := s.ShowActiveSet()
	stagePendingConfirmed(t, s, "eth1", "untrust") // armed, NEVER resolved
	unconfirmed := s.ShowActiveSet()
	if unconfirmed == base {
		t.Fatal("PREMISE: the unconfirmed config must differ from the rollback target")
	}
	if rec, err := s.db.ReadConfirm(); err != nil || rec == nil || rec.Resolved {
		t.Fatalf("#8565: a LIVE armed window must not carry a resolution tombstone: rec=%+v err=%v", rec, err)
	}

	forceConfirmDeadlinePast(t, path) // window lapsed while the daemon was down
	s2 := newTestStoreAt(t, path)
	if err := s2.Load(); err != nil {
		t.Fatalf("boot Load: %v", err)
	}
	if got := s2.ShowActiveSet(); got != base {
		t.Fatalf("#4577 REGRESSION (#8565 control): an expired UNCONFIRMED window did not roll "+
			"back on boot. The operator never confirmed, so the config on disk must not stand.\n"+
			"want %s\ngot  %s", base, got)
	}
}
