package daemon

import (
	"path/filepath"
	"testing"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
)

// TestHandleConfigSync_AppliedMarkerKeysAppliedConfigNotRacedActive is the
// #6296 regression. Before the fix, handleConfigSync stamped the applied marker
// (MarkActiveApplied) AFTER syncAndApply had RELEASED applySem, and
// MarkActiveApplied re-read s.active at stamp time. A concurrent secondary-side
// promoter (a local commit / commit-confirmed rollback) landing in that
// post-release window mutated s.active, so the stamp keyed the WRONG (never-
// applied-through-this-path) active digest — a later re-push of that exact text
// would then be falsely treated as converged and advance the config high-water
// past a config the dataplane never converged.
//
// The fix relocates the stamp INTO syncAndApply, under applySem, keyed to a
// digest captured for the exact config SyncApply promoted (ActiveDigest ->
// MarkAppliedDigest). This test simulates the concurrent promoter by mutating
// s.active to a DIFFERENT config from inside the apply body (applyBodyForTest),
// which — for BOTH the old and new code — runs before the applied-marker stamp.
// It then asserts the marker reflects the config that was APPLIED (cfgA), not
// the promoter's raced config (cfgB).
//
// Fail-on-revert:
//   - Reverting the stamp to a post-applySem-release MarkActiveApplied() in
//     handleConfigSync keys the marker to s.active == cfgB at stamp time, so
//     ActiveApplied() reads TRUE for cfgB (which was never applied) — the first
//     assertion goes RED.
//   - Removing the stamp entirely leaves the marker unset, so restoring active
//     to the applied config cfgA reads FALSE — the second assertion goes RED.
func TestHandleConfigSync_AppliedMarkerKeysAppliedConfigNotRacedActive(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))

	// The canonical hierarchical text a primary pushes for each config. cfgA is
	// the config this sync APPLIES; cfgB is what a concurrent promoter races into
	// s.active before the applied marker is stamped.
	cfgA := renderSyncedConfigText(t, "system host-name applied-a")
	cfgB := renderSyncedConfigText(t, "system host-name promoter-b")

	var promoterFired bool
	d := &Daemon{
		// No cluster manager: standalone passes the config-authority guard and
		// makes the topology/identity preflights no-ops. No dataplane: the deferred
		// session invalidation short-circuits (nil dp).
		store:    store,
		applySem: semaphore.NewWeighted(1),
	}
	// The apply-body seam replaces the real reconcile pipeline. It also injects
	// the concurrent promoter EXACTLY ONCE: after syncAndApply's SyncApply(cfgA)
	// promoted active to A (and, under the fix, after ActiveDigest captured A's
	// digest), a secondary-side promoter lands and mutates s.active to B. In BOTH
	// old and new code this runs before the applied-marker stamp, so it isolates
	// which config the stamp keys.
	d.applyBodyForTest = func(*config.Config) {
		if promoterFired {
			return
		}
		promoterFired = true
		if _, err := store.SyncApply(cfgB, nil); err != nil {
			t.Errorf("injected promoter SyncApply(cfgB): %v", err)
		}
	}

	if err := d.handleConfigSync(cfgA); err != nil {
		t.Fatalf("handleConfigSync(cfgA): %v", err)
	}
	if !promoterFired {
		t.Fatal("test setup: apply body (and the injected promoter) never ran — " +
			"the sync must have reached applyConfigLocked")
	}
	if got := store.ShowActive(); got != cfgB {
		t.Fatalf("test setup: expected active to be the promoter's cfgB, got:\n%s", got)
	}

	// s.active is now cfgB (the promoter's config), which was NEVER applied
	// through the daemon apply path. The applied marker must therefore NOT report
	// the current active as applied: with the fix it keyed cfgA's captured digest,
	// so ActiveApplied() (which compares against the CURRENT active == cfgB) is
	// false. Reverting to the post-release MarkActiveApplied() keys cfgB and this
	// reads TRUE — RED.
	if store.ActiveApplied() {
		t.Fatal("#6296: applied marker must NOT key the concurrently-promoted, " +
			"never-applied active (cfgB); it must key the config syncAndApply " +
			"actually applied (cfgA)")
	}

	// Positive: restore active to cfgA (the config that WAS applied) with a bare
	// store promotion that does NOT re-stamp the marker. Now ActiveApplied() must
	// read TRUE, proving the marker keyed cfgA's digest. Under a revert that
	// removed the stamp the marker is unset, so this reads FALSE — RED.
	if _, err := store.SyncApply(cfgA, nil); err != nil {
		t.Fatalf("restore active to cfgA: %v", err)
	}
	if !store.ActiveApplied() {
		t.Fatal("#6296: applied marker must key the digest of the config that was " +
			"applied (cfgA) — restoring active to cfgA must read as applied")
	}
}
