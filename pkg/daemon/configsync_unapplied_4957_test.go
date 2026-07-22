package daemon

import (
	"errors"
	"path/filepath"
	"testing"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
)

// renderSyncedConfigText returns the canonical hierarchical text a cluster
// primary would push over config-sync for the given flat `set` lines. The
// primary sends d.store.ShowActive(), so a faithful test must feed the SAME
// canonical render (not raw set commands) into handleConfigSync, whose
// convergence shortcut compares against ShowActive().
func renderSyncedConfigText(t *testing.T, setLines ...string) string {
	t.Helper()
	s := newConfigStore(t, filepath.Join(t.TempDir(), "render.db"))
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, line := range setLines {
		if err := s.SetFromInput(line); err != nil {
			t.Fatalf("SetFromInput(%q): %v", line, err)
		}
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return s.ShowActive()
}

// TestHandleConfigSync_PromotedButUnappliedIsNotConverged is the #4957
// regression. configstore.SyncApply promotes s.active to the peer config BEFORE
// applyConfigLocked runs and, under the #1799 degrade-not-fail doctrine, does
// NOT roll s.active back when the apply FAILS (a transient networkd/nft/IPsec
// tail error). Before the fix, handleConfigSync's convergence shortcut keyed on
// active-text equality alone: the primary's same-generation re-push saw
// active==incoming, returned nil, and the config high-water advanced — treating
// a config whose dataplane never converged as applied. The standby then acked a
// generation it never finished applying and could expose stale/disarmed
// forwarding at failover.
//
// The fix ANDs the shortcut with store.ActiveApplied(), a marker stamped ONLY
// after a fully-successful apply. So a re-push of a promoted-but-unapplied
// config must fall through and RE-ATTEMPT the apply (reconcile retry) rather
// than be swallowed as a duplicate.
//
// Fail-on-revert: the second sync's assertion that applyConfigLocked is invoked
// a SECOND time goes RED if the ActiveApplied() gate is removed — the reverted
// shortcut returns nil on active-text equality and never retries the apply.
func TestHandleConfigSync_PromotedButUnappliedIsNotConverged(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))

	var applyCalls int
	d := &Daemon{
		// No cluster manager: standalone passes the config-authority guard, and a
		// standalone (non-cluster) config makes the topology/identity preflights
		// no-ops. No dataplane: the deferred session invalidation short-circuits.
		store:    store,
		applySem: semaphore.NewWeighted(1),
		// The seam replaces the real reconcile pipeline: count every attempt.
		applyBodyForTest: func(*config.Config) { applyCalls++ },
	}

	// A NON-FATAL apply error (not a required-protocol-gate disarm and not a
	// context abort): the #4957 class. The config stays active + armed,
	// syncAndApply returns the error, and handleConfigSync returns it so the
	// high-water does NOT advance and the peer re-pushes the same generation.
	transient := errors.New("transient networkd tail error")

	// The canonical text a primary pushes for this config.
	cfgB := renderSyncedConfigText(t, "system host-name synced-b")

	// --- Delivery 1: apply FAILS (transient tail error). ---
	d.applyErrForTest = transient
	if err := d.handleConfigSync(cfgB); err == nil {
		t.Fatal("first sync: expected an error from the failed apply (high-water must not advance)")
	}
	if applyCalls != 1 {
		t.Fatalf("first sync: applyConfigLocked calls = %d, want 1", applyCalls)
	}
	// Degrade-not-fail: SyncApply promoted active to B despite the failed apply,
	// but the config is NOT applied.
	if store.ShowActive() == "" {
		t.Fatal("first sync: active should have been promoted to the synced config")
	}
	if store.ActiveApplied() {
		t.Fatal("first sync: a promoted-but-unapplied config must not read as applied")
	}

	// --- Delivery 2: primary re-pushes the SAME config (same generation). ---
	// With the fix the shortcut is suppressed (active matches but was never
	// applied), so the reconcile retry runs. Let the retry succeed this time.
	d.applyErrForTest = nil
	if err := d.handleConfigSync(cfgB); err != nil {
		t.Fatalf("second sync: reconcile retry must succeed, got %v", err)
	}
	if applyCalls != 2 {
		t.Fatalf("second sync: applyConfigLocked calls = %d, want 2 — the reconcile retry "+
			"must run, NOT be shortcut-as-converged (#4957 fail-on-revert)", applyCalls)
	}
	if !store.ActiveApplied() {
		t.Fatal("second sync: a successfully-applied config must read as applied")
	}

	// --- Delivery 3: now genuinely converged. A re-push MUST take the shortcut
	// and not re-apply, else every reconnect re-applies a live config. ---
	if err := d.handleConfigSync(cfgB); err != nil {
		t.Fatalf("third sync: converged re-push error = %v", err)
	}
	if applyCalls != 2 {
		t.Fatalf("third sync: applyConfigLocked calls = %d, want 2 — an applied config "+
			"must take the converged shortcut (no redundant re-apply)", applyCalls)
	}
}
