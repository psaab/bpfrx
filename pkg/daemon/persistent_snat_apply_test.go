package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/vrrp"
)

// persistentSourceNATConfig returns a config that uses persistent source NAT
// — the feature whose protocol gate (ErrPersistentSourceNATProtocolIncompatible)
// is the subject of #2138. The actual config contents do not matter for the
// apply-path test below (the fake dataplane returns the sentinel directly),
// but a representative config keeps the test honest about what triggers the
// gate in production.
func persistentSourceNATConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Security.NAT.SourcePools = map[string]*config.NATPool{
		"pool-a": {
			Name:          "pool-a",
			Addresses:     []string{"203.0.113.10"},
			PersistentNAT: &config.PersistentNATConfig{InactivityTimeout: 300},
		},
	}
	cfg.Security.NAT.Source = []*config.NATRuleSet{{
		Name:     "rs",
		FromZone: "trust",
		ToZone:   "wan",
		Rules: []*config.NATRule{{
			Name: "snat",
			Then: config.NATThen{Type: config.NATSource, PoolName: "pool-a"},
		}},
	}}
	return cfg
}

// TestApplyConfigLockedAbortsCommitOnPersistentSourceNATProtocolMismatch is
// the #2138 regression on the COMMIT path. When the running helper is too old
// for persistent source NAT, ApplyConfig disarms the helper and returns
// ErrPersistentSourceNATProtocolIncompatible. The daemon's commit-style apply
// (applyConfigLocked, used by commitAndApply / commitConfirmedAndApply) MUST
// propagate that error so the operator's commit reports failure rather than
// success against a disarmed dataplane.
//
// Non-tautological: pre-fix, compileErrorMustAbortApply matched only the
// scheduler sentinel, so this apply would NOT return the persistent-SNAT
// sentinel — it would fall through compileErrorMustAbortApply and continue
// past the dataplane apply, returning nil (or a later unrelated error). This
// test fails against the pre-#2138 abort set.
func TestApplyConfigLockedAbortsCommitOnPersistentSourceNATProtocolMismatch(t *testing.T) {
	dp := &runtimeOnlyApplyTestDP{
		applyErr: dpuserspace.ErrPersistentSourceNATProtocolIncompatible,
	}
	d := &Daemon{
		vrrpMgr: vrrp.NewManager(),
		store:   newConfigStore(t, filepath.Join(t.TempDir(), "config.db")),
		opts:    Options{NoDataplane: true},
	}
	d.setDataplane(dp) // #2114: publish through the cell

	err := d.applyConfigLocked(context.Background(), persistentSourceNATConfig())
	if !errors.Is(err, dpuserspace.ErrPersistentSourceNATProtocolIncompatible) {
		t.Fatalf("applyConfigLocked error = %v, want ErrPersistentSourceNATProtocolIncompatible "+
			"(commit must abort on a required protocol-gate mismatch)", err)
	}
	if dp.applyCalls != 1 {
		t.Fatalf("ApplyConfig calls = %d, want 1 (the aborting apply must run exactly once)", dp.applyCalls)
	}
}

// TestApplyConfigLenientWrapperSwallowsPersistentSourceNATProtocolMismatch is
// the #2138 lenient-load (#1960) half. The boot apply and the DHCP/feed/event
// re-apply paths go through the void applyConfig wrapper, which logs slog.Warn
// and SWALLOWS the error so an already-persisted persistent-SNAT config
// against an old helper still boots through (warn + disarmed helper, not a
// brick). The commit-abort fix must NOT change that: applyConfig must not
// panic or surface the error, and the underlying apply must still have been
// attempted. (The peer config-sync path is lenient too, but by a different
// mechanism — syncAndApply propagates the error and handleConfigSync logs
// slog.Error and returns; it is not exercised by this test, which targets the
// void wrapper specifically.)
//
// Together with the commit-path test above, this proves the fail-closed-at-
// commit / lenient-at-load split: the SAME protocol mismatch aborts when it
// flows through the operator-facing commit path but is swallowed when it flows
// through the void boot/background apply wrapper.
func TestApplyConfigLenientWrapperSwallowsPersistentSourceNATProtocolMismatch(t *testing.T) {
	dp := &runtimeOnlyApplyTestDP{
		applyErr: dpuserspace.ErrPersistentSourceNATProtocolIncompatible,
	}
	d := &Daemon{
		applySem: semaphore.NewWeighted(1),
		vrrpMgr:  vrrp.NewManager(),
		store:    newConfigStore(t, filepath.Join(t.TempDir(), "config.db")),
		opts:     Options{NoDataplane: true},
	}
	d.setDataplane(dp) // #2114: publish through the cell

	// The void wrapper must return normally (log + swallow) — no panic, no
	// propagation. If this path aborted/propagated, a node carrying a
	// persisted persistent-SNAT config would fail to boot against an old
	// helper (the #1960 brick this fix must avoid).
	d.applyConfig(persistentSourceNATConfig())

	if dp.applyCalls != 1 {
		t.Fatalf("ApplyConfig calls = %d, want 1 (the lenient apply must still attempt the apply)", dp.applyCalls)
	}
	// applySem must be released after the wrapper returns — a leaked
	// semaphore would mean the wrapper exited abnormally.
	if !d.applySem.TryAcquire(1) {
		t.Fatal("applySem not released after applyConfig returned (lenient wrapper exited abnormally)")
	}
	d.applySem.Release(1)
}
