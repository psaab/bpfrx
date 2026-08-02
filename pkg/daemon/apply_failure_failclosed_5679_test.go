package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/networkd"
	"github.com/psaab/xpf/pkg/vrrp"
)

// TestApplyConfigLockedFailsCommitOnOrdinaryDataplaneApplyError_5679 is the
// #5679 commit-level wiring proof. An ORDINARY (non-abort-class) full dataplane
// apply failure — the dataplane ApplyConfig returns a plain error that is NOT one of the
// required-protocol-gate sentinels compileErrorMustAbortApply matches — does
// NOT disarm the dataplane: the OLD compiled policy stays live and forwarding
// while store.Commit has already promoted+persisted the NEW config. Before the
// fix the failure was swallowed (recorded for /health, then fall-through) and
// applyConfigLocked returned nil, so the commit reported SUCCESS while the new
// policy was never on the wire — a fail-open-to-stale (a tightening commit,
// e.g. a new deny, looked applied while the looser old policy still enforced).
//
// The fix captures the ordinary apply error as a DEFERRED commit error threaded
// into applyTailReconciles' errors.Join (fail-closed but complete, like
// networkdErr / ifaceErr), so applyConfigLocked now returns non-nil and the
// commit reports failure.
//
// FAIL-ON-REVERT: delete the `applyErr = err` assignment in the ordinary-apply
// branch of applyDataplaneAndHACore (daemon_apply.go) and this goes RED — the
// error is swallowed and applyConfigLocked returns nil despite the new policy
// not being on the dataplane.
func TestApplyConfigLockedFailsCommitOnOrdinaryDataplaneApplyError_5679(t *testing.T) {
	installFakeNetworkctl(t)

	// A plain, non-abort-class apply failure (a control-socket / helper error),
	// distinct from the required-protocol-gate sentinels. Guard the premise so a
	// future reclassification that makes this abort-class does not silently turn
	// the test into an exercise of the (already-covered) early-abort path.
	injected := errors.New("dataplane control-socket sync failed: connection reset")
	if compileErrorMustAbortApply(injected) {
		t.Fatal("precondition: injected error must be ORDINARY (non-abort-class); " +
			"compileErrorMustAbortApply matched it — pick a different vector")
	}

	dp := &runtimeOnlyApplyTestDP{applyErr: injected}
	d := &Daemon{
		networkd: networkd.NewInDir(t.TempDir()),
		store:    newConfigStore(t, filepath.Join(t.TempDir(), "config.db")),
		vrrpMgr:  vrrp.NewManager(),
		opts:     Options{NoDataplane: true},
	}
	d.setDataplane(dp) // #2114: publish through the cell

	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", Interfaces: []string{"reth0.0"}},
	}

	err := d.applyConfigLocked(context.Background(), cfg)
	if err == nil {
		t.Fatal("applyConfigLocked must FAIL the commit when an ordinary dataplane " +
			"apply fails (the new policy is not on the wire); got nil — the error " +
			"was swallowed and the commit would report success against stale policy")
	}
	if !errors.Is(err, injected) {
		t.Fatalf("applyConfigLocked error must wrap the injected apply failure; got %v", err)
	}
	if dp.applyCalls != 1 {
		t.Fatalf("dataplane ApplyConfig calls = %d, want 1 (apply must have been attempted)", dp.applyCalls)
	}

	// The ordinary apply failure is a DEFERRED (non-fatal) commit error, NOT a
	// disarm/abort: the dataplane is still armed with the OLD config, so the
	// standby must still receive the committed config (#4034). Pin that this
	// error class does NOT suppress the peer sync — distinguishing it from the
	// required-protocol-gate (disarmed) and context-abort classes.
	if applyErrSkipsPeerSync(err) {
		t.Fatal("an ordinary (non-abort) dataplane-apply failure must NOT skip the " +
			"peer config-sync (#4034): the dataplane is still armed and the standby " +
			"has to converge; only a disarmed-gate or context-abort error skips it")
	}
}

// TestApplyConfigLockedAbortClassStillEarlyReturns_5679 pins the OTHER half of
// the #5679 contract: an abort-class (required-protocol-gate) apply failure
// still returns via the terminal `err` path — an EARLY return that skips the
// routing / service / tail reconciles — rather than being demoted to the new
// deferred applyErr slot. The abort class means the dataplane is DISARMED
// (fail-closed), so aborting the rest of the apply is correct. This guards the
// fix from over-reaching (folding the abort case into the deferred path would
// keep running the tail against a disarmed dataplane).
func TestApplyConfigLockedAbortClassStillEarlyReturns_5679(t *testing.T) {
	installFakeNetworkctl(t)

	dp := &runtimeOnlyApplyTestDP{applyErr: dpuserspace.ErrPolicySchedulerProtocolIncompatible}
	d := &Daemon{
		networkd: networkd.NewInDir(t.TempDir()),
		store:    newConfigStore(t, filepath.Join(t.TempDir(), "config.db")),
		vrrpMgr:  vrrp.NewManager(),
		opts:     Options{NoDataplane: true},
	}
	d.setDataplane(dp) // #2114: publish through the cell

	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", Interfaces: []string{"reth0.0"}},
	}

	err := d.applyConfigLocked(context.Background(), cfg)
	if !errors.Is(err, dpuserspace.ErrPolicySchedulerProtocolIncompatible) {
		t.Fatalf("abort-class apply failure must surface the gate sentinel; got %v", err)
	}
	// It MUST remain in the fatal (peer-sync-skipping, disarmed) class.
	if !applyErrSkipsPeerSync(err) {
		t.Fatal("abort-class (required-protocol-gate) apply failure must still skip " +
			"the peer sync — the dataplane is disarmed; pushing it to the standby is worse")
	}
}
