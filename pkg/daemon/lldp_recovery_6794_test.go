package daemon

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/lldp"
)

// lldpDaemon returns a Daemon with a real lldp.Manager, plus a mutable set of
// "present" kernel interface names the lookup seam resolves. Socket setup
// always fails so no real socket is opened — name RESOLUTION is the axis #6794
// turns on, and that still runs.
func lldpDaemon(t *testing.T) (*Daemon, map[string]bool) {
	t.Helper()
	present := map[string]bool{}
	lldp.SetInterfaceByNameForTesting(func(name string) (*net.Interface, error) {
		if present[name] {
			return &net.Interface{Index: 1, Name: name}, nil
		}
		return nil, errors.New("no such interface: " + name)
	})
	lldp.FailIfSessionForTesting(errors.New("injected: no CAP_NET_RAW in test"))
	mgr := lldp.New()
	t.Cleanup(func() {
		mgr.Stop()
		lldp.SetInterfaceByNameForTesting(nil)
		lldp.FailIfSessionForTesting(nil)
	})
	return &Daemon{lldpMgr: mgr, daemonCtx: context.Background()}, present
}

// TestUnchangedConfigRecoversADarkInterface6794 is the #6794 fail-on-revert
// test, and it is a WIRING cell by construction: everything it asserts is about
// what reconcileLLDP DOES with Apply's return value. The pkg/lldp cells prove
// Apply reports the unresolved set correctly, and they stay green if the caller
// throws that value away — which is exactly what the caller used to do, because
// it recorded the desired config as applied BEFORE calling Apply at all.
//
// Scenario, which is an ordinary boot race rather than an exotic one: LLDP is
// configured on two interfaces and one of them does not exist yet (renamed a
// moment later by a .link file, or created later as a VLAN/tunnel). The first
// reconcile brings up one and leaves the other dark. The interface then appears.
// A LATER reconcile with an entirely UNCHANGED config must rebuild the
// generation — otherwise recovery needs a `protocols lldp` edit or a daemon
// restart.
//
// FAIL-ON-REVERT: moving the cache back above the Apply call (or dropping the
// lldpRecoveryDue term from the guard) makes the second reconcile take the
// early return, ApplyCount stays 1, and this reds.
func TestUnchangedConfigRecoversADarkInterface6794(t *testing.T) {
	d, present := lldpDaemon(t)
	present["ge-0-0-0"] = true // ge-0/0/1 is not there yet

	cfg := lldpCfg(false, "ge-0/0/0", "ge-0/0/1")

	d.reconcileLLDP(cfg)
	if got := d.lldpMgr.ApplyCount(); got != 1 {
		t.Fatalf("premise: first reconcile must apply, ApplyCount = %d", got)
	}
	if len(d.lldpUnresolved) != 1 || d.lldpUnresolved[0] != "ge-0/0/1" {
		t.Fatalf("the incomplete generation must be RECORDED from Apply's return; unresolved = %v. "+
			"If the caller discards it, an incomplete generation is indistinguishable from a "+
			"converged one (#6794)", d.lldpUnresolved)
	}

	// The missing NIC appears. Config is byte-identical.
	present["ge-0-0-1"] = true

	d.reconcileLLDP(cfg)
	if got := d.lldpMgr.ApplyCount(); got != 2 {
		t.Fatalf("a reconcile on UNCHANGED config must re-apply once a previously-dark interface "+
			"appears; ApplyCount = %d, want 2. Without it LLDP stays dark on that interface until "+
			"someone edits `protocols lldp` or restarts the daemon (#6794)", got)
	}
	if len(d.lldpUnresolved) != 0 {
		t.Errorf("after the recovering apply nothing should remain unresolved, got %v", d.lldpUnresolved)
	}

	// And once converged, the guard must go quiet again.
	d.reconcileLLDP(cfg)
	if got := d.lldpMgr.ApplyCount(); got != 2 {
		t.Errorf("a converged generation must not re-apply on an unchanged config; ApplyCount = %d, "+
			"want 2", got)
	}
}

// TestPermanentlyAbsentInterfaceDoesNotChurn6794 is the tightening control, and
// it guards the regression a naive fix causes.
//
// Manager.Apply Stop()s the whole generation before rebuilding — closing every
// socket AND wiping the neighbor table — so re-applying on every commit is the
// exact churn the #2372 finding-6 guard exists to prevent. A fix that simply
// retries whenever the last apply was incomplete would do that forever on a box
// with one typo'd interface name, blanking `show lldp neighbors` on every
// unrelated firewall-policy commit.
//
// The retry must gate on the WORLD having changed in a way that could fix it.
// Here it never does.
//
// FAIL-ON-REVERT: making lldpRecoveryDue return true whenever lldpUnresolved is
// non-empty reds this on the second reconcile.
func TestPermanentlyAbsentInterfaceDoesNotChurn6794(t *testing.T) {
	d, present := lldpDaemon(t)
	present["ge-0-0-0"] = true // "ge-0/0/9" is a typo and will never appear

	cfg := lldpCfg(false, "ge-0/0/0", "ge-0/0/9")

	d.reconcileLLDP(cfg)
	if got := d.lldpMgr.ApplyCount(); got != 1 {
		t.Fatalf("premise: first reconcile must apply, ApplyCount = %d", got)
	}

	for i := 0; i < 3; i++ {
		d.reconcileLLDP(cfg)
	}
	if got := d.lldpMgr.ApplyCount(); got != 1 {
		t.Errorf("an interface that is permanently absent must NOT make every later commit rebuild "+
			"the LLDP generation; ApplyCount = %d, want 1. Apply Stop()s first, so each rebuild "+
			"closes every socket and wipes the neighbor table — the #2372 churn this guard "+
			"exists to prevent (#6794)", got)
	}
}

// TestHealthyGenerationStillSkipsOnUnchangedConfig6794 is the second tightening
// control: the ORIGINAL #2372 guard must survive. Without this cell, a "fix"
// that simply deleted the unchanged-config short-circuit would satisfy the
// recovery test above while bouncing LLDP on every commit.
func TestHealthyGenerationStillSkipsOnUnchangedConfig6794(t *testing.T) {
	d, present := lldpDaemon(t)
	present["ge-0-0-0"] = true

	cfg := lldpCfg(false, "ge-0/0/0")
	d.reconcileLLDP(cfg)
	if got := d.lldpMgr.ApplyCount(); got != 1 {
		t.Fatalf("premise: ApplyCount = %d, want 1", got)
	}
	if len(d.lldpUnresolved) != 0 {
		t.Fatalf("premise: a fully-resolvable config must leave nothing unresolved, got %v",
			d.lldpUnresolved)
	}

	for i := 0; i < 3; i++ {
		d.reconcileLLDP(cfg)
	}
	if got := d.lldpMgr.ApplyCount(); got != 1 {
		t.Errorf("an unrelated commit must not bounce a HEALTHY LLDP generation (sockets + "+
			"neighbor table); ApplyCount = %d, want 1 (#2372)", got)
	}
}

// TestDisabledBranchRecordsConvergence6794 covers the OTHER branch of
// reconcileLLDP. The function forks on `want == nil` — Stop() — and a fixture
// that only ever exercises the Apply branch leaves the nil branch's bookkeeping
// mutation-invisible: it could record nothing, or carry stale retry debt
// forward, and every Apply-branch cell would stay green.
//
// Stop cannot partially fail, so the nil branch must record convergence
// outright: unchanged-nil must then skip, and the stale unresolved set from a
// previous generation must be CLEARED — otherwise lldpRecoveryDue would keep
// firing against interfaces that LLDP is no longer even configured on.
func TestDisabledBranchRecordsConvergence6794(t *testing.T) {
	d, present := lldpDaemon(t)
	present["ge-0-0-0"] = true

	// A generation with retry debt (ge-0/0/1 is dark).
	d.reconcileLLDP(lldpCfg(false, "ge-0/0/0", "ge-0/0/1"))
	if len(d.lldpUnresolved) == 0 {
		t.Fatalf("premise: expected retry debt after a partial apply")
	}
	afterFirst := d.lldpMgr.ApplyCount()

	// LLDP is disabled: the nil branch.
	d.reconcileLLDP(&config.Config{})
	if len(d.lldpUnresolved) != 0 {
		t.Errorf("disabling LLDP must CLEAR the unresolved set, got %v. Carrying it forward makes "+
			"the recovery guard fire against interfaces LLDP is no longer configured on (#6794)",
			d.lldpUnresolved)
	}
	if d.lldpApplied != nil {
		t.Errorf("the disabled branch must record the nil config as applied, got %v", d.lldpApplied)
	}

	// The missing interface appears; LLDP is still disabled. Nothing must move.
	present["ge-0-0-1"] = true
	d.reconcileLLDP(&config.Config{})
	if got := d.lldpMgr.ApplyCount(); got != afterFirst {
		t.Errorf("an unchanged DISABLED config must not apply; ApplyCount = %d, want %d",
			got, afterFirst)
	}
}
