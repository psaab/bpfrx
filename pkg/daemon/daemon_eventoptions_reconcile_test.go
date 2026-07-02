package daemon

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/rpm"
)

// eventOptionsCfg builds a *config.Config carrying the named event-options
// policies (each a single-event, single-command remediation).
func eventOptionsCfg(names ...string) *config.Config {
	cfg := &config.Config{}
	for _, name := range names {
		cfg.EventOptions = append(cfg.EventOptions, &config.EventPolicy{
			Name:         name,
			Events:       []string{"ping_test_failed"},
			ThenCommands: []string{"set system host-name " + name},
		})
	}
	return cfg
}

// bootEventDaemon wires a Daemon the way daemon_run.go wires it for the event
// engine: an RPM manager and a configstore exist, then initEventEngine
// constructs the engine unconditionally.
func bootEventDaemon(t *testing.T) *Daemon {
	t.Helper()
	d := &Daemon{
		daemonCtx: context.Background(),
		rpm:       rpm.New(),
		store:     newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf")),
	}
	d.initEventEngine()
	return d
}

// TestInitEventEngineConstructsUnconditionally is the fail-on-revert pin for
// the #3752 root cause: the engine must be constructed at boot even when the
// boot config carries NO event-options policy. The pre-fix boot gated
// construction on len(cfg.EventOptions) > 0, so a daemon that booted policy-
// less left d.eventEngine nil and every day-2 apply (`if d.eventEngine != nil`)
// was a silent no-op.
//
// If initEventEngine is reverted to gate on a non-empty policy set, this goes
// RED (engine nil) — as does the day-2 test below (PolicyCount stays 0).
func TestInitEventEngineConstructsUnconditionally(t *testing.T) {
	d := bootEventDaemon(t)
	if d.eventEngine == nil {
		t.Fatal("initEventEngine did not construct the engine at boot")
	}
	if got := d.eventEngine.PolicyCount(); got != 0 {
		t.Fatalf("engine loaded %d policies at boot with an empty config; want 0", got)
	}
}

// TestReconcileEventOptionsDay2Enable is the fail-on-revert pin for #3752.
//
// A daemon booted with NO event-options policy (engine constructed, zero
// policies) then receives a day-2 commit enabling the FIRST policy. The
// reconcile must load it into the engine so the policy is live — the exact
// scenario that was inert until a restart before the fix.
func TestReconcileEventOptionsDay2Enable(t *testing.T) {
	d := bootEventDaemon(t)

	// Boot reconcile with no policies (models a policy-less boot).
	d.reconcileEventOptions(eventOptionsCfg())
	if got := d.eventEngine.PolicyCount(); got != 0 {
		t.Fatalf("policy-less boot loaded %d policies; want 0", got)
	}

	// Day-2 commit enables the first policy — it MUST take effect now.
	d.reconcileEventOptions(eventOptionsCfg("wan-failover"))
	if got := d.eventEngine.PolicyCount(); got != 1 {
		t.Fatalf("day-2 first-enable loaded %d policies; want 1 (#3752: the "+
			"engine must start on a day-2 enable, not only at boot)", got)
	}

	// A second day-2 commit adding another policy reconciles to two.
	d.reconcileEventOptions(eventOptionsCfg("wan-failover", "lan-failover"))
	if got := d.eventEngine.PolicyCount(); got != 2 {
		t.Fatalf("day-2 add loaded %d policies; want 2", got)
	}

	// Removing all policies reconciles back to zero without tearing the engine.
	d.reconcileEventOptions(eventOptionsCfg())
	if got := d.eventEngine.PolicyCount(); got != 0 {
		t.Fatalf("policy removal left %d policies; want 0", got)
	}
	if d.eventEngine == nil {
		t.Fatal("reconcile must never reassign/clear the engine pointer")
	}
	d.eventEngine.Close()
}

// TestInitEventEngineRegistersRPMCallbackBeforeProbes pins the #3755 ordering
// guarantee at the boot-wiring level: initEventEngine (called before
// reconcileRPM starts probes) registers the RPM event callback, so the first
// probe cycle's events reach the event engine instead of firing into a nil
// callback. If the callback registration is dropped from initEventEngine, or
// initEventEngine is not run before probes start, HasEventCallback stays false.
func TestInitEventEngineRegistersRPMCallbackBeforeProbes(t *testing.T) {
	d := &Daemon{
		daemonCtx: context.Background(),
		rpm:       rpm.New(),
		store:     newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf")),
	}
	if d.rpm.HasEventCallback() {
		t.Fatal("RPM event callback set before initEventEngine")
	}
	d.initEventEngine()
	if !d.rpm.HasEventCallback() {
		t.Fatal("initEventEngine did not register the RPM event callback " +
			"(the first probe cycle's events would be dropped, #3755)")
	}
	d.eventEngine.Close()
}

// reconcileEventOptions must tolerate a nil config (bootstrap / no-active-
// config paths call it as a safety net).
func TestReconcileEventOptionsNilConfig(t *testing.T) {
	d := bootEventDaemon(t)
	d.reconcileEventOptions(nil)
	if got := d.eventEngine.PolicyCount(); got != 0 {
		t.Fatalf("nil config loaded %d policies; want 0", got)
	}
	d.eventEngine.Close()
}
