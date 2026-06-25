package daemon

import (
	"context"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// lldpCfg builds a *config.Config with an LLDP stanza. disable toggles the
// global `protocols lldp disable`; ifaces names the enabled interfaces.
func lldpCfg(disable bool, ifaces ...string) *config.Config {
	cfg := &config.Config{}
	cfg.Protocols.LLDP = &config.LLDPConfig{Disable: disable}
	for _, name := range ifaces {
		cfg.Protocols.LLDP.Interfaces = append(cfg.Protocols.LLDP.Interfaces,
			config.LLDPInterface{Name: name})
	}
	return cfg
}

// TestReconcileLLDPLazyCreateOnDay2Enable is the fail-on-revert pin for #2372.
//
// The defect: LLDP was Apply()'d once at boot (daemon_run.go) and never from
// the day-2 apply pipeline, so a commit that enabled `protocols lldp` after the
// daemon booted with LLDP disabled (d.lldpMgr == nil) did nothing — the manager
// was never instantiated post-boot. This test recreates that exact failure
// mode: a daemon that booted with LLDP disabled (nil manager) receives a day-2
// commit enabling LLDP, and the reconcile MUST lazily create the manager.
//
// If the day-2 reconcile is reverted (LLDP start moves back to boot-only),
// reconcileLLDP would no longer create the manager on a day-2 enable and
// d.lldpMgr stays nil → this test goes RED.
func TestReconcileLLDPLazyCreateOnDay2Enable(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Boot state: LLDP disabled, manager never created.
	d := &Daemon{daemonCtx: ctx}
	d.reconcileLLDP(lldpCfg(true))
	if d.lldpMgr != nil {
		t.Fatalf("reconcileLLDP allocated a manager for a disabled stanza; want nil")
	}

	// Day-2 commit enables LLDP. The manager must be lazily instantiated, even
	// though no interface socket can be opened in the test env (the interface
	// lookup is a no-op skip without a real NIC + CAP_NET_RAW).
	d.reconcileLLDP(lldpCfg(false, "xpf-lldp-test-nic0"))
	if d.lldpMgr == nil {
		t.Fatalf("day-2 enable did not lazily create the LLDP manager; " +
			"reconcile is not running on commit (the #2372 boot-only defect)")
	}

	// Clean up any goroutines the manager started.
	d.lldpMgr.Stop()
}

// TestReconcileLLDPDisableStopsRunning verifies the inverse: a day-2 commit that
// disables LLDP stops the running service. It needs a live generation, which
// requires opening an AF_PACKET socket on the loopback interface (CAP_NET_RAW).
// When that capability is absent (unprivileged CI), Apply() logs + skips the
// interface so no session starts; the test then skips rather than asserting a
// transition it could not establish.
func TestReconcileLLDPDisableStopsRunning(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	d := &Daemon{daemonCtx: ctx}
	d.reconcileLLDP(lldpCfg(false, "lo"))
	if d.lldpMgr == nil {
		t.Fatal("enable on lo did not create the manager")
	}
	if !d.lldpMgr.Running() {
		d.lldpMgr.Stop()
		t.Skip("no live LLDP generation on lo (no CAP_NET_RAW); " +
			"skipping the disable-stops-running transition")
	}

	// Day-2 disable must tear the running generation down.
	d.reconcileLLDP(lldpCfg(true))
	if d.lldpMgr.Running() {
		d.lldpMgr.Stop()
		t.Fatalf("day-2 disable did not stop the running LLDP service")
	}
}
