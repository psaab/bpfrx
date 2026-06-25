package daemon

import (
	"context"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/lldp"
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

// bootDaemon returns a Daemon wired the way daemon_run.go wires it for LLDP:
// the manager is constructed once at boot (unconditionally), so reconcileLLDP
// never reassigns the pointer.
func bootDaemon(ctx context.Context) *Daemon {
	return &Daemon{daemonCtx: ctx, lldpMgr: lldp.New()}
}

// TestReconcileLLDPManagerIdentityStable is the fail-on-revert pin for #2372
// finding 3 (data race on the d.lldpMgr pointer).
//
// The manager is constructed exactly once at boot; reconcileLLDP must only ever
// call Apply()/Stop() on it and NEVER reassign the pointer. The `show lldp
// neighbors` gRPC/CLI handlers read d.lldpMgr lock-free on a handler goroutine,
// so a day-2 reassignment (the lazy-create the first version did) would be a
// data race on the pointer field per the Go memory model. This test asserts the
// pointer identity is stable across the full lifecycle: a day-2 enable, a
// reconfigure, and a disable.
//
// If reconcileLLDP reverts to reassigning d.lldpMgr (e.g. lazy-create on
// enable), the identity check goes RED.
func TestReconcileLLDPManagerIdentityStable(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	d := bootDaemon(ctx)
	orig := d.lldpMgr
	if orig == nil {
		t.Fatal("boot wiring did not construct the LLDP manager")
	}

	// Boot reconcile with LLDP disabled.
	d.reconcileLLDP(lldpCfg(true))
	// Day-2 enable.
	d.reconcileLLDP(lldpCfg(false, "xpf-lldp-test-nic0"))
	// Day-2 reconfigure (different interface set).
	d.reconcileLLDP(lldpCfg(false, "xpf-lldp-test-nic1"))
	// Day-2 disable.
	d.reconcileLLDP(lldpCfg(true))

	if d.lldpMgr != orig {
		t.Fatalf("reconcileLLDP reassigned the d.lldpMgr pointer; the handler "+
			"read path would race a commit (#2372 finding 3). orig=%p now=%p",
			orig, d.lldpMgr)
	}
	d.lldpMgr.Stop()
}

// TestReconcileLLDPSkipsUnchangedCommit is the fail-on-revert pin for #2372
// finding 6 (per-commit thrash).
//
// lldp.Manager.Apply unconditionally Stop()s the running generation — closing
// sockets, joining goroutines, AND wiping the neighbor table — before
// rebuilding. So reconcileLLDP must call Apply only when the effective LLDP
// config actually changed; an unrelated day-2 commit (with LLDP unchanged) must
// NOT re-Apply, or `show lldp neighbors` blanks and sockets churn while
// neighbors re-learn.
//
// The seam is lldp.Manager.ApplyCount(). A second commit with an identical LLDP
// stanza must leave it unchanged. Reverting the diff-guard (calling Apply on
// every commit) makes the unchanged-commit assertion RED.
func TestReconcileLLDPSkipsUnchangedCommit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	d := bootDaemon(ctx)

	// First commit enables LLDP — must Apply once.
	d.reconcileLLDP(lldpCfg(false, "xpf-lldp-test-nic0"))
	if got := d.lldpMgr.ApplyCount(); got != 1 {
		t.Fatalf("first enable: ApplyCount = %d, want 1", got)
	}

	// Second commit with an identical LLDP stanza (a fresh but equal config,
	// modelling an unrelated day-2 commit) must be skipped — no re-Apply.
	d.reconcileLLDP(lldpCfg(false, "xpf-lldp-test-nic0"))
	if got := d.lldpMgr.ApplyCount(); got != 1 {
		t.Fatalf("unchanged commit re-Applied (per-commit thrash, #2372 "+
			"finding 6): ApplyCount = %d, want 1", got)
	}

	// A genuine change (different interface) must re-Apply.
	d.reconcileLLDP(lldpCfg(false, "xpf-lldp-test-nic1"))
	if got := d.lldpMgr.ApplyCount(); got != 2 {
		t.Fatalf("changed commit did not re-Apply: ApplyCount = %d, want 2", got)
	}

	// Another unchanged commit (matching the last applied) must again skip.
	d.reconcileLLDP(lldpCfg(false, "xpf-lldp-test-nic1"))
	if got := d.lldpMgr.ApplyCount(); got != 2 {
		t.Fatalf("second unchanged commit re-Applied: ApplyCount = %d, want 2", got)
	}

	d.lldpMgr.Stop()
}

// TestReconcileLLDPLazyCreateOnDay2Enable verifies the day-2 enable still takes
// effect with the construct-once wiring: a daemon that booted with LLDP
// disabled (manager constructed but never Apply()'d) and then receives a commit
// enabling LLDP must Apply the new config. This recreates the original #2372
// failure mode (boot-only start) at the reconcile level.
func TestReconcileLLDPLazyCreateOnDay2Enable(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	d := bootDaemon(ctx)

	// Boot state: LLDP disabled — no Apply.
	d.reconcileLLDP(lldpCfg(true))
	if got := d.lldpMgr.ApplyCount(); got != 0 {
		t.Fatalf("disabled boot Applied: ApplyCount = %d, want 0", got)
	}

	// Day-2 commit enables LLDP — must Apply (the boot-only defect would skip
	// this because the day-2 reconcile would not run at all).
	d.reconcileLLDP(lldpCfg(false, "xpf-lldp-test-nic0"))
	if got := d.lldpMgr.ApplyCount(); got != 1 {
		t.Fatalf("day-2 enable did not Apply (the #2372 boot-only defect): "+
			"ApplyCount = %d, want 1", got)
	}
	d.lldpMgr.Stop()
}

// TestReconcileLLDPDisableStopsRunning verifies that a day-2 commit which
// disables LLDP stops the running service. It needs a live generation, which
// requires opening an AF_PACKET socket on the loopback interface (CAP_NET_RAW).
// When that capability is absent (unprivileged CI), Apply() logs + skips the
// interface so no session starts; the test then skips rather than asserting a
// transition it could not establish.
func TestReconcileLLDPDisableStopsRunning(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	d := bootDaemon(ctx)
	d.reconcileLLDP(lldpCfg(false, "lo"))
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
