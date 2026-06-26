package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/vrrp"
)

// minimalApplyCtxDaemon builds a Daemon wired with just enough to drive the
// REAL applyConfigLocked body (no applyBodyForTest seam): a recording runtime
// dataplane, a VRRP manager, and a store. d.routing/d.frr/d.networkd are nil,
// so the netlink reconcile phases (steps 0/1) are skipped and the first
// side-effecting step the body reaches is the dataplane apply (step 2). That
// makes the dataplane's applyCalls counter a precise probe for "did the apply
// proceed past the #2926 cancellation boundaries".
func minimalApplyCtxDaemon(t *testing.T) (*Daemon, *runtimeOnlyApplyTestDP, *config.Config) {
	t.Helper()
	installFakeNetworkctl(t)
	dp := &runtimeOnlyApplyTestDP{}
	d := &Daemon{
		dp:      dp,
		vrrpMgr: vrrp.NewManager(),
		store:   newConfigStore(t, filepath.Join(t.TempDir(), "config.db")),
		opts:    Options{NoDataplane: true},
	}
	return d, dp, &config.Config{}
}

// TestApplyConfigLockedAbortsOnCanceledCtx is the #2926 fail-on-revert guard:
// applyConfigLocked must honor a canceled context at a coarse boundary and
// return ctx.Err() WITHOUT performing the heavy work — here, the dataplane
// apply / Rust control-socket sync push (step 2). The runtimeOnlyApplyTestDP
// records every ApplyConfig call, so applyCalls==0 proves the sync push never
// ran.
//
// Mutation check (fail-on-revert): delete the `if err := ctx.Err(); err != nil`
// boundary checks from applyConfigLocked and this test goes RED — the canceled
// apply proceeds into step 2 (dp.applyCalls becomes 1) and returns nil instead
// of context.Canceled.
func TestApplyConfigLockedAbortsOnCanceledCtx(t *testing.T) {
	d, dp, cfg := minimalApplyCtxDaemon(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // canceled before the apply even begins

	err := d.applyConfigLocked(ctx, cfg)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("applyConfigLocked(canceled ctx) = %v, want context.Canceled", err)
	}
	if dp.applyCalls != 0 {
		t.Fatalf("applyConfigLocked ran the dataplane sync push despite a "+
			"canceled context (applyCalls=%d, want 0): the #2926 boundary "+
			"check did not abort the apply", dp.applyCalls)
	}
}

// TestApplyCancelCtxAbortsApplyOnDaemonStop exercises the REAL production
// wiring (#2926 fold): it does NOT inject a pre-canceled context directly into
// applyConfigLocked. Instead it reproduces exactly how Run wires the cancel
// signal — d.daemonCtx is the never-canceled context.Background() that cmd/xpfd
// passes into Run, and the apply-abort context (d.applyCancelContext) is a
// SEPARATE child of the SIGTERM/SIGINT signal context. The apply is then driven
// through d.applyCancelCtx() (the production seam), and "daemon stop" is
// simulated by canceling the signal parent, which must propagate to the
// dedicated apply-abort child and make applyConfigLocked bail at boundary C1
// (dp.applyCalls stays 0).
//
// Fail-on-revert: this is the test the ORIGINAL inert wiring fails. If
// applyCancelCtx() reverts to returning d.daemonCtx (the pre-fold code), it
// returns the never-canceled context.Background() set below, the apply runs to
// completion (dp.applyCalls==1) and returns nil instead of context.Canceled —
// the test goes RED. The earlier TestApplyConfigLockedAbortsOnCanceledCtx
// (direct-injection) would still PASS under the inert wiring, which is why it
// gave false confidence; this test closes that gap.
func TestApplyCancelCtxAbortsApplyOnDaemonStop(t *testing.T) {
	d, dp, cfg := minimalApplyCtxDaemon(t)

	// Production wiring: daemonCtx is the never-canceled background context
	// cmd/xpfd passes into Run. The apply-abort context is the separate
	// signal-child Run creates after signal.NotifyContext.
	d.daemonCtx = context.Background()
	signalCtx, daemonStop := context.WithCancel(context.Background())
	defer daemonStop()
	d.applyCancelContext, d.applyCancel = context.WithCancel(signalCtx)
	defer d.applyCancel()

	// Simulate `systemctl stop xpfd`: the signal context is canceled, which
	// must propagate through to the dedicated apply-abort child returned by
	// applyCancelCtx().
	daemonStop()

	err := d.applyConfigLocked(d.applyCancelCtx(), cfg)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("applyConfigLocked(applyCancelCtx after daemon stop) = %v, "+
			"want context.Canceled — the daemon-stop signal did not reach the "+
			"#2926 boundary checks (inert wiring)", err)
	}
	if dp.applyCalls != 0 {
		t.Fatalf("applyConfigLocked ran the dataplane sync push despite a "+
			"daemon stop (applyCalls=%d, want 0): applyCancelCtx() is not wired "+
			"to the signal-cancellable context", dp.applyCalls)
	}
}

// TestApplyCancelCtxRunsFullApplyWhileDaemonLive is the live-daemon companion
// to TestApplyCancelCtxAbortsApplyOnDaemonStop: with the apply-abort context
// wired but NOT canceled (daemon running normally), a commit-path apply driven
// through applyCancelCtx() must run in full (dp.applyCalls==1). This guards
// against an over-eager wiring that would abort healthy day-2 commits.
func TestApplyCancelCtxRunsFullApplyWhileDaemonLive(t *testing.T) {
	d, dp, cfg := minimalApplyCtxDaemon(t)

	d.daemonCtx = context.Background()
	signalCtx, daemonStop := context.WithCancel(context.Background())
	defer daemonStop()
	d.applyCancelContext, d.applyCancel = context.WithCancel(signalCtx)
	defer d.applyCancel()

	if err := d.applyConfigLocked(d.applyCancelCtx(), cfg); err != nil {
		t.Fatalf("applyConfigLocked(applyCancelCtx, daemon live) = %v, want nil", err)
	}
	if dp.applyCalls != 1 {
		t.Fatalf("applyConfigLocked did not run the full apply on a live "+
			"daemon (applyCalls=%d, want 1)", dp.applyCalls)
	}
}

// TestApplyConfigLockedRunsFullApplyOnLiveCtx is the regression half: a live
// (non-canceled) context must run the apply exactly as before #2926 — the
// dataplane sync push happens (applyCalls==1) and the body returns nil. This
// guards against an over-eager boundary check that would abort a healthy apply.
func TestApplyConfigLockedRunsFullApplyOnLiveCtx(t *testing.T) {
	d, dp, cfg := minimalApplyCtxDaemon(t)

	if err := d.applyConfigLocked(context.Background(), cfg); err != nil {
		t.Fatalf("applyConfigLocked(live ctx) = %v, want nil", err)
	}
	if dp.applyCalls != 1 {
		t.Fatalf("applyConfigLocked did not run the full apply on a live "+
			"context (applyCalls=%d, want 1)", dp.applyCalls)
	}
}
