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
