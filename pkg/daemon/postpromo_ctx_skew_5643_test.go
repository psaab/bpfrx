package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/vrrp"
)

// postPromoCancelDP is a RuntimeDataPlane whose ApplyConfig fires a supplied
// cancel func as a side effect — simulating a daemon stop (`systemctl stop
// xpfd`) arriving DURING the dataplane apply, i.e. AFTER Store.Commit already
// promoted the config but BEFORE the nft/login tail runs. Production passes
// context.Background() to d.dp.ApplyConfig, so the cancel targets the apply ctx
// carried by applyConfigLocked, which is then observed at the #2926 C3 boundary
// (after the dataplane apply, before the FRR reload).
type postPromoCancelDP struct {
	runtimeOnlyApplyTestDP
	cancel  func()
	applied bool
}

func (d *postPromoCancelDP) ApplyConfig(_ context.Context, _ *config.Config) (*dataplane.ApplyResult, error) {
	d.applied = true
	if d.cancel != nil {
		d.cancel() // daemon-stop arrives mid-apply (post-promotion)
	}
	return &dataplane.ApplyResult{ZoneIDs: map[string]uint16{}}, nil
}

// TestPostPromotionCancelRunsHostAuthorizationCloseout is the #5643 (M35)
// fail-on-revert guard. A config apply that is cancelled at the #2926 C3
// boundary AFTER the dataplane apply (post-promotion daemon stop) must STILL run
// the nft host-authorization tail, so the durable config and the kernel nft
// state do not skew — otherwise a committed host-inbound/lo0 tightening is
// silently deferred for the entire intentional-stop window.
//
// The harness drives the REAL applyConfigLocked (no applyBodyForTest seam) with
// a dp whose ApplyConfig cancels the apply ctx, then asserts:
//   - the apply returns context.Canceled (it did bail at a #2926 boundary),
//   - the dataplane apply ran (dp.applied) — proving the cancel is
//     POST-promotion (past C2, at C3), not a pre-apply C1/C2 bail, and
//   - nftApplyPayload was invoked despite the cancel — proving the nft
//     host-authorization closeout ran, closing the skew.
//
// Fail-on-revert: remove the applyHostAuthorizationCloseout call from
// applyConfigLocked's cancellation branch and nftApplyPayload is never invoked
// (nftCalls==0) — the tail is skipped and the test goes RED.
func TestPostPromotionCancelRunsHostAuthorizationCloseout(t *testing.T) {
	installFakeNetworkctl(t)

	// Hermetic nft: record every nft operation (applyLo0Filter /
	// applyHostInboundFilter route both their apply and their delete-table
	// idioms through nftApplyPayload) instead of shelling out to `nft`.
	origApply, origDelete := nftApplyPayload, nftDeleteTable
	nftCalls := 0
	nftApplyPayload = func(string) ([]byte, error) { nftCalls++; return nil, nil }
	nftDeleteTable = func(string, string) ([]byte, error) { nftCalls++; return nil, nil }
	defer func() { nftApplyPayload, nftDeleteTable = origApply, origDelete }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dp := &postPromoCancelDP{cancel: cancel}
	d := &Daemon{
		dp:      dp,
		vrrpMgr: vrrp.NewManager(),
		store:   newConfigStore(t, filepath.Join(t.TempDir(), "config.db")),
		opts:    Options{NoDataplane: true},
	}

	err := d.applyConfigLocked(ctx, &config.Config{})

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("applyConfigLocked = %v, want context.Canceled (the apply must bail at the C3 boundary)", err)
	}
	if !dp.applied {
		t.Fatalf("dataplane apply did not run: the cancel was not POST-promotion (C3), so the test is not exercising M35")
	}
	if nftCalls == 0 {
		t.Fatalf("nft host-authorization closeout did NOT run after a post-promotion cancel " +
			"(#5643/M35 skew): durable config committed but kernel nft state left stale")
	}
}

// TestLiveApplyRunsHostAuthorizationTailOnce guards against a double-apply or a
// regression on the normal (uncancelled) path: a live apply must run the nft
// tail exactly through the ordinary applyTailReconciles path (not the #5643
// closeout), and must NOT skip or double-run it. The closeout only fires on the
// cancellation branch, so a healthy apply's nft-call count is driven solely by
// the tail.
func TestLiveApplyRunsHostAuthorizationTailOnce(t *testing.T) {
	installFakeNetworkctl(t)

	origApply, origDelete := nftApplyPayload, nftDeleteTable
	nftCalls := 0
	nftApplyPayload = func(string) ([]byte, error) { nftCalls++; return nil, nil }
	nftDeleteTable = func(string, string) ([]byte, error) { nftCalls++; return nil, nil }
	defer func() { nftApplyPayload, nftDeleteTable = origApply, origDelete }()

	dp := &runtimeOnlyApplyTestDP{}
	d := &Daemon{
		dp:      dp,
		vrrpMgr: vrrp.NewManager(),
		store:   newConfigStore(t, filepath.Join(t.TempDir(), "config.db")),
		opts:    Options{NoDataplane: true},
	}

	if err := d.applyConfigLocked(context.Background(), &config.Config{}); err != nil {
		t.Fatalf("applyConfigLocked(live ctx) = %v, want nil", err)
	}
	if dp.applyCalls != 1 {
		t.Fatalf("dataplane apply ran %d times, want 1", dp.applyCalls)
	}
	if nftCalls == 0 {
		t.Fatalf("nft host-authorization tail did not run on a healthy apply (nftCalls=0)")
	}
}
