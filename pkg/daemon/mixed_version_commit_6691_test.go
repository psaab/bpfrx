package daemon

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/networkd"
	"github.com/psaab/xpf/pkg/vrrp"
)

// TestMixedVersionHelperRefusalFailsTheCommit_6691 is the COMMIT-PATH half of
// the #6691 round 9b mixed-version matrix: what a v6 control plane does when it
// meets a v5 helper on a config the secure-tunnel gate does NOT arm for — which
// is every reference cluster this project runs (the loss userspace cluster
// compiles to 16 interface rows and zero flagged ones; see
// TestMixedVersionMatrix_6691).
//
// This exists because the existing #5679 proof injects a GENERIC apply failure
// ("control-socket sync failed"). That leaves the step from "the helper refused
// on version" to "the commit fails via the deferred path" as a READ of the
// classification rather than a measurement of it. A protocol bump is exactly
// the change where that step should not be assumed: #6722 bumped 4 -> 5 the
// same day on a matrix that generalised from one measurement and was wrong.
//
// So the injected error is the REAL one — the string the helper emits
// (server/handlers/snapshot.rs), wrapped the way process_control.go wraps an
// ok=false response and publishSnapshotFailClosedLocked wraps that.
//
// The measured outcome is a CLEAN REFUSAL, not a wrong answer: the commit
// FAILS, and because the class is not a gate sentinel the helper is NOT
// disarmed — it refused the new snapshot, so it is still enforcing its
// previous-good image and forwarding. Disarming it would convert a handshake
// disagreement into a dataplane outage.
//
// FAIL-ON-REVERT: classify the version refusal as a required-protocol-gate
// sentinel and the peer-sync assertion reds (it would become an abort-class
// error); delete the `applyErr = err` deferred capture and the commit-failure
// assertion reds.
func TestMixedVersionHelperRefusalFailsTheCommit_6691(t *testing.T) {
	installFakeNetworkctl(t)

	for _, tc := range []struct {
		name    string
		refusal error
	}{
		{
			// Direction A: new Go (v6) publishing to an old helper (v5).
			name:    "v6 control plane against a v5 helper",
			refusal: errors.New("unsupported snapshot protocol version 6 (want 5)"),
		},
		{
			// Direction B: an old control plane (v5) publishing to this helper
			// (v6). The helper's check is `snapshot.version != CONST`, so the
			// two directions are the same line with the operands swapped.
			name:    "v5 control plane against a v6 helper",
			refusal: errors.New("unsupported snapshot protocol version 5 (want 6)"),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			injected := fmt.Errorf("publish userspace snapshot: %w", tc.refusal)

			// PREMISE: this must be the ORDINARY class. If a future change
			// reclassifies it, the assertions below stop describing the path
			// they name and this test must be re-read, not silently repurposed.
			if compileErrorMustAbortApply(injected) {
				t.Fatal("premise broken: the helper's version refusal is abort-class, " +
					"so it DISARMS the helper. That is the wrong action for a refusal " +
					"the helper answered by keeping its previous-good snapshot")
			}

			dp := &runtimeOnlyApplyTestDP{applyErr: injected}
			d := &Daemon{
				dp:       dp,
				networkd: networkd.NewInDir(t.TempDir()),
				store:    newConfigStore(t, filepath.Join(t.TempDir(), "config.db")),
				vrrpMgr:  vrrp.NewManager(),
				opts:     Options{NoDataplane: true},
			}

			cfg := &config.Config{}
			cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
				"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
			}
			cfg.Security.Zones = map[string]*config.ZoneConfig{
				"trust": {Name: "trust", Interfaces: []string{"reth0.0"}},
			}

			err := d.applyConfigLocked(context.Background(), cfg)
			if err == nil {
				t.Fatal("the commit REPORTED SUCCESS while the helper refused the " +
					"snapshot on protocol version — the committed config is promoted and " +
					"persisted but the dataplane is enforcing the previous one. That is " +
					"a WRONG ANSWER, not a clean refusal")
			}
			if !errors.Is(err, tc.refusal) {
				t.Fatalf("commit error must surface the helper's refusal; got %v", err)
			}
			if dp.applyCalls != 1 {
				t.Fatalf("dataplane ApplyConfig calls = %d, want 1", dp.applyCalls)
			}
			// The helper is NOT disarmed — it is still forwarding its
			// previous-good image, so the standby must still converge.
			if applyErrSkipsPeerSync(err) {
				t.Error("a version refusal skipped the peer config-sync, which is the " +
					"DISARMED-helper behaviour. The helper refused the snapshot and is " +
					"still armed on its previous-good image, so the standby has to " +
					"converge (#4034)")
			}
			// And it must not be mistaken for the secure-tunnel gate, whose
			// action is deliberately the opposite (abort + disarm).
			if errors.Is(err, dpuserspace.ErrSecureTunnelProtocolIncompatible) {
				t.Error("a plain version refusal surfaced the secure-tunnel gate sentinel")
			}
		})
	}
}
